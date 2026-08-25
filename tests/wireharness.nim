## Shared in-memory async wire for property-testing the real transfer and server
## state machines without sockets. A generated schedule (seq[WireAction]) may
## perturb packets in flight (drop / duplicate / reorder); `makeTransport` gives
## each side a Transport over one direction of the wire. Foundation for the
## scriptable-mock-network work (issue #15).
##
## Directions: a2b is "side A -> side B", b2a is "side B -> side A". Call
## makeTransport(w, sideA = true) for the side that drives a2b.

import std/[deques, asyncdispatch]
import ../src/chapulin/transfer
import ../src/chapulin/transport
# Only `pumpSession` (below, alongside `driveOne`/`driveBoth`) needs
# `TftpSession`/`poll` -- every other proc in this module stays confined to
# the bare `transfer.nim`/`transport.nim` level. Unlike the R2-1 `toByteSeq`
# re-export this file used to carry (dropped because it pulled all of
# `proptest` into every non-fuzz consumer for one proc's convenience), this
# is an intra-repo, already-FFI-free production module that every Part-A
# caller of `pumpSession` (RFC verification-harness-v2.md
# A-shared/A1a/A1b/A2/A3/A4) needs directly anyway -- not an avoidable
# transitive cost, and `api.nim` itself already depends on
# `transfer`/`transport`, so this adds no NEW leaf dependency to the module
# graph, only a re-traversal of one already in it.
import ../src/chapulin/api

# R2-1 code-review finding: this module used to `import ./fuzzsupport` and
# `export toByteSeq` solely to save its downstream consumers a second import
# line. That pulled all of `proptest` (via fuzzsupport) transitively into
# EVERY wireharness consumer, including non-fuzz ones (t_wireharness.nim
# imports only std/[asyncdispatch, unittest] + this module and does no
# fuzzing at all). `wireharness` itself never calls `toByteSeq` — the
# re-export was pure convenience plumbing — so the clean fix is to drop the
# import/re-export entirely and have `toByteSeq`'s real consumers
# (t_hostile.nim, t_props_transfer.nim, t_props_server.nim) import it from
# `fuzzsupport` directly. All three already depend on `proptest` directly
# (they use Strategy/property machinery), so importing `fuzzsupport` too adds
# no new transitive dependency for them — only `wireharness`'s non-fuzz
# consumers are freed of it.

type
  WireAction* = enum
    waPass    ## deliver normally
    waDrop    ## drop the packet
    waDup     ## deliver twice
    waDelay   ## hold; release after the next delivered packet (reorder)

  WirePacket* = tuple[data: seq[byte], host: string, port: int]
    ## A packet in flight, carrying its (spoofable) source address. Legit
    ## traffic sent via `wireSend` always carries the fixed peer identity
    ## `("peer", 0)` -- the address `makeTransport`'s `doRecv` reports for
    ## everything, matching every real caller's `newPeer("peer", 0, ...)`.
    ## `injectPacket` is the one place a DIFFERENT (host, port) can be
    ## supplied -- the off-TID attacker dimension (RFC verification-harness.md
    ## D8b, slice 8).

  Wire* = ref object
    a2b*, b2a*: Deque[WirePacket]
    actions: seq[WireAction]   # consumed per send; empty = always waPass
    idx: int
    pendA, pendB: seq[WirePacket]
    dropAOcc, dropBOcc: int    # deterministic single drop by occurrence (-1 none)
    aSent, bSent: int
    aBouncedCount, bBouncedCount: int
      ## count of `Transport.send` calls whose destination (host, port) was
      ## NOT the wire's one modeled peer identity (`WirePeerHost`,
      ## `WirePeerPort`) -- e.g. `transfer.recvOnce`'s TID-lock ERROR-bounce
      ## reply, addressed back to an off-TID attacker's injected source
      ## rather than the locked peer. The mock has no third node listening
      ## at an arbitrary address, so -- mirroring real UDP, where that
      ## datagram lands only at (host, port) and never touches the legit
      ## peer's stream -- such a send is counted here but never delivered
      ## onto a2b/b2a (see `makeTransport`'s `doSend`).
    aLog*, bLog*: seq[seq[byte]]  # every packet each side attempted to send
    aRecvTimeoutsMs*, bRecvTimeoutsMs*: seq[int]
      ## every timeoutMs a side's Transport.recv was called with, in order --
      ## lets a test observe that a negotiated `timeout` actually reached the
      ## recv call governing the transfer (RFC conformance-closure D5's
      ## "apply", not just "validate"). Recorded regardless of outcome
      ## (delivered / dropped / spin-timeout).

proc newWire*(actions: seq[WireAction] = @[],
              dropAOcc = -1, dropBOcc = -1): Wire =
  Wire(a2b: initDeque[WirePacket](), b2a: initDeque[WirePacket](),
       actions: actions, dropAOcc: dropAOcc, dropBOcc: dropBOcc)

proc aSends*(w: Wire): int = w.aSent   ## packets side A has sent (incl. dropped)
proc bSends*(w: Wire): int = w.bSent   ## packets side B has sent (incl. dropped)

const
  WirePeerHost* = "peer"  ## the wire's one modeled peer identity -- every
  WirePeerPort* = 0       ## legit packet (wireSend) carries this source, and
    ## every real caller's PeerEndpoint is `newPeer(WirePeerHost, WirePeerPort,
    ## ...)`. `Transport.send` to any OTHER (host, port) targets a node this
    ## two-side mock doesn't model (an off-TID attacker) -- see `makeTransport`.

proc aBounced*(w: Wire): int = w.aBouncedCount
  ## sends side A attempted to a non-peer destination (off-TID ERROR bounces)
proc bBounced*(w: Wire): int = w.bBouncedCount
  ## sends side B attempted to a non-peer destination (off-TID ERROR bounces)

proc nextAction(w: Wire): WireAction =
  if w.actions.len == 0: return waPass
  result = w.actions[w.idx mod w.actions.len]
  inc w.idx

proc wireSend(w: Wire, sideA: bool, data: seq[byte]) =
  if sideA: w.aLog.add data else: w.bLog.add data
  # Targeted single-packet drop takes precedence over the action schedule.
  if sideA:
    let occ = w.aSent; inc w.aSent
    if occ == w.dropAOcc: return
  else:
    let occ = w.bSent; inc w.bSent
    if occ == w.dropBOcc: return
  let pkt: WirePacket = (data, WirePeerHost, WirePeerPort)
  case w.nextAction()
  of waPass:
    if sideA:
      w.a2b.addLast(pkt)
      if w.pendA.len > 0: w.a2b.addLast(w.pendA[0]); w.pendA = @[]
    else:
      w.b2a.addLast(pkt)
      if w.pendB.len > 0: w.b2a.addLast(w.pendB[0]); w.pendB = @[]
  of waDup:
    if sideA:
      w.a2b.addLast(pkt)
      w.a2b.addLast(pkt)
    else:
      w.b2a.addLast(pkt)
      w.b2a.addLast(pkt)
  of waDrop:
    discard
  of waDelay:
    if sideA:
      if w.pendA.len == 0: w.pendA = @[pkt] else: w.a2b.addLast(pkt)
    else:
      if w.pendB.len == 0: w.pendB = @[pkt] else: w.b2a.addLast(pkt)

proc injectPacket*(w: Wire, toSideA: bool, data: seq[byte],
                    host: string = WirePeerHost, port: int = WirePeerPort) =
  ## Deliver a forged/garbage packet directly onto the wire, bypassing
  ## `wireSend` entirely: no `WireAction` schedule consumption, no
  ## aSent/bSent occurrence bookkeeping, no `aLog`/`bLog` recording (nothing
  ## legitimately "sent" this — an attacker/MITM packet has no sender-side
  ## Transport.send call to log). `toSideA = true` delivers to side A's next
  ## `recv` (queued on `b2a`, mirroring how a real packet *from* B reaches
  ## A); `toSideA = false` delivers to side B (queued on `a2b`). Unconditional
  ## and immediate — an injected packet is never dropped/duplicated/delayed.
  ##
  ## `host`/`port` default to `("peer", 0)` -- the SAME fixed source address
  ## every legitimate packet carries (`wireSend`, above) -- so every slice-7
  ## call site (same-TID payload injection, D8a) is a zero-diff caller of
  ## this proc. Passing a DIFFERENT `(host, port)` is the off-TID attacker
  ## dimension (RFC verification-harness.md D8b, slice 8): the packet still
  ## reaches the victim's `recv`, but `transfer.recvOnce`'s TID-lock check
  ## (`transfer.nim` — `resp.host != peer.host or resp.port != peer.port`)
  ## sees a source that doesn't match the locked peer and rejects it.
  if toSideA: w.b2a.addLast((data, host, port))
  else: w.a2b.addLast((data, host, port))

# A transport over one side of the wire. `recv` yields to the dispatcher until a
# packet is available, bounded by a spin budget so a stall raises
# TransportTimeoutError (treated as a lost packet) instead of hanging.
#
# swallowFirst models TFTP's two-socket handshake: a client's initial RRQ/WRQ
# goes to the server's listener, not the per-transfer socket, so the first send
# on that transport is discarded rather than placed on the wire.
proc makeTransport*(w: Wire, sideA: bool, swallowFirst = false): Transport =
  var swallowed = false
  proc doSend(data: seq[byte], host: string, port: int): Future[void] {.async.} =
    if swallowFirst and not swallowed:
      swallowed = true
      return
    if host != WirePeerHost or port != WirePeerPort:
      # Destined for some address other than the wire's one modeled peer --
      # e.g. `transfer.recvOnce`'s TID-lock ERROR-bounce reply
      # (`transport.send(errPkt, resp.host, resp.port)`), addressed back to
      # an off-TID attacker's injected source rather than the locked peer.
      # This two-node mock has no third party listening at an arbitrary
      # address: mirroring real UDP, where that datagram lands only at
      # (host, port) and never touches the legit peer's stream, the send is
      # counted (aBounced/bBounced) but NOT delivered onto a2b/b2a. Without
      # this gate, `wireSend` would ignore the destination entirely and
      # misroute the bounce back onto the legit pipe, corrupting the victim's
      # own transfer with a reply that was never addressed to it.
      if sideA: inc w.aBouncedCount else: inc w.bBouncedCount
      return
    w.wireSend(sideA, data)

  proc doRecv(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte],
              host: string, port: int]] {.async.} =
    if sideA: w.aRecvTimeoutsMs.add timeoutMs else: w.bRecvTimeoutsMs.add timeoutMs
    var spins = 0
    while true:
      if sideA:
        if w.b2a.len > 0: return w.b2a.popFirst()
      else:
        if w.a2b.len > 0: return w.a2b.popFirst()
      inc spins
      if spins > 500:
        raise newException(TransportTimeoutError, "wire idle")
      await sleepAsync(0)

  proc doClose() = discard

  Transport(send: doSend, recv: doRecv, close: doClose)

# ---------------------------------------------------------------------------
# WireRegistry -- a minting TransportFactory over per-call-order Wires
# (RFC verification-harness-v2.md §3.1 "Listener seam" piece (a), slice
# A1a-i). Lives here (not in a test file) because BOTH A1a-ii's listener
# bridge and A4's N-transport reject path import it -- A4's registry IS this
# generalized 1->N, not an independent design (§3.1), so it is shared infra.
# ---------------------------------------------------------------------------

type
  WireRegistry* = ref object
    ## A registry of freshly-minted single-peer `Wire`s backing a
    ## `TransportFactory`. Each factory call mints a NEW `Wire` (appended to
    ## `wires` in call order) and returns a `Transport` driving one side of
    ## it, so N calls yield N independently-addressable Wires with NO shared
    ## key.
    ##
    ## It deliberately does NOT key on the factory's `port` arg. Under the
    ## default server config (`portRangeStart/End = 0`, `hasPortRange()`
    ## false) `allocateTransferTransport` calls `transferFactory(0)` for
    ## EVERY transfer (`server.nim`), so a `Table[port, Wire]` would collapse
    ## every transfer onto key 0 -- a single entry (architect r2, HIGH). The
    ## call-order index (the proven `t_session.nim:455-464` `wireIdx`
    ## pattern -- which solved this exact degeneracy) sidesteps it: the
    ## implicit index is simply `wires.len` at mint time, never the port.
    wires*: seq[Wire]
    sideA: bool
    swallowFirst: bool

proc newWireRegistry*(sideA = true, swallowFirst = false): WireRegistry =
  ## A registry whose minted transports drive side `sideA` of each fresh Wire
  ## (default `true` -- the client-side convention `makeTransport(w, sideA =
  ## true)` every real `transportFactory` uses). `swallowFirst` is forwarded
  ## to `makeTransport` (A1a-ii needs the client's first send discarded to the
  ## listener, not placed on the per-transfer Wire); the default `false`
  ## keeps every send observable for A1a-i's unit assertions.
  WireRegistry(wires: @[], sideA: sideA, swallowFirst: swallowFirst)

proc factory*(reg: WireRegistry): TransportFactory =
  ## The minting `TransportFactory` (matches `api.TransportFactory =
  ## proc(host, port): Transport`, `api.nim:64`). Both args are IGNORED for
  ## keying -- each call mints a fresh `Wire`, records it in call order, and
  ## returns a `Transport` bound to that one Wire. The k-th call returns the
  ## transport for `reg.wires[k]`, so a test correlates a returned transport
  ## with its Wire by index. Pass this straight to
  ## `newSession(transportFactory = reg.factory())`.
  proc(host: string, port: int): Transport =
    let w = newWire()
    reg.wires.add w
    makeTransport(w, reg.sideA, reg.swallowFirst)

proc makeAdoptingTransport*(listenerWire: Wire, reg: WireRegistry): Transport =
  ## A1a-ii (RFC verification-harness-v2.md §3.1 "Listener seam" piece (c) --
  ## "the genuinely novel, highest-risk part"): the client-side counterpart of
  ## `makeListenerFromWire`. Mirrors real TFTP TID adoption -- client sends
  ## RRQ/WRQ to the server's well-known port; server replies from a fresh
  ## ephemeral port; client learns it and redirects every later send there --
  ## over the Wire mock, where "port" and "Wire object" are the same fact
  ## (see this file's header comment / t_listenerbridge.nim's module doc).
  ##
  ## Mechanism: starts UNADOPTED, sending onto `listenerWire` (the well-known
  ## "port" a bridge listener drains, piece (b)) exactly like a real client's
  ## RRQ/WRQ. The FIRST `recv` call blocks (bounded spin, like every other
  ## Wire-backed recv here) until `reg` mints a NEW Wire beyond the count that
  ## existed at construction time -- i.e. until the moment a per-transfer
  ## transport gets allocated for THIS request (`allocateTransferTransport`/
  ## `transferFactory`, server.nim:710, or A4's reject-path reroute) --
  ## builds a `Transport` bound to THAT wire (side B, since the registry's
  ## `factory()` always hands its caller side A -- here, the server's
  ## per-transfer allocation), and permanently locks onto it: every
  ## subsequent `send`/`recv` -- the ACK/DATA phase, retransmits, everything
  ## -- delegates to the adopted transport, never back to `listenerWire`.
  ## This is a ONE-WAY, ONE-TIME adoption (mirrors `PeerEndpoint.lockTo`'s
  ## own one-shot TID lock in transfer.nim) -- there is exactly one
  ## per-transfer port to learn, not a moving target.
  var adopted: Transport
  var hasAdopted = false
  let preAdopt = makeTransport(listenerWire, sideA = true)
  let baseline = reg.wires.len

  proc doSend(data: seq[byte], host: string, port: int): Future[void] {.async.} =
    if hasAdopted:
      await adopted.send(data, host, port)
    else:
      await preAdopt.send(data, host, port)

  proc doRecv(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte],
              host: string, port: int]] {.async.} =
    if not hasAdopted:
      var spins = 0
      while reg.wires.len <= baseline:
        inc spins
        if spins > 500:
          raise newException(TransportTimeoutError,
            "no per-transfer wire minted yet")
        await sleepAsync(0)
      # `reg.wires[baseline]` is the very Wire minted in response to this
      # transfer's request -- the registry's OWN call-order-index design
      # (A1a-i) makes "the next wire past what existed when I started" an
      # unambiguous, single-client fact, exactly as required here.
      adopted = makeTransport(reg.wires[baseline], sideA = false)
      hasAdopted = true
    return await adopted.recv(bufSize, timeoutMs)

  proc doClose() =
    if hasAdopted:
      if adopted.close != nil: adopted.close()
    else:
      if preAdopt.close != nil: preAdopt.close()

  Transport(send: doSend, recv: doRecv, close: doClose)

proc futVal*[T](f: Future[T]): T =
  ## Read a finished future's value. (Named to avoid clashing with proptest's
  ## `read` on PromiseStore, which shadows asyncdispatch's `read` for callers
  ## that import both.)
  read(f)

proc driveOne*[T](f: Future[T], maxSteps = 100_000): bool =
  ## Pump the dispatcher until a single future finishes or the cap is hit.
  var steps = 0
  while not f.finished:
    if not hasPendingOperations(): break
    poll()
    inc steps
    if steps > maxSteps: break
  f.finished

proc driveBoth*[T](a, b: Future[T], maxSteps = 100_000): bool =
  ## Pump the dispatcher until both futures finish or the step cap is hit.
  ## Returns whether both finished (false = stalled, i.e. a hang).
  var steps = 0
  while not (a.finished and b.finished):
    if not hasPendingOperations(): break
    poll()
    inc steps
    if steps > maxSteps: break
  a.finished and b.finished

# ---------------------------------------------------------------------------
# pumpSession -- the fixed-tick pump for Part A's facade StateMachine
# invariant hook (RFC verification-harness-v2.md A-shared, §3.1's "pump
# discipline" paragraph). `driveOne`/`driveBoth`/`driveAll` above all drive
# TO COMPLETION (or a generous step cap) -- exactly what a stateful
# invariant must NOT do: draining a transfer to completion inside every
# invariant call would finish the whole exchange before an injection rule
# ever gets a turn (the same R1-1 vacuity `t_hostile.nim`'s `pumpAndSurface`
# exists to avoid, just one layer up at the `TftpSession` facade instead of
# bare `sendBlocks`/`recvBlocks`).
# ---------------------------------------------------------------------------

const PumpSessionTicks* = 6
  ## Default tick count for `pumpSession` -- see its doc comment for the
  ## sizing argument. Exported so a Part-A slice that needs a LARGER budget
  ## for a specific op (e.g. A4's multi-hop reject chain) can state its
  ## override as an explicit multiple of this documented baseline instead
  ## of a bare unexplained integer literal.

proc pumpSession*(s: TftpSession, ticks = PumpSessionTicks) =
  ## Advance the shared dispatcher a SMALL, FIXED number of ticks: calls
  ## `s.poll(0)` (`api.nim`'s iterator -- pumps `asyncdispatch.poll(0)` once
  ## per call, then drains and discards every queued `Event`) exactly
  ## `ticks` times. Deliberately NEVER `drain()`/`waitTransfer()`/
  ## `waitServer()` (`api.nim` — all three loop on wall-clock `epochTime`,
  ## not a tick count) — replaying a recorded proptest choice sequence
  ## under container scheduling jitter would see a different number of
  ## completed hops each run with a wall-clock budget, breaking
  ## reproducibility. A tick count is deterministic input, not measured
  ## time.
  ##
  ## One shared pump op, not per-session: `asyncdispatch` is a single
  ## process-global dispatcher (confirmed by `api.nim`'s `poll` iterator,
  ## which calls the bare module-level `asyncdispatch.poll`, not anything
  ## session-scoped) — one `pumpSession` tick advances EVERY session,
  ## transfer, and server sharing the dispatcher by one readiness pass, not
  ## just `s`'s own coroutines. Part A's op vocabulary therefore has one
  ## pump op shared across every live session in an example, never
  ## per-session polling (RFC §3.1) — that would only look more
  ## fine-grained, not actually be so.
  ##
  ## Sizing `PumpSessionTicks` (6): `tests/t_hostile.nim`'s `pumpAndSurface`
  ## empirically proved 3 ticks/call sufficient to advance one
  ## `transfer.nim`-level DATA-send / ACK-recv hop through this module's own
  ## `doSend`/`doRecv` (each `await sleepAsync(0)` spin in `doRecv` costs one
  ## dispatcher tick to become ready) without ever letting a single
  ## invariant call drain an entire transfer to completion (see that file's
  ## R1-1 comment for the empirical history). A facade-level `TftpSession`
  ## wraps that SAME `sendBlocks`/`recvBlocks` engine inside one more layer
  ## of orchestration (`api.nim`'s per-transfer async runner plus its own
  ## event-enqueue bookkeeping) — so this pump needs AT LEAST that
  ## proven per-hop granularity, with headroom for the api.nim-level
  ## layer's own await point(s). `PumpSessionTicks = 6` (2x t_hostile's
  ## proven-sufficient 3) is a deliberately conservative starting point, not
  ## a re-derivation from scratch: it is a documented hypothesis for
  ## A1a-ii/A2 (the first slices that actually drive a real Wire-backed
  ## `TftpSession` hop chain end-to-end) to empirically confirm or tighten.
  ## RFC §3.1 names A4's reject chain (client RRQ → `listener.recv` resolves
  ## → reject check → `sendError` await → `Event` enqueue — roughly 2
  ## genuine awaits) as the other data point this budget must cover; 6
  ## comfortably exceeds that with margin to spare. Wire's callback-ready
  ## ordering is deterministic-by-construction (software FIFO queues, never
  ## OS-multiplexed epoll/select readiness), so a correctly-sized N is a
  ## fixed property of the hop-chain's shape, not a source of run-to-run
  ## flakiness — unlike a wall-clock budget, tightening or loosening it
  ## later is a one-line, fully-reproducible change.
  for _ in 0 ..< ticks:
    for ev in s.poll(0): discard

proc pumpSessionCollect*(s: TftpSession, ticks = PumpSessionTicks): seq[Event] =
  ## Same fixed-tick discipline as `pumpSession` above (same default tick
  ## count, same never-`drain()`/`waitTransfer()`/`waitServer()` contract —
  ## see that proc's doc comment for the sizing argument), but RETURNS every
  ## drained `Event` instead of discarding it (RFC verification-harness-v2.md
  ## A2, §3.1's anti-vacuity paragraph: "ops actually ran against a live
  ## session, the pump actually advanced transfers" needs something to
  ## observe — `pumpSession`'s discard-everything body has nothing for a
  ## caller to inspect). Deliberately a SEPARATE proc, not a flag on
  ## `pumpSession`: `pumpSession`'s existing callers (`t_pumpsession.nim`,
  ## any future no-observation caller) keep exactly the same body: no
  ## `seq[Event]` allocation, no behavior change.
  for _ in 0 ..< ticks:
    for ev in s.poll(0): result.add ev

# ---------------------------------------------------------------------------
# makeListener — a UdpListener backed by an in-memory deque, mirroring
# makeTransport. Feed listener.recv() in server.run()'s loop without sockets.
# ---------------------------------------------------------------------------

type
  ListenerQueue* = ref object
    ## In-memory queue of inbound TFTP requests for wireharness-based tests.
    queue*: Deque[tuple[data: seq[byte], host: string, port: int]]

proc newListenerQueue*(): ListenerQueue =
  ## Create an empty ListenerQueue.
  ListenerQueue(queue: initDeque[tuple[data: seq[byte], host: string, port: int]]())

proc push*(q: ListenerQueue, data: seq[byte], host: string, port: int) =
  ## Enqueue a fake inbound request; call from test code before or while driving.
  q.queue.addLast((data, host, port))

proc makeListenerFromWire*(w: Wire, port: int = 0): UdpListener =
  ## A1a-ii (RFC verification-harness-v2.md §3.1 "Listener seam" piece (b)):
  ## promotes the old `swallowFirst`+manual-`ListenerQueue.push` trick into a
  ## first-class `UdpListener` that drains the SAME queue a real client's
  ## first send lands on -- `w.a2b`, exactly what `makeTransport(w, sideA =
  ## true).send` pushes onto for a legit (non-injected) send. A client built
  ## over `w` (or, once adopted, `makeAdoptingTransport`, below) therefore
  ## needs NO `swallowFirst`/manual push: its actual RRQ/WRQ reaches this
  ## listener the same way a real UDP listener socket receives whatever a
  ## client's first datagram carries.
  ##
  ## Mirrors `makeListener`'s shape exactly (spin-then-timeout `recv`, no-op
  ## `close`, stub `localPort`) so it's a drop-in `ListenerFactory` result --
  ## only the backing queue differs.
  proc doRecv(timeoutMs: int): Future[tuple[data: seq[byte],
              host: string, port: int]] {.async.} =
    var spins = 0
    while true:
      if w.a2b.len > 0:
        return w.a2b.popFirst()
      inc spins
      if spins > 500:
        raise newException(TransportTimeoutError, "listener idle")
      await sleepAsync(0)

  proc doClose() = discard

  UdpListener(recv: doRecv, close: doClose, localPort: proc(): int = port)

proc makeListener*(q: ListenerQueue, port: int = 0): UdpListener =
  ## Build a UdpListener whose recv pops from q. If q is empty it spins up to
  ## 500 times (yield each spin) then raises TransportTimeoutError so the
  ## server loop's `except TransportTimeoutError: continue` keeps running.
  ## localPort() returns the `port` value supplied at construction (stub).
  proc doRecv(timeoutMs: int): Future[tuple[data: seq[byte],
              host: string, port: int]] {.async.} =
    var spins = 0
    while true:
      if q.queue.len > 0:
        return q.queue.popFirst()
      inc spins
      if spins > 500:
        raise newException(TransportTimeoutError, "listener idle")
      await sleepAsync(0)

  proc doClose() = discard

  UdpListener(recv: doRecv, close: doClose, localPort: proc(): int = port)

# ---------------------------------------------------------------------------
# makeFailingTransport — identical to makeTransport but send raises OSError
# after `failAfter` successful deliveries, so the never-raise server property
# can be tested (slices 2/4).
# ---------------------------------------------------------------------------

proc makeFailingTransport*(w: Wire, sideA: bool, failAfter: int,
                           swallowFirst = false): Transport =
  ## Build a Transport whose send succeeds for the first `failAfter` calls then
  ## raises OSError on every subsequent call. recv is the normal wire path.
  ## failAfter = 1 → 1st send succeeds, 2nd raises.
  var swallowed = false
  var sendCount = 0

  proc doSend(data: seq[byte], host: string, port: int): Future[void] {.async.} =
    if swallowFirst and not swallowed:
      swallowed = true
      return
    inc sendCount
    if sendCount > failAfter:
      raise newException(OSError, "send failed")
    w.wireSend(sideA, data)

  proc doRecv(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte],
              host: string, port: int]] {.async.} =
    var spins = 0
    while true:
      if sideA:
        if w.b2a.len > 0: return w.b2a.popFirst()
      else:
        if w.a2b.len > 0: return w.a2b.popFirst()
      inc spins
      if spins > 500:
        raise newException(TransportTimeoutError, "wire idle")
      await sleepAsync(0)

  proc doClose() = discard

  Transport(send: doSend, recv: doRecv, close: doClose)

# ---------------------------------------------------------------------------
# makeFailingListener — a UdpListener whose recv raises OSError (NOT
# TransportTimeoutError) on the very first call.  Used to test Bug 2: an
# unexpected recv error must not wedge the session (evServerStopped must
# still be emitted).
# ---------------------------------------------------------------------------

proc makeFailingListener*(): UdpListener =
  ## Build a UdpListener whose recv raises OSError on the first call.
  ## Subsequent calls raise TransportTimeoutError so callers that retry do
  ## not spin forever, but with the Bug 2 fix the loop breaks on the first
  ## error and never reaches a second call.
  var called = false
  proc doRecv(timeoutMs: int): Future[tuple[data: seq[byte],
              host: string, port: int]] {.async.} =
    if not called:
      called = true
      raise newException(OSError, "recv failed: simulated network error")
    raise newException(TransportTimeoutError, "listener idle")

  proc doClose() = discard

  UdpListener(recv: doRecv, close: doClose, localPort: proc(): int = 0)

proc driveAll*[T](futs: seq[Future[T]], maxSteps = 200_000): bool =
  ## Pump the dispatcher until every future finishes or the cap is hit. Used to
  ## interleave several concurrent transfers on the one event loop.
  proc allDone(): bool =
    for f in futs:
      if not f.finished: return false
    true
  var steps = 0
  while not allDone():
    if not hasPendingOperations(): break
    poll()
    inc steps
    if steps > maxSteps: break
  allDone()
