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
