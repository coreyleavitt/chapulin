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

proc toByteSeq*(xs: seq[int]): seq[byte] =
  result = newSeq[byte](xs.len)
  for i, x in xs: result[i] = byte(x and 0xFF)

type
  WireAction* = enum
    waPass    ## deliver normally
    waDrop    ## drop the packet
    waDup     ## deliver twice
    waDelay   ## hold; release after the next delivered packet (reorder)

  Wire* = ref object
    a2b*, b2a*: Deque[seq[byte]]
    actions: seq[WireAction]   # consumed per send; empty = always waPass
    idx: int
    pendA, pendB: seq[seq[byte]]
    dropAOcc, dropBOcc: int    # deterministic single drop by occurrence (-1 none)
    aSent, bSent: int
    aLog*, bLog*: seq[seq[byte]]  # every packet each side attempted to send

proc newWire*(actions: seq[WireAction] = @[],
              dropAOcc = -1, dropBOcc = -1): Wire =
  Wire(a2b: initDeque[seq[byte]](), b2a: initDeque[seq[byte]](),
       actions: actions, dropAOcc: dropAOcc, dropBOcc: dropBOcc)

proc aSends*(w: Wire): int = w.aSent   ## packets side A has sent (incl. dropped)
proc bSends*(w: Wire): int = w.bSent   ## packets side B has sent (incl. dropped)

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
  case w.nextAction()
  of waPass:
    if sideA:
      w.a2b.addLast(data)
      if w.pendA.len > 0: w.a2b.addLast(w.pendA[0]); w.pendA = @[]
    else:
      w.b2a.addLast(data)
      if w.pendB.len > 0: w.b2a.addLast(w.pendB[0]); w.pendB = @[]
  of waDup:
    if sideA:
      w.a2b.addLast(data)
      w.a2b.addLast(data)
    else:
      w.b2a.addLast(data)
      w.b2a.addLast(data)
  of waDrop:
    discard
  of waDelay:
    if sideA:
      if w.pendA.len == 0: w.pendA = @[data] else: w.a2b.addLast(data)
    else:
      if w.pendB.len == 0: w.pendB = @[data] else: w.b2a.addLast(data)

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
    w.wireSend(sideA, data)

  proc doRecv(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte],
              host: string, port: int]] {.async.} =
    var spins = 0
    while true:
      if sideA:
        if w.b2a.len > 0: return (w.b2a.popFirst(), "peer", 0)
      else:
        if w.a2b.len > 0: return (w.a2b.popFirst(), "peer", 0)
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
        if w.b2a.len > 0: return (w.b2a.popFirst(), "peer", 0)
      else:
        if w.a2b.len > 0: return (w.a2b.popFirst(), "peer", 0)
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
