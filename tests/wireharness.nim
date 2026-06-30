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

proc newWire*(actions: seq[WireAction] = @[],
              dropAOcc = -1, dropBOcc = -1): Wire =
  Wire(a2b: initDeque[seq[byte]](), b2a: initDeque[seq[byte]](),
       actions: actions, dropAOcc: dropAOcc, dropBOcc: dropBOcc)

proc nextAction(w: Wire): WireAction =
  if w.actions.len == 0: return waPass
  result = w.actions[w.idx mod w.actions.len]
  inc w.idx

proc wireSend(w: Wire, sideA: bool, data: seq[byte]) =
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
