## Property-based tests for the transfer state machines (transfer.nim).
##
## Connects the REAL sendBlocks and recvBlocks over an in-memory async wire and
## asserts the receiver reconstructs the sender's bytes for arbitrary file
## sizes, block sizes, and window sizes. Running both real implementations
## against each other (rather than a scripted mock) exercises the actual
## window / final-block / ACK logic on both sides.
##
## This is the harness the scriptable-mock-network work (issue #15) extends:
## this first slice uses a lossless wire; a generated NetworkSchedule (drops,
## duplicates, reordering) plugs into `makeTransport` next.
##
## Run in the nim devtools container (deps resolved on the host by milpa):
##   docker run --rm -v ${PWD}:C:\app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r tests/t_props_transfer.nim

import std/[unittest, deques, asyncdispatch]
import proptest
import ../src/chapulin/transfer

proc toByteSeq(xs: seq[int]): seq[byte] =
  result = newSeq[byte](xs.len)
  for i, x in xs: result[i] = byte(x and 0xFF)

type Wire = ref object
  a2b: Deque[seq[byte]]   # sender -> receiver
  b2a: Deque[seq[byte]]   # receiver -> sender
  dups: seq[bool]         # per-send: deliver the packet twice? (empty = never)
  dupIdx: int

proc newWire(dups: seq[bool] = @[]): Wire =
  Wire(a2b: initDeque[seq[byte]](), b2a: initDeque[seq[byte]](), dups: dups)

proc nextDup(w: Wire): bool =
  if w.dups.len == 0: return false
  result = w.dups[w.dupIdx mod w.dups.len]
  inc w.dupIdx

proc deliver(w: Wire, isSender: bool, data: seq[byte]) =
  let twice = w.nextDup()
  if isSender:
    w.a2b.addLast(data)
    if twice: w.a2b.addLast(data)
  else:
    w.b2a.addLast(data)
    if twice: w.b2a.addLast(data)

# A transport over one direction of the wire. `recv` yields to the dispatcher
# until a packet is available, bounded by a spin budget so a stall fails fast
# (TransportTimeoutError) instead of hanging the test.
proc makeTransport(w: Wire, isSender: bool): Transport =
  proc doSend(data: seq[byte], host: string, port: int): Future[void] {.async.} =
    w.deliver(isSender, data)

  proc doRecv(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte],
              host: string, port: int]] {.async.} =
    var spins = 0
    while true:
      if isSender:
        if w.b2a.len > 0: return (w.b2a.popFirst(), "peer", 0)
      else:
        if w.a2b.len > 0: return (w.a2b.popFirst(), "peer", 0)
      inc spins
      if spins > 5000:
        raise newException(TransportTimeoutError, "wire idle")
      await sleepAsync(0)

  proc doClose() = discard

  Transport(send: doSend, recv: doRecv, close: doClose)

# Drive a real sender and receiver to completion over a lossless wire.
# Returns (both succeeded, received bytes, receiver's reported byte count).
proc runTransfer(content: seq[byte], blocksize, windowsize: int,
                 dups: seq[bool] = @[]): (bool, seq[byte], int64) =
  let w = newWire(dups)
  let cfg = newTransferConfig(blocksize = blocksize, timeout = 5, retries = 3,
                              windowsize = windowsize,
                              totalSize = content.len.int64)
  let senderPeer = newPeer("peer", 0, locked = true)
  let receiverPeer = newPeer("peer", 0, locked = true)

  let readData = proc(blockNum: uint16, bs: int): seq[byte] =
    let start = (int(blockNum) - 1) * bs
    if start >= content.len: return @[]
    return content[start ..< min(start + bs, content.len)]

  var received: seq[byte]
  let onData = proc(blockNum: uint16, data: seq[byte]) =
    received.add data

  let sf = sendBlocks(makeTransport(w, true), cfg, senderPeer, 1, readData)
  let rf = recvBlocks(makeTransport(w, false), cfg, receiverPeer, 1, onData)

  var steps = 0
  while not (sf.finished and rf.finished):
    if not hasPendingOperations(): break
    poll()
    inc steps
    if steps > 500_000: break

  if not (sf.finished and rf.finished):
    return (false, received, -1)
  let sres = sf.read()
  let rres = rf.read()
  return (sres.success and rres.success, received, rres.bytesTransferred)

proc fileContents(): Strategy[seq[byte]] =
  lists(integers(0, 255), minLen = 0, maxLen = 2048).map(toByteSeq)

suite "transfer state-machine properties (lossless wire)":

  property "receiver reconstructs sender's bytes across block/window sizes":
    given content in fileContents(),
          blocksize in integers(8, 512),
          windowsize in integers(1, 8)
    let (ok, received, n) = runTransfer(content, blocksize, windowsize)
    ensure ok and received == content and n == content.len.int64

  property "duplicated packets do not corrupt the transfer (Sorcerer's Apprentice)":
    given content in lists(integers(0, 255), minLen = 0, maxLen = 1024).map(toByteSeq),
          blocksize in integers(8, 256),
          windowsize in integers(1, 4),
          dups in lists(booleans(), minLen = 1, maxLen = 32)
    let (ok, received, n) = runTransfer(content, blocksize, windowsize, dups)
    ensure ok and received == content and n == content.len.int64
