## Property-based tests for the transfer state machines (transfer.nim).
##
## Connects the REAL sendBlocks and recvBlocks over an in-memory async wire and
## asserts invariants across arbitrary file sizes, block sizes, window sizes,
## and — via a generated per-packet schedule — adversarial networks (drops,
## duplicates, reordering). Running both real implementations against each
## other exercises the actual window / final-block / ACK / retransmit logic.
##
## This is the scriptable-mock-network harness (issue #15): the NetworkSchedule
## is plain data (seq[WireAction]), so proptest generates and shrinks it.
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

type
  WireAction = enum
    waPass    ## deliver normally
    waDrop    ## drop the packet
    waDup     ## deliver twice
    waDelay   ## hold; release after the next delivered packet (reorder)

  Wire = ref object
    a2b: Deque[seq[byte]]    # sender -> receiver
    b2a: Deque[seq[byte]]    # receiver -> sender
    actions: seq[WireAction] # consumed per send; empty = always waPass
    idx: int
    pendA: seq[seq[byte]]    # held sender->receiver packet (0/1)
    pendB: seq[seq[byte]]    # held receiver->sender packet (0/1)

proc newWire(actions: seq[WireAction] = @[]): Wire =
  Wire(a2b: initDeque[seq[byte]](), b2a: initDeque[seq[byte]](), actions: actions)

proc nextAction(w: Wire): WireAction =
  if w.actions.len == 0: return waPass
  result = w.actions[w.idx mod w.actions.len]
  inc w.idx

# Apply the next scheduled action to a packet sent in one direction.
proc wireSend(w: Wire, isSender: bool, data: seq[byte]) =
  case w.nextAction()
  of waPass:
    if isSender:
      w.a2b.addLast(data)
      if w.pendA.len > 0: w.a2b.addLast(w.pendA[0]); w.pendA = @[]
    else:
      w.b2a.addLast(data)
      if w.pendB.len > 0: w.b2a.addLast(w.pendB[0]); w.pendB = @[]
  of waDup:
    if isSender:
      w.a2b.addLast(data)
      w.a2b.addLast(data)
    else:
      w.b2a.addLast(data)
      w.b2a.addLast(data)
  of waDrop:
    discard
  of waDelay:
    if isSender:
      if w.pendA.len == 0: w.pendA = @[data] else: w.a2b.addLast(data)
    else:
      if w.pendB.len == 0: w.pendB = @[data] else: w.b2a.addLast(data)

# A transport over one direction of the wire. `recv` yields to the dispatcher
# until a packet is available, bounded by a spin budget so a stall raises
# TransportTimeoutError (which the transfer treats as a lost packet) instead of
# hanging.
proc makeTransport(w: Wire, isSender: bool): Transport =
  proc doSend(data: seq[byte], host: string, port: int): Future[void] {.async.} =
    w.wireSend(isSender, data)

  proc doRecv(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte],
              host: string, port: int]] {.async.} =
    var spins = 0
    while true:
      if isSender:
        if w.b2a.len > 0: return (w.b2a.popFirst(), "peer", 0)
      else:
        if w.a2b.len > 0: return (w.a2b.popFirst(), "peer", 0)
      inc spins
      if spins > 500:
        raise newException(TransportTimeoutError, "wire idle")
      await sleepAsync(0)

  proc doClose() = discard

  Transport(send: doSend, recv: doRecv, close: doClose)

# Drive a real sender and receiver to completion over the wire.
proc runTransfer(content: seq[byte], blocksize, windowsize: int,
                 actions: seq[WireAction] = @[]):
    tuple[terminated, ok: bool, received: seq[byte], n: int64] =
  let w = newWire(actions)
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
    if steps > 100_000: break

  let terminated = sf.finished and rf.finished
  if not terminated:
    return (false, false, received, -1'i64)
  let sres = sf.read()
  let rres = rf.read()
  return (terminated, sres.success and rres.success, received, rres.bytesTransferred)

proc fileContents(maxLen = 2048): Strategy[seq[byte]] =
  lists(integers(0, 255), minLen = 0, maxLen = maxLen).map(toByteSeq)

proc dupActions(): Strategy[seq[WireAction]] =
  # Pass-biased, duplicates only — recovery is not needed, so success is required.
  lists(sampledFrom(@[waPass, waPass, waDup]), minLen = 1, maxLen = 32)

proc anyActions(): Strategy[seq[WireAction]] =
  lists(sampledFrom(@[waPass, waPass, waPass, waDrop, waDup, waDelay]),
        minLen = 1, maxLen = 20)

suite "transfer state-machine properties":

  property "lossless: receiver reconstructs sender's bytes across block/window sizes":
    given content in fileContents(),
          blocksize in integers(8, 512),
          windowsize in integers(1, 8)
    let r = runTransfer(content, blocksize, windowsize)
    ensure r.terminated and r.ok and r.received == content and
           r.n == content.len.int64

  property "duplicated packets do not corrupt the transfer (Sorcerer's Apprentice)":
    given content in fileContents(1024),
          blocksize in integers(8, 256),
          windowsize in integers(1, 4),
          actions in dupActions()
    let r = runTransfer(content, blocksize, windowsize, actions)
    ensure r.terminated and r.ok and r.received == content and
           r.n == content.len.int64

  property "any drop/dup/reorder schedule terminates; bytes correct on success":
    # Robustness: no schedule may crash, hang, or deliver wrong bytes. Recovery
    # (success) is NOT required — drops beyond the retry budget fail cleanly.
    given content in fileContents(384),
          blocksize in integers(8, 256),
          windowsize in integers(1, 4),
          actions in anyActions()
    let r = runTransfer(content, blocksize, windowsize, actions)
    ensure r.terminated and (not r.ok or r.received == content)
