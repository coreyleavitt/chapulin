## Property-based tests for the transfer state machines (transfer.nim).
##
## Runs the REAL sendBlocks and recvBlocks against each other over the shared
## in-memory wire (tests/wireharness.nim) across arbitrary file sizes, block
## sizes, window sizes, and — via a generated schedule — adversarial networks
## (drops, duplicates, reordering).
##
## Run in the nim devtools container (deps resolved on the host by milpa):
##   docker run --rm -v ${PWD}:C:\app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r tests/t_props_transfer.nim

import std/unittest
import proptest
import ../src/chapulin/transfer
import ./wireharness

# Drive a real sender (side A) and receiver (side B) to completion over the wire.
proc runTransfer(content: seq[byte], blocksize, windowsize: int,
                 actions: seq[WireAction] = @[],
                 dropAOcc = -1, dropBOcc = -1):
    tuple[terminated, ok: bool, received: seq[byte], n: int64] =
  let w = newWire(actions, dropAOcc, dropBOcc)
  let cfg = newTransferConfig(blocksize = blocksize, timeout = 5, retries = 3,
                              windowsize = windowsize,
                              totalSize = content.len.int64)
  let readData = proc(blockNum: uint16, bs: int): seq[byte] =
    let start = (int(blockNum) - 1) * bs
    if start >= content.len: return @[]
    return content[start ..< min(start + bs, content.len)]
  var received: seq[byte]
  let onData = proc(blockNum: uint16, data: seq[byte]) =
    received.add data

  let sf = sendBlocks(makeTransport(w, true), cfg, newPeer("peer", 0, true),
                      1, readData)
  let rf = recvBlocks(makeTransport(w, false), cfg, newPeer("peer", 0, true),
                      1, onData)

  if not driveBoth(sf, rf):
    return (false, false, received, -1'i64)
  let sres = futVal(sf)
  let rres = futVal(rf)
  return (true, sres.success and rres.success, received, rres.bytesTransferred)

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

# Known bug — https://github.com/coreyleavitt/chapulin/issues/18. sendBlocks does
# not retransmit a DATA packet lost after block 1, so a mid-stream loss truncates
# the transfer. This test encodes the desired (recovered) behavior and FAILS
# today. It is gated off the normal suite; run `nim c -r -d:knownFailing
# tests/t_props_transfer.nim` to reproduce, and remove the gate when #18 is fixed.
when defined(knownFailing):
  suite "transfer recovery (known-failing: issue #18)":
    test "a DATA packet lost mid-stream is retransmitted and the file completes":
      var content = newSeq[byte](25)        # 25 bytes / blocksize 10 => 3 blocks
      for i in 0 ..< content.len: content[i] = byte(i)
      let r = runTransfer(content, blocksize = 10, windowsize = 1,
                          dropAOcc = 1)       # drop DATA(2)'s first transmission
      check r.ok and r.received == content
