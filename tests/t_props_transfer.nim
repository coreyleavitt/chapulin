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
                 dropAOcc = -1, dropBOcc = -1,
                 peakCacheBlocksOut: ref int = new(int)):
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
                      1, readData, peakCacheBlocksOut = peakCacheBlocksOut)
  let rf = recvBlocks(makeTransport(w, false), cfg, newPeer("peer", 0, true),
                      1, onData)

  if not driveBoth(sf, rf):
    return (false, false, received, -1'i64)
  let sres = futVal(sf)
  let rres = futVal(rf)
  return (true, sres.success and rres.success, received, rres.bytesTransferred)

# Same as runTransfer, but wires up sendBlocks' onDelivered hook (RFC
# checksum-integrity-error-hygiene, D1 Option A / slice 1.0) and captures every
# firing so tests can assert once-per-block, ascending order, and correct bytes.
proc runTransferWithHook(content: seq[byte], blocksize, windowsize: int,
                        actions: seq[WireAction] = @[],
                        dropAOcc = -1, dropBOcc = -1):
    tuple[terminated, ok: bool, received: seq[byte], delivered: seq[seq[byte]],
          sentBytes: int64] =
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
  var delivered: seq[seq[byte]] = @[]
  let onDelivered = proc(data: openArray[byte]) =
    var chunk = newSeq[byte](data.len)
    for i in 0 ..< data.len: chunk[i] = data[i]
    delivered.add chunk

  let sf = sendBlocks(makeTransport(w, true), cfg, newPeer("peer", 0, true),
                      1, readData, onDelivered = onDelivered)
  let rf = recvBlocks(makeTransport(w, false), cfg, newPeer("peer", 0, true),
                      1, onData)

  if not driveBoth(sf, rf):
    return (false, false, received, delivered, 0'i64)
  let sres = futVal(sf)
  let rres = futVal(rf)
  return (true, sres.success and rres.success, received, delivered, sres.bytesTransferred)

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

# Regression guard for https://github.com/coreyleavitt/chapulin/issues/18. Before
# the fix, sendBlocks ignored the duplicate ACKs a receiver sends after losing a
# DATA packet, so a mid-stream loss deadlocked and the transfer truncated. The
# dup-ACK fast-retransmit now recovers it.
suite "transfer recovery (issue #18)":

  test "a DATA packet lost mid-stream is retransmitted and the file completes":
    var content = newSeq[byte](25)        # 25 bytes / blocksize 10 => 3 blocks
    for i in 0 ..< content.len: content[i] = byte(i)
    let r = runTransfer(content, blocksize = 10, windowsize = 1,
                        dropAOcc = 1)       # drop DATA(2)'s first transmission
    check r.terminated and r.ok and r.received == content

  property "any single mid-stream DATA loss still completes intact":
    # Generalises the regression test: dropping the first transmission of any one
    # DATA packet (not just block 1) must still recover and reconstruct the file.
    given content in fileContents(512),
          blocksize in integers(8, 128),
          dropIdx in integers(1, 6)
    let nBlocks = (content.len + blocksize - 1) div blocksize
    # Only meaningful when the drop targets an actual mid-stream block.
    if nBlocks >= 2 and dropIdx < nBlocks:
      let r = runTransfer(content, blocksize, windowsize = 1, dropAOcc = dropIdx)
      ensure r.terminated and r.ok and r.received == content

# Efficiency guards for the #18 dup-ACK retransmit. A lock-step (windowsize=1)
# transfer sends exactly `len div blocksize + 1` DATA packets — one per block
# plus the final short/empty block that signals end-of-file.
proc senderPackets(content: seq[byte], blocksize, windowsize: int,
                   actions: seq[WireAction]): tuple[ok: bool, sent: int] =
  let w = newWire(actions)
  let cfg = newTransferConfig(blocksize = blocksize, timeout = 5, retries = 3,
                              windowsize = windowsize,
                              totalSize = content.len.int64)
  let readData = proc(blockNum: uint16, bs: int): seq[byte] =
    let start = (int(blockNum) - 1) * bs
    if start >= content.len: return @[]
    return content[start ..< min(start + bs, content.len)]
  var received: seq[byte]
  let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
  let sf = sendBlocks(makeTransport(w, true), cfg, newPeer("peer", 0, true),
                      1, readData)
  let rf = recvBlocks(makeTransport(w, false), cfg, newPeer("peer", 0, true),
                      1, onData)
  let done = driveBoth(sf, rf)
  let ok = done and futVal(sf).success and futVal(rf).success and received == content
  (ok, w.aSends())

suite "transfer efficiency (no spurious or cascading retransmits)":

  property "a clean lock-step transfer sends exactly one DATA per block":
    # Teeth for the #18 fix: the dup-ACK retransmit must stay dormant when
    # nothing is lost. A perturbation-free transfer sends each block exactly once
    # (plus the final short block) — a spuriously firing retransmit would exceed
    # this exact count.
    given content in fileContents(512),
          blocksize in integers(16, 128)
    let r = senderPackets(content, blocksize, windowsize = 1, @[])
    ensure r.ok and r.sent == content.len div blocksize + 1

  property "duplication never cascades into resending the whole file":
    # RFC 1123 4.2.3.1 Sorcerer's Apprentice: under a duplication-only network the
    # sender must not roughly double its packet count.
    given content in fileContents(512),
          blocksize in integers(16, 128),
          actions in dupActions()
    let ideal = content.len div blocksize + 1
    let r = senderPackets(content, blocksize, windowsize = 1, actions)
    ensure r.ok and r.sent < 2 * ideal

# onDelivered hook + send-byte cache — RFC docs/rfc/checksum-integrity-error-hygiene.md,
# D1 Option A, slice 1.0. Proven entirely here, with zero dependency on checksum.nim:
# onDelivered must fire exactly once per block, in ascending order, with the exact
# bytes that block was last sent with — under lossless lock-step, dup-ACK
# fast-retransmit (issue #18's recovery path), and a windowsize>=3 cumulative ACK
# (the round-2 CRITICAL case: a naive once-per-ACK-packet firing would only hash
# the last block of the window and silently drop the interior blocks).
suite "transfer onDelivered hook (checksum-integrity-error-hygiene D1 Option A)":

  property "fires exactly once per block, ascending order, correct bytes (lossless)":
    given content in fileContents(),
          blocksize in integers(8, 512),
          windowsize in integers(1, 8)
    let r = runTransferWithHook(content, blocksize, windowsize)
    var reassembled: seq[byte] = @[]
    for chunk in r.delivered: reassembled.add chunk
    ensure r.terminated and r.ok and reassembled == content and
           r.delivered.len == content.len div blocksize + 1

  test "dup-ACK fast-retransmit still delivers each block exactly once, in order (issue #18 path)":
    var content = newSeq[byte](25)        # 25 bytes / blocksize 10 => 3 blocks
    for i in 0 ..< content.len: content[i] = byte(i)
    let r = runTransferWithHook(content, blocksize = 10, windowsize = 1,
                                dropAOcc = 1)   # drop DATA(2)'s first transmission
    check r.terminated and r.ok
    var reassembled: seq[byte] = @[]
    for chunk in r.delivered: reassembled.add chunk
    check reassembled == content
    check r.delivered.len == content.len div 10 + 1   # 3 blocks, no double-fire

  test "a windowsize>=3 cumulative ACK fires every intermediate block, ascending":
    # 55 bytes / blocksize 10 = 6 blocks (5 full + 1 short final); windowsize 5
    # means recvBlocks only ACKs once for blocks 1..5 (a single cumulative ACK),
    # then once more for block 6. A naive fire-once-per-ACK-packet implementation
    # would call onDelivered twice total (missing blocks 1-4's bytes entirely) —
    # this assertion goes RED against that shape.
    var content = newSeq[byte](55)
    for i in 0 ..< content.len: content[i] = byte(i)
    let r = runTransferWithHook(content, blocksize = 10, windowsize = 5)
    check r.terminated and r.ok
    var reassembled: seq[byte] = @[]
    for chunk in r.delivered: reassembled.add chunk
    check reassembled == content
    check r.delivered.len == 6

# M7: sendOneBlock's `if not isResend: bytesSent += blkData.len`
# (transfer.nim ~200-206) must count a resent block's bytes only once, so a
# retransmitted block never inflates the sender-side byte count past the true
# file size. The existing "partial ACK in window resumes correctly" test
# (t_transfer.nim) never actually exercises the resend branch (its window
# completes within the initial fill, isResend stays false throughout), so it
# cannot catch a regression here. This reuses the exact issue #18 dup-ACK
# fast-retransmit scenario proven above ("dup-ACK fast-retransmit still
# delivers each block exactly once") -- dropAOcc=1 drops DATA(2)'s first
# transmission, forcing the dup-ACK path to resend block 2 from windowCache
# (isResend == true) -- and additionally checks the sender's own
# bytesTransferred against the true file size.
suite "transfer byte-count accounting (M7: bytesSent resend fix)":

  test "a dup-ACK-triggered resend does not double-count bytesTransferred":
    var content = newSeq[byte](25)        # 25 bytes / blocksize 10 => 3 blocks
    for i in 0 ..< content.len: content[i] = byte(i)
    let r = runTransferWithHook(content, blocksize = 10, windowsize = 1,
                                dropAOcc = 1)   # drop DATA(2)'s first transmission
    check r.terminated and r.ok
    # With the fix: block1(10) + block2(10, counted once despite the resend)
    # + block3(5, final) == 25 == content.len. Revert the `if not isResend`
    # guard and this balloons to 35 (block 2's resend double-counted).
    check r.sentBytes == content.len.int64

# Round-3 code-review fix 1: windowCache eviction was WRONGLY nested inside
# `if onDelivered != nil:` in sendBlocks' ACK-acceptance branch, so on the
# onDelivered == nil path (the DEFAULT/common case: every client PUT has no
# onDelivered param; every server RRQ with checksumMode == csNone, the
# default) nothing was ever evicted and windowCache grew to O(filesize)
# instead of the documented O(windowsize x blocksize). This drives a transfer
# with many more blocks than the window, onDelivered = nil, and asserts the
# cache's observed peak size (sendBlocks' `peakCacheBlocksOut` out-param, a
# call-scoped diagnostic box -- see transfer.nim's doc comment, mirroring
# server.nim's `diagOut` idiom so concurrent sendBlocks calls never share
# mutable state) stayed bounded by ~windowsize rather than growing to ~total
# block count.
suite "transfer windowCache eviction (round-3 fix 1: memory leak on default path)":

  test "onDelivered == nil: windowCache peak stays O(windowsize), not O(filesize)":
    const blocksize = 8
    const windowsize = 4
    const nBlocks = 20
    var content = newSeq[byte](blocksize * nBlocks)   # 20 full blocks + 1 final empty block
    for i in 0 ..< content.len: content[i] = byte(i mod 256)

    let box = new(int)
    let r = runTransfer(content, blocksize, windowsize, peakCacheBlocksOut = box)   # onDelivered defaults to nil
    check r.terminated and r.ok and r.received == content

    # Before the fix: eviction never runs (onDelivered == nil), so the peak
    # equals the total number of distinct blocks ever cached (~nBlocks + 1,
    # the final short block) -- RED. After the fix: eviction runs
    # unconditionally on every confirmed ACK, so the peak never exceeds the
    # window (windowsize, +1 slack for the final short block) -- GREEN.
    check box[] <= windowsize + 1
    check box[] < nBlocks

  test "onDelivered == nil, lock-step (windowsize=1): peak stays at 1, not O(filesize)":
    const blocksize = 8
    const nBlocks = 20
    var content = newSeq[byte](blocksize * nBlocks)
    for i in 0 ..< content.len: content[i] = byte(i mod 256)

    let box = new(int)
    let r = runTransfer(content, blocksize, windowsize = 1, peakCacheBlocksOut = box)
    check r.terminated and r.ok and r.received == content
    check box[] <= 2   # in-flight block + at most one resend overlap
    check box[] < nBlocks

# RFC conformance-closure D6: recvBlocks' RFC 7440 gap-ACK (pkt.blockNum >
# expectedBlock) must compose with sendBlocks' dup-ACK classifier
# (transfer.nim: `ackBlockNum >= lastAcked+1` is forward-progress,
# `ackBlockNum == lastAcked` is a duplicate needing `dupAckThreshold`
# repeats). The two tests below drive the REAL sendBlocks against the REAL
# recvBlocks over the wire (not a mock) so the composability itself is what's
# under test, not either side's classifier in isolation.
#
# Both scenarios need the gap to land in a window that is NOT the sender's
# final one (hitFinal == false at the moment the gap-ACK arrives) -- the
# sender's partial-ACK forward-progress branch
# (`elif not hitFinal: ... fillWindow()`) only fires a proactive resend when
# more data is still pending. A gap inside the transfer's last window falls
# back to the (still-correct, just slower) timeout/dup-ACK path regardless of
# fire count -- an orthogonal, pre-existing characteristic of sendBlocks'
# own gating that D6 does not touch. Both proc bodies below are wired with a
# trailing 4th block precisely so this doesn't apply.
proc runTransferWithWire(content: seq[byte], blocksize, windowsize: int,
                        dropAOcc = -1, dropBOcc = -1):
    tuple[terminated, ok: bool, w: Wire] =
  let w = newWire(dropAOcc = dropAOcc, dropBOcc = dropBOcc)
  let cfg = newTransferConfig(blocksize = blocksize, timeout = 5, retries = 3,
                              windowsize = windowsize,
                              totalSize = content.len.int64)
  let readData = proc(blockNum: uint16, bs: int): seq[byte] =
    let start = (int(blockNum) - 1) * bs
    if start >= content.len: return @[]
    return content[start ..< min(start + bs, content.len)]
  var received: seq[byte]
  let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data

  let sf = sendBlocks(makeTransport(w, true), cfg, newPeer("peer", 0, true),
                      1, readData)
  let rf = recvBlocks(makeTransport(w, false), cfg, newPeer("peer", 0, true),
                      1, onData)

  let terminated = driveBoth(sf, rf)
  let ok = terminated and futVal(sf).success and futVal(rf).success and
           received == content
  (terminated, ok, w)

proc countAck(log: seq[seq[byte]], blockNum: uint16): int =
  for raw in log:
    let pkt = decode(raw)
    if pkt.opcode == opAck and pkt.ackBlockNum == blockNum:
      inc result

suite "receiver gap-ACK composability (RFC 7440, D6)":

  test "mid-window gap: exactly ONE gap-ACK, and it drives the sender's forward-progress resend":
    # blocksize=10, 4 blocks (10,10,10,5-final). windowsize=3: window 1 is
    # [1,2,3] (not the file's final window -- block 4 is still pending).
    # dropAOcc=1 drops DATA(2)'s first transmission (0-indexed: block1=occ0,
    # block2=occ1, block3=occ2), so the receiver sees block1, then block3
    # arrives ahead of the still-missing block2: expectedBlock=2,
    # pkt.blockNum=3 > expectedBlock -- a mid-window gap. The receiver has
    # never ACKed block1 yet (windowsize=3 hasn't been reached), so this MUST
    # fire exactly once (a second copy would prime the sender's dupAcks as a
    # phantom duplicate against the now-advanced lastAcked).
    var content = newSeq[byte](35)
    for i in 0 ..< content.len: content[i] = byte(i)
    let r = runTransferWithWire(content, blocksize = 10, windowsize = 3,
                                dropAOcc = 1)
    check r.terminated and r.ok
    # The gap-ACK's target is the last in-order block (expectedBlock-1 == 1).
    # Exactly one such ACK may appear -- windowsize=3 never legitimately ACKs
    # block 1 alone through the normal windowed path, so any ACK(1) on the
    # wire can only be the gap-ACK.
    check countAck(r.w.bLog, 1'u16) == 1

  test "window-boundary gap: exactly dupAckThreshold gap-ACKs, reaching the sender's fast-retransmit":
    # blocksize=10, 4 blocks (10,10,10,5-final). windowsize=2: window 1 is
    # [1,2] (both delivered, receiver ACKs block 2 -- a genuine, already-sent
    # ACK). Window 2 is [3,4]; dropAOcc=2 drops DATA(3)'s first transmission
    # (occ0=block1, occ1=block2, occ2=block3), so the receiver sees block4
    # arrive ahead of the still-missing block3: expectedBlock=3,
    # pkt.blockNum=4 > expectedBlock -- a window-boundary gap, because the
    # target (block 2) was ALREADY ACKed when window 1 drained. This must
    # fire exactly dupAckThreshold times to reach the sender's fast-retransmit
    # (a single copy would just read as yet another already-seen duplicate
    # ACK on the sender's side and go nowhere).
    var content = newSeq[byte](35)
    for i in 0 ..< content.len: content[i] = byte(i)
    let r = runTransferWithWire(content, blocksize = 10, windowsize = 2,
                                dropAOcc = 2)
    check r.terminated and r.ok
    # ACK(2) appears once legitimately (window 1's cumulative ACK) plus
    # exactly dupAckThreshold times as the boundary gap-ACK.
    check countAck(r.w.bLog, 2'u16) == 1 + dupAckThreshold
