import unittest
import std/[strutils, asyncdispatch]
import ../src/chapulin/protocol
import ../src/chapulin/transfer

# --- Local async mock (mirrors helpers.nim pattern) ---

type
  MockResponse = object
    data: seq[byte]
    host: string
    port: int

  MockTransport = ref object
    responses: seq[MockResponse]
    responseIdx: int
    sentPackets: seq[tuple[data: seq[byte], host: string, port: int]]
    timeoutOnNext: int
    recvTimeoutsMs: seq[int]  ## every timeoutMs a caller asked recv() for, in
                               ## order -- lets a test observe the R5 deadline
                               ## budget shrinking across recvOnce's internal
                               ## retry loop instead of resetting each call.
    recvDelayMs: int  ## optional artificial delay (via sleepAsync) before each
                       ## recv() resolves -- lets a test make real wall-clock
                       ## time elapse deterministically between iterations of
                       ## recvOnce's internal loop, without relying on OS
                       ## timer/scheduling precision for the assertion itself.

proc newMock(): MockTransport =
  MockTransport(responses: @[], responseIdx: 0, sentPackets: @[], timeoutOnNext: 0,
               recvTimeoutsMs: @[], recvDelayMs: 0)

proc addResponse(mt: MockTransport, pkt: TftpPacket, host: string = "10.0.0.1", port: int = 5000) =
  mt.responses.add MockResponse(data: encode(pkt), host: host, port: port)

proc addRawResponse(mt: MockTransport, data: seq[byte], host: string = "10.0.0.1", port: int = 5000) =
  mt.responses.add MockResponse(data: data, host: host, port: port)

proc toTransport(mt: MockTransport): Transport =
  result.send = proc(data: seq[byte], host: string, port: int): Future[void] =
    mt.sentPackets.add (data: data, host: host, port: port)
    let fut = newFuture[void]("mockSend")
    fut.complete()
    return fut

  result.recv = proc(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte], host: string, port: int]] {.async.} =
    mt.recvTimeoutsMs.add timeoutMs
    if mt.recvDelayMs > 0:
      await sleepAsync(mt.recvDelayMs)
    if mt.timeoutOnNext > 0:
      mt.timeoutOnNext.dec
      raise newException(TransportTimeoutError, "Mock timeout")
    if mt.responseIdx >= mt.responses.len:
      raise newException(TransportTimeoutError, "No more mock responses")
    let resp = mt.responses[mt.responseIdx]
    mt.responseIdx.inc
    return (data: resp.data, host: resp.host, port: resp.port)

proc makeDataPkt(blockNum: uint16, payload: seq[byte]): TftpPacket =
  TftpPacket(opcode: opData, blockNum: blockNum, data: payload)

proc makeAckPkt(blockNum: uint16): TftpPacket =
  TftpPacket(opcode: opAck, ackBlockNum: blockNum)

proc makeErrorPkt(code: TftpErrorCode, msg: string): TftpPacket =
  TftpPacket(opcode: opError, errorCode: code, errorMsg: msg)

# ============================================================
# recvPacket tests
# ============================================================

suite "Option bounds (D7 — protocol.nim single source of truth)":
  test "validateBlocksize clamps into [MinBlocksize, MaxBlocksize]":
    check protocol.validateBlocksize(0) == MinBlocksize
    check protocol.validateBlocksize(MinBlocksize) == MinBlocksize
    check protocol.validateBlocksize(1024) == 1024
    check protocol.validateBlocksize(MaxBlocksize) == MaxBlocksize
    check protocol.validateBlocksize(999_999) == MaxBlocksize

  test "validateWindowsize clamps into [MinWindowsize, MaxWindowsize]":
    check protocol.validateWindowsize(0) == MinWindowsize
    check protocol.validateWindowsize(MinWindowsize) == MinWindowsize
    check protocol.validateWindowsize(4) == 4
    check protocol.validateWindowsize(MaxWindowsize) == MaxWindowsize
    check protocol.validateWindowsize(999_999) == MaxWindowsize

  test "validateTimeoutOpt accepts only 1..255 (RFC 2349)":
    check MinTimeoutOpt == 1
    check MaxTimeoutOpt == 255
    check protocol.validateTimeoutOpt(0) == false
    check protocol.validateTimeoutOpt(1) == true
    check protocol.validateTimeoutOpt(255) == true
    check protocol.validateTimeoutOpt(256) == false

  test "newTransferConfig still clamps blocksize/windowsize via the relocated predicates":
    let cfg = newTransferConfig(blocksize = 999_999, windowsize = 0)
    check cfg.blocksize == MaxBlocksize
    check cfg.windowsize == MinWindowsize

  test "newTransferConfig clamps timeout into [MinTimeoutOpt, MaxTimeoutOpt] (D5 client outbound)":
    check newTransferConfig(timeout = 0).timeout == MinTimeoutOpt
    check newTransferConfig(timeout = 300).timeout == MaxTimeoutOpt
    check newTransferConfig(timeout = 30).timeout == 30  # in-range: unchanged

suite "Adaptive timeout (RFC 1123)":
  test "peer starts with no adaptive timeout":
    let peer = newPeer("10.0.0.1", 5000)
    check peer.srtt < 0
    check peer.adaptiveTimeout == 0
    check peer.effectiveTimeout(5000) == 5000  # falls back to config

  test "updateRtt sets adaptive timeout on first measurement":
    let peer = newPeer("10.0.0.1", 5000)
    peer.updateRtt(100.0)  # 100ms RTT
    check peer.srtt == 100.0
    check peer.adaptiveTimeout > 0
    # configTimeoutMs (500) is below the computed adaptive value here, so the
    # adaptive value still wins -- see the dedicated floor test below for the
    # case where the negotiated config value is the LARGER of the two.
    check peer.effectiveTimeout(500) == peer.adaptiveTimeout

  test "effectiveTimeout floors at the negotiated config value (D5, round-2 bug 4a)":
    let peer = newPeer("10.0.0.1", 5000)
    peer.updateRtt(100.0)  # adaptiveTimeout settles at 1000ms (the algorithm's floor)
    check peer.adaptiveTimeout == 1000
    # A peer that negotiated timeout=20s (20000ms) for a high-latency link
    # must keep that floor even though the adaptive sample is smaller --
    # discarding it was the bug (effectiveTimeout used to return
    # peer.adaptiveTimeout unconditionally once it was > 0).
    check peer.effectiveTimeout(20000) == 20000
    # Once adaptive refinement exceeds the negotiated floor, it still governs.
    for i in 0 ..< 10:
      peer.updateRtt(30_000.0)
    check peer.adaptiveTimeout > 20000
    check peer.effectiveTimeout(20000) == peer.adaptiveTimeout

  test "updateRtt converges with stable RTT":
    let peer = newPeer("10.0.0.1", 5000)
    for i in 0 ..< 10:
      peer.updateRtt(50.0)  # stable 50ms
    # SRTT should converge to ~50ms
    check peer.srtt > 45.0 and peer.srtt < 55.0
    # Timeout = SRTT + 4*RTTVAR, with small variance
    check peer.adaptiveTimeout >= 1000  # minimum 1000ms

  test "updateRtt adapts to increasing RTT":
    let peer = newPeer("10.0.0.1", 5000)
    # Start with low RTT
    for i in 0 ..< 5:
      peer.updateRtt(50.0)
    let srtt1 = peer.srtt
    # Shift to high RTT
    for i in 0 ..< 10:
      peer.updateRtt(500.0)
    # SRTT should have increased significantly
    check peer.srtt > srtt1 * 2

  test "recvPacket uses adaptive timeout after first response":
    let mt = newMock()
    mt.addResponse(makeAckPkt(1))
    mt.addResponse(makeAckPkt(2))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000)
    # First call establishes RTT
    discard waitFor recvPacket(mt.toTransport, config, peer, @[])
    check peer.adaptiveTimeout > 0
    # Second call uses adaptive timeout
    discard waitFor recvPacket(mt.toTransport, config, peer, @[])
    check peer.srtt >= 0

suite "recvPacket":
  test "returns valid decoded packet":
    let mt = newMock()
    mt.addResponse(makeAckPkt(1))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000)
    let pkt = waitFor recvPacket(mt.toTransport, config, peer, @[])
    check pkt.opcode == opAck
    check pkt.ackBlockNum == 1

  test "locks TID on first response":
    let mt = newMock()
    mt.addResponse(makeAckPkt(0), host = "10.0.0.99", port = 9999)
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 69)
    discard waitFor recvPacket(mt.toTransport, config, peer, @[])
    check peer.locked == true
    check peer.host == "10.0.0.99"
    check peer.port == 9999

  test "timeout retransmits lastSent then succeeds":
    let mt = newMock()
    mt.timeoutOnNext = 1
    mt.addResponse(makeAckPkt(1))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let lastSent = encode(TftpPacket(opcode: opData, blockNum: 1, data: @[byte 1]))
    let pkt = waitFor recvPacket(mt.toTransport, config, peer, lastSent)
    check pkt.opcode == opAck
    check mt.sentPackets.len == 1

  test "retry exhaustion raises TransferError":
    let mt = newMock()
    mt.timeoutOnNext = 100
    var config = newTransferConfig()
    config.retries = 2
    let peer = newPeer("10.0.0.1", 5000)
    expect(TransferError):
      discard waitFor recvPacket(mt.toTransport, config, peer, @[])

  test "TID mismatch sends ERROR and continues":
    let mt = newMock()
    mt.addResponse(makeAckPkt(0), host = "10.0.0.99", port = 6666)
    mt.addResponse(makeAckPkt(1), host = "10.0.0.1", port = 5000)
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let pkt = waitFor recvPacket(mt.toTransport, config, peer, @[])
    check pkt.opcode == opAck
    check pkt.ackBlockNum == 1
    check mt.sentPackets.len == 1
    let errPkt = decode(mt.sentPackets[0].data)
    check errPkt.opcode == opError

  test "corrupt packet skipped":
    let mt = newMock()
    mt.addRawResponse(@[byte 0xFF, 0xFF, 0x00])
    mt.addResponse(makeAckPkt(5))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000)
    let pkt = waitFor recvPacket(mt.toTransport, config, peer, @[])
    check pkt.ackBlockNum == 5

  test "error packet raises TransferError":
    let mt = newMock()
    mt.addResponse(makeErrorPkt(errFileNotFound, "No such file"))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000)
    try:
      discard waitFor recvPacket(mt.toTransport, config, peer, @[])
      fail()
    except TransferError as e:
      check "No such file" in e.msg

# ============================================================
# recvOnce R5 deadline tests (issue: dally deadline bypassable -> remote DoS)
#
# Bug: recvOnce's inner loop re-issued `transport.recv(.., timeoutMs)` with the
# SAME un-decremented timeoutMs on every decode-failure / TID-mismatch
# iteration, so a flood of garbage/off-TID packets (faster than one per
# timeout) kept resetting the receive window and held recvOnce -- and thus
# dallyAfterFinalAck and its coroutine/transfer slot -- alive indefinitely.
# Fix: recvOnce must bound its ENTIRE internal loop by one absolute wall-clock
# deadline derived from the caller-supplied timeoutMs, passing the shrinking
# remaining budget to each transport.recv call.
# ============================================================

suite "recvOnce R5 deadline (bounded by ONE wall-clock budget, not reset per iteration)":
  test "a flood of decode-fail packets cannot extend recvOnce past its single timeout budget":
    let mt = newMock()
    mt.recvDelayMs = 20  # real elapsed time per iteration, so the deadline can bind
    for i in 0 ..< 500:
      mt.addRawResponse(@[byte 0])  # 1 byte: too short to decode -> TftpDecodeError -> continue
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let outcome = waitFor recvOnce(mt.toTransport, config, peer, 200)  # 200ms budget, 20ms/iter
    check outcome.ok == false
    # Before the fix: timeoutMs never shrinks, so the loop only stops once the
    # 500 queued garbage packets are exhausted -- consuming all of them.
    # After the fix: the deadline binds after roughly 200/20 = 10 iterations,
    # leaving the vast majority of the flood unconsumed.
    check mt.responseIdx < 500
    check mt.recvTimeoutsMs.len < 500
    # The per-call timeout budget passed to transport.recv must strictly
    # shrink call over call -- the direct signature of the bug (constant
    # timeoutMs == the reset-the-window defect).
    for i in 1 ..< mt.recvTimeoutsMs.len:
      check mt.recvTimeoutsMs[i] < mt.recvTimeoutsMs[i - 1]
    # The very first call should see essentially the full 200ms budget (a
    # sub-millisecond bookkeeping gap between capturing the deadline and the
    # first remaining-budget computation is fine; a fixed, non-flaky
    # tolerance avoids asserting exact floating-point equality on wall time).
    check mt.recvTimeoutsMs[0] in 190..200

  test "a flood of TID-mismatched packets cannot extend recvOnce past its single timeout budget":
    let mt = newMock()
    mt.recvDelayMs = 20
    for i in 0 ..< 500:
      mt.addResponse(makeAckPkt(0), host = "10.0.0.99", port = 9999)  # wrong TID
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)  # locked to a DIFFERENT peer
    let outcome = waitFor recvOnce(mt.toTransport, config, peer, 200)
    check outcome.ok == false
    check mt.responseIdx < 500
    check mt.recvTimeoutsMs.len < 500
    for i in 1 ..< mt.recvTimeoutsMs.len:
      check mt.recvTimeoutsMs[i] < mt.recvTimeoutsMs[i - 1]
    # Every mismatched packet still gets an "Unknown transfer ID" ERROR reply.
    check mt.sentPackets.len == mt.recvTimeoutsMs.len

  test "a genuine TID-matched packet still returns immediately (happy path unaffected)":
    let mt = newMock()
    mt.addResponse(makeAckPkt(1))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let outcome = waitFor recvOnce(mt.toTransport, config, peer, 5000)
    check outcome.ok == true
    check outcome.pkt.ackBlockNum == 1
    check mt.recvTimeoutsMs.len == 1
    check mt.recvTimeoutsMs[0] in 4990..5000

  test "dallyAfterFinalAck returns within the single-timeout bound despite a decode-fail flood":
    let mt = newMock()
    mt.recvDelayMs = 20
    for i in 0 ..< 500:
      mt.addRawResponse(@[byte 0])
    var config = newTransferConfig()
    config.timeout = 1  # 1s config timeout -> effectiveTimeout floors at 1000ms
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let finalAck = encode(makeAckPkt(5))
    waitFor dallyAfterFinalAck(mt.toTransport, peer, config, finalAck, 5'u16)
    # No valid final-DATA retransmit ever arrived, so no re-ACK should fire --
    # but critically the call must RETURN (bounded by config.timeout, ~1000ms /
    # 20ms per iter =~ 50 iterations) rather than consuming the full 500-packet
    # flood (which the pre-fix reset bug would have required).
    check mt.sentPackets.len == 0
    check mt.responseIdx < 500

suite "recvBlocks":
  test "single block transfer":
    let mt = newMock()
    mt.addResponse(makeDataPkt(1, @[byte 1, 2, 3]))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var received: seq[byte] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData)
    check result.success == true
    check result.bytesTransferred == 3
    check received == @[byte 1, 2, 3]

  test "multi-block transfer":
    let mt = newMock()
    let fullBlock = newSeq[byte](512)
    mt.addResponse(makeDataPkt(1, fullBlock))
    mt.addResponse(makeDataPkt(2, fullBlock))
    mt.addResponse(makeDataPkt(3, @[byte 0xFF]))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var blocks: seq[uint16] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) = blocks.add blockNum
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData)
    check result.success == true
    check blocks == @[1'u16, 2, 3]
    check result.bytesTransferred == 512 + 512 + 1

  test "zero-length final block":
    let mt = newMock()
    mt.addResponse(makeDataPkt(1, newSeq[byte](512)))
    mt.addResponse(makeDataPkt(2, @[]))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData)
    check result.success == true
    check result.bytesTransferred == 512

  test "duplicate block re-ACKed but not delivered":
    let mt = newMock()
    let fullBlock = newSeq[byte](512)
    mt.addResponse(makeDataPkt(1, fullBlock))
    mt.addResponse(makeDataPkt(1, fullBlock))
    mt.addResponse(makeDataPkt(2, @[byte 1]))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var blocks: seq[uint16] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) = blocks.add blockNum
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData)
    check result.success == true
    check blocks == @[1'u16, 2]

  test "cancel stops transfer":
    let mt = newMock()
    for i in 1'u16 .. 100'u16:
      mt.addResponse(makeDataPkt(i, newSeq[byte](512)))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var count = 0
    let onData = proc(blockNum: uint16, data: seq[byte]) = count.inc
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData,
                                     cancelCheck = proc(): bool = count >= 3)
    check result.success == false
    check "cancelled" in result.errorMsg.toLowerAscii

  test "progress callback fires":
    let mt = newMock()
    mt.addResponse(makeDataPkt(1, newSeq[byte](512)))
    mt.addResponse(makeDataPkt(2, @[byte 1]))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var progressCalls: seq[int64] = @[]
    let onProgress = proc(b: int64, t: int64) = progressCalls.add b
    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData, onProgress)
    check result.success == true
    check progressCalls == @[int64 512, 513]

  test "error from server fails transfer":
    let mt = newMock()
    mt.addResponse(makeErrorPkt(errAccessViolation, "Denied"))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData)
    check result.success == false
    check "Denied" in result.errorMsg

suite "recvBlocks windowed (RFC 7440)":
  test "windowsize=2 receives 2 blocks then ACKs the last":
    let mt = newMock()
    # Server sends window of 2 blocks, expects ACK of block 2
    mt.addResponse(makeDataPkt(1, newSeq[byte](512)))
    mt.addResponse(makeDataPkt(2, @[byte 0xAB]))  # short = final

    let config = newTransferConfig(windowsize = 2)
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var blocks: seq[uint16] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) = blocks.add blockNum
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData)
    check result.success == true
    check blocks == @[1'u16, 2]
    check result.bytesTransferred == 512 + 1
    # Should ACK only block 2 (cumulative, covers 1 and 2)
    # With ws=2: receive block 1 (don't ACK yet), receive block 2 (ACK block 2)
    check mt.sentPackets.len >= 1
    let lastAck = decode(mt.sentPackets[^1].data)
    check lastAck.opcode == opAck
    check lastAck.ackBlockNum == 2

  test "windowsize=3 multi-window download":
    let mt = newMock()
    let fullBlock = newSeq[byte](512)
    # Window 1: blocks 1,2,3
    mt.addResponse(makeDataPkt(1, fullBlock))
    mt.addResponse(makeDataPkt(2, fullBlock))
    mt.addResponse(makeDataPkt(3, fullBlock))
    # Window 2: blocks 4,5 (block 5 is final)
    mt.addResponse(makeDataPkt(4, fullBlock))
    mt.addResponse(makeDataPkt(5, @[byte 1]))

    let config = newTransferConfig(windowsize = 3)
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var blocks: seq[uint16] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) = blocks.add blockNum
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData)
    check result.success == true
    check blocks == @[1'u16, 2, 3, 4, 5]
    check result.bytesTransferred == 512 * 4 + 1

  test "windowsize=1 behaves identically to lock-step":
    let mt = newMock()
    mt.addResponse(makeDataPkt(1, newSeq[byte](512)))
    mt.addResponse(makeDataPkt(2, @[byte 1]))

    let config = newTransferConfig(windowsize = 1)
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var blocks: seq[uint16] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) = blocks.add blockNum
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData)
    check result.success == true
    check blocks == @[1'u16, 2]
    # Lock-step: ACK after each block
    check mt.sentPackets.len == 2

suite "recvBlocks gap-ACK / duplicate re-ACK (RFC 7440, D6)":
  test "duplicate branch re-ACKs the last IN-ORDER block, not the stale duplicate's own number":
    # windowsize=3: blocks 1 and 2 are received but NOT yet ACKed (only 2 of
    # the 3 blocks needed to cross the window threshold). A duplicate re-send
    # of block 1 then arrives. Pre-D6 bug: the duplicate branch echoed
    # pkt.blockNum (1) directly; the fix re-ACKs lastInOrderBlock(expectedBlock)
    # (2) -- the receiver's true highest in-order progress.
    let mt = newMock()
    let fullBlock = newSeq[byte](512)
    mt.addResponse(makeDataPkt(1, fullBlock))
    mt.addResponse(makeDataPkt(2, fullBlock))
    mt.addResponse(makeDataPkt(1, fullBlock))   # stale duplicate of block 1
    mt.addResponse(makeDataPkt(3, @[byte 0xFF])) # final block, completes the transfer

    let config = newTransferConfig(windowsize = 3)
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var blocks: seq[uint16] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) = blocks.add blockNum
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData)
    check result.success == true
    check blocks == @[1'u16, 2, 3]
    # The duplicate's re-ACK is the FIRST packet this call ever sends (blocks
    # 1/2 alone never crossed the windowsize=3 threshold).
    check mt.sentPackets.len == 2
    check decode(mt.sentPackets[0].data).ackBlockNum == 2   # NOT 1
    check decode(mt.sentPackets[1].data).ackBlockNum == 3   # final block

  test "gap-ACK underflow guard: expectedBlock == 0 does not raise a Defect (block-2-first arrival)":
    # A direct, synthetic call with startBlock = 0 (production callers only
    # ever pass 1 or 2 -- see engine.nim/server.nim -- but D6's underflow
    # guard must hold regardless, defensively). DATA(1) arrives first with
    # nothing preceding it: expectedBlock stays at 0, pkt.blockNum(1) > 0 is a
    # gap. The re-ACK target computes as `expectedBlock - 1`, which
    # underflows an unguarded uint16 to 65535 (an OverflowDefect escaping
    # `except CatchableError` -- the tracked never-throw Defect hazard). The
    # guard must compute target == 0 instead, and — since lastAckedBlock is
    # seeded from the very same guarded helper at startBlock=0 — this reads
    # as a window-boundary gap (target already "acked"), firing
    # dupAckThreshold times.
    let mt = newMock()
    mt.addResponse(makeDataPkt(1, @[byte 1, 2, 3]))
    # retries=0: once the gap-ACKs fire, no more mock responses exist and the
    # call must fail cleanly on the very next timeout, rather than recvPacket's
    # own resend-on-timeout loop padding sentPackets with further copies of
    # `lastSent` -- keeps this test's packet count pinned to exactly the
    # gap-ACK firing under test.
    let config = newTransferConfig(retries = 0)
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 0'u16, onData)
    # No more mock responses after the gap-ACKs -> the call ultimately times
    # out and reports failure. That's expected and NOT what's under test;
    # what matters is that no Defect escaped and the guard produced ACK(0).
    check result.success == false
    check mt.sentPackets.len == 2
    check decode(mt.sentPackets[0].data).ackBlockNum == 0
    check decode(mt.sentPackets[1].data).ackBlockNum == 0

  test "recvBlocks dallies after the final ACK and re-ACKs a retransmitted final DATA (D2)":
    # The sender's final DATA arrives twice -- as if our first final ACK was
    # lost and the sender retransmitted. recvBlocks' epilogue (dallyAfterFinalAck)
    # must re-ACK the retransmit rather than returning without a second look.
    let mt = newMock()
    mt.addResponse(makeDataPkt(1, @[byte 0xAB]))   # final block (short -> triggers dally)
    mt.addResponse(makeDataPkt(1, @[byte 0xAB]))   # sender's retransmitted final DATA
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor recvBlocks(mt.toTransport, config, peer, 1, onData)
    check result.success == true
    check mt.sentPackets.len == 2
    check decode(mt.sentPackets[0].data).ackBlockNum == 1
    check decode(mt.sentPackets[1].data).ackBlockNum == 1

# ============================================================
# dallyAfterFinalAck tests (RFC conformance-closure D2, policy R5)
# ============================================================

suite "dallyAfterFinalAck":
  test "re-ACKs a single retransmitted final DATA exactly once":
    let mt = newMock()
    mt.addResponse(makeDataPkt(5, @[byte 0xAB]))  # retransmitted final DATA
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let finalAck = encode(makeAckPkt(5))
    waitFor dallyAfterFinalAck(mt.toTransport, peer, config, finalAck, 5'u16)
    check mt.sentPackets.len == 1
    check decode(mt.sentPackets[0].data).ackBlockNum == 5

  test "re-ACK count is bounded by MaxDallyReacks even if more retransmits arrive":
    let mt = newMock()
    for i in 0 ..< MaxDallyReacks + 1:
      mt.addResponse(makeDataPkt(5, @[byte 0xAB]))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let finalAck = encode(makeAckPkt(5))
    waitFor dallyAfterFinalAck(mt.toTransport, peer, config, finalAck, 5'u16)
    check mt.sentPackets.len == MaxDallyReacks

  test "exits on the deadline with no spurious resend when nothing arrives":
    let mt = newMock()  # no responses queued: every recv times out
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let finalAck = encode(makeAckPkt(5))
    waitFor dallyAfterFinalAck(mt.toTransport, peer, config, finalAck, 5'u16)
    check mt.sentPackets.len == 0

  test "off-target packets are ignored without consuming a re-ACK":
    let mt = newMock()
    mt.addResponse(makeAckPkt(5))               # off-target: wrong opcode
    mt.addResponse(makeDataPkt(3, @[byte 1]))   # off-target: wrong block number
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let finalAck = encode(makeAckPkt(5))
    waitFor dallyAfterFinalAck(mt.toTransport, peer, config, finalAck, 5'u16)
    check mt.sentPackets.len == 0

# ============================================================
# sendBlocks tests
# ============================================================

suite "sendBlocks":
  test "single block upload":
    let mt = newMock()
    mt.addResponse(makeAckPkt(1))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let fileData = @[byte 1, 2, 3]
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      if blockNum == 1: fileData else: @[]
    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData)
    check result.success == true
    check result.bytesTransferred == 3

  test "a readData that raises CatchableError fails sendBlocks' Future cleanly (L1, never-throw hazard)":
    # netasciiReader's readData used to `doAssert` on a broken invariant --
    # an uncatchable AssertionDefect that would crash the process. It now
    # raises a plain CatchableError instead. sendBlocks itself has no
    # try/except around its readData call (see fillWindow/sendOneBlock
    # above) -- under Nim's async transform, a synchronous raise inside an
    # {.async.} proc's body is captured into the returned Future's failure
    # state, not thrown at the call site. This test confirms that: the
    # Future sendBlocks returns is `failed`, carrying the original message,
    # and is observable via an ordinary `except CatchableError` -- exactly
    # the shape api.nim's `fut.addCallback`/`fut.failed` and server.nim's
    # `run`'s `hf.addCallback`/`hf.failed` already handle, so this
    # degrades to a clean transfer failure rather than a new escape.
    let mt = newMock()
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      raise newException(ValueError, "simulated reader invariant violation")
    let fut = sendBlocks(mt.toTransport, config, peer, 1, readData)
    var caught = false
    var msg = ""
    try:
      discard waitFor fut
    except CatchableError as e:
      caught = true
      msg = e.msg
    check caught
    check msg.contains("simulated reader invariant violation")
    check fut.failed

  test "multi-block upload":
    let mt = newMock()
    mt.addResponse(makeAckPkt(1))
    mt.addResponse(makeAckPkt(2))
    mt.addResponse(makeAckPkt(3))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let fullBlock = newSeq[byte](512)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      case blockNum
      of 1, 2: fullBlock
      of 3: @[byte 0xAB]
      else: @[]
    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData)
    check result.success == true
    check result.bytesTransferred == 512 + 512 + 1

  test "zero-length final block":
    let mt = newMock()
    mt.addResponse(makeAckPkt(1))
    mt.addResponse(makeAckPkt(2))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      if blockNum == 1: newSeq[byte](512)
      elif blockNum == 2: @[]
      else: @[]
    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData)
    check result.success == true
    check result.bytesTransferred == 512

  test "duplicate ACK ignored":
    let mt = newMock()
    mt.addResponse(makeAckPkt(1))
    mt.addResponse(makeAckPkt(1))
    mt.addResponse(makeAckPkt(2))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let fullBlock = newSeq[byte](512)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      case blockNum
      of 1: fullBlock
      of 2: @[byte 1]
      else: @[]
    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData)
    check result.success == true
    check result.bytesTransferred == 512 + 1

  test "cancel stops upload":
    let mt = newMock()
    for i in 1'u16 .. 100'u16:
      mt.addResponse(makeAckPkt(i))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var blocksSent = 0
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      blocksSent.inc; newSeq[byte](512)
    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData,
                                     cancelCheck = proc(): bool = blocksSent >= 3)
    check result.success == false
    check "cancelled" in result.errorMsg.toLowerAscii

  test "progress callback fires":
    let mt = newMock()
    mt.addResponse(makeAckPkt(1))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var progressCalled = false
    let onProgress = proc(b: int64, t: int64) = progressCalled = true
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      if blockNum == 1: @[byte 42] else: @[]
    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData, onProgress)
    check result.success == true
    check progressCalled == true

  test "error from peer fails transfer":
    let mt = newMock()
    mt.addResponse(makeErrorPkt(errDiskFull, "Disk full"))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] = @[byte 1]
    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData)
    check result.success == false
    check "Disk full" in result.errorMsg

  test "block 65535 limit":
    let mt = newMock()
    mt.addResponse(makeAckPkt(high(uint16)))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] = newSeq[byte](512)
    let result = waitFor sendBlocks(mt.toTransport, config, peer, high(uint16), readData)
    check result.success == false
    check "65535" in result.errorMsg

  # RFC checksum-integrity-error-hygiene, finding M8b: the Testing-strategy
  # section calls for "one test asserting a transfer exceeding the block-number
  # limit fails with no sidecar", which guards that sendBlocks' onDelivered
  # firing loop (transfer.nim ~232-251) stays BEFORE the `lastAcked ==
  # high(uint16)` early return (~259-262) -- a future reorder would silently
  # under-hash near the ceiling.
  #
  # LEVEL CHOSEN: sendBlocks, not a full server-level handleRrq(csMd5) RRQ.
  # handleRrq always calls sendBlocks with a hardcoded startBlock = 1 (no
  # test-only hook to jump near the ceiling), so proving the literal
  # server-level claim would require actually sending and ACKing ~65535 real
  # DATA blocks through the wire harness -- expensive, and this batch must not
  # touch server.nim to add a shortcut. Proving the invariant here is
  # equivalent: handleRrq's checksum digester is fed *exclusively* through
  # onDelivered, and its sidecar commit is strictly gated on
  # `xferResult.success` (server.nim: `if xferResult.success and digester !=
  # nil: ... commit`). The existing "block 65535 limit" test above already
  # proves sendBlocks reports success == false at the ceiling; this test
  # additionally proves the onDelivered firing loop still runs -- in
  # ascending order, exactly the genuinely-confirmed block, nothing past the
  # ceiling -- immediately BEFORE that failing return, never after. A future
  # reorder that returned failure without ever running the firing loop (or
  # that fired for blocks beyond what was actually confirmed) would go RED
  # here: `deliveredBlocks` would end up empty (or wrong), even though the
  # ACK legitimately confirmed block 65535.
  test "block 65535 limit: onDelivered still fires for the confirmed block before the failing return":
    let mt = newMock()
    mt.addResponse(makeAckPkt(high(uint16)))
    let config = newTransferConfig()
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let blockPayload = newSeq[byte](512)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] = blockPayload
    var deliveredBlocks: seq[seq[byte]] = @[]
    let onDelivered = proc(data: openArray[byte]) =
      var chunk = newSeq[byte](data.len)
      for i in 0 ..< data.len: chunk[i] = data[i]
      deliveredBlocks.add chunk
    let result = waitFor sendBlocks(mt.toTransport, config, peer, high(uint16), readData,
                                    onDelivered = onDelivered)
    check result.success == false
    check "65535" in result.errorMsg
    check deliveredBlocks.len == 1
    check deliveredBlocks[0] == blockPayload

suite "sendBlocks windowed (RFC 7440)":
  test "windowsize=2 sends 2 blocks then waits for ACK":
    let mt = newMock()
    # Window of 2: server ACKs block 2 (covers 1 and 2)
    mt.addResponse(makeAckPkt(2))  # ACK for window [1,2]
    mt.addResponse(makeAckPkt(3))  # ACK for final block 3

    let config = newTransferConfig(windowsize = 2)
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let fullBlock = newSeq[byte](512)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      case blockNum
      of 1, 2: fullBlock
      of 3: @[byte 0xAB]  # short = final
      else: @[]

    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData)
    check result.success == true
    check result.bytesTransferred == 512 + 512 + 1

    # Should have sent: DATA(1), DATA(2), then after ACK(2): DATA(3)
    check mt.sentPackets.len == 3
    let pkt1 = decode(mt.sentPackets[0].data)
    let pkt2 = decode(mt.sentPackets[1].data)
    check pkt1.opcode == opData
    check pkt1.blockNum == 1
    check pkt2.opcode == opData
    check pkt2.blockNum == 2

  test "windowsize=3 single window completes":
    let mt = newMock()
    # 3 blocks all short enough to fit in one window, block 3 is final
    mt.addResponse(makeAckPkt(3))

    let config = newTransferConfig(windowsize = 3)
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      case blockNum
      of 1, 2: newSeq[byte](512)
      of 3: @[byte 1]
      else: @[]

    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData)
    check result.success == true
    check result.bytesTransferred == 512 + 512 + 1
    check mt.sentPackets.len == 3

  test "windowsize=1 behaves identically to lock-step":
    let mt = newMock()
    mt.addResponse(makeAckPkt(1))
    mt.addResponse(makeAckPkt(2))

    let config = newTransferConfig(windowsize = 1)
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      case blockNum
      of 1: newSeq[byte](512)
      of 2: @[byte 1]
      else: @[]

    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData)
    check result.success == true
    check result.bytesTransferred == 512 + 1
    # Lock-step: DATA(1), wait ACK(1), DATA(2), wait ACK(2)
    check mt.sentPackets.len == 2

  test "windowed progress fires for each block":
    let mt = newMock()
    mt.addResponse(makeAckPkt(2))  # ACK covers blocks 1 and 2

    let config = newTransferConfig(windowsize = 2)
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    var progressCalls: seq[int64] = @[]
    let onProgress = proc(b: int64, t: int64) = progressCalls.add b
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      case blockNum
      of 1: newSeq[byte](512)  # full block
      of 2: @[byte 1]          # short = final
      else: @[]

    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData, onProgress)
    check result.success == true
    check progressCalls.len == 2  # once per block sent
    check progressCalls[0] == 512
    check progressCalls[1] == 513

  test "partial ACK in window resumes correctly":
    # Client sends window [1,2,3], server ACKs only block 1 (lost 2 or 3)
    let mt = newMock()
    mt.addResponse(makeAckPkt(1))  # only ACKed block 1
    mt.addResponse(makeAckPkt(3))  # after retransmit, ACK block 3

    let config = newTransferConfig(windowsize = 3)
    let peer = newPeer("10.0.0.1", 5000, locked = true)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      case blockNum
      of 1, 2: newSeq[byte](512)
      of 3: @[byte 0xFF]
      else: @[]

    let result = waitFor sendBlocks(mt.toTransport, config, peer, 1, readData)
    check result.success == true
    check result.bytesTransferred == 512 + 512 + 1
