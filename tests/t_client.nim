import unittest
import std/[strutils, asyncdispatch, os]
import ../src/chapulin/protocol
import ../src/chapulin/engine
import ../src/chapulin/netascii
import ../src/chapulin/api
import helpers

suite "RRQ (getFile) basic flow":
  test "single block transfer":
    let mt = newMockTransport()
    let payload = @[byte 1, 2, 3, 4, 5]
    mt.addResponse(makeDataPkt(1, payload))

    var receivedData: seq[byte] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      receivedData.add data

    let config = newDefaultConfig()
    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "test.txt", onData)

    check result.success == true
    check result.bytesTransferred == 5
    check receivedData == payload

    # Should have sent: RRQ, then ACK for block 1
    check mt.sentPackets.len == 2
    let rrq = decode(mt.sentPackets[0].data)
    check rrq.opcode == opRrq
    check rrq.filename == "test.txt"
    let ack = decode(mt.sentPackets[1].data)
    check ack.opcode == opAck
    check ack.ackBlockNum == 1

  test "single-block GET dallies and re-ACKs a retransmitted final DATA (D2)":
    # Sender's final DATA arrives twice, as if the client's first final ACK
    # was lost and the sender retransmitted. getFile's single-block branch has
    # nothing left for recvBlocks' loop to receive -- dallyAfterFinalAck must
    # handle the retransmit directly.
    let mt = newMockTransport()
    let payload = @[byte 1, 2, 3, 4, 5]
    mt.addResponse(makeDataPkt(1, payload))
    mt.addResponse(makeDataPkt(1, payload))  # sender retransmits the final DATA

    var receivedData: seq[byte] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      receivedData.add data

    let config = newDefaultConfig()
    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "test.txt", onData)

    check result.success == true
    check result.bytesTransferred == 5
    # RRQ, ACK(1), then a second ACK(1) from the dally re-ACKing the retransmit
    check mt.sentPackets.len == 3
    let reAck = decode(mt.sentPackets[2].data)
    check reAck.opcode == opAck
    check reAck.ackBlockNum == 1

  test "multi-block transfer":
    let mt = newMockTransport()
    let config = newDefaultConfig()  # blocksize 512
    let fullBlock = newSeq[byte](512)
    let lastBlock = @[byte 0xFF, 0xFE]

    mt.addResponse(makeDataPkt(1, fullBlock))
    mt.addResponse(makeDataPkt(2, fullBlock))
    mt.addResponse(makeDataPkt(3, lastBlock))

    var receivedBlocks: seq[uint16] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      receivedBlocks.add blockNum

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "test.bin", onData)

    check result.success == true
    check result.bytesTransferred == 512 + 512 + 2
    check receivedBlocks == @[1'u16, 2, 3]
    # RRQ + 3 ACKs = 4 sent packets
    check mt.sentPackets.len == 4

  test "zero-length final block":
    let mt = newMockTransport()
    let config = newDefaultConfig()
    let fullBlock = newSeq[byte](512)

    mt.addResponse(makeDataPkt(1, fullBlock))
    mt.addResponse(makeDataPkt(2, @[]))  # empty = final

    var totalBytes: int64 = 0
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      totalBytes += data.len

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "exact.bin", onData)

    check result.success == true
    check result.bytesTransferred == 512

suite "RRQ error handling":
  test "server error mid-transfer":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    mt.addResponse(makeDataPkt(1, newSeq[byte](512)))
    mt.addResponse(makeErrorPkt(errFileNotFound, "File not found"))

    var blocksReceived = 0
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      blocksReceived.inc

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "missing.txt", onData)

    check result.success == false
    check "File not found" in result.errorMsg
    check blocksReceived == 1

  test "immediate server error":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    mt.addResponse(makeErrorPkt(errAccessViolation, "Permission denied"))

    let onData = proc(blockNum: uint16, data: seq[byte]) =
      discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "secret.txt", onData)

    check result.success == false
    check "Permission denied" in result.errorMsg
    check result.bytesTransferred == 0

suite "RRQ timeout and retransmit":
  test "timeout triggers retransmit then succeeds":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    mt.timeoutOnNext = 1  # first recv times out
    mt.addResponse(makeDataPkt(1, @[byte 42]))

    var receivedData: seq[byte] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      receivedData.add data

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "retry.txt", onData)

    check result.success == true
    check receivedData == @[byte 42]
    # Should have sent: RRQ, then RRQ again (retransmit), then ACK
    check mt.sentPackets.len == 3

  test "all retries exhausted":
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.retries = 2

    mt.timeoutOnNext = 10  # always timeout

    let onData = proc(blockNum: uint16, data: seq[byte]) =
      discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "gone.txt", onData)

    check result.success == false
    check "Timeout" in result.errorMsg

suite "RRQ handshake DoS bound (R2-1 — decode-fail/off-target packets must consume the attempt's budget)":
  # Bug: getFile's handshake loop called `transport.recv(.., config.timeout *
  # 1000)` directly and `continue`d on a decode-fail (`except
  # TftpDecodeError`) or an off-target DATA block (blockNum != 1) WITHOUT
  # consuming any of retryCount's budget. Since `transport.recv` arms a
  # FRESH full timeout every call, a peer flooding decodable-but-irrelevant
  # packets faster than `config.timeout` kept the loop alive forever --
  # `TransportTimeoutError` never fired, `retryCount` never advanced.
  # Fix: ONE absolute wall-clock deadline per retry attempt (mirroring
  # recvOnce's contract in transfer.nim); a decode-fail/off-target `continue`
  # loops on the SAME deadline's shrinking remaining budget instead of a
  # fresh one.
  test "a flood of decode-fail packets during the RRQ handshake wait cannot extend a retry attempt past its single timeout budget":
    let mt = newMockTransport()
    mt.recvDelayMs = 20  # real elapsed time per iteration, so the deadline can bind
    for i in 0 ..< 500:
      mt.addRawResponse(@[byte 0])  # 1 byte: too short to decode -> TftpDecodeError -> continue

    var config = newDefaultConfig()
    config.timeout = 1   # 1000ms budget
    config.retries = 0   # a single attempt -- isolates the per-attempt bound cleanly

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "flood.bin", onData)

    check result.success == false
    check "Timeout" in result.errorMsg
    # Before the fix: the loop only stops once the 500-packet flood is
    # exhausted (or never, for a larger/endless flood). After the fix: the
    # deadline binds after roughly 1000/20 = 50 iterations.
    check mt.responseIdx < 500
    check mt.recvTimeoutsMs.len < 500
    # The per-call timeout budget passed to transport.recv must strictly
    # shrink call over call within this single attempt -- the direct
    # signature of the bug (constant/reset timeoutMs).
    for i in 1 ..< mt.recvTimeoutsMs.len:
      check mt.recvTimeoutsMs[i] < mt.recvTimeoutsMs[i - 1]
    check mt.recvTimeoutsMs[0] in 990..1000

  test "a flood of off-target DATA blocks during the RRQ handshake wait cannot extend a retry attempt past its single timeout budget":
    let mt = newMockTransport()
    mt.recvDelayMs = 20
    for i in 0 ..< 500:
      mt.addResponse(makeDataPkt(99, @[byte 1]))  # decodable, but not block 1

    var config = newDefaultConfig()
    config.timeout = 1
    config.retries = 0

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "flood2.bin", onData)

    check result.success == false
    check mt.responseIdx < 500
    check mt.recvTimeoutsMs.len < 500
    for i in 1 ..< mt.recvTimeoutsMs.len:
      check mt.recvTimeoutsMs[i] < mt.recvTimeoutsMs[i - 1]
    check mt.recvTimeoutsMs[0] in 990..1000

  test "a genuine OACK arriving immediately still returns without waiting out the budget (happy path unaffected)":
    let mt = newMockTransport()
    mt.addResponse(makeOackPkt(@[("blksize", "1024")]))
    mt.addResponse(makeDataPkt(1, newSeq[byte](100)))

    var config = newDefaultConfig()
    config.blocksize = 1024

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "ok.bin", onData)

    check result.success == true
    # 3 recv calls total: the handshake OACK recv, recvBlocks' DATA(1) recv
    # (a 100-byte block is short of the negotiated 1024 -- final), and the
    # D2 dally epilogue's own recvOnce call after the final ACK.
    check mt.recvTimeoutsMs.len == 3

suite "WRQ handshake DoS bound (R2-1 — same class, sibling code path)":
  test "a flood of off-target ACKs during the WRQ handshake wait cannot extend a retry attempt past its single timeout budget":
    let mt = newMockTransport()
    mt.recvDelayMs = 20
    for i in 0 ..< 500:
      mt.addResponse(makeAckPkt(77))  # decodable, but not ACK(0)

    var config = newDefaultConfig()
    config.timeout = 1
    config.retries = 0

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] = @[byte 1]
    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "flood.bin", readData)

    check result.success == false
    check mt.responseIdx < 500
    check mt.recvTimeoutsMs.len < 500
    for i in 1 ..< mt.recvTimeoutsMs.len:
      check mt.recvTimeoutsMs[i] < mt.recvTimeoutsMs[i - 1]
    check mt.recvTimeoutsMs[0] in 990..1000

  test "a flood of decode-fail packets during the WRQ handshake wait cannot extend a retry attempt past its single timeout budget":
    let mt = newMockTransport()
    mt.recvDelayMs = 20
    for i in 0 ..< 500:
      mt.addRawResponse(@[byte 0])

    var config = newDefaultConfig()
    config.timeout = 1
    config.retries = 0

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] = @[byte 1]
    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "flood2.bin", readData)

    check result.success == false
    check mt.responseIdx < 500
    check mt.recvTimeoutsMs.len < 500
    for i in 1 ..< mt.recvTimeoutsMs.len:
      check mt.recvTimeoutsMs[i] < mt.recvTimeoutsMs[i - 1]

  test "cancel check stops the WRQ handshake wait (parity with getFile, which already has this check)":
    let mt = newMockTransport()
    mt.addResponse(makeAckPkt(0))

    let config = newDefaultConfig()
    let cancelCheck = proc(): bool = true  # cancel on the very first check

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] = @[byte 1]
    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "cancel.bin",
                         readData, nil, cancelCheck)

    check result.success == false
    check "cancelled" in result.errorMsg.toLowerAscii
    check mt.recvTimeoutsMs.len == 0  # cancelled before ever calling recv

suite "RRQ option negotiation":
  test "OACK with blocksize":
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.blocksize = 1024

    mt.addResponse(makeOackPkt(@[("blksize", "1024")]))
    # After OACK, server sends data with negotiated blocksize
    mt.addResponse(makeDataPkt(1, newSeq[byte](100)))  # short block = done

    var receivedData: seq[byte] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      receivedData.add data

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "big.bin", onData)

    check result.success == true
    check result.bytesTransferred == 100
    # Should have sent: RRQ, ACK(0) for OACK, ACK(1) for data
    check mt.sentPackets.len == 3
    let oackAck = decode(mt.sentPackets[1].data)
    check oackAck.opcode == opAck
    check oackAck.ackBlockNum == 0

  test "OACK with tsize":
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.requestTsize = true

    mt.addResponse(makeOackPkt(@[("tsize", "1024")]))
    mt.addResponse(makeDataPkt(1, @[byte 1]))

    var progressTotal: int64 = -1
    let onProgress = proc(bytesTransferred: int64, totalSize: int64) =
      progressTotal = totalSize

    let onData = proc(blockNum: uint16, data: seq[byte]) =
      discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "sized.bin",
                         onData, onProgress)

    check result.success == true
    check result.totalSize == 1024
    check progressTotal == 1024

  test "negotiated timeout governs the post-OACK recv, not just validation (D5 apply)":
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.timeout = 10  # client requests timeout=10

    # Server accepts option negotiation but returns a DIFFERENT, still-valid
    # timeout (20) -- legal per RFC 2349 (the server need not echo the
    # client's requested value verbatim, only stay in 1..255).
    mt.addResponse(makeOackPkt(@[("timeout", "20")]))
    mt.addResponse(makeDataPkt(1, @[byte 1, 2, 3]))  # short block = final

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "slow.bin", onData)

    check result.success == true
    # recvTimeoutsMs[0] is the pre-negotiation handshake recv (config.timeout
    # == 10s == 10000ms). recvTimeoutsMs[1] is recvBlocks' first recvPacket
    # call, made AFTER applyOack -- at that point peer.adaptiveTimeout is
    # still 0 (no RTT sample has been taken yet), so effectiveTimeout returns
    # the config value unmodified. If applyOack had NOT wired neg.timeout
    # into xferConfig, this would read 10000 (the stale requested value) or
    # 5000 (DefaultTimeout) instead of the negotiated 20000. recvTimeoutsMs[2]
    # is the D2 dally epilogue's own recvOnce call after the final ACK -- it
    # too must be governed by the negotiated timeout, not a stale/default one.
    # Its value is a wall-clock remaining-budget computation (deadline minus
    # epochTime()), so allow a small tolerance for real elapsed time rather
    # than asserting exact equality.
    check mt.recvTimeoutsMs.len == 3
    check mt.recvTimeoutsMs[0] == 10_000
    check mt.recvTimeoutsMs[1] == 20_000
    check abs(mt.recvTimeoutsMs[2] - 20_000) <= 50

  test "OACK omitting timeout must not clobber the client's configured timeout (Fix A)":
    # Client configures a non-default timeout AND a non-default blocksize.
    # The server's OACK grants only blksize -- omitting "timeout" entirely,
    # which is perfectly RFC-2349-legal (many servers negotiate blksize but
    # never touch timeout). validateAndParseOack must seed its negotiated
    # timeout from the client's OWN configured value (30), never from the
    # global DefaultTimeout (5) -- otherwise applyOack's unconditional
    # `xferConfig.timeout = neg.timeout` would silently downgrade the
    # client's configured 30s down to 5s on exactly the lossy links this
    # option exists to protect.
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.timeout = 30
    config.blocksize = 1024

    mt.addResponse(makeOackPkt(@[("blksize", "1024")]))  # timeout NOT echoed
    mt.addResponse(makeDataPkt(1, newSeq[byte](100)))  # short block = final

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "big.bin", onData)

    check result.success == true
    # recvTimeoutsMs[0] is the pre-negotiation handshake recv (config.timeout
    # == 30s == 30000ms). recvTimeoutsMs[1] is recvBlocks' first recv, made
    # AFTER applyOack -- at that point peer.adaptiveTimeout is still 0 (no
    # RTT sample yet), so effectiveTimeout returns the config value
    # unmodified. If the OACK's omission of "timeout" had clobbered
    # xferConfig.timeout down to DefaultTimeout, this would read 5000
    # instead of the client's configured 30000.
    check mt.recvTimeoutsMs.len == 3
    check mt.recvTimeoutsMs[0] == 30_000
    check mt.recvTimeoutsMs[1] == 30_000

suite "RRQ OACK timeout clamp (R2-3 fix a — engine seeds from xferConfig.timeout, not raw config.timeout)":
  test "OACK omitting timeout clamps an out-of-range HIGH client-configured timeout into range":
    # Client configures timeout=300, which is out of RFC 2349 range
    # (MaxTimeoutOpt == 255). `toTransferConfig` clamps this into
    # `xferConfig.timeout == 255` one line before the handshake loop. The
    # server's OACK grants only blksize, omitting "timeout" entirely
    # (RFC-2349-legal). Before the fix, engine.getFile passed the RAW,
    # unclamped `config.timeout` (300) as `validateAndParseOack`'s
    # `configuredTimeout` fallback seed, so `outcome.negotiated.timeout`
    # came back 300 -- an out-of-RFC-range value that then flowed straight
    # into `applyOack`'s unconditional `xferConfig.timeout = neg.timeout`,
    # itself never re-clamped.
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.timeout = 300     # out of range: MaxTimeoutOpt == 255
    config.blocksize = 1024

    mt.addResponse(makeOackPkt(@[("blksize", "1024")]))  # timeout NOT echoed
    mt.addResponse(makeDataPkt(1, newSeq[byte](100)))     # short block = final

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "big.bin", onData)

    check result.success == true
    # recvTimeoutsMs[0] is the PRE-negotiation HANDSHAKE recv -- the R3-1
    # site. Before that fix, engine.getFile seeded the handshake deadline
    # from the raw, unclamped `config.timeout` (300 -> 300_000ms) instead of
    # the already-clamped `xferConfig.timeout` (255 -> 255_000ms) that sits
    # one line above it. recvTimeoutsMs[1] is recvBlocks' first recv, made
    # AFTER applyOack -- it must reflect the CLAMPED 255s (255_000ms), never
    # the raw 300_000ms (the pre-fix bug) and never 0.
    check mt.recvTimeoutsMs.len == 3
    check mt.recvTimeoutsMs[0] == 255_000
    check mt.recvTimeoutsMs[1] == 255_000

  test "a zero client-configured timeout clamps to MinTimeoutOpt and the handshake recv is actually awaited (R3-1)":
    # Client configures timeout=0, out of range on the LOW end (MinTimeoutOpt
    # == 1). `toTransferConfig` clamps this into `xferConfig.timeout == 1`
    # one line before the handshake loop. Before the R3-1 fix, the handshake
    # deadline was seeded from the raw `config.timeout.float` (0.0), which
    # collapses `deadline` to essentially "now" -- the loop's very first
    # `remainingMs <= 0` check fires before `transport.recv` is EVER called,
    # so every retry burns instantly and the transfer fails without a single
    # real recv attempt. Seeding from `xferConfig.timeout` (clamped to 1s)
    # gives the first attempt a genuine ~1000ms budget, so the mocked OACK
    # response is actually received and the transfer succeeds.
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.timeout = 0       # out of range: MinTimeoutOpt == 1
    config.blocksize = 1024

    mt.addResponse(makeOackPkt(@[("blksize", "1024")]))  # timeout NOT echoed
    mt.addResponse(makeDataPkt(1, newSeq[byte](100)))     # short block = final

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "big.bin", onData)

    check result.success == true
    # A pre-fix run never reaches a single transport.recv call (all 3 retries
    # burn on the collapsed deadline before the loop's recv line), so
    # recvTimeoutsMs stays empty and the transfer fails outright -- both of
    # which the checks below rule out.
    check mt.recvTimeoutsMs.len == 3
    check mt.recvTimeoutsMs[0] == MinTimeoutOpt * 1000
    check mt.recvTimeoutsMs[1] == MinTimeoutOpt * 1000

suite "RRQ OACK validation -> ERROR(8)":
  test "unrequested-but-in-range OACK option is filtered, never applied":
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.blocksize = 1024  # only blksize requested

    # Rogue/generous server foists an in-range windowsize the client never asked for.
    mt.addResponse(makeOackPkt(@[("blksize", "1024"), ("windowsize", "8")]))
    mt.addResponse(makeDataPkt(1, newSeq[byte](50)))  # short block = done

    var negotiatedWindowsize = -1
    let onNegotiated = proc(blocksize: int, windowsize: int) =
      negotiatedWindowsize = windowsize

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "big.bin", onData,
                                 nil, nil, onNegotiated)

    check result.success == true
    check negotiatedWindowsize == DefaultWindowsize  # NOT 8 -- proves enforcement, not just validation

  test "bad OACK value for a requested option sends ERROR(8) and surfaces errorCode 8":
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.timeout = 10  # requests timeout=10

    mt.addResponse(makeOackPkt(@[("timeout", "0")]))  # rogue server returns out-of-range value

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "rogue.bin", onData)

    check result.success == false
    check result.errorCode == ord(errOptionNegotiation)
    check result.errorCode == 8

    # The client must tell the server, not just fail locally.
    check mt.sentPackets.len == 2  # RRQ, then ERROR
    let errPkt = decode(mt.sentPackets[1].data)
    check errPkt.opcode == opError
    check errPkt.errorCode == errOptionNegotiation
    check "/" notin errPkt.errorMsg  # path-free message

suite "RRQ duplicate block handling":
  test "duplicate block is re-ACKed and ignored":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    mt.addResponse(makeDataPkt(1, newSeq[byte](512)))
    mt.addResponse(makeDataPkt(1, newSeq[byte](512)))  # duplicate
    mt.addResponse(makeDataPkt(2, @[byte 1]))  # final

    var blocksReceived: seq[uint16] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      blocksReceived.add blockNum

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "dup.bin", onData)

    check result.success == true
    check blocksReceived == @[1'u16, 2]

suite "RRQ cancellation":
  test "cancel check stops transfer":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    mt.addResponse(makeDataPkt(1, newSeq[byte](512)))
    mt.addResponse(makeDataPkt(2, @[byte 1]))

    var callCount = 0
    let cancelCheck = proc(): bool =
      callCount.inc
      callCount > 1  # cancel after first iteration

    let onData = proc(blockNum: uint16, data: seq[byte]) =
      discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "cancel.bin",
                         onData, nil, cancelCheck)

    check result.success == false
    check "cancelled" in result.errorMsg.toLowerAscii

suite "RRQ progress callback":
  test "progress fires for each block":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    mt.addResponse(makeDataPkt(1, newSeq[byte](512)))
    mt.addResponse(makeDataPkt(2, newSeq[byte](512)))
    mt.addResponse(makeDataPkt(3, @[byte 1]))

    var progressCalls: seq[int64] = @[]
    let onProgress = proc(bytesTransferred: int64, totalSize: int64) =
      progressCalls.add bytesTransferred

    let onData = proc(blockNum: uint16, data: seq[byte]) =
      discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "progress.bin",
                         onData, onProgress)

    check result.success == true
    check progressCalls == @[int64 512, 1024, 1025]

suite "WRQ (putFile) basic flow":
  test "single block upload":
    let mt = newMockTransport()
    let config = newDefaultConfig()
    let fileData = @[byte 1, 2, 3]

    mt.addResponse(makeAckPkt(0))  # ACK for WRQ
    mt.addResponse(makeAckPkt(1))  # ACK for data block 1

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      if blockNum == 1: fileData
      else: @[]

    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "upload.txt", readData)

    check result.success == true
    check result.bytesTransferred == 3

    # Should have sent: WRQ, DATA(1)
    check mt.sentPackets.len >= 2
    let wrq = decode(mt.sentPackets[0].data)
    check wrq.opcode == opWrq
    check wrq.filename == "upload.txt"

  test "multi-block upload":
    let mt = newMockTransport()
    let config = newDefaultConfig()
    let fullBlock = newSeq[byte](512)
    let lastBlock = @[byte 0xAB]

    mt.addResponse(makeAckPkt(0))  # ACK for WRQ
    mt.addResponse(makeAckPkt(1))  # ACK for block 1
    mt.addResponse(makeAckPkt(2))  # ACK for block 2
    mt.addResponse(makeAckPkt(3))  # ACK for block 3 (final)

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      case blockNum
      of 1, 2: fullBlock
      of 3: lastBlock
      else: @[]

    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "big.bin", readData)

    check result.success == true
    check result.bytesTransferred == 512 + 512 + 1

suite "WRQ netascii send side (RFC-conformance-closure D1b/d, slice 7a)":
  test "client suppresses outbound tsize under netascii (D1d, client-side specifics)":
    # engine.clientBuildOptions: requestTsize = config.requestTsize and
    # config.mode != tmNetascii -- even though the caller asked for tsize,
    # netascii must never see it on the wire (translation makes the
    # pre-negotiation size meaningless).
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.mode = tmNetascii
    config.requestTsize = true
    config.tsize = 42

    mt.addResponse(makeAckPkt(0))
    mt.addResponse(makeAckPkt(1))

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      if blockNum == 1: @[byte 1] else: @[]

    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "up.txt", readData)
    check result.success == true

    let wrq = decode(mt.sentPackets[0].data)
    check wrq.opcode == opWrq
    check wrq.mode == tmNetascii
    for (k, v) in wrq.options:
      check k != "tsize"

  test "client PUT under netascii encodes local LF as wire CR LF via netasciiReader":
    # Wires netasciiReader (server.nim's D1b block-chunking read adapter, also
    # used client-side per D1d(3)) directly into putFile's readData param --
    # proves the reader's output actually reaches the wire DATA payload
    # untouched by any further seek-addressed re-reading.
    let path = getTempDir() / "t_client_netascii_put.tmp"
    writeFile(path, "AB\nCD")  # local bytes: A, B, LF, C, D (5 bytes)
    let f = open(path, fmRead)
    var enc: NetasciiEncoder
    let reader = netasciiReader(f, enc)

    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.mode = tmNetascii

    mt.addResponse(makeAckPkt(0))
    mt.addResponse(makeAckPkt(1))

    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "netascii.txt", reader)
    f.close()
    removeFile(path)

    check result.success == true
    # Wire bytes: A, B, CR, LF, C, D (6 bytes) -- the local LF became CR LF.
    let sentData = decode(mt.sentPackets[1].data)
    check sentData.opcode == opData
    check sentData.data == @[byte('A'), byte('B'), byte('\r'), byte('\n'), byte('C'), byte('D')]
    check result.bytesTransferred == 6

suite "RRQ netascii recv side (RFC-conformance-closure D1c/d, slice 7b)":
  test "client suppresses outbound tsize under netascii on GET too (shared clientBuildOptions, D1d)":
    # engine.clientBuildOptions is the SAME site putFile uses (7a) -- getFile
    # calls it too, so the receive-side tsize suppression needs no distinct
    # site; this pins that sharing rather than re-deriving it.
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.mode = tmNetascii
    config.requestTsize = true
    config.tsize = 42

    mt.addResponse(makeDataPkt(1, @[byte('x')]))

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "down.txt", onData)
    check result.success == true

    let rrq = decode(mt.sentPackets[0].data)
    check rrq.opcode == opRrq
    check rrq.mode == tmNetascii
    for (k, v) in rrq.options:
      check k != "tsize"

  test "client GET under netascii decodes wire CR LF as local LF via NetasciiDecoder":
    # Mirrors tdGet's own onData shape (api.nim ~:266-296): feed each block
    # through a NetasciiDecoder, write the decoded bytes, and call
    # finishNetasciiDecode at the block recognized as final (data.len <
    # negotiated blocksize) -- proving the decode+write path reproduces the
    # api.nim client GET call site without going through the session queue.
    let path = getTempDir() / "t_client_netascii_get.tmp"
    let mt = newMockTransport()
    let wireBytes = @[byte('A'), byte('B'), byte('\r'), byte('\n'),
                      byte('C'), byte('D'), byte('\r'), byte(0),
                      byte('E'), byte('F')]
    mt.addResponse(makeDataPkt(1, wireBytes))

    var config = newDefaultConfig()
    config.mode = tmNetascii

    var gfile = open(path, fmWrite)
    var dec: NetasciiDecoder
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      let decoded = dec.feed(data)
      if decoded.len > 0:
        discard gfile.writeBytes(decoded, 0, decoded.len)
      if data.len < config.blocksize:
        finishNetasciiDecode(gfile, dec, true)

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "netascii_get.txt", onData)
    gfile.close()

    check result.success == true
    let content = readFile(path)
    removeFile(path)
    # Wire "AB" CR LF "CD" CR NUL "EF" -> local "AB" LF "CD" CR "EF".
    check content == "AB" & "\n" & "CD" & "\r" & "EF"

suite "WRQ error handling":
  test "server rejects upload":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    mt.addResponse(makeErrorPkt(errAccessViolation, "Write denied"))

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      @[byte 1]

    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "denied.txt", readData)

    check result.success == false
    check "Write denied" in result.errorMsg

suite "WRQ option negotiation":
  test "OACK with blocksize on upload":
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.blocksize = 1024

    mt.addResponse(makeOackPkt(@[("blksize", "1024")]))
    mt.addResponse(makeAckPkt(1))  # ACK for first (and only) data block

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      if blockNum == 1: @[byte 1, 2, 3]
      else: @[]

    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "oack_upload.bin", readData)

    check result.success == true
    check result.bytesTransferred == 3

suite "WRQ OACK validation -> ERROR(8)":
  test "bad OACK value for a requested option sends ERROR(8) and surfaces errorCode 8":
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.blocksize = 1024  # requests blksize=1024

    mt.addResponse(makeOackPkt(@[("blksize", "2048")]))  # rogue: larger than requested

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] = @[byte 1]

    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "rogue_upload.bin", readData)

    check result.success == false
    check result.errorCode == ord(errOptionNegotiation)

    check mt.sentPackets.len == 2  # WRQ, then ERROR
    let errPkt = decode(mt.sentPackets[1].data)
    check errPkt.opcode == opError
    check errPkt.errorCode == errOptionNegotiation

suite "WRQ timeout":
  test "timeout on upload retransmits":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    mt.timeoutOnNext = 1  # first recv times out
    mt.addResponse(makeAckPkt(0))
    mt.addResponse(makeAckPkt(1))

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      if blockNum == 1: @[byte 99]
      else: @[]

    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "retry_up.txt", readData)

    check result.success == true
    # WRQ sent twice (original + retransmit), then DATA
    check mt.sentPackets.len >= 3

suite "WRQ duplicate/stale ACK handling":
  test "duplicate ACK for previous block is ignored":
    let mt = newMockTransport()
    let config = newDefaultConfig()
    let fullBlock = newSeq[byte](512)

    mt.addResponse(makeAckPkt(0))   # ACK for WRQ
    mt.addResponse(makeAckPkt(1))   # ACK for block 1
    mt.addResponse(makeAckPkt(1))   # duplicate ACK for block 1 (stale)
    mt.addResponse(makeAckPkt(2))   # ACK for block 2 (final)

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      case blockNum
      of 1: fullBlock
      of 2: @[byte 0xAA]  # short = final
      else: @[]

    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "dup_ack.bin", readData)

    check result.success == true
    check result.bytesTransferred == 512 + 1

  test "ACK for block 0 repeated after first DATA is ignored":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    mt.addResponse(makeAckPkt(0))   # ACK for WRQ
    mt.addResponse(makeAckPkt(0))   # stale duplicate ACK(0)
    mt.addResponse(makeAckPkt(1))   # real ACK for block 1

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      if blockNum == 1: @[byte 1]
      else: @[]

    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "stale0.bin", readData)

    check result.success == true

suite "WRQ cancellation":
  test "cancel stops upload":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    mt.addResponse(makeAckPkt(0))
    for i in 1'u16 .. 100'u16:
      mt.addResponse(makeAckPkt(i))

    var blocksSent = 0
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      blocksSent.inc
      newSeq[byte](512)

    let cancelAfter = 3
    let result = waitFor putFile(mt.toTransport, config, "127.0.0.1", 69, "cancel_up.bin",
                         readData, nil,
                         cancelCheck = proc(): bool = blocksSent >= cancelAfter)

    check result.success == false
    check "cancelled" in result.errorMsg.toLowerAscii

suite "Block number boundary":
  test "getFile handles block near uint16 max":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    # Simulate receiving block 65534 and 65535 (final)
    mt.addResponse(makeDataPkt(65534, newSeq[byte](512)))
    mt.addResponse(makeDataPkt(65535, @[byte 1]))  # short = done

    var received: seq[uint16] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      received.add blockNum

    # We need to trick the client into thinking we're at block 65534.
    # The client starts expecting block 1, so this will fail as "out of order".
    # This test documents the limitation — there's no way to resume mid-transfer
    # with the current API. The real test is the integration test with a large file.
    # For now, just verify the client doesn't crash on high block numbers.
    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "huge.bin", onData)

    # Block 65534 is not block 1, so client times out waiting for block 1.
    # The key assertion is that the client returns a failure result rather than crashing.
    check result.success == false

suite "Corrupt/malformed server responses":
  test "corrupt packet does not crash — returns failure":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    # Add a raw garbage response (not a valid TFTP packet)
    mt.responses.add MockResponse(data: @[byte 0xFF, 0xFF, 0x00], host: "127.0.0.1", port: 12345)

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "test.txt", onData)

    check result.success == false

  test "truncated DATA packet does not crash":
    let mt = newMockTransport()
    let config = newDefaultConfig()

    # Valid opcode but truncated (DATA needs at least 4 bytes)
    mt.responses.add MockResponse(data: @[byte 0x00, 0x03, 0x00], host: "127.0.0.1", port: 12345)

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "test.txt", onData)

    check result.success == false

  test "OACK with non-numeric blksize does not crash":
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.blocksize = 1024

    mt.addResponse(makeOackPkt(@[("blksize", "notanumber")]))

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "test.txt", onData)

    # Should fail gracefully, not crash with ValueError
    check result.success == false

  test "OACK with non-numeric tsize does not crash":
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.requestTsize = true

    mt.addResponse(makeOackPkt(@[("tsize", "abc")]))

    let onData = proc(blockNum: uint16, data: seq[byte]) = discard
    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "test.txt", onData)

    check result.success == false

suite "Blocksize fallback (non-option-aware servers)":
  test "server ignores options and sends 512-byte DATA — full transfer completes":
    # Server doesn't support RFC 2348, responds with plain DATA at 512 bytes.
    # Client requested blocksize=4096. If activeBlocksize is not reset to 512,
    # the 512-byte block looks like a short/final block and the transfer truncates.
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.blocksize = 4096  # request large blocksize

    # Server ignores options, sends standard 512-byte blocks
    let fullBlock = newSeq[byte](512)
    mt.addResponse(makeDataPkt(1, fullBlock))
    mt.addResponse(makeDataPkt(2, fullBlock))
    mt.addResponse(makeDataPkt(3, @[byte 0xAB]))  # short = real final block

    var receivedBlocks: seq[uint16] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      receivedBlocks.add blockNum

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "fallback.bin", onData)

    check result.success == true
    check receivedBlocks == @[1'u16, 2, 3]
    check result.bytesTransferred == 512 + 512 + 1

  test "server responds with OACK then large blocks — uses negotiated blocksize":
    let mt = newMockTransport()
    var config = newDefaultConfig()
    config.blocksize = 1024

    mt.addResponse(makeOackPkt(@[("blksize", "1024")]))
    mt.addResponse(makeDataPkt(1, newSeq[byte](1024)))
    mt.addResponse(makeDataPkt(2, @[byte 1]))  # short at 1024 threshold

    var receivedBlocks: seq[uint16] = @[]
    let onData = proc(blockNum: uint16, data: seq[byte]) =
      receivedBlocks.add blockNum

    let result = waitFor getFile(mt.toTransport, config, "127.0.0.1", 69, "oack.bin", onData)

    check result.success == true
    check receivedBlocks == @[1'u16, 2]
    check result.bytesTransferred == 1024 + 1

suite "Public API path timeout clamp (R2-3 fix b — api.startTransfer can't inject an out-of-range timeout)":
  # api.startTransfer built `TftpClientConfig(timeout: req.options.timeout,
  # ...)` with NO clamp, even though blocksize/windowsize were clamped
  # inline right there. A caller-supplied timeout of 0 survived all the way
  # into engine.getFile's config.timeout -- and (independently of fix a)
  # into the R2-1 handshake deadline math too, where an unclamped 0 collapses
  # every attempt's budget to ~0 before a single transport.recv is even
  # issued. These tests go through the PUBLIC path (TftpSession.startTransfer)
  # rather than calling engine.getFile directly, so they can only pass once
  # the clamp in api.nim actually runs.
  test "startTransfer clamps an out-of-range LOW (zero) requested timeout before it ever reaches the client engine":
    let mt = newMockTransport()
    mt.addResponse(makeOackPkt(@[("blksize", "1024")]))  # timeout NOT echoed
    mt.addResponse(makeDataPkt(1, newSeq[byte](50)))       # short block = final

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = mt.toTransport)

    let outPath = getTempDir() / "t_client_r23_clamp_zero.tmp"
    defer:
      try: removeFile(outPath) except: discard

    var req = newTransferRequest("127.0.0.1", 69, "big.bin", outPath, tdGet)
    req.options.timeout = 0     # out of range: MinTimeoutOpt == 1
    req.options.blocksize = 1024

    let id = s.startTransfer(req)
    let result = s.waitTransfer(id)

    check result.success == true
    # recvTimeoutsMs[0]: getFile's handshake recv -- must reflect the
    # CLAMPED MinTimeoutOpt (1s == 1000ms), never the raw requested 0 (which,
    # fed unclamped into the R2-1 deadline math, would make every attempt's
    # budget expire before transport.recv is even called, and the transfer
    # would fail rather than succeed).
    check mt.recvTimeoutsMs.len == 3
    check mt.recvTimeoutsMs[0] == MinTimeoutOpt * 1000
    # recvTimeoutsMs[1]: recvBlocks' first recv, post-applyOack -- must
    # reflect the clamped negotiated timeout, never 0.
    check mt.recvTimeoutsMs[1] == MinTimeoutOpt * 1000

  test "startTransfer clamps an out-of-range HIGH (300) requested timeout before it ever reaches the client engine":
    let mt = newMockTransport()
    mt.addResponse(makeOackPkt(@[("blksize", "1024")]))  # timeout NOT echoed
    mt.addResponse(makeDataPkt(1, newSeq[byte](50)))       # short block = final

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = mt.toTransport)

    let outPath = getTempDir() / "t_client_r23_clamp_high.tmp"
    defer:
      try: removeFile(outPath) except: discard

    var req = newTransferRequest("127.0.0.1", 69, "big.bin", outPath, tdGet)
    req.options.timeout = 300   # out of range: MaxTimeoutOpt == 255
    req.options.blocksize = 1024

    let id = s.startTransfer(req)
    let result = s.waitTransfer(id)

    check result.success == true
    check mt.recvTimeoutsMs.len == 3
    check mt.recvTimeoutsMs[0] == MaxTimeoutOpt * 1000
    check mt.recvTimeoutsMs[1] == MaxTimeoutOpt * 1000
