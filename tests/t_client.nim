import unittest
import std/[strutils, asyncdispatch]
import ../src/chapulin/protocol
import ../src/chapulin/engine
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
