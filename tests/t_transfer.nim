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

proc newMock(): MockTransport =
  MockTransport(responses: @[], responseIdx: 0, sentPackets: @[], timeoutOnNext: 0)

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

  result.recv = proc(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte], host: string, port: int]] =
    let fut = newFuture[tuple[data: seq[byte], host: string, port: int]]("mockRecv")
    if mt.timeoutOnNext > 0:
      mt.timeoutOnNext.dec
      fut.fail(newException(TransportTimeoutError, "Mock timeout"))
      return fut
    if mt.responseIdx >= mt.responses.len:
      fut.fail(newException(TransportTimeoutError, "No more mock responses"))
      return fut
    let resp = mt.responses[mt.responseIdx]
    mt.responseIdx.inc
    fut.complete((data: resp.data, host: resp.host, port: resp.port))
    return fut

proc makeDataPkt(blockNum: uint16, payload: seq[byte]): TftpPacket =
  TftpPacket(opcode: opData, blockNum: blockNum, data: payload)

proc makeAckPkt(blockNum: uint16): TftpPacket =
  TftpPacket(opcode: opAck, ackBlockNum: blockNum)

proc makeErrorPkt(code: TftpErrorCode, msg: string): TftpPacket =
  TftpPacket(opcode: opError, errorCode: code, errorMsg: msg)

# ============================================================
# recvPacket tests
# ============================================================

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
    check peer.effectiveTimeout(5000) == peer.adaptiveTimeout

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
# recvBlocks tests
# ============================================================

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
