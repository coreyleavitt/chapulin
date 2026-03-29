import unittest
import std/[os, strutils, asyncdispatch]
import ../src/chapulin/protocol
import ../src/chapulin/transfer
import ../src/chapulin/options
import ../src/chapulin/server_config
import ../src/chapulin/security
import ../src/chapulin/server

# --- Test helpers ---

type
  MockResponse = object
    data: seq[byte]
    host: string
    port: int

  ServerMock = ref object
    responses: seq[MockResponse]
    responseIdx: int
    sentPackets: seq[tuple[data: seq[byte], host: string, port: int]]
    timeoutOnNext: int

proc newServerMock(): ServerMock =
  ServerMock(responses: @[], responseIdx: 0, sentPackets: @[], timeoutOnNext: 0)

proc addResponse(sm: ServerMock, pkt: TftpPacket, host: string = "10.0.0.1", port: int = 5000) =
  sm.responses.add MockResponse(data: encode(pkt), host: host, port: port)

proc toTransport(sm: ServerMock): Transport =
  result.send = proc(data: seq[byte], host: string, port: int): Future[void] =
    sm.sentPackets.add (data: data, host: host, port: port)
    let fut = newFuture[void]("mockSend")
    fut.complete()
    return fut
  result.recv = proc(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte], host: string, port: int]] =
    let fut = newFuture[tuple[data: seq[byte], host: string, port: int]]("mockRecv")
    if sm.timeoutOnNext > 0:
      sm.timeoutOnNext.dec
      fut.fail(newException(TransportTimeoutError, "Mock timeout"))
      return fut
    if sm.responseIdx >= sm.responses.len:
      fut.fail(newException(TransportTimeoutError, "No more responses"))
      return fut
    let resp = sm.responses[sm.responseIdx]
    sm.responseIdx.inc
    fut.complete((data: resp.data, host: resp.host, port: resp.port))
    return fut
  result.close = proc() = discard

proc makeAckPkt(blockNum: uint16): TftpPacket =
  TftpPacket(opcode: opAck, ackBlockNum: blockNum)

proc makeDataPkt(blockNum: uint16, payload: seq[byte]): TftpPacket =
  TftpPacket(opcode: opData, blockNum: blockNum, data: payload)

suite "Broadcast rejection (RFC 1123)":
  test "IPv4 broadcast rejected":
    check isBroadcastOrMulticast("255.255.255.255") == true
    check isBroadcastOrMulticast("0.0.0.0") == true

  test "IPv4 multicast rejected":
    check isBroadcastOrMulticast("224.0.0.1") == true
    check isBroadcastOrMulticast("224.1.2.3") == true

  test "IPv6 multicast rejected":
    check isBroadcastOrMulticast("ff02::1") == true
    check isBroadcastOrMulticast("ff05::2") == true

  test "normal addresses accepted":
    check isBroadcastOrMulticast("192.168.1.1") == false
    check isBroadcastOrMulticast("10.0.0.1") == false
    check isBroadcastOrMulticast("127.0.0.1") == false
    check isBroadcastOrMulticast("::1") == false

# Test root directory
let testRoot = getTempDir() / "chapulin_server_test"

suite "Server test setup":
  test "create test files":
    createDir(testRoot)
    writeFile(testRoot / "hello.txt", "Hello from TFTP server")
    writeFile(testRoot / "exact512.bin", 'A'.repeat(512))
    writeFile(testRoot / "multi.bin", 'B'.repeat(1025))
    check fileExists(testRoot / "hello.txt")

suite "handleRrq — serve file to client":
  test "single block file served correctly":
    let sm = newServerMock()
    # Client sends ACK(1) after receiving DATA(1)
    sm.addResponse(makeAckPkt(1))

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "hello.txt",
                              mode: tmOctet, options: @[])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    check result.bytesTransferred > 0
    # Server should have sent DATA(1)
    check sm.sentPackets.len >= 1
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opData
    check sent.blockNum == 1

  test "multi-block file served correctly":
    let sm = newServerMock()
    sm.addResponse(makeAckPkt(1))
    sm.addResponse(makeAckPkt(2))
    sm.addResponse(makeAckPkt(3))

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "multi.bin",
                              mode: tmOctet, options: @[])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    check result.bytesTransferred == 1025

  test "file not found returns error":
    let sm = newServerMock()

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "nonexistent.txt",
                              mode: tmOctet, options: @[])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == false
    # Server should have sent ERROR packet
    check sm.sentPackets.len >= 1
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opError
    check sent.errorCode == errFileNotFound

  test "path traversal returns error":
    let sm = newServerMock()

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "../../../etc/passwd",
                              mode: tmOctet, options: @[])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == false
    check sm.sentPackets.len >= 1
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opError
    check sent.errorCode == errAccessViolation

  test "RRQ with blksize option sends OACK then DATA":
    let sm = newServerMock()
    sm.addResponse(makeAckPkt(0))  # client ACKs OACK
    sm.addResponse(makeAckPkt(1))  # client ACKs DATA(1)

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "hello.txt",
                              mode: tmOctet,
                              options: @[("blksize", "1024")])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    # First sent packet should be OACK
    let oack = decode(sm.sentPackets[0].data)
    check oack.opcode == opOack
    check ("blksize", "1024") in oack.oackOptions

suite "handleWrq — receive file from client":
  test "single block upload succeeds":
    let sm = newServerMock()
    sm.addResponse(makeDataPkt(1, @[byte 1, 2, 3]))

    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    let request = TftpPacket(opcode: opWrq, filename: "uploaded.txt",
                              mode: tmOctet, options: @[])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    check result.bytesTransferred == 3
    # Verify file was written
    check fileExists(testRoot / "uploaded.txt")
    check readFile(testRoot / "uploaded.txt").len == 3
    # First sent packet should be ACK(0)
    let ack = decode(sm.sentPackets[0].data)
    check ack.opcode == opAck
    check ack.ackBlockNum == 0

  test "write denied in read-only mode":
    let sm = newServerMock()

    let config = newDefaultServerConfig(testRoot)  # wpDeny is default
    let request = TftpPacket(opcode: opWrq, filename: "forbidden.txt",
                              mode: tmOctet, options: @[])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == false
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opError
    check sent.errorCode == errAccessViolation

  test "createOnly rejects existing file":
    let sm = newServerMock()

    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOnly
    let request = TftpPacket(opcode: opWrq, filename: "hello.txt",
                              mode: tmOctet, options: @[])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == false
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opError
    check sent.errorCode == errFileAlreadyExists

  test "WRQ with options sends OACK then receives DATA":
    let sm = newServerMock()
    # RFC 2347: for WRQ, client acknowledges OACK with DATA(1), not ACK(0)
    sm.addResponse(makeDataPkt(1, @[byte 42]))

    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    let request = TftpPacket(opcode: opWrq, filename: "opt_upload.txt",
                              mode: tmOctet,
                              options: @[("blksize", "1024")])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    let oack = decode(sm.sentPackets[0].data)
    check oack.opcode == opOack

  test "path traversal on WRQ returns error":
    let sm = newServerMock()

    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    let request = TftpPacket(opcode: opWrq, filename: "../../etc/cron.d/evil",
                              mode: tmOctet, options: @[])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == false
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opError

suite "Server test cleanup":
  test "remove test files":
    removeDir(testRoot)
    check not dirExists(testRoot)
