import unittest
import std/[os, strutils, asyncdispatch]
import ../src/chapulin/protocol
import ../src/chapulin/transfer
import ../src/chapulin/options
import ../src/chapulin/server_config
import ../src/chapulin/security
import ../src/chapulin/server
import ../src/chapulin/netascii

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
    writeFile(testRoot / "netascii_lf.txt", "hello\nworld")
    writeFile(testRoot / "netascii_chunks.txt", "ABCDEFGH\nIJKLMNOP\nQR")
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
    check result.errorCode == ord(errFileNotFound)  # Fix B: errorCode wired, not 0
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
    check result.errorCode == ord(errAccessViolation)  # Fix B: errorCode wired, not 0
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

  test "RRQ cancelled by cancelCheck returns failure":
    let sm = newServerMock()
    # No ACK responses needed — cancelCheck fires before any recv
    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "hello.txt",
                              mode: tmOctet, options: @[])
    let alwaysCancel: CancelCheck = proc(): bool = true
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000, nil, nil, 0.0, alwaysCancel)
    check result.success == false
    check "cancel" in result.errorMsg.toLowerAscii

  test "RRQ with unparseable option value sends ERROR(8), not ERROR(4)":
    # D3/R6: an unparseable (not merely out-of-range) option value is the
    # ONLY case that gets ERROR(8) errOptionNegotiation -- clamp/drop handle
    # out-of-range-but-parseable values without ever reaching this catch.
    let sm = newServerMock()

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "hello.txt",
                              mode: tmOctet,
                              options: @[("blksize", "not-a-number")])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == false
    check result.errorCode == ord(errOptionNegotiation)
    check sm.sentPackets.len >= 1
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opError
    check sent.errorCode == errOptionNegotiation

suite "handleRrq — netascii send side (RFC-conformance-closure D1b/d, slice 7a)":
  test "LF to CR LF round trip: a real file's LF bytes arrive on the wire as CR LF":
    let sm = newServerMock()
    sm.addResponse(makeAckPkt(1))

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "netascii_lf.txt",
                              mode: tmNetascii, options: @[])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    # Local "hello\nworld" (11 bytes) -> wire "hello" CR LF "world" (12 bytes).
    check result.bytesTransferred == 12
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opData
    check sent.blockNum == 1
    check sent.data == @[byte('h'), byte('e'), byte('l'), byte('l'), byte('o'),
                        byte('\r'), byte('\n'),
                        byte('w'), byte('o'), byte('r'), byte('l'), byte('d')]

  test "multi-block RRQ under netascii: CR LF encoding spans block boundaries correctly":
    # "ABCDEFGH\nIJKLMNOP\nQR" (20 local bytes, 2 LFs) -> 22 wire bytes after
    # each LF expands to CR LF. blksize=8 (RFC 2348's floor -- MinBlocksize)
    # lands this as three blocks: 8 full + 8 full + 6 short-final --
    # exercising netasciiReader's block-chunking read-ahead loop across
    # several internal raw reads, not just a single-call translation.
    let localBytes = cast[seq[byte]]("ABCDEFGH\nIJKLMNOP\nQR")
    let expectedWire = toNetascii(localBytes)
    check expectedWire.len == 22

    let sm = newServerMock()
    sm.addResponse(makeAckPkt(0))  # OACK ack
    sm.addResponse(makeAckPkt(1))
    sm.addResponse(makeAckPkt(2))
    sm.addResponse(makeAckPkt(3))

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "netascii_chunks.txt",
                              mode: tmNetascii,
                              options: @[("blksize", "8")])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    check result.bytesTransferred == expectedWire.len

    let d1 = decode(sm.sentPackets[1].data)
    let d2 = decode(sm.sentPackets[2].data)
    let d3 = decode(sm.sentPackets[3].data)
    check d1.blockNum == 1
    check d2.blockNum == 2
    check d3.blockNum == 3
    check d1.data.len == 8    # full block
    check d2.data.len == 8    # full block
    check d3.data.len < 8     # short -- final (true EOF, not a straddle artifact)
    check d1.data & d2.data & d3.data == expectedWire

  test "retransmission under netascii: dup-ACK fast retransmit replays windowCache, never re-invokes the reader":
    # Same 3-block layout as above (blksize=8: 8 + 8 + 6). windowsize=2 fills
    # DATA(1),DATA(2); two duplicate ACK(0) reach dupAckThreshold and force a
    # resend of the outstanding window. If a future change re-invoked
    # readData for the resend instead of replaying sendBlocks' windowCache,
    # netasciiReader's continuity doAssert would crash outright (blockNum
    # would repeat instead of advancing) -- so this test also stands as the
    # "future retry-logic change can't silently corrupt netascii" regression
    # guard the RFC calls for.
    let localBytes = cast[seq[byte]]("ABCDEFGH\nIJKLMNOP\nQR")
    let expectedWire = toNetascii(localBytes)

    let sm = newServerMock()
    sm.addResponse(makeAckPkt(0))  # OACK ack
    sm.addResponse(makeAckPkt(0))  # duplicate #1 (window [1,2] outstanding)
    sm.addResponse(makeAckPkt(0))  # duplicate #2 -> fast retransmit of [1,2]
    sm.addResponse(makeAckPkt(2))  # forward progress covers 1 and 2
    sm.addResponse(makeAckPkt(3))  # final block acked

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "netascii_chunks.txt",
                              mode: tmNetascii,
                              options: @[("blksize", "8"), ("windowsize", "2")])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    check result.bytesTransferred == expectedWire.len

    # [0]=OACK, [1]=DATA(1) original, [2]=DATA(2) original,
    # [3]=DATA(1) resend, [4]=DATA(2) resend, [5]=DATA(3) final.
    check sm.sentPackets.len == 6
    let orig1 = decode(sm.sentPackets[1].data)
    let orig2 = decode(sm.sentPackets[2].data)
    let resend1 = decode(sm.sentPackets[3].data)
    let resend2 = decode(sm.sentPackets[4].data)
    let final3 = decode(sm.sentPackets[5].data)

    check orig1.blockNum == 1
    check resend1.blockNum == 1
    check orig1.data == resend1.data          # replayed byte-identical

    check orig2.blockNum == 2
    check resend2.blockNum == 2
    check orig2.data == resend2.data          # replayed byte-identical

    check final3.blockNum == 3
    check orig1.data & orig2.data & final3.data == expectedWire

  test "checksum sidecar is skipped under netascii (R3)":
    let sm = newServerMock()
    sm.addResponse(makeAckPkt(1))

    var config = newDefaultServerConfig(testRoot)
    config.checksumMode = csMd5
    let request = TftpPacket(opcode: opRrq, filename: "netascii_lf.txt",
                              mode: tmNetascii, options: @[])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    check not fileExists(testRoot / "netascii_lf.txt.md5")

  test "tsize is dropped under netascii: no OACK at all when tsize is the only requested option":
    # negotiateServerOptions(mode = tmNetascii) never emits the tsize OACK
    # entry -- with tsize the only option requested, oackOptions ends up
    # empty and handleRrq skips the OACK handshake entirely, going straight
    # to DATA(1). (An octet RRQ with the same request would OACK tsize back.)
    let sm = newServerMock()
    sm.addResponse(makeAckPkt(1))

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "netascii_lf.txt",
                              mode: tmNetascii,
                              options: @[("tsize", "0")])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opData  # NOT opOack -- tsize was the only option and it was dropped
    check sent.blockNum == 1

suite "netascii finishNetasciiDecode — shared terminal-flush helper (D1c, slice 7b)":
  test "flushes the trailing deferred CR to disk on success":
    let path = testRoot / "finish_decode_success.tmp"
    var f = open(path, fmWrite)
    var dec: NetasciiDecoder
    # A lone wire CR fed with nothing after it: `feed` defers classification
    # (never resolves a CR via in-call lookahead) rather than writing anything.
    let decoded = dec.feed(@[byte('A'), byte('\r')])
    discard f.writeBytes(decoded, 0, decoded.len)
    check decoded == @[byte('A')]  # the CR itself is still pending, not yet written

    let ok = finishNetasciiDecode(f, dec, true)
    f.close()
    # flush() resolves the trailing lone CR to a literal CR (R2) and it is
    # written as the file's final byte.
    check readFile(path) == "A\r"
    check ok == true  # Fix A: terminal write succeeded -- surfaced, not swallowed

  test "does NOT flush a partial decode on failure/abort":
    let path = testRoot / "finish_decode_failure.tmp"
    var f = open(path, fmWrite)
    var dec: NetasciiDecoder
    let decoded = dec.feed(@[byte('A'), byte('\r')])
    discard f.writeBytes(decoded, 0, decoded.len)

    # success = false: a failed/aborted transfer must not flush the pending
    # CR as if the stream had ended cleanly.
    let ok = finishNetasciiDecode(f, dec, false)
    f.close()
    check readFile(path) == "A"  # trailing CR never materialized
    check ok == true  # nothing was attempted -- not itself a failure

suite "handleWrq — netascii recv side (RFC-conformance-closure D1c, slice 7b)":
  test "CR LF to LF round trip: wire CR LF arrives as local LF on disk":
    let sm = newServerMock()
    let wireBytes = @[byte('h'), byte('e'), byte('l'), byte('l'), byte('o'),
                      byte('\r'), byte('\n'),
                      byte('w'), byte('o'), byte('r'), byte('l'), byte('d')]
    sm.addResponse(makeDataPkt(1, wireBytes))

    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    let request = TftpPacket(opcode: opWrq, filename: "netascii_wrq_lf.txt",
                              mode: tmNetascii, options: @[])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    # Wire "hello" CR LF "world" (12 bytes) -> local "hello" LF "world" (11 bytes).
    check readFile(testRoot / "netascii_wrq_lf.txt") == "hello\nworld"

  test "foreign-interop-shaped: a CR LF / CR NUL wire stream decodes end-to-end through the write path":
    # Exercises both wire escapes a conformant foreign sender may produce in
    # the same stream: CR LF (line ending -> local LF) and CR NUL (escaped
    # literal CR -> local CR), through the actual handleWrq write path (not
    # a bare feed/flush call).
    let sm = newServerMock()
    let wireBytes = @[byte('A'), byte('B'), byte('\r'), byte('\n'),
                      byte('C'), byte('D'), byte('\r'), byte(0),
                      byte('E'), byte('F')]
    sm.addResponse(makeDataPkt(1, wireBytes))

    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    let request = TftpPacket(opcode: opWrq, filename: "netascii_wrq_interop.txt",
                              mode: tmNetascii, options: @[])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    let expected = "AB" & "\n" & "CD" & "\r" & "EF"
    check readFile(testRoot / "netascii_wrq_interop.txt") == expected

  test "trailing deferred CR at true end-of-stream is flushed via finishNetasciiDecode":
    let sm = newServerMock()
    let wireBytes = @[byte('A'), byte('B'), byte('\r')]  # ends in a lone CR
    sm.addResponse(makeDataPkt(1, wireBytes))

    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    let request = TftpPacket(opcode: opWrq, filename: "netascii_wrq_trailing_cr.txt",
                              mode: tmNetascii, options: @[])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    check readFile(testRoot / "netascii_wrq_trailing_cr.txt") == "AB\r"

  test "zero-length file boundary under netascii":
    let sm = newServerMock()
    sm.addResponse(makeDataPkt(1, @[]))  # empty, final block

    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    let request = TftpPacket(opcode: opWrq, filename: "netascii_wrq_zero.txt",
                              mode: tmNetascii, options: @[])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    check result.bytesTransferred == 0
    check fileExists(testRoot / "netascii_wrq_zero.txt")
    check readFile(testRoot / "netascii_wrq_zero.txt").len == 0

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
    check result.errorCode == ord(errAccessViolation)  # Fix B: errorCode wired, not 0
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
    check result.errorCode == ord(errFileAlreadyExists)  # Fix B: errorCode wired, not 0
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
    check result.errorCode == ord(errAccessViolation)  # Fix B: errorCode wired, not 0
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opError

  test "WRQ with unparseable option value sends ERROR(8), not ERROR(4)":
    let sm = newServerMock()

    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    let request = TftpPacket(opcode: opWrq, filename: "opt_bad.txt",
                              mode: tmOctet,
                              options: @[("windowsize", "not-a-number")])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == false
    check result.errorCode == ord(errOptionNegotiation)
    check sm.sentPackets.len >= 1
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opError
    check sent.errorCode == errOptionNegotiation

# ---------------------------------------------------------------------------
# RFC conformance-closure D5/R6: an out-of-range-but-parseable timeout is
# dropped (omitted from the OACK), never clamped or substituted -- RFC 2349
# forbids silent substitution for timeout, unlike blksize/windowsize which
# RFC 2348/7440 permit clamping. The pure-function drop is already covered by
# `negotiateServerOptions` unit tests in tests/t_options.nim; this suite is
# the wire/session-level integration counterpart D3/D4/D6 already got but D5
# didn't -- a real RRQ/WRQ carrying an out-of-range timeout through
# handleRrq/handleWrq, asserting the resulting OACK omits "timeout" while a
# concurrently-requested, in-range option (blksize) IS still negotiated.
# ---------------------------------------------------------------------------
suite "handleRrq/handleWrq — R6: out-of-range timeout is dropped from the OACK (D5 integration coverage)":
  test "RRQ with timeout=0 (below range): OACK negotiates blksize but omits timeout entirely":
    let sm = newServerMock()
    sm.addResponse(makeAckPkt(0))  # client ACKs OACK
    sm.addResponse(makeAckPkt(1))  # client ACKs DATA(1)

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "hello.txt",
                              mode: tmOctet,
                              options: @[("blksize", "1024"), ("timeout", "0")])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    let oack = decode(sm.sentPackets[0].data)
    check oack.opcode == opOack
    check ("blksize", "1024") in oack.oackOptions       # valid option still negotiated
    for (key, _) in oack.oackOptions:
      check key.toLowerAscii != "timeout"               # out-of-range option dropped, not clamped

  test "RRQ with timeout=300 (above range): OACK negotiates blksize but omits timeout entirely":
    let sm = newServerMock()
    sm.addResponse(makeAckPkt(0))
    sm.addResponse(makeAckPkt(1))

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "hello.txt",
                              mode: tmOctet,
                              options: @[("blksize", "1024"), ("timeout", "300")])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    let oack = decode(sm.sentPackets[0].data)
    check oack.opcode == opOack
    check ("blksize", "1024") in oack.oackOptions
    for (key, _) in oack.oackOptions:
      check key.toLowerAscii != "timeout"

  test "WRQ with timeout=0 (below range): OACK negotiates blksize but omits timeout entirely":
    let sm = newServerMock()
    sm.addResponse(makeDataPkt(1, @[byte 7, 8, 9]))  # RFC 2347: client ACKs OACK with DATA(1)

    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    let request = TftpPacket(opcode: opWrq, filename: "d5_timeout_wrq.txt",
                              mode: tmOctet,
                              options: @[("blksize", "1024"), ("timeout", "0")])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == true
    let oack = decode(sm.sentPackets[0].data)
    check oack.opcode == opOack
    check ("blksize", "1024") in oack.oackOptions
    for (key, _) in oack.oackOptions:
      check key.toLowerAscii != "timeout"

suite "handleRrq — csSha256 fails loud, never a silent no-op (H2)":
  test "csSha256 config: handleRrq fails, sends ERROR, writes no sidecar":
    # RFC checksum-integrity-error-hygiene H2: before this fix, handleRrq's
    # sidecar-construction guard was `config.checksumMode == csMd5`, so
    # csSha256 fell through into the SAME branch as csNone (no digester, no
    # error) — the RRQ silently succeeded with no sidecar and no error,
    # reproducing the exact pre-RFC silent-no-op bug for any caller that
    # drives handleRrq directly with a csSha256 config (bypassing the
    # parseChecksumMode/startServer boundary guards). It must instead fail
    # loud: no successful transfer, no sidecar, an ERROR sent to the client.
    let sm = newServerMock()
    sm.addResponse(makeAckPkt(1))  # only consumed if the guard fails to fire

    var config = newDefaultServerConfig(testRoot)
    config.checksumMode = csSha256
    let request = TftpPacket(opcode: opRrq, filename: "hello.txt",
                              mode: tmOctet, options: @[])
    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == false
    check sm.sentPackets.len >= 1
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opError
    check not fileExists(testRoot / "hello.txt.md5")

suite "onTransferStart callback":
  test "onTransferStart fires once with correct totalBytes for RRQ":
    let sm = newServerMock()
    sm.addResponse(makeAckPkt(1))

    let config = newDefaultServerConfig(testRoot)
    let request = TftpPacket(opcode: opRrq, filename: "hello.txt",
                              mode: tmOctet, options: @[])

    var startFired = 0
    var startInfo: TransferInfo
    let onStart = proc(info: TransferInfo) {.closure.} =
      inc startFired
      startInfo = info

    let result = waitFor handleRrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000, nil, onStart, 0.0)

    check result.success == true
    check startFired == 1
    check startInfo.totalBytes == getFileSize(testRoot / "hello.txt")

  test "onTransferStart fires once with correct totalBytes for WRQ (tsize known)":
    let sm = newServerMock()
    # WRQ with tsize option so totalBytes is known; client ACKs OACK with DATA(1)
    sm.addResponse(makeDataPkt(1, @[byte 10, 20, 30]))

    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    let request = TftpPacket(opcode: opWrq, filename: "start_wrq.bin",
                              mode: tmOctet,
                              options: @[("tsize", "3")])

    var startFired = 0
    var startInfo: TransferInfo
    let onStart = proc(info: TransferInfo) {.closure.} =
      inc startFired
      startInfo = info

    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000, nil, onStart, 0.0)

    check result.success == true
    check startFired == 1
    check startInfo.totalBytes == 3

suite "transferFactory injection":
  test "transferFactory is invoked for each request":
    # Re-create the test file because cleanup may have run if suites share state
    createDir(testRoot)
    writeFile(testRoot / "hello.txt", "Hello from TFTP server")

    let sm = newServerMock()
    sm.addResponse(makeAckPkt(1))

    var factoryCalled = 0
    let config = newDefaultServerConfig(testRoot)
    let server = newTftpServer(config)
    server.transferFactory = proc(port: int): Transport =
      inc factoryCalled
      return sm.toTransport()

    let rrqPkt = TftpPacket(opcode: opRrq, filename: "hello.txt",
                             mode: tmOctet, options: @[])
    waitFor server.handleRequest(encode(rrqPkt), "10.0.0.1", 5000)

    check factoryCalled == 1

suite "parseChecksumMode — FIX 10: sha256 raises ValueError":

  test "md5 parses as csMd5":
    check parseChecksumMode("md5") == csMd5
    check parseChecksumMode("MD5") == csMd5

  test "none and empty string parse as csNone":
    check parseChecksumMode("none") == csNone
    check parseChecksumMode("") == csNone

  test "sha256 raises ValueError (not yet implemented)":
    var raised = false
    try:
      discard parseChecksumMode("sha256")
    except ValueError as e:
      raised = true
      check "sha256" in e.msg
      check "not yet implemented" in e.msg
    check raised

  test "unknown value raises ValueError":
    var raised = false
    try:
      discard parseChecksumMode("crc32")
    except ValueError:
      raised = true
    check raised

suite "clientSafeError — exhaustive, path-free (RFC checksum-integrity-error-hygiene slice 3a)":
  test "every TftpErrorCode maps to a non-empty, path-free message":
    for code in TftpErrorCode:
      let msg = clientSafeError(code)
      check msg.len > 0
      check '/' notin msg
      check '\\' notin msg
      check testRoot notin msg

suite "sendOsErrorAndFail — no OS path/errno leak (slice 3a)":
  test "direct call for errAccessViolation (the RRQ open-failure code) leaks nothing":
    # There is no portable way to force a real open() failure at the RRQ
    # `except IOError` site in handleRrq (server.nim): a directory RRQ is
    # rejected earlier by the `fileExists` check with a canned, path-free
    # string (see "file not found returns error" above), and a permission-
    # based trigger isn't cross-platform-portable (Windows read-only
    # attributes don't block reads). Real open()-failure reproduction for
    # the RRQ site is slice 3b's job (POSIX-only permission denial). Here
    # we verify the shared helper the RRQ site now calls -- with the exact
    # code (errAccessViolation) it has always used -- leaks nothing.
    let sm = newServerMock()
    # Fake OS detail deliberately embeds testRoot, to also prove (L2) that
    # the folded helper's `.diag` half is redacted independently of the
    # client-facing `.xfer` half.
    let fakeOsDetail = "permission denied: " & (testRoot / "secret.bin")
    let outcome = waitFor sendOsErrorAndFail(sm.toTransport, "10.0.0.1", 5000,
                                              errAccessViolation, testRoot,
                                              fakeOsDetail, "RRQ open failed")

    check outcome.xfer.success == false
    check outcome.xfer.errorCode == ord(errAccessViolation)  # Fix B: errorCode wired, not 0
    check outcome.xfer.errorMsg == clientSafeError(errAccessViolation)
    check testRoot notin outcome.xfer.errorMsg

    # Operator-only diag half: carries the OS detail, but redacted.
    check outcome.diag.len > 0
    check testRoot notin outcome.diag
    check outcome.diag != outcome.xfer.errorMsg

    check sm.sentPackets.len == 1
    let sent = decode(sm.sentPackets[0].data)
    check sent.opcode == opError
    check sent.errorCode == errAccessViolation
    check sent.errorMsg == clientSafeError(errAccessViolation)

suite "WRQ open failure — no OS path/errno leak (slice 3a)":
  test "WRQ targeting an existing directory does not leak rootDir or errno text":
    # Opening an existing directory with fmWrite raises IOError on both
    # POSIX and Windows, and (unlike RRQ's fileExists pre-check) nothing
    # in validatePath/checkWriteAccess rejects a directory target under
    # wpCreateOrOverwrite -- so this portably reaches the real
    # `except IOError` block at handleWrq's open() call.
    let sm = newServerMock()
    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    createDir(testRoot / "adir")

    let request = TftpPacket(opcode: opWrq, filename: "adir",
                              mode: tmOctet, options: @[])
    let result = waitFor handleWrq(config, request, sm.toTransport,
                           "10.0.0.1", 5000)

    check result.success == false
    check result.errorCode == ord(errDiskFull)  # Fix B: errorCode wired, not 0
    check testRoot notin result.errorMsg
    check result.errorMsg == clientSafeError(errDiskFull)

    var foundError = false
    for pkt in sm.sentPackets:
      let decoded = decode(pkt.data)
      if decoded.opcode == opError:
        foundError = true
        check decoded.errorCode == errDiskFull
        check testRoot notin decoded.errorMsg
        check decoded.errorMsg == clientSafeError(errDiskFull)
    check foundError

suite "RRQ open failure — real OS reproduction (slice 3b, POSIX-only)":
  test "chmod-000 file reaches the real open(fmRead) IOError and leaks nothing":
    when not defined(windows):
      # Unlike slice 3a (which could only call sendOsErrorAndFail directly,
      # because no portable trigger reaches handleRrq's `except IOError` at
      # server.nim:~153), a real file with all permission bits stripped makes
      # `fileExists`/`validatePath` pass (the file genuinely exists) while
      # `open(resolvedPath, fmRead)` genuinely fails with EACCES -- on any
      # POSIX UID *without* DAC-override (i.e. non-root). This drives the
      # actual handler code path end-to-end, not just the helper.
      let path = testRoot / "unreadable_rrq.bin"
      writeFile(path, "secret content that must never reach the client or errorMsg")
      setFilePermissions(path, {})

      let sm = newServerMock()
      # Queued in case open() unexpectedly succeeds (root/DAC-override UID in
      # the container -- root bypasses permission bits for open(2) entirely,
      # a real POSIX property, not a test bug) so the transfer can complete
      # normally instead of the mock exhausting and masking which code path
      # actually ran.
      sm.addResponse(makeAckPkt(1))

      let config = newDefaultServerConfig(testRoot)
      let request = TftpPacket(opcode: opRrq, filename: "unreadable_rrq.bin",
                                mode: tmOctet, options: @[])
      let result = waitFor handleRrq(config, request, sm.toTransport,
                             "10.0.0.1", 5000)

      # Restore permissions before any check/removeDir, or teardown fails.
      setFilePermissions(path, {fpUserRead, fpUserWrite})

      if result.success:
        echo "NOTE (slice 3b): open(fmRead) did NOT fault on chmod-000 file -- " &
             "this UID has DAC override (root) in this container, so the " &
             "real-fault assertion below could not be exercised here. CI's " &
             "native, non-root POSIX legs (ci.yaml) are the gate for this " &
             "invariant; the helper-level leak-freedom is already proven by " &
             "slice 3a's direct sendOsErrorAndFail test."
      else:
        check testRoot notin result.errorMsg
        check result.errorMsg == clientSafeError(errAccessViolation)

        var foundError = false
        for pkt in sm.sentPackets:
          let decoded = decode(pkt.data)
          if decoded.opcode == opError:
            foundError = true
            check decoded.errorCode == errAccessViolation
            check testRoot notin decoded.errorMsg
            check decoded.errorMsg == clientSafeError(errAccessViolation)
        check foundError
    else:
      echo "SKIP (slice 3b): POSIX-only -- setFilePermissions on Windows only " &
           "toggles the read-only attribute and does not block owner reads " &
           "(see docs/rfc/checksum-integrity-error-hygiene.md, slice 3b)."

suite "Redacted operator diagnostics (slice 6, D2 follow-on)":
  test "WRQ open failure logs a redacted diagnostic; wire/errorMsg stay generic":
    # Reuses slice 3a's portable directory-WRQ trigger (server.nim's real
    # `except IOError` at the WRQ open() site) but observes the operator-only
    # side: the existing handleRequest logger should receive an extra,
    # redacted diagnostic line carrying the OS detail slice 3a intentionally
    # dropped from the wire/errorMsg -- with config.rootDir stripped so no
    # absolute filesystem path appears even here.
    createDir(testRoot / "slice6_wrq_dir")

    var logged: seq[tuple[level: LogLevel, msg: string]]
    let logger = newLogger(llDebug, proc(level: LogLevel, msg: string) =
      logged.add (level, msg))

    let sm = newServerMock()
    var config = newDefaultServerConfig(testRoot)
    config.writePolicy = wpCreateOrOverwrite
    let server = newTftpServer(config, logger = logger)
    server.transferFactory = proc(port: int): Transport = sm.toTransport()

    var errCbMsg = ""
    server.callbacks.onTransferError = proc(info: TransferInfo, msg: string) =
      errCbMsg = msg

    let request = TftpPacket(opcode: opWrq, filename: "slice6_wrq_dir",
                              mode: tmOctet, options: @[])
    waitFor server.handleRequest(encode(request), "10.0.0.1", 5000)

    # Client-facing side is unchanged: still the generic, path-free message.
    check errCbMsg == clientSafeError(errDiskFull)
    check testRoot notin errCbMsg

    var foundError = false
    for pkt in sm.sentPackets:
      let decoded = decode(pkt.data)
      if decoded.opcode == opError:
        foundError = true
        check testRoot notin decoded.errorMsg
    check foundError

    # Operator-facing side: a redacted diagnostic was logged at warn level
    # (the existing handleRequest logger, distinct from its info/error
    # transfer-summary line), with no absolute rootDir substring, and
    # distinct in content from the generic client-facing message.
    var diagLine = ""
    for entry in logged:
      if entry.level == llWarn:
        diagLine = entry.msg
    check diagLine.len > 0
    check testRoot notin diagLine
    check diagLine != clientSafeError(errDiskFull)

  test "sidecar commit failure logs a redacted diagnostic; RRQ still succeeds":
    # Reuses slice 4's escaping-symlink trigger for writeSidecar containment
    # (t_security.nim) so digester.commit(...) returns (false, err) after an
    # otherwise-successful RRQ. Previously this failure was silently
    # discarded; slice 6 makes it operator-visible (redacted) without
    # turning the RRQ into a reported failure.
    let outsideDir = getTempDir() / "chapulin_server_test_slice6_outside"
    createDir(outsideDir)
    let outsideTarget = outsideDir / "escape_target.txt"
    writeFile(outsideTarget, "outside content")

    let resolvedName = "slice6_sidecar.bin"
    let resolvedPath = testRoot / resolvedName
    writeFile(resolvedPath, "hello world")

    var symlinkOk = true
    try:
      createSymlink(outsideTarget, resolvedPath & ".md5")
    except OSError, IOError:
      symlinkOk = false

    if not symlinkOk:
      checkpoint("symlink creation unsupported here -- sidecar diagnostic test skipped")
      skip()
    else:
      var logged: seq[tuple[level: LogLevel, msg: string]]
      let logger = newLogger(llDebug, proc(level: LogLevel, msg: string) =
        logged.add (level, msg))

      let sm = newServerMock()
      sm.addResponse(makeAckPkt(1))
      var config = newDefaultServerConfig(testRoot)
      config.checksumMode = csMd5
      let server = newTftpServer(config, logger = logger)
      server.transferFactory = proc(port: int): Transport = sm.toTransport()

      var completed = false
      server.callbacks.onTransferComplete = proc(info: TransferInfo) =
        completed = true

      let request = TftpPacket(opcode: opRrq, filename: resolvedName,
                                mode: tmOctet, options: @[])
      waitFor server.handleRequest(encode(request), "10.0.0.1", 5000)

      check completed == true

      # Containment refused the write: the outside file is untouched and the
      # planted symlink is left exactly as it was.
      check readFile(outsideTarget) == "outside content"
      check symlinkExists(resolvedPath & ".md5")

      var diagLine = ""
      for entry in logged:
        if entry.level == llWarn:
          diagLine = entry.msg
      check diagLine.len > 0
      check testRoot notin diagLine

      removeFile(resolvedPath & ".md5")

    removeDir(outsideDir)

suite "Server test cleanup":
  test "remove test files":
    removeDir(testRoot)
    check not dirExists(testRoot)
