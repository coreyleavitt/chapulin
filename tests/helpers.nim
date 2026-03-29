## Shared test helpers — async mock transport, packet constructors.

import std/asyncdispatch
import ../src/chapulin/protocol
import ../src/chapulin/transfer

type
  MockResponse* = object
    data*: seq[byte]
    host*: string
    port*: int

  MockTransport* = ref object
    responses*: seq[MockResponse]
    responseIdx*: int
    sentPackets*: seq[tuple[data: seq[byte], host: string, port: int]]
    timeoutOnNext*: int

proc newMockTransport*(): MockTransport =
  MockTransport(responses: @[], responseIdx: 0, sentPackets: @[], timeoutOnNext: 0)

proc addResponse*(mt: MockTransport, pkt: TftpPacket, host: string = "127.0.0.1", port: int = 12345) =
  mt.responses.add MockResponse(data: encode(pkt), host: host, port: port)

proc addRawResponse*(mt: MockTransport, data: seq[byte], host: string = "127.0.0.1", port: int = 12345) =
  mt.responses.add MockResponse(data: data, host: host, port: port)

proc toTransport*(mt: MockTransport): Transport =
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

  result.close = proc() = discard

proc makeDataPkt*(blockNum: uint16, payload: seq[byte]): TftpPacket =
  TftpPacket(opcode: opData, blockNum: blockNum, data: payload)

proc makeAckPkt*(blockNum: uint16): TftpPacket =
  TftpPacket(opcode: opAck, ackBlockNum: blockNum)

proc makeErrorPkt*(code: TftpErrorCode, msg: string): TftpPacket =
  TftpPacket(opcode: opError, errorCode: code, errorMsg: msg)

proc makeOackPkt*(options: seq[(string, string)]): TftpPacket =
  TftpPacket(opcode: opOack, oackOptions: options)
