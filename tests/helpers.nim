## Shared test helpers — async mock transport, packet constructors.

import std/[asyncdispatch, tables, options]
import ../src/chapulin/protocol
import ../src/chapulin/transfer
import ../src/chapulin/blocksource

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
    recvTimeoutsMs*: seq[int]  ## every timeoutMs a caller asked recv() for, in
                               ## order -- lets a test observe that a
                               ## negotiated `timeout` actually reached the
                               ## wire-level recv call (RFC conformance-
                               ## closure D5's "apply", not just "validate").
    recvDelayMs*: int  ## optional artificial delay (via sleepAsync) before
                       ## each recv() resolves -- lets a test make real
                       ## wall-clock time elapse deterministically between
                       ## iterations of a bounded-deadline retry loop (R2-1),
                       ## mirroring t_transfer.nim's local mock.

proc newMockTransport*(): MockTransport =
  MockTransport(responses: @[], responseIdx: 0, sentPackets: @[], timeoutOnNext: 0,
               recvTimeoutsMs: @[], recvDelayMs: 0)

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

  result.close = proc() = discard

proc makeDataPkt*(blockNum: uint16, payload: seq[byte]): TftpPacket =
  TftpPacket(opcode: opData, blockNum: blockNum, data: payload)

proc makeAckPkt*(blockNum: uint16): TftpPacket =
  TftpPacket(opcode: opAck, ackBlockNum: blockNum)

proc makeErrorPkt*(code: TftpErrorCode, msg: string): TftpPacket =
  TftpPacket(opcode: opError, errorCode: code, errorMsg: msg)

proc makeOackPkt*(options: seq[(string, string)]): TftpPacket =
  TftpPacket(opcode: opOack, oackOptions: options)

# ---------------------------------------------------------------------------
# Shared in-RAM table factories (RFC in-memory-sources-sinks.md §5.1, slice
# 5/"6") -- the harness-only composition that lets a two-session Wire demo
# use ONE TableRef[string, seq[byte]] as both parties' "filesystem": a
# client PUT commits into the table on finish(); a subsequent server-GET of
# the SAME path must observe that commit, not a construction-time snapshot.
# ---------------------------------------------------------------------------

proc tableSourceFactory*(t: TableRef[string, seq[byte]]): BlockSourceFactory =
  ## Looks the path up at CALL time (every invocation re-reads `t`), not at
  ## the moment this factory is constructed -- otherwise a reader built
  ## before a writer's `finish()` would capture a stale/empty view.
  result = proc(path: string): Option[OpenedSource] =
    if not t.hasKey(path): none(OpenedSource)
    else: some((memoryBlockSource(t[path]), some(t[path].len.int64)))

proc tableSinkFactory*(t: TableRef[string, seq[byte]]): BlockSinkFactory =
  ## Wraps `memoryBlockSink`'s own `finish` so that on a SUCCESSFUL terminal
  ## flush, the accumulated buffer is committed into the shared table under
  ## `path` -- the only way a subsequent same-table read can see it.
  result = proc(path: string): BlockSink =
    let buf = new(seq[byte])
    var s = memoryBlockSink(buf)
    let inner = s.finish
    s.finish = proc(success: bool): bool =
      result = inner(success)
      if success: t[path] = buf[]
    s
