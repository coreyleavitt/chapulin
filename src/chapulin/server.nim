## TFTP server — async request handlers and listener dispatch.
## No threads, no locks, no atomics. Concurrent transfers via asyncCheck.

import std/[os, asyncdispatch, strutils, times]
import protocol
import transfer
import transport
import options
import security
import server_config
import logging
export logging

type
  TransferInfo* = object
    clientHost*: string
    clientPort*: int
    filename*: string
    direction*: string
    bytesTransferred*: int64

  ServerCallbacks* = object
    onTransferStart*: proc(info: TransferInfo) {.closure.}
    onTransferComplete*: proc(info: TransferInfo) {.closure.}
    onTransferError*: proc(info: TransferInfo, msg: string) {.closure.}

  TftpServer* = ref object
    config*: ServerConfig
    callbacks*: ServerCallbacks
    logger*: Logger
    running*: bool
    activeTransfers*: int

proc serverOptionLimits(config: ServerConfig): ServerOptionLimits =
  ServerOptionLimits(
    maxBlocksize: config.maxBlocksize,
    minBlocksize: config.minBlocksize,
    timeout: config.timeout,
    maxWindowsize: config.maxWindowsize,
    minWindowsize: config.minWindowsize
  )

proc sendError(transport: Transport, host: string, port: int,
               code: TftpErrorCode, msg: string) {.async.} =
  let errPkt = TftpPacket(opcode: opError, errorCode: code, errorMsg: msg)
  await transport.send(encode(errPkt), host, port)

proc failResult(msg: string): TransferResult =
  TransferResult(success: false, bytesTransferred: 0, errorMsg: msg, totalSize: -1)

# --- RRQ handler: serve file to client ---

proc handleRrq*(config: ServerConfig, request: TftpPacket,
                transport: Transport, clientHost: string,
                clientPort: int): Future[TransferResult] {.async.} =
  let (valid, resolvedPath, pathErr) = validatePath(config.rootDir, request.filename)
  if not valid:
    await sendError(transport, clientHost, clientPort, errAccessViolation, pathErr)
    return failResult(pathErr)

  if not fileExists(resolvedPath):
    await sendError(transport, clientHost, clientPort, errFileNotFound, "File not found")
    return failResult("File not found: " & request.filename)

  let fileSize = getFileSize(resolvedPath)
  var file: File
  try:
    file = open(resolvedPath, fmRead)
  except IOError as e:
    await sendError(transport, clientHost, clientPort, errAccessViolation, e.msg)
    return failResult("Cannot open file: " & e.msg)
  defer: file.close()

  var xferConfig = newTransferConfig(
    blocksize = DefaultBlocksize,
    timeout = config.timeout,
    retries = config.retries,
    totalSize = fileSize
  )
  let peer = newPeer(clientHost, clientPort, locked = true)

  if request.options.len > 0:
    let limits = serverOptionLimits(config)
    var neg: NegotiatedOptions
    var oackOpts: seq[(string, string)]
    try:
      (neg, oackOpts) = negotiateServerOptions(request.options, limits,
                                                fileSize = fileSize)
    except ValueError:
      await sendError(transport, clientHost, clientPort, errIllegalOperation,
                      "Invalid option value")
      return failResult("Invalid option in request")

    xferConfig.blocksize = neg.blocksize
    if neg.totalSize >= 0:
      xferConfig.totalSize = neg.totalSize

    if oackOpts.len > 0:
      let oack = TftpPacket(opcode: opOack, oackOptions: oackOpts)
      let oackData = encode(oack)
      await transport.send(oackData, clientHost, clientPort)

      var pkt: TftpPacket
      try:
        pkt = await recvPacket(transport, xferConfig, peer, oackData)
      except TransferError as e:
        return failResult("OACK handshake failed: " & e.msg)

      if pkt.opcode != opAck or pkt.ackBlockNum != 0:
        return failResult("Expected ACK(0) after OACK, got: " & $pkt.opcode)

  let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
    let offset = int64(blockNum - 1) * int64(blocksize)
    file.setFilePos(offset)
    var buf = newSeq[byte](blocksize)
    let bytesRead = file.readBytes(buf, 0, blocksize)
    buf.setLen(bytesRead)
    return buf

  return await sendBlocks(transport, xferConfig, peer, 1, readData)

# --- WRQ handler: receive file from client ---

proc handleWrq*(config: ServerConfig, request: TftpPacket,
                transport: Transport, clientHost: string,
                clientPort: int): Future[TransferResult] {.async.} =
  let (valid, resolvedPath, pathErr) = validatePath(config.rootDir, request.filename)
  if not valid:
    await sendError(transport, clientHost, clientPort, errAccessViolation, pathErr)
    return failResult(pathErr)

  let (writeOk, writeErrCode, writeErr) = checkWriteAccess(config, resolvedPath)
  if not writeOk:
    await sendError(transport, clientHost, clientPort, writeErrCode, writeErr)
    return failResult(writeErr)

  var xferConfig = newTransferConfig(
    blocksize = DefaultBlocksize,
    timeout = config.timeout,
    retries = config.retries
  )
  let peer = newPeer(clientHost, clientPort, locked = true)

  if request.options.len > 0:
    let limits = serverOptionLimits(config)
    var neg: NegotiatedOptions
    var oackOpts: seq[(string, string)]
    try:
      (neg, oackOpts) = negotiateServerOptions(request.options, limits)
    except ValueError:
      await sendError(transport, clientHost, clientPort, errIllegalOperation,
                      "Invalid option value")
      return failResult("Invalid option in request")

    xferConfig.blocksize = neg.blocksize
    if neg.totalSize >= 0:
      xferConfig.totalSize = neg.totalSize

    if oackOpts.len > 0:
      let oack = TftpPacket(opcode: opOack, oackOptions: oackOpts)
      await transport.send(encode(oack), clientHost, clientPort)
      # RFC 2347: for WRQ, client acknowledges OACK with DATA(1), not ACK(0)
  else:
    await transport.send(encode(TftpPacket(opcode: opAck, ackBlockNum: 0)),
                         clientHost, clientPort)

  var file: File
  try:
    file = open(resolvedPath, fmWrite)
  except IOError as e:
    await sendError(transport, clientHost, clientPort, errDiskFull, e.msg)
    return failResult("Cannot open file for writing: " & e.msg)
  defer: file.close()

  var writeError = ""
  let onData = proc(blockNum: uint16, data: seq[byte]) =
    if writeError.len > 0: return
    if data.len > 0:
      let written = file.writeBytes(data, 0, data.len)
      if written != data.len:
        writeError = "Write failed"

  let cancelOnWriteError: CancelCheck = proc(): bool = writeError.len > 0

  var xferResult = await recvBlocks(transport, xferConfig, peer, 1, onData,
                                     cancelCheck = cancelOnWriteError)

  if writeError.len > 0:
    xferResult = failResult(writeError)

  return xferResult

# --- Server lifecycle ---

proc newTftpServer*(config: ServerConfig,
                    callbacks: ServerCallbacks = ServerCallbacks(),
                    logger: Logger = nil): TftpServer =
  let log = if logger != nil: logger else: newLogger(llInfo, nil)
  TftpServer(config: config, callbacks: callbacks, logger: log,
             running: false, activeTransfers: 0)

proc stop*(server: TftpServer) =
  server.running = false

proc handleRequest*(server: TftpServer, data: seq[byte],
                   clientHost: string, clientPort: int) {.async.} =
  var pkt: TftpPacket
  try:
    pkt = decode(data)
  except TftpDecodeError:
    server.logger.debug("Malformed packet from " & clientHost & ":" & $clientPort)
    return

  let direction = if pkt.opcode == opRrq: "RRQ" else: "WRQ"
  server.logger.info(direction & " " & pkt.filename & " from " &
                     clientHost & ":" & $clientPort)

  var xferTransport: Transport
  if server.config.hasPortRange():
    # Try ports in the configured range
    var bound = false
    for port in server.config.portRangeStart .. server.config.portRangeEnd:
      try:
        xferTransport = newUdpTransport(port)
        bound = true
        break
      except OSError:
        continue  # port in use, try next
    if not bound:
      server.logger.error("No available ports in range " &
        $server.config.portRangeStart & ":" & $server.config.portRangeEnd)
      await sendError(newUdpTransport(0), clientHost, clientPort,
                      errNotDefined, "Server has no available transfer ports")
      return
  else:
    xferTransport = newUdpTransport(0)

  let startTime = epochTime()
  defer:
    if xferTransport.close != nil: xferTransport.close()
    server.activeTransfers.dec

  var xferResult: TransferResult
  case pkt.opcode
  of opRrq:
    xferResult = await handleRrq(server.config, pkt, xferTransport,
                                  clientHost, clientPort)
  of opWrq:
    xferResult = await handleWrq(server.config, pkt, xferTransport,
                                  clientHost, clientPort)
  else:
    server.logger.warn("Unexpected opcode from " & clientHost)
    await sendError(xferTransport, clientHost, clientPort,
                    errIllegalOperation, "Expected RRQ or WRQ")
    return

  let durationMs = (epochTime() - startTime) * 1000.0
  let logMsg = formatTransferLog(direction, clientHost, clientPort,
                                  pkt.filename, xferResult.success,
                                  xferResult.bytesTransferred, durationMs,
                                  xferResult.errorMsg)
  if xferResult.success:
    server.logger.info(logMsg)
  else:
    server.logger.error(logMsg)

  let info = TransferInfo(
    clientHost: clientHost, clientPort: clientPort,
    filename: pkt.filename, direction: direction,
    bytesTransferred: xferResult.bytesTransferred)

  if xferResult.success:
    if server.callbacks.onTransferComplete != nil:
      server.callbacks.onTransferComplete(info)
  else:
    if server.callbacks.onTransferError != nil:
      server.callbacks.onTransferError(info, xferResult.errorMsg)

proc isBroadcastOrMulticast*(host: string): bool =
  ## RFC 1123 section 4.2: TFTP server must not respond to broadcast/multicast.
  host in ["255.255.255.255", "0.0.0.0"] or
  host.startsWith("224.") or  # IPv4 multicast (224.0.0.0/4)
  host.startsWith("ff")       # IPv6 multicast (ff00::/8)

proc run*(server: TftpServer, listener: UdpListener) {.async.} =
  ## Run the server main loop. Concurrent transfers via asyncCheck — no threads.
  server.running = true

  while server.running:
    var data: seq[byte]
    var clientHost: string
    var clientPort: int
    try:
      (data, clientHost, clientPort) = await listener.recv(1000)
    except TransportTimeoutError:
      continue

    # RFC 1123 section 4.2: silently ignore broadcast/multicast requests
    if isBroadcastOrMulticast(clientHost):
      continue

    if not checkHostAccess(server.config, clientHost):
      server.logger.warn("Access denied for " & clientHost)
      let xfer = newUdpTransport(0)
      await sendError(xfer, clientHost, clientPort, errAccessViolation, "Access denied")
      if xfer.close != nil: xfer.close()
      continue

    if server.activeTransfers >= server.config.maxConcurrent:
      server.logger.warn("Max concurrent transfers reached, rejecting " & clientHost)
      let xfer = newUdpTransport(0)
      await sendError(xfer, clientHost, clientPort, errNotDefined,
                      "Server busy, max concurrent transfers reached")
      if xfer.close != nil: xfer.close()
      continue

    server.activeTransfers.inc
    asyncCheck server.handleRequest(data, clientHost, clientPort)
