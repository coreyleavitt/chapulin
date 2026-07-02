## TFTP server — async request handlers and listener dispatch.
## No threads, no locks, no atomics. Concurrent transfers via addCallback.

import std/[os, asyncdispatch, strutils, times, md5]
import protocol
import transfer
import transport
import options
import security
import server_config
import logging
import format
export logging

type
  TransferInfo* = object
    clientHost*: string
    clientPort*: int
    filename*: string
    direction*: string
    bytesTransferred*: int64
    totalBytes*: int64
    startedAt*: float
    blocksize*: int       ## negotiated (or default) blocksize for this transfer
    windowsize*: int      ## negotiated (or default) windowsize for this transfer
    mode*: TransferMode   ## transfer mode (tmOctet / tmNetascii)
    reqId*: int           ## monotonic per-server request counter; unique within server lifetime

  ServerCallbacks* = object
    onTransferStart*: proc(info: TransferInfo) {.closure.}
    onTransferProgress*: proc(info: TransferInfo) {.closure.}
    onTransferComplete*: proc(info: TransferInfo) {.closure.}
    onTransferError*: proc(info: TransferInfo, msg: string) {.closure.}

  TftpServer* = ref object
    config*: ServerConfig
    callbacks*: ServerCallbacks
    logger*: Logger
    running*: bool
    activeTransfers*: int
    nextReqId*: int       ## incremented once per accepted request; never reset
    transferFactory*: proc(port: int): Transport {.closure.}
    cancelFactory*: proc(reqId: int): CancelCheck {.closure.}

proc serverOptionLimits(config: ServerConfig): ServerOptionLimits =
  ServerOptionLimits(
    maxBlocksize: config.maxBlocksize,
    minBlocksize: config.minBlocksize,
    timeout: config.timeout,
    maxWindowsize: config.maxWindowsize,
    minWindowsize: config.minWindowsize
  )

proc filterOptionsForPxe(opts: seq[(string, string)]): seq[(string, string)] =
  ## PXE compatibility: only allow tsize option, strip everything else.
  for (key, val) in opts:
    if key.toLowerAscii == "tsize":
      result.add (key, val)

proc sendError(transport: Transport, host: string, port: int,
               code: TftpErrorCode, msg: string) {.async.} =
  let errPkt = TftpPacket(opcode: opError, errorCode: code, errorMsg: msg)
  await transport.send(encode(errPkt), host, port)

proc failResult(msg: string): TransferResult =
  TransferResult(success: false, bytesTransferred: 0, errorMsg: msg, totalSize: -1)

# --- RRQ handler: serve file to client ---

proc generateChecksum(filePath: string, mode: ChecksumMode): string =
  ## Generate a checksum sidecar file after a successful read transfer.
  if mode == csMd5:
    let content = readFile(filePath)
    let hash = $toMD5(content)
    let sidecar = filePath & ".md5"
    writeFile(sidecar, hash & "  " & extractFilename(filePath) & "\n")
    return sidecar
  return ""

proc generateDirListing(rootDir: string): string =
  ## Generate a directory listing of the TFTP root.
  for kind, path in walkDir(rootDir):
    let name = extractFilename(path)
    case kind
    of pcFile:
      let size = getFileSize(path)
      result.add name & "\t" & $size & "\n"
    of pcDir:
      result.add name & "/\n"
    else: discard

proc handleRrq*(config: ServerConfig, request: TftpPacket,
                transport: Transport, clientHost: string,
                clientPort: int,
                onProgress: ProgressCallback = nil,
                onStart: proc(info: TransferInfo) {.closure.} = nil,
                startedAt: float = 0.0,
                cancelCheck: CancelCheck = nil,
                reqId: int = 0): Future[TransferResult] {.async.} =
  # Check for directory listing request
  if config.dirListFile.len > 0 and request.filename == config.dirListFile:
    let listing = generateDirListing(config.rootDir)
    let listingBytes = cast[seq[byte]](listing)
    var offset = 0
    let xferConfig = newTransferConfig(timeout = config.timeout, retries = config.retries)
    let peer = newPeer(clientHost, clientPort, locked = true)
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      let start = int(blockNum - 1) * blocksize
      if start >= listingBytes.len: return @[]
      let endPos = min(start + blocksize, listingBytes.len)
      return listingBytes[start ..< endPos]
    return await sendBlocks(transport, xferConfig, peer, 1, readData, nil, cancelCheck)

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

  let clientOpts = if config.pxeCompat: filterOptionsForPxe(request.options)
                   else: request.options
  if clientOpts.len > 0:
    let limits = serverOptionLimits(config)
    var neg: NegotiatedOptions
    var oackOpts: seq[(string, string)]
    try:
      (neg, oackOpts) = negotiateServerOptions(clientOpts, limits,
                                                fileSize = fileSize)
    except ValueError:
      await sendError(transport, clientHost, clientPort, errIllegalOperation,
                      "Invalid option value")
      return failResult("Invalid option in request")

    xferConfig.blocksize = neg.blocksize
    xferConfig.windowsize = neg.windowsize
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
    if blockNum == 0: return @[]
    let offset = int64(blockNum - 1) * int64(blocksize)
    file.setFilePos(offset)
    var buf = newSeq[byte](blocksize)
    let bytesRead = file.readBytes(buf, 0, blocksize)
    buf.setLen(bytesRead)
    return buf

  if onStart != nil:
    let startInfo = TransferInfo(
      clientHost: clientHost, clientPort: clientPort,
      filename: request.filename, direction: "RRQ",
      bytesTransferred: 0, totalBytes: xferConfig.totalSize,
      startedAt: startedAt,
      blocksize: xferConfig.blocksize,
      windowsize: xferConfig.windowsize,
      mode: request.mode,
      reqId: reqId)
    onStart(startInfo)

  let xferResult = await sendBlocks(transport, xferConfig, peer, 1, readData, onProgress, cancelCheck)

  if xferResult.success and config.checksumMode != csNone:
    discard generateChecksum(resolvedPath, config.checksumMode)

  return xferResult

# --- WRQ handler: receive file from client ---

proc handleWrq*(config: ServerConfig, request: TftpPacket,
                transport: Transport, clientHost: string,
                clientPort: int,
                onProgress: ProgressCallback = nil,
                onStart: proc(info: TransferInfo) {.closure.} = nil,
                startedAt: float = 0.0,
                cancelCheck: CancelCheck = nil,
                reqId: int = 0): Future[TransferResult] {.async.} =
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

  let wrqClientOpts = if config.pxeCompat: filterOptionsForPxe(request.options)
                      else: request.options
  if wrqClientOpts.len > 0:
    let limits = serverOptionLimits(config)
    var neg: NegotiatedOptions
    var oackOpts: seq[(string, string)]
    try:
      (neg, oackOpts) = negotiateServerOptions(wrqClientOpts, limits)
    except ValueError:
      await sendError(transport, clientHost, clientPort, errIllegalOperation,
                      "Invalid option value")
      return failResult("Invalid option in request")

    xferConfig.blocksize = neg.blocksize
    xferConfig.windowsize = neg.windowsize
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

  if onStart != nil:
    let startInfo = TransferInfo(
      clientHost: clientHost, clientPort: clientPort,
      filename: request.filename, direction: "WRQ",
      bytesTransferred: 0, totalBytes: xferConfig.totalSize,
      startedAt: startedAt,
      blocksize: xferConfig.blocksize,
      windowsize: xferConfig.windowsize,
      mode: request.mode,
      reqId: reqId)
    onStart(startInfo)

  var writeError = ""
  let onData = proc(blockNum: uint16, data: seq[byte]) =
    if writeError.len > 0: return
    if data.len > 0:
      let written = file.writeBytes(data, 0, data.len)
      if written != data.len:
        writeError = "Write failed"

  let combinedCancel: CancelCheck = proc(): bool =
    writeError.len > 0 or (cancelCheck != nil and cancelCheck())

  var xferResult = await recvBlocks(transport, xferConfig, peer, 1, onData,
                                     onProgress, combinedCancel)

  if writeError.len > 0:
    xferResult = failResult(writeError)

  return xferResult

# --- Server lifecycle ---

proc newTftpServer*(config: ServerConfig,
                    callbacks: ServerCallbacks = ServerCallbacks(),
                    logger: Logger = nil): TftpServer =
  let log = if logger != nil: logger else: newLogger(llInfo, nil)
  TftpServer(config: config, callbacks: callbacks, logger: log,
             running: false, activeTransfers: 0,
             transferFactory: proc(port: int): Transport = newUdpTransport(port))

proc stop*(server: TftpServer) =
  server.running = false

proc handleRequest*(server: TftpServer, data: seq[byte],
                   clientHost: string, clientPort: int) {.async.} =
  server.activeTransfers.inc
  defer: server.activeTransfers.dec
  var pkt: TftpPacket
  try:
    pkt = decode(data)
  except TftpDecodeError:
    server.logger.debug("Malformed packet from " & clientHost & ":" & $clientPort)
    return

  if pkt.opcode notin {opRrq, opWrq}:
    server.logger.debug("Ignoring non-request opcode " & $pkt.opcode & " from " &
                        clientHost & ":" & $clientPort)
    return

  let direction = if pkt.opcode == opRrq: "RRQ" else: "WRQ"
  server.logger.info(direction & " " & sanitizeForDisplay(pkt.filename) & " from " &
                     clientHost & ":" & $clientPort)

  var xferTransport: Transport
  if server.config.hasPortRange():
    # Try ports in the configured range
    var bound = false
    for port in server.config.portRangeStart .. server.config.portRangeEnd:
      try:
        xferTransport = server.transferFactory(port)
        bound = true
        break
      except OSError:
        continue  # port in use, try next
    if not bound:
      server.logger.error("No available ports in range " &
        $server.config.portRangeStart & ":" & $server.config.portRangeEnd)
      try:
        let errXfer = newUdpTransport(0)
        await sendError(errXfer, clientHost, clientPort,
                        errNotDefined, "Server has no available transfer ports")
        if errXfer.close != nil: errXfer.close()
      except OSError, CatchableError:
        discard
      return
  else:
    xferTransport = server.transferFactory(0)

  # Allocate a monotonic per-request id — unique within this server's lifetime.
  inc server.nextReqId
  let reqId = server.nextReqId

  let startTime = epochTime()
  let reqCancel: CancelCheck =
    if server.cancelFactory != nil: server.cancelFactory(reqId)
    else: nil
  defer:
    if xferTransport.close != nil: xferTransport.close()

  # Mutable negotiated params: set inside onStart (after OACK) so progressCb
  # and the final complete/error info carry the actual negotiated values.
  var effBlocksize = DefaultBlocksize
  var effWindowsize = DefaultWindowsize
  var effMode = tmOctet

  # Per-transfer progress callback — captures effBlocksize/windowsize/mode by
  # reference; by the time sendBlocks calls this, onStart has already run.
  let progressCb: ProgressCallback = if server.callbacks.onTransferProgress != nil:
    proc(bytes: int64, total: int64) =
      let info = TransferInfo(
        clientHost: clientHost, clientPort: clientPort,
        filename: pkt.filename, direction: direction,
        bytesTransferred: bytes, totalBytes: total,
        startedAt: startTime,
        blocksize: effBlocksize,
        windowsize: effWindowsize,
        mode: effMode,
        reqId: reqId)
      server.callbacks.onTransferProgress(info)
  else:
    nil

  # Per-transfer start callback — always non-nil so it captures negotiated params.
  let onStart: proc(info: TransferInfo) {.closure.} =
    proc(info: TransferInfo) =
      effBlocksize = info.blocksize
      effWindowsize = info.windowsize
      effMode = info.mode
      if server.callbacks.onTransferStart != nil:
        server.callbacks.onTransferStart(info)

  var xferResult: TransferResult
  case pkt.opcode
  of opRrq:
    xferResult = await handleRrq(server.config, pkt, xferTransport,
                                  clientHost, clientPort, progressCb,
                                  onStart, startTime, reqCancel, reqId)
  of opWrq:
    xferResult = await handleWrq(server.config, pkt, xferTransport,
                                  clientHost, clientPort, progressCb,
                                  onStart, startTime, reqCancel, reqId)
  else:
    discard  # unreachable: guard above returns for any non-RRQ/WRQ opcode

  let durationMs = (epochTime() - startTime) * 1000.0
  let logMsg = formatTransferLog(direction, clientHost, clientPort,
                                  sanitizeForDisplay(pkt.filename), xferResult.success,
                                  xferResult.bytesTransferred, durationMs,
                                  sanitizeForDisplay(xferResult.errorMsg))
  if xferResult.success:
    server.logger.info(logMsg)
  else:
    server.logger.error(logMsg)

  let info = TransferInfo(
    clientHost: clientHost, clientPort: clientPort,
    filename: pkt.filename, direction: direction,
    bytesTransferred: xferResult.bytesTransferred,
    totalBytes: xferResult.totalSize,
    startedAt: startTime,
    blocksize: effBlocksize,
    windowsize: effWindowsize,
    mode: effMode,
    reqId: reqId)

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
  ## Run the server main loop. Concurrent transfers via addCallback — no threads.
  server.running = true

  while server.running:
    var data: seq[byte]
    var clientHost: string
    var clientPort: int
    try:
      (data, clientHost, clientPort) = await listener.recv(1000)
    except TransportTimeoutError:
      continue
    except CatchableError as e:
      server.logger.error("Listener error: " & e.msg)
      break

    # RFC 1123 section 4.2: silently ignore broadcast/multicast requests
    if isBroadcastOrMulticast(clientHost):
      continue

    if not checkHostAccess(server.config, clientHost):
      server.logger.warn("Access denied for " & clientHost)
      try:
        let xfer = newUdpTransport(0)
        await sendError(xfer, clientHost, clientPort, errAccessViolation, "Access denied")
        if xfer.close != nil: xfer.close()
      except OSError, CatchableError:
        discard
      continue

    if server.activeTransfers >= server.config.maxConcurrent:
      server.logger.warn("Max concurrent transfers reached, rejecting " & clientHost)
      try:
        let xfer = newUdpTransport(0)
        await sendError(xfer, clientHost, clientPort, errNotDefined,
                        "Server busy, max concurrent transfers reached")
        if xfer.close != nil: xfer.close()
      except OSError, CatchableError:
        discard
      continue

    let hf = server.handleRequest(data, clientHost, clientPort)
    hf.addCallback(proc() {.gcsafe.} =
      {.cast(gcsafe).}:
        if hf.failed:
          server.logger.error("Unhandled transfer handler error: " & hf.readError.msg))
