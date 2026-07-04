## TFTP server — async request handlers and listener dispatch.
## No threads, no locks, no atomics. Concurrent transfers via addCallback.

import std/[os, asyncdispatch, strutils, times]
import protocol
import transfer
import transport
import options
import security
import server_config
import checksum
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

proc clientSafeError*(code: TftpErrorCode): string =
  ## Generic, path-free, client-safe message for a TFTP error code.
  ## Exhaustive by construction (no `else`): a future `TftpErrorCode` fails
  ## to compile here until it is given a generic string. Intended for the
  ## narrow job of wrapping OS-exception messages (see sendOsErrorAndFail
  ## below) -- NOT a blanket replacement for the already-useful, path-free
  ## canned strings used at the other sendError call sites in this module
  ## (e.g. "Server is read-only", "File already exists").
  ## Exported so tests can verify exhaustiveness/path-freedom directly.
  case code
  of errNotDefined: "Undefined error"
  of errFileNotFound: "File not found"
  of errAccessViolation: "Access violation"
  of errDiskFull: "Disk full or allocation exceeded"
  of errIllegalOperation: "Illegal TFTP operation"
  of errUnknownTransferId: "Unknown transfer ID"
  of errFileAlreadyExists: "File already exists"
  of errNoSuchUser: "No such user"

proc redactRoot*(rootDir: string, msg: string): string =
  ## Strip every occurrence of the server's absolute `rootDir` from `msg`,
  ## replacing it with a root-relative marker. Used exclusively to prepare
  ## operator-only diagnostics (RFC checksum-integrity-error-hygiene, slice
  ## 6: OS open-failure detail, non-fatal sidecar-write failures) for the
  ## existing `handleRequest` logger -- these diagnostics carry OS errno
  ## text and internal error strings that were deliberately excluded from
  ## the wire and `TransferResult.errorMsg` (D2), but an operator debugging
  ## the server still needs the class/detail beyond the bare TFTP error
  ## code, without ever seeing the server's absolute filesystem layout.
  if rootDir.len == 0: return msg
  msg.replace(rootDir, "<root>")

proc sendOsErrorAndFail*(transport: Transport, host: string, port: int,
                         code: TftpErrorCode, rootDir: string, osDetail: string,
                         label: string): Future[tuple[xfer: TransferResult, diag: string]] {.async.} =
  ## Send an ERROR packet and build BOTH halves of the required handling for
  ## an OS-level exception (e.g. an open() failure) in one call (RFC
  ## checksum-integrity-error-hygiene, slice 6 / finding L2 -- folds what
  ## used to be a separate `sendOsErrorAndFail` + manual `redactRoot`
  ## two-step at each call site): `.xfer` is the generic, path-free,
  ## client-facing TransferResult; `.diag` is the redacted, operator-only
  ## diagnostic (rootDir stripped) that the caller forwards into
  ## handleRrq/handleWrq's `diagOut` channel (never onto the client-shared
  ## TransferResult -- see finding M3).
  ##
  ## `rootDir`/`osDetail` are woven ONLY into `.diag`: `.xfer.errorMsg` is
  ## built solely from `clientSafeError(code)`, so no path through this
  ## helper can route OS errno/path text onto the wire or into the
  ## client-shared TransferResult, even though (unlike the pre-L2 version)
  ## this helper does accept those strings as parameters now. Exported so
  ## tests can verify both halves directly, including at sites with no
  ## portable way to force a real OS failure (see RRQ open-failure coverage
  ## in tests/t_server.nim).
  let msg = clientSafeError(code)
  await sendError(transport, host, port, code, msg)
  let diag = redactRoot(rootDir, label & ": " & osDetail)
  return (xfer: failResult(msg), diag: diag)

# --- RRQ handler: serve file to client ---

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
                reqId: int = 0,
                diagOut: ref string = new(string)): Future[TransferResult] {.async.} =
  ## `diagOut` receives a redacted, operator-only diagnostic (RFC checksum-
  ## integrity-error-hygiene, finding M3) -- OS open-failure detail or a
  ## non-fatal sidecar-write failure. This is a SERVER-ONLY channel, separate
  ## from the returned (client-shared) TransferResult; only handleRequest
  ## reads it (via its own box) after the call. Never placed on the wire or
  ## in the returned TransferResult.errorMsg.
  ##
  ## Defaults to a freshly-allocated box rather than nil (round-3 code-review
  ## fix 3): Nim evaluates a default argument expression per call, so every
  ## caller that omits `diagOut` gets its own private, empty, immediately-
  ## discarded box. This makes every write site inside this proc an
  ## unconditional `diagOut[] = ...` instead of `if diagOut != nil: ...` --
  ## collapsing per-call-site nil discipline (a future forgetful write site
  ## would be a live NilAccessDefect landmine, per the codebase's tracked
  ## never-throw Defect hazard) into a single structural guarantee.
  # Fail LOUD on an unimplemented checksum mode (RFC checksum-integrity-
  # error-hygiene H2), instead of silently falling through to the same
  # no-sidecar branch as csNone. startServer already rejects an unimplemented
  # mode before a listener ever binds, but handleRrq is itself an exported
  # entry point (the RFC's own testing strategy calls it directly) — so this
  # guard must not rely on callers routing through startServer first. Routes
  # through the single shared authority (checksumModeImplemented) so the
  # rule can never drift from parseChecksumMode's or startServer's copy.
  # Checked before the directory-listing branch too: an invalid server
  # config should refuse every RRQ uniformly, not just file serves. The
  # wire-facing message stays generic (D2 error-hygiene invariant) — this is
  # a server/config condition, not something to explain to the client.
  if not checksumModeImplemented(config.checksumMode):
    let msg = "Server checksum mode not supported"
    await sendError(transport, clientHost, clientPort, errNotDefined, msg)
    return failResult(msg)

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
  except IOError:
    let osDetail = getCurrentExceptionMsg()
    let osResult = await sendOsErrorAndFail(transport, clientHost, clientPort,
      errAccessViolation, config.rootDir, osDetail, "RRQ open failed")
    diagOut[] = osResult.diag
    return osResult.xfer
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

  # Checksum sidecar (RFC D1): only constructed when csMd5 is enabled, so the
  # csNone path (default) allocates nothing and passes onDelivered = nil into
  # sendBlocks (zero overhead). onDelivered feeds each delivered block's bytes
  # (ACK-confirmed, ascending order, via transfer.nim's windowCache — never a
  # second readFile of the source) into the incremental digest; the sidecar
  # itself is written once, after a successful transfer, from the composed
  # digester.commit call below.
  #
  # M1 (reserved-namespace cluster): never digest/commit a sidecar for a
  # served file that is ITSELF a reserved .md5 name. A client legitimately
  # downloading an existing sidecar to verify a prior transfer must still be
  # served in full (the fileExists/open/sendBlocks path above is untouched),
  # but generating foo.md5.md5 here would let any RRQ of the newest sidecar
  # grow an unbounded, client-driven chain. Same isReservedSidecarName
  # authority as checkWriteAccess (H1/M5), so "what counts as reserved"
  # cannot drift between the WRQ-side and RRQ-side enforcement.
  var digester: Digester
  var onDelivered: proc(data: openArray[byte]) {.closure.}
  if config.checksumMode == csMd5 and not isReservedSidecarName(resolvedPath):
    digester = newDigester(csMd5)
    onDelivered = proc(data: openArray[byte]) = digester.update(data)

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

  var xferResult = await sendBlocks(transport, xferConfig, peer, 1, readData,
                                     onProgress, cancelCheck, onDelivered)

  # Sidecar only follows a successful transfer (never on cancel/abort/error) —
  # commit/writeSidecar never raise, so a sidecar failure must not fault this
  # Future or turn a successful RRQ into a reported error.
  if xferResult.success and digester != nil:
    let (sidecarOk, sidecarErr) = digester.commit(config.rootDir, resolvedPath)
    if not sidecarOk:
      diagOut[] = redactRoot(config.rootDir, "sidecar write failed: " & sidecarErr)

  return xferResult

# --- WRQ handler: receive file from client ---

proc handleWrq*(config: ServerConfig, request: TftpPacket,
                transport: Transport, clientHost: string,
                clientPort: int,
                onProgress: ProgressCallback = nil,
                onStart: proc(info: TransferInfo) {.closure.} = nil,
                startedAt: float = 0.0,
                cancelCheck: CancelCheck = nil,
                reqId: int = 0,
                diagOut: ref string = new(string)): Future[TransferResult] {.async.} =
  ## See handleRrq's `diagOut` doc: same server-only, operator-diagnostic
  ## channel (RFC checksum-integrity-error-hygiene, finding M3), including
  ## the always-allocated default box (round-3 fix 3).
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
  except IOError:
    let osDetail = getCurrentExceptionMsg()
    let osResult = await sendOsErrorAndFail(transport, clientHost, clientPort,
      errDiskFull, config.rootDir, osDetail, "WRQ open failed")
    diagOut[] = osResult.diag
    return osResult.xfer
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
  # Server-only channel (RFC checksum-integrity-error-hygiene, finding M3):
  # handleRrq/handleWrq populate this with a redacted, operator-only
  # diagnostic when there is one. It never rides on the client-shared
  # TransferResult.
  let diagBox = new(string)
  case pkt.opcode
  of opRrq:
    xferResult = await handleRrq(server.config, pkt, xferTransport,
                                  clientHost, clientPort, progressCb,
                                  onStart, startTime, reqCancel, reqId, diagBox)
  of opWrq:
    xferResult = await handleWrq(server.config, pkt, xferTransport,
                                  clientHost, clientPort, progressCb,
                                  onStart, startTime, reqCancel, reqId, diagBox)
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

  # Redacted operator-only diagnostic (RFC checksum-integrity-error-hygiene,
  # slice 6 / finding M3): open-failure OS detail or a non-fatal sidecar-write
  # failure. Never on the wire or in errorMsg/callbacks -- diagBox is a
  # server-only channel, populated by handleRrq/handleWrq specifically for
  # this log line, entirely separate from the client-shared TransferResult.
  if diagBox[].len > 0:
    server.logger.warn("Diagnostic (redacted) for " & direction & " " &
      sanitizeForDisplay(pkt.filename) & " from " & clientHost & ":" &
      $clientPort & ": " & diagBox[])

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
