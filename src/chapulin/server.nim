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
import netascii
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
    errorCode*: int       ## RFC TftpErrorCode ord on failure (Q1/Option A); 0 (errNotDefined)
                          ## absent a failure, or when the failure path hasn't been wired to
                          ## a specific code yet. Additive field -- rides on the existing
                          ## onTransferError(info, msg) callback signature.

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

proc shouldDigestForSidecar(config: ServerConfig, mode: TransferMode,
                            resolvedPath: string): bool =
  ## Named gate for the RRQ sidecar-digest decision (RFC code-review
  ## finding, D1d/M1 collapse): a served file is digested into a .md5
  ## sidecar iff the server is configured for it, netascii's R3 policy
  ## doesn't skip it (translation would make the sidecar mode-dependent --
  ## see the call site's fuller comment), and the file being served isn't
  ## itself a reserved sidecar name (M1 -- prevents an unbounded
  ## foo.md5.md5.md5... chain from a client repeatedly RRQing the newest
  ## sidecar). Named and pulled out of the `if` at the call site purely for
  ## readability -- same three conditions, same order, same short-circuit
  ## behavior as before.
  config.checksumMode == csMd5 and not netasciiPolicyFor(mode).skipSidecar and
    not isReservedSidecarName(resolvedPath)

proc filterOptionsForPxe(opts: seq[(string, string)]): seq[(string, string)] =
  ## PXE compatibility: only allow tsize option, strip everything else.
  for (key, val) in opts:
    if key.toLowerAscii == "tsize":
      result.add (key, val)

proc sendError(transport: Transport, host: string, port: int,
               code: TftpErrorCode, msg: string) {.async.} =
  let errPkt = TftpPacket(opcode: opError, errorCode: code, errorMsg: msg)
  await transport.send(encode(errPkt), host, port)

proc failResult(msg: string, errorCode: int = 0): TransferResult =
  TransferResult(success: false, bytesTransferred: 0, errorMsg: msg,
                 errorCode: errorCode, totalSize: -1)

proc mkTransferInfo(clientHost: string, clientPort: int, filename, direction: string,
                    totalBytes: int64, startedAt: float, blocksize, windowsize: int,
                    mode: TransferMode, reqId: int): TransferInfo =
  ## Shared `onStart`-callback TransferInfo builder. Used both on the normal
  ## pre-transfer path (after option negotiation succeeds, reporting
  ## negotiated blocksize/windowsize) AND on the option-negotiation failure
  ## path (Q1/Option A -- see the `except ValueError` sites in
  ## handleRrq/handleWrq): calling `onStart` there mints a TransferId for the
  ## about-to-fail request so its ERROR(8) can surface via `onTransferError`,
  ## rather than being silently dropped by Invariant 4 (which still applies,
  ## unchanged, to every OTHER pre-onStart failure -- checksum-mode,
  ## config-bounds, path-validation, file-not-found, OS open failure). This
  ## is the one call site the RFC's Q1 resolution requires to be observable;
  ## widening Invariant 4 itself is out of scope. `bytesTransferred` is
  ## always 0 here -- this fires before any bytes move either way.
  TransferInfo(clientHost: clientHost, clientPort: clientPort, filename: filename,
              direction: direction, bytesTransferred: 0, totalBytes: totalBytes,
              startedAt: startedAt, blocksize: blocksize, windowsize: windowsize,
              mode: mode, reqId: reqId)

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
  of errOptionNegotiation: "Option negotiation failed"

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
  return (xfer: failResult(msg, ord(code)), diag: diag)

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

  # RFC conformance-closure D7: belt-and-suspenders. startServer already
  # rejects an out-of-RFC-bound config before a listener ever binds, but
  # handleRrq is itself an exported entry point that can be called directly
  # (bypassing startServer) -- same rationale as the checksumMode guard
  # above, same shared authority (server_config.serverConfigBoundsValid).
  if not serverConfigBoundsValid(config):
    let msg = "Server configuration invalid"
    await sendError(transport, clientHost, clientPort, errNotDefined, msg)
    return failResult(msg)

  # Check for directory listing request
  if config.dirListFile.len > 0 and request.filename == config.dirListFile:
    let listing = generateDirListing(config.rootDir)
    # D1d(4): the pseudo-file is already a fully-materialized in-memory
    # buffer, so under netascii it gets a one-shot feed+flush translation up
    # front (netascii.nim's toNetascii convenience wrapper) rather than being
    # forced through the block-chunking netasciiReader -- then plain
    # seek-addressing continues over the (already-translated) wire bytes.
    let listingBytes = if request.mode == tmNetascii: toNetascii(cast[seq[byte]](listing))
                       else: cast[seq[byte]](listing)
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
    return failResult(pathErr, ord(errAccessViolation))

  if not fileExists(resolvedPath):
    await sendError(transport, clientHost, clientPort, errFileNotFound, "File not found")
    return failResult("File not found: " & request.filename, ord(errFileNotFound))

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
                                                fileSize = fileSize,
                                                suppressTsize = netasciiPolicyFor(request.mode).suppressTsize)
    except ValueError:
      # R6: this fires only on a syntactically unparseable option value
      # (never on an out-of-range-but-parseable one, which is clamped or
      # dropped) -- RFC 2347 error code 8 (errOptionNegotiation).
      if onStart != nil:
        onStart(mkTransferInfo(clientHost, clientPort, request.filename, "RRQ",
                               xferConfig.totalSize, startedAt, xferConfig.blocksize,
                               xferConfig.windowsize, request.mode, reqId))
      await sendError(transport, clientHost, clientPort, errOptionNegotiation,
                      clientSafeError(errOptionNegotiation))
      return failResult("Invalid option in request", ord(errOptionNegotiation))

    xferConfig.blocksize = neg.blocksize
    xferConfig.windowsize = neg.windowsize
    xferConfig.timeout = neg.timeout
    if neg.totalSize >= 0:
      xferConfig.totalSize = neg.totalSize

    if oackOpts.len > 0:
      let oack = TftpPacket(opcode: opOack, oackOptions: oackOpts)
      let oackData = encode(oack)
      await transport.send(oackData, clientHost, clientPort)

      # neg.timeout was assigned into xferConfig ABOVE, before this wait, so
      # the handshake itself honors the negotiated value (RFC conformance-
      # closure D5) rather than the pre-negotiation default.
      var pkt: TftpPacket
      try:
        pkt = await recvPacket(transport, xferConfig, peer, oackData)
      except TransferError as e:
        return failResult("OACK handshake failed: " & e.msg)

      if pkt.opcode != opAck or pkt.ackBlockNum != 0:
        return failResult("Expected ACK(0) after OACK, got: " & $pkt.opcode)

  # D1b/d: netascii translation is expansive and data-dependent, so the wire
  # offset of a given local byte can't be computed from blockNum*blocksize --
  # the seek-addressed octet closure is invalid for netascii. makeSendReader
  # (netascii.nim) owns that choice now; octet keeps its self-correcting seek
  # closure untouched, just relocated inside that constructor.
  var netasciiEnc: NetasciiEncoder
  let readData = makeSendReader(file, request.mode, netasciiEnc)

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
  # R3: under netascii, skip the .md5 sidecar entirely (as tsize is dropped).
  # Hashing post-translation wire bytes would make the sidecar mode-dependent
  # and clobber a prior octet sidecar; hashing pre-translation bytes would
  # break the checksum RFC's "delivered bytes" invariant. Skipping avoids
  # both -- this is one of the enumerated policy-seam sites (D1d).
  var digester: Digester
  var onDelivered: proc(data: openArray[byte]) {.closure.}
  if shouldDigestForSidecar(config, request.mode, resolvedPath):
    digester = newDigester(csMd5)
    onDelivered = proc(data: openArray[byte]) = digester.update(data)

  if onStart != nil:
    onStart(mkTransferInfo(clientHost, clientPort, request.filename, "RRQ",
                           xferConfig.totalSize, startedAt, xferConfig.blocksize,
                           xferConfig.windowsize, request.mode, reqId))

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
  # RFC conformance-closure D7: belt-and-suspenders -- see handleRrq's
  # identical guard for the rationale (handleWrq is likewise a directly-
  # callable exported entry point that can bypass startServer).
  if not serverConfigBoundsValid(config):
    let msg = "Server configuration invalid"
    await sendError(transport, clientHost, clientPort, errNotDefined, msg)
    return failResult(msg)

  let (valid, resolvedPath, pathErr) = validatePath(config.rootDir, request.filename)
  if not valid:
    await sendError(transport, clientHost, clientPort, errAccessViolation, pathErr)
    return failResult(pathErr, ord(errAccessViolation))

  let (writeOk, writeErrCode, writeErr) = checkWriteAccess(config, resolvedPath)
  if not writeOk:
    await sendError(transport, clientHost, clientPort, writeErrCode, writeErr)
    return failResult(writeErr, ord(writeErrCode))

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
      (neg, oackOpts) = negotiateServerOptions(wrqClientOpts, limits,
                                                suppressTsize = netasciiPolicyFor(request.mode).suppressTsize)
    except ValueError:
      # R6: syntactically unparseable option value -- see handleRrq's
      # identical catch for the rationale.
      if onStart != nil:
        onStart(mkTransferInfo(clientHost, clientPort, request.filename, "WRQ",
                               xferConfig.totalSize, startedAt, xferConfig.blocksize,
                               xferConfig.windowsize, request.mode, reqId))
      await sendError(transport, clientHost, clientPort, errOptionNegotiation,
                      clientSafeError(errOptionNegotiation))
      return failResult("Invalid option in request", ord(errOptionNegotiation))

    xferConfig.blocksize = neg.blocksize
    xferConfig.windowsize = neg.windowsize
    xferConfig.timeout = neg.timeout
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
    onStart(mkTransferInfo(clientHost, clientPort, request.filename, "WRQ",
                           xferConfig.totalSize, startedAt, xferConfig.blocksize,
                           xferConfig.windowsize, request.mode, reqId))

  # D1c: writes route through makeRecvSink (netascii.nim), which owns the
  # decode-feed (undoing the wire's CR-LF/CR-NUL escaping under netascii)
  # AND the terminal finalize/flush -- see its doc for the exact contract.
  let recvSink = makeRecvSink(file, request.mode)

  var writeError = ""
  let onData = proc(blockNum: uint16, data: seq[byte]) =
    if writeError.len > 0: return
    # Final (short) block: the sink flushes durably on this call so the file
    # is durable on disk as soon as the data is accepted -- NOT gated on
    # recvBlocks() returning. D2's bounded final-ACK dally now runs (an extra
    # async suspension) between sendAck and recvBlocks' return, during which
    # the event loop can resume the CLIENT's coroutine (which sees the ACK
    # and reports its own transfer complete) well before the server-side
    # `defer: file.close()` below fires. Without this, a caller that reacts
    # to the client's completion (e.g. this module's own test harness) can
    # observe a not-yet-flushed file.
    if not recvSink(data, data.len < xferConfig.blocksize):
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
    reqId: reqId,
    errorCode: xferResult.errorCode)

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
