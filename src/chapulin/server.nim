## TFTP server — async request handlers and listener dispatch.
## No threads, no locks, no atomics. Concurrent transfers via addCallback.

import std/[os, asyncdispatch, strutils, times, options]
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
import blocksource
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
    errorCode*: Option[TftpErrorCode]  ## none = no failure, or a failure with
                          ## no peer-supplied code; some(c) = this server
                          ## actually emitted/decoded TFTP error code c.
                          ## Additive field -- rides on the existing
                          ## onTransferError(info, msg) callback signature.
    requestedParams*: TransferParams  ## The client's RFC-clamped
                          ## pre-negotiation ask (see `askedParams`/
                          ## `NegotiationOutcome.requestedParams`).
                          ## A per-transfer INVARIANT value -- set once (from
                          ## `negotiateCore`, via `TransferSeam.requestedAsk`) and
                          ## never mutated per-tick, unlike `blocksize`/`windowsize`
                          ## above which DO change (default -> negotiated) as a
                          ## transfer progresses. Do not confuse the two: this
                          ## field answers "what did the client ask for," the
                          ## other two answer "what is in effect right now."

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

  TransferSeam = object
    ## Named seam that replaces three loose enclosing `var effBlocksize`/
    ## `effWindowsize`/`effMode` that `progressCb` and `onStart` both captured
    ## by reference to the same shared location. Nim closures over enclosing
    ## `var`s already share one location -- routing that through one named
    ## object is a readability/encapsulation improvement, NOT a fix for a
    ## duplication bug (there was none). `requestedAsk` is an immutable
    ## sibling: set exactly once, at construction, from the client's raw
    ## request options, and never mutated after -- a per-transfer INVARIANT
    ## value (unlike `eff*`, which are per-tick facts progressCb/onStart
    ## update as negotiation completes). Set from `info.requestedParams`
    ## inside `onStart` below -- the SAME value `negotiateCore` computed via
    ## `askedParams` and threaded onto `NegotiationOutcome.requestedParams` ->
    ## `mkTransferInfo` -- rather than recomputed here via a second
    ## `askedParams(pkt.options)` call, so there is exactly one place this is
    ## ever parsed. Wired into TransferInfo/api.nim's TransferSnapshot.requested.
    effBlocksize: int
    effWindowsize: int
    effMode: TransferMode
    requestedAsk: TransferParams

  NegotiationRequest = object
    ## The invariant request-describing quintet shared verbatim by
    ## negotiateCore and both wrappers -- grouped so it isn't repeated as five
    ## loose params at each of the three call sites. `peer` carries host+port
    ## (no separate clientHost/clientPort).
    transport*: Transport
    config*:    ServerConfig
    peer*:      PeerEndpoint
    request*:   TftpPacket
    direction*: string

  NegotiationOutcome = object
    ## FLAT, bool-gated (like OackOutcome -- exactly one failure mode no
    ## consumer must tell apart), NOT a case-object: a wrong-branch field
    ## access would be a FieldDefect escaping `except CatchableError` (the
    ## tracked never-throw Defect hazard).
    ok*:              bool
    xferConfig*:      TransferConfig   ## by value; meaningful iff ok
    oackData*:        seq[byte]        ## meaningful iff ok; empty iff no OACK was sent
                                        ## (a former `oackSent: bool` used to carry this redundantly --
                                        ## it was only ever set true in the same branch that populated
                                        ## `oackData`, so `oackSent == (oackData.len > 0)` always held.
                                        ## Readers now check `oackData.len > 0` directly). Also carries
                                        ## the wire bytes of the OACK just sent, so negotiateRrq can hand
                                        ## them to recvPacket as the retransmit payload on a per-attempt
                                        ## timeout (not part of the RFC's minimum field list -- pure
                                        ## internal plumbing between negotiateCore and negotiateRrq)
    requestedParams*: TransferParams   ## client's RFC-clamped pre-negotiation ask;
                                        ## computed once in negotiateCore
    failure*:         TransferResult   ## meaningful iff not ok

proc serverOptionLimits(config: ServerConfig): ServerOptionLimits =
  ServerOptionLimits(
    maxBlocksize: config.blocksizeRange.maxVal,
    minBlocksize: config.blocksizeRange.minVal,
    timeout: config.timeout,
    maxWindowsize: config.windowsizeRange.maxVal,
    minWindowsize: config.windowsizeRange.minVal
  )

proc shouldDigestForSidecar(config: ServerConfig, mode: TransferMode,
                            resolvedPath: string): bool =
  ## Named gate for the RRQ sidecar-digest decision: a served file is
  ## digested into a .md5 sidecar iff the server is configured for it,
  ## netascii's translation policy doesn't skip it (translation would make
  ## the sidecar mode-dependent -- see the call site's fuller comment), and
  ## the file being served isn't itself a reserved sidecar name (prevents an
  ## unbounded foo.md5.md5.md5... chain from a client repeatedly RRQing the
  ## newest sidecar). Named and pulled out of the `if` at the call site
  ## purely for readability -- same three conditions, same order, same
  ## short-circuit behavior as before.
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

proc failResult(msg: string, errorCode: Option[TftpErrorCode] = none(TftpErrorCode)): TransferResult =
  TransferResult(success: false, bytesTransferred: 0, errorMsg: msg,
                 errorCode: errorCode, totalSize: -1)

proc mkTransferInfo(clientHost: string, clientPort: int, filename, direction: string,
                    totalBytes: int64, startedAt: float, blocksize, windowsize: int,
                    mode: TransferMode, reqId: int,
                    requestedParams: TransferParams): TransferInfo =
  ## Shared `onStart`-callback TransferInfo builder. Used both on the normal
  ## pre-transfer path (after option negotiation succeeds, reporting
  ## negotiated blocksize/windowsize) AND on the option-negotiation failure
  ## path (see the `except ValueError` sites in handleRrq/handleWrq): calling
  ## `onStart` there mints a TransferId for the about-to-fail request so its
  ## ERROR(8) can surface via `onTransferError`, rather than being silently
  ## dropped by Invariant 4 (which still applies, unchanged, to every OTHER
  ## pre-onStart failure -- checksum-mode, config-bounds, path-validation,
  ## file-not-found, OS open failure). This is the one call site that needs
  ## to make an option-negotiation failure observable to the caller;
  ## widening Invariant 4 itself is out of scope. `bytesTransferred` is
  ## always 0 here -- this fires before any bytes move either way.
  ## `requestedParams`: the client's clamped ask, computed once by the
  ## caller (negotiateCore, via `askedParams`) and threaded straight
  ## through -- never recomputed here.
  TransferInfo(clientHost: clientHost, clientPort: clientPort, filename: filename,
              direction: direction, bytesTransferred: 0, totalBytes: totalBytes,
              startedAt: startedAt, blocksize: blocksize, windowsize: windowsize,
              mode: mode, reqId: reqId, requestedParams: requestedParams)

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
  ## the wire and `TransferResult.errorMsg`, but an operator debugging
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
  return (xfer: failResult(msg, some(code)), diag: diag)

# --- Best-effort client-ask parser: what did the client request, pre-negotiation? ---

proc askedParams*(options: seq[(string, string)]): TransferParams =
  ## Pure, best-effort parse of the client's RAW requested options
  ## (`request.options` wire strings), RFC-clamped per protocol.nim's GLOBAL
  ## bounds -- NOT the operator's configured `ServerOptionLimits`, which is a
  ## different, narrower question `negotiateServerOptions` already answers.
  ## Mirrors the client's own `validateBlocksize` /
  ## `max(MinWindowsize, min(MaxWindowsize, _))` clamp calls (api.nim) so
  ## client-side and server-side "requested" values are computed the same way.
  ##
  ## Per-option independent: a malformed/unparseable/missing key falls back
  ## to THAT field's default (`DefaultBlocksize`/`DefaultWindowsize`) alone --
  ## it never discards a valid sibling. LIMITATION (documented, not a bug):
  ## an unparseable option makes the client's true ask unknowable
  ## server-side, so this reports the default for that field; this coincides
  ## with a request that fails ERROR(8) anyway via negotiateCore's own parse.
  ##
  ## Exported so tests can verify the clamp/fallback/independence contract
  ## directly (mirrors clientSafeError*/sendOsErrorAndFail*'s testing-driven
  ## export pattern in this module). Feeds NegotiationOutcome.requestedParams
  ## through to api.nim's TransferSnapshot.
  result = TransferParams(blocksize: DefaultBlocksize, windowsize: DefaultWindowsize)
  for (rawKey, val) in options:
    case rawKey.toLowerAscii
    of "blksize":
      try:
        result.blocksize = validateBlocksize(parseInt(val))
      except ValueError:
        discard  # unparseable -- leave at default; see LIMITATION above
    of "windowsize":
      try:
        result.windowsize = validateWindowsize(parseInt(val))
      except ValueError:
        discard
    else:
      discard  # no bound to enforce for any other/unrecognized key

# --- Shared negotiate+OACK handshake primitive ---

proc clientOptsFor(config: ServerConfig, request: TftpPacket): seq[(string, string)] =
  ## PXE-compatibility filter, shared by negotiateCore (to decide whether
  ## there's anything to negotiate at all) and negotiateWrq (to decide
  ## whether the zero-options bare-ACK(0) case applies) -- same source of
  ## truth so the two decisions can never drift apart.
  if config.pxeCompat: filterOptionsForPxe(request.options) else: request.options

proc negotiateCore(req: NegotiationRequest, initialCfg: TransferConfig, fileSize: int64,
                   onStart: proc(info: TransferInfo) {.closure.},
                   startedAt: float, reqId: int): Future[NegotiationOutcome] {.async.} =
  ## Owns everything except the post-OACK reply: `filterOptionsForPxe`
  ## dispatch (via `clientOptsFor`), `serverOptionLimits`, the
  ## `negotiateServerOptions` call, the `ValueError` -> `onStart` ->
  ## `ERROR(8)` failure path, the `xferConfig` field assignment, the OACK
  ## send, and the best-effort `requestedParams` computation. The two
  ## thin wrappers (negotiateRrq/negotiateWrq) each own only the divergence
  ## that's really theirs -- the post-OACK reply shape RFC 2347 makes
  ## asymmetric between RRQ and WRQ.
  ##
  ## onStart firing is structural, not flag-driven: this proc fires `onStart`
  ## itself on the ValueError path, immediately before ERROR(8) is sent
  ## (ERROR(8) is sent INSIDE this primitive, so the ordering must hold here).
  ## On the success path this proc does NOT fire onStart -- the handler fires
  ## it, exactly once, after its wrapper returns `ok = true`.
  let requestedParams = askedParams(req.request.options)
  var xferConfig = initialCfg
  let clientOpts = clientOptsFor(req.config, req.request)

  if clientOpts.len == 0:
    return NegotiationOutcome(ok: true, xferConfig: xferConfig,
                              requestedParams: requestedParams)

  let limits = serverOptionLimits(req.config)
  var neg: NegotiatedOptions
  var oackOpts: seq[(string, string)]
  try:
    (neg, oackOpts) = negotiateServerOptions(clientOpts, limits,
                                              fileSize = fileSize,
                                              suppressTsize = netasciiPolicyFor(req.request.mode).suppressTsize)
  except ValueError:
    # This fires only on a syntactically unparseable option value (never
    # on an out-of-range-but-parseable one, which is clamped or dropped) --
    # RFC 2347 error code 8 (errOptionNegotiation).
    if onStart != nil:
      onStart(mkTransferInfo(req.peer.host, req.peer.port, req.request.filename,
                             req.direction, xferConfig.totalSize, startedAt,
                             xferConfig.blocksize, xferConfig.windowsize,
                             req.request.mode, reqId, requestedParams))
    await sendError(req.transport, req.peer.host, req.peer.port, errOptionNegotiation,
                    clientSafeError(errOptionNegotiation))
    return NegotiationOutcome(ok: false, requestedParams: requestedParams,
                              failure: failResult("Invalid option in request", some(errOptionNegotiation)))

  xferConfig.blocksize = neg.blocksize
  xferConfig.windowsize = neg.windowsize
  xferConfig.timeout = neg.timeout
  if neg.totalSize >= 0:
    xferConfig.totalSize = neg.totalSize

  var oackData: seq[byte]
  if oackOpts.len > 0:
    let oack = TftpPacket(opcode: opOack, oackOptions: oackOpts)
    oackData = encode(oack)
    await req.transport.send(oackData, req.peer.host, req.peer.port)

  return NegotiationOutcome(ok: true, xferConfig: xferConfig,
                            oackData: oackData, requestedParams: requestedParams)

proc negotiateRrq(req: NegotiationRequest, initialCfg: TransferConfig, fileSize: int64,
                  onStart: proc(info: TransferInfo) {.closure.},
                  startedAt: float, reqId: int): Future[NegotiationOutcome] {.async.} =
  ## RRQ's post-OACK divergence: await the client's ACK(0) ONLY when an
  ## OACK was actually sent -- a bare RRQ with zero negotiated options gets no
  ## reply from this proc at all; sendBlocks' DATA(1) is the first thing the
  ## wire sees. A failed post-OACK wait returns `ok = false` WITHOUT firing
  ## `onStart` -- it either already fired (the ValueError path, inside
  ## negotiateCore) or must not (a dropped ACK(0) is Invariant-4 territory);
  ## the handler's early-return on `not ok` never fires it either.
  result = await negotiateCore(req, initialCfg, fileSize, onStart, startedAt, reqId)
  if not result.ok or result.oackData.len == 0:
    return result

  var pkt: TftpPacket
  try:
    pkt = await recvPacket(req.transport, result.xferConfig, req.peer, result.oackData)
  except TransferError as e:
    return NegotiationOutcome(ok: false, requestedParams: result.requestedParams,
                              failure: failResult("OACK handshake failed: " & e.msg))

  if pkt.opcode != opAck or pkt.ackBlockNum != 0:
    return NegotiationOutcome(ok: false, requestedParams: result.requestedParams,
                              failure: failResult("Expected ACK(0) after OACK, got: " & $pkt.opcode))

proc negotiateWrq(req: NegotiationRequest, initialCfg: TransferConfig,
                  onStart: proc(info: TransferInfo) {.closure.},
                  startedAt: float, reqId: int): Future[NegotiationOutcome] {.async.} =
  ## WRQ's post-OACK divergence: returns immediately after the OACK send
  ## -- RFC 2347 has the client acknowledge a WRQ's OACK with DATA(1), which
  ## recvBlocks picks up on the block-1 receive, not an ACK(0) this proc
  ## would wait for. Also owns a second, easy-to-miss divergence: a WRQ
  ## with ZERO requested options gets a bare ACK(0) sent
  ## unconditionally by THIS proc (mirrors pre-extraction server.nim's
  ## behavior) -- RRQ's zero-options path sends nothing at all. Dropping
  ## this would break every default-options `tftp put`.
  result = await negotiateCore(req, initialCfg, -1, onStart, startedAt, reqId)
  if not result.ok:
    return result

  if clientOptsFor(req.config, req.request).len == 0:
    await req.transport.send(encode(TftpPacket(opcode: opAck, ackBlockNum: 0)),
                             req.peer.host, req.peer.port)

# --- RRQ handler: serve file to client ---

proc resolveSourceFactory(config: ServerConfig): BlockSourceFactory =
  ## RFC in-memory-sources-sinks.md §5.1 -- resolve `config`'s injected
  ## source factory, or the file-backed default (`defaultBlockSourceFactory`,
  ## blocksource.nim -- hoisted there, code-review S4-1/S4-3, so this and
  ## api.nim's equivalent share one implementation instead of two
  ## hand-rolled copies). NEVER dereference `config.sourceFactory` directly
  ## at a call site (nil-call hazard) -- every caller goes through this.
  if config.sourceFactory != nil: config.sourceFactory else: defaultBlockSourceFactory()

proc resolveSinkFactory(config: ServerConfig): BlockSinkFactory =
  ## Same contract, sink side (`defaultBlockSinkFactory`, blocksource.nim).
  if config.sinkFactory != nil: config.sinkFactory else: defaultBlockSinkFactory()

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
  ## Defaults to a freshly-allocated box rather than nil: Nim evaluates a
  ## default argument expression per call, so every caller that omits
  ## `diagOut` gets its own private, empty, immediately-discarded box. This
  ## makes every write site inside this proc an unconditional
  ## `diagOut[] = ...` instead of `if diagOut != nil: ...` -- collapsing
  ## per-call-site nil discipline (a future forgetful write site would be a
  ## live NilAccessDefect landmine, per the codebase's tracked never-throw
  ## Defect hazard) into a single structural guarantee.
  # RFC conformance-closure D7: belt-and-suspenders. startServer already
  # rejects an out-of-RFC-bound config before a listener ever binds, but
  # handleRrq is itself an exported entry point that can be called directly
  # (bypassing startServer) -- routes through the single shared authority
  # (server_config.serverConfigBoundsValid).
  if not serverConfigBoundsValid(config):
    let msg = "Server configuration invalid"
    await sendError(transport, clientHost, clientPort, errNotDefined, msg)
    return failResult(msg)

  # Check for directory listing request
  if config.dirListFile.len > 0 and request.filename == config.dirListFile:
    let listing = generateDirListing(config.rootDir)
    # The pseudo-file is already a fully-materialized in-memory
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
    return failResult(pathErr, some(errAccessViolation))

  # RFC in-memory-sources-sinks.md §5.1: the standalone fileExists/
  # getFileSize/open sequence is now folded into ONE factory call with the
  # same three-outcome contract -- absent (`none`) => errFileNotFound,
  # present-but-unopenable => errAccessViolation with the existing OS-detail
  # redaction, opened (`some`) => transfer proceeds. A nil
  # config.sourceFactory resolves to the file-backed default
  # (`defaultBlockSourceFactory`, blocksource.nim) below, so behavior is
  # byte-for-byte unchanged from the old direct calls.
  #
  # Catches BOTH `IOError` (the built-in default's raised type, matching a
  # real `open` failure) AND `OSError` (code-review S4-1: `std/os.
  # getFileSize` raises `OSError`, not `IOError` -- the built-in default
  # re-raises it as `IOError`, but this is a bare closure type, so Nim
  # cannot enforce that on an arbitrary INJECTED factory. Without this,
  # an injected factory that raises `OSError` directly -- e.g. one that
  # forwards a real `getFileSize` failure without translating it -- would
  # escape this handler entirely: no client ERROR packet, and the
  # exception propagates out of `handleRequest` since nothing there awaits
  # this call inside a try/except either).
  var opened: Option[OpenedSource]
  try:
    opened = resolveSourceFactory(config)(resolvedPath)
  except IOError, OSError:
    let osDetail = getCurrentExceptionMsg()
    let osResult = await sendOsErrorAndFail(transport, clientHost, clientPort,
      errAccessViolation, config.rootDir, osDetail, "RRQ open failed")
    diagOut[] = osResult.diag
    return osResult.xfer
  if opened.isNone:
    await sendError(transport, clientHost, clientPort, errFileNotFound, "File not found")
    return failResult("File not found: " & request.filename, some(errFileNotFound))
  let (source, sizeOpt) = opened.get
  let fileSize = sizeOpt.get(0'i64)
  defer: source.close()

  let initialCfg = newTransferConfig(
    blocksize = DefaultBlocksize,
    timeout = config.timeout,
    retries = config.retries,
    totalSize = fileSize
  )
  let peer = newPeer(clientHost, clientPort, locked = true)

  let negReq = NegotiationRequest(transport: transport, config: config, peer: peer,
                                  request: request, direction: "RRQ")
  let negOutcome = await negotiateRrq(negReq, initialCfg, fileSize, onStart, startedAt, reqId)
  if not negOutcome.ok:
    return negOutcome.failure

  var xferConfig = negOutcome.xferConfig

  # netascii translation is expansive and data-dependent, so the wire
  # offset of a given local byte can't be computed from blockNum*blocksize --
  # a seek-addressed read is invalid for netascii. makeSendReader
  # (netascii.nim) owns the mode choice now: it wraps `source` in the
  # netasciiBlockSource decorator under netascii, and reads it plain (forward-only,
  # via blocksource.nim's toReadData/fileBlockSource) under octet -- see
  # in-memory-sources-sinks.md §2 for why forward-only is behavior-preserving
  # for octet too (sendBlocks never re-reads a block; retransmits replay its
  # own windowCache).
  let readData = makeSendReader(source, request.mode)

  # Checksum sidecar: only constructed when csMd5 is enabled, so the
  # csNone path (default) allocates nothing and passes onDelivered = nil into
  # sendBlocks (zero overhead). onDelivered feeds each delivered block's bytes
  # (ACK-confirmed, ascending order, via transfer.nim's windowCache — never a
  # second readFile of the source) into the incremental digest; the sidecar
  # itself is written once, after a successful transfer, from the composed
  # digester.commit call below.
  #
  # Never digest/commit a sidecar for a served file that is ITSELF a
  # reserved .md5 name. A client legitimately downloading an existing
  # sidecar to verify a prior transfer must still be served in full (the
  # source-factory/sendBlocks path above is untouched), but generating
  # foo.md5.md5 here would let any RRQ of the newest sidecar grow an
  # unbounded, client-driven chain. Same isReservedSidecarName authority as
  # checkWriteAccess, so "what counts as reserved" cannot drift between the
  # WRQ-side and RRQ-side enforcement.
  # Under netascii, skip the .md5 sidecar entirely (as tsize is dropped).
  # Hashing post-translation wire bytes would make the sidecar mode-dependent
  # and clobber a prior octet sidecar; hashing pre-translation bytes would
  # break the checksum RFC's "delivered bytes" invariant. Skipping avoids
  # both -- this is one of the enumerated policy-seam sites.
  var digester: Digester
  var onDelivered: proc(data: openArray[byte]) {.closure.}
  if shouldDigestForSidecar(config, request.mode, resolvedPath):
    digester = newDigester(csMd5)
    onDelivered = proc(data: openArray[byte]) = digester.update(data)

  if onStart != nil:
    onStart(mkTransferInfo(clientHost, clientPort, request.filename, "RRQ",
                           xferConfig.totalSize, startedAt, xferConfig.blocksize,
                           xferConfig.windowsize, request.mode, reqId,
                           negOutcome.requestedParams))

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
  ## the always-allocated default box.
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
    return failResult(pathErr, some(errAccessViolation))

  let (writeOk, writeErrCode, writeErr) = checkWriteAccess(config, resolvedPath)
  if not writeOk:
    await sendError(transport, clientHost, clientPort, writeErrCode, writeErr)
    return failResult(writeErr, some(writeErrCode))

  let initialCfg = newTransferConfig(
    blocksize = DefaultBlocksize,
    timeout = config.timeout,
    retries = config.retries
  )
  let peer = newPeer(clientHost, clientPort, locked = true)

  let negReq = NegotiationRequest(transport: transport, config: config, peer: peer,
                                  request: request, direction: "WRQ")
  let negOutcome = await negotiateWrq(negReq, initialCfg, onStart, startedAt, reqId)
  if not negOutcome.ok:
    return negOutcome.failure

  var xferConfig = negOutcome.xferConfig

  var sink: BlockSink
  try:
    sink = resolveSinkFactory(config)(resolvedPath)
  except IOError, OSError:
    let osDetail = getCurrentExceptionMsg()
    let osResult = await sendOsErrorAndFail(transport, clientHost, clientPort,
      errDiskFull, config.rootDir, osDetail, "WRQ open failed")
    diagOut[] = osResult.diag
    return osResult.xfer
  defer: sink.close()

  if onStart != nil:
    onStart(mkTransferInfo(clientHost, clientPort, request.filename, "WRQ",
                           xferConfig.totalSize, startedAt, xferConfig.blocksize,
                           xferConfig.windowsize, request.mode, reqId,
                           negOutcome.requestedParams))

  # Writes route through makeRecvHandler (netascii.nim), which owns the
  # decode-feed (undoing the wire's CR-LF/CR-NUL escaping under netascii)
  # AND the terminal finalize/flush -- see its doc for the exact contract.
  let recvSink = makeRecvHandler(sink, request.mode)

  var writeError = ""
  let onData = proc(blockNum: uint16, data: seq[byte]) =
    if writeError.len > 0: return
    # Final (short) block: the sink flushes durably on this call so the file
    # is durable on disk as soon as the data is accepted -- NOT gated on
    # recvBlocks() returning. A bounded final-ACK dally now runs (an extra
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

proc allocateTransferTransport*(server: TftpServer,
                                config: ServerConfig): (Transport, bool) =
  ## Extracted from handleRequest: the transport/port-range allocation
  ## loop, unchanged in behavior. When a port range is
  ## configured, tries each port in turn -- OSError means only "in use, try
  ## the next one" -- and returns `(transport, true)` on the first successful
  ## bind, or `(Transport(), false)` (a zero-value Transport; never touched
  ## by any caller) if the whole range is exhausted. The caller owns
  ## sendError+return on `bound == false`, since only it has the client
  ## address to send to. With no port range configured, binds a single
  ## ephemeral port unconditionally (`bound` always true; an OSError there
  ## propagates uncaught, exactly as before this extraction).
  if config.hasPortRange():
    for port in config.portRangeStart .. config.portRangeEnd:
      try:
        return (server.transferFactory(port), true)
      except OSError:
        continue  # port in use, try next
    return (Transport(), false)
  else:
    return (server.transferFactory(0), true)

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

  let (xferTransport, bound) = allocateTransferTransport(server, server.config)
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

  # Allocate a monotonic per-request id — unique within this server's lifetime.
  inc server.nextReqId
  let reqId = server.nextReqId

  let startTime = epochTime()
  let reqCancel: CancelCheck =
    if server.cancelFactory != nil: server.cancelFactory(reqId)
    else: nil
  defer:
    if xferTransport.close != nil: xferTransport.close()

  # Named seam replacing three loose enclosing `var`s: progressCb and
  # onStart both capture `seam` by reference to the
  # same shared location, set inside onStart (after OACK) so progressCb and
  # the final complete/error info carry the actual negotiated values.
  # `requestedAsk` starts at the same harmless default `eff*` do below and is
  # overwritten, once, inside `onStart` from `info.requestedParams` -- the
  # value `negotiateCore` already computed via `askedParams` and threaded
  # through `mkTransferInfo`. This is a read of that single computation, not
  # a second `askedParams(pkt.options)` call (see TransferSeam's doc
  # comment) -- if `onStart` never fires (a pre-onStart failure; Invariant 4
  # applies), the default below is never observed by any callback.
  var seam = TransferSeam(
    effBlocksize: DefaultBlocksize,
    effWindowsize: DefaultWindowsize,
    effMode: tmOctet,
    requestedAsk: TransferParams(blocksize: DefaultBlocksize, windowsize: DefaultWindowsize))

  # Per-transfer progress callback — captures `seam` by reference; by the
  # time sendBlocks calls this, onStart has already run.
  let progressCb: ProgressCallback = if server.callbacks.onTransferProgress != nil:
    proc(bytes: int64, total: int64) =
      let info = TransferInfo(
        clientHost: clientHost, clientPort: clientPort,
        filename: pkt.filename, direction: direction,
        bytesTransferred: bytes, totalBytes: total,
        startedAt: startTime,
        blocksize: seam.effBlocksize,
        windowsize: seam.effWindowsize,
        mode: seam.effMode,
        reqId: reqId,
        requestedParams: seam.requestedAsk)
      server.callbacks.onTransferProgress(info)
  else:
    nil

  # Per-transfer start callback — always non-nil so it captures negotiated params.
  let onStart: proc(info: TransferInfo) {.closure.} =
    proc(info: TransferInfo) =
      seam.effBlocksize = info.blocksize
      seam.effWindowsize = info.windowsize
      seam.effMode = info.mode
      seam.requestedAsk = info.requestedParams
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
    blocksize: seam.effBlocksize,
    windowsize: seam.effWindowsize,
    mode: seam.effMode,
    reqId: reqId,
    errorCode: xferResult.errorCode,
    requestedParams: seam.requestedAsk)

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
