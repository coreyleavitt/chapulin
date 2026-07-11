## Public API — the stable contract that CLI and GUI frontends consume.
## No frontend should import protocol or engine directly.

import std/asyncdispatch
import engine
import protocol
import netascii
import blocksource
export Transport, CancelCheck, TransportTimeoutError,
       TransferResult, DefaultBlocksize, DefaultTimeout,
       DefaultRetries, DefaultWindowsize, MinWindowsize, MaxWindowsize,
       MinBlocksize, MaxBlocksize, validateBlocksize,
       TransferMode, TftpErrorCode, TransferParams
import std/os
import std/[tables, options, times]
export options
import logging
import transport as transportMod
import server
import server_config
import format
import eventqueue
export LogLevel, formatLogMessage, UdpListener
export server_config
export fraction, formatBytes, formatSpeed, sanitizeForDisplay
export EventKind, TransferDirection, TransferId, ServerId, NoTransfer, NoServer,
       TransferSnapshot, Event, `==`, inEffect

type
  TransferOptions* = object
    blocksize*: int
    timeout*: int
    retries*: int
    windowsize*: int
    mode*: TransferMode

  TransferRequest* = object
    host*: string
    port*: int
    filename*: string
    localPath*: string
    direction*: TransferDirection
    options*: TransferOptions

proc newTransferRequest*(host: string, port: int, filename: string,
                         localPath: string, direction: TransferDirection): TransferRequest =
  TransferRequest(
    host: host, port: port, filename: filename,
    localPath: localPath, direction: direction,
    options: TransferOptions(blocksize: DefaultBlocksize, timeout: DefaultTimeout,
                             retries: DefaultRetries, windowsize: DefaultWindowsize,
                             mode: tmOctet)
  )

# ---------------------------------------------------------------------------
# Session API — slice 1: spine + client transfers
# ---------------------------------------------------------------------------
#
# EventKind, TransferDirection, TransferId, ServerId, TransferSnapshot, Event
# and the EventQueue they're built on live in eventqueue.nim and are
# re-exported above -- api.nim consumes them but is no longer their home.

type
  TransportFactory* = proc(host: string, port: int): Transport {.closure.}
  ListenerFactory*  = proc(bindAddr: string, port: int): UdpListener {.closure.}

  TransferOrigin = enum
    ## Flat tag distinguishing client- from server-side transfers within the
    ## single consolidated `transfers` table below. Not a case-object variant
    ## discriminator -- no per-branch payload hangs off this, so there is no
    ## FieldDefect surface. It exists solely so `close()`/`drain()`/
    ## `sessionActiveCount` can single out client transfers (server transfers
    ## are deliberately left to drain to completion on `stop()`/`close()`,
    ## never force-cancelled).
    toClient, toServer

  TransferRecord = object
    ## The sole per-transfer record, keyed by TransferId, for BOTH client
    ## and server-side transfers. Replaces the old `active`/`serverXferCancel`
    ## split -- `cancel(id)` is now one lookup + one flag set regardless of
    ## a transfer's origin. Deliberately flat (no case-object): an audit
    ## confirmed the old TransferEntry.transport field was dead (written
    ## once, never read -- the transport is closed via a separately-captured
    ## closure variable), so nothing justifies a variant here.
    cancelFlag: ref bool
    origin:     TransferOrigin

  XferKey = int  ## monotonic reqId allocated once per accepted request

  ServerEntry = ref object
    srv:            TftpServer
    listener:       UdpListener
    runFut:         Future[void]
    stopRequested:  bool
    stoppedEmitted: bool
    xfers:          Table[XferKey, TransferId]
    ## Transient bridge only: `cancelFactory` (called with reqId, before a
    ## TransferId exists) stashes the flag here; `onTransferStart` (which
    ## mints the TransferId) immediately consumes+deletes the entry and moves
    ## the flag into `transfers[tid]`. Never a second permanent home for
    ## cancellation state -- entries live at most from cancelFactory's call to
    ## the next onTransferStart/onTransferError callback.
    cancelFlags:    Table[XferKey, ref bool]

  TftpSession* = ref object
    queue:            EventQueue
    nextId:           uint32
    transfers:        Table[uint32, TransferRecord]
    minLogLevel:      LogLevel
    transportFactory: TransportFactory
    listenerFactory:  ListenerFactory
    sourceFactory:    BlockSourceFactory
    sinkFactory:      BlockSinkFactory
    servers:          Table[uint32, ServerEntry]
    nextServerId:     uint32

const MaxQueuedEvents* = 8192 ## TRUE hard cap on s.queue: log-kind events are evicted first
                               ## when full, then the oldest event of any kind (drop-oldest) --
                               ## len never exceeds this, even under sustained saturation. See
                               ## eventqueue.nim's module doc-comment and docs/api-reference.md.
const WaitCapIterations = 5_000_000 ## safety valve; hasPendingOperations early-exit fires first

proc enqueue(s: TftpSession, ev: Event) =
  ## Push ev onto the session event queue. Coalescing (progress), bounded
  ## eviction, and dropped-count bookkeeping all live in EventQueue.push
  ## (eventqueue.nim) -- this is a thin delegate kept so the many
  ## `s.enqueue(...)` call sites below don't need to change.
  s.queue.push(ev)

proc activeClientCount(s: TftpSession): int =
  ## Number of client-originated (toClient) transfers still in `s.transfers`.
  ## Server-side transfers share the same table but are excluded here: they
  ## are deliberately left to drain, not force-cancelled, by close()/drain().
  for _, rec in s.transfers.pairs:
    if rec.origin == toClient: inc result

proc mkSnap(bytes: int64, total: Option[int64],
            direction: TransferDirection, mode: TransferMode,
            requested: TransferParams, effective: Option[TransferParams],
            startedAt: float): TransferSnapshot =
  ## `requested` is ALWAYS the clamped ask; `effective` is `none` until
  ## the handshake resolves and `some(params)` once in-effect -- see
  ## startTransfer's `zeroSnap`/evTransferStarted call sites and
  ## server.nim's TransferSeam-sourced call sites below.
  TransferSnapshot(bytes: bytes, total: total, requested: requested,
                   effective: effective,
                   direction: direction, mode: mode, startedAt: startedAt)

proc newSession*(minLogLevel: LogLevel = llInfo,
                 transportFactory: TransportFactory = nil,
                 listenerFactory:  ListenerFactory = nil,
                 sourceFactory:    BlockSourceFactory = nil,
                 sinkFactory:      BlockSinkFactory = nil): TftpSession =
  let factory =
    if transportFactory != nil: transportFactory
    else:
      proc(host: string, port: int): Transport =
        transportMod.newUdpTransport(0, transportMod.isIPv6(host))
  TftpSession(
    queue:            initEventQueue(MaxQueuedEvents),
    nextId:           0,
    transfers:        initTable[uint32, TransferRecord](),
    minLogLevel:      minLogLevel,
    transportFactory: factory,
    listenerFactory:  listenerFactory,
    sourceFactory:    sourceFactory,
    sinkFactory:      sinkFactory,
    servers:          initTable[uint32, ServerEntry](),
    nextServerId:     0
  )

proc resolveSourceFactory(s: TftpSession): BlockSourceFactory =
  ## RFC §5.1 -- resolve the session's injected source factory, or the
  ## file-backed default (`defaultBlockSourceFactory`, blocksource.nim --
  ## hoisted there, code-review S4-1/S4-3, so this and server.nim's
  ## equivalent share one implementation instead of two hand-rolled
  ## copies). NEVER dereferences `s.sourceFactory` directly at the call site
  ## (nil-call hazard) -- every caller goes through this.
  if s.sourceFactory != nil: s.sourceFactory else: defaultBlockSourceFactory()

proc resolveSinkFactory(s: TftpSession): BlockSinkFactory =
  ## RFC §5.1 -- resolve the session's injected sink factory, or the
  ## file-backed default (`defaultBlockSinkFactory`, blocksource.nim).
  if s.sinkFactory != nil: s.sinkFactory else: defaultBlockSinkFactory()

proc setupGetTransfer(s: TftpSession, req: TransferRequest, md: TransferMode,
                      requestedParams: TransferParams,
                      getEffective: proc(): Option[TransferParams] {.closure.},
                      xport: Transport, config: TftpClientConfig,
                      progressCb: ProgressCallback,
                      onNegCb: proc(blocksize: int, windowsize: int) {.closure.},
                      flag: ref bool
                      ): tuple[fut: Future[TransferResult], cleanup: proc() {.closure.}] =
  ## tdGet's setup, extracted verbatim from startTransfer's former inline
  ## branch -- builds the lazily-opened receive file + sink, the
  ## write-error/cancel wiring, and launches getFile. `getEffective` reads the
  ## live `effectiveParams` that lives in startTransfer's scope and that
  ## onNegCb mutates; it's passed as a closure (not a `var` param) because a
  ## `var` param captured by a NEW closure built in this proc would reference
  ## a stack slot that outlives this call -- Nim's compiler rejects that
  ## ("cannot be captured... violate memory safety") and suggests exactly
  ## this: a capturable reference. A closure over the caller's own local is
  ## the safe equivalent of a `ref` here.
  var gsink:       BlockSink
  var writeError:  string = ""
  # The RECEIVE-side counterpart of tdPut's readData -- api.nim owns
  # this sink directly (not via engine.nim), so it builds its own
  # `makeRecvHandler` once the sink is open (it can't be built up front like
  # server.handleWrq's, since the open itself is lazy here -- deferred
  # to the first onData call rather than done eagerly). The sink is
  # constructed via `resolveSinkFactory(s)` (RFC in-memory-sources-sinks.md
  # §5.1) -- nil session factory => file-backed default (`open(req.localPath,
  # fmWrite)`), so behavior with no injected factory is byte-for-byte
  # unchanged from the old direct `open`+`fileBlockSink` call.
  #
  # Structural nil-invariant fix: there is deliberately NO separate
  # "is the file open" bool. `recvSink != nil` IS the single source of
  # truth for "the file is open and its sink is ready" -- the open and the
  # sink construction happen in the same branch, guarded by the same check
  # that gates every call to `recvSink` below. A prior version tracked
  # file-openness with its own `gfileOpened` flag, separate from
  # `recvSink`'s nil-ness; a future edit could then in principle flip one
  # without the other and reach `recvSink(...)` while it was still nil
  # (NilAccessDefect, the tracked never-throw hazard). Collapsing both onto
  # one variable makes that ordering a compile-time-adjacent impossibility
  # rather than a doAssert/runtime check.
  var recvSink: proc(data: seq[byte], isFinal: bool): bool

  let onData: proc(blockNum: uint16, data: seq[byte]) =
    proc(blockNum: uint16, data: seq[byte]) =
      if writeError.len > 0: return
      if recvSink == nil:
        try:
          gsink = resolveSinkFactory(s)(req.localPath)
          recvSink = makeRecvHandler(gsink, md)
        except IOError as e:
          writeError = "Cannot open file for writing: " & e.msg
          return
      # Same final-block signal recvBlocks/getFile's single-block branch
      # use (`data.len < negotiated blocksize`); `effectiveParams`
      # (Option[TransferParams]) tracks the negotiated value from the
      # moment onNegCb fires -- `inEffect` (the same never-raising
      # accessor as `TransferSnapshot.inEffect`) falls back to the
      # pre-negotiation requested blocksize before any DATA arrives, the
      # same starting point the old bare `effBs` variable had. A
      # short/failed terminal write is no longer silently discarded --
      # makeRecvHandler folds it into its return value exactly like a
      # per-block write mismatch, so combinedCancel below (and the
      # caller's failure path) observes it.
      if not recvSink(data, data.len < getEffective().inEffect(requestedParams).blocksize):
        writeError = "Write failed"

  let combinedCancel: CancelCheck = proc(): bool = writeError.len > 0 or flag[]

  let cleanup = proc() {.closure.} =
    if recvSink != nil: gsink.close()

  let fut = getFile(xport, config, req.host, req.port, req.filename,
                    onData, progressCb, combinedCancel, onNegCb)
  result = (fut, cleanup)

proc setupPutTransfer(s: TftpSession, req: TransferRequest, md: TransferMode,
                      xport: Transport, config: var TftpClientConfig,
                      progressCb: ProgressCallback,
                      onNegCb: proc(blocksize: int, windowsize: int) {.closure.},
                      flag: ref bool
                      ): tuple[fut: Future[TransferResult], cleanup: proc() {.closure.},
                               startTotal: Option[int64]] =
  ## tdPut's setup, extracted verbatim from startTransfer's former inline
  ## branch -- opens the send source, sizes it into config.tsize, builds the
  ## netascii-aware reader, and launches putFile. Source open is pre-launch;
  ## failure propagates to the caller's outer try/except -> evTransferError,
  ## not a raise out of the public API. `config` is a `var` param (this proc
  ## is NOT `{.async.}`, so that's allowed) purely so `config.tsize` can be
  ## set here instead of the caller doing it after the call.
  ##
  ## The source is constructed via `resolveSourceFactory(s)` (RFC
  ## in-memory-sources-sinks.md §5.1): nil session factory => file-backed
  ## default, preserving today's eager `open(req.localPath, fmRead)` +
  ## `getFileSize` behavior byte-for-byte. The factory's `Option[OpenedSource]`
  ## folds the old "does it exist" / "can it open" distinction into one call:
  ## `none` (not found) is raised here as an IOError so it reaches the exact
  ## same evTransferError outcome the old direct `open` produced for a
  ## missing file; a present-but-unopenable path still raises IOError from
  ## inside the factory itself, propagating unchanged.
  let opened = resolveSourceFactory(s)(req.localPath)
  if opened.isNone:
    raise newException(IOError,
      "Cannot open file for reading: " & req.localPath & " (No such file or directory)")
  let (source, sizeOpt) = opened.get
  let fileSize = sizeOpt.get(0'i64)
  config.tsize = fileSize
  let netasciiPolicy = netasciiPolicyFor(md)
  # Client PUT: `.bytes` counts post-translation wire bytes while
  # `fileSize` is pre-translation local bytes -- under netascii the two
  # can diverge (progress could otherwise exceed 100%), so the reported
  # total is unknown rather than the (wrong) pre-translation size.
  let startTotal = if netasciiPolicy.reportTotalUnknown: none(int64)
                  else: some(fileSize)

  let readData = makeSendReader(source, md)

  let cleanup = proc() {.closure.} = source.close()

  let fut = putFile(xport, config, req.host, req.port, req.filename,
                    readData, progressCb, proc(): bool = flag[], onNegCb)
  result = (fut, cleanup, startTotal)

proc startTransfer*(s: TftpSession, req: TransferRequest): TransferId =
  ## Returns immediately with a valid id.  Never raises (Invariant 2).
  inc s.nextId
  if s.nextId == 0: inc s.nextId   # wrap: skip 0
  let id  = TransferId(s.nextId)
  let t0  = epochTime()
  # Clamp ONCE, up front, before bs/ws are first captured -- this is the
  # structural fix for a verified pre-clamp echo bug (evTransferStarted.snap
  # used to echo the RAW req.options values, while the wire request a few
  # lines below always sent the clamped ones). Reuses the exact same clamp
  # calls the TftpClientConfig construction below already applied; that
  # construction now just reads the already-clamped bs/ws rather than
  # re-deriving them.
  let bs  = validateBlocksize(req.options.blocksize)
  let ws  = max(MinWindowsize, min(MaxWindowsize, req.options.windowsize))
  let dir = req.direction
  let md  = req.options.mode

  ## `requested` is the clamped ask, constant for the whole transfer.
  let requestedParams = TransferParams(blocksize: bs, windowsize: ws)

  ## `effectiveParams` starts `none` (handshake not yet resolved) and
  ## onNegCb sets it to `some(negotiated)` once the handshake settles, so all
  ## subsequent snapshots (evTransferProgress, evTransferComplete) report the
  ## negotiated values. In practice this always happens strictly before the
  ## first evTransferProgress (engine.nim fires onNegotiated before the first
  ## onData/progress callback on every path).
  var effectiveParams: Option[TransferParams] = none(TransferParams)

  let onNegCb = proc(blocksize: int, windowsize: int) {.closure.} =
    effectiveParams = some(TransferParams(blocksize: blocksize, windowsize: windowsize))

  ## Read-only view of `effectiveParams` for setupGetTransfer -- see that
  ## proc's doc comment for why this is a closure rather than a `var` param.
  let getEffective = proc(): Option[TransferParams] {.closure.} = effectiveParams

  template zeroSnap(): TransferSnapshot =
    mkSnap(0, none(int64), dir, md, requestedParams, none(TransferParams), t0)

  try:
    let xport = s.transportFactory(req.host, req.port)

    var config = TftpClientConfig(
      # Clamp into [MinTimeoutOpt, MaxTimeoutOpt] here, same spirit as bs/ws
      # above (clamped once, up front) -- belt-and-suspenders so the public
      # API can never hand engine.getFile/putFile an out-of-range (or zero)
      # timeout in the first place. engine.nim's toTransferConfig clamps
      # too, but that second layer should never be the ONLY thing standing
      # between a bad public-API input and a zero timeout reaching
      # validateAndParseOack's configuredTimeout fallback.
      timeout:      max(MinTimeoutOpt, min(MaxTimeoutOpt, req.options.timeout)),
      retries:      req.options.retries,
      blocksize:    bs,
      windowsize:   ws,
      mode:         md,
      requestTsize: true,
      tsize:        -1
    )

    var flag: ref bool
    new(flag)
    flag[] = false

    var fut: Future[TransferResult]
    var fileCleanup: proc() {.closure.} = nil
    var startTotal: Option[int64] = none(int64)  ## known for PUT, none for GET

    let progressCb: ProgressCallback = proc(bytes, total: int64) =
      # `effectiveParams` is always `some` by the time any progress callback
      # fires -- onNegCb (which sets it) runs strictly before the first
      # onData/progress callback on every engine.nim path (RRQ OACK, RRQ
      # bare-DATA, and the WRQ mirror).
      s.enqueue(Event(xfrId: id, srvId: NoServer, kind: evTransferProgress,
                      snap: mkSnap(bytes,
                                   (if total >= 0: some(total) else: none(int64)),
                                   dir, md, requestedParams,
                                   effectiveParams, t0)))

    case req.direction
    of tdGet:
      let setup   = setupGetTransfer(s, req, md, requestedParams, getEffective,
                                     xport, config, progressCb, onNegCb, flag)
      fut         = setup.fut
      fileCleanup = setup.cleanup

    of tdPut:
      # Source open is pre-launch; failure → outer except → evTransferError, not raise.
      let setup   = setupPutTransfer(s, req, md, xport, config, progressCb, onNegCb, flag)
      fut         = setup.fut
      fileCleanup = setup.cleanup
      startTotal  = setup.startTotal

    # All pre-launch setup succeeded — emit Started then register and drive.
    # startTotal is some(fileSize) for PUT (known upfront), none for GET (tsize via OACK).
    # effective is none here -- the handshake has not resolved yet
    # (onNegCb has not fired).
    s.enqueue(Event(xfrId: id, srvId: NoServer, kind: evTransferStarted,
                    snap: mkSnap(0, startTotal, dir, md, requestedParams,
                                 none(TransferParams), t0)))
    s.transfers[id.uint32] = TransferRecord(cancelFlag: flag, origin: toClient)

    # Capture locals for the callback closure.
    let cId    = id
    let cS     = s
    let cDir   = dir
    let cMd    = md
    let cT0    = t0
    let cXport = xport
    let cClean = fileCleanup

    fut.addCallback(proc() {.closure, gcsafe.} =
      {.cast(gcsafe).}:
        if cClean != nil: cClean()
        # `cEffective` reflects whether onNegCb ever fired for this
        # transfer -- `some` for the overwhelming common case (failure/
        # completion after a resolved handshake), `none` only if the
        # transfer failed before negotiation ever resolved (e.g. handshake
        # timeout).
        let cEffective = effectiveParams
        if fut.failed:
          cS.enqueue(Event(xfrId: cId, srvId: NoServer, kind: evTransferError,
                           snap: mkSnap(0, none(int64), cDir, cMd, requestedParams,
                                        cEffective, cT0),
                           errorCode: none(TftpErrorCode), errorMsg: fut.readError().msg))
        else:
          let r      = fut.read()
          let totOpt = if r.totalSize >= 0: some(r.totalSize) else: none(int64)
          if r.success:
            cS.enqueue(Event(xfrId: cId, srvId: NoServer, kind: evTransferComplete,
                             snap: mkSnap(r.bytesTransferred, totOpt, cDir, cMd, requestedParams,
                                          cEffective, cT0)))
          else:
            cS.enqueue(Event(xfrId: cId, srvId: NoServer, kind: evTransferError,
                             snap: mkSnap(r.bytesTransferred, totOpt, cDir, cMd, requestedParams,
                                          cEffective, cT0),
                             errorCode: r.errorCode, errorMsg: r.errorMsg))
        if cXport.close != nil: cXport.close()
        cS.transfers.del(cId.uint32)
    )

  except CatchableError as e:
    s.enqueue(Event(xfrId: id, srvId: NoServer, kind: evTransferError,
                    snap: zeroSnap(), errorCode: none(TftpErrorCode), errorMsg: e.msg))

  return id

proc cancel*(s: TftpSession, id: TransferId) =
  ## Signal an active transfer to cancel. If `id` is not currently active
  ## (already resolved, never started, or from another session) this is a
  ## no-op. Never raises. Never enqueues a terminal event directly — the
  ## transfer future's addCallback does that when it observes the flag.
  if id.uint32 in s.transfers:
    let rec = s.transfers[id.uint32]
    if rec.cancelFlag != nil: rec.cancelFlag[] = true

proc startServer*(s: TftpSession, config: ServerConfig): ServerId =
  ## Start a TFTP server and return its id immediately.  Never raises (Invariant 2).
  ## On bind failure enqueues evServerStartFailed and returns the id; caller can
  ## distinguish success vs failure by draining poll.
  inc s.nextServerId
  if s.nextServerId == 0: inc s.nextServerId
  let srvId = ServerId(s.nextServerId)

  try:
    # RFC conformance-closure D7: reject an out-of-RFC-bound config (blksize,
    # windowsize, timeout) at server construction, before any listener binds
    # or RRQ is served. Routes through the single shared authority (server_config.
    # serverConfigBoundsValid) so this can never drift from handleRrq's/
    # handleWrq's own copy of the same rule.
    if not serverConfigBoundsValid(config):
      raise newException(ValueError,
        "ServerConfig option bounds out of RFC range (blksize " &
        $MinBlocksize & ".." & $MaxBlocksize & ", windowsize " &
        $MinWindowsize & ".." & $MaxWindowsize & ", timeout " &
        $MinTimeoutOpt & ".." & $MaxTimeoutOpt & ")")

    # --- Build listener ---
    let listener: UdpListener =
      if s.listenerFactory != nil:
        s.listenerFactory(config.listenAddr, config.listenPort)
      else:
        transportMod.newUdpListener(config.listenAddr, config.listenPort,
                                    transportMod.isIPv6(config.listenAddr))

    # Locals captured by the server callbacks.
    let cS     = s
    let cSrvId = srvId

    # --- Build ServerCallbacks that translate into Session events ---
    let callbacks = ServerCallbacks(
      onTransferStart: proc(info: TransferInfo) {.closure.} =
        {.cast(gcsafe).}:
          inc cS.nextId
          if cS.nextId == 0: inc cS.nextId
          let tid  = TransferId(cS.nextId)
          let key: XferKey = info.reqId   # unique per accepted request
          let k32  = cSrvId.uint32
          if k32 in cS.servers:
            cS.servers[k32].xfers[key] = tid
            # Consume the transient cancelFactory->onTransferStart bridge:
            # move the flag into the single consolidated transfers table.
            let cancelFlag = cS.servers[k32].cancelFlags.getOrDefault(key, nil)
            cS.servers[k32].cancelFlags.del(key)
            cS.transfers[tid.uint32] = TransferRecord(cancelFlag: cancelFlag, origin: toServer)
          let dir    = if info.direction == "RRQ": tdGet else: tdPut
          let totOpt = if info.totalBytes >= 0: some(info.totalBytes) else: none(int64)
          # Server-side effective is always some(...) here (OACK, if any,
          # precedes onStart) -- some(defaults) even for a bare RRQ/WRQ with
          # zero options, meaning "in-effect defaults," not "an OACK occurred."
          cS.enqueue(Event(xfrId: tid, srvId: cSrvId, kind: evTransferStarted,
                           snap: mkSnap(0, totOpt, dir, info.mode,
                                        info.requestedParams,
                                        some(TransferParams(blocksize: info.blocksize,
                                                        windowsize: info.windowsize)),
                                        info.startedAt)))
      ,
      onTransferProgress: proc(info: TransferInfo) {.closure.} =
        {.cast(gcsafe).}:
          let key: XferKey = info.reqId
          let k32  = cSrvId.uint32
          if k32 notin cS.servers: return
          let tid  = cS.servers[k32].xfers.getOrDefault(key, NoTransfer)
          if tid == NoTransfer: return
          let dir    = if info.direction == "RRQ": tdGet else: tdPut
          let totOpt = if info.totalBytes >= 0: some(info.totalBytes) else: none(int64)
          cS.enqueue(Event(xfrId: tid, srvId: cSrvId, kind: evTransferProgress,
                           snap: mkSnap(info.bytesTransferred, totOpt, dir, info.mode,
                                        info.requestedParams,
                                        some(TransferParams(blocksize: info.blocksize,
                                                        windowsize: info.windowsize)),
                                        info.startedAt)))
      ,
      onTransferComplete: proc(info: TransferInfo) {.closure.} =
        {.cast(gcsafe).}:
          let key: XferKey = info.reqId
          let k32  = cSrvId.uint32
          if k32 notin cS.servers: return
          let tid  = cS.servers[k32].xfers.getOrDefault(key, NoTransfer)
          if tid == NoTransfer: return
          cS.servers[k32].xfers.del(key)
          cS.transfers.del(tid.uint32)
          let dir    = if info.direction == "RRQ": tdGet else: tdPut
          let totOpt = if info.totalBytes >= 0: some(info.totalBytes) else: none(int64)
          cS.enqueue(Event(xfrId: tid, srvId: cSrvId, kind: evTransferComplete,
                           snap: mkSnap(info.bytesTransferred, totOpt, dir, info.mode,
                                        info.requestedParams,
                                        some(TransferParams(blocksize: info.blocksize,
                                                        windowsize: info.windowsize)),
                                        info.startedAt)))
      ,
      onTransferError: proc(info: TransferInfo, msg: string) {.closure.} =
        {.cast(gcsafe).}:
          let key: XferKey = info.reqId
          let k32  = cSrvId.uint32
          if k32 notin cS.servers: return
          cS.servers[k32].cancelFlags.del(key)  # always clean up before early return, even on the failure path
          let tid  = cS.servers[k32].xfers.getOrDefault(key, NoTransfer)
          if tid == NoTransfer: return  # failure before onStart — drop (Invariant 4)
          cS.servers[k32].xfers.del(key)
          cS.transfers.del(tid.uint32)
          let dir    = if info.direction == "RRQ": tdGet else: tdPut
          let totOpt = if info.totalBytes >= 0: some(info.totalBytes) else: none(int64)
          cS.enqueue(Event(xfrId: tid, srvId: cSrvId, kind: evTransferError,
                           snap: mkSnap(info.bytesTransferred, totOpt, dir, info.mode,
                                        info.requestedParams,
                                        some(TransferParams(blocksize: info.blocksize,
                                                        windowsize: info.windowsize)),
                                        info.startedAt),
                           errorCode: info.errorCode, errorMsg: msg))
    )

    # --- Logger that feeds evServerLog ---
    let logOutput: LogOutput = proc(level: LogLevel, msg: string) =
      {.cast(gcsafe).}:
        cS.enqueue(Event(xfrId: NoTransfer, srvId: cSrvId, kind: evServerLog,
                         sLevel: level, sMessage: msg))
    let logger = newLogger(s.minLogLevel, logOutput)

    # --- Build TftpServer; wire transferFactory + cancelFactory through the session ---
    let srv = newTftpServer(config, callbacks, logger)
    srv.transferFactory = proc(port: int): Transport =
      cS.transportFactory("127.0.0.1", port)
    srv.cancelFactory = proc(reqId: int): CancelCheck =
      {.cast(gcsafe).}:
        var flag: ref bool
        new(flag); flag[] = false
        let key: XferKey = reqId
        let k32 = cSrvId.uint32
        if k32 in cS.servers:
          cS.servers[k32].cancelFlags[key] = flag
        return proc(): bool = flag[]

    # --- Emit evServerStarted BEFORE storing (so poll can deliver it first) ---
    # Use listener.localPort() so callers that bind port 0 learn the real
    # OS-assigned ephemeral port rather than the requested 0.
    s.enqueue(Event(xfrId: NoTransfer, srvId: srvId, kind: evServerStarted,
                    boundAddr: config.listenAddr,
                    boundPort: (if listener.localPort != nil: listener.localPort() else: config.listenPort)))

    # --- Store the entry BEFORE starting run so callbacks can write to xfers ---
    let entry = ServerEntry(
      srv:            srv,
      listener:       listener,
      stopRequested:  false,
      stoppedEmitted: false,
      xfers:          initTable[int, TransferId](),
      cancelFlags:    initTable[int, ref bool]()
    )
    s.servers[srvId.uint32] = entry

    # --- Drive run() via addCallback (never asyncCheck — Invariant 2) ---
    let runFut = srv.run(listener)
    entry.runFut = runFut
    runFut.addCallback(proc() = discard)

  except CatchableError as e:
    s.enqueue(Event(xfrId: NoTransfer, srvId: srvId, kind: evServerStartFailed,
                    startErr: e.msg))

  return srvId

proc stop*(s: TftpSession, id: ServerId) =
  ## Signal the server to stop accepting new requests.  In-flight transfers run
  ## to completion.  evServerStopped is emitted once the run loop exits and all
  ## active transfers drain.  Never raises (Invariant 7).
  let k32 = id.uint32
  if k32 notin s.servers: return
  let entry = s.servers[k32]
  if entry.stopRequested: return
  entry.stopRequested = true
  entry.srv.stop()

iterator poll*(s: TftpSession, timeoutMs: int = 0): Event =
  ## Pump the dispatcher then drain and yield all queued events.
  ## Never raises (Invariant 2). Yields are outside try/except (Nim constraint).
  try:
    if hasPendingOperations() or timeoutMs > 0:
      asyncdispatch.poll(timeoutMs)
    # Drain gate: emit evServerStopped exactly once when run loop exits + no
    # active transfers remain (Invariant 8).
    # Collect keys to delete AFTER the loop (safe iteration; deleting from
    # a Table while iterating over it is undefined behavior).
    var stoppedKeys: seq[uint32]
    for srvKey, entry in s.servers.pairs:
      if not entry.stoppedEmitted and
         entry.runFut != nil and entry.runFut.finished and
         entry.srv.activeTransfers == 0:
        entry.stoppedEmitted = true
        if entry.listener.close != nil:
          try: entry.listener.close() except CatchableError: discard
        if entry.runFut.failed:
          s.enqueue(Event(xfrId: NoTransfer, srvId: ServerId(srvKey),
                          kind: evServerLog, sLevel: llError,
                          sMessage: entry.runFut.readError.msg))
        s.enqueue(Event(xfrId: NoTransfer, srvId: ServerId(srvKey),
                        kind: evServerStopped))
        stoppedKeys.add(srvKey)
    # Delete stopped servers and their lingering transfer records.
    for k in stoppedKeys:
      if k in s.servers:
        let ent = s.servers[k]
        for _, tid in ent.xfers.pairs:
          s.transfers.del(tid.uint32)
        s.servers.del(k)
  except CatchableError:
    discard  # empty-dispatcher ValueError or any I/O escape → yield nothing
  while true:
    let ev = s.queue.tryPopFirst()
    if ev.isNone: break
    yield ev.get

proc close*(s: TftpSession) =
  ## Signal all active client transfers to cancel and all servers to stop.
  ## Never raises.  Use drain() as the ergonomic teardown companion — it pumps
  ## poll() until all terminals are emitted and resources are released.
  ## Manual poll() pumping is only necessary if transfers are still in flight
  ## and the caller needs to inspect events before draining.
  ## Do NOT force-close transports here — the in-flight futures own them; let
  ## their addCallbacks close transports after the future resolves.
  for _, rec in s.transfers.pairs:
    if rec.origin == toClient and rec.cancelFlag != nil:
      rec.cancelFlag[] = true
  for _, srvEntry in s.servers.pairs:
    if not srvEntry.stopRequested:
      srvEntry.stopRequested = true
      srvEntry.srv.stop()

proc drain*(s: TftpSession, timeoutMs: int = 2000) =
  ## Ergonomic teardown companion to close().  Pumps poll(2) in a loop until
  ## there are no active client transfers AND all servers have emitted their
  ## terminal event, or the deadline elapses, or no pending async work remains.
  ## Never raises.  Events yielded during drain are discarded — callers that
  ## need them should collect events before calling close()+drain().
  let deadline = epochTime() + timeoutMs.float / 1000.0
  while true:
    try:
      for ev in s.poll(2): discard
    except CatchableError: discard
    if s.activeClientCount() == 0 and s.servers.len == 0: break
    if not hasPendingOperations() and s.queue.len == 0: break
    if epochTime() >= deadline: break

proc waitTransfer*(s: TftpSession, id: TransferId): TransferResult =
  ## Loops on poll(2) until `id` reaches its terminal event
  ## (evTransferComplete or evTransferError).  Events for OTHER ids are buffered
  ## and re-enqueued after this returns so they are not swallowed.  Never raises.
  var buffered: seq[Event]
  var found = false
  var cap = WaitCapIterations
  while cap > 0:
    dec cap
    for ev in s.poll(2):
      if ev.xfrId == id and ev.kind in {evTransferComplete, evTransferError}:
        if ev.kind == evTransferComplete:
          result = TransferResult(success: true,
                                  bytesTransferred: ev.snap.bytes,
                                  totalSize: ev.snap.total.get(-1))
        else:
          result = TransferResult(success: false,
                                  bytesTransferred: ev.snap.bytes,
                                  totalSize: ev.snap.total.get(-1),
                                  errorCode: ev.errorCode,
                                  errorMsg: ev.errorMsg)
        found = true
        break   # remaining events stay in s.queue (dequeue-per-yield)
      else:
        buffered.add ev
    if found: break
    if not hasPendingOperations() and s.queue.len == 0:
      break   # no async work remains; target terminal will never arrive
  if not found:
    result = TransferResult(success: false,
                            errorMsg: "waitTransfer: no terminal event received",
                            totalSize: -1)
  for ev in buffered:
    s.enqueue(ev)

proc waitServer*(s: TftpSession, id: ServerId) =
  ## Loops on poll(2) until `id` emits evServerStopped or evServerStartFailed.
  ## Non-target events are buffered and re-enqueued after this returns.
  ## Never raises.
  var buffered: seq[Event]
  var found = false
  var cap = WaitCapIterations
  while cap > 0:
    dec cap
    for ev in s.poll(2):
      if ev.srvId == id and ev.kind in {evServerStopped, evServerStartFailed}:
        found = true
        break   # remaining events stay in s.queue
      else:
        buffered.add ev
    if found: break
    if not hasPendingOperations() and s.queue.len == 0:
      break
  for ev in buffered:
    s.enqueue(ev)

# ---------------------------------------------------------------------------
# Test-observable helpers (minimal; used only by t_session.nim)
# Compiled only when -d:chapulinTest is passed; invisible in production builds.
# ---------------------------------------------------------------------------

when defined(chapulinTest):
  proc sessionServerCount*(s: TftpSession): int =
    ## Returns the number of server entries currently retained in the session.
    ## Zero after all servers have emitted evServerStopped.
    s.servers.len

  proc sessionActiveCount*(s: TftpSession): int =
    ## Returns the number of active client transfers currently in the session.
    ## (Server-side transfers share the same consolidated `transfers` table
    ## but are excluded — see `activeClientCount`.)
    s.activeClientCount()

  proc sessionQueueLen*(s: TftpSession): int =
    ## Returns the current number of events waiting in the session queue.
    s.queue.len

  proc injectEvent*(s: TftpSession, ev: Event) =
    ## Test helper: inject an event directly through enqueue (exercises cap logic).
    s.enqueue(ev)
