## Public API — the stable contract that CLI and GUI frontends consume.
## No frontend should import protocol or engine directly.

import std/asyncdispatch
import engine
import protocol
export Transport, CancelCheck, TransportTimeoutError,
       TransferResult, DefaultBlocksize, DefaultTimeout,
       DefaultRetries, DefaultWindowsize, MinWindowsize, MaxWindowsize,
       MinBlocksize, MaxBlocksize, validateBlocksize,
       TransferMode
import std/os
import std/[deques, tables, options, times]
export options
import logging
import transport as transportMod
import server
import server_config
import format
export LogLevel, formatLogMessage, UdpListener
export server_config
export fraction, formatBytes, formatSpeed, sanitizeForDisplay

type
  TransferDirection* = enum
    tdGet
    tdPut

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

type
  TransferId* = distinct uint32
  ServerId*   = distinct uint32

const
  NoTransfer* = TransferId(0)
  NoServer*   = ServerId(0)

proc `==`*(a, b: TransferId): bool {.borrow.}
proc `==`*(a, b: ServerId):   bool {.borrow.}

type
  TransportFactory* = proc(host: string, port: int): Transport {.closure.}
  ListenerFactory*  = proc(bindAddr: string, port: int): UdpListener {.closure.}

  EventKind* = enum
    evTransferStarted, evTransferProgress, evTransferComplete, evTransferError,
    evTransferLog, evServerStarted, evServerStartFailed, evServerStopped, evServerLog

  TransferSnapshot* = object
    bytes*:      int64
    total*:      Option[int64]   ## none until tsize negotiated
    blocksize*:  int             ## client: requested at evTransferStarted, negotiated (OACK) from first evTransferProgress onward; server: already negotiated at evTransferStarted (OACK precedes onStart)
    windowsize*: int             ## client: requested at evTransferStarted, negotiated (OACK) from first evTransferProgress onward; server: already negotiated at evTransferStarted (OACK precedes onStart)
    direction*:  TransferDirection
    mode*:       TransferMode
    startedAt*:  float           ## epochTime() at transfer start

  Event* = object
    xfrId*: TransferId
    srvId*: ServerId
    snap*:  TransferSnapshot   ## common field; populated for all evTransfer* kinds; zero for server events
    case kind*: EventKind
    of evTransferStarted, evTransferProgress, evTransferComplete:
      discard
    of evTransferError:
      errorCode*: int
      errorMsg*:  string
    of evTransferLog:
      xLevel*:   LogLevel
      xMessage*: string
    of evServerStarted:
      boundAddr*: string
      boundPort*: int
    of evServerStartFailed:
      startErr*: string
    of evServerLog:
      sLevel*:   LogLevel
      sMessage*: string
    of evServerStopped:
      discard

  TransferEntry = object
    transport:        Transport
    cancelRequested:  ref bool

  XferKey = int  ## monotonic reqId allocated once per accepted request

  ServerEntry = ref object
    srv:            TftpServer
    listener:       UdpListener
    runFut:         Future[void]
    stopRequested:  bool
    stoppedEmitted: bool
    xfers:          Table[XferKey, TransferId]
    cancelFlags:    Table[XferKey, ref bool]

  TftpSession* = ref object
    events:           Deque[Event]
    nextId:           uint32
    active:           Table[uint32, TransferEntry]
    minLogLevel:      LogLevel
    transportFactory: TransportFactory
    listenerFactory:  ListenerFactory
    servers:          Table[uint32, ServerEntry]
    nextServerId:     uint32
    serverXferCancel: Table[uint32, ref bool]
    droppedLogCount:  int  ## FIX 7: count of log events dropped due to queue cap

const MaxQueuedEvents* = 8192 ## hard cap on s.events; oldest log events evicted when full
const WaitCapIterations = 5_000_000 ## safety valve; hasPendingOperations early-exit fires first

proc enqueue(s: TftpSession, ev: Event) =
  ## Append ev to the session event queue.
  ## FIX 7: bounded — drops log events when full; never drops terminals or evTransferStarted.
  let isProtected = ev.kind in {evTransferComplete, evTransferError,
                                 evServerStopped, evServerStartFailed, evTransferStarted}
  # Coalesce progress: replace the existing entry for the same id so the queue
  # never accumulates more than one evTransferProgress per transfer id.
  if ev.kind == evTransferProgress:
    for i in 0 ..< s.events.len:
      if s.events[i].kind == evTransferProgress and s.events[i].xfrId == ev.xfrId:
        s.events[i] = ev   # coalesce: latest wins, position kept
        return
    # No existing entry — fall through to bounded add.

  if s.events.len >= MaxQueuedEvents:
    if not isProtected:
      # Log / progress event: drop and count.
      inc s.droppedLogCount
      return
    else:
      # Protected event: evict the oldest log event to make room.
      var newDq = initDeque[Event]()
      var evicted = false
      for item in s.events:
        if not evicted and item.kind in {evServerLog, evTransferLog}:
          evicted = true
          inc s.droppedLogCount   # count the evicted log as dropped
        else:
          newDq.addLast(item)
      if evicted:
        s.events = newDq
      # If no log found, fall through and temporarily exceed the cap for this critical event.

  # If previous calls dropped events and we now have room, emit one warning.
  if s.droppedLogCount > 0:
    let n = s.droppedLogCount
    s.droppedLogCount = 0
    # Direct addLast — do NOT call enqueue() recursively to avoid re-triggering.
    s.events.addLast(Event(xfrId: NoTransfer, srvId: NoServer, kind: evServerLog,
                           sLevel: llWarn,
                           sMessage: "dropped " & $n & " log events (queue cap)"))
  s.events.addLast(ev)

proc mkSnap(bytes: int64, total: Option[int64],
            direction: TransferDirection, mode: TransferMode,
            bs, ws: int, startedAt: float): TransferSnapshot =
  TransferSnapshot(bytes: bytes, total: total, blocksize: bs, windowsize: ws,
                   direction: direction, mode: mode, startedAt: startedAt)

proc newSession*(minLogLevel: LogLevel = llInfo,
                 transportFactory: TransportFactory = nil,
                 listenerFactory:  ListenerFactory = nil): TftpSession =
  let factory =
    if transportFactory != nil: transportFactory
    else:
      proc(host: string, port: int): Transport =
        transportMod.newUdpTransport(0, transportMod.isIPv6(host))
  TftpSession(
    events:           initDeque[Event](),
    nextId:           0,
    active:           initTable[uint32, TransferEntry](),
    minLogLevel:      minLogLevel,
    transportFactory: factory,
    listenerFactory:  listenerFactory,
    servers:          initTable[uint32, ServerEntry](),
    nextServerId:     0,
    serverXferCancel: initTable[uint32, ref bool]()
  )

proc startTransfer*(s: TftpSession, req: TransferRequest): TransferId =
  ## Returns immediately with a valid id.  Never raises (Invariant 2).
  inc s.nextId
  if s.nextId == 0: inc s.nextId   # wrap: skip 0
  let id  = TransferId(s.nextId)
  let t0  = epochTime()
  let bs  = req.options.blocksize
  let ws  = req.options.windowsize
  let dir = req.direction
  let md  = req.options.mode

  ## effBs/effWs start at the requested values (best-effort pre-OACK).
  ## onNegCb updates them once the handshake settles so all subsequent
  ## snapshots (evTransferProgress, evTransferComplete) report the negotiated values.
  var effBs = bs
  var effWs = ws

  let onNegCb = proc(blocksize: int, windowsize: int) {.closure.} =
    effBs = blocksize
    effWs = windowsize

  template zeroSnap(): TransferSnapshot =
    mkSnap(0, none(int64), dir, md, bs, ws, t0)

  try:
    let xport = s.transportFactory(req.host, req.port)

    var config = TftpClientConfig(
      timeout:      req.options.timeout,
      retries:      req.options.retries,
      blocksize:    validateBlocksize(bs),
      windowsize:   max(MinWindowsize, min(MaxWindowsize, ws)),
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
      s.enqueue(Event(xfrId: id, srvId: NoServer, kind: evTransferProgress,
                      snap: mkSnap(bytes,
                                   (if total >= 0: some(total) else: none(int64)),
                                   dir, md, effBs, effWs, t0)))

    case req.direction
    of tdGet:
      var gfile:       File
      var gfileOpened: bool = false
      var writeError:  string = ""

      let onData: proc(blockNum: uint16, data: seq[byte]) =
        proc(blockNum: uint16, data: seq[byte]) =
          if writeError.len > 0: return
          if not gfileOpened:
            try:
              gfile = open(req.localPath, fmWrite)
              gfileOpened = true
            except IOError as e:
              writeError = "Cannot open file for writing: " & e.msg
              return
          if data.len > 0:
            let written = gfile.writeBytes(data, 0, data.len)
            if written != data.len:
              writeError = "Write failed"

      let combinedCancel: CancelCheck = proc(): bool = writeError.len > 0 or flag[]

      fileCleanup = proc() {.closure.} =
        if gfileOpened: gfile.close()

      fut = getFile(xport, config, req.host, req.port, req.filename,
                    onData, progressCb, combinedCancel, onNegCb)

    of tdPut:
      # File open is pre-launch; failure → outer except → evTransferError, not raise.
      var pfile = open(req.localPath, fmRead)
      let fileSize = getFileSize(req.localPath)
      config.tsize = fileSize
      startTotal = some(fileSize)

      var blockCache: seq[byte]
      var cachedBlock: uint16 = 0

      let readData: proc(blockNum: uint16, blocksize: int): seq[byte] =
        proc(blockNum: uint16, blocksize: int): seq[byte] =
          if blockNum == 0: return @[]
          if blockNum == cachedBlock: return blockCache
          let offset = int64(blockNum - 1) * int64(blocksize)
          pfile.setFilePos(offset)
          var buf = newSeq[byte](blocksize)
          let nr = pfile.readBytes(buf, 0, blocksize)
          buf.setLen(nr)
          blockCache = buf
          cachedBlock = blockNum
          return buf

      fileCleanup = proc() {.closure.} = pfile.close()

      fut = putFile(xport, config, req.host, req.port, req.filename,
                    readData, progressCb, proc(): bool = flag[], onNegCb)

    # All pre-launch setup succeeded — emit Started then register and drive.
    # startTotal is some(fileSize) for PUT (known upfront), none for GET (tsize via OACK).
    s.enqueue(Event(xfrId: id, srvId: NoServer, kind: evTransferStarted,
                    snap: mkSnap(0, startTotal, dir, md, bs, ws, t0)))
    s.active[id.uint32] = TransferEntry(transport: xport, cancelRequested: flag)

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
        if fut.failed:
          cS.enqueue(Event(xfrId: cId, srvId: NoServer, kind: evTransferError,
                           snap: mkSnap(0, none(int64), cDir, cMd, effBs, effWs, cT0),
                           errorCode: 0, errorMsg: fut.readError().msg))
        else:
          let r      = fut.read()
          let totOpt = if r.totalSize >= 0: some(r.totalSize) else: none(int64)
          if r.success:
            cS.enqueue(Event(xfrId: cId, srvId: NoServer, kind: evTransferComplete,
                             snap: mkSnap(r.bytesTransferred, totOpt, cDir, cMd, effBs, effWs, cT0)))
          else:
            cS.enqueue(Event(xfrId: cId, srvId: NoServer, kind: evTransferError,
                             snap: mkSnap(r.bytesTransferred, totOpt, cDir, cMd, effBs, effWs, cT0),
                             errorCode: r.errorCode, errorMsg: r.errorMsg))
        if cXport.close != nil: cXport.close()
        cS.active.del(cId.uint32)
    )

  except CatchableError as e:
    s.enqueue(Event(xfrId: id, srvId: NoServer, kind: evTransferError,
                    snap: zeroSnap(), errorCode: 0, errorMsg: e.msg))

  return id

proc cancel*(s: TftpSession, id: TransferId) =
  ## Signal an active transfer to cancel. If `id` is not currently active
  ## (already resolved, never started, or from another session) this is a
  ## no-op. Never raises. Never enqueues a terminal event directly — the
  ## transfer future's addCallback does that when it observes the flag.
  if id.uint32 in s.active:
    s.active[id.uint32].cancelRequested[] = true
  elif id.uint32 in s.serverXferCancel:
    s.serverXferCancel[id.uint32][] = true

proc startServer*(s: TftpSession, config: ServerConfig): ServerId =
  ## Start a TFTP server and return its id immediately.  Never raises (Invariant 2).
  ## On bind failure enqueues evServerStartFailed and returns the id; caller can
  ## distinguish success vs failure by draining poll.
  inc s.nextServerId
  if s.nextServerId == 0: inc s.nextServerId
  let srvId = ServerId(s.nextServerId)

  try:
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
            let cancelFlag = cS.servers[k32].cancelFlags.getOrDefault(key, nil)
            if cancelFlag != nil:
              cS.serverXferCancel[tid.uint32] = cancelFlag
          let dir    = if info.direction == "RRQ": tdGet else: tdPut
          let totOpt = if info.totalBytes >= 0: some(info.totalBytes) else: none(int64)
          cS.enqueue(Event(xfrId: tid, srvId: cSrvId, kind: evTransferStarted,
                           snap: mkSnap(0, totOpt, dir, info.mode,
                                        info.blocksize, info.windowsize, info.startedAt)))
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
                                        info.blocksize, info.windowsize, info.startedAt)))
      ,
      onTransferComplete: proc(info: TransferInfo) {.closure.} =
        {.cast(gcsafe).}:
          let key: XferKey = info.reqId
          let k32  = cSrvId.uint32
          if k32 notin cS.servers: return
          let tid  = cS.servers[k32].xfers.getOrDefault(key, NoTransfer)
          if tid == NoTransfer: return
          cS.servers[k32].xfers.del(key)
          cS.servers[k32].cancelFlags.del(key)
          cS.serverXferCancel.del(tid.uint32)
          let dir    = if info.direction == "RRQ": tdGet else: tdPut
          let totOpt = if info.totalBytes >= 0: some(info.totalBytes) else: none(int64)
          cS.enqueue(Event(xfrId: tid, srvId: cSrvId, kind: evTransferComplete,
                           snap: mkSnap(info.bytesTransferred, totOpt, dir, info.mode,
                                        info.blocksize, info.windowsize, info.startedAt)))
      ,
      onTransferError: proc(info: TransferInfo, msg: string) {.closure.} =
        {.cast(gcsafe).}:
          let key: XferKey = info.reqId
          let k32  = cSrvId.uint32
          if k32 notin cS.servers: return
          cS.servers[k32].cancelFlags.del(key)  # FIX 6b: always clean up before early return
          let tid  = cS.servers[k32].xfers.getOrDefault(key, NoTransfer)
          if tid == NoTransfer: return  # failure before onStart — drop (Invariant 4)
          cS.servers[k32].xfers.del(key)
          cS.serverXferCancel.del(tid.uint32)
          let dir    = if info.direction == "RRQ": tdGet else: tdPut
          let totOpt = if info.totalBytes >= 0: some(info.totalBytes) else: none(int64)
          cS.enqueue(Event(xfrId: tid, srvId: cSrvId, kind: evTransferError,
                           snap: mkSnap(info.bytesTransferred, totOpt, dir, info.mode,
                                        info.blocksize, info.windowsize, info.startedAt),
                           errorCode: 0, errorMsg: msg))
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
    # FIX 6a: collect keys to delete AFTER the loop (safe iteration).
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
    # Delete stopped servers and their lingering serverXferCancel entries.
    for k in stoppedKeys:
      if k in s.servers:
        let ent = s.servers[k]
        for _, tid in ent.xfers.pairs:
          s.serverXferCancel.del(tid.uint32)
        s.servers.del(k)
  except CatchableError:
    discard  # empty-dispatcher ValueError or any I/O escape → yield nothing
  while s.events.len > 0:
    yield s.events.popFirst()

proc close*(s: TftpSession) =
  ## Signal all active client transfers to cancel and all servers to stop.
  ## Never raises.  Use drain() as the ergonomic teardown companion — it pumps
  ## poll() until all terminals are emitted and resources are released.
  ## Manual poll() pumping is only necessary if transfers are still in flight
  ## and the caller needs to inspect events before draining.
  ## Do NOT force-close transports here — the in-flight futures own them; let
  ## their addCallbacks close transports after the future resolves.
  for _, entry in s.active:
    entry.cancelRequested[] = true
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
    if s.active.len == 0 and s.servers.len == 0: break
    if not hasPendingOperations() and s.events.len == 0: break
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
        break   # remaining events stay in s.events (dequeue-per-yield)
      else:
        buffered.add ev
    if found: break
    if not hasPendingOperations() and s.events.len == 0:
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
        break   # remaining events stay in s.events
      else:
        buffered.add ev
    if found: break
    if not hasPendingOperations() and s.events.len == 0:
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
    ## Zero after all servers have emitted evServerStopped (FIX 6a).
    s.servers.len

  proc sessionActiveCount*(s: TftpSession): int =
    ## Returns the number of active client transfers currently in the session.
    s.active.len

  proc sessionQueueLen*(s: TftpSession): int =
    ## Returns the current number of events waiting in the session queue.
    s.events.len

  proc injectEvent*(s: TftpSession, ev: Event) =
    ## Test helper: inject an event directly through enqueue (exercises cap logic).
    s.enqueue(ev)
