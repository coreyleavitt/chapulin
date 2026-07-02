## Tests for TftpSession slice 1: spine + client transfers.
##
## All tests run over an in-memory wire (tests/wireharness.nim); no real UDP.
## Drive loop: s.poll(0) in a step-capped loop pumps the shared dispatcher,
## advancing both the client future (owned by TftpSession) and the server
## responder future concurrently.
##
## Run:
##   docker run --rm -v ${PWD}:/app -w /app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r --hints:off tests/t_session.nim

import std/unittest
import std/[os, asyncdispatch, strutils, options, times]
import proptest
import ../src/chapulin/api
import ../src/chapulin/server
import ../src/chapulin/server_config
import ../src/chapulin/protocol
import ../src/chapulin/transfer
import ./wireharness

# ---------------------------------------------------------------------------
# Drive helper: pump s.poll(0) until a terminal event for `id` is seen or
# the step cap is hit.  Returns all collected events.
# ---------------------------------------------------------------------------
proc driveSession(s: TftpSession, id: TransferId,
                  maxSteps = 200_000): seq[Event] =
  var done = false
  var steps = 0
  while steps < maxSteps and not done:
    for ev in s.poll(0):
      result.add ev
      if ev.xfrId == id and ev.kind in {evTransferComplete, evTransferError}:
        done = true
    inc steps
  # Drain any remaining events after terminal (e.g. none, but be tidy)
  if done:
    for ev in s.poll(0):
      result.add ev

# ---------------------------------------------------------------------------
# Test 1: idle poll — yields nothing and does NOT raise
# ---------------------------------------------------------------------------
suite "TftpSession — idle poll":
  test "idle poll on fresh session yields nothing and does not raise":
    let s = newSession()
    var n = 0
    for ev in s.poll(0): inc n
    check n == 0

# ---------------------------------------------------------------------------
# Test 2: client GET over in-memory wire
# ---------------------------------------------------------------------------
suite "TftpSession — client GET over wire":
  test "GET emits Started then at-least-one Progress then Complete":
    # Server-side: temp dir with a known file.
    let tmpDir = getTempDir() / "chapulin_t_session_get"
    createDir(tmpDir)
    let serverFile = tmpDir / "hello.txt"
    writeFile(serverFile, "Hello from TFTP!")   # 16 bytes, fits in one block

    let localOut = getTempDir() / "chapulin_t_session_get_out.bin"
    defer:
      try: removeFile(localOut)  except: discard
      try: removeDir(tmpDir)     except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()

    # Server responder: recv the RRQ, hand off to handleRrq.
    let serverT = makeTransport(w, sideA = false)
    proc serverRespond(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      let pkt = decode(data)
      discard await handleRrq(serverCfg, pkt, serverT, host, port)
    discard serverRespond()

    # Session with a factory that returns the client side of the wire.
    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))

    var req = newTransferRequest("peer", 0, "hello.txt", localOut, tdGet)
    let id = s.startTransfer(req)

    check id != NoTransfer

    let evs = driveSession(s, id)

    # Structural assertions
    check evs.len >= 3                        # Started + ≥1 Progress + Complete
    check evs[0].kind == evTransferStarted
    check evs[^1].kind == evTransferComplete
    for ev in evs:
      check ev.xfrId == id
      check ev.srvId == NoServer

    # At least one progress event
    var hasProgress = false
    for ev in evs:
      if ev.kind == evTransferProgress: hasProgress = true
    check hasProgress

    # File content must match what was served
    check fileExists(localOut)
    check readFile(localOut) == "Hello from TFTP!"

# ---------------------------------------------------------------------------
# Test 3: client PUT over in-memory wire
# ---------------------------------------------------------------------------
suite "TftpSession — client PUT over wire":
  test "PUT emits Started then at-least-one Progress then Complete":
    let tmpDir = getTempDir() / "chapulin_t_session_put"
    createDir(tmpDir)

    let localSrc = getTempDir() / "chapulin_t_session_put_src.bin"
    writeFile(localSrc, "Upload this data!")   # 17 bytes

    defer:
      try: removeFile(localSrc) except: discard
      try: removeDir(tmpDir)    except: discard

    # Write policy must allow creation.
    var serverCfg = newDefaultServerConfig(tmpDir)
    serverCfg.writePolicy = wpCreateOrOverwrite

    let w = newWire()
    let serverT = makeTransport(w, sideA = false)

    proc serverRespond(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      let pkt = decode(data)
      discard await handleWrq(serverCfg, pkt, serverT, host, port)
    discard serverRespond()

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))

    var req = newTransferRequest("peer", 0, "upload.txt", localSrc, tdPut)
    let id = s.startTransfer(req)

    check id != NoTransfer

    let evs = driveSession(s, id)

    check evs.len >= 3
    check evs[0].kind == evTransferStarted
    check evs[^1].kind == evTransferComplete
    for ev in evs:
      check ev.xfrId == id
      check ev.srvId == NoServer

    var hasProgress = false
    for ev in evs:
      if ev.kind == evTransferProgress: hasProgress = true
    check hasProgress

    # The server should have written the file
    let receivedFile = tmpDir / "upload.txt"
    check fileExists(receivedFile)
    check readFile(receivedFile) == "Upload this data!"

# ---------------------------------------------------------------------------
# Test 4: pre-launch failure → event, not raise
# ---------------------------------------------------------------------------
suite "TftpSession — pre-launch failure":
  test "PUT with nonexistent localPath returns valid id and evTransferError, never raises":
    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(newWire(), sideA = true))

    let missingPath = getTempDir() / "chapulin_no_such_file_xyz_12345.bin"
    var req = newTransferRequest("peer", 0, "upload.txt", missingPath, tdPut)

    # Must not raise
    var id: TransferId
    try:
      id = s.startTransfer(req)
    except:
      fail()

    check id != NoTransfer

    # Pumping poll must yield exactly one evTransferError for this id.
    var kinds: seq[EventKind]
    for ev in s.poll(0):
      if ev.xfrId == id:
        kinds.add ev.kind

    check kinds == @[evTransferError]

# ---------------------------------------------------------------------------
# Tests 5–7: cancel — Tests A, B, C
# ---------------------------------------------------------------------------
suite "TftpSession — cancel":

  test "cancel after partial GET yields exactly one evTransferError (Test A)":
    let tmpDir = getTempDir() / "chapulin_t_cancel_a"
    createDir(tmpDir)
    let serverFile = tmpDir / "big.bin"
    writeFile(serverFile, "A".repeat(4096))  # 8 full blocks at 512 blocksize
    let localOut = getTempDir() / "chapulin_t_cancel_a_out.bin"
    defer:
      try: removeFile(localOut) except: discard
      try: removeDir(tmpDir) except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()
    let serverT = makeTransport(w, sideA = false)
    proc serverRespondA(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), serverT, host, port)
    discard serverRespondA()

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))

    var req = newTransferRequest("peer", 0, "big.bin", localOut, tdGet)
    let id = s.startTransfer(req)

    # Pump until the first progress event without reaching a terminal.
    var partialEvs: seq[Event]
    var gotProgress = false
    var gotTerminal = false
    var steps = 0
    while steps < 200_000 and not gotProgress and not gotTerminal:
      for ev in s.poll(0):
        partialEvs.add ev
        if ev.xfrId == id:
          case ev.kind
          of evTransferProgress:  gotProgress = true
          of evTransferComplete, evTransferError: gotTerminal = true
          else: discard
      inc steps

    require gotProgress
    require not gotTerminal  # file large enough that completion hasn't happened yet

    s.cancel(id)

    let rest = driveSession(s, id)
    let allEvs = partialEvs & rest

    var terminals: seq[EventKind]
    for ev in allEvs:
      if ev.xfrId == id and ev.kind in {evTransferComplete, evTransferError}:
        terminals.add ev.kind

    check terminals.len == 1
    check terminals[0] == evTransferError

  test "cancel on already-resolved id is a no-op (Test B)":
    let tmpDir = getTempDir() / "chapulin_t_cancel_b"
    createDir(tmpDir)
    let serverFile = tmpDir / "small.txt"
    writeFile(serverFile, "Hi!")
    let localOut = getTempDir() / "chapulin_t_cancel_b_out.bin"
    defer:
      try: removeFile(localOut) except: discard
      try: removeDir(tmpDir) except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()
    let serverT = makeTransport(w, sideA = false)
    proc serverRespondB(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), serverT, host, port)
    discard serverRespondB()

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))

    var req = newTransferRequest("peer", 0, "small.txt", localOut, tdGet)
    let id = s.startTransfer(req)

    # Drive to completion: id removed from active after terminal event.
    let evs = driveSession(s, id)
    check evs[^1].kind == evTransferComplete

    # cancel on a resolved (stale) id must be a no-op — no raise.
    var raised = false
    try:
      s.cancel(id)
    except:
      raised = true
    check not raised

    # No further events after the no-op cancel.
    var extraEvs: seq[Event]
    for ev in s.poll(0): extraEvs.add ev
    check extraEvs.len == 0

  test "cancel on never-existed id is a no-op (Test C)":
    let s = newSession()
    var raised = false
    try:
      s.cancel(TransferId(9999))
    except:
      raised = true
    check not raised

    var n = 0
    for ev in s.poll(0): inc n
    check n == 0

# ---------------------------------------------------------------------------
# Test D: never-throw over a failing transport (property)
# ---------------------------------------------------------------------------
proc runNeverThrowCase(failAfter: int): tuple[raised: bool, terms: seq[EventKind]] =
  let w = newWire()
  let s = newSession(transportFactory =
    proc(host: string, port: int): Transport =
      makeFailingTransport(w, true, failAfter))
  let localOut = getTempDir() / "chapulin_never_throw_prop.bin"
  var req = newTransferRequest("peer", 0, "test.txt", localOut, tdGet)
  var id: TransferId
  var raised = false
  try:
    id = s.startTransfer(req)
  except:
    raised = true
    return (true, @[])
  var terms: seq[EventKind]
  var steps = 0
  while steps < 50_000:
    try:
      for ev in s.poll(0):
        if ev.xfrId == id and ev.kind in {evTransferComplete, evTransferError}:
          terms.add ev.kind
      if terms.len > 0: break
    except:
      raised = true
      break
    inc steps
  try: removeFile(localOut) except: discard
  (raised, terms)

suite "TftpSession — never-throw property":
  property "GET over failing transport: never raises, exactly one evTransferError":
    given failAfter in integers(0, 3)
    let r = runNeverThrowCase(failAfter)
    ensure (not r.raised) and r.terms == @[evTransferError]

# ---------------------------------------------------------------------------
# Helper: advance the shared dispatcher directly (NOT s.poll) until a future
# finishes or the step cap is hit.  Events accumulate in s.events unread.
# ---------------------------------------------------------------------------
proc advanceUntil[T](fut: Future[T], maxSteps = 200_000) =
  var steps = 0
  while steps < maxSteps and not fut.finished:
    if hasPendingOperations():
      asyncdispatch.poll(0)
    inc steps
  # Extra pumps to flush any pending addCallback continuations.
  var extra = 0
  while extra < 500 and hasPendingOperations():
    asyncdispatch.poll(0)
    inc extra

# ---------------------------------------------------------------------------
# Suite: bounded, coalescing event queue (slice 3)
# ---------------------------------------------------------------------------
suite "TftpSession — coalescing event queue":

  test "progress coalesces to one per id":
    # 4096 bytes = 8 full 512-byte blocks at default blocksize → many progress
    # callbacks before evTransferComplete is enqueued.  By advancing the
    # dispatcher directly (NOT s.poll) we let all callbacks fire without
    # draining, so without coalescing the queue would hold 8+ progress events.
    # With coalescing, exactly 1 survives carrying the latest (largest) bytes.
    let tmpDir = getTempDir() / "chapulin_t_coalesce_single"
    createDir(tmpDir)
    writeFile(tmpDir / "big.bin", "B".repeat(4096))
    let localOut = getTempDir() / "chapulin_t_coalesce_single_out.bin"
    defer:
      try: removeFile(localOut) except: discard
      try: removeDir(tmpDir)    except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()
    let serverT = makeTransport(w, sideA = false)

    proc srvResp1(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), serverT, host, port)
    let srvFut1 = srvResp1()

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))

    var req = newTransferRequest("peer", 0, "big.bin", localOut, tdGet)
    let id = s.startTransfer(req)

    # Advance without draining so progress events accumulate in s.events.
    advanceUntil(srvFut1)

    # Drain exactly once.
    var evs: seq[Event]
    for ev in s.poll(0):
      evs.add ev

    var startedCount, progressCount, completeCount: int
    var progressBytes: int64 = -1
    for ev in evs:
      check ev.xfrId == id
      case ev.kind
      of evTransferStarted:  inc startedCount
      of evTransferProgress:
        inc progressCount
        progressBytes = ev.snap.bytes   # last assignment = latest value
      of evTransferComplete: inc completeCount
      else: discard

    check startedCount  == 1
    check progressCount == 1   # coalesced: exactly one per id
    check completeCount == 1
    check progressBytes == 4096   # latest (largest) value survives

  test "terminals survive at concurrency":
    # Three simultaneous GETs in the same session. After advancing all three
    # without draining, each id must yield exactly one terminal event and at
    # most one progress event (coalesced).  Terminals must never be dropped or
    # merged with another id's event.
    let tmpDir = getTempDir() / "chapulin_t_coalesce_conc"
    createDir(tmpDir)
    writeFile(tmpDir / "multi.bin", "C".repeat(4096))
    let localOuts = [
      getTempDir() / "chapulin_t_coalesce_conc_1.bin",
      getTempDir() / "chapulin_t_coalesce_conc_2.bin",
      getTempDir() / "chapulin_t_coalesce_conc_3.bin",
    ]
    defer:
      try: removeDir(tmpDir) except: discard
      for p in localOuts:
        try: removeFile(p) except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)

    let w1 = newWire(); let w2 = newWire(); let w3 = newWire()
    let st1 = makeTransport(w1, sideA = false)
    let st2 = makeTransport(w2, sideA = false)
    let st3 = makeTransport(w3, sideA = false)

    proc srv1(): Future[void] {.async.} =
      let (data, host, port) = await st1.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), st1, host, port)
    proc srv2(): Future[void] {.async.} =
      let (data, host, port) = await st2.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), st2, host, port)
    proc srv3(): Future[void] {.async.} =
      let (data, host, port) = await st3.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), st3, host, port)

    let sf1 = srv1(); let sf2 = srv2(); let sf3 = srv3()

    # Round-robin transport factory: successive startTransfer calls get w1, w2, w3.
    var wireIdx: ref int
    new(wireIdx); wireIdx[] = 0
    let allWires = [w1, w2, w3]

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport =
        let idx = wireIdx[]
        inc wireIdx[]
        makeTransport(allWires[idx], sideA = true))

    let id1 = s.startTransfer(newTransferRequest("peer", 0, "multi.bin", localOuts[0], tdGet))
    let id2 = s.startTransfer(newTransferRequest("peer", 0, "multi.bin", localOuts[1], tdGet))
    let id3 = s.startTransfer(newTransferRequest("peer", 0, "multi.bin", localOuts[2], tdGet))

    # Advance all three concurrently on the shared dispatcher without draining.
    var steps = 0
    while steps < 200_000 and not (sf1.finished and sf2.finished and sf3.finished):
      if hasPendingOperations():
        asyncdispatch.poll(0)
      inc steps
    var extra = 0
    while extra < 500 and hasPendingOperations():
      asyncdispatch.poll(0)
      inc extra

    # Drain once.
    var evs: seq[Event]
    for ev in s.poll(0):
      evs.add ev

    # Each id: exactly one terminal, at most one progress.
    for checkId in [id1, id2, id3]:
      var termCount, progCount: int
      for ev in evs:
        if ev.xfrId == checkId:
          if ev.kind in {evTransferComplete, evTransferError}:
            inc termCount
          elif ev.kind == evTransferProgress:
            inc progCount
      check termCount == 1
      check progCount <= 1

  test "early break mid-drain re-delivers the rest":
    # Queue events by advancing without draining, then break out of the first
    # s.poll after the very first event, and confirm the second s.poll delivers
    # the remaining events in order with exactly one coalesced progress event.
    let tmpDir = getTempDir() / "chapulin_t_coalesce_rebreak"
    createDir(tmpDir)
    writeFile(tmpDir / "rebreak.bin", "D".repeat(4096))
    let localOut = getTempDir() / "chapulin_t_coalesce_rebreak_out.bin"
    defer:
      try: removeFile(localOut) except: discard
      try: removeDir(tmpDir)    except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()
    let serverT = makeTransport(w, sideA = false)

    proc srvResp3(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), serverT, host, port)
    let srvFut3 = srvResp3()

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))

    var req = newTransferRequest("peer", 0, "rebreak.bin", localOut, tdGet)
    let id = s.startTransfer(req)

    advanceUntil(srvFut3)

    # First poll: break immediately after the first event (evTransferStarted).
    var firstEv: Event
    var gotFirst = false
    for ev in s.poll(0):
      firstEv = ev
      gotFirst = true
      break

    check gotFirst
    check firstEv.kind == evTransferStarted
    check firstEv.xfrId == id

    # Second poll: remaining events must be re-delivered in full.
    var rest: seq[Event]
    for ev in s.poll(0):
      rest.add ev

    var progCount, completeCount: int
    for ev in rest:
      check ev.xfrId == id
      if ev.kind == evTransferProgress: inc progCount
      elif ev.kind == evTransferComplete: inc completeCount

    check progCount    == 1   # coalesced: exactly one
    check completeCount == 1

    # Progress must precede Complete in the remaining sequence.
    var seenProgress = false
    for ev in rest:
      if ev.kind == evTransferProgress:
        seenProgress = true
      elif ev.kind == evTransferComplete:
        check seenProgress   # complete must follow progress

# ---------------------------------------------------------------------------
# Suite: server lifecycle — startServer / stop (slice 4)
# ---------------------------------------------------------------------------
suite "TftpSession — server lifecycle":

  test "stop with no in-flight emits exactly one evServerStopped":
    let tmpDir = getTempDir() / "chapulin_t_srv_lifecycle"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except: discard)

    let q = newListenerQueue()
    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(newWire(), sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 6900

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    # Drain evServerStarted
    var startedSeen = false
    for step in 0 .. 2000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted:
          startedSeen = true
      if startedSeen: break
    check startedSeen

    # Stop with no in-flight requests
    s.stop(srvId)

    var stoppedCount = 0
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStopped:
          inc stoppedCount
      if stoppedCount > 0: break

    check stoppedCount == 1

  test "bind failure enqueues evServerStartFailed, no raise, no evServerStarted":
    let s = newSession(
      listenerFactory = proc(a: string, p: int): UdpListener =
        raise newException(OSError, "bind: address already in use")
    )

    var cfg = newDefaultServerConfig(getTempDir())
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 9

    var srvId: ServerId
    var raised = false
    try:
      srvId = s.startServer(cfg)
    except:
      raised = true

    check not raised
    check srvId != NoServer

    var kinds: seq[EventKind]
    for ev in s.poll(0):
      if ev.srvId == srvId:
        kinds.add ev.kind

    check kinds == @[evServerStartFailed]
    check kinds[0] == evServerStartFailed

# ---------------------------------------------------------------------------
# Suite: server GET over wire — full transfer event sequence (slice 4)
# ---------------------------------------------------------------------------
suite "TftpSession — server GET over wire":

  test "server GET emits srvId-tagged Started/Progress/Complete then evServerStopped":
    let tmpDir = getTempDir() / "chapulin_t_srv_get"
    createDir(tmpDir)
    writeFile(tmpDir / "serve_me.txt", "Hello server side!")   # 18 bytes, 1 block
    defer: (try: removeDir(tmpDir) except: discard)

    let w = newWire()
    let q = newListenerQueue()

    # Server data transport: sideA=false (sends to b2a, reads from a2b).
    # Client data transport will be sideA=true (reads from b2a, sends to a2b).
    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(w, sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 6901

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    # Drain evServerStarted
    var startedSeen = false
    for step in 0 .. 2000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted:
          startedSeen = true
          check ev.boundPort == cfg.listenPort
      if startedSeen: break
    check startedSeen

    # Push an RRQ into the listener queue.  The wire returns ("peer", 0) from
    # recv, so the request must carry the same host/port so sendBlocks' locked-
    # peer check matches.
    let rrqPkt = TftpPacket(opcode: opRrq, filename: "serve_me.txt",
                             mode: tmOctet, options: @[])
    q.push(encode(rrqPkt), "peer", 0)

    # Minimal GET client coroutine: receive DATA blocks, send ACKs.
    let clientT = makeTransport(w, sideA = true)
    proc clientGetResponder(): Future[void] {.async.} =
      while true:
        let (data, host, port) = await clientT.recv(65536, 5000)
        let pkt = decode(data)
        if pkt.opcode != opData: break
        let ack = TftpPacket(opcode: opAck, ackBlockNum: pkt.blockNum)
        await clientT.send(encode(ack), host, port)
        if pkt.data.len < 512: break   # last block — transfer done
    discard clientGetResponder()

    # Drive until evTransferComplete arrives for this server
    var evs: seq[Event]
    var gotComplete = false
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        evs.add ev
        if ev.srvId == srvId and ev.kind == evTransferComplete:
          gotComplete = true
      if gotComplete: break

    check gotComplete

    # Verify event sequence: Started → Progress → Complete, all with srvId + stable xfrId
    var xfrId = NoTransfer
    var gotTStart, gotTProgress, gotTComplete: bool
    for ev in evs:
      if ev.srvId != srvId: continue
      case ev.kind
      of evTransferStarted:
        gotTStart = true
        xfrId = ev.xfrId
        check xfrId != NoTransfer
      of evTransferProgress:
        if ev.xfrId == xfrId: gotTProgress = true
      of evTransferComplete:
        check ev.xfrId == xfrId
        gotTComplete = true
      else: discard

    check gotTStart
    check gotTProgress
    check gotTComplete

    # Stop and verify exactly one evServerStopped (Invariant 8)
    s.stop(srvId)
    var stoppedCount = 0
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStopped:
          inc stoppedCount
      if stoppedCount > 0: break

    check stoppedCount == 1

# ---------------------------------------------------------------------------
# Suite: slice 5 — per-transfer server cancel + concurrent stop
# ---------------------------------------------------------------------------
suite "TftpSession — server transfer cancel":

  test "cancel server transfer mid-flight yields evTransferError, server stays up":
    let tmpDir = getTempDir() / "chapulin_t_srv_cancel_single"
    createDir(tmpDir)
    writeFile(tmpDir / "bigfile.bin", "X".repeat(4096))  # 8 x 512-byte blocks
    defer: (try: removeDir(tmpDir) except: discard)

    let w = newWire()
    let q = newListenerQueue()

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(w, sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 6910

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    # Drain evServerStarted
    var startedSeen = false
    for step in 0 .. 2000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: startedSeen = true
      if startedSeen: break
    check startedSeen

    let rrq = TftpPacket(opcode: opRrq, filename: "bigfile.bin",
                          mode: tmOctet, options: @[])
    q.push(encode(rrq), "peer", 0)

    # Client responder: ACK all DATA blocks
    let clientT = makeTransport(w, sideA = true)
    proc clientRespCancel(): Future[void] {.async.} =
      while true:
        var tdata: seq[byte]; var host: string; var port: int
        try:
          (tdata, host, port) = await clientT.recv(65536, 5000)
        except TransportTimeoutError: break
        let pkt = decode(tdata)
        if pkt.opcode != opData: break
        let ack = TftpPacket(opcode: opAck, ackBlockNum: pkt.blockNum)
        await clientT.send(encode(ack), host, port)
        if pkt.data.len < 512: break
    discard clientRespCancel()

    # Drive: capture xfrId at Started; cancel on first Progress; wait for terminal.
    var xfrId = NoTransfer
    var evs: seq[Event]
    var cancelled = false
    var gotTerminal = false
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        evs.add ev
        if ev.srvId == srvId:
          case ev.kind
          of evTransferStarted:
            xfrId = ev.xfrId
          of evTransferProgress:
            if not cancelled and xfrId != NoTransfer:
              s.cancel(xfrId)
              cancelled = true
          of evTransferComplete, evTransferError:
            if ev.xfrId == xfrId: gotTerminal = true
          else: discard
      if gotTerminal: break

    require xfrId != NoTransfer
    require cancelled
    require gotTerminal

    # Exactly one terminal for xfrId; must be evTransferError
    var terminals: seq[EventKind]
    for ev in evs:
      if ev.xfrId == xfrId and ev.kind in {evTransferComplete, evTransferError}:
        terminals.add ev.kind
    check terminals.len == 1
    check terminals[0] == evTransferError

    # Server is still up — no evServerStopped yet
    var stoppedCount = 0
    for ev in evs:
      if ev.srvId == srvId and ev.kind == evServerStopped: inc stoppedCount
    check stoppedCount == 0

    # Cleanup
    s.stop(srvId)
    for step in 0 .. 200_000:
      for ev in s.poll(0): discard
      break

  test "two concurrent server transfers, cancel one, the other completes":
    let tmpDir = getTempDir() / "chapulin_t_srv_cancel_conc"
    createDir(tmpDir)
    writeFile(tmpDir / "bigfile.bin", "Y".repeat(4096))
    defer: (try: removeDir(tmpDir) except: discard)

    let w1 = newWire()
    let w2 = newWire()
    let q = newListenerQueue()

    # Transport factory cycles w1 then w2 on successive calls.
    var tfIdx: ref int
    new(tfIdx); tfIdx[] = 0
    let wires = [w1, w2]

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        let idx = tfIdx[]
        inc tfIdx[]
        makeTransport(wires[idx mod 2], sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 6911

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    # Drain evServerStarted
    for step in 0 .. 2000:
      var saw = false
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: saw = true
      if saw: break

    let rrq = TftpPacket(opcode: opRrq, filename: "bigfile.bin",
                          mode: tmOctet, options: @[])
    # Both requests look identical from the wire perspective (locked peer "peer":0).
    # They are distinguished by their per-handleRequest epochTime() startedAt.
    q.push(encode(rrq), "peer", 0)
    q.push(encode(rrq), "peer", 0)

    # Two independent client responders — one per wire.
    let ct1 = makeTransport(w1, sideA = true)
    let ct2 = makeTransport(w2, sideA = true)

    proc mkConcResp(t: Transport): Future[void] {.async.} =
      while true:
        var tdata: seq[byte]; var host: string; var port: int
        try:
          (tdata, host, port) = await t.recv(65536, 5000)
        except TransportTimeoutError: break
        let pkt = decode(tdata)
        if pkt.opcode != opData: break
        let ack = TftpPacket(opcode: opAck, ackBlockNum: pkt.blockNum)
        await t.send(encode(ack), host, port)
        if pkt.data.len < 512: break

    discard mkConcResp(ct1)
    discard mkConcResp(ct2)

    var xfrId1 = NoTransfer
    var xfrId2 = NoTransfer
    var cancelledId = NoTransfer
    var evs: seq[Event]

    for step in 0 .. 200_000:
      for ev in s.poll(0):
        evs.add ev
        if ev.srvId == srvId:
          case ev.kind
          of evTransferStarted:
            if xfrId1 == NoTransfer: xfrId1 = ev.xfrId
            elif xfrId2 == NoTransfer and ev.xfrId != xfrId1: xfrId2 = ev.xfrId
          of evTransferProgress:
            # Cancel the first transfer we see progress for
            if cancelledId == NoTransfer and xfrId1 != NoTransfer:
              s.cancel(xfrId1)
              cancelledId = xfrId1
          else: discard
      # Stop when both have terminals
      var t1 = false; var t2 = false
      for ev in evs:
        if xfrId1 != NoTransfer and ev.xfrId == xfrId1 and
           ev.kind in {evTransferComplete, evTransferError}: t1 = true
        if xfrId2 != NoTransfer and ev.xfrId == xfrId2 and
           ev.kind in {evTransferComplete, evTransferError}: t2 = true
      if t1 and t2: break

    require xfrId1 != NoTransfer
    require xfrId2 != NoTransfer
    require cancelledId == xfrId1

    var term1, term2: EventKind
    for ev in evs:
      if ev.xfrId == xfrId1 and ev.kind in {evTransferComplete, evTransferError}:
        term1 = ev.kind
      if ev.xfrId == xfrId2 and ev.kind in {evTransferComplete, evTransferError}:
        term2 = ev.kind
    check term1 == evTransferError
    check term2 == evTransferComplete

    # Both tagged with srvId
    for ev in evs:
      if ev.xfrId == xfrId1 or ev.xfrId == xfrId2:
        check ev.srvId == srvId

    # Cleanup
    s.stop(srvId)
    for step in 0 .. 200_000:
      for ev in s.poll(0): discard
      break

  test "stop with in-flight server transfer: transfer completes, exactly one evServerStopped":
    let tmpDir = getTempDir() / "chapulin_t_srv_stop_inflight"
    createDir(tmpDir)
    writeFile(tmpDir / "stopfile.bin", "Z".repeat(4096))
    defer: (try: removeDir(tmpDir) except: discard)

    let w = newWire()
    let q = newListenerQueue()

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(w, sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 6912

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    for step in 0 .. 2000:
      var saw = false
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: saw = true
      if saw: break

    let rrq = TftpPacket(opcode: opRrq, filename: "stopfile.bin",
                          mode: tmOctet, options: @[])
    q.push(encode(rrq), "peer", 0)

    let clientT2 = makeTransport(w, sideA = true)
    proc clientRespStop(): Future[void] {.async.} =
      while true:
        var tdata: seq[byte]; var host: string; var port: int
        try:
          (tdata, host, port) = await clientT2.recv(65536, 5000)
        except TransportTimeoutError: break
        let pkt = decode(tdata)
        if pkt.opcode != opData: break
        let ack = TftpPacket(opcode: opAck, ackBlockNum: pkt.blockNum)
        await clientT2.send(encode(ack), host, port)
        if pkt.data.len < 512: break
    discard clientRespStop()

    # Drive until transfer starts, then call stop immediately.
    # The in-flight transfer must still complete (Invariant 7: stop ≠ force-cancel).
    var xfrId = NoTransfer
    var evs: seq[Event]
    var stopCalled = false

    for step in 0 .. 200_000:
      for ev in s.poll(0):
        evs.add ev
        if ev.srvId == srvId and ev.kind == evTransferStarted:
          xfrId = ev.xfrId
      if not stopCalled and xfrId != NoTransfer:
        s.stop(srvId)
        stopCalled = true
      var gotStopped = false
      for ev in evs:
        if ev.srvId == srvId and ev.kind == evServerStopped: gotStopped = true
      if gotStopped: break

    require xfrId != NoTransfer
    require stopCalled

    # Transfer must have completed (stop does NOT force-cancel — Invariant 7)
    var termKind: EventKind
    var termCount = 0
    for ev in evs:
      if ev.xfrId == xfrId and ev.kind in {evTransferComplete, evTransferError}:
        termKind = ev.kind
        inc termCount
    check termCount == 1
    check termKind == evTransferComplete

    # Exactly one evServerStopped (Invariant 8)
    var stoppedCount = 0
    for ev in evs:
      if ev.srvId == srvId and ev.kind == evServerStopped: inc stoppedCount
    check stoppedCount == 1

  test "cancel on already-terminated server transfer is a no-op (Invariant 4)":
    let tmpDir = getTempDir() / "chapulin_t_srv_cancel_noop"
    createDir(tmpDir)
    writeFile(tmpDir / "small.txt", "hello!")
    defer: (try: removeDir(tmpDir) except: discard)

    let w = newWire()
    let q = newListenerQueue()

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(w, sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 6913

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    for step in 0 .. 2000:
      var saw = false
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: saw = true
      if saw: break

    let rrq = TftpPacket(opcode: opRrq, filename: "small.txt",
                          mode: tmOctet, options: @[])
    q.push(encode(rrq), "peer", 0)

    let clientT3 = makeTransport(w, sideA = true)
    proc clientRespNoop(): Future[void] {.async.} =
      while true:
        var tdata: seq[byte]; var host: string; var port: int
        try:
          (tdata, host, port) = await clientT3.recv(65536, 5000)
        except TransportTimeoutError: break
        let pkt = decode(tdata)
        if pkt.opcode != opData: break
        let ack = TftpPacket(opcode: opAck, ackBlockNum: pkt.blockNum)
        await clientT3.send(encode(ack), host, port)
        if pkt.data.len < 512: break
    discard clientRespNoop()

    # Drive to completion
    var xfrId = NoTransfer
    var evs: seq[Event]
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        evs.add ev
        if ev.srvId == srvId and ev.kind == evTransferStarted: xfrId = ev.xfrId
      var done = false
      for ev in evs:
        if xfrId != NoTransfer and ev.xfrId == xfrId and ev.kind == evTransferComplete:
          done = true
      if done: break

    require xfrId != NoTransfer

    var termCount = 0
    for ev in evs:
      if ev.xfrId == xfrId and ev.kind in {evTransferComplete, evTransferError}:
        inc termCount
    check termCount == 1

    # cancel after terminal — must be a no-op, no raise, no new events
    var raised = false
    try: s.cancel(xfrId)
    except: raised = true
    check not raised

    var extra: seq[Event]
    for ev in s.poll(0): extra.add ev
    check extra.len == 0

    # Cleanup
    s.stop(srvId)
    for step in 0 .. 200_000:
      for ev in s.poll(0): discard
      break

# ---------------------------------------------------------------------------
# Suite: server never re-raises through poll — failing data transport (slice 4)
# ---------------------------------------------------------------------------
suite "TftpSession — server never-raise property":

  test "handleRequest exception does not propagate through poll; server is stoppable":
    let tmpDir = getTempDir() / "chapulin_t_srv_neverraise"
    createDir(tmpDir)
    writeFile(tmpDir / "fail_test.txt", "Test data for fail scenario")
    defer: (try: removeDir(tmpDir) except: discard)

    let w = newWire()
    let q = newListenerQueue()

    # Inject a failing data transport: first send raises OSError, so
    # sendBlocks in handleRrq raises, propagating through handleRequest.
    # The addCallback in run() swallows it — poll must never raise.
    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeFailingTransport(w, sideA = false, failAfter = 0),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 6902

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    # Wait for evServerStarted
    for step in 0 .. 2000:
      var sawStart = false
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: sawStart = true
      if sawStart: break

    # Push a valid RRQ — handleRequest will fail when sendBlocks raises
    let rrqPkt = TftpPacket(opcode: opRrq, filename: "fail_test.txt",
                             mode: tmOctet, options: @[])
    q.push(encode(rrqPkt), "peer", 0)

    # Pump many steps; poll must never raise regardless of the handler error
    var raised = false
    try:
      for step in 0 .. 5000:
        for ev in s.poll(0): discard
    except:
      raised = true

    check not raised

    # Stop and confirm the server drains cleanly → exactly one evServerStopped
    s.stop(srvId)
    var stoppedCount = 0
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStopped:
          inc stoppedCount
      if stoppedCount > 0: break

    check stoppedCount == 1

# ---------------------------------------------------------------------------
# Slice 6A: fraction helper reachable through api
# ---------------------------------------------------------------------------
suite "fraction helper (slice 6A)":
  test "fraction(bytes, some(total)) returns some(bytes/total)":
    check fraction(50'i64, some(100'i64)) == some(0.5)

  test "fraction(bytes, none) returns none":
    check fraction(5'i64, none(int64)).isNone

  test "fraction(bytes, some(0)) returns some(0.0) — no div-by-zero":
    check fraction(5'i64, some(0'i64)) == some(0.0)

  test "fraction(0, some(total)) returns some(0.0)":
    check fraction(0'i64, some(200'i64)) == some(0.0)

# ---------------------------------------------------------------------------
# Slice 6B: PUT evTransferStarted carries known total
# ---------------------------------------------------------------------------
suite "TftpSession — PUT evTransferStarted.total (slice 6B)":
  test "PUT evTransferStarted snapshot has total == some(fileSize)":
    let tmpDir = getTempDir() / "chapulin_t_put_total_6b"
    createDir(tmpDir)
    let localSrc = tmpDir / "src6b.bin"
    let payload = "Hello6B".repeat(10)  # 70 bytes
    writeFile(localSrc, payload)
    let fileSize = int64(payload.len)

    defer:
      try: removeDir(tmpDir) except: discard

    var serverCfg = newDefaultServerConfig(tmpDir)
    serverCfg.writePolicy = wpCreateOrOverwrite

    let w = newWire()
    let serverT = makeTransport(w, sideA = false)

    proc serverRespond6B(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(65536, 5000)
      let pkt = decode(data)
      discard await handleWrq(serverCfg, pkt, serverT, host, port)
    discard serverRespond6B()

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))

    var req = newTransferRequest("peer", 0, "upload6b.txt", localSrc, tdPut)
    let id = s.startTransfer(req)
    check id != NoTransfer

    let evs = driveSession(s, id)

    # First event must be evTransferStarted with total == some(fileSize)
    require evs.len >= 1
    check evs[0].kind == evTransferStarted
    check evs[0].snap.total.isSome
    check evs[0].snap.total.get == fileSize

# ---------------------------------------------------------------------------
# Slice 7a: waitTransfer / waitServer / close-mid-transfer
# ---------------------------------------------------------------------------

suite "TftpSession — waitTransfer (slice 7a)":

  test "waitTransfer returns success result for completed GET":
    let tmpDir = getTempDir() / "chapulin_t_wt_get"
    createDir(tmpDir)
    let payload = "WaitTransfer test data, 23 bytes"
    writeFile(tmpDir / "wt.txt", payload)
    let localOut = getTempDir() / "chapulin_t_wt_get_out.bin"
    defer:
      try: removeDir(tmpDir) except: discard
      try: removeFile(localOut) except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()
    let serverT = makeTransport(w, sideA = false)

    proc wtSrv(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), serverT, host, port)
    discard wtSrv()

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))

    let req = newTransferRequest("peer", 0, "wt.txt", localOut, tdGet)
    let id = s.startTransfer(req)

    var res: TransferResult
    var raised = false
    try:
      res = s.waitTransfer(id)
    except:
      raised = true

    check not raised
    check res.success
    check res.bytesTransferred == int64(payload.len)

  test "waitTransfer buffers non-target events so server events are not swallowed":
    # Run a server AND a client transfer concurrently.  waitTransfer(clientId)
    # must complete and not discard the server's evServerStarted event — it
    # should be retrievable by a subsequent poll().
    let tmpDir = getTempDir() / "chapulin_t_wt_buf"
    createDir(tmpDir)
    writeFile(tmpDir / "buf.txt", "Buffering test data!")
    let localOut = getTempDir() / "chapulin_t_wt_buf_out.bin"
    defer:
      try: removeDir(tmpDir) except: discard
      try: removeFile(localOut) except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()
    let serverT = makeTransport(w, sideA = false)
    let q = newListenerQueue()

    proc wtBufSrv(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), serverT, host, port)
    discard wtBufSrv()

    let s = newSession(
      transportFactory = proc(host: string, port: int): Transport =
        makeTransport(w, sideA = true),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    # Start a TFTP server — will enqueue evServerStarted
    var srvCfg = newDefaultServerConfig(tmpDir)
    srvCfg.listenAddr = "127.0.0.1"
    srvCfg.listenPort = 6921
    let srvId = s.startServer(srvCfg)

    # Start client GET
    let cId = s.startTransfer(newTransferRequest("peer", 0, "buf.txt", localOut, tdGet))

    # waitTransfer must complete without discarding the evServerStarted event
    let res = s.waitTransfer(cId)
    check res.success

    # After waitTransfer returns, drain and verify evServerStarted is still available
    var serverStartedSeen = false
    for step in 0 .. 2000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted:
          serverStartedSeen = true
      if serverStartedSeen: break
    check serverStartedSeen

    # Cleanup
    s.stop(srvId)
    for step in 0 .. 200_000:
      var done = false
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStopped: done = true
      if done: break

  test "waitTransfer returns a failure result without hanging on evServerStartFailed id":
    # Pass a TransferId that never gets a terminal because we started a server
    # (wrong id type scenario): waitTransfer should exit via the
    # hasPendingOperations guard and return a failure TransferResult.
    let s = newSession(
      listenerFactory = proc(a: string, p: int): UdpListener =
        raise newException(OSError, "bind failed")
    )
    var cfg = newDefaultServerConfig(getTempDir())
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 9
    discard s.startServer(cfg)

    # Use a TransferId that will never have a terminal (it was never startTransfer'd)
    let ghostId = TransferId(9999)
    var res: TransferResult
    var raised = false
    try:
      res = s.waitTransfer(ghostId)
    except:
      raised = true
    check not raised
    check not res.success   # must return gracefully, not hang

suite "TftpSession — waitServer (slice 7a)":

  test "waitServer exits on evServerStartFailed without hanging":
    let s = newSession(
      listenerFactory = proc(a: string, p: int): UdpListener =
        raise newException(OSError, "bind: address already in use")
    )
    var cfg = newDefaultServerConfig(getTempDir())
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 9

    let srvId = s.startServer(cfg)
    var raised = false
    try:
      s.waitServer(srvId)
    except:
      raised = true
    check not raised
    # No further events for this server
    var extra: seq[Event]
    for ev in s.poll(0):
      if ev.srvId == srvId: extra.add ev
    check extra.len == 0

  test "waitServer exits on evServerStopped after stop()":
    let tmpDir = getTempDir() / "chapulin_t_ws_stop"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except: discard)

    let q = newListenerQueue()
    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(newWire(), sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 6922

    let srvId = s.startServer(cfg)

    # Drain evServerStarted first, then stop, then waitServer
    for step in 0 .. 2000:
      var saw = false
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: saw = true
      if saw: break

    s.stop(srvId)

    var raised = false
    try:
      s.waitServer(srvId)
    except:
      raised = true
    check not raised

    # After waitServer, no further server events
    var extra: seq[Event]
    for ev in s.poll(0):
      if ev.srvId == srvId: extra.add ev
    check extra.len == 0

suite "TftpSession — close mid-transfer (slice 7a)":

  test "close() mid-transfer emits one terminal per active client id then quiesces":
    let tmpDir = getTempDir() / "chapulin_t_close_mid"
    createDir(tmpDir)
    writeFile(tmpDir / "big1.bin", "A".repeat(8192))
    writeFile(tmpDir / "big2.bin", "B".repeat(8192))
    let out1 = getTempDir() / "chapulin_t_close_mid_out1.bin"
    let out2 = getTempDir() / "chapulin_t_close_mid_out2.bin"
    defer:
      try: removeDir(tmpDir) except: discard
      try: removeFile(out1) except: discard
      try: removeFile(out2) except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w1 = newWire(); let w2 = newWire()
    let st1 = makeTransport(w1, sideA = false)
    let st2 = makeTransport(w2, sideA = false)

    proc srvClose1(): Future[void] {.async.} =
      let (data, host, port) = await st1.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), st1, host, port)
    proc srvClose2(): Future[void] {.async.} =
      let (data, host, port) = await st2.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), st2, host, port)
    discard srvClose1()
    discard srvClose2()

    var wIdx: ref int
    new(wIdx); wIdx[] = 0
    let wires = [w1, w2]
    let s = newSession(transportFactory =
      proc(h: string, p: int): Transport =
        let i = wIdx[]
        inc wIdx[]
        makeTransport(wires[i mod 2], sideA = true))

    let id1 = s.startTransfer(newTransferRequest("peer", 0, "big1.bin", out1, tdGet))
    let id2 = s.startTransfer(newTransferRequest("peer", 0, "big2.bin", out2, tdGet))

    # Pump until both have evTransferStarted; abort if we see a terminal first.
    var got1Started = false; var got2Started = false
    var got1Terminal = false; var got2Terminal = false
    var allBefore: seq[Event]
    var steps = 0
    while steps < 200_000 and not (got1Started and got2Started):
      for ev in s.poll(0):
        allBefore.add ev
        if ev.xfrId == id1:
          if ev.kind == evTransferStarted: got1Started = true
          elif ev.kind in {evTransferComplete, evTransferError}: got1Terminal = true
        elif ev.xfrId == id2:
          if ev.kind == evTransferStarted: got2Started = true
          elif ev.kind in {evTransferComplete, evTransferError}: got2Terminal = true
      inc steps

    require got1Started and got2Started
    # If a terminal already arrived we can't test close-mid-transfer.
    require not (got1Terminal or got2Terminal)

    s.close()

    # Pump until both terminals arrive.
    var allAfter: seq[Event]
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        allAfter.add ev
        if ev.xfrId == id1 and ev.kind in {evTransferComplete, evTransferError}: got1Terminal = true
        if ev.xfrId == id2 and ev.kind in {evTransferComplete, evTransferError}: got2Terminal = true
      if got1Terminal and got2Terminal: break

    check got1Terminal and got2Terminal

    let allEvs = allBefore & allAfter

    # Exactly one terminal per id (Invariant 4)
    for checkId in [id1, id2]:
      var termCount = 0
      for ev in allEvs:
        if ev.xfrId == checkId and ev.kind in {evTransferComplete, evTransferError}:
          inc termCount
      check termCount == 1

    # After terminals, one final poll should yield nothing for these ids
    for ev in s.poll(0):
      check ev.xfrId notin [id1, id2]

# ---------------------------------------------------------------------------
# Bug 1 regression: non-request opcodes (DATA/ACK/ERROR/OACK) must not
# crash handleRequest via FieldDefect on pkt.filename access.
# ---------------------------------------------------------------------------
suite "TftpSession — Bug 1: non-request opcodes do not crash":
  test "DATA/ACK/ERROR/OACK packets do not raise; subsequent RRQ still completes; one evServerStopped":
    let tmpDir = getTempDir() / "chapulin_t_bug1"
    createDir(tmpDir)
    writeFile(tmpDir / "ok.txt", "OK!")
    defer: (try: removeDir(tmpDir) except: discard)

    let w = newWire()
    let q = newListenerQueue()

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(w, sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 7001

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    # Drain evServerStarted
    var startedSeen = false
    for step in 0 .. 2000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: startedSeen = true
      if startedSeen: break
    check startedSeen

    # Push non-request packets: DATA, ACK, ERROR, OACK
    let dataPkt  = TftpPacket(opcode: opData, blockNum: 1,
                               data: @[byte('h'), byte('i')])
    let ackPkt   = TftpPacket(opcode: opAck, ackBlockNum: 0)
    let errPkt   = TftpPacket(opcode: opError, errorCode: errNotDefined, errorMsg: "test")
    let oackPkt  = TftpPacket(opcode: opOack, oackOptions: @[])
    q.push(encode(dataPkt),  "127.0.0.1", 12345)
    q.push(encode(ackPkt),   "127.0.0.1", 12346)
    q.push(encode(errPkt),   "127.0.0.1", 12347)
    q.push(encode(oackPkt),  "127.0.0.1", 12348)
    # Garbage bytes that will be rejected by decode() (not a valid opcode crash path)
    q.push(@[byte(0xFF), byte(0xFE)], "127.0.0.1", 12349)

    # (a) poll must never raise
    var raised = false
    try:
      for step in 0 .. 5000:
        for ev in s.poll(0): discard
    except:
      raised = true
    check not raised

    # (b) a valid RRQ pushed afterward must still complete (evTransferComplete)
    let rrqPkt = TftpPacket(opcode: opRrq, filename: "ok.txt",
                             mode: tmOctet, options: @[])
    q.push(encode(rrqPkt), "peer", 0)

    let clientT = makeTransport(w, sideA = true)
    proc clientGetBug1(): Future[void] {.async.} =
      while true:
        var tdata: seq[byte]; var host: string; var port: int
        try:
          (tdata, host, port) = await clientT.recv(65536, 5000)
        except TransportTimeoutError: break
        let pkt = decode(tdata)
        if pkt.opcode != opData: break
        let ack = TftpPacket(opcode: opAck, ackBlockNum: pkt.blockNum)
        await clientT.send(encode(ack), host, port)
        if pkt.data.len < 512: break
    discard clientGetBug1()

    var gotComplete = false
    try:
      for step in 0 .. 200_000:
        for ev in s.poll(0):
          if ev.srvId == srvId and ev.kind == evTransferComplete:
            gotComplete = true
        if gotComplete: break
    except:
      discard
    check gotComplete

    # (c) stop emits exactly one evServerStopped
    s.stop(srvId)
    var stoppedCount = 0
    try:
      for step in 0 .. 200_000:
        for ev in s.poll(0):
          if ev.srvId == srvId and ev.kind == evServerStopped:
            inc stoppedCount
        if stoppedCount > 0: break
    except:
      discard
    check stoppedCount == 1

# ---------------------------------------------------------------------------
# Bug 2 regression: OSError from listener.recv must not wedge the session.
# evServerStopped must be emitted even when run() exits unexpectedly.
# ---------------------------------------------------------------------------
suite "TftpSession — Bug 2: run() crash emits evServerStopped":
  test "OSError from listener.recv: poll does not raise; exactly one evServerStopped":
    let tmpDir = getTempDir() / "chapulin_t_bug2"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except: discard)

    let s = newSession(
      listenerFactory = proc(a: string, p: int): UdpListener =
        makeFailingListener()
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 7002

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    # Collect ALL server events in one combined loop — do NOT separate a
    # "drain evServerStarted" phase because run() may complete synchronously,
    # causing evServerStopped to appear in the very first poll() call.
    var raised = false
    var startedSeen = false
    var stoppedCount = 0
    try:
      for step in 0 .. 200_000:
        for ev in s.poll(0):
          if ev.srvId == srvId:
            case ev.kind
            of evServerStarted:  startedSeen = true
            of evServerStopped:  inc stoppedCount
            else: discard
        if startedSeen and stoppedCount > 0: break
    except:
      raised = true

    check not raised
    check startedSeen
    check stoppedCount == 1

# ---------------------------------------------------------------------------
# BUG 3 regression: server-side TransferSnapshot must carry negotiated
# blocksize/windowsize, not hardcoded defaults.
# ---------------------------------------------------------------------------
suite "TftpSession — BUG 3 regression: negotiated blocksize/windowsize in snap":

  test "server GET with blksize=1024,windowsize=2 options reports correct snap values":
    let tmpDir = getTempDir() / "chapulin_t_bug3"
    createDir(tmpDir)
    # 2000 bytes: 1 full block (1024) + 1 short block (976) at blksize 1024
    writeFile(tmpDir / "bug3.bin", "Z".repeat(2000))
    defer: (try: removeDir(tmpDir) except: discard)

    let w = newWire()
    let q = newListenerQueue()

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(w, sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 7010

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    var startedSeen2 = false
    for step in 0 .. 2000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: startedSeen2 = true
      if startedSeen2: break
    check startedSeen2

    # RRQ requesting blksize=1024 and windowsize=2
    let rrqPkt = TftpPacket(opcode: opRrq, filename: "bug3.bin",
                             mode: tmOctet,
                             options: @[("blksize", "1024"), ("windowsize", "2")])
    q.push(encode(rrqPkt), "peer", 0)

    # Client responder: handle OACK then ACK each DATA block
    let clientT = makeTransport(w, sideA = true)
    proc clientGetBug3(): Future[void] {.async.} =
      while true:
        var tdata: seq[byte]; var host: string; var port: int
        try:
          (tdata, host, port) = await clientT.recv(65536, 5000)
        except TransportTimeoutError: break
        let pkt = decode(tdata)
        case pkt.opcode
        of opOack:
          let ack = TftpPacket(opcode: opAck, ackBlockNum: 0)
          await clientT.send(encode(ack), host, port)
        of opData:
          let ack = TftpPacket(opcode: opAck, ackBlockNum: pkt.blockNum)
          await clientT.send(encode(ack), host, port)
          if pkt.data.len < 1024: break   # last block
        else: break
    discard clientGetBug3()

    # Drive until we see the server-side evTransferStarted
    var startSnap: TransferSnapshot
    var gotStarted = false
    var gotComplete = false
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        if ev.srvId == srvId:
          case ev.kind
          of evTransferStarted:
            startSnap = ev.snap
            gotStarted = true
          of evTransferComplete:
            gotComplete = true
          else: discard
      if gotComplete: break

    check gotStarted
    check gotComplete
    # BUG 3 regression: must report negotiated values, not hardcoded 512/1
    check startSnap.blocksize == 1024
    check startSnap.windowsize == 2

    s.stop(srvId)
    for step in 0 .. 200_000:
      for ev in s.poll(0): discard
      break

# ---------------------------------------------------------------------------
# BUG 4 regression: reqId-keyed concurrent transfers from the same peer:0
# both receive distinct, correct terminal events (no XferKey collision).
# ---------------------------------------------------------------------------
suite "TftpSession — BUG 4 regression: reqId-keyed concurrent server transfers":

  test "two concurrent same-peer GETs each receive exactly one evTransferComplete":
    # Both requests arrive from "peer":0 (wireharness always reports this).
    # The old epochTime key could collide; the new reqId key is always unique.
    let tmpDir = getTempDir() / "chapulin_t_bug4"
    createDir(tmpDir)
    writeFile(tmpDir / "f4.bin", "A".repeat(512))  # exactly 1 default block
    defer: (try: removeDir(tmpDir) except: discard)

    let w1 = newWire()
    let w2 = newWire()
    let q  = newListenerQueue()

    var tfIdx4: ref int
    new(tfIdx4); tfIdx4[] = 0
    let wires4 = [w1, w2]

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        let idx = tfIdx4[]
        inc tfIdx4[]
        makeTransport(wires4[idx mod 2], sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg4 = newDefaultServerConfig(tmpDir)
    cfg4.listenAddr = "127.0.0.1"
    cfg4.listenPort = 7020

    let srvId4 = s.startServer(cfg4)
    check srvId4 != NoServer

    for step in 0 .. 2000:
      var saw = false
      for ev in s.poll(0):
        if ev.srvId == srvId4 and ev.kind == evServerStarted: saw = true
      if saw: break

    # Push two RRQs from the same peer:0 — both share the same clientHost/clientPort.
    # With the old XferKey=(host,port,epochTime) they may collide on fast machines.
    let rrq4 = TftpPacket(opcode: opRrq, filename: "f4.bin",
                           mode: tmOctet, options: @[])
    q.push(encode(rrq4), "peer", 0)
    q.push(encode(rrq4), "peer", 0)

    let ct1 = makeTransport(w1, sideA = true)
    let ct2 = makeTransport(w2, sideA = true)

    proc mkResp4(t: Transport): Future[void] {.async.} =
      while true:
        var tdata: seq[byte]; var host: string; var port: int
        try:
          (tdata, host, port) = await t.recv(65536, 5000)
        except TransportTimeoutError: break
        let pkt = decode(tdata)
        if pkt.opcode != opData: break
        let ack = TftpPacket(opcode: opAck, ackBlockNum: pkt.blockNum)
        await t.send(encode(ack), host, port)
        if pkt.data.len < 512: break

    discard mkResp4(ct1)
    discard mkResp4(ct2)

    var xfrIds4: seq[TransferId]
    var evs4: seq[Event]

    for step in 0 .. 200_000:
      for ev in s.poll(0):
        evs4.add ev
        if ev.srvId == srvId4 and ev.kind == evTransferStarted:
          xfrIds4.add ev.xfrId
      var terms = 0
      for ev in evs4:
        if ev.srvId == srvId4 and ev.kind in {evTransferComplete, evTransferError}:
          inc terms
      if terms >= 2: break

    # Both started with distinct IDs (BUG 4 fix: unique reqIds)
    require xfrIds4.len == 2
    check xfrIds4[0] != xfrIds4[1]

    # Each must have exactly one evTransferComplete
    for xid in xfrIds4:
      var termCount = 0
      var termKind: EventKind
      for ev in evs4:
        if ev.xfrId == xid and ev.kind in {evTransferComplete, evTransferError}:
          inc termCount
          termKind = ev.kind
      check termCount == 1
      check termKind == evTransferComplete

    # Cleanup: stop server; exactly one evServerStopped
    s.stop(srvId4)
    var stopped4 = 0
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        if ev.srvId == srvId4 and ev.kind == evServerStopped: inc stopped4
      if stopped4 > 0: break
    check stopped4 == 1

# ---------------------------------------------------------------------------
# FIX 5: snap is the common accessor for all evTransfer* events
# ---------------------------------------------------------------------------
suite "TftpSession — FIX 5: snap field on transfer events":

  test "evTransferComplete exposes snap; evTransferError exposes snap+errorMsg":
    # Complete event: use a successful small GET.
    let tmpDir = getTempDir() / "chapulin_t_fix5"
    createDir(tmpDir)
    writeFile(tmpDir / "fix5.txt", "FixFive!")
    let localOut = getTempDir() / "chapulin_t_fix5_out.bin"
    defer:
      try: removeDir(tmpDir) except: discard
      try: removeFile(localOut) except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()
    let serverT = makeTransport(w, sideA = false)
    proc fix5Srv(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), serverT, host, port)
    discard fix5Srv()

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))

    let goodId = s.startTransfer(newTransferRequest("peer", 0, "fix5.txt", localOut, tdGet))
    let evs = driveSession(s, goodId)

    var completeEv: Event
    var gotComplete = false
    for ev in evs:
      if ev.xfrId == goodId and ev.kind == evTransferComplete:
        completeEv = ev
        gotComplete = true
    require gotComplete
    # evTransferComplete must expose snap (the common accessor)
    check completeEv.snap.bytes > 0

    # Error event: PUT with nonexistent file.
    let badId = s.startTransfer(
      newTransferRequest("peer", 0, "no_file.txt",
                         getTempDir() / "chapulin_fix5_no_such_file.bin", tdPut))
    var errEvs: seq[Event]
    for ev in s.poll(0):
      if ev.xfrId == badId: errEvs.add ev
    require errEvs.len == 1
    check errEvs[0].kind == evTransferError
    # evTransferError must expose snap and errorMsg (snap is the common accessor)
    check errEvs[0].errorMsg.len > 0

# ---------------------------------------------------------------------------
# FIX 6: server table cleanup after evServerStopped
# ---------------------------------------------------------------------------
suite "TftpSession — FIX 6: server table cleanup":

  test "server removed from session table after evServerStopped; second stop is no-op":
    let q = newListenerQueue()
    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(newWire(), sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(getTempDir())
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 7100

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    # Drain evServerStarted
    for step in 0 .. 2000:
      var saw = false
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: saw = true
      if saw: break

    # Stop and wait for evServerStopped
    s.stop(srvId)
    var stoppedCount = 0
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStopped: inc stoppedCount
      if stoppedCount > 0: break
    check stoppedCount == 1

    # FIX 6a: after evServerStopped the server entry must be removed.
    check s.sessionServerCount() == 0

    # Second stop on the same (now-gone) id must be a clean no-op.
    var raised = false
    try: s.stop(srvId)
    except: raised = true
    check not raised

    # No further server events after removal.
    var extra: seq[Event]
    for ev in s.poll(0):
      if ev.srvId == srvId: extra.add ev
    check extra.len == 0

  test "repeated start+stop cycles do not accumulate server entries":
    # Five start/stop rounds in the SAME session; table must be 0 after each.
    let q = newListenerQueue()
    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(newWire(), sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    for i in 0 .. 4:
      var cfg = newDefaultServerConfig(getTempDir())
      cfg.listenAddr = "127.0.0.1"
      cfg.listenPort = 7110 + i

      let sid = s.startServer(cfg)
      check sid != NoServer

      for step in 0 .. 2000:
        var saw = false
        for ev in s.poll(0):
          if ev.srvId == sid and ev.kind == evServerStarted: saw = true
        if saw: break

      s.stop(sid)
      for step in 0 .. 200_000:
        var done = false
        for ev in s.poll(0):
          if ev.srvId == sid and ev.kind == evServerStopped: done = true
        if done: break

      # After each cycle the entry must be gone.
      check s.sessionServerCount() == 0

# ---------------------------------------------------------------------------
# FIX 7: bounded event queue
# ---------------------------------------------------------------------------
suite "TftpSession — FIX 7: bounded queue":

  test "flood of evServerLog stays bounded and a subsequent terminal still arrives":
    let s = newSession()

    # Inject MaxQueuedEvents + 1000 server-log events directly via injectEvent.
    for i in 0 ..< MaxQueuedEvents + 1000:
      s.injectEvent(Event(xfrId: NoTransfer, srvId: NoServer, kind: evServerLog,
                          sLevel: llInfo, sMessage: "flood " & $i))

    # Queue length must not exceed the cap (plus small slack for the drop-warning).
    check s.sessionQueueLen() <= MaxQueuedEvents + 2

    # A terminal injected after the flood must survive eviction.
    s.injectEvent(Event(xfrId: TransferId(9001), srvId: NoServer,
                        kind: evTransferComplete,
                        snap: TransferSnapshot(bytes: 42, total: some(42'i64),
                                               blocksize: 512, windowsize: 1,
                                               direction: tdGet, mode: tmOctet,
                                               startedAt: 0.0)))

    var termSeen = false
    var warnSeen = false
    for ev in s.poll(0):
      if ev.kind == evTransferComplete and ev.xfrId == TransferId(9001):
        termSeen = true
      if ev.kind == evServerLog and ev.sLevel == llWarn and
         "dropped" in ev.sMessage:
        warnSeen = true

    check termSeen   # terminal must not be lost
    check warnSeen   # drop-warning must be emitted

# ---------------------------------------------------------------------------
# FIX 11: drain() ergonomic teardown
# ---------------------------------------------------------------------------
suite "TftpSession — FIX 11: drain()":

  test "close()+drain() returns promptly and clears active transfers":
    let tmpDir = getTempDir() / "chapulin_t_drain"
    createDir(tmpDir)
    # Large enough that transfer is still in flight when close() is called.
    writeFile(tmpDir / "drain.bin", "D".repeat(4096))
    let out1 = getTempDir() / "chapulin_t_drain_out1.bin"
    defer:
      try: removeDir(tmpDir) except: discard
      try: removeFile(out1) except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()
    let serverT = makeTransport(w, sideA = false)

    proc srvDrain(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      discard await handleRrq(serverCfg, decode(data), serverT, host, port)
    discard srvDrain()

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))

    let id = s.startTransfer(newTransferRequest("peer", 0, "drain.bin", out1, tdGet))

    # Pump until evTransferStarted arrives so the transfer is registered.
    var gotStarted = false
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        if ev.xfrId == id and ev.kind == evTransferStarted: gotStarted = true
      if gotStarted: break
    require gotStarted

    # close() signals cancel; drain() pumps until active count reaches 0 or timeout.
    s.close()
    let t0 = epochTime()
    s.drain(timeoutMs = 5000)
    let elapsed = epochTime() - t0

    # drain returns in reasonable time
    check elapsed < 6.0

    # After drain, no active client transfers remain.
    check s.sessionActiveCount() == 0

# ---------------------------------------------------------------------------
# FIX 9: evServerStarted.boundPort reflects the OS-assigned port for port=0
# ---------------------------------------------------------------------------
suite "TftpSession — FIX 9: evServerStarted.boundPort reports real OS port":

  test "listenPort=0 yields non-zero boundPort in evServerStarted (real UDP socket)":
    ## Uses a REAL UDP socket (no listenerFactory override) so the OS assigns
    ## an ephemeral port.  Before the fix, boundPort echoed config.listenPort
    ## (i.e. 0); after the fix it is the actual OS-assigned port.
    let tmpDir = getTempDir() / "chapulin_t_fix9"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except: discard)

    # No listenerFactory — falls through to transportMod.newUdpListener (real socket).
    let s = newSession()

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 0   # ask OS for an ephemeral port

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    # Poll until evServerStarted arrives.
    var boundPort = -1
    for step in 0 .. 200_000:
      for ev in s.poll(10):
        if ev.srvId == srvId and ev.kind == evServerStarted:
          boundPort = ev.boundPort
      if boundPort != -1: break
    check boundPort != -1   # event must arrive
    check boundPort != 0    # FIX 9: must be the real OS-assigned port

    # Stop the real server and drain so the socket is released.
    s.stop(srvId)
    for step in 0 .. 200_000:
      var stopped = false
      for ev in s.poll(10):
        if ev.srvId == srvId and ev.kind == evServerStopped: stopped = true
      if stopped: break

# ---------------------------------------------------------------------------
# FIX 12-residual: server ERROR path — exactly-one-(or-zero)-terminal count
# (Invariant 4): no id receives more than one terminal; fail-before-start
# (file not found, onTransferStart never fires) yields zero transfer terminals;
# fail-after-start (client sends ERROR after receiving first DATA block, so
# onTransferStart fires then sendBlocks returns failure) yields exactly one
# evTransferError.  The server stops cleanly with exactly one evServerStopped.
# ---------------------------------------------------------------------------
suite "TftpSession — FIX 12-residual: server ERROR path terminal count":

  test "fail-before-start (file not found) yields zero transfer terminals; one evServerStopped":
    # The server receives an RRQ for a nonexistent file.
    # handleRrq returns failResult *before* calling onStart → api.nim drops the
    # error (onTransferError sees NoTransfer, Invariant 4) → no transfer events.
    let tmpDir = getTempDir() / "chapulin_t_fix12_fnf"
    createDir(tmpDir)
    # Deliberately do NOT write any file — we want "file not found".
    defer: (try: removeDir(tmpDir) except: discard)

    let w = newWire()
    let q = newListenerQueue()

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(w, sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 7200

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    # Drain evServerStarted
    var startedSeen = false
    for step in 0 .. 2000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: startedSeen = true
      if startedSeen: break
    check startedSeen

    # Push RRQ for a file that doesn't exist — handleRrq returns before onStart.
    let rrq = TftpPacket(opcode: opRrq, filename: "no_such_file.txt",
                          mode: tmOctet, options: @[])
    q.push(encode(rrq), "peer", 0)

    # The server will send an ERROR packet over the wire; client side reads it
    # but we don't care — just drain to let the handler complete.
    let clientT = makeTransport(w, sideA = true)
    proc drainErr(): Future[void] {.async.} =
      try:
        discard await clientT.recv(65536, 3000)
      except: discard
    discard drainErr()

    # Drive for enough steps to let the handler finish.
    for step in 0 .. 10_000:
      for ev in s.poll(0): discard

    # Count transfer terminals for this server — must be ZERO (Invariant 4).
    var termCount = 0
    for step in 0 .. 2000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind in {evTransferComplete, evTransferError}:
          inc termCount

    check termCount == 0

    # Stop the server — exactly one evServerStopped.
    s.stop(srvId)
    var stoppedCount = 0
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStopped: inc stoppedCount
      if stoppedCount > 0: break

    check stoppedCount == 1

  test "fail-after-start (client sends ERROR after first DATA) yields exactly one evTransferError; no id gets more than one terminal":
    # The client sends an ERROR packet after receiving the first DATA block.
    # sendBlocks in handleRrq catches TransferError (from recvPacket seeing
    # opError) and returns TransferResult(success:false).  handleRequest then
    # calls onTransferError, which — because onTransferStart already fired —
    # emits exactly one evTransferError tagged with the transfer's xfrId.
    let tmpDir = getTempDir() / "chapulin_t_fix12_afterstart"
    createDir(tmpDir)
    writeFile(tmpDir / "serve_me.txt", "Fail after start test data")
    defer: (try: removeDir(tmpDir) except: discard)

    let w = newWire()
    let q = newListenerQueue()

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(w, sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 7201

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    # Drain evServerStarted
    var startedSeen = false
    for step in 0 .. 2000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: startedSeen = true
      if startedSeen: break
    check startedSeen

    # Push a valid RRQ — file exists, so onTransferStart WILL fire.
    let rrq = TftpPacket(opcode: opRrq, filename: "serve_me.txt",
                          mode: tmOctet, options: @[])
    q.push(encode(rrq), "peer", 0)

    # Client: receive the first DATA block then send an ERROR to abort.
    # recvPacket in sendBlocks sees opError → raises TransferError →
    # sendBlocks catches it and returns TransferResult(success:false).
    let clientT = makeTransport(w, sideA = true)
    proc clientSendError(): Future[void] {.async.} =
      try:
        let (data, host, port) = await clientT.recv(65536, 5000)
        let pkt = decode(data)
        if pkt.opcode == opData:
          let errPkt = TftpPacket(opcode: opError, errorCode: errNotDefined,
                                   errorMsg: "client abort")
          await clientT.send(encode(errPkt), host, port)
      except: discard
    discard clientSendError()

    # Collect all server events until we see a terminal for this server.
    var evs: seq[Event]
    var gotTerminal = false
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        evs.add ev
        if ev.srvId == srvId and ev.kind in {evTransferComplete, evTransferError}:
          gotTerminal = true
      if gotTerminal: break

    require gotTerminal

    # Recover the xfrId assigned by onTransferStart.
    var xfrId = NoTransfer
    for ev in evs:
      if ev.srvId == srvId and ev.kind == evTransferStarted:
        xfrId = ev.xfrId
    require xfrId != NoTransfer

    # Exactly one terminal, and it must be evTransferError (Invariant 4).
    var termCount = 0
    var termKind: EventKind
    for ev in evs:
      if ev.xfrId == xfrId and ev.kind in {evTransferComplete, evTransferError}:
        inc termCount
        termKind = ev.kind
    check termCount == 1
    check termKind == evTransferError

    # Stop server — exactly one evServerStopped (Invariant 8).
    s.stop(srvId)
    var stoppedCount = 0
    for step in 0 .. 200_000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStopped: inc stoppedCount
      if stoppedCount > 0: break

    check stoppedCount == 1

# ---------------------------------------------------------------------------
# R2-2: snap is a common field on ALL evTransfer* kinds (including evTransferError)
# ---------------------------------------------------------------------------
suite "TftpSession — R2-2: snap common field on evTransferError":

  test "evTransferError exposes ev.snap.bytes and ev.errorMsg without errSnap":
    # Pre-launch failure (PUT with nonexistent localPath): snap.bytes == 0,
    # errorMsg non-empty. Demonstrates that ev.snap is the common field accessible
    # on evTransferError — no separate errSnap field exists after R2-2.
    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(newWire(), sideA = true))

    let missingPath = getTempDir() / "chapulin_r22_no_such_file.bin"
    let id = s.startTransfer(newTransferRequest("peer", 0, "upload.txt", missingPath, tdPut))
    check id != NoTransfer

    var errEv: Event
    var gotErr = false
    for ev in s.poll(0):
      if ev.xfrId == id and ev.kind == evTransferError:
        errEv = ev
        gotErr = true

    require gotErr
    # Common field ev.snap is accessible on evTransferError (replaces errSnap)
    check errEv.snap.bytes == 0         # no bytes transferred before failure
    check errEv.errorMsg.len > 0        # error message is populated

  test "evTransferError from failing transport carries snap.bytes accessible via common field":
    # A GET over a transport that fails immediately. The error event's ev.snap.bytes
    # is accessible via the common field (>= 0 always).
    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport =
        makeFailingTransport(newWire(), sideA = true, failAfter = 0))

    let localOut = getTempDir() / "chapulin_r22_fail_out.bin"
    defer: (try: removeFile(localOut) except: discard)

    let id = s.startTransfer(newTransferRequest("peer", 0, "test.txt", localOut, tdGet))
    check id != NoTransfer

    var errEv: Event
    var gotErr = false
    var steps = 0
    while steps < 50_000 and not gotErr:
      for ev in s.poll(0):
        if ev.xfrId == id and ev.kind == evTransferError:
          errEv = ev
          gotErr = true
      inc steps

    require gotErr
    # ev.snap is the common field: always accessible regardless of outcome
    check errEv.snap.bytes >= 0
    check errEv.errorMsg.len > 0

# ---------------------------------------------------------------------------
# R2-4: nil localPort in UdpListener must not raise NilAccessDefect
# ---------------------------------------------------------------------------
suite "TftpSession — R2-4: nil localPort fallback in startServer":

  test "startServer with nil localPort does not raise; boundPort falls back to config.listenPort":
    # Build a UdpListener with a valid recv/close but localPort = nil.
    # Before the fix, calling listener.localPort() raises NilAccessDefect (Defect,
    # uncatchable). After the fix, the nil-guard falls back to config.listenPort.
    let q = newListenerQueue()
    let baseListener = makeListener(q, 8500)
    let nilPortListener = UdpListener(
      recv:      baseListener.recv,
      close:     baseListener.close,
      localPort: nil)  # omitted — simulates older/simpler factory

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(newWire(), sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = nilPortListener
    )

    var cfg = newDefaultServerConfig(getTempDir())
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 8500

    var srvId: ServerId
    var raised = false
    try:
      srvId = s.startServer(cfg)
    except:
      raised = true

    check not raised      # must NOT raise NilAccessDefect
    check srvId != NoServer

    # Must emit evServerStarted; boundPort must fall back to config.listenPort
    var boundPort = -1
    for step in 0 .. 2000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted:
          boundPort = ev.boundPort
      if boundPort != -1: break

    check boundPort == cfg.listenPort  # R2-4: fell back to configured port

    # Stop cleanly
    s.stop(srvId)
    for step in 0 .. 200_000:
      var done = false
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStopped: done = true
      if done: break

# ---------------------------------------------------------------------------
# R2-5: pkt.filename with control chars must be sanitized before log emission
# ---------------------------------------------------------------------------
suite "TftpSession — R2-5: log injection sanitization":

  test "RRQ filename with newline and control chars is sanitized in evServerLog messages":
    # An attacker RRQ with "\n" and "\x01" in the filename must NOT propagate
    # those bytes into evServerLog messages. The sanitizeForLog helper replaces
    # bytes < 0x20 and 0x7F with '?'.
    let tmpDir = getTempDir() / "chapulin_t_r2_5"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except: discard)

    let w = newWire()
    let q = newListenerQueue()

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport =
        makeTransport(w, sideA = false),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p)
    )

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.listenAddr = "127.0.0.1"
    cfg.listenPort = 8600

    let srvId = s.startServer(cfg)
    check srvId != NoServer

    for step in 0 .. 2000:
      var saw = false
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStarted: saw = true
      if saw: break

    # Attacker-controlled filename with newline and control chars
    let injectedName = "evil\nINJECTED\x01file.txt"
    let rrq = TftpPacket(opcode: opRrq, filename: injectedName,
                         mode: tmOctet, options: @[])
    q.push(encode(rrq), "peer", 0)

    # Drain the server error response on the client side so the handler completes
    let clientT = makeTransport(w, sideA = true)
    proc drainR25(): Future[void] {.async.} =
      try: discard await clientT.recv(65536, 3000)
      except: discard
    discard drainR25()

    # Collect server log events over enough steps for the handler to finish
    var logMessages: seq[string]
    for step in 0 .. 15_000:
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerLog:
          logMessages.add ev.sMessage

    # R2-5: none of the log messages may contain raw control chars
    var foundControlChar = false
    for msg in logMessages:
      for c in msg:
        if ord(c) < 0x20 or ord(c) == 0x7f:
          foundControlChar = true
          break
      if foundControlChar: break

    check logMessages.len > 0      # at least the initial request log was emitted
    check not foundControlChar     # no raw control chars in any log message

    s.stop(srvId)
    for step in 0 .. 200_000:
      var done = false
      for ev in s.poll(0):
        if ev.srvId == srvId and ev.kind == evServerStopped: done = true
      if done: break

# ---------------------------------------------------------------------------
# Round-2 regression: client snapshot must report NEGOTIATED blocksize, not
# the REQUESTED blocksize, for evTransferProgress and evTransferComplete.
# evTransferStarted is allowed to carry the requested value (pre-handshake).
# ---------------------------------------------------------------------------
suite "TftpSession — client OACK negotiation: snapshot reports negotiated blocksize":

  test "GET: OACK downgrades blksize from requested to negotiated; progress+complete snapshots reflect negotiated value":
    # Request blksize=4096.  The wire responder OACKs with blksize=1024.
    # Before the fix: progress/complete snaps report 4096 (REQUESTED).
    # After the fix:  progress/complete snaps report 1024 (NEGOTIATED).
    # evTransferStarted is allowed to carry the requested value (4096).
    let tmpDir = getTempDir() / "chapulin_t_oack_neg"
    createDir(tmpDir)
    let localOut = tmpDir / "oack_neg_out.bin"
    defer:
      try: removeDir(tmpDir) except: discard

    let w = newWire()
    let serverT = makeTransport(w, sideA = false)

    let payload = newSeq[byte](100)   # 100 bytes < 1024, so single block finishes it

    # Custom responder: receive RRQ, reply OACK(blksize=1024), then DATA(1).
    proc oackResponder(): Future[void] {.async.} =
      # Step 1: receive RRQ
      let (rrqData, rHost, rPort) = await serverT.recv(65536, 5000)
      let rrqPkt = decode(rrqData)
      check rrqPkt.opcode == opRrq

      # Step 2: send OACK downgrading blksize from 4096 to 1024
      let oackPkt = TftpPacket(opcode: opOack,
                                oackOptions: @[("blksize", "1024")])
      await serverT.send(encode(oackPkt), rHost, rPort)

      # Step 3: receive ACK(0) from client
      let (ack0Data, aHost, aPort) = await serverT.recv(65536, 5000)
      let ack0 = decode(ack0Data)
      check ack0.opcode == opAck
      check ack0.ackBlockNum == 0

      # Step 4: send DATA(1) — short block, signals end of transfer
      let dataPkt = TftpPacket(opcode: opData, blockNum: 1, data: payload)
      await serverT.send(encode(dataPkt), aHost, aPort)

      # Step 5: drain ACK(1) so the wire does not stall
      try:
        let (_, _, _) = await serverT.recv(65536, 2000)
      except TransportTimeoutError:
        discard

    discard oackResponder()

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))

    var req = newTransferRequest("peer", 0, "oack_file.bin", localOut, tdGet)
    req.options.blocksize = 4096   # REQUEST large blocksize

    let id = s.startTransfer(req)
    check id != NoTransfer

    let evs = driveSession(s, id)

    # Must complete successfully
    check evs.len >= 3
    check evs[0].kind  == evTransferStarted
    check evs[^1].kind == evTransferComplete

    # evTransferStarted carries the REQUESTED blocksize (pre-handshake semantics)
    check evs[0].snap.blocksize == 4096

    # evTransferProgress and evTransferComplete must carry the NEGOTIATED blocksize
    var sawProgress = false
    for ev in evs:
      case ev.kind
      of evTransferProgress:
        sawProgress = true
        check ev.snap.blocksize == 1024   # negotiated, not requested
      of evTransferComplete:
        check ev.snap.blocksize == 1024   # negotiated, not requested
      else: discard

    check sawProgress   # must have at least one progress event
