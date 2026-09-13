## The load-bearing test for the desktop GUI's pump + client translation
## (RFC gui-oyamel-port.md §4.2/§7 tier 1). Builds the real GUI tree under
## oyamel's NoopBackend (no platform define needed), drives a REAL client
## transfer through the TftpSession facade over the in-memory wire, pumps
## `pumpOnce` in a loop, and asserts the widget state the pump produced:
## progress → 1.0, the status line, the log lines, and the enable-disable
## state machine (incl. the single-active-transfer invariant).
##
##   docker run --rm -v ${PWD}:C:\app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r tests/t_gui_pump.nim

import std/[unittest, os, asyncdispatch, options, strutils, times]
import oyamel
import ../src/chapulin/api except Event, EventKind
import ../src/chapulin/server
import ../src/chapulin/server_config
import ../src/chapulin/protocol
import ./wireharness
import ../gui/desktop/chapulin_gui
# `api` excepts `Event`/`EventKind` (oyamel's names win unqualified — see
# chapulin_gui.nim's own header comment). To build a raw chapulin `Event` for
# `injectEvent` (server event translation suite, below) this imports
# eventqueue with ZERO unqualified symbols (`import nil`) so `eventqueue.Event`
# is reachable qualified with no risk of colliding with oyamel's bare `Event`
# used everywhere else in this file (`clickStart`'s `Event(kind: ekClick, ...)`).
from ../src/chapulin/eventqueue import nil

# Build the GUI under NoopBackend and wire the client handlers, over a session
# whose transport is the in-memory wire (client side). Returns everything the
# test needs to drive it. A single-shot server responder answers the RRQ/WRQ.
proc newClientHarness(session: TftpSession): (App[NoopBackend], GuiRefs) =
  var app = newApp()
  let refs = buildGui(app, session)
  wireClient(app, refs, session)
  (app, refs)

proc fillClientForm(app: App[NoopBackend]; refs: GuiRefs;
                    remote, localPath: string; directionIndex: int) =
  app.update(refs.client.host, text = "peer")
  app.update(refs.client.port, text = "0")
  app.update(refs.client.remote, text = remote)
  app.update(refs.client.local, text = localPath)
  app.update(refs.client.dirCombo, selectedIndex = directionIndex)
  app.update(refs.client.bsCombo, selectedIndex = 0)

proc clickStart(app: App[NoopBackend]; refs: GuiRefs) =
  var ev = Event(kind: ekClick, target: refs.client.startBtn.id)
  app.dispatch(ev)

proc pumpToQuiescence(app: App[NoopBackend]; refs: GuiRefs;
                      session: TftpSession; maxSteps = 200_000) =
  ## Pump until the client transfer reaches a terminal event (active flips
  ## false) or the step cap is hit.
  var steps = 0
  while steps < maxSteps and refs.clientSt.active:
    pumpOnce(app, refs, session)
    inc steps

suite "GUI pump — client GET translation (NoopBackend, in-memory wire)":
  test "a GET driven through the facade reaches progress 1.0 + complete status + log":
    let tmpDir = getTempDir() / "chapulin_t_gui_pump_get"
    createDir(tmpDir)
    writeFile(tmpDir / "hello.txt", "Hello from TFTP!")   # 16 bytes, one block
    let localOut = getTempDir() / "chapulin_t_gui_pump_get_out.bin"
    defer:
      try: removeFile(localOut) except: discard
      try: removeDir(tmpDir)    except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()
    let serverT = makeTransport(w, sideA = false)
    proc serverRespond(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      let pkt = decode(data)
      discard await handleRrq(serverCfg, pkt, serverT, host, port)
    discard serverRespond()

    let session = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))
    let (app, refs) = newClientHarness(session)

    fillClientForm(app, refs, "hello.txt", localOut, directionIndex = 0)
    clickStart(app, refs)

    # State machine: start disables Start, enables Cancel.
    check app.read(refs.client.startBtn, enabled) == false
    check app.read(refs.client.cancelBtn, enabled) == true
    check refs.clientSt.active

    pumpToQuiescence(app, refs, session)

    check app.read(refs.client.prog, value) == 1.0
    check "Transfer complete" in app.read(refs.client.status, text)
    let logText = app.read(refs.client.log, text)
    check "GET hello.txt from peer:0" in logText
    check "Completed:" in logText
    # Terminal event re-enables Start, disables Cancel.
    check app.read(refs.client.startBtn, enabled) == true
    check app.read(refs.client.cancelBtn, enabled) == false
    # File actually arrived (the transfer was real, not simulated).
    check readFile(localOut) == "Hello from TFTP!"

  test "a second Start while a transfer is active is ignored (single active)":
    let tmpDir = getTempDir() / "chapulin_t_gui_pump_single"
    createDir(tmpDir)
    writeFile(tmpDir / "big.bin", "A".repeat(4096))       # 8 blocks — stays active
    let localOut = getTempDir() / "chapulin_t_gui_pump_single_out.bin"
    defer:
      try: removeFile(localOut) except: discard
      try: removeDir(tmpDir)    except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()
    let serverT = makeTransport(w, sideA = false)
    proc serverRespond(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      let pkt = decode(data)
      discard await handleRrq(serverCfg, pkt, serverT, host, port)
    discard serverRespond()

    let session = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))
    let (app, refs) = newClientHarness(session)

    fillClientForm(app, refs, "big.bin", localOut, directionIndex = 0)
    clickStart(app, refs)
    let firstId = refs.clientSt.xferId
    check firstId != NoTransfer
    # No pumping between the two clicks, so the transfer is still active.
    clickStart(app, refs)
    check refs.clientSt.xferId == firstId   # the second click minted no new transfer

    pumpToQuiescence(app, refs, session)
    check app.read(refs.client.prog, value) == 1.0

suite "GUI pump — client error translation":
  test "a GET of a missing remote file shows an error status + log, re-enables Start":
    let tmpDir = getTempDir() / "chapulin_t_gui_pump_err"
    createDir(tmpDir)                                      # empty — file absent
    let localOut = getTempDir() / "chapulin_t_gui_pump_err_out.bin"
    defer:
      try: removeFile(localOut) except: discard
      try: removeDir(tmpDir)    except: discard

    let serverCfg = newDefaultServerConfig(tmpDir)
    let w = newWire()
    let serverT = makeTransport(w, sideA = false)
    proc serverRespond(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      let pkt = decode(data)
      discard await handleRrq(serverCfg, pkt, serverT, host, port)
    discard serverRespond()

    let session = newSession(transportFactory =
      proc(host: string, port: int): Transport = makeTransport(w, sideA = true))
    let (app, refs) = newClientHarness(session)

    fillClientForm(app, refs, "nope.txt", localOut, directionIndex = 0)
    clickStart(app, refs)
    pumpToQuiescence(app, refs, session)

    check "Error:" in app.read(refs.client.status, text)
    check "Error:" in app.read(refs.client.log, text)
    check app.read(refs.client.startBtn, enabled) == true

suite "GUI pump — validation (no widgets touched by the facade)":
  test "clicking Start with an empty host logs the notice and starts no transfer":
    let session = newSession()
    let (app, refs) = newClientHarness(session)
    fillClientForm(app, refs, "hello.txt", "out.bin", directionIndex = 0)
    app.update(refs.client.host, text = "")     # invalid
    clickStart(app, refs)
    check refs.clientSt.xferId == NoTransfer
    check not refs.clientSt.active
    check "Please enter a host address." in app.read(refs.client.log, text)

# ---------------------------------------------------------------------------
# Server panel — build under NoopBackend, wire against a session whose
# startServer binds a REAL UDP socket on 127.0.0.1 (the session's default
# listenerFactory — self-contained, no external daemon, no wireharness mock
# needed for the lifecycle itself).
# ---------------------------------------------------------------------------

proc newServerHarness(session: TftpSession): (App[NoopBackend], GuiRefs) =
  var app = newApp()
  let refs = buildGui(app, session)
  wireServer(app, refs, session)
  (app, refs)

proc fillServerForm(app: App[NoopBackend]; refs: GuiRefs;
                    rootDir, portStr: string; writePolicyIndex: int;
                    maxClientsStr = "10") =
  app.update(refs.server.rootDir, text = rootDir)
  app.update(refs.server.srvPort, text = portStr)
  app.update(refs.server.wpCombo, selectedIndex = writePolicyIndex)
  app.update(refs.server.maxClients, text = maxClientsStr)

proc clickServerStart(app: App[NoopBackend]; refs: GuiRefs) =
  var ev = Event(kind: ekClick, target: refs.server.startBtn.id)
  app.dispatch(ev)

proc clickServerStop(app: App[NoopBackend]; refs: GuiRefs) =
  var ev = Event(kind: ekClick, target: refs.server.stopBtn.id)
  app.dispatch(ev)

proc pumpServerUntil(app: App[NoopBackend]; refs: GuiRefs; session: TftpSession;
                     predicate: proc(): bool {.closure.}; timeoutSec = 3.0) =
  ## Pump wall-clock-bounded (not step-bounded): the real listener's recv
  ## uses a genuine timeout, so `stop()` only takes effect once that real
  ## timeout elapses -- a step cap on a tight spin loop would either hit its
  ## cap long before enough real time passed, or (if huge) needlessly thrash
  ## CPU well past the real deadline. epochTime() is what actually gates it.
  let deadline = epochTime() + timeoutSec
  while not predicate() and epochTime() < deadline:
    pumpOnce(app, refs, session)

suite "GUI pump — server lifecycle (NoopBackend, real UDP listener)":
  test "Start binds a real server (evServerStarted -> running status); Stop drains it":
    let tmpDir = getTempDir() / "chapulin_t_gui_pump_server"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except CatchableError: discard)

    let session = newSession()
    let (app, refs) = newServerHarness(session)

    fillServerForm(app, refs, tmpDir, "0", writePolicyIndex = 0)   # port 0 = OS-assigned
    clickServerStart(app, refs)

    pumpServerUntil(app, refs, session,
      proc(): bool = "running" in app.read(refs.server.status, text))

    check "running" in app.read(refs.server.status, text)
    check app.read(refs.server.startBtn, enabled) == false
    check app.read(refs.server.stopBtn, enabled) == true
    check refs.serverSt.serverId != NoServer

    clickServerStop(app, refs)
    # Stop() flips stopBtn immediately (synchronous, no pump needed)...
    check app.read(refs.server.stopBtn, enabled) == false
    check "Stopping..." in app.read(refs.server.status, text)

    # ...but the real evServerStopped only lands once the listener's own
    # recv timeout elapses and the run loop actually exits.
    pumpServerUntil(app, refs, session,
      proc(): bool = "stopped" in app.read(refs.server.status, text), timeoutSec = 5.0)

    check "stopped" in app.read(refs.server.status, text)
    check app.read(refs.server.startBtn, enabled) == true
    check app.read(refs.server.stopBtn, enabled) == false
    check "Server stopped" in app.read(refs.server.log, text)

suite "GUI pump — server event translation (injected events, deterministic)":
  test "evServerLog and evTransfer* events translate onto the server log":
    let tmpDir = getTempDir() / "chapulin_t_gui_pump_server_events"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except CatchableError: discard)

    let session = newSession()
    let (app, refs) = newServerHarness(session)

    fillServerForm(app, refs, tmpDir, "0", writePolicyIndex = 0)
    clickServerStart(app, refs)
    pumpServerUntil(app, refs, session,
      proc(): bool = "running" in app.read(refs.server.status, text))

    let srvId = refs.serverSt.serverId
    check srvId != NoServer

    let params = TransferParams(blocksize: 512, windowsize: 1)
    session.injectEvent(eventqueue.Event(kind: evServerLog, xfrId: NoTransfer,
      srvId: srvId, sLevel: llWarn, sMessage: "disk almost full"))
    session.injectEvent(eventqueue.Event(kind: evTransferStarted, xfrId: NoTransfer,
      srvId: srvId, snap: TransferSnapshot(bytes: 0, total: some(2048'i64),
        requested: params, effective: some(params), direction: tdGet,
        mode: tmOctet, startedAt: epochTime()),
      errorCode: none(TftpErrorCode), errorMsg: ""))
    session.injectEvent(eventqueue.Event(kind: evTransferComplete, xfrId: NoTransfer,
      srvId: srvId, snap: TransferSnapshot(bytes: 2048, total: some(2048'i64),
        requested: params, effective: some(params), direction: tdGet,
        mode: tmOctet, startedAt: epochTime()),
      errorCode: none(TftpErrorCode), errorMsg: ""))
    session.injectEvent(eventqueue.Event(kind: evTransferError, xfrId: NoTransfer,
      srvId: srvId, snap: TransferSnapshot(bytes: 0, total: none(int64),
        requested: params, effective: none(TransferParams), direction: tdPut,
        mode: tmOctet, startedAt: epochTime()),
      errorCode: none(TftpErrorCode), errorMsg: "disk full"))

    pumpOnce(app, refs, session)

    let logText = app.read(refs.server.log, text)
    check "[WARN] disk almost full" in logText
    check "Incoming transfer started (RRQ)" in logText
    check "Transfer complete: " in logText
    check "Transfer error: disk full" in logText

    clickServerStop(app, refs)
    pumpServerUntil(app, refs, session,
      proc(): bool = "stopped" in app.read(refs.server.status, text), timeoutSec = 5.0)
