## chapulin desktop GUI — oyamel (Win32 + GTK4).
##
## Ported from the frozen NiGui GUI (git history keeps the original). Client and
## server panels live in a real tabContainer; a single 50 ms timer pumps
## `session.poll(0)` and translates the chapulin event stream to widget updates
## on the UI thread (`-d:oyamelAsync` OFF — the pump is the whole integration).
## See docs/rfc/gui-oyamel-port.md.
##
## Build gate (link, not `nim check`):  pwsh scripts/dev-test.ps1 -GuiBuild
##
## SLICE 2 (client): the client tab, the pump's client translation, the
## validation split, and the read-only auto-tailing log.
##
## SLICE 3 (server): the server tab, server lifecycle (start/stop), and the
## server-side event translation (evServer*/evTransfer* on the server's log).

import std/[times, options, deques, strutils, os]
import oyamel
import oyamel/dsl
# oyamel's `Event`/`EventKind` (GUI events) collide with chapulin's `Event`/
# `EventKind` (the TFTP event stream). This file names ONLY oyamel's; the pump's
# `ev` is inferred from `poll()` and never spelled, and chapulin's ev* enum
# VALUES (evTransferProgress, …) remain in scope (excepting the type name does
# not except its members). See RFC §3/§4.7.
import ../../src/chapulin/api except Event, EventKind
import gui_pure

const
  LabelWidth = 80
  MaxLogLines = 500   ## cap the log's backing model (RFC §4.4)

type
  ClientUi* = object
    ## Typed widget handles for the client panel (the `as` bindings, lifted out
    ## of buildGui's tuple). Handlers and the pump address the typed surface
    ## through these — never build-order-dependent.
    host*, port*, remote*, local*: WidgetRef[wkTextBox]
    dirCombo*, bsCombo*: WidgetRef[wkComboBox]
    startBtn*, cancelBtn*, browseBtn*: WidgetRef[wkButton]
    prog*: WidgetRef[wkProgressBar]
    status*: WidgetRef[wkLabel]
    log*: WidgetRef[wkTextArea]

  ClientState* = ref object
    ## Mutable per-panel state. `ref` because oyamel handler closures capture it
    ## and Nim closures cannot capture a `var`. `xferId` is the single active
    ## client transfer (NoTransfer = idle); `active` gates the start button.
    xferId*: TransferId
    active*: bool
    startTime*: float
    logLines*: Deque[string]

  ServerUi* = object
    ## Typed widget handles for the server panel, mirroring ClientUi.
    rootDir*, srvPort*, maxClients*: WidgetRef[wkTextBox]
    wpCombo*: WidgetRef[wkComboBox]
    startBtn*, stopBtn*, rootBrowseBtn*: WidgetRef[wkButton]
    status*: WidgetRef[wkLabel]
    log*: WidgetRef[wkTextArea]

  ServerState* = ref object
    ## Mutable per-panel state, mirroring ClientState. `serverId` is the
    ## single active server this panel owns (NoServer = idle).
    serverId*: ServerId
    logLines*: Deque[string]

  GuiRefs* = object
    win*: WidgetId
    client*: ClientUi
    clientSt*: ClientState
    server*: ServerUi
    serverSt*: ServerState

# ---------------------------------------------------------------------------
# Log model — read-only, auto-tailing, capped (RFC §4.4)
# ---------------------------------------------------------------------------

proc appendLog[B](app: App[B]; log: WidgetRef[wkTextArea]; logLines: var Deque[string];
                   msg: string) =
  ## Append one line to a panel's log. Uses oyamel's `appendText` (O(appended),
  ## keeps the view tailed) on the normal path; only when the cap is exceeded
  ## does it trim + full-replace (a cold path for TFTP's short logs). The
  ## backing Deque is the source of truth for that rebuild. Shared by both the
  ## client and server panels (`logLine`/`serverLogLine` below) — same model,
  ## two independent Deques.
  let firstLine = logLines.len == 0
  logLines.addLast(msg)
  if logLines.len > MaxLogLines:
    while logLines.len > MaxLogLines: discard logLines.popFirst()
    var whole = ""
    for i in 0 ..< logLines.len:
      if i > 0: whole.add '\n'
      whole.add logLines[i]
    app.update(log, text = whole)
  else:
    app.appendText(log, if firstLine: msg else: "\n" & msg)

proc logLine[B](app: App[B]; ui: ClientUi; st: ClientState; msg: string) =
  appendLog(app, ui.log, st.logLines, msg)

proc serverLogLine[B](app: App[B]; ui: ServerUi; st: ServerState; msg: string) =
  appendLog(app, ui.log, st.logLines, msg)

# ---------------------------------------------------------------------------
# Client transfer state machine
# ---------------------------------------------------------------------------

proc setTransferring[B](app: App[B]; ui: ClientUi; st: ClientState; running: bool) =
  ## Single-active-transfer invariant (RFC §4.3): Start is disabled from
  ## startTransfer until the transfer's terminal event re-enables it.
  st.active = running
  app.update(ui.startBtn, enabled = not running)
  app.update(ui.cancelBtn, enabled = running)

proc readClientForm[B](app: App[B]; ui: ClientUi): ClientForm =
  ## Impure half of the validation split (§4.5): the widget reads. The pure
  ## parseClientForm (gui_pure) does the validation + request build.
  ClientForm(
    host: app.read(ui.host, text),
    portStr: app.read(ui.port, text),
    remoteFile: app.read(ui.remote, text),
    localFile: app.read(ui.local, text),
    directionIndex: app.read(ui.dirCombo, selectedIndex),
    blocksizeIndex: app.read(ui.bsCombo, selectedIndex))

proc notify[B](app: App[B]; win: WidgetId; ui: ClientUi; st: ClientState; msg: string) =
  ## A validation/error notice. showMessage is deferred to a later loop turn
  ## (safe from the pump) and its callback carries no decision. ALSO logged: a
  ## showMessage whose backend dialog fails reports as cancelled — the log line
  ## is the durable record the blocking NiGui `alert` never had (§4.5).
  logLine(app, ui, st, msg)
  app.showMessage(win, MessageConfig(text: msg, icon: miWarning, buttons: mbOk),
                  proc(res: MessageDialogResult) = discard)

# ---------------------------------------------------------------------------
# Server lifecycle state machine
# ---------------------------------------------------------------------------

proc setServerRunning[B](app: App[B]; ui: ServerUi; st: ServerState; running: bool) =
  ## Start/Stop enable-disable pair, mirroring setTransferring.
  app.update(ui.startBtn, enabled = not running)
  app.update(ui.stopBtn, enabled = running)

proc readServerForm[B](app: App[B]; ui: ServerUi): ServerForm =
  ## Impure half of the validation split (§4.5): the widget reads. The pure
  ## parseServerForm (gui_pure) does the validation.
  ServerForm(
    rootDir: app.read(ui.rootDir, text),
    portStr: app.read(ui.srvPort, text),
    maxClientsStr: app.read(ui.maxClients, text),
    writePolicyIndex: app.read(ui.wpCombo, selectedIndex))

proc serverNotify[B](app: App[B]; win: WidgetId; ui: ServerUi; st: ServerState; msg: string) =
  ## A validation/error notice on the server panel, mirroring `notify`.
  serverLogLine(app, ui, st, msg)
  app.showMessage(win, MessageConfig(text: msg, icon: miWarning, buttons: mbOk),
                  proc(res: MessageDialogResult) = discard)

# ---------------------------------------------------------------------------
# Client event translation (pump target)
# ---------------------------------------------------------------------------

proc onClientEvent*[B](app: App[B]; ui: ClientUi; st: ClientState; ev: auto) =
  ## Translate one client transfer event to widget updates. Exhaustive over the
  ## transfer kinds this panel owns; `else: discard` covers only the other
  ## panel's kinds (RFC §4.3 — never a blanket over this panel's own kinds).
  case ev.kind
  of evTransferProgress:
    let f = fraction(ev.snap.bytes, ev.snap.total)
    if f.isSome:
      app.update(ui.prog, value = max(0.0, min(1.0, f.get)))   # clamp for GTK4 parity
    let elapsed = epochTime() - st.startTime
    app.update(ui.status, text = progressText(ev.snap, elapsed))
  of evTransferComplete:
    app.update(ui.prog, value = 1.0)
    let elapsed = epochTime() - st.startTime
    app.update(ui.status, text = "Transfer complete (" &
      elapsed.formatFloat(ffDecimal, 2) & "s)")
    logLine(app, ui, st, "Completed: " & formatBytes(ev.snap.bytes))
    setTransferring(app, ui, st, false)
  of evTransferError:
    app.update(ui.status, text = "Error: " & sanitizeForDisplay(ev.errorMsg))
    logLine(app, ui, st, "Error: " & sanitizeForDisplay(ev.errorMsg))
    setTransferring(app, ui, st, false)
  else:
    discard   # server-side kinds — handled by onServerEvent

# ---------------------------------------------------------------------------
# Server event translation (pump target)
# ---------------------------------------------------------------------------

proc onServerEvent*[B](app: App[B]; ui: ServerUi; st: ServerState; ev: auto) =
  ## Translate one server-routed event to widget updates. `snap`/`errorMsg`
  ## are read only inside their own evTransfer* arms (Defect-safe — RFC §4.8):
  ## `ev.snap` is a compile error on any evServer* kind, so there is no way to
  ## accidentally read it off-arm.
  case ev.kind
  of evServerStarted:
    app.update(ui.status, text = "Server running on " & ev.boundAddr & ":" & $ev.boundPort)
  of evServerStartFailed:
    # Mirrors onClientEvent's evTransferError: a pump-fired failure gets a
    # log line + status update, never a modal dialog (dialogs are reserved
    # for SYNCHRONOUS validation notices, which have a WidgetId to anchor on
    # — onServerEvent, like onClientEvent, does not take one).
    serverLogLine(app, ui, st, "Server failed to start: " & sanitizeForDisplay(ev.startErr))
    setServerRunning(app, ui, st, false)
    app.update(ui.status, text = "Server stopped")
  of evServerStopped:
    setServerRunning(app, ui, st, false)
    app.update(ui.status, text = "Server stopped")
    serverLogLine(app, ui, st, "Server stopped")
  of evServerLog:
    serverLogLine(app, ui, st, "[" & $ev.sLevel & "] " & sanitizeForDisplay(ev.sMessage))
  of evServerRejected:
    discard   # already surfaced via evServerLog at warn (NiGui parity) — handled
              # explicitly, never folded into a blanket else
  of evTransferStarted:
    serverLogLine(app, ui, st, "Incoming transfer started (" &
      (if ev.snap.direction == tdGet: "RRQ" else: "WRQ") & ")")
  of evTransferProgress:
    let f = fraction(ev.snap.bytes, ev.snap.total)
    serverLogLine(app, ui, st, "Transfer progress: " & formatBytes(ev.snap.bytes) &
      (if f.isSome: " (" & $(int(f.get * 100.0)) & "%)" else: ""))
  of evTransferComplete:
    serverLogLine(app, ui, st, "Transfer complete: " & formatBytes(ev.snap.bytes))
  of evTransferError:
    serverLogLine(app, ui, st, "Transfer error: " & sanitizeForDisplay(ev.errorMsg))

# ---------------------------------------------------------------------------
# Build + wire
# ---------------------------------------------------------------------------

proc buildGui*[B](app: App[B]; session: TftpSession): GuiRefs =
  ## Lay out the whole widget tree in one build (build-then-register, §4.2).
  ## Backend-generic so the same tree builds under a real platform backend
  ## (launchGui) and under NoopBackend (tests/t_gui_pump.nim). Inside a generic
  ## proc the `as` bindings survive only via the returned tuple.
  let ui = app.build:
    window(title = "chapulin", size = (680, 580), spacing = 6, padding = 8) as winId:
      tabContainer(expand = emFill) as tabs:
        tab(title = "Client") as clientTab:
          vbox(spacing = 6, expand = emFill):
            # NB: `as` binding names are suffixed (…Box/…Btn/…) — a bare name
            # like `local` or `log` collides with an imported stdlib symbol
            # (std/times.local, std/math.log) and mistypes the build tuple field.
            hbox(spacing = 6):
              label(text = "Host:", minSize = (LabelWidth, 0))
              textBox(text = "192.168.1.1", expand = emFill) as hostBox
              label(text = "Port:")
              textBox(text = "69", size = (65, 0)) as portBox
            hbox(spacing = 6):
              label(text = "Remote file:", minSize = (LabelWidth, 0))
              textBox(expand = emFill) as remoteBox
            hbox(spacing = 6):
              label(text = "Local file:", minSize = (LabelWidth, 0))
              textBox(expand = emFill) as localBox
              button(text = "Browse...") as browseBtn
            hbox(spacing = 6):
              label(text = "Direction:", minSize = (LabelWidth, 0))
              comboBox(items = @["GET (Download)", "PUT (Upload)"],
                       selectedIndex = 0) as dirCombo
              label(text = "Block size:")
              comboBox(items = @["512", "1024", "1468", "4096", "8192"],
                       selectedIndex = 0) as bsCombo
            hbox(spacing = 6):
              button(text = "Start Transfer", expand = emFill) as startBtn
              button(text = "Cancel", enabled = false) as cancelBtn
            progressBar(value = 0.0) as progBar
            label(text = "Ready") as statusLbl
            textArea(readOnly = true, expand = emFill) as logArea
        tab(title = "Server") as serverTab:
          vbox(spacing = 6, expand = emFill):
            # NB: `as` binding names are suffixed (srv…/wpCombo) — a bare name
            # like `local` or `log` collides with an imported stdlib symbol
            # (std/times.local, std/math.log) and mistypes the build tuple field.
            hbox(spacing = 6):
              label(text = "Root dir:", minSize = (LabelWidth, 0))
              textBox(expand = emFill) as srvRootBox
              button(text = "Browse...") as srvRootBrowseBtn
            hbox(spacing = 6):
              label(text = "Port:", minSize = (LabelWidth, 0))
              textBox(text = "69", size = (65, 0)) as srvPortBox
              label(text = "Write policy:")
              comboBox(items = @["deny", "create", "overwrite", "all"],
                       selectedIndex = 0) as wpCombo
              label(text = "Max:")
              textBox(text = "10", size = (40, 0)) as srvMaxBox
            hbox(spacing = 6):
              button(text = "Start Server", expand = emFill) as srvStartBtn
              button(text = "Stop", enabled = false) as srvStopBtn
            label(text = "Server stopped") as srvStatusLbl
            textArea(readOnly = true, expand = emFill) as srvLogArea
  discard ui.tabs
  let client = ClientUi(
    host: ui.hostBox, port: ui.portBox, remote: ui.remoteBox, local: ui.localBox,
    dirCombo: ui.dirCombo, bsCombo: ui.bsCombo,
    startBtn: ui.startBtn, cancelBtn: ui.cancelBtn, browseBtn: ui.browseBtn,
    prog: ui.progBar, status: ui.statusLbl, log: ui.logArea)
  let server = ServerUi(
    rootDir: ui.srvRootBox, srvPort: ui.srvPortBox, maxClients: ui.srvMaxBox,
    wpCombo: ui.wpCombo,
    startBtn: ui.srvStartBtn, stopBtn: ui.srvStopBtn, rootBrowseBtn: ui.srvRootBrowseBtn,
    status: ui.srvStatusLbl, log: ui.srvLogArea)
  GuiRefs(
    win: ui.winId.id,
    client: client,
    clientSt: ClientState(xferId: NoTransfer, active: false,
                          logLines: initDeque[string]()),
    server: server,
    serverSt: ServerState(serverId: NoServer, logLines: initDeque[string]()))

proc wireClient*[B](app: App[B]; refs: GuiRefs; session: TftpSession) =
  ## Register the client handlers after the build, when every `as` binding is in
  ## scope (§4.2). Handlers capture app/ui/session/st.
  let ui = refs.client
  let st = refs.clientSt
  let win = refs.win

  app.on(ui.browseBtn, ekClick, proc(event: var oyamel.Event) =
    # NiGui's blocking dialog becomes oyamel's completion callback. GET → save
    # dialog, PUT → open dialog (direction read off the combo).
    let isGet = app.read(ui.dirCombo, selectedIndex) == 0
    let cfg = FileDialogConfig(
      kind: if isGet: fdkSave else: fdkOpen,
      title: if isGet: "Save downloaded file as" else: "Select file to upload",
      filters: @[("All files", "*")])   # "*" not "*.*" — GTK4 hides extensionless otherwise (§6.2)
    app.showFileDialog(win, cfg, proc(res: FileDialogResult) =
      if not res.cancelled and res.paths.len > 0:
        app.update(ui.local, text = res.paths[0])))

  app.on(ui.startBtn, ekClick, proc(event: var oyamel.Event) =
    if st.active: return                       # single active transfer (§4.3)
    let parsed = parseClientForm(readClientForm(app, ui))
    if not parsed.ok:
      notify(app, win, ui, st, parsed.err); return
    if parsed.req.direction == tdPut and not fileExists(parsed.req.localPath):
      notify(app, win, ui, st, "Local file not found: " & parsed.req.localPath); return

    st.startTime = epochTime()
    app.update(ui.prog, value = 0.0)
    setTransferring(app, ui, st, true)
    let dirStr = if parsed.req.direction == tdGet: "GET" else: "PUT"
    logLine(app, ui, st, dirStr & " " & parsed.req.filename & " " &
      (if parsed.req.direction == tdGet: "from " else: "to ") &
      parsed.req.host & ":" & $parsed.req.port)
    st.xferId = session.startTransfer(parsed.req))

  app.on(ui.cancelBtn, ekClick, proc(event: var oyamel.Event) =
    if st.xferId != NoTransfer:
      session.cancel(st.xferId)
      logLine(app, ui, st, "Cancelling transfer..."))

proc wireServer*[B](app: App[B]; refs: GuiRefs; session: TftpSession) =
  ## Register the server handlers after the build, when every `as` binding is
  ## in scope (§4.2). Handlers capture app/ui/session/st. Mirrors wireClient's
  ## shape: a browse callback, a Start handler (validate → check root dir
  ## exists → build ServerConfig → start), and a Stop handler.
  let ui = refs.server
  let st = refs.serverSt
  let win = refs.win

  app.on(ui.rootBrowseBtn, ekClick, proc(event: var oyamel.Event) =
    let cfg = FileDialogConfig(kind: fdkFolder, title: "Select TFTP root directory")
    app.showFileDialog(win, cfg, proc(res: FileDialogResult) =
      if not res.cancelled and res.paths.len > 0:
        app.update(ui.rootDir, text = res.paths[0])))

  app.on(ui.startBtn, ekClick, proc(event: var oyamel.Event) =
    let parsed = parseServerForm(readServerForm(app, ui))
    if not parsed.ok:
      serverNotify(app, win, ui, st, parsed.err); return
    # IMPURE checks, deliberately outside gui_pure's parseServerForm (§4.5):
    # dirExists touches the filesystem; newServerConfig builds the real
    # ServerConfig (its own bounds validation is the single shared authority —
    # RFC conformance-closure D7 — never re-derived here).
    if not dirExists(parsed.rootDir):
      serverNotify(app, win, ui, st, "Directory not found: " & parsed.rootDir); return
    let outcome = newServerConfig(rootDir = parsed.rootDir, listenPort = parsed.port,
                                   writePolicy = parsed.writePolicy,
                                   maxConcurrent = parsed.maxClients)
    if not outcome.ok:
      serverNotify(app, win, ui, st, outcome.rejectReason); return
    setServerRunning(app, ui, st, true)
    serverLogLine(app, ui, st, "Starting server...")
    st.serverId = session.startServer(outcome.config))

  app.on(ui.stopBtn, ekClick, proc(event: var oyamel.Event) =
    if st.serverId != NoServer:
      session.stop(st.serverId)
      app.update(ui.stopBtn, enabled = false)
      app.update(ui.status, text = "Stopping..."))

# ---------------------------------------------------------------------------
# The pump (load-bearing) — route first, then translate (RFC §4.3)
# ---------------------------------------------------------------------------

proc pumpOnce*[B](app: App[B]; refs: GuiRefs; session: TftpSession) =
  ## Drain the session event queue under a small per-tick time budget (§4.3),
  ## routing each event to its panel by the key it already carries — the
  ## client/server split is one decision, not re-derived per arm.
  let deadline = epochTime() + 0.010
  while true:
    var any = false
    for ev in session.poll(0):
      any = true
      if ev.srvId != NoServer:
        onServerEvent(app, refs.server, refs.serverSt, ev)
      elif ev.xfrId == refs.clientSt.xferId:
        onClientEvent(app, refs.client, refs.clientSt, ev)
      # else: stale client event (e.g. post-cancel) — dropped, as today
    if not any or epochTime() >= deadline: break

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# launchGui is the only proc that names a concrete backend (newPlatformApp),
# which exists ONLY under a backend define. Guard it so this module still
# compiles with NO define — the path tests/t_gui_pump.nim takes under
# NoopBackend (buildGui/wireClient/pumpOnce are backend-generic and always
# compile). src/chapulin.nim imports this module only under -d:withGui, which
# (via config.nims) always implies a backend define, so the call site is safe.
when defined(oyamelWin32) or defined(oyamelGtk4):
  proc launchGui*() =
    let session = newSession()  # default minLogLevel = llInfo

    # newPlatformApp() runs the backend's init() synchronously and can raise
    # (GtkApiError when the GTK4 runtime is absent/too old). Catch it here — in
    # the GUI file, never src/ — so the no-src/-diff invariant holds.
    let app =
      try:
        newPlatformApp()
      except CatchableError as e:
        stderr.writeLine "chapulin: GUI backend unavailable: " & e.msg
        return

    let refs = buildGui(app, session)
    wireClient(app, refs, session)
    wireServer(app, refs, session)

    # ekClose lifecycle (§4.7): close() flips flags; drain() pumps poll() until
    # transfers/servers release their transports or the 500 ms deadline elapses.
    app.on(refs.win, ekClose, proc(event: var oyamel.Event) =
      session.close()
      session.drain(timeoutMs = 500)
      app.quit())

    # The load-bearing pump: one 50 ms UI-thread timer. -d:oyamelAsync OFF.
    discard app.setInterval(50, proc() = pumpOnce(app, refs, session))

    # Defect safety (§4.8): a throwing handler/pump re-raises out of run(),
    # skipping shutdown(); chapulin's facade can leak Nim Defects past
    # `except CatchableError`, so guard with `except Exception` and always shut
    # down.
    try:
      app.run()
    except Exception as e:
      stderr.writeLine "chapulin: GUI error: " & e.msg
    finally:
      try: app.shutdown()
      except Exception: discard
