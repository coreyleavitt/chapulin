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
## validation split, and the read-only auto-tailing log. Server tab is a
## placeholder until slice 3.

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

  GuiRefs* = object
    win*: WidgetId
    client*: ClientUi
    clientSt*: ClientState
    serverTab*: WidgetId   ## slice 3 builds the server panel into this

# ---------------------------------------------------------------------------
# Log model — read-only, auto-tailing, capped (RFC §4.4)
# ---------------------------------------------------------------------------

proc logLine[B](app: App[B]; ui: ClientUi; st: ClientState; msg: string) =
  ## Append one line to the client log. Uses oyamel's `appendText` (O(appended),
  ## keeps the view tailed) on the normal path; only when the cap is exceeded
  ## does it trim + full-replace (a cold path for TFTP's short logs). The
  ## backing Deque is the source of truth for that rebuild.
  let firstLine = st.logLines.len == 0
  st.logLines.addLast(msg)
  if st.logLines.len > MaxLogLines:
    while st.logLines.len > MaxLogLines: discard st.logLines.popFirst()
    var whole = ""
    for i in 0 ..< st.logLines.len:
      if i > 0: whole.add '\n'
      whole.add st.logLines[i]
    app.update(ui.log, text = whole)
  else:
    app.appendText(ui.log, if firstLine: msg else: "\n" & msg)

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
    discard   # server-side kinds — handled by onServerEvent (slice 3)

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
          label(text = "Server panel — slice 3")   # replaced in slice 3
  discard ui.tabs
  let client = ClientUi(
    host: ui.hostBox, port: ui.portBox, remote: ui.remoteBox, local: ui.localBox,
    dirCombo: ui.dirCombo, bsCombo: ui.bsCombo,
    startBtn: ui.startBtn, cancelBtn: ui.cancelBtn, browseBtn: ui.browseBtn,
    prog: ui.progBar, status: ui.statusLbl, log: ui.logArea)
  GuiRefs(
    win: ui.winId.id,
    client: client,
    clientSt: ClientState(xferId: NoTransfer, active: false,
                          logLines: initDeque[string]()),
    serverTab: ui.serverTab.id)

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
        discard   # server-side — slice 3 (onServerEvent)
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
