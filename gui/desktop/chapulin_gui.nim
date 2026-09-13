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
## SLICE 1 (this commit): in-place cutover skeleton — window + tabContainer with
## two placeholder tabs + a LIVE (but empty) pump + the ekClose lifecycle +
## Defect-safe run/shutdown. Panels and event translation land in slices 2-3.

import oyamel
import oyamel/dsl
# oyamel's `Event`/`EventKind` (GUI events) collide with chapulin's `Event`/
# `EventKind` (the TFTP event stream). This file names ONLY oyamel's; the pump's
# `ev` is inferred from `poll()` and never spelled, and chapulin's ev* enum
# VALUES (evTransferProgress, …) remain in scope (excepting the type name does
# not except its members). See RFC §3/§4.7.
import ../../src/chapulin/api except Event, EventKind

type
  GuiRefs* = object
    ## Handles the pump and lifecycle need after the build. Grows with the
    ## panels (slices 2-3); the skeleton needs only the window and the two tabs
    ## to build into.
    win*: WidgetId
    clientTab*: WidgetId
    serverTab*: WidgetId

proc buildGui*[B](app: App[B]; session: TftpSession): GuiRefs =
  ## Lay out the whole widget tree (build-then-register, §4.2). Backend-generic
  ## so the same tree builds under a real platform backend (launchGui) and under
  ## NoopBackend (the tests/t_gui_pump.nim seam, slice 2). Inside a generic proc
  ## the `as` bindings survive only via the returned tuple, not the scope splice.
  let ui = app.build:
    window(title = "chapulin", size = (680, 580), spacing = 6, padding = 8) as winId:
      tabContainer(expand = emFill) as tabs:
        tab(title = "Client") as clientTab:
          label(text = "")   # placeholder — buildClientPanel fills this in slice 2
        tab(title = "Server") as serverTab:
          label(text = "")   # placeholder — buildServerPanel fills this in slice 3
  discard ui.tabs
  GuiRefs(win: ui.winId.id, clientTab: ui.clientTab.id, serverTab: ui.serverTab.id)

proc pumpOnce*[B](app: App[B]; refs: GuiRefs; session: TftpSession) =
  ## Drain the session event queue once and translate to widget updates. The
  ## skeleton keeps the timer LIVE (so close is clean) but has nothing to
  ## translate yet — slices 2-3 add the route-first-then-translate body.
  for ev in session.poll(0):
    discard ev

proc launchGui*() =
  let session = newSession()  # default minLogLevel = llInfo

  # newPlatformApp() runs the backend's init() synchronously and can raise
  # (GtkApiError when the GTK4 runtime is absent/too old). Catch it here — in
  # the GUI file, never src/ — so the no-src/-diff invariant holds. CatchableError
  # covers GtkApiError without importing the gtk4-only type (which won't compile
  # under -d:oyamelWin32).
  let app =
    try:
      newPlatformApp()
    except CatchableError as e:
      stderr.writeLine "chapulin: GUI backend unavailable: " & e.msg
      return

  let refs = buildGui(app, session)

  # ekClose lifecycle (§4.7): close() alone only flips flags; drain() pumps
  # poll() until transfers/servers actually release their transports or the
  # 500 ms deadline elapses. A bounded block on the UI thread in a close
  # handler is acceptable — ekClose fires pre-teardown with the window still up.
  # quit() is redundant on Win32 (WM_DESTROY already requests quit) but needed
  # for GTK4's last-window rule.
  app.on(refs.win, ekClose, proc(event: var oyamel.Event) =
    session.close()
    session.drain(timeoutMs = 500)
    app.quit())

  # The load-bearing pump: one 50 ms UI-thread timer. -d:oyamelAsync OFF, so
  # this is the only thing advancing the session; poll(0) is non-blocking.
  discard app.setInterval(50, proc() = pumpOnce(app, refs, session))

  # Defect safety (§4.8): oyamel's callbackGuard re-raises a throwing handler/
  # pump out of run(), skipping shutdown(). chapulin's facade can leak Nim
  # Defects past `except CatchableError`, so guard with `except Exception` and
  # always shut down.
  try:
    app.run()
  except Exception as e:
    stderr.writeLine "chapulin: GUI error: " & e.msg
  finally:
    try: app.shutdown()
    except Exception: discard
