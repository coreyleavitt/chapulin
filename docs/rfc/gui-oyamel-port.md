# RFC: chapulin GUI — NiGui → oyamel port

**Status:** draft (Stage 1 — `/architect` round 1 applied; platform-scope fork **resolved** 2026-09-13, §6.0 — Win32 + Linux/GTK4 targets, macOS GUI dropped until oyamel ships Cocoa; ready for `/tdd`)
**Predecessor:** `gui/desktop/chapulin_gui.nim` (the NiGui GUI, complete and working — Windows-only)
**Handoff:** `gui-oyamel-port.handoff.md`
**Spike evidence:** `gui/desktop/chapulin_gui_oyamel_spike.nim` (throwaway client-panel spike, `nim check -d:oyamelWin32` clean at oyamel@35096e2)

## 1. Motivation

chapulin's desktop GUI (`gui/desktop/chapulin_gui.nim`, ~400 lines) is built on **NiGui**, which is effectively frozen. (NiGui is *not* Windows-only — chapulin ships a NiGui GTK3 GUI on Linux and macOS today, CI builds `-d:withGui` on all three OSes — but it is a dead upstream.) **oyamel** — Corey's cross-platform (Win32 + GTK4, Cocoa forthcoming) toolkit — is its intended successor. Porting is worth doing now because oyamel has matured past every Win32 blocker a prior spike surfaced, and the move buys:

- **A live, modern cross-platform backend.** oyamel's **GTK4** backend replaces NiGui's frozen GTK3 on Linux (newer toolkit, active upstream) and its Win32 backend replaces NiGui on Windows. macOS keeps the NiGui-era GUI dropped for now (no oyamel Cocoa backend yet — §6.0) but the CLI stays cross-platform. For an FFI-free TFTP tool that already runs headless anywhere, this swaps a dead GUI dependency for a maintained one without losing the Win32/Linux GUI.
- **A safer, terser widget API.** oyamel's RFC 0013 "typed mutation surface" replaces NiGui's untyped imperative widget pokes with `app.update(id, field = val)` / `app.read(id, field)`, where the field is **type-checked against the widget kind at compile time**. The whole `newX(...) ; x.prop = ...` construction/mutation idiom collapses into a declarative `app.build:` tree plus typed accessors.
- **Two capabilities NiGui lacks outright:** a real first-class `tabContainer` (the GUI currently fakes tabs with two buttons toggling `panel.visible`), and a window-close hook (`ekClose`) — so the port can finally `session.close()` on exit instead of the current "let the process exit release resources" note (`chapulin_gui.nim:403-407`).

The GUI is a frontend: it imports only `src/chapulin/api.nim` (the session facade) and drives it through the event stream. **This port changes no `src/` code and no protocol/engine/transfer logic** — it rewrites one file and swaps one dependency.

## 2. Goals / non-goals

**Goals.**
- **G1.** Port `gui/desktop/chapulin_gui.nim` from NiGui to oyamel, preserving all current behavior: client (GET/PUT with host/port/remote/local/direction/blocksize, browse, progress, status, log, cancel) and server (root dir, port, write policy, max clients, start/stop, status, log) panels.
- **G2.** Adopt oyamel's genuine improvements rather than transliterate NiGui: a real `tabContainer`, an `ekClose` handler that calls `session.close()`, and the typed `app.update`/`app.read` surface.
- **G3.** Swap the dependency (NiGui → oyamel) in `milpa.kdl`, and establish a compile gate for the ported GUI (it is outside `dev-test.ps1`'s compile set, exactly as the CLI and the current GUI are).
- **G4.** Keep the load-bearing invariant explicit and unchanged in shape: **one `setInterval(50)` timer pumps `session.poll(0)`**, translating the chapulin event stream to widget updates on the UI thread, with `-d:oyamelAsync` OFF.

**Non-goals.**
- Any `src/` change. This is a frontend swap; the never-throw facade, protocol, engine, and transfer layers are untouched.
- Redesigning the GUI's information architecture beyond the tab/lifecycle upgrades in G2 (no new features, no restyle).
- Adopting oyamel's async mode. `-d:oyamelAsync` was removed upstream and re-seeded as oyamel RFC 0015 (not shipped); even once it re-lands, chapulin keeps it off — chronos would collide with chapulin's `std/asyncdispatch`. The pump is the integration.
- **macOS GUI.** oyamel has no Cocoa backend yet, so macOS builds without `-d:withGui` (CLI only) until oyamel ships Cocoa (§6.0). Dropping the mac GUI NiGui provides today is an accepted, temporary consequence.

GTK4 *is* an in-scope tested target now (the softlink floor is resolved in slice 0, §6.0) — the port is backend-agnostic by construction (cross-platform DSL surface only), and both `-d:oyamelWin32` **and** `-d:oyamelGtk4` get build gates, with a GTK4 loopback run in oyamel's gtk4 container (§5/§7). Note one GTK4-specific touch: `newPlatformApp()` raises `GtkApiError` when the GTK4 runtime is absent, so `launchGui` must catch it (this lives in the GUI file, not `src/`, so the no-`src/`-diff invariant holds).

## 3. The validated foundation (why this is low-risk)

A compile-first spike (`gui/desktop/chapulin_gui_oyamel_spike.nim`) already exercised the load-bearing client path against oyamel and `nim check`s clean at oyamel@35096e2. Every structural blocker a source read could not have caught has been surfaced and resolved:

| Concern | Status |
| --- | --- |
| The pump: `setInterval(50)` → `session.poll(0)` → typed widget updates | Compiles clean; this is the spike's core |
| Dialog-callback restructuring (`showFileDialog` completion callback) | Compiles clean |
| oyamel wired via milpa alongside chapulin's z3 stack | Win32 resolves cleanly (oyamel dropped its *unconditional* softlink `require`). GTK4's in-code `requireSoftlink "0.12.3"` floor (`gtk4/bindings/glib.nim:36`) vs chapulin's softlink 0.11.1 pin is resolved in **slice 0** by bumping the pin to 0.12.3 — safe because `z3.nimble` declares no softlink requirement and nim-z3 main works against 0.12.3 (§6.0). |
| `Event` name collision (chapulin's `api.Event` vs oyamel's `Event`) | **Partially** fixed upstream (oyamel#214: the DSL's *inline* `on ekX:` codegen now `bindSym"Event"`s its lambda param). This does **not** cover hand-written `app.on(id, kind, proc(event: var Event) = …)` — both `Event`s are in scope there and a bare `Event` is ambiguous (the spike writes `oyamel.Event`, `spike:159-164`). Since §4.2 routes *every* handler through `app.on`, the GUI resolves it at the import: `import ../../src/chapulin/api except Event, EventKind`. `poll` still infers chapulin's event type, and this file never needs to name it. See §4.3/§4.7. |
| Real `tabContainer` initial-visibility correctness | Fixed upstream (oyamel#201/#202) |
| RFC 0014 effect contracts breaking consumer handlers | oyamel's `callbackGuard` catches every exception (Defects included) through the OS frame — but **re-raises** it at the next drain boundary, so a throwing handler/pump surfaces as an exception out of `app.run()`, skipping `app.shutdown()`. Not "firewalled away": UB-through-an-OS-frame becomes deterministic app death. Given chapulin's facade can leak Nim `Defect`s past `except CatchableError`, the port must make handlers never-throw and wrap `run()`/`shutdown()` — see §4.8. |
| `-d:oyamelAsync` vs `std/asyncdispatch` | Moot — no async mode currently exists in oyamel |

The port therefore starts against a clean, no-workaround foundation **for the Win32 backend's client-GET path** — which is all the spike exercised. The cross-OS build surface (CI, `chapulin.nimble`, the macOS/Linux GUI that NiGui ships today) and the server-side event arms are *not* part of that foundation; see the §6 platform-scope fork.

## 4. Design

### 4.1 Dependency + build wiring

> **The dep swap is not one file.** CI and release resolve deps via **`nimble install -d -y`** against **`chapulin.nimble`** (which `requires NiGui#head`), *not* milpa — and build `-d:withGui` on **all three OSes**. Swapping only `milpa.kdl` leaves CI/release red. The full build-system change is **slice 0** (§5): bump softlink to 0.12.3 + swap the dep in both `milpa.kdl` and `chapulin.nimble`; set the per-OS CI/release matrix — **Windows `-d:oyamelWin32`**, **Linux `-d:oyamelGtk4`** (install GTK4 dev libs, *not* GTK3), **macOS drops `-d:withGui`** (§6.0); update README, the `gui` nimble task, and add the committed `config.nims`.

- `milpa.kdl`: **remove** `NiGui` from `deps`, **add** `oyamel` pinned by commit (no tags yet; oyamel is under heavy RFC-driven dev — pin a ref, never `main`; pin-by-40-hex-`ref` is supported). Re-`lock`/`fetch`; confirm `_deps/oyamel` materializes and `nim.cfg` gains its `--path`. **Mirror this in `chapulin.nimble`** (drop NiGui, add oyamel) so the nimble-driven CI/release path resolves too.
- **Backend + console defines — committed home.** `-d:withGui` stays the "build the GUI at all" gate; the backend define rides alongside. The default cannot live in `nim.cfg` (milpa-generated, gitignored) or a `src/*.cfg` (violates the no-`src/`-diff DoD), so it lives in a **committed root `config.nims`**: on Windows (unless `-d:oyamelGtk4` is explicitly passed) default `oyamelWin32` + `oyamelShowConsole`; on Linux default `oyamelGtk4`. `oyamelShowConsole` is **required** on the Win32 build, not cosmetic — without it the vcc Win32 build links `/SUBSYSTEM:WINDOWS` and chapulin's `get`/`serve` CLI subcommands print nothing (`backends/win32.nim:33-42`).
- **The gate is `nim c`, not `nim check`.** The GUI is outside `dev-test.ps1`'s compile set, so it needs an explicit gate in the Windows container — but it must *link* (tier-2 in §7): `nim check` skips codegen/linking and would miss the `/SUBSYSTEM`/manifest/`passL "comctl32.lib"` layer and gcsafe-of-stored-closures issues. A full `nim c -d:withGui` of GUI-enabled chapulin has never actually been run in chapulin's container.

### 4.2 Module structure — build-then-register

oyamel's `as` bindings are lexical `let`s (a handler can only reference widgets declared *above* it — the spike's Finding B). A ~400-line GUI with handlers that touch widgets declared much later (the pump touches nearly every widget; `startBtn` touches the progress bar and log) would otherwise force an awkward top-to-bottom ordering.

The clean pattern — which oyamel's own `settings_dialog.nim` uses for its cross-scope reaction — is **build first, register handlers after**: lay out the whole widget tree in one `app.build:` with `as` bindings and no (or minimal) inline handlers, then register every handler *after* the build with `app.on(id, kind, proc(...))`, where all `as` bindings are in scope. This sidesteps build-order entirely and keeps layout and behavior as two readable sections, mirroring how the NiGui version already assigns all `onClick`s after constructing the tree. Inline `on ekClick:` is reserved for the handful of handlers that only touch already-declared, local widgets.

**Decompose into panels, not one 400-line proc.** The NiGui version is a single `launchGui` mixing layout, mutable state (`transferActive`, `clientStartTime`, `serverId`), event translation, and validation; the spike made this *worse* by hoisting state to module-level globals. The port should not inherit the monolith. oyamel's `app.build:` already **returns a named tuple of every `as` binding** (`dsl.nim`), and `build(app, parent, body)` builds into an existing parent — so each panel is a unit with a small typed interface:

```nim
type GuiApp   = typeof(newPlatformApp())         # avoids naming the backend generic
type ClientState = ref object                     # ref: Nim closures can't capture `var` params
  xferId: TransferId
  startTime: float
proc buildClientPanel(app: GuiApp, parent: WidgetId): auto =   # returns typed refs
  app.build(parent): vbox(...): ...
proc wireClient(app: GuiApp, ui: auto, session: TftpSession, st: ClientState) = ...
proc onClientEvent(app: GuiApp, ui: auto, st: ClientState, ev: Event) = ...  # see §4.3
```

Same shape for `ServerPanel`/`ServerState`. This (a) stays inside the non-goals (no IA change, no new feature), (b) makes slices 2 and 3 genuinely independent (each fills its own tab), and (c) the tuple channel dissolves the lexical-ordering constraint this section is built around — handlers registered against `ui.<name>` never see it. Dead state in the NiGui version (`transferActive`, `serverActive` are write-only) is dropped, not copied.

**Build the GUI against a backend-generic `App[B]` so it is unit-testable.** The top-level proc is `proc buildGui*[B](app: var App[B]; session: TftpSession): GuiRefs` and the pump body is `proc pumpOnce*[B](app: var App[B]; refs: GuiRefs; session: TftpSession)` (the `setInterval` handler just calls `pumpOnce`). oyamel ships a `NoopBackend` (`core/backend.nim`, records `update`/`read` calls) that compiles with **no** backend define — exactly how oyamel's own cross-platform suites run. This lets `tests/t_gui_pump.nim` build the GUI under `NoopBackend` inside `dev-test.ps1`'s container, drive a real loopback transfer through the facade, call `pumpOnce` in a loop, and assert `app.read(refs.prog, value) == 1.0` / status text / log lines / the enable-disable state machine. That is a genuine RED→GREEN for the load-bearing translation (§7), and the only way behavior parity gets a test rather than a manual eyeball. Note the spike is module-top-level code; production must live inside `launchGui*()` — so this restructuring is required regardless.

### 4.3 The pump (load-bearing, unchanged in shape)

One `app.setInterval(50, proc() = ...)` drains `session.poll(0)`. The timer handler runs on the UI thread (Win32 `SetTimer`/`WM_TIMER`), so touching widgets inside it is safe. `ev`'s type is chapulin's `Event`, inferred from `poll` — and because this file does `import … api except Event` (§3/§4.7), there is no ambiguity and no qualifier needed in the loop. `sanitizeForDisplay` (already re-exported by the facade) still guards every attacker-influenced string (`errorMsg`, `sMessage`, and `startErr` — which the NiGui version does *not* currently sanitize, `chapulin_gui.nim:297`; the port should).

**Route first, then translate — don't re-derive the client/server split in every arm.** The NiGui pump re-derives `ev.srvId == NoServer and ev.xfrId == clientXferId` vs `ev.srvId != NoServer` inside each of six transfer arms (`chapulin_gui.nim:250,263,272,279,283,287`) — one routing bug waiting in any of them, and the only reason §4.2 needs the build-then-register rule at all. The `Event` carries the routing key (`xfrId`, `srvId`) outside the `case`, so routing is one decision made once:

```nim
discard app.setInterval(50, proc() =
  for ev in session.poll(0):
    if ev.srvId != NoServer:        app.onServerEvent(serverUi, serverSt, ev)
    elif ev.xfrId == client.xferId: app.onClientEvent(clientUi, clientSt, ev)
    # else: stale client event (e.g. post-cancel) — dropped, exactly as today
)
```

`onClientEvent` is a `case ev.kind` over only `evTransferProgress/Complete/Error` (+ `else: discard`); `onServerEvent` over the five `evServer*` kinds plus the server branches of the transfer kinds. Extract the progress-string formatting — duplicated today at `:252-262` (client) and `:265-269` (server) — into a **pure** `proc progressText(snap: TransferSnapshot; elapsed: float): string` with no oyamel import; it is the one genuinely unit-testable piece and the NoopBackend test (§4.2) asserts against it.

**Invariants the port must state and keep (the spike violates two):**
- **Exhaustive `case`, no `else` on the kind switch's producer side.** `verification-harness-v2` C2 records that a non-exhaustive `case ev.kind` previously broke the GUI; the NiGui pump has no catch-all. Each panel's `case` handles its kinds explicitly and uses `else: discard` *only* for the other panel's kinds — never as a blanket.
- **Single active client transfer.** Start is disabled from `startTransfer` until that id's terminal event (the NiGui `setTransferring` enforces this; the spike does not — a second Start opens a second sink on the same local path). Slice 2 acceptance must cover it.
- **No nested native message loop from the pump body.** Nothing that runs a modal loop may be called inside the `poll` iteration (NiGui's blocking `window.alert` at `:297` did exactly this, re-entering `asyncdispatch.poll` while the outer iterator frame was live). oyamel's `showMessage`/`showFileDialog` are *deferred to a later loop turn* by construction, which is what makes the `evServerStartFailed` arm safe — state this so a future `showInput` (which pumps a dialog loop) isn't added to the pump.

**Throughput budget, not "one poll per tick."** `api.poll` calls `asyncdispatch.poll` once; on Windows `runOnce` dequeues a single completion packet, so at ~one I/O completion per 50 ms tick a TFTP transfer is throttled to roughly one block per two ticks (order ~5 KB/s at 512-byte blocks). This ceiling is pre-existing in NiGui, but the port is the moment to fix it cheaply: drain under a small per-tick time budget — `let deadline = epochTime() + 0.010; while epochTime() < deadline and hasPendingWork: for ev in session.poll(0): translate(ev)`. State the 10 ms budget as the invariant (replacing G4's "one `poll(0)` per tick"); measure before/after with the existing loopback tests.

### 4.4 Widget & idiom mapping

| NiGui | oyamel |
| --- | --- |
| `app.init()` / `app.run()` | `newPlatformApp()` / `app.run()` / `app.shutdown()` |
| `newWindow(t)` | `window(title = t, ...) as winId` |
| `newLayoutContainer(Layout_Vertical/Horizontal)` | `vbox` / `hbox(spacing = ...)` |
| `newButton(t)` / `.onClick =` | `button(text = t) as id` / `on ekClick:` or `app.on(id, ekClick, ...)` |
| `btn.enabled = false` | `app.update(id, enabled = false)` — **every** interactive widget spells it `enabled`; there is **no** `disabled` field (verified against `core/types.nim`; the §6 "disabled vs enabled split" was a phantom and has been deleted) |
| `WidthMode_Expand` | `expand = emFill` |
| `newLabel(t)` / `.minWidth = W` alignment | `label(text = t, minSize = (W, 0))` — `minSize` is a generic `{.dsl.}` property on every widget (`types.nim`), a direct 1:1 map. Keep `const LabelWidth = 80`. (Do **not** use a 2-column `grid`: its `columnWeights` aren't DSL-reachable and the rows are ragged.) |
| `newTextBox(v)` / `.text` / `.width = N` | `textBox() as id`; `app.read(id, text)` / `app.update(id, text = v)`; fixed width via `size = (N, 0)` (port box `(65,0)`, max-clients `(40,0)`); `expand = emFill` on the boxes NiGui let expand by default |
| `newComboBox(@[...])` / `.index` / `.options` | `comboBox(items = @[...], selectedIndex = 0)` — **the `selectedIndex = 0` is mandatory**: oyamel defaults it to `-1` (`types.nim:1810`), and `items[-1]` raises `IndexDefect` → fatal (§4.8). Read via `app.read(id, selectedIndex)` and map index→value with a `case` + default, never `items[idx]`; guard `if idx < 0`. |
| `newProgressBar()` / `.value` (0..1) | `progressBar(value = 0.0)`; `app.update(id, value = f)` — clamp `f` into `[0,1]` in the GUI (`fraction` doc range is `[0,∞)`; Win32 clamps via `PBM_SETPOS` but GTK4 may not, so clamp here for backend parity) |
| `newTextArea("")` / `.editable=false` / `.addLine` | `textArea() as id`. **Two parity gaps (see §6):** (1) oyamel's `TextAreaData` has **no read-only** field — `enabled=false` greys it and kills copy/scroll, so the log is either user-editable or grey until an oyamel `readOnly` lands; (2) there is **no `addLine`** and the whole-buffer `text =` push resets scroll/caret and round-trips through `syncTextArea`. Do **not** use the naive `text = read & "\n" & line` read-modify-write (it is O(n²) across a transfer and resets scroll every server-progress line). Use a capped line model — `Deque[string]` with a cap (~500), batch all lines produced in one tick into **one** `update` per textArea per tick — and file the oyamel `readOnly` + `appendText` enhancement. |
| tab buttons + `panel.visible` toggle | real `tabContainer:` with `tab(title = "Client"):` / `tab(title = "Server"):` — stand this up in **slice 1** (empty tabs), not a later "fold-in" slice (§5). `tab()` mints its own vbox (spacing 4 / padding 8), so don't double-nest a panel `vbox` inside it. |
| `startRepeatingTimer(50, ...)` | `app.setInterval(50, proc() = ...)` |

**Geometry (NiGui sets it; oyamel won't by default).** NiGui opens 680×580 (`chapulin_gui.nim:19-20`); oyamel auto-sizes a `(0,0)` window to intrinsic size, and a `textArea`'s intrinsic is ~4 lines/80px — so the port opens tiny unless it sets `window(size = (680, 580), ...)` and gives each log `expand = emFill` with vertical weight. Note oyamel is per-monitor-DPI-v2 aware, so 680×580 is logical px.

### 4.5 Dialog-callback restructuring

NiGui's dialogs block (`dialog.run()`); oyamel's are non-blocking completion callbacks. Three sites:

- **Client browse** (`chapulin_gui.nim:213-223`): GET → save dialog, PUT → open dialog. Becomes: read `dirCombo` selection, then `showFileDialog(winId, FileDialogConfig(kind: if get: fdkSave else fdkOpen, ...), proc(res) = if not res.cancelled and res.paths.len > 0: app.update(localBox, text = res.paths[0]))`. Natural as a callback.
- **Server root browse** (`:226-231`): `showFileDialog(..., kind: fdkFolder, ...)`.
- **Validation `window.alert(msg); return`** — there are **more sites than two**: client start (`:323-338`), server start (`:356-367`), the `configOutcome.rejectReason` alert (`:385`), and the `evServerStartFailed` alert *inside the pump* (`:297`). These are pure error *notices*. Restructure each to `if invalid: app.showMessage(winId, MessageConfig(text: msg, ...), proc(_) = discard); return`. `showMessage` is deferred to a later loop turn (so the one fired from the pump is safe per §4.3's nested-loop invariant) and its callback carries no decision; the `return` short-circuits submission. **Also append the notice to the panel log** — a `showMessage` whose backend dialog *fails* reports as `cancelled` (indistinguishable from the user dismissing it), so a click that silently does nothing would otherwise leave no trace; the log line is the durable record the blocking `alert` never had.

  Separate the three concerns rather than interleaving reads/parse/notice in one handler: `readClientForm(app, ui)` (widget reads → a plain record) → `parseClientForm(f): (ok, req, err)` (**pure**, FFI-free, display-free — testable under `dev-test.ps1`) → one `alert` site. The server side already has the pure validating constructor `newServerConfig` (`:378-386`); mirror the shape: `readServerForm` → `parseServerForm` → `newServerConfig`.

### 4.6 Tab upgrade

Replace the two-button + `panel.visible` fake (`chapulin_gui.nim:27-34, 204-210`) with oyamel's real `tabContainer:` holding `tab(title = "Client"):` and `tab(title = "Server"):`. This deletes the manual visibility state and the tab-button handlers, and the create-path initial-visibility correctness the port relies on is the exact thing fixed by oyamel#201/#202.

### 4.7 Lifecycle

Register the close handler — qualifying the param type (`api.Event` is excluded at import per §3, but spelling `oyamel.Event` here is still the clearest signal of which `Event` this is):

```nim
app.on(win, ekClose, proc(event: var oyamel.Event) =
  session.close()
  session.drain(timeoutMs = 500)   # REQUIRED — see below
  app.quit())
```

**`session.close()` alone releases nothing.** `close()` only flips cancel/stop flags and calls `srv.stop()`; it deliberately does *not* close transports ("the in-flight futures own them", `api.nim:692-706`) — they release on *subsequent* `poll()`/`drain()` callbacks. `close(); app.quit()` returns from `run()` with nothing left to pump, i.e. functionally identical to the NiGui "let the process exit release resources" note (`:403-407`). The `drain(500)` is what actually makes the §1/§7 "clean `session.close()` on exit" real: it pumps `poll` until transfers/servers terminate or the deadline elapses. A bounded block on the UI thread in a close handler is acceptable — `ekClose` fires pre-teardown with the window still up. (If instant-close UX matters more than clean release, veto the close (`event.consumed = true`), disable the UI, and let the existing 50 ms pump drain until quiescent before quitting — but that is more machinery; `drain(500)` is the recommended default.) `app.quit()` is redundant on Win32 (WM_DESTROY already requests quit) but keep it for GTK4's last-window rule.

Also decide: **closing during an active transfer** — the recommended `close()+drain()` cancels in-flight transfers and waits up to 500 ms; if a confirm prompt is wanted instead, that is the `event.consumed` veto path. State the chosen behavior; the parity checklist (§7) exercises it.

### 4.8 Defect safety (never-throw handlers)

chapulin's facade is known to leak Nim `Defect`s (`FieldDefect`/`NilAccessDefect`) past `except CatchableError`. oyamel's `callbackGuard` catches handler exceptions through the OS frame but **re-raises** them out of `app.run()` (§3), so a single Defect from the pump or a handler kills the GUI and skips `app.shutdown()`. The port must therefore:

1. Wrap the run at the top: `try: app.run() finally: app.shutdown()`, with an `except Exception` that logs to stderr and exits non-zero (or shows a final `showMessage`) rather than crashing raw out of `launchGui` (`src/chapulin.nim:287`).
2. Make the pump body and every handler never-throw by construction. Concrete Defect sites to guard (each fatal without this):
   - `comboBox` index → value via `case` + default, never `items[selectedIndex]` (default `-1`; §4.4).
   - `ev.snap.total.get` is safe only via the implicit `fraction.isSome ⇔ total.isSome` coupling (`:259`); write `total.get(0)` or make the coupling explicit.
   - progress `value` clamped to `[0,1]` (§4.4).
   - port / max-clients `parseInt` already guarded by the validation notices (§4.5) — do **not** carry the spike's silent `except ValueError: 69` default into production; it swallows a real input error.

## 5. Slices (vertical)

> The old plan built two flat panels, then "folded" them into tabs (slice 4), then cutover (slice 5). But #201/#202 are fixed so there is no reason to defer tabs, there is no visible-toggle scaffolding in the oyamel version to delete, and `tab()` mints its own vbox — so building flat first *creates* the layout drift §6 warns about. And slices 1–4 all left `src/chapulin.nim -d:withGui` broken (it imports the GUI) until slice 5. The slices below cut over **in place** from slice 1 and dissolve 4/5.

0. **Build-system + CI (a round, not a slice — blast radius `milpa.kdl` + `chapulin.nimble` + two workflow files + `README.md` + `config.nims` + `dev-test.ps1`).** Bump softlink `v0.11.1`→`v0.12.3` and swap NiGui→oyamel (pinned) in **both** `milpa.kdl` and `chapulin.nimble`; add the committed `config.nims` (per-OS backend + `oyamelShowConsole`); set the CI/release matrix — Windows `-d:oyamelWin32`, Linux `-d:oyamelGtk4` + GTK4 dev libs, macOS no `-d:withGui`; update README + the `gui` nimble task; add the `-GuiBuild` gate to `dev-test.ps1`. Gate: CI green on all three OSes (GUI built on Win/Linux, CLI-only on macOS) + the existing z3/nelli test stack still resolves against softlink 0.12.3.
1. **In-place cutover skeleton.** Replace `gui/desktop/chapulin_gui.nim` (git history keeps the NiGui version): `newPlatformApp()` + `window(size = (680,580))` + `tabContainer` with two **empty** `tab()`s + an **empty pump** (`setInterval(50, proc() = for ev in session.poll(0): discard)`, so the skeleton is *live* — timer fires, clean close — not inert) + the `ekClose` → `close()+drain()` lifecycle (§4.7) + `try/run/finally/shutdown` (§4.8). Gate: the tier-2 `nim c -d:withGui` link gate (§7) is green; host-run shows the window opens and closes with exit 0.
2. **Client tab + pump translation.** `buildClientPanel(app, clientTab)` + `wireClient` + `onClientEvent` (§4.2/§4.3); the `NoopBackend` test `t_gui_pump.nim` (§7 tier 1) is the RED→GREEN; batched/capped log (§4.4); the validation split (§4.5). Host: loopback GET + PUT to 100%, cancel.
3. **Server tab + server arms.** `buildServerPanel` + `wireServer` + `onServerEvent` (the five `evServer*` arms + server branches of transfer events) + one `elif` in the router (§4.3); extend `t_gui_pump.nim`. Host: start/stop/log/reject.
4. **GTK4 producer (makes "cross-platform" real, not claimed).** Add the `-d:oyamelGtk4` link gate in oyamel's gtk4 container/podman image and a loopback GET/PUT **run** on Linux; fix the GTK4-specific gaps the backend-agnostic code can still trip (file-dialog `"*"` filter not `"*.*"`, `GtkApiError` catch in `launchGui`, log scroller — §6.2). This is the slice that produces the load-bearing cross-platform property; without it the port is green-but-Win32-only.

**Status (2026-09-13) — ALL SLICES DONE:** slice 0 ✅ `5e13f23`; slice 1 ✅ `bcaf59a`; slice 2 ✅ `ad5b7bd`+`ffb30a4` (pure + client); slice 3 ✅ `edd1b5a` (server); slice 4 ✅ this commit. GTK4: `-d:oyamelGtk4` link gate green (gtk4-win) AND a real Linux compile+headless-run gate (`dev-test.ps1 -GuiBuild -GuiBackend gtk4-linux`, podman+Xvfb: BUILD_EXIT=0/RUN_EXIT=0) + a CI GTK4 headless smoke (xvfb-run). GTK4 gaps: `"*"` filter ✅, `GtkApiError` catch ✅ (via `except CatchableError`), log tailing ✅ (oyamel `appendText` scroll-to-end). The driven visible loopback-transfer on GTK4 remains a manual host-checklist item (the transfer TRANSLATION is proven cross-platform by `t_gui_pump` under NoopBackend — the same backend-generic `buildGui`/`pumpOnce`/`onClientEvent`/`onServerEvent` code the GTK4 run instantiates). Cutover: spike deleted ✅; `git grep -i nigui` clean across build files + shipped source (only design/RFC docs retain the migration record) ✅.

## 6. Risks / open questions (for the `/architect` round)

### 6.0 Platform scope (RESOLVED 2026-09-13)

**Decision: target Win32 + Linux/GTK4; drop the macOS GUI for now.** The round surfaced that the original "low-risk, one file + one dep, cross-platform win" framing was wrong, so for the record:

- **NiGui is not "Windows-only" in chapulin.** CI and release build `-d:withGui` on **ubuntu/macos/windows** (`ci.yaml:14,33-40`; `release.yaml`), installing NiGui's **GTK3** backend on Linux/macOS. So chapulin ships a working GUI on all three OSes *today*. "Port to oyamel" as written would regress that.
- **oyamel has no macOS backend** (`backends/` = `win32`, `gtk4` only) — `-d:withGui` on macOS won't compile at all.
- **oyamel's GTK4 backend carried an apparent block** — a compile-time `requireSoftlink "0.12.3"` floor (`gtk4/bindings/glib.nim:36`, the bottom bindings layer every GTK4 module imports) vs chapulin's softlink **0.11.1** pin. This is the floor the *Win32* fix (oyamel dropping its unconditional softlink `require`) did **not** cover.
- CI/release resolve via **`nimble install -d -y`** against **`chapulin.nimble`** (which still `requires NiGui#head`), *not* milpa.

**Resolution:**
- **Linux/GTK4 is a real, tested target.** The softlink floor is not a hard conflict: `z3.nimble` declares **no** softlink requirement (softlink is resolved purely by `milpa.kdl`), so 0.11.1 is chapulin's pin choice and nim-z3 main works against 0.12.3. Slice 0 **bumps `milpa.kdl`'s softlink pin `v0.11.1` → `v0.12.3`**, which satisfies oyamel's GTK4 floor. Cross-platform is therefore *delivered* here — GTK4 gets a real compile/run gate (§5/§7), not a deferral.
- **macOS GUI dropped for now.** oyamel has no Cocoa backend, so macOS builds **without `-d:withGui`** (CLI stays cross-platform). A deliberate, temporary drop of the mac GUI NiGui ships today; when oyamel lands Cocoa it falls back into place with no chapulin-side change (same DSL surface).
- **Build-system swap is slice 0** — it touches `milpa.kdl` (dep swap + softlink bump) **and** `chapulin.nimble`, both CI/release workflows (per-OS backend matrix; GTK4 dev libs on Linux, drop `-d:withGui` on macOS), `README.md`, and a committed `config.nims`.

### 6.1 oyamel enhancements to file (prerequisites for slice 2, not blockers for the port's shape)

- **`readOnly` on `TextAreaData`** (`ES_READONLY` / `gtk_text_view_set_editable(false)`) — the one behavior the port cannot preserve today (NiGui's `editable = false`). Without it the logs are either user-editable or greyed-and-uncopyable. ✅ **DONE** (no interim taken) — implemented in oyamel `736c937` (both backends); the log builds `textArea(readOnly = true)`. Verified: oyamel `t_widget_update` readOnly suite + native `t_textarea_readonly_append` round-trip.
- **`appendText` at end (keeping the view tailed)** — the same backend call (`EM_REPLACESEL` at end / `gtk_text_buffer_insert` at end). Removes the O(n²)/scroll-reset problem the §4.4 capped-model only bounds. ✅ **DONE** — `app.appendText` in oyamel `736c937` (both backends); win32 brackets `EM_REPLACESEL` with `EM_SETREADONLY(0/1)` since it is a no-op on read-only EDITs. chapulin's `logLine` uses it (capped `Deque` rebuild only on 500-line overflow).

### 6.2 Smaller open items

- **`-d:withGui` × backend define — committed home.** milpa regenerates `nim.cfg` (gitignored) and a `src/*.cfg` would violate the no-`src/`-diff DoD, so the default lives in a **committed root `config.nims`**: `when defined(withGui) and defined(windows) and not defined(oyamelGtk4): switch("define","oyamelWin32"); switch("define","oyamelShowConsole")`. The `oyamelShowConsole` is not optional — without it the vcc build links `/SUBSYSTEM:WINDOWS` and `chapulin get`/`serve` print nothing (§4.1/§7).
- **GTK4 DSL gaps (for when backend B lands):** file dialog `"*.*"` filter hides extensionless files on GTK4 (PXE payloads: `vmlinuz`, `initrd`) — use `"*"` or no filter; `MessageConfig.title/.icon` and `FileDialogConfig.defaultExtension` are silent no-ops on GTK4; the GTK4 textArea has no scroller wired; `newPlatformApp()` raises `GtkApiError` when the GTK4 runtime is absent — `src/chapulin.nim:286-289` needs that catch.
- **Keyboard / focus / default button.** Decide initial focus, whether Tab cycles fields on the (non-modal) main window, and whether Start is `default = true` (`ButtonData.isDefault`). One-line decisions; pin them so layout doesn't drift.
- **oyamel pin cadence.** oyamel moves fast; the port pins a commit and will need periodic bumps. Acceptable — the API surface the port uses is stable across the last several RFCs. Pin-by-commit works in milpa (40-hex `ref`).

## 7. Definition of done

**Three-tier verification** (compile-only is insufficient for a "behavior parity" DoD, and there is no host Nim — unit tests run in the Docker container, the GUI runs on the Windows 11 host):

1. **Unit (in `dev-test.ps1`'s container).** `tests/t_gui_pump.nim` builds the GUI under `NoopBackend` (§4.2), drives a real loopback transfer + server through the facade, pumps `pumpOnce`, and asserts widget state (progress → 1.0, status/log strings, the enable-disable state machine, cancel). This is the RED→GREEN for the load-bearing translation and brings it into the compile set (closing G3's gap).
2. **Link gates (both backends, `nim c` not `nim check`).** Committed gates run **`nim c --threads:on -d:withGui -d:oyamelWin32 -d:oyamelShowConsole`** of `src/chapulin.nim` in the Windows container **and** **`nim c --threads:on -d:withGui -d:oyamelGtk4`** in oyamel's gtk4 container. `nim c`, not `check`: `check` skips codegen/linking and would miss the `/SUBSYSTEM`/manifest/`passL` layer and gcsafe-of-stored-closures issues the spike never exercised. Home: a `-GuiBuild` mode in `dev-test.ps1` (via `scripts/lib/nimcontainer.ps1`'s `-NimArgs`), output to a gitignored binary inside the bind mount so the host can run it.
3. **Host run (manual checklist — must be written into the handoff; it currently contains none).** Per-slice rows, fully self-contained via loopback, on **both Windows (Win32) and Linux (GTK4)**: window opens/closes/exit-0; start Server tab on `127.0.0.1:6969`, GET **and** PUT from the Client tab to 100%; cancel mid-transfer; browse dialogs; server start/stop/log/reject; tabs switch; **close during an active transfer**; and **`chapulin get`/`serve` still print to the console** in the GUI-enabled build.

**Parity inventory** (source of truth for the checklist — the port must preserve these exact defaults/behaviors): host `192.168.1.1`, port `69`, blocksizes `512/1024/1468/4096/8192`, max clients `10`, write-policy order `deny/create/overwrite/all` → `wpDeny/wpCreateOnly/wpOverwrite/wpCreateOrOverwrite`; every status/log string; every `setTransferring` / `srvStart/Stop` enable-disable transition; the four dialog titles; PUT `fileExists` and root `dirExists` checks; window 680×580.

**Cutover / cleanliness:**
- `gui/desktop/chapulin_gui.nim` is oyamel-based; NiGui is gone from **every** reference, not just `milpa.kdl` — `git grep -i nigui` is empty (covers `chapulin.nimble`, `.github/workflows/*.yaml`, `README.md`, the `gui` nimble task). ✅ build files + shipped source clean; only design/RFC docs (this port's own RFC included) retain the migration record.
- CI is green on all three OSes: GUI built on Windows (Win32) and Linux (GTK4), CLI-only on macOS (no `-d:withGui`); the z3/nelli test stack resolves against the bumped softlink 0.12.3. ⏳ **post-push confirmation** — local container gates all green (win32 link, gtk4-win link, gtk4-linux compile+run, full suite incl. t_symex against softlink 0.12.3); GitHub CI validated when chapulin is pushed.
- Behavior parity with the predecessor GUI for both panels (per the checklist above), plus the two upgrades: real tabs and a `session.close()+drain()` that actually releases on window close (§4.7). ✅ client + server panels ported; parity strings/defaults preserved (progressText, block sizes, write-policy order, dialog titles, status/log strings); tabs + close()+drain() live.
- The throwaway spike is deleted. ✅
- No `src/` diff (frontend-only port), confirmed by `git diff --name-only -- src/` being empty. *(Note: `config.nims` and the test live at repo root / `tests/`, not `src/`, so they don't violate this.)* ✅ verified — no `src/` changes in the whole port.
