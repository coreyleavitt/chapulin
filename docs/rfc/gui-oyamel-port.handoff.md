# chapulin GUI oyamel port — handoff

- **Stage:** 2 (`/tdd` in progress, 2026-09-13) — running `/loop /tdd the rfc til done` (autonomous, no-defer). **Slice 0 DONE + verified.** Next: slice 1 (in-place cutover skeleton).
- **RFC:** `docs/rfc/gui-oyamel-port.md`
- **Key standing decision (no-defer mandate):** the two oyamel enhancements (RFC §6.1: `readOnly` + `appendText` on `TextAreaData`) will be **implemented in oyamel** (both backends) when slice 2 needs them — NOT stubbed with the "interim editable log". oyamel is pinned by commit in `milpa.kdl`+`chapulin.nimble`; milpa fetches from GitHub at that ref, so oyamel changes must be **pushed + re-pinned** (see slice-2 note when reached).
- **Scope (resolved):** **Win32 + Linux/GTK4**; **macOS GUI dropped for now** (no oyamel Cocoa backend → macOS builds without `-d:withGui`). Frontend-only / no `src/` change.
- **Slice 0 (build-system) — DONE 2026-09-13.** `milpa.kdl` (NiGui→oyamel@35096e2 in deps; softlink v0.11.1→v0.12.3), `chapulin.nimble` (same swap; `when defined(linux): requires softlink 0.12.3` for the nimble-GTK4 path), new committed `config.nims` (per-OS backend + oyamelShowConsole), `ci.yaml`+`release.yaml` (Linux GTK4 dev libs + GUI build, Windows GUI build, macOS CLI-only), `README.md`, `.gitignore` (`_gui_gate/`), and `scripts/dev-test.ps1 -GuiBuild [-GuiBackend win32|gtk4]` link-gate mode. **Verified locally:** `milpa lock/fetch` resolves 4 deps (oyamel/softlink/z3/nelli, NiGui gone); z3/softlink-0.12.3 path green (`dev-test.ps1 t_symex_smoke` exit 0). CI-green-on-3-OSes is the post-push confirmation.
- **Resume:** slice 1 — replace `gui/desktop/chapulin_gui.nim` with the oyamel skeleton (newPlatformApp + window(680,580) + tabContainer with 2 empty tabs + empty pump + ekClose→close()+drain() + try/run/finally/shutdown + GtkApiError catch in launchGui). Gate: `pwsh scripts/dev-test.ps1 -GuiBuild` (win32 link) green; host run opens/closes window exit 0. oyamel API map is in this session's context (newApp()→App[NoopBackend] for tests; app.build returns named tuple; app.update/read; TextAreaData has NO readOnly/appendText yet).
- **Round 1 key corrections (all applied to the RFC):** `disabled`→`enabled` (no `disabled` field exists); comboBox `selectedIndex` defaults `-1` → must set `=0` + guard (IndexDefect); `minSize` IS a 1:1 map for label alignment; `Event` ambiguity in `app.on` handlers → `import api except Event`; `session.close()` alone releases nothing → `close()+drain(500)`; oyamel's guard RE-RAISES out of `run()` → wrap `run()/shutdown()` + never-throw handlers; gate is `nim c` not `nim check`; `-d:oyamelShowConsole` required or CLI goes silent; pump = route-then-translate + per-panel `onEvent`; build against `NoopBackend` for `tests/t_gui_pump.nim`; slices cut over in-place from slice 1 (tabs in slice 1, old 4/5 dissolved, GTK4 producer is slice 4).

## Validated foundation (do NOT re-derive — spike already proved these)

Spike: `gui/desktop/chapulin_gui_oyamel_spike.nim` (throwaway, client GET path). `nim check -d:oyamelWin32` GREEN twice — 2026-08-29 @ oyamel@098b5929 and 2026-09-12 @ oyamel@35096e2.

All prior blockers resolved as of oyamel@35096e2:
- **Pump** (`setInterval(50)`→`session.poll(0)`→typed `app.update`/`app.read`) compiles clean. `-d:oyamelAsync` OFF; async mode was removed upstream (re-seeded as oyamel RFC 0015, not shipped) so nothing collides with chapulin's `std/asyncdispatch`.
- **milpa resolves oyamel cleanly** — oyamel dropped its unconditional gtk4-only `softlink >= 0.12.3` require that had collided with chapulin's softlink 0.11.1 pin (nim-z3 floor). Add oyamel to `milpa.kdl` deps pinned by commit; `MILPA_CACHE_DIR="$PWD/.milpa-cache" milpa -C . lock && ... fetch`.
- **oyamel#214 FIXED in code** (RFC 0014, `bindSym"Event"` at dsl.nim:554) — plain `import chapulin/api` compiles, NO `except Event` workaround. Issue closed 2026-09-12.
- **oyamel#201/#202 FIXED** (tabContainer initial visibility) — the port can use a real `tabContainer` instead of the NiGui visible-toggle fake.
- **RFC 0014 effect contracts** don't touch consumer handlers (`EventHandler`/timer callbacks carry no `raises`; oyamel firewalls them).

**Don't trust oyamel GitHub issue OPEN/CLOSED state — verify against code** (#214 was fixed-in-code while still showing OPEN).

## Slices (from RFC §5)

1. Dep + skeleton (milpa swap, newPlatformApp + empty window + ekClose/session.close + nim check gate).
2. Client panel + the pump (productionize the spike).
3. Server panel (start/stop/root-browse + server-side event arms).
4. Tab container (fold both panels into tabContainer/tab(); delete visible-toggle).
5. Cutover (delete NiGui GUI + spike; ported file becomes chapulin_gui.nim; NiGui out of milpa.kdl).

## Key references

- Current GUI (the thing being ported): `gui/desktop/chapulin_gui.nim` (~400 lines, client+server, NiGui). Its pump+event-translation (`:239-314`) is the reference for the oyamel pump.
- Facade the GUI drives: `src/chapulin/api.nim` — re-exports `Event`, `EventKind`, `fraction`, `formatBytes`, `formatSpeed`, `sanitizeForDisplay`, `TransferId`/`ServerId`/`NoTransfer`/`NoServer`, etc.
- oyamel idiom reference: its `examples/hello_dsl.nim` + `examples/settings_dialog.nim` (build-then-register via `app.on`; showFileDialog/showMessage callbacks).
- Build gate note: the GUI is OUTSIDE `dev-test.ps1`'s compile set — needs its own `nim check -d:withGui -d:oyamelWin32` in the Windows container.

## Nothing committed. RFC + handoff + spike are the only artifacts; the working GUI and milpa.kdl are untouched.
