# chapulin — committed compiler config (read by `nim` for any build in this tree).
#
# Home for the oyamel BACKEND define that the GUI build needs. It cannot live in
# nim.cfg (milpa-generated, gitignored) or a src/*.cfg (would violate the
# gui-oyamel-port DoD's no-src/-diff invariant), so it lives here — see
# docs/rfc/gui-oyamel-port.md §4.1 / §6.2.
#
# Only matters when the GUI is built at all (`-d:withGui`, the CLI default is
# GUI-free). Backend selection:
#   - Windows: oyamelWin32 (unless -d:oyamelGtk4 is passed explicitly, e.g. the
#     GTK4-on-Windows link gate). oyamelShowConsole is REQUIRED, not cosmetic:
#     without it the vcc build links /SUBSYSTEM:WINDOWS and `chapulin get`/`serve`
#     print nothing (oyamel backends/win32.nim).
#   - Linux: oyamelGtk4.
#   - macOS: no backend — oyamel has no Cocoa backend yet, so macOS builds
#     without -d:withGui (CLI only). If -d:withGui is forced here it fails to
#     compile (newPlatformApp does not exist), which is the correct signal.
when defined(withGui):
  when defined(windows) and not defined(oyamelGtk4):
    switch("define", "oyamelWin32")
    switch("define", "oyamelShowConsole")
  elif defined(linux):
    switch("define", "oyamelGtk4")
