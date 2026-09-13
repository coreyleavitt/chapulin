# Package
version       = "0.1.0"
author        = "corey"
description   = "Cross-platform TFTP client and server"
license       = "Apache-2.0"
srcDir        = "src"
bin           = @["chapulin"]

# Dependencies
requires "nim >= 2.0.0"
# oyamel — the cross-platform (Win32 + GTK4) GUI toolkit driving the desktop
# GUI (gui/desktop/chapulin_gui.nim), the maintained successor to the frozen
# toolkit chapulin used before. Pinned BY
# COMMIT (oyamel ships no tags; under heavy RFC-driven dev). This is the
# nimble-resolved half of the dep swap — milpa.kdl carries the same pin for the
# container dev-loop. See docs/rfc/gui-oyamel-port.md §4.1.
requires "https://github.com/coreyleavitt/oyamel.git#736c937665373ffa27d55b000f20a2c9ae702d77"
# oyamel's GTK4 backend (Linux) enforces a compile-time `requireSoftlink
# "0.12.3"` floor (glib.nim). oyamel deliberately declares NO softlink require
# of its own — that would floor Win32 consumers who never compile a line of it
# — so a nimble-driven GTK4 build must bring softlink itself. Win32 and macOS
# never touch softlink, so scope it to Linux (the only OS that builds
# -d:oyamelGtk4 via nimble; matches oyamel.nimble's documented follow-up).
when defined(linux):
  requires "https://github.com/coreyleavitt/softlink.git#v0.12.3"

task test, "Run unit tests":
  exec "nim c -r -d:chapulinTest tests/t_protocol.nim"
  exec "nim c -r -d:chapulinTest tests/t_transfer.nim"
  exec "nim c -r -d:chapulinTest tests/t_options.nim"
  exec "nim c -r -d:chapulinTest tests/t_security.nim"
  exec "nim c -r -d:chapulinTest tests/t_server.nim"
  exec "nim c -r -d:chapulinTest tests/t_logging.nim"
  exec "nim c -r -d:chapulinTest tests/t_uri.nim"
  exec "nim c -r -d:chapulinTest tests/t_client.nim"
  exec "nim c -r -d:chapulinTest tests/t_api.nim"
  exec "nim c -r -d:chapulinTest tests/t_props.nim"
  exec "nim c -r -d:chapulinTest tests/t_props_transfer.nim"
  exec "nim c -r -d:chapulinTest tests/t_props_server.nim"
  exec "nim c -r -d:chapulinTest tests/t_wireharness.nim"
  exec "nim c -r -d:chapulinTest tests/t_session.nim"
  # Desktop GUI pure layer (oyamel-free): status formatting + form validation.
  exec "nim c -r -d:chapulinTest tests/t_gui_pure.nim"
  # Desktop GUI pump + client translation under oyamel's NoopBackend (headless,
  # no backend define) driving a real transfer over the in-memory wire.
  exec "nim c -r -d:chapulinTest tests/t_gui_pump.nim"

task gui, "Build with GUI support":
  exec "nim c --threads:on -d:withGui -d:release -o:chapulin src/chapulin.nim"
