# Package
version       = "0.1.0"
author        = "corey"
description   = "Cross-platform TFTP client and server"
license       = "MIT"
srcDir        = "src"
bin           = @["chapulin"]

# Dependencies
requires "nim >= 2.0.0"
requires "nigui >= 0.2.8"

task test, "Run unit tests":
  exec "nim c -r tests/t_protocol.nim"
  exec "nim c -r tests/t_transfer.nim"
  exec "nim c -r tests/t_options.nim"
  exec "nim c -r tests/t_security.nim"
  exec "nim c -r tests/t_server.nim"
  exec "nim c -r tests/t_logging.nim"
  exec "nim c -r tests/t_uri.nim"
  exec "nim c -r tests/t_client.nim"
  exec "nim c -r tests/t_api.nim"

task gui, "Build desktop GUI":
  exec "nim c --threads:on -o:chapulin_gui gui/desktop/chapulin_gui.nim"
