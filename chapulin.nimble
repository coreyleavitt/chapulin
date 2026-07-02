# Package
version       = "0.1.0"
author        = "corey"
description   = "Cross-platform TFTP client and server"
license       = "Apache-2.0"
srcDir        = "src"
bin           = @["chapulin"]

# Dependencies
requires "nim >= 2.0.0"
requires "https://github.com/coreyleavitt/NiGui#head"

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

task gui, "Build with GUI support":
  exec "nim c --threads:on -d:withGui -d:release -o:chapulin src/chapulin.nim"
