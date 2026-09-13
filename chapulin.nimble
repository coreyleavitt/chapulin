# Package
version       = "0.1.0"
author        = "corey"
description   = "Cross-platform TFTP client and server"
license       = "Apache-2.0"
srcDir        = "src"
bin           = @["chapulin"]

# Dependencies are resolved by MILPA (milpa.kdl / milpa.lock), NOT nimble.
# nimble cannot evaluate softlink's .nimble (it imports a source module) and
# does not know the milpa-managed dev-deps (nelli, wired into every test via
# coverpragma). See scripts/ci.sh + scripts/dev-test.ps1. The only require kept
# here is the compiler floor; oyamel/softlink/nelli/z3 live in milpa.kdl.
requires "nim >= 2.0.0"

# Build/test entry points do NOT go through nimble tasks anymore:
#   - CI:    bash scripts/ci.sh            (milpa fetch + nim, native per-OS)
#   - local: pwsh scripts/dev-test.ps1     (milpa fetch + nim in the container)
#            pwsh scripts/dev-test.ps1 -GuiBuild [-GuiBackend win32|gtk4|gtk4-linux]
