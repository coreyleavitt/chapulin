# Resolve deps on the host with milpa, then run the test suite inside the nim
# devtools container. nim is intentionally NOT installed on the host.
#
#   - milpa (host): clones deps into _deps/ as relative symlinks into a
#     content-addressed store and emits nim.cfg. MILPA_CACHE_DIR is pinned
#     inside the project so the symlinks stay within the tree and a single
#     `-v <proj>:C:\app` bind mount resolves them in the container.
#   - nim (container): compiles+runs each test, reading milpa's nim.cfg.
#
# Usage:  pwsh scripts/dev-test.ps1            # whole suite
#         pwsh scripts/dev-test.ps1 t_props    # one file (without .nim)

param([string[]]$Only)

$ErrorActionPreference = "Stop"
$proj  = Split-Path -Parent $PSScriptRoot
$image = "ghcr.io/coreyleavitt/nim:2.2.10"

# Keep the CAS in-tree (absolute path under the project — CWD-independent).
$env:MILPA_CACHE_DIR = Join-Path $proj ".milpa-cache"

Write-Host "==> milpa fetch (host)" -ForegroundColor Cyan
milpa -C $proj fetch
if ($LASTEXITCODE -ne 0) { throw "milpa fetch failed" }

$tests = if ($Only) { $Only } else {
  @("t_protocol", "t_transfer", "t_options", "t_security", "t_server",
    "t_logging", "t_uri", "t_client", "t_api", "t_props", "t_props_transfer",
    "t_props_server", "t_wireharness", "t_session", "t_checksum", "t_netascii")
}

$failed = @()
foreach ($t in $tests) {
  Write-Host "==> $t (container)" -ForegroundColor Cyan
  docker run --rm -v "${proj}:C:\app" $image nim c -r --hints:off --colors:off -d:chapulinTest "tests\$t.nim"
  if ($LASTEXITCODE -ne 0) { $failed += $t }
}

if ($failed.Count -gt 0) {
  Write-Host "FAILED: $($failed -join ', ')" -ForegroundColor Red
  exit 1
}
Write-Host "All test files passed." -ForegroundColor Green
