# Resolve deps on the host with milpa, then run the test suite inside the nim
# devtools container. nim is intentionally NOT installed on the host.
#
#   - milpa (host): clones deps into _deps/ as relative symlinks into a
#     content-addressed store and emits nim.cfg. MILPA_CACHE_DIR is pinned
#     inside the project so the symlinks stay within the tree and a single
#     `-v <proj>:C:\app` bind mount resolves them in the container.
#   - nim (container): compiles+runs each test, reading milpa's nim.cfg.
#
# Usage:  pwsh scripts/dev-test.ps1                              # whole suite
#         pwsh scripts/dev-test.ps1 t_props                      # one file (without .nim)
#         pwsh scripts/dev-test.ps1 -Only @('t_props','t_hostile')  # subset -- ARRAY form
#
# Note: `-Only` is [string[]]. Pass a subset as an array (`@('a','b')`), NOT a
# bare comma string `-Only "a,b"` (binds as ONE element -> a nonexistent suite)
# and NOT space-separated `-Only a b` (the second value misbinds to -Image). The
# guard below recovers the comma-string case; the space case can't be recovered
# positionally, so it's documented, not caught.

param([string[]]$Only, [string]$Image)

$ErrorActionPreference = "Stop"

# R1-10: recover the comma-joined-string footgun (`-Only "t_a,t_b"`) by splitting
# it back into real suite names, rather than silently running a suite that doesn't exist.
if ($Only -and $Only.Count -eq 1 -and $Only[0] -match ',') { $Only = $Only[0] -split ',' }
$proj  = Split-Path -Parent $PSScriptRoot
# Default toolchain image, plus a naming convention for the opt-in symex suites:
# any suite prefixed `t_symex` needs the z3-extended image (Dockerfile.symex) and
# auto-selects it, so `pwsh scripts/dev-test.ps1 -Only t_symex_smoke` just works —
# no image to remember, and no per-file map entry to forget when a new t_symex*
# suite is added (a lookup table keyed by exact suite name silently falls back to
# $baseImage for an unlisted suite, producing a cryptic link/compile failure
# instead of an obvious one). `-Image <tag>` forces one image for every suite
# (e.g. testing a new z3/nim build). Precedence: -Image > t_symex* convention > base.
$baseImage  = "ghcr.io/coreyleavitt/nim:2.2.10"
$symexImage = "chapulin-symex:2.2.10"

# Keep the CAS in-tree (absolute path under the project — CWD-independent).
$env:MILPA_CACHE_DIR = Join-Path $proj ".milpa-cache"

Write-Host "==> milpa fetch (host)" -ForegroundColor Cyan
milpa -C $proj fetch
if ($LASTEXITCODE -ne 0) { throw "milpa fetch failed" }

$tests = if ($Only) { $Only } else {
  @("t_protocol", "t_transfer", "t_options", "t_security", "t_server",
    "t_logging", "t_uri", "t_client", "t_api", "t_props", "t_props_transfer",
    "t_props_server", "t_wireharness", "t_session", "t_checksum", "t_netascii",
    "t_blocksource", "t_blocksource_demo", "t_eventqueue", "t_format", "t_corpus", "t_hostile")
}

$failed = @()
foreach ($t in $tests) {
  $img = if ($Image) { $Image } elseif ($t -like "t_symex*") { $symexImage } else { $baseImage }
  Write-Host "==> $t (container: $img)" -ForegroundColor Cyan
  docker run --rm -v "${proj}:C:\app" $img nim c -r --hints:off --colors:off -d:chapulinTest "tests\$t.nim"
  if ($LASTEXITCODE -ne 0) { $failed += $t }
}

if ($failed.Count -gt 0) {
  Write-Host "FAILED: $($failed -join ', ')" -ForegroundColor Red
  exit 1
}
Write-Host "All test files passed." -ForegroundColor Green
