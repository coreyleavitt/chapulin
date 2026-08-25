# Resolve deps on the host with milpa, then run the test suite inside the nim
# devtools container. nim is intentionally NOT installed on the host.
#
#   - milpa (host): clones deps into _deps/ as relative symlinks into a
#     content-addressed store and emits nim.cfg. MILPA_CACHE_DIR is pinned
#     inside the project so the symlinks stay within the tree and a single
#     `-v <proj>:C:\app` bind mount resolves them in the container.
#   - nim (container): compiles+runs each test, reading milpa's nim.cfg.
#
# The milpa-fetch/mount/image-selection scaffolding lives in the sourced
# helper `scripts/lib/nimcontainer.ps1` (`Invoke-NimContainer`) so the future
# `-Soak` mode and `-CorpusReport` verb can reuse it without duplicating it or
# overloading THIS script's own contract (compile+run named suites, exit a
# failure list) -- see docs/rfc/verification-harness-v2.md §3.3/§5 (slice C0).
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

param([string[]]$Only, [string]$Image, [int]$Soak, [switch]$CorpusReport, [string]$CorpusReportTarget)

$ErrorActionPreference = "Stop"

# R1-10: recover the comma-joined-string footgun (`-Only "t_a,t_b"`) by splitting
# it back into real suite names, rather than silently running a suite that doesn't exist.
if ($Only -and $Only.Count -eq 1 -and $Only[0] -match ',') { $Only = $Only[0] -split ',' }
$proj  = Split-Path -Parent $PSScriptRoot

. (Join-Path $PSScriptRoot "lib/nimcontainer.ps1")

# -Soak: RFC verification-harness-v2.md §3.3/§5, slice C1. A DISTINCT mode,
# not a suite in $tests below -- runs ONE long-lived coverage-guided
# `fuzzWith` campaign (tests/soak_decode.nim) instead of the fast
# fixed-seed/FuzzN suites, so it must never share this script's
# compile+run-named-suites/exit-a-failure-list contract (C0's own
# rationale for extracting Invoke-NimContainer in the first place). Reuses
# the SAME helper, just with the extra `-e CHAPULIN_SOAK_SECONDS=<n>` the
# helper's `-EnvVars` param exists for -- no milpa-fetch/mount/image
# scaffolding is re-derived here. Local-opt-in ONLY: never invoked unless
# `-Soak` is explicitly passed a positive duration, so the default
# `pwsh scripts/dev-test.ps1` (no -Soak) is completely unaffected -- this
# whole block is skipped, falling through to the unchanged suite loop.
if ($Soak -gt 0) {
  Write-Host "==> Soak mode: tests/soak_decode.nim for ${Soak}s (CHAPULIN_SOAK_SECONDS)" -ForegroundColor Cyan
  $exitCode = Invoke-NimContainer -ProjectRoot $proj -NimFile "tests\soak_decode.nim" -Image $Image `
    -EnvVars @{ CHAPULIN_SOAK_SECONDS = "$Soak" }
  exit $exitCode
}

# -CorpusReport: RFC verification-harness-v2.md §3.3/§5, slice C5. A
# DISTINCT mode, not a suite in $tests below -- runs the coverage-progress
# report program (tests/coveragereport.nim's `when isMainModule` block)
# instead of the fast fixed-seed/FuzzN suites, so -- same rationale as
# -Soak above -- it must never share this script's
# compile+run-named-suites/exit-a-failure-list contract. Reuses the SAME
# helper via the `-NimArgs` param C0 added for exactly this: the
# coverage-report program is not a `-d:chapulinTest` suite (it needs none
# of api.nim's test-observable helpers, C0's own doc comment on
# `-NimArgs` names this future use), so this is a genuinely
# differently-shaped invocation, not merely the default args passed
# explicitly. Target selection threads through `-EnvVars`
# (`CHAPULIN_CORPUS_REPORT_TARGET`) the same way -Soak's
# `CHAPULIN_SOAK_SECONDS` already does -- `Invoke-NimContainer` has no seam
# for a post-file program argument (`-NimArgs` splices only BEFORE the
# compiled file), so an env var is this repo's established pattern here,
# not a new one. Local-opt-in ONLY, like -Soak: never invoked unless the
# `-CorpusReport` SWITCH is explicitly passed, so the default
# `pwsh scripts/dev-test.ps1` is completely unaffected. `-CorpusReportTarget`
# is optional -- when omitted, `tests/coveragereport.nim`'s own default
# (the flagship real soak target, `protocol.decode.soak-corpus`) is used,
# so `-CorpusReport` alone is a complete, useful invocation.
if ($CorpusReport) {
  $envVars = @{}
  if ($CorpusReportTarget) { $envVars['CHAPULIN_CORPUS_REPORT_TARGET'] = $CorpusReportTarget }
  $targetMsg = if ($CorpusReportTarget) { " (target: $CorpusReportTarget)" } else { "" }
  Write-Host "==> Corpus report mode: tests/coveragereport.nim$targetMsg" -ForegroundColor Cyan
  $exitCode = Invoke-NimContainer -ProjectRoot $proj -NimFile "tests\coveragereport.nim" -Image $Image `
    -NimArgs @('c', '-r', '--hints:off', '--colors:off') `
    -EnvVars $envVars
  exit $exitCode
}

$tests = if ($Only) { $Only } else {
  @("t_protocol", "t_transfer", "t_options", "t_security", "t_server",
    "t_logging", "t_uri", "t_client", "t_api", "t_props", "t_props_transfer",
    "t_props_server", "t_wireharness", "t_session", "t_checksum", "t_netascii",
    "t_blocksource", "t_blocksource_demo", "t_eventqueue", "t_format", "t_corpus", "t_hostile",
    "t_pumpsession", "t_asynccheck_tripwire", "t_defect_canary", "t_wireregistry",
    "t_listenerbridge", "t_a1b_smoke", "t_a2_facade_stateful", "t_a4_maxconcurrent",
    "t_soak_encoder", "t_interop_capture", "t_corpus_minimize", "t_coverage_report")
}

$failed = @()
foreach ($t in $tests) {
  $exitCode = Invoke-NimContainer -ProjectRoot $proj -NimFile "tests\$t.nim" -Image $Image
  if ($exitCode -ne 0) { $failed += $t }
}

if ($failed.Count -gt 0) {
  Write-Host "FAILED: $($failed -join ', ')" -ForegroundColor Red
  exit 1
}
Write-Host "All test files passed." -ForegroundColor Green
