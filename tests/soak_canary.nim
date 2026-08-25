## C1 TDD canary (RFC verification-harness-v2.md §3.3, slice C1) — a
## DELIBERATELY-CRASHING synthetic `fuzzWith` target proving `soakrunner`'s
## first-Defect stop/minimize/commit-as-`soak-crash`/exit-non-zero path
## (mirrors `t_defect_canary.nim`'s role for the PBT engine: a permanent,
## cheap, always-reproducible proof of the detection pipeline, distinct
## from any real chapulin Defect class so a failure here can never be
## confused with a genuine `src/` finding).
##
## NOT part of `scripts/dev-test.ps1`'s default `$tests` array and NOT
## wired to `-Soak` (which always targets `./soak_decode.nim`) — run it
## directly:
##   pwsh scripts/dev-test.ps1 -Only @('soak_canary')
##
## With no `CHAPULIN_SOAK_SECONDS` set, `soakrunner.runSoak` takes its
## single-ad-hoc-burst path (~1s native `timeBudget`) — ample, since this
## target raises on its very first generated value, every time.

import nelli
import ./soakrunner

type
  SoakCanaryDefect = object of Defect
    ## Synthetic — never raised by any real chapulin code.

proc canaryProp(x: int) =
  raise newException(SoakCanaryDefect,
    "soak canary: synthetic Defect from a soak target (proves the " &
    "stop/minimize/commit/exit-non-zero path, RFC §3.3)")

when isMainModule:
  let code = runSoak(integers(0, 100), canaryProp, "soak.canary")
  doAssert code == 1, "canary target did not report the expected crash exit code"
  echo "==> canary confirmed: first-Defect stop/minimize/commit/exit-non-zero path is real"
  quit(0)
