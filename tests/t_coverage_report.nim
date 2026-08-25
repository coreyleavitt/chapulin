## C5 coverage-progress signal: RED-GREEN acceptance test using a
## SYNTHETIC under-covered target (RFC verification-harness-v2.md §3.3/§5,
## slice C5). Registered in `scripts/dev-test.ps1`'s default `$tests` —
## fast, fully deterministic (fixed IR seeds, no fuzzing/mutation, no
## wall-clock, no z3), same judgment call `t_corpus_minimize.nim`/
## `t_soak_encoder.nim` already recorded for this kind of suite.
##
## 0.3.1 modernization (change #7): the signal under test is now a REAL
## source-mapped uncovered-locations report (`uncoveredSources()`, C1
## RFC-chapulin-hardening — confirmed present since proptest 0.1.0), not a
## coarse before/after edge COUNT. Per the RFC's own explicit instruction
## (§3.3/§7, restated in the C5 slice description): asserting growth
## against a REAL committed corpus (`protocol.decode`'s own `corpus`
## section) is NON-repeatable — an already-fuzzed target can legitimately
## leave zero previously-uncovered branches for a given seed pair to newly
## reach. This suite instead uses a SYNTHETIC, deliberately under-covered
## target (own local copy, not `t_corpus_minimize.nim`'s `syntheticBranchy`
## — kept independent so this suite's under-coverage story is
## self-contained and never silently drifts if that other file's fixture
## changes) where "this seed reaches a branch no prior seed reached" is
## true by construction, and where every registered branch location is
## known and fixed (this file's own line numbers), so asserting on the
## real returned `seq[string]` stays deterministic.

import std/[unittest, strutils]
import nelli
import nelli/choice
import ./coveragereport

# A deliberately under-covered synthetic target: an if/elif/elif/elif/else
# chain over an int, `{.cover.}`-instrumented (imports `proptest` directly,
# so `cover` is the REAL AST-rewriting macro unconditionally here — this is
# a test-only fixture, not a `src/` proc, so it doesn't need
# `coverpragma.nim`'s define-gated shim). Any single call traverses exactly
# ONE arm of the chain, so each NEW seed value in a genuinely-unexercised
# range provably adds exactly one new registered source location to the
# covered set.
proc syntheticUnderCovered(x: int): int {.cover.} =
  if x < 0: result = 0
  elif x == 0: result = 1
  elif x < 10: result = 2
  elif x < 100: result = 3
  else: result = 4

proc syntheticUnderCoveredProp(x: int) =
  discard syntheticUnderCovered(x)

suite "C5: coverage-progress signal -- synthetic under-covered target (RED-GREEN)":

  test "adding a coverage-expanding seed provably shrinks the real uncovered-source-location set":
    let strat = integers(-5, 150)

    # BEFORE: a deliberately narrow seed set exercising only the FIRST TWO
    # arms of the chain (x < 0, x == 0) -- under-covered by construction,
    # not by chance or an unlucky fuzz run.
    let before = @[
      @[integerChoice(-3, -5, 150, 0)],   # hits "x < 0"
      @[integerChoice(0, -5, 150, 0)],    # hits "x == 0"
    ]

    # AFTER: the same seeds PLUS one seed reaching an arm no `before` seed
    # reaches (x == 50 falls into "x < 100", never hit above).
    let after = before & @[
      @[integerChoice(50, -5, 150, 0)],   # hits "x < 100" -- a NEW source location
    ]

    let delta = sourceCoverageDelta(strat, syntheticUnderCoveredProp, before, after)
    checkpoint("beforeUncovered=" & $delta.beforeUncovered)
    checkpoint("afterUncovered=" & $delta.afterUncovered)

    # `uncoveredSources()` reports over the WHOLE binary's registered
    # `{.cover.}` sites, not just this file's synthetic proc -- this file
    # transitively imports `coveragereport.nim` -> `soak_decode.nim` ->
    # `src/chapulin/protocol.nim`, whose OWN `{.cover.}` sites (active
    # under `-d:chapulinFuzz`, tests-wide via `tests/nim.cfg`) register
    # into the SAME shared table. Neither `before` nor `after` ever runs
    # `protocol.decode`, so protocol.nim's branch locations are equally
    # unhit (equally present) in BOTH sides and cancel out of the diff --
    # asserting an absolute uncovered COUNT would be coupled to
    # protocol.nim's own unrelated branch count; asserting the RELATIVE
    # shrink (exactly one arm flipped) is what stays deterministic and
    # true to just this fixture.
    check delta.beforeUncovered.len == delta.afterUncovered.len + 1

    let gained = newlyCovered(delta)
    check gained.len == 1   # exactly the "x < 100" arm's location
    # Genuinely source-mapped, not a placeholder string: the one newly-
    # covered location names THIS file (proving `uncoveredSources()` really
    # returned a `file:line:col`, not a synthetic stand-in).
    check "t_coverage_report.nim" in gained[0]
    check expanded(delta)   # the coverage-progress signal itself

  test "an unchanged corpus (before == after) does NOT falsely report expansion":
    ## Anti-vacuity for the signal itself: a no-op "campaign" (same entries
    ## on both sides) must report `expanded == false`, or the signal would
    ## be meaningless noise that always says "grew."
    let strat = integers(-5, 150)
    let same = @[@[integerChoice(-3, -5, 150, 0)]]
    let delta = sourceCoverageDelta(strat, syntheticUnderCoveredProp, same, same)
    check delta.beforeUncovered == delta.afterUncovered
    check newlyCovered(delta).len == 0
    check not expanded(delta)
