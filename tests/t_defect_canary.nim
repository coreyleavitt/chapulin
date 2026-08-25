## StateMachine-routed Defect-canary (RFC verification-harness-v2.md
## A-shared, §3.1/§4). Every never-Defect property in this suite (v1's
## `t_hostile.nim`, v2's future facade stateful target) rests on an
## assumption that is easy to state and easy to get wrong: "if the code
## under test raises a Defect, proptest's engine actually surfaces it as a
## falsification instead of silently losing it." This test proves that
## assumption against the PINNED proptest source, rather than merely citing
## it -- and, in the course of doing so, corrects a claim the RFC itself
## got wrong (documented below, not silently worked around).
##
## --- What the RFC claims, and what the source actually does -------------
##
## `_deps/proptest/src/proptest/engine/eval.nim`'s `evalReplay` (~68-95) has
## TWO `except Defect` arms: one around the strategy's own `s.generate(ds)`
## call (~92-95, message `"strategy crashed: " & ...`), one around the
## later `prop(x)` call (~109-112, message `"crashed: " & ...`, no
## "strategy" prefix). The RFC (architect r2) reads this as "a StateMachine
## target's invariant-Defect always reports via the FIRST arm" and asks
## this canary to assert on the literal substring `"strategy crashed:"`.
##
## That is only TRUE for the replay-shaped phases that actually call
## `evalReplay`: `dbReusePhase` (replaying a persisted corpus entry,
## `engine/phases.nim` ~68, forwards `r.fMsg` verbatim) and
## `explicitExamplesPhase` (pinned `examples ...` values, ~144). It is
## FALSE for `randomPhase` (`engine/phases.nim` ~175-214) -- the phase that
## runs on a FRESH invocation with no persisted DB entry, i.e. exactly this
## canary's own shape. `randomPhase` does NOT call `evalReplay` at all: it
## inlines its own single `try/except Defect` around BOTH `s.generate(ds)`
## and `prop(x)` (lines 197-208) and classifies EITHER site identically as
## `"crashed: " & $e.name & ": " & e.msg` -- no "strategy" distinction, ever.
## `shrinkPhase` (~235-292) calls `evalReplay` again during minimization,
## but only to decide flaky/shrunk *choices* -- it never rewrites
## `rawFalsification.message`, so `finalizePhase` (~362-400) still reports
## the ORIGINAL `randomPhase` message. **The literal substring
## `"strategy crashed:"` therefore never reaches a fresh, non-DB-backed
## `forAll`/`property` run's `Report.message` at all** -- it is real
## behavior, but only on corpus-replay (a SECOND run against an
## already-committed `tests/corpus/*.bin` entry) or explicit examples, not
## on first discovery. Both messages DO always contain the substring
## `"crashed:"` (the RFC's own weaker, always-true observation) -- that
## substantive guarantee ("a Defect is never silently swallowed; it always
## surfaces as SOME falsification") holds unconditionally.
##
## This file proves BOTH halves, honestly:
##   1. `evalReplay` ITSELF -- the exact code the architect's citation is
##      about -- really does classify a StateMachine invariant's Defect via
##      the `"strategy crashed:"` arm (called directly, no `forAll`/DB
##      plumbing in between: the most literal, most future-proof test of
##      the cited mechanism, immune to `randomPhase`/`dbReusePhase` wiring
##      changing independently of `eval.nim`'s own classification logic).
##   2. A committed, ALWAYS-RUN `forAll` property (no DB, matching this
##      canary's own "runs cold every time" nature) proves the WEAKER,
##      universally-true claim that actually matters for detection: the
##      Defect is never swallowed and the report contains `"crashed:"`.
## A2/A3's real properties DO use `fuzzProperty`'s persisted `testId`/
## `dbPath` (matching `t_hostile.nim`'s convention) -- so on any run AFTER
## the first, a genuine escaped Defect they commit to the corpus WILL
## replay via `dbReusePhase` and DOES get the precise `"strategy crashed:"`
## wording; test 1 above is what proves that specific path is real.
##
## ALWAYS RUN (not a bring-up-only manual check): also a re-run acceptance
## gate on any future proptest pin bump (B4 included) -- if an upgrade
## changes `eval.nim`'s classification or `phases.nim`'s message plumbing,
## one of these two tests fails loudly, instead of every OTHER never-Defect
## property in this suite silently losing its detection guarantee with no
## signal.
##
## Deliberately NOT built with the `property`/`fuzzProperty` macros for
## test 2: those macros turn an `otFalsified` report into `check false` (a
## FAILING test), which is exactly backwards here -- falsification-via-
## Defect is this test's PASSING condition. It calls `forAll` directly and
## asserts on the returned `Report[T]`.
##
## Run:
##   pwsh scripts/dev-test.ps1 -Only @('t_defect_canary')

import std/[unittest, strutils]
import nelli

type
  CanaryDefect = object of Defect
    ## Synthetic Defect distinct from any real chapulin Defect class, so a
    ## failure here can never be confused with a genuine src/ finding.

  CanaryState = object

let canarySM = StateMachine[CanaryState](
  initial: just(CanaryState()),
  rules: @[],
  invariant: proc(s: CanaryState) =
    raise newException(CanaryDefect,
      "canary: synthetic Defect raised from inside a StateMachine invariant"))
  ## Raises from the INVARIANT (permitted alongside "a rule" by the RFC),
  ## not a rule: `stateful`'s generation closure calls the invariant once,
  ## unconditionally, on the freshly-built initial state, before the
  ## per-step `drawBoolean(0.9)` continuation gate or any rule selection --
  ## so this fires deterministically on EVERY example, with zero dependence
  ## on the random step count (a rule-based canary would carry a small but
  ## real per-example chance of drawing zero steps and never firing).
  ## `just(...)` also consumes no choices, so replaying it needs an empty
  ## choice sequence (`@[]`, used by test 1 below).

suite "Defect-canary -- StateMachine-routed Defect detection (A-shared)":
  test "evalReplay classifies a StateMachine invariant's Defect as 'strategy crashed:'":
    ## Calls the exact mechanism the RFC/architect cited (eval.nim's
    ## `except Defect` arm around `s.generate(ds)`) directly -- no
    ## `forAll`/phase-selection plumbing in between, so this can't be
    ## accidentally satisfied (or broken) by which PHASE happens to
    ## discover the falsification first.
    var ev: Eval[CanaryState]
    withEngineFrame:
      # `evalReplay` reaches into `currentFrame()` (clearing
      # scores/notes) even outside a full `forAll` run -- `withEngineFrame`
      # (proptest/engine/frame.nim) is the same push/pop `forAll` itself
      # does, borrowed directly rather than re-implemented here.
      ev = evalReplay(stateful(canarySM), proc(final: CanaryState) = discard,
                      candidate = newSeq[ChoiceNode]())
    checkpoint("kind: " & $ev.kind)
    checkpoint("fMsg: " & ev.fMsg)
    check ev.kind == ekFalsified
    check "strategy crashed:" in ev.fMsg
    check "CanaryDefect" in ev.fMsg

  test "a fresh, non-DB forAll run never swallows the Defect (reports 'crashed:')":
    ## The universally-true half (holds on `randomPhase`'s coarser
    ## classifier too, not just `evalReplay`'s two-arm split above) -- this
    ## is the guarantee every never-Defect property in this suite actually
    ## depends on: an escaped Defect is ALWAYS reported as SOME
    ## falsification, never silently lost. No `testId`/`dbPath` set (this
    ## canary is never meant to persist a corpus entry -- deliberately
    ## exercises the "no DB, first discovery" `randomPhase` path every
    ## single run, matching its own always-cold nature).
    var settings = defaultSettings()
    settings.maxExamples = 3
    let rep = forAll(stateful(canarySM), proc(final: CanaryState) = discard, settings)
    checkpoint("outcome: " & $rep.outcome)
    checkpoint("message: " & rep.message)
    check rep.outcome == otFalsified
    check "crashed:" in rep.message
    check "CanaryDefect" in rep.message
