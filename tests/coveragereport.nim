## Coverage-progress signal + `-CorpusReport` verb (RFC
## verification-harness-v2.md §3.3/§5, slice C5). Test-tooling only, no
## `src/` changes.
##
## --- 0.3.1 modernization (proptest maintainer guidance, change #7):
## real source-mapped uncovered-locations report via `uncoveredSources()`
## -------------------------------------------------------------------------
## v1 of this module shipped a re-scoped, coarse VISITED-EDGE COUNT signal
## because, at the time, there was genuinely no reverse map from a bitmap
## slot back to a `file:line:col` — `coverage.nim`'s `{.cover.}` macro
## hashes source location *into* an edge id at compile time
## (`edgeIdFromLineInfo`) and (as far as v1 could see) never recorded the
## inverse. **That map has existed since proptest 0.1.0** (C1,
## RFC-chapulin-hardening): `registerEdgeSource`/`edgeSources`/
## `uncoveredSources` (`coverage.nim`) are a slot -> `file:line:col`
## side-table, populated as a side effect of a `{.cover.}`'d proc's own
## definition executing (so every registered branch location is known at
## module-init time, whether or not it's ever hit) — `uncoveredSources()`
## returns the source locations of every REGISTERED slot whose bitmap byte
## is currently 0 (unhit), in ascending slot order. This module now reports
## THAT — real source lines, not a bare edge count — confirmed present and
## exported by direct read of `_deps/proptest/src/proptest/coverage.nim`
## before relying on it (per the modernization pass's own discipline).
##
## --- Why a dedicated `uncoveredSourcesFor` wrapper, not `inProcessTarget`
## directly --------------------------------------------------------------
## `uncoveredSources()` reads the LIVE per-thread coverage bitmap at call
## time — it is not parameterized over a `Coverage` value the way
## `corpusmin.nim`'s `unionCoverageOf` is. `fuzz.nim`'s `inProcessTarget`
## calls `resetCoverage()` at the START of every single `run()`, which
## would wipe an earlier entry's hits before the next entry's replay —
## fine for computing ONE run's own coverage, wrong for accumulating the
## UNION a whole entry set reaches (what "beforeEntries vs afterEntries"
## needs). `uncoveredSourcesFor` below resets ONCE, replays+runs every
## entry in the set without an intervening reset (so hits accumulate on
## the shared live bitmap exactly like a real corpus-wide fuzz session
## would), then reads `uncoveredSources()` once at the end — a real,
## non-hand-rolled use of the shipped API, not a reimplementation of it.
##
## --- The signal itself: `sourceCoverageDelta` -----------------------------
## Measures the SAME way on both sides (`uncoveredSourcesFor`, called once
## per entry set) so the two location lists are directly comparable.
## `newlyCovered` is the set-difference: locations uncovered by
## `beforeEntries` that are NOT uncovered by `afterEntries` — i.e. genuine
## NEW coverage, named at the source level instead of as an opaque count.
## `expanded` answers "did growing the corpus from `beforeEntries` to
## `afterEntries` newly cover at least one previously-uncovered source
## location?" — the source-mapped analog of v1's `after > before` edge
## count, and strictly more informative (a caller can now see WHICH
## branch newly fired, not just that the count moved).
##
## --- RED-GREEN acceptance test uses a SYNTHETIC target (see
## `t_coverage_report.nim`) -----------------------------------------------
## Asserting real growth against a REAL committed corpus (e.g.
## `protocol.decode`'s own `corpus` section) is non-repeatable: an already-
## fuzzed target's corpus can legitimately leave zero previously-uncovered
## branches for a given seed pair to newly reach. So the default-suite
## acceptance test drives `sourceCoverageDelta` over a synthetic,
## deliberately under-covered target where "adding this seed reaches a
## branch no prior seed reached" is true by construction — now asserted as
## a shrinking, real `seq[string]` of uncovered locations, not merely a
## count delta. The real-target "uncovered sources shrank after a soak"
## claim is a ONE-TIME §7 manual demonstration via the `-CorpusReport` verb
## below — never an automated assertion (the RFC is explicit on this
## point).
##
## --- The `-CorpusReport` verb ------------------------------------------
## `dev-test.ps1 -CorpusReport [<testId>]` runs THIS file's `when
## isMainModule` block via `Invoke-NimContainer -NimArgs <...>` (C0) --
## deliberately NOT one of dev-test.ps1's registered `$tests` suites (a
## differently-shaped invocation, matching C1's `-Soak` precedent: local
## opt-in, own exit code, never touches the suite pass/fail contract).
## Target selection is via an env var (`CHAPULIN_CORPUS_REPORT_TARGET`,
## plumbed through `Invoke-NimContainer -EnvVars` the same way C1's
## `CHAPULIN_SOAK_SECONDS` already is) rather than a program argv, since
## `Invoke-NimContainer`'s `-NimArgs` splices only *before* the compiled
## file path -- there is no seam for a post-file program argument today,
## and env vars are this repo's already-established pattern for threading
## an operator-supplied value into a container run without a recompile.
## Defaults to the one real flagship soak target, `protocol.decode` --
## whose soak-grown coverage corpus lives in that testId's OWN never-pruned
## `corpus` section (F1; see `soakrunner.nim`'s doc comment). Prints ONE
## snapshot per invocation, now real source LOCATIONS (not a bare count);
## "before vs after a campaign" is achieved by running this verb once,
## running `-Soak`, then running this verb again and comparing the two
## printed lists by eye -- exactly the manual §7 demonstration the RFC
## calls for, not something this program diffs itself.

import std/os
import nelli
import nelli/datasource
import ./fuzzsupport
import ./soak_decode

proc uncoveredSourcesFor*[T](s: Strategy[T], prop: proc(x: T),
                             entries: seq[seq[ChoiceNode]]): seq[string] =
  ## Real source-mapped uncovered-locations report (C1, RFC-chapulin-
  ## hardening): replay+run every entry in `entries` against the shared
  ## LIVE coverage bitmap (reset once, up front, so hits accumulate across
  ## the whole set the way a real fuzz session's admissions do -- see the
  ## module doc comment for why this can't reuse `inProcessTarget`
  ## directly), then read `uncoveredSources()` once. An entry that fails to
  ## replay (`Rejection`/`Overrun`) contributes no coverage and is skipped,
  ## matching `unionCoverageOf`'s own "drop what doesn't replay" behavior.
  ## An entry whose oracle raises still gets to run its full REACHED code
  ## path up to the raise before the exception is caught here -- the
  ## registered edges it DID hit on the way still count as covered.
  let prior = currentCoverageMode()
  setCoverageMode(cmRecording)
  resetCoverage()
  for choices in entries:
    var ds = newReplaySource(choices)
    var val: T
    var generated = true
    try:
      val = s.generate(ds)
    except Rejection, Overrun:
      generated = false
    if not generated: continue
    try: prop(val)
    except CatchableError, Defect: discard
  result = uncoveredSources()
  setCoverageMode(prior)

type
  SourceCoverageDelta* = object
    beforeUncovered*: seq[string]
    afterUncovered*: seq[string]

proc newlyCovered*(d: SourceCoverageDelta): seq[string] =
  ## Source locations uncovered by `beforeUncovered` that are no longer
  ## uncovered by `afterUncovered` -- i.e. genuinely NEW coverage, named at
  ## the source level.
  for loc in d.beforeUncovered:
    if loc notin d.afterUncovered: result.add loc

proc expanded*(d: SourceCoverageDelta): bool =
  ## "Did the soak (or seed addition) newly cover at least one previously-
  ## uncovered source location?" -- the source-mapped coverage-progress
  ## signal itself (RFC §3.3, modernized per change #7).
  newlyCovered(d).len > 0

proc sourceCoverageDelta*[T](s: Strategy[T], prop: proc(x: T),
                             beforeEntries, afterEntries: seq[seq[ChoiceNode]]): SourceCoverageDelta =
  ## The coverage-progress signal: uncovered-source-location sets for
  ## `beforeEntries` vs `afterEntries`, both measured via
  ## `uncoveredSourcesFor` (reused verbatim, not re-derived).
  result.beforeUncovered = uncoveredSourcesFor(s, prop, beforeEntries)
  result.afterUncovered = uncoveredSourcesFor(s, prop, afterEntries)

proc committedCorpusUncoveredSources*[T](s: Strategy[T], prop: proc(x: T),
                                         db: ExampleDatabase, testId: string): seq[string] =
  ## Uncovered-source-location report for a target's CURRENT committed
  ## coverage corpus -- a single snapshot (no before/after pair), what
  ## `-CorpusReport` prints per target. Reads `testId`'s own never-pruned
  ## `corpus` section (F1; `FuzzSettings.database`/`persistKey` -- see
  ## `soakrunner.nim`'s doc comment), not a sibling `.soak-corpus` file.
  uncoveredSourcesFor(s, prop, db.loadCorpus(testId))

when isMainModule:
  let target = getEnv("CHAPULIN_CORPUS_REPORT_TARGET", "protocol.decode")
  let db = directoryBasedDatabase(CorpusDir)
  let entryCount = db.loadCorpus(target).len
  let uncovered = committedCorpusUncoveredSources(byteSeqs(), decodeProp, db, target)
  echo "==> corpus report: " & target
  echo "    committed entries  : " & $entryCount
  echo "    uncovered sources  : " & $uncovered.len &
       " registered {.cover.} branch location(s) not yet hit by this corpus"
  for loc in uncovered:
    echo "      - " & loc
  echo "==> to demonstrate coverage GROWTH: run this verb, run -Soak <n>, run this verb again, and compare the two 'uncovered sources' lists by eye -- fewer (or different) uncovered locations is growth; RFC S7 one-time manual demo, not an automated assertion"
