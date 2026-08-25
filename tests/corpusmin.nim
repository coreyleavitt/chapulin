## Corpus minimization + size ceiling + provenance tagging (RFC
## verification-harness-v2.md §3.3/§5, slice C4). Test-tooling only, no
## `src/` changes.
##
## --- Finding #1 (RESOLVED as of nelli 0.5.3): `minimalCovering` is now
## exported -------------------------------------------------------------
## Verified directly against the pinned nelli 0.5.3 source
## (`_deps/nelli/src/nelli/fuzz.nim:368`, milpa's resolved dep tree — see
## `milpa.kdl`'s `dev-deps` pin, `ref="v0.5.3"`): `proc
## minimalCovering*(entries: seq[seq[ChoiceNode]]; covs: seq[Coverage]):
## seq[seq[ChoiceNode]]` now carries the `*` export marker — it IS directly
## callable from chapulin test code. (An earlier pin had this
## module-private to nelli's own `fuzz.nim`; that is no longer the case.)
## `minimizeGrownCorpus` below still goes through the exported
## `FuzzSettings.minimizeCorpus*: bool` front door rather than calling
## `minimalCovering*` directly — see "Current implementation note" below for
## why that is now a convenience choice, not a structural necessity.
##
## --- Finding #2 (RESOLVED as of nelli 0.5.3): the front door now replays
## preloaded seeds for real coverage before minimizing -----------------------
## Traced through `fuzz()`'s own body (`fuzz.nim` ~459-520, tagged `F2` in
## the nelli source, "RFC-chapulin-hardening ~line 632"): after preloaded
## seeds are assembled into `corpus`, an up-front pass replays EACH ONE
## through the exact same replay→generate→target.run path the mutation loop
## uses per iteration, records the resulting `Coverage` into `corpusCov[i]`,
## and folds it into `frontier.admit` so a preloaded seed's coverage is
## indistinguishable from coverage discovered in-session. Consequence:
## `minimalCovering(choices, corpusCov)` CAN now select a preloaded seed on
## its own merits — this is no longer "reduce THIS campaign's own fresh
## in-session discoveries to a covering subset." The front door's real,
## source-verified semantics as of 0.5.3: "take my already-known corpus
## (preloaded via `initialIRCorpus`/`settings.database.loadPrimary`) and
## losslessly reduce it to a minimal covering subset, using coverage
## computed for every entry — preloaded or freshly discovered during the
## run — not merely the latter."
##
## --- Current implementation note ---------------------------------------
## `minimizeGrownCorpus` below still seeds a bounded, fully DETERMINISTIC
## (`maxIterations`, never `timeBudget` — no wall-clock race under
## container jitter, unlike `-Soak`, which legitimately wants wall-clock)
## `fuzzWith` call from a target's already-grown corpus and turns
## `minimizeCorpus` on, rather than calling `minimalCovering*` directly.
## With both findings above resolved upstream, this is no longer a
## workaround for an unreachable symbol or a lossy front door — the front
## door now performs a genuine, lossless reduction over a
## preloaded/externally-curated corpus, using each entry's own real
## coverage, exactly as a direct `minimalCovering*` call would. The front
## door is still the simpler choice: it also handles the seed-replay/
## frontier-admission bookkeeping described in Finding #2, which a bare
## `minimalCovering*` call would otherwise have to reimplement by hand.
## `unionCoverageOf` (below) still independently re-verifies, via ONLY
## exported nelli APIs (`inProcessTarget`, `Observation.coverage`), that a
## set's covered-edge union is what it is — computed OUTSIDE `fuzz()`'s own
## internal bookkeeping, so "preserves coverage" isn't trusted from the
## mechanism being verified.
##
## Both gaps were originally filed as a nelli ticket (Corey-owned repo, same
## convention as the `symexAssume`/2-arg-`shrink`-overload findings from
## B1/B2/C1): export `minimalCovering*`, and have `fuzz()` run an up-front
## coverage replay pass over preloaded seeds. Both landed in nelli 0.5.3
## (see `docs/proptest-findings.md` for the per-pin re-evaluation). This
## module's doc comment previously described the pre-fix (pre-0.5.3) state;
## corrected here against the pinned source, not re-derived from the RFC's
## prose.
##
## --- Provenance tagging (RFC C4/C6) -----------------------------------
## The primary section (`db.nim`'s `DbContents.primary`) is a bare
## `seq[seq[ChoiceNode]]` — no per-entry metadata slot at all. The
## SECONDARY section's `ScoredEntry = tuple[choices, score, scores:
## Table[string, float]]` (`db.nim`, `saveSecondary`/`loadSecondary`) is
## the one EXPORTED per-entry metadata channel proptest actually has —
## reused here (not a new hand-rolled file format) to extend the
## `osTaggedId`/`.soak-corpus`/`.interop-capture` testId-suffix convention
## (C1/C3, which segregates by FILE/channel) down to PER-ENTRY origin
## (source + campaign date), so a later-failing entry within a channel is
## still triageable. `campaignEpochDay` is always CALLER-supplied — this
## module makes no wall-clock call (`times.now`/`epochTime`) internally;
## per the task's own constraint, a real campaign run threads its own date
## through explicitly, the same way `-Soak`'s env-var convention threads
## its time budget through rather than reading a clock internally.

import std/tables
import nelli
import nelli/datasource
import ./fuzzsupport

type
  CampaignSource* = enum
    ## Provenance origin, mirroring (numerically, for the float-valued
    ## `ScoredEntry.scores` table) the existing testId-suffix channels
    ## (C1's `.soak-corpus`/`.soak-crash`, C3's
    ## `.interop-capture`/`.interop-capture-unverified`) plus the plain
    ## fixed-seed-default channel `fuzzProperty` itself owns.
    csFixedSeedDefault
    csSoak
    csInteropCapture
    csInteropCaptureUnverified

proc sourceTag*(src: CampaignSource): float = float(ord(src))
proc sourceFromTag*(tag: float): CampaignSource = CampaignSource(int(tag))

proc minimizeGrownCorpus*[T](s: Strategy[T], prop: proc(x: T),
                             seedEntries: seq[seq[ChoiceNode]],
                             seed: uint64, maxIterations: int): seq[seq[ChoiceNode]] =
  ## The real `minimizeCorpus` front door (see module doc comment's "Current
  ## implementation note" for why this, not a direct `minimalCovering*`
  ## call, is still used even though nelli 0.5.3 now exports it). Fully
  ## deterministic: `maxIterations` gates the loop; `timeBudget`
  ## is left at its zero-value ("no wall-clock cap"), so the SAME
  ## `(seedEntries, seed, maxIterations)` triple always retraces the exact
  ## same mutation path, in Docker or anywhere else.
  doAssert maxIterations > 0, "minimizeGrownCorpus needs a positive, deterministic maxIterations (never a wall-clock timeBudget)"
  let settings = FuzzSettings(
    maxIterations: maxIterations,
    mutationMode: fmIR,
    initialIRCorpus: seedEntries,
    minimizeCorpus: true,
    seed: seed)
  let report = fuzzWith(s, prop, settings)
  doAssert report.irCrashes.len == 0,
    "minimizeGrownCorpus: the campaign hit a Defect/crash mid-minimization -- " &
    "investigate before minimizing (crash: " &
    (if report.irCrashes.len > 0: report.irCrashes[0].message else: "") & ")"
  report.corpus.irEntries

proc unionCoverageOf*[T](s: Strategy[T], prop: proc(x: T),
                        entries: seq[seq[ChoiceNode]]): Coverage =
  ## Independently recompute the total edge-set `entries` reaches, entirely
  ## via EXPORTED proptest APIs (`inProcessTarget`, `Observation.coverage`)
  ## — so "the minimized set still covers what the pre-minimization set
  ## covered" is proven OUTSIDE the mechanism being verified (`fuzz()`'s own
  ## internal `corpusCov`/`minimalCovering` bookkeeping), not merely trusted
  ## from it. Entries that fail to replay (structurally invalid IR for this
  ## strategy — `Rejection`/`Overrun`) contribute no coverage and are
  ## skipped, matching `captureIR`'s own "drop what doesn't replay"
  ## behavior rather than raising.
  let target = inProcessTarget(prop)
  result = Coverage(counters: newSeq[uint8](coverageEdgeCount))
  for choices in entries:
    var ds = newReplaySource(choices)
    var val: T
    try:
      val = s.generate(ds)
    except Rejection, Overrun:
      continue
    let obs = target.run(val)
    for i in 0 ..< obs.coverage.counters.len:
      if obs.coverage.counters[i] > 0'u8:
        result.counters[i] = 1'u8

proc coveredEdgeCount*(c: Coverage): int =
  ## Number of distinct hit slots in an (independently-recomputed) `Coverage`
  ## — the same notion `currentCoverage()`/`coverageHits` report, but over a
  ## caller-supplied bitmap rather than the live per-thread one.
  result = 0
  for b in c.counters:
    if b > 0'u8: inc result

proc replaysCleanly*[T](s: Strategy[T], oracle: proc(x: T),
                       choices: seq[ChoiceNode]): bool =
  ## The C1-deferred replay-and-reassert primitive: "valid seed" (the IR
  ## replays through the strategy without `Rejection`/`Overrun` — the same
  ## failure mode `captureIR`/`fuzz()`'s own seeding silently drops seeds
  ## for) AND "no crash" (the oracle proc raises nothing at all escaping
  ## it). Every soak/dictionary/capture oracle in this repo (e.g.
  ## `soak_decode.nim`'s `decodeProp`) already swallows its one ALLOWED
  ## exception internally and lets anything else (a Defect, or an
  ## unexpected exception) propagate — so "oracle raised nothing" here is
  ## exactly "replayed cleanly," matching the target's own never-throw
  ## contract.
  var ds = newReplaySource(choices)
  var val: T
  try:
    val = s.generate(ds)
  except Rejection, Overrun:
    return false
  try:
    oracle(val)
  except CatchableError, Defect:
    return false
  true

proc tagProvenance*(db: ExampleDatabase, testId: string,
                    entries: seq[seq[ChoiceNode]], source: CampaignSource,
                    campaignEpochDay: float, maxEntries = CorpusSizeCeiling) =
  ## Attach per-entry provenance (source + campaign date) to `entries` via
  ## the secondary section's `scores` sidecar (see module doc comment for
  ## why this channel, not a new file format). `campaignEpochDay` is always
  ## caller-supplied (no internal clock call — see module doc comment).
  var scored: seq[ScoredEntry]
  for e in entries:
    var scores = initTable[string, float]()
    scores["source"] = sourceTag(source)
    scores["campaignEpochDay"] = campaignEpochDay
    scored.add (choices: e, score: 0.0, scores: scores)
  db.saveSecondary(testId, scored, maxEntries)

proc loadProvenance*(db: ExampleDatabase, testId: string): seq[ScoredEntry] =
  ## Reload the provenance sidecar `tagProvenance` wrote — for triage
  ## ("which campaign/date produced this entry?") or for a round-trip test.
  db.loadSecondary(testId)

proc withinSizeCeiling*(db: ExampleDatabase, testId: string,
                       ceiling = CorpusSizeCeiling): bool =
  ## RFC §3.3 "per-target corpus size ceiling": the committed primary
  ## corpus for `testId` must not silently grow past `ceiling` (replay
  ## time scales with corpus size — the fast default's own wall-clock
  ## budget depends on this staying bounded).
  db.loadPrimary(testId).len <= ceiling
