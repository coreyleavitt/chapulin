## Corpus minimization + size ceiling + provenance tagging + the
## C1-deferred replay-and-reassert safety net (RFC
## verification-harness-v2.md §3.3/§5, slice C4). Test-tooling only, no
## `src/` changes. Fast + fully deterministic (no z3, no Docker-side
## randomness beyond fixed-seed proptest calls, no wall-clock) --
## registered in `scripts/dev-test.ps1`'s default `$tests` array.
##
## See `corpusmin.nim`'s module doc comment for the two source-verified
## findings this slice is built around: (1) `minimalCovering` (fuzz.nim:337)
## carries no `*` and cannot be called directly -- the only reachable door
## is `FuzzSettings.minimizeCorpus*`; (2) that door only computes real
## per-entry `Coverage` for entries discovered DURING that call, not for
## preloaded seeds -- so the deterministic proof below cross-checks against
## the run's OWN `coverageHits` (the same admitted-edge universe
## `minimalCovering`'s greedy pass draws from), not against an independently
## recomputed coverage of the pre-minimization set (which would include a
## "first mystery seed" blind spot fuzz() itself never resolves either).
##
## Run:
##   pwsh scripts/dev-test.ps1 -Only @('t_corpus_minimize')

import std/[unittest, os, tables]
import nelli
import nelli/choice
import nelli/datasource
import ./fuzzsupport
import ./corpusmin
import ./soakrunner        # soakCorpusTaggedId / soakCrashTaggedId (C1 convention, reused)
import ./interopcapture    # interopCaptureTaggedId / interopCaptureUnverifiedTaggedId (C3, reused)
import ./soakseeds         # allDictionarySeeds / encodeByteSeqIR (C2, reused)
import ./soak_decode       # decodeProp* -- the EXACT oracle C1's soak already fuzzes, reused verbatim

# --- Synthetic under-covered target (RFC C5's own sanctioned pattern,
# invoked here one slice early): a real converged corpus can legitimately
# add/preserve coverage in ways that are hard to pin to an exact number
# deterministically; a synthetic target with a small, fully-known branch
# set gives an exact, reproducible "shrinks + preserves coverage" bar
# instead of an approximate one. -------------------------------------------

proc syntheticBranchy(x: int): int {.cover.} =
  if x < 0: result = 0
  elif x == 0: result = 1
  elif x < 10: result = 2
  elif x < 100: result = 3
  else: result = 4

proc syntheticProp(x: int) =
  discard syntheticBranchy(x)

const
  SyntheticSeed = 0xC4_5EED'u64
  SyntheticIterations = 3000

suite "C4: minimalCovering minimization pass, via the real (only-reachable) front door":

  test "shrinks a redundant discovered corpus while EXACTLY preserving the campaign's own covered-edge total":
    let strat = integers(-5, 150)
    let baseline = fuzzWith(strat, syntheticProp, FuzzSettings(
      maxIterations: SyntheticIterations, mutationMode: fmIR, seed: SyntheticSeed))
    check baseline.irCrashes.len == 0
    let unminimized = baseline.corpus.irEntries
    checkpoint("unminimized entries: " & $unminimized.len &
               ", campaign coverageHits: " & $baseline.coverageHits)
    check unminimized.len > 1        # anti-vacuity: something to minimize at all
    check baseline.coverageHits > 0  # anti-vacuity: the campaign covered something

    # Same seed + same maxIterations + same (empty) seed corpus -> the
    # mutation loop inside `minimizeGrownCorpus`'s own `fuzzWith` call
    # retraces `baseline`'s exact random walk (the `minimizeCorpus` flag is
    # only consulted AFTER the loop completes, fuzz.nim ~456-459) --
    # `minimized` is therefore a genuine reduction of THIS SAME discovered
    # set, not a differently-explored one.
    let minimized = minimizeGrownCorpus(strat, syntheticProp, @[], SyntheticSeed, SyntheticIterations)
    checkpoint("minimized entries: " & $minimized.len)

    check minimized.len < unminimized.len
    for e in minimized:
      check e in unminimized         # a genuine SUBSET, not fabricated entries

    # Independently recompute (via ONLY exported APIs -- `inProcessTarget`/
    # `Observation.coverage`, never proptest's own internal bookkeeping)
    # the edge-set the MINIMIZED set alone reaches, and assert it equals
    # the full campaign's covered-edge total exactly -- proving no edge was
    # lost, from OUTSIDE the mechanism being verified.
    let recomputed = unionCoverageOf(strat, syntheticProp, minimized)
    check coveredEdgeCount(recomputed) > 0
    check coveredEdgeCount(recomputed) == baseline.coverageHits

suite "C4: per-target corpus size ceiling":

  test "withinSizeCeiling: db.save's own maxEntries cap enforces the ceiling":
    let tmpDir = getTempDir() / "chapulin_corpusmin_ceiling"
    removeDir(tmpDir)
    let db = directoryBasedDatabase(tmpDir)
    let testId = "t_corpus_minimize.ceiling-fixture"
    for i in 0 ..< (CorpusSizeCeiling + 5):
      db.save(testId, @[integerChoice(i, 0, 1000, 0)], maxEntries = CorpusSizeCeiling)
    check db.loadPrimary(testId).len == CorpusSizeCeiling
    check withinSizeCeiling(db, testId)
    removeDir(tmpDir)

  test "every committed soak/soak-crash corpus file in tests/corpus stays within the ceiling":
    ## 0.3.1 modernization: soak-crash entries and soak-grown coverage seeds
    ## no longer live in separate `.soak-corpus`/`.soak-crash` testId-suffix
    ## files -- coverage growth lives in the plain testId's own never-pruned
    ## `corpus` section (F1), and crash witnesses live in that SAME testId's
    ## `primary` section (F6-tagged, alongside any `fuzzProperty` witness),
    ## via `FuzzSettings.database`/`persistKey`. `sectionSizes` (F8,
    ## RFC-chapulin-hardening) is the real API for a per-section entry count.
    let db = directoryBasedDatabase(CorpusDir)
    let decodeSizes = db.sectionSizes("protocol.decode")
    checkpoint("protocol.decode: primary=" & $decodeSizes.primary &
               " secondary=" & $decodeSizes.secondary & " corpus=" & $decodeSizes.corpus)
    check decodeSizes.primary <= CorpusSizeCeiling
    check decodeSizes.corpus <= CorpusSizeCeiling
    let canarySizes = db.sectionSizes("soak.canary")
    checkpoint("soak.canary: primary=" & $canarySizes.primary &
               " secondary=" & $canarySizes.secondary & " corpus=" & $canarySizes.corpus)
    check canarySizes.primary <= CorpusSizeCeiling

suite "C4: provenance tagging (per-entry source + campaign date)":

  test "tagProvenance/loadProvenance round-trips source + campaignEpochDay per entry":
    let tmpDir = getTempDir() / "chapulin_corpusmin_provenance"
    removeDir(tmpDir)
    let db = directoryBasedDatabase(tmpDir)
    let testId = "t_corpus_minimize.provenance-fixture"
    let entries = @[
      @[integerChoice(1, 0, 10, 0)],
      @[integerChoice(2, 0, 10, 0)],
    ]
    tagProvenance(db, testId, entries, csSoak, 20648.0)
    let reloaded = loadProvenance(db, testId)
    check reloaded.len == entries.len
    for entry in reloaded:
      check entry.choices in entries
      check sourceFromTag(entry.scores["source"]) == csSoak
      check entry.scores["campaignEpochDay"] == 20648.0
    removeDir(tmpDir)

  test "distinct provenance sources round-trip distinctly (verified vs unverified interop-capture)":
    let tmpDir = getTempDir() / "chapulin_corpusmin_provenance_sources"
    removeDir(tmpDir)
    let db = directoryBasedDatabase(tmpDir)
    let verifiedId = "t_corpus_minimize.src-fixture"
    let unverifiedId = verifiedId & "-unverified"
    tagProvenance(db, verifiedId, @[@[integerChoice(7, 0, 10, 0)]], csInteropCapture, 1.0)
    tagProvenance(db, unverifiedId, @[@[integerChoice(8, 0, 10, 0)]], csInteropCaptureUnverified, 2.0)
    check sourceFromTag(loadProvenance(db, verifiedId)[0].scores["source"]) == csInteropCapture
    check sourceFromTag(loadProvenance(db, unverifiedId)[0].scores["source"]) == csInteropCaptureUnverified
    removeDir(tmpDir)

suite "C4: replay-and-reassert -- the C1-deferred default-suite safety net":
  ## C1's own doc comment explicitly deferred "automated default-suite
  ## replay-and-re-assert of the soak corpus" to C4. This suite is that
  ## deliverable: reload every committed soak/interop-capture corpus entry
  ## (plus the C2 dictionary, re-derived identically every run since it was
  ## never committed as files to begin with) and re-assert each one still
  ## replays cleanly (a valid seed for `byteSeqs()`, and the same
  ## `decodeProp` oracle C1's soak already fuzzes raises nothing) through
  ## its target strategy+property -- closing the loop C1 left open.

  test "protocol.decode: every committed corpus-section entry replays cleanly":
    ## 0.3.1 modernization: soak-grown coverage seeds live in
    ## `protocol.decode.bin`'s own never-pruned `corpus` section (F1) now,
    ## not a sibling `.soak-corpus` file -- see `soakrunner.nim`'s doc
    ## comment.
    let db = directoryBasedDatabase(CorpusDir)
    let entries = db.loadCorpus("protocol.decode")
    check entries.len > 0   # anti-vacuity: this corpus really is non-empty in the committed tree
    for i, e in entries:
      checkpoint("corpus-section entry " & $i)
      check replaysCleanly(byteSeqs(), decodeProp, e)

  test "protocol.decode: every committed soak-crash entry is at least a valid, replayable seed":
    ## Soak-crash entries are KNOWN Defect-triggering inputs by definition
    ## (that's what they demonstrate) -- re-asserting "no crash" on them
    ## would contradict their own purpose, so this checks only the "valid
    ## seed" half (replays through the strategy without
    ## `Rejection`/`Overrun`), proving the committed crash reproducer itself
    ## hasn't bit-rotted into an unreplayable file.
    ##
    ## 0.3.1 modernization: soak-crash entries now live in the testId's
    ## OWN `primary` section (F6-tagged via `soakCrashEntries`, alongside
    ## any `fuzzProperty` witness sharing that section), not a sibling
    ## `.soak-crash` file -- see `soakrunner.nim`'s doc comment. Scoped to
    ## `protocol.decode`'s OWN soak-crash-tagged entries only --
    ## `soak.canary`'s are a DIFFERENT target's crash corpus
    ## (`soak_canary.nim`'s `integers(0, 100)` strategy, not `byteSeqs()`);
    ## replaying them through the wrong strategy is an apples-to-oranges
    ## mismatch, not a real replayability check, confirmed empirically (RED
    ## for the right reason: a first cut of this test included it and
    ## failed with `Overrun` -- `strategy.nim`'s `drawBoolean` expecting a
    ## `ckBoolean` where the `integers`-recorded IR's first node is a
    ## `ckInteger` -- the correct fix is scoping the check to the matching
    ## target, not loosening it).
    let db = directoryBasedDatabase(CorpusDir)
    let entries = soakCrashEntries(db, "protocol.decode")
    checkpoint("protocol.decode soak-crash-tagged entries: " & $entries.len)
    for i, e in entries:
      checkpoint("protocol.decode soak-crash entry " & $i)
      var ds = newReplaySource(e)
      discard byteSeqs().generate(ds)  # raises on Rejection/Overrun -- fails the test if so

  test "protocol.decode: the full C2 seed dictionary replays cleanly":
    ## Not loaded from `tests/corpus` (the dictionary was never committed as
    ## files -- `soakseeds.nim`'s builders regenerate it identically every
    ## run), but the exact same "reload + re-assert" spirit for the
    ## dictionary half of C1's deferred item.
    let seeds = allDictionarySeeds()
    check seeds.len > 0
    for seed in seeds:
      checkpoint("dictionary seed: " & seed.id)
      check replaysCleanly(byteSeqs(), decodeProp, encodeByteSeqIR(seed.bytes))

  test "protocol.decode: any committed interop-capture entries replay cleanly":
    ## Honest, documented gap (not silently hidden): C3's own handoff
    ## records that a live capture could not be exercised in this
    ## Windows-containers-only Docker environment, so zero real
    ## interop-capture entries are committed to `tests/corpus` yet -- both
    ## loops below are correctly vacuous today (0 entries, 0 assertions,
    ## no false failure) and become real checks the moment a genuine
    ## harvest (`interopcapture.nim`'s manual `when isMainModule` entry
    ## point) is ever run and committed.
    let db = directoryBasedDatabase(CorpusDir)
    for testId in [interopCaptureTaggedId("protocol.decode"),
                   interopCaptureUnverifiedTaggedId("protocol.decode")]:
      let entries = db.loadPrimary(testId)
      checkpoint(testId & ": " & $entries.len & " entries")
      for i, e in entries:
        checkpoint(testId & " entry " & $i)
        check replaysCleanly(byteSeqs(), decodeProp, e)
