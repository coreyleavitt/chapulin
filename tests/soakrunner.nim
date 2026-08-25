## Shared `fuzzWith` `fmIR` soak driver (RFC verification-harness-v2.md
## §3.3, slice C1). One place implements the plumbing every soak target
## needs — env-var-fed native `FuzzSettings.timeBudget`, first-Defect
## stop/minimize/commit/exit-non-zero, and committed-corpus growth via
## `directoryBasedDatabase` — so this slice's `protocol.decode` demo AND any
## future C2+ soak target share ONE proven driver instead of re-deriving it
## per file (mirrors `scripts/lib/nimcontainer.ps1`'s own "factor the shared
## scaffolding once" rationale, C0).
##
## --- Mode = fmIR, not fmBytes (RFC §3.3) ----------------------------------
## `fmIR` is `FuzzSettings.mutationMode`'s zero-value default — set
## explicitly below anyway so the choice is visible, not implicit. `fmIR`
## is the ONLY mode whose corpus is choice-IR (`seq[ChoiceNode]`), so it is
## the only mode this driver can hand `FuzzSettings.database`/`persistKey`
## for directly (confirmed against `fuzz.nim`'s `fuzzWithBytes`/`FuzzCorpus`
## — `fmBytes`' corpus is a disjoint byte-blob format this driver never
## touches).
##
## --- Persistence: real `FuzzSettings.database` + `persistKey` (0.3.1
## modernization — proptest maintainer guidance, replaces a v1 hand-rolled
## `.soak-corpus`/`.soak-crash` testId-suffix channel) ----------------------
## v1 of this driver could not use `fuzz()`'s own built-in persistence
## because of a proptest bug: `fuzzWithIR`'s `CoverageFrontier` always has
## `targetId = ""`, so the auto-derived key `fuzzCorpusKey(persistKey,
## targetId)` was the dangling `"<persistKey>#"` — `db.nim`'s `safeKey`
## escaped that literal `#` into a SURPRISE SIBLING FILE (`…%23.bin`)
## instead of `persistKey`'s own corpus section (see `fuzz.nim`'s
## `fuzzCorpusKey` doc comment, "Post-0.3.0 (chapulin soakrunner finding)").
## **Fixed in 0.3.1**: an empty `targetId` now folds to the bare
## `persistKey`, and the corpus lands in the SAME testId file's dedicated,
## never-pruned `corpus` section (F1, RFC-chapulin-hardening) — safely
## co-resident with a `fuzzProperty` regression channel of the same name,
## because `dbReusePhase` (`engine/phases.nim`) only ever reads/prunes the
## `primary` section, never `corpus`. So this driver now sets
## `FuzzSettings.database`/`persistKey` directly to `testId` (the SAME
## testId an existing `fuzzProperty(testId, ...)` call already uses) and
## lets `fuzz()` do the corpus load-on-start / save-on-admit itself —
## no hand-rolled suffix channel, no manual seed bookkeeping for corpus
## growth.
##
## What this driver still does by hand: seed `initialIRCorpus` from the
## plain testId's PRIMARY section (any REAL regression a `fuzzProperty` has
## separately found and committed there) — `fuzz()`'s automatic seeding
## only ever reads the `corpus` section (`settings.database.loadCorpus`),
## never `primary`, so a known regression witness is a reasonable extra
## mutation seed this driver adds on top, exactly as v1 did. This driver
## never WRITES to `primary` for non-crash purposes, so it cannot trigger
## `dbReusePhase`'s prune-on-pass behavior in the other direction.
##
## --- First-Defect stop/minimize/commit/exit (RFC §3.3 "Failure behavior")-
## 0.3.1 modernization: `FuzzSettings.stopOnFirstCrash*` (F4,
## RFC-chapulin-hardening) now exists and does exactly what v1's hand-rolled
## burst-series loop existed to approximate — halt the coverage-guided loop
## the moment the first NEW (de-duped) crash is recorded, so
## first-Defect-detection latency is bounded by ONE mutation, not by an
## entire burst or the whole requested soak duration. v1 could not use this
## (it didn't exist pre-0.3.1) and instead served the overall requested
## duration as a series of short bounded `fuzzWith` calls, carrying the
## corpus forward via `initialIRCorpus` and checking `report.irCrashes`
## between bursts — collapsed here into the single native call
## `stopOnFirstCrash` makes possible. `report.iterations` reflects the
## early exit when it fires (per `FuzzSettings.stopOnFirstCrash`'s own doc
## comment), not `maxIterations`.
##
## Once a crash is found: `shrink()` (a REAL, non-hand-rolled proptest API
## — `proptest/shrinker.nim:396-427`, confirmed to treat any propagated
## `CatchableError`/`Defect` as "still falsifies", `shrinker.nim:104-115`,
## so it minimizes a Defect-raising choice sequence exactly as it would a
## `FalsifiedError` one) minimizes the triggering sequence; the minimized
## result is committed to the testId's OWN primary section (no separate
## suffix file needed — "crashes belong in the primary section and survive
## replay by construction," per the maintainer's 0.3.1 guidance), tagged
## with per-entry metadata (F6, `save(..., meta)`) so a later reader can
## tell a soak-discovered crash apart from a `fuzzProperty`'s own witnesses
## sharing the same primary section — see `soakCrashMeta`/`soakCrashEntries`
## below. The commit is self-verified (reload + membership-check via
## `soakCrashEntries`), not merely trusted, before the driver exits
## non-zero.
##
## --- Empirically-discovered toolchain blocker (found building this slice,
## catalogued per the B1-B3 precedent, not silently worked around; STILL
## PRESENT as of the 0.3.1 modernization pass -- unrelated to the
## database/persistKey/stopOnFirstCrash changes above, so left as-is) -------
## `shrink(s, prop, choices)`'s convenience 2-arg overload calls
## `defaultShrinkPasses[T]()`, which chains into `lowerIntegerShrinkPass[T]`
## -> `lowerIntegerAt[T]`'s `Int128` binary-search arithmetic
## (`shrinker.nim:270-284`). Called with `T = int` (the canary target,
## `tests/soak_canary.nim`) this compiles and runs cleanly. Called with
## `T = seq[byte]` (the real `protocol.decode` soak target) from THIS
## external module, it fails to compile: `shrinker.nim(274,18) Error: type
## mismatch: one < dist` where BOTH operands are printed as `Int128` by the
## compiler's own diagnostic, and `int128.nim:41`'s `func \`<\`*(a, b:
## Int128): bool` is demonstrably in scope (`import proptest/int128` added
## explicitly; no change) — yet it is absent from the candidate list Nim
## reports. This reproduces only for `T = seq[byte]`, only when the
## generic chain is FIRST instantiated from a module outside proptest's
## own package (a chapulin test file) — i.e. it is not that `<` is
## missing, but that Nim's "open symbol" resolution for this specific
## nested-generic-calling-generic chain (`shrink`->`defaultShrinkPasses`->
## `lowerIntegerShrinkPass`->`lowerIntegerAt`, all defined in the SAME
## proptest module but instantiated from chapulin's) picks up a different,
## incomplete overload set depending on which external `T` triggers the
## first instantiation. Bisected empirically (not guessed): swapping the
## 2-arg `shrink()` call for the 5-arg overload with an EXPLICIT pass list
## that OMITS `lowerIntegerShrinkPass[T]()` — i.e. `deleteSpansShrinkPass[T]()`
## alone — compiles and runs cleanly for `T = seq[byte]`. Applied below.
## Cost, disclosed: minimization for the byte-list soak target shortens the
## crash input (span/element deletion) but does not additionally lower
## each surviving byte's integer value toward 0 the way the full pass
## suite would. A genuine, if partial, minimization capability — not a
## silently-accepted no-op — and worth a proptest ticket (Corey-owned
## repo, same convention as B1/B2's `symexAssume` finding) rather than a
## chapulin-side fix, since the bug lives in `shrinker.nim`'s own generic
## structure, not in anything this driver controls.
##
## --- Primary / secondary / corpus sections (0.3.1 recap) ------------------
## `directoryBasedDatabase`'s one file per testId holds THREE independent
## sections (`db.nim`'s `DbContents`): PRIMARY (`dbReusePhase`,
## `phases.nim:35-56` — known FALSIFYING examples replayed as a regression
## check on every run; `shrinkPhase`, `phases.nim:278`, is what writes it,
## and this driver's own crash-commit path also writes it, tagged via
## metadata), SECONDARY (`targeting.nim:316,371` — the coverage-guided
## hill-climb's scored front, read/written only by `forAll`'s own targeted-
## PBT phase; also reused by `corpusmin.nim`'s provenance tagging), and
## CORPUS (F1 — coverage-guided fuzz seeds; never touched by `dbReusePhase`,
## and now this driver's OWN channel for clean coverage growth via
## `database`/`persistKey`, replacing the old `.soak-corpus` suffix file).
## A target like `protocol.decode` that has never crashed via a soak run
## has an EMPTY set of soak-tagged primary entries even though its `.bin`
## file is non-empty (PBT's own primary/secondary content, populated by
## `t_props.nim`'s `fuzzProperty`) and its `corpus` section IS populated
## (this driver's own growth) — verified directly while building this
## slice.

import std/[os, times, monotimes, strutils, tables]
import nelli
import nelli/shrinker
import nelli/int128
import ./fuzzsupport

const
  SoakSingleBurstBudget = initDuration(seconds = 1)
    ## Used when the caller supplies no positive duration (env var unset
    ## or `"0"`) — a single short native-timeBudget-bounded run, not "no
    ## soak at all." This is what lets a synthetic always-crashing canary
    ## target (`tests/soak_canary.nim`) exercise this driver's crash path
    ## quickly and deterministically without needing `-Soak`'s env-var
    ## plumbing at all — the canary crashes on its very first generated
    ## value, so even this minimal budget is ample.

  SoakCrashOriginKey = "origin"
  SoakCrashOriginValue = "soak-crash"
    ## F6 per-primary-entry metadata tag (RFC-chapulin-hardening) this
    ## driver attaches to a committed crash witness, so a reader can tell a
    ## soak-discovered crash apart from a `fuzzProperty`'s own regression
    ## witnesses sharing the SAME testId's primary section — see
    ## `soakCrashMeta`/`soakCrashEntries`.

proc soakCrashMeta*(): Table[string, string] =
  ## The F6 metadata this driver attaches to every crash witness it commits
  ## — see `SoakCrashOriginKey`/`SoakCrashOriginValue` above.
  result[SoakCrashOriginKey] = SoakCrashOriginValue

proc soakCrashEntries*(db: ExampleDatabase, testId: string): seq[seq[ChoiceNode]] =
  ## Primary entries under `testId` that carry this driver's soak-crash
  ## metadata tag — distinguishing them from any `fuzzProperty`'s own
  ## regression witnesses that may share the same testId's primary section
  ## now that crashes are no longer segregated into a separate `.soak-crash`
  ## file (0.3.1 modernization; see module doc comment).
  for entry in db.loadPrimaryWithMeta(testId):
    if entry.meta.getOrDefault(SoakCrashOriginKey) == SoakCrashOriginValue:
      result.add entry.choices

proc loadPrimarySafe(db: ExampleDatabase, testId: string): seq[seq[ChoiceNode]] =
  try: db.loadPrimary(testId)
  except CatchableError as e:
    # A genuine read failure (corrupt file, decode panic) -- NOT the normal
    # "no primary entries yet" case, which returns an empty seq with no
    # exception. Surfaced, not silently swallowed.
    echo "==> WARNING: loadPrimary(" & testId & ") failed, starting fresh: " &
         $e.name & ": " & e.msg
    @[]

proc runSoak*[T](s: Strategy[T], prop: proc(x: T), testId: string,
                 envVar = "CHAPULIN_SOAK_SECONDS"): int =
  ## The shared driver. `testId` should be the exact string an existing
  ## `fuzzProperty("...", testId)` call in the default suite already uses
  ## for this target: clean coverage growth persists into the SAME file's
  ## never-pruned `corpus` section (via `FuzzSettings.database`/
  ## `persistKey`, F1), and any Defect found is committed to that SAME
  ## file's `primary` section, tagged via `soakCrashMeta` (F6) — see the
  ## module doc comment's persistence section. Returns the process exit
  ## code the caller's `soak_*.nim` main file should `quit()` with (0 =
  ## clean soak, 1 = a Defect was found, minimized, and committed).
  let rawSeconds =
    try: parseInt(getEnv(envVar, "0"))
    except ValueError: 0
  let seconds = max(rawSeconds, 0)
  let budget = if seconds > 0: initDuration(seconds = seconds) else: SoakSingleBurstBudget

  echo "==> soak '" & testId & "': " & envVar & "=" & $rawSeconds &
       " -> FuzzSettings.timeBudget budget=" & $budget &
       (if seconds <= 0: " (no positive duration given -- single ad hoc run)" else: "")

  let db = directoryBasedDatabase(CorpusDir)
  # Seed from any REAL regression a PBT property has separately committed to
  # this testId's primary section -- `fuzz()`'s own `database`/`persistKey`
  # seeding below only ever reads the `corpus` section, never `primary`, so
  # this is this driver's own addition on top (a real bug is a fine extra
  # mutation seed; this driver never writes non-crash entries to `primary`,
  # so reading it here cannot trigger `dbReusePhase`'s prune-on-pass problem
  # in the other direction).
  let seedWitnesses = loadPrimarySafe(db, testId)
  echo "==> seeding " & $seedWitnesses.len & " known-regression witness(es) from " &
       testId & ".bin's primary section (corpus-section seeds are loaded " &
       "automatically by FuzzSettings.database/persistKey)"

  let settings = FuzzSettings(
    maxIterations: 0,               # time-bounded only
    timeBudget: budget,              # the NATIVE mechanism the env var feeds
    mutationMode: fmIR,
    initialIRCorpus: seedWitnesses,
    seed: FuzzSeed.uint64,
    database: db,
    persistKey: testId,
    corpusLimit: CorpusSizeCeiling,
    stopOnFirstCrash: true)          # F4: bound detection latency to one mutation
  let report = fuzzWith(s, prop, settings)

  if report.irCrashes.len > 0:
    let crash = report.irCrashes[0]
    echo "==> SOAK CRASH after " & $report.iterations & " iterations: " & crash.message
    let shrunk = shrink(s, prop, crash.choices, 500, @[deleteSpansShrinkPass[T]()])
    echo "==> minimized " & $crash.choices.len & " -> " & $shrunk.choices.len &
         " choice node(s)" & (if shrunk.flaky: " (WARNING: flaky on final replay)" else: "")
    db.save(testId, shrunk.choices, soakCrashMeta(), maxEntries = CorpusSizeCeiling)
    let reloaded = soakCrashEntries(db, testId)
    doAssert shrunk.choices in reloaded,
      "soak-crash commit to tests/corpus/" & testId & ".bin (primary, tagged " &
      SoakCrashOriginKey & "=" & SoakCrashOriginValue & ") did not round-trip"
    echo "==> committed minimized crash to tests/corpus/" & testId &
         ".bin (primary section, tagged origin: soak-crash), confirmed round-tripped; exiting non-zero"
    return 1

  echo "==> soak clean: " & $report.iterations & " iteration(s), " &
       $report.corpus.irEntries.len & " corpus entrie(s) admitted this run " &
       "(persisted incrementally to tests/corpus/" & testId & ".bin's corpus section)"
  return 0
