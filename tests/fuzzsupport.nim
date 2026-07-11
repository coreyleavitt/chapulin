## Shared coverage-guided fuzz-property support (RFC verification-harness.md
## D1/D2). Every coverage-guided suite imports this instead of hand-copying
## the `with Settings(...)` clause and the `currentCoverage() > 0` tripwire.
##
## `FuzzSeed`/`FuzzN` are fixed so the default suite is deterministic and
## bounded (Hard constraints): a fixed seed + finite `maxExamples`, never an
## unbounded soak. `CorpusDir` is the committed `directoryBasedDatabase` root
## (slice 5 commits its contents) — `testId` + `dbPath` together make
## `forAll` auto-replay any stored falsification first and save a fresh one
## back, so persistence needs no per-target plumbing.

import std/macros
import std/unittest
import proptest
when defined(chapulinFuzz): import proptest/coverage

const
  FuzzSeed* = 0xC0FFEE
  FuzzN*    = 200
  CorpusDir* = "tests/corpus"

  OsTag* = when defined(windows): "windows"
           elif defined(posix): "posix"
           else: "other"
    ## RFC verification-harness.md D3/slice 5: `directoryBasedDatabase` keys
    ## one file per `testId` (`db.nim`'s `safeKey`), so segregating a
    ## platform-specific corpus witness from the shared one is a `testId`
    ## suffix, not a `dbPath`/subdirectory change — `osTaggedId` below is
    ## that suffix. **Not applied to any of today's 8 committed fuzz
    ## targets**, by design, not oversight: each target's oracle asserts an
    ## invariant that holds identically on every OS (see
    ## `t_security.nim`'s `validatePathOracle` doc comment — the
    ## Windows-only `:`/ADS branch is exercised by the same fuzz input
    ## space, but the oracle only checks the platform-independent
    ## never-escape property, so a witness found on Windows replays
    ## harmlessly on Linux and vice versa; same reasoning covers the other
    ## 7 targets, none of which has an `if defined(windows/posix)` fork in
    ## its *oracle*). Reach for `osTaggedId` the day a target's oracle
    ## itself branches on OS (e.g. asserting the ADS-`:` rejection is
    ## exactly what fires, not merely that escape is refused) — call
    ## `fuzzProperty(name, osTaggedId("some.target"))` at that site so the
    ## Windows and POSIX corpora land in separate `.bin` files and a future
    ## Linux CI run (today's suite is Windows-container only — see RFC
    ## "Known CI prerequisites") never mis-replays the other OS's witness as
    ## a false failure.

proc osTaggedId*(base: string): string = base & "." & OsTag

# --- shared generator-strategy helpers (R1-6 code-review finding) -----------
#
# These four were copy-pasted, byte-for-byte, across every fuzz suite
# (t_props.nim, t_hostile.nim; `charsToStr` alone was also re-copied into
# t_security.nim and t_checksum.nim for their own differently-alphabeted
# strategies). Hoisted here — the one module every fuzz suite already
# imports — so there is a single definition to keep correct.
#
# `toByteSeq` in particular used to have TWO exported homes (this module and
# `wireharness.nim`, which a suite importing both would see simultaneously).
# R2-1 code-review finding: `wireharness.nim` briefly imported this proc and
# re-exported it (`export toByteSeq`) instead of defining its own copy, but
# that re-export pulled all of `proptest` (via this module) transitively into
# every wireharness consumer, including non-fuzz ones. `wireharness.nim` no
# longer imports this module at all — this is the one canonical definition,
# and callers that need it (t_hostile.nim, t_props_transfer.nim,
# t_props_server.nim) import `./fuzzsupport` directly; all three already
# depend on `proptest` directly, so this adds no new transitive dependency
# for them.

proc toByteSeq*(xs: seq[int]): seq[byte] =
  result = newSeq[byte](xs.len)
  for i, x in xs: result[i] = byte(x and 0xFF)

proc byteSeqs*(maxLen = 600): Strategy[seq[byte]] =
  ## Arbitrary wire bytes — the decode fuzzing surface.
  lists(integers(0, 255), minLen = 0, maxLen = maxLen).map(toByteSeq)

proc charsToStr*(cs: seq[char]): string =
  result = newStringOfCap(cs.len)
  for c in cs: result.add c

const SafeAlphabet* = @['a', 'b', 'c', 'x', 'Y', 'Z', '0', '9', '.', '_', '-']

proc safeStrings*(minLen = 0, maxLen = 16): Strategy[string] =
  ## NUL-free, separator-free strings — safe to round-trip through C-string
  ## wire fields (filenames, option keys/values, error messages).
  lists(sampledFrom(SafeAlphabet), minLen = minLen, maxLen = maxLen).map(charsToStr)

# R2-2 code-review finding: `RawAlphabet`/`rawPathStrings` (t_security.nim)
# and `RawSidecarAlphabet`/`rawSidecarStrings` (t_checksum.nim) were each kept
# local with a comment saying they "genuinely differ from fuzzsupport's
# SafeAlphabet" — true, but both missed that they were byte-for-byte
# identical to EACH OTHER (same alphabet literal, same
# `lists(sampledFrom(...)).map(charsToStr)` wrapper), just under different
# names in different files. Hoisted here as the one shared definition. The
# only difference between the two original call sites was the default
# `maxLen` (24 in t_security.nim, 20 in t_checksum.nim) — preserved by
# keeping this proc's default at 24 (t_security.nim's bare `rawPathStrings()`
# call is unaffected) and having t_checksum.nim's bare call site pass its
# `20` explicitly instead of relying on a differing default.
const RawPathAlphabet* = @['a', 'b', '.', '/', '\\', '\0', ':', ' ', 't']
  ## Baseline alphabet for containment/path-string fuzzing: separators (both
  ## slashes), dot-dot fuel, embedded NUL, drive-colon, space, and a couple of
  ## ordinary filename chars.

proc rawPathStrings*(maxLen = 24): Strategy[string] =
  ## Arbitrary/adversarial path-shaped strings built from `RawPathAlphabet` --
  ## almost always rejected by a containment check before anything else
  ## happens; used both to stress `validatePath`'s lexical escape logic
  ## (t_security.nim) and `writeSidecar`'s containment re-check
  ## (t_checksum.nim).
  lists(sampledFrom(RawPathAlphabet), minLen = 0, maxLen = maxLen).map(charsToStr)

macro fuzzProperty*(name: string, tid: string, body: untyped): untyped =
  ## `property name` with the corpus-persisted coverage-guided `Settings`
  ## clause already applied, plus the `currentCoverage()` tripwire bundled
  ## in — the only things call sites vary are the property name, the
  ## `testId`, and the `given`/`ensure` body.
  ##
  ## Deliberately a **macro**, not a template (deviation from the RFC's own
  ## sketch, confirmed empirically — this is the "slice 1 confirms
  ## empirically" check the RFC calls for): `property` is itself a macro
  ## that indexes its `body`'s direct children (`body[0]`, `body[1]`, ...),
  ## and a template that spliced its own `body` param as a *nested*
  ## statement (`property name: with Settings(...); body`) hands `property`
  ## a 2-element body (`[withClause, nestedStmtList]`) instead of the
  ## required 3 (`[withClause, given, ensure]`) — `property` rejects it
  ## ("body must include `given` and a predicate after `with`"). Building
  ## the call by hand and appending `body`'s own children directly avoids
  ## the nesting. `bindSym` on every symbol this macro depends on
  ## (`property`, `Settings`, `currentCoverage`, `CorpusDir`/`FuzzSeed`/
  ## `FuzzN`) ties them to fuzzsupport.nim's own imports rather than the
  ## call site's — the same guarantee a template's default hygiene would
  ## give, since a macro's `quote`/`ident` nodes are open symbols by
  ## default. This is what lets a caller (`t_props.nim`) use the tripwire
  ## without itself importing `proptest/coverage`.
  let settingsSym = bindSym"Settings"
  let corpusSym = bindSym"CorpusDir"
  let seedSym = bindSym"FuzzSeed"
  let nSym = bindSym"FuzzN"
  let settingsExpr = quote do:
    `settingsSym`(coverageGuided: true, testId: `tid`, dbPath: `corpusSym`,
                  seed: `seedSym`, maxExamples: `nSym`)

  var propBody = newStmtList(nnkCommand.newTree(ident"with", settingsExpr))
  for stmt in body:
    propBody.add stmt

  result = newStmtList(newCall(bindSym"property", name, propBody))

  when defined(chapulinFuzz):
    let coverageSym = bindSym"currentCoverage"
    result.add quote do:
      doAssert `coverageSym`() > 0,
        "chapulinFuzz coverage tripwire failed for '" & `tid` &
        "' — missing tests/nim.cfg define or a dropped {.cover.} pragma"

# --- anti-vacuity counter helper (R2-4 code-review finding) -----------------
#
# t_hostile.nim hand-rolled three module-level `var int` counters
# (d8aLiveInjections, d8bLiveInjections, d8bBounceTotal), each paired with an
# implicit "the `test` block runs after the `property` above it, in
# unittest's own source-order execution" contract: a stateful property
# accumulates into the counter across every example it generates, and a
# plain `test` block placed immediately after it inspects the final total
# once, proving the property wasn't vacuously true (e.g. every injection
# landing only in the post-transfer dally epilogue, never a live window).
# This mechanism was CERTIFIED GENUINE by security + verification-rigor
# review — this helper factors ONLY the repeated storage + the post-property
# `check count > 0` assertion boilerplate. It does NOT decide, and must
# never be asked to decide, WHEN or WHERE a counter is incremented — that
# stays entirely at each call site (see t_hostile.nim's `noteD8aLiveInjection`
# / `noteD8bLiveInjection`, which still gate every `note()` call behind their
# own `inLiveDataPhase` liveness predicate, untouched by this refactor).
#
# Deliberately NOT `proptest`'s `event()`: `event()` only surfaces counts in
# the human-readable report, it does not fail the run — swapping to it would
# silently turn a hard "this run proved nothing" failure into a passing test
# that merely logs a suspicious 0, which is exactly the vacuity this
# mechanism exists to catch.
type
  VacuityCounter* = object
    count: int

proc note*(vc: var VacuityCounter, n = 1) =
  ## Record one occurrence (or, for an accumulator like d8bBounceTotal, add
  ## an arbitrary per-example magnitude via `n`). Call site decides whether
  ## and when to call this — this proc has no opinion on liveness/timing.
  vc.count += n

proc assertFired*(vc: VacuityCounter, msg: string) =
  ## Call exactly once, after every property/example that feeds `note` has
  ## already run (unittest's source-order contract — same as the original
  ## hand-rolled `check counter > 0`). Uses `checkpoint` + `check`, not
  ## `doAssert`, so this reads exactly like the code it replaces: a failure
  ## here fails the test but does not raise, and multiple `assertFired` calls
  ## in the same `test` block are each still evaluated independently (no
  ## short-circuiting on the first failure).
  checkpoint(msg)
  check vc.count > 0
