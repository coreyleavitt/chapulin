## Corpus replay round-trip check (RFC verification-harness.md, slice 5).
##
## Two independent proofs:
## 1. A synthetic hand-built choice-sequence entry survives a
##    save -> reload round trip byte-for-byte and struct-for-struct: no
##    corruption, no CRLF mangling (embedded 0x0A/0x0D bytes inside a
##    ckBytes payload pass through the write/read path completely opaque),
##    and re-saving the identical sequence reproduces byte-identical file
##    contents (the encoder is deterministic -- the "stable replay" half).
## 2. EVERY committed `tests/corpus/*.bin` fuzz-target entry reloads without
##    raising `DbError`/`DbCorrupt`, and reloading twice through two
##    independent `directoryBasedDatabase` handles (simulating two separate
##    process runs -- nothing but the on-disk file carries state between
##    them) yields identical decoded entries both times. That is the actual
##    "replay is deterministic" claim slice 5 asks for, exercised against the
##    real committed corpus rather than a synthetic stand-in.
##
##    R1-5 code-review fix: the set of testIds this iterates used to be a
##    hand-maintained `CommittedTestIds` const, which silently fell out of
##    sync as new fuzz targets landed (it stayed at its original 8 entries
##    through slice 6's `eventqueue.opseq` and the two `hostile.*` targets
##    from the hostile-session work, so "every" was actually checking only 8
##    of the real 11) -- a false "every" that could recur with the next new
##    target. `corpusTestIds()` below instead DERIVES the list at runtime by
##    enumerating `tests/corpus/*.bin` directly, so the checked set can never
##    drift from the real committed set again.
##
## Per `proptest.nim`'s own module doc: `proptest/choice`'s constructors
## (`integerChoice` etc.) and the raw serializer are deliberately NOT
## re-exported from the top-level `proptest` module -- reached only via a
## submodule import, exactly for "test fixtures that hand-craft sequences."
## That is this file's whole business, so it imports `proptest/choice`
## directly alongside the normal `import proptest`.
##
## `.gitattributes`' `tests/corpus/** binary` rule (confirmed present,
## verified separately) is what keeps GIT ITSELF from ever normalizing,
## diffing, or 3-way-merging these files. This suite proves the other half:
## the Nim-side write/read path is already binary-safe end to end
## (`readFile`/`writeFile` are byte-exact -- Nim has no implicit text-mode
## translation), so the two protections (git config + I/O path) are each
## independently verified rather than one standing in for the other.
##
## OS-tagging (RFC D3 "Containment findings gated on `when defined(windows)`
## branches ... get an OS tag"): see `fuzzsupport.nim`'s `OsTag`/
## `osTaggedId` -- the mechanism exists, but none of the committed targets
## below use it. That's a design call, not an omission: each target's
## *oracle* asserts an invariant that already holds identically on every OS
## (see `t_security.nim`'s `validatePathOracle` doc comment for the fullest
## example -- the Windows-only `:`/ADS branch is exercised by the same
## fuzz input space, but the oracle only checks the platform-independent
## never-escape property). A witness saved under `tests/corpus/` today was
## found on Windows (the only container `dev-test.ps1` runs today) but
## replays harmlessly if a future Linux run loads the same file, because
## nothing in any of these oracles branches on OS. `osTaggedId` is there for
## the day a target's oracle itself becomes OS-divergent.
##
## Run in the nim devtools container:
##   docker run --rm -v ${PWD}:C:\app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r tests/t_corpus.nim

import std/[unittest, os]
import proptest
import proptest/choice
import fuzzsupport

suite "corpus replay round-trip (RFC verification-harness.md, slice 5)":

  let tmpDir = getTempDir() / "chapulin_corpus_replay_fuzz"

  test "setup: disposable DB directory":
    removeDir(tmpDir)  # in case a prior run crashed mid-test
    check not dirExists(tmpDir)

  test "synthetic entry: save -> reload is struct-identical, and re-saving reproduces byte-identical file contents":
    let testId = "synthetic.roundtrip.smoke"
    # A payload with the exact bytes a naive text-mode write would mangle:
    # NUL (would truncate a C-string reader), LF and CR (would be rewritten
    # by CRLF normalization -- a lone 0x0A becoming 0x0D 0x0A), and a high
    # byte (0xFF -- not valid ASCII/UTF-8 alone, proving the path is
    # byte-oriented, not string/text-mode).
    let needle = @[byte 0x00, 0x0A, 0x0D, 0xFF, 0x41]
    let choices = @[
      integerChoice(42, 0, 100, 0),
      bytesChoice(needle, 0, 10),
      booleanChoice(true, 0.5),
    ]

    let db1 = directoryBasedDatabase(tmpDir)
    db1.save(testId, choices)

    let entryPath = tmpDir / "synthetic.roundtrip.smoke.bin"
    let rawBytes1 = readFile(entryPath)

    # Reload through a FRESH ExampleDatabase handle (not the one that just
    # wrote) -- the "separate process" simulation: only the on-disk file
    # carries state across the two handles.
    let db2 = directoryBasedDatabase(tmpDir)
    let reloaded = db2.loadPrimary(testId)
    check reloaded.len == 1
    check reloaded[0] == choices  # struct-for-struct: every field, incl.
                                  # the embedded NUL/LF/CR/high-byte payload

    # The embedded NUL/LF/CR/0xFF/'A' quintuple must appear in the raw file
    # exactly as constructed -- confirms it wasn't rewritten (CRLF
    # expansion would grow the file and shift the byte after the LF) or
    # truncated (a text-mode NUL-terminated write would drop everything
    # after the 0x00).
    var found = false
    for i in 0 .. rawBytes1.len - needle.len:
      var allMatch = true
      for j in 0 ..< needle.len:
        if byte(rawBytes1[i + j]) != needle[j]:
          allMatch = false
          break
      if allMatch:
        found = true
        break
    check found

    # Re-saving the identical choice-sequence from scratch must reproduce
    # byte-identical file content -- `encodeContents` has no
    # timestamp/randomness, so this is the "stable replay" half: the same
    # logical entry always serializes to the same bytes, run after run.
    removeFile(entryPath)
    let db3 = directoryBasedDatabase(tmpDir)
    db3.save(testId, choices)
    let rawBytes2 = readFile(entryPath)
    check rawBytes1 == rawBytes2

  test "teardown: remove disposable DB directory":
    removeDir(tmpDir)
    check not dirExists(tmpDir)

  # --- replay of the real, already-committed corpus -------------------------

  proc corpusTestIds(): seq[string] =
    ## R1-5 code-review fix: DERIVE the checked testId set from the actual
    ## `tests/corpus/*.bin` files on disk instead of a hand-maintained list --
    ## the committed corpus entry filenames ARE the testIds with `.bin`
    ## appended (`directoryBasedDatabase`'s `safeKey` convention: `db.save`
    ## writes `dbPath / (testId & ".bin")`), so this can never drift from the
    ## real committed set the way the old `CommittedTestIds` const did.
    ##
    ## `walkFiles` with a plain (non-recursive) `*.bin` glob only matches
    ## files directly inside `CorpusDir` -- it does not descend into
    ## subdirectories -- so the committed `tests/corpus/fixtures/root/` tree
    ## (the symlink-free fixture directory the LEXICAL containment fuzz
    ## targets read against, not itself a corpus entry, and not `.bin` files
    ## regardless) is never mis-picked-up here.
    for path in walkFiles(CorpusDir / "*.bin"):
      let (_, name, _) = splitFile(path)
      result.add name
      # R2-3: this filename->testId mapping assumes every testId is already
      # made of `safeKey`-safe chars ([A-Za-z0-9.-]); a future testId using
      # other chars would derive a safeKey-encoded on-disk name instead, and
      # the mismatch would fail loudly below via `secondaryA.len > 0`
      # (a corpus entry that was never actually reloaded), not silently.

  test "every committed fuzz-target corpus entry reloads without error and replays deterministically":
    let testIds = corpusTestIds()
    # Guard (R1-5): a mis-pointed CorpusDir (typo'd path, corpus dir wiped,
    # etc.) would make the loop below iterate zero times and the test
    # vacuously "pass" having checked nothing at all -- exactly the kind of
    # false "every" this fix exists to close. Fail loudly instead.
    check testIds.len > 0
    for tid in testIds:
      checkpoint("testId: " & tid)
      let dbA = directoryBasedDatabase(CorpusDir)
      let dbB = directoryBasedDatabase(CorpusDir)  # independent handle -- "second run"
      let secondaryA = dbA.loadSecondary(tid)
      let secondaryB = dbB.loadSecondary(tid)
      let primaryA = dbA.loadPrimary(tid)
      let primaryB = dbB.loadPrimary(tid)
      check secondaryA.len > 0   # coverage-guided interesting-input entries exist
      check secondaryA == secondaryB  # deterministic: two independent loads agree
      check primaryA == primaryB      # (empty today -- no crash ever found by
                                       # these targets -- but the equality itself
                                       # is the determinism claim being checked,
                                       # independent of which list is empty)

  test "osTaggedId suffixes a base testId with the current OS tag (R1-10)":
    # `osTaggedId` is the mechanism reserved for the day a target's oracle
    # branches on OS (see fuzzsupport.nim's `OsTag` doc). It's deliberately
    # unwired today, so this unit test is the only thing guarding its suffix
    # logic from a silent typo until the first real caller appears.
    check OsTag in ["windows", "posix", "other"]
    check osTaggedId("some.target") == "some.target." & OsTag
    when defined(windows):
      check osTaggedId("x") == "x.windows"
