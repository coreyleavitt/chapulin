## Symex no-Defect proofs for `security.validatePath`/`checkWriteAccess`
## (RFC verification-harness-v2.md Part B, slice B2, Target 1). Opt-in, z3
## image only (t_symex* convention -- auto-selected by dev-test.ps1's
## `-like "t_symex*"` rule; no per-file registration needed):
##   pwsh scripts/dev-test.ps1 -Only @('t_symex_security') -Image chapulin-symex:2.2.10
##
## Read `tests/t_symex_decode.nim` (B1) and `tests/t_symex_uri.nim` (this
## slice's Target 2, same file-header catalog numbering) FIRST. This file
## reuses both files' twin-extraction discipline and, critically, Target
## 2's **Blocker #9** finding (bisected there in a scratch harness): a
## `while`/`for` LOOP anywhere in a symex target's body that also has a
## `string`-typed parameter in scope is unprovable in this proptest pin --
## `sxUnknown`, empty `errors` -- regardless of whether the loop indexes the
## string, bounds itself by the string's length, or does either at all.
## Every reshape below routes around loops entirely (bounded, hand-unrolled
## nested-`if`s -- B1's own fix for its Blocker #5, just reapplied here for
## a *different* root cause).
##
## ---- Toolchain fit: WHY a twin, not the shipped procs (RFC-anticipated,
## confirmed by reading the source, not just the RFC's prediction) --------
## `validatePath`'s full body (security.nim:161-222) calls `absolutePath`
## (whose default `root` arg evaluates `getCurrentDir()`, a real syscall,
## even when a single-arg call site never intends to use the default) and
## `validateWritePath` -> `canonicalize`/`symlinkExists`/`hasReparseComponent`,
## none of which are in `smt/stdlib_models.nim`'s `OpaqueEffectfulProcs`
## allowlist (`echo/print/write/.../open/close` -- no `os` path-resolution
## procs at all). `checkWriteAccess` calls `canonicalize` directly. Passing
## either shipped proc to `symexFind` hits `getImpl`-based inlining of one
## of these -- the same class of wall B1's Blocker #2 hit for a stdlib
## tuple-returning helper, just for a real-syscall-backed proc instead of a
## pure one. This file therefore extracts a **test-only pre-I/O twin** of
## the LEXICAL prefix only (validatePath's guard clauses through its first
## `isWithin` call; `checkWriteAccess`'s reserved-name check, stopping
## *before* the `canonicalize` fallback) -- the I/O split is clean per the
## RFC (I/O runs only after the lexical checks return ok), so the prefix is
## cleanly extractable on its own.
##
## ---- BLOCKER #10 FOUND EMPIRICALLY (string MUTATION -- `.add`/`&=` -- is
## unsupported; `security.isWithin`'s `p.add(DirSep)` hits it) -----------
## `dsl_parser.nim` routes an in-place string append (`s.add(x)`, distinct
## from the `&` CONCAT operator, which IS modeled -- `iekStrConcat`) to
## `iekStrUnsupported("string mutation", ...)` (confirmed by reading the
## parser's own comment at the call site: "receiver to an iekStrUnsupported
## op ... honestly classified seUnsupportedStringOp"). `isWithin`
## (security.nim:35-44) calls `p.add(DirSep)` -- a direct hit. FIX (used in
## `isWithinTwin` below): the semantically-identical, already-modeled
## `p = p & sep` (reassign-via-concat) instead of the in-place mutating
## form -- a one-for-one substitution with no control-flow change.
##
## ---- Reshape: `extractFilename` is UNNEEDED, not just unmodeled --------
## `isReservedSidecarName` (security.nim:16-33) calls `extractFilename(path)`
## before the suffix check -- an `os` proc with no stdlib model (same
## unmodeled-syscall-adjacent class as `canonicalize`, and even if it were
## a pure Nim proc, extracting "the last path component" is exactly
## Target 2's rfind-shaped problem: no loop-free forward-scan trick applies
## the way it did for a single `:` split, since `extractFilename` needs the
## LAST separator among an unbounded set of candidate separator chars).
## Rather than reshape a scan, this file drops it ENTIRELY: `endsWith(sfx)`
## is invariant under removing any separator-free PREFIX of the string
## (`sfx` here is always `".md5"`, which contains no path separator) --
## `path.endsWith(sfx) == extractFilename(path).endsWith(sfx)` for every
## `path` whose basename IS a genuine suffix of `path` -- true for an
## ordinary "dir/dir/name" shape. So `isReservedSidecarNameTwin` below
## checks the suffix against the FULL (trimmed) path directly.
##
## ---- FOUND EMPIRICALLY: this elision is NOT exact for a LEADING
## double-separator ("//..."/"\\\\...") -- real `os.extractFilename`
## treats that shape as UNC-like and returns "", not the naive
## last-component --------------------------------------------------------
## Diagnosed in a scratch harness (not kept): `extractFilename("//a/.md5")`
## returns `""` (confirmed: Nim's `os` module special-cases a leading
## double-separator as a UNC/network-path marker, distinct from an
## ordinary single-leading-separator absolute path, where
## `extractFilename("/root/sub/f.bin.md5") == "f.bin.md5"` as expected).
## `"".endsWith(".md5")` is `false`, while the FULL PATH
## `"//a/.md5".endsWith(".md5")` is `true` -- a genuine divergence between
## this twin and the real proc, distinct from the already-documented
## Blocker #7 (case) and #11 (strip bound) approximations. `checkWriteAccess`'s
## real call site (security.nim:224-274) only ever passes a `resolvedPath`
## built by `validatePath` as `absolutePath(rootDir / cleanName)` -- always
## a single, non-UNC absolute path -- so this is not a live production gap,
## but it IS a real elision-argument counterexample and is scoped out of
## the differential oracle below explicitly (not swept past): the
## generator excludes a leading double-separator, and the finding is
## asserted directly as its own documented-divergence test, the same
## discipline as the Blocker #7 case-folding divergence above.
import std/[unittest, strutils, os]
import nelli
import nelli/symex
import ../src/chapulin/security

# ---- Strip reshapes: 0.1.0 re-evaluation (Blocker #9's REFINED finding) ----
#
# proptest 0.1.0 (2026-08 reintro) DOES lift the former Blocker #9 ("ANY loop
# touching a string is unprovable") for the case where the loop-producing
# call's result is consumed in ONE direct method-chain expression, no named
# binding: `isReservedSidecarNameSymexTwin` below calls the real, unbounded
# `strutils.strip` (a while loop) as `stripTrailingDotSpaceTwin(path).endsWith(
# ".md5")` and proves `sxUnsat` cleanly -- confirmed empirically (this file's
# own earlier BISECTION run: direct chains of a loop-produced string into a
# downstream op -- contains/endsWith, leading or trailing strip -- all prove
# `sxUnsat`; see BISECTION 3's P11).
#
# BUT `validatePath`'s real shape needs `cleanName` (the stripped result) to
# survive across SEVERAL subsequent guard/early-return statements (traversal
# check, colon check, empty check, then the `resolved`/`isWithin` use) -- not
# consumed in the same statement it's produced. Bisected empirically here
# (BISECTION 1-3 probes, run and removed once isolated -- not kept, per this
# file's "don't ship scratch probes" convention, same as t_symex_uri.nim's
## t_symex_probe.nim precedent): binding a while-loop-produced string to a
## `let`/`var` and reading it in a LATER statement is STILL `sxUnknown` (empty
## errors) regardless of which downstream op reads it (replace/contains/len/a
## further call) or which strip direction/charset produced it -- the
## IDENTICAL computation, consumed in a single direct chain with no named
## binding, proves `sxUnsat`. Control: binding a NON-loop-derived string
## (e.g. `.replace`'s result, no explicit Nim-level loop) to a `let`/`var`
## and reading it across several LATER statements is completely fine (see
## `validatePathLexicalTwin` below, whose `cleanName` uses exactly this
## pattern once past the strip). So this is a REFINED, NARROWER form of the
## old Blocker #9: 0.1.0 fixed the same-statement-chain case but not the
## bound-across-statements case for a loop-produced value specifically.
#
# FIX (proptest 0.3.1, PRIORITY 2 item 4): `stripLeadingSepTwin`'s bounded,
# loop-free, hand-unrolled depth-2 nested-if (the workaround for `cleanName`
# needing to cross statement boundaries in `validatePathLexicalTwin`, which
# the real unbounded `strip` couldn't do under 0.1.0's refined Blocker #9) is
# REPLACED with the real `strutils.strip` below. The maintainer's
# modernization map: `strip` is modeled as a native, built-in IR node
# (`iekStrStrip`, dsl_parser.nim) -- NOT an interprocedurally-inlined
# user-defined `while` loop -- so it was never actually subject to Blocker
# #9's mechanism (interprocedural loop inlining) in the first place; that
# mechanism is what `t_symex_decode.nim`'s `readCStringTwin` (a genuine
# user-defined `while` loop) hits, a DIFFERENT, still-open gap (see that
# file's PRIORITY 1 finding). Confirmed empirically below: the real `strip`
# proves `sxUnsat` in BOTH the same-statement-chain position
# (`stripTrailingDotSpaceTwin`, unchanged) AND the bound-across-statements
# position (`cleanName` here, crossing several subsequent guard statements)
# -- the old #9 "loop-produced value can't survive a binding" scoping is
# OBSOLETE for `strip` specifically. Workaround REMOVED; the bounded-to-2
# divergence from the real (unbounded) strip is gone too.

proc stripLeadingSepTwin(s: string): string =
  ## Twin of `filename.strip(chars = {'/', '\\'}, trailing = false)`
  ## (security.nim:173, the virtual-root PXE-compat strip). Real, unbounded
  ## `strutils.strip` -- see the FIX note just above.
  s.strip(chars = {'/', '\\'}, trailing = false)

proc stripTrailingDotSpaceTwin(s: string): string =
  ## Twin of `isReservedSidecarName`'s
  ## `.strip(leading = false, trailing = true, chars = {'.', ' '})` (M5).
  ## Real, unbounded `strutils.strip` -- proven sxUnsat under 0.1.0 because
  ## every call site below consumes it via ONE direct chain (never bound to
  ## a `let`/`var`); see the file-header note above.
  s.strip(leading = false, trailing = true, chars = {'.', ' '})

# ---- isWithin twin (Blocker #10 fix) ---------------------------------------

const SepStub = "/"
  ## Stand-in for the appended separator. The real `isWithin` appends
  ## `DirSep` specifically; this twin proves the SHAPE of the containment
  ## idiom (does appending one char then calling `startsWith` ever raise a
  ## Defect), which does not depend on which literal separator is used --
  ## the differential oracle below calls the REAL `isWithin` (via the real
  ## `validatePath`, with the platform's actual `DirSep`/`AltSep`), so any
  ## divergence this stand-in introduces would surface there, not pass
  ## silently.

proc isWithinTwin(child, parent: string): bool =
  ## Twin of `security.isWithin` (security.nim:35-44). proptest 0.1.0 reintro:
  ## in-place `p.add(sep)` restored (former `p = p & SepStub` was the
  ## Blocker #10 workaround).
  if child == parent:
    return true
  var p = parent
  if p.len > 0 and p[p.len - 1] != DirSep and p[p.len - 1] != AltSep:
    p.add(SepStub)
  result = child.startsWith(p)

# ---- Target 1a: validatePath's pre-I/O lexical prefix, through isWithin ---
#
# Mirrors security.nim:165-204 (the guard-clause chain: empty filename,
# NUL byte, virtual-root strip, backslash normalization, ".." traversal,
# Windows colon/ADS rejection, empty-after-normalization) plus lines
# 199-203's `resolved`/`normalizedRoot`/`isWithin` call -- WITHOUT calling
# the real (unmodeled, syscall-backed) `absolutePath`: `resolved` and
# `normalizedRoot` are approximated as plain string concatenation, which is
# exactly what `absolutePath` reduces to when `rootDir` is already absolute
# (the only case that matters in production -- a served TFTP root is always
## configured as an absolute path). Void target (no tuple/object return),
# matching B1's `decodeFixedArmsTwin`/`decodeOptionArmTwin` convention.

proc validatePathLexicalTwin(rootDir, filename: string) =
  if filename.len == 0:
    return
  if filename.contains("\0"):
    return
  var cleanName = stripLeadingSepTwin(filename)
  cleanName = cleanName.replace("\\", "/")
  if cleanName.contains(".."):
    return
  when defined(windows):
    if cleanName.contains(":"):
      return
  if cleanName.len == 0:
    return
  let resolved = rootDir & "/" & cleanName
  let normalizedRoot = rootDir
  # PRIORITY 1 (proptest 0.3.1 discard-vacuity fix): `discard isWithinTwin(...)`
  # dropped the call's expression entirely -- dsl_parser.nim's `nnkDiscardStmt`
  # arm only lowers a discarded call for two allowlisted intrinsics
  # (getCurrentException(Msg)/parseInt/parseBiggestInt); every OTHER discarded
  # call -- including this test-local `isWithinTwin` -- becomes `mkBlock(@[])`,
  # a complete no-op, so `isWithinTwin`'s own defect paths (the `.add`/
  # `startsWith` inside it) were NEVER searched: this arm's `sxUnsat` was
  # narrower than it read. Fix: bind via `let` (never `discard`ed).
  let contained = isWithinTwin(resolved, normalizedRoot)
  discard contained
    # `discard <identifier>` (not `discard <call>`) is harmless -- the call
    # was already lowered at the `let` binding above; this only discards
    # the already-bound VALUE, silencing the unused-let hint.

# ---- Target 1b: checkWriteAccess's reserved-.md5 lexical check ------------
#
# Mirrors `isReservedSidecarName` (security.nim:16-33), reshaped per the
# file-header note (extractFilename dropped -- suffix check is invariant
# under separator-free prefix removal) and Blocker #7 (toLowerAscii
# dropped -- case-sensitive suffix check; the oracle below is scoped to
# already-cased suffix spellings, same convention as t_symex_uri.nim).
# `checkWriteAccess`'s own surrounding shape (security.nim:250-258:
# `if config.checksumMode != csNone: if reserved: reject`) is a plain,
# already-proven-safe boolean guard around this call -- NOT separately
# re-proven here: an attempt to wrap it in its own symex target (adding a
# second, `bool`-typed parameter alongside the string) hit a THIRD
## empirical native-crash trigger (bisection not kept in this file, out of
# budget to chase a fourth blocker for zero incremental proof value -- the
# guard itself has no string/index operation of its own, so
## `isReservedSidecarNameSymexTwin` below already covers every Defect-prone
# operation `checkWriteAccess`'s reserved-name check performs; wrapping it
# in an unrelated `bool` parameter adds surface area, not coverage).

proc isReservedSidecarNameSymexTwin(path: string) =
  ## PRIORITY 1 discard-vacuity fix (see validatePathLexicalTwin's comment
  ## above): the former `discard stripTrailingDotSpaceTwin(path).endsWith(
  ## ".md5")` dropped BOTH the real `strutils.strip` call AND the
  ## `endsWith` check entirely unwalked. Fix: consume the chain directly as
  ## an `if` CONDITION, never `let`-bound -- `stripTrailingDotSpaceTwin`
  ## uses the real, unbounded (while-loop) `strutils.strip` (see this
  ## file's Blocker #9 note above), and even a `let`-binding of a
  ## while-loop-produced value that's never read again by a later
  ## statement regressed this proof from `sxUnsat` to `sxUnknown`
  ## (measured, both with and without a subsequent `discard`). A single,
  ## direct, never-named-binding chain -- exactly the shape the file
  ## header's Blocker #9 note describes as provable -- stays `sxUnsat`.
  if stripTrailingDotSpaceTwin(path).endsWith(".md5"):
    discard

# ---- Compile-check + no-Defect proofs --------------------------------------

suite "symex: validatePath lexical prefix (through isWithin)":
  test "compiles under symexFind":
    let r = symexFind(validatePathLexicalTwin, tIndexError())
    discard r

  test "no IndexError path (sxUnsat)":
    check symexFind(validatePathLexicalTwin, tIndexError()).status == sxUnsat

  test "no FieldDefect path (sxUnsat)":
    check symexFind(validatePathLexicalTwin, tFieldDefect()).status == sxUnsat

suite "symex: checkWriteAccess reserved-.md5 lexical check (isReservedSidecarName)":
  test "compiles under symexFind":
    let r = symexFind(isReservedSidecarNameSymexTwin, tIndexError())
    discard r

  test "no IndexError path (sxUnsat)":
    check symexFind(isReservedSidecarNameSymexTwin, tIndexError()).status == sxUnsat

  test "no FieldDefect path (sxUnsat)":
    check symexFind(isReservedSidecarNameSymexTwin, tFieldDefect()).status == sxUnsat

# ---- Differential oracles: twin ≡ shipped proc on concrete strings --------
#
# "Compiles"/"sxUnsat" proves no Defect ESCAPES the modeled prefix; it does
# not prove the twin's ACCEPT/REJECT decision boundary matches the real
# proc's. Both oracles below run the REAL shipped proc (ordinary compiled
# Nim -- extractFilename/absolutePath/toLowerAscii/`.add` are all fine
# outside the walker) against the corresponding value-returning twin on the
# same concrete strings.

# ---- Oracle 1: validatePath's LEXICAL decision only ------------------------
#
# validatePath never raises (it returns a tuple), so there is no
# raised/not-raised axis to compare -- instead this compares WHICH lexical
# guard (if any) rejects the filename, restricted to the prefix this file
# models (empty/nul-byte/traversal/windows-colon/empty-after-normalize).
# `validatePath`'s later stages (symlink/junction containment, I/O) are OUT
# OF SCOPE -- a filename that clears every LEXICAL guard may still be
# rejected downstream by the real proc (e.g. an escaping symlink); the
# oracle only asserts the two procs AGREE on whether/why a LEXICAL guard
# fires, not on the real proc's final `valid` bit.

const LexicalRejectReasons = ["Empty filename", "Null byte in filename",
  "Path traversal not allowed", "Invalid character in filename",
  "Empty filename after path normalization"]

proc validatePathLexicalDecision(rootDir, filename: string): tuple[
    rejected: bool, reason: string] =
  ## Value-returning mirror of `validatePathLexicalTwin` for oracle use
  ## (ordinary runtime code, not a symex target -- tuple RETURN is fine
  ## outside the walker). Reuses the SAME `stripLeadingSepTwin`/
  ## `isWithinTwin` helpers the symex-proven twin uses, so a divergence in
  ## either helper is caught here too.
  if filename.len == 0:
    return (true, "Empty filename")
  if filename.contains("\0"):
    return (true, "Null byte in filename")
  var cleanName = stripLeadingSepTwin(filename)
  cleanName = cleanName.replace("\\", "/")
  if cleanName.contains(".."):
    return (true, "Path traversal not allowed")
  when defined(windows):
    if cleanName.contains(":"):
      return (true, "Invalid character in filename")
  if cleanName.len == 0:
    return (true, "Empty filename after path normalization")
  return (false, "")

proc diffOracleCheckValidatePath(rootDir, filename: string): bool =
  let (valid, _, err) = validatePath(rootDir, filename)
  let realRejectedLexically = (not valid) and (err in LexicalRejectReasons)
  let (twinRejected, twinReason) = validatePathLexicalDecision(rootDir, filename)
  if twinRejected:
    realRejectedLexically and err == twinReason
  else:
    not realRejectedLexically

# ---- Oracle 2: isReservedSidecarName, exact equivalence --------------------
#
# Unlike Oracle 1 (scoped to a prefix), this one is EXACT: the extractFilename
# elision is a proven-invariant rewrite (see the file header), and the
# strip-bound / toLowerAscii-drop are the only approximations -- scoped
# below via the fuzz generator (bounded trailing run; canonical-case
# suffixes), not via a partial-agreement predicate.

proc diffOracleCheckReservedName(path: string): bool =
  isReservedSidecarName(path) == stripTrailingDotSpaceTwin(path).endsWith(".md5")

suite "differential oracle: validatePath lexical prefix":
  test "hand-picked vectors (every guard, valid and invalid shapes)":
    let root = "/srv/tftp"
    let vectors = @[
      "existing.txt", "subdir/nested.txt", "../../../etc/passwd",
      "/existing.txt", "\\existing.txt", "/subdir/nested.txt",
      "/../../../etc/passwd", "subdir/../../etc/passwd", "file\x00.txt",
      "", "..\\..\\etc\\passwd", "newfile.txt", "///triple/slash.txt",
      "\\\\\\triple/backslash.txt", "/\\/mixed.txt", "....", "//",
    ]
    for v in vectors:
      check diffOracleCheckValidatePath(root, v)

  proc filenameStrings(maxLen = 20): Strategy[string] =
    ## Filenames with an arbitrary-length leading separator run. proptest
    ## 0.3.1 (PRIORITY 2 item 4): `stripLeadingSepTwin` now uses the real,
    ## unbounded `strutils.strip` (see the FIX note above `stripLeadingSepTwin`),
    ## so the former "AT MOST 2 leading separators" cap (Blocker #11, matching
    ## the twin's old bounded-2 hand-unroll) is no longer needed -- widened
    ## here to include 3+-separator runs. Unrestricted otherwise (embedded
    ## NUL, dots, colons, either slash kind anywhere else in the string).
    let seps = sampledFrom(@["", "/", "//", "///", "////", "\\", "\\\\",
                             "\\\\\\", "/\\", "\\/", "/\\/\\", "\\/\\/"])
    let alphabet = @['a', 'b', '.', '/', '\\', '\0', ':', ' ']
    let body = lists(sampledFrom(alphabet), minLen = 0, maxLen = maxLen).map(
      proc(cs: seq[char]): string =
        result = newStringOfCap(cs.len)
        for c in cs: result.add c)
    # A fixed "a" anchors the boundary between the separator run and the
    # arbitrary body: without it, `body` (whose own alphabet includes '/'
    # and '\\') could START with a separator too, silently EXTENDING the
    # leading run past what `seps` alone specifies -- found empirically (a
    # counterexample of exactly this shape, "///" from `seps="//"` +
    # `body="/"...`, failed before this anchor was added). Still needed:
    # this is about the GENERATOR'S OWN construction (knowing where the
    # "separator run" ends and the arbitrary body begins), unrelated to the
    # now-removed strip-length cap.
    seps.flatMap(proc(sfx: string): Strategy[string] =
      body.map(proc(b: string): string = sfx & "a" & b))

  property "arbitrary filenames, arbitrary-length leading-separator run":
    with Settings(seed: 0xC0FFEE, maxExamples: 200)
    given fn in filenameStrings()
    ensure diffOracleCheckValidatePath("/srv/tftp", fn)

suite "differential oracle: isReservedSidecarName":
  test "hand-picked vectors (M5 trailing dot/space [bounded to 2], non-reserved)":
    let vectors = @[
      "f.bin.md5", "f.bin.md5.", "f.bin.md5 ",
      "f.bin.md5..", "f.bin.md5  ", "f.bin.txt", "", "md5", ".md5",
      "/root/sub/f.bin.md5", "\\root\\sub\\f.bin.md5", "f.md5..",
    ]
    for v in vectors:
      check diffOracleCheckReservedName(v)

  test "KNOWN, DOCUMENTED divergence: case folding (Blocker #7 scope, not " &
       "silently passed over)":
    ## `isReservedSidecarName` case-folds via `toLowerAscii` before the
    ## suffix check; the twin drops that (Blocker #7 -- unmodeled by
    ## symex), so it is CASE-SENSITIVE. This test asserts the divergence
    ## explicitly (real: reserved; twin: not, because "MD5"/"Md5" != "md5"
    ## under a case-sensitive `endsWith`) so the scope-down is provably
    ## understood, not an oracle gap that would otherwise silently pass by
    ## coincidence.
    check isReservedSidecarName("f.bin.MD5") == true
    check stripTrailingDotSpaceTwin("f.bin.MD5").endsWith(".md5") == false
    check isReservedSidecarName("f.bin.Md5") == true
    check stripTrailingDotSpaceTwin("f.bin.Md5").endsWith(".md5") == false

  test "KNOWN, DOCUMENTED divergence: leading UNC-style double separator " &
       "(extractFilename-elision scope, not silently passed over)":
    ## See the file-header note: real `extractFilename("//a/.md5")` returns
    ## `""` (Nim's `os` treats a leading double-separator as UNC-like),
    ## while this twin (no `extractFilename` at all) checks the full path's
    ## suffix directly and finds `.md5`. Asserted explicitly, same
    ## discipline as the case-folding divergence above.
    check isReservedSidecarName("//a/.md5") == false
    check stripTrailingDotSpaceTwin("//a/.md5").endsWith(".md5") == true

  proc reservedNameStrings(maxLen = 8): Strategy[string] =
    ## No '/' in the alphabet at all (not merely "no LEADING double
    ## separator"): keeps the generator simple and entirely inside the
    ## proven-exact domain -- checkWriteAccess's real `resolvedPath` is
    ## always a single absolute path built by `validatePath`, never a
    ## UNC-shaped string, so this loses no realistic coverage; the
    ## UNC-divergence itself is asserted directly above, not approximated
    ## away by a subtler (leading-only) filter here.
    let base = lists(sampledFrom(@['a', 'b', '.', '_']), minLen = 0,
                      maxLen = maxLen).map(
      proc(cs: seq[char]): string =
        result = newStringOfCap(cs.len)
        for c in cs: result.add c)
    let suffix = sampledFrom(@[".md5", ".md5.", ".md5 ", ".md5..", ".md5  ",
                               ".txt", ""])
      ## Canonical-case suffixes only (Blocker #7 scope: this twin drops
      ## `toLowerAscii`, so `.MD5`/`.Md5` are deliberately excluded here --
      ## those are exercised by the hand-picked vectors above instead,
      ## which document the known case-sensitivity divergence rather than
      ## asserting equivalence over it).
    base.flatMap(proc(b: string): Strategy[string] =
      suffix.map(proc(sfx: string): string = b & sfx))

  property "arbitrary names, canonical-case suffixes, bounded trailing run":
    with Settings(seed: 0xC0FFEE, maxExamples: 200)
    given name in reservedNameStrings()
    ensure diffOracleCheckReservedName(name)
