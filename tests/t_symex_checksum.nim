## Symex no-Defect proof for `checksum.writeSidecar`'s LEXICAL sidecar-path
## derivation (RFC verification-harness-v2.md Part B, slice B3, Target 1).
## Opt-in, z3 image only (t_symex* convention -- auto-selected by
## dev-test.ps1's `-like "t_symex*"` rule; no per-file registration needed):
##   pwsh scripts/dev-test.ps1 -Only @('t_symex_checksum') -Image chapulin-symex:2.2.10
##
## Read `tests/t_symex_decode.nim` (B1) and `tests/t_symex_security.nim` /
## `tests/t_symex_uri.nim` (B2) FIRST -- this file reuses their twin-
## extraction + differential-oracle discipline.
##
## ---- Toolchain fit: this target needs NO extraction wall-dodge at all ----
## `writeSidecar`'s full body (checksum.nim:59-92) does real I/O
## (`validateWritePath`, `symlinkExists`, `writeFile`) -- same unmodeled-
## syscall class as B2's Target 1 (`validatePath`/`checkWriteAccess`), so the
## shipped proc itself is not a candidate for `symexFind` (same wall: those
## calls are absent from `smt/stdlib_models.nim`'s `OpaqueEffectfulProcs`
## allowlist). But the PURE LEXICAL PREFIX the RFC scopes this slice to --
## the sidecar-path derivation itself (checksum.nim:80: `resolvedPath &
## SidecarExt`) -- runs entirely BEFORE any of those I/O calls and is a
## single `&`-concat with NO loop and NO branch: `string` is a supported
## symex witness (`itString`), `&`-concat is a modeled string op
## (`iekStrConcat`, confirmed by `t_symex_security.nim`'s own Blocker #10
## note: `&` is fine, only in-place `.add` is not), and there is nothing
## here for Blocker #9 (loop+string) to trigger -- no loop at all. This is
## the "if the derivation is a simple &-concat with no loop, it may be
## provable near-directly" case the task anticipated; no twin-extraction
## gymnastics needed beyond copying the one line as its own target proc
## (still test-only per the RFC's "twins live in test code" rule -- the
## shipped `writeSidecar` is not modified and not itself the symex target).
##
## ---- proptest 0.1.0 re-evaluation (2026-08): no change needed ------------
## This target never had a workaround to revisit (see above -- it was
## already the simplest possible shape, one `&`-concat, no loop). Re-verified
## green under 0.1.0 unmodified.
##
## ---- proptest 0.3.1 PRIORITY 1 finding: 0.1.0's "green" was VACUOUS -------
## `discard resolvedPath & SidecarExt` is `discard <call>` (`&` is, in the
## typed AST, a call to the `&` proc) -- dsl_parser.nim's `nnkDiscardStmt`
## arm only lowers a discarded call for two allowlisted intrinsics
## (getCurrentException(Msg)/parseInt/parseBiggestInt); every other
## discarded call, including this `&` concat, becomes `mkBlock(@[])`, a
## complete no-op. So this file's ENTIRE proof, from its very first version,
## was vacuous: `&`-concat was NEVER lowered, meaning nothing was ever
## walked/checked at all, and the "no change needed, re-verified green"
## note above never actually re-verified anything.
##
## Fixed (this pass) by making the concat genuinely non-`discard`ed -- and
## that surfaces a NEW, genuine finding: a bare `resolvedPath & SidecarExt`,
## once actually walked, proves only `sxUnknown`, not `sxUnsat`, REGARDLESS
## of how the result is consumed (measured three ways: `let`-bound and
## unread; `let`-bound then `discard`ed by name; consumed directly as an
## `if`-condition with no naming at all -- all three `sxUnknown`) and
## regardless of an extra, always-true guard statement preceding it
## (measured a fourth way -- still `sxUnknown`). This is NOT the same
## mechanism as t_symex_decode.nim's/t_symex_security.nim's refined
## Blocker #9 (interprocedural `while`-loop inlining): `&`-concat has no
## loop and is a native, built-in-modeled IR node (`iekStrConcat`), not an
## interprocedurally-inlined user proc. It is also NOT explained by "any
## concat of an unconstrained string is unprovable" -- t_symex_security.nim's
## `validatePathLexicalTwin` genuinely proves `sxUnsat` for an analogous
## `rootDir & "/" & cleanName` concat on an equally-unconstrained `rootDir`
## parameter. The two differ in that `validatePathLexicalTwin`'s concat sits
## after several prior guard statements and its result is consumed by a
## further real call (`isWithinTwin`); this file's minimal target has
## neither, and swapping in a trivial preceding guard did not change the
## verdict. The exact solver-side root cause is NOT fully characterized by
## this pass's budget -- documented honestly here as a genuine,
## previously-vacuity-masked finding, not papered over by re-adding a
## `discard`. See the suite below, which asserts the honest `sxUnknown`
## verdict rather than a stale, never-actually-proven `sxUnsat`.
##
## ---- TIGHTENED to sxUnsat (A6, RFC-chapulin-hardening, 2026-08) ----------
## The `sxUnknown` gap documented immediately above was never characterized
## to a root cause by that pass's budget -- it has since closed, silently,
## as a side effect of engine work between 0.3.1 and 0.4.0 (not itself a
## variant-construction change; this target has no variant in it at all).
## Retested empirically against nelli 0.4.0: the same bare
## `resolvedPath & SidecarExt`, consumed the same non-`discard`ed way, now
## proves `sxUnsat` cleanly. This is exactly the condition this file's own
## finding above anticipated ("a future proptest pin that closes this gap
## turns this test red, signalling tighten back to sxUnsat") -- the two
## canary assertions below are now tightened accordingly. The historical
## finding above is left intact as the record of what was true at 0.3.1.
import std/[unittest, os]
import nelli
import nelli/symex
import ../src/chapulin/checksum
import ../src/chapulin/security
import fuzzsupport

# ---- Symex target: the lexical path-derivation prefix ----------------------
#
# Void target (no string RETURN) -- mirrors B1/B2's convention
# (`decodeFixedArmsTwin`, `validatePathLexicalTwin`, `isReservedSidecarNameSymexTwin`
## are all void, `discard`-ing their computed value) rather than risk an
# untested return-type path; nothing here needs the value back inside the
# symex-scoped proof, only that computing it never raises/crashes.

proc sidecarPathTwin(resolvedPath: string) =
  ## PRIORITY 1 (proptest 0.3.1 discard-vacuity fix): consume the `&`-concat
  ## via an `if` condition -- never `discard`ed, never `let`-bound (both
  ## also measured; see the file-header finding above for why binding
  ## shape doesn't matter here). Non-vacuous: this genuinely lowers
  ## `iekStrConcat`.
  if (resolvedPath & SidecarExt).len >= 0:
    discard

suite "symex: checksum.writeSidecar lexical sidecar-path derivation":
  ## TIGHTENED (A6, RFC-chapulin-hardening; walker >=77): this file's own
  ## doc comment (above) said to tighten these two assertions back to
  ## `sxUnsat` once the engine's solver-capability gap on a bare `&`-concat
  ## closed -- confirmed against nelli 0.4.0: this proc's `&`-concat
  ## (`iekStrConcat`, no loop, no variant construction involved -- the
  ## engine change that closed this gap is unrelated to A0-A5's variant
  ## work) now proves `sxUnsat` cleanly. This was the "1 red" left over from
  ## the chapulin proptest->nelli rename absorption's own suite run (its own
  ## canary firing, expected and now resolved here, not a regression).
  test "compiles under symexFind (twin shape is walkable)":
    let r = symexFind(sidecarPathTwin, tIndexError())
    discard r  # compiling to this line + the check below IS the proof

  test "IndexError search: sxUnsat (solver capability gap CLOSED at 0.4.0 -- see above)":
    check symexFind(sidecarPathTwin, tIndexError()).status == sxUnsat

  test "FieldDefect search: sxUnsat (solver capability gap CLOSED at 0.4.0 -- see above)":
    check symexFind(sidecarPathTwin, tFieldDefect()).status == sxUnsat

# ---- Differential oracle: twin's derivation == the shipped derivation -----
#
# The real `sidecar` local inside `writeSidecar` is not itself observable
# (it's a proc-local var, not returned) -- so this compares INDIRECTLY but
# exactly: when `writeSidecar` reports `ok`, it must have just written the
# digest text to precisely the path this twin's value-returning mirror
# predicts. A divergence between the twin's derivation and the real one
# would manifest as either a missing file at the predicted path, or (were
# the two derivations to differ in a way that still produced SOME file) a
# file at the WRONG path -- `fileExists` at the exact predicted path catches
# both. Runs the REAL `writeSidecar` (ordinary compiled Nim, not a symex
# target) against a disposable temp root, mirroring `t_checksum.nim`'s own
# "writeSidecar LEXICAL fuzz target" setup (disposable OS temp dir, not the
# committed fixture tree, since this target performs a real write).

proc sidecarPathDecision(resolvedPath: string): string =
  ## Value-returning mirror of `sidecarPathTwin`, for oracle use (ordinary
  ## runtime code, not a symex target -- string RETURN is fine outside the
  ## walker).
  resolvedPath & SidecarExt

let symexChecksumFuzzRoot = getTempDir() / "chapulin_symex_checksum_root"

proc writeSidecarPathOracle(resolvedPath: string): bool =
  ## TOTAL w.r.t. anything but the (false, err) return: no `except` here at
  ## all, matching `t_checksum.nim`'s own `writeSidecarOracle` style -- any
  ## exception/Defect escaping `writeSidecar` itself is the finding, not
  ## this oracle's job to catch. When containment/IO rejects (`ok == false`)
  ## the twin makes no claim (nothing was written to compare against).
  let (ok, _) = writeSidecar(symexChecksumFuzzRoot, resolvedPath, "deadbeef")
  if not ok:
    return true
  fileExists(sidecarPathDecision(resolvedPath))

proc benignNameStrings(maxLen = 12): Strategy[string] =
  lists(sampledFrom(@['a', 'b', 'c', 'x', '1', '2', '_', '-']),
        minLen = 1, maxLen = maxLen).map(charsToStr)

suite "writeSidecar path-derivation differential oracle setup":
  test "create disposable oracle root":
    createDir(symexChecksumFuzzRoot)
    check dirExists(symexChecksumFuzzRoot)

suite "differential oracle: sidecarPathTwin(resolvedPath) === writeSidecar's own derivation":
  test "hand-picked in-root names":
    let vectors = @[
      symexChecksumFuzzRoot / "plain.txt",
      symexChecksumFuzzRoot / "with.dots.bin",
      symexChecksumFuzzRoot / "UPPER.TXT",
    ]
    for v in vectors:
      check writeSidecarPathOracle(v)

  property "arbitrary benign in-root names":
    with Settings(seed: FuzzSeed, maxExamples: FuzzN)
    given name in benignNameStrings()
    ensure writeSidecarPathOracle(symexChecksumFuzzRoot / name)

suite "writeSidecar path-derivation differential oracle cleanup":
  test "remove disposable oracle root":
    removeDir(symexChecksumFuzzRoot)
    check not dirExists(symexChecksumFuzzRoot)
