## Toolchain smoke test for the opt-in symbolic-execution suite.
##
## Confirms the z3-extended image (`Dockerfile.symex`) is wired end-to-end:
## proptest/symex's `import z3` resolves (milpa `--path`), softlink's
## compile-time `_Static_assert` passes against `z3.h`, softlink loads `libz3`
## at runtime via `ensureLoaded()`, and a real Z3 C-API call returns.
##
## This needs the z3-extended image + Z3 headers on the C include path, so it is
## deliberately kept OUT of `dev-test.ps1`'s default array. Run it opt-in:
##   pwsh scripts/dev-test.ps1 -Only t_symex_smoke -Image chapulin-symex:2.2.10
##
## (Header include path comes from the auto-loaded `t_symex_smoke.nim.cfg`.)
import std/unittest
import std/strutils
import z3

suite "z3 toolchain smoke":
  test "libz3 loads and reports a version":
    let v = z3FullVersion()      # ensureLoaded() -> Z3_get_full_version()
    check v.len > 0
    # nim-z3 main returns the bare dotted version, e.g. "4.13.4.0" (older
    # bindings prefixed "Z3 "). Assert it's a real version: leading digit + dot.
    check v[0] in {'0'..'9'}
    check '.' in v
