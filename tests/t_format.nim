## Property test for chapulin's display-sanitizer (RFC verification-harness.md,
## "committed fork"): `format.sanitizeForDisplay` makes untrusted strings safe
## to print by replacing control/DEL bytes with '?'. New file — no t_format.nim
## existed before this slice (beside-the-domain convention: a new domain gets
## its own test file). Plain `property` (not coverage-guided — a handful-of-
## lines pure function, per the RFC's own call; no `fuzzProperty`/`{.cover.}`
## needed).
##
## Run in the nim devtools container:
##   docker run --rm -v ${PWD}:C:\app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r tests/t_format.nim

import std/unittest
import nelli
import ../src/chapulin/format

proc arbitraryChars(maxLen = 40): Strategy[string] =
  ## Full 0..255 byte range as chars — the whole space sanitizeForDisplay
  ## must handle, not just a printable-ASCII sample.
  lists(integers(0, 255), minLen = 0, maxLen = maxLen).map(
    proc(xs: seq[int]): string =
      result = newStringOfCap(xs.len)
      for x in xs: result.add chr(x))

suite "sanitizeForDisplay — display-sanitizer property (RFC verification-harness.md, committed fork)":

  property "output never contains a raw control byte (ord<0x20 or 0x7F) except the substituted '?', never a Defect":
    given s in arbitraryChars()
    let sanitized = sanitizeForDisplay(s)
    var ok = true
    for c in sanitized:
      if ord(c) < 0x20 or ord(c) == 0x7f:
        ok = false
    ensure ok

  property "sanitizeForDisplay is one-for-one: output length always equals input length":
    given s in arbitraryChars()
    ensure sanitizeForDisplay(s).len == s.len

  property "bytes >= 0x80 pass through unchanged (valid UTF-8 multibyte sequences preserved)":
    given s in arbitraryChars()
    let sanitized = sanitizeForDisplay(s)
    var ok = true
    for i in 0 ..< s.len:
      if ord(s[i]) >= 0x80 and sanitized[i] != s[i]:
        ok = false
    ensure ok
