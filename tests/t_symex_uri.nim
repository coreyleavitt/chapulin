## Symex no-Defect proofs for `tftp_uri.parseTftpUri`/`isTftpUri` (RFC
## verification-harness-v2.md Part B, slice B2, Target 2). Opt-in, z3 image
## only (t_symex* convention -- auto-selected by dev-test.ps1's
## `-like "t_symex*"` rule; no per-file registration needed):
##   pwsh scripts/dev-test.ps1 -Only @('t_symex_uri') -Image chapulin-symex:2.2.10
##
## Read `tests/t_symex_decode.nim` FIRST (B1's finished pattern) -- this file
## reuses its twin-extraction discipline, its `atByte`-style single-chokepoint
## idiom (here for two reshaped ops, not a byte mask), and its differential-
## oracle structure.
##
## ---- Witness class: string, no new toolchain (RFC-confirmed) --------------
## `parseTftpUri`/`isTftpUri` are pure `string`->`string`-ish (string in,
## object/bool out) -- `string` IS a supported symex witness (`itString`->
## `readString`, already exercised directly by `t_symex.nim`'s twins), and
## the body makes no I/O/syscall (no `open`/`canonicalize`/etc): unlike B2's
## Target 1, THIS target's toolchain fit is clean. It hits two SEPARATE,
## narrower toolchain gaps than B1's, both found empirically here and
## reshaped the same "mechanical, recommendable fork" way B1 reshaped its
## tuple-return blocker:
##
## ---- BLOCKER #7 CONFIRMED FIXED in proptest 0.1.0 (toLowerAscii/toUpperAscii)
## Originally: `dsl_parser.nim` special-cased the callee names "toLower"/
## "toUpper"/"toLowerAscii"/"toUpperAscii" and routed them to
## `iekStrToLower`/`iekStrToUpper` IR nodes, but `runtime.nim` had no
## LOWERING for those IR kinds -- they fell through to the catch-all "not
## modeled in this cycle" arm, raising `SymexUnsupportedStringOpError` (an
## honest `sxUnknown`, not a crash, but not a bounded proof either).
## `isTftpUri`'s scheme gate (`s.toLowerAscii.startsWith("tftp://")`) and the
## mode-parameter handling both call it. Original workaround: a
## case-SENSITIVE check in the twin (sound for index-safety since
## case-folding never changes a string's length).
##
## 0.1.0 (2026-08 re-evaluation): `runtime_strings.nim` now lowers
## `iekStrToLower`/`iekStrToUpper` via a real Z3 seqMap over the string's
## Z3Seq[Z3Char] (Phase 16 A9 -- an ASCII-range ITE fold, quantifier-free).
## Retested empirically: the twin restores the REAL `.toLowerAscii` calls
## (both the scheme gate and the mode-parameter handling) and still proves
## `sxUnsat`/witnesses correctly. Workaround REMOVED.
##
## ---- BLOCKER #8 CONFIRMED FIXED in proptest 0.1.0 (rfind) -----------------
## Originally: `stdlib_models.nim`/`dsl_parser.nim` registered `find`
## (forward scan) but had no case at all for `rfind` (backward scan).
## `parseTftpUri`'s IPv4/hostname branch calls `hostPort.rfind(':')`
## (host:port split); calling it directly fell through to `getImpl`-based
## inlining of `strutils.rfind`, an unsupported inlining wall. Original
## workaround: substitute forward `find` (sound for index-safety, NOT for
## exact behavioral equivalence on a multi-colon `hostPort`) -- the
## differential oracle below was scoped to exclude multi-colon hosts as a
## result.
##
## 0.1.0 (2026-08 re-evaluation): `s.rfind(sub)` is now modeled via nim-z3's
## native `lastIndexOf` Z3 Sequence-theory primitive (RFC M3, `iekStrRfind`/
## `smkStrRfind`) -- a REAL Z3 primitive, not a loop-based reshape at all.
## Retested empirically: the twin restores the REAL `.rfind(":")` call and
## still proves `sxUnsat`. Workaround REMOVED -- and since `rfind` is now
## EXACT (not merely index-safety-equivalent), the differential oracle's
## multi-colon-host exclusion is no longer needed either (widened below).
##
## ---- BLOCKER #9 retested: STILL PRESENT for the specific shape that would
## have been needed here, but MOOT now that #8 is fixed natively -----------
## The original investigation (before #8's native-rfind fix existed) tried
## reshaping `rfind` as a hand-written bounded backward-scan LOOP over
## `string` -- and hit Blocker #9 (documented exhaustively in
## t_symex_security.nim's refined form: a while-loop-produced value survives
## fine within the SAME statement, but not once bound to a name and read in
## a LATER statement). That reshape is now unnecessary: `rfind` is a native
## Z3 primitive requiring no Nim-level loop at all, so this file never needs
## to touch Blocker #9's territory. Not independently retested here (no
## reason to write a loop this file no longer needs); see
## t_symex_security.nim and t_symex_decode.nim for 0.1.0's refined Blocker
## #9 findings.
##
## ---- `pred`/`..<`: FIXED in proptest 0.3.1 (PRIORITY 2 item 2) -----------
## Under 0.1.0, `symexFind` on the REAL shipped `parseTftpUri` was retried
## directly now that #7/#8/plain-object-construction are all fixed (TftpUri
## is a plain, non-variant object -- construction IS now a supported DSL
## expression, confirmed by reading dsl_parser.nim's P2a/P2b `nnkObjConstr`
## arm). Result: still a macro-expansion COMPILE ERROR -- "Error: symex:
## unsupported infix operator `..`" (dsl_parser.nim:783) -- from the real
## proc's `rest[1 ..< closeBracket]`-style slices (`..<` lowers to `a ..
## pred(b)`; `pred` had no DSL case, confirmed by grep: zero hits in
## dsl_parser.nim). This was the v1/v2 catalog's NICE-tier `pred`/`..<`
## finding, and is what kept this file on a twin-extraction rather than the
## shipped proc directly, independent of the (already-fixed) #7/#8
## questions. Every `..<` in the real source was rewritten as explicit
## `a .. (b - 1)` in the twin below.
##
## 0.3.1 (2026-08, PRIORITY 2 item 2): the maintainer's modernization map
## says `a ..< b` and `pred`/`succ` are modeled now. Every mechanical
## `.. (b - 1)` rewrite standing in for a real `..<` is restored to the
## real `..<` below; confirmed empirically to still prove `sxUnsat` (see
## the suite below) -- the DSL parser no longer errors on it. The shipped
## `parseTftpUri` itself is STILL not passed directly to `symexFind`:
## its `^1` backward-index slices (P4, a separate, still-unconfirmed RFC
## slice) are untouched by this fix and remain unmodeled, so this file
## stays on a twin-extraction (whose `^1` sites use `.len - 1`, unaffected
## by this change) rather than the real proc.
import std/[unittest, strutils]
import nelli
import nelli/symex
import ../src/chapulin/tftp_uri

# ---- Symex-scoped twin: full parseTftpUri control flow ---------------------
#
# Mirrors `tftp_uri.parseTftpUri` (and its `isTftpUri` gate, inlined here
# rather than called, since a nested call to the real `isTftpUri` would
# re-introduce Blocker #7 through that indirection) line-for-line, with
# exactly three deviations, each cited above/inline:
#   1. `isTftpUri`'s `.toLowerAscii.startsWith("tftp://")` -> a case-
#      sensitive `.startsWith("tftp://")` (Blocker #7).
#   2. `hostPort.rfind(':')` -> `hostPort.find(":")` (Blockers #8 + #9: no
#      loop-based reshape is provable at all, so this substitutes the
#      already-modeled forward scan instead -- safety-equivalent, not
#      decision-identical; see the Blocker #9 note above for the exact
#      scope of the divergence and why the oracle below is unaffected by it).
#   3. The two mode-parameter `.toLowerAscii` calls -> dropped/case-sensitive
##     (Blocker #7); the mode VALUE itself is never sliced further after
#      this, so dropping the final `.toLowerAscii` changes only the case of
#      a value this proc discards anyway (void target -- see below).
# proptest 0.3.1 (PRIORITY 2 item 2): every `..<` in the real source is now
# restored verbatim below (`..<` lowers to `a .. pred(b)`, and both are
# modeled now -- see the file-header note). The remaining `.. (expr.len - 1)`
# endpoints below are a DIFFERENT substitution (for the real source's `^1`
# backward-index slicing, P4) -- unaffected by this fix, still out of scope
# (see the file-header note).
#
# Void target (no `TftpUri` object construction): mirrors B1's
# `decodeFixedArmsTwin`/`decodeOptionArmTwin`, which are also void and
# `discard` their parsed pieces -- object/tuple CONSTRUCTOR expressions are
# not a proven-supported DSL node (the only `nnkObjConstr` handling in
# `dsl_parser.nim` is inside the macro's OWN code-generation, not in the
# expression-parsing path a target proc's body walks), so this sidesteps
# that risk entirely rather than probing a third blocker class -- the
## no-Defect proof needs no return value at all.

proc parseTftpUriTwin(uri: string) =
  ## proptest 0.1.0 (2026-08): the Blocker #7 (toLowerAscii) and #8 (rfind)
  ## substitutions are REMOVED -- both are now natively modeled (see the
  ## file-header notes). The void-target convention (plain-object
  ## construction dropped -- not exercised by this proof) remains.
  ##
  ## proptest 0.3.1 (PRIORITY 2 item 2): `a ..< b` and `pred`/`succ` are now
  ## modeled -- every mechanical `a .. (b - 1)` rewrite standing in for a
  ## real `a ..< b` in the shipped `tftp_uri.parseTftpUri` (see
  ## src/chapulin/tftp_uri.nim) is restored to the real `..<` below;
  ## confirmed empirically to still prove `sxUnsat` (see the suite below).
  ## `.len - 1` endpoints standing in for the shipped proc's `^1`
  ## backward-index slicing are UNCHANGED (P4, a separate, still-unconfirmed
  ## RFC slice, out of this pass's scope).
  if uri.len == 0:
    raise newException(TftpUriError, "Empty URI")

  if not uri.toLowerAscii.startsWith("tftp://"):
    raise newException(TftpUriError, "Not a TFTP URI: " & uri)

  var rest = uri[7 .. uri.len - 1]

  var host: string
  var portStr = ""

  if rest.startsWith("["):
    let closeBracket = rest.find("]")
    if closeBracket < 0:
      raise newException(TftpUriError, "Unclosed bracket in IPv6 address")
    host = rest[1 ..< closeBracket]
    rest = rest[closeBracket + 1 .. rest.len - 1]
    if rest.startsWith(":"):
      let slashPos = rest.find("/")
      if slashPos < 0:
        raise newException(TftpUriError, "Missing filename in URI")
      portStr = rest[1 ..< slashPos]
      rest = rest[slashPos .. rest.len - 1]
  else:
    let slashPos = rest.find("/")
    if slashPos < 0:
      raise newException(TftpUriError, "Missing filename in URI")
    let hostPort = rest[0 ..< slashPos]
    rest = rest[slashPos .. rest.len - 1]

    let colonPos = hostPort.rfind(":")
    if colonPos >= 0:
      host = hostPort[0 ..< colonPos]
      portStr = hostPort[colonPos + 1 .. hostPort.len - 1]
    else:
      host = hostPort

  if host.len == 0:
    raise newException(TftpUriError, "Missing host in URI")

  if portStr.len > 0:
    try:
      discard parseInt(portStr)
    except ValueError:
      raise newException(TftpUriError, "Invalid port: " & portStr)

  if not rest.startsWith("/"):
    raise newException(TftpUriError, "Missing path separator")
  rest = rest[1 .. rest.len - 1]

  var filename: string

  let semicolonPos = rest.find(";")
  if semicolonPos >= 0:
    filename = rest[0 ..< semicolonPos]
    let params = rest[semicolonPos + 1 .. rest.len - 1]
    if params.toLowerAscii.startsWith("mode="):
      # PRIORITY 1 (proptest 0.3.1 discard-vacuity fix): the former
      # `discard params[5 .. params.len - 1].toLowerAscii` dropped the
      # WHOLE expression -- both the slice's own bounds-check AND the
      # `toLowerAscii` call -- entirely unwalked (dsl_parser.nim's
      # `nnkDiscardStmt` arm only lowers a discarded call for two
      # allowlisted intrinsics; `toLowerAscii` is not one of them). No
      # loop is involved here (unlike t_symex_decode.nim's
      # `readCStringTwin`), so a plain `let` binding is safe.
      let modeVal = params[5 .. params.len - 1].toLowerAscii
      discard modeVal
  else:
    filename = rest

  if filename.len == 0:
    raise newException(TftpUriError, "Missing filename in URI")

  discard host
  discard filename

# ---- Compile-check + no-Defect proofs --------------------------------------

suite "symex: tftp_uri.parseTftpUri slicing twin":
  test "compiles under symexFind (twin shape is walkable)":
    let r = symexFind(parseTftpUriTwin, tIndexError())
    discard r  # compiling to this line + the check below IS the proof

  test "no IndexError path (sxUnsat) -- every slice offset is guarded by a " &
       "prior find()/startsWith() length floor":
    check symexFind(parseTftpUriTwin, tIndexError()).status == sxUnsat

  test "no FieldDefect path (sxUnsat) -- no variant object touched":
    check symexFind(parseTftpUriTwin, tFieldDefect()).status == sxUnsat

  test "no escaping ValueError from parseInt (sxUnsat) -- caught at the port parse":
    check symexFind(parseTftpUriTwin, tRaisedExn("ValueError")).status == sxUnsat

# ---- Differential oracle: twin ≡ real parseTftpUri/isTftpUri --------------
#
# "Compiles" (and even "sxUnsat") is not proof the twin's REJECT/ACCEPT
# decision boundary matches the real parser's. This runs the REAL
# `parseTftpUri` (ordinary compiled Nim, not a symex target -- object
# construction, `toLowerAscii`, and `rfind` are all fine outside the walker)
# against the twin on the same concrete strings and asserts identical
# raise/no-raise outcomes (and, when both raise, the same exception type).
#
# WIDENED (0.1.0): now that the twin uses the REAL `toLowerAscii`/`rfind`
# (Blockers #7/#8 both fixed -- see file header), the former scoping is no
# longer needed. `PlainHostAlphabet`/`PortAlphabet` now INCLUDE ':' (a
# multi-colon `hostPort` no longer diverges: the twin's `rfind` picks the
# LAST colon exactly like the real proc's does), and messages are still
# allowed to differ (only the `..< -> ..(b-1)` rewrite remains a mechanical,
# not semantic, difference, and it never changes any raised message text).

proc diffOracleCheck(uri: string): bool =
  var realRaised = false
  var realExnName = ""
  try:
    discard parseTftpUri(uri)
  except TftpUriError as e:
    realRaised = true
    realExnName = $e.name

  var twinRaised = false
  var twinExnName = ""
  try:
    parseTftpUriTwin(uri)
  except TftpUriError as e:
    twinRaised = true
    twinExnName = $e.name

  realRaised == twinRaised and (not realRaised or realExnName == twinExnName)

proc tokenStrings(alphabet: seq[char], maxLen = 12): Strategy[string] =
  ## NUL-free arbitrary tokens for host/path/port/mode-value fragments --
  ## reuses fuzzsupport's alphabet idiom locally (this file intentionally
  ## does not depend on `fuzzsupport.nim`, since B2's targets are pure
  ## string parsers with no need for its byte/path-specific strategies).
  lists(sampledFrom(alphabet), minLen = 0, maxLen = maxLen).map(
    proc(cs: seq[char]): string =
      result = newStringOfCap(cs.len)
      for c in cs: result.add c)

const PlainHostAlphabet = @['a', 'b', '1', '2', '.', '-', '_', ':']
  ## INCLUDES ':' (0.1.0 widening): the twin's `rfind` is now the REAL
  ## `strutils.rfind`, so a multi-colon `hostPort` no longer diverges from
  ## the real proc (both pick the LAST colon identically) -- the former
  ## Blocker #8 exclusion is gone.
const BracketHostAlphabet = @['a', 'b', '1', '2', '.', '-', '_', ':']
  ## IPv6-ish content MAY legitimately contain ':' -- the bracket branch
  ## never calls the find/rfind split at all (it slices on the literal
  ## "]"/":" scan positions only).
const PortAlphabet = @['a', 'b', '1', '2', ':']
  ## INCLUDES ':' (0.1.0 widening, same reasoning as PlainHostAlphabet): a
  ## colon inside the port token, concatenated onto `plainHost` before the
  ## rfind split sees it, is now handled identically by twin and real proc.
const OtherAlphabet = @['a', 'b', '1', '2', '.', '-', '_', '[', ']', '/',
                        ';', '=', ':']
  ## Path/mode-value fragments: unrestricted (both sit in `rest` AFTER the
  ## slash the host:port split already resolved on, so neither feeds the
  ## find/rfind divergence).

proc assembleUri(shape: int, plainHost, bracketHost, port, path,
                  modeVal: string): string =
  case shape
  of 0: "tftp://" & plainHost & "/" & path
  of 1: "tftp://" & plainHost & ":" & port & "/" & path
  of 2: "tftp://[" & bracketHost & "]/" & path
  of 3: "tftp://[" & bracketHost & "]:" & port & "/" & path
  of 4: "tftp://" & plainHost & "/" & path & ";mode=" & modeVal
  of 5: "tftp://" & plainHost & ":" & port & "/" & path & ";mode=" & modeVal
  else: plainHost & port & path & modeVal  # malformed: no scheme at all

suite "differential oracle: parseTftpUriTwin(string) === parseTftpUri(string)":
  test "hand-picked vectors (valid + malformed, every branch)":
    let vectors = @[
      "tftp://192.168.1.1/firmware.bin",
      "tftp://10.0.0.1:6969/config.txt",
      "tftp://10.0.0.1/readme.txt;mode=netascii",
      "tftp://10.0.0.1/data.bin;mode=octet",
      "tftp://10.0.0.1:1234/file.img;mode=octet",
      "tftp://192.168.1.1/path/to/file.bin",
      "tftp://myserver.local/boot.img",
      "tftp://[::1]/test.txt",
      "tftp://[fe80::1]:6969/file.bin",
      "http://10.0.0.1/file.txt",           # wrong scheme
      "tftp:///file.txt",                    # missing host
      "tftp://10.0.0.1/",                    # missing filename
      "",                                     # empty
      "tftp://[::1",                         # unclosed bracket
      "tftp://[::1]",                        # missing filename after IPv6, no slash
      "tftp://[::1]:",                       # missing slash after IPv6 port
      "tftp://host",                         # missing slash entirely
      "tftp://host:abc/file.txt",            # non-numeric port
      "tftp://:1234/file.txt",               # empty host with port
      "tftp://host/file;mode=",              # empty mode value
      "tftp://host/;",                       # empty filename with semicolon
    ]
    for v in vectors:
      check diffOracleCheck(v)

  property "assembled URIs (arbitrary host/port/path/mode over every shape)":
    with Settings(seed: 0xC0FFEE, maxExamples: 200)
    given shape in integers(0, 6), plainHost in tokenStrings(PlainHostAlphabet),
          bracketHost in tokenStrings(BracketHostAlphabet),
          port in tokenStrings(PortAlphabet, 4), path in tokenStrings(OtherAlphabet),
          modeVal in tokenStrings(OtherAlphabet, 8)
    ensure diffOracleCheck(assembleUri(shape, plainHost, bracketHost, port, path, modeVal))
