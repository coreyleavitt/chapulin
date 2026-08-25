## Symex proof/witness targets over chapulin's option-validation idiom.
## RFC verification-harness.md, Slice 9 (D4/D9). Opt-in, z3 image only:
##   pwsh scripts/dev-test.ps1 -Only t_symex -Image chapulin-symex:2.2.10
## (auto-selected via the `t_symex*` convention in dev-test.ps1 -- kept out of
## the default suite array for the same reason t_symex_smoke is: it needs the
## z3-extended image, not the base toolchain image. See t_symex_smoke.nim for
## that precedent; this file's `.nim.cfg` mirrors it.)
##
## `symexFind` has no witness reader for `seq[(string, string)]` -- the real
## `negotiateServerOptions`/`validateAndParseOack` signatures in
## src/chapulin/options.nim -- it errors at macro-expansion on that param
## shape (proptest/symex.nim's `emitTyAndReader` has no `itSeq` case for a
## tuple element type). Per D4/D9's resolution, each targeted option-key ARM
## is mirrored below as a small `val: string` TWIN: same parseInt/
## parseBiggestInt call, same try/except (or deliberate lack of one), same
## bounds check, same raise/early-return site as the real arm it stands in
## for -- just wearing a witness-friendly single-string signature. Twins are
## test-only fixtures, never shipped; they exist purely so z3 can crawl the
## real validation idiom's shape. Each twin's doc-comment cites the exact
## options.nim lines it mirrors.
##
## Two families, matching the two real functions D9 names
## (options.nim:66 validateAndParseOack, options.nim:143 negotiateServerOptions):
##
##   * CLIENT twins mirror validateAndParseOack's arms, which wrap
##     parseInt/parseBiggestInt in `try/except ValueError: return reject(...)`
##     (options.nim:100-139) -- a non-numeric OACK value from a hostile/buggy
##     SERVER is caught and turned into a clean rejection, never an escaping
##     exception. `tRaisedExn("ValueError")` is expected **sxUnsat** here: a
##     bounded proof the try/except really does swallow every ValueError this
##     arm's shape can produce.
##   * SERVER twins mirror negotiateServerOptions's arms, which call
##     parseInt/parseBiggestInt **uncaught** (options.nim:157-216; the
##     timeout arm's own comment at :205-206 says it plainly: "a syntactically
##     unparseable value still raises ValueError from parseInt above,
##     unwinding to the caller's ERROR(8) catch") -- a non-numeric option from
##     a hostile/buggy CLIENT is meant to propagate. `tRaisedExn("ValueError")`
##     is expected **sxRaised** here: a constructive witness confirming that
##     design intent (server.nim's caller is the one responsible for catching
##     it into ERROR(8), not this proc).
##
## Neither family touches an array index or a variant-object field, so
## `tIndexError()`/`tFieldDefect()` are expected **sxUnsat** across the board
## -- included per D9's target list as bounded proofs that this modeled
## fragment genuinely has no such path (not vacuous: the walker forks on
## every syntactic `arr[i]`/variant-field read, and these twins have none).
##
## Every `sxRaised`/`sxSat` witness is cross-checked against REAL Nim
## `parseInt` (the `nimParseIntRaises` ground truth below) -- the soundness
## check D9 requires.
##
## B4 UNBLOCKED (tsize twins) -- proptest 0.1.0 models `parseBiggestInt` -----
## The real tsize arms (both functions) call `parseBiggestInt`, not
## `parseInt`. Under proptest 99fa2dbe the symex engine modeled ONLY
## `parseInt` (zero hits for "parseBiggestInt" anywhere under
## `_deps/proptest/src`) -- every target against a `parseBiggestInt`-based
## twin came back `sxUnknown`. v2's B4 slice was gated on this.
##
## 0.1.0 (2026-08 re-evaluation): confirmed by reading `dsl_parser.nim`
## directly (RFC-chapulin-hardening M2) -- `parseBiggestInt(s)` now routes to
## the SAME `iekStrToInt` IR node as `parseInt(s)` (`BiggestInt` is 64-bit on
## this platform, identical to `parseInt`'s result type, so no new IR kind or
## runtime lowering was needed; only the parser's callee-name dispatch grew a
## second name). The `parseInt` substitution is REMOVED below: both tsize
## twins now call the REAL `parseBiggestInt` and both still prove/witness
## exactly as before (`sxUnsat` client-side / `sxRaised` server-side) --
## confirmed empirically, not just from reading the source. B4 is DONE.
import std/[unittest, strutils]
import nelli/symex
import ../src/chapulin/protocol

# ---- Ground truth: what real Nim actually does ------------------------------

proc nimParseIntRaises(s: string): bool =
  ## True iff real Nim `parseInt(s)` raises `ValueError`.
  try:
    discard parseInt(s)
    false
  except ValueError:
    true

proc nimParseBiggestIntRaises(s: string): bool =
  ## True iff real Nim `parseBiggestInt(s)` raises `ValueError`. B4:
  ## dedicated ground truth for the tsize twins now that they call the REAL
  ## `parseBiggestInt` (not the former `parseInt` substitution) -- exact,
  ## not merely "both raise identically" as argued when the substitution
  ## was load-bearing.
  try:
    discard parseBiggestInt(s)
    false
  except ValueError:
    true

# ---- Client twins: validateAndParseOack arms (options.nim:100-139) --------
#
# windowsize/timeout/tsize mirror their real arm exactly (each parses exactly
# one wire value). blksize's real arm (options.nim:101-110) parses TWO values
# (`val` and `reqVal`) inside a single try/except -- the twin below keeps the
# `val`-side parse (the attacker-controlled half; `reqVal` is the client's own
# previously-sent request, not hostile input) and drops the second parse plus
# the `bs > reqBs` cross-check. The try/except's ValueError-handling is
# identical regardless of which of the two parses inside it raises, so
# dropping the second parse does not change the never-escapes proof this twin
# exists to establish.

proc twinClientBlksize(val: string) =
  ## Mirrors validateAndParseOack's "blksize" arm (options.nim:101-110).
  var bs: int
  try:
    bs = parseInt(val)
  except ValueError:
    return
  if bs < MinBlocksize or bs > MaxBlocksize:
    return

proc twinClientTimeout(val: string) =
  ## Mirrors validateAndParseOack's "timeout" arm (options.nim:111-119).
  var t: int
  try:
    t = parseInt(val)
  except ValueError:
    return
  if not validateTimeoutOpt(t):
    return

proc twinClientWindowsize(val: string) =
  ## Mirrors validateAndParseOack's "windowsize" arm (options.nim:120-128).
  var ws: int
  try:
    ws = parseInt(val)
  except ValueError:
    return
  if ws < MinWindowsize or ws > MaxWindowsize:
    return

proc twinClientTsize(val: string) =
  ## Mirrors validateAndParseOack's "tsize" arm (options.nim:129-137). Uses
  ## the REAL `parseBiggestInt` -- see the file-level B4 UNBLOCKED note above.
  var ts: int64
  try:
    ts = parseBiggestInt(val)
  except ValueError:
    return
  if ts < 0:
    return

# ---- Server twins: negotiateServerOptions arms (options.nim:157-216) ------
#
# Each calls parseInt/parseBiggestInt UNCAUGHT, mirroring the real arm's
# documented design (options.nim:205-206: the value "still raises ValueError
# ... unwinding to the caller's ERROR(8) catch"). Bounds constants stand in
# for the real `ServerOptionLimits` param at its protocol-default values
# (MinBlocksize/MaxBlocksize/etc, protocol.nim) since the twin has no
# `limits` param -- the twin's job is the parse+raise shape, not limits
# plumbing.

proc twinServerBlksize(val: string) =
  ## Mirrors negotiateServerOptions's "blksize" arm (options.nim:159-172),
  ## including its REAL `min(limits.maxBlocksize, reqBs)` clamp call.
  ## proptest 0.1.0 (2026-08 re-evaluation): `system.min`/`max` inlining
  ## (previously unsupported -- their stdlib body is an `if`-*expression*, a
  ## node kind the inter-procedural walker couldn't inline) now proves
  ## `sxUnsat` directly, confirmed empirically. Workaround (explicit `if`
  ## clamp) REMOVED.
  let reqBs = parseInt(val)
  if reqBs >= MinBlocksize:
    let bs = min(MaxBlocksize, reqBs)
    discard bs

proc twinServerTimeout(val: string) =
  ## Mirrors negotiateServerOptions's "timeout" arm (options.nim:199-209).
  ## PRIORITY 1 (proptest 0.3.1 discard-vacuity fix): the former
  ## `discard validateTimeoutOpt(t)` dropped that call's expression entirely
  ## -- dsl_parser.nim's `nnkDiscardStmt` arm only lowers a discarded call
  ## for two allowlisted intrinsics (getCurrentException(Msg)/parseInt/
  ## parseBiggestInt); `validateTimeoutOpt` (a real shipped proc, not one of
  ## those) became `mkBlock(@[])` -- a complete no-op, so its own body was
  ## never walked. Fix: bind via `let` (never `discard`ed).
  let t = parseInt(val)
  let validTimeout = validateTimeoutOpt(t)
  discard validTimeout
    # `discard <identifier>` (not `discard <call>`) is harmless -- the call
    # was already lowered at the `let` binding above.

proc twinServerWindowsize(val: string) =
  ## Mirrors negotiateServerOptions's "windowsize" arm (options.nim:210-214),
  ## including its REAL `max(limits.minWindowsize, min(limits.maxWindowsize,
  ## ws))` clamp call -- see twinServerBlksize above (0.1.0 min/max-inlining
  ## fix). Workaround (explicit `if` clamps) REMOVED.
  let ws = max(MinWindowsize, min(MaxWindowsize, parseInt(val)))
  discard ws

proc twinServerTsize(val: string) =
  ## Mirrors negotiateServerOptions's "tsize" arm (options.nim:173-198). Uses
  ## the REAL `parseBiggestInt` -- see the file-level B4 UNBLOCKED note above.
  let clientTsize = parseBiggestInt(val)
  discard clientTsize >= 0

# ---- Client-side (caught) targets: sxUnsat = bounded proof of no escape ----

suite "symex: validateAndParseOack arm twins never let ValueError escape":
  test "blksize twin: ValueError is fully caught (sxUnsat)":
    let r = symexFind(twinClientBlksize, tRaisedExn("ValueError"))
    check r.status == sxUnsat

  test "timeout twin: ValueError is fully caught (sxUnsat)":
    let r = symexFind(twinClientTimeout, tRaisedExn("ValueError"))
    check r.status == sxUnsat

  test "windowsize twin: ValueError is fully caught (sxUnsat)":
    let r = symexFind(twinClientWindowsize, tRaisedExn("ValueError"))
    check r.status == sxUnsat

  test "tsize twin: ValueError is fully caught (sxUnsat)":
    ## Twin uses the REAL `parseBiggestInt` (B4 unblocked -- see the
    ## file-level note).
    let r = symexFind(twinClientTsize, tRaisedExn("ValueError"))
    check r.status == sxUnsat

suite "symex: validateAndParseOack arm twins have no IndexError/FieldDefect path":
  test "blksize twin: no index/field-defect path":
    check symexFind(twinClientBlksize, tIndexError()).status == sxUnsat
    check symexFind(twinClientBlksize, tFieldDefect()).status == sxUnsat

  test "timeout twin: no index/field-defect path":
    check symexFind(twinClientTimeout, tIndexError()).status == sxUnsat
    check symexFind(twinClientTimeout, tFieldDefect()).status == sxUnsat

  test "windowsize twin: no index/field-defect path":
    check symexFind(twinClientWindowsize, tIndexError()).status == sxUnsat
    check symexFind(twinClientWindowsize, tFieldDefect()).status == sxUnsat

  test "tsize twin: no index/field-defect path":
    check symexFind(twinClientTsize, tIndexError()).status == sxUnsat
    check symexFind(twinClientTsize, tFieldDefect()).status == sxUnsat

# ---- Server-side (uncaught) targets: sxRaised = constructive witness -------

suite "symex: negotiateServerOptions arm twins raise ValueError on hostile input (by design)":
  test "blksize twin: ValueError witness, validated against real parseInt":
    let r = symexFind(twinServerBlksize, tRaisedExn("ValueError"))
    check r.status == sxRaised
    check r.raisedTypeId == "ValueError"
    check nimParseIntRaises(r.raisedWitness[0])

  test "timeout twin: ValueError witness, validated against real parseInt":
    let r = symexFind(twinServerTimeout, tRaisedExn("ValueError"))
    check r.status == sxRaised
    check r.raisedTypeId == "ValueError"
    check nimParseIntRaises(r.raisedWitness[0])

  test "windowsize twin: ValueError witness, validated against real parseInt":
    let r = symexFind(twinServerWindowsize, tRaisedExn("ValueError"))
    check r.status == sxRaised
    check r.raisedTypeId == "ValueError"
    check nimParseIntRaises(r.raisedWitness[0])

  test "tsize twin: ValueError witness, validated against real parseBiggestInt":
    ## Twin uses the REAL `parseBiggestInt` (B4 unblocked -- see the
    ## file-level note).
    let r = symexFind(twinServerTsize, tRaisedExn("ValueError"))
    check r.status == sxRaised
    check r.raisedTypeId == "ValueError"
    check nimParseBiggestIntRaises(r.raisedWitness[0])

suite "symex: negotiateServerOptions arm twins have no IndexError/FieldDefect path":
  test "blksize twin: no index/field-defect path":
    check symexFind(twinServerBlksize, tIndexError()).status == sxUnsat
    check symexFind(twinServerBlksize, tFieldDefect()).status == sxUnsat

  test "timeout twin: no index/field-defect path":
    check symexFind(twinServerTimeout, tIndexError()).status == sxUnsat
    check symexFind(twinServerTimeout, tFieldDefect()).status == sxUnsat

  test "windowsize twin: no index/field-defect path":
    check symexFind(twinServerWindowsize, tIndexError()).status == sxUnsat
    check symexFind(twinServerWindowsize, tFieldDefect()).status == sxUnsat

  test "tsize twin: no index/field-defect path":
    check symexFind(twinServerTsize, tIndexError()).status == sxUnsat
    check symexFind(twinServerTsize, tFieldDefect()).status == sxUnsat
