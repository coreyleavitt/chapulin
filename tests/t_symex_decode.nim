## Symex no-Defect proofs for `protocol.decode` (RFC verification-harness-v2.md
## Part B, slice B1). Opt-in, z3 image only (t_symex* convention -- auto-
## selected by dev-test.ps1's `-like "t_symex*"` rule, same as t_symex.nim /
## t_symex_smoke.nim; no per-file registration needed):
##   pwsh scripts/dev-test.ps1 -Only @('t_symex_decode') -Image chapulin-symex:2.2.10
##
## ---- BLOCKER #1 PARTIALLY FIXED in proptest 0.1.0 --------------------------
## Originally: `decode(data: seq[byte])` could not be passed to `symexFind`
## directly -- `seq[byte]` (== `seq[uint8]`) had no witness reader in
## proptest/symex.nim's `emitTyAndReader` (`itSeq` only special-cased
## `seq[int]` (signed 64-bit) / `seq[float32]` / `seq[float64]` / `seq[ref T]`).
##
## 0.1.0 (2026-08 re-evaluation): `symex.nim`'s `itSeq` reader now has a case
## for EVERY fixed-width int element type (`byte`/`uint8..uint64`,
## `int8..int32` -- RFC-chapulin-hardening M1), confirmed by reading the
## source. `seq[byte]` genuinely has a witness reader now -- the witness half
## of Blocker #1 is FIXED. But retested empirically (kept as the file's own
## record, see the BLOCKER #3 note below): a `seq[byte]`-typed twin using the
## REAL bitwise combine (`shl`/`or`) for the big-endian read, with the
## combined value then used in a subsequent boolean guard (`wireOp < 1 or
## wireOp > 6`) -- decode's own exact shape -- CRASHES natively (same
## `inner.kind == svBool` assertion class as Blocker #3, a different call
## site than originally cited). So `seq[byte]` is witness-readable, but this
## file still cannot USE it end-to-end for the big-endian/opcode-dispatch
## composition without hitting Blocker #3's crash -- PARTIALLY fixed, twins
## below stay on the `seq[int]`-masked + arithmetic-combine shape.
##
## ---- BLOCKER #2 CONFIRMED FIXED in proptest 0.1.0 --------------------------
## Originally found empirically: even before the seq[byte] issue is reached,
## `symexFind(decode, ...)` failed while INLINING `decode`'s callee
## `readCString` (protocol.nim:96-105), whose body ends `return (s, i + 1)`
## -- a TUPLE-CONSTRUCTOR expression the DSL parser had no case for at all
## (`99fa2dbe`'s only `nnkTupleConstr` handling was a `yield (e1, e2)`
## special case for multi-var `for` iteration -- nothing for an ordinary
## tuple-literal expression). The original workaround: since `var`
## out-parameters ARE a supported, first-class DSL construct, every twin
## helper returned its *primary* result normally and threaded any *second*
## value out through a `var` parameter instead of a tuple.
##
## proptest 0.1.0 (2026-08 re-evaluation): `dsl_parser.nim` now has a general
## `of nnkTupleConstr:` expression-parsing arm (RFC-chapulin-hardening P1),
## confirmed by reading the source (not just re-running the old workaround).
## Retested empirically: `readCStringTwin` below now uses the REAL tuple
## RETURN shape (`(string, int)`, no var-out-param reshape) and proves
## `sxUnsat` cleanly at both its call sites (`decodeFixedArmsTwin`'s opError
## arm, `decodeOptionArmTwin`'s filename scan) -- both are single,
## non-looped call sites; Blocker #5 (var-out-param call FROM INSIDE a loop
## crashes) is untouched by this change and is orthogonal (it was never
## about the tuple-vs-var-out-param mechanism, only about loop-wrapped
## calls). Workaround REMOVED.
##
## Seq SLICING (`data[4 .. ^1]`) is ALSO unsupported by the same parser (only
## a single-index `s[i]` is modeled for `itSeq`; string slicing is special-
## cased, seq slicing is not) -- `decodeFixedArmsTwin`'s DATA arm below notes
## the point-substitute it uses instead (both slice endpoints touched
## directly under the same length guard, not a loop).
##
## ---- Twin shape --------------------------------------------------------
## `seq[int]` MASKED to the `[0,255]` domain a real byte occupies, at EVERY
## element access (never asserted once) via the single `atByte` chokepoint
## below -- this is chapulin's existing house idiom for this exact
## conversion (`tests/fuzzsupport.nim`'s `toByteSeq`: `byte(x and 0xFF)` per
## element), just applied at READ time instead of at upfront conversion
## time, since the symex target takes `seq[int]` directly (no upfront
## seq[byte] ever exists for the solver to reason about).
import std/[unittest, sequtils, strutils]
import nelli
import nelli/symex
import ../src/chapulin/protocol
import fuzzsupport

# ---- Shared masked-access primitive (single chokepoint) --------------------

## ---- BLOCKER #3 FIXED in proptest 0.3.1 (PRIORITY 2 item 1) ---------------
## Originally: the obvious `data[i] and 0xFF` mask + `(hi shl 8) or lo`
## combine on a PLAIN `int` (the only witness-readable seq element type at
## the time) crashed the walker at RUN time: `AssertionDefect` at
## `runtime.nim:2886` (`doAssert inner.kind == svBool`) -- a plain int has no
## fixed width to promote to a bitvector from, so `bAnd`/`bOr`/`bShl` on it
## is an uncaught assert, not a classified `sxUnknown`.
##
## 0.1.0 re-evaluation: now that `seq[byte]` elements ARE fixed-width
## (Blocker #1's witness reader, above), retested with a genuinely
## fixed-width bitvector operand -- `readU16Natural(data: seq[byte], ...):
## uint16` combining via real `shl`/`or`. Bisected empirically (probes not
## kept, per this file's established scratch-code convention): the bitwise
## combine ALONE compiles/runs fine; a `wireOp < 1 or wireOp > 6` boolean
## guard on a bare symbolic `uint16` ALONE also compiles/runs fine; but the
## COMBINATION -- a bitwise-combined value fed into a subsequent boolean
## guard, i.e. `decode`'s own real shape -- crashed natively with the SAME
## `inner.kind == svBool` assertion, this time at `runtime.nim:3155` (a
## different call site than the original :2886, reached via `lowerBool`/
## `lowerBoolInExpr` rather than the original path -- same assertion class,
## a new trigger shape). Blocker #3 was NOT fixed for this composition
## under 0.1.0; the arithmetic-mask workaround stayed in place.
##
## 0.3.1 (2026-08, PRIORITY 2 item 1): the maintainer's modernization map
## says the inline bitwise-combine + downstream boolean-guard composition
## (this exact D1c parser crash) is fixed. Retested empirically: `atByte`
## now uses the real `and 0xFF` mask and `readU16Twin` the real `(hi shl 8)
## or lo` combine, whose result (`wireOp`) still feeds a subsequent boolean
## guard (`wireOp < 1 or wireOp > 6`) exactly as before -- confirmed via
## the suites below: STILL `sxUnsat` for opData/opAck (strong), and the
## differential oracle (which exercises the real bitwise path against real
## `decode` on concrete bytes) still passes. Workaround REMOVED.
proc atByte(data: seq[int], i: int): int =
  ## Mask a seq[int] element to the [0,255] domain a real `byte` occupies --
  ## real bitwise `and 0xFF` (Blocker #3 fixed, proptest 0.3.1) -- applied AT
  ## THIS CALL SITE, i.e. at every single element read the twins below
  ## perform. Every other proc in this file reads a "byte" ONLY through this
  ## proc; there is no second, unmasked read path anywhere below.
  ## Cross-checked against real `and 0xFF` by the differential oracle
  ## further down (which calls this SAME proc, not a copy -- a divergence
  ## here would fail that check; moot now that this IS real `and 0xFF`, but
  ## kept as the single chokepoint discipline).
  data[i] and 0xFF

proc readU16Twin(data: seq[int], offset: int): int =
  ## Twin of protocol.nim's private `readUint16BE` (line ~90-94). No tuple
  ## involved (single int return) -- unaffected by Blocker #2. The
  ## big-endian combine is the real `(hi shl 8) or lo` (Blocker #3 fixed,
  ## proptest 0.3.1) -- safe/equivalent regardless of bit overlap since
  ## `hi`/`lo` are always `atByte`'s output (constrained to [0,255]) and the
  ## shift/or is the REAL operation `protocol.nim`'s `readUint16BE` performs.
  ##
  ## BLOCKER #4 FOUND EMPIRICALLY (bisected in a scratch harness, not kept
  ## in this file): a non-void proc whose body's LAST STATEMENT is a bare
  ## expression referencing an EARLIER `let`/`var` local as its IMPLICIT
  ## return crashes the walker with `KeyError: key not found: <name>`
  ## (`runtime.nim:2629`'s `env[e.vname]`) -- reproduced with inputs as
  ## trivial as `let hi = data[offset] mod 256; hi + 1`, with NO bitwise
  ## ops and NO nested proc calls involved, so it is unrelated to Blocker
  ## #3. Bisection isolated the exact trigger: it is specifically the
  ## IMPLICIT tail-expression return form -- an EXPLICIT `return <expr
  ## using a local>` (as `readCStringTwin` below already does) and an
  ## EXPLICIT `result = <expr using a local>` both work fine; only the
  ## bare-tail-expression form breaks. Fix applied here: `result =`
  ## instead of a bare tail expression.
  if offset + 2 > data.len:
    raise newException(TftpDecodeError,
      "Truncated packet: need 2 bytes at offset " & $offset)
  let hi = data[offset] and 0xFF
  let lo = data[offset + 1] and 0xFF
  result = (hi shl 8) or lo

proc readCStringTwin(data: seq[int], offset: int): (string, int) =
  ## Twin of protocol.nim's private `readCString` (line ~96-105). proptest
  ## 0.1.0 finding (2026-08): Blocker #2 (no `nnkTupleConstr` case in the DSL
  ## parser) is CONFIRMED FIXED -- `dsl_parser.nim` now has a general
  ## `of nnkTupleConstr:` expression arm (RFC-chapulin-hardening P1). Retested
  ## empirically: the REAL tuple-return shape (no var-out-param reshape)
  ## proves `sxUnsat` for every single-call-site use below (both callers here
  ## call this once per branch, never from inside a loop -- Blocker #5, still
  ## untested/unrelated, was specifically about a var-out-param call FROM
  ## INSIDE a loop; this proc's OWN internal `while` is unaffected either way
  ## since it returns directly from inside the loop body, never binding the
  ## loop-produced offset to a name read in a later statement -- see
  ## t_symex_security.nim's refined Blocker #9 finding for why that
  ## distinction matters). Workaround REMOVED; this is now a byte-for-byte
  ## copy of the real `readCString`'s control flow (mod the seq[int] mask).
  var s = ""
  var i = offset
  while i < data.len:
    let b = atByte(data, i)
    if b == 0:
      return (s, i + 1)
    s.add char(b)
    i.inc
  raise newException(TftpDecodeError, "Unterminated string at offset " & $offset)

# ---- Symex-scoped twin #1: fixed-size arms (opData/opAck/opError) ---------
#
# Mirrors protocol.decode's header check + the opData/opAck/opError arms
# (protocol.nim:151-190) exactly, including the `readCString` call opError
# makes for its error message. Deliberately does NOT model opRRQ/opWRQ/
# opOACK (that would drag in `readOptions`' loop into THIS proof's solver
# cost -- decodeOptionArmTwin's job, kept separate per the RFC's scope
# split).
#
# ---- SPLIT (proptest 0.3.1, PRIORITY 1 discard-vacuity fix) --------------
# opData/opAck (below) vs opError (decodeFixedArmsErrorTwin, further down)
# used to be ONE combined proc. Splitting them is NEW as of this pass: fixing
# the opError arm's `discard readU16Twin(...)`/`discard readCStringTwin(...)`
# vacuity (the callee was never walked at all -- see the PRIORITY 1 note
# below) means `readCStringTwin`'s internal `while` loop is now GENUINELY
# interprocedurally inlined -- and that surfaces a genuine, previously-masked
# solver-capability gap: even a SOLO (non-chained, literal-offset)
# `readCStringTwin` call only proves `sxUnknown`, not `sxUnsat`, once
# actually walked (confirmed via an isolated scratch probe, not kept: a bare
# `if readCStringTwin(data, 0)[0].len >= 0: discard` with NO other logic at
# all also comes back `sxUnknown`). Since opData/opAck never call
# `readCStringTwin`, splitting them out recovers a real, strong `sxUnsat`
# proof for those two arms instead of leaving them dragged down to
# `sxUnknown` by opError's now-honestly-unprovable readCStringTwin call
# (ADR-0012 D2: one `sxUnknown` segment with no `sxSat`/`sxRaised` anywhere
# makes the WHOLE combined-function verdict `sxUnknown`). See
# decodeFixedArmsErrorTwin below for the full finding writeup.

## BLOCKER #11 FOUND EMPIRICALLY, walker v85 (2026-08-16, A6 retest against
## 0.4.1): `decodeFixedArmsTwin`/`decodeOackArmTwin` (below) construct
## `TftpPacket`'s `uint16` fields (`blockNum`/`ackBlockNum`) via
## `uint16(<int-typed value>)` -- a NARROWING conversion from the file's
## legacy `seq[int]`-masked representation (`readU16Twin` returns plain
## `int`). B2 (round-6, walker v79-80) intentionally classifies NARROWING
## int conversions as a decline, not a crash -- "Scope locks (round-2):
## NARROWING (uint8(x) truncation) and same-width signedness
## reinterpretation are CLASSIFIED DECLINES" -- so this is working exactly
## as B2 designed it, not a new engine gap: any proc containing a narrowing
## cast degrades to `sxUnknown` for the whole run (ADR-0012 D2), same as an
## unmodeled construct anywhere else. Bisected in isolation (scratch probe,
## not kept): `uint16(n)` where `n: int` alone (no seq field, no variant, no
## Bug #2 involvement at all) reproduces the degrade; `blockNum: int`
## (no narrowing) proves clean.
##
## The REAL `decode()` never narrows here -- `readUint16BE` (protocol.nim)
## takes `seq[byte]` and does `(uint16(data[offset]) shl 8) or
## uint16(data[offset + 1])`: `data[offset]` is ALREADY `byte`-typed (every
## element of a real `seq[byte]` is byte-width from the start), so lifting
## it to `uint16` is WIDENING -- B2's fully-supported case. The narrowing
## artifact is specific to this file's `seq[int]`-masked twin representation
## (`atByte`'s `and 0xFF` mask keeps every value plain `int`), a historical
## workaround this file's own header notes predate B1's now-mature
## `seq[byte]` support (the RFC's own recorded key decision: "seq[byte]
## migration is a chapulin PREREQUISITE" -- B7's row is where the OTHER
## three arms' shared `atByte`/`readU16Twin`/`readCStringTwin` machinery
## gets migrated wholesale). Rather than pre-empt that broader B7 migration,
## the two arms A6 actually gates (opData/opAck, both header-dispatch-only,
## no `readCStringTwin` involvement) read their two header bytes INLINE
## below, narrowly scoped to unblock A6 without touching
## `decodeFixedArmsErrorTwin`/`decodeOptionArmTwin`/`decodeIntTwin`'s shared
## `seq[int]` machinery (those three stay exactly as before -- still
## classified `sxUnknown` for the OTHER, pre-existing Blocker #6 reason,
## unaffected by this change).
##
## BLOCKER #12 FOUND EMPIRICALLY, walker v85 (2026-08-16, A6 retest against
## 0.4.1, found immediately after BLOCKER #11): a SEPARATE, genuine witness-
## EXTRACTION gap, distinct from BLOCKER #11's proof-level narrowing decline
## -- the PROOF itself was already sound (`sxSat`, target reachable) but the
## reported `witness[0]` for this proc's `seq[byte]` param came back all-
## zero (`@[0, 0, 0, 0]`) regardless of the actual solved model, whenever the
## two header bytes were read via a SEPARATE helper proc call (a
## `readU16Bytes(data, offset)`-shaped indirection -- interprocedurally
## inlined, same as `readU16Twin`/`atByte` elsewhere in this file) rather
## than indexing `data` directly in THIS proc's own body. Bisected in
## isolation (scratch probe, not kept): a helper-proc-mediated read of
## `data[0]`/`data[1]` reproduces the all-zero witness on an otherwise
## `sxSat` target; the IDENTICAL read inlined directly (no helper) reports
## the correct witness (`@[0, 3, 0, 5]`). Fix: this proc reads its two
## `uint16` header fields DIRECTLY (`(uint16(data[i]) shl 8) or
## uint16(data[i+1])`, no helper proc), matching real `decode()`'s own
## widening arithmetic exactly, just without the extra call-boundary hop.

proc decodeFixedArmsTwin(data: seq[byte]): TftpPacket =
  ## opData + opAck arms ONLY (no `readCStringTwin` call -- see the SPLIT
  ## note above). Strong `sxUnsat` IndexError/FieldDefect proof, unaffected
  ## by the readCString solver-capability gap.
  ##
  ## A6 (RFC-chapulin-hardening, walker >=77): UN-VOIDED. Pre-0.4.0, variant
  ## object construction had no case in the DSL walker's expression path at
  ## all, so every twin in this file stayed `void` (discarding its computed
  ## value) -- `docs/proptest-findings.md`'s "nnkObjConstr ... variant
  ## objects STILL UNSUPPORTED" row. A1's `iekVariantLit` (literal-
  ## discriminant construction) plus A2's `retBindEq` svVariant general
  ## encoding make constructing the REAL `TftpPacket` here provable, not
  ## just a macro error -- this proc now RETURNS the constructed packet.
  ##
  ## `data: seq[byte]` (BLOCKER #11, see above) -- the real parameter type,
  ## not the file's legacy `seq[int]` mask.
  ##
  ## The opData arm's `data` PAYLOAD field is left at its zero value (`@[]`,
  ## given EXPLICITLY -- an OMITTED seq-typed field also degrades the whole
  ## proc to `sxUnknown`, a SEPARATE finding also folded into BLOCKER #11's
  ## write-up above: the constructor's own default-zero-value synthesis for
  ## an omitted field is a real, distinct gap from `lowerSeqLit`'s
  ## already-fixed EXPLICIT `@[]`-literal path, B6's empty-literal rider,
  ## which does not cover it) even when `data.len > 4` and the length-guarded
  ## slice is still computed below (`payload`) -- a `seq[byte]` slice itself
  ## is a SEPARATE, still-open DSL gap (the seq-slicing row in
  ## `docs/proptest-findings.md`), orthogonal to variant construction and
  ## untouched by A1/A3. The oracle cross-check further down is therefore
  ## drawn from a `data.len == 4` witness specifically, so the twin's
  ## zero-value `data` field and real `decode()`'s empty payload slice agree
  ## BY CONSTRUCTION, not by omission.
  if data.len < 2:
    raise newException(TftpDecodeError, "Packet too short: " & $data.len & " bytes")
  # BLOCKER #12 (see above): read INLINE, not via a helper proc -- a
  # helper-mediated read of these same bytes reports an all-zero witness
  # despite a genuinely sxSat proof.
  let wireOp = (uint16(data[0]) shl 8) or uint16(data[1])
  if wireOp < 1 or wireOp > 6:
    raise newException(TftpDecodeError, "Invalid opcode: " & $wireOp)
  if wireOp == 3:            # opData (opcodeToWire: ord(opData)=2 -> wire 3)
    if data.len < 4:
      raise newException(TftpDecodeError, "DATA packet too short: " & $data.len & " bytes")
    let blockNum = (uint16(data[2]) shl 8) or uint16(data[3])
    if data.len > 4:
      # See the file-level BLOCKER #11 note: this slice is computed (never
      # `discard`ed vacuously) but its VALUE is not fed into the constructed
      # packet below -- the `data` payload field stays at its zero value
      # regardless, per the seq-slicing gap noted above.
      let payload = data[4 .. ^1]
      discard payload
    # A6: literal-discriminant construction (A1 iekVariantLit); `blockNum`
    # is ALREADY `uint16` (inline widening read, no narrowing cast needed at
    # the construction site -- BLOCKER #11); `data` EXPLICITLY `@[]`.
    result = TftpPacket(opcode: opData, blockNum: blockNum, data: @[])
    if data.len == 4 and result.blockNum == 5:
      # Oracle-compared witness target (opData): reachable only through the
      # EMPTY-payload sub-case (data.len==4), so the witness below is
      # directly comparable to real decode()'s output field-for-field.
      symexTarget("a6_opdata_block5_emptypayload")
  elif wireOp == 4:          # opAck
    if data.len < 4:
      raise newException(TftpDecodeError, "ACK packet too short: " & $data.len & " bytes")
    let ackBlockNum = (uint16(data[2]) shl 8) or uint16(data[3])
    # A6: literal-discriminant construction (A1 iekVariantLit); opAck has no
    # payload/loop complication at all, and no seq-typed field to omit.
    # `ackBlockNum` is ALREADY `uint16` -- see BLOCKER #11 above.
    result = TftpPacket(opcode: opAck, ackBlockNum: ackBlockNum)
    if result.ackBlockNum == 7:
      # Oracle-compared witness target (opAck).
      symexTarget("a6_opack_block7")
  else:
    discard   # opRRQ(1)/opWRQ(2)/opError(5)/opOACK(6) -- opError is proven
              # separately by decodeFixedArmsErrorTwin (see above); the rest
              # are not modeled here (unchanged from before the split).
              # `result` stays the zero-value TftpPacket(opcode: opRrq) on
              # this branch -- unread by anything in this file (no oracle
              # target below reaches it).

proc decodeFixedArmsErrorTwin(data: seq[int]): TftpPacket =
  ## opError arm ONLY, split out of decodeFixedArmsTwin (see the SPLIT note
  ## above). NEW FINDING (proptest 0.3.1, PRIORITY 1 discard-vacuity fix):
  ## this arm's `sxUnsat` claim, as it stood before this pass, was VACUOUS --
  ## `discard readU16Twin(data, 2)` / `discard readCStringTwin(data, 4)` both
  ## dropped their call expressions entirely (dsl_parser.nim's
  ## `nnkDiscardStmt` arm only lowers a discarded call for two allowlisted
  ## intrinsics: getCurrentException(Msg)/parseInt/parseBiggestInt), so
  ## `readCStringTwin`'s own `while` loop was NEVER actually walked. Once
  ## genuinely non-vacuous (the call sits in an `if` condition below, never
  ## `discard`ed and never `let`-bound -- binding it, even to a name never
  ## read again, ALSO regressed this to `sxUnknown`, measured), the honest
  ## verdict is `sxUnknown`, not `sxUnsat`. This is not a composition
  ## artifact: an isolated scratch probe with NO other logic at all --
  ## `if readCStringTwin(data, 0)[0].len >= 0: discard` -- ALSO returns
  ## `sxUnknown`. So this is `readCStringTwin`'s own while loop, once
  ## genuinely interprocedurally inlined, exceeding this solver's ability to
  ## decide -- the SAME class of gap BLOCKER #6 (below, decodeOptionArmTwin)
  ## already catalogs for a CHAINED scan, now shown to also cover the
  ## single, non-chained, literal-offset case (BLOCKER #6's text below
  ## previously claimed the single-scan case was "NOT affected" -- that
  ## claim was itself an artifact of this same vacuity bug and is now
  ## corrected). Kept honestly `sxUnknown` (see the suite below) -- NOT
  ## re-vacuous-discarded to manufacture a fake `sxUnsat`.
  ##
  ## A6 (RFC-chapulin-hardening): CONSTRUCTS the real `TftpPacket` opError
  ## arm now (A1's `iekVariantLit`, no macro error, no void twin) -- but the
  ## WALK stays classified `sxUnknown`, unchanged by this slice: the gap
  ## documented above was never about constructing the variant, it is
  ## `readCStringTwin`'s own interprocedurally-inlined `while` loop
  ## exceeding this solver's decidability. A1/A3's construction machinery
  ## does not touch that gap. Pending Track B's B4 (accumulating-string
  ## closed form).
  if data.len < 5:
    raise newException(TftpDecodeError, "ERROR packet too short: " & $data.len & " bytes")
  let errCode = readU16Twin(data, 2)
  let mappedCode = if errCode <= 8: TftpErrorCode(errCode) else: errNotDefined
  let (msg, _) = readCStringTwin(data, 4)
  result = TftpPacket(opcode: opError, errorCode: mappedCode, errorMsg: msg)

# ---- Symex-scoped twin #2: option-parsing arm (opRRQ/opWRQ) ---------------
#
# `readOptions` (protocol.nim:113-123) loops on option count against
# `maxLoopUnwind=5` (the walker's generic while-loop cap). The RFC's plan was
# to hand-unroll that loop to a structural ≤2-option bound (two nested `if`
# blocks instead of a `for`/`while`, since D5/D6 below rule out an actual
# loop construct here). That WAS built and is preserved in the RFC/handoff
# writeup, but it does not come back `sxUnsat` -- see BLOCKER #6. This proc
# is therefore SCOPED DOWN to what was meant to be provable: the RRQ/WRQ
# header dispatch (opcode-range check + the opRRQ(1)/opWRQ(2) selector) plus
# exactly the FIRST cstring scan (filename, protocol.nim:160).
#
# BLOCKER #6 REVISED (proptest 0.3.1, PRIORITY 1 discard-vacuity fix): this
# proc's own filename scan was ALSO vacuous before this pass (`discard
# readCStringTwin(data, 2)`), so its former "proves sxUnsat cleanly" claim
# was never a real proof either -- see decodeFixedArmsErrorTwin's doc
# comment above for the full finding. Genuinely walked (below), it proves
# `sxUnknown`, honestly, same as the opError arm. Extending the chain to the
# mode string / option pairs remains additionally blocked by the CHAINED-scan
# gap BLOCKER #6 documents below (a strictly worse outcome, a native crash,
# not just `sxUnknown`) -- so this proc stays scoped to "header + first
# scan" even though that scan alone no longer proves `sxUnsat`.
#
# BLOCKER #5 FOUND EMPIRICALLY (bisected in a scratch harness, not kept in
# this file): calling a `var`-out-param helper proc (`readCStringTwin`) FROM
# INSIDE a `for`/`while` LOOP crashes the compiled walker natively -- no Nim
# exception, no assertion message, just a non-zero process exit ("Error:
# execution of an external program failed", nothing else). Reproduced with a
# minimal 2-iteration `for` loop calling `readCStringTwin` once per
# iteration; the IDENTICAL calls made OUTSIDE a loop (straight-line, called
# twice in sequence) work fine. This is WHY the (now-descoped) ≤2-option
# version hand-unrolled to nested `if`s rather than a `for` loop -- but see
# BLOCKER #6: that dodge doesn't rescue provability, only the crash.
#
# BLOCKER #6 FOUND EMPIRICALLY (the actual reason the ≤2-option version is
# descoped) -- bisected down to a MINIMAL, isolated repro kept only in this
# comment for the record (not shipped, to keep this file's default run
# fast + green):
#
#   proc scanLen(data: seq[int], offset: int): int =
#     var i = offset
#     while i < data.len:
#       if ((data[i] mod 256) + 256) mod 256 == 0: return i + 1
#       i.inc
#     raise newException(TftpDecodeError, "...")
#   proc chainOnly(data: seq[int]) =
#     let p1 = scanLen(data, 2)
#     discard scanLen(data, p1)        # <-- offset is p1, not a literal
#   symexFind(chainOnly, tIndexError())   # => sxUnknown, r.errors == @[]
#
# TWO chained while-loop scans, where the SECOND scan's starting offset is
# the (symbolic) RESULT of the first, return `sxUnknown` -- not a crash,
# not a witness, an honest "solver could not decide" per
# `canonicalize.nim`'s own vocabulary. This is INDEPENDENT of:
#   * the unmodeled `string add` op (Blocker seen mid-investigation): the
#     no-string-content `scanLen` shape above still gives `sxUnknown` with
#     an EMPTY `errors` seq, so it isn't that diagnostic firing;
#   * `maxLoopUnwind`: tried both the default (5) and a much smaller bound
#     (2) via an explicit `SymexSettings` override -- both `sxUnknown`;
#   * `maxCallDepth`: tried both the default (3) and 20 -- both `sxUnknown`;
#   * `symexAssume`-based bounding of `data.len`: ALSO tried, and
#     discovered its own, separate, DOCUMENTED-VS-IMPLEMENTED mismatch —
#     `dsl_parser.nim`'s `nnkCall`/`nnkCommand` dispatch (~line 2716) parses
#     `symexAssume(cond)` to `mkAssert(cond)`, IDENTICAL to `symexAssert`,
#     not the doc comment's claimed "early return if violated" filter
#     semantics (`symex.nim` ~938-945). Since a `seq[int]`/`int` parameter's
#     length/value is otherwise unconstrained, an assumed upper bound is
#     always constructively "violatable", so `symexAssume(data.len <= N)`
#     just manufactures its own `sxRaised(AssertionDefect)` finding instead
#     of narrowing the search -- a genuine proptest doc/implementation
#     mismatch, not a lever this file can use.
# A single, non-chained scan (offset a literal, as in this proc) was
# ORIGINALLY believed "NOT affected" by this chained-loop gap -- that belief
# is now known to have been a false negative caused by the SEPARATE
# discard-vacuity bug (both this proc's and decodeFixedArmsTwin's original
# `discard readCStringTwin(...)` calls were never walked at all, so neither
# ever really tested a single scan's provability). Once genuinely walked
# (proptest 0.3.1, PRIORITY 1 fix, this pass), a SINGLE non-chained scan is
# ALSO only `sxUnknown`, not `sxUnsat` -- see decodeFixedArmsErrorTwin's doc
# comment above for the isolated scratch-probe confirmation. So the gap
# documented below (a SECOND scan whose start offset is a prior scan's
# symbolic result) is not a separate, worse tier on top of an otherwise-solid
# single-scan proof -- it was always compounding on top of an already-shaky
# (previously vacuous) foundation. Both remain genuine solver-capability
# gaps for bounded loops interprocedurally inlined under this proptest pin,
# distinct from Blockers #1-#5, and are the honest reason this proof stops
# at "header + first scan, sxUnknown" rather than reaching the RFC's
# original ≤2-option, sxUnsat target.
#
# BLOCKER #6 RETESTED under 0.1.0, STILL PRESENT (and WORSE) -- a probe
# (not kept, per this file's convention) reran the exact repro above, now
# using `readCStringTwin`'s real tuple-return form (post-Blocker-#2-fix):
#   let (_, p1) = readCStringTwin(data, 2)
#   discard readCStringTwin(data, p1)
# This is no longer a graceful `sxUnknown` -- it is a hard native CRASH (bare
# non-zero exit, no output at all, not even reaching the `echo` after
# `symexFind` returns). This is consistent with t_symex_security.nim's
# refined Blocker #9 finding (a while-loop-produced value bound to a name
# and read in a LATER statement is unprovable) -- `p1` is exactly that shape
# here (destructured from a tuple return whose producing call contains a
# loop, then reused as the second call's argument) -- but manifests here as
# a crash rather than `sxUnknown`, a strictly worse outcome for this
# composition. Confirms: do not chain a second scan off a first scan's
# result, full stop, under this pin -- the option-arm scope stays at
# "header + first scan."

proc decodeOptionArmTwin(data: seq[int]): TftpPacket =
  ## A6 (RFC-chapulin-hardening): CONSTRUCTS the real `TftpPacket` opRRQ/
  ## opWRQ arm now (A1's `iekVariantLit`, no macro error, no void twin) --
  ## `filename` is the one field this proc actually scans (below); `mode`/
  ## `options` are PLACEHOLDER values (`tmOctet` / `@[]`), NOT derived from
  ## `data` -- the mode-string scan (chained off the filename scan's own
  ## result offset) and the options loop are BLOCKER #6/B5/B6 territory,
  ## untouched by A1/A3's construction machinery. The WALK stays classified
  ## `sxUnknown` below, unchanged by this slice (BLOCKER #6 REVISED, see
  ## above): the gap was never about constructing the variant.
  if data.len < 2:
    raise newException(TftpDecodeError, "Packet too short: " & $data.len & " bytes")
  let wireOp = readU16Twin(data, 0)
  if wireOp < 1 or wireOp > 6:
    raise newException(TftpDecodeError, "Invalid opcode: " & $wireOp)
  if wireOp != 1 and wireOp != 2:
    return          # opRRQ(1)/opWRQ(2) only; other wire values untouched here
  # PRIORITY 1 discard-vacuity fix (see decodeFixedArmsErrorTwin's comment
  # above): consume the call's tuple result via a genuine `let` bind (not
  # `discard`ed) so the constructed packet reflects a real scan, not a
  # placeholder value -- still honestly `sxUnknown` below (BLOCKER #6
  # REVISED, see above), the bind shape doesn't change that verdict here
  # (unlike decodeFixedArmsErrorTwin's opError arm, this was already
  # `sxUnknown`, not a former vacuous `sxUnsat`, so there is no regression
  # to measure).
  let (filename, _) = readCStringTwin(data, 2)
  # Nim itself (not a symex restriction) only accepts a RUNTIME discriminant
  # in constructor syntax when NO arm-specific field is set alongside it
  # (opRrq/opWrq's arm carries filename/mode/options, all arm-specific) --
  # the same constraint A1's own SUT #6 doc comment names
  # (tsymex_r6_a1_variantlit.nim). So each literal branch constructs with
  # its OWN literal `opcode:` (A1's iekVariantLit territory), not a shared
  # runtime-valued `op` local.
  if wireOp == 1:
    result = TftpPacket(opcode: opRrq, filename: filename, mode: tmOctet, options: @[])
  else:
    result = TftpPacket(opcode: opWrq, filename: filename, mode: tmOctet, options: @[])

proc decodeOackArmTwin(data: seq[int]): TftpPacket =
  ## opOack arm -- A6 CONSTRUCTION-ONLY pin (no twin existed for this arm
  ## before this slice; the RFC's A6 row requires all five arms construct,
  ## not just the four already-present twins). Real `decode()`'s opOack case
  ## is `TftpPacket(opcode: opOack, oackOptions: readOptions(data, 2))` --
  ## the `readOptions` loop is BLOCKER #6/B6 territory (accumulating
  ## option-pair scan), untouched by A1/A3's variant CONSTRUCTION machinery
  ## (which only makes the `TftpPacket(opcode: opOack, ...)` EXPRESSION
  ## constructible, not the loop that would compute a real `oackOptions`).
  ## `oackOptions` is therefore left at its zero value (`@[]`) -- a
  ## placeholder, not a decoded result. Oracle comparison against real
  ## `decode()` is explicitly OUT OF SCOPE for this arm at this gate (Track
  ## B's B6 + B7 own it); see the suite below for the classified-sxUnknown-
  ## or-sxUnsat pin (whichever this trivial, loop-free header-only body
  ## actually proves). `oackOptions` is given EXPLICITLY (`@[]`), not
  ## omitted -- see decodeFixedArmsTwin's BLOCKER #11 note above (an omitted
  ## seq-typed field degrades the whole proc to sxUnknown regardless of
  ## whether that field's type is one of Bug #2's placeholder-carrying ones).
  if data.len < 2:
    raise newException(TftpDecodeError, "Packet too short: " & $data.len & " bytes")
  let wireOp = readU16Twin(data, 0)
  if wireOp < 1 or wireOp > 6:
    raise newException(TftpDecodeError, "Invalid opcode: " & $wireOp)
  if wireOp == 6:
    result = TftpPacket(opcode: opOack, oackOptions: @[])
  else:
    discard   # opRRQ(1)/opWRQ(2)/opDATA(3)/opACK(4)/opERROR(5) -- proven
              # elsewhere; zero-value TftpPacket(opcode: opRrq) returned,
              # unread by anything below.


# ---- Compile-check + no-Defect proofs --------------------------------------

suite "symex: protocol.decode fixed-size arms (opData/opAck)":
  ## opError is proven separately below (decodeFixedArmsErrorTwin) -- see
  ## the SPLIT note above decodeFixedArmsTwin's definition. This suite keeps
  ## its strong `sxUnsat` proof (opData/opAck never call `readCStringTwin`).
  test "compiles under symexFind (first proof: the seq[byte] twin shape is walkable -- BLOCKER #11)":
    let r = symexFind(decodeFixedArmsTwin, tIndexError())
    discard r  # compiling to this line + the check below IS the proof

  test "no IndexError path (sxUnsat)":
    check symexFind(decodeFixedArmsTwin, tIndexError()).status == sxUnsat

  test "no FieldDefect path (sxUnsat)":
    check symexFind(decodeFixedArmsTwin, tFieldDefect()).status == sxUnsat

suite "symex: protocol.decode fixed-size arms (opError)":
  ## NEW FINDING (proptest 0.3.1, PRIORITY 1 discard-vacuity fix): honestly
  ## `sxUnknown`, not `sxUnsat` -- see decodeFixedArmsErrorTwin's doc comment
  ## above for the full writeup (this arm's former `sxUnsat` claim was
  ## vacuous; genuinely walking `readCStringTwin`'s internal loop surfaces a
  ## real solver-capability gap, not a defect). Asserted here explicitly so
  ## a future proptest pin that DOES close this gap turns this test red
  ## (signalling "tighten back to sxUnsat"), rather than silently staying
  ## green on a stale, weaker claim.
  test "compiles under symexFind":
    let r = symexFind(decodeFixedArmsErrorTwin, tIndexError())
    discard r

  test "IndexError search: sxUnknown (solver capability gap, not a defect -- see above)":
    check symexFind(decodeFixedArmsErrorTwin, tIndexError()).status == sxUnknown

  test "FieldDefect search: sxUnknown (solver capability gap, not a defect -- see above)":
    check symexFind(decodeFixedArmsErrorTwin, tFieldDefect()).status == sxUnknown

suite "symex: protocol.decode option-parsing arm (opRRQ/opWRQ header + first scan)":
  ## Scope note (BLOCKER #6 REVISED, see the doc comment above
  ## decodeOptionArmTwin): this proc's own filename scan is ALSO honestly
  ## `sxUnknown` now (same solver-capability gap as decodeFixedArmsErrorTwin
  ## above), not `sxUnsat` -- its former "proves sxUnsat cleanly" claim was
  ## vacuous (discard-vacuity bug). Chaining a SECOND scan (mode, options)
  ## is additionally, separately blocked (a native crash, worse than
  ## `sxUnknown`) regardless of maxLoopUnwind/maxCallDepth tuning.
  test "compiles under symexFind":
    let r = symexFind(decodeOptionArmTwin, tIndexError())
    discard r

  test "IndexError search: sxUnknown (solver capability gap, not a defect -- see above)":
    check symexFind(decodeOptionArmTwin, tIndexError()).status == sxUnknown

  test "FieldDefect search: sxUnknown (solver capability gap, not a defect -- see above)":
    check symexFind(decodeOptionArmTwin, tFieldDefect()).status == sxUnknown

suite "symex: protocol.decode option-acknowledgment arm (opOack) -- construction-only pin, Track B owns the walk":
  ## See decodeOackArmTwin's doc comment above: `oackOptions` is a
  ## placeholder (`@[]`), not a decoded result -- this suite pins that the
  ## arm CONSTRUCTS (no macro error, no void twin) and that its trivial,
  ## loop-free header-only body classifies cleanly, never a crash. No
  ## oracle comparison here (Track B's B6/B7 own that).
  test "compiles under symexFind (constructs, no macro error, no void twin)":
    let r = symexFind(decodeOackArmTwin, tIndexError())
    discard r

  test "no IndexError path (sxUnsat -- header-only body, no readCString/readOptions on this path)":
    check symexFind(decodeOackArmTwin, tIndexError()).status == sxUnsat

  test "no FieldDefect path (sxUnsat -- header-only body, no readCString/readOptions on this path)":
    check symexFind(decodeOackArmTwin, tFieldDefect()).status == sxUnsat

# ---- A6 oracle: opData/opAck constructed-packet witnesses cross-checked -----
# against the REAL decode() ---------------------------------------------------
#
# Honest arm accounting (RFC A6): opData/opAck are the two arms with no
# `readCString`/`readOptions` on their path, so they are the only two that
# get a REAL end-to-end oracle-compared witness at this gate -- opError/
# opRRQ-opWRQ/opOack all CONSTRUCT (pins above) but stay classified
# `sxUnknown` pending Track B (B4/B5/B6), with their own oracle coverage
# landing alongside B7.
#
# Pattern (mirrors tsymex_r6_a1_variantlit.nim/a2_retbind_variant.nim's own
# construct-and-constrain style, and t_symex.nim's
# `nimParseIntRaises(r.raisedWitness[0])` ground-truth cross-check):
# `symexFind` PROVES a specific literal outcome on the CONSTRUCTED packet is
# reachable (`decodeFixedArmsTwin`'s own `symexTarget` calls, added this
# slice), then the witness's `data` param is converted to real bytes and run
# through the SHIPPED `decode()` -- the symbolic proof and ground truth must
# agree exactly, not just both compile.

suite "symex round-6 A6 -- opData/opAck construction, witness cross-checked against real decode()":
  test "opData: blockNum==5 with an empty payload (data.len==4) is reachable, and real decode() agrees exactly":
    let r = symexFind(decodeFixedArmsTwin, tLabel("a6_opdata_block5_emptypayload"))
    check r.status == sxSat
    # BLOCKER #11 (see decodeFixedArmsTwin's doc comment): the twin's `data`
    # param is now genuinely `seq[byte]` (not the file's legacy `seq[int]`
    # mask), so the witness is already real bytes -- no `mapIt(byte(it and
    # 0xFF))` reinterpretation needed.
    let bytes = r.witness[0]
    let real = decode(bytes)
    check real.opcode == opData
    check real.blockNum == 5'u16
    check real.data == newSeq[byte]()

  test "opAck: ackBlockNum==7 is reachable, and real decode() agrees exactly":
    let r = symexFind(decodeFixedArmsTwin, tLabel("a6_opack_block7"))
    check r.status == sxSat
    let bytes = r.witness[0]
    let real = decode(bytes)
    check real.opcode == opAck
    check real.ackBlockNum == 7'u16

# ---- Differential oracle: twin ≡ real decode(seq[byte]) on concrete bytes --
#
# "Compiles" is a syntax check, not proof the twin walks the same
# control-flow paths as the real `decode(seq[byte])` -- an incomplete 0..255
# constraint could fabricate an sxSat/sxRaised witness unreachable by any
# real seq[byte], or the shl/or arithmetic could quietly diverge. This runs
# a FULL (unbounded-loop, ordinary runtime, non-symex) twin against real
# `decode` on the same concrete byte sequences and asserts identical
# outcomes. Reuses `fuzzsupport.byteSeqs()` (the same arbitrary-wire-bytes
# generator `t_props.nim`'s `decodeOracle` property already fuzzes decode
# with) so the cross-check runs over a broad, not hand-picked-only, set of
# inputs.

proc parseModeTwin(s: string): TransferMode =
  ## Twin of protocol.nim's private `parseMode` (line ~107-111). Plain
  ## runtime code (not a symex target) -- used only by `decodeIntTwin` below.
  case s.toLowerAscii
  of "octet": tmOctet
  of "netascii": tmNetascii
  else: raise newException(TftpDecodeError, "Unknown transfer mode: " & s)

proc readOptionsTwin(data: seq[int], offset: int): seq[(string, string)] =
  ## Twin of protocol.nim's private `readOptions` (line ~113-123), UNBOUNDED
  ## (ordinary runtime code, not a symex target -- tuple returns and
  ## unbounded loops are both fine here; the maxLoopUnwind cost concern is
  ## symex-macro-specific, not a general Nim compile restriction).
  var pos = offset
  while pos < data.len:
    let (key, nextPos) = readCStringTwin(data, pos)
    if nextPos >= data.len and key.len > 0:
      raise newException(TftpDecodeError, "Option key without value at offset " & $pos)
    if key.len == 0 and nextPos >= data.len:
      break
    let (val, finalPos) = readCStringTwin(data, nextPos)
    result.add (key, val)
    pos = finalPos

proc decodeIntTwin(data: seq[int]): TftpPacket =
  ## FULL twin of protocol.decode (all six opcodes) over seq[int] -- the
  ## differential-oracle target. Every element read still goes through
  ## `atByte`/`readU16Twin`/`readCStringTwin` (the SAME masked primitives
  ## the two symex-scoped twins above use), so a divergence here would
  ## indict those shared primitives, not a separate reimplementation.
  if data.len < 2:
    raise newException(TftpDecodeError, "Packet too short: " & $data.len & " bytes")
  let wireOp = readU16Twin(data, 0)
  if wireOp < 1 or wireOp > 6:
    raise newException(TftpDecodeError, "Invalid opcode: " & $wireOp)
  let op = TftpOpcode(wireOp - 1)
  case op
  of opRrq, opWrq:
    let (filename, afterFilename) = readCStringTwin(data, 2)
    if afterFilename >= data.len:
      raise newException(TftpDecodeError, "Missing transfer mode")
    let (modeStr, afterMode) = readCStringTwin(data, afterFilename)
    let mode = parseModeTwin(modeStr)
    let opts = readOptionsTwin(data, afterMode)
    result = TftpPacket(opcode: op, filename: filename, mode: mode, options: opts)
  of opData:
    if data.len < 4:
      raise newException(TftpDecodeError, "DATA packet too short: " & $data.len & " bytes")
    let blockNum = uint16(readU16Twin(data, 2))
    let payload =
      if data.len > 4: data[4 .. ^1].mapIt(byte(it and 0xFF))
      else: newSeq[byte]()
    result = TftpPacket(opcode: opData, blockNum: blockNum, data: payload)
  of opAck:
    if data.len < 4:
      raise newException(TftpDecodeError, "ACK packet too short: " & $data.len & " bytes")
    result = TftpPacket(opcode: opAck, ackBlockNum: uint16(readU16Twin(data, 2)))
  of opError:
    if data.len < 5:
      raise newException(TftpDecodeError, "ERROR packet too short: " & $data.len & " bytes")
    let errCode = readU16Twin(data, 2)
    let mappedCode = if errCode <= 8: TftpErrorCode(errCode) else: errNotDefined
    let (msg, _) = readCStringTwin(data, 4)
    result = TftpPacket(opcode: opError, errorCode: mappedCode, errorMsg: msg)
  of opOack:
    let opts = readOptionsTwin(data, 2)
    result = TftpPacket(opcode: opOack, oackOptions: opts)

# Structural equality for the variant packet -- Nim's auto-generated `==`
# rejects case objects (same reason t_props.nim/t_hostile.nim each define
# their own local copy of this exact proc).
proc `==`(a, b: TftpPacket): bool =
  if a.opcode != b.opcode: return false
  case a.opcode
  of opRrq, opWrq:
    a.filename == b.filename and a.mode == b.mode and a.options == b.options
  of opData: a.blockNum == b.blockNum and a.data == b.data
  of opAck: a.ackBlockNum == b.ackBlockNum
  of opError: a.errorCode == b.errorCode and a.errorMsg == b.errorMsg
  of opOack: a.oackOptions == b.oackOptions

proc diffOracleCheck(bytes: seq[byte]): bool =
  let ints = bytes.mapIt(int(it))
  var realOk = true
  var realErr = ""
  var realPkt: TftpPacket
  try:
    realPkt = decode(bytes)
  except TftpDecodeError as e:
    realOk = false
    realErr = e.msg

  var twinOk = true
  var twinErr = ""
  var twinPkt: TftpPacket
  try:
    twinPkt = decodeIntTwin(ints)
  except TftpDecodeError as e:
    twinOk = false
    twinErr = e.msg

  if realOk != twinOk: return false
  if realOk: realPkt == twinPkt
  else: realErr == twinErr

suite "differential oracle: decodeIntTwin(seq[int]) === decode(seq[byte])":
  test "hand-picked vectors (RRQ/WRQ w/ options, DATA, ACK, ERROR, edge cases)":
    let vectors = @[
      @[0'u8, 1, 'a'.byte, 0, 'o'.byte, 'c'.byte, 't'.byte, 'e'.byte, 't'.byte, 0],  # RRQ octet
      @[0'u8, 2, 'b'.byte, 0, 'n'.byte, 'e'.byte, 't'.byte, 'a'.byte, 's'.byte,
        'c'.byte, 'i'.byte, 'i'.byte, 0],                                          # WRQ netascii
      @[0'u8, 1, 'f'.byte, 0, 'o'.byte, 'c'.byte, 't'.byte, 'e'.byte, 't'.byte, 0,
        'b'.byte, 'l'.byte, 'k'.byte, 's'.byte, 'i'.byte, 'z'.byte, 'e'.byte, 0,
        '5'.byte, '1'.byte, '2'.byte, 0],                                         # RRQ + 1 option
      @[0'u8, 3, 0, 1, 'h'.byte, 'i'.byte],           # DATA block 1, 2-byte payload
      @[0'u8, 3, 0, 1],                               # DATA block 1, empty payload
      @[0'u8, 4, 0, 7],                                # ACK block 7
      @[0'u8, 5, 0, 2, 'n'.byte, 'o'.byte, 0],        # ERROR code 2 "no"
      @[0'u8, 5, 0, 99, 'x'.byte, 0],                 # ERROR code 99 (>8 -> errNotDefined)
      @[0'u8, 6],                                      # OACK, no options
      @[],                                              # empty: too short
      @[0'u8],                                          # 1 byte: too short
      @[0'u8, 7],                                       # invalid opcode 7
      @[0'u8, 0],                                       # invalid opcode 0
      @[0'u8, 1, 'a'.byte],                            # RRQ, unterminated filename
      @[0'u8, 1, 'a'.byte, 0],                          # RRQ, missing mode
      @[0'u8, 3],                                       # DATA too short
      @[0'u8, 4],                                       # ACK too short
      @[0'u8, 5],                                       # ERROR too short
    ]
    for v in vectors:
      check diffOracleCheck(v)

  property "arbitrary wire bytes (fuzzsupport.byteSeqs)":
    with Settings(seed: FuzzSeed, maxExamples: FuzzN)
    given bytes in byteSeqs()
    ensure diffOracleCheck(bytes)
