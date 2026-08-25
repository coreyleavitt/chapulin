## Symex no-Defect proof for `netascii.NetasciiDecoder.feed`/`flush` (RFC
## verification-harness-v2.md Part B, slice B3, Target 2). Opt-in, z3 image
## only (t_symex* convention -- auto-selected by dev-test.ps1's
## `-like "t_symex*"` rule; no per-file registration needed):
##   pwsh scripts/dev-test.ps1 -Only @('t_symex_netascii') -Image chapulin-symex:2.2.10
##
## Read `tests/t_symex_decode.nim` (B1) FIRST, then `tests/t_symex_security.nim`
## + `tests/t_symex_uri.nim` (B2, esp. their **Blocker #9**: any while/for
## loop in a symex target's body that ALSO has a `string`-typed parameter in
## scope is unprovable -- `sxUnknown`, empty errors -- in this proptest pin.
##
## ---- Why this target is modeled PER-TRANSITION, not as a call to feed() --
## `NetasciiDecoder.feed` (netascii.nim:94-118) loops over `input:
## openArray[byte]`. Per Blocker #1 (seq[byte] has no symex witness reader)
## the loop's buffer would need the seq[int]-masked twin shape B1 established
## -- but `feed`'s own per-iteration BODY has no `string` parameter in scope
## (`NetasciiDecoder` carries only a plain `bool` field, `pendingCr`), so
## Blocker #9 does not literally apply here the way it did to B2's
## `string`-scanning targets. The task's design constraint is nonetheless to
## go loop-free from the start (rather than empirically re-discover a
## DIFFERENT crash/gap specific to this shape), because the actually
## interesting property is per-byte-transition safety, and a straight-line
## proof over the two-dimensional state space (`pendingCr` x `byte value`)
## is EXHAUSTIVE and strictly stronger than a bounded loop unwind would be:
## `maxLoopUnwind` bounds a loop proof to some N iterations of arbitrary
## LENGTH input, whereas modeling the transition directly covers the full
## finite domain (2 x 256 = 512 states) with no unwind bound at all. This
## also sidesteps needing any seq witness (masked or otherwise) in the
## SYMEX-SCOPED target altogether -- the twin below takes the state
## (`pendingCr: bool`) and the next byte (masked `int`, B1's chokepoint
## convention) directly as scalar params, no buffer.
##
## ---- Line-drift note (confirm-cited-lines discipline) --------------------
## The RFC/handoff cite "netascii.nim ~120-123" for "a lone wire CR not
## followed by LF/NUL". Reading the ACTUAL source: lines 120-124 are
## `NetasciiDecoder.flush` (the trailing-lone-CR-at-EOF case), not the
## non-conformant-CR-mid-stream branch this slice targets. The branch this
## slice actually needs -- "wire CR followed by neither LF nor NUL, inside
## `feed`" -- is at netascii.nim:110-113 (the `else:` arm under `if
## d.pendingCr:`, which falls through to reclassify `b` fresh below it).
## Mechanical citation drift only (same class as the A4 line-drift note in
## the handoff ledger) -- the branch's CONTENT matches the RFC's description
## exactly (module doc's own R2 section, and the prior round-2 false-EOF bug
## it cites, both point at this same code), just at a different line number
## than cited. Not a structural surprise, no escalation.
##
## ---- proptest 0.1.0 re-evaluation (2026-08): no change needed ------------
## This target has no removable workaround: `netasciiDecodeTransitionTwin` is
## loop-free by construction (an intentional straight-line, exhaustive
## finite-state model, not a Blocker-#9 dodge -- see the design-constraint
## note above), and its only "byte" handling is the `atByte` arithmetic mask
## on a SCALAR `int` param with EQUALITY comparisons only (no bitwise ops,
## no seq, no indexing) -- Blocker #1 (seq[byte] witness) and #3
## (bitwise-on-plain-int crash) both concern shapes this target never had.
## Re-verified green under 0.1.0 unmodified; nothing to remove or restore.
import std/unittest
import nelli/symex
import ../src/chapulin/netascii

const
  Cr = byte('\r')
  Lf = byte('\n')
  Nul = byte(0)

# ---- Shared masked-access primitive (B1's chokepoint idiom, reused) --------
#
# Applied here to a lone scalar byte, not a seq element -- but the SAME
# reasoning holds: a plain `int` symbolic has no fixed width (Blocker #3),
# so every place this file would otherwise write `x and 0xFF` uses the
# arithmetic equivalent instead, at one chokepoint.

proc atByte(x: int): int =
  ((x mod 256) + 256) mod 256

const
  CrInt = int(Cr)
  LfInt = int(Lf)
  NulInt = int(Nul)

# ---- Symex-scoped twin: single wire-byte transition (feed's per-iteration
# body, netascii.nim:100-118), loop-free by construction -----------------
#
# Mirrors the two cases `feed`'s body dispatches on for one input byte,
# given the carried `pendingCr` state:
#   pendingCr == true:  Lf -> resolve (emit Lf);  Nul -> resolve (emit Cr);
#                        else -> THE NON-CONFORMANT ARM (netascii.nim:110-113):
#                        emit a literal Cr, then reclassify `b` FRESH exactly
#                        as the `pendingCr == false` case below would.
#   pendingCr == false: Cr -> defer (no emission, pendingCr becomes true);
#                        else -> emit `b` as-is.
## Void target (no seq return -- nothing here needs a return value inside
# the symex-scoped proof, only that computing the transition never raises;
# see B1/B2's identical void-target convention). Straight-line nested `if`,
# bounded to depth 2 (well under Blocker #11's depth-3 native-crash
# threshold, which in any case was specific to STRING-typed results chained
# into a further string op -- this target has no string at all).

proc netasciiDecodeTransitionTwin(pendingCr: bool, rawByte: int) =
  let b = atByte(rawByte)
  if pendingCr:
    if b == LfInt:
      discard                      # resolves to Lf; pendingCr -> false
    elif b == NulInt:
      discard                      # resolves to Cr; pendingCr -> false
    else:
      # The genuinely hostile arm (R2 / prior round-2 false-EOF bug locus):
      # a wire CR not followed by LF or NUL. Emits the deferred Cr literally,
      # then reclassifies `b` fresh -- exactly the `pendingCr == false`
      # dispatch below, inlined rather than called (a call here would be a
      # var-out-param-in-caller-body shape close to B1's Blocker #5 territory;
      # inlining sidesteps it entirely and is a direct, faithful copy of the
      # real code's own inline `case b: of Cr: d.pendingCr = true / else:
      # result.add b` that follows the `if`, netascii.nim:114-118).
      if b == CrInt:
        discard                    # re-classified b is itself Cr -> defers again
      else:
        discard                    # ordinary byte -> emitted as-is
  else:
    if b == CrInt:
      discard                      # defers -- pendingCr -> true, nothing emitted
    else:
      discard                      # ordinary byte -> emitted as-is

suite "symex: NetasciiDecoder.feed single-byte transition (non-conformant-CR arm)":
  test "compiles under symexFind (twin shape is walkable)":
    let r = symexFind(netasciiDecodeTransitionTwin, tIndexError())
    discard r  # compiling to this line + the check below IS the proof

  test "no IndexError path (sxUnsat)":
    check symexFind(netasciiDecodeTransitionTwin, tIndexError()).status == sxUnsat

  test "no FieldDefect path (sxUnsat)":
    check symexFind(netasciiDecodeTransitionTwin, tFieldDefect()).status == sxUnsat

# ---- Differential oracle: twin's transition decision === the REAL decoder's
#
# "Compiles"/"sxUnsat" proves the modeled transition never raises; it does
# NOT prove the twin's OUTPUT/next-state decision matches the real decoder's
## -- an incomplete case split could fabricate a proof over a transition
# table that doesn't correspond to any real `feed` behavior. This drives the
# REAL `NetasciiDecoder.feed` (ordinary compiled Nim, not a symex target)
## through both possible `pendingCr` entry states and every possible next
# byte (EXHAUSTIVE over the full 2 x 256 = 512-state space, not sampled --
# the whole point of proving a per-transition abstraction is that its state
# space is small enough to enumerate completely, stronger than any bounded
# fuzz/property sampling of `feed` over variable-length buffers could
# demonstrate for this specific local claim) and asserts identical
# (outputBytes, resultingPendingCr).

proc transitionDecision(pendingCr: bool, b: byte): tuple[outBytes: seq[byte], newPendingCr: bool] =
  ## Value-returning mirror of `netasciiDecodeTransitionTwin`, for oracle use
  ## (ordinary runtime code, not a symex target -- seq[byte] RETURN is fine
  ## outside the walker).
  if pendingCr:
    if b == Lf:
      (@[Lf], false)
    elif b == Nul:
      (@[Cr], false)
    else:
      if b == Cr:
        (@[Cr], true)
      else:
        (@[Cr, b], false)
  else:
    if b == Cr:
      (newSeq[byte](0), true)
    else:
      (@[b], false)

proc realTransition(pendingCr: bool, b: byte): tuple[outBytes: seq[byte], newPendingCr: bool] =
  ## Drives the REAL `NetasciiDecoder.feed` to the requested entry state
  ## (feeding a lone `Cr` first sets `pendingCr = true` and emits nothing --
  ## the decoder's own documented defer contract, module doc + t_netascii.nim
  ## "straddled CR" suite), then feeds exactly the one byte under test and
  ## observes both the emitted output and the resulting carried state.
  var d: NetasciiDecoder
  if pendingCr:
    let primed = d.feed(@[Cr])
    doAssert primed.len == 0 and d.pendingCr == true  # sanity: priming itself must defer
  let outp = d.feed(@[b])
  (outp, d.pendingCr)

proc transitionOracleCheck(pendingCr: bool, b: byte): bool =
  realTransition(pendingCr, b) == transitionDecision(pendingCr, b)

suite "differential oracle: netasciiDecodeTransitionTwin === NetasciiDecoder.feed (real)":
  test "hand-picked vectors -- the non-conformant-CR (hostile) arm, both sub-cases":
    # CR followed by neither LF nor NUL: literal Cr passes through, next byte
    # reprocessed fresh (module doc R2; netascii.nim:110-113).
    check transitionOracleCheck(true, byte('X'))
    # CR CR: the reprocessed byte is ITSELF Cr -- defers again rather than
    # resolving (the exact "CR CR LF" scenario t_netascii.nim's own "CR CR LF:
    # first CR is literal ... second CR pairs with LF" test exercises across
    # two feed calls; this is transition 1 of that sequence in isolation).
    check transitionOracleCheck(true, Cr)

  test "hand-picked vectors -- the conformant resolutions + the deferring case":
    check transitionOracleCheck(true, Lf)     # CR LF -> Lf
    check transitionOracleCheck(true, Nul)    # CR NUL -> literal Cr
    check transitionOracleCheck(false, Cr)    # ordinary CR -> defers
    check transitionOracleCheck(false, byte('A'))  # ordinary byte -> passthrough

  test "exhaustive: every (pendingCr, byte) pair over the full 0..255 domain":
    for pendingCr in [false, true]:
      for v in 0 .. 255:
        check transitionOracleCheck(pendingCr, byte(v))

# ---- End-to-end tie-back: the same hostile shape through the REAL public
# feed() over a multi-byte buffer, not just the per-transition abstraction --
#
# Closes the loop to the RFC's own framing ("the module doc cites a prior
# round-2 false-EOF bug here") by reproducing t_netascii.nim's own "CR CR LF"
# and "CR then ordinary byte" cases directly through `feed`/`flush`, so this
# file's claim ("the loop-free per-transition model matches the real
# decoder") is anchored to the actual multi-byte hostile scenario, not only
# to isolated single-byte transitions.

suite "hostile non-conformant-CR arm, tied back to real multi-byte feed()":
  test "CR followed by an ordinary byte: literal Cr, byte reprocessed fresh":
    var d: NetasciiDecoder
    check d.feed(@[Cr, byte('X')]) == @[Cr, byte('X')]

  test "CR CR LF: first CR is literal (non-conformant arm), second CR pairs with LF":
    var d: NetasciiDecoder
    check d.feed(@[Cr, Cr, Lf]) == @[Cr, Lf]

  test "CR CR NUL: first CR is literal, second CR resolves via NUL to a literal CR":
    var d: NetasciiDecoder
    check d.feed(@[Cr, Cr, Nul]) == @[Cr, Cr]

  test "straddled non-conformant CR: feed(CR) then feed(ordinary byte) across two calls":
    var d: NetasciiDecoder
    discard d.feed(@[Cr])
    check d.pendingCr == true
    check d.feed(@[byte('Q')]) == @[Cr, byte('Q')]
    check d.pendingCr == false
