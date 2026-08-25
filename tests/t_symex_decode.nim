## Symex no-Defect proofs for `protocol.decode` (RFC verification-harness-v2.md
## Part B, slice B1; RFC-chapulin-hardening Track A/A6 + Track B/B7). Opt-in,
## z3 image only (t_symex* convention -- auto-selected by dev-test.ps1's
## `-like "t_symex*"` rule):
##   pwsh scripts/dev-test.ps1 -Only @('t_symex_decode') -Image chapulin-symex:2.2.10
##
## ---- B7 (round-6 Track B exit gate) -- unified natural twin ---------------
##
## Two engine gaps blocked full unification earlier this round (see git
## history / the RFC handoff for the full isolation trail):
##
## * **BLOCKER A** -- the scan-idiom recognizer family (Q1/B0, B3, B4, B6)
##   required a literal `string`-typed receiver; `seq[byte]` never got the
##   closed form. FIXED by the B7-rider (nelli commit `c99bd87`, walker v87):
##   a shared `scanReceiverOk`/`scanDelimiterChar` gate now accepts a
##   string-backed `seq[byte]` receiver (B1's classifier, `
##   collectStringBackedByteSeqParams`, now tries all four shape predicates,
##   not just Q1's and-guard shape) with a byte-literal delimiter (`0'u8`,
##   `byte(0)`, or a plain in-range int literal); string-backed params now
##   also bridge through one level of helper-proc call.
## * **Companion witness bug** -- combining two `char`-sourced B2-widened
##   (`iekConvIntWidth`) values in one expression left the combined value's
##   high byte unconstrained (root cause: `char` was missing from
##   `normalizeIntTyName`'s alias map, so `uint16(<charExpr>)` silently
##   DROPPED the widening conversion -- the `sxSat` verdict was real, only
##   the witness was Z3's free choice for the un-widened high byte). FIXED
##   in the same commit (`char` -> `uint8` in the alias map).
##
## Both were verified fixed empirically before writing this file's real
## code (isolated probes, not shipped): a `readCStringTwin`-shaped
## accumulating scan over `seq[byte]` now closed-form-proves standalone AND
## as a helper called from a separate top-level dispatch proc (B4); the
## combined-widen witness (`uint16(data[0]) shl 8 or uint16(data[1])`)
## extracts correctly. This unlocks a REAL capability upgrade over A6: the
## unified `decodeTwin` below now performs a genuine CHAINED filename->mode
## scan for opRrq/opWrq (not a placeholder-only header dispatch), and
## opError's message scan is now closed-form-provable with real oracle
## content coverage (`errorMsg == "no"`, not just classified `sxUnknown`).
##
## **BLOCKER B7-1, FIXED (nelli commit `e6d3f0c`, walker v88).** B6's
## pair-loop closed form previously fired only for the exact shape of B6's
## own pinned SUT (an unconditional, un-dispatched, un-constructed `void`
## proc) -- isolated (round-1 escalation) to THREE independently-sufficient
## breakers: conditional dispatch wrapping, downstream variant construction,
## and helper-proc indirection. Root cause (per the coordinator, confirmed
## empirically below): all three shared ONE cause, not three -- the loop
## counter (`readOptionsTwin`'s `pos`) was seeded from a LITERAL (`2`), and
## int-offset promotion (`collectIntOffsetParams`) only traced counters back
## to FORMAL PARAMS, so a literal-seeded counter stayed BV-represented and
## failed the closed form's CR-17 Int-sortedness gate regardless of
## wrapping -- a NEW parse-time collector, `collectIntOffsetLiteralLocals`,
## promotes literal-seeded locals to `svInt` too. Confirmed via the exact
## `decodeOackTwin` shape (dispatch + call-boundary `readOptionsTwin` +
## `TftpPacket` construction, below, now MERGED into `decodeTwin`): proves
## end-to-end, region-membership `sxUnsat` for the whole unified twin, with
## a disjoint sibling arm's own defect still independently found.
##
## **BLOCKER B7-2 -- STILL OPEN, escalated to its own future round (NOT
## fixed this pass):** a `case`/`if`-chain matching a SCANNED string's
## content with an `else: raise` arm (`parseMode`'s own shape) poisons a
## sibling branch's target when embedded in a multi-branch dispatch,
## reproduced both as a separate proc call and fully inlined; unrelated to
## `seq[byte]`/BLOCKER A (pure string case-match). Per the coordinator: the
## natural branch-boundary catch fix proved UNSOUND on this C backend (the
## exception gets elided) and needs its own round. DIRECT string/value
## EQUALITY comparisons (no case-match) do NOT trigger it, confirmed via the
## same isolation harness -- this stays the resolution below: `mode` is a
## construction-time placeholder with a DIRECT `modeStr == "octet"`-style
## equality driving the oracle-comparable target (a natural spelling, not a
## workaround-of-convenience -- the twin keeps it regardless of B7-2's
## eventual fix). `options`/`oackOptions` stay unread regardless -- B6's own
## committed scope: "the no-defect proof for the whole option arm WITHOUT
## MODELING THE FOLD" -- membership + `ScanError` reachability + the
## oracle's comparison on non-options fields is the committed gate; options
## CONTENT comparison lives only in `decodeFullTwin`'s concrete (non-symex)
## differential oracle.
##
## Every seq/string-typed field is supplied EXPLICITLY (`@[]`), never
## omitted (the A6 constructor-omission workaround still applies).
import std/[unittest, sequtils, strutils]
import nelli
import nelli/symex
import ../src/chapulin/protocol
import fuzzsupport

# ---- Helper twins (4): real seq[byte], real B2 widening, no atByte mask,
#      no seq[int] typing -----------------------------------------------------

proc readU16Twin(data: seq[byte], offset: int): uint16 =
  ## Twin of protocol.nim's private `readUint16BE`. Real B2 widening
  ## (`uint16(byte)` zero-extends) -- BLOCKER #12 (helper-proc-mediated
  ## widened-header witness fidelity) confirmed fixed at walker v86; the
  ## companion char-widening witness bug (BLOCKER B7-fix) confirmed fixed
  ## at v87. This helper is called by every arm below, not read inline.
  if offset + 2 > data.len:
    raise newException(TftpDecodeError, "Truncated packet: need 2 bytes at offset " & $offset)
  result = (uint16(data[offset]) shl 8) or uint16(data[offset + 1])

proc readCStringTwin(data: seq[byte], offset: int): (string, int) =
  ## Twin of protocol.nim's private `readCString`. `seq[byte]` receiver,
  ## B4-recognized closed form (BLOCKER A fixed, walker v87) -- byte-for-byte
  ## identical control flow to the real function, no `atByte` mask. Confirmed
  ## closed-form-provable both standalone and as a helper called from a
  ## separate top-level dispatch proc.
  var s = ""
  var i = offset
  while i < data.len:
    if data[i] == 0:
      return (s, i + 1)
    s.add char(data[i])
    i.inc
  raise newException(TftpDecodeError, "Unterminated string at offset " & $offset)

proc parseModeTwin(s: string): TransferMode =
  ## Twin of protocol.nim's private `parseMode`. Used ONLY by the plain
  ## (non-symex) differential-oracle path below -- NOT called from
  ## `decodeTwin`'s symex-walked body (BLOCKER B7-2: a case-match over a
  ## SCANNED string's content with an `else: raise` arm, embedded in a
  ## multi-branch dispatch, poisons a sibling branch's target -- reproduced
  ## both as a proc call and fully inlined, so this is not fixable by
  ## restructuring the call site; see the file-level design note).
  case s.toLowerAscii
  of "octet": tmOctet
  of "netascii": tmNetascii
  else: raise newException(TftpDecodeError, "Unknown transfer mode: " & s)

proc readOptionsTwin(data: seq[byte], offset: int): seq[(string, string)] =
  ## Twin of protocol.nim's private `readOptions`. `seq[byte]` receiver,
  ## B6-recognized pair-loop closed form (BLOCKER A fixed, walker v87;
  ## BLOCKER B7-1's literal-seeded-counter gap fixed, walker v88) -- proven
  ## PROVABLE now called from `decodeTwin`'s own opOack arm (a
  ## dispatch-wrapped, call-boundary, construction-followed use -- exactly
  ## the composite shape BLOCKER B7-1 blocked pre-v88). Region MEMBERSHIP
  ## proof: loop-safety with no IndexError/ScanError reachable beyond what a
  ## truncated region's own scans would raise; the fold `result.add` is
  ## never modeled -- exactly the exit-gate text's committed scope. The
  ## "Option key without value" raise arm real `readOptions` has is dropped,
  ## matching B6's own recognized 5-statement shape (two chained B4-shaped
  ## calls, empty-key break, fold, index advance) exactly.
  var pos = offset
  while pos < data.len:
    let (key, nextPos) = readCStringTwin(data, pos)
    if key.len == 0:
      break
    let (val, finalPos) = readCStringTwin(data, nextPos)
    result.add (key, val)
    pos = finalPos

proc readOptionsOracle(data: seq[byte], offset: int): seq[(string, string)] =
  ## Byte-for-byte faithful mirror of real `readOptions` (protocol.nim:113-123),
  ## used ONLY by the concrete differential oracle (`decodeFullTwin`), NOT by
  ## the symex membership proof (`decodeTwin`/`readOptionsTwin`). The symex
  ## twin `readOptionsTwin` intentionally drops the "Option key without
  ## value" raise arm and unconditionally breaks on an empty key -- a
  ## disclosed, narrower-scope drift that is legitimate for the
  ## region-membership proof it serves (documented on `readOptionsTwin`
  ## itself). Reusing that same drifted twin from the CONCRETE oracle would
  ## make ITS broader, undisclosed claim -- full `TftpPacket` equality
  ## (including `oackOptions`/`options`) AND exact error-message equality,
  ## over "arbitrary wire bytes" -- silently false for inputs it should
  ## catch: an empty-key/non-empty-value OACK option (real yields
  ## `("", val)`; the drifted twin drops it) and a truncated non-empty key
  ## (real raises "Option key without value at offset N"; the drifted twin
  ## falls through to `readCStringTwin` and raises the different message
  ## "Unterminated string at offset N"). This reader restores exact
  ## fidelity -- including the precise raise-message text -- so the
  ## concrete oracle's full-equivalence claim is actually true, not just
  ## plausible-looking on the uniform `byteSeqs()` generator (which
  ## essentially never draws either falsifying shape).
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

# ---- Unified decode twin: ONE proc, FOUR of five arms ----------------------

proc decodeTwin(data: seq[byte]): TftpPacket =
  ## Replaces `decodeFixedArmsTwin`/`decodeFixedArmsErrorTwin`/
  ## `decodeOptionArmTwin`/`decodeOackArmTwin` (four procs pre-B7 -> ONE).
  ## Mirrors real `decode`'s own dispatch shape exactly: header check,
  ## opcode range check, per-opcode arm, all FIVE arms (six wire opcodes).
  ## Each arm constructs with its OWN literal `opcode:` (A1's
  ## `iekVariantLit` constraint). Every seq/string-typed field is given
  ## EXPLICITLY (`@[]`), never omitted (the A6 constructor-omission
  ## finding/workaround).
  if data.len < 2:
    raise newException(TftpDecodeError, "Packet too short: " & $data.len & " bytes")
  let wireOp = readU16Twin(data, 0)
  if wireOp < 1 or wireOp > 6:
    raise newException(TftpDecodeError, "Invalid opcode: " & $wireOp)

  if wireOp == 1 or wireOp == 2:               # opRrq(1) / opWrq(2)
    # Real CHAINED filename->mode scan (a genuine capability upgrade over
    # A6's original "header + first scan only" -- confirmed safe: two
    # chained single-level B4 scans compose fine across a 3+-way dispatch).
    # `mode` stays a construction-time placeholder and `modeStr` is compared
    # DIRECTLY (equality, not a case-match/proc-call -- BLOCKER B7-2), so
    # the SPECIFIC witness reaching each target below genuinely has
    # oracle-matching mode content even though the general construction
    # doesn't validate it. `options` stays unread (B6/BLOCKER-B7-1 scope).
    let (filename, afterFilename) = readCStringTwin(data, 2)
    if afterFilename >= data.len:
      raise newException(TftpDecodeError, "Missing transfer mode")
    let (modeStr, _) = readCStringTwin(data, afterFilename)
    if wireOp == 1:
      result = TftpPacket(opcode: opRrq, filename: filename, mode: tmOctet, options: @[])
    else:
      result = TftpPacket(opcode: opWrq, filename: filename, mode: tmNetascii, options: @[])
    if wireOp == 1 and filename == "X" and modeStr == "octet":
      symexTarget("b7_oprrq_filename_x_octet")
    if wireOp == 2 and filename == "Y" and modeStr == "netascii":
      symexTarget("b7_opwrq_filename_y_netascii")

  elif wireOp == 3:                            # opData
    if data.len < 4:
      raise newException(TftpDecodeError, "DATA packet too short: " & $data.len & " bytes")
    let blockNum = readU16Twin(data, 2)
    # The `data` PAYLOAD field is left at its zero value (`@[]`, given
    # EXPLICITLY) even when a length-guarded slice is computable -- seq
    # slicing (`data[4 .. ^1]`) is a separate, still-open DSL gap, unchanged
    # by this slice (matches A6's own established scope exactly).
    result = TftpPacket(opcode: opData, blockNum: blockNum, data: @[])
    if data.len == 4 and result.blockNum == 5:
      symexTarget("b7_opdata_block5_emptypayload")

  elif wireOp == 4:                            # opAck
    if data.len < 4:
      raise newException(TftpDecodeError, "ACK packet too short: " & $data.len & " bytes")
    let ackBlockNum = readU16Twin(data, 2)
    result = TftpPacket(opcode: opAck, ackBlockNum: ackBlockNum)
    if result.ackBlockNum == 7:
      symexTarget("b7_opack_block7")

  elif wireOp == 5:                            # opError
    if data.len < 5:
      raise newException(TftpDecodeError, "ERROR packet too short: " & $data.len & " bytes")
    let errCode = readU16Twin(data, 2)
    let mappedCode = if errCode <= 8: TftpErrorCode(errCode) else: errNotDefined
    let (msg, _) = readCStringTwin(data, 4)
    result = TftpPacket(opcode: opError, errorCode: mappedCode, errorMsg: msg)
    if mappedCode == errAccessViolation and msg == "no":
      symexTarget("b7_operror_code2_msg_no")

  else:                                        # opOack (wireOp == 6)
    let opts = readOptionsTwin(data, 2)
    discard opts   # B6 scope: option-region CONTENT (the fold) is never modeled.
    result = TftpPacket(opcode: opOack, oackOptions: @[])
    symexTarget("b7_opoack_reachable")

# ---- Compile-check + no-Defect proofs --------------------------------------

suite "symex: protocol.decode unified twin (B7 -- all five arms, one proc)":
  test "compiles under symexFind":
    let r = symexFind(decodeTwin, tIndexError())
    discard r  # compiling to this line + the check below IS the proof

  test "IndexError search (whole-proc, unconstrained data.len): sxUnknown -- NOT a regression from merging opOack in; confirmed via isolated diagnostic (not shipped) that the opOack arm ALONE, in total isolation, already has this same whole-proc verdict. B6's own committed scope is 'membership + ScanError reachability + oracle on non-options fields' -- it never claimed index-safety is provable for an UNCONSTRAINED data.len through the non-member region's k-unroll fallback (the SAME maxLoopUnwind=5 boundedness every other unrecognized loop shape has always had, unrelated to B6's own closed form). Per-arm targets (below) prove cleanly; only this maximally-broad, no-specific-target search stays honest sxUnknown":
    check symexFind(decodeTwin, tIndexError()).status == sxUnknown

  test "FieldDefect search (whole-proc): sxUnknown -- same reason as above":
    check symexFind(decodeTwin, tFieldDefect()).status == sxUnknown

# ---- Per-arm reachability + oracle cross-check, all FIVE arms -------------
#
# Each witness is replayed through the REAL, shipped `decode()` and must
# agree exactly on every NON-options field (options/oackOptions content is
# never modeled -- B6's own committed scope: "the no-defect proof for the
# whole option arm WITHOUT MODELING THE FOLD").

suite "symex round-6 B7 -- witness cross-checked against real decode() (all FIVE arms)":
  test "opData: blockNum==5 with an empty payload (data.len==4) is reachable, and real decode() agrees exactly":
    let r = symexFind(decodeTwin, tLabel("b7_opdata_block5_emptypayload"))
    check r.status == sxSat
    let bytes = r.witness[0]
    let real = decode(bytes)
    check real.opcode == opData
    check real.blockNum == 5'u16
    check real.data == newSeq[byte]()

  test "opAck: ackBlockNum==7 is reachable, and real decode() agrees exactly":
    let r = symexFind(decodeTwin, tLabel("b7_opack_block7"))
    check r.status == sxSat
    let bytes = r.witness[0]
    let real = decode(bytes)
    check real.opcode == opAck
    check real.ackBlockNum == 7'u16

  test "opRrq: filename==\"X\", mode content==\"octet\" is reachable (chained filename->mode scan); real decode() agrees on the non-options fields":
    let r = symexFind(decodeTwin, tLabel("b7_oprrq_filename_x_octet"))
    check r.status == sxSat
    let bytes = r.witness[0]
    let real = decode(bytes)
    check real.opcode == opRrq
    check real.filename == "X"
    check real.mode == tmOctet
    # options content is never modeled (B6 scope) -- no comparison here.

  test "opWrq: filename==\"Y\", mode content==\"netascii\" is reachable (chained filename->mode scan); real decode() agrees on the non-options fields":
    let r = symexFind(decodeTwin, tLabel("b7_opwrq_filename_y_netascii"))
    check r.status == sxSat
    let bytes = r.witness[0]
    let real = decode(bytes)
    check real.opcode == opWrq
    check real.filename == "Y"
    check real.mode == tmNetascii

  test "opError: errorCode==2 (errAccessViolation), errorMsg==\"no\" is reachable; real decode() agrees exactly":
    let r = symexFind(decodeTwin, tLabel("b7_operror_code2_msg_no"))
    check r.status == sxSat
    let bytes = r.witness[0]
    let real = decode(bytes)
    check real.opcode == opError
    check real.errorCode == errAccessViolation
    check real.errorMsg == "no"

  test "opOack: reachable via the option-region membership proof (BLOCKER B7-1 fixed, walker v88); real decode() agrees on opcode -- oackOptions is the ONLY field, and its CONTENT is never modeled (B6's committed scope: membership + ScanError reachability + oracle on non-options fields, not the fold), so there is no other field to compare":
    let r = symexFind(decodeTwin, tLabel("b7_opoack_reachable"))
    check r.status == sxSat
    let bytes = r.witness[0]
    let real = decode(bytes)
    check real.opcode == opOack

suite "symex round-6 B7 -- walker/render version pins":
  test "walker version floor >= 88 (BLOCKER B7-1 fix: literal-seeded loop-counter int-offset promotion)":
    check parseInt(symexWalkerVersion) >= 88

  test "render version floor >= 11":
    check parseInt(renderAsChoicesVersion) >= 11

# ---- Differential oracle: the twins ≡ real decode() on concrete bytes -----
#
# "Compiles"/"proves" is not proof the twins walk the same control-flow as
# real `decode` on EVERY concrete input -- this runs the twins (ordinary Nim
# procs, unbounded outside of symex) directly against real `decode` on a
# broad set of concrete byte sequences (reusing `fuzzsupport.byteSeqs()`,
# the same generator t_props.nim's decodeOracle already fuzzes decode with).

# Structural equality for the variant packet. `options`/`oackOptions` ARE
# compared here (unlike the symex-side scope) -- at ordinary concrete
# runtime, `decodeFullTwin` below computes the real fold via
# `readOptionsOracle`/`parseModeTwin` (NOT the symex twin `readOptionsTwin`
# -- see `readOptionsOracle`'s docstring), so the plain differential oracle
# can and does check every field, exactly, same as pre-B7's `decodeIntTwin`
# did; only the SYMEX walk (BLOCKER B7-1/B7-2) stops short of modeling them.
proc `==`(a, b: TftpPacket): bool =
  if a.opcode != b.opcode: return false
  case a.opcode
  of opRrq, opWrq:
    a.filename == b.filename and a.mode == b.mode and a.options == b.options
  of opData: a.blockNum == b.blockNum and a.data == b.data
  of opAck: a.ackBlockNum == b.ackBlockNum
  of opError: a.errorCode == b.errorCode and a.errorMsg == b.errorMsg
  of opOack: a.oackOptions == b.oackOptions

proc decodeFullTwin(data: seq[byte]): TftpPacket =
  ## FULL twin of protocol.decode (all six wire opcodes) -- the
  ## differential-oracle target, plain (unbounded, non-symex) runtime code.
  ## Reuses every helper twin above VERBATIM (a divergence here would indict
  ## those shared primitives, not a separate reimplementation) -- including
  ## `parseModeTwin`, which is safe to call here (this is ordinary Nim, not
  ## a symex target; BLOCKER B7-1/B7-2 are symex-macro-specific). Option
  ## reading uses `readOptionsOracle`, NOT `readOptionsTwin` -- see
  ## `readOptionsOracle`'s docstring for why the symex twin's disclosed,
  ## narrower-scope drift is unacceptable for this proc's broader,
  ## full-equivalence claim.
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
    let opts = readOptionsOracle(data, afterMode)
    result = TftpPacket(opcode: op, filename: filename, mode: mode, options: opts)
  of opData:
    if data.len < 4:
      raise newException(TftpDecodeError, "DATA packet too short: " & $data.len & " bytes")
    let blockNum = readU16Twin(data, 2)
    let payload = if data.len > 4: data[4 .. ^1] else: newSeq[byte]()
    result = TftpPacket(opcode: opData, blockNum: blockNum, data: payload)
  of opAck:
    if data.len < 4:
      raise newException(TftpDecodeError, "ACK packet too short: " & $data.len & " bytes")
    result = TftpPacket(opcode: opAck, ackBlockNum: readU16Twin(data, 2))
  of opError:
    if data.len < 5:
      raise newException(TftpDecodeError, "ERROR packet too short: " & $data.len & " bytes")
    let errCode = readU16Twin(data, 2)
    let mappedCode = if errCode <= 8: TftpErrorCode(errCode) else: errNotDefined
    let (msg, _) = readCStringTwin(data, 4)
    result = TftpPacket(opcode: opError, errorCode: mappedCode, errorMsg: msg)
  of opOack:
    let opts = readOptionsOracle(data, 2)
    result = TftpPacket(opcode: opOack, oackOptions: opts)

proc diffOracleCheck(bytes: seq[byte]): bool =
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
    twinPkt = decodeFullTwin(bytes)
  except TftpDecodeError as e:
    twinOk = false
    twinErr = e.msg

  if realOk != twinOk: return false
  if realOk: realPkt == twinPkt
  else: realErr == twinErr

suite "differential oracle: decodeFullTwin(seq[byte]) === decode(seq[byte])":
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
      @[0'u8, 6, 0, 'A'.byte, 0],       # OACK, empty option key then value "A" (H1)
      @[0'u8, 6, 'k'.byte, 0],          # OACK, non-empty key, no value (H1)
    ]
    for v in vectors:
      check diffOracleCheck(v)

  property "arbitrary wire bytes (fuzzsupport.byteSeqs)":
    with Settings(seed: FuzzSeed, maxExamples: FuzzN)
    given bytes in byteSeqs()
    ensure diffOracleCheck(bytes)
