## Byte -> choice-IR seed encoder (RFC verification-harness-v2.md §3.3/§5,
## slice C2). `fuzzWith`'s `fmIR` mode (C1) seeds its corpus from
## `FuzzSettings.initialIRCorpus: seq[seq[ChoiceNode]]` -- typed choice-IR,
## not raw bytes. To hand-craft a seed from a boundary value / known-bad
## string / reserved device name, we must produce the EXACT choice-IR a real
## run of the soak target's own strategy would have recorded, not merely
## "some IR that decodes to the right bytes."
##
## --- The protocol, confirmed against source (not assumed from the RFC's
## prose) -------------------------------------------------------------------
## `soak_decode.nim`'s target strategy is `fuzzsupport.byteSeqs()` ==
## `lists(integers(0, 255)).map(toByteSeq)`. Reading `strategy.nim`'s real
## `lists`/`integers` (`_deps/proptest/src/proptest/strategy.nim:410-472`):
##   - `lists` draws *element at a time*: before EVERY element (including the
##     0th), it opens a span and calls `src.drawBoolean(p)` -- a "continue?"
##     gate -- THEN (only if true) draws one `elem` (here `integers(0,255)`,
##     one `ckInteger` node), then closes the span. The sequence terminates
##     the moment a drawn boolean is `false`.
##   - So the IR for an N-byte list is exactly:
##       [bool(true), int(b0), bool(true), int(b1), ..., bool(true), int(bN-1), bool(false)]
##     -- 2N+1 nodes, boolean-then-integer interleaved, ending on a lone
##     terminating `false`. This is the RFC's "continuation-boolean
##     protocol," confirmed against `strategy.nim` line-for-line, not merely
##     cited.
##   - `datasource.nim`'s replay path (`drawBoolean`/`drawInteger`,
##     ~129-154/210-280) confirms WHY constraints on our hand-built nodes
##     mostly don't matter for the *value* that comes out, but the KIND
##     ordering matters absolutely: `takeReplay(kind)` (~120-127) raises
##     `Overrun` the instant the next recorded node's `kind` doesn't match
##     what the strategy is about to draw. Emit the wrong node kind at the
##     wrong position (e.g. a bare run of `ckInteger` nodes with no
##     interleaved booleans -- the naive first guess before reading
##     `strategy.nim`) and replay overruns immediately: `s.generate` raises,
##     `fuzz.nim`'s `captureIR` catches `Overrun` and returns `(ok: false,
##     ...)`, and the seed is silently dropped from `initialIRCorpus` --
##     never even reaching the mutation loop. This module's own
##     `t_soak_encoder.nim` proves this empirically (RED before GREEN): the
##     naive all-integer encoder was built first, confirmed to fail the
##     round-trip-through-`byteSeqs()` assertion (not merely "compile"), and
##     THEN replaced with the interleaved-boolean version below.
##
## Building nodes via `proptest/choice`'s validating constructors
## (`booleanChoice`/`integerChoke`, exported specifically "for test fixtures
## that hand-craft sequences" per `proptest.nim`'s own module doc) rather
## than raw `ChoiceNode(...)` object literals means a constraints bug (e.g.
## an out-of-[0,255] value) raises `ValueError` at ENCODE time, not a mystery
## divergence discovered only by the round-trip assertion -- fail fast,
## fail loud.
##
## Reusable for C3 (interop-captured packet seeds harvest through this same
## encoder, per the RFC's own instruction) -- `encodeByteSeqIR` has no
## dependency on *where* the bytes came from (hand-built boundary packet,
## captured wire packet, whatever).

import nelli
import nelli/choice
import ../src/chapulin/protocol

proc encodeByteSeqIR*(bytes: openArray[byte]): seq[ChoiceNode] =
  ## Encode `bytes` as the choice-IR `fuzzsupport.byteSeqs()`
  ## (`lists(integers(0,255)).map(toByteSeq)`) would have recorded had it
  ## generated exactly this sequence. See the module doc comment for the
  ## protocol this must match and why (confirmed against `strategy.nim`).
  ##
  ## GREEN (RFC-confirmed) shape: a `ckBoolean` continuation gate before
  ## EVERY element, then the element's `ckInteger`, repeated per byte, and
  ## a single trailing `ckBoolean(false)` to end the list -- 2N+1 nodes for
  ## N bytes. `p=0.9`/`forced=false` on every boolean matches the general
  ## (non-boundary-length) case `lists` itself uses for `minLen=0` inputs
  ## well under `maxLen` (the only forced cases in the real strategy are
  ## `p=1.0` below `minLen` and `p=0.0` at `maxLen`, neither reachable by
  ## the short dictionary packets this module builds) -- `permits` for a
  ## mid-range `p` admits both true and false, so `booleanChoice` accepts
  ## either value at this `p` without raising.
  ##
  ## A NAIVE (WRONG) first cut was tried here first and confirmed to fail
  ## (RFC-mandated RED phase, `t_soak_encoder.nim`): one bare `ckInteger`
  ## per byte, no continuation booleans at all. It looked plausible ("a
  ## list of bytes is a list of int choices") but the very first thing
  ## `lists` reads is a `ckBoolean`, not a `ckInteger` -- replaying that IR
  ## through the real `byteSeqs()` strategy raised `Overrun` immediately
  ## (kind mismatch: strategy wants `ckBoolean`, recorded node is
  ## `ckInteger`), dropping the seed entirely rather than merely
  ## generating an "inert" value.
  result = newSeqOfCap[ChoiceNode](bytes.len * 2 + 1)
  for b in bytes:
    result.add booleanChoice(true, 0.9)
    result.add integerChoice(int(b), 0, 255, 0)
  result.add booleanChoice(false, 0.9)

# --- Seed dictionary (RFC C2: boundary values / known-bad strings / ---------
# --- reserved device names) -------------------------------------------------

const BoundaryValueStrings* = @[
  "0",                              # zero
  "-1",                             # negative-ish
  "65535", "65536", "65537",        # 2^16 -1 / 2^16 / 2^16 +1
  "4294967295", "4294967296", "4294967297",  # 2^32 -1 / 2^32 / 2^32 +1
  "9223372036854775807",            # 2^63 -1 (int64 max)
  "9223372036854775808",            # 2^63 (overflows int64 as a string value)
  "9223372036854775809",            # 2^63 +1
  "-9223372036854775808",           # int64 min -- the sharpest "negative-ish"
]
  ## RFC §3.3/§5 C2: blksize/tsize/windowsize at 2^16/2^32/2^63 ±1, zero,
  ## negative-ish. `protocol.decode` doesn't parse these numerically itself
  ## (that's `options.nim`, a separate module/slice) -- as THIS soak
  ## target's seeds, they exercise `readOptions`' cstring-pair scanning with
  ## realistic-length numeric option values.

const KnownBadOptionStrings* = @[
  "",                     # empty value
  "abc",                  # non-numeric
  "  ",                   # whitespace-only
  "0x10",                 # hex, not decimal
  "1.5",                  # fractional
  "+5",                   # explicit-sign
  "NaN",
  "-",                    # bare sign, no digits
  "99999999999999999999999999999999999999",  # absurdly oversized
]

const ReservedDeviceNames* = @[
  "CON", "PRN", "AUX", "NUL",
  "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
  "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
  "con",        # case-insensitive collision
  "NUL.txt",    # extension doesn't launder a reserved stem on Windows
  "COM1.log",
]

type
  DictSeed* = tuple[id: string, bytes: seq[byte]]
    ## One dictionary entry: a human-readable id (for `checkpoint`/failure
    ## messages) and the raw wire bytes `protocol.decode` would receive.

proc mkOptionPacket*(optKey, optVal: string, filename = "f.bin"): seq[byte] =
  ## An RRQ packet in octet mode carrying exactly one `(optKey, optVal)`
  ## option -- reuses the real `protocol.encode`, never hand-derives the
  ## wire format for the well-formed cases. (Fixed to `opRrq`: `TftpPacket`
  ## is a Nim object variant, and constructing one with a *runtime* `opcode`
  ## parameter feeding the discriminator is rejected at compile time --
  ## "cannot prove that it's safe to initialize ... with the runtime value
  ## for the discriminator" -- so this stays a same-shape RRQ-only helper
  ## rather than parameterizing over opcode.)
  encode(TftpPacket(opcode: opRrq, filename: filename, mode: tmOctet,
                    options: @[(optKey, optVal)]))

proc mkFilenamePacket*(filename: string): seq[byte] =
  ## An RRQ packet (no options) with `filename` as the requested name --
  ## the reserved-device-name dictionary's shape.
  encode(TftpPacket(opcode: opRrq, filename: filename, mode: tmOctet,
                    options: @[]))

proc rawCString(s: string): seq[byte] =
  ## Local NUL-terminated-cstring writer. `protocol.nim`'s own
  ## `addCString` is private (no `*`) -- correctly so, it's an encoding
  ## implementation detail, not public API -- so a test that needs a
  ## deliberately MALFORMED wire shape (one `protocol.encode` structurally
  ## cannot produce, e.g. a dangling option key with no value) writes its
  ## own minimal byte-former rather than reaching for internals.
  result = newSeq[byte](s.len + 1)
  for i, c in s: result[i] = byte(c)
  # result[s.len] is already 0 (newSeq zero-inits) -- the NUL terminator.

proc mkDanglingKeyPacket*(filename = "f.bin", key = "blksize"): seq[byte] =
  ## An RRQ packet whose option list ends immediately after a NUL-terminated
  ## KEY with no following value -- `readOptions`' "Option key without
  ## value at offset" `TftpDecodeError` arm (`protocol.nim:117-118`).
  ## Deliberately hand-built (not via `protocol.encode`, which always pairs
  ## key+value) -- a genuinely known-bad wire shape, not merely a bad
  ## string value.
  result = @[byte 0, byte 1]  # wire opcode 1 == RRQ
  result.add rawCString(filename)
  result.add rawCString("octet")
  result.add rawCString(key)  # key, NUL-terminated, then the packet just ends

proc boundaryOptionSeeds*(): seq[DictSeed] =
  ## blksize/tsize/windowsize x every boundary value.
  for key in ["blksize", "tsize", "windowsize"]:
    for val in BoundaryValueStrings:
      result.add (id: key & "=" & val, bytes: mkOptionPacket(key, val))

proc knownBadOptionSeeds*(): seq[DictSeed] =
  ## blksize/tsize/windowsize x every known-bad string, plus the
  ## dangling-key structural case (once, not per-key -- it isn't
  ## key-specific).
  for key in ["blksize", "tsize", "windowsize"]:
    for val in KnownBadOptionStrings:
      result.add (id: key & "~" & val, bytes: mkOptionPacket(key, val))
  result.add (id: "dangling-key", bytes: mkDanglingKeyPacket())

proc reservedNameSeeds*(): seq[DictSeed] =
  for name in ReservedDeviceNames:
    result.add (id: "name:" & name, bytes: mkFilenamePacket(name))

proc allDictionarySeeds*(): seq[DictSeed] =
  ## The full C2 seed dictionary in one call -- what a future `-Soak`
  ## wiring (or C3's interop-capture harvest) would fold into
  ## `protocol.decode`'s `initialIRCorpus`.
  boundaryOptionSeeds() & knownBadOptionSeeds() & reservedNameSeeds()
