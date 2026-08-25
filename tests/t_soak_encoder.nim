## Byte -> choice-IR seed encoder: round-trip-through-the-ACTUAL-strategy
## test (RFC verification-harness-v2.md §3.3/§5, slice C2).
##
## THE CRITICAL TEST (RFC-mandated, non-negotiable): a structural IR
## round-trip (encode -> decode-as-IR -> same `seq[ChoiceNode]`) is
## INSUFFICIENT -- a well-formed IR seed can still decode, through the real
## strategy, to a value that ISN'T the boundary you intended (the strategy
## clamps / reinterprets the choice stream; see `datasource.nim`'s
## `drawInteger`/`drawBoolean`). So every assertion below actually calls
## `fuzzsupport.byteSeqs().generate(newReplaySource(ir))` -- the same
## `Strategy[seq[byte]]` `soak_decode.nim` fuzzes -- and checks the
## CONCRETE generated value, not merely that encoding succeeded.
##
## Two layers of proof per seed:
##   1. `generated == intendedBytes` -- byte-exact: the strategy, replayed
##      against our hand-built IR, reproduces the exact wire bytes we meant.
##   2. `protocol.decode(generated)` extracts the SAME semantic boundary
##      value we encoded (the option value string / filename) -- proving
##      the round-tripped bytes are not just byte-identical in the
##      abstract, but still parse to the intended boundary through the
##      real production decoder. This is the "produces the boundary input
##      you intended" half the RFC calls out by name.
##
## Fast + deterministic (no coverage-guided search, no z3, no Docker-side
## randomness beyond what's hand-constructed) -- REGISTERED in
## `scripts/dev-test.ps1`'s default `$tests` array (this suite's own
## judgment call, recorded in the handoff): it's exactly the shape of every
## other fast unit suite already in that list (t_protocol, t_options, ...),
## not a fuzz/soak campaign, so opting it OUT would be inconsistent with
## how every other cheap deterministic suite in this repo is treated.
##
## Run:
##   pwsh scripts/dev-test.ps1 -Only @('t_soak_encoder')

import std/[unittest, tables, strutils]
import nelli
import nelli/datasource
import ../src/chapulin/protocol
import fuzzsupport
import soakseeds

proc replayThroughByteSeqs(ir: seq[ChoiceNode]): seq[byte] =
  ## The one place this suite touches the real soak-target strategy --
  ## every test below routes through here, never through a hand-rolled
  ## "decode the IR myself" shortcut.
  var ds = newReplaySource(ir)
  byteSeqs().generate(ds)

suite "C2 byte->choice-IR encoder: round-trip through the ACTUAL strategy":

  test "one boundary value: blksize=65536 round-trips through byteSeqs() to the intended packet":
    ## RFC-mandated first vertical slice: prove ONE boundary value before
    ## building out the rest of the dictionary.
    let intended = mkOptionPacket("blksize", "65536")
    let ir = encodeByteSeqIR(intended)
    let generated = replayThroughByteSeqs(ir)
    checkpoint("intended: " & $intended)
    checkpoint("generated: " & $generated)
    check generated == intended
    let pkt = decode(generated)
    check pkt.opcode == opRrq
    check pkt.options.len == 1
    check pkt.options[0] == ("blksize", "65536")

  test "boundary option dictionary (blksize/tsize/windowsize x every boundary value)":
    let seeds = boundaryOptionSeeds()
    check seeds.len > 0  # anti-vacuity: the dictionary actually enumerated something
    for seed in seeds:
      checkpoint("seed: " & seed.id)
      let ir = encodeByteSeqIR(seed.bytes)
      let generated = replayThroughByteSeqs(ir)
      check generated == seed.bytes
      let pkt = decode(generated)
      check pkt.opcode == opRrq
      check pkt.options.len == 1
      # The concrete generated value must carry the EXACT intended boundary
      # string, not merely "some string" -- this is the "equals the
      # intended boundary" assertion, per seed.
      let expectedVal = seed.id.split('=')[1]
      check pkt.options[0][1] == expectedVal

  test "known-bad option strings round-trip to the intended (malformed) value":
    let seeds = knownBadOptionSeeds()
    check seeds.len > 0
    for seed in seeds:
      checkpoint("seed: " & seed.id)
      let ir = encodeByteSeqIR(seed.bytes)
      let generated = replayThroughByteSeqs(ir)
      check generated == seed.bytes
      if seed.id == "dangling-key":
        # Structurally malformed on purpose (RFC "known-bad option
        # strings" includes shapes decode ITSELF rejects, not only
        # strings that parse but are semantically bad) -- decode must
        # raise TftpDecodeError, proving the round-tripped bytes still
        # carry the intended dangling-key shape into the real decoder.
        expect(TftpDecodeError):
          discard decode(generated)
      else:
        let pkt = decode(generated)
        check pkt.opcode == opRrq
        check pkt.options.len == 1
        let expectedVal = seed.id.split('~')[1]
        check pkt.options[0][1] == expectedVal

  test "reserved device names round-trip to the intended filename":
    let seeds = reservedNameSeeds()
    check seeds.len > 0
    for seed in seeds:
      checkpoint("seed: " & seed.id)
      let ir = encodeByteSeqIR(seed.bytes)
      let generated = replayThroughByteSeqs(ir)
      check generated == seed.bytes
      let pkt = decode(generated)
      check pkt.opcode == opRrq
      let expectedName = seed.id.split(":", 1)[1]
      check pkt.filename == expectedName

  test "full dictionary is non-empty and every id is unique (anti-vacuity)":
    let all = allDictionarySeeds()
    check all.len > 0
    var seen = initTable[string, bool]()
    for seed in all:
      check seed.id notin seen
      seen[seed.id] = true
