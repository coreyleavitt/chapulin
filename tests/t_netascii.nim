## Tests for the stateful netascii transformers (RFC-conformance-closure,
## slice 6 / D1a). Crux under test: `feed` must never resolve a `CR` via
## in-call lookahead -- a CR/LF or CR/NUL pair straddling two `feed` calls
## (i.e. a block-boundary cut on the wire) must still translate correctly.
##
## Run in the nim devtools container:
##   docker run --rm -v ${PWD}:C:\app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r tests/t_netascii.nim

import std/unittest
import std/sequtils
import std/os
import proptest
import ../src/chapulin/netascii

const
  Cr = byte('\r')
  Lf = byte('\n')
  Nul = byte(0)

suite "NetasciiEncoder.feed -- single-call translation":
  test "LF alone becomes CR LF":
    var e: NetasciiEncoder
    check e.feed(@[byte('A'), Lf, byte('B')]) == @[byte('A'), Cr, Lf, byte('B')]

  test "a lone CR (followed by an ordinary byte) becomes CR NUL":
    var e: NetasciiEncoder
    check e.feed(@[byte('A'), Cr, byte('B')]) == @[byte('A'), Cr, Nul, byte('B')]

  test "a local CR immediately followed by LF passes through as CR LF (no doubling)":
    var e: NetasciiEncoder
    check e.feed(@[Cr, Lf]) == @[Cr, Lf]

  test "ordinary bytes are untouched":
    var e: NetasciiEncoder
    let data = @[byte('h'), byte('i'), byte(0), byte(200)]
    check e.feed(data) == data

  test "empty input yields empty output and no pending state":
    var e: NetasciiEncoder
    check e.feed(@[]) == newSeq[byte]()
    check e.pendingCr == false

suite "NetasciiEncoder -- the defer-CR-across-calls contract":
  test "a CR that is the last byte of a feed call defers -- emits nothing yet":
    var e: NetasciiEncoder
    let outp = e.feed(@[byte('A'), Cr])
    check outp == @[byte('A')]
    check e.pendingCr == true

  test "straddled CR LF: feed(CR) then feed(LF) emits CR LF, not CR NUL + LF-as-CRLF":
    var e: NetasciiEncoder
    let first = e.feed(@[Cr])
    check first == newSeq[byte]()
    let second = e.feed(@[Lf])
    check second == @[Cr, Lf]

  test "straddled lone CR: feed(CR) then flush() emits the lone-CR encoding":
    var e: NetasciiEncoder
    discard e.feed(@[Cr])
    check e.pendingCr == true
    let tail = e.flush()
    check tail == @[Cr, Nul]
    check e.pendingCr == false

  test "straddled lone CR followed by more data: feed(CR) then feed(ordinary byte)":
    var e: NetasciiEncoder
    discard e.feed(@[Cr])
    let second = e.feed(@[byte('X')])
    check second == @[Cr, Nul, byte('X')]

  test "the deferred-CR contract holds regardless of chunk size (1-byte vs whole-buffer feeds agree)":
    let data = @[byte('a'), Cr, Lf, byte('b'), Cr, byte('c')]
    var whole: NetasciiEncoder
    let wholeOut = whole.feed(data) & whole.flush()

    var chunked: NetasciiEncoder
    var chunkedOut: seq[byte]
    for b in data:
      chunkedOut.add chunked.feed(@[b])
    chunkedOut.add chunked.flush()

    check chunkedOut == wholeOut

  test "flush on an encoder with no pending CR is a no-op":
    var e: NetasciiEncoder
    discard e.feed(@[byte('A')])
    check e.flush() == newSeq[byte]()

suite "NetasciiDecoder.feed -- single-call translation":
  test "CR LF becomes LF":
    var d: NetasciiDecoder
    check d.feed(@[byte('A'), Cr, Lf, byte('B')]) == @[byte('A'), Lf, byte('B')]

  test "CR NUL becomes a literal CR":
    var d: NetasciiDecoder
    check d.feed(@[byte('A'), Cr, Nul, byte('B')]) == @[byte('A'), Cr, byte('B')]

  test "ordinary bytes are untouched":
    var d: NetasciiDecoder
    let data = @[byte('h'), byte('i'), byte(200)]
    check d.feed(data) == data

suite "NetasciiDecoder -- straddled CR LF / CR NUL across two feeds":
  test "CR LF straddled: feed(CR) then feed(LF) emits LF":
    var d: NetasciiDecoder
    let first = d.feed(@[Cr])
    check first == newSeq[byte]()
    check d.pendingCr == true
    let second = d.feed(@[Lf])
    check second == @[Lf]

  test "CR NUL straddled: feed(CR) then feed(NUL) emits a literal CR":
    var d: NetasciiDecoder
    discard d.feed(@[Cr])
    let second = d.feed(@[Nul])
    check second == @[Cr]

  test "a trailing lone wire CR resolves at flush() to a literal CR":
    var d: NetasciiDecoder
    discard d.feed(@[Cr])
    let tail = d.flush()
    check tail == @[Cr]
    check d.pendingCr == false

  test "flush on a decoder with no pending CR is a no-op":
    var d: NetasciiDecoder
    discard d.feed(@[byte('A')])
    check d.flush() == newSeq[byte]()

suite "NetasciiDecoder -- CR followed by neither LF nor NUL (R2 edge behavior)":
  test "CR followed by an ordinary byte: CR passes through literally, next byte reprocessed fresh":
    var d: NetasciiDecoder
    check d.feed(@[Cr, byte('X')]) == @[Cr, byte('X')]

  test "CR CR LF: first CR is literal (not followed by LF/NUL), second CR pairs with LF":
    var d: NetasciiDecoder
    check d.feed(@[Cr, Cr, Lf]) == @[Cr, Lf]

suite "totality on adversarial byte inputs":
  test "all-CR input never raises, through feed and flush":
    var e: NetasciiEncoder
    var d: NetasciiDecoder
    let allCr = newSeq[byte](200).mapIt(Cr)
    let wire = e.feed(allCr) & e.flush()
    discard d.feed(wire) & d.flush()

  test "all-NUL input never raises":
    var e: NetasciiEncoder
    var d: NetasciiDecoder
    let allNul = newSeq[byte](200).mapIt(Nul)
    discard e.feed(allNul) & e.flush()
    discard d.feed(allNul) & d.flush()

  test "alternating CR/LF/NUL never raises":
    var e: NetasciiEncoder
    var d: NetasciiDecoder
    var data: seq[byte]
    for i in 0 ..< 300:
      data.add (if i mod 3 == 0: Cr elif i mod 3 == 1: Lf else: Nul)
    let wire = e.feed(data) & e.flush()
    discard d.feed(wire) & d.flush()

  test "every possible byte value, one feed call each, never raises":
    for v in 0 .. 255:
      var e: NetasciiEncoder
      var d: NetasciiDecoder
      discard e.feed(@[byte(v)]) & e.flush()
      discard d.feed(@[byte(v)]) & d.flush()

  test "full 0..255 sweep in one buffer, plus its own wire round trip, never raises":
    var data = newSeq[byte](256)
    for v in 0 .. 255: data[v] = byte(v)
    var e: NetasciiEncoder
    let wire = e.feed(data) & e.flush()
    var d: NetasciiDecoder
    discard d.feed(wire) & d.flush()

suite "toNetascii / fromNetascii -- one-shot convenience wrappers":
  test "toNetascii encodes a whole buffer":
    check toNetascii(@[byte('A'), Lf]) == @[byte('A'), Cr, Lf]

  test "fromNetascii decodes a whole buffer":
    check fromNetascii(@[byte('A'), Cr, Lf]) == @[byte('A'), Lf]

  test "toNetascii resolves a trailing lone CR via its internal flush":
    check toNetascii(@[byte('A'), Cr]) == @[byte('A'), Cr, Nul]

  test "fromNetascii resolves a trailing lone wire CR via its internal flush":
    check fromNetascii(@[byte('A'), Cr]) == @[byte('A'), Cr]

suite "netasciiReader -- block-chunking read adapter (D1b, RFC-conformance-closure slice 7a)":
  test "content shorter than blocksize returns the short final block (true EOF)":
    let path = getTempDir() / "t_netascii_reader_short.tmp"
    writeFile(path, "AB")
    let f = open(path, fmRead)
    var enc: NetasciiEncoder
    let reader = netasciiReader(f, enc)
    let blk = reader(1, 10)
    check blk == @[byte('A'), byte('B')]
    f.close()
    removeFile(path)

  test "multiple full blocks then a short final block, no CR/LF involved":
    let path = getTempDir() / "t_netascii_reader_chunks.tmp"
    writeFile(path, "ABCDEFGHI")
    let f = open(path, fmRead)
    var enc: NetasciiEncoder
    let reader = netasciiReader(f, enc)
    check reader(1, 4) == @[byte('A'), byte('B'), byte('C'), byte('D')]
    check reader(2, 4) == @[byte('E'), byte('F'), byte('G'), byte('H')]
    check reader(3, 4) == @[byte('I')]
    f.close()
    removeFile(path)

  test "a block landing short purely from a deferred straddled CR is NOT a false EOF (round-2 bug)":
    # Raw file bytes: A, B, C, CR, D (5 bytes). With blocksize=4, the first raw
    # read pulls exactly "ABC\r" -- enc.feed emits "ABC" and defers the
    # trailing CR (pendingCr), so the carry buffer is only 3 bytes after that
    # read: NOT yet a full block, and NOT eof (the file has more data). The
    # correct read-ahead loop keeps pulling ("D" next), which resolves the
    # deferred CR to its escaped CR-NUL form and reaches a full 4-byte block.
    # A buggy single-read implementation would have returned the 3-byte carry
    # early and mistaken it for a final (short) block.
    let path = getTempDir() / "t_netascii_reader_straddle.tmp"
    writeFile(path, "ABC\rD")
    let f = open(path, fmRead)
    var enc: NetasciiEncoder
    let reader = netasciiReader(f, enc)
    let blk1 = reader(1, 4)
    check blk1.len == 4  # NOT short -- read-ahead kept going, not a false EOF
    check blk1 == @[byte('A'), byte('B'), byte('C'), Cr]
    let blk2 = reader(2, 4)
    check blk2.len < 4  # genuine final block: true EOF (file read returned 0)
    check blk2 == @[Nul, byte('D')]
    f.close()
    removeFile(path)

  test "readData must be invoked strictly ascending -- reinvoking a block raises a catchable error":
    # Load-bearing invariant: sendBlocks calls readData exactly once per
    # block, strictly ascending; retransmits replay its own windowCache
    # instead. This used to be a `doAssert` (uncatchable AssertionDefect --
    # the tracked never-throw hazard); a future retry-logic regression that
    # violates the invariant must instead degrade to a clean transfer
    # failure, so a plain CatchableError is raised here.
    let path = getTempDir() / "t_netascii_reader_assert.tmp"
    writeFile(path, "hello world")
    let f = open(path, fmRead)
    var enc: NetasciiEncoder
    let reader = netasciiReader(f, enc)
    discard reader(1, 4)
    var trapped = false
    try:
      discard reader(1, 4)  # same block again -- not ascending
    except NetasciiReaderError:
      trapped = true
    check trapped
    f.close()
    removeFile(path)

suite "writeNetasciiTail -- terminal-write-failure seam (Fix A code-review finding)":
  # Before this fix, `finishNetasciiDecode` did
  # `discard file.writeBytes(tail, 0, tail.len)` on the terminal netascii
  # tail -- the ONLY write site in the codebase that ignored its result. A
  # short/ENOSPC write on that final <=1-byte flush was invisible: the
  # transfer reported success with a file missing its last byte. This seam
  # isolates the write-result-checking DECISION from the real `File` so it
  # can be exercised with an injected short-writing sink, without faking an
  # entire `File`.
  test "a non-empty tail that is fully written reports ok":
    let ok = writeNetasciiTail(@[byte('\r')], proc(data: seq[byte]): int = data.len)
    check ok == true

  test "a non-empty tail that is short-written (simulated ENOSPC) reports failure, not swallowed":
    let ok = writeNetasciiTail(@[byte('\r')], proc(data: seq[byte]): int = 0)
    check ok == false

  test "an empty tail is trivially ok and never invokes the sink":
    var invoked = false
    let ok = writeNetasciiTail(@[], proc(data: seq[byte]): int =
      invoked = true
      data.len)
    check ok == true
    check invoked == false

suite "finishNetasciiDecode -- return value surfaces terminal-write outcome (Fix A)":
  test "returns true when the trailing deferred CR is written successfully":
    let path = getTempDir() / "t_netascii_finish_ok.tmp"
    var f = open(path, fmWrite)
    var dec: NetasciiDecoder
    let decoded = dec.feed(@[byte('A'), Cr])  # defers the trailing CR; "A" resolves now
    discard f.writeBytes(decoded, 0, decoded.len)
    let ok = finishNetasciiDecode(f, dec, true)
    f.close()
    check ok == true
    check readFile(path) == "A\r"
    removeFile(path)

  test "returns true (nothing attempted) when success is false, even with a pending CR":
    let path = getTempDir() / "t_netascii_finish_abort.tmp"
    var f = open(path, fmWrite)
    var dec: NetasciiDecoder
    let decoded = dec.feed(@[byte('A'), Cr])
    discard f.writeBytes(decoded, 0, decoded.len)
    let ok = finishNetasciiDecode(f, dec, false)
    f.close()
    check ok == true  # not a failure -- the write was correctly skipped
    check readFile(path) == "A"
    removeFile(path)

# --- R2-scoped round-trip property + explicit documented collapse cases ------

const NetasciiAlphabet = @[Cr, Lf, Nul, byte('A'), byte('B')]

proc netasciiBytes(maxLen = 16): Strategy[seq[byte]] =
  lists(sampledFrom(NetasciiAlphabet), minLen = 0, maxLen = maxLen)

proc isCrSafe(data: seq[byte]): bool =
  ## R2 scope: a raw CR never immediately precedes a CR/LF-adjacent byte.
  for i in 0 ..< data.len - 1:
    if data[i] == Cr and (data[i+1] == Cr or data[i+1] == Lf):
      return false
  true

proc crSafeBytes(maxLen = 16): Strategy[seq[byte]] =
  netasciiBytes(maxLen).filter(isCrSafe)

suite "R2-scoped round-trip property":
  property "encode then decode is identity on CR-safe text (R2 scope)":
    given data in crSafeBytes()
    var e: NetasciiEncoder
    var d: NetasciiDecoder
    let wire = e.feed(data) & e.flush()
    let back = d.feed(wire) & d.flush()
    ensure back == data

  property "encoding is chunk-boundary agnostic on CR-safe text (straddle invariance)":
    given data in crSafeBytes(), cut in integers(0, 16)
    let c = min(cut, data.len)
    var wholeEnc: NetasciiEncoder
    let wholeOut = wholeEnc.feed(data) & wholeEnc.flush()

    var chunkedEnc: NetasciiEncoder
    let chunkedOut = chunkedEnc.feed(data[0 ..< c]) &
                     chunkedEnc.feed(data[c ..< data.len]) &
                     chunkedEnc.flush()

    ensure chunkedOut == wholeOut

  property "decoding is chunk-boundary agnostic on arbitrary wire bytes":
    given data in netasciiBytes(), cut in integers(0, 16)
    let c = min(cut, data.len)
    var wholeDec: NetasciiDecoder
    let wholeOut = wholeDec.feed(data) & wholeDec.flush()

    var chunkedDec: NetasciiDecoder
    let chunkedOut = chunkedDec.feed(data[0 ..< c]) &
                     chunkedDec.feed(data[c ..< data.len]) &
                     chunkedDec.flush()

    ensure chunkedOut == wholeOut

suite "R2 -- documented lossy collapse cases (explicit, not round-trip-clean)":
  test "[CR,LF] encodes to [CR,LF] and decodes to [LF] -- the bare CR is not recoverable":
    var e: NetasciiEncoder
    let wire = e.feed(@[Cr, Lf]) & e.flush()
    check wire == @[Cr, Lf]
    var d: NetasciiDecoder
    let back = d.feed(wire) & d.flush()
    check back == @[Lf]
    check back != @[Cr, Lf]  # explicitly NOT round-trip-clean

  test "[CR,CR,LF] encodes to [CR,NUL,CR,LF] and decodes to [CR,LF] -- loses a byte":
    var e: NetasciiEncoder
    let wire = e.feed(@[Cr, Cr, Lf]) & e.flush()
    check wire == @[Cr, Nul, Cr, Lf]
    var d: NetasciiDecoder
    let back = d.feed(wire) & d.flush()
    check back == @[Cr, Lf]
    check back.len == 2  # 3 input bytes -> 2 output bytes: a documented loss
