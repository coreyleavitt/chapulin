## Tests for `blocksource.nim` (RFC in-memory-sources-sinks.md, slice 1):
## BlockSource/BlockSink, the four first-party adapters, and `toReadData`'s
## two hard invariants (ascending-once-per-block, oversized-read).
##
## Run in the nim devtools container:
##   pwsh scripts/dev-test.ps1 -Only @('t_blocksource')

import std/unittest
import std/os
import proptest
import fuzzsupport
import ../src/chapulin/blocksource

suite "toReadData -- EOF signaling (short-but-nonzero is NOT eof)":
  test "a true empty read signals EOF immediately":
    let src = BlockSource(
      read: proc(n: int): seq[byte] = @[],
      close: proc() = discard)
    let reader = toReadData(src)
    check reader(1, 10) == newSeq[byte]()

  test "short-but-nonzero reads are absorbed -- toReadData keeps pulling until blocksize or true EOF":
    # First call returns 1 byte, second returns 2 more (still short of the
    # requested 10), third returns empty -- the only one that is true EOF.
    # A buggy implementation that treated "short" as EOF would stop after the
    # first or second call and return a truncated 1- or 3-byte block instead
    # of continuing to pull.
    var calls = 0
    let chunks = @[@[byte('A')], @[byte('B'), byte('C')], newSeq[byte]()]
    let src = BlockSource(
      read: proc(n: int): seq[byte] =
        result = chunks[calls]
        calls.inc,
      close: proc() = discard)
    let reader = toReadData(src)
    let blk = reader(1, 10)
    check blk == @[byte('A'), byte('B'), byte('C')]
    check calls == 3  # kept pulling past both short-but-nonzero reads

suite "toReadData -- ascending-once-per-block guard":
  test "calling with a blockNum that skips ahead raises BlockSourceOrderError":
    let src = memoryBlockSource(@[byte('A'), byte('B'), byte('C'), byte('D')])
    let reader = toReadData(src)
    discard reader(1, 2)
    expect BlockSourceOrderError:
      discard reader(3, 2)  # skipped block 2

  test "invoking the same block twice raises BlockSourceOrderError":
    let src = memoryBlockSource(@[byte('A'), byte('B')])
    let reader = toReadData(src)
    discard reader(1, 2)
    expect BlockSourceOrderError:
      discard reader(1, 2)  # same block again -- not ascending

suite "toReadData -- oversized-read guard":
  test "a source whose read(n) over-returns raises BlockSourceOrderError":
    let misbehaving = BlockSource(
      read: proc(n: int): seq[byte] = newSeq[byte](n + 1),  # deliberately over-returns
      close: proc() = discard)
    let reader = toReadData(misbehaving)
    expect BlockSourceOrderError:
      discard reader(1, 4)

suite "close -- non-nil and fires for every adapter":
  test "memoryBlockSource.close is non-nil and fires":
    var source = memoryBlockSource(@[byte(1)])
    check source.close != nil
    var fired = false
    let orig = source.close
    source.close = proc() =
      fired = true
      orig()
    source.close()
    check fired == true

  test "memoryBlockSink.close is non-nil and fires":
    var buf = new(seq[byte])
    var sink = memoryBlockSink(buf)
    check sink.close != nil
    var fired = false
    let orig = sink.close
    sink.close = proc() =
      fired = true
      orig()
    sink.close()
    check fired == true

  test "fileBlockSource.close is non-nil, fires, and does not crash":
    let path = getTempDir() / "t_blocksource_file_source_close.tmp"
    writeFile(path, "hello")
    let f = open(path, fmRead)
    var source = fileBlockSource(f)
    check source.close != nil
    var fired = false
    let orig = source.close
    source.close = proc() =
      fired = true
      orig()
    source.close()
    check fired == true
    removeFile(path)

  test "fileBlockSink.close is non-nil, fires, and does not crash":
    let path = getTempDir() / "t_blocksource_file_sink_close.tmp"
    let f = open(path, fmWrite)
    var sink = fileBlockSink(f)
    check sink.close != nil
    var fired = false
    let orig = sink.close
    sink.close = proc() =
      fired = true
      orig()
    sink.close()
    check fired == true
    removeFile(path)

suite "memoryBlockSource / memoryBlockSink -- round trip":
  test "memoryBlockSource round-trips bytes across short pulls":
    let data = @[byte(1), byte(2), byte(3), byte(4), byte(5)]
    let src = memoryBlockSource(data)
    var got: seq[byte] = @[]
    while true:
      let chunk = src.read(2)
      if chunk.len == 0: break
      got.add chunk
    check got == data

  test "memoryBlockSink accumulates written bytes into the caller's ref; finish(true) returns true":
    var buf = new(seq[byte])
    let sink = memoryBlockSink(buf)
    check sink.write(@[byte('a'), byte('b')]) == true
    check sink.write(@[byte('c')]) == true
    check buf[] == @[byte('a'), byte('b'), byte('c')]
    check sink.finish(true) == true

# --- never-throw fuzz verification (ordinary never-throw, NOT a Defect canary) ----

proc memoryNeverThrowOracle(data: seq[byte]): bool =
  ## Drives `memoryBlockSource`/`memoryBlockSink` through `toReadData` in the
  ## same strict, ascending, in-order fashion `transfer.nim` itself calls
  ## `readData` -- so `BlockSourceOrderError` should never fire either. No
  ## `except` clause: any exception escaping here, of any kind, is itself
  ## the finding (mirrors `validateAndParseOackOracle`, t_props.nim).
  let src = memoryBlockSource(data)
  let reader = toReadData(src)
  var buf = new(seq[byte])
  let sink = memoryBlockSink(buf)
  var blockNum: uint16 = 1
  while true:
    let blk = reader(blockNum, 8)
    discard sink.write(blk)
    if blk.len < 8: break
    blockNum.inc
  discard sink.finish(true)
  src.close()
  sink.close()
  true

proc fileNeverThrowOracle(data: seq[byte]): bool =
  ## Same drive, backed by real file adapters over a fresh temp file per
  ## example -- proves the never-throw property for the file-backed pair too,
  ## not only the in-memory one.
  let path = getTempDir() / "t_blocksource_fuzz.tmp"
  writeFile(path, "")
  block:
    let wf = open(path, fmWrite)
    let sink = fileBlockSink(wf)
    discard sink.write(data)
    discard sink.finish(true)
    sink.close()
  let rf = open(path, fmRead)
  let src = fileBlockSource(rf)
  let reader = toReadData(src)
  var blockNum: uint16 = 1
  while true:
    let blk = reader(blockNum, 8)
    if blk.len < 8: break
    blockNum.inc
  src.close()
  removeFile(path)
  true

suite "blocksource -- never-throw fuzz verification":
  fuzzProperty("memoryBlockSource/memoryBlockSink never throw over adversarial byte inputs",
               "blocksource.memoryRoundtrip"):
    given data in byteSeqs()
    ensure memoryNeverThrowOracle(data)

  fuzzProperty("fileBlockSource/fileBlockSink never throw over adversarial byte inputs",
               "blocksource.fileRoundtrip"):
    given data in byteSeqs(200)
    ensure fileNeverThrowOracle(data)
