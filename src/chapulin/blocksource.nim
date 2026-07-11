## `BlockSource`/`BlockSink` — the byte source/sink abstraction (RFC
## in-memory-sources-sinks.md, slice 1).
##
## Sits directly under `protocol.nim` in the DAG: pure I/O plumbing, no
## dependency on `transfer.nim`. Forward-stream only (§2 of the RFC) — no
## seeking, no block-number-addressed reads. `toReadData` is the seam that
## adapts a `BlockSource`'s `read(n)` to `transfer.nim`'s block-indexed
## `readData` contract, absorbing the "short-but-nonzero is not EOF, keep
## pulling" loop and owning the ascending-once-per-block + oversized-read
## guards for every mode (§4, §7).
##
## Defects: structural avoidance only (§6) — this module raises exactly one
## error type, `BlockSourceOrderError`, for genuine contract violations. It
## never catches `Defect`.

import std/options
import std/os
import coverpragma

type
  BlockSource* = object
    read*: proc(n: int): seq[byte] {.closure.}
      ## Forward-only pull. Returns 1..n bytes while data remains; a true
      ## empty result signals EOF ("short but non-empty" is NOT eof). Returns
      ## seq[byte] (not a filled buffer) to match the sibling `TransportRecvProc`
      ## precedent (transfer.nim:19), which is the codebase's established shape
      ## for a closure-record I/O boundary. After empty, not called again.
    close*: proc() {.closure.}
      ## Release the backing resource; called exactly once on EVERY exit path
      ## (success or failure). Because the factory owns `open()`, the value
      ## must own `close()` -- without this, every production transfer leaks
      ## a file descriptor. No-op for memory adapters.

  BlockSink* = object
    write*: proc(data: seq[byte]): bool {.closure.}
      ## true iff every byte accepted; false on a short/failed write (ENOSPC).
      ## Must not partially apply data and report true.
    finish*: proc(success: bool): bool {.closure.}
      ## Terminal flush, called **at most once — only if the final block is
      ## reached** (a mid-stream cancel/timeout calls it ZERO times; nothing
      ## needs flushing on that path). `finish` is NOT a guaranteed cleanup
      ## hook -- that is `close` (always, every exit path). success=false:
      ## apply nothing beyond what `write` already committed -- never resolve
      ## a transform's dangling tail (e.g. netascii's pending CR) from an
      ## aborted transfer. Returns true iff the terminal step succeeded.
    close*: proc() {.closure.}
      ## Release the backing resource; exactly once, every exit path. No-op
      ## for memory adapters. (Same FD-leak fix as BlockSource.close.)

  OpenedSource* = tuple[source: BlockSource, size: Option[int64]]
    ## What a source factory returns on success: the source AND its octet
    ## (pre-translation) byte size for tsize. `size` is `Option[int64]`:
    ## every real adapter returns `some(n)`, but a future sizeless source
    ## (socket/generator) returns `none` rather than a sentinel.

  BlockSourceOrderError* = object of CatchableError
    ## The ONE error type this module raises: an out-of-contract call --
    ## `blockNum` not exactly last+1, or a `read` returning more than `n`
    ## bytes (§7). A plain `CatchableError`, NOT a Defect-catch (§6 -- this
    ## RFC does not catch Defects).

  BlockSourceFactory* = proc(path: string): Option[OpenedSource] {.closure.}
    ## RFC §5.1 -- the injectable construction seam for a `BlockSource`,
    ## mirroring the existing `transportFactory`/`listenerFactory` idiom
    ## (`api.nim`). `nil` => the caller falls back to a file-backed default.
    ## Raise-preserving, THREE-outcome contract (same as today's
    ## `fileExists`+`open`+`getFileSize` trio, folded into one call):
    ## - `none`           => genuinely absent (replaces a standalone
    ##                       `fileExists` check returning false).
    ## - `raise`          => present but unopenable (permission error on
    ##                       `open`, etc.) -- the built-in file-backed
    ##                       default (`defaultBlockSourceFactory`, below)
    ##                       always raises `IOError` for this outcome,
    ##                       INCLUDING a post-open size-query failure (a
    ##                       `std/os.getFileSize` `OSError`, which it
    ##                       catches and re-raises as `IOError` so this
    ##                       stays a single outcome). Call sites therefore
    ##                       catch `except IOError` for the built-in
    ##                       default -- but because this is a bare closure
    ##                       type, Nim cannot enforce "raises IOError only"
    ##                       on an arbitrary INJECTED factory, so every call
    ##                       site also catches `OSError` defensively (a test
    ##                       double or future factory that raises `OSError`
    ##                       directly still produces the same client-visible
    ##                       outcome, never an escape).
    ## - `some(opened)`   => opened; `opened.size` feeds tsize.

  BlockSinkFactory* = proc(path: string): BlockSink {.closure.}
    ## RFC §5.1 -- the injectable construction seam for a `BlockSink`. `nil`
    ## => the caller falls back to a file-backed default (`open(path,
    ## fmWrite)`). Raises `IOError` on open failure, matching today's narrow
    ## `except IOError` at the call site -- a test double simulating an open
    ## failure MUST raise `IOError` specifically to be caught there.

proc toReadData*(source: BlockSource): proc(blockNum: uint16, blocksize: int): seq[byte] =
  ## Adapts `source.read(n)` to `transfer.nim`'s block-indexed `readData`
  ## contract. Owns two hard invariants (§4, §7):
  ## - `blockNum` must be exactly `lastBlock + 1` on every call (ascending-once).
  ## - `source.read(want)` must never return more than `want` bytes.
  ## Both violations raise `BlockSourceOrderError`.
  var lastBlock: uint16 = 0
  result = proc(blockNum: uint16, blocksize: int): seq[byte] {.cover.} =
    if blockNum != lastBlock + 1:
      raise newException(BlockSourceOrderError,
        "readData must be invoked exactly once per block, strictly ascending")
    lastBlock = blockNum
    var buf: seq[byte] = @[]
    while buf.len < blocksize:
      let want = blocksize - buf.len
      let chunk = source.read(want)
      if chunk.len == 0: break
      if chunk.len > want:
        raise newException(BlockSourceOrderError,
          "BlockSource.read returned more bytes than requested (would emit an over-length DATA packet)")
      buf.add chunk
    buf

proc fileBlockSource*(file: File): BlockSource =
  result.read = proc(n: int): seq[byte] {.cover.} =
    var buf = newSeq[byte](n)
    let got = file.readBytes(buf, 0, n)
    buf.setLen(got)
    buf
  result.close = proc() = file.close()   # every ctor MUST set close --
                                         # an unset field is nil => NilAccessDefect at cleanup.

proc fileBlockSink*(file: File): BlockSink =
  result.write = proc(data: seq[byte]): bool {.cover.} =
    data.len == 0 or file.writeBytes(data, 0, data.len) == data.len
  result.finish = proc(success: bool): bool {.cover.} =
    if success: flushFile(file)
    true
  result.close = proc() = file.close()

proc memoryBlockSource*(data: seq[byte]): BlockSource =
  var pos = 0
  result.read = proc(n: int): seq[byte] {.cover.} =
    let take = min(n, data.len - pos)
    result = data[pos ..< pos + take]
    pos += take
  result.close = proc() = discard         # memory adapters own no OS handle.

proc memoryBlockSink*(buf: ref seq[byte]): BlockSink =
  ## `ref` box, not a `var` param -- a closure cannot capture a `var`
  ## parameter. The caller keeps its own `ref` to inspect the accumulated
  ## bytes after the transfer.
  ##
  ## Caveat: `write` appends unconditionally with no size cap (below). Wiring
  ## this sink to a network-facing WRQ handler exposes a RAM-exhaustion DoS --
  ## TFTP `tsize` is advisory only, and the receive loop enforces no cap of
  ## its own, so a remote client can stream an arbitrarily large WRQ straight
  ## into an ever-growing in-memory buffer. A hard cap belongs in the
  ## embedder's `sinkFactory` or in receive-loop policy, not in this
  ## primitive -- it is not added here.
  result.write = proc(data: seq[byte]): bool {.cover.} =
    buf[].add data
    true
  result.finish = proc(success: bool): bool = true
  result.close = proc() = discard

proc defaultBlockSourceFactory*(): BlockSourceFactory =
  ## The file-backed default every `sourceFactory` resolver (api.nim's
  ## `TftpSession`, server.nim's `ServerConfig`) falls back to when no
  ## factory is injected. Hoisted here (RFC in-memory-sources-sinks.md §5.1,
  ## code-review S4-1/S4-3) so the two call sites collapse to one line
  ## instead of hand-rolling an identical closure, and so the fix below
  ## lives in exactly one place.
  ##
  ## Fixes a regression vs. the pre-RFC direct-call sequence (which computed
  ## size BEFORE opening): Nim evaluates a tuple literal left-to-right, so
  ## `(fileBlockSource(open(path, fmRead)), some(getFileSize(path)))` opens
  ## the file FIRST and only then queries its size -- a `getFileSize`
  ## failure after a successful `open` then leaves the just-opened `File` a
  ## discarded temporary with no `close`, leaking a file descriptor. Query
  ## the size first instead, so a size-query failure never has an open
  ## handle to leak.
  ##
  ## `std/os.getFileSize` raises `OSError`, not `IOError` -- caught and
  ## re-raised as `IOError` here so a size-query failure collapses onto the
  ## SAME "present but unopenable" outcome a real `open` failure produces
  ## (see `BlockSourceFactory`'s contract doc above), rather than a second,
  ## differently-typed failure mode call sites would need to know about.
  proc(path: string): Option[OpenedSource] =
    if not fileExists(path): none(OpenedSource)
    else:
      var sz: int64
      try:
        sz = getFileSize(path)
      except OSError as e:
        raise newException(IOError, e.msg)
      some((fileBlockSource(open(path, fmRead)), some(sz)))

proc defaultBlockSinkFactory*(): BlockSinkFactory =
  ## Same contract, sink side: `open(path, fmWrite)`, raising `IOError` on
  ## failure exactly like today's direct construction (no size query on this
  ## side, so there is no equivalent leak/wrong-exception hazard to fix).
  proc(path: string): BlockSink = fileBlockSink(open(path, fmWrite))
