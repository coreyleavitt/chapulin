# RFC: `BlockSource`/`BlockSink` — the byte source/sink abstraction

- **Status:** **Implemented — Stage 3 complete (all 5 slices green, full suite passing).** Architect rounds 1+2 done. Next: Stage 4 (`/code-review`).
- **Tracking issue:** none. **This RFC is NOT GitHub issue #13.** Issue #13 ("netascii is a no-op;
  redesign the data path around sources/sinks") described a *different* change that already shipped —
  netascii is fully wired, and issue #13 was closed by `rfc-conformance-closure`. The "#13" label got
  misattached to this work through v2's Fork A wording and is dropped here. This RFC is the residual
  byte-store *injection* seam that issue #13's redesign never actually built.
- **Related:** #17 (embedding API — deliberately deferred this seam, `embedding-api.md:333,431-437`),
  verification-harness-v2 (Part A1b's file dependency; gates on this landing first — see its
  handoff's escalation), #15 (scriptable mock network — a sibling seam, not this one)
- **Supersedes:** `netascii.nim`'s `makeSendReader(file, mode, enc)` / `makeRecvSink(file, mode)`
  signatures (behavior preserved except the disclosed octet fail-fast change, §2; `File` parameter generalized)

## Scope decision

`verification-harness-v2.handoff.md`'s escalation found GitHub issue #13's original premise stale (netascii is
already fully wired to `File` — the only real residue is that `File` is hardcoded at 4 call sites
with no injection point), and offered four scope options from "narrow injection-seam shim" up to
"full first-class abstraction." Corey's steer was **best-in-class, PhD-level design, effort no
object** — which selects the broad end: a first-class, general-purpose, production byte
source/sink abstraction, not a test-only shim, designed so embedder-supplied streams (#17),
transforms beyond netascii, and eventually async/generator sources are natural extensions rather
than rewrites. The in-memory harness need (v2 Part A1b) is satisfied as one *instance* of this
abstraction, not its reason for existing.

**Two distinct injection tiers — do not conflate them (both matter, only one is deferred):**
- **(in scope) Internal session/server factory injection.** `TftpSession`/`TftpServer` gain
  `sourceFactory`/`sinkFactory` fields that default (nil) to file-backed and can be overridden per
  construction — *exactly* the established idiom of the existing `transportFactory`/
  `listenerFactory` test seams (`api.nim:63,146-148`). **This is the actual v2 Part A(b) enabler:**
  it lets the two-real-session Wire harness run file I/O in-memory *through the real facade*
  (`api.nim setupGet/PutTransfer`, `server.nim handleRrq/Wrq`), not by calling `transfer.nim`
  directly. Without it, this RFC would not unblock what it is being drafted to unblock.
- **(deferred) Public embedder hook.** A `TransferRequest.source`/`.sink` field letting an *external*
  embedder supply a `BlockSource`/`BlockSink` on the public API surface reopens already-shipped
  RFC #17 and is a larger, deliberate decision — sketched (§5), not built here (§ Out of scope).

## Current reality (grounded in source, not memory)

Four ops, `File`-shaped, fused with mode selection:

- **Send/read** — `makeSendReader(file: File, mode: TransferMode, enc: var NetasciiEncoder): proc(blockNum: uint16, blocksize: int): seq[byte]`
  (`netascii.nim:205`). Octet branch is a stateless seek-addressed closure
  (`file.setFilePos((blockNum-1)*blocksize)` then `readBytes`, `:228-235`). Netascii branch
  (`netasciiReader`, `:136`) is strictly forward: reads raw bytes, feeds a stateful
  `NetasciiEncoder` (carries `pendingCr` across calls), buffers translated output in `carry` until
  a full block is available. It **self-enforces** "called exactly once per block, strictly
  ascending" (`:182-187`) because `sendBlocks` (`transfer.nim:290`) only ever calls `readData`
  that way in practice — retransmits replay `windowCache` (`transfer.nim:342-356`), never
  re-invoke the reader.
- **Recv/write** — `makeRecvSink(file: File, mode: TransferMode): proc(data: seq[byte], isFinal: bool): bool`
  (`netascii.nim:303`). Per-block write (decoded through `NetasciiDecoder` under netascii,
  verbatim under octet) plus, on `isFinal`, a terminal step: netascii's `finishNetasciiDecode`
  (deferred-CR tail write + durable flush, `:267`) or plain `flushFile`. `success` gates the
  terminal step (`:297`: a failed/aborted transfer must not fabricate a plausible tail from
  dangling decoder state).
- **4 call sites**, each opening a `File` inline and constructing a fresh encoder/decoder state
  with no seam for anything else: `server.nim` `handleRrq` (~498), `handleWrq` (~613); `api.nim`
  `setupGetTransfer` (~210, lazy-open inside `onData`), `setupPutTransfer` (~263).
- `transfer.nim` is the one module that must **not** change: `sendBlocks` consumes
  `readData: proc(blockNum: uint16, blocksize: int): seq[byte]`; `recvBlocks` consumes
  `onData: proc(blockNum: uint16, data: seq[byte])`. Both are plain sync procs, called directly
  (never awaited) inside `{.async.}` bodies. This RFC's abstraction sits **below** that contract
  and composes down to it — it does not touch `transfer.nim`.

## Design

### 1. The types

A new module, `src/chapulin/blocksource.nim`, sitting directly under `protocol.nim` in the DAG
(no dependency on `transfer.nim` — it's pure I/O plumbing, symmetric with how `transport.nim`
owns `Transport`):

```nim
type
  BlockSource* = object
    read*: proc(n: int): seq[byte] {.closure.}
      ## Forward-only pull. Returns 1..n bytes while data remains; a true
      ## empty result signals EOF ("short but non-empty" is NOT eof). Returns
      ## seq[byte] (not a filled buffer) to match the sibling `TransportRecvProc`
      ## precedent (transfer.nim:19), which is the codebase's established shape
      ## for a closure-record I/O boundary. After empty, not called again.
    close*: proc() {.closure.}
      ## (architect r1, Design-lens Critical) Release the backing resource;
      ## called exactly once on EVERY exit path (success or failure). Because
      ## the factory now owns `open()` (§5.1), the value must own `close()` --
      ## without this, every production transfer leaks a file descriptor.
      ## No-op for memory adapters.

  BlockSink* = object
    write*: proc(data: seq[byte]): bool {.closure.}
      ## true iff every byte accepted; false on a short/failed write (ENOSPC).
      ## Must not partially apply data and report true.
    finish*: proc(success: bool): bool {.closure.}
      ## Terminal flush, called **at most once — only if the final block is
      ## reached** (a mid-stream cancel/timeout calls it ZERO times; nothing
      ## needs flushing on that path). `finish` is NOT a guaranteed cleanup
      ## hook -- that is `close` (always, every exit path). success=false:
      ## apply nothing beyond what `write` already committed -- never resolve a
      ## transform's dangling tail (e.g. netascii's pending CR) from an aborted
      ## transfer. Returns true iff the terminal step succeeded.
    close*: proc() {.closure.}
      ## Release the backing resource; exactly once, every exit path. No-op
      ## for memory adapters. (Same FD-leak fix as BlockSource.close.)

  OpenedSource* = tuple[source: BlockSource, size: Option[int64]]
    ## (architect r1 Depth/Breadth, r2 Design) What a source factory returns on
    ## success: the source AND its octet (pre-translation) byte size for tsize.
    ## Folds today's separate `fileExists` + `getFileSize` + `open` on the
    ## RRQ/WRQ file path into ONE call (else a memory-backed RRQ stats/opens the
    ## real path and 404s before the factory is reached) -- and closes their
    ## latent open-after-stat TOCTOU. **`size` is `Option[int64]`** (r2): every
    ## real adapter returns `some(n)`, but a future sizeless source (socket/
    ## generator) returns `none` rather than a sentinel -- and tsize is already
    ## omittable downstream (`netasciiPolicyFor.suppressTsize`), so `none` costs
    ## nothing today and avoids a breaking shape change later.

  BlockSourceOrderError* = object of CatchableError
    ## The ONE error type this module raises: an out-of-contract call --
    ## `blockNum` not exactly last+1, or a `read` returning more than `n`
    ## bytes (§7). A plain `CatchableError`, NOT a Defect-catch (see §6 --
    ## this RFC does not catch Defects). Hoisted from `netasciiReader`'s old
    ## `NetasciiReaderError` so the ordering guard applies to EVERY source,
    ## not only netascii -- octet never had it before (a deliberate behavior
    ## change: octet loses incidental seek-idempotency, gains uniform
    ## fail-fast; see §2).
```

`BlockSource`/`BlockSink` are flat structs of closures — the same shape as `transfer.nim`'s
`Transport` (`send`/`recv`/`close`) and exactly the pattern `design-philosophy.md` names as the
project's transport abstraction: *"a flat struct of ... closures ... direction-neutral ... maps
directly to C function pointers for the future FFI layer, with no vtable or class hierarchy."*
That precedent is doing real work here (see §3).

### 2. Position: forward-stream, not random-access

**Forward-stream wins, and both cited facts settle it independently, not just jointly.**

- The windowCache insight already proves seeking was never load-bearing *even for the file case*:
  `sendBlocks` calls `readData` **at most once per block, strictly ascending** — a lost block is
  retransmitted by replaying the cached bytes from `windowCache` (`transfer.nim:344-356`), never
  by re-reading the source. The octet closure's `setFilePos` recomputation on every call is
  therefore not exploiting any real requirement; it's an artifact of the closure being written
  stateless (no local position to track) before `windowCache` existed to make that redundant. A
  plain sequential read produces byte-identical results. **One disclosed behavior change (architect
  r1, Depth — *not* "pure preservation"):** octet now also flows through `toReadData`'s
  ascending-once guard, so a future bug that re-invoked `readData` out of order would hard-fail an
  octet transfer (`BlockSourceOrderError`) where today's seek-addressed closure silently
  self-corrects. Deliberate: uniform fail-fast over incidental (luck-based) idempotency.
- Netascii already *requires* forward-only, stateful reads (the encoder's `pendingCr` carries
  across calls) — there has never been a mode where seeking was actually necessary.
- Future non-seekable sources (a socket, a generator, an embedder's ring buffer) **cannot**
  satisfy a seek-addressed contract at all — not "would find it inconvenient," structurally
  cannot. Designing the seam around random access would make every such source either lie (fake
  seek support with an internal buffer-everything-first fallback) or be rejected outright.

So `read(n)` takes no offset and no block number. `blockNum` never was information the *source*
needed — it existed solely so `netasciiReader` could self-check `sendBlocks`' own ascending-call
invariant. That check is real and worth keeping, but it belongs at the seam between `BlockSource`
and `transfer.nim`'s block-indexed contract, not inside every source implementation (see `toReadData`,
§4). This also means the file case gets *strictly simpler*, not just decoupled: `fileBlockSource`
never seeks.

### 3. Mechanism: closure-record, not `concept`/inheritance/`std/streams`/variant

Four candidates, evaluated against the actual requirements (open extension by code chapulin
doesn't control, runtime store selection, honest async posture, never-throw-Defect containment):

| Mechanism | Open extension by embedders | Runtime selection | Fit here |
|---|---|---|---|
| `concept` | No — concepts are structural but only bind at **compile time** per instantiation; there is no single runtime value of "any BlockSource" to pass through `api.nim`'s public surface without making `transfer.nim`/`api.nim` generic (viral through the whole call chain) | Poor — a generic proc is monomorphized per concrete type, not chosen at runtime from one call site | Rejected |
| Inheritance + `method` (vtable) | Yes, structurally | Yes | Works, but `design-philosophy.md` explicitly rejects vtables/class hierarchies for this exact class of problem (`Transport`) in favor of closures, citing a future C-callable boundary. Adopting a vtable here for the sibling abstraction would be an unexplained inconsistency |
| `std/streams.Stream` | Yes (it's the stdlib's own open extension point) | Yes | `Stream`'s contract is bytes-via-raw-`pointer`/`copyMem` (`readData(s, buffer: pointer, bufLen: int)`), plus a much larger surface than TFTP needs (`setPosition`, `getPosition`, `peekData`, `atEnd`, ...) that a source author must implement or stub. Nothing here is FFI, but it reintroduces raw-pointer plumbing into a codebase that is `seq[byte]`/`openArray[byte]` throughout — a real stylistic and safety regression for no gain, since the two-outcome (bytes-or-EOF) contract this RFC needs is much narrower than `Stream`'s |
| Object variant (`case object`) | **No** — every new kind requires adding a branch chapulin itself compiles, i.e. *closed* to third parties by construction | Yes | Rejected outright: fails the stated goal, and is the exact shape `MEMORY.md`'s never-throw-Defect note flags as a `FieldDefect` hazard (wrong-branch field access) |
| **Closure-record** (chosen) | Yes — any code, in or out of this repo, builds a `BlockSource`/`BlockSink` as a plain object literal; no base type to subclass, no vtable to register into | Yes — it's a value; pick which one to construct per call, exactly like `TftpServer.transferFactory: proc(port: int): Transport` already does | **Fits every requirement, and matches the codebase's existing precedent for the sibling `Transport` abstraction** |

**Runtime store selection** falls out for free: `BlockSource`/`BlockSink` are ordinary values, so
"which backing store" is just "which constructor did you call," decided by whatever runtime
condition the caller already has (production: always `fileBlockSource`; test: `memoryBlockSource`;
a future embedder: their own constructor) — no dispatch mechanism to design beyond the closure
call itself.

**Async — honest answer: out of scope for this RFC's `read`/`write`, and here's exactly why.**
`transfer.nim`'s `sendBlocks`/`recvBlocks` call `readData`/`onData` **synchronously**, not via
`await`, even though the enclosing procs are `{.async.}` (`transfer.nim:347`:
`readData(blkNum, config.blocksize)`, no `await`). Making `BlockSource.read` return
`Future[seq[byte]]` today would require nothing on the `BlockSource` side changing but a *real*
change in `transfer.nim` — replacing that call with `await readData(...)` — which this RFC is
explicitly constrained not to do (transfer.nim's contract "must keep working" as specified). So a
genuinely async, backpressured source (bytes trickling in over time, e.g. from a slow upstream
socket) cannot be honestly modeled by this interface yet: its `read(n)` has exactly two outcomes
(≥1 byte now, or true EOF) — there is no third "not ready yet, ask again" outcome, and forcing one
in would mean either busy-polling or blocking the single-threaded event loop (a deadlock risk, not
a solution). Two things are true at once: (a) this is a genuine gap, not swept under the rug, and
(b) the design doesn't foreclose it — a future sibling `AsyncBlockSource` (same shape, `Future`-
returning fields) is an additive type this module can gain later, gated on `transfer.nim` itself
learning to `await readData`/`onData` (a disclosed, separate, non-trivial RFC, not a tweak). What
*is* in scope and buildable today: a source that is conceptually a "generator" — `read` is already
exactly a pull-based generator (call it, get the next chunk, repeat) — chapulin needs no
`iterator`-keyword machinery for that; any closure satisfies it, including one that closes over an
embedder's cursor/generator state. The gap is specifically genuine backpressure/streaming-over-time,
not "generator-shaped" sources in general.

### 4. Composition: netascii as a source/sink decorator

Netascii is not a mode fused into the reader — it is a `BlockSource -> BlockSource` (and
`BlockSink -> BlockSink`) **decorator**, living in `netascii.nim` (which imports `blocksource.nim`):

```nim
proc netasciiSource*(inner: BlockSource): BlockSource =
  ## Local -> wire. Same state machine as today's netasciiReader (carry
  ## buffer + NetasciiEncoder), now pulling from ANY forward BlockSource
  ## instead of a File directly.
  var enc: NetasciiEncoder
  var carry: seq[byte] = @[]
  var trueEof = false
  result.read = proc(n: int): seq[byte] =
    if not trueEof:
      while carry.len < n:
        let raw = inner.read(n)
        if raw.len == 0:
          trueEof = true
          carry.add enc.flush()
          break
        carry.add enc.feed(raw)
    let take = min(n, carry.len)
    result = carry[0 ..< take]
    carry = if take < carry.len: carry[take ..< carry.len] else: @[]
  result.close = inner.close   # (r2 Crit) a decorator MUST forward close, or the
                               # wrapped file handle leaks / a nil close crashes.

proc netasciiSink*(inner: BlockSink): BlockSink =
  ## Wire -> local. Same NetasciiDecoder state machine, writing through
  ## ANY inner BlockSink.
  var dec: NetasciiDecoder
  result.write = proc(data: seq[byte]): bool =
    let decoded = dec.feed(data)
    decoded.len == 0 or inner.write(decoded)
  result.finish = proc(success: bool): bool =
    if not success: return inner.finish(false)
    let tail = dec.flush()
    let tailOk = tail.len == 0 or inner.write(tail)
    inner.finish(true) and tailOk
  result.close = inner.close   # (r2 Crit) forward close through the decorator.
```

A future transform (compression, an incremental checksum tap, encryption) plugs in **identically**
— `proc(inner: BlockSource): BlockSource` / `proc(inner: BlockSink): BlockSink` — and stacks by
composition (`netasciiSource(someOtherTransform(fileBlockSource(f)))`). This is the "source
decorator" the mode transform was asked to be: netascii is not privileged, it's just the first
instance.

**`makeSendReader`/`makeRecvSink` change signature but keep their names and one-call-per-site
shape** — the seam server.nim/api.nim already call through:

```nim
proc makeSendReader*(source: BlockSource, mode: TransferMode): proc(blockNum: uint16, blocksize: int): seq[byte] =
  toReadData(if mode == tmNetascii: netasciiSource(source) else: source)

proc makeRecvSink*(sink: BlockSink, mode: TransferMode): proc(data: seq[byte], isFinal: bool): bool =
  let s = if mode == tmNetascii: netasciiSink(sink) else: sink
  result = proc(data: seq[byte], isFinal: bool): bool =
    result = s.write(data)
    if isFinal:
      if not s.finish(result): result = false
```

Callers no longer own a `var netasciiEnc: NetasciiEncoder` (the leaky implementation detail from
today's `makeSendReader(pfile, md, netasciiEnc)`) — the decorator owns its own state entirely.

**`toReadData`** (in `blocksource.nim`) is the seam that both (a) adapts `BlockSource.read(n)` to
`transfer.nim`'s block-indexed contract, absorbing the "short-but-nonzero is not EOF, keep pulling"
loop that `netasciiReader` used to do only for itself, and (b) owns the ascending-once-per-block
guard **for every mode**, not just netascii:

```nim
proc toReadData*(source: BlockSource): proc(blockNum: uint16, blocksize: int): seq[byte] =
  var lastBlock: uint16 = 0
  result = proc(blockNum: uint16, blocksize: int): seq[byte] =
    if blockNum != lastBlock + 1:
      raise newException(BlockSourceOrderError,
        "readData must be invoked exactly once per block, strictly ascending")
    lastBlock = blockNum
    var buf: seq[byte] = @[]
    while buf.len < blocksize:
      let want = blocksize - buf.len
      let chunk = source.read(want)
      if chunk.len == 0: break
      if chunk.len > want:                            # (r2 High) the hard invariant §7 promises --
        raise newException(BlockSourceOrderError,     # was described but missing from this listing.
          "BlockSource.read returned more bytes than requested (would emit an over-length DATA packet)")
      buf.add chunk
    buf
```

### 5. Usage

**Store constructors** (`blocksource.nim`):

```nim
proc fileBlockSource*(file: File): BlockSource =
  result.read = proc(n: int): seq[byte] =
    var buf = newSeq[byte](n)
    let got = file.readBytes(buf, 0, n)
    buf.setLen(got)
    buf
  result.close = proc() = file.close()   # (r2 Crit) every ctor MUST set close --
                                         # an unset field is nil => NilAccessDefect at cleanup.

proc fileBlockSink*(file: File): BlockSink =
  result.write = proc(data: seq[byte]): bool =
    data.len == 0 or file.writeBytes(data, 0, data.len) == data.len
  result.finish = proc(success: bool): bool =
    if success: flushFile(file)
    true
  result.close = proc() = file.close()

proc memoryBlockSource*(data: seq[byte]): BlockSource =
  var pos = 0
  result.read = proc(n: int): seq[byte] =
    let take = min(n, data.len - pos)
    result = data[pos ..< pos + take]
    pos += take
  result.close = proc() = discard         # memory adapters own no OS handle.

proc memoryBlockSink*(buf: ref seq[byte]): BlockSink =
  ## `ref` box, not a `var` param -- a closure cannot capture a `var`
  ## parameter (same rule netasciiReader's doc already explains for
  ## `enc: sink NetasciiEncoder`). The caller keeps its own `ref` to
  ## inspect the accumulated bytes after the transfer, mirroring
  ## sendBlocks' existing `peakCacheBlocksOut: ref int` pattern.
  result.write = proc(data: seq[byte]): bool =
    buf[].add data
    true
  result.finish = proc(success: bool): bool = true
  result.close = proc() = discard
```

**The 4 call sites** (behavior-preserving, mechanical diffs):

```nim
# server.nim handleRrq -- RETAIN the source value; IT (not the raw File) owns close now.
# (r2 Crit/High: makeSendReader does NOT return close, so the call site must keep the source
#  and call its close -- closures are ref-shared, so the retained value's close is the live one.)
let source = fileBlockSource(file)
defer: source.close()                       # replaces today's `defer: file.close()`
let readData = makeSendReader(source, request.mode)

# server.nim handleWrq
let sink = fileBlockSink(file)
defer: sink.close()
let recvSink = makeRecvSink(sink, request.mode)

# api.nim setupPutTransfer
let source = fileBlockSource(pfile)
# cleanup = proc() = source.close()         # was: pfile.close()
let readData = makeSendReader(source, md)

# api.nim setupGetTransfer -- LAZY-OPEN (r2 High): the sink is built inside `if recvSink == nil`,
# so its close must escape to the OUTER-scope cleanup. Add a parallel outer var set in the SAME
# branch, so laziness is preserved (no file created before DATA arrives) AND close still reaches
# cleanup:
var gsink: BlockSink                         # outer scope, beside `var recvSink`
# ... inside onData's first-DATA branch (unchanged laziness):
  gfile = open(req.localPath, fmWrite)
  gsink = fileBlockSink(gfile)
  recvSink = makeRecvSink(gsink, md)
# cleanup = proc() = (if recvSink != nil: gsink.close())   # was: if recvSink != nil: gfile.close()
```

**In-memory test** (the v2 harness's actual near-term need):

```nim
var outBuf = new(seq[byte])
let onData = proc(blockNum: uint16, data: seq[byte]) =
  discard makeRecvSink(memoryBlockSink(outBuf), tmOctet)(data, data.len < blocksize)
# ... drive recvBlocks over the Wire harness ...
doAssert outBuf[] == expectedBytes
```

or on the send side: `makeSendReader(memoryBlockSource(fileBytes), tmNetascii)` — a full
`sendBlocks`/`recvBlocks` round trip with **zero disk I/O** on either side. *This direct-drive
test proves the adapters compose with the transfer primitives — but it does **not** by itself
close v2 Part A1b, because A1b needs the in-memory store reached **through the real facade**
(`api.nim`/`server.nim`), not by calling `transfer.nim` directly. That is what §5.1 provides.*

### 5.1 Session/server factory injection — the v2 Part A(b) enabler (in scope)

The 4 call sites must not hardcode `fileBlockSource(open(path))`; they construct through an
injectable factory that defaults to file-backed, mirroring the existing `transportFactory`/
`listenerFactory` seams verbatim:

```nim
type
  BlockSourceFactory* = proc(path: string): Option[OpenedSource] {.closure.}
    ## nil => file-backed default. `none` = not found (replaces `fileExists`);
    ## `some (source, size)` = opened, size feeds tsize (replaces `getFileSize`
    ## + `open`). Returning the size THROUGH the factory is what makes the
    ## harness fully hermetic — see the metadata note below.
  BlockSinkFactory* = proc(path: string): BlockSink {.closure.}
    ## nil => file-backed default (`open(path, fmWrite)`); raises `IOError` on
    ## open failure, matching today's narrow `except IOError` at the call site.
    ## A test factory wanting to simulate an open failure MUST raise `IOError`
    ## (a subtype) specifically, or it escapes that catch.
```

**Factory placement — `ServerConfig`, not `TftpServer` (architect r1, resolves a Breadth/Feasibility conflict).** `handleRrq`/`handleWrq` take `config: ServerConfig` and are called *directly* by ~20 tests with no `TftpServer` in scope (a deliberate, documented entry point). Critically, the factory needs `resolvedPath`, which is computed *inside* `handleRrq` (post-`validatePath`) — so unlike `transferFactory`/`cancelFactory` (resolved in `handleRequest` to a concrete value keyed on data known there), the factory itself must travel *with `config`*. So the fields live on **`ServerConfig`** (already in scope; zero new params, zero ripple to the direct-call tests) and on **`TftpSession`** (client side, `s` already in scope in `setupGet/PutTransfer`). One check-off: `ServerConfig` gains closure fields — confirm Nim's derived `==` (used at `t_session.nim:3180`) still compiles over a nil-default `proc` field (near-certain; both sides nil).

**Source factory has the SAME raise-preserving contract as the sink factory (r2 Depth/Feasibility
High).** `handleRrq` today distinguishes THREE outcomes, not two: absent (`fileExists` false →
`errFileNotFound`), present-but-unopenable (`open` raises `IOError` → `sendOsErrorAndFail(errAccessViolation, …)`
with OS-detail redaction, exercised by `t_server.nim:1055`), and opened. So `none` = **genuinely
absent only**; a permission/other open failure must **raise `IOError`** (not collapse to `none`,
which would downgrade EACCES to a 404). The call site keeps the existing `try/except IOError` around
the factory call. Call sites become (handleRrq shown):

```nim
# server.nim handleRrq -- config.sourceFactory nil => the file-backed default below
var opened: Option[OpenedSource]
try:
  opened = resolveSourceFactory(config)(resolvedPath)
except IOError:
  sendOsErrorAndFail(errAccessViolation, getCurrentExceptionMsg(), …); return  # present-but-unopenable
if opened.isNone: return  # errFileNotFound -- replaces the standalone fileExists(resolvedPath)
let (source, fileSize) = opened.get                        # fileSize: Option[int64] -> tsize
defer: source.close()                                      # call site RETAINS the source value and
                                                           # owns close() (closures are ref-shared;
                                                           # makeSendReader does not consume it away)
let readData = makeSendReader(source, request.mode)
```

The default file factory is therefore `proc(path): Option[OpenedSource] = (if not fileExists(path):
none(OpenedSource) else: some((fileBlockSource(open(path, fmRead)), some(getFileSize(path)))))` — the
`open` still raises `IOError` on a present-but-unopenable file, preserved by the call-site `try`.

**Security invariant (stated, not implicit):** the factory receives only the *post-`validatePath`/`checkWriteAccess`* `resolvedPath` — containment enforcement runs unconditionally, before and independent of which factory is active, so an injected memory factory can never bypass it (it never sees the raw client filename). **Metadata note:** routing existence+size through the factory is exactly what lets the harness be hermetic — the previous draft left `fileExists`/`getFileSize`/`open` on the raw path, so a memory-backed RRQ would 404 on the real FS before the factory was called. One residual, stated not hidden: `validateWritePath`'s `canonicalize`/`expandFilename` still require the configured `rootDir` to exist on disk, so a fully memory-backed run still needs a real (possibly empty) root dir — "hermetic file I/O," not "zero syscalls." **Three further disclosed residuals (r2 Breadth/Depth) — the hermetic claim is scoped to the RRQ/WRQ *data* path with `checksumMode == csNone` and no overwrite-policy:** (1) `handleWrq`'s `checkWriteAccess` does its own `fileExists(resolvedPath)` for `wpCreateOnly`/`wpOverwrite` policy — *not* routed through `sinkFactory` (the sink factory has no existence channel; a symmetric add is possible later but v2 doesn't need hermetic overwrite-policy testing), so those WRQ policy modes decide against the real rootDir, not the injected table; (2) under `csMd5`, `writeSidecar` writes a real `.md5` to disk regardless of `sinkFactory`; (3) the dir-listing pseudo-file (`generateDirListing`) does its own `getFileSize` per entry and is not `BlockSource`-shaped — explicitly out of this RFC's blast radius. With those scoped out, a full client↔server RRQ/WRQ negotiation + transfer runs with no *data* disk touches, *through the facade* — closing v2 Part A1b and reaching the negotiation phase v1's R1-7 gap never did.

**Shared in-RAM table factory (r2 — what slice 5 actually uses).** The single-buffer `memoryBlockSource`/`memoryBlockSink` don't compose into the path-keyed table a two-session harness needs (client PUT writes path *p*; server GET reads path *p*). The factory closures must look the table up **at call time**, not capture a snapshot at construction — else the reader captures a stale/empty view taken before the writer's `finish()`. **Key = the *resolved* path (slice-5 impl note):** the `path` the server passes the factory is the post-`validatePath` *resolved absolute* path (the security invariant above), **not** the raw client filename — so a harness pre-populating or asserting on the table must key by the same resolved path (compute it via `security.validatePath(rootDir, filename)`, the authority the server itself uses), not by the bare filename:

```nim
proc tableSourceFactory*(t: TableRef[string, seq[byte]]): BlockSourceFactory =
  proc(path: string): Option[OpenedSource] =
    if not t.hasKey(path): none(OpenedSource)                 # per-call lookup, not captured
    else: some((memoryBlockSource(t[path]), some(t[path].len.int64)))
proc tableSinkFactory*(t: TableRef[string, seq[byte]]): BlockSinkFactory =
  proc(path: string): BlockSink =
    let buf = new(seq[byte])
    var s = memoryBlockSink(buf)
    let inner = s.finish
    s.finish = proc(success: bool): bool =                    # on success, commit into the table
      result = inner(success)
      if success: t[path] = buf[]
    s
```


**Sketch of a hypothetical embedder-supplied source** (illustrative only — wiring this into the
public `TransferRequest`/session API is explicitly *not* built by this RFC; see Out of scope):

```nim
# In an embedder's own module -- chapulin never sees the concrete type.
proc sensorRingBlockSource(ring: SensorRing): BlockSource =
  result.read = proc(n: int): seq[byte] = ring.pull(n)  # embedder's own forward accessor

# A future session-level hook (NOT part of this RFC) might look like:
let req = TransferRequest(direction: tdRrq, filename: "telemetry.bin",
                          source: some(sensorRingBlockSource(myRing)), ...)
```

The point of the sketch: nothing about `BlockSource` requires the embedder to know TFTP block
numbers, `File`, or netascii — just "give me the next `n` bytes, or tell me you're done."

### 6. Defects: structural avoidance for first-party sources; foreign-code containment deferred

**Decision (architect r1, Corey): this RFC does NOT catch `Defect`.** An earlier draft wrapped the
source/sink seams in `except CatchableError, Defect` to contain a misbehaving *caller-supplied*
implementation. That is the wrong design here, for three reasons:

1. **No trust boundary is in scope.** The public embedder hook — the only thing that admits foreign,
   un-auditable code — is deferred (§ Out of scope). Every source/sink this RFC constructs is
   first-party: `fileBlockSource`, `memoryBlockSource`, `netasciiSource`, and test doubles. The
   error-handling boundary should match the *real* trust boundary, and no wider.
2. **Catching `Defect` around first-party code sabotages the never-throw verification.** chapulin's
   discipline (`SECURITY.md`) is **structural avoidance** — Defects are made unreachable by
   construction and *proven absent* by the harness. A `Defect`-catch at this seam would swallow a
   genuine first-party bug into a clean transfer failure — the exact bug verification-harness-v2's
   stateful property + fuzz canary exist to surface as `"crashed:"`. Building bug-masking into `src/`
   while building the machine to detect those bugs is self-defeating.
3. **`except Defect` would be the wrong containment even for the eventual hook.** It rests entirely
   on `--panics:off` staying the global build default forever — an invisible coupling any future
   release-tuning could flip silently. Best-in-class foreign-code containment is *structural*: give
   the embedder an interface that **cannot** raise a Defect (a pull-closure whose only failure mode
   is a returned error/EOF), or isolate it — not a `try/except` gambling on a compiler flag. That is
   a real design, and it belongs in the embedder-hook RFC, co-located with the boundary it protects
   (and it must also handle the liveness case — a source that never EOFs and never raises — which a
   `Defect`-catch cannot).

**So, in this RFC:** first-party sources/sinks are Defect-free *by construction* (bounds-checked, no
unguarded nil/variant — the same bar as all of `src/`) and verified so under the harness. The only
thing this module *raises* is `BlockSourceOrderError` (a `CatchableError`) for genuine contract
violations — out-of-order reads and oversized reads (§7) — which flow into `sendBlocks`/`recvBlocks`'
existing `TransferError`/`writeError` path exactly as a real `IOError` does. There is no `toOnData`
Defect-wrap (dropped) and no second `BlockSourceFault` error type (the "Open forks" naming question
is thereby resolved: one error type). Foreign-code containment moves, whole, to the future
embedder-hook RFC.

### 7. Trade-offs

- **Dispatch overhead:** one extra proc-pointer indirection per `read`/`write` call versus today's
  fused closures (the netascii decorator is now a separate closure layer instead of inline code in
  `netasciiReader`). Negligible in absolute terms — this is bounded above by one UDP send/recv per
  block already, and the current code already returns closures at this exact seam, so the marginal
  cost of one more layer is a single indirect call, not a new class of overhead.
- **API surface growth:** one new module (`blocksource.nim`) and roughly seven new public symbols
  (`BlockSource`, `BlockSink`, `BlockSourceOrderError`, `fileBlockSource`, `fileBlockSink`,
  `memoryBlockSource`, `memoryBlockSink`, `toReadData`) versus zero today. Justified by turning an
  un-injectable dependency into an injectable one at exactly the seam two independent efforts
  (verification-harness-v2, a future embedder) both need — but it is real surface a reviewer should
  weigh, not a free abstraction.
- **Foot-guns, named rather than left implicit:**
  - A `read` returning **more** than `n` bytes is enforced as a **hard invariant** in `toReadData` —
    it *raises `BlockSourceOrderError`* (a `CatchableError`), not a silent `doAssert`. This is not a
    nicety: an oversized buffer flows straight into `sendBlocks`' `opData` packet and onto the wire
    as an over-length DATA packet (a protocol violation that also defeats the `blkData.len <
    blocksize` short-final-block detection). Enforced in Stage 1, not deferred.
  - A `write` that returns `true` without durably applying `data` is undetectable by construction —
    this abstraction cannot verify a backing store's honesty, exactly as `Transport.send` cannot
    verify a real socket delivered a packet. Same trust boundary as the rest of the I/O stack;
    inherited, not new.
  - Calling `read` after it returned empty, or `finish` twice, are documented-but-unenforced
    contract violations for now — the ascending-block guard in `toReadData` catches the ordering
    violation `sendBlocks` could realistically produce; the only in-repo callers go through
    `toReadData`, so the guard is complete for every call site that exists today.

## Stages / `/tdd`-sized slices

*(Order fixed in r2: field-adding slices (3,4) come BEFORE the call-site wiring (5), since the
wiring resolves `config.sourceFactory` / `session.sourceFactory` — fields that don't exist until
3/4. The r1 ordering had slice 3 wire a factory field that hadn't been added yet.)*

1. **`blocksource.nim` (new module).** `BlockSource`/`BlockSink` (incl. `close`), `OpenedSource`
   (`size: Option[int64]`), the 4 adapters (each assigning `close`), `toReadData` (ascending-once +
   oversized-read guards), `BlockSourceOrderError`. **No `Defect`-wrapper** (§6). No call site
   touched. Tests (`t_blocksource.nim`): EOF signaling (empty vs short-but-nonzero); ascending-once
   **and** oversized-read both raise `BlockSourceOrderError`; **`close` fires on every exit path and
   is non-nil for every adapter**; first-party sources never-throw over adversarial 0..255 inputs
   (ordinary never-throw verification — *not* a containment canary). *(Big-ish; may internally split
   1a = types + `toReadData` guards + error type, 1b = 4 adapters + `close` + fuzz — same slice
   number.)*
2. **`netascii.nim`: decorators + signature change.** Add `netasciiSource`/`netasciiSink` (**each
   forwarding `close` to `inner`**); change `makeSendReader`/`makeRecvSink` to take
   `BlockSource`/`BlockSink`. Keep `netasciiReader*` as a thin compat shim
   (`toReadData(netasciiSource(fileBlockSource(file)))`) — but **it is NOT fully green-preserving**:
   the shim now raises `BlockSourceOrderError` where the old code raised `NetasciiReaderError`, so
   **`t_netascii.nim:256`'s `except NetasciiReaderError` MUST migrate to `except BlockSourceOrderError`**
   (a required sub-task, not "unmodified"). `t_client.nim:657-684` never asserts on the error type —
   unaffected. *(Optional 2b: delete `netasciiReader`, migrate both callers.)*
3. **Client factory fields (`TftpSession`).** `sourceFactory`/`sinkFactory` + `newSession` params,
   nil-default file-backed, mirroring `transportFactory`/`listenerFactory`.
4. **Server factory fields (`ServerConfig`).** Same two fields on `ServerConfig` (not `TftpServer` —
   §5.1); `resolveSourceFactory(config)` helper. `==` over the nil-default closure fields **compiles**
   (Nim's generic `EqProc`, verified r2) — add a one-line doc caveat that `==` is referential-identity
   once a factory is non-nil.
5. **Wire the 4 call sites through the factory + `close` retention.** `handleRrq`/`handleWrq`,
   `setupGetTransfer`/`setupPutTransfer` construct via the nil-defaulting factory (existence+size via
   `Option[OpenedSource]`, raise-preserving for present-but-unopenable), **retaining the source/sink
   value and calling its `close`** (`defer` server-side; outer-var + cleanup for the lazy GET path).
   Drop the caller-owned `var netasciiEnc`. Default factory = zero behavior change; `t_server`/`t_api`/
   `t_client` green (except the §5.1 `errAccessViolation` path stays byte-identical via the retained
   `try/except IOError`). Preserve `setupGetTransfer` lazy-open + a no-file-on-pre-DATA-failure test.
6. **In-memory demonstration (A1b proof) — descoped off the unbuilt listener bridge (r2 High).** v2's
   `makeListenerFromWire` (A1a-ii) does NOT exist yet and `wireharness.nim` is point-to-point only, so
   this slice **drives `handleRrq`/`handleWrq` directly** against a real client `TftpSession` over two
   `Wire`-backed transports + a shared `TableRef[string, seq[byte]]` (the `tableSource/SinkFactory`
   above) — no listener/accept step. That still proves the BlockSource/BlockSink **hermeticity**,
   which is *this* RFC's job; the full facade-listener path is v2 A1b's own slice, gated on v2 A1a-ii.

**Deferred, not built here:** the *public per-request* embedder hook — a `TransferRequest.source`/
`.sink` field letting an external caller pass a `BlockSource`/`BlockSink` on the shipped public API
(sketched in §5, not wired) — reopening `api.nim`'s already-shipped RFC #17 surface is a separate,
larger decision Corey should make deliberately, not a side effect of this RFC. **Note the
distinction from §5.1's `sourceFactory`/`sinkFactory`, which *is* in scope:** those are the same
class of construction-time test seam as the existing `transportFactory`/`listenerFactory` (not a
new public data-flow contract), and they are what actually unblocks v2 Part A(b).

## Out of scope

- Genuinely async/backpressured sources (§3) — needs `transfer.nim` itself to `await`
  `readData`/`onData`, a disclosed follow-on RFC.
- Wiring a `BlockSource`/`BlockSink` hook into the public embedding API (§5/"Deferred" above).
- New transforms beyond netascii (compression, checksumming taps, encryption) — the decorator
  shape supports them; none are built here.
- `--panics:on` migration or auditing every existing Defect-avoidance site — out of blast radius.
- **Foreign-code Defect containment** (the earlier draft's §6 `except Defect` wrapper) — deferred
  *whole* to the embedder-hook RFC, where an actual trust boundary exists and can be handled
  structurally (a Defect-proof foreign interface / isolation), not with a flag-dependent `try/except`.
  This RFC catches no Defects (§6).

## Open forks (awaiting Corey)

- **None.** (The earlier `BlockSourceOrderError`-vs-`BlockSourceFault` naming fork is resolved by
  §6's decision: no `Defect`-catch → no foreign-fault type → one error type, `BlockSourceOrderError`.)
