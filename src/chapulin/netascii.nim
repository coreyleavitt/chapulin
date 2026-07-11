## Netascii CR/LF conversion per RFC 1350.
##
## Stateful, byte-at-a-time transformers (D1a of the RFC-conformance-closure
## mini-RFC). The previous buffer-local `toNetascii`/`fromNetascii` inspected
## `data[i±1]` within a single call, so a `CR LF` / `CR NUL` pair straddling a
## block-sized read/write boundary was mistranslated. `NetasciiEncoder` and
## `NetasciiDecoder` instead carry one bit of state (`pendingCr`) across calls,
## so translation is correct regardless of how the caller chunks its input.
##
## Wire format (encoder's output / decoder's input): a line ending is
## `CR LF`; a literal `CR` in the data is escaped as `CR NUL`. Canonical local
## newline is `LF` (R1) — the decoder always emits `LF` for a wire `CR LF`,
## and the encoder always emits `CR LF` for a local `LF`.
##
## **The defer-CR-across-calls contract:** `feed` never resolves a `CR` via
## in-call lookahead, even when a later byte in the *same* call would answer
## the question. It is a strict left-to-right one-state machine: seeing `CR`
## always just sets `pendingCr` and moves on; the *next* byte fed — whether
## later in this call or in a future call — resolves it. This makes "does
## this CR call for `LF`-merge or `NUL`-escape" chunk-boundary-agnostic by
## construction, rather than by a special-cased end-of-buffer check. `flush`
## resolves a trailing `pendingCr` (a lone CR at true end-of-stream) to its
## lone-CR encoding/decoding.
##
## **R2 (documented lossy edge case, decoder):** RFC 1350 guarantees a
## conformant sender only ever follows wire `CR` with `LF` or `NUL`. If a
## non-conformant stream (or locally-authored text fed straight through the
## encoder without netascii's own escaping — see the round-trip scope below)
## produces a `CR` followed by neither, we treat that `CR` as a literal byte
## and reprocess the following byte fresh (RFC-1350-faithful: a `CR` is only
## ever *introduced* by the encoder paired with `LF` or `NUL`, so an
## unpaired one is passed through rather than dropped or erroring). The same
## rule applies at `flush`: a lone trailing `CR` decodes as a literal `CR`.
##
## Round-trip identity (`encode` then `decode`) holds for any local text
## where a raw `CR` never immediately precedes `CR` or `LF` — see
## `tests/t_netascii.nim`. Where it does, the round-trip is *intentionally
## lossy*: `[CR,LF]` -> encode -> `[CR,LF]` -> decode -> `[LF]` (the bare `CR`
## is not recoverable — it reads back as an ordinary local line ending), and
## `[CR,CR,LF]` -> encode -> `[CR,NUL,CR,LF]` -> decode -> `[CR,LF]` (loses a
## byte). Both are asserted as explicit documented behavior, not round-tripped.

import protocol
import coverpragma
import blocksource

const
  Cr = byte('\r')
  Lf = byte('\n')
  Nul = byte(0)

type
  NetasciiEncoder* = object   ## local -> wire
    pendingCr*: bool          ## last byte fed was a lone CR; classification deferred
  NetasciiDecoder* = object   ## wire -> local
    pendingCr*: bool          ## last byte fed was an unresolved wire CR; deferred

proc feed*(e: var NetasciiEncoder, input: openArray[byte]): seq[byte] {.cover.} =
  ## Encode local bytes to wire bytes. `LF` -> `CR LF`; a lone `CR` (not
  ## immediately followed by `LF`) -> `CR NUL`. Never resolves a `CR` that is
  ## the last byte of `input` by peeking past the end of this call — it sets
  ## `e.pendingCr` and lets the next `feed`/`flush` resolve it.
  for b in input:
    if e.pendingCr:
      e.pendingCr = false
      if b == Lf:
        # Deferred CR immediately followed by LF: the pair is the wire's own
        # line-ending shape already -- emit it as-is, and this LF is consumed
        # as part of the pair (not reprocessed below).
        result.add Cr
        result.add Lf
        continue
      else:
        # Deferred CR was lone -- escape it, then fall through to classify
        # `b` fresh (it was never consumed by the CR).
        result.add Cr
        result.add Nul
    case b
    of Lf:
      result.add Cr
      result.add Lf
    of Cr:
      e.pendingCr = true
    else:
      result.add b

proc flush*(e: var NetasciiEncoder): seq[byte] {.cover.} =
  ## Resolve a trailing lone CR (true end-of-stream) to its lone-CR encoding.
  if e.pendingCr:
    result.add Cr
    result.add Nul
    e.pendingCr = false

proc feed*(d: var NetasciiDecoder, input: openArray[byte]): seq[byte] {.cover.} =
  ## Decode wire bytes to local bytes. `CR LF` -> `LF`; `CR NUL` -> `CR`. A
  ## wire `CR` followed by neither (non-conformant input) decodes as a
  ## literal `CR`, and the byte after it is reprocessed fresh (see module
  ## doc, R2). Never resolves a `CR` that is the last byte of `input` via
  ## in-call lookahead -- defers to the next `feed`/`flush`.
  for b in input:
    if d.pendingCr:
      d.pendingCr = false
      case b
      of Lf:
        result.add Lf
        continue
      of Nul:
        result.add Cr
        continue
      else:
        # Non-conformant: the deferred CR was not part of CR-LF or CR-NUL.
        # Pass it through literally, then classify `b` fresh below.
        result.add Cr
    case b
    of Cr:
      d.pendingCr = true
    else:
      result.add b

proc flush*(d: var NetasciiDecoder): seq[byte] {.cover.} =
  ## Resolve a trailing lone wire CR (true end-of-stream) to a literal CR.
  if d.pendingCr:
    result.add Cr
    d.pendingCr = false

proc netasciiBlockSource*(inner: BlockSource): BlockSource =
  ## Local -> wire. Same state machine as the old `netasciiReader` (carry
  ## buffer + `NetasciiEncoder`), now pulling from ANY forward `BlockSource`
  ## instead of a `File` directly (RFC in-memory-sources-sinks.md §4).
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
  result.close = inner.close   # a decorator MUST forward close, or the
                               # wrapped handle leaks / a nil close crashes.

proc netasciiBlockSink*(inner: BlockSink): BlockSink =
  ## Wire -> local. Same `NetasciiDecoder` state machine, writing through
  ## ANY inner `BlockSink`.
  var dec: NetasciiDecoder
  result.write = proc(data: seq[byte]): bool =
    let decoded = dec.feed(data)
    decoded.len == 0 or inner.write(decoded)
  result.finish = proc(success: bool): bool =
    if not success: return inner.finish(false)
    let tail = dec.flush()
    let tailOk = tail.len == 0 or inner.write(tail)
    inner.finish(true) and tailOk
  result.close = inner.close   # forward close through the decorator.

proc netasciiReader*(file: File, enc: sink NetasciiEncoder): proc(blockNum: uint16, blocksize: int): seq[byte] =
  ## Thin compat shim (RFC in-memory-sources-sinks.md, slice 2) over the
  ## general `netasciiBlockSource`/`toReadData` seam. `enc` is accepted for
  ## historical call-site shape only -- every caller passes a freshly
  ## default-initialized encoder that is never read again, and
  ## `netasciiBlockSource` now owns its own encoder state internally, so
  ## `enc` itself is unused here. Retained as a directly-tested compat shim
  ## (see `tests/t_netascii.nim`) -- there is no current `src/` production
  ## caller; `makeSendReader`/`makeRecvHandler` (below) are the production
  ## seam.
  ##
  ## The returned closure now raises `BlockSourceOrderError` (blocksource.nim)
  ## where this used to raise `NetasciiReaderError` on an out-of-order call --
  ## the ascending-once guard moved to `toReadData`, which applies it
  ## uniformly to every `BlockSource`, not just netascii.
  toReadData(netasciiBlockSource(fileBlockSource(file)))

proc makeSendReader*(source: BlockSource, mode: TransferMode): proc(blockNum: uint16, blocksize: int): seq[byte] =
  ## Send-side seam (D1b/d unification): owns the choice between wrapping
  ## `source` in the netascii decorator (`netasciiBlockSource`, above) and
  ## using it plain under octet, so callers (`server.handleRrq`, `api.nim`'s
  ## `tdPut` closure) each call ONE function instead of branching on mode
  ## themselves. Returns a closure of the exact same type `sendBlocks`
  ## (transfer.nim) already expects as `readData` -- no change needed there.
  ##
  ## Callers no longer own a `var netasciiEnc: NetasciiEncoder` -- the
  ## decorator owns its own state entirely (RFC in-memory-sources-sinks.md §4).
  toReadData(if mode == tmNetascii: netasciiBlockSource(source) else: source)

proc makeRecvHandler*(sink: BlockSink, mode: TransferMode): proc(data: seq[byte], isFinal: bool): bool =
  ## Recv-side seam (D1c unification) -- the receive-side mirror of
  ## `makeSendReader`: owns decode-feed + per-block write + terminal
  ## finalize for BOTH octet and netascii RECEIVE paths, wrapping `sink` in
  ## the netascii decorator (`netasciiBlockSink`, above) under netascii,
  ## plain otherwise (RFC in-memory-sources-sinks.md §4).
  ##
  ## Renamed from `makeRecvSink` (code-review S4-6): it takes a `BlockSink`
  ## but RETURNS an `onData`-shaped closure (`proc(data, isFinal): bool`),
  ## NOT a `BlockSink` -- the old name mispromised the return type.
  let s = if mode == tmNetascii: netasciiBlockSink(sink) else: sink
  result = proc(data: seq[byte], isFinal: bool): bool =
    result = s.write(data)
    if isFinal:
      if not s.finish(result): result = false

proc toNetascii*(data: seq[byte]): seq[byte] =
  ## One-shot local -> wire convenience wrapper over `NetasciiEncoder`, for
  ## callers that hold the whole buffer at once (e.g. the directory-listing
  ## pseudo-file, D1d). Streaming callers (block-chunked transfers) should
  ## use `feed`/`flush` directly so state carries across blocks.
  var enc: NetasciiEncoder
  result = enc.feed(data) & enc.flush()

proc fromNetascii*(data: seq[byte]): seq[byte] =
  ## One-shot wire -> local convenience wrapper over `NetasciiDecoder`. See
  ## `toNetascii` for the streaming caveat.
  var dec: NetasciiDecoder
  result = dec.feed(data) & dec.flush()

# --- D1d: the netascii-mode policy seam --------------------------------------
##
## All mode-conditional behavior in the send path (server.nim, engine.nim,
## api.nim) routes through this ONE value rather than scattering
## `mode == tmNetascii` checks across those modules. Every field below is
## `mode == tmNetascii` today (that IS the policy, for now), but naming each
## call site's *decision* separately means a future mode with different
## needs (or a future reviewer auditing "is every site accounted for") has
## exactly one place to look, and no site can silently diverge from another.
##
## Surviving policy sites (each genuinely needs the decision at its own call
## site -- no reader/sink/negotiator constructor can own it):
##   (a) skipSidecar          -- server.nim: don't hash/write the .md5 sidecar (R3)
##   (b) suppressTsize        -- server.nim's outbound OACK (passed into
##                                `negotiateServerOptions` as a plain bool,
##                                keeping that module mode-agnostic) AND
##                                engine.nim's outbound request: never
##                                offer/request tsize (applies to BOTH
##                                directions -- engine's `clientBuildOptions`
##                                is shared by getFile and putFile, so this
##                                one site already covers client GET too)
##   (c) reportTotalUnknown   -- api.nim's client PUT: `.bytes` counts
##                                post-translation wire bytes while `fileSize`
##                                is pre-translation, so the reported `total`
##                                must be `none`, not the raw file size
##
## What used to be separate fields here -- routing the send-side file read
## through `netasciiReader` vs. the seek-addressed octet closure, and routing
## the recv-side file write through a `NetasciiDecoder` vs. writing wire
## bytes as-is -- is now decided INSIDE `makeSendReader`/`makeRecvHandler`
## themselves (both above), which take `mode` directly rather than exposing
## it as a policy bit callers had to re-read and branch on. Removing them
## from this object is the point of that refactor: no field survives here
## that is merely `mode == tmNetascii` re-read at a site that should have let
## a deep constructor own the decision.
##
## (The directory-listing pseudo-file is handled directly via `toNetascii`'s
## one-shot wrapper at its call site -- it is not a boolean gate on an
## existing closure the way the others are.)
type
  NetasciiPolicy* = object
    skipSidecar*: bool
    suppressTsize*: bool
    reportTotalUnknown*: bool

proc netasciiPolicyFor*(mode: TransferMode): NetasciiPolicy =
  let nx = mode == tmNetascii
  NetasciiPolicy(skipSidecar: nx, suppressTsize: nx, reportTotalUnknown: nx)
