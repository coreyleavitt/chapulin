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

const
  Cr = byte('\r')
  Lf = byte('\n')
  Nul = byte(0)

type
  NetasciiEncoder* = object   ## local -> wire
    pendingCr*: bool          ## last byte fed was a lone CR; classification deferred
  NetasciiDecoder* = object   ## wire -> local
    pendingCr*: bool          ## last byte fed was an unresolved wire CR; deferred

  NetasciiReaderError* = object of CatchableError
    ## Raised by netasciiReader's returned closure when invoked out of its
    ## documented contract (blockNum not exactly lastReaderBlock+1). This
    ## used to be a `doAssert` (an uncatchable `AssertionDefect`, the tracked
    ## never-throw hazard) -- a plain `CatchableError` subtype instead, so a
    ## future retry-logic regression that re-invokes the reader out of order
    ## degrades to a clean transfer failure (sendBlocks' Future fails, and
    ## every caller already treats a failed Future as an ordinary transfer
    ## error -- see api.nim's `fut.addCallback`/`fut.failed` and server.nim's
    ## `run`'s `hf.addCallback`/`hf.failed`) instead of crashing the process.

proc feed*(e: var NetasciiEncoder, input: openArray[byte]): seq[byte] =
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

proc flush*(e: var NetasciiEncoder): seq[byte] =
  ## Resolve a trailing lone CR (true end-of-stream) to its lone-CR encoding.
  if e.pendingCr:
    result.add Cr
    result.add Nul
    e.pendingCr = false

proc feed*(d: var NetasciiDecoder, input: openArray[byte]): seq[byte] =
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

proc flush*(d: var NetasciiDecoder): seq[byte] =
  ## Resolve a trailing lone wire CR (true end-of-stream) to a literal CR.
  if d.pendingCr:
    result.add Cr
    d.pendingCr = false

proc netasciiReader*(file: File, enc: sink NetasciiEncoder): proc(blockNum: uint16, blocksize: int): seq[byte] =
  ## Block-chunking read adapter (D1b) for the netascii SEND side. Translation
  ## is expansive and data-dependent, so the seek-addressed `(blockNum-1)*blocksize`
  ## closure octet mode uses (server.nim's original RRQ readData) is invalid here
  ## -- the wire offset of a given local byte depends on how many LFs/CRs
  ## preceded it. This closure instead reads the *local* file strictly forward,
  ## feeds each chunk through `enc`, and buffers translated (wire) bytes in a
  ## `carry` seq until it can hand back a full `blocksize` chunk.
  ##
  ## Returned closure has the SAME type as sendBlocks' existing seek-addressed
  ## `readData` (transfer.nim's `proc(blockNum: uint16, blocksize: int): seq[byte]`)
  ## -- sendBlocks needs no type change. `blockNum` is used ONLY to assert
  ## strictly-ascending, exactly-once-per-block calls (sendBlocks' load-bearing
  ## invariant: retransmits replay its own `windowCache`, never re-invoke
  ## `readData`) -- never for seeking, since seeking the encoded stream isn't
  ## meaningful (the encoder carries state across calls).
  ##
  ## Read-ahead / EOF contract (round-2 false-EOF bug): a short return means
  ## EOF *only* when the underlying `file` read itself returned 0 bytes. A
  ## block landing short purely because a straddled CR deferred one byte into
  ## `enc`'s internal state is NOT eof -- the loop below keeps pulling raw
  ## bytes and feeding them until either the carry buffer holds >= blocksize,
  ## or the file truly runs dry (at which point `enc.flush()` resolves any
  ## trailing deferred CR and whatever remains, however short, is the final
  ## return).
  ##
  ## `carry` (not-yet-emitted translated overflow) is distinct from
  ## sendBlocks' `windowCache` (already-emitted bytes kept only for retransmit
  ## replay) -- the two must never be conflated.
  ##
  ## `enc` is `sink` (not `var`): Nim refuses to let a closure capture a
  ## `var` parameter at all (it is a hidden pointer into the caller's stack
  ## frame, which the closure would outlive -- a memory-safety violation the
  ## compiler rejects outright), so the pre-`sink` version copied `enc` into
  ## a local (`var encState = enc`) purely to have something capturable.
  ## `sink` expresses the real contract directly: ownership of the encoder's
  ## state fully transfers to the returned closure from this point on; the
  ## caller's `enc` argument is a one-shot seed (typically freshly
  ## default-initialized) and is never read again after this call. The local
  ## copy below is still needed (a closure can't capture a parameter, sink or
  ## not -- only a local), but `sink` lets the compiler move rather than copy
  ## at the call site when the caller's argument is itself a fresh value.
  var encState = enc
  var carry: seq[byte] = @[]
  var trueEof = false
  var lastReaderBlock: uint16 = 0
  result = proc(blockNum: uint16, blocksize: int): seq[byte] =
    if blockNum != lastReaderBlock + 1:
      raise newException(NetasciiReaderError,
        "netasciiReader: readData must be invoked exactly once per block, " &
        "strictly ascending -- retransmits must replay sendBlocks' windowCache, " &
        "never re-invoke the reader (would silently corrupt a netascii transfer)")
    lastReaderBlock = blockNum

    if not trueEof:
      while carry.len < blocksize:
        var raw = newSeq[byte](blocksize)
        let bytesRead = file.readBytes(raw, 0, blocksize)
        if bytesRead == 0:
          trueEof = true
          carry.add encState.flush()
          break
        raw.setLen(bytesRead)
        carry.add encState.feed(raw)

    let n = min(blocksize, carry.len)
    result = carry[0 ..< n]
    carry = if n < carry.len: carry[n ..< carry.len] else: @[]

proc makeSendReader*(file: File, mode: TransferMode, enc: var NetasciiEncoder): proc(blockNum: uint16, blocksize: int): seq[byte] =
  ## Send-side seam (D1b/d unification, RFC code-review handoff): owns the
  ## choice between the block-chunking netascii reader (`netasciiReader`,
  ## above) and the seek-addressed octet closure, so callers
  ## (`server.handleRrq`, `api.nim`'s `tdPut` closure) each call ONE
  ## function instead of branching on a `useBlockChunkedReader` policy bit
  ## and hand-rolling the octet fallback closure themselves at every call
  ## site. Returns a closure of the exact same type `sendBlocks`
  ## (transfer.nim) already expects as `readData` -- no change needed there,
  ## and no change to sendBlocks' load-bearing "readData called at most once
  ## per block, strictly ascending" contract (the octet closure below is
  ## seek-addressed and idempotent regardless of call count/order; the
  ## netascii branch's own invariant is documented on `netasciiReader`).
  ##
  ## `enc` is forwarded straight through to `netasciiReader` under netascii
  ## (see its doc for the by-value capture discipline -- ownership of the
  ## encoder's state transfers to the returned closure); under octet it is
  ## simply unused. Callers pass a freshly default-initialized `var`
  ## unconditionally either way, so the call site itself needs no mode
  ## branch.
  if mode == tmNetascii:
    netasciiReader(file, enc)
  else:
    proc(blockNum: uint16, blocksize: int): seq[byte] =
      if blockNum == 0: return @[]
      let offset = int64(blockNum - 1) * int64(blocksize)
      file.setFilePos(offset)
      var buf = newSeq[byte](blocksize)
      let bytesRead = file.readBytes(buf, 0, blocksize)
      buf.setLen(bytesRead)
      return buf

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

proc writeNetasciiTail*(tail: seq[byte], writeBytes: proc(data: seq[byte]): int): bool =
  ## Terminal-tail write seam (Fix A, RFC code-review handoff): performs the
  ## actual disk write of `tail` (the netascii decoder's resolved trailing
  ## byte, if any -- `dec.flush()`'s result) through the injected
  ## `writeBytes` closure, and reports whether every tail byte was written.
  ## `writeBytes` mirrors `File.writeBytes`'s contract (returns the actual
  ## byte count written, which can be short on `ENOSPC`/similar) so tests can
  ## inject a short-writing fake without faking an entire `File`.
  ##
  ## An empty tail is trivially ok and never invokes `writeBytes` at all --
  ## most blocks have no deferred CR to resolve, and this must not be
  ## mistaken for (or require) a zero-byte write attempt.
  if tail.len == 0:
    return true
  writeBytes(tail) == tail.len

proc finishNetasciiDecode*(file: File, dec: var NetasciiDecoder, success: bool): bool {.discardable.} =
  ## Terminal decode flush (D1c), shared by BOTH netascii RECEIVE-side write
  ## paths: `server.handleWrq` (server WRQ) and `api.nim`'s `tdGet` closure
  ## (client GET, which owns its file handle directly rather than through
  ## `engine.nim`). Each caller detects "this is the final block" the same
  ## way the transfer layer does (`data.len < blocksize`) and calls this at
  ## that point -- writing any trailing byte `dec.flush()` resolves (a
  ## deferred lone wire `CR` at true end-of-stream) and durably flushing the
  ## file to disk.
  ##
  ## `success` gates the write: called unconditionally with whatever success
  ## state the caller has just determined, rather than each call site
  ## wrapping the call itself in an `if`, so both callers share one shape. A
  ## failed or aborted transfer must NOT flush a partial decode as if the
  ## stream had ended cleanly -- the decoder's dangling `pendingCr` (if any)
  ## does not describe the true tail of the file in that case, and writing
  ## it would silently fabricate a byte that was never confirmed delivered.
  ##
  ## Returns `true` iff the terminal tail write (if any) fully succeeded, or
  ## there was nothing to attempt (`success == false`, or an empty tail).
  ## Returns `false` iff a non-empty tail was short-written -- the ONE write
  ## site in this module that used to `discard` this outcome (RFC code-
  ## review finding, Fix A): a short/`ENOSPC` write on this final ≤1-byte
  ## flush used to be invisible, reporting a truncated file as a successful
  ## transfer. Callers MUST fold a `false` return into the same write-
  ## failure/`writeError` path they already use for per-block write
  ## mismatches -- `{.discardable.}` exists only so the pre-existing direct
  ## unit tests of this proc (which assert on file contents, not the return
  ## value) don't need a `discard` at every call, NOT as license for a
  ## production call site to ignore it.
  if not success:
    return true
  let tail = dec.flush()
  result = writeNetasciiTail(tail, proc(data: seq[byte]): int = file.writeBytes(data, 0, data.len))
  flushFile(file)

proc makeRecvSink*(file: File, mode: TransferMode): proc(data: seq[byte], isFinal: bool): bool =
  ## Recv-side seam (D1c unification) -- the receive-side mirror of
  ## `makeSendReader`: owns decode-feed + per-block write + terminal
  ## finalize + write-failure detection for BOTH octet and netascii RECEIVE
  ## paths, so callers (`server.handleWrq`, `api.nim`'s `tdGet` closure)
  ## collapse their `onData` bodies to the same shape regardless of mode --
  ## no in-body `if netascii` branch, no hand-rolled final-block
  ## `finishNetasciiDecode` call at either site.
  ##
  ## The returned closure writes `data` to `file` -- decoded through a
  ## `NetasciiDecoder` owned by this closure under netascii, verbatim under
  ## octet -- and, when `isFinal` is true (the caller's existing
  ## `data.len < blocksize` final-block signal, unchanged), also performs
  ## the terminal step: netascii's `finishNetasciiDecode` (the deferred-CR
  ## tail write + durable flush) or octet's plain `flushFile`. Octet's
  ## terminal flush is skipped if THIS call's own per-block write already
  ## failed -- mirrors the pre-existing
  ## `elif writeError.len == 0: flushFile(file)` shape exactly.
  ##
  ## Returns `true` iff this call's write(s) fully succeeded; `false` iff
  ## the per-block write, or (at the final block) the terminal tail write,
  ## was short/failed. This closure has no memory of a PRIOR call's
  ## failure -- the caller is still responsible for short-circuiting future
  ## calls once it observes a `false`, exactly like the pre-refactor
  ## per-call-site `if writeError.len > 0: return` guard, which stays at
  ## the call site (it is caller-side state, not this closure's job to own).
  var dec: NetasciiDecoder
  result = proc(data: seq[byte], isFinal: bool): bool =
    result = true
    let toWrite = if mode == tmNetascii: dec.feed(data) else: data
    if toWrite.len > 0:
      let written = file.writeBytes(toWrite, 0, toWrite.len)
      if written != toWrite.len:
        result = false
    if isFinal:
      if mode == tmNetascii:
        if not finishNetasciiDecode(file, dec, result):
          result = false
      elif result:
        flushFile(file)

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
## bytes as-is -- is now decided INSIDE `makeSendReader`/`makeRecvSink`
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
