# RFC: TFTP RFC-conformance closure

- **Status:** Draft — **architect rounds 1 & 2 applied; Q1 → Option A. No open forks. Ready for `/tdd`.**
- **Tracking issue:** none — spun out of a conformance audit of `src/chapulin/` against
  RFC 1350 / 2347 / 2348 / 2349 / 7440 (20 MUST/SHOULD clauses checked, 14 conform).
  Folds the pre-existing netascii TODO ([#13](https://github.com/coreyleavitt/chapulin/issues/13)) in.
- **Scope:** `src/chapulin/protocol.nim`, `options.nim`, `transfer.nim`, `engine.nim`, `api.nim`,
  `netascii.nim`, `server.nim`, `server_config.nim`. The only public-API change is the **additive**
  `TransferInfo.errorCode: int` field (Q1 → Option A; `onTransferError`'s signature is unchanged). Changes are
  otherwise on-the-wire behavior, one new error code, and three pre-existing latent bugs the review surfaced
  (negotiated-`timeout` never applied; duplicate re-ACK echoes the wrong block; `effectiveTimeout` discards the
  negotiated value).

## Why now

chapulin already leads the field on hardening, integrity, and reliability engineering, and is at parity on
the modern option set (blksize/timeout/tsize/windowsize). The remaining distance to *strict* RFC conformance
is six clauses — small, self-contained, each independently testable. None breaks a happy-path octet transfer
(which is why they've survived), but two are latent **data-corruption / reliability holes** we currently
advertise as working, and the rest are cheap conformance/robustness cleanups. One mini-RFC keeps the reasoning
and regression tests in one place and rides the architect → tdd → review flow.

## Problem — the six confirmed gaps

Each cites the audit clause, the RFC, and the source anchor. Severity is *real-world impact*, not RFC letter.

1. **netascii translation is orphaned — silent data corruption** *(RFC 1350; clause 2; VIOLATES).*
   `--mode=netascii` is negotiated on the wire, but `netascii.toNetascii`/`fromNetascii`
   (`netascii.nim:5,23`) have **zero production callers**; the existing procs are also **non-stateful**
   (inspect `data[i±1]` within one buffer), so a `CR LF`/`CR NUL` pair straddling a block cut is mistranslated.
   A corruption path advertised as supported. Closes #13.
2. **No dallying after the final ACK — final-ACK-loss hole** *(RFC 1350; clause 4; VIOLATES).*
   `recvBlocks` (`transfer.nim:372-375`) and the single-block client GET (`engine.nim:99-118`) return
   immediately after the final ACK; a lost final ACK strands the sender. Fires on every tail-loss transfer.
3. **Error code 8 (option-negotiation) is unrepresentable** *(RFC 2347; clause 8; VIOLATES).*
   `TftpErrorCode` stops at `errNoSuchUser = 7` (`protocol.nim:17-25`); decode folds `> 7` to `errNotDefined`
   (`:173`). Option failures reuse `errIllegalOperation` (4) at `server.nim:234`, `:353`.
4. **Client does not validate the OACK — trusts a rogue server** *(RFC 2347; clause 9; VIOLATES).*
   `applyOack`→`parseOackOptions` (`engine.nim:36-40`, `options.nim:43-51`) applies whatever the OACK contains.
5. **`timeout` not range-checked to 1..255 — and never applied even when valid** *(RFC 2349; clause 14;
   VIOLATES).* `parseInt` with no bound on both sides; `timeout=0` yields a zero-second timer. **And** the
   negotiated `timeout` is never wired into the transfer config (`handleRrq`/`handleWrq`/`applyOack` set
   blocksize/windowsize/totalSize but never timeout — the #16 windowsize-bug class, missed for timeout).
6. **RFC 7440 receiver gap-ACK missing** *(RFC 7440; clause 17; INCOMPLETE).* `recvBlocks` has no
   `pkt.blockNum > expectedBlock` branch (`transfer.nim:361-393`); a forward gap is dropped with no ACK, so
   the sender waits a full RTO. The duplicate re-ACK (`:390-392`) also echoes the *received* block, not the
   last in-order one.

## Q1 — resolved → Option A

Server-side ERROR(8) is made observable through the embedding API. `TransferInfo` (`server.nim:17-28`) gains an
**additive** `errorCode: int` field; `ServerCallbacks.onTransferError` keeps its `proc(info, msg)` signature
(the code rides on the existing `info` param). The server populates `info.errorCode` on failure, and `api.nim`'s
server-side callback stops hardcoding `0`. The client side already carries `errorCode` to `evTransferError`
(`api.nim:348`). This lands with **slice 1** (D3), where server-side code 8 is first emitted.

## Resolutions (decisions taken across rounds 1–2; recommended, veto-able)

- **R1. netascii canonical local newline = `LF`** (platform-independent; deterministic; matches
  tftpd-hpa/atftp). Encoder is already robust to mixed input; only the decoder output-newline is a convention.
- **R2. netascii round-trip is intentionally lossy at CR-ambiguity** (`[CR,LF]`→`[LF]`; `[CR,CR,LF]` loses a
  byte). Slice 6's property test is scoped to text where a raw `CR` never precedes a `CR`/`LF`-adjacent byte;
  the collapse cases are asserted as explicit documented behavior.
- **R3. Under `mode == tmNetascii` the server skips the `.md5` sidecar** (as it drops `tsize`) — hashing
  post-translation wire bytes would make the sidecar mode-dependent and clobber a prior octet sidecar; hashing
  pre-translation bytes would break the checksum RFC's "delivered bytes" invariant. Skipping avoids both.
- **R4. Client OACK policy = ignore-unrequested, reject-bad-value.** An unrequested option is **filtered out
  and never applied** (see D4 — this is *enforced*, not merely validated); `ERROR(8)` + clean fail is reserved
  for an out-of-range/malformed *value* of a *requested* option.
- **R5. Dally is bounded by a wall-clock deadline of one `peer.effectiveTimeout` AND `MaxDallyReacks = 2`
  re-ACKs**, decoupled from `config.retries`. The deadline (not just the re-ACK count) caps total linger so a
  trickle of off-target packets can't extend the epilogue.
- **R6. Server option-failure policy (the negotiation-side mirror of R4):** *clamp-and-OACK* for out-of-range
  `blksize`/`windowsize` (RFC 2348 permits substitution); *drop-and-ignore* for out-of-range `timeout` (RFC
  2349 does not permit silent substitution, so we omit rather than clamp); *ERROR(8)* only for a syntactically
  **unparseable** value. The server never emits ERROR(8) merely for an unacceptable-but-parseable option — it
  ignores it, mirroring R4's client stance.

## Design

### D1 — netascii: stateful transformers + a block-chunking read adapter + one policy seam (gap 1)

**(a) Byte-level stateful transformers** in `netascii.nim`:

```nim
type
  NetasciiEncoder* = object   ## local → wire
    pendingCr: bool           ## last input byte was a lone CR; classification deferred to next feed/flush
  NetasciiDecoder* = object   ## wire → local
    pendingCr: bool
proc feed*(e: var NetasciiEncoder, input: openArray[byte]): seq[byte]
proc flush*(e: var NetasciiEncoder): seq[byte]
proc feed*(d: var NetasciiDecoder, input: openArray[byte]): seq[byte]
proc flush*(d: var NetasciiDecoder): seq[byte]
```

**Contract (tested):** `feed` NEVER resolves a CR that is the last byte of the current call via in-call
lookahead — it sets `pendingCr` and defers to the next `feed`/`flush`, regardless of chunk size. Canonical
local newline = `LF` (R1).

**(b) Block-chunking read adapter.** Translation is expansive and data-dependent, so the current
seek-addressed `readData` (`server.nim:258-265`, `(blockNum-1)*blocksize`) is invalid for netascii. Provide,
built once:

```nim
proc netasciiReader*(file: File, enc: var NetasciiEncoder): proc(blockNum: uint16, blocksize: int): seq[byte]
```

**Signature note (was a round-2 bug):** the closure takes `(blockNum, blocksize)` — the **same type as
`sendBlocks`'s existing `readData`** (`transfer.nim:168`), so **`sendBlocks` needs no type change**. `blockNum`
is used *only* for a continuity `doAssert blockNum == lastReaderBlock+1` (never for seeking); octet mode keeps
its self-correcting seek-addressed closure unchanged (a future invariant violation crashes rather than
silently corrupts — the stronger guarantee is worth keeping for octet).

**Read-ahead / EOF contract (was a round-2 false-EOF bug):** a short return means EOF **only** when the
underlying `file` read returned 0 bytes. The adapter loops: pull raw bytes → `enc.feed` into a carry buffer
until either (a) the carry buffer holds ≥ `blocksize` (return the first `blocksize`, retain the remainder) or
(b) the file read returns 0 (true EOF → `enc.flush`, append, return whatever remains, however short — this is
the only short-return that signals end). A block that lands short purely because a straddled CR deferred one
byte is **not** EOF. The carry buffer (not-yet-emitted overflow) is distinct from `sendBlocks`'s `windowCache`
(already-emitted, retransmit-replay); they must not be conflated.

**Load-bearing invariant:** `sendBlocks` calls `readData` exactly once per block, strictly ascending
(retransmits replay `windowCache`, never re-invoke `readData`). The `doAssert` above enforces it so a future
retry-logic change can't silently corrupt netascii transfers; a retransmission-under-netascii test covers it.

**(c) Decode/write side.** Wrap `recvBlocks`'s `onData(blockNum, data)` (naturally sequential) with a decoder;
the write closure recomputes `data.len < blocksize` to know when a block is final. A shared
`finishNetasciiDecode(file: File, dec: var NetasciiDecoder, success: bool)` helper performs the terminal
`flush` write and is called by **both** decode callers — `handleWrq` and `api.nim`'s `tdGet` closure
(`api.nim:266-284`, which owns its file handle directly, not via `engine.nim`) — **only on success**.

**(d) The netascii-mode policy seam.** All mode-conditional behavior routes through one enumerated policy
(a `netasciiPolicyFor(mode)` value or an explicit "these are the only sites" list in code) so no site is
missed or duplicated. The sites are exactly: (1) skip `.md5` sidecar — guard the digester construction at
`server.nim:285`; (2) drop `tsize` — thread `mode: TransferMode = tmOctet` into `negotiateServerOptions`
(currently no `mode` param) at both `handleRrq`/`handleWrq`; (3) route reads through `netasciiReader` (server
RRQ, client PUT) and writes through the decoder (server WRQ, client GET); (4) encode the directory-listing
pseudo-file — since it's an already-materialized in-memory `seq[byte]`, do a one-shot `feed`+`flush` over the
whole buffer up front, then keep plain seek-addressing over the translated bytes (do **not** force the small
pseudo-file through `netasciiReader`).

**Client-side specifics.** Outbound `tsize` suppression under netascii lives in `engine.clientBuildOptions`
(`engine.nim:31-34`, which has `config.mode`), **not** `buildClientOptions`/`TransferConfig` (which have no
`mode` field) — `requestTsize = config.requestTsize and config.mode != tmNetascii`. For a netascii **PUT**,
`api.nim`'s `tdPut` branch (`:289-294`) must also mark the reported `total` as unknown (`none`), because
`.bytes` counts post-translation wire bytes while `fileSize` is pre-translation — otherwise progress can
exceed 100%.

### D2 — bounded dally (gap 2)

After the final ACK, `recvBlocks` `break`s into a distinct **epilogue phase** (not a fourth `case` nesting):
`dallyAfterFinalAck(transport, peer, config, finalAck, finalBlock)`, extracted in `transfer.nim` and called
from **both** `recvBlocks`'s final-block branch and `engine.getFile`'s single-block branch. (Do **not** fold
the single-block path into `recvBlocks` — its loop expects more DATA; the dally-only case has nothing to
receive but a possible retransmit, which is exactly what dally handles directly.)

**recvOnce extraction (was a round-2 non-buildable finding).** Dally cannot reuse `recvPacket`: `recvPacket`
resends `lastSent` on every timeout and *raises* on exhaustion — dally needs the inverse (silence ⇒ success,
no resend). So slice 5 first extracts a `recvOnce` primitive — a single receive + TID-lock validation + decode
(the core currently inline in `recvPacket`'s loop) — with **no** auto-resend and **no** raise-on-timeout.
`recvPacket` is rewritten to call `recvOnce` inside its existing retry/resend loop (behavior-preserving;
guarded by the three existing `t_transfer` tests: retransmit-then-succeed, retry-exhaustion-raises,
TID-mismatch). `dallyAfterFinalAck` calls `recvOnce` directly, so TID-lock validation is preserved
structurally rather than duplicated. Off-target packets (wrong block/opcode) are ignored without consuming a
re-ACK. Bounded by a wall-clock deadline of one `peer.effectiveTimeout` **and** `MaxDallyReacks = 2` (R5).

### D3 — error code 8 (gap 3)

Add `errOptionNegotiation = 8` to `TftpErrorCode`; widen decode to `errCode <= 8` (`> 8` still folds). Add the
`of errOptionNegotiation:` arm to `server.nim`'s exhaustive `clientSafeError` (`:69-87`) in the same slice or
the suite won't compile. Convert the two server option-failure catches (`server.nim:234`, `:353`) from
`errIllegalOperation` to `errOptionNegotiation` (R6 — these fire only on *unparseable* values). Strengthen the
existing `t_protocol` "decode ERROR code 8" test to pin `pkt.errorCode == errOptionNegotiation` (today it only
checks the opcode).

### D4 — client OACK validation, one pass, enforced filtering (gap 4; policy R4)

A single **pure** function replaces the two-step design (validate-then-reparse was a footgun — a caller could
skip the validator and reparse raw):

```nim
type OackOutcome* = object   ## FLAT object, NOT a case-object (never-throw Defect hazard)
  ok*: bool
  negotiated*: NegotiatedOptions   ## meaningful iff ok
  rejectReason*: string            ## "" iff ok
proc validateAndParseOack*(returned, requested: seq[(string,string)]): OackOutcome
```

It runs on the **raw** OACK pairs (critical: `parseOackOptions` clamps blksize/windowsize, so a post-parse
bounds check is vacuous), in one traversal, and:
- **filters out** (does not parse, does not apply) any returned option the client didn't request — R4
  enforcement. `applyOack`'s call site (`engine.nim:37`) is changed to consume `outcome.negotiated`, **not**
  `pkt.oackOptions` — otherwise an in-range foisted option still gets applied (the round-2 enforcement gap);
- for each *requested* option, checks the raw value against the D7 bounds predicates (`blksize` ≤ requested
  and ∈ 8..65464, `timeout` ∈ 1..255, `windowsize` ∈ 1..65535, `tsize` parses as `int64` ≥ 0);
- rejects a duplicate option name; matches names case-insensitively (client sends lowercase literals, so the
  requested set is already canonical);
- catches `parseBiggestInt`/`parseInt` `ValueError` **internally** → `ok=false` (the function stays total; no
  exception escapes a verdict-returning proc).

On `not ok`, `getFile`/`putFile` (which hold `transport`/`peer`) send `ERROR(8)` and return a
`TransferResult` with `errorCode = ord(errOptionNegotiation)` (so it reaches `evTransferError`) and a path-free
message. This also **replaces** the pre-existing silent `except ValueError` OACK path (`engine.nim:87,187`),
which today fails locally without signalling the server. (Nim 2.2.10: keep any distinct `except` types in
separate branches — multi-type `as e` doesn't compile.)

### D5 — timeout: validate, and *actually apply* the negotiated value (gap 5)

- **Server request path:** in `negotiateServerOptions`, an out-of-range `timeout` is **dropped** (R6). Seed the
  option's default from `limits.timeout` (populated from `ServerConfig.timeout` at `server.nim:50`, and
  **currently never read** in the `timeout` case) — **not** the global `DefaultTimeout` — so that an
  unconditional apply can't clobber a non-default operator timeout when the client negotiates only
  blksize/windowsize (round-2 bug 4b).
- **Client outbound:** clamp `timeout` to 1..255 in `newTransferConfig` (`transfer.nim:72-80`), the existing
  single choke point.
- **Apply it:** wire `xferConfig.timeout = neg.timeout` in `applyOack` and `handleRrq`/`handleWrq`. Assign
  **before** the post-OACK handshake wait (`recvPacket` for ACK(0), `server.nim:249-256`) so the handshake
  itself uses the negotiated value.
- **effectiveTimeout floor (round-2 bug 4a):** `effectiveTimeout` (`transfer.nim:100-103`) returns
  `peer.adaptiveTimeout` once it's `> 0`, discarding the negotiated value after the first RTT sample. Change it
  to treat the negotiated `config.timeout` as a **floor**: `max(adaptiveTimeout, config.timeout*1000)` — so a
  peer that negotiated a larger timeout for a high-latency link keeps that intent, while adaptive refinement
  still applies above the floor.

### D6 — receiver gap-ACK that composes with the sender's dup-ACK classifier (gap 6)

Add the `pkt.blockNum > expectedBlock` branch to `recvBlocks`. The subtlety (round-2 critical): the sender
classifies an incoming ACK as *forward-progress* (`ackBlockNum >= lastAcked+1`) or *duplicate*
(`ackBlockNum == lastAcked`), and it takes **2** duplicates (`dupAckThreshold`) to fast-retransmit. So the
receiver's response must depend on whether it has **already ACKed** the gap-target block (`expectedBlock-1`):

- **Mid-window gap** (target never ACKed by the receiver yet): a **single** gap-ACK lands in the sender's
  *forward-progress* branch and immediately drives the partial-ACK retransmit (`fillWindow`). Fire **once** —
  a second copy would then match the now-updated `lastAcked` as a phantom duplicate and prime `dupAcks`,
  causing a later spurious retransmit (defeating the Sorcerer's-Apprentice guard).
- **Window-boundary gap** (target already ACKed — previous window drained, first block(s) of the new window
  lost): the gap-ACK is a genuine duplicate from the sender's view, so fire it **exactly `dupAckThreshold`
  times** back-to-back to reach the fast-retransmit threshold.

The receiver knows locally which case it's in (it tracks its own highest-ACKed block). Track `lastGapAcked`
(compared against the current `expectedBlock`, not a sticky flag) to suppress re-firing for the *same* gap
while still allowing a distinct later gap. Hoist `dupAckThreshold` from the private `const` in `sendBlocks`
(`transfer.nim:226`) to a shared top-level constant so both sides agree by construction. **Underflow guard:**
compute the target as `if expectedBlock == 0: 0 else: expectedBlock - 1` (an unguarded `uint16` underflow is an
`OverflowDefect` that escapes `except CatchableError` — the tracked never-throw Defect hazard). Extract the
"last in-order block" computation into one helper used by **both** the duplicate branch (fixing its
wrong-block echo) and the gap branch.

### D7 — single source of truth for option bounds, in `protocol.nim` (new)

Bounds are scattered today; D4/D5 would add more copies. Consolidate all four families (blksize, windowsize,
timeout + predicates `validateBlocksize`/`validateWindowsize`/`validateTimeoutOpt`, consts
`Min/MaxTimeoutOpt = 1/255`) into **`protocol.nim`** — the pure, import-free RFC-codec module where
legal-value facts belong. `transfer.nim` `import`s and `export`s them (so `newTransferConfig`'s existing calls
and `api.nim`'s re-export chain need zero changes); **`server_config.nim` switches `import transfer` →
`import protocol`**, dropping an unnecessary transitive `asyncdispatch` dependency it only carried to reach
four constants. Route all four policy sites (client parse, server negotiate, D4, D5) through the shared
predicates, differing only in on-failure policy (clamp / drop / ERROR(8) per R6).

**ServerConfig validation** has no real construction choke point (it's a plain mutable object; the CLI sets
`config.maxBlocksize = blocksize` raw at `chapulin.nim:228`) — mirror the `checksumModeImplemented`
precedent: validate `{min,max}Blocksize`, `{min,max}Windowsize`, and `timeout` against the protocol constants
in **`startServer`** (raise → `evServerStartFailed`, the proven channel) **and** belt-and-suspenders in
`handleRrq`/`handleWrq` (both are directly-callable exported entry points that bypass `startServer`).
Reliability constants `dupAckThreshold` and `MaxDallyReacks` are deliberately **not** operator-configurable
(unlike the option bounds) and stay as internal consts.

## Slices (`/tdd`-sized, independently testable)

Tests land in existing files (no new test file / `dev-test.ps1` entry except `t_netascii`): pure predicates in
`t_transfer`; `ServerConfig`-rejection in `t_session` (mirrors the `startServer rejects csSha256` test);
client-engine in `t_client`; loss/reorder via `wireharness`. Slices 0–5 land before any netascii work (6/7a/7b
last and isolated).

0. **Option bounds → `protocol.nim` + `ServerConfig` validation (D7)** — relocate/add consts + predicates with
   re-export; `server_config.nim` imports `protocol`; validate bounds in `startServer` + `handleRrq/Wrq`. Pure
   + one integration test. (Prereq for 2, 3.)
1. **Error code 8 (D3) + `TransferInfo.errorCode` (Q1/A)** — enum + decode (`<= 8`) + `clientSafeError` arm +
   convert the two server catches; add the additive `TransferInfo.errorCode` field and populate it server-side
   (stop hardcoding 0); pin the decode test. *Test:* `t_protocol` + `t_server` + a `t_session` assertion that a
   server option-negotiation failure surfaces `evTransferError` with `errorCode == 8`.
2. **Client OACK validation → ERROR(8) (D4, R4)** — pure `validateAndParseOack` (filter-unrequested,
   reject-bad-value, dedupe, total); `applyOack` consumes `outcome.negotiated`; `ERROR(8)` send +
   `errorCode` set; unify old `ValueError` path. *Test:* `t_options` (pure) + `t_client` (wire). (Needs 0,1.)
3. **timeout validate + apply (D5)** — server drops out-of-range + seeds default from `limits.timeout`; client
   clamps outbound; wire `neg.timeout` through (before handshake wait); `effectiveTimeout` floor. *Test:*
   `t_options` + `t_client`/`t_session` + an apply assertion. (Needs 0.)
4. **RFC 7440 gap-ACK (D6)** — single- vs double-fire by already-ACKed state; hoisted constant; underflow
   guard; shared re-ACK-target helper. *Test:* `wireharness` — drop mid-window block (ws≥2), assert gap-ACK
   count (1 mid-window / 2 at boundary) precedes retransmitted DATA via `bLog`; block-2-first underflow.
5. **Bounded final-ACK dally (D2, R5)** — extract `recvOnce`, rewrite `recvPacket` on it (REFACTOR sub-step),
   `dallyAfterFinalAck` in `recvBlocks` **and** the single-block GET; deadline + `MaxDallyReacks`. *Test:*
   `t_transfer` (queued duplicate final DATA; exact re-ACK count; no spurious tail resend) + `t_client`.
6. **Stateful netascii transform, pure (D1a)** — `feed`/`flush`, defer-CR contract, straddle cases, scoped
   round-trip (R2). *Test:* `t_netascii` (add to `dev-test.ps1`).
7a. **netascii send side (D1b/d)** — `netasciiReader` (two-arg, read-ahead EOF, ascending assert); wire server
    RRQ + client PUT; policy seam (skip sidecar, drop tsize, encode dir-listing); netascii-PUT `total=none`.
    *Test:* `t_server`/`t_client` — LF↔CRLF RRQ, retransmission-under-netascii, sidecar-skipped. (Needs 6.)
7b. **netascii recv side (D1c)** — decoder-wrapped write + `finishNetasciiDecode`; server WRQ + client GET;
    suppress outbound tsize. *Test:* `t_server`/`t_client` — netascii WRQ round-trip, zero-length boundary.
    (Needs 5 for the post-dally success semantics, and 6.) Closes #13.

## Non-goals

- **Multicast (RFC 2090 / mtftp)** — new capability, not conformance; out of scope.
- **SHA-256 checksums** — tracked separately; `csSha256` stays rejected.
- **Receiver-side SACK / reorder buffer** — out-of-order blocks stay dropped; D6 adds only the prompt gap-ACK.
- **A folded `RecvContext`** collapsing the `(transport, config, peer)` triplet across
  `recvPacket`/`recvOnce`/`recvBlocks`/`dallyAfterFinalAck` — pre-existing debt this RFC doesn't create;
  logged as a note, not done here.
- **`rollover` / sub-second `utimeout`** — not standard-track; unknown options remain ignored.
- **WRQ `tsize` disk-space precheck** — a hardening nicety, not a conformance clause.

## Test strategy

No host Nim — verify each slice via `pwsh scripts/dev-test.ps1 <suite>` (Windows container) and, for netascii
LF↔CRLF and POSIX-real paths, the Linux container. Beyond per-slice tests:
- **Real foreign-tftpd interop** (tftpd-hpa/atftp, Linux container) for netascii **both** directions — GET
  (chapulin decodes a real server's stream) *and* PUT (a real server decodes chapulin's encode).
- **Client decoding an inbound ERROR(8)** from a foreign server — exercises the decode-widening symmetry and
  `errorCode: 8` surfacing on the receive side.
- **Combined loss** in one transfer: mid-stream gap (D6) then final-ACK loss (D2).
- **netascii × windowsize > 1** end-to-end; **OACK option-name casing** variation.
- **checksum × netascii** — assert the sidecar is *skipped* (R3).
- **zero-length file under netascii** (GET + PUT); **concurrent transfer starved by a lingering dally** under a
  constrained `portRange` (D2 capacity note).
netascii straddle, dally, and gap-ACK are prime `proptest` targets. No new FFI.
