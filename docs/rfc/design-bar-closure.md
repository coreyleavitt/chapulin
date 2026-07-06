# RFC: Design-bar closure — server.nim + api.nim + cross-cutting surface

- **Status:** Draft — ready for architect review.
- **Tracking issue:** none — spun out of two independent design audits plus `design-philosophy.md`
  (root, line 11: *"If something is done the wrong way, it gets rewritten — not patched"*).
- **Scope:** `src/chapulin/server.nim`, `api.nim`, `server_config.nim`, `checksum.nim`, `netascii.nim`,
  `transport.nim`, and their public-surface fallout in `src/chapulin.nim` (CLI). `protocol.nim`,
  `options.nim`, `engine.nim`, `security.nim` are not REDESIGNED — they are already at the bar. `transfer.nim`
  carries one explicit carve-out: D5's `errorCode` type migration (`int`→`Option[TftpErrorCode]`)
  necessarily touches `transfer.nim` (the `TransferResult.errorCode` field definition) and `engine.nim`
  (three producer sites). This is a mechanical type change, not a design change — those modules are
  otherwise untouched by this RFC.

## Why now

Two design audits agree: the CORE modules — `protocol.nim` (pure codec), `transfer.nim` (shared
`sendBlocks`/`recvBlocks`), `options.nim` (negotiation), `security.nim`, `netascii.nim`'s codec — are at
the PhD-CS bar the project's own philosophy demands. Two layers built *on top* of that core are not:
`server.nim`'s request handling (god-procs, duplicated handshake logic, mutable threading through
closures) and `api.nim`'s session orchestration (four hand-synced bookkeeping structures, an event queue
with its coalescing/eviction logic inlined into one proc, an error taxonomy downgraded to a bare `int`).
Plus a handful of cross-cutting surface issues (dead speculative generality, a stale doc, a misplaced
policy type). None of this is exotic — every fix below reuses a primitive the core modules already
established (`OackOutcome`'s flat-object shape, `makeSendReader`/`makeRecvSink`'s constructor-owns-the-
decision pattern, `awaitHandshakeReply`'s handshake extraction). This RFC closes the gap using those
existing primitives, not new ones.

Two of the ten findings are **verified bugs**, cited here as such (not merely style):

1. **Pre-clamp snapshot echo.** `api.nim`'s `startTransfer` binds `bs`/`ws` from the raw, unclamped
   request (`api.nim:216-217`, `let bs = req.options.blocksize`, `let ws = req.options.windowsize`) and
   never reassigns them. Every `evTransferStarted` built from these — both the normal-path emit
   (`api.nim:342-343`, `mkSnap(0, startTotal, dir, md, bs, ws, t0)`) and the exception-path `zeroSnap`
   template (`api.nim:231-232`, used at the `except CatchableError` handler, `api.nim:376-378`) — echo
   the **raw** request values. Meanwhile the actual wire request three lines below the first use
   clamps them (`api.nim:247-248`: `blocksize: validateBlocksize(bs)`, `windowsize: max(MinWindowsize,
   min(MaxWindowsize, ws))`). An embedder reading `evTransferStarted.snap.blocksize` sees a value the
   wire never sent. This is broader than a single `zeroSnap` call site — it is every `evTransferStarted`
   the client path emits.
2. **`errorCode: 0` collision.** `api.nim`'s transfer-future failure callback hardcodes `errorCode: 0`
   at two sites — the local/transport failure path (`api.nim:361`, inside `fut.addCallback`) and the
   pre-launch exception path (`api.nim:378`). `0` is also `TftpErrorCode.errNotDefined`
   (`protocol.nim:18`) — the code a *peer* sends for "undefined error." An embedder cannot distinguish
   "the server told me error 0" from "chapulin never reached the server at all."

## Resolutions (decisions, veto-able)

- **R1.** D5's fix is a **flat `Option[TftpErrorCode]`**, not a variant/case-object. `options.nim`'s
  `OackOutcome` (`options.nim:22-31`) already sets this precedent explicitly: *"A case-object here would
  make a wrong-branch field access a FieldDefect that escapes `except CatchableError`."* `Option[T]` is
  not a case-object in that sense (it has no caller-visible discriminant to mis-branch on) and is the
  established idiom (`TransferSnapshot.total*: Option[int64]` already does this, `api.nim:80`).
- **R2.** D6's `requested`/`negotiated` split makes client and server snapshot semantics **identical** —
  today's role-dependent meaning (comment at `api.nim:81-82`) is the asymmetry being removed, not
  preserved under a new name. Achieving that server-side is **not free**: `TransferInfo` (`server.nim:
  18-33`) today carries only post-negotiation values, so the client's pre-negotiation ask must be
  threaded through `TransferInfo` for server-side `requested` to be meaningful (otherwise it would
  vacuously equal the effective values). **Decision (architect round 1):** thread the client's clamped
  ask into `TransferInfo` for true parity — see revised D6.
- **R3.** D8's per-scalar distinct types for every client-side field (e.g. a `Blocksize` distinct
  `int`) are **out of scope** — flagged as an open question for architect review, not committed. Only
  the server's `{min,max}` *pair* becomes a bounded-range type (the actual asymmetry: server has an
  unlinked pair, client has a single scalar — the pair is what's under-modeled, not the scalar).
- **R4.** D7's `newServerConfig` validating constructor is the **recommended construction choke point**
  and single-sources the bounds validation, but it does **not** remove `api.nim:417`'s guard.
  `serverConfigBoundsValid` (`server_config.nim:75-90`) currently guards three call sites
  (`server.nim:229` in `handleRrq`, `server.nim:398` in `handleWrq`, `api.nim:417` in `startServer`)
  precisely because — per that proc's own doc comment — *"ServerConfig has no real construction choke
  point."* That remains true even once the constructor exists: `ServerConfig` has every field public
  (`*`) and is re-exported through `api.nim`, so it is fully hand-buildable and post-construction
  mutable — `startServer` is exactly as bypassable an entry point as `handleRrq`/`handleWrq`. All three
  existing guards therefore stay as belt-and-suspenders; the constructor is purely additive (a
  validated, ergonomic construction path), not a replacement that removes a guard.

## Designs

### D1 — Shared negotiate+OACK handshake primitive (`server.nim`)

**Current.** `handleRrq` (`server.nim:183-379`) and `handleWrq` (`server.nim:383-499`) each inline the
same five-part dance: build `ServerOptionLimits` via `serverOptionLimits(config)` (`server.nim:51-58`),
call `negotiateServerOptions` in a `try/except ValueError` that emits `mkTransferInfo`-via-`onStart` then
`errOptionNegotiation` (`server.nim:289-303` / `:426-438`, byte-for-byte parallel structure), assign
`neg.{blocksize,windowsize,timeout,totalSize}` into `xferConfig` (`:305-309` / `:440-444`), and send the
OACK if `oackOpts.len > 0`. The two handlers diverge only after this: RRQ actively waits for the
post-OACK `ACK(0)` via `recvPacket` (`:319-326`); WRQ sends the OACK and returns, relying on
`recvBlocks`' block-1 receive to pick up the client's `DATA(1)` (`:446-448`, comment at `:449` explains
why). That divergence is real (RFC 2347 asymmetry between RRQ/WRQ acknowledgment shape), not
duplication — the primitive must accommodate it, not paper over it.

**Why below the bar.** `sendBlocks`/`recvBlocks` unified the data phase one layer down (`transfer.nim`);
the handshake phase directly above it never got the same treatment, so it drifts by hand — the
`suppressTsize` computation, the option-filter-for-PXE call, and the `onStart`-before-error ordering all
have to be kept in lockstep across two ~200-line procs by inspection.

**Target.** A `var` parameter on an `{.async.}` proc does not compile in Nim (async lowers to a
closure-iterator, which forbids `var` params — the codebase's own `awaitHandshakeReply` doc,
`engine.nim:114-115`, states this). So `xferConfig` cannot be threaded in by `var`; it is instead
threaded out solely through the returned `NegotiationOutcome`, by value.

A single `negotiateAndAck(..., wrq: bool)` primitive would also reintroduce the `wrq: bool`
behavior-flag smell `awaitHandshakeReply` already rejects — that proc's own pattern is "push divergence
to the caller that owns it." Extract instead one un-exported core plus two thin named public wrappers:

```nim
type NegotiationRequest = object
  transport*: Transport
  config*:    ServerConfig
  peer*:      PeerEndpoint       ## carries host+port; no separate clientHost/clientPort
  request*:   TftpPacket
  direction*: string

proc negotiateCore(req: NegotiationRequest,
                   onStart: proc(info: TransferInfo) {.closure.},
                   startedAt: float, reqId: int
                   ): Future[NegotiationOutcome] {.async.}

proc negotiateRrq(...): Future[NegotiationOutcome] {.async.}
  ## awaits the post-OACK ACK(0) when an OACK was sent

proc negotiateWrq(...): Future[NegotiationOutcome] {.async.}
  ## returns immediately after the OACK send; for the zero-options case,
  ## sends the bare ACK(0) itself
```

Grouping the invariant request-describing quintet (`transport`/`config`/`peer`/`request`/`direction`) into
`NegotiationRequest` collapses the parameter repetition that otherwise compounds across all three procs
(core + both wrappers each forward it); `onStart`/`startedAt`/`reqId` stay loose because they are
per-request plumbing `handleRequest` generates, not part of "the request."

`negotiateCore` owns everything except the post-OACK reply: `filterOptionsForPxe` dispatch,
`serverOptionLimits`, the `negotiateServerOptions` call, the `ValueError` → `onStart` → `ERROR(8)`
failure path, the `xferConfig` field assignment, and the OACK send. The two wrappers each own exactly
the divergence that's really theirs: `negotiateRrq` awaits the post-OACK `ACK(0)` when an OACK was sent;
`negotiateWrq` returns immediately after the OACK send — **and** must own a second, easy-to-miss
divergence (depth finding): a WRQ with **zero** requested options unconditionally sends a bare `ACK(0)`
itself today (`server.nim:450-452`), whereas RRQ's zero-options path sends nothing (its first reply is
`DATA(1)` from `sendBlocks`). This is called out explicitly here so an implementer doesn't drop it —
dropping it would break every default-options `tftp put`.

`NegotiationOutcome` is a flat object carrying at least:

```nim
type NegotiationOutcome = object
  ok*:              bool
  xferConfig*:      TransferConfig   ## by value; meaningful iff ok
  oackSent*:        bool             ## meaningful iff ok; tells negotiateRrq whether to await ACK(0)
  requestedParams*: TransferParams   ## client's RFC-clamped pre-negotiation ask (D6 parity plumbing);
                                     ## computed once in negotiateCore, inert until slice 7 wires it
  failure*:         TransferResult   ## meaningful iff not ok
```

The codebase has two established flat-outcome conventions, not one: **bool-gated** (`OackOutcome` —
exactly one failure mode, or failure modes no consumer must tell apart) and **kind-gated**
(`HandshakeOutcome` — 2+ non-success outcomes some consumer must distinguish, via an explicit `case
kind`). `NegotiationOutcome` is bool-gated like `OackOutcome`; the R1 citation of both in one breath
overstated the uniformity. Per-field `## meaningful iff ok / iff not ok` comments live directly on the
type declaration above (matching `OackOutcome`'s in-type doc style), not only in this prose.

The onStart firing asymmetry the implementer must preserve is handled **structurally, not by a flag**
(this is why there is no `onStartFired` field): `negotiateCore` fires `onStart` itself on the
`ValueError` path, immediately **before** `ERROR(8)` (`server.nim:296-303`), because `ERROR(8)` is sent
inside the primitive and the ordering must hold. On the success path `negotiateCore`/the wrappers do
**not** fire `onStart` — the handler fires it, exactly once, only after the wrapper returns `ok = true`.
A failed post-OACK `ACK(0)` wait (`server.nim:322-326`) returns `ok = false` **without** firing
`onStart`; the handler's early-return on `not ok` therefore never fires it either, honoring Invariant 4
(dropped) automatically. Because the success-path `onStart` is the handler's sole responsibility and
every failure path either already fired it (ValueError) or must not (dropped ACK(0)), no coordinating
flag is needed — the two behaviors fall out of *where* `onStart` is called.

Each handler shrinks to: config/path guards → `negotiateRrq`/`negotiateWrq` → build `readData`/
`recvSink` via the already-shared `makeSendReader`/`makeRecvSink` → `onStart` → transfer primitive →
sidecar/report. `handleRrq` is ~197 lines today (`server.nim:183-379`); `handleWrq` is ~117 lines
(`server.nim:383-499`) — not "two ~200-line procs." Estimated ~40-50 lines per handler
post-extraction.

### D2 — Decompose `handleRequest` (`server.nim`)

**Current.** `handleRequest` (`server.nim:514-658`) does: transport allocation with port-range retry
(`:534-556`, a `for port in ... try/except OSError: continue` loop), `reqId` allocation (`:559-561`),
three mutable `var effBlocksize`/`effWindowsize`/`effMode` (`:572-574`) threaded through two closures
(`progressCb` at `:578-591`, `onStart` at `:594-601`) so the *later* `TransferInfo` built at `:640-650`
can report negotiated values, opcode dispatch (`:608-618`), transfer-result logging (`:620-638`), and
diagnostic-channel logging (`:630-638`). Both `progressCb` and `onStart` are declared in the same
enclosing scope as `effBlocksize`/`effWindowsize`/`effMode`, and Nim closures capture such enclosing
`var`s by reference to **one shared location** — there is no actual duplication of state today; both
closures already see the same three variables.

**Target.** Extract the transport/port-range allocation into a helper, e.g. `allocateTransferTransport
(server, config): (Transport, bool)`, returning whether binding succeeded so the caller does the
`sendError`+return. The `eff*` mutable threading is a readability/encapsulation improvement, **not a bug
fix** — three loose enclosing `var`s is a weaker seam than one named object, so route the shared
negotiated-values state through one named seam/object instead of three loose `var`s; this is about
naming and encapsulating existing-correct state, not correcting a duplication that doesn't exist. Also
fold in the `transport.nim` byte↔string dedup as a minor cleanup in this slice (see below) since it is
adjacent, trivial, and touched by nothing else in this RFC. (Note: this dedup is validated only
transitively — no `t_transport` test exists — acceptable given its acknowledged triviality.)

**`transport.nim` dedup (minor, folded in).** `newUdpTransport`'s `send` (`transport.nim:16-18`) and
`recv` (`:31-34`) each hand-roll a `seq[byte]` ↔ `string` conversion loop; `newUdpListener`'s `recv`
(`:66-69`) duplicates the `string`→`seq[byte]` half a third time. Extract `toWireString(data:
seq[byte]): string` and `toByteSeq(s: string): seq[byte]` once, used by all three sites.

### D3 — Consolidate `api.nim` session state

**Current.** Four parallel structures on `TftpSession` (`api.nim:126-136`): `active: Table[uint32,
TransferEntry]` (client transfers, `:129`), `servers[srvId].xfers: Table[XferKey, TransferId]`
(`:123`), `servers[srvId].cancelFlags: Table[XferKey, ref bool]` (`:124`), and `serverXferCancel:
Table[uint32, ref bool]` (`:135`). They are kept in sync by hand at every server callback: `onStart`
writes `xfers` and mirrors into `serverXferCancel` (`:443-449`); `onTransferComplete`/`onTransferError`
each delete from `xfers`, `cancelFlags`, **and** `serverXferCancel` in the same handler (`:476-478`,
`:490,493-494`) — three deletes for one logical "this transfer is done." `cancel` (`:382-390`) itself
branches on which of the two cancel-flag tables (`active` vs `serverXferCancel`) holds the id.

**Target.** One `Table[TransferId, TransferRecord]`. Drop the `case kind: TransferKind` case-object:
verify during implementation that `TransferEntry.transport` (`api.nim:111-113`) is genuinely dead — it
is written once (`api.nim:344`) and never read (the transport is closed via a separately-captured
closure variable, not via the table). If confirmed dead, `TransferRecord` becomes a flat `object` with
just `cancelFlag: ref bool` — no case-object, no Defect surface at all:

```nim
type
  TransferRecord = object
    cancelFlag: ref bool
```

`cancel(id)` is one lookup + one flag set, kind-agnostic. The per-server reqId → TransferId resolution
(needed because `TransferInfo` only carries `reqId`, not `TransferId`) still needs two small tables per
server, not one: `xfers: Table[XferKey, TransferId]`, the steady-state reverse lookup used to resolve an
incoming callback once a `TransferId` exists, and `cancelFlags: Table[XferKey, ref bool]`, a transient
bridge holding the `ref bool` handed to `cancelFactory` (called with only a `reqId`, before any
`TransferId` exists) until `onTransferStart` mints the `TransferId` and moves the flag into the
consolidated record. Neither disappears — both remain as the two other tables alongside the consolidated
`Table[TransferId, TransferRecord]`, each justified by a distinct need (steady-state lookup vs. the
pre-mint bridge), not a single catch-all table.

The earlier "internal routing data, never a client-facing boundary" justification for a case-object
does not hold up: per depth review, that internal/external distinction is inconsistent with this RFC's
own cited precedents — `OackOutcome`/`HandshakeOutcome` are also internal-only, yet chose flatness
because a `FieldDefect` crashes the process regardless of which module raised it. The real safety rule
is: if a per-kind variant is ever genuinely needed (justified by a named consumer), every read must go
through an exhaustive `case record.kind:` — never an `if record.kind == X: record.field` — and be
exposed via a named accessor, not raw field access.

**Test-only accessors.** The `when defined(chapulinTest)` test-only accessors (`sessionActiveCount`,
`sessionServerCount`, `sessionQueueLen`, `injectEvent`, `api.nim` ~691-708) must be re-pointed at the new
consolidated structures as part of this slice.

### D4 — Extract the event queue into its own tested type

**Current.** `enqueue` (`api.nim:141-182`) inlines three concerns: progress coalescing (an O(n) linear
scan over `s.events` at `:149-153` to find-and-replace the existing progress entry for an id), bounded
eviction (a full-deque rebuild scanning for the first log-kind event at `:162-171`), and dropped-count
bookkeeping with a synthetic warning event (`:174-182`). It is only exercised today through whole-session
integration tests (`t_session.nim`), never directly.

**Target.** An `EventQueue` type (a new small module, or a clearly-separated section of `api.nim`) built
on **key redirection**, not placeholders — round 2 rejected the placeholder split because a
marker-`Event`-in-a-`Deque` is either an undocumented invisible convention or a case-object (the exact
`FieldDefect` shape the Hard Constraints forbid), and it invited silent event loss and unbounded growth:

```nim
type EventQueue = object
  order:       Deque[int]             ## arrival-ordered keys (FIFO); every key maps to a real payload
  payload:     Table[int, Event]      ## key -> the event (terminals, logs, and progress alike)
  progressKey: Table[TransferId, int] ## an id's LIVE key iff it has an un-drained progress event
  nextKey:     int                    ## monotonic key mint
proc push(q: var EventQueue, ev: Event)
proc tryPopFirst(q: var EventQueue): Option[Event]
proc len(q: EventQueue): int
```

Every value in `order`/`payload` is a real payload — there is no "marker vs. real" distinction, so
nothing wants to become a case-object. Coalescing is O(1) and position-preserving: `push` of a progress
event whose id already has a live key in `progressKey` **overwrites `payload[key]` in place** (the key
keeps its original FIFO position in `order` — this *is* the coalesce, not a bolted-on resolution step);
otherwise it mints a new key, appends it to `order`, and records it in `progressKey`. `tryPopFirst` pops
the front key from `order`, returns `payload[key]` (deleting it), and — if that key was the id's live
progress key — clears `progressKey[id]` in the **same** step, so one code path owns both structures'
consistency.

The load-bearing invariant (state it, test it): **`id` is a key in `progressKey` iff `id` has exactly
one un-drained progress event, whose key is `progressKey[id]`.** From it: (1) a progress `push` after
that id's prior progress was already drained sees no live key and correctly mints a fresh one at the new
tail position (no silent loss — the bug the placeholder split invited); (2) `progressKey` holds only ids
with a currently-queued progress event, so it is bounded by queue size, not by total transfers ever run
(no leak — the placeholder-`Table` unbounded-growth risk is gone); (3) a terminal event is an ordinary
keyed payload that never touches `progressKey`. Bounded eviction and dropped-count bookkeeping operate on
`order`/`payload` exactly as today (evict the first log-kind payload, never a terminal), with the
dropped-count synthetic-warning policy preserved as an internal method.

`popFirst` is deliberately not offered: `std/deques.popFirst` raises `IndexDefect` (a Defect that
escapes `except CatchableError`) on an empty deque, and a directly-unit-tested standalone type invites
that violation. `tryPopFirst(q: var EventQueue): Option[Event]` returns `none` when empty and never
raises; `poll()`'s drain loop becomes `while true: (let ev = q.tryPopFirst(); if ev.isNone: break; yield
ev.get)`. This matches R1's `Option[T]`-as-value discipline.

(Realization note: `Deque[int]` keys + `Table[int, Event]` payloads is one concrete form; a
`std/tables.OrderedTable[int, Event]` collapses `order`+`payload` into one structure if its
deletion/iteration cost is acceptable — an implementation-time check against stdlib, not a design fork.
Both satisfy the design above; neither uses a placeholder.)

Same test-only-accessor re-pointing as D3 applies here.

### D5 — Error taxonomy reaches the public boundary

**Current.** `TransferResult.errorCode: int` (`transfer.nim:27`), `Event.errorCode: int`
(`api.nim:95`, inside the `evTransferError` variant arm), `TransferInfo.errorCode: int`
(`server.nim:30`) all downgrade the real `TftpErrorCode` enum (`protocol.nim:17-26`) to a bare `int`,
and `0` is ambiguous per the verified bug above.

**Target.** All three become `errorCode*: Option[TftpErrorCode]` (R1 — flat `Option`, not a variant).
Semantics: `none` = local/transport/decode failure with no peer-supplied code (covers today's hardcoded
`errorCode: 0` sites, `api.nim:361,378`, and `server.nim`'s pre-`onStart` failures); `some(c)` = a peer
(or this server) actually emitted/decoded TFTP error code `c` — covers every site that currently does
`ord(errCode)` (`engine.nim:268-269`, `:352-353`; `server.nim`'s `failResult(msg, ord(code))` call sites
at `server.nim:272` and `server.nim:462`, the real RRQ/WRQ `osResult` return sites — not `:307`, which is
`xferConfig.blocksize = neg.blocksize`, unrelated to error codes). Every producer that currently passes
an `int` switches to passing `some(code)`; every site with no real code passes `none(TftpErrorCode)`.
One more consumer/producer round 2 surfaced: `waitTransfer` (`api.nim:649`) reconstructs a
`TransferResult` from a terminal `Event` via `errorCode: ev.errorCode` — it stays compiling
post-migration (both sides become `Option` together) but is a real `errorCode` round-trip site; slice 6
adds a regression test driving it through a genuine `evTransferError`.

The collision's real root also lives in `transfer.nim`: `sendBlocks` (lines 377-378, 384-385, 415-417,
442-444) and `recvBlocks` (508-509, 515-516, 538-540, 588-590) construct `TransferResult` **without**
setting `errorCode`, silently defaulting to 0 (=`errNotDefined`) — the same collision. Once the field is
`Option[TftpErrorCode]`, Nim's zero-value-is-`none` fixes these for free — noted here so the implementer
knows why `transfer.nim` is in the touched set (this reinforces the Scope carve-out above).

**CLI update:** `src/chapulin.nim` does not currently read `ev.errorCode` at all (only `ev.errorMsg`, at
`:207,267`), so this slice has no required CLI behavior change — it is a pure type-signature migration
at the boundary, verified by grep against the CLI source, not an assumption.

### D6 — `TransferSnapshot`: requested vs effective

**Current.** `TransferSnapshot.blocksize`/`.windowsize` (`api.nim:81-82`) carry role-dependent meaning
documented only in a comment: for the client, "requested at `evTransferStarted`, negotiated (OACK) from
first `evTransferProgress` onward"; for the server, "already negotiated at `evTransferStarted`" (OACK
precedes `onStart` there). Plus the verified pre-clamp echo above.

**Target.** Design review changed the shape from an `Option`-wrapped substruct to a flat shape: forcing
every consumer to unwrap an `Option` for the overwhelmingly common post-handshake case is friction with
no payoff, and a flat "always-present field + explicit bool gate" matches the codebase's own
`OackOutcome`/`HandshakeOutcome` idiom better than `Option`-wrapping the substruct. The field is named
`effective` (not `negotiated`) and the gate `settled` (not `negotiated`) — because for a bare RRQ/WRQ no
OACK occurs at all, so "negotiated" would be a misnomer; "settled/in-effect" is honest:

`TransferParams` is defined once in `protocol.nim` (both `api.nim` and `server.nim` already import it;
`api.nim` re-exports several `protocol` symbols), so the client snapshot and the server-side ask share
one structural type rather than two identical records in two modules.

```nim
type
  TransferParams* = object
    blocksize*:  int
    windowsize*: int
  TransferSnapshot* = object
    bytes*:      int64
    total*:      Option[int64]
    requested*:  TransferParams  ## ALWAYS the clamped requested/opening-ask values
    effective*:  TransferParams  ## == requested until settled==true, THEN in-effect. WARNING: reading
                                 ## effective without checking settled yields a plausible request-echoing
                                 ## value, not garbage — consumers must gate on settled.
    settled*:    bool            ## true once the handshake has resolved; server: always true post-admit
    direction*:  TransferDirection
    mode*:       TransferMode
    startedAt*:  float
```

`requested` is populated from the **clamped** values at every call site — for the client this means
`startTransfer` must clamp `bs`/`ws` once, up front (reusing the same `validateBlocksize`/
`max(MinWindowsize, min(MaxWindowsize, _))` calls already at `api.nim:247-248`, just applied before
`bs`/`ws` are captured rather than only at the `TftpClientConfig` construction ~31 lines later) — this
structurally fixes the pre-clamp bug rather than patching the two call sites that read `bs`/`ws`
independently. `effective` equals `requested` until `settled` flips true, at which point it holds
`TransferParams(blocksize: effBs, windowsize: effWs)` for the client (from first `evTransferProgress`
onward), and holds the negotiated values immediately at server `evTransferStarted` (since OACK precedes
`onStart` there). Identical meaning for client and server (R2) — no per-role comment needed once the
three fields exist.

**Trade-off, stated explicitly (depth review):** `requested` being *always* the clamped value
deliberately discards the caller's true pre-clamp input — a caller requesting blocksize=4 sees the
clamped 8 everywhere, with no signal it was out of range. This is defensible (never expose a value never
actually put on the wire), but it is a real trade-off, not purely a bug fix, and is recorded as such
rather than framed only as "fixing the bug."

**Server-side true parity (architect round 1 decision — Corey chose this; round 2 fully scoped it).**
The client's clamped ask must reach `api.nim`'s `requested` for every server-side snapshot. Round 2
traced this and found it is more involved than "thread one `TransferInfo` field":

- **Source (new `server.nim` code, not `options.nim`).** `request.options` is raw wire strings; the only
  parser, `negotiateServerOptions` (`options.nim`), is out of scope AND clamps to *server limits*, not
  the RFC-global bounds the client's `requested` uses. So add a small **pure, best-effort** helper in
  `server.nim` that parses the raw option strings and RFC-clamps them (mirroring the client's own
  `validateBlocksize` / `max(MinWindowsize, min(MaxWindowsize, _))`), **per-option independently** — one
  malformed key must not discard a valid sibling. A missing or unparseable option falls back to that
  field's default (`DefaultBlocksize`/`DefaultWindowsize`). **Limitation (honest, documented):** a
  malformed option means the client's true ask is *unknowable* server-side, so `requested` shows the
  default for that field — this is the one case where server-side parity degrades, and it coincides with
  a request that fails with `ERROR(8)` anyway.
- **Compute once, carry as plumbing.** `negotiateCore` computes this ask once (it already has the raw
  options in scope) and returns it on `NegotiationOutcome.requestedParams` (D1). This avoids re-parsing
  and lets the handler's success-path snapshot read the same value the failure-path `onStart` inside
  `negotiateCore` uses.
- **Six construction sites, not four.** `TransferInfo` is built at six sites in `server.nim`: four via
  `mkTransferInfo` (the onStart/failure paths) plus two direct literals — `progressCb`
  (`server.nim:580-588`, every progress tick) and the final complete/error `info` (`server.nim:640-650`).
  Since `requested` is ALWAYS-present on the snapshot, it must be correct on progress and terminal
  snapshots too, so the ask must be captured into **D2's named seam object** as an *immutable sibling* to
  `eff*` (set once, never mutated) and reused at all three construction shapes. It does ride on
  `TransferInfo` — that is the only server→`api.nim` channel — but as an invariant-per-transfer value,
  doc-commented as such so it isn't mistaken for a per-tick fact.
- **`api.nim` wiring.** `mkSnap` is called by all four callback closures (start/progress/complete/error);
  each maps the `TransferInfo` ask field into `snap.requested`, while the post-negotiation values map into
  `effective`. This makes server-side `requested` genuinely show the client's ask (e.g. 8192) even when
  negotiation clamped `effective` down (e.g. 4096) — true parity, honoring R2.

This threads through D1 (`NegotiationOutcome` field + the new helper), D2 (the seam sibling), and D6
(`TransferInfo` field + `api.nim` mapping). Slices 1, 2, and 7 must each carry their part — see the slice
list.

**Bare-request semantics.** For a bare RRQ/WRQ (zero options), no OACK/negotiation occurs at all (the
`if clientOpts.len > 0` branch is skipped, `server.nim:285`/`:422`); `settled` is still `true` at server
`evTransferStarted` in this case, but it means "in-effect defaults," **not** "an OACK was exchanged" —
made explicit here so it isn't misread as an OACK-occurred signal.

**CLI impact:** `src/chapulin.nim` does not read `ev.snap.blocksize`/`.windowsize` today (verified by
grep), so no required CLI code change; update is type-only at the public boundary, same situation as D5.

### D7 — `ServerConfig` validating constructor + structure

**Current.** `ServerConfig` (`server_config.nim:18-36`) is an 18-field flat mutable object (`rootDir`,
`listenAddr`, `listenPort`, `writePolicy`, `maxConcurrent`, `timeout`, `retries`, `maxBlocksize`,
`minBlocksize`, `maxWindowsize`, `minWindowsize`, `portRangeStart`, `portRangeEnd`, `pxeCompat`,
`dirListFile`, `checksumMode`, `allowedHosts`, `deniedHosts`). `serverConfigBoundsValid`'s own doc
comment (`:81-83`) states it directly: *"ServerConfig has no real construction choke point (a plain
mutable object; the CLI pokes fields directly)."* Confirmed at the CLI: `src/chapulin.nim:224-239`
builds via `newDefaultServerConfig(rootDir)` then assigns **11** fields directly, one per line
(`listenPort`, `writePolicy`, `maxConcurrent`, `maxBlocksize`, `timeout`, `retries`,
`portRangeStart`, `portRangeEnd`, `pxeCompat`, `listenAddr`, `dirListFile`), plus the validated
`checksumMode` assignment (`:236-239`) via `parseChecksumMode`. Bounds are re-validated ad-hoc at three
sites: `server.nim:229` (`handleRrq`), `server.nim:398` (`handleWrq`), `api.nim:417` (`startServer`).

**Target.** Not a raising constructor and not `Result[ServerConfig, string]`. A flat `ServerConfigOutcome`
object:

```nim
type ServerConfigOutcome* = object
  ok*:           bool
  config*:       ServerConfig  ## meaningful iff ok
  rejectReason*: string        ## meaningful iff not ok
```

Rationale (design review): a raising constructor would be the one construction path in the never-throw
`api.nim` facade (which the GUI consumer relies on) that breaks the "never raises" promise; and
`Result[T,E]` would be the codebase's first use of a generic result type, contradicting the RFC's own
"reuse existing shapes" hard constraint. The flat `*Outcome` matches `OackOutcome`. `newServerConfig(...):
ServerConfigOutcome` validates once, at construction, folding in `serverConfigBoundsValid`'s and
`checksumModeImplemented`'s checks (R4). The CLI checks `.ok` instead of catching an exception.

Per R4 above: the constructor does **not** remove `api.nim:417`'s guard — all three existing guards
(`server.nim:229`, `server.nim:398`, `api.nim:417`) stay as belt-and-suspenders, since `ServerConfig`
remains fully hand-buildable and mutable regardless of the constructor's existence. Sub-group fields
conceptually (binding: `listenAddr`/`listenPort`/`portRangeStart`/`portRangeEnd`; policy:
`writePolicy`/`maxConcurrent`/`allowedHosts`/`deniedHosts`; protocol-bounds: `timeout`/`retries`/
blocksize+windowsize ranges (D8); features: `pxeCompat`/`dirListFile`/`checksumMode`) — as doc-comment
grouping and constructor parameter order, not necessarily nested sub-objects (avoid over-restructuring a
type every test file already constructs positionally/by-field).

**Two construction sites migrate.** CLI (`src/chapulin.nim:224-239`) builds via the constructor instead
of `newDefaultServerConfig` + 11 direct assignments. The desktop GUI
(`gui/desktop/chapulin_gui.nim:377-380`) also builds `ServerConfig` via `newDefaultServerConfig` + direct
field pokes (`listenPort`, `writePolicy`, `maxConcurrent`) — the same anti-pattern. Decision: migrate it
to the constructor alongside the CLI (cheap, and keeps the "one recommended construction path" invariant
honest even though the GUI is slated for the oyamel port).

### D8 — Config symmetry + bounded-range type

**Current.** Client-side blocksize is a scalar: `TransferOptions.blocksize: int` (`api.nim:31`),
`TftpClientConfig.blocksize: int` (`engine.nim:18`) — one requested value, clamped once
(`validateBlocksize`, `protocol.nim:208-210`). Server-side is two unlinked bare ints: `ServerConfig.
maxBlocksize`/`.minBlocksize` (`server_config.nim:26-27`), same shape for windowsize
(`.maxWindowsize`/`.minWindowsize`, `:28-29`) — nothing at the type level prevents `minBlocksize >
maxBlocksize` (that's exactly what `serverConfigBoundsValid` has to check by hand, `server_config.nim:
84-89`). Confirmed: the CLI never sets `minBlocksize`/`minWindowsize` at all (grep of
`src/chapulin.nim` shows only `config.maxBlocksize = blocksize`, `:228` — the min side is silently
whatever `newDefaultServerConfig` set, `MinBlocksize`/`MinWindowsize` from `protocol.nim`).

**Target.** A bounded-pair type per option family:

```nim
type
  BlocksizeRange* = object
    minVal*, maxVal*: int
  WindowsizeRange* = object
    minVal*, maxVal*: int
proc newBlocksizeRange*(minVal, maxVal: int): BlocksizeRange   ## validates min<=max, both in RFC bounds
proc newWindowsizeRange*(minVal, maxVal: int): WindowsizeRange
```

used by `ServerConfig` in place of the four bare ints. `newServerConfig` still takes the four values as
loose `int` parameters (`minBlocksize`/`maxBlocksize`/`minWindowsize`/`maxWindowsize` — kept flat, not a
range-typed pair, so existing CLI/GUI call sites don't ripple) and builds `BlocksizeRange`/
`WindowsizeRange` from them internally via `newBlocksizeRange`/`newWindowsizeRange`, folding a raised
`ValueError` into `ServerConfigOutcome.rejectReason`. So an invalid pair is still representable at the
call boundary and still rejected post-hoc, not structurally ruled out by the type — what D7/D8 buy is
that this check now happens at one never-raising construction choke point (`newServerConfig`) instead of
being re-derived ad hoc at each of the three scattered validation sites (`server.nim`'s
`handleRrq`/`handleWrq`, `api.nim`'s `startServer`), which still call `serverConfigBoundsValid` as
belt-and-suspenders. **Open question, not committed (R3):** per-scalar distinct types for every
client-side field (a `Blocksize`/`Windowsize`/`TimeoutSeconds` distinct `int` wrapping
`TransferOptions.blocksize` etc.) is a plausible further-symmetry move but is likely
over-engineering for a single scalar with one clamp call — left for architect review rather than
committed here.

### D9 — Remove `csSha256` dead speculative generality

**Current.** `csSha256` is a live `ChecksumMode` enum value (`server_config.nim:16`) with zero
implementation, forcing dead/guard arms at every consumer: `checksum.nim`'s `newDigester`
(`:34-35`, raises), `update` (`:47-48`, `discard # unreachable`), `finalize` (`:61-62`, `discard #
unreachable`), `commit` (`:110-111`, `discard # unreachable`); `server_config.nim`'s
`checksumModeImplemented` (`:73`, excludes it from the `{csNone, csMd5}` set) and `parseChecksumMode`
(`:100`, parses the string then immediately re-rejects it via that same predicate, `:104-106`); the CLI
has no direct reference (it goes through `parseChecksumMode`) but the RFC's own non-goals section
(`rfc-conformance-closure.md`, "SHA-256 checksums — tracked separately") already treats it as a future
item, not a live feature.

**Target.** Remove the `csSha256` enum value entirely and every dead/guard arm it forces (the four
`checksum.nim` arms, the `checksumModeImplemented` exclusion becomes unnecessary — `ChecksumMode`
becomes exactly `{csNone, csMd5}` so no filtering predicate is needed at all — and `parseChecksumMode`'s
`"sha256"` case becomes a plain `else` rejection like any other unrecognized string). Re-add the enum
value (and its real implementation) when SHA-256 is actually built; the cross-reference in
`rfc-conformance-closure.md`'s non-goals stays the tracking anchor.

### D10 — Docs

**(a) API reference.** Add `docs/api-reference.md`: `TftpSession` as the entry point, the (post-D9) 9
`EventKind` values (`api.nim:74-76`: `evTransferStarted, evTransferProgress, evTransferComplete,
evTransferError, evTransferLog, evServerStarted, evServerStartFailed, evServerStopped, evServerLog`),
the happy-path one-liner (`newSession` → `startTransfer`/`startServer` → `poll`/`waitTransfer`/`drain`),
and the never-raise guarantee (every public proc's doc already asserts this per-proc; this doc collects
it in one place). Distinct from this RFC and its siblings (decision-logs, not a stable reference) — for
the imminent oyamel GUI consumer per `MEMORY.md`'s oyamel-gui-toolkit note.

Also specify two contracts the GUI consumer needs, currently only scattered across `api.nim` doc-comments:

1. **Event-ordering contract** — for a given `TransferId`, `evTransferStarted` is always first, at most
   one terminal (`evTransferComplete` xor `evTransferError`) is emitted and always last, and
   `evTransferProgress` may be coalesced/dropped but never reordered past the terminal.
2. **Cancellation semantics** — `cancel(id)` is asynchronous/best-effort (sets a flag observed at the
   next checkpoint, does not guarantee a terminal error; a transfer that completes first still emits
   `evTransferComplete`; cancel on an unknown/already-terminal/foreign id is a silent no-op), and the same
   drain semantics apply to `stop()`/`evServerStopped`.

**Docs action:** `docs/rfc/embedding-api.md` (RFC #17) documents the OLD shapes — `Event.errorCode: int`
(line ~181), `TransferSnapshot.blocksize`/`.windowsize: int` (lines ~165-166), and a usage example
`modal.blocksize = ev.snap.blocksize` (line ~219). D5/D6 make these factually wrong. Update
`embedding-api.md`'s type snippet and usage example to the post-D5/D6 shapes (or mark those two fields
superseded), as part of this docs slice.

**(b) `design-philosophy.md` drift fix.** Line 72 states *"The server dispatches concurrent transfers via
`asyncCheck`"* — verified false against the actual code: `server.nim:706-710`'s `run` proc calls
`server.handleRequest(...)` then `hf.addCallback(proc() {.gcsafe.} = ...)`, not `asyncCheck`. This is the
documented never-raise-Defect switch (a failed handler future is inspected and logged, never left to
crash the process the way an unhandled `asyncCheck` failure can). Fix the line to say `addCallback`. This
slice is **review-verified, not test-verified** — a doc-text correction has no runtime behavior to pin a
test to; say so explicitly rather than inventing a test for it.

**Folded-in minor item (no slice; architect-discretion).** `NetasciiPolicy` (`netascii.nim:382-390`) is
arguably mis-scoped under `netascii.nim` — its own doc comment (`:343-390`) already frames it as
transfer-*mode* policy (`skipSidecar`, `suppressTsize`, `reportTotalUnknown`), not CR/LF translation, and
a case could be made for relocating it to `protocol.nim` near `TransferMode`. Flagged as a **candidate**
relocation, **low priority**: it was refactored recently (per its own doc's "what used to be separate
fields here" note) and moving it now is low-value churn against a freshly-settled shape. Left to
architect discretion; not committed as a slice.

## Slices

Internal refactors under green first, then breaking public-surface changes (each also updates the CLI
where the CLI actually consumes the changed surface — D5/D6 do not, verified above), then docs.

1. **D1 — server handshake primitive extraction.** Refactor under green: `t_server.nim` is the spec, plus
   `t_props_server.nim` and `t_props.nim` (in `dev-test.ps1`'s default suite) which drive `handleRrq`/
   `handleWrq` and `negotiateServerOptions` directly at ~30 call sites — a materially broader net than
   `t_server.nim`'s examples; run these, not just `t_server`, plus
   one NEW test that pins the onStart-before-ERROR(8) ordering — it does not currently exist (existing
   unparseable-option tests at `t_server.nim:188-206` and `:538-554` pass `onStart = nil` so can't observe
   it). The new test passes a spy `onStart` + an unparseable option and asserts it fires exactly once with
   pre-negotiation defaults before `ERROR(8)`. Extract `negotiateCore` plus the `negotiateRrq`/
   `negotiateWrq` wrappers; both `handleRrq`/`handleWrq` call their respective wrapper. Pin: existing
   RRQ/WRQ option-negotiation-failure tests still pass unchanged; add a test preserving the bare-WRQ
   `ACK(0)` send (RRQ awaits `ACK(0)` via `negotiateRrq`, WRQ returns immediately and `recvBlocks` picks up
   `DATA(1)`, except the zero-options case where `negotiateWrq` sends the bare `ACK(0)` itself). Also (D6
   parity plumbing): `negotiateCore` computes the client's RFC-clamped ask once via the new best-effort
   `server.nim` helper and returns it on `NegotiationOutcome.requestedParams` — inert until slice 7, but
   built and unit-tested here so slice 7 doesn't widen the primitive's return contract six slices late.
2. **D2 — `handleRequest` decomposition + transport dedup.** Refactor under green: `t_server.nim` is the
   spec. Note the citation fix: `t_integration.nim` is **not** in `dev-test.ps1`'s default suite
   (`scripts/dev-test.ps1:26-30`) and does not cover port-range retry at all. Add a direct
   port-range-retry test (a fake transfer factory raising `OSError` on the first N port binds, asserting
   the loop advances and the `bound` flag is honored) as the RED for `allocateTransferTransport` — this
   test must exist BEFORE the extraction for it to be a real refactor-under-green. Regroup the `eff*`
   state between `progressCb`/`onStart` as a readability improvement (not a bug fix — see D2). Design the
   named seam object with an **immutable `requestedAsk` sibling** (a `TransferParams`) alongside the
   mutable `eff*` fields — set once, unused until slice 7. This is where D2 and D6 touch the same
   `handleRequest` local state; making the field exist now means slice 7 reads it rather than reopening
   this seam. Extract `toWireString`/`toByteSeq` in `transport.nim`, used by both `newUdpTransport` and
   `newUdpListener` (transport dedup remains transitively validated; no `t_transport` test).
3. **D3 — `api.nim` session-state consolidation.** Refactor under green: `t_session.nim` is the spec
   (server-transfer lifecycle: start → progress → complete/error → cancel, both client and server
   transfers). Collapse `active`+`serverXferCancel` into one `Table[TransferId, TransferRecord]`;
   `cancel` becomes one lookup. Pin: existing cancel-mid-transfer and double-cancel-is-noop tests.
4. **D4 — `EventQueue` extraction + direct unit tests.** New direct tests (likely a new `t_eventqueue.nim`
   added to `dev-test.ps1`, or a section of `t_session.nim` if the type stays private to `api.nim`) proving
   O(1) coalescing (push N progress events for one id, assert `len` stays 1 without an O(n) scan
   assumption baked into the test) and the eviction/dropped-count policy directly, not only through
   `TftpSession`. Add the `tryPopFirst`/`Option` shape (never raises on empty, unlike `deques.popFirst`)
   and a cross-kind ORDERING test — e.g. log-A, progress-B(v1), log-C, progress-B(v2 coalesced),
   terminal-B → assert drained order preserves the position-pinned rule — since no existing test pins
   cross-kind relative order. Existing `t_session.nim` queue-cap tests keep passing unchanged
   (behavior-preserving).
5. **D9 — `csSha256` removal.** Not an "assertion update": `csSha256` is referenced as a live enum
   **literal** in three test blocks that will FAIL TO COMPILE once the enum value is removed:
   `tests/t_checksum.nim:42-44`, `tests/t_server.nim:625-650` (whole suite), `tests/t_session.nim:
   633-667`. These three blocks must be **deleted** (the "fails loud as unimplemented" behavior no longer
   exists as a distinct path), landed atomically in the same commit as the `checksum.nim`/
   `server_config.nim` source change so the tree compiles.
6. **D5 — `errorCode` → `Option[TftpErrorCode]`.** BREAKING. Fixes the verified `errorCode==0` collision.
   Update `TransferResult`, `Event`, `TransferInfo`; every producer site listed in D5 switches int→
   `Option`. Touches `transfer.nim` (the field + the unset-`errorCode` sites in `sendBlocks`/
   `recvBlocks`) and `engine.nim` (3 producer sites), per the Scope carve-out — a mechanical type change,
   not a redesign. No CLI code change required (verified: CLI never reads `.errorCode`). Tests:
   `t_client.nim`/`t_server.nim`/`t_session.nim` assertions on `.errorCode` change from `== 0`/
   `== ord(code)` to `== none(TftpErrorCode)`/`== some(code)`; add the regression test this bug deserves —
   a local transport failure (mock transport raising before any peer packet) must yield
   `errorCode == none(...)`, proving it's no longer indistinguishable from a peer's `errNotDefined`. Add a
   second regression test driving `waitTransfer` (`api.nim:649`) through a genuine `evTransferError` and
   asserting the reconstructed `.errorCode` is `some(code)` — that round-trip site has no existing
   terminal-error test. Also add a compile-check that `tests/t_integration.nim` (a real consumer of
   `TransferResult.errorCode`/`ev.snap`, compiled by `docker-compose.yml` though not by `dev-test.ps1`)
   still compiles after the type migration.
7. **D6 — `TransferSnapshot` requested/effective/settled.** BREAKING. Fixes the verified pre-clamp echo.
   Update `TransferSnapshot` to the flat `requested`/`effective`/`settled` shape; clamp `bs`/`ws` once in
   `startTransfer` before first capture. Add server-side parity (architect round 1 decision; round 2
   scoping): read the client's clamped ask already computed on `NegotiationOutcome.requestedParams`
   (slice 1) and stored in D2's seam sibling (slice 2), add the `TransferInfo` ask field, and map it into
   `snap.requested` at ALL FOUR `api.nim` callback closures (start/progress/complete/error), populated at
   all SIX `server.nim` `TransferInfo` construction sites (four `mkTransferInfo` + `progressCb`
   `server.nim:580-588` + final `info` `:640-650`). This slice reads the slice-1 and slice-2 plumbing
   rather than reopening either. No CLI code change required (verified: CLI never reads
   `.snap.blocksize`/`.windowsize`). Tests: `t_session.nim` — (a) out-of-range requested blocksize/
   windowsize → `evTransferStarted.snap.requested` is clamped not raw; (b) client `.settled` is `false` at
   `evTransferStarted`, `true` from first `evTransferProgress`; (c) server `.settled` already `true` at
   `evTransferStarted`; (d) server-side `requested` reflects the client's ask while `effective` reflects
   the clamped negotiated value when they differ (verifies the six-site threading, not just the start
   snapshot — assert `requested` on a progress and on a terminal snapshot too); (e) bare RRQ/WRQ →
   `settled` true meaning in-effect defaults.
8. **Split into 8a and 8b** (feasibility):
   - **8a. D7 — `ServerConfig` validating constructor.** BREAKING. `newServerConfig` returning
     `ServerConfigOutcome`, over the existing bare-int fields; single-sources validation; all three
     existing guards (`server.nim:229`, `server.nim:398`, `api.nim:417`) stay. Migrate CLI
     (`src/chapulin.nim:224-239`) AND the desktop GUI (`gui/desktop/chapulin_gui.nim:377-380`) to build
     via it. Smaller, independently committable.
   - **8b. D8 — bounded-range types.** BREAKING. Swap the four bare min/max ints for
     `BlocksizeRange`/`WindowsizeRange` inside the now-existing constructor. Atomic: the field rename
     ripples in ONE commit to `server.nim:51-58`'s `serverOptionLimits` (reads the four fields directly),
     the CLI, and a full rewrite of `tests/t_session.nim:669-716` (the existing 8-case `expectRejected`
     helper mutates the bare int fields post-construction — it cannot compile post-D8 and must be
     rewritten around `newBlocksizeRange`/`newWindowsizeRange` call-site validation). Add BOTH: (1) a
     `newBlocksizeRange`/`newWindowsizeRange` constructor-level min>max rejection test, AND (2) a rewrite
     of the old 8-case `expectRejected` pattern that still proves R4's belt-and-suspenders —
     post-construction field mutation (now `.blocksizeRange.minVal` etc., since the range fields stay
     public and hand-pokable) that bypasses the constructor is still caught by `serverConfigBoundsValid`
     at `startServer`. Dropping (2) would silently lose the guard coverage the old test provided.
9. **D10 — docs.** `docs/api-reference.md` (new, including the event-ordering and cancellation
    contracts); `docs/rfc/embedding-api.md` update (post-D5/D6 shapes for `Event.errorCode` and
    `TransferSnapshot.blocksize`/`.windowsize`, and the `modal.blocksize = ev.snap.blocksize` usage
    example); `design-philosophy.md:72` `asyncCheck`→`addCallback` fix. Review-verified, not
    test-verified — say so in the PR/commit, not test output.

## Non-goals

- **UFTP/multicast (RFC 2090 / mtftp)** — a new capability, not a design-bar fix; out of scope.
- **A full public-API v2** beyond the items above — this RFC closes a specific, itemized gap, not a
  general API redesign.
- **Per-scalar distinct types for every client-side field** (D8's open question) — flagged for architect
  review, not committed here.
- **Reworking the core modules** (`protocol.nim`, `transfer.nim`, `options.nim`, `engine.nim`,
  `security.nim`) — both audits agree they are already at the bar; touching them is out of scope for this
  RFC — except the single `errorCode` field type migration D5 forces in `transfer.nim`/`engine.nim`,
  which is a mechanical type change, not a redesign (see Scope).
- **GUI/frontend work beyond the CLI updates the breaking slices force** — the oyamel port (per
  `MEMORY.md`) is separate future work; D10(a)'s API reference is preparation for it, not the port itself.

## Test strategy

No host Nim — verify each slice via `pwsh scripts/dev-test.ps1 <suite>` (Windows container). Per-slice
test files are named in each slice above; no new `dev-test.ps1` entries are required except possibly a
`t_eventqueue.nim` for slice 4 (or a section within `t_session.nim`, at implementer discretion — pick
whichever avoids duplicating `TftpSession` construction boilerplate). `t_security`'s `Cleanup` step is a
known pre-existing Windows-container flake — ignore failures there; it is unrelated to this RFC's
changes. Note: `docker-compose.yml`'s `dev` service suite omits `t_checksum`/`t_netascii` (which D9
touches) — this RFC's verification path is `dev-test.ps1`, not `docker compose run dev`; don't verify D9
via the latter.

The "slices 1-5 show zero test-file changes" claim from an earlier draft is false — each of slices 1-5
now has a specific, intended test change: slice 1 **adds** an onStart-ordering pin; slice 2 **adds** a
port-range test; slice 4 **adds** an ordering test plus new direct tests; slice 5 **deletes** three test
blocks (named above) that no longer compile. Slices 6-8b are breaking and each names its updated/new
assertions above; slice 9 is docs and is reviewed, not tested.

## Hard constraints

- **FFI-free.** No `importc`/`exportc`/`dynlib`/`cdecl`/`{.header.}`/`std/winlean` anywhere touched by
  this RFC (none of D1-D10 needs any — confirmed by inspection of the touched modules).
- **Never-throw-Defect discipline.** Flat objects over variants wherever a wrong-branch field access
  would be a `FieldDefect` escaping `except CatchableError` — this is the reason D5 uses
  `Option[TftpErrorCode]` rather than a variant (R1), and the reason D3 drops its `TransferRecord`
  case-object entirely once `transport` is confirmed dead: `OackOutcome`/`HandshakeOutcome` show that
  "internal-only" is not an exemption from this discipline, since a `FieldDefect` crashes the process
  regardless of which module raised it. If a per-kind variant is ever genuinely needed there, every read
  must go through an exhaustive `case` and a named accessor — never raw field access.
- **PhD-CS bar.** Every design above reuses an existing, already-reviewed primitive shape
  (`OackOutcome`'s flatness, `awaitHandshakeReply`'s extraction pattern, `makeSendReader`/
  `makeRecvSink`'s constructor-owns-the-decision pattern) rather than inventing a new one — consistency
  with the core modules' style is part of the bar.
- **Lands on `main`.** No feature branches, no PRs — per `MEMORY.md`'s commit-to-main-always note.
