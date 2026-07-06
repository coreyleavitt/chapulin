# chapulin API reference

Stable reference for embedding chapulin (currently the imminent oyamel GUI consumer; see
`MEMORY.md`'s oyamel-gui-toolkit note). Unlike `docs/rfc/*.md` — which are decision logs, dated
records of *why* a design changed — this document describes the *current* shape of the public
surface and is kept in sync with the source as it evolves. Where the two disagree, the source
(`src/chapulin/api.nim`, `src/chapulin/eventqueue.nim`, `src/chapulin/protocol.nim`) wins.

Frontends (CLI, GUI) must import only `src/chapulin/api.nim`. Nothing in `protocol.nim`,
`engine.nim`, `transfer.nim`, or `server.nim` is a supported entry point on its own — `api.nim`
re-exports every symbol a frontend legitimately needs.

## Entry point: `TftpSession`

`TftpSession` (an opaque `ref object`) is the whole embedding surface. One session can run any
number of concurrent client transfers and any number of listening servers; both share one event
queue.

```nim
proc newSession*(minLogLevel: LogLevel = llInfo,
                 transportFactory: TransportFactory = nil,
                 listenerFactory:  ListenerFactory = nil): TftpSession
```

`transportFactory`/`listenerFactory` are injection seams for tests (they default to real UDP);
embedders normally call `newSession()` with no arguments.

## The happy path

```nim
let s = newSession()
let id = s.startTransfer(newTransferRequest(host, port, filename, localPath, tdGet))
# ... on a GUI timer / poll loop:
for ev in s.poll(0):
  case ev.kind
  of evTransferComplete, evTransferError: ...
  else: discard
# ... or, for a script/CLI that just wants the outcome:
let result = s.waitTransfer(id)
```

One-liner: **`newSession` → `startTransfer` / `startServer` → `poll` / `waitTransfer` / `drain`.**

- `startTransfer(s, req: TransferRequest): TransferId` — launch a client GET/PUT. Returns
  immediately; the transfer runs against the session's async dispatcher.
- `startServer(s, config: ServerConfig): ServerId` — bind a listener and start serving. Returns
  immediately; bind failure is reported as `evServerStartFailed`, not a raise.
- `poll(s, timeoutMs: int = 0): iterator Event` — pumps the async dispatcher once, then drains and
  yields every currently-queued event. Call this from a GUI timer/idle callback.
- `waitTransfer(s, id: TransferId): TransferResult` — blocks (via repeated `poll(2)`) until `id`'s
  terminal event arrives; returns the outcome directly. Events for *other* ids seen while waiting
  are buffered and re-enqueued, so they are not lost.
- `waitServer(s, id: ServerId)` — the server-side analog: blocks until `evServerStopped` or
  `evServerStartFailed` for `id`.
- `drain(s, timeoutMs: int = 2000)` — ergonomic teardown: call after `close()` to pump `poll()`
  until all client transfers and servers have reached a terminal state, the deadline elapses, or no
  async work remains. Events seen during `drain` are discarded — collect events yourself before
  calling `close()`+`drain()` if you need them.
- `close(s)` — signals every active client transfer to cancel and every server to stop. Does not
  itself pump the queue; pair with `drain()` (or manual `poll()`) to observe/await the result.
- `cancel(s, id: TransferId)` / `stop(s, id: ServerId)` — see Cancellation semantics below.

**`poll()` drives a process-global dispatcher (L5).** `poll()` pumps the process-global
`asyncdispatch` (bare `asyncdispatch.poll`/`hasPendingOperations`) — there is no per-session
dispatcher. Pumping one session's `poll()` therefore advances every pending async operation in the
*process*, including another session's in-flight transfers and servers. This is harmless today —
each session owns its own `EventQueue` (see below), so one session's `poll()` can advance another
session's I/O without ever seeing or delivering that other session's events — but it is worth
knowing if an embedder runs two sessions side by side (e.g. a client session and a server session):
both still need their own `poll()` calls to drain their own events, and either call may incidentally
progress the other's pending I/O as a side effect.

**`waitTransfer`/`waitServer` bound waiting by iteration count, not a timeout (L6).** Both loop on
internal `poll(2)` calls up to `WaitCapIterations` (5,000,000, an internal constant — not part of the
public API) before giving up; there is no `waitTransfer(timeoutMs)` overload. In practice the
future/event driving the wait resolves via the engine's own retry/timeout configuration
(`TransferConfig.timeout`/`retries`, or the server's per-request handling) long before that iteration
cap is ever reached — the cap is a last-resort safety valve against a wait that would otherwise never
return, not a tuning knob. An embedder that needs a bounded wait should bound it by the
transfer/server's own timeout/retry configuration supplied at `startTransfer`/`startServer` time,
not by expecting a caller-supplied wait timeout.

## The never-raise guarantee

Every public session proc — `newSession`, `startTransfer`, `cancel`, `startServer`, `stop`,
`poll`, `close`, `drain`, `waitTransfer`, `waitServer` — **never raises**. This is asserted
per-proc in `api.nim`'s doc comments; this section collects it in one place because it is the
property a GUI event loop is built on: a call into the session can never unwind the caller's stack,
so a GUI frontend never needs a `try/except` around a session call. Failure is always reported
through the event stream instead:

- A `startTransfer` that fails before it can even launch (e.g. the local file won't open) emits
  `evTransferError` synchronously into the queue rather than raising, and still returns a valid
  (already-terminal) `TransferId`.
- A `startServer` that fails to bind emits `evServerStartFailed` and still returns a valid
  `ServerId`.
- `poll` itself swallows any exception surfacing from pumping the async dispatcher (e.g. an empty
  dispatcher's `ValueError`) and simply yields nothing that round.

## Building a `ServerConfig` (M1)

`startServer(s, config: ServerConfig)` takes a `ServerConfig`. Frontends should not hand-assemble one
field-by-field; `src/chapulin/server_config.nim` (re-exported through `api.nim` — no separate import
needed) provides the validated construction path.

### `newServerConfig` — two overloads sharing one validated body

```nim
proc newServerConfig*(
    rootDir: string,
    listenAddr: string = "0.0.0.0", listenPort: int = 69,
    portRangeStart: int = 0, portRangeEnd: int = 0,
    writePolicy: WritePolicy = wpDeny, maxConcurrent: int = 10,
    allowedHosts: seq[string] = @[], deniedHosts: seq[string] = @[],
    timeout: int = DefaultTimeout, retries: int = DefaultRetries,
    minBlocksize: int = MinBlocksize, maxBlocksize: int = MaxBlocksize,
    minWindowsize: int = MinWindowsize, maxWindowsize: int = MaxWindowsize,
    pxeCompat: bool = false, dirListFile: string = "",
    checksumMode: ChecksumMode = csNone): ServerConfigOutcome

proc newServerConfig*(
    rootDir: string,
    listenAddr: string = "0.0.0.0", listenPort: int = 69,
    portRangeStart: int = 0, portRangeEnd: int = 0,
    writePolicy: WritePolicy = wpDeny, maxConcurrent: int = 10,
    allowedHosts: seq[string] = @[], deniedHosts: seq[string] = @[],
    timeout: int = DefaultTimeout, retries: int = DefaultRetries,
    blocksizeRange: BlocksizeRange, windowsizeRange: WindowsizeRange,
    pxeCompat: bool = false, dirListFile: string = "",
    checksumMode: ChecksumMode = csNone): ServerConfigOutcome
```

Both build a `ServerConfig` and run the same bounds check exactly once; pick whichever fits the call
site:

- **Four-int overload** (`minBlocksize`/`maxBlocksize`/`minWindowsize`/`maxWindowsize`) — the simplest
  entry point. Pass loose ints; the ranges are built internally.
- **Range-accepting overload** (`blocksizeRange: BlocksizeRange`, `windowsizeRange: WindowsizeRange`)
  — for a caller that already holds pre-validated range values (built once via
  `newBlocksizeRange`/`newWindowsizeRange` and reused across several configs, or forwarded from
  another already-validated `ServerConfig`).

### `ServerConfigOutcome` — never raises

```nim
ServerConfigOutcome* = object
  ok*:           bool
  config*:       ServerConfig    ## meaningful iff ok
  rejectReason*: string          ## "" iff ok
```

Like every other entry point in the session facade, `newServerConfig` **never raises**: an embedder
checks `.ok` and, on rejection, reads `.rejectReason` for a human-readable cause (e.g. an
out-of-RFC-range `timeout`, or an invalid blocksize/windowsize pair). `.config` is still populated on
rejection (via an internal default-config fallback) so the field is never left undefined, but it
should not be used unless `.ok` is true.

### `BlocksizeRange` / `WindowsizeRange` — these DO raise

```nim
BlocksizeRange* = object
  minVal*, maxVal*: int
WindowsizeRange* = object
  minVal*, maxVal*: int

proc newBlocksizeRange*(minVal, maxVal: int): BlocksizeRange   ## raises ValueError on an invalid pair
proc newWindowsizeRange*(minVal, maxVal: int): WindowsizeRange ## raises ValueError on an invalid pair
```

Unlike `newServerConfig`, these two lower-level constructors are **raising** by design: they check
`minVal <= maxVal` and that both endpoints fall within the RFC-legal bound (`MinBlocksize..
MaxBlocksize` for blocksize per RFC 2348, `MinWindowsize..MaxWindowsize` for windowsize per RFC 7440),
and `raise ValueError` on an invalid pair. The never-throw guarantee lives one level up: the four-int
`newServerConfig` overload wraps both calls in `try/except ValueError` and folds the message into
`ServerConfigOutcome.rejectReason` rather than letting it escape. An embedder calling
`newBlocksizeRange`/`newWindowsizeRange` directly — bypassing `newServerConfig` — takes on the raise
itself and needs its own `try/except`.

Both range types stay public/hand-pokable objects rather than sealed ones. `ServerConfig` has no
single construction choke point of its own (it remains a plain mutable object; a range built validly
via `newBlocksizeRange` can still have `.minVal`/`.maxVal` poked invalid afterward), so `startServer`
and the server-side request handlers re-validate bounds at every entry point rather than trusting
construction alone.

## Events: `EventKind`, `Event`, `TransferSnapshot`

### `EventKind` — verified against `src/chapulin/eventqueue.nim:36-38`

```nim
EventKind* = enum
  evTransferStarted, evTransferProgress, evTransferComplete, evTransferError,
  evServerStarted, evServerStartFailed, evServerStopped, evServerLog
```

Eight values. `evTransferLog` (a per-transfer diagnostic log kind distinct from `evServerLog`) was
removed: it had zero producers in `src/` (only GUI/CLI consumer code and a test helper referenced
it) and is not part of the shipped contract.

### `Event` — the discriminated payload (`eventqueue.nim:77-102`)

`xfrId: TransferId` and `srvId: ServerId` are always readable regardless of `kind` (outside the
`case`) — `NoTransfer`/`NoServer` mark "not applicable." `snap: TransferSnapshot` is likewise a
common field, populated for every `evTransfer*` kind (zero-valued for server-lifecycle/log kinds).
The `case kind` arms:

| Kind | Extra fields |
|---|---|
| `evTransferStarted`, `evTransferProgress`, `evTransferComplete` | *(none — `snap` carries everything)* |
| `evTransferError` | `errorCode: Option[TftpErrorCode]`, `errorMsg: string` |
| `evServerStarted` | `boundAddr: string`, `boundPort: int` |
| `evServerStartFailed` | `startErr: string` |
| `evServerLog` | `sLevel: LogLevel`, `sMessage: string` |
| `evServerStopped` | *(none)* |

**`errorCode: Option[TftpErrorCode]`** (current shape, superseding an earlier bare `int`): `none`
means a local/transport/decode failure with no peer-supplied code; `some(c)` means a genuine
peer-emitted or locally-decoded `TftpErrorCode` (`errNotDefined`, `errFileNotFound`,
`errAccessViolation`, `errDiskFull`, `errIllegalOperation`, `errUnknownTransferId`,
`errFileAlreadyExists`, `errNoSuchUser`, `errOptionNegotiation` — `protocol.nim:17-26`). The old
bare-`int` shape defaulted to `0`, which was indistinguishable from a peer's genuine
`errNotDefined` (also ordinal `0`) — the `Option` wrapper removes that collision structurally.

### `TransferSnapshot` — `requested`/`effective` (`eventqueue.nim:55-75`)

```nim
TransferSnapshot* = object
  bytes*:      int64
  total*:      Option[int64]           # none until tsize negotiated
  requested*:  TransferParams          # ALWAYS the clamped requested/opening ask
  effective*:  Option[TransferParams]  # none until the handshake resolves, THEN some(in-effect)
  direction*:  TransferDirection
  mode*:       TransferMode
  startedAt*:  float
```

`TransferParams` (`protocol.nim:51-61`) is `object { blocksize*: int; windowsize*: int }`, shared
by both fields so they can't drift into two different shapes.

- `requested` is the clamped ask (post `validateBlocksize`/windowsize-clamp), constant for the
  whole transfer.
- `effective` is `none` until the handshake resolves and `some(params)` once in-effect (from the
  OACK handshake, or defaults if the peer sent none). M5 (code-review): this replaces an earlier
  `effective: TransferParams` + `settled: bool` pair that reintroduced the plausible-sentinel hazard
  D5 removed for `errorCode` — `effective` was always populated and indistinguishable from
  `requested` until `settled` flipped, guarded only by a hand-written doc warning. Collapsing to
  `Option[TransferParams]` makes "not yet settled" structurally distinct from any real value instead
  of relying on callers to check a separate bool first.
- On the server side `effective` is already `some(...)` by the time `evTransferStarted` fires (an
  OACK, if any, precedes the start callback) — `some(defaults)` there means "these are the in-effect
  defaults," not necessarily "an OACK occurred."
- On the client side `effective` is `none` at `evTransferStarted` and becomes `some(...)` once the
  handshake resolves, strictly before the first `evTransferProgress` on every path.

**`inEffect(snap): TransferParams`** (R2-M1, code-review; `eventqueue.nim`, re-exported through
`api.nim`): the safe accessor for "the in-effect params" — `snap.effective.get(snap.requested)`.
Never raises. Use `snap.inEffect` (or `ev.snap.inEffect`) rather than a bare `snap.effective.get`,
which raises `UnpackDefect` — a `Defect`, not a `CatchableError` — if read before the handshake
settles.

This supersedes an earlier flat `blocksize: int` / `windowsize: int` pair on `TransferSnapshot`
(0 until handshake, RFC-#17-documented) that conflated "requested" and "negotiated" into a single
field and could not represent both.

## The event queue's bounded contract (H1, code-review)

Every session has exactly one event queue (`MaxQueuedEvents` = 8192 in production), and **the cap
is a true, absolute ceiling**: the queue never holds more than `cap` events, full stop, no
exception — this is enforced after every single push, not just "eventually" or "on average".

This was **not** always true. An earlier revision treated `evTransferStarted`,
`evTransferComplete`, `evTransferError`, `evServerStarted`, `evServerStartFailed`, and
`evServerStopped` as a protected set that was never evicted and never dropped — but that made the
cap not actually hard: once the queue was full of protected events with no cheaper (progress/log)
event left to reclaim, a push of another protected event exceeded the cap outright. Worse, in a
flood consisting *entirely* of protected events (e.g. malformed-option RRQ/WRQ packets, each
injecting an `evTransferStarted` + `evTransferError` pair for the cost of one wire packet), the
synthetic drop-count warning — itself a coalescing log-kind event — never got a chance to fire
either, so the queue grew silently and unboundedly: a remote denial-of-service vector for any
embedder that polls slower than the flood.

The bounded contract now: when the queue is full, a log-kind event (`evServerLog`) is evicted
first to make room, as before — so protected events are still *preferred* to survive. But once no
log-kind event remains to reclaim, the queue drops the single **oldest** queued event, regardless
of kind, rather than ever exceeding the cap — terminal and start events included. All drops (log,
progress, or oldest-event) are coalesced into one running count and surfaced via a single
synthetic `evServerLog` warning (`"dropped N events (queue cap)"`), itself only flushed once room
exists for it (so the flush can never itself push the queue past the cap either).

**Practical consequence for a frontend:** under sustained queue saturation (the frontend is not
draining `poll()` often enough relative to the volume of activity), an `evTransferStarted` or even
a terminal event for some `TransferId` can, in the worst case, be dropped rather than delivered.
This is a deliberate change from the old "protected events are never dropped" promise to "bounded:
under queue saturation, the oldest event may be dropped, terminal events included." A frontend
that drains `poll()` every tick, as recommended, will not observe this in practice — 8192 events is
a large buffer relative to any reasonable poll cadence; this is a last-resort safety valve against
a hostile or pathological peer, not a normal operating mode.

## Contract 1 — event ordering

For a given `TransferId`, under normal (non-saturated) queue operation:

1. `evTransferStarted` is always the first event observed for that id.
2. At most one terminal event is emitted per id — `evTransferComplete` **xor**
   `evTransferError` — and it is always the *last* event observed for that id.
3. `evTransferProgress` events for that id may be coalesced (the queue keeps only the
   latest-position progress payload per id) or dropped under queue pressure, but are never
   reordered past that id's terminal event.

A frontend can therefore treat "terminal event seen" as an unconditional signal that no further
events for that `TransferId` will ever arrive. Under queue saturation (see the bounded contract
above), an id's `evTransferStarted` or terminal event is one of the last-resort drop-oldest
candidates like any other queued event — this ordering contract describes delivered events, not a
guarantee that every id's events are always delivered.

## Contract 2 — cancellation semantics

`cancel(s, id: TransferId)` and `stop(s, id: ServerId)` are both **asynchronous, best-effort**
requests, not synchronous cancellations:

- `cancel(id)` sets a flag that the in-flight transfer observes at its next checkpoint (the next
  block send/receive loop iteration) — it does not force an immediate stop and does **not**
  guarantee a terminal `evTransferError`. If the transfer happens to complete before it next checks
  the flag, it still emits `evTransferComplete`, not an error.
- `cancel` on an id that is unknown, already terminal, or belongs to a different session is a
  silent no-op — no event, no error.
- `stop(id)` signals a server to stop accepting *new* requests; transfers already in flight on that
  server are deliberately left to drain to completion (never force-cancelled). `evServerStopped` is
  emitted once the accept loop has exited **and** all of that server's active transfers have
  finished — the same "eventually consistent, observed via poll/drain" pattern as transfer
  cancellation.
- `stop` on an unknown or already-stop-requested id is a silent no-op.

`close()` applies `cancel`-style best-effort cancellation to every active client transfer and
`stop`-style shutdown to every server in one call; `drain()` is the pump that waits (up to its
timeout) for all of those best-effort requests to actually resolve into terminal/`evServerStopped`
events.

## Verification notes

This document was written against the post-slice-8b tree (`design-bar-closure.md` slices 1-8b) and
is **review-verified, not test-verified**: it is prose describing existing, already-tested runtime
behavior, and a doc-text description has no independent runtime behavior of its own to pin a new
test to. Every symbol, field, and enum value above was grep/read-verified against the current
source (`src/chapulin/api.nim`, `src/chapulin/eventqueue.nim`, `src/chapulin/protocol.nim`,
`src/chapulin/transfer.nim`) rather than transcribed from RFC prose; see the slice-9 handoff notes
for the exact grep evidence.
