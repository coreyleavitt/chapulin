# RFC: Embedding API — session + event queue as the single frontend contract

- **Status:** Draft — architect review **rounds 1 + 2 applied** (ready for `/tdd`)
- **Tracking issue:** [#17](https://github.com/coreyleavitt/chapulin/issues/17)
- **Related:** #4 (oyamel migration — the consumer), #3 (server per-transfer progress modal),
  #14 (session establishment primitive — *under* this), #13 (sources/sinks data path — *under* this),
  #15 (scriptable mock network — testing substrate; partially satisfied today by `tests/wireharness.nim`),
  #8 (library/binary package split — this API is the library surface)
- **Supersedes:** the current `api.nim` (`executeTransfer` / `TransferRequest` / `TransferCallbacks`)

## Why now

The oyamel GUI port (#4) is imminent. Porting the current GUI as-is means porting its accidental
complexity — worker threads, a `Channel[TransferMsg]`, `Atomic[bool]` flags, a 50 ms polling timer,
and a hand-rolled copy of the server loop — into the new toolkit. Fixing the *contract* once, before
the second frontend exists, turns the port into a widget swap. This RFC consolidates four facets that
are all aspects of one contract:

| Facet | Where it lives in this RFC |
|-------|----------------------------|
| **A. Transfer session** (own the thread/async/poll once) | The spine: `TftpSession` + `poll` iterator + event queue |
| **B. One server loop + wire `onTransferStart`** | The server half of the same event model |
| **C. Never-throw boundary** | An invariant of the session: failures are *events*, never exceptions |
| **D. Config/progress ergonomics** | The event payload + session ops (`fraction`, enum `checksumMode`, tsize defaults, uniform `cancel`) |

## Problem

`api.nim` covers exactly one use case — a blocking client transfer with three callbacks — so every other
frontend need was improvised inside the frontends:

- The **GUI imports 6 internal modules** (`server`, `server_config`, `logging`, `transport`, `format`,
  `api`); the CLI imports 10 (`api`, `transport`, `format`, `server`, `server_config`, `security`,
  `protocol`, `transfer`, `tftp_uri`, `logging`). The "`api.nim` is the stable public contract" claim in
  `design-philosophy.md` is structurally unachievable today because **there is no server API at all**.
- The **GUI reimplements the server listener loop** (`gui/desktop/chapulin_gui.nim:98-114`) instead of
  using `srv.run()`, and the copy has **drifted**: it silently skips `checkHostAccess` and drops requests
  at max-concurrent without the "Server busy" error packet that `server.nim:376-382` sends. Two server
  behaviours exist, selected by which frontend started it. (Facet B.)
- `ServerCallbacks.onTransferStart` is **declared and never fired** (`server.nim:23` vs `handleRequest`),
  so a frontend cannot show "transfer began" — one reason the GUI forked the loop. (Facet B.)
- The GUI **hand-rolls worker threads + `Channel` + `Atomic[bool]` + a 50 ms polling timer** — violating
  the project's own "no threads, no locks, no atomics" philosophy — purely because NiGui's event loop
  can't share the async dispatcher. (Facet A.)
- The error model **leaks past the result type**: most failures return in `TransferResult`, but handshake
  paths raise (`TftpDecodeError`, `ValueError`), and twelve `await sendError(...)` callsites, four
  `newUdpTransport(0)` sites (`server.nim:288,292,371,378`), and three bare `await transport.send`
  handshake sends (`server.nim:148,217,220`) can raise `OSError`. Under `asyncCheck` (`server.nim:385`)
  such an exception re-raises *inside the next `poll()`*. On a worker thread today it is a crash, not an
  `onError`. (Facet C — the central hazard; see Invariant 2.)
- Progress carries `totalSize = -1` until `tsize` is negotiated, and `requestTsize` defaults off, so a
  progress bar cannot show a percentage without the frontend knowing to flip a flag. `checksumMode` is a
  bare string while its siblings (`WritePolicy`, `TransferMode`) are enums. (Facet D.)
- **None of this frontend-side logic has tests.**

## First-Principles Ideal

The core is already single-threaded async. A GUI timer tick calling `asyncdispatch.poll(0)` runs the
entire server and all client transfers **on the UI thread** — both NiGui (`startRepeatingTimer`) and
oyamel (`wkTimer`) provide the tick. So the ideal frontend contract is:

- a **session** owning all live state (transfers, servers, event queue),
- **opaque ids** (`TransferId`, `ServerId`) — and a `TransferId` is issued for **every** transfer the
  session owns, server-initiated ones included, so `cancel` is uniform,
- a single **`poll`** call that pumps the dispatcher **and yields** the drained events — no separate
  "pump" and "drain" steps to forget,
- events as **plain data** — no closures crossing the boundary, no marshalling, no thread-context
  questions,
- a hard guarantee that **`poll` and every session call never raise** across the boundary (Facet C):
  every recoverable failure is an event.

GUI tick and CLI loop become the same drain code with different poll timeouts. The duplicated server loop
and the thread machinery become **structurally impossible**: there is exactly one server loop, inside the
library, and there are no threads to share state across.

## Proposed Interface

```nim
## api.nim — the complete embedding surface (replaces the current api.nim)

type
  TftpSession* = ref object        # opaque; owns ids, event queue, async state
  TransferId* = distinct uint32    # issued for EVERY transfer, client- or server-side
  ServerId*   = distinct uint32

const
  NoTransfer* = TransferId(0)      # the nil id; a real id is never 0 (allocation is 1-based)
  NoServer*   = ServerId(0)

type
  # Adapters injected ONCE at construction (ports & adapters) — never per call, so
  # the production surface has zero test seams and Invariant 6 is enforceable.
  TransportFactory* = proc(host: string, port: int): Transport {.closure.}
  ListenerFactory*  = proc(bindAddr: string, port: int): UdpListener {.closure.}

proc newSession*(minLogLevel: LogLevel = llInfo,
                 transportFactory: TransportFactory = nil,  # nil → real UDP; ipv6 derived via isIPv6(host)
                 listenerFactory: ListenerFactory = nil): TftpSession

# --- client transfers ---
proc startTransfer*(s: TftpSession, req: TransferRequest): TransferId
  ## Returns immediately with a valid id. All setup (file open, validation) happens
  ## in the async body or is caught and materialised as an immediate evTransferError
  ## carrying the returned id — startTransfer itself never raises (Invariant 2).

# --- servers ---
proc startServer*(s: TftpSession, config: ServerConfig): ServerId
  ## Bind failure (port in use) surfaces as evServerStartFailed, not a raise.
proc stop*(s: TftpSession, id: ServerId)
  ## Graceful stop: refuse new requests immediately; in-flight transfers run to their
  ## natural terminal (complete, or timeout-error after retries). Emits evServerStopped
  ## once the last handler terminates. For an *expedited* stop, cancel(xfrId) the
  ## in-flight transfers first, then stop. (See Invariant 7; stop never force-cancels.)

# --- cancellation: uniform across client and server transfers ---
proc cancel*(s: TftpSession, id: TransferId)
  ## No-op (emits nothing) for an unknown/stale/already-terminal id.

# --- the pump + drain, in ONE call ---
iterator poll*(s: TftpSession, timeoutMs: int = 0): Event
  ## Pump the dispatcher AND yield the events drained this tick. 0 = non-blocking
  ## (GUI timer tick); >0 = block up to N ms (CLI). MUST NOT raise (Invariant 2).
  ## Dequeue-per-yield: `break`ing out of the loop leaves undrained events queued for
  ## the next call — no event is ever lost by an early break. Calling poll from within
  ## a poll iteration is a programmer error (asyncdispatch is not re-entrant).

# --- orderly shutdown ---
proc close*(s: TftpSession)
  ## Cancel all client transfers, stop all servers, close all owned transports/listeners.
  ## Resources are released only as the drain proceeds: the frontend MUST keep pumping
  ## `poll` until it yields nothing, then drop the ref. Dropping the ref without draining
  ## does NOT free sockets immediately — in-flight futures hold a ref to the session, so
  ## it stays alive (holding OS sockets) until every transfer times out (up to
  ## timeout×retries seconds). `=destroy` calls `close` but can only reclaim an *idle*
  ## session; it cannot force cleanup of active transfers without a pump (Invariant 6).

# --- blocking convenience for the single-workload CLI ---
proc waitTransfer*(s: TftpSession, id: TransferId): TransferResult
  ## Loops on poll() until `id` reaches its terminal event. Events for OTHER ids are
  ## buffered (not dropped) and re-delivered on the next poll() after this returns, so a
  ## server's evServerStopped is never swallowed (see Invariant 4/8). Safe to interleave
  ## with a running server.
proc waitServer*(s: TftpSession, id: ServerId)
  ## Loops on poll() until `id` reaches a terminal event — either evServerStopped OR
  ## evServerStartFailed. Non-target events are buffered, as in waitTransfer.
```

### Event model

Events are a Nim variant with **exactly one shape per concept**. Round 2 collapsed the former
twelve kinds into eight: there is **one** transfer family (`evTransfer*`), used for both client- and
server-initiated transfers — the hoisted `srvId` already tells the frontend which server (if any) a
transfer belongs to, so a parallel `evServerTransfer*` family encoded the same fact twice. The two id
fields live **outside** the discriminant so they are always readable without a prior `case` check.

```nim
type
  EventKind* = enum
    evTransferStarted, evTransferProgress, evTransferComplete, evTransferError, evTransferLog,
    evServerStarted, evServerStartFailed, evServerStopped, evServerLog

  # ONE progress payload, used identically for client and server transfers.
  TransferSnapshot* = object
    bytes*:      int64            # bytes transferred so far
    total*:      Option[int64]    # none until/unless tsize is known — no -1 sentinel
    blocksize*:  int              # 0 until handshake; from OACK
    windowsize*: int              # 0 until handshake; from OACK
    direction*:  TransferDirection
    mode*:       TransferMode      # octet / netascii
    startedAt*:  float            # epochTime() at handshake completion (speed/ETA)

  Event* = object
    xfrId*: TransferId          # the transfer this concerns; NoTransfer for server-lifecycle/log
    srvId*: ServerId            # NoServer for a pure client transfer; else the owning server
    case kind*: EventKind
    of evTransferStarted, evTransferProgress, evTransferComplete, evTransferError:
      # Nim forbids repeating a field name (`snap`) across separate `of` branches,
      # so the four transfer kinds share ONE branch. snap is the current/last-known
      # position (last-known is useful for resume/report UX on error); errorCode/
      # errorMsg are meaningful for evTransferError only (zero-valued otherwise).
      snap*:      TransferSnapshot
      errorCode*: int
      errorMsg*:  string
    of evTransferLog:           # per-transfer diagnostics (retransmit/timeout); gated by minLogLevel
      xLevel*: LogLevel
      xMessage*: string
    of evServerStarted:
      boundAddr*: string        # actual bound address/port — lets ServerConfig.port = 0 (OS-assigned) work
      boundPort*: int
    of evServerStartFailed:
      startErr*: string
    of evServerLog:
      sLevel*: LogLevel
      sMessage*: string
    of evServerStopped:
      discard

# Free helper (lives in format.nim, NOT a method on Event): no sentinel in the contract.
proc fraction*(bytes: int64, total: Option[int64]): Option[float] =
  total.map(proc(t: int64): float = (if t > 0: bytes.float / t.float else: 0.0))
```

A server-initiated transfer is just an `evTransfer*` event whose `srvId != NoServer`. The session maps
`server.nim`'s internal `TransferInfo` into `TransferSnapshot` at the enqueue boundary, so `TransferInfo`
stays private and can gain bookkeeping fields without widening the public API.

`format(ev)` is intentionally **absent**: display strings are locale/toolkit-specific and every frontend
overrides them. Events carry raw fields; the CLI and GUI render with the existing `format.nim` helpers.
`activeTransfers` is **absent**: the frontend derives the live set from `evTransferStarted` / terminal
events (the event stream is the single source of truth; a synchronous snapshot would race it and carry no
cancellable id anyway).

Usage — the entire GUI integration (oyamel `wkTimer` or NiGui repeating timer):

```nim
for ev in session.poll(0):
  case ev.kind
  of evTransferStarted:
    if ev.srvId != NoServer: incomingList.add(ev.xfrId)     # server-side
    else:                    modal.blocksize = ev.snap.blocksize
  of evTransferProgress:
    let f = fraction(ev.snap.bytes, ev.snap.total)
    if f.isSome: bar.value = f.get else: bar.setIndeterminate()
  of evTransferComplete, evTransferError: status.text = render(ev)
  of evServerLog:         logArea.append(ev.sMessage)
  of evServerStarted:     status.text = "Listening on " & ev.boundAddr & ":" & $ev.boundPort
  of evServerStartFailed: status.text = "Start failed: " & ev.startErr
  else: discard
```

CLI: `let res = session.waitTransfer(session.startTransfer(req))`.

## Invariants (the contract reviewers attacked in rounds 1–2)

1. **Pump-or-nothing.** Nothing progresses unless the frontend iterates `poll()`. Single-threaded.
2. **Never-throw (Facet C) — by mechanism, not hope.** Three distinct escape paths are each closed:
   - *Async bodies:* the session drives every internal future with `future.addCallback(...)` capturing
     success/failure and enqueuing the corresponding event; it **never** uses `asyncCheck` inside the
     boundary (which would re-raise through `poll()`). `server.run()` is likewise driven so a raising
     `handleRequest` becomes `evTransferError`, not a `poll()` raise.
   - *Synchronous pre-launch:* `startTransfer`/`startServer` allocate the id **first**, then run all
     fallible setup (validation, closure construction) inside a `try/except` that, on any exception,
     enqueues `evTransferError`/`evServerStartFailed` against the already-allocated id and returns it
     normally. addCallback covers only code inside a future; this covers the code before one exists.
   - *The iterator itself:* the `poll` body wraps its `asyncdispatch.poll(timeoutMs)` call and its
     event-drain loop in `try/except`, converting any escape (including the empty-dispatcher case below)
     into "yield nothing this tick." The dispatcher is **empty** when no fd/timer is registered (all
     transfers done); `asyncdispatch.poll` raises `ValueError` in that state, so the iterator guards with
     `if hasPendingOperations() or timeoutMs > 0:` before calling it — the same guard the wireharness
     `driveAll` already uses. The only escapes permitted past the boundary are programmer errors (e.g. an
     id from another session, re-entrant poll) — never I/O, decode, OACK, bind, or send failures.
3. **Terminal events bypass the bound.** The queue coalesces **progress** events per id under
   backpressure, but `evTransferComplete` / `evTransferError` / `evServerStopped` / `evServerStartFailed`
   are stored unbounded and always delivered. The accumulation is bounded in practice by the number of
   concurrent transfers (itself ≤ Σ `maxConcurrent` over active servers, plus client transfers); a
   frontend that drains every tick sees at most that many undelivered terminals. A frontend that stalls
   its own event loop for many seconds is the cause of, and the fix for, any growth — the library does
   not silently drop terminals to protect against a frozen UI.
4. **Exactly one terminal per `TransferId`.** A transfer emits `evTransferStarted` (≤1) then exactly one
   of `evTransferComplete` / `evTransferError`. There is **no** cancel/complete race: execution is
   single-threaded, so when `cancel(id)` runs the transfer's future is either already resolved (cancel is
   a no-op; the standing terminal is unchanged) or still pending (cancel resolves it as cancelled,
   emitting one `evTransferError`). No session-level double-terminal guard is required; single-threaded
   sequencing enforces it structurally.
5. **Id state freed at drain.** Per-id state is retained until its terminal event is drained by the
   frontend, then released. Operations on a stale/foreign/already-drained id emit nothing (no crash). Ids
   are per-session, monotonic `distinct uint32`, allocated from **1** (`0` = `NoTransfer`/`NoServer`
   sentinel); on the (practically unreachable) 2³² wrap the allocator skips 0. Because state is freed at
   drain well before 4 billion ids elapse, reuse collisions cannot occur.
6. **Caller never touches transports.** Production factories construct and own `Transport`/`UdpListener`
   (deriving IPv6 via `isIPv6` on host/`listenAddr`); the session closes them on terminal events and in
   `close`. There is no public way to pass one in. `=destroy` calls `close` as a convenience for an
   **idle** session only — while in-flight futures hold a session ref the refcount never reaches zero, so
   a frontend that drops the ref mid-transfer without pumping leaks until those transfers time out. This
   is documented on `close`, not presented as an automatic safety net.
7. **One server loop, graceful stop.** `startServer` drives `server.run()` (extended in slice 0, not
   copied); the GUI's duplicate is deleted, so host-access and "Server busy" rejection apply to every
   frontend. `stop` refuses new requests and lets in-flight transfers reach their natural terminal
   (complete or timeout-error) — it does **not** force-cancel them; expedited shutdown is `cancel` per
   transfer, then `stop`.
8. **Exactly one terminal per `ServerId`.** The first event for a `ServerId` is either `evServerStarted`
   (bind ok) or `evServerStartFailed` (bind failed, terminal — no further events). After a successful
   start, `evServerStopped` is the sole terminal, emitted once every in-flight handler has terminated
   following `stop`. `waitServer` therefore exits on `evServerStopped` **or** `evServerStartFailed`.

## Dependency Strategy

- **Ports & adapters:** UDP via `Transport`/`UdpListener` closure structs, injected through the
  `newSession` factories. The per-transfer data socket (`newUdpTransport(0)` inside the server) is
  injected via a `transferFactory` seam on `TftpServer` (slice 0b) so a full server transfer can run
  entirely in-memory. Production factories construct real ones internally and own their lifetime.
- **In-process:** session state, id allocation, event queue — pure, single-threaded, no atomics.
- **Local-substitutable:** file I/O stays internal to the session (TFTP *is* file transfer). The internal
  file/netascii seam is #13's sources/sinks — out of scope here.

## Stages and `/tdd`-sized slices

Each slice leaves the suite green and is testable against `tests/wireharness.nim` (extended in slice 0)
plus temp dirs. Round 1 inserted the `server.nim` seams that slices 4–6 silently depended on and locked
the never-throw mechanism into slice 1; **round 2 split those seams into three genuinely independent
`/tdd` slices (0a/0b/0c)** because they need incompatible RED setups, and added the per-transfer
`transferFactory` seam without which slice 4 cannot run in-memory.

**0a. `server.nim` event-data seams** *(mock `ServerCallbacks` observes; suite green).*
   - Add `totalBytes` + `startedAt` to `TransferInfo`; populate the three constructors that build it
     (`server.nim:302-305` progressCb, `334-337` complete/error) from `xferConfig.totalSize` / a captured
     `epochTime()`.
   - Fire the dead `onTransferStart`. `handleRequest` does **not** know the file size (RRQ size comes from
     `getFileSize` inside `handleRrq`; WRQ size from the negotiated `tsize` inside `handleWrq`), so add an
     `onStart: proc(info: TransferInfo)` hook to `handleRrq`/`handleWrq` and fire it post-open / post-OACK
     with `totalBytes` populated — not from `handleRequest`, where it would always be −1.
   - Test: a `ServerCallbacks` mock asserts `onTransferStart` fires once with correct `totalBytes`.

**0b. `server.nim` cancel + injection seams** *(wire drop + cancel assertion; suite green).*
   - Add `cancelCheck: CancelCheck = nil` to `handleRrq`/`handleWrq` (the type already exists at
     `transfer.nim:28`, and `sendBlocks`/`recvBlocks` already accept it). In `handleWrq`, **OR** it with
     the existing `cancelOnWriteError` (`server.nim:239`) into a `combinedCancel` — the same pattern as
     `api.nim:90-92` — rather than replacing it.
   - Add a `transferFactory: proc(port: int): Transport` field to `TftpServer` (default `newUdpTransport`)
     and route the per-transfer socket sites (`server.nim:280,292`) through it, so slice 4 can inject an
     in-memory transport for the data channel.
   - Defensive never-raise wrapping of the server-loop reject paths that raise *inside* `run()`:
     `newUdpTransport(0)` + `sendError` at `server.nim:288,371-372,378-379`. (Full `handleRequest`
     never-raise is proven in slice 4 via addCallback + the failing transport from 0c.)

**0c. Wireharness substrate.** `makeListener` (a `UdpListener` backed by a deque, mirroring
   `makeTransport`) and a `failingSend` `Transport` variant whose `send` raises `OSError` after N
   deliveries (needed to test the never-raise property in slices 2/4). Pure test code.

1. **Session skeleton + client transfer (never-throw mechanism locked here).** `newSession` (with
   factories), `startTransfer`, `poll` iterator (with the empty-dispatcher guard + top-level try/except of
   Invariant 2, dequeue-per-yield), `evTransferStarted/Progress/Complete`. Internal futures use
   `addCallback`+error-capture — **never `asyncCheck`** — and synchronous pre-launch is wrapped, so all
   three escape paths of Invariant 2 are baked in from the first slice. Boundary test: drive a GET/PUT over
   the wire (pump `poll(0)` in a step-capped loop), assert the drained event sequence; also assert an idle
   `poll(0)` on a fresh session yields nothing and does not raise.
2. **Never-throw property + cancel.** Property test: feed arbitrary handshake garbage (reuse `t_props`
   byte strategies) **and** a `failingSend` transport (from 0c); pumping `poll` must terminate with
   exactly one terminal event and never raise. Add `cancel`; test cancel→terminal and that cancel on an
   already-resolved id is a no-op (Invariant 4).
3. **Bounded, coalescing event queue.** Per-id progress coalescing; terminal events bypass the bound
   (Invariant 3). Test: flood progress without draining; assert coalescing + terminal survival even at
   `maxConcurrent` simultaneous completions; assert an early `break` mid-drain re-delivers the rest next
   `poll` (dequeue-per-yield).
4. **Server via the one loop + events (Facet B).** `startServer` drives `server.run()` with the slice-0
   seams; `handleRequest` is driven by `addCallback` (replacing `asyncCheck`), translating
   `ServerCallbacks` + `Logger` into `evTransfer*` (with `srvId` set) and `evServerLog` events;
   `evServerStarted` carries the actual bound addr/port; `evServerStartFailed` on bind failure;
   `stop`→`evServerStopped` after in-flight drain (Invariants 7–8). Boundary test (uses `makeListener` +
   injected `transferFactory`): start→`evTransferStarted(srvId)→…Progress→…Complete`→stop→stopped; a
   `failingSend` variant proves `handleRequest` never re-raises through `poll`.
5. **Per-transfer server cancel (Facet D-ops).** The session issues a `TransferId` per server transfer
   (from `onStart`) and registers its slice-0b `cancelCheck`; `cancel(id)` reaches it. Test: two
   concurrent server transfers, cancel one, assert the other completes and the cancelled one emits
   `evTransferError`; and a concurrent `stop` with two in-flight transfers emits one `evServerStopped`
   after both terminals.
6. **Config/progress ergonomics (Facet D-payload).** `fraction(bytes, Option[int64])` helper; session
   requests `tsize` by default for GET and stamps it from the local file stat for PUT (no engine change —
   `engine.nim` already supports it), so `total` is `some` from the first event; enum-ify `checksumMode`
   (`csNone`/`csMd5`/`csSha256`) in `server_config` — **includes** `server.nim:60,62` (the
   `generateChecksum` signature + `mode == "md5"` compare) and `server.nim:169`, plus **`chapulin.nim`**
   where line 139 must **parse** the CLI string to the enum (not a rename), and the `t_server.nim`
   checksum test — all in the same slice so the suite stays green.
7. **Port CLI + NiGui onto the session.** CLI imports shrink to `api` (+ `tftp_uri`). GUI deletes threads,
   channels, atomics, the 50 ms pump, and the duplicated loop; its server panel handles `evTransfer*`
   (with `srvId`) for per-transfer progress, not just `evServerLog`. `--notify` rings the bell on
   `evTransferComplete` with `srvId != NoServer` (a **structural** trigger, replacing the fragile
   `" OK " in msg` log string-match at `chapulin.nim:236`). Proves the seam while NiGui still exists, so
   the later oyamel port (#4) touches only widget code.
8. **Remove dead surface.** Delete `executeTransfer`, `TransferCallbacks`, direct `Logger` /
   `ServerCallbacks` exposure; delete the `t_api.nim` callback-plumbing tests (superseded by
   event-sequence assertions).

## Testing Strategy

- **Substrate:** `tests/wireharness.nim` is the mock network. Slice 0c adds `makeListener` (full server
  can be driven) and a `failingSend` transport (never-raise property); #15 is **not** a blocker. Tests
  pump `poll(0)` in a step-capped loop (the harness's deque is in-memory, so `poll(timeoutMs>0)` would
  block on the OS poller and hang — `poll(N>0)` with N>0 is for production frontends only). The idle-poll
  guard (Invariant 2) is itself under test.
- **New tests** (`t_session.nim`): start→progress→complete; cancel→terminal and cancel-after-resolve
  no-op; **close() mid-transfer** emits one terminal per active id then quiesces; server start→request
  events→stop→`evServerStopped`; **bind failure→`evServerStartFailed` and `waitServer` exits on it**;
  **concurrent in-flight `stop`** yields a single `evServerStopped` after all terminals; concurrent
  transfers produce correctly-id-tagged interleaved events; queue coalescing keeps terminal events and
  early-break re-delivers; the Facet-C never-throw property over garbage handshakes **and** a failing
  transport, on both client and server paths.
- **Deleted:** `t_api.nim` callback-plumbing tests.

## Out of scope (explicitly deferred)

- **#14** (session-establishment primitive) and **#13** (sources/sinks + real netascii) are refactors
  *beneath* this API. This RFC builds on the engine as-is (the slice-0 audit confirms the never-throw
  boundary is achievable without them); they land independently and the session surface does not change.
- **Netascii wiring.** `src/chapulin/netascii.nim` (`toNetascii`/`fromNetascii`) exists but is **orphaned**
  — no production module imports it, so `--mode=netascii` sets the packet mode without applying the byte
  transform. Wiring it is #13's sources/sinks. Slice 7 must **not** silently preserve the broken path:
  carry a `TODO(#13)` on the `--mode=netascii` CLI branch so the latent bug is visible, not laundered
  through the new API.
- **#15** mocknet beyond what `wireharness.nim` + slice-0c `makeListener`/`failingSend` provide.
- **oyamel widget code** (#4) — slice 7 stops at proving the seam with NiGui.

## Round-1 decisions log

Applied directly (clear-best): never-throw as a mechanism (addCallback, not asyncCheck); new server-seam
prerequisite slice; `poll`+`events` collapsed into one iterator; test injection via `newSession`
factories; uniform `TransferId` for server transfers (`activeTransfers` removed); concrete `Event`
case-object with ids hoisted, `format` removed, `fraction`→`Option`; new `evTransferStarted` /
`evServerStartFailed` / `TransferInfo` fields; `close*` + `=destroy` discipline; pinned
terminal/id/`stop` semantics.

## Round-2 decisions log

Applied directly (clear-best; four review lenses):

- **Event families unified 12→8** — the parallel `evServerTransfer*` kinds encoded via the discriminant
  what the hoisted `srvId` already encodes; one `evTransfer*` family now serves both, distinguished by
  `srvId != NoServer`. *(design #1, breadth #15, depth #9)*
- **One `TransferSnapshot` payload** replaces the flat-fields-vs-`TransferInfo` split; internal
  `TransferInfo` no longer leaks into the public `Event`. `total`/`tsize` became **`Option[int64]`**,
  removing the −1 sentinel that had merely migrated down from `fraction`. *(design #2–3, depth #9)*
- **Never-throw hardened** for the two paths addCallback misses: the empty-dispatcher `ValueError` (idle
  GUI tick / end of `waitTransfer`) is guarded with `hasPendingOperations()`; the iterator body and
  synchronous pre-launch code are wrapped in `try/except`. *(depth #1–3, feasibility #2,7)*
- **`waitTransfer`/`waitServer` buffer non-target events** instead of dropping them, closing the
  `waitTransfer`-then-`waitServer` deadlock; `waitServer` exits on `evServerStartFailed` too. *(depth #4,
  breadth #16,20, design #5)*
- **Ids 1-based** with `NoTransfer`/`NoServer` constants; wrap skips 0. *(depth #5, design #6)*
- **`close`/`=destroy` reframed** as idle-only reclamation with an explicit "drop-without-drain leaks
  until timeout" warning, not an automatic safety net. Name kept (`close` pairs with `=destroy`; the doc
  comment carries the async-drain protocol). *(depth #6, breadth #12)*
- **`stop` = graceful drain** (run to natural terminal), never force-cancel; expedited stop = `cancel`
  then `stop`. Removes the "(or are cancelled)" ambiguity. New **Invariant 8** (one terminal per
  `ServerId`). *(depth #11, breadth #10–11)*
- **Slice 0 split into 0a/0b/0c** (event-data / cancel+injection / substrate) — three incompatible RED
  setups, not one slice; added the **`transferFactory`** per-transfer-socket seam (without it slice 4
  cannot run in-memory) and a **`failingSend`** harness transport for the never-raise property.
  *(feasibility #3–6,8)*
- **New event fields:** `evServerStarted.boundAddr/boundPort` (OS-assigned ports usable); `direction`/
  `mode` on the snapshot; `startedAt` available on every progress event; new **`evTransferLog`** for
  client-side `--verbose` diagnostics (`minLogLevel` gates only the two log kinds, never structural
  events). *(depth #10, breadth #4–7)*
- **Citations corrected & grounded** (verified against source): checksum compare at `server.nim:60,62`
  (not 68); `newUdpTransport(0)` at 288/292/371/378; bare handshake sends at 148/217/220; progressCb
  constructor 302-305; `t_server.nim` (not `t_props_server.nim`); CLI imports 10 (not 9);
  `chapulin.nim:139` needs a string→enum **parse**. *(breadth #1–3,9, feasibility #1,9)*
- **Netascii orphan** called out in Out-of-scope with a slice-7 `TODO(#13)` so the migration doesn't
  laser the broken `--mode=netascii` path into the new API. *(breadth #8)*

## Open questions

None. Round 2 resolved the three items round 1 parked: (a) transfer event *kinds* unified (not just ids);
(b) queue policy pinned to "coalesce progress, terminals bypass the bound, bounded by concurrency" with no
magic capacity number; (c) `waitTransfer`/`waitServer` now buffer rather than drop. The RFC is ready for
`/tdd` (slice 0a).
