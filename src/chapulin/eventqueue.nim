## Session event queue — extracted per RFC design-bar-closure.md D4.
##
## `enqueue` used to inline three concerns directly on `TftpSession.events`
## (a plain `Deque[Event]`): O(n) progress coalescing, a full-deque-rebuild
## bounded eviction, and dropped-count bookkeeping with a synthetic warning
## event. This module gives that logic its own directly-tested type.
##
## Key redirection, not placeholders: every value in `order`/`payload` is a
## real event payload -- there is no marker/placeholder event standing in
## for "not yet coalesced," so nothing here wants to become a case-object
## (the FieldDefect shape the project's never-throw discipline forbids).
## Coalescing is O(1) and position-preserving: a `push` of a progress event
## whose id already has a live key in `progressKey` overwrites `payload[key]`
## in place -- the key keeps its original FIFO position in `order`, which
## *is* the coalesce, not a bolted-on resolution step run at drain time.
##
## Load-bearing invariant (tested directly in tests/t_eventqueue.nim):
##   `id` is a key in `progressKey` iff `id` has exactly one un-drained
##   progress event in the queue, whose key is `progressKey[id]`.
## From it: (1) a progress push after that id's prior progress was already
## drained sees no live key and mints a fresh one at the new tail position
## -- no silent loss; (2) `progressKey` holds only ids with a currently-
## queued progress event, so it is bounded by queue size, not by total
## transfers ever run -- no leak; (3) a terminal event is an ordinary keyed
## payload that never touches `progressKey`.
##
## `popFirst` is deliberately not offered: `std/deques.popFirst` raises
## `IndexDefect` (a Defect that escapes `except CatchableError`) on an empty
## deque. `tryPopFirst` returns `none(Event)` on empty and never raises.
##
## Bounded contract (H1, code-review): `cap` is a TRUE absolute ceiling --
## `q.len <= cap` holds after every `push`, always, with no exception. An
## earlier revision treated `ProtectedKinds` (terminal/start events) as
## never-evict/never-drop, but that made `cap` not actually hard: once the
## queue was full of protected events with no log-kind event left to evict,
## `push` fell through and exceeded `cap` -- and in a flood consisting
## entirely of protected events (e.g. malformed-option RRQ/WRQ packets each
## injecting `evTransferStarted` + `evTransferError`), the synthetic
## drop-count warning (itself a log-kind event) never got a chance to fire
## either, so growth was silent, unbounded, and a remote DoS vector. The
## fix: `push` still evicts a log-kind event first when the queue is full
## (protected events are still *preferred* to survive), but if none remains
## it now drops the OLDEST queued event regardless of kind (drop-oldest) --
## terminal/start events included -- so a protected event can always get in
## without ever exceeding `cap`. This is a deliberate contract change from
## "protected events are never dropped" to "bounded: under sustained queue
## saturation, the oldest event may be dropped, terminal events included."
## All drops (log, progress, or drop-oldest) are coalesced into one counter
## and surfaced via a single synthetic `evServerLog` warning, itself never
## flushed until room for it exists (so the flush can never push `len` past
## `cap` either). See `push`/`flushWarningIfRoom`/`evictOldestAny` and the
## H1 suite in tests/t_eventqueue.nim.
##
## R2-L1 (code-review): the reservation loop in `push` needs room for BOTH
## the incoming protected event and its possibly-pending drop-count warning,
## i.e. it needs `cap >= 2` to be satisfiable. `initEventQueue` enforces this
## with a `doAssert` -- see its doc-comment.

import std/[deques, tables, options]
import logging
import protocol
import coverpragma

type
  EventKind* = enum
    evTransferStarted, evTransferProgress, evTransferComplete, evTransferError,
    evServerStarted, evServerStartFailed, evServerStopped, evServerLog,
    evServerRejected

  TransferDirection* = enum
    tdGet
    tdPut

  TransferId* = distinct uint32
  ServerId*   = distinct uint32

const
  NoTransfer* = TransferId(0)
  NoServer*   = ServerId(0)

proc `==`*(a, b: TransferId): bool {.borrow.}
proc `==`*(a, b: ServerId):   bool {.borrow.}

type
  TransferSnapshot* = object
    ## M5 (code-review): `effective: TransferParams` + `settled: bool` (RFC
    ## design-bar-closure D6) reintroduced exactly the plausible-sentinel
    ## hazard D5 removed for errorCode -- `effective` was always populated
    ## and indistinguishable from `requested` until `settled` flipped,
    ## guarded only by a hand-written doc warning. Collapsed into a single
    ## `effective: Option[TransferParams]`: `none` until the handshake
    ## resolves, `some(params)` once in-effect. `requested`/`effective` share
    ## one structural type (`protocol.TransferParams`) rather than being
    ## duplicated here.
    bytes*:      int64
    total*:      Option[int64]           ## none until tsize negotiated
    requested*:  TransferParams          ## ALWAYS the clamped requested/opening-ask values
    effective*:  Option[TransferParams]  ## none = handshake not yet resolved (client
                                          ## pre-negotiation evTransferStarted); some(params)
                                          ## once in-effect -- server: some(defaults) even for
                                          ## a bare RRQ/WRQ with zero options ("in-effect
                                          ## defaults," still distinguishable from none =
                                          ## not-yet-settled).
    direction*:  TransferDirection
    mode*:       TransferMode
    startedAt*:  float           ## epochTime() at transfer start

  Event* = object
    xfrId*: TransferId
    srvId*: ServerId
    case kind*: EventKind
    of evTransferStarted, evTransferProgress, evTransferComplete, evTransferError:
      ## M2 (code-review): `snap` used to be a field OUTSIDE this `case` --
      ## a true common field, structurally readable on every `EventKind`
      ## including the five server kinds below, where it was always a
      ## meaningless all-zero `TransferSnapshot` (a plausible-sentinel
      ## hazard: nothing stopped a caller from reading `ev.snap.bytes` on
      ## `evServerStarted` and silently getting zero, never a compile error
      ## or Defect -- the exact hazard `TransferSnapshot.effective` was made
      ## `Option` to kill one level down, see that type's doc comment
      ## above). Moved into this `case` arm instead, so `ev.snap` is a
      ## compile error on any of the five server kinds.
      ##
      ## `errorCode`/`errorMsg` join `snap` in this SAME arm rather than a
      ## separate `of evTransferError:` arm -- Nim forbids two different
      ## `case` branches from declaring a field with the same name (even
      ## mutually-exclusive ones), so `snap` cannot live in both an
      ## evTransferError-only arm and a separate Started/Progress/Complete
      ## arm; merging all four `evTransfer*` kinds into one arm is the only
      ## way a single `ev.snap` accessor works uniformly across all of them
      ## (preserving the R2-2 ergonomics: one name, not `snap`/`errSnap`
      ## split by kind). This does NOT reopen a plausible-sentinel hazard:
      ## unlike `snap` on a server kind (no valid transfer-snapshot concept
      ## applies there at all), `errorCode = none` / `errorMsg = ""` on
      ## evTransferStarted/Progress/Complete is not a wrong reading of
      ## meaningless data -- it IS the correct value ("no error").
      snap*:      TransferSnapshot
      errorCode*: Option[TftpErrorCode]  ## RFC design-bar-closure D5: none =
      ## local/transport/decode failure, no peer code (or: not an error
      ## event at all); some(c) = a genuine peer-emitted/decoded
      ## TftpErrorCode on evTransferError. See transfer.nim's
      ## TransferResult.errorCode doc for the full verified-bug rationale.
      errorMsg*:  string  ## "" on evTransferStarted/Progress/Complete (no
      ## error); the failure message on evTransferError.
    of evServerStarted:
      boundAddr*: string
      boundPort*: int
    of evServerStartFailed:
      startErr*: string
    of evServerLog:
      sLevel*:   LogLevel
      sMessage*: string
    of evServerStopped:
      discard
    of evServerRejected:
      ## RFC verification-harness-v2.md A4: the server's accept loop rejected
      ## an inbound request BEFORE a reqId/TransferId was minted (no-available-
      ## port, host-access denial, or maxConcurrent) -- so, unlike every
      ## evTransfer* kind above, this carries the rejected peer's raw address
      ## directly rather than routing through `xfrId` (always `NoTransfer`
      ## here). `rejCode`/`rejMsg` mirror the ERROR packet actually sent to
      ## that peer (see `clientSafeError`, server.nim) -- a structured signal
      ## a session can assert on directly, not a free-text `evServerLog`
      ## substring.
      rejClientHost*: string
      rejClientPort*: int
      rejCode*:       TftpErrorCode
      rejMsg*:        string

  EventQueue* = object
    order:           Deque[int]             ## arrival-ordered keys (FIFO); every key maps to a real payload
    payload:         Table[int, Event]      ## key -> the event (terminals, logs, and progress alike)
    progressKey:     Table[TransferId, int] ## an id's LIVE key iff it has an un-drained progress event
    nextKey:         int                    ## monotonic key mint
    cap:             int                    ## hard cap on total queued events -- q.len <= cap
                                              ## holds after EVERY push, always (H1, code-review).
    droppedLogCount: int                    ## count of events dropped/evicted since the last
                                              ## synthetic warning -- NOT log-only since H1: a
                                              ## drop-oldest eviction of a protected event under
                                              ## saturation counts here too.

proc inEffect*(snap: TransferSnapshot): TransferParams =
  ## The in-effect transfer params: never raises. Pre-settlement (`effective`
  ## is `none`) returns the always-present, already-clamped `requested`
  ## values; once the handshake settles (`some(params)`) returns those. Use
  ## this instead of a bare `snap.effective.get` -- the latter raises
  ## `UnpackDefect` (a Defect, not a `CatchableError`) if read before
  ## settlement.
  snap.effective.get(snap.requested)

proc inEffect*(effective: Option[TransferParams], requested: TransferParams): TransferParams =
  ## Same never-raising fallback rule as `TransferSnapshot.inEffect`, usable
  ## where the effective/requested params haven't been assembled into a
  ## `TransferSnapshot` yet (e.g. mid-transfer local state tracked ahead of
  ## the next snapshot).
  effective.get(requested)

const ProtectedKinds = {evTransferComplete, evTransferError,
                         evServerStopped, evServerStartFailed, evTransferStarted,
                         evServerRejected}
  ## H1 (code-review, remote DoS): this used to mean "never dropped, never
  ## evicted to make room" -- but `cap` was consequently NOT a true ceiling:
  ## when the queue was full of protected events with no log-kind event to
  ## reclaim, push() fell through and exceeded `cap`, and in a pure
  ## protected-event flood the synthetic drop-warning (itself a log-kind
  ## event) never even got a chance to fire, so growth was silent and
  ## unbounded. The bounded contract now: ProtectedKinds events are
  ## PREFERRED to survive (a log-kind event is always evicted first to make
  ## room for one), but under sustained saturation with no log-kind event
  ## left to reclaim, the OLDEST queued event -- protected or not -- is
  ## dropped instead of ever exceeding `cap`. See `push`.
  ##
  ## M3 (code-review): `evServerRejected` is a terminal-class structured
  ## signal akin to `evTransferError` -- a server-side accept-loop rejection
  ## carrying `rejClientHost/rejClientPort/rejCode/rejMsg`. Before this fix
  ## it fell into the droppable branch (`push`'s `notin ProtectedKinds`
  ## check) and, under the exact sustained-maxConcurrent saturation scenario
  ## the reject feature exists to observe, was silently discarded and
  ## folded into the generic coalesced "dropped N events" warning, losing
  ## its structured payload. It is now preferred to survive like every
  ## other terminal/start event in this set, subject to the same
  ## drop-oldest bound under sustained saturation -- see `push`.

const LogKinds = {evServerLog}
  ## The only kind bounded eviction is allowed to reclaim.

proc initEventQueue*(cap: int): EventQueue =
  ## `cap` is the hard cap on total queued events (production: MaxQueuedEvents).
  ##
  ## Precondition: `cap >= 2` (R2-L1, code-review). `push`'s protected-event
  ## reservation loop needs room for BOTH the incoming event and its
  ## possibly-pending coalesced drop-count warning -- at cap 0 or 1 that
  ## reservation is unsatisfiable, the give-up branch is reached, and
  ## `flushWarningIfRoom`/`rawAdd` then append unconditionally, so
  ## `q.len <= cap` (the invariant `push` documents) would be false. `cap` is
  ## always a compile-time constant in this codebase (MaxQueuedEvents = 8192),
  ## so a degenerate cap is a programming error, not attacker-reachable --
  ## caught here at construction rather than silently violated later.
  doAssert cap >= 2, "EventQueue requires cap >= 2 (room for an event plus its coalesced drop-warning)"
  EventQueue(
    order:           initDeque[int](),
    payload:         initTable[int, Event](),
    progressKey:     initTable[TransferId, int](),
    nextKey:         0,
    cap:             cap,
    droppedLogCount: 0
  )

proc len*(q: EventQueue): int =
  q.order.len

proc hasLiveProgressKey*(q: EventQueue, id: TransferId): bool =
  ## Introspection seam (RFC verification-harness.md D6/slice 6): true iff
  ## `id` currently has a live (un-drained) progress event queued -- the
  ## externally-observable form of the `progressKey` invariant documented
  ## above. Read-only; exposes no mutation surface over `progressKey`.
  q.progressKey.hasKey(id)

proc pendingDropCount*(q: EventQueue): int =
  ## Introspection seam (RFC verification-harness.md D6/slice 6): the
  ## coalesced drop/eviction count still pending a synthetic warning flush
  ## (see `droppedLogCount`/`flushWarningIfRoom`). Read-only. Named apart
  ## from the private `droppedLogCount` field (not re-using that name) so
  ## there's no same-name field/proc shadowing to reason about.
  q.droppedLogCount

proc tryPopFirst*(q: var EventQueue): Option[Event] {.cover.} =
  ## Never raises (unlike `deques.popFirst` on an empty deque). Pops the
  ## front key, returns its payload, and -- in the same step -- clears
  ## `progressKey[id]` if that key was id's live progress key. One code
  ## path owns both structures' consistency.
  if q.order.len == 0:
    return none(Event)
  let key = q.order.popFirst()
  let ev  = q.payload[key]
  q.payload.del(key)
  if ev.kind == evTransferProgress and q.progressKey.getOrDefault(ev.xfrId, -1) == key:
    q.progressKey.del(ev.xfrId)
  some(ev)

proc rawAdd(q: var EventQueue, ev: Event) =
  ## Unconditionally mints a new key and appends at the tail. Callers are
  ## responsible for coalescing/bounding decisions before reaching here.
  let key = q.nextKey
  inc q.nextKey
  q.order.addLast(key)
  q.payload[key] = ev
  if ev.kind == evTransferProgress:
    q.progressKey[ev.xfrId] = key

proc evictOneLog(q: var EventQueue): bool =
  ## Evicts the first log-kind payload (in FIFO order) to make room for a
  ## protected event. Rebuilds `order` (Deque has no arbitrary-position
  ## remove) skipping the evicted key; `payload`/`progressKey` are updated
  ## in the same pass. Returns true iff something was evicted.
  var newOrder = initDeque[int]()
  var evicted = false
  for key in q.order:
    if not evicted and q.payload[key].kind in LogKinds:
      evicted = true
      q.payload.del(key)
      # A log-kind event is never evTransferProgress, so it never holds a
      # progressKey entry -- no progressKey bookkeeping needed here.
    else:
      newOrder.addLast(key)
  if evicted:
    q.order = newOrder
  evicted

proc evictOldestAny(q: var EventQueue): bool =
  ## H1 last-resort eviction: unconditionally evicts the single oldest
  ## queued event, regardless of kind (protected kinds included). Only
  ## reached once evictOneLog has already failed (no log-kind event left to
  ## reclaim) and the queue is still at/over cap. Returns true iff something
  ## was evicted (false only when the queue is already empty).
  if q.order.len == 0:
    return false
  let key = q.order.popFirst()
  let victim = q.payload[key]
  q.payload.del(key)
  if victim.kind == evTransferProgress and q.progressKey.getOrDefault(victim.xfrId, -1) == key:
    q.progressKey.del(victim.xfrId)
  true

proc flushWarningIfRoom(q: var EventQueue) =
  ## Emits the single coalesced dropped-count synthetic warning iff one is
  ## pending AND there is already a free slot for it -- this is the H1 fix
  ## for the old code's unconditional, cap-unchecked flush (the bug that let
  ## the warning itself push `len` past `cap`). If there is no room yet, the
  ## warning stays pending (count keeps accumulating, nothing is lost) and
  ## is retried on a later push.
  if q.droppedLogCount > 0 and q.order.len < q.cap:
    let n = q.droppedLogCount
    q.droppedLogCount = 0
    q.rawAdd(Event(xfrId: NoTransfer, srvId: NoServer, kind: evServerLog,
                   sLevel: llWarn,
                   sMessage: "dropped " & $n & " events (queue cap)"))

proc push*(q: var EventQueue, ev: Event) {.cover.} =
  ## Coalesce (O(1), position-preserving), then bound + evict, then flush
  ## any pending dropped-count synthetic warning, then append.
  ##
  ## H1 (code-review, remote DoS): `q.len <= q.cap` holds after EVERY push,
  ## always -- including the warning-flush's own rawAdd, which used to be
  ## unconditional and could itself push `len` past `cap`.
  if ev.kind == evTransferProgress and q.progressKey.hasKey(ev.xfrId):
    q.payload[q.progressKey[ev.xfrId]] = ev   # coalesce: latest wins, position kept
    return

  if ev.kind notin ProtectedKinds:
    # Droppable kind (log/progress): never evicts anything else to make
    # room for itself -- if there's no room once any pending warning has
    # had its opportunity to flush, ev itself is what gets dropped.
    flushWarningIfRoom(q)
    if q.order.len >= q.cap:
      inc q.droppedLogCount
    else:
      q.rawAdd(ev)
    return

  # Protected kind: guaranteed to get in. Reserve room for [ev] and, if a
  # warning flush is (or becomes) pending, for that too -- recomputed every
  # iteration since an eviction performed here can itself be what makes a
  # warning newly pending (droppedLogCount 0 -> >0 mid-loop).
  while true:
    let needed = 1 + (if q.droppedLogCount > 0: 1 else: 0)
    if q.order.len + needed <= q.cap:
      break
    if q.evictOneLog():
      inc q.droppedLogCount
    elif q.evictOldestAny():
      # Drop-oldest: no log-kind event left to reclaim, so the oldest
      # queued event is dropped regardless of kind -- terminal/start events
      # included. This is the deliberate contract change (H1): bounded,
      # not "protected events never dropped."
      inc q.droppedLogCount
    else:
      break   # defensive only: with initEventQueue's cap >= 2 precondition
              # this can't actually happen. evictOldestAny only fails on an
              # empty queue, and an empty queue always satisfies the room
              # check above first (needed <= 2 <= cap), so this branch is
              # unreachable in practice -- it stays as a fallback rather than
              # an infinite loop if that precondition is ever weakened.
  flushWarningIfRoom(q)
  q.rawAdd(ev)
