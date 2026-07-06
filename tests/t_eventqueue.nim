## Direct unit tests for EventQueue (RFC design-bar-closure.md D4).
##
## Constructs EventQueue directly -- no TftpSession/wire boilerplate needed,
## since the type is now a standalone module (src/chapulin/eventqueue.nim).
##
## Run:
##   docker run --rm -v ${PWD}:/app -w /app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r --hints:off tests/t_eventqueue.nim

import std/unittest
import std/options
import ../src/chapulin/eventqueue
import ../src/chapulin/logging
import ../src/chapulin/protocol

proc mkProgress(id: TransferId, bytes: int64): Event =
  Event(xfrId: id, srvId: NoServer, kind: evTransferProgress,
        snap: TransferSnapshot(bytes: bytes, total: none(int64),
                               requested: TransferParams(blocksize: 512, windowsize: 1),
                               effective: some(TransferParams(blocksize: 512, windowsize: 1)),
                               direction: tdGet, mode: tmOctet, startedAt: 0.0))

proc mkLog(msg: string): Event =
  ## M4: evTransferLog was removed (zero producers in src/); this helper now
  ## mints the one remaining log-kind event, evServerLog, so the eviction/
  ## dropped-count tests below still have a log-kind event to push.
  Event(xfrId: NoTransfer, srvId: NoServer, kind: evServerLog,
        sLevel: llInfo, sMessage: msg,
        snap: TransferSnapshot(bytes: 0, total: none(int64),
                               requested: TransferParams(blocksize: 512, windowsize: 1),
                               effective: some(TransferParams(blocksize: 512, windowsize: 1)),
                               direction: tdGet, mode: tmOctet, startedAt: 0.0))

proc mkStarted(id: TransferId): Event =
  Event(xfrId: id, srvId: NoServer, kind: evTransferStarted,
        snap: TransferSnapshot(bytes: 0, total: none(int64),
                               requested: TransferParams(blocksize: 512, windowsize: 1),
                               effective: some(TransferParams(blocksize: 512, windowsize: 1)),
                               direction: tdGet, mode: tmOctet, startedAt: 0.0))

proc mkComplete(id: TransferId): Event =
  Event(xfrId: id, srvId: NoServer, kind: evTransferComplete,
        snap: TransferSnapshot(bytes: 100, total: none(int64),
                               requested: TransferParams(blocksize: 512, windowsize: 1),
                               effective: some(TransferParams(blocksize: 512, windowsize: 1)),
                               direction: tdGet, mode: tmOctet, startedAt: 0.0))

# ---------------------------------------------------------------------------
# R2-M1 (code-review): `inEffect` -- the safe effective-or-requested accessor.
# ---------------------------------------------------------------------------
suite "TransferSnapshot — inEffect":

  test "inEffect returns requested when effective is none (pre-settlement)":
    let requested = TransferParams(blocksize: 512, windowsize: 1)
    let snap = TransferSnapshot(bytes: 0, total: none(int64),
                                requested: requested,
                                effective: none(TransferParams),
                                direction: tdGet, mode: tmOctet, startedAt: 0.0)
    check snap.inEffect == requested

  test "inEffect returns effective once settled (some)":
    let requested = TransferParams(blocksize: 512, windowsize: 1)
    let negotiated = TransferParams(blocksize: 1024, windowsize: 4)
    let snap = TransferSnapshot(bytes: 0, total: none(int64),
                                requested: requested,
                                effective: some(negotiated),
                                direction: tdGet, mode: tmOctet, startedAt: 0.0)
    check snap.inEffect == negotiated

  test "the Option+requested overload matches the same fallback rule":
    let requested = TransferParams(blocksize: 512, windowsize: 1)
    let negotiated = TransferParams(blocksize: 1024, windowsize: 4)
    check inEffect(none(TransferParams), requested) == requested
    check inEffect(some(negotiated), requested) == negotiated

# ---------------------------------------------------------------------------
# O(1) coalescing
# ---------------------------------------------------------------------------
suite "EventQueue — coalescing":

  test "pushing N progress events for one id keeps len at 1":
    var q = initEventQueue(cap = 8192)
    let id = TransferId(1)
    for i in 1 .. 500:
      q.push(mkProgress(id, int64(i)))
      check q.len == 1

    let ev = q.tryPopFirst()
    check ev.isSome
    check ev.get.kind == evTransferProgress
    check ev.get.snap.bytes == 500   # latest value survives
    check q.len == 0

  test "a fresh progress push after the prior one drained mints a new tail key":
    var q = initEventQueue(cap = 8192)
    let id = TransferId(1)
    q.push(mkProgress(id, 1))
    discard q.tryPopFirst()          # drains id's only progress event
    q.push(mkLog("between"))
    q.push(mkProgress(id, 2))        # must NOT coalesce with the drained one

    check q.len == 2
    let first = q.tryPopFirst()
    check first.get.kind == evServerLog
    let second = q.tryPopFirst()
    check second.get.kind == evTransferProgress
    check second.get.snap.bytes == 2

# ---------------------------------------------------------------------------
# tryPopFirst never raises on empty
# ---------------------------------------------------------------------------
suite "EventQueue — tryPopFirst on empty":

  test "tryPopFirst on a fresh empty queue returns none, never raises":
    var q = initEventQueue(cap = 8192)
    var raised = false
    var result: Option[Event]
    try:
      result = q.tryPopFirst()
    except:
      raised = true
    check not raised
    check result.isNone

  test "tryPopFirst returns none again after draining everything":
    var q = initEventQueue(cap = 8192)
    q.push(mkLog("only one"))
    discard q.tryPopFirst()
    var raised = false
    var result: Option[Event]
    try:
      result = q.tryPopFirst()
    except:
      raised = true
    check not raised
    check result.isNone

# ---------------------------------------------------------------------------
# Eviction + dropped-count policy, exercised directly on EventQueue
# ---------------------------------------------------------------------------
suite "EventQueue — bounded eviction + dropped-count":

  test "log events are dropped once the cap is reached; no synthetic warning yet":
    var q = initEventQueue(cap = 3)
    q.push(mkLog("a"))
    q.push(mkLog("b"))
    q.push(mkLog("c"))
    check q.len == 3
    q.push(mkLog("d"))   # cap reached, non-protected: dropped silently
    check q.len == 3

  test "a protected event evicts the oldest logs to make room for both itself and the pending warning (H1: cap is never exceeded)":
    var q = initEventQueue(cap = 3)
    let id = TransferId(1)
    q.push(mkLog("a"))
    q.push(mkLog("b"))
    q.push(mkLog("c"))
    q.push(mkLog("d"))            # cap reached, non-protected: dropped silently (count=1)
    # Now push a protected Started event: room must be reserved for BOTH the
    # Started event itself AND the now-pending dropped-count warning (H1 --
    # the pre-fix code only reserved room for the event, then flushed the
    # warning unconditionally, which is exactly how `len` used to exceed
    # `cap`). That means evicting TWO logs ("a", then "b"; count reaches 3),
    # not just one.
    q.push(mkStarted(id))
    check q.len <= 3   # the load-bearing H1 invariant: never exceeds cap

    var drained: seq[Event]
    while true:
      let ev = q.tryPopFirst()
      if ev.isNone: break
      drained.add ev.get

    # "a" and "b" were evicted (never drained); "c" remains as a log; then
    # the synthetic warning (count=3: "d" dropped + "a","b" evicted); then
    # Started. Cap stays 3 throughout -- never exceeded (H1).
    check drained.len == 3
    check drained[0].kind == evServerLog
    check drained[0].sMessage == "c"
    check drained[1].kind == evServerLog     # synthetic dropped-count warning
    check drained[1].sLevel == llWarn
    check drained[1].sMessage == "dropped 3 events (queue cap)"
    check drained[2].kind == evTransferStarted
    check drained[2].xfrId == id

  test "H1 bounded contract: with no log to evict, protected events are dropped (oldest-first) rather than ever exceeding cap":
    var q = initEventQueue(cap = 2)
    let id = TransferId(7)
    q.push(mkStarted(id))
    q.push(mkComplete(id))
    check q.len == 2
    # Cap already met with two protected events and no log-kind event to
    # reclaim -- a third protected event must still get in. Per the H1
    # bounded contract, room must be reserved for BOTH the new event and the
    # dropped-count warning it triggers; with zero logs to reclaim, that
    # costs two drop-oldest evictions (both id-7 events), never a temporary
    # cap overshoot.
    q.push(mkStarted(TransferId(8)))
    check q.len == 2   # H1: cap is a TRUE ceiling, never exceeded -- not 3

    var drained: seq[Event]
    while true:
      let ev = q.tryPopFirst()
      if ev.isNone: break
      drained.add ev.get

    check drained.len == 2
    check drained[0].kind == evServerLog   # synthetic dropped-count warning
    check drained[0].sLevel == llWarn
    check drained[0].sMessage == "dropped 2 events (queue cap)"
    check drained[1].kind == evTransferStarted
    check drained[1].xfrId == TransferId(8)

# ---------------------------------------------------------------------------
# H1 (code-review, remote DoS): `cap` must be a TRUE absolute ceiling.
#
# Pre-fix, ProtectedKinds events were never evicted, and when the queue was
# full with no log-kind event to reclaim, push() fell through and exceeded
# `cap` -- worse, in a pure-protected-event flood (no log events ever
# pushed) `droppedLogCount` never incremented (it was only bumped on a
# *successful* log eviction), so the synthetic drop-warning never fired
# either: `len` grew strictly +1 per push, unbounded, and silently.
#
# The fixed contract: q.len <= cap holds after EVERY push, always. When the
# queue is full and a protected event needs to get in: evict a log-kind
# event first (as before); if none remains, drop the OLDEST event
# regardless of kind (drop-oldest) -- terminal/start events included. This
# is a deliberate change from the old "protected events are never dropped"
# contract to "bounded -- under queue saturation the oldest event may be
# dropped, terminal events included."
# ---------------------------------------------------------------------------
suite "EventQueue — H1: cap is a true absolute ceiling under protected-event saturation":

  test "flooding ONLY protected events (no log events ever) never exceeds cap, and a dropped-count warning is emitted":
    var q = initEventQueue(cap = 5)
    for i in 1 .. 15:
      q.push(mkStarted(TransferId(i)))
      # The load-bearing assertion: true after EVERY push, not just at the end.
      check q.len <= 5

    var drained: seq[Event]
    while true:
      let ev = q.tryPopFirst()
      if ev.isNone: break
      drained.add ev.get

    check drained.len <= 5   # never exceeded cap, even while draining what's left
    var sawWarning = false
    for ev in drained:
      if ev.kind == evServerLog and ev.sLevel == llWarn:
        sawWarning = true
    check sawWarning   # the coalesced drop-count warning must have been surfaced

# ---------------------------------------------------------------------------
# R2-L1 (code-review): the H1 invariant ("q.len <= cap holds after every
# push, always") is only actually satisfiable if cap >= 2 -- the protected-
# event reservation loop needs room for BOTH the incoming event and its
# possibly-pending coalesced drop-count warning. `initEventQueue` now
# enforces `cap >= 2` as a construction-time precondition (doAssert) rather
# than letting a degenerate cap silently violate the invariant later.
# ---------------------------------------------------------------------------
suite "EventQueue — R2-L1: cap >= 2 precondition":

  test "cap = 0 is rejected at construction":
    var raised = false
    try:
      discard initEventQueue(cap = 0)
    except AssertionDefect:
      raised = true
    check raised

  test "cap = 1 is rejected at construction":
    var raised = false
    try:
      discard initEventQueue(cap = 1)
    except AssertionDefect:
      raised = true
    check raised

  test "cap = 2 (the boundary) is accepted and the H1 invariant holds under protected-event saturation":
    var q = initEventQueue(cap = 2)
    let id = TransferId(7)
    q.push(mkStarted(id))
    q.push(mkComplete(id))
    check q.len == 2
    # A third protected event with no log-kind event to reclaim: per the H1
    # bounded contract, room must be reserved for BOTH the new event and the
    # dropped-count warning it triggers -- with zero logs to reclaim, that's
    # two drop-oldest evictions. Never a temporary cap overshoot.
    q.push(mkStarted(TransferId(8)))
    check q.len <= 2   # the load-bearing invariant: never exceeds cap

# ---------------------------------------------------------------------------
# Cross-kind ORDERING: position-pinned coalescing
# ---------------------------------------------------------------------------
suite "EventQueue — cross-kind ordering":

  test "log-A, progress-B(v1), log-C, progress-B(v2 coalesced), terminal-B drains in position-pinned order":
    var q = initEventQueue(cap = 8192)
    let bId = TransferId(2)

    q.push(mkLog("A"))              # position 0
    q.push(mkProgress(bId, 1))      # position 1 -- B's live progress key
    q.push(mkLog("C"))              # position 2
    q.push(mkProgress(bId, 2))      # coalesces into position 1, does NOT move
    q.push(mkComplete(bId))         # position 3 -- ordinary keyed payload

    check q.len == 4   # NOT 5 -- the second progress coalesced

    var drained: seq[Event]
    while true:
      let ev = q.tryPopFirst()
      if ev.isNone: break
      drained.add ev.get

    check drained.len == 4
    check drained[0].kind == evServerLog
    check drained[0].sMessage == "A"
    check drained[1].kind == evTransferProgress    # B's progress, AT ITS ORIGINAL POSITION
    check drained[1].xfrId == bId
    check drained[1].snap.bytes == 2               # holding the coalesced v2 value
    check drained[2].kind == evServerLog
    check drained[2].sMessage == "C"
    check drained[3].kind == evTransferComplete     # terminal-B last
    check drained[3].xfrId == bId

# ---------------------------------------------------------------------------
# The load-bearing invariant, tested directly:
#   id is a key in progressKey iff id has exactly one un-drained progress
#   event, whose key is progressKey[id].
#
# progressKey itself is private, so the invariant is observed through its
# only externally-visible consequences: (1) a second progress push for the
# same id while the first is still queued coalesces (len unchanged); (2) once
# drained, the id has no "live key" memory -- a subsequent push for the same
# id is a brand new tail entry, not a phantom coalesce target; (3) a
# terminal event for an id never prevents that id from independently getting
# a fresh, un-coalesced progress entry afterward.
# ---------------------------------------------------------------------------
suite "EventQueue — progressKey invariant (observed via push/pop behavior)":

  test "id not yet pushed has no live key: its first progress event mints fresh, alone":
    var q = initEventQueue(cap = 8192)
    let id = TransferId(3)
    q.push(mkProgress(id, 1))
    check q.len == 1

  test "after a terminal for id, a later progress for the SAME id is independent (not coalesced with the terminal)":
    var q = initEventQueue(cap = 8192)
    let id = TransferId(4)
    q.push(mkProgress(id, 1))
    discard q.tryPopFirst()          # progress drained -> id has no live key
    q.push(mkComplete(id))          # terminal: never touches progressKey
    q.push(mkProgress(id, 2))       # id still has no live key (terminal isn't progress) -> fresh key
    check q.len == 2                # terminal + fresh progress, NOT coalesced

  test "two different ids never coalesce with each other":
    var q = initEventQueue(cap = 8192)
    let a = TransferId(10)
    let b = TransferId(11)
    q.push(mkProgress(a, 1))
    q.push(mkProgress(b, 1))
    check q.len == 2
    q.push(mkProgress(a, 2))
    q.push(mkProgress(b, 2))
    check q.len == 2   # each coalesced independently, not cross-id
