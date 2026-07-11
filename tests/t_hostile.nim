## Hostile-session PAYLOAD injection (RFC verification-harness.md D8a, slice 7).
##
## Drives a live sendBlocks (server/peer side) <-> recvBlocks (client/victim
## side) exchange over the in-memory Wire harness (tests/wireharness.nim),
## using proptest's `stateful`/`StateMachine` harness (`_deps/proptest/src/
## proptest/stateful.nim`) to inject forged/garbage DATA/ACK/ERROR packets
## (attacker-chosen block numbers, truncated/oversized/malformed-opcode
## bytes) into the SAME source TID mid-transfer.
##
## Invariant under test: the session (transfer.nim's real parse/dispatch
## loop, exercised through its actual async entry points, `sendBlocks`/
## `recvBlocks`) never raises a Nim Defect. It MAY legitimately abort the
## transfer via its normal CatchableError / `TransferResult(success: false)`
## path -- that is the documented never-throw contract (SECURITY.md), not a
## finding. A Defect escaping IS the finding.
##
## No manual Defect bookkeeping is needed here: proptest's engine
## (`engine/eval.nim`'s `evalReplay`) already wraps strategy generation in
## `except Defect` and reports it as a falsification. Because `stateful`'s
## generated strategy (`stateful.nim`) runs every rule's `execute` AND the
## `StateMachine.invariant` hook *inside* `sm.initial.run(src)` /
## `rule.runStep`, any Defect raised while pumping the dispatcher below
## propagates straight out through that call chain into `evalReplay` --
## this property only has to avoid swallowing it, not catch it itself.
##
## D8a scope: PAYLOAD injection only, same source TID ("peer", 0 -- the
## fixed address `wireharness.makeTransport`'s `doRecv` always reports).
## Off-TID / wrong-source-address injection is D8b, below.
##
## R1-7 (code-review finding, scope decision): D8 as written in the RFC names
## `sendBlocks`/`recvBlocks`/`handleRrq`/`handleWrq` as the exchange to drive
## hostile traffic into. This file drives only `sendBlocks`/`recvBlocks` --
## i.e. the post-negotiation DATA phase -- never `handleRrq`/`handleWrq`
## themselves (the RRQ/WRQ + OACK negotiation phase). Extending this harness
## to negotiation would mean building a second, materially different
## state-machine target: `handleRrq`/`handleWrq` need a REAL client
## counterpart that speaks the request+OACK dance (`engine.getFile`/
## `putFile`, per `tests/t_props_server.nim`'s pattern), and -- unlike the
## pure in-memory `sendBlocks`/`recvBlocks` pairing here -- `handleRrq` reads
## and `handleWrq` writes real files, so a stateful property over it needs
## real per-example disk setup/teardown (`createDir`/`writeFile`/cleanup),
## which is exactly the cost this file's own top-of-file design note (above
## the `HostilePayload` const) says was deliberately avoided to keep ~200
## examples x up to 50 steps fast. That is a new slice's worth of harness
## plumbing, not a same-file extension, so it is deliberately NOT done here
## -- see SECURITY.md's Verification section for the documented scope
## narrowing and README.md/this file's own scope notes for the same.
##
## Run:
##   pwsh scripts/dev-test.ps1 -Only @('t_hostile')

import std/[asyncdispatch, unittest]
import proptest
import ../src/chapulin/protocol
import ../src/chapulin/transfer
import ./wireharness
import ./fuzzsupport

# ---------------------------------------------------------------------------
# A fixed, small, in-memory transfer -- no file I/O, so ~200 stateful
# examples x up to 50 steps each stay fast and the generators only need to
# stress the wire, not disk setup/teardown.
#
# R1-1 fix (code-review finding cluster): the payload used to be 20 bytes (3
# blocks), which -- combined with the old 20-tick `pumpAndSurface` budget --
# let the ENTIRE transfer (all 3 blocks plus the final-ACK dally) finish
# inside the very first invariant call, before any inject rule had ever
# fired (`stateful`'s `invariant` runs once on the initial state BEFORE any
# rule, then after each rule -- see `proptest/stateful.nim`). Every injected
# packet therefore landed in the post-transfer dally epilogue, never a live
# DATA/ACK window. `HostilePayloadLen` is now large enough, combined with
# `pumpAndSurface`'s shrunk per-call tick budget below, that completion
# genuinely spans many invariant calls -- i.e. many rule-firing
# opportunities -- instead of one.
# ---------------------------------------------------------------------------

const
  HostileBlocksize = 8
  HostilePayloadLen = 172
    ## 21 full blocks of 8 bytes + a final short block of 4 (172 = 21*8 + 4).

proc mkHostilePayload(): seq[byte] =
  result = newSeq[byte](HostilePayloadLen)
  for i in 0 ..< result.len: result[i] = byte((i mod 250) + 1)

let HostilePayload = mkHostilePayload()

# ---------------------------------------------------------------------------
# R1-1/R1-3 anti-vacuity instrumentation. Module-level (not per-`HostileState`)
# because these claims are about the RUN as a whole, not any single generated
# example: a short/early-terminating example legitimately may inject nothing
# live (see the file's pre-existing note, below, on a 0-step example never
# injecting anything) -- these counters accumulate across every example the
# property below generates, and the assertion is checked once, after the
# `property` has run all its examples ("by end of run", not per-example).
#
# R2-4 code-review finding: the three `var int` counters below used to be
# hand-rolled directly. `VacuityCounter`/`note`/`assertFired`
# (fuzzsupport.nim) now factor the storage + the post-property `check
# count > 0` boilerplate into one shared, minimal helper -- WHEN/WHERE each
# counter is incremented (the liveness-gated call sites below, and the
# `inLiveDataPhase` predicate they depend on) is completely unchanged; only
# the storage type and the final assertion's spelling moved.
# ---------------------------------------------------------------------------

var d8aLiveInjections = VacuityCounter()
  ## D8a (R1-1): incremented by an inject rule ONLY when, at injection time,
  ## the DATA/ACK exchange is still genuinely in flight -- see
  ## `inLiveDataPhase` (keyed on the SENDER future, `serverFut`/sendBlocks,
  ## never the dally-parked receiver). A packet injected then has a real
  ## chance of landing in a live window, not just the post-transfer dally
  ## epilogue.

var d8bLiveInjections = VacuityCounter()
  ## D8b (R1-3) counterpart to `d8aLiveInjections`, over the off-TID rules.

var d8bBounceTotal = VacuityCounter()
  ## D8b (R1-3): accumulates `final.w.aBounced + final.w.bBounced` (an
  ## off-TID `Transport.send` -- i.e. `recvOnce`'s TID-lock ERROR-bounce
  ## reply actually firing) across every example. Proves the off-TID
  ## property isn't vacuously true because every injected off-TID packet
  ## happened to arrive after both transfers had already finished (nothing
  ## left running to ever call `recvOnce` and hit the mismatch arm).

proc hostileReadData(blockNum: uint16, blocksize: int): seq[byte] =
  let start = (int(blockNum) - 1) * blocksize
  if start < 0 or start >= HostilePayload.len: return @[]
  let stop = min(start + blocksize, HostilePayload.len) - 1
  HostilePayload[start .. stop]

proc hostileOnData(blockNum: uint16, data: seq[byte]) =
  discard  # victim side -- content is not asserted, only never-Defect

# --- generators ---------------------------------------------------------------
#
# toByteSeq/byteSeqs/charsToStr/safeStrings/SafeAlphabet used to be defined
# here (byte-for-byte identical to t_props.nim's copies, and to
# wireharness.nim's own separately-defined `toByteSeq`). R1-6 code-review
# finding hoisted all of them into fuzzsupport.nim, which this file already
# imports (`./fuzzsupport`, below). R2-1 code-review finding later removed
# `wireharness.nim`'s brief `toByteSeq` re-export (it existed only to save
# downstream consumers a second import line, but pulled all of proptest into
# every wireharness consumer, including non-fuzz ones) -- this file already
# imports `./fuzzsupport` directly, so that change is a no-op here.
# `byteSeqs`'s default maxLen (600, set by fuzzsupport to match
# t_props.nim's bare `byteSeqs()` call) doesn't change behavior here: every
# call site below passes an explicit maxLen (300 or 600).

# ---------------------------------------------------------------------------
# State: one live Wire plus the two in-flight futures it carries.
# ---------------------------------------------------------------------------

type
  HostileState = object
    w: Wire
    clientFut: Future[TransferResult]   ## recvBlocks -- the injection victim
    serverFut: Future[TransferResult]   ## sendBlocks -- the peer

proc buildHostileState(): HostileState =
  let w = newWire()
  let cfg = newTransferConfig(blocksize = HostileBlocksize, timeout = 1,
                              retries = 0, windowsize = 1,
                              totalSize = HostilePayload.len.int64)
  let serverT = makeTransport(w, sideA = false)
  let clientT = makeTransport(w, sideA = true)
  let serverPeer = newPeer("peer", 0)
  let clientPeer = newPeer("peer", 0)
  HostileState(
    w: w,
    serverFut: sendBlocks(serverT, cfg, serverPeer, 1'u16, hostileReadData),
    clientFut: recvBlocks(clientT, cfg, clientPeer, 1'u16, hostileOnData))

proc pumpAndSurface(st: HostileState) =
  ## Advance the dispatcher a SMALL bounded number of ticks, then -- if
  ## either future has resolved -- force its stored result to actually
  ## surface via `.read()`. A CatchableError there is the transfer's
  ## documented abort path (swallowed, expected). A Defect is deliberately
  ## NOT caught: it propagates out of this proc and up through stateful's
  ## generation, where proptest's engine classifies it as a falsification
  ## (see file doc comment above). Called by `stateful` after the initial
  ## state AND after every rule fires (`StateMachine.invariant`'s contract),
  ## so no rule needs its own pump logic.
  ##
  ## R1-1 fix: this budget was 20, which (with the old small payload) was
  ## enough to drain the WHOLE transfer to completion inside a single call
  ## -- i.e. before any rule had a chance to fire. 3 ticks/call, combined
  ## with the enlarged `HostilePayload` above, means completion genuinely
  ## requires many invariant calls (many rule-firing opportunities), so an
  ## inject rule's packet has a real chance of landing while the coroutine
  ## is still live. A run that happens to end (few steps, or `maxSteps`)
  ## before the transfer fully drains is fine here -- `drainFully` (below)
  ## is the one place completion is guaranteed, run once at the very end of
  ## each example, never during it.
  for _ in 0 ..< 3:
    if not hasPendingOperations(): break
    asyncdispatch.poll(0)
  if st.clientFut.finished and st.clientFut.failed:
    try: discard st.clientFut.read()
    except CatchableError: discard
  if st.serverFut.finished and st.serverFut.failed:
    try: discard st.serverFut.read()
    except CatchableError: discard

proc drainFully(st: HostileState) =
  ## Safety drain, run exactly ONCE per example -- after `stateful` returns
  ## the final state, never during it (`pumpAndSurface`'s shrunk per-step
  ## budget above is what keeps the transfer genuinely live across rule
  ## firings; draining fully there would defeat that). A short or
  ## early-terminating example (`stateful`'s own `drawBoolean(0.9)` can stop
  ## after zero steps) can legitimately end with `clientFut`/`serverFut`
  ## still pending -- without this, that future would be abandoned
  ## mid-flight, kept alive only by asyncdispatch's global dispatcher, and
  ## nothing would ever surface (or discard) whatever it eventually resolves
  ## to. `driveBoth` (wireharness.nim) pumps to completion or a generous
  ## step cap; same never-catch-Defect contract as `pumpAndSurface`.
  discard driveBoth(st.serverFut, st.clientFut)
  if st.clientFut.finished and st.clientFut.failed:
    try: discard st.clientFut.read()
    except CatchableError: discard
  if st.serverFut.finished and st.serverFut.failed:
    try: discard st.serverFut.read()
    except CatchableError: discard

# ---------------------------------------------------------------------------
# Injection rules -- each forges one packet shape and injects it via
# Wire.injectPacket (tests/wireharness.nim), targeting either the client
# (victim, recvBlocks) or the server (peer, sendBlocks) -- both named in
# D8's scope ("...into a live sendBlocks/recvBlocks/handleRrq/handleWrq
# exchange"). Injection only ever touches the wire and `d8aLiveInjections`,
# never any other part of HostileState.
# ---------------------------------------------------------------------------

proc inLiveDataPhase(s: HostileState): bool =
  ## True iff the sender (`serverFut`/sendBlocks) has NOT yet finished -- i.e.
  ## a genuine in-flight DATA/ACK window still exists. This is the honest
  ## "mid-flight, not the dally epilogue" predicate: sendBlocks returns the
  ## instant the FINAL block is ACKed, which is the very moment recvBlocks
  ## enters `dallyAfterFinalAck`. So `not serverFut.finished` is exactly
  ## "the data phase is still live" -- crucially it is NOT
  ## `not clientFut.finished`, because recvBlocks stays pending all through
  ## its dally epilogue; keying on the client future would (wrongly) count a
  ## dally-only injection as live, which is precisely the R1-1 vacuity.
  # R2-5: a narrow multi-tick boundary window exists where the client has
  # already entered dally a tick before serverFut actually resolves, so a
  # rule firing in that exact gap is counted live when it's really just
  # barely dally -- acceptable because across 22 blocks x ~200 examples it's
  # statistically implausible that EVERY positive increment lands only in
  # that tail.
  not s.serverFut.finished

proc noteD8aLiveInjection(s: HostileState, toClient: bool) =
  ## R1-1: mark this injection as having landed while the DATA/ACK exchange
  ## was genuinely still in flight (see `inLiveDataPhase`), not merely in the
  ## post-transfer dally epilogue.
  if inLiveDataPhase(s): d8aLiveInjections.note()

proc mkInjectData(toClient: bool): Rule[HostileState] =
  let strat = integers(0, 65535).flatMap(proc(b: int): Strategy[(int, seq[byte])] =
    byteSeqs(300).map(proc(d: seq[byte]): (int, seq[byte]) = (b, d)))
  rule(
    (if toClient: "inject DATA -> client" else: "inject DATA -> server"),
    strat,
    proc(s: var HostileState, args: (int, seq[byte])) =
      noteD8aLiveInjection(s, toClient)
      let pkt = TftpPacket(opcode: opData, blockNum: uint16(args[0]), data: args[1])
      s.w.injectPacket(toClient, encode(pkt)))

proc mkInjectAck(toClient: bool): Rule[HostileState] =
  rule(
    (if toClient: "inject ACK -> client" else: "inject ACK -> server"),
    integers(0, 65535),
    proc(s: var HostileState, b: int) =
      noteD8aLiveInjection(s, toClient)
      let pkt = TftpPacket(opcode: opAck, ackBlockNum: uint16(b))
      s.w.injectPacket(toClient, encode(pkt)))

proc mkInjectError(toClient: bool): Rule[HostileState] =
  let strat = integers(0, 8).flatMap(proc(c: int): Strategy[(int, string)] =
    safeStrings(0, 16).map(proc(m: string): (int, string) = (c, m)))
  rule(
    (if toClient: "inject ERROR -> client" else: "inject ERROR -> server"),
    strat,
    proc(s: var HostileState, args: (int, string)) =
      noteD8aLiveInjection(s, toClient)
      let pkt = TftpPacket(opcode: opError, errorCode: TftpErrorCode(args[0]),
                            errorMsg: args[1])
      s.w.injectPacket(toClient, encode(pkt)))

proc mkInjectGarbage(toClient: bool): Rule[HostileState] =
  rule(
    (if toClient: "inject garbage -> client" else: "inject garbage -> server"),
    byteSeqs(600),
    proc(s: var HostileState, data: seq[byte]) =
      noteD8aLiveInjection(s, toClient)
      s.w.injectPacket(toClient, data))

let hostileSM = StateMachine[HostileState](
  initial: newStrategy(proc(src: var DataSource): HostileState = buildHostileState()),
  rules: @[
    mkInjectData(true),    mkInjectData(false),
    mkInjectAck(true),     mkInjectAck(false),
    mkInjectError(true),   mkInjectError(false),
    mkInjectGarbage(true), mkInjectGarbage(false),
  ],
  invariant: pumpAndSurface)

suite "hostile session -- payload injection (RFC verification-harness.md D8a)":
  # R1-4: brought under the same coverage-guided + corpus-persisted
  # discipline as every other fuzz target (`fuzzProperty` bundles
  # `coverageGuided: true, testId, dbPath: CorpusDir, seed: FuzzSeed,
  # maxExamples: FuzzN` plus the `currentCoverage() > 0` tripwire -- see
  # tests/fuzzsupport.nim). `sendBlocks`/`recvBlocks`/`recvOnce`
  # (src/chapulin/transfer.nim) now carry `{.cover.}` so this has real
  # coverage-guided signal to search against.
  fuzzProperty("injected forged/garbage DATA/ACK/ERROR never raises a Defect",
               "hostile.payloadInjection"):
    given final in stateful(hostileSM)
    ensure (block:
      # `drainFully` guarantees this example's transfer/dally has actually
      # finished (and any CatchableError surfaced/discarded) before we
      # inspect it below -- see its doc comment.
      drainFully(final)
      final.w != nil)

  test "payload injection reaches a LIVE in-flight transfer, not only the " &
       "post-transfer dally epilogue (R1-1 anti-vacuity)":
    ## Runs after the property above (unittest executes a suite's tests in
    ## source order), so `d8aLiveInjections` reflects every example that
    ## property just generated. This is the check that reproduces R1-1 when
    ## it's false: before the `pumpAndSurface`/`HostilePayload` fix above,
    ## the whole transfer finished inside the very first invariant call
    ## (before any inject rule ever fired), so this counter stayed exactly 0
    ## across all ~200 examples.
    d8aLiveInjections.assertFired(
      "R1-1 vacuity: no injection ever landed in a live in-flight window")

# ---------------------------------------------------------------------------
# Off-TID injection (RFC verification-harness.md D8b, slice 8).
#
# Same live sendBlocks<->recvBlocks exchange, but BOTH peers are constructed
# already TID-locked (`newPeer(WirePeerHost, WirePeerPort, locked = true)` --
# the same "already-established session" precedent `t_props_transfer.nim`
# uses) so the TID-lock check in `transfer.recvOnce`
# (`resp.host != peer.host or resp.port != peer.port`) is live from the very
# first injected packet, rather than racing an unlocked peer that would
# happily lock onto the first attacker packet it sees.
#
# `wireharness.injectPacket` now takes an optional (host, port); every rule
# here supplies an ATTACKER address distinct from `WirePeerHost`/
# `WirePeerPort` (`attackerAddr` below draws from a fixed non-"peer" host
# list, so the mismatch is true by construction, not by probability). The
# companion fix in `makeTransport.doSend` (tests/wireharness.nim) makes the
# mock route a `Transport.send` to a non-peer destination nowhere instead of
# leaking it onto the legit pipe -- without that fix, `recvOnce`'s
# ERROR-bounce reply to the attacker's address would misroute back onto the
# victim's own transfer (the mock ignoring destination), which would corrupt
# the legitimate session for a reason that has nothing to do with the TID
# lock itself.
#
# Invariant, same shape as D8a: never a Defect. `w.aBounced`/`w.bBounced`
# (incremented only on a non-peer-destination send) additionally proves the
# TID-lock's mismatch branch genuinely fired at least once per run -- without
# it this property could pass vacuously if every injected off-TID packet
# happened to be consumed some other way (e.g. arriving after both transfers
# already completed) without ever exercising `recvOnce`'s mismatch arm.
# ---------------------------------------------------------------------------

proc buildOffTidState(): HostileState =
  let w = newWire()
  let cfg = newTransferConfig(blocksize = HostileBlocksize, timeout = 1,
                              retries = 0, windowsize = 1,
                              totalSize = HostilePayload.len.int64)
  let serverT = makeTransport(w, sideA = false)
  let clientT = makeTransport(w, sideA = true)
  let serverPeer = newPeer(WirePeerHost, WirePeerPort, locked = true)
  let clientPeer = newPeer(WirePeerHost, WirePeerPort, locked = true)
  HostileState(
    w: w,
    serverFut: sendBlocks(serverT, cfg, serverPeer, 1'u16, hostileReadData),
    clientFut: recvBlocks(clientT, cfg, clientPeer, 1'u16, hostileOnData))

const AttackerHosts = @["attacker", "evil.example", "10.6.6.6", "mitm"]
  ## None equal WirePeerHost ("peer") -- so any draw from this list is an
  ## off-TID source regardless of the port drawn alongside it.

proc attackerAddr(): Strategy[(string, int)] =
  sampledFrom(AttackerHosts).flatMap(proc(h: string): Strategy[(string, int)] =
    integers(0, 65535).map(proc(p: int): (string, int) = (h, p)))

proc noteD8bLiveInjection(s: HostileState, toClient: bool) =
  ## R1-3 counterpart to `noteD8aLiveInjection` -- same `inLiveDataPhase`
  ## predicate (keys on the sender, never the dally-parked receiver).
  if inLiveDataPhase(s): d8bLiveInjections.note()

proc mkInjectOffTidData(toClient: bool): Rule[HostileState] =
  let strat = attackerAddr().flatMap(proc(a: (string, int)): Strategy[(string, int, int, seq[byte])] =
    integers(0, 65535).flatMap(proc(b: int): Strategy[(string, int, int, seq[byte])] =
      byteSeqs(300).map(proc(d: seq[byte]): (string, int, int, seq[byte]) = (a[0], a[1], b, d))))
  rule(
    (if toClient: "inject off-TID DATA -> client" else: "inject off-TID DATA -> server"),
    strat,
    proc(s: var HostileState, args: (string, int, int, seq[byte])) =
      noteD8bLiveInjection(s, toClient)
      let pkt = TftpPacket(opcode: opData, blockNum: uint16(args[2]), data: args[3])
      s.w.injectPacket(toClient, encode(pkt), args[0], args[1]))

proc mkInjectOffTidAck(toClient: bool): Rule[HostileState] =
  let strat = attackerAddr().flatMap(proc(a: (string, int)): Strategy[(string, int, int)] =
    integers(0, 65535).map(proc(b: int): (string, int, int) = (a[0], a[1], b)))
  rule(
    (if toClient: "inject off-TID ACK -> client" else: "inject off-TID ACK -> server"),
    strat,
    proc(s: var HostileState, args: (string, int, int)) =
      noteD8bLiveInjection(s, toClient)
      let pkt = TftpPacket(opcode: opAck, ackBlockNum: uint16(args[2]))
      s.w.injectPacket(toClient, encode(pkt), args[0], args[1]))

proc mkInjectOffTidError(toClient: bool): Rule[HostileState] =
  let strat = attackerAddr().flatMap(proc(a: (string, int)): Strategy[(string, int, int, string)] =
    integers(0, 8).flatMap(proc(c: int): Strategy[(string, int, int, string)] =
      safeStrings(0, 16).map(proc(m: string): (string, int, int, string) = (a[0], a[1], c, m))))
  rule(
    (if toClient: "inject off-TID ERROR -> client" else: "inject off-TID ERROR -> server"),
    strat,
    proc(s: var HostileState, args: (string, int, int, string)) =
      noteD8bLiveInjection(s, toClient)
      let pkt = TftpPacket(opcode: opError, errorCode: TftpErrorCode(args[2]),
                            errorMsg: args[3])
      s.w.injectPacket(toClient, encode(pkt), args[0], args[1]))

proc mkInjectOffTidGarbage(toClient: bool): Rule[HostileState] =
  let strat = attackerAddr().flatMap(proc(a: (string, int)): Strategy[(string, int, seq[byte])] =
    byteSeqs(600).map(proc(d: seq[byte]): (string, int, seq[byte]) = (a[0], a[1], d)))
  rule(
    (if toClient: "inject off-TID garbage -> client" else: "inject off-TID garbage -> server"),
    strat,
    proc(s: var HostileState, args: (string, int, seq[byte])) =
      noteD8bLiveInjection(s, toClient)
      s.w.injectPacket(toClient, args[2], args[0], args[1]))

let offTidSM = StateMachine[HostileState](
  initial: newStrategy(proc(src: var DataSource): HostileState = buildOffTidState()),
  rules: @[
    mkInjectOffTidData(true),    mkInjectOffTidData(false),
    mkInjectOffTidAck(true),     mkInjectOffTidAck(false),
    mkInjectOffTidError(true),   mkInjectOffTidError(false),
    mkInjectOffTidGarbage(true), mkInjectOffTidGarbage(false),
  ],
  invariant: pumpAndSurface)

suite "hostile session -- off-TID injection (RFC verification-harness.md D8b)":
  # R1-4: same coverage-guided + corpus-persisted discipline as D8a above.
  fuzzProperty("off-TID DATA/ACK/ERROR/garbage is rejected by the TID lock, never raises a Defect",
               "hostile.offTidInjection"):
    given final in stateful(offTidSM)
    ensure (block:
      drainFully(final)
      # R1-3: accumulate this example's bounce count into the run-level
      # total checked below -- proves `recvOnce`'s TID-mismatch/bounce arm
      # genuinely fired at least once across the run, not merely that every
      # injected off-TID packet happened to be consumed some other way.
      d8bBounceTotal.note(final.w.aBounced + final.w.bBounced)
      final.w != nil)

  test "off-TID injection reaches a LIVE in-flight transfer and the TID-lock " &
       "mismatch arm genuinely fires across the run (R1-3 anti-vacuity)":
    ## Same "by end of run, not per-example" reasoning as D8a's companion
    ## test above. `d8bBounceTotal.assertFired(...)` below is the check that
    ## directly reproduces R1-3: the property's own `ensure` never inspected
    ## `aBounced`/`bBounced` before this fix, so ~200 fuzz examples proved
    ## nothing about whether the TID-lock mismatch arm ever actually ran --
    ## only the deterministic test below did.
    d8bLiveInjections.assertFired(
      "R1-3 vacuity: no off-TID injection ever landed in a live in-flight window")
    d8bBounceTotal.assertFired(
      "R1-3 vacuity: recvOnce's TID-mismatch/bounce arm never fired across the run")

  test "off-TID DATA is bounced -- never delivered, never derails the legit transfer":
    ## Deterministic complement to the property above: the stateful property
    ## proves never-Defect over many random schedules but can't cheaply
    ## assert "the TID-lock mismatch branch actually fired this run" without
    ## risking a flaky per-example check (a 0-step example legitimately never
    ## injects anything). This test nails the concrete claim down: a single
    ## off-TID DATA packet is rejected (bounced, never delivered to the
    ## victim's onData) and the legitimate transfer still completes
    ## correctly around it.
    let st = buildOffTidState()
    let forged = TftpPacket(opcode: opData, blockNum: 1'u16,
                             data: @[byte 0xDE, 0xAD, 0xBE, 0xEF])
    st.w.injectPacket(true, encode(forged), "attacker", 31337)
    check driveBoth(st.serverFut, st.clientFut)
    # Side A (the client) is the one whose recv saw the off-TID packet and
    # attempted the RFC 1350 "Unknown transfer ID" ERROR-bounce reply back to
    # the attacker's address -- caught and discarded by the routing gate in
    # makeTransport.doSend, never delivered onto the legit pipe.
    check st.w.aBounced == 1
    check st.w.bBounced == 0
    let serverResult = futVal(st.serverFut)
    let clientResult = futVal(st.clientFut)
    check serverResult.success
    check clientResult.success
    check clientResult.bytesTransferred == HostilePayload.len.int64
