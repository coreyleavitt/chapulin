## A4 (RFC verification-harness-v2.md §3.1/§5): maxConcurrent reject-path
## prod reroute -- server.nim's three `newUdpTransport(0)` reject sites
## (no-available-port, host-access denial, maxConcurrent) now route through
## `server.transferFactory` instead -- plus the new `onRejected` ServerCallbacks
## hook + `evServerRejected` EventKind + api.nim wiring, so a Wire-backed
## session's rejection is a structured, observable Event instead of a
## real-socket open / free-text log substring.
##
## Two suites:
##  - "direct TftpServer" -- the PRIMARY anti-vacuity assertion, keyed on
##    `server.activeTransfers == maxConcurrent` (RFC §3.1's corrected reading:
##    NOT `activeClientCount`, api.nim:127-132's disjoint OUTBOUND-only
##    counter, which this scenario can never touch since every request here
##    is INBOUND). Only reachable with direct access to the `TftpServer` ref,
##    which api.nim's session facade deliberately does not expose -- so this
##    suite drives `newTftpServer`/`run()` directly (mirrors t_server.nim's
##    existing direct-server style), not through `newSession`.
##  - "api.nim session facade" -- confirms `onRejected` surfaces as a
##    structured `evServerRejected` Event through a real `TftpSession`
##    (RFC: "wire it through api.nim so a session observes rejections as a
##    structured Event, NOT a free-text log substring") -- the embedding-
##    facing half of the deliverable (RFC #17's actual consumer).
##
## Zero-real-socket note: every transport in both suites is minted by a
## `WireRegistry`-backed `transportFactory` (A1a-i, shared with A4's
## mechanism per §3.1's "A4's registry IS this generalized 1->N"). Since all
## three reject sites now call `server.transferFactory(0)` instead of
## `transport.newUdpTransport` directly, and the registry never touches
## `newUdpTransport`, no real OS socket opens anywhere in either suite --
## `reg.wires.len` is asserted to account for every mint (accepted transfers
## plus each reject site's own mint, now that it shares the seam). No
## test-only open-count counter was added to `transport.nim`: that file is
## NOT part of A4's scoped src/ change (the task's own boundary is server.nim's
## three-site reroute + the onRejected hook/EventKind + api.nim wiring only)
## -- adding one there would be a fourth, out-of-scope src/ file touched.
##
## Run:
##   pwsh scripts/dev-test.ps1 -Only @('t_a4_maxconcurrent')

import std/[unittest, asyncdispatch, os]
import ../src/chapulin/server
import ../src/chapulin/server_config
import ../src/chapulin/protocol
import ../src/chapulin/transfer
import ../src/chapulin/api
import ./wireharness

proc pumpTicks(n: int) =
  for _ in 0 ..< n:
    if hasPendingOperations(): asyncdispatch.poll(0)

type RejectRecord = object
  host: string
  port: int
  code: TftpErrorCode
  msg: string
  activeAtReject: int

suite "A4: maxConcurrent reject reroute (direct TftpServer)":
  test "the (N+1)th inbound request is rejected while server.activeTransfers == maxConcurrent, observed via onRejected":
    let tmpDir = getTempDir() / "chapulin_t_a4_direct"
    createDir(tmpDir)
    writeFile(tmpDir / "f.bin", "hello world")
    defer:
      try: removeDir(tmpDir) except CatchableError: discard

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.maxConcurrent = 2   # N = 2: two accepted, the 3rd must reject

    let reg = newWireRegistry()
    let srv = newTftpServer(cfg)
    let regFactory = reg.factory()
    srv.transferFactory = proc(port: int): Transport = regFactory("127.0.0.1", port)

    var rejects: seq[RejectRecord]
    srv.callbacks.onRejected = proc(info: RejectInfo) {.closure.} =
      # Read srv.activeTransfers SYNCHRONOUSLY, inside the same call stack
      # the reject fired on (single-threaded dispatcher -- no race): this is
      # the literal server.nim:~918 gate value at the moment of rejection,
      # not a proxy/reconstruction.
      rejects.add RejectRecord(host: info.clientHost, port: info.clientPort,
                               code: info.code, msg: info.msg,
                               activeAtReject: srv.activeTransfers)

    let q = newListenerQueue()
    let listener = makeListener(q)
    let rrq = encode(TftpPacket(opcode: opRrq, filename: "f.bin", mode: tmOctet, options: @[]))
    q.push(rrq, "10.0.0.1", 1001)   # accepted (slot 1/2)
    q.push(rrq, "10.0.0.2", 1002)   # accepted (slot 2/2)
    q.push(rrq, "10.0.0.3", 1003)   # the (N+1)th -- must be rejected

    let runFut = server.run(srv, listener)
    pumpTicks(200)

    check rejects.len == 1
    check rejects[0].host == "10.0.0.3"
    check rejects[0].port == 1003
    check rejects[0].code == errNotDefined
    check rejects[0].activeAtReject == cfg.maxConcurrent   # == 2, the ANTI-VACUITY assertion

    # Still true post-hoc: both accepted transfers are genuinely mid-flight
    # (awaiting an ACK on their own freshly-minted Wire that nothing ever
    # answers) -- not a stale snapshot from a transfer that already finished.
    check srv.activeTransfers == cfg.maxConcurrent

    # Zero real sockets: 2 accepted transfers + 1 reject-site mint, all via
    # the registry, none via transport.newUdpTransport.
    check reg.wires.len == 3

    srv.stop()
    pumpTicks(50)
    discard runFut

  test "H2: a throwing onRejected callback does not kill run()'s accept loop":
    ## RFC verification-harness-v2.handoff.md H2: reject sites 2/3 used to
    ## invoke `server.callbacks.onRejected` UNWRAPPED, directly inside run()'s
    ## `while` loop -- a CatchableError raised by an app-supplied callback
    ## propagated straight out of `run()`, failing its Future and permanently
    ## stopping the listener (a DoS: chapulin is single-threaded, so this
    ## kills client+server both). The fix (`rejectRequest`) wraps the
    ## `onRejected` invocation in its own try/except CatchableError so a
    ## raising callback degrades to a logged warning and the accept loop
    ## keeps running.
    ##
    ## Anti-vacuity: drives a reject (host-access denial -- reject site 2,
    ## independent of maxConcurrent) whose onRejected callback raises, then
    ## pushes a SECOND, unrelated, allowed request and asserts it was actually
    ## accepted (srv.activeTransfers becomes 1) -- i.e. the loop is still
    ## alive and iterating, not just "didn't crash the test process."
    let tmpDir = getTempDir() / "chapulin_t_a4_h2"
    createDir(tmpDir)
    writeFile(tmpDir / "f.bin", "hello world")
    defer:
      try: removeDir(tmpDir) except CatchableError: discard

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.deniedHosts = @["10.0.0.42"]   # triggers reject site 2 (host-access denial)

    let reg = newWireRegistry()
    let srv = newTftpServer(cfg)
    let regFactory = reg.factory()
    srv.transferFactory = proc(port: int): Transport = regFactory("127.0.0.1", port)

    srv.callbacks.onRejected = proc(info: RejectInfo) {.closure.} =
      raise newException(ValueError, "boom -- app callback misbehaves")

    let q = newListenerQueue()
    let listener = makeListener(q)
    let rrq = encode(TftpPacket(opcode: opRrq, filename: "f.bin", mode: tmOctet, options: @[]))
    q.push(rrq, "10.0.0.42", 4242)   # denied -- rejects, onRejected raises
    q.push(rrq, "10.0.0.55", 4255)   # unrelated, allowed -- must still be accepted

    let runFut = server.run(srv, listener)
    pumpTicks(200)

    # The listener survived the raising callback: the second, unrelated
    # request was actually accepted and handleRequest spawned for it (its
    # transfer never completes -- no ACK is ever sent on its Wire -- so
    # activeTransfers stays at 1 rather than reverting to 0).
    check srv.activeTransfers == 1

    srv.stop()
    pumpTicks(50)
    discard runFut

suite "A4: onRejected surfaces as a structured evServerRejected Event (api.nim session facade)":
  test "a session observes the (N+1)th rejection as evServerRejected, not a free-text log substring":
    let tmpDir = getTempDir() / "chapulin_t_a4_facade"
    createDir(tmpDir)
    writeFile(tmpDir / "f.bin", "hello world")
    defer:
      try: removeDir(tmpDir) except CatchableError: discard

    var cfg = newDefaultServerConfig(tmpDir)
    cfg.maxConcurrent = 1   # N = 1: one accepted, the 2nd must reject

    let reg = newWireRegistry()
    let q = newListenerQueue()

    let s = newSession(
      transportFactory = reg.factory(),
      listenerFactory = proc(a: string, p: int): UdpListener = makeListener(q, p))

    let rrq = encode(TftpPacket(opcode: opRrq, filename: "f.bin", mode: tmOctet, options: @[]))
    q.push(rrq, "10.0.0.9", 2001)    # accepted
    q.push(rrq, "10.0.0.10", 2002)   # rejected

    discard s.startServer(cfg)

    var evs: seq[Event]
    for i in 0 ..< 100:
      for ev in s.poll(0): evs.add ev

    var rejectedEvents: seq[Event]
    var startedEvents: seq[Event]
    for ev in evs:
      case ev.kind
      of evServerRejected: rejectedEvents.add ev
      of evTransferStarted: startedEvents.add ev
      else: discard

    # The structured signal: exactly one evServerRejected, carrying the
    # rejected peer's own address/code/msg -- not routed through evServerLog.
    check rejectedEvents.len == 1
    check rejectedEvents[0].xfrId == NoTransfer   # no reqId/TransferId ever minted for a reject
    check rejectedEvents[0].rejClientHost == "10.0.0.10"
    check rejectedEvents[0].rejClientPort == 2002
    check rejectedEvents[0].rejCode == errNotDefined
    check rejectedEvents[0].rejMsg.len > 0

    # Existing accepted-request behavior is unaffected: the 1st request still
    # started normally (byte-identical existing behavior with onRejected wired
    # in but not firing for it).
    check startedEvents.len == 1
