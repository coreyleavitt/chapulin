## A1b (RFC verification-harness-v2.md §3.1/§5, slice A1b): get AND put smoke
## -- a real client `TftpSession` completes a full transfer over ONE `Wire`
## against a REAL server `TftpSession` (via `startServer`, its actual accept
## loop and `ServerCallbacks`), with file I/O on BOTH sides supplied by the
## BlockSource/BlockSink in-memory adapters (`docs/rfc/in-memory-sources-sinks.md`)
## instead of real disk.
##
## This is the piece `tests/t_blocksource_demo.nim` deliberately did NOT build
## (its own RFC's slice 6/"5" descoped the listener bridge as not-yet-existing
## and drove `handleRrq`/`handleWrq` directly, no accept loop, no listener).
## A1a-ii's `makeListenerFromWire`/`makeAdoptingTransport` (proven alone in
## `t_listenerbridge.nim` against a HAND-SIMULATED "server") are the missing
## link: here the far side of the bridge is a REAL `TftpSession.startServer`,
## not a hand-rolled `serverSide` proc. Wiring:
##
##   server TftpSession: transportFactory = reg.factory()            (A1a-i)
##                        listenerFactory = makeListenerFromWire(w)  (A1a-ii b)
##   client TftpSession: transportFactory = makeAdoptingTransport(w, reg) (A1a-ii c)
##
## `srv.transferFactory` (server.nim) is wired from the server SESSION's own
## `transportFactory` (`api.nim`'s `startServer`: `cS.transportFactory("127.0.0.1",
## port)`) -- so `reg.factory()` mints the per-transfer Wire exactly the way
## `allocateTransferTransport`/`transferFactory(0)` does in production
## (default `portRangeStart/End = 0` -> the degenerate single-key case A1a-i's
## call-order index exists to sidestep).
##
## File I/O: `ServerConfig.sourceFactory`/`sinkFactory` (RFC
## in-memory-sources-sinks.md §5.1) on the server side, `TftpSession.
## sourceFactory`/`sinkFactory` on the client side -- both memory-backed, zero
## disk touches on either party's transfer data path.
##
## Run:
##   pwsh scripts/dev-test.ps1 -Only @('t_a1b_smoke')

import std/unittest
import std/[os, options]
import ../src/chapulin/api
import ../src/chapulin/server_config
import ../src/chapulin/blocksource
import ./wireharness

proc repeatToSize(pattern: string, size: int): seq[byte] =
  ## A deterministic payload of exactly `size` bytes, sized (below) to span
  ## multiple DATA blocks AND leave a short final block -- so the transfer
  ## exercises real multi-block windowing, not a single packet.
  result = newSeq[byte](size)
  for i in 0 ..< size:
    result[i] = byte(pattern[i mod pattern.len])

# ---------------------------------------------------------------------------
# Drive helper: pump BOTH sessions' `poll(0)` each step. `asyncdispatch` is one
# process-global dispatcher (wireharness.pumpSession's own doc), so either
# session's `poll(0)` call advances the shared coroutines (the server's
# `run()` accept loop, the in-flight `handleRequest`/`getFile`/`putFile`
# futures) -- polling both here only ensures each session's OWN event queue is
# drained (and, for the server, that its `evServerStarted`/`evServerStopped`
# bookkeeping progresses), matching t_blocksource_demo.nim's/t_listenerbridge.
# nim's established `driveSession` idiom, extended to two sessions.
# ---------------------------------------------------------------------------
proc driveSessions(client, srv: TftpSession, id: TransferId,
                   maxSteps = 200_000): seq[Event] =
  var done = false
  var steps = 0
  while steps < maxSteps and not done:
    for ev in client.poll(0):
      result.add ev
      if ev.xfrId == id and ev.kind in {evTransferComplete, evTransferError}:
        done = true
    for ev in srv.poll(0): discard
    inc steps
  if done:
    for ev in client.poll(0): result.add ev

suite "A1b: real client TftpSession <-> real server TftpSession over Wire (A1a bridge), BlockSource/BlockSink in-memory":

  test "GET: client downloads from the real server session, zero disk I/O either side":
    let tmpDir = getTempDir() / "chapulin_t_a1b_get"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except CatchableError: discard)

    # Multi-block: 1400 bytes with DefaultBlocksize (512) => blocks of
    # 512, 512, 376 (short final block).
    let knownBytes = repeatToSize("A1b closes the RRQ/WRQ negotiation gap end to end over Wire. ", 1400)

    var serverCfg = newDefaultServerConfig(tmpDir)
    serverCfg.sourceFactory = proc(path: string): Option[OpenedSource] =
      some((memoryBlockSource(knownBytes), some(knownBytes.len.int64)))

    let listenerWire = newWire()
    let reg = newWireRegistry()

    let serverSession = newSession(
      transportFactory = reg.factory(),
      listenerFactory = proc(bindAddr: string, port: int): UdpListener =
        makeListenerFromWire(listenerWire))
    let srvId = serverSession.startServer(serverCfg)
    check srvId != NoServer

    let clientBuf = new(seq[byte])
    let clientSession = newSession(
      transportFactory = proc(host: string, port: int): Transport =
        makeAdoptingTransport(listenerWire, reg),
      sinkFactory = proc(path: string): BlockSink = memoryBlockSink(clientBuf))

    # localOut deliberately points at a path never created on disk -- if the
    # file-backed default sink were live instead of the injected one, the
    # first DATA packet would create it.
    let localOut = getTempDir() / "chapulin_t_a1b_get_NOFILE.bin"
    check not fileExists(localOut)

    var req = newTransferRequest("peer", 0, "served.bin", localOut, tdGet)
    let id = clientSession.startTransfer(req)
    check id != NoTransfer

    let evs = driveSessions(clientSession, serverSession, id)
    check evs.len > 0
    check evs[^1].kind == evTransferComplete
    check evs[^1].snap.bytes == knownBytes.len

    check clientBuf[] == knownBytes
    check not fileExists(localOut)                   # client-side: zero disk I/O
    check not fileExists(tmpDir / "served.bin")       # server-side: zero disk I/O

  test "PUT: client uploads into the real server session, zero disk I/O either side":
    let tmpDir = getTempDir() / "chapulin_t_a1b_put"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except CatchableError: discard)

    let knownBytes = repeatToSize("Uploading through two real sessions, never touching disk! ", 1600)

    let uploaded = new(seq[byte])
    var serverCfg = newDefaultServerConfig(tmpDir)
    serverCfg.writePolicy = wpCreateOrOverwrite
    serverCfg.sinkFactory = proc(path: string): BlockSink = memoryBlockSink(uploaded)

    let listenerWire = newWire()
    let reg = newWireRegistry()

    let serverSession = newSession(
      transportFactory = reg.factory(),
      listenerFactory = proc(bindAddr: string, port: int): UdpListener =
        makeListenerFromWire(listenerWire))
    let srvId = serverSession.startServer(serverCfg)
    check srvId != NoServer

    let clientSession = newSession(
      transportFactory = proc(host: string, port: int): Transport =
        makeAdoptingTransport(listenerWire, reg),
      sourceFactory = proc(path: string): Option[OpenedSource] =
        some((memoryBlockSource(knownBytes), some(knownBytes.len.int64))))

    # phantomPath deliberately points at a file that does NOT exist -- the
    # injected sourceFactory must be the only thing consulted.
    let phantomPath = getTempDir() / "chapulin_t_a1b_put_NOFILE.bin"
    check not fileExists(phantomPath)

    var req = newTransferRequest("peer", 0, "uploaded.bin", phantomPath, tdPut)
    let id = clientSession.startTransfer(req)
    check id != NoTransfer

    let evs = driveSessions(clientSession, serverSession, id)
    check evs.len > 0
    check evs[^1].kind == evTransferComplete
    check evs[^1].snap.bytes == knownBytes.len

    check uploaded[] == knownBytes
    check not fileExists(phantomPath)                 # client-side: zero disk I/O
    check not fileExists(tmpDir / "uploaded.bin")      # server-side: zero disk I/O
