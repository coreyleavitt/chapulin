## In-memory demonstration -- RFC in-memory-sources-sinks.md slice 5 (listed
## as stage "6" in the RFC's §Stages), the A1b hermeticity capstone proof.
##
## A real client TftpSession (through the public facade) transfers against
## the real server handleRrq/handleWrq handlers, over two Wire-backed
## transports (tests/wireharness.nim), with a SHARED in-RAM path-keyed
## TableRef[string, seq[byte]] (tests/helpers.nim's tableSourceFactory/
## tableSinkFactory) as the only backing storage on EITHER party. There is
## no listener/accept step -- the v2 listener bridge (makeListenerFromWire)
## does not exist yet, so this drives handleRrq/handleWrq directly, exactly
## like slice 3's (t_session.nim) and slice 4's (t_server.nim) suites.
##
## Every test asserts byte-for-byte round-trip AND `not fileExists(...)` for
## every path that would have touched disk under the file-backed default --
## proving zero DATA-path disk I/O on both client and server.
##
## Run:
##   pwsh scripts/dev-test.ps1 -Only @('t_blocksource_demo')

import std/unittest
import std/[os, asyncdispatch, options, tables, sequtils, strutils]
import ../src/chapulin/api
import ../src/chapulin/server
import ../src/chapulin/server_config
import ../src/chapulin/protocol
import ../src/chapulin/transfer
import ../src/chapulin/blocksource
import ../src/chapulin/security
import ./wireharness
import ./helpers

proc keyFor(rootDir, filename: string): string =
  ## The table key a request for `filename` under `rootDir` actually maps
  ## to: `handleRrq`/`handleWrq` call `resolveSourceFactory(config)`/
  ## `resolveSinkFactory(config)` with the POST-`validatePath` resolved
  ## absolute path (RFC in-memory-sources-sinks.md §5.1), never the raw
  ## client-supplied filename -- so a table-backed factory must be keyed
  ## the same way. Computed here via the same authority the server itself
  ## uses, rather than guessed/reconstructed, so the demo can't silently
  ## drift from the real resolution rule.
  let (valid, resolved, err) = validatePath(rootDir, filename)
  doAssert valid, "test setup: path must validate: " & err
  resolved

# ---------------------------------------------------------------------------
# Drive helper: pump s.poll(0) until a terminal event for `id` is seen or
# the step cap is hit. asyncdispatch.poll (inside s.poll) advances every
# pending future on the shared dispatcher, including the fire-and-forget
# server-side handleRrq/handleWrq future started below -- same pattern as
# t_session.nim's driveSession.
# ---------------------------------------------------------------------------
proc driveSession(s: TftpSession, id: TransferId,
                  maxSteps = 200_000): seq[Event] =
  var done = false
  var steps = 0
  while steps < maxSteps and not done:
    for ev in s.poll(0):
      result.add ev
      if ev.xfrId == id and ev.kind in {evTransferComplete, evTransferError}:
        done = true
    inc steps
  if done:
    for ev in s.poll(0): result.add ev

proc repeatToSize(pattern: string, size: int): seq[byte] =
  ## A deterministic payload of exactly `size` bytes built by repeating
  ## `pattern`. Sized (in the tests below) to span multiple DATA blocks
  ## AND leave a short final block, so the transfer exercises real
  ## multi-block windowing, not a single packet.
  result = newSeq[byte](size)
  for i in 0 ..< size:
    result[i] = byte(pattern[i mod pattern.len])

suite "In-memory demonstration -- shared-table BlockSource/BlockSink hermeticity (RFC in-memory-sources-sinks.md, slice 5)":

  test "server-GET: client downloads from a shared in-RAM table -- zero disk I/O on either side":
    let tmpDir = getTempDir() / "chapulin_t_blocksource_demo_get"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except: discard)

    let table = newTable[string, seq[byte]]()
    # Multi-block: 1400 bytes with DefaultBlocksize (512) => blocks of
    # 512, 512, 376 (short final block).
    let knownBytes = repeatToSize("The quick brown fox jumps over the lazy dog. ", 1400)
    table[keyFor(tmpDir, "served.bin")] = knownBytes

    var serverCfg = newDefaultServerConfig(tmpDir)
    serverCfg.sourceFactory = tableSourceFactory(table)

    let w = newWire()
    let serverT = makeTransport(w, sideA = false)
    proc serverRespond(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      let pkt = decode(data)
      discard await handleRrq(serverCfg, pkt, serverT, host, port)
    discard serverRespond()

    let clientBuf = new(seq[byte])
    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport = makeTransport(w, sideA = true),
      sinkFactory = proc(path: string): BlockSink = memoryBlockSink(clientBuf))

    # localOut deliberately points at a path that is never created on disk --
    # if the file-backed default sink were still live, the first DATA packet
    # would create it.
    let localOut = getTempDir() / "chapulin_t_blocksource_demo_get_NOFILE.bin"
    check not fileExists(localOut)

    var req = newTransferRequest("peer", 0, "served.bin", localOut, tdGet)
    let id = s.startTransfer(req)
    check id != NoTransfer
    let evs = driveSession(s, id)
    check evs[^1].kind == evTransferComplete

    check clientBuf[] == knownBytes
    check not fileExists(localOut)                  # client-side: zero disk I/O
    check not fileExists(tmpDir / "served.bin")      # server-side: zero disk I/O
    check toSeq(walkDir(tmpDir)).len == 0            # rootDir stayed empty throughout

  test "client-PUT: client uploads into a shared in-RAM table -- zero disk I/O on either side":
    let tmpDir = getTempDir() / "chapulin_t_blocksource_demo_put"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except: discard)

    let table = newTable[string, seq[byte]]()
    let knownBytes = repeatToSize("Upload this from RAM, never touching disk! ", 1600)

    var serverCfg = newDefaultServerConfig(tmpDir)
    serverCfg.writePolicy = wpCreateOrOverwrite
    serverCfg.sinkFactory = tableSinkFactory(table)

    let w = newWire()
    let serverT = makeTransport(w, sideA = false)
    proc serverRespond(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      let pkt = decode(data)
      discard await handleWrq(serverCfg, pkt, serverT, host, port)
    discard serverRespond()

    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport = makeTransport(w, sideA = true),
      sourceFactory = proc(path: string): Option[OpenedSource] =
        some((memoryBlockSource(knownBytes), some(knownBytes.len.int64))))

    # localPath deliberately points at a file that does NOT exist -- the
    # injected sourceFactory must be the only thing consulted.
    let phantomPath = getTempDir() / "chapulin_t_blocksource_demo_put_NOFILE.bin"
    check not fileExists(phantomPath)

    var req = newTransferRequest("peer", 0, "uploaded.bin", phantomPath, tdPut)
    let id = s.startTransfer(req)
    check id != NoTransfer
    let evs = driveSession(s, id)
    check evs[^1].kind == evTransferComplete

    let key = keyFor(tmpDir, "uploaded.bin")
    check table.hasKey(key)
    check table[key] == knownBytes
    check not fileExists(phantomPath)                  # client-side: zero disk I/O
    check not fileExists(tmpDir / "uploaded.bin")       # server-side: zero disk I/O
    check toSeq(walkDir(tmpDir)).len == 0

  test "PUT then server-GET of the SAME path/table: reader observes the writer's finish() commit, not a construction-time snapshot":
    let tmpDir = getTempDir() / "chapulin_t_blocksource_demo_coherence"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except: discard)

    let table = newTable[string, seq[byte]]()
    var serverCfg = newDefaultServerConfig(tmpDir)
    serverCfg.writePolicy = wpCreateOrOverwrite
    # Constructed while `table` is still EMPTY. If either factory captured a
    # snapshot of the table at construction time (instead of looking it up
    # per call), the GET below would see nothing -- proving the hazard
    # RFC §5.1 names is actually avoided.
    serverCfg.sourceFactory = tableSourceFactory(table)
    serverCfg.sinkFactory = tableSinkFactory(table)
    let key = keyFor(tmpDir, "roundtrip.bin")
    check not table.hasKey(key)

    let knownBytes = repeatToSize("Round trip through the shared table. ", 1500)

    # --- Step 1: client PUT "roundtrip.bin" ---
    block:
      let w = newWire()
      let serverT = makeTransport(w, sideA = false)
      proc serverRespondPut(): Future[void] {.async.} =
        let (data, host, port) = await serverT.recv(576, 5000)
        let pkt = decode(data)
        discard await handleWrq(serverCfg, pkt, serverT, host, port)
      discard serverRespondPut()

      let s = newSession(
        transportFactory = proc(h: string, p: int): Transport = makeTransport(w, sideA = true),
        sourceFactory = proc(path: string): Option[OpenedSource] =
          some((memoryBlockSource(knownBytes), some(knownBytes.len.int64))))

      let phantomPath = getTempDir() / "chapulin_t_blocksource_demo_coherence_put_NOFILE.bin"
      var req = newTransferRequest("peer", 0, "roundtrip.bin", phantomPath, tdPut)
      let id = s.startTransfer(req)
      let evs = driveSession(s, id)
      check evs[^1].kind == evTransferComplete

    # The PUT's finish() committed into the SAME table the (already
    # constructed) sourceFactory closes over.
    check table.hasKey(key)
    check table[key] == knownBytes

    # --- Step 2: a SUBSEQUENT server-GET of the same path, same table ---
    block:
      let w2 = newWire()
      let serverT2 = makeTransport(w2, sideA = false)
      proc serverRespondGet(): Future[void] {.async.} =
        let (data, host, port) = await serverT2.recv(576, 5000)
        let pkt = decode(data)
        discard await handleRrq(serverCfg, pkt, serverT2, host, port)
      discard serverRespondGet()

      let clientBuf = new(seq[byte])
      let s2 = newSession(
        transportFactory = proc(h: string, p: int): Transport = makeTransport(w2, sideA = true),
        sinkFactory = proc(path: string): BlockSink = memoryBlockSink(clientBuf))

      let getPhantom = getTempDir() / "chapulin_t_blocksource_demo_coherence_get_NOFILE.bin"
      var req2 = newTransferRequest("peer", 0, "roundtrip.bin", getPhantom, tdGet)
      let id2 = s2.startTransfer(req2)
      let evs2 = driveSession(s2, id2)
      check evs2[^1].kind == evTransferComplete

      check clientBuf[] == knownBytes
      check not fileExists(getPhantom)

    check not fileExists(tmpDir / "roundtrip.bin")
    check toSeq(walkDir(tmpDir)).len == 0

  test "netascii mode: server-GET through the shared table decodes embedded newlines correctly, still zero disk I/O":
    let tmpDir = getTempDir() / "chapulin_t_blocksource_demo_netascii"
    createDir(tmpDir)
    defer: (try: removeDir(tmpDir) except: discard)

    let table = newTable[string, seq[byte]]()
    # Content whose local (pre-translation) representation contains bare
    # '\n' line endings -- netascii expands each to CRLF on the wire, so a
    # correct decode is what proves the netasciiBlockSource/netasciiBlockSink
    # decorators compose hermetically through the facade (not just octet).
    var lines = newSeq[string]()
    for i in 0 ..< 80:
      lines.add "line " & $i & " of the netascii demo payload"
    let localText = lines.join("\n") & "\n"
    let knownBytes = cast[seq[byte]](localText)
    check knownBytes.len > DefaultBlocksize   # multi-block even pre-expansion
    table[keyFor(tmpDir, "served_na.txt")] = knownBytes

    var serverCfg = newDefaultServerConfig(tmpDir)
    serverCfg.sourceFactory = tableSourceFactory(table)

    let w = newWire()
    let serverT = makeTransport(w, sideA = false)
    proc serverRespond(): Future[void] {.async.} =
      let (data, host, port) = await serverT.recv(576, 5000)
      let pkt = decode(data)
      discard await handleRrq(serverCfg, pkt, serverT, host, port)
    discard serverRespond()

    let clientBuf = new(seq[byte])
    let s = newSession(
      transportFactory = proc(h: string, p: int): Transport = makeTransport(w, sideA = true),
      sinkFactory = proc(path: string): BlockSink = memoryBlockSink(clientBuf))

    let localOut = getTempDir() / "chapulin_t_blocksource_demo_netascii_NOFILE.bin"
    var req = newTransferRequest("peer", 0, "served_na.txt", localOut, tdGet)
    req.options.mode = tmNetascii
    let id = s.startTransfer(req)
    check id != NoTransfer
    let evs = driveSession(s, id)
    check evs[^1].kind == evTransferComplete

    # Decoded back through the facade, the client's in-memory sink holds
    # exactly the original local bytes -- the wire carried CRLF-expanded
    # bytes (a different, larger byte sequence) in between.
    check clientBuf[] == knownBytes
    check cast[string](clientBuf[]) == localText
    check not fileExists(localOut)
    check not fileExists(tmpDir / "served_na.txt")
    check toSeq(walkDir(tmpDir)).len == 0
