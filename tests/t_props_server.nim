## Property-based tests for the server request handlers (server.nim), end to end.
##
## Connects the REAL client engine (getFile / putFile) to the REAL server
## handlers (handleRrq / handleWrq) over the shared in-memory wire, against real
## temp files. Exercises path validation, the request->serve/store flow, file
## I/O on both sides, and isolation of concurrent transfers interleaved on one
## event loop.
##
## Run in the nim devtools container (deps resolved on the host by milpa):
##   docker run --rm -v ${PWD}:C:\app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r tests/t_props_server.nim

import std/[unittest, os, asyncdispatch, strutils, md5, tables]  # asyncdispatch: Future only
import proptest
import ../src/chapulin/protocol
import ../src/chapulin/engine          # getFile, putFile, newDefaultConfig
import ../src/chapulin/server          # handleRrq, handleWrq
import ../src/chapulin/server_config
import ../src/chapulin/security         # canonicalize, isReservedSidecarName (H1 capability probe)
import ./wireharness

let serverRoot = getTempDir() / "chapulin_props_server"

proc toStr(b: seq[byte]): string =
  result = newString(b.len)
  for i in 0 ..< b.len: result[i] = char(b[i])

proc toBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len: result[i] = byte(s[i])

proc clientConfig(): TftpClientConfig =
  result = newDefaultConfig()
  result.requestTsize = false

# --- per-transfer setup (futures created, not yet driven) -------------------

# RRQ: server serves `fname` (already on disk) to a real client. Server drives
# a2b (DATA), client drives b2a (RRQ/ACK); the client's RRQ is swallowed (it
# would reach the listener, not the per-transfer socket).
proc setupRrq(w: Wire, fname: string):
    tuple[sf, cf: Future[TransferResult], received: ref seq[byte]] =
  let cfg = newDefaultServerConfig(serverRoot)
  let request = TftpPacket(opcode: opRrq, filename: fname, mode: tmOctet,
                           options: @[])
  var received: ref seq[byte]
  new(received)
  let onData = proc(blockNum: uint16, data: seq[byte]) = received[].add data
  let sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0)
  let cf = getFile(makeTransport(w, false, swallowFirst = true), clientConfig(),
                   "peer", 0, fname, onData)
  (sf, cf, received)

# WRQ: client uploads `content` to the server, stored at `fname`.
proc setupWrq(w: Wire, fname: string, content: seq[byte]):
    tuple[sf, cf: Future[TransferResult]] =
  var cfg = newDefaultServerConfig(serverRoot)
  cfg.writePolicy = wpCreateOrOverwrite
  let request = TftpPacket(opcode: opWrq, filename: fname, mode: tmOctet,
                           options: @[])
  let readData = proc(blockNum: uint16, bs: int): seq[byte] =
    let start = (int(blockNum) - 1) * bs
    if start >= content.len: return @[]
    return content[start ..< min(start + bs, content.len)]
  let cf = putFile(makeTransport(w, true, swallowFirst = true), clientConfig(),
                   "peer", 0, fname, readData)
  let sf = handleWrq(cfg, request, makeTransport(w, false), "peer", 0)
  (sf, cf)

# --- single-transfer runners ------------------------------------------------

proc serveRrq(content: seq[byte]): tuple[ok: bool, received: seq[byte]] =
  createDir(serverRoot)
  writeFile(serverRoot / "served.bin", toStr(content))
  let (sf, cf, received) = setupRrq(newWire(), "served.bin")
  if not driveBoth(sf, cf): return (false, received[])
  (futVal(sf).success and futVal(cf).success, received[])

proc recvWrq(content: seq[byte]): tuple[ok: bool, written: seq[byte]] =
  createDir(serverRoot)
  let (sf, cf) = setupWrq(newWire(), "uploaded.bin", content)
  if not driveBoth(sf, cf): return (false, @[])
  let ok = futVal(sf).success and futVal(cf).success
  var written: seq[byte]
  if fileExists(serverRoot / "uploaded.bin"):
    written = toBytes(readFile(serverRoot / "uploaded.bin"))
  (ok, written)

# RRQ where the client requests options (blksize/windowsize) so the OACK
# handshake runs. The request packet mirrors the options getFile will send.
proc setupRrqOpts(w: Wire, fname: string, blocksize, windowsize: int):
    tuple[sf, cf: Future[TransferResult], received: ref seq[byte]] =
  let opts = buildClientOptions(
    newTransferConfig(blocksize = blocksize, windowsize = windowsize),
    requestTsize = false)
  let cfg = newDefaultServerConfig(serverRoot)
  let request = TftpPacket(opcode: opRrq, filename: fname, mode: tmOctet,
                           options: opts)
  var ccfg = newDefaultConfig()
  ccfg.blocksize = blocksize
  ccfg.windowsize = windowsize
  ccfg.requestTsize = false
  var received: ref seq[byte]
  new(received)
  let onData = proc(blockNum: uint16, data: seq[byte]) = received[].add data
  let sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0)
  let cf = getFile(makeTransport(w, false, swallowFirst = true), ccfg,
                   "peer", 0, fname, onData)
  (sf, cf, received)

proc serveRrqNegotiated(content: seq[byte], blocksize, windowsize: int):
    tuple[ok: bool, received: seq[byte]] =
  createDir(serverRoot)
  writeFile(serverRoot / "neg.bin", toStr(content))
  let (sf, cf, received) = setupRrqOpts(newWire(), "neg.bin", blocksize, windowsize)
  if not driveBoth(sf, cf): return (false, received[])
  (futVal(sf).success and futVal(cf).success, received[])

# WRQ under a given write policy, optionally against a pre-existing file.
# Returns whether the server accepted, the bytes on disk afterward, and whether
# the file exists.
proc wrqUnderPolicy(policy: WritePolicy, content: seq[byte], fname: string,
                    preExisting: seq[byte] = @[], hasPreExisting = false,
                    checksumMode: ChecksumMode = csNone,
                    dir: string = serverRoot):
    tuple[serverOk: bool, onDisk: seq[byte], existed: bool] =
  createDir(dir)
  let path = dir / fname
  if hasPreExisting: writeFile(path, toStr(preExisting))
  elif fileExists(path): removeFile(path)
  var cfg = newDefaultServerConfig(dir)
  cfg.writePolicy = policy
  cfg.checksumMode = checksumMode
  let request = TftpPacket(opcode: opWrq, filename: fname, mode: tmOctet,
                           options: @[])
  let readData = proc(blockNum: uint16, bs: int): seq[byte] =
    let start = (int(blockNum) - 1) * bs
    if start >= content.len: return @[]
    return content[start ..< min(start + bs, content.len)]
  let w = newWire()
  let cf = putFile(makeTransport(w, true, swallowFirst = true), clientConfig(),
                   "peer", 0, fname, readData)
  let sf = handleWrq(cfg, request, makeTransport(w, false), "peer", 0)
  discard driveBoth(sf, cf)
  let existed = fileExists(path)
  var onDisk: seq[byte]
  if existed: onDisk = toBytes(readFile(path))
  (futVal(sf).success, onDisk, existed)

proc rrqServed(filename: string): bool =
  createDir(serverRoot)
  let cfg = newDefaultServerConfig(serverRoot)
  let request = TftpPacket(opcode: opRrq, filename: filename, mode: tmOctet,
                           options: @[])
  let serverF = handleRrq(cfg, request, makeTransport(newWire(), true), "peer", 0)
  let done = driveOne(serverF)
  done and futVal(serverF).success

# --- concurrent runners (interleaved on one event loop) ---------------------

proc serveTwoRrq(c1, c2: seq[byte]): tuple[ok: bool, r1, r2: seq[byte]] =
  createDir(serverRoot)
  writeFile(serverRoot / "c1.bin", toStr(c1))
  writeFile(serverRoot / "c2.bin", toStr(c2))
  let (sf1, cf1, rec1) = setupRrq(newWire(), "c1.bin")
  let (sf2, cf2, rec2) = setupRrq(newWire(), "c2.bin")
  if not driveAll(@[sf1, cf1, sf2, cf2]): return (false, rec1[], rec2[])
  let ok = futVal(sf1).success and futVal(cf1).success and
           futVal(sf2).success and futVal(cf2).success
  (ok, rec1[], rec2[])

proc serveGetAndPut(getContent, putContent: seq[byte]):
    tuple[ok: bool, got, put: seq[byte]] =
  createDir(serverRoot)
  writeFile(serverRoot / "cget.bin", toStr(getContent))
  let (gsf, gcf, got) = setupRrq(newWire(), "cget.bin")
  let (psf, pcf) = setupWrq(newWire(), "cput.bin", putContent)
  if not driveAll(@[gsf, gcf, psf, pcf]): return (false, got[], @[])
  let ok = futVal(gsf).success and futVal(gcf).success and
           futVal(psf).success and futVal(pcf).success
  var put: seq[byte]
  if fileExists(serverRoot / "cput.bin"):
    put = toBytes(readFile(serverRoot / "cput.bin"))
  (ok, got[], put)

# Serve the directory-listing pseudo-file from a fresh root holding `files`.
proc serveListing(files: seq[(string, seq[byte])]): seq[byte] =
  let dir = serverRoot / "listing"
  removeDir(dir)
  createDir(dir)
  for (name, content) in files: writeFile(dir / name, toStr(content))
  var cfg = newDefaultServerConfig(dir)
  cfg.dirListFile = "__list__"
  let request = TftpPacket(opcode: opRrq, filename: "__list__", mode: tmOctet,
                           options: @[])
  let w = newWire()
  var received: seq[byte]
  let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
  let sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0)
  let cf = getFile(makeTransport(w, false, swallowFirst = true), clientConfig(),
                   "peer", 0, "__list__", onData)
  discard driveBoth(sf, cf)
  received

# Serve a file with md5 checksum mode on; return whether it succeeded and the
# sidecar contents written to disk. Takes a caller-supplied `Wire` (mirrors
# setupRrq) so later slices can inject loss/overwrite via the wire's action
# schedule, and an injectable `windowsize` (mirrors serveRrqNegotiated /
# setupRrqOpts): windowsize<=1 keeps today's optionless RRQ (no OACK
# handshake); windowsize>1 negotiates via buildClientOptions and runs the
# OACK handshake, same as setupRrqOpts. `cancelCheck` threads straight through
# to handleRrq (mirrors its own param) so a test can force a clean
# TransferResult(success: false) — e.g. behavior (c): a failed/aborted
# transfer must write no sidecar.
proc serveWithChecksum(content: seq[byte], w: Wire = newWire(),
                       windowsize = 1,
                       cancelCheck: proc(): bool {.closure.} = nil,
                       onProgress: ProgressCallback = nil):
    tuple[ok: bool, sidecar: string, received: seq[byte]] =
  let dir = serverRoot / "checksum"
  removeDir(dir)
  createDir(dir)
  writeFile(dir / "f.bin", toStr(content))
  var cfg = newDefaultServerConfig(dir)
  cfg.checksumMode = csMd5
  var received: seq[byte]
  let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
  var sf, cf: Future[TransferResult]
  if windowsize <= 1:
    let request = TftpPacket(opcode: opRrq, filename: "f.bin", mode: tmOctet,
                             options: @[])
    sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0,
                   onProgress = onProgress, cancelCheck = cancelCheck)
    cf = getFile(makeTransport(w, false, swallowFirst = true), clientConfig(),
                 "peer", 0, "f.bin", onData)
  else:
    let opts = buildClientOptions(
      newTransferConfig(blocksize = DefaultBlocksize, windowsize = windowsize),
      requestTsize = false)
    let request = TftpPacket(opcode: opRrq, filename: "f.bin", mode: tmOctet,
                             options: opts)
    var ccfg = newDefaultConfig()
    ccfg.blocksize = DefaultBlocksize
    ccfg.windowsize = windowsize
    ccfg.requestTsize = false
    sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0,
                   onProgress = onProgress, cancelCheck = cancelCheck)
    cf = getFile(makeTransport(w, false, swallowFirst = true), ccfg,
                 "peer", 0, "f.bin", onData)
  discard driveBoth(sf, cf)
  let ok = futVal(sf).success and futVal(cf).success
  var sidecar = ""
  if fileExists(dir / "f.bin.md5"): sidecar = readFile(dir / "f.bin.md5")
  (ok, sidecar, received)

# Serve an RRQ with pxeCompat on; return the option keys the server put in its
# OACK (the first packet it sends).
proc pxeOackOptions(blksize, windowsize: int): seq[(string, string)] =
  let dir = serverRoot / "pxe"
  removeDir(dir)
  createDir(dir)
  writeFile(dir / "f.bin", "hello pxe world")
  var cfg = newDefaultServerConfig(dir)
  cfg.pxeCompat = true
  let request = TftpPacket(opcode: opRrq, filename: "f.bin", mode: tmOctet,
    options: @[("blksize", $blksize), ("windowsize", $windowsize), ("tsize", "0")])
  let w = newWire()
  var received: seq[byte]
  let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
  let sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0)
  let cf = getFile(makeTransport(w, false, swallowFirst = true), clientConfig(),
                   "peer", 0, "f.bin", onData)
  discard driveBoth(sf, cf)
  if w.aLog.len == 0: return @[]
  let oack = decode(w.aLog[0])
  if oack.opcode != opOack: return @[]
  oack.oackOptions

# --- strategies -------------------------------------------------------------

proc fileBytes(maxLen = 1024): Strategy[seq[byte]] =
  lists(integers(0, 255), minLen = 0, maxLen = maxLen).map(toByteSeq)

proc traversalNames(): Strategy[string] =
  lists(sampledFrom(@['a', 'b', 'c', '.', '/']), minLen = 1, maxLen = 8).map(
    proc(cs: seq[char]): string =
      result = "../"
      for c in cs: result.add c)

proc missingNames(): Strategy[string] =
  lists(sampledFrom(@['a', 'b', 'c', 'd', 'e', '0', '1', '2']),
        minLen = 1, maxLen = 8).map(
    proc(cs: seq[char]): string =
      result = "missing_"
      for c in cs: result.add c)

# --- properties -------------------------------------------------------------

suite "server handler properties (end-to-end over the wire)":

  property "RRQ serves an arbitrary file; the client receives it intact":
    given content in fileBytes()
    let r = serveRrq(content)
    ensure r.ok and r.received == content

  property "WRQ stores an arbitrary upload; the server writes it intact":
    given content in fileBytes()
    let r = recvWrq(content)
    ensure r.ok and r.written == content

  property "RRQ for a path-traversal filename is refused, never served":
    given seg in traversalNames()
    ensure not rrqServed(seg)

  property "RRQ for a non-existent file is refused":
    given name in missingNames()
    if fileExists(serverRoot / name): removeFile(serverRoot / name)
    ensure not rrqServed(name)

suite "server write-policy enforcement (end-to-end)":

  property "wpDeny refuses every upload and writes nothing":
    given content in fileBytes(512)
    let r = wrqUnderPolicy(wpDeny, content, "wp.bin")
    ensure (not r.serverOk) and (not r.existed)

  property "wpOverwrite refuses creating a new file":
    given content in fileBytes(512)
    let r = wrqUnderPolicy(wpOverwrite, content, "wp.bin")
    ensure (not r.serverOk) and (not r.existed)

  property "wpCreateOnly refuses overwriting; the original is preserved":
    given original in fileBytes(512), attempt in fileBytes(512)
    let r = wrqUnderPolicy(wpCreateOnly, attempt, "wp.bin", original, true)
    ensure (not r.serverOk) and r.existed and r.onDisk == original

  property "wpCreateOrOverwrite replaces an existing file":
    given original in fileBytes(512), replacement in fileBytes(512)
    let r = wrqUnderPolicy(wpCreateOrOverwrite, replacement, "wp.bin",
                           original, true)
    ensure r.serverOk and r.onDisk == replacement

suite "server concurrency isolation":

  property "two concurrent RRQ transfers complete independently":
    given c1 in fileBytes(768), c2 in fileBytes(768)
    let r = serveTwoRrq(c1, c2)
    ensure r.ok and r.r1 == c1 and r.r2 == c2

  property "a concurrent GET and PUT do not interfere":
    given getContent in fileBytes(768), putContent in fileBytes(768)
    let r = serveGetAndPut(getContent, putContent)
    ensure r.ok and r.got == getContent and r.put == putContent

suite "server option negotiation (end-to-end)":

  property "RRQ with a negotiated blocksize completes intact":
    given content in fileBytes(1500),
          blocksize in integers(16, 1024)
    let r = serveRrqNegotiated(content, blocksize, 1)
    ensure r.ok and r.received == content

  property "RRQ with a negotiated window completes intact":
    given content in fileBytes(1500),
          blocksize in integers(64, 512),
          windowsize in integers(1, 6)
    let r = serveRrqNegotiated(content, blocksize, windowsize)
    ensure r.ok and r.received == content

suite "server features (listing, checksum)":

  property "directory listing reports every file with its size":
    given ca in fileBytes(300), cb in fileBytes(300), cc in fileBytes(300)
    let listing = toStr(serveListing(@[("a.bin", ca), ("b.bin", cb),
                                       ("c.bin", cc)]))
    ensure ("a.bin\t" & $ca.len) in listing and
           ("b.bin\t" & $cb.len) in listing and
           ("c.bin\t" & $cc.len) in listing

  property "RRQ with md5 checksum mode writes a correct sidecar":
    given content in fileBytes(512)
    let r = serveWithChecksum(content)
    ensure r.ok and r.sidecar.startsWith($toMD5(toStr(content)))

  property "RRQ with md5 checksum mode writes a correct sidecar under a negotiated window":
    given content in fileBytes(1500)
    let r = serveWithChecksum(content, newWire(), windowsize = 3)
    ensure r.ok and r.sidecar.startsWith($toMD5(toStr(content)))

  test "RRQ with md5 checksum mode on a zero-byte file writes the empty-content digest":
    # The single DATA block is the empty terminating block (hitFinal on send
    # #1) — must be fed to the digester as a zero-length no-op, not skipped.
    let content: seq[byte] = @[]
    let r = serveWithChecksum(content)
    check r.ok and r.sidecar.startsWith($toMD5(""))

  test "RRQ with md5 checksum mode survives a dup-ACK retransmit (static-file sanity)":
    # dropAOcc=1 drops DATA(2)'s first transmission, forcing the #18 dup-ACK
    # fast-retransmit. This is a no-corruption check on a STATIC file — it does
    # not by itself distinguish the windowCache-replay design from a naive
    # re-readData-on-resend design (slice 2's TOCTOU-mutation test does that).
    var content = newSeq[byte](1200)
    for i in 0 ..< content.len: content[i] = byte(i mod 256)
    let r = serveWithChecksum(content, newWire(dropAOcc = 1))
    check r.ok and r.sidecar.startsWith($toMD5(toStr(content)))

  test "TOCTOU: sidecar attests delivered bytes across a mutation spanned by a dup-ACK retransmit":
    # This is the real D1 proof (RFC slice 2). Neither a mid-transfer overwrite
    # alone nor a dup-ACK retransmit alone exercises the bug — round-1 depth
    # finding: a naive design that re-reads the file on resend serves NEW bytes
    # to the client on the retransmit while a "hash at first send" digest would
    # have already committed to the OLD bytes for that block. Combine both:
    #
    #   - 3-block file: 16384 + 16384 + a short final block.
    #   - Mutate the on-disk file (different content, same length so only the
    #     byte VALUES differ, not the block layout) right after block 2's
    #     first send is cached — before the client ever sees it.
    #   - dropAOcc drops DATA(2)'s first transmission, so recvBlocks times out
    #     waiting for it and re-ACKs block 1; the #18 dup-ACK fast-retransmit
    #     then resends block 2 — AFTER the mutation.
    #
    # A large negotiated blocksize (16384) is deliberate, not cosmetic: each
    # readData call requests far more than a libc/CRT stdio buffer's default
    # size, so a resend's fresh read is a genuine large read from the current
    # file state rather than being served from a small internal read-ahead
    # buffer already populated (and thus blind to the mutation) — otherwise
    # this test can't discriminate the two designs at all, since NEITHER
    # design's "fresh" read would ever observe the write.
    #
    # Trigger index: onProgress (transfer.nim:27) fires once per sendOneBlock
    # call — every first send AND every resend, but never for the OACK (that's
    # sent directly by handleRrq, not through sendOneBlock) — so a plain
    # invocation counter reliably identifies "block 2's first send" as call #2
    # here (call #1 = block 1's first send) REGARDLESS of windowsize/OACK.
    # (What *does* shift with a negotiating variant is a wire-occurrence index
    # like dropAOcc — negotiating blksize alone still inserts one OACK send
    # before any DATA, so dropAOcc=2 here: occ 0 = OACK, 1 = DATA(1),
    # 2 = DATA(2)'s first send.)
    const bs = 16384
    var original = newSeq[byte](bs * 2 + 500)
    for i in 0 ..< original.len: original[i] = byte(i mod 256)
    var mutated = newSeq[byte](original.len)
    for i in 0 ..< mutated.len: mutated[i] = 0xAA

    let dir = serverRoot / "toctou"
    removeDir(dir)
    createDir(dir)
    let path = dir / "f.bin"
    writeFile(path, toStr(original))

    var calls = 0
    let onProgress = proc(bytesTransferred, totalSize: int64) =
      inc calls
      if calls == 2:                       # block 2's first (soon-dropped) send
        writeFile(path, toStr(mutated))    # mutate mid-transfer, after caching

    var cfg = newDefaultServerConfig(dir)
    cfg.checksumMode = csMd5
    let opts = buildClientOptions(
      newTransferConfig(blocksize = bs, windowsize = 1), requestTsize = false)
    let request = TftpPacket(opcode: opRrq, filename: "f.bin", mode: tmOctet,
                             options: opts)
    var ccfg = newDefaultConfig()
    ccfg.blocksize = bs
    ccfg.windowsize = 1
    ccfg.requestTsize = false
    let w = newWire(dropAOcc = 2)  # drop DATA(2)'s first transmission (occ 0 = OACK)
    var received: seq[byte]
    let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
    let sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0,
                       onProgress = onProgress)
    let cf = getFile(makeTransport(w, false, swallowFirst = true), ccfg,
                     "peer", 0, "f.bin", onData)
    check driveBoth(sf, cf)
    check futVal(sf).success and futVal(cf).success

    let sidecar = readFile(path & ".md5")
    let deliveredDigest = $toMD5(toStr(received))
    let originalDigest = $toMD5(toStr(original))
    let mutatedDigest = $toMD5(toStr(mutated))
    # The sidecar attests exactly what the client received — never the
    # pre-mutation nor the fully-post-mutation content.
    check sidecar.startsWith(deliveredDigest)
    check not sidecar.startsWith(originalDigest)
    check not sidecar.startsWith(mutatedDigest)

  # A windowsize>=2 variant (cumulative ACK + mutation) was attempted here and
  # is deliberately NOT included: it passed under both the real cached design
  # AND the temporarily-reverted naive re-read design, i.e. it doesn't
  # discriminate the two designs. Root cause: with more blocks already
  # ACKed before the drop, the loss can be resolved by the *server's own*
  # recvPacket-level timeout retry (transfer.nim's recvPacket resends the
  # literal already-encoded `lastSentPacket` bytes on ITS OWN timeout — a raw
  # buffer replay that never calls sendOneBlock/readData again), which races
  # the client's dup-ACK-driven fillWindow() resend (the only path that
  # actually re-invokes sendOneBlock and is sensitive to the cache-vs-fresh-
  # read distinction). Which one resolves the loss first is a function of
  # exact async-scheduling parity between the two sides and isn't reliably
  # steerable from test code, so a green result here doesn't mean what it
  # would appear to mean. The windowsize=1 combination test above is the
  # RFC's mandatory proof and reliably distinguishes the designs (verified:
  # RED against a temporarily-reverted naive readData-on-resend, GREEN
  # against the real windowCache-replay design).

  test "a cancelled RRQ transfer writes no checksum sidecar":
    # A clean cancel (existing cancelCheck mechanism) yields
    # TransferResult(success: false) with zero blocks ever confirmed
    # delivered — commit() must never run, so no .md5 file appears.
    let content = newSeq[byte](2048)
    let cancelNow = proc(): bool = true
    let r = serveWithChecksum(content, cancelCheck = cancelNow)
    check (not r.ok) and r.sidecar.len == 0

  test "RRQ with md5 checksum still succeeds when the sidecar path is a pre-planted escaping symlink (slice 4)":
    # RFC checksum-integrity-error-hygiene, Ds (fixes defect 4). Plant
    # `f.bin.md5` as a symlink to a file OUTSIDE the server root before the
    # RRQ runs. writeSidecar's containment + unconditional symlinkExists
    # refusal must refuse the write WITHOUT raising — so the RRQ transfer
    # itself still completes successfully, and the outside target is left
    # untouched (never clobbered with sidecar text).
    let dir = serverRoot / "checksum_escape"
    removeDir(dir)
    createDir(dir)
    let outsideDir = getTempDir() / "chapulin_props_server_outside"
    removeDir(outsideDir)
    createDir(outsideDir)
    let outsideTarget = outsideDir / "escape_target.txt"
    writeFile(outsideTarget, "original outside content")

    let content = toBytes("hello from the sidecar escape test")
    writeFile(dir / "f.bin", toStr(content))

    var symlinkOk = true
    try:
      createSymlink(outsideTarget, dir / "f.bin.md5")
    except OSError, IOError:
      symlinkOk = false

    if not symlinkOk:
      checkpoint("symlink creation unsupported here — sidecar escape e2e test skipped")
      skip()
    else:
      var cfg = newDefaultServerConfig(dir)
      cfg.checksumMode = csMd5
      let request = TftpPacket(opcode: opRrq, filename: "f.bin", mode: tmOctet,
                               options: @[])
      let w = newWire()
      var received: seq[byte]
      let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
      let sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0)
      let cf = getFile(makeTransport(w, false, swallowFirst = true), clientConfig(),
                       "peer", 0, "f.bin", onData)
      check driveBoth(sf, cf)
      check futVal(sf).success and futVal(cf).success
      check received == content
      # Containment refused the sidecar write: the planted symlink is left
      # exactly as it was, and the outside target it points to was never
      # overwritten with sidecar text.
      check symlinkExists(dir / "f.bin.md5")
      check readFile(outsideTarget) == "original outside content"
      removeFile(dir / "f.bin.md5")

    removeDir(dir)
    removeDir(outsideDir)

  test "RRQ of an existing .md5 sidecar does not chain into foo.md5.md5 (M1)":
    # RFC checksum-integrity-error-hygiene reserved-namespace cluster, M1.
    # handleRrq must not generate a sidecar-of-a-sidecar: serving a file
    # that is ITSELF a reserved .md5 name (e.g. because a client legitimately
    # downloads a sidecar to verify a prior transfer) must still succeed as
    # a read, but must not commit a new foo.md5.md5 next to it — otherwise
    # each RRQ of the newest sidecar grows an unbounded, client-driven chain.
    let dir = serverRoot / "m1_no_chain"
    removeDir(dir)
    createDir(dir)
    let sidecarContent = toBytes("deadbeef  foo\n")
    writeFile(dir / "foo.md5", toStr(sidecarContent))

    var cfg = newDefaultServerConfig(dir)
    cfg.checksumMode = csMd5
    let request = TftpPacket(opcode: opRrq, filename: "foo.md5", mode: tmOctet,
                             options: @[])
    let w = newWire()
    var received: seq[byte]
    let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
    let sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0)
    let cf = getFile(makeTransport(w, false, swallowFirst = true), clientConfig(),
                     "peer", 0, "foo.md5", onData)
    check driveBoth(sf, cf)
    check futVal(sf).success and futVal(cf).success
    check received == sidecarContent

    check not fileExists(dir / "foo.md5.md5")
    removeDir(dir)

  test "WRQ to an in-root symlink aliasing a real .md5 sidecar is rejected, sidecar unchanged (H1)":
    # RFC checksum-integrity-error-hygiene reserved-namespace cluster, H1.
    # Full e2e proof (over handleWrq, not just checkWriteAccess directly):
    # plant an in-root symlink `alias -> legit.md5` where legit.md5 already
    # holds a real sidecar's content, then WRQ `alias`. validatePath's
    # containment check follows the symlink and allows it (legit.md5 is
    # in-root), and the alias's own lexical name doesn't end in ".md5" — so
    # without the canonicalize-based check in checkWriteAccess, the WRQ
    # would proceed to open(resolvedPath, fmWrite), which the OS resolves
    # through the symlink, silently overwriting legit.md5. Requires a real
    # symlink (Linux compose container only — Windows expandFilename does
    # not resolve symlinks, so this test is a no-op skip there).
    let dir = serverRoot / "h1_symlink_alias"
    removeDir(dir)
    createDir(dir)
    let legitContent = "deadbeef  legit\n"
    writeFile(dir / "legit.md5", legitContent)

    var symlinkOk = true
    try:
      createSymlink(dir / "legit.md5", dir / "alias")
    except OSError, IOError:
      symlinkOk = false

    if not symlinkOk:
      checkpoint("symlink creation unsupported here — H1 e2e test skipped")
      skip()
    # Capability probe (K1): the fix depends on canonicalize/expandFilename
    # actually resolving the symlink to its real target — best-effort on
    # Windows (expandFilename does not resolve symlinks/junctions there,
    # an accepted limit). A Windows container that (unlike a typical
    # unprivileged CI runner) holds the symlink-create privilege can still
    # create `alias` but canonicalize won't see through it; detect that
    # here with the exact predicate the fix itself calls rather than
    # asserting a security property this platform structurally cannot
    # provide.
    elif not isReservedSidecarName(canonicalize(dir / "alias")):
      checkpoint("platform cannot resolve the symlink to its real path here " &
                 "(K1: best-effort on Windows) — H1 e2e assertion skipped")
      skip()
      removeFile(dir / "alias")
    else:
      var cfg = newDefaultServerConfig(dir)
      cfg.checksumMode = csMd5
      cfg.writePolicy = wpCreateOrOverwrite
      let forged = toBytes("forged digest, attacker-controlled")
      let request = TftpPacket(opcode: opWrq, filename: "alias", mode: tmOctet,
                               options: @[])
      let readData = proc(blockNum: uint16, bs: int): seq[byte] =
        let start = (int(blockNum) - 1) * bs
        if start >= forged.len: return @[]
        return forged[start ..< min(start + bs, forged.len)]
      let w = newWire()
      let cf = putFile(makeTransport(w, true, swallowFirst = true), clientConfig(),
                       "peer", 0, "alias", readData)
      let sf = handleWrq(cfg, request, makeTransport(w, false), "peer", 0)
      check driveBoth(sf, cf)
      check not futVal(sf).success

      check readFile(dir / "legit.md5") == legitContent
      removeFile(dir / "alias")

    removeDir(dir)

  test "WRQ to f.bin.md5 is rejected under csMd5, and a legitimate sidecar survives (slice 5)":
    # RFC checksum-integrity-error-hygiene, Ds (fixes defect 5 — reserved
    # namespace, Invariant 6). A legitimate csMd5 RRQ of f.bin first writes a
    # real sidecar; a subsequent WRQ targeting f.bin.md5 directly must be
    # refused by checkWriteAccess's reservation even under
    # wpCreateOrOverwrite (the most permissive policy) — proving the
    # forged-attestation sink (defect 5) is closed and the real sidecar is
    # never clobbered.
    let dir = serverRoot / "slice5_reserved"
    removeDir(dir)
    createDir(dir)
    let content = toBytes("legit content for slice 5 e2e")
    writeFile(dir / "f.bin", toStr(content))

    var cfg = newDefaultServerConfig(dir)
    cfg.checksumMode = csMd5
    let request = TftpPacket(opcode: opRrq, filename: "f.bin", mode: tmOctet,
                             options: @[])
    let w = newWire()
    var received: seq[byte]
    let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
    let sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0)
    let cf = getFile(makeTransport(w, false, swallowFirst = true), clientConfig(),
                     "peer", 0, "f.bin", onData)
    check driveBoth(sf, cf)
    check futVal(sf).success and futVal(cf).success

    let sidecarPath = dir / "f.bin.md5"
    check fileExists(sidecarPath)
    let legitSidecar = readFile(sidecarPath)

    # wrqUnderPolicy removes any pre-existing target unless told it's
    # expected (hasPreExisting) — pass the real sidecar's own bytes through
    # that path so the helper's setup doesn't itself delete the very file
    # we're proving survives (mirrors the "wpCreateOnly preserves the
    # original" pattern above).
    let forged = toBytes("forged digest, attacker-controlled")
    let r = wrqUnderPolicy(wpCreateOrOverwrite, forged, "f.bin.md5",
                           toBytes(legitSidecar), true,
                           checksumMode = csMd5, dir = dir)
    check not r.serverOk

    # The legitimate sidecar is untouched by the refused WRQ.
    check r.existed
    check r.onDisk == toBytes(legitSidecar)
    check readFile(sidecarPath) == legitSidecar

    removeDir(dir)

  property "pxeCompat keeps only tsize in the OACK (blksize/windowsize stripped)":
    given blksize in integers(16, 1024), windowsize in integers(2, 8)
    var keys: seq[string]
    for (k, _) in pxeOackOptions(blksize, windowsize): keys.add k.toLowerAscii
    ensure ("tsize" in keys) and ("blksize" notin keys) and
           ("windowsize" notin keys)

# --- model-based sequence testing -------------------------------------------
# Replay a generated sequence of uploads/downloads against a fresh server root
# and a reference model (filename -> expected bytes). proptest shrinks the
# sequence to a minimal failing trace.

type
  OpKind = enum okPut, okGet
  Op = object
    kind: OpKind
    name: string
    content: seq[byte]

proc opStrategy(): Strategy[Op] =
  # Pass-biased toward Put so Gets land on existing files; small name set so
  # operations collide (overwrite, get-after-put).
  sampledFrom(@[okPut, okPut, okGet]).flatMap(proc(k: OpKind): Strategy[Op] =
    sampledFrom(@["a.bin", "b.bin", "c.bin"]).flatMap(proc(n: string): Strategy[Op] =
      fileBytes(256).map(proc(c: seq[byte]): Op =
        Op(kind: k, name: n, content: c))))

proc wrqTo(dir, name: string, content: seq[byte]): bool =
  var cfg = newDefaultServerConfig(dir)
  cfg.writePolicy = wpCreateOrOverwrite
  let request = TftpPacket(opcode: opWrq, filename: name, mode: tmOctet,
                           options: @[])
  let readData = proc(blockNum: uint16, bs: int): seq[byte] =
    let start = (int(blockNum) - 1) * bs
    if start >= content.len: return @[]
    return content[start ..< min(start + bs, content.len)]
  let w = newWire()
  let cf = putFile(makeTransport(w, true, swallowFirst = true), clientConfig(),
                   "peer", 0, name, readData)
  let sf = handleWrq(cfg, request, makeTransport(w, false), "peer", 0)
  discard driveBoth(sf, cf)
  futVal(sf).success and futVal(cf).success

proc rrqFrom(dir, name: string): tuple[ok: bool, got: seq[byte]] =
  let cfg = newDefaultServerConfig(dir)
  let request = TftpPacket(opcode: opRrq, filename: name, mode: tmOctet,
                           options: @[])
  let w = newWire()
  var received: seq[byte]
  let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
  let sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0)
  let cf = getFile(makeTransport(w, false, swallowFirst = true), clientConfig(),
                   "peer", 0, name, onData)
  discard driveBoth(sf, cf)
  (futVal(sf).success and futVal(cf).success, received)

suite "server filesystem model (operation sequences)":

  property "uploads and downloads stay consistent with a file model":
    given ops in lists(opStrategy(), minLen = 0, maxLen = 12)
    let dir = serverRoot / "model"
    removeDir(dir)
    createDir(dir)
    var model = initTable[string, seq[byte]]()
    var ok = true
    for op in ops:
      case op.kind
      of okPut:
        if wrqTo(dir, op.name, op.content): model[op.name] = op.content
        else: ok = false
      of okGet:
        let (gok, got) = rrqFrom(dir, op.name)
        if op.name in model:
          if not (gok and got == model[op.name]): ok = false
        elif gok:
          ok = false        # downloading a never-uploaded file must fail
    ensure ok

# Regression guard for https://github.com/coreyleavitt/chapulin/issues/16. The
# server negotiates and OACKs a windowsize; before the fix it never APPLIED it
# (handleRrq set only blocksize/totalSize), so it sent lock-step. Transfers still
# completed — the client's window never filled, the server timed out and
# retransmitted each block, and the duplicate-re-ACK unblocked it — but every
# block cost a retransmit (~2 packets/block), pathologically slow on a real
# network. handleRrq now copies neg.windowsize into xferConfig, so a windowed
# RRQ sends ~one DATA per block.
suite "server windowsize efficiency (issue #16)":
  test "a windowed RRQ sends ~one DATA per block (no per-block retransmit)":
    createDir(serverRoot)
    var content = newSeq[byte](2000)       # blocksize 100 => 20 blocks + final
    for i in 0 ..< content.len: content[i] = byte(i and 0xFF)
    writeFile(serverRoot / "win.bin", toStr(content))
    let w = newWire()
    let (sf, cf, received) = setupRrqOpts(w, "win.bin", 100, 8)
    discard driveBoth(sf, cf)
    check received[] == content            # correctness still holds
    # ~21 DATA + 1 OACK when windowsize is applied; ~2x that with the bug.
    check w.aSends() <= 25
