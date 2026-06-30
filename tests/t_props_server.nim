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
                    preExisting: seq[byte] = @[], hasPreExisting = false):
    tuple[serverOk: bool, onDisk: seq[byte], existed: bool] =
  createDir(serverRoot)
  let path = serverRoot / fname
  if hasPreExisting: writeFile(path, toStr(preExisting))
  elif fileExists(path): removeFile(path)
  var cfg = newDefaultServerConfig(serverRoot)
  cfg.writePolicy = policy
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
# sidecar contents written to disk.
proc serveWithChecksum(content: seq[byte]): tuple[ok: bool, sidecar: string] =
  let dir = serverRoot / "checksum"
  removeDir(dir)
  createDir(dir)
  writeFile(dir / "f.bin", toStr(content))
  var cfg = newDefaultServerConfig(dir)
  cfg.checksumMode = "md5"
  let request = TftpPacket(opcode: opRrq, filename: "f.bin", mode: tmOctet,
                           options: @[])
  let w = newWire()
  var received: seq[byte]
  let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
  let sf = handleRrq(cfg, request, makeTransport(w, true), "peer", 0)
  let cf = getFile(makeTransport(w, false, swallowFirst = true), clientConfig(),
                   "peer", 0, "f.bin", onData)
  discard driveBoth(sf, cf)
  let ok = futVal(sf).success and futVal(cf).success
  var sidecar = ""
  if fileExists(dir / "f.bin.md5"): sidecar = readFile(dir / "f.bin.md5")
  (ok, sidecar)

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
