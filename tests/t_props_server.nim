## Property-based tests for the server request handlers (server.nim), end to end.
##
## Connects the REAL client engine (getFile / putFile) to the REAL server
## handlers (handleRrq / handleWrq) over the shared in-memory wire, against real
## temp files. Exercises path validation, the request->serve/store flow, and the
## file I/O on both sides for arbitrary payloads.
##
## Run in the nim devtools container (deps resolved on the host by milpa):
##   docker run --rm -v ${PWD}:C:\app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r tests/t_props_server.nim

import std/[unittest, os]
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

# RRQ: server serves a file on disk to a real client. Server drives a2b (DATA),
# client drives b2a (RRQ/ACK).
proc serveRrq(content: seq[byte]): tuple[ok: bool, received: seq[byte]] =
  createDir(serverRoot)
  let fname = "served.bin"
  writeFile(serverRoot / fname, toStr(content))
  let cfg = newDefaultServerConfig(serverRoot)
  let request = TftpPacket(opcode: opRrq, filename: fname, mode: tmOctet,
                           options: @[])
  var ccfg = newDefaultConfig()
  ccfg.requestTsize = false
  let w = newWire()
  var received: seq[byte]
  let onData = proc(blockNum: uint16, data: seq[byte]) = received.add data
  let serverF = handleRrq(cfg, request, makeTransport(w, true), "peer", 0)
  let clientF = getFile(makeTransport(w, false, swallowFirst = true), ccfg,
                        "peer", 0, fname, onData)
  if not driveBoth(serverF, clientF): return (false, received)
  return (futVal(serverF).success and futVal(clientF).success, received)

# WRQ: client uploads to the server, which stores it on disk. Client drives a2b
# (WRQ/DATA), server drives b2a (ACK).
proc recvWrq(content: seq[byte]): tuple[ok: bool, written: seq[byte]] =
  createDir(serverRoot)
  let fname = "uploaded.bin"
  var cfg = newDefaultServerConfig(serverRoot)
  cfg.writePolicy = wpCreateOrOverwrite
  let request = TftpPacket(opcode: opWrq, filename: fname, mode: tmOctet,
                           options: @[])
  var ccfg = newDefaultConfig()
  ccfg.requestTsize = false
  let readData = proc(blockNum: uint16, bs: int): seq[byte] =
    let start = (int(blockNum) - 1) * bs
    if start >= content.len: return @[]
    return content[start ..< min(start + bs, content.len)]
  let w = newWire()
  let clientF = putFile(makeTransport(w, true, swallowFirst = true), ccfg,
                        "peer", 0, fname, readData)
  let serverF = handleWrq(cfg, request, makeTransport(w, false), "peer", 0)
  if not driveBoth(serverF, clientF): return (false, @[])
  let ok = futVal(serverF).success and futVal(clientF).success
  var written: seq[byte]
  if fileExists(serverRoot / fname):
    written = toBytes(readFile(serverRoot / fname))
  return (ok, written)

# RRQ for a filename the server must refuse to serve.
proc rrqServed(filename: string): bool =
  createDir(serverRoot)
  let cfg = newDefaultServerConfig(serverRoot)
  let request = TftpPacket(opcode: opRrq, filename: filename, mode: tmOctet,
                           options: @[])
  let w = newWire()
  let serverF = handleRrq(cfg, request, makeTransport(w, true), "peer", 0)
  let done = driveOne(serverF)
  done and futVal(serverF).success

proc fileBytes(maxLen = 1024): Strategy[seq[byte]] =
  lists(integers(0, 255), minLen = 0, maxLen = maxLen).map(toByteSeq)

proc traversalNames(): Strategy[string] =
  lists(sampledFrom(@['a', 'b', 'c', '.', '/']), minLen = 1, maxLen = 8).map(
    proc(cs: seq[char]): string =
      result = "../"
      for c in cs: result.add c)

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
