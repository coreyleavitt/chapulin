## Property-based tests for chapulin's pure layers (proptest engine).
##
## Restores the coverage of the removed libFuzzer harnesses as properties:
## protocol decode safety + roundtrip, option parsing, path validation, and
## URI parsing. Decode/parse "safety" properties assert the codec either
## succeeds or raises ONLY its declared error type — any other exception or
## Defect (IndexDefect, RangeDefect, …) propagates and proptest reports it as
## a shrunk falsification.
##
## Run in the nim devtools container (deps resolved on the host by milpa):
##   docker run --rm -v ${PWD}:C:\app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r tests/t_props.nim

import std/unittest
import std/[strutils, os]
import proptest

import ../src/chapulin/protocol
import ../src/chapulin/options
import ../src/chapulin/security
import ../src/chapulin/tftp_uri
import ../src/chapulin/transfer       # newPeer, updateRtt, effectiveTimeout
import ../src/chapulin/server_config  # ServerConfig, checkHostAccess inputs

# Structural equality for the variant packet — Nim's auto-generated `==` uses a
# parallel `fields` iterator that rejects case objects, so define it explicitly.
proc `==`(a, b: TftpPacket): bool =
  if a.opcode != b.opcode: return false
  case a.opcode
  of opRrq, opWrq:
    a.filename == b.filename and a.mode == b.mode and a.options == b.options
  of opData: a.blockNum == b.blockNum and a.data == b.data
  of opAck: a.ackBlockNum == b.ackBlockNum
  of opError: a.errorCode == b.errorCode and a.errorMsg == b.errorMsg
  of opOack: a.oackOptions == b.oackOptions

# --- generators ---------------------------------------------------------------

proc toByteSeq(xs: seq[int]): seq[byte] =
  result = newSeq[byte](xs.len)
  for i, x in xs: result[i] = byte(x and 0xFF)

proc byteSeqs(maxLen = 600): Strategy[seq[byte]] =
  ## Arbitrary wire bytes — the decode fuzzing surface.
  lists(integers(0, 255), minLen = 0, maxLen = maxLen).map(toByteSeq)

proc charsToStr(cs: seq[char]): string =
  result = newStringOfCap(cs.len)
  for c in cs: result.add c

const SafeAlphabet = @['a', 'b', 'c', 'x', 'Y', 'Z', '0', '9', '.', '_', '-']

proc safeStrings(minLen = 0, maxLen = 16): Strategy[string] =
  ## NUL-free, separator-free strings — safe to round-trip through C-string
  ## wire fields (filenames, option keys/values, error messages).
  lists(sampledFrom(SafeAlphabet), minLen = minLen, maxLen = maxLen).map(charsToStr)

proc kvPair(): Strategy[(string, string)] =
  safeStrings(1, 8).flatMap(proc(k: string): Strategy[(string, string)] =
    safeStrings(1, 8).map(proc(v: string): (string, string) = (k, v)))

proc kvPairs(maxLen = 3): Strategy[seq[(string, string)]] =
  lists(kvPair(), minLen = 0, maxLen = maxLen)

# Path-stressing alphabet: separators, dot-dot fuel, embedded NUL, drive colon.
const PathAlphabet = @['a', 'b', '.', '/', '\\', '\0', ':', ' ', 't']

proc pathStrings(maxLen = 24): Strategy[string] =
  lists(sampledFrom(PathAlphabet), minLen = 0, maxLen = maxLen).map(charsToStr)

# URI-stressing alphabet, always scheme-prefixed so the parser's interesting
# branches (host/port/IPv6/mode) are actually reached.
const UriAlphabet = @['a', '1', '.', ':', '/', '[', ']', ';', '=', '-', 'b']

proc uriStrings(maxLen = 30): Strategy[string] =
  lists(sampledFrom(UriAlphabet), minLen = 0, maxLen = maxLen).map(
    proc(cs: seq[char]): string = "tftp://" & charsToStr(cs))

# Option pairs with numeric values (no parse failures) — for negotiation
# invariants that should hold whenever the values actually parse.
proc numericOptionPairs(maxLen = 4): Strategy[seq[(string, string)]] =
  let pair = sampledFrom(@["blksize", "windowsize", "timeout", "tsize"]).flatMap(
    proc(k: string): Strategy[(string, string)] =
      integers(-100, 200_000).map(proc(n: int): (string, string) = (k, $n)))
  lists(pair, minLen = 0, maxLen = maxLen)

# Filenames guaranteed to contain a `..` segment.
proc traversalNames(): Strategy[string] =
  safeStrings(0, 6).flatMap(proc(a: string): Strategy[string] =
    safeStrings(0, 6).map(proc(b: string): string = a & "/../" & b))

const NegLimits = ServerOptionLimits(
  maxBlocksize: 65464, minBlocksize: 8, timeout: 5,
  maxWindowsize: 64, minWindowsize: 1)

# --- properties ---------------------------------------------------------------

suite "protocol codec properties":

  property "decode either returns a packet or raises TftpDecodeError":
    given data in byteSeqs()
    let ok =
      try:
        discard decode(data)
        true
      except TftpDecodeError:
        true
    ensure ok

  property "roundtrip: ACK":
    given b in integers(0, 65535)
    let pkt = TftpPacket(opcode: opAck, ackBlockNum: uint16(b))
    ensure decode(encode(pkt)) == pkt

  property "roundtrip: DATA":
    given b in integers(0, 65535), payload in byteSeqs(512)
    let pkt = TftpPacket(opcode: opData, blockNum: uint16(b), data: payload)
    ensure decode(encode(pkt)) == pkt

  property "roundtrip: ERROR":
    given code in integers(0, 7), msg in safeStrings(0, 24)
    let pkt = TftpPacket(opcode: opError,
                         errorCode: TftpErrorCode(code), errorMsg: msg)
    ensure decode(encode(pkt)) == pkt

  property "roundtrip: RRQ/WRQ with options":
    given isRead in booleans(),
          fn in safeStrings(1, 20),
          netascii in booleans(),
          opts in kvPairs()
    let mode = if netascii: tmNetascii else: tmOctet
    let pkt =
      if isRead: TftpPacket(opcode: opRrq, filename: fn, mode: mode, options: opts)
      else: TftpPacket(opcode: opWrq, filename: fn, mode: mode, options: opts)
    ensure decode(encode(pkt)) == pkt

  property "roundtrip: OACK":
    given opts in kvPairs(5)
    let pkt = TftpPacket(opcode: opOack, oackOptions: opts)
    ensure decode(encode(pkt)) == pkt

suite "option negotiation properties":

  property "negotiateServerOptions never OACKs an unsolicited option":
    # RFC 2347: the server may only acknowledge options the client requested.
    given opts in numericOptionPairs()
    let (_, oack) = negotiateServerOptions(opts, NegLimits)
    var requested: seq[string]
    for (k, _) in opts: requested.add k.toLowerAscii
    var ok = true
    for (k, _) in oack:
      if k.toLowerAscii notin requested: ok = false
    ensure ok

  property "negotiateServerOptions clamps blocksize/windowsize to server limits":
    given opts in numericOptionPairs()
    let (neg, _) = negotiateServerOptions(opts, NegLimits)
    ensure neg.blocksize >= NegLimits.minBlocksize and
           neg.blocksize <= NegLimits.maxBlocksize and
           neg.windowsize >= NegLimits.minWindowsize and
           neg.windowsize <= NegLimits.maxWindowsize

suite "security properties":

  property "validatePath never escapes root, never crashes":
    given fn in pathStrings()
    const root = "tftproot"
    let (valid, resolved, _) = validatePath(root, fn)
    ensure (not valid) or resolved.startsWith(absolutePath(root))

  property "validatePath rejects any path containing a .. segment":
    given fn in traversalNames()
    let (valid, _, _) = validatePath("tftproot", fn)
    ensure not valid

suite "uri parsing properties":

  property "parseTftpUri either parses or raises TftpUriError":
    given s in uriStrings()
    let ok =
      try:
        discard parseTftpUri(s)
        true
      except TftpUriError:
        true
    ensure ok

  property "parseTftpUri round-trips host:port/file;mode":
    given host in safeStrings(1, 10), port in integers(1, 65535),
          file in safeStrings(1, 12), netascii in booleans()
    let mode = if netascii: "netascii" else: "octet"
    let uri = "tftp://" & host & ":" & $port & "/" & file & ";mode=" & mode
    let parsed = parseTftpUri(uri)
    ensure parsed.host == host and parsed.port == port and
           parsed.filename == file and parsed.mode == mode

suite "adaptive timeout properties (RFC 1123 / Jacobson)":

  property "adaptive timeout stays >= 1000ms after any RTT samples":
    given samples in lists(integers(0, 100_000), minLen = 1, maxLen = 20)
    let peer = newPeer("h", 1)
    for s in samples: peer.updateRtt(float(s))
    ensure peer.adaptiveTimeout >= 1000

  property "effectiveTimeout uses the adaptive value once measured, else config":
    given samples in lists(integers(0, 100_000), minLen = 0, maxLen = 10),
          cfgTimeout in integers(1, 30_000)
    let peer = newPeer("h", 1)
    for s in samples: peer.updateRtt(float(s))
    let eff = peer.effectiveTimeout(cfgTimeout)
    ensure (if samples.len == 0: eff == cfgTimeout else: eff >= 1000)

suite "host access control properties":

  proc hostNames(): Strategy[string] =
    sampledFrom(@["10.0.0.1", "10.0.0.2", "192.168.1.1", "::1", "127.0.0.1"])

  property "checkHostAccess: denylist wins; empty allowlist allows all":
    given host in hostNames(),
          allowed in lists(hostNames(), minLen = 0, maxLen = 4),
          denied in lists(hostNames(), minLen = 0, maxLen = 4)
    var cfg = newDefaultServerConfig("root")
    cfg.allowedHosts = allowed
    cfg.deniedHosts = denied
    let expected =
      if host in denied: false
      elif allowed.len == 0: true
      else: host in allowed
    ensure checkHostAccess(cfg, host) == expected
