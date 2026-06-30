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

const OptionKeys = @["blksize", "timeout", "windowsize", "tsize", "frobnicate"]

proc optionPair(): Strategy[(string, string)] =
  sampledFrom(OptionKeys).flatMap(proc(k: string): Strategy[(string, string)] =
    safeStrings(0, 10).map(proc(v: string): (string, string) = (k, v)))

proc optionPairs(maxLen = 4): Strategy[seq[(string, string)]] =
  lists(optionPair(), minLen = 0, maxLen = maxLen)

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

  property "parseOackOptions raises only ValueError on arbitrary pairs":
    given opts in optionPairs()
    let ok =
      try:
        discard parseOackOptions(opts)
        true
      except ValueError:
        true
    ensure ok

suite "security properties":

  property "validatePath never escapes root, never crashes":
    given fn in pathStrings()
    const root = "tftproot"
    let (valid, resolved, _) = validatePath(root, fn)
    ensure (not valid) or resolved.startsWith(absolutePath(root))

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
