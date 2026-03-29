## TFTP Protocol codec — pure packet encode/decode, no I/O.
## Implements RFC 1350 + RFC 2347/2348/2349 extensions.

import std/strutils

type
  TftpOpcode* = enum
    ## Wire opcodes are 1-6, but Nim variant discriminants must start at 0.
    ## Use opcodeToWire/wireToOpcode for conversion.
    opRrq = 0    ## Read Request (wire: 1)
    opWrq = 1    ## Write Request (wire: 2)
    opData = 2   ## Data (wire: 3)
    opAck = 3    ## Acknowledgment (wire: 4)
    opError = 4  ## Error (wire: 5)
    opOack = 5   ## Option Acknowledgment (wire: 6)

  TftpErrorCode* = enum
    errNotDefined = 0
    errFileNotFound = 1
    errAccessViolation = 2
    errDiskFull = 3
    errIllegalOperation = 4
    errUnknownTransferId = 5
    errFileAlreadyExists = 6
    errNoSuchUser = 7

  TransferMode* = enum
    tmOctet = "octet"
    tmNetascii = "netascii"

  TftpPacket* = object
    case opcode*: TftpOpcode
    of opRrq, opWrq:
      filename*: string
      mode*: TransferMode
      options*: seq[(string, string)]
    of opData:
      blockNum*: uint16
      data*: seq[byte]
    of opAck:
      ackBlockNum*: uint16
    of opError:
      errorCode*: TftpErrorCode
      errorMsg*: string
    of opOack:
      oackOptions*: seq[(string, string)]

  TftpDecodeError* = object of CatchableError

proc opcodeToWire*(op: TftpOpcode): uint16 =
  uint16(ord(op) + 1)

proc wireToOpcode*(wire: uint16): TftpOpcode =
  if wire < 1 or wire > 6:
    raise newException(TftpDecodeError, "Invalid opcode: " & $wire)
  TftpOpcode(wire - 1)

# --- Encoding helpers ---

proc addUint16BE(result: var seq[byte], val: uint16) =
  result.add byte(val shr 8)
  result.add byte(val and 0xFF)

proc addCString(result: var seq[byte], s: string) =
  for c in s:
    result.add byte(c)
  result.add 0

proc addOptions(result: var seq[byte], opts: seq[(string, string)]) =
  for (key, val) in opts:
    result.addCString(key)
    result.addCString(val)

# --- Decoding helpers ---

proc readUint16BE(data: seq[byte], offset: int): uint16 =
  if offset + 2 > data.len:
    raise newException(TftpDecodeError, "Truncated packet: need 2 bytes at offset " & $offset)
  var raw: uint16 = uint16(data[offset]) shl 8 or uint16(data[offset + 1])
  result = raw

proc readCString(data: seq[byte], offset: int): (string, int) =
  ## Read a null-terminated string. Returns (string, next offset after null).
  var s = ""
  var i = offset
  while i < data.len:
    if data[i] == 0:
      return (s, i + 1)
    s.add char(data[i])
    i.inc
  raise newException(TftpDecodeError, "Unterminated string at offset " & $offset)

proc parseMode(s: string): TransferMode =
  case s.toLowerAscii
  of "octet": tmOctet
  of "netascii": tmNetascii
  else: raise newException(TftpDecodeError, "Unknown transfer mode: " & s)

proc readOptions(data: seq[byte], offset: int): seq[(string, string)] =
  var pos = offset
  while pos < data.len:
    let (key, nextPos) = readCString(data, pos)
    if nextPos >= data.len and key.len > 0:
      raise newException(TftpDecodeError, "Option key without value at offset " & $pos)
    if key.len == 0 and nextPos >= data.len:
      break
    let (val, finalPos) = readCString(data, nextPos)
    result.add (key, val)
    pos = finalPos

# --- Public API ---

proc encode*(packet: TftpPacket): seq[byte] =
  result = newSeq[byte]()
  result.addUint16BE(opcodeToWire(packet.opcode))

  case packet.opcode
  of opRrq, opWrq:
    result.addCString(packet.filename)
    result.addCString($packet.mode)
    result.addOptions(packet.options)

  of opData:
    result.addUint16BE(packet.blockNum)
    result.add(packet.data)

  of opAck:
    result.addUint16BE(packet.ackBlockNum)

  of opError:
    result.addUint16BE(uint16(ord(packet.errorCode)))
    result.addCString(packet.errorMsg)

  of opOack:
    result.addOptions(packet.oackOptions)

proc decode*(data: seq[byte]): TftpPacket =
  if data.len < 2:
    raise newException(TftpDecodeError, "Packet too short: " & $data.len & " bytes")

  let wireOp = readUint16BE(data, 0)
  let op = wireToOpcode(wireOp)

  case op
  of opRrq, opWrq:
    let (filename, afterFilename) = readCString(data, 2)
    if afterFilename >= data.len:
      raise newException(TftpDecodeError, "Missing transfer mode")
    let (modeStr, afterMode) = readCString(data, afterFilename)
    let mode = parseMode(modeStr)
    let opts = readOptions(data, afterMode)
    result = TftpPacket(opcode: op, filename: filename, mode: mode, options: opts)

  of opData:
    if data.len < 4:
      raise newException(TftpDecodeError, "DATA packet too short: " & $data.len & " bytes")
    let blockNum = readUint16BE(data, 2)
    let payload = if data.len > 4: data[4 .. ^1] else: @[]
    result = TftpPacket(opcode: opData, blockNum: blockNum, data: payload)

  of opAck:
    if data.len < 4:
      raise newException(TftpDecodeError, "ACK packet too short: " & $data.len & " bytes")
    let blockNum = readUint16BE(data, 2)
    result = TftpPacket(opcode: opAck, ackBlockNum: blockNum)

  of opError:
    if data.len < 5:
      raise newException(TftpDecodeError, "ERROR packet too short: " & $data.len & " bytes")
    let errCode = readUint16BE(data, 2)
    # Map codes 0-7 to the enum; codes >7 (from RFC 2347+ or vendor extensions)
    # map to errNotDefined so the client can still read the error message.
    let mappedCode = if errCode <= 7: TftpErrorCode(errCode) else: errNotDefined
    let (msg, _) = readCString(data, 4)
    result = TftpPacket(opcode: opError, errorCode: mappedCode, errorMsg: msg)

  of opOack:
    let opts = readOptions(data, 2)
    result = TftpPacket(opcode: opOack, oackOptions: opts)
