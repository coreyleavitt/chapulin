import unittest
import std/strutils
import ../src/chapulin/protocol

func toBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)

suite "TftpOpcode wire conversion":
  test "opcodeToWire maps correctly":
    check opcodeToWire(opRrq) == 1'u16
    check opcodeToWire(opWrq) == 2'u16
    check opcodeToWire(opData) == 3'u16
    check opcodeToWire(opAck) == 4'u16
    check opcodeToWire(opError) == 5'u16
    check opcodeToWire(opOack) == 6'u16

  test "wireToOpcode maps correctly":
    check wireToOpcode(1) == opRrq
    check wireToOpcode(2) == opWrq
    check wireToOpcode(3) == opData
    check wireToOpcode(4) == opAck
    check wireToOpcode(5) == opError
    check wireToOpcode(6) == opOack

  test "wireToOpcode rejects invalid opcodes":
    expect(TftpDecodeError):
      discard wireToOpcode(0)
    expect(TftpDecodeError):
      discard wireToOpcode(7)
    expect(TftpDecodeError):
      discard wireToOpcode(255)

suite "Encode RRQ/WRQ":
  test "encode RRQ basic":
    let pkt = TftpPacket(opcode: opRrq, filename: "test.txt", mode: tmOctet, options: @[])
    let encoded = encode(pkt)
    # opcode 1 (2 bytes) + "test.txt" + 0 + "octet" + 0
    check encoded[0] == 0
    check encoded[1] == 1
    check encoded[2 ..< 10] == "test.txt".toBytes
    check encoded[10] == 0
    check encoded[11 ..< 16] == "octet".toBytes
    check encoded[16] == 0
    check encoded.len == 17

  test "encode WRQ basic":
    let pkt = TftpPacket(opcode: opWrq, filename: "upload.bin", mode: tmNetascii, options: @[])
    let encoded = encode(pkt)
    check encoded[0] == 0
    check encoded[1] == 2
    # filename + 0 + mode + 0
    let expectedLen = 2 + len("upload.bin") + 1 + len("netascii") + 1
    check encoded.len == expectedLen

  test "encode RRQ with options":
    let pkt = TftpPacket(
      opcode: opRrq,
      filename: "big.bin",
      mode: tmOctet,
      options: @[("blksize", "1024"), ("tsize", "0")]
    )
    let encoded = encode(pkt)
    # Should contain option key-value pairs after mode
    var asStr = newString(encoded.len - 2)
    for i in 2 ..< encoded.len:
      asStr[i - 2] = char(encoded[i])
    check "blksize" in asStr
    check "1024" in asStr
    check "tsize" in asStr
    check "0" in asStr

  test "encode RRQ with empty filename":
    let pkt = TftpPacket(opcode: opRrq, filename: "", mode: tmOctet, options: @[])
    let encoded = encode(pkt)
    check encoded[0] == 0
    check encoded[1] == 1
    check encoded[2] == 0  # empty filename, immediate null terminator
    check encoded[3 ..< 8] == "octet".toBytes
    check encoded[8] == 0

suite "Encode DATA":
  test "encode DATA with payload":
    let pkt = TftpPacket(opcode: opData, blockNum: 1, data: @[byte 0xDE, 0xAD, 0xBE, 0xEF])
    let encoded = encode(pkt)
    check encoded[0] == 0
    check encoded[1] == 3  # opcode 3
    check encoded[2] == 0
    check encoded[3] == 1  # block 1
    check encoded[4 .. 7] == @[byte 0xDE, 0xAD, 0xBE, 0xEF]

  test "encode DATA with empty payload (final block)":
    let pkt = TftpPacket(opcode: opData, blockNum: 5, data: @[])
    let encoded = encode(pkt)
    check encoded.len == 4
    check encoded[2] == 0
    check encoded[3] == 5

  test "encode DATA with max block number":
    let pkt = TftpPacket(opcode: opData, blockNum: 65535, data: @[byte 1])
    let encoded = encode(pkt)
    check encoded[2] == 0xFF
    check encoded[3] == 0xFF

suite "Encode ACK":
  test "encode ACK block 0":
    let pkt = TftpPacket(opcode: opAck, ackBlockNum: 0)
    let encoded = encode(pkt)
    check encoded == @[byte 0, 4, 0, 0]

  test "encode ACK block 42":
    let pkt = TftpPacket(opcode: opAck, ackBlockNum: 42)
    let encoded = encode(pkt)
    check encoded == @[byte 0, 4, 0, 42]

  test "encode ACK max block":
    let pkt = TftpPacket(opcode: opAck, ackBlockNum: 65535)
    let encoded = encode(pkt)
    check encoded == @[byte 0, 4, 0xFF, 0xFF]

suite "Encode ERROR":
  test "encode ERROR with message":
    let pkt = TftpPacket(opcode: opError, errorCode: errFileNotFound, errorMsg: "No such file")
    let encoded = encode(pkt)
    check encoded[0] == 0
    check encoded[1] == 5  # opcode 5
    check encoded[2] == 0
    check encoded[3] == 1  # error code 1
    check encoded[^1] == 0  # null terminated

  test "encode ERROR with empty message":
    let pkt = TftpPacket(opcode: opError, errorCode: errNotDefined, errorMsg: "")
    let encoded = encode(pkt)
    check encoded == @[byte 0, 5, 0, 0, 0]

  test "encode all error codes":
    for code in TftpErrorCode:
      let pkt = TftpPacket(opcode: opError, errorCode: code, errorMsg: "test")
      let encoded = encode(pkt)
      check encoded[3] == byte(ord(code))

suite "Encode OACK":
  test "encode OACK with options":
    let pkt = TftpPacket(opcode: opOack, oackOptions: @[("blksize", "1024")])
    let encoded = encode(pkt)
    check encoded[0] == 0
    check encoded[1] == 6  # opcode 6
    # "blksize" + 0 + "1024" + 0
    check encoded.len == 2 + len("blksize") + 1 + len("1024") + 1

  test "encode OACK with multiple options":
    let pkt = TftpPacket(opcode: opOack, oackOptions: @[
      ("blksize", "1024"),
      ("tsize", "524288"),
      ("timeout", "3")
    ])
    let encoded = encode(pkt)
    check encoded[0] == 0
    check encoded[1] == 6

  test "encode OACK with no options":
    let pkt = TftpPacket(opcode: opOack, oackOptions: @[])
    let encoded = encode(pkt)
    check encoded == @[byte 0, 6]

suite "Decode RRQ/WRQ":
  test "decode RRQ roundtrip":
    let original = TftpPacket(opcode: opRrq, filename: "test.txt", mode: tmOctet, options: @[])
    let decoded = decode(encode(original))
    check decoded.opcode == opRrq
    check decoded.filename == "test.txt"
    check decoded.mode == tmOctet
    check decoded.options.len == 0

  test "decode WRQ roundtrip":
    let original = TftpPacket(opcode: opWrq, filename: "upload.bin", mode: tmNetascii, options: @[])
    let decoded = decode(encode(original))
    check decoded.opcode == opWrq
    check decoded.filename == "upload.bin"
    check decoded.mode == tmNetascii

  test "decode RRQ with options roundtrip":
    let original = TftpPacket(
      opcode: opRrq,
      filename: "big.bin",
      mode: tmOctet,
      options: @[("blksize", "1024"), ("tsize", "0")]
    )
    let decoded = decode(encode(original))
    check decoded.opcode == opRrq
    check decoded.filename == "big.bin"
    check decoded.options.len == 2
    check decoded.options[0] == ("blksize", "1024")
    check decoded.options[1] == ("tsize", "0")

  test "decode RRQ malformed - no null terminators":
    expect(TftpDecodeError):
      discard decode(@[byte 0, 1, byte(ord('a'))])  # no null terminator

  test "decode RRQ malformed - missing mode":
    expect(TftpDecodeError):
      discard decode(@[byte 0, 1, byte(ord('a')), 0])  # filename but no mode

suite "Decode DATA":
  test "decode DATA roundtrip":
    let original = TftpPacket(opcode: opData, blockNum: 42, data: @[byte 1, 2, 3, 4])
    let decoded = decode(encode(original))
    check decoded.opcode == opData
    check decoded.blockNum == 42
    check decoded.data == @[byte 1, 2, 3, 4]

  test "decode DATA empty payload":
    let original = TftpPacket(opcode: opData, blockNum: 1, data: @[])
    let decoded = decode(encode(original))
    check decoded.opcode == opData
    check decoded.blockNum == 1
    check decoded.data.len == 0

  test "decode DATA max block number":
    let original = TftpPacket(opcode: opData, blockNum: 65535, data: @[byte 0xFF])
    let decoded = decode(encode(original))
    check decoded.blockNum == 65535

  test "decode DATA malformed - too short":
    expect(TftpDecodeError):
      discard decode(@[byte 0, 3, 0])  # only 3 bytes, need at least 4

suite "Decode ACK":
  test "decode ACK roundtrip":
    let original = TftpPacket(opcode: opAck, ackBlockNum: 7)
    let decoded = decode(encode(original))
    check decoded.opcode == opAck
    check decoded.ackBlockNum == 7

  test "decode ACK block 0":
    let decoded = decode(@[byte 0, 4, 0, 0])
    check decoded.opcode == opAck
    check decoded.ackBlockNum == 0

  test "decode ACK malformed - too short":
    expect(TftpDecodeError):
      discard decode(@[byte 0, 4, 0])

suite "Decode ERROR":
  test "decode ERROR roundtrip":
    let original = TftpPacket(opcode: opError, errorCode: errFileNotFound, errorMsg: "File not found")
    let decoded = decode(encode(original))
    check decoded.opcode == opError
    check decoded.errorCode == errFileNotFound
    check decoded.errorMsg == "File not found"

  test "decode ERROR empty message":
    let original = TftpPacket(opcode: opError, errorCode: errNotDefined, errorMsg: "")
    let decoded = decode(encode(original))
    check decoded.errorMsg == ""

  test "decode all error codes roundtrip":
    for code in TftpErrorCode:
      let original = TftpPacket(opcode: opError, errorCode: code, errorMsg: "test")
      let decoded = decode(encode(original))
      check decoded.errorCode == code

suite "Decode OACK":
  test "decode OACK roundtrip":
    let original = TftpPacket(opcode: opOack, oackOptions: @[("blksize", "1024")])
    let decoded = decode(encode(original))
    check decoded.opcode == opOack
    check decoded.oackOptions == @[("blksize", "1024")]

  test "decode OACK multiple options roundtrip":
    let original = TftpPacket(opcode: opOack, oackOptions: @[
      ("blksize", "1024"),
      ("tsize", "524288"),
      ("timeout", "3")
    ])
    let decoded = decode(encode(original))
    check decoded.oackOptions.len == 3

  test "decode OACK empty":
    let original = TftpPacket(opcode: opOack, oackOptions: @[])
    let decoded = decode(encode(original))
    check decoded.oackOptions.len == 0

## Wire-format tests — verify exact byte sequences per RFC 1350.
## These catch bugs that roundtrip tests miss (e.g., symmetric byte-order errors).
## Reference: https://datatracker.ietf.org/doc/html/rfc1350

suite "Wire format - encode produces correct bytes":
  test "RRQ for 'test.txt' octet matches RFC example":
    # RFC 1350 Figure 5-1: RRQ/WRQ packet
    # 2 bytes opcode | string filename | 1 byte 0 | string mode | 1 byte 0
    let pkt = TftpPacket(opcode: opRrq, filename: "test.txt", mode: tmOctet, options: @[])
    let wire = encode(pkt)
    let expected = @[
      byte 0x00, 0x01,                                       # opcode 1 (RRQ), big-endian
      byte 0x74, 0x65, 0x73, 0x74, 0x2E, 0x74, 0x78, 0x74,  # "test.txt"
      byte 0x00,                                              # null terminator
      byte 0x6F, 0x63, 0x74, 0x65, 0x74,                     # "octet"
      byte 0x00                                               # null terminator
    ]
    check wire == expected

  test "WRQ for 'file.bin' netascii matches RFC format":
    let pkt = TftpPacket(opcode: opWrq, filename: "file.bin", mode: tmNetascii, options: @[])
    let wire = encode(pkt)
    check wire[0] == 0x00
    check wire[1] == 0x02  # opcode 2 (WRQ), big-endian
    check wire[^1] == 0x00

  test "DATA block 1 matches RFC format":
    # RFC 1350 Figure 5-2: DATA packet
    # 2 bytes opcode | 2 bytes block# | n bytes data
    let pkt = TftpPacket(opcode: opData, blockNum: 1, data: @[byte 0xCA, 0xFE])
    let wire = encode(pkt)
    check wire == @[byte 0x00, 0x03, 0x00, 0x01, 0xCA, 0xFE]

  test "DATA block 256 — catches byte-order bugs":
    # Block 256 = 0x0100 big-endian. If byte order is wrong, we'd get 0x0001.
    let pkt = TftpPacket(opcode: opData, blockNum: 256, data: @[byte 0xAB])
    let wire = encode(pkt)
    check wire[0] == 0x00
    check wire[1] == 0x03  # opcode
    check wire[2] == 0x01  # high byte of 256
    check wire[3] == 0x00  # low byte of 256
    check wire[4] == 0xAB

  test "DATA block 0x0102 — asymmetric value proves byte order":
    # 0x0102 big-endian = [0x01, 0x02]. If swapped: [0x02, 0x01].
    let pkt = TftpPacket(opcode: opData, blockNum: 0x0102, data: @[])
    let wire = encode(pkt)
    check wire == @[byte 0x00, 0x03, 0x01, 0x02]

  test "ACK block 300 — multi-byte big-endian":
    # 300 = 0x012C big-endian = [0x01, 0x2C]
    let pkt = TftpPacket(opcode: opAck, ackBlockNum: 300)
    let wire = encode(pkt)
    check wire == @[byte 0x00, 0x04, 0x01, 0x2C]

  test "ACK block 0x1234":
    let pkt = TftpPacket(opcode: opAck, ackBlockNum: 0x1234)
    let wire = encode(pkt)
    check wire == @[byte 0x00, 0x04, 0x12, 0x34]

  test "ERROR code 3 with message matches RFC format":
    # RFC 1350 Figure 5-4: ERROR packet
    # 2 bytes opcode | 2 bytes errorcode | string errmsg | 1 byte 0
    let pkt = TftpPacket(opcode: opError, errorCode: errDiskFull, errorMsg: "full")
    let wire = encode(pkt)
    check wire == @[
      byte 0x00, 0x05,             # opcode 5
      byte 0x00, 0x03,             # error code 3
      byte 0x66, 0x75, 0x6C, 0x6C, # "full"
      byte 0x00                     # null terminator
    ]

  test "OACK with blksize matches RFC 2347 format":
    let pkt = TftpPacket(opcode: opOack, oackOptions: @[("blksize", "1024")])
    let wire = encode(pkt)
    let expected = @[
      byte 0x00, 0x06,                                 # opcode 6
      byte 0x62, 0x6C, 0x6B, 0x73, 0x69, 0x7A, 0x65,  # "blksize"
      byte 0x00,                                        # null
      byte 0x31, 0x30, 0x32, 0x34,                     # "1024"
      byte 0x00                                         # null
    ]
    check wire == expected

suite "Wire format - decode from known bytes":
  test "decode RRQ from known wire bytes":
    let wire = @[
      byte 0x00, 0x01,
      byte 0x66, 0x6F, 0x6F, 0x2E, 0x62, 0x69, 0x6E,  # "foo.bin"
      byte 0x00,
      byte 0x6F, 0x63, 0x74, 0x65, 0x74,               # "octet"
      byte 0x00
    ]
    let pkt = decode(wire)
    check pkt.opcode == opRrq
    check pkt.filename == "foo.bin"
    check pkt.mode == tmOctet

  test "decode DATA block 256 from known wire bytes":
    let wire = @[byte 0x00, 0x03, 0x01, 0x00, 0xDE, 0xAD]
    let pkt = decode(wire)
    check pkt.opcode == opData
    check pkt.blockNum == 256
    check pkt.data == @[byte 0xDE, 0xAD]

  test "decode DATA block 0x0102 from known wire bytes":
    let wire = @[byte 0x00, 0x03, 0x01, 0x02, 0xFF]
    let pkt = decode(wire)
    check pkt.blockNum == 0x0102

  test "decode ACK block 300 from known wire bytes":
    # 300 = 0x012C
    let wire = @[byte 0x00, 0x04, 0x01, 0x2C]
    let pkt = decode(wire)
    check pkt.opcode == opAck
    check pkt.ackBlockNum == 300

  test "decode ACK block 0x1234 from known wire bytes":
    let wire = @[byte 0x00, 0x04, 0x12, 0x34]
    let pkt = decode(wire)
    check pkt.ackBlockNum == 0x1234

  test "decode ERROR code 5 from known wire bytes":
    let wire = @[
      byte 0x00, 0x05,
      byte 0x00, 0x05,             # error code 5
      byte 0x62, 0x61, 0x64,       # "bad"
      byte 0x00
    ]
    let pkt = decode(wire)
    check pkt.opcode == opError
    check pkt.errorCode == errUnknownTransferId
    check pkt.errorMsg == "bad"

  test "decode OACK from known wire bytes":
    let wire = @[
      byte 0x00, 0x06,
      byte 0x74, 0x73, 0x69, 0x7A, 0x65,  # "tsize"
      byte 0x00,
      byte 0x35, 0x31, 0x32,               # "512"
      byte 0x00
    ]
    let pkt = decode(wire)
    check pkt.opcode == opOack
    check pkt.oackOptions == @[("tsize", "512")]

suite "Decode edge cases":
  test "decode empty input":
    expect(TftpDecodeError):
      discard decode(@[])

  test "decode single byte":
    expect(TftpDecodeError):
      discard decode(@[byte 0])

  test "decode invalid opcode 0":
    expect(TftpDecodeError):
      discard decode(@[byte 0, 0, 0, 0])

  test "decode invalid opcode 7":
    expect(TftpDecodeError):
      discard decode(@[byte 0, 7, 0, 0])

  test "decode invalid opcode 255":
    expect(TftpDecodeError):
      discard decode(@[byte 0, 255, 0, 0])

  test "decode ERROR with code 8 (extended, e.g. option negotiation)":
    # RFC 2347 and real servers use error codes >7.
    # The client must not crash on them.
    let wire = @[byte 0x00, 0x05, 0x00, 0x08, byte(ord('x')), 0x00]
    # Currently this raises — this test documents the bug (issue #10).
    # After fix, it should succeed and return errNotDefined or a raw code.
    try:
      let pkt = decode(wire)
      # If we get here, the fix is in — verify it decoded something reasonable
      check pkt.opcode == opError
      check pkt.errorMsg == "x"
    except TftpDecodeError:
      # This is the current (buggy) behavior. Test marks as known failure.
      fail()

  test "decode ERROR with code 255":
    let wire = @[byte 0x00, 0x05, 0x00, 0xFF, byte(ord('y')), 0x00]
    try:
      let pkt = decode(wire)
      check pkt.opcode == opError
    except TftpDecodeError:
      fail()

  test "decode RRQ with invalid transfer mode":
    # Unknown mode string — should raise
    let wire = @[byte 0x00, 0x01] & "f".toBytes & @[byte 0x00] &
               "binary".toBytes & @[byte 0x00]
    expect(TftpDecodeError):
      discard decode(wire)

  test "options with consecutive null bytes (empty key)":
    # OACK with \0\0 in options area — should not produce garbage entries
    let wire = @[byte 0x00, 0x06, 0x00, 0x00]  # opcode 6 + two nulls
    let pkt = decode(wire)
    check pkt.opcode == opOack
    # Empty key/value pair should either be ignored or produce ("", "")
    # but should not crash
