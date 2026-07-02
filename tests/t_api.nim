import unittest
import std/os
import ../src/chapulin/api

suite "API - TransferRequest defaults":
  test "default options are sensible":
    let req = newTransferRequest("10.0.0.1", 69, "config.bin", getTempDir() / "out", tdGet)
    check req.host == "10.0.0.1"
    check req.port == 69
    check req.options.blocksize == 512
    check req.options.timeout == 5
    check req.options.retries == 3
    check req.direction == tdGet

suite "API - sanitizeForDisplay":
  test "strips ESC, newline, and other control bytes to '?'; passes high bytes unchanged":
    # Control characters (ord < 0x20) and DEL (0x7F) must become '?'.
    # Bytes >= 0x80 must pass through so UTF-8 multibyte sequences are preserved.
    let input = "\x1b[31mX\nY\x01"
    let got = sanitizeForDisplay(input)
    # \x1b -> '?', '[', '3', '1', 'm' stay, 'X' stays, \n -> '?', 'Y' stays, \x01 -> '?'
    check got == "?[31mX?Y?"

  test "high bytes (>= 0x80) pass through unchanged":
    # Two-byte UTF-8 sequence for U+00E9 (é): 0xC3 0xA9
    let utf8 = "\xC3\xA9"
    check sanitizeForDisplay(utf8) == utf8

  test "clean ASCII string is returned unchanged":
    check sanitizeForDisplay("hello world") == "hello world"

  test "DEL byte (0x7F) becomes '?'":
    check sanitizeForDisplay("\x7f") == "?"

  test "empty string returns empty string":
    check sanitizeForDisplay("") == ""
