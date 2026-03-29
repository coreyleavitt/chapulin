import unittest
import ../src/chapulin/tftp_uri

suite "TFTP URI parsing (RFC 3617)":
  test "basic URI":
    let uri = parseTftpUri("tftp://192.168.1.1/firmware.bin")
    check uri.host == "192.168.1.1"
    check uri.port == 69
    check uri.filename == "firmware.bin"
    check uri.mode == "octet"

  test "URI with port":
    let uri = parseTftpUri("tftp://10.0.0.1:6969/config.txt")
    check uri.host == "10.0.0.1"
    check uri.port == 6969
    check uri.filename == "config.txt"

  test "URI with mode=netascii":
    let uri = parseTftpUri("tftp://10.0.0.1/readme.txt;mode=netascii")
    check uri.host == "10.0.0.1"
    check uri.filename == "readme.txt"
    check uri.mode == "netascii"

  test "URI with mode=octet":
    let uri = parseTftpUri("tftp://10.0.0.1/data.bin;mode=octet")
    check uri.mode == "octet"

  test "URI with port and mode":
    let uri = parseTftpUri("tftp://10.0.0.1:1234/file.img;mode=octet")
    check uri.host == "10.0.0.1"
    check uri.port == 1234
    check uri.filename == "file.img"
    check uri.mode == "octet"

  test "URI with path separators":
    let uri = parseTftpUri("tftp://192.168.1.1/path/to/file.bin")
    check uri.filename == "path/to/file.bin"

  test "hostname instead of IP":
    let uri = parseTftpUri("tftp://myserver.local/boot.img")
    check uri.host == "myserver.local"
    check uri.filename == "boot.img"

  test "IPv6 address in brackets":
    let uri = parseTftpUri("tftp://[::1]/test.txt")
    check uri.host == "::1"
    check uri.filename == "test.txt"

  test "IPv6 with port":
    let uri = parseTftpUri("tftp://[fe80::1]:6969/file.bin")
    check uri.host == "fe80::1"
    check uri.port == 6969

  test "missing scheme raises":
    expect(TftpUriError):
      discard parseTftpUri("http://10.0.0.1/file.txt")

  test "missing host raises":
    expect(TftpUriError):
      discard parseTftpUri("tftp:///file.txt")

  test "missing filename raises":
    expect(TftpUriError):
      discard parseTftpUri("tftp://10.0.0.1/")

  test "empty string raises":
    expect(TftpUriError):
      discard parseTftpUri("")

  test "isTftpUri detects tftp URIs":
    check isTftpUri("tftp://10.0.0.1/file.bin") == true
    check isTftpUri("TFTP://10.0.0.1/file.bin") == true
    check isTftpUri("192.168.1.1") == false
    check isTftpUri("http://example.com") == false
    check isTftpUri("file.txt") == false
