import unittest
import std/md5
import ../src/chapulin/checksum
import ../src/chapulin/server_config

proc toBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)

suite "checksum.nim — Digester (RFC D1, slice 1.1)":

  test "multi-block digest matches toMD5 of the whole content":
    let content = "the quick brown fox jumps over the lazy dog"
    let b1 = content[0 ..< 10]
    let b2 = content[10 ..< 25]
    let b3 = content[25 .. ^1]

    let d = newDigester(csMd5)
    d.update(toBytes(b1))
    d.update(toBytes(b2))
    d.update(toBytes(b3))

    check d.finalize() == $toMD5(content)

  test "zero-byte content digests to the empty-content digest":
    let d = newDigester(csMd5)
    check d.finalize() == $toMD5("")

  test "zero-length update does not raise and contributes nothing":
    let b1 = toBytes("hello ")
    let b2 = toBytes("world")
    let empty = newSeq[byte](0)

    let d = newDigester(csMd5)
    d.update(b1)
    d.update(b2)
    d.update(empty) # empty terminating DATA block — must not raise

    check d.finalize() == $toMD5("hello world")

  test "newDigester(csSha256) raises ValueError":
    expect ValueError:
      discard newDigester(csSha256)
