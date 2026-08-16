import unittest
import std/md5
import std/os
import std/strutils
import nelli
import fuzzsupport
import ../src/chapulin/checksum
import ../src/chapulin/server_config
import ../src/chapulin/security

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

# --- writeSidecar LEXICAL fuzz target (RFC verification-harness.md, slice 4) --
#
# D3 table row: `checksum.writeSidecar(root, resolvedPath, digest)` --
# allowed exceptions: `OSError`/`IOError` only (writeSidecar's own
# try/except catches exactly these two and returns (false, err); anything
# else escaping is itself a finding). Additional invariant asserted here:
# never writes outside root (LEXICAL only). Mirrors t_security.nim's slice-3
# containment split: no symlinks are planted for this fuzz target (git can't
# portably hold them and per-iteration on-disk symlink setup fights corpus
# determinism) -- the symlink-escape / alias-forgery refusals stay covered
# by the existing dynamic e2e suites above ("writeSidecar containment" /
# "reparse-ancestor containment"), which this fuzz target does not touch.
#
# Unlike validatePath/checkWriteAccess (pure string functions fuzzed against
# a read-only fixture tree), writeSidecar actually performs a real write when
# containment passes -- so this target uses a disposable OS temp directory
# (NOT the git-committed tests/corpus/fixtures/ tree) as its root, cleaned
# up after the run, rather than risk polluting a checked-in fixture.

let fuzzSidecarRoot = getTempDir() / "chapulin_checksum_fuzz_root"

suite "writeSidecar fuzz setup":
  test "create disposable fuzz root":
    createDir(fuzzSidecarRoot)
    check dirExists(fuzzSidecarRoot)

# charsToStr used to be redefined here (byte-for-byte identical to
# t_props.nim/t_hostile.nim/t_security.nim's own copies); R1-6 code-review
# finding hoisted the one canonical definition into fuzzsupport.nim, which
# this file already imports. `RawSidecarAlphabet`/`rawSidecarStrings` below
# genuinely differed from fuzzsupport's SafeAlphabet, so they stayed local --
# but R2-2 code-review finding caught that they were byte-for-byte identical
# to t_security.nim's own "kept local" `RawAlphabet`/`rawPathStrings` (same
# alphabet, same wrapper, just a different default `maxLen`: 20 here vs. 24
# there). Both are now `RawPathAlphabet`/`rawPathStrings` in fuzzsupport.nim;
# this file's one former bare `rawSidecarStrings()` call (in
# `sidecarResolvedPaths`, below) now passes `20` explicitly to preserve this
# file's original default instead of picking up fuzzsupport's `24`.

proc benignNameStrings(maxLen = 12): Strategy[string] =
  ## Ordinary filename characters only, no separators -- constructed as
  ## `fuzzSidecarRoot / name` below so a fraction of examples land in-root
  ## and actually reach the real `writeFile` call, exercising that path too.
  lists(sampledFrom(@['a', 'b', 'c', 'x', '1', '2', '_', '-']),
        minLen = 1, maxLen = maxLen).map(charsToStr)

proc sidecarResolvedPaths(): Strategy[string] =
  oneOf([rawPathStrings(20),  # 20: this file's original rawSidecarStrings() default
         benignNameStrings().map(proc(n: string): string = fuzzSidecarRoot / n)])

proc writeSidecarOracle(resolvedPath: string): bool =
  ## `writeSidecar`'s per-target oracle (RFC D3): TOTAL w.r.t. anything but
  ## `OSError`/`IOError` -- no `except` clause here at all, matching
  ## `validateAndParseOackOracle`'s style in t_props.nim: any exception (or
  ## Defect) escaping writeSidecar itself (which already catches
  ## OSError/IOError internally) is the finding. Additional invariant:
  ## LEXICAL never-escape -- when writeSidecar reports ok, the sidecar path
  ## it just wrote must resolve at or under fuzzSidecarRoot.
  let (ok, _) = writeSidecar(fuzzSidecarRoot, resolvedPath, "deadbeef")
  if not ok:
    return true
  let sidecar = absolutePath(resolvedPath & SidecarExt)
  let normRoot = absolutePath(fuzzSidecarRoot)
  sidecar == normRoot or sidecar.startsWith(normRoot & $DirSep)

suite "writeSidecar LEXICAL fuzz target (RFC verification-harness.md, slice 4)":
  fuzzProperty("writeSidecar never escapes its root and never raises anything but OSError/IOError",
               "checksum.writeSidecar"):
    given resolvedPath in sidecarResolvedPaths()
    ensure writeSidecarOracle(resolvedPath)

suite "writeSidecar fuzz cleanup":
  test "remove disposable fuzz root":
    removeDir(fuzzSidecarRoot)
    check not dirExists(fuzzSidecarRoot)
