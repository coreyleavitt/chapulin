import unittest
import std/os
import ../src/chapulin/protocol
import ../src/chapulin/server_config
import ../src/chapulin/security
import ../src/chapulin/checksum

# Create a temp directory structure for testing
let testRoot = getTempDir() / "chapulin_security_test"
# A sibling directory *outside* the TFTP root, used as a symlink target.
let outsideRoot = getTempDir() / "chapulin_security_outside"
# Whether the platform/user can create symlinks (Windows needs privilege).
# The issue #19 symlink tests are skipped when false.
var symlinkOk = false

suite "Setup":
  test "create test directory structure":
    createDir(testRoot)
    createDir(testRoot / "subdir")
    writeFile(testRoot / "existing.txt", "hello")
    writeFile(testRoot / "subdir" / "nested.txt", "nested")
    check dirExists(testRoot)

  test "create symlink fixtures (skipped if unsupported)":
    createDir(outsideRoot)
    writeFile(outsideRoot / "secret.txt", "topsecret")
    try:
      # A symlink inside the root pointing at a file outside it.
      createSymlink(outsideRoot / "secret.txt", testRoot / "evil_link")
      # A symlink inside the root pointing at a directory outside it.
      createSymlink(outsideRoot, testRoot / "escape_dir")
      # A symlink inside the root pointing at a file inside it (legitimate).
      createSymlink(testRoot / "existing.txt", testRoot / "good_link")
      symlinkOk = symlinkExists(testRoot / "evil_link")
    except OSError, IOError:
      symlinkOk = false
    if not symlinkOk:
      checkpoint("symlink creation unsupported here — #19 symlink tests skipped")

suite "validatePath":
  test "simple filename resolves correctly":
    let (valid, resolved, _) = validatePath(testRoot, "existing.txt")
    check valid == true
    check resolved == testRoot / "existing.txt"

  test "subdirectory path resolves correctly":
    let (valid, resolved, _) = validatePath(testRoot, "subdir/nested.txt")
    check valid == true
    check resolved == testRoot / "subdir" / "nested.txt"

  test "rejects .. traversal":
    let (valid, _, err) = validatePath(testRoot, "../../../etc/passwd")
    check valid == false
    check err.len > 0

  test "virtual root: strips leading slash (PXE compat)":
    let (valid, resolved, _) = validatePath(testRoot, "/existing.txt")
    check valid == true
    check resolved == testRoot / "existing.txt"

  test "virtual root: strips leading backslash":
    let (valid, resolved, _) = validatePath(testRoot, "\\existing.txt")
    check valid == true
    check resolved == testRoot / "existing.txt"

  test "virtual root: PXE-style absolute path":
    let (valid, resolved, _) = validatePath(testRoot, "/subdir/nested.txt")
    check valid == true
    check resolved == testRoot / "subdir" / "nested.txt"

  test "still rejects .. even with leading slash":
    let (valid, _, err) = validatePath(testRoot, "/../../../etc/passwd")
    check valid == false
    check err.len > 0

  test "rejects embedded .. traversal":
    let (valid, _, err) = validatePath(testRoot, "subdir/../../etc/passwd")
    check valid == false
    check err.len > 0

  test "rejects null byte in filename":
    let (valid, _, err) = validatePath(testRoot, "file\x00.txt")
    check valid == false
    check err.len > 0

  test "rejects empty filename":
    let (valid, _, err) = validatePath(testRoot, "")
    check valid == false
    check err.len > 0

  test "rejects backslash traversal":
    let (valid, _, err) = validatePath(testRoot, "..\\..\\etc\\passwd")
    check valid == false
    check err.len > 0

  test "allows nonexistent file (for WRQ create)":
    let (valid, resolved, _) = validatePath(testRoot, "newfile.txt")
    check valid == true
    check resolved == testRoot / "newfile.txt"

  when defined(windows):
    # Round-3 code-review fix 2: NTFS Alternate Data Streams. A WRQ/RRQ
    # filename of "data.bin.md5::$DATA" (or "data.bin.md5:$DATA", or any
    # "name:stream" form) has a suffix of "::$data"/"5:$data" -- NOT ".md5"
    # -- so isReservedSidecarName's suffix check never fires, but Windows'
    # open(..., fmWrite/fmRead) resolves the stream-qualified name to the
    # real "data.bin.md5"'s default data stream, forging/overwriting a
    # server-owned sidecar. validatePath must reject any colon in the
    # (normalized) filename on Windows, closing the whole colon class
    # (including drive-relative "C:foo") at the shared RRQ+WRQ entry gate.
    test "rejects NTFS ADS bypass of the reserved .md5 sidecar name (data.bin.md5::$DATA)":
      let (valid, _, err) = validatePath(testRoot, "data.bin.md5::$DATA")
      check valid == false
      check err.len > 0

    test "rejects NTFS ADS bypass, single-colon form (data.bin.md5:$DATA)":
      let (valid, _, err) = validatePath(testRoot, "data.bin.md5:$DATA")
      check valid == false
      check err.len > 0

    test "rejects any name:stream colon form (foo:bar)":
      let (valid, _, err) = validatePath(testRoot, "foo:bar")
      check valid == false
      check err.len > 0

suite "validatePath symlink containment (issue #19)":
  test "rejects symlink inside root pointing at a file outside (RRQ read)":
    if not symlinkOk:
      skip()
    else:
      let (valid, _, err) = validatePath(testRoot, "evil_link")
      check valid == false
      check err.len > 0

  test "rejects overwrite of a symlink whose target escapes root (WRQ)":
    # Same on-disk symlink; the WRQ path exercises the identical sink.
    if not symlinkOk:
      skip()
    else:
      let (valid, _, _) = validatePath(testRoot, "evil_link")
      check valid == false

  test "rejects create through a symlinked dir that escapes root (WRQ)":
    if not symlinkOk:
      skip()
    else:
      let (valid, _, err) = validatePath(testRoot, "escape_dir/pwned.txt")
      check valid == false
      check err.len > 0

  test "allows a symlink whose target stays inside root":
    if not symlinkOk:
      skip()
    else:
      let (valid, resolved, _) = validatePath(testRoot, "good_link")
      when defined(windows):
        # K1 trade-off (deliberate, not a bug): detecting a reparse point
        # is FFI-free on Windows (symlinkExists), but resolving WHERE it
        # points is not, so hasReparseComponent cannot tell "stays inside
        # root" apart from "escapes root" — it rejects every reparse
        # point on Windows regardless of target. This POSIX-only
        # guarantee is intentionally given up there in exchange for
        # closing the #19/K1 escape (see hasReparseComponent's doc
        # comment in security.nim).
        check valid == false
      else:
        check valid == true
        check resolved == testRoot / "good_link"

when defined(windows):
  # K1: junctions are the Windows analogue of the #19 symlink escape, but
  # need NO privilege to create (unlike symlinks, gated above by
  # symlinkOk) — `mklink /J` works unprivileged. expandFilename does not
  # resolve junctions either, so a junction planted inside root pointing
  # outside it defeats validateWritePath's realpath check exactly like an
  # unprivileged-Windows symlink would.
  #
  # Fixtures live under getTempDir(), NOT under a path derived from the
  # bind-mounted repo tree: a container quirk means bind-mounted volumes
  # may not support reparse points, while the container's own local temp
  # drive does.
  let junctionRoot = getTempDir() / "chapulin_junction_root"
  let junctionOutsideRoot = getTempDir() / "chapulin_junction_outside"
  var junctionOk = false

  suite "K1 setup: junction fixture":
    test "create junction fixture (skipped if unsupported)":
      createDir(junctionRoot)
      writeFile(junctionRoot / "existing.txt", "hello")
      createDir(junctionOutsideRoot)
      writeFile(junctionOutsideRoot / "secret.txt", "topsecret-junction")
      let rc = execShellCmd("cmd /c mklink /J \"" & (junctionRoot / "escape_junc") &
                             "\" \"" & junctionOutsideRoot & "\" >NUL")
      junctionOk = rc == 0 and symlinkExists(junctionRoot / "escape_junc")
      if not junctionOk:
        checkpoint("junction creation unsupported here — K1 junction tests skipped")

  suite "validatePath junction containment (K1)":
    test "rejects RRQ read of a path traversing a junction that escapes root":
      if not junctionOk:
        skip()
      else:
        let (valid, _, err) = validatePath(junctionRoot, "escape_junc/secret.txt")
        check valid == false
        check err.len > 0

    test "rejects WRQ overwrite of a file reached through an escaping junction":
      if not junctionOk:
        skip()
      else:
        let (valid, _, _) = validatePath(junctionRoot, "escape_junc/secret.txt")
        check valid == false

    test "rejects WRQ create of a new file inside an escaping junction dir":
      if not junctionOk:
        skip()
      else:
        let (valid, _, err) = validatePath(junctionRoot, "escape_junc/newfile.txt")
        check valid == false
        check err.len > 0

    test "still accepts a legitimate in-root path with no reparse component":
      if not junctionOk:
        skip()
      else:
        let (valid, resolved, _) = validatePath(junctionRoot, "existing.txt")
        check valid == true
        check resolved == junctionRoot / "existing.txt"

  suite "writeSidecar reparse-ancestor containment (authority moved into validateWritePath)":
    # The reviewer's authority-seam finding: `hasReparseComponent` was wired
    # only into `validatePath`, so `checksum.writeSidecar`'s own re-assertion
    # of containment (via `validateWritePath`) was blind to a Windows
    # junction — the sidecar write could be steered outside root through the
    # very same `escape_junc` fixture used above, even though `validatePath`
    # itself was already protected. Now that the check lives inside
    # `validateWritePath` (the module's sole containment authority),
    # `writeSidecar` gets it too without calling `validatePath` at all.
    test "refuses to write a sidecar reached through a junction ancestor that escapes root":
      if not junctionOk:
        skip()
      else:
        let resolvedPath = junctionRoot / "escape_junc" / "sidecar_target.txt"
        let (ok, err) = writeSidecar(junctionRoot, resolvedPath, "deadbeef")
        check ok == false
        check err.len > 0
        # Containment refused the write entirely: nothing landed on the
        # far side of the junction, in junctionOutsideRoot.
        check not fileExists(junctionOutsideRoot / "sidecar_target.txt.md5")

  suite "K1 Cleanup":
    test "remove junction fixture":
      # Remove the junction link itself (plain, non-recursive rmdir — this
      # unlinks the reparse point without touching the outside target's
      # contents) before removing the directories, so teardown never
      # walks through the junction into junctionOutsideRoot.
      if junctionOk:
        discard execShellCmd("cmd /c rmdir \"" & (junctionRoot / "escape_junc") & "\" >NUL")
      removeDir(junctionRoot)
      removeDir(junctionOutsideRoot)
      check not dirExists(junctionOutsideRoot)

  # FIX B (boundary bug): `hasReparseComponent`'s ancestor walk stops when
  # the climbed component string-equals `rootDir`. `absolutePath(rootDir)`
  # does not strip a trailing separator, but the climb (via splitPath)
  # never produces one, so a `rootDir` configured WITH a trailing separator
  # (`C:\tftpboot\` — an ordinary way to type it; the CLI stores it
  # verbatim) never matches and the walk climbs PAST the true root. That is
  # only observable when the served root itself is reparse-backed: the
  # over-climbed step lands on `rootDir` itself, which IS the junction, so
  # `symlinkExists` fires and every legitimate in-root request is falsely
  # rejected. This fixture makes the served root itself a junction to
  # discriminate that case from the ordinary "escaping junction inside
  # root" fixtures above.
  let reparseRootTarget = getTempDir() / "chapulin_reparse_root_target"
  let reparseRootLink = getTempDir() / "chapulin_reparse_root"
  var reparseRootOk = false

  suite "K1 setup: reparse-root-as-served-root fixture (FIX B)":
    test "create reparse-root fixture (skipped if unsupported)":
      createDir(reparseRootTarget)
      writeFile(reparseRootTarget / "existing.txt", "hello")
      let rc = execShellCmd("cmd /c mklink /J \"" & reparseRootLink &
                             "\" \"" & reparseRootTarget & "\" >NUL")
      reparseRootOk = rc == 0 and symlinkExists(reparseRootLink)
      if not reparseRootOk:
        checkpoint("junction creation unsupported here — FIX B boundary test skipped")

  suite "validatePath: trailing separator on a reparse-backed root (FIX B)":
    test "accepts a legitimate in-root file when rootDir has a trailing separator":
      if not reparseRootOk:
        skip()
      else:
        let rootWithTrailingSep = reparseRootLink & $DirSep
        let (valid, resolved, err) = validatePath(rootWithTrailingSep, "existing.txt")
        check valid == true
        check err.len == 0
        check resolved == reparseRootLink / "existing.txt"

  suite "K1 Cleanup: reparse-root fixture (FIX B)":
    test "remove reparse-root fixture":
      if reparseRootOk:
        discard execShellCmd("cmd /c rmdir \"" & reparseRootLink & "\" >NUL")
      removeDir(reparseRootTarget)
      check not dirExists(reparseRootTarget)

suite "checkWriteAccess":
  test "wpDeny always rejects":
    let config = ServerConfig(writePolicy: wpDeny, rootDir: testRoot)
    let (ok, errCode, _) = checkWriteAccess(config, testRoot / "existing.txt")
    check ok == false
    check errCode == errAccessViolation

  test "wpCreateOnly allows new file":
    let config = ServerConfig(writePolicy: wpCreateOnly, rootDir: testRoot)
    let (ok, _, _) = checkWriteAccess(config, testRoot / "brand_new.txt")
    check ok == true

  test "wpCreateOnly rejects existing file":
    let config = ServerConfig(writePolicy: wpCreateOnly, rootDir: testRoot)
    let (ok, errCode, _) = checkWriteAccess(config, testRoot / "existing.txt")
    check ok == false
    check errCode == errFileAlreadyExists

  test "wpOverwrite allows existing file":
    let config = ServerConfig(writePolicy: wpOverwrite, rootDir: testRoot)
    let (ok, _, _) = checkWriteAccess(config, testRoot / "existing.txt")
    check ok == true

  test "wpOverwrite rejects new file":
    let config = ServerConfig(writePolicy: wpOverwrite, rootDir: testRoot)
    let (ok, errCode, _) = checkWriteAccess(config, testRoot / "brand_new.txt")
    check ok == false
    check errCode == errFileNotFound

  test "wpCreateOrOverwrite allows new file":
    let config = ServerConfig(writePolicy: wpCreateOrOverwrite, rootDir: testRoot)
    let (ok, _, _) = checkWriteAccess(config, testRoot / "brand_new.txt")
    check ok == true

  test "wpCreateOrOverwrite allows existing file":
    let config = ServerConfig(writePolicy: wpCreateOrOverwrite, rootDir: testRoot)
    let (ok, _, _) = checkWriteAccess(config, testRoot / "existing.txt")
    check ok == true

suite "checkWriteAccess reserved .md5 namespace (slice 5)":
  # RFC checksum-integrity-error-hygiene, Ds (fixes defect 5 — reserved
  # namespace). The server owns the `.md5` sidecar suffix once checksumMode
  # is on: no client WRQ may create, overwrite, or forge a sidecar under any
  # write policy other than wpDeny (which already rejects everything).
  test "wpCreateOnly rejects a .md5 target when checksumMode is csMd5":
    let config = ServerConfig(writePolicy: wpCreateOnly, rootDir: testRoot,
                               checksumMode: csMd5)
    let (ok, errCode, _) = checkWriteAccess(config, testRoot / "f.bin.md5")
    check ok == false
    check errCode == errAccessViolation

  test "wpOverwrite rejects a .md5 target when checksumMode is csMd5":
    let config = ServerConfig(writePolicy: wpOverwrite, rootDir: testRoot,
                               checksumMode: csMd5)
    let (ok, errCode, _) = checkWriteAccess(config, testRoot / "f.bin.md5")
    check ok == false
    check errCode == errAccessViolation

  test "wpCreateOrOverwrite rejects a .md5 target when checksumMode is csMd5":
    let config = ServerConfig(writePolicy: wpCreateOrOverwrite, rootDir: testRoot,
                               checksumMode: csMd5)
    let (ok, errCode, _) = checkWriteAccess(config, testRoot / "f.bin.md5")
    check ok == false
    check errCode == errAccessViolation

  test "case-insensitive: a .MD5 target is also rejected under csMd5":
    let config = ServerConfig(writePolicy: wpCreateOrOverwrite, rootDir: testRoot,
                               checksumMode: csMd5)
    let (ok, errCode, _) = checkWriteAccess(config, testRoot / "f.bin.MD5")
    check ok == false
    check errCode == errAccessViolation

  test "off by default: a .md5 target behaves normally when checksumMode is csNone":
    let config = ServerConfig(writePolicy: wpCreateOrOverwrite, rootDir: testRoot,
                               checksumMode: csNone)
    let (ok, _, _) = checkWriteAccess(config, testRoot / "brandnew.md5")
    check ok == true

  test "non-.md5 target is unaffected under csMd5":
    let config = ServerConfig(writePolicy: wpCreateOrOverwrite, rootDir: testRoot,
                               checksumMode: csMd5)
    let (ok, _, _) = checkWriteAccess(config, testRoot / "brandnew.bin")
    check ok == true

  test "trailing dot on a .md5 target is still rejected under csMd5 (M5)":
    # Windows' CreateFileW silently strips a trailing '.' or ' ' from the
    # final path component, so a WRQ target of "f.bin.md5." would actually
    # open "f.bin.md5" on disk while a naive endsWith(".md5") string check
    # sees "f.bin.md5." (doesn't end in ".md5") and lets it through. The
    # reservation must normalize the trailing dot/space away before the
    # suffix comparison.
    let config = ServerConfig(writePolicy: wpCreateOrOverwrite, rootDir: testRoot,
                               checksumMode: csMd5)
    let (ok, errCode, _) = checkWriteAccess(config, testRoot / "f.bin.md5.")
    check ok == false
    check errCode == errAccessViolation

  test "trailing space on a .md5 target is still rejected under csMd5 (M5)":
    let config = ServerConfig(writePolicy: wpCreateOrOverwrite, rootDir: testRoot,
                               checksumMode: csMd5)
    let (ok, errCode, _) = checkWriteAccess(config, testRoot / "f.bin.md5 ")
    check ok == false
    check errCode == errAccessViolation

suite "checkWriteAccess reserved .md5 namespace: symlink alias (H1)":
  # RFC checksum-integrity-error-hygiene reserved-namespace cluster, H1.
  # checkWriteAccess's reservation (suite above) tests the LEXICAL
  # resolvedPath returned by validatePath. An in-root symlink
  # `md5_alias -> real_target.md5` makes validatePath's containment check
  # follow the symlink (sees real_target.md5 in-root, so it's allowed) and
  # return the alias's own lexical name — which does not end in ".md5" —
  # so the old lexical-only check never fired, and handleWrq's
  # open(resolvedPath, fmWrite) would have the OS follow the symlink and
  # overwrite real_target.md5. checkWriteAccess must also test the
  # canonicalized (symlink-resolved) real path.
  test "WRQ to an in-root symlink aliasing a real .md5 file is rejected (H1)":
    if not symlinkOk:
      checkpoint("symlink creation unsupported here — H1 alias test skipped")
      skip()
    else:
      writeFile(testRoot / "real_target.md5", "deadbeef  real_target\n")
      var aliasCreated = true
      try:
        createSymlink(testRoot / "real_target.md5", testRoot / "md5_alias")
      except OSError, IOError:
        aliasCreated = false

      if not aliasCreated:
        checkpoint("could not create md5_alias symlink — H1 alias test skipped")
        skip()
      # Capability probe (K1): checkWriteAccess's H1 defense depends on
      # canonicalize/expandFilename actually resolving the symlink to its
      # real target. This is best-effort on Windows — expandFilename does
      # not resolve symlinks/junctions there, an accepted limit — so a
      # Windows container that (unlike a typical unprivileged CI runner)
      # happens to hold the symlink-create privilege can still create
      # `md5_alias` but canonicalize won't see through it. Detect that here
      # (using the exact same predicate the fix itself calls) rather than
      # asserting a security property this platform structurally cannot
      # provide; mirrors this file's pre-existing acceptance of the
      # identical limitation in the "issue #19" suite above.
      elif not isReservedSidecarName(canonicalize(testRoot / "md5_alias")):
        checkpoint("platform cannot resolve the symlink to its real path here " &
                   "(K1: best-effort on Windows) — H1 assertion skipped")
        skip()
      else:
        let (valid, resolvedPath, _) = validatePath(testRoot, "md5_alias")
        check valid == true  # containment follows the in-root symlink; lexically fine

        let config = ServerConfig(writePolicy: wpCreateOrOverwrite, rootDir: testRoot,
                                   checksumMode: csMd5)
        let (ok, errCode, _) = checkWriteAccess(config, resolvedPath)
        check ok == false
        check errCode == errAccessViolation

        # The real sidecar is untouched.
        check readFile(testRoot / "real_target.md5") == "deadbeef  real_target\n"

      if aliasCreated and symlinkExists(testRoot / "md5_alias"):
        removeFile(testRoot / "md5_alias")
      removeFile(testRoot / "real_target.md5")

suite "checkHostAccess":
  test "empty allowlist allows all":
    let config = ServerConfig(allowedHosts: @[], deniedHosts: @[])
    check checkHostAccess(config, "10.0.0.1") == true
    check checkHostAccess(config, "192.168.1.1") == true

  test "allowlist restricts to listed hosts":
    let config = ServerConfig(allowedHosts: @["10.0.0.1", "10.0.0.2"], deniedHosts: @[])
    check checkHostAccess(config, "10.0.0.1") == true
    check checkHostAccess(config, "10.0.0.2") == true
    check checkHostAccess(config, "10.0.0.3") == false

  test "denylist blocks listed hosts":
    let config = ServerConfig(allowedHosts: @[], deniedHosts: @["192.168.1.100"])
    check checkHostAccess(config, "192.168.1.100") == false
    check checkHostAccess(config, "192.168.1.101") == true

  test "denylist takes precedence over allowlist":
    let config = ServerConfig(
      allowedHosts: @["10.0.0.1"],
      deniedHosts: @["10.0.0.1"]
    )
    check checkHostAccess(config, "10.0.0.1") == false

suite "validateWritePath":
  test "path inside root is ok":
    let (ok, err) = validateWritePath(testRoot, testRoot / "existing.txt")
    check ok == true
    check err.len == 0

  test "path lexically outside root is rejected":
    let (ok, err) = validateWritePath(testRoot, outsideRoot / "secret.txt")
    check ok == false
    check err.len > 0

suite "writeSidecar containment (slice 4)":
  # RFC checksum-integrity-error-hygiene, Ds (fixes defect 4 — reopens the
  # #19 class if skipped): `writeSidecar` must independently refuse a
  # pre-existing symlink at the sidecar path, on top of validateWritePath's
  # containment check.
  let outsideTarget = outsideRoot / "sidecar_escape_target.txt"

  test "symlink-escape refusal: pre-planted <name>.md5 symlink to an outside file is refused":
    if not symlinkOk:
      checkpoint("symlink creation unsupported here — sidecar escape test skipped")
      skip()
    else:
      writeFile(outsideTarget, "original outside content")
      let resolvedPath = testRoot / "sidecar_escape.txt"
      createSymlink(outsideTarget, resolvedPath & ".md5")
      let (ok, err) = writeSidecar(testRoot, resolvedPath, "deadbeef")
      check ok == false
      check err.len > 0
      # Containment refused the write entirely: the outside target must be
      # untouched (still its original content, not overwritten with the
      # sidecar text), and the symlink itself is left exactly as planted.
      check readFile(outsideTarget) == "original outside content"
      check symlinkExists(resolvedPath & ".md5")

  test "normal sidecar still writes when no symlink is present":
    let resolvedPath = testRoot / "sidecar_normal.txt"
    writeFile(resolvedPath, "content")
    let (ok, err) = writeSidecar(testRoot, resolvedPath, "cafebabe")
    check ok == true
    check err.len == 0
    check readFile(resolvedPath & ".md5") == "cafebabe  sidecar_normal.txt\n"

  test "write failure (missing parent directory) never raises":
    # Portable, root-proof failure trigger: writeFile into a non-existent
    # parent directory raises IOError regardless of process privilege —
    # unlike a read-only-directory test, which a root-run container can
    # bypass via DAC override (same caveat as the slice 3b open-failure
    # test). Proves the never-raise contract without faking a permission
    # failure that wouldn't actually fail as root.
    let resolvedPath = testRoot / "no_such_subdir" / "f.txt"
    let (ok, err) = writeSidecar(testRoot, resolvedPath, "deadbeef")
    check ok == false
    check err.len > 0

suite "Cleanup":
  test "remove test directory":
    # Remove symlinks explicitly first so directory teardown never follows
    # `escape_dir` into (and deletes the contents of) the outside target.
    for link in ["evil_link", "escape_dir", "good_link", "sidecar_escape.txt.md5"]:
      if symlinkExists(testRoot / link):
        removeFile(testRoot / link)
    removeDir(testRoot)
    removeDir(outsideRoot)
    check not dirExists(testRoot)
    check not dirExists(outsideRoot)
