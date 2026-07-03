import unittest
import std/os
import ../src/chapulin/protocol
import ../src/chapulin/server_config
import ../src/chapulin/security

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
      check valid == true
      check resolved == testRoot / "good_link"

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

suite "Cleanup":
  test "remove test directory":
    # Remove symlinks explicitly first so directory teardown never follows
    # `escape_dir` into (and deletes the contents of) the outside target.
    for link in ["evil_link", "escape_dir", "good_link"]:
      if symlinkExists(testRoot / link):
        removeFile(testRoot / link)
    removeDir(testRoot)
    removeDir(outsideRoot)
    check not dirExists(testRoot)
    check not dirExists(outsideRoot)
