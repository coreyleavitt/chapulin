import unittest
import std/os
import ../src/chapulin/protocol
import ../src/chapulin/server_config
import ../src/chapulin/security

# Create a temp directory structure for testing
let testRoot = getTempDir() / "chapulin_security_test"

suite "Setup":
  test "create test directory structure":
    createDir(testRoot)
    createDir(testRoot / "subdir")
    writeFile(testRoot / "existing.txt", "hello")
    writeFile(testRoot / "subdir" / "nested.txt", "nested")
    check dirExists(testRoot)

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

  test "rejects absolute path":
    let (valid, _, err) = validatePath(testRoot, "/etc/passwd")
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
    removeDir(testRoot)
    check not dirExists(testRoot)
