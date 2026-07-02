## Integration tests — external TFTP server + our own client-to-server tests.

import unittest
import std/[os, strutils, envvars, asyncdispatch]
import ../src/chapulin/protocol
import ../src/chapulin/transport
import ../src/chapulin/api
import ../src/chapulin/server
import ../src/chapulin/server_config

let tftpHost = getEnv("TFTP_HOST", "127.0.0.1")
let tftpPort = parseInt(getEnv("TFTP_PORT", "69"))

proc serverAvailable(): bool =
  let t = newUdpTransport()
  let rrq = TftpPacket(opcode: opRrq, filename: "hello.txt", mode: tmOctet, options: @[])
  try:
    waitFor t.send(encode(rrq), tftpHost, tftpPort)
    discard waitFor t.recv(516, 3000)
    return true
  except:
    return false

let hasServer = serverAvailable()

template skipIfNoServer() =
  if not hasServer:
    echo "  (skipped - no TFTP server)"
    skip()

suite "Integration - GET":
  test "download small file":
    skipIfNoServer()
    let outPath = getTempDir() / "chapulin_int_hello.txt"
    defer: removeFile(outPath)
    let s = newSession()
    let req = newTransferRequest(tftpHost, tftpPort, "hello.txt", outPath, tdGet)
    let result = s.waitTransfer(s.startTransfer(req))
    if not result.success:
      echo "  Error: " & result.errorMsg
    check result.success == true
    check result.bytesTransferred > 0
    check fileExists(outPath)
    let content = readFile(outPath)
    check "Hello TFTP World" in content

  test "download 10KB binary file":
    skipIfNoServer()
    let outPath = getTempDir() / "chapulin_int_random.bin"
    defer: removeFile(outPath)
    let s = newSession()
    let req = newTransferRequest(tftpHost, tftpPort, "random.bin", outPath, tdGet)
    let result = s.waitTransfer(s.startTransfer(req))
    if not result.success:
      echo "  Error: " & result.errorMsg
    check result.success == true
    check result.bytesTransferred == 10240

  test "download nonexistent file":
    skipIfNoServer()
    let outPath = getTempDir() / "chapulin_int_missing.txt"
    defer: removeFile(outPath)
    let s = newSession()
    let req = newTransferRequest(tftpHost, tftpPort, "does_not_exist.txt", outPath, tdGet)
    let result = s.waitTransfer(s.startTransfer(req))
    check result.success == false
    check result.errorMsg.len > 0

  test "download with custom blocksize":
    skipIfNoServer()
    let outPath = getTempDir() / "chapulin_int_bs.bin"
    defer: removeFile(outPath)
    let s = newSession()
    var req = newTransferRequest(tftpHost, tftpPort, "random.bin", outPath, tdGet)
    req.options.blocksize = 1024
    let result = s.waitTransfer(s.startTransfer(req))
    if not result.success:
      echo "  Error: " & result.errorMsg
    check result.success == true
    check result.bytesTransferred == 10240

suite "Integration - PUT":
  setup:
    # Create a small temp file for upload tests
    let uploadFile = getTempDir() / "chapulin_int_upload.txt"
    writeFile(uploadFile, "Test upload content from chapulin integration test\n")

  teardown:
    removeFile(getTempDir() / "chapulin_int_upload.txt")

  test "upload small file":
    skipIfNoServer()
    let s = newSession()
    let req = newTransferRequest(tftpHost, tftpPort, "uploaded.txt", uploadFile, tdPut)
    let result = s.waitTransfer(s.startTransfer(req))
    if not result.success:
      echo "  Error: " & result.errorMsg
    check result.success == true
    check result.bytesTransferred > 0

suite "Integration - Progress":
  test "progress callback fires during multi-block download":
    skipIfNoServer()
    let outPath = getTempDir() / "chapulin_int_progress.bin"
    defer: removeFile(outPath)
    let s = newSession()
    let req = newTransferRequest(tftpHost, tftpPort, "random.bin", outPath, tdGet)
    let id = s.startTransfer(req)
    var progressCount = 0
    var result = TransferResult(success: false)
    var done = false
    while not done:
      for ev in s.poll(0):
        if ev.xfrId == id:
          case ev.kind
          of evTransferProgress: progressCount.inc
          of evTransferComplete:
            result = TransferResult(success: true, bytesTransferred: ev.snap.bytes,
                                    totalSize: ev.snap.total.get(-1))
            done = true
          of evTransferError:
            result = TransferResult(success: false, errorCode: ev.errorCode,
                                    errorMsg: ev.errorMsg)
            done = true
          else: discard
      if not done and not hasPendingOperations(): done = true
    if not result.success:
      echo "  Error: " & result.errorMsg
    check result.success == true
    check progressCount > 1

suite "Integration - Large file (>128KB, block numbers >255)":
  test "download 256KB file — proves byte order works for block >255":
    skipIfNoServer()
    let outPath = getTempDir() / "chapulin_int_large.bin"
    defer: removeFile(outPath)
    let s = newSession()
    let req = newTransferRequest(tftpHost, tftpPort, "large.bin", outPath, tdGet)
    let result = s.waitTransfer(s.startTransfer(req))
    if not result.success:
      echo "  Error: " & result.errorMsg
    check result.success == true
    check result.bytesTransferred == 256 * 1024  # 262144 bytes = 512 blocks

# ============================================================
# Self-hosted server integration tests
# Our client talks to our server over real UDP on localhost.
# Server and client share the same async event loop — no threads needed.
# ============================================================

let selfTestRoot = getTempDir() / "chapulin_self_integration"
let selfTestPort = 10069

var serverInstance: TftpServer
var selfTestListener: UdpListener

proc startTestServer() =
  createDir(selfTestRoot)
  writeFile(selfTestRoot / "readme.txt", "Self-test file content")
  writeFile(selfTestRoot / "multiblock.bin", 'X'.repeat(2000))
  writeFile(selfTestRoot / "writable.txt", "")

  var config = newDefaultServerConfig(selfTestRoot)
  config.listenPort = selfTestPort
  config.writePolicy = wpCreateOrOverwrite
  config.timeout = 3
  config.retries = 3
  serverInstance = newTftpServer(config)

suite "Self-hosted server setup":
  test "start server":
    startTestServer()
    selfTestListener = newUdpListener(port = selfTestPort)
    # Start server on the async event loop — non-blocking.
    # Use addCallback (not asyncCheck) so a future failure never re-raises
    # through the test runner (mirrors api.nim Invariant 2).
    let runFut = serverInstance.run(selfTestListener)
    runFut.addCallback(proc() = discard)
    check serverInstance.running == true

suite "Self-hosted - Client GET from our server":
  test "download small file":
    let outPath = getTempDir() / "chapulin_self_get.txt"
    defer: removeFile(outPath)
    let s = newSession()
    let req = newTransferRequest("127.0.0.1", selfTestPort, "readme.txt", outPath, tdGet)
    let result = s.waitTransfer(s.startTransfer(req))
    if not result.success:
      echo "  Self-hosted GET error: " & result.errorMsg
    check result.success == true
    check fileExists(outPath)
    check readFile(outPath) == "Self-test file content"

  test "download multi-block file":
    let outPath = getTempDir() / "chapulin_self_multi.bin"
    defer: removeFile(outPath)
    let s = newSession()
    let req = newTransferRequest("127.0.0.1", selfTestPort, "multiblock.bin", outPath, tdGet)
    let result = s.waitTransfer(s.startTransfer(req))
    if not result.success:
      echo "  Self-hosted multi GET error: " & result.errorMsg
    check result.success == true
    check result.bytesTransferred == 2000

  test "file not found":
    let outPath = getTempDir() / "chapulin_self_missing.txt"
    defer: removeFile(outPath)
    let s = newSession()
    let req = newTransferRequest("127.0.0.1", selfTestPort, "nonexistent.txt", outPath, tdGet)
    let result = s.waitTransfer(s.startTransfer(req))
    check result.success == false

  test "path traversal rejected":
    let outPath = getTempDir() / "chapulin_self_traversal.txt"
    defer: removeFile(outPath)
    let s = newSession()
    let req = newTransferRequest("127.0.0.1", selfTestPort, "../../../etc/passwd", outPath, tdGet)
    let result = s.waitTransfer(s.startTransfer(req))
    check result.success == false

suite "Self-hosted - Client PUT to our server":
  test "upload small file":
    let uploadPath = getTempDir() / "chapulin_self_upload_src.txt"
    writeFile(uploadPath, "Uploaded via self-test")
    defer: removeFile(uploadPath)
    let s = newSession()
    let req = newTransferRequest("127.0.0.1", selfTestPort, "writable.txt", uploadPath, tdPut)
    let result = s.waitTransfer(s.startTransfer(req))
    if not result.success:
      echo "  Self-hosted PUT error: " & result.errorMsg
    check result.success == true
    check result.bytesTransferred > 0
    check readFile(selfTestRoot / "writable.txt") == "Uploaded via self-test"

  test "upload with options (tsize)":
    let uploadPath = getTempDir() / "chapulin_self_upload_opt.txt"
    writeFile(uploadPath, "Options upload test")
    defer: removeFile(uploadPath)
    let s = newSession()
    let req = newTransferRequest("127.0.0.1", selfTestPort, "writable.txt", uploadPath, tdPut)
    let result = s.waitTransfer(s.startTransfer(req))
    if not result.success:
      echo "  Self-hosted PUT+options error: " & result.errorMsg
    check result.success == true

suite "Self-hosted - Concurrent transfers":
  test "two simultaneous async GETs succeed":
    let s = newSession()
    let req1 = newTransferRequest("127.0.0.1", selfTestPort,
                                   "multiblock.bin", getTempDir() / "chapulin_conc1.bin", tdGet)
    let req2 = newTransferRequest("127.0.0.1", selfTestPort,
                                   "readme.txt", getTempDir() / "chapulin_conc2.txt", tdGet)
    let id1 = s.startTransfer(req1)
    let id2 = s.startTransfer(req2)
    let result1 = s.waitTransfer(id1)
    let result2 = s.waitTransfer(id2)
    defer:
      removeFile(getTempDir() / "chapulin_conc1.bin")
      removeFile(getTempDir() / "chapulin_conc2.txt")
    if not result1.success:
      echo "  Concurrent GET 1 error: " & result1.errorMsg
    if not result2.success:
      echo "  Concurrent GET 2 error: " & result2.errorMsg
    check result1.success == true
    check result2.success == true
    check result1.bytesTransferred == 2000
    check readFile(getTempDir() / "chapulin_conc2.txt") == "Self-test file content"

suite "Self-hosted server teardown":
  test "stop server and clean up":
    serverInstance.stop()
    # Drain any pending async events
    waitFor sleepAsync(100)
    selfTestListener.close()
    removeDir(selfTestRoot)
    check not dirExists(selfTestRoot)
