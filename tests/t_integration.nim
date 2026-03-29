## Integration tests — external TFTP server + our own client-to-server tests.

import unittest
import std/[os, strutils, envvars, asyncdispatch]
import ../src/chapulin/protocol
import ../src/chapulin/engine
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

type ErrorRef = ref object
  msg: string

proc newErrorRef(): ErrorRef = ErrorRef(msg: "")

proc makeCallbacks(err: ErrorRef): TransferCallbacks =
  TransferCallbacks(
    onProgress: proc(b: int64, t: int64) = discard,
    onComplete: proc() = discard,
    onError: proc(code: int, msg: string) = err.msg = msg
  )

suite "Integration - GET":
  test "download small file":
    skipIfNoServer()
    let outPath = "/tmp/chapulin_int_hello.txt"
    defer: removeFile(outPath)

    let errRef = newErrorRef()
    let callbacks = makeCallbacks(errRef)
    let req = newTransferRequest(tftpHost, tftpPort, "hello.txt", outPath, tdGet)
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)

    if not result.success:
      echo "  Error: " & errRef.msg
    check result.success == true
    check result.bytesTransferred > 0
    check fileExists(outPath)
    let content = readFile(outPath)
    check "Hello TFTP World" in content

  test "download 10KB binary file":
    skipIfNoServer()
    let outPath = "/tmp/chapulin_int_random.bin"
    defer: removeFile(outPath)

    let errRef = newErrorRef()
    let callbacks = makeCallbacks(errRef)
    let req = newTransferRequest(tftpHost, tftpPort, "random.bin", outPath, tdGet)
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)

    if not result.success:
      echo "  Error: " & errRef.msg
    check result.success == true
    check result.bytesTransferred == 10240

  test "download nonexistent file":
    skipIfNoServer()
    let outPath = "/tmp/chapulin_int_missing.txt"
    defer: removeFile(outPath)

    let errRef = newErrorRef()
    let callbacks = makeCallbacks(errRef)
    let req = newTransferRequest(tftpHost, tftpPort, "does_not_exist.txt", outPath, tdGet)
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)

    check result.success == false
    check errRef.msg.len > 0

  test "download with custom blocksize":
    skipIfNoServer()
    let outPath = "/tmp/chapulin_int_bs.bin"
    defer: removeFile(outPath)

    let errRef = newErrorRef()
    let callbacks = makeCallbacks(errRef)
    var req = newTransferRequest(tftpHost, tftpPort, "random.bin", outPath, tdGet)
    req.options.blocksize = 1024
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)

    if not result.success:
      echo "  Error: " & errRef.msg
    check result.success == true
    check result.bytesTransferred == 10240

suite "Integration - PUT":
  setup:
    let uploadFile = "/tmp/chapulin_int_upload.txt"
    writeFile(uploadFile, "Test upload content from chapulin integration test\n")

  teardown:
    removeFile("/tmp/chapulin_int_upload.txt")

  test "upload small file":
    skipIfNoServer()

    let errRef = newErrorRef()
    let callbacks = makeCallbacks(errRef)
    let req = newTransferRequest(tftpHost, tftpPort, "uploaded.txt",
                                  uploadFile, tdPut)
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)

    if not result.success:
      echo "  Error: " & errRef.msg
    check result.success == true
    check result.bytesTransferred > 0

suite "Integration - Progress":
  test "progress callback fires during multi-block download":
    skipIfNoServer()
    let outPath = "/tmp/chapulin_int_progress.bin"
    defer: removeFile(outPath)

    let progressCount = new int
    progressCount[] = 0
    let errRef2 = newErrorRef()

    let callbacks = TransferCallbacks(
      onProgress: proc(b: int64, t: int64) =
        progressCount[].inc,
      onComplete: proc() = discard,
      onError: proc(code: int, msg: string) = errRef2.msg = msg
    )

    let req = newTransferRequest(tftpHost, tftpPort, "random.bin", outPath, tdGet)
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)

    if not result.success:
      echo "  Error: " & errRef2.msg
    check result.success == true
    check progressCount[] > 1

suite "Integration - Large file (>128KB, block numbers >255)":
  test "download 256KB file — proves byte order works for block >255":
    skipIfNoServer()
    let outPath = "/tmp/chapulin_int_large.bin"
    defer: removeFile(outPath)

    let errRef3 = newErrorRef()
    let callbacks = makeCallbacks(errRef3)
    let req = newTransferRequest(tftpHost, tftpPort, "large.bin", outPath, tdGet)
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)

    if not result.success:
      echo "  Error: " & errRef3.msg
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
    # Start server on the async event loop — non-blocking
    asyncCheck serverInstance.run(selfTestListener)
    check serverInstance.running == true

suite "Self-hosted - Client GET from our server":
  test "download small file":
    let outPath = "/tmp/chapulin_self_get.txt"
    defer: removeFile(outPath)
    let errRef = newErrorRef()
    let callbacks = makeCallbacks(errRef)
    let req = newTransferRequest("127.0.0.1", selfTestPort,
                                  "readme.txt", outPath, tdGet)
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)
    if udp.close != nil: udp.close()
    if not result.success:
      echo "  Self-hosted GET error: " & errRef.msg
    check result.success == true
    check fileExists(outPath)
    check readFile(outPath) == "Self-test file content"

  test "download multi-block file":
    let outPath = "/tmp/chapulin_self_multi.bin"
    defer: removeFile(outPath)
    let errRef = newErrorRef()
    let callbacks = makeCallbacks(errRef)
    let req = newTransferRequest("127.0.0.1", selfTestPort,
                                  "multiblock.bin", outPath, tdGet)
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)
    if udp.close != nil: udp.close()
    if not result.success:
      echo "  Self-hosted multi GET error: " & errRef.msg
    check result.success == true
    check result.bytesTransferred == 2000

  test "file not found":
    let outPath = "/tmp/chapulin_self_missing.txt"
    defer: removeFile(outPath)
    let errRef = newErrorRef()
    let callbacks = makeCallbacks(errRef)
    let req = newTransferRequest("127.0.0.1", selfTestPort,
                                  "nonexistent.txt", outPath, tdGet)
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)
    if udp.close != nil: udp.close()
    check result.success == false

  test "path traversal rejected":
    let outPath = "/tmp/chapulin_self_traversal.txt"
    defer: removeFile(outPath)
    let errRef = newErrorRef()
    let callbacks = makeCallbacks(errRef)
    let req = newTransferRequest("127.0.0.1", selfTestPort,
                                  "../../../etc/passwd", outPath, tdGet)
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)
    if udp.close != nil: udp.close()
    check result.success == false

suite "Self-hosted - Client PUT to our server":
  test "upload small file":
    let uploadPath = "/tmp/chapulin_self_upload_src.txt"
    writeFile(uploadPath, "Uploaded via self-test")
    defer: removeFile(uploadPath)
    let clientConfig = TftpClientConfig(
      timeout: 3, retries: 3, blocksize: DefaultBlocksize,
      requestTsize: false, tsize: -1
    )
    let ct = newUdpTransport()
    var file = open(uploadPath, fmRead)
    defer: file.close()
    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      let offset = int64(blockNum - 1) * int64(blocksize)
      file.setFilePos(offset)
      var buf = newSeq[byte](blocksize)
      let bytesRead = file.readBytes(buf, 0, blocksize)
      buf.setLen(bytesRead)
      return buf
    let result = waitFor putFile(ct, clientConfig,
                                  "127.0.0.1", selfTestPort, "writable.txt", readData)
    if ct.close != nil: ct.close()
    if not result.success:
      echo "  Self-hosted PUT error: " & result.errorMsg
    check result.success == true
    check result.bytesTransferred > 0
    check readFile(selfTestRoot / "writable.txt") == "Uploaded via self-test"

  test "upload with options (tsize)":
    let uploadPath = "/tmp/chapulin_self_upload_opt.txt"
    writeFile(uploadPath, "Options upload test")
    defer: removeFile(uploadPath)
    let errRef = newErrorRef()
    let callbacks = makeCallbacks(errRef)
    let req = newTransferRequest("127.0.0.1", selfTestPort,
                                  "writable.txt", uploadPath, tdPut)
    let udp = newUdpTransport()
    let result = waitFor executeTransfer(req, callbacks, udp)
    if udp.close != nil: udp.close()
    if not result.success:
      echo "  Self-hosted PUT+options error: " & errRef.msg
    check result.success == true

suite "Self-hosted - Concurrent transfers":
  test "two simultaneous async GETs succeed":
    # Both transfers run concurrently on the same async event loop
    proc twoGets(): Future[tuple[r1: TransferResult, r2: TransferResult]] {.async.} =
      let errRef1 = newErrorRef()
      let cb1 = makeCallbacks(errRef1)
      let req1 = newTransferRequest("127.0.0.1", selfTestPort,
                                     "multiblock.bin", "/tmp/chapulin_conc1.bin", tdGet)
      let udp1 = newUdpTransport()

      let errRef2 = newErrorRef()
      let cb2 = makeCallbacks(errRef2)
      let req2 = newTransferRequest("127.0.0.1", selfTestPort,
                                     "readme.txt", "/tmp/chapulin_conc2.txt", tdGet)
      let udp2 = newUdpTransport()

      # Launch both transfers concurrently on the event loop
      let fut1 = executeTransfer(req1, cb1, udp1)
      let fut2 = executeTransfer(req2, cb2, udp2)

      let r1 = await fut1
      let r2 = await fut2

      if udp1.close != nil: udp1.close()
      if udp2.close != nil: udp2.close()
      return (r1: r1, r2: r2)

    let (result1, result2) = waitFor twoGets()
    defer:
      removeFile("/tmp/chapulin_conc1.bin")
      removeFile("/tmp/chapulin_conc2.txt")

    if not result1.success:
      echo "  Concurrent GET 1 error: " & result1.errorMsg
    if not result2.success:
      echo "  Concurrent GET 2 error: " & result2.errorMsg
    check result1.success == true
    check result2.success == true
    check result1.bytesTransferred == 2000
    check readFile("/tmp/chapulin_conc2.txt") == "Self-test file content"

suite "Self-hosted server teardown":
  test "stop server and clean up":
    serverInstance.stop()
    # Drain any pending async events
    waitFor sleepAsync(100)
    selfTestListener.close()
    removeDir(selfTestRoot)
    check not dirExists(selfTestRoot)
