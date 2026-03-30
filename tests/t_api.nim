import unittest
import std/[os, strutils, asyncdispatch]
import ../src/chapulin/protocol
import ../src/chapulin/engine
import ../src/chapulin/api
import helpers

# Alias for backward compat with existing tests
proc newMockState(): MockTransport = newMockTransport()

suite "API - startGetTransfer":
  test "successful download invokes progress and complete callbacks":
    let mt = newMockState()
    mt.addResponse(makeDataPkt(1, @[byte 1, 2, 3]))

    var progressCalled = false
    var completeCalled = false
    var progressBytes: int64 = 0
    var errorCalled = false

    let callbacks = TransferCallbacks(
      onProgress: proc(b: int64, t: int64) = progressCalled = true; progressBytes = b,
      onComplete: proc() = completeCalled = true,
      onError: proc(code: int, msg: string) = errorCalled = true
    )

    let req = newTransferRequest("127.0.0.1", 69, "test.txt", getTempDir() / "test_out.bin", tdGet)
    let result = waitFor executeTransfer(req, callbacks, mt.toTransport)

    check result.success == true
    check result.bytesTransferred == 3
    check progressCalled == true
    check progressBytes == 3
    check completeCalled == true
    check errorCalled == false

  test "failed download invokes error callback":
    let mt = newMockState()
    mt.addResponse(makeErrorPkt(errFileNotFound, "Not found"))

    var errorCalled = false
    var errorMessage = ""
    var completeCalled = false

    let callbacks = TransferCallbacks(
      onProgress: proc(b: int64, t: int64) = discard,
      onComplete: proc() = completeCalled = true,
      onError: proc(code: int, msg: string) = errorCalled = true; errorMessage = msg
    )

    let req = newTransferRequest("127.0.0.1", 69, "missing.txt", getTempDir() / "test_out.bin", tdGet)
    let result = waitFor executeTransfer(req, callbacks, mt.toTransport)

    check result.success == false
    check errorCalled == true
    check "Not found" in errorMessage
    check completeCalled == false

suite "API - startPutTransfer":
  setup:
    # Create a small temp file for upload tests
    let testFile = getTempDir() / "chapulin_test_upload.bin"
    writeFile(testFile, "hello world")

  teardown:
    removeFile(getTempDir() / "chapulin_test_upload.bin")

  test "successful upload invokes progress and complete":
    let mt = newMockState()
    mt.addResponse(makeAckPkt(0))  # ACK for WRQ
    mt.addResponse(makeAckPkt(1))  # ACK for data block 1

    var progressCalled = false
    var completeCalled = false

    let callbacks = TransferCallbacks(
      onProgress: proc(b: int64, t: int64) = progressCalled = true,
      onComplete: proc() = completeCalled = true,
      onError: proc(code: int, msg: string) = discard
    )

    let req = newTransferRequest("127.0.0.1", 69, "upload.txt",
                                  getTempDir() / "chapulin_test_upload.bin", tdPut)
    let result = waitFor executeTransfer(req, callbacks, mt.toTransport)

    check result.success == true
    check progressCalled == true
    check completeCalled == true

suite "API - TransferRequest defaults":
  test "default options are sensible":
    let req = newTransferRequest("10.0.0.1", 69, "config.bin", getTempDir() / "out", tdGet)
    check req.host == "10.0.0.1"
    check req.port == 69
    check req.options.blocksize == 512
    check req.options.timeout == 5
    check req.options.retries == 3
    check req.direction == tdGet

suite "API - cancellation":
  test "cancel stops transfer":
    let mt = newMockState()
    # Add enough responses to keep the transfer going
    for i in 1'u16 .. 100'u16:
      mt.addResponse(makeDataPkt(i, newSeq[byte](512)))

    var blockCount = 0
    var errorCalled = false

    let callbacks = TransferCallbacks(
      onProgress: proc(b: int64, t: int64) = blockCount.inc,
      onComplete: proc() = discard,
      onError: proc(code: int, msg: string) = errorCalled = true
    )

    let req = newTransferRequest("127.0.0.1", 69, "big.bin", getTempDir() / "out", tdGet)

    # Cancel after 3 progress callbacks
    let cancelAfter = 3
    let result = waitFor executeTransfer(req, callbacks, mt.toTransport,
      cancelCheck = proc(): bool = blockCount >= cancelAfter)

    check result.success == false
    check blockCount <= cancelAfter + 1  # may get one more before cancel is checked
    check errorCalled == true

suite "API - file I/O error handling":
  test "GET to invalid path invokes error callback, not unhandled exception":
    let mt = newMockState()
    mt.addResponse(makeDataPkt(1, @[byte 1, 2, 3]))

    var errorCalled = false
    var errorMsg = ""

    let callbacks = TransferCallbacks(
      onProgress: proc(b: int64, t: int64) = discard,
      onComplete: proc() = discard,
      onError: proc(code: int, msg: string) = errorCalled = true; errorMsg = msg
    )

    # Path that doesn't exist — open() will fail
    let req = newTransferRequest("127.0.0.1", 69, "test.txt",
                                  "/nonexistent/dir/file.txt", tdGet)
    try:
      let result = waitFor executeTransfer(req, callbacks, mt.toTransport)
      # If we get here, the fix is in and error was handled gracefully
      check result.success == false
      check errorCalled == true
    except IOError:
      # Current behavior: unhandled IOError propagates. This documents the bug.
      fail()

  test "PUT from nonexistent file invokes error callback":
    let mt = newMockState()
    mt.addResponse(makeAckPkt(0))

    var errorCalled = false

    let callbacks = TransferCallbacks(
      onProgress: proc(b: int64, t: int64) = discard,
      onComplete: proc() = discard,
      onError: proc(code: int, msg: string) = errorCalled = true
    )

    let req = newTransferRequest("127.0.0.1", 69, "upload.txt",
                                  getTempDir() / "this_file_does_not_exist.bin", tdPut)
    try:
      let result = waitFor executeTransfer(req, callbacks, mt.toTransport)
      check result.success == false
      check errorCalled == true
    except IOError:
      fail()

  test "GET to read-only directory invokes error callback":
    let mt = newMockState()
    mt.addResponse(makeDataPkt(1, @[byte 1]))

    var errorCalled = false

    let callbacks = TransferCallbacks(
      onProgress: proc(b: int64, t: int64) = discard,
      onComplete: proc() = discard,
      onError: proc(code: int, msg: string) = errorCalled = true
    )

    # /proc is read-only on Linux
    let req = newTransferRequest("127.0.0.1", 69, "test.txt",
                                  "/proc/test_output.bin", tdGet)
    try:
      let result = waitFor executeTransfer(req, callbacks, mt.toTransport)
      check result.success == false
      check errorCalled == true
    except IOError:
      fail()
