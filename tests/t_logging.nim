import unittest
import std/strutils
import ../src/chapulin/logging

suite "Log level filtering":
  test "debug level passes all messages":
    var messages: seq[string] = @[]
    let logger = newLogger(llDebug, proc(level: LogLevel, msg: string) =
      messages.add $level & ": " & msg)
    logger.debug("trace info")
    logger.info("status")
    logger.warn("caution")
    logger.error("failure")
    check messages.len == 4

  test "info level filters debug":
    var messages: seq[string] = @[]
    let logger = newLogger(llInfo, proc(level: LogLevel, msg: string) =
      messages.add msg)
    logger.debug("hidden")
    logger.info("visible")
    logger.warn("visible")
    logger.error("visible")
    check messages.len == 3

  test "warn level filters debug and info":
    var messages: seq[string] = @[]
    let logger = newLogger(llWarn, proc(level: LogLevel, msg: string) =
      messages.add msg)
    logger.debug("hidden")
    logger.info("hidden")
    logger.warn("visible")
    logger.error("visible")
    check messages.len == 2

  test "error level filters everything below":
    var messages: seq[string] = @[]
    let logger = newLogger(llError, proc(level: LogLevel, msg: string) =
      messages.add msg)
    logger.debug("hidden")
    logger.info("hidden")
    logger.warn("hidden")
    logger.error("visible")
    check messages.len == 1

  test "none level suppresses all":
    var messages: seq[string] = @[]
    let logger = newLogger(llNone, proc(level: LogLevel, msg: string) =
      messages.add msg)
    logger.debug("hidden")
    logger.info("hidden")
    logger.warn("hidden")
    logger.error("hidden")
    check messages.len == 0

suite "Log formatting":
  test "formatLogMessage includes level prefix":
    check formatLogMessage(llInfo, "test") == "[INFO]  test"
    check formatLogMessage(llWarn, "caution") == "[WARN]  caution"
    check formatLogMessage(llError, "bad") == "[ERROR] bad"
    check formatLogMessage(llDebug, "trace") == "[DEBUG] trace"

  test "formatTransferLog includes all fields":
    let msg = formatTransferLog("RRQ", "10.0.0.1", 5000, "firmware.bin",
                                 success = true, bytes = 10240, durationMs = 150.0)
    check "RRQ" in msg
    check "10.0.0.1" in msg
    check "firmware.bin" in msg
    check "10" in msg  # bytes are formatted (10KB or 10240)

  test "formatTransferLog handles failure":
    let msg = formatTransferLog("WRQ", "10.0.0.1", 5000, "upload.txt",
                                 success = false, bytes = 0, durationMs = 50.0,
                                 errorMsg = "Access denied")
    check "FAILED" in msg or "failed" in msg
    check "Access denied" in msg

suite "Logger with nil output":
  test "nil output does not crash":
    let logger = newLogger(llInfo, nil)
    logger.info("should not crash")
    logger.error("should not crash")
