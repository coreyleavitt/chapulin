## Structured logging — shared by client and server.
## Pure formatting + configurable output sink.

import std/[strutils, times]

type
  LogLevel* = enum
    llDebug = "DEBUG"
    llInfo = "INFO"
    llWarn = "WARN"
    llError = "ERROR"
    llNone = "NONE"  ## suppresses all output

  LogOutput* = proc(level: LogLevel, msg: string) {.closure.}

  Logger* = ref object
    minLevel*: LogLevel
    output*: LogOutput

proc newLogger*(minLevel: LogLevel = llInfo, output: LogOutput = nil): Logger =
  Logger(minLevel: minLevel, output: output)

proc log*(logger: Logger, level: LogLevel, msg: string) =
  if logger.output == nil: return
  if level == llNone: return
  if ord(level) >= ord(logger.minLevel):
    logger.output(level, msg)

proc debug*(logger: Logger, msg: string) = logger.log(llDebug, msg)
proc info*(logger: Logger, msg: string) = logger.log(llInfo, msg)
proc warn*(logger: Logger, msg: string) = logger.log(llWarn, msg)
proc error*(logger: Logger, msg: string) = logger.log(llError, msg)

# --- Formatting ---

proc formatLogMessage*(level: LogLevel, msg: string): string =
  let prefix = case level
    of llDebug: "[DEBUG] "
    of llInfo:  "[INFO]  "
    of llWarn:  "[WARN]  "
    of llError: "[ERROR] "
    of llNone:  ""
  prefix & msg

proc formatTransferLog*(direction: string, clientHost: string, clientPort: int,
                         filename: string, success: bool, bytes: int64,
                         durationMs: float, errorMsg: string = ""): string =
  let status = if success: "OK" else: "FAILED"
  let bytesStr = if bytes < 1024: $bytes & "B"
                 elif bytes < 1048576: $(bytes div 1024) & "KB"
                 else: $(bytes div 1048576) & "MB"
  let durationStr = if durationMs < 1000: durationMs.formatFloat(ffDecimal, 0) & "ms"
                    else: (durationMs / 1000).formatFloat(ffDecimal, 2) & "s"
  result = direction & " " & filename & " " & clientHost & ":" & $clientPort &
           " " & status & " " & bytesStr & " " & durationStr
  if not success and errorMsg.len > 0:
    result &= " (" & errorMsg & ")"

# --- Standard output sinks ---

proc stderrOutput*(level: LogLevel, msg: string) =
  stderr.writeLine formatLogMessage(level, msg)
  stderr.flushFile

proc stdoutOutput*(level: LogLevel, msg: string) =
  echo formatLogMessage(level, msg)
