## Shared formatting utilities for CLI and GUI.

import std/strutils

proc formatBytes*(bytes: int64): string =
  if bytes < 1024: return $bytes & " B"
  elif bytes < 1048576:
    return (float(bytes) / 1024.0).formatFloat(ffDecimal, 1) & " KB"
  else:
    return (float(bytes) / 1048576.0).formatFloat(ffDecimal, 1) & " MB"

proc formatSpeed*(bytesPerSec: float): string =
  if bytesPerSec < 1024: return bytesPerSec.formatFloat(ffDecimal, 0) & " B/s"
  elif bytesPerSec < 1048576: return (bytesPerSec / 1024).formatFloat(ffDecimal, 1) & " KB/s"
  else: return (bytesPerSec / 1048576).formatFloat(ffDecimal, 1) & " MB/s"
