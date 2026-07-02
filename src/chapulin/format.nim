## Shared formatting utilities for CLI and GUI.

import std/strutils
import std/options

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

proc fraction*(bytes: int64, total: Option[int64]): Option[float] =
  ## Return bytes/total as a float in [0.0, ∞), or none when total is unknown.
  ## Returns some(0.0) when total is 0 (avoids division-by-zero).
  total.map(proc(t: int64): float = (if t > 0: bytes.float / t.float else: 0.0))

proc sanitizeForDisplay*(s: string): string =
  ## Replace control characters (ord < 0x20 or == 0x7F) with '?' to prevent
  ## terminal escape injection at display sites.  Bytes >= 0x80 pass through
  ## unchanged so valid UTF-8 multibyte sequences are preserved.
  ## Pure, FFI-free: plain Nim string scan, no external calls.
  result = newStringOfCap(s.len)
  for c in s:
    if ord(c) < 0x20 or ord(c) == 0x7f: result.add '?'
    else: result.add c
