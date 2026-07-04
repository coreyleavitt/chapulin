## Server configuration types.

import transfer
import std/strutils

type
  WritePolicy* = enum
    wpDeny              ## Read-only server (default)
    wpCreateOnly        ## Allow creating new files only
    wpOverwrite         ## Allow overwriting existing files
    wpCreateOrOverwrite ## Allow both create and overwrite

  ChecksumMode* = enum
    csNone   ## Disabled (default)
    csMd5    ## Generate .md5 sidecar after successful RRQ
    csSha256 ## Reserved; not yet implemented

  ServerConfig* = object
    rootDir*: string
    listenAddr*: string
    listenPort*: int
    writePolicy*: WritePolicy
    maxConcurrent*: int
    timeout*: int
    retries*: int
    maxBlocksize*: int
    minBlocksize*: int
    maxWindowsize*: int
    minWindowsize*: int
    portRangeStart*: int  ## 0 = OS-assigned ephemeral ports (default)
    portRangeEnd*: int    ## 0 = OS-assigned ephemeral ports (default)
    pxeCompat*: bool      ## Only negotiate tsize (no blksize/windowsize/timeout)
    dirListFile*: string  ## Filename that triggers directory listing ("" = disabled)
    checksumMode*: ChecksumMode ## Checksum sidecar mode (csNone = disabled)
    allowedHosts*: seq[string]
    deniedHosts*: seq[string]

proc hasPortRange*(config: ServerConfig): bool =
  config.portRangeStart > 0 and config.portRangeEnd >= config.portRangeStart

proc newDefaultServerConfig*(rootDir: string): ServerConfig =
  ServerConfig(
    rootDir: rootDir,
    listenAddr: "0.0.0.0",
    listenPort: 69,
    writePolicy: wpDeny,
    maxConcurrent: 10,
    timeout: DefaultTimeout,
    retries: DefaultRetries,
    maxBlocksize: MaxBlocksize,
    minBlocksize: MinBlocksize,
    maxWindowsize: MaxWindowsize,
    minWindowsize: MinWindowsize,
    portRangeStart: 0,
    portRangeEnd: 0,
    pxeCompat: false,
    dirListFile: "",
    checksumMode: csNone,
    allowedHosts: @[],
    deniedHosts: @[]
  )

proc checksumModeImplemented*(m: ChecksumMode): bool =
  ## Single authority for "is this checksum mode usable" (RFC checksum-
  ## integrity-error-hygiene, H2). csSha256 is a legal enum value — a
  ## deliberate forward-compat placeholder — but has no implementation
  ## behind it (checksum.newDigester(csSha256) raises). Every boundary that
  ## must reject an unimplemented mode (the CLI's parseChecksumMode, the
  ## embedding API's startServer, and the RRQ hot path's handleRrq) routes
  ## through this ONE predicate so "which modes are usable" is decided in
  ## exactly one place instead of being re-derived — and able to drift —
  ## at each call site.
  m in {csNone, csMd5}

proc parseChecksumMode*(s: string): ChecksumMode =
  ## Parse a checksum mode string from CLI/config.
  ## Raises ValueError for unrecognised values, or for a value that names a
  ## real (but unimplemented) ChecksumMode — routed through
  ## checksumModeImplemented so this can never drift from the other
  ## boundaries that enforce the same rule.
  let mode = case s.toLowerAscii
    of "md5":      csMd5
    of "sha256":   csSha256
    of "", "none": csNone
    else: raise newException(ValueError, "Invalid checksum mode: '" & s &
        "' (expected md5 or none)")
  if not checksumModeImplemented(mode):
    raise newException(ValueError, "checksum mode '" & s.toLowerAscii &
        "' is not yet implemented (use md5 or none)")
  mode
