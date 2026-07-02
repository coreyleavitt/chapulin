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

proc parseChecksumMode*(s: string): ChecksumMode =
  ## Parse a checksum mode string from CLI/config.
  ## Raises ValueError for unrecognised values.
  case s.toLowerAscii
  of "md5":    csMd5
  of "sha256": raise newException(ValueError,
      "checksum mode 'sha256' is not yet implemented (use md5 or none)")
  of "", "none": csNone
  else: raise newException(ValueError, "Invalid checksum mode: '" & s &
      "' (expected md5 or none)")
