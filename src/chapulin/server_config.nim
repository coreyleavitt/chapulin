## Server configuration types.

import transfer

type
  WritePolicy* = enum
    wpDeny              ## Read-only server (default)
    wpCreateOnly        ## Allow creating new files only
    wpOverwrite         ## Allow overwriting existing files
    wpCreateOrOverwrite ## Allow both create and overwrite

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
    allowedHosts: @[],
    deniedHosts: @[]
  )
