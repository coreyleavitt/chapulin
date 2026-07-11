## Server configuration types.

import protocol
import blocksource
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

  BlocksizeRange* = object
    ## RFC conformance-closure D8: the server's blksize option is a bounded
    ## PAIR (min<=max, both within protocol.nim's MinBlocksize..MaxBlocksize,
    ## RFC 2348) -- unlike the client's single scalar ask, the pair is what
    ## was under-modeled as two unlinked bare ints (R3). Fields stay public/
    ## hand-pokable on purpose (ServerConfig itself is never fully sealed,
    ## R4) -- `serverConfigBoundsValid` is the belt-and-suspenders guard for
    ## a pair mutated after `newBlocksizeRange` already validated it.
    minVal*, maxVal*: int

  WindowsizeRange* = object
    ## Same shape/rationale as `BlocksizeRange`, for RFC 7440 windowsize.
    minVal*, maxVal*: int

  ServerConfig* = object
    rootDir*: string
    listenAddr*: string
    listenPort*: int
    writePolicy*: WritePolicy
    maxConcurrent*: int
    timeout*: int
    retries*: int
    blocksizeRange*: BlocksizeRange
    windowsizeRange*: WindowsizeRange
    portRangeStart*: int  ## 0 = OS-assigned ephemeral ports (default)
    portRangeEnd*: int    ## 0 = OS-assigned ephemeral ports (default)
    pxeCompat*: bool      ## Only negotiate tsize (no blksize/windowsize/timeout)
    dirListFile*: string  ## Filename that triggers directory listing ("" = disabled)
    checksumMode*: ChecksumMode ## Checksum sidecar mode (csNone = disabled)
    allowedHosts*: seq[string]
    deniedHosts*: seq[string]
    sourceFactory*: BlockSourceFactory  ## RFC in-memory-sources-sinks.md §5.1.
      ## nil (default) => file-backed (`resolveSourceFactory` in server.nim
      ## folds in the existing `fileExists`/`getFileSize`/`open` logic).
      ## Lives on `ServerConfig`, not `TftpServer`, because `handleRrq`
      ## needs it and is called directly (no `TftpServer`) by ~20 tests, and
      ## the factory needs `resolvedPath`, known only inside `handleRrq`.
      ## NOTE: Nim's derived `==` over a nil-default `proc` field is
      ## referential-identity once a factory is non-nil (two configs with
      ## *different* non-nil factory closures compare unequal even if the
      ## closures behave identically) -- fine for every current comparison
      ## site (`t_session.nim:3180` compares two nil-factory configs).
    sinkFactory*: BlockSinkFactory      ## Same contract, sink side.

proc validateRangePair(minVal, maxVal, hardMin, hardMax: int; label: string) =
  ## Shared bounds-check for `newBlocksizeRange`/`newWindowsizeRange` (L7):
  ## both constructors have the same "min<=max, both within a hard RFC
  ## bound" shape and differed only in which protocol.nim constants and
  ## which label they used. Raises `ValueError` on an invalid pair -- min>max,
  ## or either endpoint outside `hardMin..hardMax`.
  if minVal > maxVal or minVal < hardMin or maxVal > hardMax:
    raise newException(ValueError,
      "invalid " & label & " range " & $minVal & ".." & $maxVal &
      " (must satisfy " & $hardMin & " <= min <= max <= " & $hardMax & ")")

proc newBlocksizeRange*(minVal, maxVal: int): BlocksizeRange =
  ## Low-level range constructor (RFC conformance-closure D8). Raises
  ## `ValueError` on an invalid pair -- min>max, or either endpoint outside
  ## protocol.nim's MinBlocksize..MaxBlocksize (RFC 2348). This is a
  ## RAISING constructor, deliberately: the never-throw guarantee lives one
  ## level up, at `newServerConfig`/`api.nim`, which wrap this call in
  ## `try/except ValueError` and fold the message into
  ## `ServerConfigOutcome.rejectReason` instead of letting it escape. A
  ## caller reaching for this constructor directly (as a range-rejection
  ## test does) sees the raise.
  validateRangePair(minVal, maxVal, MinBlocksize, MaxBlocksize, "blocksize")
  BlocksizeRange(minVal: minVal, maxVal: maxVal)

proc newWindowsizeRange*(minVal, maxVal: int): WindowsizeRange =
  ## Same contract as `newBlocksizeRange`, for RFC 7440 windowsize.
  validateRangePair(minVal, maxVal, MinWindowsize, MaxWindowsize, "windowsize")
  WindowsizeRange(minVal: minVal, maxVal: maxVal)

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
    # MinBlocksize..MaxBlocksize / MinWindowsize..MaxWindowsize are RFC
    # constants known-valid at compile time -- built directly rather than
    # through newBlocksizeRange/newWindowsizeRange so this default-config
    # path can never raise.
    blocksizeRange: BlocksizeRange(minVal: MinBlocksize, maxVal: MaxBlocksize),
    windowsizeRange: WindowsizeRange(minVal: MinWindowsize, maxVal: MaxWindowsize),
    portRangeStart: 0,
    portRangeEnd: 0,
    pxeCompat: false,
    dirListFile: "",
    checksumMode: csNone,
    allowedHosts: @[],
    deniedHosts: @[]
  )

proc serverConfigBoundsValid*(config: ServerConfig): bool =
  ## Single authority for "are this ServerConfig's option bounds legal per
  ## protocol.nim's RFC bounds" (RFC conformance-closure D7). Every boundary
  ## that must reject an invalid config (startServer, handleRrq, handleWrq)
  ## routes through this ONE predicate so "which bounds are legal" can never
  ## drift between them.
  ## ServerConfig has no real construction choke point (a plain mutable
  ## object; the CLI pokes fields directly), so this exists to be called at
  ## every entry point instead of trusted-by-construction. D8: this is also
  ## why `BlocksizeRange`/`WindowsizeRange` stay public/hand-pokable rather
  ## than sealed -- a config that got a valid pair through
  ## `newBlocksizeRange` can still have `.blocksizeRange.minVal` poked
  ## invalid afterward, and this predicate (not the constructor) is what
  ## catches that at every entry point.
  config.blocksizeRange.minVal >= MinBlocksize and
    config.blocksizeRange.maxVal <= MaxBlocksize and
    config.blocksizeRange.minVal <= config.blocksizeRange.maxVal and
    config.windowsizeRange.minVal >= MinWindowsize and
    config.windowsizeRange.maxVal <= MaxWindowsize and
    config.windowsizeRange.minVal <= config.windowsizeRange.maxVal and
    validateTimeoutOpt(config.timeout)

type
  ServerConfigOutcome* = object
    ## FLAT object -- NOT a case-object, NOT Result[T,E] (matches
    ## OackOutcome's shape; RFC conformance-closure D7 / R4). A raising
    ## constructor would be the one construction path in the never-throw
    ## `api.nim` facade (which the GUI consumer relies on) that breaks the
    ## "never raises" promise, and `Result[T,E]` would be this codebase's
    ## first generic result type. `config` is meaningful iff `ok`;
    ## `rejectReason` is "" iff `ok`.
    ok*: bool
    config*: ServerConfig
    rejectReason*: string

proc buildServerConfigOutcome(
    rootDir: string,
    listenAddr: string,
    listenPort: int,
    portRangeStart: int,
    portRangeEnd: int,
    writePolicy: WritePolicy,
    maxConcurrent: int,
    allowedHosts: seq[string],
    deniedHosts: seq[string],
    timeout: int,
    retries: int,
    blocksizeRange: BlocksizeRange,
    windowsizeRange: WindowsizeRange,
    pxeCompat: bool,
    dirListFile: string,
    checksumMode: ChecksumMode
  ): ServerConfigOutcome =
  ## Shared construction/validation body behind both `newServerConfig`
  ## overloads (M7): assembles the `ServerConfig` from already-built
  ## `BlocksizeRange`/`WindowsizeRange` values and runs
  ## `serverConfigBoundsValid` on it exactly once. Never raises -- both
  ## public overloads reach this only after their range values are already
  ## in hand (one built internally and wrapped in try/except, the other
  ## accepted directly from a caller who already validated them).
  let config = ServerConfig(
    rootDir: rootDir,
    listenAddr: listenAddr,
    listenPort: listenPort,
    writePolicy: writePolicy,
    maxConcurrent: maxConcurrent,
    timeout: timeout,
    retries: retries,
    blocksizeRange: blocksizeRange,
    windowsizeRange: windowsizeRange,
    portRangeStart: portRangeStart,
    portRangeEnd: portRangeEnd,
    pxeCompat: pxeCompat,
    dirListFile: dirListFile,
    checksumMode: checksumMode,
    allowedHosts: allowedHosts,
    deniedHosts: deniedHosts
  )
  if not serverConfigBoundsValid(config):
    # blocksizeRange/windowsizeRange are already known-valid at this point
    # (constructed above without raising) -- the only way this branch is
    # still reachable is an out-of-bound `timeout`, since that field isn't
    # covered by a range type (R3: only the server min/max PAIR became a
    # bounded-range type this slice), OR a range that was built validly via
    # `newBlocksizeRange`/`newWindowsizeRange` but whose fields were poked
    # invalid afterward before reaching the range-accepting overload (R4).
    return ServerConfigOutcome(
      ok: false,
      config: newDefaultServerConfig(rootDir),
      rejectReason: "ServerConfig timeout out of RFC range (" &
        $MinTimeoutOpt & ".." & $MaxTimeoutOpt & ")")
  ServerConfigOutcome(ok: true, config: config, rejectReason: "")

proc newServerConfig*(
    rootDir: string,
    # -- binding --
    listenAddr: string = "0.0.0.0",
    listenPort: int = 69,
    portRangeStart: int = 0,  ## 0 = OS-assigned ephemeral ports (default)
    portRangeEnd: int = 0,    ## 0 = OS-assigned ephemeral ports (default)
    # -- policy --
    writePolicy: WritePolicy = wpDeny,
    maxConcurrent: int = 10,
    allowedHosts: seq[string] = @[],
    deniedHosts: seq[string] = @[],
    # -- protocol bounds --
    timeout: int = DefaultTimeout,
    retries: int = DefaultRetries,
    blocksizeRange: BlocksizeRange,
    windowsizeRange: WindowsizeRange,
    # -- features --
    pxeCompat: bool = false,
    dirListFile: string = "",
    checksumMode: ChecksumMode = csNone
  ): ServerConfigOutcome =
  ## Range-accepting overload (M7): for a caller who already holds
  ## pre-validated `BlocksizeRange`/`WindowsizeRange` values (e.g. built via
  ## `newBlocksizeRange`/`newWindowsizeRange`, or forwarded from another
  ## validated `ServerConfig`), this skips rebuilding the ranges from four
  ## loose ints and gets the "invalid pair is unrepresentable at this
  ## boundary" guarantee those range constructors provide directly. Shares
  ## `buildServerConfigOutcome` with the four-int overload below so the two
  ## never assemble a `ServerConfig` differently.
  buildServerConfigOutcome(rootDir, listenAddr, listenPort, portRangeStart,
    portRangeEnd, writePolicy, maxConcurrent, allowedHosts, deniedHosts,
    timeout, retries, blocksizeRange, windowsizeRange, pxeCompat,
    dirListFile, checksumMode)

proc newServerConfig*(
    rootDir: string,
    # -- binding --
    listenAddr: string = "0.0.0.0",
    listenPort: int = 69,
    portRangeStart: int = 0,  ## 0 = OS-assigned ephemeral ports (default)
    portRangeEnd: int = 0,    ## 0 = OS-assigned ephemeral ports (default)
    # -- policy --
    writePolicy: WritePolicy = wpDeny,
    maxConcurrent: int = 10,
    allowedHosts: seq[string] = @[],
    deniedHosts: seq[string] = @[],
    # -- protocol bounds --
    timeout: int = DefaultTimeout,
    retries: int = DefaultRetries,
    minBlocksize: int = MinBlocksize,
    maxBlocksize: int = MaxBlocksize,
    minWindowsize: int = MinWindowsize,
    maxWindowsize: int = MaxWindowsize,
    # -- features --
    pxeCompat: bool = false,
    dirListFile: string = "",
    checksumMode: ChecksumMode = csNone
  ): ServerConfigOutcome =
  ## The recommended construction choke point for `ServerConfig` (RFC
  ## conformance-closure D7). Builds a `ServerConfig` from the given fields
  ## and runs `serverConfigBoundsValid` on it exactly once, instead of
  ## trusting every call site to hand-build a legal config (the anti-pattern
  ## this replaces: `newDefaultServerConfig` + direct field pokes at the CLI
  ## and desktop GUI, which is how an out-of-RFC-bound config could reach
  ## `startServer` in the first place).
  ##
  ## Does NOT remove the three existing `serverConfigBoundsValid` guards
  ## (`server.nim`'s `handleRrq`/`handleWrq`, `api.nim`'s `startServer`):
  ## `ServerConfig` remains fully public/mutable and re-exported through
  ## `api.nim`, so it stays fully hand-buildable and post-construction
  ## mutable regardless of this constructor's existence -- those guards stay
  ## as belt-and-suspenders (R4). This constructor is purely additive: a
  ## validated, ergonomic path that single-sources the same bounds check.
  ##
  ## Parameters are grouped conceptually (binding / policy / protocol-bounds
  ## / features) by doc-comment and parameter order, not nested sub-objects,
  ## so every existing positional/by-field `ServerConfig` construction site
  ## in the test suite is unaffected.
  ##
  ## Parameter list is unchanged from slice 8a's four bare
  ## `minBlocksize`/`maxBlocksize`/`minWindowsize`/`maxWindowsize` ints --
  ## RFC D8's bounded-range types (`BlocksizeRange`/`WindowsizeRange`) are
  ## built INTERNALLY from them below, so the CLI/GUI call sites (which pass
  ## these as keyword args, not field pokes) do not ripple.
  ##
  ## Constructor-boundary note (D8): `newBlocksizeRange`/`newWindowsizeRange`
  ## are raising constructors (they `raise ValueError` on an invalid pair --
  ## required so a direct caller of those constructors sees a hard
  ## rejection). `newServerConfig` stays never-raising (the `api.nim` facade
  ## it backs must never throw) by catching that raise here and folding the
  ## message into `ServerConfigOutcome.rejectReason` instead of letting it
  ## escape -- the wrap is the ONLY thing standing between a raising
  ## low-level constructor and this never-throw choke point. Once the ranges
  ## are built, this delegates to the range-accepting overload above so both
  ## share `buildServerConfigOutcome`'s single assembly path (M7).
  var blocksizeRange: BlocksizeRange
  var windowsizeRange: WindowsizeRange
  try:
    blocksizeRange = newBlocksizeRange(minBlocksize, maxBlocksize)
    windowsizeRange = newWindowsizeRange(minWindowsize, maxWindowsize)
  except ValueError as e:
    return ServerConfigOutcome(
      ok: false,
      config: newDefaultServerConfig(rootDir),
      rejectReason: e.msg)

  newServerConfig(rootDir, listenAddr, listenPort, portRangeStart,
    portRangeEnd, writePolicy, maxConcurrent, allowedHosts, deniedHosts,
    timeout, retries, blocksizeRange, windowsizeRange, pxeCompat,
    dirListFile, checksumMode)

proc parseChecksumMode*(s: string): ChecksumMode =
  ## Parse a checksum mode string from CLI/config.
  ## Raises ValueError for unrecognised values.
  case s.toLowerAscii
  of "md5":      csMd5
  of "", "none": csNone
  else: raise newException(ValueError, "Invalid checksum mode: '" & s &
      "' (expected md5 or none)")
