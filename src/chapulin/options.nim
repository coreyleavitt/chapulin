## TFTP option negotiation — shared by client and server.
## RFC 2347 (Option Extension), RFC 2348 (Blocksize), RFC 2349 (Timeout/Tsize),
## RFC 7440 (Windowsize).

import std/strutils
import transfer

type
  NegotiatedOptions* = object
    blocksize*: int
    totalSize*: int64
    timeout*: int
    windowsize*: int

  ServerOptionLimits* = object
    maxBlocksize*: int
    minBlocksize*: int
    timeout*: int
    maxWindowsize*: int
    minWindowsize*: int

  OackOutcome* = object
    ## FLAT object -- NOT a case-object. `negotiated` is meaningful iff `ok`;
    ## `rejectReason` is "" iff `ok`. A case-object here would make a
    ## wrong-branch field access a FieldDefect that escapes
    ## `except CatchableError` (the tracked never-throw Defect hazard) --
    ## this shape trades one always-present (if sometimes-unused) field for
    ## that guarantee.
    ok*: bool
    negotiated*: NegotiatedOptions
    rejectReason*: string

proc defaultNegotiated*(): NegotiatedOptions =
  NegotiatedOptions(blocksize: DefaultBlocksize, totalSize: -1,
                    timeout: DefaultTimeout, windowsize: DefaultWindowsize)

# --- Client-side ---

proc buildClientOptions*(config: TransferConfig,
                         requestTsize: bool = false,
                         tsizeValue: int64 = -1): seq[(string, string)] =
  if config.blocksize != DefaultBlocksize:
    result.add ("blksize", $config.blocksize)
  if requestTsize:
    if tsizeValue >= 0:
      result.add ("tsize", $tsizeValue)
    else:
      result.add ("tsize", "0")
  if config.timeout != DefaultTimeout:
    result.add ("timeout", $config.timeout)
  if config.windowsize != DefaultWindowsize:
    result.add ("windowsize", $config.windowsize)

proc findRequested(requested: seq[(string, string)], key: string): tuple[found: bool, val: string] =
  ## Linear lookup is fine here -- `requested` holds at most the four known
  ## options (D7), never a caller-scaled collection.
  for (k, v) in requested:
    if k.toLowerAscii == key:
      return (true, v)
  (false, "")

proc reject(reason: string): OackOutcome =
  OackOutcome(ok: false, negotiated: defaultNegotiated(), rejectReason: reason)

proc validateAndParseOack*(returned, requested: seq[(string, string)],
                          configuredTimeout: int = DefaultTimeout): OackOutcome =
  ## The single, pure, total gate an OACK's raw wire pairs must pass before
  ## anything from it is applied (RFC 2347 clause 9; policy R4). Runs on RAW
  ## values -- clamping a value after the fact (as the removed, dead
  ## `parseOackOptions` once did) would make a post-parse bounds check
  ## vacuous, so this function parses and bounds-checks in the same step.
  ##
  ## R4 enforcement: a returned option the client did not request is
  ## filtered out here -- never parsed, never applied -- rather than merely
  ## flagged. Only a bad *value* of a *requested* option fails the whole
  ## OACK (`ok = false`). Duplicate option names and non-numeric values are
  ## both rejections; no exception ever escapes (parseInt/parseBiggestInt
  ## ValueErrors are caught internally), so this proc is total on any input.
  result.ok = true
  result.negotiated = defaultNegotiated()
  # Fix A (mirror of D5/R6 on the client side): seed the negotiated timeout
  # from the CLIENT'S OWN configured/requested timeout, not the global
  # protocol default -- so an OACK that omits "timeout" (RFC-2349-legal; many
  # servers negotiate blksize/windowsize but never touch timeout) doesn't
  # have the client's configured value silently downgraded to DefaultTimeout
  # by the unconditional `applyOack` that consumes this result.
  result.negotiated.timeout = configuredTimeout
  var seenKeys: seq[string] = @[]

  for (rawKey, val) in returned:
    let key = rawKey.toLowerAscii
    let (isRequested, reqVal) = findRequested(requested, key)
    if not isRequested:
      continue  # R4: filter, don't parse or apply
    if key in seenKeys:
      return reject("duplicate option in OACK: " & key)
    seenKeys.add key

    case key
    of "blksize":
      var bs, reqBs: int
      try:
        bs = parseInt(val)
        reqBs = parseInt(reqVal)
      except ValueError:
        return reject("non-numeric blksize in OACK")
      if bs < MinBlocksize or bs > MaxBlocksize or bs > reqBs:
        return reject("blksize out of bounds in OACK")
      result.negotiated.blocksize = bs
    of "timeout":
      var t: int
      try:
        t = parseInt(val)
      except ValueError:
        return reject("non-numeric timeout in OACK")
      if not validateTimeoutOpt(t):
        return reject("timeout out of bounds in OACK")
      result.negotiated.timeout = t
    of "windowsize":
      var ws: int
      try:
        ws = parseInt(val)
      except ValueError:
        return reject("non-numeric windowsize in OACK")
      if ws < MinWindowsize or ws > MaxWindowsize:
        return reject("windowsize out of bounds in OACK")
      result.negotiated.windowsize = ws
    of "tsize":
      var ts: int64
      try:
        ts = parseBiggestInt(val)
      except ValueError:
        return reject("non-numeric tsize in OACK")
      if ts < 0:
        return reject("negative tsize in OACK")
      result.negotiated.totalSize = ts
    else:
      discard  # requested-but-unrecognized key: no bound to enforce

# --- Server-side ---

proc negotiateServerOptions*(clientOpts: seq[(string, string)],
                              limits: ServerOptionLimits,
                              fileSize: int64 = -1,
                              suppressTsize: bool = false
                             ): tuple[negotiated: NegotiatedOptions,
                                      oackOptions: seq[(string, string)]] =
  result.negotiated = defaultNegotiated()
  # D5/R6: seed from the operator's configured limit, not the global protocol
  # default -- so a client that negotiates only blksize/windowsize (never
  # touching "timeout") doesn't have a non-default operator timeout silently
  # clobbered back to DefaultTimeout by an unconditional downstream apply
  # (round-2 bug 4b).
  result.negotiated.timeout = limits.timeout

  for (key, val) in clientOpts:
    case key.toLowerAscii
    of "blksize":
      let reqBs = parseInt(val)
      # RFC 2348: the server MUST NOT reply with a blksize larger than the
      # one the client requested. Clamping DOWN to maxBlocksize keeps that
      # invariant (result <= requested); clamping UP to minBlocksize would
      # violate it. When the request is below the operator's configured
      # minBlocksize, the option can't be honored within limits at all, so
      # it is DROPPED from the OACK entirely (mirrors the R6 timeout-drop
      # policy above) rather than offered at an out-of-spec larger value --
      # both sides then fall back to the protocol default of 512.
      if reqBs >= limits.minBlocksize:
        let bs = min(limits.maxBlocksize, reqBs)
        result.negotiated.blocksize = bs
        result.oackOptions.add ("blksize", $bs)
    of "tsize":
      let clientTsize = parseBiggestInt(val)
      # RFC-conformance-closure D1d: under netascii, tsize is dropped from the
      # OACK entirely (R3's sibling policy for tsize) -- translation is
      # expansive/data-dependent, so any size the server could report here
      # (pre- or post-translation) would misrepresent the other side's byte
      # count. `negotiated.totalSize` is still computed for internal
      # bookkeeping; only the outbound wire option is suppressed. This
      # module stays mode-agnostic/pure -- the caller (server.nim) computes
      # `suppressTsize` from its own `netasciiPolicyFor(request.mode)` and
      # passes the plain bool in, rather than this negotiator importing
      # netascii itself just to re-derive one boolean from a mode.
      if clientTsize == 0 and fileSize >= 0:
        result.negotiated.totalSize = fileSize
      else:
        result.negotiated.totalSize = clientTsize
      if not suppressTsize:
        result.oackOptions.add ("tsize", $result.negotiated.totalSize)
    of "timeout":
      let t = parseInt(val)
      # R6: RFC 2349 forbids silent substitution for timeout (unlike
      # blksize/windowsize, which RFC 2348/7440 permit clamping) -- an
      # out-of-range-but-parseable value is DROPPED (omitted from the OACK,
      # negotiated.timeout stays at the limits seed above), never clamped.
      # A syntactically unparseable value still raises ValueError from
      # parseInt above, unwinding to the caller's ERROR(8) catch.
      if validateTimeoutOpt(t):
        result.negotiated.timeout = t
        result.oackOptions.add ("timeout", $t)
    of "windowsize":
      var ws = parseInt(val)
      ws = max(limits.minWindowsize, min(limits.maxWindowsize, ws))
      result.negotiated.windowsize = ws
      result.oackOptions.add ("windowsize", $ws)
    else:
      discard
