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

proc parseOackOptions*(opts: seq[(string, string)]): NegotiatedOptions =
  result = defaultNegotiated()
  for (key, val) in opts:
    case key.toLowerAscii
    of "blksize": result.blocksize = validateBlocksize(parseInt(val))
    of "tsize": result.totalSize = parseBiggestInt(val)
    of "timeout": result.timeout = parseInt(val)
    of "windowsize": result.windowsize = max(MinWindowsize, min(MaxWindowsize, parseInt(val)))
    else: discard

# --- Server-side ---

proc negotiateServerOptions*(clientOpts: seq[(string, string)],
                              limits: ServerOptionLimits,
                              fileSize: int64 = -1
                             ): tuple[negotiated: NegotiatedOptions,
                                      oackOptions: seq[(string, string)]] =
  result.negotiated = defaultNegotiated()

  for (key, val) in clientOpts:
    case key.toLowerAscii
    of "blksize":
      var bs = parseInt(val)
      bs = max(limits.minBlocksize, min(limits.maxBlocksize, bs))
      result.negotiated.blocksize = bs
      result.oackOptions.add ("blksize", $bs)
    of "tsize":
      let clientTsize = parseBiggestInt(val)
      if clientTsize == 0 and fileSize >= 0:
        result.negotiated.totalSize = fileSize
        result.oackOptions.add ("tsize", $fileSize)
      else:
        result.negotiated.totalSize = clientTsize
        result.oackOptions.add ("tsize", $clientTsize)
    of "timeout":
      let t = parseInt(val)
      result.negotiated.timeout = t
      result.oackOptions.add ("timeout", $t)
    of "windowsize":
      var ws = parseInt(val)
      ws = max(limits.minWindowsize, min(limits.maxWindowsize, ws))
      result.negotiated.windowsize = ws
      result.oackOptions.add ("windowsize", $ws)
    else:
      discard
