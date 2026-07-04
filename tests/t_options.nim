import unittest
import ../src/chapulin/protocol
import ../src/chapulin/transfer
import ../src/chapulin/options

suite "buildClientOptions":
  test "default config produces empty options":
    let config = newTransferConfig()
    check buildClientOptions(config).len == 0

  test "custom blocksize produces blksize option":
    let config = newTransferConfig(blocksize = 1024)
    let opts = buildClientOptions(config)
    check opts.len == 1
    check opts[0] == ("blksize", "1024")

  test "custom timeout produces timeout option":
    let config = newTransferConfig(timeout = 10)
    let opts = buildClientOptions(config)
    check opts.len == 1
    check opts[0] == ("timeout", "10")

  test "tsize request for RRQ sends tsize=0":
    let config = newTransferConfig()
    let opts = buildClientOptions(config, requestTsize = true)
    check ("tsize", "0") in opts

  test "tsize for WRQ sends actual file size":
    let config = newTransferConfig()
    let opts = buildClientOptions(config, requestTsize = true, tsizeValue = 524288)
    check ("tsize", "524288") in opts

  test "all options combined":
    let config = newTransferConfig(blocksize = 4096, timeout = 10)
    let opts = buildClientOptions(config, requestTsize = true)
    check opts.len == 3

  test "custom windowsize produces windowsize option":
    let config = newTransferConfig(windowsize = 4)
    let opts = buildClientOptions(config)
    check opts.len == 1
    check opts[0] == ("windowsize", "4")

  test "all options including windowsize":
    let config = newTransferConfig(blocksize = 1024, timeout = 3, windowsize = 8)
    let opts = buildClientOptions(config, requestTsize = true)
    check opts.len == 4

suite "validateAndParseOack":
  test "filters an unrequested option out of negotiated (R4 enforcement)":
    let requested = @[("blksize", "1024")]
    let returned = @[("blksize", "1024"), ("windowsize", "8")]  # windowsize never requested
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == true
    check outcome.negotiated.blocksize == 1024
    check outcome.negotiated.windowsize == DefaultWindowsize  # NOT 8 -- foisted option never applied

  test "accepts a requested blksize within bounds and <= requested value":
    let requested = @[("blksize", "4096")]
    let returned = @[("blksize", "2048")]
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == true
    check outcome.negotiated.blocksize == 2048

  test "rejects a requested blksize larger than what was requested":
    let requested = @[("blksize", "1024")]
    let returned = @[("blksize", "2048")]  # server tried to raise it
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == false
    check outcome.rejectReason.len > 0

  test "rejects a requested blksize below the RFC 2348 floor":
    let requested = @[("blksize", "1024")]
    let returned = @[("blksize", "4")]  # below MinBlocksize == 8
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == false

  test "rejects a requested timeout outside 1..255":
    let requested = @[("timeout", "10")]
    let returned = @[("timeout", "0")]
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == false

  test "rejects a requested windowsize outside bounds":
    let requested = @[("windowsize", "8")]
    let returned = @[("windowsize", "70000")]  # > MaxWindowsize
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == false

  test "accepts a requested tsize that parses as a non-negative int64":
    let requested = @[("tsize", "0")]
    let returned = @[("tsize", "1048576")]
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == true
    check outcome.negotiated.totalSize == 1048576

  test "rejects a negative tsize":
    let requested = @[("tsize", "0")]
    let returned = @[("tsize", "-1")]
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == false

  test "rejects a duplicate option name in the returned OACK":
    let requested = @[("blksize", "1024")]
    let returned = @[("blksize", "1024"), ("blksize", "512")]
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == false

  test "matches option names case-insensitively":
    let requested = @[("blksize", "1024")]
    let returned = @[("BLKSIZE", "1024")]
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == true
    check outcome.negotiated.blocksize == 1024

  test "is total on garbage (non-numeric) input for a requested option — no exception, ok=false":
    let requested = @[("blksize", "1024")]
    let returned = @[("blksize", "not-a-number")]
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == false

  test "empty returned OACK is accepted with defaults":
    let requested = @[("blksize", "1024")]
    let outcome = validateAndParseOack(@[], requested)
    check outcome.ok == true
    check outcome.negotiated.blocksize == DefaultBlocksize

  test "multiple valid requested options all negotiate together":
    let requested = @[("blksize", "4096"), ("timeout", "10"), ("windowsize", "8"), ("tsize", "0")]
    let returned = @[("blksize", "4096"), ("timeout", "10"), ("windowsize", "8"), ("tsize", "2048")]
    let outcome = validateAndParseOack(returned, requested)
    check outcome.ok == true
    check outcome.negotiated.blocksize == 4096
    check outcome.negotiated.timeout == 10
    check outcome.negotiated.windowsize == 8
    check outcome.negotiated.totalSize == 2048

suite "negotiateServerOptions":
  test "accepts blocksize within server limits":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 5)
    let clientOpts = @[("blksize", "4096")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check neg.blocksize == 4096
    check ("blksize", "4096") in oackOpts

  test "clamps blocksize to server max":
    let limits = ServerOptionLimits(
      maxBlocksize: 1468, minBlocksize: 8, timeout: 5)
    let clientOpts = @[("blksize", "8192")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check neg.blocksize == 1468
    check ("blksize", "1468") in oackOpts

  test "requested blksize below server min is omitted, never clamped upward (Fix B, RFC 2348)":
    # Old (buggy) behavior clamped UP to limits.minBlocksize here, which
    # violates RFC 2348 ("server MUST NOT respond with a blksize larger than
    # the one requested") and made this project's own client reject its own
    # server's OACK. The corrected behavior drops the option entirely when it
    # cannot be honored within limits without exceeding the request.
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 512, timeout: 5)
    let clientOpts = @[("blksize", "64")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check oackOpts.len == 0  # dropped, not offered at any value
    check neg.blocksize == DefaultBlocksize

  test "requested blksize below server minBlocksize is omitted, not offered above the request (Fix B)":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 100, timeout: 5)
    let clientOpts = @[("blksize", "64")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check oackOpts.len == 0
    check ("blksize", "100") notin oackOpts
    check neg.blocksize == DefaultBlocksize

  test "tsize request returns file size":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 5)
    let clientOpts = @[("tsize", "0")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits, fileSize = 1048576)
    check ("tsize", "1048576") in oackOpts
    check neg.totalSize == 1048576

  test "tsize from WRQ client (non-zero) is accepted":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 5)
    let clientOpts = @[("tsize", "999")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check neg.totalSize == 999
    check ("tsize", "999") in oackOpts

  test "timeout is echoed back":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 5)
    let clientOpts = @[("timeout", "3")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check neg.timeout == 3
    check ("timeout", "3") in oackOpts

  test "no timeout requested seeds negotiated.timeout from limits.timeout, not the global default (D5, round-2 bug 4b)":
    # limits.timeout is populated from the operator's ServerConfig.timeout,
    # deliberately set here to something other than DefaultTimeout so this
    # test cannot pass by accident.
    check DefaultTimeout != 20
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 20,
      maxWindowsize: 16, minWindowsize: 1)
    # Client negotiates only blksize/windowsize -- no timeout option at all.
    let clientOpts = @[("blksize", "1024"), ("windowsize", "4")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check neg.timeout == 20  # the operator's configured timeout, NOT DefaultTimeout
    check oackOpts.len == 2  # only blksize + windowsize -- timeout never echoed

  test "out-of-range but parseable timeout is dropped, not clamped or raised (R6)":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 7,
      maxWindowsize: 16, minWindowsize: 1)
    let (negLow, oackLow) = negotiateServerOptions(@[("timeout", "0")], limits)
    check negLow.timeout == 7          # falls back to the limits seed
    check oackLow.len == 0             # dropped, not echoed at any value

    let (negHigh, oackHigh) = negotiateServerOptions(@[("timeout", "300")], limits)
    check negHigh.timeout == 7
    check oackHigh.len == 0

  test "windowsize negotiated within server limits":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 5,
      maxWindowsize: 16, minWindowsize: 1)
    let clientOpts = @[("windowsize", "8")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check neg.windowsize == 8
    check ("windowsize", "8") in oackOpts

  test "windowsize clamped to server max":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 5,
      maxWindowsize: 4, minWindowsize: 1)
    let clientOpts = @[("windowsize", "16")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check neg.windowsize == 4
    check ("windowsize", "4") in oackOpts

  test "unknown options are omitted from OACK":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 5,
      maxWindowsize: 16, minWindowsize: 1)
    let clientOpts = @[("custom_ext", "val"), ("blksize", "1024")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check oackOpts.len == 1  # only blksize, not custom_ext
    check neg.blocksize == 1024

  test "no recognized options returns empty OACK":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 5,
      maxWindowsize: 16, minWindowsize: 1)
    let clientOpts = @[("custom_ext", "4")]
    let (_, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check oackOpts.len == 0

  test "empty client options returns defaults":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 5)
    let (neg, oackOpts) = negotiateServerOptions(@[], limits)
    check neg.blocksize == DefaultBlocksize
    check oackOpts.len == 0

  test "invalid non-numeric value raises ValueError":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 8, timeout: 5)
    expect(ValueError):
      discard negotiateServerOptions(@[("blksize", "notanum")], limits)

  test "multiple options including windowsize all negotiated":
    let limits = ServerOptionLimits(
      maxBlocksize: 4096, minBlocksize: 8, timeout: 5,
      maxWindowsize: 16, minWindowsize: 1)
    let clientOpts = @[("blksize", "8192"), ("tsize", "0"), ("timeout", "2"), ("windowsize", "8")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits, fileSize = 2048)
    check neg.blocksize == 4096
    check neg.totalSize == 2048
    check neg.timeout == 2
    check neg.windowsize == 8
    check oackOpts.len == 4
