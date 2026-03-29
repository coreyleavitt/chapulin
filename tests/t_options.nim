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

suite "parseOackOptions":
  test "parses blksize":
    let opts = @[("blksize", "1024")]
    let neg = parseOackOptions(opts)
    check neg.blocksize == 1024

  test "parses tsize":
    let opts = @[("tsize", "65536")]
    let neg = parseOackOptions(opts)
    check neg.totalSize == 65536

  test "parses timeout":
    let opts = @[("timeout", "10")]
    let neg = parseOackOptions(opts)
    check neg.timeout == 10

  test "parses windowsize":
    let opts = @[("windowsize", "4")]
    let neg = parseOackOptions(opts)
    check neg.windowsize == 4

  test "ignores unknown options":
    let opts = @[("blksize", "1024"), ("custom", "val")]
    let neg = parseOackOptions(opts)
    check neg.blocksize == 1024

  test "case insensitive keys":
    let opts = @[("BLKSIZE", "2048"), ("Tsize", "100")]
    let neg = parseOackOptions(opts)
    check neg.blocksize == 2048
    check neg.totalSize == 100

  test "validates blocksize range":
    let opts = @[("blksize", "99999")]
    let neg = parseOackOptions(opts)
    check neg.blocksize == MaxBlocksize  # clamped

  test "invalid non-numeric blksize raises ValueError":
    let opts = @[("blksize", "abc")]
    expect(ValueError):
      discard parseOackOptions(opts)

  test "invalid non-numeric tsize raises ValueError":
    let opts = @[("tsize", "xyz")]
    expect(ValueError):
      discard parseOackOptions(opts)

  test "empty options returns defaults":
    let neg = parseOackOptions(@[])
    check neg.blocksize == DefaultBlocksize
    check neg.totalSize == -1
    check neg.timeout == DefaultTimeout
    check neg.windowsize == DefaultWindowsize

  test "invalid non-numeric windowsize raises ValueError":
    let opts = @[("windowsize", "abc")]
    expect(ValueError):
      discard parseOackOptions(opts)

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

  test "clamps blocksize to server min":
    let limits = ServerOptionLimits(
      maxBlocksize: 65464, minBlocksize: 512, timeout: 5)
    let clientOpts = @[("blksize", "64")]
    let (neg, oackOpts) = negotiateServerOptions(clientOpts, limits)
    check neg.blocksize == 512
    check ("blksize", "512") in oackOpts

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
