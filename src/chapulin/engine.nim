## TFTP client transfer engine — thin async wrappers around transfer.nim.
## Handles client-specific initiation (RRQ/WRQ handshake + option negotiation).

import std/asyncdispatch
import protocol
import transfer
import options

export transfer
export options

type
  TftpClientConfig* = object
    timeout*: int
    retries*: int
    blocksize*: int
    windowsize*: int
    mode*: TransferMode
    requestTsize*: bool
    tsize*: int64

proc newDefaultConfig*(): TftpClientConfig =
  TftpClientConfig(timeout: DefaultTimeout, retries: DefaultRetries,
                   blocksize: DefaultBlocksize, windowsize: DefaultWindowsize,
                   mode: tmOctet, requestTsize: false, tsize: -1)

proc toTransferConfig(config: TftpClientConfig): TransferConfig =
  newTransferConfig(blocksize = config.blocksize, timeout = config.timeout,
                    retries = config.retries, windowsize = config.windowsize)

proc clientBuildOptions(config: TftpClientConfig): seq[(string, string)] =
  buildClientOptions(toTransferConfig(config),
                     requestTsize = config.requestTsize,
                     tsizeValue = config.tsize)

proc applyOack(pkt: TftpPacket, xferConfig: var TransferConfig) =
  let neg = parseOackOptions(pkt.oackOptions)
  xferConfig.blocksize = neg.blocksize
  xferConfig.totalSize = neg.totalSize
  xferConfig.windowsize = neg.windowsize

# --- getFile: client RRQ ---

proc getFile*(transport: Transport, config: TftpClientConfig,
              host: string, port: int, filename: string,
              onData: proc(blockNum: uint16, data: seq[byte]),
              onProgress: ProgressCallback = nil,
              cancelCheck: CancelCheck = nil): Future[TransferResult] {.async.} =
  let opts = clientBuildOptions(config)
  let rrq = TftpPacket(opcode: opRrq, filename: filename, mode: config.mode, options: opts)
  await transport.send(encode(rrq), host, port)

  var xferConfig = toTransferConfig(config)
  let peer = newPeer(host, port)
  let optionsRequested = opts.len > 0

  var startBlock: uint16 = 1
  var retryCount = 0

  while retryCount <= config.retries:
    if cancelCheck != nil and cancelCheck():
      return TransferResult(success: false, bytesTransferred: 0,
                            errorMsg: "Transfer cancelled", totalSize: xferConfig.totalSize)
    var resp: tuple[data: seq[byte], host: string, port: int]
    try:
      resp = await transport.recv(xferConfig.blocksize + 4, config.timeout * 1000)
    except TransportTimeoutError:
      retryCount.inc
      if retryCount > config.retries:
        return TransferResult(success: false, bytesTransferred: 0,
                              errorMsg: "Timeout after " & $config.retries & " retries",
                              totalSize: xferConfig.totalSize)
      await transport.send(encode(rrq), host, port)
      continue

    var pkt: TftpPacket
    try:
      pkt = decode(resp.data)
    except TftpDecodeError:
      continue

    case pkt.opcode
    of opOack:
      try:
        applyOack(pkt, xferConfig)
      except ValueError:
        return TransferResult(success: false, bytesTransferred: 0,
                              errorMsg: "Invalid option value in OACK",
                              totalSize: xferConfig.totalSize)
      peer.lockTo(resp.host, resp.port)
      await transport.send(encode(TftpPacket(opcode: opAck, ackBlockNum: 0)),
                           peer.host, peer.port)
      startBlock = 1
      break

    of opData:
      peer.lockTo(resp.host, resp.port)
      if optionsRequested:
        xferConfig.blocksize = DefaultBlocksize
      if pkt.blockNum == 1:
        onData(1, pkt.data)
        let bytesFromFirst = int64(pkt.data.len)
        await transport.send(encode(TftpPacket(opcode: opAck, ackBlockNum: 1)),
                             peer.host, peer.port)
        if onProgress != nil:
          onProgress(bytesFromFirst, xferConfig.totalSize)
        if pkt.data.len < xferConfig.blocksize:
          return TransferResult(success: true, bytesTransferred: bytesFromFirst,
                                totalSize: xferConfig.totalSize)
        startBlock = 2
        break
      else:
        continue

    of opError:
      return TransferResult(success: false, bytesTransferred: 0,
                            errorMsg: pkt.errorMsg,
                            errorCode: ord(pkt.errorCode),
                            totalSize: xferConfig.totalSize)

    else:
      return TransferResult(success: false, bytesTransferred: 0,
                            errorMsg: "Unexpected packet type: " & $pkt.opcode,
                            totalSize: xferConfig.totalSize)

  # Handshake complete — delegate to shared recvBlocks
  var bytesFromHandshake: int64 = 0
  if startBlock == 2:
    bytesFromHandshake = int64(xferConfig.blocksize)

  let wrappedProgress: ProgressCallback = if onProgress != nil:
    proc(b: int64, t: int64) = onProgress(b + bytesFromHandshake, t)
  else:
    nil

  var xferResult = await recvBlocks(transport, xferConfig, peer, startBlock,
                                     onData, wrappedProgress, cancelCheck)
  xferResult.bytesTransferred += bytesFromHandshake
  return xferResult

# --- putFile: client WRQ ---

proc putFile*(transport: Transport, config: TftpClientConfig,
              host: string, port: int, filename: string,
              readData: proc(blockNum: uint16, blocksize: int): seq[byte],
              onProgress: ProgressCallback = nil,
              cancelCheck: CancelCheck = nil): Future[TransferResult] {.async.} =
  let opts = clientBuildOptions(config)
  let wrq = TftpPacket(opcode: opWrq, filename: filename, mode: config.mode, options: opts)
  await transport.send(encode(wrq), host, port)

  var xferConfig = toTransferConfig(config)
  let peer = newPeer(host, port)
  let optionsRequested = opts.len > 0

  var retryCount = 0

  while retryCount <= config.retries:
    var resp: tuple[data: seq[byte], host: string, port: int]
    try:
      resp = await transport.recv(xferConfig.blocksize + 4, config.timeout * 1000)
    except TransportTimeoutError:
      retryCount.inc
      if retryCount > config.retries:
        return TransferResult(success: false, bytesTransferred: 0,
                              errorMsg: "Timeout after " & $config.retries & " retries",
                              totalSize: xferConfig.totalSize)
      await transport.send(encode(wrq), host, port)
      continue

    var pkt: TftpPacket
    try:
      pkt = decode(resp.data)
    except TftpDecodeError:
      continue

    case pkt.opcode
    of opOack:
      try:
        applyOack(pkt, xferConfig)
      except ValueError:
        return TransferResult(success: false, bytesTransferred: 0,
                              errorMsg: "Invalid option value in OACK",
                              totalSize: xferConfig.totalSize)
      peer.lockTo(resp.host, resp.port)
      break

    of opAck:
      if pkt.ackBlockNum == 0:
        peer.lockTo(resp.host, resp.port)
        if optionsRequested:
          xferConfig.blocksize = DefaultBlocksize
        break
      else:
        continue

    of opError:
      return TransferResult(success: false, bytesTransferred: 0,
                            errorMsg: pkt.errorMsg,
                            errorCode: ord(pkt.errorCode),
                            totalSize: xferConfig.totalSize)

    else:
      return TransferResult(success: false, bytesTransferred: 0,
                            errorMsg: "Unexpected packet type: " & $pkt.opcode,
                            totalSize: xferConfig.totalSize)

  return await sendBlocks(transport, xferConfig, peer, 1, readData,
                           onProgress, cancelCheck)
