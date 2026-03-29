## Shared transfer primitives — the foundation for both client and server.
## All I/O procs are async. Pure procs (types, constants, validation) are sync.

import std/[asyncdispatch, times]
import protocol

type
  TransportSendProc* = proc(data: seq[byte], host: string, port: int): Future[void] {.closure.}
  TransportRecvProc* = proc(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte], host: string, port: int]] {.closure.}
  TransportCloseProc* = proc() {.closure.}

  Transport* = object
    send*: TransportSendProc
    recv*: TransportRecvProc
    close*: TransportCloseProc

  TransportTimeoutError* = object of CatchableError
  TransferError* = object of CatchableError

  TransferResult* = object
    success*: bool
    bytesTransferred*: int64
    errorMsg*: string
    errorCode*: int
    totalSize*: int64     ## -1 if unknown

  ProgressCallback* = proc(bytesTransferred: int64, totalSize: int64) {.closure.}
  CancelCheck* = proc(): bool {.closure.}

  TransferConfig* = object
    blocksize*: int
    timeout*: int         ## seconds
    retries*: int
    totalSize*: int64     ## -1 if unknown
    windowsize*: int      ## RFC 7440, default 1 (lock-step)

  ## RFC 1350 TID lock + RFC 1123 adaptive timeout state.
  ## Ref object because async procs can't take var params.
  PeerEndpoint* = ref object
    host*: string
    port*: int
    locked*: bool
    # Adaptive timeout (RFC 1123 section 4.2, Jacobson's algorithm)
    srtt*: float       ## Smoothed RTT in milliseconds (-1 = not yet measured)
    rttvar*: float     ## RTT variance
    adaptiveTimeout*: int  ## Current adaptive timeout in ms (0 = use config)

const
  MinBlocksize* = 8
  MaxBlocksize* = 65464
  DefaultBlocksize* = 512
  DefaultTimeout* = 5
  DefaultRetries* = 3
  MinWindowsize* = 1
  MaxWindowsize* = 65535
  DefaultWindowsize* = 1

proc validateBlocksize*(bs: int): int =
  max(MinBlocksize, min(MaxBlocksize, bs))

proc newTransferConfig*(blocksize: int = DefaultBlocksize,
                        timeout: int = DefaultTimeout,
                        retries: int = DefaultRetries,
                        windowsize: int = DefaultWindowsize,
                        totalSize: int64 = -1): TransferConfig =
  TransferConfig(blocksize: validateBlocksize(blocksize),
                 timeout: timeout, retries: retries,
                 windowsize: max(MinWindowsize, min(MaxWindowsize, windowsize)),
                 totalSize: totalSize)

proc newPeer*(host: string, port: int, locked: bool = false): PeerEndpoint =
  PeerEndpoint(host: host, port: port, locked: locked,
               srtt: -1.0, rttvar: 0.0, adaptiveTimeout: 0)

proc updateRtt*(peer: PeerEndpoint, rttMs: float) =
  ## Update adaptive timeout using Jacobson's algorithm (RFC 6298/1123).
  ## SRTT = 0.875*SRTT + 0.125*RTT
  ## RTTVAR = 0.75*RTTVAR + 0.25*|SRTT - RTT|
  ## Timeout = SRTT + 4*RTTVAR (clamped to minimum 1000ms)
  if peer.srtt < 0:
    # First measurement
    peer.srtt = rttMs
    peer.rttvar = rttMs / 2.0
  else:
    peer.rttvar = 0.75 * peer.rttvar + 0.25 * abs(peer.srtt - rttMs)
    peer.srtt = 0.875 * peer.srtt + 0.125 * rttMs
  peer.adaptiveTimeout = max(1000, int(peer.srtt + 4.0 * peer.rttvar))

proc effectiveTimeout*(peer: PeerEndpoint, configTimeoutMs: int): int =
  ## Return adaptive timeout if available, otherwise config timeout.
  if peer.adaptiveTimeout > 0: peer.adaptiveTimeout
  else: configTimeoutMs

proc lockTo*(peer: PeerEndpoint, host: string, port: int) =
  peer.host = host
  peer.port = port
  peer.locked = true

# --- Core async recv with retry/TID/decode handling ---

proc recvPacket*(transport: Transport, config: TransferConfig,
                 peer: PeerEndpoint,
                 lastSent: seq[byte]): Future[TftpPacket] {.async.} =
  var retryCount = 0
  while retryCount <= config.retries:
    let timeoutMs = peer.effectiveTimeout(config.timeout * 1000)
    let sendTime = epochTime()

    var resp: tuple[data: seq[byte], host: string, port: int]
    try:
      resp = await transport.recv(config.blocksize + 4, timeoutMs)
    except TransportTimeoutError:
      retryCount.inc
      if retryCount > config.retries:
        raise newException(TransferError,
          "Timeout after " & $config.retries & " retries")
      if lastSent.len > 0:
        await transport.send(lastSent, peer.host, peer.port)
      continue

    # Measure RTT and update adaptive timeout (RFC 1123)
    let rttMs = (epochTime() - sendTime) * 1000.0
    peer.updateRtt(rttMs)

    # Decode — skip corrupt packets
    var pkt: TftpPacket
    try:
      pkt = decode(resp.data)
    except TftpDecodeError:
      continue

    # TID validation
    if peer.locked:
      if resp.host != peer.host or resp.port != peer.port:
        let errPkt = TftpPacket(opcode: opError, errorCode: errUnknownTransferId,
                                 errorMsg: "Unknown transfer ID")
        await transport.send(encode(errPkt), resp.host, resp.port)
        continue

    # Lock TID on first valid response
    if not peer.locked:
      peer.lockTo(resp.host, resp.port)

    # Check for error packet
    if pkt.opcode == opError:
      raise newException(TransferError, pkt.errorMsg)

    return pkt

  raise newException(TransferError,
    "Timeout after " & $config.retries & " retries")

# --- sendBlocks: send DATA, wait for ACK (supports RFC 7440 windowsize) ---

proc sendBlocks*(transport: Transport, config: TransferConfig,
                 peer: PeerEndpoint, startBlock: uint16,
                 readData: proc(blockNum: uint16, blocksize: int): seq[byte],
                 onProgress: ProgressCallback = nil,
                 cancelCheck: CancelCheck = nil): Future[TransferResult] {.async.} =
  var bytesSent: int64 = 0
  var nextBlock = startBlock        # next block to read and send
  var lastAcked: uint16 = startBlock - 1  # last ACKed block number
  var windowEnd: uint16 = 0        # highest block sent in current window
  var hitFinal = false              # whether we've sent a short (final) block
  var lastSentPacket: seq[byte]     # for retransmit on timeout
  let ws = config.windowsize

  template sendOneBlock(blkNum: uint16) =
    let blkData = readData(blkNum, config.blocksize)
    let dataPkt = TftpPacket(opcode: opData, blockNum: blkNum, data: blkData)
    lastSentPacket = encode(dataPkt)
    await transport.send(lastSentPacket, peer.host, peer.port)
    bytesSent += blkData.len
    windowEnd = blkNum
    if blkData.len < config.blocksize:
      hitFinal = true
    if onProgress != nil:
      onProgress(bytesSent, config.totalSize)

  # Fill and send the initial window
  template fillWindow() =
    var sent = 0
    while sent < ws and not hitFinal:
      if nextBlock == high(uint16) and sent > 0:
        break  # don't overflow
      sendOneBlock(nextBlock)
      nextBlock.inc
      sent.inc

  fillWindow()

  while true:
    if cancelCheck != nil and cancelCheck():
      return TransferResult(success: false, bytesTransferred: bytesSent,
                            errorMsg: "Transfer cancelled", totalSize: config.totalSize)

    var pkt: TftpPacket
    try:
      pkt = await recvPacket(transport, config, peer, lastSentPacket)
    except TransferError as e:
      return TransferResult(success: false, bytesTransferred: bytesSent,
                            errorMsg: e.msg, totalSize: config.totalSize)

    if pkt.opcode == opAck:
      if pkt.ackBlockNum >= lastAcked + 1 and pkt.ackBlockNum <= windowEnd:
        lastAcked = pkt.ackBlockNum

        # If final block was ACKed, transfer complete
        if hitFinal and lastAcked == windowEnd:
          return TransferResult(success: true, bytesTransferred: bytesSent,
                                totalSize: config.totalSize)

        # Block number limit check
        if lastAcked == high(uint16):
          return TransferResult(success: false, bytesTransferred: bytesSent,
                                errorMsg: "Block number limit reached (65535). Use a larger blocksize.",
                                totalSize: config.totalSize)

        if pkt.ackBlockNum == windowEnd:
          # Full window ACKed — send next window
          fillWindow()
        elif not hitFinal:
          # Partial ACK — resend from lastAcked+1 and fill rest of window
          nextBlock = lastAcked + 1
          hitFinal = false  # re-read blocks, may hit final again
          # Re-send the un-ACKed portion + new blocks
          fillWindow()
      # else: stale ACK for already-ACKed block — ignore
    else:
      return TransferResult(success: false, bytesTransferred: bytesSent,
                            errorMsg: "Unexpected packet type: " & $pkt.opcode,
                            totalSize: config.totalSize)

# --- recvBlocks: recv DATA, send ACK (supports RFC 7440 windowsize) ---

proc recvBlocks*(transport: Transport, config: TransferConfig,
                 peer: PeerEndpoint, startBlock: uint16,
                 onData: proc(blockNum: uint16, data: seq[byte]),
                 onProgress: ProgressCallback = nil,
                 cancelCheck: CancelCheck = nil): Future[TransferResult] {.async.} =
  var bytesReceived: int64 = 0
  var expectedBlock = startBlock
  var lastSent: seq[byte]
  let ws = config.windowsize
  var blocksInWindow = 0  # how many blocks received since last ACK

  template sendAck(blkNum: uint16) =
    let ack = TftpPacket(opcode: opAck, ackBlockNum: blkNum)
    let ackData = encode(ack)
    await transport.send(ackData, peer.host, peer.port)
    lastSent = ackData
    blocksInWindow = 0

  while true:
    if cancelCheck != nil and cancelCheck():
      return TransferResult(success: false, bytesTransferred: bytesReceived,
                            errorMsg: "Transfer cancelled", totalSize: config.totalSize)

    var pkt: TftpPacket
    try:
      pkt = await recvPacket(transport, config, peer, lastSent)
    except TransferError as e:
      return TransferResult(success: false, bytesTransferred: bytesReceived,
                            errorMsg: e.msg, totalSize: config.totalSize)

    case pkt.opcode
    of opData:
      if pkt.blockNum == expectedBlock:
        onData(pkt.blockNum, pkt.data)
        bytesReceived += pkt.data.len
        blocksInWindow.inc

        if onProgress != nil:
          onProgress(bytesReceived, config.totalSize)

        # Final block — always ACK immediately
        if pkt.data.len < config.blocksize:
          sendAck(pkt.blockNum)
          return TransferResult(success: true, bytesTransferred: bytesReceived,
                                totalSize: config.totalSize)

        if expectedBlock == high(uint16):
          sendAck(pkt.blockNum)
          return TransferResult(success: false, bytesTransferred: bytesReceived,
                                errorMsg: "Block number limit reached (65535). Use a larger blocksize.",
                                totalSize: config.totalSize)

        expectedBlock.inc

        # ACK after windowsize blocks received, or for lock-step (ws=1)
        if blocksInWindow >= ws:
          sendAck(pkt.blockNum)

      elif pkt.blockNum < expectedBlock:
        # Duplicate — re-ACK
        let ack = TftpPacket(opcode: opAck, ackBlockNum: pkt.blockNum)
        await transport.send(encode(ack), peer.host, peer.port)

    else:
      return TransferResult(success: false, bytesTransferred: bytesReceived,
                            errorMsg: "Unexpected packet type: " & $pkt.opcode,
                            totalSize: config.totalSize)
