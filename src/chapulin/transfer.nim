## Shared transfer primitives — the foundation for both client and server.
## All I/O procs are async. Pure procs (types, constants, validation) are sync.

import std/[asyncdispatch, times, tables]
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
    ## NOTE (RFC checksum-integrity-error-hygiene, finding M3): this type is
    ## SHARED by both client transfers (engine/sendBlocks/recvBlocks, surfaced
    ## through api.nim's getFile/putFile) and the server's handleRrq/handleWrq.
    ## It must carry ONLY client-facing fields. The server's operator-only
    ## diagnostic (redacted OS open-failure / sidecar-write detail) is
    ## deliberately NOT a field here -- see server.nim's `diagOut: ref string`
    ## channel on handleRrq/handleWrq, consumed solely by handleRequest's
    ## logger. That keeps the client-shared type structurally incapable of
    ## carrying operator-only detail, rather than relying on a doc-comment
    ## convention that a future wholesale-serialize/log/GUI consumer of
    ## TransferResult could silently violate.

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
                 cancelCheck: CancelCheck = nil,
                 onDelivered: proc(data: openArray[byte]) = nil,
                 peakCacheBlocksOut: ref int = new(int)): Future[TransferResult] {.async.} =
  ## Send DATA blocks starting at `startBlock`, driven by the receiver's ACKs
  ## (RFC 7440 windowsize supported: up to `config.windowsize` blocks may be
  ## in flight unacknowledged at once).
  ##
  ## `onDelivered`, when non-nil, is the sender-side confirmed-delivery hook
  ## (RFC checksum-integrity-error-hygiene, D1 Option A). Its contract:
  ## - Fires exactly once per CONFIRMED block, never for a block that has not
  ##   been ACKed, and never more than once for the same block.
  ## - Fires in strictly ascending block-number order. Because TFTP ACKs are
  ##   cumulative, a single ACK (e.g. under windowsize > 1) can confirm several
  ##   blocks at once — the hook still fires once per block, never once per
  ##   ACK packet.
  ## - The payload is the bytes that block was *last transmitted* with (a
  ##   cached copy from send time), not a fresh `readData` call. This matters
  ##   under a source that mutates between sends: a block that is lost and
  ##   retransmitted must report what the receiver actually holds, which may
  ##   differ from a fresh read of the (by-then-mutated) source.
  ## - The `openArray[byte]` payload is only valid for the duration of the
  ##   synchronous callback — do not retain it; copy out if the caller needs
  ##   the bytes to outlive the call.
  ## - The firing loop for a confirming ACK runs strictly BEFORE the
  ##   `lastAcked == high(uint16)` (>65535 blocks) early-return check, so the
  ##   block that hits that ceiling is still delivered through this hook even
  ##   though the overall transfer then reports failure.
  ##
  ## `peakCacheBlocksOut`: call-scoped diagnostic — peak `windowCache` size
  ## reached during this transfer (for the O(window) memory-bound test). Like
  ## `handleRrq`/`handleWrq`'s `diagOut`, each caller that omits it gets its
  ## own private, freshly-allocated box (Nim evaluates a `ref` default fresh
  ## per omitting call site), so concurrent `sendBlocks` calls never share
  ## mutable state through it.
  var bytesSent: int64 = 0
  var nextBlock = startBlock        # next block to read and send
  var lastAcked: uint16 = startBlock - 1  # last ACKed block number
  var windowEnd: uint16 = 0        # highest block sent in current window
  var hitFinal = false              # whether we've sent a short (final) block
  var lastSentPacket: seq[byte]     # for retransmit on timeout
  var dupAcks = 0                   # consecutive re-ACKs of lastAcked (loss signal)
  let ws = config.windowsize
  # Bytes each in-flight (unacked) block was *last sent* with. A resend (partial-ACK
  # refill or dup-ACK fast-retransmit) replays the cached bytes rather than
  # re-invoking readData — correct under a mutating source (a block the client
  # loses and re-receives must not silently change content across retransmits) —
  # and onDelivered fires from this cache on confirm. Evicted on ACK, so memory
  # stays O(windowsize x blocksize), never O(filesize).
  var windowCache = initTable[uint16, seq[byte]]()

  # A receiver that loses a DATA packet keeps re-ACKing its last in-order block.
  # Those duplicate ACKs arrive before our recv times out, so a timeout-only
  # retransmit never fires and the transfer deadlocks (issue #18). Treat repeated
  # duplicate ACKs as a retransmit request. RFC 1123 4.2.3.1: reacting to a
  # *single* duplicate ACK causes the Sorcerer's Apprentice cascade, so only act
  # once the loss is confirmed by a second duplicate — one echoed ACK is ignored.
  const dupAckThreshold = 2

  template sendOneBlock(blkNum: uint16) =
    let isResend = windowCache.hasKey(blkNum)
    let blkData = if isResend: windowCache[blkNum]
                  else: readData(blkNum, config.blocksize)
    if not isResend:
      windowCache[blkNum] = blkData
      peakCacheBlocksOut[] = max(peakCacheBlocksOut[], windowCache.len)
    let dataPkt = TftpPacket(opcode: opData, blockNum: blkNum, data: blkData)
    lastSentPacket = encode(dataPkt)
    await transport.send(lastSentPacket, peer.host, peer.port)
    if not isResend:
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
        let prevAcked = lastAcked
        lastAcked = pkt.ackBlockNum
        dupAcks = 0                 # forward progress clears the loss signal

        # TFTP ACKs are cumulative: a single accepted ACK can jump lastAcked
        # forward by a whole window (windowsize>1), so fire once per confirmed
        # block in ascending order — never once per ACK packet — replaying the
        # bytes each block was last sent with. lastAcked advances only here, so
        # consecutive firings partition the block space with no gap/overlap.
        # Eviction is UNCONDITIONAL for every confirmed block (round-3 fix 1):
        # only the onDelivered *call* is guarded on non-nil. Gating eviction
        # itself behind onDelivered left the default/common path (every
        # client PUT; every server RRQ with checksums off) never evicting,
        # so windowCache grew to O(filesize) instead of O(windowsize).
        for b in (prevAcked + 1) .. lastAcked:
          if onDelivered != nil:               # nil closure => NilAccessDefect if called
            onDelivered(windowCache[b])        # bytes block b was last sent with
          windowCache.del(b)                   # evict on confirm -> O(window) memory, always

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
      elif pkt.ackBlockNum == lastAcked and windowEnd > lastAcked:
        # Duplicate ACK with data still outstanding: the receiver is stuck
        # waiting for lastAcked+1, so a block in the window was lost. Once the
        # loss is confirmed (see dupAckThreshold), resend the whole outstanding
        # window — recvBlocks drops out-of-order blocks, so everything after the
        # gap must be retransmitted, not just the missing block.
        inc dupAcks
        if dupAcks >= dupAckThreshold:
          dupAcks = 0
          nextBlock = lastAcked + 1
          hitFinal = false
          fillWindow()
      # else: out-of-range / very stale ACK — ignore
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
