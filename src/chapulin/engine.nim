## TFTP client transfer engine — thin async wrappers around transfer.nim.
## Handles client-specific initiation (RRQ/WRQ handshake + option negotiation).

import std/asyncdispatch
import std/times
import protocol
import transfer
import options
import netascii

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
  # RFC-conformance-closure D1d (client-side specifics): under netascii, a
  # requested tsize would describe pre-translation local bytes while the
  # actual transfer is measured in post-translation wire bytes -- suppress
  # the outbound request through the same policy seam server.nim's OACK-side
  # drop uses, so the two directions can't drift apart.
  buildClientOptions(toTransferConfig(config),
                     requestTsize = config.requestTsize and
                                    not netasciiPolicyFor(config.mode).suppressTsize,
                     tsizeValue = config.tsize)

const OptionNegotiationFailedMsg = "Option negotiation failed"
  ## Path-free, client-safe -- mirrors server.nim's clientSafeError(errOptionNegotiation)
  ## text, kept as a local literal so this client-side module has no reason
  ## to import the server module.

proc applyOack(neg: NegotiatedOptions, xferConfig: var TransferConfig) =
  ## Consumes an already-validated `NegotiatedOptions` -- NEVER `pkt.oackOptions`
  ## directly. This is the R4 enforcement point: an unrequested-but-in-range
  ## option was already filtered out of `neg` by `validateAndParseOack`, so it
  ## is structurally impossible for it to reach `xferConfig` from here.
  xferConfig.blocksize = neg.blocksize
  xferConfig.totalSize = neg.totalSize
  xferConfig.windowsize = neg.windowsize
  xferConfig.timeout = neg.timeout

proc sendOackFailure(transport: Transport, host: string, port: int,
                     totalSize: int64): Future[TransferResult] {.async.} =
  ## Shared ERROR(8) + failure-result path for a rejected OACK (D4/R4) --
  ## used by both getFile and putFile. Replaces the old silent
  ## `except ValueError` path, which failed the client locally without ever
  ## telling the server why.
  let errPkt = TftpPacket(opcode: opError, errorCode: errOptionNegotiation,
                          errorMsg: OptionNegotiationFailedMsg)
  await transport.send(encode(errPkt), host, port)
  return TransferResult(success: false, bytesTransferred: 0,
                        errorMsg: OptionNegotiationFailedMsg,
                        errorCode: ord(errOptionNegotiation),
                        totalSize: totalSize)

# --- awaitHandshakeReply: the shared bounded-wait-and-resend handshake loop ---
#
# R3-2 extraction: getFile and putFile each ran a near-verbatim copy of this
# loop (deadline init, remainingMs budget check, transport.recv, decode-fail
# `continue` without reseeding the deadline, remainingMs<=0/TransportTimeoutError
# -> retryCount.inc + resend + reseed, retry-exhaustion return), differing only
# in the request packet resent and which decoded packet counts as "the reply
# we were waiting for". FLAT result (mirrors transfer.nim's RecvOutcome, not a
# variant) -- `kind` gates which other fields are meaningful, so there is no
# wrong-branch field access to worry about (the tracked never-throw Defect
# hazard).
#
# `wanted` is the caller's off-target classifier: an off-target-but-decodable
# packet (RRQ handshake's DATA(blockNum != 1); WRQ handshake's ACK(ackBlockNum
# != 0)) makes `wanted` return false, so this loop `continue`s WITHOUT
# reseeding the deadline -- the packet is absorbed within the CURRENT
# attempt's shrinking budget, exactly like a decode failure. Every other
# decoded packet (OACK, the wanted DATA/ACK, ERROR, or any other opcode) is
# handed back to the caller via `kind: hoGot` for it to `case` on and dispatch
# -- including the "unexpected packet type" and OACK-rejection paths, which
# stay in the caller unchanged.
type
  HandshakeOutcomeKind* = enum
    hoGot, hoTimedOut, hoCancelled

  HandshakeOutcome* = object
    kind*: HandshakeOutcomeKind
    pkt*: TftpPacket      ## meaningful iff kind == hoGot
    respHost*: string     ## meaningful iff kind == hoGot
    respPort*: int        ## meaningful iff kind == hoGot
    failure*: TransferResult  ## meaningful iff kind != hoGot -- the ready-to-
                              ## return TransferResult for hoCancelled/hoTimedOut
                              ## (R4-1: see below)

proc awaitHandshakeReply(transport: Transport, xferConfig: TransferConfig,
                        host: string, port: int, requestPkt: seq[byte],
                        cancelCheck: CancelCheck,
                        wanted: proc(pkt: TftpPacket): bool {.closure.}): Future[HandshakeOutcome] {.async.} =
  ## Bounded wait for the server's first handshake reply (OACK / DATA(1) for
  ## GET; OACK / ACK(0) for PUT), resending `requestPkt` and reseeding the
  ## deadline on each genuine per-attempt timeout, up to `xferConfig.retries`.
  ## All loop state (deadline, retryCount) is LOCAL -- no `var` params on this
  ## `{.async.}` proc.
  ##
  ## `wanted` must be non-nil -- both callers (getFile's `rrqWanted`, putFile's
  ## `wrqWanted`) pass a live closure unconditionally; there is no runtime
  ## nil check here.
  ##
  ## R4-1: getFile and putFile used to each hold a verbatim ~10-line copy of
  ## the hoCancelled/hoTimedOut -> TransferResult translation. Both
  ## `xferConfig.totalSize` and (for the timeout message) `xferConfig.retries`
  ## are already in scope here, so this proc builds the final TransferResult
  ## once, up front, and stashes it on `failure` -- every hoCancelled/hoTimedOut
  ## return below reuses the same value. Callers now only branch on `hoGot`;
  ## any other kind is `return handshake.failure` as-is. Error strings are
  ## byte-for-byte identical to the pre-extraction copies (both callers'
  ## `config.retries` equals this `xferConfig.retries` -- toTransferConfig
  ## copies it verbatim, no clamp).
  let cancelledResult = TransferResult(success: false, bytesTransferred: 0,
                                       errorMsg: "Transfer cancelled",
                                       totalSize: xferConfig.totalSize)
  let timedOutResult = TransferResult(success: false, bytesTransferred: 0,
                                      errorMsg: "Timeout after " & $xferConfig.retries & " retries",
                                      totalSize: xferConfig.totalSize)

  var retryCount = 0
  # R3-1: seed from xferConfig.timeout (already clamped into
  # [MinTimeoutOpt, MaxTimeoutOpt] by toTransferConfig), never the raw
  # config.timeout the caller built xferConfig from.
  var deadline = epochTime() + xferConfig.timeout.float

  while retryCount <= xferConfig.retries:
    if cancelCheck != nil and cancelCheck():
      return HandshakeOutcome(kind: hoCancelled, failure: cancelledResult)

    let remainingMs = int((deadline - epochTime()) * 1000.0)
    if remainingMs <= 0:
      retryCount.inc
      if retryCount > xferConfig.retries:
        return HandshakeOutcome(kind: hoTimedOut, failure: timedOutResult)
      await transport.send(requestPkt, host, port)
      deadline = epochTime() + xferConfig.timeout.float
      continue

    var resp: tuple[data: seq[byte], host: string, port: int]
    try:
      resp = await transport.recv(xferConfig.blocksize + 4, remainingMs)
    except TransportTimeoutError:
      retryCount.inc
      if retryCount > xferConfig.retries:
        return HandshakeOutcome(kind: hoTimedOut, failure: timedOutResult)
      await transport.send(requestPkt, host, port)
      deadline = epochTime() + xferConfig.timeout.float
      continue

    var pkt: TftpPacket
    try:
      pkt = decode(resp.data)
    except TftpDecodeError:
      continue

    if not wanted(pkt):
      continue

    return HandshakeOutcome(kind: hoGot, pkt: pkt, respHost: resp.host, respPort: resp.port)

  return HandshakeOutcome(kind: hoTimedOut, failure: timedOutResult)

# --- getFile: client RRQ ---

proc getFile*(transport: Transport, config: TftpClientConfig,
              host: string, port: int, filename: string,
              onData: proc(blockNum: uint16, data: seq[byte]),
              onProgress: ProgressCallback = nil,
              cancelCheck: CancelCheck = nil,
              onNegotiated: proc(blocksize: int, windowsize: int) {.closure.} = nil): Future[TransferResult] {.async.} =
  let opts = clientBuildOptions(config)
  let rrq = TftpPacket(opcode: opRrq, filename: filename, mode: config.mode, options: opts)
  let rrqPkt = encode(rrq)  ## computed once; reused below as awaitHandshakeReply's resend packet
  await transport.send(rrqPkt, host, port)

  var xferConfig = toTransferConfig(config)
  let peer = newPeer(host, port)
  let optionsRequested = opts.len > 0

  var startBlock: uint16 = 1

  # R2-1/R3-2: the bounded wait-and-resend loop itself now lives in the
  # shared awaitHandshakeReply helper (mirrors recvOnce's contract in
  # transfer.nim). An off-target DATA (blockNum != 1) is the ONE packet this
  # handshake must absorb WITHOUT reseeding the deadline -- everything else
  # decodable (OACK, DATA(1), ERROR, or any other opcode) is handed back here
  # for dispatch, unchanged from the pre-extraction inline loop.
  let rrqWanted = proc(pkt: TftpPacket): bool =
    not (pkt.opcode == opData and pkt.blockNum != 1)

  let handshake = await awaitHandshakeReply(transport, xferConfig, host, port,
                                            rrqPkt, cancelCheck, rrqWanted)

  # R4-1: hoCancelled/hoTimedOut are already fully translated into their
  # final TransferResult by awaitHandshakeReply -- see its doc comment.
  case handshake.kind
  of hoCancelled, hoTimedOut:
    return handshake.failure
  of hoGot:
    discard

  let pkt = handshake.pkt
  case pkt.opcode
  of opOack:
    # R2-3 fix (a): seed from the ALREADY-CLAMPED xferConfig.timeout, not
    # the raw config.timeout -- xferConfig was built via toTransferConfig
    # (which clamps into [MinTimeoutOpt, MaxTimeoutOpt]) one line above.
    # validateAndParseOack falls back to this `configuredTimeout` when the
    # OACK omits "timeout"; passing the raw value let an out-of-range/zero
    # config.timeout survive into applyOack's `xferConfig.timeout =
    # neg.timeout`, and a zero timeout there collapses recvOnce's deadline
    # to "now" -- every post-handshake recv times out instantly.
    let oackResult = validateAndParseOack(pkt.oackOptions, opts, xferConfig.timeout)
    if not oackResult.ok:
      return await sendOackFailure(transport, handshake.respHost, handshake.respPort, xferConfig.totalSize)
    applyOack(oackResult.negotiated, xferConfig)
    if onNegotiated != nil:
      onNegotiated(xferConfig.blocksize, xferConfig.windowsize)
    peer.lockTo(handshake.respHost, handshake.respPort)
    await transport.send(encode(TftpPacket(opcode: opAck, ackBlockNum: 0)),
                         peer.host, peer.port)
    startBlock = 1

  of opData:
    peer.lockTo(handshake.respHost, handshake.respPort)
    if optionsRequested:
      xferConfig.blocksize = DefaultBlocksize
    # rrqWanted guarantees pkt.blockNum == 1 here -- an off-target DATA never
    # reaches this dispatch.
    if onNegotiated != nil:
      onNegotiated(xferConfig.blocksize, xferConfig.windowsize)
    onData(1, pkt.data)
    let bytesFromFirst = int64(pkt.data.len)
    let finalAck = encode(TftpPacket(opcode: opAck, ackBlockNum: 1))
    await transport.send(finalAck, peer.host, peer.port)
    if onProgress != nil:
      onProgress(bytesFromFirst, xferConfig.totalSize)
    if pkt.data.len < xferConfig.blocksize:
      # Single-block GET: nothing left for recvBlocks' loop to receive,
      # just a possible retransmit of this same final DATA if our ACK was
      # lost -- dallyAfterFinalAck handles that directly (D2).
      await dallyAfterFinalAck(transport, peer, xferConfig, finalAck, 1'u16)
      return TransferResult(success: true, bytesTransferred: bytesFromFirst,
                            totalSize: xferConfig.totalSize)
    startBlock = 2

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
              cancelCheck: CancelCheck = nil,
              onNegotiated: proc(blocksize: int, windowsize: int) {.closure.} = nil): Future[TransferResult] {.async.} =
  let opts = clientBuildOptions(config)
  let wrq = TftpPacket(opcode: opWrq, filename: filename, mode: config.mode, options: opts)
  let wrqPkt = encode(wrq)  ## computed once; reused below as awaitHandshakeReply's resend packet
  await transport.send(wrqPkt, host, port)

  var xferConfig = toTransferConfig(config)
  let peer = newPeer(host, port)
  let optionsRequested = opts.len > 0

  # R2-1/R3-2: see the matching comment in getFile above -- the bounded
  # wait-and-resend loop lives in the shared awaitHandshakeReply helper. An
  # off-target ACK (ackBlockNum != 0) is the ONE packet this handshake must
  # absorb WITHOUT reseeding the deadline -- everything else decodable
  # (OACK, ACK(0), ERROR, or any other opcode) is handed back here for
  # dispatch, unchanged from the pre-extraction inline loop.
  let wrqWanted = proc(pkt: TftpPacket): bool =
    not (pkt.opcode == opAck and pkt.ackBlockNum != 0)

  let handshake = await awaitHandshakeReply(transport, xferConfig, host, port,
                                            wrqPkt, cancelCheck, wrqWanted)

  # R4-1: hoCancelled/hoTimedOut are already fully translated into their
  # final TransferResult by awaitHandshakeReply -- see its doc comment.
  case handshake.kind
  of hoCancelled, hoTimedOut:
    return handshake.failure
  of hoGot:
    discard

  let pkt = handshake.pkt
  case pkt.opcode
  of opOack:
    # R2-3 fix (a): seed from the already-clamped xferConfig.timeout --
    # see the matching comment in getFile above.
    let oackResult = validateAndParseOack(pkt.oackOptions, opts, xferConfig.timeout)
    if not oackResult.ok:
      return await sendOackFailure(transport, handshake.respHost, handshake.respPort, xferConfig.totalSize)
    applyOack(oackResult.negotiated, xferConfig)
    if onNegotiated != nil:
      onNegotiated(xferConfig.blocksize, xferConfig.windowsize)
    peer.lockTo(handshake.respHost, handshake.respPort)

  of opAck:
    # wrqWanted guarantees pkt.ackBlockNum == 0 here -- an off-target ACK
    # never reaches this dispatch.
    peer.lockTo(handshake.respHost, handshake.respPort)
    if optionsRequested:
      xferConfig.blocksize = DefaultBlocksize
    if onNegotiated != nil:
      onNegotiated(xferConfig.blocksize, xferConfig.windowsize)

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
