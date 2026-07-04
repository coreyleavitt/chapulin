## Shared transfer primitives — the foundation for both client and server.
## All I/O procs are async. Pure procs (types, constants, validation) are sync.

import std/[asyncdispatch, times, tables]
import protocol
export protocol  ## option bounds + defaults now live in protocol.nim (D7);
                  ## re-exported so existing callers (options.nim, api.nim,
                  ## server_config.nim, ...) see zero-diff.

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

proc newTransferConfig*(blocksize: int = DefaultBlocksize,
                        timeout: int = DefaultTimeout,
                        retries: int = DefaultRetries,
                        windowsize: int = DefaultWindowsize,
                        totalSize: int64 = -1): TransferConfig =
  TransferConfig(blocksize: validateBlocksize(blocksize),
                 timeout: max(MinTimeoutOpt, min(MaxTimeoutOpt, timeout)),
                 retries: retries,
                 windowsize: validateWindowsize(windowsize),
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
  ## Return the adaptive timeout once RTT samples exist, but never below the
  ## peer's negotiated `config.timeout` (RFC conformance-closure D5, round-2
  ## bug 4a). Discarding the negotiated value once adaptive refinement kicked
  ## in was the bug: a peer that explicitly negotiated a larger timeout for a
  ## high-latency link kept losing that intent after the first RTT sample.
  ## `configTimeoutMs` is a FLOOR, not a ceiling -- adaptive refinement still
  ## applies above it.
  if peer.adaptiveTimeout > 0: max(peer.adaptiveTimeout, configTimeoutMs)
  else: configTimeoutMs

proc lockTo*(peer: PeerEndpoint, host: string, port: int) =
  peer.host = host
  peer.port = port
  peer.locked = true

# A receiver that loses a DATA packet keeps re-ACKing its last in-order block.
# Those duplicate ACKs arrive before our recv times out, so a timeout-only
# retransmit never fires and the transfer deadlocks (issue #18). Treat repeated
# duplicate ACKs as a retransmit request. RFC 1123 4.2.3.1: reacting to a
# *single* duplicate ACK causes the Sorcerer's Apprentice cascade, so only act
# once the loss is confirmed by a second duplicate — one echoed ACK is ignored.
#
# Hoisted to top level (RFC conformance-closure D6) — was private to
# sendBlocks. recvBlocks' RFC 7440 gap-ACK needs to fire this EXACT number of
# back-to-back duplicates for a window-boundary gap, so both sides must agree
# on the value by construction rather than by two modules independently
# hardcoding the same magic number.
const dupAckThreshold* = 2

# Bounded final-ACK dally (RFC conformance-closure D2, policy R5). Deliberately
# NOT operator-configurable (unlike the option bounds in protocol.nim) -- an
# internal reliability constant, exported only so tests can assert against it
# by name rather than a re-hardcoded magic number.
const MaxDallyReacks* = 2

# --- recvOnce: the single-attempt receive primitive ---
#
# FLAT result (never a case-object -- the tracked never-throw Defect hazard is
# wrong-branch field access on a variant). `ok=false` means "no valid packet
# this call" for any of three reasons -- a genuine transport timeout, a
# corrupt/undecodable packet, or a TID-mismatched response (which this proc
# answers with ERROR/unknown-TID, per RFC 1350, before trying again) -- and the
# caller cannot tell which. That collapse is intentional: recvPacket's retry
# budget (config.retries) has only ever counted genuine timeouts (see below),
# and corrupt/mismatched packets are absorbed by looping internally on the SAME
# timeoutMs budget the caller supplied, exactly mirroring the pre-extraction
# inline loop. Only a real `TransportTimeoutError` from `transport.recv`
# reaches the caller as ok=false.
type
  RecvOutcome* = object
    ok*: bool
    pkt*: TftpPacket   ## meaningful iff ok

proc recvOnce*(transport: Transport, config: TransferConfig,
               peer: PeerEndpoint, timeoutMs: int): Future[RecvOutcome] {.async.} =
  ## A single receive + TID-lock validation + decode, with NO auto-resend and
  ## NO raise on timeout (the inverse of `recvPacket`'s contract -- needed by
  ## `dallyAfterFinalAck`, where silence means "done", not "resend and raise").
  ## Both `recvPacket` (retry/resend/raise layered on top) and
  ## `dallyAfterFinalAck` (bounded re-ACK-on-retransmit layered on top) sit on
  ## this primitive, so TID-lock validation is structural, not duplicated.
  ##
  ## R5 fix (dally-deadline-bypassable-dos): a decode-failure or TID-mismatch
  ## makes this loop `continue` rather than return, and each iteration used to
  ## re-issue `transport.recv` with the SAME `timeoutMs` -- since
  ## `transport.recv` starts a FRESH timer every call, a peer flooding
  ## malformed/off-TID UDP faster than one packet per `timeoutMs` reset the
  ## receive window forever, holding this call (and thus `dallyAfterFinalAck`,
  ## its coroutine, and a server transfer slot) open indefinitely. The whole
  ## internal loop is now bounded by ONE absolute wall-clock deadline derived
  ## from the caller-supplied `timeoutMs`; each iteration passes the
  ## shrinking remaining budget to `transport.recv`, so the TOTAL time this
  ## call can spend across any number of garbage/mismatched iterations is
  ## capped at that single timeout. A budget that has already run out is
  ## reported the exact same way a genuine `TransportTimeoutError` is
  ## (`RecvOutcome(ok: false)`), preserving `recvPacket`'s retry/resend and
  ## `dallyAfterFinalAck`'s deadline/`MaxDallyReacks` contracts unchanged.
  let deadline = epochTime() + timeoutMs.float / 1000.0
  while true:
    let remainingMs = int((deadline - epochTime()) * 1000.0)
    if remainingMs <= 0:
      return RecvOutcome(ok: false)

    var resp: tuple[data: seq[byte], host: string, port: int]
    try:
      resp = await transport.recv(config.blocksize + 4, remainingMs)
    except TransportTimeoutError:
      return RecvOutcome(ok: false)

    # Decode — skip corrupt packets and try again (does not consume the
    # caller's retry budget; see the type doc comment above). The NEXT
    # iteration recomputes `remainingMs` from the same deadline, so this
    # never re-arms a fresh full-length timeout.
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

    return RecvOutcome(ok: true, pkt: pkt)

# --- Core async recv with retry/TID/decode handling ---

proc recvPacket*(transport: Transport, config: TransferConfig,
                 peer: PeerEndpoint,
                 lastSent: seq[byte]): Future[TftpPacket] {.async.} =
  var retryCount = 0
  while retryCount <= config.retries:
    let timeoutMs = peer.effectiveTimeout(config.timeout * 1000)
    let sendTime = epochTime()

    let outcome = await recvOnce(transport, config, peer, timeoutMs)
    if not outcome.ok:
      retryCount.inc
      if retryCount > config.retries:
        raise newException(TransferError,
          "Timeout after " & $config.retries & " retries")
      if lastSent.len > 0:
        await transport.send(lastSent, peer.host, peer.port)
      continue

    # Measure RTT and update adaptive timeout (RFC 1123). Intentional: this
    # only runs when `outcome.ok` -- recvOnce's internal loop already
    # absorbed any corrupt/TID-mismatched packets on the way here without
    # returning, so `sendTime` is never sampled against anything but the
    # peer's own genuine response. Timing a corrupt or off-TID packet would
    # pollute the RTT estimate with a value that says nothing about this
    # peer's actual latency.
    let rttMs = (epochTime() - sendTime) * 1000.0
    peer.updateRtt(rttMs)

    # Check for error packet
    if outcome.pkt.opcode == opError:
      raise newException(TransferError, outcome.pkt.errorMsg)

    return outcome.pkt

  raise newException(TransferError,
    "Timeout after " & $config.retries & " retries")

proc dallyAfterFinalAck*(transport: Transport, peer: PeerEndpoint,
                         config: TransferConfig, finalAck: seq[byte],
                         finalBlock: uint16): Future[void] {.async.} =
  ## RFC 1350 dally: after sending the final ACK, linger briefly so a
  ## retransmitted final DATA (the sender's evidence that our ACK was lost)
  ## gets re-ACKed instead of stranding the sender. Calls `recvOnce` directly
  ## rather than `recvPacket` -- dally needs silence-means-success (no resend,
  ## no raise), the opposite of `recvPacket`'s contract -- so the TID-lock
  ## validation is preserved structurally rather than duplicated.
  ##
  ## Bounded by BOTH (R5), whichever binds first: a wall-clock deadline of one
  ## `peer.effectiveTimeout`, and `MaxDallyReacks` re-ACKs. The deadline caps
  ## total linger so a trickle of off-target packets can't extend the
  ## epilogue; the re-ACK count caps retransmit responses.
  ##
  ## An off-target packet (wrong block number, or not a DATA packet) is
  ## ignored WITHOUT consuming a re-ACK and WITHOUT ending the dally -- only a
  ## genuine timeout from `recvOnce` (nothing arrived within the remaining
  ## budget) ends it early.
  let deadline = epochTime() + peer.effectiveTimeout(config.timeout * 1000).float / 1000.0
  var reAcks = 0
  while reAcks < MaxDallyReacks:
    let remainingMs = int((deadline - epochTime()) * 1000.0)
    if remainingMs <= 0:
      break
    let outcome = await recvOnce(transport, config, peer, remainingMs)
    if not outcome.ok:
      break  # silence within the remaining budget -- dally is done
    if outcome.pkt.opcode == opData and outcome.pkt.blockNum == finalBlock:
      await transport.send(finalAck, peer.host, peer.port)
      reAcks.inc
    # else: off-target -- ignore, keep dallying within the remaining budget

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
  #
  # NOTE (pre-existing, out of this RFC's scope): `nextBlock` is a `uint16`
  # and TFTP block numbers have no room past 65535. `nextBlock.inc` at
  # `high(uint16)` wraps to 0 (unsigned wraparound, not a checked/Defect-
  # raising overflow in Nim), but that wrapped value is never actually put on
  # the wire or fed back into `fillWindow`: the block-count ceiling check
  # below (`lastAcked == high(uint16)` -> "Block number limit reached
  # (65535)") returns failure as soon as block 65535 itself is ACKed, which
  # happens before any subsequent `fillWindow()` call could run with the
  # wrapped `nextBlock`. A transfer that legitimately needs more than 65535
  # blocks at the negotiated blocksize has no path to succeed today --
  # documented here as the current hard ceiling, not a silent-wrap hazard.
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

proc lastInOrderBlock(expectedBlock: uint16): uint16 =
  ## The most recent block number the receiver has actually taken delivery of,
  ## in-order -- the correct re-ACK target for both recvBlocks' duplicate
  ## branch (pkt.blockNum < expectedBlock) and its RFC 7440 gap-ACK branch
  ## (pkt.blockNum > expectedBlock, D6). Guarded against a `uint16` underflow
  ## when expectedBlock == 0 (no in-order block received yet this call): an
  ## unguarded `expectedBlock - 1` there is an `OverflowDefect`, which is the
  ## tracked never-throw Defect hazard escaping past `except CatchableError`.
  if expectedBlock == 0: 0'u16 else: expectedBlock - 1'u16

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

  # The last block number this call has actually put on the wire in an ACK.
  # Seeded to the block already implied "acked" on entry (lastInOrderBlock of
  # startBlock) rather than a raw 0/unset sentinel -- e.g. a client resuming
  # recvBlocks at startBlock=2 after handling block 1 inline during the
  # handshake has, in reality, already had block 1 ACKed on the wire, and the
  # sender's own `lastAcked` reflects that. Needed by the RFC 7440 gap-ACK
  # (D6) to tell a mid-window gap (target never yet ACKed) from a
  # window-boundary gap (target already ACKed) -- see recvBlocks below.
  var lastAckedBlock = lastInOrderBlock(startBlock)

  # Suppresses re-firing the gap-ACK sequence for the SAME still-open gap
  # (e.g. a duplicated copy of the same ahead-of-gap block arriving again
  # before the hole is filled) while still allowing a later, DISTINCT gap to
  # fire. Keyed on the expectedBlock at the time of firing (not a sticky
  # bool) so it naturally resets once real progress closes the gap.
  var lastGapAcked: uint16
  var lastGapAckedSet = false

  # Set only on the successful final-block break out of the loop below --
  # feeds the epilogue's dallyAfterFinalAck call (D2).
  var finalBlockNum: uint16

  template sendAck(blkNum: uint16) =
    let ack = TftpPacket(opcode: opAck, ackBlockNum: blkNum)
    let ackData = encode(ack)
    await transport.send(ackData, peer.host, peer.port)
    lastSent = ackData
    # Intentional (not a bug under windowsize>1): sendAck is also used for
    # duplicate-block and RFC 7440 gap re-ACKs, not just the normal
    # every-`ws`-blocks ACK. Any ACK we send -- final, duplicate, or gap --
    # tells the sender "here is what I actually have", which effectively
    # restarts the receiver's window from that point; resetting
    # blocksInWindow to 0 here keeps the next real ACK's timing anchored to
    # that restart instead of counting blocks received before it.
    blocksInWindow = 0
    lastAckedBlock = blkNum

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

        # Final block — always ACK immediately, then break into the dally
        # epilogue below (a distinct phase, not a fourth nested case) rather
        # than returning directly from inside the loop.
        if pkt.data.len < config.blocksize:
          sendAck(pkt.blockNum)
          finalBlockNum = pkt.blockNum
          break

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
        # Duplicate — re-ACK the last block actually received in-order, NOT
        # the stale duplicate's own block number (pre-D6 bug: echoing
        # pkt.blockNum under windowsize>1 could under-report the receiver's
        # true progress relative to the sender's cumulative-ACK view).
        sendAck(lastInOrderBlock(expectedBlock))

      else:
        # pkt.blockNum > expectedBlock: RFC 7440 gap-ACK (D6). A forward
        # block arrived while an earlier one is still missing -- re-ACK the
        # last in-order block so the sender doesn't wait a full RTO. The
        # response arity MUST compose with how sendBlocks classifies an
        # incoming ACK: forward-progress (`ackBlockNum >= lastAcked+1`) or
        # duplicate (`ackBlockNum == lastAcked`, needing `dupAckThreshold`
        # repeats to fast-retransmit).
        if not (lastGapAckedSet and lastGapAcked == expectedBlock):
          lastGapAcked = expectedBlock
          lastGapAckedSet = true
          let target = lastInOrderBlock(expectedBlock)
          if lastAckedBlock == target:
            # Window-boundary gap: the target was already ACKed (a previous
            # window fully drained before the new window's lead block(s)
            # were lost). From the sender's view this re-ACK is a genuine
            # duplicate, so fire it dupAckThreshold times back-to-back to
            # reach the sender's fast-retransmit threshold.
            for _ in 1 .. dupAckThreshold:
              sendAck(target)
          else:
            # Mid-window gap: the target has never been ACKed yet, so a
            # single re-ACK lands in the sender's forward-progress branch and
            # immediately drives its partial-ACK retransmit (fillWindow). A
            # second copy would then match the just-advanced lastAcked as a
            # phantom duplicate and prime dupAcks, causing a later spurious
            # retransmit -- defeating the Sorcerer's-Apprentice guard.
            sendAck(target)
        # else: this exact gap was already re-ACKed -- suppress, so a
        # redundant copy of the same ahead-of-gap block doesn't re-fire the
        # sequence every time it arrives before the hole is actually filled.

    else:
      return TransferResult(success: false, bytesTransferred: bytesReceived,
                            errorMsg: "Unexpected packet type: " & $pkt.opcode,
                            totalSize: config.totalSize)

  # --- Epilogue: RFC 1350 bounded final-ACK dally (D2, R5) ---
  # Reached only via the successful final-block `break` above (every other
  # exit from the loop `return`s directly and skips this phase). Re-ACKs a
  # retransmitted final DATA (the sender's evidence our ACK was lost) instead
  # of leaving the sender stranded.
  await dallyAfterFinalAck(transport, peer, config, lastSent, finalBlockNum)
  return TransferResult(success: true, bytesTransferred: bytesReceived,
                        totalSize: config.totalSize)
