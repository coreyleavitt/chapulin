## A1a-ii (RFC verification-harness-v2.md §3.1 "Listener seam" pieces (b)+(c),
## §5 slice A1a-ii): the listener bridge (`makeListenerFromWire`) + client-side
## port adoption (`makeAdoptingTransport`) -- the genuinely new architecture.
##
## Piece (b): today's `wireharness.ListenerQueue`/`makeListener` is NOT
## connected to a `Wire`'s a2b/b2a queues -- every server-side test hand-feeds
## the queue and `makeTransport`'s `swallowFirst` DISCARDS the client's actual
## first send. `makeListenerFromWire` promotes that trick into a first-class
## `UdpListener` that drains the SAME `a2b` queue a real client's first send
## lands on, so a REAL `TftpSession.startTransfer`'s RRQ reaches it.
##
## Piece (c) -- THE NOVEL PIECE: once "the server" replies from a freshly
## minted per-transfer Wire (the A1a-i `WireRegistry`, shared with A4), the
## client's `Transport` must learn that and redirect every subsequent send
## there -- mirroring real TFTP's TID-adoption handshake (client sends
## RRQ/WRQ to the server's well-known port; server replies from a fresh
## ephemeral port; client adopts it for the rest of the transfer).
##
## Mechanism note: in this in-memory mock, `Wire.wireSend` tags every legit
## packet with the SAME constant source identity (`WirePeerHost`/
## `WirePeerPort`) regardless of which `Wire` object carried it -- there is no
## numeric "port" in the packet payload that differs per Wire. So literal
## port-number sniffing would be theater here: the thing that GENUINELY
## differs per per-transfer allocation is WHICH `Wire` object the registry
## minted. `makeAdoptingTransport` therefore learns "the server's per-transfer
## port" by watching the shared `WireRegistry` for the new `Wire` minted in
## response to this transfer's request (an `allocateTransferTransport`/
## `transferFactory` call, `server.nim`), and adopts THAT wire -- a registry-
## minted `Wire` and a per-transfer TID/port are the same fact in this harness
## (§3.1: "this is A4's transport mechanism too, generalized 1->N").
##
## Run:
##   pwsh scripts/dev-test.ps1 -Only @('t_listenerbridge')

import std/[unittest, asyncdispatch, os, sequtils]
import ../src/chapulin/api
import ../src/chapulin/protocol
import ../src/chapulin/transfer
import ./wireharness

# ---------------------------------------------------------------------------
# Local drive helper (mirrors t_session.nim's driveSession): pump s.poll(0)
# until a terminal event for `id` is seen or the step cap is hit.
# ---------------------------------------------------------------------------
proc driveSession(s: TftpSession, id: TransferId,
                  maxSteps = 200_000): seq[Event] =
  var done = false
  var steps = 0
  while steps < maxSteps and not done:
    for ev in s.poll(0):
      result.add ev
      if ev.xfrId == id and ev.kind in {evTransferComplete, evTransferError}:
        done = true
    inc steps

suite "A1a-ii: listener bridge":
  test "a real client startTransfer's first send reaches the bridge listener":
    let listenerWire = newWire()
    let listener = makeListenerFromWire(listenerWire)

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport =
        makeTransport(listenerWire, sideA = true))

    let localOut = getTempDir() / "chapulin_t_listenerbridge_unused.bin"
    let req = newTransferRequest("peer", 0, "whatever.bin", localOut, tdGet)
    discard s.startTransfer(req)

    let recvFut = listener.recv(0)
    check driveOne(recvFut)
    let (data, host, port) = recvFut.read()
    let pkt = decode(data)
    check pkt.opcode == opRrq
    check pkt.filename == "whatever.bin"
    check host == WirePeerHost
    check port == WirePeerPort

suite "A1a-ii: client-side port adoption":
  test "client adopts the server's freshly-minted per-transfer wire and routes subsequent sends there":
    # "The server", minimally: read the RRQ off the bridge listener, mint a
    # fresh per-transfer Wire via the SAME WireRegistry A4's reject-path
    # reroute shares (§3.1: "A4's registry IS this generalized 1->N"), and
    # reply with a real, short bare-DATA(1) packet -- the genuine no-options
    # TFTP fast path (engine.getFile's `of opData` branch), addressed back
    # to whatever the RRQ reported as its source. No hand-fed ListenerQueue,
    # no swallowFirst discard: both the request and the reply are REAL sends
    # over REAL Wires, exactly like `handleRequest`'s
    # `allocateTransferTransport` mints a real per-transfer transport in
    # production (server.nim:710).
    let listenerWire = newWire()
    let listener = makeListenerFromWire(listenerWire)
    let reg = newWireRegistry()

    let s = newSession(transportFactory =
      proc(host: string, port: int): Transport =
        makeAdoptingTransport(listenerWire, reg))

    let tmpDir = getTempDir() / "chapulin_t_listenerbridge_adopt"
    createDir(tmpDir)
    let localOut = tmpDir / "out.bin"
    defer:
      try: removeFile(localOut) except CatchableError: discard
      try: removeDir(tmpDir) except CatchableError: discard

    let req = newTransferRequest("peer", 0, "whatever.bin", localOut, tdGet)
    let id = s.startTransfer(req)

    proc serverSide() {.async.} =
      let (data, _, _) = await listener.recv(2000)
      let pkt = decode(data)
      doAssert pkt.opcode == opRrq
      # Mint the per-transfer Wire -- the exact mechanism A4's reject-path
      # reroute and `allocateTransferTransport` share (server.nim:710):
      # a fresh registry call, never the listener's own wire.
      let xferTransport = reg.factory()("127.0.0.1", 0)
      let payload = @[byte(1), byte(2), byte(3)]  # < any real blocksize -> final block
      let dataPkt = encode(TftpPacket(opcode: opData, blockNum: 1, data: payload))
      await xferTransport.send(dataPkt, WirePeerHost, WirePeerPort)

    check driveOne(serverSide())

    # Exactly one per-transfer Wire minted -- the client's freshly-learned "port".
    check reg.wires.len == 1

    let evs = driveSession(s, id)
    check evs.anyIt(it.kind == evTransferComplete and it.xfrId == id)
    let complete = evs.filterIt(it.kind == evTransferComplete)[0]
    check complete.snap.bytes == 3

    # The genuinely novel assertion: the client's SUBSEQUENT send (the ACK
    # for the final DATA block) landed on the ADOPTED per-transfer Wire's
    # b2a queue (side B == client here, since the registry minted the
    # server side A) -- NOT back on the original listener Wire. Real TID
    # adoption: once learned, every later packet goes to the NEW port, never
    # the well-known one again.
    check reg.wires[0].bSends() >= 1
    check listenerWire.aSends() == 1  # only the original RRQ ever touched it
