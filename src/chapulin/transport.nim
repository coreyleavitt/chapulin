## Real UDP transport — async sockets for client, server, and listener.

import std/[asyncdispatch, asyncnet, net, nativesockets]
import transfer

proc isIPv6*(host: string): bool =
  ':' in host

proc toWireString(data: seq[byte]): string =
  ## RFC design-bar-closure D2 dedup: the `seq[byte]` -> `string` conversion
  ## loop hand-rolled at three send/recv sites in this module (newUdpTransport's
  ## send/recv, newUdpListener's recv), extracted once. Trivial and
  ## transitively validated (no dedicated t_transport test — acknowledged in
  ## the RFC as acceptable given the triviality).
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

proc toByteSeq(s: string): seq[byte] =
  ## Inverse of toWireString; see its doc comment.
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)

proc newUdpTransport*(bindPort: int = 0, ipv6: bool = false): Transport =
  ## Create an async UDP transport on an ephemeral (or specified) port.
  let domain = if ipv6: AF_INET6 else: AF_INET
  let sock = newAsyncSocket(domain, SOCK_DGRAM, IPPROTO_UDP)
  sock.bindAddr(Port(bindPort))

  result.send = proc(data: seq[byte], host: string, port: int): Future[void] {.async.} =
    await sock.sendTo(host, Port(port), toWireString(data))

  var pendingRecv: Future[tuple[data: string, address: string, port: Port]]

  result.recv = proc(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte], host: string, port: int]] {.async.} =
    if pendingRecv == nil or pendingRecv.finished:
      pendingRecv = sock.recvFrom(bufSize)
    let completed = await withTimeout(pendingRecv, timeoutMs)
    if not completed:
      raise newException(TransportTimeoutError, "Receive timed out")
    let (strData, address, senderPort) = pendingRecv.read()
    pendingRecv = nil
    return (data: toByteSeq(strData), host: address, port: int(senderPort))

  result.close = proc() =
    sock.close()

# --- Server listener ---

type
  UdpListener* = object
    recv*:      proc(timeoutMs: int): Future[tuple[data: seq[byte], host: string, port: int]] {.closure.}
    close*:     proc() {.closure.}
    localPort*: proc(): int {.closure.}

proc newUdpListener*(bindAddr: string = "0.0.0.0", port: int = 69,
                     ipv6: bool = false): UdpListener =
  let domain = if ipv6: AF_INET6 else: AF_INET
  let sock = newAsyncSocket(domain, SOCK_DGRAM, IPPROTO_UDP)
  sock.bindAddr(Port(port), bindAddr)
  let (_, assignedPort) = sock.getLocalAddr()
  result.localPort = proc(): int = int(assignedPort)

  # Single persistent recvFrom future — avoids orphaned pending reads on timeout.
  var pendingRecv: Future[tuple[data: string, address: string, port: Port]]

  result.recv = proc(timeoutMs: int): Future[tuple[data: seq[byte], host: string, port: int]] {.async.} =
    if pendingRecv == nil or pendingRecv.finished:
      pendingRecv = sock.recvFrom(576)
    let completed = await withTimeout(pendingRecv, timeoutMs)
    if not completed:
      raise newException(TransportTimeoutError, "Listener timed out")
    let (strData, address, senderPort) = pendingRecv.read()
    pendingRecv = nil  # consumed, next call creates a new one
    return (data: toByteSeq(strData), host: address, port: int(senderPort))

  result.close = proc() =
    sock.close()
