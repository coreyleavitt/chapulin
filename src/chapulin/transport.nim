## Real UDP transport — async sockets for client, server, and listener.

import std/[asyncdispatch, asyncnet, net, nativesockets]
import transfer

proc isIPv6*(host: string): bool =
  ':' in host

proc newUdpTransport*(bindPort: int = 0, ipv6: bool = false): Transport =
  ## Create an async UDP transport on an ephemeral (or specified) port.
  let domain = if ipv6: AF_INET6 else: AF_INET
  let sock = newAsyncSocket(domain, SOCK_DGRAM, IPPROTO_UDP)
  sock.bindAddr(Port(bindPort))

  result.send = proc(data: seq[byte], host: string, port: int): Future[void] {.async.} =
    var strData = newString(data.len)
    for i, b in data:
      strData[i] = char(b)
    await sock.sendTo(host, Port(port), strData)

  var pendingRecv: Future[tuple[data: string, address: string, port: Port]]

  result.recv = proc(bufSize: int, timeoutMs: int): Future[tuple[data: seq[byte], host: string, port: int]] {.async.} =
    if pendingRecv == nil or pendingRecv.finished:
      pendingRecv = sock.recvFrom(bufSize)
    let completed = await withTimeout(pendingRecv, timeoutMs)
    if not completed:
      raise newException(TransportTimeoutError, "Receive timed out")
    let (strData, address, senderPort) = pendingRecv.read()
    pendingRecv = nil
    var bytes = newSeq[byte](strData.len)
    for i, c in strData:
      bytes[i] = byte(c)
    return (data: bytes, host: address, port: int(senderPort))

  result.close = proc() =
    sock.close()

# --- Server listener ---

type
  UdpListener* = object
    recv*: proc(timeoutMs: int): Future[tuple[data: seq[byte], host: string, port: int]] {.closure.}
    close*: proc() {.closure.}

proc newUdpListener*(bindAddr: string = "0.0.0.0", port: int = 69,
                     ipv6: bool = false): UdpListener =
  let domain = if ipv6: AF_INET6 else: AF_INET
  let sock = newAsyncSocket(domain, SOCK_DGRAM, IPPROTO_UDP)
  sock.bindAddr(Port(port), bindAddr)

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
    var bytes = newSeq[byte](strData.len)
    for i, c in strData:
      bytes[i] = byte(c)
    return (data: bytes, host: address, port: int(senderPort))

  result.close = proc() =
    sock.close()
