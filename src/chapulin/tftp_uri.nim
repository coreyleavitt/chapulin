## TFTP URI parsing per RFC 3617.
## Format: tftp://host[:port]/file[;mode=netascii|octet]

import std/strutils

type
  TftpUri* = object
    host*: string
    port*: int
    filename*: string
    mode*: string  ## "octet" or "netascii"

  TftpUriError* = object of CatchableError

proc isTftpUri*(s: string): bool =
  s.toLowerAscii.startsWith("tftp://")

proc parseTftpUri*(uri: string): TftpUri =
  if uri.len == 0:
    raise newException(TftpUriError, "Empty URI")

  if not isTftpUri(uri):
    raise newException(TftpUriError, "Not a TFTP URI: " & uri)

  # Strip scheme
  var rest = uri[7 .. ^1]  # after "tftp://"

  # Parse host (may be [IPv6]:port or host:port or host)
  var host: string
  var portStr = ""
  var pathStart: int

  if rest.startsWith("["):
    # IPv6: [addr]:port/path or [addr]/path
    let closeBracket = rest.find(']')
    if closeBracket < 0:
      raise newException(TftpUriError, "Unclosed bracket in IPv6 address")
    host = rest[1 ..< closeBracket]
    rest = rest[closeBracket + 1 .. ^1]
    if rest.startsWith(":"):
      let slashPos = rest.find('/')
      if slashPos < 0:
        raise newException(TftpUriError, "Missing filename in URI")
      portStr = rest[1 ..< slashPos]
      rest = rest[slashPos .. ^1]
  else:
    # IPv4 or hostname
    let slashPos = rest.find('/')
    if slashPos < 0:
      raise newException(TftpUriError, "Missing filename in URI")
    let hostPort = rest[0 ..< slashPos]
    rest = rest[slashPos .. ^1]

    let colonPos = hostPort.rfind(':')
    if colonPos >= 0:
      host = hostPort[0 ..< colonPos]
      portStr = hostPort[colonPos + 1 .. ^1]
    else:
      host = hostPort

  if host.len == 0:
    raise newException(TftpUriError, "Missing host in URI")

  # Parse port
  var port = 69
  if portStr.len > 0:
    try:
      port = parseInt(portStr)
    except ValueError:
      raise newException(TftpUriError, "Invalid port: " & portStr)

  # rest starts with "/", strip it
  if not rest.startsWith("/"):
    raise newException(TftpUriError, "Missing path separator")
  rest = rest[1 .. ^1]

  # Parse filename and mode parameter
  var filename: string
  var mode = "octet"

  let semicolonPos = rest.find(';')
  if semicolonPos >= 0:
    filename = rest[0 ..< semicolonPos]
    let params = rest[semicolonPos + 1 .. ^1]
    if params.toLowerAscii.startsWith("mode="):
      mode = params[5 .. ^1].toLowerAscii
  else:
    filename = rest

  if filename.len == 0:
    raise newException(TftpUriError, "Missing filename in URI")

  TftpUri(host: host, port: port, filename: filename, mode: mode)
