## chapulin — TFTP client and server

import chapulin/api
import chapulin/transport
import chapulin/format
import chapulin/server
import chapulin/server_config
import chapulin/security
import chapulin/protocol
import chapulin/transfer
import chapulin/tftp_uri
import chapulin/logging
import std/[os, parseopt, strutils, times, asyncdispatch]

when defined(withGui):
  import ../gui/desktop/chapulin_gui

const Version = "0.1.0"

proc usage() =
  echo "chapulin v" & Version & " — TFTP client and server"
  echo ""
  echo "Usage:"
  echo "  chapulin get <host> <filename> [options]"
  echo "  chapulin get tftp://<host>[:<port>]/<filename> [options]"
  echo "  chapulin put <host> <filename> [options]"
  echo "  chapulin put tftp://<host>[:<port>]/<filename> [options]"
  echo "  chapulin serve <rootdir> [options]"
  when defined(withGui):
    echo "  chapulin gui"
  echo ""
  echo "Client options:"
  echo "  --port=N         Server port (default: 69)"
  echo "  --blocksize=N    Block size in bytes (default: 512)"
  echo "  --windowsize=N   Window size in blocks (default: 1, RFC 7440)"
  echo "  --timeout=N      Timeout in seconds (default: 5)"
  echo "  --retries=N      Max retransmit attempts (default: 3)"
  echo "  --output=PATH    Local file path (default: filename for get)"
  echo ""
  echo "Server options:"
  echo "  --port=N         Listen port (default: 69)"
  echo "  --write=POLICY   deny|create|overwrite|all (default: deny)"
  echo "  --max-clients=N  Max concurrent transfers (default: 10)"
  echo "  --blocksize=N    Max blocksize (default: 65464)"
  echo "  --timeout=N      Timeout in seconds (default: 5)"
  echo "  --port-range=S:E Transfer port range for firewall (e.g., 6881:6889)"
  echo "  --pxe-compat     Only negotiate tsize option (for buggy PXE ROMs)"
  echo "  --bind=ADDR      Bind to specific IP address (default: 0.0.0.0)"
  echo "  --dir-list=FILE  Serve directory listing as this filename (e.g., dir.txt)"
  echo "  --checksum=MODE  Generate checksum sidecar after read (md5 or none)"
  echo ""
  echo "General options:"
  echo "  --notify         Audible bell on transfer completion"
  echo "  --verbose        Show detailed output (debug level)"
  echo "  --quiet          Suppress all output except errors"
  echo "  --help           Show this help"
  echo "  --version        Show version"

when isMainModule:
  var
    command = ""
    positionalIdx = 0
    host, filename, localPath, rootDir: string
    port = -1  # -1 = use default for command
    blocksize = DefaultBlocksize
    windowsize = DefaultWindowsize
    timeout = DefaultTimeout
    retries = DefaultRetries
    logLevel = llInfo
    notify = false
    writePolicy = wpDeny
    maxClients = 10
    portRangeStart = 0
    portRangeEnd = 0
    pxeCompat = false
    bindAddr = "0.0.0.0"
    dirListFile = ""
    checksumMode = ""

  var p = initOptParser(commandLineParams())
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key.toLowerAscii
      of "help", "h": usage(); quit(0)
      of "notify": notify = true
      of "verbose": logLevel = llDebug
      of "quiet", "q": logLevel = llError
      of "version", "v": echo "chapulin v" & Version; quit(0)
      of "port":
        try: port = parseInt(p.val)
        except ValueError: stderr.writeLine "Invalid port: " & p.val; quit(2)
      of "blocksize":
        try: blocksize = parseInt(p.val)
        except ValueError: stderr.writeLine "Invalid blocksize: " & p.val; quit(2)
      of "windowsize":
        try: windowsize = parseInt(p.val)
        except ValueError: stderr.writeLine "Invalid windowsize: " & p.val; quit(2)
      of "timeout":
        try: timeout = parseInt(p.val)
        except ValueError: stderr.writeLine "Invalid timeout: " & p.val; quit(2)
      of "retries":
        try: retries = parseInt(p.val)
        except ValueError: stderr.writeLine "Invalid retries: " & p.val; quit(2)
      of "output", "o": localPath = p.val
      of "write":
        case p.val.toLowerAscii
        of "deny": writePolicy = wpDeny
        of "create": writePolicy = wpCreateOnly
        of "overwrite": writePolicy = wpOverwrite
        of "all": writePolicy = wpCreateOrOverwrite
        else: stderr.writeLine "Invalid write policy: " & p.val; quit(2)
      of "max-clients":
        try: maxClients = parseInt(p.val)
        except ValueError: stderr.writeLine "Invalid max-clients: " & p.val; quit(2)
      of "port-range":
        let parts = p.val.split(':')
        if parts.len != 2:
          stderr.writeLine "Invalid port-range format (expected START:END): " & p.val; quit(2)
        try:
          portRangeStart = parseInt(parts[0])
          portRangeEnd = parseInt(parts[1])
        except ValueError:
          stderr.writeLine "Invalid port-range: " & p.val; quit(2)
        if portRangeStart <= 0 or portRangeEnd < portRangeStart:
          stderr.writeLine "Invalid port-range: start must be > 0 and end >= start"; quit(2)
      of "pxe-compat": pxeCompat = true
      of "bind": bindAddr = p.val
      of "dir-list": dirListFile = p.val
      of "checksum": checksumMode = p.val
      else: stderr.writeLine "Unknown option: " & p.key; quit(2)
    of cmdArgument:
      case positionalIdx
      of 0: command = p.key.toLowerAscii
      of 1:
        if command in ["get", "put"]:
          if isTftpUri(p.key):
            # RFC 3617: tftp://host[:port]/file[;mode=netascii|octet]
            try:
              let uri = parseTftpUri(p.key)
              host = uri.host
              port = uri.port
              filename = uri.filename
            except TftpUriError as e:
              stderr.writeLine "Invalid URI: " & e.msg; quit(2)
          else:
            host = p.key
        elif command == "serve": rootDir = p.key
      of 2:
        if command in ["get", "put"] and filename.len == 0: filename = p.key
      else: discard
      positionalIdx.inc

  case command
  of "get", "put":
    if host.len == 0 or filename.len == 0:
      stderr.writeLine "Error: missing required arguments"
      usage(); quit(2)
    if port < 0: port = 69
    if localPath.len == 0:
      localPath = extractFilename(filename)
    let direction = if command == "get": tdGet else: tdPut

    let startTime = epochTime()
    echo (if direction == tdGet: "Downloading " else: "Uploading ") &
      filename & (if direction == tdGet: " from " else: " to ") &
      host & ":" & $port

    let progressCb = proc(bytesTransferred: int64, totalBytes: int64) =
      let elapsed = epochTime() - startTime
      let speed = if elapsed > 0: float(bytesTransferred) / elapsed else: 0.0
      var line = "\r  " & formatBytes(bytesTransferred)
      if totalBytes > 0:
        let pct = int(bytesTransferred * 100 div totalBytes)
        line &= " / " & formatBytes(totalBytes) & " (" & $pct & "%)"
      line &= " | " & formatSpeed(speed)
      if line.len < 60: line &= ' '.repeat(60 - line.len)
      stdout.write line
      stdout.flushFile
    let completeCb = proc() =
      let elapsed = epochTime() - startTime
      echo "\nTransfer complete (" & elapsed.formatFloat(ffDecimal, 2) & "s)"
      if notify: stdout.write "\a"; stdout.flushFile
    let errorCb = proc(code: int, msg: string) =
      stderr.writeLine "\nError: " & msg
    let callbacks = TransferCallbacks(
      onProgress: progressCb, onComplete: completeCb, onError: errorCb)

    var req = newTransferRequest(host, port, filename, localPath, direction)
    req.options.blocksize = blocksize
    req.options.windowsize = windowsize
    req.options.timeout = timeout
    req.options.retries = retries

    let udpTransport = newUdpTransport(ipv6 = isIPv6(host))
    let result = waitFor executeTransfer(req, callbacks, udpTransport)
    if udpTransport.close != nil: udpTransport.close()
    quit(if result.success: 0 else: 1)

  of "serve":
    if rootDir.len == 0:
      stderr.writeLine "Error: missing root directory"
      usage(); quit(2)
    if not dirExists(rootDir):
      stderr.writeLine "Error: directory not found: " & rootDir
      quit(2)
    if port < 0: port = 69

    var config = newDefaultServerConfig(rootDir)
    config.listenPort = port
    config.writePolicy = writePolicy
    config.maxConcurrent = maxClients
    config.maxBlocksize = blocksize
    config.timeout = timeout
    config.retries = retries
    config.portRangeStart = portRangeStart
    config.portRangeEnd = portRangeEnd
    config.pxeCompat = pxeCompat
    config.listenAddr = bindAddr
    config.dirListFile = dirListFile
    config.checksumMode = checksumMode

    let serverOutput: LogOutput = proc(level: LogLevel, msg: string) =
      echo formatLogMessage(level, msg)
      # Bell on transfer completion (info messages containing "OK")
      if notify and level == llInfo and " OK " in msg:
        stdout.write "\a"; stdout.flushFile
    let serverLogger = newLogger(logLevel, serverOutput)
    let srv = newTftpServer(config, logger = serverLogger)

    serverLogger.info("chapulin server v" & Version)
    serverLogger.info("Root: " & absolutePath(rootDir))
    serverLogger.info("Port: " & $port)
    serverLogger.info("Write policy: " & $writePolicy)
    serverLogger.info("Max clients: " & $maxClients)
    serverLogger.info("Listening...")

    let listener = newUdpListener(config.listenAddr, port,
                                   ipv6 = isIPv6(config.listenAddr))
    waitFor srv.run(listener)
    listener.close()

  of "gui":
    when defined(withGui):
      launchGui()
    else:
      stderr.writeLine "GUI not available (build with -d:withGui)"
      quit(1)

  else:
    if command.len == 0:
      stderr.writeLine "Error: no command specified"
    else:
      stderr.writeLine "Unknown command: " & command
    usage()
    quit(2)
