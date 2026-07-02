## chapulin — TFTP client and server

import chapulin/api
import chapulin/tftp_uri
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
  echo "  --mode=MODE      Transfer mode: octet or netascii (default: octet)"
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
    transferMode = tmOctet
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
      of "mode":
        case p.val.toLowerAscii
        of "octet": transferMode = tmOctet
        of "netascii":
          transferMode = tmNetascii
          # TODO(#13): netascii byte transform is not applied — netascii.nim is orphaned;
          # sets packet mode only.
        else: stderr.writeLine "Invalid mode: " & p.val & " (octet or netascii)"; quit(2)
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

    let s = newSession(minLogLevel = logLevel)
    var req = newTransferRequest(host, port, filename, localPath, direction)
    req.options.blocksize = blocksize
    req.options.windowsize = windowsize
    req.options.mode = transferMode
    req.options.timeout = timeout
    req.options.retries = retries

    let id = s.startTransfer(req)
    var exitCode = 0
    var done = false
    while not done:
      for ev in s.poll(50):
        if ev.xfrId != id: continue
        case ev.kind
        of evTransferProgress:
          let elapsed = epochTime() - startTime
          let speed = if elapsed > 0: float(ev.snap.bytes) / elapsed else: 0.0
          var line = "\r  " & formatBytes(ev.snap.bytes)
          let tot = ev.snap.total
          if tot.isSome and tot.get > 0:
            let pct = int(ev.snap.bytes * 100 div tot.get)
            line &= " / " & formatBytes(tot.get) & " (" & $pct & "%)"
          line &= " | " & formatSpeed(speed)
          if line.len < 60: line &= ' '.repeat(60 - line.len)
          stdout.write line
          stdout.flushFile
        of evTransferComplete:
          let elapsed = epochTime() - startTime
          echo "\nTransfer complete (" & elapsed.formatFloat(ffDecimal, 2) & "s)"
          if notify: stdout.write "\a"; stdout.flushFile
          exitCode = 0
          done = true
        of evTransferError:
          stderr.writeLine "\nError: " & sanitizeForDisplay(ev.errorMsg)
          exitCode = 1
          done = true
        else: discard
      if not done and not hasPendingOperations(): done = true
    s.close()
    quit(exitCode)

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
    try:
      config.checksumMode = parseChecksumMode(checksumMode)
    except ValueError as e:
      stderr.writeLine e.msg; quit(2)

    let s = newSession(minLogLevel = logLevel)

    echo formatLogMessage(llInfo, "chapulin server v" & Version)
    echo formatLogMessage(llInfo, "Root: " & absolutePath(rootDir))
    echo formatLogMessage(llInfo, "Port: " & $port)
    echo formatLogMessage(llInfo, "Write policy: " & $writePolicy)
    echo formatLogMessage(llInfo, "Max clients: " & $maxClients)

    discard s.startServer(config)

    # Server poll loop — use poll(50) for real sockets (blocking is desirable;
    # avoids a hot busy-spin while still pumping the dispatcher regularly).
    while true:
      for ev in s.poll(50):
        case ev.kind
        of evServerLog:
          echo formatLogMessage(ev.sLevel, ev.sMessage)
        of evServerStarted:
          echo formatLogMessage(llInfo, "Listening on " & ev.boundAddr & ":" & $ev.boundPort)
        of evServerStartFailed:
          stderr.writeLine formatLogMessage(llError, "Start failed: " & sanitizeForDisplay(ev.startErr))
          quit(1)
        of evTransferComplete:
          # Structural --notify: bell fires on the event, not on a log string match.
          if notify: stdout.write "\a"; stdout.flushFile
        of evTransferError:
          stderr.writeLine formatLogMessage(llError, "transfer error: " & sanitizeForDisplay(ev.errorMsg))
        of evTransferStarted, evTransferProgress,
           evTransferLog, evServerStopped:
          discard

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
