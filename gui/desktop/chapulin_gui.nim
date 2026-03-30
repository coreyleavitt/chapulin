## chapulin NiGui desktop GUI — client and server with log viewer

import nigui
import std/os
import std/strutils
import std/times
import std/[atomics, asyncdispatch]
import ../../src/chapulin/api
import ../../src/chapulin/transport
import ../../src/chapulin/format
import ../../src/chapulin/server
import ../../src/chapulin/server_config
import ../../src/chapulin/logging

type
  MsgKind = enum
    mkProgress, mkComplete, mkError, mkLog

  TransferMsg = object
    case kind: MsgKind
    of mkProgress:
      bytesTransferred: int64
      totalBytes: int64
    of mkComplete:
      finalBytes: int64
    of mkError:
      errorMsg: string
    of mkLog:
      logMsg: string

  TransferParams = object
    host: string
    port: int
    remoteFile: string
    localFile: string
    direction: TransferDirection
    blocksize: int

  ServerParams = object
    rootDir: string
    port: int
    writePolicy: WritePolicy
    maxClients: int

var
  clientChannel: Channel[TransferMsg]
  serverChannel: Channel[TransferMsg]
  cancelRequested: Atomic[bool]
  serverStopRequested: Atomic[bool]
  transferParams: TransferParams
  srvParams: ServerParams

clientChannel.open()
serverChannel.open()

# --- Client transfer worker ---
proc transferWorker() {.thread.} =
  {.gcsafe.}:
    let params = transferParams
    var lastBytes: int64 = 0
    let callbacks = TransferCallbacks(
      onProgress: proc(b: int64, t: int64) =
        lastBytes = b
        clientChannel.send(TransferMsg(kind: mkProgress,
                                        bytesTransferred: b, totalBytes: t)),
      onComplete: proc() =
        clientChannel.send(TransferMsg(kind: mkComplete, finalBytes: lastBytes)),
      onError: proc(code: int, msg: string) =
        clientChannel.send(TransferMsg(kind: mkError, errorMsg: msg))
    )
    var req = newTransferRequest(params.host, params.port, params.remoteFile,
                                 params.localFile, params.direction)
    req.options.blocksize = params.blocksize
    let udpTransport = newUdpTransport(ipv6 = isIPv6(params.host))
    defer:
      if udpTransport.close != nil: udpTransport.close()
    discard waitFor executeTransfer(req, callbacks, udpTransport,
      cancelCheck = proc(): bool = cancelRequested.load())

# --- Server worker ---
proc serverWorker() {.thread.} =
  {.gcsafe.}:
    let params = srvParams
    let logOutput: LogOutput = proc(level: LogLevel, msg: string) =
      serverChannel.send(TransferMsg(kind: mkLog,
                                      logMsg: formatLogMessage(level, msg)))
    let logger = newLogger(llInfo, logOutput)
    var config = newDefaultServerConfig(params.rootDir)
    config.listenPort = params.port
    config.writePolicy = params.writePolicy
    config.maxConcurrent = params.maxClients
    let srv = newTftpServer(config, logger = logger)
    let listener = newUdpListener(port = params.port)
    serverChannel.send(TransferMsg(kind: mkLog,
                                    logMsg: "[INFO]  Server started on port " & $params.port))
    # Run until stopped — poll serverStopRequested via a custom check
    # Since server.run is async and blocks, we run it in waitFor
    # and check the stop flag periodically
    proc runUntilStopped() {.async.} =
      srv.running = true
      while srv.running and not serverStopRequested.load():
        var data: seq[byte]
        var clientHost: string
        var clientPort: int
        try:
          (data, clientHost, clientPort) = await listener.recv(500)
        except TransportTimeoutError:
          continue
        if isBroadcastOrMulticast(clientHost): continue
        if srv.activeTransfers >= config.maxConcurrent: continue
        srv.activeTransfers.inc
        asyncCheck srv.handleRequest(data, clientHost, clientPort)
      srv.running = false
      listener.close()
    waitFor runUntilStopped()
    serverChannel.send(TransferMsg(kind: mkLog,
                                    logMsg: "[INFO]  Server stopped"))

proc launchGui*() =
  app.init()

  var window = newWindow("chapulin — TFTP Client & Server")
  window.width = 680
  window.height = 620
  window.minWidth = 620
  window.minHeight = 480

  let rootContainer = newLayoutContainer(Layout_Vertical)
  rootContainer.padding = 12
  rootContainer.spacing = 8
  rootContainer.widthMode = WidthMode_Expand
  rootContainer.heightMode = HeightMode_Expand
  window.add(rootContainer)

  # === Tab buttons ===
  let tabRow = newLayoutContainer(Layout_Horizontal)
  tabRow.spacing = 8
  tabRow.widthMode = WidthMode_Expand
  rootContainer.add(tabRow)
  let clientTabBtn = newButton("    Client    ")
  let serverTabBtn = newButton("    Server    ")
  tabRow.add(clientTabBtn)
  tabRow.add(serverTabBtn)

  # === Client panel ===
  let clientPanel = newLayoutContainer(Layout_Vertical)
  clientPanel.spacing = 8
  clientPanel.padding = 4
  clientPanel.widthMode = WidthMode_Expand
  clientPanel.heightMode = HeightMode_Expand
  rootContainer.add(clientPanel)

  # Connection
  let connRow = newLayoutContainer(Layout_Horizontal)
  connRow.spacing = 8
  connRow.widthMode = WidthMode_Expand
  clientPanel.add(connRow)
  connRow.add(newLabel("Host:"))
  let hostInput = newTextBox("192.168.1.1")
  hostInput.widthMode = WidthMode_Expand
  connRow.add(hostInput)
  connRow.add(newLabel("Port:"))
  let portInput = newTextBox("69")
  portInput.width = 70
  connRow.add(portInput)

  # Remote file
  let fileRow = newLayoutContainer(Layout_Horizontal)
  fileRow.spacing = 8
  fileRow.widthMode = WidthMode_Expand
  clientPanel.add(fileRow)
  fileRow.add(newLabel("Remote file:"))
  let remoteFileInput = newTextBox("")
  remoteFileInput.widthMode = WidthMode_Expand
  fileRow.add(remoteFileInput)

  # Local file
  let localRow = newLayoutContainer(Layout_Horizontal)
  localRow.spacing = 8
  localRow.widthMode = WidthMode_Expand
  clientPanel.add(localRow)
  localRow.add(newLabel("Local file:"))
  let localFileInput = newTextBox("")
  localFileInput.widthMode = WidthMode_Expand
  localRow.add(localFileInput)
  let browseBtn = newButton("Browse...")
  localRow.add(browseBtn)

  # Options
  let optRow = newLayoutContainer(Layout_Horizontal)
  optRow.spacing = 8
  optRow.widthMode = WidthMode_Expand
  clientPanel.add(optRow)
  optRow.add(newLabel("Direction:"))
  let dirCombo = newComboBox(@["GET (Download)", "PUT (Upload)"])
  optRow.add(dirCombo)
  optRow.add(newLabel("Block size:"))
  let bsCombo = newComboBox(@["512", "1024", "1468", "4096", "8192"])
  optRow.add(bsCombo)

  # Client actions
  let clientActionRow = newLayoutContainer(Layout_Horizontal)
  clientActionRow.spacing = 8
  clientActionRow.widthMode = WidthMode_Expand
  clientPanel.add(clientActionRow)
  let startBtn = newButton("Start Transfer")
  startBtn.widthMode = WidthMode_Expand
  clientActionRow.add(startBtn)
  let cancelBtn = newButton("Cancel")
  cancelBtn.enabled = false
  clientActionRow.add(cancelBtn)

  # Progress
  let progressBar = newProgressBar()
  clientPanel.add(progressBar)
  let statusLabel = newLabel("Ready")
  clientPanel.add(statusLabel)

  # Client log
  let clientLog = newTextArea("")
  clientLog.editable = false
  clientLog.heightMode = HeightMode_Expand
  clientLog.minHeight = 150
  clientPanel.add(clientLog)

  # === Server panel (hidden by default) ===
  let serverPanel = newLayoutContainer(Layout_Vertical)
  serverPanel.spacing = 8
  serverPanel.padding = 4
  serverPanel.widthMode = WidthMode_Expand
  serverPanel.heightMode = HeightMode_Expand
  serverPanel.visible = false
  rootContainer.add(serverPanel)

  # Server config
  let srvRow1 = newLayoutContainer(Layout_Horizontal)
  srvRow1.spacing = 8
  srvRow1.widthMode = WidthMode_Expand
  serverPanel.add(srvRow1)
  srvRow1.add(newLabel("Root dir:"))
  let rootDirInput = newTextBox("")
  rootDirInput.widthMode = WidthMode_Expand
  srvRow1.add(rootDirInput)
  let rootBrowseBtn = newButton("Browse...")
  srvRow1.add(rootBrowseBtn)

  let srvRow2 = newLayoutContainer(Layout_Horizontal)
  srvRow2.spacing = 8
  srvRow2.widthMode = WidthMode_Expand
  serverPanel.add(srvRow2)
  srvRow2.add(newLabel("Port:"))
  let srvPortInput = newTextBox("69")
  srvPortInput.width = 70
  srvRow2.add(srvPortInput)
  srvRow2.add(newLabel("Write policy:"))
  let writePolicyCombo = newComboBox(@["deny", "create", "overwrite", "all"])
  srvRow2.add(writePolicyCombo)
  srvRow2.add(newLabel("Max clients:"))
  let maxClientsInput = newTextBox("10")
  maxClientsInput.width = 40
  srvRow2.add(maxClientsInput)

  # Server actions
  let srvActionRow = newLayoutContainer(Layout_Horizontal)
  srvActionRow.spacing = 8
  srvActionRow.widthMode = WidthMode_Expand
  serverPanel.add(srvActionRow)
  let srvStartBtn = newButton("Start Server")
  srvStartBtn.widthMode = WidthMode_Expand
  srvActionRow.add(srvStartBtn)
  let srvStopBtn = newButton("Stop")
  srvStopBtn.enabled = false
  srvActionRow.add(srvStopBtn)

  let srvStatusLabel = newLabel("Server stopped")
  serverPanel.add(srvStatusLabel)

  # Server log
  let serverLog = newTextArea("")
  serverLog.editable = false
  serverLog.heightMode = HeightMode_Expand
  serverLog.minHeight = 200
  serverPanel.add(serverLog)

  # === State ===
  var transferThread: Thread[void]
  var transferActive = false
  var clientStartTime: float = 0.0
  var serverThread: Thread[void]
  var serverActive = false

  proc appendClientLog(msg: string) =
    if clientLog.text.len > 0: clientLog.addLine(msg)
    else: clientLog.text = msg

  proc appendServerLog(msg: string) =
    if serverLog.text.len > 0: serverLog.addLine(msg)
    else: serverLog.text = msg

  proc setTransferring(running: bool) =
    transferActive = running
    startBtn.enabled = not running
    cancelBtn.enabled = running

  # === Tab switching ===
  clientTabBtn.onClick = proc(event: ClickEvent) =
    clientPanel.visible = true
    serverPanel.visible = false

  serverTabBtn.onClick = proc(event: ClickEvent) =
    clientPanel.visible = false
    serverPanel.visible = true

  # === Client browse ===
  browseBtn.onClick = proc(event: ClickEvent) =
    if dirCombo.index == 0:
      let dialog = newSaveFileDialog()
      dialog.title = "Save downloaded file as"
      dialog.run()
      if dialog.file.len > 0: localFileInput.text = dialog.file
    else:
      let dialog = newOpenFileDialog()
      dialog.title = "Select file to upload"
      dialog.run()
      if dialog.files.len > 0: localFileInput.text = dialog.files[0]

  # === Server root browse ===
  rootBrowseBtn.onClick = proc(event: ClickEvent) =
    let dialog = newSelectDirectoryDialog()
    dialog.title = "Select TFTP root directory"
    dialog.run()
    if dialog.selectedDirectory.len > 0:
      rootDirInput.text = dialog.selectedDirectory

  # === Client cancel ===
  cancelBtn.onClick = proc(event: ClickEvent) =
    cancelRequested.store(true)
    appendClientLog("Cancelling transfer...")

  # === Client transfer timer ===
  discard startRepeatingTimer(50, proc(event: TimerEvent) =
    # Poll client channel
    if transferActive:
      var recvResult = clientChannel.tryRecv()
      while recvResult.dataAvailable:
        let msg = recvResult.msg
        case msg.kind
        of mkProgress:
          let elapsed = epochTime() - clientStartTime
          let speed = if elapsed > 0: float(msg.bytesTransferred) / elapsed else: 0.0
          var status = formatBytes(msg.bytesTransferred)
          if msg.totalBytes > 0:
            let pct = float(msg.bytesTransferred) / float(msg.totalBytes)
            progressBar.value = pct
            status &= " / " & formatBytes(msg.totalBytes) &
                      " (" & $(int(pct * 100)) & "%)"
          status &= " | " & formatSpeed(speed)
          statusLabel.text = status
        of mkComplete:
          progressBar.value = 1.0
          let elapsed = epochTime() - clientStartTime
          statusLabel.text = "Transfer complete (" &
            elapsed.formatFloat(ffDecimal, 2) & "s)"
          appendClientLog("Completed: " & formatBytes(msg.finalBytes))
          joinThread(transferThread)
          setTransferring(false)
          return
        of mkError:
          statusLabel.text = "Error: " & msg.errorMsg
          appendClientLog("Error: " & msg.errorMsg)
          joinThread(transferThread)
          setTransferring(false)
          return
        of mkLog:
          appendClientLog(msg.logMsg)
        recvResult = clientChannel.tryRecv()

    # Poll server channel
    if serverActive:
      var recvResult = serverChannel.tryRecv()
      while recvResult.dataAvailable:
        let msg = recvResult.msg
        case msg.kind
        of mkLog:
          appendServerLog(msg.logMsg)
        else:
          discard
        recvResult = serverChannel.tryRecv()
  )

  # === Client start ===
  startBtn.onClick = proc(event: ClickEvent) =
    let host = hostInput.text.strip()
    let portStr = portInput.text.strip()
    let remoteFile = remoteFileInput.text.strip()
    let localFile = localFileInput.text.strip()

    if host.len == 0:
      window.alert("Please enter a host address."); return
    if remoteFile.len == 0:
      window.alert("Please enter a remote filename."); return
    if localFile.len == 0:
      window.alert("Please enter a local file path."); return

    var port: int
    try: port = parseInt(portStr)
    except ValueError: window.alert("Invalid port number."); return

    let blocksize = parseInt(bsCombo.options[bsCombo.index])
    let direction = if dirCombo.index == 0: tdGet else: tdPut

    if direction == tdPut and not fileExists(localFile):
      window.alert("Local file not found: " & localFile); return

    transferParams = TransferParams(
      host: host, port: port, remoteFile: remoteFile,
      localFile: localFile, direction: direction, blocksize: blocksize)

    cancelRequested.store(false)
    clientStartTime = epochTime()
    progressBar.value = 0.0
    setTransferring(true)

    let dirStr = if direction == tdGet: "GET" else: "PUT"
    appendClientLog(dirStr & " " & remoteFile & " " &
      (if direction == tdGet: "from " else: "to ") & host & ":" & $port)

    createThread(transferThread, transferWorker)

  # === Server start ===
  srvStartBtn.onClick = proc(event: ClickEvent) =
    let rootDir = rootDirInput.text.strip()
    if rootDir.len == 0:
      window.alert("Please select a root directory."); return
    if not dirExists(rootDir):
      window.alert("Directory not found: " & rootDir); return

    var port: int
    try: port = parseInt(srvPortInput.text.strip())
    except ValueError: window.alert("Invalid port."); return

    var maxClients: int
    try: maxClients = parseInt(maxClientsInput.text.strip())
    except ValueError: window.alert("Invalid max clients."); return

    let wp = case writePolicyCombo.index
      of 0: wpDeny
      of 1: wpCreateOnly
      of 2: wpOverwrite
      of 3: wpCreateOrOverwrite
      else: wpDeny

    srvParams = ServerParams(
      rootDir: rootDir, port: port, writePolicy: wp, maxClients: maxClients)

    serverStopRequested.store(false)
    serverActive = true
    srvStartBtn.enabled = false
    srvStopBtn.enabled = true
    srvStatusLabel.text = "Server running on port " & $port
    appendServerLog("Starting server...")

    createThread(serverThread, serverWorker)

  # === Server stop ===
  srvStopBtn.onClick = proc(event: ClickEvent) =
    serverStopRequested.store(true)
    srvStopBtn.enabled = false
    srvStatusLabel.text = "Stopping..."
    appendServerLog("Stopping server...")
    # Server thread will exit and post a log message

  # === Server stop completion (check in timer) ===
  discard startRepeatingTimer(500, proc(event: TimerEvent) =
    if serverActive and serverStopRequested.load():
      # Check if server thread finished
      try:
        joinThread(serverThread)
        serverActive = false
        srvStartBtn.enabled = true
        srvStopBtn.enabled = false
        srvStatusLabel.text = "Server stopped"
      except:
        discard  # not finished yet
  )

  window.show()
  app.run()
