## chapulin NiGui desktop GUI — client and server with log viewer
## Layout follows NiCalc pattern: no explicit widthMode/heightMode on containers,
## TextBoxes expand by default, labels use minWidth for alignment.

import nigui
import std/os
import std/strutils
import std/times
import ../../src/chapulin/api

const LabelWidth = 80

proc launchGui*() =
  let session = newSession()  # default minLogLevel = llInfo (resolved in api.nim's scope)

  app.init()

  var window = newWindow("chapulin")
  window.width = 680
  window.height = 580

  let mainContainer = newLayoutContainer(Layout_Vertical)
  mainContainer.padding = 8
  mainContainer.spacing = 6
  window.add(mainContainer)

  # === Tab buttons ===
  let tabRow = newLayoutContainer(Layout_Horizontal)
  tabRow.spacing = 8
  mainContainer.add(tabRow)
  let clientTabBtn = newButton("    Client    ")
  let serverTabBtn = newButton("    Server    ")
  tabRow.add(clientTabBtn)
  tabRow.add(serverTabBtn)

  # === Client panel ===
  let clientPanel = newLayoutContainer(Layout_Vertical)
  clientPanel.spacing = 6
  mainContainer.add(clientPanel)

  # Connection
  let connRow = newLayoutContainer(Layout_Horizontal)
  connRow.spacing = 6
  clientPanel.add(connRow)
  let hostLabel = newLabel("Host:")
  hostLabel.minWidth = LabelWidth
  hostLabel.heightMode = HeightMode_Fill
  connRow.add(hostLabel)
  let hostInput = newTextBox("192.168.1.1")
  connRow.add(hostInput)
  let portLabel = newLabel("Port:")
  portLabel.heightMode = HeightMode_Fill
  connRow.add(portLabel)
  let portInput = newTextBox("69")
  portInput.width = 65
  connRow.add(portInput)

  # Remote file
  let fileRow = newLayoutContainer(Layout_Horizontal)
  fileRow.spacing = 6
  clientPanel.add(fileRow)
  let remoteLabel = newLabel("Remote file:")
  remoteLabel.minWidth = LabelWidth
  remoteLabel.heightMode = HeightMode_Fill
  fileRow.add(remoteLabel)
  let remoteFileInput = newTextBox("")
  fileRow.add(remoteFileInput)

  # Local file
  let localRow = newLayoutContainer(Layout_Horizontal)
  localRow.spacing = 6
  clientPanel.add(localRow)
  let localLabel = newLabel("Local file:")
  localLabel.minWidth = LabelWidth
  localLabel.heightMode = HeightMode_Fill
  localRow.add(localLabel)
  let localFileInput = newTextBox("")
  localRow.add(localFileInput)
  let browseBtn = newButton("Browse...")
  browseBtn.heightMode = HeightMode_Fill
  localRow.add(browseBtn)

  # Options
  let optRow = newLayoutContainer(Layout_Horizontal)
  optRow.spacing = 6
  clientPanel.add(optRow)
  let dirLabel = newLabel("Direction:")
  dirLabel.minWidth = LabelWidth
  dirLabel.heightMode = HeightMode_Fill
  optRow.add(dirLabel)
  let dirCombo = newComboBox(@["GET (Download)", "PUT (Upload)"])
  optRow.add(dirCombo)
  let bsLabel = newLabel("Block size:")
  bsLabel.heightMode = HeightMode_Fill
  optRow.add(bsLabel)
  let bsCombo = newComboBox(@["512", "1024", "1468", "4096", "8192"])
  optRow.add(bsCombo)

  # Client actions
  let clientActionRow = newLayoutContainer(Layout_Horizontal)
  clientActionRow.spacing = 6
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
  clientPanel.add(clientLog)

  # === Server panel (hidden by default) ===
  let serverPanel = newLayoutContainer(Layout_Vertical)
  serverPanel.spacing = 6
  serverPanel.visible = false
  mainContainer.add(serverPanel)

  # Server root dir
  let srvRow1 = newLayoutContainer(Layout_Horizontal)
  srvRow1.spacing = 6
  serverPanel.add(srvRow1)
  let rootDirLabel = newLabel("Root dir:")
  rootDirLabel.minWidth = LabelWidth
  rootDirLabel.heightMode = HeightMode_Fill
  srvRow1.add(rootDirLabel)
  let rootDirInput = newTextBox("")
  srvRow1.add(rootDirInput)
  let rootBrowseBtn = newButton("Browse...")
  rootBrowseBtn.heightMode = HeightMode_Fill
  srvRow1.add(rootBrowseBtn)

  # Server options
  let srvRow2 = newLayoutContainer(Layout_Horizontal)
  srvRow2.spacing = 6
  serverPanel.add(srvRow2)
  let srvPortLabel = newLabel("Port:")
  srvPortLabel.minWidth = LabelWidth
  srvPortLabel.heightMode = HeightMode_Fill
  srvRow2.add(srvPortLabel)
  let srvPortInput = newTextBox("69")
  srvPortInput.width = 65
  srvRow2.add(srvPortInput)
  let wpLabel = newLabel("Write policy:")
  wpLabel.heightMode = HeightMode_Fill
  srvRow2.add(wpLabel)
  let writePolicyCombo = newComboBox(@["deny", "create", "overwrite", "all"])
  srvRow2.add(writePolicyCombo)
  let mcLabel = newLabel("Max:")
  mcLabel.heightMode = HeightMode_Fill
  srvRow2.add(mcLabel)
  let maxClientsInput = newTextBox("10")
  maxClientsInput.width = 40
  srvRow2.add(maxClientsInput)

  # Server actions
  let srvActionRow = newLayoutContainer(Layout_Horizontal)
  srvActionRow.spacing = 6
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
  serverPanel.add(serverLog)

  # === State ===
  var transferActive = false
  var clientStartTime: float = 0.0
  var serverActive = false
  var clientXferId: TransferId = NoTransfer
  var serverId: ServerId = NoServer

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
    session.cancel(clientXferId)
    appendClientLog("Cancelling transfer...")

  # === Single 50 ms timer: pump session events for both client and server ===
  discard startRepeatingTimer(50, proc(event: TimerEvent) =
    for ev in session.poll(0):
      case ev.kind
      of evTransferStarted:
        # Server-side: a new incoming transfer was accepted.
        if ev.srvId != NoServer:
          let dirStr = if ev.snap.direction == tdGet: "RRQ" else: "WRQ"
          appendServerLog("Incoming transfer started (" & dirStr & ")")
        # Client-side: no additional UI action needed; startTransfer already logged.

      of evTransferProgress:
        if ev.srvId == NoServer and ev.xfrId == clientXferId:
          # Client transfer progress: update progress bar and status label.
          let f = fraction(ev.snap.bytes, ev.snap.total)
          if f.isSome:
            progressBar.value = f.get
          let elapsed = epochTime() - clientStartTime
          let speed = if elapsed > 0.0: float(ev.snap.bytes) / elapsed else: 0.0
          var status = formatBytes(ev.snap.bytes)
          if f.isSome:
            status &= " / " & formatBytes(ev.snap.total.get) &
                      " (" & $(int(f.get * 100.0)) & "%)"
          status &= " | " & formatSpeed(speed)
          statusLabel.text = status
        elif ev.srvId != NoServer:
          # Server-side per-transfer progress: show in server log.
          let f = fraction(ev.snap.bytes, ev.snap.total)
          var line = "Transfer progress: " & formatBytes(ev.snap.bytes)
          if f.isSome:
            line &= " (" & $(int(f.get * 100.0)) & "%)"
          appendServerLog(line)

      of evTransferComplete:
        if ev.srvId == NoServer and ev.xfrId == clientXferId:
          progressBar.value = 1.0
          let elapsed = epochTime() - clientStartTime
          statusLabel.text = "Transfer complete (" &
            elapsed.formatFloat(ffDecimal, 2) & "s)"
          appendClientLog("Completed: " & formatBytes(ev.snap.bytes))
          setTransferring(false)
        elif ev.srvId != NoServer:
          appendServerLog("Transfer complete: " & formatBytes(ev.snap.bytes))

      of evTransferError:
        if ev.srvId == NoServer and ev.xfrId == clientXferId:
          statusLabel.text = "Error: " & sanitizeForDisplay(ev.errorMsg)
          appendClientLog("Error: " & sanitizeForDisplay(ev.errorMsg))
          setTransferring(false)
        elif ev.srvId != NoServer:
          appendServerLog("Transfer error: " & sanitizeForDisplay(ev.errorMsg))

      of evTransferLog:
        if ev.srvId != NoServer:
          appendServerLog("[" & $ev.xLevel & "] " & ev.xMessage)
        else:
          appendClientLog("[" & $ev.xLevel & "] " & ev.xMessage)

      of evServerLog:
        appendServerLog("[" & $ev.sLevel & "] " & ev.sMessage)

      of evServerStarted:
        srvStatusLabel.text = "Server running on " & ev.boundAddr & ":" & $ev.boundPort

      of evServerStartFailed:
        window.alert("Server failed to start: " & ev.startErr)
        serverActive = false
        srvStartBtn.enabled = true
        srvStopBtn.enabled = false
        srvStatusLabel.text = "Server stopped"

      of evServerStopped:
        serverActive = false
        srvStartBtn.enabled = true
        srvStopBtn.enabled = false
        srvStatusLabel.text = "Server stopped"
        appendServerLog("Server stopped")
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

    var req = newTransferRequest(host, port, remoteFile, localFile, direction)
    req.options.blocksize = blocksize

    clientStartTime = epochTime()
    progressBar.value = 0.0
    setTransferring(true)

    let dirStr = if direction == tdGet: "GET" else: "PUT"
    appendClientLog(dirStr & " " & remoteFile & " " &
      (if direction == tdGet: "from " else: "to ") & host & ":" & $port)

    clientXferId = session.startTransfer(req)

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

    var config = newDefaultServerConfig(rootDir)
    config.listenPort = port
    config.writePolicy = wp
    config.maxConcurrent = maxClients

    serverActive = true
    srvStartBtn.enabled = false
    srvStopBtn.enabled = true
    appendServerLog("Starting server...")

    serverId = session.startServer(config)

  # === Server stop ===
  srvStopBtn.onClick = proc(event: ClickEvent) =
    session.stop(serverId)
    srvStopBtn.enabled = false
    srvStatusLabel.text = "Stopping..."

  window.show()
  app.run()
  # Note: no session.close() on exit.  NiGui has no window-close hook accessible
  # here (app.run() returns only after the window is destroyed), and pumping
  # poll() after that point would stall on the OS poller with no running event
  # loop.  For TFTP this is acceptable: transfers are short-lived and the process
  # exits immediately, releasing all OS resources.
