## Public API — the stable contract that CLI and GUI frontends consume.
## No frontend should import protocol or engine directly.

import std/asyncdispatch
import engine
import protocol
export Transport, CancelCheck, TransportTimeoutError, TransportCloseProc,
       TransferResult, ProgressCallback, DefaultBlocksize, DefaultTimeout,
       DefaultRetries, MinBlocksize, MaxBlocksize, validateBlocksize,
       TransferMode
import std/os

type
  TransferDirection* = enum
    tdGet
    tdPut

  TransferOptions* = object
    blocksize*: int
    timeout*: int
    retries*: int
    windowsize*: int
    mode*: TransferMode

  TransferRequest* = object
    host*: string
    port*: int
    filename*: string
    localPath*: string
    direction*: TransferDirection
    options*: TransferOptions

  OnProgress* = proc(bytesTransferred: int64, totalBytes: int64) {.closure.}
  OnError* = proc(code: int, msg: string) {.closure.}
  OnComplete* = proc() {.closure.}

  TransferCallbacks* = object
    onProgress*: OnProgress
    onError*: OnError
    onComplete*: OnComplete

proc newTransferRequest*(host: string, port: int, filename: string,
                         localPath: string, direction: TransferDirection): TransferRequest =
  TransferRequest(
    host: host, port: port, filename: filename,
    localPath: localPath, direction: direction,
    options: TransferOptions(blocksize: DefaultBlocksize, timeout: DefaultTimeout,
                             retries: DefaultRetries, windowsize: DefaultWindowsize,
                             mode: tmOctet)
  )

proc failResult(msg: string): TransferResult =
  TransferResult(success: false, bytesTransferred: 0, errorMsg: msg, totalSize: -1)

proc executeTransfer*(req: TransferRequest, callbacks: TransferCallbacks,
                      transport: Transport,
                      cancelCheck: CancelCheck = nil): Future[TransferResult] {.async.} =
  var config = TftpClientConfig(
    timeout: req.options.timeout,
    retries: req.options.retries,
    blocksize: validateBlocksize(req.options.blocksize),
    windowsize: max(MinWindowsize, min(MaxWindowsize, req.options.windowsize)),
    mode: req.options.mode,
    requestTsize: true,
    tsize: -1
  )

  case req.direction
  of tdGet:
    var file: File
    var fileOpened = false
    var writeError = ""
    defer:
      if fileOpened: file.close()

    let onData = proc(blockNum: uint16, data: seq[byte]) =
      if writeError.len > 0: return
      if not fileOpened:
        try:
          file = open(req.localPath, fmWrite)
          fileOpened = true
        except IOError as e:
          writeError = "Cannot open file for writing: " & e.msg
          return
      if data.len > 0:
        let written = file.writeBytes(data, 0, data.len)
        if written != data.len:
          writeError = "Write failed: wrote " & $written & " of " & $data.len & " bytes"

    let combinedCancel: CancelCheck = proc(): bool =
      writeError.len > 0 or (cancelCheck != nil and cancelCheck())

    result = await getFile(transport, config, req.host, req.port, req.filename,
                           onData, callbacks.onProgress, combinedCancel)

    if writeError.len > 0:
      result = failResult(writeError)

    if result.success:
      if callbacks.onComplete != nil: callbacks.onComplete()
    else:
      if callbacks.onError != nil: callbacks.onError(result.errorCode, result.errorMsg)

  of tdPut:
    var file: File
    try:
      file = open(req.localPath, fmRead)
    except IOError as e:
      result = failResult("Cannot open file for reading: " & e.msg)
      if callbacks.onError != nil: callbacks.onError(result.errorCode, result.errorMsg)
      return
    defer: file.close()

    let fileSize = getFileSize(req.localPath)
    config.tsize = fileSize

    var blockCache: seq[byte]
    var cachedBlock: uint16 = 0

    let readData = proc(blockNum: uint16, blocksize: int): seq[byte] =
      if blockNum == cachedBlock: return blockCache
      let offset = int64(blockNum - 1) * int64(blocksize)
      file.setFilePos(offset)
      var buf = newSeq[byte](blocksize)
      let bytesRead = file.readBytes(buf, 0, blocksize)
      buf.setLen(bytesRead)
      blockCache = buf
      cachedBlock = blockNum
      return buf

    let progressCb: ProgressCallback = if callbacks.onProgress != nil:
      proc(bytesTransferred: int64, totalSize: int64) =
        callbacks.onProgress(bytesTransferred, fileSize)
    else:
      nil

    result = await putFile(transport, config, req.host, req.port, req.filename,
                           readData, progressCb, cancelCheck)

    if result.success:
      if callbacks.onComplete != nil: callbacks.onComplete()
    else:
      if callbacks.onError != nil: callbacks.onError(result.errorCode, result.errorMsg)
