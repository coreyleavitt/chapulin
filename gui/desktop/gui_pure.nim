## Pure, display-free, oyamel-free helpers for the desktop GUI.
##
## These are the pieces of the port worth unit-testing on their own (RFC
## gui-oyamel-port.md §4.3/§4.5): status-line formatting, the comboBox index
## guards, and client-form validation + request building. Importing this pulls
## in NO GUI backend, so tests/t_gui_pure.nim builds it in the dev-test
## container without oyamel. The impure counterparts (widget reads, the
## fileExists check, showMessage) stay in chapulin_gui.nim.

import std/[strutils, options]
import ../../src/chapulin/api

const Blocksizes* = [512, 1024, 1468, 4096, 8192]
  ## The client block-size combo, in order (predecessor parity).

proc blocksizeFor*(index: int): int =
  ## Map a comboBox selectedIndex to a block size, guarding the -1 "no
  ## selection" default (oyamel defaults comboBox selectedIndex to -1, and
  ## `Blocksizes[-1]` is a fatal IndexDefect). Out-of-range falls back to the
  ## first entry.
  if index >= 0 and index < Blocksizes.len: Blocksizes[index] else: Blocksizes[0]

proc progressText*(snap: TransferSnapshot; elapsed: float): string =
  ## The client status line, matching the predecessor format for parity:
  ##   "<bytes>[ / <total> (<pct>%)] | <speed>"
  ## Pure: no widget access, no oyamel. `snap.total.get(0)` is belt-and-
  ## suspenders (the segment is only built when `fraction` isSome, which implies
  ## total isSome), guarding the never-throw boundary per §4.8.
  let f = fraction(snap.bytes, snap.total)
  let speed = if elapsed > 0.0: float(snap.bytes) / elapsed else: 0.0
  result = formatBytes(snap.bytes)
  if f.isSome:
    result &= " / " & formatBytes(snap.total.get(0)) &
              " (" & $(int(f.get * 100.0)) & "%)"
  result &= " | " & formatSpeed(speed)

type
  ClientForm* = object
    ## The client panel's inputs as a plain record. The GUI's `readClientForm`
    ## does the impure widget reads and produces this; `parseClientForm`
    ## consumes it. Kept separate so validation is pure and testable.
    host*: string
    portStr*: string
    remoteFile*: string
    localFile*: string
    directionIndex*: int   ## 0 = GET, 1 = PUT
    blocksizeIndex*: int
  ClientFormResult* = object
    ok*: bool
    req*: TransferRequest
    err*: string           ## "" iff ok

proc parseClientForm*(f: ClientForm): ClientFormResult =
  ## Validate the form and build a TransferRequest. Pure and display-free:
  ## returns an error message, never shows a dialog. The PUT `fileExists` check
  ## stays in the caller (it touches the filesystem). Notice order matches the
  ## predecessor version so the parity checklist holds.
  let host = f.host.strip()
  let remoteFile = f.remoteFile.strip()
  let localFile = f.localFile.strip()
  if host.len == 0:
    return ClientFormResult(ok: false, err: "Please enter a host address.")
  if remoteFile.len == 0:
    return ClientFormResult(ok: false, err: "Please enter a remote filename.")
  if localFile.len == 0:
    return ClientFormResult(ok: false, err: "Please enter a local file path.")
  var port: int
  try:
    port = parseInt(f.portStr.strip())
  except ValueError:
    return ClientFormResult(ok: false, err: "Invalid port number.")
  let direction = if f.directionIndex == 0: tdGet else: tdPut
  var req = newTransferRequest(host, port, remoteFile, localFile, direction)
  req.options.blocksize = blocksizeFor(f.blocksizeIndex)
  ClientFormResult(ok: true, req: req, err: "")

# ---------------------------------------------------------------------------
# Server form validation (RFC gui-oyamel-port.md §4.5/§4.6, slice 3)
# ---------------------------------------------------------------------------

proc writePolicyFor*(index: int): WritePolicy =
  ## Map the write-policy comboBox's selectedIndex to a WritePolicy (predecessor
  ## parity order: deny/create/overwrite/all). Out-of-range (including the -1
  ## "no selection" default) falls back to the safe default, wpDeny.
  case index
  of 0: wpDeny
  of 1: wpCreateOnly
  of 2: wpOverwrite
  of 3: wpCreateOrOverwrite
  else: wpDeny

type
  ServerForm* = object
    ## The server panel's inputs as a plain record, mirroring ClientForm.
    rootDir*: string
    portStr*: string
    maxClientsStr*: string
    writePolicyIndex*: int
  ServerFormResult* = object
    ok*: bool
    rootDir*: string
    port*: int
    maxClients*: int
    writePolicy*: WritePolicy
    err*: string           ## "" iff ok

proc parseServerForm*(f: ServerForm): ServerFormResult =
  ## Validate the server form. Pure and display-free: no `dirExists` (that
  ## touches the filesystem and stays in wireServer) and no `newServerConfig`
  ## (that builds the real ServerConfig and stays in wireServer too). Notice
  ## order matches the predecessor version so the parity checklist holds.
  let rootDir = f.rootDir.strip()
  if rootDir.len == 0:
    return ServerFormResult(ok: false, err: "Please select a root directory.")
  var port: int
  try:
    port = parseInt(f.portStr.strip())
  except ValueError:
    return ServerFormResult(ok: false, err: "Invalid port.")
  var maxClients: int
  try:
    maxClients = parseInt(f.maxClientsStr.strip())
  except ValueError:
    return ServerFormResult(ok: false, err: "Invalid max clients.")
  ServerFormResult(ok: true, rootDir: rootDir, port: port, maxClients: maxClients,
                   writePolicy: writePolicyFor(f.writePolicyIndex), err: "")
