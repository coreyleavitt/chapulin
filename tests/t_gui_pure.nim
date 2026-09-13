## Unit tests for the desktop GUI's pure helpers (gui/desktop/gui_pure.nim) --
## the oyamel-free, display-free pieces of the port worth testing on their own
## (RFC gui-oyamel-port.md §4.3/§4.5, §7 tier 1). Runs in the dev-test
## container with NO GUI backend.
##
##   docker run --rm -v ${PWD}:C:\app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r tests/t_gui_pure.nim

import std/[unittest, options]
import ../src/chapulin/api
import ../gui/desktop/gui_pure

suite "gui_pure: progressText (client status line, NiGui parity)":
  test "mid-transfer with known total: bytes / total (pct) | speed":
    let snap = TransferSnapshot(bytes: 512, total: some(1024'i64))
    # "0." B/s (not "0") is formatSpeed(0.0)'s ffDecimal-0 output -- matched here
    # because parity means reproducing the NiGui status string exactly.
    check progressText(snap, 0.0) == "512 B / 1.0 KB (50%) | 0. B/s"

  test "unknown total omits the ' / total (pct)' segment":
    let snap = TransferSnapshot(bytes: 512, total: none(int64))
    check progressText(snap, 0.0) == "512 B | 0. B/s"

  test "nonzero elapsed yields a real speed":
    let snap = TransferSnapshot(bytes: 1024, total: some(2048'i64))
    check progressText(snap, 1.0) == "1.0 KB / 2.0 KB (50%) | 1.0 KB/s"

suite "gui_pure: blocksizeFor (comboBox index guard)":
  test "each index maps to the parity block size in order":
    check blocksizeFor(0) == 512
    check blocksizeFor(1) == 1024
    check blocksizeFor(2) == 1468
    check blocksizeFor(3) == 4096
    check blocksizeFor(4) == 8192

  test "the -1 'no selection' default falls back to the first entry":
    check blocksizeFor(-1) == 512

  test "an out-of-range index falls back rather than IndexDefect-ing":
    check blocksizeFor(99) == 512

suite "gui_pure: parseClientForm (pure validation + request build)":
  proc validForm(): ClientForm =
    ClientForm(host: "192.168.1.1", portStr: "69", remoteFile: "fw.bin",
               localFile: "out.bin", directionIndex: 0, blocksizeIndex: 1)

  test "a valid GET form builds the request with the chosen block size":
    let r = parseClientForm(validForm())
    check r.ok
    check r.err == ""
    check r.req.host == "192.168.1.1"
    check r.req.port == 69
    check r.req.filename == "fw.bin"
    check r.req.localPath == "out.bin"
    check r.req.direction == tdGet
    check r.req.options.blocksize == 1024

  test "directionIndex 1 selects PUT":
    var f = validForm()
    f.directionIndex = 1
    let r = parseClientForm(f)
    check r.ok
    check r.req.direction == tdPut

  test "empty host is rejected with the host notice":
    var f = validForm()
    f.host = "   "
    let r = parseClientForm(f)
    check not r.ok
    check r.err == "Please enter a host address."

  test "empty remote filename is rejected":
    var f = validForm()
    f.remoteFile = ""
    let r = parseClientForm(f)
    check not r.ok
    check r.err == "Please enter a remote filename."

  test "empty local path is rejected":
    var f = validForm()
    f.localFile = ""
    let r = parseClientForm(f)
    check not r.ok
    check r.err == "Please enter a local file path."

  test "a non-numeric port is rejected rather than silently defaulted":
    var f = validForm()
    f.portStr = "not-a-port"
    let r = parseClientForm(f)
    check not r.ok
    check r.err == "Invalid port number."
