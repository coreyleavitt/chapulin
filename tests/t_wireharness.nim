## Smoke tests for the wireharness substrate helpers added in slice 0c:
## makeListener / newListenerQueue and makeFailingTransport.
##
## Run in the nim devtools container:
##   docker run --rm -v ${PWD}:/app -w /app ghcr.io/coreyleavitt/nim:2.2.10 \
##     nim c -r --hints:off tests/t_wireharness.nim

import std/[asyncdispatch, unittest]
import ../src/chapulin/transfer
import ./wireharness

suite "wireharness substrate (slice 0c)":

  test "makeListener delivers queued requests in FIFO order":
    let q = newListenerQueue()
    q.push(@[byte 1, 2, 3], "host-a", 1234)
    q.push(@[byte 4, 5],    "host-b", 5678)
    let listener = makeListener(q)
    let r1 = waitFor listener.recv(1000)
    check r1.data == @[byte 1, 2, 3]
    check r1.host == "host-a"
    check r1.port == 1234
    let r2 = waitFor listener.recv(1000)
    check r2.data == @[byte 4, 5]
    check r2.host == "host-b"
    check r2.port == 5678

  test "makeListener raises TransportTimeoutError when queue is empty":
    let q = newListenerQueue()
    let listener = makeListener(q)
    expect TransportTimeoutError:
      discard waitFor listener.recv(1000)

  test "makeFailingTransport: first N sends succeed, subsequent sends raise OSError":
    let w = newWire()
    let t = makeFailingTransport(w, sideA = true, failAfter = 1)
    # First send (count 1 <= failAfter 1) must succeed
    waitFor t.send(@[byte 0x01, 0x02], "peer", 69)
    # Second send (count 2 > failAfter 1) must raise OSError
    var caught = false
    try:
      waitFor t.send(@[byte 0x03, 0x04], "peer", 69)
    except OSError:
      caught = true
    check caught
