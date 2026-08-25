## A1a-i (RFC verification-harness-v2.md §3.1 "Listener seam" piece (a),
## §5 slice A1a-i): the per-ephemeral-port Wire registry + minting
## transportFactory. Unit-tested ALONE -- no listener bridge (A1a-ii), no
## client port-adoption (A1a-ii), no file dependency (A1b). This slice proves
## only that N successive factory calls mint N independently-addressable
## Wires with no collision, each minted Transport bound to its own Wire.
##
## CRITICAL degeneracy this guards (architect r2): a `Table[port, Wire]`
## keyed on the factory's `port` arg collapses to ONE entry under the default
## server config -- with no portRange set (server_config.nim
## portRangeStart/End = 0, hasPortRange() false), allocateTransferTransport
## calls transferFactory(0) for EVERY transfer (server.nim), so every key is
## 0. The registry uses the proven call-order index (t_session.nim:455-464
## `wireIdx`) instead, so port is never a key.

import std/unittest
import ./wireharness
import ../src/chapulin/transfer  # Transport

suite "A1a-i: minting Wire registry":
  test "N factory calls all made with port 0 still mint N distinct Wires":
    # The degenerate server case: transferFactory(0) called for every
    # transfer. A port-keyed table would collapse to one entry; the
    # call-order registry must not.
    let reg = newWireRegistry()
    let factory = reg.factory()
    const N = 5
    var transports: seq[Transport]
    for _ in 0 ..< N:
      transports.add factory("peer", 0)   # port 0 EVERY call -- the degeneracy

    check reg.wires.len == N
    # All distinct refs (independently addressable).
    for i in 0 ..< N:
      for j in i + 1 ..< N:
        check reg.wires[i] != reg.wires[j]

  test "each minted Transport is wired to its own Wire (no crosstalk)":
    let reg = newWireRegistry()
    let factory = reg.factory()
    const N = 4
    var transports: seq[Transport]
    for _ in 0 ..< N:
      transports.add factory("peer", 0)

    # Send one distinct packet through each transport. `makeTransport`'s
    # doSend runs synchronously up to its (absent) first await, so
    # wireSend -> w.aLog.add fires immediately; no polling needed. If any two
    # transports shared a Wire, that Wire's aLog would carry 2 entries and
    # another 0.
    for k in 0 ..< N:
      discard transports[k].send(@[byte(k)], WirePeerHost, WirePeerPort)

    for k in 0 ..< N:
      check reg.wires[k].aLog.len == 1
      check reg.wires[k].aLog[0] == @[byte(k)]
