## Shared hostile-injection rule builders (RFC verification-harness-v2.md
## §3.1/§5, slice "A-shared"). Extracted from t_hostile.nim (RFC
## verification-harness.md D8a/D8b, slices 7/8) so the SAME forged/garbage/
## off-TID DATA/ACK/ERROR/garbage rule shapes can drive a proptest
## `StateMachine[S]` over ANY state `S` that exposes one live `Wire` --
## t_hostile's bare `sendBlocks`/`recvBlocks` pair today, and v2 Part A's
## facade `TftpSession` stateful target tomorrow (A2/A3) -- without either
## duplicating ~150 lines of rule-building code (extract, don't duplicate)
## or forcing t_hostile.nim to depend on the facade harness's state type, or
## vice versa (extract, don't absorb -- t_hostile keeps its own independent
## value isolating transfer.nim without the full session stack).
##
## Two families:
##   - same-TID (D8a): mkInjectData / mkInjectAck / mkInjectError / mkInjectGarbage
##   - off-TID  (D8b): mkInjectOffTidData / ...Ack / ...Error / ...Garbage
##     (extra attacker (host, port), drawn from `AttackerHosts`/`attackerAddr`)
##
## Every builder is parameterized over:
##   wireOf: S -> Wire          -- projects the one live Wire out of a
##     caller's state. Correct for a single-Wire target (t_hostile's
##     HostileState today; Part A's A1b/A2/A3 tomorrow, one session pair per
##     example) -- it deliberately does NOT generalize to A4's N-Wire
##     registry, which is out of scope for this module (RFC §3.1).
##   notify: (S, bool) -> void  -- READ-ONLY in `S`: this parameter is a
##     plain, non-`var` `S`, so a `notify` closure's body can inspect `s`
##     (typically a liveness check against a Wire/Future) but the compiler
##     rejects any attempt to assign through it. A caller bumps its OWN
##     external counter (a `VacuityCounter` or otherwise) from inside
##     `notify` -- so t_hostile's original informal "injection never
##     mutates state beyond the wire + counter" comment becomes a
##     compiler-enforced property here, not a review convention. `toClient`
##     is the same injection-direction flag the rule itself received; ports
##     to this module's callers that don't key on direction (none of the
##     eight builders below do) simply ignore it, same as t_hostile's
##     original `noteD8aLiveInjection`/`noteD8bLiveInjection`.
##   invert: bool = false (A3 addition, verification-harness-v2.md slice A3)
##     -- every builder forwards `toClient` STRAIGHT to
##     `wireharness.injectPacket`'s `toSideA` parameter, so the rule's
##     printed name ("-> client"/"-> server") is only accurate when a
##     caller's `wireOf` happens to return a Wire where side A IS the
##     client -- true for `t_hostile.nim`'s bare `HostileState`
##     (`clientT = makeTransport(w, sideA = true)`). It is FALSE for Part
##     A's facade per-transfer Wire (`wireharness.WireRegistry.factory()`
##     mints the SERVER's transport with `sideA = true` -- reused as-is
##     from A1a-i/A1b/A2 -- while `makeAdoptingTransport` hard-codes the
##     CLIENT's adopted transport to `sideA = false`; discovered wiring a
##     fact, not a choice, at A3 time). Passing `invert = true` flips the
##     physical `toSideA` sent to `injectPacket` (`toClient != invert`,
##     i.e. XOR) while leaving the rule's *name* keyed on the logical
##     `toClient` the caller asked for -- so "inject DATA -> client" always
##     means "the client's `recv` will see this," on ANY target's Wire
##     side convention, not just t_hostile's. Default `false` is a pure
##     no-op for every existing caller (t_hostile.nim needs no changes).
##
## Each rule's own execute body only ever touches the wire (via `wireOf`)
## and calls `notify` -- never anything else in `s` -- so the read-only
## `notify` signature isn't decoration: nothing in this module can mutate
## `S` at all.

import nelli
import ../src/chapulin/protocol
import ./wireharness
import ./fuzzsupport

type
  WireOf*[S] = proc(s: S): Wire {.closure.}
    ## Projects the single live Wire out of a stateful target's state.
  NotifyInject*[S] = proc(s: S, toClient: bool) {.closure.}
    ## Read-only observer -- see the module doc comment above.

# ---------------------------------------------------------------------------
# Same-TID family (D8a) -- forged/garbage packets carrying the SAME source
# address every legitimate packet does (wireharness.WirePeerHost/Port).
# ---------------------------------------------------------------------------

proc mkInjectData*[S](toClient: bool, wireOf: WireOf[S],
                      notify: NotifyInject[S], invert: bool = false): Rule[S] =
  let strat = integers(0, 65535).flatMap(proc(b: int): Strategy[(int, seq[byte])] =
    byteSeqs(300).map(proc(d: seq[byte]): (int, seq[byte]) = (b, d)))
  rule(
    (if toClient: "inject DATA -> client" else: "inject DATA -> server"),
    strat,
    proc(s: var S, args: (int, seq[byte])) =
      notify(s, toClient)
      let pkt = TftpPacket(opcode: opData, blockNum: uint16(args[0]), data: args[1])
      wireOf(s).injectPacket(toClient != invert, encode(pkt)))

proc mkInjectAck*[S](toClient: bool, wireOf: WireOf[S],
                     notify: NotifyInject[S], invert: bool = false): Rule[S] =
  rule(
    (if toClient: "inject ACK -> client" else: "inject ACK -> server"),
    integers(0, 65535),
    proc(s: var S, b: int) =
      notify(s, toClient)
      let pkt = TftpPacket(opcode: opAck, ackBlockNum: uint16(b))
      wireOf(s).injectPacket(toClient != invert, encode(pkt)))

proc mkInjectError*[S](toClient: bool, wireOf: WireOf[S],
                       notify: NotifyInject[S], invert: bool = false): Rule[S] =
  let strat = integers(0, 8).flatMap(proc(c: int): Strategy[(int, string)] =
    safeStrings(0, 16).map(proc(m: string): (int, string) = (c, m)))
  rule(
    (if toClient: "inject ERROR -> client" else: "inject ERROR -> server"),
    strat,
    proc(s: var S, args: (int, string)) =
      notify(s, toClient)
      let pkt = TftpPacket(opcode: opError, errorCode: TftpErrorCode(args[0]),
                            errorMsg: args[1])
      wireOf(s).injectPacket(toClient != invert, encode(pkt)))

proc mkInjectGarbage*[S](toClient: bool, wireOf: WireOf[S],
                         notify: NotifyInject[S], invert: bool = false): Rule[S] =
  rule(
    (if toClient: "inject garbage -> client" else: "inject garbage -> server"),
    byteSeqs(600),
    proc(s: var S, data: seq[byte]) =
      notify(s, toClient)
      wireOf(s).injectPacket(toClient != invert, data))

# ---------------------------------------------------------------------------
# Off-TID family (D8b) -- same shapes, plus an attacker (host, port) distinct
# from wireharness.WirePeerHost/Port, so the TID-lock's mismatch branch is
# what has to reject the packet, not merely address equality by luck.
# ---------------------------------------------------------------------------

const AttackerHosts* = @["attacker", "evil.example", "10.6.6.6", "mitm"]
  ## None equal `wireharness.WirePeerHost` ("peer") -- any draw from this
  ## list is an off-TID source regardless of the port drawn alongside it.

proc attackerAddr*(): Strategy[(string, int)] =
  sampledFrom(AttackerHosts).flatMap(proc(h: string): Strategy[(string, int)] =
    integers(0, 65535).map(proc(p: int): (string, int) = (h, p)))

proc mkInjectOffTidData*[S](toClient: bool, wireOf: WireOf[S],
                            notify: NotifyInject[S], invert: bool = false): Rule[S] =
  let strat = attackerAddr().flatMap(proc(a: (string, int)): Strategy[(string, int, int, seq[byte])] =
    integers(0, 65535).flatMap(proc(b: int): Strategy[(string, int, int, seq[byte])] =
      byteSeqs(300).map(proc(d: seq[byte]): (string, int, int, seq[byte]) = (a[0], a[1], b, d))))
  rule(
    (if toClient: "inject off-TID DATA -> client" else: "inject off-TID DATA -> server"),
    strat,
    proc(s: var S, args: (string, int, int, seq[byte])) =
      notify(s, toClient)
      let pkt = TftpPacket(opcode: opData, blockNum: uint16(args[2]), data: args[3])
      wireOf(s).injectPacket(toClient != invert, encode(pkt), args[0], args[1]))

proc mkInjectOffTidAck*[S](toClient: bool, wireOf: WireOf[S],
                           notify: NotifyInject[S], invert: bool = false): Rule[S] =
  let strat = attackerAddr().flatMap(proc(a: (string, int)): Strategy[(string, int, int)] =
    integers(0, 65535).map(proc(b: int): (string, int, int) = (a[0], a[1], b)))
  rule(
    (if toClient: "inject off-TID ACK -> client" else: "inject off-TID ACK -> server"),
    strat,
    proc(s: var S, args: (string, int, int)) =
      notify(s, toClient)
      let pkt = TftpPacket(opcode: opAck, ackBlockNum: uint16(args[2]))
      wireOf(s).injectPacket(toClient != invert, encode(pkt), args[0], args[1]))

proc mkInjectOffTidError*[S](toClient: bool, wireOf: WireOf[S],
                             notify: NotifyInject[S], invert: bool = false): Rule[S] =
  let strat = attackerAddr().flatMap(proc(a: (string, int)): Strategy[(string, int, int, string)] =
    integers(0, 8).flatMap(proc(c: int): Strategy[(string, int, int, string)] =
      safeStrings(0, 16).map(proc(m: string): (string, int, int, string) = (a[0], a[1], c, m))))
  rule(
    (if toClient: "inject off-TID ERROR -> client" else: "inject off-TID ERROR -> server"),
    strat,
    proc(s: var S, args: (string, int, int, string)) =
      notify(s, toClient)
      let pkt = TftpPacket(opcode: opError, errorCode: TftpErrorCode(args[2]),
                            errorMsg: args[3])
      wireOf(s).injectPacket(toClient != invert, encode(pkt), args[0], args[1]))

proc mkInjectOffTidGarbage*[S](toClient: bool, wireOf: WireOf[S],
                               notify: NotifyInject[S], invert: bool = false): Rule[S] =
  let strat = attackerAddr().flatMap(proc(a: (string, int)): Strategy[(string, int, seq[byte])] =
    byteSeqs(600).map(proc(d: seq[byte]): (string, int, seq[byte]) = (a[0], a[1], d)))
  rule(
    (if toClient: "inject off-TID garbage -> client" else: "inject off-TID garbage -> server"),
    strat,
    proc(s: var S, args: (string, int, seq[byte])) =
      notify(s, toClient)
      wireOf(s).injectPacket(toClient != invert, args[2], args[0], args[1]))
