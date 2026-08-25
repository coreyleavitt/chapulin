## C1 soak scaffold (RFC verification-harness-v2.md §3.3/§5, slice C1) —
## the one target e2e demonstration of the `fuzzWith` `fmIR` soak plumbing
## (`./soakrunner.nim`). NOT part of `scripts/dev-test.ps1`'s default
## `$tests` array (that list is a literal name array, not a directory scan
## — a file simply not named in it is never picked up) and does not use
## the `t_symex*` naming convention (no z3 image needed). Invoked ONLY via
## `pwsh scripts/dev-test.ps1 -Soak <seconds>` (local-opt-in, never CI).
##
## --- Why `protocol.decode` (not the A3 facade StateMachine) ---------------
## The RFC leaves the soak subject open ("the A3 facade
## `facade.hostileInjection` target OR a simpler decode/parse target...a
## simpler target is fine for C1's 'one target e2e' — the point is the
## PLUMBING"). `fuzzWith` takes a plain `Strategy[T]` + `prop: proc(x: T)`
## (fuzz.nim), not a `StateMachine` — A3's `a3SM` is driven through
## `stateful(...)` inside a PBT `property`/`forAll`, a DIFFERENT
## coverage-guided mechanism (`Settings.coverageGuided` hill-climbing
## inside `forAll`, not the standalone `fuzz`/`fuzzWith` engine this slice
## exists to stand up — RFC line 20: "proptest's currently-unused
## `fuzzWith` engine"). Wiring a `StateMachine` through `fuzzWith` would
## need its own non-trivial adapter (a `Strategy[A2State-shaped-thing]`)
## that is out of scope for "prove the plumbing" — reused verbatim, `t_
## props.nim`'s existing `protocol.decode` target (`byteSeqs()` +
## `decodeOracle`) already has the exact `Strategy[seq[byte]]` +
## `proc(x: seq[byte])` shape `fuzzWith` wants. This soak persists its
## growth into `tests/corpus/protocol.decode.bin` itself, via
## `FuzzSettings.database`/`persistKey` (0.3.1) — but into that file's own
## never-pruned `corpus` section (F1, RFC-chapulin-hardening), a section
## `dbReusePhase` never reads or prunes, so it's safe to co-reside with
## `t_props.nim`'s own PBT-property channel (that channel's `primary`/
## `secondary` sections) in the SAME file; see `./soakrunner.nim`'s doc
## comment for the fuller account.
##
## Run:
##   pwsh scripts/dev-test.ps1 -Soak 8

import ../src/chapulin/protocol
import ./fuzzsupport
import ./soakrunner

proc decodeProp*(data: seq[byte]) =
  ## Same oracle as `t_props.nim`'s `decodeOracle`, reshaped to `fuzzWith`'s
  ## `proc(x: T)` contract (failure = raise, not a bool return): the only
  ## expected exception is `TftpDecodeError`; anything else (a Defect, or
  ## any other exception) propagates and `fuzzWith`'s `inProcessTarget`
  ## classifies it as a finding (`"crashed: "`-prefixed for a `Defect`,
  ## same substring guarantee `t_defect_canary.nim` proves for the PBT
  ## engine — `fuzz.nim`'s `inProcessTarget` has its own independent
  ## `except Defect as e: ... "crashed: " & ...` arm, verified directly).
  try:
    discard decode(data)
  except TftpDecodeError:
    discard

when isMainModule:
  quit(runSoak(byteSeqs(), decodeProp, "protocol.decode"))
