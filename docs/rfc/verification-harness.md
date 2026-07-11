# RFC: Verification harness — coverage-guided fuzzing + bounded proof for the parse / never-Defect surface

Status: **implemented** (rfc-flow Stage 3 — all 10 slices landed green, see
[the handoff doc](verification-harness.handoff.md)). Next: Stage 4 (`/code-review`), not yet run.

## Summary

chapulin's headline safety property — *hostile input degrades to an `ERROR`
reply or a per-option default, never a process-killing Nim `Defect`* — is the
foundation `SECURITY.md` rests on, yet it is barely verified. Meanwhile the
dev-dependency `proptest` (coreyleavitt/proptest) is a full **coverage-guided
fuzzer** and a **z3-backed symbolic-execution engine**, of which chapulin uses
only the `forAll`/`property` surface — and even that surface, it turns out,
*already* exposes coverage-guided search and crash-corpus persistence behind two
`Settings` fields we never set.

This RFC stands up a real verification harness for the attacker-facing parse
surface by **extending chapulin's existing `t_props.nim` properties** into
coverage-guided, corpus-persisted fuzz targets with per-target never-`Defect`
oracles; adds the parse/containment targets currently missing (netascii decoder,
the `.md5` sidecar writer, the reserved-namespace authorization check); converts
the bounded event queue's saturation invariant from example tests into a
property; and adds bounded symbolic-execution **proof/witness** targets over the
parsers (toolchain built + proven on Windows/MSVC; the engine covers chapulin's
`parseInt`+`try` idiom — see D4).

## Scope

**In scope:** the fuzzing / property verification of chapulin's pure parse /
containment / queue layers, extending the existing `t_props.nim` /
`t_props_transfer.nim` / `t_props_server.nim` / `t_netascii.nim` property suite.

**Explicitly out of scope (separate track — do not fold in):** interop
*conformance* breadth (netascii/windowsize/real-peer/loss injection against a
real external daemon) and the two known interop defects (the atftp PUT test that
prints PASS unconditionally; the missing `large.bin` fixture). These belong to an
interop RFC. Note: this is about interop *conformance* — fuzzing the netascii
*decoder* for Defects (D3) is squarely this RFC's business and is **in** scope.

**Deferred:** CI integration of the property/fuzz layer. milpa isn't complete
enough to wire proptest resolution into GitHub CI yet; this harness targets the
local Docker/milpa flow (`scripts/dev-test.ps1`). Revisit when milpa lands.

*Known CI prerequisites (recorded now, not yet actioned — the toolchain work
surfaced them):* (a) the symex suite needs a **different image**, not just an
`-Image` swap — `Dockerfile.symex` is Windows-PowerShell-specific (`Expand-Archive`,
`Move-Item`), a genuinely separate build; (b) `dev-test.ps1` hardcodes the
Windows-container mount `C:\app` with no OS branch, so a GitHub-hosted **Linux**
runner can't invoke it unmodified; (c) `milpa fetch` must run first with
`MILPA_CACHE_DIR` pinned in-tree (so bind-mounted symlinks resolve), and cache
semantics (ephemeral vs cross-run) decided; (d) **GitHub-hosted Windows runners
don't cleanly run Windows containers** (Docker there defaults to Linux-container
mode) — a self-hosted Windows runner, or a Linux z3 image for symex specifically,
is likely required. The whole default suite is Windows-container-only today (so
the POSIX branches of `security.nim` get no fuzz coverage until a Linux mount path
is added — D3's OS-tag scheme is aspirational until then).

## Verified before drafting (so the spec isn't built on hearsay)

Confirmed against the pinned `proptest` source at `_deps/proptest` (symlink into
the gitignored `.milpa-cache`; read via Read/Bash, not Grep) and chapulin's tree:

- **The fuzzer is pure Nim.** Coverage is instrumented via a `{.cover.}`
  **macro/AST rewrite** (`src/proptest/coverage.nim`, an 8192-slot edge bitmap),
  NOT C sanitizer-coverage. No FFI. It catches Nim `Defect`s and records failing
  inputs. Two mutation kernels: `fmIR` (mutates the typed choice-sequence —
  structurally smart) and `fmBytes` (raw AFL-style). Requires `--panics:off` so
  Defects raise rather than abort.
- **The existing `forAll`/`property` surface already does what D1/D5 wanted by
  hand.** `Settings.coverageGuided = true` (`proptest/engine/types.nim`, wired in
  `engine.nim`) turns the *same* property surface `t_props.nim` uses today into a
  coverage-guided search, feeding the per-example coverage delta into the
  targeted-SA phase that already drives shrinking. And `forAll`/`property` with
  both `Settings.testId` and `Settings.dbPath` set **automatically** replays any
  DB-stored falsification first and saves a fresh one back, via
  `directoryBasedDatabase` — the exact backend D5 names. The `property` DSL takes
  these via a `with <Settings>` clause (`dsl.nim:37-39`). *This reshapes the
  design below:* the default path is now "add a `Settings` clause to the
  properties we already have," not "build a new `t_fuzz.nim` + `fuzzWith`
  harness."
- **`--panics:off` is Nim's default and this repo never overrides it.** Verified:
  `nim.cfg` carries only `--path` entries; `chapulin.nimble` and
  `scripts/dev-test.ps1` invoke `nim c -r --hints:off --colors:off -d:chapulinTest`
  with no `--panics` flag anywhere in the tree. The `except Defect` premise holds
  end-to-end here.
- **`protocol.decode`'s exception surface really is `TftpDecodeError` only** (every
  raise site traced; the one enum-conversion hazard at `protocol.nim:187` is
  range-guarded). **But `negotiateServerOptions` is NOT total** — it raises bare,
  uncaught `ValueError` by design (`options.nim:159,173,199,210`), caught only by
  its real caller `negotiateCore` (`server.nim:310-314`). **`validateAndParseOack`
  IS total** (all numeric branches wrapped `try/except ValueError → reject`,
  `options.nim:65-138`). *These three demand three different oracles* (see D3) —
  one shared oracle shape would manufacture false crashes on the option parser.
- **The z3 toolchain is done: binding, wiring, and symex-engine fragment
  coverage are all resolved.** `src/proptest/symex.nim` does `import z3`;
  `import proptest` does not pull it, so the pure-Nim fuzz half (D1-D3, D6)
  never links z3. The binding (`coreyleavitt/nim-z3`) is a **softlink**-based
  FFI layer that is **runtime-optional** — it skips cleanly if `libz3` is
  absent rather than aborting at startup — and, as of `nim-z3 6a708ed` +
  `softlink v0.5.1`, compiles clean under Windows/MSVC (`Dockerfile.symex`,
  proven: `z3FullVersion()` returns a live value) with no OS-specific flag
  beyond `--cincludes:"C:/z3/include"`. Current `proptest` (`99fa2dbe`, now
  pinned) models `parseInt`/`toLowerAscii`/`try`-`except` in the symex engine
  itself, so `symexFind` over chapulin's own `parseInt`+bounds+raise idiom
  returns real `sxSat`/`sxRaised` witnesses (cross-checked against real Nim) —
  **no `{.symexOpaque.}` wrappers needed**. Symex is a first-class slice-7
  target, not a prerequisite-gated stretch spike. **Full resolution narrative
  (binding internals, the 3-pin milpa shim and its removal checklist, the MSVC
  compile-time-assert root cause, platform findings): see
  [Appendix A](#appendix-a-z3symex-toolchain-resolution-history) — kept out of
  the main verified-facts list because it's debugging history for whoever
  removes the TEMP shim later, not something a slice 1-8 implementer needs to
  read.** See also [[softlink-dynlib-lib]].
  **FFI-free is a property of the shipped artifact, not the test harness** — the
  softlink/z3 stack in tests is fine. See [[corey-nim-ffi-and-testing]].
- **A hostile-*session* target is absent, and a foundation for it already exists.**
  Today's targets are all isolated pure parsers. SECURITY.md's core never-crash
  claim is about the `api.nim` facade across a *live* transfer. `tests/wireharness.nim`
  already runs the real `sendBlocks`/`recvBlocks`/`handleRrq`/`handleWrq` against
  each other under a generated `WireAction` schedule (pass/drop/dup/delay) — but
  only perturbs *delivery* of legitimate packets, never injecting forged/off-TID/
  garbage traffic. proptest's `stateful.nim` (`Rule[S]`/`StateMachine[S]`) is
  unused. This gap is closed in scope as slices 7–8 (D8).

## Goals

1. Turn the existing `t_props.nim` never-`Defect` properties into
   **coverage-guided, corpus-persisted** fuzz targets by setting
   `Settings(coverageGuided: true, testId, dbPath)` — with a **per-target** oracle
   (the allowed-exception set differs per parser).
2. **Close the target-coverage gaps** that leave named `SECURITY.md` claims
   unverified: the netascii decoder, the `.md5` sidecar writer's symlink refusal,
   and the reserved-namespace forgery refusal in `checkWriteAccess`.
3. Convert the event queue's saturation invariant (the safety form
   `droppedLogCount>0 ⇒ order.len==cap`, checked after every op — not the
   untestable "eventually surfaces" liveness prose) from example tests into a
   property, **without** dropping the queue's coalescing invariant.
4. Ship without coupling `src/` to the test framework or to z3, and without
   changing the release build in any way.
5. Add z3 symex **proof/witness** targets over the parsers (`sxUnsat` = bounded
   no-Defect proof; `sxRaised`/`sxSat` = witnesses validated against real Nim),
   in an opt-in binary that never blocks goals 1–4.

## Non-goals

- Unbounded proof. symex is bounded (`maxLoopUnwind` 5, `maxCallDepth` 3); it
  proves for bounded structures. Fuzzing covers the unbounded tail.
- Any FFI, dependency, or behavior change in `src/` / the shipped binary. (The
  one `src/` touch — a gated `{.cover.}` annotation — is a compile-time no-op in
  normal/release builds; its accepted cost is stated in D2.)
- Interop *conformance* and CI (see Scope).
- `tftp_uri.parseTftpUri` — a hand-rolled URI parser, but it consumes **CLI/operator
  input** (`src/chapulin.nim`), not attacker-controlled network bytes, so it's
  outside SECURITY.md's threat model. Excluded deliberately (stated so the target
  list is genuinely complete, not a silent omission).
- `maxConcurrent` / transfer port-range bounds — resource bookkeeping over trusted
  config, not a parse/Defect surface.

## Hard constraints

- `src/` and the release build stay FFI-free and free of any `proptest`/`z3`
  import at normal/release build time. Instrumentation is gated so those builds
  are byte-for-byte unaffected.
- The default test suite (`dev-test.ps1`) must not require z3. Symex lives in a
  separate, opt-in test binary that never joins the default suite array.
- Fuzz/property runs are **deterministic and bounded** in the default suite:
  fixed seed, finite iteration/example count, with a `currentCoverage() > 0`
  tripwire (D2) so a vacuous zero-coverage run cannot pass green (the DSL doesn't
  surface the run's iteration count, and zero examples ⇒ zero coverage anyway).
  Long soak is a separate opt-in mode. (Determinism holds *with* `coverageGuided`:
  round 2 verified proptest's engine has no unseeded entropy — no
  `epochTime`/`rand()`; deadline off by default; the coverage bitmap resets per run
  and is keyed by a static `(file,line,col)` hash. So fixed-seed → reproducible.)

## Design

> Code sketches are illustrative; exact `proptest` signatures are confirmed in
> slice 1 against the pinned source. Note: proptest has no `bytes()` strategy —
> `t_props.nim` already composes `seq[byte]` via `byteSeqs()`; reuse it.

### D1 — Coverage-guided fuzz targets by extending the existing properties
The default fuzz path is **not** a new module. It is the `t_props.nim` /
`t_props_transfer.nim` / etc. properties we already have, upgraded with a
`Settings` clause that (a) enables coverage-guided search and (b) persists/replays
a crash corpus:

```nim
property "decode raises only TftpDecodeError, never a Defect":
  with Settings(coverageGuided: true, testId: "protocol.decode",
                dbPath: "tests/corpus", seed: FUZZ_SEED, maxExamples: FUZZ_N)
  given data in byteSeqs()
  ensure decodeOracle(data)          # per-target oracle, see D3
```

`FUZZ_SEED`/`FUZZ_N` are fixed module constants so the suite run is deterministic
(Hard constraints). The oracle proc returns a bool (or asserts) and encodes the
target's *specific* allowed-exception discipline (D3).

**Opt-in soak mode (not the default suite).** proptest's `fuzzWith(strategy,
prop, settings)` is a *different algorithm* from `coverageGuided` `forAll`: an
unbounded, iteration/time-budgeted AFL-style loop with its own growing corpus
(`fuzz.nim`). Reserve it for a manually-invoked soak target *only if* the bounded
SA search proves too shallow — decided by evidence, not by default. If adopted,
its `FuzzSettings` **must** set a finite `maxIterations` explicitly: a zero-init
`FuzzSettings` means "no cap" on *both* iteration and time and will hang the
suite forever (`fuzz.nim:127-133,302-308`), and `dev-test.ps1` wraps each
`docker run` with no external timeout.

**Do not duplicate the oracle.** The soak target and the `property` target call
the *same* named oracle proc — never two independent restatements of "raises only
X."

### D2 — `{.cover.}` instrumentation shim (opt-in, no src coupling by default)
Coverage-guided search reads the same 8192-slot edge bitmap that `{.cover.}`
populates, so the SUT procs need the pragma even on the `coverageGuided` path.
Importing proptest into `src/` would couple production code to a dev-dep, so gate
it behind one **shared** module (e.g. `src/chapulin/coverpragma.nim`) that both
SUT modules import — not a `when` block duplicated per file:

```nim
# coverpragma.nim
when defined(chapulinFuzz):
  import proptest/coverage
  export cover                      # re-export the macro under its own name
else:
  {.pragma: cover*.}                # exported no-op user pragma
```

SUT procs are annotated `{.cover.}`. Under `-d:chapulinFuzz` the pragma
instruments; otherwise it is an exported no-op and `src/` imports nothing. The
release/default *artifact* is byte-for-byte unaffected (`recordEdge` no-ops under
`cmOff` regardless, `coverage.nim:60-72`). `{.cover.}` is a **pure Nim AST macro**
(rewrites the annotated proc's own `if`/`case`/`while` body, `coverage.nim:139-147`)
— no FFI, no MSVC-specific C — so it compiles on the base image's MSVC toolchain
like today's suite; slice 1 confirms with one empirical compile (the softlink/z3
MSVC saga does not apply — that was C-ABI signature verification, a different path).

**Why not keep `{.cover.}` out of `src/` entirely?** The macro instruments the
*body it is attached to*. A tests-side wrapper (`proc w(x) {.cover.} = decode(x)`)
only instruments the wrapper's branchless body — it cannot reach `decode`'s inner
`if`/`case` arms, which is the whole point. So a re-export shim or a separate `src`
mirror degrades to "did we call decode," not "which branch." One gated pragma in
`src/` is the price of real edge feedback; we accept it.

**Enabling the instrument per test module — one directory-level cfg, not N
per-file copies (round 3).** `-d:chapulinFuzz` must reach every coverage-guided
test's compile. Nim's config loader doesn't only look for `<module>.nim.cfg` —
it also loads a bare `nim.cfg` sitting in the main module's directory, applied to
*every* file compiled from that directory regardless of name. `tests/` holds no
`nim.cfg` today, so add **one** `tests/nim.cfg` carrying `--define:chapulinFuzz`,
instead of hand-copying an identical one-line `t_props.nim.cfg` /
`t_netascii.nim.cfg` / `t_security.nim.cfg` / `t_checksum.nim.cfg` /
`t_eventqueue.nim.cfg` into every coverage-guided suite (D3's destination
mapping). The define is harmless on files that don't `import coverpragma` — it
only changes what that one shim module compiles to — so applying it
tests/-wide is not a scoping leak, it just removes a per-file step that can be
silently forgotten. (`t_symex_smoke.nim.cfg`'s `--cincludes` stays file-scoped:
that flag is specific to the opt-in z3 image and has no reason to reach the
other suites.) Miss the define entirely (delete `tests/nim.cfg`, or the module
stops importing `coverpragma`) and `{.cover.}` silently resolves to the no-op
branch, degrading coverage-guided search to plain random with **no error**
(proptest returns `otPassed` with zero coverage). Guard it with a tripwire —
see the `fuzzProperty` template below, which now bundles the tripwire so it
isn't hand-copied either.

**Shared `fuzzProperty` template — bundle the `Settings` clause and the
tripwire once (round 3).** D1's sketch repeats five `Settings` fields
(`coverageGuided`, `testId`, `dbPath`, `seed`, `maxExamples`) on every property,
and the `doAssert currentCoverage() > 0` tripwire
(`coverage.nim:71-74`) would otherwise be hand-copied at each coverage-guided
site too — four-plus near-identical restatements is exactly the boilerplate a
deep module should hide. Put both in one small shared file (e.g.
`tests/fuzzsupport.nim`, alongside the existing `tests/helpers.nim`) that each
coverage-guided suite imports:

```nim
# tests/fuzzsupport.nim
import proptest
when defined(chapulinFuzz): import proptest/coverage

const
  FuzzSeed* = 0xC0FFEE
  FuzzN*    = 200
  CorpusDir* = "tests/corpus"

template fuzzProperty*(name: string, tid: string, body: untyped) =
  ## `property name` with the corpus-persisted coverage-guided Settings
  ## already applied, plus the currentCoverage() tripwire — the *only* thing
  ## call sites vary is the property name, the testId, and the given/ensure
  ## body.
  property name:
    with Settings(coverageGuided: true, testId: tid, dbPath: CorpusDir,
                  seed: FuzzSeed, maxExamples: FuzzN)
    body
  when defined(chapulinFuzz):
    doAssert currentCoverage() > 0,
      "chapulinFuzz coverage tripwire failed for '" & tid &
      "' — missing tests/nim.cfg define or a dropped {.cover.} pragma"
```

Call sites collapse to the two things that actually differ per target:

```nim
fuzzProperty("decode raises only TftpDecodeError, never a Defect", "protocol.decode"):
  given data in byteSeqs()
  ensure decodeOracle(data)
```

(Assumes `property` is itself a template/macro that accepts an `untyped` block,
which D1's own `with Settings(...)` sketch already relies on — slice 1's planned
empirical compile confirms this along with the MSVC `{.cover.}` check.) This
doesn't change D3's per-target *oracle* logic (still one oracle per target,
per the exception-surface table) — it only removes the Settings/tripwire
boilerplate wrapped around each oracle call.

### D3 — Fuzz-target corpus and **per-target** oracles
Each target gets the oracle its actual exception contract demands — a single
shared shape is wrong (Verified-before-drafting):

| target | allowed exceptions | additional invariant asserted |
|--------|--------------------|-------------------------------|
| `protocol.decode(seq[byte])` | **`TftpDecodeError` only** | — |
| `negotiateServerOptions(...)` | **`ValueError` only** (raises bare by design) | negotiated values within configured bounds |
| `validateAndParseOack(...)` | **none — total** | any exception at all is a finding |
| `validatePath` / `checkWriteAccess(config, resolvedPath)` | none (total) | **lexical (fuzzed):** never escapes root (traversal/absolute/`..`/NUL/ADS); reserved-`.md5` refusal on the `resolvedPath` string itself. **Deferred to e2e (needs a real symlink):** the `canonicalize()`-based alias-forgery refusal (`security.nim:249-257`) — inert on a symlink-free fixture, see below |
| `netascii.NetasciiDecoder.feed`/`flush` (+`NetasciiEncoder`) | none (total per-byte loop) | never Defects on any byte stream; documented round-trip / lossy-edge invariants hold |
| `checksum.writeSidecar(root, resolvedPath, digest)` | `OSError`/`IOError` only | never writes outside root; never writes through a symlink (the sidecar-symlink-refusal claim) |

The netascii decoder (`netascii.nim:103-133`) is a stateful per-byte machine fed
every WRQ DATA payload — exactly what coverage-guided fuzzing exists to shake out.
`writeSidecar` (`checksum.nim:58-91`) and the reserved-namespace check in
`checkWriteAccess` (`security.nim:249-257`) each verify a *named* `SECURITY.md`
control that currently has zero coverage.

**Destination — properties live beside their domain's existing tests** (the
codebase convention; *not* centralized in `t_props.nim`): `decode` + the
option/OACK parsers → `t_props.nim`'s existing protocol/options suites; netascii →
`t_netascii.nim` (already has round-trip properties); containment + reserved
namespace → `t_security.nim`; `writeSidecar` → `t_checksum.nim`. Each of those
files imports `tests/fuzzsupport.nim` (D2) to pick up the shared
`-d:chapulinFuzz` define (via `tests/nim.cfg`) and the `fuzzProperty` template.

**Filesystem-dependent targets: fuzz the string, not the fs.** `validatePath` /
`checkWriteAccess` / `writeSidecar` consult live fs state. Fuzz the **path/name
string** against one checked-in, static fixture tree under `tests/corpus/fixtures/`
for the *lexical* surface — traversal, absolute paths, `..`, embedded NUL, `:` ADS
— which is replayable from the choice-sequence corpus alone. Containment findings
gated on `when defined(windows)` branches (`:` ADS rejection) get an OS tag so a
Linux run doesn't mis-replay a Windows-only expectation.

**The symlink/reparse refusals are NOT fuzzed here (corrected from round 1).** Git
can't portably hold symlinks/junctions (`core.symlinks`; NTFS reparse points have
no git representation), and reproducing them needs per-iteration on-disk setup that
fights corpus determinism. So the symlink-dependent named SECURITY.md controls —
symlink-escape refusal, the `.md5` sidecar-symlink refusal, and the canonical
`.md5`-alias forgery refusal — stay covered by the **existing dynamic e2e tests**
(`t_props_server.nim:514-658` builds the symlink at run time with a `skip()`
fallback) and `t_security.nim`'s example tests, which the fuzz slices must **not**
delete. The D3 table's "Deferred to e2e" containment clause and the writeSidecar
row's "never writes through a symlink" clause are assertions on *those* tests; the
fuzz targets carry only the lexical-containment and never-Defect assertions.

### D4 — Symbolic-execution proof/witness targets (`tests/t_symex.nim`, opt-in, z3)
A **separate, opt-in** binary (only it `import proptest/symex`, so z3 links only
here) run via `dev-test.ps1 -Only t_symex -Image chapulin-symex:2.2.10`. This is
**no longer a prerequisite-gated stretch spike** — the toolchain is built and the
engine covers chapulin's parsers (Verified-before-drafting); all three former
prerequisites are retired (z3 binding is git-hosted + shimmed; Windows/MSVC works,
no Linux detour; `parseInt`/`toLowerAscii`/`try`/`except` are modeled, so **no
`{.symexOpaque.}` wrappers**).

Targets on the real option/OACK parsers (or thin faithful twins where a param
type isn't yet a supported witness shape):
- `symexFind(parser, tRaisedExn("ValueError"))` → `sxRaised` with a witness that
  **is** genuinely non-numeric (validate each witness against real Nim `parseInt`,
  per proptest's own `tsymex_discard_raise` pattern) — proves the "hostile input
  degrades to `ValueError`, never a Defect" half of the contract *constructively*.
- `symexFind(parser, tIndexError())` / `tFieldDefect()` / `tAssertionViolation()`
  → `sxUnsat` = a **bounded proof** that no reachable input triggers that Defect
  over the modeled fragment; `sxSat` = a witness (a real bug) to fix.
The bound is still real (symex is bounded: `maxLoopUnwind`/`maxCallDepth`), so
fuzzing (D1–D3) still covers the unbounded tail — the two compose. Symex never
gates the pure-Nim fuzz half; it runs only in the z3 image.

### D5 — Corpus / regression DB (mostly free)
On the default `coverageGuided` `property` path, corpus persistence is
**automatic**: `testId` + `dbPath` make `forAll` replay the committed corpus first
and save new falsifications back via `directoryBasedDatabase` — no per-target
plumbing. Persistence is **choice-sequence** based (`db.save(testId, choices)`,
`db.nim:79-81`); there is no raw-byte save path, which is why the default path
uses `fmIR`/choice-sequence corpora and the committed store lives at
`tests/corpus/` (committed, so any found crash is a permanent regression case).
If the opt-in soak mode (D1) is ever used, a single `tests/helpers.nim` helper
wraps "load committed corpus → `fuzzWith` → save new `irCrashes`" so soak targets
don't hand-roll DB calls.

### D6 — Event-queue saturation property
Replace the example-only H1 tests with a `forAll` over a random sequence of
push/pop/kind **operations** (a plain `Strategy[seq[Op]]` — *not* proptest
`stateful`, which is built for rule-precondition state machines this flat
invariant doesn't need). Assert:

- **after every operation** — the safety invariant `q.order.len ≤ q.cap`, the
  coalescing invariant (below), and `payload`/`progressKey` sizes bounded by `cap`;
- **after every `push` only** — the drop-accounting safety form
  **`droppedLogCount > 0 ⇒ q.order.len == q.cap`** (pending drops exist only when
  full; the next push with room flushes them). This is push-scoped *by design*:
  `tryPopFirst` never touches `droppedLogCount`, so a pop right after a saturating
  push leaves `droppedLogCount > 0` with `order.len == cap-1` for one op — asserting
  this form after *every* op is a false negative (`eventqueue.nim` doc-comment:
  the warning "is retried on a later push"). It's the checkable form of the earlier
  untestable "a `dropped N` warning always eventually surfaces."

D6 **replaces** the example H1 tests but must **carry over the coalescing
invariant** (`eventqueue.nim:17-19`: `id ∈ progressKey` iff `id` has exactly one
un-drained progress event keyed by `progressKey[id]`) — either as an additional
per-op assertion in the same property or by keeping a scoped example test
alongside. Do not let the "replace" drop it.

### D7 — Toolchain & build modes
- **Default** (`dev-test.ps1`): pure-Nim fuzz + property targets; no z3. The
  `-d:chapulinFuzz` define needed by the coverage path is supplied once via a
  directory-level `tests/nim.cfg` (`--define:chapulinFuzz`) — Nim auto-loads a
  bare `nim.cfg` for every main module compiled from that directory, so
  `dev-test.ps1`'s shared-flag loop (`dev-test.ps1:34-38`) needs no change and
  no per-file `.nim.cfg` duplication is needed either (D2).
- **Green condition (deterministic):** falsification is caught automatically (the
  `property` macro `check false`s on any non-pass outcome, so no explicit
  `crashes==0`), and the `fuzzProperty` template's `currentCoverage() > 0` tripwire
  (`coverage.nim:71-74`) guards the silently-vacuous run (a dropped `{.cover.}` or a
  missing `-d:chapulinFuzz` define). `iterations>0` is *not* used — the DSL never
  surfaces the `Report`, and zero-coverage subsumes it.
- **Extended** (opt-in): the z3 symex binary against the **Windows** z3 image
  (`chapulin-symex`, `Dockerfile.symex`). `dev-test.ps1` now **auto-selects** it
  by naming convention — any suite matching `t_symex*` gets `chapulin-symex:2.2.10`
  — with `-Image <tag>` as an override — so `-Only t_symex` just works, no image
  to remember, and no per-file map entry to maintain as more `t_symex_*` targets
  are added (round 3: a suite-name lookup table was replaced with the prefix
  match precisely so a forgotten map entry can't silently fall back to the base
  image and fail cryptically). Symex compile needs `--cincludes:"C:/z3/include"`
  (via the test's `.nim.cfg`). See [[softlink-dynlib-lib]], [[no-local-builds-ci-verifies]].
- No new deps for the fuzz half (pure Nim via the existing proptest dev-dep).

### D8 — Hostile-session fuzzing (in scope — Corey accepted full, 2026-07-10)
A `proptest/stateful` `StateMachine` over `Wire` (extending `tests/wireharness.nim`)
injecting hostile traffic into a live `sendBlocks`/`recvBlocks`/`handleRrq`/
`handleWrq` exchange, invariant "the session never raises anything but a clean
`TransferResult`/`ERROR` — never a Defect." This is where SECURITY.md's core
end-to-end never-crash claim lives. **Two sub-pieces of differing cost, both in
scope, sequenced as two slices:**
- **(a) forged/garbage-payload injection** (slice 7) — cheap: the wire already
  carries raw `seq[byte]`, so a `waInject` action injecting attacker-chosen
  DATA/ACK/ERROR bytes with arbitrary block numbers drops into the existing
  `WireAction` schedule.
- **(b) off-TID injection** (slice 8) — first extend `Wire`/`Transport` with a
  **per-packet source-address dimension** (`makeTransport` currently hardcodes a
  fixed `("peer", 0)` in its `doRecv`), then inject packets from a wrong `(host,
  port)` and assert the TID lock (`transfer.nim` §4) rejects them without a Defect.

## Slices (TDD-sized; internal → additive; each green in Docker)

1. **Coverage-guided scaffold.** Add `tests/nim.cfg` (`-d:chapulinFuzz`, D2) +
   the shared `coverpragma` module + `tests/fuzzsupport.nim` (`fuzzProperty`
   template bundling `Settings(coverageGuided, testId, dbPath, seed,
   maxExamples)` and the `currentCoverage()>0` tripwire) + `{.cover.}` on
   `protocol.decode`'s path; upgrade the existing `decode` property to
   `fuzzProperty(..., "protocol.decode")` with the `decodeOracle`. Green condition:
   the `property` macro already `check false`s on any falsification (so `crashes==0`
   needs no explicit assert), and the template's `currentCoverage()>0` tripwire is
   the vacuous-run guard — `iterations>0` isn't reachable through the DSL (the macro
   never surfaces the `Report`) and coverage==0 subsumes it anyway. Proves the path
   end-to-end and confirms `{.cover.}` compiles under MSVC.
2. **Per-target option oracles.** `negotiateServerOptions` (allow `ValueError`
   only) + `validateAndParseOack` (total) with their distinct oracles and
   `{.cover.}` annotations, in `t_props.nim`.
3. **Containment (lexical) target.** Fuzz `validatePath`/`checkWriteAccess`
   path/name strings against the fixed `tests/corpus/fixtures/` tree; assert
   never-escape (lexical) **and** the reserved-`.md5` refusal on the `resolvedPath`
   string (the `canonicalize()` alias-forgery sub-case stays in the e2e tests, per
   D3). In `t_security.nim` (imports `tests/fuzzsupport.nim`). **Do not** delete the
   existing dynamic symlink e2e tests — the symlink refusals stay there (D3).
4. **Netascii + sidecar targets.** Fuzz `NetasciiDecoder.feed`/`flush` (+encoder)
   in `t_netascii.nim`, and `checksum.writeSidecar`'s lexical never-escape in
   `t_checksum.nim`; each imports `tests/fuzzsupport.nim`. (The sidecar-symlink
   refusal stays in the existing e2e test, per D3.)
5. **Corpus commit + replay.** Commit `.gitattributes` `tests/corpus/** binary`
   **first**; confirm `directoryBasedDatabase` under `tests/corpus/` replays
   committed choice-sequences (a two-run round-trip smoke check); OS-tag the
   platform-gated entries.
6. **Event-queue property.** D6 in `t_eventqueue.nim`: safety + (push-scoped)
   drop-accounting + coalescing invariants over random op-sequences, replacing the
   example-only H1 tests (carry the coalescing coverage over).
7. **Hostile-session — payload injection.** D8(a): a `proptest/stateful`
   `StateMachine` over `Wire` (extending `tests/wireharness.nim`) with a `waInject`
   action injecting forged/garbage DATA/ACK/ERROR (attacker-chosen block numbers +
   bytes) into a live `sendBlocks`/`recvBlocks`/`handleRrq`/`handleWrq` exchange.
   Invariant: the session yields only a clean `TransferResult`/`ERROR`, never a Defect.
8. **Hostile-session — off-TID injection.** D8(b): first extend `Wire`/`Transport`
   with a per-packet source-address dimension (`makeTransport` hardcodes `("peer",
   0)` today), then inject packets from a wrong `(host, port)` and assert the TID
   lock (`transfer.nim` §4) rejects them without a Defect.
9. **Symex proof/witness targets.** D4: point `symexFind` at `negotiateServerOptions`
   and `validateAndParseOack` (`options.nim:142,65`). Their `seq[(string,string)]`
   param has **no witness reader** (symex errors at macro-expansion on seq-of-tuple),
   so per-arm **twins are required, not optional**: one `val: string` proc per option
   key (`blksize`/`timeout`/`windowsize`/`tsize`) mirroring that arm's
   `parseInt`+bounds+raise body — the shape the 2026-07-10 probe already proved.
   Targets `tRaisedExn("ValueError")` / `tIndexError()` / `tFieldDefect()`; assert
   status and validate every `sxRaised`/`sxSat` witness against real Nim. (*Not*
   block-number arithmetic — `uint16` never raises a Defect on wrap, so it'd be a
   trivial `sxUnsat` proving only language semantics.) No wrappers, no gating. In
   `t_symex.nim`, z3 image.
10. **Docs & SECURITY cross-ref (tail).** The toolchain half is already **done**
    (`Dockerfile.symex`, `dev-test.ps1` suite→image map, `t_symex_smoke` green);
    what remains is documenting the build modes and cross-referencing each
    `SECURITY.md` never-Defect / containment claim to its verifying target — which
    genuinely needs slices 1–9 landed.

## Open forks

**None — the RFC is fully resolved (2026-07-10), ready for `/tdd`.**

- **Symex** — the earlier "compile-errors / `sxUnknown` / non-portable /
  wrong-platform" escalation is *closed*: the toolchain works on Windows/MSVC
  (`Dockerfile.symex`, proven), proptest `99fa2dbe` models
  `parseInt`/`toLowerAscii`/`try`-`except`, and `symexFind` over chapulin's idiom
  returns real `sxSat`/`sxRaised` witnesses (slice 9, no wrappers, no gating; D4).
- **Hostile-session (D8)** — Corey accepted **both** halves in scope (2026-07-10):
  payload injection (slice 7) and off-TID injection (slice 8, including the
  `Wire`/`Transport` source-address extension). Nothing deferred.
- Also resolved earlier: committed `tests/corpus/`; interop kept a separate track.

**Two named-control properties (committed — they back a SECURITY.md claim slice 8
must cross-reference, so not left to "unless you object"):** a `forAll` property for
`server.redactRoot` ("`rootDir notin redactRoot(rootDir, msg)` for arbitrary `msg`")
in **`t_server.nim`** — the named "information-leak hygiene" control, zero coverage
today; and one for `format.sanitizeForDisplay` ("output never contains a raw control
byte except the substituted `?`") in a **new `t_format.nim`** (none exists — create
it per the beside-the-domain convention). Both pure functions, a handful of lines;
land alongside slice 4 as plain `forAll` (no coverage-guiding needed). (Dropped the
earlier `checkHostAccess` suggestion — round 2 found it already shipped:
`t_props.nim:218-229`, commit `82828a8`.)

## Appendix A: z3/symex toolchain resolution history

*(Round 3: moved out of "Verified before drafting" so that section stays a
scannable list of facts the design depends on. This appendix is the debugging
diary behind one of those facts — read it only if you're touching the z3
shim, the MSVC build, or the symex engine itself; a slice 1-8 implementer
never needs it.)*

- **Binding.** `nim-z3` (`coreyleavitt/nim-z3`) is a **softlink**-based FFI
  layer — `src/z3/ffi.nim` declares the whole Z3 C API inside softlink
  `dynlib "libz3.so(.4|.4.13|…)": …` blocks (compile-time `_Static_assert`
  signature verification against `z3.h`, *not* raw `{.dynlib/passL.}`), and
  `src/z3/context.nim` **lazily** loads libz3 via softlink's loader
  (`ensureLoaded`, surfacing `LoadResult`/`SoftlinkError`). So z3 is
  **runtime-optional**: the symex path skips cleanly if libz3 is absent
  instead of `rawQuit`-ing at startup.
- **Toolchain wiring.** `nim-z3` *is* git-hosted and milpa-configured
  (`coreyleavitt/nim-z3`, public, tags through `v2.0.0`). The only reason it
  isn't in chapulin's `_deps` is that **proptest's** `milpa.kdl` references it
  by a `local=` path (line 8). Fix = flip that one line to `z3
  git="…/nim-z3.git" ref="v2.0.0"` on **proptest's `main`** (chapulin pins
  `proptest ref=main`) + re-lock proptest; then chapulin's `milpa fetch` pulls
  `nim-z3` transitively (z3 is a regular `dep` of proptest, like `softlink`
  which already fetches). Chapulin's own manifest needs no edit, and its
  `milpa.lock` is already `dag-sha256` (the `sha256→dag-sha256` re-lock is
  confined to Corey's libs). nim-z3's own manifest pins proptest by local
  path, but that's a *dev*-dep (test-only) so it is not pulled transitively
  into chapulin — a publish-nim-z3-standalone concern, not a chapulin
  blocker. Applied locally as a TEMP shim — **three pins** in chapulin's
  `milpa.kdl` `dev-deps`: `z3 git=…/nim-z3 ref=6a708ed`; a `softlink v0.5.1`
  root override (nim-z3 pins v0.5.0, proptest pins `main`; the override
  forces v0.5.1 — the MSVC verify fix); and `proptest ref=99fa2dbe` (pinned
  off `main` to pick up the symex `parseInt`/`try`/uninit-var fixes). `milpa
  fetch` pulls nim-z3 into `_deps/z3` + emits `--path:"_deps/z3/src"`.
  **Removal is a 3-item checklist, each an independent upstream edit** —
  don't read "proptest flipped z3" as "shim fully removable": (1) proptest's
  `main` flips `z3 local=` → `git=`; (2) proptest's softlink pin aligns to
  v0.5.1 (drops the override); (3) chapulin reverts `proptest` to
  `ref="main"` once main ≥ 99fa2dbe.
- **Platform.** The binding is cross-platform — Windows OR Linux. As of
  nim-z3 `6a708ed` + softlink `v0.5.1`, the three `dynlib` blocks in
  `ffi.nim` are the **bare** `dynlib "z3"`, and softlink's
  `deriveLibPattern` (`softlink.nim:103-109`) OS-expands it: `libz3.so(|.7|…)`
  on Linux, `lib z3(|…).dylib` on macOS, `(libz3|z3).dll` on Windows. So the
  earlier ".so-only" limitation is gone. The image just needs the native lib
  + `z3.h` (softlink's compile-time `_Static_assert`): Windows = Microsoft's
  `z3-*-x64-win.zip` (`z3.dll`/`libz3.dll` + headers); Linux = `apt install
  libz3-dev`. Symex targets are OS-agnostic string parsers, so either host
  works; container choice is pure preference (Windows for suite uniformity vs
  Linux for the already-running `desktop-linux` daemon).
- **Windows/MSVC compile.** Built the z3-extended Windows image
  (`Dockerfile.symex`: nim base + z3 **4.13.4** — the newest in nim-z3's CI
  matrix; 4.16.0 gives signature-mismatch asserts). The smoke probe
  `z3smoke.nim` (`import z3; echo z3FullVersion()`) compiles under `nim c`
  and prints `Z3 4.13.4.0` — softlink's real compile-time `_Static_assert`
  passes, then it loads `libz3.dll` via `ensureLoaded()` and makes a live Z3
  call.
  - The original MSVC wall was softlink's compile-time verification: its
    `nim c` `_Generic` path was const-INtolerant for `Z3_string` (`const
    char*`) returns, and its `nim cpp` path had a template error (C2955)
    plus nim-z3's C-only `void*`→fn-pointer reliance (C2664). nim-z3's CI is
    Linux/gcc-only so neither showed there. A stub experiment (disabling
    verification) first proved there was **no ABI/runtime wall** — the
    blocker was purely the compile-time check.
  - **Fixed upstream (2026-07-10): softlink v0.5.1 + nim-z3 `6a708ed`.** The
    only Windows-specific compile flag now needed is
    `--cincludes:"C:/z3/include"` (forward slashes — nim cfg escapes `\`);
    `/std:clatest` is no longer required. chapulin's `milpa.kdl` shim pins
    these (`z3 ref=6a708ed`, softlink override `v0.5.1`).
- **Symex engine fragment.** An earlier review (against chapulin's *frozen*
  proptest pin) concluded the engine compile-errors on
  `parseInt`/`toLowerAscii` and would need `{.symexOpaque.}` wrappers
  yielding only `sxUnknown`. **That was a stale-pin artifact.** Current
  proptest (`99fa2dbe`, now pinned) models `parseInt` via Z3 `str.to.int`
  with the ValueError raise-fork (`dsl_parser.nim:1506,2893`),
  `toLowerAscii` via a per-char BV map (`:1692`), `try`/`except`
  (`nnkTryStmt` arm, `:2934`), and zero-inits uninitialized `var`s. **Proven
  end-to-end in chapulin's own setup (2026-07-10):** `symexFind` over a
  `parseInt`+bounds+raise validator — chapulin's exact option-validation
  idiom — returns `sxSat` (witness `"0"`) and `sxRaised` (witness `""`),
  each cross-checked against real Nim `parseInt`. No `{.symexOpaque.}`
  wrappers, no compile error. (A soundness review of the raise-modeling also
  surfaced and fixed a real proptest bug: `discard parseInt(s)` was dropping
  the raise.)
