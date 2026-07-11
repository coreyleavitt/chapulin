# BlockSource/BlockSink RFC — handoff

- **Stage:** 4 (code-review) **— COMPLETE. Fix loop hit the FLOOR (0 Crit/High/Med) after 2 fix rounds; full suite green.** Only Lows (S4-9/10/11/13) + 1 wontfix-this-RFC (S4-12) + 1 out-of-scope follow-up (S4-14) remain. Stage 3 green; architect rounds 1+2 done. **RFC LANDED → v2 Part A1b ungated.**
- **Resume:** Corey-gated — (a) COMMIT this RFC's work (nothing committed all session), and/or (b) enter v2 Stage 3, and/or (c) file the S4-14 `recvBlocks` follow-up. Optional: sweep the 4 remaining Lows. See **Stage-4 review ledger** below.

## Slice progress (RFC §Stages 6-slice order — AUTHORITATIVE)
- [x] **1 — `blocksource.nim`** (new module): types, `OpenedSource` (`size: Option[int64]`), 4 adapters (each assigns `close`), `toReadData` (ascending-once + oversized-read guards), `BlockSourceOrderError`; no Defect-catch. `t_blocksource.nim` green (12 tests + 2 never-throw fuzz props). Registered in `dev-test.ps1`. **Added `{.cover.}`/`coverpragma`** to satisfy the fuzz-coverage tripwire (`-d:chapulinFuzz` + `fuzzsupport` asserts `currentCoverage()>0`) — spec-consistent, same opt-in as other fuzzed `src/` procs.
- [x] **2 — netascii decorators + signature change** ✓: `netasciiSource`/`netasciiSink` (each forwards `close`); `makeSendReader`/`makeRecvSink` take `BlockSource`/`BlockSink`; `netasciiReader` compat shim (raises `BlockSourceOrderError` now); dead code deleted (`NetasciiReaderError`, old seek-octet closure, old File overloads); 4 call sites adapted to direct `fileBlockSource`/`fileBlockSink` + `close` retention (incl. api.nim lazy-GET threading); `t_netascii:256` migrated. **Full default suite green.** (t_integration external-daemon tests fail on missing port-69 server — pre-existing env gap, self-hosted-facade suite passed.)
- [x] **3 — client: TftpSession factory fields + WIRE api.nim's 2 call sites** ✓: factory TYPES `BlockSourceFactory`/`BlockSinkFactory` added to `blocksource.nim`; `TftpSession`/`newSession` gained nil-default `sourceFactory`/`sinkFactory` beside `transportFactory`; `resolveSourceFactory`/`resolveSinkFactory` helpers; `setupPutTransfer` (eager) + `setupGetTransfer` (lazy-open preserved) wired; 2 behavior tests in `t_session.nim` (client PUT from `memoryBlockSource`, client GET into `memoryBlockSink`, both assert zero client disk I/O). **Full suite green (580 OK).**
- [x] **4 — server: ServerConfig factory fields + WIRE server.nim's 2 call sites** ✓: fields on `ServerConfig` (`server_config.nim`, per §5.1) + `resolveSourceFactory(config)`/`resolveSinkFactory(config)` helpers; `handleRrq` folds `fileExists`+`getFileSize`+`open` into raise-preserving `Option[OpenedSource]` (all 3 outcomes byte-identical, `t_server:1055` green); `handleWrq` open-failure→`errDiskFull` (pre-existing, preserved); `checkWriteAccess`/`csMd5` sidecar/dir-listing left on disk (disclosed residuals R2-7/9); `==` compiles. 5 behavior tests. **Full suite green.**
- [x] **5 — in-memory demo (A1b proof)** ✓ (was slice 6): **test-only, no src/ change** — `tableSourceFactory`/`tableSinkFactory` (per-call lookup + finish-commits-to-table) added to `tests/helpers.nim`; new `tests/t_blocksource_demo.nim` (registered in `dev-test.ps1`) drives real client `TftpSession` ↔ `handleRrq`/`handleWrq` over two `Wire` transports + shared `TableRef[string,seq[byte]]`, zero disk both ends (asserts `not fileExists` + empty `walkDir`); 4 cases: server-GET, client-PUT, same-path PUT-then-GET coherence, netascii-mode; all multi-block (>512B + short final). **Full suite green** ("All test files passed"). Impl note folded into RFC §5.1: factory `path` is the *resolved* path, key the table by `security.validatePath(rootDir, filename)`.

## Stage-4 review scope (when Corey runs `/code-review`)
- New: `src/chapulin/blocksource.nim` (types, 4 adapters, `toReadData`, factory types). Changed: `netascii.nim` (decorators + signature change + shim), `api.nim` + `server.nim` + `server_config.nim` (factory injection). Tests: `t_blocksource.nim`, `t_blocksource_demo.nim`, additions to `t_session.nim`/`t_server.nim`/`t_netascii.nim`/`helpers.nim`.
- Watch items for review: never-throw-Defect discipline at the new seams (no Defect-catch, structural only — §6); `close` fires on every exit path (r2 Crit); the octet ascending-once fail-fast behavior change (disclosed §2); the 3 disclosed hermeticity residuals (checkWriteAccess / csMd5 sidecar / dir-listing still touch disk).
- **Nothing committed** this entire session (v1 checkpoint + all this RFC's work uncommitted) — Corey-gated.

## Slicing decisions (this session — clear-best, NOT design changes)
- **Slice 2 also adapted the 4 call sites** (not just signatures): the signature change breaks callers' compilation, so slice 2 adapted them to the minimal **direct** `fileBlockSource(open(path))` form to stay green.
- **Merged old-slice-5 (wiring) into per-side field slices 3 (client) & 4 (server), and renumbered old-slice-6 → 5.** Rationale: a field-only slice has no honest behavior test (/tdd smell), and slice 2 already touched the call sites, so a separate "wire all 4" slice re-touches them redundantly. RFC's only hard constraint is "fields before wiring," preserved within each merged slice. Client/server wiring have no cross-dependency. RFC design unchanged. **Final plan = 5 slices: 1,2 done; 3 client; 4 server; 5 demo.**
- **Structure DECIDED (Corey 2026-07-10):** this RFC stays **separate** from verification-harness-v2
  (production `src/` data-path refactor vs. verification tooling — different kind, different review,
  standalone RFC #17 value). Sequencing unchanged: it lands before v2 Part A1b.
- **Naming (Corey 2026-07-11):** dropped the "RFC #13" label — this is **not** GitHub issue #13 (a
  separate, already-shipped netascii change). Refer to it as the **BlockSource/BlockSink RFC**
  (`in-memory-sources-sinks.md`).
- **Resume:** after architect round 1 completes → `/architect docs/rfc/in-memory-sources-sinks.md round 2`

## Slices (SUPERSEDED — pre-r2 5-slice list; use the 6-slice "Slice progress" section above)
- [ ] 1 — `blocksource.nim`: `BlockSource`/`BlockSink` types, `fileBlockSource`, `fileBlockSink`,
      `memoryBlockSource`, `memoryBlockSink`, `toReadData`, `BlockSourceOrderError`, Defect-containment
      wrapper. New module, no existing call site touched. (Adapter-level direct-drive round-trip test lives here.)
- [ ] 2 — `netascii.nim`: `netasciiSource`/`netasciiSink` decorators; `makeSendReader`/`makeRecvSink`
      signature change to take `BlockSource`/`BlockSink`; delete now-dead file-specific internals.
- [ ] 3 — Wire the 4 call sites (`server.nim` `handleRrq`/`handleWrq`, `api.nim`
      `setupGetTransfer`/`setupPutTransfer`) **through the nil-defaulting factory**, not a hardcoded
      `open()`. Zero behavior change with the default.
- [ ] 4 — **Session/server factory injection (the actual v2 enabler, §5.1):** `sourceFactory`/
      `sinkFactory` on `TftpSession` (api.nim) + `TftpServer`/`ServerConfig` (server.nim) +
      `newSession` params, nil-default file-backed, mirroring `transportFactory`/`listenerFactory`.
- [ ] 5 — **Facade-level in-memory demonstration (the real A1b proof):** inject a shared in-RAM file
      table into a real client `TftpSession` **and** server `TftpServer`, run a full RRQ/WRQ
      **through the facade** over `Wire` with zero disk I/O. (Slice 1's test is adapter-level only;
      this is what unblocks verification-harness-v2 Part A1b.)

## Open forks (awaiting Corey)
- Naming: reuse `BlockSourceOrderError` for the Defect-containment catch in `toReadData`/`toOnData`,
  or split a distinct `BlockSourceFault` (recommended) so "our own ordering bug" and "a third-party
  source crashed" are distinguishable in logs. Non-blocking for architect round 1.

## Key decisions (this session)
- Scope = **general-purpose, first-class, production abstraction** (not a narrow test-only shim) —
  the broad end of the options the v2 escalation left pending. Driver = Corey's quality-bar steer
  *"best-in-class, PhD-level, effort no object,"* NOT an explicit option pick. *(An earlier subagent
  fabricated a "Corey chose (2026-07-10)" line and drafted the RFC ahead of the design-selection
  gate; corrected. Design bake-off = 4 lenses {minimal, flexible, ergonomic, ports-adapters}, all
  source-grounded; this draft synthesizes them + one Opus-caught gap fix: §5.1 factory injection was
  missing, without which this RFC wouldn't actually unblock v2 Part A. Corey has NOT formally signed off
  on the design yet — architect round 1 is the next gate; he may redirect.)*
- Mechanism: **closure-record** (flat struct of `proc` fields), matching `Transport`'s existing
  precedent (`design-philosophy.md`'s "no vtable, maps to future C function pointers" reasoning) —
  rejected `concept` (no runtime polymorphism), inheritance+`method` (vtable, inconsistent with
  stated philosophy), `std/streams.Stream` (forces raw-pointer/`copyMem` surface + oversized
  contract), object variant (closed to third-party extension, a named `FieldDefect` hazard).
- Access pattern: **forward-stream only**, no seek. Settled by two independent facts: (a)
  `windowCache` already proves retransmit never needs to re-read the source (replays cached
  bytes), so the file case's `setFilePos` was always incidental, not required; (b) future
  non-seekable sources (sockets/generators/embedder streams) structurally cannot seek at all.
- Async sources: **out of scope, honestly** — `transfer.nim`'s `sendBlocks`/`recvBlocks` call
  `readData`/`onData` synchronously (not `await`ed) even though the enclosing procs are
  `{.async.}`; making `BlockSource.read` return a `Future` would require changing `transfer.nim`
  itself, which this RFC is constrained not to do. Flagged as a disclosed follow-on, not solved
  here. "Generator" sources (pull-based, no genuine backpressure) ARE in scope — any closure
  already satisfies that shape.
- netascii is a **decorator** (`BlockSource -> BlockSource`, `BlockSink -> BlockSink`), not a mode
  branch fused into the reader — future transforms (compression, checksumming, encryption) plug
  in identically.
- Never-throw-Defect containment for **foreign** (embedder-authored) `BlockSource`/`BlockSink`
  implementations: `toReadData`/`toOnData` catch `except CatchableError, Defect` — a deliberate,
  narrow exception to the codebase's usual "never catch Defect, avoid structurally" rule, justified
  because this project verified (`verification-harness.md:81`, reaffirmed in v2) that
  `--panics:off` is the build default everywhere, which makes Defects genuinely catchable at this
  one seam. Two named residual limits: depends on that build flag never flipping; doesn't address
  a misbehaving source that hangs/never-terminates (a liveness gap, not a crash gap).
- Deliberately **not** wiring an embedder-facing hook into the public `TransferRequest`/session API
  in this RFC — sketched only (§5 of the RFC). Reopening RFC #17's already-shipped public surface
  is a separate decision.

## Context / why this RFC exists now
`verification-harness-v2.handoff.md` had an unresolved escalation: GitHub issue #13's original
premise (netascii needs wiring) turned out stale — netascii shipped fully wired to `File` already
(`ca955f7`). The only real residue was that `File` is hardcoded at 4 call sites with no injection
point, which is exactly what v2 Part A1b needs (two real sessions, file I/O in-memory over `Wire`).
That escalation offered 4 scope options; this RFC is the resolution, at the broad end of that
range. Once this RFC's slices land, `verification-harness-v2`'s Part A1b (and the rest of its
Stage 3) is unblocked — update that RFC's handoff to drop the "gated on the BlockSource/BlockSink RFC" language once
slices 1-4 above are done.

## Architect round-1 ledger (all source-grounded; applied unless noted)
| id | sev | finding | status |
|----|-----|---------|--------|
| R1-1 | Crit | §6 Defect-catch over-broad — masks first-party bugs, sabotages v2 never-throw verification; no trust boundary in scope (public hook deferred) | **RESOLVED (Corey): defer foreign containment whole to embedder-hook RFC; this RFC catches NO Defects.** §6 rewritten; `toOnData` dropped; one error type (BlockSourceOrderError, CatchableError) |
| R1-2 | Crit | `close` op missing → factory owns `open()` → FD leak every transfer | fixed — `close` added to both types; `defer: source.close()` at call sites |
| R1-3 | High | `toOnData` named in §6 but never defined; write-side wrap absent | fixed (moot) — §6 no longer wraps; makeRecvSink calls write/finish directly (first-party, structurally safe) |
| R1-4 | High | tsize/existence: `fileExists`/`getFileSize`/`open` run on raw path *before* factory → "zero disk" false, memory RRQ 404s early | fixed — factory returns `Option[OpenedSource]` (source+size); folds existence+size+open, closes TOCTOU |
| R1-5 | High | factory placement conflict (Breadth: TftpServer / Feasibility: ServerConfig) | fixed — **ServerConfig** (factory needs resolvedPath known only inside handleRrq → must travel with config; zero test ripple). Client side: TftpSession. `==` compile check-off noted |
| R1-6 | High | `netasciiReader` has 2 direct test callers (t_netascii:193, t_client:657); deleting breaks them | fixed — keep as compat shim; optional slice 2b to remove |
| R1-7 | Med | octet ascending-guard = undisclosed behavior change | fixed — disclosed in §2 + Supersedes + type doc (deliberate fail-fast) |
| R1-8 | Med | oversized-read was a §7 "doAssert" aside — actually protocol-corruption risk | fixed — hard invariant in toReadData, raises BlockSourceOrderError, Stage 1 |
| R1-9 | Med | setupGetTransfer lazy-open must not become eager (pre-DATA failure would create file) | fixed — slice 4a preserves laziness + adds a no-file-on-pre-DATA-failure test |
| R1-10 | Med | security check must run before/independent of factory (stated as invariant) | fixed — §5.1 states the post-validatePath invariant + rootDir-must-exist residual |
| R1-11 | Low | server-side factory folded into one slice as if symmetric w/ client | fixed — split into slice 4a (client) + 4b (server) |
| R1-12 | Low | dir-listing pseudo-file / checksum sidecar disk touches unmentioned | partially noted (rootDir residual); dir-listing/sidecar scope note → fold in round 2 |
| — | info | read(n):seq[byte] MORE consistent than fill-buffer (cite TransportRecvProc) | fixed — cited in §1 |
| — | info | verified faithful: netascii decorator logic; --panics:off in actual container cmd; memory ref-capture | no change |

## Architect round-2 ledger (all clear-best; applied — zero forks)
| id | sev | finding | status |
|----|-----|---------|--------|
| R2-1 | Crit | `close` field never assigned by any ctor, nor forwarded by decorators → nil `close` → NilAccessDefect at cleanup (contradicts §6 "Defect-free") | fixed — all 4 ctors assign `close`; both decorators forward `inner.close`; call sites RETAIN source/sink value + call its close; lazy GET threads via outer var |
| R2-2 | High | `Option[OpenedSource]` loses "found-but-unopenable" → EACCES downgraded to errFileNotFound (t_server:1055) | fixed — source factory now raise-preserving (none=absent, raise IOError=unopenable); handleRrq keeps try/except IOError→errAccessViolation |
| R2-3 | High | `netasciiReader` shim raises `BlockSourceOrderError`, but t_netascii:256 asserts `except NetasciiReaderError` → NOT green | fixed — slice 2 migrates that except-clause (disclosed as required sub-task, not "unmodified") |
| R2-4 | High | oversized-read described as enforced but MISSING from `toReadData` code listing | fixed — check added to the listing (raises BlockSourceOrderError) |
| R2-5 | High | slice 3 (wire call sites through factory) ordered BEFORE the fields it needs (4a/4b) | fixed — reordered: 1,2,3(client fields),4(server fields),5(wire),6(demo) |
| R2-6 | High | slice 5 secretly depends on v2 A1a-ii listener bridge (unbuilt; wireharness is point-to-point) | fixed — slice 6 descoped to drive handleRrq/handleWrq directly over two Wire transports + shared table; proves hermeticity (this RFC's job), full facade-listener path stays v2's |
| R2-7 | High | write-side existence: `checkWriteAccess` fileExists bypasses sinkFactory (overwrite-policy) | disclosed residual — split is principled (Design), v2 doesn't need hermetic overwrite-policy; sink factory could gain existence later |
| R2-8 | Med | `size: int64` forces future sizeless sources into a sentinel | fixed — `size: Option[int64]` |
| R2-9 | Med | checksum `.md5` sidecar + dir-listing getFileSize are undisclosed real-disk touches | fixed — disclosed as residuals; hermetic claim scoped to RRQ/WRQ data path, csNone, no overwrite-policy |
| R2-10 | Med | shared in-RAM table factory unspecified + snapshot-vs-call-time hazard | fixed — `tableSource/SinkFactory` sketch with per-call lookup + finish-commits-to-table |
| R2-11 | Med | `finish` doc "exactly once" wrong (zero on mid-stream cancel); confused with cleanup | fixed — "at most once, only if final block reached; `close` is the real cleanup hook" |
| R2-12 | Low | `ServerConfig ==` over closures | confirmed COMPILES (Nim EqProc); doc caveat added (referential identity once non-nil) |
| — | Low/polish | naming: `makeRecvSink` returns onData-shape not BlockSink; `toReadData` off-pattern; Block-infix inconsistent (netasciiSource vs fileBlockSource) | **carry to implementation** — rename at slice time if desired (`toReadData`→`sourceToReadData`, consistent Block infix); non-blocking |
| — | info | Design: source/sink asymmetry PRINCIPLED (not a BlockStore unify); closure-depth 3x justified; ServerConfig copy safe | no change |

## Stage-4 review ledger (round 1) — 5 reviewers (correctness/security/design/quality/coverage), all sonnet
Mandate: fix through Medium, leave Low (awaiting Corey). All Crit/High adversarially verified by the Opus control loop.

| id | sev | finding | file | status | proof / verification |
|----|-----|---------|------|--------|----------------------|
| S4-1 | **High** | Default source factory leaks the just-opened FD if `getFileSize` raises (tuple evals `open` before `getFileSize`); server also can't catch it (`getFileSize`→`OSError`, catch is `except IOError`) → no client ERROR packet, may escape `handleRequest` | `api.nim:180`, `server.nim:401` + catch `server.nim:491` | open | CONFIRMED: `git show HEAD:server.nim` had size-BEFORE-open (no leak) → regression; codebase convention (checksum.nim:91, security.nim:153/255) proves `getFileSize` raises `OSError`, a sibling of `IOError` |
| S4-2 | **High** | Client-side factory injection tested only for the `some`/success outcome; `none` and `raise IOError` untested on both source & sink (server tests all 3) — the never-raises facade error paths are unverified | `t_session.nim` (setup*Transfer) | open | Coverage gap, confirmed by inspection; asymmetric vs `t_server.nim:1301-1360` |
| S4-3 | Med | File-backed default factory duplicated verbatim across client & server `resolve*Factory` — future drift risk; S4-1 fix should land ONCE here | `api.nim:172-188` vs `server.nim:390-408` | open | Confirmed x3 (design+quality+correctness); server doc says "verbatim". Fix: hoist `defaultBlockSourceFactory`/`defaultBlockSinkFactory` into `blocksource.nim` |
| S4-4 | Med | `{.cover.}` missing on the 4 adapter closures the fuzz props actually drive (`fileBlockSource.read`, `fileBlockSink.write/finish`, `memoryBlockSource.read`, `memoryBlockSink.write`) — tripwire still passes via `toReadData`, silently defeating coverage feedback; handoff's "same opt-in" claim inaccurate | `blocksource.nim:108-140` | open | Confirmed by read; only line 91 carries `{.cover.}` |
| S4-5 | Med | Dead production code w/ false docs: `finishNetasciiDecode`/`writeNetasciiTail` have ZERO `src/` callers post-slice-2 yet docs claim live wiring ("shared by server.handleWrq and api.nim tdGet") | `netascii.nim:214-263` | open | CONFIRMED via `grep src/`: only test callers. Fix: delete (+migrate their unit tests) or correct docs |
| S4-6 | Med | `makeRecvSink` takes a `BlockSink` but returns an `onData`-shaped closure, not a `BlockSink` — name promises the wrong type for a load-bearing type; sibling `makeSendReader` is named correctly | `netascii.nim:188` | open | Confirmed by read. Fix: rename `makeRecvHandler` |
| S4-7 | Med | Decorator `close`-forwarding (`netasciiSource`/`netasciiSink`) is untested AND currently unreached in production — `toReadData`/`makeRecvSink` use only `.read`/`.write`/`.finish`; the RAW source/sink `close` is what's `defer`-ed. No leak, but forwarded-close is unexercised | `netascii.nim:145,160` | open | Confirmed: raw `source.close()`/`sink.close()` deferred at `server.nim:502/633`. Fix: unit-test forwarding or doc as composability-only |
| S4-8 | Med | `makeRecvSink` finish-failure fold (`if not s.finish(result): result=false`) untested — no sink whose `finish(true)` returns false | `netascii.nim:195-198` | open | Coverage gap; all real sinks hardcode finish=true |
| S4-9 | Low | `memoryBlockSink` unbounded growth → RAM-exhaustion DoS if an embedder wires a memory sink to a network WRQ (tsize advisory, no cap in recvBlocks). Inherent to the primitive; default is file-backed | `blocksource.nim:132-138` | open | Confirmed; proportionate fix = doc caveat (hard cap belongs in embedder/recvBlocks policy) |
| S4-10 | Low | Block-infix naming inconsistency: `netasciiSource`/`netasciiSink` drop "Block" that `fileBlockSource`/`memoryBlockSource` carry, despite returning the same types; will replicate per future decorator | `netascii.nim:126,148` | open | — |
| S4-11 | Low | `netasciiReader` doc overstates production relevance ("call-site compatibility with existing callers") — no `src/` callers remain (disclosed compat shim, handoff R1-6); doc phrasing only | `netascii.nim:162-174` | open | — |
| S4-12 | info | **Accepted/disclosed residual (NOT a round-1 fix):** foreign `BlockSource`/`BlockSink` with a nil closure field → `NilAccessDefect` past `except CatchableError` → single-thread crash / breaks never-raises. Deliberately out of scope per **R1-1** (this RFC catches no Defects; foreign containment deferred to the embedder-hook RFC) | `blocksource.nim:19-47` | wontfix (this RFC) | Security-confirmed real; = the disclosed §6 boundary |
| S4-13 | info | Doc nit: "closes a TOCTOU" claim (blocksource.nim:66 / R1-4) overstated — old code ran the same 3 syscalls with no `await` between, so no race existed to close; the fold is a hermeticity/single-call-site win, not a race fix | `blocksource.nim:66` | open (Low doc) | Security-noted; matches HEAD diff |

**Verified correct (no action):** path-validation ordering (validatePath before any factory, no raw filename reaches it); close fires exactly once on every server exit path via `defer` incl. on `BlockSourceOrderError`, and client via `addCallback`; `toReadData` ascending-once + oversized-read guards enforced & unbypassable; 3-outcome factory contract preserved in `handleRrq` (server side fully tested); errFileNotFound/errAccessViolation split + OS-detail redaction unchanged; slice-2 dead code (`NetasciiReaderError`, old octet closure, old `File` overloads, old chunking) correctly deleted; no unguarded `Option.get` (`sizeOpt.get(0'i64)` safe); BlockSource/BlockSink deep-module shape sound.

### Round-1 fix results (mandate: fix through Medium; delegated sonnet agents; full suite green, 22 suites / 586 checks / exit 0)
- **S4-1 + S4-3 → fixed:** hoisted `defaultBlockSourceFactory`/`defaultBlockSinkFactory` into `blocksource.nim:153-189` (`import std/os`); source default computes `getFileSize` BEFORE `open` (leak gone) and catches `OSError`→re-raises `IOError` (contract stays "IOError only"); `api.nim:172-184` + `server.nim:390-401` collapse to one-line delegation; ALSO widened `handleRrq` catch to `except IOError, OSError` (`server.nim:496`) since a bare injected factory can raise `OSError` directly. RED→GREEN: `t_server.nim` "injected sourceFactory raising OSError … never escapes (S4-1)".
- **S4-2 → fixed:** 3 client error-path tests added to `t_session.nim` (~3452+): PUT+`none`, PUT+`IOError`, GET+sinkFactory-raises-`IOError`, each → `evTransferError`, no raw escape.
- **S4-4 → fixed:** `{.cover.}` added to all 4 adapter closures in `blocksource.nim`.
- **S4-5 → fixed:** confirmed `netasciiSink.finish`+`fileBlockSink.write` subsume the terminal short-write semantics; DELETED `finishNetasciiDecode`/`writeNetasciiTail` + their direct unit tests (`t_netascii.nim`, `t_server.nim`); rewrote a `t_client.nim` test that used `finishNetasciiDecode` as plumbing to drive `makeRecvHandler`/`fileBlockSink`.
- **S4-6 → fixed:** `makeRecvSink`→`makeRecvHandler` (`netascii.nim:188`) + all call sites (`api.nim`, `server.nim`) + docs.
- **S4-7, S4-8 → in progress** (agent 2: decorator close-forwarding unit test; `makeRecvHandler` finish-failure fold test).
- **Lows S4-9/10/11/13 → deferred** per mandate (leave Low). **S4-12 → wontfix (this RFC)** per R1-1.

| id | sev | finding | file | status | proof / verification |
|----|-----|---------|------|--------|----------------------|
| S4-14 | High (transfer.nim — follow-up, fixed on Corey's request) | `recvBlocks` re-checked `cancelCheck` only at loop top, so a **final/single-block write failure was never observed → transfer silently reported success.** Client GET was genuinely vulnerable; server WRQ was already safe via belt-and-suspenders `if writeError.len>0: failResult` at `server.nim:672-673`. | `transfer.nim:517-609` | **fixed** | Minimal `cancelCheck` recheck added immediately after `onData` (every block — also stops ACKing un-persisted data); no signature ripple. RED→GREEN: final-block + single-block write-failure tests in `t_transfer.nim`. Full suite green. |

### Round-2 re-review (3 agents on the fix diff: correctness / security / design)
- **Security → CLEAN.** Confirmed the widened catch closes (not opens) a hole: OS-detail stays on the server-only `diagOut`, never the wire; path containment intact (factory only sees post-`validatePath` resolvedPath); size-before-open leak-free; no new Defect path.
- **Design → CLEAN + complete.** Dedup single-sourced in `blocksource.nim` (no residual bodies); no layering violation; `BlockSourceFactory` doc coherent with the widened catch; rename consistent (zero old-name call sites); dead procs fully gone. (Nit → S4-16 below.)
- **Correctness → found ONE Medium (S4-15) + otherwise clean** (leak fix verified leak-free, short-write/ENOSPC detection preserved through `netasciiSink.finish`→`makeRecvHandler`, no unguarded `Option.get`, resolve* never returns nil).

| id | sev | finding | file | status | proof / verification |
|----|-----|---------|------|--------|----------------------|
| S4-15 | Med | Fix-round asymmetry: S4-1 widened `handleRrq` source-open to `except IOError, OSError` but `handleWrq`'s **sink**-open still catches only `IOError` → an injected `sinkFactory` raising `OSError` escapes uncaught (no `errDiskFull` ERROR packet; client times out; no TransferResult/error event). Same hazard S4-1 closed, still open on WRQ side. | `server.nim:629-637` | **fixed** | `server.nim:632` widened to `except IOError, OSError` (errDiskFull preserved); RED→GREEN test "injected sinkFactory raising OSError … never escapes" in `t_server.nim`. Control-loop verified try-body wraps only the factory call (no over-catch); both factory sites (495/631) now symmetric, zero un-widened sites remain. |
| S4-16 | Low | Stale comment: `"the fileExists/open/sendBlocks path above is untouched"` describes pre-refactor code; the path above is now the `resolveSourceFactory`/`opened.get`/`makeSendReader` factory flow | `server.nim:547` | **fixed** | Reworded to "the source-factory/sendBlocks path above is untouched" |

### Round-3 verify → FLOOR REACHED
S4-15's fix is a proven-symmetric one-line mirror of the round-2-cleared `handleRrq` widening (security+design already blessed that class); control loop verified directly (try-body scope, no residual un-widened site) rather than spending a fresh 3-agent round. **Fix loop terminates: 0 Critical/High/Medium.** Full suite green (`All test files passed`).

### Post-floor cleanup (Corey requested: "fix S4-14 and lows now") — all done, full suite green
- **S4-14 → fixed** (see row above): `recvBlocks` final/single-block write-failure now fails the transfer; client GET was vulnerable, server WRQ already safe.
- **S4-9 → fixed:** `memoryBlockSink` doc caveat (unbounded → RAM-exhaustion DoS if wired to network WRQ; cap belongs in embedder/receive-loop policy). Doc-only, no cap added.
- **S4-10 → fixed:** renamed `netasciiSource`/`netasciiSink` → `netasciiBlockSource`/`netasciiBlockSink` (Block-infix consistency); all `src/`+`tests/` call sites updated, zero old-name hits (docs/rfc history left intact).
- **S4-11 → fixed:** `netasciiReader` doc reworded — directly-tested compat shim, no current production caller.
- **S4-13 → already clean:** no "closes a TOCTOU" claim present in `blocksource.nim` (the S4-1 rewrite already framed the fold as a hermeticity win). No edit needed.

**Everything actionable is now closed.** Only **S4-12** remains open by design (wontfix-this-RFC: foreign nil-closure Defect, disclosed §6 boundary R1-1, deferred to the embedder-hook RFC).

**Nothing committed this session** — Corey-gated. Working tree carries: this RFC's full change (blocksource/netascii/api/server/server_config + tests), the S4-* review fixes, the S4-14 `transfer.nim` fix, and the earlier uncommitted v1 checkpoint + other-RFC work.
