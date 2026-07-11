# Verification Harness v2 — handoff

- **Stage:** 2 (architect) — **BOTH ROUNDS DONE.** Round 2 = 4-lens team, all source-grounded; ~20 clear-best fixes applied to RFC; **zero open forks** (all round-2 findings carried a recommendation → resolved, none escalated).   •   **Round:** 2 of 2 complete.
- **Resume — the BlockSource/BlockSink RFC has LANDED (2026-07-11): Part A1b is UNBLOCKED.** The prerequisite `in-memory-sources-sinks.md` completed Stage 3 (all 5 slices green, full suite passing) — the injectable `sourceFactory`/`sinkFactory` seam now exists on both `TftpSession` and `ServerConfig`, and a two-party in-memory RRQ/WRQ round trip over Wire is proven (`tests/t_blocksource_demo.nim`). **v2 Stage 3 can now proceed** across all of A/B/C. v2 RFC itself is Stage-2-complete, zero open forks. **Next: enter v2 Stage 3** (`/loop` its slices) — start with A1 (Wire↔session seams), which A1b now builds on.
- **BlockSource/BlockSink RFC:** `docs/rfc/in-memory-sources-sinks.md` — **Stage 3 COMPLETE (implemented, green)**; see its handoff `docs/rfc/in-memory-sources-sinks.handoff.md` (heading into its own Stage 4 `/code-review`). **NOT GitHub issue #13** — that "#13" label was misattached and is dropped (Corey 2026-07-11). Escalation below RESOLVED; kept for history.

## ⚠️ ESCALATION — the "#13" premise was stale (GitHub issue #13 ≠ what v2 needs) — RESOLVED 2026-07-10
Exploration + self-verified greps overturned the assumption behind "draft #13":
- **#13's production goals are ALREADY SHIPPED.** Netascii is fully wired + tested (not a no-op): `makeSendReader`/`makeRecvSink` (`netascii.nim:205,303`) apply CR/LF on both directions, called from `server.nim:498/613` + `api.nim:210/263`; streaming `NetasciiEncoder/Decoder` w/ pending-CR carry; 425-line `t_netascii.nim`. Landed in `ca955f7`. Closures NOT hand-duplicated (retransmit unified in `transfer.nim` `windowCache`). tsize-under-netascii decided = "omit" via `netasciiPolicyFor`. Issue #13 is CLOSED + stale; RFC #17's "netascii orphan / TODO(#13)" para is dead prose.
- **The only real residue = exactly what v2 Part A(b) needs:** `makeSendReader`/`makeRecvSink` take a concrete `File` opened INLINE at 4 call sites → **no injection point for an in-memory backing store.** No `BlockSource`/`BlockSink` exists (greenfield). Issue #13's own "no seam exists" blocker is GONE (the seam = those 2 constructors); residue is just DI of the byte backing store (~4 call sites + 2 signatures). Netascii/retransmit stay.
- **Scope (interpreted from Corey's steer 2026-07-10 — NOT an explicit 4-option pick):** Corey did not choose among the enumerated options (1)-(4); he said *"best-in-class, PhD-level design, effort no object."* That quality bar selects the broad end: a general-purpose, first-class production `BlockSource`/`BlockSink` abstraction (embedder-supplied streams for #17, transforms beyond netascii as composable decorators, honest async scoping), not the narrow shim. *(An earlier subagent fabricated a "Corey chose broader than (1) (2026-07-10)" ledger line + drafted the RFC ahead of the selection gate; corrected here. The design bake-off (4 lenses) ran; the draft synthesizes them and is Opus-reviewed, but Corey has not yet formally signed off on the design — architect round 1 is the next hardening gate, and Corey may still redirect.)*
- **Resume:** ✅ the BlockSource/BlockSink RFC LANDED (Stage 3 complete, green, 2026-07-11). v2 is unfrozen; Part A1b's file-in-memory dependency is satisfied. v2 RFC itself is Stage-2-complete, zero open forks — ready to enter Stage 3.
- **RFC:** `docs/rfc/verification-harness-v2.md`
- **Scope (Corey chose 2026-07-10):** ALL THREE parts — (A) api.nim facade stateful target over Wire, (B) symex extensions downward, (C) soak campaign + corpus.
- **Origin:** follow-ups Corey raised after v1's Stage-4 code review — "larger/better fuzzing corpus?", "more symex coverage?", "more coverage of api.nim (the real core)". v1 (`verification-harness.md`) is complete; its disclosed gaps (api.nim transitive-only, maxConcurrent untested, symex option-parsers-only, no soak/corpus growth) are v2's targets.

## Slices
Part A (facade): 
- [ ] A1 — Wire↔session seams (TransportFactory + ListenerFactory adapters) + client/server session get+put smoke over Wire
- [ ] A2 — facade stateful StateMachine (op vocabulary + core never-throw invariants; no injection)
- [ ] A3 — hostile injection into facade + VacuityCounter anti-vacuity; coverage-guided + corpus
- [ ] A4 — maxConcurrent enforcement invariant
Part B (symex):
- [ ] B1 — symex protocol.decode (tIndexError/tFieldDefect)
- [ ] B2 — symex validatePath/checkWriteAccess lexical
- [ ] B3 — symex writeSidecar lexical
- [ ] B4 — tsize unblock (proptest parseBiggestInt bump; retire parseInt sub) — gated on proptest-manifest PR
Part C (soak):
- [ ] C1 — fuzzWith soak scaffold (opt-in, one target e2e) — blocked by env fork for CI
- [ ] C2 — seed dictionary (boundaries + known-bad + reserved names)
- [ ] C3 — real captured-packet seeds from interop tests
- [ ] C4 — corpus minimization pass + committed minimized corpus
- [ ] C5 — coverage-gap reporting (edge-bitmap diff)

## Open forks (awaiting Corey — after architect round 1)
1. ~~Part C soak environment~~ — **RESOLVED: local-opt-in only** (no CI).
2. ~~Part B4 sequencing~~ — RESOLVED: dependency not fork (B1–B3 independent; B4 last).
3. ~~FORK A~~ — **RESOLVED (Corey): (b)** — two real sessions, file I/O in-memory via the **BlockSource/BlockSink seam** (its own RFC, `in-memory-sources-sinks.md`). ✅ **That RFC has now LANDED (Stage 3 complete, green, 2026-07-11) — A1b is UNGATED.** Everything (all of A/B/C) is now unblocked. *(NB: not GitHub issue #13 — that was a separate, already-shipped change; the misattached label is dropped.)*
4. ~~RFC structure~~ — **RESOLVED (Corey): one umbrella** (A/B/C = independent tracks in this RFC).

## Architect round-1 findings (source-verified — applied to RFC)
- **A4 maxConcurrent**: reject path `server.nim:701/852/862` calls `newUdpTransport(0)`, bypassing `transferFactory` → real socket + Wire-unobservable. Fix: 1-line prod reroute + structured signal (not log substring) + N-Wire-per-call registry + own anti-vacuity counter. "Zero prod refactor" claim corrected.
- **B1**: `seq[byte]` has NO symex witness reader → compile error. Fix: `seq[int]`-masked(0..255) twins (preserves indexing); scope decode to fixed-size arms; option-parsing arm a separate ≤2-option bounded twin (readOptions loops vs maxLoopUnwind=5).
- **A1 listener**: genuinely new architecture — Wire↔listener request bridge doesn't exist (`swallowFirst` discards client's 1st send); re-sliced A1a(bridge)/A1b(smoke). A4 decoupleable via hand-fed ListenerQueue.
- **A determinism**: invariant hook must use fixed-tick pump, never drain()/waitTransfer() (wall-clock epochTime); single global dispatcher → one shared pump op, not per-session.
- **A Defect-detection contingent**: needs a Defect-canary (prove pipeline reports "crashed:") + asyncCheck-in-src tripwire (guarantee rests on synchronous pump + zero asyncCheck in src/).
- **C**: fmIR mode (persists to corpus default replays) + byte→IR seed encoder; minimalCovering is a real built-in (C4 de-risked) + size ceiling; C5 no edge→source API → re-scoped to coarse before/after count (full report deferred §8); C3 no pcap capture in repo → capture-point prereq; dev-test.ps1 -Soak mode + -CorpusReport verb + provenance tagging.
- **Validated clean (no change)**: B2/B3 string witness; B4 gating accurate; --panics:off real (reaffirmed as load-bearing for A/B/C).
- Added: shared injection-rule module (extract from t_hostile, don't duplicate/absorb); netascii+blocksize op variety; doc-update slice; quantitative success bars; §8 considered/deferred (differential testing, the BlockSource/BlockSink seam, full coverage report).

## Slices (revised — architect r2; supersedes r1 list)
Part A: [ ] A-shared (extract BOTH inject families {same-TID + off-TID}, notify non-var + pumpSession helper + call-form asyncCheck tripwire + StateMachine-routed committed Defect-canary) · [ ] A1a-i (Wire registry + minting factory, round-robin index NOT port-key; shared w/ A4) · [ ] A1a-ii (listener bridge makeListenerFromWire + client port-adoption — the novel piece) · [ ] A1b (get/put smoke; **gated on the BlockSource/BlockSink RFC**) · [ ] A2 (stateful + pumpSession + never-throw invariants + narrow waitTransfer/waitServer property) · [ ] A3 (hostile injection + anti-vacuity, both-sides liveness) · [ ] A4 (3-site prod reroute + onRejected hook/EventKind + anti-vacuity on server.activeTransfers==maxConcurrent)
Part B: [ ] B1 (decode seq[int]-masked twins + differential oracle) · [ ] B2 (validatePath/checkWriteAccess pre-I/O twin + tftp_uri parseTftpUri/isTftpUri) · [ ] B3 (writeSidecar lexical + netascii decode feed/flush twin) · [ ] B4 (tsize unblock — gated, Corey-owned proptest fork)
Part C: [ ] C0 (factor nimcontainer.ps1 helper) · [ ] C1 (fuzzWith fmIR scaffold + -Soak via env-var→timeBudget + first-Defect stop/commit/exit≠0) · [ ] C2 (byte→IR encoder round-trip-through-actual-strategy + dictionary) · [ ] C3 (capture point + harvest) · [ ] C4 (minimalCovering + ceiling + provenance) · [ ] C5 (coverage-progress, synthetic-target RED + -CorpusReport)
Cross: [ ] Docs (SECURITY.md + README claim rows)

## Architect round-2 findings (source-verified — applied to RFC)
- **A4 anti-vacuity counter conflation (Breadth + Design, 2× confirmed — was a latent Critical):** the r1 spec keyed anti-vacuity on `activeClientCount == maxConcurrent`, but `activeClientCount` (api.nim:127-132) = session's own OUTBOUND startTransfers; `maxConcurrent` gates `server.activeTransfers` (server.nim:859) = INBOUND — disjoint paths. As written the invariant was unreachable. Rekeyed to `server.activeTransfers == maxConcurrent` via the onRejected Event.
- **A4 "one line" is 3 sites + new signal plumbing (Depth + Feasibility):** server.nim:701/852/862 each build newUdpTransport(0); reject fires before reqId minted so needs new onRejected ServerCallbacks hook + EventKind + api wiring. Sized as a prod sub-slice.
- **Table[port,Wire] registry degenerate under default config (Design, HIGH):** portRangeStart/End default 0 → transferFactory(0) every call → single key. Fixed to round-robin call-order index (proven t_session.nim:455-464).
- **A1a is 2+ slices (Feasibility, HIGH):** split A1a-i (registry) / A1a-ii (listener bridge + client port-adoption — the genuinely novel, highest-risk piece; A4's registry = this generalized 1→N).
- **B2 "no blocker" false (Feasibility, HIGH):** validatePath/checkWriteAccess bodies call unmodeled syscalls (canonicalize/symlinkExists) → same macro-expansion wall as B1; needs own pre-I/O twin extraction.
- **Defect-canary proves wrong branch (Depth):** StateMachine invariant-Defects surface via "strategy crashed:" (eval.nim ~92), not plain "crashed:" (~110); canary must raise from inside a rule/invariant + be committed always-run + a re-run gate on B4's proptest bump.
- **decode twin: compile ≠ semantic equiv (Depth):** added concrete differential oracle vs real decode(seq[byte]); 0..255 mask must constrain every element use.
- **fmIR encoder round-trip insufficient (Depth):** must run seeds through the ACTUAL strategy (strategies filter/rescale) and assert concrete value == intended boundary.
- **-Soak mechanism = env var, not -d: (Feasibility):** `docker run -e … → getEnv → native FuzzSettings.timeBudget` (no recompile-per-budget; r1 overstated the obstacle). + factor nimcontainer.ps1 helper (C0) to keep dev-test.ps1's contract clean.
- **New symex targets added:** tftp_uri.parseTftpUri/isTftpUri (B2), netascii decode feed/flush (B3) — same witness classes, no new toolchain.
- **Coverage additions:** pumpSession helper (avoid per-file magic-tick redrivation); waitTransfer/waitServer narrow property in A2; both-sides liveness predicate; A-shared extracts BOTH off-TID + same-TID families (8 builders); notify typed non-var (compiler-enforced read-only); zero-real-socket measured by a counter in the default factory.
- **C5 flakiness (Feasibility):** RED test uses a synthetic under-covered target (real converged corpus can add 0 edges on the coarse 8192-slot bitmap); real-target increase = one-time §7 demo.
- **§8 deferrals added:** multi-TftpSession crosstalk; waitTransfer/waitServer deep coverage.
- **Precision fixes:** asyncCheck tripwire anchored to call-form `asyncCheck\(` (api.nim:581 is a comment); B4 dep is Corey's own proptest fork (track w/ ticket); citation lines re-pinned.

## Key decisions (this session)
- Bundled all three workstreams into ONE RFC (Corey's scope choice), sliced so each part is independent; soak (Part C) explicitly splittable if it proves too heavy in architect.
- api.nim reframed: it's the never-throw *boundary* + embedding surface (RFC #17), not the algorithmic core — but that's exactly why direct coverage is the top-value gap. Tool-fit: api.nim → stateful property (NOT symex; z3 can't model async/IO); symex extends downward to pure cores only.
- Enabling seam for Part A (`transportFactory`/`listenerFactory`) confirmed present in `api.nim:146-148` — no production refactor needed; listener side flagged as needing feasibility check in A1.

## Prereqs / context for implementers
- Tests run ONLY via `pwsh scripts/dev-test.ps1 [suite]` in Nim Docker Windows containers (no host Nim). Symex suites (`t_symex*`) auto-select `chapulin-symex:2.2.10` (z3). FFI-free bar = shipped `src/` only.
- Reuse v1: `fuzzsupport` (fuzzProperty/VacuityCounter/CorpusDir/generators), `wireharness` (injectPacket/Wire), `t_symex*` convention, `Dockerfile.symex`.
- v1 is committed? NO — v1's full checkpoint (10 slices + code-review fixes + Lows) is still UNCOMMITTED in the working tree awaiting Corey. v2 work stacks on top of that uncommitted state.

## Review ledger (stage 4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| —  | —   | (populated at stage 4) | — | — |
