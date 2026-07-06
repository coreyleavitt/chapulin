# Design-bar closure — handoff

- **Stage:** 4 (code-review) **COMPLETE** — 3 rounds, floor reached (R3 re-review found 0 Critical/High/Medium). All 10 slices + all fixes green in Docker, **uncommitted**. → next is **commit** (only when Corey asks; straight to main per [[commit-to-main-always]]).
- **Stage-4 outcome:** R1 = 1 High + 7 Med + 8 Low; R2 (re-review of R1 delta) = 1 Med + 1 Low (new); R3 (re-review of R2 delta) = clean → floor. Fixed: H1, M1–M7, R2-M1, R2-L1, L2/L5/L6/L7/L8. Left: L1 (wontfix — architect-reasoned onStartFired removal), L3 (deferred — startTransfer decomposition = future slice), L4 (deferred — decision-log comment cleanup, batch at RFC archival). Full ledger below.
- **RFC citation drift (for stage-4 awareness):** D6 says "six TransferInfo sites, four via mkTransferInfo"; actual tree has **five** (three mkTransferInfo + two literals: progressCb, final info). Slice 7 covered all five — no phantom missing site. Also slice 5 already removed `checksumModeImplemented`, so slice 8a's constructor folds only `serverConfigBoundsValid` (not the checksum predicate the RFC D7 text mentions).
- **Note for slices 6-7 (type relocation):** slice 4 moved `Event`, `EventKind`, `TransferSnapshot`, `TransferId`/`ServerId`, `TransferDirection` out of `api.nim` into new `src/chapulin/eventqueue.nim` (re-exported from api.nim; public surface unchanged). So slice 6 edits `Event.errorCode` in eventqueue.nim (not api.nim), and slice 7 edits `TransferSnapshot` in eventqueue.nim.
- **Note for slice 7:** slice 2 set the seam's `requestedAsk` from `askedParams(pkt.options)` directly in `handleRequest` (real value, inert). Slice 7 should consolidate to the value threaded on `NegotiationOutcome.requestedParams` (slice 1) via `TransferInfo` and drop the now-duplicate `askedParams` call in `handleRequest`.
- **Resume:** commit when Corey asks (straight to main; trailer lines per session rules). Stage 4 done — RFC is ship-ready. Safe to `/compact`. NOTE: nothing is committed yet — the whole RFC's changes (10 slices + 3 review rounds) sit dirty in the working tree. eventqueue.nim is a NEW untracked file (expected). Do NOT reuse scratchpad msg-feat.txt/msg-docs.txt — those are the *other* RFC (rfc-conformance-closure); draft a fresh design-bar-closure message.
- **RFC:** `docs/rfc/design-bar-closure.md`
- **Contract before Stage 3:** both architect rounds done AND the RFC reflects their fixes.
- **Origin:** the design-assessment punch-list (server.nim + api.nim below the bar; core modules already at it). Corey chose **full redesign now** (breaking public-surface changes included; best done before the oyamel GUI ports onto api.nim). CLI updated in-repo as part of the breaking slices.

## Verified before drafting (so the spec isn't built on audit hearsay)
- **Pre-clamp snapshot bug — REAL** (api.nim:216-217 raw bs/ws; :247-248 clamped for wire; :342-343 + zeroSnap echo raw). → fixed by D6.
- **errorCode==0 collision — REAL** (api.nim:361,378 hardcode `errorCode:0`; `errNotDefined=0`). → fixed by D5.
- **"=destroy phantom docstring" — FALSE / hallucinated by an audit agent** (no `=destroy` anywhere in `src/`; no such docstring in api.nim). Dropped from scope. (Also caught: one audit mislabeled `design-philosophy.md`'s path — it's at repo root, not `docs/`.)

## Architect round 1 (2026-07-05) — applied to RFC
4-agent team (depth/breadth/design/feasibility). All findings clear-best except ONE genuine escalation.
- **Escalation resolved:** R2's "identical semantics" was vacuous server-side (TransferInfo carries only post-negotiation values). Corey chose **true parity** → thread the client's clamped ask into TransferInfo (D6, slice 7).
- **Blockers fixed:** D1 `var TransferConfig` on async proc won't compile → thread via return; D1 missing bare-WRQ ACK(0) divergence → negotiateWrq owns it; D5/Scope contradiction (touches transfer.nim/engine.nim) → explicit carve-out; D4 popFirst IndexDefect → `tryPopFirst: Option[Event]`.
- **Majors fixed:** D1 wrq:bool smell → `negotiateCore` + `negotiateRrq`/`negotiateWrq` wrappers (+ `onStartFired`/`oackSent` in NegotiationOutcome); D4 ordering rule specified (position-pinned replay); D7 → flat `ServerConfigOutcome` (not raise/Result); D7/R4 keep all 3 guards (ServerConfig fully public/mutable, startServer bypassable); D3 drop case-object → flat `{cancelFlag}`; D6 → flat `requested`/`effective`/`settled` (not Option); D10 add event-ordering + cancellation contracts + embedding-api.md update; slice 8 → 8a/8b; slices 1/2/4 gain missing test pins; slice 5 = delete 3 test blocks (compile-break, not assertion edit).
- **Minors fixed:** citation fixes (osResult :272/:462; handleWrq ~117 lines; CLI 11 fields); D2 "eff* duplication" claim corrected (closures already share by ref); docker-compose dev suite omits t_checksum/t_netascii.
- **Held clean:** both verified bugs; D9; D8 distinct range types; D10(b) asyncCheck→addCallback.
- **New open item for round 2:** D8/R3 per-scalar distinct client types still deferred; verify round-1 edits didn't introduce new weak spots (esp. the TransferInfo client-ask threading + D4 placeholder mechanism).

## Architect round 2 (2026-07-05) — applied to RFC
4-agent team (depth/breadth/design/feasibility). ALL findings clear-best — **no genuine forks this round**.
Three of four lenses independently converged on the round-1 server-parity thread being under-scoped.
- **Dominant finding — D6 server-side parity re-scoped (depth+breadth+feasibility+design):** the client's
  clamped ask has no parse source (raw wire strings; `options.nim` parser is out-of-scope + server-limit
  clamped, not RFC-clamped). Resolution: (1) new **pure best-effort helper in `server.nim`**, per-option
  independent, RFC-clamp, unparseable→default; (2) documented limitation — a malformed option makes the
  ask unknowable server-side (degenerate, coincides with ERROR(8)); (3) compute once in `negotiateCore`,
  carry on `NegotiationOutcome.requestedParams` (slice 1 plumbing); (4) store in **D2's seam** as immutable
  sibling (slice 2 plumbing); (5) **six** TransferInfo construction sites not four (`mkTransferInfo`×4 +
  progressCb `server.nim:580-588` + final info `:640-650`) → `requested` maps at all four `api.nim`
  callbacks. Slices 1/2/7 each carry their part; slice 7 now READS the pre-plumbing, not reopens it.
- **D4 event queue redesigned:** placeholder-split had a comment/rule contradiction, silent event-loss on
  push-drain-push, unbounded `progress`-table growth, and its natural form is a case-object (forbidden).
  Replaced with **key-redirection** (`order: Deque[int]` + `payload: Table[int,Event]` + `progressKey:
  Table[TransferId,int]`): coalesce = in-place overwrite at existing key; drain clears the key; stated
  invariant; no placeholder, no case-object, bounded. Slice 4 adds push-drain-push + bounded-growth tests.
- **D1 tightened:** dropped `clientHost`/`clientPort` (redundant with `peer`); grouped invariant
  request-fields into a `NegotiationRequest` context object (×3 repetition across core+2 wrappers);
  **removed `onStartFired`** (dead — the onStart asymmetry is structural: core fires ValueError-path
  onStart, handler fires success-path onStart only on `ok`); named the two outcome conventions
  (bool-gated vs kind-gated) + added in-type "meaningful iff" comments.
- **Minors fixed:** `waitTransfer` (`api.nim:649`) named as 3rd errorCode producer + slice-6 regression
  test; `t_integration.nim` compile-check added to slice 6; `t_props_server.nim`/`t_props.nim` named as
  slice-1/2 spec; slice-8b keeps the post-mutation-still-rejected test (R4 coverage) + the constructor
  test; `TransferParams` sourced once from `protocol.nim`; `effective` field gets a pre-settlement-trap
  WARNING doc-comment; citation nit (~31 lines, not "three lines"); 10-param signature.
- **Held clean:** client-side D6 shape; D3 flat record; D5/D9; D7 ServerConfigOutcome; D8 range types;
  bare-request settled semantics; all round-1 citations re-verified byte-accurate by feasibility.
- **One thing for Corey's awareness (not a blocker):** his true-parity choice has one degenerate — a
  *malformed* client option is unknowable server-side, so `requested` falls back to defaults for that
  field. Resolved as best-effort-with-documented-limitation; veto-able if he wants different degenerate
  handling.

## Slices (now 8a/8b split → 1-7, 8a, 8b, 9; internal-under-green → breaking surface → docs)
- [x] 1 — D1 server handshake primitive (`negotiateCore`/`negotiateRrq`/`negotiateWrq`); collapse handleRrq/handleWrq. Refactor under green (t_server + t_props_server + t_props). Preserves RRQ ACK(0)-wait vs WRQ send-and-return asymmetry. **DONE** (2026-07-05): `TransferParams` added to protocol.nim; `askedParams` D6 helper + `NegotiationOutcome.requestedParams` plumbing (inert until 7); 10 new t_server tests (onStart-before-ERROR(8) pin, bare-WRQ ACK(0), askedParams unit); all 3 suites green. Uncommitted.
- [x] 2 — D2 decompose handleRequest (port-range alloc helper, unify eff* seam) + transport.nim byte↔string dedup. Under green. **DONE** (2026-07-05): `allocateTransferTransport` extracted (RED-first port-range-retry test); `TransferSeam` object unifies `eff*` + immutable `requestedAsk` sibling; `toWireString`/`toByteSeq` dedup at 3 sites; t_server/t_props_server/t_props green. Uncommitted.
- [x] 3 — D3 api.nim 4 tables → 1 `Table[TransferId, TransferRecord]`. Under green (t_session spec). **DONE** (2026-07-05): `TransferEntry.transport` confirmed dead; case-object dropped; `TransferRecord{cancelFlag, origin}` (flat `origin: TransferOrigin` enum tag added — no Defect surface — to keep client-force-cancel vs server-drain distinction after table merge); `cancel` now kind-agnostic single lookup; test-accessors re-pointed; t_session/t_client green. Uncommitted.
- [x] 4 — D4 extract `EventQueue` type (O(1) progress coalesce) + direct unit tests. **DONE** (2026-07-05): new `eventqueue.nim` module (key-redirection: Deque[int]+Table+progressKey), `push`/`tryPopFirst`/`len`; event types relocated there + re-exported from api.nim (incl. `export ==`); 11 direct tests (coalesce, empty tryPopFirst, eviction/dropped-count, cross-kind ordering, invariant); registered t_eventqueue in dev-test.ps1; t_eventqueue/t_session/t_api/t_client green. Uncommitted.
- [x] 5 — D9 remove `csSha256` dead generality (ChecksumMode → {csNone,csMd5}; drop 4 dead arms + checksumModeImplemented). **DONE** (2026-07-05): enum→{csNone,csMd5}; `checksumModeImplemented` removed + both call sites (api.nim startServer, server.nim handleRrq); `parseChecksumMode` "sha256"→plain else; 4 checksum.nim arms gone; 3 named test blocks deleted + a 4th parseChecksumMode test updated (rejection kept, stale msg dropped); grep-clean; t_checksum/t_server/t_session green. Uncommitted.
- [x] 6 — D5 **BREAKING** errorCode → `Option[TftpErrorCode]` (TransferResult/Event/TransferInfo). Fixes errorCode==0. No CLI change (CLI never reads .errorCode). **DONE** (2026-07-05): 3 fields migrated (transfer.nim, eventqueue.nim, server.nim); all producers split some/none; `failResult` default→none; `TftpErrorCode` added to api.nim exports; 2 regression tests (local-fail→none, waitTransfer round-trip→some); t_client/t_server/t_session green; t_integration compiles (linux container); CLI grep-clean. Uncommitted.
- [x] 7 — D6 **BREAKING** TransferSnapshot → flat `requested`/`effective`/`settled` (`TransferParams` from protocol.nim). Fixes pre-clamp. Server parity: reads slice-1 `NegotiationOutcome.requestedParams` + slice-2 seam sibling, maps `requested` at all 4 api.nim callbacks / (actual) 5 server.nim TransferInfo sites. No CLI change. **DONE** (2026-07-05): flat snapshot in eventqueue.nim; clamp-once in startTransfer (structural fix); `TransferInfo.requestedParams` threaded from `NegotiationOutcome.requestedParams`; slice-2 duplicate `askedParams` consolidated (onStart reads info.requestedParams); `settled` flips in onNegCb (before any progress); 3 new + updated t_session tests (a/b/c/d/e); t_session/t_client/t_server/t_eventqueue green; t_integration compiles. Uncommitted.
- [x] 8a — D7 **BREAKING** `newServerConfig` → `ServerConfigOutcome` over bare-int fields; CLI + desktop GUI migrated; all 3 `serverConfigBoundsValid` guards kept (R4). **DONE** (2026-07-05): 5 tests; t_session/t_server green; CLI + GUI compile-verified (GUI binary produced). Uncommitted.
- [x] 8b — D8 **BREAKING** swap 4 bare min/max ints for `BlocksizeRange`/`WindowsizeRange` inside the constructor; ripples to serverOptionLimits + CLI + t_session field-poke test rewrite. **DONE** (2026-07-05): range types + raising `newBlocksizeRange`/`newWindowsizeRange` wrapped by never-raising `newServerConfig` (try/except→rejectReason); `serverOptionLimits` rippled; CLI/GUI no ripple; 10 constructor-rejection tests + rewritten 8-case belt-and-suspenders; t_session/t_server/t_client green; CLI compiles. Uncommitted.
- [x] 9 — D10 docs: new `docs/api-reference.md` + fix `design-philosophy.md:72` asyncCheck→addCallback. Review-verified, not test-verified. **DONE** (2026-07-05): api-reference.md created (TftpSession entry, 9 EventKind values grep-verified, happy-path, never-raise, event-ordering + cancellation contracts, post-D5/D6 shapes); embedding-api.md snippets/example updated to Option errorCode + requested/effective/settled; design-philosophy.md asyncCheck→addCallback (both occurrences). Historical decision-log narrative intentionally left. Uncommitted.

## Open forks (awaiting Corey)
- Resolved this session: **full redesign now** (the scope fork). Resolutions R1–R4 in the RFC are recommended + veto-able.
- **R3/D8 per-scalar distinct client types — RESOLVED (both architect rounds): stays deferred/out of scope.** Neither round pushed for it; design round 2 confirmed the server `{min,max}` pair is the real asymmetry (→ D8 range types), a single client scalar with one clamp is not under-modeled. Not a committed slice.

## Key decisions (this session)
- errorCode fix = **flat `Option[TftpErrorCode]`, not a variant** (preserve never-throw/no-FieldDefect discipline; matches OackOutcome flatness). [[never-throw-defect-hazard]]
- Snapshot fix = **requested (clamped) + negotiated(Option)**, identical client/server semantics — subsumes the pre-clamp bug structurally.
- ServerConfig fix = **validating constructor as the choke point** (removes api.nim:417 re-validation; handleRrq/Wrq keep belt-and-suspenders guards as directly-callable exported entry points).
- D3's `TransferRecord` **case-object is OK** — internal routing data, never a client-facing never-throw boundary.
- NetasciiPolicy relocation + per-scalar distinct types = low-priority/architect-discretion, not committed slices.
- Core modules (protocol/transfer/options/engine/security) explicitly **out of scope** — already at the bar.
- Land on `main` per [[commit-to-main-always]]; verify each slice in Docker per [[no-local-builds-ci-verifies]].

## Review ledger (stage 4)
Round 1 (2026-07-05): 4 dimensions (correctness/quality/security/design) on sonnet. H1 verified directly against eventqueue.nim by the control loop; converged by correctness+security independently. Doc/dead-arm claims grep-confirmed.
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| H1 | High | EventQueue protected-event cap escape → unbounded growth / remote DoS (malformed-option flood = 2 protected events/pkt; warning-flush re-fills evicted slot → +1 retained/push) | fixed (R1) | Corey chose policy (A) true hard ceiling. eventqueue.nim push now reserves room, evicts logs then drop-oldest (terminals included), warning-flush can't overflow. TDD: RED confirmed 6→15 unbounded → GREEN bounded. tests/t_eventqueue.nim new flood test + 2 eviction tests updated; api-reference.md bounded-contract section added. |
| M1 | Med | api-reference.md omits entire ServerConfig construction path (newServerConfig/ServerConfigOutcome/Blocksize/WindowsizeRange) — D10 gap for oyamel consumer | fixed (R1) | added "Building a ServerConfig" section (both overloads, never-raise .ok/.rejectReason, raising range constructors) |
| M2 | Med | design-philosophy.md:78 stale — claims GUI uses background thread+waitFor; actually poll() on startRepeatingTimer(50) | fixed (R1) | rewrote sentence to poll-on-timer model; CLI/asyncCheck lines untouched |
| M3 | Med | chapulin.nim:88 stale TODO(#13) — netascii IS wired end-to-end; comment misleads | fixed (R1) | stale comment block deleted (no accurate caveat needed) |
| M4 | Med | dead evTransferLog EventKind arm — no producer in src/ (consumer+tests only) | fixed (R1) | removed enum+fields, LogKinds→{evServerLog}, GUI/CLI consumer arms, api-reference count 9→8, t_eventqueue mkLog repointed |
| M5 | Med | TransferSnapshot.effective+settled reintroduces the plausible-sentinel shape D5 rejected; Option[TransferParams] proposed | fixed (R1) | Corey's pick: effective→Option[TransferParams] (none=unsettled), settled field dropped; all producers/consumers/tests/docs updated; suite green |
| M6 | Med | NegotiationOutcome.oackSent/oackData duplicate one bit (oackSent == oackData.len>0 always) | fixed (R1) | dropped oackSent; all readers check oackData.len>0; OACK-retransmit path unchanged; t_server green |
| M7 | Med | D8 "invalid pair unrepresentable" overclaims — newServerConfig still takes 4 loose ints (deliberate, documented) | fixed (R1) | RFC D8 softened + added range-accepting newServerConfig overload (shared buildServerConfigOutcome); 4-int form delegates; CLI/GUI unchanged; 3 t_session tests |
| L1 | Low | onStart firing split across 3 procs, no type-level anchor (onStartFired) | fixed (R3, "fix lows") | NOT via re-adding the dead field (would reverse architect decision). Closed the testability gap instead: audited t_server (branches 1+3 already pinned), added the missing branch-2 test — failed post-OACK ACK(0) wait does NOT fire onStart (asserts startFired==0, only OACK sent). Asymmetry now test-anchored. t_server green. |
| L2 | Low | D3 "only other table" claim wrong — two per-server tables (xfers + cancelFlags) | fixed (R1) | D3 wording corrected to acknowledge both tables |
| L3 | Low | startTransfer ~210 lines undecomposed (same shape D2 fixed in handleRequest) | fixed (R3, "fix lows") | extracted setupGetTransfer/setupPutTransfer; startTransfer now thin clamp→dispatch→wire→launch orchestrator; clamp-once/mkSnap/inEffect/Option[effective]/cancel bookkeeping untouched; var-capture handled via getEffective closure; t_session/t_client green, no test edits |
| L4 | Low | comment archaeology (D1/D2/R tags) will rot once RFC archived | fixed (R3, "fix lows") | rewrote all design-bar-closure-internal D/R/L/M/H/FIX citations in api.nim + server.nim as self-contained prose (kept the rationale, dropped the dangling letters); preserved real anchors (RFC 13xx, issue #s, other named RFCs). Comment-only (git-diff verified); t_server/t_session green. |
| L5 | Low | poll() drives process-global asyncdispatch — undocumented cross-session coupling | fixed (R1) | api-reference.md callout added |
| L6 | Low | waitTransfer/waitServer safety valve is iteration-count (5M), not a caller timeout | fixed (R1) | api-reference.md note added (bound via engine/transfer config) |
| L7 | Low | newBlocksizeRange/newWindowsizeRange near-duplicate; extract validateRangePair helper | fixed (R1) | private validateRangePair(min,max,hardMin,hardMax,label) extracted; both constructors delegate |
| L8 | Low | negotiateServerOptions tsize lacks <0 guard (client-side validateAndParseOack has one) | fixed (R1) | <0 guard added in options.nim (negative tsize treated as absent); 2 t_server tests; behavior-preserving hardening |

Round 2 re-review (2026-07-05): correctness/security/design on the R1 delta. H1 drop-oldest/progressKey verified clean by all three (evictOldestAny mirrors tryPopFirst cleanup; order/payload/progressKey all pinned ≤ cap). M5/M6/M7/L8 hold; M6/M7/docs/L1 explicitly "at the bar." Two NEW items:
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R2-M1 | Med | R1 M5 doc left embedding-api.md example as bare `ev.snap.effective.get.blocksize` → UnpackDefect (escapes except CatchableError) pre-settlement; steers oyamel embedder into the never-throw-Defect hazard. No safe accessor exists; internal api.nim uses get-with-fallback, doc uses bare get | fixed (R2) | [[never-throw-defect-hazard]]; added inEffect*(snap)=effective.get(requested) + Option overload, re-exported via api.nim; api.nim:283 uses it; embedding-api.md + api-reference.md de-trapped (grep-clean of bare .effective.get); 3 t_eventqueue tests |
| R2-L1 | Low | H1 push invariant "len ≤ cap always" violated for cap∈{0,1} (give-up path double-appends warning+ev); comment says "only cap≤0" | fixed (R2) | initEventQueue doAssert cap>=2 (documented precondition — needs room for event+coalesced warning; cap is compile-time 8192); comment corrected; cap=0/1 raise AssertionDefect, cap=2 boundary test holds len≤cap |
