# Checksum integrity + error hygiene — handoff

- **Stage:** 4 (`/code-review`) **COMPLETE — fix loop hit the floor (0 Critical/High/Medium open); K1 hardening added + re-verified**   •
  **Next:** Corey's call — commit everything (nothing committed yet), disposition deferred/accepted items, reconcile HEAD.
- **Resume:** decide commit + M6/#17 defer + 3 round-2 scope-expansion vetoes. Findings: round-1 (15) + re-review R2/R3 (3) +
  K1 slice + K1 re-review (2 incl. a LIVE sidecar bypass) — ALL resolved. Fixed: H1,H2,M1,M2,M3,M5,M7,M8a,M8b,L2,L3 + R2-1,R2-2,R2-3,R3-1 + K1 + K1-a,K1-b,K1-c.
  By-design: M4,L4. Deferred: M6→#17. Accepted: K1 trade-off (Windows denies in-root symlink serving). Left (Low): L1,L5,K1-d, escape_dir teardown red.
- **Verification:** whole suite delta-green in BOTH containers. K1 BONUS: #19 symlink baseline reds now PASS on Windows (only remaining
  t_security Windows red = pre-existing `escape_dir` test-teardown Access-denied, zero delta); Linux compose fully green.
- **K1 was NOT in the original RFC** — added this session at Corey's request as a real FFI-free fix for the accepted Windows containment gap.

## Review ledger (stage 4, round 1)
Four dimensions (Correctness, Security, Design&ergonomics, RFC-fidelity) run in parallel; High/Medium claims
verified by direct code trace (Nim absent on host). Root causes cross-linked.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| H1 | High | `.md5` reservation bypassed by in-root symlink alias: `checkWriteAccess` tests the LEXICAL path (security.nim:116), not the symlink-resolved real path → WRQ to `foo`(→`bar.md5`) forges/overwrites a sidecar | **fixed** (batch A) | `checkWriteAccess` now checks `isReservedSidecarName` on lexical AND `canonicalize`d path (OSError→lexical fallback). RED (e2e) genuinely overwrote legit.md5; GREEN in Linux container. Windows = accepted K1 best-effort (capability-probe skip). |
| H2 | High | `csSha256` landmine: constructible-but-illegal enum guarded by 3 scattered checks; RRQ path (server.nim:232 `== csMd5`) SILENTLY no-ops for csSha256, reproducing the pre-RFC bug for direct handleRrq consumers; startServer rejection untested | **fixed** (batch B) | Single authority `checksumModeImplemented*` in server_config.nim; parseChecksumMode + startServer + new handleRrq early-guard all route through it. handleRrq fails loud (generic wire msg, D2-safe). RED reproduced silent no-op; GREEN. csSha256 kept in enum (RFC forward-compat, not reversed). |
| M1 | Med | RRQ of a `.md5` file generates a chained `.md5.md5` sidecar (server.nim:232-255 has no filename guard on commit) → unbounded client-driven disk growth. PURE network attack, no local access | **fixed** (batch A) | handleRrq gates digester on `csMd5 and not isReservedSidecarName(resolvedPath)`; RED→GREEN test in t_props_server. Read of a `.md5` still succeeds; only the sidecar-of-sidecar write is skipped. |
| M2 | Med | `.md5` literal duplicated (security.nim:116 vs checksum.nim:90), no shared constant → future divergence silently reopens defect 5 | **fixed** (batch A) | `const SidecarExt* = ".md5"` in security.nim; both `checkWriteAccess` and `writeSidecar` reference it. |
| M3 | Med | `diagDetail` (server/operator-only) lives on the client-shared `TransferResult` type, safe only by doc-comment convention — same latent-leak shape D2 closed for `errorMsg` | **fixed** (batch C1) | Removed from `TransferResult`; operator diag now flows via server-only `diagOut: ref string` out-param, populated only by handleRrq/handleWrq, boxed only by handleRequest. Audience split now structural, not conventional. Client type unchanged (no call-site churn). Slice-6 tests still discriminate. |
| M4 | Med | Redundant `== csMd5` + `digester != nil` booleans for one fact (server.nim:232/254); commit's csNone arm is dead. Always-construct-digester collapses them (interacts w/ H2 fix) | **by-design** (batch B) | After H2's early guard the mode is proven csNone/csMd5; collapsing the booleans adds no correctness value and would either regress csNone's zero-overhead nil-hook (RFC perf intent) or risk Batch A's reserved-name clause. Redundancy is intentional & documented. |
| M5 | Med | Windows trailing dot/space (`name.md5.`/`name.md5 `) may bypass lexical `.md5` check while OS opens `name.md5` | **fixed** (batch A) | `isReservedSidecarName` strips trailing dots/spaces from basename before suffix test; RED→GREEN unit tests in t_security. Defense-in-depth regardless of runtime exploitability. |
| M6 | Med | Peer-supplied ERROR-packet text → `evTransferError.errorMsg` unsanitized (transfer.nim:151→api.nim:462) → ctrl-char/escape injection into embedding GUI | open (OUT OF RFC SCOPE) | Pre-existing reverse-direction path; reviewer suggests folding into embedding-API/#17 hygiene. Fork: in-scope now or defer? |
| M7 | Med | `bytesSent` over-count fix (transfer.nim:195-201) has NO regression test; existing t_transfer.nim:532 never triggers a resend | open | CONFIRMED (trace + test read). Revert would go undetected. |
| M8a | Med | Coverage: startServer csSha256 rejection (api.nim:382-384) untested | **fixed** (batch B) | Test in t_session.nim (evServerStartFailed, no evServerStarted). |
| M7 | Med | `bytesSent` over-count fix (transfer.nim:195-201) has NO regression test; existing t_transfer.nim:532 never triggers a resend | **fixed** (batch C2) | New suite in t_props_transfer.nim; dup-ACK resend scenario, asserts `bytesTransferred == filesize`. Verified RED (35 vs 25 w/ guard reverted) → GREEN. `runTransferWithHook` extended to surface `sentBytes`. |
| M8b | Med | Coverage: RFC's own ">65535-block tripwire, no sidecar" test missing | **fixed** (batch C2) | Test in t_transfer.nim at sendBlocks level (startBlock=high(uint16)): asserts onDelivered fires once for the confirmed block BEFORE the limit-return, success=false. RED-confirmed by moving the return. Server-level equivalent (handleRrq hardcodes startBlock=1, no test hook; digester fed only via onDelivered + commit gated on success). |
| L1 | Low | `redactRoot` under-redacts for relative/case/short-name rootDir (server.nim:88-99) — operator-log only, never reaches client | open | Security. |
| L2 | Low | `sendOsErrorAndFail`+`redactRoot` two-step copy-pasted at both RRQ/WRQ sites; fold diagDetail into the helper | **fixed** (batch C1) | `sendOsErrorAndFail` now returns `(xfer, diag)` with redaction internal; both sites collapsed to one call. `.xfer.errorMsg` built solely from `clientSafeError`. |
| L3 | Low | `onDelivered` exactly-once/ordering/lifetime contract lives in impl comments, not on the parameter doc | **fixed** (batch C2) | `##` doc added to sendBlocks: fires once/confirmed-block, ascending, payload = last-transmitted bytes, valid only for the synchronous callback, loop before the >65535 return. |
| L4 | Low | `commit` csNone arm dead from real call site (subsumed by M4) | **by-design** | Deep-module defensive completeness — Digester correctly handles every variant even if csNone's commit is currently unreached (csNone keeps nil digester). Not a defect. |
| L5 | Low/info | sidecar existence = download-history timing oracle (no escalation); UDP amplification (protocol-inherent, pre-existing) | wontfix? | Security informational. |
| K1 | Known→**FIXED** | Windows `expandFilename` does NOT resolve symlinks/junctions → Invariant-5 containment is POSIX-only (sidecar write inherits #19's documented best-effort limit) | **FIXED & re-verified (Option A + K1r2)** | `hasReparseComponent*(rootDir,absPath)` (security.nim) walks components leaf→root(excl), rejects any reparse point via `symlinkExists` (catches junctions+symlinks). Wired into validatePath `when defined(windows)`; POSIX untouched. 4 junction tests RED→GREEN (unprivileged `mklink /J`). BONUS: #19 symlink baseline reds now PASS on Windows; H1 `.md5`-alias Windows residual fully closed. Deliberate trade-off: Windows denies in-root symlink/junction serving (documented). Remaining Low: pre-existing test-teardown `Access denied` on `escape_dir` cleanup (test-only, zero delta). | Investigation (2026-07-03): `symlinkExists`/`getFileInfo(false).kind` detect JUNCTIONS (generic `FILE_ATTRIBUTE_REPARSE_POINT` bit) — proven in stdlib source + Windows-container junction probe. Fix (Option A, FFI-free, Windows-only): `hasReparseComponent(rootDir,path)` walks components leaf→root, `symlinkExists` each existing one, reject if any is a reparse point → lexical path == real path, isWithin exact. Wire into validatePath `when defined(windows)`. POSIX unchanged (already exact, intentionally allows in-root symlinks — universal would regress that). ~half-day incl. tests. Junctions need NO privilege (`mklink /J`) → runs for real on windows-latest CI, not skipped. Product call: denies Windows in-root symlink/junction serving (rare; the faithful alternative needs FFI). |

**Verified-correct (no finding):** onDelivered exactly-once/ascending firing & windowCache lifecycle (no leak/KeyError/double-hash); zero-byte & exact-multiple digests; `finalize` hex == `$toMD5`; Digester variant safety (no FieldDefect; nil guarded); `clientSafeError` exhaustive (no `else`); `sendOsErrorAndFail` redaction-by-non-construction; slice-2 TOCTOU test is a genuine discriminator; all 6 invariants enforced-and-tested (modulo the gaps above); csSha256 rejected at CLI+startServer; windowCache bounded O(window×blocksize); no FFI in src; no disallowed `except OSError, IOError as e:` form.

**Root-cause clusters (for the fix loop):** {H1, M1, M2} = one reserved-`.md5` authority (shared `SidecarExt` + canonical-path reserved-target predicate applied at BOTH the WRQ gate and the RRQ commit sink). {H2, M4, M8-part} = single checksum-mode authority + always-construct. {M7, M8} = pure test additions.

## Review ledger — round 2 (re-review of the fixes)
Re-ran Security + Design (standing) + Correctness over the changed scope. Fixes for H1/H2/M1/M2/M3/M5/M7/M8/L2/L3 all HOLD (see verdicts). Two NEW findings opened:

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R2-1 | Med (Windows-only) | NTFS ADS bypass of reserved `.md5`: `isReservedSidecarName` (security.nim) doesn't normalize the `::$DATA`/`:$DATA` stream qualifier → WRQ `data.bin.md5::$DATA` skips the guard, OS opens real `data.bin.md5` → forge/overwrite sidecar. Same Invariant-6 defeat as M5, different name trick | **fixed** (round 3) | `validatePath` rejects any `:` in filename `when defined(windows)` (closes ADS + drive-relative, shared RRQ+WRQ gate, POSIX unaffected). 3 tests RED→GREEN in Windows container. |
| R2-2 | Low | `diagOut: ref string = nil` default leaves nil-safety as per-call-site discipline (3 `if diagOut != nil` guards) — matches the tracked never-throw Defect hazard (NilAccessDefect past `except CatchableError`); a future forgetful write site is a live landmine | **fixed** (round 3) | Default → `= new(string)` (per-call throwaway box); 3 guards collapsed to unconditional writes. handleRequest's own box unaffected. Refactor under green. |
| R2-3 | **Med-High** | `windowCache` eviction (transfer.nim:243-246) is nested INSIDE `if onDelivered != nil:` but blocks are cached unconditionally on send → when `onDelivered==nil` (every client PUT; every `csNone` RRQ = the DEFAULT + large-file path) the cache is never evicted → **O(filesize)** memory, contradicting the doc's O(window×blocksize) claim. Round-1 agents missed it (saw `.del`, assumed unconditional) | **fixed** (round 3) | `windowCache.del(b)` moved OUT of the guard (unconditional per confirmed block); only the hook call stays conditional. New `when defined(chapulinTest)` peak-size probe + discriminating test in t_props_transfer (onDelivered==nil): RED peak=21 → GREEN ≤ windowsize+1. Delta-green both containers. |

## Review ledger — round 3 (re-review of round-2 fixes)
All three round-3 fixes (R2-1 ADS, R2-2 diagOut, R2-3 windowCache leak) HOLD — Security + Correctness both cleared with nothing above Low; the windowCache KeyError risk is definitively refuted (contiguous non-overlapping eviction ranges; evicted blocks never re-referenced; `Table.del` no-op on absent key). One new item:

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R3-1 | Low (Design says Med) | `lastSendPeakCacheBlocks` test probe is a module-level mutable global (transfer.nim) — non-reentrant if two `sendBlocks` overlap; contradicts the module's concurrency-first design. Compiled out of production (`when defined(chapulinTest)`), not exercised concurrently today (all property tests single-transfer) | **fixed** (round 3b) | Adjudicated Low for product risk (Security+Correctness concur: test-only, no prod path) but worth the trivial fix. Converted to a call-scoped `ref int` out-param on sendBlocks (mirrors the just-blessed `diagOut` idiom), removing the global. Mechanical change in code 3 agents cleared this round. |

## Review ledger — K1 slice re-review
K1 (junction/reparse containment) re-reviewed by Security+Design+Correctness. Security: HOLDS (walk-boundary safe, coverage complete). Two fixes surfaced + 2 Lows:

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| K1-a | **High** (upgraded) | `hasReparseComponent` wired only into `validatePath`, NOT `validateWritePath` — the authority `checksum.writeSidecar` calls directly. RED proved this was a **LIVE bypass, not just TOCTOU**: pre-fix `writeSidecar` actually wrote a file THROUGH a junction to outside root (`ok=true`) | **fixed** (K1r2) | Moved `when defined(windows): hasReparseComponent` into `validateWritePath`; removed redundant `validatePath` call; documented the 2 layers. RED (writeSidecar wrote outside root) → GREEN (rejected). All 3 callers now uniformly protected. |
| K1-b | Med | boundary `current != rootDir` (security.nim:95) not trailing-sep-tolerant → trailing-slash rootDir over-climbs past root; if served root is reparse-backed (bind mount/DFS/OneDrive) → EVERY request falsely rejected (self-inflicted outage). CLI doesn't trim rootDir. Not caught (test roots via getTempDir normalize the sep) | **fixed** (K1r2) | `stopAt = rootDir.strip(trailing DirSep/AltSep)` before the loop compare. RED (junction-as-root + trailing-sep → legit file falsely rejected) → GREEN (accepted). |
| K1-c | Low | `isWithin*`/`hasReparseComponent*` exported but no external callers | **fixed** (K1r2) | Grep-verified no external callers; dropped `*` from both. `canonicalize*`/`validateWritePath*` stay exported (consumed externally). |
| K1-d | Low | `validateWritePath` name narrower than scope (now a 3-caller general containment authority) | **wontfix (skip)** | Rename ripples across checksum.nim + validatePath + tests for a cosmetic Low — not worth the churn. Noted. |

**Round-2 verdicts:** Fix 1 (reserved-`.md5` authority) — right home, deep context-free predicate, no fail-open in canonicalize fallback; HOLDS modulo R2-1. Fix 2 (csSha256 single authority) — genuinely collapsed to one `{csNone,csMd5}` predicate across 3 legit entry points; HOLDS (newDigester's own raise is defensible belt-and-suspenders, fails safe). Fix 3 (diagOut channel) — `TransferResult` structurally can't carry operator detail now; `ref string` is the required async idiom; `.xfer.errorMsg` built solely from `clientSafeError`; all `diagOut[]` writes nil-guarded today; HOLDS modulo R2-2. M6/K1/L1/L5 unaffected — severities unchanged.
- **Uncommitted:** all changes are in the working tree, NOT committed (per standing rule). After stage 4:
  `src/chapulin/{transfer,security,server,api,server_config}.nim` (M) + `checksum.nim` (new);
  `tests/{t_props_server,t_props_transfer,t_security,t_server,t_session,t_transfer}.nim` (M) + `t_checksum.nim` (new);
  `scripts/dev-test.ps1` (M); `docs/rfc/checksum-integrity-error-hygiene.{md,handoff.md}` (new).
  (Removed a stray `*full.diff` artifact a review subagent accidentally wrote to the repo root.)
- **RFC:** `docs/rfc/checksum-integrity-error-hygiene.md`   •   **Origin:** #19 review (no tracking issue)

## Slice progress (10 total: 0, 1.0, 1.1, 1.2, 2, 3a, 3b, 4, 5, 6)
- [x] **0** prereq — `validateWritePath*` factored out of `security.nim` (+`isWithin*`/`canonicalize*` exported,
  `validatePath` delegates to it, new `suite "validateWritePath"`); `serveWithChecksum` parameterized with
  `w: Wire = newWire()` + `windowsize = 1` (OACK path when >1). Both suites green in container.
- [x] **1.0** transfer hook+cache — `onDelivered` param on `sendBlocks`, `windowCache`, ascending firing loop,
  cache-hit resend skips `bytesSent`. New suite in `t_props_transfer.nim` (lossless / dup-ACK / windowsize=5).
  Verified RED against naive one-call-per-ACK. `bytesSent` over-count was latent, never asserted — no fixes.
- [x] **1.1** pure `checksum.nim` — `Digester`/`newDigester`(csSha256 raises)/`update`(len==0 guard)/`finalize`
  fully impl; `writeSidecar`/`commit` STUBS (never-raise plain write, `<hex>  <basename>\n`; TODO(slice 4)
  containment). New `t_checksum.nim` (added to `dev-test.ps1` array). All green.
- [x] **1.2** server wiring — `handleRrq` real-file path constructs `Digester` (csMd5 only) + `onDelivered =
  digester.update`; post-transfer `if xferResult.success and digester != nil: discard commit(...)` (nil guard
  added — commit on nil ref defects); `generateChecksum`+`md5` import removed; `csSha256` rejected in
  `api.nim` `startServer`; harness gained `cancelCheck` param. D1 core (defects 1+2) DONE.
- [x] **2** TOCTOU combo proof — TEST-ONLY (`t_props_server.nim`); 3-block file @ blocksize 16384 (needed to
  defeat CRT stdio whole-file prefetch that masked the mutation at 512), `onProgress` mutates on-disk file at
  block 2, `dropAOcc=2` forces dup-ACK resend after mutation; asserts `sidecar == MD5(received[])` and `!=`
  original/mutated. Verified RED against naive fresh-readData resend; transfer.nim restored. windowsize≥2
  variant dropped (didn't discriminate — recvPacket replay races fillWindow, unsteerable). D1 fully proven.
- [x] **3a** D2 generic wire/errorMsg — `clientSafeError*` (exhaustive case, no else, in server.nim) +
  `sendOsErrorAndFail*` wired at RRQ(~150)/WRQ(~296) `except IOError` (no `e` bound → `e.msg` unreachable);
  other canned sendError sites untouched. Portable trigger = directory-WRQ (RRQ rejected earlier by
  fileExists). RED showed abs path leak, GREEN generic. Tests in `t_server.nim`. RRQ real-OS repro → 3b.
- [x] **3b** POSIX real open-failure — `when not defined(windows)` test in `t_server.nim`, 0o000 file faults
  `open(fmRead)` at RRQ ~152. Root has DAC-override (mode bypass = real POSIX property) so subagent ran the
  binary as `nobody` for REAL coverage; RED (reverted site) leaked abs path, GREEN generic. Linux `dev`
  compose container = the real gate; Windows container compiles it out (SKIP). D2 (defect 3) DONE.
  → **Linux compose run recipe:** `DOCKER_CONTEXT=desktop-linux docker compose run --rm dev sh -c "nim c -r
  --hints:off -d:chapulinTest tests/t_server.nim"` — use for any symlink/POSIX-real coverage (slice 4!).
- [x] **4** sidecar containment (CRITICAL) — `writeSidecar` (checksum.nim) hardened: `validateWritePath` +
  unconditional `symlinkExists` leaf-refusal + never-raise; no import cycle. Tests in `t_security.nim` (new
  `writeSidecar containment` suite) + `t_props_server.nim` (e2e escape). RED-against-stub proven in Linux
  container (clobbered outside file); green both platforms (leaf symlinkExists works on Windows too, unlike
  #19's expandFilename). Junction fixture skipped w/ justification (would only assert the documented Windows
  ancestor-reparse gap). Only t_security reds = known #19 baseline.
- [x] **5** reserved `.md5` namespace (HIGH) — `checkWriteAccess` rejects `*.md5` (case-insensitive) with
  `errAccessViolation` when `checksumMode != csNone`, before the policy case. Tests in `t_security.nim` (new
  suite, 6 tests) + `t_props_server.nim` e2e (forged WRQ can't clobber legit sidecar). RED verified both.
  `wrqUnderPolicy` gained `checksumMode`/`dir` params. Delta green (only #19 baseline reds). Invariant 6 DONE.
- [x] **6** redacted operator logging (optional, Q3 keep) — reused existing `TftpServer.logger`; new
  operator-only `TransferResult.diagDetail` field carries redacted detail up to `handleRequest`
  (`logger.warn`), client wire/`errorMsg` untouched (D2 intact); `redactRoot` strips `rootDir`. Logs OS
  open-failure + non-fatal sidecar-commit failure (RRQ still succeeds). Tests in `t_server.nim`. Green.

## Final verification state (end of stage 3)
- **Windows container:** `t_server`, `t_props_server`, `t_checksum`, `t_props_transfer`, `t_props`,
  `t_transfer`, `t_session`, `t_api` all GREEN. `t_security` = only the 3 known pre-existing #19 symlink reds
  + cascading Cleanup (Windows `expandFilename` limit; verified on baseline — NOT ours).
- **Linux compose container:** `t_server` + `t_security` FULLY green (incl. #19 symlink suite + all new
  slice-4 real-symlink assertions). `t_integration`: pre-existing external-daemon-dependent failures, unrelated.
- Everything uncommitted. Three round-2 scope expansions (defect 5, `bytesSent` in-scope, digest-reuse demote)
  were implemented as-specced and remain flagged for Corey's veto if desired — none blocking.

## Environment facts (discovered slice 0 — pass to every slice subagent)
- **Docker context:** `scripts/dev-test.ps1` needs `$env:DOCKER_CONTEXT = "desktop-windows"` in this sandbox
  (host default `desktop-linux` can't mount `...:C:\app` / run the Windows nim image). Set per-invocation.
- **Nim 2.2.10 syntax caveats (slice 1.1):** `except OSError, IOError as e:` does NOT compile (multi-type
  except can't bind an alias) → use `except OSError, IOError:` + `getCurrentExceptionMsg()`. Case-object empty
  branches need `discard` on its own indented line, no inline trailing `##` comment. Applies to slice-4
  `writeSidecar` never-raise body and any D2 error handling.
- **Pre-existing t_security failure (NOT ours):** the `"validatePath symlink containment (issue #19)"` suite +
  cascading `Cleanup` fail **in the Windows container** because Windows `expandFilename` doesn't fully resolve
  symlinks (documented "best-effort on Windows" limit). Verified identical on baseline via `git stash`.
  → Treat as a known baseline red. Slices 4/5 must use **junction** fixtures / `checkpoint` skips (already in
  the RFC slice-4 text) and must not be misread as a regression. Confirm green DELTA, not absolute green, for
  t_security until a fix lands.

## Open forks (awaiting Corey)
- *(none)* — grinding. Three round-2 scope expansions remain flagged for veto (non-blocking):
  defect 5 reserved `*.md5`; `bytesSent` folded into slice 1.0; digest→embedding-API reuse demoted to #17.

## Key decisions (architecture rounds 1&2 — see RFC)
- Q1→Option A: `onDelivered(data: openArray[byte])` hook in `sendBlocks`, fired via ascending range-loop
  `(prevAcked+1)..lastAcked` (per-BLOCK not per-ACK — windowsize>1 cumulative ACK else drops interior blocks),
  before both early returns; `windowCache: Table[uint16, seq[byte]]` evicts on confirm (O(window) memory);
  skip `bytesSent` on cache-hit resend. `update` zero-length no-op before `unsafeAddr data[0]`.
- `commit` facade; `writeSidecar`/`commit` NEVER raise. Containment authority = `security.validateWritePath`
  + independent unconditional `symlinkExists` refusal on sidecar. `sendOsErrorAndFail(code)` helper;
  `clientSafeError` exhaustive case; `csSha256` raises at `newDigester` + rejected at `startServer`.

## Resume command
`/loop implement the next unimplemented RFC slice with /tdd …` (full form above). `/compact` between slices OK.
