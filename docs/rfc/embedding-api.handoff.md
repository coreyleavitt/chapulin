# Embedding API RFC — handoff

- **Stage:** 4 code-review — COMPLETE (floor reached round 4: 0 Crit/High/Med)   •   **Rounds:** 4
- **Resume:** review done; awaiting Corey's OK to COMMIT (nothing committed yet). Then RFC #17 ships.
- **Resume:** `/code-review docs/rfc/embedding-api.md`  (recommend `/compact` first — long slice grind)
- **Stage 3 close:** full unit suite green in Docker (t_protocol/transfer/options/security/server/logging/uri/
  client/api/props/props_transfer/props_server/session/wireharness), CLI compiles importing only api+tftp_uri,
  t_integration compiles. NOTHING committed yet — working tree holds all of slices 0a–8.
- **⚠ GUI unverified:** `gui/desktop/chapulin_gui.nim` was rewritten onto the session but CANNOT build headless
  (no GTK/NiGui in the toolchain image). Corey to build with `nimble gui` on a GTK machine. Watch-list at the
  slice-7 entry below (WritePolicy enum qual, poll inline-iterator-in-closure, NiGui field names).
- **Code-review watch-list (known gaps flagged during the grind):**
  - evServerStarted.boundPort echoes config; OS-assigned port for listenPort=0 needs a UdpListener.localPort seam (slice 4).
  - slice-2 never-throw property used failingSend only (not a garbage-bytes responder); server-path garbage covered in slice 4.
  - client evTransferStarted is emitted pre-handshake (total=none for GET; snapshot blocksize/windowsize = requested, not OACK-negotiated — engine doesn't expose negotiated values).
  - Event `snap`/errorCode/errorMsg share one branch (Nim forbids dup field names across branches) — RFC snippet corrected.

## RFC
- Doc: `docs/rfc/embedding-api.md` — consolidates A (session), B (one server loop + `onTransferStart`),
  C (never-throw boundary), D (config/progress ergonomics) into the #17 umbrella.
- Lifted from issue #17 (already a near-complete RFC); folded in C, B's unwired callback, D; updated
  testing to use `tests/wireharness.nim` (so #15 isn't a blocker).

## Slices (defined; not implemented) — round 2 split slice 0 into 0a/0b/0c
- [x] 0a server.nim event-data: TransferInfo.totalBytes+startedAt (fix 3 constructors); fire onTransferStart
      via onStart hook inside handleRrq/handleWrq (handleRequest doesn't know size)
      DONE: +startedAt threaded from handleRequest startTime; onStart fired post-open/OACK; 2 t_server tests green
- [x] 0b server.nim cancel+injection: cancelCheck on handleRrq/Wrq (OR with cancelOnWriteError);
      transferFactory seam on TftpServer for per-transfer socket; defensive wrap of run() reject-path sends
      DONE: combinedCancel ORs (not replaces) cancelOnWriteError; transferFactory defaults newUdpTransport;
      3 reject-path sends wrapped try/except; 2 t_server tests green (full run()-never-raise proven in slice 4)
- [x] 0c wireharness: makeListener (deque UdpListener) + failingSend Transport (raises after N)
      DONE: newListenerQueue/push/makeListener + makeFailingTransport(failAfter); t_wireharness (3 tests)
      registered in docker-compose + chapulin.nimble; props regressions clean
- [x] 1 Session skeleton + client transfer — poll guard+try/except+dequeue-per-yield; addCallback (NOT asyncCheck)
      DONE: newSession/startTransfer/poll/close in api.nim (executeTransfer kept until slice 8); full 9-kind
      Event model; never-throw mechanized (id-before-try, pre-launch try/except→event, addCallback, poll
      pump-wrapped+hasPendingOperations guard, yields outside try); t_session 4 tests green (GET/PUT over
      wire via handleRrq/handleWrq responder, idle-poll-no-raise, pre-launch-fail→event). Reviewed by Opus.
      SPEC-DOC FIX: RFC Event snippet had `snap` in two `of` branches (Nim forbids) → merged 4 transfer
      kinds into one branch (semantics unchanged; errorCode/errorMsg meaningful for evTransferError only).
- [x] 2 Never-throw property (garbage + failingSend) + cancel (cancel-after-resolve no-op)
      DONE: cancel via TransferEntry.cancelRequested ref bool ORed into GET+PUT cancelCheck; no-op for
      stale/unknown; terminal only via future resolution; never-throw property green 100 iters (failingSend
      depths 0-3). NOTE: property used failingSend only, not a garbage-bytes responder — server-path garbage
      revisited in slice 4; flag for code-review if broader client-garbage coverage wanted.
- [x] 3 Bounded coalescing queue (terminals bypass; early-break re-delivers)
      DONE: enqueue coalesces evTransferProgress per xfrId (O(n) scan, latest-wins, no magic cap);
      terminals/started/logs never coalesced; 3 t_session tests (RED 9→1 progress, terminals@concurrency,
      early-break re-deliver). Advance-without-drain tested via direct asyncdispatch.poll(0).
- [x] 4 Server via one loop + events (addCallback replaces asyncCheck; evServerStarted bound addr/port; stop→stopped)
      DONE: startServer/stop + ServerEntry + drain-gate-in-poll (stopRequested & runFut.finished &
      activeTransfers==0 → one evServerStopped, Inv 8); ServerCallbacks→evTransfer*(srvId) via correlation
      key (clientHost,clientPort,startedAt)→TransferId; Logger sink→evServerLog; evServerStartFailed terminal.
      server.nim: asyncCheck→addCallback (never-raise) + FIXED activeTransfers leak (inc+defer dec at top of
      handleRequest, covers malformed-packet early return; run() no longer inc's — Opus-verified balanced).
      Full-transfer tracer + bind-fail + never-raise + stop-no-inflight; t_session/t_server/t_api/t_client green.
      GAP: evServerStarted.boundPort echoes config (OS-assigned port for listenPort=0 needs UdpListener.localPort
      seam — deferred, flag for code-review). srv.transferFactory reuses session transportFactory seam.
- [x] 5 Per-transfer server cancel + concurrent-stop single evServerStopped
      DONE: server.nim cancelFactory seam (nil default) → reqCancel threaded into handleRrq/handleWrq;
      session cancelFactory closure creates ref-bool flag keyed (host,port,startedAt), onStart links tid→flag
      in serverXferCancel; cancel() unified client+server; terminal cleanup. 4 tests incl. FULL two-concurrent
      (cancel one→Error, other→Complete), stop-no-force-cancel→Complete+one Stopped, post-terminal no-op. Green.
- [x] 6 Config/progress: fraction(Option), tsize defaults, enum checksumMode (+chapulin.nim parse, t_props_server test)
      DONE: ChecksumMode enum (csNone/csMd5/csSha256) across server_config/server/chapulin/t_props_server;
      parseChecksumMode validates (CLI exits 2 on bad); md5-only preserved. fraction in format.nim, exported
      via api (none + div-by-zero safe). PUT evTransferStarted.total=some(fileSize); GET stays none til OACK.
      5 suites + CLI compile green. Spec citation corrected: checksum test is t_props_server.nim not t_server.nim.
- [x] 7 Port CLI + NiGui; --notify structural (evTransferComplete+srvId); netascii TODO(#13)
      DONE 7a (VERIFIED): api waitTransfer/waitServer (buffer non-target events, poll(0)+cap), close-mid-transfer
      cancels active client xfers→one terminal each; CLI ported to imports = api + tftp_uri ONLY (compiles),
      client+serve poll(50) loops, structural --notify on evTransferComplete (deleted " OK " hack), netascii
      TODO(#13); 6 new t_session tests green. api exports widened (format helpers, logging LogLevel/
      formatLogMessage/LogOutput/newLogger, options).
      DONE 7b (UNVERIFIED — Corey builds `nimble gui` on GTK): gui/desktop/chapulin_gui.nim rewritten to
      session model — deleted Channel/Atomic/threads/workers/dup-loop/dual-timers; single 50ms timer pumps
      session.poll(0)→widgets; server panel shows srvId-tagged evTransfer* progress; imports = nigui + std +
      api only; NO api exports needed to add. Opus-read for structural soundness (state vars declared,
      dispatch faithful). Watch at build: WritePolicy unqualified enum vals, poll inline-iterator-in-closure,
      bsCombo.options/dialog fields (copied verbatim from working original).
- [x] 8 Remove dead surface (executeTransfer/TransferCallbacks, t_api plumbing tests)
      DONE: deleted executeTransfer + TransferCallbacks + On{Progress,Error,Complete} + failResult from api;
      export narrowed (LogLevel+formatLogMessage+UdpListener kept; newLogger/LogOutput/Logger/ServerCallbacks
      NOT public); t_api trimmed to the one non-superseded newTransferRequest-defaults test; t_integration
      ported to session (startTransfer/waitTransfer, compiles); zero remaining old-API refs. Full suite green.

## Open forks (awaiting Corey)
- _(none — rounds 1 & 2 both found zero genuine forks; all fixes clear-best and applied)_

## Key decisions (this session)
- One RFC, not four — A/B/C/D are facets of #17's single contract.
- Build on engine/server as-is; #13/#14 are refactors *beneath* this and deferred.
- `wireharness.nim` is the boundary-test substrate; #15 not required first.
- **R1:** never-throw = addCallback+capture (never asyncCheck); poll+events collapsed into one iterator;
  test injection via newSession factories; uniform TransferId for server transfers (activeTransfers dropped);
  concrete Event case-object; added close*, evTransferStarted, evServerStartFailed; pinned queue/id/stop semantics.
- **R2:** Event kinds unified 12→8 (one evTransfer* family, srvId distinguishes); one TransferSnapshot payload,
  TransferInfo no longer leaks; Option[int64] kills the -1 sentinel. Never-throw hardened for the 2 paths
  addCallback misses (empty-dispatcher ValueError guard via hasPendingOperations; iterator + sync pre-launch
  try/except). waitTransfer/waitServer BUFFER non-target events (was silent drop → deadlock); waitServer exits
  on evServerStartFailed. Ids 1-based + NoTransfer/NoServer. stop = graceful drain (never force-cancel) + new
  Invariant 8 (one terminal per ServerId). Slice 0→0a/0b/0c; added transferFactory seam (slice 4 needs it for
  in-memory) + failingSend harness. New fields: evServerStarted bound addr/port, snapshot direction/mode/startedAt,
  new evTransferLog. Citations corrected against source. Netascii orphan flagged TODO(#13).

## Review ledger (stage 4)
Round 1: 6 reviewers + 4 adversarial verifiers complete. Awaiting Corey's fix mandate (Step 6).
Severities post-verification. C=Critical H=High M=Medium L=Low. "pre" = pre-existing base-server, out of RFC scope.
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R1-1 | C | FieldDefect crash: server.nim:301 reads `pkt.filename` on non-RRQ/WRQ variant; DATA/ACK/ERROR/OACK 4-byte pkt → uncatchable Defect, defeats never-throw | FIXED | opcode guard before .filename (server.nim ~300); t_session Bug1 suite (DATA/ACK/ERROR/OACK/garbage → no raise, valid RRQ still completes) |
| R1-2 | H | server run() catches only TransportTimeoutError (server.nim:412); any other recv error → runFut fails, callback discards, drain-gate needs stopRequested → evServerStopped never emitted, embedder wedges | FIXED | run() catches CatchableError→log+break; poll gate fires on runFut.finished regardless of stopRequested, evServerLog(err)+one evServerStopped; wireharness makeFailingListener + t_session Bug2 suite |
| R1-3 | H | server-side TransferSnapshot hardcodes DefaultBlocksize/1/tmOctet — negotiated never surfaced | FIXED | TransferInfo gained blocksize/windowsize/mode/reqId (post-OACK); api closures use info.*; t_session BUG3 test (blksize=1024,wsize=2) deterministic RED→GREEN |
| R1-4 | M | XferKey keyed on raw epochTime() collides under coarse clock | FIXED | XferKey→int reqId (TftpServer.nextReqId monotonic); cancelFactory(reqId); t_session BUG4 two-concurrent-same-peer test (robustness) |
| R1-5 | M | Event.errorCode/errorMsg readable on non-error branches — no type guardrail | FIXED | case split: snap on Started/Progress/Complete, errSnap+errorCode+errorMsg on Error only; waitTransfer→errSnap; GUI needed no change; t_session test |
| R1-6 | M | Unbounded growth: s.servers never purged post-stop; cancelFlags leaks on pre-onStart fail | FIXED | drain-gate deletes stopped servers (deferred del after pairs loop) + serverXferCancel cleanup; onTransferError dels cancelFlags[reqId] before NoTransfer return; t_session 5-cycle test |
| R1-7 | M | Event queue unbounded under evServerLog/Started flood | FIXED | const MaxQueuedEvents=8192; enqueue evicts oldest log event, never terminals/started; droppedLogCount + one coalesced warn; t_session 9192-flood test bounds queue |
| R1-8 | M | waitTransfer/waitServer busy-spin poll(0) | FIXED | poll(0)→poll(2); named const WaitCapIterations |
| R1-9 | M | port=0 → evServerStarted.boundPort echoes 0; needs UdpListener.localPort seam | FIXED | UdpListener.localPort closure via getLocalAddr; api boundPort=listener.localPort(); wireharness makeListener(q,port); t_session real-socket port=0 test asserts boundPort!=0 |
| R1-10 | M | csSha256 accepted by parseChecksumMode but generateChecksum silently no-ops | FIXED | parseChecksumMode("sha256") raises ValueError (not-yet-implemented); CLI already quit(2)s; t_server 4 tests |
| R1-11 | M | close() "must keep pumping" contract unmet by both consumers; add session.drain(timeoutMs) | FIXED | added drain*(timeoutMs=2000) pumping poll(2) to quiescence; close() doc points at drain(); t_session close+drain test |
| R1-Lx | L | Group C added test-only accessors (sessionServerCount/ActiveCount/QueueLen/injectEvent) to public api surface | open | fold into Low batch — gate behind when-defined or test include |
| R1-12 | M | Test gaps: server garbage/opcode-fuzz never-throw; 2+ concurrent; server error exactly-one-terminal; run()-crash observability | FIXED | covered across A (garbage+crash), B (2-concurrent), E (server-error terminal-count: 0 before-start / 1 after-start) |
| R1-13 | M | t_integration.nim asyncCheck (176) + bypasses session API (228) — violates Invariant 2 pattern | FIXED | asyncCheck→addCallback; PUT test → session API (startTransfer/waitTransfer); unused engine import removed |

**Round 1 fixes complete (R1-1..13). Independent verify: ALL 14 suites green (direct-run + canonical dev), CLI_OK, INTEG_OK.**

### Round 2 re-review findings (new)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R2-0 | M(infra) | canonical `docker compose run --rm dev` broken: YAML `>` folded scalar preserves newlines on more-indented lines → shell `for` syntax error; test entrypoint never ran | FIXED | rewrote as single-line `command: sh -c "..."`; verified exit 0 |
| R2-1 | H | client-side snapshot reports REQUESTED not OACK-negotiated blocksize/windowsize; asymmetric with fixed server path | FIXED | engine getFile/putFile gained onNegotiated hook (fires post-applyOack incl. 512 fallback); api mutable effBs/effWs used by progressCb+terminal; evTransferStarted stays requested (documented); t_session client-OACK test (req 4096, OACK 1024) deterministic RED→GREEN |

**Round 2 fixes complete. Round 3 verify: ALL 14 green (canonical dev + -d:chapulinTest), CLI_OK, INTEG_OK.**

### Round 3 re-review findings
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R3-S1 | M(sec) | client-side terminal escape injection via attacker ERROR-packet errorMsg/startErr printed raw | FIXED | sanitizeForDisplay* in format.nim (exported via api); server.nim dedups to it; CLI wraps errorMsg+startErr; GUI wraps 3 error sites; t_api 4 unit tests (control-strip, UTF-8 passthrough) |
| R3-D1 | L | TransferSnapshot doc wrong for SERVER evTransferStarted | FIXED | comment split: client=requested@Started→negotiated@Progress; server=negotiated@Started (OACK precedes onStart) |
| R3-L1 | L | stale test name/comment referencing removed `errSnap` | FIXED | suite/test renamed to `snap`; assertions unchanged |
| R3-D2 | L | scripts/dev-test.ps1 $tests array missing t_wireharness + t_session (docker-compose + nimble have them) | open | report — cosmetic host-script gap, left per mandate |
| R3-info | - | Event snap-zero-for-server-events + -d:chapulinTest split both judged acceptable (loud failure mode) | — | no action |

Round 3: verify green; correctness/never-throw round-3 pass = 0 Crit/High/Med (1 Low); security+design = 1 Med (S1) + Lows.

### Round 4 — FLOOR REACHED
- Independent verify: ALL 14 suites green (canonical dev + -d:chapulinTest, 323 [OK]/0 FAIL), CLI_OK, INTEG_OK.
- Final security+correctness pass: **0 Critical/High/Medium.** Escape-injection fix confirmed complete at every attacker-controlled display site; sanitizeForDisplay correct + UTF-8-safe; no import cycle; no never-throw regression.
- Only Low remaining: R4-L1 — `sanitizeForDisplay("\x7f")` boundary not directly asserted (code handles it; add one check line).

### Lows — CLEARED (Group L, verified green: 14 suites + CLI test/release + integration)
DONE: R4-L1 0x7F test; R3-D2 dev-test.ps1 suites; dead serve-loop discard removed; dead exports
ProgressCallback/TransportCloseProc dropped; onStart wrapper → direct param; stale asyncCheck comments
fixed; progressCb hoisted; dead try/except round srv.stop() removed; blockNum==0 guards (api+server);
close()/drain() doc clarified; GUI evTransferLog srvId routing; CLI serve surfaces evTransferError.
LEFT (deliberate, cosmetic): TransferSnapshot.startedAt kept (harmless wall-clock convenience now that
reqId is the correlation key; removal = wide mkSnap churn for no gain); possibly-dead else branch (harmless).
WON'T-FIX: xLevel/sLevel → shared name — Nim forbids duplicate field names across case-object branches.
(two-step TransferRequest construction: left — the options-object builder is a nice-to-have, not needed.)

### GUI watchpoints for `nimble gui` (headless-unverifiable — Corey builds)
Cumulative: WritePolicy enum vals, poll inline-iterator-in-closure, bsCombo.options, dialog .file/.files/.selectedDirectory, startRepeatingTimer/TimerEvent; NEW: 3× sanitizeForDisplay wraps at error-display sites (all use only fields confirmed to exist).

### Verification command (canonical, now fixed)
`docker compose run --rm dev`  →  14 suites w/ -d:chapulinTest. Plus `nim c src/chapulin.nim` (CLI) + `nim c tests/t_integration.nim`.
| R2-2 | M | Event `errSnap` split ergonomic wart; pull `snap` to top-level common field | FIXED | snap common field (before case); error arm keeps errorCode/errorMsg only; waitTransfer→ev.snap; CLI/GUI unaffected; t_session R2-2 tests |
| R2-3 | M | test-only accessors public footgun (injectEvent can fake terminals) | FIXED | 4 accessors wrapped `when defined(chapulinTest)`; -d:chapulinTest added to docker-compose dev + chapulin.nimble (14) + scripts/dev-test.ps1; MaxQueuedEvents* stays public; non-test `nim c src/chapulin.nim` still builds |
| R2-4 | M | never-throw REGRESSION (Fix 9): unguarded listener.localPort() → nil closure NilAccessDefect escapes startServer | FIXED | nil-guard localPort() + entry.listener.close(); t_session R2-4 nil-localPort test (no raise, boundPort falls back) |
| R2-5 | M(sec) | log injection: pkt.filename logged verbatim before validatePath | FIXED | sanitizeForLog (strip <0x20/0x7F→'?') on filename in info log + formatTransferLog + errorMsg; t_session R2-5 test |
| R2-L | L | drain() doc overstates when needed; dead else branch server.nim:402 (opcode guard makes unreachable); latent nil-guard on entry.listener.close | open | Low batch |
| R1-L | L | batch: serve-loop dead `discard` (was mis-rated Critical→REFUTED, dead code); dead exports ProgressCallback/TransportCloseProc; onStart wrapper; stale "asyncCheck" comments; dup progressCb; dead try/except round srv.stop; uint16 blockNum=0 guard; startedAt leaked in snapshot; xLevel/sLevel naming; 2-step TransferRequest; magic 500/5e6; GUI evTransferLog srvId guard; CLI serve drops per-xfer events; OS-error detail in errorMsg | open | QUAL/CORR/DESIGN/PORT Lows |
| R1-pre-a | H(pre) | symlink traversal: security.nim validatePath uses lexical absolutePath, no realpath/expandSymlinks | filed | → GitHub #19 (Corey: separate issue, not this pass) |
| R1-pre-b | L-M(pre) | generateChecksum readFile whole file → OOM; default-off | filed | → GitHub #19 |
| R1-pre-c | L(pre) | checksum TOCTOU + OS-error-path detail leak | filed | → GitHub #19 |

**Mandate (Corey):** fix Crit→Med (R1-1..13), leave Lows (R1-L) for a final batch. Pre-existing → #19, not this pass.
**Fix loop:** serialized groups (api.nim+server.nim shared): A=never-throw(1,2) · B=snapshot+key(3,4) · C=lifecycle(5,6,7,8,11) · D=config(9,10) · E=tests(12,13). Re-review after.
**Test cmd:** `docker compose run --rm dev` (14 files) + `nim c src/chapulin.nim` + `nim c tests/t_integration.nim`.

GUI compile watchpoints (headless-unverifiable, for `nimble gui`): bsCombo.options field, startRepeatingTimer/TimerEvent sig,
dialog .file/.files/.selectedDirectory. All api symbols confirmed exported by port-fidelity reviewer.

## Recently shipped (context)
- main @ d086196: #16 (windowsize applied) + #18 (dup-ACK fast retransmit) fixed; full proptest suite green.
