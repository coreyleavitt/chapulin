# Security Policy

chapulin is an FFI-free, single-threaded, async TFTP server and client written in Nim.
This document states what chapulin defends against **in-process**, what it deliberately
does **not** try to defend (and why), the known **residual limitations** of its
approach, and the **deployment hardening** we expect operators to add around it.

The guiding principle: **chapulin's job is to be a correct, unexploitable, fail-closed
transport.** Security is a bar we hold — but most of that bar is robustness and
containment, not cryptography, and the parts that require kernel enforcement or a trust
anchor are the deployer's ring, not the library's.

---

## Reporting a vulnerability

Please report suspected vulnerabilities privately to **corey@leavitt.dev** rather than
opening a public issue. Include a description, affected version/commit, and a
reproduction if you have one. We aim to acknowledge within a few days and will
coordinate disclosure once a fix is available.

---

## Threat model

chapulin runs on an **untrusted network** and parses **attacker-controlled UDP packets**.
The adversaries we design against:

- **A malicious network peer** sending malformed, hostile, or floods of TFTP packets
  (RRQ/WRQ, options, DATA/ACK/ERROR) — attempting to crash the process, escape the
  served directory, exhaust memory, or read/write files outside policy.
- **A hostile filename or option** attempting path traversal, symlink/junction escape,
  reserved-name forgery, integer overflow, or type confusion in the option parser.

Two things are explicitly **outside** the network threat model (see Non-goals):

- **Confidentiality/integrity of the bytes on the wire.** TFTP is unauthenticated and
  unencrypted by design; an on-path attacker can read or rewrite any transfer.
- **The trustworthiness of a peer's identity** beyond coarse host allow/deny. TFTP has
  no authentication.

The **filesystem is a trust boundary**: the server root (`rootDir`) is the containment
perimeter, and every served/written path must stay inside it.

---

## What chapulin defends in-process

These are the controls chapulin implements and holds to the bar. They are portable,
FFI-free, require no privileges, and are exercised by the test suite (`tests/t_security.nim`
and the property tests).

### Path containment (the filesystem perimeter)
- `security.validatePath` / `validateWritePath` resolve a request filename against
  `rootDir` and **refuse** anything that escapes it — `..` traversal, absolute paths,
  and symlink/junction escapes. The stance is **refuse, not silently resolve**:
  a path that cannot be proven in-root is rejected fail-closed.
- On Windows, reparse points (symlinks and junctions) are detected FFI-free via the
  generic reparse bit and refused, since `expandFilename` does not resolve them.
- The `.md5` checksum sidecar has an **additional, unconditional** symlink refusal on
  the sidecar path itself (independent of `validateWritePath`), so an attacker-planted
  in-root symlink at `<name>.md5` cannot redirect a sidecar write onto another in-root file.

### Authorization
- **Write policy** (`WritePolicy`): default `wpDeny` (read-only server). `wpCreateOnly`,
  `wpOverwrite`, and `wpCreateOrOverwrite` widen it explicitly. A read-only server
  rejects every WRQ.
- **Reserved namespace**: while checksums are enabled, `<name>.md5` is a server-owned
  pseudo-name; no client WRQ may create, overwrite, or forge one. This is checked
  against both the lexical path and its canonicalized real path, so an in-root symlink
  aliasing a `.md5` target is still refused.
- **Host access** (`checkHostAccess`): optional `allowedHosts`/`deniedHosts`. Denylist
  takes precedence; an empty allowlist means allow-all. (Coarse, IP-based — not
  authentication; trivially spoofable on an untrusted L2 segment.)
- **Transfer ID (TID) lock** (RFC 1350 §5, `transfer.nim`'s `recvOnce`): a transfer locks
  onto its peer's `(host, port)` on the first valid response; every later packet from a
  different address is bounced with `ERROR` "Unknown transfer ID" and never accepted into
  the transfer. A forged or off-path attacker who guesses block numbers cannot inject
  into, hijack, or derail an in-flight transfer without also spoofing the legitimate
  peer's source address.

### Input hardening — never crash on hostile input
- The public API (`src/chapulin/api.nim`) is a **never-throw facade**: no
  `CatchableError` escapes to the caller.
- Critically, this extends to Nim **Defects** (`FieldDefect`, `IndexDefect`,
  `NilAccessDefect`, `UnpackDefect`) — which escape `except CatchableError` and would
  crash the process (a remote DoS). The codebase's **never-throw-Defect discipline**
  structurally avoids them: no case-object field access without a `kind` guard, no
  unguarded `Option.get`, no `popFirst` on a possibly-empty deque. A malformed packet
  or option degrades to an `ERROR` reply or a per-option default — never a crash.
- Option parsing (blksize / windowsize / timeout / tsize) is bounds-checked and
  clamped; numeric overflow/non-numeric values raise `ValueError` (caught → `ERROR(8)`),
  not a Defect.

### Denial-of-service resistance
- The per-session event queue is **hard-bounded** (`MaxQueuedEvents = 8192`) with a
  true absolute ceiling: under saturation it drops the oldest event (terminal events
  included) rather than growing without limit. This closes a memory-exhaustion vector
  reachable by flooding malformed-option requests. See "Residual limitations" for the
  accepted trade-off.
- `maxConcurrent` bounds simultaneous in-flight transfers.
- Transfer transports are allocated from a bounded configured port range.

### Information-leak hygiene
- Operator diagnostics that may contain filesystem paths (OS open-failure detail,
  non-fatal sidecar-write failures) are emitted on a **server-only** channel with the
  server root **redacted** — they are not sent to the client.

---

## Verification

Every claim above is backed by a named, running test target — not code-review confidence alone.
`file:testId`/`property` strings below are exact, taken from the source at the time of writing; if a
target is renamed or moved, this table (not the claim above) is what's stale. The harness is described in
[`docs/rfc/verification-harness.md`](docs/rfc/verification-harness.md) (v1: fuzz + symex over the parse/
containment/queue layers, plus the post-negotiation data phase) and extended by
[`docs/rfc/verification-harness-v2.md`](docs/rfc/verification-harness-v2.md) (v2: a stateful property over
the `api.nim` facade itself, `maxConcurrent` enforcement, deeper bounded symex proofs, and a soak/corpus
campaign — see that RFC's handoff for the as-landed scope of each, including where a proof is bounded
rather than total); see the README's "Verification harness" section for how to run it. `dev-test.ps1` runs
the default suite (no z3 required); `t_symex*` suites need the opt-in z3 image; `-Soak`/`-CorpusReport` are
separate, local-opt-in-only modes of `dev-test.ps1`, never run by the default suite or CI.

| Claim | Verifying target(s) |
|---|---|
| `validatePath`/`validateWritePath` never resolve outside the configured root — `..`, absolute-path, and NUL traversal inputs are refused (lexical) | `tests/t_security.nim` coverage-guided fuzz property, `testId: "security.validatePath.lexical"` (200 examples, corpus-persisted under `tests/corpus/`) — the oracle asserts the **no-escape invariant** (any accepted path stays within root) over these traversal classes, not merely that a literal `..` is the rejection reason |
| …symlink/junction escape refusal (needs a real reparse point — not fuzzable from a corpus, see the RFC's D3) | `tests/t_security.nim` suites "validatePath symlink containment (issue #19)" and "validatePath junction containment (K1)"; `tests/t_props_server.nim` end-to-end tests (e.g. "RRQ with md5 checksum still succeeds when the sidecar path is a pre-planted escaping symlink") |
| Windows reparse-bit detection (symlinks/junctions unresolved by `expandFilename`) | Same junction-containment suite (`t_security.nim` "validatePath junction containment (K1)") — dynamic, built against a real NTFS junction fixture |
| `.md5` sidecar: unconditional symlink refusal on the sidecar path itself | `tests/t_checksum.nim` fuzz property `testId: "checksum.writeSidecar"` (lexical never-escape half); `tests/t_security.nim` suite "writeSidecar containment (slice 4)" (dynamic symlink-escape refusal, e2e) |
| Write policy (`wpDeny`/`wpCreateOnly`/`wpOverwrite`/`wpCreateOrOverwrite`) | `tests/t_security.nim` suite "checkWriteAccess" (example tests, one per policy/state combination); `tests/t_props_server.nim` suite "server write-policy enforcement (end-to-end)" |
| Reserved `.md5` namespace refusal — lexical half | `tests/t_security.nim` coverage-guided fuzz property, `testId: "security.checkWriteAccess.reservedLexical"` |
| …canonicalized-alias half (in-root symlink aliasing a `.md5` target) | `tests/t_security.nim` suite "checkWriteAccess reserved .md5 namespace: symlink alias (H1)"; `tests/t_props_server.nim` (e.g. "WRQ to an in-root symlink aliasing a real .md5 sidecar is rejected, sidecar unchanged (H1)") — dynamic e2e, not fuzzed (needs a real symlink) |
| Host access (`checkHostAccess`: denylist wins, empty allowlist allows all) | `tests/t_props.nim` property "checkHostAccess: denylist wins; empty allowlist allows all"; `tests/t_security.nim` suite "checkHostAccess" |
| Transfer ID (TID) lock rejects off-TID DATA/ACK/ERROR/garbage | `tests/t_hostile.nim` coverage-guided stateful property `testId: "hostile.offTidInjection"` ("off-TID DATA/ACK/ERROR/garbage is rejected by the TID lock, never raises a Defect", D8b), its run-level anti-vacuity assertion (`d8bLiveInjections>0` — off-TID packets genuinely land mid-flight — and `d8bBounceTotal>0` — `recvOnce`'s TID-mismatch/ERROR-bounce arm actually fired), plus the deterministic companion test "off-TID DATA is bounced" |
| Never-throw-Defect discipline — `protocol.decode` | `tests/t_props.nim` fuzz property `testId: "protocol.decode"` (allowed: `TftpDecodeError` only); `tests/t_symex_decode.nim` bounded `sxUnsat` proofs (`tIndexError`/`tFieldDefect`) over `seq[int]`-masked twins for the fixed-size arms (`opData`/`opAck`/`opError`), plus a concrete differential oracle against the real `decode(seq[byte])` over hand vectors + fuzzed input. **Scope (bounded, not total)**: the RRQ/WRQ option-parsing arm is `sxUnsat` only for header dispatch + the *first* filename/cstring scan — a second, chained bounded scan (whose start offset is the first scan's symbolic result) returns `sxUnknown`, a genuine dependent-loop solver gap in the pinned proptest build (confirmed invariant under `maxLoopUnwind`/`maxCallDepth`/`symexAssume` retuning), so this is a proof over the header + first field, **not** "all RRQs/WRQs proven." |
| …option negotiation (`negotiateServerOptions`, `validateAndParseOack`) | `tests/t_props.nim` fuzz properties `testId: "options.negotiateServerOptions"` (allowed: `ValueError` only) and `testId: "options.validateAndParseOack"` (total — no exception at all permitted); `tests/t_symex.nim` bounded `sxUnsat` proofs (`tIndexError`/`tFieldDefect`) and validated `sxRaised` witnesses over 8 per-arm parser twins (z3 image, opt-in) |
| …netascii decoder/encoder | `tests/t_netascii.nim` fuzz properties `testId: "netascii.NetasciiDecoder.feed"` and `testId: "netascii.NetasciiEncoder.feed"`; `tests/t_symex_netascii.nim` suite "symex: NetasciiDecoder.feed single-byte transition (non-conformant-CR arm)" — an EXHAUSTIVE (not unwind-bounded) `sxUnsat` proof over the full 512-state `(pendingCr, byte 0..255)` space for the wire→local non-conformant-CR decode branch (the genuinely hostile arm; the encoder only ever sees trusted local bytes, so it is out of scope for this proof), with a differential oracle checked over all 512 pairs against the real `feed()` |
| …path/write-access parsers | `tests/t_security.nim` fuzz properties `testId: "security.validatePath.lexical"` and `testId: "security.checkWriteAccess.reservedLexical"` (both total — no exception of any kind permitted); `tests/t_symex_security.nim` suites "symex: validatePath lexical prefix (through isWithin)" and "symex: checkWriteAccess reserved-.md5 lexical check (isReservedSidecarName)" — bounded `sxUnsat` (`tIndexError`/`tFieldDefect`) over test-only pre-I/O twins. **Scope**: the shipped `validatePath`/`checkWriteAccess` call unmodeled syscalls (`canonicalize`/`symlinkExists`/`hasReparseComponent`, absent from proptest's effectful-proc allowlist), so this proves only the lexical prefix — through the first `isWithin` check, and the pre-canonicalize `.md5` check respectively — the same scope the fuzz properties above already cover, now with an exhaustive-over-the-modeled-space proof rather than sampling; the I/O-dependent tail is verified only by the dynamic e2e suites elsewhere in this table. Two twin/shipped-proc divergences are explicitly documented in the suite, not hidden: case-folding (`toLowerAscii` is unmodeled by proptest) and an `os.extractFilename("//a/..")==""` UNC quirk. |
| …URI parsing (`tftp_uri.parseTftpUri`/`isTftpUri`) | `tests/t_symex_uri.nim` suite "symex: tftp_uri.parseTftpUri slicing twin" — bounded `sxUnsat` proofs (`tIndexError`/`tFieldDefect`/`tRaisedExn(ValueError)`) over an extracted twin (`parseTftpUriTwin`) covering the attacker-influenced slice offsets (`rest[1 ..< closeBracket]`, `hostPort[colonPos+1 .. ^1]`, `params[5 .. ^1]`); a differential oracle (suite "differential oracle: parseTftpUriTwin(string) === parseTftpUri(string)") checks the twin against the real parser over hand-picked valid/malformed URIs. **Scope**: the shipped `parseTftpUri`/`isTftpUri` themselves hit `sxUnknown` (unmodeled `toLowerAscii`/`rfind`) — the twin substitutes case-sensitive checks and a forward `find` for `rfind`, validated equivalent to the real parser only where host/port tokens are colon-free (where `find`≡`rfind` exactly); a bounded proof, not a total one over every input shape. Previously covered only by 15 hand-written examples (`tests/t_uri.nim`) — this is the first systematic proof over offsets reachable from arbitrary embedder strings (RFC #17). |
| …`.md5` sidecar writer | `tests/t_checksum.nim` fuzz property `testId: "checksum.writeSidecar"`; `tests/t_symex_checksum.nim` suite "symex: checksum.writeSidecar lexical sidecar-path derivation" — `sxUnsat` (`tIndexError`/`tFieldDefect`) proven directly on the real derivation logic (a single `&`-concat, no test-only extraction needed), with an indirect-but-exact differential oracle: drives the real `writeSidecar` against a disposable temp root and asserts the sidecar lands at exactly the twin's predicted path. |
| …event queue | `tests/t_eventqueue.nim` fuzz property `testId: "eventqueue.opseq"` |
| …a live session under forged/garbage injection | `tests/t_hostile.nim` coverage-guided stateful property `testId: "hostile.payloadInjection"` ("injected forged/garbage DATA/ACK/ERROR never raises a Defect", D8a) — drives real `sendBlocks`/`recvBlocks` (both `{.cover.}`-instrumented, along with `recvOnce`) over a `proptest/stateful` state machine, with a run-level anti-vacuity assertion (`d8aLiveInjections>0`) proving injections genuinely reach a live in-flight DATA/ACK window, not only the post-transfer dally epilogue. **Scope (R1-7, documented narrowing):** the hostile-session harness covers the post-negotiation *data phase* (`sendBlocks`/`recvBlocks`); the RRQ/WRQ + OACK *negotiation phase* (`handleRrq`/`handleWrq`) is **not** yet driven under hostile injection. Extending to it needs a real request/OACK-speaking client counterpart plus per-example disk setup/teardown — a separate harness slice, tracked as a follow-up, not closed here. |
| …the public API facade (`src/chapulin/api.nim`) itself | `tests/t_a2_facade_stateful.nim` suite "A2: facade stateful StateMachine over a REAL TftpSession pair (RFC verification-harness-v2.md A2)" — a real client↔server `TftpSession` pair driven over `Wire` (BlockSource/BlockSink in-memory I/O, no disk) through `startTransfer`(get/put)/`startServer`/`cancel`/`stop`/a shared fixed-tick pump/`close`, varying mode (octet/netascii) and blocksize/windowsize; asserts no Defect escapes api.nim's `except CatchableError` boundaries, `poll` never raises, and `drain`/`close` terminate within a fixed 100-round tick cap (never the wall-clock path). Extended by suite "A3: hostile injection into the facade StateMachine (RFC verification-harness-v2.md A3)" — coverage-guided `fuzzProperty`, `testId: "facade.hostileInjection"` (corpus `tests/corpus/facade.hostileInjection.bin`) — adding forged/garbage/off-TID DATA/ACK/ERROR + malformed RRQ/WRQ + forged OACK injection, with `VacuityCounter` anti-vacuity (both sides of the session provably progress under hostility, not just one). The wall-clock waiters get a separate, narrower property: suite "A2: narrow waitTransfer/waitServer property (kept separate from the tick-pumped StateMachine)" in the same file. **The Defect-detection guarantee this rests on is itself proven, not assumed**: `tests/t_defect_canary.nim` (a committed, always-run canary) confirms a `StateMachine` invariant's Defect is classified `"strategy crashed:"` on replay and the weaker-but-universal `"crashed:"` on cold discovery, and `tests/t_asynccheck_tripwire.nim` confirms `src/` carries zero call-form `asyncCheck(` invocations (a detached Future's Defect would otherwise be silently lost, making the whole facade property vacuous). **Scope**: this verifies the facade's orchestration/never-throw boundary over a `Wire`-mocked transport+listener (deterministic, hermetic); it does not, and cannot, prove anything about real OS socket/file-descriptor faults (out of scope per the RFC's own non-goals — symex/mocked harnesses can't model the OS). |
| Option bounds-checking/clamping; numeric overflow → `ValueError` → `ERROR(8)` | `tests/t_props.nim` property "negotiateServerOptions clamps blocksize/windowsize to server limits", plus the `options.*` fuzz/symex targets listed above |
| Event queue hard bound + oldest-drop under saturation (terminal events included) | `tests/t_eventqueue.nim` fuzz property `testId: "eventqueue.opseq"` — safety invariant `q.len <= cap` and drop-accounting invariant `pendingDropCount>0 ⇒ q.len==cap`, fuzzed over a mixed op sequence that includes terminal (`epComplete`/`epError`) event kinds |
| `maxConcurrent` bounds simultaneous transfers | `tests/t_a4_maxconcurrent.nim`, two suites. (1) "the (N+1)th inbound request is rejected while server.activeTransfers == maxConcurrent, observed via onRejected" — drives the `TftpServer`/`run()` accept loop directly (a `WireRegistry`-backed `transferFactory` + hand-fed `ListenerQueue`) and asserts the anti-vacuity condition `activeAtReject == cfg.maxConcurrent` at the moment of rejection — keyed on the inbound gate `server.activeTransfers`, **not** `activeClientCount` (the session's own disjoint outbound-transfer counter, which this scenario never touches). (2) "a session observes the (N+1)th rejection as evServerRejected, not a free-text log substring" — proves the rejection surfaces through the public facade as the new structured `evServerRejected` `Event` (`xfrId == NoTransfer`, `rejClientHost`/`rejClientPort`/`rejCode`/`rejMsg` populated), not a log-string convention an embedder would have to parse. **This claim required a production change** — the only `src/` change in the whole v2 RFC: the three reject sites in `server.nim` (no-available-port, host-access denial, maxConcurrent) were rerouted from a direct `newUdpTransport(0)` call to `server.transferFactory(0)`, and a new `ServerCallbacks.onRejected` hook + `EventKind.evServerRejected` were added, since the reject fires before a transfer id is minted and none of the four existing callbacks could carry it. Every transport in both suites comes from the test's `WireRegistry`, never `transport.newUdpTransport`, so the property is real-socket-free by construction. |
| Transfer transports allocated from a bounded port range | `tests/t_server.nim` suite "allocateTransferTransport — port-range retry (RFC design-bar-closure D2)" — example tests (advances through the range on `OSError`, reports not-bound when exhausted, binds directly when unconfigured) |
| Information-leak hygiene — `redactRoot` | `tests/t_server.nim` property "redactRoot never leaves rootDir as a substring of its output, never a Defect" |
| …`sanitizeForDisplay` | `tests/t_format.nim` properties (never a raw control byte except `?`; length-preserving; high bytes pass through unchanged); `tests/t_api.nim` suite "API - sanitizeForDisplay" (example tests at the facade level) |
| The default fuzz corpus is a real coverage-guided **campaign product**, not a fixed thin seed, and stays cheap to replay | `pwsh scripts/dev-test.ps1 -Soak <seconds>` runs `tests/soak_decode.nim` (proptest's `fuzzWith`/`fmIR` coverage-guided loop, `--panics:off`) against `protocol.decode` and deposits clean growth into `tests/corpus/protocol.decode.soak-corpus.bin`, which the default suite replays on every run; on the FIRST Defect it stops, minimizes, commits the crash under `tests/corpus/<testId>.soak-crash.bin`, and exits non-zero — the stop/minimize/commit/exit-nonzero contract is itself proven by `tests/soak_canary.nim`'s synthetic crasher. `tests/t_corpus_minimize.nim` (in the default suite) then re-minimizes campaign growth via proptest's real, only-reachable `minimizeCorpus` door and independently re-verifies coverage held (measured 16→9 entries, 13/13 edges preserved on `protocol.decode`), enforces a per-target `CorpusSizeCeiling = 16` (`tests/fuzzsupport.nim`) on every committed `.soak-corpus`/`.soak-crash` file so growth can't silently balloon default-suite replay time, tags every entry with campaign provenance (`tagProvenance`/`loadProvenance`: source + campaign date, in the corpus's own secondary/scores section), and replays every committed soak/dictionary/interop-capture entry as a default-suite safety net. **Local-opt-in only** — `-Soak` is never invoked by CI or the default suite; growing the corpus is a manual operator action, by design. |
| A campaign can be shown to measurably increase coverage on an under-covered target | `tests/t_coverage_report.nim` (in the default suite) — a RED-GREEN acceptance test against a **synthetic** deliberately-under-covered target, asserting `coverageDelta(...).expanded == true` once a new seed reaches a previously-unreached arm, and the converse (`expanded == false`) for an unchanged corpus. `pwsh scripts/dev-test.ps1 -CorpusReport` exposes the same before/after visited-edge signal for any real committed target. **Honest scope**: asserting `after > before` against a REAL `src/` target is not repeatable — `protocol.decode` was already fuzzed to convergence in v1/C1/C4 on the coarse 8192-slot coverage bitmap, so a fresh soak burst can legitimately find zero new edges. Confirmed exactly that, once, as this RFC's own one-time demonstration: baseline 9 committed entries / 13 visited edges → after a 5-second `-Soak` campaign, 16 entries / **still 13** visited edges. Recorded as the expected outcome of an already-converged corpus, not claimed as an automated increasing-coverage guarantee. |
| Seed diversity spans protocol boundary values, known-bad options, reserved device names, and real-traffic shapes | `tests/t_soak_encoder.nim` (in the default suite) — a byte→choice-IR encoder (`encodeByteSeqIR`) round-tripped through the ACTUAL fuzz strategy (not just structurally), seeding blksize/tsize/windowsize boundary values (2¹⁶/2³²/2⁶³ ±1, zero, negative-ish), known-bad option strings, and reserved Windows device names (`CON`/`NUL`/`COM1`–`9`/`LPT1`–`9`, case-insensitive + dotted variants). `tests/t_interop_capture.nim` (in the default suite) builds the harvest mechanism (a from-scratch classic-pcap parser, `tests/interopcapture.nim`, plus new `docker-compose.yml` tcpdump sidecars on the interop network) that deposits real captured-packet seeds under an `interop-capture` provenance tag; atftp's PUT leg (a known always-PASS interop-harness bug — `echo "PASS…$$?"` reports `echo`'s own exit code, not atftp's) is kept segregated under a distinct `interop-capture-unverified` tag, never merged into the trusted seed pool. **Honest scope-down**: a real capture could not be exercised in this environment — this host's Docker Desktop is pinned to Windows containers and the (Linux-only) interop images cannot even be pulled here — so the harvest path is proven end-to-end against representative hand-built pcap samples instead of a genuine capture; the mechanism is built and documented for the next Linux-capable environment, not yet exercised live. |

## Security non-goals

chapulin deliberately does **not** implement these. Each is out of scope for a reason,
not an oversight:

- **Transfer-layer confidentiality or authenticity (encryption / signing / MAC over the
  wire).** TFTP carries no trust anchor — no key, cert, or signature semantics — so any
  self-contained integrity check travels the same untrusted channel as the file and buys
  nothing against an on-path attacker who rewrites both. Real tamper protection belongs
  to **self-authenticating payloads** (signed boot/firmware images verified by the
  consumer against a pre-provisioned key), which work over *any* conformant TFTP,
  chapulin included, and require no code from us. If you need integrity, sign the
  payload; don't trust the transport.
- **The `.md5` checksum sidecar is not a security control.** It exists for
  **accidental-corruption detection** and `md5sum(1)` interoperability. MD5's collision
  weakness is irrelevant to accidental corruption, and no hash sidecar (MD5 or SHA-256)
  provides tamper resistance without an out-of-band trust anchor. Do not rely on it to
  detect malicious modification.
- **In-process OS sandboxing (chroot / namespaces / jails / AppContainer) and privilege
  dropping (`setuid`/`setgid`).** These require FFI syscalls that chapulin's FFI-free
  constraint forbids, and a *library* must not jail or drop privileges on its host
  process (the CLI, GUI, and embedders share that process). Containment-of-the-process
  is the **deployer's** decision — see Deployment hardening.
- **Authentication of peers.** TFTP has none; host allow/deny is coarse network filtering
  only.

---

## Residual limitations (known and accepted)

We hold path validation as a **primary control that must be correct** — it is not a
kernel-enforced jail, so it is best-effort-correct, not correctness-independent. Known
residuals:

- **TOCTOU on writes.** There is a validate-then-open / `symlinkExists`-then-`writeFile`
  gap. Closing it fully needs `openat2(RESOLVE_BENEATH)` / `O_NOFOLLOW|O_EXCL` (POSIX) or
  handle-based Windows APIs — all FFI, which we do not use. The window is narrow and
  documented in-code; a kernel sandbox (below) closes it externally.
- **Windows path edge cases.** `expandFilename` does not resolve symlinks/junctions on
  Windows, so containment there relies on reparse-bit refusal rather than resolution
  (best-effort, documented). Windows filesystem semantics — alternate data streams
  (`file:stream`), 8.3 short names, trailing dots/spaces, device names (`CON`, `NUL`,
  `COM1`), case-insensitivity — are a large surface a userspace check must get right.
  This is the most likely place a containment bug would hide, and the productive place
  to invest test rigor.
- **Correctness-dependent containment.** A jail contains you even if our check has a bug;
  our check is the only line. Treat OS sandboxing as defense-in-depth, not optional.
- **Event loss under queue saturation.** The hard-bounded queue drops the oldest event —
  which can include a terminal/error event — under sustained saturation. A `dropped N`
  warning is always surfaced, so total silent loss is impossible, but a consumer relying
  on receiving *every specific* error event (e.g. downstream alerting) may miss which
  transfer/peer triggered one during a flood. This is the accepted cost of a guaranteed
  memory bound.
- **No privilege drop.** If chapulin binds the privileged TFTP port (69) as root and does
  not drop privileges (it can't, FFI-free), any containment bug runs with that privilege.
  Bind the port without root — see below.
- **ERROR-reply reflection.** UDP has no return-path verification, so an attacker can spoof
  a victim's source address in an unsolicited/malformed request; chapulin's fail-closed
  design replies with an `ERROR` packet, which lands at the spoofed victim instead of the
  real sender. This is a minor **reflection** vector, not an **amplification** one: a TFTP
  `ERROR` packet is small and bounded by the request that provoked it (roughly 1:1
  request-to-reply size), so chapulin cannot be leveraged as a bandwidth-multiplying DDoS
  reflector the way UDP protocols with large response payloads (DNS, NTP, memcached) can.
  Mitigate at the network edge: rate-limit inbound UDP on the served port, and prefer the
  network-placement guidance below (trusted/isolated segment) over open internet exposure.

---

## Recommended deployment hardening (the operator's ring)

chapulin does its portable, always-on containment; the **kernel sandbox and least
privilege are yours to add**, and we strongly recommend them as defense-in-depth.

### Least privilege & the port-69 problem
- Do **not** run chapulin as root. To bind UDP/69 without root, use
  `setcap CAP_NET_BIND_SERVICE=+ep` on the binary, `authbind`, systemd socket
  activation, or a high port behind a firewall redirect.
- Run as a dedicated unprivileged user/service account whose filesystem access is
  limited to `rootDir` via OS permissions/ACLs.

### Sandbox the process
- **Linux (systemd):** `ProtectSystem=strict`, `ReadWritePaths=<rootDir>` (or omit it
  entirely for a read-only RRQ server), `PrivateTmp=true`, `NoNewPrivileges=true`,
  `RestrictAddressFamilies=AF_INET AF_INET6`, and a locked-down `User=`.
- **Containers:** run with `rootDir` as the only bind mount — **read-only** for a pure
  RRQ (download) server — as a non-root UID, with a minimal image.
- **Windows:** a dedicated low-privilege service account with NTFS ACLs scoping
  `rootDir`; optionally AppContainer or Windows Sandbox.

### Network placement
- TFTP is unauthenticated and unencrypted. Keep it on a **trusted/isolated network
  segment** (e.g. a provisioning VLAN), not a routable or hostile network. If bytes must
  cross an untrusted path, tunnel over IPsec/VPN or sign the payload — the transport
  itself provides no protection.

### Server configuration
- Keep the default **read-only** (`wpDeny`) write policy unless writes are required;
  widen to the narrowest policy that works (`wpCreateOnly` over `wpCreateOrOverwrite`).
- Set `allowedHosts` to the known client set where feasible (defense-in-depth, not
  authentication).
- Bound `maxConcurrent` and the transfer port range to your expected load.

---

## Why the FFI-free constraint shapes this

chapulin is intentionally FFI-free (no `importc`/`exportc`/`dynlib`/`cdecl`/`{.header.}`/
`std/winlean`, and no `std/posix` syscall bindings). This buys portability, a small
auditable surface, and no C-boundary memory-safety hazards — but it means the OS-level
controls that *would* give correctness-independent containment (chroot, namespaces,
`O_NOFOLLOW`, privilege drop, AppContainer) are unavailable in-process **by design**.
We compensate with rigorous userspace containment and by pushing kernel enforcement out
to the deployment ring, where it belongs for a library anyway.
