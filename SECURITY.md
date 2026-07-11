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
[`docs/rfc/verification-harness.md`](docs/rfc/verification-harness.md); see the README's "Verification
harness" section for how to run it. `dev-test.ps1` runs the default suite (no z3 required); `t_symex*`
suites need the opt-in z3 image.

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
| Never-throw-Defect discipline — `protocol.decode` | `tests/t_props.nim` fuzz property `testId: "protocol.decode"` (allowed: `TftpDecodeError` only) |
| …option negotiation (`negotiateServerOptions`, `validateAndParseOack`) | `tests/t_props.nim` fuzz properties `testId: "options.negotiateServerOptions"` (allowed: `ValueError` only) and `testId: "options.validateAndParseOack"` (total — no exception at all permitted); `tests/t_symex.nim` bounded `sxUnsat` proofs (`tIndexError`/`tFieldDefect`) and validated `sxRaised` witnesses over 8 per-arm parser twins (z3 image, opt-in) |
| …netascii decoder/encoder | `tests/t_netascii.nim` fuzz properties `testId: "netascii.NetasciiDecoder.feed"` and `testId: "netascii.NetasciiEncoder.feed"` |
| …path/write-access parsers | `tests/t_security.nim` fuzz properties `testId: "security.validatePath.lexical"` and `testId: "security.checkWriteAccess.reservedLexical"` (both total — no exception of any kind permitted) |
| …`.md5` sidecar writer | `tests/t_checksum.nim` fuzz property `testId: "checksum.writeSidecar"` |
| …event queue | `tests/t_eventqueue.nim` fuzz property `testId: "eventqueue.opseq"` |
| …a live session under forged/garbage injection | `tests/t_hostile.nim` coverage-guided stateful property `testId: "hostile.payloadInjection"` ("injected forged/garbage DATA/ACK/ERROR never raises a Defect", D8a) — drives real `sendBlocks`/`recvBlocks` (both `{.cover.}`-instrumented, along with `recvOnce`) over a `proptest/stateful` state machine, with a run-level anti-vacuity assertion (`d8aLiveInjections>0`) proving injections genuinely reach a live in-flight DATA/ACK window, not only the post-transfer dally epilogue. **Scope (R1-7, documented narrowing):** the hostile-session harness covers the post-negotiation *data phase* (`sendBlocks`/`recvBlocks`); the RRQ/WRQ + OACK *negotiation phase* (`handleRrq`/`handleWrq`) is **not** yet driven under hostile injection. Extending to it needs a real request/OACK-speaking client counterpart plus per-example disk setup/teardown — a separate harness slice, tracked as a follow-up, not closed here. |
| …the public API facade (`src/chapulin/api.nim`) itself | **No dedicated fuzz/stateful target drives hostile bytes through `api.nim`'s own entry points** (`request`/`poll`/`drain`/session teardown). Coverage today is *transitive*: `t_hostile.nim` exercises the same `sendBlocks`/`recvBlocks` primitives `api.nim` wraps, and every parser it calls into is fuzzed individually above — but nothing proves the facade's own `except CatchableError` boundaries (`api.nim:411,586,635,668`) under load. **Follow-up, not a blocker**: a `stateful` property over a `TftpSession` (or embedding-API surface, per RFC #17) would close this directly. |
| Option bounds-checking/clamping; numeric overflow → `ValueError` → `ERROR(8)` | `tests/t_props.nim` property "negotiateServerOptions clamps blocksize/windowsize to server limits", plus the `options.*` fuzz/symex targets listed above |
| Event queue hard bound + oldest-drop under saturation (terminal events included) | `tests/t_eventqueue.nim` fuzz property `testId: "eventqueue.opseq"` — safety invariant `q.len <= cap` and drop-accounting invariant `pendingDropCount>0 ⇒ q.len==cap`, fuzzed over a mixed op sequence that includes terminal (`epComplete`/`epError`) event kinds |
| `maxConcurrent` bounds simultaneous transfers | **No verifying target.** `tests/t_session.nim` only round-trips `maxConcurrent` through config parsing (`config.maxConcurrent == 5`); nothing tests that the (N+1)th concurrent transfer is actually rejected/queued. The verification-harness RFC scoped this out deliberately ("resource bookkeeping over trusted config, not a parse/Defect surface") — a reasonable call for *this* RFC, but the enforcement path itself is genuinely untested today. Flagged here as a follow-up for a future (non-fuzzing) test slice, not a gap this RFC should have closed. |
| Transfer transports allocated from a bounded port range | `tests/t_server.nim` suite "allocateTransferTransport — port-range retry (RFC design-bar-closure D2)" — example tests (advances through the range on `OSError`, reports not-bound when exhausted, binds directly when unconfigured) |
| Information-leak hygiene — `redactRoot` | `tests/t_server.nim` property "redactRoot never leaves rootDir as a substring of its output, never a Defect" |
| …`sanitizeForDisplay` | `tests/t_format.nim` properties (never a raw control byte except `?`; length-preserving; high bytes pass through unchanged); `tests/t_api.nim` suite "API - sanitizeForDisplay" (example tests at the facade level) |

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
