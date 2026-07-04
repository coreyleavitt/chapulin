# RFC: Checksum integrity + error-message hygiene (server hardening)

- **Status:** Draft — **architect rounds 1 & 2 applied; Q1 → Option A. No open forks. Ready for `/tdd`.**
- **Tracking issue:** none — spun out of the [#19](https://github.com/coreyleavitt/chapulin/issues/19)
  code-review as the *related, lower-severity* items explicitly left out of the #19 symlink fix.
- **Scope:** primarily `src/chapulin/server.nim` + a new `src/chapulin/checksum.nim`. **The correct fix for
  the checksum TOCTOU (round-1 depth finding) additionally requires a small, additive, non-breaking hook in
  `src/chapulin/transfer.nim`** — the original "server.nim only" scope was an incorrect assumption
  (resolved by Q1 → Option A). No public-API *shape* change (the `.md5` sidecar contract and TFTP ERROR
  opcodes are unchanged).

## Why now

The #19 fix closed the path-containment hole. Its review surfaced residual server-side defects that share
one root cause: **the server re-reads or re-exposes state it already holds, and does so carelessly.** None
is urgent (checksums are default-off; the leak needs an OS error to fire), so they don't warrant tracking
issues — but they're cheap to fix correctly now, while the server internals are fresh. Folding them into
one mini-RFC keeps the reasoning (and the tests) in one place. Round-1 review then found that one of them
(the checksum TOCTOU) is deeper than it first appeared and that the `.md5` **sidecar write reopens the very
symlink-escape class #19 just closed** — so this is worth doing properly, not as a drive-by.

## Problem

Five grounded defects, all reachable from `server.nim`:

1. **Unbounded checksum read → OOM.** `generateChecksum` (`server.nim:70-78`) does `readFile(filePath)` —
   the *entire* file into one `string` — before `toMD5`. A multi-GB file under `--checksum=md5` allocates
   its whole size in RAM. Default-off (`csNone`), so latent, but it defeats a *streaming* file server.

2. **Checksum TOCTOU → sidecar lies about served bytes.** The RRQ path serves through an open fd
   (`file`, `server.nim:126`; the real-file `readData` closure at `173-180` — *not* the dir-listing
   closure at `107-112`), then — *after* `sendBlocks` completes — `generateChecksum` performs a **second,
   independent open** (`readFile`) of the same path (`server.nim:196-197`). Under `--write=all`
   (`wpCreateOrOverwrite`) a concurrent WRQ overwrites the file in the gap — and `open(_, fmWrite)`
   (`server.nim:256`) **truncates at open time**, so the window is the whole transfer, not a hair. The
   `.md5` then describes bytes the client never received. *(Round-1 depth finding: this race is not even
   fully closed by "hash while serving" — see Design D1 and Q1 — because `sendBlocks` re-reads the file on
   retransmit, so a block resent after truncation sends new bytes the naive first-send hash never sees.)*

3. **OS error detail leaked to the remote client — and to embedding-API frontends.** `open()` failures
   forward `IOError.msg` verbatim: into the TFTP ERROR packet on the wire (RRQ `server.nim:128`, WRQ
   `server.nim:258`) **and** into `failResult(... & e.msg)` (`server.nim:129,259`), whose message becomes
   `TransferResult.errorMsg` → `onTransferError(info, msg)` (`server.nim:433`) → the embedding-API
   `evTransferError.errorMsg` (RFC #17). On both POSIX and Windows that message embeds the **absolute
   server path** and OS errno text — handed to an unauthenticated client *and* to any GUI/frontend, which
   may be a different trust boundary than "operator with shell access." `sanitizeForDisplay`
   (`format.nim:23`) only strips control bytes for terminal-escape defense; it does not redact paths, and
   isn't applied on these paths anyway. *(Verified: the only two `sendError` sites that interpolate
   exception/path detail are 128 and 258; every other `sendError` — 116/120/150/218/237/343/465/475 —
   already passes a canned, path-free string.)*

4. **The `.md5` sidecar write is itself an unvalidated symlink-escape (reopens the #19 class).**
   `generateChecksum` does `writeFile(filePath & ".md5", …)` with **no** containment check. `filePath` is
   the *lexical* `resolved` from `validatePath` (`security.nim:62,89`), never the canonicalized real path;
   `.md5` is appended and written directly. Same threat model as #19: an attacker who plants
   `<name>.md5` as a symlink pointing outside `rootDir` causes a subsequent `--checksum=md5` RRQ of
   `<name>` to `writeFile` **through** that symlink, clobbering an arbitrary out-of-root file with
   attacker-observable content. The #19 fix guards the *served* file; it does nothing for the sidecar.

5. **The `.md5` sidecar name is unprotected from a *direct WRQ* — the attestation is forgeable without any
   symlink (round-2 breadth).** Defect 4 guards `writeSidecar`'s own write; it says nothing about the
   independent `handleWrq` path (`server.nim:203-291`). `checkWriteAccess` (`security.nim:91-108`) has no
   concept of a reserved filename, so under any policy other than `wpDeny` an unauthenticated client can
   `WRQ "<name>.md5"` with arbitrary content — before, after, or racing a legitimate RRQ's sidecar write.
   A client can also RRQ the sidecar directly, so a forged digest is observable before the next `csMd5` RRQ
   of `<name>` regenerates it. The feature's whole purpose — a client-verifiable attestation of what was
   served — is defeatable by any client that can write at all. This is a distinct sink from defect 4
   (symlink escape *out* of root); this one clobbers/forges the sidecar *in-place, in-root*.

## Design

Three decisions. D1 dissolves defects 1+2 (mechanism = Q1→Option A); Ds dissolves 4 **and 5**; D2
addresses 3.

### D1 — A checksum module that hashes the bytes actually delivered (fixes 1 + 2)

Stop re-reading the file. Extract a small, FFI-free `src/chapulin/checksum.nim` — its own module because it
is a distinct concern that will grow (`csSha256`) and because a digest reachable only by also writing a
file is a missed reuse point for the embedding API:

```nim
# checksum.nim
type
  Digester* = ref object
    case mode*: ChecksumMode
    of csMd5:    ctx: MD5Context          # std/md5 incremental; seq[byte] satisfies md5Update's openArray[uint8]
    of csSha256: discard                  # unreachable: newDigester(csSha256) raises (see below)
    of csNone:   discard

proc newDigester*(mode: ChecksumMode): Digester
  ## csNone → a no-op digester; no MD5Context allocated.
  ## csSha256 → raises ValueError (unsupported). Belt-and-suspenders: startServer also rejects
  ## csSha256 at construction (matching the CLI parseChecksumMode), so this raise is a guard the
  ## RRQ path should never hit — but it fails loud, never a silent no-op (closes the round-1 finding),
  ## and never a FieldDefect from touching the discard arm (see [[never-throw-defect-hazard]]).
proc update*(d: Digester, data: openArray[byte])
  ## Feeds confirmed bytes; no-op for csNone. MUST special-case `data.len == 0` as a true no-op
  ## BEFORE taking `unsafeAddr data[0]` — a zero-length seq has no backing store, so the pointer
  ## bridge to std/md5's `cstring,len` shape is out-of-bounds (IndexDefect / UB) on the empty
  ## terminating DATA block that every exact-blocksize-multiple file sends (round-2 depth #2).
proc finalize*(d: Digester): string               # PURE: hex digest string, no I/O
proc writeSidecar*(rootDir, resolvedPath, digest: string): tuple[ok: bool, err: string]
  ## I/O, SEPARATE from finalize. Delegates containment to `security.validateWritePath` (see Ds)
  ## and adds an independent, unconditional `symlinkExists` refusal. NEVER raises: its whole body
  ## (containment probe + writeFile) is wrapped `try/except OSError, IOError: (false, e.msg)`.
proc commit*(d: Digester, rootDir, resolvedPath: string): tuple[ok: bool, err: string]
  ## Facade: no-op success for csNone; otherwise finalize() then writeSidecar() in one call, so the
  ## caller never sequences the two by hand. NEVER raises (inherits writeSidecar's contract).
```

`server.nim`'s post-transfer line is **one** guarded call: `if xferResult.success: discard
digester.commit(config.rootDir, resolvedPath)` — `commit` absorbs the `csNone` check and the
finalize→write ordering. `finalize`/`writeSidecar` stay exported for pure unit tests. `finalize` is
unit-testable without touching a filesystem; `writeSidecar` carries the security check; `std/md5`'s C-ish
`cstring,len` shape is hidden inside `update`. When `csNone`, no `MD5Context` is allocated and `update` is a
no-op — **zero overhead on the default path.** Because `commit`/`writeSidecar` never raise, a sidecar
failure (disk full after a multi-GB transfer, permission race) **cannot** fault `handleRrq`'s async Future
and turn a fully-successful RRQ into a reported "unhandled transfer error" (round-2 depth #3) — it returns
`(false, err)`, which the caller may log via the existing `handleRequest` logger (`server.nim:407-415`) but
never propagates to the client or the transfer result. (`std/md5` is `{.deprecated.}` in 2.2.10 but
`server.nim` already imports it; migrating to `std/checksums/md5` is out of scope — a mechanical import
swap.)

**The hard part — feeding `update` with the bytes the client actually got (this is Q1).** Round-1 depth
proved that hashing at *send* time, gated on first in-order delivery, is wrong: `sendOneBlock`
(`transfer.nim:177-187`) re-invokes `readData` on both retransmit paths (partial-ACK refill
`transfer.nim:234`, dup-ACK fast-retransmit `247`), so a block resent *after* a concurrent truncation
transmits **new** bytes to the client that a first-send hash never sees — the digest attests superseded
content. The only correct source of truth is **the bytes confirmed delivered (ACKed)**, hashed once per
block from what was actually transmitted — which is transfer-layer knowledge. Two designs satisfied this;
they differed only in scope/risk (was Q1). **Resolved → Option A** (Corey, round 2 gate). Option B is
retained below only as the recorded rejected alternative.

- **Option A (CHOSEN) — hash ACK-confirmed bytes via a `transfer.nim` hook.** Add an optional,
  default-`nil`, additive param to `sendBlocks`: `onDelivered: proc(data: openArray[byte])` — the payload is
  *only* the confirmed bytes, in delivery order, exactly once per block. (No `blockNum`: the digester never
  needs it; block numbers are transfer-internal, used only to index the send-byte cache. Payload is
  `openArray[byte]` not `seq[byte]` so feeding the cache entry to `update` is zero-copy; fall back to
  `seq[byte]` only if the container's Nim rejects `openArray` in a stored closure proc-type. Name is the
  *contract* — "delivered" — not the mechanism "onBlockAcked".)

  **Firing (round-2 CRITICAL — this is not one call per ACK).** TFTP ACKs are cumulative: `recvBlocks`
  (`transfer.nim:298-314`) only ACKs once per window (`blocksInWindow >= ws`), so a single accepted ACK can
  jump `lastAcked` forward by an entire window when `windowsize > 1` (issue #16 made the server actually
  honor negotiated windows — this is *normal* traffic, not loss recovery). Firing once per ACK packet would
  hash only the last block of each window and silently drop the interior blocks → a wrong `.md5` for any
  ordinary `windowsize>1` client. The hook therefore fires in an **ascending range loop over the delta**,
  placed in the ACK-acceptance branch (`transfer.nim:213-215`) **before** both early-return paths (the
  `hitFinal and lastAcked == windowEnd` return at `:219` and the `high(uint16)` limit return at `:224`):

  ```nim
  let prevAcked = lastAcked
  lastAcked = pkt.ackBlockNum
  dupAcks = 0
  if onDelivered != nil:                       # guard wraps the WHOLE loop (nil closure ⇒ NilAccessDefect)
    for b in (prevAcked + 1) .. lastAcked:
      onDelivered(windowCache[b])              # cache entry = the bytes block b was last sent with
      windowCache.del(b)                       # evict on confirm → memory stays O(window)
  ```

  Because `lastAcked` advances *only* through this one branch, consecutive firings partition the block space
  `(prevAcked+1)..lastAcked` with no gaps and no overlap by construction — which is exactly why it composes
  uniformly with partial-ACK refill and dup-ACK fast-retransmit (those paths never touch `lastAcked`; only
  the accepted-ACK branch does).

  This **also fixes a latent transfer-integrity bug independent of checksums**: today `sendBlocks` re-reads
  the file on every resend, so a mutating file yields inconsistent block content across retransmits (a block
  the client loses and re-receives can legitimately differ) — caching the in-flight window's sent bytes in
  `windowCache: Table[uint16, seq[byte]]` and resending *those* (not a fresh `readData`) is the correct TFTP
  behavior. The cache also makes the **`bytesSent` over-count trivial to fix in passing** (skip the
  increment on a cache-hit resend) — now folded into slice 1.0 rather than deferred, since we're rewriting
  `sendOneBlock`'s read path anyway. Memory: `O(windowsize × blocksize)` for the unacked window (default
  window 1 → one block; bounded regardless of file size). Cost: touches `transfer.nim` and the #18
  fast-retransmit code; the diff has four sites (a `std/tables` import, a cache-hit branch in the
  `sendOneBlock` template shared by all three refill call sites, the eviction loop above, and the
  default-nil param) — budgeted in slice 1.0.
- **Option B (REJECTED — recorded for provenance) — detect mutation, refuse to attest.** Keep hashing while serving,
  but before writing the sidecar, verify the file did not change under us (`getFileInfo` fd identity +
  size + mtime captured at open vs. at finalize; or the round-1 fstat(dev,ino,mtime,size) snapshot). If it
  changed, **write no sidecar** (optionally an `evServerLog` note). Never a false attestation; degrades to
  *absent* under concurrent overwrite. `server.nim`-only; does **not** fix the latent transfer bug.

Both were correct (never a lying sidecar). **A is chosen** — it is the deep fix and repairs real transfer
behavior; B (minimal, `server.nim`-only) is recorded above for provenance only.

*Octet only.* `--mode=netascii` is orphaned (byte transform unwired — see the embedding-API RFC), so
"bytes served == bytes read" holds; carry a `TODO(#13)` if netascii is ever wired.

### Ds — Sidecar name is protected: containment-checked write (fixes 4) + reserved namespace (fixes 5)

**Containment (fixes 4).** `security.nim` is the sole authority for "is this path safe to touch," so the
shared check is **factored into** `security.validateWritePath*(rootDir, absPath): tuple[ok, err]` (not left
as a duplicate-or-export either/or — a security invariant re-derived at two call sites is how #19-class bugs
regress). It generalizes the existing symlink-containment block (`security.nim:78-87`) to an arbitrary
target and keeps its fail-closed `except OSError` policy. `writeSidecar` calls it on `resolvedPath & ".md5"`,
**then adds an independent, unconditional `symlinkExists` refusal** — this is *additive*, not implied by
containment: `validatePath`'s containment deliberately *follows and permits* an in-root symlink (correct for
a served file), but the sidecar must refuse a pre-existing symlink at `<name>.md5` **regardless of where it
points**, or an attacker-planted in-root symlink silently redirects the write to clobber another in-root
file. `writeSidecar` **never raises** (whole body `try/except OSError, IOError`); on failure returns
`(false, err)` and the RRQ still succeeds. *Residual TOCTOU:* the `symlinkExists`-then-`writeFile` gap is a
narrow, accepted race — Nim's `std/os` has no portable `O_NOFOLLOW|O_EXCL` without FFI (this codebase is
FFI-free), so Invariant 5 is worded to that limit rather than an absolute no-follow claim.

**Reserved namespace (fixes 5).** The forged-sidecar-via-WRQ sink is a *different* path — `handleWrq`, not
`writeSidecar`. Close it at the write-authorization layer: when `config.checksumMode != csNone`,
`checkWriteAccess` (`security.nim:91-108`) rejects any target whose name ends in `.md5` with
`errAccessViolation` — the server owns that namespace, exactly as `dirListFile` is already a reserved
pseudo-name. This is the only place a client can name the sidecar, so one gate covers create, overwrite, and
the RRQ-race. (Trade-off noted: a client can no longer *upload* a file literally named `*.md5` while
checksums are on — acceptable; the sidecar contract owns the suffix. Off by default, so zero effect unless
`csMd5` is enabled.)

### D2 — One error-response choke point; generic on the wire *and* in `errorMsg` (fixes 3)

Split the audience structurally rather than by convention at each call site. Two moves:

1. **`clientSafeError(code: TftpErrorCode): string`** — an **exhaustive `case code`** (no `else`), so adding
   a `TftpErrorCode` later *fails to compile* until its generic, path-free string is supplied. Intended use
   is **narrow: wrapping OS-exception messages** (the two sites below) — *not* a blanket replacement for the
   already-useful canned strings at 120/150/237/343/465/475 (flattening "Server busy" → generic would lose
   real, non-sensitive diagnostics).
2. **Remove the raw-string parameter from the two risk sites entirely** — don't merely route it through
   `clientSafeError` and trust every future edit to remember. `sendError` (`server.nim:60`) is *already*
   private (no `*`), so "un-export it" (a round-1 note) buys nothing: the leak sites (`server.nim:128,258`)
   are *intra-module*, where privacy is irrelevant. Instead, replace the duplicated send+`failResult`
   pattern at `:125-129` and `:254-259` with a helper that **cannot** be handed an arbitrary string:

   ```nim
   proc sendOsErrorAndFail(transport: Transport, host: string, port: int,
                           code: TftpErrorCode): Future[TransferResult] {.async.} =
     let msg = clientSafeError(code)
     await sendError(transport, host, port, code, msg)
     return failResult(msg)
   ```

   Now the `except IOError as e:` blocks never bind a call in which `e.msg` is even *reachable* as an
   argument — the compiler-visible surface for "strings that reach the wire" shrinks to one call taking no
   string. This closes the wire leak **and** the `evTransferError.errorMsg` leak in one move —
   `TransferResult.errorMsg` is now generic everywhere it flows (wire, callbacks, events). The operator
   still learns the *class* from the TFTP error code (`errAccessViolation` / `errDiskFull`) and the
   already-logged root-relative filename at `handleRequest` (`server.nim:407-411`); the raw OS errno string
   is dropped from the default path (preserving it would require threading a `Logger` into
   `handleRrq`/`handleWrq`, a signature change touching every direct-call test — deliberately avoided).

Preserving errno for the operator without leaking it to clients is the optional slice 4 (redacted
diagnostic logging), kept separate because it's the lowest-value piece.

*Design note (rationale worth stating):* this is **redaction by non-construction** — the `sendOsErrorAndFail`
helper never *builds* the leaky string, which is strictly deeper than scrubbing `e.msg` after the fact
(`sanitizeForDisplay` can't redact a path anyway) and strictly deeper than routing-by-discipline (which a
future edit can silently bypass). The type of the exception-handling path simply has no seat for a raw
message.

## Invariants

1. **Sidecar = delivered bytes.** For a successful RRQ with `csMd5`, the `.md5` digest equals MD5 of the
   exact byte sequence the client received (ACK-confirmed), **independent of any concurrent write.** On a
   failed/aborted transfer, no sidecar is written (gated on `xferResult.success`).
2. **Bounded server memory.** Checksum generation allocates `O(windowsize × blocksize)` for the unacked
   window — never `O(filesize)` — because delivered blocks are evicted from `windowCache` on ACK.
3. **No OS path/errno on the wire or in `errorMsg`.** No TFTP ERROR packet, `TransferResult.errorMsg`, or
   `evTransferError.errorMsg` contains an absolute filesystem path or raw OS errno text. (Operator logs may,
   only via the optional redacted slice 6.)
4. **Each delivered block hashed exactly once, in order.** Retransmits, duplicate ACKs, and cumulative
   `windowsize>1` ACKs each feed every block's bytes to `update` once and in ascending block order — the
   ascending range-loop over `(prevAcked+1)..lastAcked` partitions the block space with no gap/overlap. The
   empty terminating DATA block is fed as a zero-length no-op, not skipped and not a crash.
5. **No sidecar write follows a symlink present at check time.** `writeSidecar` delegates containment to
   `security.validateWritePath` and additionally refuses any pre-existing `symlinkExists(<name>.md5)` — the
   #19 guarantee extended to the sidecar. (Not an absolute no-follow: a narrow check-then-write TOCTOU
   remains, uncloseable without FFI in an FFI-free codebase — an accepted, documented non-goal.)
6. **Sidecar name is server-owned.** With `csMd5` enabled, no client WRQ can create, overwrite, or forge a
   `*.md5` file — `checkWriteAccess` rejects the suffix, so the only writer of a sidecar is the server's own
   post-RRQ `writeSidecar`.

## `/tdd`-sized slices

Each leaves the suite green. **Two small test-helper prerequisites (found in round 1) are called out inline
so they aren't rediscovered mid-slice.**

**0 (prereq, trivial).** Parameterize the existing `serveWithChecksum` helper (`t_props_server.nim:203-222`)
   to accept a caller-supplied `Wire` (mirror `setupRrq`'s signature, `t_props_server.nim:40-51`) so slices
   1.x–2 can inject loss/overwrite, **and an injectable `windowsize`** (reuse the `serveRrqNegotiated`
   pattern, `t_props_server.nim:110-116`). Factor `validateWritePath` out of `security.nim`'s containment
   block (and export `isWithin`/`canonicalize`) for `writeSidecar`.

*Slice 1 is split three ways (round-2 feasibility): the transfer hook is its own driving RED→GREEN cycle
with zero dependency on `checksum.nim`/`server.nim`, and 1.1 is independent of both.*

**1.0. `transfer.nim` — `onDelivered` hook + send-byte cache (D1 Option A; transfer-layer only).** Add the
   default-`nil` `onDelivered` param, the `windowCache: Table[uint16, seq[byte]]`, the cache-hit resend
   branch in `sendOneBlock`, the ascending-range firing loop with eviction (see D1), and skip the
   `bytesSent` increment on a cache-hit resend. Proven **entirely in `t_props_transfer.nim`**, no checksum
   code involved: assert `onDelivered` fires **once per block, in ascending order**, with the correct bytes,
   under (a) lossless lock-step, (b) dup-ACK fast-retransmit (reuse `dropAOcc`, `t_props_transfer.nim:89-96`),
   and (c) **a `windowsize≥3` cumulative ACK that confirms multiple blocks in one packet** (the CRITICAL
   round-2 case — a naive one-call-per-ACK impl fails here). Existing `t_props_transfer` assertions
   (`senderPackets` counts, #18 regression) stay green — verified none assert sender-side `bytesTransferred`
   across retransmits.

**1.1. `checksum.nim` — pure `Digester`/`update`/`finalize` (+`commit`/`writeSidecar` stubs).** New module,
   independent of 1.0. Unit-tested in a new `t_checksum.nim` with **no filesystem**: `finalize` over a
   multi-block sequence == `toMD5(content)`; **zero-byte file** == empty-content digest; **`update(d,
   newSeq[byte](0))` must not raise** and `[b1, b2, ""]` digests to `toMD5(b1 & b2)` (the empty terminating
   block); `newDigester(csSha256)` **raises** (not `""`, not a Defect).

**1.2. Wire it together (server.nim).** Feed 1.0's `onDelivered` into 1.1's `Digester` from the RRQ path;
   replace `generateChecksum`'s `readFile` with the composed `digester.commit(...)` after a successful RRQ;
   construct the digester only when `checksumMode == csMd5`; **reject `csSha256` at `startServer`**
   (matching the CLI). Tests via the slice-0 harness: (a) sidecar digest == `toMD5(fullContent)` for a
   multi-block **and** a zero-byte file end-to-end; (b) sanity: a `dropAOcc` retransmit on a *static* file
   still yields the correct digest (this is a no-corruption check — it does **not** by itself distinguish
   Option A from a naive design, which slice 2 does); (c) failed transfer writes no sidecar — force via the
   existing `cancelCheck` param (clean `TransferResult(success:false)`), **not** a failing transport (its
   `OSError` faults the Future instead).

**2. TOCTOU regression — the combination test (the real D1 proof; must fail against a naive design).** Use
   `handleRrq`'s existing `onProgress` hook (fired per block in `sendOneBlock`) to `writeFile(path,
   newContent)` **after block K**, *and* force a dup-ACK retransmit of a block spanning that mutation
   (round-1 depth: neither overwrite-alone nor retransmit-alone exercises the bug). This is the test that
   *drives* 1.0's cache design — author it here and confirm it genuinely goes RED by temporarily reverting
   the cache to a fresh `readData` on resend (feasibility #2: with a static file the two designs are
   byte-identical, so only a mid-transfer mutation discriminates them). Assert `sidecar ==
   toMD5(toStr(received[]))` — the bytes the client actually got, captured by `setupRrq`'s `received: ref
   seq[byte]` — never the pre- or post-overwrite file content. *Trigger note:* `onProgress`
   (`transfer.nim:27`) carries no block number, so drive "after block K" off an invocation counter; with no
   OACK the Nth `onProgress` call == block N's first send (occurrence = wire-send index). Document that
   no-OACK assumption inline, or derive the index from `w.aLog`/`w.aSends()` rather than hand arithmetic —
   it shifts by one the moment a variant negotiates options. Deterministic; no second WRQ transfer, no new
   harness. Ideally run one variant at `windowsize≥2` to prove per-block ordering under a cumulative ACK
   *and* a mutation together.

**3a. Generic wire + `errorMsg` (D2, easy).** Add exhaustive `clientSafeError`; route `server.nim:128,258`
   client string **and** `failResult` message through it. Test (portable, no OS failure needed): assert the
   ERROR packet's `errorMsg` and the returned `TransferResult.errorMsg` contain no `rootDir` substring and
   no OS errno text. Provable via a bare `handleRrq` call — consistent with every existing test.

**3b. Real OS open-failure reproduction (D2, POSIX-only).** `when not defined(windows):` — force an actual
   `open()` failure via `setFilePermissions 0o000` / `0o555` dir and assert the same. Scoped POSIX because
   Nim's `setFilePermissions` on Windows only toggles read-only (doesn't block owner reads) and blocking
   reads needs ACL/FFI, which violates the no-direct-FFI rule; CI is tri-platform *native*
   (`ci.yaml:13-14`, not Docker), so the guard is real. The `clientSafeError` mapping is exercised
   identically regardless of trigger, so Windows coverage loss is cosmetic.

**4. Sidecar containment (Ds — CRITICAL, do not skip).** `writeSidecar` delegates to `validateWritePath`
   and adds the unconditional `symlinkExists` refusal; body wrapped never-raise. Tests (beside `t_security`'s
   #19 fixtures): plant `<name>.md5 -> outside`, RRQ `<name>` with `--checksum=md5`, assert the out-of-root
   target is **not** written and the transfer still succeeds; a normal sidecar still writes; **and a
   sidecar-write failure (read-only target dir) returns `(false, err)` without faulting the RRQ.**
   *Windows coverage (round-2 breadth #5):* the #19 fixtures gate on `symlinkOk`, which is `false` on a
   Windows CI leg lacking symlink privilege — so a naive copy would run **zero** assertions on the platform
   where `expandFilename` is weakest. Add a **junction**-based fixture (`New-Item -ItemType Junction` /
   `mklink /J`, no privilege needed) for the Windows leg, or at minimum `checkpoint` the skip so a green
   Windows run isn't misread as "containment verified."

**5. Reserved `.md5` namespace (Ds fixes 5 — HIGH, do not skip).** `checkWriteAccess` rejects a `*.md5`
   target with `errAccessViolation` when `checksumMode != csNone`. Tests (`t_security.nim` +
   `t_props_server.nim`): with `csMd5` enabled, `WRQ "f.bin.md5"` is rejected under each non-`wpDeny` policy;
   a legitimate sidecar written by a prior RRQ is **not** subsequently clobberable by WRQ; with `csNone`,
   `*.md5` WRQ behaves normally (no reservation). Portable — no symlink/OS-failure machinery.

**6. (Optional) Redacted operator logging (D2 follow-on).** Log `open`-failure detail (and non-fatal
   sidecar-write failures) with `rootDir` stripped to root-relative, via the existing `handleRequest` logger.
   Cuttable — the lowest-value piece; kept in-but-last per Q3.

## Testing strategy

- **Substrate:** existing `tests/wireharness.nim` — `newWire(dropAOcc=…)` for retransmit, `onProgress` for
  mid-serve mutation, `cancelCheck` for clean failure, `serveRrqNegotiated` for `windowsize>1`; the
  `t_server` filesystem-model harness for sequences. No new harness *primitive* required — the slice-0 tweaks
  (caller-supplied `Wire`, injectable `windowsize`) are signature-only.
- **New assertions** land in `t_props_transfer.nim` (the `onDelivered` once-per-block/ordering/cumulative-ACK
  proofs, slice 1.0), `t_server.nim`/`t_props_server.nim` (end-to-end checksum + error hygiene),
  `t_security.nim` (sidecar containment **and** the reserved-`.md5` WRQ rejection, beside the #19 tests), and
  a new `t_checksum.nim` for the pure `Digester`/`update`/`finalize` unit tests (incl. the zero-length and
  `csSha256`-raises cases).
- **`>65535`-block tripwire:** one test asserting a transfer exceeding the block-number limit fails with no
  sidecar — documents that the ascending firing-loop's block arithmetic depends on `sendBlocks`' existing
  `high(uint16)` guard (`transfer.nim:224-227`, and the loop must fire *before* that early return) and trips
  if the guard is ever relaxed.

## Out of scope

- **Netascii digest semantics** (#13) — orphaned transform; `TODO(#13)` marker only.
- **`csSha256` (silent-no-op) is NOW IN SCOPE — closed in slice 1.1/1.2, not deferred.** The prior "still
  raises `ValueError`" claim was true only on the *CLI string* path (`parseChecksumMode`,
  `server_config.nim:63-72`); an embedding-API caller setting `ServerConfig.checksumMode = csSha256` directly
  hit `generateChecksum`'s `if mode == csMd5: … ; return ""` and got a **silent no-op**. Resolution:
  `newDigester(csSha256)` **raises** and `startServer` **rejects** it at construction (matching the CLI) —
  fail-loud, never `""`, never a Defect from the discard arm. *Adding the sha256 digest itself* stays out of
  scope.
- **Expose the digest via `TransferResult`/`evTransferComplete` (embedding-API reuse) — deferred follow-up.**
  D1 splits `checksum.nim` out partly so the digest is reusable, but this RFC only writes it to disk; no
  `TransferResult`/`TransferInfo`/RFC-#17 event carries it yet, so a frontend that wants to display/verify a
  checksum must re-read the `.md5` (mildly reopening the "re-read state" smell, but off-default and low-risk).
  Threading the digest through to `evTransferComplete` is a clean **RFC #17 follow-up**, explicitly named
  here rather than silently dropped. The module split still earns its keep on testability + the coming
  sha256, independent of this.
- **WRQ (uploads) never checksum** — intentional and unchanged: the sidecar attests *what a downloader
  received*, not upload integrity; extending to WRQ is a separate feature.
- **WRQ `errDiskFull` code inaccuracy** — `server.nim:258` reports `errDiskFull` for *all* `fmWrite` open
  failures (permission, ENOENT-on-parent), not just ENOSPC. D2 makes the *message* honest but the *code*
  stays coarse; mapping `EACCES`/`ENOSPC`/`EROFS` to distinct TFTP codes is a separate polish.
- **`bytesSent` over-count is NOW folded into slice 1.0** (skip the increment on a cache-hit resend) —
  formerly deferred; the Option A cache rewrite makes it nearly free and it removes a known-wrong,
  user-visible `bytesTransferred`/`TransferSnapshot.bytes` value. Kept explicitly separable in the diff.
- **Concurrent same-file RRQs** each writing the identical `.md5` — benign last-writer-wins (same content ⇒
  same digest); no locking. *Note:* "concurrent" here means **async interleaving at `await` points in the
  single-threaded loop**, not OS threads — the last-writer-wins reasoning holds only under that model; a
  future threaded frontend must not inherit it by accident (one Invariant-6 sentence guards the sidecar name
  regardless).

## Open questions

**Q1 (RESOLVED → Option A).** The correct checksum fix must hash ACK-confirmed delivered bytes, which is
transfer-layer knowledge, so it breaks the draft's "server.nim only" scope. **Decision: Option A** — additive
default-nil `onDelivered` hook + in-flight `windowCache` in `transfer.nim`, fired via an ascending
range-loop per accepted (possibly cumulative) ACK. Correct sidecar *always*; **also fixes** the latent
"retransmit re-reads a mutated file" transfer bug and the `bytesSent` over-count; accepts a change to the
recently-landed #18 fast-retransmit code, covered by slices 1.0/2. Option B (server-local mutation-detect,
correct-or-absent) is recorded as the rejected alternative in D1.

**Q2 (resolved):** generic-message granularity — one string per TFTP error code, exhaustive `case`.

**Q3 (RESOLVED → keep):** optional slice 6 (redacted operator logging) stays, in-but-last and cuttable.

**Round 2 — no new forks.** The round-2 team surfaced two CRITICAL correctness holes (windowsize>1
cumulative-ACK undercount; zero-length `update` Defect), one new HIGH defect (defect 5 — WRQ sidecar
forgery), and several structural fixes (validateWritePath authority, never-raise `writeSidecar`,
`sendOsErrorAndFail`, `onDelivered`/`commit` ergonomics, slice 1 split). All were clear-best and are applied
above. **The RFC is ready for `/tdd` (stage 3).**
