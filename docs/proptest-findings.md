# What proptest is missing — findings from chapulin verification-harness v1 + v2

Everything below was discovered empirically while building chapulin's symex + fuzz + soak
harnesses against proptest pinned at `99fa2dbe`. proptest is our own sibling repo
(`_deps/proptest/`), so these are ticket candidates, not third-party gripes. Citations
`file:line` are into `_deps/proptest/src/proptest/…` unless noted; each finding also names the
chapulin test that documents it.

## Current state — nelli 0.4.1 (2026-08-16, AUTHORITATIVE)

> nelli 0.4.1 (walker v85) released 2026-08-16: variant-object (`case` object)
> construction is DONE — see the "Variant-object construction" row below, now
> updated from MED/in-progress to FIXED. Two production bugs found and fixed
> during A6 (RFC-chapulin-hardening) closed this out: Bug #1 (an exported-field
> `.strVal` crash on any variant type whose fields carry Nim's export marker —
> every `TftpPacket` field is exported, a shape no prior synthetic test
> exercised) and Bug #2 (eager, whole-type field classification poisoned
> `symexFind` for ANY proc merely allocating a variant type with an unsupported
> field on ANY arm, not just paths that touch it). The package was also renamed
> `proptest` → `nelli` upstream (2026-08-15); this doc's historical rows below
> predate the rename and refer to it by its old name where the citation is
> from that era. Two NEW, narrower findings surfaced verifying `TftpPacket`
> specifically (both worked around in `t_symex_decode.nim`'s test-only twins,
> neither blocks anything): an object constructor OMITTING a seq-typed field
> (relying on Nim's own implicit zero-init) degrades the whole proc to
> `sxUnknown`, independent of Bug #2 and of the field's own type-support
> status (explicit `@[]` avoids it); and reading two `seq[byte]` elements
> through a helper-proc call (rather than indexing the array directly in the
> target proc's own body) reports an all-zero witness for an otherwise
> genuinely `sxSat` proof (inlining the read avoids it). See the "BLOCKER #11"
> and "BLOCKER #12" rows below.

Tracked across four releases (0.1.0 → 0.2.0 → 0.3.0 → 0.3.1), each re-probed empirically via
`dev-test.ps1` and cross-checked against the maintainer's ledger `_deps/proptest/docs/RFC-chapulin-hardening.md`.
Of the original ~27 findings, **the large majority are fixed.** The consumer-side workaround-removal
pass (INT-1) has landed: chapulin's twins now use real `and 0xFF`/`shl|or`, real `data[4 .. ^1]`
slices, real `strutils.strip`, real `..<`, real `parseBiggestInt`/`min`/`max`/`toLowerAscii`/`rfind`/
`.add`, and the soak/coverage tooling uses real `database`+`persistKey`, `stopOnFirstCrash`, and
`uncoveredSources()`.

### ✅ FIXED across 0.1.0–0.3.1 (do NOT refile)
`seq[byte]` witnesses (M1) · bitwise-into-guard crash / D1c (v64) · tail-return `KeyError` (CR-1b) ·
var-out-param-in-loop crash → now classified (CR/§0) · depth-3 nested-if crash (v0.2.0) · chained-scan
crash → now classified `sxUnknown` · tuple-return `nnkTupleConstr` (P1) · `toLowerAscii`/`toUpperAscii`
(A9) · `rfind` (M3) · `.add` string-arg (M4) · `..<`/`pred`/`succ` (v64) · `..^` seq-slice `data[a..^1]`
(P4/v67) · standalone `strutils.strip` in both chained & bound-across-statements positions (v66) ·
`symexAssume` filter semantics (SND-2) · `min`/`max` inlining (M5) · `parseBiggestInt` → **B4 done** (M2) ·
`shrink`/`Int128` `seq[byte]` compile bug · `minimalCovering*` export (F3) · `stopOnFirstCrash` (F4) ·
per-entry `save(meta)` (F6) · **`dbReusePhase` corpus-eating → fixed via `persistKey` never-pruned
corpus section (F1)** · **coverage slot→`file:line:col` via `uncoveredSources()` (C1)**.

### ❌ STILL OPEN at 0.4.1 — the current list for the devs

| Item | Severity | Status / evidence |
|---|---|---|
| **`discard <call>` is a no-op — callee never walked** | ~~CRITICAL~~ **FIXED in 0.3.2 (walker v68)** | Was: the `nnkDiscardStmt` arm lowered a discarded call to `mkBlock(@[])` for everything outside a small allowlist. v68 lowers EVERY discarded expression to a synthetic sink `let`, so raise/defect forks are searched exactly as a bound use (`tsymex_r5_discard` pins: defect-in-discarded-call FOUND, guarded UNSAT honesty, non-call `discard data[i]` IndexDefect FOUND). Chapulin action at the 0.3.2 pin bump: drop the bind+use workarounds, and expect previously-vacuous `sxUnsat` in discard-masked shapes to re-probe honestly as `sxRaised`/`sxUnknown`. |
| **String-scan `while` loop can't be defect-searched** | HIGH — **design recorded (ADR-0028), implementation round 6** | Confirmed the Q2/`maxLoopUnwind` class; with v69's tuple wiring the shape now degrades at its true boundary (`beBudgetExhausted`, pinned upstream in `tsymex_retest_c6_tuple_chain`). Upstream design ADR-0028 (SYMEX_PLAN.md): recognize the accumulating scan at parse time and emit closed forms (indexOf + v67 slice view + seqMap) — the ADR-0025/0026 lineage — with the ADR-0027 Int-representation pre-pass as prerequisite. Also directly covers the #6 chained-scan case. |
| **Bare `&`-concat of an unconstrained string can't be defect-searched** | ~~HIGH~~ **ROOT-CAUSED + FIXED (walker v69, unreleased)** | Never about concat: the degrade fired whenever a MODULE-LEVEL CONST (`SidecarExt`) appeared in the expression — const syms emitted `iekVar` with no env binding → KeyError → walker fault → `sxUnknown`. The shape-sensitivity was whether the const happened to fold. v69 folds `nskConst` syms to their values at parse time; the writeSidecar length lemma now proves (`tsymex_r5_const_fold` upstream). Chapulin action at the pin bump: re-probe `t_symex_checksum` — its honest `sxUnknown` was this. **RE-PROBED (B7, 2026-08-16, against nelli LOCAL main HEAD `d54f85a`, walker v86):** `t_symex_checksum`'s sidecar-path canaries were already tightened `sxUnknown` → `sxUnsat` in `29f963d` (A6 pass); re-run against v86 confirms both `tIndexError()`/`tFieldDefect()` searches on `sidecarPathTwin` still prove `sxUnsat` cleanly (compile, both defect searches, and both differential-oracle suites all green — 8/8 checks). The const-fold item is CLOSED, no further action; no regression between v85 (0.4.1) and v86. |
| **`maxLoopUnwind=5` default** | ~~MED~~ **CLOSED — decided, stays 5** | Dependent/nested bounded loops exhaust the budget → classified `beBudgetExhausted`/`sxUnknown` (no longer a crash). The "document it" half landed in v67 (decidability-boundary doctrine on the field itself); maintainer decision (round-5 ledger): the default stays 5 — raising it trades every caller's solve budget against exactly the Q2/#6 dependent-loop class whose real fix is the round-5 design work (closed-form lifts), and the per-call override is the sanctioned lever. |
| **Explicit two-endpoint seq slice `data[a .. b]`** | ~~MED~~ **FIXED in v67 (0.3.1), upstream-confirmed** | The v0.3.0 probe predates walker v67, which shipped `iekSeqSlice` handling **both** the two-endpoint `..`/`..<` forms and the `^k` backward form, in bracket and call position. Now pinned upstream in `tsymex_r4_seq_slice`: `data[4 .. data.len-1]` SAT-with-witness + view-length UNSAT, and `data[4 ..< data.len]` view-element UNSAT — all green at 0.3.1. Chapulin action: drop the P3 point-substitute workaround at the next pin bump (a chapulin-side probe of the natural shape should now prove). |
| **Variant-object (`case` object) construction** | ~~MED~~ **FIXED (walker v77 construction + walker v85 poisoning fix, released 0.4.1)** | Upstream design ADR-0029 landed across round 6: `iekVariantLit` (literal-discriminant construction, walker v75) + a `retBindEq` svVariant arm (walker v76) + `isVariantConstructSym` fork-per-tag for symbolic discriminants (walker v77) make constructing a real variant object provable, not just a macro error. Two production bugs surfaced verifying chapulin's own `TftpPacket` specifically and are now BOTH fixed — see the "Bug #1" and "Bug #2" rows below. Exit criterion met: `tests/t_symex_decode.nim`'s twins construct the real `TftpPacket` (all five arms) and are no longer `void`; the opData/opAck arms additionally prove `sxUnsat` end-to-end with a witness cross-checked against real `decode()` (RFC-chapulin-hardening A6). |
| **Bug #1: exported-field `.strVal` crash on variant construction** | ~~CRIT~~ **FIXED (nelli `ca51c3e`, no walker bump — crash-fix class)** | `classifyObjectRecordFields`'s VARIANT path read field names via a bare `.strVal` on raw `getImpl` nodes. An EXPORTED field (`name*: T`, Nim's `nnkPostfix("*", name)` shape) doesn't parse that way — every `TftpPacket` field is export-marked, a shape no prior synthetic round-6 test exercised (they all used local unexported types), so any attempt to construct/allocate `TftpPacket` crashed the macro expansion outright, before any symex work even started. The identical class of bug had already been fixed for the plain-record path; this landed the same fix (a shared `fieldNameStr`/`unwrapFieldNameNode` helper) at the 3 analogous variant-path sites. Directly blocked chapulin from exercising variant construction on its OWN real types at all until fixed. |
| **Bug #2: eager whole-type field classification poisons any allocating proc** | ~~CRIT~~ **FIXED (nelli `60540a6`, walker v85, per-field scoped decline with read-taint, released 0.4.1)** | `classifyObjectRecordFields` classified (and, via `allocateSym`, allocated) every declared arm's fields UNCONDITIONALLY — so `TftpPacket`'s `options: seq[(string,string)]` field, present only on the untouched `opRrq`/`opWrq` arms, poisoned `symexFind` for EVERY proc merely constructing/returning/receiving a `TftpPacket`, including `decodeFixedArmsTwin`'s opData/opAck arms which never read `options` at all — degrading a would-be `sxUnsat` proof to `sxUnknown`. Fix: an unsupported field type classifies to a KIND-MARKED PLACEHOLDER (`isUnsupportedFieldPlaceholder`) instead of raising; `allocateSym` allocates it as a fresh opaque value (never raises); only an ACTUAL READ of the placeholder field (`dsl_parser.nim`'s `nnkDotExpr` arm) deposits a classified taint on that read's own statement — so a proc that merely allocates/constructs/returns the type, without reading the unsupported field, now proves its REAL verdict. This was the blocker that made chapulin's A6 exit-gate ("un-void `t_symex_decode`, oracle-check opData/opAck against a released tag") unsatisfiable against 0.4.0 as released; 0.4.1 was cut specifically to carry this fix. |
| **BLOCKER #11: omitted seq-typed constructor field degrades to `sxUnknown`** | MED — new finding, walker v85 (0.4.1), NOT a Bug #2 recurrence | Independent of Bug #2 (reproduced on a two-arm type with no unsupported-field arm anywhere, i.e. no placeholder involved at all): an object/variant constructor call that OMITS a `seq[byte]`-typed field (relying on Nim's own implicit zero-init for the unset field, e.g. `TftpPacket(opcode: opData, blockNum: n)` leaving `data` unset) degrades the WHOLE proc to `sxUnknown` — reproduced down to a plain non-variant object with a single omitted `seq[byte]` field. Giving the field EXPLICITLY (`data: @[]`) avoids it; an explicit `newSeq[byte]()` call in the same position instead hits a SEPARATE compile-time "node has no type" crash in `parseVariantCtorField` (a call-expression field value the parser can't classify in that position) — so the untyped `@[]` literal spelling is the only one that avoids both. Worked around in `t_symex_decode.nim`'s twins (chapulin repo); not filed upstream. |
| **BLOCKER #12: `seq[byte]` witness extraction loses fidelity through a helper-proc read** | ~~MED~~ **FIXED (walker v86, A6-rider-2)** | Was: the proof/search itself was unaffected (a genuinely `sxSat` target was still found), but the reported `witness[...]` for a `seq[byte]` parameter came back all-zero, not the real solved model, whenever the two bytes composing a value were read via a SEPARATE helper proc call rather than indexed directly in the target proc's own body. Root cause (A6-rider-2): `isCall`'s implicit-fallthrough exit never bound `retSym` to the callee's `result`; fixed by mirroring the closure-call path's `retBindEq` idiom into the ordinary call-inlining arm. Confirmed fixed in `t_symex_decode.nim`'s unified `decodeTwin` (B7): `readU16Twin` is now called as a shared helper by every arm, witness-correct. |
| **nim-z3: `z3FullVersion()` shape change** | LOW | Now returns bare `4.13.4.0` (dropped the `"Z3 "` prefix) — undocumented; broke one chapulin assertion. CHANGELOG note. |
| **softlink v0.11.1: ABI compat-manifest warning** | LOW | Ships a `linux-lp64`-harvested `z3.compat.json`; on a `windows-llp64` build it warns and ignores it. Degrades safely — confirm intended. |
| **BLOCKER B7-1: B6's `readOptions` pair-loop closed form does not compose with conditional dispatch or downstream construction** | ~~HIGH~~ **FIXED (nelli commit `e6d3f0c`, walker v88)** | Was: B6's closed form fired only for the exact shape of its own pinned SUT (unconditional, un-dispatched, un-constructed `void` proc); wrapping in `if`/`elif`, following with a variant construction, or calling via a helper proc each independently degraded it. Root cause: the loop counter was seeded from a LITERAL (`var pos = offset` where `offset` was itself a literal at the call site), and int-offset promotion (`collectIntOffsetParams`) only traced counters back to FORMAL params, not literal-seeded locals — the counter stayed BV-represented and failed the closed form's CR-17 Int-sortedness gate regardless of surrounding structure. Fix: a new parse-time collector, `collectIntOffsetLiteralLocals`, promotes literal-seeded locals to `svInt` too. Confirmed in `t_symex_decode.nim`: `decodeOackTwin` merged back into the unified `decodeTwin` (dispatch + call-boundary `readOptionsTwin` + `TftpPacket` construction, all six wire opcodes / five arms in ONE proc); `opOack` now proves via the option-region membership proof end-to-end, witness cross-checked against real `decode()`. |
| **BLOCKER B7-2: a case-match over a scanned string's content, with an `else: raise` arm, poisons a sibling dispatch branch** | HIGH — new finding, walker v87, STILL OPEN (escalated to its own future round, walker v88 confirmed unchanged) | `parseMode`'s own shape (`case s.toLowerAscii of "octet": ...; of "netascii": ...; else: raise ...`) degrades a WHOLLY UNRELATED sibling branch's target to `sxUnknown` when embedded in a multi-branch dispatch — reproduced both as a separate proc call and fully inlined, and does NOT involve `seq[byte]`/any scan recognizer at all (a pure `string` case-match), so it is independent of BLOCKER A's byte-receiver widening fix and of BLOCKER B7-1's fix (confirmed still present, unmodified, at walker v88). Per the maintainer: the natural fix (a branch-boundary exception catch) proved UNSOUND on the C backend (the exception gets elided) and needs its own dedicated round, not a quick follow-up. DIRECT string equality comparisons (`modeStr == "octet"`, no case-match, no proc call) do NOT trigger it — this is the spelling `t_symex_decode.nim`'s `decodeTwin` uses (a natural choice, not a workaround-of-convenience — kept regardless of B7-2's eventual fix): `mode` stays a construction-time placeholder, with the oracle-comparable target driven by a direct equality on the scanned `modeStr` instead of `parseModeTwin`. Not filed upstream as a fix; recorded here as a precise, minimal-repro'd blocker, still blocking the B7 stretch goal (below). |

## B7 stretch goal — real `protocol.decode` passed directly to `symexFind` (2026-08-16, NOT gated, attempted twice since the gated B7 work went green)

Attempted `symexFind(decode, tIndexError())` / `symexFind(decode, tFieldDefect())` directly
against the shipped `decode(data: seq[byte]): TftpPacket` (no twin at all), first at nelli local
main `e04f13b` (walker v87) and again at `9a652b8` (walker v88, BLOCKER B7-1 fixed). **Result both
times: compiles cleanly** (no macro `error()`, confirming variant construction + `seq[byte]`
params both parse fine end-to-end on the real function) **but both searches degrade to
`sxUnknown`, unchanged by the v88 fix** — expected: BLOCKER B7-1's fix closes the `readOptions`
composability gap, but `decode` ALSO calls `parseMode` (BLOCKER B7-2's own shape, embedded in the
`opRrq`/`opWrq` arm, confirmed still open at v88) — one live blocker is sufficient to keep the
whole-function verdict `sxUnknown`. Consistent with, not additional evidence beyond, BLOCKER B7-2
as isolated via the twins — no new finding. Re-attempt once B7-2 is fixed upstream (its own
dedicated round, per the maintainer); until then the twin (`decodeTwin`, now genuinely unified —
all five arms, one proc) remains the vehicle, per the RFC's own recorded design.

Severity/verdict detail for the historical rounds is preserved below.

## Historical — 2026-08 re-evaluation against proptest 0.1.0 (superseded by the 0.3.1 section above)

proptest was upgraded `99fa2dbe` (v1 pin) → `0.1.0`/main (nim-z3 → main, softlink → v0.11.1).
Every symex twin in `tests/t_symex*.nim` was re-tried in its NATURAL/shipped-proc-closest form;
each verdict below is empirical (built + run via `dev-test.ps1`, not read-only), except where
marked "static read only" for the fuzz/corpus/shrinker items that weren't re-run this round.
**Rule enforced throughout: a workaround was only removed when the natural form proved `sxUnsat`
(or witnessed correctly) — never traded for a weaker `sxUnknown`, and no crash was ever
"fixed" by silently keeping the crashing form.**

| # | Finding | Verdict | Evidence |
|---|---|---|---|
| #1 | `seq[byte]`/fixed-width-int seq witness reader | **PARTIALLY FIXED** | `itSeq` now has reader cases for every fixed-width int element type (`symex.nim` ~715-746, RFC-chapulin-hardening M1) — `seq[byte]` genuinely has a witness now. But combining a `seq[byte]`-witnessed value with a bitwise op *and* feeding the result into a later boolean guard still crashes (see #3) — `t_symex_decode.nim` twins stay on `seq[int]`-masked. |
| #2 | `nnkTupleConstr` (tuple-constructor expressions) unsupported | **CONFIRMED FIXED** | `dsl_parser.nim` now has a general `of nnkTupleConstr:` expression arm (P1). `t_symex_decode.nim`'s `readCStringTwin` now returns the REAL `(string, int)` tuple (var-out-param workaround removed); proves `sxUnsat` at both call sites. |
| #3 | Bitwise ops (`and`/`or`/`shl`) on a symbolic value crash the walker | **STILL PRESENT (refined/narrower)** | Retested with a genuinely fixed-width `seq[byte]`-witnessed `uint16` (not a plain int): the bitwise combine alone compiles/runs fine, a boolean guard alone compiles/runs fine, but the COMBINATION — a bitwise-combined value fed into a later boolean guard (`decode`'s own exact shape) — crashes with the same `inner.kind == svBool` assertion, now at `runtime.nim:3155` (a different call site than the original `:2886`). `t_symex_decode.nim` keeps the arithmetic-combine (`mod`/`+`/`*`) workaround. |
| #4 | Implicit tail-expression return referencing a local → `KeyError` | **NOT RETESTED** | Not independently re-probed this round (the twins already use explicit `result =`, per the original fix, and that shape is unaffected by anything else touched). No evidence either way under 0.1.0. |
| #5 | `var`-out-param helper called inside a loop → native crash | **NOT RETESTED (moot for current shapes)** | `t_symex_decode.nim` no longer uses var-out-param at all (superseded by #2's fix), so this specific interaction has no live call site to retest. The RELATED-BUT-DISTINCT shape — a loop-produced value bound to a name and read in a later statement/call — was retested and found STILL PRESENT, see #9 below and the new Blocker #6 finding. |
| #6 | Chained/dependent bounded scans (2nd scan's offset = 1st's symbolic result) → `sxUnknown` | **STILL PRESENT, and WORSE (now a CRASH)** | Retested the exact original repro (now using the post-#2-fix tuple-returning `readCStringTwin`): `let (_, p1) = readCStringTwin(data, 2); discard readCStringTwin(data, p1)` — this is no longer a graceful `sxUnknown`, it is a hard native crash (bare non-zero exit). `t_symex_decode.nim`'s option-arm proof stays scoped to "header + first scan." |
| #7 | `toLowerAscii`/`toUpperAscii` parsed but never executed | **CONFIRMED FIXED** | `runtime_strings.nim` now lowers `iekStrToLower`/`iekStrToUpper` via a real Z3 seqMap over the string's `Z3Seq[Z3Char]` (Phase 16 A9). `t_symex_uri.nim`'s twin restores the REAL `.toLowerAscii` calls (scheme gate + mode-param handling); proves `sxUnsat`/witnesses correctly. Workaround removed; the differential oracle's case-scoping was also removed (widened). |
| #8 | `rfind` unmodeled (only forward `find` is) | **CONFIRMED FIXED** | `s.rfind(sub)` is now modeled via nim-z3's native `lastIndexOf` Z3 Sequence-theory primitive (RFC M3, `iekStrRfind`/`smkStrRfind`) — a real solver primitive, not a loop reshape. `t_symex_uri.nim`'s twin restores the REAL `.rfind(":")` call; proves `sxUnsat`. Workaround removed; the differential oracle's multi-colon-host exclusion was also removed (widened, now includes `:` in the host/port alphabets). |
| #9 | ANY loop in a target with a `string` param in scope → `sxUnknown` | **PARTIALLY FIXED (narrower, precisely characterized)** | 0.1.0 now proves a loop-producing call (e.g. real `strutils.strip`) `sxUnsat` when its result is consumed in ONE direct method-chain expression, never bound to a name (`t_symex_security.nim`'s `isReservedSidecarNameSymexTwin`: `stripTrailingDotSpaceTwin(path).endsWith(".md5")` proves `sxUnsat`). But binding that SAME loop-produced value to a `let`/`var` and reading it in a LATER statement is still `sxUnknown` — bisected exhaustively (12 probes) in `t_symex_security.nim`: every downstream op (replace/contains/len/a further call) and both strip directions fail identically once let-bound-across-statements; the identical value consumed same-statement always succeeds. Control: a NON-loop-derived string (e.g. `.replace`'s result) bound to a var and read across statements is completely fine — the gap is specifically "outlives its producing loop's statement," not "any named string." `validatePathLexicalTwin` (which needs its stripped result across several guard statements) keeps a bounded, loop-free, hand-unrolled `stripLeadingSepTwin`; `t_symex_uri.nim` never needed a loop-based `rfind` reshape in the first place, now that #8 is a native primitive. |
| #10 | In-place string mutation (`.add`/`&=`) unsupported | **CONFIRMED FIXED (for string args; char args still unmodeled)** | `dsl_parser.nim` now models `s.add(x)` for a STRING-typed `x` as the in-place concat-assign `s := s & x`, reusing `iekStrConcat` (Phase 16 M4). `t_symex_security.nim`'s `isWithinTwin` restores the REAL `p.add(SepStub)` in-place call; proves `sxUnsat`. `s.add(charValue)` (a CHAR arg, e.g. `readCString`'s `s.add char(b)`) is still routed to `iekStrUnsupported` (an honest, non-crashing `sxUnknown` if reached on a path the check depends on) — not retested as a blocking issue since existing twins using this exact shape (`readCStringTwin`) still prove `sxUnsat` for the checks they make (index/field-defect safety doesn't depend on the string's exact content). |
| #11 | Depth-3 nested-if + subsequent string op → native crash | **NOT RE-ISOLATED (superseded)** | Not independently re-bisected at depth 3 this round — `t_symex_security.nim`'s strip twins stay at the same bounded shape they already had, now justified by the *new*, more specific #9 finding (loop-avoidance for cross-statement survival) rather than the original depth-3 crash threshold. No evidence either way on whether the original depth-3 crash itself is fixed. |
| `symexAssume` == `symexAssert` (doc/impl mismatch) | **CONFIRMED FIXED** (static read only) | `dsl_parser.nim` now parses `symexAssume(cond)` to a DISTINCT `mkAssume` IR node (Phase 16 SND-2, not `mkAssert`) — the code's own comment confirms: "Previously byte-identical to `symexAssert` ... which masked `sxUnsat` with a false `sxRaised`... Distinct IR kind: `mkAssume`." Not re-exercised against a live target this round (no current twin needs assume-based bounding), but the parser-level fix is unambiguous from source. |
| `system.min`/`system.max` if-expression-bodied inlining | **CONFIRMED FIXED** | Retested empirically in `t_symex.nim`: `min(MaxBlocksize, reqBs)` now proves `sxUnsat` directly. `twinServerBlksize`/`twinServerWindowsize` now call the REAL `min`/`max` (explicit-if clamp workaround removed). |
| `parseBiggestInt` unmodeled (B4 gate) | **CONFIRMED FIXED — B4 DONE** | `dsl_parser.nim` now routes `parseBiggestInt(s)` to the SAME `iekStrToInt` IR node as `parseInt(s)` (RFC-chapulin-hardening M2, both 64-bit on this platform). `t_symex.nim`'s tsize twins now call the REAL `parseBiggestInt`; both `sxUnsat` (client, caught) and `sxRaised` (server, uncaught, witness cross-checked against real `parseBiggestInt`) still verify. |
| `nnkTupleConstr`/`nnkObjConstr` construction (general, not just tuple-return) | **CONFIRMED FIXED for plain objects; variant objects STILL UNSUPPORTED** | `dsl_parser.nim`'s `of nnkObjConstr:` arm (P2a/P2b) now builds plain (non-variant) object/tuple-literal expressions, confirmed by reading source and by successfully retrying `symexFind` on the real, plain-object-returning `parseTftpUri` (it got past object construction — see the `pred`/`..<` finding below for why it still doesn't fully compile). A VARIANT (`case`) object constructor is EXPLICITLY still out of scope ("P2b: variant object constructor ... is out of scope" — `dsl_parser.nim` ~2165) — confirmed relevant to `protocol.TftpPacket` (a case object), so `t_symex_decode.nim`'s twins stay void (never construct the real variant packet). |
| `pred`/`succ` (the `..<` lowering) | **STILL UNSUPPORTED** | `symexFind` on the real shipped `parseTftpUri` (now that #7/#8/plain-object-construction are all fixed) still fails to COMPILE: "Error: symex: unsupported infix operator `..`" (`dsl_parser.nim:783`), from `rest[1 ..< closeBracket]`-style slices. Grepped `dsl_parser.nim` for `pred`/`succ`: zero hits. `t_symex_uri.nim` keeps its `..< -> ..(b-1)` mechanical rewrite for this reason alone. |
| seq slicing (`data[a..b]`) | **NOT RETESTED** | Not independently re-probed this round; `t_symex_decode.nim`'s DATA arm keeps its point-substitute (touch both slice endpoints under the length guard) unchanged. |
| `minimalCovering*` export | **CONFIRMED FIXED** (static read + existing test corroboration) | `fuzz.nim:368`: `proc minimalCovering*(...)` — now exported. `tests/t_corpus_minimize.nim`'s "C4: minimalCovering minimization pass, via the real (only-reachable) front door" suite is green in the default run, corroborating. |
| `FuzzSettings.stopOnFirstCrash` | **CONFIRMED FIXED** (static read only) | `fuzz.nim`: `stopOnFirstCrash*: bool` field exists and is consumed (`if settings.stopOnFirstCrash and isNewCrash: break`). Not independently exercised by a new chapulin test this round. |
| `dbReusePhase` primary-pruning (shared testId unsafe for corpus growth) | **STILL PRESENT** (static read only) | `engine/phases.nim`'s `dbReusePhase` is structurally unchanged: still batches and `removeMany`s every entry that doesn't currently falsify. chapulin's existing workaround (persist soak growth under a distinct `.soak-corpus`/`.soak-crash` suffix, confirmed still in use by `tests/corpus/*.soak-corpus.bin` and the green C4 replay-and-reassert suite) is still necessary. |
| `shrink` 2-arg overload / `Int128.<` cross-module bug for `seq[byte]` | **NOT RETESTED** | Not re-run against a live cross-module `T=seq[byte]` instantiation this round (would need a dedicated test, out of this round's symex-focused budget). The overload shape in `shrinker.nim` is structurally similar to before; no evidence either way. |
| Coverage slot→`file:line:col` reverse map | **NOT RETESTED** | Out of scope for this round (a tooling/coverage-report question, not symex); `coveragereport.nim`/`t_coverage_report.nim` still pass in the default suite, consistent with the coarse-count-only design being unchanged. |

**Net effect on the symex test suite:** `t_symex_decode.nim` (Blocker #2 workaround removed — real
tuple return), `t_symex_security.nim` (Blocker #9's refined boundary found and both leading/trailing
strip twins re-tuned — one upgraded to real `strutils.strip`, one kept bounded for cross-statement
survival; `isWithinTwin` upgraded to real `.add`), `t_symex_uri.nim` (Blockers #7 and #8 workarounds
both removed — real `.toLowerAscii`/`.rfind`; differential oracle widened), `t_symex.nim` (B4 done —
real `parseBiggestInt`; `system.min`/`max` workaround removed). `t_symex_netascii.nim` and
`t_symex_checksum.nim` needed no changes (already the simplest possible shape for their scope). All
seven `t_symex*` suites plus the full default suite are green (`dev-test.ps1`, no `-Only` filter).

**Severity legend:** `CRASH` = brings the walker/run down with no classified result (worst —
these should be impossible by construction). `BLOCKER` = made a target unprovable/unrunnable in
its natural shape; a workaround existed. `SCOPE` = forced an honest narrowing of what we proved.
`NICE` = ergonomic rough edge, cost debugging time or readability, no correctness impact.

---

## 0. The one cross-cutting theme: the walker crashes when it should fail soft

The symex walker has two classes of gap. One class fails *gracefully* — returns `sxUnknown`
with empty errors (Blockers #6, #9). That's fine; it's an honest "solver couldn't decide."

The other class **crashes the process** — an uncaught `doAssert`, a `KeyError`, or a bare
non-zero exit with no message at all (Blockers #3, #4, #5, #11). These are the dangerous ones:
they're indistinguishable from a real defect-detection until you bisect, they can't be caught by
the harness, and they turn "prove this pure function never raises" into "debug the prover."

**Highest-value single ticket: make the walker's failure mode total — any unsupported construct
must degrade to a classified `sxUnknown`/`SymexUnsupported…Error`, never a native crash or an
uncaught assertion.** That one invariant would downgrade #3/#4/#5/#11 from CRASH to SCOPE
overnight, even before the underlying features are built.

---

## 1. Symex — walker/runtime crashes (fix the crash first, the feature second)

### #3 — bitwise ops (`and`/`or`/`shl`) on a plain-`int` symbolic value crash the walker  ·  CRASH
- **Symptom:** `AssertionDefect` at `runtime.nim:2886` (`doAssert inner.kind == svBool`), via `runtime.nim:2955-2957`.
- **Cause:** the abstraction layer only promotes a *fixed-width* Nim type (int8/uint8/…) to a Z3 bitvector; a plain `int` has no width to promote from, so it stays an unbounded Z3 Int, and `bAnd`/`bOr`/`bShl` on an Int operand hits an **uncaught** `doAssert` (runtime.nim's own comment: "abstraction layer should have declined promotion under bit-twiddling"). And plain `int` is the *only* witness-readable seq element type (see #1), so byte-parsing code hits this constantly.
- **Workaround:** never emit a bitwise op on a plain-int symbolic; use arithmetic equivalents — `((x mod 256)+256) mod 256` for `and 0xFF`, `hi*256+lo` for `(hi shl 8) or lo`.
- **Fix:** promote Int→bitvector on demand when a bitwise op is applied, OR classify as `sxUnknown` instead of asserting. *(t_symex_decode.nim:64-95)*

### #4 — implicit tail-expression return referencing a local → `KeyError`  ·  CRASH
- **Symptom:** `KeyError: key not found: <name>` at `runtime.nim:2629` (`env[e.vname]`) — for a body as trivial as `let hi = data[o] mod 256; hi + 1`, no bitwise ops, no nested calls.
- **Cause:** env lookup for the bare-tail-expression return form doesn't see a preceding `let`/`var`. An explicit `return <expr>` or `result = <expr>` sees the same env fine.
- **Workaround:** always use explicit `result =` / `return`, never rely on implicit tail return.
- **Fix:** thread the environment into the implicit-tail-return path. *(t_symex_decode.nim:105-117)*

### #5 — a `var`-out-param helper called *inside a loop* → native crash  ·  CRASH
- **Symptom:** no Nim exception, no assertion — bare non-zero exit ("execution of an external program failed"). Minimal repro: a 2-iteration `for` calling a var-out-param helper once per iteration. The identical calls straight-line (outside a loop) work.
- **Cause:** unclassified — a genuine crash in the compiled walker's path for var-out-param calls in loop bodies.
- **Workaround:** hand-unroll such loops into nested `if`s.
- **Fix:** at minimum classify instead of crashing; ideally support the construct. *(t_symex_decode.nim:199-208)*

### #11 — depth-3 nested-if in a string helper + a further string op on its result → native crash  ·  CRASH
- **Symptom:** bare non-zero process exit (same signature class as #5). A helper with `if p1: … if p2: … if p3: …` returning a `string` that the caller then feeds to `.replace`/`.contains` crashes. Depth-1 and depth-2 versions prove `sxUnsat` cleanly; only depth-3 crashes. Bisected across 21 minimal variants.
- **Cause:** unpinned — an empirical branching-depth×string-op threshold.
- **Workaround:** bound string-processing twins to nested-if depth ≤2 (a real scope-down — we strip fewer path components than the production code).
- **Fix:** find the crash; at minimum degrade to a classified error. *(t_symex_security.nim:102-127)*

---

## 2. Symex — stdlib model gaps (parser knows the call; runtime doesn't execute it)

### #1 — `seq[byte]`/`seq[uint8]` has no witness reader  ·  BLOCKER
- **Symptom:** `symexFind` on any proc taking `seq[byte]` fails at macro expansion.
- **Cause:** `symex.nim`'s `emitTyAndReader` `itSeq` case (~660-698) only handles `seq[int]`, `seq[float32/64]`, `seq[ref T]`. v1 hit the same class for `seq[(string,string)]`.
- **Workaround:** take `seq[int]` and mask each element to `[0,255]` at read time via one `atByte` chokepoint. (This is *the* reason byte-parsers then hit #3.)
- **Fix:** add `itSeq` reader cases for the fixed-width integer element types (byte/uint8…uint64, int8…int32). Would eliminate the mask workaround *and* the #3 collision. *(t_symex_decode.nim:8-12)*

### #7 — `toLowerAscii`/`toUpperAscii` parsed but never executed  ·  BLOCKER
- **Symptom:** `sxUnknown` via `SymexUnsupportedStringOpError`.
- **Cause:** half-built feature. `dsl_parser.nim` (~1692) *does* route `toLower(Ascii)`/`toUpper(Ascii)` to `iekStrToLower`/`iekStrToUpper` IR nodes — but `runtime.nim`'s `probeProto` allowlist enumerates every *modeled* string op and dumps these two into the catch-all "not modeled" arm.
- **Workaround:** case-sensitive checks in the twin (sound because case-folding never changes length, and every slice is length-guarded).
- **Fix:** implement the two IR nodes in `runtime.nim` — the parser plumbing already exists. *(t_symex_uri.nim:22-52; reused in t_symex_security.nim)*

### #8 — `rfind` unmodeled; only forward `find` is  ·  BLOCKER
- **Symptom:** falls through to `getImpl` inlining of `strutils.rfind` → the #2-class inlining wall.
- **Cause:** stdlib model has `find` but zero `rfind` cases (grepped both `stdlib_models.nim` and `dsl_parser.nim`).
- **Workaround:** substitute forward `find` — sound for *index-safety* (same `[-1,len)` domain) but NOT for exact equivalence when the separator appears 2+ times (`find` first vs `rfind` last); differential oracle scoped to exclude multi-colon hosts.
- **Fix:** add an `rfind` model mirroring `find`. *(t_symex_uri.nim:54-63,102-119)*

### #10 — in-place string mutation (`.add` / `&=`) unsupported  ·  BLOCKER
- **Symptom:** classified `seUnsupportedStringOp` via `iekStrUnsupported("string mutation")`.
- **Cause:** DSL parser models `&`-concat (`iekStrConcat`) but explicitly declines in-place append.
- **Workaround:** `p.add(x)` → `p = p & x`.
- **Fix:** model `.add` the same way `&` is (semantically identical). *(t_symex_security.nim:38-48,150-170)*

### `parseBiggestInt` entirely unmodeled — **this is what gates B4**  ·  BLOCKER
- **Symptom:** any target over a `parseBiggestInt`-based twin → `sxUnknown`.
- **Cause:** the engine models `parseInt` only (zero hits for `parseBiggestInt` under `_deps/proptest/src`). chapulin's real tsize arms (`options.nim`) use `parseBiggestInt`.
- **Workaround:** substitute `parseInt` — sound here (both raise `ValueError` identically, both 64-bit on this platform) but load-bearing, not cosmetic. This is why v2 slice **B4 is gated** on an upstream proptest change.
- **Fix:** model `parseBiggestInt` (near-clone of the existing `parseInt` model, modulo width). *(t_symex.nim:52-63)*

### `system.min`/`system.max` can't be inlined  ·  BLOCKER (v1 finding)
- **Cause:** their stdlib body is an *if-expression*, an unsupported inlining node kind.
- **Workaround:** inline the clamp as an explicit `if` statement.
- **Fix:** support if-expression-bodied procs, or special-case min/max to comparison IR. *(t_symex.nim:142-149)*

---

## 3. Symex — DSL parser expression gaps

### #2 — tuple-constructor return (`nnkTupleConstr`) unsupported  ·  BLOCKER
- **Symptom:** "unsupported expression kind nnkTupleConstr in `(s, i+1)`" when inlining a callee that returns a bare tuple.
- **Cause:** `dsl_parser.nim`'s `parseExpr` has no general `nnkTupleConstr` case (only a `yield (e1,e2)` for-loop special-case ~2002).
- **Workaround:** return the primary value normally and thread the secondary out through a `var` param (var-out-params ARE first-class). Mechanical, no control-flow change.
- **Fix:** add a general `nnkTupleConstr` case. *(t_symex_decode.nim:14-40)*

### `nnkObjConstr` (object/variant construction) not in the expression path  ·  SCOPE
- **Cause:** the only `nnkObjConstr` handling is in the macro's own codegen, not in the walk of a target body.
- **Workaround:** make every twin `void` (discard its computed value).
- **Fix:** allow constructing objects/tuples/variants as DSL expressions so twins needn't be forced to void. *(t_symex_uri.nim:157-164)*

### seq slicing (`data[a..b]`) unsupported (string slicing IS)  ·  SCOPE
- **Cause:** `itSeq` models only single-index `s[i]`; string slicing is special-cased, seq slicing isn't.
- **Workaround:** point-substitute the slice's bounds-safety — touch `data[low]` and `data[high]` under the same length guard, instead of modeling a copy loop.
- **Fix:** add seq slicing mirroring the string special-case. *(t_symex_decode.nim:42-46,162-171)*

### `pred`/`..<` has no DSL case  ·  NICE
- **Cause:** `a ..< b` lowers to `a .. pred(b)`; `pred` has no parser case (zero grep hits).
- **Workaround:** write `a .. (b-1)` explicitly.
- **Fix:** trivial `pred`/`succ` arithmetic-passthrough case. *(t_symex_uri.nim:151-155)*

---

## 4. Symex — solver capability gaps (these fail *soft*, which is correct)

### #6 — chained bounded scans (2nd scan's offset = 1st's symbolic result) → `sxUnknown`  ·  BLOCKER/SCOPE
- **Symptom:** `sxUnknown`, empty errors. Confirmed independent of `maxLoopUnwind` (2 & 5), `maxCallDepth` (3 & 20), and `symexAssume` bounding.
- **Cause:** dependent bounded loops where a later loop's bound derives from an earlier loop's result aren't decidable at this pin.
- **Workaround:** scope the decode option-arm proof to "header + first scan," not "≤2 options."
- **Fix:** improve dependent-bounded-loop handling. *(t_symex_decode.nim:210-253)*

### #9 — ANY loop in a symex target whose frame also has a `string` param → `sxUnknown`  ·  BLOCKER
- **Symptom:** `sxUnknown`, empty errors — for *every* variant (forward/backward scan, loop bounded by `s.len`, loop bounded by a literal that indexes `s` once). A single literal-index read with no loop proves `sxUnsat` fine. Bisected across 8 variants. **Distinct from #6:** #6 is two *individually*-provable int scans; #9 is that a *single* loop of any shape is already unprovable the moment a string param is in scope.
- **Cause:** walker/Z3-Sequence-theory interaction — rules out essentially all string-scanning code from bounded-loop proofs.
- **Workaround:** no loops in string-param targets; bounded hand-unrolled `if`s.
- **Fix:** investigate the Sequence-theory×loop interaction — this is the biggest single capability gap for string code. *(t_symex_uri.nim:65-100; t_symex_security.nim:11-17)*

### `symexAssume` is implemented identically to `symexAssert` (doc says otherwise)  ·  BLOCKER
- **Symptom:** `symexAssume(len <= N)` manufactures its own `sxRaised(AssertionDefect)` instead of narrowing the search.
- **Cause:** `dsl_parser.nim` (~2716) parses `symexAssume(cond)` to `mkAssert(cond)` — identical to `symexAssert` — while `symex.nim` (~938-945) documents "early return if violated" filter semantics.
- **Workaround:** none — an assumed bound on an otherwise-unconstrained value is always constructively violatable, so it's unusable for narrowing.
- **Fix:** implement the documented filter/prune semantics, or fix the doc. This also removes one of the levers we tried (and failed) to use against #6. *(t_symex_decode.nim:236-246)*

---

## 5. Fuzz engine / corpus / DB

### `dbReusePhase` primary-pruning makes a shared testId unsafe for corpus growth  ·  BLOCKER
- **Symptom:** a whole soak's clean coverage-growth entries silently vanish on the next default-suite run of the same testId.
- **Cause:** `engine/phases.nim:35-84` replays every primary entry and `removeMany`s any that doesn't currently falsify. Primary is a *regression-replay* channel; a coverage-guided soak's entries never falsify → pruned. But `fuzzWith`'s corpus-growth and `forAll`'s regression-replay share one storage/API with incompatible semantics.
- **Workaround:** persist soak growth under a distinct `<testId>.soak-corpus` suffix (and crashes under `.soak-crash`) that no `fuzzProperty` references.
- **Fix:** a third, non-pruned "coverage corpus" channel separate from the regression-replay primary section. *(soakrunner.nim:36-88)*

### `minimizeCorpus` only "sees" coverage for entries discovered *in that run*  ·  BLOCKER
- **Symptom:** `minimalCovering` can never select a preloaded seed — its recorded coverage is the zero-value `Coverage()`.
- **Cause:** `fuzz()` seeds `corpusCov = newSeq[Coverage](corpus.len)` (all-zero) after loading preloaded seeds via `captureIR` (~381-403), which replays through the *strategy* only (`s.generate`) and never calls `target.run()`. Only fresh in-session admissions get a real `obs.coverage` (~440-445). So `minimizeCorpus` means "reduce this campaign's fresh discoveries," not "losslessly reduce a curated corpus file."
- **Workaround:** "continuation minimization" — bounded deterministic `fuzzWith` seeded from the grown corpus with `minimizeCorpus:true`, then re-verify coverage independently via `inProcessTarget`/`Observation.coverage`. Got `protocol.decode` 16→9 entries, coverage held 13/13.
- **Fix:** run an up-front coverage-replay pass over preloaded seeds so an external corpus can be losslessly minimized. *(corpusmin.nim:23-72)*

### `minimalCovering` is module-private (no `*`)  ·  SCOPE (export ask)
- **Cause:** `fuzz.nim:337` — no `*`; only reachable via the `FuzzSettings.minimizeCorpus` flag consumed at run-end.
- **Fix:** `export minimalCovering*` (trivially unblocks direct, offline corpus minimization). *(corpusmin.nim:1-21)*

### `FuzzSettings` has no "stop after first crash" knob  ·  NICE
- **Cause:** only `maxIterations`/`timeBudget` gate the loop.
- **Workaround:** run the soak as a series of short bounded bursts, carrying corpus via `initialIRCorpus`, checking `report.irCrashes` between bursts.
- **Fix:** add `stopOnFirstCrash: bool`. *(soakrunner.nim:90-107)*

### `db.nim applySave` prepends → `loadPrimary` is reverse-insertion order  ·  NICE
- **Symptom:** a positional `reloaded[i] == originals[i]` assertion failed with an exact order reversal.
- **Cause:** `applySave`: `c.primary = @[choices] & deduped`. Undocumented.
- **Workaround:** match by content, not position (a corpus is a set, not a sequence).
- **Fix:** document the ordering, or provide an ordering guarantee / timestamp. *(interopcapture.nim:24-28)*

### No per-entry metadata slot on the primary corpus section  ·  NICE
- **Cause:** `primary` is a bare `seq[seq[ChoiceNode]]`; only the *secondary* section has `ScoredEntry.scores: Table[string,float]`, meant for the hill-climb front, not provenance.
- **Workaround:** repurpose `scores` (unused by these testIds) to float-encode `source`/`campaignEpochDay`.
- **Fix:** add a real per-primary-entry metadata slot (optional `Table[string,string]`). *(corpusmin.nim:74-88)*

### Byte→choice-IR seed protocol is undocumented, and malformed IR is *silently* dropped  ·  NICE
- **Symptom:** a hand-built seed with the wrong choice-node shape is discarded before the mutation loop — no error, no warning, no log.
- **Cause:** the per-strategy choice-IR draw order (`strategy.nim:410-472`: a `ckBoolean` continuation gate before each element, then its `ckInteger`, ending in `ckBoolean(false)` — 2N+1 nodes for N elements) is entirely implicit; `datasource.nim`'s `takeReplay` raises `Overrun` on mismatch, `fuzz.nim`'s `captureIR` (~262-277) swallows it and returns `ok:false`, and `initialIRCorpus` (~381-383) silently skips `!ok` entries.
- **Workaround:** a dedicated `encodeByteSeqIR` mirroring the confirmed draw order + validating `booleanChoice`/`integerChoice` constructors that raise at *encode* time; a RED-first test (naive all-integer encoder) to catch the shape before silent data loss.
- **Fix:** (a) document the draw-order protocol; (b) surface `captureIR`'s dropped-seed count/reason in `FuzzReport` so a caller knows part of their corpus never entered the run. *(soakseeds.nim:1-53)*

### "0 committed seeds" for a never-falsified testId reads like a bug  ·  NICE
- **Cause:** a `.bin` can be non-empty (all secondary/targeting-front bytes) while the primary section is empty; the primary/secondary split isn't obvious to a reader.
- **Fix:** an introspection helper reporting both section sizes. *(soakrunner.nim:159-178)*

---

## 6. Coverage

### No reverse map from a bitmap slot → `file:line:col`  ·  SCOPE (arguably BLOCKER for the intended feature)
- **Cause:** `coverage.nim`'s `{.cover.}` (`edgeIdFromLineInfo`) hashes location→slot at compile time and never records the inverse.
- **Impact:** forced C5 to ship a coarse visited-edge *count* signal instead of the intended "which source locations are still uncovered" report (deferred to a future RFC + new compile-time tooling).
- **Fix:** emit a slot→location side-table at `{.cover.}` expansion, or an API to enumerate it. *(coveragereport.nim:1-17)*

### 8192-slot bitmap converges fast → real-corpus before/after deltas non-repeatable  ·  NICE
- **Symptom:** live demo — after a `-Soak 5` (42248 iters, corpus 9→16 entries) `protocol.decode` stayed at **13/8192** edges. Correct behavior, but it means a real-target "coverage went up" assertion can't be automated.
- **Workaround:** the automated RED-GREEN test uses a synthetic under-covered target; the real-target increase is a one-time manual `-CorpusReport` demo.
- **Fix:** none strictly needed (inherent to a fixed coarse bitmap); the slot→source map above would at least let "0 new edges" be *explained* rather than only observed. *(coveragereport.nim:27-40)*

---

## 7. Shrinker

### `shrink(s, prop, choices)` 2-arg overload fails to **compile** for `T = seq[byte]` from an external module  ·  BLOCKER
- **Symptom:** `shrinker.nim(274,18) Error: type mismatch: one < dist`, both operands `Int128`, with `int128.nim:41`'s `<` demonstrably in scope yet absent from the reported candidate set. Reproduces ONLY for `T=seq[byte]`, ONLY when the generic chain first instantiates from a module outside proptest.
- **Cause:** an open-symbol / cross-module generic-instantiation bug in the chain `shrink`→`defaultShrinkPasses[T]`→`lowerIntegerShrinkPass[T]`→`lowerIntegerAt[T]` (its `Int128` binary search). `T=int` compiles fine.
- **Workaround:** the 5-arg overload with an explicit pass list omitting `lowerIntegerShrinkPass[T]` (use `deleteSpansShrinkPass[T]()` alone).
- **Cost:** byte-list crash minimization deletes spans/elements but doesn't lower surviving byte values toward 0.
- **Fix:** fix the open-symbol resolution so `Int128.<` resolves regardless of the triggering external `T`. *(soakrunner.nim:125-157)*

---

## 8. Prioritized ticket list

**Tier 1 — correctness of the prover itself (do these first):**
1. **Walker never crashes** — classify every unsupported construct as `sxUnknown`/`SymexUnsupported…`, never a native exit or uncaught assert. Converts #3/#4/#5/#11 from CRASH to SCOPE immediately. *(cross-cutting)*
2. **`parseBiggestInt` model** — directly unblocks chapulin v2 **B4**. Near-clone of `parseInt`.
3. **`shrink` 2-arg overload for `seq[byte]`** — open-symbol/`Int128.<` resolution bug; today byte-crash minimization is partial.

**Tier 2 — high-leverage capability (unlock whole classes of target):**
4. **`seq[byte]`/fixed-width-int witness readers** (#1) — removes the masking workaround *and* the #3 collision.
5. **Loop + string-param → `sxUnknown`** (#9) — biggest single gap for string-scanning code; nothing with a real loop over a string is provable today.
6. **Model `toLowerAscii`/`toUpperAscii`** (#7, parser plumbing already exists) and **`rfind`** (#8) and **in-place `string.add`** (#10).
7. **`symexAssume` filter semantics** (or fix the doc) — also removes a lever we needed against #6.

**Tier 3 — corpus/soak workflow:**
8. **Non-pruned coverage-corpus channel** separate from regression-replay primary (`dbReusePhase`).
9. **Export `minimalCovering*`** + an **up-front coverage-replay of preloaded seeds** so external corpora minimize losslessly.
10. **`FuzzSettings.stopOnFirstCrash`**, **per-primary-entry metadata slot**, and **surface `captureIR` dropped-seed count** in `FuzzReport`.

**Tier 4 — parser completeness & ergonomics:**
11. `nnkTupleConstr` (#2), `nnkObjConstr`, seq slicing, `pred`/`..<`, if-expression-bodied `min`/`max` inlining.
12. Document the choice-IR draw-order protocol; document `db.nim` primary ordering; a corpus section-size introspection helper.

**Tier 5 — coverage reporting:**
13. Slot→`file:line:col` side-table at `{.cover.}` expansion (unblocks the deferred source-mapped coverage-gap report; also lets "0 new edges" be explained).

---

*Compiled 2026-07-12 from the v1/v2 harness build. Every item is reproducible from the cited
chapulin test; the symex Blockers #1–#11 also live as in-file doc comments in `tests/t_symex_*.nim`.*
