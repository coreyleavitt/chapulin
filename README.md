# chapulin

Cross-platform TFTP client and server. Single binary, CLI and GUI, full RFC compliance.

## Quick start

Download a file:
```
chapulin get 192.168.1.1 firmware.bin
```

Upload a file:
```
chapulin put 192.168.1.1 config.txt --output=router-config.txt
```

Serve a directory:
```
chapulin serve ./tftp-root --port=69 --write=all
```

URI syntax works too:
```
chapulin get tftp://192.168.1.1:69/firmware.bin
```

## Install

### Download binary

Prebuilt binaries for Linux, macOS, and Windows are available on the [releases page](https://github.com/coreyleavitt/chapulin/releases).

### Build from source

Requires [Nim](https://nim-lang.org/) 2.0+.

```
nimble install
nimble build
```

With GUI support (Windows + Linux):
```
nim c --threads:on -d:withGui -d:release -o:chapulin src/chapulin.nim
```
The GUI uses the [oyamel](https://github.com/coreyleavitt/oyamel) toolkit —
Win32 on Windows, GTK4 on Linux (`libgtk-4-dev`). The backend is selected
automatically by `config.nims`. macOS is CLI-only for now (oyamel has no Cocoa
backend yet); build it without `-d:withGui`.

### Docker

```
docker build -t chapulin .
docker run --rm chapulin nimble test
```

## CLI reference

```
chapulin get <host> <filename> [options]
chapulin get tftp://<host>[:<port>]/<filename> [options]
chapulin put <host> <filename> [options]
chapulin put tftp://<host>[:<port>]/<filename> [options]
chapulin serve <rootdir> [options]
chapulin gui
```

### Client options

| Flag | Default | Description |
|------|---------|-------------|
| `--port=N` | 69 | Server port |
| `--blocksize=N` | 512 | Block size in bytes |
| `--windowsize=N` | 1 | Window size in blocks (RFC 7440) |
| `--timeout=N` | 5 | Timeout in seconds |
| `--retries=N` | 3 | Max retransmit attempts |
| `--output=PATH` | filename | Local file path |
| `--mode=MODE` | octet | Transfer mode: `octet` or `netascii` |

### Server options

| Flag | Default | Description |
|------|---------|-------------|
| `--port=N` | 69 | Listen port |
| `--write=POLICY` | deny | Write policy: `deny`, `create`, `overwrite`, `all` |
| `--max-clients=N` | 10 | Max concurrent transfers |
| `--blocksize=N` | 65464 | Max negotiated blocksize |
| `--timeout=N` | 5 | Timeout in seconds |
| `--port-range=S:E` | OS-assigned | Transfer port range for firewalls |
| `--pxe-compat` | off | Only negotiate tsize (for buggy PXE ROMs) |
| `--bind=ADDR` | 0.0.0.0 | Bind to specific IP address |
| `--dir-list=FILE` | disabled | Serve directory listing as this filename |
| `--checksum=MODE` | disabled | Generate checksum sidecar after read (`md5`) |

### General options

| Flag | Description |
|------|-------------|
| `--notify` | Audible bell on transfer completion |
| `--verbose` | Debug-level output |
| `--quiet` | Errors only |
| `--help` | Show help |
| `--version` | Show version |

## GUI

Launch with `chapulin gui` (requires build with `-d:withGui`; Windows and Linux). Client and server in one window with tabbed panels.

## RFC compliance

| RFC | Description | Status |
|-----|-------------|--------|
| [RFC 1350](https://datatracker.ietf.org/doc/html/rfc1350) | TFTP Protocol (base) | Complete |
| [RFC 2347](https://datatracker.ietf.org/doc/html/rfc2347) | Option Extension (OACK) | Complete |
| [RFC 2348](https://datatracker.ietf.org/doc/html/rfc2348) | Blocksize Option | Complete |
| [RFC 2349](https://datatracker.ietf.org/doc/html/rfc2349) | Timeout & Transfer Size | Complete |
| [RFC 7440](https://datatracker.ietf.org/doc/html/rfc7440) | Windowsize Option | Complete |
| [RFC 1123 s4.2](https://datatracker.ietf.org/doc/html/rfc1123) | Adaptive timeout, broadcast rejection | Complete |
| [RFC 3617](https://datatracker.ietf.org/doc/html/rfc3617) | TFTP URI Scheme | Complete |

## Architecture

```
protocol.nim             pure packet codec
    |
transfer.nim             async sendBlocks/recvBlocks primitives
    |
options.nim              option negotiation (client + server)
    |       \
engine.nim   server.nim  client and server as equal siblings
    |            |
    |       security.nim + server_config.nim
    |
transport.nim            async UDP sockets + server listener
    |
api.nim                  public API
    |
chapulin.nim             combined CLI (get/put/serve/gui)
```

Single-threaded async I/O (`std/asyncdispatch`). Concurrent server transfers via `asyncCheck`. 228 tests. Interop tested against tftpd-hpa and atftp.

See [design-philosophy.md](design-philosophy.md) for architectural decisions and rationale.

## Verification harness

Beyond the example/property test suite (`nimble test` / `scripts/dev-test.ps1`), chapulin carries a
coverage-guided fuzzing + bounded symbolic-execution + stateful-property harness over the attacker-facing
parse/containment/orchestration surface — it *proves* the never-throw-Defect claims in
[SECURITY.md](SECURITY.md#verification) rather than resting on code-review confidence. Full design:
[docs/rfc/verification-harness.md](docs/rfc/verification-harness.md) (v1 — fuzz + symex over parse/
containment/queue, plus the post-negotiation data phase) and
[docs/rfc/verification-harness-v2.md](docs/rfc/verification-harness-v2.md) (v2 — the `api.nim` facade
itself, `maxConcurrent` enforcement, deeper symex, and the soak/corpus campaign below; see its handoff
doc for the as-landed scope of each item).

**Fuzz/property suite** (pure Nim, no z3 — this is the default suite):
```
pwsh scripts/dev-test.ps1
```
`milpa` resolves dev-deps on the host, then each `tests/t_*.nim` file compiles and runs inside the nim
devtools container. Coverage-guided targets (e.g. `t_props`, `t_security`, `t_netascii`, `t_checksum`,
`t_eventqueue`, `t_hostile`) are compiled with a `-d:chapulinFuzz` define (`tests/nim.cfg`) that turns on
`{.cover.}` instrumentation (`src/chapulin/coverpragma.nim`); off that define, `{.cover.}` is an exported
no-op, so normal/release builds of `src/` never import the fuzzer and are byte-for-byte unaffected. Each
fuzz target's crash corpus is committed under `tests/corpus/` (binary-protected via `.gitattributes`) and
is automatically replayed and extended on every run via its `testId`.

**Facade stateful property** (in the default suite): `tests/t_a2_facade_stateful.nim` drives a REAL
client↔server `TftpSession` pair over a mocked `Wire` (file I/O via the in-memory BlockSource/BlockSink
seam, so no disk is touched) through `startTransfer`(get/put)/`startServer`/`cancel`/`stop`/`close`, and
— under coverage-guided hostile packet injection (forged/garbage/off-TID DATA/ACK/ERROR, malformed
RRQ/WRQ, forged OACK) — asserts no Nim `Defect` ever escapes `api.nim`'s own `except CatchableError`
boundaries. This is the never-throw claim's highest-value gap closed: earlier suites proved the layers
*beneath* the facade never raise a Defect; this one drives hostile input through the facade's own entry
points. `tests/t_a4_maxconcurrent.nim` proves the (N+1)th concurrent transfer is actually rejected (not
just config-plumbed) and surfaces as a structured `evServerRejected` event through the public API.

**Symex proof/witness suite** (opt-in — needs the z3-extended image, not part of the default run):
```
pwsh scripts/dev-test.ps1 -Only @('t_symex') -Image chapulin-symex:2.2.10
```
Any suite named `t_symex*` auto-selects the `chapulin-symex:2.2.10` image (built from `Dockerfile.symex`),
so `-Image` is optional. This is the only place `import proptest/symex` (and transitively, z3 via the
runtime-optional `nim-z3`/`softlink` binding) is linked in — it never reaches `src/` or the default suite.
It produces bounded no-Defect proofs (`sxUnsat`) and validated raised-exception witnesses (`sxRaised`) over
the option/OACK parsers, `protocol.decode`'s fixed-size opcode arms plus its RRQ/WRQ option-parsing header
+ first-field scan (bounded, not total — a second, chained scan hits a documented solver limit), the
lexical prefixes of `validatePath`/`checkWriteAccess`, `tftp_uri.parseTftpUri`/`isTftpUri`,
`checksum.writeSidecar`'s path derivation, and the netascii decoder's non-conformant-CR transition. See
[SECURITY.md's Verification table](SECURITY.md#verification) for the exact scope/bound of each proof.

**Soak campaign** (local-opt-in only — never run by CI or the default suite):
```
pwsh scripts/dev-test.ps1 -Soak 60         # grow the corpus for 60 seconds
pwsh scripts/dev-test.ps1 -CorpusReport    # report a committed target's visited-edge count
```
`-Soak` runs a coverage-guided campaign (proptest's `fuzzWith`) against `protocol.decode`, growing
`tests/corpus/protocol.decode.soak-corpus.bin` — a file the default suite replays on every run. The first
Defect found stops the campaign, minimizes it, and commits it under a `.soak-crash` corpus file instead.
Growth is periodically re-minimized and size-capped (`CorpusSizeCeiling = 16` per target, so replay time
stays bounded) and every entry is provenance-tagged (soak / interop-capture / interop-capture-unverified +
campaign date). `-CorpusReport` shows the coarse visited-edge count for a target before/after a campaign —
a target already fuzzed to convergence can legitimately show no increase; that's an expected, documented
outcome, not a bug. See [SECURITY.md](SECURITY.md#verification) for the full corpus/coverage claim rows,
including the honest scope-down on live interop-capture (mechanism built; not exercised on this project's
Windows-containers-only Docker environment).

**The never-throw-Defect property, in one sentence:** hostile input to any fuzzed target degrades to a
caught `CatchableError` (or a documented per-option default) — never an escaping Nim `Defect` — enforced
per-target by an oracle proc, not asserted by convention. See
[SECURITY.md's Verification section](SECURITY.md#verification) for the full claim-by-claim cross-reference
to the exact test target that proves each one.

## License

Apache 2.0
