# Design philosophy

This project is a proof of concept, a demonstration of engineering skill, and a beta. Every decision should reflect the best possible approach a computer scientist would take — no shortcuts justified by "it's just a prototype," no compromises rationalized by "we can fix it later." The codebase should demonstrate what correct, elegant systems software looks like.

This document captures architectural decisions and the reasoning behind them. These are not arbitrary preferences — each reflects a specific trade-off evaluation.

## No compromises on correctness

When choosing between design approaches, prioritize safety, correctness, elegance, maintainability, and architectural soundness over simplicity or expediency. A flat proc may be "simpler" but a shared abstraction may be more correct if it enforces separation of concerns. Three similar lines of code is better than a premature abstraction. Be bold in pursuing the right design — "safe" means structurally sound and secure, not timid.

If something is done the wrong way, it gets rewritten — not patched, not documented as tech debt, not deferred. The cost of carrying a wrong design forward always exceeds the cost of fixing it now, and a proof of concept that demonstrates the wrong approach demonstrates nothing.

## Embrace breaking changes

The API is not set in stone. If a breaking change results in better code — cleaner interfaces, stronger invariants, better separation of concerns — make the breaking change. Do not preserve a suboptimal API out of inertia.

## Fix the architecture, don't patch symptoms

When a design is fundamentally wrong, fix the design instead of adding workarounds. If adding a server reveals that the client engine fused initiation with transfer logic, extract the shared primitives and rebuild both sides on top of them. Don't bolt server support onto client code.

## Design from first principles

Approach every non-trivial problem as a greenfield question. Start from the perspective of a computer scientist designing the best possible solution with zero constraints — no anchoring to existing implementations (ours or anyone else's), no "this is how tftpd-hpa does it" as justification. Determine the ideal design, then work backwards to fit it into the project. The existing codebase is a starting point, not a constraint. If the ideal design conflicts with what we have, change what we have.

## Test-driven development

Tests are the specification. Write tests before implementation, and use them to prove the implementation is correct.

**Wire-format tests over roundtrip tests.** For any wire protocol, always test against known-good byte sequences from the RFC. Roundtrip tests (`decode(encode(x)) == x`) only prove encode and decode are inverses, not that either is correct. A byte-order bug can survive all roundtrip tests because both sides have the same error.

**Tests document bugs.** When a review finds a potential bug, write a test that would fail if the bug exists before fixing it. If the test passes, the bug is a false positive and the test becomes a regression guard.

**Existing tests are the rewrite spec.** When refactoring a module, the existing passing tests define correct behavior. If any break, the refactor is wrong — not the tests.

**Every test proves something specific.** "Transfer completed without error" is not a test — "transfer of 2000 bytes across 4 blocks produces correct ACK sequence and file content" is a test.

## Module architecture

The codebase is split into focused modules in a layered DAG. Each module has a single responsibility and clean dependency boundaries.

```
protocol.nim             (pure packet codec, no I/O)
    |
transfer.nim             (shared sendBlocks/recvBlocks primitives)
    |
options.nim              (option negotiation for both client and server)
    |       \
engine.nim   server.nim  (equal siblings, not parent-child)
    |            |
    |       security.nim + server_config.nim
    |
transport.nim            (real UDP sockets + server listener)
    |
api.nim                  (client public API with file I/O)
    |
chapulin.nim              (combined CLI: get/put/serve)
chapulin_gui.nim          (NiGui desktop GUI)
```

**Key boundary decisions:**

- **protocol.nim is pure.** No I/O, no side effects, no imports beyond `std/strutils`. Every packet type encodes and decodes identically for client and server. This is the most reusable module and the most thoroughly tested.
- **transfer.nim is the center of gravity.** All shared types (`Transport`, `TransferConfig`, `PeerEndpoint`, `TransferResult`) and the two core state machines (`sendBlocks`, `recvBlocks`) live here. Both client and server are thin wrappers around these primitives.
- **engine.nim and server.nim are siblings.** Neither wraps the other. They share `transfer.nim` and `options.nim` but have no dependency between them. Adding a server did not require changing the client engine.
- **transport.nim owns real I/O.** The `Transport` type is a struct of closures (send/recv/close), making it trivially mockable. Real UDP implementation and the server listener live here. Everything above is testable without touching the network.
- **api.nim is the stable public contract.** CLI and GUI consume only this module. It re-exports everything frontends need so they never import engine or server directly.

## Concurrency model

Single-threaded async with `std/asyncdispatch`. This is the canonical Nim 2.x approach for I/O-bound network servers and the most correct choice for demonstrating idiomatic Nim.

**The entire I/O stack is async.** `Transport` closures return `Future`. Transfer primitives (`sendBlocks`, `recvBlocks`) are `{.async.}`. The server dispatches concurrent transfers via `asyncCheck` — no threads, no locks, no atomics, no channels. Each concurrent transfer is an async task on the same event loop.

**Why async is canonical Nim:** The stdlib networking ecosystem (`asyncnet`, `asynchttpserver`) is built on `asyncdispatch`. Production Nim servers (Mummy, Jester, Prologue) use async event loops. ORC handles async future cycles correctly. Using threads for I/O-bound server work in Nim is fighting the language.

**Why the colored-function tradeoff is worth it:** Yes, `async`/`await` propagates through the call stack. But the benefits are decisive: zero threading complexity in the server, server and client can share the same event loop in tests, the single-threaded model eliminates races and deadlocks, and concurrent transfers come for free via `asyncCheck`.

**Client wraps async in `waitFor`.** The CLI calls `waitFor executeTransfer(...)` and `waitFor srv.run(...)`. The GUI runs transfers in a background thread with `waitFor` internally (NiGui's event loop cannot share the async dispatch loop). This is correct — the client does one operation at a time.

## Transport abstraction

`Transport` is a flat struct of three closures: `send`, `recv`, `close`. This is direction-neutral — the same type serves client sockets, server per-transfer sockets, and mock transports for testing. The closure-based design maps directly to C function pointers for the future FFI layer, with no vtable or class hierarchy.

## Combined binary

One binary serves as both client and server (`get`/`put`/`serve` subcommands). One GUI with client and server capabilities. This reflects that the domain is one thing (TFTP) with two roles, not two separate programs that happen to share code.

## Testing strategy

**Test categories:**
- **Wire-format tests** (t_protocol.nim): exact byte sequences per RFC
- **Transfer primitive tests** (t_transfer.nim): sendBlocks/recvBlocks with mock transport
- **Option negotiation tests** (t_options.nim): client and server sides, edge cases
- **Client integration tests** (t_client.nim): full getFile/putFile flows with mock
- **Security tests** (t_security.nim): path traversal, write policies, host access
- **Server handler tests** (t_server.nim): handleRrq/handleWrq with mock transport
- **API tests** (t_api.nim): public API with file I/O error handling
- **Self-hosted integration tests** (t_integration.nim): our client talking to our server over real UDP, including concurrent transfers
- **External integration tests** (t_integration.nim): our client against tftpd-hpa in Docker, validating interoperability with battle-tested third-party implementations
