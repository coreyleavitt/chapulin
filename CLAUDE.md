# chapulin

FFI-free async single-threaded TFTP server/client in Nim. Public API is `src/chapulin/api.nim` (the session
facade); frontends must not import `protocol`/`engine`/`transfer` directly.

## Compact Instructions

When compacting, preserve in the summary: the active RFC and its handoff-doc path, the current stage/round,
slices done vs remaining, open forks awaiting me, and the exact resume command. After compacting, re-read the
handoff doc and MEMORY.md before continuing.
