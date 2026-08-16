## Coverage-instrumentation shim (RFC verification-harness.md D2).
##
## Coverage-guided fuzzing reads the same edge bitmap that `proptest`'s
## `{.cover.}` macro populates, so the SUT procs targeted by a fuzz property
## need that pragma even on the plain `coverageGuided` `property` path.
## Importing `proptest` directly into `src/` would couple production code to
## a dev-dependency, so this ONE shared module is the sole `src/` file aware
## of `-d:chapulinFuzz`:
##
## - Under `-d:chapulinFuzz` (set tests-wide by `tests/nim.cfg`), `cover` is
##   `proptest/coverage`'s real AST-rewriting macro — it instruments the
##   annotated proc's own branch arms so coverage-guided search gets real
##   edge feedback.
## - Otherwise `cover` is an exported no-op user pragma: `src/` imports
##   nothing from `proptest`, and the release/default build is byte-for-byte
##   unaffected (the pragma vanishes at the annotation site).
##
## SUT procs opt in with `{.cover.}`; nothing else about them changes.
when defined(chapulinFuzz):
  import nelli/coverage
  export cover                      # re-export the macro under its own name
else:
  # Exported no-op user pragma. NOTE (deviation from the RFC's own sketch,
  # confirmed empirically): the statement form `{.pragma: cover*.}` does not
  # parse (`*` isn't accepted directly after the pragma name in that form) —
  # the `template name*() {.pragma.}` form is the one Nim actually accepts
  # for an *exported* user pragma, verified cross-module in the target
  # container (ghcr.io/coreyleavitt/nim:2.2.10).
  template cover*() {.pragma.}
