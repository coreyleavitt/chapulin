## One-shot corpus minimization for the `protocol.decode` soak-grown corpus
## (RFC verification-harness-v2.md §3.3/§5, slice C4). Opt-in/manual --
## mirrors `-Soak`'s and `interopcapture.nim`'s own manual-invocation
## convention (NOT part of `scripts/dev-test.ps1`'s default suite): this is
## a maintenance operation an operator runs occasionally after a soak
## campaign has grown a corpus, not a fast-suite assertion.
##
## Uses `corpusmin.nim`'s `minimizeGrownCorpus` (the real, only-reachable
## `minimizeCorpus` front door -- see that module's doc comment) seeded
## from the CURRENTLY-committed `protocol.decode.bin`'s own `corpus`
## section (F1, RFC-chapulin-hardening -- 0.3.1 modernization; growth used
## to live in a sibling `protocol.decode.soak-corpus.bin`, see
## `soakrunner.nim`'s doc comment), verifies (via `unionCoverageOf`,
## independently, using only exported proptest APIs) that the minimized
## set's covered-edge total is not a regression, then re-promotes every
## surviving entry to the front of that same `corpus` section (see the
## `when isMainModule` block below for why this is a promotion, not a
## hard replace -- the `corpus` section exposes no bulk-remove) and tags
## each with per-entry provenance (source=soak, the caller-supplied
## campaign date -- see `corpusmin.nim`'s doc comment for why this module
## makes no internal wall-clock call) via the SECONDARY section's scores
## sidecar.
##
## Run (from the repo root, inside the nim container -- see
## scripts/dev-test.ps1 for the exact container invocation shape):
##   nim c -r tests/corpusminimize_decode.nim [campaignEpochDay]
##
## `campaignEpochDay` is any caller-chosen number identifying "when this
## minimization campaign ran" (e.g. days since epoch, or just an
## incrementing counter) -- defaults to 0.0 (with a warning) if omitted.

import std/[os, strutils]
import nelli
import ./fuzzsupport
import ./corpusmin
import ./soak_decode  # decodeProp* -- reused verbatim, the exact oracle C1's soak already fuzzes

when isMainModule:
  let campaignEpochDay =
    if paramCount() >= 1:
      try: parseFloat(paramStr(1))
      except ValueError: 0.0
    else:
      echo "==> no campaignEpochDay given -- tagging provenance with 0.0 (caller should supply one for real triage use)"
      0.0

  let db = directoryBasedDatabase(CorpusDir)
  let testId = "protocol.decode"
  let before = db.loadCorpus(testId)
  echo "==> loaded " & $before.len & " entries from tests/corpus/" & testId & ".bin's corpus section"
  doAssert before.len > 0, "nothing to minimize -- run `dev-test.ps1 -Soak <seconds>` first"

  let beforeCoverage = unionCoverageOf(byteSeqs(), decodeProp, before)
  let beforeEdges = coveredEdgeCount(beforeCoverage)
  echo "==> pre-minimization covered edges (independently recomputed): " & $beforeEdges

  # Deterministic (maxIterations, never a wall-clock timeBudget): re-derive
  # a covering subset of what a bounded continuation campaign, seeded from
  # `before`, discovers. See corpusmin.nim's module doc comment for the
  # honest "continuation minimization, not byte-exact static reduction"
  # framing this necessarily is, given `minimalCovering`'s real semantics.
  let minimized = minimizeGrownCorpus(byteSeqs(), decodeProp, before, FuzzSeed.uint64, 20000)
  let afterCoverage = unionCoverageOf(byteSeqs(), decodeProp, minimized)
  let afterEdges = coveredEdgeCount(afterCoverage)
  echo "==> post-minimization: " & $minimized.len & " entries (was " & $before.len &
       "), covered edges: " & $afterEdges

  doAssert afterEdges >= beforeEdges,
    "minimization LOST coverage (" & $afterEdges & " < " & $beforeEdges & ") -- refusing to commit"

  # The `corpus` section (F1, RFC-chapulin-hardening) is deliberately
  # append/dedup-only -- `ExampleDatabase` exposes `saveCorpusImpl`/
  # `loadCorpusImpl` but no `removeCorpusImpl` (unlike `primary`, which has
  # `removeMany`). So "commit the minimized set" here re-promotes each
  # minimized entry to the front of the section via `saveCorpus`'s own
  # dedup+prepend admission policy (db.nim's `dedupPrepend`) rather than
  # hard-replacing it: an entry minimization DROPPED simply stops being
  # re-promoted and ages out via the maxEntries tail-eviction the next time
  # this tool (or a soak run) admits enough fresh entries, instead of being
  # removed atomically today. Disclosed, not silently presented as a hard
  # replace (mirrors corpusmin.nim's own "continuation, not byte-exact
  # reduction" disclosure for `minimizeGrownCorpus` itself).
  for e in minimized:
    db.saveCorpus(testId, e, maxEntries = CorpusSizeCeiling)
  tagProvenance(db, testId, minimized, csSoak, campaignEpochDay)

  let reloaded = db.loadCorpus(testId)
  echo "==> promoted " & $minimized.len & " minimized entrie(s) to the front of tests/corpus/" &
       testId & ".bin's corpus section (now " & $reloaded.len &
       " total entries, origin: soak, tagged csSoak, day=" & $campaignEpochDay & ")"
