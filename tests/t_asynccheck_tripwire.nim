## Call-form `asyncCheck(` tripwire (RFC verification-harness-v2.md
## A-shared, §3.1/§4). `src/` must carry ZERO `asyncCheck(` CALLS: a
## detached Future's Defect would be silently lost by asyncdispatch's
## fire-and-forget callback, which is one of the two facts (the other being
## "pumping is synchronous in the invariant call stack") the whole "an
## escaped Defect surfaces" guarantee the rest of Part A rests on (architect
## r1; sharpened r2).
##
## Anchored to the CALL form (`asyncCheck(`), not a bare substring match on
## the identifier "asyncCheck" -- `api.nim:619` carries a prose comment
## ("...never asyncCheck — Invariant 2") that mentions the identifier but is
## not a call; a naive substring scan would misfire on it and on any future
## comment that explains the rule using the same word.
##
## Run:
##   pwsh scripts/dev-test.ps1 -Only @('t_asynccheck_tripwire')

import std/[os, strutils, unittest]

const SrcDir = currentSourcePath.parentDir / ".." / "src"

proc stripLineComment(line: string): string =
  ## Best-effort Nim line-comment strip: everything from the first `#`
  ## onward is comment/doc-comment text, never call syntax. A full Nim
  ## lexer is unwarranted for one anchored substring tripwire -- no
  ## chapulin source line embeds a literal `#` inside a string ahead of a
  ## real `asyncCheck(` call.
  let idx = line.find('#')
  if idx < 0: line else: line[0 ..< idx]

proc findAsyncCheckCalls*(text: string): seq[string] =
  ## Every line (as `"N: <line>"`, 1-indexed) whose CODE portion (line
  ## comments stripped) contains the call form `asyncCheck(`.
  let lines = text.splitLines()
  for i, line in lines:
    if "asyncCheck(" in stripLineComment(line):
      result.add($(i + 1) & ": " & line.strip())

suite "asyncCheck-in-src tripwire -- scanner exclusion logic (A-shared)":
  test "the scanner finds a real call and ignores a plain comment mentioning asyncCheck":
    let fixture = """
proc setup() =
  # never asyncCheck -- Invariant 2
  discard

proc leaky() =
  asyncCheck(doSomething())  # a real, forbidden call
"""
    let hits = findAsyncCheckCalls(fixture)
    check hits.len == 1
    check "asyncCheck(doSomething())" in hits[0]

  test "the scanner ignores a comment that itself contains the call-form text":
    ## The stricter case the RFC calls out: a comment that literally
    ## contains "asyncCheck(" (e.g. a doc example) must still be excluded --
    ## proves this is `stripLineComment` at work, not luck that api.nim's
    ## one existing comment happens to lack a trailing paren.
    let fixture = "  # e.g. asyncCheck(foo()) is forbidden here\n"
    check findAsyncCheckCalls(fixture).len == 0

suite "asyncCheck-in-src tripwire -- committed, always-run gate (A-shared)":
  test "src/ contains zero call-form asyncCheck( invocations":
    var offenders: seq[string]
    for path in walkDirRec(SrcDir):
      if not path.endsWith(".nim"): continue
      for hit in findAsyncCheckCalls(readFile(path)):
        offenders.add(path & ":" & hit)
    for o in offenders: checkpoint(o)
    check offenders.len == 0
