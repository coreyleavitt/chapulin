# Shared container-invocation helper (RFC verification-harness-v2, slice C0).
#
# Factors the milpa-fetch / Docker-mount / image-selection scaffolding that
# every "compile+run a nim file inside the pinned toolchain container" verb
# needs, out of dev-test.ps1's per-suite loop and into one reusable function:
# `Invoke-NimContainer`. dev-test.ps1 sources this file and calls the
# function once per suite; the future `-Soak` mode (C1 -- a long single-target
# run that needs an extra `-e CHAPULIN_SOAK_SECONDS=<n>`) and `-CorpusReport`
# verb (C5 -- a differently-shaped nim invocation, not one of the registered
# test suites) are expected to source this same file and call the same
# function, rather than re-deriving milpa-fetch/mount/image-selection.
#
# This file intentionally does NOT know about "suites", "-Only", pass/fail
# accounting, or exit codes -- that contract stays entirely in dev-test.ps1
# (and whatever -Soak/-CorpusReport become). It knows only how to run one
# nim file in one container.

# Toolchain images. `t_symex*`-named targets need the z3-extended image
# (Dockerfile.symex); everything else uses the base nim image. Kept as an
# implementation detail of the helper (not exported globals) so callers only
# ever need to know about the `-Image` override escape hatch.
$script:ChapulinBaseImage  = "ghcr.io/coreyleavitt/nim:2.2.10"
$script:ChapulinSymexImage = "chapulin-symex:2.2.10"

# milpa fetch resolves deps into _deps/ on the HOST once; it's a project-wide
# precondition, not a per-target one, so it's memoized per process rather than
# re-run on every Invoke-NimContainer call (every current/future caller needs
# the precondition satisfied, but only the first call in a process should pay
# for it -- matches dev-test.ps1's original once-before-the-loop behavior).
$script:ChapulinMilpaFetched = $false

function Invoke-NimContainer {
    <#
    .SYNOPSIS
        Resolve deps (once per process) then compile+run one nim file inside
        the pinned toolchain container, selecting the image the same way
        dev-test.ps1 always has.

    .PARAMETER ProjectRoot
        Repo root. Bind-mounted read/write into the container at C:\app;
        also used as milpa's `-C` target and to pin MILPA_CACHE_DIR in-tree.

    .PARAMETER NimFile
        Path to the nim file to compile+run, relative to ProjectRoot (e.g.
        "tests\t_protocol.nim"). The `t_symex*` image convention is matched
        against this file's base name.

    .PARAMETER Image
        Explicit image override. Highest precedence -- beats the `t_symex*`
        convention, same as dev-test.ps1's existing `-Image` flag.

    .PARAMETER EnvVars
        Extra `-e KEY=VALUE` docker run flags, e.g.
        @{ CHAPULIN_SOAK_SECONDS = "60" } for the future -Soak mode. Empty by
        default, so today's callers get byte-identical `docker run` invocations.

    .PARAMETER NimArgs
        The nim invocation verb + flags, before the file path. Defaults to
        dev-test.ps1's existing invocation. A future -CorpusReport verb that
        runs a differently-shaped nim program can override this.

    .OUTPUTS
        The container's exit code (int), so callers do their own pass/fail
        accounting -- this function makes no judgment about success/failure.
    #>
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$NimFile,
        [string]$Image,
        [hashtable]$EnvVars = @{},
        [string[]]$NimArgs = @('c', '-r', '--hints:off', '--colors:off', '-d:chapulinTest')
    )

    if (-not $script:ChapulinMilpaFetched) {
        Write-Host "==> milpa fetch (host)" -ForegroundColor Cyan
        # Keep the CAS in-tree (absolute path under the project -- CWD-independent).
        $env:MILPA_CACHE_DIR = Join-Path $ProjectRoot ".milpa-cache"
        milpa -C $ProjectRoot fetch
        if ($LASTEXITCODE -ne 0) { throw "milpa fetch failed" }
        $script:ChapulinMilpaFetched = $true
    }

    # Image selection: -Image override > t_symex* convention (by file base
    # name) > base image. A lookup table keyed by exact suite name would
    # silently fall back to the base image for an unlisted t_symex* suite,
    # producing a cryptic link/compile failure instead of an obvious one --
    # the `-like` convention needs no per-file entry to remember.
    $baseName = [IO.Path]::GetFileNameWithoutExtension($NimFile)
    $img =
        if ($Image) { $Image }
        elseif ($baseName -like 't_symex*') { $script:ChapulinSymexImage }
        else { $script:ChapulinBaseImage }

    Write-Host "==> $baseName (container: $img)" -ForegroundColor Cyan

    $envFlags = @()
    foreach ($key in $EnvVars.Keys) { $envFlags += @('-e', "$key=$($EnvVars[$key])") }

    # `| Out-Host` -- NOT a bare `docker run ...` statement. A bare native-command
    # statement's stdout becomes this FUNCTION's own success-stream output; a caller
    # that captures the call (`$exitCode = Invoke-NimContainer ...`, which is exactly
    # how dev-test.ps1's suite loop and -Soak mode both call this) then gets an
    # `Object[]` of every compiled/echoed line PLUS the trailing `$LASTEXITCODE`
    # bundled together, not a bare int -- so a caller's `-ne 0`/`-gt 0` check against
    # that array is ALWAYS truthy (array `-ne` returns the non-matching subset, and
    # any non-empty array is truthy), misreporting every run as failed regardless of
    # the real exit code. `Out-Host` prints the container's output for the operator
    # to read (unchanged visible behavior) without adding it to the pipeline, so the
    # explicit `return $LASTEXITCODE` below is genuinely the only value callers see.
    docker run --rm @envFlags -v "${ProjectRoot}:C:\app" $img nim @NimArgs $NimFile | Out-Host
    return $LASTEXITCODE
}
