#!/usr/bin/env bash
# CI build + test driver.
#
# Resolves deps with MILPA, not nimble: nimble cannot evaluate softlink's
# .nimble file (it `import`s a source module) and does not know the
# milpa-managed dev-deps (nelli, wired into every test via coverpragma). milpa
# reads milpa.kdl/milpa.lock, materializes deps into _deps/, and emits nim.cfg
# with the --path lines -- exactly the local dev loop (scripts/dev-test.ps1),
# except CI runs nim natively on the runner instead of in the Docker container.
#
# Usage: bash scripts/ci.sh   (auto-detects OS via uname)
set -uo pipefail

export MILPA_CACHE_DIR="$PWD/.milpa-cache"   # keep the CAS in-tree (relative dep symlinks)

# milpa (dep resolver) — install via pipx if the runner doesn't have it. All
# deps it resolves are public git repos, so no auth is needed. PATH is exported
# within this one bash process, so the milpa call below sees it (no GITHUB_PATH
# juggling).
if ! command -v milpa >/dev/null 2>&1; then
  echo "==> installing milpa via pipx"
  pipx install "git+https://github.com/coreyleavitt/milpa.git#subdirectory=impls/python"
  bindir="$(pipx environment --value PIPX_BIN_DIR)"
  # On Windows git-bash, PIPX_BIN_DIR is a C:\... path -- the drive-letter colon
  # would split PATH -- so convert to a /c/... POSIX path first.
  case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) bindir="$(cygpath -u "$bindir")";; esac
  export PATH="$bindir:$PATH"
fi

echo "==> milpa lock + fetch (resolve deps into _deps/, emit nim.cfg)"
# Re-lock per-OS rather than trusting the committed milpa.lock: milpa's content
# hashes depend on the checkout's line endings (git autocrlf), so a lock made on
# one OS diverges on another (FETCH-PROVENANCE-DIVERGENCE). Regenerating here
# makes lock + fetch self-consistent on whatever runner this is. (Upstream milpa
# should normalize line endings in its content-addressing; tracked separately.)
milpa -C . lock  || { echo "FATAL: milpa lock failed";  exit 1; }
milpa -C . fetch || { echo "FATAL: milpa fetch failed"; exit 1; }

OS="$(uname -s)"
echo "==> OS: $OS"

# Fast unit suites. Excluded on purpose: t_symex* (need the z3-extended image,
# not a bare runner), the -Soak/-CorpusReport modes, and t_integration (needs a
# real external TFTP daemon). This mirrors the nimble `test` task's old list plus
# the two GUI suites.
SUITES="t_protocol t_transfer t_options t_security t_server t_logging t_uri \
        t_client t_api t_props t_props_transfer t_props_server t_wireharness \
        t_session t_gui_pure t_gui_pump"

case "$OS" in
  MINGW*|MSYS*|CYGWIN*)
    # t_security's symlink-containment suite (issue #19) needs POSIX
    # expandFilename symlink resolution, which Windows lacks (a documented
    # best-effort limit -- see the no-local-builds memory / t_security header).
    # Valid on Linux + macOS; skipped on Windows so a known-limitation red does
    # not mask real regressions.
    SUITES="${SUITES/t_security /}"
    ;;
esac

failed=""
for t in $SUITES; do
  echo "==> test: $t"
  if ! nim c -r --hints:off --colors:off -d:chapulinTest "tests/$t.nim"; then
    failed="$failed $t"
  fi
done
if [ -n "$failed" ]; then
  echo "FAILED suites:$failed"
  exit 1
fi

echo "==> build"
case "$OS" in
  Linux)
    nim c --threads:on -d:withGui -d:release -o:chapulin src/chapulin.nim
    # GTK4 runtime smoke: prove the GUI instantiates on the real backend, not
    # just links. -d:chapulinGuiSmokeQuit opens the window, runs the pump, then
    # self-quits (gui-oyamel-port §5 slice 4).
    echo "==> GTK4 headless runtime smoke"
    nim c --threads:on -d:withGui -d:chapulinGuiSmokeQuit -o:chapulin-gui-smoke src/chapulin.nim
    xvfb-run -a dbus-run-session -- ./chapulin-gui-smoke gui
    ;;
  Darwin)
    # macOS is CLI-only: oyamel has no Cocoa backend yet (gui-oyamel-port §6.0).
    nim c --threads:on -d:release -o:chapulin src/chapulin.nim
    ;;
  MINGW*|MSYS*|CYGWIN*)
    # Windows: MSVC (vcc) -- the Win32 backend's toolchain. config.nims adds
    # -d:oyamelWin32 + -d:oyamelShowConsole under -d:withGui.
    nim c --threads:on --cc:vcc -d:withGui -d:release -o:chapulin.exe src/chapulin.nim
    ;;
  *)
    echo "unknown OS: $OS"; exit 1;;
esac

echo "==> ci.sh OK"
