## TFTP server security — path validation, write access, host access control.

import std/os
import std/strutils
import protocol
import server_config

const SidecarExt* = ".md5"
  ## The server-owned checksum sidecar suffix (RFC checksum-integrity-error-
  ## hygiene, Ds, defect 5 / Invariant 6). The single source of truth for the
  ## reserved suffix — checksum.nim's writeSidecar and this module's
  ## checkWriteAccess/isReservedSidecarName must never hardcode ".md5"
  ## independently (M2), or the two sites can silently drift apart.

proc isReservedSidecarName*(path: string): bool =
  ## True if `path`'s final path component names a reserved checksum
  ## sidecar. Shared authority for "is this a `.md5` name" so the rule
  ## cannot drift between call sites (M2): checkWriteAccess (WRQ target
  ## rejection, H1/M5) and handleRrq (skip generating a sidecar-of-a-
  ## sidecar, M1) both defer to this single predicate.
  ##
  ## Normalizes two ways before comparing:
  ## - lowercases (Windows filesystems are case-insensitive; a case-
  ##   sensitive check would leave `.MD5` as a bypass).
  ## - strips trailing dots/spaces from the basename (M5): Windows'
  ##   CreateFileW silently drops a trailing '.' or ' ' from the final
  ##   path component, so "name.md5." or "name.md5 " opens "name.md5" on
  ##   disk even though a plain string endsWith(".md5") test on the
  ##   untrimmed name would say no.
  let name = extractFilename(path).strip(leading = false, trailing = true,
                                          chars = {'.', ' '})
  name.toLowerAscii.endsWith(SidecarExt)

proc isWithin(child, parent: string): bool =
  ## True if `child` is `parent` itself or a path nested beneath it.
  ## Uses a separator-aware boundary so `/root/evil` is not treated as
  ## being within `/rootfoo` (a naive startsWith prefix match would).
  if child == parent:
    return true
  var p = parent
  if p.len > 0 and p[^1] != DirSep and p[^1] != AltSep:
    p.add(DirSep)
  return child.startsWith(p)

proc canonicalize*(path: string): string =
  ## Resolve symlinks in `path` (realpath semantics), tolerating a
  ## non-existent leaf/tail: resolve the deepest existing ancestor and
  ## re-append the remaining components. Lets us canonicalize a WRQ-create
  ## target whose file does not exist yet while still resolving any symlink
  ## in its existing parent chain. May raise OSError if resolution fails.
  var existing = path
  var tail: seq[string]
  while existing.len > 0 and not fileExists(existing) and
        not dirExists(existing) and not symlinkExists(existing):
    let (parent, name) = splitPath(existing)
    if name.len == 0 or parent == existing:
      break
    tail.add(name)
    existing = parent
  if existing.len == 0:
    return path
  result = expandFilename(existing)
  for i in countdown(tail.high, 0):
    result = result / tail[i]

proc hasReparseComponent(rootDir, absPath: string): bool =
  ## True if any path component of `absPath`, walking up from the leaf
  ## toward (but never including) `rootDir`, is a reparse point — a
  ## symlink OR a junction. Both `rootDir` and `absPath` must already be
  ## normalized (e.g. via `absolutePath`) and `absPath` must be lexically
  ## within `rootDir`, so the ancestor walk reaches `rootDir` exactly.
  ##
  ## K1 (Windows): `expandFilename` (thus `canonicalize`/`validateWritePath`)
  ## does not resolve symlinks OR junctions on Windows — it is purely
  ## lexical there. A junction (no privilege required to create, unlike a
  ## symlink) planted inside the served root that points outside it passes
  ## the lexical `isWithin` check and the OS transparently follows it on
  ## open(), enabling arbitrary read (RRQ) / overwrite (WRQ) outside root.
  ##
  ## Resolving *where* a reparse point leads needs FFI on Windows (no
  ## `std/os` primitive does it). Instead, refuse to traverse through one
  ## at all: `symlinkExists` detects the generic `FILE_ATTRIBUTE_REPARSE_
  ## POINT` bit, which both symlinks and junctions set, FFI-free. If no
  ## component between the leaf and the root is a reparse point, the
  ## lexical path already IS the real path — `isWithin` is exact and there
  ## is nothing left to escape through.
  ##
  ## A not-yet-existing leaf (a WRQ-create target) cannot itself be a
  ## reparse point — `symlinkExists` is false for a path that does not
  ## exist at all — so the walk simply climbs past it to its parent. A
  ## DANGLING symlink/junction leaf (`symlinkExists` true even though
  ## the target is gone) is still caught, because the check is purely
  ## "is this component itself a reparse point," never "does it resolve."
  ##
  ## The stop condition tolerates a trailing separator on `rootDir`
  ## (e.g. a served root configured as `C:\tftpboot\` — an ordinary way to
  ## type it, and callers do not trim it). `absolutePath` does not strip a
  ## trailing separator, but `splitPath`'s climb (via `rootDir / name`
  ## upstream) does, so a raw string `!=` against an untrimmed `rootDir`
  ## would never match at the true root and the walk would climb PAST it —
  ## checking rootDir itself, then its parent, etc. That over-climb is
  ## harmless unless the served root itself sits on a reparse point (a
  ## container bind mount, DFS namespace, OneDrive, or storage-tiering
  ## volume — all ordinary on Windows), in which case `symlinkExists(root)`
  ## fires and EVERY request is falsely rejected: a total outage. Stripping
  ## the trailing separator before comparing keeps the walk's own "never
  ## including rootDir" contract regardless of how rootDir was spelled.
  let stopAt = rootDir.strip(leading = false, trailing = true,
                              chars = {DirSep, AltSep})
  var current = absPath
  while current.len > 0 and current != stopAt:
    if symlinkExists(current):
      return true
    let (parent, name) = splitPath(current)
    if name.len == 0 or parent == current:
      break
    current = parent
  return false

proc validateWritePath*(rootDir, absPath: string): tuple[ok: bool, err: string] =
  ## Re-assert containment of an arbitrary absolute target path against
  ## `rootDir`, resolving symlinks (issue #19's real-path check, generalized
  ## beyond the RRQ/WRQ `resolved` path so other writers — e.g. the checksum
  ## sidecar — can reuse the same authority). Best-effort on Windows, where
  ## expandFilename does not fully resolve symlinks/junctions.
  ##
  ## This is the module's SOLE containment authority: `validatePath` (RRQ +
  ## WRQ) and `checksum.writeSidecar` (sidecar re-assertion at write time)
  ## both delegate here instead of each rolling their own check, so every
  ## caller gets identical protection. Two layers, both needed, deliberately
  ## not merged into one walk (K1):
  ##   1. Reparse-point refusal (Windows only, `hasReparseComponent`):
  ##      `expandFilename`/`canonicalize` below do not resolve symlinks OR
  ##      junctions on Windows, so a reparse point planted in the tree that
  ##      leads outside it would pass layer 2's realpath check unchanged.
  ##      This layer instead refuses to traverse through ANY reparse point
  ##      at all (see hasReparseComponent's doc comment for why it can't
  ##      instead resolve where the reparse point leads: that needs FFI).
  ##   2. Realpath containment (`canonicalize` + `isWithin`, all
  ##      platforms), fail-closed on `OSError`. This is the general #19
  ##      real-path re-check and remains the primary guard on POSIX, where
  ##      `expandFilename` IS realpath and layer 1 is a no-op.
  when defined(windows):
    if hasReparseComponent(absolutePath(rootDir), absPath):
      return (false, "Path escapes root directory")

  try:
    let realRoot = expandFilename(absolutePath(rootDir))
    let realTarget = canonicalize(absPath)
    if not isWithin(realTarget, realRoot):
      return (false, "Path escapes root directory (symlink)")
  except OSError:
    # Could not resolve the real path (unresolvable root, dangling symlink,
    # permission error, or a TOCTOU race). Fail closed rather than serve a
    # path whose containment we cannot verify.
    return (false, "Cannot resolve path")

  return (true, "")

proc validatePath*(rootDir: string, filename: string): tuple[
    valid: bool, resolved: string, err: string] =
  ## Validate a requested filename is safe and resolves within rootDir.
  ## Returns the resolved absolute path if valid.
  if filename.len == 0:
    return (false, "", "Empty filename")

  if '\0' in filename:
    return (false, "", "Null byte in filename")

  # Virtual root: strip leading path separators (PXE clients send /tftpboot/file)
  var cleanName = filename
  cleanName = cleanName.strip(chars = {'/', '\\'}, trailing = false)
  # Normalize backslashes to forward slashes
  cleanName = cleanName.replace('\\', '/')

  if ".." in cleanName:
    return (false, "", "Path traversal not allowed")

  # Windows NTFS Alternate Data Streams (round-3 code-review fix 2): a name
  # like "data.bin.md5::$DATA" (or "data.bin.md5:$DATA", or any "name:stream"
  # form) does not end in ".md5" -- isReservedSidecarName's suffix check
  # never fires -- but Windows' open(..., fmWrite) resolves the
  # stream-qualified name to the real "data.bin.md5"'s default data stream,
  # forging/overwriting a server-owned sidecar (defeats Invariant 6). This is
  # a different bypass class from the #19 symlink one: no symlink is
  # involved, just NTFS's colon-delimited stream syntax (which also covers
  # drive-relative "C:foo"). ':' is not a legal filename character on
  # Windows at all, so rejecting it here closes the whole class at the
  # shared RRQ+WRQ entry gate. Scoped to Windows only: ':' is a legal POSIX
  # filename character and there is no ADS concept there.
  when defined(windows):
    if ':' in cleanName:
      return (false, "", "Invalid character in filename")

  if cleanName.len == 0:
    return (false, "", "Empty filename after path normalization")

  let resolved = absolutePath(rootDir / cleanName)
  let normalizedRoot = absolutePath(rootDir)

  # Lexical containment: the requested path is textually under the root.
  if not isWithin(resolved, normalizedRoot):
    return (false, "", "Path escapes root directory")

  # Symlink containment (issue #19): the lexical check above is purely
  # textual and does not follow symlinks. A symlink planted inside the root
  # that points outside it passes the lexical check, and the subsequent
  # open() would follow it (arbitrary read via RRQ; arbitrary overwrite of
  # the link target via WRQ). validateWritePath below is the module's sole
  # containment authority and re-asserts containment against the real path
  # (symlink/junction-resolved as far as FFI-free Windows APIs allow) — see
  # its doc comment for the two-layer defense (K1: Windows reparse-point
  # refusal via hasReparseComponent, then realpath containment). Routing
  # through the one authority here means RRQ, WRQ, and the checksum
  # sidecar (checksum.writeSidecar, which also calls validateWritePath
  # directly) all get identical protection — none can drift out of sync.
  let writeCheck = validateWritePath(normalizedRoot, resolved)
  if not writeCheck.ok:
    return (false, "", writeCheck.err)

  return (true, resolved, "")

proc checkWriteAccess*(config: ServerConfig, resolvedPath: string): tuple[
    ok: bool, errCode: TftpErrorCode, err: string] =
  ## Check if writing to resolvedPath is allowed per the server's write policy.
  ##
  ## Reserved `.md5` namespace (RFC checksum-integrity-error-hygiene, Ds,
  ## defect 5): once the server generates checksum sidecars, `<name>.md5` is
  ## a server-owned pseudo-name — exactly as `dirListFile` is reserved. No
  ## client WRQ may create, overwrite, or forge one. Gated on
  ## `checksumMode != csNone` (the suffix is unreserved while checksums are
  ## off). Checked before the policy switch below so it applies uniformly
  ## under every non-wpDeny policy (wpDeny already rejects everything).
  ##
  ## Checked against BOTH the lexical `resolvedPath` and its canonicalized
  ## real path (H1): `resolvedPath` is the LEXICAL path returned by
  ## validatePath, which follows an in-root symlink for containment
  ## purposes but returns the alias's own (non-`.md5`) name. An in-root
  ## symlink `alias -> legit.md5` would then pass the lexical check while
  ## `open(resolvedPath, fmWrite)` has the OS follow the symlink and
  ## overwrite legit.md5. Canonicalizing resolves the symlink to its real
  ## target and re-tests the reservation against that. canonicalize may
  ## raise OSError (unresolvable path, dangling symlink, permission error,
  ## TOCTOU race) — on failure we fall back to the lexical result alone
  ## rather than failing the whole write open just because the real-path
  ## probe didn't succeed. Best-effort on Windows, where expandFilename
  ## does not resolve symlinks/junctions (accepted limit, matches
  ## validateWritePath's existing best-effort documentation).
  if config.checksumMode != csNone:
    var reserved = isReservedSidecarName(resolvedPath)
    if not reserved:
      try:
        reserved = isReservedSidecarName(canonicalize(resolvedPath))
      except OSError:
        discard
    if reserved:
      return (false, errAccessViolation, "Reserved filename")

  let exists = fileExists(resolvedPath)

  case config.writePolicy
  of wpDeny:
    return (false, errAccessViolation, "Server is read-only")
  of wpCreateOnly:
    if exists:
      return (false, errFileAlreadyExists, "File already exists")
    return (true, errNotDefined, "")
  of wpOverwrite:
    if not exists:
      return (false, errFileNotFound, "File does not exist (overwrite-only mode)")
    return (true, errNotDefined, "")
  of wpCreateOrOverwrite:
    return (true, errNotDefined, "")

proc checkHostAccess*(config: ServerConfig, clientHost: string): bool =
  ## Check if a client host is allowed to connect.
  ## Denylist takes precedence. Empty allowlist means allow all.
  if clientHost in config.deniedHosts:
    return false
  if config.allowedHosts.len > 0:
    return clientHost in config.allowedHosts
  return true
