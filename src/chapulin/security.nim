## TFTP server security — path validation, write access, host access control.

import std/os
import std/strutils
import protocol
import server_config

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

proc canonicalize(path: string): string =
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
  # the link target via WRQ). Resolve the real path of the target (and, for
  # a not-yet-existing WRQ-create target, its existing parent chain) and
  # re-assert containment within the real root. Best-effort on Windows,
  # where expandFilename does not fully resolve symlinks/junctions; the
  # lexical and `..` checks remain the primary guard there.
  try:
    let realRoot = expandFilename(normalizedRoot)
    let realTarget = canonicalize(resolved)
    if not isWithin(realTarget, realRoot):
      return (false, "", "Path escapes root directory (symlink)")
  except OSError:
    # Could not resolve the real path (unresolvable root, dangling symlink,
    # permission error, or a TOCTOU race). Fail closed rather than serve a
    # path whose containment we cannot verify.
    return (false, "", "Cannot resolve path")

  return (true, resolved, "")

proc checkWriteAccess*(config: ServerConfig, resolvedPath: string): tuple[
    ok: bool, errCode: TftpErrorCode, err: string] =
  ## Check if writing to resolvedPath is allowed per the server's write policy.
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
