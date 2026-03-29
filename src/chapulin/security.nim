## TFTP server security — path validation, write access, host access control.

import std/os
import std/strutils
import protocol
import server_config

proc validatePath*(rootDir: string, filename: string): tuple[
    valid: bool, resolved: string, err: string] =
  ## Validate a requested filename is safe and resolves within rootDir.
  ## Returns the resolved absolute path if valid.
  if filename.len == 0:
    return (false, "", "Empty filename")

  if '\0' in filename:
    return (false, "", "Null byte in filename")

  if filename.startsWith("/") or filename.startsWith("\\"):
    return (false, "", "Absolute path not allowed")

  if ".." in filename:
    return (false, "", "Path traversal not allowed")

  if '\\' in filename:
    return (false, "", "Backslash in filename not allowed")

  let resolved = absolutePath(rootDir / filename)
  let normalizedRoot = absolutePath(rootDir)

  # Verify the resolved path is still under the root
  if not resolved.startsWith(normalizedRoot):
    return (false, "", "Path escapes root directory")

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
