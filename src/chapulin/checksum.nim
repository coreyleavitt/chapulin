## Checksum sidecar generation — hashes bytes actually delivered to the client.
##
## This module is independent of transfer.nim/server.nim (RFC D1, slice 1.1). It exposes a
## small incremental `Digester` so callers can feed confirmed-delivered bytes as they arrive
## (rather than re-reading the file after the fact, which can race a concurrent truncation —
## see docs/rfc/checksum-integrity-error-hygiene.md D1).

import std/[os, md5]
import server_config
import security

type
  Digester* = ref object
    case mode*: ChecksumMode
    of csNone:
      discard
    of csMd5:
      ctx: MD5Context
    of csSha256:
      discard

proc newDigester*(mode: ChecksumMode): Digester =
  ## csNone → a no-op digester; no MD5Context allocated.
  ## csMd5  → initializes the incremental context.
  ## csSha256 → raises ValueError (unsupported). This is a guard the RRQ path should never hit
  ## (startServer/parseChecksumMode already reject csSha256 at construction), but it fails loud
  ## rather than silently no-op'ing or touching the unallocated `discard` arm.
  case mode
  of csNone:
    result = Digester(mode: csNone)
  of csMd5:
    result = Digester(mode: csMd5)
    md5Init(result.ctx)
  of csSha256:
    raise newException(ValueError, "checksum mode sha256 is not yet implemented")

proc update*(d: Digester, data: openArray[byte]) =
  ## Feeds confirmed-delivered bytes into the digest; no-op for csNone.
  ##
  ## `data.len == 0` MUST be handled as a true no-op before md5Update ever touches the array:
  ## std/md5's internal copyMem step indexes `input[0]` unconditionally, which is out-of-bounds
  ## (IndexDefect, or UB with bound checks off) for a zero-length seq — and every exact-blocksize
  ## -multiple file legitimately sends an empty terminating DATA block.
  case d.mode
  of csNone:
    discard
  of csSha256:
    discard # unreachable: newDigester raises before a Digester in this mode can exist
  of csMd5:
    if data.len == 0:
      return
    md5Update(d.ctx, data)

proc finalize*(d: Digester): string =
  ## PURE: returns the hex digest string for the bytes fed so far. No I/O, and does not mutate
  ## the digester (a copy of the incremental context is finalized), so it is safe to call more
  ## than once or before all data has been fed.
  case d.mode
  of csNone:
    ""
  of csSha256:
    "" # unreachable
  of csMd5:
    var ctxCopy = d.ctx
    var digest: MD5Digest
    md5Final(ctxCopy, digest)
    $digest

proc writeSidecar*(rootDir, resolvedPath, digest: string): tuple[ok: bool, err: string] =
  ## Writes the `.md5` sidecar next to `resolvedPath`. NEVER raises.
  ##
  ## Sidecar text format matches the pre-existing server.nim generateChecksum: `<hexdigest>  <basename>\n`.
  ##
  ## Containment (RFC Ds, fixes defect 4 — reopens the #19 class if skipped):
  ## 1. Delegate to `security.validateWritePath` — the sole containment authority
  ##    — on the sidecar path itself (symlink-aware, fail-closed on OSError).
  ## 2. THEN an independent, UNCONDITIONAL `symlinkExists` refusal: this is
  ##    *additive*, not implied by step 1. `validateWritePath` deliberately
  ##    follows and permits an in-root symlink (correct policy for a served
  ##    file), but the sidecar must refuse a pre-existing symlink at
  ##    `<name>.md5` regardless of where it points — even one that resolves
  ##    in-root — or an attacker-planted in-root symlink silently redirects
  ##    the write to clobber a different in-root file.
  ## 3. Only if both pass, write.
  ##
  ## *Residual TOCTOU:* the symlinkExists-then-writeFile gap below is a
  ## narrow, accepted race — std/os has no portable O_NOFOLLOW|O_EXCL without
  ## FFI (this codebase is FFI-free) — see Invariant 5.
  try:
    let sidecar = resolvedPath & SidecarExt

    let containment = validateWritePath(rootDir, sidecar)
    if not containment.ok:
      return (false, containment.err)

    if symlinkExists(sidecar):
      return (false, "Refusing to write sidecar: symlink present at " & sidecar)

    writeFile(sidecar, digest & "  " & extractFilename(resolvedPath) & "\n")
    (true, "")
  except OSError, IOError:
    (false, getCurrentExceptionMsg())

proc commit*(d: Digester, rootDir, resolvedPath: string): tuple[ok: bool, err: string] =
  ## Facade: no-op success for csNone; otherwise finalize() then writeSidecar() in one call.
  ## NEVER raises (inherits writeSidecar's contract).
  case d.mode
  of csNone:
    (true, "")
  of csSha256:
    (true, "") # unreachable
  of csMd5:
    let digest = d.finalize()
    writeSidecar(rootDir, resolvedPath, digest)
