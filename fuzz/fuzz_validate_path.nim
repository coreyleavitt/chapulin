## Fuzz target: security.nim validatePath()
## Must never resolve outside root directory.
##
## Build:
##   nim c --mm:arc -d:useMalloc -d:danger -d:nosignalhandler --nomain:on \
##     --cc:clang -t:"-fsanitize=fuzzer,address,undefined" \
##     -l:"-fsanitize=fuzzer,address,undefined" -g \
##     fuzz/fuzz_validate_path.nim
##
## Run:
##   ./fuzz/fuzz_validate_path fuzz/corpus/validate_path/ -max_len=256 -timeout=5

import ../src/chapulin/protocol
import ../src/chapulin/server_config
import ../src/chapulin/security
import std/os

const testRoot = "/tmp/fuzz_tftp_root"

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}
  createDir(testRoot)
  createDir(testRoot / "subdir")

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  if len == 0: return 0
  var filename = newString(len)
  copyMem(addr filename[0], data, len)
  try:
    let (valid, resolved, err) = validatePath(testRoot, filename)
    if valid:
      # Invariant: resolved must always be under testRoot
      let absRoot = absolutePath(testRoot)
      doAssert resolved.startsWith(absRoot),
        "Path escaped root! filename=" & filename & " resolved=" & resolved
  except:
    discard
  return 0
