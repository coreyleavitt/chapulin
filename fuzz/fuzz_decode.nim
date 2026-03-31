## Fuzz target: protocol.nim decode()
## Primary attack surface — parses untrusted UDP packet bytes.
##
## Build:
##   nim c --mm:arc -d:useMalloc -d:danger -d:nosignalhandler --nomain:on \
##     --cc:clang -t:"-fsanitize=fuzzer,address,undefined" \
##     -l:"-fsanitize=fuzzer,address,undefined" -g \
##     fuzz/fuzz_decode.nim
##
## Run:
##   ./fuzz/fuzz_decode fuzz/corpus/decode/ -max_len=576 -timeout=5
##
## Replay crash:
##   nim c --mm:arc -d:fuzzReplay -d:nosignalhandler -d:danger fuzz/fuzz_decode.nim
##   ./fuzz/fuzz_decode crash-*

import ../src/chapulin/protocol

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  if len < 2: return 0
  var payload = newSeq[byte](len)
  copyMem(addr payload[0], data, len)
  try:
    discard decode(payload)
  except TftpDecodeError:
    discard
  except ValueError:
    discard
  return 0

when defined(fuzzReplay):
  import std/os
  proc main() =
    {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}
    for i in 1 ..< paramCount() + 1:
      let data = readFile(paramStr(i))
      var bytes = newSeq[byte](data.len)
      if data.len > 0:
        copyMem(addr bytes[0], unsafeAddr data[0], data.len)
      discard testOneInput(cast[ptr UncheckedArray[byte]](addr bytes[0]), bytes.len)
      echo "OK: " & paramStr(i)
  main()
