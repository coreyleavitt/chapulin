## Fuzz target: tftp_uri.nim parseTftpUri()
## URI parsing from user input — IPv6 brackets, port extraction.
##
## Build:
##   nim c --mm:arc -d:useMalloc -d:danger -d:nosignalhandler --nomain:on \
##     --cc:clang -t:"-fsanitize=fuzzer,address,undefined" \
##     -l:"-fsanitize=fuzzer,address,undefined" -g \
##     fuzz/fuzz_parse_uri.nim
##
## Run:
##   ./fuzz/fuzz_parse_uri fuzz/corpus/parse_uri/ -max_len=512 -timeout=5

import ../src/chapulin/tftp_uri

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  if len == 0: return 0
  var input = newString(len)
  copyMem(addr input[0], data, len)
  try:
    let uri = parseTftpUri(input)
    # Invariants if parsing succeeded
    doAssert uri.host.len > 0
    doAssert uri.port > 0
    doAssert uri.filename.len > 0
    doAssert uri.mode in ["octet", "netascii"]
  except TftpUriError:
    discard
  except ValueError:
    discard
  return 0
