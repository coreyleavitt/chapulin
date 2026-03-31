## Fuzz target: options.nim parseOackOptions()
## Attacker-controlled option values from network OACK packets.
##
## Build:
##   nim c --mm:arc -d:useMalloc -d:danger -d:nosignalhandler --nomain:on \
##     --cc:clang -t:"-fsanitize=fuzzer,address,undefined" \
##     -l:"-fsanitize=fuzzer,address,undefined" -g \
##     fuzz/fuzz_parse_options.nim
##
## Run:
##   ./fuzz/fuzz_parse_options fuzz/corpus/parse_options/ -max_len=512 -timeout=5

import ../src/chapulin/protocol
import ../src/chapulin/transfer
import ../src/chapulin/options

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  if len < 4: return 0
  # Interpret fuzz input as null-terminated key-value pairs (like OACK wire format)
  var payload = newSeq[byte](len)
  copyMem(addr payload[0], data, len)
  # Parse as raw OACK — build option pairs from null-separated strings
  var opts: seq[(string, string)]
  var i = 0
  var strings: seq[string]
  var current = ""
  while i < len:
    if payload[i] == 0:
      strings.add current
      current = ""
    else:
      current.add char(payload[i])
    i.inc
  if current.len > 0:
    strings.add current
  # Pair up strings as key-value
  var j = 0
  while j + 1 < strings.len:
    opts.add (strings[j], strings[j+1])
    j += 2
  try:
    discard parseOackOptions(opts)
  except ValueError:
    discard
  return 0
