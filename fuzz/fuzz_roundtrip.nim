## Fuzz target: encode/decode roundtrip
## Structured fuzzing — generates packet-like byte sequences and verifies
## that decode(encode(decode(input))) doesn't crash or lose data.
##
## Build:
##   nim c --mm:arc -d:useMalloc -d:danger -d:nosignalhandler --nomain:on \
##     --cc:clang -t:"-fsanitize=fuzzer,address,undefined" \
##     -l:"-fsanitize=fuzzer,address,undefined" -g \
##     fuzz/fuzz_roundtrip.nim
##
## Run:
##   ./fuzz/fuzz_roundtrip fuzz/corpus/roundtrip/ -max_len=1024 -timeout=5

import ../src/chapulin/protocol

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  if len < 2: return 0
  var payload = newSeq[byte](len)
  copyMem(addr payload[0], data, len)

  # Step 1: decode arbitrary bytes
  var pkt: TftpPacket
  try:
    pkt = decode(payload)
  except TftpDecodeError:
    return 0  # can't decode, skip roundtrip
  except ValueError:
    return 0

  # Step 2: re-encode the decoded packet
  let reencoded = encode(pkt)

  # Step 3: decode the re-encoded bytes — must succeed
  var pkt2: TftpPacket
  try:
    pkt2 = decode(reencoded)
  except:
    doAssert false, "decode(encode(decode(input))) failed: " &
      getCurrentExceptionMsg()

  # Step 4: re-encode again — must produce identical bytes
  let reencoded2 = encode(pkt2)
  doAssert reencoded == reencoded2,
    "encode is not idempotent: encode(decode(encode(decode(x)))) != encode(decode(x))"

  return 0
