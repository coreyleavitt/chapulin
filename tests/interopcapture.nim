## Interop-capture harvest (RFC verification-harness-v2.md §3.3/§5, slice C3).
##
## C3 is two parts:
##
## Part 1 -- capture point (the prereq). §4's hard constraint: A4 is the
## ONLY `src/` production change in the whole v2 RFC, so C3's capture
## mechanism must be test-infra only. The RFC's own §3.3 offers two options
## ("a `tcpdump` sidecar on the interop network, or a chapulin debug hook
## logging raw decoded bytes"); the debug-hook option is a SECOND `src/`
## change and is explicitly declined here as a wrong-spec escalation. This
## slice uses the tcpdump-sidecar option: see `docker-compose.yml`'s
## `pcap-tftp-server` / `pcap-our-server` services (no `src/` touched).
## Confirmed against actual repo state before writing a line of this module
## (per the task's own instruction to verify the RFC's claims, not just
## cite them): `docker-compose.yml` had ONLY functional PASS/FAIL assertion
## scripts before this slice -- the RFC's "no pcap/tcpdump capture exists"
## claim holds exactly.
##
## Part 2 -- harvest (this module). Parse a classic (libpcap, NOT pcapng)
## capture file, extract every raw UDP datagram payload, and deposit each
## as a choice-IR seed through C2's `encodeByteSeqIR` (`./soakseeds.nim`)
## into the SAME `tests/corpus` `directoryBasedDatabase` convention C1/C2
## established -- under a testId distinct from anything a `fuzzProperty`
## call references, reusing C1's `.soak-corpus`/`.soak-crash` lesson
## (`dbReusePhase` batch-prunes any PRIMARY entry that doesn't currently
## falsify; writing non-falsifying growth to a `fuzzProperty`-owned testId
## self-erases on the very next default-suite run -- see
## `soakrunner.nim`'s doc comment for the fuller account of that finding).
##
## --- Why NO port filter (finding, applied) ---------------------------------
## A TFTP request goes to a well-known port (69, or 6969 for our-server's
## configured listen port) but the SERVER's reply comes from a freshly
## allocated per-transfer ephemeral port -- filtering strictly on
## "port == 69/6969" would capture only each transfer's FIRST packet
## (the RRQ/WRQ) and silently drop every DATA/ACK/ERROR that follows on the
## ephemeral port. `extractUdpPayloads` therefore takes every UDP datagram
## in the capture, unfiltered -- the tcpdump sidecar's OWN capture filter
## (`udp`, no port clause; see docker-compose.yml) is what scopes the
## capture to relevant traffic, not a port check here.
##
## --- Why the payload length comes from the UDP header, not the pcap
## record's captured length (finding, applied) -------------------------------
## An Ethernet frame's payload is padded to a 46-byte minimum; a short TFTP
## packet (an RRQ is often well under that) captured over a real Ethernet
## link (the `pcap-tftp-server` sidecar -- a genuinely separate container
## reached over the default bridge network, not a shared network
## namespace) can therefore carry trailing zero-padding the UDP header's
## own 16-bit `length` field does not count. Slicing by the pcap record's
## `incl_len` would hand `encodeByteSeqIR` a byte sequence with junk
## trailing zero bytes appended -- this module slices every payload using
## the UDP header's own `length` field (length - 8 header bytes) instead.
##
## --- Link-type coverage -----------------------------------------------
## This RFC's own two sidecars produce two different pcap link types, both
## handled: `pcap-our-server` runs inside `our-server`'s network namespace
## (`network_mode: "service:our-server"`, the same trick
## `interop-external-client` already uses in docker-compose.yml) -- traffic
## between the shared-namespace atftp client and our-server crosses the
## LOOPBACK interface, which Linux libpcap tags DLT_NULL/DLT_LOOPBACK
## (linktype 0: a 4-byte address-family pseudo-header, no Ethernet framing
## at all). `pcap-tftp-server` is a genuinely separate container reached
## over the default bridge network -- a real Ethernet interface,
## DLT_EN10MB (linktype 1: the standard 14-byte Ethernet header). DLT_LINUX_SLL
## (linktype 113: a `tcpdump -i any` invocation's 16-byte pseudo-header) is
## also handled for robustness, though this RFC's own sidecars pin a
## specific interface rather than `any` (see docker-compose.yml), so 113 is
## not the expected case for either of them today.
##
## --- Provenance / the always-PASS atftp-PUT caveat -------------------------
## `interopCaptureTaggedId`/`interopCaptureUnverifiedTaggedId` below are the
## two provenance channels: seeds from any interop leg with a REAL
## functional pass/fail assertion land under `.interop-capture`; seeds
## harvested from the atftp-PUT leg specifically -- whose own assertion
## (`echo "PASS: PUT completed (exit $$?)"`) reports `echo`'s exit code, not
## atftp's, and therefore ALWAYS prints PASS regardless of whether the
## transfer actually succeeded -- land under `.interop-capture-unverified`,
## so a later triage never conflates "this shape was seen on a verified
## leg" with "this shape was merely seen."
##
## --- Manual harvest entry point (opt-in, NOT part of the default suite) ----
## `when isMainModule`, below: given a real captured `.pcap` file (produced
## by actually running the sidecars against a live `docker compose up` of
## the interop stack), harvest it into the REAL `tests/corpus`. This step
## is inherently opt-in/manual, the same way C1's `-Soak` mode is: it needs
## the interop compose stack up, which this module cannot assume.
##
##   nim c -r tests/interopcapture.nim <pcap-path> <testId-base> [unverified]

import nelli
import ./soakseeds  # encodeByteSeqIR (C2)
import ./fuzzsupport  # CorpusSizeCeiling (C4)

const
  LtEthernet = 1
  LtNull = 0
  LtLinuxSll = 113

proc readU16be(s: openArray[byte], off: int): int =
  (int(s[off]) shl 8) or int(s[off + 1])

proc readU32le(s: openArray[byte], off: int): uint32 =
  uint32(s[off]) or (uint32(s[off + 1]) shl 8) or
    (uint32(s[off + 2]) shl 16) or (uint32(s[off + 3]) shl 24)

proc stringToBytes*(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len: result[i] = byte(s[i])

proc extractUdpPayloads*(pcapBytes: openArray[byte]):
    tuple[payloads: seq[seq[byte]], unconsumedBytes: int] =
  ## Parse a classic (non-pcapng) little-endian pcap capture and return
  ## every UDP datagram's payload, in file order, alongside
  ## `unconsumedBytes`: the number of trailing bytes of `pcapBytes` left
  ## once the record-parsing loop stopped. See the module doc comment for
  ## why there's no port filter and why the UDP header's own length field
  ## (not the pcap record's captured length) determines the payload slice.
  ##
  ## ANY record the parser cannot make sense of -- a truncated trailing
  ## record header, or a record whose `incl_len` claims more bytes than
  ## remain in the buffer, whether that's genuine trailing truncation (a
  ## sidecar killed mid-write) or mid-stream corruption -- halts parsing at
  ## that record; the function returns only the payloads decoded so far.
  ## `unconsumedBytes > 0` makes that observable: it's the record-parsing
  ## loop's leftover byte count. This parser does NOT attempt to resync
  ## past a corrupt `incl_len` -- classic pcap records are self-delimiting
  ## only via `incl_len`, so once one is wrong the next record boundary is
  ## genuinely unrecoverable; a bad length could just as easily land
  ## mid-buffer as at the end, silently discarding every record after it,
  ## which is exactly why callers must not treat `unconsumedBytes` as
  ## always meaning "trailing junk, safe to ignore."
  ##
  ## A buffer too short to hold a global header, or one whose magic isn't
  ## classic little-endian pcap (`0xa1b2c3d4` -- e.g. a pcapng or
  ## big-endian capture), is a distinct, pre-loop failure mode: it returns
  ## an empty payload set with `unconsumedBytes == 0` (never asserts/raises
  ## -- this parser consumes attacker/third-party `.pcap` files and must
  ## degrade gracefully on any input shape it doesn't understand).
  var payloads: seq[seq[byte]] = @[]
  if pcapBytes.len < 24: return (payloads, 0)
  let magic = readU32le(pcapBytes, 0)
  if magic != 0xa1b2c3d4'u32: return (payloads, 0)  # not classic LE pcap (pcapng/BE/garbage) -- skip, don't raise
  let linktype = int(readU32le(pcapBytes, 20))
  var pos = 24
  while pos + 16 <= pcapBytes.len:
    let inclLen = int(readU32le(pcapBytes, pos + 8))
    pos += 16
    if inclLen < 0 or pos + inclLen > pcapBytes.len: break
    let recEnd = pos + inclLen
    var ipOff = -1
    case linktype
    of LtEthernet:
      if inclLen >= 14 and readU16be(pcapBytes, pos + 12) == 0x0800:
        ipOff = pos + 14
    of LtNull:
      if inclLen >= 4:
        ipOff = pos + 4
        # No address-family check: IPv6-over-loopback is out of scope for
        # this TFTP-over-IPv4 harness. A non-IPv4 packet simply fails the
        # IPv4-header sanity checks below and is skipped, not mis-parsed.
    of LtLinuxSll:
      if inclLen >= 16 and readU16be(pcapBytes, pos + 14) == 0x0800:
        ipOff = pos + 16
    else:
      discard  # unrecognized linktype: skip this record, don't abort the capture
    if ipOff >= 0 and ipOff + 20 <= recEnd:
      let verIhl = int(pcapBytes[ipOff])
      let ihl = (verIhl and 0x0F) * 4
      let proto = int(pcapBytes[ipOff + 9])
      if (verIhl shr 4) == 4 and ihl >= 20 and proto == 17 and
         ipOff + ihl + 8 <= recEnd:
        let udpOff = ipOff + ihl
        let udpLen = readU16be(pcapBytes, udpOff + 4)
        let payloadLen = udpLen - 8
        if payloadLen >= 0 and udpOff + 8 + payloadLen <= recEnd:
          var payload = newSeq[byte](payloadLen)
          for i in 0 ..< payloadLen: payload[i] = pcapBytes[udpOff + 8 + i]
          payloads.add payload
    pos = recEnd
  let unconsumed = pcapBytes.len - pos
  if unconsumed > 0:
    # L3: the loop above stopped before reaching the end of the buffer --
    # either a truncated trailing record header (`pos + 16 > len`) or a
    # record whose `incl_len` overran the buffer (the `break` above). Either
    # way, every record from `pos` onward -- possibly many intact ones, if
    # this was mid-stream corruption rather than trailing truncation -- is
    # now unrecoverably lost (see the doc comment above: `incl_len` is the
    # only record delimiter, so a corrupt one cannot be resynced past).
    # Surfaced here, not silently swallowed, so a caller (including the
    # `when isMainModule` harvest CLI below, which routes through this proc
    # via `harvestPcapFile`/`harvestPcapBytes`) always sees it.
    stderr.writeLine "extractUdpPayloads: stopped early: " & $unconsumed &
      " unconsumed byte(s) at offset " & $pos &
      " -- remaining record(s), if any, are unrecoverable"
  (payloads, unconsumed)

proc interopCaptureTaggedId*(base: string): string =
  ## Provenance-tag convention (mirrors `soakrunner.nim`'s
  ## `.soak-corpus`/`.soak-crash` testId-suffix convention and
  ## `fuzzsupport.nim`'s `osTaggedId`, rather than inventing a third
  ## tagging channel) for seeds harvested from an interop leg with a real
  ## functional pass/fail assertion.
  base & ".interop-capture"

proc interopCaptureUnverifiedTaggedId*(base: string): string =
  ## Provenance tag for seeds harvested from the atftp-PUT leg specifically
  ## -- see the module doc comment's "always-PASS caveat" section. Carries
  ## wire SHAPE only, not a correctness guarantee.
  base & ".interop-capture-unverified"

proc harvestPcapBytes*(db: ExampleDatabase, pcapBytes: openArray[byte],
                       testId: string, maxEntries = CorpusSizeCeiling): int =
  ## Extract every UDP payload from `pcapBytes` and deposit each as a
  ## choice-IR seed (via C2's `encodeByteSeqIR`) under `testId`. Returns the
  ## number of payloads harvested (0 is a valid, non-error result -- an
  ## empty or entirely-irrelevant capture). If parsing stopped early (see
  ## `extractUdpPayloads`'s doc comment), that's already surfaced to stderr
  ## by `extractUdpPayloads` itself -- this proc still deposits whatever
  ## payloads it did decode rather than discarding them.
  let (payloads, _) = extractUdpPayloads(pcapBytes)
  for payload in payloads:
    db.save(testId, encodeByteSeqIR(payload), maxEntries = maxEntries)
  payloads.len

proc harvestPcapFile*(dbPath, pcapPath, testId: string, maxEntries = CorpusSizeCeiling): int =
  ## Same as `harvestPcapBytes`, reading the capture from disk and opening
  ## `dbPath` as a `directoryBasedDatabase` -- the shape the manual CLI
  ## entry point below and any future real-capture harvest call.
  let db = directoryBasedDatabase(dbPath)
  harvestPcapBytes(db, stringToBytes(readFile(pcapPath)), testId, maxEntries)

when isMainModule:
  ## Manual, opt-in harvest of a REAL captured `.pcap` file into the real
  ## `tests/corpus` -- NOT invoked by `scripts/dev-test.ps1`'s default
  ## suite (that suite's own proof, `t_interop_capture.nim`, uses a
  ## disposable tmp database and a representative in-memory sample; see its
  ## own doc comment for why). Run this only after actually bringing up the
  ## interop compose stack with the two tcpdump sidecars and copying their
  ## `.pcap` output out of the bind-mounted `./interop-captures/` directory.
  import std/os
  if paramCount() < 2:
    echo "usage: interopcapture <pcap-path> <testId-base> [unverified]"
    quit 1
  let pcapPath = paramStr(1)
  let base = paramStr(2)
  let unverified = paramCount() >= 3 and paramStr(3) == "unverified"
  let testId = if unverified: interopCaptureUnverifiedTaggedId(base)
               else: interopCaptureTaggedId(base)
  let n = harvestPcapFile(CorpusDir, pcapPath, testId)
  echo "==> harvested " & $n & " packet(s) from " & pcapPath &
       " into tests/corpus/" & testId & ".bin" &
       (if unverified: " (origin: interop-capture, UNVERIFIED -- atftp-PUT leg)"
        else: " (origin: interop-capture)")
