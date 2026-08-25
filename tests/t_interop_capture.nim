## C3 interop-capture harvest: proof the pipeline works (RFC
## verification-harness-v2.md §3.3/§5, slice C3).
##
## --- Honest scope (read this before anything else) -------------------------
## The interop docker-compose stack (`pghalliday/tftp`, `opensuse/tumbleweed`)
## is Linux-only; this repo's toolchain images are pinned multi-platform but
## the CAPTURE mechanism this slice adds (`docker-compose.yml`'s
## `pcap-tftp-server`/`pcap-our-server` tcpdump sidecars) needs Linux
## containers to run at all. Confirmed empirically in THIS environment:
## `docker info --format '{{.OSType}}'` reports `windows` (Docker Desktop is
## in Windows-container mode here), and `docker pull pghalliday/tftp` fails
## outright with `image operating system "linux" cannot be used on this
## platform`. So a LIVE capture cannot be exercised in this session --
## per the task's own "honest scope-down, not a blocker" instruction (same
## class as B1's honest scope-downs), this suite proves the harvest
## mechanism (parse -> encodeByteSeqIR -> corpus, with provenance tagging
## and round-trip-through-the-actual-strategy proof, per C2's discipline)
## against a REPRESENTATIVE in-memory sample -- realistic TFTP wire bytes
## (built via the real `protocol.encode`, never hand-derived) wrapped in
## hand-built-but-standards-conformant pcap/Ethernet/IP/UDP framing -- NOT a
## faked "capture happened" claim. This suite never touches the real
## `tests/corpus/` directory (a disposable tmp `directoryBasedDatabase`,
## same pattern `t_corpus.nim`'s synthetic-entry test already uses) --
## depositing synthetic packets under an `interop-capture` provenance tag
## in the REAL committed corpus would misrepresent them as a genuine
## capture, which the task explicitly says not to do.
##
## Once the interop stack IS run somewhere with Linux containers available
## (a plain `docker compose up --build tftp-server integration-client
## pcap-tftp-server` / `... our-server interop-external-client
## pcap-our-server`, see docker-compose.yml's comments), the exact same
## `harvestPcapFile` this suite proves is invoked manually against the
## resulting `.pcap` file(s) via `interopcapture.nim`'s `when isMainModule`
## entry point, depositing real seeds into the real `tests/corpus/` --
## that step is inherently opt-in/manual (needs the compose stack up), the
## same way C1's `-Soak` mode is manual, so it is NOT part of this default
## suite. See `interopcapture.nim`'s module doc comment for the full
## capture-mechanism + provenance-convention writeup.
##
## Fast + deterministic (pure byte-construction + in-memory parsing, no
## Docker, no z3) -- registered in `scripts/dev-test.ps1`'s default `$tests`
## array, same judgment call `t_soak_encoder.nim` (C2) already recorded for
## itself: this is exactly the shape of every other cheap unit suite in
## that list, not a fuzz/soak/interop-stack-dependent target.
##
## Run:
##   pwsh scripts/dev-test.ps1 -Only @('t_interop_capture')

import std/[unittest, os]
import nelli
import nelli/datasource
import ../src/chapulin/protocol
import ./interopcapture
import ./fuzzsupport

# --- minimal pcap/Ethernet/IP/UDP builders (test-only; mirror what a real
# tcpdump-produced capture looks like on the wire, byte for byte) -----------

proc u16be(v: int): seq[byte] =
  @[byte((v shr 8) and 0xFF), byte(v and 0xFF)]

proc u32le(v: uint32): seq[byte] =
  @[byte(v and 0xFF), byte((v shr 8) and 0xFF),
    byte((v shr 16) and 0xFF), byte((v shr 24) and 0xFF)]

proc u16le(v: int): seq[byte] =
  @[byte(v and 0xFF), byte((v shr 8) and 0xFF)]

proc mkGlobalHeader(linktype: uint32): seq[byte] =
  result = u32le(0xa1b2c3d4'u32)
  result.add u16le(2)
  result.add u16le(4)
  result.add u32le(0'u32)
  result.add u32le(0'u32)
  result.add u32le(65535'u32)
  result.add u32le(linktype)

proc mkIpv4Udp(payload: seq[byte], srcPort, dstPort: int): seq[byte] =
  ## A minimal (no-options) IPv4 header wrapping a UDP datagram. Header/UDP
  ## checksums are left as 0 -- `extractUdpPayloads` never validates them
  ## (a real tcpdump-produced capture's checksums are real, but this parser
  ## doesn't need them to be for its own job: locating the payload).
  let udpLen = 8 + payload.len
  var udp = u16be(srcPort)
  udp.add u16be(dstPort)
  udp.add u16be(udpLen)
  udp.add u16be(0)
  udp.add payload

  let totalLen = 20 + udp.len
  var ip = @[byte(0x45), byte(0)]
  ip.add u16be(totalLen)
  ip.add u16be(0)
  ip.add u16be(0)
  ip.add @[byte(64), byte(17)]  # TTL=64, protocol=UDP
  ip.add u16be(0)               # header checksum
  ip.add @[byte(127), byte(0), byte(0), byte(1)]  # src 127.0.0.1
  ip.add @[byte(127), byte(0), byte(0), byte(1)]  # dst 127.0.0.1
  ip.add udp
  ip

proc wrapEthernet(ipPacket: seq[byte], padTo = 0): seq[byte] =
  ## linktype 1 -- a genuinely separate container over the default bridge
  ## network (`pcap-tftp-server`'s expected capture shape).
  result = newSeq[byte](12)  # dst mac + src mac, zeroed (irrelevant to the parser)
  result.add u16be(0x0800)
  result.add ipPacket
  while result.len < padTo: result.add byte(0)  # Ethernet minimum-frame padding

proc wrapLoopback(ipPacket: seq[byte]): seq[byte] =
  ## linktype 0 (DLT_NULL) -- a shared network namespace
  ## (`network_mode: "service:our-server"`), traffic crosses loopback
  ## (`pcap-our-server`'s expected capture shape). 4-byte address-family
  ## pseudo-header, AF_INET=2, host byte order (little-endian on the x86
  ## Linux hosts this RFC's sidecars run on).
  result = u32le(2'u32)
  result.add ipPacket

proc mkPcapRecord(frame: seq[byte]): seq[byte] =
  result = u32le(0'u32)  # ts_sec
  result.add u32le(0'u32)  # ts_usec
  result.add u32le(uint32(frame.len))  # incl_len
  result.add u32le(uint32(frame.len))  # orig_len
  result.add frame

proc mkPcap(linktype: uint32, frames: seq[seq[byte]]): seq[byte] =
  result = mkGlobalHeader(linktype)
  for f in frames: result.add mkPcapRecord(f)

suite "C3 interop-capture harvest: parse -> encodeByteSeqIR -> corpus":

  test "extractUdpPayloads: loopback linktype (pcap-our-server shape), no port filter":
    ## Three real TFTP packets over one Wire-shaped exchange: RRQ (client
    ## ephemeral 51000 -> well-known 6969), DATA reply (server's
    ## PER-TRANSFER ephemeral 6970 -- NOT 6969 -- -> 51000), ACK (51000 ->
    ## 6970). The DATA/ACK legs deliberately never touch port 6969 at all,
    ## exercising the "no port filter" finding directly: a port-filtered
    ## parser would drop both.
    let rrq = encode(TftpPacket(opcode: opRrq, filename: "hello.txt",
                                 mode: tmOctet, options: @[]))
    let data = encode(TftpPacket(opcode: opData, blockNum: 1,
                                  data: stringToBytes("hi")))
    let ack = encode(TftpPacket(opcode: opAck, ackBlockNum: 1))

    let pcap = mkPcap(0'u32, @[
      wrapLoopback(mkIpv4Udp(rrq, 51000, 6969)),
      wrapLoopback(mkIpv4Udp(data, 6970, 51000)),
      wrapLoopback(mkIpv4Udp(ack, 51000, 6970)),
    ])
    let (payloads, unconsumed) = extractUdpPayloads(pcap)
    check payloads.len == 3
    check payloads[0] == rrq
    check payloads[1] == data
    check payloads[2] == ack
    check unconsumed == 0

  test "extractUdpPayloads: Ethernet linktype (pcap-tftp-server shape) + padding is stripped":
    ## The RRQ frame is short enough that a real Ethernet NIC would pad it
    ## to the 46-byte minimum payload -- `padTo` simulates that. The UDP
    ## header's own `length` field, not the padded frame length, must
    ## determine the extracted payload -- this is the "trust UDP length,
    ## not incl_len" finding, exercised directly (not merely asserted in
    ## prose).
    let rrq = encode(TftpPacket(opcode: opRrq, filename: "x", mode: tmOctet,
                                 options: @[]))
    let errPkt = encode(TftpPacket(opcode: opError, errorCode: errFileNotFound,
                                    errorMsg: "File not found"))
    let ethFrame = wrapEthernet(mkIpv4Udp(rrq, 51001, 69), padTo = 60)
    check ethFrame.len == 60  # confirm padding actually happened in this fixture
    let pcap = mkPcap(1'u32, @[
      ethFrame,
      wrapEthernet(mkIpv4Udp(errPkt, 69, 51001)),
    ])
    let (payloads, unconsumed) = extractUdpPayloads(pcap)
    check payloads.len == 2
    check payloads[0] == rrq          # exact, no trailing pad bytes
    check payloads[0].len == rrq.len  # would be 46+ if incl_len/padding leaked in
    check payloads[1] == errPkt
    check unconsumed == 0

  test "extractUdpPayloads: a truncated trailing record is skipped, not raised":
    let rrq = encode(TftpPacket(opcode: opRrq, filename: "y", mode: tmOctet,
                                 options: @[]))
    var pcap = mkPcap(0'u32, @[wrapLoopback(mkIpv4Udp(rrq, 51002, 6969))])
    pcap.add @[byte 1, 2, 3]  # a partial record header, less than 16 bytes
    let (payloads, unconsumed) = extractUdpPayloads(pcap)
    check payloads.len == 1
    check payloads[0] == rrq
    check unconsumed == 3  # L3: the leftover partial header is observable, not silently dropped

  test "extractUdpPayloads: pcapng / non-classic-pcap magic degrades to empty, not a crash (L2)":
    ## `0x0A0D0D0A` is pcapng's block-type magic in the position classic
    ## pcap puts its global-header magic -- exactly the shape a
    ## Wireshark-default-format file handed to this tool would have. Must
    ## NOT `doAssert`/raise (this tool consumes attacker/third-party pcap
    ## files); must degrade to an empty, non-error result instead.
    var pcapng = u32le(0x0A0D0D0A'u32)
    pcapng.add newSeq[byte](40)  # arbitrary trailing bytes; irrelevant, never parsed
    let (payloads, unconsumed) = extractUdpPayloads(pcapng)
    check payloads.len == 0
    check unconsumed == 0

  test "extractUdpPayloads: a corrupt MID-STREAM incl_len halts parsing but surfaces it, not silent data loss (L3)":
    ## Three real records; the SECOND record's `incl_len` is corrupted to
    ## claim far more bytes than remain in the buffer. The parser cannot
    ## resync past a corrupt `incl_len` (classic pcap records are
    ## self-delimiting only via that field), so the honest behavior is: (a)
    ## keep whatever intact records were decoded before the corruption --
    ## here, just the first -- and (b) make the stoppage OBSERVABLE via
    ## `unconsumedBytes`, rather than silently discarding the third
    ## (perfectly intact) record with no signal at all.
    let rrq = encode(TftpPacket(opcode: opRrq, filename: "z", mode: tmOctet,
                                 options: @[]))
    let data = encode(TftpPacket(opcode: opData, blockNum: 1,
                                  data: stringToBytes("mid-stream")))
    let ack = encode(TftpPacket(opcode: opAck, ackBlockNum: 1))

    var pcap = mkPcap(0'u32, @[wrapLoopback(mkIpv4Udp(rrq, 51003, 6969))])
    let corruptRecordOffset = pcap.len
    pcap.add mkPcapRecord(wrapLoopback(mkIpv4Udp(data, 6972, 51003)))
    let thirdRecordBytes = mkPcapRecord(wrapLoopback(mkIpv4Udp(ack, 51003, 6972)))
    pcap.add thirdRecordBytes

    # Corrupt the second record's incl_len (the pcap record header is
    # ts_sec/ts_usec/incl_len/orig_len, each a u32le -- incl_len is bytes
    # [8..12) of the 16-byte header) to a value guaranteed to overrun the
    # buffer.
    let inclLenOff = corruptRecordOffset + 8
    let bogus = u32le(0xFFFFFF00'u32)
    for i in 0 ..< 4: pcap[inclLenOff + i] = bogus[i]

    let (payloads, unconsumed) = extractUdpPayloads(pcap)
    check payloads.len == 1        # only the RRQ before the corruption survives
    check payloads[0] == rrq
    # Everything from just past the corrupt record's 16-byte header onward
    # -- including the otherwise-perfectly-intact third record -- is
    # reported as unconsumed: this is the "not silent" property under test.
    check unconsumed == pcap.len - (corruptRecordOffset + 16)
    check unconsumed >= thirdRecordBytes.len  # the intact 3rd record really was lost, and that loss is sized correctly

  test "harvest: verified-leg packets deposit through encodeByteSeqIR into a distinct testId, and every seed round-trips (per C2's discipline)":
    let tmpDir = getTempDir() / "chapulin_interop_capture_harvest"
    removeDir(tmpDir)

    let rrq = encode(TftpPacket(opcode: opRrq, filename: "random.bin",
                                 mode: tmOctet,
                                 options: @[("blksize", "1024")]))
    let data = encode(TftpPacket(opcode: opData, blockNum: 1,
                                  data: stringToBytes("payload-bytes")))
    let ack = encode(TftpPacket(opcode: opAck, ackBlockNum: 1))
    let originals = @[rrq, data, ack]

    let pcap = mkPcap(0'u32, @[
      wrapLoopback(mkIpv4Udp(rrq, 52000, 6969)),
      wrapLoopback(mkIpv4Udp(data, 6971, 52000)),
      wrapLoopback(mkIpv4Udp(ack, 52000, 6971)),
    ])

    let db = directoryBasedDatabase(tmpDir)
    let testId = interopCaptureTaggedId("t_interop_capture.getleg")
    let n = harvestPcapBytes(db, pcap, testId)
    check n == 3

    # RED-phase finding (confirmed against source, `db.nim`'s `applySave`:
    # `c.primary = @[choices] & deduped` -- each `save` PREPENDS): `loadPrimary`
    # returns entries most-recently-saved-first, NOT insertion order. A first
    # cut of this test asserted `reloaded[i] == originals[i]` positionally and
    # failed with an exact reversal (index 0 <-> index 2) -- a real ordering
    # fact about the shared corpus mechanism, not a bug in this harvest path.
    # Fixed below to match by CONTENT (order-independent), which is also the
    # only thing that should matter for a corpus: it's a set of seeds, not a
    # sequence a consumer replays in a specific order.
    let reloaded = db.loadPrimary(testId)
    check reloaded.len == 3
    var matchedRrq, matchedData, matchedAck = false
    for i, ir in reloaded:
      checkpoint("harvested seed index " & $i)
      var ds = newReplaySource(ir)
      let generated = byteSeqs().generate(ds)
      # THE CRITICAL PROOF (C2's own discipline, reused verbatim, not
      # re-derived): a structural IR round-trip is insufficient -- assert
      # the CONCRETE value the actual soak-target strategy produces from
      # this seed is byte-identical to one of the originally-captured
      # packets...
      check generated in originals
      # ...and decodes, through the REAL production decoder, to the exact
      # semantic value that specific captured packet carried -- not merely
      # "decodes to something," the actual filename/option/block-number/data
      # the capture carried, mirroring t_soak_encoder.nim's own
      # field-level assertions (not just a decode-outcome string compare).
      let pkt = decode(generated)
      case pkt.opcode
      of opRrq:
        check generated == rrq
        check pkt.filename == "random.bin"
        check pkt.options == @[("blksize", "1024")]
        matchedRrq = true
      of opData:
        check generated == data
        check pkt.blockNum == 1'u16
        check pkt.data == stringToBytes("payload-bytes")
        matchedData = true
      of opAck:
        check generated == ack
        check pkt.ackBlockNum == 1'u16
        matchedAck = true
      else:
        check false  # unexpected opcode for this fixture
    check matchedRrq and matchedData and matchedAck  # all 3 captured packets accounted for exactly once

    removeDir(tmpDir)

  test "harvest: atftp-PUT-leg packets tag under the UNVERIFIED provenance id, distinct from the verified-leg id":
    ## Simulates harvesting docker-compose.yml's "Test 5: PUT with atftp"
    ## leg -- confirmed by direct read (this suite's own module doc + the
    ## RFC) to always report PASS regardless of whether the upload actually
    ## succeeded (`echo "PASS: PUT completed (exit $$?)"` reports `echo`'s
    ## own exit code). A packet harvested from that leg must land under
    ## `interopCaptureUnverifiedTaggedId`, never silently merged into the
    ## verified-leg corpus.
    let tmpDir = getTempDir() / "chapulin_interop_capture_unverified"
    removeDir(tmpDir)

    let wrq = encode(TftpPacket(opcode: opWrq, filename: "uploaded_atftp.txt",
                                 mode: tmOctet, options: @[]))
    let pcap = mkPcap(0'u32, @[wrapLoopback(mkIpv4Udp(wrq, 53000, 6969))])

    let db = directoryBasedDatabase(tmpDir)
    let verifiedId = interopCaptureTaggedId("t_interop_capture.putleg")
    let unverifiedId = interopCaptureUnverifiedTaggedId("t_interop_capture.putleg")
    let n = harvestPcapBytes(db, pcap, unverifiedId)
    check n == 1

    check db.loadPrimary(unverifiedId).len == 1
    check db.loadPrimary(verifiedId).len == 0  # distinct id -- no cross-contamination
    check unverifiedId != verifiedId
    check unverifiedId == verifiedId & "-unverified"

    removeDir(tmpDir)

  test "empty / entirely-irrelevant capture harvests zero seeds, not an error":
    let pcap = mkGlobalHeader(0'u32)  # header only, zero packet records
    let (payloads, unconsumed) = extractUdpPayloads(pcap)
    check payloads.len == 0
    check unconsumed == 0
