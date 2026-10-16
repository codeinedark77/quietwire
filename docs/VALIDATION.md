# Validation

Everything below was run against the sources in this archive (0.2.0). Commands to reproduce are given for each item.

## 1. Test suite

* **1,062 tests**: 1,031 run by default (1,030 on Python 3.9, where one stdlib-introspection test skips itself) plus 31
  real-capture regression tests that need `QUIETWIRE_CORPUS=<dir>` (the captures are not redistributed; with the corpus all
  1,062 pass). Run: `pip install -e .[dev] && pytest` (also `jsonschema` for the SARIF test).
* **98 % line+branch coverage** (4,457 statements, 1,786 branches; `coverage run -m pytest && coverage report`).
* Passes on **Python 3.9.25, 3.12.3 and 3.13.16** (Linux x86-64).
* Test types: byte-exact canonical vectors (Modbus spec example, DNP3 primer frame, published S7 frames, CRC-16/DNP catalogue
  check value `0xEA82`); **independent golden tables** for every protocol table (function names/kinds, object and element sizes,
  areas, return codes, cause names); exact-boundary tests for every limit; per-rule positive/negative tests; engine scenarios;
  **property tests** (re-segmenting all TCP payloads to MSS 1/3/7/64/200, 25 trials of local reordering plus duplication,
  every tunnel kind and fragment ordering must not change any decoded message or alert); policy validation matrix;
  audit-log tamper tests (edit, delete, reorder, truncate with/without anchor, recomputed chain without the HMAC key, concurrent
  multi-process writers); multi-file analysis; SARIF validated against the official OASIS 2.1.0 schema; CLI exit codes; **live
  capture on `lo` with real sockets**; static guards that the package never calls `send*`, opens raw sockets only in
  `capture/live.py`, imports only the standard library and uses no `eval/exec/pickle`.

## 2. Real captures vs tshark 4.2.2 (`scripts/validate_tshark.py`)

Corpus: 31 public captures, 75,660 packets - nDPI `tests/cfgs/default/pcap/{dnp3,modbus,s7comm,s7comm-plus,IEC104,iec60780-5-104}.pcap`
and Zeek `testing/btest/Traces/{dnp3,modbus}/*.pcap` (includes DNP3 over UDP, file transfer, select/operate, a non-standard
port, Modbus with non-Modbus traffic on port 502, a 60,227-packet Modbus capture, and deliberately fuzzed/corrupted captures).
All were processed without error: 47,403 messages decoded, 89 flagged with a protocol anomaly.

*Level 1* - per frame, the multiset of function codes / ASDU type ids must equal tshark's (TCP retransmissions excluded on the
tshark side). *Level 2* - decoded field values must equal tshark's: Modbus start address/quantity, S7 item area/DB/address/
length/type, DNP3 object group/variation lists, IEC 104 type/cause/common address/object count/first object address.

| | compared | identical |
|---|---|---|
| DNP3 function codes | 313 frames | 313 (100 %) |
| DNP3 object-header lists | 245 messages | 245 (100 %) |
| S7comm function codes | 139 frames | 139 (100 %) |
| S7comm variable items | 25 | 25 (100 %) |
| Modbus function codes | 45,707 frames | 45,701 (99.987 %) |
| Modbus request start/quantity | 22,696 | 22,696 (100 %) |
| IEC 104 ASDU type ids | 27 frames | 23 (85 %) - the 4 differing frames are corrupt, see below |
| IEC 104 ASDU details | 25 | 25 (100 %) |

Every differing frame was examined; none is a quietwire misparse:

* `modbusBig` frame 3150: tshark labels it "TCP Spurious Retransmission" because the ACK for it was captured *before* the data.
  Per sequence numbers the bytes were never seen, so quietwire decodes them.
* `modbus.pcap` frame 113: the response carries 3 bytes beyond its declared MBAP length; tshark skips it, quietwire decodes the
  message and reports the stray bytes as `QW-M001`.
* `fuzz-72` frames 2, 5, 7, 20: a trace with garbled flags and sequence numbers; both tools decode 17 messages, attributed to
  different frames because out-of-order data is handled differently.
* `ndpi_iec60780-5-104.pcap` frames 25, 41, 58, 83, 96: a deliberately corrupted stream; tshark itself reports "Malformed
  Packet" and a bogus type id (24/26) from the junk bytes; quietwire reports the junk as malformed APCI.

## 3. Tunnels and fragments vs tshark (synthetic)

16 synthetic captures built by `quietwire.synth` from the same attack/baseline scenario: plain, GRE, GRE with key+sequence+
checksum, GRE transparent bridging, ERSPAN II, ERSPAN III, ERSPAN III with platform sub-header, VXLAN, IP-in-IP, MPLS (one label
and a 3-label stack), PPPoE, IPv4 fragmentation (16-byte fragments in order, 8-byte fragments reversed, 24-byte fragments
shuffled) and a fragmented GRE tunnel with shuffled fragments. The encapsulated frames were produced by independent encoders,
decoded by quietwire and compared with tshark's own decapsulation/reassembly: DNP3 208/208 frames (and 208/208 object lists),
Modbus 1,120/1,120 (544/544 request fields), S7comm 304/304 (112/112 items) - 100 %, including which *frame* completes a
fragmented datagram. Unit tests additionally assert that every kind yields exactly the plain capture's messages and alerts.

## 4. pcap reader and packet decoder vs dpkt (`scripts/validate_dpkt.py`)

76,299 packets (the 31 captures plus three synthetic captures written as pcap, pcapng and nanosecond pcap): packet count,
timestamp and bytes identical in every file; the decoded 5-tuple, TCP sequence/ack/flags and payload identical for every
packet dpkt decodes except one: a fuzzed packet whose IPv4 version nibble is 2. dpkt ignores the version; quietwire and
tshark ("Bogus IPv4 version") reject it.

## 5. Fuzzing (`scripts/fuzz.py`, plus `tests/test_fuzz.py`)

Mutation fuzzing of whole-pipeline input (bit flips, byte overwrites, truncation, junk insertion, deletion, 0x00/0xFF runs;
timestamp jumps). Seeds: the synthetic scenario, its eight tunnelled and two fragmented variants, and the real captures
including both IEC 104 files. Final-code campaign: **25,929 runs, 5,817,762 packets in 150 s, 0 crashes** (earlier campaigns on
intermediate code: 21,538 + 10,971 + 17,625 runs, also 0 crashes). Adversarial dissector inputs (65 KB of zeros, `05 64` spam,
header-like noise) complete in tens of milliseconds.

## 6. Mutation testing (`scripts/mutation_test.py`)

One mutation at a time (comparison/boolean/arithmetic operators, integer and boolean constants, `not`) against the relevant
test files; a mutant *survives* if every test still passes. Seeded random samples (so the "before" and "after" columns use the
**identical mutants**). "Before" = the suite as first written for this release; "after" = after adding golden-table and exact-
boundary tests for the survivors.

| module | mutants (same sample) | before | after |
|---|---|---|---|
| proto/dnp3.py | 384 | 43.8 % | 91.1 % |
| proto/modbus.py | 196 | 76.0 % | 89.3 % |
| proto/s7comm.py | 238 | 70.6 % | 87.8 % |
| proto/iec104.py | 344 | 74.1 % | 93.6 % |
| net/reassembly.py | 94 (module has 104) | 79.8 % | 90.4 % |
| net/fragments.py | 87 (all) | 70.1 % | 90.8 % |

Survivors that remain are mostly message-text formatting (`"..." % x` mutated), defaults/limits that only matter at exact
values, and fallbacks such as `self.next_seq or 0` that cannot be reached. They were triaged by pattern, not one by one.
Not run: rules, policy, decoder, CLI, report modules.

## 7. Live capture

`tests/test_live.py` captures a real client/server Modbus exchange on `lo` and checks message counts (8), flow roles,
alerts, kernel counters (0 drops), absence of duplicate frames, and that `capture --save-pcap` output replays to the same
result; `tests/test_live_errors.py` drives the error paths through a fake socket. They skip automatically where raw capture is
not permitted. Only loopback was tested; no physical NIC, SPAN port or promiscuous-mode traffic was available.

## 8. Throughput

60,227 packets (9 MB, Modbus) in 1.74 s = ~34.6k packets/s; 13,622 packets in 0.33 s = ~40.7k packets/s (single thread, this
sandbox, Python 3.12).

## 9. What was *not* validated

See LIMITATIONS.md ("Verification gaps"). Notably: S7 stop/download traffic and the S7CommPlus function table (no real capture /
no independent dissector), IEC 104 beyond two small captures, any production network, other Python versions or operating
systems, the systemd unit as a running service, and interoperability with the AI Empire components.
