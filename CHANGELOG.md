# Changelog

## 0.2.0 - "max out" pass

### Added
* **IEC 60870-5-104** dissector (APCI framing/resync, I/S/U formats, ASDU header, exact element tiling for every standard type,
  command decoding incl. select/execute), wired into inventory, policy (`iec104` writers, `command`/`setpoint`/`bitstring`/
  `parameter` write ranges), rules (reset-process = critical, broadcast CA 0xFFFF) and signature identification.
  Cross-checked against tshark on the two real captures available.
* **S7CommPlus** header/function/sequence/session decoding (function names unverified against an independent dissector).
* **Tunnel decapsulation**: GRE (key/seq/checksum, transparent Ethernet), ERSPAN II/III, VXLAN, MPLS, PPPoE, IPv4/IPv6-in-IP.
* **IPv4/IPv6 fragment reassembly** with bounds, first-copy-wins and conflict reporting (`QW-M003`).
* **Policy `allowed_functions`** (+ `@tag` groups, name validation) and rule **QW-F002**; `baseline` now emits it.
* Rule **QW-E002** (request flood; default derived from the real corpus' busiest poller).
* **Audit log HMAC** (`--audit-key-file`, `quietwire audit-key`, keyed `verify-log`).
* **Multi-file `analyze`** (rotated captures as one stream; per-file evidence in JSON and SARIF).
* Kernel packet-drop counters in live mode; `deploy/quietwire.service` (hardened systemd unit) and docs/DEPLOYMENT.md.
* `scripts/mutation_test.py` (AST mutation tester, no dependencies).

### Changed
* CLI: exit status `1` now means "alert at/above --fail-on or log verification failed" (was `2`, which collided with argparse
  usage errors); `analyze` takes several captures; audit `analysis_start` events list `files` instead of one hash.
* Throughput: ~35k packets/s (60,227 packets in 1.74 s). A first cut of the new decoder had dropped this to ~21k; profiling
  led to C-speed MAC formatting, precompiled header structs, an address cache and direction-aware rule dispatch.

### Defects and test weaknesses found while verifying this release
| # | Finding | How it was found |
|---|---|---|
| 1 | **Several of my own new tests were tautological**: they read expected sizes/names from the table under test, so corrupting the table could not fail them. Replaced by independent literal golden tables (DNP3 object sizes, IEC 104 types, S7 tables). | mutation testing (DNP3 table mutants survived despite the new tests) |
| 2 | DNP3 mutation score was 43.8 % on a 384-mutant sample (function/object tables untested) -> 91.1 % after golden tests; Modbus 76.0 % -> 89.3 % (196 mutants, quantity/byte-count boundaries); S7comm 70.6 % -> 87.8 % (238); IEC 104 74.1 % -> 93.6 % (344); TCP reassembler 79.8 % -> 90.4 % (94); fragment reassembler 70.1 % -> 90.8 % (87). | mutation testing |
| 3 | Dead code: an unreachable `missing_asdu` branch (IEC 104) and an unused `_HEADER_ONLY` set (DNP3) were removed. | own tests / surviving mutants |
| 4 | IEC 104 S-format validation accepted extra bits in the control octet (`0x09`); tightened to exactly `0x01`. | own boundary test |
| 5 | The tshark comparison script counted S7CommPlus frames as S7comm mismatches after S7CommPlus gained function names (775 compared, 139 matching) - a bug in the validator, not the dissector; fixed. | final cross-check |
| 6 | The fragment-evasion test I first wrote could not trigger `QW-M003`: a decoy sent as the *last* fragment completes the datagram, so no conflict is ever seen. Documented as a design limit (conflict is detectable only while the datagram is incomplete). | writing the test |
| 7 | Throughput regression (41k -> 21k packets/s) from the decoder refactor. | profiling |

### Known quirks, not defects
* `ndpi_iec60780-5-104.pcap` is a deliberately corrupted IEC 104 stream (junk prefixes before `0x68`); quietwire flags 29
  messages malformed. tshark also flags five frames as "Malformed Packet" and reports bogus ASDU type 24/26 from them.
* Earlier quirks still apply (Zeek `modbus.pcap` responses with bytes beyond the MBAP length; `fuzz-72` frame attribution).

## 0.1.0 - initial release

First public build: Modbus/TCP+UDP, DNP3 (TCP/UDP), S7comm dissectors; asset/flow inventory; policy baseline + enforcement;
18 detection rules with ATT&CK for ICS mapping; JSON / SARIF 2.1.0 / text reports; hash-chained audit log;
offline (pcap, pcapng, stdin) and live (Linux AF_PACKET, receive-only) operation.

### Defects found and fixed while verifying this release

Each was caught by an actual run (real capture, property test, fuzzing or a hung test), not by inspection.

| # | Defect | How it was found |
|---|---|---|
| 1 | DNP3 transport header FIR/FIN bits were swapped (FIN is bit 7, FIR is bit 6). My own synthetic encoder had the same mistake, so the unit tests agreed with the bug. | tshark cross-check on real DNP3 captures: multi-frame fragments were dropped as "orphan segments" |
| 2 | DNP3 over UDP lost transport-reassembly state between datagrams. | real UDP captures vs tshark |
| 3 | S7 READ_VAR responses: items with an error return code carry no data bytes; the parser expected data and flagged a false protocol violation. | real S7comm capture |
| 4 | DNP3 free-format objects (g70v5 file transport) inside a READ request carry data; the parser assumed header-only. | real DNP3 file-transfer capture |
| 5 | A garbled SYN (SYN+FIN+PSH+URG) from the server port swapped client and server for the whole flow, mislabelling requests and responses. Roles are now decided by well-known port, then a *sane* SYN, then a heuristic, and are flagged `role_inferred` when heuristic. | Zeek fuzz-72 capture |
| 6 | Segments held behind a TCP hole were never released until the end of the capture, so messages were attributed to the wrong packet or lost; added timed release, per-segment evidence tags and a flush at flow end. | real captures with loss |
| 7 | I added "release held segments when the peer ACKs past the hole" and then **removed it again**: under capture-side reordering an ACK legitimately precedes the data it acknowledges, and the property test showed it silently dropped valid messages. | local-reordering invariance test |
| 8 | Modbus re-synchronisation either hid fuzzed/vendor function codes (too strict) or invented messages from zero-heavy non-Modbus payloads (too lax). Now relaxed at TCP chunk boundaries, strict mid-chunk. | real fuzzed and non-Modbus-on-502 captures |
| 9 | One bogus far-future/past TCP segment could poison a stream's sequence state; added window checks, a contiguous-run resync, and new-connection detection on a reused 4-tuple (FIN/RST or implausible sequence space). | Zeek fuzz-72, then dedicated tests |
| 10 | `capture --duration` never fired on an idle link (the deadline was only checked when a packet arrived), so the command could hang indefinitely. | the live end-to-end test hung |
| 11 | `QW-S001` (response without request) fired when a SPAN delivered a response just before its request; now needs `pairing_grace` seconds of capture time and a flush at end of capture. | reordering property test |
| 12 | After reordered delivery an alert's *first* packet could be a later one; evidence pointers now keep the true minimum/maximum. | reordering property test |
| 13 | S7 PI-service name was read from the wrong offset when a parameter block was present. | unit test |
| 14 | Retired MITRE IDs T0855/T0856 were in the first draft; the live ATT&CK matrix (v19) merged them into T1692.001/.002. | fetching the official matrix |
| 15 | IP total length larger than a *fully captured* frame was treated as snaplen truncation (an attacker could fabricate "gaps"); now rejected unless the capture really cut the frame. | review while hardening TCP handling |
| 16 | Loopback live capture counted every frame twice (kernel delivers outgoing+incoming copies); duplicates are now dropped on loopback only. | live loopback test |

### Known quirks, not defects
* `modbus.pcap` (Zeek) contains a device whose responses carry bytes beyond the declared MBAP length; quietwire decodes the
  message and reports the stray bytes (`QW-M001`, 32 times) whereas tshark skips such responses entirely.
* Heavily corrupted captures (Zeek `fuzz-72`) decode the same number of messages as tshark (17) but attribute four of them to
  different frames, because the two tools handle out-of-order data differently.
