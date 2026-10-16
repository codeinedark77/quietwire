# Limitations

Read this before relying on quietwire. Items are ordered roughly by how likely they are to matter.

## Coverage
* **Four protocols**: Modbus/TCP(+UDP), DNP3 (TCP/UDP), S7comm, IEC 60870-5-104. No Modbus RTU/ASCII-over-TCP, EtherNet/IP/CIP,
  IEC 61850 (MMS/GOOSE), OPC UA, BACnet, PROFINET, FINS, etc. Traffic of those protocols is ignored.
* **S7CommPlus (S7-1200/1500 engineering traffic) is only partly decoded**: header, opcode, function code, sequence number and
  session id. Function names come from the public reverse-engineered table; **tshark 4.2.2 has no S7CommPlus dissector, so
  they could not be cross-checked**, and only a handful of functions occur in the one real capture available (CreateObject,
  SetMultiVariables, GetMultiVariables). Write *targets* are not decoded, so `write_ranges` produce "target could not be
  determined" alerts for S7CommPlus writes. TLS-protected S7CommPlus (newer firmware) is invisible.
* **No encrypted/authenticated variants**: TLS-wrapped DNP3, Modbus/TCP Security, IEC 62351-3, DNP3 Secure Authentication (g120)
  are not decoded or verified; encrypted traffic is invisible beyond the TCP level.
* **DNP3 object parsing uses a partial size table.** Unknown group/variation combinations stop object parsing for that message
  (`objects_partially_parsed`, not an alert), so controls hidden behind an unknown object are not seen.
* **IEC 104**: values of monitor-direction information objects are structure-checked but not decoded; only command-direction
  qualifiers (select/execute, states, set-point values) are decoded. Frames with non-standard field lengths (IEC 101 style
  1-byte cause / 1-byte common address) are reported as malformed.
* **S7 userdata** is only partly decoded (SZL read, block list, clock). Layouts come from public reverse-engineered
  documentation, not a vendor specification.

## Capture quality
* Detections assume a **complete, symmetric capture** (SPAN/TAP seeing both directions). One-sided or lossy captures reduce
  accuracy; the engine reports gaps (`QW-P001`, `tcp_gaps`) and kernel drops (live mode) but cannot recover lost data.
* **Tunnels handled**: VLAN (802.1Q/ad), MPLS, PPPoE session, GRE (plain, key/seq/checksum, transparent Ethernet bridging),
  ERSPAN II/III, VXLAN, IPv4/IPv6-in-IP, up to 3 levels deep. **Not handled**: GENEVE, VXLAN-GPE, L2TP, GTP, IPsec/WireGuard
  (encrypted anyway), ERSPAN type I, non-Ethernet pseudowires.
* **IP fragments are reassembled** (IPv4 and IPv6), bounded (1,024 datagrams, 256 fragments each, 30 s, 64 KiB) with
  first-copy-wins for overlaps. Conflicting overlaps (`QW-M003`) are only detectable if the conflicting copy arrives *before*
  the datagram completes; a monitor and a target with different reassembly policies can still disagree.
* **TCP reassembly is simplified.** Bounded buffers; bytes already delivered are never replaced by a later overlapping copy; a
  0.25 s reorder window before a hole is declared lost; sequence-window checks (1 MiB) with a contiguous-run resync; a reused
  4-tuple starts a new connection when FIN/RST was seen or its sequence space is implausible; no SACK/urgent-data handling. A
  determined evasion attacker who exploits differences between this reassembly and the victim's TCP stack could hide
  traffic; this is not an IPS-grade normaliser.
* Live capture timestamps are user-space receive times; Linux only; needs root/`CAP_NET_RAW`. The Python pipeline handled
  ~35k packets/s on the validation machine (single thread; 60,227 Modbus packets in 1.74 s); it is meant for OT segments, not
  10 Gbit links. Under overload the kernel drops frames (reported, not prevented).

## Detection logic
* Thresholds (sweep, exception storm, flood, warm-up) are **defaults chosen by judgement, not tuned on production networks.**
  The flood default (500 requests/s per pair) leaves ~9x headroom over the busiest legitimate poller in the validation corpus
  (55/s), which proves little about *your* plant. Expect to tune them and to review the first week of alerts. No
  false-positive rates are claimed.
* The sweep rules only count *new* contacts after the warm-up window (default 120 s from the first packet); a capture that
  starts in the middle of a scan will under-report.
* Role inference (who is the master) is exact for well-known ports and DNP3 (DIR bit); otherwise it uses the TCP handshake,
  else a heuristic (higher port = client). Such flows carry `role_inferred: true`.
* `allowed_functions` is name based: it cannot express "this register range only" (use `write_ranges`) or value limits.
* No timing/periodicity model: a changed polling cycle, replayed traffic or value-level anomalies (setpoints within permitted
  ranges but physically dangerous) are not detected.
* Policies are IP-based. NAT, DHCP churn, VLAN or MAC-based identity are not modelled. Write ranges are inclusive and not merged
  across entries.
* Technique mapping to ATT&CK for ICS is advisory; it was verified against the public matrix (v19) on 2026-10-04, which changes.

## Verification gaps
* **Table contents are only as right as my reading of the standards.** The golden-table tests (function names, object sizes,
  IEC 104 element sizes, S7 areas/return codes) pin the dissectors to values I took from IEEE 1815, IEC 60870-5-101/104 and the
  public S7 documentation; where that reading is wrong, code and tests are wrong *together*. Independent checks exist only for
  what occurs in the real captures (tshark cross-checks). In particular the IEC 104 element sizes of types absent from the two
  real captures, most DNP3 object variations, and the S7CommPlus function table have no independent oracle here.
* Real S7comm coverage is thin: **two real captures** (one classic, one S7CommPlus). No real S7 stop/download traffic was
  available - those paths are tested against synthetic frames built from the documented layouts. IEC 104 has **two small real
  captures**, one of which is a deliberately corrupted stream.
* Real-capture validation compares against tshark/Wireshark 4.2.2; where both could share a misunderstanding, no independent
  oracle exists. Zeek's own logs were not used as a second oracle.
* **Mutation testing is a sample**, not exhaustive: seeded random subsets of mutants per module (see docs/VALIDATION.md); the
  survivors were triaged by pattern (message text, defaults) rather than one by one.
* The audit log is *tamper-evident, not tamper-proof*: without the HMAC key whoever can rewrite the log and the stored anchor can
  forge a history; with the key on the same host, a host compromise gets the key too.
* The audit-log and SARIF formats were not tested against the AI Empire components (no repository access in the build sandbox).
* `deploy/quietwire.service` was syntax-checked with `systemd-analyze` 255 (exposure score 1.5) but **never run as a service**
  (no systemd PID 1 in the sandbox). Hardening options such as `MemoryDenyWriteExecute` or the syscall filter may need relaxing
  on your distribution.
* Python versions tested: 3.9.25, 3.12.3, 3.13.16 on Linux x86-64 only. macOS/Windows are untested (`fcntl` locking and live
  capture are POSIX/Linux features; offline analysis is pure Python).
* No license file is included; add the one you want.
