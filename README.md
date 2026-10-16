# quietwire

[![CI](https://github.com/codeinedark77/quietwire/actions/workflows/ci.yml/badge.svg)](https://github.com/codeinedark77/quietwire/actions/workflows/ci.yml)
![Tests](https://img.shields.io/badge/tests-1025%20passed-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)
![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-0-success)

Passive ICS/OT protocol analyzer for **Modbus/TCP**, **DNP3**, **S7comm** and **IEC 60870-5-104**.
It reads packet captures (pcap / pcapng / stdin) or listens on a Linux interface, builds an asset and
communication inventory, learns a policy baseline from known-good traffic, and raises detections
(unauthorised writes, functions outside an allow-list, stop/restart/download commands, scans, floods,
protocol violations, IP-fragment evasion, ...).

* **Receive-only.** No code path transmits a packet (a test scans the package for send calls).
* **Zero dependencies**, Python >= 3.9 (tested on 3.9, 3.12, 3.13).
* **Sees through the plumbing.** Decapsulates GRE, ERSPAN II/III, VXLAN, MPLS, PPPoE and IP-in-IP; reassembles IPv4/IPv6
  fragments (first-copy-wins, conflicting overlaps reported); recovers from TCP loss, reordering and reconnects.
* **Evidence you can jump to.** SARIF 2.1.0 output points at the byte offset of the first matching packet, in the right
  member file when several captures are analysed together.
* **Tamper-evident audit log**, optionally HMAC-keyed.
* **Honest about gaps.** TCP loss, truncation and re-synchronisation are reported (`QW-P001`), never silently papered over.
  See [LIMITATIONS.md](LIMITATIONS.md) and [docs/VALIDATION.md](docs/VALIDATION.md).

## Quick start

```bash
pip install .                      # or: PYTHONPATH=src python -m quietwire ...
quietwire demo ./demo              # writes baseline.pcap, attack.pcap, policy.json
quietwire analyze demo/baseline.pcap --policy demo/policy.json        # 0 alerts
quietwire analyze demo/attack.pcap   --policy demo/policy.json --fail-on high
```

Real output (abridged) for the synthetic attack capture:

```
quietwire 0.2.0 - passive ICS analysis
packets  : 213  (2023-11-16T02:00:00.000500Z -> 2023-11-16T02:00:05.149489Z, 5.149s)
ICS msgs : dnp3=13, modbus=70, s7comm=22
alerts   : 26  (critical=3, high=23)

SEV       RULE     N   FIRST(UTC)    MESSAGE
CRITICAL  QW-C001  1   02:00:05.133  10.0.0.66 sent DNP3 COLD_RESTART to 10.0.0.20:20000: cold restart of the outstation
CRITICAL  QW-C001  1   02:00:05.144  10.0.0.66 sent S7COMM PLC_STOP (service P_PROGRAM) to 10.0.0.30:102: stops the PLC program
CRITICAL  QW-C001  1   02:00:05.145  10.0.0.66 sent S7COMM REQUEST_DOWNLOAD (DB00001) to 10.0.0.30:102: begins a program/block download to the PLC
HIGH      QW-F001  2   02:00:05.017  modbus traffic 10.0.0.66 -> 10.0.0.100:502 is not covered by allowed_flows
...
```

## Commands

| Command | Purpose |
|---|---|
| `quietwire analyze CAPTURE... [--policy P] [--format text\|json\|sarif] [--out F] [--audit-log L] [--audit-key-file K] [--min-severity S] [--fail-on S]` | Analyse pcap/pcapng file(s). Several files are processed **in the order given as one continuous stream** (rotated captures, oldest first); `-` reads stdin (`tcpdump -w - ... \| quietwire analyze -`) |
| `quietwire baseline CAPTURE [--out policy.json]` | Derive a *starting-point* policy from known-good traffic (needs human review) |
| `quietwire capture -i IFACE [--duration N] [--count N] [--save-pcap F] [--no-promisc]` plus the `analyze` options | Live receive-only capture (Linux, root / `CAP_NET_RAW`). Alerts stream to stderr; kernel drop counters are reported. A hardened systemd unit is in `deploy/` |
| `quietwire audit-key PATH` | Create a random 256-bit HMAC key file (mode 0600, never overwrites) |
| `quietwire verify-log LOG [--anchor HASH] [--audit-key-file K]` | Verify an audit-log hash chain (and macs) |
| `quietwire rules [--json]` | List detection rules |
| `quietwire demo DIR` | Write demo captures and a matching policy |

Exit status: `0` ok, `1` an alert at or above `--fail-on` (or log verification failed), `2` command-line usage error
(argparse), `3` unreadable/invalid capture, policy, key or audit log.

## What is decoded

| Protocol | Transport | Decoded |
|---|---|---|
| Modbus | TCP 502, UDP 502 | MBAP framing/resync; function codes 1-8, 11, 12, 15-17, 20-24, 43/14 with structural validation (quantities, byte counts, device-id objects); exceptions; request/response pairing; write targets (coil / holding-register ranges); diagnostics sub-functions |
| DNP3 | TCP/UDP 20000 | Link layer with CRC check of every header and data block; transport reassembly; application functions; object headers with a table of common object sizes; CROB and analog-output control decoding; IIN flags |
| S7comm | TCP 102 (TPKT/COTP) | COTP connect (rack/slot from TSAP), setup communication, READ/WRITE VAR items (area, DB, address), PLC stop, PI services, download/upload, userdata (SZL read, block list, clock). **S7CommPlus (`0x72`)**: header, opcode, function (names from the public reverse-engineered table), sequence number and session id only |
| IEC 60870-5-104 | TCP 2404 | APCI framing with resync; I/S/U formats; ASDU header (type, SQ/N, cause + P/N + test bits, originator, common address); every standard type id checked for exact element tiling; command decoding (single/double/regulating step, set-points, bitstring; select vs execute); interrogation, clock sync, reset process, parameter and file-transfer types |

ICS protocols on other ports are identified by signature (`QW-N001`). Everything else is ignored.

## Detections

Severity is the default; policy files can override it. ATT&CK for ICS IDs were checked against the live matrix
(v19) - note the old T0855/T0856 no longer exist there and are intentionally not used.

| Rule | Default | Name | ATT&CK for ICS |
|---|---|---|---|
| QW-A001 | medium | Asset not in policy | - |
| QW-F001 | high | Communication path not allowed by policy | - |
| QW-F002 | high | Function not allowed on this communication path | T1692.001 (when the function writes) |
| QW-W001 | high | Write or control from unauthorised source | T1692.001, T0836 |
| QW-W002 | low | Write or control operation observed (no writer policy) | T0836 |
| QW-W003 | high | Write outside permitted ranges | T0836, T1692.001 |
| QW-C001 | high | Critical operation (stop/restart/mode change/program transfer; critical for stop, cold/warm restart and download) | per operation: T0814, T0816, T0843, T0845, T0858, T0881, T0889 |
| QW-C002 | high | Broadcast command | T1692.001 |
| QW-R001 | medium | Host sweep | T0846 |
| QW-R002 | medium | Unit/address sweep | T0846 |
| QW-R003 | low | Device fingerprinting | T0888 |
| QW-M001 | medium | Malformed message or protocol violation | - |
| QW-M002 | medium | Unknown or undefined function code | - |
| QW-M003 | medium | Conflicting overlapping IP fragments (reassembly evasion) | - |
| QW-E001 | medium | Exception/error response storm | - |
| QW-E002 | medium | Request flood (default 500 requests/s per master-server pair; busiest real poller seen: 55/s) | T0814 |
| QW-S001 | low | Response without matching request | T1692.002 |
| QW-S002 | low | Host acts as both master and server | T0848 |
| QW-D001 | medium | Device restart / trouble indication | T0816 |
| QW-N001 | low | ICS protocol on non-standard port | T0885 |
| QW-P001 | info | Capture/stream health (gap / resync) | - |

Identical findings are aggregated (count, first/last packet, up to 3 samples). Technique names: T0814 Denial of Service,
T0816 Device Restart/Shutdown, T0836 Modify Parameter, T0843 Program Download, T0845 Program Upload, T0846 Remote System
Discovery, T0848 Rogue Master, T0858 Change Operating Mode, T0881 Service Stop, T0885 Commonly Used Port, T0888 Remote
System Information Discovery, T0889 Modify Program, T1692.001 Unauthorized Message: Command Message, T1692.002
Unauthorized Message: Reporting Message.

## Policy file (JSON)

A section that is **absent is not enforced**; a section that is **present is enforced strictly** (an empty list means
"nothing is allowed"). Unknown keys are rejected so a typo cannot silently disable a check; keys starting with `_`
are free-form annotations. IPs may be exact addresses, CIDR networks or `*`.

```json
{
  "version": 1,
  "assets": [{"ip": "10.0.0.10", "name": "PLC-1"}],
  "allowed_flows": [{"master": "10.0.0.2", "server": "10.0.0.10", "protocol": "modbus", "port": 502}],
  "allowed_functions": [{"master": "10.0.0.2", "server": "10.0.0.10", "protocol": "modbus",
                         "functions": ["READ_HOLDING_REGISTERS", "WRITE_SINGLE_REGISTER", "@read"]}],
  "writers": {"modbus": ["10.0.0.2"], "dnp3": ["10.0.0.3"], "s7comm": ["10.0.0.9"], "iec104": ["10.0.0.5"]},
  "engineering_stations": ["10.0.0.9"],
  "write_ranges": [{"server": "10.0.0.10", "protocol": "modbus", "unit": 1, "area": "holding_register", "start": 100, "end": 109}],
  "ignore_rules": ["QW-R003"],
  "severity_overrides": {"QW-S002": "medium"},
  "thresholds": {"warmup_seconds": 120, "sweep_hosts": 8, "unit_sweep_ids": 8, "exception_threshold": 10,
                 "flood_threshold": 500}
}
```

`allowed_functions` lists, per master/server(/protocol) path, the function names a master may use (names as printed in
alerts, e.g. `READ_VAR`, `DIRECT_OPERATE`, `C_SC_NA_1`, `S7PLUS_SET_MULTI_VARIABLES`; `UNKNOWN_<n>`; `*` = anything;
`@read`, `@write`, `@control`, `@critical`, ... = by behavioural tag). Names are validated, so typos are errors. Only
requests on a covered path are checked; session/link/response/malformed messages are exempt.

Write-target areas: Modbus `coil`, `holding_register`; S7 `DB<n>`, `M`, `Q`, `I` (byte offsets); DNP3 `binary_output`,
`analog_output` (point indices); IEC 104 `command`, `setpoint`, `bitstring`, `parameter` (information object addresses).
Tunable thresholds: `warmup_seconds`, `sweep_window`, `sweep_hosts`, `unit_sweep_ids`, `exception_window`,
`exception_threshold`, `flood_window`, `flood_threshold`, `flow_idle_seconds`, `max_flows`, `tcp_reorder_window`,
`pairing_grace`, `defrag_timeout`, `defrag_max_datagrams`. Engineering stations are exempt from QW-C001 and QW-R003.

`quietwire baseline` writes `assets`, `allowed_flows`, `allowed_functions` (observed request functions per path),
`writers`, `write_ranges` (adjacent writes merged) and an **empty** `engineering_stations`. It permits everything it saw,
including writes and critical operations - review it.

## Outputs

* **text** (default) - summary, alert table, assets, flows.
* **json** - full report (`schema_version` 1): input files with hashes, statistics (tunnels, fragments, TCP health),
  alerts, assets, flows, warnings.
* **sarif** - SARIF 2.1.0 (validated against the OASIS schema in the test-suite). `byteOffset` = the capture-file offset of
  the first packet record of the alert; `partialFingerprints` are stable across runs.
* **audit log** (`--audit-log`) - append-only JSONL, each record `{v, seq, ts, event, prev, hash[, mac]}` with
  `hash = SHA256(prev + "\n" + canonical_json(...))`. `verify-log` detects edits, deletions, reordering, partial lines
  and (given the anchor printed to stderr) tail truncation. With `--audit-key-file` every record also carries
  `mac = HMAC-SHA256(key, hash)`, so someone who can rewrite the file but lacks the key cannot forge a consistent history.
  **Store the anchor (and the key) where the writer host cannot modify them** - see docs/DEPLOYMENT.md.

## Library use

```python
from quietwire.capture import CaptureReader
from quietwire.detect import Engine, load_policy

engine = Engine(load_policy("policy.json"), on_alert=lambda alert, is_update: print(alert.rule_id, alert.message))
with CaptureReader("capture.pcap") as reader:
    for packet in reader:
        engine.process(packet)
result = engine.finalize()          # alerts, inventory, stats
```

## Layout

```
src/quietwire/
  capture/   pcap + pcapng readers, pcap writer, live AF_PACKET capture (the only raw-socket code)
  net/       Ethernet/VLAN/IPv4/IPv6/TCP/UDP decode + tunnels (decode.py), fragment reassembly, bounded TCP reassembly
  proto/     modbus.py  dnp3.py  s7comm.py  iec104.py  identify.py (signature identification)
  detect/    engine.py (flows, aggregation)  rules.py  policy.py  mitre.py
  inventory.py  report/ (json, sarif, text, auditlog)  cli.py  synth.py (traffic generator)
tests/       unit, golden-table, property, fuzz, live-loopback and real-capture regression tests
scripts/     validate_tshark.py  validate_dpkt.py  fuzz.py  mutation_test.py
deploy/      hardened systemd unit + environment file
docs/        VALIDATION.md  DEPLOYMENT.md
```

## Verification summary

See [docs/VALIDATION.md](docs/VALIDATION.md) for methods, numbers and the defects found on the way. In short (0.2.0):
1,062 tests at 98 % line+branch coverage on Python 3.9/3.12/3.13; dissector output compared with tshark on 31 real public
captures (75,660 packets) plus 16 synthetic tunnelled/fragmented captures; pcap reader/decoder compared with dpkt
(76,299 packets); SARIF against the official schema; live capture against real sockets on loopback; mutation testing of the
dissectors and reassemblers (scores 87-94 % on the sampled mutants after two rounds of test hardening); mutation fuzzing
without a crash.

## Integration points (AI Empire stack)

These are interfaces only; nothing here was tested against your repositories.

* **Meta Dashboard / Sieve-style consumers:** `--format sarif` emits SARIF 2.1.0 (`ruleId`, `level`, `locations`,
  `security-severity`), the same shape as other scanners; ATT&CK tags are in rule `properties.tags`.
* **Gates and CI:** `--fail-on high` returns exit 1; use it from guardian-gate / agent-harness style checks.
* **Chronicle / empire-audit:** the audit log is quietwire's own hash chain (`AuditLog.append(event, ts)`, optional HMAC).
  It has not been verified against Chronicle's or empire-audit's formats; adapting is a one-function change in
  `report/auditlog.py`.
* **Streaming:** `Engine(on_alert=callback)` is called for the first occurrence of each alert and at counts 10, 100, 1000, ...
