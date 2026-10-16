# Deployment notes

quietwire is a *sensor*: it must see a copy of the OT traffic and must never be in its path.

## Placement
* Feed it from a **SPAN/mirror port or a network TAP** of the OT segment (both directions). The capture interface needs no IP
  address; keep the management interface separate. Mirroring over the network (ERSPAN II/III, GRE, VXLAN) is decapsulated for
  you; VLAN tags are fine.
* quietwire only receives. `capture` opens an `AF_PACKET` socket and calls `recvfrom`; the package contains no code path that
  transmits (a test enforces it). Promiscuous mode is a receive-side NIC setting (`--no-promisc` to skip it).
* Mirror both directions of a flow. One-sided captures are analysed but lose request/response pairing and role information;
  expect `QW-S001` and `role_inferred` flows.

## Live service
`deploy/quietwire.service` runs `quietwire capture` as an unprivileged `quietwire` user with only `CAP_NET_RAW`, a read-only
file system except `/var/lib/quietwire`, a syscall filter and `AF_PACKET`/`AF_UNIX` sockets only. It was syntax-checked with
`systemd-analyze verify` (systemd 255; exposure score 1.5) but **not run as a service** here; if it fails to start, relax
`MemoryDenyWriteExecute` and `SystemCallFilter` first. Set the interface in `/etc/quietwire/quietwire.env`.

The service overwrites `last-report.json` when it stops and streams alerts to the journal as they occur. For continuous
reporting prefer short capture windows (`--duration 3600` with `Restart=always`) or consume the audit log.

## Offline / rotated captures
```bash
tcpdump -i eth1 -s 0 -G 300 -w '/var/spool/qw/cap-%Y%m%d-%H%M%S.pcap' 'tcp port 502 or 20000 or 102 or 2404 or udp port 20000 or proto gre'
quietwire analyze $(ls -tr /var/spool/qw/cap-*.pcap) --policy policy.json --fail-on high --format sarif --out run.sarif
```
Files are analysed in the order given as one stream - pass them oldest first. Use a capture filter that keeps tunnel traffic
(GRE/UDP 4789) if your mirror is encapsulated.

## Policy lifecycle
1. Capture a representative window of **known-good** operation (include shift changes and maintenance windows you consider
   normal) and run `quietwire baseline`.
2. **Review the generated policy.** It permits everything it saw, including writes and critical operations; fill in
   `engineering_stations`, prune `writers`, narrow `write_ranges`, and review `allowed_functions`.
3. Run the enforced policy in shadow (alerts to a ticket queue, no gating) for at least a week; tune thresholds, add
   `ignore_rules`/`severity_overrides` with a comment (`_note` keys are allowed).
4. Only then wire `--fail-on` into gates.

## Audit log integrity
* The hash chain proves integrity *relative to an anchor*. After each run, store the printed **anchor** somewhere the sensor
  cannot write (remote syslog, a ticket, an append-only bucket). `verify-log --anchor` then catches truncation.
* With `--audit-key-file` each record carries an HMAC. Anyone who can rewrite the log but lacks the key cannot forge a
  consistent history. The sensor itself needs the key to write, so a compromised sensor can forge *new* records; keep older
  anchors off-box and treat the sensor as a witness, not a vault. Create keys with `quietwire audit-key` (mode 0600).
* Rotate by starting a new log file and archiving the old one together with its anchor.

## Monitoring the monitor
* `QW-P001` and the report's `tcp_gaps`, `tcp_out_of_window`, `ip_fragment_datagrams_expired` and (live) the kernel drop warning
  tell you when the picture is incomplete. A sensor that is silently dropping packets is worse than none.
* Capacity: ~35k packets/s on one core in the validation environment. OT segments are usually far below that; check yours.
* Check `skipped` in the JSON statistics for unsupported link types or fragments you chose not to reassemble.
