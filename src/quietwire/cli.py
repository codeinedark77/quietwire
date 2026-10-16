"""Command line interface."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import signal
import stat
import sys
import time
from typing import Any, Dict, List, Optional

from . import __version__
from .capture.pcap import CaptureReader
from .capture.pcapwriter import PcapWriter
from .detect.engine import Config, Engine, Result
from .detect.policy import Policy, build_baseline, load_policy
from .detect.mitre import ATTACK_ICS_VERSION, TECHNIQUES, VERIFIED_ON
from .detect.rules import RULES
from .errors import AuditLogError, CaptureFormatError, PolicyError, QuietwireError
from .model import Alert, Severity
from .report.auditlog import AuditLog, verify_log
from .report.jsonout import build_report, render_json
from .report.sarif import render_sarif
from .report.text import render_text

EXIT_OK = 0
EXIT_THRESHOLD = 1   # --fail-on threshold reached (analyze/capture) or log verification failed
# argparse exits with 2 for command-line syntax errors
EXIT_INPUT = 3       # unreadable/invalid capture, policy or audit log


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _severity(text: str) -> Severity:
    try:
        return Severity.parse(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def _alert_event(alert: Alert, update: bool) -> Dict[str, Any]:
    d = alert.to_dict()
    d.pop("samples", None)
    d["event"] = "alert"
    d["update"] = update
    return d


def _write_output(text: str, out: Optional[str]) -> None:
    if out and out != "-":
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except BrokenPipeError:  # pragma: no cover - interactive convenience
            try:
                sys.stdout.close()
            except Exception:
                pass


def _load_key(path: Optional[str]) -> Optional[bytes]:
    if not path:
        return None
    try:
        with open(path, "rb") as fh:
            key = fh.read().strip()
    except OSError as exc:
        raise QuietwireError("cannot read audit key file %s: %s" % (path, exc))
    if len(key) < 16:
        raise QuietwireError("audit key file %s holds %d bytes; need at least 16 (use `quietwire audit-key`)"
                             % (path, len(key)))
    return key


def _render(result: Result, fmt: str, source: str, source_fmt: str, sha: Optional[str],
            policy: Policy, policy_path: Optional[str], warnings: List[str],
            files: Optional[List[Dict[str, Any]]] = None) -> str:
    if fmt == "sarif":
        return render_sarif(result, source, source_fmt, sha, files)
    report = build_report(result, source, source_fmt, sha, policy_path, policy.enforced_sections(), warnings, files)
    return render_json(report) if fmt == "json" else render_text(report)


def _exceeds(result: Result, threshold: Optional[Severity]) -> bool:
    return threshold is not None and any(a.severity >= threshold for a in result.alerts)


# ---------------------------------------------------------------- analyze
def cmd_analyze(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy) if args.policy else Policy()
    cfg = Config(min_severity=args.min_severity, identify_nonstandard=not args.no_identify)
    paths: List[str] = args.captures
    if paths.count("-") > 1 or ("-" in paths and len(paths) > 1):
        raise QuietwireError("'-' (stdin) cannot be combined with other inputs")
    for path in paths:
        if path != "-" and not os.path.isfile(path):
            raise QuietwireError("capture file not found: %s" % path)
    audit = AuditLog(args.audit_log, key=_load_key(args.audit_key_file)) if args.audit_log else None
    files: List[Dict[str, Any]] = []
    for path in paths:
        files.append({"path": "stdin" if path == "-" else path, "format": None,
                      "sha256": None if path == "-" else _sha256_file(path), "packets": 0})
    if audit:
        audit.append({"event": "analysis_start", "tool": "quietwire", "version": __version__,
                      "files": [{"name": os.path.basename(f["path"]), "sha256": f["sha256"]} for f in files],
                      "policy": os.path.basename(args.policy) if args.policy else None,
                      "policy_sections": policy.enforced_sections()}, time.time())

    def on_alert(alert: Alert, update: bool) -> None:
        if audit:
            audit.append(_alert_event(alert, update), time.time())

    engine = Engine(policy, cfg, on_alert if audit else None)
    warnings: List[str] = []
    base = 0
    try:
        for i, path in enumerate(paths):
            reader = CaptureReader(sys.stdin.buffer if path == "-" else path)
            files[i]["format"] = reader.format
            engine.source_index = i
            try:
                for raw in reader:
                    if base:
                        raw = dataclasses.replace(raw, index=raw.index + base)
                    engine.process(raw)
                    files[i]["packets"] += 1
            except CaptureFormatError as exc:
                warnings.append("%s ended early: %s" % (os.path.basename(files[i]["path"]), exc))
            warnings.extend("%s: %s" % (os.path.basename(files[i]["path"]), w) for w in reader.warnings)
            base += files[i]["packets"]
    except CaptureFormatError:
        if audit:
            audit.close()
        raise
    result = engine.finalize()
    result.warnings = warnings
    if audit:
        audit.append({"event": "analysis_end", "packets": result.stats.packets, "alerts": len(result.alerts),
                      "by_severity": {s.label: sum(1 for a in result.alerts if a.severity == s) for s in Severity},
                      "warnings": warnings}, time.time())
        sys.stderr.write("audit log anchor (store externally to detect truncation): %s\n" % audit.anchor)
        audit.close()
    single = len(files) == 1
    source = files[0]["path"] if single else "%d files" % len(files)
    fmt = files[0]["format"] if single else "mixed" if len({f["format"] for f in files}) > 1 else files[0]["format"]
    text = _render(result, args.format, source, fmt, files[0]["sha256"] if single else None, policy, args.policy,
                   warnings, files)
    _write_output(text, args.out)
    return EXIT_THRESHOLD if _exceeds(result, args.fail_on) else EXIT_OK


# --------------------------------------------------------------- baseline
def cmd_baseline(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.capture):
        raise QuietwireError("capture file not found: %s" % args.capture)
    engine = Engine(Policy(), Config(identify_nonstandard=not args.no_identify), None, rules=[])
    reader = CaptureReader(args.capture)
    for raw in reader:
        engine.process(raw)
    result = engine.finalize()
    doc = build_baseline(result.inventory)
    doc["_source_capture"] = {"file": os.path.basename(args.capture), "sha256": _sha256_file(args.capture),
                              "packets": result.stats.packets}
    _write_output(json.dumps(doc, indent=2) + "\n", args.out)
    if not doc["allowed_flows"]:
        sys.stderr.write("warning: no ICS traffic found in capture; baseline is empty\n")
    return EXIT_OK


# ---------------------------------------------------------------- capture
def cmd_capture(args: argparse.Namespace) -> int:
    from .capture.live import LiveCapture

    policy = load_policy(args.policy) if args.policy else Policy()
    cfg = Config(min_severity=args.min_severity, identify_nonstandard=not args.no_identify)
    audit = AuditLog(args.audit_log, key=_load_key(args.audit_key_file)) if args.audit_log else None
    cap = LiveCapture(args.interface, promisc=not args.no_promisc, duration=args.duration, max_packets=args.count)
    saver = PcapWriter(args.save_pcap) if args.save_pcap else None

    def on_alert(alert: Alert, update: bool) -> None:
        tag = "UPDATE" if update else "ALERT "
        sys.stderr.write("[%s] %s %-8s %s x%d  %s\n" % (time.strftime("%H:%M:%S"), tag, alert.severity.label.upper(),
                                                      alert.rule_id, alert.count, alert.message))
        sys.stderr.flush()
        if audit:
            audit.append(_alert_event(alert, update), time.time())

    engine = Engine(policy, cfg, on_alert)
    if audit:
        audit.append({"event": "capture_start", "tool": "quietwire", "version": __version__,
                      "interface": args.interface, "promiscuous": not args.no_promisc,
                      "policy_sections": policy.enforced_sections()}, time.time())

    def _stop(_sig, _frm) -> None:
        cap.stop()

    old_int = signal.signal(signal.SIGINT, _stop)
    old_term = signal.signal(signal.SIGTERM, _stop)
    try:
        for raw in cap:
            engine.process(raw)
            if saver:
                saver.write(raw.ts, raw.data)
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        cap.close()
        if saver:
            saver.close()
    result = engine.finalize()
    warnings: List[str] = []
    if cap.kernel_drops:
        warnings.append("the kernel dropped %d of %d frames (capture too slow for the link): results are incomplete"
                        % (cap.kernel_drops, cap.kernel_packets))
        sys.stderr.write("warning: " + warnings[-1] + "\n")
    if audit:
        audit.append({"event": "capture_end", "packets": result.stats.packets, "alerts": len(result.alerts),
                      "kernel_packets": cap.kernel_packets, "kernel_drops": cap.kernel_drops}, time.time())
        sys.stderr.write("audit log anchor (store externally to detect truncation): %s\n" % audit.anchor)
        audit.close()
    text = _render(result, args.format, "live:" + args.interface, "live", None, policy, args.policy, warnings)
    _write_output(text, args.out)
    return EXIT_THRESHOLD if _exceeds(result, args.fail_on) else EXIT_OK


# ----------------------------------------------------------- verify-log
def cmd_verify_log(args: argparse.Namespace) -> int:
    key = _load_key(args.audit_key_file)
    res = verify_log(args.log, args.anchor, key)
    if res.ok:
        how = "chain intact, macs verified" if res.mac_verified else (
            "chain intact (keyed log: macs NOT verified, no key supplied)" if res.keyed else "chain intact")
        print("OK: %d records, %s, last hash %s" % (res.records, how, res.last_hash))
        return EXIT_OK
    print("FAILED: %s%s (verified %d records before failure)"
          % (res.error, " at line %d" % res.line if res.line else "", res.records))
    return EXIT_THRESHOLD


# -------------------------------------------------------------- audit-key
def cmd_audit_key(args: argparse.Namespace) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(args.path, flags, stat.S_IRUSR | stat.S_IWUSR)
    except FileExistsError:
        raise QuietwireError("%s already exists; refusing to overwrite a key" % args.path)
    except OSError as exc:
        raise QuietwireError("cannot create %s: %s" % (args.path, exc))
    with os.fdopen(fd, "wb") as fh:
        fh.write(os.urandom(32).hex().encode("ascii") + b"\n")
    print("wrote a 256-bit key to %s (mode 0600). Keep it OFF the host that writes the audit log if that host is "
          "in your threat model." % args.path)
    return EXIT_OK


# ------------------------------------------------------------------ rules
def cmd_rules(args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps([{"id": r.id, "name": r.name, "default_severity": r.severity.label,
                           "description": r.description, "mitre_attack_ics": list(r.mitre)}
                          for r in RULES.values()], indent=2))
        return EXIT_OK
    for r in RULES.values():
        print("%s  %-8s %s%s" % (r.id, r.severity.label, r.name, "  [" + ",".join(r.mitre) + "]" if r.mitre else ""))
        print("          " + r.description)
    print("\nATT&CK for ICS %s technique ids (verified %s): %s" % (
        ATTACK_ICS_VERSION, VERIFIED_ON, "; ".join("%s %s" % kv for kv in sorted(TECHNIQUES.items()))))
    return EXIT_OK


# ------------------------------------------------------------------- demo
def cmd_demo(args: argparse.Namespace) -> int:
    from . import synth

    os.makedirs(args.outdir, exist_ok=True)
    base = synth.scenario_baseline()
    base.write_pcap(os.path.join(args.outdir, "baseline.pcap"))
    attack = synth.scenario_baseline(synth.PcapBuilder(start_ts=1_700_100_000.0), cycles=5)
    synth.scenario_attack(attack)
    attack.write_pcap(os.path.join(args.outdir, "attack.pcap"))
    with open(os.path.join(args.outdir, "policy.json"), "w") as fh:
        json.dump(synth.demo_policy(), fh, indent=2)
        fh.write("\n")
    print("wrote baseline.pcap, attack.pcap and policy.json to %s" % args.outdir)
    print("try:")
    print("  quietwire analyze %s/baseline.pcap --policy %s/policy.json" % (args.outdir, args.outdir))
    print("  quietwire analyze %s/attack.pcap   --policy %s/policy.json --fail-on high" % (args.outdir, args.outdir))
    return EXIT_OK


# ------------------------------------------------------------------ parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="quietwire",
                                description="Passive ICS/OT protocol analyzer (Modbus/TCP, DNP3, S7comm). "
                                            "Receive-only: never transmits.")
    p.add_argument("--version", action="version", version="quietwire " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser, live: bool = False) -> None:
        sp.add_argument("--policy", help="JSON policy file (see README)")
        sp.add_argument("--format", choices=("text", "json", "sarif"), default="text")
        sp.add_argument("--out", help="write the report here instead of stdout")
        sp.add_argument("--audit-log", help="append alerts to a tamper-evident hash-chained JSONL log")
        sp.add_argument("--audit-key-file", help="HMAC key file: every audit record also carries an HMAC-SHA256 mac "
                                                 "(see `quietwire audit-key`)")
        sp.add_argument("--min-severity", type=_severity, default=Severity.INFO,
                        help="suppress alerts below this severity (info|low|medium|high|critical)")
        sp.add_argument("--fail-on", type=_severity, default=None,
                        help="exit with status 2 if any alert is at or above this severity")
        sp.add_argument("--no-identify", action="store_true",
                        help="do not try to identify ICS protocols on non-standard ports")

    a = sub.add_parser("analyze", help="analyse pcap/pcapng file(s) in the order given (or '-' for stdin)")
    a.add_argument("captures", nargs="+", metavar="CAPTURE",
                   help="one or more captures, treated as one continuous stream (e.g. rotated tcpdump files, oldest first)")
    common(a)
    a.set_defaults(func=cmd_analyze)

    b = sub.add_parser("baseline", help="derive a starting-point policy from a capture of known-good traffic")
    b.add_argument("capture")
    b.add_argument("--out", help="write the policy here instead of stdout")
    b.add_argument("--no-identify", action="store_true")
    b.set_defaults(func=cmd_baseline)

    c = sub.add_parser("capture", help="live receive-only capture on a Linux interface (needs root/CAP_NET_RAW)")
    c.add_argument("--interface", "-i", required=True)
    c.add_argument("--duration", type=float, default=0.0, help="stop after N seconds (default: until Ctrl-C)")
    c.add_argument("--count", type=int, default=0, help="stop after N packets")
    c.add_argument("--save-pcap", help="also write captured frames to this pcap file")
    c.add_argument("--no-promisc", action="store_true", help="do not enable promiscuous mode")
    common(c, live=True)
    c.set_defaults(func=cmd_capture)

    v = sub.add_parser("verify-log", help="verify an audit log hash chain")
    v.add_argument("log")
    v.add_argument("--anchor", help="expected final hash (detects tail truncation)")
    v.add_argument("--audit-key-file", help="HMAC key file (verifies the per-record macs)")
    v.set_defaults(func=cmd_verify_log)

    k = sub.add_parser("audit-key", help="create a random HMAC key file (mode 0600) for keyed audit logs")
    k.add_argument("path")
    k.set_defaults(func=cmd_audit_key)

    r = sub.add_parser("rules", help="list detection rules")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_rules)

    d = sub.add_parser("demo", help="write demo captures and a matching policy")
    d.add_argument("outdir")
    d.set_defaults(func=cmd_demo)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (PolicyError, CaptureFormatError, AuditLogError, QuietwireError) as exc:
        sys.stderr.write("quietwire: error: %s\n" % exc)
        return EXIT_INPUT
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
