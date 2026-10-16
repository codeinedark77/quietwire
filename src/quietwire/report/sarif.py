"""SARIF 2.1.0 rendering.

Each alert becomes one SARIF result. For file captures the physical location
points at the byte offset of the first matching packet record in the capture so
a SARIF viewer / pipeline can jump straight to the evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List, Optional

from .. import __version__
from ..detect.engine import Result
from ..detect.rules import RULES
from ..model import Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {Severity.INFO: "note", Severity.LOW: "note", Severity.MEDIUM: "warning",
          Severity.HIGH: "error", Severity.CRITICAL: "error"}
_SECURITY_SEVERITY = {Severity.INFO: "0.0", Severity.LOW: "3.0", Severity.MEDIUM: "5.5",
                      Severity.HIGH: "8.0", Severity.CRITICAL: "9.5"}


def _fingerprint(alert) -> str:
    raw = json.dumps([str(x) for x in alert.key], sort_keys=False, ensure_ascii=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def render_sarif(result: Result, source: str, fmt: str, input_sha256: Optional[str] = None,
                 files: Optional[List[Dict[str, Any]]] = None) -> str:
    rule_ids = sorted(RULES)
    index = {rid: i for i, rid in enumerate(rule_ids)}
    rules: List[Dict[str, Any]] = []
    for rid in rule_ids:
        r = RULES[rid]
        entry: Dict[str, Any] = {
            "id": rid,
            "name": r.name.title().replace(" ", "").replace("/", "").replace("-", ""),
            "shortDescription": {"text": r.name},
            "fullDescription": {"text": r.description},
            "defaultConfiguration": {"level": _LEVEL[r.severity]},
            "properties": {
                "tags": ["ics", "ot", "network"] + ["external/mitre-attack-ics/" + t for t in r.mitre],
                "security-severity": _SECURITY_SEVERITY[r.severity],
            },
        }
        rules.append(entry)
    if files is None:
        files = [{"path": source, "format": fmt, "sha256": input_sha256}]
    file_based = bool(files) and all(f.get("format") in ("pcap", "pcapng") and f.get("path") not in ("-", "stdin")
                                     for f in files)
    uris = [os.path.basename(f["path"]) for f in files]
    results: List[Dict[str, Any]] = []
    for a in result.alerts:
        res: Dict[str, Any] = {
            "ruleId": a.rule_id,
            "ruleIndex": index[a.rule_id],
            "level": _LEVEL[a.severity],
            "message": {"text": a.message + (" (x%d)" % a.count if a.count > 1 else "")},
            "partialFingerprints": {"quietwire/v1": _fingerprint(a)},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[a.severity],
                "severity": a.severity.label,
                "protocol": a.protocol,
                "count": a.count,
                "source": "%s:%d" % (a.src_ip, a.src_port),
                "destination": "%s:%d" % (a.dst_ip, a.dst_port),
                "first_packet": a.first_packet.index,
                "last_packet": a.last_packet.index,
                "mitre_attack_ics": list(a.mitre),
            },
        }
        flow_name = "%s:%d->%s:%d/%s" % (a.src_ip, a.src_port, a.dst_ip, a.dst_port, a.transport)
        if file_based and a.first_packet.offset >= 0 and a.first_packet.source < len(uris):
            res["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uris[a.first_packet.source], "index": a.first_packet.source},
                    "region": {"byteOffset": a.first_packet.offset},
                },
                "logicalLocations": [{"fullyQualifiedName": flow_name, "kind": "resource"}],
            }]
        else:
            res["locations"] = [{"logicalLocations": [{"fullyQualifiedName": flow_name, "kind": "resource"}]}]
        results.append(res)
    run: Dict[str, Any] = {
        "tool": {"driver": {"name": "quietwire", "version": __version__, "semanticVersion": __version__,
                            "rules": rules}},
        "results": results,
        "invocations": [{"executionSuccessful": True}],
        "properties": {"packets": result.stats.packets},
    }
    if file_based:
        run["artifacts"] = []
        for f, uri in zip(files, uris):
            art: Dict[str, Any] = {"location": {"uri": uri}, "mimeType": "application/vnd.tcpdump.pcap"}
            if f.get("sha256"):
                art["hashes"] = {"sha-256": f["sha256"]}
            run["artifacts"].append(art)
    doc = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"
