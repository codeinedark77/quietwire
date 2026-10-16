"""Machine-readable JSON report."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .. import __version__
from ..detect.engine import Result
from ..model import Severity
from ..util import iso_ts

REPORT_SCHEMA_VERSION = 1


def build_report(result: Result, source: str, fmt: str, input_sha256: Optional[str] = None,
                 policy_path: Optional[str] = None, policy_sections: Optional[List[str]] = None,
                 warnings: Optional[List[str]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    by_sev = {s.label: 0 for s in sorted(Severity, reverse=True)}
    for a in result.alerts:
        by_sev[a.severity.label] += 1
    first, last = result.first_ts, result.last_ts
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": "quietwire", "version": __version__},
        "input": {
            "source": source,
            "format": fmt,
            "sha256": input_sha256,
            "files": list(files) if files is not None else [{"path": source, "format": fmt, "sha256": input_sha256,
                                                              "packets": result.stats.packets}],
            "packets": result.stats.packets,
            "first_packet": iso_ts(first) if first is not None else None,
            "last_packet": iso_ts(last) if last is not None else None,
            "duration_seconds": round(last - first, 6) if first is not None and last is not None else 0.0,
        },
        "policy": {"path": policy_path, "enforced_sections": policy_sections or []},
        "summary": {
            "alerts_total": len(result.alerts),
            "alerts_by_severity": by_sev,
            "assets": len(result.inventory.assets),
            "flows": len(result.inventory.flows),
        },
        "stats": result.stats.to_dict(),
        "alerts": [a.to_dict() for a in result.alerts],
        "assets": [result.inventory.assets[ip].to_dict() for ip in sorted(result.inventory.assets)],
        "flows": [result.inventory.flows[k].to_dict() for k in sorted(result.inventory.flows)],
        "warnings": list(warnings or result.warnings),
    }


def render_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=False, ensure_ascii=True) + "\n"
