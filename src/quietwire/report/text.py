"""Human-readable text summary."""

from __future__ import annotations

from typing import Any, Dict, List

from ..util import iso_ts


def _table(rows: List[List[str]], header: List[str]) -> List[str]:
    widths = [len(h) for h in header]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    fmt = "  ".join("%%-%ds" % w for w in widths)
    lines = [fmt % tuple(header), fmt % tuple("-" * w for w in widths)]
    lines += [fmt % tuple(r) for r in rows]
    return [ln.rstrip() for ln in lines]


def render_text(report: Dict[str, Any], max_alerts: int = 200) -> str:
    inp = report["input"]
    summ = report["summary"]
    out: List[str] = []
    out.append("quietwire %s - passive ICS analysis" % report["tool"]["version"])
    out.append("input    : %s (%s)" % (inp["source"], inp["format"]))
    if inp.get("sha256"):
        out.append("sha256   : %s" % inp["sha256"])
    out.append("packets  : %d  (%s -> %s, %.3fs)" % (inp["packets"], inp["first_packet"], inp["last_packet"],
                                                    inp["duration_seconds"]))
    st = report["stats"]
    out.append("ICS msgs : %s" % (", ".join("%s=%d" % kv for kv in st["messages"].items()) or "none"))
    if st["malformed"]:
        out.append("malformed: %s" % ", ".join("%s=%d" % kv for kv in st["malformed"].items()))
    sev = summ["alerts_by_severity"]
    out.append("alerts   : %d  (%s)" % (summ["alerts_total"],
                                        ", ".join("%s=%d" % (k, v) for k, v in sev.items() if v) or "none"))
    out.append("")
    if report["alerts"]:
        rows = []
        for a in report["alerts"][:max_alerts]:
            rows.append([a["severity"].upper(), a["rule_id"], str(a["count"]), a["first_seen"][11:23],
                         a["message"] if len(a["message"]) <= 110 else a["message"][:107] + "..."])
        out += _table(rows, ["SEV", "RULE", "N", "FIRST(UTC)", "MESSAGE"])
        if len(report["alerts"]) > max_alerts:
            out.append("... %d more alerts omitted (see JSON/SARIF output)" % (len(report["alerts"]) - max_alerts))
        out.append("")
    if report["assets"]:
        rows = []
        for a in report["assets"]:
            protos = []
            for p, info in a["protocols"].items():
                role = "+".join(r for r in ("master", "server") if info[r]) or "-"
                protos.append("%s(%s)" % (p, role))
            ids = []
            if a.get("modbus_unit_ids"):
                ids.append("units=" + ",".join(map(str, a["modbus_unit_ids"][:6])))
            if a.get("dnp3_addresses"):
                ids.append("dnp3=" + ",".join(map(str, a["dnp3_addresses"][:6])))
            if a.get("s7_endpoints"):
                ids.append("s7=" + ",".join("r%ds%d" % (e["rack"], e["slot"]) for e in a["s7_endpoints"][:4]))
            rows.append([a["ip"], " ".join(protos), " ".join(ids), str(a["packets"])])
        out += ["Assets", ""] + _table(rows, ["IP", "PROTOCOLS", "IDENTIFIERS", "PKTS"]) + [""]
    if report["flows"]:
        rows = [[f["master"], f["server"] + ":" + str(f["server_port"]), f["protocol"], str(f["requests"]),
                 str(f["write_requests"]), str(f["exception_responses"])] for f in report["flows"]]
        out += ["Flows", ""] + _table(rows, ["MASTER", "SERVER", "PROTO", "REQ", "WRITES", "EXC"]) + [""]
    for w in report.get("warnings", []):
        out.append("warning: " + w)
    return "\n".join(out).rstrip() + "\n"
