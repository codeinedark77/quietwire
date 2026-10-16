"""Policy file: schema validation, matching helpers and baseline generation.

Semantics: a policy section that is *absent* is not enforced; a section that is
*present* is enforced strictly (an empty list means "nothing is allowed").
Unknown top-level keys are rejected (typos must not silently disable a check);
keys starting with ``_`` are free-form annotations and ignored.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field, fields
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..errors import PolicyError
from ..model import Severity, Target

PROTOCOLS = ("modbus", "dnp3", "s7comm", "iec104")
_TOP_KEYS = {"version", "assets", "enforce_assets", "allowed_flows", "writers", "engineering_stations",
             "write_ranges", "allowed_functions", "ignore_rules", "severity_overrides", "thresholds"}


class IPMatcher:
    """Match IPs against exact addresses, CIDR networks and ``*``."""

    def __init__(self, patterns: Iterable[str]):
        self.any = False
        self._exact: Set[str] = set()
        self._nets: List[Any] = []
        self._cache: Dict[str, bool] = {}
        for p in patterns:
            self.add(p)

    def add(self, pattern: str) -> None:
        if pattern == "*":
            self.any = True
            return
        try:
            if "/" in pattern:
                self._nets.append(ipaddress.ip_network(pattern, strict=False))
            else:
                self._exact.add(ipaddress.ip_address(pattern).compressed)
        except ValueError:
            raise PolicyError("invalid IP address or network %r" % pattern)
        self._cache.clear()

    def matches(self, ip: str) -> bool:
        if self.any:
            return True
        hit = self._cache.get(ip)
        if hit is not None:
            return hit
        res = ip in self._exact
        if not res and self._nets:
            try:
                addr = ipaddress.ip_address(ip)
                res = any(addr in n for n in self._nets if n.version == addr.version)
            except ValueError:
                res = False
        if len(self._cache) < 65536:
            self._cache[ip] = res
        return res

    def __bool__(self) -> bool:
        return self.any or bool(self._exact) or bool(self._nets)


@dataclass
class FlowRule:
    master: IPMatcher
    server: IPMatcher
    protocol: Optional[str]
    port: Optional[int]

    def matches(self, master: str, server: str, protocol: str, port: int) -> bool:
        return ((self.protocol is None or self.protocol == protocol)
                and (self.port is None or self.port == port)
                and self.master.matches(master) and self.server.matches(server))


@dataclass
class FunctionRule:
    master: IPMatcher
    server: IPMatcher
    protocol: Optional[str]
    names: frozenset
    kinds: frozenset
    wildcard: bool

    def covers_path(self, master: str, server: str, protocol: str) -> bool:
        return ((self.protocol is None or self.protocol == protocol)
                and self.master.matches(master) and self.server.matches(server))

    def permits(self, function: str, message_kinds: frozenset) -> bool:
        return self.wildcard or function in self.names or bool(self.kinds & message_kinds)


@dataclass
class WriteRange:
    server: IPMatcher
    protocol: str
    unit: Optional[int]
    area: str
    start: int
    end: int


@dataclass
class Policy:
    assets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    enforce_assets: bool = False
    allowed_flows: Optional[List[FlowRule]] = None
    writers: Dict[str, IPMatcher] = field(default_factory=dict)
    engineering_stations: IPMatcher = field(default_factory=lambda: IPMatcher([]))
    write_ranges: List[WriteRange] = field(default_factory=list)
    allowed_functions: Optional[List[FunctionRule]] = None
    ignore_rules: Set[str] = field(default_factory=set)
    severity_overrides: Dict[str, Severity] = field(default_factory=dict)
    thresholds: Dict[str, Any] = field(default_factory=dict)
    _asset_matcher: Optional[IPMatcher] = None

    # -- queries ---------------------------------------------------------
    def enforced_sections(self) -> List[str]:
        out = []
        if self.enforce_assets:
            out.append("assets")
        if self.allowed_flows is not None:
            out.append("allowed_flows")
        for proto in sorted(self.writers):
            out.append("writers.%s" % proto)
        if self.engineering_stations:
            out.append("engineering_stations")
        if self.write_ranges:
            out.append("write_ranges")
        if self.allowed_functions is not None:
            out.append("allowed_functions")
        return out

    def asset_known(self, ip: str) -> bool:
        if self._asset_matcher is None:
            self._asset_matcher = IPMatcher(self.assets.keys())
        return self._asset_matcher.matches(ip)

    def flow_allowed(self, master: str, server: str, protocol: str, port: int) -> bool:
        if self.allowed_flows is None:
            return True
        return any(r.matches(master, server, protocol, port) for r in self.allowed_flows)

    def writer_allowed(self, protocol: str, ip: str) -> Optional[bool]:
        """None when writer enforcement is off for this protocol."""
        m = self.writers.get(protocol)
        if m is None:
            return None
        return m.matches(ip)

    def function_allowed(self, master: str, server: str, protocol: str, function: str,
                         kinds: frozenset) -> Optional[bool]:
        """None when no allowed_functions entry covers this path; else whether the function is permitted."""
        if self.allowed_functions is None:
            return None
        covering = [r for r in self.allowed_functions if r.covers_path(master, server, protocol)]
        if not covering:
            return None
        return any(r.permits(function, kinds) for r in covering)

    def is_engineering_station(self, ip: str) -> bool:
        return self.engineering_stations.matches(ip)

    def range_violations(self, server: str, protocol: str, unit: Optional[int],
                         targets: Tuple[Target, ...]) -> Optional[List[Target]]:
        """Return the targets outside permitted ranges, or None if ranges aren't enforced here."""
        applicable = [r for r in self.write_ranges
                      if r.protocol == protocol and r.server.matches(server)
                      and (r.unit is None or unit is None or r.unit == unit)]
        if not applicable:
            return None
        if not targets:
            return []  # caller treats "enforced but indeterminable" separately
        bad = []
        for t in targets:
            if not any(r.area == t.area and r.start <= t.start and t.end <= r.end for r in applicable):
                bad.append(t)
        return bad

    def ranges_enforced_for(self, server: str, protocol: str, unit: Optional[int]) -> bool:
        return any(r.protocol == protocol and r.server.matches(server)
                   and (r.unit is None or unit is None or r.unit == unit) for r in self.write_ranges)


# -- loading ---------------------------------------------------------------
def _err(path: str, msg: str) -> PolicyError:
    return PolicyError("%s: %s" % (path, msg))


def _as_list(v: Any, path: str) -> list:
    if not isinstance(v, list):
        raise _err(path, "must be a list")
    return v


def _as_int(v: Any, path: str, lo: int, hi: int) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise _err(path, "must be an integer in %d..%d" % (lo, hi))
    return v


def _ip_list(v: Any, path: str) -> IPMatcher:
    items = _as_list(v, path)
    for i, x in enumerate(items):
        if not isinstance(x, str):
            raise _err("%s[%d]" % (path, i), "must be a string")
    try:
        return IPMatcher(items)
    except PolicyError as exc:
        raise _err(path, str(exc))


def _protocol(v: Any, path: str, allow_none: bool = False) -> Optional[str]:
    if v is None and allow_none:
        return None
    if v not in PROTOCOLS:
        raise _err(path, "must be one of %s" % ", ".join(PROTOCOLS))
    return v


def parse_policy(doc: Any) -> Policy:
    if not isinstance(doc, dict):
        raise PolicyError("policy root must be a JSON object")
    unknown = [k for k in doc if k not in _TOP_KEYS and not str(k).startswith("_")]
    if unknown:
        raise PolicyError("unknown policy key(s): %s (known: %s)" % (", ".join(sorted(unknown)),
                                                                   ", ".join(sorted(_TOP_KEYS))))
    if doc.get("version", 1) != 1:
        raise PolicyError("unsupported policy version %r (this build understands version 1)" % doc.get("version"))
    pol = Policy()
    if "assets" in doc:
        for i, a in enumerate(_as_list(doc["assets"], "assets")):
            path = "assets[%d]" % i
            if not isinstance(a, dict) or not isinstance(a.get("ip"), str):
                raise _err(path, "must be an object with a string 'ip'")
            bad = [k for k in a if k not in ("ip", "name", "role")]
            if bad:
                raise _err(path, "unknown key(s) %s" % ", ".join(sorted(bad)))
            try:
                IPMatcher([a["ip"]])
            except PolicyError as exc:
                raise _err(path + ".ip", str(exc))
            pol.assets[a["ip"]] = {k: a[k] for k in ("name", "role") if k in a}
        pol.enforce_assets = True
    if "enforce_assets" in doc:
        if not isinstance(doc["enforce_assets"], bool):
            raise _err("enforce_assets", "must be true or false")
        pol.enforce_assets = doc["enforce_assets"]
    if "allowed_flows" in doc:
        rules = []
        for i, f in enumerate(_as_list(doc["allowed_flows"], "allowed_flows")):
            path = "allowed_flows[%d]" % i
            if not isinstance(f, dict):
                raise _err(path, "must be an object")
            bad = [k for k in f if k not in ("master", "server", "protocol", "port")]
            if bad:
                raise _err(path, "unknown key(s) %s" % ", ".join(sorted(bad)))
            for req in ("master", "server"):
                if req not in f:
                    raise _err(path, "missing required key '%s'" % req)
            port = None
            if "port" in f:
                port = _as_int(f["port"], path + ".port", 1, 65535)
            rules.append(FlowRule(
                master=_ip_list(f["master"] if isinstance(f["master"], list) else [f["master"]], path + ".master"),
                server=_ip_list(f["server"] if isinstance(f["server"], list) else [f["server"]], path + ".server"),
                protocol=_protocol(f.get("protocol"), path + ".protocol", allow_none=True),
                port=port))
        pol.allowed_flows = rules
    if "writers" in doc:
        w = doc["writers"]
        if not isinstance(w, dict):
            raise _err("writers", "must be an object mapping protocol -> list of IPs")
        for proto, ips in w.items():
            _protocol(proto, "writers.%s" % proto)
            pol.writers[proto] = _ip_list(ips, "writers.%s" % proto)
    if "engineering_stations" in doc:
        pol.engineering_stations = _ip_list(doc["engineering_stations"], "engineering_stations")
    if "write_ranges" in doc:
        for i, r in enumerate(_as_list(doc["write_ranges"], "write_ranges")):
            path = "write_ranges[%d]" % i
            if not isinstance(r, dict):
                raise _err(path, "must be an object")
            bad = [k for k in r if k not in ("server", "protocol", "unit", "area", "start", "end")]
            if bad:
                raise _err(path, "unknown key(s) %s" % ", ".join(sorted(bad)))
            for req in ("server", "protocol", "area", "start", "end"):
                if req not in r:
                    raise _err(path, "missing required key '%s'" % req)
            if not isinstance(r["area"], str) or not r["area"]:
                raise _err(path + ".area", "must be a non-empty string")
            start = _as_int(r["start"], path + ".start", 0, 0xFFFFFFFF)
            end = _as_int(r["end"], path + ".end", 0, 0xFFFFFFFF)
            if end < start:
                raise _err(path, "end < start")
            unit = _as_int(r["unit"], path + ".unit", 0, 0xFFFF) if "unit" in r else None
            pol.write_ranges.append(WriteRange(
                server=_ip_list(r["server"] if isinstance(r["server"], list) else [r["server"]], path + ".server"),
                protocol=_protocol(r["protocol"], path + ".protocol"), unit=unit,
                area=r["area"], start=start, end=end))
    if "allowed_functions" in doc:
        from ..proto import FUNCTION_KINDS, function_names

        entries: List[FunctionRule] = []
        for i, f in enumerate(_as_list(doc["allowed_functions"], "allowed_functions")):
            path = "allowed_functions[%d]" % i
            if not isinstance(f, dict):
                raise _err(path, "must be an object")
            bad = [k for k in f if k not in ("master", "server", "protocol", "functions")]
            if bad:
                raise _err(path, "unknown key(s) %s" % ", ".join(sorted(bad)))
            for req in ("master", "server", "functions"):
                if req not in f:
                    raise _err(path, "missing required key '%s'" % req)
            proto = _protocol(f.get("protocol"), path + ".protocol", allow_none=True)
            catalogue = (function_names(proto) if proto else
                         frozenset().union(*(function_names(p) for p in PROTOCOLS)))
            names, kinds, wildcard = set(), set(), False
            for j, fn in enumerate(_as_list(f["functions"], path + ".functions")):
                if not isinstance(fn, str) or not fn:
                    raise _err("%s.functions[%d]" % (path, j), "must be a non-empty string")
                if fn == "*":
                    wildcard = True
                elif fn.startswith("@"):
                    if fn[1:] not in FUNCTION_KINDS:
                        raise _err("%s.functions[%d]" % (path, j), "unknown tag %r (known: %s)"
                                   % (fn, ", ".join("@" + k for k in sorted(FUNCTION_KINDS))))
                    kinds.add(fn[1:])
                elif fn in catalogue or fn.startswith("UNKNOWN_"):
                    names.add(fn)
                else:
                    raise _err("%s.functions[%d]" % (path, j), "unknown function name %r%s" % (
                        fn, " for protocol %s" % proto if proto else ""))
            entries.append(FunctionRule(
                master=_ip_list(f["master"] if isinstance(f["master"], list) else [f["master"]], path + ".master"),
                server=_ip_list(f["server"] if isinstance(f["server"], list) else [f["server"]], path + ".server"),
                protocol=proto, names=frozenset(names), kinds=frozenset(kinds), wildcard=wildcard))
        pol.allowed_functions = entries
    if "ignore_rules" in doc:
        ids = _as_list(doc["ignore_rules"], "ignore_rules")
        from .rules import RULES
        for x in ids:
            if x not in RULES:
                raise _err("ignore_rules", "unknown rule id %r" % (x,))
        pol.ignore_rules = set(ids)
    if "severity_overrides" in doc:
        so = doc["severity_overrides"]
        if not isinstance(so, dict):
            raise _err("severity_overrides", "must be an object mapping rule id -> severity")
        from .rules import RULES
        for rid, sev in so.items():
            if rid not in RULES:
                raise _err("severity_overrides", "unknown rule id %r" % rid)
            try:
                pol.severity_overrides[rid] = Severity.parse(str(sev))
            except ValueError as exc:
                raise _err("severity_overrides.%s" % rid, str(exc))
    if "thresholds" in doc:
        th = doc["thresholds"]
        if not isinstance(th, dict):
            raise _err("thresholds", "must be an object")
        from .engine import Config
        valid = {f.name: f.type for f in fields(Config) if f.name in Config.TUNABLE}
        for k, v in th.items():
            if k not in valid:
                raise _err("thresholds", "unknown threshold %r (tunable: %s)" % (k, ", ".join(sorted(valid))))
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
                raise _err("thresholds.%s" % k, "must be a non-negative number")
        pol.thresholds = dict(th)
    return pol


def load_policy(path: str) -> Policy:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        raise PolicyError("cannot read policy %s: %s" % (path, exc))
    except ValueError as exc:
        raise PolicyError("policy %s is not valid JSON: %s" % (path, exc))
    return parse_policy(doc)


# -- baseline generation ---------------------------------------------------
def _merge_intervals(iv: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for s, e in sorted(iv):
        if out and s <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def build_baseline(inv: "Any", max_ranges_per_key: int = 64) -> Dict[str, Any]:
    """Derive a policy document from observed (assumed clean) traffic.

    The result is a *starting point for human review*: it permits everything
    that was observed, including any writes and critical operations.
    """
    assets = []
    for ip in sorted(inv.assets):
        a = inv.assets[ip]
        roles = set()
        for p in a.protocols.values():
            if p["master"]:
                roles.add("master")
            if p["server"]:
                roles.add("server")
        role = "both" if len(roles) == 2 else (next(iter(roles)) if roles else "unknown")
        assets.append({"ip": ip, "role": role})
    flows = []
    functions = []
    writers: Dict[str, Set[str]] = {p: set() for p in PROTOCOLS}
    critical_seen = []
    for key in sorted(inv.flows):
        f = inv.flows[key]
        flows.append({"master": f.master, "server": f.server, "protocol": f.protocol, "port": f.server_port})
        if f.request_functions:
            functions.append({"master": f.master, "server": f.server, "protocol": f.protocol,
                              "functions": sorted(f.request_functions)})
        if f.write_requests:
            writers[f.protocol].add(f.master)
        if f.critical_functions:
            critical_seen.append({"master": f.master, "server": f.server, "protocol": f.protocol,
                                  "functions": sorted(f.critical_functions)})
    ranges: List[Dict[str, Any]] = []
    for (server, protocol, unit, area), ivs in sorted(inv.write_targets.items(), key=lambda kv: str(kv[0])):
        merged = _merge_intervals(ivs)
        if len(merged) > max_ranges_per_key:
            merged = [(merged[0][0], merged[-1][1])]
        for s, e in merged:
            entry: Dict[str, Any] = {"server": server, "protocol": protocol, "area": area, "start": s, "end": e}
            if unit is not None:
                entry["unit"] = unit
            ranges.append(entry)
    doc: Dict[str, Any] = {
        "version": 1,
        "_generated_by": "quietwire baseline",
        "_review": ("Generated from observed traffic; it permits everything seen, including writes and critical "
                    "operations. Review before enforcing. engineering_stations is intentionally empty."),
        "assets": assets,
        "allowed_flows": flows,
        "writers": {p: sorted(ips) for p, ips in writers.items() if inv.protocol_seen(p)},
        "engineering_stations": [],
        "write_ranges": ranges,
        "allowed_functions": functions,
    }
    if critical_seen:
        doc["_observed_critical_operations"] = critical_seen
    return doc
