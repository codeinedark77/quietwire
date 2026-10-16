"""Detection rules.

Each rule inspects one message (or TCP SYN contact) together with its flow
context and yields :class:`Finding` objects. De-duplication/aggregation is done
by the engine using ``Finding.key``.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

from ..model import PacketRef, ProtoMessage, Severity


@dataclass(frozen=True)
class RuleInfo:
    id: str
    name: str
    severity: Severity
    description: str
    mitre: Tuple[str, ...] = ()


def _rules(*items: RuleInfo) -> Dict[str, RuleInfo]:
    return {r.id: r for r in items}


S = Severity
RULES: Dict[str, RuleInfo] = _rules(
    RuleInfo("QW-A001", "Asset not in policy", S.MEDIUM,
             "A host speaking an ICS protocol is not listed in the policy asset inventory."),
    RuleInfo("QW-F001", "Communication path not allowed by policy", S.HIGH,
             "A master/server/protocol/port combination is not covered by allowed_flows."),
    RuleInfo("QW-F002", "Function not allowed on this communication path", S.HIGH,
             "A request used a protocol function that the policy's allowed_functions does not permit for this "
             "master/server pair.", ()),
    RuleInfo("QW-W001", "Write or control from unauthorised source", S.HIGH,
             "A host that is not listed as a writer for this protocol issued a write or control operation.",
             ("T1692.001", "T0836")),
    RuleInfo("QW-W002", "Write or control operation observed (no writer policy)", S.LOW,
             "A write or control operation was observed and no writer policy exists for the protocol.",
             ("T0836",)),
    RuleInfo("QW-W003", "Write outside permitted ranges", S.HIGH,
             "A write targeted addresses outside the write_ranges permitted for the server.",
             ("T0836", "T1692.001")),
    RuleInfo("QW-C001", "Critical operation", S.HIGH,
             "Restart, stop, mode change, program transfer or similar high-impact operation from a host that is "
             "not a declared engineering station."),
    RuleInfo("QW-C002", "Broadcast command", S.HIGH,
             "A command addressed to a broadcast / all-stations address (DNP3 0xFFFD-0xFFFF, IEC 104 common address 0xFFFF, Modbus unit 0).",
             ("T1692.001",)),
    RuleInfo("QW-R001", "Host sweep", S.MEDIUM,
             "One master contacted many previously unseen servers in a short window.", ("T0846",)),
    RuleInfo("QW-R002", "Unit/address sweep", S.MEDIUM,
             "One master probed many previously unseen unit ids / link addresses on a server.", ("T0846",)),
    RuleInfo("QW-R003", "Device fingerprinting", S.LOW,
             "Device identification / block listing / SZL read request.", ("T0888",)),
    RuleInfo("QW-M001", "Malformed message or protocol violation", S.MEDIUM,
             "Framing or structural violation (possible fuzzing, evasion or implementation bug)."),
    RuleInfo("QW-M003", "Conflicting overlapping IP fragments", S.MEDIUM,
             "Overlapping IP fragments carried different bytes: a reassembly-evasion technique (the receiver and "
             "monitor may reconstruct different data)."),
    RuleInfo("QW-M002", "Unknown or undefined function code", S.MEDIUM,
             "A request used a function code outside the public protocol definition (may be vendor specific)."),
    RuleInfo("QW-E001", "Exception/error response storm", S.MEDIUM,
             "A server returned many exception/error responses in a short window (scanning or fuzzing)."),
    RuleInfo("QW-E002", "Request flood", S.MEDIUM,
             "One master sent an unusually high number of requests to one server within a short window "
             "(denial-of-service or runaway client).", ("T0814",)),
    RuleInfo("QW-S001", "Response without matching request", S.LOW,
             "A response arrived with no outstanding matching request (spoofing, asymmetric capture or gap).",
             ("T1692.002",)),
    RuleInfo("QW-S002", "Host acts as both master and server", S.LOW,
             "A host changed role for the same protocol.", ("T0848",)),
    RuleInfo("QW-D001", "Device restart / trouble indication", S.MEDIUM,
             "A device reported restart, trouble or configuration corruption.", ("T0816",)),
    RuleInfo("QW-N001", "ICS protocol on non-standard port", S.LOW,
             "Traffic identified by signature as an ICS protocol on a non-standard port.", ("T0885",)),
    RuleInfo("QW-P001", "Capture/stream health", S.INFO,
             "A TCP gap or resynchronisation occurred; results for this flow may be incomplete."),
)


@dataclass
class Finding:
    rule_id: str
    key: Tuple[Any, ...]
    message: str
    severity: Optional[Severity] = None
    mitre: Optional[Tuple[str, ...]] = None
    details: Dict[str, Any] = field(default_factory=dict)
    ctx: Optional["Ctx"] = None  # evidence context, when emitted later than the packet it concerns


@dataclass
class Ctx:
    msg: Optional[ProtoMessage]  # None for TCP SYN contacts
    pkt: PacketRef
    protocol: str
    transport: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    master_ip: str
    server_ip: str
    server_port: int
    flow_key: Tuple[Any, ...]
    scratch: Dict[str, Any]
    policy: Any
    cfg: Any
    first_ts: float

    @property
    def in_warmup(self) -> bool:
        return (self.pkt.ts - self.first_ts) < self.cfg.warmup_seconds


class Rule:
    #: "request" / "response" lets the engine skip the rule for the other direction entirely
    direction = "any"

    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    def end_of_capture(self, scratch: Dict[str, Any], now: float) -> Iterable[Finding]:
        """Called once per flow when it is retired (idle expiry or end of input)."""
        return ()


def _where(ctx: Ctx) -> str:
    return "%s -> %s:%d" % (ctx.master_ip, ctx.server_ip, ctx.server_port)


def _fn(msg: ProtoMessage) -> str:
    extra = ""
    d = msg.details
    if "subfunction_name" in d:
        extra = " (%s)" % d["subfunction_name"]
    elif "service" in d:
        extra = " (service %s)" % d["service"]
    elif "block_type" in d:
        extra = " (%s%s)" % (d["block_type"], d.get("block_number", ""))
    return "%s %s%s" % (msg.protocol.upper(), msg.function, extra)


# ---------------------------------------------------------------- policy rules
class AssetRule(Rule):
    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        pol = ctx.policy
        if ctx.msg is None or not pol.enforce_assets or "malformed" in ctx.msg.kinds:
            return
        for ip, role in ((ctx.master_ip, "master"), (ctx.server_ip, "server")):
            if not pol.asset_known(ip):
                yield Finding("QW-A001", (ip,), "%s speaks %s as %s but is not in the policy asset list"
                              % (ip, ctx.protocol, role),
                              mitre=("T0848",) if role == "master" else (),
                              details={"ip": ip, "role": role})


class FlowRuleCheck(Rule):
    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        pol = ctx.policy
        if pol.allowed_flows is None or ctx.msg is None or "malformed" in ctx.msg.kinds:
            return
        if not pol.flow_allowed(ctx.master_ip, ctx.server_ip, ctx.protocol, ctx.server_port):
            yield Finding("QW-F001", (ctx.master_ip, ctx.server_ip, ctx.protocol, ctx.server_port),
                          "%s traffic %s is not covered by allowed_flows" % (ctx.protocol, _where(ctx)),
                          details={"master": ctx.master_ip, "server": ctx.server_ip, "port": ctx.server_port})


class FunctionCheck(Rule):
    direction = "request"
    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        pol = ctx.policy
        msg = ctx.msg
        if (pol.allowed_functions is None or msg is None or not msg.is_request
                or msg.kinds & {"malformed", "session", "link"}):
            return
        if pol.function_allowed(ctx.master_ip, ctx.server_ip, ctx.protocol, msg.function, msg.kinds) is False:
            impactful = bool(msg.kinds & {"write", "control", "critical", "program_transfer"})
            yield Finding("QW-F002", (ctx.master_ip, ctx.server_ip, ctx.protocol, msg.function),
                          "%s sent %s to %s:%d, which allowed_functions does not permit on this path"
                          % (ctx.master_ip, _fn(msg), ctx.server_ip, ctx.server_port),
                          mitre=("T1692.001",) if impactful else (),
                          details={"function": msg.function})


class WriteRule(Rule):
    direction = "request"
    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if msg is None or not msg.is_request or not ("write" in msg.kinds or "control" in msg.kinds):
            return
        pol = ctx.policy
        label = _fn(msg)
        tdesc = ", ".join("%s[%d-%d]" % (t.area, t.start, t.end) for t in msg.targets[:6])
        allowed = pol.writer_allowed(ctx.protocol, ctx.master_ip)
        base = {"function": msg.function, "targets": [t.to_dict() for t in msg.targets[:16]]}
        if allowed is False:
            yield Finding("QW-W001", (ctx.master_ip, ctx.server_ip, ctx.protocol, msg.function),
                          "%s sent %s to %s:%d%s but is not an authorised %s writer"
                          % (ctx.master_ip, label, ctx.server_ip, ctx.server_port,
                             " targeting " + tdesc if tdesc else "", ctx.protocol), details=base)
        elif allowed is None:
            yield Finding("QW-W002", (ctx.master_ip, ctx.server_ip, ctx.protocol),
                          "%s sent %s to %s:%d%s" % (ctx.master_ip, label, ctx.server_ip, ctx.server_port,
                                                    " targeting " + tdesc if tdesc else ""), details=base)
        if pol.ranges_enforced_for(ctx.server_ip, ctx.protocol, msg.unit):
            if not msg.targets:
                yield Finding("QW-W003", (ctx.master_ip, ctx.server_ip, ctx.protocol, msg.function, "unknown"),
                              "%s sent %s to %s:%d; write_ranges are enforced but the target could not be determined"
                              % (ctx.master_ip, label, ctx.server_ip, ctx.server_port), details=base)
            else:
                bad = pol.range_violations(ctx.server_ip, ctx.protocol, msg.unit, msg.targets)
                if bad:
                    b = bad[0]
                    yield Finding("QW-W003", (ctx.master_ip, ctx.server_ip, ctx.protocol, b.area, b.start, b.end),
                                  "%s wrote %s[%d-%d] on %s:%d, outside permitted write_ranges"
                                  % (ctx.master_ip, b.area, b.start, b.end, ctx.server_ip, ctx.server_port),
                                  details=dict(base, violations=[t.to_dict() for t in bad[:16]]))


# (protocol, function[, subkey]) -> (severity, mitre, reason)
CRITICAL_TABLE: Dict[Tuple[Any, ...], Tuple[Severity, Tuple[str, ...], str]] = {
    ("modbus", "DIAGNOSTICS", 0x0004): (S.HIGH, ("T0814",), "forces the device into listen-only mode (stops responding)"),
    ("modbus", "DIAGNOSTICS", 0x0001): (S.HIGH, ("T0816",), "restarts the communications port and clears counters/logs"),
    ("dnp3", "COLD_RESTART"): (S.CRITICAL, ("T0816",), "cold restart of the outstation"),
    ("dnp3", "WARM_RESTART"): (S.CRITICAL, ("T0816",), "warm restart of the outstation"),
    ("dnp3", "INITIALIZE_DATA"): (S.HIGH, ("T0816",), "re-initialises outstation data"),
    ("dnp3", "INITIALIZE_APPL"): (S.HIGH, ("T0816",), "re-initialises an outstation application"),
    ("dnp3", "START_APPL"): (S.HIGH, ("T0858",), "starts an outstation application"),
    ("dnp3", "STOP_APPL"): (S.CRITICAL, ("T0881",), "stops an outstation application"),
    ("dnp3", "SAVE_CONFIG"): (S.MEDIUM, ("T0836",), "saves outstation configuration"),
    ("dnp3", "DELETE_FILE"): (S.HIGH, (), "deletes a file on the outstation"),
    ("dnp3", "ACTIVATE_CONFIG"): (S.HIGH, ("T0836",), "activates a staged configuration"),
    ("iec104", "C_RP_NA_1"): (S.HIGH, ("T0816",), "resets the controlled station's process (restart)"),
    ("s7comm", "PLC_STOP"): (S.CRITICAL, ("T0858",), "stops the PLC program"),
    ("s7comm", "PI_SERVICE", "P_PROGRAM"): (S.HIGH, ("T0858",), "PI service P_PROGRAM (CPU run/stop control)"),
    ("s7comm", "PI_SERVICE", "_INSE"): (S.CRITICAL, ("T0843", "T0889"), "inserts a program block"),
    ("s7comm", "PI_SERVICE", "_DELE"): (S.HIGH, ("T0889",), "deletes a program block"),
    ("s7comm", "PI_SERVICE", "_MODU"): (S.HIGH, ("T0889",), "copies RAM to ROM (persists changes)"),
    ("s7comm", "PI_SERVICE", "_GARB"): (S.MEDIUM, ("T0889",), "compresses program memory"),
    ("s7comm", "REQUEST_DOWNLOAD"): (S.CRITICAL, ("T0843",), "begins a program/block download to the PLC"),
    ("s7comm", "DOWNLOAD_BLOCK"): (S.CRITICAL, ("T0843",), "transfers a program block to the PLC"),
    ("s7comm", "DOWNLOAD_ENDED"): (S.CRITICAL, ("T0843",), "finishes a program download"),
    ("s7comm", "START_UPLOAD"): (S.HIGH, ("T0845",), "begins reading a program block from the PLC"),
    ("s7comm", "UPLOAD"): (S.HIGH, ("T0845",), "reads a program block from the PLC"),
    ("s7comm", "END_UPLOAD"): (S.HIGH, ("T0845",), "finishes a program upload"),
}


class CriticalRule(Rule):
    direction = "request"
    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if msg is None or not msg.is_request:
            return
        if not (msg.kinds & {"critical", "program_transfer", "file_transfer"}):
            return
        if ctx.policy.is_engineering_station(ctx.master_ip):
            return
        sub = msg.details.get("subfunction") if msg.protocol == "modbus" else msg.details.get("service")
        entry = CRITICAL_TABLE.get((msg.protocol, msg.function, sub)) or CRITICAL_TABLE.get((msg.protocol, msg.function))
        if entry:
            sev, mitre, why = entry
        elif "file_transfer" in msg.kinds and "critical" not in msg.kinds:
            sev, mitre, why = S.MEDIUM, (), "file transfer operation"
        else:
            sev, mitre, why = S.HIGH, (), "high-impact operation"
        yield Finding("QW-C001", (ctx.master_ip, ctx.server_ip, msg.protocol, msg.function, sub),
                      "%s sent %s to %s:%d: %s" % (ctx.master_ip, _fn(msg), ctx.server_ip, ctx.server_port, why),
                      severity=sev, mitre=mitre,
                      details={"function": msg.function, "subfunction": sub, "reason": why})


class BroadcastRule(Rule):
    direction = "request"
    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if msg is None or not msg.is_request or not msg.broadcast or "malformed" in msg.kinds:
            return
        impactful = msg.kinds & {"write", "control", "critical"}
        if msg.protocol == "dnp3":
            if not impactful and "maintenance" not in msg.kinds:
                return
            sev = S.HIGH if impactful else S.LOW
            if ctx.policy.is_engineering_station(ctx.master_ip) and not impactful:
                return
        elif msg.protocol == "iec104":
            if not impactful:  # general interrogation / clock sync to the global address is routine
                return
            sev = S.HIGH
        elif msg.protocol == "modbus":
            if not impactful:
                return
            sev = S.LOW  # unit id 0 is routinely used as a plain address on Modbus/TCP devices
        else:
            return
        yield Finding("QW-C002", (ctx.master_ip, ctx.server_ip, msg.protocol, msg.function),
                      "%s sent broadcast-addressed %s (unit/address %s) via %s:%d"
                      % (ctx.master_ip, _fn(msg), msg.unit, ctx.server_ip, ctx.server_port),
                      severity=sev, details={"function": msg.function, "unit": msg.unit})


# ------------------------------------------------------------------ recon rules
class ScanRule(Rule):
    """Sweep detection counting only *new* contacts after a warm-up period.

    Masters that poll a fixed set of servers never look like sweeps in steady
    state; a scanner keeps touching previously unseen hosts / unit ids.
    """

    _CAP = 8192

    def __init__(self) -> None:
        self._seen_servers: Dict[str, Set[str]] = {}
        self._new_servers: Dict[str, Deque[Tuple[float, str]]] = {}
        self._seen_units: Dict[Tuple[str, str, str], Set[int]] = {}
        self._new_units: Dict[Tuple[str, str, str], Deque[Tuple[float, int]]] = {}

    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if msg is not None:
            if not msg.is_request or "malformed" in msg.kinds:
                return
        cfg = ctx.cfg
        ts = ctx.pkt.ts
        known_path = (ctx.policy.allowed_flows is not None
                      and ctx.policy.flow_allowed(ctx.master_ip, ctx.server_ip, ctx.protocol, ctx.server_port))
        m = ctx.master_ip
        seen = self._seen_servers.setdefault(m, set())
        if len(self._seen_servers) > self._CAP:
            self._seen_servers.clear()
            self._new_servers.clear()
        if ctx.server_ip not in seen:
            seen.add(ctx.server_ip)
            if not ctx.in_warmup and not known_path:
                dq = self._new_servers.setdefault(m, deque())
                dq.append((ts, ctx.server_ip))
                while dq and ts - dq[0][0] > cfg.sweep_window:
                    dq.popleft()
                distinct = {s for _, s in dq}
                if len(distinct) >= cfg.sweep_hosts:
                    yield Finding("QW-R001", (m,),
                                  "%s contacted %d previously unseen hosts on %s within %.0fs"
                                  % (m, len(distinct), ctx.protocol, cfg.sweep_window),
                                  details={"servers": sorted(distinct)[:32], "protocol": ctx.protocol})
        if msg is None or msg.unit is None or msg.broadcast:
            return
        ukey = (m, ctx.server_ip, ctx.protocol)
        useen = self._seen_units.setdefault(ukey, set())
        if len(self._seen_units) > self._CAP:
            self._seen_units.clear()
            self._new_units.clear()
        if msg.unit not in useen:
            useen.add(msg.unit)
            if not ctx.in_warmup and not known_path:
                dq2 = self._new_units.setdefault(ukey, deque())
                dq2.append((ts, msg.unit))
                while dq2 and ts - dq2[0][0] > cfg.sweep_window:
                    dq2.popleft()
                units = {u for _, u in dq2}
                if len(units) >= cfg.unit_sweep_ids:
                    yield Finding("QW-R002", (m, ctx.server_ip, ctx.protocol),
                                  "%s probed %d new %s unit/address values on %s:%d within %.0fs"
                                  % (m, len(units), ctx.protocol, ctx.server_ip, ctx.server_port, cfg.sweep_window),
                                  details={"units": sorted(units)[:32]})


class FingerprintRule(Rule):
    direction = "request"
    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if msg is None or not msg.is_request or "discovery" not in msg.kinds:
            return
        if ctx.policy.is_engineering_station(ctx.master_ip):
            return
        yield Finding("QW-R003", (ctx.master_ip, ctx.server_ip, msg.protocol, msg.function),
                      "%s requested device information (%s) from %s:%d"
                      % (ctx.master_ip, _fn(msg), ctx.server_ip, ctx.server_port),
                      details={"function": msg.function})


# ------------------------------------------------------------- protocol hygiene
class MalformedRule(Rule):
    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if msg is None or not msg.anomalies:
            return
        for a in msg.anomalies:
            yield Finding("QW-M001", (ctx.master_ip, ctx.server_ip, msg.protocol, a.code),
                          "%s %s: %s (%s)" % (msg.protocol, _where(ctx), a.message, a.code),
                          details={"code": a.code, "function": msg.function})


class UnknownFunctionRule(Rule):
    direction = "request"
    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if msg is None or not msg.is_request or "unknown_function" not in msg.kinds:
            return
        yield Finding("QW-M002", (ctx.master_ip, ctx.server_ip, msg.protocol, msg.function_code),
                      "%s sent %s function code %s to %s:%d" % (ctx.master_ip, msg.protocol, msg.function,
                                                                ctx.server_ip, ctx.server_port),
                      details={"function_code": msg.function_code})


class ExceptionStormRule(Rule):
    direction = "response"
    def __init__(self) -> None:
        self._hist: Dict[Tuple[str, str, str], Deque[float]] = {}

    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if msg is None or msg.is_request or "exception" not in msg.kinds:
            return
        key = (ctx.server_ip, ctx.master_ip, msg.protocol)
        if len(self._hist) > 8192:
            self._hist.clear()
        dq = self._hist.setdefault(key, deque())
        ts = ctx.pkt.ts
        dq.append(ts)
        while dq and ts - dq[0] > ctx.cfg.exception_window:
            dq.popleft()
        if len(dq) >= ctx.cfg.exception_threshold:
            yield Finding("QW-E001", key,
                          "%s returned %d error responses to %s within %.0fs (%s)"
                          % (ctx.server_ip, len(dq), ctx.master_ip, ctx.cfg.exception_window, msg.protocol),
                          details={"window_s": ctx.cfg.exception_window})


class FloodRule(Rule):
    direction = "request"
    """Per master/server/protocol request rate. Defaults leave ~9x headroom over the busiest legitimate
    poller seen in the validation corpus (55 requests/s); tune ``flood_threshold`` for your plant."""

    def __init__(self) -> None:
        self._hist: Dict[Tuple[str, str, str], Deque[float]] = {}

    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if msg is None or not msg.is_request or msg.kinds & {"session", "link", "malformed"}:
            return
        thr = int(ctx.cfg.flood_threshold)
        if thr <= 0:
            return
        key = (ctx.master_ip, ctx.server_ip, msg.protocol)
        if len(self._hist) > 8192:
            self._hist.clear()
        dq = self._hist.setdefault(key, deque())
        ts = ctx.pkt.ts
        dq.append(ts)
        while len(dq) > thr:
            dq.popleft()
        if len(dq) == thr and ts - dq[0] <= ctx.cfg.flood_window:
            yield Finding("QW-E002", key,
                          "%s sent >= %d %s requests to %s:%d within %.2fs"
                          % (ctx.master_ip, thr, msg.protocol, ctx.server_ip, ctx.server_port, ctx.cfg.flood_window),
                          details={"threshold": thr, "window_s": ctx.cfg.flood_window})


class PairingRule(Rule):
    """Flags Modbus/S7 responses that have no matching request.

    A response seen slightly *before* its request is normal when a TAP/SPAN feed skews
    the two directions, so an unmatched response is only reported once
    ``pairing_grace`` seconds of capture time pass without the request showing up.
    """

    _PAIRED = ("modbus", "s7comm")
    _MAX_ORPHANS = 64

    @staticmethod
    def _finding(octx: Ctx, txn: int) -> Finding:
        m = octx.msg
        return Finding("QW-S001", (octx.server_ip, octx.master_ip, m.protocol),
                       "%s sent a %s %s response (id %d) to %s with no outstanding request"
                       % (octx.server_ip, m.protocol, m.function, txn, octx.master_ip),
                       details={"transaction": txn}, ctx=octx)

    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if (msg is None or msg.protocol not in self._PAIRED or msg.transaction is None
                or "malformed" in msg.kinds or "session" in msg.kinds):
            return
        pend: Dict[int, int] = ctx.scratch.setdefault("pending", {})
        orphans: Deque[Tuple[float, Ctx, int]] = ctx.scratch.setdefault("orphans", deque())
        now = ctx.pkt.ts
        while orphans and now - orphans[0][0] > ctx.cfg.pairing_grace:
            _ts, octx, txn = orphans.popleft()
            yield self._finding(octx, txn)
        txn = msg.transaction
        if msg.is_request:
            ctx.scratch["req_seen"] = True
            for i, (_ts, _octx, otxn) in enumerate(orphans):
                if otxn == txn:  # its response was captured first: the pair is complete
                    del orphans[i]
                    return
            pend[txn] = pend.get(txn, 0) + 1
            if len(pend) > 4096:
                pend.pop(next(iter(pend)))
            return
        if pend.get(txn, 0) > 0:
            pend[txn] -= 1
            if pend[txn] == 0:
                del pend[txn]
            return
        if ctx.scratch.get("req_seen"):
            orphans.append((now, ctx, txn))
            if len(orphans) > self._MAX_ORPHANS:
                _ts, octx, otxn = orphans.popleft()
                yield self._finding(octx, otxn)

    def end_of_capture(self, scratch: Dict[str, Any], now: float) -> Iterable[Finding]:
        orphans = scratch.get("orphans")
        while orphans:
            ts, octx, txn = orphans.popleft()
            if now - ts > octx.cfg.pairing_grace:  # younger orphans cannot be judged: capture ended too soon
                yield self._finding(octx, txn)


class RoleRule(Rule):
    def __init__(self) -> None:
        self._roles: Dict[Tuple[str, str], Set[str]] = {}

    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if msg is None or "malformed" in msg.kinds or "link" in msg.kinds:
            return
        sender, role = (ctx.master_ip, "master") if msg.is_request else (ctx.server_ip, "server")
        key = (sender, msg.protocol)
        if len(self._roles) > 16384:
            self._roles.clear()
        roles = self._roles.setdefault(key, set())
        if role in roles:
            return
        roles.add(role)
        if len(roles) == 2:
            yield Finding("QW-S002", key, "%s now acts as both master and server for %s" % (sender, msg.protocol),
                          details={"ip": sender})


class DeviceStateRule(Rule):
    direction = "response"
    _MAP = (("restart_flag", "restarted (IIN DEVICE_RESTART)", S.MEDIUM),
            ("config_corrupt", "reports corrupt configuration (IIN CONFIG_CORRUPT)", S.MEDIUM),
            ("device_trouble", "reports device trouble (IIN DEVICE_TROUBLE)", S.LOW))

    def evaluate(self, ctx: Ctx) -> Iterable[Finding]:
        msg = ctx.msg
        if msg is None or msg.is_request:
            return
        for kind, text, sev in self._MAP:
            if kind in msg.kinds:
                yield Finding("QW-D001", (ctx.server_ip, msg.protocol, kind),
                              "%s %s" % (ctx.server_ip, text), severity=sev, details={"flag": kind})


def default_rules() -> List[Rule]:
    return [AssetRule(), FlowRuleCheck(), FunctionCheck(), WriteRule(), CriticalRule(), BroadcastRule(), ScanRule(),
            FingerprintRule(), MalformedRule(), UnknownFunctionRule(), ExceptionStormRule(), FloodRule(), PairingRule(),
            RoleRule(), DeviceStateRule()]
