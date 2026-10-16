"""Analysis engine: packets -> flows -> messages -> inventory + alerts.

The engine is a pure consumer: it is fed :class:`RawPacket` objects (from a file
or a live socket) and never emits traffic.
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from dataclasses import dataclass, field, fields
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..capture.pcap import RawPacket
from ..inventory import Inventory
from ..model import Alert, PacketRef, ProtoMessage, Severity
from ..net.decode import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, DecodedPacket, Decoder
from ..net.fragments import FragmentReassembler
from ..net.reassembly import DirectionStream
from ..proto import DISSECTORS, WELL_KNOWN_TCP, WELL_KNOWN_UDP, identify
from ..proto.base import FlowDissector
from .policy import Policy
from .rules import RULES, Ctx, Finding, Rule, default_rules

_DEFAULT_PORT = {"modbus": 502, "dnp3": 20000, "s7comm": 102, "iec104": 2404}
_UPDATE_COUNTS = (10, 100, 1000, 10000, 100000)


@dataclass
class Config:
    warmup_seconds: float = 120.0
    sweep_window: float = 60.0
    sweep_hosts: int = 8
    unit_sweep_ids: int = 8
    exception_window: float = 10.0
    exception_threshold: int = 10
    flood_window: float = 1.0
    flood_threshold: int = 500
    flow_idle_seconds: float = 600.0
    tcp_reorder_window: float = 0.25
    pairing_grace: float = 1.0
    defragment: bool = True
    defrag_timeout: float = 30.0
    defrag_max_datagrams: int = 1024
    decapsulate: bool = True
    max_flows: int = 20000
    max_alerts: int = 20000
    max_samples: int = 3
    identify_nonstandard: bool = True
    min_severity: Severity = Severity.INFO

    TUNABLE = ("warmup_seconds", "sweep_window", "sweep_hosts", "unit_sweep_ids", "exception_window",
               "exception_threshold", "flood_window", "flood_threshold", "flow_idle_seconds", "max_flows", "tcp_reorder_window",
               "pairing_grace", "defrag_timeout", "defrag_max_datagrams")

    def apply(self, overrides: Dict[str, Any]) -> None:
        types = {f.name: f.type for f in fields(self)}
        for k, v in overrides.items():
            if k not in self.TUNABLE:
                raise ValueError("threshold %r is not tunable" % k)
            cur = getattr(self, k)
            setattr(self, k, type(cur)(v))


@dataclass
class Stats:
    packets: int = 0
    bytes: int = 0
    decoded: int = 0
    skipped: Counter = field(default_factory=Counter)
    ics_packets: int = 0
    messages: Counter = field(default_factory=Counter)
    malformed: Counter = field(default_factory=Counter)
    flows_created: int = 0
    flows_by_signature: int = 0
    tcp_gaps: int = 0
    tcp_retransmits: int = 0
    tcp_out_of_window: int = 0
    tcp_connections_restarted: int = 0
    ip_fragments_held: int = 0
    ip_datagrams_reassembled: int = 0
    ip_fragment_conflicts: int = 0
    ip_fragment_datagrams_expired: int = 0
    tunneled_packets: int = 0
    tunnels: Counter = field(default_factory=Counter)
    alerts_dropped: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packets": self.packets, "bytes": self.bytes, "decoded": self.decoded,
            "skipped": dict(sorted(self.skipped.items())),
            "ics_packets": self.ics_packets,
            "messages": dict(sorted(self.messages.items())),
            "malformed": dict(sorted(self.malformed.items())),
            "flows_created": self.flows_created, "flows_identified_by_signature": self.flows_by_signature,
            "tcp_gaps": self.tcp_gaps, "tcp_retransmits": self.tcp_retransmits,
            "tcp_out_of_window": self.tcp_out_of_window,
            "tcp_connections_restarted": self.tcp_connections_restarted,
            "ip_fragments_held": self.ip_fragments_held,
            "ip_datagrams_reassembled": self.ip_datagrams_reassembled,
            "ip_fragment_conflicts": self.ip_fragment_conflicts,
            "ip_fragment_datagrams_expired": self.ip_fragment_datagrams_expired,
            "tunneled_packets": self.tunneled_packets,
            "tunnels": dict(sorted(self.tunnels.items())),
            "alerts_dropped": self.alerts_dropped,
        }


class FlowState:
    __slots__ = ("key", "client", "server", "protocol", "transport", "dissector", "streams", "identified_by",
                 "first_ts", "last_ts", "role_heuristic", "scratch", "last_ref", "closing")

    def __init__(self, key, client, server, protocol, transport, dissector, identified_by, ts, heuristic,
                 reorder_window=0.25):
        self.key = key
        self.client = client
        self.server = server
        self.protocol = protocol
        self.transport = transport
        self.dissector: FlowDissector = dissector
        self.streams = {True: DirectionStream(reorder_window=reorder_window),
                        False: DirectionStream(reorder_window=reorder_window)}
        self.last_ref = None
        self.closing = False  # FIN/RST seen since the last SYN: the next SYN starts a new connection
        self.identified_by = identified_by
        self.first_ts = ts
        self.last_ts = ts
        self.role_heuristic = heuristic
        self.scratch: Dict[str, Any] = {}


class AlertStore:
    def __init__(self, max_alerts: int, max_samples: int, on_alert: Optional[Callable[[Alert, bool], None]],
                 stats: Stats):
        self._alerts: "OrderedDict[Tuple[Any, ...], Alert]" = OrderedDict()
        self._max = max_alerts
        self._max_samples = max_samples
        self._on_alert = on_alert
        self._stats = stats

    def add(self, rule_id: str, key: Tuple[Any, ...], severity: Severity, message: str, mitre: Tuple[str, ...],
            ctx: Ctx, details: Dict[str, Any]) -> None:
        full_key = (rule_id,) + tuple(key)
        sample = {"packet": ctx.pkt.index, "message": message}
        existing = self._alerts.get(full_key)
        if existing is None:
            if len(self._alerts) >= self._max:
                self._stats.alerts_dropped += 1
                return
            alert = Alert(
                rule_id=rule_id, severity=severity, title=RULES[rule_id].name, message=message, key=full_key,
                protocol=ctx.protocol, transport=ctx.transport, src_ip=ctx.src_ip, dst_ip=ctx.dst_ip,
                src_port=ctx.src_port, dst_port=ctx.dst_port, first_ts=ctx.pkt.ts, last_ts=ctx.pkt.ts,
                first_packet=ctx.pkt, last_packet=ctx.pkt, count=1, mitre=mitre, details=details,
                samples=[sample],
            )
            self._alerts[full_key] = alert
            if self._on_alert:
                self._on_alert(alert, False)
            return
        existing.count += 1
        if ctx.pkt.index < existing.first_packet.index:  # reordered delivery: keep true first/last evidence
            existing.first_packet, existing.first_ts = ctx.pkt, ctx.pkt.ts
        if ctx.pkt.index > existing.last_packet.index:
            existing.last_packet, existing.last_ts = ctx.pkt, ctx.pkt.ts
        if len(existing.samples) < self._max_samples and all(s["message"] != message for s in existing.samples):
            existing.samples.append(sample)
        if existing.count in _UPDATE_COUNTS and self._on_alert:
            self._on_alert(existing, True)

    def all(self) -> List[Alert]:
        return sorted(self._alerts.values(), key=lambda a: (-int(a.severity), a.first_ts, a.rule_id))


@dataclass
class Result:
    alerts: List[Alert]
    inventory: Inventory
    stats: Stats
    first_ts: Optional[float]
    last_ts: Optional[float]
    warnings: List[str] = field(default_factory=list)


class Engine:
    def __init__(self, policy: Optional[Policy] = None, config: Optional[Config] = None,
                 on_alert: Optional[Callable[[Alert, bool], None]] = None,
                 rules: Optional[List[Rule]] = None):
        self.policy = policy or Policy()
        self.cfg = config or Config()
        if self.policy.thresholds:
            self.cfg.apply(self.policy.thresholds)
        self.stats = Stats()
        self.inv = Inventory()
        self.alerts = AlertStore(self.cfg.max_alerts, self.cfg.max_samples, on_alert, self.stats)
        self.rules = rules if rules is not None else default_rules()
        self._req_rules = [r for r in self.rules if getattr(r, "direction", "any") != "response"]
        self._resp_rules = [r for r in self.rules if getattr(r, "direction", "any") != "request"]
        self.flows: "OrderedDict[Tuple[Any, ...], FlowState]" = OrderedDict()
        self._neg: "OrderedDict[Tuple[Any, ...], bool]" = OrderedDict()
        self._syns: "OrderedDict[Tuple[Any, ...], Tuple[str, int]]" = OrderedDict()
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self._caplen = 0
        self._cur_ref: Optional[PacketRef] = None
        self.source_index = 0  # which input file the packets currently being fed come from
        self._decoder = Decoder(
            FragmentReassembler(self.cfg.defrag_max_datagrams, self.cfg.defrag_timeout) if self.cfg.defragment else None,
            self.cfg.decapsulate)
        self._decoder.conflict_hook = self._on_fragment_conflict

    # ------------------------------------------------------------ ingestion
    def process(self, raw: RawPacket) -> None:
        st = self.stats
        st.packets += 1
        st.bytes += raw.caplen
        if self.first_ts is None or raw.ts < self.first_ts:
            self.first_ts = raw.ts
        if self.last_ts is None or raw.ts > self.last_ts:
            self.last_ts = raw.ts
        ref = PacketRef(raw.index, raw.offset, raw.ts, self.source_index)
        self._cur_ref = ref
        pkt, why = self._decoder.decode(raw.linktype, raw.data, raw.caplen < raw.origlen, raw.ts)
        if pkt is None:
            if why == "fragment_pending":
                st.ip_fragments_held += 1
            else:
                st.skipped[why or "unknown"] += 1
            return
        st.decoded += 1
        if pkt.fragments:
            st.ip_datagrams_reassembled += 1
        if pkt.tunnel:
            st.tunneled_packets += 1
            st.tunnels[pkt.tunnel] += 1
        self._caplen = raw.caplen
        if pkt.proto == 6:
            self._tcp(pkt, ref)
        else:
            self._udp(pkt, ref)
        if st.packets % 2048 == 0:
            self._expire(raw.ts)

    def _on_fragment_conflict(self, src_ip: str, dst_ip: str, conflicts: int) -> None:
        ref = self._cur_ref
        if ref is None:
            return
        self.stats.ip_fragment_conflicts += conflicts
        ctx = Ctx(msg=None, pkt=ref, protocol="ip", transport="ip", src_ip=src_ip, dst_ip=dst_ip, src_port=0,
                  dst_port=0, master_ip=src_ip, server_ip=dst_ip, server_port=0, flow_key=("frag", src_ip, dst_ip),
                  scratch={}, policy=self.policy, cfg=self.cfg,
                  first_ts=self.first_ts if self.first_ts is not None else ref.ts)
        self._emit(Finding("QW-M003", (src_ip, dst_ip),
                           "%s sent overlapping IP fragments to %s whose bytes differ (reassembly evasion attempt)"
                           % (src_ip, dst_ip), details={"conflicting_overlaps": conflicts}), ctx)

    def finalize(self) -> Result:
        d = self._decoder.defrag
        if d is not None:
            self.stats.ip_fragment_datagrams_expired = d.expired + d.evicted
        for flow in list(self.flows.values()):
            self._retire(flow)
        self.flows.clear()
        return Result(self.alerts.all(), self.inv, self.stats, self.first_ts, self.last_ts)

    # ----------------------------------------------------------- flow logic
    @staticmethod
    def _key(pkt: DecodedPacket) -> Tuple[Any, ...]:
        a = (pkt.src_ip, pkt.src_port)
        b = (pkt.dst_ip, pkt.dst_port)
        return (a, b, pkt.proto) if a <= b else (b, a, pkt.proto)

    @staticmethod
    def _pick_client(pkt: DecodedPacket, protocol: str,
                     syn_initiator: Optional[Tuple[str, int]] = None) -> Tuple[Tuple[str, int], bool]:
        """Decide which endpoint is the client. Returns (client_endpoint, inferred_by_heuristic).

        Order of evidence: (1) the side using the protocol's well-known port is the
        server; (2) a *sane* SYN (no FIN/RST/URG/PSH) identifies the initiator; (3)
        heuristic: the higher port is the client. TCP flags are only trusted when they
        look like a real handshake, so crafted/garbled flags cannot flip the roles.
        """
        src = (pkt.src_ip, pkt.src_port)
        dst = (pkt.dst_ip, pkt.dst_port)
        wk = _DEFAULT_PORT[protocol]
        if pkt.dst_port == wk and pkt.src_port != wk:
            return src, False
        if pkt.src_port == wk and pkt.dst_port != wk:
            return dst, False
        if syn_initiator is not None:
            return syn_initiator, False
        if pkt.is_tcp and pkt.flags & TCP_SYN and not pkt.flags & (TCP_FIN | TCP_RST | 0x20 | 0x08):
            return (dst, False) if pkt.flags & TCP_ACK else (src, False)
        return (src if pkt.src_port >= pkt.dst_port else dst), True

    def _new_flow(self, key, pkt: DecodedPacket, protocol: str, transport: str, ident: str, ref: PacketRef) -> FlowState:
        client, heuristic = self._pick_client(pkt, protocol, self._syns.get(key))
        server = (pkt.dst_ip, pkt.dst_port) if client == (pkt.src_ip, pkt.src_port) else (pkt.src_ip, pkt.src_port)
        flow = FlowState(key, client, server, protocol, transport, DISSECTORS[protocol](), ident, ref.ts, heuristic,
                         self.cfg.tcp_reorder_window)
        self.flows[key] = flow
        self.stats.flows_created += 1
        if ident == "signature":
            self.stats.flows_by_signature += 1
            ctx = self._ctx(flow, (pkt.src_ip, pkt.src_port) == client, ref, None, client[0], server[0], server[1])
            self._emit(Finding("QW-N001", (server[0], server[1], protocol),
                               "%s traffic identified by signature on non-standard port %s:%d"
                               % (protocol, server[0], server[1]),
                               details={"protocol": protocol, "port": server[1]}), ctx)
        while len(self.flows) > self.cfg.max_flows:
            self._retire(self.flows.popitem(last=False)[1])
        return flow

    def _maybe_restart(self, flow: FlowState, pkt: DecodedPacket, from_client: bool) -> None:
        """A fresh SYN on a known 4-tuple: decide whether it starts a *new* TCP connection.

        Fixed source ports make reconnects on the same 4-tuple common in OT. The flow is reset
        when the previous connection was closed (FIN/RST seen) or when the SYN's sequence space is
        implausibly far from the stream's. A retransmitted SYN, or an in-window SYN on a live
        connection (possible injection), leaves the state untouched.
        """
        d = flow.streams[from_client]
        if d.next_seq is None:
            return
        isn_next = (pkt.seq + 1) & 0xFFFFFFFF
        if d.next_seq == isn_next or d.isn_next == isn_next:  # (late) duplicate of this connection's own SYN
            return
        ahead = (isn_next - d.next_seq) & 0xFFFFFFFF
        plausible = ahead <= d._max_ahead or (0x100000000 - ahead) <= d._max_ahead
        if not (flow.closing or not plausible):
            return
        self._retire_streams(flow)
        flow.dissector = DISSECTORS[flow.protocol]()
        flow.streams = {True: DirectionStream(reorder_window=self.cfg.tcp_reorder_window),
                        False: DirectionStream(reorder_window=self.cfg.tcp_reorder_window)}
        flow.scratch = {}
        flow.closing = False
        self.stats.tcp_connections_restarted += 1

    def _remember_syn(self, key, initiator: Tuple[str, int]) -> None:
        self._syns[key] = initiator
        while len(self._syns) > 65536:
            self._syns.popitem(last=False)

    def _remember_negative(self, key) -> None:
        self._neg[key] = True
        while len(self._neg) > 65536:
            self._neg.popitem(last=False)

    def _tcp(self, pkt: DecodedPacket, ref: PacketRef) -> None:
        syn = bool(pkt.flags & TCP_SYN)
        ack = bool(pkt.flags & TCP_ACK)
        key = self._key(pkt)
        flow = self.flows.get(key)
        if flow is None and syn and not pkt.flags & (TCP_FIN | TCP_RST | 0x20 | 0x08):
            # a sane SYN names its sender as the initiator; a SYN|ACK names its *receiver*
            self._remember_syn(key, (pkt.dst_ip, pkt.dst_port) if ack else (pkt.src_ip, pkt.src_port))
        if flow is None:
            protocol = WELL_KNOWN_TCP.get(pkt.dst_port) or WELL_KNOWN_TCP.get(pkt.src_port)
            ident = "port"
            if protocol is None:
                if not pkt.payload or not self.cfg.identify_nonstandard or key in self._neg:
                    return
                protocol = identify(pkt.payload)
                if protocol is None:
                    self._remember_negative(key)
                    return
                ident = "signature"
            flow = self._new_flow(key, pkt, protocol, "tcp", ident, ref)
        else:
            self.flows.move_to_end(key)
        flow.last_ts = ref.ts
        self.stats.ics_packets += 1
        self.inv.note_packet(pkt.src_ip, pkt.dst_ip, pkt.src_mac, pkt.dst_mac, self._caplen, ref.ts)
        from_client = (pkt.src_ip, pkt.src_port) == flow.client
        sane_syn = syn and not pkt.flags & (TCP_FIN | TCP_RST | 0x20 | 0x08)
        if pkt.flags & (TCP_FIN | TCP_RST) and not syn:
            flow.closing = True
        if sane_syn and not ack:
            self._maybe_restart(flow, pkt, from_client)
            self._syn_contact(flow, pkt, ref)
        if not pkt.payload and not syn:
            return
        flow.last_ref = ref
        chunks = flow.streams[from_client].add(pkt.seq, pkt.payload, pkt.wire_payload_len, syn, ref.ts, ref)
        self._feed_chunks(flow, from_client, chunks, ref)

    def _udp(self, pkt: DecodedPacket, ref: PacketRef) -> None:
        key = self._key(pkt)
        flow = self.flows.get(key)
        if flow is None:
            protocol = WELL_KNOWN_UDP.get(pkt.dst_port) or WELL_KNOWN_UDP.get(pkt.src_port)
            if protocol is None or not pkt.payload:
                return
            flow = self._new_flow(key, pkt, protocol, "udp", "port", ref)
        else:
            self.flows.move_to_end(key)
        flow.last_ts = ref.ts
        if not pkt.payload:
            return
        self.stats.ics_packets += 1
        self.inv.note_packet(pkt.src_ip, pkt.dst_ip, pkt.src_mac, pkt.dst_mac, self._caplen, ref.ts)
        from_client = (pkt.src_ip, pkt.src_port) == flow.client
        flow.last_ref = ref
        for msg in flow.dissector.feed_datagram(from_client, pkt.payload):
            self._handle(flow, from_client, ref, msg)

    # -------------------------------------------------------------- dispatch
    def _feed_chunks(self, flow: FlowState, from_client: bool, chunks, ref: PacketRef) -> None:
        for data, gap, tag in chunks:
            cref = tag if tag is not None else ref
            if gap:
                self._health(flow, from_client, cref)
            for msg in flow.dissector.feed_stream(from_client, data, gap):
                self._handle(flow, from_client, cref, msg)

    def _ctx(self, flow: FlowState, from_client: bool, ref: PacketRef, msg: Optional[ProtoMessage],
             master: str, server: str, server_port: int) -> Ctx:
        src, dst = (flow.client, flow.server) if from_client else (flow.server, flow.client)
        return Ctx(msg=msg, pkt=ref, protocol=flow.protocol, transport=flow.transport, src_ip=src[0],
                   dst_ip=dst[0], src_port=src[1], dst_port=dst[1], master_ip=master,
                   server_ip=server, server_port=server_port, flow_key=flow.key, scratch=flow.scratch,
                   policy=self.policy, cfg=self.cfg, first_ts=self.first_ts if self.first_ts is not None else ref.ts)

    def _handle(self, flow: FlowState, from_client: bool, ref: PacketRef, msg: ProtoMessage) -> None:
        src, dst = (flow.client, flow.server) if from_client else (flow.server, flow.client)
        if msg.is_request:
            master, server, sport = src[0], dst[0], dst[1]
        else:
            master, server, sport = dst[0], src[0], src[1]
        st = self.stats
        st.messages[msg.protocol] += 1
        if msg.anomalies or "malformed" in msg.kinds:
            st.malformed[msg.protocol] += 1
        self.inv.note_message(msg, master, server, sport, flow.transport, ref.ts, flow.identified_by, flow.role_heuristic)
        ctx = self._ctx(flow, from_client, ref, msg, master, server, sport)
        for rule in (self._req_rules if msg.is_request else self._resp_rules):
            for f in rule.evaluate(ctx):
                self._emit(f, ctx)

    def _syn_contact(self, flow: FlowState, pkt: DecodedPacket, ref: PacketRef) -> None:
        from_client = (pkt.src_ip, pkt.src_port) == flow.client
        ctx = self._ctx(flow, from_client, ref, None, pkt.src_ip, pkt.dst_ip, pkt.dst_port)
        for rule in self.rules:
            if rule.__class__.__name__ == "ScanRule":
                for f in rule.evaluate(ctx):
                    self._emit(f, ctx)

    def _health(self, flow: FlowState, from_client: bool, ref: PacketRef) -> None:
        ctx = self._ctx(flow, from_client, ref, None, flow.client[0], flow.server[0], flow.server[1])
        self._emit(Finding("QW-P001", (flow.client, flow.server, flow.protocol),
                           "TCP gap or retransmission loss in %s flow %s:%d <-> %s:%d; parsing resynchronised"
                           % (flow.protocol, flow.client[0], flow.client[1], flow.server[0], flow.server[1])), ctx)

    def _retire_streams(self, flow: FlowState) -> None:
        """Flush data still held behind holes and account the stream statistics."""
        ref = flow.last_ref
        for from_client in (True, False):
            d = flow.streams[from_client]
            if ref is not None:
                self._feed_chunks(flow, from_client, d.flush(), ref)
            self.stats.tcp_gaps += d.gaps
            self.stats.tcp_retransmits += d.retransmitted_segments
            self.stats.tcp_out_of_window += d.out_of_window

    def _retire(self, flow: FlowState) -> None:
        """End of a flow's life: flush its streams, then let rules emit end-of-capture findings."""
        self._retire_streams(flow)
        now = self.last_ts if self.last_ts is not None else 0.0
        for rule in self.rules:
            for f in rule.end_of_capture(flow.scratch, now):
                if f.ctx is not None:
                    self._emit(f, f.ctx)

    def _emit(self, f: Finding, ctx: Ctx) -> None:
        ctx = f.ctx if f.ctx is not None else ctx
        pol = self.policy
        if f.rule_id in pol.ignore_rules:
            return
        info = RULES[f.rule_id]
        sev = pol.severity_overrides.get(f.rule_id) or f.severity or info.severity
        if sev < self.cfg.min_severity:
            return
        mitre = f.mitre if f.mitre is not None else info.mitre
        details = dict(f.details)
        msg = ctx.msg
        if msg is not None:
            details.setdefault("function", msg.function)
            if msg.unit is not None:
                details.setdefault("unit", msg.unit)
        self.alerts.add(f.rule_id, f.key, sev, f.message, tuple(mitre), ctx, details)

    def _expire(self, now: float) -> None:
        idle = self.cfg.flow_idle_seconds
        while self.flows:
            k = next(iter(self.flows))
            if now - self.flows[k].last_ts > idle:
                self._retire(self.flows.pop(k))
            else:
                break
