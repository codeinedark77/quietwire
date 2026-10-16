"""Passive asset and flow inventory built from decoded messages."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

from .model import ProtoMessage

MAX_ID_VALUES = 256
MAX_INTERVALS = 512


class Asset:
    def __init__(self, ip: str, ts: float):
        self.ip = ip
        self.macs: Set[str] = set()
        self.first_seen = ts
        self.last_seen = ts
        self.packets = 0
        self.bytes = 0
        # protocol -> {"master": bool, "server": bool, "ports": set}
        self.protocols: Dict[str, Dict[str, Any]] = {}
        self.modbus_units: Set[int] = set()
        self.dnp3_addresses: Set[int] = set()
        self.iec104_common_addresses: Set[int] = set()
        self.s7_endpoints: List[Dict[str, Any]] = []
        self.device_info: Dict[str, Any] = {}
        self.functions: Counter = Counter()

    def proto(self, protocol: str) -> Dict[str, Any]:
        p = self.protocols.get(protocol)
        if p is None:
            p = {"master": False, "server": False, "ports": set()}
            self.protocols[protocol] = p
        return p

    def to_dict(self) -> Dict[str, Any]:
        from .util import iso_ts

        d: Dict[str, Any] = {
            "ip": self.ip,
            "macs": sorted(self.macs),
            "first_seen": iso_ts(self.first_seen),
            "last_seen": iso_ts(self.last_seen),
            "packets": self.packets,
            "bytes": self.bytes,
            "protocols": {
                k: {"master": v["master"], "server": v["server"], "ports": sorted(v["ports"])}
                for k, v in sorted(self.protocols.items())
            },
            "functions": dict(sorted(self.functions.items())),
        }
        if self.modbus_units:
            d["modbus_unit_ids"] = sorted(self.modbus_units)
        if self.dnp3_addresses:
            d["dnp3_addresses"] = sorted(self.dnp3_addresses)
        if self.iec104_common_addresses:
            d["iec104_common_addresses"] = sorted(self.iec104_common_addresses)
        if self.s7_endpoints:
            d["s7_endpoints"] = self.s7_endpoints
        if self.device_info:
            d["device_info"] = self.device_info
        return d


class FlowRecord:
    def __init__(self, master: str, server: str, protocol: str, server_port: int, transport: str, ts: float):
        self.master = master
        self.server = server
        self.protocol = protocol
        self.server_port = server_port
        self.transport = transport
        self.first_seen = ts
        self.last_seen = ts
        self.requests = 0
        self.responses = 0
        self.write_requests = 0
        self.exceptions = 0
        self.malformed = 0
        self.functions: Counter = Counter()
        self.request_functions: Counter = Counter()  # requests only (session/link/malformed excluded)
        self.critical_functions: Set[str] = set()
        self.identified_by = "port"
        self.role_inferred = False

    def to_dict(self) -> Dict[str, Any]:
        from .util import iso_ts

        return {
            "master": self.master,
            "server": self.server,
            "protocol": self.protocol,
            "server_port": self.server_port,
            "transport": self.transport,
            "identified_by": self.identified_by,
            "role_inferred": self.role_inferred,
            "first_seen": iso_ts(self.first_seen),
            "last_seen": iso_ts(self.last_seen),
            "requests": self.requests,
            "responses": self.responses,
            "write_requests": self.write_requests,
            "exception_responses": self.exceptions,
            "malformed": self.malformed,
            "functions": dict(sorted(self.functions.items())),
        }


class Inventory:
    def __init__(self) -> None:
        self.assets: Dict[str, Asset] = {}
        self.flows: Dict[Tuple[str, str, str, int], FlowRecord] = {}
        # (server, protocol, unit, area) -> merged observed write intervals
        self.write_targets: Dict[Tuple[str, str, Optional[int], str], List[Tuple[int, int]]] = {}
        self._protocols_seen: Set[str] = set()

    def protocol_seen(self, protocol: str) -> bool:
        return protocol in self._protocols_seen

    def asset(self, ip: str, ts: float) -> Asset:
        a = self.assets.get(ip)
        if a is None:
            a = Asset(ip, ts)
            self.assets[ip] = a
        if ts > a.last_seen:
            a.last_seen = ts
        return a

    def note_packet(self, src_ip: str, dst_ip: str, src_mac: Optional[str], dst_mac: Optional[str],
                    nbytes: int, ts: float) -> None:
        for ip, mac in ((src_ip, src_mac), (dst_ip, dst_mac)):
            a = self.asset(ip, ts)
            a.packets += 1
            a.bytes += nbytes
            if mac and len(a.macs) < 8:
                a.macs.add(mac)

    def flow(self, master: str, server: str, protocol: str, port: int, transport: str, ts: float,
             identified_by: str = "port") -> FlowRecord:
        key = (master, server, protocol, port)
        f = self.flows.get(key)
        if f is None:
            f = FlowRecord(master, server, protocol, port, transport, ts)
            f.identified_by = identified_by
            self.flows[key] = f
        if ts > f.last_seen:
            f.last_seen = ts
        return f

    def note_message(self, msg: ProtoMessage, master: str, server: str, server_port: int,
                     transport: str, ts: float, identified_by: str, role_inferred: bool = False) -> None:
        self._protocols_seen.add(msg.protocol)
        f = self.flow(master, server, msg.protocol, server_port, transport, ts, identified_by)
        if role_inferred:
            f.role_inferred = True
        ma = self.asset(master, ts)
        sa = self.asset(server, ts)
        ma.proto(msg.protocol)["master"] = True
        sa.proto(msg.protocol)["server"] = True
        sa.proto(msg.protocol)["ports"].add(server_port)
        if msg.is_request:
            f.requests += 1
        else:
            f.responses += 1
        if "malformed" in msg.kinds:
            f.malformed += 1
            return
        if "exception" in msg.kinds:
            f.exceptions += 1
        label = "%s:%s" % (msg.protocol, msg.function)
        f.functions[msg.function] += 1
        sender = ma if msg.is_request else sa
        sender.functions[label] += 1
        if msg.is_request:
            if not msg.kinds & {"session", "link"}:
                f.request_functions[msg.function] += 1
            if "write" in msg.kinds or "control" in msg.kinds:
                f.write_requests += 1
                self._note_targets(server, msg)
            if "critical" in msg.kinds or "program_transfer" in msg.kinds:
                f.critical_functions.add(msg.function)
        self._note_identifiers(msg, ma, sa)

    def _note_targets(self, server: str, msg: ProtoMessage) -> None:
        for t in msg.targets:
            key = (server, msg.protocol, msg.unit if msg.protocol == "modbus" else None, t.area)
            iv = self.write_targets.setdefault(key, [])
            if len(iv) < MAX_INTERVALS:
                iv.append((t.start, t.end))

    def _note_identifiers(self, msg: ProtoMessage, master: Asset, server: Asset) -> None:
        if msg.protocol == "modbus" and msg.unit is not None and len(server.modbus_units) < MAX_ID_VALUES:
            if msg.is_request:
                server.modbus_units.add(msg.unit)
            devid = msg.details.get("device_id")
            if devid and not msg.is_request:
                server.device_info.update({"modbus_device_id": devid})
        elif msg.protocol == "dnp3":
            for addr, asset in ((msg.src_addr, master if msg.is_request else server),
                                (msg.dst_addr, server if msg.is_request else master)):
                if addr is not None and addr < 0xFFF0 and len(asset.dnp3_addresses) < MAX_ID_VALUES:
                    asset.dnp3_addresses.add(addr)
        elif msg.protocol == "iec104" and msg.unit is not None and msg.unit != 0xFFFF:
            if len(server.iec104_common_addresses) < MAX_ID_VALUES:
                server.iec104_common_addresses.add(msg.unit)
        elif msg.protocol == "s7comm" and msg.function == "COTP_CONNECT_REQUEST":
            called = msg.details.get("called")
            if called and "rack" in called:
                ep = {"rack": called["rack"], "slot": called["slot"], "connection_type": called.get("connection_type")}
                if ep not in server.s7_endpoints and len(server.s7_endpoints) < 32:
                    server.s7_endpoints.append(ep)
