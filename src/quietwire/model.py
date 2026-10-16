"""Protocol-neutral data model shared by dissectors, rules and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, FrozenSet, List, Optional, Tuple


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[text.strip().upper()]
        except KeyError:
            raise ValueError(
                "unknown severity %r (expected one of: %s)"
                % (text, ", ".join(s.label for s in cls))
            )


@dataclass(frozen=True)
class Target:
    """An addressable object touched by a write/control operation.

    ``area`` is protocol specific (e.g. ``coil``, ``holding_register``, ``DB5``,
    ``binary_output``); ``start``/``end`` are inclusive wire addresses (S7: byte
    offsets).
    """

    area: str
    start: int
    end: int

    def to_dict(self) -> Dict[str, Any]:
        return {"area": self.area, "start": self.start, "end": self.end}


@dataclass
class Anomaly:
    code: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass
class PacketRef:
    """Where a packet came from (for evidence pointers)."""

    index: int  # 1-based packet number within the (possibly multi-file) input stream
    offset: int  # byte offset of the packet record in its file, -1 for live
    ts: float
    source: int = 0  # index of the input file in the report's ``files`` list

    def to_dict(self) -> Dict[str, Any]:
        return {"index": self.index, "offset": self.offset, "ts": self.ts, "source": self.source}


@dataclass
class ProtoMessage:
    """One application-layer message decoded by a dissector.

    ``is_request`` is True when the sender acts as master/client.  ``kinds`` is
    a set of behavioural tags consumed by the detection rules:
    read, write, control, critical, discovery, diagnostic, maintenance,
    program_transfer, file_transfer, session, link, exception, unknown_function.
    """

    protocol: str
    is_request: bool
    function: str
    function_code: Optional[int] = None
    kinds: FrozenSet[str] = frozenset()
    targets: Tuple[Target, ...] = ()
    unit: Optional[int] = None
    src_addr: Optional[int] = None
    dst_addr: Optional[int] = None
    transaction: Optional[int] = None
    exception: Optional[int] = None
    broadcast: bool = False
    size: int = 0
    details: Dict[str, Any] = field(default_factory=dict)
    anomalies: List[Anomaly] = field(default_factory=list)

    def has(self, kind: str) -> bool:
        return kind in self.kinds


@dataclass
class Alert:
    rule_id: str
    severity: Severity
    title: str
    message: str
    key: Tuple[Any, ...]
    protocol: str
    transport: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    first_ts: float
    last_ts: float
    first_packet: PacketRef
    last_packet: PacketRef
    count: int = 1
    mitre: Tuple[str, ...] = ()
    details: Dict[str, Any] = field(default_factory=dict)
    samples: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        from .util import iso_ts

        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "title": self.title,
            "message": self.message,
            "protocol": self.protocol,
            "transport": self.transport,
            "src": "%s:%d" % (self.src_ip, self.src_port),
            "dst": "%s:%d" % (self.dst_ip, self.dst_port),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "count": self.count,
            "first_seen": iso_ts(self.first_ts),
            "last_seen": iso_ts(self.last_ts),
            "first_packet": self.first_packet.to_dict(),
            "last_packet": self.last_packet.to_dict(),
            "mitre_attack_ics": list(self.mitre),
            "details": self.details,
            "samples": self.samples,
        }
