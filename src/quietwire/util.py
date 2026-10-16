"""Small shared helpers (no third-party dependencies)."""

from __future__ import annotations

import datetime as _dt
from typing import List

_DNP_TABLE: List[int] = []


def _build_dnp_table() -> List[int]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
        table.append(crc)
    return table


_DNP_TABLE = _build_dnp_table()


def crc16_dnp(data: bytes) -> int:
    """CRC-16/DNP (poly 0x3D65 reflected, init 0, xorout 0xFFFF).

    Check value for b"123456789" is 0xEA82 (CRC RevEng catalogue).
    """
    crc = 0
    table = _DNP_TABLE
    for b in data:
        crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFF


def iso_ts(ts: float) -> str:
    """Format an epoch timestamp as ISO-8601 UTC with microseconds."""
    try:
        d = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return "1970-01-01T00:00:00.000000Z"
    return d.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def hexdump_short(data: bytes, limit: int = 32) -> str:
    h = data[:limit].hex()
    return h + ("..." if len(data) > limit else "")
