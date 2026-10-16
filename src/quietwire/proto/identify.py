"""Signature-based protocol identification for flows on non-standard ports.

Conservative on purpose: a flow is only labelled when its first payload parses
cleanly as a complete, structurally valid message of exactly one protocol.
"""

from __future__ import annotations

from typing import Optional

from ..util import crc16_dnp
from . import modbus
from .modbus import FUNCTIONS as _MODBUS_FUNCS

WELL_KNOWN_TCP = {502: "modbus", 20000: "dnp3", 102: "s7comm", 2404: "iec104"}
WELL_KNOWN_UDP = {502: "modbus", 20000: "dnp3"}


def looks_like_dnp3(p: bytes) -> bool:
    return (len(p) >= 10 and p[0] == 0x05 and p[1] == 0x64 and p[2] >= 5
            and crc16_dnp(p[:8]) == (p[8] | (p[9] << 8)))


def looks_like_s7(p: bytes) -> bool:
    if len(p) < 8 or p[0] != 3 or p[1] != 0:
        return False
    tlen = (p[2] << 8) | p[3]
    if tlen < 7 or tlen > len(p):
        return False
    li = p[4]
    ptype = p[5] & 0xF0
    if ptype in (0xE0, 0xD0):
        return li >= 6 and 5 + li <= tlen
    if ptype == 0xF0:
        return li == 2 and tlen >= 8 and (tlen == 7 or p[7] in (0x32, 0x72))
    return False


def looks_like_modbus(p: bytes) -> bool:
    if len(p) < 8 or p[2] != 0 or p[3] != 0:
        return False
    length = (p[4] << 8) | p[5]
    if not 2 <= length <= 254 or 6 + length > len(p):
        return False
    fc = p[7] & 0x7F
    if fc not in _MODBUS_FUNCS:
        return False
    for is_request in (True, False):
        msg = modbus.parse_adu(p[: 6 + length], is_request)
        if not msg.anomalies:
            return True
    return False


def looks_like_iec104(p: bytes) -> bool:
    """A complete APDU that is a valid U/S frame or an I frame whose ASDU tiles exactly."""
    if len(p) < 6 or p[0] != 0x68 or not 4 <= p[1] <= 253 or len(p) < 2 + p[1]:
        return False
    from . import iec104

    msg = iec104.Iec104Dissector._apdu(True, p[: 2 + p[1]])
    if msg.anomalies or "malformed" in msg.kinds:
        return False
    if msg.details.get("format") == "I":
        return msg.function_code in iec104.TYPES and msg.details["num_objects"] > 0
    return True


def identify(payload: bytes) -> Optional[str]:
    """Return 'dnp3' / 's7comm' / 'iec104' / 'modbus' or None."""
    if looks_like_dnp3(payload):
        return "dnp3"
    if looks_like_s7(payload):
        return "s7comm"
    if looks_like_iec104(payload):
        return "iec104"
    if looks_like_modbus(payload):
        return "modbus"
    return None
