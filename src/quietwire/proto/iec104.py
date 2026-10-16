"""IEC 60870-5-104 dissector (APCI framing + ASDU decoding).

Layouts follow IEC 60870-5-104 / IEC 60870-5-101 (information-element sizes per type id).
Scope: APDU framing with resynchronisation, I/S/U control formats, ASDU header (type, SQ/N,
cause + P/N + test bits, originator, common address), element-size tiling checks, command
decoding (single/double/regulating-step commands, set-points, bitstring), select/execute flag,
system commands (interrogation, clock sync, reset process), parameter and file-transfer types.
Information values of *monitor-direction* data are not decoded (only their structure is checked).
"""

from __future__ import annotations

import struct
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from ..model import Anomaly, ProtoMessage, Target
from .base import MAX_MALFORMED_PER_FEED, FlowDissector, malformed

START = 0x68
MAX_APDU = 253
BROADCAST_CA = 0xFFFF

# type id -> (name, element bytes (excluding the 3-byte IOA), kinds)
_RD, _CTL, _WR, _MON = frozenset(["read"]), frozenset(["control", "write"]), frozenset(["write"]), frozenset(["monitor"])
TYPES: Dict[int, Tuple[str, int, FrozenSet[str]]] = {
    1: ("M_SP_NA_1", 1, _MON), 2: ("M_SP_TA_1", 4, _MON), 3: ("M_DP_NA_1", 1, _MON), 4: ("M_DP_TA_1", 4, _MON),
    5: ("M_ST_NA_1", 2, _MON), 6: ("M_ST_TA_1", 5, _MON), 7: ("M_BO_NA_1", 5, _MON), 8: ("M_BO_TA_1", 8, _MON),
    9: ("M_ME_NA_1", 3, _MON), 10: ("M_ME_TA_1", 6, _MON), 11: ("M_ME_NB_1", 3, _MON), 12: ("M_ME_TB_1", 6, _MON),
    13: ("M_ME_NC_1", 5, _MON), 14: ("M_ME_TC_1", 8, _MON), 15: ("M_IT_NA_1", 5, _MON), 16: ("M_IT_TA_1", 8, _MON),
    17: ("M_EP_TA_1", 6, _MON), 18: ("M_EP_TB_1", 7, _MON), 19: ("M_EP_TC_1", 7, _MON), 20: ("M_PS_NA_1", 5, _MON),
    21: ("M_ME_ND_1", 2, _MON),
    30: ("M_SP_TB_1", 8, _MON), 31: ("M_DP_TB_1", 8, _MON), 32: ("M_ST_TB_1", 9, _MON), 33: ("M_BO_TB_1", 12, _MON),
    34: ("M_ME_TD_1", 10, _MON), 35: ("M_ME_TE_1", 10, _MON), 36: ("M_ME_TF_1", 12, _MON), 37: ("M_IT_TB_1", 12, _MON),
    38: ("M_EP_TD_1", 10, _MON), 39: ("M_EP_TE_1", 11, _MON), 40: ("M_EP_TF_1", 11, _MON),
    45: ("C_SC_NA_1", 1, _CTL), 46: ("C_DC_NA_1", 1, _CTL), 47: ("C_RC_NA_1", 1, _CTL),
    48: ("C_SE_NA_1", 3, _CTL), 49: ("C_SE_NB_1", 3, _CTL), 50: ("C_SE_NC_1", 5, _CTL), 51: ("C_BO_NA_1", 4, _CTL),
    58: ("C_SC_TA_1", 8, _CTL), 59: ("C_DC_TA_1", 8, _CTL), 60: ("C_RC_TA_1", 8, _CTL),
    61: ("C_SE_TA_1", 10, _CTL), 62: ("C_SE_TB_1", 10, _CTL), 63: ("C_SE_TC_1", 12, _CTL), 64: ("C_BO_TA_1", 11, _CTL),
    70: ("M_EI_NA_1", 1, _MON),
    100: ("C_IC_NA_1", 1, _RD), 101: ("C_CI_NA_1", 1, _RD), 102: ("C_RD_NA_1", 0, _RD),
    103: ("C_CS_NA_1", 7, frozenset(["maintenance"])), 104: ("C_TS_NA_1", 2, frozenset(["diagnostic"])),
    105: ("C_RP_NA_1", 1, frozenset(["critical"])), 106: ("C_CD_NA_1", 2, frozenset(["maintenance"])),
    107: ("C_TS_TA_1", 9, frozenset(["diagnostic"])),
    110: ("P_ME_NA_1", 3, _WR), 111: ("P_ME_NB_1", 3, _WR), 112: ("P_ME_NC_1", 5, _WR), 113: ("P_AC_NA_1", 1, _WR),
    120: ("F_FR_NA_1", 6, frozenset(["file_transfer"])), 121: ("F_SR_NA_1", 7, frozenset(["file_transfer"])),
    122: ("F_SC_NA_1", 4, frozenset(["file_transfer"])), 123: ("F_LS_NA_1", 5, frozenset(["file_transfer"])),
    124: ("F_AF_NA_1", 4, frozenset(["file_transfer"])), 125: ("F_SG_NA_1", -1, frozenset(["file_transfer"])),
    126: ("F_DR_TA_1", 13, frozenset(["file_transfer"])), 127: ("F_SC_NB_1", 16, frozenset(["file_transfer"])),
}
_SETPOINT_TYPES = frozenset([48, 49, 50, 61, 62, 63])
_BITSTRING_TYPES = frozenset([51, 64])
COMMAND_TYPES = frozenset(t for t, v in TYPES.items() if v[2] == _CTL)

COT_NAMES = {1: "periodic", 2: "background_scan", 3: "spontaneous", 4: "initialized", 5: "request", 6: "activation",
             7: "activation_con", 8: "deactivation", 9: "deactivation_con", 10: "activation_term",
             11: "return_remote", 12: "return_local", 13: "file_transfer", 20: "interrogated_station",
             44: "unknown_type", 45: "unknown_cause", 46: "unknown_ca", 47: "unknown_ioa"}
for _g in range(1, 17):
    COT_NAMES[20 + _g] = "interrogated_group_%d" % _g
for _g in range(1, 5):
    COT_NAMES[36 + _g] = "counter_group_%d" % _g

U_FUNCTIONS = {0x07: "STARTDT_ACT", 0x0B: "STARTDT_CON", 0x13: "STOPDT_ACT", 0x23: "STOPDT_CON",
               0x43: "TESTFR_ACT", 0x83: "TESTFR_CON"}
MAX_OBJECTS_LISTED = 8
MAX_TARGETS = 256


def type_name(tid: int) -> str:
    entry = TYPES.get(tid)
    return entry[0] if entry else "UNKNOWN_%d" % tid


def _element_decode(tid: int, elem: bytes) -> Optional[Dict[str, Any]]:
    """Decode the command/parameter qualifier of one information element (control direction)."""
    if tid in (45, 58):
        b = elem[0]
        return {"state": "on" if b & 1 else "off", "qualifier": (b >> 2) & 0x1F, "select": bool(b & 0x80)}
    if tid in (46, 59):
        b = elem[0]
        return {"state": {1: "off", 2: "on"}.get(b & 3, "invalid_%d" % (b & 3)), "qualifier": (b >> 2) & 0x1F,
                "select": bool(b & 0x80)}
    if tid in (47, 60):
        b = elem[0]
        return {"step": {1: "lower", 2: "higher"}.get(b & 3, "invalid_%d" % (b & 3)), "qualifier": (b >> 2) & 0x1F,
                "select": bool(b & 0x80)}
    if tid in (48, 61):
        return {"value": struct.unpack("<h", elem[:2])[0] / 32768.0, "select": bool(elem[2] & 0x80), "ql": elem[2] & 0x7F}
    if tid in (49, 62):
        return {"value": struct.unpack("<h", elem[:2])[0], "select": bool(elem[2] & 0x80), "ql": elem[2] & 0x7F}
    if tid in (50, 63):
        return {"value": struct.unpack("<f", elem[:4])[0], "select": bool(elem[4] & 0x80), "ql": elem[4] & 0x7F}
    if tid in (51, 64):
        return {"bits": struct.unpack("<I", elem[:4])[0]}
    return None


def parse_asdu(asdu: bytes, from_master: bool) -> Tuple[ProtoMessage, int]:
    """Decode one ASDU. Returns (message, ioa_count)."""
    anomalies: List[Anomaly] = []
    if len(asdu) < 6:
        return malformed("iec104", from_master, "short_asdu", "ASDU shorter than its 6-byte header", len(asdu)), 0
    tid, vsq, cot_b, org, ca = asdu[0], asdu[1], asdu[2], asdu[3], struct.unpack_from("<H", asdu, 4)[0]
    sq, n = bool(vsq & 0x80), vsq & 0x7F
    cause = cot_b & 0x3F
    negative, test = bool(cot_b & 0x40), bool(cot_b & 0x80)
    entry = TYPES.get(tid)
    kinds = set(entry[2]) if entry else set(["unknown_function"])
    details: Dict[str, Any] = {
        "type_id": tid, "sq": sq, "num_objects": n, "cause": cause, "cause_name": COT_NAMES.get(cause, str(cause)),
        "negative": negative, "test": test, "originator": org, "common_address": ca,
    }
    if cause == 0:
        anomalies.append(Anomaly("bad_cot", "cause of transmission 0 is not defined"))
    if n == 0:
        anomalies.append(Anomaly("zero_objects", "ASDU announces zero information objects"))
    body = asdu[6:]
    targets: List[Target] = []
    ioas: List[int] = []
    controls: List[Dict[str, Any]] = []
    if entry is not None and n > 0:
        esz = entry[1]
        pos = 0
        ok = True
        if esz >= 0:
            need = (3 + n * esz) if sq else n * (3 + esz)
            if need != len(body):
                anomalies.append(Anomaly("bad_asdu_length", "%s with %d object(s) needs %d bytes, ASDU carries %d"
                                         % (entry[0], n, need, len(body))))
                ok = False
        if ok:
            area = ("setpoint" if tid in _SETPOINT_TYPES else "bitstring" if tid in _BITSTRING_TYPES
                    else "parameter" if tid in (110, 111, 112, 113) else "command")
            for i in range(n):
                if sq:
                    if i == 0:
                        ioa0 = int.from_bytes(body[0:3], "little")
                        pos = 3
                    ioa = ioa0 + i
                else:
                    if tid == 125:
                        if pos + 7 > len(body):
                            anomalies.append(Anomaly("bad_asdu_length", "segment object overruns ASDU"))
                            break
                        seg = body[pos + 3 + 3]  # NOF(2) NOS(1) LOS(1) after the IOA
                        eln = 4 + seg
                    else:
                        eln = esz
                    if pos + 3 + eln > len(body):
                        anomalies.append(Anomaly("bad_asdu_length", "information object overruns ASDU"))
                        break
                    ioa = int.from_bytes(body[pos : pos + 3], "little")
                    pos += 3
                if len(ioas) < MAX_OBJECTS_LISTED:
                    ioas.append(ioa)
                if tid in COMMAND_TYPES or tid in (110, 111, 112, 113):
                    if len(targets) < MAX_TARGETS:
                        targets.append(Target(area, ioa, ioa))
                    if tid in COMMAND_TYPES and len(controls) < MAX_OBJECTS_LISTED:
                        elem = body[pos : pos + esz]
                        dec = _element_decode(tid, elem) if len(elem) == esz else None
                        if dec is not None:
                            dec["ioa"] = ioa
                            controls.append(dec)
                pos += esz if tid != 125 else 4 + body[pos + 3]
        if sq and ok and n > 1 and targets:
            targets = [Target(targets[0].area, targets[0].start, targets[0].start + n - 1)]
    details["ioas"] = ioas
    if controls:
        details["controls"] = controls
        details["select"] = any(c.get("select") for c in controls)
    # only activation / deactivation requests are *commands*; confirmations and monitor data are not
    if kinds & {"control", "write"} and cause not in (6, 8):
        kinds -= {"control", "write"}
        kinds.add("monitor")
        targets = []
    msg = ProtoMessage(
        protocol="iec104", is_request=from_master, function=type_name(tid), function_code=tid,
        kinds=frozenset(kinds), targets=tuple(targets), unit=ca, broadcast=(from_master and ca == BROADCAST_CA),
        size=len(asdu) + 6, details=details, anomalies=anomalies,
    )
    return msg, n


def _plausible_start(buf: bytes, i: int) -> bool:
    return buf[i] == START and 4 <= buf[i + 1] <= MAX_APDU


class Iec104Dissector(FlowDissector):
    protocol = "iec104"

    def __init__(self) -> None:
        self._bufs = {True: bytearray(), False: bytearray()}

    def reset(self, from_client: bool) -> None:
        self._bufs[from_client].clear()

    def feed_stream(self, from_client: bool, data: bytes, gap: bool) -> List[ProtoMessage]:
        buf = self._bufs[from_client]
        if gap:
            buf.clear()
        buf += data
        out: List[ProtoMessage] = []
        bad = 0
        while len(buf) >= 2:
            if buf[0] != START or not 4 <= buf[1] <= MAX_APDU:
                if bad < MAX_MALFORMED_PER_FEED:
                    out.append(malformed("iec104", from_client, "bad_apci",
                                         "invalid APCI start/length %s" % bytes(buf[:2]).hex(), len(buf)))
                bad += 1
                skip = next((i for i in range(1, len(buf) - 1) if _plausible_start(buf, i)), None)
                if skip is None:
                    keep = 1 if buf[-1] == START else 0  # a trailing 0x68 may be the start of the next APDU
                    del buf[: len(buf) - keep]
                    break
                del buf[:skip]
                continue
            total = 2 + buf[1]
            if len(buf) < total:
                break
            apdu = bytes(buf[:total])
            del buf[:total]
            out.append(self._apdu(from_client, apdu))
        return out

    @staticmethod
    def _apdu(from_master: bool, apdu: bytes) -> ProtoMessage:
        c1, c2, c3, c4 = apdu[2], apdu[3], apdu[4], apdu[5]
        asdu = apdu[6:]
        if c1 & 1 == 0:  # I-format
            ns = (c1 >> 1) | (c2 << 7)
            nr = (c3 >> 1) | (c4 << 7)
            msg, _n = parse_asdu(asdu, from_master)
            msg.size = len(apdu)
            msg.details.update(format="I", ns=ns, nr=nr)
            return msg
        if c1 & 3 == 1:  # S-format
            anomalies = []
            if c1 != 0x01 or c2 != 0 or c3 & 1 or len(asdu):
                anomalies.append(Anomaly("bad_s_format", "S-format APDU with reserved bits or payload"))
            return ProtoMessage("iec104", from_master, "S_FORMAT", None, frozenset(["link"]), size=len(apdu),
                                details={"format": "S", "nr": (c3 >> 1) | (c4 << 7)}, anomalies=anomalies)
        # U-format
        name = U_FUNCTIONS.get(c1)
        anomalies = []
        if name is None:
            anomalies.append(Anomaly("bad_u_format", "undefined U-format control octet 0x%02x" % c1))
            name = "U_FORMAT_0x%02X" % c1
        if c2 or c3 or c4 or len(asdu):
            anomalies.append(Anomaly("bad_u_format", "U-format APDU with non-zero reserved octets or payload"))
        return ProtoMessage("iec104", from_master, name, c1, frozenset(["session"]), size=len(apdu),
                            details={"format": "U"}, anomalies=anomalies)
