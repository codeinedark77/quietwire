"""S7comm dissector: TPKT (RFC 1006) + COTP (ISO 8073) + S7comm (classic, protocol id 0x32).

S7CommPlus (protocol id 0x72, used by S7-1200/1500 engineering traffic) is
recognised and reported as such but not dissected.  Layouts follow the public
reverse-engineered descriptions (Wireshark s7comm dissector documentation,
snap7 sources); they are not vendor-published specifications.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from ..model import Anomaly, ProtoMessage, Target
from .base import MAX_MALFORMED_PER_FEED, FlowDissector, malformed

MAX_S7_PDU = 65535
_COTP_TYPES = frozenset([0xE0, 0xD0, 0x80, 0xC0, 0xF0, 0x70, 0x60, 0x10, 0x20, 0x30])
MAX_PENDING_COTP = 65535

FUNCTIONS: Dict[int, Tuple[str, FrozenSet[str]]] = {
    0x00: ("CPU_SERVICES", frozenset(["other"])),
    0xF0: ("SETUP_COMMUNICATION", frozenset(["session"])),
    0x04: ("READ_VAR", frozenset(["read"])),
    0x05: ("WRITE_VAR", frozenset(["write"])),
    0x1A: ("REQUEST_DOWNLOAD", frozenset(["critical", "program_transfer"])),
    0x1B: ("DOWNLOAD_BLOCK", frozenset(["critical", "program_transfer"])),
    0x1C: ("DOWNLOAD_ENDED", frozenset(["critical", "program_transfer"])),
    0x1D: ("START_UPLOAD", frozenset(["program_transfer"])),
    0x1E: ("UPLOAD", frozenset(["program_transfer"])),
    0x1F: ("END_UPLOAD", frozenset(["program_transfer"])),
    0x28: ("PI_SERVICE", frozenset(["critical"])),
    0x29: ("PLC_STOP", frozenset(["critical"])),
}
ROSCTR_NAMES = {1: "JOB", 2: "ACK", 3: "ACK_DATA", 7: "USERDATA"}

AREAS = {0x03: "SYS_INFO", 0x05: "SYS_FLAGS", 0x06: "ANA_IN", 0x07: "ANA_OUT", 0x80: "P",
         0x81: "I", 0x82: "Q", 0x83: "M", 0x84: "DB", 0x85: "DI", 0x86: "L", 0x87: "V",
         0x1C: "C", 0x1D: "T", 0x1E: "IEC_C", 0x1F: "IEC_T"}
# S7ANY transport-size (data type) code -> bytes per element (bit access counted as 1)
ELEM_BYTES = {1: 1, 2: 1, 3: 1, 4: 2, 5: 2, 6: 4, 7: 4, 8: 4, 9: 2, 10: 4, 11: 4, 12: 2, 15: 8,
              28: 2, 29: 2, 30: 12, 31: 4, 32: 4}
BLOCK_TYPES = {"08": "OB", "0A": "DB", "0B": "SDB", "0C": "FC", "0D": "SFC", "0E": "FB", "0F": "SFB"}
UD_GROUPS = {0: "MODE_TRANSITION", 1: "PROGRAMMER", 2: "CYCLIC_DATA", 3: "BLOCK_FUNCTIONS",
             4: "CPU_FUNCTIONS", 5: "SECURITY", 6: "PBC", 7: "TIME_FUNCTIONS"}
RETURN_CODES = {0xFF: "success", 0x01: "hardware_fault", 0x03: "access_denied", 0x05: "invalid_address",
                0x06: "data_type_not_supported", 0x07: "data_type_inconsistent", 0x0A: "object_not_available"}
MAX_ITEMS = 32
USERDATA_FUNCTIONS = frozenset(["READ_SZL", "LIST_BLOCKS", "LIST_BLOCKS_OF_TYPE", "GET_BLOCK_INFO", "READ_CLOCK",
                                "SET_CLOCK", "READ_CLOCK_FOLLOWING", "USERDATA"] +
                               ["USERDATA_" + g for g in ("MODE_TRANSITION", "PROGRAMMER", "CYCLIC_DATA",
                                                          "BLOCK_FUNCTIONS", "CPU_FUNCTIONS", "SECURITY", "PBC",
                                                          "TIME_FUNCTIONS")] +
                               ["NO_PARAMETER", "S7COMMPLUS"] +
                               ["S7PLUS_" + n for n in ("ERROR", "EXPLORE", "CREATE_OBJECT", "DELETE_OBJECT",
                                                        "SET_VARIABLE", "GET_LINK", "SET_MULTI_VARIABLES",
                                                        "GET_MULTI_VARIABLES", "BEGIN_SEQUENCE", "END_SEQUENCE",
                                                        "INVOKE", "SET_VAR_SUBSTREAMED", "GET_VAR_SUBSTREAMED",
                                                        "ABORT")])


def _s7_function(code: int) -> Tuple[str, FrozenSet[str]]:
    entry = FUNCTIONS.get(code)
    if entry:
        return entry
    return "UNKNOWN_0x%02X" % code, frozenset(["unknown_function"])


def _parse_var_items(param: bytes, is_write: bool, anomalies: List[Anomaly]
                     ) -> Tuple[List[Dict[str, Any]], List[Target], bool]:
    """Parse READ_VAR/WRITE_VAR job items. Returns items, targets, all_targets_known."""
    if len(param) < 2:
        anomalies.append(Anomaly("bad_length", "variable job parameter too short"))
        return [], [], False
    count = param[1]
    pos = 2
    items: List[Dict[str, Any]] = []
    targets: List[Target] = []
    known = True
    for _ in range(count):
        if pos + 2 > len(param):
            anomalies.append(Anomaly("bad_item", "variable item list truncated"))
            return items, targets, False
        spec, ln = param[pos], param[pos + 1]
        body = param[pos + 2 : pos + 2 + ln]
        if len(body) < ln:
            anomalies.append(Anomaly("bad_item", "variable item overruns parameter block"))
            return items, targets, False
        pos += 2 + ln
        if spec == 0x12 and ln == 10 and body[0] == 0x10:
            tsize = body[1]
            length = (body[2] << 8) | body[3]
            db = (body[4] << 8) | body[5]
            area = body[6]
            addr = (body[7] << 16) | (body[8] << 8) | body[9]
            byte_off = addr >> 3
            width = ELEM_BYTES.get(tsize, 1)
            nbytes = max(1, length * width)
            area_name = AREAS.get(area, "AREA_0x%02X" % area)
            if area == 0x84:
                area_name = "DB%d" % db
            item = {"area": area_name, "area_code": area, "db": db, "address": addr, "length": length,
                    "offset": byte_off, "length_bytes": nbytes, "data_type": tsize}
            if tsize == 1:
                item["bit"] = addr & 7
            if len(items) < MAX_ITEMS:
                items.append(item)
            if len(targets) < 256:
                targets.append(Target(area_name, byte_off, byte_off + nbytes - 1))
        else:
            known = False
            if len(items) < MAX_ITEMS:
                items.append({"spec": spec, "syntax": body[0] if body else None, "unparsed": True})
    if pos != len(param):
        anomalies.append(Anomaly("bad_length", "%d trailing bytes after variable items" % (len(param) - pos)))
    return items, targets, known


def _parse_filename(param: bytes, off: int) -> Optional[Dict[str, str]]:
    if len(param) <= off:
        return None
    ln = param[off]
    raw = param[off + 1 : off + 1 + ln]
    if len(raw) < ln:
        return None
    text = raw.decode("ascii", "replace")
    info = {"filename": text}
    if len(text) == 9 and text[0] == "_":
        info["block_type"] = BLOCK_TYPES.get(text[1:3], text[1:3])
        info["block_number"] = text[3:8]
        info["destination"] = text[8]
    return info


def _parse_pi(param: bytes, off: int) -> Optional[str]:
    # after the (variable) unknown/parameter-block part the service name is length prefixed
    if len(param) <= off:
        return None
    ln = param[off]
    raw = param[off + 1 : off + 1 + ln]
    if len(raw) < ln or ln == 0:
        return None
    return raw.decode("ascii", "replace")


# S7CommPlus (protocol id 0x72, S7-1200/1500 engineering traffic): only the PDU header and the
# function code are decoded. Names follow the public reverse-engineered table; of these only
# CreateObject occurs in the real capture available for validation, so treat the rest as
# "decoded per documentation, not independently verified here" (see LIMITATIONS.md).
S7PLUS_OPCODES = {0x31: "REQUEST", 0x32: "RESPONSE", 0x33: "NOTIFICATION"}
S7PLUS_FUNCTIONS = {
    0x04B1: ("ERROR", frozenset(["exception"])),
    0x04BB: ("EXPLORE", frozenset(["read"])),
    0x04CA: ("CREATE_OBJECT", frozenset(["maintenance"])),
    0x04D4: ("DELETE_OBJECT", frozenset(["maintenance"])),
    0x04F2: ("SET_VARIABLE", frozenset(["write"])),
    0x0524: ("GET_LINK", frozenset(["read"])),
    0x0542: ("SET_MULTI_VARIABLES", frozenset(["write"])),
    0x054C: ("GET_MULTI_VARIABLES", frozenset(["read"])),
    0x0556: ("BEGIN_SEQUENCE", frozenset(["maintenance"])),
    0x0560: ("END_SEQUENCE", frozenset(["maintenance"])),
    0x056B: ("INVOKE", frozenset(["other"])),
    0x0586: ("SET_VAR_SUBSTREAMED", frozenset(["write"])),
    0x0592: ("GET_VAR_SUBSTREAMED", frozenset(["read"])),
    0x059A: ("ABORT", frozenset(["maintenance"])),
}


def _parse_s7plus(payload: bytes, from_client: bool) -> ProtoMessage:
    size = len(payload)
    details: Dict[str, Any] = {"s7commplus": True}
    anomalies: List[Anomaly] = []
    if size < 4:
        return malformed("s7comm", from_client, "short_s7plus", "S7CommPlus header shorter than 4 bytes", size)
    details["version"] = payload[1]
    dlen = (payload[2] << 8) | payload[3]
    if payload[1] not in (1, 2, 3):
        anomalies.append(Anomaly("bad_s7plus_version", "S7CommPlus protocol version %d" % payload[1]))
    if size > 4 and 4 + dlen > size:
        anomalies.append(Anomaly("length_mismatch", "S7CommPlus data length %d exceeds the PDU (%d bytes)"
                                 % (dlen, size - 4)))
    if size < 17 or payload[4] not in S7PLUS_OPCODES or payload[4] == 0x33:
        # keep-alives, notifications, integrity-only PDUs: recognised, function not decoded
        return ProtoMessage("s7comm", from_client, "S7COMMPLUS", 0x72, frozenset(["other"]), size=size,
                            details=details, anomalies=anomalies)
    opcode = payload[4]
    fcode = (payload[7] << 8) | payload[8]
    seq = (payload[11] << 8) | payload[12]
    details.update(opcode=S7PLUS_OPCODES[opcode], seq=seq)
    details["session"] = int.from_bytes(payload[13:17], "big")
    entry = S7PLUS_FUNCTIONS.get(fcode)
    if entry is None:
        name, kinds = "S7PLUS_0x%04X" % fcode, frozenset(["unknown_function"])
    else:
        name, kinds = "S7PLUS_" + entry[0], entry[1]
    details["function_code"] = fcode
    is_request = opcode == 0x31
    if not is_request:  # a response never counts as a request-side write/control
        kinds = frozenset(k for k in kinds if k not in ("write", "unknown_function"))
    return ProtoMessage("s7comm", is_request, name, 0x7200 | 0, kinds, transaction=seq, size=size,
                        details=details, anomalies=anomalies)


def parse_s7(payload: bytes, from_client: bool) -> ProtoMessage:
    size = len(payload)
    if size < 1:
        return malformed("s7comm", from_client, "empty_s7", "empty S7 payload")
    if payload[0] == 0x72:
        return _parse_s7plus(payload, from_client)
    if payload[0] != 0x32:
        return malformed("s7comm", from_client, "bad_protocol_id",
                         "S7 protocol id 0x%02x (expected 0x32)" % payload[0], size)
    if size < 10:
        return malformed("s7comm", from_client, "short_header", "S7 header shorter than 10 bytes", size)
    rosctr = payload[1]
    pduref = (payload[4] << 8) | payload[5]
    plen = (payload[6] << 8) | payload[7]
    dlen = (payload[8] << 8) | payload[9]
    anomalies: List[Anomaly] = []
    details: Dict[str, Any] = {"rosctr": ROSCTR_NAMES.get(rosctr, str(rosctr)), "pdu_ref": pduref}
    hdr = 10
    err: Optional[int] = None
    if rosctr in (2, 3):
        hdr = 12
        if size < 12:
            return malformed("s7comm", from_client, "short_header", "S7 ack header shorter than 12 bytes", size)
        err = (payload[10] << 8) | payload[11]
    elif rosctr not in (1, 7):
        anomalies.append(Anomaly("unknown_rosctr", "ROSCTR %d" % rosctr))
    if hdr + plen + dlen != size:
        anomalies.append(Anomaly("length_mismatch", "S7 lengths (hdr %d + param %d + data %d) != PDU size %d"
                                 % (hdr, plen, dlen, size)))
    param = payload[hdr : hdr + plen]
    data = payload[hdr + plen : hdr + plen + dlen]
    kinds: set = set()
    targets: List[Target] = []
    exception: Optional[int] = None
    if err:
        kinds.add("exception")
        exception = err
        details["error_class"], details["error_code"] = err >> 8, err & 0xFF

    if rosctr == 7:
        return _userdata(param, data, size, pduref, from_client, anomalies, details)

    if rosctr == 2:  # bare acknowledgement
        return ProtoMessage("s7comm", False, "ACK", None, frozenset(kinds), transaction=pduref,
                            exception=exception, size=size, details=details, anomalies=anomalies)

    is_request = rosctr == 1
    if not param:
        anomalies.append(Anomaly("no_parameter", "S7 %s without parameter block" % ROSCTR_NAMES.get(rosctr, "PDU")))
        return ProtoMessage("s7comm", is_request, "NO_PARAMETER", None, frozenset(kinds | {"other"}),
                            transaction=pduref, exception=exception, size=size, details=details,
                            anomalies=anomalies)
    fcode = param[0]
    name, base_kinds = _s7_function(fcode)
    kinds |= set(base_kinds)
    if fcode == 0xF0 and len(param) >= 8:
        details["pdu_length"] = (param[6] << 8) | param[7]
    elif fcode in (0x04, 0x05):
        if is_request:
            items, targets, known = _parse_var_items(param, fcode == 0x05, anomalies)
            details["items"] = items
            if fcode == 0x05 and not known:
                details["targets_unknown"] = True
        elif rosctr == 3 and fcode == 0x05 and len(data) >= 1:
            codes = list(data[: param[1] if len(param) > 1 else 0])
            details["return_codes"] = [RETURN_CODES.get(c, "0x%02X" % c) for c in codes[:MAX_ITEMS]]
            if any(c != 0xFF for c in codes):
                kinds.add("exception")
                exception = next(c for c in codes if c != 0xFF)
        elif rosctr == 3 and fcode == 0x04:
            codes = _read_response_codes(param, data)
            if codes is not None:
                details["return_codes"] = [RETURN_CODES.get(c, "0x%02X" % c) for c in codes[:MAX_ITEMS]]
                if any(c != 0xFF for c in codes):
                    kinds.add("exception")
                    exception = next(c for c in codes if c != 0xFF)
            else:
                anomalies.append(Anomaly("bad_data_items", "READ_VAR response data items malformed"))
    elif fcode in (0x1A, 0x1D) and is_request:
        info = _parse_filename(param, 8)
        if info:
            details.update(info)
    elif fcode == 0x28 and is_request:
        # function, 7 unknown bytes, 2-byte parameter-block length, parameter block, then the
        # length-prefixed service name (e.g. P_PROGRAM, _INSE)
        block = (param[8] << 8) | param[9] if len(param) >= 10 else 0
        svc = _parse_pi(param, 10 + block)
        if svc:
            details["service"] = svc
    elif fcode == 0x29 and is_request:
        svc = _parse_pi(param, 6)
        if svc:
            details["service"] = svc
    return ProtoMessage(
        "s7comm", is_request, name, fcode, frozenset(kinds), targets=tuple(targets), transaction=pduref,
        exception=exception, size=size, details=details, anomalies=anomalies,
    )


def _read_response_codes(param: bytes, data: bytes) -> Optional[List[int]]:
    if len(param) < 2:
        return None
    count = param[1]
    pos = 0
    codes: List[int] = []
    for i in range(count):
        if pos + 4 > len(data):
            return None
        rc, tsize = data[pos], data[pos + 1]
        ln = (data[pos + 2] << 8) | data[pos + 3]
        # Items with an error return code carry no data bytes (length field is informational).
        if rc != 0xFF:
            nbytes = 0
        else:
            nbytes = (ln + 7) // 8 if tsize in (3, 4, 5) else ln
        codes.append(rc)
        pos += 4 + nbytes
        if pos > len(data):
            return None
        if i != count - 1 and nbytes % 2:
            pos += 1  # items are padded to even length except the last
    return codes


def _userdata(param: bytes, data: bytes, size: int, pduref: int, from_client: bool,
              anomalies: List[Anomaly], details: Dict[str, Any]) -> ProtoMessage:
    if len(param) < 8 or param[0:3] != b"\x00\x01\x12":
        anomalies.append(Anomaly("bad_userdata", "userdata parameter head malformed"))
        return ProtoMessage("s7comm", from_client, "USERDATA", 0x00, frozenset(["other"]), transaction=pduref,
                            size=size, details=details, anomalies=anomalies)
    typ, group = param[5] >> 4, param[5] & 0x0F
    sub = param[6]
    is_request = typ == 4
    details.update(group=UD_GROUPS.get(group, str(group)), subfunction=sub)
    kinds: set = set()
    exception: Optional[int] = None
    name = "USERDATA_%s" % UD_GROUPS.get(group, "GROUP_%d" % group)
    if group == 4 and sub == 1:
        name = "READ_SZL"
        kinds.add("discovery")
        if is_request and len(data) >= 8:
            details["szl_id"] = (data[4] << 8) | data[5]
            details["szl_index"] = (data[6] << 8) | data[7]
    elif group == 3:
        kinds.add("discovery")
        name = {1: "LIST_BLOCKS", 2: "LIST_BLOCKS_OF_TYPE", 3: "GET_BLOCK_INFO"}.get(sub, name)
    elif group == 7:
        kinds.add("maintenance" if sub in (2, 4) else "diagnostic")
        name = {1: "READ_CLOCK", 2: "SET_CLOCK", 3: "READ_CLOCK_FOLLOWING", 4: "SET_CLOCK"}.get(sub, name)
    else:
        kinds.add("other")
    if not is_request and len(param) >= 12:
        ec = (param[10] << 8) | param[11]
        if ec not in (0, 0x0000):
            kinds.add("exception")
            exception = ec
            details["error_code"] = ec
    return ProtoMessage("s7comm", is_request, name, 0x00, frozenset(kinds), transaction=pduref,
                        exception=exception, size=size, details=details, anomalies=anomalies)


def _tsap_info(raw: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {"tsap": raw.hex()}
    if len(raw) == 2:
        info["connection_type"] = {1: "PG", 2: "OP", 3: "S7_BASIC"}.get(raw[0], "0x%02x" % raw[0])
        info["rack"] = (raw[1] >> 5) & 0x07
        info["slot"] = raw[1] & 0x1F
    return info


class S7Dissector(FlowDissector):
    protocol = "s7comm"

    def __init__(self) -> None:
        self._bufs = {True: bytearray(), False: bytearray()}
        self._cotp = {True: bytearray(), False: bytearray()}

    def reset(self, from_client: bool) -> None:
        self._bufs[from_client].clear()
        self._cotp[from_client].clear()

    def feed_stream(self, from_client: bool, data: bytes, gap: bool) -> List[ProtoMessage]:
        buf = self._bufs[from_client]
        if gap:
            self.reset(from_client)
        buf += data
        out: List[ProtoMessage] = []
        bad = 0
        while len(buf) >= 4:
            tlen = (buf[2] << 8) | buf[3]
            if buf[0] != 3 or buf[1] != 0 or tlen < 7:
                if bad < MAX_MALFORMED_PER_FEED:
                    out.append(malformed("s7comm", from_client, "bad_tpkt",
                                         "invalid TPKT header %s" % bytes(buf[:4]).hex(), size=len(buf)))
                bad += 1
                skip = None
                for i in range(1, len(buf) - 5):
                    if (buf[i] == 3 and buf[i + 1] == 0 and ((buf[i + 2] << 8) | buf[i + 3]) >= 7
                            and 1 <= buf[i + 4] <= 0x40 and (buf[i + 5] & 0xF0) in _COTP_TYPES):
                        skip = i
                        break
                if skip is None:
                    del buf[:-3]
                    break
                del buf[:skip]
                continue
            if len(buf) < tlen:
                break
            tpkt = bytes(buf[:tlen])
            del buf[:tlen]
            out.extend(self._tpkt(from_client, tpkt))
        return out

    def _tpkt(self, from_client: bool, tpkt: bytes) -> List[ProtoMessage]:
        li = tpkt[4]
        if li < 1 or 5 + li - 1 > len(tpkt) or 4 + 1 + li > len(tpkt):
            return [malformed("s7comm", from_client, "bad_cotp", "COTP length indicator %d overruns TPKT" % li,
                              len(tpkt))]
        ptype = tpkt[5] & 0xF0
        hdr_end = 5 + li
        if ptype in (0xE0, 0xD0):  # connection request / confirm
            name = "COTP_CONNECT_REQUEST" if ptype == 0xE0 else "COTP_CONNECT_CONFIRM"
            details: Dict[str, Any] = {}
            anomalies: List[Anomaly] = []
            if li < 6:
                anomalies.append(Anomaly("bad_cotp", "connection TPDU too short"))
            else:
                pos = 11
                while pos + 2 <= hdr_end:
                    code, plen = tpkt[pos], tpkt[pos + 1]
                    val = tpkt[pos + 2 : pos + 2 + plen]
                    pos += 2 + plen
                    if pos > hdr_end:
                        anomalies.append(Anomaly("bad_cotp", "COTP parameter overruns header"))
                        break
                    if code == 0xC1:
                        details["calling"] = _tsap_info(val)
                    elif code == 0xC2:
                        details["called"] = _tsap_info(val)
                    elif code == 0xC0 and plen == 1:
                        details["tpdu_size"] = 1 << val[0] if val[0] < 16 else None
            return [ProtoMessage("s7comm", ptype == 0xE0, name, ptype, frozenset(["session"]),
                                 size=len(tpkt), details=details, anomalies=anomalies)]
        if ptype in (0x80, 0xC0):
            return [ProtoMessage("s7comm", from_client, "COTP_DISCONNECT" if ptype == 0x80 else "COTP_DISCONNECT_CONFIRM",
                                 ptype, frozenset(["session"]), size=len(tpkt))]
        if ptype == 0xF0:  # data
            if li != 2:
                return [malformed("s7comm", from_client, "bad_cotp", "DT TPDU length indicator %d != 2" % li,
                                  len(tpkt))]
            eot = bool(tpkt[6] & 0x80)
            body = tpkt[hdr_end:]
            acc = self._cotp[from_client]
            acc += body
            if len(acc) > MAX_S7_PDU:
                acc.clear()
                return [malformed("s7comm", from_client, "pdu_too_large", "reassembled S7 PDU too large",
                                  len(tpkt))]
            if not eot:
                return []
            payload = bytes(acc)
            acc.clear()
            if not payload:
                return []
            return [parse_s7(payload, from_client)]
        return [ProtoMessage("s7comm", from_client, "COTP_0x%02X" % ptype, ptype, frozenset(["other"]),
                             size=len(tpkt))]
