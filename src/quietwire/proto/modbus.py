"""Modbus/TCP (and Modbus over UDP) dissector.

Structural rules follow the MODBUS Application Protocol Specification V1.1b3
and the MODBUS Messaging on TCP/IP Implementation Guide V1.0b.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from ..model import Anomaly, ProtoMessage, Target
from .base import MAX_MALFORMED_PER_FEED, FlowDissector, malformed

# function code -> (name, kinds)
FUNCTIONS: Dict[int, Tuple[str, FrozenSet[str]]] = {
    1: ("READ_COILS", frozenset(["read"])),
    2: ("READ_DISCRETE_INPUTS", frozenset(["read"])),
    3: ("READ_HOLDING_REGISTERS", frozenset(["read"])),
    4: ("READ_INPUT_REGISTERS", frozenset(["read"])),
    5: ("WRITE_SINGLE_COIL", frozenset(["write"])),
    6: ("WRITE_SINGLE_REGISTER", frozenset(["write"])),
    7: ("READ_EXCEPTION_STATUS", frozenset(["read"])),
    8: ("DIAGNOSTICS", frozenset(["diagnostic"])),
    11: ("GET_COMM_EVENT_COUNTER", frozenset(["diagnostic"])),
    12: ("GET_COMM_EVENT_LOG", frozenset(["diagnostic"])),
    15: ("WRITE_MULTIPLE_COILS", frozenset(["write"])),
    16: ("WRITE_MULTIPLE_REGISTERS", frozenset(["write"])),
    17: ("REPORT_SERVER_ID", frozenset(["discovery"])),
    20: ("READ_FILE_RECORD", frozenset(["read"])),
    21: ("WRITE_FILE_RECORD", frozenset(["write"])),
    22: ("MASK_WRITE_REGISTER", frozenset(["write"])),
    23: ("READ_WRITE_MULTIPLE_REGISTERS", frozenset(["read", "write"])),
    24: ("READ_FIFO_QUEUE", frozenset(["read"])),
    43: ("ENCAPSULATED_INTERFACE_TRANSPORT", frozenset(["diagnostic"])),
}

DIAG_SUBFUNCTIONS = {
    0x0000: "RETURN_QUERY_DATA",
    0x0001: "RESTART_COMMUNICATIONS_OPTION",
    0x0002: "RETURN_DIAGNOSTIC_REGISTER",
    0x0003: "CHANGE_ASCII_INPUT_DELIMITER",
    0x0004: "FORCE_LISTEN_ONLY_MODE",
    0x000A: "CLEAR_COUNTERS_AND_DIAGNOSTIC_REGISTER",
    0x000B: "RETURN_BUS_MESSAGE_COUNT",
    0x000C: "RETURN_BUS_COMMUNICATION_ERROR_COUNT",
    0x000D: "RETURN_BUS_EXCEPTION_ERROR_COUNT",
    0x000E: "RETURN_SERVER_MESSAGE_COUNT",
    0x000F: "RETURN_SERVER_NO_RESPONSE_COUNT",
    0x0010: "RETURN_SERVER_NAK_COUNT",
    0x0011: "RETURN_SERVER_BUSY_COUNT",
    0x0012: "RETURN_BUS_CHARACTER_OVERRUN_COUNT",
    0x0014: "CLEAR_OVERRUN_COUNTER_AND_FLAG",
}
CRITICAL_DIAG = frozenset([0x0001, 0x0004])

EXCEPTIONS = {
    1: "ILLEGAL_FUNCTION",
    2: "ILLEGAL_DATA_ADDRESS",
    3: "ILLEGAL_DATA_VALUE",
    4: "SERVER_DEVICE_FAILURE",
    5: "ACKNOWLEDGE",
    6: "SERVER_DEVICE_BUSY",
    8: "MEMORY_PARITY_ERROR",
    10: "GATEWAY_PATH_UNAVAILABLE",
    11: "GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND",
}

DEVICE_ID_OBJECTS = {
    0: "VendorName", 1: "ProductCode", 2: "MajorMinorRevision", 3: "VendorUrl",
    4: "ProductName", 5: "ModelName", 6: "UserApplicationName",
}

MAX_VALUES = 16


def function_name(fc: int) -> str:
    entry = FUNCTIONS.get(fc)
    return entry[0] if entry else "UNKNOWN_%d" % fc


def _u16(b: bytes, off: int) -> int:
    return (b[off] << 8) | b[off + 1]


def parse_pdu(fc_byte: int, data: bytes, is_request: bool) -> Tuple[str, FrozenSet[str], Tuple[Target, ...], Dict[str, Any], List[Anomaly], Optional[int]]:
    """Decode one PDU. Returns name, kinds, targets, details, anomalies, exception_code."""
    anomalies: List[Anomaly] = []
    details: Dict[str, Any] = {}
    targets: Tuple[Target, ...] = ()
    exc: Optional[int] = None
    is_exc = bool(fc_byte & 0x80)
    fc = fc_byte & 0x7F
    name = function_name(fc)
    base = FUNCTIONS.get(fc)
    kinds = set(base[1]) if base else set(["unknown_function"])

    def bad(code: str, msg: str) -> None:
        anomalies.append(Anomaly(code, msg))

    if is_exc:
        if is_request:
            bad("exception_in_request", "exception function code 0x%02x in a request" % fc_byte)
        if len(data) != 1:
            bad("bad_exception_length", "exception PDU has %d data bytes (expected 1)" % len(data))
        else:
            exc = data[0]
            details["exception_name"] = EXCEPTIONS.get(exc, "UNKNOWN_%d" % exc)
        kinds = set(["exception"]) | (set(["unknown_function"]) if not base else set())
        return name, frozenset(kinds), targets, details, anomalies, exc

    n = len(data)
    if fc not in FUNCTIONS:
        details["raw_len"] = n
        return name, frozenset(kinds), targets, details, anomalies, exc

    if is_request:
        if fc in (1, 2, 3, 4):
            if n != 4:
                bad("bad_length", "%s request length %d != 4" % (name, n))
            else:
                start, qty = _u16(data, 0), _u16(data, 2)
                details.update(start=start, quantity=qty)
                limit = 2000 if fc in (1, 2) else 125
                if not 1 <= qty <= limit:
                    bad("bad_quantity", "%s quantity %d outside 1..%d" % (name, qty, limit))
        elif fc == 5:
            if n != 4:
                bad("bad_length", "WRITE_SINGLE_COIL length %d != 4" % n)
            else:
                addr, val = _u16(data, 0), _u16(data, 2)
                details.update(start=addr, value=val)
                targets = (Target("coil", addr, addr),)
                if val not in (0x0000, 0xFF00):
                    bad("bad_value", "coil value 0x%04x is neither 0x0000 nor 0xFF00" % val)
        elif fc == 6:
            if n != 4:
                bad("bad_length", "WRITE_SINGLE_REGISTER length %d != 4" % n)
            else:
                addr, val = _u16(data, 0), _u16(data, 2)
                details.update(start=addr, value=val)
                targets = (Target("holding_register", addr, addr),)
        elif fc in (7, 11, 12, 17):
            if n != 0:
                bad("bad_length", "%s request carries %d unexpected bytes" % (name, n))
        elif fc == 8:
            if n < 2:
                bad("bad_length", "DIAGNOSTICS request shorter than 2 bytes")
            else:
                sub = _u16(data, 0)
                details["subfunction"] = sub
                details["subfunction_name"] = DIAG_SUBFUNCTIONS.get(sub, "UNKNOWN_%d" % sub)
                if sub in CRITICAL_DIAG:
                    kinds.add("critical")
        elif fc == 15:
            if n < 5:
                bad("bad_length", "WRITE_MULTIPLE_COILS request too short")
            else:
                start, qty, bc = _u16(data, 0), _u16(data, 2), data[4]
                details.update(start=start, quantity=qty)
                if not 1 <= qty <= 1968:
                    bad("bad_quantity", "coil quantity %d outside 1..1968" % qty)
                if bc != (qty + 7) // 8 or n != 5 + bc:
                    bad("bad_byte_count", "byte count %d inconsistent with quantity %d / length %d" % (bc, qty, n))
                if 1 <= qty <= 1968:
                    targets = (Target("coil", start, start + qty - 1),)
        elif fc == 16:
            if n < 5:
                bad("bad_length", "WRITE_MULTIPLE_REGISTERS request too short")
            else:
                start, qty, bc = _u16(data, 0), _u16(data, 2), data[4]
                details.update(start=start, quantity=qty)
                if not 1 <= qty <= 123:
                    bad("bad_quantity", "register quantity %d outside 1..123" % qty)
                if bc != 2 * qty or n != 5 + bc:
                    bad("bad_byte_count", "byte count %d inconsistent with quantity %d / length %d" % (bc, qty, n))
                if 1 <= qty <= 123:
                    targets = (Target("holding_register", start, start + qty - 1),)
        elif fc == 20:
            if n < 1 or data[0] != n - 1 or data[0] % 7 != 0 or not 7 <= data[0] <= 0xF5:
                bad("bad_byte_count", "READ_FILE_RECORD byte count inconsistent")
            else:
                details["sub_requests"] = data[0] // 7
        elif fc == 21:
            if n < 1 or data[0] != n - 1 or not 9 <= data[0] <= 0xFB:
                bad("bad_byte_count", "WRITE_FILE_RECORD byte count inconsistent")
            else:
                pos, count = 1, 0
                while pos + 7 <= n:
                    rec_len = _u16(data, pos + 5)
                    pos += 7 + 2 * rec_len
                    count += 1
                if pos != n:
                    bad("bad_file_record", "WRITE_FILE_RECORD sub-requests do not tile the PDU")
                details["sub_requests"] = count
        elif fc == 22:
            if n != 6:
                bad("bad_length", "MASK_WRITE_REGISTER length %d != 6" % n)
            else:
                addr = _u16(data, 0)
                details.update(start=addr, and_mask=_u16(data, 2), or_mask=_u16(data, 4))
                targets = (Target("holding_register", addr, addr),)
        elif fc == 23:
            if n < 9:
                bad("bad_length", "READ_WRITE_MULTIPLE_REGISTERS request too short")
            else:
                rs, rq, ws, wq, bc = _u16(data, 0), _u16(data, 2), _u16(data, 4), _u16(data, 6), data[8]
                details.update(read_start=rs, read_quantity=rq, write_start=ws, write_quantity=wq)
                if not 1 <= rq <= 125 or not 1 <= wq <= 121:
                    bad("bad_quantity", "read %d / write %d quantity out of range" % (rq, wq))
                if bc != 2 * wq or n != 9 + bc:
                    bad("bad_byte_count", "byte count %d inconsistent with write quantity %d" % (bc, wq))
                if 1 <= wq <= 121:
                    targets = (Target("holding_register", ws, ws + wq - 1),)
        elif fc == 24:
            if n != 2:
                bad("bad_length", "READ_FIFO_QUEUE length %d != 2" % n)
            else:
                details["start"] = _u16(data, 0)
        elif fc == 43:
            if n < 1:
                bad("bad_length", "ENCAPSULATED_INTERFACE_TRANSPORT request empty")
            else:
                mei = data[0]
                details["mei_type"] = mei
                if mei == 0x0E:
                    kinds.add("discovery")
                    if n != 3 or not 1 <= data[1] <= 4:
                        bad("bad_device_id_request", "malformed Read Device Identification request")
                    else:
                        details.update(read_device_id_code=data[1], object_id=data[2])
    else:
        if fc in (1, 2, 3, 4):
            if n < 1 or data[0] != n - 1:
                bad("bad_byte_count", "%s response byte count inconsistent" % name)
            elif fc in (3, 4):
                if data[0] % 2:
                    bad("bad_byte_count", "register response has odd byte count %d" % data[0])
                else:
                    regs = struct.unpack(">%dH" % (data[0] // 2), data[1:])
                    details["values"] = list(regs[:MAX_VALUES])
                    details["value_count"] = len(regs)
            else:
                details["byte_count"] = data[0]
        elif fc in (5, 6, 15, 16, 11):
            if n != 4:
                bad("bad_length", "%s response length %d != 4" % (name, n))
        elif fc == 7:
            if n != 1:
                bad("bad_length", "READ_EXCEPTION_STATUS response length %d != 1" % n)
        elif fc == 8:
            if n < 2:
                bad("bad_length", "DIAGNOSTICS response shorter than 2 bytes")
            else:
                details["subfunction"] = _u16(data, 0)
        elif fc in (12, 17, 20, 23):
            if n < 1 or data[0] != n - 1:
                bad("bad_byte_count", "%s response byte count inconsistent" % name)
            elif fc == 17:
                details["server_id_hex"] = data[1:33].hex()
            elif fc == 23 and data[0] % 2:
                bad("bad_byte_count", "READ_WRITE_MULTIPLE_REGISTERS response odd byte count")
        elif fc == 22:
            if n != 6:
                bad("bad_length", "MASK_WRITE_REGISTER response length %d != 6" % n)
        elif fc == 24:
            if n < 4 or _u16(data, 0) != n - 2:
                bad("bad_byte_count", "READ_FIFO_QUEUE response byte count inconsistent")
        elif fc == 43:
            _parse_device_id_response(data, details, anomalies)
    return name, frozenset(kinds), targets, details, anomalies, exc


def _parse_device_id_response(data: bytes, details: Dict[str, Any], anomalies: List[Anomaly]) -> None:
    if len(data) < 1:
        anomalies.append(Anomaly("bad_length", "ENCAPSULATED_INTERFACE_TRANSPORT response empty"))
        return
    details["mei_type"] = data[0]
    if data[0] != 0x0E:
        return
    if len(data) < 6:
        anomalies.append(Anomaly("bad_device_id_response", "Read Device Identification response too short"))
        return
    count = data[5]
    pos = 6
    objs: Dict[str, str] = {}
    for _ in range(count):
        if pos + 2 > len(data):
            anomalies.append(Anomaly("bad_device_id_response", "device identification object list truncated"))
            return
        oid, olen = data[pos], data[pos + 1]
        pos += 2
        if pos + olen > len(data):
            anomalies.append(Anomaly("bad_device_id_response", "device identification object overruns PDU"))
            return
        text = data[pos : pos + olen].decode("ascii", "replace")
        objs[DEVICE_ID_OBJECTS.get(oid, "object_%d" % oid)] = "".join(c if 32 <= ord(c) < 127 else "?" for c in text)
        pos += olen
    details["device_id"] = objs


def parse_adu(frame: bytes, is_request: bool) -> ProtoMessage:
    """Decode one complete MBAP frame (header + unit + PDU)."""
    tid, _pid, length, unit = struct.unpack_from(">HHHB", frame, 0)
    fc_byte = frame[7] if len(frame) > 7 else 0
    if len(frame) < 8:
        return ProtoMessage("modbus", is_request, "EMPTY_PDU", None, frozenset(["malformed"]), unit=unit,
                            transaction=tid, size=len(frame),
                            anomalies=[Anomaly("empty_pdu", "MBAP frame carries no function code")])
    name, kinds, targets, details, anomalies, exc = parse_pdu(fc_byte, frame[8:], is_request)
    return ProtoMessage(
        protocol="modbus",
        is_request=is_request,
        function=name,
        function_code=fc_byte & 0x7F,
        kinds=kinds,
        targets=targets,
        unit=unit,
        transaction=tid,
        exception=exc,
        broadcast=(unit == 0 and is_request),
        size=len(frame),
        details=details,
        anomalies=anomalies,
    )


def _plausible_header(buf: bytes, i: int) -> bool:
    return buf[i + 2] == 0 and buf[i + 3] == 0 and 2 <= ((buf[i + 4] << 8) | buf[i + 5]) <= 254


def _valid_candidate(buf: bytearray, i: int, at_boundary: bool) -> bool:
    """Is there a complete frame at ``i`` that is safe to resynchronise on?

    Candidates at a TCP chunk boundary (clients send one ADU per segment, so a
    segment start is where a frame is most likely to begin) are accepted on a
    plausible header alone, which keeps fuzzed and vendor-specific function codes
    visible after a desynchronisation. Mid-chunk candidates must additionally use
    a defined function code, parse cleanly and be followed by nothing/another
    plausible header, so zero-heavy non-Modbus payloads on port 502 do not create
    phantom messages.
    """
    if len(buf) - i < 8 or not _plausible_header(buf, i):
        return False
    total = 6 + ((buf[i + 4] << 8) | buf[i + 5])
    if len(buf) - i < total:
        return False
    rest = len(buf) - i - total
    if rest >= 7 and not _plausible_header(buf, i + total):
        return False
    if at_boundary:
        return True
    if (buf[i + 7] & 0x7F) not in FUNCTIONS:
        return False
    frame = bytes(buf[i : i + total])
    return any(not parse_adu(frame, r).anomalies for r in (True, False))


class ModbusDissector(FlowDissector):
    protocol = "modbus"

    def __init__(self) -> None:
        self._bufs = {True: bytearray(), False: bytearray()}
        self._marks = {True: set(), False: set()}  # chunk-start offsets inside each buffer

    def reset(self, from_client: bool) -> None:
        self._bufs[from_client].clear()
        self._marks[from_client].clear()

    def _consume(self, from_client: bool, n: int) -> None:
        del self._bufs[from_client][:n]
        self._marks[from_client] = {m - n for m in self._marks[from_client] if m - n > 0}

    def feed_stream(self, from_client: bool, data: bytes, gap: bool) -> List[ProtoMessage]:
        buf = self._bufs[from_client]
        if gap:
            self.reset(from_client)
        if buf:
            self._marks[from_client].add(len(buf))
        buf += data
        out: List[ProtoMessage] = []
        bad = 0
        while len(buf) >= 7:
            length = (buf[4] << 8) | buf[5]
            if buf[2] != 0 or buf[3] != 0 or length < 2 or length > 254:
                if bad < MAX_MALFORMED_PER_FEED:
                    out.append(malformed("modbus", from_client, "bad_mbap",
                                         "invalid MBAP header %s" % bytes(buf[:7]).hex(), size=len(buf)))
                bad += 1
                marks = self._marks[from_client]
                skip = None
                for i in range(1, len(buf) - 7):
                    if _valid_candidate(buf, i, i in marks):
                        skip = i
                        break
                if skip is None:
                    keep = min(len(buf), 6)
                    self._consume(from_client, len(buf) - keep)
                    break
                self._consume(from_client, skip)
                continue
            total = 6 + length
            if len(buf) < total:
                break
            frame = bytes(buf[:total])
            self._consume(from_client, total)
            out.append(parse_adu(frame, from_client))
        return out
