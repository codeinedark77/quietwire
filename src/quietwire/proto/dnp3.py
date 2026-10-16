"""DNP3 (IEEE 1815) dissector: data link, transport and application layers.

Scope: link framing with CRC verification, transport reassembly, application
header + object-header parsing with a table of common object sizes, CROB /
analog-output control decoding, IIN flag decoding.  Secure Authentication (g120)
and file-transfer payloads (g70) are recognised but not decoded in depth.
"""

from __future__ import annotations

import struct
from collections import OrderedDict
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from ..model import Anomaly, ProtoMessage, Target
from ..util import crc16_dnp
from .base import MAX_MALFORMED_PER_FEED, FlowDissector, malformed

START = b"\x05\x64"
MAX_FRAGMENT = 4096  # spec maximum is 2048; allow slack but bound memory
BROADCAST_MIN = 0xFFFD

LINK_PRIMARY = {0: "RESET_LINK_STATES", 2: "TEST_LINK_STATES", 3: "CONFIRMED_USER_DATA",
                4: "UNCONFIRMED_USER_DATA", 9: "REQUEST_LINK_STATUS"}
LINK_SECONDARY = {0: "ACK", 1: "NACK", 11: "LINK_STATUS", 15: "NOT_SUPPORTED"}

APP_FUNCTIONS: Dict[int, str] = {
    0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE", 5: "DIRECT_OPERATE",
    6: "DIRECT_OPERATE_NR", 7: "IMMED_FREEZE", 8: "IMMED_FREEZE_NR", 9: "FREEZE_CLEAR",
    10: "FREEZE_CLEAR_NR", 11: "FREEZE_AT_TIME", 12: "FREEZE_AT_TIME_NR", 13: "COLD_RESTART",
    14: "WARM_RESTART", 15: "INITIALIZE_DATA", 16: "INITIALIZE_APPL", 17: "START_APPL",
    18: "STOP_APPL", 19: "SAVE_CONFIG", 20: "ENABLE_UNSOLICITED", 21: "DISABLE_UNSOLICITED",
    22: "ASSIGN_CLASS", 23: "DELAY_MEASURE", 24: "RECORD_CURRENT_TIME", 25: "OPEN_FILE",
    26: "CLOSE_FILE", 27: "DELETE_FILE", 28: "GET_FILE_INFO", 29: "AUTHENTICATE_FILE",
    30: "ABORT_FILE", 31: "ACTIVATE_CONFIG", 32: "AUTHENTICATE_REQ", 33: "AUTH_REQ_NO_ACK",
    129: "RESPONSE", 130: "UNSOLICITED_RESPONSE", 131: "AUTHENTICATE_RESP",
}
RESPONSE_FCS = frozenset([129, 130, 131])

_KINDS: Dict[int, FrozenSet[str]] = {
    1: frozenset(["read"]),
    2: frozenset(["write"]),
    3: frozenset(["control", "write"]),
    4: frozenset(["control", "write"]),
    5: frozenset(["control", "write"]),
    6: frozenset(["control", "write"]),
    7: frozenset(["maintenance"]), 8: frozenset(["maintenance"]), 9: frozenset(["maintenance"]),
    10: frozenset(["maintenance"]), 11: frozenset(["maintenance"]), 12: frozenset(["maintenance"]),
    13: frozenset(["critical"]), 14: frozenset(["critical"]), 15: frozenset(["critical"]),
    16: frozenset(["critical"]), 17: frozenset(["critical"]), 18: frozenset(["critical"]),
    19: frozenset(["critical"]),
    20: frozenset(["maintenance"]), 21: frozenset(["maintenance"]),
    22: frozenset(["maintenance"]), 23: frozenset(["maintenance"]), 24: frozenset(["maintenance"]),
    25: frozenset(["file_transfer"]), 26: frozenset(["file_transfer"]),
    27: frozenset(["critical", "file_transfer"]), 28: frozenset(["file_transfer"]),
    29: frozenset(["file_transfer"]), 30: frozenset(["file_transfer"]),
    31: frozenset(["critical"]),
    32: frozenset(["maintenance"]), 33: frozenset(["maintenance"]),
}
# functions whose object headers are followed by object data (all others carry headers only)
_CARRIES_DATA = frozenset([2, 3, 4, 5, 6, 15, 16, 17, 18, 19, 25, 26, 27, 28, 29, 30, 31, 32, 33, 129, 130, 131])

IIN1 = ["BROADCAST", "CLASS_1_EVENTS", "CLASS_2_EVENTS", "CLASS_3_EVENTS", "NEED_TIME",
        "LOCAL_CONTROL", "DEVICE_TROUBLE", "DEVICE_RESTART"]
IIN2 = ["NO_FUNC_CODE_SUPPORT", "OBJECT_UNKNOWN", "PARAMETER_ERROR", "EVENT_BUFFER_OVERFLOW",
        "ALREADY_EXECUTING", "CONFIG_CORRUPT", "RESERVED_1", "RESERVED_2"]

# (group, variation) -> bytes per object (data only, excluding index/size prefix)
OBJ_SIZES: Dict[Tuple[int, int], int] = {
    (1, 2): 1, (2, 1): 1, (2, 2): 7, (2, 3): 3, (3, 2): 1, (4, 1): 1, (4, 2): 7, (4, 3): 3,
    (10, 2): 1, (11, 1): 1, (11, 2): 7, (12, 1): 11, (12, 2): 11, (13, 1): 1, (13, 2): 7,
    (20, 1): 5, (20, 2): 3, (20, 5): 4, (20, 6): 2,
    (21, 1): 5, (21, 2): 3, (21, 5): 11, (21, 6): 9, (21, 9): 4, (21, 10): 2,
    (22, 1): 5, (22, 2): 3, (22, 5): 11, (22, 6): 9,
    (23, 1): 5, (23, 2): 3, (23, 5): 11, (23, 6): 9,
    (30, 1): 5, (30, 2): 3, (30, 3): 4, (30, 4): 2, (30, 5): 5, (30, 6): 9,
    (32, 1): 5, (32, 2): 3, (32, 3): 11, (32, 4): 9, (32, 5): 5, (32, 6): 9, (32, 7): 11, (32, 8): 15,
    (40, 1): 5, (40, 2): 3, (40, 3): 5, (40, 4): 9,
    (41, 1): 5, (41, 2): 3, (41, 3): 5, (41, 4): 9,
    (42, 1): 5, (42, 2): 3, (42, 3): 11, (42, 4): 9, (42, 5): 5, (42, 6): 9, (42, 7): 11, (42, 8): 15,
    (43, 1): 5, (43, 2): 3, (43, 3): 11, (43, 4): 9, (43, 5): 5, (43, 6): 9, (43, 7): 11, (43, 8): 15,
    (50, 1): 6, (50, 2): 10, (50, 3): 6, (50, 4): 11, (51, 1): 6, (51, 2): 6, (52, 1): 2, (52, 2): 2,
    (60, 1): 0, (60, 2): 0, (60, 3): 0, (60, 4): 0,
}
# packed-bit variations: (group, variation) -> bits per object
PACKED_BITS: Dict[Tuple[int, int], int] = {(1, 1): 1, (10, 1): 1, (80, 1): 1, (3, 1): 2}

CROB_OPS = {0: "NUL", 1: "PULSE_ON", 2: "PULSE_OFF", 3: "LATCH_ON", 4: "LATCH_OFF"}
CROB_TCC = {0: "NUL", 1: "CLOSE", 2: "TRIP", 3: "RESERVED"}
MAX_LISTED = 16
MAX_TARGETS = 256


class _ObjectError(ValueError):
    pass


def decode_iin(b1: int, b2: int) -> List[str]:
    flags = [IIN1[i] for i in range(8) if b1 & (1 << i)]
    flags += [IIN2[i] for i in range(8) if b2 & (1 << i) and not IIN2[i].startswith("RESERVED")]
    return flags


def _read_uint(buf: bytes, pos: int, n: int) -> int:
    return int.from_bytes(buf[pos : pos + n], "little")


def parse_objects(buf: bytes, pos: int, with_data: bool, fc: int
                  ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Target], List[Anomaly], bool]:
    """Parse object headers (and data when ``with_data``).

    Returns (objects, controls, targets, anomalies, fully_parsed).
    """
    objects: List[Dict[str, Any]] = []
    controls: List[Dict[str, Any]] = []
    targets: List[Target] = []
    anomalies: List[Anomaly] = []
    n = len(buf)
    try:
        while pos < n:
            if pos + 3 > n:
                raise _ObjectError("truncated object header")
            g, v, q = buf[pos], buf[pos + 1], buf[pos + 2]
            pos += 3
            prefix = (q >> 4) & 0x07
            rng = q & 0x0F
            start = stop = None
            count: Optional[int] = None
            if rng in (0, 3):
                sz = 1
            elif rng in (1, 4):
                sz = 2
            elif rng in (2, 5):
                sz = 4
            else:
                sz = 0
            if rng in (0, 1, 2, 3, 4, 5):
                if pos + 2 * sz > n:
                    raise _ObjectError("truncated range for g%dv%d" % (g, v))
                start = _read_uint(buf, pos, sz)
                stop = _read_uint(buf, pos + sz, sz)
                pos += 2 * sz
                if stop < start:
                    raise _ObjectError("range stop %d < start %d for g%dv%d" % (stop, start, g, v))
                count = stop - start + 1
            elif rng == 6:
                count = None
            elif rng in (7, 8, 9):
                csz = {7: 1, 8: 2, 9: 4}[rng]
                if pos + csz > n:
                    raise _ObjectError("truncated count for g%dv%d" % (g, v))
                count = _read_uint(buf, pos, csz)
                pos += csz
            elif rng == 0x0B:
                if pos + 1 > n:
                    raise _ObjectError("truncated variable-format count")
                count = buf[pos]
                pos += 1
            else:
                raise _ObjectError("reserved range code 0x%x in qualifier 0x%02x" % (rng, q))
            if prefix == 7 or (rng == 0x0B and prefix not in (4, 5, 6)):
                raise _ObjectError("unsupported prefix code in qualifier 0x%02x" % q)
            desc: Dict[str, Any] = {"group": g, "variation": v, "qualifier": q}
            if count is not None:
                desc["count"] = count
            if start is not None:
                desc["start"] = start
                desc["stop"] = stop
            if len(objects) < MAX_LISTED * 2:
                objects.append(desc)
            # Free-format qualifier (range code 0xB) objects always carry data, even in a READ
            # request (e.g. g70v5 file transport); everything else follows the function code.
            if not with_data and rng != 0x0B:
                continue
            if count is None:
                # "all objects" qualifier inside a data-carrying message carries no data
                continue
            idx_bytes = {0: 0, 1: 1, 2: 2, 3: 4}.get(prefix, 0)
            size_prefix = {4: 1, 5: 2, 6: 4}.get(prefix, 0)
            if (g, v) in PACKED_BITS:
                bits = PACKED_BITS[(g, v)]
                need = (count * bits + 7) // 8
                if pos + need > n:
                    raise _ObjectError("g%dv%d packed data overruns fragment" % (g, v))
                pos += need
                continue
            osz = OBJ_SIZES.get((g, v))
            if osz is None:
                if size_prefix == 0:
                    # cannot determine object length: stop here without error
                    desc["unparsed"] = True
                    return objects, controls, targets, anomalies, False
                for _ in range(count):
                    if pos + size_prefix > n:
                        raise _ObjectError("size prefix overruns fragment")
                    olen = _read_uint(buf, pos, size_prefix)
                    pos += size_prefix + olen
                    if pos > n:
                        raise _ObjectError("variable object g%dv%d overruns fragment" % (g, v))
                continue
            per = idx_bytes + osz
            if size_prefix:
                per += size_prefix
            if count and per * count > n - pos:
                raise _ObjectError("g%dv%d objects (%d x %d bytes) overrun fragment" % (g, v, count, per))
            for k in range(count):
                if idx_bytes:
                    index = _read_uint(buf, pos, idx_bytes)
                elif start is not None:
                    index = start + k
                else:
                    index = k
                body = pos + idx_bytes + size_prefix
                if g == 12 and v == 1 and fc in (3, 4, 5, 6):
                    cc = buf[body]
                    on_ms, off_ms = struct.unpack_from("<II", buf, body + 2)
                    ctl = {
                        "index": index,
                        "op": CROB_OPS.get(cc & 0x0F, "UNKNOWN_%d" % (cc & 0x0F)),
                        "tcc": CROB_TCC[(cc >> 6) & 3],
                        "count": buf[body + 1],
                        "on_ms": on_ms,
                        "off_ms": off_ms,
                    }
                    if len(controls) < MAX_LISTED:
                        controls.append(ctl)
                    if len(targets) < MAX_TARGETS:
                        targets.append(Target("binary_output", index, index))
                elif g == 41 and fc in (3, 4, 5, 6):
                    if v == 1:
                        val: Any = struct.unpack_from("<i", buf, body)[0]
                    elif v == 2:
                        val = struct.unpack_from("<h", buf, body)[0]
                    elif v == 3:
                        val = struct.unpack_from("<f", buf, body)[0]
                    else:
                        val = struct.unpack_from("<d", buf, body)[0]
                    if len(controls) < MAX_LISTED:
                        controls.append({"index": index, "analog_value": val, "variation": v})
                    if len(targets) < MAX_TARGETS:
                        targets.append(Target("analog_output", index, index))
                pos += per
    except _ObjectError as exc:
        anomalies.append(Anomaly("bad_object", str(exc)))
        return objects, controls, targets, anomalies, False
    return objects, controls, targets, anomalies, True


class _Assembly:
    __slots__ = ("seq", "data")

    def __init__(self, seq: int, data: bytearray):
        self.seq = seq
        self.data = data


class Dnp3Dissector(FlowDissector):
    protocol = "dnp3"

    def __init__(self, max_pending: int = 256) -> None:
        self._bufs = {True: bytearray(), False: bytearray()}
        # transport reassembly keyed by (from_client, link_src, link_dst)
        self._asm: Dict[Tuple[bool, int, int], _Assembly] = {}
        self._pending: "OrderedDict[Tuple[int, int, int], str]" = OrderedDict()
        self._max_pending = max_pending

    def reset(self, from_client: bool) -> None:
        self._bufs[from_client].clear()
        for k in [k for k in self._asm if k[0] == from_client]:
            del self._asm[k]

    def feed_datagram(self, from_client: bool, data: bytes) -> List[ProtoMessage]:
        # An application fragment may span several UDP datagrams: keep transport
        # reassembly state, drop only a partial link frame left in the byte buffer.
        msgs = self.feed_stream(from_client, data, False)
        self._bufs[from_client].clear()
        return msgs

    # -- framing ---------------------------------------------------------
    def feed_stream(self, from_client: bool, data: bytes, gap: bool) -> List[ProtoMessage]:
        buf = self._bufs[from_client]
        if gap:
            self.reset(from_client)
        buf += data
        out: List[ProtoMessage] = []
        bad = 0

        def note(code: str, text: str, size: int = 0) -> None:
            nonlocal bad
            if bad < MAX_MALFORMED_PER_FEED:
                out.append(malformed("dnp3", from_client, code, text, size))
            bad += 1

        while True:
            idx = buf.find(START)
            if idx < 0:
                if buf and buf[-1] == 0x05:
                    del buf[:-1]
                else:
                    buf.clear()
                break
            if idx > 0:
                note("garbage", "%d bytes before DNP3 start sequence" % idx, idx)
                del buf[:idx]
            if len(buf) < 10:
                break
            length = buf[2]
            if crc16_dnp(bytes(buf[:8])) != (buf[8] | (buf[9] << 8)):
                note("bad_header_crc", "link header CRC mismatch", 10)
                del buf[:2]
                continue
            if length < 5:
                note("bad_length", "link length field %d < 5" % length, 10)
                del buf[:2]
                continue
            ud_len = length - 5
            blocks = (ud_len + 15) // 16
            total = 10 + ud_len + 2 * blocks
            if len(buf) < total:
                break
            frame = bytes(buf[:total])
            del buf[:total]
            out.extend(self._frame(from_client, frame, ud_len))
        return out

    # -- one link frame --------------------------------------------------
    def _frame(self, from_client: bool, frame: bytes, ud_len: int) -> List[ProtoMessage]:
        ctrl = frame[3]
        dest, src = struct.unpack_from("<HH", frame, 4)
        dir_master = bool(ctrl & 0x80)
        prm = bool(ctrl & 0x40)
        func = ctrl & 0x0F
        # strip data CRCs
        user = bytearray()
        pos = 10
        remaining = ud_len
        while remaining > 0:
            chunk = min(16, remaining)
            blk = frame[pos : pos + chunk]
            crc = frame[pos + chunk] | (frame[pos + chunk + 1] << 8)
            if crc16_dnp(blk) != crc:
                m = malformed("dnp3", dir_master, "bad_data_crc", "link data block CRC mismatch", len(frame))
                m.src_addr, m.dst_addr = src, dest
                return [m]
            user += blk
            pos += chunk + 2
            remaining -= chunk
        base = dict(protocol="dnp3", src_addr=src, dst_addr=dest, size=len(frame),
                    broadcast=(dest >= BROADCAST_MIN), unit=dest if dir_master else src)
        if ud_len == 0 or not prm:
            names = LINK_PRIMARY if prm else LINK_SECONDARY
            name = names.get(func, "LINK_FUNCTION_%d" % func)
            msg = ProtoMessage(is_request=dir_master, function=name, function_code=func,
                               kinds=frozenset(["link"]), details={"layer": "link", "dir_master": dir_master,
                                                                   "prm": prm}, **base)
            if prm and func not in LINK_PRIMARY:
                msg.anomalies.append(Anomaly("unknown_link_function", "primary link function %d" % func))
            elif not prm and func not in LINK_SECONDARY:
                msg.anomalies.append(Anomaly("unknown_link_function", "secondary link function %d" % func))
            return [msg]
        if func not in (3, 4):
            m = malformed("dnp3", dir_master, "unexpected_user_data",
                          "link function %d carries user data" % func, len(frame))
            m.src_addr, m.dst_addr = src, dest
            return [m]
        return self._transport(from_client, dir_master, src, dest, bytes(user), base)

    # -- transport + application ----------------------------------------
    def _transport(self, from_client: bool, dir_master: bool, src: int, dest: int,
                   user: bytes, base: Dict[str, Any]) -> List[ProtoMessage]:
        th = user[0]
        # Transport header (IEEE 1815 clause 8): bit7 = FIN, bit6 = FIR, bits 5..0 = sequence.
        # (Note the order is the reverse of the application control byte, where FIR is bit 7.)
        fir, fin, seq = bool(th & 0x40), bool(th & 0x80), th & 0x3F
        seg = user[1:]
        key = (from_client, src, dest)
        out: List[ProtoMessage] = []
        asm = self._asm.get(key)
        problem: Optional[Tuple[str, str]] = None
        if fir:
            if asm is not None:
                problem = ("unfinished_fragment", "new FIR before previous fragment finished")
            asm = _Assembly(seq, bytearray(seg))
            self._asm[key] = asm
        else:
            if asm is None:
                m = malformed("dnp3", dir_master, "orphan_segment",
                              "transport segment without FIR", base["size"])
                m.src_addr, m.dst_addr = src, dest
                return [m]
            if seq != (asm.seq + 1) & 0x3F:
                del self._asm[key]
                m = malformed("dnp3", dir_master, "transport_sequence",
                              "transport sequence %d after %d" % (seq, asm.seq), base["size"])
                m.src_addr, m.dst_addr = src, dest
                return [m]
            asm.seq = seq
            asm.data += seg
        if problem:
            m = malformed("dnp3", dir_master, problem[0], problem[1], base["size"])
            m.src_addr, m.dst_addr = src, dest
            out.append(m)
        if len(asm.data) > MAX_FRAGMENT:
            del self._asm[key]
            m = malformed("dnp3", dir_master, "fragment_too_large",
                          "application fragment exceeds %d bytes" % MAX_FRAGMENT, base["size"])
            m.src_addr, m.dst_addr = src, dest
            out.append(m)
            return out
        if fin:
            del self._asm[key]
            out.append(self._application(dir_master, bytes(asm.data), base))
        return out

    def _application(self, dir_master: bool, frag: bytes, base: Dict[str, Any]) -> ProtoMessage:
        src, dest = base["src_addr"], base["dst_addr"]
        if len(frag) < 2:
            m = malformed("dnp3", dir_master, "short_fragment", "application fragment shorter than 2 bytes",
                          base["size"])
            m.src_addr, m.dst_addr = src, dest
            return m
        ac, fc = frag[0], frag[1]
        app_seq = ac & 0x0F
        is_resp = fc in RESPONSE_FCS
        anomalies: List[Anomaly] = []
        details: Dict[str, Any] = {
            "layer": "application", "app_seq": app_seq, "fir": bool(ac & 0x80), "fin": bool(ac & 0x40),
            "con": bool(ac & 0x20), "uns": bool(ac & 0x10), "dir_master": dir_master,
        }
        kinds = set(_KINDS.get(fc, frozenset()))
        name = APP_FUNCTIONS.get(fc)
        if name is None:
            name = "UNKNOWN_%d" % fc
            kinds.add("unknown_function")
        pos = 2
        if is_resp:
            if len(frag) < 4:
                anomalies.append(Anomaly("short_response", "response fragment lacks IIN"))
                pos = len(frag)
            else:
                iin1, iin2 = frag[2], frag[3]
                flags = decode_iin(iin1, iin2)
                details["iin"] = flags
                details["iin_raw"] = (iin1 << 8) | iin2
                for flag, kind in (("DEVICE_RESTART", "restart_flag"), ("DEVICE_TROUBLE", "device_trouble"),
                                   ("LOCAL_CONTROL", "local_control"), ("CONFIG_CORRUPT", "config_corrupt")):
                    if flag in flags:
                        kinds.add(kind)
                if any(f in flags for f in ("NO_FUNC_CODE_SUPPORT", "OBJECT_UNKNOWN", "PARAMETER_ERROR")):
                    kinds.add("exception")
                pos = 4
        elif fc >= 128:
            anomalies.append(Anomaly("unknown_response_code", "response-range function code %d" % fc))
        with_data = fc in _CARRIES_DATA
        objects: List[Dict[str, Any]] = []
        targets: List[Target] = []
        if pos < len(frag):
            objects, controls, targets, obj_anoms, full = parse_objects(frag, pos, with_data, fc)
            anomalies.extend(obj_anoms)
            if not full and not obj_anoms:
                details["objects_partially_parsed"] = True
            if objects:
                details["objects"] = objects[:MAX_LISTED]
            if controls:
                details["controls"] = controls
            if fc == 2 and objects and all(o["group"] in (50, 80) for o in objects):
                kinds.discard("write")
                kinds.add("maintenance")
        # request/response pairing by (master addr, outstation addr, app seq)
        if not is_resp:
            if fc != 0:
                key = (src, dest, app_seq)
                self._pending[key] = name
                self._pending.move_to_end(key)
                while len(self._pending) > self._max_pending:
                    self._pending.popitem(last=False)
        elif fc == 129:
            key = (dest, src, app_seq)
            req = self._pending.pop(key, None)
            if req is not None:
                details["request_function"] = req
        return ProtoMessage(
            is_request=not is_resp, function=name, function_code=fc, kinds=frozenset(kinds),
            targets=tuple(targets), details=details, anomalies=anomalies, **base,
        )
