"""Synthetic ICS traffic generator (pcap/pcapng writers, TCP helper, message encoders).

Used by the test-suite and by ``quietwire demo``. The encoders here are written
from the protocol layouts independently of the dissectors (they share no code
with ``quietwire.proto``) so tests exercise real round-trips.
"""

from __future__ import annotations

import socket
import struct
from typing import Iterable, List, Optional, Sequence, Tuple

SYN, FIN, RST, PSH, ACK = 0x02, 0x01, 0x04, 0x08, 0x10


# ------------------------------------------------------------------ primitives
def inet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def ethernet(src_mac: str, dst_mac: str, etype: int, payload: bytes, vlan: Optional[int] = None) -> bytes:
    hdr = mac_bytes(dst_mac) + mac_bytes(src_mac)
    if vlan is not None:
        hdr += struct.pack("!HH", 0x8100, vlan & 0x0FFF)
    return hdr + struct.pack("!H", etype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 1, ttl: int = 64,
         frag: int = 0x4000) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, frag, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    csum = inet_checksum(hdr)
    return hdr[:10] + struct.pack("!H", csum) + hdr[12:] + payload


def ipv6(src: str, dst: str, nxt: int, payload: bytes, hop: int = 64) -> bytes:
    return (struct.pack("!IHBB", 0x60000000, len(payload), nxt, hop)
            + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload)


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    if ":" in src:
        return (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
                + struct.pack("!IBBBB", length, 0, 0, 0, proto))
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, length)


def tcp_segment(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
                payload: bytes = b"", window: int = 64240, options: bytes = b"") -> bytes:
    off = (20 + len(options)) // 4
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, off << 4, flags, window, 0, 0)
    hdr += options
    csum = inet_checksum(_pseudo(src, dst, 6, len(hdr) + len(payload)) + hdr + payload)
    return hdr[:16] + struct.pack("!H", csum) + hdr[18:] + payload


def udp_datagram(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    csum = inet_checksum(_pseudo(src, dst, 17, length) + hdr + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, csum) + payload


def frame_for(src: str, dst: str, proto: int, l4: bytes, src_mac: str, dst_mac: str,
              vlan: Optional[int] = None, ident: int = 1) -> bytes:
    if ":" in src:
        return ethernet(src_mac, dst_mac, 0x86DD, ipv6(src, dst, proto, l4), vlan)
    return ethernet(src_mac, dst_mac, 0x0800, ipv4(src, dst, proto, l4, ident), vlan)


# --------------------------------------------------------------------- builder
class PcapBuilder:
    def __init__(self, start_ts: float = 1_700_000_000.0, linktype: int = 1):
        self.ts = start_ts
        self.linktype = linktype
        self.frames: List[Tuple[float, bytes]] = []

    def add(self, frame: bytes, ts: Optional[float] = None) -> float:
        if ts is None:
            ts = self.ts
        self.frames.append((ts, frame))
        return ts

    def ordered(self) -> List[Tuple[float, bytes]]:
        return sorted(self.frames, key=lambda f: f[0])

    def write_pcap(self, path: str, nano: bool = False, big_endian: bool = False) -> None:
        e = ">" if big_endian else "<"
        magic = 0xA1B23C4D if nano else 0xA1B2C3D4
        with open(path, "wb") as fh:
            fh.write(struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, self.linktype))
            for ts, data in self.ordered():
                sec = int(ts)
                frac = int(round((ts - sec) * (1e9 if nano else 1e6)))
                fh.write(struct.pack(e + "IIII", sec, frac, len(data), len(data)))
                fh.write(data)

    def write_pcapng(self, path: str, big_endian: bool = False, tsresol: Optional[int] = None) -> None:
        e = ">" if big_endian else "<"

        def block(btype: int, body: bytes) -> bytes:
            pad = (-len(body)) % 4
            total = 12 + len(body) + pad
            return struct.pack(e + "II", btype, total) + body + b"\x00" * pad + struct.pack(e + "I", total)

        shb = block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1))
        opts = b""
        res = 1e-6
        if tsresol is not None:
            opts = struct.pack(e + "HH", 9, 1) + bytes([tsresol]) + b"\x00\x00\x00" + struct.pack(e + "HH", 0, 0)
            res = 10.0 ** -tsresol
        idb = block(1, struct.pack(e + "HHI", self.linktype, 0, 65535) + opts)
        with open(path, "wb") as fh:
            fh.write(shb + idb)
            for ts, data in self.ordered():
                ticks = int(round(ts / res))
                body = struct.pack(e + "IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data)) + data
                fh.write(block(6, body))


class Conn:
    """A TCP connection that appends correctly sequenced frames to a builder."""

    def __init__(self, pb: PcapBuilder, client: str, server: str, cport: int, sport: int, *,
                 cmac: str = "02:00:00:00:00:01", smac: str = "02:00:00:00:00:02",
                 isn_c: int = 1000, isn_s: int = 500000, vlan: Optional[int] = None, mss: int = 1460):
        self.pb, self.client, self.server = pb, client, server
        self.cport, self.sport = cport, sport
        self.cmac, self.smac = cmac, smac
        self.seq_c, self.seq_s = isn_c, isn_s
        self.vlan, self.mss = vlan, mss
        self._ident = 1

    def _emit(self, from_client: bool, seq: int, ack: int, flags: int, data: bytes, dt: float) -> None:
        self.pb.ts += dt
        if from_client:
            src, dst, sp, dp, sm, dm = self.client, self.server, self.cport, self.sport, self.cmac, self.smac
        else:
            src, dst, sp, dp, sm, dm = self.server, self.client, self.sport, self.cport, self.smac, self.cmac
        l4 = tcp_segment(src, dst, sp, dp, seq, ack, flags, data)
        self._ident += 1
        self.pb.add(frame_for(src, dst, 6, l4, sm, dm, self.vlan, self._ident))

    def open(self, dt: float = 0.0005) -> None:
        self._emit(True, self.seq_c, 0, SYN, b"", dt)
        self.seq_c += 1
        self._emit(False, self.seq_s, self.seq_c, SYN | ACK, b"", dt)
        self.seq_s += 1
        self._emit(True, self.seq_c, self.seq_s, ACK, b"", dt)

    def push(self, from_client: bool, data: bytes, dt: float = 0.001, mss: Optional[int] = None) -> None:
        step = mss or self.mss
        for i in range(0, len(data), step):
            chunk = data[i : i + step]
            if from_client:
                self._emit(True, self.seq_c, self.seq_s, ACK | PSH, chunk, dt)
                self.seq_c += len(chunk)
            else:
                self._emit(False, self.seq_s, self.seq_c, ACK | PSH, chunk, dt)
                self.seq_s += len(chunk)
            dt = 0.0002

    def segment(self, from_client: bool, seq: int, data: bytes, dt: float = 0.001) -> None:
        """Emit a segment with an explicit sequence number (retransmit / reorder tests)."""
        ack = self.seq_s if from_client else self.seq_c
        self._emit(from_client, seq, ack, ACK | PSH, data, dt)

    def close(self, dt: float = 0.001) -> None:
        self._emit(True, self.seq_c, self.seq_s, FIN | ACK, b"", dt)
        self.seq_c += 1
        self._emit(False, self.seq_s, self.seq_c, FIN | ACK, b"", dt)
        self.seq_s += 1
        self._emit(True, self.seq_c, self.seq_s, ACK, b"", dt)


def udp_exchange(pb: PcapBuilder, src: str, dst: str, sport: int, dport: int, payload: bytes,
                 src_mac: str = "02:00:00:00:00:01", dst_mac: str = "02:00:00:00:00:02", dt: float = 0.001) -> None:
    pb.ts += dt
    pb.add(frame_for(src, dst, 17, udp_datagram(src, dst, sport, dport, payload), src_mac, dst_mac))


# -------------------------------------------------------------- Modbus encoders
def mb_adu(tid: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def mb_read(fc: int, start: int, qty: int) -> bytes:
    return bytes([fc]) + struct.pack(">HH", start, qty)


def mb_write_single_register(addr: int, value: int) -> bytes:
    return bytes([6]) + struct.pack(">HH", addr, value)


def mb_write_single_coil(addr: int, on: bool) -> bytes:
    return bytes([5]) + struct.pack(">HH", addr, 0xFF00 if on else 0)


def mb_write_multiple_registers(start: int, values: Sequence[int]) -> bytes:
    return bytes([16]) + struct.pack(">HHB", start, len(values), 2 * len(values)) + struct.pack(">%dH" % len(values), *values)


def mb_write_multiple_coils(start: int, bits: Sequence[int]) -> bytes:
    nbytes = (len(bits) + 7) // 8
    packed = bytearray(nbytes)
    for i, b in enumerate(bits):
        if b:
            packed[i // 8] |= 1 << (i % 8)
    return bytes([15]) + struct.pack(">HHB", start, len(bits), nbytes) + bytes(packed)


def mb_diag(sub: int, data: int = 0) -> bytes:
    return bytes([8]) + struct.pack(">HH", sub, data)


def mb_device_id(code: int = 1, obj: int = 0) -> bytes:
    return bytes([43, 0x0E, code, obj])


def mb_exception(fc: int, code: int) -> bytes:
    return bytes([fc | 0x80, code])


def mb_resp_registers(fc: int, values: Sequence[int]) -> bytes:
    return bytes([fc, 2 * len(values)]) + struct.pack(">%dH" % len(values), *values)


def mb_resp_bits(fc: int, bits: Sequence[int]) -> bytes:
    nbytes = (len(bits) + 7) // 8
    packed = bytearray(nbytes)
    for i, b in enumerate(bits):
        if b:
            packed[i // 8] |= 1 << (i % 8)
    return bytes([fc, nbytes]) + bytes(packed)


def mb_echo_write(fc: int, a: int, b: int) -> bytes:
    return bytes([fc]) + struct.pack(">HH", a, b)


def mb_device_id_response(objs: Sequence[Tuple[int, bytes]]) -> bytes:
    body = bytes([43, 0x0E, 1, 0x01, 0, 0, len(objs)])
    for oid, val in objs:
        body += bytes([oid, len(val)]) + val
    return body


# --------------------------------------------------------------- DNP3 encoders
def dnp_crc(data: bytes) -> int:
    """Bitwise CRC-16/DNP (deliberately different from the table-driven library code)."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def dnp3_link(dest: int, src: int, ctrl: int, user: bytes = b"") -> bytes:
    head = b"\x05\x64" + bytes([5 + len(user), ctrl]) + struct.pack("<HH", dest, src)
    out = head + struct.pack("<H", dnp_crc(head))
    for i in range(0, len(user), 16):
        blk = user[i : i + 16]
        out += blk + struct.pack("<H", dnp_crc(blk))
    return out


def dnp3_app(fc: int, objects: bytes = b"", seq: int = 0, fir: bool = True, fin: bool = True, con: bool = False,
             uns: bool = False, iin: Optional[Tuple[int, int]] = None) -> bytes:
    ac = (0x80 if fir else 0) | (0x40 if fin else 0) | (0x20 if con else 0) | (0x10 if uns else 0) | (seq & 0x0F)
    hdr = bytes([ac, fc])
    if iin is not None:
        hdr += bytes(iin)
    return hdr + objects


def dnp3_frames(dest: int, src: int, app: bytes, master: bool, tseq: int = 0, confirmed: bool = False) -> List[bytes]:
    """Split an application fragment into link frames with transport headers."""
    ctrl_func = 3 if confirmed else 4
    ctrl = (0x80 if master else 0) | 0x40 | ctrl_func
    chunks = [app[i : i + 249] for i in range(0, len(app), 249)] or [b""]
    frames = []
    for i, chunk in enumerate(chunks):
        th = (0x40 if i == 0 else 0) | (0x80 if i == len(chunks) - 1 else 0) | ((tseq + i) & 0x3F)  # FIR=0x40, FIN=0x80
        frames.append(dnp3_link(dest, src, ctrl, bytes([th]) + chunk))
    return frames


def dnp3_obj(group: int, var: int, qualifier: int, rng: bytes = b"", data: bytes = b"") -> bytes:
    return bytes([group, var, qualifier]) + rng + data


def dnp3_crob(index: int, code: int, count: int = 1, on_ms: int = 1000, off_ms: int = 0, status: int = 0) -> bytes:
    """g12v1 with qualifier 0x17 (1-byte count, 1-byte index prefix) for one point."""
    return dnp3_obj(12, 1, 0x17, bytes([1]), bytes([index]) + bytes([code, count]) + struct.pack("<IIB", on_ms, off_ms, status))


# ------------------------------------------------------------------ S7 encoders
def tpkt(payload: bytes) -> bytes:
    return b"\x03\x00" + struct.pack(">H", len(payload) + 4) + payload


def cotp_dt() -> bytes:
    return b"\x02\xf0\x80"


def cotp_cr(calling_tsap: bytes = b"\x01\x00", called_tsap: bytes = b"\x01\x02") -> bytes:
    params = b"\xc1\x02" + calling_tsap + b"\xc2\x02" + called_tsap + b"\xc0\x01\x0a"
    body = b"\xe0\x00\x00\x00\x01\x00" + params
    return bytes([len(body)]) + body


def s7_pdu(rosctr: int, pduref: int, param: bytes, data: bytes = b"", err: Optional[int] = None) -> bytes:
    hdr = struct.pack(">BBHHHH", 0x32, rosctr, 0, pduref, len(param), len(data))
    if err is not None:
        hdr += struct.pack(">H", err)
    return hdr + param + data


def s7_item(area: int, db: int, byte_off: int, nbytes: int, tsize: int = 2) -> bytes:
    addr = byte_off << 3
    return (b"\x12\x0a\x10" + bytes([tsize]) + struct.pack(">HH", nbytes, db) + bytes([area])
            + bytes([(addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF]))


def s7_read_job(pduref: int, items: Iterable[Tuple[int, int, int, int]]) -> bytes:
    items = list(items)
    param = bytes([0x04, len(items)]) + b"".join(s7_item(*i) for i in items)
    return tpkt(cotp_dt() + s7_pdu(1, pduref, param))


def s7_write_job(pduref: int, items: Iterable[Tuple[int, int, int, bytes]]) -> bytes:
    items = list(items)
    param = bytes([0x05, len(items)]) + b"".join(s7_item(a, d, o, len(v)) for a, d, o, v in items)
    data = b""
    for i, (_a, _d, _o, v) in enumerate(items):
        data += bytes([0x00, 0x04]) + struct.pack(">H", len(v) * 8) + v
        if len(v) % 2 and i != len(items) - 1:
            data += b"\x00"
    return tpkt(cotp_dt() + s7_pdu(1, pduref, param, data))


def s7_read_ack(pduref: int, values: Sequence[bytes]) -> bytes:
    param = bytes([0x04, len(values)])
    data = b""
    for i, v in enumerate(values):
        data += bytes([0xFF, 0x04]) + struct.pack(">H", len(v) * 8) + v
        if len(v) % 2 and i != len(values) - 1:
            data += b"\x00"
    return tpkt(cotp_dt() + s7_pdu(3, pduref, param, data, err=0))


def s7_write_ack(pduref: int, codes: Sequence[int]) -> bytes:
    return tpkt(cotp_dt() + s7_pdu(3, pduref, bytes([0x05, len(codes)]), bytes(codes), err=0))


def s7_setup(pduref: int = 0, pdu_len: int = 480, ack: bool = False) -> bytes:
    param = bytes([0xF0, 0]) + struct.pack(">HHH", 1, 1, pdu_len)
    return tpkt(cotp_dt() + s7_pdu(3 if ack else 1, pduref, param, err=0 if ack else None))


def s7_plc_stop(pduref: int = 1) -> bytes:
    param = bytes([0x29, 0, 0, 0, 0, 0, 9]) + b"P_PROGRAM"
    return tpkt(cotp_dt() + s7_pdu(1, pduref, param))


def s7_pi_service(service: bytes, pduref: int = 1, args: bytes = b"") -> bytes:
    param = bytes([0x28, 0, 0, 0, 0, 0, 0, 0xFD]) + struct.pack(">H", len(args)) + args + bytes([len(service)]) + service
    return tpkt(cotp_dt() + s7_pdu(1, pduref, param))


def s7_request_download(filename: bytes = b"_0A00001P", pduref: int = 1) -> bytes:
    param = bytes([0x1A, 0, 0, 0, 0, 0, 0, 0xFD]) + bytes([len(filename)]) + filename
    return tpkt(cotp_dt() + s7_pdu(1, pduref, param))


def s7_start_upload(filename: bytes = b"_0A00001P", pduref: int = 1) -> bytes:
    param = bytes([0x1D, 0, 0, 0, 0, 0, 0, 0xFD]) + bytes([len(filename)]) + filename
    return tpkt(cotp_dt() + s7_pdu(1, pduref, param))


def s7_userdata(group: int, sub: int, typ: int = 4, data: bytes = b"", pduref: int = 1, seq: int = 0) -> bytes:
    param = b"\x00\x01\x12\x04\x11" + bytes([(typ << 4) | group, sub, seq])
    return tpkt(cotp_dt() + s7_pdu(7, pduref, param, data))


# ------------------------------------------------------------------- scenarios
HMI = "10.0.0.2"
SCADA = "10.0.0.3"
EWS = "10.0.0.9"
MB_PLC = "10.0.0.10"
RTU = "10.0.0.20"
S7_PLC = "10.0.0.30"
ROGUE = "10.0.0.66"


def scenario_baseline(pb: Optional[PcapBuilder] = None, cycles: int = 20, period: float = 1.0,
                      mss: int = 1460) -> PcapBuilder:
    """Normal operation: Modbus polling+setpoint writes, DNP3 integrity polls+control, S7 reads+DB writes."""
    pb = pb or PcapBuilder()
    t0 = pb.ts
    mb = Conn(pb, HMI, MB_PLC, 40001, 502, cmac="02:00:00:00:10:02", smac="02:00:00:00:10:0a", mss=mss)
    dn = Conn(pb, SCADA, RTU, 40002, 20000, cmac="02:00:00:00:10:03", smac="02:00:00:00:10:14", mss=mss)
    s7 = Conn(pb, EWS, S7_PLC, 40003, 102, cmac="02:00:00:00:10:09", smac="02:00:00:00:10:1e", mss=mss)
    mb.open()
    dn.open()
    s7.open()
    s7.push(True, tpkt(cotp_cr()))
    s7.push(False, tpkt(bytes([0x11, 0xD0]) + b"\x00\x01\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a"))
    s7.push(True, s7_setup(0))
    s7.push(False, s7_setup(0, ack=True))
    for i in range(cycles):
        pb.ts = t0 + 1 + i * period
        tid = i + 1
        mb.push(True, mb_adu(tid, 1, mb_read(3, 0, 10)))
        mb.push(False, mb_adu(tid, 1, mb_resp_registers(3, list(range(10)))))
        if i % 5 == 0:
            mb.push(True, mb_adu(1000 + tid, 1, mb_write_single_register(100, 50 + i)))
            mb.push(False, mb_adu(1000 + tid, 1, mb_echo_write(6, 100, 50 + i)))
        # DNP3 class 0 poll (g60v1) + occasional control relay
        poll = dnp3_app(1, dnp3_obj(60, 1, 0x06), seq=i)
        for f in dnp3_frames(20, 3, poll, master=True, tseq=i):
            dn.push(True, f)
        resp = dnp3_app(129, dnp3_obj(1, 2, 0x00, bytes([0, 1]), bytes([1, 1])), seq=i, iin=(0, 0))
        for f in dnp3_frames(3, 20, resp, master=False, tseq=i):
            dn.push(False, f)
        if i % 10 == 5:
            op = dnp3_app(5, dnp3_crob(2, 0x03), seq=i + 1)
            for f in dnp3_frames(20, 3, op, master=True, tseq=i):
                dn.push(True, f)
            rs = dnp3_app(129, dnp3_crob(2, 0x03), seq=i + 1, iin=(0, 0))
            for f in dnp3_frames(3, 20, rs, master=False, tseq=i):
                dn.push(False, f)
        s7.push(True, s7_read_job(10 + i, [(0x84, 1, 0, 4)]))
        s7.push(False, s7_read_ack(10 + i, [b"\x00\x00\x00\x01"]))
        if i % 5 == 1:
            s7.push(True, s7_write_job(500 + i, [(0x84, 1, 10, b"\x00\x2a")]))
            s7.push(False, s7_write_ack(500 + i, [0xFF]))
    mb.close()
    dn.close()
    s7.close()
    return pb


def scenario_attack(pb: Optional[PcapBuilder] = None, mss: int = 1460) -> PcapBuilder:
    """Rogue host performing recon, unauthorised writes and disruptive operations."""
    pb = pb or PcapBuilder()
    # Host sweep on Modbus
    for i in range(12):
        c = Conn(pb, ROGUE, "10.0.0.%d" % (100 + i), 50000 + i, 502, cmac="02:00:00:00:66:66", mss=mss)
        c.open()
        c.push(True, mb_adu(1, 1, mb_read(3, 0, 1)))
        c.push(False, mb_adu(1, 1, mb_exception(3, 2)))
        c.close()
    # Unit-id sweep + device identification on the PLC
    c = Conn(pb, ROGUE, MB_PLC, 51000, 502, cmac="02:00:00:00:66:66", mss=mss)
    c.open()
    for unit in range(1, 15):
        c.push(True, mb_adu(unit, unit, mb_read(3, 0, 1)))
        c.push(False, mb_adu(unit, unit, mb_exception(3, 11)))
    c.push(True, mb_adu(100, 1, mb_device_id()))
    c.push(True, mb_adu(101, 1, mb_write_single_register(5, 0xFFFF)))
    c.push(False, mb_adu(101, 1, mb_echo_write(6, 5, 0xFFFF)))
    c.push(True, mb_adu(102, 1, mb_diag(0x0004)))
    c.push(True, mb_adu(103, 0, mb_write_single_coil(7, True)))
    c.push(True, mb_adu(104, 1, bytes([90, 1, 2, 3])))
    c.close()
    # DNP3 disruptive commands
    d = Conn(pb, ROGUE, RTU, 52000, 20000, cmac="02:00:00:00:66:66", mss=mss)
    d.open()
    for f in dnp3_frames(20, 666, dnp3_app(13, seq=1), master=True):
        d.push(True, f)
    for f in dnp3_frames(20, 3, dnp3_app(129, seq=1, iin=(0x80, 0)), master=False):
        d.push(False, f)
    for f in dnp3_frames(0xFFFF, 666, dnp3_app(5, dnp3_crob(0, 0x04), seq=2), master=True):
        d.push(True, f)
    d.close()
    # S7 stop + program download
    s = Conn(pb, ROGUE, S7_PLC, 53000, 102, cmac="02:00:00:00:66:66", mss=mss)
    s.open()
    s.push(True, tpkt(cotp_cr()))
    s.push(True, s7_setup(0))
    s.push(True, s7_userdata(4, 1, data=b"\xff\x09\x00\x04\x00\x11\x00\x01"))
    s.push(True, s7_plc_stop(5))
    s.push(True, s7_request_download(b"_0A00001P", 6))
    s.push(True, s7_write_job(7, [(0x84, 1, 500, b"\xde\xad")]))
    s.close()
    return pb


def demo_policy() -> dict:
    """A policy matching ``scenario_baseline`` (used by ``quietwire demo`` and tests)."""
    return {
        "version": 1,
        "assets": [{"ip": ip} for ip in (HMI, SCADA, EWS, MB_PLC, RTU, S7_PLC)],
        "allowed_flows": [
            {"master": HMI, "server": MB_PLC, "protocol": "modbus", "port": 502},
            {"master": SCADA, "server": RTU, "protocol": "dnp3", "port": 20000},
            {"master": EWS, "server": S7_PLC, "protocol": "s7comm", "port": 102},
        ],
        "writers": {"modbus": [HMI], "dnp3": [SCADA], "s7comm": [EWS]},
        "engineering_stations": [EWS],
        "allowed_functions": [
            {"master": HMI, "server": MB_PLC, "protocol": "modbus",
             "functions": ["READ_HOLDING_REGISTERS", "WRITE_SINGLE_REGISTER"]},
            {"master": SCADA, "server": RTU, "protocol": "dnp3", "functions": ["READ", "DIRECT_OPERATE", "@read"]},
            {"master": EWS, "server": S7_PLC, "protocol": "s7comm", "functions": ["READ_VAR", "WRITE_VAR"]},
        ],
        "write_ranges": [
            {"server": MB_PLC, "protocol": "modbus", "unit": 1, "area": "holding_register", "start": 100, "end": 109},
            {"server": S7_PLC, "protocol": "s7comm", "area": "DB1", "start": 0, "end": 99},
            {"server": RTU, "protocol": "dnp3", "area": "binary_output", "start": 0, "end": 7},
        ],
        "thresholds": {"warmup_seconds": 5},
    }


# ------------------------------------------------------------------ IEC 104 encoders
def iec104_apdu_u(code: int) -> bytes:
    return bytes([0x68, 4, code, 0, 0, 0])


def iec104_apdu_s(nr: int) -> bytes:
    return bytes([0x68, 4, 0x01, 0]) + struct.pack("<H", nr << 1)


def iec104_asdu(type_id: int, objects: Sequence[bytes], cot: int = 6, ca: int = 1, org: int = 0, sq: bool = False,
                negative: bool = False, test: bool = False) -> bytes:
    """``objects`` are pre-encoded (IOA + element) blobs; with ``sq`` the first one carries the IOA."""
    vsq = (0x80 if sq else 0) | len(objects)
    cot_b = (cot & 0x3F) | (0x40 if negative else 0) | (0x80 if test else 0)
    return bytes([type_id, vsq, cot_b, org]) + struct.pack("<H", ca) + b"".join(objects)


def iec104_apdu_i(ns: int, nr: int, asdu: bytes) -> bytes:
    ctrl = struct.pack("<HH", ns << 1, nr << 1)
    return bytes([0x68, 4 + len(asdu)]) + ctrl + asdu


def iec104_obj(ioa: int, element: bytes) -> bytes:
    return struct.pack("<I", ioa)[:3] + element


def iec104_single_command(ioa: int, on: bool, select: bool = False, ca: int = 1, ns: int = 0, cot: int = 6,
                          qualifier: int = 0) -> bytes:
    sco = (1 if on else 0) | ((qualifier & 0x1F) << 2) | (0x80 if select else 0)
    return iec104_apdu_i(ns, 0, iec104_asdu(45, [iec104_obj(ioa, bytes([sco]))], cot=cot, ca=ca))


def iec104_setpoint_float(ioa: int, value: float, select: bool = False, ca: int = 1, ns: int = 0) -> bytes:
    el = struct.pack("<fB", value, 0x80 if select else 0)
    return iec104_apdu_i(ns, 0, iec104_asdu(50, [iec104_obj(ioa, el)], cot=6, ca=ca))


def iec104_interrogation(ca: int = 1, ns: int = 0, cot: int = 6) -> bytes:
    return iec104_apdu_i(ns, 0, iec104_asdu(100, [iec104_obj(0, bytes([20]))], cot=cot, ca=ca))


def iec104_clock_sync(ca: int = 1, ns: int = 0) -> bytes:
    return iec104_apdu_i(ns, 0, iec104_asdu(103, [iec104_obj(0, bytes(7))], cot=6, ca=ca))


def iec104_reset_process(ca: int = 1, ns: int = 0) -> bytes:
    return iec104_apdu_i(ns, 0, iec104_asdu(105, [iec104_obj(0, bytes([1]))], cot=6, ca=ca))


def iec104_single_points(ioas: Sequence[int], values: Sequence[int], ca: int = 1, ns: int = 0, cot: int = 3,
                         sq: bool = False) -> bytes:
    if sq:
        body = [iec104_obj(ioas[0], bytes([values[0]]))] + [bytes([v]) for v in values[1:]]
    else:
        body = [iec104_obj(i, bytes([v])) for i, v in zip(ioas, values)]
    return iec104_apdu_i(ns, 0, iec104_asdu(1, body, cot=cot, ca=ca, sq=sq))


# ---------------------------------------------------------------- encapsulation / fragmentation
def gre(payload: bytes, ptype: int, key: Optional[int] = None, seq: Optional[int] = None, csum: bool = False) -> bytes:
    flags = (0x8000 if csum else 0) | (0x2000 if key is not None else 0) | (0x1000 if seq is not None else 0)
    hdr = struct.pack("!HH", flags, ptype)
    if csum:
        hdr += b"\x00\x00\x00\x00"
    if key is not None:
        hdr += struct.pack("!I", key)
    if seq is not None:
        hdr += struct.pack("!I", seq)
    return hdr + payload


def erspan2(inner_eth: bytes, session: int = 1, vlan: int = 0, seq: int = 1) -> bytes:
    hdr = struct.pack("!HHI", (1 << 12) | (vlan & 0x0FFF), session & 0x3FF, 0)  # ver=1, vlan, session id, index
    return gre(hdr + inner_eth, 0x88BE, seq=seq)


def erspan3(inner_eth: bytes, session: int = 1, vlan: int = 0, seq: int = 1, platform_subheader: bool = False) -> bytes:
    word0 = (2 << 12) | (vlan & 0x0FFF)  # version 2 = type III
    word1 = session & 0x3FF
    last = (1 if platform_subheader else 0)  # O bit
    hdr = struct.pack("!HHIHBB", word0, word1, 12345, 0, 0, last)
    if platform_subheader:
        hdr += bytes(8)
    return gre(hdr + inner_eth, 0x22EB, seq=seq)


def vxlan(inner_eth: bytes, vni: int = 5000) -> bytes:
    return bytes([0x08, 0, 0, 0]) + struct.pack("!I", vni << 8) + inner_eth


def mpls_labels(labels: Sequence[int]) -> bytes:
    out = b""
    for i, lab in enumerate(labels):
        out += struct.pack("!I", (lab << 12) | (1 << 8 if i == len(labels) - 1 else 0) | 64)
    return out


def pppoe_session(ip_packet: bytes, session_id: int = 7) -> bytes:
    proto = 0x0057 if ip_packet[0] >> 4 == 6 else 0x0021
    return struct.pack("!BBHH", 0x11, 0, session_id, len(ip_packet) + 2) + struct.pack("!H", proto) + ip_packet


def split_ipv4(ip_packet: bytes, frag_payload: int, order: Optional[Sequence[int]] = None) -> List[bytes]:
    """Split one IPv4 packet into fragments carrying ``frag_payload`` (multiple of 8) bytes each."""
    ihl = (ip_packet[0] & 0x0F) * 4
    head, body = bytearray(ip_packet[:ihl]), ip_packet[ihl:]
    frags = []
    for off in range(0, len(body), frag_payload):
        chunk = body[off : off + frag_payload]
        more = off + frag_payload < len(body)
        h = bytearray(head)
        h[2:4] = struct.pack("!H", ihl + len(chunk))
        h[6:8] = struct.pack("!H", (0x2000 if more else 0) | (off // 8))
        h[10:12] = b"\x00\x00"
        h[10:12] = struct.pack("!H", inet_checksum(bytes(h)))
        frags.append(bytes(h) + bytes(chunk))
    if order is not None:
        frags = [frags[i] for i in order]
    return frags


def split_ipv6(src: str, dst: str, upper: int, l4: bytes, ident: int, frag_payload: int,
               order: Optional[Sequence[int]] = None) -> List[bytes]:
    frags = []
    for off in range(0, len(l4), frag_payload):
        chunk = l4[off : off + frag_payload]
        more = off + frag_payload < len(l4)
        fh = struct.pack("!BBHI", upper, 0, ((off // 8) << 3) | (1 if more else 0), ident)
        frags.append(ipv6(src, dst, 44, fh + chunk))
    if order is not None:
        frags = [frags[i] for i in order]
    return frags


def encapsulate(pb: PcapBuilder, kind: str, **kw) -> PcapBuilder:
    """Return a copy of ``pb`` (Ethernet/IPv4 frames) with every frame wrapped as ``kind``.

    kinds: gre-ip, gre-key, gre-teb, erspan2, erspan3, erspan3-sub, vxlan, mpls, mpls-stack, pppoe, ipip,
    vlan-in-erspan.
    """
    out = PcapBuilder(start_ts=pb.ts, linktype=pb.linktype)
    o_src, o_dst = "192.0.2.1", "192.0.2.2"
    o_smac, o_dmac = "02:aa:00:00:00:01", "02:aa:00:00:00:02"
    for i, (ts, frame) in enumerate(pb.ordered()):
        ip = frame[14:]
        if kind == "gre-ip":
            outer = ipv4(o_src, o_dst, 47, gre(ip, 0x0800), ident=i)
        elif kind == "gre-key":
            outer = ipv4(o_src, o_dst, 47, gre(ip, 0x0800, key=77, seq=i, csum=True), ident=i)
        elif kind == "gre-teb":
            outer = ipv4(o_src, o_dst, 47, gre(frame, 0x6558), ident=i)
        elif kind == "erspan2":
            outer = ipv4(o_src, o_dst, 47, erspan2(frame, session=9, seq=i), ident=i)
        elif kind == "erspan3":
            outer = ipv4(o_src, o_dst, 47, erspan3(frame, session=9, seq=i), ident=i)
        elif kind == "erspan3-sub":
            outer = ipv4(o_src, o_dst, 47, erspan3(frame, session=9, seq=i, platform_subheader=True), ident=i)
        elif kind == "vxlan":
            outer = ipv4(o_src, o_dst, 17, udp_datagram(o_src, o_dst, 40000 + i % 100, 4789, vxlan(frame)), ident=i)
        elif kind == "ipip":
            outer = ipv4(o_src, o_dst, 4, ip, ident=i)
        elif kind in ("mpls", "mpls-stack"):
            labels = [1000 + i % 50] if kind == "mpls" else [16, 17, 18]
            out.add(ethernet(o_smac, o_dmac, 0x8847, mpls_labels(labels) + ip), ts)
            continue
        elif kind == "pppoe":
            out.add(ethernet(o_smac, o_dmac, 0x8864, pppoe_session(ip)), ts)
            continue
        else:
            raise ValueError(kind)
        out.add(ethernet(o_smac, o_dmac, 0x0800, outer), ts)
    return out


def fragment_capture(pb: PcapBuilder, frag_payload: int = 16, only_if_longer: int = 40, reverse: bool = False,
                     shuffle_seed: Optional[int] = None) -> PcapBuilder:
    """Fragment every IPv4 packet whose payload exceeds ``only_if_longer`` bytes."""
    import random

    out = PcapBuilder(start_ts=pb.ts, linktype=pb.linktype)
    rng = random.Random(shuffle_seed)
    for ts, frame in pb.ordered():
        eth, ip = frame[:14], frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) - ihl <= only_if_longer:
            out.add(frame, ts)
            continue
        frags = split_ipv4(ip, frag_payload)
        order = list(range(len(frags)))
        if reverse:
            order.reverse()
        if shuffle_seed is not None:
            rng.shuffle(order)
        for k, idx in enumerate(order):
            out.add(eth + frags[idx], ts + k * 1e-6)
    return out


# ---------------------------------------------------------------- S7CommPlus encoder
def s7plus_pdu(opcode: int, function: int, seq: int = 1, session: int = 0x120, version: int = 1,
               data_len: Optional[int] = None, extra: bytes = b"") -> bytes:
    """TPKT/COTP-wrapped S7CommPlus PDU: header, opcode, function, sequence number, session id."""
    body = (bytes([opcode]) + b"\x00\x00" + struct.pack(">H", function) + b"\x00\x00" + struct.pack(">H", seq)
            + struct.pack(">I", session) + b"\x36" + extra)
    dlen = len(body) if data_len is None else data_len
    return tpkt(cotp_dt() + bytes([0x72, version]) + struct.pack(">H", dlen) + body)
