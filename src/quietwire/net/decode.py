"""Link/IP/TCP/UDP decoding with tunnel decapsulation and IP fragment reassembly.

Decoding never raises on bad input. ``decode_packet`` is a stateless convenience wrapper;
the analysis engine uses a long-lived :class:`Decoder` (which owns the fragment reassembler).

Decapsulated: 802.1Q/ad VLAN, MPLS, PPPoE (session), GRE (incl. transparent Ethernet bridging,
ERSPAN type II/III), VXLAN, IPv4/IPv6-in-IP. Decoded packets report the *innermost* addresses and
ports; ``tunnel`` names the encapsulations that were removed.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .fragments import FragmentReassembler

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

SUPPORTED_LINKTYPES = frozenset(
    [LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL,
     LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LINUX_SLL2]
)

_ETH_IPV4 = 0x0800
_ETH_IPV6 = 0x86DD
_ETH_VLAN = (0x8100, 0x88A8, 0x9100)
_ETH_MPLS = (0x8847, 0x8848)
_ETH_PPPOE = 0x8864
_GRE_TEB = 0x6558
_GRE_ERSPAN2 = 0x88BE
_GRE_ERSPAN3 = 0x22EB
_VXLAN_PORT = 4789
MAX_DEPTH = 3


@dataclass
class DecodedPacket:
    src_mac: Optional[str]
    dst_mac: Optional[str]
    vlan: Optional[int]
    ip_version: int
    src_ip: str
    dst_ip: str
    proto: int  # 6 = TCP, 17 = UDP
    src_port: int
    dst_port: int
    payload: bytes
    wire_payload_len: int  # payload length according to IP/TCP headers (>= len(payload) if snaplen-truncated)
    seq: int = 0
    ack: int = 0
    flags: int = 0
    tunnel: Optional[str] = None  # e.g. "gre", "erspan2", "vxlan", "mpls" (innermost last, ">"-joined)
    fragments: int = 0  # number of IP fragments this datagram was reassembled from

    @property
    def is_tcp(self) -> bool:
        return self.proto == 6


def _mac(b: bytes) -> str:
    return b.hex(":")


_IP4 = struct.Struct("!BBHHHBBH4s4s")  # vihl tos total ident flags_frag ttl proto csum src dst
_TCP = struct.Struct("!HHIIH")
_ip4_cache: dict = {}


def _ip4(raw: bytes) -> str:
    s = _ip4_cache.get(raw)
    if s is None:
        s = socket.inet_ntoa(raw)
        if len(_ip4_cache) < 65536:
            _ip4_cache[raw] = s
    return s


class Decoder:
    """Stateful decoder: owns the (optional) fragment reassembler and the decapsulation limits."""

    def __init__(self, defrag: Optional[FragmentReassembler] = None, decapsulate: bool = True):
        self.defrag = defrag
        self.decapsulate = decapsulate
        self.conflict_hook = None  # called as hook(src_ip, dst_ip, conflicts) on conflicting overlaps

    # ------------------------------------------------------------------ entry
    def decode(self, linktype: int, data: bytes, truncated: bool = True, ts: float = 0.0,
               _depth: int = 0, _tunnel: Optional[str] = None
               ) -> Tuple[Optional[DecodedPacket], Optional[str]]:
        src_mac = dst_mac = None
        vlan = None
        n = len(data)
        if linktype == LINKTYPE_ETHERNET:
            if n < 14:
                return None, "truncated"
            dst_mac, src_mac = _mac(data[0:6]), _mac(data[6:12])
            etype = struct.unpack_from("!H", data, 12)[0]
            pos = 14
            tags = 0
            while etype in _ETH_VLAN and tags < 4:
                if n < pos + 4:
                    return None, "truncated"
                tci, etype = struct.unpack_from("!HH", data, pos)
                if vlan is None:
                    vlan = tci & 0x0FFF
                pos += 4
                tags += 1
            l3 = pos
        elif linktype == LINKTYPE_NULL:
            if n < 4:
                return None, "truncated"
            fam_le = struct.unpack_from("<I", data, 0)[0]
            fam_be = struct.unpack_from(">I", data, 0)[0]
            fam = fam_le if fam_le < 256 else fam_be
            if fam == 2:
                etype = _ETH_IPV4
            elif fam in (10, 24, 28, 30):
                etype = _ETH_IPV6
            else:
                return None, "non_ip"
            l3 = 4
        elif linktype == LINKTYPE_LINUX_SLL:
            if n < 16:
                return None, "truncated"
            etype = struct.unpack_from("!H", data, 14)[0]
            l3 = 16
        elif linktype == LINKTYPE_LINUX_SLL2:
            if n < 20:
                return None, "truncated"
            etype = struct.unpack_from("!H", data, 0)[0]
            l3 = 20
        elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
            if n < 1:
                return None, "truncated"
            ver = data[0] >> 4
            if ver == 4:
                etype = _ETH_IPV4
            elif ver == 6:
                etype = _ETH_IPV6
            else:
                return None, "non_ip"
            l3 = 0
        else:
            return None, "unsupported_linktype"

        st = _State(src_mac, dst_mac, vlan, truncated, ts, _depth, _tunnel)
        if etype in _ETH_MPLS and self.decapsulate:
            return self._mpls(data, l3, st)
        if etype == _ETH_PPPOE and self.decapsulate:
            return self._pppoe(data, l3, st)
        if etype == _ETH_IPV4:
            return self._ipv4(data, l3, st)
        if etype == _ETH_IPV6:
            return self._ipv6(data, l3, st)
        return None, "non_ip"

    # --------------------------------------------------------------- L2.5 / tunnels
    def _inner_ip(self, data: bytes, pos: int, st: "_State", name: str):
        if st.depth >= MAX_DEPTH or pos >= len(data):
            return None, "truncated" if pos >= len(data) else "tunnel_too_deep"
        ver = data[pos] >> 4
        if ver not in (4, 6):
            return None, "non_ip"
        lt = LINKTYPE_IPV4 if ver == 4 else LINKTYPE_IPV6
        pkt, why = self.decode(lt, data[pos:], st.truncated, st.ts, st.depth + 1, _join(st.tunnel, name))
        return self._inherit(pkt, st), why

    def _inner_eth(self, data: bytes, pos: int, st: "_State", name: str):
        if st.depth >= MAX_DEPTH:
            return None, "tunnel_too_deep"
        pkt, why = self.decode(LINKTYPE_ETHERNET, data[pos:], st.truncated, st.ts, st.depth + 1,
                               _join(st.tunnel, name))
        return pkt, why

    @staticmethod
    def _inherit(pkt: Optional[DecodedPacket], st: "_State") -> Optional[DecodedPacket]:
        if pkt is not None:
            if pkt.src_mac is None:
                pkt.src_mac, pkt.dst_mac = st.src_mac, st.dst_mac
            if pkt.vlan is None:
                pkt.vlan = st.vlan
        return pkt

    def _mpls(self, data: bytes, pos: int, st: "_State"):
        labels = 0
        while pos + 4 <= len(data) and labels < 16:
            bottom = data[pos + 2] & 1
            pos += 4
            labels += 1
            if bottom:
                break
        else:
            return None, "truncated"
        return self._inner_ip(data, pos, st, "mpls")

    def _pppoe(self, data: bytes, pos: int, st: "_State"):
        if len(data) < pos + 8:
            return None, "truncated"
        ver_type, code = data[pos], data[pos + 1]
        proto = struct.unpack_from("!H", data, pos + 6)[0]
        if ver_type != 0x11 or code != 0 or proto not in (0x0021, 0x0057):
            return None, "non_ip"
        return self._inner_ip(data, pos + 8, st, "pppoe")

    def _gre(self, data: bytes, pos: int, end: int, st: "_State"):
        if pos + 4 > end:
            return None, "truncated"
        flags, ptype = struct.unpack_from("!HH", data, pos)
        if flags & 0x0007:  # version != 0 (e.g. PPTP enhanced GRE)
            return None, "non_ip"
        off = pos + 4
        if flags & 0x8000:
            off += 4
        key_seq = bool(flags & 0x1000)
        if flags & 0x2000:
            off += 4
        if key_seq:
            off += 4
        if off > end:
            return None, "truncated"
        inner = data[:end]
        if ptype in (_ETH_IPV4, _ETH_IPV6):
            return self._inner_ip(inner, off, st, "gre")
        if ptype == _GRE_TEB:
            return self._inner_eth(inner, off, st, "gre")
        if ptype in _ETH_MPLS:
            return self._mpls(inner, off, _State(st.src_mac, st.dst_mac, st.vlan, st.truncated, st.ts, st.depth + 1,
                                                 _join(st.tunnel, "gre")))
        if ptype == _GRE_ERSPAN2:
            if off + 8 > end:
                return None, "truncated"
            return self._inner_eth(inner, off + 8, st, "erspan2")
        if ptype == _GRE_ERSPAN3:
            if off + 12 > end:
                return None, "truncated"
            has_sub = bool(inner[off + 11] & 1)
            return self._inner_eth(inner, off + 12 + (8 if has_sub else 0), st, "erspan3")
        return None, "non_ip"

    # ------------------------------------------------------------------- IPv4
    def _ipv4(self, data: bytes, off: int, st: "_State"):
        n = len(data)
        if n < off + 20:
            return None, "truncated"
        vihl, _tos, total_len, ident, flags_frag, _ttl, proto, _csum, raw_src, raw_dst = _IP4.unpack_from(data, off)
        if vihl >> 4 != 4:
            return None, "bad_header"
        ihl = (vihl & 0x0F) * 4
        if ihl < 20 or n < off + ihl:
            return None, "bad_header"
        if total_len == 0:  # TCP segmentation offload artefact: the length is filled in later, trust the frame
            total_len = n - off
        if total_len < ihl:
            return None, "bad_header"
        src_ip = _ip4(raw_src)
        dst_ip = _ip4(raw_dst)
        l4 = off + ihl
        end = min(off + total_len, n)
        if not st.truncated and off + total_len > n:
            return None, "bad_length"
        frag_off = (flags_frag & 0x1FFF) * 8
        more = bool(flags_frag & 0x2000)
        if more or frag_off:
            return self._fragment(("v4", src_ip, dst_ip, proto, ident), frag_off, bytes(data[l4:end]), more, proto,
                                  4, src_ip, dst_ip, st)
        return self._l4(data, l4, end, off + total_len, proto, 4, src_ip, dst_ip, st)

    # ------------------------------------------------------------------- IPv6
    def _ipv6(self, data: bytes, off: int, st: "_State"):
        n = len(data)
        if n < off + 40:
            return None, "truncated"
        if data[off] >> 4 != 6:
            return None, "bad_header"
        payload_len = struct.unpack_from("!H", data, off + 4)[0]
        nxt = data[off + 6]
        src_ip = socket.inet_ntop(socket.AF_INET6, data[off + 8 : off + 24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[off + 24 : off + 40])
        pos = off + 40
        hops = 0
        while nxt in (0, 43, 60) and hops < 8:
            if n < pos + 8:
                return None, "truncated"
            nxt_next = data[pos]
            ext_len = (data[pos + 1] + 1) * 8
            pos += ext_len
            nxt = nxt_next
            hops += 1
        wire_end = n if payload_len == 0 else off + 40 + payload_len  # 0 = jumbogram / TSO artefact
        end = min(wire_end, n)
        if not st.truncated and wire_end > n:
            return None, "bad_length"
        if nxt == 44:
            if n < pos + 8:
                return None, "truncated"
            upper = data[pos]
            offset_flags, ident = struct.unpack_from("!HI", data, pos + 2)
            return self._fragment(("v6", src_ip, dst_ip, ident), (offset_flags >> 3) * 8,
                                  bytes(data[pos + 8 : end]), bool(offset_flags & 1), upper, 6, src_ip, dst_ip, st)
        return self._l4(data, pos, end, wire_end, nxt, 6, src_ip, dst_ip, st)

    # --------------------------------------------------------------- fragments
    def _fragment(self, key, offset, payload, more, proto, ipver, src_ip, dst_ip, st: "_State"):
        if self.defrag is None:
            return None, "fragment"
        status, result, conflicts = self.defrag.add(key, offset, payload, more, st.ts,
                                                    proto if offset == 0 else None)
        if conflicts and self.conflict_hook is not None:
            self.conflict_hook(src_ip, dst_ip, conflicts)
        if status == "rejected":
            return None, "fragment_rejected"
        if status == "pending" or result is None:
            return None, "fragment_pending"
        upper_proto, body = result
        pkt, why = self._l4(body, 0, len(body), len(body), upper_proto, ipver, src_ip, dst_ip, st)
        if pkt is not None:
            pkt.fragments = max(pkt.fragments, 2)
        return pkt, why

    # ---------------------------------------------------------------------- L4
    def _l4(self, data: bytes, l4: int, end: int, wire_end: int, proto: int, ipver: int, src_ip: str, dst_ip: str,
            st: "_State"):
        if proto == 6:
            if end < l4 + 20:
                return None, "truncated"
            sport, dport, seq, ack, offs_flags = _TCP.unpack_from(data, l4)
            doff = (offs_flags >> 12) * 4
            if doff < 20:
                return None, "bad_header"
            flags = offs_flags & 0x3F
            pstart = l4 + doff
            if pstart > end:
                return None, "truncated"
            payload = bytes(data[pstart:end])
            wire_len = max(wire_end - pstart, len(payload))
            return DecodedPacket(st.src_mac, st.dst_mac, st.vlan, ipver, src_ip, dst_ip, 6, sport, dport,
                                 payload, wire_len, seq, ack, flags, st.tunnel), None
        if proto == 17:
            if end < l4 + 8:
                return None, "truncated"
            sport, dport, ulen = struct.unpack_from("!HHH", data, l4)
            body = bytes(data[l4 + 8 : end])
            if ulen >= 8:
                body = body[: ulen - 8]
            if (dport == _VXLAN_PORT and self.decapsulate and len(body) >= 8 + 14 and body[0] & 0x08
                    and st.depth < MAX_DEPTH):
                return self._inner_eth(body, 8, st, "vxlan")
            return DecodedPacket(st.src_mac, st.dst_mac, st.vlan, ipver, src_ip, dst_ip, 17, sport, dport,
                                 body, len(body), tunnel=st.tunnel), None
        if not self.decapsulate:
            return None, "non_tcp_udp"
        if proto == 47:
            return self._gre(data, l4, end, st)
        if proto in (4, 41):  # IPv4-in-IP / IPv6-in-IP
            return self._inner_ip(data[:end], l4, st, "ipip")
        return None, "non_tcp_udp"


@dataclass
class _State:
    src_mac: Optional[str]
    dst_mac: Optional[str]
    vlan: Optional[int]
    truncated: bool
    ts: float
    depth: int
    tunnel: Optional[str]


def _join(outer: Optional[str], name: str) -> str:
    return name if not outer else outer + ">" + name


_DEFAULT = Decoder()


def decode_packet(linktype: int, data: bytes, truncated: bool = True) -> Tuple[Optional[DecodedPacket], Optional[str]]:
    """Stateless decode (no fragment reassembly). See :class:`Decoder` for the full feature set.

    ``truncated`` says whether the capture may have cut the frame short (snaplen). When it is
    False the whole frame is present, so an IP length that promises more bytes than the frame
    holds is a malformed (possibly crafted) packet that the destination would not accept; it is
    rejected as ``bad_length`` instead of being mistaken for capture truncation.

    Returns ``(packet, None)`` on success or ``(None, reason)`` where reason is one of:
    unsupported_linktype, truncated, non_ip, fragment, non_tcp_udp, bad_header, bad_length,
    tunnel_too_deep.
    """
    return _DEFAULT.decode(linktype, data, truncated)
