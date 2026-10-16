"""Streaming readers for classic pcap and pcapng capture files (no dependencies)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Dict, Iterator, List, Optional, Union

from ..errors import CaptureFormatError

MAX_CAPLEN = 1 << 20  # sanity limit for a single captured packet
MAX_BLOCK = 1 << 26  # sanity limit for a single pcapng block

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


@dataclass
class RawPacket:
    index: int  # 1-based
    offset: int  # byte offset of the record/block in the file
    ts: float
    linktype: int
    caplen: int
    origlen: int
    data: bytes


class CaptureReader:
    """Iterate over packets of a pcap/pcapng file.

    Truncated trailing records are tolerated: iteration stops and a message is
    appended to ``warnings``.  Structurally impossible headers raise
    :class:`CaptureFormatError`.
    """

    def __init__(self, source: Union[str, BinaryIO]):
        self._own = isinstance(source, str)
        self._fh: BinaryIO = open(source, "rb") if self._own else source  # type: ignore[assignment]
        self.warnings: List[str] = []
        self.format: str = ""
        self.linktype: Optional[int] = None
        self._closed = False
        head = self._fh.read(4)
        if len(head) < 4:
            self.close()
            raise CaptureFormatError("file too short to be a capture")
        self._head = head
        if head in _PCAP_MAGICS:
            self.format = "pcap"
        elif head == _PCAPNG_SHB:
            self.format = "pcapng"
        else:
            self.close()
            raise CaptureFormatError("unrecognised capture magic %s" % head.hex())

    # -- lifecycle -------------------------------------------------------
    def close(self) -> None:
        if not self._closed and self._own:
            self._fh.close()
        self._closed = True

    def __enter__(self) -> "CaptureReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __iter__(self) -> Iterator[RawPacket]:
        try:
            if self.format == "pcap":
                yield from self._iter_pcap()
            else:
                yield from self._iter_pcapng()
        finally:
            self.close()

    # -- classic pcap ----------------------------------------------------
    def _iter_pcap(self) -> Iterator[RawPacket]:
        endian, res = _PCAP_MAGICS[self._head]
        rest = self._fh.read(20)
        if len(rest) < 20:
            raise CaptureFormatError("truncated pcap global header")
        _vmaj, _vmin, _tz, _sig, snaplen, network = struct.unpack(endian + "HHiIII", rest)
        linktype = network & 0x0FFFFFFF
        self.linktype = linktype
        rec = struct.Struct(endian + "IIII")
        index = 0
        offset = 24
        while True:
            hdr = self._fh.read(16)
            if not hdr:
                return
            if len(hdr) < 16:
                self.warnings.append("truncated packet header at offset %d" % offset)
                return
            ts_sec, ts_frac, incl, orig = rec.unpack(hdr)
            if incl > MAX_CAPLEN:
                raise CaptureFormatError(
                    "implausible captured length %d at offset %d" % (incl, offset)
                )
            data = self._fh.read(incl)
            if len(data) < incl:
                self.warnings.append("truncated packet data at offset %d" % offset)
                return
            index += 1
            yield RawPacket(index, offset, ts_sec + ts_frac * res, linktype, incl, orig, data)
            offset += 16 + incl

    # -- pcapng ----------------------------------------------------------
    def _iter_pcapng(self) -> Iterator[RawPacket]:
        fh = self._fh
        endian = "<"
        ifaces: List[Dict[str, float]] = []  # each: {"linktype": int, "res": float}
        index = 0
        offset = 0
        pending_head: Optional[bytes] = self._head
        while True:
            if pending_head is not None:
                btype_raw = pending_head
                pending_head = None
            else:
                btype_raw = fh.read(4)
                if not btype_raw:
                    return
                if len(btype_raw) < 4:
                    self.warnings.append("truncated block header at offset %d" % offset)
                    return
            lenraw = fh.read(4)
            if len(lenraw) < 4:
                self.warnings.append("truncated block length at offset %d" % offset)
                return
            if btype_raw == _PCAPNG_SHB:
                # byte order is defined by the magic inside the SHB body
                bom = fh.read(4)
                if len(bom) < 4:
                    self.warnings.append("truncated section header at offset %d" % offset)
                    return
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise CaptureFormatError("bad pcapng byte-order magic at offset %d" % offset)
                total = struct.unpack(endian + "I", lenraw)[0]
                # remaining bytes of the block after type(4)+len(4)+bom(4)
                remaining = total - 12
                if total < 28 or total % 4 or total > MAX_BLOCK:
                    raise CaptureFormatError("bad section header length %d at offset %d" % (total, offset))
                blob = fh.read(remaining)
                if len(blob) < remaining:
                    self.warnings.append("truncated section header at offset %d" % offset)
                    return
                ifaces = []
                offset += total
                continue
            total = struct.unpack(endian + "I", lenraw)[0]
            if total < 12 or total % 4 or total > MAX_BLOCK:
                raise CaptureFormatError("bad pcapng block length %d at offset %d" % (total, offset))
            btype = struct.unpack(endian + "I", btype_raw)[0]
            body = fh.read(total - 8)
            if len(body) < total - 8:
                self.warnings.append("truncated block at offset %d" % offset)
                return
            payload = body[:-4]
            block_offset = offset
            offset += total
            if btype == 1:  # Interface Description Block
                if len(payload) < 8:
                    raise CaptureFormatError("short IDB at offset %d" % block_offset)
                linktype, _res, _snap = struct.unpack(endian + "HHI", payload[:8])
                ifaces.append({"linktype": linktype, "res": self._tsresol(payload[8:], endian)})
                if self.linktype is None:
                    self.linktype = linktype
            elif btype == 6:  # Enhanced Packet Block
                if len(payload) < 20:
                    raise CaptureFormatError("short EPB at offset %d" % block_offset)
                ifid, th, tl, caplen, origlen = struct.unpack(endian + "IIIII", payload[:20])
                if ifid >= len(ifaces):
                    self.warnings.append("EPB references unknown interface %d" % ifid)
                    continue
                if caplen > MAX_CAPLEN or 20 + caplen > len(payload):
                    raise CaptureFormatError("implausible EPB length %d at offset %d" % (caplen, block_offset))
                ts = ((th << 32) | tl) * ifaces[ifid]["res"]
                index += 1
                yield RawPacket(
                    index, block_offset, ts, int(ifaces[ifid]["linktype"]), caplen, origlen,
                    bytes(payload[20 : 20 + caplen]),
                )
            elif btype == 3:  # Simple Packet Block (no timestamp)
                if not ifaces:
                    self.warnings.append("SPB before any interface")
                    continue
                if len(payload) < 4:
                    raise CaptureFormatError("short SPB at offset %d" % block_offset)
                origlen = struct.unpack(endian + "I", payload[:4])[0]
                caplen = min(origlen, len(payload) - 4)
                index += 1
                yield RawPacket(
                    index, block_offset, 0.0, int(ifaces[0]["linktype"]), caplen, origlen,
                    bytes(payload[4 : 4 + caplen]),
                )
            # all other block types (NRB, ISB, custom, ...) are skipped

    @staticmethod
    def _tsresol(opts: bytes, endian: str) -> float:
        pos = 0
        while pos + 4 <= len(opts):
            code, length = struct.unpack(endian + "HH", opts[pos : pos + 4])
            pos += 4
            if code == 0:
                break
            val = opts[pos : pos + length]
            pos += (length + 3) & ~3
            if code == 9 and length >= 1:
                b = val[0]
                if b & 0x80:
                    return 2.0 ** -(b & 0x7F)
                return 10.0 ** -(b & 0x7F)
        return 1e-6


def open_capture(path: str) -> CaptureReader:
    return CaptureReader(path)
