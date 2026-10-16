"""Minimal classic-pcap writer (used by ``capture --save-pcap`` and the demo generator)."""

from __future__ import annotations

import struct
from typing import BinaryIO, Optional, Union


class PcapWriter:
    def __init__(self, target: Union[str, BinaryIO], linktype: int = 1, snaplen: int = 65535):
        self._own = isinstance(target, str)
        self._fh: BinaryIO = open(target, "wb") if self._own else target  # type: ignore[assignment]
        self._snaplen = snaplen
        self._fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        self.packets = 0

    def write(self, ts: float, data: bytes, origlen: Optional[int] = None) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1000000:
            sec += 1
            usec -= 1000000
        cap = data[: self._snaplen]
        self._fh.write(struct.pack("<IIII", sec, usec, len(cap), origlen if origlen is not None else len(data)))
        self._fh.write(cap)
        self.packets += 1

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        if self._own:
            self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
