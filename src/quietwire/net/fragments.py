"""Bounded IPv4/IPv6 fragment reassembly (first-copy-wins, conflicts reported).

Hostile fragments must not be able to exhaust memory or hide traffic: the number of
concurrent datagrams, fragments per datagram, datagram size and the reassembly lifetime
are all bounded, overlapping bytes are resolved first-copy-wins and any overlap whose bytes
*differ* (the classic Ptacek-Newsham/teardrop evasion) is counted and reported.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

MAX_DATAGRAM = 65535


class _Datagram:
    __slots__ = ("buf", "covered", "total", "first_ts", "proto", "frags", "conflicts")

    def __init__(self, ts: float):
        self.buf = bytearray()
        self.covered: List[Tuple[int, int]] = []  # merged, sorted [start, end) intervals
        self.total: Optional[int] = None
        self.first_ts = ts
        self.proto: Optional[int] = None
        self.frags = 0
        self.conflicts = 0


class FragmentReassembler:
    def __init__(self, max_datagrams: int = 1024, timeout: float = 30.0, max_fragments: int = 256):
        self._d: "OrderedDict[tuple, _Datagram]" = OrderedDict()
        self._max_datagrams = max_datagrams
        self._timeout = timeout
        self._max_fragments = max_fragments
        self.completed = 0
        self.expired = 0
        self.evicted = 0
        self.conflicts = 0
        self.rejected = 0

    def __len__(self) -> int:
        return len(self._d)

    def add(self, key: tuple, offset: int, data: bytes, more: bool, ts: float,
            proto: Optional[int] = None) -> Tuple[str, Optional[Tuple[int, bytes]], int]:
        """Offer one fragment.

        Returns ``(status, result, conflicts)``: status is ``pending``, ``complete`` (result is
        ``(upper_protocol, payload)``) or ``rejected``; ``conflicts`` counts overlapping bytes that
        differed from bytes already held for this datagram *in this call*.
        """
        self._expire(ts)
        end = offset + len(data)
        if end > MAX_DATAGRAM or (more and len(data) == 0):
            self.rejected += 1
            self._d.pop(key, None)
            return "rejected", None, 0
        dg = self._d.get(key)
        if dg is None:
            if len(self._d) >= self._max_datagrams:
                self._d.popitem(last=False)
                self.evicted += 1
            dg = _Datagram(ts)
            self._d[key] = dg
        dg.frags += 1
        if dg.frags > self._max_fragments:
            del self._d[key]
            self.rejected += 1
            return "rejected", None, 0
        if offset == 0 and proto is not None:
            dg.proto = proto
        if not more:
            if dg.total is not None and dg.total != end:
                del self._d[key]  # two different "last" fragments: contradictory, drop the datagram
                self.rejected += 1
                return "rejected", None, 0
            dg.total = end
        if dg.total is not None and end > dg.total:
            del self._d[key]
            self.rejected += 1
            return "rejected", None, 0
        conflicts = self._merge(dg, offset, data)
        self.conflicts += conflicts
        if dg.total is not None and dg.covered == [(0, dg.total)] and dg.proto is not None:
            del self._d[key]
            self.completed += 1
            return "complete", (dg.proto, bytes(dg.buf[: dg.total])), conflicts
        return "pending", None, conflicts

    # -- internals -------------------------------------------------------
    def _expire(self, now: float) -> None:
        while self._d:
            k, dg = next(iter(self._d.items()))
            if now - dg.first_ts > self._timeout:
                del self._d[k]
                self.expired += 1
            else:
                break

    @staticmethod
    def _merge(dg: _Datagram, start: int, data: bytes) -> int:
        end = start + len(data)
        if len(dg.buf) < end:
            dg.buf.extend(b"\x00" * (end - len(dg.buf)))
        conflicts = 0
        cursor = start
        new_cover: List[Tuple[int, int]] = []
        for cs, ce in dg.covered:
            if ce <= start or cs >= end:
                continue
            ov_s, ov_e = max(cs, start), min(ce, end)
            if cursor < ov_s:  # gap before this covered run: bytes are new
                dg.buf[cursor:ov_s] = data[cursor - start : ov_s - start]
            if dg.buf[ov_s:ov_e] != data[ov_s - start : ov_e - start]:
                conflicts += 1  # first copy wins; remember that the retransmitted bytes differed
            cursor = max(cursor, ov_e)
        if cursor < end:
            dg.buf[cursor:end] = data[cursor - start :]
        merged: List[Tuple[int, int]] = []
        for s, e in sorted(dg.covered + [(start, end)]):
            if merged and s <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((s, e))
        dg.covered = merged
        dg.conflicts += conflicts
        return conflicts
