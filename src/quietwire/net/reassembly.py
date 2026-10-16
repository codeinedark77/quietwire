"""Minimal single-direction TCP byte-stream reassembly.

Design goals: bounded memory, tolerance for retransmissions / reordering /
mid-stream capture start, and *prompt recovery after capture loss*: segments
held back behind a hole are released (with an explicit gap marker) when the hole
has not been filled within ``reorder_window`` seconds of capture time or when too
many segments are queued; anything still held is released by ``flush()``.
(ACK-based release was tried and removed: with capture-side reordering an ACK can
legitimately precede the segment it acknowledges, which silently dropped data.)  Protocol framers use the gap marker to
resynchronise instead of mis-parsing.

Sequence-space hygiene (a passive analyser must not let one bogus packet poison a
stream): segments further than ``max_ahead`` bytes ahead of or behind the expected
sequence number are *out of window*. They are counted and ignored, unless
``resync_after`` consecutive out-of-window segments form a contiguous run in a new
sequence space (the connection was re-established and its SYN was not captured), in
which case the stream is re-based there with an explicit gap marker.

Every offered segment may carry an opaque ``tag`` (the engine passes the packet
reference).  Delivered chunks carry the tag of the segment they came from, so
evidence pointers stay correct even when delivery was delayed by reordering.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

_MASK = 0xFFFFFFFF
_HALF = 0x80000000

Chunk = Tuple[bytes, bool, Any]  # (data, gap_before, tag)


class DirectionStream:
    def __init__(self, max_ooo_bytes: int = 65536, max_ooo_segments: int = 8, reorder_window: float = 0.25,
                 max_ahead: int = 1 << 20, resync_after: int = 3):
        self.next_seq: Optional[int] = None
        self._ooo: Dict[int, Tuple[bytes, int, float, Any]] = {}
        self._ooo_bytes = 0
        self._max_ooo_bytes = max_ooo_bytes
        self._max_ooo_segments = max_ooo_segments
        self._window = reorder_window
        self._gap_pending = False
        self.gaps = 0
        self.retransmitted_segments = 0
        self.delivered_bytes = 0
        self.out_of_window = 0
        self.isn_next: Optional[int] = None  # first data sequence number announced by this stream's SYN
        self._max_ahead = max_ahead
        self._resync_after = resync_after
        self._oow_run: List[Tuple[int, bytes, int, Any]] = []

    # -- public API ------------------------------------------------------
    def add(self, seq: int, data: bytes, wire_len: Optional[int] = None, syn: bool = False,
            ts: float = 0.0, tag: Any = None) -> List[Chunk]:
        """Offer a segment. Returns in-order chunks as ``(data, gap_before, tag)``."""
        out: List[Chunk] = []
        if syn:
            seq = (seq + 1) & _MASK
            if self.next_seq is None:
                self.next_seq = seq
                self.isn_next = seq
        n = wire_len if wire_len is not None else len(data)
        if n == 0:
            return out
        if self.next_seq is None:
            self.next_seq = seq
        delta = (seq - self.next_seq) & _MASK
        if delta == 0:
            self._oow_run.clear()
            self._deliver(data, n, tag, out)
        elif delta <= self._max_ahead:
            self._oow_run.clear()
            held = self._ooo.get(seq)
            if held is None or len(held[0]) < len(data):
                if held is not None:
                    self._ooo_bytes -= len(held[0])
                self._ooo[seq] = (data, n, held[2] if held else ts, tag)
                self._ooo_bytes += len(data)
        else:
            overlap = (self.next_seq - seq) & _MASK
            if overlap <= self._max_ahead:  # behind us: retransmission or partial overlap
                self._oow_run.clear()
                if overlap >= n:
                    self.retransmitted_segments += 1
                else:
                    self._deliver(data[overlap:], n - overlap, tag, out)
            else:
                self._out_of_window(seq, data, n, tag, out)
        self._release_stale(ts, out)
        return out

    def _out_of_window(self, seq: int, data: bytes, n: int, tag: Any, out: List[Chunk]) -> None:
        self.out_of_window += 1
        if self._oow_run and seq != (self._oow_run[-1][0] + self._oow_run[-1][2]) & _MASK:
            self._oow_run.clear()  # not contiguous with the previous stray segment: still just noise
        self._oow_run.append((seq, data, n, tag))
        if len(self._oow_run) >= self._resync_after:
            run, self._oow_run = self._oow_run, []
            self._ooo.clear()
            self._ooo_bytes = 0
            self.next_seq = run[0][0]
            self._gap_pending = True
            self.gaps += 1
            for rseq, rdata, rn, rtag in run:
                self._deliver(rdata, rn, rtag, out)

    def flush(self) -> List[Chunk]:
        """Release everything still held behind holes (end of capture / flow expiry)."""
        out: List[Chunk] = []
        while self._ooo:
            self._skip_to_nearest(out)
        return out

    # -- internals -------------------------------------------------------
    def _nearest(self) -> int:
        base = self.next_seq or 0
        return min(self._ooo, key=lambda k: (k - base) & _MASK)

    def _skip_to_nearest(self, out: List[Chunk]) -> None:
        nearest = self._nearest()
        self.next_seq = nearest
        self._gap_pending = True
        self.gaps += 1
        data, n, _ts, tag = self._pop(nearest)
        self._deliver(data, n, tag, out)

    def _release_stale(self, now: float, out: List[Chunk]) -> None:
        while self._ooo:
            oldest = min(v[2] for v in self._ooo.values())
            if (len(self._ooo) > self._max_ooo_segments or self._ooo_bytes > self._max_ooo_bytes
                    or now - oldest > self._window):
                self._skip_to_nearest(out)
            else:
                break

    def _pop(self, seq: int) -> Tuple[bytes, int, float, Any]:
        entry = self._ooo.pop(seq)
        self._ooo_bytes -= len(entry[0])
        return entry

    def _deliver(self, data: bytes, n: int, tag: Any, out: List[Chunk]) -> None:
        self._emit(data, n, tag, out)
        progressed = True
        while progressed and self._ooo:
            progressed = False
            for k in list(self._ooo):
                delta = (k - (self.next_seq or 0)) & _MASK
                if delta == 0:
                    d, ln, _ts, t = self._pop(k)
                    self._emit(d, ln, t, out)
                    progressed = True
                elif delta >= _HALF:
                    d, ln, _ts, t = self._pop(k)
                    overlap = ((self.next_seq or 0) - k) & _MASK
                    if overlap < ln:
                        self._emit(d[overlap:], ln - overlap, t, out)
                    progressed = True

    def _emit(self, data: bytes, n: int, tag: Any, out: List[Chunk]) -> None:
        if data:
            out.append((data, self._gap_pending, tag))
            self._gap_pending = False
            self.delivered_bytes += len(data)
        if len(data) < n:
            # snaplen truncated this segment: the missing tail is a gap
            self._gap_pending = True
            self.gaps += 1
        self.next_seq = ((self.next_seq or 0) + n) & _MASK
