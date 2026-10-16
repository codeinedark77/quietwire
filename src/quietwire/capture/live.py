"""Receive-only live capture on Linux (AF_PACKET raw socket).

This module never transmits: it opens a socket, binds it to one interface,
optionally enables promiscuous mode (a receive-side NIC setting) and calls
``recvfrom``. Requires CAP_NET_RAW (typically root).
"""

from __future__ import annotations

import select
import socket
import struct
import time
from typing import Iterator, Optional

from ..errors import QuietwireError
from .pcap import RawPacket

_ETH_P_ALL = 0x0003
_SOL_PACKET = 263
_PACKET_ADD_MEMBERSHIP = 1
_PACKET_DROP_MEMBERSHIP = 2
_PACKET_STATISTICS = 6
_PACKET_MR_PROMISC = 1
PACKET_OUTGOING = 4


class LiveCaptureError(QuietwireError):
    pass


def is_loopback(interface: str) -> bool:
    """True for loopback interfaces (IFF_LOOPBACK), where every frame is delivered twice."""
    try:
        with open("/sys/class/net/%s/flags" % interface) as fh:
            return bool(int(fh.read().strip(), 16) & 0x8)
    except (OSError, ValueError):
        return interface == "lo"


class LiveCapture:
    """Iterate over frames from ``interface`` until closed or ``stop()`` is called.

    ``skip_outgoing``: ``None`` (default) drops PACKET_OUTGOING copies on loopback only
    (the kernel hands a raw socket both an outgoing and an incoming copy of every
    loopback frame); on real interfaces outgoing frames are kept.
    """

    def __init__(self, interface: str, promisc: bool = True, snaplen: int = 65535,
                 skip_outgoing: Optional[bool] = None, poll_interval: float = 0.25,
                 duration: float = 0.0, max_packets: int = 0):
        if not hasattr(socket, "AF_PACKET"):
            raise LiveCaptureError("live capture requires Linux (AF_PACKET is unavailable on this platform)")
        self.interface = interface
        self.snaplen = snaplen
        self._skip_outgoing = is_loopback(interface) if skip_outgoing is None else skip_outgoing
        self._poll = poll_interval
        self._duration = duration
        self._max_packets = max_packets
        self._stop = False
        self._promisc = False
        self.dropped_outgoing = 0
        self.kernel_packets = 0  # frames the kernel delivered to this socket (incl. ones we then discarded)
        self.kernel_drops = 0    # frames the kernel dropped because we were too slow (socket buffer full)
        try:
            self._ifindex = socket.if_nametoindex(interface)
        except OSError:
            raise LiveCaptureError("no such interface: %s" % interface)
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
            self._sock.bind((interface, 0))
        except PermissionError:
            raise LiveCaptureError("permission denied opening a raw socket on %s (needs root or CAP_NET_RAW)"
                                   % interface)
        except OSError as exc:
            raise LiveCaptureError("cannot open capture socket on %s: %s" % (interface, exc))
        if promisc:
            try:
                mreq = struct.pack("iHH8s", self._ifindex, _PACKET_MR_PROMISC, 0, b"")
                self._sock.setsockopt(_SOL_PACKET, _PACKET_ADD_MEMBERSHIP, mreq)
                self._promisc = True
            except OSError as exc:
                self._sock.close()
                raise LiveCaptureError("cannot enable promiscuous mode on %s: %s" % (interface, exc))
        self._index = 0

    def stop(self) -> None:
        self._stop = True

    def collect_kernel_stats(self) -> None:
        """Fold the kernel's per-socket counters into ``kernel_packets``/``kernel_drops``.

        PACKET_STATISTICS counters reset on every read, so they are accumulated here.
        """
        if self._sock is None:
            return
        try:
            raw = self._sock.getsockopt(_SOL_PACKET, _PACKET_STATISTICS, 8)
            pkts, drops = struct.unpack("II", raw)
        except (OSError, struct.error, AttributeError):
            return
        self.kernel_packets += pkts
        self.kernel_drops += drops

    def close(self) -> None:
        if self._sock is None:
            return
        self.collect_kernel_stats()
        if self._promisc:
            try:
                mreq = struct.pack("iHH8s", self._ifindex, _PACKET_MR_PROMISC, 0, b"")
                self._sock.setsockopt(_SOL_PACKET, _PACKET_DROP_MEMBERSHIP, mreq)
            except OSError:
                pass
            self._promisc = False
        self._sock.close()
        self._sock = None  # type: ignore[assignment]

    def __enter__(self) -> "LiveCapture":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __iter__(self) -> Iterator[RawPacket]:
        # The deadline is evaluated on every poll wake-up, so --duration also ends an idle link.
        deadline = time.time() + self._duration if self._duration > 0 else None
        while not self._stop and self._sock is not None:
            if deadline is not None and time.time() >= deadline:
                return
            if self._max_packets and self._index >= self._max_packets:
                return
            try:
                ready, _, _ = select.select([self._sock], [], [], self._poll)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                data, addr = self._sock.recvfrom(self.snaplen)
            except (OSError, ValueError):
                return
            ts = time.time()
            if self._skip_outgoing and len(addr) > 2 and addr[2] == PACKET_OUTGOING:
                self.dropped_outgoing += 1
                continue
            self._index += 1
            yield RawPacket(self._index, -1, ts, 1, len(data), len(data), data)
