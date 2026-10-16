"""Error handling of the live capture module, driven through a fake socket (no privileges needed)."""

import socket
import struct

import pytest

from quietwire.capture import live
from quietwire.capture.live import LiveCapture, LiveCaptureError, PACKET_OUTGOING


class FakeSock:
    def __init__(self, frames=(), fail_setsockopt=False, fail_bind=None, fail_recv=False):
        self.frames = list(frames)
        self.opts = []
        self.fail_setsockopt = fail_setsockopt
        self.fail_recv = fail_recv
        self.closed = False
        if fail_bind:
            self._bind_exc = fail_bind
        else:
            self._bind_exc = None

    def bind(self, addr):
        if self._bind_exc:
            raise self._bind_exc

    def setsockopt(self, level, opt, val):
        if self.fail_setsockopt and opt == live._PACKET_ADD_MEMBERSHIP:
            raise OSError("no promisc for you")
        self.opts.append((level, opt, val))

    def fileno(self):
        return 99

    def recvfrom(self, n):
        if self.fail_recv:
            raise OSError("socket died")
        if not self.frames:
            raise OSError("empty")
        return self.frames.pop(0)

    def getsockopt(self, level, opt, n):
        if getattr(self, "stats_exc", None):
            raise self.stats_exc
        assert (level, opt) == (live._SOL_PACKET, live._PACKET_STATISTICS) and n == 8
        return struct.pack("II", *self.stats_queue.pop(0)) if getattr(self, "stats_queue", None) else struct.pack("II", 0, 0)

    def close(self):
        self.closed = True


@pytest.fixture
def patch(monkeypatch):
    def apply(sock=None, exc=None, ready=True):
        monkeypatch.setattr(socket, "if_nametoindex", lambda name: 7)
        if exc is not None:
            def boom(*a, **k):
                raise exc
            monkeypatch.setattr(socket, "socket", boom)
        else:
            monkeypatch.setattr(socket, "socket", lambda *a, **k: sock)
        monkeypatch.setattr(live.select, "select", lambda r, w, x, t: (r if ready else [], [], []))
    return apply


def test_permission_denied_message(patch):
    patch(exc=PermissionError())
    with pytest.raises(LiveCaptureError, match="permission denied.*CAP_NET_RAW"):
        LiveCapture("eth0")


def test_generic_open_error(patch):
    patch(exc=OSError("boom"))
    with pytest.raises(LiveCaptureError, match="cannot open capture socket"):
        LiveCapture("eth0")


def test_bind_error_is_wrapped(patch):
    patch(FakeSock(fail_bind=OSError("no such device")))
    with pytest.raises(LiveCaptureError, match="cannot open capture socket"):
        LiveCapture("eth0")


def test_promiscuous_failure_closes_the_socket(patch):
    sock = FakeSock(fail_setsockopt=True)
    patch(sock)
    with pytest.raises(LiveCaptureError, match="promiscuous"):
        LiveCapture("eth0", promisc=True)
    assert sock.closed


def test_promisc_membership_is_added_and_dropped(patch):
    sock = FakeSock()
    patch(sock)
    cap = LiveCapture("eth0", promisc=True)
    assert sock.opts[0][1] == live._PACKET_ADD_MEMBERSHIP
    assert struct.unpack("iHH8s", sock.opts[0][2])[:2] == (7, live._PACKET_MR_PROMISC)
    cap.close()
    assert sock.opts[-1][1] == live._PACKET_DROP_MEMBERSHIP and sock.closed
    cap.close()  # idempotent


def test_frames_flow_through_and_outgoing_filtering(patch):
    frames = [(b"aaa", ("eth0", 0x800, 0, 1, b"")), (b"bbb", ("eth0", 0x800, PACKET_OUTGOING, 1, b"")),
              (b"ccc", ("eth0", 0x800, 0, 1, b""))]
    sock = FakeSock(frames)
    patch(sock)
    cap = LiveCapture("eth0", promisc=False, skip_outgoing=True, max_packets=2)
    got = [p.data for p in cap]
    assert got == [b"aaa", b"ccc"] and cap.dropped_outgoing == 1
    keep = LiveCapture("eth0", promisc=False, skip_outgoing=False)
    keep._sock = FakeSock(frames[:2])
    assert [p.data for p in _take(keep, 2)] == [b"aaa", b"bbb"]


def _take(cap, n):
    out = []
    for p in cap:
        out.append(p)
        if len(out) == n:
            cap.stop()
    return out


def test_socket_errors_end_iteration_cleanly(patch):
    patch(FakeSock(fail_recv=True))
    assert list(LiveCapture("eth0", promisc=False)) == []


def test_select_errors_end_iteration_cleanly(patch, monkeypatch):
    patch(FakeSock())
    monkeypatch.setattr(live.select, "select", lambda *a: (_ for _ in ()).throw(OSError("bad fd")))
    assert list(LiveCapture("eth0", promisc=False)) == []


def test_idle_link_honours_duration(patch):
    import time

    patch(FakeSock(), ready=False)
    t = time.time()
    assert list(LiveCapture("eth0", promisc=False, duration=0.4, poll_interval=0.05)) == []
    assert 0.35 <= time.time() - t < 3


def test_non_linux_platform_error(monkeypatch):
    monkeypatch.delattr(socket, "AF_PACKET", raising=False)
    with pytest.raises(LiveCaptureError, match="requires Linux"):
        LiveCapture("eth0")


def test_is_loopback_fallbacks(monkeypatch):
    real_open = open

    def fake_open(path, *a, **k):
        if str(path).startswith("/sys/class/net/"):
            raise OSError("no sysfs")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    assert live.is_loopback("lo") and not live.is_loopback("eth0")


def test_kernel_stats_accumulate_across_reads_and_survive_errors(patch):
    sock = FakeSock()
    sock.stats_queue = [(10, 1), (5, 2)]
    patch(sock)
    cap = LiveCapture("eth0", promisc=False)
    cap.collect_kernel_stats()
    cap.close()  # close() folds in the final counters too
    assert (cap.kernel_packets, cap.kernel_drops) == (15, 3)
    cap.collect_kernel_stats()  # after close: no-op, no exception
    sock2 = FakeSock()
    sock2.stats_exc = OSError("unsupported")
    patch(sock2)
    cap2 = LiveCapture("eth0", promisc=False)
    cap2.close()
    assert (cap2.kernel_packets, cap2.kernel_drops) == (0, 0)
