"""Live capture tests on the loopback interface (need Linux + CAP_NET_RAW; skipped otherwise)."""

import json
import socket
import threading
import time

import pytest

from quietwire import synth
from quietwire.capture.live import LiveCapture, LiveCaptureError, is_loopback
from quietwire.cli import main
from quietwire.detect.engine import Engine


def _can_capture():
    if not hasattr(socket, "AF_PACKET"):
        return False
    try:
        LiveCapture("lo", promisc=False).close()
        return True
    except LiveCaptureError:
        return False


pytestmark = pytest.mark.skipif(not _can_capture(), reason="raw capture on 'lo' not permitted here")


class ModbusEcho:
    """A tiny real Modbus/TCP server: answers reads with 3 registers and echoes writes."""

    def __init__(self, port=0):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        try:
            while True:
                c, _ = self.srv.accept()
                try:
                    while True:
                        d = c.recv(4096)
                        if not d:
                            break
                        fc = d[7]
                        if fc == 3:
                            c.sendall(d[:4] + b"\x00\x09" + bytes([d[6]]) + b"\x03\x06\x00\x01\x00\x02\x00\x03")
                        else:
                            c.sendall(d)
                except OSError:
                    pass
                finally:
                    c.close()
        except OSError:
            pass

    def close(self):
        try:
            self.srv.close()
        except OSError:
            pass


def traffic(port, n_reads=3, with_write=True, delay=0.3):
    time.sleep(delay)
    cl = socket.create_connection(("127.0.0.1", port))
    for i in range(n_reads):
        cl.sendall(synth.mb_adu(i + 1, 1, synth.mb_read(3, 0, 3)))
        cl.recv(4096)
    if with_write:
        cl.sendall(synth.mb_adu(50, 1, synth.mb_write_single_register(5, 7)))
        cl.recv(4096)
    time.sleep(0.2)
    cl.close()


def sniff(engine, duration):
    cap = LiveCapture("lo", promisc=False)
    frames = []
    done = threading.Event()

    def run():
        for raw in cap:
            frames.append(raw)
            engine.process(raw)
        done.set()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return cap, frames, t


def test_loopback_detection():
    assert is_loopback("lo")


def test_live_capture_sees_real_modbus_traffic_without_duplicates():
    srv = ModbusEcho()
    eng = Engine()
    cap, frames, t = sniff(eng, 3)
    try:
        time.sleep(0.2)
        traffic(srv.port)
        time.sleep(0.3)
    finally:
        cap.stop()
        t.join(3)
        cap.close()
        srv.close()
    res = eng.finalize()
    assert cap.dropped_outgoing > 0           # loopback duplicates were filtered at the socket
    assert cap.kernel_packets >= len(frames) + cap.dropped_outgoing and cap.kernel_drops == 0
    assert res.stats.tcp_retransmits == 0     # ...so nothing looks retransmitted
    assert res.stats.messages["modbus"] == 8  # 4 requests + 4 responses
    (flow,) = res.inventory.flows.values()
    assert (flow.requests, flow.responses, flow.write_requests) == (4, 4, 1)
    assert flow.server_port == srv.port and flow.identified_by == "signature" and not flow.role_inferred
    rules = {a.rule_id for a in res.alerts}
    assert "QW-N001" in rules and "QW-W002" in rules  # non-standard port + write visibility
    assert all(f.index > 0 and f.offset == -1 for f in [a.first_packet for a in res.alerts])


def test_live_capture_on_port_502_when_bindable():
    try:
        srv = ModbusEcho(502)
    except OSError:
        pytest.skip("cannot bind port 502")
    eng = Engine()
    cap, frames, t = sniff(eng, 3)
    try:
        time.sleep(0.2)
        traffic(502, n_reads=2, with_write=False)
        time.sleep(0.3)
    finally:
        cap.stop()
        t.join(3)
        cap.close()
        srv.close()
    res = eng.finalize()
    (flow,) = res.inventory.flows.values()
    assert flow.server_port == 502 and flow.identified_by == "port" and flow.requests == 2
    assert not [a for a in res.alerts if a.rule_id == "QW-N001"]


def test_cli_capture_command_end_to_end(tmp_path, capsys):
    srv = ModbusEcho()
    out = str(tmp_path / "live.json")
    pcap = str(tmp_path / "saved.pcap")
    log = str(tmp_path / "audit.jsonl")
    th = threading.Thread(target=traffic, args=(srv.port,), kwargs={"delay": 0.6}, daemon=True)
    th.start()
    try:
        rc = main(["capture", "-i", "lo", "--duration", "2.5", "--no-promisc", "--format", "json", "--out", out,
                   "--save-pcap", pcap, "--audit-log", log, "--fail-on", "low"])
    finally:
        th.join(5)
        srv.close()
    assert rc == 1  # the write produced a LOW alert, --fail-on low trips
    doc = json.load(open(out))
    assert doc["input"]["format"] == "live" and doc["input"]["source"] == "live:lo"
    assert doc["stats"]["messages"]["modbus"] == 8
    assert any(a["rule_id"] == "QW-W002" for a in doc["alerts"])
    # the saved pcap replays to the same message count
    rc = main(["analyze", pcap, "--format", "json", "--out", str(tmp_path / "replay.json")])
    replay = json.load(open(tmp_path / "replay.json"))
    assert replay["stats"]["messages"]["modbus"] == 8 and replay["input"]["packets"] == doc["input"]["packets"]
    from quietwire.report.auditlog import verify_log

    assert verify_log(log).ok
    err = capsys.readouterr().err
    assert "ALERT" in err and "QW-W002" in err  # alerts are streamed to stderr as they happen


def test_stop_ends_iteration_and_close_is_idempotent():
    cap = LiveCapture("lo", promisc=False)
    cap.stop()
    assert list(cap) == []
    cap.close()
    cap.close()


def test_errors():
    with pytest.raises(LiveCaptureError, match="no such interface"):
        LiveCapture("definitely-not-an-iface0")
