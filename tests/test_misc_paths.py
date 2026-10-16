"""Remaining small paths: table limits, resets, reports with unusual data, module entry point."""

import io
import json
import runpy
import sys

import pytest

from conftest import run
from quietwire import synth
from quietwire.capture.pcap import RawPacket
from quietwire.detect.engine import Config, Engine
from quietwire.detect.policy import parse_policy
from quietwire.detect.rules import (ExceptionStormRule, RoleRule, ScanRule, default_rules)
from quietwire.model import Alert, Anomaly, PacketRef, ProtoMessage, Severity
from quietwire.report import build_report, render_text
from quietwire.synth import Conn, PcapBuilder, mb_adu


def test_model_helpers():
    assert Anomaly("c", "m").to_dict() == {"code": "c", "message": "m"}
    m = ProtoMessage("modbus", True, "X", kinds=frozenset(["write"]))
    assert m.has("write") and not m.has("read")
    assert PacketRef(3, 100, 1.5).to_dict() == {"index": 3, "offset": 100, "ts": 1.5, "source": 0}


def test_rule_state_tables_are_bounded_by_clearing():
    """Each rule keeps per-host state; a flood of distinct hosts must not grow it without limit."""
    pb = PcapBuilder()
    for i in range(300):
        c = Conn(pb, "10.%d.%d.1" % (i // 250, i % 250), "10.200.0.%d" % (i % 200 + 1), 40000, 502)
        c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
        c.push(False, mb_adu(1, 1, synth.mb_exception(3, 2)))
    scan, storm, role = ScanRule(), ExceptionStormRule(), RoleRule()
    scan._CAP = 20
    ScanRule._CAP = 20
    try:
        eng = Engine(config=Config(warmup_seconds=0), rules=[scan, storm, role, *default_rules()[:0]])
        from conftest import raw_packets
        for raw in raw_packets(pb):
            eng.process(raw)
        assert len(scan._seen_servers) <= 21 and len(scan._seen_units) <= 21
    finally:
        ScanRule._CAP = 8192
    storm._hist.update({("a", "b", str(i)): None for i in range(9000)})
    role._roles.update({("a", str(i)): set() for i in range(17000)})
    eng2 = Engine(rules=[storm, role])
    c = Conn(PcapBuilder(), "10.0.0.2", "10.0.0.10", 1, 502)
    pb2 = PcapBuilder()
    c = Conn(pb2, "10.0.0.2", "10.0.0.10", 1, 502)
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c.push(False, mb_adu(1, 1, synth.mb_exception(3, 2)))
    for raw in raw_packets(pb2):
        eng2.process(raw)
    assert len(storm._hist) < 9000 and len(role._roles) < 17000


def test_pairing_orphan_queue_is_bounded():
    pb = PcapBuilder()
    c = Conn(pb, "10.0.0.2", "10.0.0.10", 40000, 502)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    for i in range(200):
        c.push(False, mb_adu(1000 + i, 1, synth.mb_resp_registers(3, [1])), dt=0.0001)
    r = run(pb, cfg=Config(pairing_grace=1e9))
    assert any(a.rule_id == "QW-S001" for a in r.alerts)  # overflow pushes the oldest orphans out as alerts


def test_alert_to_dict_and_text_report_with_malformed_and_warnings():
    pb = PcapBuilder()
    c = Conn(pb, "10.0.0.2", "10.0.0.10", 40000, 502)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 999)))
    r = run(pb)
    rep = build_report(r, "x.pcap", "pcap", warnings=["capture ended early: demo"])
    txt = render_text(rep)
    assert "malformed:" in txt and "warning: capture ended early: demo" in txt
    d = r.alerts[0].to_dict()
    assert d["src"].endswith(":40000") and d["dst"].endswith(":502") and d["first_seen"].endswith("Z")


def test_inventory_device_info_appears_in_asset_dict():
    pb = PcapBuilder()
    c = Conn(pb, "10.0.0.2", "10.0.0.10", 40000, 502)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_device_id()))
    c.push(False, mb_adu(1, 1, synth.mb_device_id_response([(0, b"Acme")])))
    d = run(pb).inventory.assets["10.0.0.10"].to_dict()
    assert d["device_info"] == {"modbus_device_id": {"VendorName": "Acme"}}


def test_baseline_collapses_many_disjoint_write_ranges():
    from quietwire.detect.policy import build_baseline

    pb = PcapBuilder()
    c = Conn(pb, "10.0.0.2", "10.0.0.10", 40000, 502)
    c.open()
    for i in range(100):
        c.push(True, mb_adu(i, 1, synth.mb_write_single_register(i * 10, 1)), dt=0.0001)
    doc = build_baseline(run(pb).inventory, max_ranges_per_key=8)
    hr = [w for w in doc["write_ranges"] if w["area"] == "holding_register"]
    assert len(hr) == 1 and (hr[0]["start"], hr[0]["end"]) == (0, 990)  # collapsed to one covering range


def test_engine_syn_and_negative_caches_are_bounded():
    eng = Engine()
    for i in range(70000):
        eng._remember_syn(("k", i), ("1.1.1.1", 1))
        eng._remember_negative(("n", i))
    assert len(eng._syns) <= 65536 and len(eng._neg) <= 65536


def test_ack_only_and_empty_segments_are_ignored_after_flow_exists():
    pb = PcapBuilder()
    c = Conn(pb, "10.0.0.2", "10.0.0.10", 40000, 502)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c.close()
    assert run(pb).stats.messages["modbus"] == 1


def test_syn_ack_first_seen_still_picks_the_right_client():
    pb = PcapBuilder()
    l4 = synth.tcp_segment("10.0.0.10", "10.0.0.2", 7000, 6000, 10, 100, synth.SYN | synth.ACK)
    pb.add(synth.frame_for("10.0.0.10", "10.0.0.2", 6, l4, "02:00:00:00:00:02", "02:00:00:00:00:01"))
    c = Conn(pb, "10.0.0.2", "10.0.0.10", 6000, 7000, isn_c=100, isn_s=11)
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c.push(False, mb_adu(1, 1, synth.mb_resp_registers(3, [1])))
    flow = list(run(pb).inventory.flows.values())[0]
    assert flow.master == "10.0.0.2" and flow.server == "10.0.0.10"


def test_module_entry_point_runs_in_process(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["quietwire", "rules", "--json"])
    with pytest.raises(SystemExit) as e:
        runpy.run_module("quietwire", run_name="__main__")
    assert e.value.code == 0
    assert len(json.loads(capsys.readouterr().out)) == 21


def test_mitre_helper():
    from quietwire.detect.mitre import technique_name
    assert technique_name("T0816") == "Device Restart/Shutdown" and technique_name("T9999") == "T9999"


def test_pcapwriter_flush_and_context(tmp_path):
    from quietwire.capture.pcapwriter import PcapWriter
    w = PcapWriter(str(tmp_path / "f.pcap"))
    w.write(1.0, b"abc")
    w.flush()
    w.close()
    assert w.packets == 1
    buf = io.BytesIO()
    pw = PcapWriter(buf)
    pw.write(2.9999999, b"x")  # rounds the microseconds up into the next second
    buf.seek(0)
    from quietwire.capture.pcap import CaptureReader
    assert list(CaptureReader(buf))[0].ts == pytest.approx(3.0)


def test_cli_analyze_closes_audit_log_when_capture_is_unreadable(tmp_path):
    from quietwire.cli import main
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a pcap")
    assert main(["analyze", str(bad), "--audit-log", str(tmp_path / "a.jsonl")]) == 3
