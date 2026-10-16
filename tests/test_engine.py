import itertools
import random

import pytest

from conftest import alerts_for, raw_packets, rule_ids, run
from quietwire import synth
from quietwire.capture.pcap import RawPacket
from quietwire.detect.engine import Config, Engine
from quietwire.detect.policy import Policy, parse_policy
from quietwire.model import Severity
from quietwire.synth import HMI, MB_PLC, ROGUE, Conn, PcapBuilder, mb_adu


def attack_capture(mss=1460):
    pb = synth.scenario_baseline(synth.PcapBuilder(start_ts=1_700_100_000.0), cycles=5, mss=mss)
    synth.scenario_attack(pb, mss=mss)
    return pb


# -- scenario level --------------------------------------------------------------------------
def test_baseline_traffic_under_matching_policy_is_silent():
    r = run(synth.scenario_baseline(), synth.demo_policy())
    assert r.alerts == []
    assert r.stats.messages["modbus"] > 30 and r.stats.messages["dnp3"] > 30 and r.stats.messages["s7comm"] > 30
    assert not r.stats.malformed and r.stats.tcp_gaps == 0 and r.stats.alerts_dropped == 0


def test_baseline_traffic_without_policy_only_reports_write_visibility():
    r = run(synth.scenario_baseline())
    assert set(rule_ids(r)) == {"QW-W002"} and all(a.severity is Severity.LOW for a in r.alerts)


def test_attack_scenario_triggers_expected_rule_families():
    r = run(attack_capture(), synth.demo_policy())
    got = set(rule_ids(r))
    expected = {"QW-A001", "QW-F001", "QW-W001", "QW-W003", "QW-C001", "QW-C002", "QW-R001", "QW-R002", "QW-R003",
                "QW-M002", "QW-E001", "QW-D001"}
    assert expected <= got, expected - got
    assert r.alerts[0].severity is Severity.CRITICAL  # sorted most severe first
    sevs = [int(a.severity) for a in r.alerts]
    assert sevs == sorted(sevs, reverse=True)
    crit = {a.details["function"] for a in alerts_for(r, "QW-C001") if a.severity is Severity.CRITICAL}
    assert {"COLD_RESTART", "PLC_STOP", "REQUEST_DOWNLOAD"} <= crit
    # the legitimate hosts never appear as the offender
    for a in r.alerts:
        if a.rule_id in ("QW-W001", "QW-C001", "QW-R001", "QW-R002"):
            assert a.src_ip == ROGUE, a.message


def test_alert_evidence_points_at_real_packets():
    pb = attack_capture()
    pkts = {p.index: p for p in raw_packets(pb)}
    r = run(pb, synth.demo_policy())
    for a in r.alerts:
        assert a.first_packet.index in pkts and a.last_packet.index in pkts
        assert a.first_packet.offset == pkts[a.first_packet.index].offset
        assert a.first_ts <= a.last_ts and a.count >= 1 and a.samples


def test_tcp_segmentation_invariance():
    """Re-segmenting every payload into tiny TCP segments must not change what is decoded or alerted."""
    ref = run(attack_capture(1460), synth.demo_policy())
    for mss in (1, 3, 7, 64, 200):
        r = run(attack_capture(mss), synth.demo_policy())
        assert dict(r.stats.messages) == dict(ref.stats.messages), mss
        assert {(a.rule_id, a.count) for a in r.alerts} == {(a.rule_id, a.count) for a in ref.alerts}, mss
        assert r.stats.tcp_gaps == 0


def test_local_packet_reordering_and_duplication_invariance():
    pb = attack_capture()
    ref = run(pb, synth.demo_policy())
    rng = random.Random(42)
    frames = pb.ordered()
    for trial in range(25):
        shuffled = []
        buf = []
        for f in frames:
            buf.append(f)
            if len(buf) == 3:
                rng.shuffle(buf)  # swap order of neighbouring packets, keep their timestamps
                shuffled.extend(buf)
                buf = []
        shuffled.extend(buf)
        shuffled += rng.sample(frames, 20)  # plus retransmitted duplicates
        order = PcapBuilder()
        order.frames = [(ts, d) for ts, d in shuffled]
        eng = Engine(parse_policy(synth.demo_policy()))
        for i, (ts, d) in enumerate(order.frames, 1):  # feed in *wire order*, not sorted
            eng.process(RawPacket(i, 0, ts, 1, len(d), len(d), d))
        r = eng.finalize()
        assert dict(r.stats.messages) == dict(ref.stats.messages), trial
        assert {a.rule_id for a in r.alerts} == {a.rule_id for a in ref.alerts}


def test_midstream_capture_without_handshake():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 41000, 502, isn_c=5000)
    for i in range(3):
        c.push(True, mb_adu(i, 1, synth.mb_write_single_register(1, i)))
        c.push(False, mb_adu(i, 1, synth.mb_echo_write(6, 1, i)))
    r = run(pb)
    assert r.stats.messages["modbus"] == 6
    assert [x for x in r.inventory.flows.values()][0].requests == 3


def test_flow_direction_from_well_known_port_not_from_garbled_flags():
    # regression (real fuzz capture): a bogus SYN from the server port must not swap client/server
    pb = PcapBuilder()
    bad = synth.tcp_segment(MB_PLC, HMI, 502, 41000, 10, 0, synth.SYN | synth.FIN | 0x20 | synth.PSH, b"")
    pb.add(synth.frame_for(MB_PLC, HMI, 6, bad, "02:00:00:00:00:02", "02:00:00:00:00:01"))
    c = Conn(pb, HMI, MB_PLC, 41000, 502)
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c.push(False, mb_adu(1, 1, synth.mb_resp_registers(3, [1])))
    r = run(pb)
    flow = list(r.inventory.flows.values())[0]
    assert (flow.master, flow.server, flow.requests, flow.responses) == (HMI, MB_PLC, 1, 1)
    assert not flow.role_inferred


def test_role_inference_on_nonstandard_ports_uses_sane_syn_else_heuristic():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 6000, 7000)  # neither port is 502: the SYN decides
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c.push(False, mb_adu(1, 1, synth.mb_resp_registers(3, [1])))
    flow = list(run(pb).inventory.flows.values())[0]
    assert flow.master == HMI and not flow.role_inferred
    pb2 = PcapBuilder()
    c2 = Conn(pb2, HMI, MB_PLC, 7000, 6000)  # mid-stream: higher port is assumed to be the client
    c2.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c2.push(False, mb_adu(1, 1, synth.mb_resp_registers(3, [1])))
    flow2 = list(run(pb2).inventory.flows.values())[0]
    assert flow2.master == HMI and flow2.role_inferred


def test_udp_dnp3_and_modbus():
    pb = PcapBuilder()
    req = synth.dnp3_frames(20, 3, synth.dnp3_app(1, synth.dnp3_obj(60, 1, 0x06)), True)[0]
    resp = synth.dnp3_frames(3, 20, synth.dnp3_app(129, b"", iin=(0, 0)), False)[0]
    synth.udp_exchange(pb, "10.0.0.3", "10.0.0.20", 40000, 20000, req)
    synth.udp_exchange(pb, "10.0.0.20", "10.0.0.3", 20000, 40000, resp, "02:00:00:00:00:02", "02:00:00:00:00:01")
    synth.udp_exchange(pb, HMI, MB_PLC, 41000, 502, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    r = run(pb)
    assert r.stats.messages["dnp3"] == 2 and r.stats.messages["modbus"] == 1
    assert {f.transport for f in r.inventory.flows.values()} == {"udp"}
    # random UDP on other ports is ignored
    pb2 = PcapBuilder()
    synth.udp_exchange(pb2, HMI, MB_PLC, 5000, 5001, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    assert run(pb2).stats.ics_packets == 0


def test_ipv6_and_vlan_flows():
    pb = PcapBuilder()
    c = Conn(pb, "fd00::2", "fd00::10", 41000, 502, vlan=100)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_write_single_register(1, 1)))
    r = run(pb)
    assert r.stats.messages["modbus"] == 1
    assert "fd00::10" in r.inventory.assets and alerts_for(r, "QW-W002")


# -- loss / reordering health ------------------------------------------------------------------
def test_capture_loss_is_reported_and_parsing_recovers():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 41000, 502)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c.seq_c += 40  # 40 bytes were never captured
    c.push(True, mb_adu(2, 1, synth.mb_read(3, 0, 2)), dt=1.0)
    c.push(True, mb_adu(3, 1, synth.mb_read(3, 0, 3)), dt=1.0)
    r = run(pb)
    txns = sorted(m for m in (a.details.get("transaction") for a in r.alerts) if m)
    assert r.stats.messages["modbus"] == 3
    health = alerts_for(r, "QW-P001")
    assert len(health) == 1 and health[0].severity is Severity.INFO and r.stats.tcp_gaps >= 1


def test_retransmissions_do_not_double_count():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 41000, 502)
    c.open()
    seq = c.seq_c
    adu = mb_adu(1, 1, synth.mb_write_single_register(1, 1))
    c.push(True, adu)
    c.segment(True, seq, adu)  # retransmission
    c.segment(True, seq, adu)
    r = run(pb)
    assert r.stats.messages["modbus"] == 1 and r.stats.tcp_retransmits == 2
    assert alerts_for(r, "QW-W002")[0].count == 1


def test_held_segments_keep_their_own_packet_reference():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 41000, 502)
    c.open()
    a, b = mb_adu(1, 1, synth.mb_write_single_register(1, 1)), mb_adu(2, 1, synth.mb_write_single_register(2, 2))
    seq = c.seq_c
    c.segment(True, seq + len(a), b)  # arrives first (reordered)
    c.segment(True, seq, a)
    r = run(pb)
    a_alert = alerts_for(r, "QW-W002")[0]
    assert a_alert.count == 2 and a_alert.first_packet.index < a_alert.last_packet.index


def test_snaplen_truncation_is_a_gap_not_a_misparse():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 41000, 502)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_write_multiple_registers(0, list(range(60)))))
    c.push(True, mb_adu(2, 1, synth.mb_read(3, 0, 1)))
    pb.frames = [(ts, d[:80] if len(d) > 100 else d) for ts, d in pb.frames]  # snaplen 80 on the big frame
    eng = Engine()
    for i, (ts, d) in enumerate(pb.ordered(), 1):
        eng.process(RawPacket(i, 0, ts, 1, len(d), len(d), d))
    r = eng.finalize()
    assert r.stats.tcp_gaps >= 1
    assert r.stats.messages["modbus"] >= 1  # the following request is still decoded


# -- alert store -----------------------------------------------------------------------------
def test_aggregation_counts_samples_and_callback_updates():
    events = []
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 41000, 502)
    c.open()
    for i in range(120):
        c.push(True, mb_adu(i, 1, synth.mb_write_single_register(i % 5, 1)))
    r = run(pb, on_alert=lambda a, upd: events.append((a.rule_id, a.count, upd)))
    (alert,) = alerts_for(r, "QW-W002")
    assert alert.count == 120 and len(alert.samples) <= 3
    assert events[0] == ("QW-W002", 1, False)
    assert [e for e in events if e[2]] == [("QW-W002", 10, True), ("QW-W002", 100, True)]


def test_max_alerts_cap_counts_drops():
    pb = PcapBuilder()
    for i in range(30):
        c = Conn(pb, "10.1.%d.1" % i, MB_PLC, 41000, 502)
        c.open()
        c.push(True, mb_adu(1, 1, synth.mb_write_single_register(1, 1)))
    r = run(pb, cfg=Config(max_alerts=10))
    assert len(r.alerts) == 10 and r.stats.alerts_dropped == 20


def test_min_severity_ignore_rules_and_overrides():
    pb = attack_capture()
    full = run(pb, synth.demo_policy())
    hi = run(pb, synth.demo_policy(), cfg=Config(min_severity=Severity.HIGH))
    assert hi.alerts and all(a.severity >= Severity.HIGH for a in hi.alerts) and len(hi.alerts) < len(full.alerts)
    pol = synth.demo_policy()
    pol["ignore_rules"] = ["QW-A001", "QW-F001"]
    r = run(pb, pol)
    assert not {"QW-A001", "QW-F001"} & set(rule_ids(r))
    pol = synth.demo_policy()
    pol["severity_overrides"] = {"QW-A001": "critical", "QW-M002": "low"}
    r = run(pb, pol)
    assert {a.severity for a in alerts_for(r, "QW-A001")} == {Severity.CRITICAL}
    assert {a.severity for a in alerts_for(r, "QW-M002")} == {Severity.LOW}


def test_policy_thresholds_reach_the_engine():
    pol = parse_policy({"version": 1, "thresholds": {"sweep_hosts": 3, "warmup_seconds": 0}})
    eng = Engine(pol)
    assert eng.cfg.sweep_hosts == 3 and eng.cfg.warmup_seconds == 0.0
    cfg = Config()
    with pytest.raises(ValueError):
        cfg.apply({"max_alerts": 5})  # not tunable from a policy file


# -- flow table management --------------------------------------------------------------------
def test_idle_flows_expire_and_flow_cap_is_enforced():
    pb = PcapBuilder()
    for i in range(40):
        c = Conn(pb, "10.2.%d.1" % i, MB_PLC, 41000, 502)
        c.open()
        c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
        pb.ts += 100.0
    eng = Engine(config=Config(flow_idle_seconds=250.0))
    for raw in raw_packets(pb):
        eng.process(raw)
    eng._expire(pb.ts)  # the periodic sweep normally runs every 2048 packets
    assert len(eng.flows) <= 3
    r = eng.finalize()
    assert r.stats.messages["modbus"] == 40
    eng2 = Engine(config=Config(max_flows=5))
    for raw in raw_packets(pb):
        eng2.process(raw)
    assert len(eng2.flows) <= 5 and eng2.finalize().stats.messages["modbus"] == 40


def test_non_ip_and_unsupported_frames_are_counted_not_fatal():
    eng = Engine()
    eng.process(RawPacket(1, 0, 1.0, 1, 60, 60, b"\x00" * 60))           # zeroed ethernet: non-IP
    eng.process(RawPacket(2, 0, 1.0, 999, 10, 10, b"\x01" * 10))         # unknown link type
    eng.process(RawPacket(3, 0, 1.0, 1, 5, 5, b"\x01" * 5))              # truncated
    r = eng.finalize()
    assert r.stats.packets == 3 and dict(r.stats.skipped) == {"non_ip": 1, "unsupported_linktype": 1, "truncated": 1}


def test_inventory_contents():
    r = run(attack_capture(), synth.demo_policy())
    inv = r.inventory
    plc = inv.assets[MB_PLC]
    assert plc.protocols["modbus"]["server"] and 502 in plc.protocols["modbus"]["ports"]
    assert 1 in plc.modbus_units and plc.macs
    rtu = inv.assets[synth.RTU]
    assert {3, 20} <= rtu.dnp3_addresses
    s7 = inv.assets[S7_PLC] if (S7_PLC := synth.S7_PLC) else None
    assert {"rack": 0, "slot": 2, "connection_type": "PG"} in s7.s7_endpoints
    flow = inv.flows[(synth.HMI, MB_PLC, "modbus", 502)]
    assert flow.requests >= 5 and flow.responses >= 5 and flow.write_requests >= 1 and flow.transport == "tcp"
    crit = [f for f in inv.flows.values() if f.critical_functions]
    assert {f.protocol for f in crit} == {"modbus", "dnp3", "s7comm"}
    assert inv.protocol_seen("dnp3") and not inv.protocol_seen("bacnet")
    d = plc.to_dict()
    assert d["ip"] == MB_PLC and d["protocols"]["modbus"]["server"] is True and d["modbus_unit_ids"]
    assert flow.to_dict()["role_inferred"] is False


def test_device_identification_response_lands_in_inventory():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 41000, 502)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_device_id()))
    c.push(False, mb_adu(1, 1, synth.mb_device_id_response([(0, b"Acme"), (4, b"PLC-9000")])))
    r = run(pb)
    assert r.inventory.assets[MB_PLC].device_info["modbus_device_id"] == {"VendorName": "Acme",
                                                                          "ProductName": "PLC-9000"}
