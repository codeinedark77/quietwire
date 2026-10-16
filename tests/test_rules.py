"""One focused test per detection rule (positive and negative cases) using synthetic traffic."""

import pytest

from conftest import alerts_for, rule_ids, run, single_modbus
from quietwire import synth
from quietwire.detect.engine import Config
from quietwire.model import Severity
from quietwire.synth import (HMI, MB_PLC, ROGUE, RTU, S7_PLC, SCADA, Conn, PcapBuilder, dnp3_app, dnp3_crob,
                             dnp3_frames, dnp3_obj, mb_adu)


def mb_conn(pb=None, client=HMI, server=MB_PLC, cport=41000):
    pb = pb or PcapBuilder()
    c = Conn(pb, client, server, cport, 502)
    c.open()
    return pb, c


def dnp3_send(c, app, master=True, src=3, dest=20, tseq=0):
    for f in dnp3_frames(dest, src, app, master=master, tseq=tseq):
        c.push(master, f)


# ------------------------------------------------------------------- QW-A001 / QW-F001
def test_asset_rule_flags_unknown_master_and_server_once_each():
    pb, c = mb_conn()
    for i in range(5):
        c.push(True, mb_adu(i, 1, synth.mb_read(3, 0, 1)))
        c.push(False, mb_adu(i, 1, synth.mb_resp_registers(3, [1])))
    r = run(pb, {"assets": [{"ip": "10.9.9.9"}]})
    a = alerts_for(r, "QW-A001")
    assert {x.details["ip"] for x in a} == {HMI, MB_PLC}
    roles = {x.details["ip"]: x.details["role"] for x in a}
    assert roles == {HMI: "master", MB_PLC: "server"}
    assert [x for x in a if x.details["ip"] == HMI][0].mitre == ("T0848",)
    assert all(x.severity is Severity.MEDIUM and x.count >= 5 for x in a)


def test_asset_rule_quiet_when_all_known_or_not_enforced():
    pb, c = mb_conn()
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    assert not alerts_for(run(pb, {"assets": [{"ip": HMI}, {"ip": MB_PLC}]}), "QW-A001")
    assert not alerts_for(run(pb, {"assets": [{"ip": "10.9.9.9"}], "enforce_assets": False}), "QW-A001")
    assert not alerts_for(run(pb), "QW-A001")


def test_flow_rule():
    pb, c = mb_conn()
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    ok = {"allowed_flows": [{"master": HMI, "server": MB_PLC, "protocol": "modbus", "port": 502}]}
    assert not alerts_for(run(pb, ok), "QW-F001")
    bad = {"allowed_flows": [{"master": SCADA, "server": MB_PLC}]}
    f = alerts_for(run(pb, bad), "QW-F001")
    assert len(f) == 1 and f[0].severity is Severity.HIGH and f[0].details["server"] == MB_PLC
    assert alerts_for(run(pb, {"allowed_flows": []}), "QW-F001")


# ------------------------------------------------------------------------- writes
def test_write_without_writer_policy_is_low_severity_visibility():
    pb, c = mb_conn()
    for i in range(3):
        c.push(True, mb_adu(i, 1, synth.mb_write_single_register(5, i)))
    r = run(pb)
    a = alerts_for(r, "QW-W002")
    assert len(a) == 1 and a[0].count == 3 and a[0].severity is Severity.LOW
    assert not alerts_for(r, "QW-W001")


def test_authorised_writer_is_silent_unauthorised_is_high():
    pb, c = mb_conn()
    c.push(True, mb_adu(1, 1, synth.mb_write_single_register(5, 1)))
    assert not run(pb, {"writers": {"modbus": [HMI]}}).alerts
    r = run(pb, {"writers": {"modbus": ["10.0.0.200"]}})
    a = alerts_for(r, "QW-W001")
    assert len(a) == 1 and a[0].severity is Severity.HIGH and a[0].mitre == ("T1692.001", "T0836")
    assert a[0].details["targets"] == [{"area": "holding_register", "start": 5, "end": 5}]
    # writer policy for another protocol does not constrain Modbus (falls back to W002)
    assert alerts_for(run(pb, {"writers": {"dnp3": []}}), "QW-W002")


def test_write_range_enforcement():
    pb, c = mb_conn()
    c.push(True, mb_adu(1, 1, synth.mb_write_single_register(105, 1)))   # inside
    c.push(True, mb_adu(2, 1, synth.mb_write_single_register(200, 1)))   # outside
    c.push(True, mb_adu(3, 1, synth.mb_write_multiple_registers(108, [1, 2, 3])))  # straddles the end
    pol = {"write_ranges": [{"server": MB_PLC, "protocol": "modbus", "unit": 1, "area": "holding_register",
                             "start": 100, "end": 109}]}
    a = alerts_for(run(pb, pol), "QW-W003")
    spans = sorted((x.details["violations"][0]["start"], x.details["violations"][0]["end"]) for x in a)
    assert spans == [(108, 110), (200, 200)]
    other_server = {"write_ranges": [{"server": "10.7.7.7", "protocol": "modbus", "area": "holding_register",
                                      "start": 0, "end": 1}]}
    assert not alerts_for(run(pb, other_server), "QW-W003")


def test_write_range_with_indeterminate_target_alerts():
    pb, c = mb_conn()
    c.push(True, mb_adu(1, 1, bytes([16, 0, 0, 0, 0, 0])))  # bad quantity => no trusted target
    pol = {"write_ranges": [{"server": MB_PLC, "protocol": "modbus", "area": "holding_register", "start": 0, "end": 9}]}
    a = alerts_for(run(pb, pol), "QW-W003")
    assert a and "could not be determined" in a[0].message


def test_dnp3_control_is_a_write_and_ranges_apply_to_control_points():
    pb = PcapBuilder()
    c = Conn(pb, SCADA, RTU, 40000, 20000)
    c.open()
    dnp3_send(c, dnp3_app(5, dnp3_crob(2, 0x03), seq=1))
    dnp3_send(c, dnp3_app(5, dnp3_crob(30, 0x04), seq=2))
    pol = {"writers": {"dnp3": [SCADA]},
           "write_ranges": [{"server": RTU, "protocol": "dnp3", "area": "binary_output", "start": 0, "end": 7}]}
    r = run(pb, pol)
    a = alerts_for(r, "QW-W003")
    assert len(a) == 1 and a[0].details["violations"][0]["start"] == 30
    assert not alerts_for(r, "QW-W001")


def test_s7_write_ranges_by_db():
    pb = PcapBuilder()
    c = Conn(pb, synth.EWS, S7_PLC, 40000, 102)
    c.open()
    c.push(True, synth.s7_write_job(1, [(0x84, 1, 10, b"\x00\x01")]))
    c.push(True, synth.s7_write_job(2, [(0x84, 7, 10, b"\x00\x01")]))
    pol = {"write_ranges": [{"server": S7_PLC, "protocol": "s7comm", "area": "DB1", "start": 0, "end": 99}]}
    a = alerts_for(run(pb, pol), "QW-W003")
    assert len(a) == 1 and a[0].details["violations"][0]["area"] == "DB7"


# ----------------------------------------------------------------------- critical
CRIT_CASES = [
    ("modbus-listen-only", lambda c: c.push(True, mb_adu(1, 1, synth.mb_diag(0x0004))), Severity.HIGH, ("T0814",)),
    ("modbus-restart-comms", lambda c: c.push(True, mb_adu(1, 1, synth.mb_diag(0x0001))), Severity.HIGH, ("T0816",)),
]


@pytest.mark.parametrize("name,send,sev,mitre", CRIT_CASES)
def test_modbus_critical_operations(name, send, sev, mitre):
    pb, c = mb_conn()
    send(c)
    a = alerts_for(run(pb), "QW-C001")
    assert len(a) == 1 and a[0].severity is sev and a[0].mitre == mitre


def test_benign_modbus_diagnostics_not_critical():
    pb, c = mb_conn()
    c.push(True, mb_adu(1, 1, synth.mb_diag(0x0000, 1)))
    assert not alerts_for(run(pb), "QW-C001")


@pytest.mark.parametrize("fc,name,sev", [(13, "COLD_RESTART", Severity.CRITICAL), (14, "WARM_RESTART", Severity.CRITICAL),
                                         (15, "INITIALIZE_DATA", Severity.HIGH), (18, "STOP_APPL", Severity.CRITICAL),
                                         (27, "DELETE_FILE", Severity.HIGH)])
def test_dnp3_critical_operations(fc, name, sev):
    pb = PcapBuilder()
    c = Conn(pb, ROGUE, RTU, 40000, 20000)
    c.open()
    dnp3_send(c, dnp3_app(fc), src=9)
    a = alerts_for(run(pb), "QW-C001")
    assert len(a) == 1 and a[0].severity is sev and name in a[0].message


def test_s7_critical_operations():
    pb = PcapBuilder()
    c = Conn(pb, ROGUE, S7_PLC, 40000, 102)
    c.open()
    c.push(True, synth.s7_plc_stop())
    c.push(True, synth.s7_pi_service(b"_INSE"))
    c.push(True, synth.s7_pi_service(b"P_PROGRAM"))
    c.push(True, synth.s7_pi_service(b"_ZZZZ"))
    c.push(True, synth.s7_request_download())
    c.push(True, synth.s7_start_upload())
    r = run(pb)
    by_msg = {a.details["function"] + ":" + str(a.details["subfunction"]): a for a in alerts_for(r, "QW-C001")}
    assert by_msg["PLC_STOP:P_PROGRAM"].severity is Severity.CRITICAL
    assert by_msg["PI_SERVICE:_INSE"].severity is Severity.CRITICAL and "T0843" in by_msg["PI_SERVICE:_INSE"].mitre
    assert by_msg["PI_SERVICE:P_PROGRAM"].severity is Severity.HIGH
    assert by_msg["PI_SERVICE:_ZZZZ"].severity is Severity.HIGH  # unknown PI service: generic high
    assert by_msg["REQUEST_DOWNLOAD:None"].severity is Severity.CRITICAL
    assert by_msg["START_UPLOAD:None"].severity is Severity.HIGH and by_msg["START_UPLOAD:None"].mitre == ("T0845",)


def test_engineering_station_is_exempt_from_critical_and_fingerprinting():
    pb = PcapBuilder()
    c = Conn(pb, synth.EWS, S7_PLC, 40000, 102)
    c.open()
    c.push(True, synth.s7_plc_stop())
    c.push(True, synth.s7_userdata(4, 1, data=b"\xff\x09\x00\x04\x00\x11\x00\x01"))
    r = run(pb, {"engineering_stations": [synth.EWS]})
    assert not alerts_for(r, "QW-C001") and not alerts_for(r, "QW-R003")
    r = run(pb)
    assert alerts_for(r, "QW-C001") and alerts_for(r, "QW-R003")


def test_file_transfer_only_is_medium():
    pb = PcapBuilder()
    c = Conn(pb, ROGUE, RTU, 40000, 20000)
    c.open()
    dnp3_send(c, dnp3_app(25, b""))
    a = alerts_for(run(pb), "QW-C001")
    assert len(a) == 1 and a[0].severity is Severity.MEDIUM


# ---------------------------------------------------------------------- broadcast
def test_broadcast_rules():
    pb = PcapBuilder()
    c = Conn(pb, ROGUE, RTU, 40000, 20000)
    c.open()
    dnp3_send(c, dnp3_app(5, dnp3_crob(0, 0x04)), dest=0xFFFF, src=9)          # control to all stations
    dnp3_send(c, dnp3_app(1, dnp3_obj(60, 1, 0x06)), dest=0xFFFF, src=9)       # read to all stations
    dnp3_send(c, dnp3_app(24, b""), dest=0xFFFD, src=9)                        # time record: maintenance
    r = run(pb)
    a = alerts_for(r, "QW-C002")
    sev = {x.details["function"]: x.severity for x in a}
    assert sev == {"DIRECT_OPERATE": Severity.HIGH, "RECORD_CURRENT_TIME": Severity.LOW}
    pb2, c2 = mb_conn()
    c2.push(True, mb_adu(1, 0, synth.mb_write_single_coil(1, True)))
    c2.push(True, mb_adu(2, 0, synth.mb_read(3, 0, 1)))
    a2 = alerts_for(run(pb2), "QW-C002")
    assert len(a2) == 1 and a2[0].severity is Severity.LOW  # unit 0 is a normal address on many gateways


# ------------------------------------------------------------------------- recon
def sweep_pb(hosts, spacing=0.5, start=1_700_000_000.0):
    pb = PcapBuilder(start_ts=start)
    for i in range(hosts):
        c = Conn(pb, ROGUE, "10.0.1.%d" % (10 + i), 50000 + i, 502)
        c.open()
        c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
        pb.ts += spacing
    return pb


def test_host_sweep_after_warmup():
    cfg = Config(warmup_seconds=0.0)
    r = run(sweep_pb(10), cfg=cfg)
    a = alerts_for(r, "QW-R001")
    assert len(a) == 1 and a[0].severity is Severity.MEDIUM and a[0].mitre == ("T0846",)
    assert len(a[0].details["servers"]) >= 8


def test_sweep_below_threshold_or_inside_warmup_is_quiet():
    assert not alerts_for(run(sweep_pb(7), cfg=Config(warmup_seconds=0.0)), "QW-R001")
    assert not alerts_for(run(sweep_pb(10), cfg=Config(warmup_seconds=3600)), "QW-R001")


def test_sweep_over_a_long_period_is_quiet():
    r = run(sweep_pb(10, spacing=30.0), cfg=Config(warmup_seconds=0.0))
    assert not alerts_for(r, "QW-R001")  # 10 hosts over 300 s: never 8 within the 60 s window


def test_known_paths_are_not_swept():
    flows = [{"master": ROGUE, "server": "10.0.1.0/24", "protocol": "modbus"}]
    r = run(sweep_pb(10), {"allowed_flows": flows}, cfg=Config(warmup_seconds=0.0))
    assert not alerts_for(r, "QW-R001")


def test_syn_only_port_sweep_is_detected():
    pb = PcapBuilder()
    for i in range(10):
        l4 = synth.tcp_segment(ROGUE, "10.0.2.%d" % (i + 1), 40000 + i, 502, 100, 0, synth.SYN)
        pb.ts += 0.2
        pb.add(synth.frame_for(ROGUE, "10.0.2.%d" % (i + 1), 6, l4, "02:00:00:00:66:66", "02:00:00:00:00:02"))
    r = run(pb, cfg=Config(warmup_seconds=0.0))
    assert len(alerts_for(r, "QW-R001")) == 1


def test_unit_id_sweep():
    pb, c = mb_conn(client=ROGUE)
    for unit in range(1, 12):
        c.push(True, mb_adu(unit, unit, synth.mb_read(3, 0, 1)))
    r = run(pb, cfg=Config(warmup_seconds=0.0))
    a = alerts_for(r, "QW-R002")
    assert len(a) == 1 and len(a[0].details["units"]) >= 8
    # a master polling one unit repeatedly is not a sweep
    pb2, c2 = mb_conn()
    for i in range(50):
        c2.push(True, mb_adu(i, 1, synth.mb_read(3, 0, 1)))
    assert not alerts_for(run(pb2, cfg=Config(warmup_seconds=0.0)), "QW-R002")


def test_fingerprinting():
    pb, c = mb_conn()
    c.push(True, mb_adu(1, 1, synth.mb_device_id()))
    c.push(True, mb_adu(2, 1, bytes([17])))
    a = alerts_for(run(pb), "QW-R003")
    assert {x.details["function"] for x in a} == {"ENCAPSULATED_INTERFACE_TRANSPORT", "REPORT_SERVER_ID"}
    assert all(x.severity is Severity.LOW and x.mitre == ("T0888",) for x in a)


# ----------------------------------------------------------------------- hygiene
def test_malformed_traffic_is_aggregated_per_code():
    pb, c = mb_conn()
    for i in range(30):
        c.push(True, mb_adu(i, 1, synth.mb_read(3, 0, 500)))  # bad quantity every time
    c.push(True, b"\xff" * 30)
    r = run(pb)
    a = alerts_for(r, "QW-M001")
    codes = {x.details["code"]: x.count for x in a}
    assert codes["bad_quantity"] == 30 and codes["bad_mbap"] == 1
    assert len(a[0].samples) <= 3


def test_unknown_function_code():
    pb, c = mb_conn()
    c.push(True, mb_adu(1, 1, bytes([90, 1, 2])))
    c.push(False, mb_adu(1, 1, bytes([90, 9])))  # responses don't count
    a = alerts_for(run(pb), "QW-M002")
    assert len(a) == 1 and a[0].details["function_code"] == 90


def test_exception_storm_threshold_and_window():
    def storm(n, gap):
        pb, c = mb_conn(client=ROGUE)
        for i in range(n):
            c.push(True, mb_adu(i, 1, synth.mb_read(3, 0, 1)))
            c.push(False, mb_adu(i, 1, synth.mb_exception(3, 2)))
            pb.ts += gap
        return pb

    assert len(alerts_for(run(storm(12, 0.1)), "QW-E001")) == 1
    assert not alerts_for(run(storm(9, 0.1)), "QW-E001")
    assert not alerts_for(run(storm(12, 5.0)), "QW-E001")


def test_response_without_request():
    pb, c = mb_conn()
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c.push(False, mb_adu(1, 1, synth.mb_resp_registers(3, [1])))
    c.push(False, mb_adu(77, 1, synth.mb_resp_registers(3, [1])))  # nobody asked
    c.push(True, mb_adu(2, 1, synth.mb_read(3, 0, 1)), dt=3.0)       # later traffic proves the grace period passed
    a = alerts_for(run(pb), "QW-S001")
    assert len(a) == 1 and a[0].details["transaction"] == 77 and a[0].mitre == ("T1692.002",)


def test_response_captured_just_before_its_request_is_not_an_alert():
    """TAP/SPAN skew can deliver the response first; only a persistently orphaned response alerts."""
    pb, c = mb_conn()
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c.push(False, mb_adu(1, 1, synth.mb_resp_registers(3, [1])))
    c.push(False, mb_adu(2, 1, synth.mb_resp_registers(3, [1])), dt=0.001)   # response first ...
    c.push(True, mb_adu(2, 1, synth.mb_read(3, 0, 1)), dt=0.001)             # ... then its request
    c.push(True, mb_adu(3, 1, synth.mb_read(3, 0, 1)), dt=5.0)
    assert not alerts_for(run(pb), "QW-S001")


def test_orphan_response_is_reported_at_end_of_capture_only_if_old_enough():
    def build(final_gap):
        pb, c = mb_conn()
        c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
        c.push(False, mb_adu(1, 1, synth.mb_resp_registers(3, [1])))
        c.push(False, mb_adu(9, 1, synth.mb_resp_registers(3, [1])))
        pb.ts += final_gap
        l4 = synth.tcp_segment(MB_PLC, HMI, 502, 41000, c.seq_s, c.seq_c, synth.ACK, b"")
        pb.add(synth.frame_for(MB_PLC, HMI, 6, l4, "02:00:00:00:00:02", "02:00:00:00:00:01"))
        return pb
    assert alerts_for(run(build(5.0)), "QW-S001")        # capture continued long enough: the orphan is real
    assert not alerts_for(run(build(0.01)), "QW-S001")   # capture ended too soon to judge


def test_pairing_grace_is_configurable():
    pb, c = mb_conn()
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c.push(False, mb_adu(1, 1, synth.mb_resp_registers(3, [1])))
    c.push(False, mb_adu(9, 1, synth.mb_resp_registers(3, [1])))
    c.push(True, mb_adu(2, 1, synth.mb_read(3, 0, 1)), dt=0.3)
    assert alerts_for(run(pb, cfg=Config(pairing_grace=0.1)), "QW-S001")
    assert not alerts_for(run(pb, cfg=Config(pairing_grace=10.0)), "QW-S001")


def test_responses_before_any_request_are_not_alerts_midstream_capture():
    pb, c = mb_conn()
    c.push(False, mb_adu(5, 1, synth.mb_resp_registers(3, [1])))  # capture started mid-conversation
    assert not alerts_for(run(pb), "QW-S001")


def test_s7_pairing_uses_pdu_reference():
    pb = PcapBuilder()
    c = Conn(pb, synth.EWS, S7_PLC, 40000, 102)
    c.open()
    c.push(True, synth.s7_read_job(10, [(0x84, 1, 0, 4)]))
    c.push(False, synth.s7_read_ack(10, [b"\x00\x00\x00\x01"]))
    c.push(False, synth.s7_read_ack(11, [b"\x00\x00\x00\x01"]))
    c.push(True, synth.s7_read_job(12, [(0x84, 1, 0, 4)]), dt=3.0)
    a = alerts_for(run(pb), "QW-S001")
    assert len(a) == 1 and a[0].details["transaction"] == 11


def test_role_change_is_flagged_once():
    pb = PcapBuilder()
    c1 = Conn(pb, HMI, MB_PLC, 40000, 502)
    c1.open()
    c1.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c1.push(False, mb_adu(1, 1, synth.mb_resp_registers(3, [1])))
    c2 = Conn(pb, MB_PLC, "10.0.0.77", 40001, 502)  # the PLC now acts as a master
    c2.open()
    c2.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c2.push(True, mb_adu(2, 1, synth.mb_read(3, 0, 1)))
    a = alerts_for(run(pb), "QW-S002")
    assert len(a) == 1 and a[0].details["ip"] == MB_PLC and a[0].mitre == ("T0848",)


def test_dnp3_device_state_flags():
    pb = PcapBuilder()
    c = Conn(pb, SCADA, RTU, 40000, 20000)
    c.open()
    dnp3_send(c, dnp3_app(129, b"", iin=(0x80, 0)), master=False, src=20, dest=3)
    dnp3_send(c, dnp3_app(129, b"", iin=(0x40, 0)), master=False, src=20, dest=3)
    dnp3_send(c, dnp3_app(129, b"", iin=(0x00, 0x20)), master=False, src=20, dest=3)
    dnp3_send(c, dnp3_app(129, b"", iin=(0x80, 0)), master=False, src=20, dest=3)
    r = run(pb)
    a = {x.details["flag"]: x for x in alerts_for(r, "QW-D001")}
    assert a["restart_flag"].severity is Severity.MEDIUM and a["restart_flag"].count == 2
    assert a["restart_flag"].mitre == ("T0816",)
    assert a["device_trouble"].severity is Severity.LOW
    assert a["config_corrupt"].severity is Severity.MEDIUM


def test_nonstandard_port_identified_by_signature():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 40000, 5020)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_read(3, 0, 1)))
    c.push(False, mb_adu(1, 1, synth.mb_resp_registers(3, [1])))
    r = run(pb)
    a = alerts_for(r, "QW-N001")
    assert len(a) == 1 and a[0].details == {"protocol": "modbus", "port": 5020}
    assert a[0].mitre == ("T0885",)
    flow = list(r.inventory.flows.values())[0]
    assert flow.identified_by == "signature" and flow.server == MB_PLC and flow.requests == 1
    assert r.stats.flows_by_signature == 1
    quiet = run(pb, cfg=Config(identify_nonstandard=False))
    assert not quiet.inventory.flows


def test_non_ics_traffic_on_random_ports_is_ignored():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 40000, 8080)
    c.open()
    c.push(True, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    c.push(False, b"HTTP/1.1 200 OK\r\n\r\n")
    r = run(pb)
    assert not r.alerts and not r.inventory.flows and r.stats.ics_packets == 0


# ---------------------------------------------------------------------------- QW-E002
def flood_capture(n, gap, mb_unit=1):
    pb, c = mb_conn(client=ROGUE)
    for i in range(n):
        c.push(True, mb_adu(i & 0xFFFF, mb_unit, synth.mb_read(3, 0, 1)), dt=gap)
    return pb


def test_request_flood_threshold_and_window():
    cfg = Config(flood_threshold=100, flood_window=1.0)
    r = run(flood_capture(150, 0.001), cfg=cfg)
    a = alerts_for(r, "QW-E002")
    assert len(a) == 1 and a[0].severity is Severity.MEDIUM and a[0].mitre == ("T0814",)
    assert a[0].count == 51 and a[0].details["threshold"] == 100          # requests 100..150 each exceed the rate
    assert not alerts_for(run(flood_capture(99, 0.001), cfg=cfg), "QW-E002")           # just below
    assert not alerts_for(run(flood_capture(150, 0.02), cfg=cfg), "QW-E002")           # 50 requests/s: legitimate
    assert not alerts_for(run(flood_capture(150, 0.001), cfg=Config(flood_threshold=0)), "QW-E002")  # disabled


def test_default_threshold_ignores_a_busy_but_legitimate_poller():
    # 55 requests/s was the busiest legitimate poller in the real captures; the default is 500/s
    assert not alerts_for(run(flood_capture(400, 1 / 55.0)), "QW-E002")
    assert alerts_for(run(flood_capture(700, 0.0005)), "QW-E002")


def test_flood_threshold_is_tunable_from_the_policy_and_per_pair():
    pb = flood_capture(60, 0.001)
    assert alerts_for(run(pb, {"thresholds": {"flood_threshold": 50}}), "QW-E002")
    assert not alerts_for(run(pb), "QW-E002")


def test_responses_session_and_malformed_traffic_do_not_count_toward_a_flood():
    pb, c = mb_conn(client=ROGUE)
    for i in range(300):
        c.push(False, mb_adu(i, 1, synth.mb_resp_registers(3, [1])), dt=0.0005)
    assert not alerts_for(run(pb, cfg=Config(flood_threshold=50)), "QW-E002")
