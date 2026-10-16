import random
import struct

import pytest

from conftest import alerts_for, run
from quietwire import synth
from quietwire.model import Severity
from quietwire.proto.identify import identify, looks_like_iec104
from quietwire.proto.iec104 import (COMMAND_TYPES, TYPES, Iec104Dissector, parse_asdu, type_name)
from quietwire.synth import (Conn, PcapBuilder, iec104_apdu_i, iec104_apdu_s, iec104_apdu_u, iec104_asdu,
                             iec104_clock_sync, iec104_interrogation, iec104_obj, iec104_reset_process,
                             iec104_setpoint_float, iec104_single_command, iec104_single_points)

MASTER, OUTSTATION = "10.0.0.5", "10.0.0.50"


def feed(d, data, master=True, gap=False):
    return d.feed_stream(master, data, gap)


def one(frame, master=True):
    msgs = feed(Iec104Dissector(), frame, master)
    assert len(msgs) == 1, msgs
    return msgs[0]


def codes(m):
    return [a.code for a in m.anomalies]


# -- control formats ----------------------------------------------------------------------------
@pytest.mark.parametrize("raw,name", [("680407000000", "STARTDT_ACT"), ("68040b000000", "STARTDT_CON"),
                                      ("680413000000", "STOPDT_ACT"), ("680423000000", "STOPDT_CON"),
                                      ("680443000000", "TESTFR_ACT"), ("680483000000", "TESTFR_CON")])
def test_u_format_vectors(raw, name):
    m = one(bytes.fromhex(raw))
    assert m.function == name and m.kinds == {"session"} and not m.anomalies and m.details["format"] == "U"
    assert synth.iec104_apdu_u(int(raw[4:6], 16)) == bytes.fromhex(raw)


def test_s_format():
    m = one(iec104_apdu_s(1234))
    assert m.function == "S_FORMAT" and m.details["nr"] == 1234 and m.kinds == {"link"} and not m.anomalies


def test_i_format_sequence_numbers():
    m = one(iec104_apdu_i(300, 20000, iec104_asdu(100, [iec104_obj(0, bytes([20]))])))
    assert (m.details["ns"], m.details["nr"], m.details["format"]) == (300, 20000, "I")


def test_malformed_control_formats():
    assert "bad_u_format" in codes(one(bytes.fromhex("68040f000000")))        # undefined U-format function bits
    assert "bad_s_format" in codes(one(bytes.fromhex("680409000000")))        # extra bits in the S-format octet
    assert "bad_u_format" in codes(one(bytes.fromhex("680407000100")))        # reserved octets set
    assert "bad_s_format" in codes(one(bytes.fromhex("680401000300")))        # reserved bit in S-format
    assert "bad_s_format" in codes(one(bytes.fromhex("68050100000000")))      # payload on S-format
    assert "short_asdu" in codes(one(bytes.fromhex("680400000000")))         # I-format without any ASDU
    assert one(bytes.fromhex("68060000000001ff")).function == "MALFORMED"    # ASDU shorter than its header


# -- commands -----------------------------------------------------------------------------------------
def test_single_command_execute_and_select():
    ex = one(iec104_single_command(5, True))
    assert (ex.function, ex.function_code, ex.unit) == ("C_SC_NA_1", 45, 1) and ex.kinds == {"control", "write"}
    assert ex.details["controls"] == [{"state": "on", "qualifier": 0, "select": False, "ioa": 5}]
    assert [t.to_dict() for t in ex.targets] == [{"area": "command", "start": 5, "end": 5}] and not ex.anomalies
    sel = one(iec104_single_command(70000, False, select=True, qualifier=2))  # 3-byte IOA, short-pulse qualifier
    assert sel.details["select"] is True and sel.details["controls"][0]["state"] == "off"
    assert sel.details["controls"][0]["qualifier"] == 2 and sel.targets[0].start == 70000


def test_double_and_regulating_step_commands():
    m = one(iec104_apdu_i(0, 0, iec104_asdu(46, [iec104_obj(7, bytes([0x02]))])))
    assert m.details["controls"][0]["state"] == "on"
    m = one(iec104_apdu_i(0, 0, iec104_asdu(46, [iec104_obj(7, bytes([0x00]))])))
    assert m.details["controls"][0]["state"] == "invalid_0"
    m = one(iec104_apdu_i(0, 0, iec104_asdu(47, [iec104_obj(8, bytes([0x01]))])))
    assert m.details["controls"][0]["step"] == "lower"


def test_setpoint_variants_and_time_tagged_commands():
    assert one(iec104_setpoint_float(9, 12.5)).details["controls"][0]["value"] == pytest.approx(12.5)
    m = one(iec104_setpoint_float(9, -3.0, select=True))
    assert m.details["select"] is True and m.targets[0].area == "setpoint"
    n = one(iec104_apdu_i(0, 0, iec104_asdu(48, [iec104_obj(1, struct.pack("<hB", 16384, 0))])))
    assert n.details["controls"][0]["value"] == pytest.approx(0.5)
    sc = one(iec104_apdu_i(0, 0, iec104_asdu(49, [iec104_obj(1, struct.pack("<hB", -7, 0))])))
    assert sc.details["controls"][0]["value"] == -7
    tt = one(iec104_apdu_i(0, 0, iec104_asdu(58, [iec104_obj(3, bytes([1]) + bytes(7))])))  # C_SC_TA_1 with CP56Time2a
    assert tt.function == "C_SC_TA_1" and not tt.anomalies and tt.details["controls"][0]["state"] == "on"
    bits = one(iec104_apdu_i(0, 0, iec104_asdu(51, [iec104_obj(4, struct.pack("<I", 0xDEADBEEF))])))
    assert bits.details["controls"][0]["bits"] == 0xDEADBEEF and bits.targets[0].area == "bitstring"


def test_only_activation_and_deactivation_are_commands():
    assert "control" in one(iec104_single_command(5, True, cot=6)).kinds
    assert "control" in one(iec104_single_command(5, False, cot=8)).kinds          # deactivation
    for cot in (7, 9, 10):                                                           # confirmations / termination
        m = one(iec104_single_command(5, True, cot=cot), master=False)
        assert "control" not in m.kinds and "write" not in m.kinds and "monitor" in m.kinds and not m.targets
    neg = one(iec104_apdu_i(0, 0, iec104_asdu(45, [iec104_obj(5, bytes([1]))], cot=7, negative=True)), master=False)
    assert neg.details["negative"] is True and neg.details["cause_name"] == "activation_con"


def test_sequence_of_command_objects_collapses_to_one_target_range():
    objs = [iec104_obj(100, bytes([1])), bytes([0]), bytes([1])]
    m = one(iec104_apdu_i(0, 0, iec104_asdu(45, objs, sq=True)))
    assert [t.to_dict() for t in m.targets] == [{"area": "command", "start": 100, "end": 102}] and not m.anomalies


# -- system / parameter / file --------------------------------------------------------------------------
def test_system_commands():
    gi = one(iec104_interrogation())
    assert gi.function == "C_IC_NA_1" and gi.kinds == {"read"} and gi.details["cause_name"] == "activation"
    assert one(iec104_clock_sync()).kinds == {"maintenance"}
    rp = one(iec104_reset_process())
    assert rp.function == "C_RP_NA_1" and rp.kinds == {"critical"}
    rd = one(iec104_apdu_i(0, 0, iec104_asdu(102, [iec104_obj(10, b"")], cot=5)))
    assert rd.kinds == {"read"} and not rd.anomalies
    ts = one(iec104_apdu_i(0, 0, iec104_asdu(104, [iec104_obj(0, struct.pack("<H", 0x55AA))])))
    assert ts.kinds == {"diagnostic"}
    assert one(iec104_apdu_i(0, 0, iec104_asdu(105, [iec104_obj(0, bytes([1]))], test=True))).details["test"] is True


def test_parameter_types_are_writes_with_parameter_targets():
    m = one(iec104_apdu_i(0, 0, iec104_asdu(112, [iec104_obj(500, struct.pack("<fB", 1.5, 1))])))
    assert m.function == "P_ME_NC_1" and m.kinds == {"write"} and m.targets[0].area == "parameter" and not m.anomalies
    assert one(iec104_apdu_i(0, 0, iec104_asdu(113, [iec104_obj(500, bytes([3]))]))).kinds == {"write"}


def test_file_transfer_types_including_variable_length_segments():
    ready = one(iec104_apdu_i(0, 0, iec104_asdu(120, [iec104_obj(0, bytes(6))], cot=13)))
    assert ready.kinds == {"file_transfer"} and not ready.anomalies
    seg_el = struct.pack("<HBB", 1, 1, 5) + b"hello"      # NOF, NOS, LOS=5, 5 data bytes
    seg = one(iec104_apdu_i(0, 0, iec104_asdu(125, [iec104_obj(0, seg_el)], cot=13)))
    assert seg.function == "F_SG_NA_1" and not seg.anomalies
    two = one(iec104_apdu_i(0, 0, iec104_asdu(125, [iec104_obj(0, struct.pack("<HBB", 1, 1, 2) + b"ab"),
                                                    iec104_obj(0, struct.pack("<HBB", 1, 2, 3) + b"xyz")], cot=13)))
    assert not two.anomalies
    cut = one(iec104_apdu_i(0, 0, iec104_asdu(125, [iec104_obj(0, struct.pack("<HBB", 1, 1, 9) + b"ab")], cot=13)))
    assert "bad_asdu_length" in codes(cut)


# -- structure checks for every defined type (element sizes: IEC 60870-5-101/104 information elements) ----
GOLDEN_SIZES = {
    1: 1, 2: 4, 3: 1, 4: 4, 5: 2, 6: 5, 7: 5, 8: 8, 9: 3, 10: 6, 11: 3, 12: 6, 13: 5, 14: 8, 15: 5, 16: 8, 17: 6,
    18: 7, 19: 7, 20: 5, 21: 2, 30: 8, 31: 8, 32: 9, 33: 12, 34: 10, 35: 10, 36: 12, 37: 12, 38: 10, 39: 11, 40: 11,
    45: 1, 46: 1, 47: 1, 48: 3, 49: 3, 50: 5, 51: 4, 58: 8, 59: 8, 60: 8, 61: 10, 62: 10, 63: 12, 64: 11, 70: 1,
    100: 1, 101: 1, 102: 0, 103: 7, 104: 2, 105: 1, 106: 2, 107: 9, 110: 3, 111: 3, 112: 5, 113: 1,
    120: 6, 121: 7, 122: 4, 123: 5, 124: 4, 126: 13, 127: 16,
}
GOLDEN_NAMES = {
    1: "M_SP_NA_1", 2: "M_SP_TA_1", 3: "M_DP_NA_1", 4: "M_DP_TA_1", 5: "M_ST_NA_1", 6: "M_ST_TA_1", 7: "M_BO_NA_1",
    8: "M_BO_TA_1", 9: "M_ME_NA_1", 10: "M_ME_TA_1", 11: "M_ME_NB_1", 12: "M_ME_TB_1", 13: "M_ME_NC_1",
    14: "M_ME_TC_1", 15: "M_IT_NA_1", 16: "M_IT_TA_1", 17: "M_EP_TA_1", 18: "M_EP_TB_1", 19: "M_EP_TC_1",
    20: "M_PS_NA_1", 21: "M_ME_ND_1", 30: "M_SP_TB_1", 31: "M_DP_TB_1", 32: "M_ST_TB_1", 33: "M_BO_TB_1",
    34: "M_ME_TD_1", 35: "M_ME_TE_1", 36: "M_ME_TF_1", 37: "M_IT_TB_1", 38: "M_EP_TD_1", 39: "M_EP_TE_1",
    40: "M_EP_TF_1", 45: "C_SC_NA_1", 46: "C_DC_NA_1", 47: "C_RC_NA_1", 48: "C_SE_NA_1", 49: "C_SE_NB_1",
    50: "C_SE_NC_1", 51: "C_BO_NA_1", 58: "C_SC_TA_1", 59: "C_DC_TA_1", 60: "C_RC_TA_1", 61: "C_SE_TA_1",
    62: "C_SE_TB_1", 63: "C_SE_TC_1", 64: "C_BO_TA_1", 70: "M_EI_NA_1", 100: "C_IC_NA_1", 101: "C_CI_NA_1",
    102: "C_RD_NA_1", 103: "C_CS_NA_1", 104: "C_TS_NA_1", 105: "C_RP_NA_1", 106: "C_CD_NA_1", 107: "C_TS_TA_1",
    110: "P_ME_NA_1", 111: "P_ME_NB_1", 112: "P_ME_NC_1", 113: "P_AC_NA_1", 120: "F_FR_NA_1", 121: "F_SR_NA_1",
    122: "F_SC_NA_1", 123: "F_LS_NA_1", 124: "F_AF_NA_1", 125: "F_SG_NA_1", 126: "F_DR_TA_1", 127: "F_SC_NB_1",
}


def test_type_table_equals_the_golden_tables():
    assert {t: v[0] for t, v in TYPES.items()} == GOLDEN_NAMES
    assert {t: v[1] for t, v in TYPES.items() if v[1] >= 0} == GOLDEN_SIZES and TYPES[125][1] == -1
    assert COMMAND_TYPES == {45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 61, 62, 63, 64}
    assert {t for t, v in TYPES.items() if v[2] == frozenset(["monitor"])} == {t for t in GOLDEN_NAMES if t < 45 or t == 70}
    kinds = {t: set(v[2]) for t, v in TYPES.items()}
    assert kinds[100] == kinds[101] == kinds[102] == {"read"} and kinds[103] == kinds[106] == {"maintenance"}
    assert kinds[104] == kinds[107] == {"diagnostic"} and kinds[105] == {"critical"}
    assert all(kinds[t] == {"write"} for t in (110, 111, 112, 113))
    assert all(kinds[t] == {"file_transfer"} for t in range(120, 128))


@pytest.mark.parametrize("tid", sorted(GOLDEN_SIZES))
@pytest.mark.parametrize("sq", [False, True])
def test_every_type_tiles_exactly_and_detects_truncation(tid, sq):
    esz = GOLDEN_SIZES[tid]
    n = 3
    objs = ([iec104_obj(1000, bytes(esz))] + [bytes(esz)] * (n - 1)) if sq else [iec104_obj(1000 + i, bytes(esz)) for i in range(n)]
    asdu = iec104_asdu(tid, objs, cot=3 if TYPES[tid][2] == frozenset(["monitor"]) else 6, sq=sq)
    m, count = parse_asdu(asdu, True)
    assert count == n and not m.anomalies, (tid, m.anomalies)
    assert m.function == type_name(tid) and m.function_code == tid
    short, _ = parse_asdu(asdu[:-1], True)
    assert "bad_asdu_length" in codes(short)
    longer, _ = parse_asdu(asdu + b"\x00", True)
    assert "bad_asdu_length" in codes(longer)


def test_monitor_data_sq_and_non_sq():
    m = one(iec104_single_points([10, 11, 12], [1, 0, 1]), master=False)
    assert m.kinds == {"monitor"} and m.details["ioas"] == [10, 11, 12] and not m.anomalies
    q = one(iec104_single_points([10, 11, 12, 13], [1, 0, 1, 1], sq=True), master=False)
    assert q.details["ioas"] == [10, 11, 12, 13] and q.details["sq"] is True and not q.anomalies


def test_unknown_and_private_types_are_flagged():
    m = one(iec104_apdu_i(0, 0, iec104_asdu(200, [iec104_obj(0, b"\x01\x02")])))
    assert m.function == "UNKNOWN_200" and "unknown_function" in m.kinds and not m.anomalies
    assert type_name(24) == "UNKNOWN_24"


def test_header_anomalies():
    assert "bad_cot" in codes(one(iec104_apdu_i(0, 0, iec104_asdu(100, [iec104_obj(0, bytes([20]))], cot=0))))
    assert "zero_objects" in codes(one(iec104_apdu_i(0, 0, iec104_asdu(100, [], cot=6))))
    m = one(iec104_apdu_i(0, 0, iec104_asdu(103, [iec104_obj(0, bytes(7))], ca=0xFFFF)))
    assert m.broadcast and m.unit == 0xFFFF
    assert not one(iec104_apdu_i(0, 0, iec104_asdu(103, [iec104_obj(0, bytes(7))], ca=0xFFFF)), master=False).broadcast


# -- framing ----------------------------------------------------------------------------------------------
def test_pipelined_split_and_byte_at_a_time():
    blob = iec104_apdu_u(0x07) + iec104_single_command(5, True) + iec104_interrogation() + iec104_apdu_s(3)
    out = feed(Iec104Dissector(), blob)
    assert [m.function for m in out] == ["STARTDT_ACT", "C_SC_NA_1", "C_IC_NA_1", "S_FORMAT"]
    d = Iec104Dissector()
    got = []
    for i in range(len(blob)):
        got += feed(d, blob[i : i + 1])
    assert [m.function for m in got] == [m.function for m in out]


def test_resync_after_garbage_and_after_gap():
    good = iec104_single_command(5, True)
    out = feed(Iec104Dissector(), b"\x00\x01\x02" + good)
    assert out[0].function == "MALFORMED" and out[-1].function == "C_SC_NA_1"
    d = Iec104Dissector()
    feed(d, good[:7])
    out = feed(d, good, gap=True)
    assert [m.function for m in out] == ["C_SC_NA_1"]
    assert feed(Iec104Dissector(), b"\x68\x02\x00\x00")[0].function == "MALFORMED"   # length < 4
    d = Iec104Dissector()
    assert [m.function for m in feed(d, b"\xff\xfe\x68")] == ["MALFORMED"] and feed(d, good[1:])[0].function == "C_SC_NA_1"


def test_garbage_never_raises_and_buffers_stay_bounded():
    rng = random.Random(3)
    d = Iec104Dissector()
    good = iec104_single_command(5, True)
    for _ in range(500):
        blob = bytearray(rng.choice([good, bytes(rng.randrange(256) for _ in range(rng.randrange(1, 300)))]))
        if rng.random() < 0.6 and blob:
            blob[rng.randrange(len(blob))] = rng.randrange(256)
        feed(d, bytes(blob), master=rng.random() < 0.5, gap=rng.random() < 0.05)
        assert len(d._bufs[True]) < 300 and len(d._bufs[False]) < 300


# -- identification -----------------------------------------------------------------------------------------
def test_identification_on_nonstandard_ports():
    assert identify(iec104_apdu_u(0x07)) == "iec104" and identify(iec104_single_command(5, True)) == "iec104"
    assert identify(iec104_apdu_s(0)) == "iec104"
    assert not looks_like_iec104(b"\x68\x04\x09\x00\x00\x00")                 # undefined U code
    assert not looks_like_iec104(iec104_apdu_i(0, 0, iec104_asdu(24, [iec104_obj(0, b"\x00")])))  # undefined type
    assert not looks_like_iec104(iec104_single_command(5, True)[:-1])          # incomplete APDU
    assert not looks_like_iec104(b"\x68\x03\x00\x00\x00")


# -- engine, rules, policy ---------------------------------------------------------------------------------------
def capture(*payloads, server=OUTSTATION, port=2404, client=MASTER):
    pb = PcapBuilder()
    c = Conn(pb, client, server, 40500, port)
    c.open()
    for from_client, data in payloads:
        c.push(from_client, data)
    return pb


def test_normal_operation_is_quiet_under_a_matching_policy():
    pol = {"writers": {"iec104": [MASTER]}, "allowed_flows": [{"master": MASTER, "server": OUTSTATION, "protocol": "iec104"}],
           "write_ranges": [{"server": OUTSTATION, "protocol": "iec104", "area": "command", "start": 0, "end": 99}]}
    pb = capture((True, iec104_apdu_u(0x07)), (False, iec104_apdu_u(0x0B)), (True, iec104_interrogation()),
                 (False, iec104_single_points([1, 2], [1, 0])), (True, iec104_clock_sync()),
                 (True, iec104_single_command(5, True, select=True)), (True, iec104_single_command(5, True)),
                 (False, iec104_single_command(5, True, cot=7)), (True, iec104_apdu_u(0x43)), (False, iec104_apdu_u(0x83)))
    r = run(pb, pol)
    assert r.alerts == [] and r.stats.messages["iec104"] == 10 and not r.stats.malformed


def test_unauthorised_and_out_of_range_commands():
    pb = capture((True, iec104_single_command(5, True)), (True, iec104_single_command(5000, True, select=True)),
                 (True, iec104_setpoint_float(7, 1.0)))
    pol = {"writers": {"iec104": ["10.9.9.9"]},
           "write_ranges": [{"server": OUTSTATION, "protocol": "iec104", "area": "command", "start": 0, "end": 99}]}
    r = run(pb, pol)
    w1 = alerts_for(r, "QW-W001")
    assert len(w1) == 2 and {a.details["function"] for a in w1} == {"C_SC_NA_1", "C_SE_NC_1"}
    w3 = alerts_for(r, "QW-W003")
    assert {(a.details["violations"][0]["area"], a.details["violations"][0]["start"]) for a in w3} == \
        {("command", 5000), ("setpoint", 7)}
    assert alerts_for(run(pb), "QW-W002")  # visibility alert without a writer policy


def test_reset_process_is_critical_but_not_for_an_engineering_station():
    pb = capture((True, iec104_reset_process()))
    a = alerts_for(run(pb), "QW-C001")
    assert len(a) == 1 and a[0].severity is Severity.HIGH and a[0].mitre == ("T0816",)
    assert not alerts_for(run(pb, {"engineering_stations": [MASTER]}), "QW-C001")


def test_broadcast_command_and_routine_broadcast_interrogation():
    pb = capture((True, iec104_apdu_i(0, 0, iec104_asdu(45, [iec104_obj(5, bytes([1]))], ca=0xFFFF))),
                 (True, iec104_interrogation(ca=0xFFFF)), (True, iec104_clock_sync(ca=0xFFFF)))
    a = alerts_for(run(pb), "QW-C002")
    assert len(a) == 1 and a[0].severity is Severity.HIGH and a[0].details["function"] == "C_SC_NA_1"


def test_common_address_sweep_and_inventory():
    pb = capture(*[(True, iec104_interrogation(ca=ca, ns=0)) for ca in range(1, 12)])
    from quietwire.detect.engine import Config
    r = run(pb, cfg=Config(warmup_seconds=0))
    assert alerts_for(r, "QW-R002")
    assert r.inventory.assets[OUTSTATION].iec104_common_addresses == set(range(1, 12))
    assert r.inventory.assets[OUTSTATION].to_dict()["iec104_common_addresses"] == list(range(1, 12))


def test_nonstandard_port_roles_and_malformed_aggregation():
    pb = capture((True, iec104_apdu_u(0x07)), (False, iec104_apdu_u(0x0B)), (True, iec104_single_command(5, True)),
                 port=12404)
    r = run(pb)
    n1 = alerts_for(r, "QW-N001")
    assert len(n1) == 1 and n1[0].details["protocol"] == "iec104"
    flow = list(r.inventory.flows.values())[0]
    assert flow.master == MASTER and flow.server == OUTSTATION and flow.requests == 2 and flow.responses == 1
    pb2 = capture(*[(True, b"\x00\x01\x02\x03\x04") for _ in range(10)])
    assert alerts_for(run(pb2), "QW-M001")


def test_unknown_private_type_triggers_m002():
    pb = capture((True, iec104_apdu_i(0, 0, iec104_asdu(200, [iec104_obj(0, b"\x01")]))))
    assert alerts_for(run(pb), "QW-M002")


def test_baseline_learns_iec104_writers_and_ranges():
    from quietwire.detect.policy import build_baseline, parse_policy
    pb = capture((True, iec104_single_command(5, True)), (True, iec104_single_command(6, False)),
                 (True, iec104_setpoint_float(30, 2.0)))
    doc = build_baseline(run(pb).inventory)
    assert doc["writers"]["iec104"] == [MASTER]
    areas = {w["area"]: (w["start"], w["end"]) for w in doc["write_ranges"]}
    assert areas == {"command": (5, 6), "setpoint": (30, 30)}
    assert run(pb, parse_policy(doc)).alerts == []
