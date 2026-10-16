"""Golden tests for the IEC 104 cause table, command qualifiers and header bit fields (mutation-testing driven)."""

import struct

import pytest

from quietwire import synth
from quietwire.proto.iec104 import COT_NAMES, MAX_OBJECTS_LISTED, Iec104Dissector, parse_asdu
from quietwire.synth import iec104_apdu_i, iec104_asdu, iec104_obj


def one(frame, master=True):
    out = Iec104Dissector().feed_stream(master, frame, False)
    assert len(out) == 1
    return out[0]


def cmd(tid, element, ioa=9, cot=6, **kw):
    return one(iec104_apdu_i(0, 0, iec104_asdu(tid, [iec104_obj(ioa, element)], cot=cot, **kw)))


EXPECTED_COT = {1: "periodic", 2: "background_scan", 3: "spontaneous", 4: "initialized", 5: "request", 6: "activation",
                7: "activation_con", 8: "deactivation", 9: "deactivation_con", 10: "activation_term",
                11: "return_remote", 12: "return_local", 13: "file_transfer", 20: "interrogated_station",
                44: "unknown_type", 45: "unknown_cause", 46: "unknown_ca", 47: "unknown_ioa",
                **{20 + g: "interrogated_group_%d" % g for g in range(1, 17)},
                **{36 + g: "counter_group_%d" % g for g in range(1, 5)}}


def test_cause_of_transmission_names():
    assert COT_NAMES == EXPECTED_COT
    for cause, name in EXPECTED_COT.items():
        m = one(iec104_apdu_i(0, 0, iec104_asdu(100, [iec104_obj(0, bytes([20]))], cot=cause)))
        assert m.details["cause"] == cause and m.details["cause_name"] == name
    assert one(iec104_apdu_i(0, 0, iec104_asdu(100, [iec104_obj(0, bytes([20]))], cot=33 + 17))).details["cause_name"] == "50"


def test_cot_flag_bits_are_independent_of_the_cause_field():
    for neg in (False, True):
        for test in (False, True):
            m = one(iec104_apdu_i(0, 0, iec104_asdu(100, [iec104_obj(0, bytes([20]))], cot=7, negative=neg, test=test)))
            assert (m.details["negative"], m.details["test"], m.details["cause"]) == (neg, test, 7)
    raw = bytearray(iec104_apdu_i(0, 0, iec104_asdu(100, [iec104_obj(0, bytes([20]))], cot=6)))
    raw[8] = 0x46                      # 0x40 (P/N) | cause 6
    m = one(bytes(raw))
    assert m.details["negative"] and not m.details["test"] and m.details["cause"] == 6
    raw[8] = 0x86                      # 0x80 (T) | cause 6
    m = one(bytes(raw))
    assert m.details["test"] and not m.details["negative"] and m.details["cause"] == 6
    raw[8], raw[9] = 0x06, 0x2A        # originator address is a separate octet
    assert one(bytes(raw)).details["originator"] == 0x2A


def test_header_fields_and_message_size():
    frame = iec104_apdu_i(0, 0, iec104_asdu(100, [iec104_obj(0, bytes([20]))], cot=6, ca=0x1234, org=7))
    m = one(frame)
    assert (m.unit, m.details["common_address"], m.details["originator"], m.details["type_id"]) == (0x1234, 0x1234, 7, 100)
    assert m.size == len(frame) and m.details["num_objects"] == 1 and m.details["sq"] is False
    sq = one(iec104_apdu_i(0, 0, iec104_asdu(1, [iec104_obj(5, b"\x01"), b"\x00", b"\x01"], cot=3, sq=True)), master=False)
    assert sq.details["sq"] is True and sq.details["num_objects"] == 3
    assert parse_asdu(frame[6:], True)[0].size == len(frame)


# ---- command qualifier decoding --------------------------------------------------------------------------------
def test_single_and_double_command_bits():
    for tid in (45, 58):
        extra = bytes(7) if tid == 58 else b""
        for byte, state, qual, sel in ((0x00, "off", 0, False), (0x01, "on", 0, False), (0x85, "on", 1, True),
                                       (0x0C, "off", 3, False), (0x7F, "on", 31, False), (0xFE, "off", 31, True)):
            c = cmd(tid, bytes([byte]) + extra).details["controls"][0]
            assert (c["state"], c["qualifier"], c["select"], c["ioa"]) == (state, qual, sel, 9), (tid, hex(byte))
    for tid in (46, 59):
        extra = bytes(7) if tid == 59 else b""
        for byte, state in ((0x00, "invalid_0"), (0x01, "off"), (0x02, "on"), (0x03, "invalid_3")):
            assert cmd(tid, bytes([byte]) + extra).details["controls"][0]["state"] == state
        c = cmd(tid, bytes([0x82]) + extra).details["controls"][0]
        assert c["select"] is True and c["qualifier"] == 0 and c["state"] == "on"
        assert cmd(tid, bytes([0x0A]) + extra).details["controls"][0]["qualifier"] == 2


def test_regulating_step_command_bits():
    for tid in (47, 60):
        extra = bytes(7) if tid == 60 else b""
        for byte, step in ((0x00, "invalid_0"), (0x01, "lower"), (0x02, "higher"), (0x03, "invalid_3")):
            assert cmd(tid, bytes([byte]) + extra).details["controls"][0]["step"] == step
        c = cmd(tid, bytes([0xD1]) + extra).details["controls"][0]
        assert c["select"] is True and c["qualifier"] == 20 and c["step"] == "lower"


def test_setpoint_commands_decode_value_select_and_qualifier():
    for tid, extra in ((48, b""), (61, bytes(7))):
        c = cmd(tid, struct.pack("<hB", -16384, 0x85) + extra).details["controls"][0]
        assert c["value"] == pytest.approx(-0.5) and c["select"] is True and c["ql"] == 5
        c = cmd(tid, struct.pack("<hB", 8192, 0x7F) + extra).details["controls"][0]
        assert c["value"] == pytest.approx(0.25) and c["select"] is False and c["ql"] == 127
    for tid, extra in ((49, b""), (62, bytes(7))):
        c = cmd(tid, struct.pack("<hB", -300, 0x81) + extra).details["controls"][0]
        assert c["value"] == -300 and c["select"] is True and c["ql"] == 1
    for tid, extra in ((50, b""), (63, bytes(7))):
        c = cmd(tid, struct.pack("<fB", 1.5, 0x80) + extra).details["controls"][0]
        assert c["value"] == pytest.approx(1.5) and c["select"] is True and c["ql"] == 0
        c = cmd(tid, struct.pack("<fB", -2.25, 0x03) + extra).details["controls"][0]
        assert c["value"] == pytest.approx(-2.25) and c["select"] is False and c["ql"] == 3
    for tid, extra in ((51, b""), (64, bytes(7))):
        assert cmd(tid, struct.pack("<I", 0x01020304) + extra).details["controls"][0]["bits"] == 0x01020304
    sp = cmd(50, struct.pack("<fB", 1.0, 0))
    assert sp.targets[0].area == "setpoint" and cmd(48, struct.pack("<hB", 1, 0)).targets[0].area == "setpoint"
    assert cmd(51, bytes(4)).targets[0].area == "bitstring" and cmd(45, b"\x01").targets[0].area == "command"
    assert cmd(113, b"\x01").targets[0].area == "parameter" and cmd(110, bytes(3)).targets[0].area == "parameter"
    assert "select" not in cmd(45, bytes([1])).details or cmd(45, bytes([1])).details["select"] is False
    assert cmd(45, bytes([0x81])).details["select"] is True


def test_deactivation_and_other_causes_for_each_command_family():
    for tid, el in ((45, b"\x01"), (46, b"\x02"), (47, b"\x01"), (48, bytes(3)), (49, bytes(3)), (50, bytes(5)),
                    (51, bytes(4))):
        for cause, is_cmd in ((6, True), (8, True), (7, False), (9, False), (10, False), (3, False), (44, False)):
            m = cmd(tid, el, cot=cause)
            assert ("control" in m.kinds and bool(m.targets)) == is_cmd, (tid, cause)
            assert ("monitor" in m.kinds) == (not is_cmd)


def test_object_and_target_lists_are_capped():
    n = MAX_OBJECTS_LISTED + 4
    objs = [iec104_obj(100 + i, bytes([1])) for i in range(n)]
    m = one(iec104_apdu_i(0, 0, iec104_asdu(45, objs)))
    assert len(m.details["ioas"]) == MAX_OBJECTS_LISTED == 8 and len(m.details["controls"]) == 8
    assert len(m.targets) == n and [t.start for t in m.targets] == list(range(100, 100 + n))
    seq = one(iec104_apdu_i(0, 0, iec104_asdu(45, [iec104_obj(100, b"\x01")] + [b"\x01"] * (n - 1), sq=True)))
    assert [(t.start, t.end) for t in seq.targets] == [(100, 100 + n - 1)] and len(seq.details["ioas"]) == 8
    one_obj = one(iec104_apdu_i(0, 0, iec104_asdu(45, [iec104_obj(100, b"\x01")], sq=True)))
    assert [(t.start, t.end) for t in one_obj.targets] == [(100, 100)]


def test_variable_length_file_segments_report_each_object_ioa():
    seg = lambda ioa, data: iec104_obj(ioa, struct.pack("<HBB", 1, 1, len(data)) + data)  # noqa: E731
    m = one(iec104_apdu_i(0, 0, iec104_asdu(125, [seg(3, b"ab"), seg(4, b"xyz"), seg(5, b"")], cot=13)))
    assert not m.anomalies and m.details["ioas"] == [3, 4, 5]
    cut = one(iec104_apdu_i(0, 0, iec104_asdu(125, [seg(3, b"ab")[:-1]], cot=13)))
    assert "bad_asdu_length" in [a.code for a in cut.anomalies]


def test_framing_boundaries():
    d = Iec104Dissector()
    assert d.feed_stream(True, b"\x68", False) == []                     # a lone start byte waits for more
    assert d.feed_stream(True, b"\x04\x07\x00\x00\x00", False)[0].function == "STARTDT_ACT"
    for length, ok in ((3, False), (4, True), (253, True), (254, False)):
        frame = bytes([0x68, length]) + bytes([0x07, 0, 0, 0]) + bytes(max(0, length - 4))
        out = Iec104Dissector().feed_stream(True, frame, False)
        assert (out[0].function != "MALFORMED") == ok or length == 253, length
    many = Iec104Dissector().feed_stream(True, b"\x00\x01" * 100, False)
    assert len([m for m in many if m.function == "MALFORMED"]) <= 8
    d = Iec104Dissector()
    out = d.feed_stream(True, b"\xaa\xbb\x68\x04\x43\x00\x00\x00", False)
    assert [m.function for m in out] == ["MALFORMED", "TESTFR_ACT"]
    d = Iec104Dissector()
    assert [m.function for m in d.feed_stream(True, b"\xaa\x68", False)] == ["MALFORMED"]
    assert d._bufs[True] == bytearray(b"\x68")                           # the trailing 0x68 may begin the next APDU
    assert d.feed_stream(True, b"\x04\x0b\x00\x00\x00", False)[0].function == "STARTDT_CON"


def test_s_and_u_frame_sequence_fields_and_roles():
    s = one(synth.iec104_apdu_s(0x7FFF))
    assert s.details["nr"] == 0x7FFF and s.is_request
    s2 = one(synth.iec104_apdu_s(3), master=False)
    assert not s2.is_request
    i = one(iec104_apdu_i(0x7FFF, 0x7FFE, iec104_asdu(100, [iec104_obj(0, bytes([20]))])))
    assert (i.details["ns"], i.details["nr"]) == (0x7FFF, 0x7FFE)
    assert one(synth.iec104_apdu_u(0x43), master=False).function == "TESTFR_ACT"


def test_remaining_area_and_select_false_cases():
    for tid, el in ((48, bytes(3)), (49, bytes(3)), (50, bytes(5)), (61, bytes(10)), (62, bytes(10)), (63, bytes(12))):
        assert cmd(tid, el).targets[0].area == "setpoint", tid
    for tid in (110, 111, 112, 113):
        el = bytes({110: 3, 111: 3, 112: 5, 113: 1}[tid])
        assert cmd(tid, el).targets[0].area == "parameter", tid
    assert cmd(46, bytes([0x02])).details["controls"][0]["select"] is False
    assert cmd(47, bytes([0x01])).details["controls"][0]["select"] is False
    assert cmd(49, struct.pack("<hB", 5, 0x7F)).details["controls"][0]["select"] is False
    assert cmd(49, struct.pack("<hB", 5, 0x01)).details["controls"][0]["select"] is False
    assert cmd(49, struct.pack("<hB", 5, 0x80)).details["controls"][0]["select"] is True
    assert cmd(47, bytes([0x80])).details["controls"][0]["select"] is True
    assert COT_NAMES[36] == "interrogated_group_16" and COT_NAMES[37] == "counter_group_1"
