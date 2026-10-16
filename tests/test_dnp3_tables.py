"""Golden/behavioural tests for every DNP3 table entry (found weak by mutation testing)."""

import struct

import pytest

from quietwire import synth
from quietwire.proto import dnp3
from quietwire.proto.dnp3 import (APP_FUNCTIONS, IIN1, IIN2, LINK_PRIMARY, LINK_SECONDARY, OBJ_SIZES, PACKED_BITS,
                                  RESPONSE_FCS, Dnp3Dissector, decode_iin, parse_objects)
from quietwire.synth import dnp3_app, dnp3_frames, dnp3_link, dnp3_obj


def messages(app, master=True, src=3, dest=20):
    d = Dnp3Dissector()
    out = []
    for f in dnp3_frames(dest, src, app, master=master):
        out += d.feed_stream(master, f, False)
    return [m for m in out if m.details.get("layer") == "application"]


def codes(m):
    return [a.code for a in m.anomalies]


# ---- names -------------------------------------------------------------------------------------------------
EXPECTED_FUNCTIONS = ["CONFIRM", "READ", "WRITE", "SELECT", "OPERATE", "DIRECT_OPERATE", "DIRECT_OPERATE_NR",
                      "IMMED_FREEZE", "IMMED_FREEZE_NR", "FREEZE_CLEAR", "FREEZE_CLEAR_NR", "FREEZE_AT_TIME",
                      "FREEZE_AT_TIME_NR", "COLD_RESTART", "WARM_RESTART", "INITIALIZE_DATA", "INITIALIZE_APPL",
                      "START_APPL", "STOP_APPL", "SAVE_CONFIG", "ENABLE_UNSOLICITED", "DISABLE_UNSOLICITED",
                      "ASSIGN_CLASS", "DELAY_MEASURE", "RECORD_CURRENT_TIME", "OPEN_FILE", "CLOSE_FILE",
                      "DELETE_FILE", "GET_FILE_INFO", "AUTHENTICATE_FILE", "ABORT_FILE", "ACTIVATE_CONFIG",
                      "AUTHENTICATE_REQ", "AUTH_REQ_NO_ACK"]


def test_application_function_names_follow_ieee_1815():
    assert {k: v for k, v in APP_FUNCTIONS.items() if k < 128} == dict(enumerate(EXPECTED_FUNCTIONS))
    assert {k: v for k, v in APP_FUNCTIONS.items() if k >= 128} == {129: "RESPONSE", 130: "UNSOLICITED_RESPONSE",
                                                                    131: "AUTHENTICATE_RESP"}
    assert RESPONSE_FCS == {129, 130, 131}


def test_link_function_names():
    assert LINK_PRIMARY == {0: "RESET_LINK_STATES", 2: "TEST_LINK_STATES", 3: "CONFIRMED_USER_DATA",
                            4: "UNCONFIRMED_USER_DATA", 9: "REQUEST_LINK_STATUS"}
    assert LINK_SECONDARY == {0: "ACK", 1: "NACK", 11: "LINK_STATUS", 15: "NOT_SUPPORTED"}
    for func, name in LINK_PRIMARY.items():
        if func not in (3, 4):  # 3/4 carry user data
            m = Dnp3Dissector().feed_stream(True, dnp3_link(1, 2, 0xC0 | func), False)[0]
            assert m.function == name and m.function_code == func and m.is_request
    for func, name in LINK_SECONDARY.items():
        m = Dnp3Dissector().feed_stream(False, dnp3_link(2, 1, func), False)[0]
        assert m.function == name and not m.is_request


# ---- behavioural categories ------------------------------------------------------------------------------------
K = frozenset
EXPECTED_KINDS = {
    0: K(), 1: K(["read"]), 2: K(["write"]), 3: K(["control", "write"]), 4: K(["control", "write"]),
    5: K(["control", "write"]), 6: K(["control", "write"]),
    **{fc: K(["maintenance"]) for fc in (7, 8, 9, 10, 11, 12, 20, 21, 22, 23, 24, 32, 33)},
    **{fc: K(["critical"]) for fc in (13, 14, 15, 16, 17, 18, 19, 31)},
    25: K(["file_transfer"]), 26: K(["file_transfer"]), 27: K(["critical", "file_transfer"]),
    28: K(["file_transfer"]), 29: K(["file_transfer"]), 30: K(["file_transfer"]),
}


@pytest.mark.parametrize("fc", range(34))
def test_every_function_code_has_its_documented_behavioural_kinds(fc):
    assert messages(dnp3_app(fc, b""))[0].kinds == EXPECTED_KINDS[fc], APP_FUNCTIONS[fc]


def test_response_function_codes_carry_no_request_kinds_and_are_not_requests():
    for fc in (129, 130, 131):
        m = messages(dnp3_app(fc, b"", iin=(0, 0)), master=False, src=20, dest=3)[0]
        assert not m.is_request and m.kinds == K()


# ---- which functions carry object data -----------------------------------------------------------------------------
DATA_FUNCTIONS = {2, 3, 4, 5, 6, 15, 16, 17, 18, 19, 25, 26, 27, 28, 29, 30, 31, 32, 33, 129, 130, 131}


@pytest.mark.parametrize("fc", sorted(set(range(34)) | {129, 130, 131}))
def test_object_data_is_consumed_only_for_functions_that_carry_it(fc):
    # one g1v2 object (range 0..1, 2 data bytes) followed by a g60v1 header: parses cleanly only if the data is skipped
    body = dnp3_obj(1, 2, 0x00, bytes([0, 1]), b"\x01\x81") + dnp3_obj(60, 1, 0x06)
    resp = fc >= 128
    m = messages(dnp3_app(fc, body, iin=(0, 0) if resp else None), master=not resp,
                 src=20 if resp else 3, dest=3 if resp else 20)[0]
    clean = not codes(m) and len(m.details["objects"]) == 2
    assert clean == (fc in DATA_FUNCTIONS), (fc, codes(m), m.details.get("objects"))


# ---- object size table (literal golden values from IEEE 1815 object definitions; NOT read from the module) ----
def _events(g):
    return {(g, 1): 5, (g, 2): 3, (g, 3): 11, (g, 4): 9, (g, 5): 5, (g, 6): 9, (g, 7): 11, (g, 8): 15}


EXPECTED_SIZES = {
    (1, 2): 1, (2, 1): 1, (2, 2): 7, (2, 3): 3, (3, 2): 1, (4, 1): 1, (4, 2): 7, (4, 3): 3,
    (10, 2): 1, (11, 1): 1, (11, 2): 7, (12, 1): 11, (12, 2): 11, (13, 1): 1, (13, 2): 7,
    (20, 1): 5, (20, 2): 3, (20, 5): 4, (20, 6): 2,
    (21, 1): 5, (21, 2): 3, (21, 5): 11, (21, 6): 9, (21, 9): 4, (21, 10): 2,
    (22, 1): 5, (22, 2): 3, (22, 5): 11, (22, 6): 9,
    (23, 1): 5, (23, 2): 3, (23, 5): 11, (23, 6): 9,
    (30, 1): 5, (30, 2): 3, (30, 3): 4, (30, 4): 2, (30, 5): 5, (30, 6): 9,
    **_events(32),
    (40, 1): 5, (40, 2): 3, (40, 3): 5, (40, 4): 9,
    (41, 1): 5, (41, 2): 3, (41, 3): 5, (41, 4): 9,
    **_events(42), **_events(43),
    (50, 1): 6, (50, 2): 10, (50, 3): 6, (50, 4): 11, (51, 1): 6, (51, 2): 6, (52, 1): 2, (52, 2): 2,
    (60, 1): 0, (60, 2): 0, (60, 3): 0, (60, 4): 0,
}


def test_object_size_table_equals_the_golden_table():
    assert OBJ_SIZES == EXPECTED_SIZES


@pytest.mark.parametrize("gv,size", sorted(EXPECTED_SIZES.items()))
def test_object_size_table_entries_consume_exactly_their_size(gv, size):
    g, v = gv
    data = bytes(range(1, 2 * size + 1)) if size else b""
    body = dnp3_obj(g, v, 0x00, bytes([0, 1]), data) + dnp3_obj(60, 1, 0x06)
    m = messages(dnp3_app(129, body, iin=(0, 0)), master=False, src=20, dest=3)[0]
    assert not codes(m), (gv, codes(m))
    assert [(o["group"], o["variation"]) for o in m.details["objects"]] == [gv, (60, 1)]


@pytest.mark.parametrize("gv,size", sorted((k, s) for k, s in EXPECTED_SIZES.items() if s))
def test_object_size_is_not_larger_or_smaller_than_the_table_says(gv, size):
    g, v = gv
    short = dnp3_obj(g, v, 0x00, bytes([0, 1]), bytes(2 * size - 1))      # one byte short: must overrun
    m = messages(dnp3_app(129, short, iin=(0, 0)), master=False, src=20, dest=3)[0]
    assert "bad_object" in codes(m), gv
    long_ = dnp3_obj(g, v, 0x00, bytes([0, 1]), bytes(2 * size)) + b"\x01"  # a stray byte cannot hide in a bigger object
    m2 = messages(dnp3_app(129, long_, iin=(0, 0)), master=False, src=20, dest=3)[0]
    assert "bad_object" in codes(m2), gv


def test_packed_bit_objects():
    assert PACKED_BITS == {(1, 1): 1, (10, 1): 1, (80, 1): 1, (3, 1): 2}
    for (g, v), bits in PACKED_BITS.items():
        for count in (1, 7, 8, 9, 16, 17):
            need = (count * bits + 7) // 8
            body = dnp3_obj(g, v, 0x00, bytes([0, count - 1]), bytes(need)) + dnp3_obj(60, 1, 0x06)
            m = messages(dnp3_app(129, body, iin=(0, 0)), master=False, src=20, dest=3)[0]
            assert not codes(m) and len(m.details["objects"]) == 2, (g, v, count)
            short = dnp3_obj(g, v, 0x00, bytes([0, count - 1]), bytes(need - 1))
            m2 = messages(dnp3_app(129, short, iin=(0, 0)), master=False, src=20, dest=3)[0]
            assert "bad_object" in codes(m2), (g, v, count)


# ---- qualifier codes ---------------------------------------------------------------------------------------------------
def objs(app_body, fc=129):
    return parse_objects(app_body, 0, True, fc)


def test_range_codes_and_prefix_codes():
    # 1/2/4-byte start-stop ranges, no prefix
    for q, fmt in ((0x00, "<BB"), (0x01, "<HH"), (0x02, "<II")):
        o, _c, _t, an, full = objs(bytes([30, 1, q]) + struct.pack(fmt, 5, 6) + bytes(10))
        assert full and not an and (o[0]["start"], o[0]["stop"], o[0]["count"]) == (5, 6, 2)
    # counts: 1/2/4 bytes
    for q, fmt in ((0x07, "<B"), (0x08, "<H"), (0x09, "<I")):
        o, _c, _t, an, full = objs(bytes([30, 1, q]) + struct.pack(fmt, 2) + bytes(10))
        assert full and not an and o[0]["count"] == 2 and "start" not in o[0]
    # index prefixes 1/2/4 bytes with 1-byte count: each object = prefix + 5 data bytes
    for q, plen in ((0x17, 1), (0x27, 2), (0x37, 4)):
        body = bytes([30, 1, q, 2]) + (bytes(plen) + bytes(5)) * 2
        o, _c, _t, an, full = objs(body)
        assert full and not an and o[0]["count"] == 2
        o2, _c, _t, an2, _f = objs(body[:-1])
        assert an2 and an2[0].code == "bad_object"
    # object-size prefixes (g110 octet strings): prefix 1/2/4 bytes
    for q, plen in ((0x47, 1), (0x57, 2), (0x67, 4)):
        item = (3).to_bytes(plen, "little") + b"abc"
        o, _c, _t, an, full = objs(bytes([110, 3, q, 1]) + item)
        assert full and not an, q
    # "all objects" qualifier carries no data even for data-carrying functions
    o, _c, _t, an, full = objs(bytes([60, 1, 0x06]) + bytes([60, 2, 0x06]))
    assert full and not an and [x["variation"] for x in o] == [1, 2]
    # virtual-address ranges (codes 3,4,5) parse like start/stop
    for q, fmt in ((0x03, "<BB"), (0x04, "<HH"), (0x05, "<II")):
        o, *_ = objs(bytes([60, 1, q]) + struct.pack(fmt, 1, 2), fc=1)
        assert o[0]["start"] == 1


def test_indexed_objects_report_their_own_indices_in_controls():
    # g12v1 with a 1-byte index prefix: two CROBs at indices 7 and 200
    crob = lambda idx: bytes([idx]) + bytes([0x03, 1]) + struct.pack("<IIB", 100, 0, 0)  # noqa: E731
    body = bytes([12, 1, 0x17, 2]) + crob(7) + crob(200)
    o, controls, targets, an, full = parse_objects(body, 0, True, 5)
    assert not an and [c["index"] for c in controls] == [7, 200] and [t.start for t in targets] == [7, 200]
    # start/stop addressing (no prefix): indices follow the range
    rng = bytes([12, 1, 0x00, 4, 5]) + bytes([0x04, 1]) + struct.pack("<IIB", 1, 1, 0)
    rng += (bytes([0x04, 1]) + struct.pack("<IIB", 1, 1, 0)) * 1 + (bytes([0x04, 1]) + struct.pack("<IIB", 1, 1, 0)) * 0
    o, controls, targets, an, full = parse_objects(bytes([12, 1, 0x00, 4, 5]) + (bytes([0x04, 1]) + struct.pack("<IIB", 1, 1, 0)) * 2, 0, True, 5)
    assert [c["index"] for c in controls] == [4, 5]


def test_crob_and_analog_control_decoding_tables():
    for code, name in {0: "NUL", 1: "PULSE_ON", 2: "PULSE_OFF", 3: "LATCH_ON", 4: "LATCH_OFF"}.items():
        body = dnp3_obj(12, 1, 0x17, bytes([1]), bytes([0]) + bytes([code, 1]) + struct.pack("<IIB", 0, 0, 0))
        assert messages(dnp3_app(4, body))[0].details["controls"][0]["op"] == name
    body = dnp3_obj(12, 1, 0x17, bytes([1]), bytes([0]) + bytes([0x0F, 1]) + struct.pack("<IIB", 0, 0, 0))
    assert messages(dnp3_app(4, body))[0].details["controls"][0]["op"] == "UNKNOWN_15"
    for tcc, name in {0: "NUL", 1: "CLOSE", 2: "TRIP", 3: "RESERVED"}.items():
        body = dnp3_obj(12, 1, 0x17, bytes([1]), bytes([0]) + bytes([0x01 | (tcc << 6), 3]) + struct.pack("<IIB", 7, 9, 0))
        c = messages(dnp3_app(4, body))[0].details["controls"][0]
        assert c["tcc"] == name and c["count"] == 3 and c["on_ms"] == 7 and c["off_ms"] == 9
    # control objects are only decoded as controls for SELECT/OPERATE/DIRECT_OPERATE(_NR), not for READ/WRITE
    body = dnp3_obj(12, 1, 0x17, bytes([1]), bytes([0]) + bytes([3, 1]) + struct.pack("<IIB", 0, 0, 0))
    for fc in (3, 4, 5, 6):
        assert "controls" in messages(dnp3_app(fc, body))[0].details
    for fc in (2, 129):
        r = messages(dnp3_app(fc, body, iin=(0, 0) if fc == 129 else None), master=fc != 129,
                     src=20 if fc == 129 else 3, dest=3 if fc == 129 else 20)[0]
        assert "controls" not in r.details


def test_iin_bit_names():
    assert IIN1 == ["BROADCAST", "CLASS_1_EVENTS", "CLASS_2_EVENTS", "CLASS_3_EVENTS", "NEED_TIME", "LOCAL_CONTROL",
                    "DEVICE_TROUBLE", "DEVICE_RESTART"]
    assert IIN2 == ["NO_FUNC_CODE_SUPPORT", "OBJECT_UNKNOWN", "PARAMETER_ERROR", "EVENT_BUFFER_OVERFLOW",
                    "ALREADY_EXECUTING", "CONFIG_CORRUPT", "RESERVED_1", "RESERVED_2"]
    for i in range(8):
        assert decode_iin(1 << i, 0) == [IIN1[i]]
    for i in range(6):
        assert decode_iin(0, 1 << i) == [IIN2[i]]
    assert decode_iin(0, 0xC0) == []                                  # reserved bits are not reported
    m = messages(dnp3_app(129, b"", iin=(0x12, 0x34)), master=False, src=20, dest=3)[0]
    assert m.details["iin_raw"] == 0x1234
    assert m.details["iin"] == ["CLASS_1_EVENTS", "NEED_TIME", "PARAMETER_ERROR", "ALREADY_EXECUTING", "CONFIG_CORRUPT"]
    for flags, kind in (((0, 0x01), "exception"), ((0, 0x02), "exception"), ((0, 0x04), "exception")):
        assert kind in messages(dnp3_app(129, b"", iin=flags), master=False, src=20, dest=3)[0].kinds
    assert "exception" not in messages(dnp3_app(129, b"", iin=(0, 0x08)), master=False, src=20, dest=3)[0].kinds


def test_application_control_bits_and_addresses():
    m = messages(dnp3_app(1, b"", seq=9, fir=True, fin=False, con=True, uns=True))[0]
    d = m.details
    assert (d["app_seq"], d["fir"], d["fin"], d["con"], d["uns"]) == (9, True, False, True, True)
    m = messages(dnp3_app(1, b"", seq=3, fir=False, fin=True, con=False, uns=False))[0]
    assert (m.details["fir"], m.details["fin"], m.details["con"], m.details["uns"]) == (False, True, False, False)
    assert (m.src_addr, m.dst_addr, m.unit) == (3, 20, 20)
    r = messages(dnp3_app(129, b"", iin=(0, 0)), master=False, src=20, dest=3)[0]
    assert (r.src_addr, r.dst_addr, r.unit) == (20, 3, 20)       # the unit is always the outstation address


def test_request_response_pairing_uses_both_addresses_and_the_sequence_number():
    d = Dnp3Dissector()
    for f in dnp3_frames(20, 3, dnp3_app(1, b"", seq=4), master=True):
        d.feed_stream(True, f, False)
    wrong_seq = [m for f in dnp3_frames(3, 20, dnp3_app(129, b"", seq=5, iin=(0, 0)), master=False)
                 for m in d.feed_stream(False, f, False) if m.details.get("layer") == "application"][0]
    assert "request_function" not in wrong_seq.details
    ok = [m for f in dnp3_frames(3, 20, dnp3_app(129, b"", seq=4, iin=(0, 0)), master=False)
          for m in d.feed_stream(False, f, False) if m.details.get("layer") == "application"][0]
    assert ok.details["request_function"] == "READ"
    again = [m for f in dnp3_frames(3, 20, dnp3_app(129, b"", seq=4, iin=(0, 0)), master=False)
             for m in d.feed_stream(False, f, False) if m.details.get("layer") == "application"][0]
    assert "request_function" not in again.details                 # a request is matched only once
    other_pair = Dnp3Dissector()
    for f in dnp3_frames(20, 3, dnp3_app(1, b"", seq=4), master=True):
        other_pair.feed_stream(True, f, False)
    stray = [m for f in dnp3_frames(9, 20, dnp3_app(129, b"", seq=4, iin=(0, 0)), master=False)
             for m in other_pair.feed_stream(False, f, False) if m.details.get("layer") == "application"][0]
    assert "request_function" not in stray.details                 # different master address
    conf = messages(dnp3_app(0, b"", seq=4))[0]
    d2 = Dnp3Dissector()
    for f in dnp3_frames(20, 3, dnp3_app(0, b"", seq=6), master=True):
        d2.feed_stream(True, f, False)
    assert not d2._pending                                         # CONFIRM is never stored as a pending request


def test_time_sync_write_is_not_a_process_write_but_other_groups_are():
    for g in (50, 80):
        assert messages(dnp3_app(2, dnp3_obj(g, 1, 0x00, bytes([0, 0]), bytes(6 if g == 50 else 1))))[0].kinds == {"maintenance"}
    mixed = dnp3_obj(50, 1, 0x00, bytes([0, 0]), bytes(6)) + dnp3_obj(10, 2, 0x00, bytes([0, 0]), b"\x01")
    assert "write" in messages(dnp3_app(2, mixed))[0].kinds


def test_link_frame_bit_fields():
    # DIR/PRM/function bits of the control octet decide the role and the name
    for ctrl, master, prm in ((0xC9, True, True), (0x49, False, True), (0x80 | 0x0B, True, False), (0x0B, False, False)):
        m = Dnp3Dissector().feed_stream(master, dnp3_link(1, 2, ctrl), False)[0]
        assert m.is_request == master and m.details["prm"] == prm and m.details["dir_master"] == master
    # a user-data frame whose DIR bit says "outstation" is a response even if it arrived on the client direction
    d = Dnp3Dissector()
    out = [m for f in dnp3_frames(3, 20, dnp3_app(129, b"", iin=(0, 0)), master=False) for m in d.feed_stream(True, f, False)]
    assert [m.is_request for m in out if m.details.get("layer") == "application"] == [False]
    # lengths: header-only frame needs length >= 5; the user-data length excludes the CRCs
    f = dnp3_frames(1, 2, dnp3_app(1, b""), master=True)[0]
    assert f[2] == 5 + 1 + 2 and len(f) == 10 + (3) + 2


def test_bad_length_and_garbage_accounting():
    head = b"\x05\x64\x04\xc4" + struct.pack("<HH", 1, 2)
    frame = head + struct.pack("<H", synth.dnp_crc(head))
    d = Dnp3Dissector()
    out = d.feed_stream(True, frame + dnp3_link(1, 2, 0xC9), False)
    assert "bad_length" in codes(out[0]) and out[-1].function == "REQUEST_LINK_STATUS"
    d = Dnp3Dissector()
    many = d.feed_stream(True, (b"\x00" * 3 + b"\x05\x64") * 30, False)
    assert len([m for m in many if m.function == "MALFORMED"]) <= 8        # bounded per feed
    d2 = Dnp3Dissector()
    assert d2.feed_stream(True, b"\x00\x00\x05", False) == [] and d2._bufs[True] == bytearray(b"\x05")  # may start a frame
    assert d2.feed_stream(True, bytes([0x64]) + b"\x00" * 8 + b"\xff", False)[0].function == "MALFORMED"
    d3 = Dnp3Dissector()
    assert d3.feed_stream(True, b"\x00\x01\x02", False) == [] and not d3._bufs[True]   # pure noise is discarded
