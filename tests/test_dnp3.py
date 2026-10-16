import random
import struct

import pytest

from quietwire import synth
from quietwire.proto.dnp3 import Dnp3Dissector, decode_iin, parse_objects
from quietwire.synth import dnp3_app, dnp3_crob, dnp3_frames, dnp3_link, dnp3_obj


def feed(d, data, master=True, gap=False):
    return d.feed_stream(master, data, gap)


def app_msgs(msgs):
    return [m for m in msgs if m.details.get("layer") == "application"]


def send(d, app, master=True, src=3, dest=20, tseq=0):
    out = []
    for f in dnp3_frames(dest, src, app, master=master, tseq=tseq):
        out += feed(d, f, master)
    return out


def codes(m):
    return [a.code for a in m.anomalies]


# -- published example frame ------------------------------------------------------------
def test_link_layer_example_frame():
    # DNP3 primer example: RESET_LINK_STATES, master 1024 -> outstation 1, header CRC E9 21
    msgs = feed(Dnp3Dissector(), bytes.fromhex("056405c001000004e921"))
    assert len(msgs) == 1
    m = msgs[0]
    assert (m.function, m.is_request, m.src_addr, m.dst_addr) == ("RESET_LINK_STATES", True, 1024, 1)
    assert m.kinds == {"link"} and not m.anomalies


def test_secondary_link_frames_and_unknown_function():
    ack = dnp3_link(1024, 1, 0x00)  # secondary, function 0 = ACK, from outstation
    m = feed(Dnp3Dissector(), ack, master=False)[0]
    assert m.function == "ACK" and not m.is_request
    status = dnp3_link(1024, 1, 0x0B)
    assert feed(Dnp3Dissector(), status, master=False)[0].function == "LINK_STATUS"
    weird = dnp3_link(1, 2, 0xC0 | 0x07)  # primary function 7 is undefined
    assert "unknown_link_function" in codes(feed(Dnp3Dissector(), weird)[0])


# -- application layer ---------------------------------------------------------------------------
def test_class_poll_read_request():
    d = Dnp3Dissector()
    msgs = app_msgs(send(d, dnp3_app(1, dnp3_obj(60, 2, 0x06) + dnp3_obj(60, 3, 0x06) + dnp3_obj(60, 1, 0x06), seq=5)))
    m = msgs[0]
    assert m.function == "READ" and m.is_request and m.kinds == {"read"} and not m.anomalies
    assert [(o["group"], o["variation"]) for o in m.details["objects"]] == [(60, 2), (60, 3), (60, 1)]
    assert m.details["app_seq"] == 5 and m.unit == 20 and not m.broadcast


def test_response_with_iin_and_data_objects_and_pairing():
    d = Dnp3Dissector()
    send(d, dnp3_app(1, dnp3_obj(1, 2, 0x00, bytes([0, 2]), bytes([0x01, 0x81, 0x01])), seq=3))
    resp = dnp3_app(129, dnp3_obj(1, 2, 0x00, bytes([0, 2]), bytes([0x01, 0x81, 0x01])), seq=3, iin=(0x02, 0x00))
    m = app_msgs(send(d, resp, master=False, src=20, dest=3))[0]
    assert m.function == "RESPONSE" and not m.is_request and not m.anomalies
    assert m.details["iin"] == ["CLASS_1_EVENTS"] and m.details["request_function"] == "READ"
    assert m.details["objects"][0]["start"] == 0 and m.details["objects"][0]["stop"] == 2


def test_iin_flags_map_to_kinds():
    d = Dnp3Dissector()
    m = app_msgs(send(d, dnp3_app(129, b"", iin=(0x80 | 0x40 | 0x20, 0x02 | 0x20)), master=False, src=20, dest=3))[0]
    assert {"restart_flag", "device_trouble", "local_control", "config_corrupt", "exception"} <= m.kinds
    assert "DEVICE_RESTART" in m.details["iin"] and "OBJECT_UNKNOWN" in m.details["iin"]
    assert decode_iin(0, 0) == []
    assert decode_iin(0x01, 0x01) == ["BROADCAST", "NO_FUNC_CODE_SUPPORT"]


@pytest.mark.parametrize("fc,name,kind", [
    (2, "WRITE", "write"), (3, "SELECT", "control"), (4, "OPERATE", "control"), (5, "DIRECT_OPERATE", "control"),
    (6, "DIRECT_OPERATE_NR", "control"), (13, "COLD_RESTART", "critical"), (14, "WARM_RESTART", "critical"),
    (15, "INITIALIZE_DATA", "critical"), (18, "STOP_APPL", "critical"), (27, "DELETE_FILE", "critical"),
    (20, "ENABLE_UNSOLICITED", "maintenance"), (25, "OPEN_FILE", "file_transfer"),
])
def test_function_code_kinds(fc, name, kind):
    d = Dnp3Dissector()
    m = app_msgs(send(d, dnp3_app(fc, b"")))[0]
    assert m.function == name and kind in m.kinds


def test_unknown_function_code_flagged():
    m = app_msgs(send(Dnp3Dissector(), dnp3_app(99, b"")))[0]
    assert m.function == "UNKNOWN_99" and "unknown_function" in m.kinds
    r = app_msgs(send(Dnp3Dissector(), dnp3_app(140, b""), master=False, src=20, dest=3))[0]
    assert "unknown_response_code" in codes(r)


def test_crob_control_decode():
    # latch-off / trip on index 4 and pulse-on / close on index 9
    objs = dnp3_obj(12, 1, 0x17, bytes([2]),
                    bytes([4]) + bytes([0x04 | (2 << 6), 1]) + struct.pack("<IIB", 500, 0, 0)
                    + bytes([9]) + bytes([0x01 | (1 << 6), 1]) + struct.pack("<IIB", 100, 100, 0))
    m = app_msgs(send(Dnp3Dissector(), dnp3_app(4, objs)))[0]
    assert not m.anomalies
    ctl = m.details["controls"]
    assert ctl[0] == {"index": 4, "op": "LATCH_OFF", "tcc": "TRIP", "count": 1, "on_ms": 500, "off_ms": 0}
    assert ctl[1]["op"] == "PULSE_ON" and ctl[1]["tcc"] == "CLOSE" and ctl[1]["off_ms"] == 100
    assert [(t.area, t.start) for t in m.targets] == [("binary_output", 4), ("binary_output", 9)]


def test_analog_output_variations():
    for var, fmt, val in ((1, "<i", -5), (2, "<h", 300), (3, "<f", 1.5), (4, "<d", 2.25)):
        body = struct.pack(fmt, val) + b"\x00"
        objs = dnp3_obj(41, var, 0x17, bytes([1]), bytes([7]) + body)
        m = app_msgs(send(Dnp3Dissector(), dnp3_app(5, objs)))[0]
        assert not m.anomalies, (var, m.anomalies)
        assert m.details["controls"][0]["analog_value"] == pytest.approx(val)
        assert m.targets[0].area == "analog_output" and m.targets[0].start == 7


def test_time_sync_write_is_maintenance_not_a_process_write():
    objs = dnp3_obj(50, 1, 0x07, bytes([1]), b"\x00" * 6)
    m = app_msgs(send(Dnp3Dissector(), dnp3_app(2, objs)))[0]
    assert "write" not in m.kinds and "maintenance" in m.kinds


def test_free_format_object_in_read_carries_data():
    # regression (real capture dnp3_file_read.pcap): g70v5 file transport in a READ request
    objs = dnp3_obj(70, 5, 0x5B, bytes([1]), struct.pack("<H", 8) + bytes.fromhex("78563412") + b"\x00\x00\x00\x00")
    m = app_msgs(send(Dnp3Dissector(), dnp3_app(1, objs)))[0]
    assert not m.anomalies and m.details["objects"][0]["group"] == 70


def test_bad_qualifier_range_and_prefix_are_reported():
    # reserved range code 0xD (real capture quirk: ndpi/Zeek dnp3.pcap)
    m = app_msgs(send(Dnp3Dissector(), dnp3_app(21, dnp3_obj(60, 2, 0x06) + dnp3_obj(60, 4, 0xED))))[0]
    assert "bad_object" in codes(m) and m.function == "DISABLE_UNSOLICITED"
    m = app_msgs(send(Dnp3Dissector(), dnp3_app(1, dnp3_obj(1, 2, 0x78))))[0]
    assert "bad_object" in codes(m)
    m = app_msgs(send(Dnp3Dissector(), dnp3_app(1, dnp3_obj(1, 2, 0x01, bytes([5, 0, 2, 0])))))[0]
    assert "bad_object" in codes(m)  # stop < start


def test_truncated_object_data_is_reported():
    objs = dnp3_obj(12, 1, 0x17, bytes([3]), b"\x01\x03\x01" + b"\x00" * 5)  # claims 3 objects, carries <1
    m = app_msgs(send(Dnp3Dissector(), dnp3_app(5, objs)))[0]
    assert "bad_object" in codes(m)


def test_unknown_object_without_size_is_partially_parsed_not_an_error():
    objs = dnp3_obj(99, 9, 0x00, bytes([0, 1]), b"\x01\x02\x03\x04")
    m = app_msgs(send(Dnp3Dissector(), dnp3_app(129, objs, iin=(0, 0)), master=False, src=20, dest=3))[0]
    assert not m.anomalies and m.details.get("objects_partially_parsed")


def test_packed_bit_objects_consume_correct_length():
    objs = dnp3_obj(1, 1, 0x00, bytes([0, 9]), b"\xff\x01") + dnp3_obj(10, 1, 0x00, bytes([0, 2]), b"\x05")
    m = app_msgs(send(Dnp3Dissector(), dnp3_app(129, objs, iin=(0, 0)), master=False, src=20, dest=3))[0]
    assert not m.anomalies and len(m.details["objects"]) == 2


def test_broadcast_destination_flagged():
    d = Dnp3Dissector()
    m = app_msgs(send(d, dnp3_app(13), dest=0xFFFF, src=7))[0]
    assert m.broadcast and m.dst_addr == 0xFFFF
    m2 = app_msgs(send(d, dnp3_app(13), dest=0xFFFC, src=7))[0]
    assert not m2.broadcast  # 0xFFFC is the self-address, not a broadcast


# -- transport layer -----------------------------------------------------------------------
def test_multi_frame_fragment_reassembly():
    d = Dnp3Dissector()
    payload = dnp3_obj(110, 200, 0x5B, bytes([1]), struct.pack("<H", 600) + bytes(600))
    frames = dnp3_frames(20, 3, dnp3_app(2, payload), master=True)
    assert len(frames) >= 3
    out = []
    for f in frames:
        out += feed(d, f)
    msgs = app_msgs(out)
    assert len(msgs) == 1 and msgs[0].function == "WRITE"


def test_transport_header_bit_order_regression():
    # IEEE 1815 transport header: bit7 = FIN, bit6 = FIR.  0xC1 = FIR+FIN, seq 1
    frame = dnp3_link(20, 3, 0xC4, bytes([0xC1, 0xC0 | 5, 0x01, 0x3C, 0x02, 0x06]))
    m = app_msgs(feed(Dnp3Dissector(), frame))[0]
    assert m.function == "READ"
    # 0x42 = FIR only (first of several), 0x85 = FIN only (last): a two-frame fragment
    d = Dnp3Dissector()
    assert app_msgs(feed(d, dnp3_link(20, 3, 0xC4, bytes([0x42]) + bytes([0xC1, 0x02, 0xAA])))) == []
    out = app_msgs(feed(d, dnp3_link(20, 3, 0xC4, bytes([0x83]) + b"\xbb\xcc")))
    assert len(out) == 1 and out[0].function == "WRITE"


def test_transport_errors():
    d = Dnp3Dissector()
    orphan = dnp3_link(20, 3, 0xC4, bytes([0x05, 1, 2, 3]))  # neither FIR nor an open fragment
    assert codes(feed(d, orphan)[0]) == ["orphan_segment"]
    d = Dnp3Dissector()
    first = dnp3_link(20, 3, 0xC4, bytes([0x40 | 0, 0xC1, 0x01]))
    skip = dnp3_link(20, 3, 0xC4, bytes([0x80 | 5, 9, 9]))  # sequence 5 after 0
    feed(d, first)
    assert codes(feed(d, skip)[0]) == ["transport_sequence"]
    d = Dnp3Dissector()
    feed(d, first)
    out = feed(d, first)  # second FIR while the first fragment is unfinished
    assert "unfinished_fragment" in [c for m in out for c in codes(m)]


def test_oversize_fragment_is_dropped():
    d = Dnp3Dissector()
    out = []
    seq = 0
    th = 0x40
    for _ in range(40):
        out += feed(d, dnp3_link(20, 3, 0xC4, bytes([th | seq]) + b"\x00" * 249))
        th = 0
        seq = (seq + 1) & 0x3F
    assert any("fragment_too_large" in codes(m) for m in out)
    assert not d._asm


def test_independent_reassembly_per_address_pair_and_direction():
    d = Dnp3Dissector()
    a = dnp3_link(20, 3, 0xC4, bytes([0x40, 0xC1, 0x02, 0x11]))
    b = dnp3_link(21, 3, 0xC4, bytes([0x40, 0xC1, 0x01, 0x22]))
    feed(d, a)
    feed(d, b)
    ea = feed(d, dnp3_link(20, 3, 0xC4, bytes([0x81, 0x33])))
    eb = feed(d, dnp3_link(21, 3, 0xC4, bytes([0x81, 0x44])))
    assert [m.function for m in app_msgs(ea)] == ["WRITE"] and [m.function for m in app_msgs(eb)] == ["READ"]


# -- link framing robustness -----------------------------------------------------------------
def test_corrupted_header_crc_resyncs_to_next_frame():
    good = dnp3_frames(20, 3, dnp3_app(1, dnp3_obj(60, 1, 0x06)), master=True)[0]
    bad = bytearray(good)
    bad[8] ^= 0xFF
    out = feed(Dnp3Dissector(), bytes(bad) + good)
    assert [m.function for m in out].count("READ") == 1
    assert any("bad_header_crc" in codes(m) for m in out)


def test_corrupted_data_block_crc_is_reported_and_dropped():
    good = dnp3_frames(20, 3, dnp3_app(1, dnp3_obj(60, 1, 0x06)), master=True)[0]
    bad = bytearray(good)
    bad[-1] ^= 0x55
    out = feed(Dnp3Dissector(), bytes(bad))
    assert [codes(m) for m in out] == [["bad_data_crc"]]


def test_garbage_before_frame_and_byte_at_a_time_feed():
    good = dnp3_frames(20, 3, dnp3_app(1, dnp3_obj(60, 1, 0x06)), master=True)[0]
    d = Dnp3Dissector()
    out = feed(d, b"\x00\x01\x02" + good)
    assert any("garbage" in codes(m) for m in out) and any(m.function == "READ" for m in out)
    d = Dnp3Dissector()
    out = []
    for i in range(len(good)):
        out += feed(d, good[i : i + 1])
    assert [m.function for m in out] == ["READ"]


def test_length_field_below_minimum_rejected():
    head = b"\x05\x64\x04\xc4" + struct.pack("<HH", 1, 2)
    frame = head + struct.pack("<H", synth.dnp_crc(head))
    out = feed(Dnp3Dissector(), frame)
    assert "bad_length" in codes(out[0])


def test_user_data_on_link_function_without_data_service():
    frame = dnp3_link(20, 3, 0xC0 | 0x09, b"\x01\x02")  # REQUEST_LINK_STATUS carrying data
    assert "unexpected_user_data" in codes(feed(Dnp3Dissector(), frame)[0])


def test_gap_flushes_partial_state():
    d = Dnp3Dissector()
    f = dnp3_frames(20, 3, dnp3_app(1, dnp3_obj(60, 1, 0x06)), master=True)[0]
    feed(d, f[:7])
    out = feed(d, f, gap=True)
    assert [m.function for m in out] == ["READ"]


def test_udp_fragment_spanning_datagrams_keeps_transport_state():
    d = Dnp3Dissector()
    payload = dnp3_obj(110, 200, 0x5B, bytes([1]), struct.pack("<H", 600) + bytes(600))
    frames = dnp3_frames(20, 3, dnp3_app(2, payload), master=True)
    out = []
    for f in frames:
        out += d.feed_datagram(True, f)
    assert [m.function for m in app_msgs(out)] == ["WRITE"]


def test_pending_request_table_is_bounded():
    d = Dnp3Dissector(max_pending=8)
    for i in range(50):
        send(d, dnp3_app(1, dnp3_obj(60, 1, 0x06), seq=i % 16), src=100 + i)
    assert len(d._pending) <= 8


def test_parse_objects_direct_error_paths():
    assert parse_objects(b"\x01\x02", 0, False, 1)[3][0].code == "bad_object"
    assert parse_objects(bytes([1, 2, 0x00, 1]), 0, False, 1)[3][0].code == "bad_object"
    assert parse_objects(bytes([1, 2, 0x07]), 0, False, 1)[3][0].code == "bad_object"
    assert parse_objects(bytes([60, 1, 0x06]), 0, False, 1)[4] is True


def test_random_garbage_never_raises():
    rng = random.Random(11)
    d = Dnp3Dissector()
    good = dnp3_frames(20, 3, dnp3_app(1, dnp3_obj(60, 1, 0x06)), master=True)[0]
    for _ in range(400):
        blob = bytearray(rng.choice([good, bytes(rng.randrange(256) for _ in range(rng.randrange(1, 80)))]))
        if rng.random() < 0.5 and blob:
            blob[rng.randrange(len(blob))] = rng.randrange(256)
        feed(d, bytes(blob), master=rng.random() < 0.5, gap=rng.random() < 0.05)
        assert len(d._bufs[True]) < 400 and len(d._bufs[False]) < 400
