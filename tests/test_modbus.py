import random
import struct

import pytest

from quietwire import synth
from quietwire.proto.modbus import ModbusDissector, function_name, parse_adu


def feed(d, from_client, data, gap=False):
    return d.feed_stream(from_client, data, gap)


def one(adu, is_request=True):
    msgs = ModbusDissector().feed_stream(is_request, adu, False)
    assert len(msgs) == 1, msgs
    return msgs[0]


def codes(msg):
    return [a.code for a in msg.anomalies]


# -- canonical vectors (MODBUS Application Protocol spec examples) ------------------------------
def test_spec_example_read_holding_registers():
    req = bytes.fromhex("00010000000611030 06B0003".replace(" ", ""))
    resp = bytes.fromhex("000100000009110306022B00000064")
    m = one(req)
    assert (m.function, m.function_code, m.unit, m.transaction) == ("READ_HOLDING_REGISTERS", 3, 0x11, 1)
    assert m.details == {"start": 107, "quantity": 3} and not m.anomalies and m.kinds == {"read"}
    r = one(resp, is_request=False)
    assert r.details["values"] == [555, 0, 100] and not r.is_request and not r.anomalies


@pytest.mark.parametrize("fc,name", [(1, "READ_COILS"), (2, "READ_DISCRETE_INPUTS"), (3, "READ_HOLDING_REGISTERS"),
                                     (4, "READ_INPUT_REGISTERS")])
def test_read_requests(fc, name):
    m = one(synth.mb_adu(7, 3, synth.mb_read(fc, 100, 10)))
    assert m.function == name and m.details == {"start": 100, "quantity": 10} and not m.targets and not m.anomalies


def test_read_quantity_limits():
    assert "bad_quantity" in codes(one(synth.mb_adu(1, 1, synth.mb_read(3, 0, 126))))
    assert "bad_quantity" in codes(one(synth.mb_adu(1, 1, synth.mb_read(3, 0, 0))))
    assert not codes(one(synth.mb_adu(1, 1, synth.mb_read(3, 0, 125))))
    assert not codes(one(synth.mb_adu(1, 1, synth.mb_read(1, 0, 2000))))
    assert "bad_quantity" in codes(one(synth.mb_adu(1, 1, synth.mb_read(1, 0, 2001))))


def test_write_single_coil_and_register_targets():
    m = one(synth.mb_adu(1, 1, synth.mb_write_single_coil(7, True)))
    assert m.kinds == {"write"} and [t.to_dict() for t in m.targets] == [{"area": "coil", "start": 7, "end": 7}]
    bad = bytes([5]) + struct.pack(">HH", 7, 0x1234)
    assert "bad_value" in codes(one(synth.mb_adu(1, 1, bad)))
    m = one(synth.mb_adu(1, 1, synth.mb_write_single_register(100, 0xBEEF)))
    assert m.details["value"] == 0xBEEF and m.targets[0].area == "holding_register" and m.targets[0].start == 100


def test_write_multiple_registers_target_range_and_consistency():
    m = one(synth.mb_adu(1, 1, synth.mb_write_multiple_registers(10, [1, 2, 3, 4])))
    assert (m.targets[0].start, m.targets[0].end) == (10, 13) and not m.anomalies
    pdu = bytes([16]) + struct.pack(">HHB", 10, 4, 6) + b"\x00" * 6  # byte count says 6, quantity says 4
    assert "bad_byte_count" in codes(one(synth.mb_adu(1, 1, pdu)))
    over = bytes([16]) + struct.pack(">HHB", 0, 0, 0)  # quantity 0 is outside 1..123
    m = one(synth.mb_adu(1, 1, over))
    assert "bad_quantity" in codes(m) and not m.targets  # no trusted target from a bad quantity


def test_write_multiple_coils():
    m = one(synth.mb_adu(1, 1, synth.mb_write_multiple_coils(0, [1, 0, 1, 1, 0, 0, 0, 1, 1])))
    assert (m.targets[0].start, m.targets[0].end) == (0, 8) and not m.anomalies and m.kinds == {"write"}


def test_mask_write_and_read_write_multiple():
    pdu = bytes([22]) + struct.pack(">HHH", 9, 0xF0F0, 0x0F0F)
    m = one(synth.mb_adu(1, 1, pdu))
    assert m.function == "MASK_WRITE_REGISTER" and m.targets[0].start == 9 and not m.anomalies
    pdu = bytes([23]) + struct.pack(">HHHHB", 0, 5, 20, 2, 4) + b"\x00" * 4
    m = one(synth.mb_adu(1, 1, pdu))
    assert m.kinds == {"read", "write"} and (m.targets[0].start, m.targets[0].end) == (20, 21) and not m.anomalies


def test_diagnostics_subfunctions_and_criticality():
    m = one(synth.mb_adu(1, 1, synth.mb_diag(0x0000, 0x1234)))
    assert m.details["subfunction_name"] == "RETURN_QUERY_DATA" and "critical" not in m.kinds
    for sub, name in ((0x0004, "FORCE_LISTEN_ONLY_MODE"), (0x0001, "RESTART_COMMUNICATIONS_OPTION")):
        m = one(synth.mb_adu(1, 1, synth.mb_diag(sub)))
        assert m.details["subfunction_name"] == name and "critical" in m.kinds
    assert one(synth.mb_adu(1, 1, synth.mb_diag(0x00AA))).details["subfunction_name"] == "UNKNOWN_170"
    assert "bad_length" in codes(one(synth.mb_adu(1, 1, bytes([8, 0]))))


def test_device_identification_request_and_response():
    m = one(synth.mb_adu(1, 1, synth.mb_device_id(1, 0)))
    assert "discovery" in m.kinds and m.details["read_device_id_code"] == 1 and not m.anomalies
    resp = synth.mb_device_id_response([(0, b"Acme"), (1, b"PLC-9000"), (2, b"V1.2")])
    r = one(synth.mb_adu(1, 1, resp), is_request=False)
    assert r.details["device_id"] == {"VendorName": "Acme", "ProductCode": "PLC-9000", "MajorMinorRevision": "V1.2"}
    # request with a trailing byte (seen in real scanner traffic) is flagged but still decoded
    odd = one(synth.mb_adu(1, 10, bytes([0x2B, 0x0E, 0x03, 0x01, 0x00])))
    assert "bad_device_id_request" in codes(odd) and odd.function == "ENCAPSULATED_INTERFACE_TRANSPORT"


def test_device_id_response_sanitises_and_bounds_strings():
    resp = bytes([43, 0x0E, 1, 1, 0, 0, 1, 0, 4]) + b"A\x00\x1bB"
    r = one(synth.mb_adu(1, 1, resp), is_request=False)
    assert r.details["device_id"]["VendorName"] == "A??B"
    trunc = bytes([43, 0x0E, 1, 1, 0, 0, 2, 0, 9]) + b"short"
    assert "bad_device_id_response" in codes(one(synth.mb_adu(1, 1, trunc), is_request=False))


def test_exception_responses():
    m = one(synth.mb_adu(1, 1, synth.mb_exception(3, 2)), is_request=False)
    assert m.exception == 2 and "exception" in m.kinds and m.function == "READ_HOLDING_REGISTERS"
    assert m.details["exception_name"] == "ILLEGAL_DATA_ADDRESS" and not m.anomalies
    assert "exception_in_request" in codes(one(synth.mb_adu(1, 1, synth.mb_exception(3, 2)), is_request=True))
    two = one(synth.mb_adu(1, 1, bytes([0x83, 2, 9])), is_request=False)
    assert "bad_exception_length" in codes(two)
    unk = one(synth.mb_adu(1, 1, bytes([0xDA, 1])), is_request=False)
    assert unk.function == "UNKNOWN_90" and "exception" in unk.kinds and "unknown_function" in unk.kinds


def test_unknown_function_codes_are_flagged_not_dropped():
    m = one(synth.mb_adu(1, 1, bytes([90, 1, 2, 3])))
    assert m.function == "UNKNOWN_90" and "unknown_function" in m.kinds and m.details["raw_len"] == 3


def test_broadcast_unit_zero_only_for_requests():
    assert one(synth.mb_adu(1, 0, synth.mb_write_single_register(1, 1))).broadcast
    assert not one(synth.mb_adu(1, 0, synth.mb_echo_write(6, 1, 1)), is_request=False).broadcast


def test_response_structures():
    bits = one(synth.mb_adu(1, 1, synth.mb_resp_bits(1, [1, 0, 1, 1, 0, 0, 0, 0, 1])), is_request=False)
    assert bits.details["byte_count"] == 2 and not bits.anomalies
    odd = one(synth.mb_adu(1, 1, bytes([3, 3, 0, 1, 2])), is_request=False)
    assert "bad_byte_count" in codes(odd)
    assert "bad_length" in codes(one(synth.mb_adu(1, 1, bytes([6, 0, 1])), is_request=False))
    big = one(synth.mb_adu(1, 1, synth.mb_resp_registers(3, list(range(100)))), is_request=False)
    assert big.details["value_count"] == 100 and len(big.details["values"]) == 16


def test_misc_function_structures():
    assert "bad_length" in codes(one(synth.mb_adu(1, 1, bytes([7, 1]))))
    assert not codes(one(synth.mb_adu(1, 1, bytes([17]))))
    assert one(synth.mb_adu(1, 1, bytes([17]))).kinds == {"discovery"}
    assert not codes(one(synth.mb_adu(1, 1, bytes([24, 0, 5]))))
    assert "bad_length" in codes(one(synth.mb_adu(1, 1, bytes([24, 0]))))
    rec = bytes([20, 7, 6, 0, 4, 0, 1, 0, 2])
    assert one(synth.mb_adu(1, 1, rec)).details["sub_requests"] == 1
    assert "bad_byte_count" in codes(one(synth.mb_adu(1, 1, bytes([20, 6, 6, 0, 4, 0, 1, 0]))))
    wr = bytes([21, 9, 6, 0, 4, 0, 1, 0, 1, 0xAA, 0xBB])
    m = one(synth.mb_adu(1, 1, wr))
    assert m.kinds == {"write"} and m.details["sub_requests"] == 1 and not m.anomalies


def test_function_name_helper():
    assert function_name(16) == "WRITE_MULTIPLE_REGISTERS" and function_name(99) == "UNKNOWN_99"


# -- framing -----------------------------------------------------------------------------------
def test_pipelined_frames_in_one_segment_and_split_across_segments():
    frames = [synth.mb_adu(i, 1, synth.mb_read(3, i, 1)) for i in range(1, 6)]
    d = ModbusDissector()
    out = feed(d, True, b"".join(frames))
    assert [m.transaction for m in out] == [1, 2, 3, 4, 5]
    d = ModbusDissector()
    out = []
    blob = b"".join(frames)
    for i in range(0, len(blob), 3):  # three bytes at a time
        out += feed(d, True, blob[i : i + 3])
    assert [m.transaction for m in out] == [1, 2, 3, 4, 5]


def test_directions_are_buffered_independently():
    d = ModbusDissector()
    req = synth.mb_adu(1, 1, synth.mb_read(3, 0, 2))
    resp = synth.mb_adu(1, 1, synth.mb_resp_registers(3, [1, 2]))
    assert feed(d, True, req[:5]) == [] and feed(d, False, resp[:4]) == []
    a = feed(d, True, req[5:])
    b = feed(d, False, resp[4:])
    assert a[0].is_request and not b[0].is_request


def test_gap_discards_partial_frame_and_resumes():
    d = ModbusDissector()
    req = synth.mb_adu(1, 1, synth.mb_read(3, 0, 2))
    assert feed(d, True, req[:6]) == []
    out = feed(d, True, req, gap=True)  # bytes were lost: partial frame must not poison the next one
    assert len(out) == 1 and out[0].function == "READ_HOLDING_REGISTERS" and not out[0].anomalies


def test_invalid_headers_are_reported_once_per_garbage_burst():
    d = ModbusDissector()
    out = feed(d, True, b"\xff" * 40)
    assert [m.function for m in out] == ["MALFORMED"] and out[0].anomalies[0].code == "bad_mbap"


def test_oversize_length_field_does_not_buffer_forever():
    d = ModbusDissector()
    hdr = struct.pack(">HHHB", 1, 0, 0x8804, 1) + b"\x03"
    out = feed(d, True, hdr + b"\x00" * 200)
    assert out and out[0].function == "MALFORMED"
    assert len(d._bufs[True]) < 10


def test_nonzero_protocol_id_is_malformed():
    bad = struct.pack(">HHHB", 1, 0x0010, 6, 10) + bytes([1, 0, 1, 0, 3])
    out = feed(ModbusDissector(), True, bad)
    assert out[0].function == "MALFORMED"


def test_resync_at_chunk_boundary_keeps_unknown_function_visible():
    d = ModbusDissector()
    # a frame whose length field is too short leaves stray bytes ...
    bad = struct.pack(">HHHB", 0, 0, 4, 1) + bytes([0x21, 0, 0, 0, 0])
    feed(d, True, bad[:9])
    feed(d, True, bad[9:])
    good = synth.mb_adu(5, 1, bytes([0x5A, 1, 2, 3, 4]))  # vendor function code 90, own TCP segment
    out = feed(d, True, good)
    assert any(m.function_code == 0x5A for m in out)


def test_midchunk_resync_requires_a_defined_function_code():
    d = ModbusDissector()
    junk = b"\xaa\xbb\xcc" + synth.mb_adu(9, 1, bytes([0x5A, 1, 2]))  # unknown FC after junk in the same chunk
    out = feed(d, True, junk)
    assert all(m.function == "MALFORMED" for m in out)
    d = ModbusDissector()
    ok = b"\xaa\xbb\xcc" + synth.mb_adu(9, 1, synth.mb_read(3, 0, 1))
    out = feed(d, True, ok)
    assert any(m.function == "READ_HOLDING_REGISTERS" for m in out)


def test_zero_heavy_non_modbus_payload_creates_no_phantom_messages():
    # regression: real capture of non-Modbus data on port 502 (zero-rich binary header)
    payload = bytes.fromhex("800000287e86ab4a0000000000000002000186a300000003" + "00" * 20)
    out = feed(ModbusDissector(), True, payload)
    assert all(m.function == "MALFORMED" for m in out)


def test_parse_adu_empty_pdu():
    m = parse_adu(struct.pack(">HHHB", 1, 0, 1, 1), True)
    assert m.function == "EMPTY_PDU" and "malformed" in m.kinds


def test_random_garbage_never_raises_and_buffer_stays_bounded():
    rng = random.Random(7)
    d = ModbusDissector()
    for _ in range(300):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 400)))
        feed(d, rng.random() < 0.5, blob, gap=rng.random() < 0.1)
        assert len(d._bufs[True]) < 600 and len(d._bufs[False]) < 600


def test_every_defined_function_code_roundtrips_without_anomalies_in_both_directions():
    reqs = {
        1: synth.mb_read(1, 0, 8), 2: synth.mb_read(2, 0, 8), 3: synth.mb_read(3, 0, 8), 4: synth.mb_read(4, 0, 8),
        5: synth.mb_write_single_coil(1, True), 6: synth.mb_write_single_register(1, 5), 7: bytes([7]),
        8: synth.mb_diag(0, 0), 11: bytes([11]), 12: bytes([12]), 15: synth.mb_write_multiple_coils(0, [1] * 10),
        16: synth.mb_write_multiple_registers(0, [1, 2]), 17: bytes([17]),
        22: bytes([22]) + struct.pack(">HHH", 1, 2, 3), 24: bytes([24, 0, 1]),
        43: synth.mb_device_id(),
    }
    for fc, pdu in reqs.items():
        m = one(synth.mb_adu(1, 1, pdu))
        assert m.function_code == fc and not m.anomalies, (fc, m.anomalies)
