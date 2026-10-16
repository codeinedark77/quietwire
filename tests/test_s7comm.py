import random
import struct

import pytest

from quietwire import synth
from quietwire.proto.s7comm import S7Dissector, parse_s7
from quietwire.synth import (cotp_cr, cotp_dt, s7_item, s7_pdu, s7_read_ack, s7_read_job, s7_setup, s7_userdata,
                             s7_write_ack, s7_write_job, tpkt)


def feed(d, data, client=True, gap=False):
    return d.feed_stream(client, data, gap)


def one(frame, client=True):
    msgs = feed(S7Dissector(), frame, client)
    assert len(msgs) == 1, msgs
    return msgs[0]


def codes(m):
    return [a.code for a in m.anomalies]


# -- canonical byte vectors (public S7comm documentation / captures) -----------------------------
def test_cotp_connection_request_vector():
    cr = bytes.fromhex("0300001611e00000000100c1020100c2020102c0010a")
    m = one(cr)
    assert m.function == "COTP_CONNECT_REQUEST" and m.is_request and not m.anomalies
    assert m.details["calling"] == {"tsap": "0100", "connection_type": "PG", "rack": 0, "slot": 0}
    assert m.details["called"] == {"tsap": "0102", "connection_type": "PG", "rack": 0, "slot": 2}
    assert m.details["tpdu_size"] == 1024


def test_setup_communication_vector():
    pkt = bytes.fromhex("03000019" "02f080" "32010000000000080000f0000001000101e0")
    m = one(pkt)
    assert (m.function, m.function_code, m.is_request) == ("SETUP_COMMUNICATION", 0xF0, True)
    assert m.details["pdu_length"] == 480 and not m.anomalies and m.kinds == {"session"}
    assert synth.s7_setup(0) == pkt  # independent encoder agrees with the documented bytes


def test_read_var_vector_db1_dbb0():
    pkt = bytes.fromhex("0300001f02f080" "32010000000100 0e0000" "0401" "120a10020001000184000000".replace(" ", ""))
    m = one(pkt)
    assert m.function == "READ_VAR" and m.kinds == {"read"} and not m.anomalies
    item = m.details["items"][0]
    assert (item["area"], item["db"], item["offset"], item["length_bytes"]) == ("DB1", 1, 0, 1)
    assert [t.to_dict() for t in m.targets] == [{"area": "DB1", "start": 0, "end": 0}]


def test_plc_stop_vector():
    pkt = tpkt(cotp_dt() + s7_pdu(1, 3, bytes.fromhex("2900000000000950 5f50524f4752414d".replace(" ", ""))))
    m = one(pkt)
    assert m.function == "PLC_STOP" and "critical" in m.kinds and m.details["service"] == "P_PROGRAM"


# -- jobs ---------------------------------------------------------------------------------------
def test_read_job_multiple_items_and_areas():
    pkt = s7_read_job(7, [(0x84, 2, 10, 4), (0x83, 0, 100, 2), (0x82, 0, 0, 1)])
    m = one(pkt)
    areas = [(i["area"], i["offset"], i["length_bytes"]) for i in m.details["items"]]
    assert areas == [("DB2", 10, 4), ("M", 100, 2), ("Q", 0, 1)] and m.transaction == 7


def test_write_job_targets_and_kinds():
    pkt = s7_write_job(9, [(0x84, 5, 20, b"\x00\x01\x02\x03"), (0x83, 0, 8, b"\xff")])
    m = one(pkt)
    assert m.function == "WRITE_VAR" and m.kinds == {"write"} and not m.anomalies
    assert [(t.area, t.start, t.end) for t in m.targets] == [("DB5", 20, 23), ("M", 8, 8)]


def test_bit_addressing_and_element_width():
    # BOOL (transport size 1) at M10.3, and 3 WORDs (size 4) at DB1.DBW20
    pkt = s7_read_job(1, [])
    param = bytes([0x04, 2]) + s7_item(0x83, 0, 10, 1, tsize=1)
    param = param[:-3] + bytes([0x00, 0x00, 10 * 8 + 3]) + s7_item(0x84, 1, 20, 3, tsize=4)
    m = one(tpkt(cotp_dt() + s7_pdu(1, 1, param)))
    first, second = m.details["items"]
    assert first["offset"] == 10 and first["bit"] == 3
    assert second["offset"] == 20 and second["length_bytes"] == 6  # 3 words


def test_unparseable_item_marks_targets_unknown_for_writes():
    param = bytes([0x05, 1, 0x13, 3, 1, 2, 3])  # non-S7ANY variable specification
    m = one(tpkt(cotp_dt() + s7_pdu(1, 1, param, b"\x00\x04\x00\x08\x01")))
    assert m.details.get("targets_unknown") and not m.targets


def test_item_list_truncation_reported():
    param = bytes([0x04, 3]) + s7_item(0x84, 1, 0, 1)  # promises 3 items, carries 1
    m = one(tpkt(cotp_dt() + s7_pdu(1, 1, param)))
    assert "bad_item" in codes(m)


def test_pi_services_and_download_upload():
    inse = one(synth.s7_pi_service(b"_INSE"))
    assert inse.function == "PI_SERVICE" and inse.details["service"] == "_INSE" and "critical" in inse.kinds
    assert one(synth.s7_pi_service(b"P_PROGRAM", args=b"\x00\x01")).details["service"] == "P_PROGRAM"
    dl = one(synth.s7_request_download(b"_0A00001P"))
    assert dl.function == "REQUEST_DOWNLOAD" and dl.kinds == {"critical", "program_transfer"}
    assert dl.details["block_type"] == "DB" and dl.details["block_number"] == "00001"
    up = one(synth.s7_start_upload(b"_0800010A"))
    assert up.function == "START_UPLOAD" and up.details["block_type"] == "OB" and "critical" not in up.kinds
    assert "program_transfer" in up.kinds


def test_unknown_function_flagged():
    m = one(tpkt(cotp_dt() + s7_pdu(1, 1, bytes([0x77, 0, 0]))))
    assert m.function == "UNKNOWN_0x77" and "unknown_function" in m.kinds


def test_s7comm_plus_is_recognised_but_not_dissected():
    m = one(tpkt(cotp_dt() + bytes([0x72, 0x01, 0x00, 0x00, 0x00])))
    assert m.function == "S7COMMPLUS" and not m.anomalies


# -- acks / responses -----------------------------------------------------------------------------
def test_read_response_values_and_error_items():
    ok = one(s7_read_ack(4, [b"\x00\x00\x00\x01"]), client=False)
    assert ok.function == "READ_VAR" and not ok.is_request and ok.details["return_codes"] == ["success"]
    # regression (real capture): items with an error return code carry no data bytes
    items = b"".join(bytes([0x0A, 0x00, 0x00, 0x04]) for _ in range(5))
    pkt = tpkt(cotp_dt() + s7_pdu(3, 5, bytes([0x04, 5]), items, err=0))
    m = one(pkt, client=False)
    assert not m.anomalies and m.exception == 0x0A and "exception" in m.kinds
    assert m.details["return_codes"] == ["object_not_available"] * 5


def test_write_response_return_codes():
    ok = one(s7_write_ack(3, [0xFF, 0xFF]), client=False)
    assert ok.details["return_codes"] == ["success", "success"] and "exception" not in ok.kinds
    bad = one(s7_write_ack(3, [0xFF, 0x03]), client=False)
    assert "exception" in bad.kinds and bad.exception == 0x03 and bad.details["return_codes"][1] == "access_denied"


def test_header_error_code_marks_exception():
    pkt = tpkt(cotp_dt() + s7_pdu(2, 9, b"", b"", err=0x8104))
    m = one(pkt, client=False)
    assert m.function == "ACK" and m.exception == 0x8104 and not m.is_request


def test_odd_length_items_are_padded_between_items():
    pkt = s7_read_ack(4, [b"\x01", b"\x02\x03"])
    m = one(pkt, client=False)
    assert not m.anomalies and m.details["return_codes"] == ["success", "success"]


# -- userdata -------------------------------------------------------------------------------------
def test_userdata_szl_read_is_discovery():
    data = b"\xff\x09\x00\x04\x00\x11\x00\x01"
    m = one(s7_userdata(4, 1, data=data))
    assert m.function == "READ_SZL" and "discovery" in m.kinds
    assert m.details["szl_id"] == 0x0011 and m.details["szl_index"] == 1


def test_userdata_other_groups():
    assert one(s7_userdata(3, 1)).function == "LIST_BLOCKS"
    assert one(s7_userdata(7, 2)).function == "SET_CLOCK"
    assert "maintenance" in one(s7_userdata(7, 2)).kinds
    assert one(s7_userdata(0, 0)).function == "USERDATA_MODE_TRANSITION"
    bad = tpkt(cotp_dt() + s7_pdu(7, 1, b"\x00\x01"))
    assert "bad_userdata" in codes(one(bad))


# -- COTP / TPKT ------------------------------------------------------------------------------------
def test_connect_confirm_and_disconnect():
    cc = tpkt(bytes([0x11, 0xD0]) + b"\x00\x01\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a")
    m = one(cc, client=False)
    assert m.function == "COTP_CONNECT_CONFIRM" and not m.is_request
    assert one(tpkt(bytes([0x06, 0x80, 0, 1, 0, 2, 0])), client=False).function == "COTP_DISCONNECT"


def test_cotp_data_fragmentation_reassembled_on_eot():
    pdu = s7_pdu(1, 3, bytes([0x04, 1]) + s7_item(0x84, 1, 0, 4))
    half = len(pdu) // 2
    a = tpkt(b"\x02\xf0\x00" + pdu[:half])  # EOT bit clear
    b = tpkt(b"\x02\xf0\x80" + pdu[half:])
    d = S7Dissector()
    assert feed(d, a) == []
    out = feed(d, b)
    assert len(out) == 1 and out[0].function == "READ_VAR" and not out[0].anomalies


def test_pipelined_tpkts_and_byte_at_a_time():
    blob = s7_read_job(1, [(0x84, 1, 0, 1)]) + s7_read_job(2, [(0x84, 1, 4, 1)])
    d = S7Dissector()
    out = []
    for i in range(len(blob)):
        out += feed(d, blob[i : i + 1])
    assert [m.transaction for m in out] == [1, 2]


def test_length_inconsistencies_are_reported():
    pdu = bytearray(s7_pdu(1, 1, bytes([0x04, 1]) + s7_item(0x84, 1, 0, 1)))
    pdu[9] = 4  # claim 4 data bytes that are not there
    m = one(tpkt(cotp_dt() + bytes(pdu)))
    assert "length_mismatch" in codes(m)
    short = tpkt(cotp_dt() + bytes([0x32, 1, 0, 0]))
    assert one(short).function == "MALFORMED"
    assert "no_parameter" in codes(one(tpkt(cotp_dt() + s7_pdu(1, 1, b""))))
    assert "unknown_rosctr" in codes(one(tpkt(cotp_dt() + s7_pdu(9, 1, bytes([0x04, 0])))))


def test_bad_protocol_id_and_cotp_structure():
    assert codes(one(tpkt(cotp_dt() + bytes([0x40]) + b"\x00" * 11))) == ["bad_protocol_id"]
    bad_li = tpkt(bytes([0x01, 0xF0, 0x80, 0x00]))  # DT TPDU with wrong length indicator
    assert "bad_cotp" in codes(one(bad_li))
    overrun = tpkt(bytes([0x20, 0xF0, 0x80]))
    assert "bad_cotp" in codes(one(overrun))
    other = one(tpkt(bytes([0x02, 0x50, 0x00]) + b"x"))
    assert other.function == "COTP_0x50"


def test_tpkt_resync_after_garbage():
    d = S7Dissector()
    good = s7_read_job(1, [(0x84, 1, 0, 1)])
    out = feed(d, b"\x41\x42\x43\x44\x45\x46" + good)
    assert any(m.function == "READ_VAR" for m in out) and out[0].function == "MALFORMED"


def test_cotp_buffer_is_bounded():
    d = S7Dissector()
    out = []
    for _ in range(40):
        out += feed(d, tpkt(b"\x02\xf0\x00" + b"\x00" * 3000))  # never sets EOT
    assert any("pdu_too_large" in codes(m) for m in out)


def test_gap_clears_partial_state():
    d = S7Dissector()
    pkt = s7_read_job(1, [(0x84, 1, 0, 1)])
    feed(d, pkt[:10])
    out = feed(d, pkt, gap=True)
    assert [m.function for m in out] == ["READ_VAR"]


def test_parse_s7_direct_edge_cases():
    assert parse_s7(b"", True).function == "MALFORMED"
    assert parse_s7(b"\x32", True).function == "MALFORMED"
    assert parse_s7(bytes([0x32, 3, 0, 0, 0, 1, 0, 0, 0, 0]), False).function == "MALFORMED"  # ack header needs 12


def test_random_garbage_never_raises():
    rng = random.Random(5)
    d = S7Dissector()
    good = s7_read_job(1, [(0x84, 1, 0, 1)])
    for _ in range(400):
        blob = bytearray(rng.choice([good, bytes(rng.randrange(256) for _ in range(rng.randrange(1, 120)))]))
        if rng.random() < 0.6 and blob:
            blob[rng.randrange(len(blob))] = rng.randrange(256)
        feed(d, bytes(blob), client=rng.random() < 0.5, gap=rng.random() < 0.05)
        assert len(d._bufs[True]) < 70000
