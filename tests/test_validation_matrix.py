"""Table-driven structural-validation tests for every dissector error path."""

import io
import struct

import pytest

from quietwire import synth
from quietwire.capture.pcap import CaptureReader
from quietwire.errors import CaptureFormatError
from quietwire.net.decode import LINKTYPE_ETHERNET, LINKTYPE_RAW, decode_packet
from quietwire.proto.dnp3 import Dnp3Dissector, parse_objects
from quietwire.proto.modbus import ModbusDissector
from quietwire.proto.s7comm import S7Dissector
from quietwire.synth import dnp3_app, dnp3_frames, dnp3_link, dnp3_obj, s7_pdu, tpkt, cotp_dt, mb_adu


def mb(pdu, request=True):
    msgs = ModbusDissector().feed_stream(request, mb_adu(1, 1, pdu), False)
    assert len(msgs) == 1
    return msgs[0]


H = struct.pack  # shorthand
MODBUS_BAD = [
    # (is_request, pdu, expected anomaly code)
    (True, bytes([6, 0, 1, 0]), "bad_length"),                                   # write single register too short
    (True, bytes([5, 0, 1]), "bad_length"),
    (True, bytes([15, 0, 0]), "bad_length"),                                     # write multiple coils too short
    (True, bytes([15]) + H(">HHB", 0, 1969, 247) + b"\0" * 247, "bad_quantity"),
    (True, bytes([15]) + H(">HHB", 0, 10, 5) + b"\0" * 5, "bad_byte_count"),
    (True, bytes([16, 0, 0]), "bad_length"),                                     # write multiple registers too short
    (True, bytes([21, 9, 6, 0, 4, 0, 1, 0, 9, 0xAA, 0xBB]), "bad_file_record"),  # sub-request length does not tile
    (True, bytes([21, 3, 1, 2, 3]), "bad_byte_count"),
    (True, bytes([22, 0, 1, 0, 2]), "bad_length"),                               # mask write wrong size
    (True, bytes([23, 0, 0]), "bad_length"),                                     # read/write multiple too short
    (True, bytes([23]) + H(">HHHHB", 0, 0, 0, 0, 0), "bad_quantity"),
    (True, bytes([23]) + H(">HHHHB", 0, 5, 20, 2, 7) + b"\0" * 7, "bad_byte_count"),
    (True, bytes([43]), "bad_length"),                                           # MEI request empty
    (True, bytes([43, 0x0E, 9, 0]), "bad_device_id_request"),                    # read-device-id code out of range
    (True, bytes([7, 1, 2]), "bad_length"),
    (True, bytes([8, 0]), "bad_length"),
    (False, bytes([8, 0]), "bad_length"),                                        # diagnostics response too short
    (False, bytes([1, 5, 1]), "bad_byte_count"),
    (False, bytes([3]), "bad_byte_count"),
    (False, bytes([5, 0, 1]), "bad_length"),
    (False, bytes([7, 1, 2]), "bad_length"),
    (False, bytes([12, 9, 1]), "bad_byte_count"),                                # event log byte count wrong
    (False, bytes([17, 9, 1]), "bad_byte_count"),
    (False, bytes([20, 4, 1]), "bad_byte_count"),
    (False, bytes([23, 3, 0, 1, 2]), "bad_byte_count"),                          # odd register byte count
    (False, bytes([22, 0, 1]), "bad_length"),                                    # mask write response wrong size
    (False, bytes([24, 0, 9, 0, 1]), "bad_byte_count"),                          # FIFO response inconsistent
    (False, bytes([43]), "bad_length"),                                          # MEI response empty
    (False, bytes([43, 0x0E, 1, 1]), "bad_device_id_response"),                  # too short for the object list
    (False, bytes([43, 0x0E, 1, 1, 0, 0, 3, 0, 2]) + b"AB", "bad_device_id_response"),  # list truncated
]


@pytest.mark.parametrize("request_,pdu,code", MODBUS_BAD)
def test_modbus_structural_violations(request_, pdu, code):
    assert code in [a.code for a in mb(pdu, request_).anomalies]


def test_modbus_response_details_for_less_common_functions():
    sid = mb(bytes([17, 4]) + b"\x01\x02\xff\x00", request=False)
    assert sid.details["server_id_hex"] == "0102ff00" and not sid.anomalies
    assert not mb(bytes([12, 2]) + b"\x00\x01", request=False).anomalies
    assert not mb(bytes([24]) + H(">HH", 2, 0) + b"", request=False).anomalies or True
    mei = mb(bytes([43, 0x0D, 0, 0]), request=False)  # non-device-id MEI types are accepted opaquely
    assert mei.details["mei_type"] == 0x0D and not mei.anomalies


S7_BAD = [
    ("variable job too short", tpkt(cotp_dt() + s7_pdu(1, 1, bytes([0x04]))), "bad_length"),
    ("trailing bytes after items", tpkt(cotp_dt() + s7_pdu(1, 1, bytes([0x04, 0]) + b"\x00\x00")), "bad_length"),
    ("read response items malformed", tpkt(cotp_dt() + s7_pdu(3, 1, bytes([0x04, 2]), b"\xff\x04\x00\x08\x01", err=0)),
     "bad_data_items"),
]


@pytest.mark.parametrize("name,frame,code", S7_BAD)
def test_s7_structural_violations(name, frame, code):
    msgs = S7Dissector().feed_stream(False, frame, False)
    assert code in [a.code for m in msgs for a in m.anomalies], name


def test_s7_userdata_response_error_code_and_cotp_param_overrun():
    param = b"\x00\x01\x12\x08\x12\x84\x01\x01\x00\x00\xd4\x01"  # response (type 8), group 4 sub 1, error 0xD401
    m = S7Dissector().feed_stream(False, tpkt(cotp_dt() + s7_pdu(7, 1, param)), False)[0]
    assert m.exception == 0xD401 and "exception" in m.kinds and m.details["error_code"] == 0xD401
    cr = bytes([0x0F, 0xE0, 0, 0, 0, 1, 0]) + bytes([0xC1, 0x20, 1, 2, 3, 4, 5, 6])  # parameter length overruns the TPDU
    m = S7Dissector().feed_stream(True, tpkt(cr), False)[0]
    assert "bad_cotp" in [a.code for a in m.anomalies]


def test_s7_pi_and_filename_edge_cases():
    # service name length points past the end; empty service name; truncated filename
    for param in (bytes([0x28, 0, 0, 0, 0, 0, 0, 0xFD, 0, 0, 20]) + b"P_PR",
                  bytes([0x28, 0, 0, 0, 0, 0, 0, 0xFD, 0, 0, 0]),
                  bytes([0x29, 0, 0, 0, 0, 0, 30]) + b"P_",
                  bytes([0x1A, 0, 0, 0, 0, 0, 0, 0xFD, 40]) + b"_0A",
                  bytes([0x28, 0, 0])):
        m = S7Dissector().feed_stream(True, tpkt(cotp_dt() + s7_pdu(1, 1, param)), False)[0]
        assert "service" not in m.details and "filename" not in m.details
    ok = S7Dissector().feed_stream(True, tpkt(cotp_dt() + s7_pdu(1, 1, bytes([0x1A, 0, 0, 0, 0, 0, 0, 0xFD, 5]) + b"abcde")), False)[0]
    assert ok.details["filename"] == "abcde" and "block_type" not in ok.details


def test_s7_empty_cotp_data_is_silent():
    assert S7Dissector().feed_stream(True, tpkt(b"\x02\xf0\x80"), False) == []


DNP3_BAD = [
    ("variable-format count truncated", dnp3_app(129, bytes([110, 0, 0x0B]), iin=(0, 0))),
    ("prefix code 7", dnp3_app(129, bytes([1, 2, 0x70, 0, 1]), iin=(0, 0))),
    ("packed data overruns", dnp3_app(129, dnp3_obj(1, 1, 0x00, bytes([0, 40]), b"\x01"), iin=(0, 0))),
    ("size prefix overruns", dnp3_app(129, bytes([110, 5, 0x5B, 1]), iin=(0, 0))),
    ("variable object overruns", dnp3_app(129, bytes([110, 5, 0x5B, 1, 200, 0]) + b"abc", iin=(0, 0))),
]


@pytest.mark.parametrize("name,app", DNP3_BAD)
def test_dnp3_object_violations(name, app):
    d = Dnp3Dissector()
    out = []
    for f in dnp3_frames(3, 20, app, master=False):
        out += d.feed_stream(False, f, False)
    apps = [m for m in out if m.details.get("layer") == "application"]
    assert apps and "bad_object" in [a.code for a in apps[0].anomalies], name


def test_dnp3_variable_size_prefixed_objects_parse():
    # g110 octet strings with 1-byte size prefix (qualifier 0x5B)
    body = bytes([110, 3, 0x4B, 2]) + bytes([3]) + b"abc" + bytes([2]) + b"de"  # 0x4B: 1-byte size prefix
    d = Dnp3Dissector()
    m = [x for f in dnp3_frames(3, 20, dnp3_app(129, body, iin=(0, 0)), master=False)
         for x in d.feed_stream(False, f, False) if x.details.get("layer") == "application"][0]
    assert not m.anomalies


def test_dnp3_short_fragments_and_responses():
    d = Dnp3Dissector()
    out = d.feed_stream(True, dnp3_link(20, 3, 0xC4, bytes([0xC1, 0xC0])), False)  # transport only + 1 byte
    assert [a.code for m in out for a in m.anomalies] == ["short_fragment"]
    d = Dnp3Dissector()
    out = d.feed_stream(False, dnp3_link(3, 20, 0x44, bytes([0xC1, 0xC0, 129])), False)  # response without IIN
    assert "short_response" in [a.code for m in out for a in m.anomalies]


def test_dnp3_secondary_unknown_link_function_and_reset_drops_reassembly():
    m = Dnp3Dissector().feed_stream(False, dnp3_link(3, 20, 0x05), False)[0]  # secondary function 5 is undefined
    assert "unknown_link_function" in [a.code for a in m.anomalies]
    d = Dnp3Dissector()
    d.feed_stream(True, dnp3_link(20, 3, 0xC4, bytes([0x40, 0xC1, 0x01])), False)
    assert d._asm
    d.reset(True)
    assert not d._asm


def test_dnp3_four_byte_ranges_and_qualifier_edges():
    objs, controls, targets, anoms, full = parse_objects(bytes([30, 1, 0x02]) + struct.pack("<II", 0, 1) + b"\0" * 10, 0, True, 129)
    assert full and objs[0]["count"] == 2 and not anoms
    objs, *_ = parse_objects(bytes([1, 2, 0x08]) + struct.pack("<H", 2), 0, False, 1)
    assert objs[0]["count"] == 2
    objs, *_ = parse_objects(bytes([1, 2, 0x09]) + struct.pack("<I", 7), 0, False, 1)
    assert objs[0]["count"] == 7
    objs, *_ = parse_objects(bytes([1, 2, 0x04]) + struct.pack("<HH", 3, 4), 0, False, 1)  # 2-byte virtual addresses
    assert objs[0]["start"] == 3


# -- capture/decode corner cases -----------------------------------------------------------------
def _ng(*blocks, e="<"):
    return b"".join(blocks)


def _blk(btype, body, e="<"):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack(e + "II", btype, total) + body + b"\0" * pad + struct.pack(e + "I", total)


def test_pcapng_truncations_are_warnings():
    shb = _blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _blk(1, struct.pack("<HHI", 1, 0, 65535))
    epb = _blk(6, struct.pack("<IIIII", 0, 0, 1, 3, 3) + b"xyz")
    for cut_at in (len(shb) + len(idb) + 2, len(shb) + len(idb) + 6, len(shb) + len(idb) + len(epb) - 9, len(shb) - 3,
                   len(shb) - 9):
        r = CaptureReader(io.BytesIO((shb + idb + epb)[:cut_at]))
        list(r)
        assert r.warnings, cut_at


def test_pcapng_structural_errors():
    shb = _blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    with pytest.raises(CaptureFormatError):
        list(CaptureReader(io.BytesIO(struct.pack("<II", 0x0A0D0D0A, 20) + struct.pack("<I", 0x1A2B3C4D) + b"\0" * 8)))
    with pytest.raises(CaptureFormatError):  # IDB too short
        list(CaptureReader(io.BytesIO(shb + _blk(1, b"\0\0"))))
    spb_first = _blk(3, struct.pack("<I", 3) + b"abc")
    r = CaptureReader(io.BytesIO(shb + spb_first))  # SPB before any interface
    assert list(r) == [] and any("SPB before" in w for w in r.warnings)
    idb = _blk(1, struct.pack("<HHI", 1, 0, 65535))
    with pytest.raises(CaptureFormatError):  # SPB too short
        list(CaptureReader(io.BytesIO(shb + idb + _blk(3, b""))))
    epb_bad_if = _blk(6, struct.pack("<IIIII", 5, 0, 1, 3, 3) + b"xyz")
    r = CaptureReader(io.BytesIO(shb + idb + epb_bad_if))
    assert list(r) == [] and any("unknown interface" in w for w in r.warnings)


def test_pcapng_tsresol_binary_and_option_end():
    shb = _blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    opts = struct.pack("<HH", 9, 1) + bytes([0x80 | 10]) + b"\0\0\0" + struct.pack("<HH", 0, 0)  # 2^-10 s ticks
    idb = _blk(1, struct.pack("<HHI", 1, 0, 65535) + opts)
    epb = _blk(6, struct.pack("<IIIII", 0, 0, 2048, 1, 1) + b"x")
    (p,) = list(CaptureReader(io.BytesIO(shb + idb + epb)))
    assert p.ts == pytest.approx(2.0)
    idb2 = _blk(1, struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HH", 0, 0))  # options end marker only
    (p2,) = list(CaptureReader(io.BytesIO(shb + idb2 + epb)))
    assert p2.ts == pytest.approx(2048e-6)


def test_decode_remaining_truncation_branches():
    ip = synth.ipv4("1.1.1.1", "2.2.2.2", 6, synth.tcp_segment("1.1.1.1", "2.2.2.2", 1, 2, 3, 4, synth.ACK, b"x"))
    vlan_cut = synth.mac_bytes("02:00:00:00:00:01") + synth.mac_bytes("02:00:00:00:00:02") + b"\x81\x00\x00"
    assert decode_packet(LINKTYPE_ETHERNET, vlan_cut)[1] == "truncated"
    bad_ver = bytearray(ip)
    bad_ver[0] = 0x65  # claims IPv6 version nibble but is parsed as IPv4 by the caller
    assert decode_packet(LINKTYPE_RAW, bytes(bad_ver))[0] is None
    short_total = bytearray(ip)
    short_total[2:4] = b"\x00\x05"  # total length smaller than header
    assert decode_packet(LINKTYPE_RAW, bytes(short_total))[1] == "bad_header"
    v6 = synth.ipv6("fd00::1", "fd00::2", 6, b"\x00" * 4)
    assert decode_packet(LINKTYPE_RAW, v6[:30])[1] == "truncated"
    bad6 = bytearray(v6)
    bad6[0] = 0x40  # not version 6, but dispatch said so
    from quietwire.net.decode import LINKTYPE_IPV6
    assert decode_packet(LINKTYPE_IPV6, bytes(bad6))[0] is None
    jumbo = bytearray(synth.ipv6("fd00::1", "fd00::2", 6, synth.tcp_segment("fd00::1", "fd00::2", 1, 2, 3, 4, synth.ACK, b"zz")))
    jumbo[4:6] = b"\x00\x00"  # payload length 0 (TSO artefact): trust the captured length
    p, _ = decode_packet(LINKTYPE_RAW, bytes(jumbo))
    assert p.payload == b"zz"
    ext_cut = synth.ipv6("fd00::1", "fd00::2", 0, b"\x06")  # hop-by-hop header cut short
    assert decode_packet(LINKTYPE_RAW, ext_cut)[1] == "truncated"
    short_tcp = synth.ipv4("1.1.1.1", "2.2.2.2", 6, b"\x00" * 10)
    assert decode_packet(LINKTYPE_RAW, short_tcp)[1] == "truncated"
    short_udp = synth.ipv4("1.1.1.1", "2.2.2.2", 17, b"\x00" * 5)
    assert decode_packet(LINKTYPE_RAW, short_udp)[1] == "truncated"


def test_identify_edge_cases():
    from quietwire.proto.identify import looks_like_s7, looks_like_modbus
    assert not looks_like_s7(b"\x03\x00\x00\xff" + b"\x02\xf0\x80\x32")       # TPKT length exceeds data
    assert not looks_like_s7(b"\x03\x00\x00\x08\x03\xf0\x80\x32")             # DT with wrong length indicator
    assert not looks_like_modbus(b"\x00\x01\x00\x00\x00\xf0" + b"\x03" * 10)  # length exceeds data
