"""Golden tests for the S7comm tables and field decoding, with distinctive (non-zero) field values."""

import struct

import pytest

from quietwire import synth
from quietwire.proto import s7comm
from quietwire.proto.s7comm import (AREAS, BLOCK_TYPES, ELEM_BYTES, FUNCTIONS, RETURN_CODES, ROSCTR_NAMES,
                                    S7PLUS_FUNCTIONS, S7PLUS_OPCODES, UD_GROUPS, S7Dissector, parse_s7)
from quietwire.synth import cotp_dt, s7_pdu, tpkt


def one(frame, client=True):
    out = S7Dissector().feed_stream(client, frame, False)
    assert len(out) == 1, out
    return out[0]


def codes(m):
    return [a.code for a in m.anomalies]


def job(param, data=b"", pduref=0x1234, rosctr=1, err=None):
    return tpkt(cotp_dt() + s7_pdu(rosctr, pduref, param, data, err=err))


K = frozenset
EXPECTED_FUNCTIONS = {
    0x00: ("CPU_SERVICES", K(["other"])), 0xF0: ("SETUP_COMMUNICATION", K(["session"])),
    0x04: ("READ_VAR", K(["read"])), 0x05: ("WRITE_VAR", K(["write"])),
    0x1A: ("REQUEST_DOWNLOAD", K(["critical", "program_transfer"])), 0x1B: ("DOWNLOAD_BLOCK", K(["critical", "program_transfer"])),
    0x1C: ("DOWNLOAD_ENDED", K(["critical", "program_transfer"])), 0x1D: ("START_UPLOAD", K(["program_transfer"])),
    0x1E: ("UPLOAD", K(["program_transfer"])), 0x1F: ("END_UPLOAD", K(["program_transfer"])),
    0x28: ("PI_SERVICE", K(["critical"])), 0x29: ("PLC_STOP", K(["critical"])),
}


def test_function_and_rosctr_tables_are_golden():
    assert FUNCTIONS == EXPECTED_FUNCTIONS
    assert ROSCTR_NAMES == {1: "JOB", 2: "ACK", 3: "ACK_DATA", 7: "USERDATA"}
    assert UD_GROUPS == {0: "MODE_TRANSITION", 1: "PROGRAMMER", 2: "CYCLIC_DATA", 3: "BLOCK_FUNCTIONS",
                         4: "CPU_FUNCTIONS", 5: "SECURITY", 6: "PBC", 7: "TIME_FUNCTIONS"}
    assert BLOCK_TYPES == {"08": "OB", "0A": "DB", "0B": "SDB", "0C": "FC", "0D": "SFC", "0E": "FB", "0F": "SFB"}
    assert RETURN_CODES == {0xFF: "success", 0x01: "hardware_fault", 0x03: "access_denied", 0x05: "invalid_address",
                            0x06: "data_type_not_supported", 0x07: "data_type_inconsistent",
                            0x0A: "object_not_available"}
    assert AREAS == {0x03: "SYS_INFO", 0x05: "SYS_FLAGS", 0x06: "ANA_IN", 0x07: "ANA_OUT", 0x80: "P", 0x81: "I",
                     0x82: "Q", 0x83: "M", 0x84: "DB", 0x85: "DI", 0x86: "L", 0x87: "V", 0x1C: "C", 0x1D: "T",
                     0x1E: "IEC_C", 0x1F: "IEC_T"}
    assert ELEM_BYTES == {1: 1, 2: 1, 3: 1, 4: 2, 5: 2, 6: 4, 7: 4, 8: 4, 9: 2, 10: 4, 11: 4, 12: 2, 15: 8,
                          28: 2, 29: 2, 30: 12, 31: 4, 32: 4}
    assert s7comm.MAX_S7_PDU == 65535
    assert s7comm._COTP_TYPES == {0xE0, 0xD0, 0x80, 0xC0, 0xF0, 0x70, 0x60, 0x10, 0x20, 0x30}


@pytest.mark.parametrize("code,expected", sorted(EXPECTED_FUNCTIONS.items()))
def test_every_function_code_through_the_dissector(code, expected):
    m = one(job(bytes([code, 0, 0, 0, 0, 0, 0, 0])))
    assert (m.function, m.kinds) == expected and m.function_code == code and m.is_request


def test_header_fields_are_decoded_from_the_right_bytes():
    pdu = s7_pdu(1, 0xBEEF, bytes([0x04, 0]), b"")            # pduref 0xBEEF, parameter length 2, data length 0
    m = one(tpkt(cotp_dt() + pdu))
    assert m.transaction == 0xBEEF and m.details["pdu_ref"] == 0xBEEF and m.details["rosctr"] == "JOB"
    bad = bytearray(pdu)
    bad[6:8], bad[8:10] = struct.pack(">H", 0x0102), struct.pack(">H", 0x0304)   # lengths that cannot match
    assert "length_mismatch" in codes(one(tpkt(cotp_dt() + bytes(bad))))
    ack = one(job(bytes([0x05, 0]), rosctr=3, err=0x8104), client=False)
    assert ack.details["error_class"] == 0x81 and ack.details["error_code"] == 0x04 and ack.exception == 0x8104
    assert one(job(b"", rosctr=2, err=0), client=False).function == "ACK"
    assert "unknown_rosctr" in codes(one(job(bytes([0x04, 0]), rosctr=5)))


def item(area, db, byte_off, length, tsize, bit=0):
    addr = (byte_off << 3) | bit
    return (b"\x12\x0a\x10" + bytes([tsize]) + struct.pack(">HH", length, db) + bytes([area])
            + bytes([(addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF]))


def read_items(*items):
    return one(job(bytes([0x04, len(items)]) + b"".join(items))).details["items"]


def test_variable_item_fields_with_distinctive_values():
    it = read_items(item(0x84, 0x1234, 0x012345, 7, 2))[0]
    assert (it["area"], it["area_code"], it["db"], it["offset"], it["length"], it["length_bytes"], it["data_type"]) == \
        ("DB4660", 0x84, 0x1234, 0x012345, 7, 7, 2)
    assert it["address"] == 0x012345 << 3
    assert read_items(item(0x84, 1, 0xFFFF, 1, 2))[0]["offset"] == 0xFFFF
    bit_item = read_items(item(0x83, 0, 100, 1, 1, bit=5))[0]
    assert bit_item["bit"] == 5 and bit_item["offset"] == 100 and bit_item["area"] == "M"
    assert "bit" not in read_items(item(0x83, 0, 100, 1, 2))[0]


@pytest.mark.parametrize("tsize,width", sorted(ELEM_BYTES.items()))
def test_transport_size_widths(tsize, width):
    assert read_items(item(0x83, 0, 10, 3, tsize))[0]["length_bytes"] == 3 * width
    assert read_items(item(0x83, 0, 10, 0, tsize))[0]["length_bytes"] == 1     # zero length still addresses one byte


def test_unknown_transport_size_defaults_to_one_byte_and_areas():
    assert read_items(item(0x83, 0, 10, 5, 99))[0]["length_bytes"] == 5
    for code, name in AREAS.items():
        got = read_items(item(code, 0x55, 4, 1, 2))[0]["area"]
        assert got == ("DB%d" % 0x55 if code == 0x84 else name), code
    assert read_items(item(0x99, 0, 4, 1, 2))[0]["area"] == "AREA_0x99"


def test_item_list_validation_and_targets_for_writes():
    two = bytes([0x05, 2]) + item(0x84, 3, 8, 2, 2) + item(0x82, 0, 1, 1, 2)
    m = one(job(two, b"\x00\x04\x00\x10\xAA\xBB\x00\x00\x04\x00\x08\xCC"))
    assert [(t.area, t.start, t.end) for t in m.targets] == [("DB3", 8, 9), ("Q", 1, 1)] and not m.anomalies
    assert "bad_length" in codes(one(job(bytes([0x04]))))
    assert "bad_item" in codes(one(job(bytes([0x04, 1, 0x12]))))                 # item header cut
    assert "bad_item" in codes(one(job(bytes([0x04, 1, 0x12, 0x0A, 0x10]))))     # item body cut
    extra = bytes([0x04, 1]) + item(0x84, 1, 0, 1, 2) + b"\x00"
    assert "bad_length" in codes(one(job(extra)))
    odd = one(job(bytes([0x04, 1, 0x13, 3, 1, 2, 3])))
    assert odd.details["items"][0]["unparsed"] and odd.details.get("targets_unknown") is None
    odd_w = one(job(bytes([0x05, 1, 0x13, 3, 1, 2, 3]), b"\x00\x04\x00\x08\x01"))
    assert odd_w.details["targets_unknown"] is True and not odd_w.targets
    s7any_short = one(job(bytes([0x04, 1, 0x12, 9]) + bytes(9)))                 # spec 0x12 but length 9 != 10
    assert s7any_short.details["items"][0].get("unparsed")


def test_response_return_codes_and_exceptions():
    for code, name in RETURN_CODES.items():
        m = one(synth.s7_write_ack(3, [code]), client=False)
        assert m.details["return_codes"] == [name]
        assert ("exception" in m.kinds) == (code != 0xFF)
        assert (m.exception == code) == (code != 0xFF) or code == 0xFF
    assert one(synth.s7_write_ack(3, [0x77]), client=False).details["return_codes"] == ["0x77"]
    m = one(synth.s7_write_ack(3, [0xFF, 0x05, 0x03]), client=False)
    assert m.exception == 0x05 and m.details["return_codes"] == ["success", "invalid_address", "access_denied"]
    # read response: data items of different sizes and an odd-length first item followed by padding
    ack = synth.s7_read_ack(9, [b"\x01\x02\x03", b"\x04\x05"])
    assert one(ack, client=False).details["return_codes"] == ["success", "success"]
    bit_item = tpkt(cotp_dt() + s7_pdu(3, 9, bytes([0x04, 1]), bytes([0xFF, 0x03, 0x00, 0x09, 0x01, 0x01]), err=0))
    assert one(bit_item, client=False).details["return_codes"] == ["success"] and not one(bit_item, client=False).anomalies
    bad = tpkt(cotp_dt() + s7_pdu(3, 9, bytes([0x04, 2]), bytes([0xFF, 0x04, 0x00, 0x08, 0x01]), err=0))
    assert "bad_data_items" in codes(one(bad, client=False))


def test_download_upload_filename_decoding():
    for name, expected in (("_0A00001P", ("DB", "00001", "P")), ("_0800010A", ("OB", "00010", "A")),
                           ("_0C00007P", ("FC", "00007", "P")), ("_0E00123A", ("FB", "00123", "A")),
                           ("_0F00001P", ("SFB", "00001", "P")), ("_0B00001P", ("SDB", "00001", "P")),
                           ("_0D00001P", ("SFC", "00001", "P")), ("_ZZ00001P", ("ZZ", "00001", "P"))):
        m = one(synth.s7_request_download(name.encode()))
        d = m.details
        assert (d["block_type"], d["block_number"], d["destination"]) == expected, name
    short = one(synth.s7_request_download(b"_0A0001P"))                          # 8 chars: not the 9-char form
    assert short.details["filename"] == "_0A0001P" and "block_type" not in short.details
    nounder = one(synth.s7_request_download(b"X0A00001P"))
    assert "block_type" not in nounder.details


def test_pi_service_names_and_offsets():
    assert one(synth.s7_pi_service(b"_INSE", args=b"\x01\x02\x03")).details["service"] == "_INSE"
    assert one(synth.s7_pi_service(b"P_PROGRAM")).details["service"] == "P_PROGRAM"
    stop = one(synth.s7_plc_stop())
    assert stop.details["service"] == "P_PROGRAM" and stop.function == "PLC_STOP"


# ---- userdata ---------------------------------------------------------------------------------------------------------------
def test_userdata_subfunctions_and_fields():
    szl = b"\xff\x09\x00\x04\x01\x23\x45\x67"                                    # szl id 0x0123, index 0x4567
    m = one(synth.s7_userdata(4, 1, data=szl))
    assert (m.function, m.details["szl_id"], m.details["szl_index"]) == ("READ_SZL", 0x0123, 0x4567)
    assert m.details["group"] == "CPU_FUNCTIONS" and m.details["subfunction"] == 1 and m.kinds == {"discovery"}
    assert "szl_id" not in one(synth.s7_userdata(4, 1, data=szl[:7])).details
    for sub, name in {1: "LIST_BLOCKS", 2: "LIST_BLOCKS_OF_TYPE", 3: "GET_BLOCK_INFO"}.items():
        m = one(synth.s7_userdata(3, sub))
        assert m.function == name and m.kinds == {"discovery"} and m.details["group"] == "BLOCK_FUNCTIONS"
    assert one(synth.s7_userdata(3, 9)).function == "USERDATA_BLOCK_FUNCTIONS"
    for sub, name, kind in ((1, "READ_CLOCK", "diagnostic"), (2, "SET_CLOCK", "maintenance"),
                            (3, "READ_CLOCK_FOLLOWING", "diagnostic"), (4, "SET_CLOCK", "maintenance")):
        m = one(synth.s7_userdata(7, sub))
        assert m.function == name and m.kinds == {kind}
    assert one(synth.s7_userdata(7, 9)).function == "USERDATA_TIME_FUNCTIONS"
    for g, name in UD_GROUPS.items():
        if g not in (3, 4, 7):
            m = one(synth.s7_userdata(g, 5))
            assert m.function == "USERDATA_" + name and m.kinds == {"other"}
    req = one(synth.s7_userdata(4, 1, typ=4))
    resp = one(synth.s7_userdata(4, 1, typ=8), client=False)
    assert req.is_request and not resp.is_request
    err = tpkt(cotp_dt() + s7_pdu(7, 1, b"\x00\x01\x12\x08\x12\x84\x01\x01\x00\x00\xd4\x01"))
    m = one(err, client=False)
    assert m.exception == 0xD401 and m.details["error_code"] == 0xD401 and "exception" in m.kinds
    ok = tpkt(cotp_dt() + s7_pdu(7, 1, b"\x00\x01\x12\x08\x12\x84\x01\x01\x00\x00\x00\x00"))
    assert one(ok, client=False).exception is None and "exception" not in one(ok, client=False).kinds
    assert "bad_userdata" in codes(one(tpkt(cotp_dt() + s7_pdu(7, 1, b"\x00\x01\x12\x04\x11\x44\x01"))))
    assert "bad_userdata" in codes(one(tpkt(cotp_dt() + s7_pdu(7, 1, b"\x00\x02\x12\x04\x11\x44\x01\x00"))))


# ---- COTP ---------------------------------------------------------------------------------------------------------------------------
def cr(calling, called, tpdu=None):
    params = b"\xc1\x02" + calling + b"\xc2\x02" + called
    if tpdu is not None:
        params += b"\xc0\x01" + bytes([tpdu])
    body = b"\xe0\x00\x00\x00\x01\x00" + params
    return tpkt(bytes([len(body)]) + body)


def test_tsap_decoding_and_tpdu_size():
    m = one(cr(b"\x01\x00", b"\xa5\xa7", tpdu=10))
    assert m.details["calling"] == {"tsap": "0100", "connection_type": "PG", "rack": 0, "slot": 0}
    assert m.details["called"] == {"tsap": "a5a7", "connection_type": "0xa5", "rack": 5, "slot": 7}
    for first, name in ((1, "PG"), (2, "OP"), (3, "S7_BASIC"), (4, "0x04")):
        assert one(cr(bytes([first, 0x21]), b"\x01\x02")).details["calling"]["connection_type"] == name
    d = one(cr(b"\x03\x21", b"\x01\x02")).details["calling"]
    assert (d["rack"], d["slot"]) == (1, 1)
    d = one(cr(b"\x01\xff", b"\x01\x02")).details["calling"]
    assert (d["rack"], d["slot"]) == (7, 31)
    assert m.details["tpdu_size"] == 1024 and one(cr(b"\x01\x00", b"\x01\x02", tpdu=7)).details["tpdu_size"] == 128
    assert one(cr(b"\x01\x00", b"\x01\x02", tpdu=15)).details["tpdu_size"] == 32768
    assert one(cr(b"\x01\x00", b"\x01\x02", tpdu=16)).details["tpdu_size"] is None
    three = tpkt(bytes([9, 0xE0, 0, 0, 0, 1, 0, 0xC1, 1, 5]))                     # a 1-byte TSAP is kept as raw hex
    assert one(three).details["calling"] == {"tsap": "05"}
    assert "bad_cotp" in codes(one(tpkt(bytes([5, 0xE0, 0, 0, 0, 1]))))            # connection TPDU shorter than 6


def test_cotp_structure_and_resync_boundaries():
    assert "bad_cotp" in codes(one(tpkt(bytes([0, 0xF0, 0x80, 0x32]))))            # length indicator 0
    assert "bad_cotp" in codes(one(tpkt(bytes([200, 0xF0, 0x80, 0x32, 0, 0, 0]))))  # indicator beyond the TPKT
    assert S7Dissector().feed_stream(True, tpkt(bytes([2, 0xF0, 0x80])), False) == []   # empty DT body: nothing to report
    d = S7Dissector()
    assert d.feed_stream(True, b"\x03\x00\x00", False) == []                          # 3 bytes: wait for the 4-byte TPKT header
    garbage = S7Dissector().feed_stream(True, b"\x41" * 4 + synth.s7_setup(0), False)
    assert garbage[0].function == "MALFORMED" and garbage[-1].function == "SETUP_COMMUNICATION"
    many = S7Dissector().feed_stream(True, b"\x41\x42\x43\x44" * 30, False)
    assert len([m for m in many if m.function == "MALFORMED"]) <= 8
    # a candidate TPKT inside junk is only accepted with a plausible COTP header after it
    junk = b"\x99" + b"\x03\x00\x00\x30\x02\xf0\x80" + b"\x00" * 3
    out = S7Dissector().feed_stream(True, junk, False)
    assert all(m.function == "MALFORMED" for m in out)
    d = S7Dissector()
    out = d.feed_stream(True, b"\x03\x00\x00\x08\x00\xf0\x80\x32" + synth.s7_setup(0), False)   # li = 0 is not a valid start
    assert out[-1].function == "SETUP_COMMUNICATION"


# ---- S7CommPlus ----------------------------------------------------------------------------------------------------------------------
def test_s7commplus_tables_and_fields_with_distinctive_values():
    assert S7PLUS_OPCODES == {0x31: "REQUEST", 0x32: "RESPONSE", 0x33: "NOTIFICATION"}
    expected = {0x04B1: ("ERROR", {"exception"}), 0x04BB: ("EXPLORE", {"read"}), 0x04CA: ("CREATE_OBJECT", {"maintenance"}),
                0x04D4: ("DELETE_OBJECT", {"maintenance"}), 0x04F2: ("SET_VARIABLE", {"write"}),
                0x0524: ("GET_LINK", {"read"}), 0x0542: ("SET_MULTI_VARIABLES", {"write"}),
                0x054C: ("GET_MULTI_VARIABLES", {"read"}), 0x0556: ("BEGIN_SEQUENCE", {"maintenance"}),
                0x0560: ("END_SEQUENCE", {"maintenance"}), 0x056B: ("INVOKE", {"other"}),
                0x0586: ("SET_VAR_SUBSTREAMED", {"write"}), 0x0592: ("GET_VAR_SUBSTREAMED", {"read"}),
                0x059A: ("ABORT", {"maintenance"})}
    assert {k: (v[0], set(v[1])) for k, v in S7PLUS_FUNCTIONS.items()} == expected
    m = one(synth.s7plus_pdu(0x31, 0x0542, seq=0xABCD, session=0x01020304, version=3))
    assert (m.function, m.transaction, m.details["session"], m.details["version"]) == ("S7PLUS_SET_MULTI_VARIABLES", 0xABCD,
                                                                                     0x01020304, 3)
    assert m.details["function_code"] == 0x0542 and m.details["opcode"] == "REQUEST" and not m.anomalies
    assert one(synth.s7plus_pdu(0x32, 0x0542), client=False).details["opcode"] == "RESPONSE"
    for ver in (1, 2, 3):
        assert not codes(one(synth.s7plus_pdu(0x31, 0x04BB, version=ver)))
    for ver in (0, 4):
        assert "bad_s7plus_version" in codes(one(synth.s7plus_pdu(0x31, 0x04BB, version=ver)))
    exact = synth.s7plus_pdu(0x31, 0x04BB)
    assert not codes(one(exact))
    declared = bytearray(exact)
    n = len(exact) - 7 - 4                                                    # real data length after the 4-byte header
    declared[9:11] = struct.pack(">H", n + 1)                                  # one byte more than present
    assert "length_mismatch" in codes(one(bytes(declared)))
    declared[9:11] = struct.pack(">H", n)
    assert not codes(one(bytes(declared)))
    assert one(synth.s7plus_pdu(0x31, 0x04BB)).function != "S7COMMPLUS"
    short = tpkt(cotp_dt() + bytes([0x72, 1, 0, 12]) + bytes([0x31]) + bytes(11))   # 16 bytes: one short of a full header
    assert one(short).function == "S7COMMPLUS"
