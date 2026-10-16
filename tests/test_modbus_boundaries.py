"""Exact-boundary tests for every Modbus limit (found weak by mutation testing: see docs/VALIDATION.md)."""

import struct

import pytest

from quietwire import synth
from types import SimpleNamespace

from quietwire.proto.modbus import (DEVICE_ID_OBJECTS, DIAG_SUBFUNCTIONS, EXCEPTIONS, FUNCTIONS, ModbusDissector,
                                    parse_adu, parse_pdu)
from quietwire.synth import mb_adu


def msg(pdu, request=True, unit=1):
    """Decode a PDU through the full ADU path when it fits (<= 253 PDU bytes), else via parse_pdu directly
    (limits such as 124 registers or 252 file-record bytes exceed the 260-byte ADU maximum by themselves)."""
    if len(pdu) <= 253:
        out = ModbusDissector().feed_stream(request, mb_adu(1, unit, pdu), False)
        assert len(out) == 1
        return out[0]
    name, kinds, targets, details, anomalies, exc = parse_pdu(pdu[0], pdu[1:], request)
    return SimpleNamespace(function=name, kinds=kinds, targets=targets, details=details, anomalies=anomalies,
                           exception=exc)


def codes(m):
    return [a.code for a in m.anomalies]


# ---- specification tables ------------------------------------------------------------------------
def test_exception_code_names_follow_the_specification():
    assert EXCEPTIONS == {1: "ILLEGAL_FUNCTION", 2: "ILLEGAL_DATA_ADDRESS", 3: "ILLEGAL_DATA_VALUE",
                          4: "SERVER_DEVICE_FAILURE", 5: "ACKNOWLEDGE", 6: "SERVER_DEVICE_BUSY",
                          8: "MEMORY_PARITY_ERROR", 10: "GATEWAY_PATH_UNAVAILABLE",
                          11: "GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND"}
    for code, name in EXCEPTIONS.items():
        assert msg(bytes([0x83, code]), request=False).details["exception_name"] == name
    assert msg(bytes([0x83, 7]), request=False).details["exception_name"] == "UNKNOWN_7"


def test_function_table_matches_the_public_function_codes():
    expected = {1: "READ_COILS", 2: "READ_DISCRETE_INPUTS", 3: "READ_HOLDING_REGISTERS", 4: "READ_INPUT_REGISTERS",
                5: "WRITE_SINGLE_COIL", 6: "WRITE_SINGLE_REGISTER", 7: "READ_EXCEPTION_STATUS", 8: "DIAGNOSTICS",
                11: "GET_COMM_EVENT_COUNTER", 12: "GET_COMM_EVENT_LOG", 15: "WRITE_MULTIPLE_COILS",
                16: "WRITE_MULTIPLE_REGISTERS", 17: "REPORT_SERVER_ID", 20: "READ_FILE_RECORD",
                21: "WRITE_FILE_RECORD", 22: "MASK_WRITE_REGISTER", 23: "READ_WRITE_MULTIPLE_REGISTERS",
                24: "READ_FIFO_QUEUE", 43: "ENCAPSULATED_INTERFACE_TRANSPORT"}
    assert {k: v[0] for k, v in FUNCTIONS.items()} == expected
    assert FUNCTIONS[11][1] == {"diagnostic"} and FUNCTIONS[12][1] == {"diagnostic"}
    assert FUNCTIONS[17][1] == {"discovery"} and FUNCTIONS[23][1] == {"read", "write"}


def test_diagnostic_subfunction_names_and_device_id_objects():
    assert DIAG_SUBFUNCTIONS == {
        0x0000: "RETURN_QUERY_DATA", 0x0001: "RESTART_COMMUNICATIONS_OPTION", 0x0002: "RETURN_DIAGNOSTIC_REGISTER",
        0x0003: "CHANGE_ASCII_INPUT_DELIMITER", 0x0004: "FORCE_LISTEN_ONLY_MODE",
        0x000A: "CLEAR_COUNTERS_AND_DIAGNOSTIC_REGISTER", 0x000B: "RETURN_BUS_MESSAGE_COUNT",
        0x000C: "RETURN_BUS_COMMUNICATION_ERROR_COUNT", 0x000D: "RETURN_BUS_EXCEPTION_ERROR_COUNT",
        0x000E: "RETURN_SERVER_MESSAGE_COUNT", 0x000F: "RETURN_SERVER_NO_RESPONSE_COUNT",
        0x0010: "RETURN_SERVER_NAK_COUNT", 0x0011: "RETURN_SERVER_BUSY_COUNT",
        0x0012: "RETURN_BUS_CHARACTER_OVERRUN_COUNT", 0x0014: "CLEAR_OVERRUN_COUNTER_AND_FLAG"}
    for sub, name in DIAG_SUBFUNCTIONS.items():
        assert msg(synth.mb_diag(sub)).details["subfunction_name"] == name
    assert DEVICE_ID_OBJECTS == {0: "VendorName", 1: "ProductCode", 2: "MajorMinorRevision", 3: "VendorUrl",
                                 4: "ProductName", 5: "ModelName", 6: "UserApplicationName"}
    objs = [(i, b"v%d" % i) for i in range(7)]
    r = msg(synth.mb_device_id_response(objs), request=False)
    assert r.details["device_id"] == {name: "v%d" % i for i, name in DEVICE_ID_OBJECTS.items()}
    assert "object_9" in msg(synth.mb_device_id_response([(9, b"x")]), request=False).details["device_id"]


# ---- quantity / byte-count boundaries ------------------------------------------------------------------
def write_coils(qty, byte_count=None, start=0):
    bc = (qty + 7) // 8 if byte_count is None else byte_count
    return bytes([15]) + struct.pack(">HHB", start, qty, bc) + bytes(bc)


@pytest.mark.parametrize("qty,ok", [(0, False), (1, True), (1968, True), (1969, False)])
def test_write_multiple_coils_quantity_limits(qty, ok):
    m = msg(write_coils(qty, start=10))
    assert ("bad_quantity" not in codes(m)) == ok
    if ok:
        assert (m.targets[0].start, m.targets[0].end) == (10, 10 + qty - 1) and not m.anomalies
    else:
        assert not m.targets


def test_write_multiple_coils_byte_count_must_match_exactly():
    assert "bad_byte_count" in codes(msg(write_coils(16, byte_count=3)))
    assert "bad_byte_count" in codes(msg(write_coils(16, byte_count=1)))
    assert not codes(msg(write_coils(17)))
    assert "bad_length" in codes(msg(bytes([15, 0, 0, 0, 1])))               # one byte too short for the fixed part
    short = bytes([15]) + struct.pack(">HHB", 0, 8, 1)                        # byte count promises 1, none present
    assert "bad_byte_count" in codes(msg(short))


def write_regs(qty, byte_count=None, start=0):
    bc = 2 * qty if byte_count is None else byte_count
    return bytes([16]) + struct.pack(">HHB", start, qty, bc) + bytes(bc)


@pytest.mark.parametrize("qty,ok", [(0, False), (1, True), (123, True), (124, False)])
def test_write_multiple_registers_quantity_limits(qty, ok):
    m = msg(write_regs(qty, start=7))
    assert ("bad_quantity" not in codes(m)) == ok
    assert bool(m.targets) == ok
    if ok:
        assert (m.targets[0].start, m.targets[0].end) == (7, 7 + qty - 1)


def test_write_multiple_registers_byte_count_and_header_length():
    assert "bad_byte_count" in codes(msg(write_regs(4, byte_count=7)))
    assert "bad_byte_count" in codes(msg(write_regs(4, byte_count=9)))
    assert "bad_length" in codes(msg(bytes([16, 0, 0, 0])))                    # fewer than 5 PDU data bytes


def rw(read_qty, write_qty, bc=None):
    bc = 2 * write_qty if bc is None else bc
    return bytes([23]) + struct.pack(">HHHHB", 5, read_qty, 100, write_qty, bc) + bytes(bc)


@pytest.mark.parametrize("rq,wq,ok", [(1, 1, True), (125, 121, True), (126, 1, False), (1, 122, False),
                                       (0, 1, False), (1, 0, False)])
def test_read_write_multiple_limits(rq, wq, ok):
    m = msg(rw(rq, wq))
    assert ("bad_quantity" not in codes(m)) == ok
    if ok:
        assert not m.anomalies and (m.details["read_start"], m.details["write_start"]) == (5, 100)
    # the write target is only trusted when the *write* quantity is valid, whatever the read quantity is
    assert bool(m.targets) == (1 <= wq <= 121)
    if m.targets:
        assert (m.targets[0].start, m.targets[0].end) == (100, 100 + wq - 1)


def test_read_write_multiple_byte_count_and_minimum_length():
    assert "bad_byte_count" in codes(msg(rw(1, 2, bc=3)))
    assert "bad_length" in codes(msg(bytes([23]) + bytes(8)))                  # needs 9 bytes before the data
    assert not codes(msg(bytes([23]) + struct.pack(">HHHHB", 0, 1, 0, 1, 2) + b"\0\0"))


def test_read_requests_exact_length_and_quantity_boundaries():
    assert "bad_length" in codes(msg(bytes([3, 0, 0, 0])))
    assert "bad_length" in codes(msg(bytes([3, 0, 0, 0, 1, 0])))
    for fc, limit in ((1, 2000), (2, 2000), (3, 125), (4, 125)):
        assert not codes(msg(synth.mb_read(fc, 0, limit)))
        assert "bad_quantity" in codes(msg(synth.mb_read(fc, 0, limit + 1)))
        assert "bad_quantity" in codes(msg(synth.mb_read(fc, 0, 0)))
        assert not codes(msg(synth.mb_read(fc, 0, 1)))


def test_single_write_value_and_length_boundaries():
    for bad in (0x0001, 0xFF01, 0x00FF, 0x8000):
        assert "bad_value" in codes(msg(bytes([5]) + struct.pack(">HH", 1, bad)))
    for good in (0x0000, 0xFF00):
        assert not codes(msg(bytes([5]) + struct.pack(">HH", 1, good)))
    assert "bad_length" in codes(msg(bytes([5, 0, 1, 0xFF])))
    assert "bad_length" in codes(msg(bytes([6, 0, 1, 0, 2, 0])))
    assert "bad_length" in codes(msg(bytes([22, 0, 1, 0, 2, 0, 3, 0])))
    m = msg(bytes([22]) + struct.pack(">HHH", 9, 0xF0F0, 0x0F0F))
    assert (m.details["and_mask"], m.details["or_mask"], m.details["start"]) == (0xF0F0, 0x0F0F, 9)


def test_no_data_functions_reject_any_payload():
    for fc in (7, 11, 12, 17):
        assert not codes(msg(bytes([fc])))
        assert "bad_length" in codes(msg(bytes([fc, 0])))


def test_diagnostics_and_fifo_length_boundaries():
    assert "bad_length" in codes(msg(bytes([8, 0])))
    assert not codes(msg(bytes([8, 0, 0])))
    assert msg(bytes([8, 0x12, 0x34, 0xAA, 0xBB])).details["subfunction"] == 0x1234
    assert "bad_length" in codes(msg(bytes([24, 0])))
    assert "bad_length" in codes(msg(bytes([24, 0, 1, 2])))
    assert msg(bytes([24, 0x12, 0x34])).details["start"] == 0x1234


def sub_req_read(n):
    return bytes([20, 7 * n]) + b"".join(bytes([6, 0, 4, 0, 1, 0, 2]) for _ in range(n))


def test_read_file_record_byte_count_boundaries():
    assert not codes(msg(sub_req_read(1))) and msg(sub_req_read(1)).details["sub_requests"] == 1
    assert not codes(msg(sub_req_read(35)))                                   # 245 bytes = 0xF5
    assert "bad_byte_count" in codes(msg(bytes([20, 252]) + bytes(252)))      # 252 > 0xF5 even though 252 % 7 == 0
    assert "bad_byte_count" in codes(msg(bytes([20, 6]) + bytes(6)))
    assert "bad_byte_count" in codes(msg(bytes([20, 8]) + bytes(8)))
    assert "bad_byte_count" in codes(msg(bytes([20, 7]) + bytes(8)))          # byte count disagrees with the length
    assert "bad_byte_count" in codes(msg(bytes([20])))


def write_file(n_words):
    sub = bytes([6, 0, 4, 0, 1]) + struct.pack(">H", n_words) + bytes(2 * n_words)
    return bytes([21, len(sub)]) + sub


def test_write_file_record_byte_count_boundaries():
    assert not codes(msg(write_file(1))) and msg(write_file(1)).details["sub_requests"] == 1   # 9 bytes: the minimum
    assert not codes(msg(write_file(122)))                                                       # 251 bytes: the maximum
    assert "bad_byte_count" in codes(msg(write_file(123)))                                       # 253 bytes
    assert "bad_byte_count" in codes(msg(bytes([21, 8]) + bytes(8)))
    assert "bad_byte_count" in codes(msg(bytes([21, 9]) + bytes(10)))
    two = bytes([21, 9 + 11]) + bytes([6, 0, 4, 0, 1, 0, 1, 0, 0]) + bytes([6, 0, 5, 0, 1, 0, 2, 0, 0, 0, 0])
    assert msg(two).details["sub_requests"] == 2 and not codes(msg(two))
    assert "bad_file_record" in codes(msg(bytes([21, 10]) + bytes([6, 0, 4, 0, 1, 0, 1, 0, 0, 7])))   # trailing byte


# ---- responses -------------------------------------------------------------------------------------------
def test_response_byte_count_rules_per_function():
    for fc in (1, 2):
        assert not codes(msg(bytes([fc, 2, 0xFF, 0x01]), request=False))
        assert "bad_byte_count" in codes(msg(bytes([fc, 3, 0xFF, 0x01]), request=False))
        assert "bad_byte_count" in codes(msg(bytes([fc]), request=False))
    for fc in (3, 4):
        assert not codes(msg(bytes([fc, 2, 0, 5]), request=False))
        assert "bad_byte_count" in codes(msg(bytes([fc, 3, 0, 5, 0]), request=False))   # odd register byte count
        assert "bad_byte_count" in codes(msg(bytes([fc, 2, 0]), request=False))
        assert msg(bytes([fc, 4, 0, 5, 1, 0]), request=False).details["values"] == [5, 256]
        assert not codes(msg(bytes([fc, 0]), request=False))                            # zero registers is structurally fine
    for fc in (12, 17, 20):
        assert not codes(msg(bytes([fc, 2, 7, 7]), request=False))
        assert "bad_byte_count" in codes(msg(bytes([fc, 3, 7, 7]), request=False))
        assert "bad_byte_count" in codes(msg(bytes([fc]), request=False))
    assert not codes(msg(bytes([23, 2, 0, 5]), request=False))
    assert "bad_byte_count" in codes(msg(bytes([23, 3, 0, 5, 0]), request=False))


def test_response_fixed_length_functions():
    for fc in (5, 6, 15, 16, 11):
        assert not codes(msg(bytes([fc, 0, 1, 0, 2]), request=False))
        assert "bad_length" in codes(msg(bytes([fc, 0, 1, 0]), request=False))
        assert "bad_length" in codes(msg(bytes([fc, 0, 1, 0, 2, 0]), request=False))
    assert not codes(msg(bytes([7, 0xAA]), request=False))
    assert "bad_length" in codes(msg(bytes([7]), request=False)) and "bad_length" in codes(msg(bytes([7, 1, 2]), request=False))
    assert not codes(msg(bytes([22]) + bytes(6), request=False))
    assert "bad_length" in codes(msg(bytes([22]) + bytes(5), request=False))
    assert msg(bytes([8, 0x12, 0x34, 0, 0]), request=False).details["subfunction"] == 0x1234
    assert "bad_length" in codes(msg(bytes([8, 0]), request=False))


def test_fifo_response_boundaries():
    assert not codes(msg(bytes([24, 0, 2, 0, 0]), request=False))                       # empty queue
    assert not codes(msg(bytes([24, 0, 4, 0, 1, 0, 2]), request=False))
    assert "bad_byte_count" in codes(msg(bytes([24, 0, 3, 0]), request=False))          # too short
    assert "bad_byte_count" in codes(msg(bytes([24, 0, 4, 0, 1, 0]), request=False))    # count disagrees with length
    assert "bad_byte_count" in codes(msg(bytes([24, 0, 2, 0, 0, 9]), request=False))


def test_server_id_hex_is_capped_at_32_bytes():
    assert msg(bytes([17, 40]) + bytes(range(40)), request=False).details["server_id_hex"] == bytes(range(32)).hex()
    assert msg(bytes([17, 2, 0xAB, 0xCD]), request=False).details["server_id_hex"] == "abcd"


def test_device_id_response_boundaries():
    assert "bad_length" in codes(msg(bytes([43]), request=False))
    assert "bad_device_id_response" in codes(msg(bytes([43, 0x0E, 1, 1, 0]), request=False))      # 5 bytes: header cut
    assert not codes(msg(bytes([43, 0x0E, 1, 1, 0, 0, 0]), request=False))                        # exactly 6, zero objects
    exact = bytes([43, 0x0E, 1, 1, 0, 0, 1, 0, 2]) + b"ab"
    assert msg(exact, request=False).details["device_id"] == {"VendorName": "ab"} and not codes(msg(exact, request=False))
    assert "bad_device_id_response" in codes(msg(exact[:-1], request=False))                        # object overruns by one
    assert "bad_device_id_response" in codes(msg(bytes([43, 0x0E, 1, 1, 0, 0, 1, 0]), request=False))  # no length byte
    assert not codes(msg(bytes([43, 0x0D]), request=False))
    assert msg(bytes([43, 0x0D]), request=False).details["mei_type"] == 0x0D


def test_exception_pdu_boundaries():
    assert "bad_exception_length" in codes(msg(bytes([0x83]), request=False))
    assert "bad_exception_length" in codes(msg(bytes([0x83, 1, 2]), request=False))
    assert not codes(msg(bytes([0x83, 1]), request=False))
    assert "exception_in_request" in codes(msg(bytes([0x83, 1]), request=True))


# ---- framing boundaries -----------------------------------------------------------------------------------
def header(length, pid=0, unit=1, tid=1):
    return struct.pack(">HHHB", tid, pid, length, unit)


@pytest.mark.parametrize("length,ok", [(1, False), (2, True), (254, True), (255, False), (0x8804, False)])
def test_mbap_length_field_boundaries(length, ok):
    frame = header(length) + bytes([3]) + bytes(max(0, length - 2))
    out = ModbusDissector().feed_stream(True, frame, False)
    assert (out[0].function != "MALFORMED") == ok


def test_protocol_id_bytes_must_both_be_zero():
    for pid in (0x0001, 0x0100, 0x8000):
        out = ModbusDissector().feed_stream(True, header(6, pid) + bytes([3, 0, 0, 0, 1]), False)
        assert out[0].function == "MALFORMED"


def test_seven_byte_header_alone_waits_for_the_rest_and_six_bytes_are_not_examined():
    d = ModbusDissector()
    assert d.feed_stream(True, header(6)[:6], False) == []
    assert d.feed_stream(True, bytes([1]), False) == []                          # header complete, body missing
    out = d.feed_stream(True, bytes([3, 0, 0, 0, 1]), False)
    assert out and out[0].function == "READ_HOLDING_REGISTERS"


def test_resync_requires_a_complete_plausible_frame_and_counts_each_burst_once():
    good = mb_adu(5, 1, synth.mb_read(3, 0, 1))
    d = ModbusDissector()
    out = d.feed_stream(True, b"\xff" * 5, False)
    assert out == [] or out[0].function == "MALFORMED"
    d = ModbusDissector()
    junk = b"\xaa" * 9
    out = d.feed_stream(True, junk + good, False)
    assert [m.function for m in out].count("MALFORMED") == 1 and out[-1].function == "READ_HOLDING_REGISTERS"
    d = ModbusDissector()
    chunk_boundary = d.feed_stream(True, junk, False)                              # junk alone, then a clean segment
    out2 = d.feed_stream(True, good, False)
    assert out2 and out2[-1].function == "READ_HOLDING_REGISTERS"
    many = ModbusDissector().feed_stream(True, (b"\xff" * 7 + b"\x00") * 40, False)
    assert len([m for m in many if m.function == "MALFORMED"]) <= 8                # MAX_MALFORMED_PER_FEED bounds the output


def test_parse_adu_without_a_function_code_and_unit_zero_broadcast():
    m = parse_adu(header(1, unit=0), True)
    assert m.function == "EMPTY_PDU" and m.unit == 0 and m.transaction == 1
    assert msg(synth.mb_write_single_register(1, 1), unit=0).broadcast
    assert not msg(synth.mb_read(3, 0, 1), unit=0).kinds & {"write"}
