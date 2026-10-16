"""Minimal S7CommPlus (0x72) decoding: header, opcode, function, sequence number and session."""

import pytest

from conftest import alerts_for, run
from quietwire import synth
from quietwire.model import Severity
from quietwire.proto.s7comm import S7PLUS_FUNCTIONS, S7Dissector
from quietwire.synth import EWS, S7_PLC, Conn, PcapBuilder, s7plus_pdu


def one(frame, client=True):
    msgs = S7Dissector().feed_stream(client, frame, False)
    assert len(msgs) == 1
    return msgs[0]


def test_header_layout_matches_real_capture_bytes():
    # first 17 bytes of the first request after the COTP handshake in a real S7-1200 capture (nDPI s7comm-plus.pcap)
    real = bytes.fromhex("720100ca31000004ca00000001000001 20".replace(" ", ""))
    built = s7plus_pdu(0x31, 0x04CA, seq=1, session=0x120, data_len=0xCA)
    assert built[7:7 + len(real)] == real          # after TPKT(4) + COTP DT(3)
    m = one(built)
    assert (m.function, m.is_request, m.transaction) == ("S7PLUS_CREATE_OBJECT", True, 1)
    assert m.details["version"] == 1 and m.details["opcode"] == "REQUEST" and m.details["session"] == 0x120


@pytest.mark.parametrize("code,entry", sorted(S7PLUS_FUNCTIONS.items()))
def test_function_table(code, entry):
    req = one(s7plus_pdu(0x31, code, seq=7))
    assert req.function == "S7PLUS_" + entry[0] and req.kinds == entry[1] and req.is_request and not req.anomalies
    resp = one(s7plus_pdu(0x32, code, seq=7), client=False)
    assert not resp.is_request and "write" not in resp.kinds and resp.transaction == 7


def test_unknown_function_and_other_opcodes():
    m = one(s7plus_pdu(0x31, 0x7777))
    assert m.function == "S7PLUS_0x7777" and "unknown_function" in m.kinds
    n = one(s7plus_pdu(0x33, 0x0000))                       # notification: recognised, not decoded further
    assert n.function == "S7COMMPLUS" and n.kinds == {"other"}
    k = one(s7plus_pdu(0x02, 0x0000))                       # unknown opcode
    assert k.function == "S7COMMPLUS"


def test_anomalies():
    assert "bad_s7plus_version" in [a.code for a in one(s7plus_pdu(0x31, 0x04F2, version=9)).anomalies]
    assert "length_mismatch" in [a.code for a in one(s7plus_pdu(0x31, 0x04F2, data_len=900)).anomalies]
    short = synth.tpkt(synth.cotp_dt() + b"\x72\x01\x00")
    assert one(short).function == "MALFORMED"
    tiny = synth.tpkt(synth.cotp_dt() + b"\x72\x01\x00\x01\x31")  # header + 1 byte: not enough for a function
    assert one(tiny).function == "S7COMMPLUS"


def capture(*pdus, client=EWS):
    pb = PcapBuilder()
    c = Conn(pb, client, S7_PLC, 40000, 102)
    c.open()
    c.push(True, synth.tpkt(synth.cotp_cr()))
    for from_client, pdu in pdus:
        c.push(from_client, pdu)
    return pb


def test_writes_over_s7commplus_are_visible_to_policy_rules():
    pb = capture((True, s7plus_pdu(0x31, 0x04CA, 1)), (False, s7plus_pdu(0x32, 0x04CA, 1)),
                 (True, s7plus_pdu(0x31, 0x0542, 2)), (False, s7plus_pdu(0x32, 0x0542, 2)),
                 (True, s7plus_pdu(0x31, 0x054C, 3)), (False, s7plus_pdu(0x32, 0x054C, 3)))
    r = run(pb)
    w = alerts_for(r, "QW-W002")
    assert len(w) == 1 and w[0].details["function"] == "S7PLUS_SET_MULTI_VARIABLES" and w[0].count == 1
    assert not alerts_for(r, "QW-S001") and r.stats.messages["s7comm"] == 7  # COTP CR + 6 PDUs, pairs matched
    bad = run(pb, {"writers": {"s7comm": ["10.9.9.9"]}})
    assert alerts_for(bad, "QW-W001")[0].severity is Severity.HIGH
    rng = {"write_ranges": [{"server": S7_PLC, "protocol": "s7comm", "area": "DB1", "start": 0, "end": 9}]}
    a = alerts_for(run(pb, rng), "QW-W003")
    assert a and "could not be determined" in a[0].message   # targets of S7CommPlus writes are not decoded


def test_policy_accepts_s7plus_function_names_and_flags_others():
    pb = capture((True, s7plus_pdu(0x31, 0x054C, 3)), (True, s7plus_pdu(0x31, 0x04D4, 4)))
    pol = {"allowed_functions": [{"master": EWS, "server": S7_PLC, "protocol": "s7comm",
                                  "functions": ["S7PLUS_GET_MULTI_VARIABLES", "S7PLUS_CREATE_OBJECT"]}]}
    r = run(pb, pol)
    assert [a.details["function"] for a in alerts_for(r, "QW-F002")] == ["S7PLUS_DELETE_OBJECT"]
