import os
import random

from quietwire import synth
from quietwire.proto.identify import identify, looks_like_dnp3, looks_like_modbus, looks_like_s7


def test_each_protocol_identified():
    assert identify(synth.mb_adu(1, 1, synth.mb_read(3, 0, 4))) == "modbus"
    assert identify(synth.mb_adu(1, 1, synth.mb_resp_registers(3, [1, 2]))) == "modbus"
    assert identify(synth.dnp3_frames(1, 2, synth.dnp3_app(1), True)[0]) == "dnp3"
    assert identify(synth.s7_setup(0)) == "s7comm"
    assert identify(synth.tpkt(synth.cotp_cr())) == "s7comm"


def test_negative_cases():
    assert identify(b"") is None
    assert identify(b"GET / HTTP/1.1\r\n\r\n") is None
    assert identify(b"\x16\x03\x01\x00\x85" + b"\x01" * 130) is None  # TLS ClientHello
    assert identify(bytes(64)) is None  # all zeros: length field 0 is not a Modbus ADU
    assert not looks_like_dnp3(b"\x05\x64\x05\xc0\x01\x00\x00\x04\x00\x00")  # right start bytes, wrong CRC
    assert not looks_like_s7(b"\x03\x00\x00\x08\x02\xf0\x80\x99")  # TPKT/COTP fine, payload not S7
    assert not looks_like_modbus(synth.mb_adu(1, 1, bytes([0x5A, 1, 2])))  # undefined function code


def test_modbus_requires_structurally_valid_pdu():
    assert not looks_like_modbus(synth.mb_adu(1, 1, synth.mb_read(3, 0, 0)))  # quantity 0 fails both directions
    assert not looks_like_modbus(synth.mb_adu(1, 1, bytes([16, 0, 0, 0, 1, 9])))


def test_random_data_has_no_false_positives():
    rng = random.Random(99)
    hits = 0
    for _ in range(20000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 80)))
        hits += identify(blob) is not None
    assert hits == 0
