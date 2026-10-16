from quietwire.synth import dnp_crc
from quietwire.util import crc16_dnp, hexdump_short, iso_ts


def test_crc_catalogue_check_value():
    # CRC RevEng catalogue: CRC-16/DNP check value for "123456789"
    assert crc16_dnp(b"123456789") == 0xEA82


def test_crc_matches_independent_bitwise_implementation():
    for blob in (b"", b"\x00", b"\xff" * 33, bytes(range(256)), b"DNP3 test"):
        assert crc16_dnp(blob) == dnp_crc(blob)


def test_crc_known_link_header():
    # published DNP3 link-layer frame: 05 64 05 C0 01 00 00 04 | CRC bytes E9 21 (little endian)
    hdr = bytes.fromhex("056405c001000004")
    assert crc16_dnp(hdr) == 0x21E9


def test_iso_ts_formats_and_survives_garbage():
    assert iso_ts(0.0) == "1970-01-01T00:00:00.000000Z"
    assert iso_ts(1700000000.5) == "2023-11-14T22:13:20.500000Z"
    assert iso_ts(1e30) == "1970-01-01T00:00:00.000000Z"
    assert iso_ts(float("nan")) == "1970-01-01T00:00:00.000000Z"


def test_hexdump_short():
    assert hexdump_short(b"\x01\x02") == "0102"
    assert hexdump_short(b"\x00" * 40, 4).endswith("...")
