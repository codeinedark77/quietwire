import io
import struct

import pytest

from quietwire import synth
from quietwire.capture.pcap import MAX_CAPLEN, CaptureReader
from quietwire.capture.pcapwriter import PcapWriter
from quietwire.errors import CaptureFormatError


def _builder(n=5):
    pb = synth.PcapBuilder(start_ts=1700000000.0)
    for i in range(n):
        pb.add(bytes([i]) * (20 + i), ts=1700000000.0 + i * 0.25 + 0.000123)
    return pb


@pytest.mark.parametrize("nano", [False, True])
@pytest.mark.parametrize("big", [False, True])
def test_classic_pcap_variants(tmp_path, nano, big):
    pb = _builder()
    path = str(tmp_path / "c.pcap")
    pb.write_pcap(path, nano=nano, big_endian=big)
    with CaptureReader(path) as r:
        pkts = list(r)
        assert r.format == "pcap" and r.linktype == 1
    assert [p.index for p in pkts] == [1, 2, 3, 4, 5]
    assert [p.data for p in pkts] == [d for _t, d in pb.ordered()]
    for p, (ts, _d) in zip(pkts, pb.ordered()):
        assert abs(p.ts - ts) < (2e-9 if nano else 2e-6)


def test_pcap_offsets_point_at_record_header(tmp_path):
    pb = _builder()
    path = str(tmp_path / "o.pcap")
    pb.write_pcap(path)
    raw = open(path, "rb").read()
    with CaptureReader(path) as r:
        for p in r:
            incl = struct.unpack_from("<I", raw, p.offset + 8)[0]
            assert incl == p.caplen
            assert raw[p.offset + 16 : p.offset + 16 + incl] == p.data


@pytest.mark.parametrize("big", [False, True])
@pytest.mark.parametrize("tsresol", [None, 9, 3])
def test_pcapng_variants(tmp_path, big, tsresol):
    pb = _builder()
    path = str(tmp_path / "n.pcapng")
    pb.write_pcapng(path, big_endian=big, tsresol=tsresol)
    with CaptureReader(path) as r:
        pkts = list(r)
        assert r.format == "pcapng" and r.linktype == 1
    assert [p.data for p in pkts] == [d for _t, d in pb.ordered()]
    tol = {None: 2e-6, 9: 2e-9, 3: 2e-3}[tsresol]
    for p, (ts, _d) in zip(pkts, pb.ordered()):
        assert abs(p.ts - ts) < tol


def test_pcapng_offsets_point_at_block(tmp_path):
    pb = _builder()
    path = str(tmp_path / "n.pcapng")
    pb.write_pcapng(path)
    raw = open(path, "rb").read()
    with CaptureReader(path) as r:
        for p in r:
            btype, total = struct.unpack_from("<II", raw, p.offset)
            assert btype == 6
            assert p.data in raw[p.offset : p.offset + total]


def test_pcapng_skips_unknown_blocks_and_handles_simple_packet_block():
    e = "<"

    def block(btype, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack(e + "II", btype, total) + body + b"\x00" * pad + struct.pack(e + "I", total)

    shb = block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack(e + "HHI", 1, 0, 65535))
    custom = block(0x00000BAD, b"whatever")
    spb = block(3, struct.pack(e + "I", 6) + b"abcdef")
    data = shb + idb + custom + spb
    pkts = list(CaptureReader(io.BytesIO(data)))
    assert len(pkts) == 1 and pkts[0].data == b"abcdef" and pkts[0].ts == 0.0


def test_pcapng_multiple_sections_reset_interfaces():
    e = "<"

    def block(btype, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack(e + "II", btype, total) + body + b"\x00" * pad + struct.pack(e + "I", total)

    shb = block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack(e + "HHI", 1, 0, 65535))
    epb = block(6, struct.pack(e + "IIIII", 0, 0, 1000000, 3, 3) + b"xyz")
    stream = shb + idb + epb + shb + idb + epb
    assert [p.data for p in CaptureReader(io.BytesIO(stream))] == [b"xyz", b"xyz"]


def test_truncated_trailing_record_is_a_warning(tmp_path):
    pb = _builder()
    path = str(tmp_path / "t.pcap")
    pb.write_pcap(path)
    raw = open(path, "rb").read()
    open(path, "wb").write(raw[:-5])
    r = CaptureReader(path)
    pkts = list(r)
    assert len(pkts) == 4
    assert any("truncated" in w for w in r.warnings)


def test_truncated_record_header_is_a_warning(tmp_path):
    pb = _builder(2)
    path = str(tmp_path / "t.pcap")
    pb.write_pcap(path)
    raw = open(path, "rb").read()
    open(path, "wb").write(raw + b"\x01\x02\x03")
    r = CaptureReader(path)
    assert len(list(r)) == 2
    assert any("truncated packet header" in w for w in r.warnings)


def test_bad_magic_and_short_file(tmp_path):
    with pytest.raises(CaptureFormatError):
        CaptureReader(io.BytesIO(b"\x00\x01\x02\x03rest"))
    with pytest.raises(CaptureFormatError):
        CaptureReader(io.BytesIO(b"\xd4\xc3"))


def test_implausible_caplen_rejected():
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 1, 0, MAX_CAPLEN + 1, MAX_CAPLEN + 1)
    with pytest.raises(CaptureFormatError):
        list(CaptureReader(io.BytesIO(hdr + rec)))


def test_truncated_pcap_global_header():
    with pytest.raises(CaptureFormatError):
        list(CaptureReader(io.BytesIO(b"\xd4\xc3\xb2\xa1" + b"\x00" * 10)))


def test_pcapng_bad_block_length_rejected():
    e = "<"
    shb_body = struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = struct.pack(e + "II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack(e + "I", 12 + len(shb_body))
    bad = struct.pack(e + "II", 1, 7) + b"\x00" * 8
    with pytest.raises(CaptureFormatError):
        list(CaptureReader(io.BytesIO(shb + bad)))


def test_pcapng_bad_byte_order_magic():
    body = struct.pack("<IHHq", 0xDEADBEEF, 1, 0, -1)
    blk = struct.pack("<II", 0x0A0D0D0A, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))
    with pytest.raises(CaptureFormatError):
        list(CaptureReader(io.BytesIO(blk)))


def test_pcapwriter_roundtrip(tmp_path):
    path = str(tmp_path / "w.pcap")
    with PcapWriter(path, linktype=1) as w:
        w.write(1700000000.999999, b"abc")
        w.write(1700000001.0, b"defgh", origlen=9)
    pkts = list(CaptureReader(path))
    assert [p.data for p in pkts] == [b"abc", b"defgh"]
    assert pkts[1].origlen == 9
    assert abs(pkts[0].ts - 1700000000.999999) < 2e-6


def test_pcapwriter_snaplen_truncates():
    buf = io.BytesIO()
    w = PcapWriter(buf, snaplen=4)
    w.write(1.0, b"abcdefgh")
    buf.seek(0)
    p = list(CaptureReader(buf))[0]
    assert p.data == b"abcd" and p.origlen == 8


def test_reader_closes_file_handle(tmp_path):
    pb = _builder(1)
    path = str(tmp_path / "x.pcap")
    pb.write_pcap(path)
    r = CaptureReader(path)
    list(r)
    assert r._closed
