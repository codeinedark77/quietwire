import socket
import struct

import pytest

from quietwire import synth
from quietwire.net.decode import (LINKTYPE_ETHERNET, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LINUX_SLL,
                                  LINKTYPE_LINUX_SLL2, LINKTYPE_NULL, LINKTYPE_RAW, decode_packet)

A, B = "10.1.1.1", "10.1.1.2"
MA, MB = "02:00:00:00:00:0a", "02:00:00:00:00:0b"


def tcp_frame(payload=b"hello", vlan=None, flags=synth.ACK | synth.PSH, seq=77, ack=88):
    l4 = synth.tcp_segment(A, B, 1234, 502, seq, ack, flags, payload)
    return synth.frame_for(A, B, 6, l4, MA, MB, vlan)


def test_ethernet_ipv4_tcp():
    pkt, why = decode_packet(LINKTYPE_ETHERNET, tcp_frame())
    assert why is None
    assert (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port) == (A, B, 1234, 502)
    assert pkt.payload == b"hello" and pkt.is_tcp and pkt.seq == 77 and pkt.ack == 88
    assert pkt.src_mac == MA and pkt.dst_mac == MB and pkt.vlan is None
    assert pkt.flags == synth.ACK | synth.PSH


@pytest.mark.parametrize("tags", [1, 2])
def test_vlan_tags(tags):
    inner = tcp_frame(vlan=None)
    frame = bytearray(inner)
    ethertype = bytes(frame[12:14])
    stacked = bytes(frame[:12])
    for i in range(tags):
        stacked += struct.pack("!HH", 0x8100 if i == 0 else 0x88A8, 100 + i)
    stacked += ethertype + bytes(frame[14:])
    pkt, why = decode_packet(LINKTYPE_ETHERNET, stacked)
    assert why is None and pkt.vlan == 100 and pkt.payload == b"hello"


def test_ethernet_padding_not_part_of_payload():
    frame = tcp_frame(payload=b"")
    padded = frame + b"\x00" * 6  # Ethernet minimum-size padding
    pkt, why = decode_packet(LINKTYPE_ETHERNET, padded)
    assert why is None and pkt.payload == b""


def test_udp():
    l4 = synth.udp_datagram(A, B, 5000, 20000, b"\x05\x64abc")
    pkt, why = decode_packet(LINKTYPE_ETHERNET, synth.frame_for(A, B, 17, l4, MA, MB))
    assert why is None and not pkt.is_tcp and pkt.payload == b"\x05\x64abc" and pkt.dst_port == 20000


def test_ipv6_and_extension_header():
    src, dst = "fd00::1", "fd00::2"
    l4 = synth.tcp_segment(src, dst, 1234, 502, 5, 6, synth.ACK, b"v6data")
    plain = synth.ethernet(MA, MB, 0x86DD, synth.ipv6(src, dst, 6, l4))
    pkt, why = decode_packet(LINKTYPE_ETHERNET, plain)
    assert why is None and pkt.ip_version == 6 and pkt.payload == b"v6data" and pkt.src_ip == src
    # hop-by-hop extension header (8 bytes) before TCP
    hbh = bytes([6, 0]) + b"\x00" * 6
    ext = synth.ethernet(MA, MB, 0x86DD, synth.ipv6(src, dst, 0, hbh + l4))
    pkt, why = decode_packet(LINKTYPE_ETHERNET, ext)
    assert why is None and pkt.payload == b"v6data"


def test_ipv6_fragment_header_is_not_decoded_by_the_stateless_wrapper():
    src, dst = "fd00::1", "fd00::2"
    frag = bytes([6, 0, 0, 1, 0, 0, 0, 1])
    f = synth.ethernet(MA, MB, 0x86DD, synth.ipv6(src, dst, 44, frag + b"xxxx"))
    pkt, why = decode_packet(LINKTYPE_ETHERNET, f)
    assert pkt is None and why == "fragment"


def test_ipv4_fragments_are_reported_not_misparsed():
    l4 = synth.tcp_segment(A, B, 1, 2, 3, 4, synth.ACK, b"x")
    for frag in (0x2000, 0x0005):  # MF set / non-zero offset
        ip = synth.ipv4(A, B, 6, l4, frag=frag)
        pkt, why = decode_packet(LINKTYPE_ETHERNET, synth.ethernet(MA, MB, 0x0800, ip))
        assert pkt is None and why == "fragment"


def test_other_linktypes():
    ip = synth.ipv4(A, B, 6, synth.tcp_segment(A, B, 1, 502, 3, 4, synth.ACK, b"zz"))
    cooked = b"\x00\x00\x00\x01\x00\x06" + b"\x00" * 8 + struct.pack("!H", 0x0800) + ip
    assert decode_packet(LINKTYPE_LINUX_SLL, cooked)[0].payload == b"zz"
    cooked2 = struct.pack("!H", 0x0800) + b"\x00" * 18 + ip
    assert decode_packet(LINKTYPE_LINUX_SLL2, cooked2)[0].payload == b"zz"
    for lt in (LINKTYPE_RAW, LINKTYPE_IPV4):
        assert decode_packet(lt, ip)[0].payload == b"zz"
    assert decode_packet(LINKTYPE_NULL, struct.pack("<I", 2) + ip)[0].payload == b"zz"
    assert decode_packet(LINKTYPE_NULL, struct.pack(">I", 2) + ip)[0].payload == b"zz"
    ip6 = synth.ipv6("fd00::1", "fd00::2", 6, synth.tcp_segment("fd00::1", "fd00::2", 1, 2, 3, 4, synth.ACK, b"q6"))
    assert decode_packet(LINKTYPE_IPV6, ip6)[0].payload == b"q6"
    assert decode_packet(LINKTYPE_RAW, ip6)[0].payload == b"q6"
    assert decode_packet(LINKTYPE_NULL, struct.pack("<I", 30) + ip6)[0].payload == b"q6"


def test_failure_reasons():
    assert decode_packet(999, b"\x00" * 60)[1] == "unsupported_linktype"
    assert decode_packet(LINKTYPE_ETHERNET, b"\x00" * 10)[1] == "truncated"
    arp = synth.ethernet(MA, MB, 0x0806, b"\x00" * 28)
    assert decode_packet(LINKTYPE_ETHERNET, arp)[1] == "non_ip"
    icmp = synth.ethernet(MA, MB, 0x0800, synth.ipv4(A, B, 1, b"\x08\x00\x00\x00\x00\x00\x00\x00"))
    assert decode_packet(LINKTYPE_ETHERNET, icmp)[1] == "non_tcp_udp"
    assert decode_packet(LINKTYPE_RAW, b"\x00")[1] == "non_ip"
    assert decode_packet(LINKTYPE_RAW, b"")[1] == "truncated"
    assert decode_packet(LINKTYPE_NULL, b"\x01\x00")[1] == "truncated"
    assert decode_packet(LINKTYPE_NULL, struct.pack("<I", 99) + b"x" * 20)[1] == "non_ip"
    bad_ihl = bytearray(synth.ipv4(A, B, 6, synth.tcp_segment(A, B, 1, 2, 3, 4, synth.ACK, b"")))
    bad_ihl[0] = 0x42  # ihl = 8 bytes
    assert decode_packet(LINKTYPE_RAW, bytes(bad_ihl))[1] == "bad_header"
    bad_tcp = bytearray(tcp_frame())
    bad_tcp[14 + 20 + 12] = 0x20  # data offset 2 words
    assert decode_packet(LINKTYPE_ETHERNET, bytes(bad_tcp))[1] == "bad_header"
    assert decode_packet(LINKTYPE_ETHERNET, tcp_frame()[:40])[1] == "truncated"


def test_snaplen_truncated_payload_reports_wire_length():
    frame = tcp_frame(payload=b"A" * 100)
    cut = frame[: len(frame) - 60]
    pkt, why = decode_packet(LINKTYPE_ETHERNET, cut)
    assert why is None and len(pkt.payload) == 40 and pkt.wire_payload_len == 100


def test_tcp_options_are_skipped():
    opts = b"\x02\x04\x05\xb4\x01\x03\x03\x02"
    l4 = synth.tcp_segment(A, B, 1, 502, 9, 0, synth.SYN, b"", options=opts)
    pkt, why = decode_packet(LINKTYPE_ETHERNET, synth.frame_for(A, B, 6, l4, MA, MB))
    assert why is None and pkt.payload == b"" and pkt.flags == synth.SYN


def test_udp_length_field_bounds_payload():
    l4 = synth.udp_datagram(A, B, 1, 2, b"abcd") + b"junk"
    pkt, why = decode_packet(LINKTYPE_ETHERNET, synth.ethernet(MA, MB, 0x0800, synth.ipv4(A, B, 17, l4)))
    assert pkt.payload == b"abcd"
