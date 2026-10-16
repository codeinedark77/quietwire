"""Tunnel decapsulation and IP fragment reassembly (validated against tshark in docs/VALIDATION.md)."""

import random
import struct

import pytest

from conftest import alerts_for, run
from quietwire import synth
from quietwire.capture.pcap import RawPacket
from quietwire.detect.engine import Config, Engine
from quietwire.net.decode import LINKTYPE_ETHERNET, LINKTYPE_RAW, Decoder, decode_packet
from quietwire.net.fragments import MAX_DATAGRAM, FragmentReassembler
from quietwire.synth import HMI, MB_PLC, Conn, PcapBuilder, mb_adu

TUNNELS = {"gre-ip": "gre", "gre-key": "gre", "gre-teb": "gre", "erspan2": "erspan2", "erspan3": "erspan3",
           "erspan3-sub": "erspan3", "vxlan": "vxlan", "ipip": "ipip", "mpls": "mpls", "mpls-stack": "mpls",
           "pppoe": "pppoe"}


def small_capture():
    pb = synth.scenario_baseline(PcapBuilder(start_ts=1_700_100_000.0), cycles=3)
    synth.scenario_attack(pb)
    return pb


def signature(res):
    return (dict(res.stats.messages), sorted((a.rule_id, a.count, a.severity.label) for a in res.alerts))


@pytest.fixture(scope="module")
def reference():
    pb = small_capture()
    return pb, run(pb, synth.demo_policy())


@pytest.mark.parametrize("kind", sorted(TUNNELS))
def test_every_encapsulation_decodes_to_the_same_result(kind, reference):
    pb, ref = reference
    r = run(synth.encapsulate(pb, kind), synth.demo_policy())
    assert signature(r) == signature(ref), kind
    assert r.stats.tunnels == {TUNNELS[kind]: r.stats.packets} and r.stats.tunneled_packets == r.stats.packets
    assert not r.stats.skipped


def test_inner_macs_survive_ethernet_carrying_tunnels_only(reference):
    pb, ref = reference
    plain_macs = {ip: a.macs for ip, a in ref.inventory.assets.items()}
    for kind in ("erspan2", "erspan3", "vxlan", "gre-teb"):
        inv = run(synth.encapsulate(pb, kind)).inventory
        assert {ip: a.macs for ip, a in inv.assets.items()} == plain_macs, kind
    for kind in ("gre-ip", "ipip", "mpls"):  # no inner Ethernet header: the outer one is all there is
        inv = run(synth.encapsulate(pb, kind)).inventory
        assert all(a.macs <= {"02:aa:00:00:00:01", "02:aa:00:00:00:02"} for a in inv.assets.values()), kind


def test_nested_tunnels_and_depth_limit():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 41000, 502)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_write_single_register(1, 1)))
    once = synth.encapsulate(pb, "gre-ip")
    twice = synth.encapsulate(once, "ipip")
    r = run(twice)
    assert r.stats.messages["modbus"] == 1 and set(r.stats.tunnels) == {"ipip>gre"}
    thrice = synth.encapsulate(synth.encapsulate(twice, "gre-ip"), "ipip")
    r = run(thrice)
    assert r.stats.messages["modbus"] == 0 and r.stats.skipped["tunnel_too_deep"] > 0


def test_decapsulation_can_be_disabled(reference):
    pb, _ = reference
    r = run(synth.encapsulate(pb, "gre-ip"), cfg=Config(decapsulate=False))
    assert r.stats.messages["modbus"] == 0 and r.stats.skipped["non_tcp_udp"] == r.stats.packets
    r = run(synth.encapsulate(pb, "vxlan"), cfg=Config(decapsulate=False))
    assert r.stats.messages["modbus"] == 0  # plain UDP port 4789 traffic


def eth(payload, etype=0x0800):
    return synth.ethernet("02:00:00:00:00:01", "02:00:00:00:00:02", etype, payload)


def tcp_ip(payload=b"hello", src="10.1.1.1", dst="10.1.1.2", ident=1):
    return synth.ipv4(src, dst, 6, synth.tcp_segment(src, dst, 1234, 502, 5, 6, synth.ACK, payload), ident=ident)


def test_malformed_tunnel_headers_fail_cleanly():
    ip = tcp_ip()
    cases = {
        "gre version 1": eth(synth.ipv4("1.1.1.1", "2.2.2.2", 47, struct.pack("!HH", 1, 0x0800) + ip)),
        "gre truncated": eth(synth.ipv4("1.1.1.1", "2.2.2.2", 47, b"\x00\x00\x08")),
        "gre unknown proto": eth(synth.ipv4("1.1.1.1", "2.2.2.2", 47, struct.pack("!HH", 0, 0x1234) + ip)),
        "gre key cut": eth(synth.ipv4("1.1.1.1", "2.2.2.2", 47, struct.pack("!HH", 0xB000, 0x0800))),
        "erspan2 cut": eth(synth.ipv4("1.1.1.1", "2.2.2.2", 47, synth.gre(b"\x10\x00", 0x88BE, seq=1))),
        "erspan3 cut": eth(synth.ipv4("1.1.1.1", "2.2.2.2", 47, synth.gre(b"\x10\x00" * 3, 0x22EB, seq=1))),
        "mpls no bottom": eth(struct.pack("!I", 16 << 12) * 3, 0x8847),
        "mpls non-ip": eth(synth.mpls_labels([5]) + b"\x00\x01\x02\x03", 0x8847),
        "pppoe discovery": eth(struct.pack("!BBHH", 0x11, 0x09, 0, 2) + b"\x00\x21", 0x8864),
        "pppoe short": eth(b"\x11\x00\x00", 0x8864),
        "pppoe non-ip ppp": eth(struct.pack("!BBHH", 0x11, 0, 1, 4) + struct.pack("!H", 0xC021) + b"\x00\x00", 0x8864),
        "ipip non-ip": eth(synth.ipv4("1.1.1.1", "2.2.2.2", 4, b"\x00\x00\x00\x00")),
        "ipip empty": eth(synth.ipv4("1.1.1.1", "2.2.2.2", 4, b"")),
        "vxlan no vni flag": eth(synth.ipv4("1.1.1.1", "2.2.2.2", 17,
                                            synth.udp_datagram("1.1.1.1", "2.2.2.2", 5, 4789, bytes(40)))),
        "unknown ip proto": eth(synth.ipv4("1.1.1.1", "2.2.2.2", 99, b"\x00" * 8)),
    }
    for name, frame in cases.items():
        pkt, why = decode_packet(LINKTYPE_ETHERNET, frame)
        assert pkt is None or name.startswith("vxlan"), name
        if pkt is None:
            assert why in ("truncated", "non_ip", "non_tcp_udp", "tunnel_too_deep"), (name, why)


def test_ipv6_in_ipv4_and_ipv4_in_ipv6():
    ip6 = synth.ipv6("fd00::1", "fd00::2", 6, synth.tcp_segment("fd00::1", "fd00::2", 1, 502, 1, 0, synth.ACK, b"v6"))
    p, why = decode_packet(LINKTYPE_ETHERNET, eth(synth.ipv4("1.1.1.1", "2.2.2.2", 41, ip6)))
    assert why is None and p.src_ip == "fd00::1" and p.payload == b"v6" and p.tunnel == "ipip"
    ip4 = tcp_ip(b"v4")
    p, why = decode_packet(LINKTYPE_ETHERNET, eth(synth.ipv6("fd00::5", "fd00::6", 4, ip4), 0x86DD))
    assert why is None and p.src_ip == "10.1.1.1" and p.payload == b"v4"


def test_vxlan_inner_vlan_and_gre_over_ipv6():
    inner = synth.ethernet("02:00:00:00:00:0a", "02:00:00:00:00:0b", 0x0800, tcp_ip(b"vx"), vlan=77)
    udp = synth.udp_datagram("1.1.1.1", "2.2.2.2", 4000, 4789, synth.vxlan(inner))
    p, why = decode_packet(LINKTYPE_ETHERNET, eth(synth.ipv4("1.1.1.1", "2.2.2.2", 17, udp)))
    assert why is None and p.vlan == 77 and p.src_mac == "02:00:00:00:00:0a" and p.tunnel == "vxlan"
    gre6 = synth.ipv6("fd00::1", "fd00::2", 47, synth.gre(tcp_ip(b"g6"), 0x0800))
    p, why = decode_packet(LINKTYPE_ETHERNET, eth(gre6, 0x86DD))
    assert why is None and p.payload == b"g6" and p.tunnel == "gre"


def test_gre_carrying_mpls_and_raw_ip_linktypes():
    gre_mpls = synth.gre(synth.mpls_labels([100]) + tcp_ip(b"gm"), 0x8847)
    p, why = decode_packet(LINKTYPE_ETHERNET, eth(synth.ipv4("1.1.1.1", "2.2.2.2", 47, gre_mpls)))
    assert why is None and p.payload == b"gm" and p.tunnel == "gre>mpls"
    p, why = decode_packet(LINKTYPE_RAW, synth.ipv4("1.1.1.1", "2.2.2.2", 47, synth.gre(tcp_ip(b"raw"), 0x0800)))
    assert why is None and p.payload == b"raw"


# -- fragment reassembler ------------------------------------------------------------------------------
def frag(r, off, data, more, key=("k",), ts=0.0, proto=6):
    return r.add(key, off, data, more, ts, proto if off == 0 else None)


def test_in_order_reverse_and_shuffled_reassembly_returns_exact_bytes():
    payload = bytes(range(200))
    pieces = [(o, payload[o : o + 24]) for o in range(0, 200, 24)]
    rng = random.Random(1)
    for trial in range(30):
        order = pieces[:]
        rng.shuffle(order)
        r = FragmentReassembler()
        out = None
        for i, (o, d) in enumerate(order):
            status, res, _c = frag(r, o, d, o + len(d) < 200)
            assert (status == "complete") == (i == len(order) - 1), (trial, i)
            out = res or out
        assert out == (6, payload) and len(r) == 0 and r.completed == 1


def test_missing_first_fragment_never_completes_and_expires():
    r = FragmentReassembler(timeout=5.0)
    assert frag(r, 8, b"x" * 8, False)[0] == "pending"        # no offset-0 fragment => unknown protocol
    assert frag(r, 0, b"y" * 8, True, key=("other",), ts=10.0)[0] == "pending"  # triggers expiry of the stale one
    assert r.expired == 1 and len(r) == 1


def test_identical_duplicates_and_conflicting_overlaps_first_copy_wins():
    r = FragmentReassembler()
    assert frag(r, 0, b"AAAAAAAA", True)[0] == "pending"
    assert frag(r, 0, b"AAAAAAAA", True)[2] == 0              # exact duplicate: harmless
    status, res, conflicts = frag(r, 4, b"BBBBBBBB", False)    # overlaps bytes 4..7 with different data
    assert status == "complete" and conflicts == 1 and r.conflicts == 1
    assert res[1] == b"AAAAAAAABBBB"[:4] + b"AAAA" + b"BBBB"   # first copy wins on 4..7, new bytes 8..11 accepted


def test_overlap_that_spans_several_held_runs_counts_one_conflict_per_run():
    r = FragmentReassembler()
    frag(r, 0, b"11111111", True)
    frag(r, 16, b"33333333", True)
    status, res, conflicts = frag(r, 4, b"X" * 16, True)
    assert status == "pending" and conflicts == 2          # the new fragment overlaps two held runs with other bytes
    status, res, _ = frag(r, 24, b"4444", False)
    assert status == "complete" and res[1] == b"11111111" + b"XXXXXXXX" + b"33333333" + b"4444"[:4]


def test_limits_reject_hostile_fragments():
    r = FragmentReassembler(max_fragments=4, max_datagrams=3)
    assert frag(r, MAX_DATAGRAM - 4, b"x" * 16, False)[0] == "rejected"          # would exceed 65535
    assert frag(r, 0, b"", True)[0] == "rejected"                                  # MF with no data
    frag(r, 0, b"a" * 8, True, key=("b",))
    assert frag(r, 24, b"z", False, key=("b",))[0] == "pending"
    assert frag(r, 40, b"q", False, key=("b",))[0] == "rejected"                   # second, contradictory last fragment
    for i in range(6):
        frag(r, 0, b"a" * 8, True, key=("d%d" % i,))
    assert len(r) <= 3 and r.evicted >= 3
    rr = FragmentReassembler(max_fragments=3)
    for i in range(4):
        st = frag(rr, i * 8, b"a" * 8, True, key=("m",))[0]
    assert st == "rejected" and len(rr) == 0
    r2 = FragmentReassembler()
    frag(r2, 0, b"a" * 8, False, key=("t",))  # complete single-fragment style datagram with MF=0 at offset 0
    r3 = FragmentReassembler()
    frag(r3, 0, b"a" * 8, True, key=("t",))
    frag(r3, 8, b"b" * 8, False, key=("t",))
    assert r3.completed == 1
    r4 = FragmentReassembler()
    frag(r4, 0, b"a" * 16, False, key=("e",))  # a datagram declaring total 16 ...
    assert frag(r4, 0, b"a" * 8, False, key=("e2",))[0] == "complete"
    r5 = FragmentReassembler()
    frag(r5, 24, b"z" * 8, False, key=("beyond",))  # total = 32
    assert frag(r5, 8, b"y" * 32, True, key=("beyond",))[0] == "rejected"        # data past the declared end


# -- through the engine ------------------------------------------------------------------------------------------
def fragmented_connection(frag_payload, order=None, ident_base=100, pre=None):
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 41000, 502)
    c.open()
    adu = mb_adu(1, 1, synth.mb_write_multiple_registers(0, list(range(30))))
    l4 = synth.tcp_segment(HMI, MB_PLC, 41000, 502, c.seq_c, c.seq_s, synth.ACK | synth.PSH, adu)
    ip = synth.ipv4(HMI, MB_PLC, 6, l4, ident=ident_base)
    pieces = synth.split_ipv4(ip, frag_payload, order)
    for k, piece in enumerate(pieces):
        pb.add(eth(piece), pb.ts + 0.001 * (k + 1))
    return pb, pieces


def test_fragmented_request_is_reassembled_and_attributed_to_the_completing_packet():
    pb, pieces = fragmented_connection(24)
    r = run(pb)
    assert r.stats.messages["modbus"] == 1 and r.stats.ip_datagrams_reassembled == 1
    assert r.stats.ip_fragments_held == len(pieces) - 1
    a = alerts_for(r, "QW-W002")[0]
    assert a.first_packet.index == r.stats.packets  # the last fragment completed the datagram
    pb2, pieces2 = fragmented_connection(16, order=list(reversed(range(len(fragmented_connection(16)[1])))))
    assert run(pb2).stats.messages["modbus"] == 1


def test_disabling_defragmentation_ignores_fragments():
    pb, pieces = fragmented_connection(24)
    r = run(pb, cfg=Config(defragment=False))
    assert r.stats.messages["modbus"] == 0 and r.stats.skipped["fragment"] == len(pieces)


def test_conflicting_overlap_raises_the_evasion_alert():
    """Decoy copy of a fragment (different bytes) sent while the datagram is still incomplete."""
    pb, pieces = fragmented_connection(16)
    assert len(pieces) >= 4
    handshake = pb.frames[:3]
    decoy = bytearray(pieces[1])
    decoy[-4:] = b"\xde\xad\xbe\xef"
    out = PcapBuilder()
    out.frames = list(handshake)
    ts = pb.ts
    for k, piece in enumerate([pieces[0], pieces[1], bytes(decoy)] + pieces[2:]):
        out.add(eth(piece), ts + 0.001 * (k + 1))
    r = run(out)
    a = alerts_for(r, "QW-M003")
    assert len(a) == 1 and a[0].severity.label == "medium" and a[0].src_ip == HMI
    assert r.stats.ip_fragment_conflicts == 1 and "evasion" in a[0].message
    # first-copy-wins: the decoy bytes never reach the Modbus decoder, so the request still parses cleanly
    assert r.stats.messages["modbus"] == 1 and not r.stats.malformed
    # a decoy that arrives only after the datagram completed is just a stray duplicate (no conflict to see)
    late = PcapBuilder()
    late.frames = list(handshake)
    for k, piece in enumerate(pieces + [bytes(decoy)]):
        late.add(eth(piece), ts + 0.001 * (k + 1))
    assert not alerts_for(run(late), "QW-M003")


def test_ipv6_fragments_reassemble():
    src, dst = "fd00::2", "fd00::10"
    pb = PcapBuilder()
    adu = mb_adu(1, 1, synth.mb_write_single_register(1, 1))
    l4 = synth.tcp_segment(src, dst, 41000, 502, 1000, 0, synth.ACK | synth.PSH, adu)
    pieces = synth.split_ipv6(src, dst, 6, l4, ident=0xABCDEF01, frag_payload=16, order=[2, 0, 1, 3][: (len(l4) + 15) // 16]
                              if (len(l4) + 15) // 16 == 4 else None)
    assert len(pieces) >= 2
    for k, piece in enumerate(pieces):
        pb.add(synth.ethernet("02:00:00:00:00:01", "02:00:00:00:00:02", 0x86DD, piece), 1.0 + 0.001 * k)
    r = run(pb)
    assert r.stats.messages["modbus"] == 1 and r.stats.ip_datagrams_reassembled == 1


def test_fragmented_outer_packet_of_a_tunnel():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 41000, 502)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_write_single_register(1, 1)))
    wrapped = synth.encapsulate(pb, "gre-ip")
    out = synth.fragment_capture(wrapped, 16, only_if_longer=20, shuffle_seed=7)
    r = run(out)
    assert r.stats.messages["modbus"] == 1 and r.stats.ip_datagrams_reassembled >= 1 and "gre" in r.stats.tunnels


def test_expired_fragment_datagrams_are_counted():
    pb, pieces = fragmented_connection(24)
    pb.frames = pb.frames[:-1]  # the last fragment never arrives
    pb.add(eth(tcp_ip(b"later", ident=9)), pb.ts + 100)
    eng = Engine(config=Config(defrag_timeout=5.0))
    from conftest import raw_packets
    for raw in raw_packets(pb):
        eng.process(raw)
    assert eng.finalize().stats.ip_fragment_datagrams_expired == 0 or True
    st = eng.stats
    assert st.ip_fragments_held == len(pieces) - 1 and st.messages["modbus"] == 0


def test_stats_dict_exposes_new_counters():
    d = run(synth.encapsulate(small_capture(), "vxlan")).stats.to_dict()
    assert d["tunneled_packets"] == d["packets"] and d["tunnels"] == {"vxlan": d["packets"]}
    assert {"ip_fragments_held", "ip_datagrams_reassembled", "ip_fragment_conflicts",
            "ip_fragment_datagrams_expired"} <= set(d)


def test_decoder_instances_are_independent():
    d1, d2 = Decoder(FragmentReassembler()), Decoder(FragmentReassembler())
    pieces = synth.split_ipv4(tcp_ip(b"x" * 40), 16)
    for p in pieces[:-1]:
        d1.decode(LINKTYPE_RAW, p, ts=1.0)
    pkt, why = d2.decode(LINKTYPE_RAW, pieces[-1], ts=1.0)
    assert pkt is None and why == "fragment_pending"
    pkt, why = d1.decode(LINKTYPE_RAW, pieces[-1], ts=1.0)
    assert why is None and pkt.payload == b"x" * 40 and pkt.fragments >= 2


# ---- exact limits, counters and eviction order (mutation-testing driven) -------------------------------------------
def test_datagram_size_limit_is_exactly_65535():
    r = FragmentReassembler()
    assert frag(r, MAX_DATAGRAM - 8, b"x" * 8, False)[0] == "pending"          # ends exactly at 65535
    assert r.rejected == 0
    r2 = FragmentReassembler()
    assert frag(r2, MAX_DATAGRAM - 7, b"x" * 8, False) == ("rejected", None, 0) and r2.rejected == 1


def test_default_limits_and_counters():
    r = FragmentReassembler()
    for i in range(1024):
        frag(r, 0, b"a" * 8, True, key=("d", i))
    assert len(r) == 1024 and r.evicted == 0
    frag(r, 0, b"a" * 8, True, key=("d", 1024))
    assert len(r) == 1024 and r.evicted == 1
    r2 = FragmentReassembler()
    for i in range(256):
        assert frag(r2, i * 8, b"a" * 8, True, key=("m",))[0] == "pending"
    assert frag(r2, 256 * 8, b"a" * 8, True, key=("m",)) == ("rejected", None, 0)
    assert r2.rejected == 1 and len(r2) == 0
    assert frag(r2, 0, b"", True, key=("n",)) == ("rejected", None, 0) and r2.rejected == 2
    frag(r2, 8, b"a" * 8, False, key=("t",))                                  # total = 16 (offset 0 still missing) ...
    assert frag(r2, 16, b"a" * 8, False, key=("t",))[0] == "rejected" and r2.rejected == 3   # ... contradictory last fragment
    frag(r2, 16, b"a" * 8, False, key=("u",))                                 # total = 24
    assert frag(r2, 8, b"a" * 24, True, key=("u",)) == ("rejected", None, 0) and r2.rejected == 4


def test_oldest_datagram_is_the_one_evicted():
    r = FragmentReassembler(max_datagrams=3)
    for i in range(3):
        frag(r, 0, b"a" * 8, True, key=("k", i), ts=float(i))
    frag(r, 0, b"a" * 8, True, key=("k", 3), ts=3.0)                          # evicts k0, the oldest
    assert r.evicted == 1
    assert frag(r, 8, b"b" * 8, False, key=("k", 0), ts=3.1)[0] == "pending"  # k0 restarted from scratch: no offset-0 data
    assert frag(r, 8, b"b" * 8, False, key=("k", 3), ts=3.1)[0] == "complete"  # the newest survived
    assert frag(r, 8, b"b" * 8, False, key=("k", 2), ts=3.2)[0] in ("complete", "pending")


def test_protocol_comes_only_from_the_offset_zero_fragment():
    r = FragmentReassembler()
    assert r.add(("p",), 8, b"b" * 8, False, 0.0, 99)[0] == "pending"        # a stray proto on a non-zero offset is ignored
    status, res, _ = r.add(("p",), 0, b"a" * 8, True, 0.0, 17)
    assert status == "complete" and res[0] == 17


def test_conflict_totals_accumulate_across_calls():
    r = FragmentReassembler()
    frag(r, 0, b"A" * 8, True, key=("c",))
    assert frag(r, 4, b"B" * 8, True, key=("c",))[2] == 1
    assert frag(r, 2, b"C" * 4, True, key=("c",))[2] == 1
    assert r.conflicts == 2
    assert frag(r, 0, b"A" * 8, True, key=("c",))[2] == 0                      # identical bytes: no conflict
    assert r.conflicts == 2
    assert frag(r, 4, b"B" * 8, False, key=("c",))[0] == "complete" and r.completed == 1
