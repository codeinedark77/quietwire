"""TCP-level robustness: connection re-use, out-of-window poisoning, resync, crafted lengths.

Several of these scenarios were found by running real fuzzed captures (Zeek fuzz-72) through the engine:
one bogus segment must never make the analyser discard the rest of a legitimate stream.
"""

import struct

import pytest

from conftest import alerts_for, run
from quietwire import synth
from quietwire.capture.pcap import RawPacket
from quietwire.detect.engine import Config, Engine
from quietwire.net.decode import LINKTYPE_ETHERNET, decode_packet
from quietwire.net.reassembly import DirectionStream
from quietwire.synth import HMI, MB_PLC, Conn, PcapBuilder, mb_adu


def exchange(c, tid, unit=1):
    c.push(True, mb_adu(tid, unit, synth.mb_read(3, 0, 1)))
    c.push(False, mb_adu(tid, unit, synth.mb_resp_registers(3, [tid])))


def two_connections(isn2, close_first=True, port=40000, gap=1.0):
    pb = PcapBuilder()
    c1 = Conn(pb, HMI, MB_PLC, port, 502, isn_c=1000, isn_s=500000)
    c1.open()
    exchange(c1, 1)
    exchange(c1, 2)
    if close_first:
        c1.close()
    pb.ts += gap
    c2 = Conn(pb, HMI, MB_PLC, port, 502, isn_c=isn2, isn_s=(isn2 * 7 + 13) & 0xFFFFFFFF)
    c2.open()
    exchange(c2, 3)
    exchange(c2, 4)
    return pb


@pytest.mark.parametrize("isn2", [5000, 1000 + (1 << 31) + 777, 1000 + (1 << 31) - 777, (1000 - 1_000_000) & 0xFFFFFFFF,
                                  0x7FFFFFFF, 0xFFFFFF00, 2_000_000_000, 3_500_000_000])
def test_reconnect_on_the_same_four_tuple_after_close(isn2):
    r = run(two_connections(isn2))
    assert r.stats.messages["modbus"] == 8, isn2  # 4 requests + 4 responses, none lost to stale sequence state
    assert r.stats.tcp_connections_restarted == 1 and r.stats.tcp_out_of_window == 0
    assert not alerts_for(r, "QW-P001")


@pytest.mark.parametrize("isn2", [(1 << 31) + 5000, 3_000_000_000])
def test_reconnect_without_seeing_the_teardown_when_sequence_space_is_implausible(isn2):
    r = run(two_connections(isn2, close_first=False))
    assert r.stats.messages["modbus"] == 8 and r.stats.tcp_connections_restarted == 1


def test_syn_retransmission_before_the_handshake_completes_is_not_a_new_connection():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 40000, 502, isn_c=1000)
    c._emit(True, 1000, 0, synth.SYN, b"", 0.001)
    c._emit(True, 1000, 0, synth.SYN, b"", 1.0)  # retransmitted SYN
    c.seq_c += 1
    c._emit(False, 500000, c.seq_c, synth.SYN | synth.ACK, b"", 0.001)
    c.seq_s += 1
    c._emit(True, c.seq_c, c.seq_s, synth.ACK, b"", 0.001)
    exchange(c, 1)
    r = run(pb)
    assert r.stats.messages["modbus"] == 2 and r.stats.tcp_connections_restarted == 0


def test_late_duplicate_of_the_connections_own_syn_after_close_is_ignored():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 40000, 502, isn_c=1000)
    c.open()
    exchange(c, 1)
    c.close()
    pb.ts += 2
    c._emit(True, 1000, 0, synth.SYN, b"", 0.001)  # stray duplicate of the very first SYN
    exchange_after = Conn(pb, HMI, MB_PLC, 40000, 502, isn_c=c.seq_c, isn_s=c.seq_s)
    r = run(pb)
    assert r.stats.tcp_connections_restarted == 0


def test_in_window_syn_injection_on_a_live_connection_does_not_reset_state():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 40000, 502, isn_c=1000)
    c.open()
    exchange(c, 1)
    c._emit(True, c.seq_c + 100, 0, synth.SYN, b"", 0.001)  # in-window SYN, no FIN/RST before it
    exchange(c, 2)
    r = run(pb)
    assert r.stats.messages["modbus"] == 4 and r.stats.tcp_connections_restarted == 0


def test_bogus_far_future_segment_does_not_poison_the_stream():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 40000, 502, isn_c=1000)
    c.open()
    exchange(c, 1)
    c.segment(True, c.seq_c + (1 << 31) - 100, mb_adu(99, 1, synth.mb_read(3, 0, 1)))  # ~2 GiB ahead
    c.segment(True, c.seq_c + (1 << 30), mb_adu(98, 1, synth.mb_read(3, 0, 1)))
    for tid in range(2, 8):
        exchange(c, tid)
    r = run(pb)
    assert r.stats.messages["modbus"] == 7 * 2 and r.stats.tcp_out_of_window == 2
    flow = list(r.inventory.flows.values())[0]
    assert flow.requests == 7 and flow.responses == 7


def test_bogus_far_behind_segment_is_ignored_too():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 40000, 502, isn_c=1000)
    c.open()
    exchange(c, 1)
    c.segment(True, c.seq_c - (1 << 30), mb_adu(77, 1, synth.mb_write_single_register(1, 1)))
    exchange(c, 2)
    r = run(pb)
    assert r.stats.messages["modbus"] == 4 and r.stats.tcp_out_of_window == 1
    assert not alerts_for(r, "QW-W002")  # the forged write never reached the dissector


def test_resync_when_a_new_sequence_space_persists_without_a_syn():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 40000, 502, isn_c=1000)
    c.open()
    exchange(c, 1)
    c.seq_c = 3_000_000_000  # connection silently replaced; its SYN was never captured
    c.seq_s = 1_200_000_000
    for tid in range(2, 6):
        exchange(c, tid)
    r = run(pb)
    assert r.stats.messages["modbus"] == 10  # all of the new connection's traffic recovered, none dropped
    assert r.stats.tcp_out_of_window == 0 or r.stats.tcp_gaps >= 1
    assert alerts_for(r, "QW-P001")  # and the discontinuity is disclosed


def test_two_stray_segments_are_not_enough_to_resync():
    s = DirectionStream(resync_after=3)
    s.add(1000, b"AAAA")
    assert s.add(5_000_000_000 & 0xFFFFFFFF, b"xx") == []
    assert s.add((5_000_000_000 + 2) & 0xFFFFFFFF, b"yy") == []
    assert s.out_of_window == 2
    assert s.add(1004, b"BBBB") == [(b"BBBB", False, None)]  # the legitimate stream continues untouched


def test_resync_run_must_be_contiguous():
    s = DirectionStream(resync_after=3)
    s.add(1000, b"AAAA")
    far = 3_000_000_000
    assert s.add(far, b"11") == [] and s.add(far + 50, b"22") == [] and s.add(far + 100, b"33") == []
    out = s.add(far + 102, b"44")  # only two contiguous so far (33, 44): still no resync
    assert out == []
    out = s.add(far + 104, b"55") + s.add(far + 106, b"66")  # third contiguous segment triggers the re-base
    assert [c[0] for c in out] == [b"33", b"44", b"55", b"66"] and out[0][1] is True and not any(c[1] for c in out[1:])


def test_in_order_segment_clears_a_partial_resync_run():
    s = DirectionStream(resync_after=3)
    s.add(1000, b"AAAA")
    far = 3_000_000_000
    s.add(far, b"11")
    s.add(far + 2, b"22")
    s.add(1004, b"BB")  # real data arrives: the stray run is discarded
    assert s.add(far + 4, b"33") == []


# -- crafted / odd IP lengths ----------------------------------------------------------------------
def frame(payload, total_len=None, ident=1):
    l4 = synth.tcp_segment(HMI, MB_PLC, 40000, 502, 1000, 0, synth.ACK | synth.PSH, payload)
    ip = bytearray(synth.ipv4(HMI, MB_PLC, 6, l4))
    if total_len is not None:
        ip[2:4] = struct.pack("!H", total_len)
        ip[10:12] = b"\x00\x00"
        ip[10:12] = struct.pack("!H", synth.inet_checksum(bytes(ip[:20])))
    return synth.ethernet("02:00:00:00:00:01", "02:00:00:00:00:02", 0x0800, bytes(ip))


def test_ip_length_longer_than_a_fully_captured_frame_is_rejected_not_treated_as_truncation():
    f = frame(b"hello", total_len=9000)
    pkt, why = decode_packet(LINKTYPE_ETHERNET, f, truncated=False)
    assert pkt is None and why == "bad_length"
    pkt, why = decode_packet(LINKTYPE_ETHERNET, f, truncated=True)  # a snaplen-cut capture may legitimately look so
    assert why is None and pkt.wire_payload_len > len(pkt.payload)
    pkt, why = decode_packet(LINKTYPE_ETHERNET, f)
    assert why is None  # default stays lenient for library callers that cannot know


def test_ipv6_payload_length_longer_than_frame_is_rejected_when_not_truncated():
    l4 = synth.tcp_segment("fd00::1", "fd00::2", 1, 502, 1, 0, synth.ACK, b"zz")
    ip = bytearray(synth.ipv6("fd00::1", "fd00::2", 6, l4))
    ip[4:6] = struct.pack("!H", 5000)
    f = synth.ethernet("02:00:00:00:00:01", "02:00:00:00:00:02", 0x86DD, bytes(ip))
    assert decode_packet(LINKTYPE_ETHERNET, f, truncated=False)[1] == "bad_length"
    assert decode_packet(LINKTYPE_ETHERNET, f, truncated=True)[0] is not None


def test_ipv4_total_length_zero_uses_the_captured_frame():
    f = frame(b"tso-frame", total_len=0)
    pkt, why = decode_packet(LINKTYPE_ETHERNET, f, truncated=False)
    assert why is None and pkt.payload == b"tso-frame"


def test_engine_ignores_crafted_length_packets_and_keeps_the_stream_intact():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 40000, 502, isn_c=1000)
    c.open()
    exchange(c, 1)
    bad = frame(mb_adu(9, 1, synth.mb_read(3, 0, 1)), total_len=40000)
    pb.ts += 0.001
    pb.add(bad)
    exchange(c, 2)
    r = run(pb)
    assert r.stats.messages["modbus"] == 4 and r.stats.skipped["bad_length"] == 1 and r.stats.tcp_gaps == 0


def test_engine_still_treats_real_snaplen_truncation_as_a_gap():
    pb = PcapBuilder()
    c = Conn(pb, HMI, MB_PLC, 40000, 502, isn_c=1000)
    c.open()
    c.push(True, mb_adu(1, 1, synth.mb_write_multiple_registers(0, list(range(60)))))
    c.push(True, mb_adu(2, 1, synth.mb_read(3, 0, 1)))
    eng = Engine()
    for i, (ts, d) in enumerate(pb.ordered(), 1):
        cut = d[:80] if len(d) > 100 else d
        eng.process(RawPacket(i, 0, ts, 1, len(cut), len(d), cut))  # origlen > caplen => genuinely truncated
    r = eng.finalize()
    assert r.stats.tcp_gaps >= 1 and r.stats.messages["modbus"] >= 1 and r.stats.skipped["bad_length"] == 0


def test_stats_expose_new_counters():
    r = run(two_connections(5000))
    d = r.stats.to_dict()
    assert d["tcp_connections_restarted"] == 1 and d["tcp_out_of_window"] == 0
