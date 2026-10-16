import random

from quietwire.net.reassembly import DirectionStream


def data(chunks):
    return b"".join(c[0] for c in chunks)


def test_in_order_and_tags():
    s = DirectionStream()
    assert s.add(1000, b"AAAA", tag="p1") == [(b"AAAA", False, "p1")]
    assert s.add(1004, b"BB", tag="p2") == [(b"BB", False, "p2")]
    assert s.delivered_bytes == 6 and s.gaps == 0


def test_syn_consumes_one_sequence_number():
    s = DirectionStream()
    assert s.add(99, b"", syn=True) == []
    assert s.add(100, b"hi") == [(b"hi", False, None)]


def test_retransmission_dropped_and_partial_overlap_trimmed():
    s = DirectionStream()
    s.add(0, b"abcd")
    assert s.add(0, b"abcd") == []
    assert s.retransmitted_segments == 1
    out = s.add(2, b"cdef")  # overlaps 2 bytes
    assert data(out) == b"ef"
    assert s.next_seq == 6


def test_out_of_order_is_held_then_delivered_in_order_with_original_tags():
    s = DirectionStream()
    s.add(0, b"AA", tag=1)
    assert s.add(4, b"CC", ts=0.0, tag=3) == []
    out = s.add(2, b"BB", ts=0.01, tag=2)
    assert out == [(b"BB", False, 2), (b"CC", False, 3)]


def test_hole_released_after_reorder_window_with_gap_flag():
    s = DirectionStream(reorder_window=0.25)
    s.add(0, b"AA", ts=0.0)
    assert s.add(10, b"ZZ", ts=1.0, tag="z") == []
    out = s.add(12, b"YY", ts=1.3, tag="y")  # oldest held segment is now 0.3s old
    assert out[0] == (b"ZZ", True, "z") and out[1][0] == b"YY" and out[1][1] is False
    assert s.gaps == 1


def test_limits_bound_memory():
    s = DirectionStream(max_ooo_segments=4, max_ooo_bytes=1 << 20)
    s.add(0, b"A")
    released = []
    for i in range(1, 30):
        released += s.add(i * 100, b"x" * 10, ts=0.0)
    assert len(s._ooo) <= 4
    assert released  # forced releases happened
    s2 = DirectionStream(max_ooo_bytes=50, max_ooo_segments=1000)
    s2.add(0, b"A")
    for i in range(1, 20):
        s2.add(i * 100, b"y" * 20, ts=0.0)
    assert s2._ooo_bytes <= 50


def test_flush_releases_everything_in_sequence_order():
    s = DirectionStream()
    s.add(0, b"A")
    s.add(100, b"C", tag="c")
    s.add(50, b"B", tag="b")
    out = s.flush()
    assert [c[0] for c in out] == [b"B", b"C"]
    assert all(c[1] for c in out[:1])
    assert s.flush() == []


def test_snaplen_truncation_marks_gap_for_next_chunk():
    s = DirectionStream()
    out = s.add(0, b"AAAA", wire_len=10)
    assert out == [(b"AAAA", False, None)]
    out = s.add(10, b"BB")
    assert out == [(b"BB", True, None)]


def test_duplicate_ooo_segment_keeps_longer_copy():
    s = DirectionStream()
    s.add(0, b"A")
    s.add(10, b"xx", ts=0.0)
    s.add(10, b"xxxx", ts=0.0)
    assert s._ooo_bytes == 4


def test_sequence_wraparound_in_order():
    s = DirectionStream()
    s.add(0xFFFFFFFE, b"ab")
    assert s.next_seq == 0
    assert data(s.add(0, b"cd")) == b"cd"


def test_random_reordering_and_duplication_reassembles_exact_stream():
    rng = random.Random(1234)
    payload = bytes(rng.randrange(256) for _ in range(4000))
    segs, pos = [], 0
    while pos < len(payload):
        n = rng.randrange(1, 120)
        segs.append((pos, payload[pos : pos + n]))
        pos += n
    for trial in range(20):
        order = segs[:]
        # local shuffling only (window of 4) so the reorder window never triggers a skip
        for i in range(0, len(order) - 4, 4):
            blk = order[i : i + 4]
            rng.shuffle(blk)
            order[i : i + 4] = blk
        order += rng.sample(segs, 10)  # duplicates
        s = DirectionStream(max_ooo_segments=64, reorder_window=1e9)
        got = b""
        base = rng.randrange(1 << 32)
        s.add((base - 1) & 0xFFFFFFFF, b"", syn=True)  # a SYN pins the initial sequence number
        for off, d in order:
            got += data(s.add((base + off) & 0xFFFFFFFF, d, ts=0.0))
        got += data(s.flush())
        assert got == payload


# ---- exact boundaries and the held-overlap path (mutation-testing driven) --------------------------------------
def test_held_segment_partially_covered_by_later_delivery_is_trimmed():
    s = DirectionStream(reorder_window=1e9)
    s.add(0, b"AAAA", tag="a")
    assert s.add(6, b"BBBB", ts=0.0, tag="b") == []        # hole 4..6: held
    out = s.add(4, b"CCCC", ts=0.1, tag="c")               # fills 4..8 and overlaps the first two bytes of B
    assert [(c[0], c[2]) for c in out] == [(b"CCCC", "c"), (b"BB", "b")] and s.next_seq == 10
    assert s._ooo == {} and s._ooo_bytes == 0 and s.gaps == 0


def test_held_segment_entirely_covered_by_later_delivery_is_dropped():
    s = DirectionStream(reorder_window=1e9)
    s.add(0, b"AAAA")
    s.add(6, b"BB", ts=0.0)
    s.add(8, b"DD", ts=0.0)
    out = s.add(4, b"CCCCCCCC", ts=0.1)                    # covers 4..12: both held segments lie inside it
    assert [c[0] for c in out] == [b"CCCCCCCC"] and s.next_seq == 12 and not s._ooo and s._ooo_bytes == 0


def test_out_of_order_byte_accounting_and_exact_limits():
    s = DirectionStream(max_ooo_bytes=10, max_ooo_segments=100, reorder_window=1e9)
    s.add(0, b"A")
    assert s.add(10, b"x" * 5, ts=0.0) == [] and s._ooo_bytes == 5
    assert s.add(20, b"y" * 5, ts=0.0) == [] and s._ooo_bytes == 10       # exactly at the limit: still held
    out = s.add(30, b"z", ts=0.0)                                         # one byte over: oldest held data is released
    assert out and out[0][1] is True and s.gaps >= 1 and s._ooo_bytes <= 10
    t = DirectionStream(max_ooo_bytes=1 << 30, reorder_window=1e9)         # default segment limit is 8
    t.add(0, b"A")
    for i in range(8):
        assert t.add(100 + i * 10, b"x", ts=0.0) == []
    assert len(t._ooo) == 8
    assert t.add(300, b"x", ts=0.0)                                        # the 9th held segment forces a release
    assert t.gaps == 1


def test_default_window_and_resync_parameters():
    s = DirectionStream()
    s.add(1000, b"AAAA")
    assert s.add(1004 + (1 << 20), b"far", ts=0.0) == [] and len(s._ooo) == 1 and s.out_of_window == 0   # exactly at max_ahead
    assert s.add(1004 + (1 << 20) + 100, b"far2", ts=0.0) == [] and s.out_of_window == 1                    # first byte beyond it
    r = DirectionStream()
    r.add(0, b"A")
    far = 3_000_000_000
    assert r.add(far, b"11") == [] and r.add(far + 2, b"22") == []
    out = r.add(far + 4, b"33")                                            # default resync_after is 3 contiguous strays
    assert [c[0] for c in out] == [b"11", b"22", b"33"] and out[0][1] is True and r.gaps == 1


def test_gap_counters_increment_exactly_once_per_event():
    s = DirectionStream(reorder_window=0.1)
    s.add(0, b"A", ts=0.0)
    s.add(10, b"B", ts=0.0)
    s.add(20, b"C", ts=1.0)                                                 # B ages out: one skip; C is then held
    assert s.gaps == 1
    s.flush()
    assert s.gaps == 2
    t = DirectionStream()
    t.add(0, b"AAAA", wire_len=9)                                           # snaplen cut: one gap
    assert t.gaps == 1
    t.add(9, b"B", wire_len=1)
    assert t.gaps == 1
