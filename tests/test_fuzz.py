"""Deterministic robustness tests: hostile or corrupt input must never crash or exhaust memory."""

import io
import os
import random
import struct

import pytest

from conftest import raw_packets
from quietwire import synth
from quietwire.capture.pcap import CaptureReader, RawPacket
from quietwire.detect.engine import Config, Engine
from quietwire.detect.policy import parse_policy
from quietwire.errors import CaptureFormatError


def corpus_frames():
    pb = synth.scenario_baseline(synth.PcapBuilder(start_ts=1_700_100_000.0), cycles=4)
    synth.scenario_attack(pb)
    return pb


def mutate(rng, data):
    b = bytearray(data)
    kind = rng.randrange(6)
    if not b:
        return bytes(b)
    if kind == 0:  # flip bits
        for _ in range(rng.randrange(1, 6)):
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
    elif kind == 1:  # overwrite a byte
        b[rng.randrange(len(b))] = rng.randrange(256)
    elif kind == 2:  # truncate
        b = b[: rng.randrange(len(b))]
    elif kind == 3:  # insert junk
        pos = rng.randrange(len(b))
        b[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 20)))
    elif kind == 4:  # delete a chunk
        pos = rng.randrange(len(b))
        del b[pos : pos + rng.randrange(1, 20)]
    else:  # splice 0xff / 0x00 runs
        pos = rng.randrange(len(b))
        b[pos : pos + 8] = bytes([rng.choice([0, 255])]) * 8
    return bytes(b)


def feed(frames):
    eng = Engine(parse_policy(synth.demo_policy()), Config(warmup_seconds=0))
    for i, (ts, d) in enumerate(frames, 1):
        eng.process(RawPacket(i, 0, ts, 1, len(d), len(d), d))
    return eng.finalize()


@pytest.mark.parametrize("seed", range(6))
def test_mutated_frames_never_crash_the_engine(seed):
    rng = random.Random(seed)
    frames = corpus_frames().ordered()
    for _round in range(8):
        mutated = [(ts, mutate(rng, d) if rng.random() < 0.15 else d) for ts, d in frames]
        res = feed(mutated)
        assert res.stats.packets == len(frames)
        assert len(res.alerts) <= 20000
        for a in res.alerts:  # every alert must be fully formed
            assert a.rule_id and a.message and a.count >= 1 and a.first_packet.index >= 1
            assert a.to_dict()["severity"] in ("info", "low", "medium", "high", "critical")


@pytest.mark.parametrize("seed", range(4))
def test_payload_level_mutation_through_valid_tcp_framing(seed):
    """Valid Ethernet/IP/TCP with corrupted application bytes: exercises the dissectors + reassembly together."""
    rng = random.Random(100 + seed)
    for _round in range(40):
        pb = synth.PcapBuilder()
        proto = rng.choice(["modbus", "dnp3", "s7comm"])
        port = {"modbus": 502, "dnp3": 20000, "s7comm": 102}[proto]
        c = synth.Conn(pb, "10.0.0.2", "10.0.0.10", 40000, port, mss=rng.choice([1, 5, 40, 1460]))
        c.open()
        for i in range(rng.randrange(3, 12)):
            if proto == "modbus":
                msg = synth.mb_adu(i, rng.randrange(0, 5), rng.choice([
                    synth.mb_read(3, 0, 4), synth.mb_write_single_register(1, 1), synth.mb_diag(4),
                    synth.mb_device_id(), bytes([rng.randrange(256), rng.randrange(256)])]))
            elif proto == "dnp3":
                msg = b"".join(synth.dnp3_frames(rng.randrange(65536), rng.randrange(65536), synth.dnp3_app(
                    rng.choice([1, 2, 4, 5, 13, 129, 130]), synth.dnp3_obj(60, 1, 0x06), seq=i), master=True))
            else:
                msg = rng.choice([synth.s7_read_job(i, [(0x84, 1, 0, 4)]), synth.s7_plc_stop(i),
                                  synth.s7_write_job(i, [(0x84, 1, 0, b"\x00\x01")]), synth.s7_setup(i)])
            if rng.random() < 0.7:
                msg = mutate(rng, msg)
            c.push(rng.random() < 0.7, msg)
        res = feed(pb.ordered())
        assert res.stats.packets == len(pb.frames)


def test_random_ethernet_garbage():
    rng = random.Random(2024)
    eng = Engine()
    for i in range(3000):
        n = rng.randrange(0, 200)
        data = bytes(rng.randrange(256) for _ in range(n))
        if rng.random() < 0.5 and n >= 34:  # make it look like IPv4/TCP to get past the first filters
            data = bytearray(data)
            data[12:14] = b"\x08\x00"
            data[14] = 0x45
            data[23] = rng.choice([6, 17])
            data = bytes(data)
        eng.process(RawPacket(i + 1, 0, 1.0 + i, rng.choice([1, 0, 101, 113, 276, 228, 229, 9999]), len(data), len(data), data))
    res = eng.finalize()
    assert res.stats.packets == 3000


def test_syn_flood_and_port_scan_memory_is_bounded():
    eng = Engine(config=Config(max_flows=1000))
    for i in range(30000):
        src = "10.%d.%d.%d" % (i % 250, (i // 250) % 250, 1 + i % 200)
        l4 = synth.tcp_segment(src, "10.9.9.9", 1024 + i % 60000, 502, 1, 0, synth.SYN)
        d = synth.frame_for(src, "10.9.9.9", 6, l4, "02:00:00:00:00:01", "02:00:00:00:00:02")
        eng.process(RawPacket(i + 1, 0, 1.0 + i * 0.001, 1, len(d), len(d), d))
    assert len(eng.flows) <= 1000
    assert len(eng._syns) <= 65536 and len(eng._neg) <= 65536
    res = eng.finalize()
    assert res.stats.packets == 30000


def test_many_unmatched_requests_do_not_grow_pending_tables():
    pb = synth.PcapBuilder()
    c = synth.Conn(pb, "10.0.0.2", "10.0.0.10", 40000, 502)
    c.open()
    for i in range(20000):
        c.push(True, synth.mb_adu(i & 0xFFFF, 1, synth.mb_read(3, 0, 1)), dt=0.0001)
    eng = Engine()
    for raw in raw_packets(pb):
        eng.process(raw)
    flow = next(iter(eng.flows.values()))
    assert len(flow.scratch["pending"]) <= 4096
    assert eng.finalize().stats.messages["modbus"] == 20000


def test_pcap_reader_survives_random_corruption():
    rng = random.Random(7)
    pb = corpus_frames()
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "b.pcap")
        ng = os.path.join(d, "b.pcapng")
        pb.write_pcap(base)
        pb.write_pcapng(ng)
        for path in (base, ng):
            raw = open(path, "rb").read()
            for _ in range(150):
                blob = mutate(rng, raw) if rng.random() < 0.8 else raw[: rng.randrange(len(raw))]
                try:
                    r = CaptureReader(io.BytesIO(blob))
                    n = sum(1 for _ in r)
                    assert n <= len(pb.frames) + 5
                except CaptureFormatError:
                    pass  # the only exception type the reader may raise on hostile input


def test_pcapng_block_length_bombs_are_rejected_not_allocated():
    e = "<"
    shb_body = struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = struct.pack(e + "II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack(e + "I", 12 + len(shb_body))
    bomb = struct.pack(e + "II", 6, 0x7FFFFFF0)
    with pytest.raises(CaptureFormatError):
        list(CaptureReader(io.BytesIO(shb + bomb)))
