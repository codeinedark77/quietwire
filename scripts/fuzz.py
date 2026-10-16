#!/usr/bin/env python3
"""Long-running mutation fuzzer for the whole analysis pipeline.

Mutates frames of synthetic scenarios and (optionally) real capture files, feeds
them through the Engine and records any exception or runaway resource use.

    python scripts/fuzz.py --seconds 120 [--seed 1] [corpus.pcap ...]
"""

from __future__ import annotations

import argparse
import collections
import os
import random
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"))

from quietwire import synth  # noqa: E402
from quietwire.capture.pcap import CaptureReader, RawPacket  # noqa: E402
from quietwire.detect.engine import Config, Engine  # noqa: E402
from quietwire.detect.policy import parse_policy  # noqa: E402
from test_fuzz import mutate  # noqa: E402


def load_real(paths, limit=3000):
    out = []
    for p in paths:
        try:
            with CaptureReader(p) as r:
                for raw in r:
                    out.append((raw.ts, raw.data, raw.linktype))
                    if len(out) >= limit:
                        return out
        except Exception:
            continue
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=60)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("captures", nargs="*")
    args = ap.parse_args()
    rng = random.Random(args.seed)
    pb = synth.scenario_baseline(synth.PcapBuilder(start_ts=1_700_100_000.0), cycles=4)
    synth.scenario_attack(pb)
    sources = [[(ts, d, 1) for ts, d in pb.ordered()]]
    # tunnelled and fragmented variants exercise the decapsulation and reassembly code with hostile bytes too
    for kind in ("gre-ip", "gre-teb", "erspan2", "erspan3-sub", "vxlan", "ipip", "mpls-stack", "pppoe"):
        sources.append([(ts, d, 1) for ts, d in synth.encapsulate(pb, kind).ordered()])
    sources.append([(ts, d, 1) for ts, d in synth.fragment_capture(pb, 16, shuffle_seed=9).ordered()])
    sources.append([(ts, d, 1) for ts, d in synth.fragment_capture(synth.encapsulate(pb, "gre-ip"), 16, only_if_longer=20,
                                                                  shuffle_seed=5).ordered()])
    for p in args.captures:
        real = load_real([p])
        if real:
            sources.append(real)
    policy = parse_policy(synth.demo_policy())
    crashes = collections.Counter()
    first = {}
    runs = pkts = 0
    t0 = time.time()
    while time.time() - t0 < args.seconds:
        frames = rng.choice(sources)
        rate = rng.choice([0.02, 0.1, 0.3, 0.7])
        eng = Engine(policy if rng.random() < 0.5 else None, Config(warmup_seconds=0))
        i = 0
        try:
            for ts, d, lt in frames:
                if rng.random() < rate:
                    d = mutate(rng, d)
                if rng.random() < 0.02:
                    ts += rng.choice([-5.0, 5.0, 1e6])
                i += 1
                eng.process(RawPacket(i, 0, ts, lt, len(d), len(d), d))
                pkts += 1
            res = eng.finalize()
            assert res.stats.packets == i
            assert len(eng.flows) == 0
        except Exception as exc:  # noqa: BLE001
            tb = traceback.format_exc()
            key = tb.strip().splitlines()[-3:]
            sig = "|".join(key)
            crashes[sig] += 1
            first.setdefault(sig, tb)
        runs += 1
    print("fuzz: %d runs, %d packets in %.0fs, %d distinct crash signatures" % (runs, pkts, time.time() - t0, len(crashes)))
    for sig, n in crashes.most_common():
        print("---- %d x" % n)
        print(first[sig])
    return 1 if crashes else 0


if __name__ == "__main__":
    sys.exit(main())
