#!/usr/bin/env python3
"""Cross-validate quietwire's dissectors against Wireshark/tshark on real captures.

Level 1 (function codes): for every frame, the multiset of protocol function codes
decoded by quietwire must equal the one tshark reports (TCP retransmissions are
excluded on the tshark side: quietwire deliberately drops retransmitted bytes so
requests are not double counted).

Level 2 (details): decoded field values that detections rely on -- Modbus start
address/quantity, S7 read/write item area/DB/address/length, DNP3 object headers
(group/variation) -- must equal tshark's values.

Requires ``tshark`` on PATH. Usage:

    python scripts/validate_tshark.py CAPTURE [CAPTURE ...] [-d tcp.port==20001,dnp3] [--verbose]
"""

from __future__ import annotations

import argparse
import collections
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from quietwire.capture.pcap import CaptureReader  # noqa: E402
from quietwire.detect.engine import Config, Engine  # noqa: E402
from quietwire.detect.rules import Ctx, Rule  # noqa: E402

DNP3_LINK_NAMES = {"RESET_LINK_STATES", "TEST_LINK_STATES", "REQUEST_LINK_STATUS", "ACK", "NACK", "LINK_STATUS",
                   "NOT_SUPPORTED", "CONFIRMED_USER_DATA", "UNCONFIRMED_USER_DATA"}


class Recorder(Rule):
    def __init__(self):
        self.rows = []

    def evaluate(self, ctx: Ctx):
        if ctx.msg is not None:
            self.rows.append((ctx.pkt.index, ctx.msg))
        return ()


def run_quietwire(path):
    rec = Recorder()
    eng = Engine(config=Config(identify_nonstandard=True), rules=[rec])
    with CaptureReader(path) as r:
        for raw in r:
            eng.process(raw)
    return rec.rows, eng.finalize()


def tshark(path, display_filter, fields, decode_as=()):
    cmd = ["tshark", "-r", path, "-n", "-Y", display_filter, "-T", "fields", "-E", "separator=|",
           "-E", "occurrence=a", "-E", "aggregator=,"]
    for d in decode_as:
        cmd += ["-d", d]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True)
    return [line.split("|") for line in out.stdout.splitlines()]


def ints(cell):
    out = []
    for x in cell.split(","):
        x = x.strip()
        if x:
            try:
                out.append(int(x, 0))
            except ValueError:
                pass
    return out


def usable(proto, m):
    if m.function_code is None or "malformed" in m.kinds:
        return False
    if proto == "dnp3" and (m.function in DNP3_LINK_NAMES or m.function.startswith("LINK_FUNCTION")):
        return False
    if proto == "s7comm" and m.function.startswith(("COTP_", "ACK", "NO_PARAMETER", "S7COMMPLUS", "S7PLUS_")):
        return False
    if proto == "iec104" and m.details.get("format") != "I":
        return False
    return True


FILTERS = {"modbus": ("mbtcp", ["tcp.port==502,mbtcp"]), "dnp3": ("dnp3", []), "s7comm": ("s7comm", []),
           "iec104": ("iec60870_asdu", [])}


def level1(path, rows, decode_as, verbose, totals):
    for proto, (flt, dflt) in FILTERS.items():
        mine = collections.defaultdict(list)
        for idx, m in rows:
            if m.protocol == proto and usable(proto, m):
                mine[idx].append(m.function_code)
        theirs = collections.defaultdict(list)
        field = {"modbus": "modbus.func_code", "dnp3": "dnp3.al.func", "s7comm": "s7comm.param.func",
                 "iec104": "iec60870_asdu.typeid"}[proto]
        for r in tshark(path, "(%s) && !tcp.analysis.retransmission" % flt, ["frame.number", field],
                        list(dflt) + list(decode_as)):
            if len(r) >= 2 and r[0]:
                codes = ints(r[1])
                if proto == "modbus":
                    codes = [c & 0x7F for c in codes]
                theirs[int(r[0])].extend(codes)
        if not mine and not theirs:
            continue
        frames = sorted(set(mine) | set(theirs))
        match = sum(1 for f in frames if sorted(mine.get(f, [])) == sorted(theirs.get(f, [])))
        t = totals.setdefault(proto, [0, 0, 0, 0])
        t[0] += len(frames)
        t[1] += match
        print("   L1 %-7s frames=%d matching=%d (%.1f%%)  messages quietwire=%d tshark=%d"
              % (proto, len(frames), match, 100.0 * match / len(frames),
                 sum(len(v) for v in mine.values()), sum(len(v) for v in theirs.values())))
        shown = 0
        for f in frames:
            if sorted(mine.get(f, [])) != sorted(theirs.get(f, [])) and (verbose or shown < 6):
                print("      frame %d: quietwire=%s tshark=%s" % (f, mine.get(f, []), theirs.get(f, [])))
                shown += 1


def level2(path, rows, decode_as, verbose, totals):
    # ---- Modbus: start address / quantity of requests
    reqs = collections.defaultdict(list)
    for idx, m in rows:
        if m.protocol == "modbus" and m.is_request and m.function_code in (1, 2, 3, 4, 5, 6, 15, 16) \
                and "start" in m.details and not m.anomalies:
            reqs[idx].append((m.function_code, m.details["start"], m.details.get("quantity")))
    if reqs:
        theirs = collections.defaultdict(list)
        for r in tshark(path, "mbtcp && !tcp.analysis.retransmission",
                        ["frame.number", "modbus.func_code", "modbus.reference_num", "modbus.word_cnt",
                         "modbus.bit_cnt"], ["tcp.port==502,mbtcp"] + list(decode_as)):
            if len(r) < 5 or not r[0]:
                continue
            fcs, refs, words, bits = ints(r[1]), ints(r[2]), ints(r[3]), ints(r[4])
            if refs and fcs and fcs[0] in (1, 2, 3, 4, 5, 6, 15, 16):
                cnt = (words or bits or [None])[0]
                theirs[int(r[0])].append((fcs[0], refs[0], cnt))
        checked = bad = 0
        for f, mine in reqs.items():
            for (fc, start, qty), tt in zip(sorted(mine, key=str), sorted(theirs.get(f, []), key=str)):
                checked += 1
                ok = fc == tt[0] and start == tt[1] and (tt[2] is None or qty == tt[2])
                if not ok:
                    bad += 1
                    if verbose or bad <= 5:
                        print("      modbus detail mismatch frame %d: quietwire=%s tshark=%s" % (f, (fc, start, qty), tt))
        t = totals.setdefault("modbus-detail", [0, 0, 0, 0])
        t[0] += checked
        t[1] += checked - bad
        print("   L2 modbus  request start/quantity: %d compared, %d mismatched" % (checked, bad))
    # ---- S7: read/write var items
    items = collections.defaultdict(list)
    for idx, m in rows:
        if m.protocol == "s7comm" and m.is_request and m.function_code in (0x04, 0x05) and not m.anomalies:
            for it in m.details.get("items", []):
                if "db" in it:
                    items[idx].append((it["area_code"], it["db"], it["address"], it["length"], it["data_type"]))
    if items:
        theirs = collections.defaultdict(list)
        rows_t = tshark(path, "s7comm.param.item.area && !tcp.analysis.retransmission",
                        ["frame.number", "s7comm.header.rosctr", "s7comm.param.item.area", "s7comm.param.item.db",
                         "s7comm.param.item.address", "s7comm.param.item.length", "s7comm.param.item.transp_size"],
                        list(decode_as))
        for r in rows_t:
            if len(r) < 7 or not r[0] or not r[2]:
                continue
            for a, d, ad, ln, ts in zip(ints(r[2]), ints(r[3]), ints(r[4]), ints(r[5]), ints(r[6])):
                theirs[int(r[0])].append((a, d, ad, ln, ts))
        checked = bad = 0
        for f, mine in items.items():
            tt = theirs.get(f, [])
            for a, b in zip(mine, tt):
                checked += 1
                if a != b:
                    bad += 1
                    if verbose or bad <= 5:
                        print("      s7 item mismatch frame %d: quietwire=%s tshark=%s" % (f, a, b))
            if len(mine) != len(tt):
                bad += 1
                print("      s7 item count mismatch frame %d: quietwire=%d tshark=%d" % (f, len(mine), len(tt)))
        t = totals.setdefault("s7-detail", [0, 0, 0, 0])
        t[0] += checked
        t[1] += checked - bad
        print("   L2 s7comm  var items (area/db/address/length/type): %d compared, %d mismatched" % (checked, bad))
    # ---- DNP3: object headers
    objs = collections.defaultdict(list)
    for idx, m in rows:
        if m.protocol == "dnp3" and m.details.get("layer") == "application" and not m.anomalies:
            objs[idx].extend((o["group"] << 8) | o["variation"] for o in m.details.get("objects", []))
    if objs:
        theirs = collections.defaultdict(list)
        for r in tshark(path, "dnp3.al.func && !tcp.analysis.retransmission", ["frame.number", "dnp3.al.obj"],
                        list(decode_as)):
            if len(r) >= 2 and r[0]:
                theirs[int(r[0])].extend(ints(r[1]))
        checked = bad = 0
        for f, mine in objs.items():
            tt = theirs.get(f, [])
            n = min(len(mine), len(tt))
            checked += 1
            if mine[:n] != tt[:n] or (len(mine) < 32 and len(mine) != len(tt)):
                bad += 1
                if verbose or bad <= 5:
                    print("      dnp3 object mismatch frame %d: quietwire=%s tshark=%s"
                          % (f, [hex(x) for x in mine[:8]], [hex(x) for x in tt[:8]]))
        t = totals.setdefault("dnp3-detail", [0, 0, 0, 0])
        t[0] += checked
        t[1] += checked - bad
        print("   L2 dnp3    object header lists: %d messages compared, %d mismatched" % (checked, bad))


def level2_iec104(path, rows, decode_as, verbose, totals):
    """ASDU header details: cause of transmission, common address, object addresses."""
    mine = collections.defaultdict(list)
    for idx, m in rows:
        if m.protocol == "iec104" and m.details.get("format") == "I" and "malformed" not in m.kinds:
            d = m.details
            mine[idx].append((d["type_id"], d["cause"], d["common_address"], d["num_objects"],
                              tuple(d["ioas"]) if not d["sq"] else (d["ioas"][0],) if d["ioas"] else ()))
    if not mine:
        return
    theirs = collections.defaultdict(list)
    cols = ["frame.number", "iec60870_asdu.typeid", "iec60870_asdu.causetx", "iec60870_asdu.addr", "iec60870_asdu.numix",
            "iec60870_asdu.sq", "iec60870_asdu.ioa"]
    for r in tshark(path, "iec60870_asdu && !tcp.analysis.retransmission", cols, list(decode_as)):
        if len(r) < 7 or not r[0]:
            continue
        tids, causes, cas, nums, ioas = ints(r[1]), ints(r[2]), ints(r[3]), ints(r[4]), ints(r[6])
        sqs = [1 if x.strip().lower() in ("1", "true") else 0 for x in r[5].split(",") if x.strip()]
        pos = 0
        for k in range(len(tids)):
            n = nums[k] if k < len(nums) else 0
            sq = (sqs[k] if k < len(sqs) else 0) == 1
            take = n  # tshark lists every object's address, even when SQ=1
            objs = tuple(ioas[pos : pos + take])
            pos += take
            theirs[int(r[0])].append((tids[k], causes[k] if k < len(causes) else None, cas[k] if k < len(cas) else None, n,
                                      objs[:8] if not sq else objs[:1]))
    checked = bad = 0
    for f, a in mine.items():
        b = theirs.get(f, [])
        for x, y in zip(a, b):
            checked += 1
            if x != y:
                bad += 1
                if verbose or bad <= 5:
                    print("      iec104 detail mismatch frame %d: quietwire=%s tshark=%s" % (f, x, y))
    t = totals.setdefault("iec104-detail", [0, 0, 0, 0])
    t[0] += checked
    t[1] += checked - bad
    print("   L2 iec104  ASDU type/cause/CA/objects/IOAs: %d compared, %d mismatched" % (checked, bad))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("captures", nargs="+")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("-d", "--decode-as", action="append", default=[],
                    help="tshark decode-as spec, e.g. tcp.port==20001,dnp3 (for non-standard ports)")
    args = ap.parse_args()
    totals = {}
    for path in args.captures:
        print("== %s" % os.path.basename(path))
        rows, res = run_quietwire(path)
        level1(path, rows, args.decode_as, args.verbose, totals)
        level2(path, rows, args.decode_as, args.verbose, totals)
        level2_iec104(path, rows, args.decode_as, args.verbose, totals)
    print("\nTOTALS (frames or items compared / matching):")
    for k, (n, ok, _a, _b) in sorted(totals.items()):
        print("   %-14s %6d / %-6d %.2f%%" % (k, n, ok, 100.0 * ok / n if n else 100.0))


if __name__ == "__main__":
    main()
