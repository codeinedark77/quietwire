#!/usr/bin/env python3
"""Cross-check quietwire's pcap/pcapng reader and link/IP/TCP/UDP decoder against dpkt.

For every packet of every capture: record count, timestamp, raw bytes and (for IPv4/IPv6
TCP/UDP) the 5-tuple, TCP sequence/flags and payload bytes must be identical to what
dpkt reports. Requires ``pip install dpkt``.

    python scripts/validate_dpkt.py CAPTURE [CAPTURE ...]
"""

from __future__ import annotations

import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import dpkt  # noqa: E402

from quietwire.capture.pcap import CaptureReader  # noqa: E402
from quietwire.net.decode import decode_packet  # noqa: E402


def dpkt_packets(path):
    with open(path, "rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            return list(dpkt.pcapng.Reader(fh)), "pcapng"
        return list(dpkt.pcap.Reader(fh)), "pcap"


def dpkt_decode(buf):
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return None
    ip = eth.data
    if isinstance(ip, dpkt.ip.IP):
        if ip.mf or ip.offset:
            return "fragment"
        src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
    elif isinstance(ip, dpkt.ip6.IP6):
        src, dst = socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst)
    else:
        return None
    l4 = ip.data
    if isinstance(l4, dpkt.tcp.TCP):
        return ("tcp", src, dst, l4.sport, l4.dport, l4.seq, l4.ack, l4.flags & 0x3F, bytes(l4.data))
    if isinstance(l4, dpkt.udp.UDP):
        return ("udp", src, dst, l4.sport, l4.dport, 0, 0, 0, bytes(l4.data))
    return None


def main():
    total = bad_reader = bad_decode = compared = 0
    for path in sys.argv[1:]:
        theirs, fmt = dpkt_packets(path)
        with CaptureReader(path) as r:
            mine = list(r)
        total += len(mine)
        if len(mine) != len(theirs):
            bad_reader += 1
            print("%s: packet count differs quietwire=%d dpkt=%d" % (os.path.basename(path), len(mine), len(theirs)))
            continue
        for m, (ts, buf) in zip(mine, theirs):
            if abs(m.ts - float(ts)) > 2e-6 or m.data != bytes(buf):
                bad_reader += 1
                print("%s: packet %d differs (ts %.6f vs %.6f)" % (os.path.basename(path), m.index, m.ts, float(ts)))
                break
        for m, (ts, buf) in zip(mine, theirs):
            ref = dpkt_decode(bytes(buf))
            pkt, why = decode_packet(m.linktype, m.data)
            if ref is None or ref == "fragment":
                continue
            compared += 1
            if pkt is None:
                bad_decode += 1
                if bad_decode <= 5:
                    print("%s: packet %d: dpkt decoded %s but quietwire skipped it (%s)"
                          % (os.path.basename(path), m.index, ref[0], why))
                continue
            got = ("tcp" if pkt.is_tcp else "udp", pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
                   pkt.seq, pkt.ack, pkt.flags, pkt.payload)
            if got != ref:
                # dpkt does not bound the TCP payload by the IP total length (Ethernet padding); allow that
                if got[:-1] == ref[:-1] and ref[-1].startswith(got[-1]):
                    continue
                bad_decode += 1
                if bad_decode <= 5:
                    print("%s: packet %d differs: quietwire=%s dpkt=%s" % (os.path.basename(path), m.index,
                                                                       got[:8], ref[:8]))
    print("packets=%d  decoded-and-compared=%d  reader mismatches=%d  decoder mismatches=%d"
          % (total, compared, bad_reader, bad_decode))
    return 1 if bad_reader or bad_decode else 0


if __name__ == "__main__":
    sys.exit(main())
