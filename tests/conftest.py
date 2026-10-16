import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from quietwire import synth  # noqa: E402
from quietwire.capture.pcap import RawPacket  # noqa: E402
from quietwire.detect.engine import Config, Engine  # noqa: E402
from quietwire.detect.policy import Policy, parse_policy  # noqa: E402


def raw_packets(pb):
    offset = 24
    for i, (ts, data) in enumerate(pb.ordered(), 1):
        yield RawPacket(i, offset, ts, pb.linktype, len(data), len(data), data)
        offset += 16 + len(data)


def run(pb, policy=None, cfg=None, rules=None, on_alert=None):
    """Feed a PcapBuilder straight into an Engine and return its Result."""
    if isinstance(policy, dict):
        policy = parse_policy(policy)
    eng = Engine(policy, cfg, on_alert, rules=rules)
    for raw in raw_packets(pb):
        eng.process(raw)
    return eng.finalize()


def rule_ids(result):
    return sorted({a.rule_id for a in result.alerts})


def alerts_for(result, rule_id):
    return [a for a in result.alerts if a.rule_id == rule_id]


@pytest.fixture
def fresh_pb():
    return synth.PcapBuilder()


@pytest.fixture
def demo_policy():
    return synth.demo_policy()


def single_modbus(requests, server=synth.MB_PLC, client=synth.HMI, pb=None, sport=502, handshake=True):
    """Build a one-connection Modbus capture. ``requests`` is a list of (from_client, adu_bytes)."""
    pb = pb or synth.PcapBuilder()
    c = synth.Conn(pb, client, server, 41000, sport)
    if handshake:
        c.open()
    for from_client, adu in requests:
        c.push(from_client, adu)
    if handshake:
        c.close()
    return pb
