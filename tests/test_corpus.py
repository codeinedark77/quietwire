"""Regression guard against real-world captures (optional).

Set QUIETWIRE_CORPUS to a directory holding (copies of) the public captures listed below and these
tests verify that every file is processed without error and yields exactly the message counts that
were cross-validated against tshark (see docs/VALIDATION.md). Without the variable they are skipped;
the captures themselves are not redistributed with this package.

Sources: nDPI (tests/cfgs/default/pcap: dnp3, modbus, s7comm, s7comm-plus; prefixed ``ndpi_`` here) and
Zeek (testing/btest/Traces/{dnp3,modbus}).
"""

import os

import pytest

from quietwire.capture.pcap import CaptureReader
from quietwire.detect.engine import Engine

CORPUS = os.environ.get("QUIETWIRE_CORPUS")
pytestmark = pytest.mark.skipif(not CORPUS or not os.path.isdir(CORPUS), reason="QUIETWIRE_CORPUS not set")

EXPECTED = {  # file -> (packets, total ICS messages decoded, messages with protocol anomalies)
    '4SICS-GeekLounge-151022-min.pcap': (2, 2, 1),
    'dnp3-flowbuffer-overflow-assert.pcap': (9, 1, 1),
    'dnp3.pcap': (214, 115, 6),
    'dnp3_del_measure.pcap': (10, 2, 0),
    'dnp3_en_spon.pcap': (10, 2, 0),
    'dnp3_file_del.pcap': (10, 2, 0),
    'dnp3_file_read.pcap': (30, 11, 0),
    'dnp3_file_write.pcap': (22, 6, 0),
    'dnp3_link_only.pcap': (35, 9, 0),
    'dnp3_read.pcap': (10, 2, 0),
    'dnp3_read_p20001.pcap': (10, 2, 0),
    'dnp3_rec_time.pcap': (10, 2, 0),
    'dnp3_select_operate.pcap': (13, 4, 0),
    'dnp3_udp_en_spon.pcap': (4, 4, 0),
    'dnp3_udp_read.pcap': (23, 9, 0),
    'dnp3_udp_select_operate.pcap': (10, 8, 0),
    'dnp3_udp_write.pcap': (2, 2, 0),
    'dnp3_write.pcap': (10, 2, 0),
    'fuzz-1011.pcap': (6, 4, 1),
    'fuzz-72.pcap': (36, 19, 2),
    'modbus-and-non-modbus-p502.pcap': (86, 23, 11),
    'modbus-eit.pcap': (4, 4, 0),
    'modbus.pcap': (60227, 39988, 32),
    'modbusBig.pcap': (13622, 6688, 0),
    'modbusSmall.pcap': (166, 32, 0),
    'ndpi_IEC104.pcap': (15, 8, 0),
    'ndpi_dnp3.pcap': (543, 93, 6),
    'ndpi_iec60780-5-104.pcap': (147, 86, 29),
    'ndpi_modbus.pcap': (102, 102, 0),
    'ndpi_s7comm-plus.pcap': (79, 26, 0),
    'ndpi_s7comm.pcap': (193, 145, 0),
}


def find(name):
    for root, _dirs, files in os.walk(CORPUS):
        if name in files:
            return os.path.join(root, name)
    return None


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_capture_matches_cross_validated_counts(name):
    path = find(name)
    if path is None:
        pytest.skip("%s not present in corpus" % name)
    eng = Engine()
    with CaptureReader(path) as r:
        for raw in r:
            eng.process(raw)
    res = eng.finalize()
    packets, messages, anomalous = EXPECTED[name]
    assert res.stats.packets == packets
    assert sum(res.stats.messages.values()) == messages
    assert sum(res.stats.malformed.values()) == anomalous
    assert not eng.flows
