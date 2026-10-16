"""allowed_functions policy section and the QW-F002 rule."""

import pytest

from conftest import alerts_for, run
from quietwire import synth
from quietwire.detect.policy import build_baseline, parse_policy
from quietwire.errors import PolicyError
from quietwire.model import Severity
from quietwire.proto import FUNCTION_KINDS, function_names
from quietwire.synth import (HMI, MB_PLC, RTU, S7_PLC, SCADA, Conn, PcapBuilder, dnp3_app, dnp3_frames, dnp3_obj,
                             mb_adu)


def pol(entries, **kw):
    doc = {"version": 1, "allowed_functions": entries}
    doc.update(kw)
    return parse_policy(doc)


def entry(functions, master=HMI, server=MB_PLC, protocol="modbus"):
    e = {"master": master, "server": server, "functions": functions}
    if protocol:
        e["protocol"] = protocol
    return e


def test_catalogues_cover_every_protocol():
    for proto, sample in (("modbus", "READ_HOLDING_REGISTERS"), ("dnp3", "DIRECT_OPERATE"), ("s7comm", "PLC_STOP"),
                          ("iec104", "C_SC_NA_1")):
        assert sample in function_names(proto)
    assert "READ_SZL" in function_names("s7comm") and function_names("bacnet") == frozenset()
    assert {"read", "write", "critical"} <= FUNCTION_KINDS


def test_semantics_none_true_false_and_union():
    p = pol([entry(["READ_COILS"]), entry(["WRITE_SINGLE_COIL"], master="10.0.0.0/24")])
    k = frozenset()
    assert p.function_allowed(HMI, MB_PLC, "modbus", "READ_COILS", k) is True
    assert p.function_allowed(HMI, MB_PLC, "modbus", "WRITE_SINGLE_COIL", k) is True      # union of covering entries
    assert p.function_allowed(HMI, MB_PLC, "modbus", "DIAGNOSTICS", k) is False
    assert p.function_allowed("192.168.1.1", MB_PLC, "modbus", "DIAGNOSTICS", k) is None  # no covering entry
    assert p.function_allowed(HMI, MB_PLC, "dnp3", "READ", k) is None                    # protocol-scoped entries
    assert Policy_default().function_allowed(HMI, MB_PLC, "modbus", "X", k) is None
    assert pol([]).function_allowed(HMI, MB_PLC, "modbus", "X", k) is None               # empty list covers nothing
    assert "allowed_functions" in p.enforced_sections()


def Policy_default():
    from quietwire.detect.policy import Policy
    return Policy()


def test_wildcards_tags_unknown_placeholders_and_protocolless_entries():
    p = pol([entry(["*"])])
    assert p.function_allowed(HMI, MB_PLC, "modbus", "DIAGNOSTICS", frozenset()) is True
    p = pol([entry(["@read"])])
    assert p.function_allowed(HMI, MB_PLC, "modbus", "READ_COILS", frozenset(["read"])) is True
    assert p.function_allowed(HMI, MB_PLC, "modbus", "WRITE_SINGLE_COIL", frozenset(["write"])) is False
    p = pol([entry(["UNKNOWN_90", "READ_COILS"])])
    assert p.function_allowed(HMI, MB_PLC, "modbus", "UNKNOWN_90", frozenset()) is True
    p = pol([entry(["READ_COILS", "READ", "PLC_STOP", "C_SC_NA_1"], protocol=None)])  # any protocol's names
    assert p.function_allowed(HMI, MB_PLC, "modbus", "READ", frozenset()) is True


@pytest.mark.parametrize("doc,fragment", [
    ({"allowed_functions": {}}, "must be a list"),
    ({"allowed_functions": [5]}, "must be an object"),
    ({"allowed_functions": [{"master": "1.1.1.1", "server": "2.2.2.2"}]}, "missing required key 'functions'"),
    ({"allowed_functions": [{"master": "1.1.1.1", "server": "2.2.2.2", "functions": [], "x": 1}]}, "unknown key"),
    ({"allowed_functions": [entry(["READ_VAR"])]}, "unknown function name 'READ_VAR' for protocol modbus"),
    ({"allowed_functions": [entry(["READ_COLS"])]}, "unknown function name"),
    ({"allowed_functions": [entry(["@reed"])]}, "unknown tag"),
    ({"allowed_functions": [entry([7])]}, "non-empty string"),
    ({"allowed_functions": [entry([""])]}, "non-empty string"),
    ({"allowed_functions": [entry("READ_COILS")]}, "must be a list"),
    ({"allowed_functions": [entry(["READ_COILS"], protocol="bacnet")]}, "must be one of"),
    ({"allowed_functions": [entry(["READ_COILS"], master="999.1.1.1")]}, "invalid IP"),
])
def test_validation_errors(doc, fragment):
    with pytest.raises(PolicyError) as exc:
        parse_policy(dict(doc, version=1))
    assert fragment in str(exc.value)


def mb_capture(*functions, client=HMI):
    pb = PcapBuilder()
    c = Conn(pb, client, MB_PLC, 41000, 502)
    c.open()
    for i, pdu in enumerate(functions):
        c.push(True, mb_adu(i, 1, pdu))
        c.push(False, mb_adu(i, 1, synth.mb_resp_registers(3, [1])))
    return pb


def test_rule_flags_only_unlisted_requests_on_covered_paths():
    pb = mb_capture(synth.mb_read(3, 0, 1), synth.mb_write_single_register(1, 1), synth.mb_diag(0), synth.mb_diag(4))
    r = run(pb, {"allowed_functions": [entry(["READ_HOLDING_REGISTERS", "WRITE_SINGLE_REGISTER"])]})
    a = alerts_for(r, "QW-F002")
    assert len(a) == 1 and a[0].details["function"] == "DIAGNOSTICS" and a[0].count == 2
    assert a[0].severity is Severity.HIGH and a[0].mitre == ()          # diagnostics is not a write
    assert "does not permit" in a[0].message
    assert not alerts_for(run(pb, {"allowed_functions": [entry(["READ_HOLDING_REGISTERS"], master="10.7.7.7")]}), "QW-F002")


def test_impactful_function_carries_attack_technique_and_severity_override():
    pb = mb_capture(synth.mb_write_single_register(1, 1))
    r = run(pb, {"allowed_functions": [entry(["READ_COILS"])], "severity_overrides": {"QW-F002": "critical"}})
    a = alerts_for(r, "QW-F002")
    assert a[0].mitre == ("T1692.001",) and a[0].severity is Severity.CRITICAL
    assert not alerts_for(run(pb, {"allowed_functions": [entry(["READ_COILS"])], "ignore_rules": ["QW-F002"]}), "QW-F002")


def test_session_link_response_and_malformed_messages_are_exempt():
    pol_ = {"allowed_functions": [{"master": "*", "server": "*", "functions": ["READ_VAR"]}]}
    pb = PcapBuilder()
    s7 = Conn(pb, synth.EWS, S7_PLC, 40000, 102)
    s7.open()
    s7.push(True, synth.tpkt(synth.cotp_cr()))
    s7.push(True, synth.s7_setup(0))
    s7.push(True, synth.s7_read_job(1, [(0x84, 1, 0, 4)]))
    s7.push(False, synth.s7_read_ack(1, [b"\x00\x00\x00\x01"]))
    dn = Conn(pb, SCADA, RTU, 40001, 20000)
    dn.open()
    for f in dnp3_frames(20, 3, dnp3_app(1, dnp3_obj(60, 1, 0x06)), master=True):
        dn.push(True, f)
    dn.push(True, synth.dnp3_link(20, 3, 0xC0))  # link-level reset: no application function
    ic = Conn(pb, "10.0.0.5", "10.0.0.50", 40002, 2404)
    ic.open()
    ic.push(True, synth.iec104_apdu_u(0x07))
    ic.push(True, synth.iec104_apdu_s(1))
    mb = Conn(pb, HMI, MB_PLC, 40003, 502)
    mb.open()
    mb.push(True, b"\xff" * 20)  # malformed
    r = run(pb, pol_)
    flagged = {(a.protocol, a.details["function"]) for a in alerts_for(r, "QW-F002")}
    assert flagged == {("dnp3", "READ")}  # only the genuine application request that is not READ_VAR


def test_dnp3_iec104_and_s7_functions_are_enforced():
    pb = PcapBuilder()
    ic = Conn(pb, "10.0.0.5", "10.0.0.50", 40002, 2404)
    ic.open()
    ic.push(True, synth.iec104_interrogation())
    ic.push(True, synth.iec104_reset_process())
    ic.push(True, synth.iec104_single_command(5, True))
    s7 = Conn(pb, synth.EWS, S7_PLC, 40000, 102)
    s7.open()
    s7.push(True, synth.s7_plc_stop())
    s7.push(True, synth.s7_userdata(4, 1, data=b"\xff\x09\x00\x04\x00\x11\x00\x01"))
    r = run(pb, {"allowed_functions": [
        {"master": "10.0.0.5", "server": "10.0.0.50", "protocol": "iec104", "functions": ["C_IC_NA_1", "@control"]},
        {"master": synth.EWS, "server": S7_PLC, "protocol": "s7comm", "functions": ["READ_SZL"]}]})
    assert {a.details["function"] for a in alerts_for(r, "QW-F002")} == {"C_RP_NA_1", "PLC_STOP"}


def test_baseline_emits_allowed_functions_and_roundtrips_clean():
    pb = synth.scenario_baseline()
    inv = run(pb).inventory
    doc = build_baseline(inv)
    by_proto = {e["protocol"]: e for e in doc["allowed_functions"]}
    assert by_proto["modbus"]["functions"] == ["READ_HOLDING_REGISTERS", "WRITE_SINGLE_REGISTER"]
    assert by_proto["dnp3"]["functions"] == ["DIRECT_OPERATE", "READ"]
    assert by_proto["s7comm"]["functions"] == ["READ_VAR", "WRITE_VAR"]       # session messages excluded
    learned = parse_policy(doc)
    assert run(synth.scenario_baseline(), learned).alerts == []
    # a function never seen during baselining is flagged on a known path
    extra = synth.scenario_baseline()
    c = Conn(extra, HMI, MB_PLC, 40100, 502)
    c.push(True, mb_adu(77, 1, synth.mb_diag(4)))
    got = alerts_for(run(extra, learned), "QW-F002")
    assert [a.details["function"] for a in got] == ["DIAGNOSTICS"]


def test_demo_policy_with_functions_still_flags_the_attack_but_not_the_baseline():
    assert run(synth.scenario_baseline(), synth.demo_policy()).alerts == []
