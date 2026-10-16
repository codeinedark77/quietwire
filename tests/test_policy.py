import json

import pytest

from quietwire.detect.policy import IPMatcher, Policy, build_baseline, load_policy, parse_policy
from quietwire.errors import PolicyError
from quietwire.model import Severity, Target


def pol(**kw):
    doc = {"version": 1}
    doc.update(kw)
    return parse_policy(doc)


def test_empty_policy_enforces_nothing():
    p = Policy()
    assert p.enforced_sections() == []
    assert p.flow_allowed("1.1.1.1", "2.2.2.2", "modbus", 502)
    assert p.writer_allowed("modbus", "1.1.1.1") is None
    assert p.asset_known("9.9.9.9") is False and not p.enforce_assets
    assert p.range_violations("2.2.2.2", "modbus", 1, (Target("coil", 0, 0),)) is None


def test_ipmatcher_exact_cidr_v6_wildcard_and_cache():
    m = IPMatcher(["10.0.0.1", "192.168.0.0/16", "fd00::/8", "2001:db8::5"])
    assert m.matches("10.0.0.1") and not m.matches("10.0.0.2")
    assert m.matches("192.168.77.9") and not m.matches("192.169.0.1")
    assert m.matches("fd00::1234") and m.matches("2001:db8::5") and not m.matches("2001:db8::6")
    assert m.matches("10.0.0.1")  # cached path
    assert not m.matches("not-an-ip")
    assert IPMatcher(["*"]).matches("203.0.113.9")
    assert not IPMatcher([]) and IPMatcher(["1.2.3.4"])
    # IPv4 address must not match an IPv6 network and vice versa
    assert not IPMatcher(["fd00::/8"]).matches("10.0.0.1")
    with pytest.raises(PolicyError):
        IPMatcher(["300.1.1.1"])
    assert IPMatcher(["::1"]).matches("::1")


def test_assets_section_enables_enforcement():
    p = pol(assets=[{"ip": "10.0.0.5", "name": "PLC-1", "role": "plc"}, {"ip": "10.9.0.0/24"}])
    assert p.enforce_assets and p.asset_known("10.0.0.5") and p.asset_known("10.9.0.77")
    assert not p.asset_known("10.0.0.6")
    assert p.assets["10.0.0.5"] == {"name": "PLC-1", "role": "plc"}
    assert "assets" in p.enforced_sections()
    assert not pol(assets=[{"ip": "1.1.1.1"}], enforce_assets=False).enforce_assets


def test_flow_rules():
    p = pol(allowed_flows=[
        {"master": "10.0.0.2", "server": "10.0.0.10", "protocol": "modbus", "port": 502},
        {"master": ["10.0.1.0/24", "10.0.2.5"], "server": "10.0.0.20"},
    ])
    assert p.flow_allowed("10.0.0.2", "10.0.0.10", "modbus", 502)
    assert not p.flow_allowed("10.0.0.2", "10.0.0.10", "modbus", 5020)
    assert not p.flow_allowed("10.0.0.2", "10.0.0.10", "dnp3", 502)
    assert p.flow_allowed("10.0.1.77", "10.0.0.20", "dnp3", 20000)
    assert p.flow_allowed("10.0.2.5", "10.0.0.20", "s7comm", 102)
    assert not p.flow_allowed("10.0.2.6", "10.0.0.20", "s7comm", 102)
    assert not pol(allowed_flows=[]).flow_allowed("1.1.1.1", "2.2.2.2", "modbus", 502)  # present-but-empty = deny all


def test_writers_and_engineering_stations():
    p = pol(writers={"modbus": ["10.0.0.2"], "dnp3": []}, engineering_stations=["10.0.0.9"])
    assert p.writer_allowed("modbus", "10.0.0.2") is True
    assert p.writer_allowed("modbus", "10.0.0.3") is False
    assert p.writer_allowed("dnp3", "10.0.0.2") is False  # present-but-empty
    assert p.writer_allowed("s7comm", "10.0.0.2") is None
    assert p.is_engineering_station("10.0.0.9") and not p.is_engineering_station("10.0.0.2")
    assert {"writers.modbus", "writers.dnp3", "engineering_stations"} <= set(p.enforced_sections())


def test_write_ranges_semantics():
    p = pol(write_ranges=[
        {"server": "10.0.0.10", "protocol": "modbus", "unit": 1, "area": "holding_register", "start": 100, "end": 109},
        {"server": "10.0.0.10", "protocol": "modbus", "area": "coil", "start": 0, "end": 7},
    ])
    hr = lambda a, b: (Target("holding_register", a, b),)  # noqa: E731
    assert p.range_violations("10.0.0.10", "modbus", 1, hr(100, 109)) == []
    assert p.range_violations("10.0.0.10", "modbus", 1, hr(100, 110))[0].end == 110
    assert p.range_violations("10.0.0.10", "modbus", 1, hr(99, 100))
    assert p.range_violations("10.0.0.10", "modbus", 2, hr(100, 100))  # unit 2: only the unit-less coil range applies
    assert p.range_violations("10.0.0.10", "modbus", 5, (Target("coil", 0, 7),)) == []
    assert p.range_violations("10.0.0.99", "modbus", 1, hr(0, 0)) is None  # server not covered => not enforced
    assert p.range_violations("10.0.0.10", "dnp3", None, hr(0, 0)) is None
    assert p.range_violations("10.0.0.10", "modbus", 1, ()) == []
    assert p.ranges_enforced_for("10.0.0.10", "modbus", 1) and not p.ranges_enforced_for("10.0.0.11", "modbus", 1)
    # an unknown unit still counts as enforced (conservative)
    assert p.ranges_enforced_for("10.0.0.10", "modbus", None)
    # a target straddling two permitted ranges is NOT permitted (ranges are not merged)
    p2 = pol(write_ranges=[{"server": "*", "protocol": "s7comm", "area": "DB1", "start": 0, "end": 9},
                           {"server": "*", "protocol": "s7comm", "area": "DB1", "start": 10, "end": 19}])
    assert p2.range_violations("1.1.1.1", "s7comm", None, (Target("DB1", 5, 15),))


def test_ignore_rules_severity_overrides_and_thresholds():
    p = pol(ignore_rules=["QW-W002"], severity_overrides={"QW-A001": "critical"},
            thresholds={"sweep_hosts": 3, "warmup_seconds": 1.5})
    assert p.ignore_rules == {"QW-W002"}
    assert p.severity_overrides == {"QW-A001": Severity.CRITICAL}
    assert p.thresholds == {"sweep_hosts": 3, "warmup_seconds": 1.5}


def test_annotation_keys_are_ignored():
    p = parse_policy({"version": 1, "_note": "hi", "_generated_by": "x", "assets": [{"ip": "1.1.1.1"}]})
    assert p.asset_known("1.1.1.1")


@pytest.mark.parametrize("doc,fragment", [
    ([], "JSON object"),
    ({"version": 2}, "version"),
    ({"asets": []}, "unknown policy key"),
    ({"assets": {}}, "must be a list"),
    ({"assets": [{"ip": 5}]}, "string 'ip'"),
    ({"assets": [{"ip": "1.1.1.1", "color": "red"}]}, "unknown key"),
    ({"assets": [{"ip": "999.1.1.1"}]}, "invalid IP"),
    ({"enforce_assets": "yes"}, "true or false"),
    ({"allowed_flows": [5]}, "must be an object"),
    ({"allowed_flows": [{"master": "1.1.1.1"}]}, "missing required key 'server'"),
    ({"allowed_flows": [{"master": "1.1.1.1", "server": "2.2.2.2", "port": 70000}]}, "port"),
    ({"allowed_flows": [{"master": "1.1.1.1", "server": "2.2.2.2", "protocol": "bacnet"}]}, "protocol"),
    ({"allowed_flows": [{"master": "1.1.1.1", "server": "2.2.2.2", "extra": 1}]}, "unknown key"),
    ({"allowed_flows": [{"master": 7, "server": "2.2.2.2"}]}, "must be a string"),
    ({"writers": []}, "mapping protocol"),
    ({"writers": {"bacnet": []}}, "must be one of"),
    ({"writers": {"modbus": "1.1.1.1"}}, "must be a list"),
    ({"write_ranges": [{"server": "*", "protocol": "modbus", "area": "coil", "start": 5, "end": 1}]}, "end < start"),
    ({"write_ranges": [{"server": "*", "protocol": "modbus", "area": "coil", "start": 0}]}, "missing required key"),
    ({"write_ranges": [{"server": "*", "protocol": "modbus", "area": "", "start": 0, "end": 1}]}, "non-empty"),
    ({"write_ranges": [{"server": "*", "protocol": "modbus", "area": "coil", "start": "0", "end": 1}]}, "integer"),
    ({"write_ranges": [{"server": "*", "protocol": "modbus", "area": "coil", "start": 0, "end": 1, "x": 1}]}, "unknown key"),
    ({"write_ranges": [{"server": "*", "protocol": "modbus", "area": "coil", "start": 0, "end": 1, "unit": -1}]}, "unit"),
    ({"ignore_rules": ["QW-NOPE"]}, "unknown rule id"),
    ({"severity_overrides": []}, "must be an object"),
    ({"severity_overrides": {"QW-NOPE": "high"}}, "unknown rule id"),
    ({"severity_overrides": {"QW-A001": "scary"}}, "unknown severity"),
    ({"thresholds": []}, "must be an object"),
    ({"thresholds": {"bogus": 1}}, "unknown threshold"),
    ({"thresholds": {"sweep_hosts": -1}}, "non-negative"),
    ({"thresholds": {"sweep_hosts": True}}, "non-negative"),
])
def test_validation_errors(doc, fragment):
    with pytest.raises(PolicyError) as exc:
        parse_policy(doc)
    assert fragment in str(exc.value)


def test_load_policy_errors(tmp_path):
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(str(tmp_path / "missing.json"))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(PolicyError, match="not valid JSON"):
        load_policy(str(bad))
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"version": 1, "assets": [{"ip": "1.2.3.4"}]}))
    assert load_policy(str(good)).asset_known("1.2.3.4")


def test_severity_parse_and_labels():
    assert Severity.parse(" High ") is Severity.HIGH and Severity.CRITICAL.label == "critical"
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    with pytest.raises(ValueError):
        Severity.parse("urgent")


# -- baseline generation ------------------------------------------------------------------------
def test_build_baseline_roundtrip_is_clean_and_reviewable():
    from conftest import run
    from quietwire import synth

    r = run(synth.scenario_baseline())
    doc = build_baseline(r.inventory)
    assert doc["version"] == 1 and doc["engineering_stations"] == []
    assert "review" in doc["_review"].lower()
    parsed = parse_policy(json.loads(json.dumps(doc)))  # must be loadable as-is
    assert {a["ip"] for a in doc["assets"]} == {synth.HMI, synth.SCADA, synth.EWS, synth.MB_PLC, synth.RTU, synth.S7_PLC}
    roles = {a["ip"]: a["role"] for a in doc["assets"]}
    assert roles[synth.HMI] == "master" and roles[synth.MB_PLC] == "server"
    assert doc["writers"] == {"dnp3": [synth.SCADA], "modbus": [synth.HMI], "s7comm": [synth.EWS]}
    areas = {(w["protocol"], w["area"]): (w["start"], w["end"]) for w in doc["write_ranges"]}
    assert areas[("modbus", "holding_register")] == (100, 100)
    assert areas[("s7comm", "DB1")] == (10, 11) and areas[("dnp3", "binary_output")] == (2, 2)
    # re-analysing the very traffic the baseline came from raises no policy alerts
    again = run(synth.scenario_baseline(), parsed)
    assert again.alerts == []


def test_baseline_notes_observed_critical_operations_and_merges_ranges():
    from conftest import run
    from quietwire import synth

    pb = synth.PcapBuilder()
    c = synth.Conn(pb, synth.HMI, synth.MB_PLC, 40000, 502)
    c.open()
    for i, start in enumerate((0, 1, 2, 10)):
        c.push(True, synth.mb_adu(i, 1, synth.mb_write_single_register(start, 1)))
    c.push(True, synth.mb_adu(9, 1, synth.mb_diag(0x0004)))
    r = run(pb)
    doc = build_baseline(r.inventory)
    hr = [w for w in doc["write_ranges"] if w["area"] == "holding_register"]
    assert [(w["start"], w["end"]) for w in hr] == [(0, 2), (10, 10)]  # 0,1,2 merged; 10 separate
    assert hr[0]["unit"] == 1
    assert doc["_observed_critical_operations"][0]["functions"] == ["DIAGNOSTICS"]
