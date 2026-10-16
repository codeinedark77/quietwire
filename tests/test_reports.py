import json
import os

import pytest

from conftest import run
from quietwire import synth
from quietwire.capture.pcap import CaptureReader
from quietwire.detect.engine import Engine
from quietwire.detect.rules import RULES
from quietwire.model import Severity
from quietwire.report import build_report, render_json, render_sarif, render_text

SCHEMA = os.path.join(os.path.dirname(__file__), "data", "sarif-schema-2.1.0.json")


@pytest.fixture(scope="module")
def attack_file(tmp_path_factory):
    pb = synth.scenario_baseline(synth.PcapBuilder(start_ts=1_700_100_000.0), cycles=5)
    synth.scenario_attack(pb)
    path = str(tmp_path_factory.mktemp("rep") / "attack.pcap")
    pb.write_pcap(path)
    return path


def analyse(path, policy=None):
    from quietwire.detect.policy import parse_policy

    eng = Engine(parse_policy(policy) if policy else None)
    with CaptureReader(path) as r:
        for raw in r:
            eng.process(raw)
        fmt = r.format
    return eng.finalize(), fmt


def test_json_report_structure_and_counts(attack_file):
    res, fmt = analyse(attack_file, synth.demo_policy())
    rep = build_report(res, attack_file, fmt, "ab" * 32, "p.json", ["assets"])
    doc = json.loads(render_json(rep))
    assert doc["schema_version"] == 1 and doc["tool"]["name"] == "quietwire"
    assert doc["input"]["packets"] == res.stats.packets and doc["input"]["sha256"] == "ab" * 32
    assert doc["input"]["duration_seconds"] > 0 and doc["input"]["first_packet"].endswith("Z")
    assert doc["summary"]["alerts_total"] == len(doc["alerts"]) == len(res.alerts)
    assert sum(doc["summary"]["alerts_by_severity"].values()) == len(res.alerts)
    assert doc["summary"]["assets"] == len(doc["assets"]) and doc["summary"]["flows"] == len(doc["flows"])
    assert doc["policy"] == {"path": "p.json", "enforced_sections": ["assets"]}
    a = doc["alerts"][0]
    assert {"rule_id", "severity", "title", "message", "protocol", "src", "dst", "count", "first_seen", "last_seen",
            "first_packet", "mitre_attack_ics", "details", "samples"} <= set(a)
    assert a["first_packet"]["offset"] >= 24 and a["severity"] == "critical"
    assert [x["ip"] for x in doc["assets"]] == sorted(x["ip"] for x in doc["assets"])


def test_json_report_for_empty_capture():
    from quietwire.detect.engine import Result

    eng = Engine()
    rep = build_report(eng.finalize(), "x.pcap", "pcap")
    assert rep["input"]["first_packet"] is None and rep["input"]["duration_seconds"] == 0.0
    assert rep["summary"]["alerts_total"] == 0 and rep["alerts"] == []
    assert "no" in render_text(rep).lower() or "alerts   : 0" in render_text(rep)


def test_text_report(attack_file):
    res, fmt = analyse(attack_file, synth.demo_policy())
    rep = build_report(res, attack_file, fmt, "cd" * 32)
    txt = render_text(rep)
    assert "quietwire" in txt and "CRITICAL" in txt and "QW-C001" in txt and "10.0.0.66" in txt
    assert "Assets" in txt and "Flows" in txt and "modbus(" in txt and "s7=r0s2" in txt
    assert "cd" * 32 in txt
    short = render_text(rep, max_alerts=3)
    assert "more alerts omitted" in short
    for line in txt.splitlines():
        assert len(line) < 260


def test_sarif_is_valid_against_the_official_schema(attack_file):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.load(open(SCHEMA))
    res, fmt = analyse(attack_file, synth.demo_policy())
    doc = json.loads(render_sarif(res, attack_file, fmt, "ef" * 32))
    jsonschema.validate(doc, schema)  # raises on any violation
    # live capture / no-file variant is valid too
    live = json.loads(render_sarif(res, "live:eth0", "live", None))
    jsonschema.validate(live, schema)
    empty = json.loads(render_sarif(Engine().finalize(), "x.pcap", "pcap"))
    jsonschema.validate(empty, schema)


def test_sarif_content(attack_file):
    res, fmt = analyse(attack_file, synth.demo_policy())
    doc = json.loads(render_sarif(res, attack_file, fmt, "ef" * 32))
    run_ = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run_["tool"]["driver"]["name"] == "quietwire"
    rules = run_["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted(RULES)
    assert len(run_["results"]) == len(res.alerts)
    assert run_["artifacts"][0]["hashes"] == {"sha-256": "ef" * 32}
    assert run_["artifacts"][0]["location"]["uri"] == "attack.pcap"  # basename only: no local paths leak
    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    raw = open(attack_file, "rb").read()
    for r, a in zip(run_["results"], res.alerts):
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"] == a.rule_id
        assert r["level"] == levels[a.severity.label]
        region = r["locations"][0]["physicalLocation"]["region"]
        assert region["byteOffset"] == a.first_packet.offset
        # the offset really is a pcap record header whose timestamp matches the alert's first packet
        sec = int.from_bytes(raw[region["byteOffset"] : region["byteOffset"] + 4], "little")
        assert sec == int(a.first_packet.ts)
        assert len(r["partialFingerprints"]["quietwire/v1"]) == 64
        assert r["properties"]["count"] == a.count
    fps = [r["partialFingerprints"]["quietwire/v1"] for r in run_["results"]]
    assert len(set(fps)) == len(fps)  # distinct alerts have distinct fingerprints
    tags = [t for r in rules for t in r["properties"]["tags"]]
    assert "external/mitre-attack-ics/T1692.001" in tags and not any("T0855" in t for t in tags)


def test_sarif_fingerprints_are_stable_across_runs(attack_file):
    a, _ = analyse(attack_file, synth.demo_policy())
    b, _ = analyse(attack_file, synth.demo_policy())
    fa = sorted(json.loads(render_sarif(a, attack_file, "pcap"))["runs"][0]["results"][i]["partialFingerprints"]["quietwire/v1"]
                for i in range(len(a.alerts)))
    fb = sorted(json.loads(render_sarif(b, attack_file, "pcap"))["runs"][0]["results"][i]["partialFingerprints"]["quietwire/v1"]
                for i in range(len(b.alerts)))
    assert fa == fb


def test_every_rule_has_catalogue_metadata_and_known_attack_ids():
    from quietwire.detect.mitre import TECHNIQUES

    assert len(RULES) == 21
    for rid, r in RULES.items():
        assert r.id == rid and r.name and r.description and isinstance(r.severity, Severity)
        for t in r.mitre:
            assert t in TECHNIQUES, (rid, t)
    # every technique referenced by the critical-operation table exists too
    from quietwire.detect.rules import CRITICAL_TABLE

    for key, (_sev, mitre, _why) in CRITICAL_TABLE.items():
        for t in mitre:
            assert t in TECHNIQUES, (key, t)


def test_readme_documents_every_rule_and_technique():
    readme = open(os.path.join(os.path.dirname(__file__), "..", "README.md"), encoding="utf-8").read() \
        if os.path.exists(os.path.join(os.path.dirname(__file__), "..", "README.md")) else None
    if readme is None:
        pytest.skip("README.md not present")
    from quietwire.detect.mitre import TECHNIQUES

    for rid in RULES:
        assert rid in readme, "README is missing rule %s" % rid
    for tid in TECHNIQUES:
        assert tid in readme, "README is missing ATT&CK technique %s" % tid
