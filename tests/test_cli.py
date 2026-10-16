import io
import json
import os
import subprocess
import sys

import pytest

from quietwire import synth
from quietwire.cli import main
from quietwire.report.auditlog import verify_log

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("demo"))
    assert main(["demo", d]) == 0
    return d


def p(demo, name):
    return os.path.join(demo, name)


def test_demo_writes_files_and_prints_usage(tmp_path, capsys):
    assert main(["demo", str(tmp_path / "x")]) == 0
    out = capsys.readouterr().out
    assert "baseline.pcap" in out and "quietwire analyze" in out
    for f in ("baseline.pcap", "attack.pcap", "policy.json"):
        assert os.path.getsize(tmp_path / "x" / f) > 100
    json.load(open(tmp_path / "x" / "policy.json"))


def test_analyze_text_clean_and_attack(demo, capsys):
    assert main(["analyze", p(demo, "baseline.pcap"), "--policy", p(demo, "policy.json")]) == 0
    out = capsys.readouterr().out
    assert "alerts   : 0" in out and "modbus=" in out and "Assets" in out
    assert main(["analyze", p(demo, "attack.pcap"), "--policy", p(demo, "policy.json")]) == 0
    out = capsys.readouterr().out
    assert "CRITICAL" in out and "QW-C001" in out


def test_fail_on_threshold_exit_codes(demo, capsys):
    pol = ["--policy", p(demo, "policy.json")]
    assert main(["analyze", p(demo, "attack.pcap"), *pol, "--fail-on", "high"]) == 1
    assert main(["analyze", p(demo, "attack.pcap"), *pol, "--fail-on", "critical"]) == 1
    assert main(["analyze", p(demo, "baseline.pcap"), *pol, "--fail-on", "info"]) == 0
    assert main(["analyze", p(demo, "baseline.pcap"), "--fail-on", "low"]) == 1   # W002 visibility alerts without policy
    assert main(["analyze", p(demo, "baseline.pcap"), "--fail-on", "medium"]) == 0
    capsys.readouterr()


def test_json_and_sarif_output_to_file(demo, tmp_path):
    out = str(tmp_path / "r.json")
    assert main(["analyze", p(demo, "attack.pcap"), "--policy", p(demo, "policy.json"), "--format", "json",
                 "--out", out]) == 0
    doc = json.load(open(out))
    assert doc["input"]["format"] == "pcap" and len(doc["input"]["sha256"]) == 64
    assert doc["policy"]["enforced_sections"]
    out2 = str(tmp_path / "r.sarif")
    assert main(["analyze", p(demo, "attack.pcap"), "--policy", p(demo, "policy.json"), "--format", "sarif",
                 "--out", out2]) == 0
    assert json.load(open(out2))["version"] == "2.1.0"


def test_min_severity_filters(demo, capsys):
    assert main(["analyze", p(demo, "attack.pcap"), "--policy", p(demo, "policy.json"), "--format", "json",
                 "--min-severity", "critical"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["alerts"] and {a["severity"] for a in doc["alerts"]} == {"critical"}


def test_audit_log_and_verify_log_roundtrip(demo, tmp_path, capsys):
    log = str(tmp_path / "audit.jsonl")
    assert main(["analyze", p(demo, "attack.pcap"), "--policy", p(demo, "policy.json"), "--audit-log", log,
                 "--format", "json", "--out", str(tmp_path / "o.json")]) == 0
    err = capsys.readouterr().err
    anchor = err.split("anchor (store externally to detect truncation): ")[1].split()[0]
    assert len(anchor) == 64
    res = verify_log(log, anchor)
    assert res.ok and res.records > 5
    events = [json.loads(l)["event"] for l in open(log)]
    assert events[0]["event"] == "analysis_start" and len(events[0]["files"][0]["sha256"]) == 64
    assert events[-1]["event"] == "analysis_end" and events[-1]["alerts"] > 0
    assert sum(1 for e in events if e["event"] == "alert") >= events[-1]["alerts"]
    assert main(["verify-log", log, "--anchor", anchor]) == 0
    assert "OK:" in capsys.readouterr().out
    # tamper
    raw = open(log, "rb").read()
    open(log, "wb").write(raw.replace(b"10.0.0.66", b"10.0.0.77", 1))
    assert main(["verify-log", log]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_analyze_appends_to_existing_audit_log_as_second_run(demo, tmp_path, capsys):
    log = str(tmp_path / "audit.jsonl")
    for _ in range(2):
        assert main(["analyze", p(demo, "baseline.pcap"), "--audit-log", log, "--format", "json",
                     "--out", str(tmp_path / "o.json")]) == 0
    res = verify_log(log)
    assert res.ok
    kinds = [json.loads(l)["event"]["event"] for l in open(log)]
    assert kinds.count("analysis_start") == 2 and kinds.count("analysis_end") == 2
    capsys.readouterr()


def test_baseline_then_enforce(demo, tmp_path, capsys):
    pol = str(tmp_path / "learned.json")
    assert main(["baseline", p(demo, "baseline.pcap"), "--out", pol]) == 0
    doc = json.load(open(pol))
    assert doc["_source_capture"]["file"] == "baseline.pcap" and len(doc["_source_capture"]["sha256"]) == 64
    assert main(["analyze", p(demo, "baseline.pcap"), "--policy", pol, "--fail-on", "info"]) == 0
    assert main(["analyze", p(demo, "attack.pcap"), "--policy", pol, "--fail-on", "high"]) == 1
    capsys.readouterr()


def test_baseline_of_capture_without_ics_warns(tmp_path, capsys):
    pb = synth.PcapBuilder()
    c = synth.Conn(pb, "10.0.0.1", "10.0.0.2", 1234, 80)
    c.open()
    c.push(True, b"GET / HTTP/1.0\r\n\r\n")
    path = str(tmp_path / "web.pcap")
    pb.write_pcap(path)
    assert main(["baseline", path]) == 0
    cap = capsys.readouterr()
    assert "no ICS traffic" in cap.err and json.loads(cap.out)["allowed_flows"] == []


def test_rules_listing(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "QW-C001" in out and "ATT&CK for ICS v19" in out
    assert main(["rules", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 21 and {"id", "name", "default_severity", "mitre_attack_ics"} <= set(data[0])


def test_stdin_input(demo, monkeypatch, capsys):
    raw = open(p(demo, "baseline.pcap"), "rb").read()

    class FakeStdin:
        buffer = io.BytesIO(raw)

    monkeypatch.setattr(sys, "stdin", FakeStdin())
    assert main(["analyze", "-", "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["input"]["source"] == "stdin" and doc["input"]["sha256"] is None and doc["input"]["packets"] > 100


def test_error_exit_codes(demo, tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "missing.pcap")]) == 3
    assert "not found" in capsys.readouterr().err
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a capture file at all")
    assert main(["analyze", str(bad)]) == 3
    assert "unrecognised capture magic" in capsys.readouterr().err
    badpol = tmp_path / "bad.json"
    badpol.write_text('{"asets": []}')
    assert main(["analyze", p(demo, "baseline.pcap"), "--policy", str(badpol)]) == 3
    assert "unknown policy key" in capsys.readouterr().err
    assert main(["baseline", str(tmp_path / "missing.pcap")]) == 3
    capsys.readouterr()
    with pytest.raises(SystemExit) as e:
        main(["analyze", p(demo, "baseline.pcap"), "--fail-on", "bogus"])
    assert e.value.code == 2
    with pytest.raises(SystemExit):
        main([])


def test_truncated_capture_is_reported_as_warning(demo, tmp_path, capsys):
    raw = open(p(demo, "baseline.pcap"), "rb").read()
    path = str(tmp_path / "t.pcap")
    open(path, "wb").write(raw[:-7])
    assert main(["analyze", path, "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert any("truncated" in w for w in doc["warnings"])


def test_corrupt_capture_midway_still_produces_a_report(demo, tmp_path, capsys):
    import struct
    raw = bytearray(open(p(demo, "baseline.pcap"), "rb").read())
    # make a record in the middle claim an absurd captured length
    off = 24
    for _ in range(40):
        incl = struct.unpack_from("<I", raw, off + 8)[0]
        off += 16 + incl
    struct.pack_into("<I", raw, off + 8, 0x7FFFFFFF)
    path = str(tmp_path / "c.pcap")
    open(path, "wb").write(bytes(raw))
    assert main(["analyze", path, "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["input"]["packets"] == 40 and any("implausible" in w for w in doc["warnings"])


def test_module_entry_point_and_version(demo):
    out = subprocess.run([sys.executable, "-m", "quietwire", "--version"], capture_output=True, text=True,
                         env=dict(os.environ, PYTHONPATH=SRC))
    assert out.returncode == 0 and out.stdout.startswith("quietwire ")
    out = subprocess.run([sys.executable, "-m", "quietwire", "analyze", p(demo, "baseline.pcap"), "--format", "json"],
                         capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC))
    assert out.returncode == 0 and json.loads(out.stdout)["summary"]["flows"] == 3
