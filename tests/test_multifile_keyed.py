"""Multi-file analysis and keyed (HMAC) audit logs."""

import json
import os
import stat

import pytest

from quietwire import synth
from quietwire.cli import main
from quietwire.errors import AuditLogError
from quietwire.report.auditlog import AuditLog, verify_log

KEY = b"0123456789abcdef0123456789abcdef"


@pytest.fixture(scope="module")
def rotated(tmp_path_factory):
    """One capture split into three consecutive files (like tcpdump -C rotation), plus the whole."""
    d = tmp_path_factory.mktemp("rot")
    pb = synth.scenario_baseline(synth.PcapBuilder(start_ts=1_700_100_000.0), cycles=5)
    synth.scenario_attack(pb)
    frames = pb.ordered()
    third = len(frames) // 3
    paths = []
    for i, chunk in enumerate((frames[:third], frames[third : 2 * third], frames[2 * third :])):
        part = synth.PcapBuilder(start_ts=pb.ts)
        part.frames = list(chunk)
        p = str(d / ("part%d.pcap" % i))
        part.write_pcap(p)
        paths.append(p)
    whole = str(d / "whole.pcap")
    pb.write_pcap(whole)
    pol = str(d / "policy.json")
    json.dump(synth.demo_policy(), open(pol, "w"))
    return paths, whole, pol


def analyse(paths, pol, *extra, capsys=None):
    out = str(os.path.join(os.path.dirname(paths[0]), "out-%d.json" % abs(hash(tuple(paths) + extra))))
    assert main(["analyze", *paths, "--policy", pol, "--format", "json", "--out", out, *extra]) == 0
    return json.load(open(out))


def test_rotated_files_are_one_continuous_stream(rotated, capsys):
    paths, whole, pol = rotated
    multi = analyse(paths, pol)
    single = analyse([whole], pol)
    assert multi["stats"]["packets"] == single["stats"]["packets"]
    assert multi["stats"]["messages"] == single["stats"]["messages"]
    key = lambda a: (a["rule_id"], a["count"], a["src"], a["dst"])  # noqa: E731
    assert sorted(map(key, multi["alerts"])) == sorted(map(key, single["alerts"]))
    assert multi["input"]["source"] == "3 files" and multi["input"]["sha256"] is None
    assert [f["packets"] for f in multi["input"]["files"]] == [f["packets"] for f in multi["input"]["files"]]
    assert sum(f["packets"] for f in multi["input"]["files"]) == multi["stats"]["packets"]
    assert all(len(f["sha256"]) == 64 and f["format"] == "pcap" for f in multi["input"]["files"])
    assert single["input"]["files"][0]["path"] == whole
    capsys.readouterr()


def test_packet_numbers_continue_and_sources_identify_the_file(rotated, capsys):
    paths, whole, pol = rotated
    multi = analyse(paths, pol)
    single = analyse([whole], pol)
    by_key = {(a["rule_id"], a["message"]): a for a in single["alerts"]}
    assert len(by_key) == len(single["alerts"])
    sources = set()
    for a in multi["alerts"]:
        ref = by_key[(a["rule_id"], a["message"])]
        assert a["first_packet"]["index"] == ref["first_packet"]["index"]  # global numbering == whole-file numbering
        sources.add(a["first_packet"]["source"])
    assert sources <= {0, 1, 2} and len(sources) >= 2
    capsys.readouterr()


def test_sarif_points_into_the_right_member_file(rotated, tmp_path, capsys):
    paths, whole, pol = rotated
    out = str(tmp_path / "m.sarif")
    assert main(["analyze", *paths, "--policy", pol, "--format", "sarif", "--out", out]) == 0
    doc = json.load(open(out))
    run_ = doc["runs"][0]
    assert [a["location"]["uri"] for a in run_["artifacts"]] == ["part0.pcap", "part1.pcap", "part2.pcap"]
    raw = {i: open(p, "rb").read() for i, p in enumerate(paths)}
    seen = set()
    for r in run_["results"]:
        loc = r["locations"][0]["physicalLocation"]
        i = loc["artifactLocation"]["index"]
        assert loc["artifactLocation"]["uri"] == "part%d.pcap" % i
        off = loc["region"]["byteOffset"]
        assert 24 <= off < len(raw[i])  # a real record offset inside that member file
        seen.add(i)
    assert len(seen) >= 2
    pytest.importorskip("jsonschema").validate(doc, json.load(open(os.path.join(os.path.dirname(__file__), "data",
                                                                                "sarif-schema-2.1.0.json"))))
    capsys.readouterr()


def test_input_validation(rotated, capsys, tmp_path):
    paths, whole, pol = rotated
    assert main(["analyze", paths[0], str(tmp_path / "missing.pcap")]) == 3
    assert "not found" in capsys.readouterr().err
    assert main(["analyze", "-", paths[0]]) == 3
    assert "stdin" in capsys.readouterr().err
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"nonsense nonsense")
    assert main(["analyze", paths[0], str(bad)]) == 3
    capsys.readouterr()


def test_truncated_member_is_reported_but_analysis_continues(rotated, tmp_path, capsys):
    paths, whole, pol = rotated
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(open(paths[1], "rb").read()[:-9])
    out = str(tmp_path / "t.json")
    assert main(["analyze", paths[0], str(cut), paths[2], "--format", "json", "--out", out]) == 0
    doc = json.load(open(out))
    assert any(w.startswith("cut.pcap: truncated") for w in doc["warnings"])
    assert doc["input"]["files"][2]["packets"] > 0
    capsys.readouterr()


def test_audit_log_records_every_input_file(rotated, tmp_path, capsys):
    paths, whole, pol = rotated
    log = str(tmp_path / "a.jsonl")
    assert main(["analyze", *paths, "--audit-log", log, "--format", "json", "--out", str(tmp_path / "o.json")]) == 0
    first = json.loads(open(log).readline())["event"]
    assert [f["name"] for f in first["files"]] == ["part0.pcap", "part1.pcap", "part2.pcap"]
    capsys.readouterr()


# -- keyed audit logs -----------------------------------------------------------------------------------
def make(path, key=KEY, n=4):
    with AuditLog(path, key=key) as log:
        for i in range(n):
            log.append({"event": "alert", "i": i}, 1.0 + i)
        return log.anchor


def test_keyed_roundtrip_and_flags(tmp_path):
    p = str(tmp_path / "k.jsonl")
    anchor = make(p)
    rec = json.loads(open(p).readline())
    assert len(rec["mac"]) == 64
    res = verify_log(p, anchor, key=KEY)
    assert res.ok and res.keyed and res.mac_verified and res.records == 4
    plain = verify_log(p)  # chain-only verification still works without the key
    assert plain.ok and plain.keyed and not plain.mac_verified


def test_wrong_key_missing_mac_and_forged_chain_are_rejected(tmp_path):
    p = str(tmp_path / "k.jsonl")
    make(p)
    assert "mac mismatch" in verify_log(p, key=b"x" * 32).error
    lines = open(p, "rb").read().splitlines(keepends=True)
    rec = json.loads(lines[1])
    del rec["mac"]
    lines[1] = (json.dumps(rec, sort_keys=True) + "\n").encode()
    open(p, "wb").write(b"".join(lines))
    res = verify_log(p, key=KEY)
    assert not res.ok and "no mac" in res.error and res.line == 2


def test_attacker_who_recomputes_the_chain_cannot_forge_macs(tmp_path):
    """Without the key, a rewritten-but-self-consistent chain still fails keyed verification."""
    from quietwire.report.auditlog import GENESIS, _digest

    p = str(tmp_path / "k.jsonl")
    make(p, n=3)
    forged, prev = [], GENESIS
    for seq, ev in enumerate(({"event": "alert", "i": 0}, {"event": "tampered"}, {"event": "alert", "i": 2}), 1):
        body = {"v": 1, "seq": seq, "ts": "2026-01-01T00:00:00.000000Z", "event": ev}
        h = _digest(prev, body)
        forged.append(dict(body, prev=prev, hash=h, mac="0" * 64))
        prev = h
    open(p, "w").write("".join(json.dumps(r, sort_keys=True) + "\n" for r in forged))
    assert verify_log(p).ok                         # the plain chain is perfectly consistent...
    res = verify_log(p, key=KEY)                    # ...but the keyed check exposes the forgery
    assert not res.ok and "mac mismatch" in res.error


def test_resume_requires_the_same_key_and_refuses_mixing(tmp_path):
    p = str(tmp_path / "k.jsonl")
    make(p, n=2)
    with pytest.raises(AuditLogError, match="keyed"):
        AuditLog(p)                                  # unkeyed writer on a keyed log
    with pytest.raises(AuditLogError, match="mac mismatch"):
        AuditLog(p, key=b"y" * 32)
    with AuditLog(p, key=KEY) as log:
        log.append({"event": "more"}, 9.0)
    assert verify_log(p, key=KEY).records == 3
    q = str(tmp_path / "plain.jsonl")
    with AuditLog(q) as log:
        log.append({"event": "x"}, 1.0)
    with pytest.raises(AuditLogError, match="no mac"):
        AuditLog(q, key=KEY)                         # keyed writer on an unkeyed log


def test_short_keys_are_refused(tmp_path):
    with pytest.raises(AuditLogError, match="at least 16"):
        AuditLog(str(tmp_path / "s.jsonl"), key=b"short")
    with pytest.raises(AuditLogError, match="at least 16"):
        verify_log(str(tmp_path / "s.jsonl"), key=b"short")


def test_cli_key_workflow(rotated, tmp_path, capsys):
    paths, whole, pol = rotated
    keyfile = str(tmp_path / "audit.key")
    assert main(["audit-key", keyfile]) == 0
    assert stat.S_IMODE(os.stat(keyfile).st_mode) == 0o600
    assert len(open(keyfile).read().strip()) == 64
    assert main(["audit-key", keyfile]) == 3                     # never overwrites a key
    assert "refusing to overwrite" in capsys.readouterr().err
    log = str(tmp_path / "audit.jsonl")
    assert main(["analyze", paths[0], "--audit-log", log, "--audit-key-file", keyfile, "--format", "json",
                 "--out", str(tmp_path / "o.json")]) == 0
    anchor = capsys.readouterr().err.split(": ")[-1].strip()
    assert main(["verify-log", log, "--anchor", anchor, "--audit-key-file", keyfile]) == 0
    assert "macs verified" in capsys.readouterr().out
    assert main(["verify-log", log]) == 0
    assert "macs NOT verified" in capsys.readouterr().out
    other = str(tmp_path / "other.key")
    open(other, "w").write("f" * 64)
    assert main(["verify-log", log, "--audit-key-file", other]) == 1
    assert "mac mismatch" in capsys.readouterr().out
    assert main(["analyze", paths[0], "--audit-log", log, "--format", "json", "--out", str(tmp_path / "o.json")]) == 3
    assert "keyed" in capsys.readouterr().err
    short = str(tmp_path / "short.key")
    open(short, "w").write("abc")
    assert main(["verify-log", log, "--audit-key-file", short]) == 3
    assert main(["verify-log", log, "--audit-key-file", str(tmp_path / "nokey")]) == 3
    capsys.readouterr()
