import json
import multiprocessing
import os

import pytest

from quietwire.errors import AuditLogError
from quietwire.report.auditlog import GENESIS, AuditLog, verify_log


def make(path, n=5):
    with AuditLog(path) as log:
        for i in range(n):
            log.append({"event": "alert", "i": i, "msg": "unicode \u00e9\u4e2d"}, 1700000000.0 + i)
        return log.anchor


def lines(path):
    return open(path, "rb").read().splitlines(keepends=True)


def test_append_and_verify(tmp_path):
    p = str(tmp_path / "a.jsonl")
    anchor = make(p)
    res = verify_log(p)
    assert res.ok and res.records == 5 and res.last_hash == anchor and res.error is None
    first = json.loads(lines(p)[0])
    assert first["prev"] == GENESIS and first["seq"] == 1 and first["v"] == 1
    assert verify_log(p, anchor).ok


def test_each_record_hash_depends_on_all_previous(tmp_path):
    a, b = str(tmp_path / "a.jsonl"), str(tmp_path / "b.jsonl")
    with AuditLog(a) as la, AuditLog(b) as lb:
        la.append({"x": 1}, 1.0)
        lb.append({"x": 2}, 1.0)
        la.append({"y": 1}, 2.0)
        lb.append({"y": 1}, 2.0)
    ha = [json.loads(l)["hash"] for l in lines(a)]
    hb = [json.loads(l)["hash"] for l in lines(b)]
    assert ha[1] != hb[1]  # identical second event, different history => different hash


def test_modified_record_is_detected(tmp_path):
    p = str(tmp_path / "a.jsonl")
    make(p)
    ls = lines(p)
    rec = json.loads(ls[2])
    rec["event"]["i"] = 999
    ls[2] = (json.dumps(rec, sort_keys=True) + "\n").encode()
    open(p, "wb").write(b"".join(ls))
    res = verify_log(p)
    assert not res.ok and res.line == 3 and "modified" in res.error and res.records == 2


def test_deleted_middle_record_is_detected(tmp_path):
    p = str(tmp_path / "a.jsonl")
    make(p)
    ls = lines(p)
    del ls[2]
    open(p, "wb").write(b"".join(ls))
    res = verify_log(p)
    assert not res.ok and res.line == 3 and "sequence" in res.error


def test_reordered_records_are_detected(tmp_path):
    p = str(tmp_path / "a.jsonl")
    make(p)
    ls = lines(p)
    ls[1], ls[2] = ls[2], ls[1]
    open(p, "wb").write(b"".join(ls))
    assert not verify_log(p).ok


def test_chain_rewrite_without_the_anchor_is_only_caught_by_the_anchor(tmp_path):
    p = str(tmp_path / "a.jsonl")
    anchor = make(p)
    ls = lines(p)
    open(p, "wb").write(b"".join(ls[:3]))  # attacker truncates the tail: still a valid chain...
    assert verify_log(p).ok
    res = verify_log(p, anchor)              # ...but not against the externally stored anchor
    assert not res.ok and "anchor mismatch" in res.error


def test_truncated_last_line_and_garbage(tmp_path):
    p = str(tmp_path / "a.jsonl")
    make(p)
    raw = open(p, "rb").read()
    open(p, "wb").write(raw[:-10])
    res = verify_log(p)
    assert not res.ok and "incomplete trailing line" in res.error and res.records == 4
    open(p, "wb").write(raw + b"not json\n")
    assert "unparsable" in verify_log(p).error
    open(p, "wb").write(raw.replace(b'"v": 1', b'"v": 2', 1))
    assert not verify_log(p).ok
    open(p, "wb").write(b'{"v":1}\n')
    assert "unparsable" in verify_log(p).error


def test_missing_file_and_empty_file(tmp_path):
    assert not verify_log(str(tmp_path / "nope.jsonl")).ok
    p = tmp_path / "empty.jsonl"
    p.write_bytes(b"")
    res = verify_log(str(p))
    assert res.ok and res.records == 0 and res.last_hash == GENESIS


def test_resume_appending_continues_the_chain(tmp_path):
    p = str(tmp_path / "a.jsonl")
    make(p, 3)
    with AuditLog(p) as log:
        assert log.records == 3
        log.append({"event": "later"}, 2.0)
    res = verify_log(p)
    assert res.ok and res.records == 4


def test_refuses_to_extend_a_corrupted_log(tmp_path):
    p = str(tmp_path / "a.jsonl")
    make(p)
    raw = open(p, "rb").read()
    open(p, "wb").write(raw.replace(b'"i": 1', b'"i": 7', 1))
    with pytest.raises(AuditLogError, match="failed verification"):
        AuditLog(p)


def test_closed_log_raises(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    log.close()
    with pytest.raises(AuditLogError):
        log.append({"x": 1}, 1.0)
    log.close()  # idempotent


def _worker(path, wid, n):
    log = AuditLog(path)
    for i in range(n):
        log.append({"event": "w", "worker": wid, "i": i}, 1.0)
    log.close()


def test_concurrent_writers_do_not_fork_the_chain(tmp_path):
    p = str(tmp_path / "shared.jsonl")
    open(p, "wb").close()
    ctx = multiprocessing.get_context("fork")
    procs = [ctx.Process(target=_worker, args=(p, w, 25)) for w in range(4)]
    for pr in procs:
        pr.start()
    for pr in procs:
        pr.join(60)
        assert pr.exitcode == 0
    res = verify_log(p)
    assert res.ok and res.records == 100, res
    events = [json.loads(l)["event"] for l in lines(p)]
    for w in range(4):
        assert [e["i"] for e in events if e["worker"] == w] == list(range(25))  # per-writer order preserved


def test_fsync_option_and_log_detects_foreign_append(tmp_path):
    p = str(tmp_path / "a.jsonl")
    with AuditLog(p, fsync=True) as a:
        a.append({"x": 1}, 1.0)
        with AuditLog(p) as b:  # a second writer appends in between
            b.append({"x": 2}, 2.0)
        a.append({"x": 3}, 3.0)  # must adopt the new tail rather than fork
    res = verify_log(p)
    assert res.ok and res.records == 3
