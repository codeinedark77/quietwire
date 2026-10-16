"""Tamper-evident, hash-chained JSONL audit log.

Record = {"v":1,"seq":N,"ts":ISO,"event":{...},"prev":hex,"hash":hex[,"mac":hex]} with
hash = SHA256(prev + "\\n" + canonical_json({"v","seq","ts","event"})).
``verify_log`` detects edits, deletions in the middle, reordering and (given the
externally stored anchor hash) truncation of the tail.

Optional keyed mode: with a secret ``key`` every record also carries
``mac = HMAC-SHA256(key, hash)``. An attacker who can rewrite the file but does not hold
the key can no longer forge a consistent history (the plain chain alone can be recomputed by
anyone). Keep the key off the host that writes the log if host compromise is in scope.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..errors import AuditLogError
from ..util import iso_ts

try:  # POSIX advisory locking; absent on Windows
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None  # type: ignore

GENESIS = "0" * 64


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(prev: str, body: Dict[str, Any]) -> str:
    return hashlib.sha256((prev + "\n" + _canon(body)).encode("ascii")).hexdigest()


MIN_KEY_BYTES = 16


def _mac(key: bytes, record_hash: str) -> str:
    return hmac.new(key, record_hash.encode("ascii"), hashlib.sha256).hexdigest()


def _check_key(key: Optional[bytes]) -> None:
    if key is not None and len(key) < MIN_KEY_BYTES:
        raise AuditLogError("audit key must be at least %d bytes" % MIN_KEY_BYTES)


@dataclass
class VerifyResult:
    ok: bool
    records: int
    last_hash: str
    error: Optional[str] = None
    line: Optional[int] = None
    keyed: bool = False        # every record carries a mac
    mac_verified: bool = False  # ... and the macs were checked against the supplied key


def verify_log(path: str, anchor: Optional[str] = None, key: Optional[bytes] = None) -> VerifyResult:
    _check_key(key)
    prev = GENESIS
    n = 0
    macs = 0
    try:
        fh = open(path, "rb")
    except OSError as exc:
        return VerifyResult(False, 0, GENESIS, "cannot open: %s" % exc)
    with fh:
        for lineno, raw in enumerate(fh, 1):
            if not raw.endswith(b"\n"):
                return VerifyResult(False, n, prev, "incomplete trailing line (truncated write?)", lineno)
            try:
                rec = json.loads(raw)
                body = {"v": rec["v"], "seq": rec["seq"], "ts": rec["ts"], "event": rec["event"]}
                rprev, rhash = rec["prev"], rec["hash"]
            except (ValueError, KeyError, TypeError):
                return VerifyResult(False, n, prev, "unparsable or incomplete record", lineno)
            if rec["v"] != 1:
                return VerifyResult(False, n, prev, "unsupported record version %r" % rec["v"], lineno)
            if rec["seq"] != n + 1:
                return VerifyResult(False, n, prev, "sequence break: expected %d, found %r" % (n + 1, rec["seq"]), lineno)
            if rprev != prev:
                return VerifyResult(False, n, prev, "previous-hash mismatch (record removed or reordered)", lineno)
            if _digest(prev, body) != rhash:
                return VerifyResult(False, n, prev, "record hash mismatch (record modified)", lineno)
            mac = rec.get("mac")
            if mac is not None:
                macs += 1
            if key is not None:
                if mac is None:
                    return VerifyResult(False, n, prev, "record carries no mac but a key was supplied "
                                                        "(unkeyed record injected or mixed log)", lineno)
                if not isinstance(mac, str) or not hmac.compare_digest(mac, _mac(key, rhash)):
                    return VerifyResult(False, n, prev, "mac mismatch (wrong key, or the chain was rewritten "
                                                        "by someone without the key)", lineno)
            prev = rhash
            n += 1
    if anchor is not None and anchor != prev:
        return VerifyResult(False, n, prev, "anchor mismatch: log tail truncated or replaced "
                                            "(expected %s, found %s)" % (anchor, prev))
    return VerifyResult(True, n, prev, keyed=n > 0 and macs == n, mac_verified=key is not None and n > 0)


class AuditLog:
    """Append-only writer; continues an existing chain after verifying it.

    Appends take an exclusive ``flock`` and re-synchronise with the file first, so
    several processes may safely share one log without forking the chain.
    """

    def __init__(self, path: str, fsync: bool = False, key: Optional[bytes] = None):
        _check_key(key)
        self.path = path
        self._fsync = fsync
        self._key = key
        self._seq = 0
        self._prev = GENESIS
        if os.path.exists(path) and os.path.getsize(path) > 0:
            res = verify_log(path, key=key)
            if not res.ok:
                raise AuditLogError("existing audit log %s failed verification: %s (line %s)"
                                    % (path, res.error, res.line))
            if key is None and res.keyed:
                raise AuditLogError("audit log %s is keyed; supply the key to append to it" % path)
            self._seq, self._prev = res.records, res.last_hash
        self._fh = open(path, "ab")
        self._size = os.fstat(self._fh.fileno()).st_size

    @property
    def anchor(self) -> str:
        return self._prev

    @property
    def records(self) -> int:
        return self._seq

    def append(self, event: Dict[str, Any], ts: float) -> Dict[str, Any]:
        if self._fh is None:
            raise AuditLogError("audit log is closed")
        fd = self._fh.fileno()
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            if os.fstat(fd).st_size != self._size:
                # another writer appended since our last write: adopt the verified chain tail
                res = verify_log(self.path, key=self._key)
                if not res.ok:
                    raise AuditLogError("audit log changed underneath writer and fails verification: %s" % res.error)
                self._seq, self._prev = res.records, res.last_hash
            body = {"v": 1, "seq": self._seq + 1, "ts": iso_ts(ts), "event": event}
            h = _digest(self._prev, body)
            rec = dict(body, prev=self._prev, hash=h)
            if self._key is not None:
                rec["mac"] = _mac(self._key, h)
            self._fh.write((json.dumps(rec, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii"))
            self._fh.flush()
            if self._fsync:
                os.fsync(fd)
            self._seq += 1
            self._prev = h
            self._size = os.fstat(fd).st_size
            return rec
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None  # type: ignore[assignment]

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
