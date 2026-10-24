"""Tamper-evident audit log: JSON lines where every entry carries the SHA-256 of its own body, and
the body includes the previous entry's hash (a hash chain) and a sequence number.

Detected: edited entries (hash mismatch), deleted, inserted or reordered entries (sequence and
link mismatch). NOT detected by the chain alone: removing entries from the END, or an attacker who
can rewrite the whole file and recompute every hash. Defence: record the head hash somewhere the
attacker cannot write (printed, shipped to remote or WORM storage) and verify with `expect_head`.

Secret values and tokens are never written here.
"""
import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

GENESIS = "0" * 64


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def entry_hash(body):
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    count: int
    head: str
    error: Optional[str] = None


def verify_file(path, expect_head=None):
    """Walk the log from the start and check every link. Needs no keys, so anyone can run it."""
    prev, count = GENESIS, 0
    path = Path(path)
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                def fail(msg):
                    return VerifyResult(False, count, prev, f"line {lineno}: {msg}")

                try:
                    entry = json.loads(line)
                except ValueError:
                    return fail("not valid JSON (blank or damaged line)")
                if not isinstance(entry, dict):
                    return fail("entry is not an object")
                if entry.get("seq") != count + 1:
                    return fail(f"expected entry #{count + 1} but found #{entry.get('seq')} - "
                                "entries were deleted, inserted or reordered")
                if entry.get("prev") != prev:
                    return fail("previous-hash link is broken - an earlier entry was changed or removed")
                body = {k: v for k, v in entry.items() if k != "hash"}
                if entry.get("hash") != entry_hash(body):
                    return fail("hash mismatch - this entry was edited")
                prev, count = entry["hash"], count + 1
    if expect_head is not None and prev != expect_head:
        return VerifyResult(False, count, prev, "head does not match the expected anchor - "
                                                "the log was truncated or replaced")
    return VerifyResult(True, count, prev)


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._seq, self._head = self._tail()

    def _tail(self):
        if not self.path.exists():
            return 0, GENESIS
        last = None
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS
        try:
            entry = json.loads(last)
            return int(entry["seq"]), entry["hash"]
        except (ValueError, KeyError, TypeError):
            raise ValueError("audit log tail is unreadable; run verify-audit before starting") from None

    def append(self, event, actor, path=None, outcome="ok", detail=None):
        with self._lock:
            body = {
                "seq": self._seq + 1,
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "event": event,
                "actor": actor,
                "outcome": outcome,
                "prev": self._head,
            }
            if path is not None:
                body["path"] = path
            if detail is not None:
                body["detail"] = detail
            entry = {**body, "hash": entry_hash(body)}
            with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(canonical(entry) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._seq, self._head = entry["seq"], entry["hash"]
            return entry

    @property
    def head(self):
        return self._head

    def verify(self, expect_head=None):
        with self._lock:
            return verify_file(self.path, expect_head)
