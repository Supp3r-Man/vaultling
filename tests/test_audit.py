import json

from vault.audit import AuditLog, entry_hash


def make_log(tmp_path, n=5):
    log = AuditLog(tmp_path / "audit.log")
    for i in range(n):
        log.append("put", actor="root", path=f"app/s{i}", detail=f"version {i}")
    return log


def read_lines(log):
    return log.path.read_text(encoding="utf-8").splitlines()


def write_lines(log, lines):
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_clean_log_verifies(tmp_path):
    log = make_log(tmp_path)
    result = log.verify()
    assert result.ok and result.count == 5 and result.head == log.head


def test_missing_or_empty_log_verifies(tmp_path):
    assert AuditLog(tmp_path / "none.log").verify().ok


def test_entries_chain_to_each_other(tmp_path):
    log = make_log(tmp_path, 3)
    entries = [json.loads(line) for line in read_lines(log)]
    assert entries[1]["prev"] == entries[0]["hash"] and entries[2]["prev"] == entries[1]["hash"]
    assert [e["seq"] for e in entries] == [1, 2, 3]


def test_edited_entry_is_detected(tmp_path):
    log = make_log(tmp_path)
    lines = read_lines(log)
    lines[2] = lines[2].replace("app/s2", "app/zz")
    write_lines(log, lines)
    result = log.verify()
    assert not result.ok and "line 3" in result.error and "edited" in result.error


def test_edit_with_recomputed_hash_still_breaks_the_next_link(tmp_path):
    log = make_log(tmp_path)
    lines = read_lines(log)
    entry = json.loads(lines[1])
    entry["path"] = "app/zz"
    entry["hash"] = entry_hash({k: v for k, v in entry.items() if k != "hash"})
    lines[1] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    write_lines(log, lines)
    result = log.verify()
    assert not result.ok and "line 3" in result.error


def test_deleted_entry_is_detected(tmp_path):
    log = make_log(tmp_path)
    lines = read_lines(log)
    del lines[1]
    write_lines(log, lines)
    result = log.verify()
    assert not result.ok and "line 2" in result.error


def test_reordered_entries_are_detected(tmp_path):
    log = make_log(tmp_path)
    lines = read_lines(log)
    lines[1], lines[2] = lines[2], lines[1]
    write_lines(log, lines)
    assert not log.verify().ok


def test_damaged_line_is_detected(tmp_path):
    log = make_log(tmp_path)
    lines = read_lines(log)
    lines[3] = "this is not json"
    write_lines(log, lines)
    result = log.verify()
    assert not result.ok and "line 4" in result.error


def test_trimmed_tail_needs_an_external_anchor(tmp_path):
    log = make_log(tmp_path)
    anchor = log.head
    lines = read_lines(log)
    write_lines(log, lines[:-1])
    assert log.verify().ok  # the chain alone cannot see this
    result = log.verify(expect_head=anchor)
    assert not result.ok and "truncated" in result.error


def test_anchor_matches_an_intact_log(tmp_path):
    log = make_log(tmp_path)
    assert log.verify(expect_head=log.head).ok


def test_reopening_continues_the_chain(tmp_path):
    make_log(tmp_path, 3)
    again = AuditLog(tmp_path / "audit.log")
    again.append("read", actor="token:abcd1234", path="app/s0")
    result = again.verify()
    assert result.ok and result.count == 4
