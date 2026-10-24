import base64
import json
import os

import pytest

from vault.core import BadRequest, Denied, IntegrityError, NotFound, Sealed, Unauthorized, Vault


def reopen(d, shares):
    v = Vault(d)
    for share in shares[:3]:
        v.unseal(share)
    return v


def test_starts_sealed_and_refuses_work(env):
    d, shares, root = env
    v = Vault(d)
    assert v.status()["sealed"] is True
    admin = v.authenticate(root)
    with pytest.raises(Sealed):
        v.put(admin, "app/db", "x")
    with pytest.raises(Sealed):
        v.get(admin, "app/db")


def test_roundtrip_and_versioning(unsealed):
    v, admin, _ = unsealed
    assert v.put(admin, "app/db", "one")["version"] == 1
    assert v.put(admin, "app/db", "two")["version"] == 2
    assert v.get(admin, "app/db")["value"] == "two"
    assert v.get(admin, "app/db", version=1)["value"] == "one"
    with pytest.raises(NotFound):
        v.get(admin, "app/db", version=3)
    with pytest.raises(NotFound):
        v.get(admin, "app/missing")


def test_two_shares_do_not_unseal_three_do(env):
    d, shares, _ = env
    v = Vault(d)
    v.unseal(shares[0])
    st = v.unseal(shares[4])
    assert st["sealed"] and st["progress"] == 2
    assert v.unseal(shares[2])["sealed"] is False


def test_any_three_distinct_shares_unseal(env):
    d, shares, _ = env
    v = Vault(d)
    for share in (shares[1], shares[3], shares[4]):
        v.unseal(share)
    assert v.status()["sealed"] is False


def test_wrong_share_fails_and_resets_progress(env):
    d, shares, _ = env
    v = Vault(d)
    bogus = (bytes([200]) + os.urandom(32)).hex()
    v.unseal(shares[0])
    v.unseal(shares[1])
    with pytest.raises(BadRequest):
        v.unseal(bogus)
    assert v.status()["sealed"] and v.status()["progress"] == 0
    for share in shares[:3]:  # the real shares still work afterwards
        v.unseal(share)
    assert v.status()["sealed"] is False


def test_shares_from_another_vault_fail(env, tmp_path):
    other_shares, _ = Vault.init(tmp_path / "other", 5, 3)
    d, _, _ = env
    v = Vault(d)
    v.unseal(other_shares[0])
    v.unseal(other_shares[1])
    with pytest.raises(BadRequest):
        v.unseal(other_shares[2])
    assert v.status()["sealed"]


def test_duplicate_share_counts_once(env):
    d, shares, _ = env
    v = Vault(d)
    for _ in range(3):
        st = v.unseal(shares[0])
    assert st["sealed"] and st["progress"] == 1


def test_malformed_shares_are_rejected(env):
    d, _, _ = env
    v = Vault(d)
    for bad in ["zz", "00" * 10, bytes(33).hex()]:  # not hex, wrong length, index 0
        with pytest.raises(BadRequest):
            v.unseal(bad)


def test_nothing_sensitive_is_written_to_disk(unsealed):
    v, admin, (d, shares, root) = unsealed
    v.put(admin, "app/db", "hunter2-plaintext")
    v.get(admin, "app/db")
    for f in d.iterdir():
        text = f.read_text(encoding="utf-8")
        assert "hunter2-plaintext" not in text
        assert root not in text
        for share in shares:
            assert share not in text


def test_deny_by_default_and_policy_grants(unsealed):
    v, admin, _ = unsealed
    v.put(admin, "app/db", "s3")
    v.put(admin, "other/db", "x")
    reader = v.authenticate(v.mint_token(admin, "app-read", 60)["token"])
    assert v.get(reader, "app/db")["value"] == "s3"
    with pytest.raises(Denied):
        v.get(reader, "other/db")
    with pytest.raises(Denied):
        v.put(reader, "app/db", "hack")
    with pytest.raises(Denied):
        v.rotate(reader, "app/db")
    with pytest.raises(Denied):
        v.mint_token(reader, "app-read")
    with pytest.raises(Denied):
        v.seal(reader)
    with pytest.raises(Denied):
        v.rotate_master(reader)


def test_missing_policy_file_denies_everything(unsealed):
    v, admin, (d, _, _) = unsealed
    v.put(admin, "app/db", "s3")
    reader = v.authenticate(v.mint_token(admin, "app-read", 60)["token"])
    (d / "policy.json").unlink()
    with pytest.raises(Denied):
        v.get(reader, "app/db")


def test_unknown_policy_cannot_be_minted(unsealed):
    v, admin, _ = unsealed
    with pytest.raises(BadRequest):
        v.mint_token(admin, "no-such-policy")


def test_token_expires_after_ttl(env):
    d, shares, root = env
    now = [1000.0]
    v = Vault(d, clock=lambda: now[0])
    for share in shares[:3]:
        v.unseal(share)
    token = v.mint_token(v.authenticate(root), "app-read", 10)["token"]
    assert v.authenticate(token).policy == "app-read"
    now[0] += 11
    with pytest.raises(Unauthorized):
        v.authenticate(token)


def test_ttl_is_validated_and_capped(unsealed):
    v, admin, _ = unsealed
    for bad in (0, -1, 99999, "60", True):
        with pytest.raises(BadRequest):
            v.mint_token(admin, "app-read", bad)


def test_bad_tokens_are_unauthorized(unsealed):
    v, _, _ = unsealed
    for bad in ("", "nope", "vl.forged"):
        with pytest.raises(Unauthorized):
            v.authenticate(bad)


def test_seal_wipes_master_key_and_tokens(unsealed):
    v, admin, _ = unsealed
    v.put(admin, "app/db", "s3")
    token = v.mint_token(admin, "app-read", 60)["token"]
    v.seal(admin)
    assert v.status()["sealed"]
    with pytest.raises(Unauthorized):
        v.authenticate(token)
    with pytest.raises(Sealed):
        v.get(admin, "app/db")


def test_rotate_creates_a_new_random_version(unsealed):
    v, admin, _ = unsealed
    v.put(admin, "app/db", "one")
    assert v.rotate(admin, "app/db")["version"] == 2
    assert v.get(admin, "app/db")["value"] != "one"
    assert v.get(admin, "app/db", version=1)["value"] == "one"
    with pytest.raises(NotFound):
        v.rotate(admin, "nope/x")


def test_rotate_master_rewraps_without_reencrypting(unsealed):
    v, admin, (d, shares, _) = unsealed
    v.put(admin, "app/db", "one")
    v.put(admin, "app/db", "two")
    v.put(admin, "app/api", "k")
    before = json.loads((d / "store.json").read_text(encoding="utf-8"))
    res = v.rotate_master(admin)
    after = json.loads((d / "store.json").read_text(encoding="utf-8"))
    assert res["master_version"] == 2 and len(res["shares"]) == 5
    for name, entry in before["secrets"].items():
        for number, rec in entry["versions"].items():
            new = after["secrets"][name]["versions"][number]
            assert new["ct"] == rec["ct"]  # secret ciphertext untouched
            assert new["wrapped_dek"] != rec["wrapped_dek"]  # data key moved under the new master
    assert v.get(admin, "app/db", version=1)["value"] == "one"
    v.seal(admin)
    v.unseal(shares[0])
    v.unseal(shares[1])
    with pytest.raises(BadRequest):  # the old shares are dead
        v.unseal(shares[2])
    for share in res["shares"][:3]:
        v.unseal(share)
    assert v.get(admin, "app/api")["value"] == "k"


def test_tampered_ciphertext_in_the_store_is_detected(unsealed):
    v, admin, (d, shares, root) = unsealed
    v.put(admin, "app/db", "secret")
    path = d / "store.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    rec = state["secrets"]["app/db"]["versions"]["1"]
    ct = bytearray(base64.b64decode(rec["ct"]))
    ct[-1] ^= 1
    rec["ct"] = base64.b64encode(bytes(ct)).decode("ascii")
    path.write_text(json.dumps(state), encoding="utf-8")
    v2 = reopen(d, shares)
    with pytest.raises(IntegrityError):
        v2.get(v2.authenticate(root), "app/db")


def test_swapping_records_between_secrets_is_detected(unsealed):
    v, admin, (d, shares, root) = unsealed
    v.put(admin, "a/one", "alpha")
    v.put(admin, "b/two", "beta")
    path = d / "store.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    recs = state["secrets"]
    recs["a/one"]["versions"]["1"], recs["b/two"]["versions"]["1"] = (
        recs["b/two"]["versions"]["1"], recs["a/one"]["versions"]["1"])
    path.write_text(json.dumps(state), encoding="utf-8")
    v2 = reopen(d, shares)
    with pytest.raises(IntegrityError):
        v2.get(v2.authenticate(root), "a/one")


def test_invalid_names_are_rejected(unsealed):
    v, admin, _ = unsealed
    for bad in ["../x", "a/../b", "A/b", "a//b", "", "a/", "/a", "a b"]:
        with pytest.raises(BadRequest):
            v.put(admin, bad, "x")


def test_audit_log_covers_operations_and_verifies(unsealed):
    v, admin, (d, _, _) = unsealed
    v.put(admin, "app/db", "s3")
    v.get(admin, "app/db")
    v.seal(admin)
    events = [json.loads(line)["event"] for line in (d / "audit.log").read_text(encoding="utf-8").splitlines()]
    assert {"init", "unseal", "put", "read", "seal"} <= set(events)
    assert v.audit.verify().ok
