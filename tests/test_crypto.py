import pytest

from vault.crypto import (DecryptError, check_keycheck, decrypt, decrypt_secret, encrypt, encrypt_secret,
                          make_keycheck, new_key, rewrap_dek)


def test_roundtrip():
    mk = new_key()
    ct, wrapped = encrypt_secret(mk, "app/db", 1, b"hunter2")
    assert b"hunter2" not in ct
    assert decrypt_secret(mk, "app/db", 1, ct, wrapped) == b"hunter2"


def test_every_encryption_uses_a_fresh_data_key_and_nonce():
    mk = new_key()
    a = encrypt_secret(mk, "app/db", 1, b"same")
    b = encrypt_secret(mk, "app/db", 1, b"same")
    assert a[0] != b[0] and a[1] != b[1]


def test_wrong_master_key_fails():
    ct, wrapped = encrypt_secret(new_key(), "app/db", 1, b"x")
    with pytest.raises(DecryptError):
        decrypt_secret(new_key(), "app/db", 1, ct, wrapped)


def test_aad_binds_the_secret_name():
    mk = new_key()
    ct, wrapped = encrypt_secret(mk, "app/db", 1, b"x")
    with pytest.raises(DecryptError):
        decrypt_secret(mk, "app/other", 1, ct, wrapped)


def test_aad_binds_the_version():
    mk = new_key()
    ct, wrapped = encrypt_secret(mk, "app/db", 1, b"x")
    with pytest.raises(DecryptError):
        decrypt_secret(mk, "app/db", 2, ct, wrapped)


def test_records_cannot_be_swapped_between_secrets():
    mk = new_key()
    ct_a, wrapped_a = encrypt_secret(mk, "a", 1, b"alpha")
    ct_b, wrapped_b = encrypt_secret(mk, "b", 1, b"beta")
    with pytest.raises(DecryptError):
        decrypt_secret(mk, "a", 1, ct_b, wrapped_a)  # b's ciphertext under a's data key
    with pytest.raises(DecryptError):
        decrypt_secret(mk, "a", 1, ct_a, wrapped_b)  # b's wrapped key presented as a's


def test_raw_aad_mismatch_fails():
    key = new_key()
    blob = encrypt(key, b"payload", b"context-1")
    assert decrypt(key, blob, b"context-1") == b"payload"
    with pytest.raises(DecryptError):
        decrypt(key, blob, b"context-2")


def test_tampered_ciphertext_fails():
    mk = new_key()
    ct, wrapped = encrypt_secret(mk, "app/db", 1, b"x")
    bad = bytearray(ct)
    bad[-1] ^= 1
    with pytest.raises(DecryptError):
        decrypt_secret(mk, "app/db", 1, bytes(bad), wrapped)


def test_truncated_blob_fails():
    with pytest.raises(DecryptError):
        decrypt(new_key(), b"short", b"")


def test_rewrap_moves_the_data_key_without_touching_the_ciphertext():
    old, new = new_key(), new_key()
    ct, wrapped = encrypt_secret(old, "app/db", 1, b"value")
    rewrapped = rewrap_dek(old, new, "app/db", 1, wrapped)
    assert rewrapped != wrapped
    assert decrypt_secret(new, "app/db", 1, ct, rewrapped) == b"value"
    with pytest.raises(DecryptError):
        decrypt_secret(old, "app/db", 1, ct, rewrapped)


def test_rewrap_still_checks_the_name():
    old, new = new_key(), new_key()
    _, wrapped = encrypt_secret(old, "app/db", 1, b"value")
    with pytest.raises(DecryptError):
        rewrap_dek(old, new, "app/other", 1, wrapped)


def test_keycheck_accepts_only_the_right_key_and_version():
    mk = new_key()
    blob = make_keycheck(mk, 1)
    assert check_keycheck(mk, blob, 1)
    assert not check_keycheck(new_key(), blob, 1)
    assert not check_keycheck(mk, blob, 2)


def test_keys_must_be_32_bytes():
    with pytest.raises(ValueError):
        encrypt(b"short", b"x", b"")
