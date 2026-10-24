from itertools import combinations

import pytest

from vault.shamir import combine, gf_div, gf_mul, split

SECRET = bytes(range(32))


def test_any_three_of_five_recover_the_secret():
    shares = split(SECRET, 5, 3)
    assert len(shares) == 5 and all(len(s) == 33 for s in shares)
    for combo in combinations(shares, 3):
        assert combine(list(combo)) == SECRET


def test_four_or_five_shares_also_work():
    shares = split(SECRET, 5, 3)
    assert combine(shares[:4]) == SECRET
    assert combine(shares) == SECRET


def test_two_of_five_does_not_recover_the_secret():
    shares = split(SECRET, 5, 3)
    for combo in combinations(shares, 2):
        assert combine(list(combo)) != SECRET


def test_a_wrong_share_corrupts_the_result():
    shares = split(SECRET, 5, 3)
    bad = bytearray(shares[2])
    bad[5] ^= 0xFF
    assert combine([shares[0], shares[1], bytes(bad)]) != SECRET


def test_splits_are_randomised():
    assert split(SECRET, 5, 3) != split(SECRET, 5, 3)


def test_other_thresholds_work():
    shares = split(SECRET, 7, 4)
    assert combine([shares[6], shares[0], shares[3], shares[5]]) == SECRET
    assert combine(shares[:3]) != SECRET


def test_bad_parameters_are_rejected():
    for n, k in [(2, 3), (5, 1), (256, 3), (5, 0)]:
        with pytest.raises(ValueError):
            split(SECRET, n, k)


def test_duplicate_shares_are_rejected():
    shares = split(SECRET, 5, 3)
    with pytest.raises(ValueError):
        combine([shares[0], shares[0], shares[1]])


def test_index_zero_and_mismatched_lengths_are_rejected():
    shares = split(SECRET, 5, 3)
    with pytest.raises(ValueError):
        combine([bytes([0]) + shares[0][1:], shares[1], shares[2]])
    with pytest.raises(ValueError):
        combine([shares[0], shares[1][:-1], shares[2]])
    with pytest.raises(ValueError):
        combine([shares[0]])


def test_field_arithmetic_sanity():
    assert gf_mul(0x53, 0xCA) == 0x01  # the classic AES inverse pair
    assert gf_mul(0, 0x77) == 0 and gf_mul(1, 0x77) == 0x77
    for a in (1, 2, 3, 0x53, 0xFF):
        for b in (1, 7, 0x80, 0xFE):
            assert gf_div(gf_mul(a, b), b) == a
    with pytest.raises(ZeroDivisionError):
        gf_div(5, 0)
