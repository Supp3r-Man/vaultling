"""Shamir secret sharing over GF(2^8), applied byte by byte. Educational and small on purpose.

How it works
- Each secret byte s is the constant term of a random polynomial f of degree k-1 over GF(256).
- Share number x (1..255) is the pair (x, f(x)). Any k shares pin the polynomial down, and
  Lagrange interpolation at x=0 returns f(0) = s. With k-1 shares, every value of s stays equally
  likely, so they reveal nothing (information-theoretic security, not computational).
- The field is GF(256) with the AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11B). Addition is XOR.
  Multiplication and division use log/exp tables built from the generator 3.

Limits: shares are not verifiable (a bad share silently yields a wrong secret; the vault catches
that with a key-check blob), and whoever combines the shares sees the whole key.
"""
import secrets


def _xtime(a):
    """Multiply by x (i.e. by 2) in GF(256), reducing by 0x11B on overflow."""
    a <<= 1
    return a ^ 0x11B if a & 0x100 else a


# Tables: _EXP[i] = 3**i, _LOG[3**i] = i. _EXP is doubled so sums of two logs need no modulo.
_EXP, _LOG = [0] * 510, [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i], _LOG[_x] = _x, _i
    _x ^= _xtime(_x)  # multiply by 3 (= x + 1)
for _i in range(255, 510):
    _EXP[_i] = _EXP[_i - 255]


def gf_mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def gf_div(a, b):
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    return 0 if a == 0 else _EXP[_LOG[a] + 255 - _LOG[b]]


def _eval(coeffs, x):
    """Evaluate the polynomial (coeffs[0] + coeffs[1]*x + ...) at x using Horner's rule."""
    acc = 0
    for c in reversed(coeffs):
        acc = gf_mul(acc, x) ^ c
    return acc


def split(secret, n=5, k=3):
    """Return n shares (bytes: index byte + one byte per secret byte); any k recover the secret."""
    if not 2 <= k <= n <= 255:
        raise ValueError("need 2 <= threshold <= shares <= 255")
    shares = [bytearray([x]) for x in range(1, n + 1)]
    for byte in secret:
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(k - 1)]  # uniformly random, zeros allowed
        for share in shares:
            share.append(_eval(coeffs, share[0]))
    return [bytes(s) for s in shares]


def combine(shares):
    """Recover the secret from shares. With fewer than k shares this returns garbage, not an error."""
    if len(shares) < 2:
        raise ValueError("need at least 2 shares")
    xs = [s[0] for s in shares]
    if len(set(xs)) != len(xs) or 0 in xs:
        raise ValueError("duplicate or invalid share index")
    if len({len(s) for s in shares}) != 1:
        raise ValueError("shares have different lengths")
    # Lagrange basis at x=0. In characteristic 2, subtraction is XOR: L_i = prod_{m!=i} x_m / (x_i ^ x_m)
    basis = []
    for i, xi in enumerate(xs):
        num = den = 1
        for m, xm in enumerate(xs):
            if m != i:
                num = gf_mul(num, xm)
                den = gf_mul(den, xi ^ xm)
        basis.append(gf_div(num, den))
    out = bytearray()
    for pos in range(1, len(shares[0])):
        acc = 0
        for share, li in zip(shares, basis):
            acc ^= gf_mul(share[pos], li)
        out.append(acc)
    return bytes(out)
