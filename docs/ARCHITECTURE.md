# Architecture

## Key hierarchy

```
  5 shares (hex, shown once at init, never stored)
        |  any 3
        v
  Shamir combine over GF(256)  (vault/shamir.py)
        |
        v
  MASTER KEY  (32 bytes, in memory only while unsealed; never written to disk)
        |  AES-256-GCM wrap, AAD = ["dek", name, version]
        v
  DATA KEY per secret version  (32 random bytes; stored only in wrapped form)
        |  AES-256-GCM, AAD = ["secret", name, version]
        v
  SECRET VALUE  (ciphertext in store.json)
```

A key-check blob (a known string encrypted under the master key) lets unseal tell a wrong reconstruction from a right one, since Shamir shares are not self-verifying.

## Components

```
  cli.py ---- HTTP, 127.0.0.1 only ---> vault/api.py (Flask) --> vault/core.py ---> vault/crypto.py (AES-GCM)
    |                                                               |   |   \
    | init, verify-audit work directly on files                     |   |    +----> vault/shamir.py
    +---------------------------------------------------------------+   +---------> vault/audit.py
                                                                        |
                                                                        v
                                                        data dir: store.json  policy.json  audit.log
```

## Storage (data dir)

- `store.json`: seal parameters, master key version, key-check blob, SHA-256 of the root token, and per-secret versions (`ct`, `wrapped_dek`). No plaintext and no keys. Written atomically (temp file, fsync, rename).
- `policy.json`: per-path rules. Deny by default; `app/*` style globs (`*` also crosses `/`). Read on every authorization; a missing or malformed file denies everything.
- `audit.log`: JSON lines forming a hash chain.

## Request flow (get)

1. API reads the bearer token; core hashes it and compares to the root hash or the in-memory token table (expired entries are rejected).
2. Policy check for `read` on the path (root passes). Denials are audited.
3. If sealed, refuse. Otherwise unwrap the data key with the master key, decrypt the value (both steps verify name and version through AAD).
4. Append an audit entry (no value, no token) and return the value with `Cache-Control: no-store`.

## Audit log

```
  entry N = { seq, ts, event, actor, outcome, [path], [detail], prev = hash(N-1), hash = SHA-256(canonical body) }
  genesis prev = 000...0
```

`verify-audit` replays the chain. It detects edits, deletions, insertions and reordering. It cannot detect a trimmed tail or a fully recomputed chain; record the head hash somewhere else and pass `--expect-head`.

## Seal, unseal, rotate

- **Sealed** (default at start): only `status` and `unseal` work; master key absent from memory.
- **Unseal**: submit shares; at the threshold they are combined and checked against the key-check blob; success or failure clears the collected shares.
- **Seal**: master key, pending shares and all tokens are dropped.
- **rotate-master**: new master key, every data key rewrapped, key-check replaced, new shares issued, all in one atomic file replace. Secret ciphertext is untouched; old shares stop working.
- **rotate** (secret): new random value stored as a new version; old versions stay readable.

## Threat model (short)

Protects against: reading the data directory or a backup (only wrapped keys and ciphertext), a holder of a read-only token reaching other paths, silent audit edits, and ciphertext moved between names or versions.
Does not protect against: root on the running host (memory and tokens are readable), anyone holding three shares, a stolen root token, rollback to an older `store.json`, side channels, Python's inability to wipe memory, or traffic sniffing beyond loopback (there is no TLS).
