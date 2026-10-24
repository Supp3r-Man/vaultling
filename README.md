# Vaultling
**🔐 Five people hold the keys. Nobody holds them all.**
## What it does
A tiny local secrets manager that shows real vault design: AES-256-GCM envelope encryption, Shamir 3-of-5 unsealing, versioned secrets, short-lived tokens, deny-by-default policy and a hash-chained audit log.
## Run it
`pip install cryptography flask pytest`, then `bash demo.sh` for the guided tour (or `python cli.py init` and `python cli.py serve`). `pytest` runs the tests.
## The unseal ceremony
First, `init` prints five shares and a root token exactly once; hand each share to a different person. Second, start the server, which boots sealed with the master key nowhere. Third, any three people run `unseal`, and the key lives in memory only until `seal` or a restart.
## Honest disclaimer
Educational and not audited. Please do not store real secrets in it.
## Things that went wrong while building this
- Nothing was run during the build, so the first `demo.sh` may find a typo before an attacker does.
- A hash chain catches edits and deletions but not a trimmed tail, so the demo shows that gap and the `--expect-head` anchor that closes it.

Rotate often, split your keys, and never email a share.
