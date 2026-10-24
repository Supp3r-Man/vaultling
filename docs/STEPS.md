# Steps

1. Install: `pip install cryptography flask pytest`.
2. Guided tour: `bash demo.sh` (init, unseal ceremony, secrets, tokens, policy, rotate-master, three audit-tamper experiments). It uses a throwaway directory and port 8217.
3. By hand:
   - `python cli.py init --data ./data` prints five shares and a root token. Store shares separately.
   - `python cli.py serve --data ./data` in one terminal (listens on 127.0.0.1:8200, starts sealed).
   - In another: `export VAULTLING_TOKEN=<root token>`, then `python cli.py unseal <share>` three times.
   - `python cli.py put app/db` (prompts for the value), `get app/db`, `rotate app/db`.
   - `python cli.py token --policy app-read --ttl 60` mints a read token; edit `data/policy.json` to change what it may do.
   - `python cli.py rotate-master` prints new shares; distribute them and destroy the old ones.
   - `python cli.py verify-audit --data ./data [--expect-head <hash>]`.
4. `pytest` runs the crypto, Shamir, audit, vault and API tests.
5. Experiment: edit or delete a line in `data/audit.log` and run `verify-audit`; then delete the last line and see why the anchor matters.

# Interview Q&A

**1. What is envelope encryption and why use it?**
Data is encrypted with a per-item data key; that data key is encrypted ("wrapped") by a higher-level key, here the master key. Rotating the master key means rewrapping small data keys instead of re-encrypting every secret, each data key protects one message, and the master key never touches bulk data, so it can live in a KMS or HSM. Deleting a wrapped data key also makes its secret unrecoverable.

**2. Why must GCM nonces never repeat under one key?**
GCM encrypts with a counter-mode keystream. Two messages under the same key and nonce share a keystream, so XORing the ciphertexts gives the XOR of the plaintexts, and the authentication subkey can be recovered, which lets an attacker forge messages. With random 96-bit nonces the collision risk grows with the number of messages per key (NIST limits this to about 2^32). Vaultling gives each secret version its own data key used for exactly one encryption, and the master key wraps only one data key per version, far below that limit. Counters or nonce-misuse-resistant modes (AES-GCM-SIV) are alternatives.

**3. Shamir secret sharing vs multi-sig?**
Shamir splits a secret into shares where any k reconstruct it and fewer reveal nothing, but reconstruction puts the whole key in one place and shares cannot be verified. Multi-sig and threshold signatures (MPC) keep the key from ever being assembled: k parties must approve each operation. Shamir answers "who can start the system", multi-sig answers "who must approve every action". Vaultling uses Shamir only to unseal.

**4. What are seal and unseal?**
Sealed means the data on disk stays encrypted and the master key is not in memory, so the process cannot decrypt anything. Unsealing reconstructs the master key from shares and keeps it in memory. Sealing, or a restart, drops it again. It makes a stolen disk or a cold restart harmless and lets you lock the vault quickly during an incident, at the cost of needing people (or an auto-unseal mechanism) after every restart.

**5. How does key rotation work here?**
There are three layers. Secret rotation writes a new value as a new version. Data keys change on every new version. Master rotation (`rotate-master`) generates a new master key, rewraps every data key under it, replaces the key-check blob and issues new shares in a single atomic file replace; the secrets themselves are not re-encrypted, and the old shares stop working. Rotate on a schedule and after any suspected exposure, and retire old shares.

**6. What role do a KMS or HSM play?**
A KMS or HSM holds a root key that never leaves it. The vault asks it to wrap and unwrap the master key (auto-unseal) or the data keys, and access is controlled and logged by the cloud's IAM. That removes the human unseal ceremony and gives hardware-backed protection, but moves trust to whoever controls the KMS permissions and makes startup depend on its availability.

**7. How does the audit log protect its integrity?**
Each entry includes the previous entry's hash and a sequence number, and its own hash covers all of that, so editing, deleting, inserting or reordering entries breaks the chain and `verify-audit` reports where. A chain alone cannot see trimmed tail entries, or an attacker who recomputes every hash. Fix it by anchoring the head hash outside the attacker's reach (print it, ship it to remote or write-once storage, sign it periodically) and by streaming entries to a separate system. Never log secret values or tokens.

**8. What is the secret zero problem?**
Every system that fetches secrets needs a first credential to authenticate with, and that credential has to be delivered somehow. Here the root token is printed once and used to mint short-lived tokens. In production, use platform identity (cloud instance identity, Kubernetes service accounts, SPIFFE) exchanged for short-lived tokens, or single-use wrapped tokens delivered by a trusted orchestrator, so no long-lived secret sits in an image or config file.

**9. What is the threat model?**
It protects against theft of the data directory or backups, a read-only token holder reaching other paths, silent audit edits, and ciphertext swapped between secrets or versions. It does not protect against root on the running host, three colluding share holders, a stolen root token, rollback to an older `store.json`, side channels, Python's lack of reliable memory wiping, or an attacker who can sniff local traffic (no TLS). Writing the model down shows what the design is for and where its limits are.

**10. What would you add for production?**
Independent security review and testing; TLS or mTLS; pluggable storage with replication and backups plus rollback protection; auto-unseal through a KMS or HSM; real authentication methods (OIDC, cloud IAM, Kubernetes); token renewal, revocation and leases; dynamic and short-lived secrets; policy versioning and tests; rate limiting and lockouts; audit shipping to remote immutable storage with signed checkpoints; memory protection (mlock, no swap or core dumps, a language with wipeable memory); verifiable share schemes and a documented rekey ceremony; and monitoring and alerting on unseal, denial and rotation events.
