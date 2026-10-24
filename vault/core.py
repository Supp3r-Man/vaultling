"""Vault core: seal state, storage, auth, policy and secret operations. The Flask layer wraps this.

State on disk (data dir): store.json (wrapped keys + ciphertext only), policy.json, audit.log.
The master key exists only in memory, and only while unsealed.
"""
import base64
import copy
import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import crypto, shamir
from .audit import AuditLog

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_./-]{0,127}$")
MAX_VALUE_BYTES = 16 * 1024
DEFAULT_TTL, MAX_TTL = 300, 3600
STARTER_POLICY = {"policies": {"app-read": {"rules": [{"path": "app/*", "capabilities": ["read"]}]}}}


class VaultError(Exception):
    status = 400


class BadRequest(VaultError):
    status = 400


class Unauthorized(VaultError):
    status = 401


class Denied(VaultError):
    status = 403


class NotFound(VaultError):
    status = 404


class IntegrityError(VaultError):
    status = 500


class Sealed(VaultError):
    status = 503


@dataclass(frozen=True)
class Principal:
    id: str
    is_root: bool
    policy: Optional[str] = None


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _unb64(text):
    return base64.b64decode(text)


def _token_hash(token):
    # Tokens are 192+ random bits, so a fast hash is enough; slow hashes are for human passwords.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _write_json(path, data):
    """Atomic replace: write a temp file in the same directory, fsync, then rename over the target."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")  # created 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def validate_name(name):
    if (not isinstance(name, str) or not NAME_RE.fullmatch(name) or ".." in name.split("/")
            or "//" in name or name.endswith("/")):
        raise BadRequest("invalid secret name (lowercase letters, digits and _ . - /; no '..' or '//')")


class Vault:
    def __init__(self, data_dir, clock=time.time):
        self.dir = Path(data_dir)
        self.clock = clock
        self._lock = threading.RLock()
        self._master = None  # 32 bytes while unsealed, otherwise None
        self._pending = {}  # share index -> share bytes collected towards the threshold
        self._tokens = {}  # sha256(token) -> {"policy", "expires"}; memory only, cleared on seal
        try:
            self._state = json.loads((self.dir / "store.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise VaultError("vault is not initialised; run `init` first") from None
        self.audit = AuditLog(self.dir / "audit.log")

    # -- setup ------------------------------------------------------------
    @classmethod
    def init(cls, data_dir, shares=5, threshold=3):
        """Create a vault. Returns (hex shares, root token). Neither is stored in the clear."""
        d = Path(data_dir)
        d.mkdir(parents=True, exist_ok=True)
        if (d / "store.json").exists():
            raise BadRequest("already initialised")
        master = crypto.new_key()
        parts = shamir.split(master, shares, threshold)
        root_token = "vr." + secrets.token_urlsafe(24)
        state = {
            "format": 1,
            "seal": {"n": shares, "k": threshold},
            "master_version": 1,
            "keycheck": _b64(crypto.make_keycheck(master, 1)),
            "root_token_hash": _token_hash(root_token),
            "secrets": {},
        }
        _write_json(d / "store.json", state)
        if not (d / "policy.json").exists():
            (d / "policy.json").write_text(json.dumps(STARTER_POLICY, indent=2) + "\n", encoding="utf-8")
        AuditLog(d / "audit.log").append("init", actor="operator", detail=f"{threshold}-of-{shares}")
        return [p.hex() for p in parts], root_token

    # -- seal state -------------------------------------------------------
    def status(self):
        seal = self._state["seal"]
        return {"sealed": self._master is None, "threshold": seal["k"], "shares": seal["n"],
                "progress": len(self._pending)}

    def unseal(self, share_hex):
        with self._lock:
            if self._master is not None:
                return self.status()
            try:
                share = bytes.fromhex(share_hex)
            except (ValueError, TypeError):
                raise BadRequest("share must be a hex string") from None
            if len(share) != crypto.KEY_BYTES + 1 or share[0] == 0:
                raise BadRequest("share is malformed")
            self._pending[share[0]] = share  # same index twice counts once
            k = self._state["seal"]["k"]
            self.audit.append("unseal_progress", actor="anonymous", detail=f"{len(self._pending)}/{k}")
            if len(self._pending) >= k:
                candidate = shamir.combine(list(self._pending.values()))
                self._pending.clear()  # success or failure, start over
                keycheck = _unb64(self._state["keycheck"])
                if not crypto.check_keycheck(candidate, keycheck, self._state["master_version"]):
                    self.audit.append("unseal", actor="anonymous", outcome="denied",
                                      detail="shares did not reconstruct the master key")
                    raise BadRequest("shares did not reconstruct the master key; progress reset")
                self._master = candidate
                self.audit.append("unseal", actor="anonymous")
            return self.status()

    def seal(self, principal):
        self._require_root(principal, "seal the vault")
        with self._lock:
            self._master = None
            self._pending.clear()
            self._tokens.clear()
            self.audit.append("seal", actor=principal.id)
            return self.status()

    def _require_unsealed(self):
        if self._master is None:
            raise Sealed("vault is sealed")

    # -- auth and policy --------------------------------------------------
    def authenticate(self, token):
        with self._lock:
            if not token:
                raise Unauthorized("missing token")
            digest = _token_hash(token)
            if hmac.compare_digest(digest, self._state["root_token_hash"]):
                return Principal("root", True)
            rec = self._tokens.get(digest)
            if rec and rec["expires"] > self.clock():
                return Principal(f"token:{digest[:8]}", False, rec["policy"])
            self._tokens.pop(digest, None)
            self.audit.append("auth", actor="anonymous", outcome="denied", detail="invalid or expired token")
            raise Unauthorized("invalid or expired token")

    def _policies(self):
        try:
            policies = json.loads((self.dir / "policy.json").read_text(encoding="utf-8"))["policies"]
            return policies if isinstance(policies, dict) else {}
        except (OSError, ValueError, KeyError, TypeError):
            return {}

    def authorize(self, principal, path, capability):
        """Deny by default: root passes; everyone else needs a matching rule. Fails closed on bad policy."""
        if principal.is_root:
            return
        try:
            rules = self._policies().get(principal.policy, {}).get("rules", [])
            allowed = any(isinstance(r, dict) and fnmatch.fnmatchcase(path, str(r.get("path", "")))
                          and capability in r.get("capabilities", []) for r in rules)
        except (AttributeError, TypeError):
            allowed = False
        if not allowed:
            self.audit.append("denied", actor=principal.id, path=path, outcome="denied", detail=capability)
            raise Denied(f"policy denies {capability} on {path}")

    def _require_root(self, principal, action):
        if not principal.is_root:
            self.audit.append("denied", actor=principal.id, outcome="denied", detail=action)
            raise Denied(f"only the root token may {action}")

    def mint_token(self, principal, policy, ttl=DEFAULT_TTL):
        self._require_root(principal, "mint tokens")
        if not isinstance(policy, str) or policy not in self._policies():
            raise BadRequest("unknown policy")
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= MAX_TTL:
            raise BadRequest(f"ttl must be an integer between 1 and {MAX_TTL} seconds")
        with self._lock:
            now = self.clock()
            self._tokens = {h: r for h, r in self._tokens.items() if r["expires"] > now}
            token = "vl." + secrets.token_urlsafe(24)
            digest = _token_hash(token)
            self._tokens[digest] = {"policy": policy, "expires": now + ttl}
            self.audit.append("token_mint", actor=principal.id, detail=f"policy={policy} ttl={ttl}s id={digest[:8]}")
            return {"token": token, "policy": policy, "ttl": ttl}

    # -- secrets ----------------------------------------------------------
    def _store_version(self, principal, name, plaintext, event):
        state = copy.deepcopy(self._state)  # mutate a copy so a failed write leaves memory consistent
        entry = state["secrets"].setdefault(name, {"current": 0, "versions": {}})
        version = entry["current"] + 1
        ciphertext, wrapped = crypto.encrypt_secret(self._master, name, version, plaintext)
        entry["versions"][str(version)] = {
            "ct": _b64(ciphertext),
            "wrapped_dek": _b64(wrapped),
            "created": datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(timespec="seconds"),
            "master_version": state["master_version"],
        }
        entry["current"] = version
        # Audit first: if the log cannot be written, nothing is stored unrecorded.
        self.audit.append(event, actor=principal.id, path=name, detail=f"version {version}")
        _write_json(self.dir / "store.json", state)
        self._state = state
        return {"name": name, "version": version}

    def put(self, principal, name, value):
        validate_name(name)
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            raise BadRequest(f"value must be a non-empty string of at most {MAX_VALUE_BYTES} bytes")
        with self._lock:
            self.authorize(principal, name, "write")
            self._require_unsealed()
            return self._store_version(principal, name, value.encode("utf-8"), "put")

    def rotate(self, principal, name):
        """Replace a secret with a fresh random value as a new version (old versions are kept)."""
        validate_name(name)
        with self._lock:
            self.authorize(principal, name, "write")
            self._require_unsealed()
            if name not in self._state["secrets"]:
                raise NotFound("no such secret; use put first")
            return self._store_version(principal, name, secrets.token_urlsafe(32).encode("utf-8"), "rotate")

    def get(self, principal, name, version=None):
        validate_name(name)
        if version is not None and (isinstance(version, bool) or not isinstance(version, int) or version < 1):
            raise BadRequest("version must be a positive integer")
        with self._lock:
            self.authorize(principal, name, "read")
            self._require_unsealed()
            entry = self._state["secrets"].get(name)
            if not entry:
                raise NotFound("no such secret")
            number = entry["current"] if version is None else version
            rec = entry["versions"].get(str(number))
            if not rec:
                raise NotFound("no such version")
            try:
                plaintext = crypto.decrypt_secret(self._master, name, number, _unb64(rec["ct"]),
                                                  _unb64(rec["wrapped_dek"]))
            except (crypto.DecryptError, ValueError):
                self.audit.append("read", actor=principal.id, path=name, outcome="error",
                                  detail=f"version {number} failed its integrity check")
                raise IntegrityError("stored secret failed its integrity check") from None
            self.audit.append("read", actor=principal.id, path=name, detail=f"version {number}")
            return {"name": name, "version": number, "value": plaintext.decode("utf-8")}

    # -- master key rotation ---------------------------------------------
    def rotate_master(self, principal):
        """New master key; every data key is rewrapped, no secret is re-encrypted. Returns new shares."""
        self._require_root(principal, "rotate the master key")
        with self._lock:
            self._require_unsealed()
            old, new = self._master, crypto.new_key()
            seal = self._state["seal"]
            parts = shamir.split(new, seal["n"], seal["k"])  # before saving, so shares always exist
            state = copy.deepcopy(self._state)
            version = state["master_version"] + 1
            for name, entry in state["secrets"].items():
                for number, rec in entry["versions"].items():
                    rec["wrapped_dek"] = _b64(crypto.rewrap_dek(old, new, name, int(number),
                                                                _unb64(rec["wrapped_dek"])))
                    rec["master_version"] = version
            state["master_version"] = version
            state["keycheck"] = _b64(crypto.make_keycheck(new, version))
            self.audit.append("rotate_master", actor=principal.id, detail=f"master_version {version}")
            _write_json(self.dir / "store.json", state)  # one atomic replace: all data keys move, or none
            self._state, self._master = state, new
            self._pending.clear()
            return {"master_version": version, "threshold": seal["k"], "shares": [p.hex() for p in parts]}

    def verify_audit(self, principal, expect_head=None):
        self._require_root(principal, "verify the audit log")
        result = self.audit.verify(expect_head)
        return {"ok": result.ok, "entries": result.count, "head": result.head, "error": result.error}
