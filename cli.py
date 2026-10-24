#!/usr/bin/env python3
"""Vaultling command line. `init` and `verify-audit` work on files directly; the rest talk to the
local API (start it with `serve`). Set VAULTLING_TOKEN rather than passing --token, because command
line arguments show up in process lists and shell history."""
import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_ADDR = "http://127.0.0.1:8200"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def fail(msg):
    raise SystemExit(f"error: {msg}")


def call(args, method, path, body=None, auth=False):
    parsed = urllib.parse.urlparse(args.addr)
    if parsed.scheme != "http" or parsed.hostname not in LOOPBACK:
        fail("refusing to talk to a non-loopback address over plain HTTP")
    headers = {"Content-Type": "application/json"}
    if auth:
        token = args.token or os.environ.get("VAULTLING_TOKEN")
        if not token:
            fail("this command needs a token: set VAULTLING_TOKEN")
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(args.addr + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        try:
            msg = json.loads(exc.read()).get("error", exc.reason)
        except ValueError:
            msg = exc.reason
        fail(f"{msg} (HTTP {exc.code})")
    except urllib.error.URLError as exc:
        fail(f"cannot reach the vault at {args.addr}: {exc.reason}")


def show_status(st):
    print(f"sealed, unseal progress {st['progress']}/{st['threshold']}" if st["sealed"] else "unsealed")


def print_shares(shares):
    for i, share in enumerate(shares, 1):
        print(f"share {i}: {share}")


def secret_path(name):
    return "/v1/secret/" + urllib.parse.quote(name, safe="/")


def cmd_init(args):
    from vault.core import Vault, VaultError

    try:
        shares, root = Vault.init(args.data, args.shares, args.threshold)
    except (VaultError, ValueError) as exc:
        fail(exc)
    print(f"Initialised {args.data}. Any {args.threshold} of these {args.shares} shares unseal the vault.")
    print("Give each share to a different person. They are shown once and are not stored.\n")
    print_shares(shares)
    print(f"\nroot token: {root}")
    print("The root token is shown once; only its hash is stored.")


def cmd_serve(args):
    from vault.api import main as serve

    serve(["--data", args.data, "--port", str(args.port)])


def cmd_status(args):
    show_status(call(args, "GET", "/v1/status"))


def cmd_unseal(args):
    for share in args.shares or [getpass.getpass("share: ")]:
        show_status(call(args, "POST", "/v1/unseal", {"share": share}))


def cmd_seal(args):
    show_status(call(args, "POST", "/v1/seal", {}, auth=True))


def cmd_put(args):
    value = args.value
    if value == "-":
        value = sys.stdin.read().rstrip("\n")
    elif value is None:
        value = getpass.getpass("value: ")
    res = call(args, "PUT", secret_path(args.name), {"value": value}, auth=True)
    print(f"stored {res['name']} as version {res['version']}")


def cmd_get(args):
    path = secret_path(args.name) + (f"?version={args.version}" if args.version else "")
    res = call(args, "GET", path, auth=True)
    print(res["value"])
    print(f"({res['name']} version {res['version']})", file=sys.stderr)


def cmd_rotate(args):
    res = call(args, "POST", "/v1/rotate/" + urllib.parse.quote(args.name, safe="/"), {}, auth=True)
    print(f"rotated {res['name']} to version {res['version']}")


def cmd_token(args):
    res = call(args, "POST", "/v1/token", {"policy": args.policy, "ttl": args.ttl}, auth=True)
    print(f"policy {res['policy']}, expires in {res['ttl']}s", file=sys.stderr)
    print(res["token"])


def cmd_rotate_master(args):
    res = call(args, "POST", "/v1/rotate-master", {}, auth=True)
    print(f"master key rotated (version {res['master_version']}). Data keys were rewrapped; secrets untouched.")
    print(f"Old shares are now useless. Any {res['threshold']} of these new shares unseal the vault:\n")
    print_shares(res["shares"])


def cmd_verify_audit(args):
    from vault.audit import verify_file

    result = verify_file(Path(args.data) / "audit.log", args.expect_head)
    if not result.ok:
        print(f"audit FAILED: {result.error}", file=sys.stderr)
        raise SystemExit(1)
    print(f"audit OK: {result.count} entries, head {result.head}")


def build_parser():
    p = argparse.ArgumentParser(prog="vaultling", description=__doc__)
    p.add_argument("--addr", default=os.environ.get("VAULTLING_ADDR", DEFAULT_ADDR), help="API address (loopback only)")
    p.add_argument("--token", help="API token (prefer the VAULTLING_TOKEN environment variable)")
    sub = p.add_subparsers(dest="cmd", required=True)
    data = argparse.ArgumentParser(add_help=False)
    data.add_argument("--data", default="data", help="vault data directory (default: data)")

    def add(name, fn, *parents, help=None):
        sp = sub.add_parser(name, parents=list(parents), help=help)
        sp.set_defaults(fn=fn)
        return sp

    sp = add("init", cmd_init, data, help="create a vault and print the unseal shares")
    sp.add_argument("--shares", type=int, default=5)
    sp.add_argument("--threshold", type=int, default=3)
    sp = add("serve", cmd_serve, data, help="run the API on 127.0.0.1 (starts sealed)")
    sp.add_argument("--port", type=int, default=8200)
    add("status", cmd_status, help="show seal status")
    sp = add("unseal", cmd_unseal, help="submit unseal shares (prompts if none given)")
    sp.add_argument("shares", nargs="*")
    add("seal", cmd_seal, help="seal the vault (root token)")
    sp = add("put", cmd_put, help="store a new version of a secret")
    sp.add_argument("name")
    sp.add_argument("value", nargs="?", help="omit to be prompted, or '-' to read stdin")
    sp = add("get", cmd_get, help="read a secret")
    sp.add_argument("name")
    sp.add_argument("--version", type=int)
    sp = add("rotate", cmd_rotate, help="replace a secret with a fresh random value (new version)")
    sp.add_argument("name")
    sp = add("token", cmd_token, help="mint a short-lived token bound to a policy (root token)")
    sp.add_argument("--policy", required=True)
    sp.add_argument("--ttl", type=int, default=300, help="seconds, 1-3600")
    add("rotate-master", cmd_rotate_master, help="new master key, rewrap data keys, print new shares")
    sp = add("verify-audit", cmd_verify_audit, data, help="check the audit log's hash chain")
    sp.add_argument("--expect-head", help="head hash recorded earlier; detects a truncated tail")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
