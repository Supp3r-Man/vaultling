#!/usr/bin/env bash
# Guided tour of Vaultling. Uses a throwaway data dir and 127.0.0.1:8217, then cleans up.
# Everything printed here (shares, tokens, secrets) is disposable demo data. Usage: bash demo.sh
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python}"
DATA="$(mktemp -d)"
export VAULTLING_ADDR="http://127.0.0.1:8217"
unset VAULTLING_TOKEN

vl() { "$PY" cli.py "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
expect_fail() { if "$@"; then echo "UNEXPECTED SUCCESS: $*" >&2; exit 1; else echo "   -> refused, as expected"; fi; }
cleanup() { if [ -n "${SERVER_PID:-}" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi; rm -rf "$DATA"; }
trap cleanup EXIT

step "1. init: split the master key into 5 shares (any 3 unseal it)"
INIT="$(vl init --data "$DATA")"
echo "$INIT"
SHARES=($(echo "$INIT" | awk '/^share [0-9]+:/ {print $3}'))
ROOT="$(echo "$INIT" | awk '/^root token:/ {print $3}')"

step "2. start the server (127.0.0.1 only); it boots sealed"
vl serve --data "$DATA" --port 8217 >"$DATA/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do vl status >/dev/null 2>&1 && break; sleep 0.2; done
vl status || { echo "server did not start:"; cat "$DATA/server.log"; exit 1; }

step "3. sealed means sealed: even the root token cannot store anything"
export VAULTLING_TOKEN="$ROOT"
expect_fail vl put app/db "demo-password-1"

step "4. unseal ceremony: two shares are not enough, the third is"
vl unseal "${SHARES[0]}"
vl unseal "${SHARES[3]}"
expect_fail vl put app/db "demo-password-1"
vl unseal "${SHARES[4]}"

step "5. secrets are versioned; rotate writes a fresh random value as a new version"
vl put app/db "demo-password-1"
vl get app/db
vl rotate app/db
echo "current:"; vl get app/db
echo "version 1 is kept:"; vl get app/db --version 1

step "6. short-lived token + deny-by-default policy (app-read allows read on app/* only)"
READ="$(vl token --policy app-read --ttl 60)"
(
  export VAULTLING_TOKEN="$READ"
  vl get app/db
  expect_fail vl put app/db "nope"
  expect_fail vl get other/thing
)

step "7. rotate-master: data keys are rewrapped, secrets untouched, old shares die"
NEW="$(vl rotate-master)"
echo "$NEW"
NEWSHARES=($(echo "$NEW" | awk '/^share [0-9]+:/ {print $3}'))
vl get app/db
vl seal
vl unseal "${SHARES[0]}" >/dev/null
vl unseal "${SHARES[1]}" >/dev/null
expect_fail vl unseal "${SHARES[2]}"
vl unseal "${NEWSHARES[1]}" "${NEWSHARES[2]}" "${NEWSHARES[4]}"
vl get app/db

step "8. the audit log is a hash chain; verify it and note the head hash"
vl verify-audit --data "$DATA"
HEAD="$(vl verify-audit --data "$DATA" | awk '{print $NF}')"
tail -n 3 "$DATA/audit.log"
cp "$DATA/audit.log" "$DATA/audit.good"

step "9. tamper 1: edit an entry"
sed -i.bak 's/"event":"put"/"event":"PUT"/' "$DATA/audit.log"
expect_fail vl verify-audit --data "$DATA"
cp "$DATA/audit.good" "$DATA/audit.log"

step "10. tamper 2: delete an entry"
sed -i.bak '3d' "$DATA/audit.log"
expect_fail vl verify-audit --data "$DATA"
cp "$DATA/audit.good" "$DATA/audit.log"

step "11. tamper 3: trim the tail. The chain alone cannot see this; an external anchor can"
sed -i.bak '$d' "$DATA/audit.log"
vl verify-audit --data "$DATA"
echo "   ^ still passes: a hash chain alone cannot detect a trimmed tail"
expect_fail vl verify-audit --data "$DATA" --expect-head "$HEAD"
cp "$DATA/audit.good" "$DATA/audit.log"
vl verify-audit --data "$DATA" --expect-head "$HEAD"

step "12. seal"
vl seal
echo
echo "Done. The throwaway vault is deleted on exit."
