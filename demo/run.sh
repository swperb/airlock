#!/usr/bin/env bash
# airlock demo: run the same hijacked agent twice, once without the gateway
# and once through it, and show the difference side by side.
set -euo pipefail

cd "$(dirname "$0")/.."
RUN=demo/.run
STATE=$RUN/state
export AIRLOCK_DEMO_DB=$RUN/demo.db
export AIRLOCK_DEMO_MAIL=$RUN/outbox.txt

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
rule() { printf '%s\n' "────────────────────────────────────────────────────────"; }

bold "Building..."
cargo build --quiet --workspace
mkdir -p "$RUN/bin" "$STATE"
for b in db-server mail-server web-server passthrough agent; do
  cp -f "target/debug/$b" "$RUN/bin/$b"
done
AIRLOCK=target/debug/airlock

customers_count() {
  # Read sqlite directly. Do NOT start db-server here: it reseeds on startup
  # and would hide whatever the agent did to the table.
  python3 -I - "$AIRLOCK_DEMO_DB" <<'PY'
import sqlite3, sys, os
path = sys.argv[1]
if not os.path.exists(path):
    print("no database"); raise SystemExit
c = sqlite3.connect(path)
try:
    n = c.execute("SELECT count(*) FROM customers").fetchone()[0]
    print(f"{n} rows")
except sqlite3.OperationalError:
    print("TABLE DROPPED (gone)")
PY
}

reset_world() {
  rm -rf "$RUN/state" "$AIRLOCK_DEMO_MAIL" "$AIRLOCK_DEMO_DB"
  mkdir -p "$STATE"
  # Seed the database by starting the server once (it seeds on startup) and stopping it.
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    | timeout 5 "$RUN/bin/db-server" >/dev/null 2>&1 || true
}

echo
rule
bold "RUN 1: WITHOUT airlock (agent talks straight to the tools)"
rule
reset_world
echo "customers table before: $(customers_count)"
echo
"$RUN/bin/agent" -- "$RUN/bin/passthrough" | grep -v AGENT_SUMMARY || true
echo
echo "customers table after:  $(customers_count)"
if [ -f "$AIRLOCK_DEMO_MAIL" ]; then
  bold "outbox.txt (mail that was 'sent'):"
  sed 's/^/    /' "$AIRLOCK_DEMO_MAIL"
else
  echo "outbox.txt: (empty)"
fi

echo
rule
bold "RUN 2: WITH airlock (same agent, same injection)"
rule
reset_world
echo "customers table before: $(customers_count)"
echo
"$RUN/bin/agent" -- "$AIRLOCK" run --policy demo/fixtures/policy.toml --task support-triage --session demo 2>/dev/null \
  | grep -v AGENT_SUMMARY || true
echo
echo "customers table after:  $(customers_count)"
if [ -s "$AIRLOCK_DEMO_MAIL" ]; then
  bold "outbox.txt (mail that was 'sent'):"
  sed 's/^/    /' "$AIRLOCK_DEMO_MAIL"
else
  echo "outbox.txt: (empty, nothing was exfiltrated)"
fi

echo
bold "Pending approvals airlock is holding for a person:"
"$AIRLOCK" pending --state-dir "$STATE" | sed 's/^/    /'

echo
bold "Audit trail (airlock run):"
"$AIRLOCK" audit tail --state-dir "$STATE" --n 10 | sed 's/^/    /'
echo
printf '    audit chain: '; "$AIRLOCK" audit verify --state-dir "$STATE"

echo
rule
bold "SUMMARY"
rule
cat <<'TXT'
  Without airlock: the injected "DROP TABLE customers" ran and the export
  email was sent to exfil@attacker.example.
  With airlock:    reading the issue was allowed (reads fail open), but
    - db.execute DROP ... was DENIED outright by a deny pattern, and
    - mail.send to attacker.example was DENIED by the recipient limit
      (and would need a person even for an allowed address, because it is
      irreversible_external and the arguments were derived from untrusted
      web content).
  Every attempt is in the tamper-evident audit log.
TXT
