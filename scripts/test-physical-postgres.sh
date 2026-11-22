#!/usr/bin/env bash
# Run portal checks against the physical PostgreSQL cluster using only a temporary database.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
export PGHOST=10.77.240.1,10.77.240.2,10.77.240.3 PGPORT=15432 PGUSER=postgres
export PGCONNECT_TIMEOUT=3 PGTARGETSESSIONATTRS=read-write
export PGPASSWORD
PGPASSWORD=$(python3 -c 'import json; print(json.load(open("/etc/pm-vpn-cluster/pg-secrets.json"))["admin"])')
need=${1:-2}
case "$need" in 1|2) ;; *) exit 2 ;; esac

for attempt in {1..30}; do
    if python3 - "$need" <<'PY'
import psycopg, sys
try:
    with psycopg.connect("dbname=postgres") as c:
        host = c.execute("SELECT inet_server_addr()").fetchone()[0]
        rows = c.execute("SELECT application_name,sync_state FROM pg_stat_replication WHERE state='streaming'").fetchall()
        if len(rows) < int(sys.argv[1]) or not any(state in ("sync", "quorum") for _, state in rows):
            sys.exit(1)
        print(f"Writer: {host}; streaming: {rows}")
except psycopg.OperationalError:
    sys.exit(1)
PY
    then break; fi
    if (( attempt == 30 )); then echo 'PostgreSQL leader or synchronous replica not ready' >&2; exit 1; fi
    sleep 2
done

db="pm_vpn_rehearsal_$(openssl rand -hex 6)"
db_admin() {
    python3 - "$1" "$db" <<'PY'
import psycopg, sys
from psycopg import sql
with psycopg.connect("dbname=postgres", autocommit=True) as db:
    if sys.argv[1] == "create":
        db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(sys.argv[2])))
    else:
        db.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(sys.argv[2])))
PY
}
db_admin create
trap 'db_admin drop' EXIT
PORTAL_TEST_DSN="dbname=$db" python3 "$root/portal/test_postgres_portal.py"
