#!/usr/bin/env bash
# Run only after both active SQLite writers have been frozen.
set -euo pipefail

src=$(cd "$(dirname "$0")" && pwd)
wgconfigs=/var/lib/vpn-portal/configs
umask 077
test -f /etc/nginx/pm-vpn-maintenance
test "$(systemctl is-active vpn-portal)" = inactive
d=$(mktemp -d)
trap 'rm -rf -- "$d"' EXIT
remote=(ssh -i /root/.ssh/fi1_to_fi2 -o IdentitiesOnly=yes -o BatchMode=yes
        -o StrictHostKeyChecking=yes -o ConnectTimeout=5 root@91.211.114.164)
"${remote[@]}" 'test -f /etc/nginx/pm-vpn-maintenance && test "$(systemctl is-active vpn-portal)" = inactive'
snapshot='import pathlib, sqlite3, sys, tempfile
with tempfile.TemporaryDirectory() as work:
    p = pathlib.Path(work) / "backup"
    src = sqlite3.connect("file:/var/lib/vpn-portal/portal.db?mode=ro", uri=True)
    dst = sqlite3.connect(p)
    src.backup(dst)
    dst.close()
    src.close()
    sys.stdout.buffer.write(p.read_bytes())'
python3 -c "$snapshot" >"$d/fi1"
"${remote[@]}" python3 -c "'$snapshot'" >"$d/fi2"
digest='import hashlib, json, pathlib, re
fields = re.compile(r"(?m)^[ \t]*(PrivateKey|PresharedKey|PublicKey|Address)[ \t]*=[ \t]*([^\r\n]+)")
pool = {}
for path in pathlib.Path("/var/lib/vpn-portal/configs").glob("client*.conf"):
    values = fields.findall(path.read_text())
    if len(values) != 4:
        raise ValueError(path.name)
    pool[path.name] = hashlib.sha256(json.dumps(sorted(values)).encode()).hexdigest()
print(json.dumps(pool, sort_keys=True))'
python3 -c "$digest" >"$d/fi1-digests"
"${remote[@]}" python3 -c "'$digest'" >"$d/fi2-digests"
if ! cmp -s "$d/fi1-digests" "$d/fi2-digests"; then
    echo "Config identities differ between FI-1 and FI-2; shared import stopped" >&2
    exit 1
fi
python3 "$src/reconcile-portal.py" "$d/fi1" "$d/fi2" "$d/merged"
export PGHOST=10.77.240.1,10.77.240.2,10.77.240.3 PGPORT=15432 PGDATABASE=pm_vpn PGUSER=postgres
export PGTARGETSESSIONATTRS=read-write PGCONNECT_TIMEOUT=3 PGPASSWORD
PGPASSWORD=$(python3 -c 'import json; print(json.load(open("/etc/pm-vpn-cluster/pg-secrets.json"))["admin"])')
pg() {
    docker exec -i -e PGHOST -e PGPORT -e PGUSER -e PGDATABASE -e PGTARGETSESSIONATTRS \
        -e PGCONNECT_TIMEOUT -e PGPASSWORD pm-vpn-postgres psql -v ON_ERROR_STOP=1 "$@"
}
python3 "$src/export-portal-postgres.py" "$d/merged" "$wgconfigs" "$@" | pg >/dev/null
pg -Atc "SELECT (SELECT COUNT(*) FROM people), (SELECT COUNT(*) FROM assignments), (SELECT COUNT(*) FROM portal_configs)"
python3 - "$d/merged" <<'PY'
import psycopg, sqlite3, sys
from pathlib import Path
src = sqlite3.connect(Path(sys.argv[1]).resolve().as_uri() + "?mode=ro", uri=True)
with psycopg.connect() as c:
    for table in ("orgs", "people", "assignments"):
        assert src.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    sql = "SELECT slot,person_id,assigned_at FROM assignments ORDER BY slot"
    assert src.execute(sql).fetchall() == c.execute(sql).fetchall()
print("Imported identities and assignments verified")
PY
