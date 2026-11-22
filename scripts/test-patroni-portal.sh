#!/usr/bin/env bash
# Disposable three-process PostgreSQL failover test on one Docker host.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
image=${1:-pm-vpn-patroni:stage}
etcd=${ETCDCTL:-/opt/pm-vpn-cluster/etcd-v3.6.17-linux-amd64/etcdctl}
export ETCDCTL_ENDPOINTS=${ETCDCTL_ENDPOINTS:-http://10.77.240.1:2379,http://10.77.240.2:2379,http://10.77.240.3:2379}
export ETCDCTL_COMMAND_TIMEOUT=5s
d=$(mktemp -d)
scope=pm-vpn-rehearsal-${d##*.}
members=()
cleanup() {
    for id in "${members[@]}"; do docker rm -f "$id" >/dev/null 2>&1 || true; done
    "$etcd" del --prefix "/service/$scope/" >/dev/null 2>&1 || true
    rm -rf -- "$d"
}
trap cleanup EXIT

export PGUSER=postgres PGPASSWORD PGPORT=15431,15432,15433 PGHOST=127.0.0.1,127.0.0.1,127.0.0.1
PGPASSWORD=$(openssl rand -hex 24)
export REPL_PASSWORD
REPL_PASSWORD=$(openssl rand -hex 24)
export SCOPE="$scope"
export PGCONNECT_TIMEOUT=3 PGTARGETSESSIONATTRS=read-write
uid=$(docker run --rm --entrypoint id "$image" -u)
gid=$(docker run --rm --entrypoint id "$image" -g)
for i in 1 2 3; do
    mkdir "$d/data-$i"
    chown "$uid:$gid" "$d/data-$i"
    chmod 0700 "$d/data-$i"
    python3 - "$i" >"$d/member-$i.json" <<'PY'
import json, os, sys
i = int(sys.argv[1])
pg = f"127.0.0.1:{15430+i}"
api = f"127.0.0.1:{18080+i}"
print(json.dumps({
    "scope": os.environ["SCOPE"], "name": f"stage-{i}", "namespace": "/service",
    "restapi": {"listen": api, "connect_address": api},
    "etcd3": {"hosts": os.environ["ETCDCTL_ENDPOINTS"].replace("http://", "")},
    "bootstrap": {
        "dcs": {
            "ttl": 20, "loop_wait": 5, "retry_timeout": 5,
            "synchronous_mode": "on", "synchronous_mode_strict": True,
            "postgresql": {"use_pg_rewind": True, "parameters": {"wal_log_hints": "on"}},
        },
        "pg_hba": [
            "local all all peer",
            "host all all 127.0.0.1/32 scram-sha-256",
            "host replication replicator 127.0.0.1/32 scram-sha-256",
        ],
    },
    "postgresql": {
        "listen": pg, "connect_address": pg, "data_dir": "/cluster", "bin_dir": "/usr/lib/postgresql/18/bin",
        "authentication": {
            "superuser": {"username": "postgres", "password": os.environ["PGPASSWORD"]},
            "replication": {"username": "replicator", "password": os.environ["REPL_PASSWORD"]},
        },
    },
}))
PY
    chown "$uid:$gid" "$d/member-$i.json"
    chmod 0400 "$d/member-$i.json"
    members+=("$(docker run -d --network host --init \
        --mount "type=bind,src=$d/data-$i,dst=/cluster" \
        --mount "type=bind,src=$d/member-$i.json,dst=/etc/patroni/config.yml,readonly" "$image")")
done

wait_replicas() {
    for attempt in {1..35}; do
        if python3 - "$1" <<'PY'
import psycopg, sys
try:
    with psycopg.connect("dbname=postgres") as db:
        streaming, sync = db.execute("SELECT COUNT(*) FILTER (WHERE state='streaming'), "
                                     "COUNT(*) FILTER (WHERE sync_state IN ('sync','quorum')) "
                                     "FROM pg_stat_replication").fetchone()
        sys.exit(streaming < int(sys.argv[1]) or sync < 1)
except psycopg.OperationalError:
    sys.exit(1)
PY
        then return; fi
        sleep 2
    done
    for id in "${members[@]}"; do docker logs --tail 16 "$id" >&2; done
    exit 1
}

check_portal() {
    local db="portal_case_$1"
    python3 - "$db" <<'PY'
import psycopg, sys
from psycopg import sql
with psycopg.connect("dbname=postgres", autocommit=True) as db:
    db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(sys.argv[1])))
PY
    PORTAL_TEST_DSN="dbname=$db" python3 "$root/portal/test_postgres_portal.py"
}

wait_replicas 2
check_portal baseline
leader=$(python3 - <<'PY'
import psycopg
with psycopg.connect("dbname=postgres") as conn:
    print(conn.execute("SELECT inet_server_port() - 15430").fetchone()[0])
PY
)
for i in "$leader" 1 2 3; do
    if [[ "${tested:-}" = *" $i "* ]]; then continue; fi
    tested="${tested:-} $i "
    id=${members[i-1]}
    docker stop --time 12 "$id" >/dev/null
    wait_replicas 1
    check_portal "after_$i"
    python3 - <<'PY'
import psycopg
with psycopg.connect("dbname=portal_case_baseline") as conn:
    assert conn.execute("SELECT COUNT(*) FROM assignments").fetchone()[0] == 2
PY
    echo "PASS: portal issued and downloaded configs while PostgreSQL member $i was down"
    docker start "$id" >/dev/null
    wait_replicas 2
done
