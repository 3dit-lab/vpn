#!/usr/bin/env bash
# Stage a PostgreSQL-capable portal alongside the working SQLite portal.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
dst=/opt/vpn-portal-shared
install -d -m 0755 "$dst"
install -m 0644 "$root"/portal/{portal,backup,postgres_backend,wireguard_profile}.py "$dst/"
install -m 0644 "$root/scripts/sync-peers.py" "$dst/"
if python3 -c 'import psycopg, gunicorn' 2>/dev/null; then
    ln -sfn /usr/bin/python3 "$dst/python"
else
    python3 -m venv --system-site-packages "$dst/venv"
    "$dst/venv/bin/pip" install 'psycopg[binary]==3.2.10'
    ln -sfn "$dst/venv/bin/python" "$dst/python"
fi
"$dst/python" -c 'import flask, psycopg, gunicorn, cryptography, PIL'
"$dst/python" -m py_compile "$dst/"*.py
for unit in vpn-portal-peers.service vpn-portal-peers.timer wg-portal-sync.service wg-portal-sync.timer; do
    install -m 0644 "$root/deploy/cluster/$unit" /etc/systemd/system/
done
systemctl daemon-reload
printf 'Portal candidate staged at %s\n' "$dst"
