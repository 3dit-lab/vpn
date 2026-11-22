#!/usr/bin/env bash
# Install a Patroni service alongside the existing portal. Start it separately.
set -euo pipefail

name=${1:?Pass fi-1, fi-2 or ee-1}
case "$name" in
    fi-1) address=10.77.240.1 ;;
    fi-2) address=10.77.240.2 ;;
    ee-1) address=10.77.240.3 ;;
    *) exit 2 ;;
esac
repo=$(cd "$(dirname "$0")/.." && pwd)
config=/etc/pm-vpn-cluster
image=pm-vpn-patroni:stage
ip -4 -o addr show dev vpn-cluster | grep -Fq " $address/32 "
test -s "$config/pg-secrets.json"
uid=$(docker run --rm --entrypoint id "$image" -u)
gid=$(docker run --rm --entrypoint id "$image" -g)
install -d -m 0700 -o "$uid" -g "$gid" /var/lib/pm-vpn-postgres
if [ ! -e "$config/patroni.json" ]; then
    python3 "$repo/scripts/render-patroni.py" "$name" "$config/pg-secrets.json" "$config/patroni.json" --uid "$uid" --gid "$gid"
fi
if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q '^Status: active$'; then
    for peer in 10.77.240.1 10.77.240.2 10.77.240.3; do
        [ "$peer" = "$address" ] && continue
        ufw allow in on vpn-cluster from "$peer" to "$address" port 15432,18080 proto tcp comment "PM-VPN PostgreSQL"
    done
fi
install -m 0644 "$repo/deploy/cluster/pm-vpn-postgres.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable pm-vpn-postgres.service
