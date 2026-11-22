#!/usr/bin/env bash
# Seed EE-1's loopback application. Public traffic remains on the FI-1 writer.
set -euo pipefail

src=${1:?Pass checked-out VPN repository path}
data=/var/lib/vpn-portal
key=/root/.ssh/vpn-replica
known=/root/.ssh/vpn-replica-known-hosts
install -d -m 0755 /opt/vpn-portal
id vpnportal >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin vpnportal
install -d -o vpnportal -g vpnportal -m 0700 "$data" "$data/configs"
install -d -o vpnportal -g vpnportal -m 0755 /var/log/vpn-portal
install -m 0644 "$src/portal/portal.py" "$src/portal/backup.py" /opt/vpn-portal/
install -m 0644 "$src/deploy/vpn-portal.service" /etc/systemd/system/
if [[ ! -s "$data/portal.db" ]]; then
    umask 077
    stage=$(mktemp -d)
    trap 'rm -rf -- "$stage"' EXIT
    timeout 90 ssh -T -i "$key" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o BindInterface=vpn-cluster -o ConnectTimeout=5 -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$known" root@10.77.240.1 export >"$stage/export.tgz"
    tar -xzf "$stage/export.tgz" -C "$stage" var/lib/vpn-portal/portal.db \
        var/lib/vpn-portal/configs var/lib/vpn-portal/peers.json etc/vpn-portal.env
    install -m 0600 "$stage/etc/vpn-portal.env" /etc/vpn-portal.env
    rsync -a --chown=vpnportal:vpnportal "$stage/var/lib/vpn-portal/configs/" "$data/configs/"
    install -m 0600 -o vpnportal -g vpnportal "$stage/var/lib/vpn-portal/peers.json" "$data/peers.json"
    install -m 0600 -o vpnportal -g vpnportal "$stage/var/lib/vpn-portal/portal.db" "$data/portal.db"
fi
systemctl daemon-reload
systemctl enable --now vpn-portal

for attempt in {1..15}; do
    if curl -fsS --max-time 2 http://127.0.0.1:8081/ >/dev/null; then break; fi
    if (( attempt == 15 )); then exit 1; fi
    sleep 1
done
install -m 0644 "$src/deploy/fail2ban/filter.d/vpn-portal-auth.conf" /etc/fail2ban/filter.d/
# Keep host defaults and the centrally managed Guard TRUST exclusions.
if [[ ! -e /var/log/nginx/vpn-portal-auth.log ]]; then
    install -m 0640 -o www-data -g adm /dev/null /var/log/nginx/vpn-portal-auth.log
fi
awk '/^\[DEFAULT\]$/ || /^ignoreip[[:space:]]*=/ {next}
     {print}
     /^logpath.*vpn-portal\/auth\.log$/ {print "           /var/log/nginx/vpn-portal-auth.log"}' \
    "$src/deploy/fail2ban/jail.d/vpn-portal.local" \
    >/etc/fail2ban/jail.d/vpn-portal.local
fail2ban-client -t
fail2ban-client reload
systemctl start guard-vpn-policy.service
fail2ban-client status
