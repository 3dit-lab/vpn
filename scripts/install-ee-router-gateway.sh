#!/usr/bin/env bash
# Install the EE-1 router-only WireGuard pool.
set -euo pipefail

src=$(cd "$(dirname "$0")" && pwd)
helper=${1:?Pass mt-peer from the matching Guard revision}
d=/etc/wg-mt
conf=/etc/wireguard/wg-mt.conf
umask 077
install -d -m 0700 "$d" /etc/wireguard
test ! -e "$d/server-id" || test "$(cat "$d/server-id")" = 3
printf '3\n' >"$d/server-id"
if [ ! -s "$d/server.key" ]; then
    wg genkey >"$d/server.key"
fi
wg pubkey <"$d/server.key" >"$d/server.pub"
touch "$d/peers.tsv"
install -m 0755 "$helper" /usr/local/sbin/mt-peer
install -m 0755 "$src/vpn-egress-firewall.sh" /usr/local/sbin/pm-vpn-egress-firewall
if [ ! -e "$conf" ]; then
    test -z "$(ss -lunH | awk '$4 ~ /:51821$/')"
    printf '[Interface]\nAddress = 10.9.3.1/24\nListenPort = 51821\nPrivateKey = %s\n' "$(cat "$d/server.key")" >"$conf"
fi
install -d -m 0755 /etc/systemd/system/wg-quick@wg-mt.service.d
cat >/etc/systemd/system/wg-quick@wg-mt.service.d/ee-1.conf <<'UNIT'
[Service]
ExecStartPost=/usr/local/sbin/pm-vpn-egress-firewall add wg-mt 10.9.3.0/24 10.9.3.1
ExecStartPost=/usr/local/sbin/mt-peer restore
ExecStopPost=/usr/local/sbin/pm-vpn-egress-firewall remove wg-mt 10.9.3.0/24 10.9.3.1
UNIT
chmod 0644 /etc/systemd/system/wg-quick@wg-mt.service.d/ee-1.conf
systemctl daemon-reload
systemctl enable --now wg-quick@wg-mt.service
wg show wg-mt listen-port
