#!/usr/bin/env bash
# Add plain WireGuard beside the existing AmneziaWG or router gateway.
set -euo pipefail

src=$(cd "$(dirname "$0")" && pwd)
key=/etc/pm-vpn-cluster/portal-wg.key
conf=/etc/wireguard/wg-portal.conf
umask 077
test -s "$key"
wg pubkey <"$key" >/dev/null
install -m 0755 "$src/vpn-egress-firewall.sh" /usr/local/sbin/pm-vpn-egress-firewall
install -d -m 0700 /etc/wireguard
if [[ ! -e "$conf" ]]; then
    [[ -z $(ip -4 route show 10.19.0.0/20) ]]
    [[ -z $(ss -lunH | awk '$4 ~ /:51822$/') ]]
    tmp=$(mktemp /etc/wireguard/.wg-portal.XXXXXX)
    trap 'rm -f -- "$tmp"' EXIT
    cat >"$tmp" <<WGCONF
[Interface]
Address = 10.19.0.1/20
ListenPort = 51822
PrivateKey = $(cat "$key")
WGCONF
    ln "$tmp" "$conf"
fi
sed -i '/^PostUp = \/usr\/local\/sbin\/pm-vpn-egress-firewall add %i 10\.19\.0\.0\/20 10\.19\.0\.1$/d;
        /^PostDown = \/usr\/local\/sbin\/pm-vpn-egress-firewall remove %i 10\.19\.0\.0\/20 10\.19\.0\.1$/d' "$conf"
install -d -m 0755 /etc/systemd/system/wg-quick@wg-portal.service.d
cat >/etc/systemd/system/wg-quick@wg-portal.service.d/egress.conf <<'UNIT'
[Service]
ExecStartPost=/usr/local/sbin/pm-vpn-egress-firewall add wg-portal 10.19.0.0/20 10.19.0.1
ExecStopPost=/usr/local/sbin/pm-vpn-egress-firewall remove wg-portal 10.19.0.0/20 10.19.0.1
UNIT
chmod 0644 /etc/systemd/system/wg-quick@wg-portal.service.d/egress.conf
systemctl daemon-reload
if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q '^Status: active$'; then
    ufw allow 51822/udp comment 'PM-VPN portal WireGuard'
fi
systemctl enable wg-quick@wg-portal.service
systemctl restart wg-quick@wg-portal.service
wg show wg-portal listen-port
