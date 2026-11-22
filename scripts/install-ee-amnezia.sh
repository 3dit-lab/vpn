#!/usr/bin/env bash
# Install the existing portal's AmneziaWG identity on EE-1.
set -euo pipefail

src=$(cd "$(dirname "$0")" && pwd)
base=${1:?Pass the FI-1 base config received over the management tunnel}
dir=/etc/amnezia/amneziawg
conf="$dir/awg0.conf"
umask 077
command -v awg
command -v awg-quick
if [ ! -e "$conf" ]; then
    install -d -m 0700 "$dir"
    t=$(mktemp "$dir/.ee-awg.XXXXXX")
    trap 'rm -f -- "$t"' EXIT
    awk '/^[[:space:]]*\[Peer\]/{exit} !/^[[:space:]]*(PreUp|PostUp|PreDown|PostDown|SaveConfig)[[:space:]]*=/ {print}' "$base" >"$t"
    grep -Eq '^Address[[:space:]]*=[[:space:]]*10\.8\.0\.1/20[[:space:]]*$' "$t"
    grep -Eq '^ListenPort[[:space:]]*=[[:space:]]*51820[[:space:]]*$' "$t"
    printf '%s\n' \
        'PostUp = /usr/local/sbin/pm-vpn-egress-firewall add %i 10.8.0.0/20 10.8.0.1' \
        'PostDown = /usr/local/sbin/pm-vpn-egress-firewall remove %i 10.8.0.0/20 10.8.0.1' >>"$t"
    install -m 0755 "$src/vpn-egress-firewall.sh" /usr/local/sbin/pm-vpn-egress-firewall
    install -m 0600 "$t" "$dir/awg0.base.conf"
    ln "$t" "$conf"
fi
systemctl enable --now awg-quick@awg0.service
awg show awg0 listen-port
