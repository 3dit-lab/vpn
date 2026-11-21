#!/usr/bin/env bash
# Prepare a persistent node key for the private PM-VPN cluster network.
set -euo pipefail

[[ $(id -u) == 0 ]] || { echo "Run as root" >&2; exit 1; }
key=/etc/wireguard/vpn-cluster.key
umask 077
install -d -m 0700 /etc/wireguard
if [[ ! -s "$key" ]]; then
    temporary=$(mktemp /etc/wireguard/.vpn-cluster.key.XXXXXX)
    trap 'rm -f -- "$temporary"' EXIT
    wg genkey > "$temporary"
    # Preserve the first key if two deployments start at the same time.
    ln "$temporary" "$key" || [[ -s "$key" ]]
fi
wg pubkey < "$key"
