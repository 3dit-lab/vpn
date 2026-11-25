#!/usr/bin/env bash
# Mirror the original WireGuard bootstrap installer without modifying it.
set -euo pipefail

apps_dir="${1:-/var/www/vpn/apps}"
dest="$apps_dir/wireguard"
installer=wireguard-installer.exe
source="https://download.wireguard.com/windows-client/$installer"
mkdir -p "$dest"
work="$(mktemp -d "$dest/.download.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

curl --fail --silent --show-error --location --retry 3 --connect-timeout 10 --max-time 60 \
    --proto '=https' --proto-redir '=https' --output "$work/$installer" "$source"
if [[ "$(head -c 2 "$work/$installer")" != MZ ]]; then
    echo "WireGuard: the download is not a Windows executable" >&2
    exit 1
fi

(cd "$work" && sha256sum -- "$installer" > SHA256SUMS)
chmod 0644 "$work/$installer" "$work/SHA256SUMS"
mv -f -- "$work/$installer" "$work/SHA256SUMS" "$dest/"
