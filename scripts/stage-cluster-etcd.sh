#!/usr/bin/env bash
# Stage the same etcd release on each node without starting a service.
set -euo pipefail

[[ $(id -u) == 0 ]] || { echo "Run as root" >&2; exit 1; }
[[ $(uname -sm) == 'Linux x86_64' ]] || { echo "Requires Linux x86_64" >&2; exit 1; }
version=v3.6.17
release="etcd-${version}-linux-amd64"
digest=5c6365e03d0c81f605458f3f9a115f6daaebca08d1fb42d3ab0f1a38fd30909c
base=/opt/pm-vpn-cluster
target="$base/$release"
install -d -m 0755 "$base"
if [[ ! -d "$target" ]]; then
    tmp=$(mktemp -d "$base/.etcd.XXXXXX")
    trap 'rm -rf -- "$tmp"' EXIT
    curl -fsSL --retry 2 --connect-timeout 10 --max-time 120 \
        "https://github.com/etcd-io/etcd/releases/download/$version/$release.tar.gz" \
        -o "$tmp/release.tar.gz"
    printf '%s  %s\n' "$digest" "$tmp/release.tar.gz" | sha256sum -c -
    mkdir "$tmp/bin"
    tar -xzf "$tmp/release.tar.gz" -C "$tmp/bin" --strip-components=1 \
        "$release/etcd" "$release/etcdctl" "$release/etcdutl"
    chmod 0755 "$tmp/bin"
    mv -T -- "$tmp/bin" "$target"
fi
"$target/etcd" --version
"$target/etcdctl" version
