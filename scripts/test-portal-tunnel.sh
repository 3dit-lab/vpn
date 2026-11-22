#!/usr/bin/env bash
# Verify one endpoint using an already authorized disposable peer.
set -euo pipefail

mode=${1:?Pass wg or awg}
endpoint=${2:?Pass expected public IPv4}
key=${3:?Pass the disposable private key path}
case "$mode" in
    wg)
        bin=wg
        type=wireguard
        port=51822
        client=10.19.15.254
        gateway=10.19.0.1
        server=wg-portal
        ;;
    awg)
        bin=awg
        type=amneziawg
        port=51820
        client=10.8.15.254
        gateway=10.8.0.1
        server=awg0
        ;;
    *) exit 2 ;;
esac
umask 077
dir=$(mktemp -d)
ns=pmvpn-test-${dir##*.}
iface=pmtest${dir: -6}
cleanup() {
    ip -n "$ns" link delete "$iface" 2>/dev/null || true
    ip link delete "$iface" 2>/dev/null || true
    ip netns delete "$ns" 2>/dev/null || true
    rm -rf -- "$dir"
}
trap cleanup EXIT
ip netns add "$ns"
ip link add "$iface" type "$type"
ip link set "$iface" netns "$ns"
printf '[Interface]\nPrivateKey = %s\n' "$(cat "$key")" >"$dir/test.conf"
if [[ "$mode" = awg ]]; then
    awk '/^(Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5])[ \t]*=/' /etc/amnezia/amneziawg/awg0.base.conf >>"$dir/test.conf"
fi
cat >>"$dir/test.conf" <<CONF
[Peer]
PublicKey = $("$bin" show "$server" public-key)
Endpoint = $endpoint:$port
AllowedIPs = $gateway/32, 1.1.1.1/32
PersistentKeepalive = 10
CONF
ip netns exec "$ns" "$bin" setconf "$iface" "$dir/test.conf"
ip -n "$ns" addr add "$client/32" dev "$iface"
ip -n "$ns" link set "$iface" mtu 1380 up
ip -n "$ns" route add "$gateway/32" dev "$iface"
ip -n "$ns" route add 1.1.1.1/32 dev "$iface"
ip netns exec "$ns" ping -c 3 -W 2 "$gateway" | tail -3
actual=$(ip netns exec "$ns" curl --noproxy '*' -fsS --max-time 12 https://1.1.1.1/cdn-cgi/trace | sed -n 's/^ip=//p')
test "$actual" = "$endpoint"
printf 'PASS %s handshake and public egress %s\n' "$mode" "$actual"
