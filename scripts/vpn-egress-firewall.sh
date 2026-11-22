#!/usr/bin/env bash
# Restrict forwarded traffic from a dedicated VPN interface to public egress.
set -euo pipefail

mode=${1:?}
iface=${2:?}
network=${3:?}
gateway=${4:?}
case "$iface:$network:$gateway" in
    wg-portal:10.19.0.0/20:10.19.0.1|awg0:10.8.0.0/20:10.8.0.1|wg-mt:10.9.3.0/24:10.9.3.1)
        ;;
    *) exit 2 ;;
esac
out=$(ip -4 route show default | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')
[[ -n "$out" && "$out" != "$iface" ]]
fwd="PM-FWD-$iface"
in="PM-IN-$iface"
ipt() { iptables -w 5 "$@"; }

remove() {
    ipt -D INPUT -i "$iface" -j "$in" 2>/dev/null || true
    ipt -D FORWARD -i "$iface" -j "$fwd" 2>/dev/null || true
    ipt -D FORWARD -o "$iface" -j "$fwd" 2>/dev/null || true
    ipt -t nat -D POSTROUTING -s "$network" -o "$out" -j MASQUERADE 2>/dev/null || true
    for chain in "$in" "$fwd"; do
        ipt -F "$chain" 2>/dev/null || true
        ipt -X "$chain" 2>/dev/null || true
    done
}

case "$mode" in
    add)
        remove
        trap remove ERR
        ipt -N "$in"
        ipt -A "$in" -s "$network" -d "$gateway" -p icmp --icmp-type echo-request -j ACCEPT
        if [ "$iface" = awg0 ]; then
            ipt -A "$in" -s "$network" -d "$gateway" -p udp --dport 53 -j ACCEPT
            ipt -A "$in" -s "$network" -d "$gateway" -p tcp --dport 53 -j ACCEPT
        fi
        ipt -A "$in" -j DROP
        ipt -N "$fwd"
        for private in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/3; do
            ipt -A "$fwd" -i "$iface" -d "$private" -j DROP
        done
        ipt -A "$fwd" -i "$iface" -o "$out" -s "$network" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
        ipt -A "$fwd" -i "$out" -o "$iface" -d "$network" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        ipt -A "$fwd" -j DROP
        ipt -I INPUT 1 -i "$iface" -j "$in"
        ipt -I FORWARD 1 -i "$iface" -j "$fwd"
        ipt -I FORWARD 1 -o "$iface" -j "$fwd"
        ipt -t nat -A POSTROUTING -s "$network" -o "$out" -j MASQUERADE
        if [[ $(sysctl -n net.ipv4.ip_forward) = 0 ]]; then
            # This host previously forwarded no traffic. Preserve that default for other paths.
            ipt -P FORWARD DROP
            sysctl -qw net.ipv4.ip_forward=1
        fi
        ;;
    remove) remove ;;
    *) exit 2 ;;
esac
