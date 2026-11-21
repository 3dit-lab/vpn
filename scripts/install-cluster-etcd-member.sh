#!/usr/bin/env bash
# Install one member. Start all three units together after verifying peer routes.
set -euo pipefail

case "${1:-}" in
    fi-1) address=10.77.240.1 ;;
    fi-2) address=10.77.240.2 ;;
    ee-1) address=10.77.240.3 ;;
    *) echo "Usage: $0 fi-1|fi-2|ee-1" >&2; exit 1 ;;
esac
member=$1
unit_source=${2:?Pass the path to pm-vpn-etcd.service}
ip -4 -o addr show dev vpn-cluster | grep -Fq " $address/32 "
test -x /opt/pm-vpn-cluster/etcd-v3.6.17-linux-amd64/etcd
install -d -m 0755 /etc/pm-vpn-cluster
env_path=/etc/pm-vpn-cluster/etcd.env
if [[ ! -e "$env_path" ]]; then
    temporary=$(mktemp /etc/pm-vpn-cluster/.etcd.XXXXXX)
    trap 'rm -f -- "$temporary"' EXIT
    cat > "$temporary" <<ENV
ETCD_NAME=$member
ETCD_LISTEN_PEER_URLS=http://$address:2380
ETCD_INITIAL_ADVERTISE_PEER_URLS=http://$address:2380
ETCD_LISTEN_CLIENT_URLS=http://$address:2379
ETCD_ADVERTISE_CLIENT_URLS=http://$address:2379
ETCD_INITIAL_CLUSTER=fi-1=http://10.77.240.1:2380,fi-2=http://10.77.240.2:2380,ee-1=http://10.77.240.3:2380
ETCD_INITIAL_CLUSTER_STATE=new
ETCD_INITIAL_CLUSTER_TOKEN=pm-vpn-20261122
ENV
    ln "$temporary" "$env_path"
fi
install -m 0644 "$unit_source" /etc/systemd/system/pm-vpn-etcd.service
systemctl daemon-reload
systemctl enable pm-vpn-etcd.service
