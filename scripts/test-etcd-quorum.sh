#!/usr/bin/env bash
# Exercise Raft leadership on three disposable loopback members.
set -euo pipefail

bin="${1:-/opt/pm-vpn-cluster/etcd-v3.6.17-linux-amd64}"
dir=$(mktemp -d)
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait || true
    rm -rf -- "$dir"
}
trap cleanup EXIT

clients=(http://127.0.0.1:12379 http://127.0.0.1:12381 http://127.0.0.1:12383)
peers=(http://127.0.0.1:12380 http://127.0.0.1:12382 http://127.0.0.1:12384)
cluster="n0=${peers[0]},n1=${peers[1]},n2=${peers[2]}"
all=$(IFS=,; echo "${clients[*]}")
ctl() {
    "$bin/etcdctl" --dial-timeout=1s --command-timeout=3s --endpoints="$1" "${@:2}"
}
for i in 0 1 2; do
    "$bin/etcd" --name="n$i" --data-dir="$dir/n$i" \
        --listen-client-urls="${clients[i]}" --advertise-client-urls="${clients[i]}" \
        --listen-peer-urls="${peers[i]}" --initial-advertise-peer-urls="${peers[i]}" \
        --initial-cluster="$cluster" --initial-cluster-token="pm-vpn-test-${dir##*/}" \
        --log-level=error >"$dir/n$i.log" 2>&1 &
    pids+=("$!")
done

for attempt in {1..10}; do
    if ctl "$all" endpoint health >/dev/null 2>&1; then break; fi
    if (( attempt == 10 )); then cat "$dir"/n*.log >&2; exit 1; fi
    sleep 1
done
ctl "$all" put /smoke before
leader_endpoint=$(ctl "$all" endpoint status -w json | python3 -c '
import json, sys
print(next(r["Endpoint"] for r in json.load(sys.stdin)
           if r["Status"]["header"]["member_id"] == r["Status"]["leader"]))')
remaining=()
for i in 0 1 2; do
    if [[ "${clients[i]}" == "$leader_endpoint" ]]; then
        kill "${pids[i]}"
        wait "${pids[i]}" || true
    else
        remaining+=("$i")
    fi
done
endpoints="${clients[remaining[0]]},${clients[remaining[1]]}"
for attempt in {1..10}; do
    if ctl "$endpoints" endpoint health >/dev/null 2>&1; then break; fi
    if (( attempt == 10 )); then cat "$dir"/n*.log >&2; exit 1; fi
    sleep 1
done
[[ $(ctl "$endpoints" get /smoke --print-value-only) == before ]]
ctl "$endpoints" put /smoke after
[[ $(ctl "${clients[remaining[1]]}" get /smoke --print-value-only) == after ]]
echo "PASS: surviving voters retain the old write and commit a new write after leader loss"

kill "${pids[remaining[0]]}"
wait "${pids[remaining[0]]}" || true
if ctl "${clients[remaining[1]]}" put /smoke no-quorum; then
    echo "Unexpected write without a majority" >&2
    exit 1
fi
echo "PASS: one remaining voter rejects writes"
