#!/usr/bin/env bash
# Add the standard WireGuard pool to the existing authoritative VPN zone.
set -euo pipefail

src=$(cd "$(dirname "$0")" && pwd)
config=/etc/vpn-dnsd.json
program=/opt/vpn-dns/vpn-dnsd.py
test -s "$config"
test -s "$program"
d=$(mktemp -d)
cleanup() { rm -rf -- "$d"; }
trap cleanup EXIT
cp -p "$config" "$d/config"
cp -p "$program" "$d/program"
python3 - "$config" >"$d/next" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
assert data["zone"].rstrip(".") == "vpn.3dit.ru"
data["wireguard_servers"] = [
    {"name": n, "ip": ip, "port": 443}
    for n, ip in (("fi-1", "194.77.71.148"), ("fi-2", "91.211.114.164"), ("ee-1", "85.92.158.146"))
]
print(json.dumps(data, indent=2))
PY
python3 -m py_compile "$src/vpn-dnsd.py"
install -m 0644 "$src/vpn-dnsd.py" "$program"
install -m 0644 "$d/next" "$config"
if systemctl restart vpn-dnsd && python3 - "$config" <<'PY'
import json, socket, sys, time
from dnslib import DNSRecord, QTYPE
data = json.load(open(sys.argv[1]))
host, port = data["listen"], int(data.get("port", 53))
for attempt in range(10):
    try:
        for record in ("vpn.3dit.ru", "wg.vpn.3dit.ru"):
            q = DNSRecord.question(record, "A")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                sock.sendto(q.pack(), (host, port))
                reply = DNSRecord.parse(sock.recv(4096))
            ips = {str(r.rdata) for r in reply.rr if r.rtype == QTYPE.A}
            assert ips and reply.header.aa
            if record.startswith("wg."):
                assert ips == {"194.77.71.148", "91.211.114.164", "85.92.158.146"}
            print(record, sorted(ips))
        break
    except (OSError, AssertionError):
        if attempt == 9:
            raise
        time.sleep(1)
PY
then :; else
    cp -p "$d/config" "$config"
    cp -p "$d/program" "$program"
    systemctl restart vpn-dnsd
    exit 1
fi
