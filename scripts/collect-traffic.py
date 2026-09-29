#!/usr/bin/env python3
"""Учёт трафика по пирам AmneziaWG (запуск от root службой vpn-traffic раз в минуту).

Читает счётчики `awg show awg0 transfer` и копит нарастающий итог по публичному ключу в
/var/lib/vpn-portal/traffic.json (портал только читает). Счётчики ядра обнуляются при перезапуске интерфейса и при
повторном добавлении пира: если новое значение меньше предыдущего, считаем, что счётчик начался заново.
Ограничение: трафик между двумя опросами при перезапуске интерфейса может не учесться (не более минуты).
"""
import grp
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

OUT = Path(os.environ.get("TRAFFIC_FILE", "/var/lib/vpn-portal/traffic.json"))
IFACE = os.environ.get("SYNC_IFACE", "awg0")
AWG = os.environ.get("AWG_BIN", "awg")
GROUP = os.environ.get("TRAFFIC_GROUP", "vpnportal")


def read_counters():
    r = subprocess.run([AWG, "show", IFACE, "transfer"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "awg show failed")
    out = {}
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
            out[parts[0]] = (int(parts[1]), int(parts[2]))
    return out


def main():
    try:
        cur = read_counters()
    except (RuntimeError, OSError) as e:
        print(f"vpn-traffic: {e}", file=sys.stderr)
        return 1
    try:
        data = json.loads(OUT.read_text())
        peers = data["peers"] if data.get("version") == 1 else {}
    except (OSError, ValueError, KeyError, AttributeError):
        peers = {}
    changed = False
    for pub, (rx, tx) in cur.items():
        e = peers.setdefault(pub, {"rx": 0, "tx": 0, "lrx": 0, "ltx": 0})
        d_rx = rx - e["lrx"] if rx >= e["lrx"] else rx
        d_tx = tx - e["ltx"] if tx >= e["ltx"] else tx
        if d_rx or d_tx or (rx, tx) != (e["lrx"], e["ltx"]):
            e["rx"] += d_rx
            e["tx"] += d_tx
            e["lrx"], e["ltx"] = rx, tx
            changed = True
    if not changed and OUT.exists():
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=OUT.parent, prefix=".traffic.")
    with os.fdopen(fd, "w") as f:
        json.dump({"version": 1, "peers": peers}, f)
    os.chmod(tmp, 0o640)
    try:
        os.chown(tmp, 0, grp.getgrnam(GROUP).gr_gid)
    except (KeyError, PermissionError):
        pass
    os.replace(tmp, OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
