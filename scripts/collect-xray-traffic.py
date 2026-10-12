#!/usr/bin/env python3
"""Учёт трафика Xray по слотам (root, раз в минуту). Пишет /var/lib/vpn-portal/traffic-xray-local.json в том же формате,
что traffic.json, с ключами "xray:NNN" (rx = от клиента, tx = клиенту). Счётчики Xray обнуляются при его перезапуске."""
import grp
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

OUT = Path(os.environ.get("XRAY_TRAFFIC_FILE", "/var/lib/vpn-portal/traffic-xray-local.json"))
XRAY = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
SERVER = os.environ.get("XRAY_API", "127.0.0.1:10085")
GROUP = os.environ.get("TRAFFIC_GROUP", "vpnportal")
NAME_RE = re.compile(r"^user>>>client(\d+)>>>traffic>>>(uplink|downlink)$")


def read_counters():
    r = subprocess.run([XRAY, "api", "statsquery", f"-server={SERVER}", "-pattern", "user>>>"],
                       capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "xray api failed")
    out = {}
    for st in json.loads(r.stdout or "{}").get("stat", []):
        m = NAME_RE.match(st.get("name", ""))
        if m:
            rx, tx = out.get(f"xray:{int(m.group(1)):03d}", (0, 0))
            v = int(st.get("value", 0) or 0)
            out[f"xray:{int(m.group(1)):03d}"] = (rx + v, tx) if m.group(2) == "uplink" else (rx, tx + v)
    return out


def main():
    try:
        cur = read_counters()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as e:
        print(f"vpn-xray-traffic: {e}", file=sys.stderr)
        return 1
    try:
        peers = json.loads(OUT.read_text())["peers"]
    except (OSError, ValueError, KeyError, TypeError):
        peers = {}
    changed = False
    for key, (rx, tx) in cur.items():
        e = peers.setdefault(key, {"rx": 0, "tx": 0, "lrx": 0, "ltx": 0})
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
    fd, tmp = tempfile.mkstemp(dir=OUT.parent, prefix=".traffic-x.")
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
