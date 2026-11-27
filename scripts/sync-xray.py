#!/usr/bin/env python3
"""Конфиг Xray (VLESS+Reality) из peers.json портала (запуск от root службой vpn-xray-sync раз в минуту).

Клиенты = включённые слоты из peers.json. UUID зависит от соли в /etc/vpn-xray.json и текущего ключа устройства.
При перевыдаче слота меняется и UUID. Xray перезапускается только когда набор клиентов или параметры
изменились. Если peers.json или /etc/vpn-xray.json нет/некорректны, ничего не меняется.
"""
import json
import grp
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

PEERS = Path(os.environ.get("SYNC_PEERS", "/var/lib/vpn-portal/peers.json"))
STATE = Path(os.environ.get("XRAY_STATE", "/etc/vpn-xray.json"))
OUT = Path(os.environ.get("XRAY_CONFIG", "/usr/local/etc/xray/config.json"))
API_PORT = 10085


def slot_uuid(salt, slot, public):
    return str(uuid.uuid5(uuid.UUID(salt), f"slot{slot:03d}:{public}"))


def build(state, peers):
    clients = [
        {"id": slot_uuid(state["salt"], slot, public), "flow": "xtls-rprx-vision", "email": f"client{slot:03d}"}
        for slot, public in sorted(peers.items())
    ]
    return {
        "log": {"loglevel": "warning"},
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": [
            {"tag": "api", "listen": "127.0.0.1", "port": API_PORT, "protocol": "dokodemo-door",
             "settings": {"address": "127.0.0.1"}},
            {"tag": "vless", "listen": "0.0.0.0", "port": int(state["port"]), "protocol": "vless",
             "settings": {"clients": clients, "decryption": "none"},
             "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                 "show": False, "dest": f'{state["sni"]}:443', "xver": 0,
                 "serverNames": [state["sni"]], "privateKey": state["private"], "shortIds": [state["short_id"]]}},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "IPOnDemand", "rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
        ]},
    }


def main():
    try:
        state = json.loads(STATE.read_text())
        for k in ("private", "public", "short_id", "sni", "port", "salt"):
            if k not in state:
                raise ValueError(k)
        uuid.UUID(state["salt"])
        data = json.loads(PEERS.read_text())
        if data.get("version") != 1 or not isinstance(data.get("peers"), list):
            raise ValueError("peers.json")
        peers = {int(p["slot"]): p["public"] for p in data["peers"]}
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"vpn-xray-sync: нет данных ({e}), без изменений", file=sys.stderr)
        return 0
    text = json.dumps(build(state, peers), indent=1, ensure_ascii=False) + "\n"
    if OUT.exists() and OUT.read_text() == text:
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    dry_restart = bool(os.environ.get("XRAY_NO_RESTART"))
    fd, name = tempfile.mkstemp(dir=OUT.parent, prefix=".config.", suffix=".json")
    tmp = Path(name)
    previous = tmp.with_suffix(".previous")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            os.fchmod(f.fileno(), 0o640)
            if not dry_restart:
                os.fchown(f.fileno(), -1, grp.getgrnam("xray").gr_gid)
        if not dry_restart:
            subprocess.run(["/usr/local/bin/xray", "run", "-test", "-c", str(tmp)], check=True)
        if OUT.exists():
            os.link(OUT, previous)
        os.replace(tmp, OUT)
        if not dry_restart and subprocess.run(["systemctl", "restart", "xray"]).returncode:
            if previous.exists():
                os.replace(previous, OUT)
                subprocess.run(["systemctl", "restart", "xray"], check=True)
            else:
                OUT.unlink()
            return 1
    finally:
        tmp.unlink(missing_ok=True)
        previous.unlink(missing_ok=True)
    print(f"vpn-xray-sync: применено клиентов: {len(peers)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
