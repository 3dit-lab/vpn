#!/usr/bin/env python3
"""Конфиг Xray (VLESS+Reality) из peers.json портала (запуск от root службой vpn-xray-sync раз в минуту).

Клиенты = включённые слоты из peers.json; UUID слота выводится из соли в /etc/vpn-xray.json (uuid5), поэтому на всех
серверах он одинаков, а выдать ссылку может любой. Xray перезапускается только когда набор клиентов или параметры
изменились. Если peers.json или /etc/vpn-xray.json нет/некорректны, ничего не меняется.
"""
import json
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


def slot_uuid(salt, slot):
    return str(uuid.uuid5(uuid.UUID(salt), f"slot{slot:03d}"))


def build(state, slots):
    clients = [{"id": slot_uuid(state["salt"], s), "flow": "xtls-rprx-vision", "email": f"client{s:03d}"} for s in sorted(slots)]
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
        "routing": {"rules": [
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
        slots = {int(p["slot"]) for p in data["peers"]}
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"vpn-xray-sync: нет данных ({e}), без изменений", file=sys.stderr)
        return 0
    text = json.dumps(build(state, slots), indent=1, ensure_ascii=False) + "\n"
    if OUT.exists() and OUT.read_text() == text:
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=OUT.parent, prefix=".config.")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o640)
    os.replace(tmp, OUT)
    if os.environ.get("XRAY_NO_RESTART"):
        return 0
    subprocess.run(["systemctl", "restart", "xray"], check=False)
    print(f"vpn-xray-sync: применено клиентов: {len(slots)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
