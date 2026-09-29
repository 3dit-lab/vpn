#!/usr/bin/env python3
"""Синхронизация пиров AmneziaWG с порталом (запуск от root службой vpn-peer-sync).

Портал пишет /var/lib/vpn-portal/peers.json: кому сейчас разрешено подключаться (выданные конфиги включённых
организаций). Скрипт собирает awg0.conf = базовая часть [Interface] + разрешённые пиры и применяет без разрыва
соединений (awg syncconf). Если peers.json нет или он некорректен, ничего не меняется.
"""
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PEERS = Path(os.environ.get("SYNC_PEERS", "/var/lib/vpn-portal/peers.json"))
CONF_DIR = Path(os.environ.get("SYNC_CONF_DIR", "/etc/amnezia/amneziawg"))
IFACE = os.environ.get("SYNC_IFACE", "awg0")
AWG = os.environ.get("AWG_BIN", "awg")
AWG_QUICK = os.environ.get("AWG_QUICK_BIN", "awg-quick")
KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
IP_RE = re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def log(msg):
    print(f"vpn-peer-sync: {msg}", flush=True)


def valid_key(k):
    if not isinstance(k, str) or not KEY_RE.match(k):
        return False
    try:
        return len(base64.b64decode(k, validate=True)) == 32
    except Exception:
        return False


def load_peers():
    data = json.loads(PEERS.read_text())
    if data.get("version") != 1 or not isinstance(data.get("peers"), list):
        raise ValueError("неизвестный формат peers.json")
    out, seen_ip, seen_key = [], set(), set()
    for p in data["peers"]:
        slot, pub, psk, ip = p.get("slot"), p.get("public"), p.get("psk"), p.get("ip")
        if not (isinstance(slot, int) and 1 <= slot <= 100000 and valid_key(pub) and valid_key(psk)
                and isinstance(ip, str) and IP_RE.match(ip) and all(0 <= int(o) <= 255 for o in ip.split("."))):
            raise ValueError(f"некорректный пир в peers.json: слот {slot!r}")
        if ip in seen_ip or pub in seen_key:
            raise ValueError(f"повтор адреса или ключа в peers.json: слот {slot}")
        seen_ip.add(ip)
        seen_key.add(pub)
        out.append((slot, pub, psk, ip))
    return sorted(out)


def base_config():
    """Часть [Interface] без пиров. Создаётся один раз из исходного awg0.conf и дальше не меняется."""
    base, conf = CONF_DIR / f"{IFACE}.base.conf", CONF_DIR / f"{IFACE}.conf"
    if not base.exists():
        text = conf.read_text()
        m = re.search(r"(?m)^(#\s*client\d+\s*$|\[Peer\])", text)
        head = text[:m.start()] if m else text
        if "[Interface]" not in head or "PrivateKey" not in head:
            raise ValueError(f"в {conf} нет корректной секции [Interface]")
        write_atomic(base, head.rstrip() + "\n")
        log(f"создан {base}")
    return base.read_text().rstrip() + "\n"


def write_atomic(path, text):
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def compose(base, peers):
    parts = [base]
    for slot, pub, psk, ip in peers:
        parts.append(f"\n# client{slot:03d}\n[Peer]\nPublicKey = {pub}\nPresharedKey = {psk}\nAllowedIPs = {ip}/32\n")
    return "".join(parts)


def apply_live():
    if subprocess.run([AWG, "show", IFACE], capture_output=True).returncode != 0:
        log(f"интерфейс {IFACE} не запущен, изменения применятся при его запуске")
        return
    strip = subprocess.run([AWG_QUICK, "strip", IFACE], capture_output=True, text=True)
    if strip.returncode != 0:
        raise RuntimeError("awg-quick strip: " + strip.stderr.strip())
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as tf:
        tf.write(strip.stdout)
    try:
        r = subprocess.run([AWG, "syncconf", IFACE, tf.name], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("awg syncconf: " + r.stderr.strip())
    finally:
        os.unlink(tf.name)


def main():
    if not PEERS.exists():
        log("peers.json нет, изменений нет")
        return 0
    try:
        peers = load_peers()
        base = base_config()
    except (ValueError, OSError) as e:
        log(f"ОШИБКА, конфигурация не изменена: {e}")
        return 1
    conf = CONF_DIR / f"{IFACE}.conf"
    new = compose(base, peers)
    if conf.exists() and conf.read_text() == new:
        return 0
    write_atomic(conf, new)
    log(f"записан {conf}: пиров {len(peers)}")
    try:
        apply_live()
    except (RuntimeError, OSError) as e:
        log(f"ОШИБКА применения: {e}")
        return 1
    log("применено")
    return 0


if __name__ == "__main__":
    sys.exit(main())
