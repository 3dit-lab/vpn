#!/usr/bin/env python3
"""Основной сервер: обмен данными с резервным (запускается sshd как принудительная команда ключа резервного сервера).

В /root/.ssh/authorized_keys основного сервера:
  command="/opt/vpn-portal/replica-serve.py kz-1 pm-vpn.3dit.ru",restrict,from="5.180.40.128" ssh-ed25519 AAAA… vpn-replica
Ключ умеет только две вещи (SSH_ORIGINAL_COMMAND):
  export          отдать tar.gz: база портала (согласованный снимок), конфиги, peers.json, /etc/vpn-portal.env, сертификат домена
  import-traffic  принять счётчики трафика резервного сервера из stdin в traffic-<имя>.json (портал суммирует по серверам)
"""
import json
import os
import re
import shutil
import sqlite3
import sys
import tarfile
import tempfile
from pathlib import Path

DATA = Path(os.environ.get("PORTAL_DATA", "/var/lib/vpn-portal"))
LE = Path(os.environ.get("LE_DIR", "/etc/letsencrypt"))
ENV_FILE = Path(os.environ.get("PORTAL_ENV", "/etc/vpn-portal.env"))
MAX_TRAFFIC = 8 * 1024 * 1024


def snapshot_db(dst):
    src = sqlite3.connect(str(DATA / "portal.db"))
    out = sqlite3.connect(str(dst))
    with out:
        src.backup(out)
    out.close()
    src.close()


def export(domain):
    with tempfile.TemporaryDirectory() as tmp:
        snap = Path(tmp) / "portal.db"
        snapshot_db(snap)
        with tarfile.open(fileobj=sys.stdout.buffer, mode="w|gz") as tar:
            tar.add(snap, arcname="var/lib/vpn-portal/portal.db")
            for name in ("peers.json",):
                if (DATA / name).is_file():
                    tar.add(DATA / name, arcname=f"var/lib/vpn-portal/{name}")
            if (DATA / "configs").is_dir():
                tar.add(DATA / "configs", arcname="var/lib/vpn-portal/configs")
            if ENV_FILE.is_file():
                tar.add(ENV_FILE, arcname="etc/vpn-portal.env")
            for sub in ("live", "archive"):
                d = LE / sub / domain
                if d.is_dir():
                    tar.add(d, arcname=f"etc/letsencrypt/{sub}/{domain}")


def import_traffic(peer):
    raw = sys.stdin.buffer.read(MAX_TRAFFIC + 1)
    if len(raw) > MAX_TRAFFIC:
        sys.exit("слишком большой файл")
    data = json.loads(raw)
    if data.get("version") != 1 or not isinstance(data.get("peers"), dict):
        sys.exit("неизвестный формат")
    dst = DATA / f"traffic-{peer}.json"
    fd, tmp = tempfile.mkstemp(dir=DATA, prefix=".traffic-in.")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.chmod(tmp, 0o640)
    try:
        shutil.chown(tmp, group="vpnportal")
    except (LookupError, PermissionError):
        pass
    os.replace(tmp, dst)


def main():
    if len(sys.argv) < 3 or not re.fullmatch(r"[a-z0-9-]{1,20}", sys.argv[1]) or not re.fullmatch(r"[A-Za-z0-9.-]{3,100}", sys.argv[2]):
        sys.exit("usage: replica-serve.py <peer-name> <domain>")
    cmd = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()
    if cmd == "export":
        export(sys.argv[2])
    elif cmd == "import-traffic":
        import_traffic(sys.argv[1])
    else:
        sys.exit("команда не разрешена")


if __name__ == "__main__":
    main()
