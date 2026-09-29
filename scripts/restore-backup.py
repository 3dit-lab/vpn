#!/usr/bin/env python3
"""Восстановление состояния портала из резервной копии (.vpnbak) на новом сервере. Запуск от root ПОСЛЕ setup-web.sh.

    sudo python3 scripts/restore-backup.py vpn-backup-20260929-1200.vpnbak [--yes]

Парольная фраза запрашивается интерактивно (или переменная VPNBAK_PASSPHRASE). Копия ЗАМЕНЯЕТ организации, людей,
выдачи и журнал, а также файлы конфигов клиентов. После восстановления портал пересоберёт peers.json, а
служба vpn-peer-sync применит список пиров к AmneziaWG.
"""
import argparse
import getpass
import importlib
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_env(path):
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--yes", action="store_true", help="не спрашивать подтверждение")
    ap.add_argument("--env", default="/etc/vpn-portal.env")
    ap.add_argument("--data", default="/var/lib/vpn-portal")
    ap.add_argument("--portal-dir", default=None, help="каталог с portal.py и backup.py (по умолчанию /opt/vpn-portal или ../portal)")
    ap.add_argument("--no-systemctl", action="store_true")
    a = ap.parse_args()

    if os.geteuid() != 0 and not a.no_systemctl:
        sys.exit("Запустите от root")
    pdir = Path(a.portal_dir) if a.portal_dir else next(
        (d for d in (Path("/opt/vpn-portal"), HERE.parent / "portal") if (d / "portal.py").exists()), None)
    if not pdir or not (pdir / "backup.py").exists():
        sys.exit("Не найдены portal.py/backup.py (сначала выполните setup-web.sh)")
    sys.path.insert(0, str(pdir))
    import backup

    blob = Path(a.file).read_bytes()
    phrase = os.environ.get("VPNBAK_PASSPHRASE") or getpass.getpass("Парольная фраза копии: ")
    try:
        manifest, state, confs = backup.read_backup(backup.decrypt(blob, phrase))
    except ValueError as e:
        sys.exit(f"Ошибка: {e}")
    n = manifest["counts"]
    print(f"Копия: организаций {n['orgs']}, людей {n['people']}, выдано {n['assignments']}, конфигов {n['configs']}")
    if not a.yes and input("Заменить текущее состояние портала этой копией? [yes/N] ").strip().lower() != "yes":
        sys.exit("Отменено")

    if Path(a.env).exists():
        load_env(a.env)
    os.environ.update(PORTAL_DATA=a.data, PORTAL_CONFIGS=f"{a.data}/configs", PORTAL_PEERS=f"{a.data}/peers.json")
    os.environ.setdefault("PORTAL_LOG_DIR", "/var/log/vpn-portal")
    os.environ.setdefault("PORTAL_SECRET_KEY", "restore-only")
    if not a.no_systemctl:
        subprocess.run(["systemctl", "stop", "vpn-portal"], check=False)
    try:
        portal = importlib.import_module("portal")
        with portal.app.app_context():
            c = portal.db()
            backup.restore_state(c, portal.CONF_DIR, state, confs)
            portal.write_peers(c)
        try:
            import pwd
            u = pwd.getpwnam("vpnportal")
            for root, dirs, files in os.walk(a.data):
                for nme in dirs + files:
                    os.chown(os.path.join(root, nme), u.pw_uid, u.pw_gid)
            os.chown(a.data, u.pw_uid, u.pw_gid)
        except KeyError:
            pass
    finally:
        if not a.no_systemctl:
            subprocess.run(["systemctl", "start", "vpn-portal"], check=False)
    print("Готово. Пиры применит vpn-peer-sync (или сразу: systemctl start vpn-peer-sync).")
    print("Проверьте вход в /super и /org, затем переключите DNS на этот сервер.")


if __name__ == "__main__":
    main()
