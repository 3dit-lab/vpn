#!/usr/bin/env python3
"""Резервный сервер: забирает данные с основного (раз в минуту, службой vpn-replica) и отдаёт ему свой трафик.

Конфиг /etc/vpn-replica.json: {"primary": "fi-1-vpn.3dit.ru", "key": "/root/.ssh/vpn-replica", "peer": "kz-1"}
Если на резервном сервере в базе есть выдачи, которых нет на основном (работали при отказе основного),
база и конфиги НЕ перезаписываются: создаётся /var/lib/vpn-portal/DIVERGED, расхождение разбирается вручную.
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CFG = json.load(open(os.environ.get("REPLICA_CONF", "/etc/vpn-replica.json")))
DATA = Path(os.environ.get("PORTAL_DATA", "/var/lib/vpn-portal"))
PRIMARY, KEY = CFG["primary"], CFG["key"]
SSH = (os.environ.get("REPLICA_SSH", "").split() or ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
       "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", f"root@{PRIMARY}"])


def log(m):
    print(f"vpn-replica: {m}", flush=True)


def rows(db):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return (set(con.execute("SELECT slot, person_id, assigned_at FROM assignments")),
                set(con.execute("SELECT id, org_id, phone FROM people")))
    finally:
        con.close()


def rsync(src, dst, delete=False):
    cmd = ["rsync", "-a", "--checksum"] + (["--delete"] if delete else []) + [str(src).rstrip("/") + "/", str(dst).rstrip("/") + "/"]
    subprocess.run(cmd, check=True)


def own(path, user="vpnportal"):
    try:
        shutil.chown(path, user, user)
    except (LookupError, PermissionError):
        pass


def chown_tree(path):
    own(path)
    for p in Path(path).rglob("*"):
        own(p)


def pull():
    stage = DATA / ".stage"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(mode=0o700)
    tarf = stage / "export.tgz"
    with open(tarf, "wb") as f:
        r = subprocess.run(SSH + ["export"], stdout=f, stderr=subprocess.PIPE, timeout=180)
    if r.returncode != 0 or tarf.stat().st_size == 0:
        log(f"основной сервер недоступен или отказал: {r.stderr.decode(errors='replace').strip()[:200]}")
        shutil.rmtree(stage, ignore_errors=True)
        return 1
    subprocess.run(["tar", "-xzf", str(tarf), "-C", str(stage)], check=True)
    tarf.unlink()
    new_db = stage / "var/lib/vpn-portal/portal.db"
    live_db = DATA / "portal.db"
    changed_peers = False
    diverged = False
    if live_db.exists():
        try:
            la, lp = rows(live_db)
            ra, rp = rows(new_db)
            if (la - ra) or (lp - rp):
                diverged = True
                (DATA / "DIVERGED").write_text(
                    f"{time.strftime('%F %T')}: на резервном сервере есть данные, которых нет на основном "
                    f"(выдачи: {sorted(la - ra)[:10]}). Данные не перезаписаны. Разберите вручную и удалите этот файл.\n")
                log("РАСХОЖДЕНИЕ: база и конфиги не обновлены, см. /var/lib/vpn-portal/DIVERGED")
        except sqlite3.Error as e:
            log(f"локальная база не читается ({e}), заменяю данными основного сервера")
    if not diverged:
        (DATA / "DIVERGED").unlink(missing_ok=True)
        rsync(stage / "var/lib/vpn-portal/configs", DATA / "configs", delete=True)
        shutil.copy2(new_db, DATA / ".portal.db.new")
        own(DATA / ".portal.db.new")
        os.replace(DATA / ".portal.db.new", live_db)
        newp = stage / "var/lib/vpn-portal/peers.json"
        if newp.exists():
            old = (DATA / "peers.json").read_bytes() if (DATA / "peers.json").exists() else b""
            if old != newp.read_bytes():
                shutil.copy2(newp, DATA / ".peers.new")
                own(DATA / ".peers.new")
                os.replace(DATA / ".peers.new", DATA / "peers.json")
                changed_peers = True
        chown_tree(DATA / "configs")
    envnew = stage / "etc/vpn-portal.env"
    if envnew.exists():
        envp = Path(os.environ.get("PORTAL_ENV", "/etc/vpn-portal.env"))
        if not envp.exists() or envp.read_bytes() != envnew.read_bytes():
            tmpenv = str(envp) + ".new"
            shutil.copy2(envnew, tmpenv)
            os.chmod(tmpenv, 0o600)
            os.replace(tmpenv, envp)
            subprocess.run(["systemctl", "restart", "vpn-portal"], check=False)
    xs = stage / "etc/vpn-xray.json"
    if xs.exists():
        xp = Path(os.environ.get("XRAY_STATE", "/etc/vpn-xray.json"))
        if not xp.exists() or xp.read_bytes() != xs.read_bytes():
            shutil.copy2(xs, str(xp) + ".new")
            os.chmod(str(xp) + ".new", 0o640)
            try:
                shutil.chown(str(xp) + ".new", group="vpnportal")
            except (LookupError, PermissionError):
                pass
            os.replace(str(xp) + ".new", xp)
            subprocess.run(["systemctl", "start", "vpn-xray-sync.service"], check=False)
            log("параметры Xray обновлены")
    certs = stage / "etc/letsencrypt"
    if certs.is_dir():
        before = subprocess.run(["bash", "-c", "find /etc/letsencrypt/archive -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum"],
                                capture_output=True, text=True).stdout
        for sub in ("archive", "live"):
            if (certs / sub).is_dir():
                Path(f"/etc/letsencrypt/{sub}").mkdir(parents=True, exist_ok=True)
                subprocess.run(["rsync", "-a", str(certs / sub) + "/", f"/etc/letsencrypt/{sub}/"], check=True)
        after = subprocess.run(["bash", "-c", "find /etc/letsencrypt/archive -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum"],
                               capture_output=True, text=True).stdout
        if before != after and subprocess.run(["nginx", "-t"], capture_output=True).returncode == 0:
            subprocess.run(["systemctl", "reload", "nginx"], check=False)
            log("сертификат обновлён")
    shutil.rmtree(stage, ignore_errors=True)
    if changed_peers:
        subprocess.run(["systemctl", "start", "vpn-peer-sync.service"], check=False)
        log("peers.json изменился, пиры применены")
    (DATA / ".last-pull").write_text(str(int(time.time())))
    return 0


def push_traffic():
    for name, cmd in (("traffic.json", "import-traffic"), ("traffic-xray-local.json", "import-traffic-xray")):
        t = DATA / name
        if not t.exists():
            continue
        with open(t, "rb") as f:
            r = subprocess.run(SSH + [cmd], stdin=f, stderr=subprocess.PIPE, timeout=60)
        if r.returncode != 0:
            log(f"трафик ({name}) не отправлен: {r.stderr.decode(errors='replace').strip()[:200]}")


def main():
    rc = pull()
    if rc == 0:
        push_traffic()
    return rc


if __name__ == "__main__":
    sys.exit(main())
