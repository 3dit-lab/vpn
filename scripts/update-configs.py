#!/usr/bin/env python3
"""Меняет в уже выданных конфигах Endpoint, DNS и список подсетей (AllowedIPs), ключи и PSK не трогает.

Нужен при переходе на имя vpn.3dit.ru и DNS внутри туннеля. Идемпотентен.
Старые конфиги на устройствах продолжают работать (pm-vpn.3dit.ru).

    sudo python3 scripts/update-configs.py --dir /var/lib/vpn-portal/configs \
        --endpoint vpn.3dit.ru --dns 10.8.0.1 [--dry-run]
"""
import argparse
import ipaddress
import os
import re
import sys
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--endpoint", help="новый домен сервера (порт сохраняется)")
    ap.add_argument("--dns", default="", help="DNS внутри туннеля, через запятую")
    ap.add_argument("--allowed-ips", help="файл со списком подсетей (allowed-ips.txt): заменить AllowedIPs в конфигах, "
                    "адреса DNS из строки DNS сохраняются")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    dns = [x.strip() for x in a.dns.split(",") if x.strip()]
    for d in dns:
        ipaddress.ip_address(d)

    nets_new = None
    if a.allowed_ips:
        found = []
        for line in Path(a.allowed_ips).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                found.append(ipaddress.ip_network(line, strict=False))
        nets_new = [str(n) for n in ipaddress.collapse_addresses(found)]

    changed = 0
    files = sorted(Path(a.dir).glob("*.conf"))
    for f in files:
        text = f.read_text()
        new = text
        if a.endpoint:
            new = re.sub(r"(?m)^Endpoint\s*=\s*[^:\s]+(:\d+)\s*$",
                         lambda m: f"Endpoint = {a.endpoint}{m.group(1)}", new)
        if dns:
            new = re.sub(r"(?m)^DNS\s*=.*\n", "", new)
            new = re.sub(r"(?m)^(Address\s*=.*)$", lambda m: f"{m.group(1)}\nDNS = {', '.join(dns)}", new, count=1)
            m = re.search(r"(?m)^AllowedIPs\s*=\s*(.*)$", new)
            if m:
                nets = [x.strip() for x in m.group(1).split(",") if x.strip()]
                for d in dns:
                    addr = ipaddress.ip_address(d)
                    if not any(addr in ipaddress.ip_network(n, strict=False) for n in nets):
                        nets.append(f"{addr}/32")
                new = new[:m.start()] + "AllowedIPs = " + ", ".join(nets) + new[m.end():]
        if nets_new is not None:
            m = re.search(r"(?m)^AllowedIPs\s*=\s*(.*)$", new)
            if m:
                nets = list(nets_new)
                for dm in re.finditer(r"(?m)^DNS\s*=\s*(.*)$", new):
                    for d in (x.strip() for x in dm.group(1).split(",")):
                        if d and not any(ipaddress.ip_address(d) in ipaddress.ip_network(n, strict=False) for n in nets):
                            nets.append(f"{d}/32")
                new = new[:m.start()] + "AllowedIPs = " + ", ".join(nets) + new[m.end():]
        if new != text:
            changed += 1
            if not a.dry_run:
                st = f.stat()
                tmp = f.with_suffix(".tmp")
                tmp.write_text(new)
                os.chmod(tmp, st.st_mode & 0o777)
                try:
                    os.chown(tmp, st.st_uid, st.st_gid)
                except PermissionError:
                    pass
                tmp.replace(f)
    print(f"Файлов: {len(files)}, изменено: {changed}{' (dry-run)' if a.dry_run else ''}")


if __name__ == "__main__":
    sys.exit(main())
