#!/usr/bin/env python3
"""Stage app-only credentials and download settings for the portal systemd service."""
import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path)
parser.add_argument("--wireguard", action="store_true")
parser.add_argument("--estonia-amnezia", action="store_true")
args = parser.parse_args()
password = json.loads(Path("/etc/pm-vpn-cluster/pg-secrets.json").read_text())["app"]
if not re.fullmatch(r"[a-f0-9]{48}", password):
    raise ValueError("Invalid generated app credentials")

dsn = "host=10.77.240.1,10.77.240.2,10.77.240.3 port=15432 dbname=pm_vpn user=vpnportal password=" + password
lines = [f'PORTAL_DB_DSN="{dsn}"']
if args.wireguard:
    with open("/etc/pm-vpn-cluster/portal-wg.key", "rb") as f:
        pub = subprocess.check_output(["wg", "pubkey"], stdin=f).decode().strip()
    plain = ("auto|wg.vpn.3dit.ru|Авто;fi1|fi-1-vpn.3dit.ru|Финляндия-1;"
             "fi2|fi-2-vpn.3dit.ru|Финляндия-2;ee1|ee-1-vpn.3dit.ru|Эстония;"
             "all|wg.vpn.3dit.ru|Авто, весь трафик IPv4|full")
    lines += [f'PORTAL_WG_PUBLIC_KEY="{pub}"', f'PORTAL_WG_SERVERS="{plain}"']
if args.estonia_amnezia:
    amnezia = ("auto|vpn.3dit.ru|Авто (рекомендуется);fi|fi-1-vpn.3dit.ru|Финляндия-1;"
               "fi2|fi-2-vpn.3dit.ru|Финляндия-2;ee1|ee-1-vpn.3dit.ru|Эстония;"
               "all|vpn.3dit.ru|Авто, весь трафик|full")
    lines.append(f'PORTAL_SERVERS="{amnezia}"')
fd, temporary = tempfile.mkstemp(dir=args.output.parent, prefix=".portal-env.")
try:
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.link(temporary, args.output)
finally:
    os.unlink(temporary)
