#!/usr/bin/env python3
"""Определяет IPv4-адреса доменов для allowed-ips.txt (запускать на VPN-сервере: клиенты получают ответы его DNS).

    python3 scripts/resolve-domains.py wetransfer.com www.wetransfer.com we.tl [--rounds 12] [--prefix 32]

Имена опрашиваются несколько раз с паузой, потому что CDN отдаёт разные адреса. Печатает по одному адресу
(--prefix 24 печатает подсети /24 целиком) в формате allowed-ips.txt, цепочки CNAME в stderr.
"""
import argparse
import ipaddress
import socket
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domains", nargs="+")
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--pause", type=float, default=1.5)
    ap.add_argument("--prefix", type=int, default=32, choices=(24, 28, 32))
    a = ap.parse_args()
    found = {}
    for i in range(a.rounds):
        for d in a.domains:
            try:
                name, _, addrs = socket.gethostbyname_ex(d)
            except OSError as e:
                if i == 0:
                    print(f"{d}: не резолвится ({e})", file=sys.stderr)
                continue
            for ip in addrs:
                found.setdefault(ip, set()).add(d)
            if i == 0 and name != d:
                print(f"{d} -> {name}", file=sys.stderr)
        time.sleep(a.pause)
    nets = sorted({ipaddress.ip_network(f"{ip}/{a.prefix}", strict=False) for ip in found})
    for n in nets:
        owners = sorted({d for ip, ds in found.items() if ipaddress.ip_address(ip) in n for d in ds})
        print(f"{n}  # {', '.join(owners)}")


if __name__ == "__main__":
    main()
