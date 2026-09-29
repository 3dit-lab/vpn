#!/usr/bin/env python3
"""Генератор конфигурации AmneziaWG: серверный awg0.conf + клиентские конфиги и QR.

Идемпотентен: ключи и параметры обфускации хранятся в secrets/state.json.
Повторный запуск ничего не перегенерирует, а только заново рендерит конфиги
(например, после смены домена или списка подсетей) и добавляет недостающих клиентов.

Пример:
    python3 scripts/generate.py --endpoint vpn.example.ru --clients 150
"""
import argparse
import base64
import csv
import ipaddress
import json
import os
import random
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def gen_keypair():
    priv = X25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return b64(raw_priv), b64(raw_pub)


def gen_obfuscation():
    rng = random.SystemRandom()
    while True:
        s1, s2 = rng.randint(15, 150), rng.randint(15, 150)
        if s1 + 56 != s2:  # ограничение AmneziaWG
            break
    headers = rng.sample(range(5, 2**31 - 1), 4)  # H1..H4 различны и не 1..4
    return {
        "Jc": rng.randint(4, 8),
        "Jmin": 10,
        "Jmax": 50,
        "S1": s1,
        "S2": s2,
        "H1": headers[0],
        "H2": headers[1],
        "H3": headers[2],
        "H4": headers[3],
    }


def load_allowed_ips(path: Path):
    nets = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            nets.append(ipaddress.ip_network(line, strict=False))
    # объединяем пересекающиеся и соседние подсети: покрытие не меняется, список короче
    return [str(n) for n in ipaddress.collapse_addresses(nets)]


def obf_lines(o):
    return "\n".join(f"{k} = {o[k]}" for k in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True, help="домен VPN-сервера (без порта)")
    ap.add_argument("--port", type=int, default=51820, help="UDP-порт сервера")
    ap.add_argument("--clients", type=int, default=150)
    ap.add_argument("--subnet", default="10.8.0.0/24")
    ap.add_argument("--mtu", type=int, default=1280)
    ap.add_argument("--keepalive", type=int, default=25)
    ap.add_argument("--allowed-ips", default=str(ROOT / "allowed-ips.txt"))
    ap.add_argument("--dns", default="", help="необязательно: DNS для клиентов (по умолчанию не задаётся)")
    ap.add_argument("--state", default=str(ROOT / "secrets" / "state.json"))
    ap.add_argument("--out", default=str(ROOT / "out"))
    args = ap.parse_args()

    net = ipaddress.ip_network(args.subnet)
    hosts = list(net.hosts())
    if args.clients > len(hosts) - 1:
        sys.exit(f"В подсети {net} не хватит адресов на {args.clients} клиентов")
    server_ip = hosts[0]

    state_path = Path(args.state)
    if state_path.exists():
        state = json.loads(state_path.read_text())
    else:
        spriv, spub = gen_keypair()
        state = {"server": {"private": spriv, "public": spub}, "obfuscation": gen_obfuscation(), "clients": {}}

    # добавляем недостающих клиентов; существующие не трогаем
    for i in range(1, args.clients + 1):
        name = f"client{i:03d}"
        if name in state["clients"]:
            continue
        cpriv, cpub = gen_keypair()
        state["clients"][name] = {
            "private": cpriv,
            "public": cpub,
            "psk": b64(secrets.token_bytes(32)),
            "ip": str(hosts[i]),  # .2, .3, ... (.1 занят сервером)
        }
    state["meta"] = {"subnet": str(net), "port": args.port}
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2))
    os.chmod(state_path, 0o600)

    allowed = load_allowed_ips(Path(args.allowed_ips))
    allowed_str = ", ".join(allowed)
    obf = state["obfuscation"]

    out = Path(args.out)
    (out / "server").mkdir(parents=True, exist_ok=True)
    (out / "clients").mkdir(exist_ok=True)

    # ---- сервер ----
    srv = [
        "[Interface]",
        f"PrivateKey = {state['server']['private']}",
        f"Address = {server_ip}/{net.prefixlen}",
        f"ListenPort = {args.port}",
        obf_lines(obf),
        # NAT наружу через интерфейс маршрута по умолчанию
        f"PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; "
        f"iptables -t nat -A POSTROUTING -s {net} -o $(ip -4 route show default | awk '{{print $5; exit}}') -j MASQUERADE",
        f"PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; "
        f"iptables -t nat -D POSTROUTING -s {net} -o $(ip -4 route show default | awk '{{print $5; exit}}') -j MASQUERADE",
        "",
    ]
    for name, c in sorted(state["clients"].items()):
        srv += [
            f"# {name}",
            "[Peer]",
            f"PublicKey = {c['public']}",
            f"PresharedKey = {c['psk']}",
            f"AllowedIPs = {c['ip']}/32",
            "",
        ]
    srv_path = out / "server" / "awg0.conf"
    srv_path.write_text("\n".join(srv))
    os.chmod(srv_path, 0o600)

    # ---- клиенты ----
    rows, sizes = [], []
    for name, c in sorted(state["clients"].items()):
        lines = [
            "[Interface]",
            f"PrivateKey = {c['private']}",
            f"Address = {c['ip']}/32",
        ]
        if args.dns:
            lines.append(f"DNS = {args.dns}")
        lines += [f"MTU = {args.mtu}", obf_lines(obf), "",
                  "[Peer]",
                  f"PublicKey = {state['server']['public']}",
                  f"PresharedKey = {c['psk']}",
                  # только подсети заблокированных сервисов; остальной трафик идёт напрямую
                  f"AllowedIPs = {allowed_str}",
                  f"Endpoint = {args.endpoint}:{args.port}",
                  f"PersistentKeepalive = {args.keepalive}",
                  ""]
        text = "\n".join(lines)
        conf_path = out / "clients" / f"{name}.conf"
        conf_path.write_text(text)
        os.chmod(conf_path, 0o600)
        size = len(text.encode())
        sizes.append(size)
        rows.append([name, c["ip"], c["public"], size])

    with open(ROOT / "clients.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["name", "ip", "public_key", "conf_bytes"])
        w.writerows(rows)

    print(f"Клиентов: {len(state['clients'])}")
    print(f"AllowedIPs: {len(allowed)} подсетей после объединения")
    print(f"Размер клиентского .conf: {min(sizes)}..{max(sizes)} байт")
    print(f"Endpoint: {args.endpoint}:{args.port}")


if __name__ == "__main__":
    main()
