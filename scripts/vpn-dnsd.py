#!/usr/bin/env python3
"""Авторитетный DNS для зоны (например vpn.3dit.ru): отдаёт только живые VPN-серверы.

Зона состоит из одного имени (apex). Сервис проверяет TCP-доступность каждого сервера
и в ответ на A-запрос возвращает адреса только живых (TTL короткий). Если не отвечает никто,
отдаёт все адреса (лучше попытаться, чем не отвечать). Рекурсию не делает: чужие имена получают REFUSED.

Конфиг: /etc/vpn-dnsd.json (пример в deploy/vpn-dnsd.json.example). Нужен пакет python3-dnslib.
"""
import http.client
import json
import random
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from dnslib import A, NS, QTYPE, RCODE, RR, SOA
from dnslib.server import BaseResolver, DNSServer

CONF = sys.argv[1] if len(sys.argv) > 1 else "/etc/vpn-dnsd.json"
cfg = json.load(open(CONF))
ZONE = cfg["zone"].rstrip(".").lower()
TTL = int(cfg.get("ttl", 30))
SERVERS = cfg["servers"]            # [{"name","ip","port":443}]
WG_NAME = "wg." + ZONE
WG_SERVERS = cfg.get("wireguard_servers", [])
NS_NAMES = cfg["ns"]
INTERVAL = float(cfg.get("interval", 5))
FAILS = int(cfg.get("fails", 4))
RATE = float(cfg.get("rate_per_sec", 100))

def address(s):
    return s["ip"], int(s.get("port", 443))


def health_key(s):
    return address(s), bool(s.get("portal_health"))


targets = {health_key(s): s for s in SERVERS + WG_SERVERS}
state = dict.fromkeys(targets, True)
fail_count = dict.fromkeys(targets, 0)
lock = threading.Lock()


def probe(s):
    try:
        with socket.create_connection(address(s), timeout=2) as conn:
            if not s.get("portal_health"):
                return True
            with ssl.create_default_context().wrap_socket(conn, server_hostname=ZONE) as tls:
                tls.settimeout(8)
                tls.sendall(f"GET /healthz HTTP/1.1\r\nHost: {ZONE}\r\nConnection: close\r\n\r\n".encode("ascii"))
                with http.client.HTTPResponse(tls) as response:
                    response.begin()
                    return response.status == 200 and response.read(3) == b"OK\n"
    except (OSError, http.client.HTTPException):
        return False


def health_loop():
    with ThreadPoolExecutor(max_workers=min(len(targets), 8)) as checks:
        while True:
            for endpoint, ok in zip(targets, checks.map(probe, targets.values())):
                update_health(endpoint, ok)
            time.sleep(INTERVAL)


def update_health(endpoint, ok):
    s = targets[endpoint]
    with lock:
        if ok:
            fail_count[endpoint] = 0
            if not state[endpoint]:
                print(f"[health] {s['name']} {s['ip']} снова доступен", flush=True)
            state[endpoint] = True
        else:
            fail_count[endpoint] += 1
            if fail_count[endpoint] >= FAILS and state[endpoint]:
                state[endpoint] = False
                print(f"[health] {s['name']} {s['ip']} недоступен", flush=True)


def alive_ips(servers):
    """Живые основные серверы; резервные ("backup": true) отдаются, только если ни один основной не жив."""
    with lock:
        alive = [s for s in servers if state[health_key(s)]]
    main = [s["ip"] for s in alive if not s.get("backup")]
    if main:
        return main
    return [s["ip"] for s in alive] or [s["ip"] for s in servers]


class Bucket:
    """Простой лимит запросов на адрес источника (защита от использования в атаках)."""

    def __init__(self, rate):
        self.rate, self.t, self.d = rate, time.monotonic(), {}

    def allow(self, ip):
        now = time.monotonic()
        tokens, last = self.d.get(ip, (self.rate, now))
        tokens = min(self.rate, tokens + (now - last) * self.rate)
        ok = tokens >= 1
        self.d[ip] = (tokens - 1 if ok else tokens, now)
        if len(self.d) > 20000:
            self.d = {k: v for k, v in self.d.items() if now - v[1] < 5}
        return ok


class Resolver(BaseResolver):
    def __init__(self):
        self.bucket = Bucket(RATE)

    def soa(self):
        serial = int(time.time()) // 60
        return RR(ZONE, QTYPE.SOA, ttl=TTL,
                  rdata=SOA(NS_NAMES[0], "hostmaster." + ZONE.split(".", 1)[-1], (serial, 60, 30, 3600, TTL)))

    def resolve(self, request, handler):
        reply = request.reply()
        reply.header.aa = 1
        reply.header.ra = 0
        q = request.q
        name = str(q.qname).rstrip(".").lower()
        qtype = QTYPE[q.qtype]
        src = handler.client_address[0]
        if not self.bucket.allow(src):
            reply.header.rcode = RCODE.REFUSED
            return reply
        if name != ZONE and not name.endswith("." + ZONE):
            reply.header.aa = 0
            reply.header.rcode = RCODE.REFUSED
            return reply
        if name == WG_NAME and WG_SERVERS:
            if qtype == "A":
                ips = alive_ips(WG_SERVERS)
                random.shuffle(ips)
                for ip in ips:
                    reply.add_answer(RR(WG_NAME, QTYPE.A, ttl=TTL, rdata=A(ip)))
            else:
                reply.add_auth(self.soa())
            return reply
        if name != ZONE:
            reply.header.rcode = RCODE.NXDOMAIN
            reply.add_auth(self.soa())
            return reply
        if qtype == "A":
            ips = alive_ips(SERVERS)
            random.shuffle(ips)  # равномерно распределяет новые подключения между живыми серверами
            for ip in ips:
                reply.add_answer(RR(ZONE, QTYPE.A, ttl=TTL, rdata=A(ip)))
        elif qtype == "NS":
            for n in NS_NAMES:
                reply.add_answer(RR(ZONE, QTYPE.NS, ttl=3600, rdata=NS(n)))
        elif qtype == "SOA":
            reply.add_answer(self.soa())
        else:
            reply.add_auth(self.soa())  # NOERROR без данных (AAAA, ANY и пр.)
        return reply


def main():
    threading.Thread(target=health_loop, daemon=True).start()
    r = Resolver()
    addr, port = cfg.get("listen", "0.0.0.0"), int(cfg.get("port", 53))
    servers = [DNSServer(r, address=addr, port=port, tcp=False),
               DNSServer(r, address=addr, port=port, tcp=True)]
    for s in servers:
        s.start_thread()
    print(f"vpn-dnsd: зона {ZONE}, {addr}:{port}, серверы {[s['ip'] for s in SERVERS]}", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
