"""Publish names and assigned router addresses from the local Guard gateway."""
import fcntl
import json
import os
import re
import time
from pathlib import Path

GATEWAYS = {1: "FI-1", 2: "FI-2", 3: "EE-1"}
STALE_AFTER = 300


def collect(directory):
    with (directory / ".lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        gateway = int((directory / "server-id").read_text().strip())
        if gateway not in GATEWAYS:
            raise ValueError("Unknown Guard gateway")
        peers = []
        for line in (directory / "peers.tsv").read_text().splitlines():
            if not line.strip():
                continue
            name, _public_key, address_slot = line.split("\t")
            slot = int(address_slot)
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name) or not 2 <= slot <= 254:
                raise ValueError("Invalid Guard peer record")
            peers.append({"name": name, "address": f"10.9.{gateway}.{slot}"})
    return gateway, peers


def overview(db, now):
    if not db.execute("SELECT to_regclass('public.router_gateway_inventory')").fetchone()[0]:
        rows = {}
    else:
        rows = {r["gateway"]: r for r in db.execute(
            "SELECT gateway, collected_at, peers FROM router_gateway_inventory"
        )}
    gateways = []
    routers = {}
    total = 0
    for gateway, title in GATEWAYS.items():
        row = rows.get(gateway)
        collected = row["collected_at"] if row else None
        fresh = collected is not None and now - collected <= STALE_AFTER
        peers = row["peers"] if row else []
        gateways.append(dict(title=title, collected=collected, fresh=fresh, count=len(peers)))
        if not fresh:
            continue
        total += len(peers)
        for peer in peers:
            router = routers.setdefault(peer["name"].casefold(), {"name": peer["name"], "addresses": {}})
            router["addresses"][title] = peer["address"]
    return dict(gateways=gateways, routers=sorted(routers.values(), key=lambda router: router["name"].casefold()),
                profiles=total, fresh=sum(gateway["fresh"] for gateway in gateways))


def main():
    from postgres_backend import Connection

    gateway, peers = collect(Path("/etc/wg-mt"))
    db = Connection(os.environ["PORTAL_DB_DSN"])
    try:
        db.execute("""INSERT INTO router_gateway_inventory(gateway, collected_at, peers)
                      VALUES (?, ?, ?::jsonb)
                      ON CONFLICT (gateway) DO UPDATE SET collected_at=EXCLUDED.collected_at, peers=EXCLUDED.peers""",
                   (gateway, int(time.time()), json.dumps(peers)))
    finally:
        db.close()
    print(f"Guard gateway {GATEWAYS[gateway]}: {len(peers)} registered profiles")


if __name__ == "__main__":
    main()
