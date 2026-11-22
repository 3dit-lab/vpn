#!/usr/bin/env python3
"""Exercise the application on a disposable PostgreSQL database."""
import concurrent.futures
import json
import os
import tempfile
from pathlib import Path

import psycopg

from test_portal import Ctx, SUPER_PW, b64key, write_confs


def main():
    dsn = os.environ["PORTAL_TEST_DSN"]
    schema = Path(__file__).resolve().parents[1] / "deploy/cluster/schema.sql"
    with tempfile.TemporaryDirectory() as work:
        root = Path(work)
        write_confs(root, 6)
        with psycopg.connect(dsn, autocommit=True) as db:
            if db.execute("SELECT to_regclass('orgs')").fetchone()[0] is not None:
                raise RuntimeError("The test requires an empty database")
            db.execute(schema.read_text())
            db.execute("INSERT INTO orgs(name,slug,code,key_limit,created_at) VALUES ('Test','test','33333',2,1)")
            with db.cursor() as cur:
                cur.executemany("INSERT INTO portal_configs(slot,body) VALUES (%s,%s)",
                                [(slot, (root / "configs" / f"client{slot:03d}.conf").read_text())
                                 for slot in range(1, 7)])
        os.environ.update(PORTAL_DEV="1", PORTAL_DATA=str(root), PORTAL_PEERS=str(root / "peers.json"),
                          PORTAL_LOG_DIR=str(root / "logs"), PORTAL_SECRET_KEY="test-shared",
                          SUPERADMIN_PASSWORD=SUPER_PW, PORTAL_DB_DSN=dsn,
                          PORTAL_WG_ENDPOINT="ee-1-vpn.example.test:51822",
                          PORTAL_WG_PUBLIC_KEY=b64key(201))
        import portal

        x = Ctx(portal)
        alice, bob, carol = (x.client() for _ in range(3))
        for index, client in enumerate((alice, bob, carol), 1):
            assert x.emp_login(client, "33333", phone=f"+7900111223{index}", name="Test User").status_code == 200
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            status = list(executor.map(lambda c: x.claim(c).status_code, (alice, bob, carol)))
        assert status == [200, 200, 200]
        assert x.slots() == [1, 2]
        slot = 1
        with psycopg.connect(dsn) as db:
            phone = db.execute("SELECT p.phone FROM assignments a JOIN people p ON p.id=a.person_id WHERE a.slot=1").fetchone()[0]
        owner = (alice, bob, carol)[int(phone[-1]) - 1]
        other = next(c for c in (alice, bob, carol) if c is not owner)
        assert other.get(f"/d/{slot}/conf").status_code == 404
        before = owner.get(f"/d/{slot}/conf")
        assert before.status_code == 200 and b"PrivateKey" in before.data
        plain = owner.get(f"/d/{slot}/conf?format=wireguard")
        assert plain.status_code == 200 and b"Endpoint = ee-1-vpn.example.test:51822" in plain.data
        assert b"Address = 10.19.0.2/32" in plain.data and b"10.8.0.2" not in plain.data
        assert other.get(f"/d/{slot}/conf?format=wireguard").status_code == 404
        admin = x.client()
        assert x.super_login(admin).status_code == 200
        assert x.post(admin, f"/super/release/{slot}").status_code == 200
        assert owner.get(f"/d/{slot}/conf").status_code == 404
        assert x.claim(other).status_code == 200
        after = other.get(f"/d/{slot}/conf")
        assert after.status_code == 200 and after.data != before.data
        peers = json.loads((root / "peers.json").read_text())["peers"]
        assert len(peers) == 2 and peers[0]["wireguard_ip"] == "10.19.0.2"
        print("PASS: concurrent claims, org limit, authorization, both profile formats, atomic rotation and reassignment")


if __name__ == "__main__":
    main()
