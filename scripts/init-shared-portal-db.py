#!/usr/bin/env python3
"""Create the shared portal database and a restricted application role."""
import json
from pathlib import Path

import psycopg
from psycopg import sql


ROOT = Path(__file__).resolve().parents[1]
HOSTS = "10.77.240.1,10.77.240.2,10.77.240.3"
creds = json.loads(Path("/etc/pm-vpn-cluster/pg-secrets.json").read_text())
params = dict(host=HOSTS, port=15432, user="postgres", password=creds["admin"],
              target_session_attrs="read-write", connect_timeout=3)
with psycopg.connect(dbname="postgres", autocommit=True, **params) as db:
    if not db.execute("SELECT 1 FROM pg_roles WHERE rolname='vpnportal'").fetchone():
        db.execute(sql.SQL("CREATE ROLE vpnportal LOGIN PASSWORD {}").format(sql.Literal(creds["app"])))
    if not db.execute("SELECT 1 FROM pg_database WHERE datname='pm_vpn'").fetchone():
        db.execute("CREATE DATABASE pm_vpn")
with psycopg.connect(dbname="pm_vpn", autocommit=True, **params) as db:
    if db.execute("SELECT to_regclass('portal_configs')").fetchone()[0] is None:
        db.execute((ROOT / "deploy/cluster/schema.sql").read_text())
    db.execute("REVOKE ALL ON DATABASE pm_vpn FROM PUBLIC")
    db.execute("GRANT CONNECT ON DATABASE pm_vpn TO vpnportal")
    db.execute("GRANT USAGE ON SCHEMA public TO vpnportal")
    db.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vpnportal")
    db.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vpnportal")
    print("Portal database and application role ready")
