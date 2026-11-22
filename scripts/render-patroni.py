#!/usr/bin/env python3
"""Render one PM-VPN Patroni node config; generated passwords stay on the nodes."""
import argparse
import json
import os
import re
import tempfile
from pathlib import Path


ADDRESSES = {"fi-1": "10.77.240.1", "fi-2": "10.77.240.2", "ee-1": "10.77.240.3"}


def render(name, secrets):
    address = ADDRESSES[name]
    if any(not re.fullmatch(r"[a-f0-9]{48}", secrets[k]) for k in ("admin", "replication", "api")):
        raise ValueError("Malformed generated credential")
    return {
        "scope": "pm-vpn-postgres", "name": name, "namespace": "/service",
        "restapi": {
            "listen": f"{address}:18080", "connect_address": f"{address}:18080",
            "authentication": {"username": "patroni", "password": secrets["api"]},
        },
        "etcd3": {"hosts": ",".join(f"{p}:2379" for p in ADDRESSES.values())},
        "bootstrap": {
            "dcs": {
                "ttl": 20, "loop_wait": 5, "retry_timeout": 5,
                "synchronous_mode": "on", "synchronous_mode_strict": True,
                "postgresql": {"use_pg_rewind": True, "parameters": {"wal_log_hints": "on"}},
            },
            "pg_hba": ["local all all peer"] + [
                line for ip in ADDRESSES.values() for line in (
                    f"host replication replicator {ip}/32 scram-sha-256",
                    f"host all all {ip}/32 scram-sha-256",
                )
            ],
        },
        "postgresql": {
            "listen": f"{address}:15432", "connect_address": f"{address}:15432",
            "data_dir": "/cluster", "bin_dir": "/usr/lib/postgresql/18/bin",
            "authentication": {
                "superuser": {"username": "postgres", "password": secrets["admin"]},
                "replication": {"username": "replicator", "password": secrets["replication"]},
            },
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", choices=ADDRESSES)
    parser.add_argument("secrets", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    args = parser.parse_args()
    settings = render(args.name, json.loads(args.secrets.read_text()))
    fd, temporary = tempfile.mkstemp(dir=args.output.parent, prefix=".patroni-conf.")
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(settings, out, indent=2)
            out.write("\n")
        os.chown(temporary, args.uid, args.gid)
        os.chmod(temporary, 0o400)
        os.link(temporary, args.output)
    finally:
        os.unlink(temporary)


if __name__ == "__main__":
    main()
