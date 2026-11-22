#!/usr/bin/env python3
"""Stream a merged SQLite snapshot and its config pool into an empty PostgreSQL database."""
import argparse
import re
import sqlite3
import sys
from pathlib import Path


TABLES = {
    "orgs": "id name slug code key_limit enabled admin_hash created_at",
    "people": "id org_id phone name created_at rx_archived tx_archived dev_limit",
    "assignments": "slot person_id label assigned_at last_download_at downloads",
    "audit": "id ts actor org_id action details",
    "attempts": "ts ip kind",
    "captchas": "id answer ts",
}


def field(value):
    if value is None:
        return r"\N"
    value = str(value)
    if "\0" in value:
        raise ValueError("Null byte in source text")
    return value.replace("\\", r"\\").replace("\n", r"\n").replace("\r", r"\r").replace("\t", r"\t")


def copy_rows(out, table, columns, rows):
    print(f"COPY {table} ({', '.join(columns.split())}) FROM STDIN;", file=out)
    for row in rows:
        print("\t".join(map(field, row)), file=out)
    print(r"\.", file=out)


def read_configs(directory):
    configs = {}
    for path in directory.iterdir():
        name = re.fullmatch(r"client(\d{3,})\.conf", path.name)
        if not name:
            continue
        slot = int(name[1])
        if slot <= 0 or slot in configs or path.is_symlink() or path.stat().st_size > 65536:
            raise ValueError(f"Invalid config file for slot {slot}")
        body = path.read_bytes().decode("utf-8")
        if not all(re.search(rf"(?m)^{key}\s*=\s*\S+", body) for key in ("PrivateKey", "PublicKey", "PresharedKey", "Address")):
            raise ValueError(f"Incomplete config in slot {slot}")
        configs[slot] = body
    if not configs:
        raise ValueError("Empty config pool")
    return configs


def export(source, configs, out):
    assigned = {r[0] for r in source.execute("SELECT slot FROM assignments")}
    if assigned - configs.keys():
        raise ValueError("Assigned slot missing from the config pool")
    print("BEGIN;", file=out)
    tables = [*TABLES, "portal_configs"]
    print(f"LOCK TABLE {', '.join(tables)} IN ACCESS EXCLUSIVE MODE;", file=out)
    populated = " OR ".join(f"EXISTS (SELECT 1 FROM {t})" for t in tables)
    print(f"DO $$ BEGIN IF {populated} THEN RAISE EXCEPTION 'Target is not empty'; END IF; END $$;", file=out)
    copy_rows(out, "portal_configs", "slot body", sorted(configs.items()))
    for table, columns in TABLES.items():
        fields = ", ".join(columns.split())
        copy_rows(out, table, columns, source.execute(f"SELECT {fields} FROM {table}"))
    for table in ("orgs", "people", "audit"):
        print(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
              f"COALESCE(MAX(id), 1), COUNT(*) > 0) FROM {table};", file=out)
    print("COMMIT;", file=out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("configs", type=Path)
    args = parser.parse_args()
    with sqlite3.connect(args.snapshot.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok" or db.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("Invalid SQLite snapshot")
        export(db, read_configs(args.configs), sys.stdout)


if __name__ == "__main__":
    main()
