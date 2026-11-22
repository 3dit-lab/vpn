#!/usr/bin/env python3
"""Merge two consistent SQLite snapshots without writing to either source."""
import argparse
import json
import os
import sqlite3
from pathlib import Path


PERSON_FIELDS = ("org_id", "phone", "name", "created_at", "rx_archived", "tx_archived", "dev_limit")


def source(path):
    conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("BEGIN")
    if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok" or conn.execute("PRAGMA foreign_key_check").fetchone():
        conn.close()
        raise ValueError(f"{path.name}: inconsistent SQLite snapshot")
    return conn


def merge(primary, secondary, dst):
    orgs = {r["slug"]: r for r in primary.execute("SELECT * FROM orgs")}
    other_orgs = {r["id"]: r for r in secondary.execute("SELECT * FROM orgs")}
    if orgs.keys() != {r["slug"] for r in other_orgs.values()}:
        raise ValueError("Organization sets differ")
    admin_fields = ("code", "name", "key_limit", "enabled", "admin_hash")
    if any(any(r[f] != orgs[r["slug"]][f] for f in admin_fields) for r in other_orgs.values()):
        raise ValueError("Organization settings differ")

    stats = {"added_users": 0, "primary_user_settings_retained": 0, "added_assignments": 0}
    people = {(r["org_id"], r["phone"]): r for r in primary.execute("SELECT * FROM people")}
    ids = {}
    dst.row_factory = sqlite3.Row
    primary.backup(dst)
    dst.execute("PRAGMA foreign_keys=ON")

    with dst:
        for person in secondary.execute("SELECT * FROM people ORDER BY id"):
            org_id = orgs[other_orgs[person["org_id"]]["slug"]]["id"]
            prior = people.get((org_id, person["phone"]))
            if prior:
                ids[person["id"]] = prior["id"]
                if any(prior[f] != person[f] for f in ("name", "dev_limit")):
                    stats["primary_user_settings_retained"] += 1
                continue
            fields = ", ".join(PERSON_FIELDS)
            values = (org_id, *(person[f] for f in PERSON_FIELDS[1:]))
            ids[person["id"]] = dst.execute(
                f"INSERT INTO people({fields}) VALUES (?, ?, ?, ?, ?, ?, ?)", values
            ).lastrowid
            stats["added_users"] += 1

        for entry in secondary.execute("SELECT * FROM assignments ORDER BY slot"):
            slot, owner = entry["slot"], ids[entry["person_id"]]
            prior = dst.execute("SELECT * FROM assignments WHERE slot=?", (slot,)).fetchone()
            if prior:
                if (prior["person_id"], prior["assigned_at"]) != (owner, entry["assigned_at"]):
                    raise ValueError(f"Conflicting active assignment for slot {slot}")
                continue
            if primary.execute(
                "SELECT 1 FROM audit WHERE ts>=? AND action=? AND details LIKE ?",
                (entry["assigned_at"], "освобождён конфиг", f"№{slot:03d} (%"),
            ).fetchone():
                raise ValueError(f"Secondary assignment for slot {slot} may have been revoked")
            dst.execute(
                "INSERT INTO assignments(slot,person_id,label,assigned_at,last_download_at,downloads) "
                "VALUES (?,?,?,?,?,?)",
                (slot, owner, entry["label"], entry["assigned_at"], entry["last_download_at"], entry["downloads"]),
            )
            stats["added_assignments"] += 1

        for entry in primary.execute("SELECT slot, assigned_at FROM assignments"):
            if secondary.execute(
                "SELECT 1 FROM audit WHERE ts>=? AND action=? AND details LIKE ?",
                (entry["assigned_at"], "освобождён конфиг", f"№{entry['slot']:03d} (%"),
            ).fetchone():
                raise ValueError(f"Primary assignment for slot {entry['slot']} may have been revoked")

    if dst.execute("PRAGMA quick_check").fetchone()[0] != "ok" or dst.execute("PRAGMA foreign_key_check").fetchone():
        raise ValueError("Merged snapshot failed integrity validation")
    stats["users"] = dst.execute("SELECT COUNT(*) FROM people").fetchone()[0]
    stats["assignments"] = dst.execute("SELECT COUNT(*) FROM assignments").fetchone()[0]
    return stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("primary", type=Path)
    parser.add_argument("secondary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        # Keep the output self-contained even when the primary uses WAL.
        with source(args.primary) as primary, source(args.secondary) as secondary, sqlite3.connect(args.output) as dst:
            result = merge(primary, secondary, dst)
            dst.execute("PRAGMA journal_mode=DELETE")
    except BaseException:
        args.output.unlink(missing_ok=True)
        raise
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
