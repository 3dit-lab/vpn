#!/usr/bin/env python3
"""Restricted SSH command for Guard on the router WireGuard gateway."""
import os
import re
import subprocess


MT_PEER = "/usr/local/sbin/mt-peer"


def main():
    command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if command in ("mt-peer show", "mt-peer show; mt-peer list | wc -l; systemctl is-active wg-quick@wg-mt"):
        subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "wg-quick@wg-mt"], check=True)
        subprocess.run([MT_PEER, "show"], check=True)
        if ";" in command:
            with open("/etc/wg-mt/peers.tsv") as peers:
                print(sum(1 for line in peers if line.strip()))
            print("active")
        return
    change = re.fullmatch(
        r"mt-peer (add|del|slot|move) ([A-Za-z0-9_.-]{1,32})(?: (.{1,55}))?", command
    )
    if change:
        action, name, extra = change.groups()
        arguments = extra.split(" ") if extra else []
        slot = r"[1-9][0-9]{0,2}"
        patterns = {
            "add": (r"[A-Za-z0-9+/]{43}=", slot),
            "del": (),
            "slot": (),
            "move": (slot, slot),
        }
        expected = patterns[action]
        if len(arguments) == len(expected) and all(
            re.fullmatch(pattern, argument) for pattern, argument in zip(expected, arguments)
        ):
            os.execv(MT_PEER, [MT_PEER, action, name, *arguments])
    raise SystemExit("VPN peer command denied")


if __name__ == "__main__":
    main()
