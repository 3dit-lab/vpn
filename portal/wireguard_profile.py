"""Render standard WireGuard profiles for a separately provisioned endpoint."""
import base64
import ipaddress
import re


NETWORK = ipaddress.IPv4Network("10.19.0.0/20")


def client_address(slot):
    if not 1 <= slot < NETWORK.num_addresses - 2:
        raise ValueError("Slot outside the WireGuard address pool")
    return str(NETWORK.network_address + slot + 1)


def key(value):
    if len(base64.b64decode(value, validate=True)) != 32:
        raise ValueError("Wrong length for a WireGuard key")
    return value


class Gateway:
    def __init__(self, endpoint, public_key, dns=""):
        match = re.fullmatch(r"([a-zA-Z0-9.-]+):([0-9]{1,5})", endpoint)
        if not match or not 1 <= int(match[2]) <= 65535:
            raise ValueError("Expected a WireGuard hostname and UDP port")
        self.endpoint = endpoint
        self.public_key = key(public_key)
        self.dns = str(ipaddress.IPv4Address(dns)) if dns else ""

    def render(self, slot, original):
        values = dict(re.findall(r"(?m)^[ \t]*(PrivateKey|PresharedKey|AllowedIPs|DNS)[ \t]*=[ \t]*([^\r\n#]+)",
                                 original.decode("utf-8")))
        private = key(values["PrivateKey"].strip())
        psk = key(values["PresharedKey"].strip())
        old_dns = {ipaddress.ip_address(s.strip()) for s in values.get("DNS", "").split(",") if s.strip()}
        routes = list(dict.fromkeys(ipaddress.ip_network(s.strip(), strict=False)
                                    for s in values["AllowedIPs"].split(",") if s.strip()))
        routes = [r for r in routes if not (r.num_addresses == 1 and r.network_address in old_dns)]
        if self.dns:
            dns = ipaddress.IPv4Address(self.dns)
            if not any(dns in r for r in routes):
                routes.append(ipaddress.ip_network(f"{dns}/32"))
        if not routes:
            raise ValueError("Empty policy routes")
        lines = ["[Interface]", f"PrivateKey = {private}", f"Address = {client_address(slot)}/32"]
        if self.dns:
            lines.append(f"DNS = {self.dns}")
        lines.extend(["", "[Peer]", f"PublicKey = {self.public_key}", f"PresharedKey = {psk}",
                      f"Endpoint = {self.endpoint}", f"AllowedIPs = {', '.join(map(str, routes))}",
                      "PersistentKeepalive = 25", ""])
        return "\n".join(lines).encode("utf-8")
