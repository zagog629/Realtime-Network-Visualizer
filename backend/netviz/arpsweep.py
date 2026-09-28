#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr, srp
from scapy.utils import ltoa

# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class Device:
    ip: str
    mac: str
    hostname: str = ""
    vendor: str = ""
    last_seen: float = field(default_factory=time.time)  # epoch seconds

    def to_dict(self) -> dict:
        return asdict(self)

# --------------------------------------------------------------------------
# OUI / vendor lookup
# --------------------------------------------------------------------------

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_CACHE = Path.home() / ".cache" / "arpsweep" / "oui.csv"


def update_oui(path: Path = OUI_CACHE) -> None:
    """Download the IEEE MA-L registry (the OUI list) to a local cache."""
    path.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(OUI_URL, headers={"User-Agent": "Mozilla/5.0 (arpsweep)"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        path.write_bytes(resp.read())


class OUIResolver:
    """MAC -> vendor name. Uses the cached IEEE list, then Scapy's bundled DB."""

    def __init__(self, path: Path = OUI_CACHE):
        self.table: dict[str, str] = {}
        if path.exists():
            with path.open(newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    # "Assignment" is the 24-bit prefix as 6 hex chars, e.g. "286FB9"
                    self.table[row["Assignment"].upper()] = row["Organization Name"].strip()

    def lookup(self, mac: str) -> str:
        octets = mac.lower().replace("-", ":").split(":")
        # Bit 1 of the first octet = "locally administered". Phones and modern
        # OSes use randomized MACs like this, so no vendor can be derived.
        if int(octets[0], 16) & 0x02:
            return "(randomized MAC)"

        vendor = self.table.get("".join(octets[:3]).upper())
        if vendor:
            return vendor

        try:  # fallback: Wireshark's manuf list that ships with Scapy
            name = conf.manufdb._get_manuf(mac)
            if name and name.lower() != mac.lower():
                return name
        except Exception:
            pass
        return ""

# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def local_network(iface=None) -> tuple[object, ipaddress.IPv4Network]:
    """Return (iface, network) for the interface Scapy would use by default."""
    iface = iface or conf.iface
    ip = get_if_addr(iface)
    own = ipaddress.ip_address(ip)
 
    candidates = []
    for route in conf.route.routes:
        net, msk, gw, r_iface = route[:4]
        if str(r_iface) != str(iface) or gw != "0.0.0.0" or msk in (0, 0xFFFFFFFF):
            continue  # not an on-link network route for this interface
        network = ipaddress.ip_network(f"{ltoa(net)}/{bin(msk).count('1')}", strict=False)
        if own in network:
            candidates.append(network)
 
    if candidates:
        return iface, max(candidates, key=lambda n: n.prefixlen)  # most specific wins
    return iface, ipaddress.ip_network(f"{ip}/24", strict=False)  # best-effort fallback


def resolve_hostname(ip: str) -> str:
    """Reverse DNS. Blocks until the resolver answers or times out, so call in threads."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:  # socket.herror / gaierror are subclasses
        return ""


def arp_sweep(network, iface=None, timeout: float = 2.0, retries: int = 2) -> list[Device]:
    """Broadcast an ARP who-has for every address in `network`; return responders."""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(packet, iface=iface, timeout=timeout, retry=retries, inter=0.002, verbose=False)

    found: dict[str, Device] = {}
    for _sent, reply in answered:
        found[reply.psrc] = Device(ip=reply.psrc, mac=reply.hwsrc.lower())

    # A host doesn't answer its own ARP request, so add this machine manually.
    own_ip = get_if_addr(iface or conf.iface)
    if ipaddress.ip_address(own_ip) in network:
        found[own_ip] = Device(ip=own_ip, mac=get_if_hwaddr(iface or conf.iface).lower())

    devices = sorted(found.values(), key=lambda d: ipaddress.ip_address(d.ip))

    oui = OUIResolver()
    with ThreadPoolExecutor(max_workers=32) as pool:
        for dev, name in zip(devices, pool.map(resolve_hostname, [d.ip for d in devices])):
            dev.hostname = name
            dev.vendor = oui.lookup(dev.mac)
    return devices

# --------------------------------------------------------------------------
# Output / CLI
# --------------------------------------------------------------------------

def print_table(devices: list[Device]) -> None:
    headers = ("IP", "MAC", "HOSTNAME", "VENDOR")
    rows = [(d.ip, d.mac, d.hostname or "-", d.vendor or "-") for d in devices]
    widths = [max(len(cell) for cell in col) for col in zip(headers, *rows)]
    line = "  ".join("{:<%d}" % w for w in widths)
    print(line.format(*headers))
    print(line.format(*("-" * w for w in widths)))
    for row in rows:
        print(line.format(*row))
    print(f"\n{len(devices)} device(s) found")


def main() -> int:
    ap = argparse.ArgumentParser(description="ARP sweep with vendor lookup")
    ap.add_argument("-t", "--target", help="CIDR to scan (default: your subnet)")
    ap.add_argument("-i", "--iface", help="network interface (default: Scapy's default)")
    ap.add_argument("--timeout", type=float, default=2.0, help="seconds to wait per round")
    ap.add_argument("--retries", type=int, default=2, help="extra rounds for unanswered hosts")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a table")
    ap.add_argument("--force", action="store_true", help="allow scanning larger than a /16")
    ap.add_argument("--update-oui", action="store_true", help="download the IEEE OUI list and exit")
    args = ap.parse_args()

    if args.update_oui:
        update_oui()
        print(f"OUI list saved to {OUI_CACHE}")
        return 0

    iface = args.iface or conf.iface
    if args.target:
        network = ipaddress.ip_network(args.target, strict=False)
    else:
        iface, network = local_network(iface)

    if network.num_addresses > 65536 and not args.force:
        print(f"Refusing to sweep {network} ({network.num_addresses} addresses); use --force.", file=sys.stderr)
        return 2

    if not OUI_CACHE.exists():
        print("Tip: run with --update-oui for a complete vendor database.", file=sys.stderr)
    print(f"Sweeping {network} on {iface} ...", file=sys.stderr)

    try:
        devices = arp_sweep(network, iface=iface, timeout=args.timeout, retries=args.retries)
    except PermissionError:
        print("Raw sockets need elevated privileges: run with sudo (or as Administrator).", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps([d.to_dict() for d in devices], indent=2))
    else:
        print_table(devices)
    return 0


if __name__ == "__main__":
    sys.exit(main())