import ipaddress
from types import SimpleNamespace

import pytest

import arpsweep

# --------------------------------------------------------------------------
# OUI lookup
# --------------------------------------------------------------------------

@pytest.fixture
def oui_csv(tmp_path):
    path = tmp_path / "oui.csv"
    path.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        "MA-L,B827EB,Raspberry Pi Foundation,Cambridge\n"
        "MA-L,286FB9,Nokia Shanghai Bell Co. Ltd.,Shanghai\n",
        encoding="utf-8",
    )
    return path


def test_oui_known_prefix(oui_csv):
    resolver = arpsweep.OUIResolver(oui_csv)
    assert resolver.lookup("b8:27:eb:12:34:56") == "Raspberry Pi Foundation"


def test_oui_accepts_uppercase_and_dashes(oui_csv):
    resolver = arpsweep.OUIResolver(oui_csv)
    assert resolver.lookup("B8-27-EB-00-00-01") == "Raspberry Pi Foundation"


def test_oui_randomized_mac(oui_csv):
    # Second hex digit of the first octet is 2/6/A/E -> locally administered
    resolver = arpsweep.OUIResolver(oui_csv)
    assert resolver.lookup("da:a1:19:00:00:01") == "(randomized MAC)"


def test_oui_missing_cache_does_not_crash(tmp_path):
    resolver = arpsweep.OUIResolver(tmp_path / "does-not-exist.csv")
    assert isinstance(resolver.lookup("00:11:22:33:44:55"), str)

# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

def test_device_to_dict():
    dev = arpsweep.Device(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff", hostname="pi.lan", vendor="Acme")
    data = dev.to_dict()
    assert data["ip"] == "10.0.0.5"
    assert data["hostname"] == "pi.lan"
    assert isinstance(data["last_seen"], float)

# --------------------------------------------------------------------------
# Subnet detection
# --------------------------------------------------------------------------

def _ip_int(text):
    return int(ipaddress.ip_address(text))


def test_local_network_reads_routing_table(monkeypatch):
    routes = [
        (0, 0, "192.168.1.1", "eth0", "192.168.1.50", 100),  # default route: ignored
        (_ip_int("192.168.1.0"), _ip_int("255.255.255.0"), "0.0.0.0", "eth0", "192.168.1.50", 100),
    ]
    monkeypatch.setattr(arpsweep.conf.route, "routes", routes)
    monkeypatch.setattr(arpsweep, "get_if_addr", lambda iface: "192.168.1.50")

    iface, network = arpsweep.local_network("eth0")
    assert iface == "eth0"
    assert network == ipaddress.ip_network("192.168.1.0/24")


def test_local_network_falls_back_to_slash_24(monkeypatch):
    monkeypatch.setattr(arpsweep.conf.route, "routes", [])
    monkeypatch.setattr(arpsweep, "get_if_addr", lambda iface: "10.1.2.3")

    _, network = arpsweep.local_network("eth0")
    assert network == ipaddress.ip_network("10.1.2.0/24")

# --------------------------------------------------------------------------
# Sweep (srp mocked)
# --------------------------------------------------------------------------

class FakeOUI:
    def lookup(self, mac):
        return "Fake Vendor"


@pytest.fixture
def fake_sweep(monkeypatch):
    replies = [
        (None, SimpleNamespace(psrc="192.168.1.10", hwsrc="AA:BB:CC:00:00:10")),
        (None, SimpleNamespace(psrc="192.168.1.2", hwsrc="AA:BB:CC:00:00:02")),
    ]
    monkeypatch.setattr(arpsweep, "srp", lambda *a, **k: (replies, []))
    monkeypatch.setattr(arpsweep, "get_if_addr", lambda iface: "192.168.1.50")
    monkeypatch.setattr(arpsweep, "get_if_hwaddr", lambda iface: "B8:27:EB:00:00:99")
    monkeypatch.setattr(arpsweep, "resolve_hostname", lambda ip: f"host-{ip.split('.')[-1]}")
    monkeypatch.setattr(arpsweep, "OUIResolver", FakeOUI)


def test_sweep_sorts_numerically_and_includes_self(fake_sweep):
    devices = arpsweep.arp_sweep(ipaddress.ip_network("192.168.1.0/24"))
    assert [d.ip for d in devices] == ["192.168.1.2", "192.168.1.10", "192.168.1.50"]


def test_sweep_fills_in_mac_hostname_vendor(fake_sweep):
    devices = arpsweep.arp_sweep(ipaddress.ip_network("192.168.1.0/24"))
    first = devices[0]
    assert first.mac == "aa:bb:cc:00:00:02"  # normalized to lowercase
    assert first.hostname == "host-2"
    assert first.vendor == "Fake Vendor"


def test_sweep_skips_self_when_outside_target(fake_sweep):
    devices = arpsweep.arp_sweep(ipaddress.ip_network("10.9.9.0/24"))
    assert "192.168.1.50" not in [d.ip for d in devices]

# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def test_print_table(capsys):
    arpsweep.print_table([
        arpsweep.Device("192.168.1.1", "28:6f:b9:aa:bb:cc", "router.lan", "Nokia"),
        arpsweep.Device("192.168.1.20", "da:a1:19:00:00:01", "", "(randomized MAC)"),
    ])
    out = capsys.readouterr().out
    assert "HOSTNAME" in out
    assert "router.lan" in out
    assert "2 device(s) found" in out