from netviz.arpsweep import Device
from netviz.events import JOINED, LEFT, UPDATED, DeviceEvent, diff_snapshots


def _dev(ip, mac, hostname="", vendor=""):
    return Device(ip=ip, mac=mac, hostname=hostname, vendor=vendor, last_seen=0.0)


def test_new_mac_is_joined():
    previous = {}
    current = {"aa:bb:cc:00:00:01": _dev("192.168.1.10", "aa:bb:cc:00:00:01")}

    events = diff_snapshots(previous, current)

    assert len(events) == 1
    assert events[0].type == JOINED
    assert events[0].device.ip == "192.168.1.10"


def test_missing_mac_is_left():
    previous = {"aa:bb:cc:00:00:01": _dev("192.168.1.10", "aa:bb:cc:00:00:01")}
    current = {}

    events = diff_snapshots(previous, current)

    assert len(events) == 1
    assert events[0].type == LEFT
    assert events[0].device.ip == "192.168.1.10"  # last known record, not blank


def test_unchanged_device_produces_no_event():
    dev = _dev("192.168.1.10", "aa:bb:cc:00:00:01", hostname="pi.lan")
    previous = {"aa:bb:cc:00:00:01": dev}
    current = {"aa:bb:cc:00:00:01": _dev("192.168.1.10", "aa:bb:cc:00:00:01", hostname="pi.lan")}

    assert diff_snapshots(previous, current) == []


def test_ip_change_is_updated_with_changes_payload():
    mac = "aa:bb:cc:00:00:01"
    previous = {mac: _dev("192.168.1.10", mac)}
    current = {mac: _dev("192.168.1.99", mac)}  # DHCP handed out a new lease

    events = diff_snapshots(previous, current)

    assert len(events) == 1
    assert events[0].type == UPDATED
    assert events[0].changes == {"ip": {"old": "192.168.1.10", "new": "192.168.1.99"}}


def test_hostname_appearing_is_updated():
    mac = "aa:bb:cc:00:00:01"
    previous = {mac: _dev("192.168.1.10", mac, hostname="")}
    current = {mac: _dev("192.168.1.10", mac, hostname="laptop.lan")}

    events = diff_snapshots(previous, current)

    assert len(events) == 1
    assert events[0].type == UPDATED
    assert events[0].changes["hostname"] == {"old": "", "new": "laptop.lan"}


def test_hostname_disappearing_is_not_reported():
    # A resolver hiccup blanking out a known hostname shouldn't be announced
    # as a change; watcher.py handles not overwriting it, but diff_snapshots
    # itself should also treat "new value empty" as uninteresting.
    mac = "aa:bb:cc:00:00:01"
    previous = {mac: _dev("192.168.1.10", mac, hostname="laptop.lan")}
    current = {mac: _dev("192.168.1.10", mac, hostname="")}

    assert diff_snapshots(previous, current) == []


def test_joined_left_updated_all_in_one_diff():
    stay = "aa:aa:aa:00:00:01"
    leave = "bb:bb:bb:00:00:02"
    join = "cc:cc:cc:00:00:03"

    previous = {
        stay: _dev("192.168.1.1", stay, hostname="router.lan"),
        leave: _dev("192.168.1.2", leave),
    }
    current = {
        stay: _dev("192.168.1.1", stay, hostname="router-new.lan"),  # renamed
        join: _dev("192.168.1.3", join),
    }

    events = diff_snapshots(previous, current)
    by_type = {e.type: e for e in events}

    assert set(by_type) == {JOINED, LEFT, UPDATED}
    assert by_type[JOINED].device.mac == join
    assert by_type[LEFT].device.mac == leave
    assert by_type[UPDATED].device.mac == stay


def test_device_event_to_dict_shape():
    dev = _dev("192.168.1.1", "aa:bb:cc:00:00:01", hostname="router.lan")
    event = DeviceEvent(JOINED, dev)
    data = event.to_dict()

    assert data["type"] == JOINED
    assert data["device"]["ip"] == "192.168.1.1"
    assert data["changes"] == {}
    assert isinstance(data["timestamp"], float)
