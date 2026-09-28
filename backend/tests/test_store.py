from netviz.arpsweep import Device
from netviz.events import JOINED, LEFT, DeviceEvent
from netviz.store import DeviceStore


def _dev(ip, mac, hostname="", vendor="", last_seen=100.0):
    return Device(ip=ip, mac=mac, hostname=hostname, vendor=vendor, last_seen=last_seen)


def test_upsert_then_all_devices(tmp_path):
    store = DeviceStore(tmp_path / "netviz.db")
    store.upsert_device(_dev("192.168.1.10", "aa:bb:cc:00:00:01", hostname="pi.lan"))

    devices = store.all_devices()

    assert len(devices) == 1
    assert devices[0].ip == "192.168.1.10"
    assert devices[0].hostname == "pi.lan"


def test_upsert_is_an_update_on_conflict(tmp_path):
    store = DeviceStore(tmp_path / "netviz.db")
    mac = "aa:bb:cc:00:00:01"
    store.upsert_device(_dev("192.168.1.10", mac, last_seen=100.0))
    store.upsert_device(_dev("192.168.1.11", mac, last_seen=200.0))  # DHCP moved it

    devices = store.all_devices()

    assert len(devices) == 1
    assert devices[0].ip == "192.168.1.11"
    assert devices[0].last_seen == 200.0


def test_mark_offline_excludes_from_online_devices(tmp_path):
    store = DeviceStore(tmp_path / "netviz.db")
    mac = "aa:bb:cc:00:00:01"
    store.upsert_device(_dev("192.168.1.10", mac))

    store.mark_offline(mac, when=150.0)

    assert store.online_devices() == {}
    all_devices = store.all_devices()
    assert len(all_devices) == 1  # still in history, just not online


def test_online_devices_keyed_by_mac(tmp_path):
    store = DeviceStore(tmp_path / "netviz.db")
    store.upsert_device(_dev("192.168.1.10", "aa:bb:cc:00:00:01"))
    store.upsert_device(_dev("192.168.1.11", "aa:bb:cc:00:00:02"))

    online = store.online_devices()

    assert set(online) == {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}


def test_record_event_and_recent_events(tmp_path):
    store = DeviceStore(tmp_path / "netviz.db")
    dev = _dev("192.168.1.10", "aa:bb:cc:00:00:01")
    store.record_event(DeviceEvent(JOINED, dev, timestamp=1.0))
    store.record_event(DeviceEvent(LEFT, dev, timestamp=2.0))

    events = store.recent_events(limit=10)

    assert len(events) == 2
    assert events[0]["type"] == LEFT  # newest first
    assert events[1]["type"] == JOINED


def test_history_survives_reopening_the_same_file(tmp_path):
    """Simulates a restart: a fresh DeviceStore instance on the same path
    should see everything the previous instance wrote."""
    db_path = tmp_path / "netviz.db"

    first = DeviceStore(db_path)
    first.upsert_device(_dev("192.168.1.10", "aa:bb:cc:00:00:01", hostname="pi.lan"))
    first.record_event(DeviceEvent(JOINED, _dev("192.168.1.10", "aa:bb:cc:00:00:01")))

    second = DeviceStore(db_path)  # fresh instance, same file

    assert len(second.all_devices()) == 1
    assert second.all_devices()[0].hostname == "pi.lan"
    assert len(second.recent_events()) == 1
