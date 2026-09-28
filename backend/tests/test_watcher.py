import asyncio
import ipaddress

from netviz.arpsweep import Device
from netviz.events import JOINED, LEFT
from netviz.store import DeviceStore
from netviz.watcher import ArpWatcher

NETWORK = ipaddress.ip_network("192.168.1.0/24")


def _dev(ip, mac, hostname="", vendor=""):
    return Device(ip=ip, mac=mac, hostname=hostname, vendor=vendor, last_seen=100.0)


class Sequence:
    """A fake sweep_fn that returns a different canned snapshot each call
    (and repeats the last one), the same role FakeOUI/monkeypatched srp play
    in the discovery tests -- no scapy, no network, no root required."""

    def __init__(self, snapshots):
        self.snapshots = snapshots
        self.calls = 0

    def __call__(self, *args, **kwargs):
        snap = self.snapshots[min(self.calls, len(self.snapshots) - 1)]
        self.calls += 1
        return snap


def make_watcher(tmp_path, sweep_fn, interval=0.05, **kwargs):
    store = DeviceStore(tmp_path / "netviz.db")
    return ArpWatcher(network=NETWORK, store=store, sweep_fn=sweep_fn, interval=interval, **kwargs)

# --------------------------------------------------------------------------
# _sweep_once: the synchronous diff-and-persist step, tested directly
# --------------------------------------------------------------------------

def test_first_sweep_emits_joined_for_every_device(tmp_path):
    devices = [_dev("192.168.1.10", "aa:bb:cc:00:00:01")]
    watcher = make_watcher(tmp_path, Sequence([devices]))

    events = watcher._sweep_once()

    assert [e.type for e in events] == [JOINED]
    assert watcher.store.all_devices()[0].ip == "192.168.1.10"


def test_diff_across_two_sweeps_produces_left_and_joined(tmp_path):
    stay, leave, join = "aa:00:00:00:00:01", "bb:00:00:00:00:02", "cc:00:00:00:00:03"
    sweep_fn = Sequence([
        [_dev("192.168.1.1", stay), _dev("192.168.1.2", leave)],
        [_dev("192.168.1.1", stay), _dev("192.168.1.3", join)],
    ])
    watcher = make_watcher(tmp_path, sweep_fn)

    first = watcher._sweep_once()
    second = watcher._sweep_once()

    assert {e.type for e in first} == {JOINED}
    assert {e.type for e in second} == {LEFT, JOINED}
    macs_left = {e.device.mac for e in second if e.type == LEFT}
    macs_joined = {e.device.mac for e in second if e.type == JOINED}
    assert macs_left == {leave}
    assert macs_joined == {join}


def test_left_device_is_marked_offline_in_store(tmp_path):
    mac = "aa:bb:cc:00:00:01"
    sweep_fn = Sequence([[_dev("192.168.1.1", mac)], []])
    watcher = make_watcher(tmp_path, sweep_fn)

    watcher._sweep_once()
    watcher._sweep_once()

    assert watcher.store.online_devices() == {}
    assert len(watcher.store.all_devices()) == 1  # still in history


def test_resolver_miss_does_not_blank_a_known_hostname(tmp_path):
    mac = "aa:bb:cc:00:00:01"
    sweep_fn = Sequence([
        [_dev("192.168.1.1", mac, hostname="pi.lan")],
        [_dev("192.168.1.1", mac, hostname="")],  # DNS hiccup this round
    ])
    watcher = make_watcher(tmp_path, sweep_fn)

    watcher._sweep_once()
    events = watcher._sweep_once()

    assert events == []  # no spurious "updated" for a blanked-out hostname
    assert watcher._last[mac].hostname == "pi.lan"


def test_restart_seeds_baseline_from_store(tmp_path):
    db_path = tmp_path / "netviz.db"
    mac = "aa:bb:cc:00:00:01"
    DeviceStore(db_path).upsert_device(_dev("192.168.1.10", mac))

    # Fresh ArpWatcher + fresh DeviceStore instance on the same file, as
    # happens on a real process restart.
    watcher = ArpWatcher(
        network=NETWORK,
        store=DeviceStore(db_path),
        sweep_fn=Sequence([[_dev("192.168.1.10", mac)]]),
    )

    events = watcher._sweep_once()

    assert events == []  # already known online; not treated as a fresh join

# --------------------------------------------------------------------------
# The async loop: start/stop, error resilience, subscriber delivery
# --------------------------------------------------------------------------

def test_sweep_exception_is_caught_and_recorded(tmp_path):
    def boom(*args, **kwargs):
        raise PermissionError("Operation not permitted")

    watcher = make_watcher(tmp_path, boom)

    async def scenario():
        await watcher.start()
        await asyncio.sleep(0.12)  # a couple of intervals
        await watcher.stop()

    asyncio.run(scenario())

    assert watcher.last_error == "Operation not permitted"
    assert not watcher.running


def test_subscriber_receives_events_from_the_loop(tmp_path):
    devices = [_dev("192.168.1.10", "aa:bb:cc:00:00:01")]
    watcher = make_watcher(tmp_path, Sequence([devices]))
    queue = watcher.subscribe()

    async def scenario():
        await watcher.start()
        event = await asyncio.wait_for(queue.get(), timeout=2.0)
        await watcher.stop()
        return event

    event = asyncio.run(scenario())

    assert event.type == JOINED
    assert event.device.ip == "192.168.1.10"


def test_unsubscribe_removes_the_queue(tmp_path):
    watcher = make_watcher(tmp_path, Sequence([[]]))
    queue = watcher.subscribe()

    watcher.unsubscribe(queue)

    assert queue not in watcher._subscribers


def test_stop_before_start_is_a_no_op(tmp_path):
    watcher = make_watcher(tmp_path, Sequence([[]]))
    asyncio.run(watcher.stop())  # should not raise
    assert not watcher.running
