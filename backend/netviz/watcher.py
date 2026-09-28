from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from typing import Callable

from .arpsweep import Device, arp_sweep
from .events import DeviceEvent, diff_snapshots
from .store import DeviceStore

logger = logging.getLogger("netviz.watcher")

SweepFn = Callable[..., list[Device]]


class ArpWatcher:
    """Owns the scan loop, the last-known snapshot, and event subscribers."""

    def __init__(
        self,
        network: ipaddress.IPv4Network,
        iface: str | None = None,
        interval: float = 20.0,
        timeout: float = 2.0,
        retries: int = 2,
        store: DeviceStore | None = None,
        sweep_fn: SweepFn = arp_sweep,
    ):
        self.network = network
        self.iface = iface
        self.interval = interval
        self.timeout = timeout
        self.retries = retries
        self.store = store or DeviceStore()
        self._sweep_fn = sweep_fn

        self._last: dict[str, Device] = self.store.online_devices()
        self._subscribers: set[asyncio.Queue] = set()
        self._task: asyncio.Task | None = None
        self._stop_event: asyncio.Event | None = None
        self.last_error: str | None = None
        self.last_scan_at: float | None = None

    # --------------------------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------------------------

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="netviz-watcher")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop_event.set()
        self._task.cancel()
        try:
            await self._task
        except (asyncio.CancelledError, Exception):
            pass
        self._task = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    # --------------------------------------------------------------------------
    # Subscriptions (one asyncio.Queue per connected websocket)
    # --------------------------------------------------------------------------

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    # --------------------------------------------------------------------------
    # Loop
    # --------------------------------------------------------------------------

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        while not self._stop_event.is_set():
            try:
                events = await loop.run_in_executor(None, self._sweep_once)
                self.last_error = None
            except Exception as exc:  # a bad sweep shouldn't kill the loop
                logger.warning("sweep failed: %s", exc)
                self.last_error = str(exc)
                events = []

            if events:
                await self._broadcast(events)

            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                pass  # normal: interval elapsed, loop again

    def _sweep_once(self) -> list[DeviceEvent]:
        """Blocking: runs in a worker thread. One full sweep -> diff -> persist."""
        devices = self._sweep_fn(
            self.network, iface=self.iface, timeout=self.timeout, retries=self.retries
        )
        self.last_scan_at = time.time()

        current: dict[str, Device] = {}
        for dev in devices:
            prev = self._last.get(dev.mac)
            # Reverse DNS can miss on any given round (sleeping hosts, slow
            # resolvers); don't blank out a hostname we already know just
            # because this round's lookup came back empty.
            if not dev.hostname and prev and prev.hostname:
                dev.hostname = prev.hostname
            current[dev.mac] = dev

        events = diff_snapshots(self._last, current)

        for event in events:
            self.store.record_event(event)
            if event.type == "left":
                self.store.mark_offline(event.device.mac, event.timestamp)
            else:
                self.store.upsert_device(event.device, online=True)

        for mac, dev in current.items():
            self.store.touch_last_seen(mac, dev.last_seen)

        self._last = current
        return events

    async def _broadcast(self, events: list[DeviceEvent]) -> None:
        stale = []
        for queue in self._subscribers:
            for event in events:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    stale.append(queue)
                    break
        for queue in stale:
            self._subscribers.discard(queue)
