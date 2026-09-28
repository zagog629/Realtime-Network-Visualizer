from __future__ import annotations

import time
from dataclasses import dataclass, field

from .arpsweep import Device

# Fields worth announcing as an "updated" event when they change between
# sweeps. `last_seen` deliberately isn't one of these. it changes on every
# sweep a device responds to, and that's not something anyone watching the
# feed needs to hear about.
WATCHED_FIELDS = ("ip", "hostname", "vendor")

JOINED = "joined"
LEFT = "left"
UPDATED = "updated"


@dataclass
class DeviceEvent:
    type: str  # JOINED | LEFT | UPDATED
    device: Device
    changes: dict[str, dict[str, str]] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "timestamp": self.timestamp,
            "device": self.device.to_dict(),
            "changes": self.changes,
        }


def diff_snapshots(
    previous: dict[str, Device], current: dict[str, Device]
) -> list[DeviceEvent]:
    """Compare two `{mac: Device}` snapshots and return what changed.

    - A MAC in `current` but not `previous` -> a `joined` event.
    - A MAC in `previous` but not `current` -> a `left` event (device is the
      last known record for that MAC, since it's no longer answering).
    - A MAC in both, with a watched field different -> an `updated` event
      carrying an {field: {old, new}} map of just the fields that changed.
    """
    events: list[DeviceEvent] = []

    for mac in current.keys() - previous.keys():
        events.append(DeviceEvent(JOINED, current[mac]))

    for mac in previous.keys() - current.keys():
        events.append(DeviceEvent(LEFT, previous[mac]))

    for mac in current.keys() & previous.keys():
        old, new = previous[mac], current[mac]
        changes = {}
        for name in WATCHED_FIELDS:
            old_val, new_val = getattr(old, name), getattr(new, name)
            if new_val and new_val != old_val:
                changes[name] = {"old": old_val, "new": new_val}
        if changes:
            events.append(DeviceEvent(UPDATED, new, changes))

    events.sort(key=lambda e: (e.type != JOINED, e.type != UPDATED, e.device.ip))
    return events
