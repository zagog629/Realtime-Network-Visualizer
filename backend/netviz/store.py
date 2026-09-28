from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .arpsweep import Device
from .events import DeviceEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT NOT NULL,
    hostname    TEXT NOT NULL DEFAULT '',
    vendor      TEXT NOT NULL DEFAULT '',
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    online      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    type    TEXT NOT NULL,
    mac     TEXT NOT NULL,
    ip      TEXT NOT NULL,
    changes TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
"""


class DeviceStore:
    """Thin wrapper around a SQLite file. One instance per running process."""

    def __init__(self, path: str | Path = "netviz.db"):
        self.path = str(path)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    # --------------------------------------------------------------------------
    # Writes
    # --------------------------------------------------------------------------

    def upsert_device(self, device: Device, online: bool = True) -> None:
        """Insert or update a device's current record."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen, online)
                VALUES (:mac, :ip, :hostname, :vendor, :last_seen, :last_seen, :online)
                ON CONFLICT(mac) DO UPDATE SET
                    ip=excluded.ip,
                    hostname=excluded.hostname,
                    vendor=excluded.vendor,
                    last_seen=excluded.last_seen,
                    online=excluded.online
                """,
                {
                    "mac": device.mac,
                    "ip": device.ip,
                    "hostname": device.hostname,
                    "vendor": device.vendor,
                    "last_seen": device.last_seen,
                    "online": int(online),
                },
            )

    def touch_last_seen(self, mac: str, last_seen: float) -> None:
        """Bump last_seen for a device that's still online but unchanged."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE devices SET last_seen = ?, online = 1 WHERE mac = ?",
                (last_seen, mac),
            )

    def mark_offline(self, mac: str, when: float | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE devices SET online = 0, last_seen = ? WHERE mac = ?",
                (when if when is not None else time.time(), mac),
            )

    def record_event(self, event: DeviceEvent) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events (ts, type, mac, ip, changes) VALUES (?, ?, ?, ?, ?)",
                (
                    event.timestamp,
                    event.type,
                    event.device.mac,
                    event.device.ip,
                    json.dumps(event.changes),
                ),
            )

    # --------------------------------------------------------------------------
    # Reads
    # --------------------------------------------------------------------------

    def all_devices(self, online_only: bool = False) -> list[Device]:
        query = "SELECT * FROM devices"
        if online_only:
            query += " WHERE online = 1"
        query += " ORDER BY ip"
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return [_row_to_device(r) for r in rows]

    def online_devices(self) -> dict[str, Device]:
        """The last known online snapshot, keyed by MAC.

        Used to seed the watcher's diff baseline on startup so a restart
        doesn't fire a spurious 'joined' event for every device that was
        already known to be on the network.
        """
        return {d.mac: d for d in self.all_devices(online_only=True)}

    def recent_events(self, limit: int = 100) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {
                "type": r["type"],
                "timestamp": r["ts"],
                "mac": r["mac"],
                "ip": r["ip"],
                "changes": json.loads(r["changes"]),
            }
            for r in rows
        ]


def _row_to_device(row: sqlite3.Row) -> Device:
    return Device(
        ip=row["ip"],
        mac=row["mac"],
        hostname=row["hostname"],
        vendor=row["vendor"],
        last_seen=row["last_seen"],
    )
