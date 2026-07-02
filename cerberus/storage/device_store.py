# deps: none — sqlite3 is stdlib
"""
storage/device_store.py

ONLY module in the entire project allowed to open a SQLite connection.

Schema (Phase 1+2): devices, scan_history tables.
Schema (Phase 3, module 13): alerts_log table for persistent alert history.

mDNS hostname enrichment: update_hostname_from_mdns() — only writes if
the device currently has NO hostname. mDNS is a secondary signal, never
overwrites what Nmap's NetBIOS/SMB scripts already found.

Vendor enrichment (this revision): update_vendor_if_missing() — same
pattern as the mDNS fix. Nmap ships its own small internal MAC-vendor
database, separate from and much smaller than Cerberus's own
VendorLookup (39k+ real IEEE OUI entries). When Nmap comes up empty on
vendor for a device, the scheduler (which already holds a VendorLookup
instance for alert-message tagging) can now backfill it here. Only
writes if vendor is currently NULL/empty — never overwrites a vendor
Nmap DID successfully identify, even if Cerberus's DB would give a
differently-worded name for the same OUI.

MAC normalization: all MACs stored and keyed lowercase.
"""

import sqlite3
import threading
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional

logger = logging.getLogger("cerberus.storage.device_store")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DeviceStore:
    """
    SQLite-backed store for discovered network devices.

    Usage:
        store = DeviceStore("data/devices.db")
        store.upsert({...})
        store.get("aa:bb:cc:dd:ee:ff")
        store.set_trust("aa:bb:cc:dd:ee:ff", True)
        store.counts()
        store.log_alert(mac, ip, verdict, network, message_summary)
        store.get_recent_alerts(limit=50)
        store.update_hostname_from_mdns(ip, hostname)
        store.update_vendor_if_missing(mac, vendor)
    """

    def __init__(self, db_path: str = "data/devices.db"):
        self.db_path = db_path
        self._lock   = threading.Lock()
        self._conn   = self._connect()
        self._init_schema()
        logger.info(f"DeviceStore ready — {db_path}")

    # ------------------------------------------------------------------
    # Public API — devices
    # ------------------------------------------------------------------

    def upsert(self, device: Dict) -> None:
        """
        Insert or update a device keyed on MAC address.
        Also appends a row to scan_history.
        """
        mac = device.get("mac")
        if not mac:
            logger.debug(f"upsert skipped — no MAC for IP {device.get('ip', '?')}")
            return

        mac = mac.lower()

        ip          = device.get("ip", "")
        network     = device.get("network", "")
        scanner     = device.get("scanner", "")
        vendor      = device.get("vendor")
        hostname    = device.get("hostname")
        os_name     = device.get("os")
        os_accuracy = device.get("os_accuracy")
        interface   = device.get("interface", "")
        http_title  = device.get("http_title")
        ssh_hostkey = device.get("ssh_hostkey")

        ports_raw  = device.get("open_ports", [])
        open_ports = ",".join(str(p) for p in ports_raw) if ports_raw else ""

        services_raw = device.get("services", {})
        services_str = json.dumps(services_raw) if services_raw else ""

        banners_raw = device.get("banners", {})
        banners_str = json.dumps(banners_raw) if banners_raw else ""

        now = _now()

        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO devices
                    (mac, ip, network, vendor, hostname, os, os_accuracy,
                     open_ports, services, http_title, ssh_hostkey, banners,
                     interface, scanner, trusted, first_seen, last_seen)
                VALUES
                    (?,   ?,  ?,       ?,      ?,        ?,  ?,
                     ?,          ?,        ?,          ?,           ?,
                     ?,         ?,       0,       ?,          ?)
                """,
                (mac, ip, network, vendor, hostname, os_name, os_accuracy,
                 open_ports, services_str, http_title, ssh_hostkey, banners_str,
                 interface, scanner, now, now),
            )

            self._conn.execute(
                """
                UPDATE devices SET
                    ip          = ?,
                    network     = ?,
                    vendor      = COALESCE(?, vendor),
                    hostname    = COALESCE(?, hostname),
                    os          = COALESCE(?, os),
                    os_accuracy = COALESCE(?, os_accuracy),
                    open_ports  = CASE WHEN ? != '' THEN ? ELSE open_ports END,
                    services    = CASE WHEN ? != '' THEN ? ELSE services END,
                    http_title  = COALESCE(?, http_title),
                    ssh_hostkey = COALESCE(?, ssh_hostkey),
                    banners     = CASE WHEN ? != '' THEN ? ELSE banners END,
                    interface   = ?,
                    scanner     = ?,
                    last_seen   = ?
                WHERE mac = ?
                """,
                (ip, network,
                 vendor, hostname, os_name, os_accuracy,
                 open_ports, open_ports,
                 services_str, services_str,
                 http_title, ssh_hostkey,
                 banners_str, banners_str,
                 interface, scanner, now,
                 mac),
            )

            self._conn.execute(
                """
                INSERT INTO scan_history
                    (mac, ip, network, scanner, interface, seen_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (mac, ip, network, scanner, interface, now),
            )

            self._conn.commit()

        logger.debug(f"upsert → {mac} ({ip}) via {scanner}")

    def get(self, mac: str) -> Optional[Dict]:
        """Fetch one device by MAC. Returns None if not found."""
        mac = mac.lower()
        row = self._conn.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_all(self) -> List[Dict]:
        """All devices ordered by last_seen descending."""
        rows = self._conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC"
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_by_trust(self, trusted: bool) -> List[Dict]:
        """Filter devices by trust status."""
        rows = self._conn.execute(
            "SELECT * FROM devices WHERE trusted = ? ORDER BY last_seen DESC",
            (1 if trusted else 0,),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def set_trust(self, mac: str, trusted: bool) -> bool:
        """Mark a device trusted or untrusted. Returns False if MAC unknown."""
        mac = mac.lower()
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE devices SET trusted = ? WHERE mac = ?",
                (1 if trusted else 0, mac),
            )
            self._conn.commit()

        if cursor.rowcount == 0:
            logger.warning(f"set_trust: {mac} not found.")
            return False

        logger.info(f"Device {mac} marked {'trusted' if trusted else 'untrusted'}.")
        return True

    def set_label(self, mac: str, label: str) -> bool:
        """Assign a human-readable name to a device. "" clears the label."""
        mac = mac.lower()
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE devices SET label = ? WHERE mac = ?",
                (label or None, mac),
            )
            self._conn.commit()

        if cursor.rowcount == 0:
            logger.warning(f"set_label: MAC {mac} not found.")
            return False

        logger.info(f"Device {mac} labelled '{label}'.")
        return True

    def update_hostname_from_mdns(self, ip: str, hostname: str) -> bool:
        """
        Set hostname for whichever device currently has this IP — but
        ONLY if it doesn't already have a hostname.
        """
        if not ip or not hostname:
            return False

        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE devices
                SET hostname = ?
                WHERE ip = ? AND (hostname IS NULL OR hostname = '')
                """,
                (hostname, ip),
            )
            self._conn.commit()

        updated = cursor.rowcount > 0
        if updated:
            logger.debug(f"[mdns] hostname set for {ip} → {hostname}")
        return updated

    def update_vendor_if_missing(self, mac: str, vendor: str) -> bool:
        """
        Set vendor for a device — but ONLY if it doesn't already have one.

        Used by scheduler to backfill vendor from Cerberus's own richer
        OUI database (39k+ entries) when Nmap's smaller internal vendor
        DB came up empty. Never overwrites a vendor Nmap DID find, even
        if the wording would differ (e.g. Nmap says "Apple" and our DB
        says "Apple, Inc." — Nmap's answer wins if it has one at all;
        this method only fills genuine gaps, never second-guesses).

        Args:
            mac    : Device MAC address (will be lowercased).
            vendor : Vendor name string from VendorLookup.lookup().

        Returns:
            True if a device row was updated, False if MAC unknown,
            it already had a vendor, or mac/vendor was empty.
        """
        if not mac or not vendor:
            return False
        mac = mac.lower()

        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE devices
                SET vendor = ?
                WHERE mac = ? AND (vendor IS NULL OR vendor = '')
                """,
                (vendor, mac),
            )
            self._conn.commit()

        updated = cursor.rowcount > 0
        if updated:
            logger.debug(f"[vendor-enrich] {mac} → {vendor}")
        return updated

    def delete(self, mac: str) -> bool:
        """Remove a device and its history. Returns False if not found."""
        mac = mac.lower()
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM devices WHERE mac = ?", (mac,)
            )
            self._conn.execute(
                "DELETE FROM scan_history WHERE mac = ?", (mac,)
            )
            self._conn.commit()

        if cursor.rowcount == 0:
            logger.warning(f"delete: {mac} not found.")
            return False

        logger.info(f"Device {mac} deleted.")
        return True

    def counts(self) -> Dict[str, int]:
        """Total / trusted / untrusted snapshot."""
        row = self._conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN trusted=1 THEN 1 ELSE 0 END) AS trusted,
                SUM(CASE WHEN trusted=0 THEN 1 ELSE 0 END) AS untrusted
            FROM devices
            """
        ).fetchone()
        return {
            "total":     row[0] or 0,
            "trusted":   row[1] or 0,
            "untrusted": row[2] or 0,
        }

    def get_history(self, mac: str, limit: int = 20) -> List[Dict]:
        """Recent scan_history rows for one MAC."""
        mac = mac.lower()
        rows = self._conn.execute(
            """
            SELECT mac, ip, network, scanner, interface, seen_at
            FROM scan_history WHERE mac = ?
            ORDER BY seen_at DESC LIMIT ?
            """,
            (mac, limit),
        ).fetchall()
        cols = ["mac", "ip", "network", "scanner", "interface", "seen_at"]
        return [dict(zip(cols, r)) for r in rows]

    # ------------------------------------------------------------------
    # Public API — alert history
    # ------------------------------------------------------------------

    def log_alert(
        self,
        mac: str,
        ip: str,
        verdict: str,
        network: str = "",
        message_summary: str = "",
        channels_fired: int = 0,
    ) -> None:
        """Append one record to the persistent alert log. Called ONLY by scheduler."""
        mac = (mac or "").lower()
        now = _now()

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO alerts_log
                    (mac, ip, network, verdict, message_summary, channels_fired, fired_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (mac, ip, network, verdict, message_summary, channels_fired, now),
            )
            self._conn.commit()

        logger.debug(f"alert logged → {mac} ({ip}) verdict={verdict}")

    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Most recent fired alerts, newest first."""
        rows = self._conn.execute(
            """
            SELECT mac, ip, network, verdict, message_summary, channels_fired, fired_at
            FROM alerts_log
            ORDER BY fired_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        cols = ["mac", "ip", "network", "verdict", "message_summary", "channels_fired", "fired_at"]
        return [dict(zip(cols, r)) for r in rows]

    def alert_counts(self) -> Dict[str, int]:
        """Lifetime alert count snapshot — total + per verdict type."""
        row = self._conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN verdict='untrusted_new' THEN 1 ELSE 0 END) AS new_unknown,
                SUM(CASE WHEN verdict='untrusted_returning' THEN 1 ELSE 0 END) AS returning_unknown
            FROM alerts_log
            """
        ).fetchone()
        return {
            "total":              row[0] or 0,
            "new_unknown":        row[1] or 0,
            "returning_unknown":  row[2] or 0,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()
        logger.info("DeviceStore connection closed.")

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        import os
        os.makedirs(
            os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".",
            exist_ok=True,
        )
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    mac         TEXT PRIMARY KEY,
                    ip          TEXT NOT NULL,
                    network     TEXT NOT NULL,
                    vendor      TEXT,
                    hostname    TEXT,
                    os          TEXT,
                    os_accuracy INTEGER,
                    open_ports  TEXT,
                    services    TEXT,
                    http_title  TEXT,
                    ssh_hostkey TEXT,
                    banners     TEXT,
                    interface   TEXT,
                    scanner     TEXT,
                    trusted     INTEGER NOT NULL DEFAULT 0,
                    label       TEXT,
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac       TEXT NOT NULL,
                    ip        TEXT NOT NULL,
                    network   TEXT NOT NULL,
                    scanner   TEXT NOT NULL,
                    interface TEXT,
                    seen_at   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts_log (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac             TEXT NOT NULL,
                    ip              TEXT NOT NULL,
                    network         TEXT,
                    verdict         TEXT NOT NULL,
                    message_summary TEXT,
                    channels_fired  INTEGER NOT NULL DEFAULT 0,
                    fired_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_history_mac      ON scan_history(mac);
                CREATE INDEX IF NOT EXISTS idx_history_seen_at  ON scan_history(seen_at);
                CREATE INDEX IF NOT EXISTS idx_devices_trusted  ON devices(trusted);
                CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
                CREATE INDEX IF NOT EXISTS idx_devices_ip       ON devices(ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_fired_at  ON alerts_log(fired_at);
                CREATE INDEX IF NOT EXISTS idx_alerts_mac       ON alerts_log(mac);
                """
            )
            self._conn.commit()
        logger.debug("Schema initialised.")

        try:
            with self._lock:
                self._conn.execute("ALTER TABLE devices ADD COLUMN label TEXT")
                self._conn.commit()
                logger.info("Migration: added 'label' column to devices table.")
        except Exception:
            pass

    def _row_to_dict(self, row) -> Dict:
        cols = [
            "mac", "ip", "network", "vendor", "hostname", "os", "os_accuracy",
            "open_ports", "services", "http_title", "ssh_hostkey", "banners",
            "interface", "scanner", "trusted", "label", "first_seen", "last_seen",
        ]
        d = dict(zip(cols, row))

        raw = d.get("open_ports") or ""
        d["open_ports"] = (
            [int(p) for p in raw.split(",") if p.strip().isdigit()]
            if raw else []
        )

        for field_name in ("services", "banners"):
            raw = d.get(field_name) or ""
            try:
                d[field_name] = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                d[field_name] = {}

        d["trusted"] = bool(d["trusted"])
        return d


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile, os, json as _json
    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")

    with tempfile.TemporaryDirectory() as tmp:
        store = DeviceStore(os.path.join(tmp, "test.db"))

        store.upsert({
            "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.10",
            "network": "192.168.1.0/24", "scanner": "scapy",
        })
        store.upsert({
            "mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.1.10",
            "network": "192.168.1.0/24", "scanner": "nmap_aggressive",
            "vendor": "Apple Inc.", "os": "macOS 13.x", "os_accuracy": 92,
            "open_ports": [22, 443, 8080],
            "services": {
                22:   {"name": "ssh",   "product": "OpenSSH", "version": "8.9", "extra": ""},
                443:  {"name": "https", "product": "nginx",   "version": "1.24","extra": ""},
                8080: {"name": "http",  "product": "",        "version": "",    "extra": ""},
            },
            "http_title": "My Home Router",
            "ssh_hostkey": "ecdsa-sha2-nistp256 AAAA...",
            "banners": {22: "SSH-2.0-OpenSSH_8.9"},
        })

        c = store.counts()
        assert c["total"] == 1
        print(f"[PASS] Counts: {c}")

        d = store.get("aa:bb:cc:dd:ee:01")
        assert d["os"] == "macOS 13.x"
        assert 22 in d["open_ports"]
        print(f"[PASS] Device merged correctly: os={d['os']}")

        hist = store.get_history("aa:bb:cc:dd:ee:01")
        assert len(hist) == 2
        print(f"[PASS] History: {len(hist)} rows")

        store.log_alert(
            mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10",
            verdict="untrusted_new", network="192.168.1.0/24",
            message_summary="Unknown Apple device on 192.168.1.10",
            channels_fired=1,
        )
        alerts = store.get_recent_alerts(limit=10)
        assert len(alerts) == 1
        print(f"[PASS] Recent alerts: {alerts}")

        ac = store.alert_counts()
        assert ac["total"] == 1
        print(f"[PASS] Alert counts: {ac}")

        # --- mDNS hostname enrichment ---
        updated = store.update_hostname_from_mdns("192.168.1.10", "Harshs-iPhone")
        assert updated is True
        d = store.get("aa:bb:cc:dd:ee:01")
        assert d["hostname"] == "Harshs-iPhone"
        print(f"[PASS] mDNS hostname set: {d['hostname']}")

        updated_again = store.update_hostname_from_mdns("192.168.1.10", "SomeOtherName")
        assert updated_again is False
        print("[PASS] mDNS did not overwrite existing hostname")

        updated_none = store.update_hostname_from_mdns("10.0.0.99", "Nobody")
        assert updated_none is False
        print("[PASS] mDNS update on unknown IP → False, no crash")

        # --- vendor enrichment (new) ---
        # This device already has vendor="Apple Inc." from the upsert above —
        # should NOT be overwritten.
        v_updated = store.update_vendor_if_missing("aa:bb:cc:dd:ee:01", "Some Other Vendor")
        assert v_updated is False
        d = store.get("aa:bb:cc:dd:ee:01")
        assert d["vendor"] == "Apple Inc."
        print(f"[PASS] vendor enrichment did not overwrite existing vendor: {d['vendor']}")

        # New device with NO vendor set — should update.
        store.upsert({
            "mac": "bb:cc:dd:ee:ff:02", "ip": "192.168.1.30",
            "network": "192.168.1.0/24", "scanner": "scapy",
        })
        v_updated2 = store.update_vendor_if_missing("bb:cc:dd:ee:ff:02", "TP-Link Technologies")
        assert v_updated2 is True
        d2 = store.get("bb:cc:dd:ee:ff:02")
        assert d2["vendor"] == "TP-Link Technologies"
        print(f"[PASS] vendor enrichment filled empty vendor: {d2['vendor']}")

        v_updated_unknown = store.update_vendor_if_missing("ff:ff:ff:ff:ff:ff", "Nobody")
        assert v_updated_unknown is False
        print("[PASS] vendor enrichment on unknown MAC → False, no crash")

        store.close()
        print("\nAll assertions passed.")