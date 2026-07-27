"""
The only module in the project allowed to open a SQLite connection.

Schema covers devices and scan_history from early on, alerts_log for
persistent alert history, and used_tokens for the email Trust/Block
feature — tracking single-use Trust confirmation tokens so a token can
only ever be redeemed once (protects against email prefetch scanners,
forwarded emails, or a link clicked twice).

update_hostname_from_mdns() only writes if the device currently has no
hostname — mDNS is a secondary signal and should never overwrite what
Nmap's NetBIOS/SMB scripts already found. update_vendor_if_missing()
follows the same pattern: Nmap ships its own small internal MAC-vendor
database, much smaller than Cerberus's own VendorLookup (39k+ real
IEEE OUI entries), so when Nmap comes up empty on vendor, the
scheduler (which already holds a VendorLookup instance for alert
tagging) can backfill it here — but only if vendor is currently NULL,
never overwriting something Nmap did successfully identify even if
Cerberus's DB would word it differently for the same OUI.

MACs are stored and keyed lowercase throughout.

link_tokens.py generates a signed, time-limited token per MAC when an
alert email goes out; this module doesn't verify signatures or expiry
(that's link_tokens.py's job, pure crypto with no DB dependency) — its
only job is the single-use half: recording that a token_id has been
redeemed so a second click, or a prefetch scanner's first click, gets
rejected. mark_token_used() is atomic via INSERT with a UNIQUE
constraint on token_id, so a race between two near-simultaneous
requests for the same token can only ever let one succeed; the other
gets rowcount 0 / IntegrityError, both handled the same way —
"already used."
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
        store.mark_token_used(token_id, mac, purpose, expires_at)
        store.is_token_used(token_id)
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
        model       = device.get("model")
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
                    (mac, ip, network, vendor, hostname, model, os, os_accuracy,
                     open_ports, services, http_title, ssh_hostkey, banners,
                     interface, scanner, trusted, first_seen, last_seen)
                VALUES
                    (?,   ?,  ?,       ?,      ?,        ?,     ?,  ?,
                     ?,          ?,        ?,          ?,           ?,
                     ?,         ?,       0,       ?,          ?)
                """,
                (mac, ip, network, vendor, hostname, model, os_name, os_accuracy,
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
                    model       = COALESCE(?, model),
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
                 vendor, hostname, model, os_name, os_accuracy,
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

    def update_model_from_ip(self, ip: str, model: str) -> bool:
        """
        Set the hardware model string for whichever device currently
        has this IP — but ONLY if it doesn't already have one. IP-keyed
        (not MAC-keyed) because every source of model data so far
        (mDNS TXT records, SSDP device descriptions) is an IP-layer
        signal that never reveals a MAC — same reasoning as
        update_hostname_from_mdns() being IP-keyed rather than MAC-keyed.

        Used by scheduler for:
          - mDNS's "model" field (detection/mdns_discovery.py TXT
            record parsing — e.g. "iPhone14,5", "MacBookPro18,1")
          - SSDP's "model_name" field (detection/ssdp_discovery.py
            device description XML — e.g. "UN55MU8000")

        Args:
            ip    : IP address the sighting came from.
            model : Model string from the discovery source.

        Returns:
            True if a device row was updated, False if no device
            currently has this IP, it already had a model, or
            ip/model was empty.
        """
        if not ip or not model:
            return False

        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE devices
                SET model = ?
                WHERE ip = ? AND (model IS NULL OR model = '')
                """,
                (model, ip),
            )
            self._conn.commit()

        updated = cursor.rowcount > 0
        if updated:
            logger.debug(f"[model-enrich] {ip} → {model}")
        return updated

    def update_vendor_from_ip(self, ip: str, vendor: str) -> bool:
        """
        Set vendor for whichever device currently has this IP — but
        ONLY if it doesn't already have one. IP-keyed sibling of
        update_vendor_if_missing() (which is MAC-keyed, for the OUI
        database backfill). This one exists specifically for SSDP's
        "manufacturer" field (detection/ssdp_discovery.py device
        description XML), which — like all SSDP/mDNS data — is an
        IP-layer signal with no MAC attached.

        Args:
            ip     : IP address the sighting came from.
            vendor : Vendor/manufacturer string from the discovery source.

        Returns:
            True if a device row was updated, False if no device
            currently has this IP, it already had a vendor, or
            ip/vendor was empty.
        """
        if not ip or not vendor:
            return False

        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE devices
                SET vendor = ?
                WHERE ip = ? AND (vendor IS NULL OR vendor = '')
                """,
                (vendor, ip),
            )
            self._conn.commit()

        updated = cursor.rowcount > 0
        if updated:
            logger.debug(f"[vendor-enrich-ip] {ip} → {vendor}")
        return updated

    def update_hostname_by_mac(self, mac: str, hostname: str) -> bool:
        """
        Set hostname for a device by MAC — but ONLY if it doesn't
        already have one. MAC-keyed (unlike update_hostname_from_mdns,
        which is IP-keyed) because DHCP is the one discovery source
        that gives us the device's real MAC directly, in the DHCP
        packet itself — no IP-to-device guessing needed at all. This
        makes DHCP-sourced hostnames the most reliable of the four
        passive discovery signals (mDNS/SSDP/LLMNR are all IP-layer-
        only and rely on whichever device currently holds that IP
        being the right one).

        If the MAC isn't in device_store yet (DHCP sighting arrived
        before Scapy ever discovered this device via ARP), this
        returns False and the sighting is simply not retried later —
        see scheduler.py's DHCP drain worker for why this is an
        accepted, deliberate simplification rather than a bug: in
        practice a device that's actively doing DHCP negotiation is,
        by definition, live on the network, so Scapy's ARP sweep
        (running far more frequently than DHCP negotiations occur)
        will almost always have already discovered it first.

        Args:
            mac      : Device MAC address (will be lowercased).
            hostname : Hostname string from the DHCP sighting.

        Returns:
            True if a device row was updated, False if the MAC is
            unknown, it already had a hostname, or mac/hostname was empty.
        """
        if not mac or not hostname:
            return False
        mac = mac.lower()

        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE devices
                SET hostname = ?
                WHERE mac = ? AND (hostname IS NULL OR hostname = '')
                """,
                (hostname, mac),
            )
            self._conn.commit()

        updated = cursor.rowcount > 0
        if updated:
            logger.debug(f"[dhcp-enrich] {mac} → {hostname}")
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
            SELECT id, mac, ip, network, verdict, message_summary, channels_fired, fired_at
            FROM alerts_log
            ORDER BY fired_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        cols = ["id", "mac", "ip", "network", "verdict", "message_summary", "channels_fired", "fired_at"]
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

    def delete_alert(self, alert_id: int) -> bool:
        """
        Delete one alert from the persistent log by its id (this
        revision — id is now included in get_recent_alerts()'s output
        specifically so the frontend can reference a single alert for
        deletion). Returns False if no alert with that id exists.

        Note: this deletes from the AUDIT LOG (alerts_log), not
        anything related to trust/cooldown state — deleting an alert
        record has no effect on whether that device gets alerted on
        again in the future. It's purely "stop showing me this old
        entry," nothing more.
        """
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM alerts_log WHERE id = ?", (alert_id,)
            )
            self._conn.commit()

        deleted = cursor.rowcount > 0
        if deleted:
            logger.info(f"[alert] Deleted alert id={alert_id}")
        return deleted

    def clear_alerts(self) -> int:
        """
        Delete ALL alerts from the persistent log. Used by the
        dashboard's "clear all" action. Returns the number of rows
        deleted, purely for a confirmation message — no other
        significance.
        """
        with self._lock:
            cursor = self._conn.execute("DELETE FROM alerts_log")
            self._conn.commit()

        deleted = cursor.rowcount
        logger.info(f"[alert] Cleared all alerts ({deleted} row(s)).")
        return deleted

    # ------------------------------------------------------------------
    # Public API — Trust-link token tracking
    # ------------------------------------------------------------------

    def mark_token_used(
        self,
        token_id: str,
        mac: str,
        purpose: str = "trust",
        expires_at: Optional[str] = None,
    ) -> bool:
        """
        Record a token as redeemed. This is the ONLY write path for
        used_tokens — there is no "unmark" method, by design: a
        redeemed single-use token stays redeemed forever.

        Atomic via INSERT with a UNIQUE constraint on token_id: if two
        requests for the same token arrive nearly simultaneously (e.g.
        a legitimate click racing an email-prefetch scanner's fetch),
        SQLite guarantees only one INSERT succeeds. The other raises
        sqlite3.IntegrityError, which this method catches and treats
        identically to "already used" — the caller (api/server.py)
        doesn't need to distinguish a genuine race from a later replay.

        Args:
            token_id   : Unique token identifier (the token's embedded
                         nonce/jti — NOT the full signed token string;
                         see utils/link_tokens.py for what this is).
            mac        : MAC address the token was issued for (stored
                         for audit/debugging, not used for validation
                         here — link_tokens.py already bound the MAC
                         into the signature).
            purpose    : What action this token authorizes — "trust"
                         for now, room to extend later without a schema
                         change.
            expires_at : ISO timestamp the token was valid until, for
                         audit purposes only (this table's own row
                         doesn't expire/get cleaned up based on this —
                         see cleanup_expired_tokens()).

        Returns:
            True if this call newly marked the token as used (i.e. this
            is the first redemption). False if the token was already
            used previously (or by a concurrent racing request).
        """
        if not token_id:
            logger.warning("mark_token_used called with empty token_id.")
            return False

        mac = (mac or "").lower()
        now = _now()

        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO used_tokens
                        (token_id, mac, purpose, used_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (token_id, mac, purpose, now, expires_at),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                logger.info(
                    f"[token] Redemption rejected — token already used "
                    f"(mac={mac}, purpose={purpose})."
                )
                return False

        logger.info(f"[token] Redeemed — mac={mac} purpose={purpose}")
        return True

    def is_token_used(self, token_id: str) -> bool:
        """
        Check whether a token has already been redeemed, WITHOUT
        marking it used. Rarely needed directly — mark_token_used()
        already does an atomic check-and-set in one call, which is
        what api/server.py should normally use. This getter exists for
        read-only status checks (e.g. showing "this link was already
        used" on the confirmation page before the user even clicks the
        confirm button, as a friendlier UX than only finding out on
        submit).
        """
        if not token_id:
            return False
        row = self._conn.execute(
            "SELECT 1 FROM used_tokens WHERE token_id = ?", (token_id,)
        ).fetchone()
        return row is not None

    def cleanup_expired_tokens(self) -> int:
        """
        Delete used_tokens rows whose expires_at has passed. Purely
        housekeeping — a used token past its expiry has no further
        replay value (link_tokens.py's own signature verification
        already rejects expired tokens regardless of what's in this
        table), so this just keeps the table from growing forever.
        Not called automatically anywhere yet; safe to wire into a
        periodic maintenance task later if the table grows large.

        Returns:
            Number of rows deleted.
        """
        now = _now()
        with self._lock:
            cursor = self._conn.execute(
                """
                DELETE FROM used_tokens
                WHERE expires_at IS NOT NULL AND expires_at < ?
                """,
                (now,),
            )
            self._conn.commit()

        deleted = cursor.rowcount
        if deleted:
            logger.info(f"[token] Cleaned up {deleted} expired token record(s).")
        return deleted

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
        # Row factory gives name-based column access (row["mac"], dict(row))
        # instead of position-based. This matters specifically because
        # 'label' and 'model' were/are added via ALTER TABLE ADD COLUMN
        # on any database that existed before those columns were part of
        # CREATE TABLE — SQLite always appends ALTER-added columns at the
        # PHYSICAL END of the table, regardless of where CREATE TABLE
        # declares them for a fresh install. A hardcoded positional
        # column list in _row_to_dict() would silently misalign every
        # field on any database that went through that migration path
        # (verified empirically while adding the 'model' column this
        # revision — this was a real, live bug on any existing Cerberus
        # database, not just a theoretical risk). Name-based access via
        # sqlite3.Row is immune to physical column order entirely, no
        # matter how many ALTER TABLE migrations a given database file
        # has accumulated over time.
        conn.row_factory = sqlite3.Row
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
                    model       TEXT,
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

                CREATE TABLE IF NOT EXISTS used_tokens (
                    token_id    TEXT PRIMARY KEY,
                    mac         TEXT NOT NULL,
                    purpose     TEXT NOT NULL DEFAULT 'trust',
                    used_at     TEXT NOT NULL,
                    expires_at  TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_history_mac      ON scan_history(mac);
                CREATE INDEX IF NOT EXISTS idx_history_seen_at  ON scan_history(seen_at);
                CREATE INDEX IF NOT EXISTS idx_devices_trusted  ON devices(trusted);
                CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
                CREATE INDEX IF NOT EXISTS idx_devices_ip       ON devices(ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_fired_at  ON alerts_log(fired_at);
                CREATE INDEX IF NOT EXISTS idx_alerts_mac       ON alerts_log(mac);
                CREATE INDEX IF NOT EXISTS idx_tokens_expires   ON used_tokens(expires_at);
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

        try:
            with self._lock:
                self._conn.execute("ALTER TABLE devices ADD COLUMN model TEXT")
                self._conn.commit()
                logger.info("Migration: added 'model' column to devices table.")
        except Exception:
            pass

    def _row_to_dict(self, row) -> Dict:
        """
        Convert a sqlite3.Row into a plain dict, then post-process the
        JSON/CSV-encoded fields into their real Python types.

        Uses dict(row) — name-based, via the sqlite3.Row row_factory set
        in _connect() — rather than a hardcoded positional column list.
        This is deliberate: it makes this method correct regardless of
        how many ALTER TABLE migrations a given database file has
        accumulated, and in what order. See _connect()'s comment for
        the specific bug this fixes.
        """
        d = dict(row)

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

        # --- vendor enrichment ---
        v_updated = store.update_vendor_if_missing("aa:bb:cc:dd:ee:01", "Some Other Vendor")
        assert v_updated is False
        d = store.get("aa:bb:cc:dd:ee:01")
        assert d["vendor"] == "Apple Inc."
        print(f"[PASS] vendor enrichment did not overwrite existing vendor: {d['vendor']}")

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

        # --- Trust-link token tracking ---
        from datetime import datetime, timezone, timedelta
        future_expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(timespec="seconds")

        first_use = store.mark_token_used(
            token_id="tok_abc123",
            mac="aa:bb:cc:dd:ee:01",
            purpose="trust",
            expires_at=future_expiry,
        )
        assert first_use is True
        print("[PASS] First token redemption succeeded")

        replay = store.mark_token_used(
            token_id="tok_abc123",
            mac="aa:bb:cc:dd:ee:01",
            purpose="trust",
            expires_at=future_expiry,
        )
        assert replay is False
        print("[PASS] Replayed token rejected (already used)")

        assert store.is_token_used("tok_abc123") is True
        assert store.is_token_used("tok_never_seen") is False
        print("[PASS] is_token_used() reflects redemption state correctly")

        # Expired token cleanup — insert one already-expired row directly
        store.mark_token_used(
            token_id="tok_expired",
            mac="bb:cc:dd:ee:ff:02",
            purpose="trust",
            expires_at="2020-01-01T00:00:00+00:00",  # long past
        )
        deleted = store.cleanup_expired_tokens()
        assert deleted == 1
        assert store.is_token_used("tok_expired") is False
        assert store.is_token_used("tok_abc123") is True  # still-valid-expiry row untouched
        print(f"[PASS] cleanup_expired_tokens() removed {deleted} expired row, left valid ones intact")

        # --- model enrichment (IP-keyed, mirrors update_hostname_from_mdns) ---
        store.upsert({
            "mac": "cc:dd:ee:ff:00:11", "ip": "192.168.1.40",
            "network": "192.168.1.0/24", "scanner": "scapy",
        })
        model_updated = store.update_model_from_ip("192.168.1.40", "iPhone14,5")
        assert model_updated is True
        d3 = store.get("cc:dd:ee:ff:00:11")
        assert d3["model"] == "iPhone14,5"
        print(f"[PASS] update_model_from_ip() filled empty model: {d3['model']}")

        model_not_overwritten = store.update_model_from_ip("192.168.1.40", "SomethingElse")
        assert model_not_overwritten is False
        assert store.get("cc:dd:ee:ff:00:11")["model"] == "iPhone14,5"
        print("[PASS] update_model_from_ip() did not overwrite existing model")

        # --- vendor enrichment from IP (SSDP manufacturer) ---
        store.upsert({
            "mac": "dd:ee:ff:00:11:22", "ip": "192.168.1.41",
            "network": "192.168.1.0/24", "scanner": "scapy",
        })
        vendor_ip_updated = store.update_vendor_from_ip("192.168.1.41", "Samsung")
        assert vendor_ip_updated is True
        assert store.get("dd:ee:ff:00:11:22")["vendor"] == "Samsung"
        print("[PASS] update_vendor_from_ip() filled empty vendor")

        # --- hostname by MAC (DHCP) ---
        store.upsert({
            "mac": "ee:ff:00:11:22:33", "ip": "192.168.1.42",
            "network": "192.168.1.0/24", "scanner": "scapy",
        })
        dhcp_updated = store.update_hostname_by_mac("ee:ff:00:11:22:33", "DESKTOP-XYZ")
        assert dhcp_updated is True
        assert store.get("ee:ff:00:11:22:33")["hostname"] == "DESKTOP-XYZ"
        print("[PASS] update_hostname_by_mac() filled empty hostname")

        dhcp_not_overwritten = store.update_hostname_by_mac("ee:ff:00:11:22:33", "OtherName")
        assert dhcp_not_overwritten is False
        print("[PASS] update_hostname_by_mac() did not overwrite existing hostname")

        dhcp_unknown_mac = store.update_hostname_by_mac("ff:ff:ff:ff:ff:ff", "Ghost")
        assert dhcp_unknown_mac is False
        print("[PASS] update_hostname_by_mac() on unknown MAC → False, no crash")

        # --- delete_device ---
        ok = store.delete("bb:cc:dd:ee:ff:02")
        assert ok is True
        assert store.get("bb:cc:dd:ee:ff:02") is None
        print("[PASS] delete_device() → device removed")

        store.close()
        print("\nAll assertions passed.")