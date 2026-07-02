# deps: none beyond stdlib + project modules
"""
service/cerberus_service.py

THE SEAM. Both cli/terminal.py (Module 14) and api/server.py (Module 15)
are required to call ONLY this class — never storage, intelligence, or
alerts directly.

This is the literal embodiment of "function call beats an API call, but
design the seam" — today this is a plain Python class CLI and Flask/FastAPI
both import directly. If Cerberus ever needs a true client-server split,
this is exactly where a network call gets inserted, without touching CLI
or web code at all. Nothing outside this file should need to change.

Rules:
  - Owns ZERO logic of its own. Every method is a thin dispatch into
    storage / intelligence / alerts. No business decisions happen here.
  - Never opens a DB connection, never reads env vars/config directly,
    never imports scapy/nmap. Pure orchestration of already-built modules.
  - Trust mutations (trust/untrust) ALSO clear the device's alert cooldown
    via alert_manager.clear_cooldown() — this is the one place that
    "knows" trust-engine state and alert-manager state are related, so
    CLI/API don't each need to remember to do both calls themselves.
  - Learning-mode controls are thin dispatches into LearningMode, same
    pattern as everything else. See learning_mode.py's cross-process
    sync note for why stop_learning_mode() called from a CLI process
    can still affect a scanner running in a different process.
"""

import logging
from typing import List, Dict, Optional

from cerberus.storage.device_store import DeviceStore
from cerberus.intelligence.trust_engine import TrustEngine

logger = logging.getLogger("cerberus.service.cerberus_service")


class CerberusService:
    """
    The seam. Construct once in cerberus_main.py (or wherever the long-
    running process lives) and hand the SAME instance to both CLI and API.

    Usage:
        service = CerberusService(
            device_store=store,
            trust_engine=trust_engine,
            alert_manager=alert_manager,   # optional
            scheduler=scheduler,           # optional, for get_scan_status()
            learning_mode=learning_mode,   # optional, for learning-mode controls
        )
        devices = service.get_devices()
        service.trust_device("aa:bb:cc:dd:ee:ff")
    """

    def __init__(
        self,
        device_store:  DeviceStore,
        trust_engine:  Optional[TrustEngine] = None,
        alert_manager                       = None,
        scheduler                           = None,
        learning_mode                       = None,
    ):
        self._store         = device_store
        self._trust_engine   = trust_engine or TrustEngine()
        self._alert_manager  = alert_manager   # None = trust ops won't clear cooldowns
        self._scheduler       = scheduler        # None = get_scan_status() returns a stub
        self._learning_mode    = learning_mode     # None = learning-mode methods return stubs

        logger.info(
            f"CerberusService ready — "
            f"alert_manager={'attached' if alert_manager else 'none'} | "
            f"scheduler={'attached' if scheduler else 'none'} | "
            f"learning_mode={'attached' if learning_mode else 'none'}"
        )

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    def get_devices(self, trusted_only: Optional[bool] = None) -> List[Dict]:
        """
        Current device list.

        Args:
            trusted_only: None = all devices. True = only trusted.
                          False = only untrusted.
        """
        if trusted_only is None:
            return self._store.get_all()
        return self._store.get_by_trust(trusted_only)

    def get_device(self, mac: str) -> Optional[Dict]:
        """Single device detail by MAC. None if not found."""
        return self._store.get(mac)

    def get_device_history(self, mac: str, limit: int = 20) -> List[Dict]:
        """Recent scan_history rows for one device."""
        return self._store.get_history(mac, limit=limit)

    def get_device_counts(self) -> Dict[str, int]:
        """{total, trusted, untrusted} snapshot."""
        return self._store.counts()

    # ------------------------------------------------------------------
    # Trust mutation
    # ------------------------------------------------------------------

    def trust_device(self, mac: str) -> bool:
        """
        Mark a device trusted. Returns False if MAC unknown.

        Also clears any active alert cooldown for this MAC — once an
        operator trusts a device, the NEXT scan cycle's trust_engine
        evaluation will naturally stop flagging it (verdict becomes
        TRUSTED), so this is mostly a courtesy reset rather than a
        functional necessity. Kept for correctness: if the operator
        immediately un-trusts again within the same cooldown window,
        they should get an alert right away, not a silently swallowed one.
        """
        result = self._store.set_trust(mac, True)
        if result and self._alert_manager:
            self._alert_manager.clear_cooldown(mac)
        return result

    def untrust_device(self, mac: str) -> bool:
        """
        Mark a device untrusted. Returns False if MAC unknown.

        Clears cooldown so the very next scan cycle can alert on this
        device immediately, instead of silently waiting out whatever
        cooldown window happened to still be active from before.
        """
        result = self._store.set_trust(mac, False)
        if result and self._alert_manager:
            self._alert_manager.clear_cooldown(mac)
        return result

    def label_device(self, mac: str, label: str) -> bool:
        """Assign a human-readable name to a device. "" clears the label."""
        return self._store.set_label(mac, label)

    def delete_device(self, mac: str) -> bool:
        """Remove a device and its scan history entirely."""
        return self._store.delete(mac)

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """
        Persistent alert history — every alert that was actually fired
        (post-cooldown), newest first. Backed by device_store's
        alerts_log table (see Phase 3 module 13 prep in scheduler.py).
        """
        return self._store.get_recent_alerts(limit=limit)

    def get_alert_counts(self) -> Dict[str, int]:
        """Lifetime alert counts — {total, new_unknown, returning_unknown}."""
        return self._store.alert_counts()

    def get_alert_manager_status(self) -> Dict:
        """
        Live alert_manager state — cooldown window, channels registered,
        active per-MAC cooldowns right now. Returns a stub dict (not an
        error) if no alert_manager was attached at construction time,
        so callers don't need a None-check before every call.
        """
        if not self._alert_manager:
            return {
                "attached": False,
                "cooldown_minutes": None,
                "channels_registered": 0,
                "total_alerts_fired": 0,
                "total_alerts_skipped": 0,
                "active_cooldowns": {},
            }
        status = self._alert_manager.status()
        status["attached"] = True
        return status

    # ------------------------------------------------------------------
    # Learning mode
    # ------------------------------------------------------------------

    def get_learning_mode_status(self) -> Dict:
        """
        Live learning-mode state — active, time remaining, devices
        auto-trusted so far. Returns a stub dict if no LearningMode was
        attached (e.g. Cerberus was started with --no-learning).
        """
        if not self._learning_mode:
            return {
                "attached": False,
                "active": False,
                "started_at": None,
                "ends_at": None,
                "remaining_seconds": None,
                "remaining_str": "not active",
                "auto_trusted": 0,
                "duration_hours": None,
            }
        status = self._learning_mode.status()
        status["attached"] = True
        return status

    def start_learning_mode(
        self, force_restart: bool = False, duration_hours: Optional[int] = None
    ) -> bool:
        """
        Deliberately (re-)start the learning window. This is the
        operator-triggered path — e.g. "I've moved to a new network
        location, trust everything for the next 2 hours." It is NEVER
        called automatically by cerberus_main.py on every boot; see
        learning_mode.py's has_ever_started() for why that auto-start
        behavior was removed (it caused learning mode to silently
        reopen every restart even after a deliberate stop).

        Args:
            force_restart  : Reset the clock even if already active.
            duration_hours : Override window length for this start only
                             (e.g. 2h for a quick new-location baseline
                             instead of the full default).

        Returns:
            True if a learning_mode instance is attached (the start was
            issued). False only if no LearningMode was attached at all.
        """
        if not self._learning_mode:
            logger.warning(
                "start_learning_mode() called but no LearningMode attached "
                "to this service instance."
            )
            return False
        self._learning_mode.start(
            force_restart=force_restart, duration_hours=duration_hours
        )
        return True

    def stop_learning_mode(self) -> bool:
        """
        End the learning window early. Safe to call even if this
        service's LearningMode instance is a SEPARATE in-memory object
        from the one inside the actively running scanner process (e.g.
        when called from the CLI) — both instances point at the same
        state_file, and learning_mode.py re-syncs from that file's
        mtime on every is_active()/status() check, so the running
        scanner picks up the change within one scan cycle.

        Returns:
            True if a learning_mode instance is attached (the stop was
            issued — it may have already been inactive, which is fine).
            False only if no LearningMode was attached to this service
            at all (nothing to stop).
        """
        if not self._learning_mode:
            logger.warning(
                "stop_learning_mode() called but no LearningMode attached "
                "to this service instance."
            )
            return False
        self._learning_mode.stop()
        return True

    # ------------------------------------------------------------------
    # Scan status
    # ------------------------------------------------------------------

    def get_scan_status(self) -> Dict:
        """
        Live scheduler state — running networks, intervals, live-host
        counts per network, active worker threads. Returns a stub dict
        (not an error) if no scheduler was attached, e.g. if this
        service is ever constructed in a context without one.
        """
        if not self._scheduler:
            return {
                "attached": False,
                "running": False,
                "networks": [],
                "active_threads": [],
            }
        status = self._scheduler.status()
        status["attached"] = True
        return status

    # ------------------------------------------------------------------
    # Combined snapshot — convenience for dashboards / CLI "status" command
    # ------------------------------------------------------------------

    def get_full_status(self) -> Dict:
        """
        One call that bundles device counts, alert counts, alert_manager
        state, learning-mode state, and scan status — exactly what a CLI
        'status' command or a dashboard landing page needs in a single
        round trip through the seam, instead of five separate calls.
        """
        return {
            "devices":       self.get_device_counts(),
            "alerts":        self.get_alert_counts(),
            "alert_manager": self.get_alert_manager_status(),
            "learning_mode": self.get_learning_mode_status(),
            "scan":          self.get_scan_status(),
        }


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile
    import os
    import logging as _logging

    _logging.basicConfig(
        level=_logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    with tempfile.TemporaryDirectory() as tmp:
        store = DeviceStore(os.path.join(tmp, "test.db"))
        service = CerberusService(device_store=store)  # no optional deps attached

        # Seed a couple of devices directly via store (simulating scanner output)
        store.upsert({
            "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.10",
            "network": "192.168.1.0/24", "scanner": "scapy",
        })
        store.upsert({
            "mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.1.20",
            "network": "192.168.1.0/24", "scanner": "scapy",
        })

        # --- get_devices ---
        all_devices = service.get_devices()
        assert len(all_devices) == 2
        print(f"[PASS] get_devices() → {len(all_devices)} devices")

        # --- get_device ---
        d = service.get_device("aa:bb:cc:dd:ee:01")
        assert d is not None and d["ip"] == "192.168.1.10"
        print(f"[PASS] get_device() → {d['ip']}")

        none_device = service.get_device("ff:ff:ff:ff:ff:ff")
        assert none_device is None
        print("[PASS] get_device() on unknown MAC → None")

        # --- trust_device / untrust_device ---
        ok = service.trust_device("aa:bb:cc:dd:ee:01")
        assert ok is True
        d = service.get_device("aa:bb:cc:dd:ee:01")
        assert d["trusted"] is True
        print("[PASS] trust_device() → device now trusted")

        ok = service.trust_device("ff:ff:ff:ff:ff:ff")  # unknown MAC
        assert ok is False
        print("[PASS] trust_device() on unknown MAC → False")

        ok = service.untrust_device("aa:bb:cc:dd:ee:01")
        assert ok is True
        d = service.get_device("aa:bb:cc:dd:ee:01")
        assert d["trusted"] is False
        print("[PASS] untrust_device() → device now untrusted")

        # --- label_device ---
        ok = service.label_device("aa:bb:cc:dd:ee:01", "Harsh's Laptop")
        assert ok is True
        d = service.get_device("aa:bb:cc:dd:ee:01")
        assert d["label"] == "Harsh's Laptop"
        print(f"[PASS] label_device() → label='{d['label']}'")

        # --- get_devices filtered by trust ---
        untrusted = service.get_devices(trusted_only=False)
        assert len(untrusted) == 2  # only ee:01 was trusted then untrusted again
        print(f"[PASS] get_devices(trusted_only=False) → {len(untrusted)} devices")

        # --- get_device_counts ---
        counts = service.get_device_counts()
        assert counts["total"] == 2
        print(f"[PASS] get_device_counts() → {counts}")

        # --- alerts (no alert_manager attached — stub path) ---
        alerts = service.get_recent_alerts()
        assert alerts == []
        print("[PASS] get_recent_alerts() with empty alerts_log → []")

        am_status = service.get_alert_manager_status()
        assert am_status["attached"] is False
        print(f"[PASS] get_alert_manager_status() with no alert_manager → {am_status}")

        # --- learning mode (no learning_mode attached — stub path) ---
        lm_status = service.get_learning_mode_status()
        assert lm_status["attached"] is False
        print(f"[PASS] get_learning_mode_status() with no learning_mode → {lm_status}")

        stopped = service.stop_learning_mode()
        assert stopped is False
        print("[PASS] stop_learning_mode() with no learning_mode → False")

        # Manually log an alert to prove the read path works end-to-end
        store.log_alert(
            mac="aa:bb:cc:dd:ee:02", ip="192.168.1.20",
            verdict="untrusted_new", network="192.168.1.0/24",
            message_summary="Test device 02", channels_fired=1,
        )
        alerts = service.get_recent_alerts()
        assert len(alerts) == 1
        print(f"[PASS] get_recent_alerts() after log_alert() → {alerts}")

        # --- scan status (no scheduler attached — stub path) ---
        scan_status = service.get_scan_status()
        assert scan_status["attached"] is False
        print(f"[PASS] get_scan_status() with no scheduler → {scan_status}")

        # --- combined snapshot ---
        full = service.get_full_status()
        assert "devices" in full and "alerts" in full and "learning_mode" in full
        print(f"[PASS] get_full_status() → keys: {list(full.keys())}")

        # --- delete_device ---
        ok = service.delete_device("aa:bb:cc:dd:ee:02")
        assert ok is True
        assert service.get_device("aa:bb:cc:dd:ee:02") is None
        print("[PASS] delete_device() → device removed")

        store.close()
        print("\nAll assertions passed.")