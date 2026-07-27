"""
The seam: both cli/terminal.py and api/server.py call only this class,
never storage, intelligence, or alerts directly. Right now it's just a
plain Python class both import directly — but if Cerberus ever needs a
true client-server split, this is exactly where a network call gets
inserted without touching CLI or web code at all.

Owns zero logic of its own — every method is a thin dispatch into
storage / intelligence / alerts, no business decisions here. Never
opens a DB connection, never reads env vars or config directly, never
imports scapy/nmap; pure orchestration of already-built modules. Trust
mutations (trust/untrust) also clear the device's alert cooldown via
alert_manager.clear_cooldown() — this is the one place that knows
trust-engine state and alert-manager state are related, so CLI and API
don't each have to remember to make both calls. Learning-mode controls
are the same thin-dispatch pattern into LearningMode (see its
cross-process sync note for why stop_learning_mode() from a CLI
process can still reach a scanner running elsewhere).

verify_trust_token() / redeem_trust_token() let server.py's
/confirm/trust/<token> routes check and act on email Trust links
without that file ever importing link_tokens or device_store
directly — same "never touch storage directly" rule as everything
else CLI/API-facing. link_secret is injected at construction (by
cerberus_main.py, whoever builds this service), never read from
config here — same injection pattern as every other optional dependency.
"""

import logging
from typing import List, Dict, Optional

from cerberus.storage.device_store import DeviceStore
from cerberus.intelligence.trust_engine import TrustEngine
from cerberus.utils import config_loader as _config_loader
from cerberus.utils.link_tokens import generate_token as _generate_link_token
from cerberus.utils.link_tokens import verify_token as _verify_link_token, TokenError

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
            link_secret=cfg.link_secret,   # optional, for Trust-link redemption
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
        link_secret:   Optional[str]        = None,
        link_token_expiry_hours: int        = 72,
    ):
        self._store         = device_store
        self._trust_engine   = trust_engine or TrustEngine()
        self._alert_manager  = alert_manager   # None = trust ops won't clear cooldowns
        self._scheduler       = scheduler        # None = get_scan_status() returns a stub
        self._learning_mode    = learning_mode     # None = learning-mode methods return stubs
        self._link_secret      = link_secret       # None = trust-link/identify-link redemption unavailable
        self._link_token_expiry_hours = link_token_expiry_hours

        logger.info(
            f"CerberusService ready — "
            f"alert_manager={'attached' if alert_manager else 'none'} | "
            f"scheduler={'attached' if scheduler else 'none'} | "
            f"learning_mode={'attached' if learning_mode else 'none'} | "
            f"trust_links={'enabled' if link_secret else 'disabled'}"
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
        alerts_log table (see scheduler.py for how it's populated).
        """
        return self._store.get_recent_alerts(limit=limit)

    def get_alert_counts(self) -> Dict[str, int]:
        """Lifetime alert counts — {total, new_unknown, returning_unknown}."""
        return self._store.alert_counts()

    def delete_alert(self, alert_id: int) -> bool:
        """Delete one alert from the persistent log. False if not found."""
        return self._store.delete_alert(alert_id)

    def clear_alerts(self) -> int:
        """Delete ALL alerts from the persistent log. Returns count deleted."""
        return self._store.clear_alerts()

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
    # Trust-link token redemption
    # ------------------------------------------------------------------

    def verify_trust_token(self, token: str) -> Dict:
        """
        Check a Trust-confirmation token's signature, expiry, and
        redemption status WITHOUT redeeming it. Used by api/server.py's
        GET /confirm/trust/<token> route to render the confirmation
        page — the operator sees device info and a "Confirm Trust"
        button before anything is actually changed. GET requests must
        never have side effects; this method guarantees that by
        design (it never calls device_store.mark_token_used or
        trust_device).

        Returns a dict, always with a "valid" key:
            {"valid": False, "reason": "unavailable", ...}
                — no link_secret was configured for this service
                  instance (Trust links were never enabled).
            {"valid": False, "reason": "malformed"|"bad_signature"|"expired", ...}
                — token failed cryptographic/expiry verification.
            {"valid": True, "reason": None, "mac": ..., "token_id": ...,
             "purpose": ..., "expires_at": ..., "already_used": bool,
             "device": Optional[Dict]}
                — token is genuine; "already_used" and "device" tell
                  the caller what to actually show/offer.
        """
        if not self._link_secret:
            return {
                "valid": False, "reason": "unavailable",
                "mac": None, "already_used": False, "device": None,
            }

        try:
            payload = _verify_link_token(token, secret=self._link_secret)
        except TokenError as e:
            return {
                "valid": False, "reason": e.reason,
                "mac": None, "already_used": False, "device": None,
            }

        already_used = self._store.is_token_used(payload.token_id)
        device = self._store.get(payload.mac)

        return {
            "valid": True,
            "reason": None,
            "mac": payload.mac,
            "token_id": payload.token_id,
            "purpose": payload.purpose,
            "expires_at": payload.expires_at,
            "already_used": already_used,
            "device": device,
        }

    def redeem_trust_token(self, token: str) -> Dict:
        """
        Verify AND redeem a Trust-confirmation token — this is the
        method with real side effects, called ONLY from api/server.py's
        POST /confirm/trust/<token> route (never GET). On success, marks
        the token used (device_store.mark_token_used — atomic, so a
        raced double-submit can only ever succeed once) and marks the
        device trusted via trust_device() (which also clears any active
        alert cooldown, same as a manual dashboard trust action).

        Returns a dict, always with a "success" key:
            {"success": False, "reason": "unavailable"|"malformed"|
             "bad_signature"|"expired"|"already_used"|
             "device_not_found"|"trust_failed",
             "mac": Optional[str], "display_name": Optional[str]}
            {"success": True, "reason": None,
             "mac": str, "display_name": str}
        """
        check = self.verify_trust_token(token)

        if not check["valid"]:
            return {
                "success": False, "reason": check["reason"],
                "mac": None, "display_name": None,
            }

        mac = check["mac"]
        device = check["device"]
        display_name = (
            (device.get("label") or device.get("hostname") or device.get("vendor") or mac)
            if device else mac
        )

        if check["already_used"]:
            return {
                "success": False, "reason": "already_used",
                "mac": mac, "display_name": display_name,
            }

        if not device:
            return {
                "success": False, "reason": "device_not_found",
                "mac": mac, "display_name": mac,
            }

        # Atomic redemption — if a concurrent request already marked
        # this token used between verify_trust_token() above and this
        # call, mark_token_used() returns False and we correctly report
        # "already_used" rather than double-trusting the device.
        marked = self._store.mark_token_used(
            token_id=check["token_id"],
            mac=mac,
            purpose=check["purpose"],
            expires_at=check["expires_at"],
        )
        if not marked:
            return {
                "success": False, "reason": "already_used",
                "mac": mac, "display_name": display_name,
            }

        trusted = self.trust_device(mac)
        if not trusted:
            # Extremely unlikely (device existed a moment ago in the
            # verify step) but handle it rather than claim false success.
            return {
                "success": False, "reason": "trust_failed",
                "mac": mac, "display_name": display_name,
            }

        logger.info(f"[trust-link] Redeemed — {mac} ({display_name}) marked trusted.")
        return {
            "success": True, "reason": None,
            "mac": mac, "display_name": display_name,
        }

    # ------------------------------------------------------------------
    # Device self-identification links
    # ------------------------------------------------------------------
    #
    # Design note: unlike the Trust links above (which the operator
    # never directly triggers per-device — alert_manager generates one
    # automatically per alert), an identify link is explicitly
    # operator-triggered from the dashboard, ONE DEVICE AT A TIME, via
    # a "Request ID" button. This directly answers "how does the
    # recipient know which device is theirs" — they don't need to,
    # because the link ITSELF already names the device (the MAC is
    # bound into the token's signature at generation time, same as
    # Trust tokens). The recipient never needs to know their own IP or
    # MAC; they just see a page asking "is this device yours?" and
    # type a name if so.
    #
    # Cerberus never sends this link anywhere itself — request_
    # identify_link() only ISSUES the token; delivering it (text,
    # WhatsApp, in person, whatever) is entirely the operator's own
    # action, by design. This keeps the feature squarely in "a tool
    # that helps the operator label their own network," not anything
    # that reaches out to a device on its own.
    #
    # Submitting a name here ONLY sets the label — it never marks the
    # device trusted. Trust remains a separate, operator-only action.

    def request_identify_link(self, mac: str) -> Dict:
        """
        Issue a fresh signed, single-use, time-limited "identify
        yourself" token for one specific device. Called from the
        dashboard's per-device "Request ID" button.

        Args:
            mac: The device this link will ask about. Bound into the
                 token's signature — cannot be changed after issuance
                 without invalidating the token.

        Returns:
            {"success": True, "mac": ..., "display_name": ..., "token": ...}
                — caller (api/server.py) builds the full shareable URL
                  from this token, since it has the current request's
                  own host/port context, which is simpler and more
                  reliable than this service trying to guess a public
                  base URL for a dashboard-triggered action.
            {"success": False, "reason": "unavailable"} if no
                  link_secret is configured for this service instance.
            {"success": False, "reason": "device_not_found"} if the MAC
                  isn't in device_store at all.
        """
        if not self._link_secret:
            return {"success": False, "reason": "unavailable"}

        device = self._store.get(mac)
        if not device:
            return {"success": False, "reason": "device_not_found"}

        display_name = device.get("label") or device.get("hostname") or device.get("vendor") or mac

        try:
            token, token_id, expires_at = _generate_link_token(
                mac=mac,
                purpose="identify",
                secret=self._link_secret,
                expiry_hours=self._link_token_expiry_hours,
            )
        except Exception as e:
            logger.error(f"[identify-link] Failed to generate token for {mac}: {e}")
            return {"success": False, "reason": "token_generation_failed"}

        logger.info(f"[identify-link] Issued — mac={mac} token_id={token_id} expires={expires_at}")
        return {
            "success": True,
            "mac": mac,
            "display_name": display_name,
            "token": token,
            "expires_at": expires_at,
        }

    def verify_identify_token(self, token: str) -> Dict:
        """
        Check an identify token's signature/expiry/redemption status
        WITHOUT redeeming it — used by the GET confirmation page so a
        mere page load never has side effects (same reasoning as
        verify_trust_token — see that method for the full explanation
        of why GET must stay side-effect-free).

        Returns a dict shaped like verify_trust_token()'s, with the
        same "valid"/"reason"/"already_used"/"device" keys — kept
        deliberately identical in shape so api/server.py's page
        rendering can share logic between the Trust and Identify flows
        rather than needing two parallel implementations.
        """
        if not self._link_secret:
            return {
                "valid": False, "reason": "unavailable",
                "mac": None, "already_used": False, "device": None,
            }

        try:
            payload = _verify_link_token(token, secret=self._link_secret)
        except TokenError as e:
            return {
                "valid": False, "reason": e.reason,
                "mac": None, "already_used": False, "device": None,
            }

        if payload.purpose != "identify":
            # A Trust token used on the Identify route (or vice versa)
            # must be rejected — the signature is valid but for the
            # wrong purpose. Treated as malformed rather than exposing
            # which specific purpose mismatch occurred.
            return {
                "valid": False, "reason": "malformed",
                "mac": None, "already_used": False, "device": None,
            }

        already_used = self._store.is_token_used(payload.token_id)
        device = self._store.get(payload.mac)

        return {
            "valid": True,
            "reason": None,
            "mac": payload.mac,
            "token_id": payload.token_id,
            "purpose": payload.purpose,
            "expires_at": payload.expires_at,
            "already_used": already_used,
            "device": device,
        }

    def redeem_identify_link(self, token: str, name: str) -> Dict:
        """
        Verify AND redeem an identify token, setting the device's label
        to the submitted name. Called ONLY from the POST route — never
        GET. Atomic against double-submission via the same
        mark_token_used() UNIQUE-constraint mechanism trust tokens use.

        Args:
            token: The token from the link.
            name : The name the person typed in. Empty/whitespace-only
                   is rejected — an empty label is not a meaningful
                   identification and would be indistinguishable from
                   "never identified" in the dashboard.

        Returns:
            {"success": False, "reason": "unavailable"|"malformed"|
             "bad_signature"|"expired"|"already_used"|"device_not_found"|
             "empty_name"|"label_failed",
             "mac": Optional[str], "display_name": Optional[str]}
            {"success": True, "reason": None,
             "mac": str, "display_name": str}
        """
        name = (name or "").strip()

        check = self.verify_identify_token(token)
        if not check["valid"]:
            return {
                "success": False, "reason": check["reason"],
                "mac": None, "display_name": None,
            }

        mac = check["mac"]
        device = check["device"]
        current_display_name = (
            (device.get("label") or device.get("hostname") or device.get("vendor") or mac)
            if device else mac
        )

        if check["already_used"]:
            return {
                "success": False, "reason": "already_used",
                "mac": mac, "display_name": current_display_name,
            }

        if not device:
            return {
                "success": False, "reason": "device_not_found",
                "mac": mac, "display_name": mac,
            }

        if not name:
            return {
                "success": False, "reason": "empty_name",
                "mac": mac, "display_name": current_display_name,
            }

        marked = self._store.mark_token_used(
            token_id=check["token_id"],
            mac=mac,
            purpose=check["purpose"],
            expires_at=check["expires_at"],
        )
        if not marked:
            return {
                "success": False, "reason": "already_used",
                "mac": mac, "display_name": current_display_name,
            }

        labeled = self.label_device(mac, name)
        if not labeled:
            return {
                "success": False, "reason": "label_failed",
                "mac": mac, "display_name": current_display_name,
            }

        logger.info(f"[identify-link] Redeemed — {mac} labeled '{name}'.")
        return {
            "success": True, "reason": None,
            "mac": mac, "display_name": name,
        }

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------
    #
    # Scoped exception to "owns zero logic of its own, never reads
    # config directly" above: settings ARE a piece of system state,
    # analogous to scan/alert-manager/learning-mode status already
    # exposed elsewhere in this class — the actual read/write logic,
    # the secrets whitelist, and the atomic-reject-on-invalid-key
    # guarantee all live in config_loader.py; this is a thin dispatch
    # into that, same pattern as everything else here.

    def get_settings(self) -> Dict:
        """
        Current editable (non-secret) settings, plus configured/not-
        configured indicators for every secret (never the secret
        values themselves). See config_loader.py's editable-settings
        section for the full whitelist and the reasoning behind it.
        """
        return {
            "editable": _config_loader.get_editable_settings(),
            "secrets": _config_loader.get_settings_status(),
        }

    def update_settings(self, updates: Dict) -> Dict:
        """
        Apply a settings update. Rejected ATOMICALLY (nothing partially
        applied) if `updates` contains any key outside the editable
        whitelist — see config_loader.update_editable_settings().

        Returns:
            {"success": True, "settings": {...}} on success.
            {"success": False, "reason": "..."} if an invalid key was
            present — reason is a human-readable message naming which
            key(s) aren't editable, safe to show directly in the UI.
        """
        try:
            merged = _config_loader.update_editable_settings(updates)
            return {"success": True, "settings": merged}
        except ValueError as e:
            return {"success": False, "reason": str(e)}

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

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """
        Close the underlying device_store connection. Added this
        revision — previously, cli/terminal.py reached into
        service._store.close() directly, which violated the seam rule
        ("CLI and frontend only ever talk to service/ — never storage,
        scanners, or intelligence directly") from OUTSIDE this file.
        cli/terminal.py's main() should be updated to call
        service.close() instead of service._store.close().
        """
        self._store.close()
        logger.debug("CerberusService closed (device_store connection closed).")


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

        # --- Trust-link token redemption — no link_secret attached ---
        check_unavail = service.verify_trust_token("whatever")
        assert check_unavail["valid"] is False
        assert check_unavail["reason"] == "unavailable"
        print("[PASS] verify_trust_token() with no link_secret → 'unavailable'")

        redeem_unavail = service.redeem_trust_token("whatever")
        assert redeem_unavail["success"] is False
        assert redeem_unavail["reason"] == "unavailable"
        print("[PASS] redeem_trust_token() with no link_secret → 'unavailable'")

        # --- delete_device ---
        ok = service.delete_device("aa:bb:cc:dd:ee:02")
        assert ok is True
        assert service.get_device("aa:bb:cc:dd:ee:02") is None
        print("[PASS] delete_device() → device removed")

        # --- close() ---
        service.close()
        print("[PASS] close() succeeded")

        print("\nAll assertions passed (link_secret-attached path tested separately "
              "in api/server.py's integration test).")