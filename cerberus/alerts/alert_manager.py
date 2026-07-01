# deps: none beyond stdlib + project modules
"""
alerts/alert_manager.py

Job: receives trust verdicts from the scheduler/trust_engine pipeline
and decides whether to fire a notification, applying a cooldown window
per device so one intruder doesn't trigger 50 alerts over an hour.

Rules:
  - Cooldown per MAC: if a device was alerted within cooldown_minutes,
    skip it. Clock resets when the device disappears and reappears.
  - Channels (email, future: webhook, desktop) are owned by their own
    modules. alert_manager decides WHETHER to alert — channels only
    know HOW to send.
  - No storage writes — alert_manager never touches the DB.
  - Reads config via get_config() — never hardcodes cooldown or toggles.
  - Thread-safe: scheduler calls process_verdicts() from worker threads.

Persistence note (module 13):
  process_verdicts() RETURNS the list of verdicts that were actually
  fired — see scheduler.py for how that's persisted to alerts_log.

VM/hypervisor tagging (Phase 3 hardening):
  _format_message() annotates the alert body if the device's vendor
  matches a known virtualization platform — purely informational.

Block-this-device hint (this revision):
  set_network_gateways() lets the scheduler hand alert_manager a
  {network_cidr: gateway_ip} map — it already has this from
  RouterDetector, alert_manager never does detection itself. When
  formatting an alert, if the device's network has a known gateway,
  the message includes a direct, universal next step: log into the
  gateway's admin page and block the MAC there. This works for every
  router on Earth since it's just pointing at the router's own admin
  UI, not attempting any vendor-specific automated blocking (which —
  see prior discussion with the operator — isn't something this
  project builds, since the only universal alternative is deauth/ARP-
  spoofing techniques identical to active attack tooling).
"""

import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Callable

from cerberus.intelligence.trust_engine import DeviceVerdict, TrustVerdict
from cerberus.detection.vendor_lookup import VendorLookup
from cerberus.utils.config_loader import get_config

logger = logging.getLogger("cerberus.alerts.alert_manager")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AlertManager:
    """
    Cooldown-aware alert dispatcher.

    Usage:
        manager = AlertManager()
        manager.register_channel(email_alert.send)        # Phase 3
        manager.set_network_gateways({"192.168.1.0/24": "192.168.1.1"})
        fired = manager.process_verdicts(verdicts)         # called by scheduler
    """

    def __init__(self, cooldown_minutes: Optional[int] = None):
        cfg = get_config()
        self._cooldown = timedelta(
            minutes=cooldown_minutes
            if cooldown_minutes is not None
            else cfg.alert_cooldown_minutes
        )
        # {mac: last_alerted_datetime} — in-memory only, resets on restart
        self._last_alerted: Dict[str, datetime] = {}
        self._lock = threading.Lock()

        # Registered alert channels — callables that accept (verdict, message)
        self._channels: List[Callable] = []

        # {network_cidr: gateway_ip} — populated by scheduler via
        # set_network_gateways(). Used only for the block-hint message;
        # never affects trust decisions or whether an alert fires.
        self._network_gateways: Dict[str, str] = {}

        # Used only for display annotation in _format_message — never
        # affects trust decisions or whether an alert fires.
        self._vendor_lookup = VendorLookup()

        # Alert counters for status()
        self._total_alerts_fired:   int = 0
        self._total_alerts_skipped: int = 0

        logger.info(
            f"AlertManager ready — "
            f"cooldown={self._cooldown.total_seconds() / 60:.0f}min | "
            f"channels={len(self._channels)}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_channel(self, send_fn: Callable) -> None:
        """
        Register an alert channel.
        send_fn must accept (verdict: DeviceVerdict, message: str).
        """
        self._channels.append(send_fn)
        logger.info(f"Alert channel registered: {send_fn.__qualname__}")

    def set_network_gateways(self, gateways: Dict[str, str]) -> None:
        """
        Provide the {network_cidr: gateway_ip} map so alert messages can
        include a "block this device at your router" hint. Called by
        scheduler once it has detected networks — alert_manager never
        does network detection itself.

        Args:
            gateways: e.g. {"192.168.1.0/24": "192.168.1.1"}.
                      Networks with no known gateway can be omitted;
                      the hint is simply skipped for those devices.
        """
        self._network_gateways = dict(gateways)
        logger.debug(f"Network gateways set: {self._network_gateways}")

    def process_verdicts(self, verdicts: List[DeviceVerdict]) -> List[DeviceVerdict]:
        """
        Main entry point — called by scheduler after every trust evaluation.
        Filters alert-worthy verdicts, applies cooldown, fires channels.

        Returns:
            The subset of verdicts that were ACTUALLY fired this cycle.
        """
        if not verdicts:
            return []

        alert_worthy = [v for v in verdicts if v.is_alert_worthy]
        if not alert_worthy:
            logger.debug(f"No alert-worthy verdicts this cycle.")
            return []

        fired: List[DeviceVerdict] = []
        for verdict in alert_worthy:
            if self._should_alert(verdict.mac):
                message = self._format_message(verdict)
                self._fire(verdict, message)
                fired.append(verdict)
            else:
                logger.debug(
                    f"[cooldown] Skipping {verdict.mac} — "
                    f"alerted within last {self._cooldown.total_seconds() / 60:.0f}min."
                )
                with self._lock:
                    self._total_alerts_skipped += 1

        return fired

    def clear_cooldown(self, mac: str) -> None:
        """Reset the cooldown for one device — next detection will alert immediately."""
        mac = mac.lower()
        with self._lock:
            if mac in self._last_alerted:
                del self._last_alerted[mac]
                logger.info(f"Cooldown cleared for {mac}")

    def status(self) -> Dict:
        """Return alert manager state snapshot for CLI / service layer."""
        with self._lock:
            active_cooldowns = {
                mac: int((dt + self._cooldown - _now()).total_seconds() // 60)
                for mac, dt in self._last_alerted.items()
                if _now() < dt + self._cooldown
            }
        return {
            "cooldown_minutes":     int(self._cooldown.total_seconds() // 60),
            "channels_registered":  len(self._channels),
            "total_alerts_fired":   self._total_alerts_fired,
            "total_alerts_skipped": self._total_alerts_skipped,
            "active_cooldowns":     active_cooldowns,
        }

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _should_alert(self, mac: str) -> bool:
        mac = mac.lower()
        with self._lock:
            last = self._last_alerted.get(mac)
            if last and _now() < last + self._cooldown:
                return False
            self._last_alerted[mac] = _now()
            return True

    def _format_message(self, verdict: DeviceVerdict) -> str:
        """
        Build a human-readable alert message from a verdict.
        This is what channels receive — they never format their own.
        """
        if verdict.verdict == TrustVerdict.UNTRUSTED_NEW:
            headline = "⚠ NEW UNKNOWN DEVICE DETECTED"
        else:
            headline = "↩ RETURNING UNKNOWN DEVICE"

        rand_note = ""
        if verdict.mac_randomization_suspected:
            rand_note = "\nNote: MAC randomization suspected — may be a known device."

        vm_note = ""
        if self._vendor_lookup.is_likely_hypervisor(verdict.vendor):
            vm_note = (
                "\nNote: vendor matches a known virtualization platform "
                "(VMware/VirtualBox/Hyper-V/etc) — possibly a VM running "
                "on a machine on this network, not necessarily an intruder. "
                "Verify before assuming malicious intent."
            )

        block_hint = ""
        gateway = self._network_gateways.get(verdict.network)
        if gateway:
            block_hint = (
                f"\n\nTo block this device: log into your router at "
                f"http://{gateway} → look for \"Connected Devices\" or "
                f"\"Access Control\" → block MAC {verdict.mac}."
            )

        port_str = ""
        if verdict.open_ports:
            port_str = f"\nOpen ports : {', '.join(str(p) for p in verdict.open_ports[:10])}"

        msg = (
            f"{headline}\n"
            f"{'─' * 48}\n"
            f"Name       : {verdict.display_name}\n"
            f"IP address : {verdict.ip}\n"
            f"MAC address: {verdict.mac}\n"
            f"Vendor     : {verdict.vendor or 'unknown'}\n"
            f"Hostname   : {verdict.hostname or 'unknown'}\n"
            f"OS         : {verdict.os or 'unknown'}\n"
            f"Network    : {verdict.network or 'unknown'}"
            f"{port_str}"
            f"{rand_note}"
            f"{vm_note}\n"
            f"{'─' * 48}\n"
            f"First seen : {verdict.first_seen or 'this session'}\n"
            f"Last seen  : {verdict.last_seen or 'just now'}"
            f"{block_hint}"
        )
        return msg

    def _fire(self, verdict: DeviceVerdict, message: str) -> None:
        severity = (
            "CRITICAL" if verdict.verdict == TrustVerdict.UNTRUSTED_NEW
            else "WARNING"
        )
        logger.log(
            logging.CRITICAL if severity == "CRITICAL" else logging.WARNING,
            f"[alert] {severity} — {verdict.display_name} | "
            f"{verdict.ip} | {verdict.mac} | "
            f"verdict={verdict.verdict.value}"
        )

        if not self._channels:
            logger.debug("[alert] No channels registered — logged only.")
        else:
            for channel in self._channels:
                try:
                    channel(verdict, message)
                except Exception as e:
                    logger.error(
                        f"[alert] Channel {channel.__qualname__} failed: {e}"
                    )

        with self._lock:
            self._total_alerts_fired += 1