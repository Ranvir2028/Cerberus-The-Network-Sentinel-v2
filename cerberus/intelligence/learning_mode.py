"""
Manages a time-boxed window where every discovered device gets
auto-trusted instead of flagged as unknown. On first run Cerberus has
zero trusted devices — without this, every device on the network
(router, phone, laptop, TV) would trigger an "INTRUDER" alert
immediately, which is useless. Learning mode gives it a window
(default 24h) to silently observe and auto-trust everything, then
hands off to trust_engine's normal judgment once the window closes.

Owns exactly one piece of state — is learning mode active, when did it
start, when does it end — and nothing else; no trust logic
duplication, no scanning. trust_engine and the scheduler just consult
is_active(). Persisted to a small JSON file (default
data/learning_mode.json) so a restart mid-window picks up where it
left off instead of resetting the clock.

The scanner (cerberus_main.py) and the CLI (terminal.py) run as
separate processes, each with its own in-memory LearningMode object.
Originally state was only loaded once at __init__, so if the CLI
called stop() to end learning mode early, the running scanner process
never noticed since it never re-read the file. Fixed by having
is_active() and status() check the state file's mtime before
answering — if it's changed since this instance last read it, reload
from disk first. Makes the JSON file the real shared source of truth
instead of just a restart-recovery snapshot, at the cost of one
stat() call per check.

Usage:
    lm = LearningMode(store=device_store)
    lm.start()                    # begin learning window
    if lm.is_active():            # check before raising alerts
        lm.auto_trust_device(device_dict)   # trust it silently
    lm.status()                   # dict with time remaining etc.
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional

logger = logging.getLogger("cerberus.intelligence.learning_mode")

_DEFAULT_STATE_FILE = "data/learning_mode.json"
_DEFAULT_DURATION_HOURS = 24


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat(timespec="seconds")


class LearningMode:
    """
    Time-boxed auto-trust window for first-run device baselining.

    Args:
        device_store    : DeviceStore instance — used to call set_trust()
                          and set_label() when auto-trusting devices.
        duration_hours  : How long the learning window stays open (default 24h).
        state_file      : Path to persist learning mode state across restarts
                          AND across processes (see cross-process sync note).
    """

    def __init__(
        self,
        device_store,
        duration_hours: int  = _DEFAULT_DURATION_HOURS,
        state_file:     str  = _DEFAULT_STATE_FILE,
    ):
        self._store          = device_store
        self._duration_hours = duration_hours
        self._state_file     = state_file

        self._started_at:  Optional[datetime] = None
        self._ends_at:     Optional[datetime] = None
        self._active:      bool               = False
        self._auto_trusted_count:  int        = 0

        # Tracks the state file's mtime as of our last read — used to
        # detect external changes from another process. None means
        # "never successfully read" (e.g. file didn't exist yet).
        self._last_seen_mtime: Optional[float] = None

        self._load_state()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, force_restart: bool = False, duration_hours: Optional[int] = None) -> None:
        """
        Begin the learning window.

        Args:
            force_restart  : If True, resets the clock even if a window is
                             already active. Used for manual re-baselining
                             (e.g. the operator deliberately changed network
                             locations and wants a fresh trust-everything
                             window). Default False — if already active,
                             does nothing.
            duration_hours : Override the window length for THIS start only
                             (e.g. a quick 1-2h baseline at a hotel/new
                             location instead of the configured default).
                             If omitted, uses whatever duration this
                             instance was constructed with. The override
                             is persisted into the state file.
        """
        self._sync_from_file_if_changed()

        if self._active and not force_restart:
            remaining = self._remaining_str()
            logger.info(
                f"Learning mode already active. "
                f"Ends in {remaining}. Use force_restart=True to reset."
            )
            return

        if duration_hours is not None:
            self._duration_hours = duration_hours

        self._started_at = _now()
        self._ends_at    = self._started_at + timedelta(hours=self._duration_hours)
        self._active     = True
        self._auto_trusted_count = 0
        self._save_state()

        logger.info(
            f"Learning mode STARTED — "
            f"window: {self._duration_hours}h — "
            f"ends at: {self._ends_at.isoformat(timespec='seconds')} UTC"
        )

    def has_ever_started(self) -> bool:
        """
        Return True if this learning window has EVER been started before
        (active right now, already expired, or manually stopped) — as
        opposed to a state file that's never existed at all.

        Fixes a real bug: cerberus_main.py used to call start()
        unconditionally on every launch, so stopping learning mode via
        the CLI and then restarting the scanner silently re-opened a
        brand new window — there was no way to distinguish "deliberately
        stopped" from "never started." Callers should check this BEFORE
        auto-starting, and only auto-start on a genuine first-ever run.
        Manual re-baselining afterward goes through
        start(force_restart=True) explicitly, triggered by the operator.
        """
        self._sync_from_file_if_changed()
        return self._started_at is not None

    def stop(self) -> None:
        """
        Manually end the learning window before it expires.

        Called either by the SAME process that started it, or by a
        separate process (e.g. the CLI's `learning stop` command) acting
        on its own LearningMode instance pointed at the same state file.
        Either way, this writes active=False to disk immediately. The
        scanner process (if this call came from elsewhere) will pick up
        the change on its next is_active()/status() call via
        _sync_from_file_if_changed() — at most one scan cycle later.
        """
        self._sync_from_file_if_changed()

        if not self._active:
            logger.info("Learning mode is not active — nothing to stop.")
            return

        self._active  = False
        self._ends_at = _now()
        self._save_state()

        logger.info(
            f"Learning mode STOPPED manually. "
            f"Auto-trusted {self._auto_trusted_count} device(s) during window."
        )

    def is_active(self) -> bool:
        """
        Return True if learning mode window is currently open.

        Re-syncs from the state file first (see cross-process sync note
        in the module docstring) so a stop() issued by another process
        is reflected here without waiting for a restart. Also
        auto-deactivates and saves state when the window expires.
        """
        self._sync_from_file_if_changed()

        if not self._active:
            return False

        if _now() >= self._ends_at:
            self._active = False
            self._save_state()
            logger.info(
                f"Learning mode window EXPIRED. "
                f"Auto-trusted {self._auto_trusted_count} device(s). "
                f"Trust engine now active."
            )
            return False

        return True

    def auto_trust_device(self, device: Dict) -> bool:
        """
        Auto-trust a device during the learning window.
        Silently marks it trusted in the DB with an auto-generated label
        if no label is already set.

        Args:
            device: Device dict from scanner output or device_store.

        Returns:
            True if the device was trusted, False if learning mode is
            not active or MAC is missing.
        """
        if not self.is_active():
            logger.debug("auto_trust_device called but learning mode not active.")
            return False

        mac = (device.get("mac") or "").lower()
        if not mac:
            logger.debug("auto_trust_device: no MAC in device dict.")
            return False

        # Trust in DB
        trusted = self._store.set_trust(mac, True)
        if not trusted:
            # Device not in DB yet — upsert happens in scheduler, 
            # trust_engine will catch it next cycle
            logger.debug(f"auto_trust: {mac} not in DB yet, will catch next cycle.")
            return False

        # Auto-label if no label set
        existing = self._store.get(mac)
        if existing and not existing.get("label"):
            auto_label = self._generate_auto_label(existing)
            if auto_label:
                self._store.set_label(mac, auto_label)
                logger.info(
                    f"[learning] Auto-trusted: {mac} ({device.get('ip', '?')}) "
                    f"→ labelled '{auto_label}'"
                )
            else:
                logger.info(
                    f"[learning] Auto-trusted: {mac} ({device.get('ip', '?')})"
                )

        self._auto_trusted_count += 1
        self._save_state()
        return True

    def auto_trust_all(self, devices) -> int:
        """
        Auto-trust an entire device list. Called by the scheduler at the
        start of each scan cycle while learning mode is active.

        Args:
            devices: List of device dicts from device_store.get_all()
                     or scanner output.

        Returns:
            Number of devices newly trusted this call.
        """
        if not self.is_active():
            return 0

        count = 0
        for device in devices:
            if not device.get("trusted"):
                if self.auto_trust_device(device):
                    count += 1

        if count:
            logger.info(
                f"[learning] Auto-trusted {count} device(s) this cycle. "
                f"Window closes in {self._remaining_str()}."
            )
        return count

    def status(self) -> Dict:
        """
        Return a snapshot of learning mode state for CLI / cerberus_main.

        Re-syncs from the state file first — same reasoning as is_active().

        Returns dict with:
            active           : bool
            started_at       : ISO string or None
            ends_at          : ISO string or None
            remaining_seconds: int or None
            remaining_str    : human-readable time remaining or "expired"
            auto_trusted     : int — devices trusted during this window
            duration_hours   : configured window length
        """
        active = self.is_active()  # already syncs internally
        remaining_secs = None
        if active and self._ends_at:
            delta = self._ends_at - _now()
            remaining_secs = max(0, int(delta.total_seconds()))

        return {
            "active":            active,
            "started_at":        self._started_at.isoformat(timespec="seconds") if self._started_at else None,
            "ends_at":           self._ends_at.isoformat(timespec="seconds")    if self._ends_at    else None,
            "remaining_seconds": remaining_secs,
            "remaining_str":     self._remaining_str() if active else "not active",
            "auto_trusted":      self._auto_trusted_count,
            "duration_hours":    self._duration_hours,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _generate_auto_label(self, device: Dict) -> Optional[str]:
        """
        Best-effort human label from available device info.
        Priority: hostname > vendor-based > None (no label set).
        """
        hostname = (device.get("hostname") or "").strip()
        if hostname:
            return hostname

        vendor = (device.get("vendor") or "").strip()
        if vendor:
            # e.g. "TP-Link Technologies" → "TP-Link device"
            short_vendor = vendor.split()[0] if vendor else ""
            if short_vendor:
                return f"{short_vendor} device"

        return None

    def _remaining_str(self) -> str:
        """Human-readable time remaining in learning window."""
        if not self._ends_at or not self._active:
            return "not active"
        delta = self._ends_at - _now()
        total = int(delta.total_seconds())
        if total <= 0:
            return "expired"
        hours, rem   = divmod(total, 3600)
        minutes, secs = divmod(rem, 60)
        if hours > 0:
            return f"{hours}h {minutes}m"
        if minutes > 0:
            return f"{minutes}m {secs}s"
        return f"{secs}s"

    def _sync_from_file_if_changed(self) -> None:
        """
        Check the state file's mtime. If it's changed since we last read
        it (meaning another process — most likely the CLI — wrote a new
        state), reload from disk. If the file doesn't exist, or stat()
        fails, this is a no-op — falls back to whatever this instance
        already has in memory, same as before this feature existed.
        """
        try:
            current_mtime = os.path.getmtime(self._state_file)
        except OSError:
            return  # File doesn't exist yet — nothing to sync from

        if self._last_seen_mtime is None or current_mtime != self._last_seen_mtime:
            logger.debug(
                f"Learning mode state file changed on disk "
                f"(mtime {self._last_seen_mtime} → {current_mtime}) — reloading."
            )
            self._load_state()

    def _save_state(self) -> None:
        """Persist learning mode state to JSON file."""
        try:
            os.makedirs(
                os.path.dirname(self._state_file)
                if os.path.dirname(self._state_file) else ".",
                exist_ok=True,
            )
            state = {
                "active":            self._active,
                "started_at":        self._started_at.isoformat() if self._started_at else None,
                "ends_at":           self._ends_at.isoformat()    if self._ends_at    else None,
                "auto_trusted_count": self._auto_trusted_count,
                "duration_hours":    self._duration_hours,
            }
            with open(self._state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)

            # Record our own write's mtime so the NEXT _sync_from_file_if_changed()
            # call in THIS process doesn't immediately reload what it just wrote.
            try:
                self._last_seen_mtime = os.path.getmtime(self._state_file)
            except OSError:
                pass

        except Exception as e:
            logger.warning(f"Could not save learning mode state: {e}")

    def _load_state(self) -> None:
        """Load persisted state from JSON file if it exists."""
        if not os.path.exists(self._state_file):
            logger.debug("No learning mode state file found — fresh start.")
            return

        try:
            with open(self._state_file, "r", encoding="utf-8") as f:
                state = json.load(f)

            self._active             = state.get("active", False)
            self._auto_trusted_count = state.get("auto_trusted_count", 0)
            self._duration_hours     = state.get("duration_hours", self._duration_hours)

            started = state.get("started_at")
            ends    = state.get("ends_at")

            self._started_at = datetime.fromisoformat(started) if started else None
            self._ends_at    = datetime.fromisoformat(ends)    if ends    else None

            # Record this read's mtime so we can detect future external changes.
            try:
                self._last_seen_mtime = os.path.getmtime(self._state_file)
            except OSError:
                pass

            if self._active and self._ends_at:
                if _now() >= self._ends_at:
                    self._active = False
                    logger.info(
                        "Learning mode window expired while Cerberus was offline. "
                        "Trust engine now active."
                    )
                else:
                    logger.info(
                        f"Learning mode resumed — "
                        f"window closes in {self._remaining_str()}."
                    )
            else:
                logger.debug(
                    f"Learning mode loaded — active={self._active}."
                )

        except Exception as e:
            logger.warning(f"Could not load learning mode state: {e}. Starting fresh.")
            self._active = False