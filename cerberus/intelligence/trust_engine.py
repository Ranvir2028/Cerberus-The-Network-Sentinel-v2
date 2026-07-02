# deps: none — uses only stdlib + device_store output
"""
intelligence/trust_engine.py

Job: takes the current device list from storage and answers exactly one
question per device — trusted, untrusted-new, or untrusted-returning?

Three verdicts:
  TRUSTED            — MAC is marked trusted in the DB. No alert.
  UNTRUSTED_NEW      — MAC never seen before. Alert immediately.
  UNTRUSTED_RETURNING — MAC was seen before (has first_seen history) but
                        is NOT marked trusted. Was previously unknown,
                        went offline, came back. Alert but at lower severity
                        than a brand-new device.

The core fix for the original Cerberus v1 problem:
  A device that WAS trusted, went to sleep, and came back must NOT be
  re-flagged as an intruder. The engine checks the trusted flag in the
  DB — not "did I see this MAC in the last scan cycle". Scapy missing a
  device for one cycle is normal (device asleep, ARP packet dropped).
  Only a MAC that is explicitly marked trusted=False triggers an alert.

MAC randomization awareness:
  Modern phones (iOS, Android, Windows Wi-Fi) randomize their MAC per
  network session. A randomized MAC looks like a brand-new device every
  time. The engine uses secondary signals to reduce false positives:
    - hostname match against known trusted hostnames
    - vendor/OUI match against known trusted vendors
    - label match (user-assigned names)
  If any secondary signal matches a trusted device, verdict is downgraded
  from UNTRUSTED_NEW to UNTRUSTED_RETURNING with a MAC_RANDOMIZATION flag.
  It does NOT auto-trust — that decision stays with the human operator.

Labels:
  Each device can have a human-readable label ("Harsh's Laptop",
  "Living Room TV"). Trust engine uses labels as a secondary identity
  signal and includes them in verdicts for CLI/alert display.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional

from cerberus.detection.vendor_lookup import VendorLookup

logger = logging.getLogger("cerberus.intelligence.trust_engine")


# ---------------------------------------------------------------------------
# Verdict types
# ---------------------------------------------------------------------------

class TrustVerdict(Enum):
    TRUSTED              = "trusted"
    UNTRUSTED_NEW        = "untrusted_new"
    UNTRUSTED_RETURNING  = "untrusted_returning"


@dataclass
class DeviceVerdict:
    """
    Full trust verdict for one device. This is what alert_manager
    and CLI receive — never raw device dicts.
    """
    mac:                str
    ip:                 str
    verdict:            TrustVerdict
    label:              Optional[str]       # user-assigned name, if set
    vendor:             Optional[str]
    hostname:           Optional[str]
    os:                 Optional[str]
    open_ports:         List[int]           = field(default_factory=list)
    first_seen:         Optional[str]       = None
    last_seen:          Optional[str]       = None
    mac_randomization_suspected: bool       = False
    matched_trusted_hostname:    Optional[str] = None
    matched_trusted_vendor:      Optional[str] = None
    network:            str                 = ""

    @property
    def display_name(self) -> str:
        """Best human-readable name for this device."""
        return (
            self.label
            or self.hostname
            or self.vendor
            or self.mac
        )

    @property
    def is_alert_worthy(self) -> bool:
        return self.verdict in (
            TrustVerdict.UNTRUSTED_NEW,
            TrustVerdict.UNTRUSTED_RETURNING,
        )


# ---------------------------------------------------------------------------
# Trust Engine
# ---------------------------------------------------------------------------

class TrustEngine:
    """
    Stateless verdict engine — takes device list from storage, returns
    a verdict per device. Never writes to storage itself.

    Usage:
        engine = TrustEngine()
        all_devices = store.get_all()          # from device_store
        verdicts = engine.evaluate(all_devices)
        alerts = [v for v in verdicts if v.is_alert_worthy]
    """

    def __init__(self):
        # Vendors known to randomize MACs — used for randomization detection
        self._randomizing_vendors = {
            "apple", "microsoft", "google", "samsung",
            "huawei", "xiaomi", "oneplus", "oppo", "vivo",
        }
        # Vendor lookup — fills in vendor field if scanner missed it
        self._vendor_lookup = VendorLookup()
        logger.debug(
            f"TrustEngine initialized — "
            f"vendor DB: {self._vendor_lookup.entry_count()} entries"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, devices: List[Dict]) -> List[DeviceVerdict]:
        """
        Evaluate trust for every device in the list.

        Args:
            devices: List of device dicts from device_store.get_all().
                     Each dict must have at minimum: mac, ip, trusted,
                     first_seen. Other fields optional.

        Returns:
            List of DeviceVerdict — one per device, in same order as input.
            Empty list if devices is empty.
        """
        if not devices:
            logger.debug("evaluate() called with empty device list.")
            return []

        # Build lookup structures for secondary signal matching
        trusted_hostnames = self._extract_trusted_hostnames(devices)
        trusted_vendors   = self._extract_trusted_vendors(devices)
        trusted_labels    = self._extract_trusted_labels(devices)

        verdicts = []
        for device in devices:
            verdict = self._evaluate_one(
                device,
                trusted_hostnames,
                trusted_vendors,
                trusted_labels,
            )
            verdicts.append(verdict)

        trusted_count    = sum(1 for v in verdicts if v.verdict == TrustVerdict.TRUSTED)
        new_count        = sum(1 for v in verdicts if v.verdict == TrustVerdict.UNTRUSTED_NEW)
        returning_count  = sum(1 for v in verdicts if v.verdict == TrustVerdict.UNTRUSTED_RETURNING)
        rand_count       = sum(1 for v in verdicts if v.mac_randomization_suspected)

        logger.info(
            f"Trust evaluation complete — "
            f"{trusted_count} trusted, "
            f"{new_count} new unknown, "
            f"{returning_count} returning unknown"
            + (f", {rand_count} possible MAC randomization" if rand_count else "")
        )

        return verdicts

    def evaluate_single(self, device: Dict, all_devices: List[Dict]) -> DeviceVerdict:
        """
        Evaluate trust for one device in the context of the full device list.
        Used by scheduler when a new MAC is spotted mid-cycle.

        Args:
            device     : The single device dict to evaluate.
            all_devices: Full device list for secondary signal context.
        """
        trusted_hostnames = self._extract_trusted_hostnames(all_devices)
        trusted_vendors   = self._extract_trusted_vendors(all_devices)
        trusted_labels    = self._extract_trusted_labels(all_devices)

        return self._evaluate_one(
            device,
            trusted_hostnames,
            trusted_vendors,
            trusted_labels,
        )

    # ------------------------------------------------------------------
    # Private — core verdict logic
    # ------------------------------------------------------------------

    def _evaluate_one(
        self,
        device: Dict,
        trusted_hostnames: Dict[str, str],  # hostname → mac
        trusted_vendors:   Dict[str, str],  # vendor_lower → mac
        trusted_labels:    Dict[str, str],  # label_lower → mac
    ) -> DeviceVerdict:
        """
        Determine verdict for one device. The logic in order:

        1. trusted=True in DB → TRUSTED. Full stop.
        2. first_seen exists and != last_seen → UNTRUSTED_RETURNING.
           (device has history — was seen before, just not trusted.)
        3. Everything else → UNTRUSTED_NEW.

        Then secondary signal check for MAC randomization:
        - If verdict is UNTRUSTED_NEW and hostname/vendor/label matches
          a known trusted device → flag mac_randomization_suspected,
          downgrade to UNTRUSTED_RETURNING (still not trusted, but lower
          severity alert — human should verify).
        """
        mac       = (device.get("mac") or "").lower()
        ip        = device.get("ip", "")
        trusted   = bool(device.get("trusted", False))
        first_seen = device.get("first_seen")
        last_seen  = device.get("last_seen")
        hostname  = device.get("hostname") or ""
        vendor    = device.get("vendor") or ""
        label     = device.get("label") or ""
        network   = device.get("network", "")

        # Enrich vendor from OUI lookup if scanner didn't provide one
        if not vendor and mac:
            looked_up = self._vendor_lookup.lookup(mac)
            if looked_up:
                vendor = looked_up
                logger.debug(f"OUI enriched vendor for {mac}: {vendor}")

        # --- Step 1: Trusted flag ---
        if trusted:
            return DeviceVerdict(
                mac=mac, ip=ip,
                verdict=TrustVerdict.TRUSTED,
                label=label or None,
                vendor=vendor or None,
                hostname=hostname or None,
                os=device.get("os"),
                open_ports=device.get("open_ports") or [],
                first_seen=first_seen,
                last_seen=last_seen,
                network=network,
            )

        # --- Step 2: Has history = returning ---
        # first_seen != last_seen means it was seen in a previous session
        has_history = bool(first_seen and last_seen and first_seen != last_seen)
        base_verdict = (
            TrustVerdict.UNTRUSTED_RETURNING
            if has_history
            else TrustVerdict.UNTRUSTED_NEW
        )

        # --- Step 3: MAC randomization secondary signals ---
        mac_rand_suspected       = False
        matched_trusted_hostname = None
        matched_trusted_vendor   = None

        if base_verdict == TrustVerdict.UNTRUSTED_NEW:
            # Check hostname
            if hostname:
                hostname_lower = hostname.lower()
                for known_host in trusted_hostnames:
                    if known_host and self._hostnames_match(hostname_lower, known_host):
                        mac_rand_suspected       = True
                        matched_trusted_hostname = known_host
                        base_verdict = TrustVerdict.UNTRUSTED_RETURNING
                        logger.warning(
                            f"MAC randomization suspected: {mac} ({ip}) "
                            f"hostname '{hostname}' matches trusted device "
                            f"'{known_host}' ({trusted_hostnames[known_host]})"
                        )
                        break

            # Check vendor (only randomizing-prone vendors worth checking)
            if not mac_rand_suspected and vendor:
                vendor_lower = vendor.lower()
                is_randomizing = any(
                    rv in vendor_lower
                    for rv in self._randomizing_vendors
                )
                if is_randomizing:
                    for known_vendor_lower in trusted_vendors:
                        if known_vendor_lower and known_vendor_lower in vendor_lower:
                            mac_rand_suspected       = True
                            matched_trusted_vendor   = known_vendor_lower
                            base_verdict = TrustVerdict.UNTRUSTED_RETURNING
                            logger.warning(
                                f"MAC randomization suspected: {mac} ({ip}) "
                                f"vendor '{vendor}' matches trusted device vendor "
                                f"'{known_vendor_lower}'"
                            )
                            break

            # Check label
            if not mac_rand_suspected and label:
                label_lower = label.lower()
                if label_lower in trusted_labels:
                    mac_rand_suspected = True
                    base_verdict = TrustVerdict.UNTRUSTED_RETURNING
                    logger.warning(
                        f"MAC randomization suspected: {mac} ({ip}) "
                        f"label '{label}' matches a trusted device label."
                    )

        log_level = logging.DEBUG if trusted else logging.WARNING
        logger.log(
            log_level,
            f"Verdict: {mac} ({ip}) → {base_verdict.value}"
            + (f" [label: {label}]" if label else "")
            + (" [MAC_RAND?]" if mac_rand_suspected else "")
        )

        return DeviceVerdict(
            mac=mac,
            ip=ip,
            verdict=base_verdict,
            label=label or None,
            vendor=vendor or None,
            hostname=hostname or None,
            os=device.get("os"),
            open_ports=device.get("open_ports") or [],
            first_seen=first_seen,
            last_seen=last_seen,
            mac_randomization_suspected=mac_rand_suspected,
            matched_trusted_hostname=matched_trusted_hostname,
            matched_trusted_vendor=matched_trusted_vendor,
            network=network,
        )

    # ------------------------------------------------------------------
    # Private — secondary signal extraction
    # ------------------------------------------------------------------

    def _extract_trusted_hostnames(self, devices: List[Dict]) -> Dict[str, str]:
        """Return {hostname_lower: mac} for all trusted devices with hostnames."""
        result = {}
        for d in devices:
            if d.get("trusted") and d.get("hostname"):
                result[d["hostname"].lower()] = (d.get("mac") or "").lower()
        return result

    def _extract_trusted_vendors(self, devices: List[Dict]) -> Dict[str, str]:
        """Return {vendor_lower: mac} for all trusted devices with vendors."""
        result = {}
        for d in devices:
            if d.get("trusted") and d.get("vendor"):
                result[d["vendor"].lower()] = (d.get("mac") or "").lower()
        return result

    def _extract_trusted_labels(self, devices: List[Dict]) -> Dict[str, str]:
        """Return {label_lower: mac} for all trusted devices with labels."""
        result = {}
        for d in devices:
            if d.get("trusted") and d.get("label"):
                result[d["label"].lower()] = (d.get("mac") or "").lower()
        return result

    def _hostnames_match(self, a: str, b: str) -> bool:
        """
        Fuzzy hostname match — handles cases like:
          'harshwardhan-iphone' == 'harshwardhan-iphone'
          'harshwardhan-iphone-2' ≈ 'harshwardhan-iphone'  (same device, iOS suffix)
        Simple prefix match on the base name (before last hyphen+digits).
        """
        def base(h: str) -> str:
            parts = h.rsplit("-", 1)
            if len(parts) == 2 and parts[1].isdigit():
                return parts[0]
            return h

        return base(a) == base(b) or a == b