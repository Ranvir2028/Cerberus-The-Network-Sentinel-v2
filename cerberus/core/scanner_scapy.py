# deps: pip install scapy
"""
core/scanner_scapy.py

Job: given one network CIDR string, send one ARP broadcast
(optionally preceded by a wake-up ICMP ping) and return every
device that answered as a list of {ip, mac, network} dicts.

Rules:
- Pure function contract: network string IN → device list OUT.
- Does NOT import RouterDetector. Does NOT detect networks itself.
- Does NOT store anything. Does NOT decide trust.
- Scheduler injects the network string — this module never fetches it.
- Empty network / no responses → return [], never crash.

Bugs fixed from old version:
  1. `network: network` dict-key bug  → fixed to `'network': network`
  2. Broken retry loop (return [] inside for-loop body) → fixed
  3. `update_network` dead line `self.auto_detect = new_network` → removed
  4. `scan_all_networks` that called RouterDetector internally → removed entirely
     (scheduler's job now, not the scanner's)
"""

import time
import logging
from typing import List, Dict, Optional

from scapy.all import ARP, Ether, srp, IP, ICMP, send

logger = logging.getLogger("cerberus.core.scanner_scapy")


class ScapyScanner:
    """
    Scapy-based ARP scanner.

    Contract:
        scanner = ScapyScanner()
        devices = scanner.scan("192.168.1.0/24")
        # → [{'ip': '192.168.1.1', 'mac': 'aa:bb:cc:dd:ee:ff',
        #      'network': '192.168.1.0/24'}, ...]

    The scheduler calls scan(network_cidr) directly — it passes the
    network string in, this class never goes looking for it itself.
    """

    def __init__(self, timeout: int = 5, wake_up_ping: bool = True):
        """
        Args:
            timeout      : Seconds to wait for ARP replies per scan.
            wake_up_ping : Send ICMP broadcast before ARP to wake
                           sleeping devices. Non-critical — failures
                           are logged at DEBUG and scanning continues.
        """
        self.timeout = timeout
        self.wake_up_ping = wake_up_ping
        logger.debug(
            f"ScapyScanner ready — timeout={timeout}s, "
            f"wake_up_ping={wake_up_ping}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, network: str) -> List[Dict[str, str]]:
        """
        ARP-scan one network CIDR and return responding devices.
        Sends ARP twice — catches devices that missed the first packet.

        Args:
            network: CIDR string, e.g. '192.168.1.0/24'

        Returns:
            List of dicts — each has 'ip', 'mac', 'network'.
            Returns [] on any failure.
        """
        if not network:
            logger.error("scan() called with empty network string.")
            return []

        logger.info(f"ARP scan starting → {network}")

        if self.wake_up_ping:
            self._send_wake_up_ping(network)

        try:
            arp_request = ARP(pdst=network)
            ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet      = ether_frame / arp_request

            # First pass
            answered, _ = srp(packet, timeout=self.timeout, verbose=0)

            # Second pass — catches devices that missed the first ARP
            time.sleep(0.5)
            answered2, _ = srp(packet, timeout=self.timeout, verbose=0)

            # Merge both passes, deduplicate by MAC
            seen_macs: set = set()
            devices: List[Dict[str, str]] = []
            for _, received in list(answered) + list(answered2):
                mac = received.hwsrc.lower()
                if mac not in seen_macs:
                    seen_macs.add(mac)
                    devices.append({
                        "ip":      received.psrc,
                        "mac":     mac,
                        "network": network,
                    })

            logger.info(
                f"ARP scan done → {network} | "
                f"{len(devices)} device(s) found."
            )
            return devices

        except PermissionError:
            logger.error(
                "Permission denied. Run Cerberus with sudo / as root."
            )
            return []
        except Exception as e:
            logger.error(f"ARP scan failed on {network}: {e}")
            return []

    def scan_with_retry(
        self,
        network: str,
        max_retries: int = 3,
    ) -> List[Dict[str, str]]:
        """
        Retry scan up to max_retries times if no devices are found.

        Args:
            network     : CIDR string to scan.
            max_retries : Maximum number of attempts before giving up.

        Returns:
            Device list from first successful attempt, or [] after all
            retries are exhausted.
        """
        # BUG FIX 2: old code had `return []` INSIDE the for-loop body,
        # which meant it always bailed after the first failed attempt
        # and never actually retried. Fixed by moving the final return
        # OUTSIDE the loop so all attempts run before giving up.

        for attempt in range(1, max_retries + 1):
            logger.debug(f"Scan attempt {attempt}/{max_retries} → {network}")

            devices = self.scan(network)
            if devices:
                return devices

            if attempt < max_retries:
                wait_time = attempt * 2  # 2s, 4s, 6s — backoff
                logger.warning(
                    f"No devices on {network}. "
                    f"Retry {attempt + 1}/{max_retries} in {wait_time}s..."
                )
                time.sleep(wait_time)

        # Reached only after ALL attempts exhausted
        logger.warning(
            f"All {max_retries} scan attempts failed for {network}."
        )
        return []  # BUG FIX 2: this line is now OUTSIDE the loop

    def quick_scan(self, network: str) -> List[Dict[str, str]]:
        """
        Fast scan — 1s timeout, no wake-up ping.
        Used by the scheduler for its frequent ~60s ARP sweeps.

        Args:
            network: CIDR string to scan.
        """
        original_timeout = self.timeout
        original_ping = self.wake_up_ping

        self.timeout = 1
        self.wake_up_ping = False

        try:
            return self.scan(network)
        finally:
            # Always restore — even if scan() raises
            self.timeout = original_timeout
            self.wake_up_ping = original_ping

    def update_network_target(self, new_network: str) -> None:
        """
        No-op placeholder — ScapyScanner is stateless about networks.
        The scheduler passes the network per-call; there's nothing to
        'update' here. Kept so any old call sites don't crash.

        BUG FIX 3: old version had `self.auto_detect = new_network`
        (assigning a string to a bool flag) followed immediately by
        `self.auto_detect = False` — a dead assignment doing nothing.
        Both lines removed. This class has no auto_detect concept.
        """
        logger.debug(
            f"update_network_target({new_network}) called — "
            "ScapyScanner is stateless, scheduler manages network selection."
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _send_wake_up_ping(self, network: str) -> bool:
        """
        Send ICMP broadcast to wake sleeping devices before ARP sweep.
        Non-critical — a failure here must never abort the scan.

        Args:
            network: CIDR string; broadcast IP derived from its base address.

        Returns:
            True if ping sent, False if it failed (caller ignores this).
        """
        try:
            # Derive broadcast from network base:
            # '192.168.1.0/24' → '192.168.1.255'
            base_ip = network.split("/")[0]
            parts = base_ip.split(".")
            broadcast_ip = ".".join(parts[:3]) + ".255"

            send(IP(dst=broadcast_ip) / ICMP(), verbose=0)
            logger.debug(f"Wake-up ping → {broadcast_ip}")
            time.sleep(1)  # Give sleeping devices a moment to respond
            return True

        except Exception as e:
            logger.debug(f"Wake-up ping failed (non-critical): {e}")
            return False


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    if len(sys.argv) < 2:
        print("Usage: sudo python -m cerberus.core.scanner_scapy <network>")
        print("Example: sudo python -m cerberus.core.scanner_scapy 192.168.1.0/24")
        sys.exit(1)

    target = sys.argv[1]
    scanner = ScapyScanner(timeout=3, wake_up_ping=True)

    print("\n" + "=" * 60)
    print("SCAPY SCANNER — SMOKE TEST")
    print("=" * 60)
    print(f"Target: {target}\n")

    devices = scanner.scan_with_retry(target, max_retries=2)

    if not devices:
        print("No devices found.")
    else:
        print(f"{'IP ADDRESS':<20} {'MAC ADDRESS':<20} {'NETWORK':<20}")
        print("-" * 60)
        for d in devices:
            print(f"{d['ip']:<20} {d['mac']:<20} {d['network']:<20}")

    print("\n" + "=" * 60)