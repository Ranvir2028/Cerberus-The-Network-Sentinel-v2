# deps: pip install zeroconf
"""
detection/mdns_discovery.py

Job: passive mDNS (Bonjour/Zeroconf) discovery — finds device hostnames
broadcast over multicast DNS, independent of MAC address.

Why this exists:
  MAC randomization (iOS "Private Wi-Fi Address", Android's equivalent)
  means the SAME physical phone can show up under a different MAC every
  time it reconnects — confusing any MAC-keyed trust tracking. mDNS
  identifies devices by the NAME they broadcast (e.g. a phone announcing
  itself as "Harshs-iPhone.local"), which stays stable across MAC churn.
  This gives trust_engine's existing hostname-correlation logic (see
  intelligence/trust_engine.py) a much more reliable secondary signal
  than NetBIOS alone — iOS devices in particular don't respond to
  NetBIOS/SMB at all, so Nmap's nbstat script never sees them, but they
  almost always respond to mDNS.

Rules (same isolation pattern as scanner_scapy.py / scanner_nmap.py):
  - No Scapy/Nmap import. No storage. No trust logic.
  - Pure: listen for `timeout` seconds, return whatever responded.
  - Does NOT know which MAC owns a given IP — mDNS operates at the IP
    layer, not the MAC layer. Correlating an IP's mDNS hostname back to
    a specific device row is the SCHEDULER's job (it already holds the
    device_store reference) — this module only reports "this IP
    announced this name."
  - zeroconf missing → logs a warning once, returns [] on every call,
    never crashes the scheduler that depends on it.

Usage:
    mdns = MDNSDiscovery(timeout=5)
    results = mdns.discover()
    # → [{'ip': '192.168.1.23', 'hostname': 'Harshs-iPhone',
    #      'service_type': '_airplay._tcp.local.'}, ...]
"""

import logging
import time
from typing import Dict, List

logger = logging.getLogger("cerberus.detection.mdns_discovery")

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    _ZEROCONF_AVAILABLE = True
except ImportError:
    _ZEROCONF_AVAILABLE = False
    # Minimal stand-in so the class body below doesn't fail to define
    # at import time when zeroconf isn't installed yet.
    class ServiceListener:  # type: ignore
        pass

# A curated set of common mDNS service types — covers most phones,
# laptops, smart TVs, printers, and speakers without needing to browse
# every possible service type (which would be noisy and slow).
_COMMON_SERVICE_TYPES = (
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_airplay._tcp.local.",       # Apple devices (phones, Macs, Apple TV)
    "_raop._tcp.local.",          # AirPlay audio
    "_googlecast._tcp.local.",    # Chromecast / Google/Android TV
    "_spotify-connect._tcp.local.",
    "_http._tcp.local.",          # Many IoT devices expose a local web UI
    "_ipp._tcp.local.",           # Printers (IPP)
    "_printer._tcp.local.",
    "_smb._tcp.local.",
    "_ssh._tcp.local.",
)


class _CollectingListener(ServiceListener):
    """
    Internal zeroconf ServiceListener — collects {ip: {ip, hostname,
    service_type}} as responses arrive. Not part of the public API;
    MDNSDiscovery.discover() is the only thing that should construct this.
    """

    def __init__(self, zeroconf: "Zeroconf", results: Dict[str, Dict]):
        self._zeroconf = zeroconf
        self._results = results

    def add_service(self, zeroconf: "Zeroconf", type_: str, name: str) -> None:
        try:
            info = zeroconf.get_service_info(type_, name, timeout=2000)
        except Exception as e:
            logger.debug(f"mDNS get_service_info failed for {name}: {e}")
            return

        if not info:
            return

        try:
            addresses = info.parsed_addresses()
        except Exception:
            addresses = []

        if not addresses:
            return

        hostname = (info.server or name or "").rstrip(".")
        if hostname.lower().endswith(".local"):
            hostname = hostname[: -len(".local")]

        for ip in addresses:
            # Keep the first hostname seen per IP — multiple service
            # types announcing the same IP shouldn't overwrite a name
            # already captured this cycle.
            if ip not in self._results or not self._results[ip].get("hostname"):
                self._results[ip] = {
                    "ip": ip,
                    "hostname": hostname,
                    "service_type": type_,
                }

    def update_service(self, zeroconf: "Zeroconf", type_: str, name: str) -> None:
        pass  # Not needed for a one-shot discovery cycle

    def remove_service(self, zeroconf: "Zeroconf", type_: str, name: str) -> None:
        pass  # Not needed for a one-shot discovery cycle


class MDNSDiscovery:
    """
    One-shot mDNS browse cycle.

    Usage:
        mdns = MDNSDiscovery(timeout=5)
        results = mdns.discover()
    """

    def __init__(self, timeout: int = 5):
        """
        Args:
            timeout: Seconds to listen for mDNS responses per discover()
                     call. 5s is enough for most devices to respond;
                     raise it if your network is large or slow to settle.
        """
        self.timeout = timeout
        self._warned_missing_dep = False

        if not _ZEROCONF_AVAILABLE:
            logger.warning(
                "zeroconf not installed — mDNS discovery disabled. "
                "Run: pip install zeroconf"
            )

    def discover(self) -> List[Dict]:
        """
        Browse common mDNS service types for `self.timeout` seconds.

        Returns:
            List of {ip, hostname, service_type} dicts, one per
            responding IP. Empty list if zeroconf is unavailable, no
            devices responded, or any error occurred — never raises,
            so the scheduler can call this every cycle without guarding
            it in a try/except itself.
        """
        if not _ZEROCONF_AVAILABLE:
            return []

        results: Dict[str, Dict] = {}
        zc = None
        browsers = []

        try:
            zc = Zeroconf()
            listener = _CollectingListener(zc, results)

            for service_type in _COMMON_SERVICE_TYPES:
                browsers.append(ServiceBrowser(zc, service_type, listener))

            logger.debug(f"mDNS discovery running for {self.timeout}s...")
            time.sleep(self.timeout)

        except Exception as e:
            logger.error(f"mDNS discovery failed: {e}")
        finally:
            if zc is not None:
                try:
                    zc.close()
                except Exception as e:
                    logger.debug(f"mDNS zeroconf.close() error (non-critical): {e}")

        devices = list(results.values())
        logger.info(f"mDNS discovery done — {len(devices)} host(s) responded.")
        return devices


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    timeout = int(sys.argv[1]) if len(sys.argv) > 1 else 5

    print("\n" + "=" * 60)
    print("mDNS DISCOVERY — SMOKE TEST")
    print("=" * 60)
    print(f"Listening for {timeout}s...\n")

    mdns = MDNSDiscovery(timeout=timeout)
    results = mdns.discover()

    if not results:
        print(
            "No devices responded. This can mean: zeroconf isn't installed, "
            "no mDNS-capable devices are nearby, or your firewall blocks "
            "multicast traffic (UDP 5353). Try increasing the timeout."
        )
    else:
        print(f"{'IP ADDRESS':<18} {'HOSTNAME':<30} {'SERVICE TYPE'}")
        print("-" * 70)
        for r in results:
            print(f"{r['ip']:<18} {r['hostname']:<30} {r['service_type']}")

    print("\n" + "=" * 60)