"""
Passive mDNS (Bonjour/Zeroconf) discovery — finds device hostnames
broadcast over multicast DNS, independent of MAC address. Matters
because MAC randomization (iOS "Private Wi-Fi Address", Android's
equivalent) means the same phone can show a different MAC on every
reconnect, which breaks MAC-keyed trust tracking. mDNS identifies
devices by the name they broadcast instead (e.g. "Harshs-iPhone.local"),
which stays stable across MAC churn — a much better secondary signal
for trust_engine's hostname correlation than NetBIOS alone, since iOS
devices don't respond to NetBIOS/SMB at all and Nmap's nbstat never
sees them, but they almost always answer mDNS.

Also parses TXT records from service types it's already browsing —
no extra traffic, no new service types. Apple's _device-info._tcp
carries a "model" key with a real hardware string (e.g.
"iPhone14,5"), more specific than anything VendorLookup's OUI
database can give since OUI only identifies the manufacturer.
_airplay/_raop carry model/deviceid for Apple TVs and AirPlay
receivers; _googlecast carries "md"/"fn" for Chromecast and Android
TV. All delivered in the same get_service_info() call this module
already makes for the hostname — just not discarded anymore.

Pure: listen for `timeout` seconds, return whatever responded. Doesn't
know which MAC owns a given IP — mDNS operates at the IP layer, so
correlating a hostname/model back to a specific device row is the
scheduler's job, since it already holds the device_store reference;
this module only reports "this IP announced this name/model." If
zeroconf isn't installed, logs a warning once and returns [] on every
call rather than crashing the scheduler that depends on it.

Usage:
    mdns = MDNSDiscovery(timeout=5)
    results = mdns.discover()
    # → [{'ip': '192.168.1.23', 'hostname': 'Harshs-iPhone',
    #      'service_type': '_airplay._tcp.local.',
    #      'model': 'iPhone14,5'}, ...]
    # 'model' is None when the announcement carried no usable TXT data.
"""

import logging
import time
from typing import Dict, List, Optional

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

# TXT record keys worth extracting as a "model" string, checked in this
# priority order per service type family. Different vendors use
# different key names for essentially the same concept.
_MODEL_TXT_KEYS = ("model", "md", "am", "deviceid")
_FRIENDLY_NAME_TXT_KEYS = ("fn", "name")


class _CollectingListener(ServiceListener):
    """
    Internal zeroconf ServiceListener — collects {ip: {ip, hostname,
    service_type, model}} as responses arrive. Not part of the public
    API; MDNSDiscovery.discover() is the only thing that should
    construct this.
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

        model = self._extract_model(info)

        for ip in addresses:
            # Keep the first hostname/model seen per IP — multiple
            # service types announcing the same IP shouldn't overwrite
            # data already captured this cycle. If an earlier service
            # type gave us a hostname but no model, and a LATER one
            # gives a model but no hostname, merge rather than skip —
            # this is common (e.g. _workstation gives hostname,
            # _device-info gives model, for the same physical device).
            existing = self._results.get(ip)
            if existing is None:
                self._results[ip] = {
                    "ip": ip,
                    "hostname": hostname,
                    "service_type": type_,
                    "model": model,
                }
            else:
                if not existing.get("hostname") and hostname:
                    existing["hostname"] = hostname
                    existing["service_type"] = type_
                if not existing.get("model") and model:
                    existing["model"] = model

    def update_service(self, zeroconf: "Zeroconf", type_: str, name: str) -> None:
        pass  # Not needed for a one-shot discovery cycle

    def remove_service(self, zeroconf: "Zeroconf", type_: str, name: str) -> None:
        pass  # Not needed for a one-shot discovery cycle

    # ------------------------------------------------------------------
    # TXT record parsing
    # ------------------------------------------------------------------

    def _extract_model(self, info) -> Optional[str]:
        """
        Pull a human-readable model/friendly-name string out of an
        mDNS ServiceInfo's TXT record properties, if present.

        zeroconf exposes TXT records via info.properties — a dict of
        {bytes: bytes} (raw, undecoded). Keys/values vary by vendor and
        aren't guaranteed to be valid UTF-8 for every possible service
        type in the wild, so every decode is wrapped defensively —
        malformed TXT data from a misbehaving device must never crash
        discovery for every other device on the network.

        Returns:
            A model string if any recognized key was found and decoded
            successfully, else None. Never raises.
        """
        try:
            props = info.properties or {}
        except Exception:
            return None

        if not props:
            return None

        # Normalize keys to lowercase strings once, skip anything that
        # doesn't decode cleanly rather than aborting the whole record.
        decoded: Dict[str, str] = {}
        for k, v in props.items():
            try:
                key = k.decode("utf-8", errors="ignore").lower() if isinstance(k, bytes) else str(k).lower()
                val = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else (str(v) if v is not None else "")
                decoded[key] = val
            except Exception:
                continue

        for key in _MODEL_TXT_KEYS:
            if decoded.get(key):
                return decoded[key]

        for key in _FRIENDLY_NAME_TXT_KEYS:
            if decoded.get(key):
                return decoded[key]

        return None


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
            List of {ip, hostname, service_type, model} dicts, one per
            responding IP. 'model' is None when no TXT record carried
            usable model/friendly-name data. Empty list if zeroconf is
            unavailable, no devices responded, or any error occurred —
            never raises, so the scheduler can call this every cycle
            without guarding it in a try/except itself.
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
        with_model = sum(1 for d in devices if d.get("model"))
        logger.info(
            f"mDNS discovery done — {len(devices)} host(s) responded "
            f"({with_model} with model/name data from TXT records)."
        )
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
        print(f"{'IP ADDRESS':<18} {'HOSTNAME':<28} {'MODEL':<20} {'SERVICE TYPE'}")
        print("-" * 90)
        for r in results:
            print(
                f"{r['ip']:<18} {r['hostname']:<28} "
                f"{(r.get('model') or '-'):<20} {r['service_type']}"
            )

    print("\n" + "=" * 60)