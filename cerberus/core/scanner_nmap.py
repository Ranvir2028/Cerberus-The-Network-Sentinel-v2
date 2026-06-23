# deps: pip install python-nmap
# system: nmap must be installed → sudo apt install nmap
"""
core/scanner_nmap.py

Job: same contract as scanner_scapy — network string IN, device list OUT —
but uses Nmap underneath for richer fingerprinting.

Two scan modes:
  scan_quick(network)  → ping sweep (-sn), fast, returns {ip, mac, vendor,
                         hostname, network, scan_type}
  scan_deep(network)   → OS + top-ports (-sn -A --top-ports 100), slow,
                         returns above + {os, open_ports}

Rules (identical to ScapyScanner):
  - NO RouterDetector import. Scheduler injects the network string.
  - NO storage, NO trust logic.
  - Any failure → return [], never crash.
  - nmap binary missing → log clearly, return [] on every call.

Bug fixed from old version:
  scan_all_networks_quick() built per-network device lists and tagged each
  device with its interface, but never called all_devices.extend(devices).
  all_devices stayed [] the entire loop. Method always returned [].
  → Fixed by removing the method entirely (scheduler's job now) and ensuring
    scan_quick / scan_deep always extend correctly inside their own loops.
"""

import subprocess
import logging
from typing import List, Dict, Optional

import nmap

logger = logging.getLogger("cerberus.core.scanner_nmap")


class NmapScanner:
    """
    Nmap-based network scanner.

    Contract:
        scanner = NmapScanner()
        devices = scanner.scan_quick("192.168.1.0/24")
        devices = scanner.scan_deep("192.168.1.0/24")
        device  = scanner.scan_single_host("192.168.1.1")

    Scheduler calls scan_quick() every ~10-15 min.
    Scheduler calls scan_deep() less frequently (or on demand).
    Neither method knows or cares how the network string was obtained.
    """

    def __init__(self):
        self.nmap_available = self._check_nmap_installed()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_quick(self, network: str) -> List[Dict]:
        """
        Ping sweep on one network. Fast, no port/OS data.

        Args:
            network: CIDR string, e.g. '192.168.1.0/24'

        Returns:
            List of dicts — {ip, mac, vendor, hostname, network, scan_type}.
            mac/vendor/hostname may be None if Nmap couldn't determine them.
            Returns [] on any failure.
        """
        if not self._guard(network, "scan_quick"):
            return []

        logger.info(f"Nmap quick scan → {network}")

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments="-sn")

            devices: List[Dict] = []
            for host in nm.all_hosts():
                devices.append(self._extract_quick(nm, host, network))

            logger.info(
                f"Quick scan done → {network} | {len(devices)} device(s)."
            )
            return devices

        except Exception as e:
            logger.error(f"Quick scan failed on {network}: {e}")
            return []

    def scan_deep(self, network: str) -> List[Dict]:
        """
        OS detection + top-100 ports scan on one network. Slow — scheduler
        runs this every ~10-15 min, never simultaneously with Scapy on the
        same network (the scheduler enforces the lock, not this module).

        Args:
            network: CIDR string, e.g. '192.168.1.0/24'

        Returns:
            List of dicts — {ip, mac, vendor, hostname, os, open_ports,
            network, scan_type}.
            Returns [] on any failure.
        """
        if not self._guard(network, "scan_deep"):
            return []

        logger.info(f"Nmap deep scan → {network} (this takes a while...)")

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments="-sn -A --top-ports 100")

            devices: List[Dict] = []
            for host in nm.all_hosts():
                devices.append(self._extract_deep(nm, host, network))

            logger.info(
                f"Deep scan done → {network} | {len(devices)} device(s)."
            )
            return devices

        except Exception as e:
            logger.error(f"Deep scan failed on {network}: {e}")
            return []

    def scan_single_host(
        self, ip: str, deep: bool = True
    ) -> Optional[Dict]:
        """
        Scan one specific IP address.
        Used by the scheduler when a new MAC appears and needs fingerprinting.

        Args:
            ip  : Target IP address string.
            deep: If True, run OS + port detection. False = ping only.

        Returns:
            Single device dict, or None if host is unreachable / scan fails.
        """
        if not self.nmap_available:
            logger.error("Nmap not available — cannot scan single host.")
            return None

        if not ip:
            logger.error("scan_single_host() called with empty IP.")
            return None

        logger.info(f"Nmap single host scan → {ip} (deep={deep})")

        try:
            nm = nmap.PortScanner()
            arguments = "-sn -A --top-ports 100" if deep else "-sn"
            nm.scan(hosts=ip, arguments=arguments)

            if ip not in nm.all_hosts():
                logger.warning(f"Host {ip} did not respond to Nmap scan.")
                return None

            if deep:
                return self._extract_deep(nm, ip, network=ip)
            else:
                return self._extract_quick(nm, ip, network=ip)

        except Exception as e:
            logger.error(f"Single host scan failed for {ip}: {e}")
            return None

    # ------------------------------------------------------------------
    # Private — data extraction helpers
    # ------------------------------------------------------------------

    def _extract_quick(self, nm: nmap.PortScanner, host: str, network: str) -> Dict:
        """Pull quick-scan fields from a scanned host."""
        device = {
            "ip":        host,
            "mac":       None,
            "vendor":    None,
            "hostname":  None,
            "network":   network,
            "scan_type": "nmap_quick",
        }

        addrs = nm[host].get("addresses", {})
        if "mac" in addrs:
            device["mac"] = addrs["mac"]

        vendor_map = nm[host].get("vendor", {})
        if vendor_map:
            device["vendor"] = list(vendor_map.values())[0]

        hostnames = nm[host].get("hostnames", [])
        if hostnames:
            device["hostname"] = hostnames[0].get("name") or None

        logger.debug(
            f"  {host} → mac={device['mac']} vendor={device['vendor']}"
        )
        return device

    def _extract_deep(self, nm: nmap.PortScanner, host: str, network: str) -> Dict:
        """Pull deep-scan fields from a scanned host."""
        device = self._extract_quick(nm, host, network)  # Start with quick fields
        device["scan_type"] = "nmap_deep"
        device["os"] = None
        device["open_ports"] = []

        osmatch = nm[host].get("osmatch", [])
        if osmatch:
            device["os"] = osmatch[0].get("name") or None

        tcp_ports = nm[host].get("tcp", {})
        for port, info in tcp_ports.items():
            if info.get("state") == "open":
                device["open_ports"].append(port)

        logger.debug(
            f"  {host} → os={device['os']} ports={device['open_ports']}"
        )
        return device

    # ------------------------------------------------------------------
    # Private — guards
    # ------------------------------------------------------------------

    def _guard(self, network: str, method: str) -> bool:
        """Return False (and log) if we can't proceed with a scan."""
        if not self.nmap_available:
            logger.error(
                f"{method}() called but Nmap is not installed. "
                "Install: sudo apt install nmap"
            )
            return False
        if not network:
            logger.error(f"{method}() called with empty network string.")
            return False
        return True

    def _check_nmap_installed(self) -> bool:
        """Check if the nmap binary is present on the system."""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            if result.returncode == 0:
                version_line = result.stdout.decode().split("\n")[0]
                logger.debug(f"Nmap found: {version_line}")
                return True
            return False
        except FileNotFoundError:
            logger.error(
                "Nmap binary not found. "
                "Install: sudo apt install nmap"
            )
            return False
        except Exception as e:
            logger.error(f"Error checking Nmap installation: {e}")
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
        print("Usage: sudo python -m cerberus.core.scanner_nmap <network> [quick|deep]")
        print("Example: sudo python -m cerberus.core.scanner_nmap 192.168.1.0/24 quick")
        sys.exit(1)

    target = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "quick"

    scanner = NmapScanner()

    print("\n" + "=" * 60)
    print(f"NMAP SCANNER — SMOKE TEST ({mode.upper()})")
    print("=" * 60)
    print(f"Target : {target}")
    print(f"Mode   : {mode}\n")

    if mode == "deep":
        devices = scanner.scan_deep(target)
    else:
        devices = scanner.scan_quick(target)

    if not devices:
        print("No devices found.")
    else:
        for i, d in enumerate(devices, 1):
            print(f"Device #{i}")
            print(f"  IP       : {d.get('ip', 'N/A')}")
            print(f"  MAC      : {d.get('mac', 'N/A')}")
            print(f"  Vendor   : {d.get('vendor', 'N/A')}")
            print(f"  Hostname : {d.get('hostname', 'N/A')}")
            if "os" in d:
                print(f"  OS       : {d.get('os', 'N/A')}")
            if "open_ports" in d and d["open_ports"]:
                print(f"  Ports    : {', '.join(map(str, d['open_ports']))}")
            print()

    print("=" * 60)