# deps: pip install python-nmap
# system: nmap must be installed → sudo apt install nmap / winget install nmap
"""
core/scanner_nmap.py

Three scan tiers — all return the same base dict shape so scheduler and
device_store never need to care which tier produced a result:

  scan_quick(network)
      Ping sweep (-sn). Fast. Returns {ip, mac, vendor, hostname, network,
      scan_type}. Used every 3 min to keep the live-host list fresh.

  scan_aggressive_hosts(live_ips, network, workers=4)
      The main fingerprinting engine. Takes a list of KNOWN-ALIVE IPs
      (from Scapy ARP, not guessed from the subnet) and scans each one
      with full -A -T4 -sV -O --top-ports 1000 + NSE scripts in a thread
      pool. Returns richest possible dict per host: {ip, mac, vendor,
      hostname, os, os_accuracy, open_ports, services, http_title,
      ssh_hostkey, scan_type, network}.

  scan_single_host(ip, aggressive=True)
      On-demand scan of one IP. Used when a brand-new MAC is spotted by
      Scapy mid-cycle and needs immediate fingerprinting.

Rules (unchanged):
  - NO RouterDetector import. Scheduler injects IPs/networks.
  - NO storage, NO trust logic.
  - Any failure → return [] / None, never crash.
  - nmap binary missing → log clearly, return empty on every call.
"""

import subprocess
import logging
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

import nmap

logger = logging.getLogger("cerberus.core.scanner_nmap")

# NSE scripts that add real value without being noisy or intrusive
_AGGRESSIVE_SCRIPTS = ",".join([
    "banner",           # grab service banners
    "http-title",       # web server page titles
    "http-server-header",
    "ssh-hostkey",      # SSH host key fingerprint
    "smb-os-discovery", # Windows SMB OS info
    "nbstat",           # NetBIOS name info
    "dns-service-discovery",
])

_AGGRESSIVE_ARGS = (
    f"-A -T4 -sV -O --top-ports 1000 "
    f"--script={_AGGRESSIVE_SCRIPTS} "
    f"--osscan-guess --version-intensity 7"
)

_QUICK_ARGS = "-sn"


class NmapScanner:
    """
    Three-tier Nmap scanner.

    All public methods are pure functions: IPs/network string in, device
    list out. No state held between calls except nmap_available flag.
    """

    def __init__(self):
        self.nmap_available = self._check_nmap_installed()

    # ------------------------------------------------------------------
    # Tier 1 — Quick ping sweep (every 3 min)
    # ------------------------------------------------------------------

    def scan_quick(self, network: str) -> List[Dict]:
        """
        Ping sweep the whole subnet. Fast — just presence + basic info.

        Returns list of {ip, mac, vendor, hostname, network, scan_type}.
        Primary use: keep live-host list current between aggressive cycles.
        """
        if not self._guard(network, "scan_quick"):
            return []

        logger.info(f"[nmap-quick] Scanning {network}")
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments=_QUICK_ARGS)

            devices = [
                self._extract_base(nm, host, network, "nmap_quick")
                for host in nm.all_hosts()
            ]
            logger.info(f"[nmap-quick] Done → {network} | {len(devices)} host(s)")
            return devices

        except Exception as e:
            logger.error(f"[nmap-quick] Failed on {network}: {e}")
            return []

    # ------------------------------------------------------------------
    # Tier 2 — Aggressive threaded fingerprint (every 6 min)
    # ------------------------------------------------------------------

    def scan_aggressive_hosts(
        self,
        live_ips: List[str],
        network: str,
        workers: int = 4,
    ) -> List[Dict]:
        """
        Aggressively fingerprint a list of known-alive IPs in parallel.

        Each IP gets its own thread (up to `workers` concurrent). Every
        host is scanned with: -A -T4 -sV -O --top-ports 1000 + NSE scripts.

        Args:
            live_ips : IPs confirmed alive by Scapy ARP this cycle.
            network  : CIDR string the IPs belong to (for tagging results).
            workers  : Thread pool size. 4 is safe on any modern machine.

        Returns:
            List of rich dicts per host. Hosts that time out or error
            are skipped (logged at WARNING), not included in results.
        """
        if not self.nmap_available:
            logger.error("[nmap-aggressive] Nmap not available.")
            return []

        if not live_ips:
            logger.debug("[nmap-aggressive] No live IPs to scan.")
            return []

        logger.info(
            f"[nmap-aggressive] Fingerprinting {len(live_ips)} host(s) "
            f"on {network} with {workers} workers..."
        )

        results: List[Dict] = []

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="nmap-agg") as pool:
            futures = {
                pool.submit(self._scan_one_host_aggressive, ip, network): ip
                for ip in live_ips
            }
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        logger.debug(
                            f"[nmap-aggressive] {ip} → "
                            f"os={result.get('os')} "
                            f"ports={result.get('open_ports')} "
                            f"services={list(result.get('services', {}).keys())}"
                        )
                    else:
                        logger.warning(
                            f"[nmap-aggressive] {ip} returned no data "
                            f"(host may have gone offline mid-scan)."
                        )
                except Exception as e:
                    logger.error(f"[nmap-aggressive] Thread error for {ip}: {e}")

        logger.info(
            f"[nmap-aggressive] Done → {network} | "
            f"{len(results)}/{len(live_ips)} host(s) fingerprinted."
        )
        return results

    # ------------------------------------------------------------------
    # Tier 3 — On-demand single host (new device spotted mid-cycle)
    # ------------------------------------------------------------------

    def scan_single_host(
        self, ip: str, network: str = "", aggressive: bool = True
    ) -> Optional[Dict]:
        """
        Scan one IP immediately. Called by scheduler when Scapy spots a
        brand-new MAC that has no fingerprint yet.

        Args:
            ip         : Target IP.
            network    : CIDR string for tagging (can be empty string).
            aggressive : True = full -A scan, False = quick ping only.

        Returns:
            Device dict or None if unreachable / scan failed.
        """
        if not self.nmap_available:
            logger.error("[nmap-single] Nmap not available.")
            return None
        if not ip:
            logger.error("[nmap-single] Called with empty IP.")
            return None

        logger.info(f"[nmap-single] Scanning {ip} (aggressive={aggressive})")

        if aggressive:
            return self._scan_one_host_aggressive(ip, network or ip)
        else:
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=ip, arguments=_QUICK_ARGS)
                if ip not in nm.all_hosts():
                    logger.warning(f"[nmap-single] {ip} did not respond.")
                    return None
                return self._extract_base(nm, ip, network or ip, "nmap_quick")
            except Exception as e:
                logger.error(f"[nmap-single] Failed for {ip}: {e}")
                return None

    # ------------------------------------------------------------------
    # Private — single-host aggressive scan (used by thread pool + single)
    # ------------------------------------------------------------------

    def _scan_one_host_aggressive(self, ip: str, network: str) -> Optional[Dict]:
        """
        Run full aggressive scan on one IP. Thread-safe — each call
        creates its own PortScanner instance.
        """
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments=_AGGRESSIVE_ARGS)

            if ip not in nm.all_hosts():
                return None

            device = self._extract_base(nm, ip, network, "nmap_aggressive")
            device["os"]          = None
            device["os_accuracy"] = None
            device["open_ports"]  = []
            device["services"]    = {}   # port → {name, version, product}
            device["http_title"]  = None
            device["ssh_hostkey"] = None
            device["banners"]     = {}   # port → banner string

            # OS detection
            osmatch = nm[ip].get("osmatch", [])
            if osmatch:
                best = osmatch[0]
                device["os"]          = best.get("name")
                device["os_accuracy"] = int(best.get("accuracy", 0))

            # TCP ports — open ones only
            tcp = nm[ip].get("tcp", {})
            for port, info in tcp.items():
                if info.get("state") != "open":
                    continue
                device["open_ports"].append(port)
                device["services"][port] = {
                    "name":    info.get("name", ""),
                    "product": info.get("product", ""),
                    "version": info.get("version", ""),
                    "extra":   info.get("extrainfo", ""),
                }

            # NSE script output
            scripts = nm[ip].get("hostscript", [])
            for s in scripts:
                sid    = s.get("id", "")
                output = s.get("output", "").strip()
                if "http-title" in sid and output:
                    device["http_title"] = output
                if "ssh-hostkey" in sid and output:
                    device["ssh_hostkey"] = output[:300]  # truncate long keys

            # Per-port script output (banners)
            for port, info in tcp.items():
                port_scripts = info.get("script", {})
                if "banner" in port_scripts:
                    device["banners"][port] = port_scripts["banner"][:200]

            return device

        except Exception as e:
            logger.error(f"[nmap-aggressive] Scan error for {ip}: {e}")
            return None

    # ------------------------------------------------------------------
    # Private — base dict builder (shared by all tiers)
    # ------------------------------------------------------------------

    def _extract_base(
        self,
        nm: nmap.PortScanner,
        host: str,
        network: str,
        scan_type: str,
    ) -> Dict:
        """Extract common fields present in any scan tier."""
        device: Dict = {
            "ip":        host,
            "mac":       None,
            "vendor":    None,
            "hostname":  None,
            "network":   network,
            "scan_type": scan_type,
        }

        addrs = nm[host].get("addresses", {})
        if "mac" in addrs:
            device["mac"] = addrs["mac"].lower()  # normalize immediately

        vendor_map = nm[host].get("vendor", {})
        if vendor_map:
            device["vendor"] = list(vendor_map.values())[0]

        hostnames = nm[host].get("hostnames", [])
        for h in hostnames:
            name = h.get("name", "").strip()
            if name:
                device["hostname"] = name
                break

        return device

    # ------------------------------------------------------------------
    # Private — guards
    # ------------------------------------------------------------------

    def _guard(self, target: str, method: str) -> bool:
        if not self.nmap_available:
            logger.error(f"[{method}] Nmap not installed.")
            return False
        if not target:
            logger.error(f"[{method}] Called with empty target.")
            return False
        return True

    def _check_nmap_installed(self) -> bool:
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
            logger.error("Nmap binary not found. Install: sudo apt install nmap")
            return False
        except Exception as e:
            logger.error(f"Nmap check error: {e}")
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
        print("Usage: python -m cerberus.core.scanner_nmap <network> [quick|aggressive]")
        print("Example: python -m cerberus.core.scanner_nmap 192.168.1.0/24 aggressive")
        sys.exit(1)

    target  = sys.argv[1]
    mode    = sys.argv[2] if len(sys.argv) > 2 else "quick"
    scanner = NmapScanner()

    print("\n" + "=" * 70)
    print(f"NMAP SCANNER — {mode.upper()} TEST")
    print("=" * 70)

    if mode == "aggressive":
        # First quick scan to get live IPs, then aggressive on those
        print("Step 1: Quick scan to find live hosts...")
        quick = scanner.scan_quick(target)
        live  = [d["ip"] for d in quick]
        print(f"Live hosts: {live}\n")
        print("Step 2: Aggressive fingerprint on live hosts...")
        devices = scanner.scan_aggressive_hosts(live, target, workers=4)
    else:
        devices = scanner.scan_quick(target)

    print(f"\nResults — {len(devices)} device(s):\n")
    for i, d in enumerate(devices, 1):
        print(f"  [{i}] {d.get('ip')}")
        print(f"       MAC       : {d.get('mac', 'N/A')}")
        print(f"       Vendor    : {d.get('vendor', 'N/A')}")
        print(f"       Hostname  : {d.get('hostname', 'N/A')}")
        print(f"       OS        : {d.get('os', 'N/A')} "
              f"(accuracy: {d.get('os_accuracy', 'N/A')}%)")
        ports = d.get("open_ports", [])
        print(f"       Ports     : {ports if ports else 'none'}")
        for port, svc in d.get("services", {}).items():
            print(f"         {port}/tcp  {svc['name']} "
                  f"{svc['product']} {svc['version']}".strip())
        if d.get("http_title"):
            print(f"       HTTP Title: {d['http_title']}")
        if d.get("ssh_hostkey"):
            print(f"       SSH Key   : {d['ssh_hostkey'][:80]}...")
        print()

    print("=" * 70)