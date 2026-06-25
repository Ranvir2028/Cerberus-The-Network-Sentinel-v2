# deps: none beyond stdlib + project modules
"""
core/scheduler.py

Three-tier scan coordinator per network:

  Tier 1 — Scapy ARP        every 60s   → fast device presence
  Tier 2 — Nmap quick       every 180s  → vendor/hostname refresh
  Tier 3 — Nmap aggressive  every 360s  → full OS/port/service fingerprint
                                           threaded pool of 4 workers
                                           targets ONLY live IPs from Scapy,
                                           not blind subnet sweep

Lock model:
  One threading.Lock per network CIDR. All three tiers acquire the same
  lock before scanning, so no two scanners ever hit the same network
  simultaneously. The aggressive tier holds the lock for longer — that's
  intentional and correct, Scapy and quick-nmap simply wait their turn.

Live-host cache:
  Scapy ARP results are stored in self._live_hosts[network] after every
  sweep. Nmap quick and aggressive tiers read from this cache — they never
  blindly sweep the whole /24. This is the Option B "smart targeting"
  architecture: find who's alive cheaply with ARP, fingerprint only those.

MAC normalization:
  Scapy returns lowercase MACs, Nmap returns uppercase. Both are lowercased
  before being handed to device_store so no duplicate rows are created.
"""

import time
import threading
import logging
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor

from cerberus.detection.router_detector import RouterDetector
from cerberus.core.scanner_scapy import ScapyScanner
from cerberus.core.scanner_nmap import NmapScanner
from cerberus.intelligence.trust_engine import TrustEngine, TrustVerdict
from cerberus.intelligence.learning_mode import LearningMode

logger = logging.getLogger("cerberus.core.scheduler")


# ---------------------------------------------------------------------------
# Per-network lock registry
# ---------------------------------------------------------------------------

class _NetworkLockRegistry:
    """One threading.Lock per network CIDR. Thread-safe registry."""

    def __init__(self):
        self._locks: Dict[str, threading.Lock] = {}
        self._meta  = threading.Lock()

    def get(self, network: str) -> threading.Lock:
        with self._meta:
            if network not in self._locks:
                self._locks[network] = threading.Lock()
                logger.debug(f"Lock created for {network}")
            return self._locks[network]


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

class Scheduler:
    """
    Three-tier scan coordinator.

    Args:
        device_store         : Any object with upsert(dict) method.
        scapy_interval       : Seconds between ARP sweeps (default 60).
        nmap_quick_interval  : Seconds between quick Nmap sweeps (default 180).
        nmap_aggressive_interval: Seconds between aggressive scans (default 360).
        aggressive_workers   : Thread pool size for aggressive scans (default 4).
        network_retry_wait   : Seconds to wait if no interfaces found (default 30).
        scapy_timeout        : ARP reply timeout in seconds (default 3).
    """

    def __init__(
        self,
        device_store,
        trust_engine:              TrustEngine  = None,
        learning_mode:             LearningMode = None,
        scapy_interval:            int = 60,
        nmap_quick_interval:       int = 180,
        nmap_aggressive_interval:  int = 360,
        aggressive_workers:        int = 4,
        network_retry_wait:        int = 30,
        scapy_timeout:             int = 3,
    ):
        self.device_store               = device_store
        self._trust_engine              = trust_engine or TrustEngine()
        self._learning_mode             = learning_mode  # None = no learning mode
        self.scapy_interval             = scapy_interval
        self.nmap_quick_interval        = nmap_quick_interval
        self.nmap_aggressive_interval   = nmap_aggressive_interval
        self.aggressive_workers         = aggressive_workers
        self.network_retry_wait         = network_retry_wait

        # Scanners — stateless, one instance each, reused per call
        self._scapy = ScapyScanner(timeout=scapy_timeout, wake_up_ping=True)
        self._nmap  = NmapScanner()

        # Live-host cache: network → set of IP strings from last Scapy sweep
        self._live_hosts: Dict[str, Set[str]] = {}
        self._live_hosts_lock = threading.Lock()

        self._locks      = _NetworkLockRegistry()
        self._stop_event = threading.Event()
        self._threads:   List[threading.Thread] = []
        self._networks:  List[Dict] = []

        logger.info(
            f"Scheduler created — "
            f"scapy={scapy_interval}s  "
            f"nmap-quick={nmap_quick_interval}s  "
            f"nmap-aggressive={nmap_aggressive_interval}s  "
            f"workers={aggressive_workers}  "
            f"learning_mode={'ON' if learning_mode else 'OFF'}"
        )

    # ------------------------------------------------------------------
    # Public control
    # ------------------------------------------------------------------

    def start(self, blocking: bool = True) -> None:
        logger.info("Scheduler starting...")
        self._stop_event.clear()

        self._networks = self._detect_networks_with_retry()
        if not self._networks:
            logger.critical("No networks found — scheduler cannot start.")
            return

        self._spawn_workers()

        if blocking:
            logger.info("Scheduler running. Press Ctrl+C to stop.")
            try:
                while not self._stop_event.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt received.")
                self.stop()

    def stop(self) -> None:
        logger.info("Scheduler stopping — waiting for workers to finish...")
        self._stop_event.set()
        for t in self._threads:
            t.join()
        self._threads.clear()
        logger.info("Scheduler stopped.")

    @property
    def is_running(self) -> bool:
        return not self._stop_event.is_set() and any(
            t.is_alive() for t in self._threads
        )

    def status(self) -> Dict:
        live_counts = {}
        with self._live_hosts_lock:
            for net, ips in self._live_hosts.items():
                live_counts[net] = len(ips)
        return {
            "running":                   self.is_running,
            "networks":                  [n["network"] for n in self._networks],
            "scapy_interval":            self.scapy_interval,
            "nmap_quick_interval":       self.nmap_quick_interval,
            "nmap_aggressive_interval":  self.nmap_aggressive_interval,
            "aggressive_workers":        self.aggressive_workers,
            "live_hosts_per_network":    live_counts,
            "active_threads":            [t.name for t in self._threads if t.is_alive()],
        }

    # ------------------------------------------------------------------
    # Network detection
    # ------------------------------------------------------------------

    def _detect_networks_with_retry(self) -> List[Dict]:
        detector = RouterDetector()
        while not self._stop_event.is_set():
            networks = detector.get_all_networks()
            if networks:
                logger.info(
                    f"Detected {len(networks)} network(s): "
                    + ", ".join(n["network"] for n in networks)
                )
                return networks
            logger.warning(
                f"No active networks. Retrying in {self.network_retry_wait}s..."
            )
            time.sleep(self.network_retry_wait)
        return []

    # ------------------------------------------------------------------
    # Worker spawning — 3 threads per network
    # ------------------------------------------------------------------

    def _spawn_workers(self) -> None:
        for net_info in self._networks:
            network = net_info["network"]
            iface   = net_info["interface"]

            # Initialise live-host cache for this network
            with self._live_hosts_lock:
                self._live_hosts[network] = set()

            threads = [
                threading.Thread(
                    target=self._scapy_worker,
                    args=(network, iface),
                    name=f"scapy-{network}",
                    daemon=True,
                ),
                threading.Thread(
                    target=self._nmap_quick_worker,
                    args=(network, iface),
                    name=f"nmap-quick-{network}",
                    daemon=True,
                ),
                threading.Thread(
                    target=self._nmap_aggressive_worker,
                    args=(network, iface),
                    name=f"nmap-agg-{network}",
                    daemon=True,
                ),
            ]

            for t in threads:
                self._threads.append(t)
                t.start()

            logger.info(
                f"3 workers started for {network} on {iface} — "
                f"[scapy / nmap-quick / nmap-aggressive]"
            )

    # ------------------------------------------------------------------
    # Worker loops
    # ------------------------------------------------------------------

    def _scapy_worker(self, network: str, iface: str) -> None:
        """
        Tier 1 — ARP sweep every scapy_interval seconds.
        Updates the live-host cache after every sweep so the Nmap workers
        always target current, confirmed-alive IPs.
        """
        logger.info(f"[scapy] Started → {network}")

        while not self._stop_event.is_set():
            lock = self._locks.get(network)
            with lock:
                logger.debug(f"[scapy] Scanning {network}")
                devices = self._scapy.scan(network)

            if devices:
                # Normalize MACs before storing
                for d in devices:
                    if d.get("mac"):
                        d["mac"] = d["mac"].lower()

                # Update live-host cache
                live_ips = {d["ip"] for d in devices}
                with self._live_hosts_lock:
                    self._live_hosts[network] = live_ips

                self._route_to_store(devices, scanner="scapy", iface=iface)
                logger.info(
                    f"[scapy] {network} → {len(devices)} device(s) | "
                    f"live: {sorted(live_ips)}"
                )

                # --- Learning mode: auto-trust during baseline window ---
                if self._learning_mode and self._learning_mode.is_active():
                    all_devices = self.device_store.get_all()
                    self._learning_mode.auto_trust_all(all_devices)

                # --- Trust engine: evaluate verdicts every cycle ---
                self._run_trust_evaluation(network)

            else:
                logger.debug(f"[scapy] No devices on {network} this cycle.")

            self._interruptible_sleep(self.scapy_interval)

        logger.info(f"[scapy] Exiting → {network}")

    def _nmap_quick_worker(self, network: str, iface: str) -> None:
        """
        Tier 2 — Quick ping sweep every nmap_quick_interval seconds.
        Updates vendor and hostname fields. Runs on live IPs only.
        Sleeps for one full quick interval on startup so Scapy always
        populates the live-host cache before Nmap reads it.
        """
        logger.info(
            f"[nmap-quick] Started → {network} | "
            f"first scan in {self.nmap_quick_interval}s"
        )
        self._interruptible_sleep(self.nmap_quick_interval)

        while not self._stop_event.is_set():
            live_ips = self._get_live_ips(network)

            if live_ips:
                lock = self._locks.get(network)
                with lock:
                    logger.debug(f"[nmap-quick] Scanning {len(live_ips)} host(s) on {network}")
                    # Pass space-separated IPs to Nmap — it accepts this fine.
                    # Then force 'network' field to the CIDR so device_store
                    # never sees "192.168.1.1 192.168.1.5" as the network value.
                    targets = " ".join(sorted(live_ips))
                    devices = self._nmap.scan_quick(targets)

                if devices:
                    for d in devices:
                        d["network"] = network  # always overwrite with real CIDR
                    self._route_to_store(devices, scanner="nmap_quick", iface=iface)
                    logger.info(
                        f"[nmap-quick] {network} → {len(devices)} device(s) updated"
                    )
            else:
                logger.debug(
                    f"[nmap-quick] No live hosts on {network} yet — skipping."
                )

            self._interruptible_sleep(self.nmap_quick_interval)

        logger.info(f"[nmap-quick] Exiting → {network}")

    def _nmap_aggressive_worker(self, network: str, iface: str) -> None:
        """
        Tier 3 — Full aggressive fingerprint every nmap_aggressive_interval.
        Targets only confirmed-alive IPs from Scapy cache.
        Uses a thread pool (aggressive_workers) to scan multiple hosts
        in parallel — one thread per host, up to the pool limit.
        Starts after one full aggressive interval so Scapy and quick-nmap
        both run first and populate the cache.
        """
        logger.info(
            f"[nmap-aggressive] Started → {network} | "
            f"first scan in {self.nmap_aggressive_interval}s"
        )
        self._interruptible_sleep(self.nmap_aggressive_interval)

        while not self._stop_event.is_set():
            live_ips = self._get_live_ips(network)

            if live_ips:
                lock = self._locks.get(network)
                with lock:
                    logger.info(
                        f"[nmap-aggressive] Fingerprinting {len(live_ips)} "
                        f"host(s) on {network} | workers={self.aggressive_workers}"
                    )
                    devices = self._nmap.scan_aggressive_hosts(
                        list(live_ips),
                        network,
                        workers=self.aggressive_workers,
                    )

                if devices:
                    for d in devices:
                        d["network"] = network  # always overwrite with real CIDR
                    self._route_to_store(
                        devices, scanner="nmap_aggressive", iface=iface
                    )
                    logger.info(
                        f"[nmap-aggressive] {network} → "
                        f"{len(devices)} host(s) fully fingerprinted"
                    )
            else:
                logger.debug(
                    f"[nmap-aggressive] No live hosts on {network} — skipping."
                )

            self._interruptible_sleep(self.nmap_aggressive_interval)

        logger.info(f"[nmap-aggressive] Exiting → {network}")

    # ------------------------------------------------------------------
    # Storage routing
    # ------------------------------------------------------------------

    def _run_trust_evaluation(self, network: str) -> None:
        """
        Pull current device list from store, run trust_engine on it,
        log every alert-worthy verdict. Phase 3 alert_manager plugs in here.
        """
        try:
            all_devices = self.device_store.get_all()
            if not all_devices:
                return

            verdicts = self._trust_engine.evaluate(all_devices)

            for v in verdicts:
                if v.verdict.value == TrustVerdict.UNTRUSTED_NEW.value:
                    logger.warning(
                        f"[trust] ⚠ NEW UNKNOWN DEVICE — "
                        f"{v.display_name} | {v.ip} | {v.mac} | "
                        f"vendor={v.vendor or 'unknown'}"
                    )
                elif v.verdict.value == TrustVerdict.UNTRUSTED_RETURNING.value:
                    rand_tag = " [MAC randomization suspected]" \
                               if v.mac_randomization_suspected else ""
                    logger.warning(
                        f"[trust] ↩ RETURNING UNKNOWN — "
                        f"{v.display_name} | {v.ip} | {v.mac}{rand_tag}"
                    )
                # TRUSTED verdicts logged at DEBUG only — not noise in normal ops
                else:
                    logger.debug(
                        f"[trust] ✔ trusted — {v.display_name} | {v.ip}"
                    )
        except Exception as e:
            logger.error(f"[trust] Trust evaluation error: {e}")

    def _route_to_store(
        self, devices: List[Dict], scanner: str, iface: str
    ) -> None:
        """Hand each device to device_store.upsert(). Never stores anything itself."""
        for device in devices:
            record = {**device, "scanner": scanner, "interface": iface}
            try:
                self.device_store.upsert(record)
            except Exception as e:
                logger.error(
                    f"device_store.upsert failed for "
                    f"{device.get('ip', '?')}: {e}"
                )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _get_live_ips(self, network: str) -> Set[str]:
        """Thread-safe read of the live-host cache for one network."""
        with self._live_hosts_lock:
            return set(self._live_hosts.get(network, set()))

    def _interruptible_sleep(self, seconds: int) -> None:
        """Sleep in 1s ticks — responds to stop_event within 1 second."""
        for _ in range(seconds):
            if self._stop_event.is_set():
                return
            time.sleep(1)