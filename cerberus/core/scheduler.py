# deps: none beyond stdlib (threading, time) + project modules
"""
core/scheduler.py

Job: the conductor.

On startup:
  1. Calls RouterDetector once to get the list of active networks.
  2. Runs a timing loop:
       - ScapyScanner  every ~60s   per network  (fast ARP sweep)
       - NmapScanner   every ~10min per network  (deep fingerprint)
  3. Passes every scan result to device_store — scheduler never stores
     anything itself, it only routes.

Rules:
  - Nmap and Scapy NEVER scan the same network simultaneously.
    Enforced by a per-network threading.Lock().
  - Only this module is allowed to import both detection/ and core/scanners.
  - device_store is injected at construction — scheduler never opens the DB.
  - Graceful shutdown on stop(): running scans finish, loop exits cleanly.
  - If RouterDetector returns [] (airplane mode / no interfaces), the
    scheduler enters a wait-and-retry loop rather than crashing.
"""

import time
import threading
import logging
from typing import List, Dict, Optional, Callable

from cerberus.detection.router_detector import RouterDetector
from cerberus.core.scanner_scapy import ScapyScanner
from cerberus.core.scanner_nmap import NmapScanner

logger = logging.getLogger("cerberus.core.scheduler")


# ---------------------------------------------------------------------------
# Per-network lock registry
# ---------------------------------------------------------------------------

class _NetworkLockRegistry:
    """
    Hands out one threading.Lock per network CIDR string.
    Scapy and Nmap both acquire the same lock for the same network,
    so they can never run simultaneously on it.
    """

    def __init__(self):
        self._locks: Dict[str, threading.Lock] = {}
        self._meta_lock = threading.Lock()  # protects the registry dict itself

    def get(self, network: str) -> threading.Lock:
        with self._meta_lock:
            if network not in self._locks:
                self._locks[network] = threading.Lock()
                logger.debug(f"Created lock for network: {network}")
            return self._locks[network]


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

class Scheduler:
    """
    Coordinates Scapy and Nmap scans across all detected networks.

    Usage:
        store = DeviceStore("data/devices.db")   # injected, never opened here
        scheduler = Scheduler(device_store=store)
        scheduler.start()   # blocks until stop() called from another thread
                            # or run headless via start(blocking=False)
        ...
        scheduler.stop()

    Args:
        device_store      : Any object with an `upsert(device_dict)` method.
                            Passed in — scheduler never imports storage directly.
        scapy_interval    : Seconds between Scapy ARP sweeps per network.
        nmap_interval     : Seconds between Nmap deep scans per network.
        network_retry_wait: Seconds to wait before retrying network detection
                            if RouterDetector returns no interfaces.
        scapy_timeout     : ARP reply timeout passed to ScapyScanner.
        nmap_deep         : If True, Nmap runs deep scan (-A). False = ping only.
    """

    def __init__(
        self,
        device_store,
        scapy_interval: int = 60,
        nmap_interval: int = 600,       # 10 minutes
        network_retry_wait: int = 30,
        scapy_timeout: int = 3,
        nmap_deep: bool = True,
    ):
        self.device_store = device_store
        self.scapy_interval = scapy_interval
        self.nmap_interval = nmap_interval
        self.network_retry_wait = network_retry_wait

        # Scanners — stateless, instantiated once, reused per call
        self._scapy = ScapyScanner(timeout=scapy_timeout, wake_up_ping=True)
        self._nmap = NmapScanner()
        self._nmap_deep = nmap_deep

        # Per-network mutex registry
        self._locks = _NetworkLockRegistry()

        # Shutdown flag — set by stop(), checked by all loops
        self._stop_event = threading.Event()

        # Active worker threads (one Scapy + one Nmap per network)
        self._threads: List[threading.Thread] = []

        # Current known networks (refreshed on restart)
        self._networks: List[Dict] = []

        logger.info(
            f"Scheduler created — "
            f"scapy_interval={scapy_interval}s  "
            f"nmap_interval={nmap_interval}s  "
            f"nmap_deep={nmap_deep}"
        )

    # ------------------------------------------------------------------
    # Public control
    # ------------------------------------------------------------------

    def start(self, blocking: bool = True) -> None:
        """
        Detect networks, spin up worker threads, then either block
        (blocking=True, for headless cerberus_main.py) or return
        immediately (blocking=False, for tests or embedding).
        """
        logger.info("Scheduler starting...")
        self._stop_event.clear()

        self._networks = self._detect_networks_with_retry()
        if not self._networks:
            logger.critical(
                "No networks found after retrying — scheduler cannot start."
            )
            return

        self._spawn_workers()

        if blocking:
            logger.info(
                "Scheduler running. Press Ctrl+C to stop."
            )
            try:
                while not self._stop_event.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt received.")
                self.stop()

    def stop(self) -> None:
        """
        Signal all worker threads to finish their current scan and exit.
        Blocks until every thread has joined.
        """
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

    # ------------------------------------------------------------------
    # Network detection with retry
    # ------------------------------------------------------------------

    def _detect_networks_with_retry(self) -> List[Dict]:
        """
        Call RouterDetector until at least one network is found, or until
        stop() is called. Returns [] only if stop() fires during the wait.
        """
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
                f"No active networks found. "
                f"Retrying in {self.network_retry_wait}s... "
                f"(Is the machine connected?)"
            )
            time.sleep(self.network_retry_wait)

        return []

    # ------------------------------------------------------------------
    # Worker thread spawning
    # ------------------------------------------------------------------

    def _spawn_workers(self) -> None:
        """Start one Scapy thread + one Nmap thread per detected network."""
        for net_info in self._networks:
            network = net_info["network"]
            iface = net_info["interface"]

            scapy_thread = threading.Thread(
                target=self._scapy_worker,
                args=(network, iface),
                name=f"scapy-{network}",
                daemon=True,
            )
            nmap_thread = threading.Thread(
                target=self._nmap_worker,
                args=(network, iface),
                name=f"nmap-{network}",
                daemon=True,
            )

            self._threads.extend([scapy_thread, nmap_thread])
            scapy_thread.start()
            nmap_thread.start()

            logger.info(
                f"Workers started for {network} on {iface}"
            )

    # ------------------------------------------------------------------
    # Worker loops
    # ------------------------------------------------------------------

    def _scapy_worker(self, network: str, iface: str) -> None:
        """
        Runs forever (until stop_event set):
          acquire network lock → scan → route to store → release → sleep.
        """
        logger.info(f"[scapy-worker] Started for {network}")

        while not self._stop_event.is_set():
            lock = self._locks.get(network)

            with lock:
                logger.debug(f"[scapy-worker] Acquired lock for {network}")
                devices = self._scapy.scan(network)

            if devices:
                self._route_to_store(devices, scanner="scapy", iface=iface)
            else:
                logger.debug(
                    f"[scapy-worker] No devices on {network} this cycle."
                )

            # Interruptible sleep — checks stop_event every second
            self._interruptible_sleep(self.scapy_interval)

        logger.info(f"[scapy-worker] Exiting for {network}")

    def _nmap_worker(self, network: str, iface: str) -> None:
        """
        Runs forever (until stop_event set):
          sleep first (Scapy gets first look), then
          acquire network lock → scan → route to store → release → sleep.

        Nmap sleeps first so it doesn't compete with Scapy on startup.
        """
        logger.info(f"[nmap-worker] Started for {network} — first scan in {self.nmap_interval}s")

        # Initial delay — let Scapy run its first sweep first
        self._interruptible_sleep(self.nmap_interval)

        while not self._stop_event.is_set():
            lock = self._locks.get(network)

            with lock:
                logger.debug(f"[nmap-worker] Acquired lock for {network}")
                if self._nmap_deep:
                    devices = self._nmap.scan_deep(network)
                else:
                    devices = self._nmap.scan_quick(network)

            if devices:
                self._route_to_store(devices, scanner="nmap", iface=iface)
            else:
                logger.debug(
                    f"[nmap-worker] No devices on {network} this cycle."
                )

            self._interruptible_sleep(self.nmap_interval)

        logger.info(f"[nmap-worker] Exiting for {network}")

    # ------------------------------------------------------------------
    # Routing to storage
    # ------------------------------------------------------------------

    def _route_to_store(
        self, devices: List[Dict], scanner: str, iface: str
    ) -> None:
        """
        Hand each device dict to device_store.upsert().
        Scheduler does zero storage logic — it just routes.

        Adds 'scanner' and 'interface' fields so device_store can log them
        in scan_history without needing to know which worker called it.
        """
        for device in devices:
            record = {**device, "scanner": scanner, "interface": iface}
            try:
                self.device_store.upsert(record)
            except Exception as e:
                # Storage failure must never kill the scan loop
                logger.error(
                    f"device_store.upsert failed for {device.get('ip')}: {e}"
                )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _interruptible_sleep(self, seconds: int) -> None:
        """
        Sleep in 1s increments so stop_event is checked frequently.
        Avoids the scanner being stuck sleeping for 10 minutes on shutdown.
        """
        for _ in range(seconds):
            if self._stop_event.is_set():
                return
            time.sleep(1)

    def status(self) -> Dict:
        """
        Return a snapshot of scheduler state for cerberus_main / CLI.
        """
        return {
            "running": self.is_running,
            "networks": [n["network"] for n in self._networks],
            "scapy_interval": self.scapy_interval,
            "nmap_interval": self.nmap_interval,
            "nmap_deep": self._nmap_deep,
            "active_threads": [t.name for t in self._threads if t.is_alive()],
        }