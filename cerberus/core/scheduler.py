# deps: none beyond stdlib + project modules
"""
core/scheduler.py

Three-tier scan coordinator per network:

  Tier 1 — Scapy ARP        every 60s   → fast device presence
  Tier 2 — Nmap quick       every 180s  → vendor/hostname refresh
  Tier 3 — Nmap aggressive  every 360s  → full OS/port/service fingerprint

Plus one GLOBAL (not per-network) tier:

  mDNS discovery  every mdns_interval (default 120s) → hostname
  enrichment via Bonjour/Zeroconf, independent of MAC.

Lock model:
  One threading.Lock per network CIDR. mDNS does not participate in
  this lock — passive listener, writes via its own narrow DB method.

Live-host cache:
  Scapy ARP results are stored in self._live_hosts[network] after every
  sweep. Nmap quick and aggressive tiers read from this cache.

MAC normalization:
  Scapy returns lowercase MACs, Nmap returns uppercase. Both lowercased
  before being handed to device_store.

Alert wiring + persistence (Phase 3, modules 12/13):
  alert_manager.process_verdicts() returns the fired verdicts; scheduler
  persists each to device_store.log_alert().

Gateway hint wiring:
  scheduler builds {network: gateway} from RouterDetector's output and
  hands it to alert_manager.set_network_gateways().

Vendor enrichment (this revision):
  Nmap ships its own small internal MAC-vendor database, separate from
  and much smaller than Cerberus's own VendorLookup (39k+ real IEEE OUI
  entries — see detection/vendor_lookup.py). After every Nmap quick/
  aggressive cycle, any device whose vendor Nmap couldn't identify gets
  backfilled via device_store.update_vendor_if_missing() using
  Cerberus's richer database. Never overwrites a vendor Nmap DID find.

Learning-mode auto-start (bugfix, this revision):
  Scheduler no longer decides whether learning mode auto-starts — that
  responsibility moved to cerberus_main.py, which now checks
  learning_mode.has_ever_started() before calling start(), fixing the
  bug where restarting the scanner after a deliberate `learning stop`
  would silently re-open a fresh 24h window. Scheduler only ever reads
  learning_mode.is_active() during scan cycles — it never calls start()
  itself, in this revision or any previous one.
"""

import time
import threading
import logging
from typing import List, Dict, Set, Optional
from concurrent.futures import ThreadPoolExecutor

from cerberus.detection.router_detector import RouterDetector
from cerberus.detection.mdns_discovery import MDNSDiscovery
from cerberus.detection.vendor_lookup import VendorLookup
from cerberus.core.scanner_scapy import ScapyScanner
from cerberus.core.scanner_nmap import NmapScanner
from cerberus.intelligence.trust_engine import TrustEngine, TrustVerdict, DeviceVerdict
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
    Three-tier (per-network) + one global (mDNS) scan coordinator.
    """

    def __init__(
        self,
        device_store,
        trust_engine:              TrustEngine  = None,
        learning_mode:             LearningMode = None,
        alert_manager                          = None,
        scapy_interval:            int = 60,
        nmap_quick_interval:       int = 180,
        nmap_aggressive_interval:  int = 360,
        aggressive_workers:        int = 4,
        network_retry_wait:        int = 30,
        scapy_timeout:             int = 3,
        mdns_enabled:              bool = True,
        mdns_interval:             int = 120,
    ):
        self.device_store               = device_store
        self._trust_engine              = trust_engine or TrustEngine()
        self._learning_mode             = learning_mode
        self._alert_manager             = alert_manager
        self.scapy_interval             = scapy_interval
        self.nmap_quick_interval        = nmap_quick_interval
        self.nmap_aggressive_interval   = nmap_aggressive_interval
        self.aggressive_workers         = aggressive_workers
        self.network_retry_wait         = network_retry_wait
        self.mdns_interval              = mdns_interval

        # Scanners — stateless, one instance each, reused per call
        self._scapy = ScapyScanner(timeout=scapy_timeout, wake_up_ping=True)
        self._nmap  = NmapScanner()
        self._mdns  = MDNSDiscovery(timeout=5) if mdns_enabled else None

        # Used ONLY for vendor-enrichment backfill (update_vendor_if_missing).
        # Never used for trust decisions here — that stays in trust_engine.
        self._vendor_lookup = VendorLookup()

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
            f"learning_mode={'ON' if learning_mode else 'OFF'}  "
            f"alert_manager={'ON' if alert_manager else 'OFF'}  "
            f"mdns={'ON every ' + str(mdns_interval) + 's' if mdns_enabled else 'OFF'}"
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

        self._configure_alert_gateways()
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
            "network_gateways":          {n["network"]: n.get("gateway", "") for n in self._networks},
            "scapy_interval":            self.scapy_interval,
            "nmap_quick_interval":       self.nmap_quick_interval,
            "nmap_aggressive_interval":  self.nmap_aggressive_interval,
            "aggressive_workers":        self.aggressive_workers,
            "live_hosts_per_network":    live_counts,
            "active_threads":            [t.name for t in self._threads if t.is_alive()],
            "alert_manager_active":      self._alert_manager is not None,
            "mdns_enabled":              self._mdns is not None,
            "mdns_interval":             self.mdns_interval,
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

    def _configure_alert_gateways(self) -> None:
        if not self._alert_manager:
            return
        gateways = {
            n["network"]: n["gateway"]
            for n in self._networks
            if n.get("gateway")
        }
        if gateways:
            self._alert_manager.set_network_gateways(gateways)
            logger.info(f"Alert gateway hints configured: {gateways}")
        else:
            logger.debug("No gateways detected — block-hint will be omitted from alerts.")

    # ------------------------------------------------------------------
    # Worker spawning
    # ------------------------------------------------------------------

    def _spawn_workers(self) -> None:
        for net_info in self._networks:
            network = net_info["network"]
            iface   = net_info["interface"]

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

        if self._mdns:
            t = threading.Thread(
                target=self._mdns_worker,
                name="mdns-discovery",
                daemon=True,
            )
            self._threads.append(t)
            t.start()
            logger.info(f"mDNS discovery worker started — every {self.mdns_interval}s")

    # ------------------------------------------------------------------
    # Worker loops — per-network tiers
    # ------------------------------------------------------------------

    def _scapy_worker(self, network: str, iface: str) -> None:
        logger.info(f"[scapy] Started → {network}")

        while not self._stop_event.is_set():
            lock = self._locks.get(network)
            with lock:
                logger.debug(f"[scapy] Scanning {network}")
                devices = self._scapy.scan(network)

            if devices:
                for d in devices:
                    if d.get("mac"):
                        d["mac"] = d["mac"].lower()

                live_ips = {d["ip"] for d in devices}
                with self._live_hosts_lock:
                    self._live_hosts[network] = live_ips

                self._route_to_store(devices, scanner="scapy", iface=iface)
                self._enrich_vendors(devices)

                logger.info(
                    f"[scapy] {network} → {len(devices)} device(s) | "
                    f"live: {sorted(live_ips)}"
                )

                if self._learning_mode and self._learning_mode.is_active():
                    all_devices = self.device_store.get_all()
                    self._learning_mode.auto_trust_all(all_devices)

                self._run_trust_evaluation(network)

            else:
                logger.debug(f"[scapy] No devices on {network} this cycle.")

            self._interruptible_sleep(self.scapy_interval)

        logger.info(f"[scapy] Exiting → {network}")

    def _nmap_quick_worker(self, network: str, iface: str) -> None:
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
                    targets = " ".join(sorted(live_ips))
                    devices = self._nmap.scan_quick(targets)

                if devices:
                    for d in devices:
                        d["network"] = network
                    self._route_to_store(devices, scanner="nmap_quick", iface=iface)
                    self._enrich_vendors(devices)
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
                        d["network"] = network
                    self._route_to_store(
                        devices, scanner="nmap_aggressive", iface=iface
                    )
                    self._enrich_vendors(devices)
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
    # Worker loop — global mDNS tier
    # ------------------------------------------------------------------

    def _mdns_worker(self) -> None:
        logger.info("[mdns] Started")
        self._interruptible_sleep(10)

        while not self._stop_event.is_set():
            try:
                results = self._mdns.discover()
            except Exception as e:
                logger.error(f"[mdns] discover() failed: {e}")
                results = []

            updated = 0
            for r in results:
                try:
                    if self.device_store.update_hostname_from_mdns(r["ip"], r["hostname"]):
                        updated += 1
                except Exception as e:
                    logger.error(f"[mdns] Failed to apply hostname for {r.get('ip')}: {e}")

            if updated:
                logger.info(f"[mdns] Enriched {updated} device(s) with mDNS hostnames.")
            else:
                logger.debug("[mdns] No new hostnames to apply this cycle.")

            self._interruptible_sleep(self.mdns_interval)

        logger.info("[mdns] Exiting")

    # ------------------------------------------------------------------
    # Vendor enrichment (this revision)
    # ------------------------------------------------------------------

    def _enrich_vendors(self, devices: List[Dict]) -> None:
        """
        For any device in this batch whose vendor is missing/empty,
        look it up against Cerberus's own richer OUI database and
        backfill it. device_store.update_vendor_if_missing() already
        guards against overwriting a vendor Nmap found — this method
        just decides WHICH devices are worth checking (only ones
        lacking a vendor in the batch we just scanned), same
        cheap-guard pattern the mDNS worker uses.
        """
        enriched = 0
        for d in devices:
            mac = d.get("mac")
            if not mac:
                continue
            # Only bother looking up if THIS scan result didn't already
            # carry a vendor — avoids a wasted lookup for the common case
            # where Nmap/Scapy already knows it.
            if d.get("vendor"):
                continue
            looked_up = self._vendor_lookup.lookup(mac)
            if not looked_up:
                continue
            try:
                if self.device_store.update_vendor_if_missing(mac, looked_up):
                    enriched += 1
            except Exception as e:
                logger.error(f"[vendor-enrich] Failed for {mac}: {e}")

        if enriched:
            logger.debug(f"[vendor-enrich] Backfilled vendor for {enriched} device(s).")

    # ------------------------------------------------------------------
    # Storage routing — trust + alerts
    # ------------------------------------------------------------------

    def _run_trust_evaluation(self, network: str) -> None:
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
                else:
                    logger.debug(
                        f"[trust] ✔ trusted — {v.display_name} | {v.ip}"
                    )

            if self._alert_manager:
                self._dispatch_and_persist_alerts(verdicts, network)

        except Exception as e:
            logger.error(f"[trust] Trust evaluation error: {e}")

    def _dispatch_and_persist_alerts(
        self, verdicts: List[DeviceVerdict], network: str
    ) -> None:
        try:
            fired: List[DeviceVerdict] = self._alert_manager.process_verdicts(verdicts)
        except Exception as e:
            logger.error(f"[alert] process_verdicts failed: {e}")
            return

        if not fired:
            return

        logger.info(f"[alert] {len(fired)} alert(s) dispatched for {network} cycle.")

        channel_count = len(getattr(self._alert_manager, "_channels", []))

        for v in fired:
            try:
                self.device_store.log_alert(
                    mac=v.mac,
                    ip=v.ip,
                    verdict=v.verdict.value,
                    network=v.network or network,
                    message_summary=f"{v.display_name} ({v.vendor or 'unknown vendor'})",
                    channels_fired=channel_count,
                )
            except Exception as e:
                logger.error(f"[alert] Failed to persist alert for {v.mac}: {e}")

    def _route_to_store(
        self, devices: List[Dict], scanner: str, iface: str
    ) -> None:
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
        with self._live_hosts_lock:
            return set(self._live_hosts.get(network, set()))

    def _interruptible_sleep(self, seconds: int) -> None:
        for _ in range(seconds):
            if self._stop_event.is_set():
                return
            time.sleep(1)