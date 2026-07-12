# deps: none beyond stdlib + project modules
"""
core/scheduler.py

Three-tier scan coordinator per network:

  Tier 1 — Scapy ARP        every 60s   → fast device presence
  Tier 2 — Nmap quick       every 180s  → vendor/hostname refresh
  Tier 3 — Nmap aggressive  every 360s  → full OS/port/service fingerprint

Plus GLOBAL (not per-network) passive/active discovery tiers:

  mDNS discovery   every mdns_interval  (default 120s) → hostname +
    model enrichment via Bonjour/Zeroconf, independent of MAC.
  DHCP sniffing    continuous background listener, drained every
    dhcp_drain_interval (default 60s) → hostname enrichment, KEYED BY
    MAC directly (the one source that gives us a MAC without needing
    IP-based device correlation).
  SSDP discovery   every ssdp_interval  (default 180s) → hostname +
    vendor + model enrichment via UPnP device descriptions.
  LLMNR discovery  every llmnr_interval (default 90s) → hostname
    enrichment via reverse lookup against currently-known live IPs
    (Windows machines that don't answer mDNS/NetBIOS).

Lock model:
  One threading.Lock per network CIDR. None of the GLOBAL discovery
  tiers (mDNS/DHCP/SSDP/LLMNR) participate in this lock — they're all
  passive listeners or narrow-scope active queries, not full-subnet
  Scapy/Nmap scans, and each writes via its own narrow device_store
  method rather than the general upsert() path.

Live-host cache:
  Scapy ARP results are stored in self._live_hosts[network] after every
  sweep. Nmap quick and aggressive tiers read from this cache. LLMNR's
  worker also reads from this cache (aggregated across all networks)
  since its reverse-lookup queries need a list of IPs to ask, not a
  self-contained "browse for anything" call — see
  detection/llmnr_discovery.py's module docstring for why that source
  is architecturally different from mDNS/SSDP.

MAC normalization:
  Scapy returns lowercase MACs, Nmap returns uppercase, DHCP sniffing
  returns lowercase (see detection/dhcp_sniffer.py). All lowercased
  before being handed to device_store.

Alert wiring + persistence (Phase 3, modules 12/13):
  alert_manager.process_verdicts() returns the fired verdicts; scheduler
  persists each to device_store.log_alert().

Gateway hint wiring:
  scheduler builds {network: gateway} from RouterDetector's output and
  hands it to alert_manager.set_network_gateways().

Vendor enrichment (Phase 3 revision):
  Nmap ships its own small internal MAC-vendor database, separate from
  and much smaller than Cerberus's own VendorLookup (39k+ real IEEE OUI
  entries — see detection/vendor_lookup.py). After every Nmap quick/
  aggressive cycle, any device whose vendor Nmap couldn't identify gets
  backfilled via device_store.update_vendor_if_missing() using
  Cerberus's richer database. Never overwrites a vendor Nmap DID find.

Passive/active discovery enrichment (this revision):
  Four independent, IP- or MAC-layer discovery sources now feed
  device_store, each through its own narrow, "fill genuine gaps, never
  overwrite" method — never through the general upsert() path, since
  none of these sources are full scan results:

    Source   Key    Fields written                  device_store method
    ------   ---    --------------                  -------------------
    mDNS     IP     hostname                         update_hostname_from_mdns
    mDNS     IP     model                            update_model_from_ip
    DHCP     MAC    hostname                         update_hostname_by_mac
    SSDP     IP     hostname (via friendly_name)      update_hostname_from_mdns
    SSDP     IP     vendor (via manufacturer)         update_vendor_from_ip
    SSDP     IP     model (via model_name)            update_model_from_ip
    LLMNR    IP     hostname                          update_hostname_from_mdns

  Note SSDP and LLMNR both reuse update_hostname_from_mdns() rather
  than a same-purpose method under a different name — the underlying
  SQL (IP-keyed, fill-if-missing) is identical regardless of which
  protocol supplied the hostname, so a separate method per protocol
  would just be duplicate code with no behavioral difference.

  DHCP's known limitation (deliberate, not a bug): a DHCP sighting for
  a MAC that device_store doesn't know about YET (i.e. arrived before
  Scapy's ARP sweep ever saw that device) is simply dropped — not
  retried on a later cycle, since drain_new_sightings() clears its
  buffer on every call. In practice this is rare: a device actively
  negotiating DHCP is, by definition, live on the network, and Scapy's
  ARP sweep (scapy_interval, far more frequent than DHCP negotiations)
  will almost always have discovered it first or in the same cycle.

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
from cerberus.detection.dhcp_sniffer import DHCPSniffer
from cerberus.detection.ssdp_discovery import SSDPDiscovery
from cerberus.detection.llmnr_discovery import LLMNRDiscovery
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
    Three-tier (per-network) + four global discovery tiers
    (mDNS/DHCP/SSDP/LLMNR) scan coordinator.
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
        dhcp_enabled:              bool = True,
        dhcp_drain_interval:       int = 60,
        ssdp_enabled:              bool = True,
        ssdp_interval:             int = 180,
        llmnr_enabled:             bool = True,
        llmnr_interval:            int = 90,
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
        self.dhcp_drain_interval        = dhcp_drain_interval
        self.ssdp_interval              = ssdp_interval
        self.llmnr_interval             = llmnr_interval

        # Scanners — stateless, one instance each, reused per call
        self._scapy = ScapyScanner(timeout=scapy_timeout, wake_up_ping=True)
        self._nmap  = NmapScanner()
        self._mdns  = MDNSDiscovery(timeout=5) if mdns_enabled else None
        self._dhcp  = DHCPSniffer() if dhcp_enabled else None
        self._ssdp  = SSDPDiscovery(timeout=4) if ssdp_enabled else None
        self._llmnr = LLMNRDiscovery(timeout=2) if llmnr_enabled else None

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
            f"mdns={'ON every ' + str(mdns_interval) + 's' if mdns_enabled else 'OFF'}  "
            f"dhcp={'ON, drained every ' + str(dhcp_drain_interval) + 's' if dhcp_enabled else 'OFF'}  "
            f"ssdp={'ON every ' + str(ssdp_interval) + 's' if ssdp_enabled else 'OFF'}  "
            f"llmnr={'ON every ' + str(llmnr_interval) + 's' if llmnr_enabled else 'OFF'}"
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

        # DHCP's sniffer runs its OWN internally-managed background
        # thread (not one of self._threads) — stop it explicitly before
        # joining everything else, same as how it's started explicitly
        # in _spawn_workers() rather than via a generic worker loop.
        if self._dhcp:
            self._dhcp.stop()

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
            "dhcp_enabled":              self._dhcp is not None,
            "dhcp_drain_interval":       self.dhcp_drain_interval,
            "dhcp_sniffer_running":      self._dhcp.is_running if self._dhcp else False,
            "ssdp_enabled":              self._ssdp is not None,
            "ssdp_interval":             self.ssdp_interval,
            "llmnr_enabled":             self._llmnr is not None,
            "llmnr_interval":            self.llmnr_interval,
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

        # --- Global discovery tiers (not per-network) ---

        if self._mdns:
            t = threading.Thread(
                target=self._mdns_worker, name="mdns-discovery", daemon=True
            )
            self._threads.append(t)
            t.start()
            logger.info(f"mDNS discovery worker started — every {self.mdns_interval}s")

        if self._dhcp:
            # DHCP is fundamentally different from the other three: it's
            # a CONTINUOUS listener (dhcp_sniffer.py's own background
            # thread), started once here — not a periodic "browse for
            # N seconds" loop. This scheduler-owned drain worker just
            # periodically pulls whatever accumulated and applies it.
            started = self._dhcp.start()
            if started:
                t = threading.Thread(
                    target=self._dhcp_drain_worker, name="dhcp-drain", daemon=True
                )
                self._threads.append(t)
                t.start()
                logger.info(
                    f"DHCP sniffer started (continuous) — "
                    f"drained every {self.dhcp_drain_interval}s"
                )
            else:
                logger.warning("DHCP sniffer failed to start — feature unavailable this run.")

        if self._ssdp:
            t = threading.Thread(
                target=self._ssdp_worker, name="ssdp-discovery", daemon=True
            )
            self._threads.append(t)
            t.start()
            logger.info(f"SSDP discovery worker started — every {self.ssdp_interval}s")

        if self._llmnr:
            t = threading.Thread(
                target=self._llmnr_worker, name="llmnr-discovery", daemon=True
            )
            self._threads.append(t)
            t.start()
            logger.info(f"LLMNR discovery worker started — every {self.llmnr_interval}s")

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
    # Worker loops — global discovery tiers
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
                    model = r.get("model")
                    if model:
                        self.device_store.update_model_from_ip(r["ip"], model)
                except Exception as e:
                    logger.error(f"[mdns] Failed to apply hostname/model for {r.get('ip')}: {e}")

            if updated:
                logger.info(f"[mdns] Enriched {updated} device(s) with mDNS hostnames.")
            else:
                logger.debug("[mdns] No new hostnames to apply this cycle.")

            self._interruptible_sleep(self.mdns_interval)

        logger.info("[mdns] Exiting")

    def _dhcp_drain_worker(self) -> None:
        """
        Periodically drain DHCPSniffer's continuously-accumulating
        buffer and apply each sighting via update_hostname_by_mac() —
        see this module's docstring for why a sighting for a MAC not
        yet in device_store is deliberately dropped rather than retried.
        """
        logger.info(f"[dhcp] Drain worker started — every {self.dhcp_drain_interval}s")
        self._interruptible_sleep(10)

        while not self._stop_event.is_set():
            try:
                sightings = self._dhcp.drain_new_sightings()
            except Exception as e:
                logger.error(f"[dhcp] drain_new_sightings() failed: {e}")
                sightings = []

            applied = 0
            dropped = 0
            for s in sightings:
                try:
                    if self.device_store.update_hostname_by_mac(s["mac"], s["hostname"]):
                        applied += 1
                    else:
                        dropped += 1
                except Exception as e:
                    logger.error(f"[dhcp] Failed to apply sighting for {s.get('mac')}: {e}")

            if applied:
                logger.info(f"[dhcp] Applied {applied} hostname(s) from DHCP sightings.")
            if dropped:
                logger.debug(
                    f"[dhcp] {dropped} sighting(s) not applied — device not yet "
                    "known to device_store, or already had a hostname."
                )

            self._interruptible_sleep(self.dhcp_drain_interval)

        logger.info("[dhcp] Drain worker exiting")

    def _ssdp_worker(self) -> None:
        logger.info("[ssdp] Started")
        self._interruptible_sleep(15)

        while not self._stop_event.is_set():
            try:
                results = self._ssdp.discover()
            except Exception as e:
                logger.error(f"[ssdp] discover() failed: {e}")
                results = []

            updated = 0
            for r in results:
                ip = r.get("ip")
                if not ip:
                    continue
                try:
                    name = r.get("friendly_name")
                    if name and self.device_store.update_hostname_from_mdns(ip, name):
                        updated += 1

                    vendor = r.get("manufacturer")
                    if vendor:
                        self.device_store.update_vendor_from_ip(ip, vendor)

                    model = r.get("model_name")
                    if model:
                        self.device_store.update_model_from_ip(ip, model)
                except Exception as e:
                    logger.error(f"[ssdp] Failed to apply enrichment for {ip}: {e}")

            if updated:
                logger.info(f"[ssdp] Enriched {updated} device(s) with friendly names.")
            else:
                logger.debug("[ssdp] No new hostnames to apply this cycle.")

            self._interruptible_sleep(self.ssdp_interval)

        logger.info("[ssdp] Exiting")

    def _llmnr_worker(self) -> None:
        """
        Unlike mDNS/SSDP, LLMNR needs to be TOLD which IPs to query
        (see detection/llmnr_discovery.py's module docstring) — this
        worker aggregates the current live-host set across every
        network's Scapy cache and asks LLMNR to reverse-resolve all of
        them in one batched call per cycle.
        """
        logger.info("[llmnr] Started")
        self._interruptible_sleep(20)

        while not self._stop_event.is_set():
            all_live_ips: Set[str] = set()
            with self._live_hosts_lock:
                for ips in self._live_hosts.values():
                    all_live_ips.update(ips)

            if all_live_ips:
                try:
                    results = self._llmnr.resolve(list(all_live_ips))
                except Exception as e:
                    logger.error(f"[llmnr] resolve() failed: {e}")
                    results = []

                updated = 0
                for r in results:
                    try:
                        if self.device_store.update_hostname_from_mdns(r["ip"], r["hostname"]):
                            updated += 1
                    except Exception as e:
                        logger.error(f"[llmnr] Failed to apply hostname for {r.get('ip')}: {e}")

                if updated:
                    logger.info(f"[llmnr] Resolved {updated} new hostname(s).")
                else:
                    logger.debug("[llmnr] No new hostnames to apply this cycle.")
            else:
                logger.debug("[llmnr] No live hosts known yet — skipping.")

            self._interruptible_sleep(self.llmnr_interval)

        logger.info("[llmnr] Exiting")

    # ------------------------------------------------------------------
    # Vendor enrichment (Phase 3 revision)
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