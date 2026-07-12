# deps: pip install scapy (already a project dependency, see scanner_scapy.py)
"""
detection/dhcp_sniffer.py

Job: passively observe DHCP broadcast traffic and extract the hostname
a device announces during its own DHCP negotiation — a signal source
that is completely independent of mDNS, and notably gives us the
device's MAC address DIRECTLY (unlike mDNS, which only ever reveals an
IP and requires the scheduler to correlate IP→MAC separately).

Why this exists:
  Almost every device does a DHCP negotiation at some point (initial
  connect, at minimum) and includes its own hostname in the request via
  DHCP Option 12 ("Host Name") — this is close to universal coverage,
  broader than mDNS (which iOS/macOS/some Linux support well, but many
  Windows machines and IoT devices don't bother with) or NetBIOS
  (which iOS never responds to at all, per trust_engine.py's existing
  MAC-randomization notes). This closes a real gap: devices that
  respond to neither mDNS nor NetBIOS/SMB can still be identified by
  hostname via DHCP, since virtually nothing skips DHCP entirely.

Architectural difference from mdns_discovery.py / ssdp / llmnr (read
this before assuming the same pattern applies):
  mDNS, SSDP, and LLMNR are all "ask a question, wait for answers
  within N seconds" — an active browse cycle the scheduler can run
  fresh every cycle. DHCP has NO such query mechanism available to an
  observer — Cerberus cannot ask "does anyone want to tell me their
  hostname" over DHCP; it can only wait for a device to volunteer one
  during its OWN negotiation, which happens on connect and at renewal
  time (often hours apart, sometimes longer). A short one-shot
  "listen for 5 seconds" window would miss almost everything.

  So this module is NOT called repeatedly with a timeout the way
  MDNSDiscovery.discover() is. Instead:
    - start() spawns ONE continuous background sniffer thread that
      runs for the lifetime of the process (until stop() is called),
      accumulating every DHCP hostname it observes into an internal,
      thread-safe buffer.
    - drain_new_sightings() is what the scheduler calls periodically
      (e.g. every 60s, alongside its other per-cycle work) to pull
      whatever has accumulated since the last drain and clear the
      buffer. Nothing is lost between drains; nothing is double
      reported after a drain.

Rules (same isolation pattern as scanner_scapy.py / mdns_discovery.py):
  - No storage, no trust logic — returns raw sighting dicts only.
  - Never SENDS a packet — this is passive capture only (scapy.sniff,
    never scapy.send/srp). This is a deliberate, narrower use of scapy
    than scanner_scapy.py's active ARP probing; using the same library
    for a fundamentally different (passive-only) purpose does not
    violate the "scanners never import detection" isolation rule —
    that rule is about active scanning/topology coupling, not a
    blanket ban on which network libraries a detection module may use
    to passively listen to traffic that's already occurring.
  - Requires the same raw-capture privilege as scanner_scapy.py
    (Administrator on Windows with Npcap, root/CAP_NET_RAW on Linux/
    macOS) — if that's unavailable, start() logs an error and the
    sniffer simply never produces sightings; it does not crash the
    scheduler that owns it.
  - Never crashes on a malformed/unexpected packet — every packet is
    parsed defensively; one broken packet must never kill the
    background thread for the rest of the process's lifetime.

Usage:
    sniffer = DHCPSniffer()
    sniffer.start()               # begins background listening
    ...
    sightings = sniffer.drain_new_sightings()
    # → [{'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': 'DESKTOP-ABC123',
    #      'ip': '192.168.1.50'}, ...]   # 'ip' is None if not present
    #                                     # in this particular packet
    ...
    sniffer.stop()                # called once, at process shutdown
"""

import logging
import threading
from typing import Dict, List, Optional

logger = logging.getLogger("cerberus.detection.dhcp_sniffer")

try:
    from scapy.all import sniff, DHCP, BOOTP, Ether, IP
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False

# DHCP option 12 is "Host Name" — the field this entire module exists
# to extract. Scapy exposes DHCP options as a list of
# (name, value) tuples (or a single "end"/"pad" string entry), already
# decoded from the wire format, so we don't hand-parse raw option bytes.
_HOSTNAME_OPTION_NAME = "hostname"

# BPF capture filter — only DHCP's two well-known UDP ports, so the
# sniffer isn't handed every packet on the interface (which would be
# wasteful and, more importantly, would require inspecting far more
# traffic than this module has any business looking at).
_DHCP_BPF_FILTER = "udp and (port 67 or port 68)"


def _parse_dhcp_packet(pkt) -> Optional[Dict]:
    """
    Pure parsing function — given one Scapy packet, extract a sighting
    dict if it's a DHCP packet carrying a hostname option, else None.

    Factored out from the sniffer's callback specifically so this logic
    can be unit-tested with synthetically constructed packets, without
    needing actual raw-socket capture privileges to build a test suite.

    Args:
        pkt: A Scapy packet, as delivered by sniff()'s prn callback.

    Returns:
        {'mac': str, 'hostname': str, 'ip': Optional[str]} if the
        packet is a valid DHCP packet with a hostname option, else None.
        Never raises — any parsing failure returns None.
    """
    try:
        if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
            return None

        mac = None
        if pkt.haslayer(Ether):
            mac = pkt[Ether].src
        if not mac:
            # BOOTP's own chaddr field is the fallback source of the
            # client's MAC if for some reason the Ethernet layer isn't
            # present (e.g. captured above L2 on some platforms).
            chaddr = getattr(pkt[BOOTP], "chaddr", None)
            if chaddr:
                mac = ":".join(f"{b:02x}" for b in chaddr[:6])
        if not mac:
            return None
        mac = mac.lower()

        hostname = None
        for opt in pkt[DHCP].options:
            # Options are (name, value) tuples for real options, or a
            # bare string ("end"/"pad") for the terminator — guard
            # against both shapes rather than assuming every entry
            # unpacks as a 2-tuple.
            if isinstance(opt, tuple) and len(opt) == 2:
                opt_name, opt_value = opt
                if opt_name == _HOSTNAME_OPTION_NAME and opt_value:
                    if isinstance(opt_value, bytes):
                        hostname = opt_value.decode("utf-8", errors="ignore").strip()
                    else:
                        hostname = str(opt_value).strip()
                    break

        if not hostname:
            return None

        # Best-effort IP — often absent on a DHCPDISCOVER (the device
        # doesn't have one yet), sometimes present on a DHCPREQUEST
        # (as the requested/previously-assigned address). None is a
        # normal, expected outcome here, not an error.
        ip = None
        if pkt.haslayer(IP) and pkt[IP].src not in ("0.0.0.0", None):
            ip = pkt[IP].src

        return {"mac": mac, "hostname": hostname, "ip": ip}

    except Exception as e:
        logger.debug(f"[dhcp] Packet parse error (skipped): {e}")
        return None


class DHCPSniffer:
    """
    Continuous background DHCP hostname listener.

    Usage:
        sniffer = DHCPSniffer()
        sniffer.start()
        # ... later, periodically ...
        new_sightings = sniffer.drain_new_sightings()
        # ... at shutdown ...
        sniffer.stop()
    """

    def __init__(self, interface: Optional[str] = None):
        """
        Args:
            interface: Specific network interface to sniff on (e.g.
                       'eth0', 'Wi-Fi'). None = Scapy's default
                       interface selection (usually correct for a
                       single-NIC machine; for multi-interface setups,
                       the scheduler may eventually want one sniffer
                       per active interface — not implemented yet,
                       flagged as a known limitation below).
        """
        self.interface = interface
        self._sightings: List[Dict] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        if not _SCAPY_AVAILABLE:
            logger.warning(
                "scapy not installed — DHCP sniffing disabled. "
                "Run: pip install scapy"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """
        Begin background DHCP listening. Safe to call once; calling
        again while already running is a no-op (logged, not an error).

        Returns:
            True if the background thread was started (or was already
            running), False if scapy is unavailable and nothing could
            be started.
        """
        if not _SCAPY_AVAILABLE:
            logger.error("[dhcp] Cannot start — scapy not installed.")
            return False

        if self._thread and self._thread.is_alive():
            logger.debug("[dhcp] start() called but sniffer already running.")
            return True

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="dhcp-sniffer", daemon=True
        )
        self._thread.start()
        logger.info(
            f"[dhcp] Background sniffer started"
            f"{f' on {self.interface}' if self.interface else ''}."
        )
        return True

    def stop(self) -> None:
        """
        Signal the background thread to stop and wait briefly for it.

        Scapy's sniff() only checks stop_filter/timeout between packets
        it actually receives — on a quiet DHCP-wise network, this can
        mean the thread doesn't notice the stop signal until either the
        next DHCP packet arrives or the internal safety timeout (see
        _run()) elapses. join() has a bounded wait rather than blocking
        forever, so shutdown is never held up indefinitely by this.
        """
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                logger.debug(
                    "[dhcp] Sniffer thread did not exit within 5s — "
                    "it is a daemon thread, so it will not block process exit."
                )
        logger.info("[dhcp] Background sniffer stopped.")

    def drain_new_sightings(self) -> List[Dict]:
        """
        Return everything accumulated since the last drain, and clear
        the internal buffer. Called periodically by the scheduler —
        each sighting is returned exactly once, never duplicated across
        drains, never lost between them (protected by the same lock
        the background thread uses to append).

        Returns:
            List of {'mac', 'hostname', 'ip'} dicts. Empty list if
            nothing new has been observed since the last call (the
            normal case most of the time, given how infrequent DHCP
            negotiations are compared to a typical scan interval).
        """
        with self._lock:
            drained = self._sightings
            self._sightings = []
        return drained

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Private — background thread body
    # ------------------------------------------------------------------

    def _run(self) -> None:
        """
        The sniffer thread's body. Runs scapy.sniff() in short bounded
        bursts (rather than one unbounded call) specifically so
        self._stop_event is checked regularly even on a network with no
        DHCP traffic at all — an unbounded sniff() with only a
        stop_filter would never re-check that filter until a packet
        actually arrives, which could mean stop() has no visible effect
        for an arbitrarily long time on a quiet network.
        """
        while not self._stop_event.is_set():
            try:
                sniff(
                    filter=_DHCP_BPF_FILTER,
                    iface=self.interface,
                    prn=self._handle_packet,
                    store=False,
                    timeout=5,  # re-check _stop_event at least every 5s
                )
            except PermissionError:
                logger.error(
                    "[dhcp] Permission denied — run Cerberus with "
                    "Administrator/root privileges for DHCP sniffing."
                )
                return
            except Exception as e:
                logger.error(f"[dhcp] Sniffer error (will retry): {e}")
                # Don't spin hot on a persistent error (e.g. interface
                # briefly down) — the outer while loop's next iteration
                # naturally waits via sniff()'s own timeout regardless,
                # but an immediate exception means that timeout never
                # applied, so this thread could otherwise loop tightly.
                self._stop_event.wait(2)

    def _handle_packet(self, pkt) -> None:
        """sniff()'s prn callback — parse one packet, buffer if valid."""
        sighting = _parse_dhcp_packet(pkt)
        if sighting:
            with self._lock:
                self._sightings.append(sighting)
            logger.debug(
                f"[dhcp] Sighting — mac={sighting['mac']} "
                f"hostname={sighting['hostname']} ip={sighting.get('ip')}"
            )


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import time

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    listen_seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 30

    print("\n" + "=" * 60)
    print("DHCP SNIFFER — SMOKE TEST")
    print("=" * 60)
    print(f"Listening for real DHCP traffic for {listen_seconds}s "
          f"(requires admin/root privileges)...\n")
    print("Note: DHCP negotiations only happen when a device connects "
          "or renews its lease — seeing nothing in a short window is "
          "normal, not a failure. Try reconnecting a phone's Wi-Fi "
          "during this test to trigger one.\n")

    sniffer = DHCPSniffer()
    if not sniffer.start():
        print("Could not start sniffer (scapy missing). Exiting.")
        sys.exit(1)

    try:
        time.sleep(listen_seconds)
    except KeyboardInterrupt:
        pass

    sightings = sniffer.drain_new_sightings()
    sniffer.stop()

    if not sightings:
        print("No DHCP hostnames observed during this window.")
    else:
        print(f"{'MAC':<20} {'HOSTNAME':<28} {'IP'}")
        print("-" * 60)
        for s in sightings:
            print(f"{s['mac']:<20} {s['hostname']:<28} {s.get('ip') or '-'}")

    print("=" * 60)