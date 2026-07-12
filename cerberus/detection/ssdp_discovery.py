# deps: none — stdlib only (socket, urllib, xml.etree)
"""
detection/ssdp_discovery.py

Job: active SSDP/UPnP discovery — sends an M-SEARCH multicast query and
collects responses from smart TVs, printers, game consoles, media
servers, and other UPnP-capable devices on the network.

Why this exists:
  Many consumer devices (smart TVs, printers, Chromecasts, game
  consoles, NAS boxes, some IoT hubs) implement UPnP/SSDP for local
  network discovery even when they don't respond to mDNS or NetBIOS.
  This is a THIRD independent identity signal alongside mDNS
  (detection/mdns_discovery.py) and DHCP (detection/dhcp_sniffer.py) —
  a device that stays silent on the other two may still announce
  itself here.

Two-stage discovery (this is what makes SSDP more useful than a bare
protocol probe):
  Stage 1 — M-SEARCH: send a multicast UDP query to 239.255.255.250:1900
    and collect the direct unicast replies for `timeout` seconds. Each
    reply's headers include a LOCATION URL pointing at an XML "device
    description" document.
  Stage 2 — description fetch: for each distinct LOCATION URL seen,
    fetch that XML document (short bounded timeout per fetch) and
    extract friendlyName / manufacturer / modelName / modelNumber —
    fields that are usually FAR more specific and human-readable than
    anything OUI/vendor lookups or raw SSDP headers alone provide (e.g.
    "Living Room TV" or "Canon MG3600 series" instead of just a vendor
    name). This is optional per-response best-effort enrichment: a
    device whose description fetch fails or times out still gets
    reported with whatever the M-SEARCH response itself contained.

Rules (same isolation pattern as mdns_discovery.py / dhcp_sniffer.py):
  - No Scapy/Nmap import, no storage, no trust logic.
  - Pure: query for `timeout` seconds, return whatever responded.
  - Does NOT know which MAC owns a responding IP — same IP-layer-only
    limitation as mDNS; correlating IP→MAC is the scheduler's job.
  - Every failure mode (socket error, malformed response, unreachable
    LOCATION URL, malformed XML) is caught and degrades gracefully —
    one bad device must never prevent reporting every other device
    that responded correctly.

Usage:
    ssdp = SSDPDiscovery(timeout=4)
    results = ssdp.discover()
    # → [{'ip': '192.168.1.40', 'server': 'Linux/3.10 UPnP/1.0 ...',
    #      'location': 'http://192.168.1.40:8080/description.xml',
    #      'friendly_name': 'Living Room TV', 'manufacturer': 'Samsung',
    #      'model_name': 'UN55...', 'model_number': None}, ...]
    # Any field can be None if that data wasn't present/fetchable.
"""

import logging
import socket
import time
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

logger = logging.getLogger("cerberus.detection.ssdp_discovery")

_SSDP_MULTICAST_ADDR = "239.255.255.250"
_SSDP_MULTICAST_PORT = 1900

# Multiple search targets in one discovery cycle — "ssdp:all" alone
# theoretically covers everything, but some devices only answer more
# specific targets reliably in practice, so a couple of well-known
# extras cost little and catch more.
_SEARCH_TARGETS = ("ssdp:all", "upnp:rootdevice")

_MSEARCH_TEMPLATE = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: {addr}:{port}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: {st}\r\n"
    "\r\n"
)

# XML namespace UPnP device descriptions use — ElementTree requires
# the namespace prefix to find elements even when the document itself
# doesn't use a prefix in its tags.
_UPNP_DEVICE_NS = {"upnp": "urn:schemas-upnp-org:device-1-0"}


# ---------------------------------------------------------------------------
# Pure parsing functions — factored out for testability without real sockets
# ---------------------------------------------------------------------------

def _parse_ssdp_response(raw: bytes) -> Optional[Dict[str, str]]:
    """
    Parse one SSDP response's raw HTTP-like header block into a dict.

    Args:
        raw: The raw bytes received from the SSDP socket for one reply.

    Returns:
        {header_name_lower: value} dict, or None if the response isn't
        a recognizable HTTP-style header block at all. Malformed
        individual header lines are skipped, not fatal to the whole
        response — a device sending one weird extra header shouldn't
        cause the entire reply to be discarded.
    """
    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        return None

    lines = text.split("\r\n")
    if not lines or not lines[0].upper().startswith("HTTP/"):
        return None

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        try:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        except Exception:
            continue

    return headers if headers else None


def _parse_device_description_xml(xml_bytes: bytes) -> Dict[str, Optional[str]]:
    """
    Extract friendlyName / manufacturer / modelName / modelNumber from
    a UPnP device description XML document.

    Args:
        xml_bytes: Raw XML content fetched from a device's LOCATION URL.

    Returns:
        Dict with all four keys always present; any field not found in
        the document (or if parsing fails entirely) is None rather than
        the key being absent, so callers never need a .get() fallback.
    """
    result = {
        "friendly_name": None,
        "manufacturer": None,
        "model_name": None,
        "model_number": None,
    }

    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        logger.debug(f"[ssdp] Device description XML parse error: {e}")
        return result

    # UPnP descriptions may or may not declare the namespace explicitly
    # in a way ElementTree's default search handles — try namespaced
    # paths first, then fall back to bare tag names (some cheaper/
    # embedded UPnP stacks emit technically-invalid but commonly-
    # tolerated XML without proper namespacing).
    field_map = {
        "friendly_name": "friendlyName",
        "manufacturer": "manufacturer",
        "model_name": "modelName",
        "model_number": "modelNumber",
    }

    for result_key, tag in field_map.items():
        el = root.find(f".//upnp:device/upnp:{tag}", _UPNP_DEVICE_NS)
        if el is None:
            el = root.find(f".//{tag}")
        if el is not None and el.text:
            result[result_key] = el.text.strip()

    return result


# ---------------------------------------------------------------------------
# SSDP discovery
# ---------------------------------------------------------------------------

class SSDPDiscovery:
    """
    One-shot SSDP/UPnP discovery cycle, with optional device-description
    enrichment.

    Usage:
        ssdp = SSDPDiscovery(timeout=4)
        results = ssdp.discover()
    """

    def __init__(self, timeout: int = 4, fetch_descriptions: bool = True):
        """
        Args:
            timeout            : Seconds to wait for M-SEARCH replies.
                                  4s is generally enough on a LAN — UPnP
                                  devices are expected to reply within
                                  their advertised MX window (2s here).
            fetch_descriptions : If True (default), fetch each distinct
                                  LOCATION URL's XML for friendly_name/
                                  manufacturer/model_name/model_number.
                                  Set False to skip this and return only
                                  what the M-SEARCH headers themselves
                                  contained — faster, less network
                                  traffic, less information.
        """
        self.timeout = timeout
        self.fetch_descriptions = fetch_descriptions

    def discover(self) -> List[Dict]:
        """
        Send M-SEARCH queries and collect responses for `self.timeout`
        seconds, then (if enabled) fetch device descriptions for each
        distinct LOCATION URL seen.

        Returns:
            List of dicts, one per responding IP:
                {ip, server, location, friendly_name, manufacturer,
                 model_name, model_number}
            All fields except 'ip' may be None. Empty list on any
            socket-level failure or if nothing responded — never raises,
            so the scheduler can call this every cycle without wrapping
            it in a try/except itself.
        """
        raw_responses = self._send_and_collect()
        if not raw_responses:
            logger.info("[ssdp] No devices responded.")
            return []

        # Dedup by IP — a device typically replies once per search
        # target we sent, so the same IP can appear multiple times
        # across _SEARCH_TARGETS. Keep the reply with the most headers
        # (usually the more informative one) per IP.
        by_ip: Dict[str, Dict[str, str]] = {}
        for ip, headers in raw_responses:
            if ip not in by_ip or len(headers) > len(by_ip[ip]):
                by_ip[ip] = headers

        results: List[Dict] = []
        description_cache: Dict[str, Dict] = {}

        for ip, headers in by_ip.items():
            location = headers.get("location")
            entry = {
                "ip": ip,
                "server": headers.get("server"),
                "location": location,
                "friendly_name": None,
                "manufacturer": None,
                "model_name": None,
                "model_number": None,
            }

            if self.fetch_descriptions and location:
                if location not in description_cache:
                    description_cache[location] = self._fetch_description(location)
                entry.update(description_cache[location])

            results.append(entry)

        with_names = sum(1 for r in results if r.get("friendly_name"))
        logger.info(
            f"[ssdp] Discovery done — {len(results)} device(s) responded "
            f"({with_names} with a friendly name from device description)."
        )
        return results

    # ------------------------------------------------------------------
    # Private — network I/O
    # ------------------------------------------------------------------

    def _send_and_collect(self) -> List[tuple]:
        """
        Send M-SEARCH for every configured search target, then listen
        for replies until self.timeout elapses overall.

        Returns:
            List of (ip, headers_dict) tuples, one per valid reply.
            Empty list on any socket setup failure.
        """
        responses: List[tuple] = []
        sock = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.5)  # per-recv poll interval, not overall timeout

            for st in _SEARCH_TARGETS:
                message = _MSEARCH_TEMPLATE.format(
                    addr=_SSDP_MULTICAST_ADDR, port=_SSDP_MULTICAST_PORT, st=st
                ).encode("utf-8")
                try:
                    sock.sendto(message, (_SSDP_MULTICAST_ADDR, _SSDP_MULTICAST_PORT))
                except OSError as e:
                    logger.debug(f"[ssdp] M-SEARCH send failed for ST={st}: {e}")

            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(8192)
                except socket.timeout:
                    continue
                except OSError as e:
                    logger.debug(f"[ssdp] recvfrom error (non-fatal): {e}")
                    continue

                headers = _parse_ssdp_response(data)
                if headers:
                    responses.append((addr[0], headers))

        except OSError as e:
            logger.error(f"[ssdp] Socket setup failed: {e}")
            return []
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        return responses

    def _fetch_description(self, location: str) -> Dict[str, Optional[str]]:
        """
        Fetch and parse one device's description XML. Bounded, best-
        effort — failure here never prevents reporting the device with
        whatever the M-SEARCH reply itself already gave us.
        """
        empty = {
            "friendly_name": None, "manufacturer": None,
            "model_name": None, "model_number": None,
        }
        try:
            with urllib.request.urlopen(location, timeout=2) as resp:
                xml_bytes = resp.read()
            return _parse_device_description_xml(xml_bytes)
        except Exception as e:
            logger.debug(f"[ssdp] Description fetch failed for {location}: {e}")
            return empty


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    timeout = int(sys.argv[1]) if len(sys.argv) > 1 else 4

    print("\n" + "=" * 60)
    print("SSDP DISCOVERY — SMOKE TEST")
    print("=" * 60)
    print(f"Querying for {timeout}s...\n")

    ssdp = SSDPDiscovery(timeout=timeout)
    results = ssdp.discover()

    if not results:
        print(
            "No devices responded. This can mean: no UPnP-capable devices "
            "are on the network, or your firewall blocks multicast/UDP 1900."
        )
    else:
        for r in results:
            print(f"{'-'*60}")
            print(f"  IP           : {r['ip']}")
            print(f"  Friendly name: {r.get('friendly_name') or '-'}")
            print(f"  Manufacturer : {r.get('manufacturer') or '-'}")
            print(f"  Model        : {r.get('model_name') or '-'} "
                  f"{r.get('model_number') or ''}")
            print(f"  Server header: {r.get('server') or '-'}")
            print(f"  Location     : {r.get('location') or '-'}")

    print("\n" + "=" * 60)