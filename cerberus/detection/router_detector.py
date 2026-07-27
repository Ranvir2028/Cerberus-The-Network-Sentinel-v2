"""
Answers one question: what networks is this machine currently on, and
how do I describe each in CIDR notation? Pure topology read —
interfaces → IPs → networks → gateways, no Scapy, no Nmap, no DB
touches. Zero active interfaces (airplane mode) just returns [], and
every caller has to treat that as normal, not an error.

Found and fixed a real bug here: Docker Desktop's WSL2 backend creates
a virtual adapter that the old filtering missed, for two reasons. The
interface-name filter (_is_virtual_interface_name, checking for
"wsl"/"vethernet") assumed netifaces reports a human-readable adapter
name — on some Windows setups it reports a raw GUID instead
(e.g. "{51226080-FBDF-4025-926E-...}"), which obviously never matches
those markers. And the IP-range filter (_is_virtual_adapter) only
covered a few fixed /24-ish ranges for VMware/VirtualBox/Docker
Toolbox — WSL2's default NAT network isn't a fixed /24 at all, it's
somewhere inside 172.16.0.0/12, varying per machine, so an adapter
landing anywhere in that block (172.21.176.0/20 in the case that
surfaced this) sailed straight through.

Fixed by swapping the ad-hoc string-prefix matching for real CIDR
containment checks via the stdlib `ipaddress` module, and adding
172.16.0.0/12 to the known-virtual-ranges list — more correct in
general too, since it handles any prefix length instead of just the
neat /24 boundaries someone wrote out by hand.

Why it mattered: every undetected phantom network got its own full
set of scan workers (Scapy + two Nmap tiers, one of them a 4-thread
aggressive pool). On an 8-core machine, a phantom network's workers
competing for CPU with the real network's workers measurably slowed
down scanning of the network that actually matters — for zero real
devices found, every cycle.
"""

import ipaddress
import socket
import struct
import logging
from typing import List, Dict, Optional

try:
    import netifaces
    _NETIFACES_AVAILABLE = True
except ImportError:
    _NETIFACES_AVAILABLE = False

logger = logging.getLogger("cerberus.detection.router_detector")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mask_to_cidr(netmask: str) -> int:
    """Convert dotted-decimal subnet mask to CIDR prefix length.

    Example: '255.255.255.0' → 24
    """
    try:
        packed = socket.inet_aton(netmask)
        bits = struct.unpack("!I", packed)[0]
        return bin(bits).count("1")
    except Exception:
        return 24  # Safe fallback — /24 is the most common home subnet


def _calculate_network_address(ip: str, netmask: str) -> str:
    """AND the IP with the mask to get the network address.

    Example: ip='192.168.1.105', mask='255.255.255.0' → '192.168.1.0'
    """
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        network_int = ip_int & mask_int
        return socket.inet_ntoa(struct.pack("!I", network_int))
    except Exception:
        # If the math fails, return the /24 base of the IP as a fallback
        return ".".join(ip.split(".")[:3]) + ".0"


def _is_loopback(interface: str, ip: str) -> bool:
    """Return True if this interface/IP should be skipped."""
    loopback_ifaces = {"lo", "lo0"}
    if interface.lower() in loopback_ifaces:
        return True
    if ip.startswith("127."):
        return True
    return False


# Known virtual-adapter ranges, expressed as real CIDR networks rather
# than string prefixes — this is what actually lets a range like
# 172.16.0.0/12 (WSL2's full possible NAT space, not one fixed /24) be
# checked correctly regardless of which specific subnet within it a
# given machine happens to be assigned.
_VIRTUAL_NETWORKS = [
    ipaddress.ip_network("192.168.56.0/24"),   # VirtualBox host-only default
    ipaddress.ip_network("192.168.153.0/24"),  # VMware host-only (common default)
    ipaddress.ip_network("192.168.99.0/24"),   # Docker Toolbox (legacy)
    ipaddress.ip_network("169.254.0.0/16"),    # APIPA / link-local — not a real network
    ipaddress.ip_network("172.16.0.0/12"),     # WSL2 default NAT space (Docker
                                                 # Desktop's WSL2 backend, and any
                                                 # standalone WSL2 install) — this
                                                 # is the range that was previously
                                                 # missing entirely.
]


def _is_virtual_adapter(ip: str) -> bool:
    """
    Return True if this IP falls within a known virtual-adapter range.
    Uses real CIDR containment (ipaddress module) rather than string
    prefix matching, so a wide range like WSL2's 172.16.0.0/12 is
    checked precisely regardless of which specific /20 or /24 within
    it a given machine's adapter actually landed on.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _VIRTUAL_NETWORKS)


def _is_virtual_interface_name(interface: str) -> bool:
    """
    Return True if the INTERFACE NAME itself identifies it as virtual,
    regardless of its IP range. This is a SECONDARY check — see this
    module's docstring for why it's known to be unreliable on some
    Windows configurations (netifaces-plus may report a raw GUID
    instead of a friendly adapter name there, in which case this check
    silently never matches and _is_virtual_adapter's IP-range check
    above is what actually does the work). Kept because on platforms
    where a friendly name IS reported, it catches virtual adapters
    that might not fall into any of the known IP ranges at all.
    """
    name_lower = interface.lower()
    virtual_name_markers = (
        "vethernet",         # Windows Hyper-V / WSL2 / Docker virtual switches
        "docker",
        "wsl",
        "virtualbox",
        "vmware",
        "hyper-v",
        "npcap loopback",
        "loopback pseudo",
    )
    return any(marker in name_lower for marker in virtual_name_markers)


# ---------------------------------------------------------------------------
# Core detector
# ---------------------------------------------------------------------------

class RouterDetector:
    """
    Walks every network interface on the machine, skips loopback,
    and returns structured network topology info.

    Usage:
        detector = RouterDetector()
        networks = detector.get_all_networks()
        # → [{'interface': 'wlan0', 'ip': '192.168.1.5',
        #      'network': '192.168.1.0/24', 'netmask': '255.255.255.0',
        #      'gateway': '192.168.1.1'}, ...]
    """

    def __init__(self):
        if not _NETIFACES_AVAILABLE:
            logger.warning(
                "netifaces-plus not installed. "
                "Run: pip install netifaces-plus"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_all_networks(self) -> List[Dict]:
        """
        Return one dict per active non-loopback, non-virtual interface.

        Each dict:
            interface : str   — e.g. 'wlan0', 'eth0'
            ip        : str   — host IP on that interface
            network   : str   — CIDR string, e.g. '192.168.1.0/24'
            netmask   : str   — dotted-decimal mask
            gateway   : str   — default gateway IP ('' if unknown)

        Returns [] if no active interfaces exist (airplane mode, etc.).
        Callers must treat [] as normal — do NOT assume at least one entry.
        """
        if not _NETIFACES_AVAILABLE:
            logger.error("netifaces-plus missing — cannot detect interfaces.")
            return []

        gateways = self._get_gateways()
        results: List[Dict] = []

        for iface in netifaces.interfaces():
            entry = self._process_interface(iface, gateways)
            if entry:
                results.append(entry)
                logger.debug(
                    f"Interface {iface}: {entry['ip']} → {entry['network']}"
                    + (f" via {entry['gateway']}" if entry['gateway'] else "")
                )

        if not results:
            logger.warning("No active non-loopback interfaces found.")
        else:
            logger.info(f"Detected {len(results)} active network(s).")

        return results

    def get_primary_network(self) -> Optional[Dict]:
        """
        Return the single 'best' network — the one whose interface owns
        the default gateway.  Falls back to the first result if no default
        gateway interface can be identified.  Returns None if no networks.
        """
        networks = self.get_all_networks()
        if not networks:
            return None

        # Try to find the interface that holds the default route
        try:
            gws = netifaces.gateways()
            default_gw = gws.get("default", {})
            if netifaces.AF_INET in default_gw:
                _, default_iface = default_gw[netifaces.AF_INET][:2]
                for net in networks:
                    if net["interface"] == default_iface:
                        logger.info(
                            f"Primary network: {net['network']} "
                            f"on {net['interface']}"
                        )
                        return net
        except Exception as e:
            logger.debug(f"Default gateway lookup failed: {e}")

        # Fallback: first result
        return networks[0]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_gateways(self) -> Dict[str, str]:
        """
        Build a map of {interface_name: gateway_ip} for every IPv4 route.
        Returns {} on any failure — gateway is optional metadata.
        """
        gw_map: Dict[str, str] = {}
        try:
            gws = netifaces.gateways()
            for gw_ip, iface, *_ in gws.get(netifaces.AF_INET, []):
                gw_map[iface] = gw_ip
            # Also capture the default gateway's interface
            default = gws.get("default", {}).get(netifaces.AF_INET)
            if default:
                gw_ip, iface = default[0], default[1]
                gw_map.setdefault(iface, gw_ip)
        except Exception as e:
            logger.debug(f"Gateway enumeration error: {e}")
        return gw_map

    def _process_interface(
        self, iface: str, gateways: Dict[str, str]
    ) -> Optional[Dict]:
        """
        Extract IPv4 info from one interface.
        Returns None for loopback, virtual, non-IPv4, or unaddressed
        interfaces.
        """
        if _is_virtual_interface_name(iface):
            logger.debug(f"Skipping virtual interface by name: {iface}")
            return None

        try:
            addrs = netifaces.ifaddresses(iface)
        except Exception as e:
            logger.debug(f"Could not read interface {iface}: {e}")
            return None

        ipv4_list = addrs.get(netifaces.AF_INET, [])
        if not ipv4_list:
            return None  # No IPv4 address — skip (e.g. IPv6-only, down iface)

        addr_info = ipv4_list[0]
        ip = addr_info.get("addr", "")
        netmask = addr_info.get("netmask", "255.255.255.0")

        if not ip or _is_loopback(iface, ip):
            return None

        if _is_virtual_adapter(ip):
            logger.debug(f"Skipping virtual adapter by IP range: {iface} ({ip})")
            return None

        network_addr = _calculate_network_address(ip, netmask)
        cidr = _mask_to_cidr(netmask)
        network_cidr = f"{network_addr}/{cidr}"
        gateway = gateways.get(iface, "")

        return {
            "interface": iface,
            "ip": ip,
            "network": network_cidr,
            "netmask": netmask,
            "gateway": gateway,
        }


# ---------------------------------------------------------------------------
# Standalone smoke-test (not used by anything in production)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    detector = RouterDetector()

    print("\n" + "=" * 60)
    print("ROUTER DETECTOR — SMOKE TEST")
    print("=" * 60)

    networks = detector.get_all_networks()

    if not networks:
        print("\n[!] No active networks found (airplane mode?).")
    else:
        print(f"\nFound {len(networks)} active network(s):\n")
        for n in networks:
            print(f"  Interface : {n['interface']}")
            print(f"  Host IP   : {n['ip']}")
            print(f"  Network   : {n['network']}")
            print(f"  Netmask   : {n['netmask']}")
            print(f"  Gateway   : {n['gateway'] or 'unknown'}")
            print()

    primary = detector.get_primary_network()
    if primary:
        print(f"Primary network (scheduler will use this): {primary['network']}")

    print("=" * 60)