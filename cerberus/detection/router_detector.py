# deps: pip install netifaces-plus
"""
detection/router_detector.py

Job: Answer ONE question — "what networks is this machine currently on,
and how do I describe each one in CIDR notation?"

Rules:
- NO Scapy, NO Nmap, NO database touches.
- Pure topology read: interfaces → IPs → networks → gateways.
- Zero active interfaces (airplane mode) → returns [], never crashes.
- Every downstream caller must treat [] as a normal, handleable state.

Update (Phase 3 hardening): added interface-NAME-based virtual adapter
filtering alongside the existing IP-prefix filtering. Docker Desktop's
WSL2/Hyper-V virtual switch ("vEthernet (WSL)", "vEthernet (Default
Switch)") doesn't reliably fall into any fixed IP range, so it could slip
past the IP-prefix check and get scanned as if it were a real LAN
segment — which is what produced a spurious "docker.internal" entry
that looked like an unknown device. Filtering by interface name closes
that gap regardless of whatever IP range Docker/WSL happens to assign.
"""

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


def _is_virtual_adapter(ip: str) -> bool:
    """
    Return True if this IP belongs to a known virtual adapter range.
    VMware uses 192.168.153.x and 192.168.x.1 on host-only adapters.
    VirtualBox uses 192.168.56.x by default.
    These produce zero real LAN devices — skip them.
    """
    virtual_prefixes = (
        "192.168.56.",   # VirtualBox host-only
        "192.168.153.",  # VMware host-only (common default)
        "192.168.99.",   # Docker Toolbox
        "169.254.",      # APIPA / link-local — not a real network
    )
    return any(ip.startswith(p) for p in virtual_prefixes)


def _is_virtual_interface_name(interface: str) -> bool:
    """
    Return True if the INTERFACE NAME itself identifies it as virtual,
    regardless of its IP range. Docker Desktop's WSL2/Hyper-V virtual
    switch doesn't reliably fall into any fixed IP range the way
    VMware/VirtualBox host-only adapters do, so an IP-prefix check
    alone misses it. This is what produced the "docker.internal"
    entry that looked like an unknown LAN device — Cerberus was
    scanning its own host's virtual switch, not a real device.
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