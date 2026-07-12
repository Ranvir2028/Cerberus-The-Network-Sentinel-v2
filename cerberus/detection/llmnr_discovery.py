# deps: none — stdlib only (socket, struct)
"""
detection/llmnr_discovery.py

Job: active LLMNR (Link-Local Multicast Name Resolution) reverse
lookup — given a list of IPs already confirmed alive, ask each one
directly "what's your hostname?" via an LLMNR PTR query.

Why this exists:
  LLMNR is Windows' fallback name-resolution protocol (used when DNS
  can't resolve a name) and is enabled by default on most Windows
  installs. Windows machines that don't run mDNS and don't always
  respond usefully to NetBIOS/SMB queries (nbstat can be blocked by
  firewall profiles, especially "Public" network profiles) will often
  still answer an LLMNR query — this is a FOURTH independent hostname
  signal alongside mDNS (mdns_discovery.py), DHCP (dhcp_sniffer.py),
  and SSDP (ssdp_discovery.py), specifically covering the Windows
  machines the other three sometimes miss.

Architectural difference from mDNS/SSDP (read before assuming the
same "browse for anything" pattern applies):
  mDNS and SSDP are both "broadcast a question, see who answers" —
  self-contained calls needing no external input. LLMNR's useful mode
  here is the OPPOSITE: a REVERSE lookup for a SPECIFIC already-known
  IP ("who are you?"), not a forward lookup for a name we don't have.
  This means resolve() takes a list of target IPs as a parameter — the
  scheduler must inject the list of currently-alive IPs (from its
  Scapy ARP cache), the same way scanner_scapy.py's scan() takes a
  network CIDR as a parameter instead of detecting it itself. This
  module never goes looking for IPs on its own.

Why this is hand-built instead of using a DNS library:
  LLMNR reuses the standard DNS wire format (RFC 4795 §2.1: "the
  packet formats for the LLMNR query and response are copied from the
  DNS query and response formats"), but the stdlib has no DNS message
  builder/parser and this project avoids adding a new third-party
  dependency for something this self-contained. The wire format is a
  fixed, well-documented 12-byte header plus length-prefixed labels —
  small enough to implement and unit-test directly, including the
  pointer-based name COMPRESSION real-world responses almost always
  use (a bare, uncompressed implementation would silently fail to
  parse most genuine Windows LLMNR replies).

Rules (same isolation pattern as mdns_discovery.py / ssdp_discovery.py):
  - No Scapy/Nmap import, no storage, no trust logic.
  - Pure: given IPs, query and wait `timeout` seconds, return whatever
    answered. Does NOT decide which IPs are worth asking — that's the
    scheduler's job, using its own live-host knowledge.
  - Every failure mode (socket error, malformed/truncated response,
    a target host with LLMNR disabled entirely — the overwhelming
    majority of non-Windows devices) degrades to "that IP just isn't
    in the results," never a crash.

Usage:
    llmnr = LLMNRDiscovery(timeout=2)
    results = llmnr.resolve(["192.168.1.10", "192.168.1.20"])
    # → [{'ip': '192.168.1.10', 'hostname': 'DESKTOP-ABC123'}]
    # IPs that didn't answer are simply absent — not an error.
"""

import logging
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("cerberus.detection.llmnr_discovery")

_LLMNR_PORT = 5355
_DNS_QTYPE_PTR = 12
_DNS_QCLASS_IN = 1

# Maximum compression-pointer hops to follow when decoding a name —
# a real message never needs more than a handful; this exists purely
# as a safety bound against a malformed/malicious packet containing a
# pointer cycle, which would otherwise loop forever.
_MAX_POINTER_HOPS = 20


# ---------------------------------------------------------------------------
# Pure packet building / parsing — factored out for testability without
# needing real sockets or real LLMNR-speaking devices.
# ---------------------------------------------------------------------------

def _ip_to_ptr_qname(ip: str) -> str:
    """
    Build the reverse-lookup query name for an IPv4 address, e.g.
    '192.168.1.50' → '50.1.168.192.in-addr.arpa' (octets reversed,
    standard PTR query convention — same one plain DNS PTR uses).
    """
    octets = ip.split(".")
    return ".".join(reversed(octets)) + ".in-addr.arpa"


def _encode_dns_name(name: str) -> bytes:
    """
    Encode a dotted name into DNS wire format: each label prefixed by
    its length byte, terminated by a zero-length byte. No compression
    used on the way OUT — only needed (and implemented) for decoding
    responses, since we control what we send.
    """
    parts = name.split(".")
    encoded = b""
    for part in parts:
        label = part.encode("ascii")
        if len(label) > 63:
            raise ValueError(f"DNS label too long: {part!r}")
        encoded += bytes([len(label)]) + label
    return encoded + b"\x00"


def _build_ptr_query(ip: str, query_id: int) -> bytes:
    """
    Build a raw LLMNR (DNS-format) PTR query packet asking "what
    hostname resolves to this IP?"

    Args:
        ip       : Target IPv4 address to query.
        query_id : 16-bit transaction ID — echoed back in the response,
                   lets us match replies to the query that triggered
                   them if ever needed (currently matched by source IP
                   instead, but included for correctness/future use).

    Returns:
        Raw bytes ready to send over UDP.
    """
    qname = _ip_to_ptr_qname(ip)
    question = _encode_dns_name(qname) + struct.pack(
        "!HH", _DNS_QTYPE_PTR, _DNS_QCLASS_IN
    )

    # DNS/LLMNR header: ID, flags, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    # flags=0x0000 is a standard query (opcode QUERY, no special bits set)
    header = struct.pack("!HHHHHH", query_id, 0x0000, 1, 0, 0, 0)

    return header + question


def _decode_dns_name(data: bytes, offset: int) -> Tuple[Optional[str], int]:
    """
    Decode a (possibly compressed) DNS name starting at `offset` within
    `data`, following compression pointers as needed.

    DNS name compression: a label length byte with its top two bits set
    (0xC0 mask) indicates a POINTER, not a literal label — the
    remaining 14 bits (this byte's low 6 bits + the next byte) give an
    offset elsewhere in the message where the name actually continues.
    Real-world LLMNR responses almost always use this for the PTR
    answer's target name, since it commonly repeats part of the
    question section.

    Args:
        data   : The full raw response packet.
        offset : Byte offset to start decoding from.

    Returns:
        (name, offset_after_name) — offset_after_name is where reading
        should resume in the ORIGINAL (non-pointer-followed) stream,
        which matters when a name appears inline (not compressed) and
        is followed by more fields (TYPE/CLASS/etc). If a pointer was
        followed, offset_after_name is the position right after the
        2-byte pointer itself, NOT the position inside the jumped-to
        location.
        Returns (None, offset) if decoding fails at any point —
        callers must treat this as "could not parse," not crash.
    """
    labels: List[str] = []
    hops = 0
    original_offset = offset
    jumped = False

    try:
        while True:
            if offset >= len(data):
                return None, original_offset

            length_byte = data[offset]

            if length_byte == 0:
                # End of name
                offset += 1
                if not jumped:
                    original_offset = offset
                break

            if (length_byte & 0xC0) == 0xC0:
                # Compression pointer — next byte + low 6 bits of this
                # one form a 14-bit offset to jump to.
                if offset + 1 >= len(data):
                    return None, original_offset
                pointer = ((length_byte & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                offset = pointer
                hops += 1
                if hops > _MAX_POINTER_HOPS:
                    logger.debug("[llmnr] Too many compression pointer hops — aborting.")
                    return None, original_offset
                continue

            # Literal label
            offset += 1
            label_bytes = data[offset: offset + length_byte]
            if len(label_bytes) != length_byte:
                return None, original_offset
            labels.append(label_bytes.decode("ascii", errors="ignore"))
            offset += length_byte

        return ".".join(labels), original_offset

    except Exception as e:
        logger.debug(f"[llmnr] Name decode error: {e}")
        return None, original_offset


def _parse_ptr_response(raw: bytes) -> Optional[str]:
    """
    Parse a raw LLMNR/DNS PTR response and extract the resolved
    hostname from its answer section.

    Args:
        raw: The full raw response packet bytes.

    Returns:
        The resolved hostname string (with any trailing root label
        removed), or None if the packet is too short, malformed, has
        no answers, or isn't a PTR answer at all.
    """
    if len(raw) < 12:
        return None

    try:
        _id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
            "!HHHHHH", raw[:12]
        )
    except struct.error:
        return None

    if ancount < 1:
        return None  # No answers — a well-formed "I don't know" response

    offset = 12

    # Skip the question section (qdcount entries) to reach the answers.
    for _ in range(qdcount):
        _name, offset = _decode_dns_name(raw, offset)
        if offset is None or offset + 4 > len(raw):
            return None
        offset += 4  # QTYPE (2 bytes) + QCLASS (2 bytes)

    # Parse the first answer record.
    _name, offset = _decode_dns_name(raw, offset)
    if offset is None or offset + 10 > len(raw):
        return None

    try:
        rtype, _rclass, _ttl, rdlength = struct.unpack(
            "!HHIH", raw[offset: offset + 10]
        )
    except struct.error:
        return None
    offset += 10

    if rtype != _DNS_QTYPE_PTR:
        return None  # Not a PTR record — nothing useful to extract

    if offset + rdlength > len(raw):
        return None

    # RDATA for a PTR record is itself a (possibly compressed) DNS name.
    ptr_name, _ = _decode_dns_name(raw, offset)
    if not ptr_name:
        return None

    return ptr_name.rstrip(".")


# ---------------------------------------------------------------------------
# LLMNR discovery
# ---------------------------------------------------------------------------

class LLMNRDiscovery:
    """
    Reverse (IP → hostname) LLMNR lookup for a given list of IPs.

    Usage:
        llmnr = LLMNRDiscovery(timeout=2)
        results = llmnr.resolve(["192.168.1.10", "192.168.1.20"])
    """

    def __init__(self, timeout: float = 2.0):
        """
        Args:
            timeout: Total seconds to wait for replies after sending
                     all queries — NOT per-IP. Every query is sent
                     up front, then this is one shared collection
                     window, so resolving 30 IPs costs roughly the
                     same wall-clock time as resolving 1.
        """
        self.timeout = timeout

    def resolve(self, ips: List[str]) -> List[Dict]:
        """
        Send an LLMNR PTR query directly (unicast) to each given IP on
        port 5355, then collect replies for self.timeout seconds.

        Unicast (not multicast) by design: we already know exactly
        which IP we want an answer FROM, so there's no need to ask the
        whole network — this is quieter and avoids needing multicast
        group membership setup, which behaves inconsistently across
        platforms for a socket that's also trying to send.

        Args:
            ips: IPs to query. Typically the scheduler's current
                 Scapy-confirmed live-host list for one network.

        Returns:
            List of {'ip', 'hostname'} — one entry per IP that
            answered. IPs with LLMNR disabled/unsupported (the
            overwhelming majority of non-Windows devices) simply don't
            appear in the result; this is normal, not a failure.
            Empty list on any socket-level setup failure.
        """
        if not ips:
            return []

        sock = None
        results: Dict[str, str] = {}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)  # per-recv poll interval, not overall timeout

            query_id = 0x1234  # fixed ID is fine — we match by source IP, not ID
            query_bytes = None
            for ip in ips:
                try:
                    query_bytes = _build_ptr_query(ip, query_id)
                    sock.sendto(query_bytes, (ip, _LLMNR_PORT))
                except (OSError, ValueError) as e:
                    logger.debug(f"[llmnr] Query send failed for {ip}: {e}")

            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError as e:
                    logger.debug(f"[llmnr] recvfrom error (non-fatal): {e}")
                    continue

                sender_ip = addr[0]
                if sender_ip not in ips or sender_ip in results:
                    continue  # not one we queried, or already answered

                hostname = _parse_ptr_response(data)
                if hostname:
                    results[sender_ip] = hostname
                    logger.debug(f"[llmnr] {sender_ip} → {hostname}")

        except OSError as e:
            logger.error(f"[llmnr] Socket setup failed: {e}")
            return []
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        logger.info(
            f"[llmnr] Resolved {len(results)}/{len(ips)} queried IP(s)."
        )
        return [{"ip": ip, "hostname": hostname} for ip, hostname in results.items()]


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
        print("Usage: python -m cerberus.detection.llmnr_discovery <ip1> [ip2] ...")
        print("Example: python -m cerberus.detection.llmnr_discovery 192.168.1.10 192.168.1.20")
        sys.exit(1)

    targets = sys.argv[1:]

    print("\n" + "=" * 60)
    print("LLMNR DISCOVERY — SMOKE TEST")
    print("=" * 60)
    print(f"Querying {len(targets)} IP(s): {targets}\n")

    llmnr = LLMNRDiscovery(timeout=2)
    results = llmnr.resolve(targets)

    if not results:
        print(
            "No responses. This is normal for non-Windows devices, or "
            "Windows machines with LLMNR disabled via Group Policy."
        )
    else:
        for r in results:
            print(f"  {r['ip']:<18} → {r['hostname']}")

    print("\n" + "=" * 60)