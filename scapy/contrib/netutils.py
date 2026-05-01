# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net for more information

# scapy.contrib.description = Network utilities for common packet operations
# scapy.contrib.status = loads

"""
Network utility functions for common packet operations.

Helper functions for quickly generating common protocol packets,
checking packet validity, and formatting protocol information.
Useful for network learning and quick testing.
"""

from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.fields import Field
from scapy.config import conf


def ip_scan_packet(target_ip, src_ip=None):
    """Build an ICMP echo request packet for a quick host scan.

    Args:
        target_ip: Destination IP address
        src_ip: Source IP address (auto-detected if None)

    Returns:
        An IP/ICMP packet ready to send

    Example:
        >>> pkt = ip_scan_packet("192.168.1.1")
        >>> ans = sr1(pkt, timeout=2)
    """
    if src_ip is None:
        src_ip = conf.route.route(target_ip)[1]
    return IP(src=src_ip, dst=target_ip) / ICMP()


def arp_query_packet(target_ip, src_ip=None, src_mac=None):
    """Build an ARP who-has packet.

    Args:
        target_ip: The IP address to query
        src_ip: Source IP address (auto-detected if None)
        src_mac: Source MAC address (auto-detected if None)

    Returns:
        An Ether/ARP packet ready to send

    Example:
        >>> pkt = arp_query_packet("192.168.1.1")
        >>> ans = srp1(pkt, timeout=2)
    """
    if src_ip is None:
        src_ip = conf.route.route(target_ip)[1]
    if src_mac is None:
        src_mac = conf.iface.mac if hasattr(conf.iface, 'mac') else None
    return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op="who-has", pdst=target_ip, psrc=src_ip, hwsrc=src_mac
    )


def tcp_syn_packet(target_ip, target_port, src_port=0, src_ip=None):
    """Build a TCP SYN packet for port scanning.

    Args:
        target_ip: Destination IP address
        target_port: Destination port number
        src_port: Source port (random if 0)
        src_ip: Source IP address (auto-detected if None)

    Returns:
        An IP/TCP SYN packet ready to send

    Example:
        >>> pkt = tcp_syn_packet("192.168.1.1", 80)
        >>> ans = sr1(pkt, timeout=2)
    """
    if src_ip is None:
        src_ip = conf.route.route(target_ip)[1]
    return IP(src=src_ip, dst=target_ip) / TCP(
        sport=src_port, dport=target_port, flags="S"
    )


def get_layer_fields_desc(layer):
    """Get all field names and their descriptions for a given layer class.

    Args:
        layer: A Scapy Packet class (e.g., IP, TCP)

    Returns:
        List of (field_name, field_type, default_value) tuples

    Example:
        >>> fields = get_layer_fields_desc(TCP)
        >>> for name, ftype, default in fields:
        ...     print(f"{name}: {ftype} (default: {default})")
    """
    result = []
    for f in layer.fields_desc:
        fname = f.name
        ftype = type(f).__name__
        fdefault = f.default
        result.append((fname, ftype, fdefault))
    return result


def packet_summary_table(pkt, indent=0):
    """Print a formatted summary of all layers in a packet.

    Useful for learning about packet structure and quickly
    inspecting captured packets.

    Args:
        pkt: A Scapy Packet object
        indent: Indentation level (used for recursion)

    Example:
        >>> pkt = IP(dst="8.8.8.8")/TCP(dport=53)
        >>> packet_summary_table(pkt)
    """
    prefix = "  " * indent
    current = pkt
    while current is not None and isinstance(current, Packet):
        layer_name = current.__class__.__name__
        print(f"{prefix}[{layer_name}]")
        for f in current.fields_desc:
            val = getattr(current, f.name)
            if val is not None and val != b"":
                print(f"{prefix}  {f.name}: {val}")
        current = current.payload
        if isinstance(current, Packet) and current.__class__.__name__ == "Raw":
            break
        if isinstance(current, Packet) and current.__class__.__name__ == "Padding":
            break


def is_ipv4_multicast(ip_addr):
    """Check if an IPv4 address is a multicast address (224.0.0.0/4).

    Args:
        ip_addr: IPv4 address string

    Returns:
        True if the address is in the multicast range

    Example:
        >>> is_ipv4_multicast("224.0.0.5")
        True
        >>> is_ipv4_multicast("192.168.1.1")
        False
    """
    from scapy.utils import atol
    try:
        first_octet = atol(ip_addr) >> 24 & 0xFF
        return 224 <= first_octet <= 239
    except Exception:
        return False


def well_known_ports():
    """Return a dictionary of common well-known TCP/UDP ports.

    Useful for quick reference when analyzing network captures.

    Returns:
        Dictionary mapping port numbers to service names

    Example:
        >>> ports = well_known_ports()
        >>> ports[80]
        'HTTP'
    """
    return {
        20: "FTP-Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP-Server",
        68: "DHCP-Client",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP-Trap",
        179: "BGP",
        194: "IRC",
        443: "HTTPS",
        514: "Syslog",
        520: "RIP",
        521: "RIPng",
        646: "LDP",
        1985: "HSRPv1",
        2029: "HSRPv2",
        3784: "BFD",
        5353: "mDNS",
        8080: "HTTP-Alt",
    }
