# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
LLMNR (Link Local Multicast Node Resolution).

[RFC 4795]

LLMNR is based on the DNS packet format (RFC1035 Section 4)
RFC also envisions LLMNR over TCP. Like vista, we don't support it -- arno
"""

import struct

from scapy.fields import (
    BitEnumField,
    BitField,
    DestField,
    DestIP6Field,
    ShortField,
)
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.compat import orb
from scapy.layers.inet import UDP
from scapy.layers.dns import (
    DNSCompressedPacket,
    DNS_am,
    DNS,
    DNSQR,
    DNSRR,
)


_LLMNR_IPv6_mcast_Addr = "FF02:0:0:0:0:0:1:3"
_LLMNR_IPv4_mcast_addr = "224.0.0.252"


class LLMNRQuery(DNSCompressedPacket):
    name = "Link Local Multicast Node Resolution - Query"
    qd = []
    fields_desc = [
        ShortField("id", 0),
        BitField("qr", 0, 1),
        BitEnumField("opcode", 0, 4, {0: "QUERY"}),
        BitField("c", 0, 1),
        BitField("tc", 0, 1),
        BitField("t", 0, 1),
        BitField("z", 0, 4)
    ] + DNS.fields_desc[-9:]
    overload_fields = {UDP: {"sport": 5355, "dport": 5355}}

    def get_full(self):
        # Required for DNSCompressedPacket
        return self.original

    def hashret(self):
        return struct.pack("!H", self.id)

    def mysummary(self):
        s = self.__class__.__name__
        if self.qr:
            if self.an and isinstance(self.an[0], DNSRR):
                s += " '%s' is at '%s'" % (
                    self.an[0].rrname.decode(errors="backslashreplace"),
                    self.an[0].rdata,
                )
            else:
                s += " [malformed]"
        elif self.qd and isinstance(self.qd[0], DNSQR):
            s += " who has '%s'" % (
                self.qd[0].qname.decode(errors="backslashreplace"),
            )
        else:
            s += " [malformed]"
        return s, [UDP]


class LLMNRResponse(LLMNRQuery):
    name = "Link Local Multicast Node Resolution - Response"
    qr = 1

    def answers(self, other):
        return (isinstance(other, LLMNRQuery) and
                self.id == other.id and
                self.qr == 1 and
                other.qr == 0)


class _LLMNR(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if len(_pkt) >= 2:
            if (orb(_pkt[2]) & 0x80):  # Response
                return LLMNRResponse
            else:                  # Query
                return LLMNRQuery
        return cls


bind_bottom_up(UDP, _LLMNR, dport=5355)
bind_bottom_up(UDP, _LLMNR, sport=5355)
bind_layers(UDP, _LLMNR, sport=5355, dport=5355)

DestField.bind_addr(LLMNRQuery, _LLMNR_IPv4_mcast_addr, dport=5355)
DestField.bind_addr(LLMNRResponse, _LLMNR_IPv4_mcast_addr, dport=5355)
DestIP6Field.bind_addr(LLMNRQuery, _LLMNR_IPv6_mcast_Addr, dport=5355)
DestIP6Field.bind_addr(LLMNRResponse, _LLMNR_IPv6_mcast_Addr, dport=5355)


class LLMNR_am(DNS_am):
    """
    LLMNR answering machine.

    This has the same arguments as DNS_am. See help(DNS_am)

    Example::

        >>> llmnrd(joker="192.168.0.2", iface="eth0")
        >>> llmnrd(match={"TEST": "192.168.0.2"})
    """
    function_name = "llmnrd"
    filter = "udp port 5355"
    cls = LLMNRQuery


# LLMNRQuery(id=RandShort(), qd=DNSQR(qname="vista.")))
