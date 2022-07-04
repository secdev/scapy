# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Mobile IP.
"""

from scapy.fields import ByteEnumField, ByteField, IPField, LongField, \
    ShortField, XByteField
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.layers.inet import IP, UDP


class MobileIP(Packet):
    name = "Mobile IP (RFC3344)"
    fields_desc = [ByteEnumField("type", 1, {1: "RRQ", 3: "RRP"})]


class MobileIPRRQ(Packet):
    name = "Mobile IP Registration Request (RFC3344)"
    fields_desc = [XByteField("flags", 0),
                   ShortField("lifetime", 180),
                   IPField("homeaddr", "0.0.0.0"),
                   IPField("haaddr", "0.0.0.0"),
                   IPField("coaddr", "0.0.0.0"),
                   LongField("id", 0), ]


class MobileIPRRP(Packet):
    name = "Mobile IP Registration Reply (RFC3344)"
    fields_desc = [ByteField("code", 0),
                   ShortField("lifetime", 180),
                   IPField("homeaddr", "0.0.0.0"),
                   IPField("haaddr", "0.0.0.0"),
                   LongField("id", 0), ]


class MobileIPTunnelData(Packet):
    name = "Mobile IP Tunnel Data Message (RFC3519)"
    fields_desc = [ByteField("nexthdr", 4),
                   ShortField("res", 0)]


bind_bottom_up(UDP, MobileIP, dport=434)
bind_bottom_up(UDP, MobileIP, sport=434)
bind_layers(UDP, MobileIP, sport=434, dport=434)
bind_layers(MobileIP, MobileIPRRQ, type=1)
bind_layers(MobileIP, MobileIPRRP, type=3)
bind_layers(MobileIP, MobileIPTunnelData, type=4)
bind_layers(MobileIPTunnelData, IP, nexthdr=4)
