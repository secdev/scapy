# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
L2TP (Layer 2 Tunneling Protocol) for VPNs.

[RFC 2661]
"""

import struct

from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import BitEnumField, ConditionalField, FlagsField, \
    PadField, ShortField
from scapy.layers.inet import UDP
from scapy.layers.ppp import PPP


class L2TP(Packet):
    name = "L2TP"
    fields_desc = [
        FlagsField("hdr", 0, 12, ['res00', 'res01', 'res02', 'res03', 'priority', 'offset',  # noqa: E501
                                  'res06', 'sequence', 'res08', 'res09', 'length', 'control']),  # noqa: E501
        BitEnumField("version", 2, 4, {2: 'L2TPv2'}),

        ConditionalField(ShortField("len", 0),
                         lambda pkt: pkt.hdr & 'control+length'),
        ShortField("tunnel_id", 0),
        ShortField("session_id", 0),
        ConditionalField(ShortField("ns", 0),
                         lambda pkt: pkt.hdr & 'sequence+control'),
        ConditionalField(ShortField("nr", 0),
                         lambda pkt: pkt.hdr & 'sequence+control'),
        ConditionalField(
            PadField(ShortField("offset", 0), 4, b"\x00"),
            lambda pkt: not (pkt.hdr & 'control') and pkt.hdr & 'offset'
        )
    ]

    def post_build(self, pkt, pay):
        if self.len is None:
            tmp_len = len(pkt) + len(pay)
            pkt = pkt[:2] + struct.pack("!H", tmp_len) + pkt[4:]
        return pkt + pay


bind_bottom_up(UDP, L2TP, dport=1701)
bind_bottom_up(UDP, L2TP, sport=1701)
bind_layers(UDP, L2TP, dport=1701, sport=1701)
bind_layers(L2TP, PPP,)
