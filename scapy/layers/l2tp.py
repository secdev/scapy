## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
L2TP (Layer 2 Tunneling Protocol) for VPNs.

[RFC 2661]
"""

import struct

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP
from scapy.layers.ppp import PPP

class L2TP(Packet):
    fields_desc = [ ShortEnumField("pkt_type",2,{2:"data"}),
                    ShortField("len", None),
                    ShortField("tunnel_id", 0),
                    ShortField("session_id", 0),
                    ShortField("ns", 0),
                    ShortField("nr", 0),
                    ShortField("offset", 0) ]

    def post_build(self, pkt, pay):
        if self.len is None:
            l = len(pkt)+len(pay)
            pkt = pkt[:2]+struct.pack("!H", l)+pkt[4:]
        return pkt+pay


bind_layers( UDP,           L2TP,          sport=1701, dport=1701)
bind_layers( L2TP,          PPP,           )
