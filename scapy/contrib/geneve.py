#! /usr/bin/env python
# (GENEVE):
# A Framework for Overlaying Virtualized Layer 2 Networks over Layer 3 Networks

from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.fields import FlagsField, XByteField, ThreeBytesField, \
    ConditionalField, ShortField, ByteEnumField, X3BytesField

#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |        Virtual Network Identifier (VNI)       |    Reserved   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Variable Length Options                    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#

class GENEVE(Packet):
    name = "GENEVE"

    fields_desc = [
        # INIT = ver + optlen + o + c + rsvd (all zeros)
        ShortField("init", 0x0),
        # PROTOCOL is a 2-bytes field
        ShortField("protocol", 0x6558),
        ThreeBytesField("vni", 0),
        XByteField("reserved2", 0),
    ]

    def mysummary(self):
        return self.sprintf("GENEVE (vni=%GENEVE.vni%)")

bind_layers(UDP, GENEVE, dport=6081)  # RFC standard port
bind_layers(UDP, GENEVE, dport=8472)  # Linux implementation port
# By default, set both ports to the RFC standard
bind_layers(UDP, GENEVE, sport=6081, dport=6081)
bind_layers(GENEVE, Ether)
