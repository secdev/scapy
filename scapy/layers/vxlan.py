"""
Virtual eXtensible Local Area Network (VXLAN)

http://tools.ietf.org/html/draft-mahalingam-dutt-dcops-vxlan-08

VXLAN Group Policy Option

http://tools.ietf.org/html/draft-smith-vxlan-group-policy-00
"""

from scapy.packet import Packet, bind_layers
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.fields import BitField, XBitField, FlagsField, ConditionalField

class VXLAN(Packet):
    name = 'VXLAN'

    fields_desc = [
        FlagsField('flags', default=0x8, size=8,
                   names=['R', 'R', 'R', 'I', 'R', 'R', 'R', 'G']),
        ConditionalField(
            XBitField('reserved1', default=0x000000, size=24),
            lambda pkt: not pkt.flags & 0x80,
        ),
        ConditionalField(
            FlagsField('gpflags', default=0, size=8,
                       names=['R', 'R', 'R', 'A', 'R', 'R', 'D', 'R']),
            lambda pkt: pkt.flags & 0x80,
        ),
        ConditionalField(
            BitField('gpid', None, size=16),
            lambda pkt: pkt.flags & 0x80,
        ),
        BitField('vni', None, size=24),
        XBitField('reserved2', default=0x00, size=8),
    ]

    overload_fields = {
        UDP: {'dport': 4789},
    }

    def mysummary(self):
        if self.flags & 0x80:
            return self.sprintf('VXLAN (vni=%VXLAN.vni% gpid=%VXLAN.gpid%)')
        else:
            return self.sprintf('VXLAN (vni=%VXLAN.vni%)')

bind_layers(UDP, VXLAN, dport=4789)  # RFC standard port
bind_layers(UDP, VXLAN, dport=8472)  # Linux implementation port
bind_layers(VXLAN, Ether)
