#! /usr/bin/env python
# RFC 7348 - Virtual eXtensible Local Area Network (VXLAN):
# A Framework for Overlaying Virtualized Layer 2 Networks over Layer 3 Networks
# http://tools.ietf.org/html/rfc7348
# https://www.ietf.org/id/draft-ietf-nvo3-vxlan-gpe-02.txt
#
# VXLAN Group Policy Option:
# http://tools.ietf.org/html/draft-smith-vxlan-group-policy-00

from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.fields import FlagsField, XByteField, ThreeBytesField, \
    ConditionalField, ShortField, ByteEnumField, X3BytesField

_GP_FLAGS = ["R", "R", "R", "A", "R", "R", "D", "R"]


class VXLAN(Packet):
    name = "VXLAN"

    fields_desc = [
        FlagsField("flags", 0x8, 8,
                   ['OAM', 'R', 'NextProtocol', 'Instance',
                    'V1', 'V2', 'R', 'G']),
        ConditionalField(
            ShortField("reserved0", 0),
            lambda pkt: pkt.flags & 0x04,
        ),
        ConditionalField(
            ByteEnumField('NextProtocol', 0,
                          {0: 'NotDefined',
                           1: 'IPv4',
                           2: 'IPv6',
                           3: 'Ethernet',
                           4: 'NSH'}),
            lambda pkt: pkt.flags & 0x04,
        ),
        ConditionalField(
            ThreeBytesField("reserved1", 0x000000),
            lambda pkt: (not pkt.flags & 0x80) and (not pkt.flags & 0x04),
        ),
        ConditionalField(
            FlagsField("gpflags", 0x0, 8, _GP_FLAGS),
            lambda pkt: pkt.flags & 0x80,
        ),
        ConditionalField(
            ShortField("gpid", 0),
            lambda pkt: pkt.flags & 0x80,
        ),
        X3BytesField("vni", 0),
        XByteField("reserved2", 0x00),
    ]

    # Use default linux implementation port
    overload_fields = {
        UDP: {'dport': 8472},
    }

    def mysummary(self):
        if self.flags & 0x80:
            return self.sprintf("VXLAN (vni=%VXLAN.vni% gpid=%VXLAN.gpid%)")
        else:
            return self.sprintf("VXLAN (vni=%VXLAN.vni%)")

bind_layers(UDP, VXLAN, dport=4789)  # RFC standard vxlan port
bind_layers(UDP, VXLAN, dport=4790)  # RFC standard vxlan-gpe port
bind_layers(UDP, VXLAN, dport=6633)  # New IANA assigned port for use with NSH
bind_layers(UDP, VXLAN, dport=8472)  # Linux implementation port
bind_layers(VXLAN, Ether, {'flags': 0x8})
bind_layers(VXLAN, Ether, {'flags': 0x88})
bind_layers(VXLAN, Ether, {'flags': 0xC, 'NextProtocol': 0}, NextProtocol=0)
bind_layers(VXLAN, IP, {'flags': 0xC, 'NextProtocol': 1}, NextProtocol=1)
bind_layers(VXLAN, IPv6, {'flags': 0xC, 'NextProtocol': 2}, NextProtocol=2)
bind_layers(VXLAN, Ether, {'flags': 0xC, 'NextProtocol': 3}, NextProtocol=3)
