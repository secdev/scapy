#! /usr/bin/env python
# scapy.contrib.description = nsh
# scapy.contrib.status = loads
from scapy.all import bind_layers
from scapy.fields import BitField, ByteField, ByteEnumField
from scapy.fields import ShortField, X3BytesField, XIntField
from scapy.fields import ConditionalField, PacketListField
from scapy.layers.inet import Ether, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.vxlan import VXLAN
from scapy.packet import Packet

from scapy.contrib.mpls import MPLS

#
# NSH Support
# https://www.ietf.org/id/draft-ietf-sfc-nsh-05.txt
#


class Metadata(Packet):
    name = 'NSH metadata'
    fields_desc = [XIntField('value', 0)]


class NSHTLV(Packet):
    "NSH MD-type 2 - Variable Length Context Headers"
    name = "NSHTLV"
    fields_desc = [
        ShortField('Class', 0),
        BitField('Critical', 0, 1),
        BitField('Type', 0, 7),
        BitField('Reserved', 0, 3),
        BitField('Len', 0, 5),
        PacketListField('Metadata', None, XIntField, count_from='Len')
    ]


class NSH(Packet):
    """Network Service Header.
       NSH MD-type 1 if there is no ContextHeaders"""
    name = "NSH"

    fields_desc = [
        BitField('Ver', 0, 2),
        BitField('OAM', 0, 1),
        BitField('Critical', 0, 1),
        BitField('Reserved', 0, 6),
        BitField('Len', 0, 6),
        ByteEnumField('MDType', 1, {1: 'Fixed Length',
                                    2: 'Variable Length'}),
        ByteEnumField('NextProto', 3, {1: 'IPv4',
                                       2: 'IPv6',
                                       3: 'Ethernet',
                                       4: 'NSH',
                                       5: 'MPLS'}),
        X3BytesField('NSP', 0),
        ByteField('NSI', 1),
        ConditionalField(XIntField('NPC', 0), lambda pkt: pkt.MDType == 1),
        ConditionalField(XIntField('NSC', 0), lambda pkt: pkt.MDType == 1),
        ConditionalField(XIntField('SPC', 0), lambda pkt: pkt.MDType == 1),
        ConditionalField(XIntField('SSC', 0), lambda pkt: pkt.MDType == 1),
        ConditionalField(PacketListField("ContextHeaders", None,
                                         NSHTLV, count_from="Length"),
                         lambda pkt: pkt.MDType == 2)
        ]

    def mysummary(self):
        return self.sprintf("NSP: %NSP% - NSI: %NSI%")


bind_layers(Ether, NSH, {'type': 0x894F}, type=0x894F)
bind_layers(VXLAN, NSH, {'flags': 0xC, 'NextProtocol': 4}, NextProtocol=4)

bind_layers(NSH, IP, {'NextProto': 1}, NextProto=1)
bind_layers(NSH, IPv6, {'NextProto': 2}, NextProto=2)
bind_layers(NSH, Ether, {'NextProto': 3}, NextProto=3)
bind_layers(NSH, NSH, {'NextProto': 4}, NextProto=4)
bind_layers(NSH, MPLS, {'NextProto': 5}, NextProto=5)
