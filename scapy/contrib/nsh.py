# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# scapy.contrib.description = Network Services Headers (NSH)
# scapy.contrib.status = loads

from scapy.all import bind_layers
from scapy.fields import BitField, ByteField, ByteEnumField, BitEnumField
from scapy.fields import ShortField, X3BytesField, XIntField
from scapy.fields import ConditionalField, PacketListField, BitFieldLenField
from scapy.layers.inet import Ether, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.vxlan import VXLAN
from scapy.packet import Packet
from scapy.layers.l2 import GRE

from scapy.contrib.mpls import MPLS

#
# NSH Support
# https://www.rfc-editor.org/rfc/rfc8300.txt  January 2018
#

class NSHTLV(Packet):
    "NSH MD-type 2 - Variable Length Context Headers"
    name = "NSHTLV"
    fields_desc = [
        ShortField('Class', 0),
        BitField('Type', 0, 8),
        BitField('Reserved', 0, 1),
        BitField('Len', 0, 7),
        PacketListField('Metadata', None, XIntField, count_from='len')
    ]


class NSH(Packet):
    """Network Service Header.
       NSH MD-type 1 if there is no ContextHeaders"""
    name = "NSH"

    fields_desc = [
        BitField('Ver', 0, 2),
        BitField('OAM', 0, 1),
        BitField('Unused1', 0, 1),
        BitField('TTL', 63, 6),
        BitFieldLenField('Length', None, 6,
                         count_of='ContextHeaders',
                         adjust=lambda pkt, x: 6 if pkt.MDType == 1 else x + 2),  # noqa: E501
        BitField('Unused2', 0, 1),
        BitField('Unused3', 0, 1),
        BitField('Unused4', 0, 1),
        BitField('Unused5', 0, 1),
        BitEnumField('MDType', 1, {0: 'Reserved MDType',
                                    1: 'Fixed Length',
                                    2: 'Variable Length',
                                    0xF: 'Experimental MDType'}),
        ByteEnumField('NextProto', 3, {1: 'IPv4',
                                       2: 'IPv6',
                                       3: 'Ethernet',
                                       4: 'NSH',
                                       5: 'MPLS',
                                       0xFE: 'Experiment 1',
                                       0xFF: 'Experiment 2'}),
        X3BytesField('SPI', 0),
        ByteField('SI', 0xFF),
        ConditionalField(XIntField('CH1', 0), lambda pkt: pkt.MDType == 1),
        ConditionalField(XIntField('CH2', 0), lambda pkt: pkt.MDType == 1),
        ConditionalField(XIntField('CH3', 0), lambda pkt: pkt.MDType == 1),
        ConditionalField(XIntField('CH4', 0), lambda pkt: pkt.MDType == 1),
        ConditionalField(PacketListField("Conditional CH", None, NSHTLV, count_from="Length"),
                         lambda pkt: pkt.MDType == 2)
    ]

    def mysummary(self):
        return self.sprintf("SPI: %SPI% - SI: %SI%")


bind_layers(Ether, NSH, {'type': 0x894F}, type=0x894F)
bind_layers(VXLAN, NSH, {'flags': 0xC, 'NextProtocol': 4}, NextProtocol=4)
bind_layers(GRE, NSH, {'proto': 0x894F}, proto=0x894F)

bind_layers(NSH, IP, {'NextProto': 1}, NextProto=1)
bind_layers(NSH, IPv6, {'NextProto': 2}, NextProto=2)
bind_layers(NSH, Ether, {'NextProto': 3}, NextProto=3)
bind_layers(NSH, NSH, {'NextProto': 4}, NextProto=4)
bind_layers(NSH, MPLS, {'NextProto': 5}, NextProto=5)
