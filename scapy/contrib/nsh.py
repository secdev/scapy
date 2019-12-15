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
from scapy.fields import BitField, ByteField, ByteEnumField, BitEnumField, \
    ShortField, X3BytesField, XIntField, XStrFixedLenField, \
    ConditionalField, PacketListField, BitFieldLenField
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
        ShortField('class', 0),
        BitField('type', 0, 8),
        BitField('reserved', 0, 1),
        BitField('length', 0, 7),
        PacketListField('metadata', None, XIntField, count_from='length')
    ]


class NSH(Packet):
    """Network Service Header.
       NSH MD-type 1 if there is no ContextHeaders"""
    name = "NSH"

    fields_desc = [
        BitField('ver', 0, 2),
        BitField('oam', 0, 1),
        BitField('unused1', 0, 1),
        BitField('ttl', 63, 6),
        BitFieldLenField('length', None, 6,
                         count_of='vlch',
                         adjust=lambda pkt, x: 6 if pkt.mdtype == 1
                         else x + 2),
        BitField('unused2', 0, 4),
        BitEnumField('mdtype', 1, 4, {0: 'Reserved MDType',
                                      1: 'Fixed Length',
                                      2: 'Variable Length',
                                      0xF: 'Experimental MDType'}),
        ByteEnumField('nextproto', 3, {1: 'IPv4',
                                       2: 'IPv6',
                                       3: 'Ethernet',
                                       4: 'NSH',
                                       5: 'MPLS',
                                       0xFE: 'Experiment 1',
                                       0xFF: 'Experiment 2'}),
        X3BytesField('spi', 0),
        ByteField('si', 0xFF),
        ConditionalField(XStrFixedLenField("context_header", "", 16),
                         lambda pkt: pkt.mdtype == 1),
        ConditionalField(PacketListField("vlch", None, NSHTLV,
                                         count_from="length"),
                         lambda pkt: pkt.mdtype == 2)
    ]

    def mysummary(self):
        return self.sprintf("SPI: %spi% - SI: %si%")


bind_layers(Ether, NSH, {'type': 0x894F}, type=0x894F)
bind_layers(VXLAN, NSH, {'flags': 0xC, 'nextprotocol': 4}, nextprotocol=4)
bind_layers(GRE, NSH, {'proto': 0x894F}, proto=0x894F)

bind_layers(NSH, IP, {'nextprotocol': 1}, nextprotocol=1)
bind_layers(NSH, IPv6, {'nextprotocol': 2}, nextprotocol=2)
bind_layers(NSH, Ether, {'nextprotocol': 3}, nextprotocol=3)
bind_layers(NSH, NSH, {'nextprotocol': 4}, nextprotocol=4)
bind_layers(NSH, MPLS, {'nextprotocol': 5}, nextprotocol=5)
