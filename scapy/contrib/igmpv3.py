#! /usr/bin/env python

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

# scapy.contrib.description = Internet Group Management Protocol v3 (IGMPv3)
# scapy.contrib.status = loads

from __future__ import print_function
from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteEnumField, ByteField, FieldLenField, \
    FieldListField, IPField, PacketListField, ShortField, XShortField
from scapy.compat import orb
from scapy.layers.inet import IP
from scapy.contrib.igmp import IGMP
from scapy.config import conf

""" Based on the following references
 http://www.iana.org/assignments/igmp-type-numbers
 http://www.rfc-editor.org/rfc/pdfrfc/rfc3376.txt.pdf

"""

# See RFC3376, Section 4. Message Formats for definitions of proper IGMPv3 message format  # noqa: E501
#   http://www.faqs.org/rfcs/rfc3376.html
#
# See RFC4286, For definitions of proper messages for Multicast Router Discovery.  # noqa: E501
#   http://www.faqs.org/rfcs/rfc4286.html
#


class IGMPv3(IGMP):
    """IGMP Message Class for v3.

    This class is derived from class Packet.
    The fields defined below are a
    direct interpretation of the v3 Membership Query Message.
    Fields 'type'  through 'qqic' are directly assignable.
    For 'numsrc', do not assign a value.
    Instead add to the 'srcaddrs' list to auto-set 'numsrc'. To
    assign values to 'srcaddrs', use the following methods:
      c = IGMPv3()
      c.srcaddrs = ['1.2.3.4', '5.6.7.8']
      c.srcaddrs += ['192.168.10.24']
    At this point, 'c.numsrc' is three (3)

    'chksum' is automagically calculated before the packet is sent.

    'mrcode' is also the Advertisement Interval field

    """
    name = "IGMPv3"
    igmpv3types = {0x11: "Membership Query",
                   0x22: "Version 3 Membership Report",
                   0x30: "Multicast Router Advertisement",
                   0x31: "Multicast Router Solicitation",
                   0x32: "Multicast Router Termination"}

    fields_desc = [ByteEnumField("type", 0x11, igmpv3types),
                   ByteField("mrcode", 20),
                   XShortField("chksum", None)]

    def encode_maxrespcode(self):
        """Encode and replace the mrcode value to its IGMPv3 encoded time value if needed,  # noqa: E501
        as specified in rfc3376#section-4.1.1.

        If value < 128, return the value specified. If >= 128, encode as a floating  # noqa: E501
        point value. Value can be 0 - 31744.
        """
        value = self.mrcode
        if value < 128:
            code = value
        elif value > 31743:
            code = 255
        else:
            exp = 0
            value >>= 3
            while(value > 31):
                exp += 1
                value >>= 1
            exp <<= 4
            code = 0x80 | exp | (value & 0x0F)
        self.mrcode = code

    def mysummary(self):
        """Display a summary of the IGMPv3 object."""
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("IGMPv3: %IP.src% > %IP.dst% %IGMPv3.type%")  # noqa: E501
        else:
            return self.sprintf("IGMPv3 %IGMPv3.type%")

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 4:
            if orb(_pkt[0]) in [0x12, 0x16, 0x17]:
                return IGMP
            elif orb(_pkt[0]) == 0x11 and len(_pkt) < 12:
                return IGMP
        return IGMPv3


class IGMPv3mq(Packet):
    """IGMPv3 Membership Query.
    Payload of IGMPv3 when type=0x11"""
    name = "IGMPv3mq"
    fields_desc = [IPField("gaddr", "0.0.0.0"),
                   BitField("resv", 0, 4),
                   BitField("s", 0, 1),
                   BitField("qrv", 0, 3),
                   ByteField("qqic", 0),
                   FieldLenField("numsrc", None, count_of="srcaddrs"),
                   FieldListField("srcaddrs", None, IPField("sa", "0.0.0.0"), count_from=lambda x: x.numsrc)]  # noqa: E501


class IGMPv3gr(Packet):
    """IGMP Group Record for IGMPv3 Membership Report

    This class is derived from class Packet and should be added in the records
    of an instantiation of class IGMPv3mr.
    """
    name = "IGMPv3gr"
    igmpv3grtypes = {1: "Mode Is Include",
                     2: "Mode Is Exclude",
                     3: "Change To Include Mode",
                     4: "Change To Exclude Mode",
                     5: "Allow New Sources",
                     6: "Block Old Sources"}

    fields_desc = [ByteEnumField("rtype", 1, igmpv3grtypes),
                   ByteField("auxdlen", 0),
                   FieldLenField("numsrc", None, count_of="srcaddrs"),
                   IPField("maddr", "0.0.0.0"),
                   FieldListField("srcaddrs", [], IPField("sa", "0.0.0.0"), count_from=lambda x: x.numsrc)]  # noqa: E501

    def mysummary(self):
        """Display a summary of the IGMPv3 group record."""
        return self.sprintf("IGMPv3 Group Record %IGMPv3gr.type% %IGMPv3gr.maddr%")  # noqa: E501

    def default_payload_class(self, payload):
        return conf.padding_layer


class IGMPv3mr(Packet):
    """IGMP Membership Report extension for IGMPv3.
    Payload of IGMPv3 when type=0x22"""
    name = "IGMPv3mr"
    fields_desc = [XShortField("res2", 0),
                   FieldLenField("numgrp", None, count_of="records"),
                   PacketListField("records", [], IGMPv3gr, count_from=lambda x: x.numgrp)]  # noqa: E501


class IGMPv3mra(Packet):
    """IGMP Multicas Router Advertisement extension for IGMPv3.
    Payload of IGMPv3 when type=0x30"""
    name = "IGMPv3mra"
    fields_desc = [ShortField("qryIntvl", 0),
                   ShortField("robust", 0)]


bind_layers(IP, IGMPv3, frag=0,
            proto=2,
            ttl=1,
            tos=0xc0,
            dst='224.0.0.22')

bind_layers(IGMPv3, IGMPv3mq, type=0x11)
bind_layers(IGMPv3, IGMPv3mr, type=0x22, mrcode=0x0)
bind_layers(IGMPv3, IGMPv3mra, type=0x30)
