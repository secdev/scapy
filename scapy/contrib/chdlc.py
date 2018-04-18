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

# scapy.contrib.description = Cisco HDLC and SLARP
# scapy.contrib.status = loads

# This layer is based on information from http://www.nethelp.no/net/cisco-hdlc.txt

from scapy.data import DLT_C_HDLC
from scapy.packet import *
from scapy.fields import *
from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *


class CHDLC(Packet):
    name = "Cisco HDLC"
    fields_desc = [ByteEnumField("address", 0x0f, {0x0f: "unicast", 0x8f: "multicast"}),
                   ByteField("control", 0),
                   XShortField("proto", 0x0800)]


class SLARP(Packet):
    name = "SLARP"
    fields_desc = [IntEnumField("type", 2, {0: "request", 1: "reply", 2: "line keepalive"}),
                   ConditionalField(IPField("address", "192.168.0.1"),
                                    lambda pkt: pkt.type == 0 or pkt.type == 1),
                   ConditionalField(IPField("mask", "255.255.255.0"),
                                    lambda pkt: pkt.type == 0 or pkt.type == 1),
                   ConditionalField(XShortField("unused", 0),
                                    lambda pkt: pkt.type == 0 or pkt.type == 1),
                   ConditionalField(IntField("mysequence", 0),
                                    lambda pkt: pkt.type == 2),
                   ConditionalField(IntField("yoursequence", 0),
                                    lambda pkt: pkt.type == 2),
                   ConditionalField(XShortField("reliability", 0xffff),
                                    lambda pkt: pkt.type == 2)]


bind_layers(CHDLC, Dot3, proto=0x6558)
bind_layers(CHDLC, IP, proto=0x800)
bind_layers(CHDLC, IPv6, proto=0x86dd)
bind_layers(CHDLC, SLARP, proto=0x8035)
bind_layers(CHDLC, STP, proto=0x4242)

conf.l2types.register(DLT_C_HDLC, CHDLC)
