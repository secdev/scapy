# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Cisco HDLC and SLARP
# scapy.contrib.status = loads

# This layer is based on information from http://www.nethelp.no/net/cisco-hdlc.txt  # noqa: E501

from scapy.data import DLT_C_HDLC
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, ConditionalField, \
    IntEnumField, IntField, IPField, XShortField
from scapy.layers.l2 import Dot3, STP
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.config import conf


class CHDLC(Packet):
    name = "Cisco HDLC"
    fields_desc = [ByteEnumField("address", 0x0f, {0x0f: "unicast", 0x8f: "multicast"}),  # noqa: E501
                   ByteField("control", 0),
                   XShortField("proto", 0x0800)]


class SLARP(Packet):
    name = "SLARP"
    fields_desc = [IntEnumField("type", 2, {0: "request", 1: "reply", 2: "line keepalive"}),  # noqa: E501
                   ConditionalField(IPField("address", "192.168.0.1"),
                                    lambda pkt: pkt.type == 0 or pkt.type == 1),  # noqa: E501
                   ConditionalField(IPField("mask", "255.255.255.0"),
                                    lambda pkt: pkt.type == 0 or pkt.type == 1),  # noqa: E501
                   ConditionalField(XShortField("unused", 0),
                                    lambda pkt: pkt.type == 0 or pkt.type == 1),  # noqa: E501
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
