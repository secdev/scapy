# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2018 Hao Zheng <haozheng10@gmail.com>

# scapy.contrib.description = Generic Network Virtualization Encapsulation (GENEVE)
# scapy.contrib.status = loads

"""
Geneve: Generic Network Virtualization Encapsulation

https://datatracker.ietf.org/doc/html/rfc8926
"""

import struct

from scapy.fields import BitField, XByteField, XShortEnumField, X3BytesField, StrLenField, PacketListField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ETHER_TYPES

CLASS_IDS = {0x0100: "Linux",
             0x0101: "Open vSwitch",
             0x0102: "Open Virtual Networking (OVN)",
             0x0103: "In-band Network Telemetry (INT)",
             0x0104: "VMware",
             0x0105: "Amazon.com, Inc.",
             0x0106: "Cisco Systems, Inc.",
             0x0107: "Oracle Corporation",
             0x0110: "Amazon.com, Inc.",
             0x0118: "IBM",
             0x0128: "Ericsson",
             0xFEFF: "Unassigned",
             0xFFFF: "Experimental"}


class GeneveOptions(Packet):
    name = "Geneve Options"
    fields_desc = [XShortEnumField("classid", 0x0000, CLASS_IDS),
                   XByteField("type", 0x00),
                   BitField("reserved", 0, 3),
                   BitField("length", None, 5),
                   StrLenField('data', '', length_from=lambda x: x.length * 4)]

    def extract_padding(self, s):
        return "", s

    def post_build(self, p, pay):
        if self.length is None:
            tmp_len = len(self.data) // 4
            p = p[:3] + struct.pack("!B", (p[3] & 0x3) | (tmp_len & 0x1f)) + p[4:]
        return p + pay


class GENEVE(Packet):
    name = "GENEVE"
    fields_desc = [BitField("version", 0, 2),
                   BitField("optionlen", None, 6),
                   BitField("oam", 0, 1),
                   BitField("critical", 0, 1),
                   BitField("reserved", 0, 6),
                   XShortEnumField("proto", 0x0000, ETHER_TYPES),
                   X3BytesField("vni", 0),
                   XByteField("reserved2", 0x00),
                   PacketListField("options", [], GeneveOptions,
                                   length_from=lambda pkt: pkt.optionlen * 4)]

    def post_build(self, p, pay):
        if self.optionlen is None:
            tmp_len = (len(p) - 8) // 4
            p = struct.pack("!B", (p[0] & 0xc0) | (tmp_len & 0x3f)) + p[1:]
        return p + pay

    def answers(self, other):
        if isinstance(other, GENEVE):
            if ((self.proto == other.proto) and (self.vni == other.vni)):
                return self.payload.answers(other.payload)
        else:
            return self.payload.answers(other)
        return 0

    def mysummary(self):
        return self.sprintf("GENEVE (vni=%GENEVE.vni%,"
                            "optionlen=%GENEVE.optionlen%,"
                            "proto=%GENEVE.proto%)")


bind_layers(UDP, GENEVE, dport=6081)
bind_layers(GENEVE, Ether, proto=0x6558)
bind_layers(GENEVE, IP, proto=0x0800)
bind_layers(GENEVE, IPv6, proto=0x86dd)
