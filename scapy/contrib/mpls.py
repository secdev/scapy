# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Multiprotocol Label Switching (MPLS)
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers, Padding
from scapy.fields import (
    BitField,
    ByteField,
    ByteEnumField,
    PacketListField,
    ShortField,
)

from scapy.layers.inet import (
    _ICMP_classnums,
    ICMPExtension_Object,
    IP,
    UDP,
)
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE

from scapy.contrib.bier import BIER


class EoMCW(Packet):
    name = "EoMCW"
    fields_desc = [BitField("zero", 0, 4),
                   BitField("reserved", 0, 12),
                   ShortField("seq", 0)]

    def guess_payload_class(self, payload):
        if len(payload) >= 1:
            return Ether
        return Padding


class MPLS(Packet):
    name = "MPLS"
    fields_desc = [BitField("label", 3, 20),
                   BitField("cos", 0, 3),
                   BitField("s", 1, 1),
                   ByteField("ttl", 0)]

    def guess_payload_class(self, payload):
        if len(payload) >= 1:
            if not self.s:
                return MPLS
            ip_version = (payload[0] >> 4) & 0xF
            if ip_version == 4:
                return IP
            elif ip_version == 5:
                return BIER
            elif ip_version == 6:
                return IPv6
            else:
                if payload[0] == 0 and payload[1] == 0:
                    return EoMCW
                else:
                    return Ether
        return Padding


# ICMP Extension

class ICMPExtension_MPLS(ICMPExtension_Object):
    name = "ICMP Extension Object - MPLS (RFC4950)"

    fields_desc = [
        ShortField("len", None),
        ByteEnumField("classnum", 1, _ICMP_classnums),
        ByteField("classtype", 1),
        PacketListField("stack", [], MPLS, length_from=lambda pkt: pkt.len - 4),
    ]


# Bindings

bind_layers(Ether, MPLS, type=0x8847)
bind_layers(IP, MPLS, proto=137)
bind_layers(IPv6, MPLS, nh=137)
bind_layers(UDP, MPLS, dport=6635)
bind_layers(GRE, MPLS, proto=0x8847)
bind_layers(MPLS, MPLS, s=0)
bind_layers(MPLS, IP, label=0)  # IPv4 Explicit NULL
bind_layers(MPLS, IPv6, label=2)  # IPv6 Explicit NULL
bind_layers(MPLS, EoMCW)
bind_layers(EoMCW, Ether, zero=0, reserved=0)
