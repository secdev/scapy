# Copyright (C) 2018 Hao Zheng <haozheng10@gmail.com>

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

# scapy.contrib.description = Generic Network Virtualization Encapsulation (GENEVE)
# scapy.contrib.status = loads

"""
Geneve: Generic Network Virtualization Encapsulation

draft-ietf-nvo3-geneve-06
"""

from scapy.fields import BitField, XByteField, XShortEnumField, X3BytesField, \
    XStrField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ETHER_TYPES
from scapy.compat import chb, orb
from scapy.error import warning


class GENEVEOptionsField(XStrField):
    islist = 1

    def getfield(self, pkt, s):
        opln = pkt.optionlen * 4
        if opln < 0:
            warning("bad optionlen (%i). Assuming optionlen=0", pkt.optionlen)
            opln = 0
        return s[opln:], self.m2i(pkt, s[:opln])


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
                   GENEVEOptionsField("options", "")]

    def post_build(self, p, pay):
        p += pay
        optionlen = self.optionlen
        if optionlen is None:
            optionlen = (len(self.options) + 3) // 4
            p = chb(optionlen & 0x2f | orb(p[0]) & 0xc0) + p[1:]
        return p

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
