# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Bit Index Explicit Replication (BIER)
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import BitEnumField, BitField, BitFieldLenField, ByteField, \
    ShortField, StrLenField
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6


class BIERLength:
    BIER_LEN_64 = 0
    BIER_LEN_128 = 1
    BIER_LEN_256 = 2
    BIER_LEN_512 = 3
    BIER_LEN_1024 = 4


BIERnhcls = {1: "MPLS",
             2: "MPLS",
             4: "IPv4",
             5: "IPv6"}


class BIFT(Packet):
    name = "BIFT"
    fields_desc = [BitField("bsl", BIERLength.BIER_LEN_256, 4),
                   BitField("sd", 0, 8),
                   BitField("set", 0, 8),
                   BitField("cos", 0, 3),
                   BitField("s", 1, 1),
                   ByteField("ttl", 0)]


class BIER(Packet):
    name = "BIER"
    fields_desc = [BitField("id", 5, 4),
                   BitField("version", 0, 4),
                   BitFieldLenField("length", BIERLength.BIER_LEN_256, 4,
                                    length_of=lambda x:(x.BitString >> 8)),
                   BitField("entropy", 0, 20),
                   BitField("OAM", 0, 2),
                   BitField("RSV", 0, 2),
                   BitField("DSCP", 0, 6),
                   BitEnumField("Proto", 2, 6, BIERnhcls),
                   ShortField("BFRID", 0),
                   StrLenField("BitString",
                               "",
                               length_from=lambda x:(8 << x.length))]


bind_layers(BIER, IP, Proto=4)
bind_layers(BIER, IPv6, Proto=5)
bind_layers(UDP, BIFT, dport=8138)
bind_layers(BIFT, BIER)
