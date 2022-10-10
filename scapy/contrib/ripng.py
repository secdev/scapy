# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Routing Information Protocol next gen (RIPng)
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, IP6Field, ShortField
from scapy.layers.inet import UDP


class RIPng(Packet):
    name = "RIPng header"
    fields_desc = [
        ByteEnumField("cmd", 1, {1: "req", 2: "resp"}),
        ByteField("ver", 1),
        ShortField("null", 0)
    ]


class RIPngEntry(Packet):
    name = "RIPng entry"
    fields_desc = [
        IP6Field("prefix_or_nh", "::"),
        ShortField("routetag", 0),
        ByteField("prefixlen", 0),
        ByteEnumField("metric", 1, {16: "Unreach",
                                    255: "next-hop entry"})
    ]


bind_layers(UDP, RIPng, sport=521, dport=521)
bind_layers(RIPng, RIPngEntry)
bind_layers(RIPngEntry, RIPngEntry)
