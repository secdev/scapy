#!/usr/bin/env python

# http://trac.secdev.org/scapy/ticket/301

# scapy.contrib.description = RIPng
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP
from scapy.layers.inet6 import *

class RIPng(Packet):
    name = "RIPng header"
    fields_desc = [
                    ByteEnumField("cmd", 1, {1 : "req", 2 : "resp"}),
                    ByteField("ver", 1),
                    ShortField("null", 0),
            ]

class RIPngEntry(Packet):
    name = "RIPng entry"
    fields_desc = [
                    ConditionalField(IP6Field("prefix", "::"),
                                            lambda pkt: pkt.metric != 255),
                    ConditionalField(IP6Field("nexthop", "::"),
                                            lambda pkt: pkt.metric == 255),
                    ShortField("routetag", 0),
                    ByteField("prefixlen", 0),
                    ByteEnumField("metric", 1, {16 : "Unreach",
                                                255 : "next-hop entry"})
            ]

bind_layers(UDP,        RIPng,          sport=521, dport=521)
bind_layers(RIPng,      RIPngEntry)
bind_layers(RIPngEntry, RIPngEntry)

if __name__ == "__main__":
    from scapy.main import interact
    interact(mydict=globals(), mybanner="RIPng")

