## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from scapy.fields import *
from scapy.packet import *

# Cisco Netflow Protocol version 1
class NetflowHeader(Packet):
    name = "Netflow Header"
    fields_desc = [ ShortField("version", 1) ]
    
class NetflowHeaderV1(Packet):
    name = "Netflow Header V1"
    fields_desc = [ ShortField("count", 0),
                    IntField("sysUptime", 0),
                    IntField("unixSecs", 0),
                    IntField("unixNanoSeconds", 0) ]


class NetflowRecordV1(Packet):
    name = "Netflow Record"
    fields_desc = [ IPField("ipsrc", "0.0.0.0"),
                    IPField("ipdst", "0.0.0.0"),
                    IPField("nexthop", "0.0.0.0"),
                    ShortField("inputIfIndex", 0),
                    ShortField("outpuIfIndex", 0),
                    IntField("dpkts", 0),
                    IntField("dbytes", 0),
                    IntField("starttime", 0),
                    IntField("endtime", 0),
                    ShortField("srcport", 0),
                    ShortField("dstport", 0),
                    ShortField("padding", 0),
                    ByteField("proto", 0),
                    ByteField("tos", 0),
                    IntField("padding1", 0),
                    IntField("padding2", 0) ]


bind_layers( NetflowHeader,   NetflowHeaderV1, version=1)
bind_layers( NetflowHeaderV1, NetflowRecordV1, )
