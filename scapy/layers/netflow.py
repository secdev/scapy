## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license
## Netflow V5 appended by spaceB0x and Guillaume Valadon

"""
Cisco NetFlow protocol v1 and v5
"""


from scapy.fields import *
from scapy.packet import *
from scapy.data import IP_PROTOS


class NetflowHeader(Packet):
    name = "Netflow Header"
    fields_desc = [ ShortField("version", 1) ]


###########################################
### Netflow Version 1
###########################################


class NetflowHeaderV1(Packet):
    name = "Netflow Header v1"
    fields_desc = [ ShortField("count", 0),
                    IntField("sysUptime", 0),
                    IntField("unixSecs", 0),
                    IntField("unixNanoSeconds", 0) ]


class NetflowRecordV1(Packet):
    name = "Netflow Record v1"
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
bind_layers( NetflowHeaderV1, NetflowRecordV1 )
bind_layers( NetflowRecordV1, NetflowRecordV1 )


#########################################
### Netflow Version 5
#########################################


class NetflowHeaderV5(Packet):
    name = "Netflow Header v5"
    fields_desc = [ ShortField("count", 0),
                    IntField("sysUptime", 0),
                    IntField("unixSecs", 0),
                    IntField("unixNanoSeconds", 0),
                    IntField("flowSequence",0),
                    ByteField("engineType", 0),
                    ByteField("engineID", 0),
                    ShortField("samplingInterval", 0) ]


class NetflowRecordV5(Packet):
    name = "Netflow Record v5"
    fields_desc = [ IPField("src", "127.0.0.1"),
                    IPField("dst", "127.0.0.1"),
                    IPField("nexthop", "0.0.0.0"),
                    ShortField("input", 0),
                    ShortField("output", 0),
                    IntField("dpkts", 1),
                    IntField("dOctets", 60),
                    IntField("first", 0),
                    IntField("last", 0),
                    ShortField("srcport", 0),
                    ShortField("dstport", 0),
                    ByteField("pad1", 0),
                    FlagsField("tcpFlags", 0x2, 8, "FSRPAUEC"),
                    ByteEnumField("prot", IP_PROTOS["tcp"], IP_PROTOS),
                    ByteField("tos",0),
                    ShortField("src_as", 0),
                    ShortField("dst_as", 0),
                    ByteField("src_mask", 0),
                    ByteField("dst_mask", 0),
                    ShortField("pad2", 0)]


bind_layers( NetflowHeader,   NetflowHeaderV5, version=5)
bind_layers( NetflowHeaderV5, NetflowRecordV5 )
bind_layers( NetflowRecordV5, NetflowRecordV5 )
