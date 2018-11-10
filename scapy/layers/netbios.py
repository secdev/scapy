# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
NetBIOS over TCP/IP

[RFC 1001/1002]
"""

import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    IPField, IntField, NetBIOSNameField, ShortEnumField, ShortField, \
    StrFixedLenField, XShortField
from scapy.layers.inet import UDP, TCP
from scapy.layers.l2 import SourceMACField


class NetBIOS_DS(Packet):
    name = "NetBIOS datagram service"
    fields_desc = [
        ByteEnumField("type", 17, {17: "direct_group"}),
        ByteField("flags", 0),
        XShortField("id", 0),
        IPField("src", "127.0.0.1"),
        ShortField("sport", 138),
        ShortField("len", None),
        ShortField("ofs", 0),
        NetBIOSNameField("srcname", ""),
        NetBIOSNameField("dstname", ""),
    ]

    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            tmp_len = len(p) - 14
            p = p[:10] + struct.pack("!H", tmp_len) + p[12:]
        return p

#        ShortField("length",0),
#        ShortField("Delimitor",0),
#        ByteField("command",0),
#        ByteField("data1",0),
#        ShortField("data2",0),
#        ShortField("XMIt",0),
#        ShortField("RSPCor",0),
#        StrFixedLenField("dest","",16),
#        StrFixedLenField("source","",16),
#
#        ]
#

# NetBIOS


_NETBIOS_SUFFIXES = {
    0x4141: "workstation",
    0x4141 + 0x03: "messenger service",
    0x4141 + 0x200: "file server service",
    0x4141 + 0x10b: "domain master browser",
    0x4141 + 0x10c: "domain controller",
    0x4141 + 0x10e: "browser election service"
}

_NETBIOS_QRTYPES = {
    0x20: "NB",
    0x21: "NBSTAT"
}

_NETBIOS_QRCLASS = {
    1: "INTERNET"
}

_NETBIOS_RNAMES = {
    0xC00C: "Label String Pointer to QUESTION_NAME"
}

_NETBIOS_OWNER_MODE_TYPES = {
    0: "B node",
    1: "P node",
    2: "M node",
    3: "H node"
}

_NETBIOS_GNAMES = {
    0: "Unique name",
    1: "Group name"
}

# Name Query Request
# Node Status Request


class NBNSQueryRequest(Packet):
    name = "NBNS query request"
    fields_desc = [ShortField("NAME_TRN_ID", 0),
                   ShortField("FLAGS", 0x0110),
                   ShortField("QDCOUNT", 1),
                   ShortField("ANCOUNT", 0),
                   ShortField("NSCOUNT", 0),
                   ShortField("ARCOUNT", 0),
                   NetBIOSNameField("QUESTION_NAME", "windows"),
                   ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0),
                   ShortEnumField("QUESTION_TYPE", 0x20, _NETBIOS_QRTYPES),
                   ShortEnumField("QUESTION_CLASS", 1, _NETBIOS_QRCLASS)]

# Name Registration Request
# Name Refresh Request
# Name Release Request or Demand


class NBNSRequest(Packet):
    name = "NBNS request"
    fields_desc = [ShortField("NAME_TRN_ID", 0),
                   ShortField("FLAGS", 0x2910),
                   ShortField("QDCOUNT", 1),
                   ShortField("ANCOUNT", 0),
                   ShortField("NSCOUNT", 0),
                   ShortField("ARCOUNT", 1),
                   NetBIOSNameField("QUESTION_NAME", "windows"),
                   ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0),
                   ShortEnumField("QUESTION_TYPE", 0x20, _NETBIOS_QRTYPES),
                   ShortEnumField("QUESTION_CLASS", 1, _NETBIOS_QRCLASS),
                   ShortEnumField("RR_NAME", 0xC00C, _NETBIOS_RNAMES),
                   ShortEnumField("RR_TYPE", 0x20, _NETBIOS_QRTYPES),
                   ShortEnumField("RR_CLASS", 1, _NETBIOS_QRCLASS),
                   IntField("TTL", 0),
                   ShortField("RDLENGTH", 6),
                   BitEnumField("G", 0, 1, _NETBIOS_GNAMES),
                   BitEnumField("OWNER_NODE_TYPE", 00, 2,
                                _NETBIOS_OWNER_MODE_TYPES),
                   BitEnumField("UNUSED", 0, 13, {0: "Unused"}),
                   IPField("NB_ADDRESS", "127.0.0.1")]

# Name Query Response
# Name Registration Response


class NBNSQueryResponse(Packet):
    name = "NBNS query response"
    fields_desc = [ShortField("NAME_TRN_ID", 0),
                   ShortField("FLAGS", 0x8500),
                   ShortField("QDCOUNT", 0),
                   ShortField("ANCOUNT", 1),
                   ShortField("NSCOUNT", 0),
                   ShortField("ARCOUNT", 0),
                   NetBIOSNameField("RR_NAME", "windows"),
                   ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0),
                   ShortEnumField("QUESTION_TYPE", 0x20, _NETBIOS_QRTYPES),
                   ShortEnumField("QUESTION_CLASS", 1, _NETBIOS_QRCLASS),
                   IntField("TTL", 0x493e0),
                   ShortField("RDLENGTH", 6),
                   ShortField("NB_FLAGS", 0),
                   IPField("NB_ADDRESS", "127.0.0.1")]

# Name Query Response (negative)
# Name Release Response


class NBNSQueryResponseNegative(Packet):
    name = "NBNS query response (negative)"
    fields_desc = [ShortField("NAME_TRN_ID", 0),
                   ShortField("FLAGS", 0x8506),
                   ShortField("QDCOUNT", 0),
                   ShortField("ANCOUNT", 1),
                   ShortField("NSCOUNT", 0),
                   ShortField("ARCOUNT", 0),
                   NetBIOSNameField("RR_NAME", "windows"),
                   ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0),
                   ShortEnumField("RR_TYPE", 0x20, _NETBIOS_QRTYPES),
                   ShortEnumField("RR_CLASS", 1, _NETBIOS_QRCLASS),
                   IntField("TTL", 0),
                   ShortField("RDLENGTH", 6),
                   BitEnumField("G", 0, 1, _NETBIOS_GNAMES),
                   BitEnumField("OWNER_NODE_TYPE", 00, 2,
                                _NETBIOS_OWNER_MODE_TYPES),
                   BitEnumField("UNUSED", 0, 13, {0: "Unused"}),
                   IPField("NB_ADDRESS", "127.0.0.1")]

# Node Status Response


class NBNSNodeStatusResponse(Packet):
    name = "NBNS Node Status Response"
    fields_desc = [ShortField("NAME_TRN_ID", 0),
                   ShortField("FLAGS", 0x8500),
                   ShortField("QDCOUNT", 0),
                   ShortField("ANCOUNT", 1),
                   ShortField("NSCOUNT", 0),
                   ShortField("ARCOUNT", 0),
                   NetBIOSNameField("RR_NAME", "windows"),
                   ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0),
                   ShortEnumField("RR_TYPE", 0x21, _NETBIOS_QRTYPES),
                   ShortEnumField("RR_CLASS", 1, _NETBIOS_QRCLASS),
                   IntField("TTL", 0),
                   ShortField("RDLENGTH", 83),
                   ByteField("NUM_NAMES", 1)]

# Service for Node Status Response


class NBNSNodeStatusResponseService(Packet):
    name = "NBNS Node Status Response Service"
    fields_desc = [StrFixedLenField("NETBIOS_NAME", "WINDOWS         ", 15),
                   ByteEnumField("SUFFIX", 0, {0: "workstation",
                                               0x03: "messenger service",
                                               0x20: "file server service",
                                               0x1b: "domain master browser",
                                               0x1c: "domain controller",
                                               0x1e: "browser election service"
                                               }),
                   ByteField("NAME_FLAGS", 0x4),
                   ByteEnumField("UNUSED", 0, {0: "unused"})]

# End of Node Status Response packet


class NBNSNodeStatusResponseEnd(Packet):
    name = "NBNS Node Status Response"
    fields_desc = [SourceMACField("MAC_ADDRESS"),
                   BitField("STATISTICS", 0, 57 * 8)]

# Wait for Acknowledgement Response


class NBNSWackResponse(Packet):
    name = "NBNS Wait for Acknowledgement Response"
    fields_desc = [ShortField("NAME_TRN_ID", 0),
                   ShortField("FLAGS", 0xBC07),
                   ShortField("QDCOUNT", 0),
                   ShortField("ANCOUNT", 1),
                   ShortField("NSCOUNT", 0),
                   ShortField("ARCOUNT", 0),
                   NetBIOSNameField("RR_NAME", "windows"),
                   ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0),
                   ShortEnumField("RR_TYPE", 0x20, _NETBIOS_QRTYPES),
                   ShortEnumField("RR_CLASS", 1, _NETBIOS_QRCLASS),
                   IntField("TTL", 2),
                   ShortField("RDLENGTH", 2),
                   BitField("RDATA", 10512, 16)]  # 10512=0010100100010000


class NBTDatagram(Packet):
    name = "NBT Datagram Packet"
    fields_desc = [ByteField("Type", 0x10),
                   ByteField("Flags", 0x02),
                   ShortField("ID", 0),
                   IPField("SourceIP", "127.0.0.1"),
                   ShortField("SourcePort", 138),
                   ShortField("Length", 272),
                   ShortField("Offset", 0),
                   NetBIOSNameField("SourceName", "windows"),
                   ShortEnumField("SUFFIX1", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0),
                   NetBIOSNameField("DestinationName", "windows"),
                   ShortEnumField("SUFFIX2", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0)]


class NBTSession(Packet):
    name = "NBT Session Packet"
    fields_desc = [ByteEnumField("TYPE", 0, {0x00: "Session Message",
                                             0x81: "Session Request",
                                             0x82: "Positive Session Response",
                                             0x83: "Negative Session Response",
                                             0x84: "Retarget Session Response",
                                             0x85: "Session Keepalive"}),
                   BitField("RESERVED", 0x00, 7),
                   BitField("LENGTH", 0, 17)]


bind_layers(UDP, NBNSQueryRequest, dport=137)
bind_layers(UDP, NBNSRequest, dport=137)
bind_layers(UDP, NBNSQueryResponse, sport=137)
bind_layers(UDP, NBNSQueryResponseNegative, sport=137)
bind_layers(UDP, NBNSNodeStatusResponse, sport=137)
bind_layers(NBNSNodeStatusResponse, NBNSNodeStatusResponseService, )
bind_layers(NBNSNodeStatusResponse, NBNSNodeStatusResponseService, )
bind_layers(NBNSNodeStatusResponseService, NBNSNodeStatusResponseService, )
bind_layers(NBNSNodeStatusResponseService, NBNSNodeStatusResponseEnd, )
bind_layers(UDP, NBNSWackResponse, sport=137)
bind_layers(UDP, NBTDatagram, dport=138)
bind_layers(TCP, NBTSession, dport=139)
