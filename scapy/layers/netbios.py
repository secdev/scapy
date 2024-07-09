# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
NetBIOS over TCP/IP

[RFC 1001/1002]
"""

import struct
from scapy.arch import get_if_addr
from scapy.base_classes import Net
from scapy.ansmachine import AnsweringMachine
from scapy.compat import bytes_encode
from scapy.config import conf

from scapy.packet import Packet, bind_bottom_up, bind_layers, bind_top_down
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    FieldLenField,
    FlagsField,
    IPField,
    IntField,
    NetBIOSNameField,
    PacketListField,
    ShortEnumField,
    ShortField,
    StrFixedLenField,
    XShortField,
    XStrFixedLenField
)
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether, SourceMACField


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
#        ShortField("Delimiter",0),
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


class NBNSHeader(Packet):
    name = "NBNS Header"
    fields_desc = [
        ShortField("NAME_TRN_ID", 0),
        BitField("RESPONSE", 0, 1),
        BitField("OPCODE", 0, 4),
        FlagsField("NM_FLAGS", 0, 7, ["B",
                                      "res1",
                                      "res0",
                                      "RA",
                                      "RD",
                                      "TC",
                                      "AA"]),
        BitField("RCODE", 0, 4),
        ShortField("QDCOUNT", 0),
        ShortField("ANCOUNT", 0),
        ShortField("NSCOUNT", 0),
        ShortField("ARCOUNT", 0),
    ]

    def hashret(self):
        return b"NBNS" + struct.pack("!B", self.OPCODE)


# Name Query Request
# RFC1002 sect 4.2.12


class NBNSQueryRequest(Packet):
    name = "NBNS query request"
    fields_desc = [NetBIOSNameField("QUESTION_NAME", "windows"),
                   ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0),
                   ShortEnumField("QUESTION_TYPE", 0x20, _NETBIOS_QRTYPES),
                   ShortEnumField("QUESTION_CLASS", 1, _NETBIOS_QRCLASS)]

    def mysummary(self):
        return "NBNSQueryRequest who has '\\\\%s'" % (
            self.QUESTION_NAME.decode(errors="backslashreplace")
        )


bind_layers(NBNSHeader, NBNSQueryRequest,
            OPCODE=0x0, NM_FLAGS=0x11, QDCOUNT=1)


# Name Query Response
# RFC1002 sect 4.2.13


class NBNS_ADD_ENTRY(Packet):
    fields_desc = [
        BitEnumField("G", 0, 1, _NETBIOS_GNAMES),
        BitEnumField("OWNER_NODE_TYPE", 00, 2,
                     _NETBIOS_OWNER_MODE_TYPES),
        BitEnumField("UNUSED", 0, 13, {0: "Unused"}),
        IPField("NB_ADDRESS", "127.0.0.1")
    ]


class NBNSQueryResponse(Packet):
    name = "NBNS query response"
    fields_desc = [NetBIOSNameField("RR_NAME", "windows"),
                   ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0),
                   ShortEnumField("QUESTION_TYPE", 0x20, _NETBIOS_QRTYPES),
                   ShortEnumField("QUESTION_CLASS", 1, _NETBIOS_QRCLASS),
                   IntField("TTL", 0x493e0),
                   FieldLenField("RDLENGTH", None, length_of="ADDR_ENTRY"),
                   PacketListField("ADDR_ENTRY",
                                   [NBNS_ADD_ENTRY()], NBNS_ADD_ENTRY,
                                   length_from=lambda pkt: pkt.RDLENGTH)
                   ]

    def mysummary(self):
        if not self.ADDR_ENTRY:
            return "NBNSQueryResponse"
        return "NBNSQueryResponse '\\\\%s' is at %s" % (
            self.RR_NAME.decode(errors="backslashreplace"),
            self.ADDR_ENTRY[0].NB_ADDRESS
        )

    def answers(self, other):
        return (
            isinstance(other, NBNSQueryRequest) and
            other.QUESTION_NAME == self.RR_NAME
        )


bind_layers(NBNSHeader, NBNSQueryResponse,  # RD+AA
            OPCODE=0x0, NM_FLAGS=0x50, RESPONSE=1, ANCOUNT=1)
for _flg in [0x58, 0x70, 0x78]:
    bind_bottom_up(NBNSHeader, NBNSQueryResponse,
                   OPCODE=0x0, NM_FLAGS=_flg, RESPONSE=1, ANCOUNT=1)


# Node Status Request
# RFC1002 sect 4.2.17

class NBNSNodeStatusRequest(NBNSQueryRequest):
    name = "NBNS status request"
    QUESTION_NAME = b"*" + b"\x00" * 14
    QUESTION_TYPE = 0x21

    def mysummary(self):
        return "NBNSNodeStatusRequest who has '\\\\%s'" % (
            self.QUESTION_NAME.decode(errors="backslashreplace")
        )


bind_bottom_up(NBNSHeader, NBNSNodeStatusRequest, OPCODE=0x0, NM_FLAGS=0, QDCOUNT=1)
bind_layers(NBNSHeader, NBNSNodeStatusRequest, OPCODE=0x0, NM_FLAGS=1, QDCOUNT=1)


# Node Status Response
# RFC1002 sect 4.2.18

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

    def default_payload_class(self, payload):
        return conf.padding_layer


class NBNSNodeStatusResponse(Packet):
    name = "NBNS Node Status Response"
    fields_desc = [NetBIOSNameField("RR_NAME", "windows"),
                   ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0),
                   ShortEnumField("RR_TYPE", 0x21, _NETBIOS_QRTYPES),
                   ShortEnumField("RR_CLASS", 1, _NETBIOS_QRCLASS),
                   IntField("TTL", 0),
                   ShortField("RDLENGTH", 83),
                   FieldLenField("NUM_NAMES", None, fmt="B",
                                 count_of="NODE_NAME"),
                   PacketListField("NODE_NAME",
                                   [NBNSNodeStatusResponseService()],
                                   NBNSNodeStatusResponseService,
                                   count_from=lambda pkt: pkt.NUM_NAMES),
                   SourceMACField("MAC_ADDRESS"),
                   XStrFixedLenField("STATISTICS", b"", 46)]

    def answers(self, other):
        return (
            isinstance(other, NBNSNodeStatusRequest) and
            other.QUESTION_NAME == self.RR_NAME
        )


bind_layers(NBNSHeader, NBNSNodeStatusResponse,
            OPCODE=0x0, NM_FLAGS=0x40, RESPONSE=1, ANCOUNT=1)


# Name Registration Request
# RFC1002 sect 4.2.2

class NBNSRegistrationRequest(Packet):
    name = "NBNS registration request"
    fields_desc = [
        NetBIOSNameField("QUESTION_NAME", "Windows"),
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
        IPField("NB_ADDRESS", "127.0.0.1")
    ]

    def mysummary(self):
        return self.sprintf("Register %G% %QUESTION_NAME% at %NB_ADDRESS%")


bind_bottom_up(NBNSHeader, NBNSRegistrationRequest, OPCODE=0x5)
bind_layers(NBNSHeader, NBNSRegistrationRequest,
            OPCODE=0x5, NM_FLAGS=0x11, QDCOUNT=1, ARCOUNT=1)


# Wait for Acknowledgement Response
# RFC1002 sect 4.2.16

class NBNSWackResponse(Packet):
    name = "NBNS Wait for Acknowledgement Response"
    fields_desc = [NetBIOSNameField("RR_NAME", "windows"),
                   ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL", 0),
                   ShortEnumField("RR_TYPE", 0x20, _NETBIOS_QRTYPES),
                   ShortEnumField("RR_CLASS", 1, _NETBIOS_QRCLASS),
                   IntField("TTL", 2),
                   ShortField("RDLENGTH", 2),
                   BitField("RDATA", 10512, 16)]  # 10512=0010100100010000


bind_layers(NBNSHeader, NBNSWackResponse,
            OPCODE=0x7, NM_FLAGS=0x40, RESPONSE=1, ANCOUNT=1)

# NetBIOS DATAGRAM HEADER


class NBTDatagram(Packet):
    name = "NBT Datagram Packet"
    fields_desc = [ByteField("Type", 0x10),
                   ByteField("Flags", 0x02),
                   ShortField("ID", 0),
                   IPField("SourceIP", "127.0.0.1"),
                   ShortField("SourcePort", 138),
                   ShortField("Length", None),
                   ShortField("Offset", 0),
                   NetBIOSNameField("SourceName", "windows"),
                   ShortEnumField("SUFFIX1", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL1", 0),
                   NetBIOSNameField("DestinationName", "windows"),
                   ShortEnumField("SUFFIX2", 0x4141, _NETBIOS_SUFFIXES),
                   ByteField("NULL2", 0)]

    def post_build(self, pkt, pay):
        if self.Length is None:
            length = len(pay) + 68
            pkt = pkt[:10] + struct.pack("!H", length) + pkt[12:]
        return pkt + pay


# SESSION SERVICE PACKETS


class NBTSession(Packet):
    name = "NBT Session Packet"
    MAXLENGTH = 0x3ffff
    fields_desc = [ByteEnumField("TYPE", 0, {0x00: "Session Message",
                                             0x81: "Session Request",
                                             0x82: "Positive Session Response",
                                             0x83: "Negative Session Response",
                                             0x84: "Retarget Session Response",
                                             0x85: "Session Keepalive"}),
                   BitField("RESERVED", 0x00, 7),
                   BitField("LENGTH", None, 17)]

    def post_build(self, pkt, pay):
        if self.LENGTH is None:
            length = len(pay) & self.MAXLENGTH
            pkt = pkt[:1] + struct.pack("!I", length)[1:]
        return pkt + pay

    def extract_padding(self, s):
        return s[:self.LENGTH], s[self.LENGTH:]

    @classmethod
    def tcp_reassemble(cls, data, *args, **kwargs):
        if len(data) < 4:
            return None
        length = struct.unpack("!I", data[:4])[0] & cls.MAXLENGTH
        if len(data) >= length + 4:
            return cls(data)


bind_bottom_up(UDP, NBNSHeader, dport=137)
bind_bottom_up(UDP, NBNSHeader, sport=137)
bind_top_down(UDP, NBNSHeader, sport=137, dport=137)

bind_bottom_up(UDP, NBTDatagram, dport=138)
bind_bottom_up(UDP, NBTDatagram, sport=138)
bind_top_down(UDP, NBTDatagram, sport=138, dport=138)

bind_bottom_up(TCP, NBTSession, dport=445)
bind_bottom_up(TCP, NBTSession, sport=445)
bind_bottom_up(TCP, NBTSession, dport=139)
bind_bottom_up(TCP, NBTSession, sport=139)
bind_layers(TCP, NBTSession, dport=139, sport=139)


class NBNS_am(AnsweringMachine):
    function_name = "nbnsd"
    filter = "udp port 137"
    sniff_options = {"store": 0}

    def parse_options(self, server_name=None, from_ip=None, ip=None):
        """
        NBNS answering machine

        :param server_name: the netbios server name to match
        :param from_ip: an IP (can have a netmask) to filter on
        :param ip: the IP to answer with
        """
        self.ServerName = bytes_encode(server_name or "")
        self.ip = ip
        if isinstance(from_ip, str):
            self.from_ip = Net(from_ip)
        else:
            self.from_ip = from_ip

    def is_request(self, req):
        if self.from_ip and IP in req and req[IP].src not in self.from_ip:
            return False
        return NBNSQueryRequest in req and (
            not self.ServerName or
            req[NBNSQueryRequest].QUESTION_NAME.strip() == self.ServerName
        )

    def make_reply(self, req):
        # type: (Packet) -> Packet
        resp = Ether(
            dst=req[Ether].src,
            src=None if req[Ether].dst == "ff:ff:ff:ff:ff:ff" else req[Ether].dst,
        ) / IP(dst=req[IP].src) / UDP(
            sport=req.dport,
            dport=req.sport,
        )
        address = self.ip or get_if_addr(self.optsniff.get("iface", conf.iface))
        resp /= NBNSHeader() / NBNSQueryResponse(
            RR_NAME=self.ServerName or req.QUESTION_NAME,
            SUFFIX=req.SUFFIX,
            ADDR_ENTRY=[NBNS_ADD_ENTRY(NB_ADDRESS=address)]
        )
        resp.NAME_TRN_ID = req.NAME_TRN_ID
        return resp
