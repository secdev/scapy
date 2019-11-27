# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
RIP (Routing Information Protocol).
"""

from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import ByteEnumField, ByteField, ConditionalField, \
    IPField, IntEnumField, IntField, ShortEnumField, ShortField, \
    StrFixedLenField, StrLenField
from scapy.layers.inet import UDP


class RIP(Packet):
    name = "RIP header"
    fields_desc = [
        ByteEnumField("cmd", 1, {1: "req", 2: "resp", 3: "traceOn", 4: "traceOff",  # noqa: E501
                                 5: "sun", 6: "trigReq", 7: "trigResp", 8: "trigAck",  # noqa: E501
                                 9: "updateReq", 10: "updateResp", 11: "updateAck"}),  # noqa: E501
        ByteField("version", 1),
        ShortField("null", 0),
    ]

    def guess_payload_class(self, payload):
        if payload[:2] == b"\xff\xff":
            return RIPAuth
        else:
            return Packet.guess_payload_class(self, payload)


class RIPEntry(RIP):
    name = "RIP entry"
    fields_desc = [
        ShortEnumField("AF", 2, {2: "IP"}),
        ShortField("RouteTag", 0),
        IPField("addr", "0.0.0.0"),
        IPField("mask", "0.0.0.0"),
        IPField("nextHop", "0.0.0.0"),
        IntEnumField("metric", 1, {16: "Unreach"}),
    ]


class RIPAuth(Packet):
    name = "RIP authentication"
    fields_desc = [
        ShortEnumField("AF", 0xffff, {0xffff: "Auth"}),
        ShortEnumField("authtype", 2, {1: "md5authdata", 2: "simple", 3: "md5"}),  # noqa: E501
        ConditionalField(StrFixedLenField("password", None, 16),
                         lambda pkt: pkt.authtype == 2),
        ConditionalField(ShortField("digestoffset", 0),
                         lambda pkt: pkt.authtype == 3),
        ConditionalField(ByteField("keyid", 0),
                         lambda pkt: pkt.authtype == 3),
        ConditionalField(ByteField("authdatalen", 0),
                         lambda pkt: pkt.authtype == 3),
        ConditionalField(IntField("seqnum", 0),
                         lambda pkt: pkt.authtype == 3),
        ConditionalField(StrFixedLenField("zeropad", None, 8),
                         lambda pkt: pkt.authtype == 3),
        ConditionalField(StrLenField("authdata", None,
                                     length_from=lambda pkt: pkt.md5datalen),
                         lambda pkt: pkt.authtype == 1)
    ]

    def pre_dissect(self, s):
        if s[2:4] == b"\x00\x01":
            self.md5datalen = len(s) - 4

        return s


bind_bottom_up(UDP, RIP, dport=520)
bind_bottom_up(UDP, RIP, sport=520)
bind_layers(UDP, RIP, sport=520, dport=520)
bind_layers(RIP, RIPEntry,)
bind_layers(RIPEntry, RIPEntry,)
bind_layers(RIPAuth, RIPEntry,)
