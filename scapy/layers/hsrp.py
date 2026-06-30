# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C)  Mathieu RENARD <mathieu.renard(at)gmail.com>

"""
HSRP (Hot Standby Router Protocol)
A proprietary redundancy protocol for Cisco routers.

- HSRP Version 1: RFC 2281
- HSRP Version 2:
    http://www.smartnetworks.jp/2006/02/hsrp_8_hsrp_version_2.html
"""
import socket


from scapy.config import conf
from scapy.compat import orb, plain_str
from scapy.fields import ByteEnumField, ByteField, IntField, IPField, \
    ShortEnumField, ShortField, SourceIPField, StrFixedLenField, \
    XIntField, XShortField, Field, MACField, StrLenField
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.pton_ntop import inet_ntop, inet_pton
from scapy.layers.inet import DestIPField, UDP


_HSRP_OPCODES = {0: "Hello", 1: "Coup", 2: "Resign", 3: "Advertise"}
_HSRP_STATES = {
    0: "Initial",
    1: "Learn",
    2: "Listen",
    4: "Speak",
    8: "Standby",
    16: "Active",
}
_HSRP_ADVERTISE_TYPES = {1: "HSRP interface state"}
_HSRP_ADVERTISE_STATES = {1: "Active", 2: "Passive"}
_HSRP_V2_STATES = {
    1: "Initial",
    2: "Learn",
    3: "Listen",
    4: "Speak",
    5: "Standby",
    6: "Active",
}
_HSRP_V2_TLV_TYPES = {
    1: "Group State",
    2: "Interface State",
    3: "Text Authentication",
    4: "MD5 Authentication",
}
_HSRP_V2_IP_VERSIONS = {
    4: "IPv4",
    6: "IPv6",
}


def _is_hsrpv2(pkt):
    if not pkt or len(pkt) < 2:
        return False

    tlvtype = orb(pkt[0:1])
    tlvlength = orb(pkt[1:2])

    if tlvtype not in _HSRP_V2_TLV_TYPES:
        return False

    if len(pkt) < 2 + tlvlength:
        return False

    if tlvtype == 1:
        return (
            tlvlength == 40 and
            len(pkt) >= 6 and
            orb(pkt[2:3]) == 2 and
            orb(pkt[3:4]) in _HSRP_OPCODES and
            orb(pkt[4:5]) in _HSRP_V2_STATES and
            orb(pkt[5:6]) in _HSRP_V2_IP_VERSIONS
        )

    if tlvtype == 2:
        return tlvlength == 4

    if tlvtype == 3:
        return tlvlength == 8

    if tlvtype == 4:
        return tlvlength == 28

    return True


class _HSRPv2VirtualIPField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "16s")

    def i2m(self, pkt, x):
        if x is None:
            return b"\x00" * 16
        if isinstance(x, bytes):
            if len(x) == 4:
                return x + b"\x00" * 12
            if len(x) == 16:
                return x
            raise ValueError("Virtual IP must be 4 or 16 bytes")
        x = plain_str(x)
        if pkt is not None and pkt.ipversion == 6:
            return inet_pton(socket.AF_INET6, x)
        return inet_pton(socket.AF_INET, x) + b"\x00" * 12

    def m2i(self, pkt, x):
        if pkt is not None and pkt.ipversion == 6:
            return inet_ntop(socket.AF_INET6, x)
        return inet_ntop(socket.AF_INET, x[:4])

    def i2repr(self, pkt, x):
        if isinstance(x, bytes):
            x = self.m2i(pkt, x)
        return plain_str(x)


class HSRP(Packet):
    name = "HSRP"
    fields_desc = [
        ByteField("version", 0),
        ByteEnumField("opcode", 0, _HSRP_OPCODES),
        ByteEnumField("state", 16, _HSRP_STATES),
        ByteField("hellotime", 3),
        ByteField("holdtime", 10),
        ByteField("priority", 120),
        ByteField("group", 1),
        ByteField("reserved", 0),
        StrFixedLenField("auth", b"cisco" + b"\00" * 3, 8),
        IPField("virtualIP", "192.168.1.1")
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _is_hsrpv2(_pkt):
            return HSRPv2
        if _pkt and len(_pkt) >= 2 and orb(_pkt[1:2]) == 3:
            return HSRPAdvertise
        return cls

    def guess_payload_class(self, payload):
        if self.underlayer.len > 28:
            return HSRPmd5
        else:
            return Packet.guess_payload_class(self, payload)


class HSRPv2(Packet):
    name = "HSRPv2"
    fields_desc = []

    def guess_payload_class(self, payload):
        if payload:
            return HSRPv2TLV
        return Packet.guess_payload_class(self, payload)


class HSRPv2TLV(Packet):
    name = "HSRPv2 TLV"

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 1:
            tlv_type = orb(_pkt[0:1])
            if tlv_type == 1:
                return HSRPv2GroupStateTLV
            if tlv_type == 2:
                return HSRPv2InterfaceStateTLV
            if tlv_type == 3:
                return HSRPv2TextAuthTLV
            if tlv_type == 4:
                return HSRPv2MD5AuthTLV
        return HSRPv2UnknownTLV


class _HSRPv2TLVPayload(Packet):
    name = "HSRPv2 TLV Payload"

    def guess_payload_class(self, payload):
        if payload:
            return HSRPv2TLV
        return Packet.guess_payload_class(self, payload)

    def post_build(self, p, pay):
        if self.len is None:
            tlv_len = len(p) - 2
            if tlv_len > 255:
                raise ValueError("HSRPv2 TLV length exceeds 255 bytes")
            p = p[:1] + bytes([tlv_len]) + p[2:]
        return p + pay


class HSRPv2GroupStateTLV(_HSRPv2TLVPayload):
    name = "HSRPv2 Group State TLV"
    fields_desc = [
        ByteEnumField("type", 1, _HSRP_V2_TLV_TYPES),
        ByteField("len", None),
        ByteField("version", 2),
        ByteEnumField("opcode", 0, _HSRP_OPCODES),
        ByteEnumField("state", 6, _HSRP_V2_STATES),
        ByteEnumField("ipversion", 4, _HSRP_V2_IP_VERSIONS),
        ShortField("group", 1),
        MACField("identifier", "00:00:00:00:00:00"),
        IntField("priority", 100),
        IntField("hellotime", 3000),
        IntField("holdtime", 10000),
        _HSRPv2VirtualIPField("virtualIP", b"\x00" * 16),
    ]


class HSRPv2InterfaceStateTLV(_HSRPv2TLVPayload):
    name = "HSRPv2 Interface State TLV"
    fields_desc = [
        ByteEnumField("type", 2, _HSRP_V2_TLV_TYPES),
        ByteField("len", None),
        ShortField("activegroups", 0),
        ShortField("passivegroups", 0),
    ]


class HSRPv2TextAuthTLV(_HSRPv2TLVPayload):
    name = "HSRPv2 Text Authentication TLV"
    fields_desc = [
        ByteEnumField("type", 3, _HSRP_V2_TLV_TYPES),
        ByteField("len", None),
        StrFixedLenField("auth", b"cisco" + b"\x00" * 3, 8),
    ]


class HSRPv2MD5AuthTLV(_HSRPv2TLVPayload):
    name = "HSRPv2 MD5 Authentication TLV"
    fields_desc = [
        ByteEnumField("type", 4, _HSRP_V2_TLV_TYPES),
        ByteField("len", None),
        ByteEnumField("algo", 1, {1: "MD5"}),
        ByteField("padding", 0),
        XShortField("flags", 0),
        SourceIPField("sourceip"),
        XIntField("keyid", 0),
        StrFixedLenField("authdigest", b"\x00" * 16, 16),
    ]


class HSRPv2UnknownTLV(_HSRPv2TLVPayload):
    name = "HSRPv2 Unknown TLV"
    fields_desc = [
        ByteEnumField("type", 0, _HSRP_V2_TLV_TYPES),
        ByteField("len", None),
        StrLenField("value", b"", length_from=lambda pkt: pkt.len),
    ]


class HSRPAdvertise(Packet):
    name = "HSRP Advertise"
    fields_desc = [
        ByteField("version", 0),
        ByteEnumField("opcode", 3, _HSRP_OPCODES),
        ShortEnumField("type", 1, _HSRP_ADVERTISE_TYPES),
        ShortField("length", 10),
        ByteEnumField("state", 1, _HSRP_ADVERTISE_STATES),
        ByteField("reserved1", 0),
        ShortField("activegroups", 0),
        ShortField("passivegroups", 0),
        IntField("reserved2", 0),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2 and orb(_pkt[1:2]) != 3:
            return HSRP
        return cls


class HSRPmd5(Packet):
    name = "HSRP MD5 Authentication"
    fields_desc = [
        ByteEnumField("type", 4, {4: "MD5 authentication"}),
        ByteField("len", None),
        ByteEnumField("algo", 0, {1: "MD5"}),
        ByteField("padding", 0x00),
        XShortField("flags", 0x00),
        SourceIPField("sourceip"),
        XIntField("keyid", 0x00),
        StrFixedLenField("authdigest", b"\00" * 16, 16)]

    def post_build(self, p, pay):
        if self.len is None and pay:
            tmp_len = len(pay)
            p = p[:1] + hex(tmp_len)[30:] + p[30:]
        return p


bind_bottom_up(UDP, HSRP, dport=1985)
bind_bottom_up(UDP, HSRP, sport=1985)
bind_bottom_up(UDP, HSRP, dport=2029)
bind_bottom_up(UDP, HSRP, sport=2029)
bind_layers(UDP, HSRP, dport=1985, sport=1985)
bind_layers(UDP, HSRP, dport=2029, sport=2029)
DestIPField.bind_addr(UDP, "224.0.0.2", dport=1985)
if conf.ipv6_enabled:
    from scapy.layers.inet6 import DestIP6Field
    DestIP6Field.bind_addr(UDP, "ff02::66", dport=2029)
