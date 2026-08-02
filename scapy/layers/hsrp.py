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

from scapy.config import conf
from scapy.compat import orb
from scapy.fields import ByteEnumField, ByteField, IntField, IPField, \
    ShortEnumField, ShortField, SourceIPField, StrFixedLenField, \
    XIntField, XShortField
from scapy.packet import Packet, bind_layers, bind_bottom_up
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
        if _pkt and len(_pkt) >= 2 and orb(_pkt[1:2]) == 3:
            return HSRPAdvertise
        return cls

    def guess_payload_class(self, payload):
        if self.underlayer.len > 28:
            return HSRPmd5
        else:
            return Packet.guess_payload_class(self, payload)


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
