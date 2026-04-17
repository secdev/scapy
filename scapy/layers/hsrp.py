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
from scapy.fields import ByteEnumField, ByteField, ConditionalField, \
    IntField, IPField, ShortEnumField, ShortField, SourceIPField, \
    StrFixedLenField, XIntField, XShortField
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.layers.inet import DestIPField, UDP


def _is_advertise(pkt) -> bool:
    return pkt.opcode == 3


def _is_not_advertise(pkt) -> bool:
    return pkt.opcode != 3


class HSRP(Packet):
    name = "HSRP"
    fields_desc = [
        ByteField("version", 0),
        ByteEnumField("opcode", 0, {0: "Hello", 1: "Coup", 2: "Resign", 3: "Advertise"}),  # noqa: E501
        ConditionalField(
            ByteEnumField("state", 16, {
                0: "Initial",
                1: "Learn",
                2: "Listen",
                4: "Speak",
                8: "Standby",
                16: "Active",
            }),
            _is_not_advertise
        ),
        ConditionalField(ByteField("hellotime", 3), _is_not_advertise),
        ConditionalField(ByteField("holdtime", 10), _is_not_advertise),
        ConditionalField(ByteField("priority", 120), _is_not_advertise),
        ConditionalField(ByteField("group", 1), _is_not_advertise),
        ConditionalField(ByteField("reserved", 0), _is_not_advertise),
        ConditionalField(StrFixedLenField("auth", b"cisco" + b"\00" * 3, 8), _is_not_advertise),
        ConditionalField(IPField("virtualIP", "192.168.1.1"), _is_not_advertise),
        ConditionalField(ShortEnumField("adv_type", 1, {1: "HSRP interface state"}), _is_advertise),
        ConditionalField(ShortField("adv_length", 10), _is_advertise),
        ConditionalField(ByteEnumField("adv_state", 1, {1: "Active", 2: "Passive"}), _is_advertise),
        ConditionalField(ByteField("adv_reserved", 0), _is_advertise),
        ConditionalField(ShortField("activegroups", 0), _is_advertise),
        ConditionalField(ShortField("passivegroups", 0), _is_advertise),
        ConditionalField(IntField("reserved2", 0), _is_advertise)
    ]

    def guess_payload_class(self, payload):
        if self.underlayer.len > 28:
            return HSRPmd5
        else:
            return Packet.guess_payload_class(self, payload)


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
