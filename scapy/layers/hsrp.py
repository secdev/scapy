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
from scapy.fields import ByteEnumField, ByteField, IPField, SourceIPField, \
    StrFixedLenField, XIntField, XShortField
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.layers.inet import DestIPField, UDP


class HSRP(Packet):
    name = "HSRP"
    fields_desc = [
        ByteField("version", 0),
        ByteEnumField("opcode", 0, {0: "Hello", 1: "Coup", 2: "Resign", 3: "Advertise"}),  # noqa: E501
        ByteEnumField("state", 16, {0: "Initial", 1: "Learn", 2: "Listen", 4: "Speak", 8: "Standby", 16: "Active"}),  # noqa: E501
        ByteField("hellotime", 3),
        ByteField("holdtime", 10),
        ByteField("priority", 120),
        ByteField("group", 1),
        ByteField("reserved", 0),
        StrFixedLenField("auth", b"cisco" + b"\00" * 3, 8),
        IPField("virtualIP", "192.168.1.1")]

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
