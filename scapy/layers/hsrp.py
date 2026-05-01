# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net for more information
# Copyright (C)  Mathieu RENARD <mathieu.renard(at)gmail.com>

"""
HSRP (Hot Standby Router Protocol)
A proprietary redundancy protocol for Cisco routers.

- HSRP Version 1: RFC 2281
- HSRP Version 2 uses different packet format with 16-bit timers
  and an identifier field. Uses UDP port 2029 and multicast
  224.0.0.102 (ff02::66 for IPv6).
"""

import struct

from scapy.config import conf
from scapy.fields import ByteEnumField, ByteField, IPField, ShortField, \
    SourceIPField, StrFixedLenField, XIntField, XShortField
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.layers.inet import DestIPField, UDP
from scapy.compat import orb

_hsrp_opcodes = {0: "Hello", 1: "Coup", 2: "Resign", 3: "Advertise"}

_hsrp_states = {
    0: "Initial",
    1: "Learn",
    2: "Listen",
    4: "Speak",
    8: "Standby",
    16: "Active",
}


class HSRP(Packet):
    name = "HSRPv1"
    fields_desc = [
        ByteField("version", 0),
        ByteEnumField("opcode", 0, _hsrp_opcodes),
        ByteEnumField("state", 16, _hsrp_states),
        ByteField("hellotime", 3),
        ByteField("holdtime", 10),
        ByteField("priority", 120),
        ByteField("group", 1),
        ByteField("reserved", 0),
        StrFixedLenField("auth", b"cisco" + b"\00" * 3, 8),
        IPField("virtualIP", "192.168.1.1"),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 1:
            ver = orb(_pkt[0])
            if ver == 1:
                return HSRPv2
        return HSRP

    def guess_payload_class(self, payload):
        if self.underlayer and self.underlayer.len > 28:
            return HSRPmd5
        else:
            return Packet.guess_payload_class(self, payload)

    def mysummary(self):
        return self.sprintf(
            "HSRPv1 group=%group% state=%state% "
            "virtualIP=%virtualIP%"
        )


class HSRPv2(Packet):
    name = "HSRPv2"
    fields_desc = [
        ByteField("version", 1),
        ByteEnumField("opcode", 0, _hsrp_opcodes),
        ByteEnumField("state", 16, _hsrp_states),
        ByteField("reserved", 0),
        ShortField("hellotime", 3000),
        ShortField("holdtime", 10000),
        ByteField("priority", 120),
        ByteField("group", 1),
        ShortField("identifier", 0),
        IPField("virtualIP", "192.168.1.1"),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 1:
            ver = orb(_pkt[0])
            if ver == 0:
                return HSRP
        return HSRPv2

    def mysummary(self):
        return self.sprintf(
            "HSRPv2 group=%group% state=%state% "
            "virtualIP=%virtualIP%"
        )


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
        StrFixedLenField("authdigest", b"\00" * 16, 16),
    ]

    def post_build(self, p, pay):
        if self.len is None:
            tmp_len = len(p) + len(pay)
            p = p[:1] + struct.pack("B", tmp_len) + p[2:]
        return p + pay


bind_bottom_up(UDP, HSRP, dport=1985)
bind_bottom_up(UDP, HSRP, sport=1985)
bind_bottom_up(UDP, HSRP, dport=2029)
bind_bottom_up(UDP, HSRP, sport=2029)
bind_layers(UDP, HSRP, dport=1985, sport=1985)
bind_layers(UDP, HSRP, dport=2029, sport=2029)
DestIPField.bind_addr(UDP, "224.0.0.2", dport=1985)
DestIPField.bind_addr(UDP, "224.0.0.102", dport=2029)
if conf.ipv6_enabled:
    from scapy.layers.inet6 import DestIP6Field
    DestIP6Field.bind_addr(UDP, "ff02::66", dport=2029)
