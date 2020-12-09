# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

#############################################################################
#                                                                           #
#  hsrp.py --- HSRP  protocol support for Scapy                             #
#                                                                           #
#  Copyright (C) 2010  Mathieu RENARD mathieu.renard(at)gmail.com           #
#                                                                           #
#  This program is free software; you can redistribute it and/or modify it  #
#  under the terms of the GNU General Public License version 2 as           #
#  published by the Free Software Foundation; version 2.                    #
#                                                                           #
#  This program is distributed in the hope that it will be useful, but      #
#  WITHOUT ANY WARRANTY; without even the implied warranty of               #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU        #
#  General Public License for more details.                                 #
#                                                                           #
#############################################################################

# $Log: hsrp.py,v $
# Revision 0.2  2011/05/01 15:23:34  mrenard
# Cleanup code

# scapy.contrib.description = Hot Standby Router Protocol (HSRP)
# scapy.contrib.status = loads

"""
HSRP (Hot Standby Router Protocol)
- RFC 7348 -

Proprietary redundancy protocol for Cisco routers.

HSRP Version 1
    Ref. https://tools.ietf.org/html/rfc2281
HSRP Version 2
    Ref. http://www.smartnetworks.jp/2006/02/hsrp_8_hsrp_version_2.html
"""

import struct
from scapy.fields import ByteEnumField, ByteField, IPField, IP6Field, \
    SourceIPField, StrFixedLenField, XIntField, XShortField, IntField, \
    StrField, ConditionalField, MultipleTypeField
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.compat import orb
from scapy.layers.inet import DestIPField, UDP
from scapy.layers.inet6 import DestIP6Field
from scapy.layers.l2 import SourceMACField
from scapy.utils import valid_net, valid_net6


class HSRP(Packet):
    """
    HSRP version 1
    """
    name = "HSRPv1"
    fields_desc = [
        ByteField("version", 0),
        ByteEnumField("opcode", 0,
                      {0: "Hello",
                       1: "Coup",
                       2: "Resign",
                       3: "Advertise"}),
        ByteEnumField("state", 16,
                      {0: "Initial",
                       1: "Learn",
                       2: "Listen",
                       4: "Speak",
                       8: "Standby",
                       16: "Active"}),
        ByteField("hellotime", 3),
        ByteField("holdtime", 10),
        ByteField("priority", 120),
        ByteField("group", 1),
        ByteField("reserved", 0),
        StrFixedLenField("auth", b"cisco" + b"\x00" * 3, 8),
        IPField("virtualIP", "192.168.1.1")
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Dissects proper version of HSRP packet
        based on the first byte.
        """
        if _pkt:
            if orb(_pkt[:1]) == 0:
                return HSRP
            if orb(_pkt[:1]) == 1:
                return HSRPv2
        return HSRP

    def guess_payload_class(self, payload):
        if self.underlayer.len > 28:
            return HSRPmd5
        else:
            return Packet.guess_payload_class(self, payload)


class HSRPv2(Packet):
    """
    HSRP version 2.
    """
    name = "HSRPv2"
    fields_desc = [
        ByteEnumField("type", 1, {1: "Group state TLV"}),
        ByteField("len", None),
        ByteField("version", 2),
        ByteEnumField("opcode", 0,
                      {0: "Hello",
                       1: "Coup",
                       2: "Resign",
                       3: "Advertise"}),
        ByteEnumField("state", 16,
                      {0: "Initial",
                       1: "Learn",
                       2: "Listen",
                       4: "Speak",
                       8: "Standby",
                       16: "Active"}),
        ByteEnumField("ipVer", None, {4: "IPv4", 6: "IPv6"}),
        XShortField("group", 1),
        SourceMACField("identifier"),
        IntField("priority", 100),
        IntField("hellotime", 3000),
        IntField("holdtime", 10000),
        MultipleTypeField(
            [
                (IPField("virtualIP", "0.0.0.0"),
                 (lambda p: p.ipVer == 4,
                  lambda p, val:
                    p.ipVer != 6 and (val is None or valid_net(val))
                  )
                 ),
                (IP6Field("virtualIP", "::"),
                 (lambda p: p.ipVer == 6,
                  lambda p, val:
                    p.ipVer != 4 and (val is None or valid_net6(val))
                  )
                 ),
            ],
            StrField("virtualIP", None)  # By default
        ),
        # The virtualIP field's expected size is always the size of an IPv6
        # address. If IPv4 is used, padding is required.
        ConditionalField(
            StrFixedLenField("padding", b"\x00" * 12, 12),
            lambda pkt: valid_net(pkt.virtualIP)
        )
    ]

    def post_build(self, pkt, pay):
        if self.ipVer is None:
            ip_ver = 4

            if valid_net6(self.virtualIP):
                ip_ver = 6

            pkt = pkt[:5] + struct.pack("B", ip_ver) + pkt[6:]

        if self.len is None:
            pkt = pkt[:1] + struct.pack("B", len(pkt) - 2) + pkt[2:]
        return pkt + pay

    def guess_payload_class(self, payload):
        if len(payload) > 0:
            hsrp_auth_payload_type = orb(payload[:1])
            if hsrp_auth_payload_type == 3:
                return HSRPv2TextAuth
            elif hsrp_auth_payload_type == 4:
                return HSRPmd5
        return Packet.guess_payload_class(self, payload)


class HSRPmd5(Packet):
    """
    MD5 Authentication header for HSRP (version 1 and 2).
    """
    name = "HSRP MD5 Authentication"
    fields_desc = [
        ByteEnumField("type", 4, {4: "MD5 authentication"}),
        ByteField("len", None),
        ByteEnumField("algo", 1, {1: "MD5"}),
        ByteField("padding", 0x00),
        XShortField("flags", 0x00),
        SourceIPField("sourceip", None),
        XIntField("keyid", 0x00),
        StrFixedLenField("authdigest", b"\x00" * 16, 16)]

    def post_build(self, pkt, pay):
        if self.len is None:
            pkt = pkt[:1] + struct.pack("B", len(pkt) - 2) + pkt[2:]
        return pkt + pay


class HSRPv2TextAuth(Packet):
    """
    Default plain text authentication header.
    This is only used with HSRP version 2.
    """
    name = "HSRP Authentication"
    fields_desc = [
        ByteEnumField("type", 3, {3: "Text Authentication TLV"}),
        ByteField("len", 8),
        StrFixedLenField("auth", b"cisco" + b"\x00" * 3, 8)
    ]


bind_bottom_up(UDP, HSRP, dport=1985)
bind_bottom_up(UDP, HSRP, sport=1985)
bind_bottom_up(UDP, HSRPv2, dport=1985)
bind_bottom_up(UDP, HSRPv2, sport=1985)
bind_bottom_up(UDP, HSRPv2, dport=2029)
bind_bottom_up(UDP, HSRPv2, sport=2029)

bind_layers(UDP, HSRP, dport=1985, sport=1985)
bind_layers(UDP, HSRPv2, dport=1985, sport=1985)  # HSRP v2 with IPv4
bind_layers(UDP, HSRPv2, dport=2029, sport=2029)  # HSRP v2 with IPv6

DestIPField.bind_addr(UDP, "224.0.0.2", dport=1985)
DestIPField.bind_addr(UDP, "224.0.0.102", dport=1985)
DestIP6Field.bind_addr(UDP, "ff02::66", dport=2029)
