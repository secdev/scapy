## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

#############################################################################
##                                                                         ##
## hsrp.py --- HSRP  protocol support for Scapy                            ##
##                                                                         ##
## Copyright (C) 2010  Mathieu RENARD mathieu.renard(at)gmail.com          ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation; version 2.                   ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################
## HSRP Version 1
##  Ref. RFC 2281
## HSRP Version 2
##  Ref. http://www.smartnetworks.jp/2006/02/hsrp_8_hsrp_version_2.html
##
## $Log: hsrp.py,v $
## Revision 0.2  2011/05/01 15:23:34  mrenard
##   Cleanup code

"""
HSRP (Hot Standby Router Protocol): proprietary redundancy protocol for Cisco routers.
"""

from scapy.fields import *
from scapy.packet import *
from scapy.layers.inet import UDP


class HSRP(Packet):
    name = "HSRP"
    fields_desc = [
        ByteField("version", 0),
        ByteEnumField("opcode", 0, {0: "Hello", 1: "Coup", 2: "Resign", 3: "Advertise"}),
        ByteEnumField("state", 16, {0: "Initial", 1: "Learn", 2: "Listen", 4: "Speak", 8: "Standby", 16: "Active"}),
        ByteField("hellotime", 3),
        ByteField("holdtime", 10),
        ByteField("priority", 120),
        ByteField("group", 1),
        ByteField("reserved", 0),
        StrFixedLenField("auth", "cisco" + "\00" * 3, 8),
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
        IPField("sourceip", None),
        XIntField("keyid", 0x00),
        StrFixedLenField("authdigest", "\00" * 16, 16)]

    def post_build(self, p, pay):
        if self.len is None and pay:
            l = len(pay)
            p = p[:1] + hex(l)[30:] + p[30:]
        return p

bind_layers(UDP, HSRP, dport=1985, sport=1985)
