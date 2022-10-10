# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2010 Florian Duraffourg

# scapy.contrib.description = Label Distribution Protocol (LDP)
# scapy.contrib.status = loads

"""
Label Distribution Protocol (LDP)

http://git.savannah.gnu.org/cgit/ldpscapy.git/snapshot/ldpscapy-5285b81d6e628043df2a83301b292f24a95f0ba1.tar.gz

"""

from __future__ import absolute_import
import struct

from scapy.compat import orb
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import BitField, IPField, IntField, ShortField, StrField, \
    XBitField
from scapy.layers.inet import UDP
from scapy.layers.inet import TCP
from scapy.config import conf
from scapy.utils import inet_aton, inet_ntoa


class _LDP_Packet(Packet):
    # Guess payload
    def guess_payload_class(self, p):
        LDPTypes = {
            0x0001: LDPNotification,
            0x0100: LDPHello,
            0x0200: LDPInit,
            0x0201: LDPKeepAlive,
            0x0300: LDPAddress,
            0x0301: LDPAddressWM,
            0x0400: LDPLabelMM,
            0x0401: LDPLabelReqM,
            0x0404: LDPLabelARM,
            0x0402: LDPLabelWM,
            0x0403: LDPLabelRelM,
        }
        type = struct.unpack("!H", p[0:2])[0]
        type = type & 0x7fff
        if type == 0x0001 and struct.unpack("!H", p[2:4])[0] > 20:
            return LDP
        if type in LDPTypes:
            return LDPTypes[type]
        else:
            return conf.raw_layer

    def post_build(self, p, pay):
        if self.len is None:
            tmp_len = len(p) - 4
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        return p + pay

#  Fields  #

# 3.4.1. FEC TLV


class FecTLVField(StrField):
    islist = 1

    def m2i(self, pkt, x):
        used = 0
        x = x[4:]
        list = []
        while x:
            # if x[0] == 1:
            #   list.append('Wildcard')
            # else:
            # mask=orb(x[8*i+3])
            # add=inet_ntoa(x[8*i+4:8*i+8])
            mask = orb(x[3])
            nbroctets = mask // 8
            if mask % 8:
                nbroctets += 1
            add = inet_ntoa(x[4:4 + nbroctets] + b"\x00" * (4 - nbroctets))
            list.append((add, mask))
            used += 4 + nbroctets
            x = x[4 + nbroctets:]
        return list

    def i2m(self, pkt, x):
        if not x:
            return b""
        if isinstance(x, bytes):
            return x
        s = b"\x01\x00"
        tmp_len = 0
        fec = b""
        for o in x:
            fec += b"\x02\x00\x01"
            # mask length
            fec += struct.pack("!B", o[1])
            # Prefix
            fec += inet_aton(o[0])
            tmp_len += 8
        s += struct.pack("!H", tmp_len)
        s += fec
        return s

    def size(self, s):
        """Get the size of this field"""
        tmp_len = 4 + struct.unpack("!H", s[2:4])[0]
        return tmp_len

    def getfield(self, pkt, s):
        tmp_len = self.size(s)
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])


# 3.4.2.1. Generic Label TLV

class LabelTLVField(StrField):
    def m2i(self, pkt, x):
        return struct.unpack("!I", x[4:8])[0]

    def i2m(self, pkt, x):
        if isinstance(x, bytes):
            return x
        s = b"\x02\x00\x00\x04"
        s += struct.pack("!I", x)
        return s

    def size(self, s):
        """Get the size of this field"""
        tmp_len = 4 + struct.unpack("!H", s[2:4])[0]
        return tmp_len

    def getfield(self, pkt, s):
        tmp_len = self.size(s)
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])


# 3.4.3. Address List TLV

class AddressTLVField(StrField):
    islist = 1

    def m2i(self, pkt, x):
        nbr = struct.unpack("!H", x[2:4])[0] - 2
        nbr //= 4
        x = x[6:]
        list = []
        for i in range(0, nbr):
            add = x[4 * i:4 * i + 4]
            list.append(inet_ntoa(add))
        return list

    def i2m(self, pkt, x):
        if not x:
            return b""
        if isinstance(x, bytes):
            return x
        tmp_len = 2 + len(x) * 4
        s = b"\x01\x01" + struct.pack("!H", tmp_len) + b"\x00\x01"
        for o in x:
            s += inet_aton(o)
        return s

    def size(self, s):
        """Get the size of this field"""
        tmp_len = 4 + struct.unpack("!H", s[2:4])[0]
        return tmp_len

    def getfield(self, pkt, s):
        tmp_len = self.size(s)
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])


# 3.4.6. Status TLV

class StatusTLVField(StrField):
    islist = 1

    def m2i(self, pkt, x):
        lst = []
        statuscode = struct.unpack("!I", x[4:8])[0]
        lst.append((statuscode & 2**31) >> 31)
        lst.append((statuscode & 2**30) >> 30)
        lst.append(statuscode & 0x3FFFFFFF)
        lst.append(struct.unpack("!I", x[8:12])[0])
        lst.append(struct.unpack("!H", x[12:14])[0])
        return lst

    def i2m(self, pkt, x):
        if isinstance(x, bytes):
            return x
        s = b"\x03\x00" + struct.pack("!H", 10)
        statuscode = 0
        if x[0] != 0:
            statuscode += 2**31
        if x[1] != 0:
            statuscode += 2**30
        statuscode += x[2]
        s += struct.pack("!I", statuscode)
        if len(x) > 3:
            s += struct.pack("!I", x[3])
        else:
            s += b"\x00\x00\x00\x00"
        if len(x) > 4:
            s += struct.pack("!H", x[4])
        else:
            s += b"\x00\x00"
        return s

    def getfield(self, pkt, s):
        tmp_len = 14
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])


# 3.5.2 Common Hello Parameters TLV
class CommonHelloTLVField(StrField):
    islist = 1

    def m2i(self, pkt, x):
        list = []
        v = struct.unpack("!H", x[4:6])[0]
        list.append(v)
        flags = orb(x[6])
        v = (flags & 0x80) >> 7
        list.append(v)
        v = (flags & 0x40) >> 6
        list.append(v)
        return list

    def i2m(self, pkt, x):
        if isinstance(x, bytes):
            return x
        s = b"\x04\x00\x00\x04"
        s += struct.pack("!H", x[0])
        byte = 0
        if x[1] == 1:
            byte += 0x80
        if x[2] == 1:
            byte += 0x40
        s += struct.pack("!B", byte)
        s += b"\x00"
        return s

    def getfield(self, pkt, s):
        tmp_len = 8
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])


# 3.5.3 Common Session Parameters TLV
class CommonSessionTLVField(StrField):
    islist = 1

    def m2i(self, pkt, x):
        lst = [struct.unpack("!H", x[6:8])[0]]
        octet = struct.unpack("B", x[8:9])[0]
        lst.append((octet & 2**7) >> 7)
        lst.append((octet & 2**6) >> 6)
        lst.append(struct.unpack("B", x[9:10])[0])
        lst.append(struct.unpack("!H", x[10:12])[0])
        lst.append(inet_ntoa(x[12:16]))
        lst.append(struct.unpack("!H", x[16:18])[0])
        return lst

    def i2m(self, pkt, x):
        if isinstance(x, bytes):
            return x
        s = b"\x05\x00\x00\x0E\x00\x01"
        s += struct.pack("!H", x[0])
        octet = 0
        if x[1] != 0:
            octet += 2**7
        if x[2] != 0:
            octet += 2**6
        s += struct.pack("!B", octet)
        s += struct.pack("!B", x[3])
        s += struct.pack("!H", x[4])
        s += inet_aton(x[5])
        s += struct.pack("!H", x[6])
        return s

    def getfield(self, pkt, s):
        tmp_len = 18
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])


#  Messages  #

# 3.5.1. Notification Message
class LDPNotification(_LDP_Packet):
    name = "LDPNotification"
    fields_desc = [BitField("u", 0, 1),
                   BitField("type", 0x0001, 15),
                   ShortField("len", None),
                   IntField("id", 0),
                   StatusTLVField("status", (0, 0, 0, 0, 0))]

# 3.5.2. Hello Message


class LDPHello(_LDP_Packet):
    name = "LDPHello"
    fields_desc = [BitField("u", 0, 1),
                   BitField("type", 0x0100, 15),
                   ShortField("len", None),
                   IntField("id", 0),
                   CommonHelloTLVField("params", [180, 0, 0])]

# 3.5.3. Initialization Message


class LDPInit(_LDP_Packet):
    name = "LDPInit"
    fields_desc = [BitField("u", 0, 1),
                   XBitField("type", 0x0200, 15),
                   ShortField("len", None),
                   IntField("id", 0),
                   CommonSessionTLVField("params", None)]

# 3.5.4. KeepAlive Message


class LDPKeepAlive(_LDP_Packet):
    name = "LDPKeepAlive"
    fields_desc = [BitField("u", 0, 1),
                   XBitField("type", 0x0201, 15),
                   ShortField("len", None),
                   IntField("id", 0)]

# 3.5.5. Address Message


class LDPAddress(_LDP_Packet):
    name = "LDPAddress"
    fields_desc = [BitField("u", 0, 1),
                   XBitField("type", 0x0300, 15),
                   ShortField("len", None),
                   IntField("id", 0),
                   AddressTLVField("address", None)]

# 3.5.6. Address Withdraw Message


class LDPAddressWM(_LDP_Packet):
    name = "LDPAddressWM"
    fields_desc = [BitField("u", 0, 1),
                   XBitField("type", 0x0301, 15),
                   ShortField("len", None),
                   IntField("id", 0),
                   AddressTLVField("address", None)]

# 3.5.7. Label Mapping Message


class LDPLabelMM(_LDP_Packet):
    name = "LDPLabelMM"
    fields_desc = [BitField("u", 0, 1),
                   XBitField("type", 0x0400, 15),
                   ShortField("len", None),
                   IntField("id", 0),
                   FecTLVField("fec", None),
                   LabelTLVField("label", 0)]

# 3.5.8. Label Request Message


class LDPLabelReqM(_LDP_Packet):
    name = "LDPLabelReqM"
    fields_desc = [BitField("u", 0, 1),
                   XBitField("type", 0x0401, 15),
                   ShortField("len", None),
                   IntField("id", 0),
                   FecTLVField("fec", None)]

# 3.5.9. Label Abort Request Message


class LDPLabelARM(_LDP_Packet):
    name = "LDPLabelARM"
    fields_desc = [BitField("u", 0, 1),
                   XBitField("type", 0x0404, 15),
                   ShortField("len", None),
                   IntField("id", 0),
                   FecTLVField("fec", None),
                   IntField("labelRMid", 0)]

# 3.5.10. Label Withdraw Message


class LDPLabelWM(_LDP_Packet):
    name = "LDPLabelWM"
    fields_desc = [BitField("u", 0, 1),
                   XBitField("type", 0x0402, 15),
                   ShortField("len", None),
                   IntField("id", 0),
                   FecTLVField("fec", None),
                   LabelTLVField("label", 0)]

# 3.5.11. Label Release Message


class LDPLabelRelM(_LDP_Packet):
    name = "LDPLabelRelM"
    fields_desc = [BitField("u", 0, 1),
                   XBitField("type", 0x0403, 15),
                   ShortField("len", None),
                   IntField("id", 0),
                   FecTLVField("fec", None),
                   LabelTLVField("label", 0)]

# 3.1. LDP PDUs


class LDP(_LDP_Packet):
    name = "LDP"
    fields_desc = [ShortField("version", 1),
                   ShortField("len", None),
                   IPField("id", "127.0.0.1"),
                   ShortField("space", 0)]

    def post_build(self, p, pay):
        pay = pay or b""
        if self.len is None:
            tmp_len = len(p) + len(pay) - 4
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        return p + pay


bind_bottom_up(TCP, LDP, sport=646)
bind_bottom_up(TCP, LDP, dport=646)
bind_bottom_up(TCP, UDP, sport=646)
bind_bottom_up(TCP, UDP, dport=646)
bind_layers(TCP, LDP, sport=646, dport=646)
bind_layers(UDP, LDP, sport=646, dport=646)
