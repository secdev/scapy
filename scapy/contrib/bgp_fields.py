#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""BGP-4 disector: fields for implementing MPBGP extensions"""

# import socket
# if not socket.has_ipv6:
#     raise socket.error("can't use AF_INET6, IPv6 is disabled")
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6

#from scapy  import *
from scapy.packet import Packet
from scapy.fields import Field, PacketListField
from scapy.layers.inet6 import IP6Field
import struct
import re
#
# Packet with padding
#
class PadPacket(Packet):
    """A packet that automatically extracts padding"""
    name = "PadPacket"
    fields_desc = []
    def extract_padding(self, pkt):
        return "", pkt
#
# Packet array
#
class PacketArrayField(PacketListField):
    """
Quick hack to chop BGPPackets in a TCP PDU into an array of BGP packets
Based on the fact that the BGP-4 header has a fixed field format:

@param name:        name of the array
@param default:     default value
@param cls:         class of the elements in the array
@param spkt_len(s): function that inspects the byte array s and
                    returns the length of the first packet in it."""
    __slots__ = ["spkt_len"]
    def __init__(self, name, default, cls, spkt_len=None):
        """We need that spkt_len is specified to know how to chop"""
        assert spkt_len is not None
        PacketListField.__init__(self, name, default, cls)
        self.spkt_len = spkt_len
    def getfield(self, pkt, s):
        """
Get one PacketField from the array,
using spkt_len to chop the string"""
        lst = []
        ret = ""
        remain = s
        l = self.spkt_len(s)
        remain, ret = s[:l], s[l:]
        while remain:
            try:
                p = self.m2i(pkt, remain)
            except Exception:
                raise
            else:
                lst.append(p)
            try:
                l = self.spkt_len(ret)
                # log_runtime.info ("Next one will be %d bytes long" % l)
                remain, ret = ret[:l], ret[l:]
            except:
                remain = ""
        return ret, lst
#
# --------- Prefixes in IPv4 and IPv6 -----------
#
class BGPIPField(Field):
    """Represents how bgp represents IPv4 prefixes
internal representation (mask, base)

Use socket.inet_ntop and _pton to reuse for IPv6 prefixes"""
    af = AF_INET
    alen = 4
    def mask2iplen(self, mask):
        """turn the mask into the length in bytes of the ip field"""
        return (mask + 7) // 8
    def h2i(self, pkt, h):
        """human x.x.x.x/y to internal"""
        if h is not None:
            ip, mask = re.split('/', h)
        else:
            ip, mask = '0' if self.af == AF_INET else "::", '0'
        return  int(mask), ip
    def i2h(self, pkt, i):
        mask, ip = i
        return ip + '/' + str(mask)
    def i2repr(self, pkt, i):
        """make it look nice"""
        return self.i2h(pkt, i)
    def i2len(self, pkt, i):
        """rely on integer division"""
        mask = i[0]
        return self.mask2iplen(mask) + 1
    def i2m(self, pkt, i):
        mask, ip = i
        ipbytes = inet_pton(self.af, ip)
        return struct.pack(">B", mask) + ipbytes[:self.mask2iplen(mask)]
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)
    def getfield(self, pkt, s):
        l = self.mask2iplen(ord(s[0])) + 1
        return s[l:], self.m2i(pkt, s[:l])
    def m2i(self, pkt, m):
        mask = ord(m[0])
        ml = self.mask2iplen(mask)
        ip = "".join([m[i + 1] if i < ml else '\x00' for i in range(self.alen)])
        return (mask, inet_ntop(self.af, ip))
#
# Derive IPv6 prefixes from IPv4Prefixes
#
class BGPIPv6Field(BGPIPField):
    """IPv6 prefixes only need constant changes
in the current implementation WRT IPv4 prefixes"""
    af = AF_INET6
    alen = 16

#
# -------------------------
#
class CommunityField(Field):
    """BGP Community field"""
    well_known = {
        "NO_EXPORT" : (0xFFFF, 0xFF01),
        "NO_ADVERTISE" : (0xFFFF, 0xFF02),
        "NO_EXPORT_SUBCONFED": (0xFFFF, 0xFF03),
    }
    def h2i(self, pkt, h):
        """human to internal (hi,lo)"""
        h = h.upper()
        if h in self.well_known.keys():
            return self.well_known[h]
        m = re.match(r"(\d+):(\d+)", h)
        return  int(m.group(1)), int(m.group(2))
    def i2h(self, pkt, i):
        for r in self.well_known:
            if i == self.well_known[r]:
                return r
        return "%d:%d" % i
    def i2repr(self, pkt, i):
        """make it look nice"""
        return self.i2h(pkt, i)
    def i2len(self, pkt, i):
        return 4
    def i2m(self, pkt, i):
        """internal to machine"""
        return struct.pack("!HH", i[0], i[1])
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)
    def getfield(self, pkt, s):
        return s[4:], self.m2i(pkt, s[:4])
    def m2i(self, pkt, m):
        return struct.unpack("!HH", m)

class AS4Field(Field):
    """4 byte AS numbers
Internal representation is hi,lo"""
    def h2i(self, pkt, h):
        """human to internal (hi,lo)"""
        m = re.match(r"(AS)?(\d+)(:(\d+))?", h)
        if m.group(4) is not None:
            return int(m.group(2)), int(m.group(4))
        else:
            return 0, int(m.group(2))
    def i2h(self, pkt, i):
        hi, lo = i
        if hi != 0:
            return "AS%d:%d" % (hi, lo)
        return "AS%d" % lo
    def i2repr(self, pkt, i):
        """make it look nice"""
        return self.i2h(pkt, i)
    def i2len(self, pkt, i):
        return 4
    def i2m(self, pkt, i):
        """internal to machine"""
        hi, lo = i
        return struct.pack("!HH", hi, lo)
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)
    def getfield(self, pkt, s):
        l = self.i2len(pkt, None)
        return s[l:], self.m2i(pkt, s[:l])
    def m2i(self, pkt, m):
        return struct.unpack("!HH", m)

class AS2Field(AS4Field):
    """4 byte AS numbers
Internal representation is short"""
    def h2i(self, pkt, h):
        """human to internal as short"""
        m = re.match(r"(AS)?(\d+)", h)
        return int(m.group(2))
    def i2h(self, pkt, i):
        return "AS%d" % i
    def i2len(self, pkt, i):
        return 2
    def i2m(self, pkt, i):
        """internal to machine"""
        return struct.pack("!H", i)
    def m2i(self, pkt, m):
        return struct.unpack("!H", m)
#
# Route Origin and Route Target extended communities
# Extended to cope with the Route Distinguisher fields
#
class RouteTargetField(Field):
    """Internal representation is shared by
route target, route origin and route distinguisher

subtype:    string
ash:        int (None for 16-bit AS, or IPv4)
asl:        int (None for IPv4)
ip:         string (IPv4 address, None for AS)
n:          int
"""
    humanRe = r"(r[ot] )?(((AS)?(\d+)(:(\d+))?)|(\d+(\.\d+)+)):(\d+)"
    def typ(self, ash, ip):
        """Get the type code (AS2, AS4 or IP)"""
        if ip is not None:
            return 1
        if ash is not None:
            return 2
        return 0

    def subtyp(self, name):
        """Subtype code"""
        return {'rt' : 2, 'ro': 3}[name]

    def h2i(self, pkt, h):
        """Human to internal representation"""
        g = re.match(self.humanRe, h)
        if g is not None:
            subtyp = g.group(1)
            if subtyp is None:
                subtyp = 'rt'
            if len(subtyp) > 2:
                subtyp = subtyp[:2]
            # Put all possible fields of the organization code to None
            # and the fill the ones that are applicable
            ip = None
            ash = None
            asl = None
            if g.group(5) is None:
                ip = g.group(2)
            elif g.group(7) is not None:
                asl = int(g.group(7))
                ash = int(g.group(5))
            else:
                asl = int(g.group(5))
            n = int(g.group(10))
        return subtyp, ash, asl, ip, n

    def i2h(self, pkt, i):
        """Internal to human"""
        subt, ash, asl, ip, n = i
        t = self.typ(ash, ip)
        if subt is None:
            subt = ""
        if len(subt) > 3:
            subt = subt[:3]
        if len(subt) == 2:
            subt += " "
        if t == 0:
            human = "%d:%d" % (asl, n)
            if asl + n != 0:
                human = "AS"+human
        elif t == 1:
            human = "%s:%d" % (ip, n)
        else:
            human = "AS%d:%d:%d" % (ash, asl, n)
        return subt + human

    def i2repr(self, pkt, i):
        """make it look nice"""
        return self.i2h(pkt, i)

    def i2len(self, pkt, i):
        """This will be always 8 bytes"""
        return 8

    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)

    def getfield(self, pkt, s):
        l = self.i2len(pkt, s)
        return s[l:], self.m2i(pkt, s[:l])

    def i2m(self, pkt, internal):
        """Internal representation to machine"""
        subt, ash, asl, ip, n = internal
        t = self.typ(ash, ip)
        s = self.subtyp(subt)
        if t == 0:
            return struct.pack("!BBHI", t, s, asl, n)
        elif t == 1:
            return struct.pack("!BB4sH", t, s, inet_pton(AF_INET, ip), n)
        else:
            return struct.pack("!BBHHH", t, s, ash, asl, n)
    def m2i(self, pkt, machine):
        """Machine to internal representation"""
        t, s = struct.unpack("!BB", machine[:2])
        subt = {2:'rt', 3:'ro'}[s]
        ash = None
        asl = None
        ip = None
        n = 0
        if t == 0:              # 0, asl (2bytes), ip=None, n (4bytes)
            asl, n = struct.unpack("!HI", machine[2:])
        elif t == 1:            # 0, 0, ip (4bytes), n (2bytes)
            ipn, n = struct.unpack("!4sH", machine[2:])
            ip = inet_ntop(AF_INET, ipn)
        elif t == 2:            # ash, asl, None, n (all 2 bytes)
            ash, asl, n = struct.unpack("!HHH", machine[2:])
        return subt, ash, asl, ip, n

class RouteDistinguisherField(RouteTargetField):
    """The route distinguisher has a shared human readable representation
but the internal representation changes"""
    humanRe = r"(rd )?(((AS)?(\d+)(:(\d+))?)|(\d+(\.\d+)+)):(\d+)"
    def i2m(self, pkt, internal):
        _, ash, asl, ip, n = internal
        t = self.typ(ash, ip)
        if t == 0:
            return struct.pack("!HHI", t, asl, n)
        elif t == 1:
            return struct.pack("!H4sH", t, inet_pton(AF_INET, ip), n)
        else:
            return struct.pack("!HHHH", t, ash, asl, n)
    def m2i(self, pkt, machine):
        """Machine to internal conversion"""
        subt = "rd"
        ash = None
        asl = None
        ip = None
        n = 0
        t = struct.unpack("!H", machine[:2])[0]
        if t == 0:
            t, asl, n = struct.unpack("!HHI", machine)
        elif t == 1:
            t, ipn, n = struct.unpack("!H4sH", machine)
            ip = inet_ntop(AF_INET, ipn)
        elif t == 2:
            t, ash, asl, n = struct.unpack("!HHHH", machine)
        return subt, ash, asl, ip, n
