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


from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.fields import *
from scapy.packet import *
from scapy.volatile import *
from scapy.config import conf
from scapy.sendrecv import sr,sr1,srp1
from scapy.as_resolvers import AS_resolver_riswhois
from scapy.supersocket import SuperSocket,L3RawSocket
from scapy.arch import *
from scapy.utils6 import *


#############################################################################
# Helpers                                                                  ##
#############################################################################

def get_cls(name, fallback_cls):
    return globals().get(name, fallback_cls)


##########################
## Neighbor cache stuff ##
##########################

conf.netcache.new_cache("in6_neighbor", 120)

def neighsol(addr, src, iface, timeout=1, chainCC=0):
    """
    Sends an ICMPv6 Neighbor Solicitation message to get the MAC address
    of the neighbor with specified IPv6 address addr. 'src' address is 
    used as source of the message. Message is sent on iface. By default,
    timeout waiting for an answer is 1 second.

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

def getmacbyip6(ip6, chainCC=0):
    """
    Returns the mac address to be used for provided 'ip6' peer. 
    neighborCache.get() method is used on instantiated neighbor cache.
    Resolution mechanism is described in associated doc string.

    (chainCC parameter value ends up being passed to sending function
     used to perform the resolution, if needed)
    """

    if in6_ismaddr(ip6): # Multicast 
        mac = in6_getnsmac(inet_pton(socket.AF_INET6, ip6))
        return mac

    iff,a,nh = conf.route6.route(ip6, dev=conf.iface6)

    if iff == LOOPBACK_NAME:
        return "ff:ff:ff:ff:ff:ff"

    if nh != '::': 
        ip6 = nh # Found next hop

    mac = conf.netcache.in6_neighbor.get(ip6)
    if mac:
        return mac

    res = neighsol(ip6, a, iff, chainCC=chainCC)

    if res is not None:
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
    ipaddress = re.compile(r"^([a-fA-F0-9:]+)(/[1]?[0-3]?[0-9])?$")

    def __init__(self, net):
        self.repr = net

        tmp = net.split('/')+["128"]
        if not self.ipaddress.match(net):
            tmp[0]=socket.getaddrinfo(tmp[0], None, socket.AF_INET6)[0][-1][0]

        netmask = int(tmp[1])
        self.net = inet_pton(socket.AF_INET6, tmp[0])
        self.mask = in6_cidr2mask(netmask)
        self.plen = netmask

    def __iter__(self):
        def m8(i):
            if i % 8 == 0:
                return i
        tuple = filter(lambda x: m8(x), xrange(8, 129))

        a = in6_and(self.net, self.mask)
        tmp = map(lambda x:  x, struct.unpack('16B', a))
   
        def parse_digit(a, netmask):
            netmask = min(8,max(netmask,0))
            a = (int(a) & (0xffL<<netmask),(int(a) | (0xffL>>(8-netmask)))+1)
            return a
        self.parsed = map(lambda x,y: parse_digit(x,y), tmp, map(lambda x,nm=self.plen: x-nm, tuple))

        def rec(n, l): 
            if n and  n % 2 == 0:
                sep = ':'
            else:       
                sep = ''
            if n == 16:
                return l
            else:
                ll = []
                for i in xrange(*self.parsed[n]):
                    for y in l:
                        ll += [y+sep+'%.2x'%i]
                return rec(n+1, ll)

        return iter(rec(0, ['']))

    def __repr__(self):
        return "<Net6 %s>" % self.repr






#############################################################################
#############################################################################
###                              IPv6 Class                               ###
#############################################################################
#############################################################################

class IP6Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "16s")
    def h2i(self, pkt, x):
        if type(x) is str:
            try:
                x = in6_ptop(x)
            except socket.error:
                x = Net6(x)
        elif type(x) is list:
            x = map(Net6, x)
        return x
    def i2m(self, pkt, x):
        return inet_pton(socket.AF_INET6, x)
    def m2i(self, pkt, x):
        return inet_ntop(socket.AF_INET6, x)
    def any2i(self, pkt, x):
        return self.h2i(pkt,x)
    def i2repr(self, pkt, x):
        if x is None:
            return self.i2h(pkt,x)
        elif not isinstance(x, Net6) and not type(x) is list:
            if in6_isaddrTeredo(x):   # print Teredo info
                server, flag, maddr, mport = teredoAddrExtractInfo(x)     
                return "%s [Teredo srv: %s cli: %s:%s]" % (self.i2h(pkt, x), server, maddr,mport)
            elif in6_isaddr6to4(x):   # print encapsulated address
                vaddr = in6_6to4ExtractAddr(x)
                return "%s [6to4 GW: %s]" % (self.i2h(pkt, x), vaddr)
        return self.i2h(pkt, x)       # No specific information to return

class SourceIP6Field(IP6Field):
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
            dst=getattr(pkt,self.dstname)
            if isinstance(dst,Gen):
                r = map(conf.route6.route, dst)
                r.sort()
                if r[0] == r[-1]:
                    x=r[0][1]
                else:
                    warning("More than one possible route for %s"%repr(dst))
                    return None
            else:
                iff,x,nh = conf.route6.route(dst)
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
        if type(i) is list:
            return len(i)
        return 0
    
    def getfield(self, pkt, s):
        c = l = None
        if self.length_from is not None:
            l = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)
            
        lst = []
        ret = ""
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
        s = ''
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
        if self.nh == 58 and len(p) > 2:
            t = ord(p[0])
            if t == 139 or t == 140: # Node Info Query 
                return _niquery_guesser(p)
            return get_cls(icmp6typescls.get(t,"Raw"), "Raw")
        elif self.nh == 135 and len(p) > 3:
            return _mip6_mhtype2cls.get(ord(p[2]), MIP6MH_Generic)
        else:
            return get_cls(ipv6nhcls.get(self.nh,"Raw"), "Raw")

class IPv6(_IPv6GuessPayload, Packet, IPTools):
    name = "IPv6"
    fields_desc = [ BitField("version" , 6 , 4),
                    BitField("tc", 0, 8), #TODO: IPv6, ByteField ?
                    BitField("fl", 0, 20),
                    ShortField("plen", None),
                    ByteEnumField("nh", 59, ipv6nh),
                    ByteField("hlim", 64),
                    SourceIP6Field("src", "dst"), # dst is for src @ selection
                    IP6Field("dst", "::1") ]

    def route(self):
        dst = self.dst
        if isinstance(dst,Gen):
            dst = iter(dst).next()
        return conf.route6.route(dst)

    def mysummary(self):
        return "%s > %s (%i)" % (self.src,self.dst, self.nh)

    def post_build(self, p, pay):
        p += pay
        if self.plen is None:
            l = len(p) - 40
            p = p[:4]+struct.pack("!H", l)+p[6:]
        return p

    def extract_padding(self, s):
        l = self.plen
        return s[:l], s[l:]

    def hashret(self):
        if self.nh == 58 and isinstance(self.payload, _ICMPv6):
            if self.payload.type < 128:
                return self.payload.payload.hashret()
            elif (self.payload.type in [133,134,135,136,144,145]):
                return struct.pack("B", self.nh)+self.payload.hashret()

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

        if conf.checkIPsrc and conf.checkIPaddr:
            sd = inet_pton(socket.AF_INET6, sd)
            ss = inet_pton(socket.AF_INET6, self.src)
            return struct.pack("B",nh)+self.payload.hashret()
        else:
            return struct.pack("B", nh)+self.payload.hashret()

    def answers(self, other):
        if not isinstance(other, IPv6): # self is reply, other is request
            return False
        if conf.checkIPaddr: 
            ss = inet_pton(socket.AF_INET6, self.src)
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
            return self.payload.answers(other.payload.payload) 
        elif other.nh == 44 and isinstance(other.payload, IPv6ExtHdrFragment):
            return self.payload.answers(other.payload.payload) 
        elif other.nh == 43 and isinstance(other.payload, IPv6ExtHdrRouting):
            return self.payload.answers(other.payload.payload) # Buggy if self.payload is a IPv6ExtHdrRouting
        elif other.nh == 60 and isinstance(other.payload, IPv6ExtHdrDestOpt):
            return self.payload.payload.answers(other.payload.payload)
        elif self.nh == 60 and isinstance(self.payload, IPv6ExtHdrDestOpt): # BU in reply to BRR, for instance
            return self.payload.payload.answers(other.payload)
        else:
            if (self.nh != other.nh):
                return False
            return self.payload.answers(other.payload)


conf.neighbor.register_l3(Ether, IPv6, lambda l2,l3: getmacbyip6(l3.dst))


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
                    s1 = str(selfup)
                    s2 = str(otherup)
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

                s1 = str(selfup)
                s2 = str(otherup)
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
    ph6s = str(ph6)
    return checksum(ph6s+p)


#############################################################################
#############################################################################
###                         Extension Headers                             ###
#############################################################################
#############################################################################


# Inherited by all extension header classes 
class _IPv6ExtHdr(_IPv6GuessPayload, Packet):
    name = 'Abstract IPV6 Option Header'
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
                                    2: "Datagram contains an Active Network message" }) ]
    # TODO : Check IANA has not defined new values for value field of RouterAlertOption
    # TODO : now that we have that option, we should do something in MLD class that need it
    def alignment_delta(self, curpos): # alignment requirement : 2n+0
        x = 2 ; y = 0
        delta = x*((curpos - y + x - 1)/x) + y - curpos 
        return delta

class Jumbo(Packet): # IPv6 Hop-By-Hop Option
    name = "Jumbo Payload" 
    fields_desc = [_OTypeField("otype", 0xC2, _hbhopts),
                   ByteField("optlen", 4),
                   IntField("jumboplen", None) ]
    def alignment_delta(self, curpos): # alignment requirement : 4n+2
        x = 4 ; y = 2
        delta = x*((curpos - y + x - 1)/x) + y - curpos 
        return delta

class HAO(Packet): # IPv6 Destination Options Header Option
    name = "Home Address Option"
    fields_desc = [_OTypeField("otype", 0xC9, _hbhopts),
                   ByteField("optlen", 16),
                   IP6Field("hoa", "::") ]
    def alignment_delta(self, curpos): # alignment requirement : 8n+6
        x = 8 ; y = 6
        delta = x*((curpos - y + x - 1)/x) + y - curpos 
        return delta

_hbhoptcls = { 0x00: Pad1,
               0x01: PadN,
               0x05: RouterAlert,
               0xC2: Jumbo,
               0xC9: HAO }


######################## Hop-by-Hop Extension Header ########################

class _HopByHopOptionsField(PacketListField):
    islist = 1
    holds_packet = 1
    def __init__(self, name, default, cls, curpos, count_from=None, length_from=None):
        self.curpos = curpos
        PacketListField.__init__(self, name, default, cls, count_from=count_from, length_from=length_from)
    
    def i2len(self, pkt, i):
        l = len(self.i2m(pkt, i))
        return l

    def i2count(self, pkt, i):
        if type(i) is list:
            return len(i)
        return 0

    def getfield(self, pkt, s):
        c = l = None
        if self.length_from is not None:
            l = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)
            
        opt = []
        ret = ""
        x = s
        if l is not None:
            x,ret = s[:l],s[l:]
        while x:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            o = ord(x[0]) # Option type
            cls = self.cls
            if _hbhoptcls.has_key(o):
                cls = _hbhoptcls[o]
            try:
                op = cls(x)
            except:
                op = self.cls(x)
            opt.append(op)
            if isinstance(op.payload, Raw):
                x = op.payload.load
                del(op.payload)
            else:
                x = ""
        return x+ret,opt

    def i2m(self, pkt, x):
        autopad = None
        try:
            autopad = getattr(pkt, "autopad") # Hack : 'autopad' phantom field
        except:
            autopad = 1
            
        if not autopad:
            return "".join(map(str, x))

        curpos = self.curpos
        s = ""
        for p in x:
            d = p.alignment_delta(curpos)
            curpos += d
            if d == 1:
                s += str(Pad1())
            elif d != 0:
                s += str(PadN(optdata='\x00'*(d-2)))
            pstr = str(p)
            curpos += len(pstr)
            s += pstr
            
        # Let's make the class including our option field
        # a multiple of 8 octets long
        d = curpos % 8
        if d == 0:
            return s
        d = 8 - d
        if d == 1:
            s += str(Pad1())
        elif d != 0:
            s += str(PadN(optdata='\x00'*(d-2)))        

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
                                  adjust = lambda pkt,x: (x+2+7)/8 - 1), 
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _HopByHopOptionsField("options", [], HBHOptUnknown, 2,
                                          length_from = lambda pkt: (8*(pkt.len+1))-2) ]
    overload_fields = {IPv6: { "nh": 0 }}


######################## Destination Option Header ##########################

class IPv6ExtHdrDestOpt(_IPv6ExtHdr):    
    name = "IPv6 Extension Header - Destination Options Header"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    FieldLenField("len", None, length_of="options", fmt="B",
                                  adjust = lambda pkt,x: (x+2+7)/8 - 1), 
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


def defragment6(pktlist):
    """
    Performs defragmentation of a list of IPv6 packets. Packets are reordered.
    Crap is dropped. What lacks is completed by 'X' characters.
    """
    
    l = filter(lambda x: IPv6ExtHdrFragment in x, pktlist) # remove non fragments
    if not l:
        return []

    id = l[0][IPv6ExtHdrFragment].id 

    llen = len(l)
    l = filter(lambda x: x[IPv6ExtHdrFragment].id == id, l)
    if len(l) != llen:
        warning("defragment6: some fragmented packets have been removed from list")
    llen = len(l)

    # reorder fragments 
    i = 0 
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
    fragmentable = ""
    for p in res:
        q=p[IPv6ExtHdrFragment]
        offset = 8*q.offset
        if offset != len(fragmentable):
            warning("Expected an offset of %d. Found %d. Padding with XXXX" % (len(fragmentable), offset))
        fragmentable += "X"*(offset - len(fragmentable))
        fragmentable += str(q.payload)

    # Regenerate the unfragmentable part.
    q = res[0]
    nh = q[IPv6ExtHdrFragment].nh
    q[IPv6ExtHdrFragment].underlayer.nh = nh
    q[IPv6ExtHdrFragment].underlayer.payload = None
    q /= Raw(load=fragmentable)
    
    return IPv6(str(q))


def fragment6(pkt, fragSize):
    """
    Performs fragmentation of an IPv6 packet. Provided packet ('pkt') must already 
    contain an IPv6ExtHdrFragment() class. 'fragSize' argument is the expected
    maximum size of fragments (MTU). The list of packets is returned.

    If packet does not contain an IPv6ExtHdrFragment class, it is returned in
    result list.
    """

    pkt = pkt.copy()
    s = str(pkt) # for instantiation to get upper layer checksum right

    if len(s) <= fragSize:
        return [pkt]

    if not IPv6ExtHdrFragment in pkt:
        # TODO : automatically add a fragment before upper Layer
        #        at the moment, we do nothing and return initial packet
        #        as single element of a list
        return [pkt]

    # Fragmentable part : fake IPv6 for Fragmentable part length computation
    fragPart = pkt[IPv6ExtHdrFragment].payload
    tmp = str(IPv6(src="::1", dst="::1")/fragPart)
    fragPartLen = len(tmp) - 40  # basic IPv6 header length
    fragPartStr = s[-fragPartLen:]

    # Grab Next Header for use in Fragment Header
    nh = IPv6(tmp[:40]).nh

    # Keep fragment header
    fragHeader = pkt[IPv6ExtHdrFragment]
    fragHeader.payload = None # detach payload

    # Unfragmentable Part
    unfragPartLen = len(s) - fragPartLen - 8
    unfragPart = pkt
    pkt[IPv6ExtHdrFragment].underlayer.payload = None # detach payload

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
            fragOffset += (innerFragSize / 8)  # compute new one
            if IPv6 in unfragPart:  
                unfragPart[IPv6].plen = None
            tempo = unfragPart/fragHeader/Raw(load=tmp)
            res.append(tempo)
        else:
            fragHeader.offset = fragOffset    # update offSet
            fragHeader.m = 0
            if IPv6 in unfragPart:
                unfragPart[IPv6].plen = None
            tempo = unfragPart/fragHeader/Raw(load=remain)
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
                   130: "ICMPv6MLQuery", 
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
                  #143: Do Me - RFC 3810
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
             143 : "Version 2 Multicast Listener Report",
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
                    XIntField("unused",0x00000000)]

class ICMPv6PacketTooBig(_ICMPv6Error):
    name = "ICMPv6 Packet Too Big"
    fields_desc = [ ByteEnumField("type",2, icmp6types),
                    ByteField("code",0),
                    XShortField("cksum", None),
                    IntField("mtu",1280)]
    
class ICMPv6TimeExceeded(_ICMPv6Error):
    name = "ICMPv6 Time Exceeded"
    fields_desc = [ ByteEnumField("type",3, icmp6types),
                    ByteField("code",{ 0: "hop limit exceeded in transit",
                                       1: "fragment reassembly time exceeded"}),
                    XShortField("cksum", None),
                    XIntField("unused",0x00000000)]

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
    __metaclass__ = NewDefaultValues
    type = 129
    def answers(self, other):
        # We could match data content between request and reply. 
        return (isinstance(other, ICMPv6EchoRequest) and
                self.id == other.id and self.seq == other.seq and
                self.data == other.data)


############ ICMPv6 Multicast Listener Discovery (RFC3810) ##################

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
                    IP6Field("mladdr",None)]

# general queries are sent to the link-scope all-nodes multicast
# address ff02::1, with a multicast address field of 0 and a MRD of
# [Query Response Interval]
# Default value for mladdr is set to 0 for a General Query, and
# overloaded by the user for a Multicast Address specific query
# TODO : See what we can do to automatically include a Router Alert
#        Option in a Destination Option Header.
class ICMPv6MLQuery(_ICMPv6ML): # RFC 2710
    name = "MLD - Multicast Listener Query"
    __metaclass__ = NewDefaultValues
    type   = 130
    mrd    = 10000
    mladdr = "::" # 10s for mrd
    overload_fields = {IPv6: { "dst": "ff02::1", "hlim": 1 }} 
    def hashret(self):
        if self.mladdr != "::":
            return struct.pack("HH",self.mladdr)+self.payload.hashret()
        else:
            return self.payload.hashret()
        
    
# TODO : See what we can do to automatically include a Router Alert
#        Option in a Destination Option Header.
class ICMPv6MLReport(_ICMPv6ML): # RFC 2710
    name = "MLD - Multicast Listener Report"
    __metaclass__ = NewDefaultValues
    type = 131
    overload_fields = {IPv6: {"hlim": 1}}
    # implementer le hashret et le answers
    
# When a node ceases to listen to a multicast address on an interface,
# it SHOULD send a single Done message to the link-scope all-routers
# multicast address (FF02::2), carrying in its multicast address field
# the address to which it is ceasing to listen
# TODO : See what we can do to automatically include a Router Alert
#        Option in a Destination Option Header.
class ICMPv6MLDone(_ICMPv6ML): # RFC 2710
    name = "MLD - Multicast Listener Done"
    __metaclass__ = NewDefaultValues
    type = 132
    overload_fields = {IPv6: { "dst": "ff02::2", "hlim": 1}}


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
                  #11: Do Me,
                  #12: Do Me,
                  #13: Do Me,
                  #14: Do Me,
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
                  26: "ICMPv6NDOptEFA"
                  }

class _ICMPv6NDGuessPayload:
    name = "Dummy ND class that implements guess_payload_class()"
    def guess_payload_class(self,p):
        if len(p) > 1:
            return get_cls(icmp6ndoptscls.get(ord(p[0]),"Raw"), "Raw") # s/Raw/ICMPv6NDOptUnknown/g ?


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
    __metaclass__ = NewDefaultValues
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
                    XIntField("validlifetime",0xffffffffL),
                    XIntField("preferredlifetime",0xffffffffL),
                    XIntField("res2",0x00000000),
                    IP6Field("prefix","::") ]
    def mysummary(self):                        
        return self.sprintf("%name% %prefix%")

# TODO: We should also limit the size of included packet to something
# like (initiallen - 40 - 2)
class TruncPktLenField(PacketLenField):

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
            return Raw(m)
        return s

    def i2m(self, pkt, x):
        s = str(x)
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
                                  adjust = lambda pkt,x:(x+4)/8),
                    XShortField("res",0),
                    TruncPktLenField("pkt", "", IPv6, 4,
                                     length_from = lambda pkt: 8*pkt.len-4) ]

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


class IP6PrefixField(IP6Field):
    def __init__(self, name, default):
        IP6Field.__init__(self, name, default)
        self.length_from = lambda pkt: 8*(pkt.len - 1)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        p = s[:l]
        if l < 16:
            p += '\x00'*(16-l)
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
            return ""
        if l in [2, 3]:
            return x[:8*(l-1)]

        return x + '\x00'*8*(l-3)

class ICMPv6NDOptRouteInfo(_ICMPv6NDGuessPayload, Packet): # RFC 4191
    name = "ICMPv6 Neighbor Discovery Option - Route Information Option"
    fields_desc = [ ByteField("type",24),
                    FieldLenField("len", None, length_of="prefix", fmt="B",
                                  adjust = lambda pkt,x: x/8 + 1),
                    ByteField("plen", None),
                    BitField("res1",0,3),
                    BitField("prf",0,2),
                    BitField("res2",0,3),
                    IntField("rtlifetime", 0xffffffff),
                    IP6PrefixField("prefix", None) ]
  
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
                    BitField("R",0,1),
                    BitField("S",0,1),
                    BitField("O",0,1),
                    XBitField("res",0,29),
                    IP6Field("tgt","::") ]
    overload_fields = {IPv6: { "nh": 58, "dst": "ff02::1", "hlim": 255 }}

    def mysummary(self):
        return self.sprintf("%name% (tgt: %tgt%)")

    def hashret(self):
        return self.tgt+self.payload.hashret() 

class ICMPv6ND_NA(ICMPv6ND_NS):
    name = "ICMPv6 Neighbor Discovery - Neighbor Advertisement"
    __metaclass__ = NewDefaultValues
    type = 136
    R    = 1
    O    = 1

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
                    StrFixedLenField("res", "\x00"*6, 6),
                    IP6ListField("addrlist", [],
                                length_from = lambda pkt: 8*(pkt.len-1)) ]

class ICMPv6NDOptTgtAddrList(ICMPv6NDOptSrcAddrList):
    name = "ICMPv6 Inverse Neighbor Discovery Option - Target Address List"
    __metaclass__ = NewDefaultValues
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

#############################################################################
###                           LLMNR (RFC4795)                             ###
#############################################################################
# LLMNR is based on the DNS packet format (RFC1035 Section 4)
# RFC also envisions LLMNR over TCP. Like vista, we don't support it -- arno

_LLMNR_IPv6_mcast_Addr = "FF02:0:0:0:0:0:1:3"
_LLMNR_IPv4_mcast_addr = "224.0.0.252"

class LLMNRQuery(Packet):
    name = "Link Local Multicast Node Resolution - Query"
    fields_desc = [ ShortField("id", 0),
                    BitField("qr", 0, 1),
                    BitEnumField("opcode", 0, 4, { 0:"QUERY" }),
                    BitField("c", 0, 1),
                    BitField("tc", 0, 2),
                    BitField("z", 0, 4),
                    BitEnumField("rcode", 0, 4, { 0:"ok" }),
                    DNSRRCountField("qdcount", None, "qd"),
                    DNSRRCountField("ancount", None, "an"),
                    DNSRRCountField("nscount", None, "ns"),
                    DNSRRCountField("arcount", None, "ar"),
                    DNSQRField("qd", "qdcount"),
                    DNSRRField("an", "ancount"),
                    DNSRRField("ns", "nscount"),
                    DNSRRField("ar", "arcount",0)]
    overload_fields = {UDP: {"sport": 5355, "dport": 5355 }}
    def hashret(self):
        return struct.pack("!H", id)

class LLMNRResponse(LLMNRQuery):
    name = "Link Local Multicast Node Resolution - Response"
    __metaclass__ = NewDefaultValues
    qr = 1
    fields_desc = []

    def answers(self, other):
        return (isinstance(other, LLMNRQuery) and
                self.id == other.id and
                self.qr == 1 and
                other.qr == 0)

def _llmnr_dispatcher(x, *args, **kargs):
    cls = Raw
    if len(x) >= 3:
        if (ord(x[4]) & 0x80): # Response
            cls = LLMNRResponse
        else:                  # Query
            cls = LLMNRQuery
    return cls(x, *args, **kargs)

bind_bottom_up(UDP, _llmnr_dispatcher, { "dport": 5355 })
bind_bottom_up(UDP, _llmnr_dispatcher, { "sport": 5355 })

# LLMNRQuery(id=RandShort(), qd=DNSQR(qname="vista.")))




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
        return self.nonce

class _ICMPv6NIAnswers:
    def answers(self, other):
        return self.nonce == other.nonce

# Buggy; always returns the same value during a session
class NonceField(StrFixedLenField):
    def __init__(self, name, default=None):
        StrFixedLenField.__init__(self, name, default, 8)
        if default is None:
            self.default = self.randval()

# Compute the NI group Address. Can take a FQDN as input parameter
def computeNIGroupAddr(name):
    import md5
    name = name.lower().split(".")[0]
    record = chr(len(name))+name
    h = md5.new(record)
    h = h.digest()
    addr = "ff02::2:%2x%2x:%2x%2x" % struct.unpack("BBBB", h[:4])
    return addr


# Here is the deal. First, that protocol is a piece of shit. Then, we 
# provide 4 classes for the different kinds of Requests (one for every
# valid qtype: NOOP, Node Name, IPv6@, IPv4@). They all share the same
# data field class that is made to be smart by guessing the specifc 
# type of value provided : 
#
# - IPv6 if acceptable for inet_pton(AF_INET6, ): code is set to 0,
#   if not overriden by user
# - IPv4 if acceptable for inet_pton(AF_INET,  ): code is set to 2,
#   if not overriden
# - Name in the other cases: code is set to 0, if not overriden by user
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
    
    if type(x) is str:
        if x and x[-1] == '\x00': # stupid heuristic
            return x
        x = [x]

    res = []
    for n in x:
        termin = "\x00"
        if n.count('.') == 0: # single-component gets one more
            termin += '\x00' 
        n = "".join(map(lambda y: chr(len(y))+y, n.split("."))) + termin
        res.append(n)
    return "".join(res)


def dnsrepr2names(x):
    """
    Take as input a DNS encoded string (possibly compressed) 
    and returns a list of DNS names contained in it.
    If provided string is already in printable format
    (does not end with a null character, a one element list
    is returned). Result is a list.
    """
    res = []
    cur = ""
    while x:
        l = ord(x[0])
        x = x[1:]
        if l == 0:
            if cur and cur[-1] == '.':
                cur = cur[:-1]
            res.append(cur)
            cur = ""
            if x and ord(x[0]) == 0: # single component
                x = x[1:]
            continue
        if l & 0xc0: # XXX TODO : work on that -- arno
            raise Exception("DNS message can't be compressed at this point!")
        else:
            cur += x[:l]+"."
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
        if x is tuple and type(x[0]) is int:
            return x

        val = None
        try: # Try IPv6
            inet_pton(socket.AF_INET6, x)
            val = (0, x)
        except:
            try: # Try IPv4
                inet_pton(socket.AF_INET, x)
                val = (2, x)
            except: # Try DNS
                if x is None:
                    x = ""
                x = names2dnsrepr(x)
                val = (1, x)
        return val

    def i2repr(self, pkt, x):
        t,val = x
        if t == 1: # DNS Name
            # we don't use dnsrepr2names() to deal with 
            # possible weird data extracted info
            res = []
            weird = None
            while val:
                l = ord(val[0]) 
                val = val[1:]
                if l == 0:
                    if (len(res) > 1 and val): # fqdn with data behind
                        weird = val
                    elif len(val) > 1: # single label with data behind
                        weird = val[1:]
                    break
                res.append(val[:l]+".")
                val = val[l:]
            tmp = "".join(res)
            if tmp and tmp[-1] == '.':
                tmp = tmp[:-1]
            return tmp
        return repr(val)

    def getfield(self, pkt, s):
        qtype = getattr(pkt, "qtype")
        if qtype == 0: # NOOP
            return s, (0, "")
        else:
            code = getattr(pkt, "code")
            if code == 0:   # IPv6 Addr
                return s[16:], (0, inet_ntop(socket.AF_INET6, s[:16]))
            elif code == 2: # IPv4 Addr
                return s[4:], (2, inet_ntop(socket.AF_INET, s[:4]))
            else:           # Name or Unknown
                return "", (1, s)

    def addfield(self, pkt, s, val):
        if ((type(val) is tuple and val[1] is None) or
            val is None):
            val = (1, "")
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
    __metaclass__ = NewDefaultValues
    qtype = 2 

# We ask for the IPv6 address of the peer 
class ICMPv6NIQueryIPv6(ICMPv6NIQueryNOOP):
    name = "ICMPv6 Node Information Query - IPv6 Address Query"
    __metaclass__ = NewDefaultValues
    qtype = 3
    flags = 0x3E

class ICMPv6NIQueryIPv4(ICMPv6NIQueryNOOP): 
    name = "ICMPv6 Node Information Query - IPv4 Address Query"
    __metaclass__ = NewDefaultValues
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
        if type(x) is not tuple:
            if pkt is not None:
                qtype = getattr(pkt, "qtype")
        else:
            qtype = x[0]
            x = x[1]

        # From that point on, x is the value (second element of the tuple)

        if qtype == 2: # DNS name
            if type(x) is str: # listify the string
                x = [x]
            if type(x) is list and x and type(x[0]) is not int: # ttl was omitted : use 0
                x = [0] + x
            ttl = x[0]
            names = x[1:]
            return (2, [ttl, names2dnsrepr(names)])

        elif qtype in [3, 4]: # IPv4 or IPv6 addr
            if type(x) is str:
                x = [x] # User directly provided an IP, instead of list

            # List elements are not tuples, user probably
            # omitted ttl value : we will use 0 instead
            def addttl(x):
                if type(x) is str:
                    return (0, x)
                return x

            return (qtype, map(addttl, x))

        return (qtype, x)


    def addfield(self, pkt, s, val):
        t,tmp = val
        if tmp is None:
            tmp = ""
        if t == 2:
            ttl,dnsstr = tmp
            return s+ struct.pack("!I", ttl) + dnsstr
        elif t == 3:
            return s + "".join(map(lambda (x,y): struct.pack("!I", x)+inet_pton(socket.AF_INET6, y), tmp))
        elif t == 4:
            return s + "".join(map(lambda (x,y): struct.pack("!I", x)+inet_pton(socket.AF_INET, y), tmp))
        else:
            return s + tmp
                
    def getfield(self, pkt, s):
        code = getattr(pkt, "code")
        if code != 0:
            return s, (0, "")

        qtype = getattr(pkt, "qtype")        
        if qtype == 0: # NOOP
            return s, (0, "")

        elif qtype == 2:
            if len(s) < 4:
                return s, (0, "")
            ttl = struct.unpack("!I", s[:4])[0]
            return "", (2, [ttl, s[4:]])

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
            return "", (0, s)

    def i2repr(self, pkt, x):
        if x is None:
            return "[]"
        
        if type(x) is tuple and len(x) == 2:
            t, val = x
            if t == 2: # DNS names
                ttl,l = val
                l = dnsrepr2names(l)
                return "ttl:%d %s" % (ttl, ", ".join(l))
            elif t == 3 or t == 4:
                return "[ %s ]" % (", ".join(map(lambda (x,y): "(%d, %s)" % (x, y), val)))
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
    __metaclass__ = NewDefaultValues
    qtype = 2

class ICMPv6NIReplyIPv6(ICMPv6NIReplyNOOP): 
    name = "ICMPv6 Node Information Reply - IPv6 addresses"
    __metaclass__ = NewDefaultValues
    qtype = 3

class ICMPv6NIReplyIPv4(ICMPv6NIReplyNOOP): 
    name = "ICMPv6 Node Information Reply - IPv4 addresses"
    __metaclass__ = NewDefaultValues
    qtype = 4

class ICMPv6NIReplyRefuse(ICMPv6NIReplyNOOP):
    name = "ICMPv6 Node Information Reply - Responder refuses to supply answer"
    __metaclass__ = NewDefaultValues
    code = 1

class ICMPv6NIReplyUnknown(ICMPv6NIReplyNOOP):
    name = "ICMPv6 Node Information Reply - Qtype unknown to the responder"
    __metaclass__ = NewDefaultValues
    code = 2


def _niquery_guesser(p):
    cls = Raw
    type = ord(p[0])
    if type == 139: # Node Info Query specific stuff
        if len(p) > 6:
            qtype, = struct.unpack("!H", p[4:6])
            cls = { 0: ICMPv6NIQueryNOOP,
                    2: ICMPv6NIQueryName,
                    3: ICMPv6NIQueryIPv6,
                    4: ICMPv6NIQueryIPv4 }.get(qtype, Raw)
    elif type == 140: # Node Info Reply specific stuff
        code = ord(p[1])
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
###                                DHCPv6                                 ###
#############################################################################
#############################################################################

All_DHCP_Relay_Agents_and_Servers = "ff02::1:2" 
All_DHCP_Servers = "ff05::1:3"  # Site-Local scope : deprecated by 3879

dhcp6opts = { 1: "CLIENTID",  
              2: "SERVERID",
              3: "IA_NA",
              4: "IA_TA",
              5: "IAADDR",
              6: "ORO",
              7: "PREFERENCE",
              8: "ELAPSED_TIME",
              9: "RELAY_MSG",
             11: "AUTH",
             12: "UNICAST",
             13: "STATUS_CODE",
             14: "RAPID_COMMIT",
             15: "USER_CLASS",
             16: "VENDOR_CLASS",
             17: "VENDOR_OPTS",
             18: "INTERFACE_ID",
             19: "RECONF_MSG",
             20: "RECONF_ACCEPT",
             21: "SIP Servers Domain Name List",     #RFC3319
             22: "SIP Servers IPv6 Address List",    #RFC3319
             23: "DNS Recursive Name Server Option", #RFC3646
             24: "Domain Search List option",        #RFC3646
             25: "OPTION_IA_PD",                     #RFC3633
             26: "OPTION_IAPREFIX",                  #RFC3633
             27: "OPTION_NIS_SERVERS",               #RFC3898
             28: "OPTION_NISP_SERVERS",              #RFC3898
             29: "OPTION_NIS_DOMAIN_NAME",           #RFC3898
             30: "OPTION_NISP_DOMAIN_NAME",          #RFC3898
             31: "OPTION_SNTP_SERVERS",              #RFC4075
             32: "OPTION_INFORMATION_REFRESH_TIME",  #RFC4242
             33: "OPTION_BCMCS_SERVER_D",            #RFC4280         
             34: "OPTION_BCMCS_SERVER_A",            #RFC4280
             36: "OPTION_GEOCONF_CIVIC",             #RFC-ietf-geopriv-dhcp-civil-09.txt
             37: "OPTION_REMOTE_ID",                 #RFC4649
             38: "OPTION_SUBSCRIBER_ID",             #RFC4580
             39: "OPTION_CLIENT_FQDN" }              #RFC4704

dhcp6opts_by_code = {  1: "DHCP6OptClientId", 
                       2: "DHCP6OptServerId",
                       3: "DHCP6OptIA_NA",
                       4: "DHCP6OptIA_TA",
                       5: "DHCP6OptIAAddress",
                       6: "DHCP6OptOptReq",
                       7: "DHCP6OptPref",
                       8: "DHCP6OptElapsedTime",
                       9: "DHCP6OptRelayMsg",
                       11: "DHCP6OptAuth",
                       12: "DHCP6OptServerUnicast",
                       13: "DHCP6OptStatusCode",
                       14: "DHCP6OptRapidCommit",
                       15: "DHCP6OptUserClass",
                       16: "DHCP6OptVendorClass",
                       17: "DHCP6OptVendorSpecificInfo",
                       18: "DHCP6OptIfaceId",
                       19: "DHCP6OptReconfMsg",
                       20: "DHCP6OptReconfAccept",
                       21: "DHCP6OptSIPDomains",          #RFC3319
                       22: "DHCP6OptSIPServers",          #RFC3319
                       23: "DHCP6OptDNSServers",          #RFC3646
                       24: "DHCP6OptDNSDomains",          #RFC3646
                       25: "DHCP6OptIA_PD",               #RFC3633
                       26: "DHCP6OptIAPrefix",            #RFC3633
                       27: "DHCP6OptNISServers",          #RFC3898
                       28: "DHCP6OptNISPServers",         #RFC3898
                       29: "DHCP6OptNISDomain",           #RFC3898
                       30: "DHCP6OptNISPDomain",          #RFC3898
                       31: "DHCP6OptSNTPServers",         #RFC4075
                       32: "DHCP6OptInfoRefreshTime",     #RFC4242
                       33: "DHCP6OptBCMCSDomains",        #RFC4280         
                       34: "DHCP6OptBCMCSServers",        #RFC4280
                       #36: "DHCP6OptGeoConf",            #RFC-ietf-geopriv-dhcp-civil-09.txt
                       37: "DHCP6OptRemoteID",            #RFC4649
                       38: "DHCP6OptSubscriberID",        #RFC4580
                       39: "DHCP6OptClientFQDN",          #RFC4704
                       #40: "DHCP6OptPANAAgent",          #RFC-ietf-dhc-paa-option-05.txt
                       #41: "DHCP6OptNewPOSIXTimeZone,    #RFC4833
                       #42: "DHCP6OptNewTZDBTimeZone,     #RFC4833
                       43: "DHCP6OptRelayAgentERO"        #RFC4994
                       #44: "DHCP6OptLQQuery",            #RFC5007
                       #45: "DHCP6OptLQClientData",       #RFC5007
                       #46: "DHCP6OptLQClientTime",       #RFC5007
                       #47: "DHCP6OptLQRelayData",        #RFC5007
                       #48: "DHCP6OptLQClientLink",       #RFC5007
}


# sect 5.3 RFC 3315 : DHCP6 Messages types
dhcp6types = {   1:"SOLICIT",
                 2:"ADVERTISE",
                 3:"REQUEST",
                 4:"CONFIRM",
                 5:"RENEW",
                 6:"REBIND",
                 7:"REPLY",
                 8:"RELEASE",
                 9:"DECLINE",
                10:"RECONFIGURE",
                11:"INFORMATION-REQUEST",
                12:"RELAY-FORW",
                13:"RELAY-REPL" }


#####################################################################
###                  DHCPv6 DUID related stuff                    ###
#####################################################################

duidtypes = { 1: "Link-layer address plus time", 
              2: "Vendor-assigned unique ID based on Enterprise Number",
              3: "Link-layer Address" }

# DUID hardware types - RFC 826 - Extracted from 
# http://www.iana.org/assignments/arp-parameters on 31/10/06
# We should add the length of every kind of address.
duidhwtypes = {  0: "NET/ROM pseudo", # Not referenced by IANA
                 1: "Ethernet (10Mb)",
                 2: "Experimental Ethernet (3Mb)",
                 3: "Amateur Radio AX.25",
                 4: "Proteon ProNET Token Ring",
                 5: "Chaos",
                 6: "IEEE 802 Networks",
                 7: "ARCNET",
                 8: "Hyperchannel",
                 9: "Lanstar",
                10: "Autonet Short Address",
                11: "LocalTalk",
                12: "LocalNet (IBM PCNet or SYTEK LocalNET)",
                13: "Ultra link",
                14: "SMDS",
                15: "Frame Relay",
                16: "Asynchronous Transmission Mode (ATM)",
                17: "HDLC",
                18: "Fibre Channel",
                19: "Asynchronous Transmission Mode (ATM)",
                20: "Serial Line",
                21: "Asynchronous Transmission Mode (ATM)",
                22: "MIL-STD-188-220",
                23: "Metricom",
                24: "IEEE 1394.1995",
                25: "MAPOS",
                26: "Twinaxial",
                27: "EUI-64",
                28: "HIPARP",
                29: "IP and ARP over ISO 7816-3",
                30: "ARPSec",
                31: "IPsec tunnel",
                32: "InfiniBand (TM)",
                33: "TIA-102 Project 25 Common Air Interface (CAI)" }

class UTCTimeField(IntField):
    epoch = (2000, 1, 1, 0, 0, 0, 5, 1, 0) # required Epoch
    def i2repr(self, pkt, x):
        x = self.i2h(pkt, x)
        from time import gmtime, strftime, mktime
        delta = mktime(self.epoch) - mktime(gmtime(0))
        x = x + delta
        t = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime(x))
        return "%s (%d)" % (t, x)

class _LLAddrField(MACField):
    pass

# XXX We only support Ethernet addresses at the moment. _LLAddrField 
#     will be modified when needed. Ask us. --arno
class DUID_LLT(Packet):  # sect 9.2 RFC 3315
    name = "DUID - Link-layer address plus time"
    fields_desc = [ ShortEnumField("type", 1, duidtypes),
                    XShortEnumField("hwtype", 1, duidhwtypes), 
                    UTCTimeField("timeval", 0), # i.e. 01 Jan 2000
                    _LLAddrField("lladdr", ETHER_ANY) ]

# In fact, IANA enterprise-numbers file available at 
# http//www.iana.org/asignments/enterprise-numbers)
# is simply huge (more than 2Mo and 600Ko in bz2). I'll
# add only most common vendors, and encountered values.
# -- arno
iana_enterprise_num = {    9: "ciscoSystems",
                          35: "Nortel Networks",
                          43: "3Com",
                         311: "Microsoft",
                        2636: "Juniper Networks, Inc.",
                        4526: "Netgear",
                        5771: "Cisco Systems, Inc.",
                        5842: "Cisco Systems",
                       16885: "Nortel Networks" }

class DUID_EN(Packet):  # sect 9.3 RFC 3315
    name = "DUID - Assigned by Vendor Based on Enterprise Number"
    fields_desc = [ ShortEnumField("type", 2, duidtypes),
                    IntEnumField("enterprisenum", 311, iana_enterprise_num),
                    StrField("id","") ] 

class DUID_LL(Packet):  # sect 9.4 RFC 3315
    name = "DUID - Based on Link-layer Address"
    fields_desc = [ ShortEnumField("type", 3, duidtypes),
                    XShortEnumField("hwtype", 1, duidhwtypes), 
                    _LLAddrField("lladdr", ETHER_ANY) ]

duid_cls = { 1: "DUID_LLT",
             2: "DUID_EN",
             3: "DUID_LL"}

#####################################################################
###                   DHCPv6 Options classes                      ###
#####################################################################

class _DHCP6OptGuessPayload(Packet):
    def guess_payload_class(self, payload):
        cls = Raw
        if len(payload) > 2 :
            opt = struct.unpack("!H", payload[:2])[0]
            cls = get_cls(dhcp6opts_by_code.get(opt, "DHCP6OptUnknown"), DHCP6OptUnknown)
        return cls

class DHCP6OptUnknown(_DHCP6OptGuessPayload): # A generic DHCPv6 Option
    name = "Unknown DHCPv6 OPtion"
    fields_desc = [ ShortEnumField("optcode", 0, dhcp6opts), 
                    FieldLenField("optlen", None, length_of="data", fmt="!H"),
                    StrLenField("data", "",
                                length_from = lambda pkt: pkt.optlen)]

class _DUIDField(PacketField):
    holds_packets=1
    def __init__(self, name, default, length_from=None):
        StrField.__init__(self, name, default)
        self.length_from = length_from

    def i2m(self, pkt, i):
        return str(i)

    def m2i(self, pkt, x):
        cls = Raw 
        if len(x) > 4:
            o = struct.unpack("!H", x[:2])[0]
            cls = get_cls(duid_cls.get(o, Raw), "Raw")
        return cls(x)

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        return s[l:], self.m2i(pkt,s[:l])
 

class DHCP6OptClientId(_DHCP6OptGuessPayload):     # RFC sect 22.2
    name = "DHCP6 Client Identifier Option"
    fields_desc = [ ShortEnumField("optcode", 1, dhcp6opts), 
                    FieldLenField("optlen", None, length_of="duid", fmt="!H"),
                    _DUIDField("duid", "",
                               length_from = lambda pkt: pkt.optlen) ]


class DHCP6OptServerId(DHCP6OptClientId):     # RFC sect 22.3
    name = "DHCP6 Server Identifier Option"
    __metaclass__ = NewDefaultValues
    optcode = 2

# Should be encapsulated in the option field of IA_NA or IA_TA options
# Can only appear at that location.
# TODO : last field IAaddr-options is not defined in the reference document
class DHCP6OptIAAddress(_DHCP6OptGuessPayload):    # RFC sect 22.6
    name = "DHCP6 IA Address Option (IA_TA or IA_NA suboption)"
    fields_desc = [ ShortEnumField("optcode", 5, dhcp6opts), 
                    FieldLenField("optlen", None, length_of="iaaddropts",
                                  fmt="!H", adjust = lambda pkt,x: x+24),
                    IP6Field("addr", "::"),
                    IntField("preflft", 0),
                    IntField("validlft", 0),
                    XIntField("iaid", None),
                    StrLenField("iaaddropts", "",
                                length_from  = lambda pkt: pkt.optlen - 24) ]
    def guess_payload_class(self, payload):
        return Padding

class _IANAOptField(PacketListField):
    def i2len(self, pkt, z):
        if z is None or z == []:
            return 0
        return sum(map(lambda x: len(str(x)) ,z))

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        lst = []
        remain, payl = s[:l], s[l:]
        while len(remain)>0:
            p = self.m2i(pkt,remain)
            if Padding in p:
                pad = p[Padding]
                remain = pad.load
                del(pad.underlayer.payload)
            else:
                remain = ""
            lst.append(p)
        return payl,lst

class DHCP6OptIA_NA(_DHCP6OptGuessPayload):         # RFC sect 22.4
    name = "DHCP6 Identity Association for Non-temporary Addresses Option"
    fields_desc = [ ShortEnumField("optcode", 3, dhcp6opts), 
                    FieldLenField("optlen", None, length_of="ianaopts",
                                  fmt="!H", adjust = lambda pkt,x: x+12),
                    XIntField("iaid", None),
                    IntField("T1", None),
                    IntField("T2", None),
                    _IANAOptField("ianaopts", [], DHCP6OptIAAddress,
                                  length_from = lambda pkt: pkt.optlen-12) ]

class _IATAOptField(_IANAOptField):
    pass

class DHCP6OptIA_TA(_DHCP6OptGuessPayload):         # RFC sect 22.5
    name = "DHCP6 Identity Association for Temporary Addresses Option"
    fields_desc = [ ShortEnumField("optcode", 4, dhcp6opts), 
                    FieldLenField("optlen", None, length_of="iataopts",
                                  fmt="!H", adjust = lambda pkt,x: x+4),
                    XIntField("iaid", None),
                    _IATAOptField("iataopts", [], DHCP6OptIAAddress,
                                  length_from = lambda pkt: pkt.optlen-4) ]


#### DHCPv6 Option Request Option ###################################

class _OptReqListField(StrLenField):
    islist = 1
    def i2h(self, pkt, x):
        if x is None:
            return []
        return x

    def i2len(self, pkt, x):
        return 2*len(x)

    def any2i(self, pkt, x):
        return x

    def i2repr(self, pkt, x):
        s = []
        for y in self.i2h(pkt, x):
            if dhcp6opts.has_key(y):
                s.append(dhcp6opts[y])
            else:
                s.append("%d" % y)
        return "[%s]" % ", ".join(s) 

    def m2i(self, pkt, x):
        r = []
        while len(x) != 0:
            if len(x)<2:
                warning("Odd length for requested option field. Rejecting last byte")
                return r
            r.append(struct.unpack("!H", x[:2])[0])
            x = x[2:]
        return r
    
    def i2m(self, pkt, x):
        return "".join(map(lambda y: struct.pack("!H", y), x))

# A client may include an ORO in a solicit, Request, Renew, Rebind,
# Confirm or Information-request
class DHCP6OptOptReq(_DHCP6OptGuessPayload):       # RFC sect 22.7
    name = "DHCP6 Option Request Option"
    fields_desc = [ ShortEnumField("optcode", 6, dhcp6opts),
                    FieldLenField("optlen", None, length_of="reqopts", fmt="!H"),
                    _OptReqListField("reqopts", [23, 24],
                                     length_from = lambda pkt: pkt.optlen) ]


#### DHCPv6 Preference Option #######################################

# emise par un serveur pour affecter le choix fait par le client. Dans
# les messages Advertise, a priori
class DHCP6OptPref(_DHCP6OptGuessPayload):       # RFC sect 22.8
    name = "DHCP6 Preference Option"
    fields_desc = [ ShortEnumField("optcode", 7, dhcp6opts), 
                    ShortField("optlen", 1 ),
                    ByteField("prefval",255) ]


#### DHCPv6 Elapsed Time Option #####################################

class _ElapsedTimeField(ShortField):
    def i2repr(self, pkt, x):
        if x == 0xffff:
            return "infinity (0xffff)"
        return "%.2f sec" % (self.i2h(pkt, x)/100.)

class DHCP6OptElapsedTime(_DHCP6OptGuessPayload):# RFC sect 22.9
    name = "DHCP6 Elapsed Time Option"
    fields_desc = [ ShortEnumField("optcode", 8, dhcp6opts), 
                    ShortField("optlen", 2),
                    _ElapsedTimeField("elapsedtime", 0) ]


#### DHCPv6 Relay Message Option ####################################

# Relayed message is seen as a payload.
class DHCP6OptRelayMsg(_DHCP6OptGuessPayload):# RFC sect 22.10
    name = "DHCP6 Relay Message Option"
    fields_desc = [ ShortEnumField("optcode", 9, dhcp6opts), 
                    ShortField("optlen", None ) ]
    def post_build(self, p, pay):
        if self.optlen is None:
            l = len(pay) 
            p = p[:2]+struct.pack("!H", l)
        return p + pay


#### DHCPv6 Authentication Option ###################################

#    The following fields are set in an Authentication option for the
#    Reconfigure Key Authentication Protocol:
#
#       protocol    3
#
#       algorithm   1
#
#       RDM         0
#
#    The format of the Authentication information for the Reconfigure Key
#    Authentication Protocol is:
#
#      0                   1                   2                   3
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |     Type      |                 Value (128 bits)              |
#     +-+-+-+-+-+-+-+-+                                               |
#     .                                                               .
#     .                                                               .
#     .                                               +-+-+-+-+-+-+-+-+
#     |                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#       Type    Type of data in Value field carried in this option:
#
#                  1   Reconfigure Key value (used in Reply message).
#
#                  2   HMAC-MD5 digest of the message (used in Reconfigure
#                      message).
#
#       Value   Data as defined by field.


# TODO : Decoding only at the moment
class DHCP6OptAuth(_DHCP6OptGuessPayload):    # RFC sect 22.11
    name = "DHCP6 Option - Authentication"
    fields_desc = [ ShortEnumField("optcode", 11, dhcp6opts), 
                    FieldLenField("optlen", None, length_of="authinfo",
                                  adjust = lambda pkt,x: x+11),
                    ByteField("proto", 3), # TODO : XXX
                    ByteField("alg", 1), # TODO : XXX
                    ByteField("rdm", 0), # TODO : XXX
                    StrFixedLenField("replay", "A"*8, 8), # TODO: XXX
                    StrLenField("authinfo", "",
                                length_from = lambda pkt: pkt.optlen - 11) ]

#### DHCPv6 Server Unicast Option ###################################

class _SrvAddrField(IP6Field):
    def i2h(self, pkt, x):
        if x is None:
            return "::"
        return x
    
    def i2m(self, pkt, x):
        return inet_pton(socket.AF_INET6, self.i2h(pkt,x))

class DHCP6OptServerUnicast(_DHCP6OptGuessPayload):# RFC sect 22.12
    name = "DHCP6 Server Unicast Option"
    fields_desc = [ ShortEnumField("optcode", 12, dhcp6opts), 
                    ShortField("optlen", 16 ),
                    _SrvAddrField("srvaddr",None) ]


#### DHCPv6 Status Code Option ######################################

dhcp6statuscodes = { 0:"Success",      # sect 24.4
                     1:"UnspecFail",
                     2:"NoAddrsAvail",
                     3:"NoBinding",
                     4:"NotOnLink",
                     5:"UseMulticast",
                     6:"NoPrefixAvail"} # From RFC3633

class DHCP6OptStatusCode(_DHCP6OptGuessPayload):# RFC sect 22.13
    name = "DHCP6 Status Code Option"
    fields_desc = [ ShortEnumField("optcode", 13, dhcp6opts), 
                    FieldLenField("optlen", None, length_of="statusmsg",
                                  fmt="!H", adjust = lambda pkt,x:x+2),
                    ShortEnumField("statuscode",None,dhcp6statuscodes),
                    StrLenField("statusmsg", "",
                                length_from = lambda pkt: pkt.optlen-2) ]


#### DHCPv6 Rapid Commit Option #####################################

class DHCP6OptRapidCommit(_DHCP6OptGuessPayload):   # RFC sect 22.14
    name = "DHCP6 Rapid Commit Option"
    fields_desc = [ ShortEnumField("optcode", 14, dhcp6opts),
                    ShortField("optlen", 0)]


#### DHCPv6 User Class Option #######################################

class _UserClassDataField(PacketListField):
    def i2len(self, pkt, z):
        if z is None or z == []:
            return 0
        return sum(map(lambda x: len(str(x)) ,z))

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        lst = []
        remain, payl = s[:l], s[l:]
        while len(remain)>0:
            p = self.m2i(pkt,remain)
            if Padding in p:
                pad = p[Padding]
                remain = pad.load
                del(pad.underlayer.payload)
            else:
                remain = ""
            lst.append(p)
        return payl,lst


class USER_CLASS_DATA(Packet):
    name = "user class data"
    fields_desc = [ FieldLenField("len", None, length_of="data"),
                    StrLenField("data", "",
                                length_from = lambda pkt: pkt.len) ]
    def guess_payload_class(self, payload):
        return Padding

class DHCP6OptUserClass(_DHCP6OptGuessPayload):# RFC sect 22.15
    name = "DHCP6 User Class Option"
    fields_desc = [ ShortEnumField("optcode", 15, dhcp6opts), 
                    FieldLenField("optlen", None, fmt="!H",
                                  length_of="userclassdata"),
                    _UserClassDataField("userclassdata", [], USER_CLASS_DATA,
                                        length_from = lambda pkt: pkt.optlen) ]


#### DHCPv6 Vendor Class Option #####################################

class _VendorClassDataField(_UserClassDataField):
    pass

class VENDOR_CLASS_DATA(USER_CLASS_DATA):
    name = "vendor class data"

class DHCP6OptVendorClass(_DHCP6OptGuessPayload):# RFC sect 22.16
    name = "DHCP6 Vendor Class Option"
    fields_desc = [ ShortEnumField("optcode", 16, dhcp6opts), 
                    FieldLenField("optlen", None, length_of="vcdata", fmt="!H",
                                  adjust = lambda pkt,x: x+4),
                    IntEnumField("enterprisenum",None , iana_enterprise_num ),
                    _VendorClassDataField("vcdata", [], VENDOR_CLASS_DATA,
                                          length_from = lambda pkt: pkt.optlen-4) ]

#### DHCPv6 Vendor-Specific Information Option ######################

class VENDOR_SPECIFIC_OPTION(_DHCP6OptGuessPayload):
    name = "vendor specific option data"
    fields_desc = [ ShortField("optcode", None),
                    FieldLenField("optlen", None, length_of="optdata"),
                    StrLenField("optdata", "",
                                length_from = lambda pkt: pkt.optlen) ]
    def guess_payload_class(self, payload):
        return Padding

# The third one that will be used for nothing interesting
class DHCP6OptVendorSpecificInfo(_DHCP6OptGuessPayload):# RFC sect 22.17
    name = "DHCP6 Vendor-specific Information Option"
    fields_desc = [ ShortEnumField("optcode", 17, dhcp6opts), 
                    FieldLenField("optlen", None, length_of="vso", fmt="!H",
                                  adjust = lambda pkt,x: x+4),
                    IntEnumField("enterprisenum",None , iana_enterprise_num),
                    _VendorClassDataField("vso", [], VENDOR_SPECIFIC_OPTION,
                                          length_from = lambda pkt: pkt.optlen-4) ]

#### DHCPv6 Interface-ID Option #####################################

# Repasser sur cette option a la fin. Elle a pas l'air d'etre des
# masses critique.
class DHCP6OptIfaceId(_DHCP6OptGuessPayload):# RFC sect 22.18
    name = "DHCP6 Interface-Id Option"
    fields_desc = [ ShortEnumField("optcode", 18, dhcp6opts),
                    FieldLenField("optlen", None, fmt="!H",
                                  length_of="ifaceid"),
                    StrLenField("ifaceid", "",
                                length_from = lambda pkt: pkt.optlen) ]


#### DHCPv6 Reconfigure Message Option ##############################

# A server includes a Reconfigure Message option in a Reconfigure
# message to indicate to the client whether the client responds with a
# renew message or an Informatiion-request message.
class DHCP6OptReconfMsg(_DHCP6OptGuessPayload):       # RFC sect 22.19
    name = "DHCP6 Reconfigure Message Option"
    fields_desc = [ ShortEnumField("optcode", 19, dhcp6opts), 
                    ShortField("optlen", 1 ),
                    ByteEnumField("msgtype", 11, {  5:"Renew Message", 
                                                   11:"Information Request"}) ]


#### DHCPv6 Reconfigure Accept Option ###############################

# A client uses the Reconfigure Accept option to announce to the
# server whether the client is willing to accept Recoonfigure
# messages, and a server uses this option to tell the client whether
# or not to accept Reconfigure messages. The default behavior in the
# absence of this option, means unwillingness to accept reconfigure
# messages, or instruction not to accept Reconfigure messages, for the
# client and server messages, respectively.
class DHCP6OptReconfAccept(_DHCP6OptGuessPayload):   # RFC sect 22.20
    name = "DHCP6 Reconfigure Accept Option"
    fields_desc = [ ShortEnumField("optcode", 20, dhcp6opts),
                    ShortField("optlen", 0)]

# As required in Sect 8. of RFC 3315, Domain Names must be encoded as 
# described in section 3.1 of RFC 1035
# XXX Label should be at most 63 octets in length : we do not enforce it
#     Total length of domain should be 255 : we do not enforce it either
class DomainNameListField(StrLenField):
    islist = 1

    def i2len(self, pkt, x):
        return len(self.i2m(pkt, x))

    def m2i(self, pkt, x):
        res = []
        while x:
            cur = []
            while x and x[0] != '\x00':
                l = ord(x[0])
                cur.append(x[1:l+1])
                x = x[l+1:]
            res.append(".".join(cur))
            if x and x[0] == '\x00':
                x = x[1:]
        return res

    def i2m(self, pkt, x):
        def conditionalTrailingDot(z):
            if z and z[-1] == '\x00':
                return z
            return z+'\x00'
        res = ""
        tmp = map(lambda y: map((lambda z: chr(len(z))+z), y.split('.')), x)
        return "".join(map(lambda x: conditionalTrailingDot("".join(x)), tmp))

class DHCP6OptSIPDomains(_DHCP6OptGuessPayload):       #RFC3319
    name = "DHCP6 Option - SIP Servers Domain Name List"
    fields_desc = [ ShortEnumField("optcode", 21, dhcp6opts),
                    FieldLenField("optlen", None, length_of="sipdomains"),
                    DomainNameListField("sipdomains", [],
                                        length_from = lambda pkt: pkt.optlen) ]

class DHCP6OptSIPServers(_DHCP6OptGuessPayload):          #RFC3319
    name = "DHCP6 Option - SIP Servers IPv6 Address List"
    fields_desc = [ ShortEnumField("optcode", 22, dhcp6opts),
                    FieldLenField("optlen", None, length_of="sipservers"),
                    IP6ListField("sipservers", [], 
                                 length_from = lambda pkt: pkt.optlen) ]

class DHCP6OptDNSServers(_DHCP6OptGuessPayload):          #RFC3646
    name = "DHCP6 Option - DNS Recursive Name Server"
    fields_desc = [ ShortEnumField("optcode", 23, dhcp6opts),
                    FieldLenField("optlen", None, length_of="dnsservers"),
                    IP6ListField("dnsservers", [],
                                 length_from = lambda pkt: pkt.optlen) ]

class DHCP6OptDNSDomains(_DHCP6OptGuessPayload): #RFC3646
    name = "DHCP6 Option - Domain Search List option"
    fields_desc = [ ShortEnumField("optcode", 24, dhcp6opts),
                    FieldLenField("optlen", None, length_of="dnsdomains"),
                    DomainNameListField("dnsdomains", [],
                                        length_from = lambda pkt: pkt.optlen) ]

# TODO: Implement iaprefopts correctly when provided with more 
#       information about it.
class DHCP6OptIAPrefix(_DHCP6OptGuessPayload):                    #RFC3633
    name = "DHCP6 Option - IA_PD Prefix option"
    fields_desc = [ ShortEnumField("optcode", 26, dhcp6opts),
                    FieldLenField("optlen", None, length_of="iaprefopts",
                                  adjust = lambda pkt,x: x+26),
                    IntField("preflft", 0),
                    IntField("validlft", 0),
                    ByteField("plen", 48),  # TODO: Challenge that default value
                    IP6Field("prefix", "2001:db8::"), # At least, global and won't hurt
                    StrLenField("iaprefopts", "",
                                length_from = lambda pkt: pkt.optlen-26) ]

class DHCP6OptIA_PD(_DHCP6OptGuessPayload):                       #RFC3633
    name = "DHCP6 Option - Identity Association for Prefix Delegation"
    fields_desc = [ ShortEnumField("optcode", 25, dhcp6opts),
                    FieldLenField("optlen", None, length_of="iapdopt",
                                  adjust = lambda pkt,x: x+12),
                    IntField("iaid", 0),
                    IntField("T1", 0),
                    IntField("T2", 0),
                    PacketListField("iapdopt", [], DHCP6OptIAPrefix,
                                    length_from = lambda pkt: pkt.optlen-12) ]

class DHCP6OptNISServers(_DHCP6OptGuessPayload):                 #RFC3898
    name = "DHCP6 Option - NIS Servers"
    fields_desc = [ ShortEnumField("optcode", 27, dhcp6opts),
                    FieldLenField("optlen", None, length_of="nisservers"),
                    IP6ListField("nisservers", [],
                                 length_from = lambda pkt: pkt.optlen) ]

class DHCP6OptNISPServers(_DHCP6OptGuessPayload):                #RFC3898
    name = "DHCP6 Option - NIS+ Servers"
    fields_desc = [ ShortEnumField("optcode", 28, dhcp6opts),
                    FieldLenField("optlen", None, length_of="nispservers"),
                    IP6ListField("nispservers", [],
                                 length_from = lambda pkt: pkt.optlen) ]

class DomainNameField(StrLenField):
    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        return s[l:], self.m2i(pkt,s[:l])

    def i2len(self, pkt, x):
        return len(self.i2m(pkt, x))

    def m2i(self, pkt, x):
        save = x
        cur = []
        while x and x[0] != '\x00':
            l = ord(x[0])
            cur.append(x[1:1+l])
            x = x[l+1:]
        if x[0] != '\x00':
            print "Found weird domain: '%s'. Keeping %s" % (save, x)
        return ".".join(cur)

    def i2m(self, pkt, x):
        def conditionalTrailingDot(z):
            if (z and z[-1] == '\x00'):
                return z
            return z+'\x00'
        if not x:
            return ""
        tmp = "".join(map(lambda z: chr(len(z))+z, x.split('.')))
        return conditionalTrailingDot(tmp)

class DHCP6OptNISDomain(_DHCP6OptGuessPayload):             #RFC3898
    name = "DHCP6 Option - NIS Domain Name"
    fields_desc = [ ShortEnumField("optcode", 29, dhcp6opts),
                    FieldLenField("optlen", None, length_of="nisdomain"),
                    DomainNameField("nisdomain", "",
                                    length_from = lambda pkt: pkt.optlen) ]

class DHCP6OptNISPDomain(_DHCP6OptGuessPayload):            #RFC3898
    name = "DHCP6 Option - NIS+ Domain Name"
    fields_desc = [ ShortEnumField("optcode", 30, dhcp6opts),
                    FieldLenField("optlen", None, length_of="nispdomain"),
                    DomainNameField("nispdomain", "",
                                    length_from= lambda pkt: pkt.optlen) ]

class DHCP6OptSNTPServers(_DHCP6OptGuessPayload):                #RFC4075
    name = "DHCP6 option - SNTP Servers"
    fields_desc = [ ShortEnumField("optcode", 31, dhcp6opts),
                    FieldLenField("optlen", None, length_of="sntpservers"),
                    IP6ListField("sntpservers", [],
                                 length_from = lambda pkt: pkt.optlen) ]

IRT_DEFAULT=86400
IRT_MINIMUM=600
class DHCP6OptInfoRefreshTime(_DHCP6OptGuessPayload):    #RFC4242
    name = "DHCP6 Option - Information Refresh Time"
    fields_desc = [ ShortEnumField("optcode", 32, dhcp6opts),
                    ShortField("optlen", 4),
                    IntField("reftime", IRT_DEFAULT)] # One day

class DHCP6OptBCMCSDomains(_DHCP6OptGuessPayload):              #RFC4280         
    name = "DHCP6 Option - BCMCS Domain Name List"
    fields_desc = [ ShortEnumField("optcode", 33, dhcp6opts),
                    FieldLenField("optlen", None, length_of="bcmcsdomains"),
                    DomainNameListField("bcmcsdomains", [],
                                        length_from = lambda pkt: pkt.optlen) ]

class DHCP6OptBCMCSServers(_DHCP6OptGuessPayload):              #RFC4280
    name = "DHCP6 Option - BCMCS Addresses List"
    fields_desc = [ ShortEnumField("optcode", 34, dhcp6opts),
                    FieldLenField("optlen", None, length_of="bcmcsservers"),
                    IP6ListField("bcmcsservers", [],
                                 length_from= lambda pkt: pkt.optlen) ]

# TODO : Does Nothing at the moment
class DHCP6OptGeoConf(_DHCP6OptGuessPayload):               #RFC-ietf-geopriv-dhcp-civil-09.txt
    name = ""
    fields_desc = [ ShortEnumField("optcode", 36, dhcp6opts),
                    FieldLenField("optlen", None, length_of="optdata"),
                    StrLenField("optdata", "",
                                length_from = lambda pkt: pkt.optlen) ]

# TODO: see if we encounter opaque values from vendor devices
class DHCP6OptRemoteID(_DHCP6OptGuessPayload):                   #RFC4649
    name = "DHCP6 Option - Relay Agent Remote-ID"
    fields_desc = [ ShortEnumField("optcode", 37, dhcp6opts),
                    FieldLenField("optlen", None, length_of="remoteid",
                                  adjust = lambda pkt,x: x+4),
                    IntEnumField("enterprisenum", None, iana_enterprise_num),
                    StrLenField("remoteid", "",
                                length_from = lambda pkt: pkt.optlen-4) ]

# TODO : 'subscriberid' default value should be at least 1 byte long
class DHCP6OptSubscriberID(_DHCP6OptGuessPayload):               #RFC4580
    name = "DHCP6 Option - Subscriber ID"
    fields_desc = [ ShortEnumField("optcode", 38, dhcp6opts),
                    FieldLenField("optlen", None, length_of="subscriberid"),
                    StrLenField("subscriberid", "",
                                length_from = lambda pkt: pkt.optlen) ]

# TODO :  "The data in the Domain Name field MUST be encoded
#          as described in Section 8 of [5]"
class DHCP6OptClientFQDN(_DHCP6OptGuessPayload):                 #RFC4704
    name = "DHCP6 Option - Client FQDN"
    fields_desc = [ ShortEnumField("optcode", 39, dhcp6opts),
                    FieldLenField("optlen", None, length_of="fqdn",
                                  adjust = lambda pkt,x: x+1),
                    BitField("res", 0, 5),
                    FlagsField("flags", 0, 3, "SON" ),
                    DomainNameField("fqdn", "",
                                    length_from = lambda pkt: pkt.optlen-1) ]

class DHCP6OptRelayAgentERO(_DHCP6OptGuessPayload):       # RFC4994
    name = "DHCP6 Option - RelayRequest Option"
    fields_desc = [ ShortEnumField("optcode", 43, dhcp6opts),
                    FieldLenField("optlen", None, length_of="reqopts", fmt="!H"),
                    _OptReqListField("reqopts", [23, 24],
                                     length_from = lambda pkt: pkt.optlen) ]

#####################################################################
###                        DHCPv6 messages                        ###
#####################################################################

# Some state parameters of the protocols that should probably be 
# useful to have in the configuration (and keep up-to-date)
DHCP6RelayAgentUnicastAddr=""
DHCP6RelayHopCount=""
DHCP6ServerUnicastAddr=""
DHCP6ClientUnicastAddr=""
DHCP6ClientIA_TA=""
DHCP6ClientIA_NA=""
DHCP6ClientIAID=""
T1="" # Voir 2462
T2="" # Voir 2462
DHCP6ServerDUID=""
DHCP6CurrentTransactionID="" # devrait etre utilise pour matcher une
# reponse et mis a jour en mode client par une valeur aleatoire pour
# laquelle on attend un retour de la part d'un serveur.
DHCP6PrefVal="" # la valeur de preference a utiliser dans
# les options preference

# Emitted by :
# - server : ADVERTISE, REPLY, RECONFIGURE, RELAY-REPL (vers relay)
# - client : SOLICIT, REQUEST, CONFIRM, RENEW, REBIND, RELEASE, DECLINE,
#            INFORMATION REQUEST
# - relay  : RELAY-FORW (toward server)

class _DHCP6GuessPayload(Packet):
    def guess_payload_class(self, payload):
        if len(payload) > 1 :
            print ord(payload[0])
            return get_cls(dhcp6opts.get(ord(payload[0]),"DHCP6OptUnknown"), Raw)
        return Raw

#####################################################################
## DHCPv6 messages sent between Clients and Servers (types 1 to 11)
# Comme specifie en section 15.1 de la RFC 3315, les valeurs de
# transaction id sont selectionnees de maniere aleatoire par le client
# a chaque emission et doivent matcher dans les reponses faites par
# les clients
class DHCP6(_DHCP6OptGuessPayload):
    name = "DHCPv6 Generic Message)"
    fields_desc = [ ByteEnumField("msgtype",None,dhcp6types),
                    X3BytesField("trid",0x000000) ]
    overload_fields = { UDP: {"sport": 546, "dport": 547} }

    def hashret(self):
        return struct.pack("!I", self.trid)[1:4]

#####################################################################
# Solicit Message : sect 17.1.1 RFC3315
# - sent by client
# - must include a client identifier option
# - the client may include IA options for any IAs to which it wants the
#   server to assign address
# - The client use IA_NA options to request the assignment of
#   non-temporary addresses and uses IA_TA options to request the
#   assignment of temporary addresses
# - The client should include an Option Request option to indicate the
#   options the client is interested in receiving (eventually
#   including hints)
# - The client includes a Reconfigure Accept option if is willing to
#   accept Reconfigure messages from the server.
# Le cas du send and reply est assez particulier car suivant la
# presence d'une option rapid commit dans le solicit, l'attente
# s'arrete au premier message de reponse recu ou alors apres un
# timeout. De la meme maniere, si un message Advertise arrive avec une
# valeur de preference de 255, il arrete l'attente et envoie une
# Request.
# - The client announces its intention to use DHCP authentication by
# including an Authentication option in its solicit message. The
# server selects a key for the client based on the client's DUID. The
# client and server use that key to authenticate all DHCP messages
# exchanged during the session

class DHCP6_Solicit(DHCP6):
    name = "DHCPv6 Solicit Message"
    __metaclass__ = NewDefaultValues
    msgtype = 1
    overload_fields = { UDP: {"sport": 546, "dport": 547} }

#####################################################################
# Advertise Message
# - sent by server
# - Includes a server identifier option
# - Includes a client identifier option
# - the client identifier option must match the client's DUID
# - transaction ID must match

class DHCP6_Advertise(DHCP6):
    name = "DHCPv6 Advertise Message"
    __metaclass__ = NewDefaultValues
    msgtype = 2
    overload_fields = { UDP: {"sport": 547, "dport": 546} }
    
    def answers(self, other):
        return (isinstance(other,DHCP6_Solicit) and 
                other.msgtype == 1 and
                self.trid == other.trid)

#####################################################################
# Request Message
# - sent by clients
# - includes a server identifier option
# - the content of Server Identifier option must match server's DUID
# - includes a client identifier option
# - must include an ORO Option (even with hints) p40
# - can includes a reconfigure Accept option indicating whether or
#   not the client is willing to accept Reconfigure messages from
#   the server (p40)
# - When the server receives a Request message via unicast from a
# client to which the server has not sent a unicast option, the server
# discards the Request message and responds with a Reply message
# containinig Status Code option with the value UseMulticast, a Server
# Identifier Option containing the server's DUID, the client
# Identifier option from the client message and no other option.

class DHCP6_Request(DHCP6):
    name = "DHCPv6 Request Message"
    __metaclass__ = NewDefaultValues
    msgtype = 3

#####################################################################
# Confirm Message
# - sent by clients
# - must include a clien identifier option
# - When the server receives a Confirm Message, the server determines
# whether the addresses in the Confirm message are appropriate for the
# link to which the client is attached. cf p50

class DHCP6_Confirm(DHCP6):
    name = "DHCPv6 Confirm Message"
    __metaclass__ = NewDefaultValues
    msgtype = 4
    
#####################################################################
# Renew Message
# - sent by clients
# - must include a server identifier option
# - content of server identifier option must match the server's identifier
# - must include a client identifier option
# - the clients includes any IA assigned to the interface that may
# have moved to a new link, along with the addresses associated with
# those IAs in its confirm messages
# - When the server receives a Renew message that contains an IA
# option from a client, it locates the client's binding and verifies
# that the information in the IA from the client matches the
# information for that client. If the server cannot find a client
# entry for the IA the server returns the IA containing no addresses
# with a status code option est to NoBinding in the Reply message. cf
# p51 pour le reste.

class DHCP6_Renew(DHCP6):
    name = "DHCPv6 Renew Message"
    __metaclass__ = NewDefaultValues
    msgtype = 5
    
#####################################################################
# Rebind Message
# - sent by clients
# - must include a client identifier option
# cf p52

class DHCP6_Rebind(DHCP6):
    name = "DHCPv6 Rebind Message"
    __metaclass__ = NewDefaultValues
    msgtype = 6
    
#####################################################################
# Reply Message
# - sent by servers
# - the message must include a server identifier option
# - transaction-id field must match the value of original message
# The server includes a Rapid Commit option in the Reply message to
# indicate that the reply is in response to a solicit message
# - if the client receives a reply message with a Status code option
# with the value UseMulticast, the client records the receipt of the
# message and sends subsequent messages to the server through the
# interface on which the message was received using multicast. The
# client resends the original message using multicast
# - When the client receives a NotOnLink status from the server in
# response to a Confirm message, the client performs DHCP server
# solicitation as described in section 17 and client-initiated
# configuration as descrribed in section 18 (RFC 3315)
# - when the client receives a NotOnLink status from the server in
# response to a Request, the client can either re-issue the Request
# without specifying any addresses or restart the DHCP server
# discovery process.
# - the server must include a server identifier option containing the
# server's DUID in the Reply message

class DHCP6_Reply(DHCP6):
    name = "DHCPv6 Reply Message"
    __metaclass__ = NewDefaultValues
    msgtype = 7
    
    def answers(self, other):
        return (isinstance(other, DHCP6_InfoRequest) and
                self.trid == other.trid)

#####################################################################
# Release Message
# - sent by clients
# - must include a server identifier option
# cf p53

class DHCP6_Release(DHCP6):
    name = "DHCPv6 Release Message"
    __metaclass__ = NewDefaultValues
    msgtype = 8
    
#####################################################################
# Decline Message
# - sent by clients
# - must include a client identifier option
# - Server identifier option must match server identifier
# - The addresses to be declined must be included in the IAs. Any
# addresses for the IAs the client wishes to continue to use should
# not be in added to the IAs.
# - cf p54 

class DHCP6_Decline(DHCP6):
    name = "DHCPv6 Decline Message"
    __metaclass__ = NewDefaultValues
    msgtype = 9
    
#####################################################################
# Reconfigure Message
# - sent by servers
# - must be unicast to the client
# - must include a server identifier option
# - must include a client identifier option that contains the client DUID
# - must contain a Reconfigure Message Option and the message type
#   must be a valid value
# - the server sets the transaction-id to 0
# - The server must use DHCP Authentication in the Reconfigure
# message. Autant dire que ca va pas etre le type de message qu'on va
# voir le plus souvent.

class DHCP6_Reconf(DHCP6):
    name = "DHCPv6 Reconfigure Message"
    __metaclass__ = NewDefaultValues
    msgtype = 10
    overload_fields = { UDP: { "sport": 547, "dport": 546 } }

    
#####################################################################
# Information-Request Message
# - sent by clients when needs configuration information but no
# addresses. 
# - client should include a client identifier option to identify
# itself. If it doesn't the server is not able to return client
# specific options or the server can choose to not respond to the
# message at all. The client must include a client identifier option
# if the message will be authenticated.
# - client must include an ORO of option she's interested in receiving
# (can include hints)

class DHCP6_InfoRequest(DHCP6):
    name = "DHCPv6 Information Request Message"    
    __metaclass__ = NewDefaultValues
    msgtype = 11 
    
    def hashret(self): 
        return struct.pack("!I", self.trid)[1:3]

#####################################################################
# sent between Relay Agents and Servers 
#
# Normalement, doit inclure une option "Relay Message Option"
# peut en inclure d'autres.
# voir section 7.1 de la 3315

# Relay-Forward Message
# - sent by relay agents to servers
# If the relay agent relays messages to the All_DHCP_Servers multicast
# address or other multicast addresses, it sets the Hop Limit field to
# 32. 

class DHCP6_RelayForward(_DHCP6GuessPayload,Packet):
    name = "DHCPv6 Relay Forward Message (Relay Agent/Server Message)"
    fields_desc = [ ByteEnumField("msgtype", 12, dhcp6types),
                    ShortField("hopcount", None),
                    IP6Field("linkaddr", "::"),
                    IP6Field("peeraddr", "::") ]
    def hashret(self): # we filter on peer address field
        return inet_pton(socket.AF_INET6, self.peeraddr)

#####################################################################
# sent between Relay Agents and Servers 
# Normalement, doit inclure une option "Relay Message Option"
# peut en inclure d'autres.
# Les valeurs des champs hop-count, link-addr et peer-addr
# sont copiees du messsage Forward associe. POur le suivi de session.
# Pour le moment, comme decrit dans le commentaire, le hashret
# se limite au contenu du champ peer address.
# Voir section 7.2 de la 3315.

# Relay-Reply Message
# - sent by servers to relay agents
# - if the solicit message was received in a Relay-Forward message,
# the server constructs a relay-reply message with the Advertise
# message in the payload of a relay-message. cf page 37/101. Envoie de
# ce message en unicast au relay-agent. utilisation de l'adresse ip
# presente en ip source du paquet recu

class DHCP6_RelayReply(DHCP6_RelayForward):
    name = "DHCPv6 Relay Reply Message (Relay Agent/Server Message)"
    __metaclass__= NewDefaultValues
    msgtype = 13
    def hashret(self): # We filter on peer address field.
        return inet_pton(socket.AF_INET6, self.peeraddr)
    def answers(self, other):
        return (isinstance(other, DHCP6_RelayForward) and
                self.count == other.count and
                self.linkaddr == other.linkaddr and
                self.peeraddr == other.peeraddr )


dhcp6_cls_by_type = {  1: "DHCP6_Solicit",
                       2: "DHCP6_Advertise",
                       3: "DHCP6_Request",
                       4: "DHCP6_Confirm",
                       5: "DHCP6_Renew",
                       6: "DHCP6_Rebind",
                       7: "DHCP6_Reply",
                       8: "DHCP6_Release",
                       9: "DHCP6_Decline",
                      10: "DHCP6_Reconf",
                      11: "DHCP6_InfoRequest",
                      12: "DHCP6_RelayForward",
                      13: "DHCP6_RelayReply" }

def _dhcp6_dispatcher(x, *args, **kargs):
    cls = Raw
    if len(x) >= 2:
        cls = get_cls(dhcp6_cls_by_type.get(ord(x[0]), "Raw"), Raw)
    return cls(x, *args, **kargs)

bind_bottom_up(UDP, _dhcp6_dispatcher, { "dport": 547 } )
bind_bottom_up(UDP, _dhcp6_dispatcher, { "dport": 546 } )



class DHCPv6_am(AnsweringMachine):
    function_name = "dhcp6d"
    filter = "udp and port 546 and port 547" 
    send_function = staticmethod(send)
    def usage(self):
        msg = """
dhcp6d( dns="2001:500::1035", domain="localdomain, local", duid=None)
        iface=conf.iface6, advpref=255, sntpservers=None, 
        sipdomains=None, sipservers=None, 
        nisdomain=None, nisservers=None, 
        nispdomain=None, nispservers=None,
        bcmcsdomain=None, bcmcsservers=None)

   debug : When set, additional debugging information is printed. 

   duid   : some DUID class (DUID_LLT, DUID_LL or DUID_EN). If none
            is provided a DUID_LLT is constructed based on the MAC 
            address of the sending interface and launch time of dhcp6d 
            answering machine. 
  
   iface : the interface to listen/reply on if you do not want to use 
           conf.iface6.

   advpref : Value in [0,255] given to Advertise preference field.
             By default, 255 is used. Be aware that this specific
             value makes clients stops waiting for further Advertise
             messages from other servers.

   dns : list of recursive DNS servers addresses (as a string or list). 
         By default, it is set empty and the associated DHCP6OptDNSServers
         option is inactive. See RFC 3646 for details.
   domain : a list of DNS search domain (as a string or list). By default, 
         it is empty and the associated DHCP6OptDomains option is inactive.
         See RFC 3646 for details.

   sntpservers : a list of SNTP servers IPv6 addresses. By default,
         it is empty and the associated DHCP6OptSNTPServers option 
         is inactive. 

   sipdomains : a list of SIP domains. By default, it is empty and the
         associated DHCP6OptSIPDomains option is inactive. See RFC 3319
         for details.
   sipservers : a list of SIP servers IPv6 addresses. By default, it is 
         empty and the associated DHCP6OptSIPDomains option is inactive. 
         See RFC 3319 for details.

   nisdomain : a list of NIS domains. By default, it is empty and the
         associated DHCP6OptNISDomains option is inactive. See RFC 3898
         for details. See RFC 3646 for details.
   nisservers : a list of NIS servers IPv6 addresses. By default, it is 
         empty and the associated DHCP6OptNISServers option is inactive.
         See RFC 3646 for details.

   nispdomain : a list of NIS+ domains. By default, it is empty and the
         associated DHCP6OptNISPDomains option is inactive. See RFC 3898
         for details.
   nispservers : a list of NIS+ servers IPv6 addresses. By default, it is 
         empty and the associated DHCP6OptNISServers option is inactive.
         See RFC 3898 for details.

   bcmcsdomain : a list of BCMCS domains. By default, it is empty and the
         associated DHCP6OptBCMCSDomains option is inactive. See RFC 4280
         for details.
   bcmcsservers : a list of BCMCS servers IPv6 addresses. By default, it is 
         empty and the associated DHCP6OptBCMCSServers option is inactive.
         See RFC 4280 for details.

   If you have a need for others, just ask ... or provide a patch."""
        print msg

    def parse_options(self, dns="2001:500::1035", domain="localdomain, local",
                      startip="2001:db8::1", endip="2001:db8::20", duid=None,
                      sntpservers=None, sipdomains=None, sipservers=None, 
                      nisdomain=None, nisservers=None, nispdomain=None,
                      nispservers=None, bcmcsservers=None, bcmcsdomains=None,
                      iface=None, debug=0, advpref=255):
        def norm_list(val, param_name):
            if val is None:
                return None
            if type(val) is list:
                return val
            elif type(val) is str:
                l = val.split(',')
                return map(lambda x: x.strip(), l)
            else:
                print "Bad '%s' parameter provided." % param_name
                self.usage()
                return -1

        if iface is None:
            iface = conf.iface6
        
        self.debug = debug

        # Dictionary of provided DHCPv6 options, keyed by option type
        self.dhcpv6_options={}

        for o in [(dns, "dns", 23, lambda x: DHCP6OptDNSServers(dnsservers=x)), 
                  (domain, "domain", 24, lambda x: DHCP6OptDNSDomains(dnsdomains=x)), 
                  (sntpservers, "sntpservers", 31, lambda x: DHCP6OptSNTPServers(sntpservers=x)),
                  (sipservers, "sipservers", 22, lambda x: DHCP6OptSIPServers(sipservers=x)),
                  (sipdomains, "sipdomains", 21, lambda x: DHCP6OptSIPDomains(sipdomains=x)),
                  (nisservers, "nisservers", 27, lambda x: DHCP6OptNISServers(nisservers=x)),
                  (nisdomain, "nisdomain", 29, lambda x: DHCP6OptNISDomain(nisdomain=(x+[""])[0])),
                  (nispservers, "nispservers", 28, lambda x: DHCP6OptNISPServers(nispservers=x)), 
                  (nispdomain, "nispdomain", 30, lambda x: DHCP6OptNISPDomain(nispdomain=(x+[""])[0])),
                  (bcmcsservers, "bcmcsservers", 33, lambda x: DHCP6OptBCMCSServers(bcmcsservers=x)),
                  (bcmcsdomains, "bcmcsdomains", 34, lambda x: DHCP6OptBCMCSDomains(bcmcsdomains=x))]:

            opt = norm_list(o[0], o[1])
            if opt == -1: # Usage() was triggered
                return False
            elif opt is None: # We won't return that option
                pass
            else:
                self.dhcpv6_options[o[2]] = o[3](opt)

        if self.debug:
            print "\n[+] List of active DHCPv6 options:"
            opts = self.dhcpv6_options.keys()
            opts.sort()
            for i in opts:
                print "    %d: %s" % (i, repr(self.dhcpv6_options[i]))

        # Preference value used in Advertise. 
        self.advpref = advpref

        # IP Pool
        self.startip = startip
        self.endip   = endip
        # XXX TODO Check IPs are in same subnet

        ####
        # The interface we are listening/replying on
        self.iface = iface

        ####        
        # Generate a server DUID
        if duid is not None:
            self.duid = duid
        else:
            # Timeval
            from time import gmtime, strftime, mktime
            epoch = (2000, 1, 1, 0, 0, 0, 5, 1, 0)
            delta = mktime(epoch) - mktime(gmtime(0))
            timeval = time.time() - delta

            # Mac Address
            rawmac = get_if_raw_hwaddr(iface)[1]
            mac = ":".join(map(lambda x: "%.02x" % ord(x), list(rawmac)))

            self.duid = DUID_LLT(timeval = timeval, lladdr = mac)
            
        if self.debug:
            print "\n[+] Our server DUID:" 
            self.duid.show(label_lvl=" "*4)

        ####
        # Find the source address we will use
        l = filter(lambda x: x[2] == iface and in6_islladdr(x[0]), 
                   in6_getifaddr())
        if not l:
            warning("Unable to get a Link-Local address")
            return 
        
        self.src_addr = l[0][0]

        ####
        # Our leases
        self.leases = {}
        

        if self.debug:
            print "\n[+] Starting DHCPv6 service on %s:" % self.iface 

    def is_request(self, p):
        if not IPv6 in p:
            return False

        src = p[IPv6].src
        dst = p[IPv6].dst

        p = p[IPv6].payload 
        if not isinstance(p, UDP) or p.sport != 546 or p.dport != 547 :
            return False

        p = p.payload
        if not isinstance(p, DHCP6):
            return False

        # Message we considered client messages :
        # Solicit (1), Request (3), Confirm (4), Renew (5), Rebind (6)
        # Decline (9), Release (8), Information-request (11),
        if not (p.msgtype in [1, 3, 4, 5, 6, 8, 9, 11]):
            return False

        # Message validation following section 15 of RFC 3315

        if ((p.msgtype == 1) or # Solicit 
            (p.msgtype == 6) or # Rebind
            (p.msgtype == 4)):  # Confirm
            if ((not DHCP6OptClientId in p) or
                DHCP6OptServerId in p):
                return False

            if (p.msgtype == 6 or # Rebind
                p.msgtype == 4):  # Confirm   
                # XXX We do not reply to Confirm or Rebind as we 
                # XXX do not support address assignment            
                return False

        elif (p.msgtype == 3 or # Request
              p.msgtype == 5 or # Renew
              p.msgtype == 8):  # Release
        
            # Both options must be present
            if ((not DHCP6OptServerId in p) or
                (not DHCP6OptClientId in p)):
                return False
            # provided server DUID must match ours
            duid = p[DHCP6OptServerId].duid
            if (type(duid) != type(self.duid)):
                return False
            if str(duid) != str(self.duid):
                return False

            if (p.msgtype == 5 or # Renew
                p.msgtype == 8):  # Release
                # XXX We do not reply to Renew or Release as we 
                # XXX do not support address assignment            
                return False

        elif p.msgtype == 9: # Decline
            # XXX We should check if we are tracking that client
            if not self.debug:
                return False

            bo = Color.bold
            g = Color.green + bo
            b = Color.blue + bo
            n = Color.normal
            r = Color.red

            vendor  = in6_addrtovendor(src)
            if (vendor and vendor != "UNKNOWN"):
                vendor = " [" + b + vendor + n + "]"
            else:
                vendor = ""
            src  = bo + src + n

            it = p
            addrs = []
            while it:
                l = []
                if isinstance(it, DHCP6OptIA_NA):
                    l = it.ianaopts
                elif isinstance(it, DHCP6OptIA_TA):
                    l = it.iataopts

                opsaddr = filter(lambda x: isinstance(x, DHCP6OptIAAddress),l)
                a=map(lambda x: x.addr,  opsaddr)
                addrs += a
                it = it.payload
                    
            addrs = map(lambda x: bo + x + n, addrs)
            if debug:
                msg = r + "[DEBUG]" + n + " Received " + g + "Decline" + n 
                msg += " from " + bo + src + vendor + " for "
                msg += ", ".join(addrs)+ n
                print msg

            # See sect 18.1.7

            # Sent by a client to warn us she has determined
            # one or more addresses assigned to her is already
            # used on the link.
            # We should simply log that fact. No messaged should
            # be sent in return.

            # - Message must include a Server identifier option
            # - the content of the Server identifier option must 
            #   match the server's identifier
            # - the message must include a Client Identifier option
            return False

        elif p.msgtype == 11: # Information-Request
            if DHCP6OptServerId in p:
                duid = p[DHCP6OptServerId].duid
                if (type(duid) != type(self.duid)):
                    return False
                if str(duid) != str(self.duid):
                    return False
            if ((DHCP6OptIA_NA in p) or 
                (DHCP6OptIA_TA in p) or
                (DHCP6OptIA_PD in p)):
                    return False
        else:
            return False

        return True

    def print_reply(self, req, reply):
        def norm(s):
            if s.startswith("DHCPv6 "):
                s = s[7:]
            if s.endswith(" Message"):
                s = s[:-8]
            return s
        
        if reply is None:
            return

        bo = Color.bold
        g = Color.green + bo
        b = Color.blue + bo
        n = Color.normal
        reqtype = g + norm(req.getlayer(UDP).payload.name) + n
        reqsrc  = req.getlayer(IPv6).src
        vendor  = in6_addrtovendor(reqsrc)
        if (vendor and vendor != "UNKNOWN"):
            vendor = " [" + b + vendor + n + "]"
        else:
            vendor = ""
        reqsrc  = bo + reqsrc + n
        reptype = g + norm(reply.getlayer(UDP).payload.name) + n

        print "Sent %s answering to %s from %s%s" % (reptype, reqtype, reqsrc, vendor)

    def make_reply(self, req):
        req_mac_src = req.src
        req_mac_dst = req.dst

        p = req[IPv6]
        req_src = p.src
        req_dst = p.dst

        p = p.payload.payload

        msgtype = p.msgtype
        trid = p.trid

        if msgtype == 1: # SOLICIT (See Sect 17.1 and 17.2 of RFC 3315)
            
            # XXX We don't support address or prefix assignment
            # XXX We also do not support relay function           --arno

            client_duid = p[DHCP6OptClientId].duid
            resp  = IPv6(src=self.src_addr, dst=req_src)
            resp /= UDP(sport=547, dport=546)
            
            if p.haslayer(DHCP6OptRapidCommit):
                # construct a Reply packet 
                resp /= DHCP6_Reply(trid=trid)
                resp /= DHCP6OptRapidCommit() # See 17.1.2
                resp /= DHCP6OptServerId(duid = self.duid)
                resp /= DHCP6OptClientId(duid = client_duid)
                
            else: # No Rapid Commit in the packet. Reply with an Advertise                
                
                if (p.haslayer(DHCP6OptIA_NA) or
                    p.haslayer(DHCP6OptIA_TA)):
                    # XXX We don't assign addresses at the moment
                    msg = "Scapy6 dhcp6d does not support address assignment"
                    resp /= DHCP6_Advertise(trid = trid)
                    resp /= DHCP6OptStatusCode(statuscode=2, statusmsg=msg)
                    resp /= DHCP6OptServerId(duid = self.duid)
                    resp /= DHCP6OptClientId(duid = client_duid)                  

                elif p.haslayer(DHCP6OptIA_PD):
                    # XXX We don't assign prefixes at the moment
                    msg = "Scapy6 dhcp6d does not support prefix assignment"
                    resp /= DHCP6_Advertise(trid = trid)
                    resp /= DHCP6OptStatusCode(statuscode=6, statusmsg=msg)
                    resp /= DHCP6OptServerId(duid = self.duid)
                    resp /= DHCP6OptClientId(duid = client_duid)                  

                else: # Usual case, no request for prefixes or addresse
                    resp /= DHCP6_Advertise(trid = trid)
                    resp /= DHCP6OptPref(prefval = self.advpref)
                    resp /= DHCP6OptServerId(duid = self.duid)
                    resp /= DHCP6OptClientId(duid = client_duid)
                    resp /= DHCP6OptReconfAccept()
                    
                    # See which options should be included
                    reqopts = []
                    if p.haslayer(DHCP6OptOptReq): # add only asked ones
                        reqopts = p[DHCP6OptOptReq].reqopts
                        for o in self.dhcpv6_options.keys():
                            if o in reqopts:
                                resp /= self.dhcpv6_options[o]
                    else: # advertise everything we have available
                        for o in self.dhcpv6_options.keys():
                            resp /= self.dhcpv6_options[o]                    

            return resp

        elif msgtype == 3: #REQUEST (INFO-REQUEST is further below)
            client_duid = p[DHCP6OptClientId].duid
            resp  = IPv6(src=self.src_addr, dst=req_src)
            resp /= UDP(sport=547, dport=546)
            resp /= DHCP6_Solicit(trid=trid)
            resp /= DHCP6OptServerId(duid = self.duid)
            resp /= DHCP6OptClientId(duid = client_duid)

            # See which options should be included
            reqopts = []
            if p.haslayer(DHCP6OptOptReq): # add only asked ones
                reqopts = p[DHCP6OptOptReq].reqopts
                for o in self.dhcpv6_options.keys():
                    if o in reqopts:
                        resp /= self.dhcpv6_options[o]
            else: 
                # advertise everything we have available.
                # Should not happen has clients MUST include 
                # and ORO in requests (sec 18.1.1)   -- arno
                for o in self.dhcpv6_options.keys():
                    resp /= self.dhcpv6_options[o]          

            return resp            
        
        elif msgtype == 4: # CONFIRM
            # see Sect 18.1.2
            
            # Client want to check if addresses it was assigned
            # are still appropriate

            # Server must discard any Confirm messages that
            # do not include a Client Identifier option OR
            # THAT DO INCLUDE a Server Identifier Option

            # XXX we must discard the SOLICIT if it is received with
            #     a unicast destination address

            pass

        elif msgtype == 5: # RENEW
            # see Sect 18.1.3
            
            # Clients want to extend lifetime of assigned addresses
            # and update configuration parameters. This message is sent
            # specifically to the server that provided her the info

            # - Received message must include a Server Identifier
            #   option.
            # - the content of server identifier option must match
            #   the server's identifier.
            # - the message must include a Client identifier option

            pass
        
        elif msgtype == 6: # REBIND
            # see Sect 18.1.4
            
            # Same purpose as the Renew message but sent to any
            # available server after he received no response
            # to its previous Renew message.

            
            # - Message must include a Client Identifier Option
            # - Message can't include a Server identifier option

            # XXX we must discard the SOLICIT if it is received with
            #     a unicast destination address

            pass

        elif msgtype == 8: # RELEASE
            # See section 18.1.6

            # Message is sent to the server to indicate that 
            # she will no longer use the addresses that was assigned
            # We should parse the message and verify our dictionary
            # to log that fact.


            # - The message must include a server identifier option
            # - The content of the Server Identifier option must
            #   match the server's identifier
            # - the message must include a Client Identifier option

            pass

        elif msgtype == 9: # DECLINE
            # See section 18.1.7            
            pass

        elif msgtype == 11: # INFO-REQUEST
            client_duid = None
            if not p.haslayer(DHCP6OptClientId):
                if self.debug:
                    warning("Received Info Request message without Client Id option")
            else:
                client_duid = p[DHCP6OptClientId].duid

            resp  = IPv6(src=self.src_addr, dst=req_src)
            resp /= UDP(sport=547, dport=546)
            resp /= DHCP6_Reply(trid=trid)
            resp /= DHCP6OptServerId(duid = self.duid)

            if client_duid:
                resp /= DHCP6OptClientId(duid = client_duid)
                
            # Stack requested options if available
            reqopts = []
            if p.haslayer(DHCP6OptOptReq):
                reqopts = p[DHCP6OptOptReq].reqopts
            for o in self.dhcpv6_options.keys():
                resp /= self.dhcpv6_options[o]

            return resp

        else:
            # what else ?
            pass

        # - We won't support reemission
        # - We won't support relay role, nor relay forwarded messages
        #   at the beginning

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
      delta = x*((curpos - y + x - 1)/x) + y - curpos
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
                    ByteField("olen", 16),
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
    epoch = (1900, 1, 1, 0, 0, 0, 5, 1, 0)
    def i2repr(self, pkt, x):
        if x < ((50*31536000)<<32):
            return "Some date a few decades ago (%d)" % x

        # delta from epoch (= (1900, 1, 1, 0, 0, 0, 5, 1, 0)) to 
        # January 1st 1970 :
        delta = -2209075761
        i = int(x >> 32)
        j = float(x & 0xffffffff) * 2.0**-32
        res = i + j + delta
        from time import strftime
        t = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(res))

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
                    StrLenField("cokt", '\x00'*8,
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
            l = (len(p)-8)/8
        p = p[0] + struct.pack("B", l) + p[2:]
        if self.cksum is None:
            cksum = in6_chksum(135, self.underlayer, p)
        else:
            cksum = self.cksum
        p = p[:4]+struct.pack("!H", cksum)+p[6:]
        return p


class MIP6MH_Generic(_MobilityHeader): # Mainly for decoding of unknown msg
    name = "IPv6 Mobility Header - Generic Message"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    ByteField("len", None),
                    ByteEnumField("mhtype", None, mhtypes),
                    ByteField("res", None),
                    XShortField("cksum", None),
                    StrLenField("msg", "\x00"*2,
                                length_from = lambda pkt: 8*pkt.len-6) ]


    
# TODO: make a generic _OptionsField
class _MobilityOptionsField(PacketListField):
    islist = 1
    holds_packet = 1

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
            o = ord(x[0]) # Option type
            cls = self.cls
            if moboptcls.has_key(o):
                cls = moboptcls[o]
            try:
                op = cls(x)
            except:
                op = self.cls(x)
            opt.append(op)
            if isinstance(op.payload, Raw):
                x = op.payload.load
                del(op.payload)
            else:
                x = ""
        return opt

    def i2m(self, pkt, x):
        autopad = None
        try:
            autopad = getattr(pkt, "autopad") # Hack : 'autopad' phantom field
        except:
            autopad = 1
            
        if not autopad:
            return "".join(map(str, x))

        curpos = self.curpos
        s = ""
        for p in x:
            d = p.alignment_delta(curpos)
            curpos += d
            if d == 1:
                s += str(Pad1())
            elif d != 0:
                s += str(PadN(optdata='\x00'*(d-2)))
            pstr = str(p)
            curpos += len(pstr)
            s += pstr
            
        # Let's make the class including our option field
        # a multiple of 8 octets long
        d = curpos % 8
        if d == 0:
            return s
        d = 8 - d
        if d == 1:
            s += str(Pad1())
        elif d != 0:
            s += str(PadN(optdata='\x00'*(d-2)))        

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
        #       value "\x00\x08\x09" (concatenation of mhtypes). This is
        #       because we need match BA with BU and BU with BRR. --arno
        return "\x00\x08\x09"

class MIP6MH_HoTI(_MobilityHeader):
    name = "IPv6 Mobility Header - Home Test Init"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    ByteField("len", None),
                    ByteEnumField("mhtype", 1, mhtypes),                    
                    ByteField("res", None),
                    XShortField("cksum", None),                    
                    StrFixedLenField("cookie", "\x00"*8, 8),
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _MobilityOptionsField("options", [], MIP6OptUnknown, 16,
                                          length_from = lambda pkt: 8*(pkt.len-1)) ]
    overload_fields = { IPv6: { "nh": 135 } }
    def hashret(self):
        return self.cookie

class MIP6MH_CoTI(MIP6MH_HoTI):
    name = "IPv6 Mobility Header - Care-of Test Init"
    __metaclass__ = NewDefaultValues
    mhtype = 2
    def hashret(self):
        return self.cookie

class MIP6MH_HoT(_MobilityHeader):
    name = "IPv6 Mobility Header - Home Test"
    fields_desc = [ ByteEnumField("nh", 59, ipv6nh),
                    ByteField("len", None),
                    ByteEnumField("mhtype", 3, mhtypes),                    
                    ByteField("res", None),
                    XShortField("cksum", None),                    
                    ShortField("index", None),
                    StrFixedLenField("cookie", "\x00"*8, 8),
                    StrFixedLenField("token", "\x00"*8, 8),
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _MobilityOptionsField("options", [], MIP6OptUnknown, 24,
                                          length_from = lambda pkt: 8*(pkt.len-2)) ]
    overload_fields = { IPv6: { "nh": 135 } }
    def hashret(self):
        return self.cookie
    def answers(self):
        if (isinstance(other, MIP6MH_HoTI) and
            self.cookie == other.cookie):
            return 1
        return 0

class MIP6MH_CoT(MIP6MH_HoT):
    name = "IPv6 Mobility Header - Care-of Test"
    __metaclass__ = NewDefaultValues
    mhtype = 4
    def hashret(self):
        return self.cookie

    def answers(self):
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
                    FlagsField("flags", 49, 6, "AHLKMR"),
                    XBitField("reserved", 0, 10),
                    LifetimeField("mhtime", 3), # unit == 4 seconds
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _MobilityOptionsField("options", [], MIP6OptUnknown, 12,
                                          length_from = lambda pkt: 8*pkt.len - 4) ]
    overload_fields = { IPv6: { "nh": 135 } }

    def hashret(self): # Hack: see comment in MIP6MH_BRR.hashret()
        return "\x00\x08\x09"

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
                    FlagsField("flags", 2, 2, "KR"),
                    XBitField("res2", None, 6),
                    XShortField("seq", None), # TODO: ShortNonceField
                    XShortField("mhtime", 0), # unit == 4 seconds
                    _PhantomAutoPadField("autopad", 1), # autopad activated by default
                    _MobilityOptionsField("options", [], MIP6OptUnknown, 12,
                                          length_from = lambda pkt: 8*pkt.len-4) ]
    overload_fields = { IPv6: { "nh": 135 }}

    def hashret(self): # Hack: see comment in MIP6MH_BRR.hashret()
        return "\x00\x08\x09"

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

        return ip,asn,desc        

class TracerouteResult6(TracerouteResult):
    def show(self):
        return self.make_table(lambda (s,r): (s.sprintf("%-42s,IPv6.dst%:{TCP:tcp%TCP.dport%}{UDP:udp%UDP.dport%}{ICMPv6EchoRequest:IER}"), # TODO: ICMPv6 !
                                              s.hlim,
                                              r.sprintf("%-42s,IPv6.src% {TCP:%TCP.flags%}"+
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

        for k in trace.values():
            m = filter(lambda x: k[x][1], k.keys())
            if not m:
                continue
            m = min(m)
            for l in k.keys():
                if l > m:
                    del(k[l])

        return trace

    def graph(self, ASres=AS_resolver6(), **kargs):
        TracerouteResult.graph(self, ASres=ASres, **kargs)
    
def traceroute6(target, dport=80, minttl=1, maxttl=30, sport=RandShort(), 
                l4 = None, timeout=2, verbose=None, **kargs):
    """
    Instant TCP traceroute using IPv6 :
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
###                          Layers binding                               ###
#############################################################################
#############################################################################

conf.l3types.register(ETH_P_IPV6, IPv6)
conf.l2types.register(31, IPv6)

bind_layers(Ether,     IPv6,     type = 0x86dd )
bind_layers(IPerror6,  TCPerror, nh = socket.IPPROTO_TCP )
bind_layers(IPerror6,  UDPerror, nh = socket.IPPROTO_UDP )
bind_layers(IPv6,      TCP,      nh = socket.IPPROTO_TCP )
bind_layers(IPv6,      UDP,      nh = socket.IPPROTO_UDP )
bind_layers(IP,        IPv6,     proto = socket.IPPROTO_IPV6 )
bind_layers(IPv6,      IPv6,     nh = socket.IPPROTO_IPV6 )

