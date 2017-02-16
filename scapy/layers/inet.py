## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
IPv4 (Internet Protocol v4).
"""

import os,time,struct,re,socket,new
from select import select
from collections import defaultdict

from scapy.utils import checksum,inet_aton,inet_ntoa
from scapy.base_classes import Gen
from scapy.data import *
from scapy.layers.l2 import *
from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.fields import *
from scapy.packet import *
from scapy.volatile import *
from scapy.sendrecv import sr,sr1,srp1
from scapy.plist import PacketList,SndRcvList
from scapy.automaton import Automaton,ATMT
from scapy.error import warning
from scapy.utils import whois

import scapy.as_resolvers

from scapy.arch import plt, MATPLOTLIB_INLINED, MATPLOTLIB_DEFAULT_PLOT_KARGS

####################
## IP Tools class ##
####################

class IPTools(object):
    """Add more powers to a class with an "src" attribute."""
    __slots__ = []
    def whois(self):
        """whois the source and print the output"""
        if WINDOWS:
            print whois(self.src)
        else:
            os.system("whois %s" % self.src)
    def ottl(self):
        t = [32,64,128,255]+[self.ttl]
        t.sort()
        return t[t.index(self.ttl)+1]
    def hops(self):
        return self.ottl() - self.ttl


_ip_options_names = { 0: "end_of_list",
                      1: "nop",
                      2: "security",
                      3: "loose_source_route",
                      4: "timestamp",
                      5: "extended_security",
                      6: "commercial_security",
                      7: "record_route",
                      8: "stream_id",
                      9: "strict_source_route",
                      10: "experimental_measurement",
                      11: "mtu_probe",
                      12: "mtu_reply",
                      13: "flow_control",
                      14: "access_control",
                      15: "encode",
                      16: "imi_traffic_descriptor",
                      17: "extended_IP",
                      18: "traceroute",
                      19: "address_extension",
                      20: "router_alert",
                      21: "selective_directed_broadcast_mode",
                      23: "dynamic_packet_state",
                      24: "upstream_multicast_packet",
                      25: "quick_start",
                      30: "rfc4727_experiment", 
                      }
                      

class _IPOption_HDR(Packet):
    fields_desc = [ BitField("copy_flag",0, 1),
                    BitEnumField("optclass",0,2,{0:"control",2:"debug"}),
                    BitEnumField("option",0,5, _ip_options_names) ]
    
class IPOption(Packet):
    name = "IP Option"
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",  # Only option 0 and 1 have no length and value
                                  length_of="value", adjust=lambda pkt,l:l+2),
                    StrLenField("value", "",length_from=lambda pkt:pkt.length-2) ]
    
    def extract_padding(self, p):
        return "",p

    registered_ip_options = {}
    @classmethod
    def register_variant(cls):
        cls.registered_ip_options[cls.option.default] = cls
    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        if pkt:
            opt = ord(pkt[0])&0x1f
            if opt in cls.registered_ip_options:
                return cls.registered_ip_options[opt]
        return cls

class IPOption_EOL(IPOption):
    name = "IP Option End of Options List"
    option = 0
    fields_desc = [ _IPOption_HDR ]
    

class IPOption_NOP(IPOption):
    name = "IP Option No Operation"
    option=1
    fields_desc = [ _IPOption_HDR ]

class IPOption_Security(IPOption):
    name = "IP Option Security"
    copy_flag = 1
    option = 2
    fields_desc = [ _IPOption_HDR,
                    ByteField("length", 11),
                    ShortField("security",0),
                    ShortField("compartment",0),
                    ShortField("handling_restrictions",0),
                    StrFixedLenField("transmission_control_code","xxx",3),
                    ]
    
class IPOption_RR(IPOption):
    name = "IP Option Record Route"
    option = 7
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="routers", adjust=lambda pkt,l:l+3),
                    ByteField("pointer",4), # 4 is first IP
                    FieldListField("routers",[],IPField("","0.0.0.0"), 
                                   length_from=lambda pkt:pkt.length-3)
                    ]
    def get_current_router(self):
        return self.routers[self.pointer/4-1]

class IPOption_LSRR(IPOption_RR):
    name = "IP Option Loose Source and Record Route"
    copy_flag = 1
    option = 3

class IPOption_SSRR(IPOption_RR):
    name = "IP Option Strict Source and Record Route"
    copy_flag = 1
    option = 9

class IPOption_Stream_Id(IPOption):
    name = "IP Option Stream ID"
    copy_flag = 1
    option = 8
    fields_desc = [ _IPOption_HDR,
                    ByteField("length", 4),
                    ShortField("security",0), ]
                    
class IPOption_MTU_Probe(IPOption):
    name = "IP Option MTU Probe"
    option = 11
    fields_desc = [ _IPOption_HDR,
                    ByteField("length", 4),
                    ShortField("mtu",0), ]

class IPOption_MTU_Reply(IPOption_MTU_Probe):
    name = "IP Option MTU Reply"
    option = 12

class IPOption_Traceroute(IPOption):
    name = "IP Option Traceroute"
    option = 18
    fields_desc = [ _IPOption_HDR,
                    ByteField("length", 12),
                    ShortField("id",0),
                    ShortField("outbound_hops",0),
                    ShortField("return_hops",0),
                    IPField("originator_ip","0.0.0.0") ]

class IPOption_Address_Extension(IPOption):
    name = "IP Option Address Extension"
    copy_flag = 1
    option = 19
    fields_desc = [ _IPOption_HDR,
                    ByteField("length", 10),
                    IPField("src_ext","0.0.0.0"),
                    IPField("dst_ext","0.0.0.0") ]

class IPOption_Router_Alert(IPOption):
    name = "IP Option Router Alert"
    copy_flag = 1
    option = 20
    fields_desc = [ _IPOption_HDR,
                    ByteField("length", 4),
                    ShortEnumField("alert",0, {0:"router_shall_examine_packet"}), ]


class IPOption_SDBM(IPOption):
    name = "IP Option Selective Directed Broadcast Mode"
    copy_flag = 1
    option = 21
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="addresses", adjust=lambda pkt,l:l+2),
                    FieldListField("addresses",[],IPField("","0.0.0.0"), 
                                   length_from=lambda pkt:pkt.length-2)
                    ]
    


TCPOptions = (
              { 0 : ("EOL",None),
                1 : ("NOP",None),
                2 : ("MSS","!H"),
                3 : ("WScale","!B"),
                4 : ("SAckOK",None),
                5 : ("SAck","!"),
                8 : ("Timestamp","!II"),
                14 : ("AltChkSum","!BH"),
                15 : ("AltChkSumOpt",None),
                25 : ("Mood","!p"),
                28 : ("UTO", "!H"),
                34 : ("TFO", "!II"),
                },
              { "EOL":0,
                "NOP":1,
                "MSS":2,
                "WScale":3,
                "SAckOK":4,
                "SAck":5,
                "Timestamp":8,
                "AltChkSum":14,
                "AltChkSumOpt":15,
                "Mood":25,
                "UTO":28,
                "TFO":34,
                } )

class TCPOptionsField(StrField):
    islist=1
    def getfield(self, pkt, s):
        opsz = (pkt.dataofs-5)*4
        if opsz < 0:
            warning("bad dataofs (%i). Assuming dataofs=5"%pkt.dataofs)
            opsz = 0
        return s[opsz:],self.m2i(pkt,s[:opsz])
    def m2i(self, pkt, x):
        opt = []
        while x:
            onum = ord(x[0])
            if onum == 0:
                opt.append(("EOL",None))
                x=x[1:]
                break
            if onum == 1:
                opt.append(("NOP",None))
                x=x[1:]
                continue
            olen = ord(x[1])
            if olen < 2:
                warning("Malformed TCP option (announced length is %i)" % olen)
                olen = 2
            oval = x[2:olen]
            if TCPOptions[0].has_key(onum):
                oname, ofmt = TCPOptions[0][onum]
                if onum == 5: #SAck
                    ofmt += "%iI" % (len(oval)/4)
                if ofmt and struct.calcsize(ofmt) == len(oval):
                    oval = struct.unpack(ofmt, oval)
                    if len(oval) == 1:
                        oval = oval[0]
                opt.append((oname, oval))
            else:
                opt.append((onum, oval))
            x = x[olen:]
        return opt
    
    def i2m(self, pkt, x):
        opt = ""
        for oname,oval in x:
            if type(oname) is str:
                if oname == "NOP":
                    opt += "\x01"
                    continue
                elif oname == "EOL":
                    opt += "\x00"
                    continue
                elif TCPOptions[1].has_key(oname):
                    onum = TCPOptions[1][oname]
                    ofmt = TCPOptions[0][onum][1]
                    if onum == 5: #SAck
                        ofmt += "%iI" % len(oval)
                    if ofmt is not None and (type(oval) is not str or "s" in ofmt):
                        if type(oval) is not tuple:
                            oval = (oval,)
                        oval = struct.pack(ofmt, *oval)
                else:
                    warning("option [%s] unknown. Skipped."%oname)
                    continue
            else:
                onum = oname
                if type(oval) is not str:
                    warning("option [%i] is not string."%onum)
                    continue
            opt += chr(onum)+chr(2+len(oval))+oval
        return opt+"\x00"*(3-((len(opt)+3)%4))
    def randval(self):
        return [] # XXX
    

class ICMPTimeStampField(IntField):
    re_hmsm = re.compile("([0-2]?[0-9])[Hh:](([0-5]?[0-9])([Mm:]([0-5]?[0-9])([sS:.]([0-9]{0,3}))?)?)?$")
    def i2repr(self, pkt, val):
        if val is None:
            return "--"
        else:
            sec, milli = divmod(val, 1000)
            min, sec = divmod(sec, 60)
            hour, min = divmod(min, 60)
            return "%d:%d:%d.%d" %(hour, min, sec, int(milli))
    def any2i(self, pkt, val):
        if type(val) is str:
            hmsms = self.re_hmsm.match(val)
            if hmsms:
                h,_,m,_,s,_,ms = hmsms = hmsms.groups()
                ms = int(((ms or "")+"000")[:3])
                val = ((int(h)*60+int(m or 0))*60+int(s or 0))*1000+ms
            else:
                val = 0
        elif val is None:
            val = int((time.time()%(24*60*60))*1000)
        return val


class DestIPField(IPField, DestField):
    bindings = {}
    def __init__(self, name, default):
        IPField.__init__(self, name, None)
        DestField.__init__(self, name, default)
    def i2m(self, pkt, x):
        if x is None:
            x = self.dst_from_pkt(pkt)
        return IPField.i2m(self, pkt, x)
    def i2h(self, pkt, x):
        if x is None:
            x = self.dst_from_pkt(pkt)
        return IPField.i2h(self, pkt, x)


class IP(Packet, IPTools):
    __slots__ = ["_defrag_pos"]
    name = "IP"
    fields_desc = [ BitField("version" , 4 , 4),
                    BitField("ihl", None, 4),
                    XByteField("tos", 0),
                    ShortField("len", None),
                    ShortField("id", 1),
                    FlagsField("flags", 0, 3, ["MF","DF","evil"]),
                    BitField("frag", 0, 13),
                    ByteField("ttl", 64),
                    ByteEnumField("proto", 0, IP_PROTOS),
                    XShortField("chksum", None),
                    #IPField("src", "127.0.0.1"),
                    Emph(SourceIPField("src","dst")),
                    Emph(DestIPField("dst", "127.0.0.1")),
                    PacketListField("options", [], IPOption, length_from=lambda p:p.ihl*4-20) ]
    def post_build(self, p, pay):
        ihl = self.ihl
        p += "\0"*((-len(p))%4) # pad IP options if needed
        if ihl is None:
            ihl = len(p)/4
            p = chr(((self.version&0xf)<<4) | ihl&0x0f)+p[1:]
        if self.len is None:
            l = len(p)+len(pay)
            p = p[:2]+struct.pack("!H", l)+p[4:]
        if self.chksum is None:
            ck = checksum(p)
            p = p[:10]+chr(ck>>8)+chr(ck&0xff)+p[12:]
        return p+pay

    def extract_padding(self, s):
        l = self.len - (self.ihl << 2)
        return s[:l],s[l:]

    def route(self):
        dst = self.dst
        if isinstance(dst,Gen):
            dst = iter(dst).next()
        if conf.route is None:
            # unused import, only to initialize conf.route
            import scapy.route
        return conf.route.route(dst)
    def hashret(self):
        if ( (self.proto == socket.IPPROTO_ICMP)
             and (isinstance(self.payload, ICMP))
             and (self.payload.type in [3,4,5,11,12]) ):
            return self.payload.payload.hashret()
        if not conf.checkIPinIP and self.proto in [4, 41]:  # IP, IPv6
            return self.payload.hashret()
        if self.dst == "224.0.0.251":  # mDNS
            return struct.pack("B", self.proto) + self.payload.hashret()
        if conf.checkIPsrc and conf.checkIPaddr:
            return (strxor(inet_aton(self.src), inet_aton(self.dst))
                    + struct.pack("B",self.proto) + self.payload.hashret())
        return struct.pack("B", self.proto) + self.payload.hashret()
    def answers(self, other):
        if not conf.checkIPinIP:  # skip IP in IP and IPv6 in IP
            if self.proto in [4, 41]:
                return self.payload.answers(other)
            if isinstance(other, IP) and other.proto in [4, 41]:
                return self.answers(other.payload)
            if conf.ipv6_enabled \
               and isinstance(other, scapy.layers.inet6.IPv6) \
               and other.nh in [4, 41]:
                return self.answers(other.payload)                
        if not isinstance(other,IP):
            return 0
        if conf.checkIPaddr:
            if other.dst == "224.0.0.251" and self.dst == "224.0.0.251":  # mDNS
                return self.payload.answers(other.payload)
            elif (self.dst != other.src):
                return 0
        if ( (self.proto == socket.IPPROTO_ICMP) and
             (isinstance(self.payload, ICMP)) and
             (self.payload.type in [3,4,5,11,12]) ):
            # ICMP error message
            return self.payload.payload.answers(other)

        else:
            if ( (conf.checkIPaddr and (self.src != other.dst)) or
                 (self.proto != other.proto) ):
                return 0
            return self.payload.answers(other.payload)
    def mysummary(self):
        s = self.sprintf("%IP.src% > %IP.dst% %IP.proto%")
        if self.frag:
            s += " frag:%i" % self.frag
        return s
                 
    def fragment(self, fragsize=1480):
        """Fragment IP datagrams"""
        fragsize = (fragsize+7)/8*8
        lst = []
        fnb = 0
        fl = self
        while fl.underlayer is not None:
            fnb += 1
            fl = fl.underlayer
        
        for p in fl:
            s = str(p[fnb].payload)
            nb = (len(s)+fragsize-1)/fragsize
            for i in xrange(nb):            
                q = p.copy()
                del(q[fnb].payload)
                del(q[fnb].chksum)
                del(q[fnb].len)
                if i != nb - 1:
                    q[fnb].flags |= 1
                q[fnb].frag += i * fragsize / 8
                r = conf.raw_layer(load=s[i*fragsize:(i+1)*fragsize])
                r.overload_fields = p[fnb].payload.overload_fields.copy()
                q.add_payload(r)
                lst.append(q)
        return lst


class TCP(Packet):
    name = "TCP"
    fields_desc = [ ShortEnumField("sport", 20, TCP_SERVICES),
                    ShortEnumField("dport", 80, TCP_SERVICES),
                    IntField("seq", 0),
                    IntField("ack", 0),
                    BitField("dataofs", None, 4),
                    BitField("reserved", 0, 3),
                    FlagsField("flags", 0x2, 9, "FSRPAUECN"),
                    ShortField("window", 8192),
                    XShortField("chksum", None),
                    ShortField("urgptr", 0),
                    TCPOptionsField("options", {}) ]
    def post_build(self, p, pay):
        p += pay
        dataofs = self.dataofs
        if dataofs is None:
            dataofs = 5+((len(self.get_field("options").i2m(self,self.options))+3)/4)
            p = p[:12]+chr((dataofs << 4) | ord(p[12])&0x0f)+p[13:]
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                if self.underlayer.len is not None:
                    if self.underlayer.ihl is None:
                        olen = sum(len(x) for x in self.underlayer.options)
                        ihl = 5 + olen / 4 + (1 if olen % 4 else 0)
                    else:
                        ihl = self.underlayer.ihl
                    ln = self.underlayer.len - 4 * ihl
                else:
                    ln = len(p)
                psdhdr = struct.pack("!4s4sHH",
                                     inet_aton(self.underlayer.src),
                                     inet_aton(self.underlayer.dst),
                                     self.underlayer.proto,
                                     ln)
                ck=checksum(psdhdr+p)
                p = p[:16]+struct.pack("!H", ck)+p[18:]
            elif conf.ipv6_enabled and isinstance(self.underlayer, scapy.layers.inet6.IPv6) or isinstance(self.underlayer, scapy.layers.inet6._IPv6ExtHdr):
                ck = scapy.layers.inet6.in6_chksum(socket.IPPROTO_TCP, self.underlayer, p)
                p = p[:16]+struct.pack("!H", ck)+p[18:]
            else:
                warning("No IP underlayer to compute checksum. Leaving null.")
        return p
    def hashret(self):
        if conf.checkIPsrc:
            return struct.pack("H",self.sport ^ self.dport)+self.payload.hashret()
        else:
            return self.payload.hashret()
    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.dport) and
                    (self.dport == other.sport)):
                return 0
        if (abs(other.seq-self.ack) > 2+len(other.payload)):
            return 0
        return 1
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("TCP %IP.src%:%TCP.sport% > %IP.dst%:%TCP.dport% %TCP.flags%")
        elif conf.ipv6_enabled and isinstance(self.underlayer, scapy.layers.inet6.IPv6):
            return self.underlayer.sprintf("TCP %IPv6.src%:%TCP.sport% > %IPv6.dst%:%TCP.dport% %TCP.flags%")
        else:
            return self.sprintf("TCP %TCP.sport% > %TCP.dport% %TCP.flags%")

class UDP(Packet):
    name = "UDP"
    fields_desc = [ ShortEnumField("sport", 53, UDP_SERVICES),
                    ShortEnumField("dport", 53, UDP_SERVICES),
                    ShortField("len", None),
                    XShortField("chksum", None), ]
    def post_build(self, p, pay):
        p += pay
        l = self.len
        if l is None:
            l = len(p)
            p = p[:4]+struct.pack("!H",l)+p[6:]
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                if self.underlayer.len is not None:
                    if self.underlayer.ihl is None:
                        olen = sum(len(x) for x in self.underlayer.options)
                        ihl = 5 + olen / 4 + (1 if olen % 4 else 0)
                    else:
                        ihl = self.underlayer.ihl
                    ln = self.underlayer.len - 4 * ihl
                else:
                    ln = len(p)
                psdhdr = struct.pack("!4s4sHH",
                                     inet_aton(self.underlayer.src),
                                     inet_aton(self.underlayer.dst),
                                     self.underlayer.proto,
                                     ln)
                ck = checksum(psdhdr+p)
                # According to RFC768 if the result checksum is 0, it should be set to 0xFFFF
                if ck == 0:
                    ck = 0xFFFF
                p = p[:6]+struct.pack("!H", ck)+p[8:]
            elif isinstance(self.underlayer, scapy.layers.inet6.IPv6) or isinstance(self.underlayer, scapy.layers.inet6._IPv6ExtHdr):
                ck = scapy.layers.inet6.in6_chksum(socket.IPPROTO_UDP, self.underlayer, p)
                # According to RFC2460 if the result checksum is 0, it should be set to 0xFFFF
                if ck == 0:
                    ck = 0xFFFF
                p = p[:6]+struct.pack("!H", ck)+p[8:]
            else:
                warning("No IP underlayer to compute checksum. Leaving null.")
        return p
    def extract_padding(self, s):
        l = self.len - 8
        return s[:l],s[l:]
    def hashret(self):
        return self.payload.hashret()
    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if conf.checkIPsrc:
            if self.dport != other.sport:
                return 0
        return self.payload.answers(other.payload)
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("UDP %IP.src%:%UDP.sport% > %IP.dst%:%UDP.dport%")
        elif isinstance(self.underlayer, scapy.layers.inet6.IPv6):
            return self.underlayer.sprintf("UDP %IPv6.src%:%UDP.sport% > %IPv6.dst%:%UDP.dport%")
        else:
            return self.sprintf("UDP %UDP.sport% > %UDP.dport%")    

icmptypes = { 0 : "echo-reply",
              3 : "dest-unreach",
              4 : "source-quench",
              5 : "redirect",
              8 : "echo-request",
              9 : "router-advertisement",
              10 : "router-solicitation",
              11 : "time-exceeded",
              12 : "parameter-problem",
              13 : "timestamp-request",
              14 : "timestamp-reply",
              15 : "information-request",
              16 : "information-response",
              17 : "address-mask-request",
              18 : "address-mask-reply" }

icmpcodes = { 3 : { 0  : "network-unreachable",
                    1  : "host-unreachable",
                    2  : "protocol-unreachable",
                    3  : "port-unreachable",
                    4  : "fragmentation-needed",
                    5  : "source-route-failed",
                    6  : "network-unknown",
                    7  : "host-unknown",
                    9  : "network-prohibited",
                    10 : "host-prohibited",
                    11 : "TOS-network-unreachable",
                    12 : "TOS-host-unreachable",
                    13 : "communication-prohibited",
                    14 : "host-precedence-violation",
                    15 : "precedence-cutoff", },
              5 : { 0  : "network-redirect",
                    1  : "host-redirect",
                    2  : "TOS-network-redirect",
                    3  : "TOS-host-redirect", },
              11 : { 0 : "ttl-zero-during-transit",
                     1 : "ttl-zero-during-reassembly", },
              12 : { 0 : "ip-header-bad",
                     1 : "required-option-missing", }, }
                         
                   


class ICMP(Packet):
    name = "ICMP"
    fields_desc = [ ByteEnumField("type",8, icmptypes),
                    MultiEnumField("code",0, icmpcodes, depends_on=lambda pkt:pkt.type,fmt="B"),
                    XShortField("chksum", None),
                    ConditionalField(XShortField("id",0),  lambda pkt:pkt.type in [0,8,13,14,15,16,17,18]),
                    ConditionalField(XShortField("seq",0), lambda pkt:pkt.type in [0,8,13,14,15,16,17,18]),
                    ConditionalField(ICMPTimeStampField("ts_ori", None), lambda pkt:pkt.type in [13,14]),
                    ConditionalField(ICMPTimeStampField("ts_rx", None), lambda pkt:pkt.type in [13,14]),
                    ConditionalField(ICMPTimeStampField("ts_tx", None), lambda pkt:pkt.type in [13,14]),
                    ConditionalField(IPField("gw","0.0.0.0"),  lambda pkt:pkt.type==5),
                    ConditionalField(ByteField("ptr",0),   lambda pkt:pkt.type==12),
                    ConditionalField(ByteField("reserved",0), lambda pkt:pkt.type in [3,11]),
                    ConditionalField(ByteField("length",0), lambda pkt:pkt.type in [3,11,12]),
                    ConditionalField(IPField("addr_mask","0.0.0.0"), lambda pkt:pkt.type in [17,18]),
                    ConditionalField(ShortField("nexthopmtu",0), lambda pkt:pkt.type==3),
                    ConditionalField(ShortField("unused",0), lambda pkt:pkt.type in [11,12]),
                    ConditionalField(IntField("unused",0), lambda pkt:pkt.type not in [0,3,5,8,11,12,13,14,15,16,17,18])
                    ]
    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
        return p
    
    def hashret(self):
        if self.type in [0,8,13,14,15,16,17,18]:
            return struct.pack("HH",self.id,self.seq)+self.payload.hashret()
        return self.payload.hashret()
    def answers(self, other):
        if not isinstance(other,ICMP):
            return 0
        if ( (other.type,self.type) in [(8,0),(13,14),(15,16),(17,18)] and
             self.id == other.id and
             self.seq == other.seq ):
            return 1
        return 0

    def guess_payload_class(self, payload):
        if self.type in [3,4,5,11,12]:
            return IPerror
        else:
            return None
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("ICMP %IP.src% > %IP.dst% %ICMP.type% %ICMP.code%")
        else:
            return self.sprintf("ICMP %ICMP.type% %ICMP.code%")
    
        



class IPerror(IP):
    name = "IP in ICMP"
    def answers(self, other):
        if not isinstance(other, IP):
            return 0
        if not ( ((conf.checkIPsrc == 0) or (self.dst == other.dst)) and
                 (self.src == other.src) and
                 ( ((conf.checkIPID == 0)
                    or (self.id == other.id)
                    or (conf.checkIPID == 1 and self.id == socket.htons(other.id)))) and
                 (self.proto == other.proto) ):
            return 0
        return self.payload.answers(other.payload)
    def mysummary(self):
        return Packet.mysummary(self)


class TCPerror(TCP):
    name = "TCP in ICMP"
    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.sport) and
                    (self.dport == other.dport)):
                return 0
        if conf.check_TCPerror_seqack:
            if self.seq is not None:
                if self.seq != other.seq:
                    return 0
            if self.ack is not None:
                if self.ack != other.ack:
                    return 0
        return 1
    def mysummary(self):
        return Packet.mysummary(self)


class UDPerror(UDP):
    name = "UDP in ICMP"
    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.sport) and
                    (self.dport == other.dport)):
                return 0
        return 1
    def mysummary(self):
        return Packet.mysummary(self)

                    

class ICMPerror(ICMP):
    name = "ICMP in ICMP"
    def answers(self, other):
        if not isinstance(other,ICMP):
            return 0
        if not ((self.type == other.type) and
                (self.code == other.code)):
            return 0
        if self.code in [0,8,13,14,17,18]:
            if (self.id == other.id and
                self.seq == other.seq):
                return 1
            else:
                return 0
        else:
            return 1
    def mysummary(self):
        return Packet.mysummary(self)

bind_layers( Ether,         IP,            type=2048)
bind_layers( CookedLinux,   IP,            proto=2048)
bind_layers( GRE,           IP,            proto=2048)
bind_layers( SNAP,          IP,            code=2048)
bind_layers( Loopback,      IP,            type=2)
bind_layers( IPerror,       IPerror,       frag=0, proto=4)
bind_layers( IPerror,       ICMPerror,     frag=0, proto=1)
bind_layers( IPerror,       TCPerror,      frag=0, proto=6)
bind_layers( IPerror,       UDPerror,      frag=0, proto=17)
bind_layers( IP,            IP,            frag=0, proto=4)
bind_layers( IP,            ICMP,          frag=0, proto=1)
bind_layers( IP,            TCP,           frag=0, proto=6)
bind_layers( IP,            UDP,           frag=0, proto=17)
bind_layers( IP,            GRE,           frag=0, proto=47)

conf.l2types.register(101, IP)
conf.l2types.register_num2layer(12, IP)

conf.l3types.register(ETH_P_IP, IP)
conf.l3types.register_num2layer(ETH_P_ALL, IP)


def inet_register_l3(l2, l3):
    return getmacbyip(l3.dst)
conf.neighbor.register_l3(Ether, IP, inet_register_l3)
conf.neighbor.register_l3(Dot3, IP, inet_register_l3)


###################
## Fragmentation ##
###################

@conf.commands.register
def fragment(pkt, fragsize=1480):
    """Fragment a big IP datagram"""
    fragsize = (fragsize+7)/8*8
    lst = []
    for p in pkt:
        s = str(p[IP].payload)
        nb = (len(s)+fragsize-1)/fragsize
        for i in xrange(nb):            
            q = p.copy()
            del(q[IP].payload)
            del(q[IP].chksum)
            del(q[IP].len)
            if i != nb - 1:
                q[IP].flags |= 1
            q[IP].frag += i * fragsize / 8
            r = conf.raw_layer(load=s[i*fragsize:(i+1)*fragsize])
            r.overload_fields = p[IP].payload.overload_fields.copy()
            q.add_payload(r)
            lst.append(q)
    return lst

@conf.commands.register
def overlap_frag(p, overlap, fragsize=8, overlap_fragsize=None):
    """Build overlapping fragments to bypass NIPS

p:                the original packet
overlap:          the overlapping data
fragsize:         the fragment size of the packet
overlap_fragsize: the fragment size of the overlapping packet"""

    if overlap_fragsize is None:
        overlap_fragsize = fragsize
    q = p.copy()
    del(q[IP].payload)
    q[IP].add_payload(overlap)

    qfrag = fragment(q, overlap_fragsize)
    qfrag[-1][IP].flags |= 1
    return qfrag+fragment(p, fragsize)

@conf.commands.register
def defrag(plist):
    """defrag(plist) -> ([not fragmented], [defragmented],
                  [ [bad fragments], [bad fragments], ... ])"""
    frags = defaultdict(PacketList)
    nofrag = PacketList()
    for p in plist:
        ip = p[IP]
        if IP not in p:
            nofrag.append(p)
            continue
        if ip.frag == 0 and ip.flags & 1 == 0:
            nofrag.append(p)
            continue
        uniq = (ip.id,ip.src,ip.dst,ip.proto)
        frags[uniq].append(p)
    defrag = []
    missfrag = []
    for lst in frags.itervalues():
        lst.sort(key=lambda x: x.frag)
        p = lst[0]
        lastp = lst[-1]
        if p.frag > 0 or lastp.flags & 1 != 0: # first or last fragment missing
            missfrag.append(lst)
            continue
        p = p.copy()
        if conf.padding_layer in p:
            del(p[conf.padding_layer].underlayer.payload)
        ip = p[IP]
        if ip.len is None or ip.ihl is None:
            clen = len(ip.payload)
        else:
            clen = ip.len - (ip.ihl<<2)
        txt = conf.raw_layer()
        for q in lst[1:]:
            if clen != q.frag<<3: # Wrong fragmentation offset
                if clen > q.frag<<3:
                    warning("Fragment overlap (%i > %i) %r || %r ||  %r" % (clen, q.frag<<3, p,txt,q))
                missfrag.append(lst)
                break
            if q[IP].len is None or q[IP].ihl is None:
                clen += len(q[IP].payload)
            else:
                clen += q[IP].len - (q[IP].ihl<<2)
            if conf.padding_layer in q:
                del(q[conf.padding_layer].underlayer.payload)
            txt.add_payload(q[IP].payload.copy())
        else:
            ip.flags &= ~1 # !MF
            del(ip.chksum)
            del(ip.len)
            p = p/txt
            defrag.append(p)
    defrag2=PacketList()
    for p in defrag:
        defrag2.append(p.__class__(str(p)))
    return nofrag,defrag2,missfrag
            
@conf.commands.register
def defragment(plist):
    """defrag(plist) -> plist defragmented as much as possible """
    frags = defaultdict(lambda:[])
    final = []

    pos = 0
    for p in plist:
        p._defrag_pos = pos
        pos += 1
        if IP in p:
            ip = p[IP]
            if ip.frag != 0 or ip.flags & 1:
                ip = p[IP]
                uniq = (ip.id,ip.src,ip.dst,ip.proto)
                frags[uniq].append(p)
                continue
        final.append(p)

    defrag = []
    missfrag = []
    for lst in frags.itervalues():
        lst.sort(key=lambda x: x.frag)
        p = lst[0]
        lastp = lst[-1]
        if p.frag > 0 or lastp.flags & 1 != 0: # first or last fragment missing
            missfrag += lst
            continue
        p = p.copy()
        if conf.padding_layer in p:
            del(p[conf.padding_layer].underlayer.payload)
        ip = p[IP]
        if ip.len is None or ip.ihl is None:
            clen = len(ip.payload)
        else:
            clen = ip.len - (ip.ihl<<2)
        txt = conf.raw_layer()
        for q in lst[1:]:
            if clen != q.frag<<3: # Wrong fragmentation offset
                if clen > q.frag<<3:
                    warning("Fragment overlap (%i > %i) %r || %r ||  %r" % (clen, q.frag<<3, p,txt,q))
                missfrag += lst
                break
            if q[IP].len is None or q[IP].ihl is None:
                clen += len(q[IP].payload)
            else:
                clen += q[IP].len - (q[IP].ihl<<2)
            if conf.padding_layer in q:
                del(q[conf.padding_layer].underlayer.payload)
            txt.add_payload(q[IP].payload.copy())
        else:
            ip.flags &= ~1 # !MF
            del(ip.chksum)
            del(ip.len)
            p = p/txt
            p._defrag_pos = max(x._defrag_pos for x in lst)
            defrag.append(p)
    defrag2=[]
    for p in defrag:
        q = p.__class__(str(p))
        q._defrag_pos = p._defrag_pos
        defrag2.append(q)
    final += defrag2
    final += missfrag
    final.sort(key=lambda x: x._defrag_pos)
    for p in final:
        del(p._defrag_pos)

    if hasattr(plist, "listname"):
        name = "Defragmented %s" % plist.listname
    else:
        name = "Defragmented"
    
    return PacketList(final, name=name)
            
        

### Add timeskew_graph() method to PacketList
def _packetlist_timeskew_graph(self, ip, **kargs):
    """Tries to graph the timeskew between the timestamps and real time for a given ip"""

    # Filter TCP segments which source address is 'ip'
    res = map(lambda x: self._elt2pkt(x), self.res)
    b = filter(lambda x:x.haslayer(IP) and x.getlayer(IP).src == ip and x.haslayer(TCP), res)

    # Build a list of tuples (creation_time, replied_timestamp)
    c = []
    tsf = ICMPTimeStampField("", None)
    for p in b:
        opts = p.getlayer(TCP).options
        for o in opts:
            if o[0] == "Timestamp":
                c.append((p.time, tsf.any2i("", o[1][0])))

    # Stop if the list is empty
    if not c:
        warning("No timestamps found in packet list")
        return []

    # Prepare the data that will be plotted
    first_creation_time = c[0][0]
    first_replied_timestamp = c[0][1]

    def _wrap_data(ts_tuple, wrap_seconds=2000):
        """Wrap the list of tuples."""

        ct,rt = ts_tuple # (creation_time, replied_timestamp)
        X = ct % wrap_seconds
        Y = ((ct-first_creation_time) - ((rt-first_replied_timestamp)/1000.0))

        return X, Y

    data = map(_wrap_data, c)

    # Mimic the default gnuplot output
    if kargs == {}:
        kargs = MATPLOTLIB_DEFAULT_PLOT_KARGS
    lines = plt.plot(data, **kargs)

    # Call show() if matplotlib is not inlined
    if not MATPLOTLIB_INLINED:
        plt.show()

    return lines

PacketList.timeskew_graph = new.instancemethod(_packetlist_timeskew_graph, None, PacketList)


### Create a new packet list
class TracerouteResult(SndRcvList):
    __slots__ = ["graphdef", "graphpadding", "graphASres", "padding", "hloc",
                 "nloc"]
    def __init__(self, res=None, name="Traceroute", stats=None):
        PacketList.__init__(self, res, name, stats)
        self.graphdef = None
        self.graphASres = 0
        self.padding = 0
        self.hloc = None
        self.nloc = None

    def show(self):
        return self.make_table(lambda (s,r): (s.sprintf("%IP.dst%:{TCP:tcp%ir,TCP.dport%}{UDP:udp%ir,UDP.dport%}{ICMP:ICMP}"),
                                              s.ttl,
                                              r.sprintf("%-15s,IP.src% {TCP:%TCP.flags%}{ICMP:%ir,ICMP.type%}")))


    def get_trace(self):
        trace = {}
        for s,r in self.res:
            if IP not in s:
                continue
            d = s[IP].dst
            if d not in trace:
                trace[d] = {}
            trace[d][s[IP].ttl] = r[IP].src, ICMP not in r
        for k in trace.itervalues():
            try:
                m = min(x for x, y in k.itervalues() if y)
            except ValueError:
                continue
            for l in k.keys():  # use .keys(): k is modified in the loop
                if l > m:
                    del k[l]
        return trace

    def trace3D(self):
        """Give a 3D representation of the traceroute.
        right button: rotate the scene
        middle button: zoom
        left button: move the scene
        left button on a ball: toggle IP displaying
        ctrl-left button on a ball: scan ports 21,22,23,25,80 and 443 and display the result"""
        trace = self.get_trace()
        import visual

        class IPsphere(visual.sphere):
            def __init__(self, ip, **kargs):
                visual.sphere.__init__(self, **kargs)
                self.ip=ip
                self.label=None
                self.setlabel(self.ip)
            def setlabel(self, txt,visible=None):
                if self.label is not None:
                    if visible is None:
                        visible = self.label.visible
                    self.label.visible = 0
                elif visible is None:
                    visible=0
                self.label=visual.label(text=txt, pos=self.pos, space=self.radius, xoffset=10, yoffset=20, visible=visible)
            def action(self):
                self.label.visible ^= 1

        visual.scene = visual.display()
        visual.scene.exit = True
        start = visual.box()
        rings={}
        tr3d = {}
        for i in trace:
            tr = trace[i]
            tr3d[i] = []
            for t in xrange(1, max(tr) + 1):
                if t not in rings:
                    rings[t] = []
                if t in tr:
                    if tr[t] not in rings[t]:
                        rings[t].append(tr[t])
                    tr3d[i].append(rings[t].index(tr[t]))
                else:
                    rings[t].append(("unk",-1))
                    tr3d[i].append(len(rings[t])-1)
        for t in rings:
            r = rings[t]
            l = len(r)
            for i in xrange(l):
                if r[i][1] == -1:
                    col = (0.75,0.75,0.75)
                elif r[i][1]:
                    col = visual.color.green
                else:
                    col = visual.color.blue
                
                s = IPsphere(pos=((l-1)*visual.cos(2*i*visual.pi/l),(l-1)*visual.sin(2*i*visual.pi/l),2*t),
                             ip = r[i][0],
                             color = col)
                for trlst in tr3d.itervalues():
                    if t <= len(trlst):
                        if trlst[t-1] == i:
                            trlst[t-1] = s
        forecol = colgen(0.625, 0.4375, 0.25, 0.125)
        for trlst in tr3d.itervalues():
            col = forecol.next()
            start = (0,0,0)
            for ip in trlst:
                visual.cylinder(pos=start,axis=ip.pos-start,color=col,radius=0.2)
                start = ip.pos
        
        movcenter=None
        while 1:
            visual.rate(50)
            if visual.scene.kb.keys:
                k = visual.scene.kb.getkey()
                if k == "esc" or k == "q":
                    break
            if visual.scene.mouse.events:
                ev = visual.scene.mouse.getevent()
                if ev.press == "left":
                    o = ev.pick
                    if o:
                        if ev.ctrl:
                            if o.ip == "unk":
                                continue
                            savcolor = o.color
                            o.color = (1,0,0)
                            a,b=sr(IP(dst=o.ip)/TCP(dport=[21,22,23,25,80,443]),timeout=2)
                            o.color = savcolor
                            if len(a) == 0:
                                txt = "%s:\nno results" % o.ip
                            else:
                                txt = "%s:\n" % o.ip
                                for s,r in a:
                                    txt += r.sprintf("{TCP:%IP.src%:%TCP.sport% %TCP.flags%}{TCPerror:%IPerror.dst%:%TCPerror.dport% %IP.src% %ir,ICMP.type%}\n")
                            o.setlabel(txt, visible=1)
                        else:
                            if hasattr(o, "action"):
                                o.action()
                elif ev.drag == "left":
                    movcenter = ev.pos
                elif ev.drop == "left":
                    movcenter = None
            if movcenter:
                visual.scene.center -= visual.scene.mouse.pos-movcenter
                movcenter = visual.scene.mouse.pos
                
                
    def world_trace(self, **kargs):
        """Display traceroute results on a world map."""

        # Check that the GeoIP module can be imported
        try:
            import GeoIP
        except ImportError:
            message = "Can't import GeoIP. Won't be able to plot the world."
            scapy.utils.log_loading.info(message)
            return list()

        # Check if this is an IPv6 traceroute and load the correct file
        if isinstance(self, scapy.layers.inet6.TracerouteResult6):
            geoip_city_filename = conf.geoip_city_ipv6
        else:
            geoip_city_filename = conf.geoip_city

        # Check that the GeoIP database can be opened
        try:
            db = GeoIP.open(conf.geoip_city, 0)
        except:
            message = "Can't open GeoIP database at %s" % conf.geoip_city
            scapy.utils.log_loading.info(message)
            return list()

        # Regroup results per trace
        ips = {}
        rt = {}
        ports_done = {}
        for s,r in self.res:
            ips[r.src] = None
            if s.haslayer(TCP) or s.haslayer(UDP):
                trace_id = (s.src,s.dst,s.proto,s.dport)
            elif s.haslayer(ICMP):
                trace_id = (s.src,s.dst,s.proto,s.type)
            else:
                trace_id = (s.src,s.dst,s.proto,0)
            trace = rt.get(trace_id,{})
            if not r.haslayer(ICMP) or r.type != 11:
                if ports_done.has_key(trace_id):
                    continue
                ports_done[trace_id] = None
            trace[s.ttl] = r.src
            rt[trace_id] = trace

        # Get the addresses locations
        trt = {}
        for trace_id in rt:
            trace = rt[trace_id]
            loctrace = []
            for i in xrange(max(trace)):
                ip = trace.get(i,None)
                if ip is None:
                    continue
                loc = db.record_by_addr(ip)
                if loc is None:
                    continue
                loc = loc.get('longitude'), loc.get('latitude')
                if loc == (None, None):
                    continue
                loctrace.append(loc)
            if loctrace:
                trt[trace_id] = loctrace

        # Load the map renderer
        from mpl_toolkits.basemap import Basemap
        bmap = Basemap()

        # Split latitudes and longitudes per traceroute measurement
        locations = [zip(*tr) for tr in trt.itervalues()]

        # Plot the traceroute measurement as lines in the map
        lines = [bmap.plot(*bmap(lons, lats)) for lons, lats in locations]

        # Draw countries   
        bmap.drawcoastlines()

        # Call show() if matplotlib is not inlined
        if not MATPLOTLIB_INLINED:
            plt.show()

        # Return the drawn lines
        return lines

    def make_graph(self,ASres=None,padding=0):
        if ASres is None:
            ASres = conf.AS_resolver
        self.graphASres = ASres
        self.graphpadding = padding
        ips = {}
        rt = {}
        ports = {}
        ports_done = {}
        for s,r in self.res:
            r = r.getlayer(IP) or (conf.ipv6_enabled and r[scapy.layers.inet6.IPv6]) or r
            s = s.getlayer(IP) or (conf.ipv6_enabled and s[scapy.layers.inet6.IPv6]) or s
            ips[r.src] = None
            if TCP in s:
                trace_id = (s.src,s.dst,6,s.dport)
            elif UDP in s:
                trace_id = (s.src,s.dst,17,s.dport)
            elif ICMP in s:
                trace_id = (s.src,s.dst,1,s.type)
            else:
                trace_id = (s.src,s.dst,s.proto,0)
            trace = rt.get(trace_id,{})
            ttl = conf.ipv6_enabled and scapy.layers.inet6.IPv6 in s and s.hlim or s.ttl
            if not (ICMP in r and r[ICMP].type == 11) and not (conf.ipv6_enabled and scapy.layers.inet6.IPv6 in r and scapy.layers.inet6.ICMPv6TimeExceeded in r):
                if trace_id in ports_done:
                    continue
                ports_done[trace_id] = None
                p = ports.get(r.src,[])
                if TCP in r:
                    p.append(r.sprintf("<T%ir,TCP.sport%> %TCP.sport% %TCP.flags%"))
                    trace[ttl] = r.sprintf('"%r,src%":T%ir,TCP.sport%')
                elif UDP in r:
                    p.append(r.sprintf("<U%ir,UDP.sport%> %UDP.sport%"))
                    trace[ttl] = r.sprintf('"%r,src%":U%ir,UDP.sport%')
                elif ICMP in r:
                    p.append(r.sprintf("<I%ir,ICMP.type%> ICMP %ICMP.type%"))
                    trace[ttl] = r.sprintf('"%r,src%":I%ir,ICMP.type%')
                else:
                    p.append(r.sprintf("{IP:<P%ir,proto%> IP %proto%}{IPv6:<P%ir,nh%> IPv6 %nh%}"))
                    trace[ttl] = r.sprintf('"%r,src%":{IP:P%ir,proto%}{IPv6:P%ir,nh%}')
                ports[r.src] = p
            else:
                trace[ttl] = r.sprintf('"%r,src%"')
            rt[trace_id] = trace
    
        # Fill holes with unk%i nodes
        unknown_label = incremental_label("unk%i")
        blackholes = []
        bhip = {}
        for rtk in rt:
            trace = rt[rtk]
            max_trace = max(trace)
            for n in xrange(min(trace), max_trace):
                if not trace.has_key(n):
                    trace[n] = unknown_label.next()
            if not ports_done.has_key(rtk):
                if rtk[2] == 1: #ICMP
                    bh = "%s %i/icmp" % (rtk[1],rtk[3])
                elif rtk[2] == 6: #TCP
                    bh = "%s %i/tcp" % (rtk[1],rtk[3])
                elif rtk[2] == 17: #UDP                    
                    bh = '%s %i/udp' % (rtk[1],rtk[3])
                else:
                    bh = '%s %i/proto' % (rtk[1],rtk[2]) 
                ips[bh] = None
                bhip[rtk[1]] = bh
                bh = '"%s"' % bh
                trace[max_trace + 1] = bh
                blackholes.append(bh)
    
        # Find AS numbers
        ASN_query_list = set(x.rsplit(" ",1)[0] for x in ips)
        if ASres is None:            
            ASNlist = []
        else:
            ASNlist = ASres.resolve(*ASN_query_list)            
    
        ASNs = {}
        ASDs = {}
        for ip,asn,desc, in ASNlist:
            if asn is None:
                continue
            iplist = ASNs.get(asn,[])
            if ip in bhip:
                if ip in ports:
                    iplist.append(ip)
                iplist.append(bhip[ip])
            else:
                iplist.append(ip)
            ASNs[asn] = iplist
            ASDs[asn] = desc
    
    
        backcolorlist=colgen("60","86","ba","ff")
        forecolorlist=colgen("a0","70","40","20")
    
        s = "digraph trace {\n"
    
        s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"
    
        s += "\n#ASN clustering\n"
        for asn in ASNs:
            s += '\tsubgraph cluster_%s {\n' % asn
            col = backcolorlist.next()
            s += '\t\tcolor="#%s%s%s";' % col
            s += '\t\tnode [fillcolor="#%s%s%s",style=filled];' % col
            s += '\t\tfontsize = 10;'
            s += '\t\tlabel = "%s\\n[%s]"\n' % (asn,ASDs[asn])
            for ip in ASNs[asn]:
    
                s += '\t\t"%s";\n'%ip
            s += "\t}\n"
    
    
    
    
        s += "#endpoints\n"
        for p in ports:
            s += '\t"%s" [shape=record,color=black,fillcolor=green,style=filled,label="%s|%s"];\n' % (p,p,"|".join(ports[p]))
    
        s += "\n#Blackholes\n"
        for bh in blackholes:
            s += '\t%s [shape=octagon,color=black,fillcolor=red,style=filled];\n' % bh

        if padding:
            s += "\n#Padding\n"
            pad={}
            for snd,rcv in self.res:
                if rcv.src not in ports and rcv.haslayer(conf.padding_layer):
                    p = rcv.getlayer(conf.padding_layer).load
                    if p != "\x00"*len(p):
                        pad[rcv.src]=None
            for rcv in pad:
                s += '\t"%s" [shape=triangle,color=black,fillcolor=red,style=filled];\n' % rcv
    
    
            
        s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"
    
    
        for rtk in rt:
            s += "#---[%s\n" % `rtk`
            s += '\t\tedge [color="#%s%s%s"];\n' % forecolorlist.next()
            trace = rt[rtk]
            maxtrace = max(trace)
            for n in xrange(min(trace), maxtrace):
                s += '\t%s ->\n' % trace[n]
            s += '\t%s;\n' % trace[maxtrace]
    
        s += "}\n";
        self.graphdef = s
    
    def graph(self, ASres=None, padding=0, **kargs):
        """x.graph(ASres=conf.AS_resolver, other args):
        ASres=None          : no AS resolver => no clustering
        ASres=AS_resolver() : default whois AS resolver (riswhois.ripe.net)
        ASres=AS_resolver_cymru(): use whois.cymru.com whois database
        ASres=AS_resolver(server="whois.ra.net")
        type: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option
        target: filename or redirect. Defaults pipe to Imagemagick's display program
        prog: which graphviz program to use"""
        if ASres is None:
            ASres = conf.AS_resolver
        if (self.graphdef is None or
            self.graphASres != ASres or
            self.graphpadding != padding):
            self.make_graph(ASres,padding)

        return do_graph(self.graphdef, **kargs)



@conf.commands.register
def traceroute(target, dport=80, minttl=1, maxttl=30, sport=RandShort(), l4 = None, filter=None, timeout=2, verbose=None, **kargs):
    """Instant TCP traceroute
traceroute(target, [maxttl=30,] [dport=80,] [sport=80,] [verbose=conf.verb]) -> None
"""
    if verbose is None:
        verbose = conf.verb
    if filter is None:
        # we only consider ICMP error packets and TCP packets with at
        # least the ACK flag set *and* either the SYN or the RST flag
        # set
        filter="(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))"
    if l4 is None:
        a,b = sr(IP(dst=target, id=RandShort(), ttl=(minttl,maxttl))/TCP(seq=RandInt(),sport=sport, dport=dport),
                 timeout=timeout, filter=filter, verbose=verbose, **kargs)
    else:
        # this should always work
        filter="ip"
        a,b = sr(IP(dst=target, id=RandShort(), ttl=(minttl,maxttl))/l4,
                 timeout=timeout, filter=filter, verbose=verbose, **kargs)

    a = TracerouteResult(a.res)
    if verbose:
        a.show()
    return a,b



#############################
## Simple TCP client stack ##
#############################

class TCP_client(Automaton):
    
    def parse_args(self, ip, port, *args, **kargs):
        self.dst = iter(Net(ip)).next()
        self.dport = port
        self.sport = random.randrange(0,2**16)
        self.l4 = IP(dst=ip)/TCP(sport=self.sport, dport=self.dport, flags=0,
                                 seq=random.randrange(0,2**32))
        self.src = self.l4.src
        self.swin=self.l4[TCP].window
        self.dwin=1
        self.rcvbuf=""
        bpf = "host %s  and host %s and port %i and port %i" % (self.src,
                                                                self.dst,
                                                                self.sport,
                                                                self.dport)

#        bpf=None
        Automaton.parse_args(self, filter=bpf, **kargs)

    
    def master_filter(self, pkt):
        return (IP in pkt and
                pkt[IP].src == self.dst and
                pkt[IP].dst == self.src and
                TCP in pkt and
                pkt[TCP].sport == self.dport and
                pkt[TCP].dport == self.sport and
                self.l4[TCP].seq >= pkt[TCP].ack and # XXX: seq/ack 2^32 wrap up
                ((self.l4[TCP].ack == 0) or (self.l4[TCP].ack <= pkt[TCP].seq <= self.l4[TCP].ack+self.swin)) )


    @ATMT.state(initial=1)
    def START(self):
        pass

    @ATMT.state()
    def SYN_SENT(self):
        pass
    
    @ATMT.state()
    def ESTABLISHED(self):
        pass

    @ATMT.state()
    def LAST_ACK(self):
        pass

    @ATMT.state(final=1)
    def CLOSED(self):
        pass

    
    @ATMT.condition(START)
    def connect(self):
        raise self.SYN_SENT()
    @ATMT.action(connect)
    def send_syn(self):
        self.l4[TCP].flags = "S"
        self.send(self.l4)
        self.l4[TCP].seq += 1


    @ATMT.receive_condition(SYN_SENT)
    def synack_received(self, pkt):
        if pkt[TCP].flags & 0x3f == 0x12:
            raise self.ESTABLISHED().action_parameters(pkt)
    @ATMT.action(synack_received)
    def send_ack_of_synack(self, pkt):
        self.l4[TCP].ack = pkt[TCP].seq+1
        self.l4[TCP].flags = "A"
        self.send(self.l4)

    @ATMT.receive_condition(ESTABLISHED)
    def incoming_data_received(self, pkt):
        if not isinstance(pkt[TCP].payload, NoPayload) and not isinstance(pkt[TCP].payload, conf.padding_layer):
            raise self.ESTABLISHED().action_parameters(pkt)
    @ATMT.action(incoming_data_received)
    def receive_data(self,pkt):
        data = str(pkt[TCP].payload)
        if data and self.l4[TCP].ack == pkt[TCP].seq:
            self.l4[TCP].ack += len(data)
            self.l4[TCP].flags = "A"
            self.send(self.l4)
            self.rcvbuf += data
            if pkt[TCP].flags & 8 != 0: #PUSH
                self.oi.tcp.send(self.rcvbuf)
                self.rcvbuf = ""
    
    @ATMT.ioevent(ESTABLISHED,name="tcp", as_supersocket="tcplink")
    def outgoing_data_received(self, fd):
        raise self.ESTABLISHED().action_parameters(fd.recv())
    @ATMT.action(outgoing_data_received)
    def send_data(self, d):
        self.l4[TCP].flags = "PA"
        self.send(self.l4/d)
        self.l4[TCP].seq += len(d)
        
    
    @ATMT.receive_condition(ESTABLISHED)
    def reset_received(self, pkt):
        if pkt[TCP].flags & 4 != 0:
            raise self.CLOSED()

    @ATMT.receive_condition(ESTABLISHED)
    def fin_received(self, pkt):
        if pkt[TCP].flags & 0x1 == 1:
            raise self.LAST_ACK().action_parameters(pkt)
    @ATMT.action(fin_received)
    def send_finack(self, pkt):
        self.l4[TCP].flags = "FA"
        self.l4[TCP].ack = pkt[TCP].seq+1
        self.send(self.l4)
        self.l4[TCP].seq += 1

    @ATMT.receive_condition(LAST_ACK)
    def ack_of_fin_received(self, pkt):
        if pkt[TCP].flags & 0x3f == 0x10:
            raise self.CLOSED()




#####################
## Reporting stuff ##
#####################


@conf.commands.register
def report_ports(target, ports):
    """portscan a target and output a LaTeX table
report_ports(target, ports) -> string"""
    ans,unans = sr(IP(dst=target)/TCP(dport=ports),timeout=5)
    rep = "\\begin{tabular}{|r|l|l|}\n\\hline\n"
    for s,r in ans:
        if not r.haslayer(ICMP):
            if r.payload.flags == 0x12:
                rep += r.sprintf("%TCP.sport% & open & SA \\\\\n")
    rep += "\\hline\n"
    for s,r in ans:
        if r.haslayer(ICMP):
            rep += r.sprintf("%TCPerror.dport% & closed & ICMP type %ICMP.type%/%ICMP.code% from %IP.src% \\\\\n")
        elif r.payload.flags != 0x12:
            rep += r.sprintf("%TCP.sport% & closed & TCP %TCP.flags% \\\\\n")
    rep += "\\hline\n"
    for i in unans:
        rep += i.sprintf("%TCP.dport% & ? & unanswered \\\\\n")
    rep += "\\hline\n\\end{tabular}\n"
    return rep


@conf.commands.register
def IPID_count(lst, funcID=lambda x:x[1].id, funcpres=lambda x:x[1].summary()):
    """Identify IP id values classes in a list of packets

lst:      a list of packets
funcID:   a function that returns IP id values
funcpres: a function used to summarize packets"""
    idlst = map(funcID, lst)
    idlst.sort()
    classes = [idlst[0]]+map(lambda x:x[1],filter(lambda (x,y): abs(x-y)>50, map(lambda x,y: (x,y),idlst[:-1], idlst[1:])))
    lst = map(lambda x:(funcID(x), funcpres(x)), lst)
    lst.sort()
    print "Probably %i classes:" % len(classes), classes
    for id,pr in lst:
        print "%5i" % id, pr
    
    
@conf.commands.register
def fragleak(target,sport=123, dport=123, timeout=0.2, onlyasc=0):
    load = "XXXXYYYYYYYYYY"
#    getmacbyip(target)
#    pkt = IP(dst=target, id=RandShort(), options="\x22"*40)/UDP()/load
    pkt = IP(dst=target, id=RandShort(), options="\x00"*40, flags=1)/UDP(sport=sport, dport=sport)/load
    s=conf.L3socket()
    intr=0
    found={}
    try:
        while 1:
            try:
                if not intr:
                    s.send(pkt)
                sin,sout,serr = select([s],[],[],timeout)
                if not sin:
                    continue
                ans=s.recv(1600)
                if not isinstance(ans, IP): #TODO: IPv6
                    continue
                if not isinstance(ans.payload, ICMP):
                    continue
                if not isinstance(ans.payload.payload, IPerror):
                    continue
                if ans.payload.payload.dst != target:
                    continue
                if ans.src  != target:
                    print "leak from", ans.src,


#                print repr(ans)
                if not ans.haslayer(conf.padding_layer):
                    continue

                
#                print repr(ans.payload.payload.payload.payload)
                
#                if not isinstance(ans.payload.payload.payload.payload, conf.raw_layer):
#                    continue
#                leak = ans.payload.payload.payload.payload.load[len(load):]
                leak = ans.getlayer(conf.padding_layer).load
                if leak not in found:
                    found[leak]=None
                    linehexdump(leak, onlyasc=onlyasc)
            except KeyboardInterrupt:
                if intr:
                    raise
                intr=1
    except KeyboardInterrupt:
        pass


@conf.commands.register
def fragleak2(target, timeout=0.4, onlyasc=0):
    found={}
    try:
        while 1:
            p = sr1(IP(dst=target, options="\x00"*40, proto=200)/"XXXXYYYYYYYYYYYY",timeout=timeout,verbose=0)
            if not p:
                continue
            if conf.padding_layer in p:
                leak  = p[conf.padding_layer].load
                if leak not in found:
                    found[leak]=None
                    linehexdump(leak,onlyasc=onlyasc)
    except:
        pass
    

conf.stats_classic_protocols += [TCP,UDP,ICMP]
conf.stats_dot11_protocols += [TCP,UDP,ICMP]

if conf.ipv6_enabled:
    import scapy.layers.inet6
