## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
DHCP (Dynamic Host Configuration Protocol) d BOOTP
"""

import struct

from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import UDP,IP
from scapy.layers.l2 import Ether
from scapy.base_classes import Net
from scapy.volatile import RandField

from scapy.arch import get_if_raw_hwaddr
from scapy.sendrecv import srp1

dhcpmagic="c\x82Sc"


class BOOTP(Packet):
    name = "BOOTP"
    fields_desc = [ ByteEnumField("op",1, {1:"BOOTREQUEST", 2:"BOOTREPLY"}),
                    ByteField("htype",1),
                    ByteField("hlen",6),
                    ByteField("hops",0),
                    IntField("xid",0),
                    ShortField("secs",0),
                    FlagsField("flags", 0, 16, "???????????????B"),
                    IPField("ciaddr","0.0.0.0"),
                    IPField("yiaddr","0.0.0.0"),
                    IPField("siaddr","0.0.0.0"),
                    IPField("giaddr","0.0.0.0"),
                    Field("chaddr","", "16s"),
                    Field("sname","","64s"),
                    Field("file","","128s"),
                    StrField("options","") ]
    def guess_payload_class(self, payload):
        if self.options[:len(dhcpmagic)] == dhcpmagic:
            return DHCP
        else:
            return Packet.guess_payload_class(self, payload)
    def extract_padding(self,s):
        if self.options[:len(dhcpmagic)] == dhcpmagic:
            # set BOOTP options to DHCP magic cookie and make rest a payload of DHCP options
            payload = self.options[len(dhcpmagic):]
            self.options = self.options[:len(dhcpmagic)]
            return payload, None
        else:
            return "", None
    def hashret(self):
        return struct.pack("L", self.xid)
    def answers(self, other):
        if not isinstance(other, BOOTP):
            return 0
        return self.xid == other.xid



#DHCP_UNKNOWN, DHCP_IP, DHCP_IPLIST, DHCP_TYPE \
#= range(4)
#

DHCPTypes = {
                1: "discover",
                2: "offer",
                3: "request",
                4: "decline",
                5: "ack",
                6: "nak",
                7: "release",
                8: "inform",
                9: "force_renew",
                10:"lease_query",
                11:"lease_unassigned",
                12:"lease_unknown",
                13:"lease_active",
                }

DHCPOptions = {
    0: "pad",
    1: IPField("subnet_mask", "0.0.0.0"),
    2: "time_zone",
    3: IPField("router","0.0.0.0"),
    4: IPField("time_server","0.0.0.0"),
    5: IPField("IEN_name_server","0.0.0.0"),
    6: IPField("name_server","0.0.0.0"),
    7: IPField("log_server","0.0.0.0"),
    8: IPField("cookie_server","0.0.0.0"),
    9: IPField("lpr_server","0.0.0.0"),
    12: "hostname",
    14: "dump_path",
    15: "domain",
    17: "root_disk_path",
    22: "max_dgram_reass_size",
    23: "default_ttl",
    24: "pmtu_timeout",
    28: IPField("broadcast_address","0.0.0.0"),
    35: "arp_cache_timeout",
    36: "ether_or_dot3",
    37: "tcp_ttl",
    38: "tcp_keepalive_interval",
    39: "tcp_keepalive_garbage",
    40: "NIS_domain",
    41: IPField("NIS_server","0.0.0.0"),
    42: IPField("NTP_server","0.0.0.0"),
    43: "vendor_specific",
    44: IPField("NetBIOS_server","0.0.0.0"),
    45: IPField("NetBIOS_dist_server","0.0.0.0"),
    50: IPField("requested_addr","0.0.0.0"),
    51: IntField("lease_time", 43200),
    54: IPField("server_id","0.0.0.0"),
    55: "param_req_list",
    57: ShortField("max_dhcp_size", 1500),
    58: IntField("renewal_time", 21600),
    59: IntField("rebinding_time", 37800),
    60: "vendor_class_id",
    61: "client_id",
    
    64: "NISplus_domain",
    65: IPField("NISplus_server","0.0.0.0"),
    69: IPField("SMTP_server","0.0.0.0"),
    70: IPField("POP3_server","0.0.0.0"),
    71: IPField("NNTP_server","0.0.0.0"),
    72: IPField("WWW_server","0.0.0.0"),
    73: IPField("Finger_server","0.0.0.0"),
    74: IPField("IRC_server","0.0.0.0"),
    75: IPField("StreetTalk_server","0.0.0.0"),
    76: "StreetTalk_Dir_Assistance",
    82: "relay_agent_Information",
    53: ByteEnumField("message-type", 1, DHCPTypes),
    #             55: DHCPRequestListField("request-list"),
    255: "end"
    }

DHCPRevOptions = {}

for k,v in DHCPOptions.iteritems():
    if type(v) is str:
        n = v
        v = None
    else:
        n = v.name
    DHCPRevOptions[n] = (k,v)
del(n)
del(v)
del(k)
    
    


class RandDHCPOptions(RandField):
    def __init__(self, size=None, rndstr=None):
        if size is None:
            size = RandNumExpo(0.05)
        self.size = size
        if rndstr is None:
            rndstr = RandBin(RandNum(0,255))
        self.rndstr=rndstr
        self._opts = DHCPOptions.values()
        self._opts.remove("pad")
        self._opts.remove("end")
    def _fix(self):
        op = []
        for k in range(self.size):
            o = random.choice(self._opts)
            if type(o) is str:
                op.append((o,self.rndstr*1))
            else:
                op.append((o.name, o.randval()._fix()))
        return op


class DHCPOptionsField(StrField):
    islist=1
    def i2repr(self,pkt,x):
        s = []
        for v in x:
            if type(v) is tuple and len(v) >= 2:
                if  DHCPRevOptions.has_key(v[0]) and isinstance(DHCPRevOptions[v[0]][1],Field):
                    f = DHCPRevOptions[v[0]][1]
                    vv = ",".join(f.i2repr(pkt,val) for val in v[1:])
                else:
                    vv = ",".join(repr(val) for val in v[1:])
                r = "%s=%s" % (v[0],vv)
                s.append(r)
            else:
                s.append(sane(v))
        return "[%s]" % (" ".join(s))
        
    def getfield(self, pkt, s):
        return "", self.m2i(pkt, s)
    def m2i(self, pkt, x):
        opt = []
        while x:
            o = ord(x[0])
            if o == 255:
                opt.append("end")
                x = x[1:]
                continue
            if o == 0:
                opt.append("pad")
                x = x[1:]
                continue
            if len(x) < 2 or len(x) < ord(x[1])+2:
                opt.append(x)
                break
            elif DHCPOptions.has_key(o):
                f = DHCPOptions[o]

                if isinstance(f, str):
                    olen = ord(x[1])
                    opt.append( (f,x[2:olen+2]) )
                    x = x[olen+2:]
                else:
                    olen = ord(x[1])
                    lval = [f.name]
                    try:
                        left = x[2:olen+2]
                        while left:
                            left, val = f.getfield(pkt,left)
                            lval.append(val)
                    except:
                        opt.append(x)
                        break
                    else:
                        otuple = tuple(lval)
                    opt.append(otuple)
                    x = x[olen+2:]
            else:
                olen = ord(x[1])
                opt.append((o, x[2:olen+2]))
                x = x[olen+2:]
        return opt
    def i2m(self, pkt, x):
        if type(x) is str:
            return x
        s = ""
        for o in x:
            if type(o) is tuple and len(o) >= 2:
                name = o[0]
                lval = o[1:]

                if isinstance(name, int):
                    onum, oval = name, "".join(lval)
                elif DHCPRevOptions.has_key(name):
                    onum, f = DHCPRevOptions[name]
                    if  f is not None:
                        lval = [f.addfield(pkt,"",f.any2i(pkt,val)) for val in lval]
                    oval = "".join(lval)
                else:
                    warning("Unknown field option %s" % name)
                    continue

                s += chr(onum)
                s += chr(len(oval))
                s += oval

            elif (type(o) is str and DHCPRevOptions.has_key(o) and 
                  DHCPRevOptions[o][1] == None):
                s += chr(DHCPRevOptions[o][0])
            elif type(o) is int:
                s += chr(o)+"\0"
            elif type(o) is str:
                s += o
            else:
                warning("Malformed option %s" % o)
        return s


class DHCP(Packet):
    name = "DHCP options"
    fields_desc = [ DHCPOptionsField("options","") ]


bind_layers( UDP,           BOOTP,         dport=67, sport=68)
bind_layers( UDP,           BOOTP,         dport=68, sport=67)
bind_bottom_up( UDP, BOOTP, dport=67, sport=67)
bind_layers( BOOTP,         DHCP,          options='c\x82Sc')

def dhcp_request(iface=None,**kargs):
    if conf.checkIPaddr != 0:
        warning("conf.checkIPaddr is not 0, I may not be able to match the answer")
    if iface is None:
        iface = conf.iface
    fam,hw = get_if_raw_hwaddr(iface)
    return srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)
                 /BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"]),iface=iface,**kargs)


class BOOTP_am(AnsweringMachine):
    function_name = "bootpd"
    filter = "udp and port 68 and port 67"
    send_function = staticmethod(sendp)
    def parse_options(self, pool=Net("192.168.1.128/25"), network="192.168.1.0/24",gw="192.168.1.1",
                      domain="localnet", renewal_time=60, lease_time=1800):
        if type(pool) is str:
            poom = Net(pool)
        self.domain = domain
        netw,msk = (network.split("/")+["32"])[:2]
        msk = itom(int(msk))
        self.netmask = ltoa(msk)
        self.network = ltoa(atol(netw)&msk)
        self.broadcast = ltoa( atol(self.network) | (0xffffffff&~msk) )
        self.gw = gw
        if isinstance(pool,Gen):
            pool = [k for k in pool if k not in [gw, self.network, self.broadcast]]
            pool.reverse()
        if len(pool) == 1:
            pool, = pool
        self.pool = pool
        self.lease_time = lease_time
        self.renewal_time = renewal_time
        self.leases = {}

    def is_request(self, req):
        if not req.haslayer(BOOTP):
            return 0
        reqb = req.getlayer(BOOTP)
        if reqb.op != 1:
            return 0
        return 1

    def print_reply(self, req, reply):
        print "Reply %s to %s" % (reply.getlayer(IP).dst,reply.dst)

    def make_reply(self, req):        
        mac = req.src
        if type(self.pool) is list:
            if not self.leases.has_key(mac):
                self.leases[mac] = self.pool.pop()
            ip = self.leases[mac]
        else:
            ip = self.pool
            
        repb = req.getlayer(BOOTP).copy()
        repb.op="BOOTREPLY"
        repb.yiaddr = ip
        repb.siaddr = self.gw
        repb.ciaddr = self.gw
        repb.giaddr = self.gw
        del(repb.payload)
        rep=Ether(dst=mac)/IP(dst=ip)/UDP(sport=req.dport,dport=req.sport)/repb
        return rep


class DHCP_am(BOOTP_am):
    function_name="dhcpd"
    def make_reply(self, req):
        resp = BOOTP_am.make_reply(self, req)
        if DHCP in req:
            dhcp_options = [(op[0],{1:2,3:5}.get(op[1],op[1]))
                            for op in req[DHCP].options
                            if type(op) is tuple  and op[0] == "message-type"]
            dhcp_options += [("server_id",self.gw),
                             ("domain", self.domain),
                             ("router", self.gw),
                             ("name_server", self.gw),
                             ("broadcast_address", self.broadcast),
                             ("subnet_mask", self.netmask),
                             ("renewal_time", self.renewal_time),
                             ("lease_time", self.lease_time), 
                             "end"
                             ]
            resp /= DHCP(options=dhcp_options)
        return resp
    

