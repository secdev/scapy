## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import socket,struct

from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import UDP

class DNSStrField(StrField):
    def i2m(self, pkt, x):
        x = [k[:63] for k in x.split(".")] # Truncate chunks that cannont be encoded (more than 63 bytes..)
        x = map(lambda y: chr(len(y))+y, x)
        x = "".join(x)
        if x[-1] != "\x00":
            x += "\x00"
        return x
    def getfield(self, pkt, s):
        n = ""
        while 1:
            l = ord(s[0])
            s = s[1:]
            if not l:
                break
            if l & 0xc0:
                raise Scapy_Exception("DNS message can't be compressed at this point!")
            else:
                n += s[:l]+"."
                s = s[l:]
        return s, n


class DNSRRCountField(ShortField):
    holds_packets=1
    def __init__(self, name, default, rr):
        ShortField.__init__(self, name, default)
        self.rr = rr
    def _countRR(self, pkt):
        x = getattr(pkt,self.rr)
        i = 0
        while isinstance(x, DNSRR) or isinstance(x, DNSQR):
            x = x.payload
            i += 1
        return i
        
    def i2m(self, pkt, x):
        if x is None:
            x = self._countRR(pkt)
        return x
    def i2h(self, pkt, x):
        if x is None:
            x = self._countRR(pkt)
        return x
    

def DNSgetstr(s,p):
    name = ""
    q = 0
    jpath = [p]
    while 1:
        if p >= len(s):
            warning("DNS RR prematured end (ofs=%i, len=%i)"%(p,len(s)))
            break
        l = ord(s[p])
        p += 1
        if l & 0xc0:
            if not q:
                q = p+1
            if p >= len(s):
                warning("DNS incomplete jump token at (ofs=%i)" % p)
                break
            p = ((l & 0x3f) << 8) + ord(s[p]) - 12
            if p in jpath:
                warning("DNS decompression loop detected")
                break
            jpath.append(p)
            continue
        elif l > 0:
            name += s[p:p+l]+"."
            p += l
            continue
        break
    if q:
        p = q
    return name,p
        

class DNSRRField(StrField):
    holds_packets=1
    def __init__(self, name, countfld, passon=1):
        StrField.__init__(self, name, None)
        self.countfld = countfld
        self.passon = passon
    def i2m(self, pkt, x):
        if x is None:
            return ""
        return str(x)
    def decodeRR(self, name, s, p):
        ret = s[p:p+10]
        type,cls,ttl,rdlen = struct.unpack("!HHIH", ret)
        p += 10
        rr = DNSRR("\x00"+ret+s[p:p+rdlen])
        if rr.type in [2, 3, 4, 5]:
            rr.rdata = DNSgetstr(s,p)[0]
        del(rr.rdlen)
        
        p += rdlen
        
        rr.rrname = name
        return rr,p
    def getfield(self, pkt, s):
        if type(s) is tuple :
            s,p = s
        else:
            p = 0
        ret = None
        c = getattr(pkt, self.countfld)
        if c > len(s):
            warning("wrong value: DNS.%s=%i" % (self.countfld,c))
            return s,""
        while c:
            c -= 1
            name,p = DNSgetstr(s,p)
            rr,p = self.decodeRR(name, s, p)
            if ret is None:
                ret = rr
            else:
                ret.add_payload(rr)
        if self.passon:
            return (s,p),ret
        else:
            return s[p:],ret
            
            
class DNSQRField(DNSRRField):
    holds_packets=1
    def decodeRR(self, name, s, p):
        ret = s[p:p+4]
        p += 4
        rr = DNSQR("\x00"+ret)
        rr.qname = name
        return rr,p
        
        

class RDataField(StrLenField):
    def m2i(self, pkt, s):
        family = None
        if pkt.type == 1:
            family = socket.AF_INET
        elif pkt.type == 28:
            family = socket.AF_INET6
        elif pkt.type == 12:
            s = DNSgetstr(s, 0)[0]
        if family is not None:    
            s = inet_ntop(family, s)
        return s
    def i2m(self, pkt, s):
        if pkt.type == 1:
            if s:
                s = inet_aton(s)
        elif pkt.type == 28:
            if s:
                s = inet_pton(socket.AF_INET6, s)
        elif pkt.type in [2,3,4,5]:
            s = "".join(map(lambda x: chr(len(x))+x, s.split(".")))
            if ord(s[-1]):
                s += "\x00"
        return s

class RDLenField(Field):
    def __init__(self, name):
        Field.__init__(self, name, None, "H")
    def i2m(self, pkt, x):
        if x is None:
            rdataf = pkt.get_field("rdata")
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x
    def i2h(self, pkt, x):
        if x is None:
            rdataf = pkt.get_field("rdata")
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x
    

class DNS(Packet):
    name = "DNS"
    fields_desc = [ ShortField("id",0),
                    BitField("qr",0, 1),
                    BitEnumField("opcode", 0, 4, {0:"QUERY",1:"IQUERY",2:"STATUS"}),
                    BitField("aa", 0, 1),
                    BitField("tc", 0, 1),
                    BitField("rd", 0, 1),
                    BitField("ra", 0 ,1),
                    BitField("z", 0, 3),
                    BitEnumField("rcode", 0, 4, {0:"ok", 1:"format-error", 2:"server-failure", 3:"name-error", 4:"not-implemented", 5:"refused"}),
                    DNSRRCountField("qdcount", None, "qd"),
                    DNSRRCountField("ancount", None, "an"),
                    DNSRRCountField("nscount", None, "ns"),
                    DNSRRCountField("arcount", None, "ar"),
                    DNSQRField("qd", "qdcount"),
                    DNSRRField("an", "ancount"),
                    DNSRRField("ns", "nscount"),
                    DNSRRField("ar", "arcount",0) ]
    def answers(self, other):
        return (isinstance(other, DNS)
                and self.id == other.id
                and self.qr == 1
                and other.qr == 0)
        
    def mysummary(self):
        type = ["Qry","Ans"][self.qr]
        name = ""
        if self.qr:
            type = "Ans"
            if self.ancount > 0 and isinstance(self.an, DNSRR):
                name = ' "%s"' % self.an.rdata
        else:
            type = "Qry"
            if self.qdcount > 0 and isinstance(self.qd, DNSQR):
                name = ' "%s"' % self.qd.qname
        return 'DNS %s%s ' % (type, name)

dnstypes = { 0:"ANY", 255:"ALL",
             1:"A", 2:"NS", 3:"MD", 4:"MD", 5:"CNAME", 6:"SOA", 7: "MB", 8:"MG",
             9:"MR",10:"NULL",11:"WKS",12:"PTR",13:"HINFO",14:"MINFO",15:"MX",16:"TXT",
             17:"RP",18:"AFSDB",28:"AAAA", 33:"SRV",38:"A6",39:"DNAME"}

dnsqtypes = {251:"IXFR",252:"AXFR",253:"MAILB",254:"MAILA",255:"ALL"}
dnsqtypes.update(dnstypes)
dnsclasses =  {1: 'IN',  2: 'CS',  3: 'CH',  4: 'HS',  255: 'ANY'}


class DNSQR(Packet):
    name = "DNS Question Record"
    show_indent=0
    fields_desc = [ DNSStrField("qname",""),
                    ShortEnumField("qtype", 1, dnsqtypes),
                    ShortEnumField("qclass", 1, dnsclasses) ]
                    
                    

class DNSRR(Packet):
    name = "DNS Resource Record"
    show_indent=0
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 1, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    RDLenField("rdlen"),
                    RDataField("rdata", "", length_from=lambda pkt:pkt.rdlen) ]

bind_layers( UDP,           DNS,           dport=53)
bind_layers( UDP,           DNS,           sport=53)


@conf.commands.register
def dyndns_add(nameserver, name, rdata, type="A", ttl=10):
    """Send a DNS add message to a nameserver for "name" to have a new "rdata"
dyndns_add(nameserver, name, rdata, type="A", ttl=10) -> result code (0=ok)

example: dyndns_add("ns1.toto.com", "dyn.toto.com", "127.0.0.1")
RFC2136
"""
    zone = name[name.find(".")+1:]
    r=sr1(IP(dst=nameserver)/UDP()/DNS(opcode=5,
                                       qd=[DNSQR(qname=zone, qtype="SOA")],
                                       ns=[DNSRR(rrname=name, type="A",
                                                 ttl=ttl, rdata=rdata)]),
          verbose=0, timeout=5)
    if r and r.haslayer(DNS):
        return r.getlayer(DNS).rcode
    else:
        return -1
    
    
    

@conf.commands.register
def dyndns_del(nameserver, name, type="ALL", ttl=10):
    """Send a DNS delete message to a nameserver for "name"
dyndns_del(nameserver, name, type="ANY", ttl=10) -> result code (0=ok)

example: dyndns_del("ns1.toto.com", "dyn.toto.com")
RFC2136
"""
    zone = name[name.find(".")+1:]
    r=sr1(IP(dst=nameserver)/UDP()/DNS(opcode=5,
                                       qd=[DNSQR(qname=zone, qtype="SOA")],
                                       ns=[DNSRR(rrname=name, type=type,
                                                 rclass="ANY", ttl=0, rdata="")]),
          verbose=0, timeout=5)
    if r and r.haslayer(DNS):
        return r.getlayer(DNS).rcode
    else:
        return -1
    

class DNS_am(AnsweringMachine):
    function_name="dns_spoof"
    filter = "udp port 53"

    def parse_options(self, joker="192.168.1.1", match=None):
        if match is None:
            self.match = {}
        else:
            self.match = match
        self.joker=joker

    def is_request(self, req):
        return req.haslayer(DNS) and req.getlayer(DNS).qr == 0
    
    def make_reply(self, req):
        ip = req.getlayer(IP)
        dns = req.getlayer(DNS)
        resp = IP(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport,sport=ip.dport)
        rdata = self.match.get(dns.qd.qname, self.joker)
        resp /= DNS(id=dns.id, qr=1, qd=dns.qd,
                    an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=rdata))
        return resp


