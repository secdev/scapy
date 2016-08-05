## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
DNS: Domain Name System.
"""

import socket,struct

from scapy.config import conf
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.sendrecv import sr1
from scapy.layers.inet import IP, DestIPField, UDP
from scapy.layers.inet6 import DestIP6Field

class DNSStrField(StrField):

    def h2i(self, pkt, x):
      if x == "":
        return "."
      return x

    def i2m(self, pkt, x):
        if x == ".":
          return "\x00"

        x = [k[:63] for k in x.split(".")] # Truncate chunks that cannot be encoded (more than 63 bytes..)
        x = map(lambda y: chr(len(y))+y, x)
        x = "".join(x)
        if x[-1] != "\x00":
            x += "\x00"
        return x

    def getfield(self, pkt, s):
        n = ""

        if ord(s[0]) == 0:
          return s[1:], "."

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
    __slots__ = ["rr"]
    def __init__(self, name, default, rr):
        ShortField.__init__(self, name, default)
        self.rr = rr
    def _countRR(self, pkt):
        x = getattr(pkt,self.rr)
        i = 0
        while isinstance(x, DNSRR) or isinstance(x, DNSQR) or isdnssecRR(x):
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
    __slots__ = ["countfld", "passon"]
    holds_packets = 1
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
        if type in [2, 3, 4, 5]:
            rr.rdata = DNSgetstr(s,p)[0]
            del(rr.rdlen)
        elif type in DNSRR_DISPATCHER:
            rr = DNSRR_DISPATCHER[type]("\x00"+ret+s[p:p+rdlen])
	else:
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
    def decodeRR(self, name, s, p):
        ret = s[p:p+4]
        p += 4
        rr = DNSQR("\x00"+ret)
        rr.qname = name
        return rr,p
        
        

class RDataField(StrLenField):
    def m2i(self, pkt, s):
        family = None
        if pkt.type == 1: # A
            family = socket.AF_INET
        elif pkt.type == 12: # PTR
            s = DNSgetstr(s, 0)[0]
        elif pkt.type == 16: # TXT
            ret_s = ""
            tmp_s = s
            # RDATA contains a list of strings, each are prepended with
            # a byte containing the size of the following string.
            while tmp_s:
                tmp_len = struct.unpack("!B", tmp_s[0])[0] + 1
                if tmp_len > len(tmp_s):
                  warning("DNS RR TXT prematured end of character-string (size=%i, remaining bytes=%i)" % (tmp_len, len(tmp_s)))
                ret_s += tmp_s[1:tmp_len]
                tmp_s = tmp_s[tmp_len:]
            s = ret_s
        elif pkt.type == 28: # AAAA
            family = socket.AF_INET6
        if family is not None:    
            s = inet_ntop(family, s)
        return s
    def i2m(self, pkt, s):
        if pkt.type == 1: # A
            if s:
                s = inet_aton(s)
        elif pkt.type in [2, 3, 4, 5, 12]: # NS, MD, MF, CNAME, PTR
            s = "".join(map(lambda x: chr(len(x))+x, s.split(".")))
            if ord(s[-1]):
                s += "\x00"
        elif pkt.type == 16: # TXT
            if s:
                ret_s = ""
                # The initial string must be splitted into a list of strings
                # prepended with theirs sizes.
                while len(s) >= 255:
                    ret_s += "\xff" + s[:255]
                    s = s[255:]
                # The remaining string is less than 255 bytes long    
                if len(s):
                    ret_s += struct.pack("!B", len(s)) + s
                s = ret_s
        elif pkt.type == 28: # AAAA
            if s:
                s = inet_pton(socket.AF_INET6, s)
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
    fields_desc = [ ShortField("id", 0),
                    BitField("qr", 0, 1),
                    BitEnumField("opcode", 0, 4, {0:"QUERY",1:"IQUERY",2:"STATUS"}),
                    BitField("aa", 0, 1),
                    BitField("tc", 0, 1),
                    BitField("rd", 1, 1),
                    BitField("ra", 0, 1),
                    BitField("z", 0, 1),
                    # AD and CD bits are defined in RFC 2535
                    BitField("ad", 0, 1), # Authentic Data
                    BitField("cd", 0, 1), # Checking Disabled
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
             1:"A", 2:"NS", 3:"MD", 4:"MF", 5:"CNAME", 6:"SOA", 7: "MB", 8:"MG",
             9:"MR",10:"NULL",11:"WKS",12:"PTR",13:"HINFO",14:"MINFO",15:"MX",16:"TXT",
             17:"RP",18:"AFSDB",28:"AAAA", 33:"SRV",38:"A6",39:"DNAME",
             41:"OPT", 43:"DS", 46:"RRSIG", 47:"NSEC", 48:"DNSKEY",
	     50: "NSEC3", 51: "NSEC3PARAM", 32769:"DLV" }

dnsqtypes = {251:"IXFR",252:"AXFR",253:"MAILB",254:"MAILA",255:"ALL"}
dnsqtypes.update(dnstypes)
dnsclasses =  {1: 'IN',  2: 'CS',  3: 'CH',  4: 'HS',  255: 'ANY'}


class DNSQR(Packet):
    name = "DNS Question Record"
    show_indent=0
    fields_desc = [DNSStrField("qname", "www.example.com"),
                   ShortEnumField("qtype", 1, dnsqtypes),
                   ShortEnumField("qclass", 1, dnsclasses)]
                    
                    

# RFC 2671 - Extension Mechanisms for DNS (EDNS0)

class EDNS0TLV(Packet):
    name = "DNS EDNS0 TLV"
    fields_desc = [ ShortEnumField("optcode", 0, { 0: "Reserved", 1: "LLQ", 2: "UL", 3: "NSID", 4: "Reserved", 5: "PING" }),
                    FieldLenField("optlen", None, "optdata", fmt="H"),
                    StrLenField("optdata", "", length_from=lambda pkt: pkt.optlen) ]

    def extract_padding(self, p):
	return "", p

class DNSRROPT(Packet):
    name = "DNS OPT Resource Record"
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 41, dnstypes),
                    ShortField("rclass", 4096),
                    ByteField("extrcode", 0),
                    ByteField("version", 0),
                    # version 0 means EDNS0
                    BitEnumField("z", 32768, 16, { 32768: "D0" }),
                    # D0 means DNSSEC OK from RFC 3225
                    FieldLenField("rdlen", None, length_of="rdata", fmt="H"),
                    PacketListField("rdata", [], EDNS0TLV, length_from=lambda pkt: pkt.rdlen) ]

# RFC 4034 - Resource Records for the DNS Security Extensions

# 09/2013 from http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
dnssecalgotypes = { 0:"Reserved", 1:"RSA/MD5", 2:"Diffie-Hellman", 3:"DSA/SHA-1", 
                    4:"Reserved", 5:"RSA/SHA-1", 6:"DSA-NSEC3-SHA1",
                    7:"RSASHA1-NSEC3-SHA1", 8:"RSA/SHA-256", 9:"Reserved",
                   10:"RSA/SHA-512", 11:"Reserved", 12:"GOST R 34.10-2001",
                   13:"ECDSA Curve P-256 with SHA-256", 14: "ECDSA Curve P-384 with SHA-384",
                  252:"Reserved for Indirect Keys", 253:"Private algorithms - domain name",
                  254:"Private algorithms - OID", 255:"Reserved" }

# 09/2013 from http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
dnssecdigesttypes = { 0:"Reserved", 1:"SHA-1", 2:"SHA-256", 3:"GOST R 34.11-94",  4:"SHA-384" }


class TimeField(IntField):

    def any2i(self, pkt, x):
        if type(x) == str:
	    import time, calendar
	    t = time.strptime(x, "%Y%m%d%H%M%S")
            return int(calendar.timegm(t))
        return x

    def i2repr(self, pkt, x):
	import time
	x = self.i2h(pkt, x)
	t = time.strftime("%Y%m%d%H%M%S", time.gmtime(x))
	return "%s (%d)" % (t ,x) 


def bitmap2RRlist(bitmap):
    """
    Decode the 'Type Bit Maps' field of the NSEC Resource Record into an 
    integer list.
    """
    # RFC 4034, 4.1.2. The Type Bit Maps Field

    RRlist = []

    while bitmap:

	if len(bitmap) < 2:
	    warning("bitmap too short (%i)" % len(bitmap))
	    return
   
	window_block = ord(bitmap[0]) # window number
	offset = 256*window_block # offset of the Ressource Record
	bitmap_len = ord(bitmap[1]) # length of the bitmap in bytes

	if bitmap_len <= 0 or bitmap_len > 32:
	    warning("bitmap length is no valid (%i)" % bitmap_len)
	    return

	tmp_bitmap = bitmap[2:2+bitmap_len]

	# Let's compare each bit of tmp_bitmap and compute the real RR value
	for b in xrange(len(tmp_bitmap)):
	    v = 128
	    for i in xrange(8):
		if ord(tmp_bitmap[b]) & v:
		    # each of the RR is encoded as a bit
		    RRlist += [ offset + b*8 + i ] 
		v = v >> 1
	
	# Next block if any
	bitmap = bitmap[2+bitmap_len:]

    return RRlist


def RRlist2bitmap(lst):
    """
    Encode a list of integers representing Resource Records to a bitmap field 
    used in the NSEC Resource Record.
    """
    # RFC 4034, 4.1.2. The Type Bit Maps Field

    import math

    bitmap = ""
    lst = list(set(lst))
    lst.sort()
    
    lst = filter(lambda x: x <= 65535, lst)
    lst = map(lambda x: abs(x), lst)

    # number of window blocks
    max_window_blocks = int(math.ceil(lst[-1] / 256.))
    min_window_blocks = int(math.floor(lst[0] / 256.))
    if min_window_blocks == max_window_blocks:
	max_window_blocks += 1

    for wb in xrange(min_window_blocks, max_window_blocks+1):
        # First, filter out RR not encoded in the current window block
        # i.e. keep everything between 256*wb <= 256*(wb+1)
        rrlist = filter(lambda x: 256 * wb <= x < 256 * (wb + 1), lst)
        rrlist.sort()
        if rrlist == []:
            continue
     
        # Compute the number of bytes used to store the bitmap
        if rrlist[-1] == 0: # only one element in the list
	    bytes = 1
        else:
	    max = rrlist[-1] - 256*wb
	    bytes = int(math.ceil(max / 8)) + 1  # use at least 1 byte
        if bytes > 32: # Don't encode more than 256 bits / values
	    bytes = 32

        bitmap += struct.pack("B", wb)
        bitmap += struct.pack("B", bytes)

        # Generate the bitmap
        for tmp in xrange(bytes):
            v = 0
            # Remove out of range Ressource Records
            tmp_rrlist = filter(lambda x: 256 * wb + 8 * tmp <= x < 256 * wb + 8 * tmp + 8, rrlist)
            if not tmp_rrlist == []:
                # 1. rescale to fit into 8 bits
                tmp_rrlist = map(lambda x: (x-256*wb)-(tmp*8), tmp_rrlist)
                # 2. x gives the bit position ; compute the corresponding value
                tmp_rrlist = map(lambda x: 2**(7-x) , tmp_rrlist)
                # 3. sum everything
                v = reduce(lambda x,y: x+y, tmp_rrlist)
            bitmap += struct.pack("B", v)
   
    return bitmap


class RRlistField(StrField):
    def h2i(self, pkt, x):
	if type(x) == list:
	    return RRlist2bitmap(x)
	return x

    def i2repr(self, pkt, x):
	x = self.i2h(pkt, x)
	rrlist = bitmap2RRlist(x)
	return [ dnstypes.get(rr, rr) for rr in rrlist ]


class _DNSRRdummy(Packet):
    name = "Dummy class that implements post_build() for Ressource Records"
    def post_build(self, pkt, pay):
        if not self.rdlen == None:
            return pkt

        lrrname = len(self.fields_desc[0].i2m("", self.getfieldval("rrname")))
        l = len(pkt) - lrrname - 10
        pkt = pkt[:lrrname+8] + struct.pack("!H", l) + pkt[lrrname+8+2:]
        
        return pkt

class DNSRRSOA(_DNSRRdummy):
    name = "DNS SOA Resource Record"
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 6, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    ShortField("rdlen", None),
                    DNSStrField("mname", ""),
                    DNSStrField("rname", ""),
                    IntField("serial", 0),
                    IntField("refresh", 0),
                    IntField("retry", 0),
                    IntField("expire", 0),
                    IntField("minimum", 0)
                  ]

class DNSRRRSIG(_DNSRRdummy):
    name = "DNS RRSIG Resource Record"
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 46, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    ShortField("rdlen", None),
                    ShortEnumField("typecovered", 1, dnstypes),
                    ByteEnumField("algorithm", 5, dnssecalgotypes),
                    ByteField("labels", 0),
                    IntField("originalttl", 0),
                    TimeField("expiration", 0),
                    TimeField("inception", 0),
                    ShortField("keytag", 0),
                    DNSStrField("signersname", ""),
                    StrField("signature", "")
                  ]


class DNSRRNSEC(_DNSRRdummy):
    name = "DNS NSEC Resource Record"
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 47, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    ShortField("rdlen", None),
                    DNSStrField("nextname", ""),
                    RRlistField("typebitmaps", "")
                  ]


class DNSRRDNSKEY(_DNSRRdummy):
    name = "DNS DNSKEY Resource Record"
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 48, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    ShortField("rdlen", None),
                    FlagsField("flags", 256, 16, "S???????Z???????"),
                    # S: Secure Entry Point
                    # Z: Zone Key
                    ByteField("protocol", 3),
                    ByteEnumField("algorithm", 5, dnssecalgotypes),
                    StrField("publickey", "")
                  ]


class DNSRRDS(_DNSRRdummy):
    name = "DNS DS Resource Record"
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 43, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    ShortField("rdlen", None),
                    ShortField("keytag", 0),
                    ByteEnumField("algorithm", 5, dnssecalgotypes),
                    ByteEnumField("digesttype", 5, dnssecdigesttypes),
                    StrField("digest", "")
                  ]


# RFC 5074 - DNSSEC Lookaside Validation (DLV)
class DNSRRDLV(DNSRRDS):
    name = "DNS DLV Resource Record"
    def __init__(self, *args, **kargs):
       DNSRRDS.__init__(self, *args, **kargs)
       if not kargs.get('type', 0):
           self.type = 32769

# RFC 5155 - DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
class DNSRRNSEC3(_DNSRRdummy):
    name = "DNS NSEC3 Resource Record"
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 50, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    ShortField("rdlen", None),
		    ByteField("hashalg", 0), 
                    BitEnumField("flags", 0, 8, {1:"Opt-Out"}),
		    ShortField("iterations", 0), 
		    FieldLenField("saltlength", 0, fmt="!B", length_of="salt"),
		    StrLenField("salt", "", length_from=lambda x: x.saltlength),
		    FieldLenField("hashlength", 0, fmt="!B", length_of="nexthashedownername"),
		    StrLenField("nexthashedownername", "", length_from=lambda x: x.hashlength),
                    RRlistField("typebitmaps", "")
		  ]


class DNSRRNSEC3PARAM(_DNSRRdummy):
    name = "DNS NSEC3PARAM Resource Record"
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 51, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    ShortField("rdlen", None),
		    ByteField("hashalg", 0), 
		    ByteField("flags", 0), 
		    ShortField("iterations", 0), 
		    FieldLenField("saltlength", 0, fmt="!B", length_of="salt"),
		    StrLenField("salt", "", length_from=lambda pkt: pkt.saltlength)
		  ]


DNSRR_DISPATCHER = {
    41: DNSRROPT,        # RFC 1671
    43: DNSRRDS,         # RFC 4034
    46: DNSRRRSIG,       # RFC 4034
    47: DNSRRNSEC,       # RFC 4034
    48: DNSRRDNSKEY,     # RFC 4034
    50: DNSRRNSEC3,      # RFC 5155
    51: DNSRRNSEC3PARAM, # RFC 5155
    32769: DNSRRDLV,     # RFC 4431
}

DNSSEC_CLASSES = tuple(DNSRR_DISPATCHER.itervalues())

def isdnssecRR(obj):
    return isinstance(obj, DNSSEC_CLASSES)

class DNSRR(Packet):
    name = "DNS Resource Record"
    show_indent=0
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 1, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    RDLenField("rdlen"),
                    RDataField("rdata", "", length_from=lambda pkt:pkt.rdlen) ]


bind_layers(UDP, DNS, dport=5353)
bind_layers(UDP, DNS, sport=5353)
bind_layers(UDP, DNS, dport=53)
bind_layers(UDP, DNS, sport=53)
DestIPField.bind_addr(UDP, "224.0.0.251", dport=5353)
DestIP6Field.bind_addr(UDP, "ff02::fb", dport=5353)


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


