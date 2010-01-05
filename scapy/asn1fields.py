## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from asn1.asn1 import *
from asn1.ber import *
from volatile import *
from base_classes import BasePacket


#####################
#### ASN1 Fields ####
#####################

class ASN1F_badsequence(Exception):
    pass

class ASN1F_element:
    pass

class ASN1F_optionnal(ASN1F_element):
    def __init__(self, field):
        self._field=field
    def __getattr__(self, attr):
        return getattr(self._field,attr)
    def dissect(self,pkt,s):
        try:
            return self._field.dissect(pkt,s)
        except ASN1F_badsequence:
            self._field.set_val(pkt,None)
            return s
        except BER_Decoding_Error:
            self._field.set_val(pkt,None)
            return s
    def build(self, pkt):
        if self._field.is_empty(pkt):
            return ""
        return self._field.build(pkt)

class ASN1F_field(ASN1F_element):
    holds_packets=0
    islist=0

    ASN1_tag = ASN1_Class_UNIVERSAL.ANY
    context=ASN1_Class_UNIVERSAL
    
    def __init__(self, name, default, context=None):
        if context is not None:
            self.context = context
        self.name = name
        self.default = default

    def i2repr(self, pkt, x):
        return repr(x)
    def i2h(self, pkt, x):
        return x
    def any2i(self, pkt, x):
        return x
    def m2i(self, pkt, x):
        return self.ASN1_tag.get_codec(pkt.ASN1_codec).safedec(x, context=self.context)
    def i2m(self, pkt, x):
        if x is None:
            x = 0
        if isinstance(x, ASN1_Object):
            if ( self.ASN1_tag == ASN1_Class_UNIVERSAL.ANY
                 or x.tag == ASN1_Class_UNIVERSAL.RAW
                 or x.tag == ASN1_Class_UNIVERSAL.ERROR
                 or self.ASN1_tag == x.tag ):
                return x.enc(pkt.ASN1_codec)
            else:
                raise ASN1_Error("Encoding Error: got %r instead of an %r for field [%s]" % (x, self.ASN1_tag, self.name))
        return self.ASN1_tag.get_codec(pkt.ASN1_codec).enc(x)

    def do_copy(self, x):
        if hasattr(x, "copy"):
            return x.copy()
        if type(x) is list:
            x = x[:]
            for i in xrange(len(x)):
                if isinstance(x[i], BasePacket):
                    x[i] = x[i].copy()
        return x

    def build(self, pkt):
        return self.i2m(pkt, getattr(pkt, self.name))

    def set_val(self, pkt, val):
        setattr(pkt, self.name, val)
    def is_empty(self, pkt):
        return getattr(pkt,self.name) is None
    
    def dissect(self, pkt, s):
        v,s = self.m2i(pkt, s)
        self.set_val(pkt, v)
        return s

    def get_fields_list(self):
        return [self]

    def __hash__(self):
        return hash(self.name)
    def __str__(self):
        return self.name
    def __eq__(self, other):
        return self.name == other
    def __repr__(self):
        return self.name
    def randval(self):
        return RandInt()


class ASN1F_INTEGER(ASN1F_field):
    ASN1_tag= ASN1_Class_UNIVERSAL.INTEGER
    def randval(self):
        return RandNum(-2**64, 2**64-1)

class ASN1F_BOOLEAN(ASN1F_field):
    ASN1_tag= ASN1_Class_UNIVERSAL.BOOLEAN
    def randval(self):
        return RandChoice(True,False)

class ASN1F_NULL(ASN1F_INTEGER):
    ASN1_tag= ASN1_Class_UNIVERSAL.NULL

class ASN1F_SEP(ASN1F_NULL):
    ASN1_tag= ASN1_Class_UNIVERSAL.SEP

class ASN1F_enum_INTEGER(ASN1F_INTEGER):
    def __init__(self, name, default, enum):
        ASN1F_INTEGER.__init__(self, name, default)
        i2s = self.i2s = {}
        s2i = self.s2i = {}
        if type(enum) is list:
            keys = xrange(len(enum))
        else:
            keys = enum.keys()
        if filter(lambda x: type(x) is str, keys):
            i2s,s2i = s2i,i2s
        for k in keys:
            i2s[k] = enum[k]
            s2i[enum[k]] = k
    def any2i_one(self, pkt, x):
        if type(x) is str:
            x = self.s2i[x]
        return x
    def i2repr_one(self, pkt, x):
        return self.i2s.get(x, repr(x))
    
    def any2i(self, pkt, x):
        if type(x) is list:
            return map(lambda z,pkt=pkt:self.any2i_one(pkt,z), x)
        else:
            return self.any2i_one(pkt,x)        
    def i2repr(self, pkt, x):
        if type(x) is list:
            return map(lambda z,pkt=pkt:self.i2repr_one(pkt,z), x)
        else:
            return self.i2repr_one(pkt,x)

class ASN1F_ENUMERATED(ASN1F_enum_INTEGER):
    ASN1_tag = ASN1_Class_UNIVERSAL.ENUMERATED

class ASN1F_STRING(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.STRING
    def randval(self):
        return RandString(RandNum(0, 1000))

class ASN1F_PRINTABLE_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING

class ASN1F_BIT_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.BIT_STRING
    
class ASN1F_IPADDRESS(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.IPADDRESS    

class ASN1F_TIME_TICKS(ASN1F_INTEGER):
    ASN1_tag = ASN1_Class_UNIVERSAL.TIME_TICKS

class ASN1F_UTC_TIME(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.UTC_TIME

class ASN1F_GENERALIZED_TIME(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME

class ASN1F_OID(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.OID
    def randval(self):
        return RandOID()

class ASN1F_SEQUENCE(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.SEQUENCE
    def __init__(self, *seq, **kargs):
        if "ASN1_tag" in kargs:
            self.ASN1_tag = kargs["ASN1_tag"]
        self.seq = seq
    def __repr__(self):
        return "<%s%r>" % (self.__class__.__name__,self.seq,)
    def set_val(self, pkt, val):
        for f in self.seq:
            f.set_val(pkt,val)
    def is_empty(self, pkt):
        for f in self.seq:
            if not f.is_empty(pkt):
                return False
        return True
    def get_fields_list(self):
        return reduce(lambda x,y: x+y.get_fields_list(), self.seq, [])
    def build(self, pkt):
        s = reduce(lambda x,y: x+y.build(pkt), self.seq, "")
        return self.i2m(pkt, s)
    def dissect(self, pkt, s):
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        try:
            i,s,remain = codec.check_type_check_len(s)
            for obj in self.seq:
                s = obj.dissect(pkt,s)
            if s:
                warning("Too many bytes to decode sequence: [%r]" % s) # XXX not reversible!
            return remain
        except ASN1_Error,e:
            raise ASN1F_badsequence(e)

class ASN1F_SET(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_UNIVERSAL.SET

class ASN1F_SEQUENCE_OF(ASN1F_SEQUENCE):
    holds_packets = 1
    islist = 1
    def __init__(self, name, default, asn1pkt, ASN1_tag=0x30):
        self.asn1pkt = asn1pkt
        self.tag = chr(ASN1_tag)
        self.name = name
        self.default = default
    def i2repr(self, pkt, i):
        if i is None:
            return []
        return i
    def get_fields_list(self):
        return [self]
    def set_val(self, pkt, val):
        ASN1F_field.set_val(self, pkt, val)
    def is_empty(self, pkt):
        return ASN1F_field.is_empty(self, pkt)
    def build(self, pkt):
        val = getattr(pkt, self.name)
        if isinstance(val, ASN1_Object) and val.tag == ASN1_Class_UNIVERSAL.RAW:
            s = val
        elif val is None:
            s = ""
        else:
            s = "".join(map(str, val ))
        return self.i2m(pkt, s)
    def dissect(self, pkt, s):
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        i,s1,remain = codec.check_type_check_len(s)
        lst = []
        while s1:
            try:
                p = self.asn1pkt(s1)
            except ASN1F_badsequence,e:
                lst.append(packet.Raw(s1))
                break
            lst.append(p)
            if packet.Raw in p:
                s1 = p[packet.Raw].load
                del(p[packet.Raw].underlayer.payload)
            else:
                break
        self.set_val(pkt, lst)
        return remain
    def randval(self):
        return fuzz(self.asn1pkt())
    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__,self.name)

class ASN1F_PACKET(ASN1F_field):
    holds_packets = 1
    def __init__(self, name, default, cls):
        ASN1_field.__init__(self, name, default)
        self.cls = cls
    def i2m(self, pkt, x):
        if x is None:
            x = ""
        return str(x)
    def extract_packet(self, cls, x):
        try:
            c = cls(x)
        except ASN1F_badsequence:
            c = packet.Raw(x)
        cpad = c.getlayer(packet.Padding)
        x = ""
        if cpad is not None:
            x = cpad.load
            del(cpad.underlayer.payload)
        return c,x
    def m2i(self, pkt, x):
        return self.extract_packet(self.cls, x)


class ASN1F_CHOICE(ASN1F_PACKET):
    ASN1_tag = ASN1_Class_UNIVERSAL.NONE
    def __init__(self, name, default, *args):
        self.name=name
        self.choice = {}
        for p in args:
            self.choice[p.ASN1_root.ASN1_tag] = p
#        self.context=context
        self.default=default
    def m2i(self, pkt, x):
        if len(x) == 0:
            return packet.Raw(),""
            raise ASN1_Error("ASN1F_CHOICE: got empty string")
        if ord(x[0]) not in self.choice:
            return packet.Raw(x),"" # XXX return RawASN1 packet ? Raise error 
            raise ASN1_Error("Decoding Error: choice [%i] not found in %r" % (ord(x[0]), self.choice.keys()))

        z = ASN1F_PACKET.extract_packet(self, self.choice[ord(x[0])], x)
        return z
    def randval(self):
        return RandChoice(*map(lambda x:fuzz(x()), self.choice.values()))
            
    
# This import must come in last to avoid problems with cyclic dependencies
import packet
