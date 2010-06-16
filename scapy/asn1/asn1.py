## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
ASN.1 (Abstract Syntax Notation One)
"""

import random
from scapy.config import conf
from scapy.error import Scapy_Exception,warning
from scapy.volatile import RandField
from scapy.utils import Enum_metaclass, EnumElement

class RandASN1Object(RandField):
    def __init__(self, objlist=None):
        if objlist is None:
            objlist = map(lambda x:x._asn1_obj,
                          filter(lambda x:hasattr(x,"_asn1_obj"), ASN1_Class_UNIVERSAL.__rdict__.values()))
        self.objlist = objlist
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    def _fix(self, n=0):
        o = random.choice(self.objlist)
        if issubclass(o, ASN1_INTEGER):
            return o(int(random.gauss(0,1000)))
        elif issubclass(o, ASN1_IPADDRESS):
            z = RandIP()._fix()
            return o(z)
        elif issubclass(o, ASN1_STRING):
            z = int(random.expovariate(0.05)+1)
            return o("".join([random.choice(self.chars) for i in range(z)]))
        elif issubclass(o, ASN1_SEQUENCE) and (n < 10):
            z = int(random.expovariate(0.08)+1)
            return o(map(lambda x:x._fix(n+1), [self.__class__(objlist=self.objlist)]*z))
        return ASN1_INTEGER(int(random.gauss(0,1000)))


##############
#### ASN1 ####
##############

class ASN1_Error(Scapy_Exception):
    pass

class ASN1_Encoding_Error(ASN1_Error):
    pass

class ASN1_Decoding_Error(ASN1_Error):
    pass

class ASN1_BadTag_Decoding_Error(ASN1_Decoding_Error):
    pass



class ASN1Codec(EnumElement):
    def register_stem(cls, stem):
        cls._stem = stem
    def dec(cls, s, context=None):
        return cls._stem.dec(s, context=context)
    def safedec(cls, s, context=None):
        return cls._stem.safedec(s, context=context)
    def get_stem(cls):
        return cls.stem
    

class ASN1_Codecs_metaclass(Enum_metaclass):
    element_class = ASN1Codec

class ASN1_Codecs:
    __metaclass__ = ASN1_Codecs_metaclass
    BER = 1
    DER = 2
    PER = 3
    CER = 4
    LWER = 5
    BACnet = 6
    OER = 7
    SER = 8
    XER = 9

class ASN1Tag(EnumElement):
    def __init__(self, key, value, context=None, codec=None):
        EnumElement.__init__(self, key, value)
        self._context = context
        if codec == None:
            codec = {}
        self._codec = codec
    def clone(self): # /!\ not a real deep copy. self.codec is shared
        return self.__class__(self._key, self._value, self._context, self._codec)
    def register_asn1_object(self, asn1obj):
        self._asn1_obj = asn1obj
    def asn1_object(self, val):
        if hasattr(self,"_asn1_obj"):
            return self._asn1_obj(val)
        raise ASN1_Error("%r does not have any assigned ASN1 object" % self)
    def register(self, codecnum, codec):
        self._codec[codecnum] = codec
    def get_codec(self, codec):
        try:
            c = self._codec[codec]
        except KeyError,msg:
            raise ASN1_Error("Codec %r not found for tag %r" % (codec, self))
        return c

class ASN1_Class_metaclass(Enum_metaclass):
    element_class = ASN1Tag
    def __new__(cls, name, bases, dct): # XXX factorise a bit with Enum_metaclass.__new__()
        for b in bases:
            for k,v in b.__dict__.iteritems():
                if k not in dct and isinstance(v,ASN1Tag):
                    dct[k] = v.clone()

        rdict = {}
        for k,v in dct.iteritems():
            if type(v) is int:
                v = ASN1Tag(k,v) 
                dct[k] = v
                rdict[v] = v
            elif isinstance(v, ASN1Tag):
                rdict[v] = v
        dct["__rdict__"] = rdict

        cls = type.__new__(cls, name, bases, dct)
        for v in cls.__dict__.values():
            if isinstance(v, ASN1Tag): 
                v.context = cls # overwrite ASN1Tag contexts, even cloned ones
        return cls
            

class ASN1_Class:
    __metaclass__ = ASN1_Class_metaclass

class ASN1_Class_UNIVERSAL(ASN1_Class):
    name = "UNIVERSAL"
    ERROR = -3
    RAW = -2
    NONE = -1
    ANY = 0
    BOOLEAN = 1
    INTEGER = 2
    BIT_STRING = 3
    STRING = 4
    NULL = 5
    OID = 6
    OBJECT_DESCRIPTOR = 7
    EXTERNAL = 8
    REAL = 9
    ENUMERATED = 10
    EMBEDDED_PDF = 11
    UTF8_STRING = 12
    RELATIVE_OID = 13
    SEQUENCE = 0x30#XXX 16 ??
    SET = 0x31 #XXX 17 ??
    NUMERIC_STRING = 18
    PRINTABLE_STRING = 19
    T61_STRING = 20
    VIDEOTEX_STRING = 21
    IA5_STRING = 22
    UTC_TIME = 23
    GENERALIZED_TIME = 24
    GRAPHIC_STRING = 25
    ISO646_STRING = 26
    GENERAL_STRING = 27
    UNIVERSAL_STRING = 28
    CHAR_STRING = 29
    BMP_STRING = 30
    IPADDRESS = 0x40
    COUNTER32 = 0x41
    GAUGE32 = 0x42
    TIME_TICKS = 0x43
    SEP = 0x80

class ASN1_Object_metaclass(type):
    def __new__(cls, name, bases, dct):
        c = super(ASN1_Object_metaclass, cls).__new__(cls, name, bases, dct)
        try:
            c.tag.register_asn1_object(c)
        except:
            warning("Error registering %r for %r" % (c.tag, c.codec))
        return c


class ASN1_Object:
    __metaclass__ = ASN1_Object_metaclass
    tag = ASN1_Class_UNIVERSAL.ANY
    def __init__(self, val):
        self.val = val
    def enc(self, codec):
        return self.tag.get_codec(codec).enc(self.val)
    def __repr__(self):
        return "<%s[%r]>" % (self.__dict__.get("name", self.__class__.__name__), self.val)
    def __str__(self):
        return self.enc(conf.ASN1_default_codec)
    def strshow(self, lvl=0):
        return ("  "*lvl)+repr(self)+"\n"
    def show(self, lvl=0):
        print self.strshow(lvl)
    def __eq__(self, other):
        return self.val == other
    def __cmp__(self, other):
        return cmp(self.val, other)

class ASN1_DECODING_ERROR(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.ERROR
    def __init__(self, val, exc=None):
        ASN1_Object.__init__(self, val)
        self.exc = exc
    def __repr__(self):
        return "<%s[%r]{{%s}}>" % (self.__dict__.get("name", self.__class__.__name__),
                                   self.val, self.exc.args[0])
    def enc(self, codec):
        if isinstance(self.val, ASN1_Object):
            return self.val.enc(codec)
        return self.val

class ASN1_force(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.RAW
    def enc(self, codec):
        if isinstance(self.val, ASN1_Object):
            return self.val.enc(codec)
        return self.val

class ASN1_BADTAG(ASN1_force):
    pass

class ASN1_INTEGER(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.INTEGER

class ASN1_STRING(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.STRING

class ASN1_BIT_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

class ASN1_PRINTABLE_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING

class ASN1_T61_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING

class ASN1_IA5_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING

class ASN1_NUMERIC_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING

class ASN1_VIDEOTEX_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING

class ASN1_IPADDRESS(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.IPADDRESS

class ASN1_UTC_TIME(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME

class ASN1_GENERALIZED_TIME(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME

class ASN1_TIME_TICKS(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS

class ASN1_BOOLEAN(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN

class ASN1_ENUMERATED(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.ENUMERATED
    
class ASN1_NULL(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.NULL

class ASN1_SEP(ASN1_NULL):
    tag = ASN1_Class_UNIVERSAL.SEP

class ASN1_GAUGE32(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.GAUGE32
    
class ASN1_COUNTER32(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32
    
class ASN1_SEQUENCE(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE
    def strshow(self, lvl=0):
        s = ("  "*lvl)+("# %s:" % self.__class__.__name__)+"\n"
        for o in self.val:
            s += o.strshow(lvl=lvl+1)
        return s
    
class ASN1_SET(ASN1_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET
    
class ASN1_OID(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.OID
    def __init__(self, val):
        val = conf.mib._oid(val)
        ASN1_Object.__init__(self, val)
    def __repr__(self):
        return "<%s[%r]>" % (self.__dict__.get("name", self.__class__.__name__), conf.mib._oidname(self.val))
    def __oidname__(self):
        return '%s'%conf.mib._oidname(self.val)
    


conf.ASN1_default_codec = ASN1_Codecs.BER
