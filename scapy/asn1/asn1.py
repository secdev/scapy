## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## Modified by Maxence Tury <maxence.tury@ssi.gouv.fr>
## This program is published under a GPLv2 license

"""
ASN.1 (Abstract Syntax Notation One)
"""

import random
from datetime import datetime
from scapy.config import conf
from scapy.error import Scapy_Exception, warning
from scapy.volatile import RandField, RandIP
from scapy.utils import Enum_metaclass, EnumElement, binrepr

class RandASN1Object(RandField):
    def __init__(self, objlist=None):
        self.objlist = [
            x._asn1_obj
            for x in ASN1_Class_UNIVERSAL.__rdict__.itervalues()
            if hasattr(x, "_asn1_obj")
        ] if objlist is None else objlist
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
            return o("".join(random.choice(self.chars) for _ in xrange(z)))
        elif issubclass(o, ASN1_SEQUENCE) and (n < 10):
            z = int(random.expovariate(0.08)+1)
            return o([self.__class__(objlist=self.objlist)._fix(n + 1)
                      for _ in xrange(z)])
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
    SEQUENCE = 16|0x20          # constructed encoding
    SET = 17|0x20               # constructed encoding
    NUMERIC_STRING = 18
    PRINTABLE_STRING = 19
    T61_STRING = 20             # aka TELETEX_STRING
    VIDEOTEX_STRING = 21
    IA5_STRING = 22
    UTC_TIME = 23
    GENERALIZED_TIME = 24
    GRAPHIC_STRING = 25
    ISO646_STRING = 26          # aka VISIBLE_STRING
    GENERAL_STRING = 27
    UNIVERSAL_STRING = 28
    CHAR_STRING = 29
    BMP_STRING = 30
    IPADDRESS = 0|0x40          # application-specific encoding
    COUNTER32 = 1|0x40          # application-specific encoding
    GAUGE32 = 2|0x40            # application-specific encoding
    TIME_TICKS = 3|0x40         # application-specific encoding


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


#######################
####  ASN1 objects ####
#######################

# on the whole, we order the classes by ASN1_Class_UNIVERSAL tag value

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
    def __repr__(self):
        h = hex(self.val)
        if h[-1] == "L":
            h = h[:-1]
        # cut at 22 because with leading '0x', x509 serials should be < 23
        if len(h) > 22:
            h = h[:12] + "..." + h[-10:]
        r = repr(self.val)
        if len(r) > 20:
            r = r[:10] + "..." + r[-10:]
        return h + " <%s[%s]>" % (self.__dict__.get("name", self.__class__.__name__), r)

class ASN1_BOOLEAN(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN
    # BER: 0 means False, anything else means True
    def __repr__(self):
        return str((not (self.val==0))) + " " + ASN1_Object.__repr__(self)
    
class ASN1_BIT_STRING(ASN1_Object):
    """
    /!\ ASN1_BIT_STRING values are bit strings like "011101".
    /!\ A zero-bit padded readable string is provided nonetheless,
    /!\ which is also output when __str__ is called.
    """
    tag = ASN1_Class_UNIVERSAL.BIT_STRING
    def __init__(self, val, readable=False):
        if not readable:
            self.val = val
        else:
            self.val_readable = val
    def __setattr__(self, name, value):
        if name == "val_readable":
            if isinstance(value, str):
                val = "".join(binrepr(ord(x)).zfill(8) for x in value)
            else:
                val = "<invalid val_readable>"
            super(ASN1_Object, self).__setattr__("val", val)
            super(ASN1_Object, self).__setattr__(name, value)
            super(ASN1_Object, self).__setattr__("unused_bits", 0)
        elif name == "val":
            if isinstance(value, str):
                if len([c for c in value if c not in ["0", "1"]]) > 0:
                    print "Invalid operation: 'val' is not a valid bit string."
                    return
                else:
                    if len(value) % 8 == 0:
                        unused_bits = 0
                    else:
                        unused_bits = 8 - (len(value) % 8)
                    padded_value = value + ("0" * unused_bits)
                    bytes_arr = zip(*[iter(padded_value)]*8)
                    val_readable = "".join(chr(int("".join(x),2)) for x in bytes_arr)
            else:
                val_readable = "<invalid val>"
                unused_bits = 0
            super(ASN1_Object, self).__setattr__("val_readable", val_readable)
            super(ASN1_Object, self).__setattr__(name, value)
            super(ASN1_Object, self).__setattr__("unused_bits", unused_bits)
        elif name == "unused_bits":
            print "Invalid operation: unused_bits rewriting is not supported."
        else:
            super(ASN1_Object, self).__setattr__(name, value)
    def __repr__(self):
        if len(self.val) <= 16:
            return "<%s[%r] (%d unused bit%s)>" % (self.__dict__.get("name", self.__class__.__name__), self.val, self.unused_bits, "s" if self.unused_bits>1 else "")
        else:
            s = self.val_readable
            if len(s) > 20:
                s = s[:10] + "..." + s[-10:]
            return "<%s[%r] (%d unused bit%s)>" % (self.__dict__.get("name", self.__class__.__name__), s, self.unused_bits, "s" if self.unused_bits>1 else "")
    def __str__(self):
        return self.val_readable

class ASN1_STRING(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.STRING

class ASN1_NULL(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.NULL
    def __repr__(self):
        return ASN1_Object.__repr__(self)

class ASN1_OID(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.OID
    def __init__(self, val):
        val = conf.mib._oid(val)
        ASN1_Object.__init__(self, val)
        self.oidname = conf.mib._oidname(val)
    def __repr__(self):
        return "<%s[%r]>" % (self.__dict__.get("name", self.__class__.__name__), self.oidname)

class ASN1_ENUMERATED(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.ENUMERATED

class ASN1_UTF8_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.UTF8_STRING

class ASN1_NUMERIC_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING

class ASN1_PRINTABLE_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING

class ASN1_T61_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING

class ASN1_VIDEOTEX_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING

class ASN1_IA5_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING

class ASN1_UTC_TIME(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME
    def __init__(self, val):
        super(ASN1_UTC_TIME, self).__init__(val)
    def __setattr__(self, name, value):
        if name == "val":
            pretty_time = None
            if (isinstance(value, str) and
                len(value) == 13 and value[-1] == "Z"):
                dt = datetime.strptime(value[:-1], "%y%m%d%H%M%S")
                pretty_time = dt.strftime("%b %d %H:%M:%S %Y GMT")
            else:
                pretty_time = "%s [invalid utc_time]" % value
            super(ASN1_UTC_TIME, self).__setattr__("pretty_time", pretty_time)
            super(ASN1_UTC_TIME, self).__setattr__(name, value)
        elif name == "pretty_time":
            print "Invalid operation: pretty_time rewriting is not supported."
        else:
            super(ASN1_UTC_TIME, self).__setattr__(name, value)
    def __repr__(self):
        return "%s %s" % (self.pretty_time, ASN1_STRING.__repr__(self))

class ASN1_GENERALIZED_TIME(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME
    def __init__(self, val):
        super(ASN1_GENERALIZED_TIME, self).__init__(val)
    def __setattr__(self, name, value):
        if name == "val":
            pretty_time = None
            if (isinstance(value, str) and
                len(value) == 15 and value[-1] == "Z"):
                dt = datetime.strptime(value[:-1], "%Y%m%d%H%M%S")
                pretty_time = dt.strftime("%b %d %H:%M:%S %Y GMT")
            else:
                pretty_time = "%s [invalid generalized_time]" % value
            super(ASN1_GENERALIZED_TIME, self).__setattr__("pretty_time", pretty_time)
            super(ASN1_GENERALIZED_TIME, self).__setattr__(name, value)
        elif name == "pretty_time":
            print "Invalid operation: pretty_time rewriting is not supported."
        else:
            super(ASN1_GENERALIZED_TIME, self).__setattr__(name, value)
    def __repr__(self):
        return "%s %s" % (self.pretty_time, ASN1_STRING.__repr__(self))

class ASN1_ISO646_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.ISO646_STRING

class ASN1_UNIVERSAL_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.UNIVERSAL_STRING

class ASN1_BMP_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.BMP_STRING

class ASN1_SEQUENCE(ASN1_Object):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE
    def strshow(self, lvl=0):
        s = ("  "*lvl)+("# %s:" % self.__class__.__name__)+"\n"
        for o in self.val:
            s += o.strshow(lvl=lvl+1)
        return s
    
class ASN1_SET(ASN1_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET

class ASN1_IPADDRESS(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.IPADDRESS

class ASN1_COUNTER32(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32

class ASN1_GAUGE32(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.GAUGE32

class ASN1_TIME_TICKS(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS
   

conf.ASN1_default_codec = ASN1_Codecs.BER
