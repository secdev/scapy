## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## Enhanced by Maxence Tury <maxence.tury@ssi.gouv.fr>
## This program is published under a GPLv2 license

"""
Classes that implement ASN.1 data structures.
"""

from asn1.asn1 import *
from asn1.ber import *
from asn1.mib import *
from volatile import *
from base_classes import BasePacket
from utils import binrepr

FLEXIBLE_TAGS = False

class ASN1F_badsequence(Exception):
    pass

class ASN1F_element(object):
    pass


##########################
#### Basic ASN1 Field ####
##########################

class ASN1F_field(ASN1F_element):
    holds_packets = 0
    islist = 0
    ASN1_tag = ASN1_Class_UNIVERSAL.ANY
    context = ASN1_Class_UNIVERSAL
    
    def __init__(self, name, default, context=None,
                 implicit_tag=None, explicit_tag=None):
        self.context = context
        self.name = name
        if default is None:
            self.default = None
        elif type(default) is ASN1_NULL:
            self.default = default
        else:
            self.default = self.ASN1_tag.asn1_object(default)
        self.flexible_tag = False or FLEXIBLE_TAGS
        if (implicit_tag is not None) and (explicit_tag is not None):
            err_msg = "field cannot be both implicitly and explicitly tagged"
            raise ASN1_Error(err_msg)
        self.implicit_tag = implicit_tag
        self.explicit_tag = explicit_tag
        # network_tag gets useful for ASN1F_CHOICE
        self.network_tag = implicit_tag or explicit_tag or self.ASN1_tag

    def i2repr(self, pkt, x):
        return repr(x)
    def i2h(self, pkt, x):
        return x
    def any2i(self, pkt, x):
        return x
    def m2i(self, pkt, s):
        """
        The good thing about safedec is that it may still decode ASN1
        even if there is a mismatch between the expected tag (self.ASN1_tag)
        and the actual tag; the decoded ASN1 object will simply be put
        into an ASN1_BADTAG object. However, safedec prevents the raising of
        exceptions needed for ASN1F_optional processing.
        Thus we use 'flexible_tag', which should be False with ASN1F_optional.

        Regarding other fields, we might need to know whether encoding went
        as expected or not. Noticeably, input methods from cert.py expect
        certain exceptions to be raised. Hence default flexible_tag is False,
        but we provide a FLEXIBLE_TAGS switch for debugging purposes.
        """
        s = BER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                            implicit_tag=self.implicit_tag,
                            explicit_tag=self.explicit_tag,
                            safe=self.flexible_tag)
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        if self.flexible_tag:
            return codec.safedec(s, context=self.context)
        else:
            return codec.dec(s, context=self.context)
    def i2m(self, pkt, x):
        if x is None:
            return ""
        if isinstance(x, ASN1_Object):
            if ( self.ASN1_tag == ASN1_Class_UNIVERSAL.ANY
                 or x.tag == ASN1_Class_UNIVERSAL.RAW
                 or x.tag == ASN1_Class_UNIVERSAL.ERROR
                 or self.ASN1_tag == x.tag ):
                s = x.enc(pkt.ASN1_codec)
            else:
                raise ASN1_Error("Encoding Error: got %r instead of an %r for field [%s]" % (x, self.ASN1_tag, self.name))
        else:
            s = self.ASN1_tag.get_codec(pkt.ASN1_codec).enc(x)
        return BER_tagging_enc(s, implicit_tag=self.implicit_tag,
                               explicit_tag=self.explicit_tag)
    def extract_packet(self, cls, s):
        if len(s) > 0:
            try:
                c = cls(s)
            except ASN1F_badsequence:
                c = packet.Raw(s)
            cpad = c.getlayer(packet.Raw)
            s = ""
            if cpad is not None:
                s = cpad.load
                del(cpad.underlayer.payload)
            return c,s
        else:
            return None,s
 
    def build(self, pkt):
        return self.i2m(pkt, getattr(pkt, self.name))
    def dissect(self, pkt, s):
        v,s = self.m2i(pkt, s)
        self.set_val(pkt, v)
        return s

    def do_copy(self, x):
        if hasattr(x, "copy"):
            return x.copy()
        if type(x) is list:
            x = x[:]
            for i in xrange(len(x)):
                if isinstance(x[i], BasePacket):
                    x[i] = x[i].copy()
        return x
    def set_val(self, pkt, val):
        setattr(pkt, self.name, val)
    def is_empty(self, pkt):
        return getattr(pkt, self.name) is None
    def get_fields_list(self):
        return [self]
    
    def __hash__(self):
        return hash(self.name)
    def __str__(self):
        return repr(self)
    def randval(self):
        return RandInt()


############################
#### Simple ASN1 Fields ####
############################

class ASN1F_BOOLEAN(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.BOOLEAN
    def randval(self):
        return RandChoice(True, False)

class ASN1F_INTEGER(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.INTEGER
    def randval(self):
        return RandNum(-2**64, 2**64-1)

class ASN1F_enum_INTEGER(ASN1F_INTEGER):
    def __init__(self, name, default, enum, context=None,
                 implicit_tag=None, explicit_tag=None):
        ASN1F_INTEGER.__init__(self, name, default, context=context,
                               implicit_tag=implicit_tag,
                               explicit_tag=explicit_tag)
        i2s = self.i2s = {}
        s2i = self.s2i = {}
        if type(enum) is list:
            keys = xrange(len(enum))
        else:
            keys = enum.keys()
        if any(isinstance(x, basestring) for x in keys):
            i2s, s2i = s2i, i2s
        for k in keys:
            i2s[k] = enum[k]
            s2i[enum[k]] = k
    def any2i_one(self, pkt, x):
        if type(x) is str:
            x = self.s2i[x]
        return x
    def any2i(self, pkt, x):
        if type(x) is list:
            return map(lambda z,pkt=pkt:self.any2i_one(pkt,z), x)
        else:
            return self.any2i_one(pkt, x)        
    def i2repr_one(self, pkt, x):
        if x is not None:
            r = self.i2s.get(x)
            if r:
                return r + " " + repr(x)
        return repr(x)
    def i2repr(self, pkt, x):
        if type(x) is list:
            return map(lambda z,pkt=pkt:self.i2repr_one(pkt, z), x)
        else:
            return self.i2repr_one(pkt, x)

class ASN1F_BIT_STRING(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.BIT_STRING
    def __init__(self, name, default, default_readable=True, context=None,
                 implicit_tag=None, explicit_tag=None):
        if default is not None and default_readable:
            default = "".join(binrepr(ord(x)).zfill(8) for x in default)
        ASN1F_field.__init__(self, name, default, context=context,
                             implicit_tag=implicit_tag,
                             explicit_tag=explicit_tag)
    def randval(self):
        return RandString(RandNum(0, 1000))
    
class ASN1F_STRING(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.STRING
    def randval(self):
        return RandString(RandNum(0, 1000))

class ASN1F_NULL(ASN1F_INTEGER):
    ASN1_tag = ASN1_Class_UNIVERSAL.NULL

class ASN1F_OID(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.OID
    def randval(self):
        return RandOID()

class ASN1F_ENUMERATED(ASN1F_enum_INTEGER):
    ASN1_tag = ASN1_Class_UNIVERSAL.ENUMERATED

class ASN1F_UTF8_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.UTF8_STRING

class ASN1F_PRINTABLE_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING

class ASN1F_T61_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.T61_STRING

class ASN1F_IA5_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.IA5_STRING
   
class ASN1F_UTC_TIME(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.UTC_TIME

class ASN1F_GENERALIZED_TIME(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME

class ASN1F_ISO646_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.ISO646_STRING

class ASN1F_UNIVERSAL_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.UNIVERSAL_STRING
   
class ASN1F_BMP_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.BMP_STRING
   
class ASN1F_SEQUENCE(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.SEQUENCE
    holds_packets = 1
    def __init__(self, *seq, **kwargs):
        name = "dummy_seq_name"
        default = [field.default for field in seq]
        for kwarg in ["context", "implicit_tag", "explicit_tag"]:
            if kwarg in kwargs:
                setattr(self, kwarg, kwargs[kwarg])
            else:
                setattr(self, kwarg, None)
        ASN1F_field.__init__(self, name, default, context=self.context,
                             implicit_tag=self.implicit_tag,
                             explicit_tag=self.explicit_tag)
        self.seq = seq
        self.islist = len(seq) > 1
    def __repr__(self):
        return "<%s%r>" % (self.__class__.__name__, self.seq)
    def is_empty(self, pkt):
        for f in self.seq:
            if not f.is_empty(pkt):
                return False
        return True
    def get_fields_list(self):
        return reduce(lambda x,y: x+y.get_fields_list(), self.seq, [])
    def m2i(self, pkt, s):
        """
        ASN1F_SEQUENCE behaves transparently, with nested ASN1_objects being
        dissected one by one. Because we use obj.dissect (see loop below)
        instead of obj.m2i (as we trust dissect to do the appropriate set_vals)
        we do not directly retrieve the list of nested objects.
        Thus m2i returns an empty list (along with the proper remainder).
        It is discarded by dissect() and should not be missed elsewhere.
        """
        s = BER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                            implicit_tag=self.implicit_tag,
                            explicit_tag=self.explicit_tag,
                            safe=self.flexible_tag)
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        i,s,remain = codec.check_type_check_len(s)
        if len(s) == 0:
            for obj in self.seq:
                obj.set_val(pkt, None)
        else:
            for obj in self.seq:
                try:
                    s = obj.dissect(pkt, s)
                except ASN1F_badsequence,e:
                    break
            if len(s) > 0:
                raise BER_Decoding_Error("unexpected remainder", remaining=s)
        return [], remain
    def dissect(self, pkt, s):
        _,x = self.m2i(pkt, s)
        return x
    def build(self, pkt):
        s = reduce(lambda x,y: x+y.build(pkt), self.seq, "")
        return self.i2m(pkt, s)

class ASN1F_SET(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_UNIVERSAL.SET

class ASN1F_SEQUENCE_OF(ASN1F_field):
    ASN1_tag = ASN1_Class_UNIVERSAL.SEQUENCE
    holds_packets = 1
    islist = 1
    def __init__(self, name, default, cls, context=None,
                 implicit_tag=None, explicit_tag=None):
        self.cls = cls
        ASN1F_field.__init__(self, name, None, context=context,
                        implicit_tag=implicit_tag, explicit_tag=explicit_tag)
        self.default = default
    def is_empty(self, pkt):
        return ASN1F_field.is_empty(self, pkt)
    def m2i(self, pkt, s):
        s = BER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                            implicit_tag=self.implicit_tag,
                            explicit_tag=self.explicit_tag,
                            safe=self.flexible_tag)
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        i,s,remain = codec.check_type_check_len(s)
        lst = []
        while s:
            c,s = self.extract_packet(self.cls, s)
            lst.append(c)
        if len(s) > 0:
            raise BER_Decoding_Error("unexpected remainder", remaining=s)
        return lst, remain
    def build(self, pkt):
        val = getattr(pkt, self.name)
        if isinstance(val, ASN1_Object) and val.tag==ASN1_Class_UNIVERSAL.RAW:
            s = val
        elif val is None:
            s = ""
        else:
            s = "".join(map(str, val))
        return self.i2m(pkt, s)

    def randval(self):
        return fuzz(self.asn1pkt())
    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)

class ASN1F_SET_OF(ASN1F_SEQUENCE_OF):
    ASN1_tag = ASN1_Class_UNIVERSAL.SET

class ASN1F_IPADDRESS(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.IPADDRESS    

class ASN1F_TIME_TICKS(ASN1F_INTEGER):
    ASN1_tag = ASN1_Class_UNIVERSAL.TIME_TICKS


#############################
#### Complex ASN1 Fields ####
#############################

class ASN1F_optional(ASN1F_element):
    def __init__(self, field, by_default=False):
        field.flexible_tag = False
        self._field = field
    def __getattr__(self, attr):
        return getattr(self._field, attr)
    def m2i(self, pkt, s):
        try:
            return self._field.m2i(pkt, s)
        except (ASN1_Error, ASN1F_badsequence, BER_Decoding_Error):
            # ASN1_Error may be raised by ASN1F_CHOICE
            return None, s
    def dissect(self, pkt, s):
        try:
            return self._field.dissect(pkt, s)
        except (ASN1_Error, ASN1F_badsequence, BER_Decoding_Error):
            self._field.set_val(pkt, None)
            return s
    def build(self, pkt):
        if self._field.is_empty(pkt):
            return ""
        return self._field.build(pkt)
    def any2i(self, pkt, x):
        return self._field.any2i(pkt, x)
    def i2repr(self, pkt, x):
        return self._field.i2repr(pkt, x)

class ASN1F_CHOICE(ASN1F_field):
    """
    Multiple types are allowed: ASN1_Packet, ASN1F_field and ASN1F_PACKET(),
    See layers/x509.py for examples.
    Other ASN1F_field instances than ASN1F_PACKET instances must not be used.
    """
    holds_packets = 1
    ASN1_tag = ASN1_Class_UNIVERSAL.ANY
    def __init__(self, name, default, *args, **kwargs):
        if "implicit_tag" in kwargs:
            err_msg = "ASN1F_CHOICE has been called with an implicit_tag"
            raise ASN1_Error(err_msg)
        self.implicit_tag = None
        for kwarg in ["context", "explicit_tag"]:
            if kwarg in kwargs:
                setattr(self, kwarg, kwargs[kwarg])
            else:
                setattr(self, kwarg, None)
        ASN1F_field.__init__(self, name, None, context=self.context,
                             explicit_tag=self.explicit_tag)
        self.default = default
        self.current_choice = None
        self.choices = {}
        self.pktchoices = {}
        for p in args:
            if hasattr(p, "ASN1_root"):     # should be ASN1_Packet
                if hasattr(p.ASN1_root, "choices"):
                    for k,v in p.ASN1_root.choices.iteritems():
                        self.choices[k] = v         # ASN1F_CHOICE recursion
                else:
                    self.choices[p.ASN1_root.network_tag] = p
            elif hasattr(p, "ASN1_tag"):
                if type(p) is type:         # should be ASN1F_field class
                    self.choices[p.ASN1_tag] = p
                else:                       # should be ASN1F_PACKET instance
                    self.choices[p.network_tag] = p
                    self.pktchoices[hash(p.cls)] = (p.implicit_tag, p.explicit_tag)
            else:
                raise ASN1_Error("ASN1F_CHOICE: no tag found for one field")
    def m2i(self, pkt, s):
        """
        First we have to retrieve the appropriate choice.
        Then we extract the field/packet, according to this choice.
        """
        if len(s) == 0:
            raise ASN1_Error("ASN1F_CHOICE: got empty string")
        s = BER_tagging_dec(s, hidden_tag=self.ASN1_tag,
                            explicit_tag=self.explicit_tag,
                            safe=self.flexible_tag)
        tag,_ = BER_id_dec(s)
        if tag not in self.choices:
            if self.flexible_tag:
                choice = ASN1F_field
            else:
                raise ASN1_Error("ASN1F_CHOICE: unexpected field")
        else:
            choice = self.choices[tag]
        if hasattr(choice, "ASN1_root"):
            return self.extract_packet(choice, s)
        else:
            if type(choice) is type:
                return choice(self.name, "").m2i(pkt, s)
            else:
                # choice must be an ASN1F_PACKET instance here
                return choice.m2i(pkt, s)
    def i2m(self, pkt, x):
        if x is None:
            s = ""
        else:
            s = str(x)
        if hash(type(x)) in self.pktchoices:
            imp, exp = self.pktchoices[hash(type(x))]
            s = BER_tagging_enc(s, implicit_tag=imp,
                                explicit_tag=exp)
        return BER_tagging_enc(s, explicit_tag=self.explicit_tag)
    def randval(self):
        return RandChoice(*(fuzz(x()) for x in self.choices.itervalues()))

class ASN1F_PACKET(ASN1F_field):
    holds_packets = 1
    def __init__(self, name, default, cls, context=None,
                 implicit_tag=None, explicit_tag=None):
        self.cls = cls
        ASN1F_field.__init__(self, name, None, context=context,
                        implicit_tag=implicit_tag, explicit_tag=explicit_tag)
        if cls.ASN1_root.ASN1_tag == ASN1_Class_UNIVERSAL.SEQUENCE:
            if implicit_tag is None and explicit_tag is None:
                self.network_tag = 16|0x20
        self.default = default
    def m2i(self, pkt, s):
        s = BER_tagging_dec(s, hidden_tag=self.cls.ASN1_root.ASN1_tag,
                            implicit_tag=self.implicit_tag,
                            explicit_tag=self.explicit_tag,
                            safe=self.flexible_tag)
        p,s = self.extract_packet(self.cls, s)
        return p,s
    def i2m(self, pkt, x):
        if x is None:
            s = ""
        else:
            s = str(x)
        return BER_tagging_enc(s, implicit_tag=self.implicit_tag,
                               explicit_tag=self.explicit_tag)

class ASN1F_BIT_STRING_ENCAPS(ASN1F_BIT_STRING):
    """
    We may emulate simple string encapsulation with explicit_tag=0x04,
    but we need a specific class for bit strings because of unused bits, etc.
    """
    holds_packets = 1
    def __init__(self, name, default, cls, context=None,
                 implicit_tag=None, explicit_tag=None):
        self.cls = cls
        ASN1F_BIT_STRING.__init__(self, name, None, context=context,
                                  implicit_tag=implicit_tag,
                                  explicit_tag=explicit_tag)
        self.default = default
    def m2i(self, pkt, s):
        bit_string, remain = ASN1F_BIT_STRING.m2i(self, pkt, s)
        if len(bit_string.val) % 8 != 0:
            raise BER_Decoding_Error("wrong bit string", remaining=s)
        p,s = self.extract_packet(self.cls, bit_string.val_readable)
        if len(s) > 0:
            raise BER_Decoding_Error("unexpected remainder", remaining=s)
        return p, remain
    def i2m(self, pkt, x):
        if x is None:
            s = ""
        else:
            s = str(x)
        s = "".join(binrepr(ord(x)).zfill(8) for x in s)
        return ASN1F_BIT_STRING.i2m(self, pkt, s)

class ASN1F_FLAGS(ASN1F_BIT_STRING):
    def __init__(self, name, default, mapping, context=None,
                 implicit_tag=None, explicit_tag=None):
        self.mapping = mapping
        ASN1F_BIT_STRING.__init__(self, name, default,
                                  default_readable=False,
                                  context=context,
                                  implicit_tag=implicit_tag,
                                  explicit_tag=explicit_tag)
    def get_flags(self, pkt):
        fbytes = getattr(pkt, self.name).val
        flags = []
        for i, positional in enumerate(fbytes):
            if positional == '1' and i < len(self.mapping):
                flags.append(self.mapping[i])
        return flags
    def i2repr(self, pkt, x):
        if x is not None:
            pretty_s = ", ".join(self.get_flags(pkt))
            return pretty_s + " " + repr(x)
        return repr(x)


# This import must come last to avoid problems with cyclic dependencies
import packet
