## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from scapy.error import warning
from scapy.utils import inet_aton,inet_ntoa
from asn1 import ASN1_Decoding_Error,ASN1_Encoding_Error,ASN1_BadTag_Decoding_Error,ASN1_Codecs,ASN1_Class_UNIVERSAL,ASN1_Error,ASN1_DECODING_ERROR,ASN1_BADTAG

##################
## BER encoding ##
##################



#####[ BER tools ]#####


class BER_Exception(Exception):
    pass

class BER_Encoding_Error(ASN1_Encoding_Error):
    def __init__(self, msg, encoded=None, remaining=None):
        Exception.__init__(self, msg)
        self.remaining = remaining
        self.encoded = encoded
    def __str__(self):
        s = Exception.__str__(self)
        if isinstance(self.encoded, BERcodec_Object):
            s+="\n### Already encoded ###\n%s" % self.encoded.strshow()
        else:
            s+="\n### Already encoded ###\n%r" % self.encoded
        s+="\n### Remaining ###\n%r" % self.remaining
        return s

class BER_Decoding_Error(ASN1_Decoding_Error):
    def __init__(self, msg, decoded=None, remaining=None):
        Exception.__init__(self, msg)
        self.remaining = remaining
        self.decoded = decoded
    def __str__(self):
        s = Exception.__str__(self)
        if isinstance(self.decoded, BERcodec_Object):
            s+="\n### Already decoded ###\n%s" % self.decoded.strshow()
        else:
            s+="\n### Already decoded ###\n%r" % self.decoded
        s+="\n### Remaining ###\n%r" % self.remaining
        return s

class BER_BadTag_Decoding_Error(BER_Decoding_Error, ASN1_BadTag_Decoding_Error):
    pass

def BER_len_enc(l, size=0):
        if l <= 127 and size==0:
            return chr(l)
        s = ""
        while l or size>0:
            s = chr(l&0xff)+s
            l >>= 8L
            size -= 1
        if len(s) > 127:
            raise BER_Exception("BER_len_enc: Length too long (%i) to be encoded [%r]" % (len(s),s))
        return chr(len(s)|0x80)+s
def BER_len_dec(s):
        l = ord(s[0])
        if not l & 0x80:
            return l,s[1:]
        l &= 0x7f
        if len(s) <= l:
            raise BER_Decoding_Error("BER_len_dec: Got %i bytes while expecting %i" % (len(s)-1, l),remaining=s)
        ll = 0L
        for c in s[1:l+1]:
            ll <<= 8L
            ll |= ord(c)
        return ll,s[l+1:]
        
def BER_num_enc(l, size=1):
        x=[]
        while l or size>0:
            x.insert(0, l & 0x7f)
            if len(x) > 1:
                x[0] |= 0x80
            l >>= 7
            size -= 1
        return "".join([chr(k) for k in x])
def BER_num_dec(s):
        x = 0
        for i in range(len(s)):
            c = ord(s[i])
            x <<= 7
            x |= c&0x7f
            if not c&0x80:
                break
        if c&0x80:
            raise BER_Decoding_Error("BER_num_dec: unfinished number description", remaining=s)
        return x, s[i+1:]

#####[ BER classes ]#####

class BERcodec_metaclass(type):
    def __new__(cls, name, bases, dct):
        c = super(BERcodec_metaclass, cls).__new__(cls, name, bases, dct)
        try:
            c.tag.register(c.codec, c)
        except:
            warning("Error registering %r for %r" % (c.tag, c.codec))
        return c


class BERcodec_Object:
    __metaclass__ = BERcodec_metaclass
    codec = ASN1_Codecs.BER
    tag = ASN1_Class_UNIVERSAL.ANY

    @classmethod
    def asn1_object(cls, val):
        return cls.tag.asn1_object(val)

    @classmethod
    def check_string(cls, s):
        if not s:
            raise BER_Decoding_Error("%s: Got empty object while expecting tag %r" %
                                     (cls.__name__,cls.tag), remaining=s)        
    @classmethod
    def check_type(cls, s):
        cls.check_string(s)
        if cls.tag != ord(s[0]):
            raise BER_BadTag_Decoding_Error("%s: Got tag [%i/%#x] while expecting %r" %
                                            (cls.__name__, ord(s[0]), ord(s[0]),cls.tag), remaining=s)
        return s[1:]
    @classmethod
    def check_type_get_len(cls, s):
        s2 = cls.check_type(s)
        if not s2:
            raise BER_Decoding_Error("%s: No bytes while expecting a length" %
                                     cls.__name__, remaining=s)
        return BER_len_dec(s2)
    @classmethod
    def check_type_check_len(cls, s):
        l,s3 = cls.check_type_get_len(s)
        if len(s3) < l:
            raise BER_Decoding_Error("%s: Got %i bytes while expecting %i" %
                                     (cls.__name__, len(s3), l), remaining=s)
        return l,s3[:l],s3[l:]

    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        if context is None:
            context = cls.tag.context
        cls.check_string(s)
        p = ord(s[0])
        if p not in context:
            t = s
            if len(t) > 18:
                t = t[:15]+"..."
            raise BER_Decoding_Error("Unknown prefix [%02x] for [%r]" % (p,t), remaining=s)
        codec = context[p].get_codec(ASN1_Codecs.BER)
        return codec.dec(s,context,safe)

    @classmethod
    def dec(cls, s, context=None, safe=False):
        if not safe:
            return cls.do_dec(s, context, safe)
        try:
            return cls.do_dec(s, context, safe)
        except BER_BadTag_Decoding_Error,e:
            o,remain = BERcodec_Object.dec(e.remaining, context, safe)
            return ASN1_BADTAG(o),remain
        except BER_Decoding_Error, e:
            return ASN1_DECODING_ERROR(s, exc=e),""
        except ASN1_Error, e:
            return ASN1_DECODING_ERROR(s, exc=e),""

    @classmethod
    def safedec(cls, s, context=None):
        return cls.dec(s, context, safe=True)


    @classmethod
    def enc(cls, s):
        if type(s) is str:
            return BERcodec_STRING.enc(s)
        else:
            return BERcodec_INTEGER.enc(int(s))

            

ASN1_Codecs.BER.register_stem(BERcodec_Object)


class BERcodec_INTEGER(BERcodec_Object):
    tag = ASN1_Class_UNIVERSAL.INTEGER
    @classmethod
    def enc(cls, i):
        s = []
        while 1:
            s.append(i&0xff)
            if -127 <= i < 0:
                break
            if 128 <= i <= 255:
                s.append(0)
            i >>= 8
            if not i:
                break
        s = map(chr, s)
        s.append(BER_len_enc(len(s)))
        s.append(chr(cls.tag))
        s.reverse()
        return "".join(s)
    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        l,s,t = cls.check_type_check_len(s)
        x = 0L
        if s:
            if ord(s[0])&0x80: # negative int
                x = -1L
            for c in s:
                x <<= 8
                x |= ord(c)
        return cls.asn1_object(x),t
    

class BERcodec_BOOLEAN(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN

class BERcodec_ENUMERATED(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.ENUMERATED

class BERcodec_NULL(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.NULL
    @classmethod
    def enc(cls, i):
        if i == 0:
            return chr(cls.tag)+"\0"
        else:
            return BERcodec_INTEGER.enc(i)

class BERcodec_SEP(BERcodec_NULL):
    tag = ASN1_Class_UNIVERSAL.SEP

class BERcodec_STRING(BERcodec_Object):
    tag = ASN1_Class_UNIVERSAL.STRING
    @classmethod
    def enc(cls,s):
        return chr(cls.tag)+BER_len_enc(len(s))+s
    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        l,s,t = cls.check_type_check_len(s)
        return cls.tag.asn1_object(s),t

class BERcodec_BIT_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

class BERcodec_PRINTABLE_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING

class BERcodec_T61_STRING (BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING

class BERcodec_IA5_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING

class BERcodec_NUMERIC_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING

class BERcodec_VIDEOTEX_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING

class BERcodec_IPADDRESS(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IPADDRESS
    
    @classmethod
    def enc(cls, ipaddr_ascii):
        try:
            s = inet_aton(ipaddr_ascii)
        except Exception:
            raise BER_Encoding_Error("IPv4 address could not be encoded") 
        return chr(cls.tag)+BER_len_enc(len(s))+s
    
    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        l,s,t = cls.check_type_check_len(s)
        try:
            ipaddr_ascii = inet_ntoa(s)
        except Exception:
            raise BER_Decoding_Error("IP address could not be decoded", decoded=obj)
        return cls.asn1_object(ipaddr_ascii), t

class BERcodec_UTC_TIME(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME

class BERcodec_GENERALIZED_TIME(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME

class BERcodec_TIME_TICKS(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS

class BERcodec_GAUGE32(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.GAUGE32

class BERcodec_COUNTER32(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32

class BERcodec_SEQUENCE(BERcodec_Object):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE
    @classmethod
    def enc(cls, l):
        if type(l) is not str:
            l = "".join(map(lambda x: x.enc(cls.codec), l))
        return chr(cls.tag)+BER_len_enc(len(l))+l
    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        if context is None:
            context = cls.tag.context
        l,st = cls.check_type_get_len(s) # we may have len(s) < l
        s,t = st[:l],st[l:]
        obj = []
        while s:
            try:
                o,s = BERcodec_Object.dec(s, context, safe)
            except BER_Decoding_Error, err:
                err.remaining += t
                if err.decoded is not None:
                    obj.append(err.decoded)
                err.decoded = obj
                raise 
            obj.append(o)
        if len(st) < l:
            raise BER_Decoding_Error("Not enough bytes to decode sequence", decoded=obj)
        return cls.asn1_object(obj),t

class BERcodec_SET(BERcodec_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET


class BERcodec_OID(BERcodec_Object):
    tag = ASN1_Class_UNIVERSAL.OID

    @classmethod
    def enc(cls, oid):
        lst = [int(x) for x in oid.strip(".").split(".")]
        if len(lst) >= 2:
            lst[1] += 40*lst[0]
            del(lst[0])
        s = "".join([BER_num_enc(k) for k in lst])
        return chr(cls.tag)+BER_len_enc(len(s))+s
    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        l,s,t = cls.check_type_check_len(s)
        lst = []
        while s:
            l,s = BER_num_dec(s)
            lst.append(l)
        if (len(lst) > 0):
            lst.insert(0,lst[0]/40)
            lst[1] %= 40
        return cls.asn1_object(".".join([str(k) for k in lst])), t


