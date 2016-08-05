## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## Modified by Maxence Tury <maxence.tury@ssi.gouv.fr>
## Acknowledgment: Ralph Broenink
## This program is published under a GPLv2 license

"""
Basic Encoding Rules (BER) for ASN.1
"""

from scapy.error import warning
from scapy.utils import binrepr,inet_aton,inet_ntoa
from scapy.asn1.asn1 import ASN1_Decoding_Error,ASN1_Encoding_Error,ASN1_BadTag_Decoding_Error,ASN1_Codecs,ASN1_Class_UNIVERSAL,ASN1_Error,ASN1_DECODING_ERROR,ASN1_BADTAG

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
def BER_num_dec(s, cls_id=0):
        x = cls_id
        for i, c in enumerate(s):
            c = ord(c)
            x <<= 7
            x |= c&0x7f
            if not c&0x80:
                break
        if c&0x80:
            raise BER_Decoding_Error("BER_num_dec: unfinished number description", remaining=s)
        return x, s[i+1:]

def BER_id_dec(s):
    # This returns the tag ALONG WITH THE PADDED CLASS+CONSTRUCTIVE INFO.
    # Let's recall that bits 8-7 from the first byte of the tag encode
    # the class information, while bit 6 means primitive or constructive.
    # For instance, with low-tag-number '\x81', class would be 0b10
    # ('context-specific') and tag 0x01, but we return 0x81 as a whole.
    # For '\xff\x02', class would be 0b11 ('private'), constructed, then
    # padding, then tag 0x02, but we return (0xff>>5)*128^1 + 0x02*128^0.
    # Why the 5-bit-shifting? Because it provides an unequivocal encoding
    # on base 128 (note that 0xff would equal 1*128^1 + 127*128^0...),
    # as we know that bits 5 to 1 are fixed to 1 anyway.
    # As long as there is no class differentiation, we have to keep this info
    # encoded in scapy's tag in order to reuse it for packet building.
    # Note that tags thus may have to be hard-coded with their extended
    # information, e.g. a SEQUENCE from asn1.py has a direct tag 0x20|16.
        x = ord(s[0])
        if x & 0x1f != 0x1f:
            # low-tag-number
            return x,s[1:]
        else:
            # high-tag-number
            return BER_num_dec(s[1:], cls_id=x>>5)
def BER_id_enc(n):
        if n < 256:
            # low-tag-number
            return chr(n)
        else:
            # high-tag-number
            s = BER_num_enc(n)
            tag = ord(s[0])             # first byte, as an int
            tag &= 0x07                 # reset every bit from 8 to 4
            tag <<= 5                   # move back the info bits on top
            tag |= 0x1f                 # pad with 1s every bit from 5 to 1
            return chr(tag) + s[1:]

# The functions below provide implicit and explicit tagging support.
def BER_tagging_dec(s, hidden_tag=None, implicit_tag=None,
                    explicit_tag=None, safe=False):
    # We output the 'real_tag' if it is different from the (im|ex)plicit_tag.
    real_tag = None
    if len(s) > 0:
        err_msg = "BER_tagging_dec: observed tag does not match expected tag"
        if implicit_tag is not None:
            ber_id,s = BER_id_dec(s)
            if ber_id != implicit_tag:
                if not safe:
                    raise BER_Decoding_Error(err_msg, remaining=s)
                else:
                    real_tag = ber_id
            s = chr(hidden_tag) + s
        elif explicit_tag is not None:
            ber_id,s = BER_id_dec(s)
            if ber_id != explicit_tag:
                if not safe:
                    raise BER_Decoding_Error(err_msg, remaining=s)
                else:
                    real_tag = ber_id
            l,s = BER_len_dec(s)
    return real_tag, s
def BER_tagging_enc(s, implicit_tag=None, explicit_tag=None):
    if len(s) > 0:
        if implicit_tag is not None:
            s = BER_id_enc(implicit_tag) + s[1:]
        elif explicit_tag is not None:
            s = BER_id_enc(explicit_tag) + BER_len_enc(len(s)) + s
    return s

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
        tag, remainder = BER_id_dec(s)
        if cls.tag != tag:
            raise BER_BadTag_Decoding_Error("%s: Got tag [%i/%#x] while expecting %r" %
                                            (cls.__name__, tag, tag, cls.tag), remaining=s)
        return remainder
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
        p,_ = BER_id_dec(s)
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


##########################
#### BERcodec objects ####
##########################

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

class BERcodec_BIT_STRING(BERcodec_Object):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING
    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        # /!\ the unused_bits information is lost after this decoding
        l,s,t = cls.check_type_check_len(s)
        if len(s) > 0:
            unused_bits = ord(s[0])
            if safe and unused_bits > 7:
                raise BER_Decoding_Error("BERcodec_BIT_STRING: too many unused_bits advertised", remaining=s)
            s = "".join(binrepr(ord(x)).zfill(8) for x in s[1:])
            if unused_bits > 0:
                s = s[:-unused_bits]
            return cls.tag.asn1_object(s),t
        else:
            raise BER_Decoding_Error("BERcodec_BIT_STRING found no content (not even unused_bits byte)", remaining=s)
    @classmethod
    def enc(cls,s):
        # /!\ this is DER encoding (bit strings are only zero-bit padded)
        if len(s) % 8 == 0:
            unused_bits = 0
        else:
            unused_bits = 8 - len(s)%8
            s += "0"*unused_bits
        s = "".join(chr(int("".join(x),2)) for x in zip(*[iter(s)]*8))
        s = chr(unused_bits) + s
        return chr(cls.tag)+BER_len_enc(len(s))+s

class BERcodec_STRING(BERcodec_Object):
    tag = ASN1_Class_UNIVERSAL.STRING
    @classmethod
    def enc(cls,s):
        return chr(cls.tag)+BER_len_enc(len(s))+s
    @classmethod
    def do_dec(cls, s, context=None, safe=False):
        l,s,t = cls.check_type_check_len(s)
        return cls.tag.asn1_object(s),t

class BERcodec_NULL(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.NULL
    @classmethod
    def enc(cls, i):
        if i == 0:
            return chr(cls.tag)+"\0"
        else:
            return super(cls,cls).enc(i)

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

class BERcodec_ENUMERATED(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.ENUMERATED

class BERcodec_UTF8_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UTF8_STRING

class BERcodec_PRINTABLE_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING

class BERcodec_T61_STRING (BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING

class BERcodec_IA5_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING

class BERcodec_UTC_TIME(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME

class BERcodec_GENERALIZED_TIME(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME

class BERcodec_ISO646_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.ISO646_STRING

class BERcodec_UNIVERSAL_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UNIVERSAL_STRING

class BERcodec_BMP_STRING (BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.BMP_STRING

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

class BERcodec_COUNTER32(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32

class BERcodec_TIME_TICKS(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS



