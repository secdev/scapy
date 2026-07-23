# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Octet Encoding Rules (OER) for ASN.1

Basic-OER as specified in ITU-T X.696 | ISO/IEC 8825-7.
"""

import struct

from scapy.error import warning
from scapy.compat import chb, orb, bytes_encode
from scapy.utils import binrepr, inet_aton, inet_ntoa
from scapy.asn1.ber import BER_num_dec, BER_num_enc
from scapy.asn1.asn1 import (
    ASN1Tag,
    ASN1_BADTAG,
    ASN1_BadTag_Decoding_Error,
    ASN1_Class,
    ASN1_Class_UNIVERSAL,
    ASN1_Codecs,
    ASN1_DECODING_ERROR,
    ASN1_Decoding_Error,
    ASN1_Encoding_Error,
    ASN1_Error,
    ASN1_Object,
    _ASN1_ERROR,
)

from typing import (
    Any,
    AnyStr,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

##################
#  OER encoding  #
##################


class OER_Exception(Exception):
    pass


class OER_Encoding_Error(ASN1_Encoding_Error):
    def __init__(self,
                 msg,  # type: str
                 encoded=None,  # type: Optional[Union['OERcodec_Object[Any]', str]]
                 remaining=b""  # type: bytes
                 ):
        # type: (...) -> None
        Exception.__init__(self, msg)
        self.remaining = remaining
        self.encoded = encoded

    def __str__(self):
        # type: () -> str
        s = Exception.__str__(self)
        if isinstance(self.encoded, ASN1_Object):
            s += "\n### Already encoded ###\n%s" % self.encoded.strshow()
        else:
            s += "\n### Already encoded ###\n%r" % self.encoded
        s += "\n### Remaining ###\n%r" % self.remaining
        return s


class OER_Decoding_Error(ASN1_Decoding_Error):
    def __init__(self,
                 msg,  # type: str
                 decoded=None,  # type: Optional[Any]
                 remaining=b""  # type: bytes
                 ):
        # type: (...) -> None
        Exception.__init__(self, msg)
        self.remaining = remaining
        self.decoded = decoded

    def __str__(self):
        # type: () -> str
        s = Exception.__str__(self)
        if isinstance(self.decoded, ASN1_Object):
            s += "\n### Already decoded ###\n%s" % self.decoded.strshow()
        else:
            s += "\n### Already decoded ###\n%r" % self.decoded
        s += "\n### Remaining ###\n%r" % self.remaining
        return s


class OER_BadTag_Decoding_Error(OER_Decoding_Error,
                                ASN1_BadTag_Decoding_Error):
    pass


# OER tag classes (bits 8-7 of the first identifier octet)
OER_CLASS_UNIVERSAL = 0x00
OER_CLASS_APPLICATION = 0x40
OER_CLASS_CONTEXT = 0x80
OER_CLASS_PRIVATE = 0xc0


def OER_len_enc(ll):
    # type: (int) -> bytes
    if ll < 128:
        return chb(ll)
    encoded = []
    value = ll
    while value > 0:
        encoded.insert(0, value & 0xff)
        value >>= 8
    if len(encoded) > 127:
        raise OER_Exception(
            "OER_len_enc: Length too long (%i) to be encoded" % len(encoded)
        )
    return chb(0x80 | len(encoded)) + bytes(encoded)


def OER_len_dec(s):
    # type: (bytes) -> Tuple[int, bytes]
    if not s:
        raise OER_Decoding_Error("OER_len_dec: got empty string", remaining=s)
    tmp_len = orb(s[0])
    if not tmp_len & 0x80:
        return tmp_len, s[1:]
    tmp_len &= 0x7f
    if len(s) <= tmp_len:
        raise OER_Decoding_Error(
            "OER_len_dec: Got %i bytes while expecting %i" %
            (len(s) - 1, tmp_len),
            remaining=s
        )
    ll = 0
    for c in s[1:tmp_len + 1]:
        ll <<= 8
        ll |= orb(c)
    return ll, s[tmp_len + 1:]


def OER_signed_integer_enc(i):
    # type: (int) -> bytes
    if i < 0:
        number_of_bits = i.bit_length()
        number_of_bytes = (number_of_bits + 7) // 8
        value = (1 << (8 * number_of_bytes)) + i
        if (value & (1 << (8 * number_of_bytes - 1))) == 0:
            value |= (0xff << (8 * number_of_bytes))
            number_of_bytes += 1
    elif i > 0:
        number_of_bits = i.bit_length()
        number_of_bytes = (number_of_bits + 7) // 8
        if number_of_bits == (8 * number_of_bytes):
            number_of_bytes += 1
        value = i
    else:
        number_of_bytes = 1
        value = 0
    return OER_len_enc(number_of_bytes) + value.to_bytes(number_of_bytes, "big")


def OER_signed_integer_dec(s):
    # type: (bytes) -> Tuple[int, bytes]
    number_of_bytes, s = OER_len_dec(s)
    if len(s) < number_of_bytes:
        raise OER_Decoding_Error(
            "OER_signed_integer_dec: Got %i bytes while expecting %i" %
            (len(s), number_of_bytes),
            remaining=s
        )
    value = int.from_bytes(s[:number_of_bytes], "big")
    number_of_bits = 8 * number_of_bytes
    if value & (1 << (number_of_bits - 1)):
        value -= (1 << number_of_bits) - 1
        value -= 1
    return value, s[number_of_bytes:]


def OER_unsigned_integer_enc(i):
    # type: (int) -> bytes
    number_of_bits = max(i.bit_length(), 1)
    number_of_bytes = (number_of_bits + 7) // 8
    return OER_len_enc(number_of_bytes) + i.to_bytes(number_of_bytes, "big")


def OER_unsigned_integer_dec(s):
    # type: (bytes) -> Tuple[int, bytes]
    number_of_bytes, s = OER_len_dec(s)
    if len(s) < number_of_bytes:
        raise OER_Decoding_Error(
            "OER_unsigned_integer_dec: Got %i bytes while expecting %i" %
            (len(s), number_of_bytes),
            remaining=s
        )
    value = int.from_bytes(s[:number_of_bytes], "big")
    return value, s[number_of_bytes:]


def OER_fixed_integer_enc(i, length, signed=True):
    # type: (int, int, bool) -> bytes
    fmt = {1: ">b", 2: ">h", 4: ">i", 8: ">q"} if signed else {
        1: ">B", 2: ">H", 4: ">I", 8: ">Q"
    }
    try:
        return struct.pack(fmt[length], i)
    except KeyError:
        raise OER_Encoding_Error(
            "OER_fixed_integer_enc: invalid length %i" % length
        )


def OER_fixed_integer_dec(s, length, signed=True):
    # type: (bytes, int, bool) -> Tuple[int, bytes]
    if len(s) < length:
        raise OER_Decoding_Error(
            "OER_fixed_integer_dec: Got %i bytes while expecting %i" %
            (len(s), length),
            remaining=s
        )
    fmt = {1: ">b", 2: ">h", 4: ">i", 8: ">q"} if signed else {
        1: ">B", 2: ">H", 4: ">I", 8: ">Q"
    }
    try:
        return struct.unpack(fmt[length], s[:length])[0], s[length:]
    except KeyError:
        raise OER_Decoding_Error(
            "OER_fixed_integer_dec: invalid length %i" % length,
            remaining=s
        )


def OER_enumerated_enc(i):
    # type: (int) -> bytes
    if 0 <= i <= 127:
        return chb(i)
    body = OER_signed_integer_enc(i)[1:]
    return chb(0x80 | len(body)) + body


def OER_enumerated_dec(s):
    # type: (bytes) -> Tuple[int, bytes]
    if not s:
        raise OER_Decoding_Error("OER_enumerated_dec: got empty string",
                                 remaining=s)
    first = orb(s[0])
    if not (first & 0x80):
        return first, s[1:]
    length = first & 0x7f
    if len(s) < length + 1:
        raise OER_Decoding_Error(
            "OER_enumerated_dec: Got %i bytes while expecting %i" %
            (len(s) - 1, length),
            remaining=s
        )
    value = int.from_bytes(s[1:length + 1], "big", signed=True)
    return value, s[length + 1:]


def OER_tag_enc(n, tag_class=OER_CLASS_CONTEXT):
    # type: (int, int) -> bytes
    if n < 63:
        return chb(tag_class | n)
    tag = bytearray([tag_class | 0x3f])
    encoded = []
    value = n
    while value > 0:
        encoded.append(0x80 | (value & 0x7f))
        value >>= 7
    encoded[0] &= 0x7f
    encoded.reverse()
    tag.extend(encoded)
    return bytes(tag)


def OER_tag_dec(s):
    # type: (bytes) -> Tuple[int, int, bytes]
    if not s:
        raise OER_Decoding_Error("OER_tag_dec: got empty string", remaining=s)
    first = orb(s[0])
    tag_class = first & 0xc0
    tag_number = first & 0x3f
    if tag_number != 0x3f:
        return tag_class, tag_number, s[1:]
    tag_number = 0
    i = 1
    while i < len(s):
        c = orb(s[i])
        tag_number <<= 7
        tag_number |= c & 0x7f
        i += 1
        if not (c & 0x80):
            break
    else:
        raise OER_Decoding_Error("OER_tag_dec: unfinished tag", remaining=s)
    return tag_class, tag_number, s[i:]


def OER_id_dec(s):
    # type: (bytes) -> Tuple[int, bytes]
    tag_class, tag_number, remainder = OER_tag_dec(s)
    return tag_class | tag_number, remainder


def OER_tagging_dec(s,  # type: bytes
                    hidden_tag=None,  # type: Optional[int | ASN1Tag]
                    implicit_tag=None,  # type: Optional[int]
                    explicit_tag=None,  # type: Optional[int]
                    safe=False,  # type: Optional[bool]
                    _fname="",  # type: str
                    ):
    # type: (...) -> Tuple[Optional[int], bytes]
    # OER does not use implicit tagging. Explicit tags are encoded as choice
    # alternatives (tag + value).
    real_tag = None
    if explicit_tag is not None and len(s) > 0:
        err_msg = (
            "OER_tagging_dec: observed tag 0x%.02x does not "
            "match expected tag 0x%.02x (%s)"
        )
        tag_class, tag_number, remainder = OER_tag_dec(s)
        observed = tag_class | tag_number
        if observed != explicit_tag:
            if not safe:
                raise OER_Decoding_Error(
                    err_msg % (observed, explicit_tag, _fname),
                    remaining=s)
            real_tag = observed
        s = remainder
    return real_tag, s


def OER_tagging_enc(s, implicit_tag=None, explicit_tag=None):
    # type: (bytes, Optional[int], Optional[int]) -> bytes
    if explicit_tag is not None:
        return OER_tag_enc(explicit_tag & 0x3f, explicit_tag & 0xc0) + s
    return s


class OERcodec_metaclass(type):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type['OERcodec_Object[Any]']
        c = cast('Type[OERcodec_Object[Any]]',
                 super(OERcodec_metaclass, cls).__new__(cls, name, bases, dct))
        try:
            c.tag.register(c.codec, c)
        except Exception:
            warning("Error registering %r for %r" % (c.tag, c.codec))
        return c


_K = TypeVar('_K')


class OERcodec_Object(Generic[_K], metaclass=OERcodec_metaclass):
    codec = ASN1_Codecs.OER
    tag = ASN1_Class_UNIVERSAL.ANY
    skip_tagging = False
    tagging_enc = staticmethod(OER_tagging_enc)
    tagging_dec = staticmethod(OER_tagging_dec)

    @classmethod
    def asn1_object(cls, val):
        # type: (_K) -> ASN1_Object[_K]
        return cls.tag.asn1_object(val)

    @classmethod
    def check_string(cls, s):
        # type: (bytes) -> None
        if not s:
            raise OER_Decoding_Error(
                "%s: Got empty object while expecting %r" %
                (cls.__name__, cls.tag), remaining=s
            )

    @classmethod
    def check_type(cls, s):
        # type: (bytes) -> bytes
        cls.check_string(s)
        return s

    @classmethod
    def check_type_get_len(cls, s):
        # type: (bytes) -> Tuple[int, bytes]
        cls.check_string(s)
        return len(s), s

    @classmethod
    def check_type_check_len(cls, s):
        # type: (bytes) -> Tuple[int, bytes, bytes]
        cls.check_string(s)
        return len(s), s, b""

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[Any], bytes]
        raise OER_Decoding_Error(
            "%s: Cannot decode unknown OER type without context" %
            cls.__name__, remaining=s
        )

    @classmethod
    def dec(cls,
            s,  # type: bytes
            context=None,  # type: Optional[Type[ASN1_Class]]
            safe=False,  # type: bool
            size_len=0,  # type: Optional[int]
            oer_unsigned=False,  # type: bool
            ):
        # type: (...) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]
        if not safe:
            return cls.do_dec(s, context, safe, size_len, oer_unsigned)
        try:
            return cls.do_dec(s, context, safe, size_len, oer_unsigned)
        except OER_BadTag_Decoding_Error as e:
            o, remain = OERcodec_Object.dec(
                e.remaining, context, safe, size_len, oer_unsigned
            )
            return ASN1_BADTAG(o), remain
        except OER_Decoding_Error as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""
        except ASN1_Error as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""

    @classmethod
    def safedec(cls,
                s,  # type: bytes
                context=None,  # type: Optional[Type[ASN1_Class]]
                size_len=0,  # type: Optional[int]
                oer_unsigned=False,  # type: bool
                ):
        # type: (...) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]
        return cls.dec(
            s, context, safe=True,
            size_len=size_len, oer_unsigned=oer_unsigned,
        )

    @classmethod
    def enc(cls, s, size_len=0):
        # type: (_K, Optional[int]) -> bytes
        if isinstance(s, (str, bytes)):
            return OERcodec_STRING.enc(s, size_len=size_len)
        else:
            try:
                return OERcodec_INTEGER.enc(int(s), size_len=size_len)  # type: ignore
            except TypeError:
                raise TypeError("Trying to encode an invalid value !")


ASN1_Codecs.OER.register_stem(OERcodec_Object)


##########################
#    OERcodec objects    #
##########################

class OERcodec_INTEGER(OERcodec_Object[int]):
    tag = ASN1_Class_UNIVERSAL.INTEGER

    @classmethod
    def enc(cls, i, size_len=0):
        # type: (int, Optional[int]) -> bytes
        if size_len in (1, 2, 4, 8):
            if i >= 0:
                if size_len == 1 and 0 <= i <= 255:
                    return OER_fixed_integer_enc(i, 1, signed=False)
                if size_len == 2 and 0 <= i <= 65535:
                    return OER_fixed_integer_enc(i, 2, signed=False)
                if size_len == 4 and 0 <= i <= 4294967295:
                    return OER_fixed_integer_enc(i, 4, signed=False)
                if size_len == 8 and 0 <= i <= 18446744073709551615:
                    return OER_fixed_integer_enc(i, 8, signed=False)
            return OER_fixed_integer_enc(i, size_len, signed=True)
        return OER_signed_integer_enc(i)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        if size_len in (1, 2, 4, 8):
            x, t = OER_fixed_integer_dec(
                s, size_len, signed=not oer_unsigned
            )
            return cls.asn1_object(x), t
        if oer_unsigned:
            x, t = OER_unsigned_integer_dec(s)
        else:
            x, t = OER_signed_integer_dec(s)
        return cls.asn1_object(x), t


class OERcodec_BOOLEAN(OERcodec_Object[int]):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN

    @classmethod
    def enc(cls, i, size_len=0):
        # type: (int, Optional[int]) -> bytes
        return chb(0xff if i else 0x00)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        cls.check_string(s)
        return cls.asn1_object(0 if orb(s[0]) == 0 else 1), s[1:]


class OERcodec_BIT_STRING(OERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[str], bytes]
        length, s = OER_len_dec(s)
        if length == 0:
            return cls.tag.asn1_object(""), s
        if len(s) < length:
            raise OER_Decoding_Error(
                "%s: Got %i bytes while expecting %i" % (cls.__name__, len(s), length),
                remaining=s
            )
        unused_bits = orb(s[0])
        if safe and unused_bits > 7:
            raise OER_Decoding_Error(
                "OERcodec_BIT_STRING: too many unused_bits advertised",
                remaining=s
            )
        fs = "".join(binrepr(orb(x)).zfill(8) for x in s[1:length])
        if unused_bits > 0:
            fs = fs[:-unused_bits]
        return cls.tag.asn1_object(fs), s[length:]

    @classmethod
    def enc(cls, _s, size_len=0):
        # type: (AnyStr, Optional[int]) -> bytes
        s = bytes_encode(_s)
        if len(s) % 8 == 0:
            unused_bits = 0
        else:
            unused_bits = 8 - len(s) % 8
            s += b"0" * unused_bits
        data = b"".join(chb(int(b"".join(chb(y) for y in x), 2))
                        for x in zip(*[iter(s)] * 8))
        body = chb(unused_bits) + data
        return OER_len_enc(len(body)) + body


class OERcodec_STRING(OERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.STRING

    @classmethod
    def enc(cls, _s, size_len=0):
        # type: (Union[str, bytes], Optional[int]) -> bytes
        s = bytes_encode(_s)
        if size_len and size_len == len(s):
            return s
        return OER_len_enc(len(s)) + s

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[Any], bytes]
        if size_len and size_len not in (1, 2, 4, 8):
            if len(s) < size_len:
                raise OER_Decoding_Error(
                    "%s: Got %i bytes while expecting %i" %
                    (cls.__name__, len(s), size_len),
                    remaining=s
                )
            return cls.tag.asn1_object(s[:size_len]), s[size_len:]
        length, s = OER_len_dec(s)
        if len(s) < length:
            raise OER_Decoding_Error(
                "%s: Got %i bytes while expecting %i" % (cls.__name__, len(s), length),
                remaining=s
            )
        return cls.tag.asn1_object(s[:length]), s[length:]


class OERcodec_NULL(OERcodec_Object[None]):
    tag = ASN1_Class_UNIVERSAL.NULL

    @classmethod
    def enc(cls, i, size_len=0):
        # type: (Any, Optional[int]) -> bytes
        return b""

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[None], bytes]
        return cls.asn1_object(None), s


class OERcodec_OID(OERcodec_Object[bytes]):
    tag = ASN1_Class_UNIVERSAL.OID

    @classmethod
    def enc(cls, _oid, size_len=0):
        # type: (AnyStr, Optional[int]) -> bytes
        oid = bytes_encode(_oid)
        if oid:
            lst = [int(x) for x in oid.strip(b".").split(b".")]
        else:
            lst = list()
        if len(lst) >= 2:
            lst[1] += 40 * lst[0]
            del lst[0]
        body = b"".join(BER_num_enc(k) for k in lst)
        return OER_len_enc(len(body)) + body

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[bytes], bytes]
        length, s = OER_len_dec(s)
        if len(s) < length:
            raise OER_Decoding_Error(
                "%s: Got %i bytes while expecting %i" % (cls.__name__, len(s), length),
                remaining=s
            )
        content, t = s[:length], s[length:]
        lst = []
        while content:
            val, content = BER_num_dec(content)
            lst.append(val)
        if len(lst) > 0:
            lst.insert(0, lst[0] // 40)
            lst[1] %= 40
        return (
            cls.asn1_object(b".".join(str(k).encode('ascii') for k in lst)),
            t,
        )


class OERcodec_ENUMERATED(OERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.ENUMERATED

    @classmethod
    def enc(cls, i, size_len=0):
        # type: (int, Optional[int]) -> bytes
        return OER_enumerated_enc(i)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        x, t = OER_enumerated_dec(s)
        return cls.asn1_object(x), t


class OERcodec_UTF8_STRING(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UTF8_STRING


class OERcodec_NUMERIC_STRING(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING


class OERcodec_PRINTABLE_STRING(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING


class OERcodec_T61_STRING(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING


class OERcodec_VIDEOTEX_STRING(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING


class OERcodec_IA5_STRING(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING


class OERcodec_GENERAL_STRING(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERAL_STRING


class OERcodec_UTC_TIME(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME


class OERcodec_GENERALIZED_TIME(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME


class OERcodec_ISO646_STRING(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.ISO646_STRING


class OERcodec_UNIVERSAL_STRING(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UNIVERSAL_STRING


class OERcodec_BMP_STRING(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.BMP_STRING


class OERcodec_SEQUENCE(OERcodec_Object[Union[bytes, List['OERcodec_Object[Any]']]]):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE

    @classmethod
    def enc(cls, _ll, size_len=0):
        # type: (Union[bytes, List[OERcodec_Object[Any]]], Optional[int]) -> bytes
        if isinstance(_ll, bytes):
            return _ll
        return b"".join(x.enc(cls.codec) for x in _ll)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[Union[bytes, List[Any]]], bytes]
        raise OER_Decoding_Error(
            "OERcodec_SEQUENCE: decoding requires schema-defined field order",
            remaining=s
        )


class OERcodec_SET(OERcodec_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET


class OERcodec_IPADDRESS(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IPADDRESS

    @classmethod
    def enc(cls, ipaddr_ascii, size_len=0):  # type: ignore
        # type: (str, Optional[int]) -> bytes
        try:
            s = inet_aton(ipaddr_ascii)
        except Exception:
            raise OER_Encoding_Error("IPv4 address could not be encoded")
        if size_len == len(s):
            return s
        return OER_len_enc(len(s)) + s

    @classmethod
    def do_dec(cls, s, context=None, safe=False,
               size_len=0, oer_unsigned=False):
        # type: (bytes, Optional[Any], bool, Optional[int], bool) -> Tuple[ASN1_Object[str], bytes]  # noqa: E501
        if size_len == 4:
            raw, remain = s[:4], s[4:]
        else:
            length, remain = OER_len_dec(s)
            if len(remain) < length:
                raise OER_Decoding_Error("IP address could not be decoded",
                                         remaining=s)
            raw, remain = remain[:length], remain[length:]
        try:
            ipaddr_ascii = inet_ntoa(raw)
        except Exception:
            raise OER_Decoding_Error("IP address could not be decoded",
                                     remaining=s)
        return cls.asn1_object(ipaddr_ascii), remain


class OERcodec_COUNTER32(OERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32


class OERcodec_COUNTER64(OERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER64


class OERcodec_GAUGE32(OERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.GAUGE32


class OERcodec_TIME_TICKS(OERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS
