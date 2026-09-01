# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = ASN.1 Octet Encoding Rules (OER)
# scapy.contrib.status = loads

"""
Octet Encoding Rules (OER) for ASN.1

Basic-OER as specified in ITU-T X.696 | ISO/IEC 8825-7.

``ASN1F_SEQUENCE`` emits the preamble required by 16.2.2: a presence bit per
``ASN1F_optional``/``ASN1F_DEFAULT`` component, preceded by an extension bit
for sequences declared with ``oer_extensible=True``. Fixed size constraints
are expressed with ``size_len=`` (octets for strings, bits for BIT STRING).

Tags declared on a field are not encoded: OER only puts a tag on the wire for
the chosen alternative of an ``ASN1F_CHOICE`` (20.2), so the ``implicit_tag=``
and ``explicit_tag=`` of the alternatives are what selects it.

Not supported yet: extension additions (an encoding that carries them is
refused rather than misparsed), SET, REAL, and the canonical variant (C-OER).
"""

import struct

from scapy.error import warning
from scapy.compat import chb, orb, bytes_encode
from scapy.utils import binrepr, inet_aton, inet_ntoa
from scapy.asn1.tag import asn1_tag_parts
from scapy.asn1.ber import BER_num_dec, BER_num_enc
from scapy.asn1.asn1 import (
    ASN1Codec_metaclass,
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
# DEFAULT components are described by the sequence preamble in OER/PER.

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
    codec_label = "OER"


class OER_Decoding_Error(ASN1_Decoding_Error):
    codec_label = "OER"


# OER tag classes (bits 8-7 of the first identifier octet)
OER_CLASS_UNIVERSAL = 0x00
OER_CLASS_APPLICATION = 0x40
OER_CLASS_CONTEXT = 0x80
OER_CLASS_PRIVATE = 0xc0


def _OER_check_len(name, s, number_of_bytes, offset=0):
    # type: (str, bytes, int, int) -> None
    """Raise unless s carries number_of_bytes octets past its first offset."""
    available = len(s) - offset
    if available < number_of_bytes:
        raise OER_Decoding_Error(
            "%s: Got %i bytes while expecting %i" %
            (name, available, number_of_bytes),
            remaining=s
        )


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
    _OER_check_len("OER_len_dec", s, tmp_len, offset=1)
    ll = 0
    for c in s[1:tmp_len + 1]:
        ll <<= 8
        ll |= orb(c)
    return ll, s[tmp_len + 1:]


def OER_signed_integer_enc(i):
    # type: (int) -> bytes
    # X.696 10.4: the shortest two's complement encoding. A negative value
    # needs one bit less than its magnitude suggests, as -2**(8n-1) still
    # fits in n octets, hence the increment before measuring.
    magnitude = i + 1 if i < 0 else i
    number_of_bytes = (magnitude.bit_length() + 8) // 8
    value = i & ((1 << (8 * number_of_bytes)) - 1)
    return OER_len_enc(number_of_bytes) + value.to_bytes(number_of_bytes, "big")


def OER_signed_integer_dec(s):
    # type: (bytes) -> Tuple[int, bytes]
    number_of_bytes, s = OER_len_dec(s)
    _OER_check_len("OER_signed_integer_dec", s, number_of_bytes)
    if number_of_bytes == 0:
        raise OER_Decoding_Error(
            "OER_signed_integer_dec: got an empty length determinant",
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
    if i < 0:
        raise OER_Encoding_Error(
            "OER_unsigned_integer_enc: %i is negative" % i
        )
    number_of_bits = max(i.bit_length(), 1)
    number_of_bytes = (number_of_bits + 7) // 8
    return OER_len_enc(number_of_bytes) + i.to_bytes(number_of_bytes, "big")


def OER_unsigned_integer_dec(s):
    # type: (bytes) -> Tuple[int, bytes]
    number_of_bytes, s = OER_len_dec(s)
    _OER_check_len("OER_unsigned_integer_dec", s, number_of_bytes)
    value = int.from_bytes(s[:number_of_bytes], "big")
    return value, s[number_of_bytes:]


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


def OER_tag_parts(identifier):
    # type: (int) -> Tuple[int, int]
    # X.696 8.7 only keeps the class and the number, so the constructed flag
    # must not leak into the encoded tag number.
    tag_class, tag_number, _constructed = asn1_tag_parts(identifier)
    return tag_class, tag_number


class OERcodec_metaclass(ASN1Codec_metaclass):
    pass


_K = TypeVar('_K')


class OERcodec_Object(Generic[_K], metaclass=OERcodec_metaclass):
    codec = ASN1_Codecs.OER
    tag = ASN1_Class_UNIVERSAL.ANY

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
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               **_kwargs  # type: Any
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
            field=None,  # type: Any
            pkt=None,  # type: Any
            size_len=None,  # type: Optional[int]
            oer_unsigned=None,  # type: Optional[bool]
            **_kwargs  # type: Any
            ):
        # type: (...) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]
        call_kw = dict(_kwargs)
        if field is not None:
            call_kw["field"] = field
        if pkt is not None:
            call_kw["pkt"] = pkt
        if size_len is not None:
            call_kw["size_len"] = size_len
        if oer_unsigned is not None:
            call_kw["oer_unsigned"] = oer_unsigned
        if not safe:
            return cls.do_dec(
                s, context=context, safe=safe, **call_kw,
            )
        try:
            return cls.do_dec(
                s, context=context, safe=safe, **call_kw,
            )
        except OER_Decoding_Error as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""
        except ASN1_Error as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""

    @classmethod
    def safedec(cls,
                s,  # type: bytes
                context=None,  # type: Optional[Type[ASN1_Class]]
                field=None,  # type: Any
                pkt=None,  # type: Any
                size_len=None,  # type: Optional[int]
                oer_unsigned=None,  # type: Optional[bool]
                **_kwargs  # type: Any
                ):
        # type: (...) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]
        return cls.dec(
            s, context, safe=True,
            field=field, pkt=pkt,
            size_len=size_len, oer_unsigned=oer_unsigned,
            **_kwargs,
        )

    @classmethod
    def enc(cls, s, size_len=0, **_kwargs):
        # type: (_K, Optional[int], **Any) -> bytes
        if isinstance(s, (str, bytes)):
            return OERcodec_STRING.enc(s, size_len=size_len)
        else:
            try:
                return OERcodec_INTEGER.enc(int(s), size_len=size_len)  # type: ignore
            except TypeError:
                raise TypeError("Trying to encode an invalid value !")


# No tagging hook: X.696 encodes no tag for a component, whatever the tagging
# environment of the module, so a field is left alone. The only tag on the
# wire is the one of a chosen CHOICE alternative, which the CHOICE hooks below
# write themselves.
ASN1_Codecs.OER.register_stem(OERcodec_Object)


##########################
#    OERcodec objects    #
##########################

class OERcodec_INTEGER(OERcodec_Object[int]):
    tag = ASN1_Class_UNIVERSAL.INTEGER

    _FIXED_FORMATS = {
        True: {1: ">b", 2: ">h", 4: ">i", 8: ">q"},
        False: {1: ">B", 2: ">H", 4: ">I", 8: ">Q"},
    }

    @classmethod
    def enc(cls, i, field=None, size_len=None, oer_unsigned=None, **_kwargs):
        # type: (int, Any, Optional[int], Optional[bool], **Any) -> bytes
        from scapy.asn1.constraints import oer_size_len, oer_unsigned as _oer_unsigned
        size_len = oer_size_len(field, size_len)
        oer_unsigned = _oer_unsigned(field, oer_unsigned)
        if oer_unsigned and i < 0:
            raise OER_Encoding_Error(
                "%s: %i is negative for an unsigned type" % (cls.__name__, i)
            )
        # X.696 10: the width and the signedness follow the declared bounds of
        # the type, never the value at hand, otherwise the decoder (which only
        # knows the type) reads something else back.
        if size_len in (1, 2, 4, 8):
            signed = not oer_unsigned
            try:
                return struct.pack(cls._FIXED_FORMATS[signed][size_len], i)
            except struct.error:
                raise OER_Encoding_Error(
                    "%s: %i does not fit in %i %s octet(s)" %
                    (cls.__name__, i, size_len,
                     "signed" if signed else "unsigned")
                )
        if oer_unsigned:
            return OER_unsigned_integer_enc(i)
        return OER_signed_integer_enc(i)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               field=None,  # type: Any
               size_len=None,  # type: Optional[int]
               oer_unsigned=None,  # type: Optional[bool]
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        from scapy.asn1.constraints import oer_size_len, oer_unsigned as _oer_unsigned
        size_len = oer_size_len(field, size_len)
        oer_unsigned = _oer_unsigned(field, oer_unsigned)
        if size_len in (1, 2, 4, 8):
            _OER_check_len(cls.__name__, s, size_len)
            x = struct.unpack(
                cls._FIXED_FORMATS[not oer_unsigned][size_len], s[:size_len]
            )[0]
            return cls.asn1_object(x), s[size_len:]
        if oer_unsigned:
            x, t = OER_unsigned_integer_dec(s)
        else:
            x, t = OER_signed_integer_dec(s)
        return cls.asn1_object(x), t


class OERcodec_BOOLEAN(OERcodec_Object[int]):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN

    @classmethod
    def enc(cls, i, **_kwargs):
        # type: (int, **Any) -> bytes
        return chb(0xff if i else 0x00)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        cls.check_string(s)
        return cls.asn1_object(0 if orb(s[0]) == 0 else 1), s[1:]


def _oer_bitstr_to_bytes(bitstr):
    # type: (bytes) -> bytes
    padded = bitstr + b"0" * (-len(bitstr) % 8)
    return bytes([int(padded[i:i + 8], 2) for i in range(0, len(padded), 8)])


def _oer_bytes_to_bitstr(data):
    # type: (bytes) -> str
    return "".join(binrepr(orb(x)).zfill(8) for x in data)


class OERcodec_BIT_STRING(OERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               field=None,  # type: Any
               size_len=None,  # type: Optional[int]
               oer_unsigned=None,  # type: Optional[bool]
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[str], bytes]
        from scapy.asn1.constraints import oer_size_len
        size_len = oer_size_len(field, size_len)
        if size_len:
            number_of_bytes = (size_len + 7) // 8
            _OER_check_len(cls.__name__, s, number_of_bytes)
            return (
                cls.tag.asn1_object(
                    _oer_bytes_to_bitstr(s[:number_of_bytes])[:size_len]
                ),
                s[number_of_bytes:],
            )
        length, s = OER_len_dec(s)
        if length == 0:
            return cls.tag.asn1_object(""), s
        _OER_check_len(cls.__name__, s, length)
        unused_bits = orb(s[0])
        if safe and unused_bits > 7:
            raise OER_Decoding_Error(
                "OERcodec_BIT_STRING: too many unused_bits advertised",
                remaining=s
            )
        fs = _oer_bytes_to_bitstr(s[1:length])
        if unused_bits > 0:
            fs = fs[:-unused_bits]
        return cls.tag.asn1_object(fs), s[length:]

    @classmethod
    def enc(cls, _s, field=None, size_len=None, **_kwargs):
        # type: (AnyStr, Any, Optional[int], **Any) -> bytes
        from scapy.asn1.constraints import oer_size_len
        size_len = oer_size_len(field, size_len)
        s = bytes_encode(_s)
        if size_len:
            # X.696 13.3: a fixed size means the bits are written padded to a
            # whole number of octets, without length or unused-bit count.
            if len(s) != size_len:
                raise OER_Encoding_Error(
                    "%s: got %i bits while expecting %i" %
                    (cls.__name__, len(s), size_len),
                    encoded=_s
                )
            return _oer_bitstr_to_bytes(s)
        body = chb(-len(s) % 8) + _oer_bitstr_to_bytes(s)
        return OER_len_enc(len(body)) + body


class OERcodec_STRING(OERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.STRING

    @classmethod
    def enc(cls, _s, field=None, size_len=None, **_kwargs):
        # type: (Union[str, bytes], Any, Optional[int], **Any) -> bytes
        from scapy.asn1.constraints import oer_size_len
        size_len = oer_size_len(field, size_len)
        s = bytes_encode(_s)
        if size_len:
            # X.696 16.1: a fixed size means no length determinant.
            if len(s) != size_len:
                raise OER_Encoding_Error(
                    "%s: got %i bytes while expecting %i" %
                    (cls.__name__, len(s), size_len),
                    encoded=_s
                )
            return s
        return OER_len_enc(len(s)) + s

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               field=None,  # type: Any
               size_len=None,  # type: Optional[int]
               oer_unsigned=None,  # type: Optional[bool]
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[Any], bytes]
        from scapy.asn1.constraints import oer_size_len
        size_len = oer_size_len(field, size_len)
        if size_len:
            _OER_check_len(cls.__name__, s, size_len)
            return cls.tag.asn1_object(s[:size_len]), s[size_len:]
        length, s = OER_len_dec(s)
        _OER_check_len(cls.__name__, s, length)
        return cls.tag.asn1_object(s[:length]), s[length:]


class OERcodec_NULL(OERcodec_Object[None]):
    tag = ASN1_Class_UNIVERSAL.NULL

    @classmethod
    def enc(cls, i, **_kwargs):
        # type: (Any, **Any) -> bytes
        return b""

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[None], bytes]
        return cls.asn1_object(None), s


class OERcodec_OID(OERcodec_Object[bytes]):
    tag = ASN1_Class_UNIVERSAL.OID

    @classmethod
    def enc(cls, _oid, **_kwargs):
        # type: (AnyStr, **Any) -> bytes
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
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[bytes], bytes]
        length, s = OER_len_dec(s)
        _OER_check_len(cls.__name__, s, length)
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
    def enc(cls, i, **_kwargs):
        # type: (int, **Any) -> bytes
        if 0 <= i <= 127:
            return chb(i)
        body = OER_signed_integer_enc(i)[1:]
        return chb(0x80 | len(body)) + body

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        if not s:
            raise OER_Decoding_Error(
                "%s: got empty string" % cls.__name__, remaining=s
            )
        first = orb(s[0])
        if not (first & 0x80):
            return cls.asn1_object(first), s[1:]
        length = first & 0x7f
        _OER_check_len(cls.__name__, s, length, offset=1)
        value = int.from_bytes(s[1:length + 1], "big", signed=True)
        return cls.asn1_object(value), s[length + 1:]


_OER_STRING_TAGS = (
    "UTF8_STRING",
    "NUMERIC_STRING",
    "PRINTABLE_STRING",
    "T61_STRING",
    "VIDEOTEX_STRING",
    "IA5_STRING",
    "GENERAL_STRING",
    "UTC_TIME",
    "GENERALIZED_TIME",
    "ISO646_STRING",
    "UNIVERSAL_STRING",
    "BMP_STRING",
)


def _oer_string_codec(name):
    # type: (str) -> type
    return type(
        "OERcodec_%s" % name,
        (OERcodec_STRING,),
        {"tag": getattr(ASN1_Class_UNIVERSAL, name)},
    )


for _tag_name in _OER_STRING_TAGS:
    globals()["OERcodec_%s" % _tag_name] = _oer_string_codec(_tag_name)


class OERcodec_SEQUENCE(OERcodec_Object[Union[bytes, List['OERcodec_Object[Any]']]]):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE

    @classmethod
    def enc(cls, _ll, **_kwargs):
        # type: (Union[bytes, List[OERcodec_Object[Any]]], **Any) -> bytes
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
               **_kwargs  # type: Any
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
    def enc(cls, ipaddr_ascii, size_len=0, **_kwargs):  # type: ignore
        # type: (str, Optional[int], **Any) -> bytes
        try:
            s = inet_aton(ipaddr_ascii)
        except Exception:
            raise OER_Encoding_Error("IPv4 address could not be encoded")
        if size_len == len(s):
            return s
        return OER_len_enc(len(s)) + s

    @classmethod
    def do_dec(cls, s, context=None, safe=False,
               size_len=0, oer_unsigned=False, **_kwargs):
        # type: (bytes, Optional[Any], bool, Optional[int], bool, **Any) -> Tuple[ASN1_Object[str], bytes]  # noqa: E501
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


# Re-export compound helpers for backward compatibility.
from scapy.asn1.compound import (  # noqa: E402
    oer_choice_bytes,
    oer_choice_decode,
    oer_sequence_of_bytes,
    oer_sequence_of_decode,
    sequence_encode_to,
    sequence_decode_from as _oer_sequence_decode_from,
)

oer_choice_i2m = oer_choice_bytes
oer_choice_m2i = oer_choice_decode
oer_sequence_of_build = oer_sequence_of_bytes
oer_sequence_of_m2i = oer_sequence_of_decode


def oer_sequence_build(field, pkt):
    # type: (Any, Any) -> bytes
    from scapy.asn1fields import ASN1F_field
    from scapy.asn1.context import OER_Encoder
    enc = OER_Encoder()
    sequence_encode_to(field, pkt, enc)
    return ASN1F_field.i2m(field, pkt, enc.finish())


def oer_sequence_m2i(field, pkt, s):
    # type: (Any, Any, bytes) -> Tuple[Any, bytes]
    from scapy.asn1.context import OER_Decoder
    dec = OER_Decoder(s)
    _oer_sequence_decode_from(field, pkt, dec)
    return [], dec.remaining()