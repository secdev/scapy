# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Octet Encoding Rules (OER) for ASN.1

Basic-OER as specified in ITU-T X.696 | ISO/IEC 8825-7.

``ASN1F_SEQUENCE`` emits the preamble required by 16.2.2: a presence bit per
``ASN1F_optional``/``ASN1F_DEFAULT`` component, preceded by an extension bit
for sequences declared with ``extensible=True``. Fixed SIZE constraints
are expressed with equal ``minimum=``/``maximum=`` (octets for strings, bits
for BIT STRING).

Tags declared on a field are not encoded: OER only puts a tag on the wire for
the chosen alternative of an ``ASN1F_CHOICE`` (20.2), so the ``implicit_tag=``
and ``explicit_tag=`` of the alternatives are what selects it.

Not supported yet: extension additions (an encoding that carries them is
refused rather than misparsed), SET, REAL, and the canonical variant (C-OER).
``ASN1F_SET_OF`` is encoded as ``ASN1F_SEQUENCE_OF``.
"""

import struct

from scapy.compat import chb, bytes_encode
from scapy.utils import binrepr, inet_aton, inet_ntoa
from scapy.asn1.ber import BER_num_dec, BER_num_enc, asn1_tag_parts
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
# DEFAULT components are described by the sequence preamble in OER/UPER.

from typing import (
    Any,
    AnyStr,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)

##################
#  OER encoding  #
##################


class OER_Encoding_Error(ASN1_Encoding_Error):
    pass


class OER_Decoding_Error(ASN1_Decoding_Error):
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
    number_of_bytes = (ll.bit_length() + 7) // 8
    if number_of_bytes > 127:
        raise OER_Encoding_Error(
            "OER_len_enc: Length too long (%i) to be encoded" %
            number_of_bytes
        )
    return chb(0x80 | number_of_bytes) + ll.to_bytes(number_of_bytes, "big")


def OER_len_dec(s):
    # type: (bytes) -> Tuple[int, bytes]
    if not s:
        raise OER_Decoding_Error("OER_len_dec: got empty string", remaining=s)
    tmp_len = s[0]
    if not tmp_len & 0x80:
        return tmp_len, s[1:]
    tmp_len &= 0x7f
    if tmp_len == 0:
        raise OER_Decoding_Error(
            "OER_len_dec: long-form length must have 1-127 subsequent octets",
            remaining=s,
        )
    if len(s) - 1 < tmp_len:
        raise OER_Decoding_Error(
            "OER_len_dec: Got %i bytes while expecting %i" %
            (len(s) - 1, tmp_len),
            remaining=s
        )
    ll = int.from_bytes(s[1:tmp_len + 1], "big")
    return ll, s[tmp_len + 1:]


def _OER_signed_integer_enc(i):
    # type: (int) -> bytes
    from scapy.asn1.intutil import twos_complement_octets
    number_of_bytes, value = twos_complement_octets(i)
    return OER_len_enc(number_of_bytes) + value.to_bytes(number_of_bytes, "big")


def _OER_signed_integer_dec(s):
    # type: (bytes) -> Tuple[int, bytes]
    from scapy.asn1.intutil import from_twos_complement
    number_of_bytes, s = OER_len_dec(s)
    if len(s) < number_of_bytes:
        raise OER_Decoding_Error(
            "_OER_signed_integer_dec: Got %i bytes while expecting %i" %
            (len(s), number_of_bytes),
            remaining=s
        )
    if number_of_bytes == 0:
        raise OER_Decoding_Error(
            "_OER_signed_integer_dec: got an empty length determinant",
            remaining=s
        )
    value = int.from_bytes(s[:number_of_bytes], "big")
    return from_twos_complement(value, number_of_bytes), s[number_of_bytes:]


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
    if len(s) < number_of_bytes:
        raise OER_Decoding_Error(
            "OER_unsigned_integer_dec: Got %i bytes while expecting %i" %
            (len(s), number_of_bytes),
            remaining=s
        )
    if number_of_bytes == 0:
        raise OER_Decoding_Error(
            "OER_unsigned_integer_dec: got an empty length determinant",
            remaining=s
        )
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
    first = s[0]
    tag_class = first & 0xc0
    tag_number = first & 0x3f
    if tag_number != 0x3f:
        return tag_class, tag_number, s[1:]
    tag_number = 0
    i = 1
    while i < len(s):
        c = s[i]
        if i == 1 and (c & 0x7f) == 0:
            raise OER_Decoding_Error(
                "OER_tag_dec: first subsequent octet has leading zeros",
                remaining=s,
            )
        tag_number <<= 7
        tag_number |= c & 0x7f
        i += 1
        if not (c & 0x80):
            break
    else:
        raise OER_Decoding_Error("OER_tag_dec: unfinished tag", remaining=s)
    if tag_number < 63:
        raise OER_Decoding_Error(
            "OER_tag_dec: long-form tag number must be >= 63",
            remaining=s,
        )
    return tag_class, tag_number, s[i:]


def OER_tag_parts(identifier):
    # type: (int) -> Tuple[int, int]
    # X.696 8.7 only keeps the class and the number, so the constructed flag
    # must not leak into the encoded tag number.
    tag_class, tag_number, _constructed = asn1_tag_parts(identifier)
    return tag_class, tag_number


def _resolve_oer_size_bounds(minimum=None,  # type: Optional[int]
                             maximum=None,  # type: Optional[int]
                             extensible=False,  # type: bool
                             ):
    # type: (...) -> Tuple[Optional[int], Optional[int]]
    """Resolve OER SIZE bounds from schema parameters.

    Extensible SIZE is not OER-visible (X.696).
    """
    if extensible:
        return None, None
    return minimum, maximum


_K = TypeVar('_K')


class OERcodec_Object(Generic[_K], metaclass=ASN1Codec_metaclass):
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
            **_kwargs  # type: Any
            ):
        # type: (...) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]
        if not safe:
            return cls.do_dec(
                s, context=context, safe=safe, **_kwargs,
            )
        try:
            return cls.do_dec(
                s, context=context, safe=safe, **_kwargs,
            )
        except ASN1_Error as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""

    @classmethod
    def safedec(cls,
                s,  # type: bytes
                context=None,  # type: Optional[Type[ASN1_Class]]
                **_kwargs  # type: Any
                ):
        # type: (...) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]
        return cls.dec(s, context, safe=True, **_kwargs)

    @classmethod
    def enc(cls, s, minimum=None, maximum=None, extensible=False,
            unsigned=False, **_kwargs):
        # type: (_K, Optional[int], Optional[int], bool, bool, **Any) -> bytes
        if isinstance(s, (str, bytes)):
            return OERcodec_STRING.enc(
                s, minimum=minimum, maximum=maximum, extensible=extensible,
            )
        else:
            try:
                return OERcodec_INTEGER.enc(
                    int(s),
                    minimum=minimum,
                    maximum=maximum,
                    extensible=extensible,
                    unsigned=unsigned,
                )  # type: ignore
            except TypeError:
                raise TypeError("Trying to encode an invalid value !")


# Tags declared on a field are not encoded for OER components (X.696);
# CHOICE writes its own alternative tags. Identity tagging is the ASN1Codec
# default when no tagging_enc/dec is registered.
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

    @staticmethod
    def _wire_params(minimum=None,  # type: Optional[int]
                     maximum=None,  # type: Optional[int]
                     unsigned=False,  # type: bool
                     extensible=False,  # type: bool
                     ):
        # type: (...) -> Tuple[Optional[int], bool, Optional[int], Optional[int]]
        """Derive OER INTEGER width and signedness from schema bounds.

        Per X.696 sections 10.3-10.4, extensible integer constraints are encoded
        as unbounded. A nonnegative lower bound without a fitting fixed upper
        bound uses variable-width unsigned encoding. A fixed eight-octet width
        is used only when ``maximum <= 2**64 - 1``.
        """
        size_len = None  # type: Optional[int]

        # Extension values may lie outside the root range.
        val_min = None if extensible else minimum
        val_max = None if extensible else maximum

        if extensible:
            return None, unsigned, None, None

        if minimum is not None and minimum >= 0:
            unsigned = True
            if maximum is not None:
                if maximum <= 0xFF:
                    size_len = 1
                elif maximum <= 0xFFFF:
                    size_len = 2
                elif maximum <= 0xFFFFFFFF:
                    size_len = 4
                elif maximum <= 0xFFFFFFFFFFFFFFFF:
                    size_len = 8
                # else: range exceeds 2^64-1 → variable unsigned
        elif minimum is not None and maximum is not None:
            unsigned = False
            for sl, lo, hi in (
                (1, -128, 127),
                (2, -32768, 32767),
                (4, -2147483648, 2147483647),
                (8, -9223372036854775808, 9223372036854775807),
            ):
                if minimum >= lo and maximum <= hi:
                    size_len = sl
                    break

        return size_len, unsigned, val_min, val_max

    @classmethod
    def enc(cls, i, minimum=None, maximum=None, extensible=False,
            unsigned=False, **_kwargs):
        # type: (int, Optional[int], Optional[int], bool, bool, **Any) -> bytes
        size_len, unsigned_flag, minimum, maximum = cls._wire_params(
            minimum=minimum,
            maximum=maximum,
            unsigned=unsigned,
            extensible=extensible,
        )
        if minimum is not None and i < minimum:
            raise OER_Encoding_Error(
                "%s: %i is below minimum %i" %
                (cls.__name__, i, minimum)
            )
        if maximum is not None and i > maximum:
            raise OER_Encoding_Error(
                "%s: %i is above maximum %i" %
                (cls.__name__, i, maximum)
            )
        if unsigned_flag and i < 0:
            raise OER_Encoding_Error(
                "%s: %i is negative for an unsigned type" % (cls.__name__, i)
            )
        # X.696 10: the width and the signedness follow the declared bounds of
        # the type, never the value at hand, otherwise the decoder (which only
        # knows the type) reads something else back.
        if size_len in (1, 2, 4, 8):
            signed = not unsigned_flag
            try:
                return struct.pack(cls._FIXED_FORMATS[signed][size_len], i)
            except struct.error:
                raise OER_Encoding_Error(
                    "%s: %i does not fit in %i %s octet(s)" %
                    (cls.__name__, i, size_len,
                     "signed" if signed else "unsigned")
                )
        if unsigned_flag:
            return OER_unsigned_integer_enc(i)
        return _OER_signed_integer_enc(i)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               minimum=None,  # type: Optional[int]
               maximum=None,  # type: Optional[int]
               extensible=False,  # type: bool
               unsigned=False,  # type: bool
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        size_len, unsigned_flag, minimum, maximum = cls._wire_params(
            minimum=minimum,
            maximum=maximum,
            unsigned=unsigned,
            extensible=extensible,
        )
        if size_len in (1, 2, 4, 8):
            if len(s) < size_len:
                raise OER_Decoding_Error(
                    "%s: Got %i bytes while expecting %i" %
                    (cls.__name__, len(s), size_len),
                    remaining=s
                )
            x = struct.unpack(
                cls._FIXED_FORMATS[not unsigned_flag][size_len], s[:size_len]
            )[0]
            t = s[size_len:]
        elif unsigned_flag:
            x, t = OER_unsigned_integer_dec(s)
        else:
            x, t = _OER_signed_integer_dec(s)
        if minimum is not None and x < minimum:
            raise OER_Decoding_Error(
                "%s: %i is below minimum %i" %
                (cls.__name__, x, minimum),
                remaining=s,
            )
        if maximum is not None and x > maximum:
            raise OER_Decoding_Error(
                "%s: %i is above maximum %i" %
                (cls.__name__, x, maximum),
                remaining=s,
            )
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
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        cls.check_string(s)
        return cls.asn1_object(0 if s[0] == 0 else 1), s[1:]


class OERcodec_BIT_STRING(OERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

    @staticmethod
    def _bitstr_to_bytes(bitstr):
        # type: (bytes) -> bytes
        padded = bitstr + b"0" * (-len(bitstr) % 8)
        return bytes([
            int(padded[i:i + 8], 2) for i in range(0, len(padded), 8)
        ])

    @staticmethod
    def _bytes_to_bitstr(data):
        # type: (bytes) -> str
        return "".join(binrepr(x).zfill(8) for x in data)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               minimum=None,  # type: Optional[int]
               maximum=None,  # type: Optional[int]
               extensible=False,  # type: bool
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[str], bytes]
        minimum, maximum = _resolve_oer_size_bounds(
            minimum=minimum, maximum=maximum, extensible=extensible,
        )
        if minimum is not None and maximum is not None and minimum == maximum:
            number_of_bytes = (minimum + 7) // 8
            if len(s) < number_of_bytes:
                raise OER_Decoding_Error(
                    "%s: Got %i bytes while expecting %i" %
                    (cls.__name__, len(s), number_of_bytes),
                    remaining=s
                )
            unused = number_of_bytes * 8 - minimum
            if unused and s[number_of_bytes - 1] & ((1 << unused) - 1):
                raise OER_Decoding_Error(
                    "OERcodec_BIT_STRING: unused bits must be zero",
                    remaining=s,
                )
            return (
                cls.tag.asn1_object(
                    cls._bytes_to_bitstr(s[:number_of_bytes])[:minimum]
                ),
                s[number_of_bytes:],
            )
        length, s = OER_len_dec(s)
        if length == 0:
            raise OER_Decoding_Error(
                "OERcodec_BIT_STRING: length must include the unused-bit count",
                remaining=s,
            )
        if len(s) < length:
            raise OER_Decoding_Error(
                "%s: Got %i bytes while expecting %i" %
                (cls.__name__, len(s), length),
                remaining=s
            )
        unused_bits = s[0]
        if unused_bits > 7:
            raise OER_Decoding_Error(
                "OERcodec_BIT_STRING: unused-bit count must be 0-7",
                remaining=s,
            )
        if length == 1 and unused_bits:
            raise OER_Decoding_Error(
                "OERcodec_BIT_STRING: empty value must have unused-bit count 0",
                remaining=s,
            )
        if unused_bits and s[length - 1] & ((1 << unused_bits) - 1):
            raise OER_Decoding_Error(
                "OERcodec_BIT_STRING: unused bits must be zero",
                remaining=s,
            )
        fs = cls._bytes_to_bitstr(s[1:length])
        if unused_bits > 0:
            fs = fs[:-unused_bits]
        s = s[length:]
        nbits = len(fs)
        if minimum is not None and nbits < minimum:
            raise OER_Decoding_Error(
                "%s: got %i bits while expecting >= %i" %
                (cls.__name__, nbits, minimum),
                remaining=s,
            )
        if maximum is not None and nbits > maximum:
            raise OER_Decoding_Error(
                "%s: got %i bits while expecting <= %i" %
                (cls.__name__, nbits, maximum),
                remaining=s,
            )
        return cls.tag.asn1_object(fs), s

    @classmethod
    def enc(cls, _s, minimum=None, maximum=None, extensible=False, **_kwargs):
        # type: (AnyStr, Optional[int], Optional[int], bool, **Any) -> bytes
        minimum, maximum = _resolve_oer_size_bounds(
            minimum=minimum, maximum=maximum, extensible=extensible,
        )
        s = bytes_encode(_s)
        nbits = len(s)
        if minimum is not None and maximum is not None and minimum == maximum:
            # X.696 13.2: a fixed size means the bits are written padded to a
            # whole number of octets, without length or unused-bit count.
            if nbits != minimum:
                raise OER_Encoding_Error(
                    "%s: got %i bits while expecting %i" %
                    (cls.__name__, nbits, minimum),
                    encoded=_s
                )
            return cls._bitstr_to_bytes(s)
        if minimum is not None and nbits < minimum:
            raise OER_Encoding_Error(
                "%s: got %i bits while expecting >= %i" %
                (cls.__name__, nbits, minimum),
                encoded=_s,
            )
        if maximum is not None and nbits > maximum:
            raise OER_Encoding_Error(
                "%s: got %i bits while expecting <= %i" %
                (cls.__name__, nbits, maximum),
                encoded=_s,
            )
        body = chb(-nbits % 8) + cls._bitstr_to_bytes(s)
        return OER_len_enc(len(body)) + body


class OERcodec_STRING(OERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.STRING

    @classmethod
    def enc(cls, _s, minimum=None, maximum=None, extensible=False, **_kwargs):
        # type: (Union[str, bytes], Optional[int], Optional[int], bool, **Any) -> bytes
        minimum, maximum = _resolve_oer_size_bounds(
            minimum=minimum, maximum=maximum, extensible=extensible,
        )
        s = bytes_encode(_s)
        length = len(s)
        if minimum is not None and maximum is not None and minimum == maximum:
            # X.696 16.1: a fixed size means no length determinant.
            if length != minimum:
                raise OER_Encoding_Error(
                    "%s: got %i bytes while expecting %i" %
                    (cls.__name__, length, minimum),
                    encoded=_s
                )
            return s
        if minimum is not None and length < minimum:
            raise OER_Encoding_Error(
                "%s: got %i bytes while expecting >= %i" %
                (cls.__name__, length, minimum),
                encoded=_s,
            )
        if maximum is not None and length > maximum:
            raise OER_Encoding_Error(
                "%s: got %i bytes while expecting <= %i" %
                (cls.__name__, length, maximum),
                encoded=_s,
            )
        return OER_len_enc(length) + s

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               minimum=None,  # type: Optional[int]
               maximum=None,  # type: Optional[int]
               extensible=False,  # type: bool
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[Any], bytes]
        minimum, maximum = _resolve_oer_size_bounds(
            minimum=minimum, maximum=maximum, extensible=extensible,
        )
        if minimum is not None and maximum is not None and minimum == maximum:
            if len(s) < minimum:
                raise OER_Decoding_Error(
                    "%s: Got %i bytes while expecting %i" %
                    (cls.__name__, len(s), minimum),
                    remaining=s
                )
            return cls.tag.asn1_object(s[:minimum]), s[minimum:]
        length, s = OER_len_dec(s)
        if len(s) < length:
            raise OER_Decoding_Error(
                "%s: Got %i bytes while expecting %i" %
                (cls.__name__, len(s), length),
                remaining=s
            )
        if minimum is not None and length < minimum:
            raise OER_Decoding_Error(
                "%s: got %i bytes while expecting >= %i" %
                (cls.__name__, length, minimum),
                remaining=s,
            )
        if maximum is not None and length > maximum:
            raise OER_Decoding_Error(
                "%s: got %i bytes while expecting <= %i" %
                (cls.__name__, length, maximum),
                remaining=s,
            )
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
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[None], bytes]
        return cls.asn1_object(None), s


class OERcodec_OID(OERcodec_Object[bytes]):
    tag = ASN1_Class_UNIVERSAL.OID

    @classmethod
    def enc(cls, _oid, **_kwargs):
        # type: (AnyStr, **Any) -> bytes
        from scapy.asn1.oid import oid_dotted_to_subidentifiers
        oid = bytes_encode(_oid)
        lst = oid_dotted_to_subidentifiers(oid)
        body = b"".join(BER_num_enc(k) for k in lst)
        return OER_len_enc(len(body)) + body

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[bytes], bytes]
        length, s = OER_len_dec(s)
        if len(s) < length:
            raise OER_Decoding_Error(
                "%s: Got %i bytes while expecting %i" %
                (cls.__name__, len(s), length),
                remaining=s
            )
        content, t = s[:length], s[length:]
        lst = []
        while content:
            val, content = BER_num_dec(content)
            lst.append(val)
        from scapy.asn1.oid import oid_subidentifiers_to_dotted
        return (
            cls.asn1_object(oid_subidentifiers_to_dotted(lst)),
            t,
        )


class OERcodec_ENUMERATED(OERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.ENUMERATED

    @classmethod
    def enc(cls, i, **_kwargs):
        # type: (int, **Any) -> bytes
        if 0 <= i <= 127:
            return chb(i)
        from scapy.asn1.intutil import twos_complement_octets
        number_of_bytes, value = twos_complement_octets(i)
        if number_of_bytes > 127:
            raise OER_Encoding_Error(
                "OERcodec_ENUMERATED: %i is outside -2**1015 .. 2**1015-1" % i
            )
        return chb(0x80 | number_of_bytes) + value.to_bytes(
            number_of_bytes, "big"
        )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        if not s:
            raise OER_Decoding_Error(
                "%s: got empty string" % cls.__name__, remaining=s
            )
        first = s[0]
        if not (first & 0x80):
            return cls.asn1_object(first), s[1:]
        length = first & 0x7f
        if length == 0:
            raise OER_Decoding_Error(
                "OERcodec_ENUMERATED: long-form encoding must have "
                "1-127 subsequent octets",
                remaining=s,
            )
        if len(s) - 1 < length:
            raise OER_Decoding_Error(
                "%s: Got %i bytes while expecting %i" %
                (cls.__name__, len(s) - 1, length),
                remaining=s
            )
        value = int.from_bytes(s[1:length + 1], "big", signed=True)
        return cls.asn1_object(value), s[length + 1:]


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
    def enc(cls, _ll, **_kwargs):
        # type: (Union[bytes, List[OERcodec_Object[Any]]], **Any) -> bytes
        if isinstance(_ll, bytes):
            return _ll
        raise OER_Encoding_Error(
            "OERcodec_SEQUENCE: encoding requires schema-defined fields"
        )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               **_kwargs  # type: Any
               ):
        # type: (...) -> Tuple[ASN1_Object[Union[bytes, List[Any]]], bytes]
        raise OER_Decoding_Error(
            "OERcodec_SEQUENCE: decoding requires schema-defined field order",
            remaining=s
        )


class OERcodec_SET(OERcodec_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET

    @classmethod
    def enc(cls, value, **kwargs):
        # type: (Any, **Any) -> bytes
        raise OER_Encoding_Error(
            "OERcodec_SET: SET encoding is not supported"
        )


class OERcodec_IPADDRESS(OERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IPADDRESS

    @classmethod
    def enc(cls, ipaddr_ascii, minimum=None, maximum=None, extensible=False,
            **_kwargs):  # type: ignore
        # type: (str, Optional[int], Optional[int], bool, **Any) -> bytes
        try:
            s = inet_aton(ipaddr_ascii)
        except Exception:
            raise OER_Encoding_Error("IPv4 address could not be encoded")
        minimum, maximum = _resolve_oer_size_bounds(
            minimum=minimum, maximum=maximum, extensible=extensible,
        )
        if minimum is not None and maximum is not None and minimum == maximum == len(s):
            return s
        return OER_len_enc(len(s)) + s

    @classmethod
    def do_dec(cls, s, context=None, safe=False,
               minimum=None, maximum=None, extensible=False, **_kwargs):
        # type: (bytes, Optional[Any], bool, Optional[int], Optional[int], bool, **Any) -> Tuple[ASN1_Object[str], bytes]  # noqa: E501
        minimum, maximum = _resolve_oer_size_bounds(
            minimum=minimum, maximum=maximum, extensible=extensible,
        )
        if minimum is not None and maximum is not None and minimum == maximum == 4:
            if len(s) < 4:
                raise OER_Decoding_Error(
                    "OERcodec_IPADDRESS: Got %i bytes while expecting 4" %
                    len(s), remaining=s
                )
            return cls.asn1_object(inet_ntoa(s[:4])), s[4:]
        tmp_len, s = OER_len_dec(s)
        if len(s) < tmp_len:
            raise OER_Decoding_Error(
                "OERcodec_IPADDRESS: Got %i bytes while expecting %i" %
                (len(s), tmp_len), remaining=s
            )
        return cls.asn1_object(inet_ntoa(s[:tmp_len])), s[tmp_len:]


class OERcodec_COUNTER32(OERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32


class OERcodec_COUNTER64(OERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER64


class OERcodec_GAUGE32(OERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.GAUGE32


class OERcodec_TIME_TICKS(OERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS
