# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = ASN.1 Unaligned Packed Encoding Rules (UPER)
# scapy.contrib.status = loads

"""
Unaligned Packed Encoding Rules (UPER) for ASN.1

As specified in ITU-T X.691 | ISO/IEC 8825-2.

UPER is registered on ``ASN1_Codecs.PER``. Schema-driven encoding and decoding
(``ASN1F_SEQUENCE``, ``ASN1F_CHOICE``, ``ASN1F_SEQUENCE_OF``,
``ASN1F_ENUMERATED``) is supported for common field types. Not supported yet:
explicit/implicit tagging, SET, extension markers,
``ASN1F_CHOICE``/``ASN1F_SEQUENCE_OF`` with nested ``ASN1_Packet``
alternatives, REAL, and PER-visible character string permuted alphabets.
"""

import binascii

from scapy.error import warning
from scapy.compat import orb, bytes_encode
from scapy.utils import binrepr, inet_aton, inet_ntoa
from scapy.asn1.ber import BER_num_dec, BER_num_enc
from scapy.asn1.asn1 import (
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


###################
#  UPER encoding  #
###################


class UPER_Encoding_Error(ASN1_Encoding_Error):
    def __init__(self,
                 msg,  # type: str
                 encoded=None,  # type: Optional[Union['UPERcodec_Object[Any]', str]]
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


class UPER_Decoding_Error(ASN1_Decoding_Error):
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


class UPER_BadTag_Decoding_Error(UPER_Decoding_Error,
                                 ASN1_BadTag_Decoding_Error):
    pass


def UPER_bits_for_range(size):
    # type: (int) -> int
    if size <= 0:
        return 0
    return size.bit_length()


class UPER_Encoder(object):
    def __init__(self):
        # type: () -> None
        self.number_of_bits = 0
        self.value = 0
        self.chunks_number_of_bits = 0
        self.chunks = []  # type: List[List[int]]

    def number_of_bytes(self):
        # type: () -> int
        return (self.chunks_number_of_bits + self.number_of_bits + 7) // 8

    def align_always(self):
        # type: () -> None
        width = 8 * self.number_of_bytes()
        width -= self.chunks_number_of_bits
        width -= self.number_of_bits
        if width:
            self.number_of_bits += width
            self.value <<= width

    def append_bit(self, bit):
        # type: (int) -> None
        self.number_of_bits += 1
        self.value <<= 1
        self.value |= 1 if bit else 0

    def append_bits(self, data, number_of_bits):
        # type: (bytes, int) -> None
        if number_of_bits == 0:
            return
        value = int.from_bytes(data, "big")
        value >>= (8 * len(data) - number_of_bits)
        self.append_non_negative_binary_integer(value, number_of_bits)

    def append_non_negative_binary_integer(self, value, number_of_bits):
        # type: (int, int) -> None
        if number_of_bits == 0:
            return
        if self.number_of_bits > 4096:
            self.chunks.append([self.value, self.number_of_bits])
            self.chunks_number_of_bits += self.number_of_bits
            self.number_of_bits = 0
            self.value = 0
        self.number_of_bits += number_of_bits
        self.value <<= number_of_bits
        self.value |= value & ((1 << number_of_bits) - 1)

    def append_bytes(self, data):
        # type: (bytes) -> None
        self.append_bits(data, 8 * len(data))

    def append_length_determinant(self, length):
        # type: (int) -> int
        if length < 128:
            encoded = bytes([length])
        elif length < 16384:
            encoded = bytes([(0x80 | (length >> 8)), (length & 0xff)])
        elif length < 32768:
            encoded = b"\xc1"
            length = 16384
        elif length < 49152:
            encoded = b"\xc2"
            length = 32768
        elif length < 65536:
            encoded = b"\xc3"
            length = 49152
        else:
            encoded = b"\xc4"
            length = 65536
        self.append_bytes(encoded)
        return length

    def append_unconstrained_whole_number(self, value):
        # type: (int) -> None
        number_of_bits = 0 if value == 0 else value.bit_length()
        if value < 0:
            number_of_bytes = (number_of_bits + 7) // 8
            enc = (1 << (8 * number_of_bytes)) + value
            if enc & (1 << (8 * number_of_bytes - 1)) == 0:
                enc |= (0xff << (8 * number_of_bytes))
                number_of_bytes += 1
        elif value > 0:
            number_of_bytes = (number_of_bits + 7) // 8
            if number_of_bits == 8 * number_of_bytes:
                number_of_bytes += 1
            enc = value
        else:
            number_of_bytes = 1
            enc = 0
        self.append_length_determinant(number_of_bytes)
        self.append_non_negative_binary_integer(enc, 8 * number_of_bytes)

    def as_bytes(self):
        # type: () -> bytes
        value = 0
        number_of_bits = 0
        for chunk_value, chunk_number_of_bits in self.chunks:
            value <<= chunk_number_of_bits
            value |= chunk_value
            number_of_bits += chunk_number_of_bits
        value <<= self.number_of_bits
        value |= self.value
        number_of_bits += self.number_of_bits
        if number_of_bits == 0:
            return b""
        number_of_alignment_bits = (8 - (number_of_bits % 8)) % 8
        value <<= number_of_alignment_bits
        number_of_bits += number_of_alignment_bits
        value |= (0x80 << number_of_bits)
        hexval = hex(value)[4:].rstrip("L")
        if len(hexval) % 2:
            hexval = "0" + hexval
        return binascii.unhexlify(hexval)


def _uper_significant_bit_count(data):
    # type: (bytes) -> int
    if not data:
        return 0
    total = 8 * len(data)
    bits = int.from_bytes(data, "big")
    end = total
    while end > 0 and ((bits >> (total - end)) & 1) == 0:
        end -= 1
    trimmed = total - end
    if trimmed > 0 and trimmed <= 8:
        return end
    return total


def _uper_per_bits_to_bytes(bit_value, number_of_bits):
    # type: (int, int) -> bytes
    if number_of_bits == 0:
        return b""
    bitstr = format(bit_value, "0%db" % number_of_bits)
    value = "10000000" + bitstr
    number_of_alignment_bits = (8 - (number_of_bits % 8))
    if number_of_alignment_bits != 8:
        value += "0" * number_of_alignment_bits
    hexval = hex(int(value, 2))[4:].rstrip("L")
    if len(hexval) % 2:
        hexval = "0" + hexval
    return binascii.unhexlify(hexval)


def UPER_append_encoded(enc, data):
    # type: (UPER_Encoder, bytes) -> None
    if not data:
        return
    nbits = _uper_significant_bit_count(data)
    if nbits == 0:
        return
    total = 8 * len(data)
    bits = int.from_bytes(data, "big")
    shift = total - nbits
    value = (bits >> shift) & ((1 << nbits) - 1)
    enc.append_non_negative_binary_integer(value, nbits)


def UPER_join_encodings(*parts):
    # type: (*bytes) -> bytes
    enc = UPER_Encoder()
    for part in parts:
        UPER_append_encoded(enc, part)
    return enc.as_bytes()


def UPER_optional_presence_enc(bits, enc=None):
    # type: (List[int], Optional[UPER_Encoder]) -> bytes
    standalone = enc is None
    if enc is None:
        enc = UPER_Encoder()
    for bit in bits:
        enc.append_bit(bit)
    return enc.as_bytes() if standalone else b""


def UPER_count_enc(count, enc=None):
    # type: (int, Optional[UPER_Encoder]) -> bytes
    standalone = enc is None
    if enc is None:
        enc = UPER_Encoder()
    enc.append_length_determinant(count)
    return enc.as_bytes() if standalone else b""


def UPER_has_unexpected_remainder(dec):
    # type: (UPER_Decoder) -> bool
    if dec.number_of_bits == 0:
        return False
    mask = (1 << dec.number_of_bits) - 1
    return (dec._bits & mask) != 0


def UPER_count_dec(s, dec=None):
    # type: (bytes, Optional[UPER_Decoder]) -> Tuple[int, bytes]
    standalone = dec is None
    if dec is None:
        dec = UPER_Decoder(s)
    count = dec.read_length_determinant()
    if standalone:
        return count, dec.remaining()
    return count, b""


class UPER_Decoder(object):
    def __init__(self, encoded):
        # type: (bytes) -> None
        self.total_number_of_bits = 8 * len(encoded)
        self.number_of_bits = self.total_number_of_bits
        if encoded:
            self._bits = int.from_bytes(encoded, "big")
        else:
            self._bits = 0

    def _read_offset(self):
        # type: () -> int
        return self.total_number_of_bits - self.number_of_bits

    def _read_bits_int(self, number_of_bits):
        # type: (int) -> int
        if number_of_bits == 0:
            return 0
        consumed = self._read_offset()
        shift = self.total_number_of_bits - consumed - number_of_bits
        mask = (1 << number_of_bits) - 1
        return (self._bits >> shift) & mask

    def read_bit(self):
        # type: () -> int
        if self.number_of_bits == 0:
            raise UPER_Decoding_Error("UPER_Decoder: out of data")
        bit = self._read_bits_int(1)
        self.number_of_bits -= 1
        return bit

    def read_bits(self, number_of_bits):
        # type: (int) -> bytes
        if number_of_bits > self.number_of_bits:
            raise UPER_Decoding_Error("UPER_Decoder: out of data")
        if number_of_bits == 0:
            return b""
        value = self._read_bits_int(number_of_bits)
        self.number_of_bits -= number_of_bits
        return _uper_per_bits_to_bytes(value, number_of_bits)

    def remaining(self):
        # type: () -> bytes
        if self.number_of_bits == 0:
            return b""
        value = self._read_bits_int(self.number_of_bits)
        return _uper_per_bits_to_bytes(value, self.number_of_bits)

    def read_bytes(self, number_of_bytes):
        # type: (int) -> bytes
        return self.read_bits(8 * number_of_bytes)

    def read_non_negative_binary_integer(self, number_of_bits):
        # type: (int) -> int
        if number_of_bits > self.number_of_bits:
            raise UPER_Decoding_Error("UPER_Decoder: out of data")
        if number_of_bits == 0:
            return 0
        value = self._read_bits_int(number_of_bits)
        self.number_of_bits -= number_of_bits
        return value

    def align_always(self):
        # type: () -> None
        consumed = self.total_number_of_bits - self.number_of_bits
        width = (8 - (consumed % 8)) % 8
        if width:
            if width > self.number_of_bits:
                raise UPER_Decoding_Error("UPER_Decoder: out of data")
            self.number_of_bits -= width

    def read_length_determinant(self):
        # type: () -> int
        value = self.read_non_negative_binary_integer(8)
        if (value & 0x80) == 0x00:
            return value
        if (value & 0xc0) == 0x80:
            return ((value & 0x7f) << 8) | self.read_non_negative_binary_integer(8)
        mapping = {0xc1: 16384, 0xc2: 32768, 0xc3: 49152, 0xc4: 65536}
        if value in mapping:
            return mapping[value]
        raise UPER_Decoding_Error(
            "UPER_Decoder: bad length determinant 0x%02x" % value
        )

    def read_unconstrained_whole_number(self):
        # type: () -> int
        number_of_bytes = self.read_length_determinant()
        enc = self.read_non_negative_binary_integer(8 * number_of_bytes)
        sign_bit = 1 << (8 * number_of_bytes - 1)
        if enc & sign_bit:
            return enc - (1 << (8 * number_of_bytes))
        return enc

    def consume_input(self):
        # type: () -> None
        self.number_of_bits = 0


def UPER_constrained_int_enc(value, minimum, maximum, enc=None):
    # type: (int, int, int, Optional[UPER_Encoder]) -> bytes
    standalone = enc is None
    if enc is None:
        enc = UPER_Encoder()
    size = maximum - minimum
    enc.append_non_negative_binary_integer(
        value - minimum, UPER_bits_for_range(size)
    )
    return enc.as_bytes() if standalone else b""


def UPER_constrained_int_dec(s, minimum, maximum):
    # type: (bytes, int, int) -> Tuple[int, bytes]
    dec = UPER_Decoder(s)
    size = maximum - minimum
    value = dec.read_non_negative_binary_integer(UPER_bits_for_range(size))
    dec.consume_input()
    return value + minimum, b""


def UPER_constrained_int_dec_from_decoder(dec, minimum, maximum):
    # type: (UPER_Decoder, int, int) -> int
    size = maximum - minimum
    value = dec.read_non_negative_binary_integer(UPER_bits_for_range(size))
    return value + minimum


def UPER_unconstrained_int_enc(value, enc=None):
    # type: (int, Optional[UPER_Encoder]) -> bytes
    standalone = enc is None
    if enc is None:
        enc = UPER_Encoder()
    enc.append_unconstrained_whole_number(value)
    return enc.as_bytes() if standalone else b""


def UPER_unconstrained_int_dec(s):
    # type: (bytes) -> Tuple[int, bytes]
    dec = UPER_Decoder(s)
    value = dec.read_unconstrained_whole_number()
    remain = dec.remaining()
    return value, remain


def UPER_boolean_enc(value, enc=None):
    # type: (int, Optional[UPER_Encoder]) -> bytes
    standalone = enc is None
    if enc is None:
        enc = UPER_Encoder()
    enc.append_bit(1 if value else 0)
    return enc.as_bytes() if standalone else b""


def UPER_boolean_dec(s):
    # type: (bytes) -> Tuple[int, bytes]
    dec = UPER_Decoder(s)
    value = dec.read_bit()
    dec.consume_input()
    return value, b""


def UPER_octet_string_enc(data, minimum=None, maximum=None, enc=None):
    # type: (bytes, Optional[int], Optional[int], Optional[UPER_Encoder]) -> bytes
    standalone = enc is None
    if enc is None:
        enc = UPER_Encoder()
    if minimum is not None and maximum is not None and minimum == maximum:
        enc.append_bytes(data)
    elif minimum is not None and maximum is not None:
        enc.append_non_negative_binary_integer(
            len(data) - minimum,
            UPER_bits_for_range(maximum - minimum),
        )
        enc.append_bytes(data)
    else:
        enc.append_length_determinant(len(data))
        enc.append_bytes(data)
    return enc.as_bytes() if standalone else b""


def UPER_octet_string_dec(s, minimum=None, maximum=None, dec=None):
    # type: (bytes, Optional[int], Optional[int], Optional[UPER_Decoder]) -> Tuple[bytes, bytes]  # noqa: E501
    standalone = dec is None
    if dec is None:
        dec = UPER_Decoder(s)
    if minimum is not None and maximum is not None and minimum == maximum:
        length = minimum
    elif minimum is not None and maximum is not None:
        length = minimum + dec.read_non_negative_binary_integer(
            UPER_bits_for_range(maximum - minimum)
        )
    else:
        length = dec.read_length_determinant()
    data = dec.read_bytes(length)
    if standalone:
        return data, dec.remaining()
    return data, b""


def UPER_choice_index_enc(index, number_of_choices, enc=None):
    # type: (int, int, Optional[UPER_Encoder]) -> bytes
    standalone = enc is None
    if enc is None:
        enc = UPER_Encoder()
    enc.append_non_negative_binary_integer(
        index, UPER_bits_for_range(number_of_choices - 1)
    )
    return enc.as_bytes() if standalone else b""


def UPER_choice_index_dec(s, number_of_choices, dec=None):
    # type: (bytes, int, Optional[UPER_Decoder]) -> Tuple[int, bytes]
    standalone = dec is None
    if dec is None:
        dec = UPER_Decoder(s)
    index = dec.read_non_negative_binary_integer(
        UPER_bits_for_range(number_of_choices - 1)
    )
    if standalone:
        return index, dec.remaining()
    return index, b""


class UPERcodec_metaclass(type):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type['UPERcodec_Object[Any]']
        c = cast('Type[UPERcodec_Object[Any]]',
                 super(UPERcodec_metaclass, cls).__new__(cls, name, bases, dct))
        try:
            c.tag.register(c.codec, c)
        except Exception:
            warning("Error registering %r for %r" % (c.tag, c.codec))
        return c


_K = TypeVar('_K')


class UPERcodec_Object(Generic[_K], metaclass=UPERcodec_metaclass):
    codec = ASN1_Codecs.PER
    tag = ASN1_Class_UNIVERSAL.ANY

    @classmethod
    def asn1_object(cls, val):
        # type: (_K) -> ASN1_Object[_K]
        return cls.tag.asn1_object(val)

    @classmethod
    def check_string(cls, s):
        # type: (bytes) -> None
        if not s and cls.tag != ASN1_Class_UNIVERSAL.NULL:
            raise UPER_Decoding_Error(
                "%s: Got empty object while expecting %r" %
                (cls.__name__, cls.tag), remaining=s
            )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               uper_min=None,  # type: Optional[int]
               uper_max=None,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               uper_enum_values=None,  # type: Optional[List[int]]
               ):
        # type: (...) -> Tuple[ASN1_Object[Any], bytes]
        raise UPER_Decoding_Error(
            "%s: Cannot decode unknown UPER type without context" %
            cls.__name__, remaining=s
        )

    @classmethod
    def dec(cls,
            s,  # type: bytes
            context=None,  # type: Optional[Type[ASN1_Class]]
            safe=False,  # type: bool
            size_len=0,  # type: Optional[int]
            uper_min=None,  # type: Optional[int]
            uper_max=None,  # type: Optional[int]
            oer_unsigned=False,  # type: bool
            uper_enum_values=None,  # type: Optional[List[int]]
            ):
        # type: (...) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]
        dec_kwargs = {}  # type: Dict[str, Any]
        if uper_enum_values is not None:
            dec_kwargs["uper_enum_values"] = uper_enum_values
        if not safe:
            return cls.do_dec(
                s, context, safe, size_len, uper_min, uper_max, oer_unsigned,
                **dec_kwargs
            )
        try:
            return cls.do_dec(
                s, context, safe, size_len, uper_min, uper_max, oer_unsigned,
                **dec_kwargs
            )
        except UPER_BadTag_Decoding_Error as e:
            o, remain = UPERcodec_Object.dec(
                e.remaining, context, safe, size_len, uper_min, uper_max,
                oer_unsigned, uper_enum_values=uper_enum_values,
            )
            return ASN1_BADTAG(o), remain
        except UPER_Decoding_Error as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""
        except ASN1_Error as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""

    @classmethod
    def safedec(cls,
                s,  # type: bytes
                context=None,  # type: Optional[Type[ASN1_Class]]
                size_len=0,  # type: Optional[int]
                uper_min=None,  # type: Optional[int]
                uper_max=None,  # type: Optional[int]
                oer_unsigned=False,  # type: bool
                uper_enum_values=None,  # type: Optional[List[int]]
                ):
        # type: (...) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]
        return cls.dec(
            s, context, safe=True,
            size_len=size_len, uper_min=uper_min, uper_max=uper_max,
            oer_unsigned=oer_unsigned, uper_enum_values=uper_enum_values,
        )

    @classmethod
    def enc(cls, s, size_len=0, uper_min=None, uper_max=None, **_kwargs):
        # type: (_K, Optional[int], Optional[int], Optional[int], **Any) -> bytes
        if isinstance(s, (str, bytes)):
            return UPERcodec_STRING.enc(s, size_len=size_len,
                                        uper_min=uper_min, uper_max=uper_max)
        else:
            try:
                return UPERcodec_INTEGER.enc(
                    int(s),
                    size_len=size_len,
                    uper_min=uper_min,
                    uper_max=uper_max,
                )
            except Exception:
                raise UPER_Encoding_Error(
                    "Cannot encode value %r for %s" % (s, cls.__name__),
                    encoded=s
                )


def _uper_enc_via_encode_into(cls, *args, **kwargs):
    # type: (Type[UPERcodec_Object[Any]], *Any, **Any) -> bytes
    enc = UPER_Encoder()
    cls.encode_into(enc, *args, **kwargs)
    return enc.as_bytes()


def UPER_tagging_enc(s, **kwargs):
    # type: (bytes, **Any) -> bytes
    # UPER has no BER-style TLV tagging.
    return s


def UPER_tagging_dec(s, **kwargs):
    # type: (bytes, **Any) -> Tuple[Optional[int], bytes]
    return None, s


ASN1_Codecs.PER.register_stem(UPERcodec_Object)
ASN1_Codecs.PER.register_tagging(UPER_tagging_enc, UPER_tagging_dec)


#########################
#    UPERcodec objects  #
#########################


def _uper_int_range(size_len, uper_min, uper_max, oer_unsigned=False):
    # type: (Optional[int], Optional[int], Optional[int], bool) -> Tuple[Optional[int], Optional[int]]  # noqa: E501
    if uper_min is not None or uper_max is not None:
        return uper_min, uper_max
    if size_len in (1, 2, 4, 8) and oer_unsigned:
        return 0, (256 ** size_len) - 1
    return None, None


class UPERcodec_INTEGER(UPERcodec_Object[int]):
    tag = ASN1_Class_UNIVERSAL.INTEGER

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    i,  # type: int
                    size_len=0,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    oer_unsigned=False,  # type: bool
                    uper_extensible=False,  # type: bool
                    ):
        # type: (...) -> None
        minimum, maximum = _uper_int_range(size_len, uper_min, uper_max, oer_unsigned)
        if uper_extensible and minimum is not None and maximum is not None:
            if minimum <= i <= maximum:
                enc.append_bit(0)
            else:
                enc.append_bit(1)
                UPER_unconstrained_int_enc(i, enc=enc)
                return
        if minimum is not None and maximum is not None:
            UPER_constrained_int_enc(i, minimum, maximum, enc=enc)
        else:
            UPER_unconstrained_int_enc(i, enc=enc)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         size_len=0,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         oer_unsigned=False,  # type: bool
                         uper_extensible=False,  # type: bool
                         ):
        # type: (...) -> ASN1_Object[int]
        minimum, maximum = _uper_int_range(size_len, uper_min, uper_max, oer_unsigned)
        if uper_extensible and minimum is not None and maximum is not None:
            if dec.read_bit():
                value = dec.read_unconstrained_whole_number()
                return cls.asn1_object(value)
        if minimum is not None and maximum is not None:
            value = UPER_constrained_int_dec_from_decoder(dec, minimum, maximum)
        else:
            value = dec.read_unconstrained_whole_number()
        return cls.asn1_object(value)

    @classmethod
    def enc(cls, i, size_len=0, uper_min=None, uper_max=None,
            oer_unsigned=False, **_kwargs):
        # type: (int, Optional[int], Optional[int], Optional[int], bool, **Any) -> bytes
        return _uper_enc_via_encode_into(
            cls, i, size_len, uper_min, uper_max, oer_unsigned,
        )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               uper_min=None,  # type: Optional[int]
               uper_max=None,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        minimum, maximum = _uper_int_range(size_len, uper_min, uper_max, oer_unsigned)
        if minimum is not None and maximum is not None:
            x, t = UPER_constrained_int_dec(s, minimum, maximum)
        else:
            x, t = UPER_unconstrained_int_dec(s)
        return cls.asn1_object(x), t


class UPERcodec_BOOLEAN(UPERcodec_Object[int]):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    i,  # type: int
                    size_len=0,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    oer_unsigned=False,  # type: bool
                    ):
        # type: (...) -> None
        UPER_boolean_enc(i, enc=enc)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         size_len=0,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         oer_unsigned=False,  # type: bool
                         ):
        # type: (...) -> ASN1_Object[int]
        return cls.asn1_object(dec.read_bit())

    @classmethod
    def enc(cls, i, size_len=0, uper_min=None, uper_max=None,
            oer_unsigned=False, **_kwargs):
        # type: (int, Optional[int], Optional[int], Optional[int], bool, **Any) -> bytes
        return _uper_enc_via_encode_into(
            cls, i, size_len, uper_min, uper_max, oer_unsigned,
        )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               uper_min=None,  # type: Optional[int]
               uper_max=None,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        x, t = UPER_boolean_dec(s)
        return cls.asn1_object(x), t


def _uper_bytes_to_bitstr(data, nbits):
    # type: (bytes, int) -> str
    bitstr = "".join(binrepr(orb(x)).zfill(8) for x in data)
    return bitstr[:nbits]


def _uper_bit_string_parts(_s):
    # type: (Any) -> Tuple[bytes, int]
    if isinstance(_s, tuple) and len(_s) == 2:
        data, nbits = _s
        return bytes_encode(data), nbits
    if isinstance(_s, str) and _s and all(c in "01" for c in _s):
        nbits = len(_s)
        padded = _s + "0" * ((8 - nbits % 8) % 8)
        data = int(padded or "0", 2).to_bytes(
            max(1, len(padded) // 8), "big"
        )
        return data, nbits
    s = bytes_encode(_s)
    return s, 8 * len(s)


class UPERcodec_BIT_STRING(UPERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    _s,  # type: Any
                    size_len=0,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    oer_unsigned=False,  # type: bool
                    ):
        # type: (...) -> None
        s, nbits = _uper_bit_string_parts(_s)
        minimum = uper_min
        maximum = uper_max
        if size_len:
            minimum = maximum = size_len
        if minimum is not None and maximum is not None and minimum == maximum:
            if nbits >= minimum:
                value = int.from_bytes(s, "big") >> (8 * len(s) - minimum)
            elif isinstance(_s, str) and _s and all(c in "01" for c in _s):
                value = int(_s, 2)
            elif nbits > 0:
                value = int.from_bytes(s, "big") >> max(0, 8 * len(s) - nbits)
            else:
                value = 0
            enc.append_non_negative_binary_integer(value, minimum)
        elif minimum is not None and maximum is not None:
            enc.append_non_negative_binary_integer(
                nbits - minimum, UPER_bits_for_range(maximum - minimum)
            )
            enc.append_bits(s, nbits)
        else:
            enc.append_length_determinant((nbits + 7) // 8)
            enc.append_bytes(s)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         size_len=0,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         oer_unsigned=False,  # type: bool
                         ):
        # type: (...) -> ASN1_Object[str]
        minimum = uper_min
        maximum = uper_max
        if size_len:
            minimum = maximum = size_len
        if minimum is not None and maximum is not None and minimum == maximum:
            nbits = minimum
        elif minimum is not None and maximum is not None:
            nbits = minimum + dec.read_non_negative_binary_integer(
                UPER_bits_for_range(maximum - minimum)
            )
        else:
            nbytes = dec.read_length_determinant()
            raw = dec.read_bytes(nbytes)
            nbits = 8 * nbytes
            return cls.asn1_object(_uper_bytes_to_bitstr(raw, nbits))
        raw = dec.read_bits(nbits)
        return cls.asn1_object(_uper_bytes_to_bitstr(raw, nbits))

    @classmethod
    def enc(cls, _s, size_len=0, uper_min=None, uper_max=None,
            oer_unsigned=False, **_kwargs):
        # type: (Any, Optional[int], Optional[int], Optional[int], bool, **Any) -> bytes
        return _uper_enc_via_encode_into(
            cls, _s, size_len, uper_min, uper_max, oer_unsigned,
        )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               uper_min=None,  # type: Optional[int]
               uper_max=None,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[str], bytes]
        dec = UPER_Decoder(s)
        minimum = uper_min
        maximum = uper_max
        if minimum is not None and maximum is not None and minimum == maximum:
            nbits = minimum
        elif minimum is not None and maximum is not None:
            nbits = minimum + dec.read_non_negative_binary_integer(
                UPER_bits_for_range(maximum - minimum)
            )
        else:
            nbytes = dec.read_length_determinant()
            raw = dec.read_bytes(nbytes)
            nbits = 8 * nbytes
            return cls.asn1_object(_uper_bytes_to_bitstr(raw, nbits)), dec.remaining()
        raw = dec.read_bits(nbits)
        return cls.asn1_object(_uper_bytes_to_bitstr(raw, nbits)), dec.remaining()


def _uper_octet_string_bounds(size_len, uper_min, uper_max):
    # type: (Optional[int], Optional[int], Optional[int]) -> Tuple[Optional[int], Optional[int]]  # noqa: E501
    if size_len:
        return size_len, size_len
    return uper_min, uper_max


class UPERcodec_STRING(UPERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.STRING

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    _s,  # type: Union[str, bytes]
                    size_len=0,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    oer_unsigned=False,  # type: bool
                    ):
        # type: (...) -> None
        s = bytes_encode(_s)
        minimum, maximum = _uper_octet_string_bounds(
            size_len, uper_min, uper_max,
        )
        UPER_octet_string_enc(s, minimum, maximum, enc=enc)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         size_len=0,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         oer_unsigned=False,  # type: bool
                         ):
        # type: (...) -> ASN1_Object[Any]
        minimum, maximum = _uper_octet_string_bounds(
            size_len, uper_min, uper_max,
        )
        raw, _ = UPER_octet_string_dec(b"", minimum, maximum, dec=dec)
        return cls.asn1_object(raw)

    @classmethod
    def enc(cls, _s, size_len=0, uper_min=None, uper_max=None,
            oer_unsigned=False, **_kwargs):
        # type: (Union[str, bytes], Optional[int], Optional[int], Optional[int], bool, **Any) -> bytes  # noqa: E501
        return _uper_enc_via_encode_into(
            cls, _s, size_len, uper_min, uper_max, oer_unsigned,
        )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               uper_min=None,  # type: Optional[int]
               uper_max=None,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[Any], bytes]
        minimum, maximum = _uper_octet_string_bounds(
            size_len, uper_min, uper_max,
        )
        raw, remain = UPER_octet_string_dec(s, minimum, maximum)
        return cls.asn1_object(raw), remain


class UPERcodec_NULL(UPERcodec_Object[None]):
    tag = ASN1_Class_UNIVERSAL.NULL

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    _s,  # type: Any
                    size_len=0,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    oer_unsigned=False,  # type: bool
                    ):
        # type: (...) -> None
        return

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         size_len=0,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         oer_unsigned=False,  # type: bool
                         ):
        # type: (...) -> ASN1_Object[None]
        return cls.asn1_object(None)

    @classmethod
    def enc(cls, _s, size_len=0, uper_min=None, uper_max=None,
            oer_unsigned=False, **_kwargs):
        # type: (Any, Optional[int], Optional[int], Optional[int], bool, **Any) -> bytes
        return b""

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               uper_min=None,  # type: Optional[int]
               uper_max=None,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[None], bytes]
        return cls.asn1_object(None), s


class UPERcodec_OID(UPERcodec_Object[bytes]):
    tag = ASN1_Class_UNIVERSAL.OID

    @classmethod
    def enc(cls, _oid, size_len=0, uper_min=None, uper_max=None, **_kwargs):
        # type: (AnyStr, Optional[int], Optional[int], Optional[int], **Any) -> bytes
        oid = bytes_encode(_oid)
        if oid:
            lst = [int(x) for x in oid.split(b".")]
            lst = [40 * lst[0] + lst[1]] + lst[2:]
        else:
            lst = []
        body = b"".join(BER_num_enc(k) for k in lst)
        enc = UPER_Encoder()
        enc.append_length_determinant(len(body))
        enc.append_bytes(body)
        return enc.as_bytes()

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               uper_min=None,  # type: Optional[int]
               uper_max=None,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[bytes], bytes]
        dec = UPER_Decoder(s)
        length = dec.read_length_determinant()
        content = dec.read_bytes(length)
        lst = []
        while content:
            val, content = BER_num_dec(content)
            lst.append(val)
        if len(lst) > 0:
            lst.insert(0, lst[0] // 40)
            lst[1] %= 40
        return (
            cls.asn1_object(b".".join(str(k).encode('ascii') for k in lst)),
            dec.remaining(),
        )


def UPER_enumerated_enc(value,
                        enum_values,  # type: List[int]
                        enc=None  # type: Optional[UPER_Encoder]
                        ):
    # type: (int, List[int], Optional[UPER_Encoder]) -> bytes
    standalone = enc is None
    if enc is None:
        enc = UPER_Encoder()
    if not enum_values:
        raise UPER_Encoding_Error("UPER_enumerated_enc: empty enumeration")
    try:
        index = enum_values.index(value)
    except ValueError:
        raise UPER_Encoding_Error(
            "UPER_enumerated_enc: unknown enumeration value %r" % value
        )
    UPER_choice_index_enc(index, len(enum_values), enc=enc)
    return enc.as_bytes() if standalone else b""


def UPER_enumerated_dec(s,
                        enum_values,  # type: List[int]
                        dec=None  # type: Optional[UPER_Decoder]
                        ):
    # type: (bytes, List[int], Optional[UPER_Decoder]) -> Tuple[int, bytes]
    standalone = dec is None
    if dec is None:
        dec = UPER_Decoder(s)
    if not enum_values:
        raise UPER_Decoding_Error("UPER_enumerated_dec: empty enumeration")
    index, _ = UPER_choice_index_dec(b"", len(enum_values), dec=dec)
    if index >= len(enum_values):
        raise UPER_Decoding_Error(
            "UPER_enumerated_dec: index %i out of range" % index
        )
    if standalone:
        dec.consume_input()
        return enum_values[index], b""
    return enum_values[index], b""


class UPERcodec_ENUMERATED(UPERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.ENUMERATED

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    i,  # type: int
                    size_len=0,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    oer_unsigned=False,  # type: bool
                    uper_enum_values=None,  # type: Optional[List[int]]
                    ):
        # type: (...) -> None
        if uper_enum_values is not None:
            UPER_enumerated_enc(i, uper_enum_values, enc=enc)
            return
        minimum = uper_min if uper_min is not None else 0
        maximum = uper_max if uper_max is not None else size_len
        if maximum is None:
            maximum = max(i, 0)
        UPER_constrained_int_enc(i, minimum, maximum, enc=enc)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         size_len=0,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         oer_unsigned=False,  # type: bool
                         uper_enum_values=None,  # type: Optional[List[int]]
                         ):
        # type: (...) -> ASN1_Object[int]
        if uper_enum_values is not None:
            value, _ = UPER_enumerated_dec(b"", uper_enum_values, dec=dec)
            return cls.asn1_object(value)
        minimum = uper_min if uper_min is not None else 0
        maximum = uper_max if uper_max is not None else size_len
        if maximum is None:
            raise UPER_Decoding_Error("UPERcodec_ENUMERATED: missing range")
        value = dec.read_non_negative_binary_integer(
            UPER_bits_for_range(maximum - minimum)
        ) + minimum
        return cls.asn1_object(value)

    @classmethod
    def enc(cls,
            i,
            size_len=0,
            uper_min=None,
            uper_max=None,
            oer_unsigned=False,
            uper_enum_values=None,
            **_kwargs
            ):
        # type: (int, Optional[int], Optional[int], Optional[int], bool, Optional[List[int]], **Any) -> bytes  # noqa: E501
        return _uper_enc_via_encode_into(
            cls, i, size_len, uper_min, uper_max, oer_unsigned,
            uper_enum_values=uper_enum_values,
        )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               uper_min=None,  # type: Optional[int]
               uper_max=None,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               uper_enum_values=None,  # type: Optional[List[int]]
               ):
        # type: (...) -> Tuple[ASN1_Object[int], bytes]
        if uper_enum_values is not None:
            x, t = UPER_enumerated_dec(s, uper_enum_values)
            return cls.asn1_object(x), t
        minimum = uper_min if uper_min is not None else 0
        maximum = uper_max if uper_max is not None else size_len
        if maximum is None:
            raise UPER_Decoding_Error("UPERcodec_ENUMERATED: missing range")
        x, t = UPER_constrained_int_dec(s, minimum, maximum)
        return cls.asn1_object(x), t


class UPERcodec_SEQUENCE(UPERcodec_Object[Union[bytes, List[Any]]]):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    _ll,  # type: Union[bytes, List[UPERcodec_Object[Any]]]
                    size_len=0,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    oer_unsigned=False,  # type: bool
                    ):
        # type: (...) -> None
        if isinstance(_ll, bytes):
            UPER_append_encoded(enc, _ll)

    @classmethod
    def enc(cls, _ll, size_len=0, uper_min=None, uper_max=None,
            oer_unsigned=False, **_kwargs):
        # type: (Union[bytes, List[UPERcodec_Object[Any]]], Optional[int], Optional[int], Optional[int], bool, **Any) -> bytes  # noqa: E501
        if isinstance(_ll, bytes):
            return _ll
        raise UPER_Encoding_Error(
            "UPERcodec_SEQUENCE: schema-defined field order required"
        )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Type[ASN1_Class]]
               safe=False,  # type: bool
               size_len=0,  # type: Optional[int]
               uper_min=None,  # type: Optional[int]
               uper_max=None,  # type: Optional[int]
               oer_unsigned=False,  # type: bool
               ):
        # type: (...) -> Tuple[ASN1_Object[Union[bytes, List[Any]]], bytes]
        raise UPER_Decoding_Error(
            "UPERcodec_SEQUENCE: decoding requires schema-defined field order",
            remaining=s
        )


class UPERcodec_SET(UPERcodec_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET


class UPERcodec_IPADDRESS(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IPADDRESS

    @classmethod
    def enc(cls, ipaddr_ascii, size_len=0, uper_min=None, uper_max=None, **_kwargs):
        # type: (str, Optional[int], Optional[int], Optional[int], **Any) -> bytes
        try:
            s = inet_aton(ipaddr_ascii)
        except Exception:
            raise UPER_Encoding_Error("IPv4 address could not be encoded")
        return UPER_octet_string_enc(s, 4, 4)

    @classmethod
    def do_dec(cls, s, context=None, safe=False,
               size_len=0, uper_min=None, uper_max=None,
               oer_unsigned=False):
        # type: (bytes, Optional[Any], bool, Optional[int], Optional[int], Optional[int], bool) -> Tuple[ASN1_Object[str], bytes]  # noqa: E501
        raw, remain = UPER_octet_string_dec(s, 4, 4)
        try:
            ipaddr_ascii = inet_ntoa(raw)
        except Exception:
            raise UPER_Decoding_Error(
                "IP address could not be decoded",
                remaining=s,
            )
        return cls.asn1_object(ipaddr_ascii), remain


class UPERcodec_COUNTER32(UPERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32


class UPERcodec_COUNTER64(UPERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER64


class UPERcodec_GAUGE32(UPERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.GAUGE32


class UPERcodec_TIME_TICKS(UPERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS


# string aliases
class UPERcodec_UTF8_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UTF8_STRING


class UPERcodec_NUMERIC_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING


class UPERcodec_PRINTABLE_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING


class UPERcodec_T61_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING


class UPERcodec_VIDEOTEX_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING


class UPERcodec_IA5_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING


class UPERcodec_GENERAL_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERAL_STRING


class UPERcodec_UTC_TIME(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME


class UPERcodec_GENERALIZED_TIME(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME


class UPERcodec_ISO646_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.ISO646_STRING


class UPERcodec_UNIVERSAL_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UNIVERSAL_STRING


class UPERcodec_BMP_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.BMP_STRING


##########################
#    ASN1F field hooks   #
##########################

def _field_extensible(field):
    # type: (Any) -> bool
    return bool(getattr(field, "codec_opts", {}).get("uper_extensible", False))


def _field_range(field):
    # type: (Any) -> Tuple[Optional[int], Optional[int]]
    opts = getattr(field, "codec_opts", {})
    return opts.get("uper_min"), opts.get("uper_max")


class _UPER_FieldHooks(object):
    """Compound ASN1F_* helpers for UPER/PER (kept out of asn1fields.py)."""

    @staticmethod
    def use_object_enc(field, pkt, item):
        # type: (Any, Any, Any) -> bool
        # Always pass constraints through codec.enc(**kwargs).
        return False

    @staticmethod
    def sequence_m2i(field, pkt, s):
        # type: (Any, Any, bytes) -> Tuple[Any, bytes]
        dec = UPER_Decoder(s)
        _UPER_FieldHooks.sequence_dissect_from_decoder(field, pkt, dec)
        if UPER_has_unexpected_remainder(dec):
            raise UPER_Decoding_Error(
                "unexpected remainder",
                remaining=dec.remaining(),
            )
        return [], b""

    @staticmethod
    def sequence_build(field, pkt):
        # type: (Any, Any) -> bytes
        from scapy.asn1fields import ASN1F_field
        enc = UPER_Encoder()
        _UPER_FieldHooks.sequence_encode_into(field, enc, pkt)
        return ASN1F_field.i2m(field, pkt, enc.as_bytes())

    @staticmethod
    def _optionals(field):
        # type: (Any) -> Tuple[Any, ...]
        from scapy.asn1fields import ASN1F_optional
        return tuple(f for f in field.seq if isinstance(f, ASN1F_optional))

    @staticmethod
    def sequence_dissect_from_decoder(field, pkt, dec):
        # type: (Any, Any, Any) -> None
        from scapy.asn1fields import ASN1F_badsequence, ASN1F_optional
        if _field_extensible(field):
            if dec.read_bit():
                raise UPER_Decoding_Error(
                    "ASN1F_SEQUENCE: extension additions are not supported"
                )
        optionals = _UPER_FieldHooks._optionals(field)
        presence = [dec.read_bit() for _ in optionals]
        opt_idx = 0
        for obj in field.seq:
            if isinstance(obj, ASN1F_optional):
                if not presence[opt_idx]:
                    obj.set_absent(pkt)
                    opt_idx += 1
                    continue
                opt_idx += 1
            try:
                obj.dissect_from_decoder(pkt, dec)
            except ASN1F_badsequence:
                break

    @staticmethod
    def sequence_encode_into(field, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        from scapy.asn1fields import ASN1F_optional
        if _field_extensible(field):
            enc.append_bit(0)
        for opt in _UPER_FieldHooks._optionals(field):
            enc.append_bit(0 if opt.is_empty(pkt) else 1)
        for obj in field.seq:
            if isinstance(obj, ASN1F_optional) and obj.is_empty(pkt):
                continue
            obj.encode_into(enc, pkt)

    @staticmethod
    def sequence_of_m2i(field, pkt, s):
        # type: (Any, Any, bytes) -> Tuple[list, bytes]
        dec = UPER_Decoder(s)
        if _field_extensible(field) and dec.read_bit():
            count = dec.read_length_determinant()
        else:
            count = _uper_count_dec(field, dec)
        lst = []
        for _ in range(count):
            c, _ = _extract_packet_from_decoder(field, dec, pkt)
            if c:
                lst.append(c)
        if UPER_has_unexpected_remainder(dec):
            raise UPER_Decoding_Error(
                "unexpected remainder",
                remaining=dec.remaining(),
            )
        return lst, b""

    @staticmethod
    def sequence_of_build(field, pkt):
        # type: (Any, Any) -> bytes
        from scapy.asn1.asn1 import ASN1_Class_UNIVERSAL, ASN1_Object
        val = getattr(pkt, field.name)
        if isinstance(val, ASN1_Object) and val.tag == ASN1_Class_UNIVERSAL.RAW:
            s = val  # type: Any
        elif val is None:
            enc = UPER_Encoder()
            enc.append_length_determinant(0)
            s = enc.as_bytes()
        else:
            enc = UPER_Encoder()
            _UPER_FieldHooks.sequence_of_encode_into(field, enc, pkt, val)
            s = enc.as_bytes()
        return field.i2m(pkt, s)

    @staticmethod
    def sequence_of_m2i_from_decoder(field, pkt, dec):
        # type: (Any, Any, Any) -> list
        if _field_extensible(field) and dec.read_bit():
            count = dec.read_length_determinant()
        else:
            count = _uper_count_dec(field, dec)
        lst = []
        for _ in range(count):
            item, _ = _extract_packet_from_decoder(field, dec, pkt)
            lst.append(item)
        return lst

    @staticmethod
    def sequence_of_encode_into(field, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        if value is None:
            value = getattr(pkt, field.name)
        if value is None:
            _uper_count_enc(field, enc, 0)
            return
        count = len(value)
        uper_min, uper_max = _field_range(field)
        if _field_extensible(field):
            if (
                    uper_min is not None and uper_max is not None and
                    uper_min <= count <= uper_max
            ):
                enc.append_bit(0)
            else:
                enc.append_bit(1)
                enc.append_length_determinant(count)
                for item in value:
                    if field.holds_packets:
                        item.ASN1_root.encode_into(enc, item)
                    else:
                        field.fld.encode_into(enc, pkt, item)
                return
        _uper_count_enc(field, enc, count)
        for item in value:
            if field.holds_packets:
                item.ASN1_root.encode_into(enc, item)
            else:
                field.fld.encode_into(enc, pkt, item)

    @staticmethod
    def choice_m2i(field, pkt, s):
        # type: (Any, Any, bytes) -> Tuple[Any, bytes]
        dec = UPER_Decoder(s)
        val = _UPER_FieldHooks.choice_m2i_from_decoder(field, pkt, dec)
        if UPER_has_unexpected_remainder(dec):
            raise UPER_Decoding_Error(
                "unexpected remainder",
                remaining=dec.remaining(),
            )
        return val, b""

    @staticmethod
    def choice_i2m(field, pkt, x):
        # type: (Any, Any, Any) -> bytes
        if x is None:
            s = b""
        else:
            enc = UPER_Encoder()
            _UPER_FieldHooks.choice_encode_into(field, enc, pkt, x)
            s = enc.as_bytes()
        return field._tagging_enc(pkt, s, explicit_tag=field.explicit_tag)

    @staticmethod
    def choice_m2i_from_decoder(field, pkt, dec):
        # type: (Any, Any, Any) -> Any
        from scapy.asn1.asn1 import ASN1_Error
        if _field_extensible(field):
            if dec.read_bit():
                raise UPER_Decoding_Error(
                    "ASN1F_CHOICE: extension additions are not supported"
                )
        order = field.choice_order
        if len(order) > 1:
            index, _ = UPER_choice_index_dec(b"", len(order), dec=dec)
        else:
            index = 0
        if index >= len(order):
            raise ASN1_Error(
                "ASN1F_CHOICE: unexpected index %s in '%s'" %
                (index, field.name)
            )
        choice = field.choice_list[index]
        if isinstance(choice, type) and hasattr(choice, "ASN1_root"):
            p = choice()
            p.add_underlayer(pkt)
            p.ASN1_root.dissect_from_decoder(p, dec)
            return p
        if isinstance(choice, type):
            return choice(field.name, b"").m2i_from_decoder(pkt, dec)
        return choice.m2i_from_decoder(pkt, dec)

    @staticmethod
    def choice_encode_into(field, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        from scapy.asn1.asn1 import ASN1_Error
        if value is None:
            value = getattr(pkt, field.name)
        index = _choice_index_for(field, value)
        if index is None:
            raise ASN1_Error(
                "ASN1F_CHOICE: cannot encode unknown alternative in '%s'" %
                field.name
            )
        if _field_extensible(field):
            enc.append_bit(0)
        order = field.choice_order
        if len(order) > 1:
            UPER_choice_index_enc(index, len(order), enc=enc)
        choice = field.choice_list[index]
        if hasattr(choice, "ASN1_root"):
            value.ASN1_root.encode_into(enc, value)
        elif isinstance(choice, type):
            choice(field.name, b"").encode_into(enc, pkt, value)
        else:
            choice.encode_into(enc, pkt, value)

    @staticmethod
    def packet_m2i_from_decoder(field, pkt, dec):
        # type: (Any, Any, Any) -> Any
        cls = field._resolve_cls(pkt)
        p = cls()
        p.add_underlayer(pkt)
        p.ASN1_root.dissect_from_decoder(p, dec)
        return p

    @staticmethod
    def packet_i2m(field, pkt, x):
        # type: (Any, Any, Any) -> bytes
        if x is None:
            s = b""
        else:
            enc = UPER_Encoder()
            _UPER_FieldHooks.packet_encode_into(field, enc, pkt, x)
            s = enc.as_bytes()
        return field._tagging_enc(
            pkt, s,
            implicit_tag=field.implicit_tag,
            explicit_tag=field.explicit_tag,
        )

    @staticmethod
    def packet_encode_into(field, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        from scapy.asn1.asn1 import ASN1_Object
        if value is None:
            value = getattr(pkt, field.name)
        if value is None:
            return
        if isinstance(value, ASN1_Object):
            value = value.val
        value.ASN1_root.encode_into(enc, value)


def _choice_index_for(field, x):
    # type: (Any, Any) -> Optional[int]
    from scapy.asn1.asn1 import ASN1_Object
    for index, choice in enumerate(field.choice_list):
        if isinstance(choice, type) and hasattr(choice, "ASN1_root"):
            if isinstance(x, choice):
                return index
        elif hasattr(choice, "ASN1_tag"):
            if isinstance(x, ASN1_Object) and x.tag == choice.ASN1_tag:
                return index
    return None


def _uper_count_enc(field, enc, count):
    # type: (Any, Any, int) -> None
    uper_min, uper_max = _field_range(field)
    if uper_min is not None and uper_max is not None:
        UPER_constrained_int_enc(count, uper_min, uper_max, enc=enc)
    else:
        enc.append_length_determinant(count)


def _uper_count_dec(field, dec):
    # type: (Any, Any) -> int
    uper_min, uper_max = _field_range(field)
    if uper_min is not None and uper_max is not None:
        size = uper_max - uper_min
        return (
            dec.read_non_negative_binary_integer(UPER_bits_for_range(size)) +
            uper_min
        )
    return dec.read_length_determinant()


def _extract_packet_from_decoder(field, dec, pkt):
    # type: (Any, Any, Any) -> Tuple[Any, bytes]
    if field.holds_packets:
        p = field.cls()
        p.add_underlayer(pkt)
        p.ASN1_root.dissect_from_decoder(p, dec)
        return p, b""
    return field.fld.m2i_from_decoder(pkt, dec), b""


# Populated by _install_uper_asn1fields() (also published on scapy.asn1fields).
ASN1F_DEFAULT = None  # type: Any


def _install_uper_asn1fields():
    # type: () -> None
    """Attach UPER bitstream helpers and DEFAULT onto asn1fields classes."""
    from scapy import asn1fields as af
    from scapy.asn1.asn1 import ASN1_Class_UNIVERSAL, ASN1_Error, ASN1_Object

    class _ASN1F_DEFAULT(af.ASN1F_optional):
        """ASN.1 field with a DEFAULT value (PER presence bit)."""

        def __init__(self, field, default):
            # type: (Any, Any) -> None
            super(_ASN1F_DEFAULT, self).__init__(field)
            self._default = default

        def is_empty(self, pkt):
            # type: (Any) -> bool
            val = getattr(pkt, self._field.name, None)
            if val is None:
                return True
            if isinstance(val, ASN1_Object):
                val = val.val
            default = self._default
            if isinstance(default, ASN1_Object):
                default = default.val
            return bool(val == default)

        def set_absent(self, pkt):
            # type: (Any) -> None
            self.set_val(pkt, self._default)

    global ASN1F_DEFAULT
    ASN1F_DEFAULT = _ASN1F_DEFAULT  # type: ignore[misc,assignment]
    af.ASN1F_DEFAULT = _ASN1F_DEFAULT

    def m2i_from_decoder(self, pkt, dec):
        # type: (Any, Any, Any) -> Any
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        return codec.dec_from_decoder(  # type: ignore[attr-defined]  # noqa: E501
            dec, **self._codec_kwargs(pkt),
        )

    def dissect_from_decoder(self, pkt, dec):
        # type: (Any, Any, Any) -> None
        self.set_val(pkt, self.m2i_from_decoder(pkt, dec))

    def encode_into(self, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        if value is None:
            value = getattr(pkt, self.name)
        if value is None:
            return
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        if isinstance(value, ASN1_Object):
            if (self.ASN1_tag == ASN1_Class_UNIVERSAL.ANY or
                    value.tag == ASN1_Class_UNIVERSAL.RAW or
                    value.tag == ASN1_Class_UNIVERSAL.ERROR or
                    self.ASN1_tag == value.tag):
                raw = value.val
            else:
                raise ASN1_Error(
                    "Encoding Error: got %r instead of an %r for field [%s]" %
                    (value, self.ASN1_tag, self.name)
                )
        else:
            raw = value
        codec.encode_into(  # type: ignore[attr-defined]  # noqa: E501
            enc, raw, **self._codec_kwargs(pkt),
        )

    af.ASN1F_field.m2i_from_decoder = m2i_from_decoder  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_field.dissect_from_decoder = dissect_from_decoder  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_field.encode_into = encode_into  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_field._uper_encode_into = encode_into  # type: ignore[attr-defined]  # noqa: E501

    def seq_dissect_from_decoder(self, pkt, dec):
        # type: (Any, Any, Any) -> None
        return _UPER_FieldHooks.sequence_dissect_from_decoder(self, pkt, dec)

    def seq_encode_into(self, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        return _UPER_FieldHooks.sequence_encode_into(self, enc, pkt, value)

    af.ASN1F_SEQUENCE.dissect_from_decoder = seq_dissect_from_decoder  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_SEQUENCE.encode_into = seq_encode_into  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_SEQUENCE._uper_encode_into = seq_encode_into  # type: ignore[attr-defined]  # noqa: E501

    def seqof_m2i_from_decoder(self, pkt, dec):
        # type: (Any, Any, Any) -> Any
        return _UPER_FieldHooks.sequence_of_m2i_from_decoder(self, pkt, dec)

    def seqof_encode_into(self, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        return _UPER_FieldHooks.sequence_of_encode_into(self, enc, pkt, value)

    af.ASN1F_SEQUENCE_OF.m2i_from_decoder = seqof_m2i_from_decoder  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_SEQUENCE_OF.encode_into = seqof_encode_into  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_SEQUENCE_OF._uper_encode_into = seqof_encode_into  # type: ignore[attr-defined]  # noqa: E501

    def choice_m2i_from_decoder(self, pkt, dec):
        # type: (Any, Any, Any) -> Any
        return _UPER_FieldHooks.choice_m2i_from_decoder(self, pkt, dec)

    def choice_encode_into(self, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        return _UPER_FieldHooks.choice_encode_into(self, enc, pkt, value)

    af.ASN1F_CHOICE.m2i_from_decoder = choice_m2i_from_decoder  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_CHOICE.encode_into = choice_encode_into  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_CHOICE._uper_encode_into = choice_encode_into  # type: ignore[attr-defined]  # noqa: E501

    def packet_m2i_from_decoder(self, pkt, dec):
        # type: (Any, Any, Any) -> Any
        return _UPER_FieldHooks.packet_m2i_from_decoder(self, pkt, dec)

    def packet_encode_into(self, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        return _UPER_FieldHooks.packet_encode_into(self, enc, pkt, value)

    af.ASN1F_PACKET.m2i_from_decoder = packet_m2i_from_decoder  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_PACKET.encode_into = packet_encode_into  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_PACKET._uper_encode_into = packet_encode_into  # type: ignore[attr-defined]  # noqa: E501

    def opt_set_absent(self, pkt):
        # type: (Any, Any) -> None
        self.set_val(pkt, None)

    def opt_dissect_from_decoder(self, pkt, dec):
        # type: (Any, Any, Any) -> None
        return self._field.dissect_from_decoder(pkt, dec)

    def opt_encode_into(self, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        self._field.encode_into(enc, pkt, value)

    af.ASN1F_optional.set_absent = opt_set_absent  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_optional.dissect_from_decoder = opt_dissect_from_decoder  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_optional.encode_into = opt_encode_into  # type: ignore[attr-defined]  # noqa: E501
    af.ASN1F_optional._uper_encode_into = opt_encode_into  # type: ignore[attr-defined]  # noqa: E501

    _orig_enum_codec_kwargs = af.ASN1F_enum_INTEGER._codec_kwargs

    def enum_codec_kwargs(self, pkt):
        # type: (Any, Any) -> Any
        kwargs = _orig_enum_codec_kwargs(self, pkt)
        # The permitted values belong to the UPER encoding, not to the field
        # definition, so they are only added for PER packets. Other codecs
        # keep an empty codec_opts and their item.enc() fast path.
        codec = getattr(pkt, "ASN1_codec", None)
        if getattr(codec, "_field_hooks", None) is _UPER_FieldHooks:
            kwargs.setdefault("uper_enum_values", list(self.i2s))
        return kwargs

    af.ASN1F_enum_INTEGER._codec_kwargs = enum_codec_kwargs  # type: ignore[assignment]  # noqa: E501


_install_uper_asn1fields()
ASN1_Codecs.PER.register_field_hooks(_UPER_FieldHooks)
