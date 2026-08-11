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
``ASN1F_ENUMERATED``) is supported for common field types. Value ranges are
declared with ``uper_min=``/``uper_max=``, fixed sizes with ``size_len=``, and
an extension marker with ``uper_extensible=True``. Content of 16K units or
more is fragmented as required by 11.9.3.8.

Not supported yet: extension additions (an encoding that carries them is
refused rather than misparsed), SET, REAL, and the known-multiplier character
string encodings, which are emitted as plain octets rather than 7 or 4 bits
per character.
"""

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
    Callable,
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


# X.691 11.9.3.8: content of 16K units or more is split into fragments, each
# one holding a multiple of this many units.
UPER_FRAGMENT_SIZE = 16384


def _uper_bits_to_bytes(value, number_of_bits):
    # type: (int, int) -> bytes
    # X.691 11.1: an encoding is padded with zero bits up to an octet
    # boundary.
    if number_of_bits == 0:
        return b""
    padding = -number_of_bits % 8
    return (value << padding).to_bytes((number_of_bits + padding) // 8, "big")


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
        # type: (int) -> None
        # X.691 11.9.3.6/11.9.3.7 only define the one and two octet forms up
        # to 16K. Longer content has to be fragmented, which requires slicing
        # the content itself, so leave that to append_fragmented rather than
        # silently emitting a determinant that does not match what follows.
        if length >= UPER_FRAGMENT_SIZE:
            raise UPER_Encoding_Error(
                "UPER_Encoder: length %i requires fragmentation" % length
            )
        if length < 128:
            encoded = bytes([length])
        else:
            encoded = bytes([(0x80 | (length >> 8)), (length & 0xff)])
        self.append_bytes(encoded)

    def append_fragmented(self, count, append_units):
        # type: (int, Callable[[int, int], None]) -> None
        # X.691 11.9.3.8: emit the content as fragments of at most 4 * 16K
        # units, each preceded by its own determinant, and always terminate
        # with a determinant below 16K (possibly zero). append_units(offset,
        # size) appends the units of one fragment.
        offset = 0
        remaining = count
        while remaining >= UPER_FRAGMENT_SIZE:
            number_of_fragments = min(remaining // UPER_FRAGMENT_SIZE, 4)
            size = number_of_fragments * UPER_FRAGMENT_SIZE
            self.append_bytes(bytes([0xc0 | number_of_fragments]))
            append_units(offset, size)
            offset += size
            remaining -= size
        self.append_length_determinant(remaining)
        append_units(offset, remaining)

    def append_unconstrained_whole_number(self, value):
        # type: (int) -> None
        # X.691 11.4: the shortest two's complement encoding. A negative value
        # needs one bit less than its magnitude suggests, as -2**(8n-1) still
        # fits in n octets, hence the increment before measuring.
        magnitude = value + 1 if value < 0 else value
        number_of_bytes = (magnitude.bit_length() + 8) // 8
        self.append_length_determinant(number_of_bytes)
        self.append_non_negative_binary_integer(
            value & ((1 << (8 * number_of_bytes)) - 1), 8 * number_of_bytes
        )

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
        return _uper_bits_to_bytes(value, number_of_bits)


def UPER_has_unexpected_remainder(dec):
    # type: (UPER_Decoder) -> bool
    if dec.number_of_bits == 0:
        return False
    mask = (1 << dec.number_of_bits) - 1
    return (dec._bits & mask) != 0


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
        return _uper_bits_to_bytes(value, number_of_bits)

    def remaining(self):
        # type: () -> bytes
        if self.number_of_bits == 0:
            return b""
        value = self._read_bits_int(self.number_of_bits)
        return _uper_bits_to_bytes(value, self.number_of_bits)

    def remaining_bytes(self):
        # type: () -> bytes
        # A standalone UPER encoding is padded to an octet boundary, so the
        # bits left over inside the current octet are padding; only whole
        # octets after it are actual remaining input.
        pad = -self._read_offset() % 8
        self.number_of_bits = max(0, self.number_of_bits - pad)
        return self.remaining()

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

    def _read_length_determinant(self):
        # type: () -> Tuple[int, bool]
        # Returns the number of units and whether more fragments follow.
        value = self.read_non_negative_binary_integer(8)
        if (value & 0x80) == 0x00:
            return value, False
        if (value & 0xc0) == 0x80:
            return (
                ((value & 0x7f) << 8) |
                self.read_non_negative_binary_integer(8)
            ), False
        if 0xc1 <= value <= 0xc4:
            return (value & 0x0f) * UPER_FRAGMENT_SIZE, True
        raise UPER_Decoding_Error(
            "UPER_Decoder: bad length determinant 0x%02x" % value
        )

    def read_length_determinant(self):
        # type: () -> int
        length, fragmented = self._read_length_determinant()
        if fragmented:
            raise UPER_Decoding_Error(
                "UPER_Decoder: unexpected fragmented length determinant"
            )
        return length

    def read_fragmented(self, read_units):
        # type: (Callable[[int], None]) -> None
        # Counterpart of UPER_Encoder.append_fragmented: read_units(size) is
        # called once per fragment, the last one being the (possibly empty)
        # fragment introduced by a determinant below 16K.
        while True:
            size, fragmented = self._read_length_determinant()
            read_units(size)
            if not fragmented:
                return

    def read_unconstrained_whole_number(self):
        # type: () -> int
        number_of_bytes = self.read_length_determinant()
        if number_of_bytes == 0:
            raise UPER_Decoding_Error(
                "UPER_Decoder: integer with an empty length determinant"
            )
        enc = self.read_non_negative_binary_integer(8 * number_of_bytes)
        sign_bit = 1 << (8 * number_of_bytes - 1)
        if enc & sign_bit:
            return enc - (1 << (8 * number_of_bytes))
        return enc

    def consume_input(self):
        # type: () -> None
        self.number_of_bits = 0


def UPER_constrained_int_enc(enc, value, minimum, maximum):
    # type: (UPER_Encoder, int, int, int) -> None
    enc.append_non_negative_binary_integer(
        value - minimum, UPER_bits_for_range(maximum - minimum)
    )


def UPER_constrained_int_dec(dec, minimum, maximum):
    # type: (UPER_Decoder, int, int) -> int
    value = dec.read_non_negative_binary_integer(
        UPER_bits_for_range(maximum - minimum)
    )
    return value + minimum


def UPER_octet_string_enc(enc, data, minimum=None, maximum=None):
    # type: (UPER_Encoder, bytes, Optional[int], Optional[int]) -> None
    if minimum is not None and maximum is not None:
        if minimum != maximum:
            enc.append_non_negative_binary_integer(
                len(data) - minimum,
                UPER_bits_for_range(maximum - minimum),
            )
        enc.append_bytes(data)
    else:
        enc.append_fragmented(
            len(data),
            lambda offset, size: enc.append_bytes(data[offset:offset + size]),
        )


def UPER_octet_string_dec(dec, minimum=None, maximum=None):
    # type: (UPER_Decoder, Optional[int], Optional[int]) -> bytes
    if minimum is not None and maximum is not None:
        length = minimum
        if minimum != maximum:
            length += dec.read_non_negative_binary_integer(
                UPER_bits_for_range(maximum - minimum)
            )
        return dec.read_bytes(length)
    fragments = []  # type: List[bytes]
    dec.read_fragmented(lambda size: fragments.append(dec.read_bytes(size)))
    return b"".join(fragments)


def UPER_choice_index_enc(enc, index, number_of_choices):
    # type: (UPER_Encoder, int, int) -> None
    enc.append_non_negative_binary_integer(
        index, UPER_bits_for_range(number_of_choices - 1)
    )


def UPER_choice_index_dec(dec, number_of_choices):
    # type: (UPER_Decoder, int) -> int
    return dec.read_non_negative_binary_integer(
        UPER_bits_for_range(number_of_choices - 1)
    )


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

    # The bit-oriented encode_into()/dec_from_decoder() pair is the primitive
    # every codec implements; enc()/do_dec() below are the standalone (byte
    # buffer) entry points, and pass every codec option straight through.

    @classmethod
    def encode_into(cls, enc, s, **kwargs):
        # type: (UPER_Encoder, Any, **Any) -> None
        # No schema information here (ANY): guess from the Python type.
        if isinstance(s, (str, bytes)):
            UPERcodec_STRING.encode_into(enc, s, **kwargs)
            return
        try:
            UPERcodec_INTEGER.encode_into(enc, int(s), **kwargs)
        except Exception:
            raise UPER_Encoding_Error(
                "Cannot encode value %r for %s" % (s, cls.__name__),
                encoded=s
            )

    @classmethod
    def dec_from_decoder(cls, dec, **kwargs):
        # type: (UPER_Decoder, **Any) -> ASN1_Object[Any]
        raise UPER_Decoding_Error(
            "%s: Cannot decode unknown UPER type without context" %
            cls.__name__, remaining=dec.remaining()
        )

    @classmethod
    def enc(cls, s, **kwargs):
        # type: (Any, **Any) -> bytes
        enc = UPER_Encoder()
        cls.encode_into(enc, s, **kwargs)
        return enc.as_bytes()

    @classmethod
    def do_dec(cls, s, context=None, safe=False, **kwargs):
        # type: (bytes, Optional[Type[ASN1_Class]], bool, **Any) -> Tuple[ASN1_Object[Any], bytes]  # noqa: E501
        dec = UPER_Decoder(s)
        return cls.dec_from_decoder(dec, **kwargs), dec.remaining_bytes()

    @classmethod
    def dec(cls, s, context=None, safe=False, **kwargs):
        # type: (bytes, Optional[Type[ASN1_Class]], bool, **Any) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]  # noqa: E501
        if not safe:
            return cls.do_dec(s, context, safe, **kwargs)
        try:
            return cls.do_dec(s, context, safe, **kwargs)
        except UPER_BadTag_Decoding_Error as e:
            o, remain = UPERcodec_Object.dec(
                e.remaining, context, safe, **kwargs
            )
            return ASN1_BADTAG(o), remain
        except (UPER_Decoding_Error, ASN1_Error) as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""

    @classmethod
    def safedec(cls, s, context=None, **kwargs):
        # type: (bytes, Optional[Type[ASN1_Class]], **Any) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]  # noqa: E501
        return cls.dec(s, context, safe=True, **kwargs)


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
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        minimum, maximum = _uper_int_range(size_len, uper_min, uper_max, oer_unsigned)
        if uper_extensible and minimum is not None and maximum is not None:
            if minimum <= i <= maximum:
                enc.append_bit(0)
            else:
                enc.append_bit(1)
                enc.append_unconstrained_whole_number(i)
                return
        if minimum is not None and maximum is not None:
            UPER_constrained_int_enc(enc, i, minimum, maximum)
        else:
            enc.append_unconstrained_whole_number(i)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         size_len=0,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         oer_unsigned=False,  # type: bool
                         uper_extensible=False,  # type: bool
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[int]
        minimum, maximum = _uper_int_range(size_len, uper_min, uper_max, oer_unsigned)
        if uper_extensible and minimum is not None and maximum is not None:
            if dec.read_bit():
                value = dec.read_unconstrained_whole_number()
                return cls.asn1_object(value)
        if minimum is not None and maximum is not None:
            value = UPER_constrained_int_dec(dec, minimum, maximum)
        else:
            value = dec.read_unconstrained_whole_number()
        return cls.asn1_object(value)


class UPERcodec_BOOLEAN(UPERcodec_Object[int]):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN

    @classmethod
    def encode_into(cls, enc, i, **_kwargs):
        # type: (UPER_Encoder, int, **Any) -> None
        enc.append_bit(1 if i else 0)

    @classmethod
    def dec_from_decoder(cls, dec, **_kwargs):
        # type: (UPER_Decoder, **Any) -> ASN1_Object[int]
        return cls.asn1_object(dec.read_bit())


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


def _uper_size_bounds(size_len, uper_min, uper_max):
    # type: (Optional[int], Optional[int], Optional[int]) -> Tuple[Optional[int], Optional[int]]  # noqa: E501
    # A SIZE constraint given as size_len is a fixed size, i.e. a range whose
    # bounds coincide.
    if size_len:
        return size_len, size_len
    return uper_min, uper_max


class UPERcodec_BIT_STRING(UPERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    _s,  # type: Any
                    size_len=0,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        s, nbits = _uper_bit_string_parts(_s)
        minimum, maximum = _uper_size_bounds(size_len, uper_min, uper_max)
        if minimum is not None and maximum is not None:
            if not minimum <= nbits <= maximum:
                raise UPER_Encoding_Error(
                    "UPERcodec_BIT_STRING: got %i bits while expecting %s" %
                    (nbits, minimum if minimum == maximum
                     else "%i..%i" % (minimum, maximum))
                )
            if minimum != maximum:
                enc.append_non_negative_binary_integer(
                    nbits - minimum, UPER_bits_for_range(maximum - minimum)
                )
            enc.append_bits(s, nbits)
        else:
            # X.691 16.11: the determinant counts bits, not octets, and no
            # padding is inserted before whatever follows the bit string.
            enc.append_fragmented(
                nbits,
                # Fragments hold whole multiples of 16K bits, so every chunk
                # but the last starts and ends on an octet boundary.
                lambda offset, size: enc.append_bits(
                    s[offset // 8:(offset + size + 7) // 8], size
                ),
            )

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         size_len=0,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[str]
        minimum, maximum = _uper_size_bounds(size_len, uper_min, uper_max)
        if minimum is not None and maximum is not None:
            nbits = minimum
            if minimum != maximum:
                nbits += dec.read_non_negative_binary_integer(
                    UPER_bits_for_range(maximum - minimum)
                )
        else:
            fragments = []  # type: List[bytes]
            sizes = []  # type: List[int]

            def read_fragment(size):
                # type: (int) -> None
                fragments.append(dec.read_bits(size))
                sizes.append(size)

            dec.read_fragmented(read_fragment)
            return cls.asn1_object(
                _uper_bytes_to_bitstr(b"".join(fragments), sum(sizes))
            )
        raw = dec.read_bits(nbits)
        return cls.asn1_object(_uper_bytes_to_bitstr(raw, nbits))


class UPERcodec_STRING(UPERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.STRING

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    _s,  # type: Union[str, bytes]
                    size_len=0,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        s = bytes_encode(_s)
        minimum, maximum = _uper_size_bounds(size_len, uper_min, uper_max)
        UPER_octet_string_enc(enc, s, minimum, maximum)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         size_len=0,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[Any]
        minimum, maximum = _uper_size_bounds(size_len, uper_min, uper_max)
        raw = UPER_octet_string_dec(dec, minimum, maximum)
        return cls.asn1_object(raw)


class UPERcodec_NULL(UPERcodec_Object[None]):
    tag = ASN1_Class_UNIVERSAL.NULL

    @classmethod
    def encode_into(cls, enc, _s, **_kwargs):
        # type: (UPER_Encoder, Any, **Any) -> None
        # NULL has an empty encoding.
        return

    @classmethod
    def dec_from_decoder(cls, dec, **_kwargs):
        # type: (UPER_Decoder, **Any) -> ASN1_Object[None]
        return cls.asn1_object(None)

    @classmethod
    def do_dec(cls, s, context=None, safe=False, **kwargs):
        # type: (bytes, Optional[Type[ASN1_Class]], bool, **Any) -> Tuple[ASN1_Object[None], bytes]  # noqa: E501
        # NULL occupies no bits at all, so the input is left untouched.
        return cls.asn1_object(None), s


class UPERcodec_OID(UPERcodec_Object[bytes]):
    tag = ASN1_Class_UNIVERSAL.OID

    @classmethod
    def encode_into(cls, enc, _oid, **_kwargs):
        # type: (UPER_Encoder, AnyStr, **Any) -> None
        oid = bytes_encode(_oid)
        if oid:
            lst = [int(x) for x in oid.split(b".")]
            lst = [40 * lst[0] + lst[1]] + lst[2:]
        else:
            lst = []
        body = b"".join(BER_num_enc(k) for k in lst)
        enc.append_fragmented(
            len(body),
            lambda offset, size: enc.append_bytes(body[offset:offset + size]),
        )

    @classmethod
    def dec_from_decoder(cls, dec, **_kwargs):
        # type: (UPER_Decoder, **Any) -> ASN1_Object[bytes]
        fragments = []  # type: List[bytes]
        dec.read_fragmented(lambda size: fragments.append(dec.read_bytes(size)))
        content = b"".join(fragments)
        lst = []
        while content:
            val, content = BER_num_dec(content)
            lst.append(val)
        if len(lst) > 0:
            lst.insert(0, lst[0] // 40)
            lst[1] %= 40
        return cls.asn1_object(b".".join(str(k).encode('ascii') for k in lst))


def UPER_enumerated_enc(enc, value, enum_values):
    # type: (UPER_Encoder, int, List[int]) -> None
    if not enum_values:
        raise UPER_Encoding_Error("UPER_enumerated_enc: empty enumeration")
    try:
        index = enum_values.index(value)
    except ValueError:
        raise UPER_Encoding_Error(
            "UPER_enumerated_enc: unknown enumeration value %r" % value
        )
    UPER_choice_index_enc(enc, index, len(enum_values))


def UPER_enumerated_dec(dec, enum_values):
    # type: (UPER_Decoder, List[int]) -> int
    if not enum_values:
        raise UPER_Decoding_Error("UPER_enumerated_dec: empty enumeration")
    index = UPER_choice_index_dec(dec, len(enum_values))
    if index >= len(enum_values):
        raise UPER_Decoding_Error(
            "UPER_enumerated_dec: index %i out of range" % index
        )
    return enum_values[index]


class UPERcodec_ENUMERATED(UPERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.ENUMERATED

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    i,  # type: int
                    size_len=0,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    uper_enum_values=None,  # type: Optional[List[int]]
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        if uper_enum_values is not None:
            UPER_enumerated_enc(enc, i, uper_enum_values)
            return
        minimum = uper_min if uper_min is not None else 0
        maximum = uper_max if uper_max is not None else size_len
        if maximum is None:
            maximum = max(i, 0)
        UPER_constrained_int_enc(enc, i, minimum, maximum)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         size_len=0,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         uper_enum_values=None,  # type: Optional[List[int]]
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[int]
        if uper_enum_values is not None:
            value = UPER_enumerated_dec(dec, uper_enum_values)
            return cls.asn1_object(value)
        minimum = uper_min if uper_min is not None else 0
        maximum = uper_max if uper_max is not None else size_len
        if maximum is None:
            raise UPER_Decoding_Error("UPERcodec_ENUMERATED: missing range")
        value = dec.read_non_negative_binary_integer(
            UPER_bits_for_range(maximum - minimum)
        ) + minimum
        return cls.asn1_object(value)


class UPERcodec_SEQUENCE(UPERcodec_Object[Union[bytes, List[Any]]]):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE

    @classmethod
    def encode_into(cls, enc, _ll, **_kwargs):
        # type: (UPER_Encoder, Any, **Any) -> None
        # A finished encoding is padded to an octet boundary, so its real bit
        # length is lost and it cannot be spliced into a bitstream. Sequences
        # are encoded through the ASN1F_SEQUENCE hooks instead.
        raise UPER_Encoding_Error(
            "UPERcodec_SEQUENCE: schema-defined field order required"
        )

    @classmethod
    def enc(cls, _ll, **_kwargs):
        # type: (Union[bytes, List[UPERcodec_Object[Any]]], **Any) -> bytes
        if isinstance(_ll, bytes):
            return _ll
        raise UPER_Encoding_Error(
            "UPERcodec_SEQUENCE: schema-defined field order required"
        )

    @classmethod
    def dec_from_decoder(cls, dec, **_kwargs):
        # type: (UPER_Decoder, **Any) -> ASN1_Object[Union[bytes, List[Any]]]
        raise UPER_Decoding_Error(
            "UPERcodec_SEQUENCE: decoding requires schema-defined field order",
            remaining=dec.remaining()
        )


class UPERcodec_SET(UPERcodec_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET


class UPERcodec_IPADDRESS(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IPADDRESS

    @classmethod
    def encode_into(cls, enc, ipaddr_ascii, **_kwargs):
        # type: (UPER_Encoder, str, **Any) -> None
        try:
            s = inet_aton(ipaddr_ascii)
        except Exception:
            raise UPER_Encoding_Error("IPv4 address could not be encoded")
        UPER_octet_string_enc(enc, s, 4, 4)

    @classmethod
    def dec_from_decoder(cls, dec, **_kwargs):
        # type: (UPER_Decoder, **Any) -> ASN1_Object[str]
        raw = UPER_octet_string_dec(dec, 4, 4)
        try:
            ipaddr_ascii = inet_ntoa(raw)
        except Exception:
            raise UPER_Decoding_Error("IP address could not be decoded")
        return cls.asn1_object(ipaddr_ascii)


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


def _uper_decode_all(s, read):
    # type: (bytes, Callable[[UPER_Decoder], Any]) -> Any
    # The field owns the whole substring it was handed, so any bit left set
    # beyond the octet padding means the encoding did not match the schema.
    dec = UPER_Decoder(s)
    value = read(dec)
    if UPER_has_unexpected_remainder(dec):
        raise UPER_Decoding_Error(
            "unexpected remainder",
            remaining=dec.remaining(),
        )
    return value


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
        _uper_decode_all(s, lambda dec: (
            _UPER_FieldHooks.sequence_dissect_from_decoder(field, pkt, dec)
        ))
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
        return _uper_decode_all(s, lambda dec: (
            _UPER_FieldHooks.sequence_of_m2i_from_decoder(field, pkt, dec)
        )), b""

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
        lst = []

        def read_items(count):
            # type: (int) -> None
            for _ in range(count):
                item = _extract_packet_from_decoder(field, dec, pkt)
                lst.append(item)

        if _field_extensible(field) and dec.read_bit():
            dec.read_fragmented(read_items)
        else:
            _uper_count_dec(field, dec, read_items)
        return lst

    @staticmethod
    def sequence_of_encode_into(field, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        if value is None:
            value = getattr(pkt, field.name)
        if value is None:
            _uper_count_enc(field, enc, 0, lambda offset, size: None)
            return
        count = len(value)

        def append_items(offset, size):
            # type: (int, int) -> None
            for item in value[offset:offset + size]:
                if field.holds_packets:
                    item.ASN1_root.encode_into(enc, item)
                else:
                    field.fld.encode_into(enc, pkt, item)

        uper_min, uper_max = _field_range(field)
        if _field_extensible(field):
            if (
                    uper_min is not None and uper_max is not None and
                    uper_min <= count <= uper_max
            ):
                enc.append_bit(0)
            else:
                enc.append_bit(1)
                enc.append_fragmented(count, append_items)
                return
        _uper_count_enc(field, enc, count, append_items)

    @staticmethod
    def choice_m2i(field, pkt, s):
        # type: (Any, Any, bytes) -> Tuple[Any, bytes]
        return _uper_decode_all(s, lambda dec: (
            _UPER_FieldHooks.choice_m2i_from_decoder(field, pkt, dec)
        )), b""

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
            index = UPER_choice_index_dec(dec, len(order))
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
            UPER_choice_index_enc(enc, index, len(order))
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


def _uper_count_enc(field, enc, count, append_items):
    # type: (Any, Any, int, Callable[[int, int], None]) -> None
    # The count of a SEQUENCE OF is a constrained whole number when the field
    # carries a size constraint; otherwise it is a length determinant, and the
    # items themselves are what gets fragmented, hence the callback.
    uper_min, uper_max = _field_range(field)
    if uper_min is not None and uper_max is not None:
        UPER_constrained_int_enc(enc, count, uper_min, uper_max)
        append_items(0, count)
    else:
        enc.append_fragmented(count, append_items)


def _uper_count_dec(field, dec, read_items):
    # type: (Any, Any, Callable[[int], None]) -> None
    uper_min, uper_max = _field_range(field)
    if uper_min is not None and uper_max is not None:
        read_items(UPER_constrained_int_dec(dec, uper_min, uper_max))
    else:
        dec.read_fragmented(read_items)


def _extract_packet_from_decoder(field, dec, pkt):
    # type: (Any, Any, Any) -> Any
    if field.holds_packets:
        p = field.cls()
        p.add_underlayer(pkt)
        p.ASN1_root.dissect_from_decoder(p, dec)
        return p
    return field.fld.m2i_from_decoder(pkt, dec)


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
        return codec.dec_from_decoder(  # type: ignore[attr-defined]
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
        codec.encode_into(  # type: ignore[attr-defined]
            enc, raw, **self._codec_kwargs(pkt),
        )

    def opt_set_absent(self, pkt):
        # type: (Any, Any) -> None
        self.set_val(pkt, None)

    def opt_dissect_from_decoder(self, pkt, dec):
        # type: (Any, Any, Any) -> None
        return self._field.dissect_from_decoder(pkt, dec)

    def opt_encode_into(self, enc, pkt, value=None):
        # type: (Any, Any, Any, Any) -> None
        self._field.encode_into(enc, pkt, value)

    hooks = _UPER_FieldHooks
    for field_cls, methods in (
        (af.ASN1F_field, {
            "m2i_from_decoder": m2i_from_decoder,
            "dissect_from_decoder": dissect_from_decoder,
            "encode_into": encode_into,
        }),
        (af.ASN1F_SEQUENCE, {
            "dissect_from_decoder": hooks.sequence_dissect_from_decoder,
            "encode_into": hooks.sequence_encode_into,
        }),
        (af.ASN1F_SEQUENCE_OF, {
            "m2i_from_decoder": hooks.sequence_of_m2i_from_decoder,
            "encode_into": hooks.sequence_of_encode_into,
        }),
        (af.ASN1F_CHOICE, {
            "m2i_from_decoder": hooks.choice_m2i_from_decoder,
            "encode_into": hooks.choice_encode_into,
        }),
        (af.ASN1F_PACKET, {
            "m2i_from_decoder": hooks.packet_m2i_from_decoder,
            "encode_into": hooks.packet_encode_into,
        }),
        (af.ASN1F_optional, {
            "set_absent": opt_set_absent,
            "dissect_from_decoder": opt_dissect_from_decoder,
            "encode_into": opt_encode_into,
        }),
    ):
        for method_name, func in methods.items():
            setattr(field_cls, method_name, func)

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

    af.ASN1F_enum_INTEGER._codec_kwargs = enum_codec_kwargs  # type: ignore[assignment]


_install_uper_asn1fields()
ASN1_Codecs.PER.register_field_hooks(_UPER_FieldHooks)
