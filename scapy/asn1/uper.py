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

``ASN1F_CHOICE`` alternatives are indexed in X.691 10.2 canonical tag order
(via ``ASN1F_CHOICE.canonical_order``). Declaration order is kept for
``alternative_index`` / BER tag lookup.
"""

from scapy.compat import orb, bytes_encode
from scapy.utils import binrepr, inet_aton, inet_ntoa
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
    Callable,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)


###################
#  UPER encoding  #
###################


class UPER_Encoding_Error(ASN1_Encoding_Error):
    codec_label = "UPER"


class UPER_Decoding_Error(ASN1_Decoding_Error):
    codec_label = "UPER"


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
    """True when unread bits remain after an octet-aligned padding check.

    Prefer :meth:`UPER_Decoder.remaining_bytes` at packet boundaries; this
    helper only reports whether non-padding bits are still pending.
    """
    pad = -dec._read_offset() % 8
    unread = max(0, dec.number_of_bits - pad)
    return unread != 0


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
        # octets after it are actual remaining input / Scapy payload.
        pad = -self._read_offset() % 8
        if pad:
            if pad > self.number_of_bits:
                raise UPER_Decoding_Error("UPER_Decoder: truncated padding")
            if self._read_bits_int(pad) != 0:
                raise UPER_Decoding_Error(
                    "UPER_Decoder: non-zero padding bits",
                    remaining=self.remaining(),
                )
            self.number_of_bits -= pad
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


def UPER_constrained_int_enc(enc, value, minimum, maximum):
    # type: (UPER_Encoder, int, int, int) -> None
    # X.691 13.2.2: the field is sized after the range, so a value outside it
    # cannot be expressed. Callers handle extensibility before coming here.
    if not minimum <= value <= maximum:
        raise UPER_Encoding_Error(
            "UPER_constrained_int_enc: got %i while expecting %i..%i" %
            (value, minimum, maximum)
        )
    enc.append_non_negative_binary_integer(
        value - minimum, UPER_bits_for_range(maximum - minimum)
    )


def UPER_constrained_int_dec(dec, minimum, maximum):
    # type: (UPER_Decoder, int, int) -> int
    value = dec.read_non_negative_binary_integer(
        UPER_bits_for_range(maximum - minimum)
    )
    value += minimum
    if not minimum <= value <= maximum:
        raise UPER_Decoding_Error(
            "UPER_constrained_int_dec: got %i while expecting %i..%i" %
            (value, minimum, maximum)
        )
    return value


def _uper_check_size(name, unit, count, minimum, maximum):
    # type: (str, str, int, int, int) -> None
    # The determinant is sized after the constraint, so a value that violates
    # it cannot be expressed: refuse rather than emit something the peer reads
    # as a different length.
    if not minimum <= count <= maximum:
        raise UPER_Encoding_Error(
            "%s: got %i %s while expecting %s" %
            (name, count, unit, minimum if minimum == maximum
             else "%i..%i" % (minimum, maximum))
        )


def UPER_octet_string_enc(enc, data, minimum=None, maximum=None):
    # type: (UPER_Encoder, bytes, Optional[int], Optional[int]) -> None
    if minimum is not None and maximum is not None:
        _uper_check_size(
            "UPER_octet_string_enc", "octets", len(data), minimum, maximum,
        )
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


class UPERcodec_metaclass(ASN1Codec_metaclass):
    pass


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
        except (UPER_Decoding_Error, ASN1_Error) as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""

    @classmethod
    def safedec(cls, s, context=None, **kwargs):
        # type: (bytes, Optional[Type[ASN1_Class]], **Any) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]  # noqa: E501
        return cls.dec(s, context, safe=True, **kwargs)


# No field tagging on the wire for PER; identity keeps the codec extension
# point without BER-style wrappers.
def _uper_tagging_enc(s, **_kwargs):
    # type: (bytes, **Any) -> bytes
    return s


def _uper_tagging_dec(s, **_kwargs):
    # type: (bytes, **Any) -> Tuple[Optional[int], bytes]
    return None, s


ASN1_Codecs.PER.register_stem(UPERcodec_Object)
ASN1_Codecs.PER.register_tagging(_uper_tagging_enc, _uper_tagging_dec)


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
                    field=None,  # type: Any
                    size_len=None,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    oer_unsigned=None,  # type: Optional[bool]
                    uper_extensible=None,  # type: Optional[bool]
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        from scapy.asn1.constraints import (
            oer_size_len,
            oer_unsigned as _oer_unsigned,
            uper_extensible as _uper_extensible,
            uper_int_range,
        )
        size_len = oer_size_len(field, size_len)
        uper_min, uper_max = uper_int_range(field, uper_min, uper_max)
        oer_unsigned = _oer_unsigned(field, oer_unsigned)
        extensible = _uper_extensible(field, uper_extensible)
        minimum, maximum = _uper_int_range(
            size_len, uper_min, uper_max, oer_unsigned,
        )
        if extensible and minimum is not None and maximum is not None:
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
                         field=None,  # type: Any
                         pkt=None,  # type: Any
                         size_len=None,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         oer_unsigned=None,  # type: Optional[bool]
                         uper_extensible=None,  # type: Optional[bool]
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[int]
        from scapy.asn1.constraints import (
            oer_size_len,
            oer_unsigned as _oer_unsigned,
            uper_extensible as _uper_extensible,
            uper_int_range,
        )
        size_len = oer_size_len(field, size_len)
        uper_min, uper_max = uper_int_range(field, uper_min, uper_max)
        oer_unsigned = _oer_unsigned(field, oer_unsigned)
        extensible = _uper_extensible(field, uper_extensible)
        minimum, maximum = _uper_int_range(
            size_len, uper_min, uper_max, oer_unsigned,
        )
        if extensible and minimum is not None and maximum is not None:
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
                    field=None,  # type: Any
                    size_len=None,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        from scapy.asn1.constraints import oer_size_len, uper_int_range
        size_len = oer_size_len(field, size_len)
        uper_min, uper_max = uper_int_range(field, uper_min, uper_max)
        if isinstance(_s, tuple) and len(_s) == 2:
            data, nbits = _s
            s = bytes_encode(data)
        elif isinstance(_s, str) and _s and all(c in "01" for c in _s):
            nbits = len(_s)
            padded = _s + "0" * ((8 - nbits % 8) % 8)
            s = int(padded or "0", 2).to_bytes(
                max(1, len(padded) // 8), "big"
            )
        else:
            s = bytes_encode(_s)
            nbits = 8 * len(s)
        minimum, maximum = _uper_size_bounds(size_len, uper_min, uper_max)
        if minimum is not None and maximum is not None:
            _uper_check_size(cls.__name__, "bits", nbits, minimum, maximum)
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
                         field=None,  # type: Any
                         size_len=None,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[str]
        from scapy.asn1.constraints import oer_size_len, uper_int_range
        size_len = oer_size_len(field, size_len)
        uper_min, uper_max = uper_int_range(field, uper_min, uper_max)
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
                    field=None,  # type: Any
                    size_len=None,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        from scapy.asn1.constraints import oer_size_len, uper_int_range
        size_len = oer_size_len(field, size_len)
        uper_min, uper_max = uper_int_range(field, uper_min, uper_max)
        s = bytes_encode(_s)
        minimum, maximum = _uper_size_bounds(size_len, uper_min, uper_max)
        UPER_octet_string_enc(enc, s, minimum, maximum)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         field=None,  # type: Any
                         size_len=None,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[Any]
        from scapy.asn1.constraints import oer_size_len, uper_int_range
        size_len = oer_size_len(field, size_len)
        uper_min, uper_max = uper_int_range(field, uper_min, uper_max)
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
        from scapy.asn1.oid import oid_dotted_to_subidentifiers
        oid = bytes_encode(_oid)
        lst = oid_dotted_to_subidentifiers(oid)
        body = b"".join(BER_num_enc(k) for k in lst)
        enc.append_fragmented(
            len(body),
            lambda offset, size: enc.append_bytes(body[offset:offset + size]),
        )

    @classmethod
    def dec_from_decoder(cls, dec, **_kwargs):
        # type: (UPER_Decoder, **Any) -> ASN1_Object[bytes]
        from scapy.asn1.oid import oid_subidentifiers_to_dotted
        fragments = []  # type: List[bytes]
        dec.read_fragmented(lambda size: fragments.append(dec.read_bytes(size)))
        content = b"".join(fragments)
        lst = []
        while content:
            val, content = BER_num_dec(content)
            lst.append(val)
        return cls.asn1_object(oid_subidentifiers_to_dotted(lst))


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
                    field=None,  # type: Any
                    pkt=None,  # type: Any
                    size_len=None,  # type: Optional[int]
                    uper_min=None,  # type: Optional[int]
                    uper_max=None,  # type: Optional[int]
                    uper_enum_values=None,  # type: Optional[List[int]]
                    uper_extensible=None,  # type: Optional[bool]
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        from scapy.asn1.constraints import (
            oer_size_len,
            uper_enum_values as _uper_enum_values,
            uper_extensible as _uper_extensible,
            uper_int_range,
        )
        size_len = oer_size_len(field, size_len)
        uper_min, uper_max = uper_int_range(field, uper_min, uper_max)
        uper_enum_values = _uper_enum_values(
            field, pkt, uper_enum_values,
        )
        extensible = _uper_extensible(field, uper_extensible)
        if uper_enum_values is not None:
            if extensible:
                # X.691 14.3: a one bit prefix says whether the value is an
                # extension addition. Only root values can be encoded.
                if i not in uper_enum_values:
                    raise UPER_Encoding_Error(
                        "UPERcodec_ENUMERATED: extension additions are not "
                        "supported"
                    )
                enc.append_bit(0)
            UPER_enumerated_enc(enc, i, uper_enum_values)
            return
        minimum, maximum = cls._range(
            size_len, uper_min, uper_max, UPER_Encoding_Error
        )
        UPER_constrained_int_enc(enc, i, minimum, maximum)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         field=None,  # type: Any
                         pkt=None,  # type: Any
                         size_len=None,  # type: Optional[int]
                         uper_min=None,  # type: Optional[int]
                         uper_max=None,  # type: Optional[int]
                         uper_enum_values=None,  # type: Optional[List[int]]
                         uper_extensible=None,  # type: Optional[bool]
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[int]
        from scapy.asn1.constraints import (
            oer_size_len,
            uper_enum_values as _uper_enum_values,
            uper_extensible as _uper_extensible,
            uper_int_range,
        )
        size_len = oer_size_len(field, size_len)
        uper_min, uper_max = uper_int_range(field, uper_min, uper_max)
        uper_enum_values = _uper_enum_values(
            field, pkt, uper_enum_values,
        )
        extensible = _uper_extensible(field, uper_extensible)
        if uper_enum_values is not None:
            if extensible and dec.read_bit():
                raise UPER_Decoding_Error(
                    "UPERcodec_ENUMERATED: extension additions are not "
                    "supported"
                )
            return cls.asn1_object(UPER_enumerated_dec(dec, uper_enum_values))
        minimum, maximum = cls._range(
            size_len, uper_min, uper_max, UPER_Decoding_Error
        )
        value = dec.read_non_negative_binary_integer(
            UPER_bits_for_range(maximum - minimum)
        ) + minimum
        return cls.asn1_object(value)

    @staticmethod
    def _range(size_len, uper_min, uper_max, error):
        # type: (Optional[int], Optional[int], Optional[int], Any) -> Tuple[int, int]  # noqa: E501
        # Without the enumeration itself the index range has to come from
        # the declared bounds; deriving it from the value at hand would
        # make the width depend on the value, which the decoder cannot
        # reproduce.
        minimum = uper_min if uper_min is not None else 0
        maximum = uper_max if uper_max is not None else (size_len or None)
        if maximum is None:
            raise error("UPERcodec_ENUMERATED: missing range")
        return minimum, maximum


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


class UPERcodec_KNOWN_MULTIPLIER_STRING(UPERcodec_STRING):
    # X.691 §3.7.16 / §30: NumericString, PrintableString, VisibleString
    # (ISO646String), IA5String, BMPString, UniversalString.
    @classmethod
    def encode_into(cls, enc, s, **_kwargs):
        # type: (UPER_Encoder, Any, **Any) -> None
        raise UPER_Encoding_Error(
            "%s: known-multiplier PER string encoding is not implemented" %
            cls.__name__
        )

    @classmethod
    def dec_from_decoder(cls, dec, **_kwargs):
        # type: (UPER_Decoder, **Any) -> ASN1_Object[Any]
        raise UPER_Decoding_Error(
            "%s: known-multiplier PER string decoding is not implemented" %
            cls.__name__
        )


class UPERcodec_UNSUPPORTED_TIME(UPERcodec_STRING):
    @classmethod
    def encode_into(cls, enc, s, **_kwargs):
        # type: (UPER_Encoder, Any, **Any) -> None
        raise UPER_Encoding_Error(
            "%s: PER time encoding is not implemented" % cls.__name__
        )

    @classmethod
    def dec_from_decoder(cls, dec, **_kwargs):
        # type: (UPER_Decoder, **Any) -> ASN1_Object[Any]
        raise UPER_Decoding_Error(
            "%s: PER time decoding is not implemented" % cls.__name__
        )


class UPERcodec_UTF8_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UTF8_STRING


class UPERcodec_NUMERIC_STRING(UPERcodec_KNOWN_MULTIPLIER_STRING):
    tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING


class UPERcodec_PRINTABLE_STRING(UPERcodec_KNOWN_MULTIPLIER_STRING):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING


class UPERcodec_T61_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING


class UPERcodec_VIDEOTEX_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING


class UPERcodec_IA5_STRING(UPERcodec_KNOWN_MULTIPLIER_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING


class UPERcodec_GENERAL_STRING(UPERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERAL_STRING


class UPERcodec_UTC_TIME(UPERcodec_UNSUPPORTED_TIME):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME


class UPERcodec_GENERALIZED_TIME(UPERcodec_UNSUPPORTED_TIME):
    tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME


class UPERcodec_ISO646_STRING(UPERcodec_KNOWN_MULTIPLIER_STRING):
    tag = ASN1_Class_UNIVERSAL.ISO646_STRING


class UPERcodec_UNIVERSAL_STRING(UPERcodec_KNOWN_MULTIPLIER_STRING):
    tag = ASN1_Class_UNIVERSAL.UNIVERSAL_STRING


class UPERcodec_BMP_STRING(UPERcodec_KNOWN_MULTIPLIER_STRING):
    tag = ASN1_Class_UNIVERSAL.BMP_STRING


# KNOWN_MULTIPLIER inherits STRING's tag for registration; restore the
# generic STRING codec used by ASN1F_STRING (octet-string UPER path).
ASN1_Class_UNIVERSAL.STRING.register(ASN1_Codecs.PER, UPERcodec_STRING)


################################
#    ASN1F compound helpers    #
################################

from scapy.asn1.compound import (  # noqa: E402
    sequence_decode_from as _uper_sequence_decode_from,
    sequence_encode_to as _uper_sequence_encode_to,
    sequence_of_decode_from as _uper_sequence_of_decode_from,
    sequence_of_encode_to as _uper_sequence_of_encode_to,
    choice_decode_from as _uper_choice_decode_from,
    choice_encode_to as _uper_choice_encode_to,
)


def uper_sequence_m2i(field, pkt, s):
    from scapy.asn1.context import UPER_DecoderContext
    dec = UPER_DecoderContext(s)
    _uper_sequence_decode_from(field, pkt, dec)
    return [], dec.remaining()


def uper_sequence_build(field, pkt):
    from scapy.asn1fields import ASN1F_field
    from scapy.asn1.context import UPER_EncoderContext
    enc = UPER_EncoderContext()
    _uper_sequence_encode_to(field, pkt, enc)
    return ASN1F_field.i2m(field, pkt, enc.finish())


def uper_sequence_of_m2i(field, pkt, s):
    from scapy.asn1.context import UPER_DecoderContext
    dec = UPER_DecoderContext(s)
    _uper_sequence_of_decode_from(field, pkt, dec)
    return getattr(pkt, field.name), dec.remaining()


def uper_sequence_of_build(field, pkt):
    from scapy.asn1.context import UPER_EncoderContext
    enc = UPER_EncoderContext()
    _uper_sequence_of_encode_to(field, pkt, enc)
    return field.i2m(pkt, enc.finish())


def uper_choice_m2i(field, pkt, s):
    from scapy.asn1.context import UPER_DecoderContext
    dec = UPER_DecoderContext(s)
    _uper_choice_decode_from(field, pkt, dec)
    return getattr(pkt, field.name), dec.remaining()


def uper_choice_i2m(field, pkt, x):
    from scapy.asn1.context import UPER_EncoderContext
    enc = UPER_EncoderContext()
    _uper_choice_encode_to(field, pkt, enc)
    return field._tagging_enc(pkt, enc.finish(), explicit_tag=field.explicit_tag)


def uper_packet_i2m(field, pkt, x):
    from scapy.asn1.compound import packet_encode_to
    from scapy.asn1.context import UPER_EncoderContext
    enc = UPER_EncoderContext()
    packet_encode_to(field, pkt, enc, x)
    return field._tagging_enc(
        pkt, enc.finish(),
        implicit_tag=field.implicit_tag,
        explicit_tag=field.explicit_tag,
    )
