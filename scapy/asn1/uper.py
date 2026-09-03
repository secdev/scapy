# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Unaligned Packed Encoding Rules (UPER) for ASN.1

As specified in ITU-T X.691 | ISO/IEC 8825-2.

UPER is registered on ``ASN1_Codecs.PER``. Schema-driven encoding and decoding
(``ASN1F_SEQUENCE``, ``ASN1F_CHOICE``, ``ASN1F_SEQUENCE_OF``,
``ASN1F_ENUMERATED``) is supported for common field types. Value ranges are
declared with ``minimum=``/``maximum=``, fixed sizes with ``size_len=``, and
an extension marker with ``extensible=True``. Content of 16K units or
more is fragmented as required by 11.9.3.8.

Not supported yet: extension additions (an encoding that carries them is
refused rather than misparsed), SET, REAL, and the known-multiplier character
string encodings (rejected rather than emitted as plain octets).

``ASN1F_CHOICE`` alternatives are indexed in X.691 10.2 canonical tag order
(via ``ASN1F_CHOICE.canonical_order``). Declaration order is kept for
BER tag lookup (``choices``) and ``alternative_tag``.
"""

from scapy.compat import bytes_encode
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
    pass


class UPER_Decoding_Error(ASN1_Decoding_Error):
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
    """Byte-oriented UPER bit writer.

    Completed octets live in a ``bytearray``; at most seven pending bits are
    kept in ``_acc``. Large octet strings stay as bytes instead of being
    folded into a growing multi-precision integer.
    """

    def __init__(self):
        # type: () -> None
        self._buf = bytearray()  # type: bytearray
        self._acc = 0  # type: int
        self._nbits = 0  # type: int

    def append_bit(self, bit):
        # type: (int) -> None
        self._acc = (self._acc << 1) | (1 if bit else 0)
        self._nbits += 1
        if self._nbits == 8:
            self._buf.append(self._acc)
            self._acc = 0
            self._nbits = 0

    def append_bits(self, data, number_of_bits):
        # type: (bytes, int) -> None
        if number_of_bits == 0:
            return
        # Keep whole octets on the byte path; only the final 1–7 bits become
        # an integer (avoids int.from_bytes of a multi-megabit BIT STRING).
        full_bytes, remaining_bits = divmod(number_of_bits, 8)
        if full_bytes:
            self.append_bytes(data[:full_bytes])
        if remaining_bits:
            self.append_non_negative_binary_integer(
                data[full_bytes] >> (8 - remaining_bits),
                remaining_bits,
            )

    def append_non_negative_binary_integer(self, value, number_of_bits):
        # type: (int, int) -> None
        if number_of_bits == 0:
            return
        value &= (1 << number_of_bits) - 1
        # Fill the pending octet first so the middle can be raw bytes.
        if self._nbits:
            space = 8 - self._nbits
            if number_of_bits <= space:
                self._acc = (self._acc << number_of_bits) | value
                self._nbits += number_of_bits
                if self._nbits == 8:
                    self._buf.append(self._acc)
                    self._acc = 0
                    self._nbits = 0
                return
            self._acc = (
                (self._acc << space) | (value >> (number_of_bits - space))
            )
            self._buf.append(self._acc)
            number_of_bits -= space
            value &= (1 << number_of_bits) - 1
            self._acc = 0
            self._nbits = 0
        full_bytes = number_of_bits // 8
        rem = number_of_bits % 8
        if full_bytes:
            mid = value >> rem if rem else value
            self._buf.extend(mid.to_bytes(full_bytes, "big"))
            if rem:
                value &= (1 << rem) - 1
            number_of_bits = rem
        if number_of_bits:
            self._acc = value
            self._nbits = number_of_bits

    def append_bytes(self, data):
        # type: (bytes) -> None
        if not data:
            return
        if self._nbits == 0:
            self._buf.extend(data)
            return
        # One bulk shift for the whole block rather than a Python loop per
        # source octet (large OCTET STRINGs after a presence/extension bit).
        offset = self._nbits
        size = len(data)
        value = int.from_bytes(data, "big")
        self._buf.extend(
            (
                (self._acc << (8 * size - offset)) |
                (value >> offset)
            ).to_bytes(size, "big")
        )
        self._acc = value & ((1 << offset) - 1)

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
        from scapy.asn1.intutil import twos_complement_octets
        number_of_bytes, masked = twos_complement_octets(value)
        self.append_length_determinant(number_of_bytes)
        self.append_non_negative_binary_integer(
            masked, 8 * number_of_bytes
        )

    def as_bytes(self):
        # type: () -> bytes
        if self._nbits == 0:
            return bytes(self._buf)
        # X.691 11.1: pad with zero bits up to an octet boundary.
        return b"".join((
            self._buf,
            bytes([self._acc << (8 - self._nbits)]),
        ))


class UPER_Decoder(object):
    def __init__(self, encoded):
        # type: (bytes) -> None
        # Byte buffer + bit cursor: avoid shifting a whole-input Python int
        # on every small field read (super-linear on large encodings).
        self._data = encoded
        self._pos = 0
        self.total_number_of_bits = 8 * len(encoded)

    @property
    def number_of_bits(self):
        # type: () -> int
        return self.total_number_of_bits - self._pos

    def _peek_bits_int(self, number_of_bits):
        # type: (int) -> int
        if number_of_bits == 0:
            return 0
        if number_of_bits > self.number_of_bits:
            raise UPER_Decoding_Error("UPER_Decoder: out of data")
        start = self._pos // 8
        offset = self._pos % 8
        nbytes = (offset + number_of_bits + 7) // 8
        window = int.from_bytes(self._data[start:start + nbytes], "big")
        shift = nbytes * 8 - offset - number_of_bits
        return (window >> shift) & ((1 << number_of_bits) - 1)

    def _read_bits_int(self, number_of_bits):
        # type: (int) -> int
        value = self._peek_bits_int(number_of_bits)
        self._pos += number_of_bits
        return value

    def read_bit(self):
        # type: () -> int
        if not self.number_of_bits:
            raise UPER_Decoding_Error("UPER_Decoder: out of data")
        byte_index = self._pos // 8
        bit_offset = self._pos % 8
        self._pos += 1
        return (self._data[byte_index] >> (7 - bit_offset)) & 1

    def read_bits(self, number_of_bits):
        # type: (int) -> bytes
        # Whole-octet requests (aligned or not) use read_bytes(); only
        # non-multiple-of-8 widths go through the small-field integer path.
        if number_of_bits % 8 == 0:
            return self.read_bytes(number_of_bits // 8)
        return _uper_bits_to_bytes(
            self._read_bits_int(number_of_bits),
            number_of_bits,
        )

    def remaining(self):
        # type: () -> bytes
        n = self.number_of_bits
        if n == 0:
            return b""
        if self._pos % 8 == 0:
            return self._data[self._pos // 8:]
        return _uper_bits_to_bytes(self._peek_bits_int(n), n)

    def remaining_bytes(self):
        # type: () -> bytes
        # A standalone UPER encoding is padded to an octet boundary, so the
        # bits left over inside the current octet are padding; only whole
        # octets after it are actual remaining input / Scapy payload.
        pad = -self._pos % 8
        if pad:
            if pad > self.number_of_bits:
                raise UPER_Decoding_Error("UPER_Decoder: truncated padding")
            if self._peek_bits_int(pad) != 0:
                raise UPER_Decoding_Error(
                    "UPER_Decoder: non-zero padding bits",
                    remaining=self.remaining(),
                )
            self._pos += pad
        n = self.number_of_bits
        if n == 0:
            return b""
        if n % 8:
            raise UPER_Decoding_Error("UPER_Decoder: truncated padding")
        start = self._pos // 8
        return self._data[start:]

    def read_bytes(self, number_of_bytes):
        # type: (int) -> bytes
        number_of_bits = 8 * number_of_bytes
        if number_of_bits > self.number_of_bits:
            raise UPER_Decoding_Error("UPER_Decoder: out of data")
        if number_of_bytes == 0:
            return b""
        if self._pos % 8 == 0:
            start = self._pos // 8
            end = start + number_of_bytes
            self._pos += number_of_bits
            return self._data[start:end]
        return self._read_bits_int(number_of_bits).to_bytes(
            number_of_bytes, "big",
        )

    def read_non_negative_binary_integer(self, number_of_bits):
        # type: (int) -> int
        return self._read_bits_int(number_of_bits)

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
        from scapy.asn1.intutil import from_twos_complement
        number_of_bytes = self.read_length_determinant()
        if number_of_bytes == 0:
            raise UPER_Decoding_Error(
                "UPER_Decoder: integer with an empty length determinant"
            )
        enc = self.read_non_negative_binary_integer(8 * number_of_bytes)
        return from_twos_complement(enc, number_of_bytes)


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


def UPER_semi_constrained_int_enc(enc, value, minimum):
    # type: (UPER_Encoder, int, int) -> None
    # X.691 11.7: encode the non-negative offset (value - lower_bound) as a
    # normally small non-negative whole number (length determinant + octets).
    if value < minimum:
        raise UPER_Encoding_Error(
            "UPER_semi_constrained_int_enc: got %i while expecting >= %i" %
            (value, minimum)
        )
    offset = value - minimum
    number_of_bytes = max((offset.bit_length() + 7) // 8, 1)
    enc.append_length_determinant(number_of_bytes)
    enc.append_non_negative_binary_integer(offset, 8 * number_of_bytes)


def UPER_semi_constrained_int_dec(dec, minimum):
    # type: (UPER_Decoder, int) -> int
    number_of_bytes = dec.read_length_determinant()
    if number_of_bytes == 0:
        raise UPER_Decoding_Error(
            "UPER_semi_constrained_int_dec: empty length determinant"
        )
    offset = dec.read_non_negative_binary_integer(8 * number_of_bytes)
    return offset + minimum


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


def UPER_octet_string_enc(enc, data, minimum=None, maximum=None,
                          extensible=False):
    # type: (UPER_Encoder, bytes, Optional[int], Optional[int], bool) -> None
    length = len(data)
    data_view = memoryview(data)
    if extensible and minimum is not None and maximum is not None:
        if minimum <= length <= maximum:
            enc.append_bit(0)
        else:
            enc.append_bit(1)
            enc.append_fragmented(
                length,
                lambda offset, size: enc.append_bytes(
                    data_view[offset:offset + size]
                ),
            )
            return
    if minimum is not None and maximum is not None:
        _uper_check_size(
            "UPER_octet_string_enc", "octets", length, minimum, maximum,
        )
        if minimum != maximum:
            enc.append_non_negative_binary_integer(
                length - minimum,
                UPER_bits_for_range(maximum - minimum),
            )
        enc.append_bytes(data)
    else:
        enc.append_fragmented(
            length,
            lambda offset, size: enc.append_bytes(
                data_view[offset:offset + size]
            ),
        )


def UPER_octet_string_dec(dec, minimum=None, maximum=None, extensible=False):
    # type: (UPER_Decoder, Optional[int], Optional[int], bool) -> bytes
    if extensible and minimum is not None and maximum is not None:
        if dec.read_bit():
            fragments = []  # type: List[bytes]
            dec.read_fragmented(
                lambda size: fragments.append(dec.read_bytes(size))
            )
            return b"".join(fragments)
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


_K = TypeVar('_K')


class UPERcodec_Object(Generic[_K], metaclass=ASN1Codec_metaclass):
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
            i = int(s)
        except (TypeError, ValueError):
            raise UPER_Encoding_Error(
                "Cannot encode value %r for %s" % (s, cls.__name__),
                encoded=s
            )
        UPERcodec_INTEGER.encode_into(enc, i, **kwargs)

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
        except ASN1_Error as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""

    @classmethod
    def safedec(cls, s, context=None, **kwargs):
        # type: (bytes, Optional[Type[ASN1_Class]], **Any) -> Tuple[Union[_ASN1_ERROR, ASN1_Object[_K]], bytes]  # noqa: E501
        return cls.dec(s, context, safe=True, **kwargs)


# No field tagging on the wire for PER; identity tagging is the ASN1Codec
# default when no tagging_enc/dec is registered.
ASN1_Codecs.PER.register_stem(UPERcodec_Object)


#########################
#    UPERcodec objects  #
#########################


class UPERcodec_INTEGER(UPERcodec_Object[int]):
    tag = ASN1_Class_UNIVERSAL.INTEGER

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    i,  # type: int
                    field=None,  # type: Any
                    size_len=None,  # type: Optional[int]
                    minimum=None,  # type: Optional[int]
                    maximum=None,  # type: Optional[int]
                    unsigned=None,  # type: Optional[bool]
                    extensible=None,  # type: Optional[bool]
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        from scapy.asn1.constraints import resolve_uper_int_bounds
        minimum, maximum, extensible = resolve_uper_int_bounds(
            field, size_len, minimum, maximum, unsigned, extensible,
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
        elif minimum is not None:
            UPER_semi_constrained_int_enc(enc, i, minimum)
        else:
            enc.append_unconstrained_whole_number(i)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         field=None,  # type: Any
                         pkt=None,  # type: Any
                         size_len=None,  # type: Optional[int]
                         minimum=None,  # type: Optional[int]
                         maximum=None,  # type: Optional[int]
                         unsigned=None,  # type: Optional[bool]
                         extensible=None,  # type: Optional[bool]
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[int]
        from scapy.asn1.constraints import resolve_uper_int_bounds
        minimum, maximum, extensible = resolve_uper_int_bounds(
            field, size_len, minimum, maximum, unsigned, extensible,
        )
        if extensible and minimum is not None and maximum is not None:
            if dec.read_bit():
                value = dec.read_unconstrained_whole_number()
                return cls.asn1_object(value)
        if minimum is not None and maximum is not None:
            value = UPER_constrained_int_dec(dec, minimum, maximum)
        elif minimum is not None:
            value = UPER_semi_constrained_int_dec(dec, minimum)
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
    bitstr = "".join(binrepr(x).zfill(8) for x in data)
    return bitstr[:nbits]


class UPERcodec_BIT_STRING(UPERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    _s,  # type: Any
                    field=None,  # type: Any
                    size_len=None,  # type: Optional[int]
                    minimum=None,  # type: Optional[int]
                    maximum=None,  # type: Optional[int]
                    extensible=None,  # type: Optional[bool]
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        from scapy.asn1.constraints import resolve_uper_size_bounds
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
        minimum, maximum, extensible = resolve_uper_size_bounds(
            field, size_len, minimum, maximum, extensible,
        )
        s_view = memoryview(s)
        if extensible and minimum is not None and maximum is not None:
            if minimum <= nbits <= maximum:
                enc.append_bit(0)
            else:
                enc.append_bit(1)
                enc.append_fragmented(
                    nbits,
                    lambda offset, size: enc.append_bits(
                        s_view[offset // 8:(offset + size + 7) // 8], size
                    ),
                )
                return
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
                    s_view[offset // 8:(offset + size + 7) // 8], size
                ),
            )

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         field=None,  # type: Any
                         size_len=None,  # type: Optional[int]
                         minimum=None,  # type: Optional[int]
                         maximum=None,  # type: Optional[int]
                         extensible=None,  # type: Optional[bool]
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[str]
        from scapy.asn1.constraints import resolve_uper_size_bounds
        minimum, maximum, extensible = resolve_uper_size_bounds(
            field, size_len, minimum, maximum, extensible,
        )

        def _read_unconstrained():
            # type: () -> ASN1_Object[str]
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

        if extensible and minimum is not None and maximum is not None:
            if dec.read_bit():
                return _read_unconstrained()
        if minimum is not None and maximum is not None:
            nbits = minimum
            if minimum != maximum:
                nbits += dec.read_non_negative_binary_integer(
                    UPER_bits_for_range(maximum - minimum)
                )
            raw = dec.read_bits(nbits)
            return cls.asn1_object(_uper_bytes_to_bitstr(raw, nbits))
        return _read_unconstrained()


class UPERcodec_STRING(UPERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.STRING

    @classmethod
    def encode_into(cls,
                    enc,  # type: UPER_Encoder
                    _s,  # type: Union[str, bytes]
                    field=None,  # type: Any
                    size_len=None,  # type: Optional[int]
                    minimum=None,  # type: Optional[int]
                    maximum=None,  # type: Optional[int]
                    extensible=None,  # type: Optional[bool]
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        from scapy.asn1.constraints import resolve_uper_size_bounds
        s = bytes_encode(_s)
        minimum, maximum, extensible = resolve_uper_size_bounds(
            field, size_len, minimum, maximum, extensible,
        )
        UPER_octet_string_enc(enc, s, minimum, maximum, extensible)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         field=None,  # type: Any
                         size_len=None,  # type: Optional[int]
                         minimum=None,  # type: Optional[int]
                         maximum=None,  # type: Optional[int]
                         extensible=None,  # type: Optional[bool]
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[Any]
        from scapy.asn1.constraints import resolve_uper_size_bounds
        minimum, maximum, extensible = resolve_uper_size_bounds(
            field, size_len, minimum, maximum, extensible,
        )
        raw = UPER_octet_string_dec(dec, minimum, maximum, extensible)
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
        body_view = memoryview(body)
        enc.append_fragmented(
            len(body),
            lambda offset, size: enc.append_bytes(
                body_view[offset:offset + size]
            ),
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
                    minimum=None,  # type: Optional[int]
                    maximum=None,  # type: Optional[int]
                    uper_enum_values=None,  # type: Optional[List[int]]
                    extensible=None,  # type: Optional[bool]
                    **_kwargs  # type: Any
                    ):
        # type: (...) -> None
        from scapy.asn1.constraints import (
            uper_enum_values as _uper_enum_values,
        )
        if size_len is None and field is not None:
            size_len = field.size_len
        if minimum is None and maximum is None and field is not None:
            minimum = field.constraints.minimum
            maximum = field.constraints.maximum
        uper_enum_values = _uper_enum_values(
            field, pkt, uper_enum_values,
        )
        if extensible is None:
            extensible = (
                bool(field.constraints.extensible) if field is not None else False
            )
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
        lo, hi = cls._range(
            size_len, minimum, maximum, UPER_Encoding_Error
        )
        UPER_constrained_int_enc(enc, i, lo, hi)

    @classmethod
    def dec_from_decoder(cls,
                         dec,  # type: UPER_Decoder
                         field=None,  # type: Any
                         pkt=None,  # type: Any
                         size_len=None,  # type: Optional[int]
                         minimum=None,  # type: Optional[int]
                         maximum=None,  # type: Optional[int]
                         uper_enum_values=None,  # type: Optional[List[int]]
                         extensible=None,  # type: Optional[bool]
                         **_kwargs  # type: Any
                         ):
        # type: (...) -> ASN1_Object[int]
        from scapy.asn1.constraints import (
            uper_enum_values as _uper_enum_values,
        )
        if size_len is None and field is not None:
            size_len = field.size_len
        if minimum is None and maximum is None and field is not None:
            minimum = field.constraints.minimum
            maximum = field.constraints.maximum
        uper_enum_values = _uper_enum_values(
            field, pkt, uper_enum_values,
        )
        if extensible is None:
            extensible = (
                bool(field.constraints.extensible) if field is not None else False
            )
        if uper_enum_values is not None:
            if extensible and dec.read_bit():
                raise UPER_Decoding_Error(
                    "UPERcodec_ENUMERATED: extension additions are not "
                    "supported"
                )
            return cls.asn1_object(UPER_enumerated_dec(dec, uper_enum_values))
        lo, hi = cls._range(
            size_len, minimum, maximum, UPER_Decoding_Error
        )
        value = dec.read_non_negative_binary_integer(
            UPER_bits_for_range(hi - lo)
        ) + lo
        return cls.asn1_object(value)

    @staticmethod
    def _range(size_len, minimum, maximum, error):
        # type: (Optional[int], Optional[int], Optional[int], Any) -> Tuple[int, int]  # noqa: E501
        # Without the enumeration itself the index range has to come from
        # the declared bounds; deriving it from the value at hand would
        # make the width depend on the value, which the decoder cannot
        # reproduce.
        lo = minimum if minimum is not None else 0
        hi = maximum if maximum is not None else (size_len or None)
        if hi is None:
            raise error("UPERcodec_ENUMERATED: missing range")
        return lo, hi


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
        except (TypeError, ValueError, OSError):
            raise UPER_Encoding_Error("IPv4 address could not be encoded")
        UPER_octet_string_enc(enc, s, 4, 4)

    @classmethod
    def dec_from_decoder(cls, dec, **_kwargs):
        # type: (UPER_Decoder, **Any) -> ASN1_Object[str]
        raw = UPER_octet_string_dec(dec, 4, 4)
        try:
            ipaddr_ascii = inet_ntoa(raw)
        except (TypeError, ValueError, OSError):
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
