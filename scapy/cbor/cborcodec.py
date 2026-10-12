# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
CBOR Codec Implementation - RFC 8949
Following the BER paradigm for ASN.1
"""

import struct
from typing import (
    Any,
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

from scapy.cbor.cbor import (
    CBOR_Codecs,
    CBOR_DECODING_ERROR,
    CBOR_Decoding_Error,
    CBOR_Encoding_Error,
    CBOR_Error,
    CBOR_MajorTypes,
    CBOR_Object,
    _CBOR_ERROR,
)
from scapy.compat import chb
from scapy.error import log_runtime


MAX_CBOR_NESTING = 128


##################
#  CBOR encoding #
##################


class CBOR_Exception(Exception):
    pass


class CBOR_INDEFINITE(object):
    """Marker returned by :func:`CBOR_decode_head` for indefinite-length items."""


class CBOR_Codec_Encoding_Error(CBOR_Encoding_Error):
    def __init__(self,
                 msg,  # type: str
                 encoded=None,  # type: Optional[Any]
                 remaining=b""  # type: bytes
                 ):
        # type: (...) -> None
        Exception.__init__(self, msg)
        self.remaining = remaining
        self.encoded = encoded


class CBOR_Codec_Decoding_Error(CBOR_Decoding_Error):
    def __init__(self,
                 msg,  # type: str
                 decoded=None,  # type: Optional[Any]
                 remaining=b""  # type: bytes
                 ):
        # type: (...) -> None
        Exception.__init__(self, msg)
        self.remaining = remaining
        self.decoded = decoded


def CBOR_encode_head(major_type, value):
    # type: (int, int) -> bytes
    """
    Encode CBOR initial byte and additional info.
    Format: 3 bits major type + 5 bits additional info
    """
    if value is None:
        raise CBOR_Codec_Encoding_Error(
            "Indefinite length requires CBOR_encode_indefinite_head")
    if not isinstance(value, int) or isinstance(value, bool):
        raise CBOR_Codec_Encoding_Error(
            "CBOR head value must be an integer, got %r" % (value,))
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise CBOR_Codec_Encoding_Error(
            "CBOR head value out of uint64 range: %r" % (value,))
    if value < 24:
        # Value fits in 5 bits
        return chb((major_type << 5) | value)
    elif value < 256:
        # 1-byte value follows
        return chb((major_type << 5) | 24) + chb(value)
    elif value < 65536:
        # 2-byte value follows
        return chb((major_type << 5) | 25) + struct.pack(">H", value)
    elif value < 4294967296:
        # 4-byte value follows
        return chb((major_type << 5) | 26) + struct.pack(">I", value)
    else:
        # 8-byte value follows
        return chb((major_type << 5) | 27) + struct.pack(">Q", value)


def CBOR_encode_indefinite_head(major_type):
    # type: (int) -> bytes
    """Encode a CBOR indefinite-length header (additional info 31)."""
    if major_type not in (2, 3, 4, 5):
        raise CBOR_Codec_Encoding_Error(
            "Indefinite length not allowed for major type %d" % major_type
        )
    return chb((major_type << 5) | 31)


def CBOR_encode_break():
    # type: () -> bytes
    """Encode the CBOR break stop code (0xff)."""
    return b'\xff'


def _cbor_buf_bytes(buf):
    # type: (Any) -> bytes
    """Materialize a bytes/memoryview slice as ``bytes``."""
    if isinstance(buf, bytes):
        return buf
    if isinstance(buf, memoryview):
        return buf.tobytes()
    return bytes(buf)


def cbor_is_break(s):
    # type: (Any) -> bool
    """Return whether *s* begins with a CBOR break byte."""
    return bool(s) and s[0] == 0xff


def cbor_consume_break(s):
    # type: (Any) -> Any
    """Consume a leading CBOR break byte from *s*."""
    if not cbor_is_break(s):
        raise CBOR_Codec_Decoding_Error(
            "Expected break byte (0xff)", remaining=_cbor_buf_bytes(s))
    return s[1:]


def CBOR_decode_head(s):
    # type: (Any) -> Tuple[int, Union[int, CBOR_INDEFINITE], Any]
    """
    Decode CBOR initial byte and additional info.
    Returns: (major_type, value, remaining_bytes)
    """
    if not s:
        raise CBOR_Codec_Decoding_Error(
            "Empty CBOR data", remaining=_cbor_buf_bytes(s))

    initial_byte = s[0]
    major_type = initial_byte >> 5
    additional_info = initial_byte & 0x1f

    if additional_info < 24:
        # Value is in the additional info
        return major_type, additional_info, s[1:]
    elif additional_info == 24:
        # 1-byte value follows
        if len(s) < 2:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 1-byte value",
                remaining=_cbor_buf_bytes(s))
        return major_type, s[1], s[2:]
    elif additional_info == 25:
        # 2-byte value follows
        if len(s) < 3:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 2-byte value",
                remaining=_cbor_buf_bytes(s))
        value = struct.unpack(">H", s[1:3])[0]
        return major_type, value, s[3:]
    elif additional_info == 26:
        # 4-byte value follows
        if len(s) < 5:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 4-byte value",
                remaining=_cbor_buf_bytes(s))
        value = struct.unpack(">I", s[1:5])[0]
        return major_type, value, s[5:]
    elif additional_info == 27:
        # 8-byte value follows
        if len(s) < 9:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 8-byte value",
                remaining=_cbor_buf_bytes(s))
        value = struct.unpack(">Q", s[1:9])[0]
        return major_type, value, s[9:]
    elif additional_info == 31:
        if major_type in (0, 1, 6):
            raise CBOR_Codec_Decoding_Error(
                "Indefinite length not allowed for major type %d" %
                major_type, remaining=_cbor_buf_bytes(s))
        if major_type in (2, 3, 4, 5):
            return major_type, CBOR_INDEFINITE, s[1:]
        raise CBOR_Codec_Decoding_Error(
            "Indefinite length not allowed for major type %d" %
            major_type, remaining=_cbor_buf_bytes(s))
    elif additional_info in (28, 29, 30):
        raise CBOR_Codec_Decoding_Error(
            "Reserved additional info: %d" % additional_info,
            remaining=_cbor_buf_bytes(s))
    else:
        raise CBOR_Codec_Decoding_Error(
            "Invalid additional info: %d" % additional_info,
            remaining=_cbor_buf_bytes(s))


def cbor_argument_is_shortest(additional_info, value):
    # type: (int, Union[int, CBOR_INDEFINITE]) -> bool
    """Return True when *additional_info* is the shortest encoding for *value*."""
    if value is CBOR_INDEFINITE:
        return additional_info == 31
    if additional_info < 24:
        return True
    if additional_info == 24:
        return value >= 24
    if additional_info == 25:
        return value >= 256
    if additional_info == 26:
        return value >= 65536
    if additional_info == 27:
        return value >= (1 << 32)
    return additional_info == 31


def _cbor_float_from_bits(ai, bits):
    # type: (int, int) -> float
    if ai == 25:
        sign = (bits >> 15) & 0x1
        exponent = (bits >> 10) & 0x1f
        fraction = bits & 0x3ff
        if exponent == 0:
            if fraction == 0:
                return -0.0 if sign else 0.0
            return ((-1) ** sign) * (fraction / 1024.0) * (2 ** -14)
        if exponent == 31:
            return float("nan") if fraction else (
                float("-inf") if sign else float("inf")
            )
        return ((-1) ** sign) * (1.0 + fraction / 1024.0) * (2 ** (exponent - 15))
    if ai == 26:
        return struct.unpack(">f", struct.pack(">I", bits))[0]
    return struct.unpack(">d", struct.pack(">Q", bits))[0]


def _cbor_float_to_half_bits(value):
    # type: (float) -> Optional[int]
    """Return IEEE binary16 bits when *value* round-trips exactly."""
    import math
    if math.isnan(value):
        # Callers that care about NaN payloads must use bit-pattern helpers.
        return 0x7E00
    sign = 0x8000 if math.copysign(1.0, value) < 0 else 0
    if math.isinf(value):
        return sign | 0x7C00
    if value == 0.0:
        return sign
    value = abs(value)
    bits64, = struct.unpack(">Q", struct.pack(">d", value))
    exp64 = ((bits64 >> 52) & 0x7FF) - 1023
    mant64 = bits64 & ((1 << 52) - 1)
    if exp64 > 15:
        return None
    if exp64 < -14:
        # Subnormal half
        shift = -14 - exp64 + 42  # 52 - 10
        if shift > 52:
            return None
        mant = ((mant64 | (1 << 52)) >> shift) if exp64 != -1023 else 0
        half = mant & 0x3FF
        preferred = math.copysign(value, -1.0 if sign else 1.0)
        if _cbor_float_from_bits(25, sign | half) != preferred:
            # Compare absolute then restore sign via copysign on left side
            decoded = _cbor_float_from_bits(25, sign | half)
            if decoded != math.copysign(abs(value), -1.0 if sign else 1.0):
                return None
        return sign | half
    half_exp = exp64 + 15
    half_mant = mant64 >> 42
    # Reject if discarded mantissa bits are nonzero (not exact).
    if mant64 & ((1 << 42) - 1):
        return None
    bits = sign | (half_exp << 10) | half_mant
    decoded = _cbor_float_from_bits(25, bits)
    if decoded != math.copysign(abs(value), -1.0 if sign else 1.0):
        return None
    return bits


def _cbor_nan_preferred_ai(ai, bits):
    # type: (int, int) -> int
    """Preferred float AI for a NaN, based on the original bit pattern.

    RFC 8949 prefers a shorter NaN only when zero-padding the shorter
    significand reconstructs the original NaN payload.
    """
    if ai == 25:
        return 25
    if ai == 26:
        # binary32 NaN: 1+8+23. Prefer half when low 13 significand bits are 0.
        mant = int(bits) & 0x7FFFFF
        if mant and (mant & ((1 << 13) - 1)) == 0:
            return 25
        return 26
    if ai == 27:
        # binary64 NaN: 1+11+52.
        mant = int(bits) & ((1 << 52) - 1)
        if mant == 0:
            # Infinity, not NaN — caller should not use this helper.
            return 27
        # Prefer half when only the top 10 significand bits are used.
        if (mant & ((1 << 42) - 1)) == 0:
            return 25
        # Prefer single when only the top 23 significand bits are used.
        if (mant & ((1 << 29) - 1)) == 0:
            return 26
        return 27
    return ai


def _cbor_preferred_float_ai(value):
    # type: (float) -> int
    """Return the preferred float AI (25/26/27) for a numeric *value*."""
    import math
    if math.isnan(value):
        # Without the original payload bits, only the quiet binary16 NaN is a
        # safe generic preference. Encoded-width checks use bit patterns.
        return 25
    if _cbor_float_to_half_bits(value) is not None:
        return 25
    try:
        single = struct.unpack(">f", struct.pack(">f", value))[0]
    except (OverflowError, struct.error):
        return 27
    if single == value or (math.isinf(single) and math.isinf(value)):
        return 26
    return 27


def _cbor_preferred_float_ai_from_encoded(ai, bits):
    # type: (int, int) -> int
    """Preferred float AI using the original encoded width and bit pattern."""
    import math
    float_val = _cbor_float_from_bits(ai, bits)
    if math.isnan(float_val):
        return _cbor_nan_preferred_ai(ai, bits)
    return _cbor_preferred_float_ai(float_val)


def cbor_find_non_deterministic(s, allow_indefinite=True, base_offset=0):
    # type: (bytes, bool, int) -> List[Tuple[int, str]]
    """Scan *s* for non-shortest CBOR argument encodings.

    Returns a list of ``(absolute_offset, message)`` issues. Indefinite-length
    items are accepted only when *allow_indefinite* is true (e.g. a BPv7
    bundle outer array). Callers that require definite-length encoding
    (primary/canonical blocks per RFC 9171) must pass ``False``.
    """
    issues = []  # type: List[Tuple[int, str]]
    index = [0]

    def _walk():
        # type: () -> None
        start = index[0]
        if start >= len(s):
            raise CBOR_Codec_Decoding_Error(
                "Empty CBOR data", remaining=s[start:])
        initial = s[start]
        if initial == 0xff:
            issues.append((
                base_offset + start,
                "Standalone break byte (0xff)",
            ))
            index[0] = start + 1
            return
        major = initial >> 5
        ai = initial & 0x1f
        pos = start + 1
        if ai < 24:
            value = ai  # type: Union[int, CBOR_INDEFINITE]
        elif ai == 24:
            if pos + 1 > len(s):
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for 1-byte value", remaining=s[start:])
            value = s[pos]
            pos += 1
        elif ai == 25:
            if pos + 2 > len(s):
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for 2-byte value", remaining=s[start:])
            value = struct.unpack(">H", s[pos:pos + 2])[0]
            pos += 2
        elif ai == 26:
            if pos + 4 > len(s):
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for 4-byte value", remaining=s[start:])
            value = struct.unpack(">I", s[pos:pos + 4])[0]
            pos += 4
        elif ai == 27:
            if pos + 8 > len(s):
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for 8-byte value", remaining=s[start:])
            value = struct.unpack(">Q", s[pos:pos + 8])[0]
            pos += 8
        elif ai == 31:
            value = CBOR_INDEFINITE
        else:
            raise CBOR_Codec_Decoding_Error(
                "Invalid additional info: %d" % ai, remaining=s[start:])
        index[0] = pos

        # Major type 7: simple values and floats. Check float preferred width.
        if major == 7:
            if ai == 24 and isinstance(value, int) and value < 32:
                issues.append((
                    base_offset + start,
                    "Non-shortest CBOR simple value encoding "
                    "(AI=24, value=%d)" % value,
                ))
            if ai in (25, 26, 27) and value is not CBOR_INDEFINITE:
                preferred = _cbor_preferred_float_ai_from_encoded(ai, int(value))
                if preferred is not None and preferred < ai:
                    issues.append((
                        base_offset + start,
                        "Non-shortest CBOR float encoding (AI=%d, preferred AI=%d)"
                        % (ai, preferred),
                    ))
            return

        if value is CBOR_INDEFINITE:
            if not allow_indefinite:
                issues.append((
                    base_offset + start,
                    "Indefinite-length item is not allowed",
                ))
            if major in (2, 3):
                while index[0] < len(s) and not cbor_is_break(s[index[0]:]):
                    _walk()
                if index[0] >= len(s) or not cbor_is_break(s[index[0]:]):
                    raise CBOR_Codec_Decoding_Error(
                        "Expected break byte (0xff)", remaining=s[index[0]:])
                index[0] += 1
                return
            if major == 4:
                while index[0] < len(s) and not cbor_is_break(s[index[0]:]):
                    _walk()
                if index[0] >= len(s) or not cbor_is_break(s[index[0]:]):
                    raise CBOR_Codec_Decoding_Error(
                        "Expected break byte (0xff)", remaining=s[index[0]:])
                index[0] += 1
                return
            if major == 5:
                key_encodings = []  # type: List[bytes]
                while index[0] < len(s) and not cbor_is_break(s[index[0]:]):
                    key_start = index[0]
                    _walk()
                    key_encodings.append(bytes(s[key_start:index[0]]))
                    _walk()
                if index[0] >= len(s) or not cbor_is_break(s[index[0]:]):
                    raise CBOR_Codec_Decoding_Error(
                        "Expected break byte (0xff)", remaining=s[index[0]:])
                index[0] += 1
                if key_encodings != sorted(key_encodings):
                    issues.append((
                        base_offset + start,
                        "CBOR map keys are not in bytewise lexicographic order",
                    ))
                return
            raise CBOR_Codec_Decoding_Error(
                "Indefinite length not allowed for major type %d" % major,
                remaining=s[start:],
            )

        if not cbor_argument_is_shortest(ai, value):
            issues.append((
                base_offset + start,
                "Non-shortest CBOR argument encoding (AI=%d, value=%r)"
                % (ai, value),
            ))

        if major in (2, 3):
            length = int(value)
            if index[0] + length > len(s):
                raise CBOR_Codec_Decoding_Error(
                    "Truncated byte/text string", remaining=s[start:])
            index[0] += length
            return
        if major == 4:
            for _ in range(int(value)):
                _walk()
            return
        if major == 5:
            key_encodings = []  # type: List[bytes]
            for _ in range(int(value)):
                key_start = index[0]
                _walk()
                key_encodings.append(bytes(s[key_start:index[0]]))
                _walk()
            if key_encodings != sorted(key_encodings):
                issues.append((
                    base_offset + start,
                    "CBOR map keys are not in bytewise lexicographic order",
                ))
            return
        if major == 6:
            _walk()
            return

    try:
        _walk()
    except CBOR_Codec_Decoding_Error:
        # Malformed input is reported by normal decoding, not this checker.
        pass
    return issues


#    [ CBOR codec classes ]    #


class CBORcodec_metaclass(type):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[CBORcodec_Object[Any]]
        c = cast('Type[CBORcodec_Object[Any]]',
                 super(CBORcodec_metaclass, cls).__new__(cls, name, bases, dct))
        try:
            c.tag.register(c.codec, c)
        except Exception:
            log_runtime.error("Failed to register codec for tag")
        return c


_K = TypeVar('_K')


class CBORcodec_Object(Generic[_K], metaclass=CBORcodec_metaclass):
    """Base CBOR codec class"""
    codec = CBOR_Codecs.CBOR
    tag = CBOR_MajorTypes.UNSIGNED_INTEGER

    @classmethod
    def cbor_object(cls, val):
        # type: (_K) -> CBOR_Object[_K]
        return cls.tag.cbor_object(val)

    @classmethod
    def check_string(cls, s):
        # type: (bytes) -> None
        if not s:
            raise CBOR_Codec_Decoding_Error(
                "%s: Got empty object while expecting tag %r" %
                (cls.__name__, cls.tag), remaining=s
            )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               _depth=0,  # type: int
               ):
        # type: (...) -> Tuple[CBOR_Object[Any], bytes]
        """Decode CBOR data using automatic dispatch based on major type."""
        return _decode_cbor_item(s, safe=False, depth=_depth)

    @classmethod
    def dec(cls,
            s,  # type: bytes
            context=None,  # type: Optional[Any]
            safe=False,  # type: bool
            _depth=0,  # type: int
            ):
        # type: (...) -> Tuple[Union[_CBOR_ERROR, CBOR_Object[_K]], bytes]
        # Nested decoding must raise so safedec only wraps the outermost item.
        if not safe:
            return cls.do_dec(s, context, False, _depth=_depth)
        try:
            return cls.do_dec(s, context, False, _depth=_depth)
        except CBOR_Codec_Decoding_Error as e:
            return CBOR_DECODING_ERROR(s, exc=e), b""
        except CBOR_Error as e:
            return CBOR_DECODING_ERROR(s, exc=e), b""

    @classmethod
    def safedec(cls,
                s,  # type: bytes
                context=None,  # type: Optional[Any]
                _depth=0,  # type: int
                ):
        # type: (...) -> Tuple[Union[_CBOR_ERROR, CBOR_Object[_K]], bytes]
        return cls.dec(s, context, safe=True, _depth=_depth)

    @classmethod
    def enc(cls, s):
        # type: (_K) -> bytes
        raise NotImplementedError("Subclasses must implement enc")


CBOR_Codecs.CBOR.register_stem(CBORcodec_Object)


##########################
#    CBORcodec objects   #
##########################


class CBORcodec_UNSIGNED_INTEGER(CBORcodec_Object[int]):
    """CBOR unsigned integer codec (major type 0)"""
    tag = CBOR_MajorTypes.UNSIGNED_INTEGER

    @classmethod
    def enc(cls, obj):
        # type: (Union[int, CBOR_Object[int]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        i = obj.val if isinstance(obj, CBOR_Object) else obj
        if i < 0:
            raise CBOR_Codec_Encoding_Error(
                "Cannot encode negative value as unsigned integer. "
                "Use CBOR_NEGATIVE_INTEGER for negative values.")
        if i > 0xFFFFFFFFFFFFFFFF:
            raise CBOR_Codec_Encoding_Error(
                "Unsigned integer exceeds uint64 range")
        return CBOR_encode_head(0, i)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               _depth=0,  # type: int
               ):
        # type: (...) -> Tuple[CBOR_Object[int], bytes]
        cls.check_string(s)
        major_type, value, remainder = CBOR_decode_head(s)
        if major_type != 0:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 0 (unsigned integer), got %d" % major_type,
                remaining=s)
        return cls.cbor_object(value), remainder


class CBORcodec_NEGATIVE_INTEGER(CBORcodec_Object[int]):
    """CBOR negative integer codec (major type 1)"""
    tag = CBOR_MajorTypes.NEGATIVE_INTEGER

    @classmethod
    def enc(cls, obj):
        # type: (Union[int, CBOR_Object[int]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        i = obj.val if isinstance(obj, CBOR_Object) else obj
        if i >= 0:
            raise CBOR_Codec_Encoding_Error(
                "Cannot encode non-negative value as negative integer. "
                "Use CBOR_UNSIGNED_INTEGER for non-negative values.")
        if i < -(1 << 64):
            raise CBOR_Codec_Encoding_Error(
                "Negative integer below CBOR int64 range")
        # CBOR negative integer: -1 - n
        return CBOR_encode_head(1, -1 - i)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               _depth=0,  # type: int
               ):
        # type: (...) -> Tuple[CBOR_Object[int], bytes]
        cls.check_string(s)
        major_type, value, remainder = CBOR_decode_head(s)
        if major_type != 1:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 1 (negative integer), got %d" % major_type,
                remaining=s)
        # Decode: -1 - n
        return cls.cbor_object(-1 - value), remainder


class CBORcodec_BYTE_STRING(CBORcodec_Object[bytes]):
    """CBOR byte string codec (major type 2)"""
    tag = CBOR_MajorTypes.BYTE_STRING

    @classmethod
    def enc(cls, obj):
        # type: (Union[bytes, CBOR_Object[bytes]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        data = obj.val if isinstance(obj, CBOR_Object) else obj
        if not isinstance(data, bytes):
            data = bytes(data)
        return CBOR_encode_head(2, len(data)) + data

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               _depth=0,  # type: int
               ):
        # type: (...) -> Tuple[CBOR_Object[bytes], bytes]
        cls.check_string(s)
        major_type, length, remainder = CBOR_decode_head(s)
        if major_type != 2:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 2 (byte string), got %d" % major_type,
                remaining=s)
        if length is CBOR_INDEFINITE:
            chunks = []  # type: List[bytes]
            while True:
                if cbor_is_break(remainder):
                    remainder = cbor_consume_break(remainder)
                    break
                chunk_mt, chunk_len, remainder = CBOR_decode_head(remainder)
                if chunk_mt != 2:
                    raise CBOR_Codec_Decoding_Error(
                        "Indefinite byte string chunk must be major type 2",
                        remaining=remainder)
                if chunk_len is CBOR_INDEFINITE:
                    raise CBOR_Codec_Decoding_Error(
                        "Nested indefinite byte string", remaining=remainder)
                if len(remainder) < chunk_len:
                    raise CBOR_Codec_Decoding_Error(
                        "Not enough bytes for byte string chunk: "
                        "expected %d, got %d" %
                        (chunk_len, len(remainder)), remaining=remainder)
                chunks.append(_cbor_buf_bytes(remainder[:chunk_len]))
                remainder = remainder[chunk_len:]
            return cls.cbor_object(b"".join(chunks)), remainder
        if len(remainder) < length:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for byte string: expected %d, got %d" %
                (length, len(remainder)), remaining=_cbor_buf_bytes(s))
        return (
            cls.cbor_object(_cbor_buf_bytes(remainder[:length])),
            remainder[length:],
        )


class CBORcodec_TEXT_STRING(CBORcodec_Object[str]):
    """CBOR text string codec (major type 3)"""
    tag = CBOR_MajorTypes.TEXT_STRING

    @classmethod
    def enc(cls, obj):
        # type: (Union[str, CBOR_Object[str]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        text = obj.val if isinstance(obj, CBOR_Object) else obj
        if isinstance(text, str):
            text_bytes = text.encode('utf-8')
        else:
            text_bytes = bytes(text)
        return CBOR_encode_head(3, len(text_bytes)) + text_bytes

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               _depth=0,  # type: int
               ):
        # type: (...) -> Tuple[CBOR_Object[str], bytes]
        cls.check_string(s)
        major_type, length, remainder = CBOR_decode_head(s)
        if major_type != 3:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 3 (text string), got %d" % major_type,
                remaining=s)
        if length is CBOR_INDEFINITE:
            decoded_chunks = []  # type: List[str]
            while True:
                if cbor_is_break(remainder):
                    remainder = cbor_consume_break(remainder)
                    break
                chunk_mt, chunk_len, remainder = CBOR_decode_head(remainder)
                if chunk_mt != 3:
                    raise CBOR_Codec_Decoding_Error(
                        "Indefinite text string chunk must be major type 3",
                        remaining=remainder)
                if chunk_len is CBOR_INDEFINITE:
                    raise CBOR_Codec_Decoding_Error(
                        "Nested indefinite text string", remaining=remainder)
                if len(remainder) < chunk_len:
                    raise CBOR_Codec_Decoding_Error(
                        "Not enough bytes for text string chunk: "
                        "expected %d, got %d" %
                        (chunk_len, len(remainder)), remaining=remainder)
                chunk_bytes = _cbor_buf_bytes(remainder[:chunk_len])
                remainder = remainder[chunk_len:]
                try:
                    decoded_chunks.append(chunk_bytes.decode('utf-8'))
                except UnicodeDecodeError as e:
                    raise CBOR_Codec_Decoding_Error(
                        "Invalid UTF-8 in text string chunk: %s" % str(e),
                        remaining=_cbor_buf_bytes(s))
            return cls.cbor_object("".join(decoded_chunks)), remainder
        if len(remainder) < length:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for text string: expected %d, got %d" %
                (length, len(remainder)), remaining=_cbor_buf_bytes(s))
        try:
            text = _cbor_buf_bytes(remainder[:length]).decode('utf-8')
        except UnicodeDecodeError as e:
            raise CBOR_Codec_Decoding_Error(
                "Invalid UTF-8 in text string: %s" % str(e),
                remaining=_cbor_buf_bytes(s))
        return cls.cbor_object(text), remainder[length:]


class CBORcodec_ARRAY(CBORcodec_Object[List[Any]]):
    """CBOR array codec (major type 4)"""
    tag = CBOR_MajorTypes.ARRAY

    @classmethod
    def enc(cls, obj):
        # type: (Union[List[Any], CBOR_Object[List[Any]]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        array = obj.val if isinstance(obj, CBOR_Object) else obj
        parts = [CBOR_encode_head(4, len(array))]
        parts.extend(
            CBORcodec_Object.encode_cbor_item(item)
            for item in array
        )
        return b"".join(parts)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               _depth=0,  # type: int
               ):
        # type: (...) -> Tuple[CBOR_Object[List[Any]], bytes]
        cls.check_string(s)
        major_type, length, remainder = CBOR_decode_head(s)
        if major_type != 4:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 4 (array), got %d" % major_type,
                remaining=s)

        items = []
        if length is CBOR_INDEFINITE:
            while True:
                if cbor_is_break(remainder):
                    remainder = cbor_consume_break(remainder)
                    break
                if not remainder:
                    raise CBOR_Codec_Decoding_Error(
                        "Not enough items in array", remaining=s)
                item, remainder = CBORcodec_Object.decode_cbor_item(
                    remainder, safe=False, depth=_depth + 1)
                items.append(item)
        else:
            for _ in range(length):
                if not remainder:
                    raise CBOR_Codec_Decoding_Error(
                        "Not enough items in array", remaining=s)
                item, remainder = CBORcodec_Object.decode_cbor_item(
                    remainder, safe=False, depth=_depth + 1)
                items.append(item)

        return cls.cbor_object(items), remainder


class CBORcodec_MAP(CBORcodec_Object[Any]):
    """CBOR map codec (major type 5).

    Maps are stored as an ordered list of ``(key, value)`` CBOR objects so
    that unhashable keys and distinct CBOR items that collide under Python
    equality (``1`` vs ``True``) round-trip faithfully.
    """
    tag = CBOR_MajorTypes.MAP

    @classmethod
    def enc(cls, obj):
        # type: (Any) -> bytes
        from scapy.cbor.cbor import CBOR_Object, CBORMapData
        mapping = obj.val if isinstance(obj, CBOR_Object) else obj
        if isinstance(mapping, CBORMapData):
            pairs = mapping.cbor_pairs()
        elif isinstance(mapping, dict):
            pairs = list(mapping.items())
        else:
            pairs = list(mapping)
        parts = [CBOR_encode_head(5, len(pairs))]
        for key, value in pairs:
            parts.append(CBORcodec_Object.encode_cbor_item(key))
            parts.append(CBORcodec_Object.encode_cbor_item(value))
        return b"".join(parts)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               _depth=0,  # type: int
               ):
        # type: (...) -> Tuple[CBOR_Object[Any], bytes]
        from scapy.cbor.cbor import CBORMapData
        cls.check_string(s)
        major_type, length, remainder = CBOR_decode_head(s)
        if major_type != 5:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 5 (map), got %d" % major_type,
                remaining=s)

        pairs = []  # type: List[Tuple[Any, Any]]
        seen_keys = set()  # type: set[bytes]

        def _add_pair(key, value):
            # type: (Any, Any) -> None
            # CBOR_FLOAT preserves received wire bytes in enc(), so distinct
            # float/NaN encodings remain distinct while semantic duplicates
            # (e.g. 1 vs 0x18 0x01) still collapse via preferred encoding.
            key_wire = CBORcodec_Object.encode_cbor_item(key)
            if key_wire in seen_keys:
                raise CBOR_Codec_Decoding_Error(
                    "Duplicate CBOR map key: %r" % (key,),
                    remaining=s)
            seen_keys.add(key_wire)
            pairs.append((key, value))

        if length is CBOR_INDEFINITE:
            while True:
                if cbor_is_break(remainder):
                    remainder = cbor_consume_break(remainder)
                    break
                if not remainder:
                    raise CBOR_Codec_Decoding_Error(
                        "Not enough key-value pairs in map", remaining=s)
                key, remainder = CBORcodec_Object.decode_cbor_item(
                    remainder, safe=False, depth=_depth + 1)
                if not remainder:
                    raise CBOR_Codec_Decoding_Error(
                        "Map key without value", remaining=s)
                value, remainder = CBORcodec_Object.decode_cbor_item(
                    remainder, safe=False, depth=_depth + 1)
                _add_pair(key, value)
        else:
            for _ in range(length):
                if not remainder:
                    raise CBOR_Codec_Decoding_Error(
                        "Not enough key-value pairs in map", remaining=s)
                key, remainder = CBORcodec_Object.decode_cbor_item(
                    remainder, safe=False, depth=_depth + 1)
                if not remainder:
                    raise CBOR_Codec_Decoding_Error(
                        "Map key without value", remaining=s)
                value, remainder = CBORcodec_Object.decode_cbor_item(
                    remainder, safe=False, depth=_depth + 1)
                _add_pair(key, value)

        return cls.cbor_object(CBORMapData(pairs)), remainder


class CBORcodec_SEMANTIC_TAG(CBORcodec_Object[Tuple[int, Any]]):
    """CBOR semantic tag codec (major type 6)"""
    tag = CBOR_MajorTypes.TAG

    @classmethod
    def enc(cls, obj):
        # type: (Union[Tuple[int, Any], CBOR_Object[Tuple[int, Any]]]) -> bytes
        from scapy.cbor.cbor import CBOR_Object
        tagged_item = obj.val if isinstance(obj, CBOR_Object) else obj
        tag_num, item = tagged_item
        if tag_num < 0 or tag_num > 0xFFFFFFFFFFFFFFFF:
            raise CBOR_Codec_Encoding_Error(
                "Semantic tag number out of uint64 range")
        return (
            CBOR_encode_head(6, tag_num)
            + CBORcodec_Object.encode_cbor_item(item)
        )

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               _depth=0,  # type: int
               ):
        # type: (...) -> Tuple[CBOR_Object[Tuple[int, Any]], bytes]
        cls.check_string(s)
        major_type, tag_num, remainder = CBOR_decode_head(s)
        if major_type != 6:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 6 (tag), got %d" % major_type,
                remaining=s)

        if not remainder:
            raise CBOR_Codec_Decoding_Error(
                "Tag without following item", remaining=s)

        item, remainder = CBORcodec_Object.decode_cbor_item(
            remainder, safe=False, depth=_depth + 1)
        return cls.cbor_object((tag_num, item)), remainder


class CBORcodec_SIMPLE_AND_FLOAT(CBORcodec_Object[Union[int, float, bool, None]]):
    """CBOR simple values and floats codec (major type 7)"""
    tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    @classmethod
    def enc(cls, obj):
        # type: (Union[int, float, bool, None, CBOR_Object[Any]]) -> bytes
        from scapy.cbor.cbor import (
            CBOR_FALSE, CBOR_TRUE, CBOR_NULL, CBOR_UNDEFINED, CBOR_Object
        )

        # Check if obj is a CBOR object instance (for special cases like UNDEFINED)
        if isinstance(obj, CBOR_UNDEFINED):
            return chb(0xf7)  # undefined
        elif isinstance(obj, CBOR_NULL):
            return chb(0xf6)  # null
        elif isinstance(obj, CBOR_TRUE):
            return chb(0xf5)  # true
        elif isinstance(obj, CBOR_FALSE):
            return chb(0xf4)  # false
        elif isinstance(obj, CBOR_Object):
            # For other CBOR objects, use their val attribute
            val = obj.val
        else:
            val = obj

        if val is False:
            return chb(0xf4)  # false
        elif val is True:
            return chb(0xf5)  # true
        elif val is None:
            return chb(0xf6)  # null
        elif isinstance(val, float):
            # Preferred serialization (RFC 8949): shortest float that
            # preserves the numeric value. Received non-preferred widths are
            # preserved via packet raw caches, not by this encoder.
            ai = _cbor_preferred_float_ai(val)
            if ai == 25:
                half = _cbor_float_to_half_bits(val)
                if half is not None:
                    return chb(0xf9) + struct.pack(">H", half)
                ai = 26
            if ai == 26:
                try:
                    return chb(0xfa) + struct.pack(">f", val)
                except (OverflowError, struct.error):
                    pass
            return chb(0xfb) + struct.pack(">d", val)
        elif isinstance(val, int) and 0 <= val <= 23:
            # Simple value 0-23
            return CBOR_encode_head(7, val)
        elif isinstance(val, int) and 32 <= val <= 255:
            return b"\xf8" + chb(val)
        else:
            raise CBOR_Codec_Encoding_Error(
                "Cannot encode value as simple/float: %r" % val)

    @classmethod
    def do_dec(cls,
               s,  # type: bytes
               context=None,  # type: Optional[Any]
               safe=False,  # type: bool
               _depth=0,  # type: int
               ):
        # type: (...) -> Tuple[CBOR_Object[Any], bytes]
        from scapy.cbor.cbor import (
            CBOR_FALSE, CBOR_TRUE, CBOR_NULL, CBOR_UNDEFINED,
            CBOR_FLOAT, CBOR_SIMPLE_VALUE
        )

        cls.check_string(s)

        # For major type 7, we need special handling because additional_info
        # encodes different things (simple values vs float sizes)
        initial_byte = s[0]
        major_type = initial_byte >> 5
        additional_info = initial_byte & 0x1f

        if major_type != 7:
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 7 (simple/float), got %d" % major_type,
                remaining=s)

        # Check for special simple values (encoded directly in additional_info)
        if additional_info == 20:
            return CBOR_FALSE(), s[1:]
        elif additional_info == 21:
            return CBOR_TRUE(), s[1:]
        elif additional_info == 22:
            return CBOR_NULL(), s[1:]
        elif additional_info == 23:
            return CBOR_UNDEFINED(), s[1:]
        elif additional_info == 25:
            # Half precision float (2 bytes) - IEEE 754 binary16
            if len(s) < 3:
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for half float", remaining=s)
            half_bytes = s[1:3]
            remainder = s[3:]
            # Convert IEEE 754 binary16 to binary64 (double)
            half_int = struct.unpack(">H", half_bytes)[0]
            sign = (half_int >> 15) & 0x1
            exponent = (half_int >> 10) & 0x1f
            fraction = half_int & 0x3ff

            # Handle special cases
            if exponent == 0:
                if fraction == 0:
                    # Zero
                    float_val = -0.0 if sign else 0.0
                else:
                    # Subnormal number
                    float_val = ((-1) ** sign) * (fraction / 1024.0) * (2 ** -14)
            elif exponent == 31:
                if fraction == 0:
                    # Infinity
                    float_val = float('-inf') if sign else float('inf')
                else:
                    # NaN
                    float_val = float('nan')
            else:
                # Normalized number
                float_val = (
                    ((-1) ** sign) *
                    (1 + fraction / 1024.0) *
                    (2 ** (exponent - 15)))

            return CBOR_FLOAT(float_val, encoded=_cbor_buf_bytes(s[:3])), remainder
        elif additional_info == 26:
            # Single precision float (4 bytes)
            if len(s) < 5:
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for single float", remaining=s)
            float_val = struct.unpack(">f", s[1:5])[0]
            return CBOR_FLOAT(float_val, encoded=_cbor_buf_bytes(s[:5])), s[5:]
        elif additional_info == 27:
            # Double precision float (8 bytes)
            if len(s) < 9:
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for double float", remaining=s)
            float_val = struct.unpack(">d", s[1:9])[0]
            return CBOR_FLOAT(float_val, encoded=_cbor_buf_bytes(s[:9])), s[9:]
        elif additional_info < 24:
            # Simple value 0-23
            return CBOR_SIMPLE_VALUE(additional_info), s[1:]
        else:
            # additional_info 24 means 1-byte simple value follows
            if additional_info == 24:
                if len(s) < 2:
                    raise CBOR_Codec_Decoding_Error(
                        "Not enough bytes for simple value", remaining=s)
                simple = s[1]
                if simple < 32:
                    raise CBOR_Codec_Decoding_Error(
                        "Two-byte simple-value encoding below 32 "
                        "is not well-formed",
                        remaining=s)
                return CBOR_SIMPLE_VALUE(simple), s[2:]
            else:
                raise CBOR_Codec_Decoding_Error(
                    "Invalid additional info for major type 7: %d" % additional_info,
                    remaining=s)


# Helper methods for encoding/decoding arbitrary CBOR items


def _encode_cbor_item(item):
    # type: (Any) -> bytes
    """Encode a Python value to CBOR bytes"""
    from scapy.cbor.cbor import (
        CBOR_Object,
        CBOR_UNDEFINED,
        CBOR_UNDEFINED_VALUE,
        CBORMapData,
        CBORTagValue,
        CBORSimpleValue,
        CBOR_SIMPLE_VALUE,
    )

    if isinstance(item, CBOR_Object):
        return item.enc()
    elif item is CBOR_UNDEFINED_VALUE:
        return CBOR_UNDEFINED().enc()
    elif isinstance(item, CBORTagValue):
        return (
            CBOR_encode_head(6, item.tag) +
            _encode_cbor_item(item.value)
        )
    elif isinstance(item, CBORSimpleValue):
        return CBORcodec_SIMPLE_AND_FLOAT.enc(CBOR_SIMPLE_VALUE(item.value))
    elif isinstance(item, CBORMapData):
        return CBORcodec_MAP.enc(item)
    elif isinstance(item, bool):
        # Must check bool before int (bool is subclass of int)
        return CBORcodec_SIMPLE_AND_FLOAT.enc(item)
    elif isinstance(item, int):
        if item >= 0:
            return CBORcodec_UNSIGNED_INTEGER.enc(item)
        else:
            return CBORcodec_NEGATIVE_INTEGER.enc(item)
    elif isinstance(item, bytes):
        return CBORcodec_BYTE_STRING.enc(item)
    elif isinstance(item, str):
        return CBORcodec_TEXT_STRING.enc(item)
    elif isinstance(item, list):
        return CBORcodec_ARRAY.enc(item)
    elif isinstance(item, dict):
        return CBORcodec_MAP.enc(item)
    elif isinstance(item, float):
        encoded = getattr(item, "cbor_encoded", None)
        if encoded is not None:
            return encoded
        return CBORcodec_SIMPLE_AND_FLOAT.enc(item)
    elif item is None:
        return CBORcodec_SIMPLE_AND_FLOAT.enc(None)
    else:
        raise CBOR_Codec_Encoding_Error(
            "Cannot encode type: %s" % type(item))


def _encode_cbor_map_deterministic(pairs):
    # type: (Any) -> bytes
    """Encode map pairs in RFC 8949 core-deterministic key order."""
    encoded_pairs = []  # type: List[Tuple[bytes, bytes]]
    for key, value in pairs:
        key_bytes = _encode_cbor_item_deterministic(key)
        value_bytes = _encode_cbor_item_deterministic(value)
        encoded_pairs.append((key_bytes, value_bytes))
    encoded_pairs.sort(key=lambda item: item[0])
    parts = [CBOR_encode_head(5, len(encoded_pairs))]
    for key_bytes, value_bytes in encoded_pairs:
        parts.append(key_bytes)
        parts.append(value_bytes)
    return b"".join(parts)


def _encode_cbor_item_deterministic(item):
    # type: (Any) -> bytes
    """Encode a Python value using RFC 8949 core-deterministic rules.

    Unlike :func:`_encode_cbor_item`, map keys at every nesting level are
    sorted by their deterministic encoded bytes. Intended for schema-driven
    rebuild paths such as preserved unknown ``CBORF_MAP`` members.

    :class:`~scapy.cbor.cbor.CBOR_Object` wrappers are accepted and reduced to
    native values (preferred float encoding, deterministic nested maps).
    """
    from scapy.cbor.cbor import (
        CBOR_Object,
        CBOR_ARRAY,
        CBOR_MAP,
        CBOR_SEMANTIC_TAG,
        CBOR_SIMPLE_VALUE,
        CBOR_UNDEFINED,
        CBOR_UNDEFINED_VALUE,
        CBORMapData,
        CBORTagValue,
        CBORSimpleValue,
    )

    if isinstance(item, CBOR_Object):
        if isinstance(item, CBOR_UNDEFINED):
            return CBOR_UNDEFINED().enc()
        if isinstance(item, CBOR_ARRAY):
            return _encode_cbor_item_deterministic(list(item.val))
        if isinstance(item, CBOR_MAP):
            if isinstance(item.val, CBORMapData):
                return _encode_cbor_map_deterministic(item.val.cbor_pairs())
            if isinstance(item.val, list):
                return _encode_cbor_map_deterministic(item.val)
            return _encode_cbor_map_deterministic(list(item.val.items()))
        if isinstance(item, CBOR_SEMANTIC_TAG):
            tag_num, inner = item.val
            return (
                CBOR_encode_head(6, tag_num)
                + _encode_cbor_item_deterministic(inner)
            )
        if isinstance(item, CBOR_SIMPLE_VALUE):
            return CBORcodec_SIMPLE_AND_FLOAT.enc(item)
        return _encode_cbor_item_deterministic(item.val)
    if item is CBOR_UNDEFINED_VALUE:
        return CBOR_UNDEFINED().enc()
    if isinstance(item, CBORTagValue):
        return (
            CBOR_encode_head(6, item.tag)
            + _encode_cbor_item_deterministic(item.value)
        )
    if isinstance(item, CBORSimpleValue):
        return CBORcodec_SIMPLE_AND_FLOAT.enc(CBOR_SIMPLE_VALUE(item.value))
    if isinstance(item, CBORMapData):
        return _encode_cbor_map_deterministic(item.cbor_pairs())
    if isinstance(item, dict):
        return _encode_cbor_map_deterministic(list(item.items()))
    if isinstance(item, list):
        encoded_items = [
            _encode_cbor_item_deterministic(element) for element in item
        ]
        return CBOR_encode_head(4, len(encoded_items)) + b"".join(encoded_items)
    if isinstance(item, bool):
        return CBORcodec_SIMPLE_AND_FLOAT.enc(item)
    if isinstance(item, int):
        if item >= 0:
            return CBORcodec_UNSIGNED_INTEGER.enc(item)
        return CBORcodec_NEGATIVE_INTEGER.enc(item)
    if isinstance(item, bytes):
        return CBORcodec_BYTE_STRING.enc(item)
    if isinstance(item, str):
        return CBORcodec_TEXT_STRING.enc(item)
    if isinstance(item, float):
        # Preserve dissected wire (e.g. NaN payloads) when known; otherwise
        # fall back to preferred-width encoding.
        encoded = getattr(item, "cbor_encoded", None)
        if encoded is not None:
            return encoded
        return CBORcodec_SIMPLE_AND_FLOAT.enc(item)
    if item is None:
        return CBORcodec_SIMPLE_AND_FLOAT.enc(None)
    raise CBOR_Codec_Encoding_Error(
        "Cannot deterministically encode type: %s" % type(item)
    )


def _decode_cbor_item(s, safe=False, depth=0):
    # type: (Any, bool, int) -> Tuple[CBOR_Object[Any], Any]
    """Decode CBOR bytes to a CBOR_Object.

    Top-level callers may pass ``bytes`` (or a subclass). Decoding then works
    on a ``memoryview`` so unread suffixes are not recopied per item.
    """
    if depth > MAX_CBOR_NESTING:
        raise CBOR_Codec_Decoding_Error(
            "Maximum CBOR nesting depth exceeded",
            remaining=_cbor_buf_bytes(s))
    if not isinstance(s, memoryview):
        obj, rem = _decode_cbor_item(memoryview(s), safe=False, depth=depth)
        return obj, _cbor_buf_bytes(rem) if isinstance(rem, memoryview) else rem
    if not s:
        raise CBOR_Codec_Decoding_Error(
            "Empty CBOR data", remaining=_cbor_buf_bytes(s))

    if cbor_is_break(s):
        raise CBOR_Codec_Decoding_Error(
            "Standalone break byte (0xff)", remaining=_cbor_buf_bytes(s))

    initial_byte = s[0]
    major_type = initial_byte >> 5

    # Dispatch to appropriate codec based on major type
    if major_type == 0:
        return CBORcodec_UNSIGNED_INTEGER.dec(s, safe=False, _depth=depth)
    elif major_type == 1:
        return CBORcodec_NEGATIVE_INTEGER.dec(s, safe=False, _depth=depth)
    elif major_type == 2:
        return CBORcodec_BYTE_STRING.dec(s, safe=False, _depth=depth)
    elif major_type == 3:
        return CBORcodec_TEXT_STRING.dec(s, safe=False, _depth=depth)
    elif major_type == 4:
        return CBORcodec_ARRAY.dec(s, safe=False, _depth=depth)
    elif major_type == 5:
        return CBORcodec_MAP.dec(s, safe=False, _depth=depth)
    elif major_type == 6:
        return CBORcodec_SEMANTIC_TAG.dec(s, safe=False, _depth=depth)
    elif major_type == 7:
        return CBORcodec_SIMPLE_AND_FLOAT.dec(s, safe=False, _depth=depth)
    else:
        raise CBOR_Codec_Decoding_Error(
            "Invalid major type: %d" % major_type,
            remaining=_cbor_buf_bytes(s))


# Add helper methods to CBORcodec_Object
CBORcodec_Object.encode_cbor_item = staticmethod(_encode_cbor_item)
CBORcodec_Object.encode_cbor_item_deterministic = staticmethod(
    _encode_cbor_item_deterministic
)
CBORcodec_Object.decode_cbor_item = staticmethod(_decode_cbor_item)
