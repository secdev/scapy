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
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

from scapy.cbor.cbor import (
    CBOR_AdditionalInfo,
    CBOR_Codecs,
    CBOR_DECODING_ERROR,
    CBOR_Decoding_Error,
    CBOR_Encoding_Error,
    CBOR_Error,
    CBOR_FloatAI,
    CBOR_MajorTypes,
    CBOR_Object,
    CBOR_SimpleValue,
    CBOR_UINT64_MAX,
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
    if value < 0 or value > CBOR_UINT64_MAX:
        raise CBOR_Codec_Encoding_Error(
            "CBOR head value out of uint64 range: %r" % (value,))
    if value < 24:
        # Value fits in 5 bits
        return chb((major_type << 5) | value)
    elif value < 256:
        # 1-byte value follows
        return (
            chb((major_type << 5) | int(CBOR_AdditionalInfo.ONE_BYTE))
            + chb(value)
        )
    elif value < 65536:
        # 2-byte value follows
        return (
            chb((major_type << 5) | int(CBOR_AdditionalInfo.TWO_BYTES))
            + struct.pack(">H", value)
        )
    elif value < 4294967296:
        # 4-byte value follows
        return (
            chb((major_type << 5) | int(CBOR_AdditionalInfo.FOUR_BYTES))
            + struct.pack(">I", value)
        )
    else:
        # 8-byte value follows
        return (
            chb((major_type << 5) | int(CBOR_AdditionalInfo.EIGHT_BYTES))
            + struct.pack(">Q", value)
        )


def CBOR_encode_indefinite_head(major_type):
    # type: (int) -> bytes
    """Encode a CBOR indefinite-length header (additional info 31)."""
    if major_type not in (
        int(CBOR_MajorTypes.BYTE_STRING),
        int(CBOR_MajorTypes.TEXT_STRING),
        int(CBOR_MajorTypes.ARRAY),
        int(CBOR_MajorTypes.MAP),
    ):
        raise CBOR_Codec_Encoding_Error(
            "Indefinite length not allowed for major type %d" % major_type
        )
    return chb((major_type << 5) | int(CBOR_AdditionalInfo.INDEFINITE))


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


def cbor_skip_item(s):
    # type: (Any) -> Any
    """Advance past one well-formed CBOR item without building objects."""
    major_type, value, rem = CBOR_decode_head(s)
    if major_type in (
        int(CBOR_MajorTypes.UNSIGNED_INTEGER),
        int(CBOR_MajorTypes.NEGATIVE_INTEGER),
        int(CBOR_MajorTypes.SIMPLE_AND_FLOAT),
    ):
        return rem
    if major_type in (
        int(CBOR_MajorTypes.BYTE_STRING),
        int(CBOR_MajorTypes.TEXT_STRING),
    ):
        if value is CBOR_INDEFINITE:
            while rem and not cbor_is_break(rem):
                rem = cbor_skip_item(rem)
            return cbor_consume_break(rem)
        length = int(value)
        if len(rem) < length:
            raise CBOR_Codec_Decoding_Error(
                "Truncated byte/text string", remaining=_cbor_buf_bytes(s))
        return rem[length:]
    if major_type == int(CBOR_MajorTypes.ARRAY):
        if value is CBOR_INDEFINITE:
            while rem and not cbor_is_break(rem):
                rem = cbor_skip_item(rem)
            return cbor_consume_break(rem)
        for _ in range(int(value)):
            rem = cbor_skip_item(rem)
        return rem
    if major_type == int(CBOR_MajorTypes.MAP):
        if value is CBOR_INDEFINITE:
            while rem and not cbor_is_break(rem):
                rem = cbor_skip_item(rem)
                rem = cbor_skip_item(rem)
            return cbor_consume_break(rem)
        for _ in range(int(value)):
            rem = cbor_skip_item(rem)
            rem = cbor_skip_item(rem)
        return rem
    if major_type == int(CBOR_MajorTypes.TAG):
        return cbor_skip_item(rem)
    raise CBOR_Codec_Decoding_Error(
        "Invalid major type: %d" % major_type,
        remaining=_cbor_buf_bytes(s),
    )


def cbor_count_items(s, max_count=None, until_break=False):
    # type: (Any, Optional[int], bool) -> int
    """Count top-level CBOR items with ``cbor_skip_item`` (no object trees).

    When *until_break* is true, stop at a break byte without consuming it.
    When *max_count* is set, stop after that many items even if more remain.
    """
    rem = s
    count = 0
    while rem and not (until_break and cbor_is_break(rem)):
        if max_count is not None and count >= max_count:
            break
        rem = cbor_skip_item(rem)
        count += 1
    return count


def cbor_count_items_until_break(s):
    # type: (Any) -> int
    """Count definite top-level items before a break without building objects."""
    return cbor_count_items(s, until_break=True)


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
    elif additional_info == int(CBOR_AdditionalInfo.ONE_BYTE):
        # 1-byte value follows
        if len(s) < 2:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 1-byte value",
                remaining=_cbor_buf_bytes(s))
        return major_type, s[1], s[2:]
    elif additional_info == int(CBOR_AdditionalInfo.TWO_BYTES):
        # 2-byte value follows
        if len(s) < 3:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 2-byte value",
                remaining=_cbor_buf_bytes(s))
        value = struct.unpack(">H", s[1:3])[0]
        return major_type, value, s[3:]
    elif additional_info == int(CBOR_AdditionalInfo.FOUR_BYTES):
        # 4-byte value follows
        if len(s) < 5:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 4-byte value",
                remaining=_cbor_buf_bytes(s))
        value = struct.unpack(">I", s[1:5])[0]
        return major_type, value, s[5:]
    elif additional_info == int(CBOR_AdditionalInfo.EIGHT_BYTES):
        # 8-byte value follows
        if len(s) < 9:
            raise CBOR_Codec_Decoding_Error(
                "Not enough bytes for 8-byte value",
                remaining=_cbor_buf_bytes(s))
        value = struct.unpack(">Q", s[1:9])[0]
        return major_type, value, s[9:]
    elif additional_info == int(CBOR_AdditionalInfo.INDEFINITE):
        if major_type in (
                int(CBOR_MajorTypes.UNSIGNED_INTEGER),
                int(CBOR_MajorTypes.NEGATIVE_INTEGER),
                int(CBOR_MajorTypes.TAG),
        ):
            raise CBOR_Codec_Decoding_Error(
                "Indefinite length not allowed for major type %d" %
                major_type, remaining=_cbor_buf_bytes(s))
        if major_type in (
                int(CBOR_MajorTypes.BYTE_STRING),
                int(CBOR_MajorTypes.TEXT_STRING),
                int(CBOR_MajorTypes.ARRAY),
                int(CBOR_MajorTypes.MAP),
        ):
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
        return additional_info == int(CBOR_AdditionalInfo.INDEFINITE)
    if additional_info < 24:
        return True
    if additional_info == int(CBOR_AdditionalInfo.ONE_BYTE):
        return value >= 24
    if additional_info == int(CBOR_AdditionalInfo.TWO_BYTES):
        return value >= 256
    if additional_info == int(CBOR_AdditionalInfo.FOUR_BYTES):
        return value >= 65536
    if additional_info == int(CBOR_AdditionalInfo.EIGHT_BYTES):
        return value >= (1 << 32)
    return additional_info == int(CBOR_AdditionalInfo.INDEFINITE)


def _cbor_float_from_bits(ai, bits):
    # type: (int, int) -> float
    if ai == int(CBOR_FloatAI.HALF):
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
    if ai == int(CBOR_FloatAI.SINGLE):
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
        if _cbor_float_from_bits(int(CBOR_FloatAI.HALF), sign | half) != preferred:
            # Compare absolute then restore sign via copysign on left side
            decoded = _cbor_float_from_bits(int(CBOR_FloatAI.HALF), sign | half)
            if decoded != math.copysign(abs(value), -1.0 if sign else 1.0):
                return None
        return sign | half
    half_exp = exp64 + 15
    half_mant = mant64 >> 42
    # Reject if discarded mantissa bits are nonzero (not exact).
    if mant64 & ((1 << 42) - 1):
        return None
    bits = sign | (half_exp << 10) | half_mant
    decoded = _cbor_float_from_bits(int(CBOR_FloatAI.HALF), bits)
    if decoded != math.copysign(abs(value), -1.0 if sign else 1.0):
        return None
    return bits


def _cbor_nan_preferred_ai(ai, bits):
    # type: (int, int) -> int
    """Preferred float AI for a NaN, based on the original bit pattern.

    RFC 8949 prefers a shorter NaN only when zero-padding the shorter
    significand reconstructs the original NaN payload.
    """
    if ai == int(CBOR_FloatAI.HALF):
        return int(CBOR_FloatAI.HALF)
    if ai == int(CBOR_FloatAI.SINGLE):
        # binary32 NaN: 1+8+23. Prefer half when low 13 significand bits are 0.
        mant = int(bits) & 0x7FFFFF
        if mant and (mant & ((1 << 13) - 1)) == 0:
            return int(CBOR_FloatAI.HALF)
        return int(CBOR_FloatAI.SINGLE)
    if ai == int(CBOR_FloatAI.DOUBLE):
        # binary64 NaN: 1+11+52.
        mant = int(bits) & ((1 << 52) - 1)
        if mant == 0:
            # Infinity, not NaN — caller should not use this helper.
            return int(CBOR_FloatAI.DOUBLE)
        # Prefer half when only the top 10 significand bits are used.
        if (mant & ((1 << 42) - 1)) == 0:
            return int(CBOR_FloatAI.HALF)
        # Prefer single when only the top 23 significand bits are used.
        if (mant & ((1 << 29) - 1)) == 0:
            return int(CBOR_FloatAI.SINGLE)
        return int(CBOR_FloatAI.DOUBLE)
    return ai


def _cbor_nan_components(ai, bits):
    # type: (int, int) -> Optional[Tuple[int, int]]
    """Return ``(sign, significand52)`` for a NaN pattern, else ``None``.

    The significand is zero-extended to a binary64-width 52-bit field so
    half / single / double representations of the same NaN share identity.
    """
    if ai == int(CBOR_FloatAI.HALF):
        sign = (int(bits) >> 15) & 0x1
        exponent = (int(bits) >> 10) & 0x1f
        fraction = int(bits) & 0x3ff
        if exponent != 31 or not fraction:
            return None
        return sign, fraction << 42
    if ai == int(CBOR_FloatAI.SINGLE):
        sign = (int(bits) >> 31) & 0x1
        exponent = (int(bits) >> 23) & 0xff
        fraction = int(bits) & 0x7fffff
        if exponent != 0xff or not fraction:
            return None
        return sign, fraction << 29
    if ai == int(CBOR_FloatAI.DOUBLE):
        sign = (int(bits) >> 63) & 0x1
        exponent = (int(bits) >> 52) & 0x7ff
        fraction = int(bits) & ((1 << 52) - 1)
        if exponent != 0x7ff or not fraction:
            return None
        return sign, fraction
    return None


def _cbor_encode_nan(sign, significand52, ai):
    # type: (int, int, int) -> bytes
    """Encode a NaN at float AI *ai* preserving *sign* and *significand52*."""
    if ai == int(CBOR_FloatAI.HALF):
        fraction = (significand52 >> 42) & 0x3ff
        bits = (sign << 15) | (0x1f << 10) | fraction
        return chb(
            (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
            | int(CBOR_FloatAI.HALF)
        ) + struct.pack(">H", bits)
    if ai == int(CBOR_FloatAI.SINGLE):
        fraction = (significand52 >> 29) & 0x7fffff
        bits = (sign << 31) | (0xff << 23) | fraction
        return chb(
            (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
            | int(CBOR_FloatAI.SINGLE)
        ) + struct.pack(">I", bits)
    if ai == int(CBOR_FloatAI.DOUBLE):
        bits = (
            (sign << 63) |
            (0x7ff << 52) |
            (significand52 & ((1 << 52) - 1))
        )
        return chb(
            (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
            | int(CBOR_FloatAI.DOUBLE)
        ) + struct.pack(">Q", bits)
    raise CBOR_Codec_Encoding_Error("Invalid NaN float AI: %d" % ai)


def _cbor_float_bits_from_encoded(encoded):
    # type: (bytes) -> Tuple[int, int]
    """Return ``(ai, bits)`` for a definite CBOR float item."""
    wire = bytes(encoded)
    if not wire:
        raise CBOR_Codec_Encoding_Error("empty CBOR float encoding")
    ai = wire[0] & 0x1f
    if ai == int(CBOR_FloatAI.HALF):
        if len(wire) < 3:
            raise CBOR_Codec_Encoding_Error("truncated half float")
        return ai, struct.unpack(">H", wire[1:3])[0]
    if ai == int(CBOR_FloatAI.SINGLE):
        if len(wire) < 5:
            raise CBOR_Codec_Encoding_Error("truncated single float")
        return ai, struct.unpack(">I", wire[1:5])[0]
    if ai == int(CBOR_FloatAI.DOUBLE):
        if len(wire) < 9:
            raise CBOR_Codec_Encoding_Error("truncated double float")
        return ai, struct.unpack(">Q", wire[1:9])[0]
    raise CBOR_Codec_Encoding_Error("not a CBOR float encoding: ai=%d" % ai)


def _cbor_preferred_float_ai(value):
    # type: (float) -> int
    """Return the preferred float AI for a numeric *value*."""
    import math
    if math.isnan(value):
        # Without the original payload bits, only the quiet binary16 NaN is a
        # safe generic preference. Encoded-width checks use bit patterns.
        return int(CBOR_FloatAI.HALF)
    if _cbor_float_to_half_bits(value) is not None:
        return int(CBOR_FloatAI.HALF)
    try:
        single = struct.unpack(">f", struct.pack(">f", value))[0]
    except (OverflowError, struct.error):
        return int(CBOR_FloatAI.DOUBLE)
    if single == value or (math.isinf(single) and math.isinf(value)):
        return int(CBOR_FloatAI.SINGLE)
    return int(CBOR_FloatAI.DOUBLE)


def cbor_find_non_deterministic(s, allow_indefinite=False, base_offset=0):
    # type: (bytes, bool, int) -> List[Tuple[int, str]]
    """Scan one top-level CBOR item for non-core-deterministic encodings.

    Walks a single top-level item (and nested contents). Trailing bytes after
    that item are ignored. Returns ``(absolute_offset, message)`` issues.
    Indefinite-length items are rejected by default; protocols that permit
    them may pass ``allow_indefinite=True``.
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
        elif ai == int(CBOR_AdditionalInfo.ONE_BYTE):
            if pos + 1 > len(s):
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for 1-byte value", remaining=s[start:])
            value = s[pos]
            pos += 1
        elif ai == int(CBOR_AdditionalInfo.TWO_BYTES):
            if pos + 2 > len(s):
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for 2-byte value", remaining=s[start:])
            value = struct.unpack(">H", s[pos:pos + 2])[0]
            pos += 2
        elif ai == int(CBOR_AdditionalInfo.FOUR_BYTES):
            if pos + 4 > len(s):
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for 4-byte value", remaining=s[start:])
            value = struct.unpack(">I", s[pos:pos + 4])[0]
            pos += 4
        elif ai == int(CBOR_AdditionalInfo.EIGHT_BYTES):
            if pos + 8 > len(s):
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for 8-byte value", remaining=s[start:])
            value = struct.unpack(">Q", s[pos:pos + 8])[0]
            pos += 8
        elif ai == int(CBOR_AdditionalInfo.INDEFINITE):
            value = CBOR_INDEFINITE
        else:
            raise CBOR_Codec_Decoding_Error(
                "Invalid additional info: %d" % ai, remaining=s[start:])
        index[0] = pos

        # Major type 7: simple values and floats. Check float preferred width.
        if major == 7:
            if (
                ai == int(CBOR_AdditionalInfo.ONE_BYTE)
                and isinstance(value, int)
                and value < 32
            ):
                issues.append((
                    base_offset + start,
                    "Non-shortest CBOR simple value encoding "
                    "(AI=24, value=%d)" % value,
                ))
            if ai in (
                int(CBOR_FloatAI.HALF),
                int(CBOR_FloatAI.SINGLE),
                int(CBOR_FloatAI.DOUBLE),
            ) and value is not CBOR_INDEFINITE:
                comps = _cbor_nan_components(ai, int(value))
                if comps is not None:
                    preferred = _cbor_nan_preferred_ai(ai, int(value))
                else:
                    preferred = _cbor_preferred_float_ai(
                        _cbor_float_from_bits(ai, int(value))
                    )
                if preferred < ai:
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
        return CBORcodec_Object.decode_cbor_item(s, depth=_depth)

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

    @staticmethod
    def encode_cbor_item(item):
        # type: (Any) -> bytes
        """Encode a Python value to CBOR bytes"""
        from scapy.cbor.cbor import (
            CBOR_Object,
            CBORMapData,
        )

        if isinstance(item, CBOR_Object):
            return item.enc()
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
            return CBORcodec_SIMPLE_AND_FLOAT.enc(item)
        elif item is None:
            return CBORcodec_SIMPLE_AND_FLOAT.enc(None)
        else:
            raise CBOR_Codec_Encoding_Error(
                "Cannot encode type: %s" % type(item))

    @staticmethod
    def _reject_duplicate_map_keys(pairs):
        # type: (Any) -> None
        """Raise if *pairs* contain CBOR-equivalent duplicate keys."""
        from scapy.cbor.cbor import _cbor_key_norm
        seen_norms = set()  # type: Set[Any]
        for key, _value in pairs:
            norm = _cbor_key_norm(key)
            if norm in seen_norms:
                raise CBOR_Codec_Encoding_Error(
                    "Duplicate CBOR map key: %r" % (key,)
                )
            seen_norms.add(norm)

    @staticmethod
    def _encode_cbor_map_deterministic(pairs):
        # type: (Any) -> bytes
        """Encode map pairs in RFC 8949 core-deterministic key order."""
        pairs = list(pairs)
        CBORcodec_Object._reject_duplicate_map_keys(pairs)
        encoded_pairs = []  # type: List[Tuple[bytes, bytes]]
        for key, value in pairs:
            key_bytes = CBORcodec_Object.encode_cbor_item_deterministic(key)
            value_bytes = CBORcodec_Object.encode_cbor_item_deterministic(
                value
            )
            encoded_pairs.append((key_bytes, value_bytes))
        encoded_pairs.sort(key=lambda item: item[0])
        parts = [CBOR_encode_head(int(CBOR_MajorTypes.MAP), len(encoded_pairs))]
        for key_bytes, value_bytes in encoded_pairs:
            parts.append(key_bytes)
            parts.append(value_bytes)
        return b"".join(parts)

    @staticmethod
    def encode_cbor_item_deterministic(item):
        # type: (Any) -> bytes
        """Encode a Python value using RFC 8949 core-deterministic rules.

        Unlike :meth:`encode_cbor_item`, map keys at every nesting level are
        sorted by their deterministic encoded bytes. Intended for schema-driven
        rebuild paths such as preserved unknown ``CBORF_MAP`` members.

        :class:`~scapy.cbor.cbor.CBOR_Object` instances are accepted and reduced
        to native values (preferred float encoding, deterministic nested maps).
        """
        import math
        from scapy.cbor.cbor import (
            CBOR_Object,
            CBOR_ARRAY,
            CBOR_FLOAT,
            CBOR_MAP,
            CBOR_SEMANTIC_TAG,
            CBOR_SIMPLE_VALUE,
            CBOR_UNDEFINED,
            CBORMapData,
            _cbor_map_pairs,
        )

        if isinstance(item, CBOR_Object):
            if isinstance(item, CBOR_UNDEFINED):
                return CBOR_UNDEFINED().enc()
            if isinstance(item, CBOR_FLOAT):
                encoded = getattr(item, "_encoded", None)
                if encoded is not None and math.isnan(float(item.val)):
                    ai, bits = _cbor_float_bits_from_encoded(encoded)
                    comps = _cbor_nan_components(ai, bits)
                    if comps is None:
                        raise CBOR_Codec_Encoding_Error(
                            "encoded float is not a NaN: %r"
                            % (bytes(encoded),)
                        )
                    sign, significand52 = comps
                    preferred = _cbor_nan_preferred_ai(ai, bits)
                    return _cbor_encode_nan(sign, significand52, preferred)
                # Finite floats ignore original width; rebuild preferred form.
                return CBORcodec_SIMPLE_AND_FLOAT.enc(float(item.val))
            if isinstance(item, CBOR_ARRAY):
                return CBORcodec_Object.encode_cbor_item_deterministic(
                    list(item.val)
                )
            if isinstance(item, CBOR_MAP):
                return CBORcodec_Object._encode_cbor_map_deterministic(
                    _cbor_map_pairs(item)
                )
            if isinstance(item, CBOR_SEMANTIC_TAG):
                tag_num, inner = item.val
                return (
                    CBOR_encode_head(int(CBOR_MajorTypes.TAG), tag_num)
                    + CBORcodec_Object.encode_cbor_item_deterministic(inner)
                )
            if isinstance(item, CBOR_SIMPLE_VALUE):
                return CBORcodec_SIMPLE_AND_FLOAT.enc(item)
            return CBORcodec_Object.encode_cbor_item_deterministic(item.val)
        if isinstance(item, CBORMapData):
            return CBORcodec_Object._encode_cbor_map_deterministic(
                item.cbor_pairs()
            )
        if isinstance(item, dict):
            return CBORcodec_Object._encode_cbor_map_deterministic(
                list(item.items())
            )
        if isinstance(item, list):
            encoded_items = [
                CBORcodec_Object.encode_cbor_item_deterministic(element)
                for element in item
            ]
            return (
                CBOR_encode_head(int(CBOR_MajorTypes.ARRAY), len(encoded_items))
                + b"".join(encoded_items)
            )
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
            # Deterministic encoding always rebuilds from the semantic float
            # value (shortest exact representation). Never reuse source wire.
            # Plain NaNs without retained CBOR bytes use quiet binary16.
            return CBORcodec_SIMPLE_AND_FLOAT.enc(float(item))
        if item is None:
            return CBORcodec_SIMPLE_AND_FLOAT.enc(None)
        raise CBOR_Codec_Encoding_Error(
            "Cannot deterministically encode type: %s" % type(item)
        )

    @staticmethod
    def decode_cbor_item(s, depth=0):
        # type: (Any, int) -> Tuple[CBOR_Object[Any], Any]
        """Decode CBOR bytes to a CBOR_Object.

        Top-level callers may pass ``bytes`` (or a subclass). Decoding then
        works on a ``memoryview`` so unread suffixes are not recopied per item.
        """
        if depth > MAX_CBOR_NESTING:
            raise CBOR_Codec_Decoding_Error(
                "Maximum CBOR nesting depth exceeded",
                remaining=_cbor_buf_bytes(s))
        if not isinstance(s, memoryview):
            obj, rem = CBORcodec_Object.decode_cbor_item(
                memoryview(s), depth=depth
            )
            return (
                obj,
                _cbor_buf_bytes(rem) if isinstance(rem, memoryview) else rem,
            )
        if not s:
            raise CBOR_Codec_Decoding_Error(
                "Empty CBOR data", remaining=_cbor_buf_bytes(s))

        if cbor_is_break(s):
            raise CBOR_Codec_Decoding_Error(
                "Standalone break byte (0xff)",
                remaining=_cbor_buf_bytes(s))

        initial_byte = s[0]
        major_type = initial_byte >> 5

        # Dispatch to appropriate codec based on major type
        if major_type == int(CBOR_MajorTypes.UNSIGNED_INTEGER):
            return CBORcodec_UNSIGNED_INTEGER.dec(s, safe=False, _depth=depth)
        elif major_type == int(CBOR_MajorTypes.NEGATIVE_INTEGER):
            return CBORcodec_NEGATIVE_INTEGER.dec(s, safe=False, _depth=depth)
        elif major_type == int(CBOR_MajorTypes.BYTE_STRING):
            return CBORcodec_BYTE_STRING.dec(s, safe=False, _depth=depth)
        elif major_type == int(CBOR_MajorTypes.TEXT_STRING):
            return CBORcodec_TEXT_STRING.dec(s, safe=False, _depth=depth)
        elif major_type == int(CBOR_MajorTypes.ARRAY):
            return CBORcodec_ARRAY.dec(s, safe=False, _depth=depth)
        elif major_type == int(CBOR_MajorTypes.MAP):
            return CBORcodec_MAP.dec(s, safe=False, _depth=depth)
        elif major_type == int(CBOR_MajorTypes.TAG):
            return CBORcodec_SEMANTIC_TAG.dec(s, safe=False, _depth=depth)
        elif major_type == int(CBOR_MajorTypes.SIMPLE_AND_FLOAT):
            return CBORcodec_SIMPLE_AND_FLOAT.dec(s, safe=False, _depth=depth)
        else:
            raise CBOR_Codec_Decoding_Error(
                "Invalid major type: %d" % major_type,
                remaining=_cbor_buf_bytes(s))


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
        if i > CBOR_UINT64_MAX:
            raise CBOR_Codec_Encoding_Error(
                "Unsigned integer exceeds uint64 range")
        return CBOR_encode_head(int(CBOR_MajorTypes.UNSIGNED_INTEGER), i)

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
        if major_type != int(CBOR_MajorTypes.UNSIGNED_INTEGER):
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
        if i < -(CBOR_UINT64_MAX + 1):
            raise CBOR_Codec_Encoding_Error(
                "Negative integer below CBOR int64 range")
        # CBOR negative integer: -1 - n
        return CBOR_encode_head(int(CBOR_MajorTypes.NEGATIVE_INTEGER), -1 - i)

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
        if major_type != int(CBOR_MajorTypes.NEGATIVE_INTEGER):
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
        return CBOR_encode_head(int(CBOR_MajorTypes.BYTE_STRING), len(data)) + data

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
        if major_type != int(CBOR_MajorTypes.BYTE_STRING):
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
        return (
            CBOR_encode_head(int(CBOR_MajorTypes.TEXT_STRING), len(text_bytes))
            + text_bytes
        )

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
        if major_type != int(CBOR_MajorTypes.TEXT_STRING):
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
        parts = [CBOR_encode_head(int(CBOR_MajorTypes.ARRAY), len(array))]
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
        if major_type != int(CBOR_MajorTypes.ARRAY):
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
                    remainder, depth=_depth + 1)
                items.append(item)
        else:
            for _ in range(length):
                if not remainder:
                    raise CBOR_Codec_Decoding_Error(
                        "Not enough items in array", remaining=s)
                item, remainder = CBORcodec_Object.decode_cbor_item(
                    remainder, depth=_depth + 1)
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
        from scapy.cbor.cbor import CBOR_Object, _cbor_map_pairs
        mapping = obj.val if isinstance(obj, CBOR_Object) else obj
        pairs = _cbor_map_pairs(mapping)
        CBORcodec_Object._reject_duplicate_map_keys(pairs)
        parts = [CBOR_encode_head(int(CBOR_MajorTypes.MAP), len(pairs))]
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
        if major_type != int(CBOR_MajorTypes.MAP):
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 5 (map), got %d" % major_type,
                remaining=s)

        pairs = []  # type: List[Tuple[Any, Any]]
        seen_norms = set()  # type: Set[Any]

        def _add_pair(key, value):
            # type: (Any, Any) -> None
            from scapy.cbor.cbor import _cbor_key_norm
            norm = _cbor_key_norm(key)
            if norm in seen_norms:
                raise CBOR_Codec_Decoding_Error(
                    "Duplicate CBOR map key: %r" % (key,),
                    remaining=s)
            seen_norms.add(norm)
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
                    remainder, depth=_depth + 1)
                if not remainder:
                    raise CBOR_Codec_Decoding_Error(
                        "Map key without value", remaining=s)
                value, remainder = CBORcodec_Object.decode_cbor_item(
                    remainder, depth=_depth + 1)
                _add_pair(key, value)
        else:
            for _ in range(length):
                if not remainder:
                    raise CBOR_Codec_Decoding_Error(
                        "Not enough key-value pairs in map", remaining=s)
                key, remainder = CBORcodec_Object.decode_cbor_item(
                    remainder, depth=_depth + 1)
                if not remainder:
                    raise CBOR_Codec_Decoding_Error(
                        "Map key without value", remaining=s)
                value, remainder = CBORcodec_Object.decode_cbor_item(
                    remainder, depth=_depth + 1)
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
        if tag_num < 0 or tag_num > CBOR_UINT64_MAX:
            raise CBOR_Codec_Encoding_Error(
                "Semantic tag number out of uint64 range")
        return (
            CBOR_encode_head(int(CBOR_MajorTypes.TAG), tag_num)
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
        if major_type != int(CBOR_MajorTypes.TAG):
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 6 (tag), got %d" % major_type,
                remaining=s)

        if not remainder:
            raise CBOR_Codec_Decoding_Error(
                "Tag without following item", remaining=s)

        item, remainder = CBORcodec_Object.decode_cbor_item(
            remainder, depth=_depth + 1)
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
            return chb(
                (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
                | int(CBOR_SimpleValue.UNDEFINED)
            )
        elif isinstance(obj, CBOR_NULL):
            return chb(
                (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
                | int(CBOR_SimpleValue.NULL)
            )
        elif isinstance(obj, CBOR_TRUE):
            return chb(
                (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
                | int(CBOR_SimpleValue.TRUE)
            )
        elif isinstance(obj, CBOR_FALSE):
            return chb(
                (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
                | int(CBOR_SimpleValue.FALSE)
            )
        elif isinstance(obj, CBOR_Object):
            # For other CBOR objects, use their val attribute
            val = obj.val
        else:
            val = obj

        if val is False:
            return chb(
                (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
                | int(CBOR_SimpleValue.FALSE)
            )
        elif val is True:
            return chb(
                (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
                | int(CBOR_SimpleValue.TRUE)
            )
        elif val is None:
            return chb(
                (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
                | int(CBOR_SimpleValue.NULL)
            )
        elif isinstance(val, float):
            # Preferred serialization (RFC 8949): shortest float that
            # preserves the numeric value. Received non-preferred widths are
            # preserved via packet raw caches, not by this encoder.
            ai = _cbor_preferred_float_ai(val)
            if ai == int(CBOR_FloatAI.HALF):
                half = _cbor_float_to_half_bits(val)
                if half is not None:
                    return chb(
                        (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
                        | int(CBOR_FloatAI.HALF)
                    ) + struct.pack(">H", half)
                ai = int(CBOR_FloatAI.SINGLE)
            if ai == int(CBOR_FloatAI.SINGLE):
                try:
                    return chb(
                        (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
                        | int(CBOR_FloatAI.SINGLE)
                    ) + struct.pack(">f", val)
                except (OverflowError, struct.error):
                    pass
            return chb(
                (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
                | int(CBOR_FloatAI.DOUBLE)
            ) + struct.pack(">d", val)
        elif isinstance(val, int) and 0 <= val <= 23:
            # Simple value 0-23
            return CBOR_encode_head(int(CBOR_MajorTypes.SIMPLE_AND_FLOAT), val)
        elif isinstance(val, int) and 32 <= val <= 255:
            return chb(
                (int(CBOR_MajorTypes.SIMPLE_AND_FLOAT) << 5)
                | int(CBOR_AdditionalInfo.ONE_BYTE)
            ) + chb(val)
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

        if major_type != int(CBOR_MajorTypes.SIMPLE_AND_FLOAT):
            raise CBOR_Codec_Decoding_Error(
                "Expected major type 7 (simple/float), got %d" % major_type,
                remaining=s)

        # Check for special simple values (encoded directly in additional_info)
        if additional_info == int(CBOR_SimpleValue.FALSE):
            return CBOR_FALSE(), s[1:]
        elif additional_info == int(CBOR_SimpleValue.TRUE):
            return CBOR_TRUE(), s[1:]
        elif additional_info == int(CBOR_SimpleValue.NULL):
            return CBOR_NULL(), s[1:]
        elif additional_info == int(CBOR_SimpleValue.UNDEFINED):
            return CBOR_UNDEFINED(), s[1:]
        elif additional_info in (
            int(CBOR_FloatAI.HALF),
            int(CBOR_FloatAI.SINGLE),
            int(CBOR_FloatAI.DOUBLE),
        ):
            width = {
                int(CBOR_FloatAI.HALF): 2,
                int(CBOR_FloatAI.SINGLE): 4,
                int(CBOR_FloatAI.DOUBLE): 8,
            }[additional_info]
            if len(s) < 1 + width:
                raise CBOR_Codec_Decoding_Error(
                    "Not enough bytes for float", remaining=s)
            fmt = {2: ">H", 4: ">I", 8: ">Q"}[width]
            bits = struct.unpack(fmt, s[1:1 + width])[0]
            float_val = _cbor_float_from_bits(additional_info, bits)
            encoded = _cbor_buf_bytes(s[:1 + width])
            return CBOR_FLOAT(float_val, encoded=encoded), s[1 + width:]
        elif additional_info < 24:
            # Simple value 0-23
            return CBOR_SIMPLE_VALUE(additional_info), s[1:]
        else:
            # additional_info 24 means 1-byte simple value follows
            if additional_info == int(CBOR_AdditionalInfo.ONE_BYTE):
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
                    "Invalid additional info for major type 7: %d"
                    % additional_info,
                    remaining=s)
