# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
"""Test helpers for CBOR deterministic-encoding checks."""

import struct
from typing import List, Tuple, Union

from scapy.cbor.cbor import (
    CBOR_AdditionalInfo,
    CBOR_FloatAI,
    CBOR_MajorTypes,
)
from scapy.cbor.cborcodec import (
    CBOR_BREAK_BYTE,
    CBOR_Codec_Decoding_Error,
    CBOR_INDEFINITE,
    CBOR_decode_head,
    MAX_CBOR_NESTING,
    _cbor_float_from_bits,
    _cbor_nan_components,
    _cbor_nan_preferred_ai,
    _cbor_preferred_float_ai,
    cbor_is_break,
)


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

    def _argument_is_shortest(ai, value):
        # type: (int, Union[int, CBOR_INDEFINITE]) -> bool
        if value is CBOR_INDEFINITE:
            return ai == int(CBOR_AdditionalInfo.INDEFINITE)
        if ai < int(CBOR_AdditionalInfo.ONE_BYTE):
            return True
        if ai == int(CBOR_AdditionalInfo.ONE_BYTE):
            return int(value) >= int(CBOR_AdditionalInfo.ONE_BYTE)
        if ai == int(CBOR_AdditionalInfo.TWO_BYTES):
            return int(value) >= 256
        if ai == int(CBOR_AdditionalInfo.FOUR_BYTES):
            return int(value) >= 65536
        if ai == int(CBOR_AdditionalInfo.EIGHT_BYTES):
            return int(value) >= (1 << 32)
        return ai == int(CBOR_AdditionalInfo.INDEFINITE)

    def _walk(depth=0):
        # type: (int) -> None
        if depth > MAX_CBOR_NESTING:
            raise CBOR_Codec_Decoding_Error(
                "Maximum CBOR nesting depth exceeded",
                remaining=s[index[0]:])
        start = index[0]
        if start >= len(s):
            raise CBOR_Codec_Decoding_Error(
                "Empty CBOR data", remaining=s[start:])
        initial = s[start]
        if initial == CBOR_BREAK_BYTE:
            issues.append((
                base_offset + start,
                "Standalone break byte (0xff)",
            ))
            index[0] = start + 1
            return
        major = initial >> 5
        ai = initial & 0x1f
        pos = start + 1
        if ai < int(CBOR_AdditionalInfo.ONE_BYTE):
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
        elif ai in (
            int(CBOR_AdditionalInfo.RESERVED_28),
            int(CBOR_AdditionalInfo.RESERVED_29),
            int(CBOR_AdditionalInfo.RESERVED_30),
        ):
            raise CBOR_Codec_Decoding_Error(
                "Reserved additional info: %d" % ai, remaining=s[start:])
        else:
            raise CBOR_Codec_Decoding_Error(
                "Invalid additional info: %d" % ai, remaining=s[start:])
        index[0] = pos

        # Major type 7: simple values and floats. Check float preferred width.
        if major == int(CBOR_MajorTypes.SIMPLE_AND_FLOAT):
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
            if major in (
                int(CBOR_MajorTypes.BYTE_STRING),
                int(CBOR_MajorTypes.TEXT_STRING),
            ):
                while index[0] < len(s) and not cbor_is_break(s[index[0]:]):
                    chunk_start = index[0]
                    chunk_major, chunk_len, rem = CBOR_decode_head(s[chunk_start:])
                    consumed = len(s) - chunk_start - len(rem)
                    if chunk_major != major:
                        raise CBOR_Codec_Decoding_Error(
                            "Indefinite string chunk must be major type %d, "
                            "got %d" % (major, chunk_major),
                            remaining=s[chunk_start:])
                    if chunk_len is CBOR_INDEFINITE:
                        raise CBOR_Codec_Decoding_Error(
                            "Nested indefinite string",
                            remaining=s[chunk_start:])
                    chunk_ai = s[chunk_start] & 0x1f
                    if not _argument_is_shortest(chunk_ai, chunk_len):
                        issues.append((
                            base_offset + chunk_start,
                            "Non-shortest CBOR argument encoding "
                            "(AI=%d, value=%r)" % (chunk_ai, chunk_len),
                        ))
                    if len(rem) < int(chunk_len):
                        raise CBOR_Codec_Decoding_Error(
                            "Truncated byte/text string chunk",
                            remaining=s[chunk_start:])
                    index[0] = chunk_start + consumed + int(chunk_len)
                if index[0] >= len(s) or not cbor_is_break(s[index[0]:]):
                    raise CBOR_Codec_Decoding_Error(
                        "Expected break byte (0xff)", remaining=s[index[0]:])
                index[0] += 1
                return
            if major == int(CBOR_MajorTypes.ARRAY):
                while index[0] < len(s) and not cbor_is_break(s[index[0]:]):
                    _walk(depth + 1)
                if index[0] >= len(s) or not cbor_is_break(s[index[0]:]):
                    raise CBOR_Codec_Decoding_Error(
                        "Expected break byte (0xff)", remaining=s[index[0]:])
                index[0] += 1
                return
            if major == int(CBOR_MajorTypes.MAP):
                key_encodings = []  # type: List[bytes]
                while index[0] < len(s) and not cbor_is_break(s[index[0]:]):
                    key_start = index[0]
                    _walk(depth + 1)
                    key_encodings.append(bytes(s[key_start:index[0]]))
                    _walk(depth + 1)
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

        if not _argument_is_shortest(ai, value):
            issues.append((
                base_offset + start,
                "Non-shortest CBOR argument encoding (AI=%d, value=%r)"
                % (ai, value),
            ))

        if major in (
            int(CBOR_MajorTypes.BYTE_STRING),
            int(CBOR_MajorTypes.TEXT_STRING),
        ):
            length = int(value)
            if index[0] + length > len(s):
                raise CBOR_Codec_Decoding_Error(
                    "Truncated byte/text string", remaining=s[start:])
            index[0] += length
            return
        if major == int(CBOR_MajorTypes.ARRAY):
            for _ in range(int(value)):
                _walk(depth + 1)
            return
        if major == int(CBOR_MajorTypes.MAP):
            key_encodings = []  # type: List[bytes]
            for _ in range(int(value)):
                key_start = index[0]
                _walk(depth + 1)
                key_encodings.append(bytes(s[key_start:index[0]]))
                _walk(depth + 1)
            if key_encodings != sorted(key_encodings):
                issues.append((
                    base_offset + start,
                    "CBOR map keys are not in bytewise lexicographic order",
                ))
            return
        if major == int(CBOR_MajorTypes.TAG):
            _walk(depth + 1)
            return

    try:
        _walk()
    except CBOR_Codec_Decoding_Error:
        # Malformed input is reported by normal decoding, not this checker.
        pass
    return issues

