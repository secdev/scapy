# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""Codec-neutral ASN.1 schema constraints."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class ASN1Constraints:
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    extensible: bool = False
    unsigned: bool = False


_SUPPORTED_CONSTRAINTS = {
    "minimum",
    "maximum",
    "extensible",
    "unsigned",
}


def normalize_constraints(codec_opts):
    # type: (Dict[str, Any]) -> ASN1Constraints
    """Build ASN1Constraints from field kwargs."""
    data = {
        "minimum": None,
        "maximum": None,
        "extensible": False,
        "unsigned": False,
    }  # type: Dict[str, Any]
    for key, value in codec_opts.items():
        if key in _SUPPORTED_CONSTRAINTS:
            data[key] = value
        else:
            raise TypeError("Unknown field constraint %r" % key)
    return ASN1Constraints(**data)


def field_extensible(field):
    # type: (Any) -> bool
    return bool(field.constraints.extensible)


def field_range(field):
    # type: (Any) -> Tuple[Optional[int], Optional[int]]
    c = field.constraints
    return c.minimum, c.maximum


def field_size_len(field=None, size_len=None):
    # type: (Any, Optional[int]) -> Optional[int]
    if size_len is not None:
        return size_len
    if field is not None:
        return field.size_len
    return None


def oer_unsigned(field=None, oer_unsigned=None):
    # type: (Any, Optional[bool]) -> bool
    if oer_unsigned is not None:
        return oer_unsigned
    if field is not None:
        return field.constraints.unsigned
    return False


def uper_extensible(field=None, uper_extensible=None):
    # type: (Any, Optional[bool]) -> bool
    if uper_extensible is not None:
        return uper_extensible
    if field is not None:
        return field.constraints.extensible
    return False


def uper_int_range(field=None, uper_min=None, uper_max=None):
    # type: (Any, Optional[int], Optional[int]) -> Tuple[Optional[int], Optional[int]]
    if uper_min is not None or uper_max is not None:
        return uper_min, uper_max
    if field is not None:
        return field_range(field)
    return None, None


def uper_enum_values(field=None, pkt=None, uper_enum_values=None):
    # type: (Any, Any, Optional[List[int]]) -> Optional[List[int]]
    if uper_enum_values is not None:
        return uper_enum_values
    if field is not None and pkt is not None and hasattr(field, "uper_enum_values"):
        from scapy.asn1.asn1 import ASN1_Codecs
        if getattr(pkt, "ASN1_codec", None) is ASN1_Codecs.PER:
            return field.uper_enum_values()
    return None


def oer_int_wire_params(field=None, size_len=None, unsigned=None):
    # type: (Any, Optional[int], Optional[bool]) -> Tuple[Optional[int], bool, Optional[int], Optional[int]]  # noqa: E501
    """Derive OER INTEGER width and signedness from field constraints.

    Per X.696 sections 10.3-10.4, extensible integer constraints are encoded
    as unbounded. A nonnegative lower bound without a fitting fixed upper
    bound uses variable-width unsigned encoding. A fixed eight-octet width
    is used only when ``maximum <= 2**64 - 1``.
    """
    size_len = field_size_len(field, size_len)
    is_unsigned = oer_unsigned(field, unsigned)
    minimum, maximum = field_range(field) if field is not None else (None, None)
    extensible = field_extensible(field) if field is not None else False

    # Extension values may lie outside the root range.
    val_min = None if extensible else minimum
    val_max = None if extensible else maximum

    if size_len is not None:
        if (not is_unsigned and minimum is not None and minimum >= 0 and
                not extensible):
            is_unsigned = True
        return size_len, is_unsigned, val_min, val_max

    if extensible:
        return None, is_unsigned, None, None

    if minimum is not None and minimum >= 0:
        is_unsigned = True
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
        is_unsigned = False
        for sl, lo, hi in (
            (1, -128, 127),
            (2, -32768, 32767),
            (4, -2147483648, 2147483647),
            (8, -9223372036854775808, 9223372036854775807),
        ):
            if minimum >= lo and maximum <= hi:
                size_len = sl
                break

    return size_len, is_unsigned, val_min, val_max
