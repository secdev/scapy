# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""Codec-neutral ASN.1 schema constraints.

``minimum`` / ``maximum`` mean a value range for INTEGER and ENUMERATED
fields, and a SIZE constraint for string and BIT STRING fields.
``size_len`` is a fixed SIZE (octets or bits) used when both bounds coincide.
``extensible`` marks an extension marker on the constraint.
``unsigned`` selects unsigned INTEGER encoding where the codec supports it.
"""

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
    for key in codec_opts:
        if key not in _SUPPORTED_CONSTRAINTS:
            raise TypeError("Unknown field constraint %r" % key)
    return ASN1Constraints(**codec_opts)


def resolve_uper_int_bounds(field=None,  # type: Any
                            size_len=None,  # type: Optional[int]
                            minimum=None,  # type: Optional[int]
                            maximum=None,  # type: Optional[int]
                            unsigned=None,  # type: Optional[bool]
                            extensible=None  # type: Optional[bool]
                            ):
    # type: (...) -> Tuple[Optional[int], Optional[int], bool]
    """Resolve UPER INTEGER root range and extensibility from field/kwargs.

    When no explicit ``minimum``/``maximum`` is set, a fixed ``size_len`` of
    1, 2, 4, or 8 with ``unsigned=True`` implies ``0 .. 256**n - 1``.
    """
    if size_len is None and field is not None:
        size_len = field.size_len
    if minimum is None and maximum is None and field is not None:
        minimum, maximum = field.constraints.minimum, field.constraints.maximum
    if unsigned is None:
        unsigned = bool(field.constraints.unsigned) if field is not None else False
    if extensible is None:
        extensible = bool(field.constraints.extensible) if field is not None else False
    if minimum is None and maximum is None:
        if size_len in (1, 2, 4, 8) and unsigned:
            minimum, maximum = 0, (256 ** size_len) - 1
    return minimum, maximum, extensible


def resolve_uper_size_bounds(field=None,  # type: Any
                             size_len=None,  # type: Optional[int]
                             minimum=None,  # type: Optional[int]
                             maximum=None,  # type: Optional[int]
                             extensible=None  # type: Optional[bool]
                             ):
    # type: (...) -> Tuple[Optional[int], Optional[int], bool]
    """Resolve UPER SIZE bounds; ``size_len`` is a fixed SIZE."""
    if size_len is None and field is not None:
        size_len = field.size_len
    if minimum is None and maximum is None and field is not None:
        minimum, maximum = field.constraints.minimum, field.constraints.maximum
    if extensible is None:
        extensible = bool(field.constraints.extensible) if field is not None else False
    if size_len:
        return size_len, size_len, extensible
    return minimum, maximum, extensible


def resolve_oer_size_bounds(field=None, size_len=None):
    # type: (Any, Optional[int]) -> Tuple[Optional[int], Optional[int]]
    """Resolve OER SIZE bounds from ``size_len`` or field constraints."""
    if size_len is None and field is not None:
        size_len = field.size_len
    # ``size_len=0`` means unset (same as the historical ``if size_len:`` check).
    if size_len:
        return size_len, size_len
    if field is not None:
        return field.constraints.minimum, field.constraints.maximum
    return None, None


def uper_enum_values(field=None, values=None):
    # type: (Any, Optional[List[int]]) -> Optional[List[int]]
    if values is not None:
        return values
    if field is not None and hasattr(field, "uper_enum_values"):
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
    if size_len is None and field is not None:
        size_len = field.size_len
    if unsigned is None:
        unsigned = bool(field.constraints.unsigned) if field is not None else False
    if field is not None:
        minimum, maximum = field.constraints.minimum, field.constraints.maximum
        extensible = bool(field.constraints.extensible)
    else:
        minimum, maximum = None, None
        extensible = False

    # Extension values may lie outside the root range.
    val_min = None if extensible else minimum
    val_max = None if extensible else maximum

    if size_len is not None:
        if (not unsigned and minimum is not None and minimum >= 0 and
                not extensible):
            unsigned = True
        return size_len, unsigned, val_min, val_max

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
