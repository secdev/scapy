# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""Codec-neutral ASN.1 schema constraints."""

import warnings
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class ASN1Constraints:
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    size_min: Optional[int] = None
    size_max: Optional[int] = None
    extensible: bool = False
    unsigned: bool = False


_LEGACY_CODEC_OPTS = {
    "uper_min": "minimum",
    "uper_max": "maximum",
    "uper_extensible": "extensible",
    "oer_extensible": "extensible",
    "oer_unsigned": "unsigned",
    "minimum": "minimum",
    "maximum": "maximum",
    "size_min": "size_min",
    "size_max": "size_max",
    "extensible": "extensible",
    "unsigned": "unsigned",
}


def normalize_constraints(codec_opts, size_len=None):
    # type: (Dict[str, Any], Optional[int]) -> ASN1Constraints
    """Build ASN1Constraints from field kwargs, with legacy alias support."""
    data = {
        "minimum": None,
        "maximum": None,
        "size_min": None,
        "size_max": None,
        "extensible": False,
        "unsigned": False,
    }  # type: Dict[str, Any]
    for key, value in codec_opts.items():
        if key in _LEGACY_CODEC_OPTS:
            if key.startswith(("uper_", "oer_")) and key not in (
                "uper_min", "uper_max", "uper_extensible",
                "oer_extensible", "oer_unsigned",
            ):
                warnings.warn(
                    "Unknown codec-prefixed constraint %r" % key,
                    DeprecationWarning,
                    stacklevel=4,
                )
                continue
            if key.startswith(("uper_", "oer_")):
                warnings.warn(
                    "codec-prefixed constraint %r is deprecated; use %r instead" %
                    (key, _LEGACY_CODEC_OPTS[key]),
                    DeprecationWarning,
                    stacklevel=4,
                )
            data[_LEGACY_CODEC_OPTS[key]] = value
        elif key in data:
            data[key] = value
        elif key.startswith(("uper_", "oer_")):
            warnings.warn(
                "Unknown codec-prefixed constraint %r" % key,
                DeprecationWarning,
                stacklevel=4,
            )
    return ASN1Constraints(**data)


def field_extensible(field):
    # type: (Any) -> bool
    return bool(field.constraints.extensible)


def field_range(field):
    # type: (Any) -> Tuple[Optional[int], Optional[int]]
    c = field.constraints
    minimum = c.minimum
    maximum = c.maximum
    if minimum is None and maximum is None:
        minimum = c.size_min
        maximum = c.size_max
    return minimum, maximum


def oer_size_len(field=None, size_len=None):
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


def uper_extensible(field=None, uper_extensible=None, oer_extensible=None):
    # type: (Any, Optional[bool], Optional[bool]) -> bool
    if uper_extensible is not None:
        return uper_extensible
    if oer_extensible:
        return True
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
