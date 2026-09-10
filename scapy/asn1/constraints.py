# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""Codec-neutral ASN.1 schema constraints.

``minimum`` / ``maximum`` mean a value range for INTEGER and ENUMERATED
fields, and a SIZE constraint for string and BIT STRING fields. A coinciding
SIZE is expressed as equal bounds. The field argument ``size_len`` is a
compatibility alias for that coinciding SIZE on OER/PER; BER still uses it
as a length-determinant width.
``extensible`` marks an extension marker on the constraint.
``unsigned`` selects unsigned INTEGER encoding where the codec supports it.

Codec-specific bound resolution lives in ``scapy.asn1.oer`` and
``scapy.asn1.uper``.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ASN1Constraints:
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    extensible: bool = False
    unsigned: bool = False
