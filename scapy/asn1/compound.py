# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""Shared helpers for ASN.1 compound-type encode/decode.

Codec-specific SEQUENCE / CHOICE / SEQUENCE OF / PACKET hooks live in
``compound_ber``, ``compound_oer``, and ``compound_uper``. Those modules
are bound as methods on the encoder/decoder contexts in
``scapy.asn1.context``.
"""

from typing import Any, Callable, List


def sequence_decode_children(field, pkt, presence, dissect):
    # type: (Any, Any, List[bool], Callable[[Any], None]) -> None
    from scapy.asn1fields import ASN1F_badsequence, ASN1F_optional

    opt_index = 0
    for obj in field.seq:
        if isinstance(obj, ASN1F_optional):
            if not presence[opt_index]:
                obj.set_missing(pkt)
                opt_index += 1
                continue
            opt_index += 1
        try:
            dissect(obj)
        except ASN1F_badsequence:
            break
