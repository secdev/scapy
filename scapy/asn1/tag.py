# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""Semantic ASN.1 tag decomposition for Scapy's legacy BER integer tags."""


from scapy.asn1.ber import BER_id_enc


def asn1_tag_parts(identifier):
    # type: (int) -> tuple
    """Return (tag_class, tag_number, constructed) for a Scapy tag integer."""
    wire = BER_id_enc(identifier)
    first = wire[0]
    tag_class = first & 0xc0
    constructed = bool(first & 0x20)
    if (first & 0x1f) != 0x1f:
        return tag_class, first & 0x1f, constructed
    tag_number = 0
    for c in wire[1:]:
        tag_number <<= 7
        tag_number |= c & 0x7f
        if not (c & 0x80):
            break
    return tag_class, tag_number, constructed
