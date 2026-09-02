# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""UPER compound-type encode/decode hooks (SEQUENCE, CHOICE, SEQUENCE OF, PACKET).

Context-first signatures so these functions can be bound on
``UPER_EncoderContext`` / ``UPER_DecoderContext``. Imports of
``scapy.asn1.uper`` stay lazy so BER/OER paths do not pull UPER in.
"""

from typing import Any

from scapy.asn1.asn1 import ASN1_Error, ASN1_Object
from scapy.asn1.compound import sequence_decode_children


# ---- SEQUENCE -------------------------------------------------------------

def uper_sequence_encode_to(enc, field, pkt):
    # type: (Any, Any, Any) -> None
    from scapy.asn1fields import ASN1F_optional

    bit_enc = enc.bit_encoder
    if field.constraints.extensible:
        bit_enc.append_bit(0)
    for opt in field.optionals:
        bit_enc.append_bit(1 if opt.is_present(pkt) else 0)
    for obj in field.seq:
        if isinstance(obj, ASN1F_optional) and not obj.is_present(pkt):
            continue
        obj.encode_to(pkt, enc)


def uper_sequence_decode_from(dec, field, pkt):
    # type: (Any, Any, Any) -> None
    from scapy.asn1.uper import UPER_Decoding_Error

    bit_dec = dec.bit_decoder
    if field.constraints.extensible:
        if bit_dec.read_bit():
            raise UPER_Decoding_Error(
                "ASN1F_SEQUENCE: extension additions are not supported"
            )
    presence = [bit_dec.read_bit() for _ in field.optionals]
    sequence_decode_children(
        field, pkt, presence,
        lambda obj: obj.decode_from(pkt, dec),
    )


# ---- SEQUENCE OF ----------------------------------------------------------

def uper_sequence_of_encode_to(enc, field, pkt, value=None):
    # type: (Any, Any, Any, Any) -> None
    from scapy.asn1.uper import UPER_constrained_int_enc

    bit_enc = enc.bit_encoder
    if value is None:
        value = getattr(pkt, field.name)
    if value is None:
        value = []
    count = len(value)

    def append_items(offset, size):
        # type: (int, int) -> None
        for i in range(offset, offset + size):
            item = value[i]
            if field.holds_packets:
                item.ASN1_root.encode_to(item, enc)
            else:
                field.fld.encode_into(bit_enc, pkt, item)

    uper_min, uper_max = field.constraints.minimum, field.constraints.maximum
    if field.constraints.extensible:
        if (
                uper_min is not None and uper_max is not None and
                uper_min <= count <= uper_max
        ):
            bit_enc.append_bit(0)
        else:
            bit_enc.append_bit(1)
            bit_enc.append_fragmented(count, append_items)
            return
    if uper_min is not None and uper_max is not None:
        UPER_constrained_int_enc(bit_enc, count, uper_min, uper_max)
        append_items(0, count)
    else:
        bit_enc.append_fragmented(count, append_items)


def uper_sequence_of_decode_from(dec, field, pkt):
    # type: (Any, Any, Any) -> None
    from scapy.asn1.uper import UPER_constrained_int_dec

    bit_dec = dec.bit_decoder
    lst = []

    def read_items(count):
        # type: (int) -> None
        for _ in range(count):
            if field.holds_packets:
                p = field.cls()
                p.add_underlayer(pkt)
                p.add_parent(pkt)
                p.ASN1_root.decode_from(p, dec)
                lst.append(p)
            else:
                lst.append(field.fld.m2i_from_decoder(pkt, bit_dec))

    if field.constraints.extensible and bit_dec.read_bit():
        bit_dec.read_fragmented(read_items)
    else:
        uper_min, uper_max = field.constraints.minimum, field.constraints.maximum
        if uper_min is not None and uper_max is not None:
            read_items(UPER_constrained_int_dec(bit_dec, uper_min, uper_max))
        else:
            bit_dec.read_fragmented(read_items)
    field.set_val(pkt, lst)


# ---- CHOICE -------------------------------------------------------------

def uper_choice_encode_to(enc, field, pkt, value=None):
    # type: (Any, Any, Any, Any) -> None
    from scapy.asn1.uper import UPER_choice_index_enc

    bit_enc = enc.bit_encoder
    if value is None:
        value = getattr(pkt, field.name)
    if value is None:
        return
    index = field.alternative_index(value)
    if index is None:
        raise ASN1_Error(
            "ASN1F_CHOICE: cannot encode unknown alternative in '%s'" %
            field.name
        )
    if field.constraints.extensible:
        bit_enc.append_bit(0)
    order = field.canonical_order
    tag = field.choice_order[index]
    canon_idx = field.canonical_index[tag]
    if len(order) > 1:
        UPER_choice_index_enc(bit_enc, canon_idx, len(order))
    choice = order[canon_idx]
    if isinstance(choice, type) and hasattr(choice, "ASN1_root"):
        value.ASN1_root.encode_to(value, enc)
    elif hasattr(choice, "cls"):
        uper_packet_encode_to(enc, choice, pkt, value)
    elif isinstance(choice, type):
        choice(field.name, b"").encode_into(bit_enc, pkt, value)
    else:
        choice.encode_into(bit_enc, pkt, value)


def uper_choice_decode_from(dec, field, pkt):
    # type: (Any, Any, Any) -> None
    from scapy.asn1.uper import UPER_Decoding_Error, UPER_choice_index_dec

    bit_dec = dec.bit_decoder
    if field.constraints.extensible:
        if bit_dec.read_bit():
            raise UPER_Decoding_Error(
                "ASN1F_CHOICE: extension additions are not supported"
            )
    order = field.canonical_order
    if len(order) > 1:
        index = UPER_choice_index_dec(bit_dec, len(order))
    else:
        index = 0
    if index >= len(order):
        raise ASN1_Error(
            "ASN1F_CHOICE: unexpected index %s in '%s'" %
            (index, field.name)
        )
    choice = order[index]
    if isinstance(choice, type) and hasattr(choice, "ASN1_root"):
        p = choice()
        p.add_underlayer(pkt)
        p.add_parent(pkt)
        p.ASN1_root.decode_from(p, dec)
        field.set_val(pkt, p)
        return
    if hasattr(choice, "cls"):
        field.set_val(pkt, uper_packet_decode_from_decoder(choice, pkt, dec))
        return
    if isinstance(choice, type):
        field.set_val(
            pkt, choice(field.name, b"").m2i_from_decoder(pkt, bit_dec),
        )
        return
    field.set_val(pkt, choice.m2i_from_decoder(pkt, bit_dec))


# ---- PACKET ---------------------------------------------------------------

def uper_packet_encode_to(enc, field, pkt, value=None):
    # type: (Any, Any, Any, Any) -> None
    if value is None:
        value = getattr(pkt, field.name)
    if value is None:
        return
    if isinstance(value, ASN1_Object):
        value = value.val
    value.ASN1_root.encode_to(value, enc)


def uper_packet_decode_from(dec, field, pkt):
    # type: (Any, Any, Any) -> None
    field.set_val(pkt, uper_packet_decode_from_decoder(field, pkt, dec))


def uper_packet_decode_from_decoder(field, pkt, dec):
    # type: (Any, Any, Any) -> Any
    cls = (field.next_cls_cb(pkt) or field.cls) if field.next_cls_cb else field.cls
    p = cls()
    p.add_underlayer(pkt)
    p.add_parent(pkt)
    p.ASN1_root.decode_from(p, dec)
    return p
