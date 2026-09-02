# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""OER compound-type encode/decode hooks (SEQUENCE, CHOICE, SEQUENCE OF).

Context-first signatures so these functions can be bound on
``OER_Encoder`` / ``OER_Decoder``. PACKET encoding is inherited from BER.
"""

from typing import Any, List, Tuple

from scapy.asn1.asn1 import (
    ASN1_Class_UNIVERSAL,
    ASN1_Error,
    ASN1_Object,
)
from scapy.asn1.compound import sequence_decode_children


def read_oer_presence_bits(s, field):
    # type: (bytes, Any) -> Tuple[List[bool], bytes]
    from scapy.asn1.oer import OER_Decoding_Error, _OER_check_len

    number_of_optionals = len(field.optionals)
    number_of_bits = (
        (1 if field.constraints.extensible else 0) + number_of_optionals
    )
    if number_of_bits == 0:
        return [], s
    number_of_bytes = (number_of_bits + 7) // 8
    _OER_check_len("ASN1F_SEQUENCE", s, number_of_bytes)
    value = int.from_bytes(s[:number_of_bytes], "big")
    bits = [
        bool((value >> (8 * number_of_bytes - 1 - i)) & 1)
        for i in range(number_of_bits)
    ]
    if field.constraints.extensible:
        if bits[0]:
            raise OER_Decoding_Error(
                "ASN1F_SEQUENCE: extension additions are not supported",
                remaining=s,
            )
        bits = bits[1:]
    return bits, s[number_of_bytes:]


def write_oer_presence_bits(bits):
    # type: (List[int]) -> bytes
    if not bits:
        return b""
    number_of_bytes = (len(bits) + 7) // 8
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    value <<= 8 * number_of_bytes - len(bits)
    return value.to_bytes(number_of_bytes, "big")


# ---- SEQUENCE -------------------------------------------------------------

def oer_sequence_encode_to(enc, field, pkt):
    # type: (Any, Any, Any) -> None
    from scapy.asn1fields import ASN1F_optional

    bits = [0] if field.constraints.extensible else []
    bits += [1 if opt.is_present(pkt) else 0 for opt in field.optionals]
    enc.write(write_oer_presence_bits(bits))
    for obj in field.seq:
        if isinstance(obj, ASN1F_optional) and not obj.is_present(pkt):
            continue
        obj.encode_to(pkt, enc)


def oer_sequence_decode_from(dec, field, pkt):
    # type: (Any, Any, Any) -> None
    s = dec.remaining()
    s = field._apply_tagging_dec(s, pkt, _fname=pkt.name)
    presence, s = read_oer_presence_bits(s, field)
    child_dec = type(dec)(s)
    sequence_decode_children(
        field, pkt, presence,
        lambda obj: obj.decode_from(pkt, child_dec),
    )
    dec.set_remainder(child_dec.remaining())


# ---- SEQUENCE OF ----------------------------------------------------------

def oer_sequence_of_encode_to(enc, field, pkt):
    # type: (Any, Any, Any) -> None
    from scapy.asn1.oer import OER_unsigned_integer_enc

    val = getattr(pkt, field.name)
    if isinstance(val, ASN1_Object) and val.tag == ASN1_Class_UNIVERSAL.RAW:
        enc.write(field.i2m(pkt, val))
        return
    items = val or []
    enc.write(field.i2m(
        pkt,
        OER_unsigned_integer_enc(len(items)) + b"".join(
            bytes(item) if field.holds_packets else field.fld.i2m(pkt, item)
            for item in items
        ),
    ))


def oer_sequence_of_decode_from(dec, field, pkt):
    # type: (Any, Any, Any) -> None
    from scapy.asn1.oer import OER_unsigned_integer_dec

    s = field._apply_tagging_dec(dec.remaining(), pkt)
    count, s = OER_unsigned_integer_dec(s)
    lst = []
    for _ in range(count):
        c, s = field._extract_packet(s, pkt)
        if c:
            lst.append(c)
    field.set_val(pkt, lst)
    dec.set_remainder(s)


# ---- CHOICE -------------------------------------------------------------

def oer_choice_encode_to(enc, field, pkt, value=None):
    # type: (Any, Any, Any, Any) -> None
    from scapy.asn1.oer import OER_tag_enc, OER_tag_parts

    if value is None:
        value = getattr(pkt, field.name)
    if value is None:
        s = b""
    else:
        if isinstance(value, ASN1_Object):
            s = value.enc(pkt.ASN1_codec)
        else:
            s = bytes(value)
        index = field.alternative_index(value)
        if index is not None:
            tag_class, tag_number = OER_tag_parts(field.choice_order[index])
            s = OER_tag_enc(tag_number, tag_class) + s
    enc.write(field._tagging_enc(pkt, s, explicit_tag=field.explicit_tag))


def oer_choice_decode_from(dec, field, pkt):
    # type: (Any, Any, Any) -> None
    from scapy.asn1fields import ASN1F_field
    from scapy.asn1.oer import OER_tag_dec, OER_tag_parts

    s = field._apply_tagging_dec(dec.remaining(), pkt)
    tag_class, tag_number, payload = OER_tag_dec(s)
    choice = None
    for key, alternative in field.choices.items():
        if OER_tag_parts(key) == (tag_class, tag_number):
            choice = alternative
            break
    if choice is None:
        if not field.flexible_tag:
            raise ASN1_Error(
                "ASN1F_CHOICE: unexpected field in '%s' "
                "(tag %s not in possible tags %s)" % (
                    field.name, tag_class | tag_number,
                    list(field.choices.keys())
                )
            )
        choice = ASN1F_field
    if hasattr(choice, "ASN1_root"):
        val, remain = field.extract_packet(
            choice, payload, _underlayer=pkt, _parent=pkt,
        )
    elif isinstance(choice, type):
        val, remain = choice(field.name, b"").m2i(pkt, payload)
    else:
        cls = (
            (choice.next_cls_cb(pkt) or choice.cls)
            if choice.next_cls_cb else choice.cls
        )
        val, remain = field.extract_packet(
            cls, payload, _underlayer=pkt, _parent=pkt,
        )
    field.set_val(pkt, val)
    dec.set_remainder(remain)
