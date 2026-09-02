# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""Shared ASN.1 compound-type encode/decode (SEQUENCE, CHOICE, SEQUENCE OF).

ASN.1 schema fields form a tree, not a flat ``fields_desc`` list. The
``encode_to`` / ``decode_from`` methods on ``ASN1F_*`` are the analogue of
Scapy ``Field.addfield`` / ``Field.getfield`` for that tree.
"""

from functools import reduce
from typing import Any, Callable, List, Tuple

from scapy.asn1.asn1 import (
    ASN1_Class_UNIVERSAL,
    ASN1_Codecs,
    ASN1_Error,
    ASN1_Object,
)
from scapy.asn1.constraints import field_extensible, field_range
from scapy.asn1.context import (
    OER_Decoder,
    per_bit_decoder,
    per_bit_encoder,
)


def sequence_presence_bits(field, pkt):
    # type: (Any, Any) -> List[int]
    bits = [0] if field_extensible(field) else []
    bits += [1 if opt.is_present(pkt) else 0 for opt in field.optionals]
    return bits


def read_oer_presence_bits(s, field):
    # type: (bytes, Any) -> Tuple[List[bool], bytes]
    from scapy.asn1.oer import OER_Decoding_Error, _OER_check_len

    number_of_optionals = len(field.optionals)
    number_of_bits = (1 if field_extensible(field) else 0) + number_of_optionals
    if number_of_bits == 0:
        return [], s
    number_of_bytes = (number_of_bits + 7) // 8
    _OER_check_len("ASN1F_SEQUENCE", s, number_of_bytes)
    value = int.from_bytes(s[:number_of_bytes], "big")
    bits = [
        bool((value >> (8 * number_of_bytes - 1 - i)) & 1)
        for i in range(number_of_bits)
    ]
    if field_extensible(field):
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


def read_uper_presence_bits(dec, field):
    # type: (Any, Any) -> List[bool]
    from scapy.asn1.uper import UPER_Decoding_Error

    if field_extensible(field):
        if dec.read_bit():
            raise UPER_Decoding_Error(
                "ASN1F_SEQUENCE: extension additions are not supported"
            )
    return [dec.read_bit() for _ in field.optionals]


def write_uper_presence_bits(enc, field, pkt):
    # type: (Any, Any, Any) -> None
    if field_extensible(field):
        enc.append_bit(0)
    for opt in field.optionals:
        enc.append_bit(1 if opt.is_present(pkt) else 0)


def _sequence_decode_children(field, pkt, presence, dissect):
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


def _sequence_encode_children(field, pkt, encode):
    # type: (Any, Any, Callable[[Any], None]) -> None
    from scapy.asn1fields import ASN1F_optional

    for obj in field.seq:
        if isinstance(obj, ASN1F_optional) and not obj.is_present(pkt):
            continue
        encode(obj)


# ---- SEQUENCE -------------------------------------------------------------

def sequence_encode_to(field, pkt, enc):
    # type: (Any, Any, Any) -> None
    enc.encode_sequence(field, pkt)


def sequence_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    dec.decode_sequence(field, pkt)


def ber_sequence_encode_to(field, pkt, enc):
    # type: (Any, Any, Any) -> None
    s = reduce(lambda x, y: x + y.build(pkt), field.seq, b"")
    enc.write(field.i2m(pkt, s))


def ber_sequence_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    s = dec.remaining()
    s = field._apply_tagging_dec(s, pkt, _fname=pkt.name)
    from scapy.asn1.ber import BER_Decoding_Error
    codec = field.ASN1_tag.get_codec(ASN1_Codecs.BER)
    _i, s, remain = codec.check_type_check_len(s)
    s = field._dissect_sequence_children(pkt, s)
    if len(s) > 0:
        raise BER_Decoding_Error(
            "unexpected remainder in %s" % pkt.name,
            remaining=s,
        )
    dec.set_remainder(remain)


def oer_sequence_encode_to(field, pkt, enc):
    # type: (Any, Any, Any) -> None
    enc.write(write_oer_presence_bits(sequence_presence_bits(field, pkt)))
    _sequence_encode_children(
        field, pkt,
        lambda obj: obj.encode_to(pkt, enc),
    )


def oer_sequence_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    s = dec.remaining()
    s = field._apply_tagging_dec(s, pkt, _fname=pkt.name)
    presence, s = read_oer_presence_bits(s, field)
    child_dec = OER_Decoder(s)
    _sequence_decode_children(
        field, pkt, presence,
        lambda obj: obj.decode_from(pkt, child_dec),
    )
    dec.set_remainder(child_dec.remaining())


def uper_sequence_encode_to(field, pkt, enc):
    # type: (Any, Any, Any) -> None
    bit_enc = per_bit_encoder(enc)
    write_uper_presence_bits(bit_enc, field, pkt)
    _sequence_encode_children(
        field, pkt,
        lambda obj: obj.encode_to(pkt, enc),
    )


def uper_sequence_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    bit_dec = per_bit_decoder(dec)
    presence = read_uper_presence_bits(bit_dec, field)
    _sequence_decode_children(
        field, pkt, presence,
        lambda obj: obj.decode_from(pkt, dec),
    )


# ---- SEQUENCE OF ----------------------------------------------------------

def sequence_of_encode_to(field, pkt, enc):
    # type: (Any, Any, Any) -> None
    enc.encode_sequence_of(field, pkt)


def sequence_of_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    dec.decode_sequence_of(field, pkt)


def ber_sequence_of_encode_to(field, pkt, enc):
    # type: (Any, Any, Any) -> None
    val = getattr(pkt, field.name)
    if isinstance(val, ASN1_Object) and val.tag == ASN1_Class_UNIVERSAL.RAW:
        s = val  # type: Any
    elif val is None:
        s = b""
    elif field.holds_packets:
        s = b"".join(bytes(i) for i in val)
    else:
        s = b"".join(field.fld.i2m(pkt, i) for i in val)
    enc.write(field.i2m(pkt, s))


def ber_sequence_of_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    from scapy.asn1.ber import BER_Decoding_Error
    s = dec.remaining()
    s = field._apply_tagging_dec(s, pkt)
    codec = field.ASN1_tag.get_codec(ASN1_Codecs.BER)
    _i, s, remain = codec.check_type_check_len(s)
    lst = []
    while s:
        c, s = field._extract_packet(s, pkt)
        if c:
            lst.append(c)
    if len(s) > 0:
        raise BER_Decoding_Error(
            "unexpected remainder in %s" % pkt.name,
            remaining=s,
        )
    field.set_val(pkt, lst)
    dec.set_remainder(remain)


def oer_sequence_of_encode_to(field, pkt, enc):
    # type: (Any, Any, Any) -> None
    enc.write(oer_sequence_of_bytes(field, pkt))


def oer_sequence_of_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    val, remain = oer_sequence_of_decode(field, pkt, dec.remaining())
    field.set_val(pkt, val)
    dec.set_remainder(remain)


def uper_sequence_of_encode_to(field, pkt, enc):
    # type: (Any, Any, Any) -> None
    uper_sequence_of_encode_into(field, enc, pkt)


def uper_sequence_of_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    field.set_val(
        pkt,
        uper_sequence_of_decode_from_decoder(field, pkt, dec),
    )


def oer_sequence_of_bytes(field, pkt):
    # type: (Any, Any) -> bytes
    from scapy.asn1.oer import OER_unsigned_integer_enc

    val = getattr(pkt, field.name)
    if isinstance(val, ASN1_Object) and val.tag == ASN1_Class_UNIVERSAL.RAW:
        return field.i2m(pkt, val)
    items = [
        bytes(item) if field.holds_packets else field.fld.i2m(pkt, item)
        for item in val or []
    ]
    return field.i2m(
        pkt, OER_unsigned_integer_enc(len(items)) + b"".join(items),
    )


def oer_sequence_of_decode(field, pkt, s):
    # type: (Any, Any, bytes) -> Tuple[list, bytes]
    from scapy.asn1.oer import OER_unsigned_integer_dec

    s = field._apply_tagging_dec(s, pkt)
    count, s = OER_unsigned_integer_dec(s)
    lst = []
    for _ in range(count):
        c, s = field._extract_packet(s, pkt)
        if c:
            lst.append(c)
    return lst, s


def uper_sequence_of_encode_into(field, enc, pkt, value=None):
    # type: (Any, Any, Any, Any) -> None
    bit_enc = per_bit_encoder(enc)
    if bit_enc is None:
        raise ASN1_Error("uper_sequence_of_encode_into: PER encoder required")
    if value is None:
        value = getattr(pkt, field.name)
    if value is None:
        _uper_count_enc(field, bit_enc, 0, lambda offset, size: None)
        return
    count = len(value)

    def append_items(offset, size):
        # type: (int, int) -> None
        for item in value[offset:offset + size]:
            if field.holds_packets:
                item.ASN1_root.encode_to(item, enc)
            else:
                field.fld.encode_into(bit_enc, pkt, item)

    uper_min, uper_max = field_range(field)
    if field_extensible(field):
        if (
                uper_min is not None and uper_max is not None and
                uper_min <= count <= uper_max
        ):
            bit_enc.append_bit(0)
        else:
            bit_enc.append_bit(1)
            bit_enc.append_fragmented(count, append_items)
            return
    _uper_count_enc(field, bit_enc, count, append_items)


def uper_sequence_of_decode_from_decoder(field, pkt, dec):
    # type: (Any, Any, Any) -> list
    from scapy.asn1.uper import UPER_constrained_int_dec

    bit_dec = per_bit_decoder(dec)
    if bit_dec is None:
        raise ASN1_Error(
            "uper_sequence_of_decode_from_decoder: PER decoder required"
        )
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

    if field_extensible(field) and bit_dec.read_bit():
        bit_dec.read_fragmented(read_items)
    else:
        uper_min, uper_max = field_range(field)
        if uper_min is not None and uper_max is not None:
            read_items(UPER_constrained_int_dec(bit_dec, uper_min, uper_max))
        else:
            bit_dec.read_fragmented(read_items)
    return lst


def _uper_count_enc(field, enc, count, append_items):
    # type: (Any, Any, int, Callable[[int, int], None]) -> None
    from scapy.asn1.uper import UPER_constrained_int_enc

    uper_min, uper_max = field_range(field)
    if uper_min is not None and uper_max is not None:
        UPER_constrained_int_enc(enc, count, uper_min, uper_max)
        append_items(0, count)
    else:
        enc.append_fragmented(count, append_items)


# ---- CHOICE -------------------------------------------------------------

def choice_encode_to(field, pkt, enc, value=None):
    # type: (Any, Any, Any, Any) -> None
    enc.encode_choice(field, pkt, value)


def choice_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    dec.decode_choice(field, pkt)


def ber_choice_encode_to(field, pkt, enc, value=None):
    # type: (Any, Any, Any, Any) -> None
    if value is None:
        value = getattr(pkt, field.name)
    enc.write(ber_choice_bytes(field, pkt, value))


def ber_choice_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    val, remain = ber_choice_decode(field, pkt, dec.remaining())
    field.set_val(pkt, val)
    dec.set_remainder(remain)


def oer_choice_encode_to(field, pkt, enc, value=None):
    # type: (Any, Any, Any, Any) -> None
    if value is None:
        value = getattr(pkt, field.name)
    enc.write(oer_choice_bytes(field, pkt, value))


def oer_choice_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    val, remain = oer_choice_decode(field, pkt, dec.remaining())
    field.set_val(pkt, val)
    dec.set_remainder(remain)


def uper_choice_encode_to(field, pkt, enc, value=None):
    # type: (Any, Any, Any, Any) -> None
    uper_choice_encode_into(field, enc, pkt, value)


def uper_choice_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    field.set_val(pkt, uper_choice_decode_from_decoder(field, pkt, dec))


def ber_choice_decode(field, pkt, s):
    # type: (Any, Any, bytes) -> Tuple[Any, bytes]
    from scapy.asn1.ber import BER_id_dec
    from scapy.asn1fields import ASN1F_field

    if len(s) == 0:
        raise ASN1_Error("ASN1F_CHOICE: got empty string")
    s = field._apply_tagging_dec(s, pkt)
    tag, _ = BER_id_dec(s)
    if tag in field.choices:
        choice = field.choices[tag]
    elif field.flexible_tag:
        choice = ASN1F_field
    else:
        raise ASN1_Error(
            "ASN1F_CHOICE: unexpected field in '%s' "
            "(tag %s not in possible tags %s)" % (
                field.name, tag, list(field.choices.keys())
            )
        )
    if hasattr(choice, "ASN1_root"):
        return field.extract_packet(choice, s, _underlayer=pkt, _parent=pkt)
    if isinstance(choice, type):
        return choice(field.name, b"").m2i(pkt, s)
    return choice.m2i(pkt, s)


def ber_choice_bytes(field, pkt, x):
    # type: (Any, Any, Any) -> bytes
    if x is None:
        s = b""
    else:
        if isinstance(x, ASN1_Object):
            s = x.enc(pkt.ASN1_codec)
        else:
            s = bytes(x)
        if type(x) in field.pktchoices:
            imp, exp = field.pktchoices[type(x)]
            s = field._tagging_enc(pkt, s, implicit_tag=imp, explicit_tag=exp)
    _imp, exp = field._tagging_tags(pkt)
    return field._tagging_enc(pkt, s, explicit_tag=exp)


def oer_choice_bytes(field, pkt, x):
    # type: (Any, Any, Any) -> bytes
    from scapy.asn1.oer import OER_tag_enc, OER_tag_parts

    if x is None:
        s = b""
    else:
        if isinstance(x, ASN1_Object):
            s = x.enc(pkt.ASN1_codec)
        else:
            s = bytes(x)
        index = field.alternative_index(x)
        if index is not None:
            tag_class, tag_number = OER_tag_parts(field.choice_order[index])
            s = OER_tag_enc(tag_number, tag_class) + s
    return field._tagging_enc(pkt, s, explicit_tag=field.explicit_tag)


def oer_choice_decode(field, pkt, s):
    # type: (Any, Any, bytes) -> Tuple[Any, bytes]
    from scapy.asn1fields import ASN1F_field
    from scapy.asn1.oer import OER_tag_dec, OER_tag_parts

    s = field._apply_tagging_dec(s, pkt)
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
        return field.extract_packet(choice, payload, _underlayer=pkt, _parent=pkt)
    if isinstance(choice, type):
        return choice(field.name, b"").m2i(pkt, payload)
    cls = (choice.next_cls_cb(pkt) or choice.cls) if choice.next_cls_cb else choice.cls
    return field.extract_packet(cls, payload, _underlayer=pkt, _parent=pkt)


def uper_choice_encode_into(field, enc, pkt, value=None):
    # type: (Any, Any, Any, Any) -> None
    from scapy.asn1.uper import UPER_choice_index_enc

    bit_enc = per_bit_encoder(enc)
    if bit_enc is None:
        raise ASN1_Error("uper_choice_encode_into: PER encoder required")
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
    if field_extensible(field):
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
        uper_packet_encode_into(choice, enc, pkt, value)
    elif isinstance(choice, type):
        choice(field.name, b"").encode_into(bit_enc, pkt, value)
    else:
        choice.encode_into(bit_enc, pkt, value)


def uper_choice_decode_from_decoder(field, pkt, dec):
    # type: (Any, Any, Any) -> Any
    from scapy.asn1.uper import UPER_Decoding_Error, UPER_choice_index_dec

    bit_dec = per_bit_decoder(dec)
    if bit_dec is None:
        raise ASN1_Error(
            "uper_choice_decode_from_decoder: PER decoder required"
        )
    if field_extensible(field):
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
        return p
    if hasattr(choice, "cls"):
        return uper_packet_decode_from_decoder(choice, pkt, dec)
    if isinstance(choice, type):
        return choice(field.name, b"").m2i_from_decoder(pkt, bit_dec)
    return choice.m2i_from_decoder(pkt, bit_dec)


# ---- PACKET (nested ASN1_Packet) ------------------------------------------

def packet_encode_to(field, pkt, enc, value=None):
    # type: (Any, Any, Any, Any) -> None
    enc.encode_packet(field, pkt, value)


def packet_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    dec.decode_packet(field, pkt)


def ber_packet_encode_to(field, pkt, enc, value=None):
    # type: (Any, Any, Any, Any) -> None
    if value is None:
        value = getattr(pkt, field.name)
    enc.write(ber_oer_packet_bytes(field, pkt, value))


def ber_packet_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    val, remain = ber_oer_packet_decode(field, pkt, dec.remaining())
    field.set_val(pkt, val)
    dec.set_remainder(remain)


def oer_packet_encode_to(field, pkt, enc, value=None):
    # type: (Any, Any, Any, Any) -> None
    ber_packet_encode_to(field, pkt, enc, value)


def oer_packet_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    ber_packet_decode_from(field, pkt, dec)


def uper_packet_encode_to(field, pkt, enc, value=None):
    # type: (Any, Any, Any, Any) -> None
    uper_packet_encode_into(field, enc, pkt, value)


def uper_packet_decode_from(field, pkt, dec):
    # type: (Any, Any, Any) -> None
    field.set_val(pkt, uper_packet_decode_from_decoder(field, pkt, dec))


def ber_oer_packet_decode(field, pkt, s):
    # type: (Any, Any, bytes) -> Tuple[Any, bytes]
    cls = (field.next_cls_cb(pkt) or field.cls) if field.next_cls_cb else field.cls
    from scapy.asn1packet import ASN1_Packet as _ASN1_Packet
    if not issubclass(cls, _ASN1_Packet):
        return field.extract_packet(cls, s, _underlayer=pkt, _parent=pkt)
    s = field._apply_tagging_dec(
        s, pkt,
        hidden_tag=cls.ASN1_root.ASN1_tag,
        _fname=field.name,
    )
    if not s:
        return None, s
    return field.extract_packet(cls, s, _underlayer=pkt, _parent=pkt)


def ber_oer_packet_bytes(field, pkt, x):
    # type: (Any, Any, Any) -> bytes
    if x is None:
        s = b""
    elif isinstance(x, bytes):
        s = x
    elif isinstance(x, ASN1_Object):
        s = bytes(x.val) if x.val else b""
    else:
        s = bytes(x)
        from scapy.asn1packet import ASN1_Packet as _ASN1_Packet
        if not isinstance(x, _ASN1_Packet):
            return s
    imp, exp = field._tagging_tags(pkt)
    return field._tagging_enc(pkt, s, implicit_tag=imp, explicit_tag=exp)


def uper_packet_encode_into(field, enc, pkt, value=None):
    # type: (Any, Any, Any, Any) -> None
    if value is None:
        value = getattr(pkt, field.name)
    if value is None:
        return
    if isinstance(value, ASN1_Object):
        value = value.val
    value.ASN1_root.encode_to(value, enc)


def uper_packet_decode_from_decoder(field, pkt, dec):
    # type: (Any, Any, Any) -> Any
    cls = (field.next_cls_cb(pkt) or field.cls) if field.next_cls_cb else field.cls
    p = cls()
    p.add_underlayer(pkt)
    p.add_parent(pkt)
    p.ASN1_root.decode_from(p, dec)
    return p
