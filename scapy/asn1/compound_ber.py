# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""BER compound-type encode/decode hooks (SEQUENCE, CHOICE, SEQUENCE OF, PACKET).

Context-first signatures so these functions can be bound on
``BER_Encoder`` / ``BER_Decoder``. OER reuses the PACKET hooks via
inheritance.
"""

from typing import Any, Tuple

from scapy.asn1.asn1 import (
    ASN1_Class_UNIVERSAL,
    ASN1_Codecs,
    ASN1_Error,
    ASN1_Object,
)


# ---- SEQUENCE -------------------------------------------------------------

def ber_sequence_encode_to(enc, field, pkt):
    # type: (Any, Any, Any) -> None
    # Encode children into a nested context, then wrap as one SEQUENCE TLV.
    child_enc = type(enc)(codec=enc.codec)
    for obj in field.seq:
        obj.encode_to(pkt, child_enc)
    enc.write(field.i2m(pkt, child_enc.finish()))


def ber_sequence_decode_from(dec, field, pkt):
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


# ---- SEQUENCE OF ----------------------------------------------------------

def ber_sequence_of_encode_to(enc, field, pkt):
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


def ber_sequence_of_decode_from(dec, field, pkt):
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


# ---- CHOICE -------------------------------------------------------------

def ber_choice_encode_to(enc, field, pkt, value=None):
    # type: (Any, Any, Any, Any) -> None
    if value is None:
        value = getattr(pkt, field.name)
    enc.write(ber_choice_bytes(field, pkt, value))


def ber_choice_decode_from(dec, field, pkt):
    # type: (Any, Any, Any) -> None
    val, remain = ber_choice_decode(field, pkt, dec.remaining())
    field.set_val(pkt, val)
    dec.set_remainder(remain)


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


# ---- PACKET (nested ASN1_Packet; also used by OER) ------------------------

def ber_packet_encode_to(enc, field, pkt, value=None):
    # type: (Any, Any, Any, Any) -> None
    if value is None:
        value = getattr(pkt, field.name)
    enc.write(nested_packet_bytes(field, pkt, value))


def ber_packet_decode_from(dec, field, pkt):
    # type: (Any, Any, Any) -> None
    val, remain = nested_packet_decode(field, pkt, dec.remaining())
    field.set_val(pkt, val)
    dec.set_remainder(remain)


def nested_packet_decode(field, pkt, s):
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


def nested_packet_bytes(field, pkt, x):
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
