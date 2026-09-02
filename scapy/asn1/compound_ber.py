# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""BER compound-type encode/decode hooks (SEQUENCE, CHOICE, SEQUENCE OF, PACKET).

Context-first signatures so these functions can be bound on
``BER_Encoder`` / ``BER_Decoder``. OER reuses the PACKET hooks via
inheritance.
"""

from typing import Any

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
    s = dec.remaining()
    s = field._apply_tagging_dec(s, pkt)
    codec = field.ASN1_tag.get_codec(ASN1_Codecs.BER)
    _i, s, remain = codec.check_type_check_len(s)
    lst = []
    while s:
        c, s = field._extract_packet(s, pkt)
        if c:
            lst.append(c)
    field.set_val(pkt, lst)
    dec.set_remainder(remain)


# ---- CHOICE -------------------------------------------------------------

def ber_choice_encode_to(enc, field, pkt, value=None):
    # type: (Any, Any, Any, Any) -> None
    if value is None:
        value = getattr(pkt, field.name)
    if value is None:
        s = b""
    else:
        if isinstance(value, ASN1_Object):
            s = value.enc(pkt.ASN1_codec)
        else:
            s = bytes(value)
        if type(value) in field.pktchoices:
            imp, exp = field.pktchoices[type(value)]
            s = field._tagging_enc(pkt, s, implicit_tag=imp, explicit_tag=exp)
    _imp, exp = field._tagging_tags(pkt)
    enc.write(field._tagging_enc(pkt, s, explicit_tag=exp))


def ber_choice_decode_from(dec, field, pkt):
    # type: (Any, Any, Any) -> None
    from scapy.asn1.ber import BER_id_dec
    from scapy.asn1fields import ASN1F_field

    s = dec.remaining()
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
        val, remain = field.extract_packet(
            choice, s, _underlayer=pkt, _parent=pkt,
        )
    elif isinstance(choice, type):
        val, remain = choice(field.name, b"").m2i(pkt, s)
    else:
        val, remain = choice.m2i(pkt, s)
    field.set_val(pkt, val)
    dec.set_remainder(remain)


# ---- PACKET (nested ASN1_Packet; also used by OER) ------------------------

def ber_packet_encode_to(enc, field, pkt, value=None):
    # type: (Any, Any, Any, Any) -> None
    if value is None:
        value = getattr(pkt, field.name)
    if value is None:
        s = b""
    elif isinstance(value, bytes):
        s = value
    elif isinstance(value, ASN1_Object):
        s = bytes(value.val) if value.val else b""
    else:
        s = bytes(value)
        from scapy.asn1packet import ASN1_Packet as _ASN1_Packet
        if not isinstance(value, _ASN1_Packet):
            enc.write(s)
            return
    imp, exp = field._tagging_tags(pkt)
    enc.write(field._tagging_enc(pkt, s, implicit_tag=imp, explicit_tag=exp))


def ber_packet_decode_from(dec, field, pkt):
    # type: (Any, Any, Any) -> None
    cls = (field.next_cls_cb(pkt) or field.cls) if field.next_cls_cb else field.cls
    from scapy.asn1packet import ASN1_Packet as _ASN1_Packet
    s = dec.remaining()
    if not issubclass(cls, _ASN1_Packet):
        val, remain = field.extract_packet(
            cls, s, _underlayer=pkt, _parent=pkt,
        )
        field.set_val(pkt, val)
        dec.set_remainder(remain)
        return
    s = field._apply_tagging_dec(
        s, pkt,
        hidden_tag=cls.ASN1_root.ASN1_tag,
        _fname=field.name,
    )
    if not s:
        field.set_val(pkt, None)
        dec.set_remainder(s)
        return
    val, remain = field.extract_packet(cls, s, _underlayer=pkt, _parent=pkt)
    field.set_val(pkt, val)
    dec.set_remainder(remain)
