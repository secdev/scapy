# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
BER ASN1_Packet and ASN1F_field build tests.
"""

from scapy.asn1.asn1 import ASN1_Codecs, ASN1_INTEGER, ASN1_STRING
from scapy.asn1fields import (
    ASN1F_BOOLEAN,
    ASN1F_CHOICE,
    ASN1F_INTEGER,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
    ASN1F_STRING,
    ASN1F_optional,
)
from scapy.asn1packet import ASN1_Packet
from scapy.packet import raw


class BERTaggedInteger(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_INTEGER("n", 0, explicit_tag=0xA1)


class BERFixedFields(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("n", 0, size_len=1),
        ASN1F_STRING("s", "", size_len=3),
    )


class BEROptionalField(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_optional(ASN1F_INTEGER("extra", 0, explicit_tag=0xA0)),
    )


class BERSequenceOfIntegers(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF("values", [], ASN1F_INTEGER)


class BERChoiceField(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
    )


class BERRecord(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_BOOLEAN("flag", False),
        ASN1F_STRING("label", ""),
        ASN1F_optional(ASN1F_INTEGER("extra", 0, explicit_tag=0xA0)),
        ASN1F_SEQUENCE_OF("values", [], ASN1F_INTEGER),
    )


class BEROptionalSequence(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("hdr", 0),
        ASN1F_optional(ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", None),
            ASN1F_STRING("label", None),
            explicit_tag=0xA0,
        )),
    )


class BERSequenceOfTaggedIntegers(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF(
        "values", [], ASN1F_INTEGER("v", 0, explicit_tag=0xA0),
    )


class BERSizedInteger(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_INTEGER("n", 0, size_len=1)


def _roundtrip(cls, pkt):
    # type: (type, ASN1_Packet) -> ASN1_Packet
    return cls(raw(pkt))


def check_ber_field_explicit_tag():
    # type: () -> None
    pkt = BERTaggedInteger(n=5)
    assert raw(pkt) == b"\xa1\x03\x02\x01\x05"
    decoded = _roundtrip(BERTaggedInteger, pkt)
    assert decoded.n.val == 5


def check_ber_field_fixed_size():
    # type: () -> None
    pkt = BERFixedFields(n=200, s=b"ABC")
    assert raw(pkt) == bytes.fromhex("300d02810200c80483000003414243")
    decoded = _roundtrip(BERFixedFields, pkt)
    assert decoded.n.val == 200
    assert decoded.s.val == b"ABC"


def check_ber_field_optional():
    # type: () -> None
    present = BEROptionalField(id=1, extra=7)
    assert raw(present) == bytes.fromhex("3008020101a003020107")
    decoded = _roundtrip(BEROptionalField, present)
    assert decoded.id.val == 1
    assert decoded.extra.val == 7

    absent = BEROptionalField(id=1, extra=None)
    assert raw(absent) == bytes.fromhex("3003020101")
    decoded = _roundtrip(BEROptionalField, absent)
    assert decoded.id.val == 1
    assert decoded.extra is None


def check_ber_optional_sequence_is_empty():
    # type: () -> None
    """Optional ASN1F_SEQUENCE must use the wrapped field's is_empty().

    SEQUENCE stores children under their own names (not dummy_seq_name), so
    inspecting pkt.dummy_seq_name incorrectly reports present children as empty
    and makes the parent SEQUENCE look empty.
    """
    opt = BEROptionalSequence.ASN1_root.seq[1]

    present = BEROptionalSequence(hdr=1, id=42, label=b"abc")
    assert opt._field.is_empty(present) is False
    assert opt.is_empty(present) is False
    assert BEROptionalSequence.ASN1_root.is_empty(present) is False
    assert raw(present) == bytes.fromhex("300f020101a00a300802012a0403616263")

    absent = BEROptionalSequence(hdr=1, id=None, label=None)
    assert opt._field.is_empty(absent) is True
    assert opt.is_empty(absent) is True
    assert raw(absent) == bytes.fromhex("3003020101")


def check_ber_field_sequence_of():
    # type: () -> None
    pkt = BERSequenceOfIntegers(values=[1, 2, 3])
    assert raw(pkt) == b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03"
    decoded = _roundtrip(BERSequenceOfIntegers, pkt)
    assert [x.val for x in decoded.values] == [1, 2, 3]


def check_ber_sequence_of_tagged_elements():
    # type: () -> None
    """SEQUENCE OF must apply the element field's tagging on build."""
    pkt = BERSequenceOfTaggedIntegers(values=[1, 2])
    assert raw(pkt) == bytes.fromhex("300aa003020101a003020102")
    decoded = _roundtrip(BERSequenceOfTaggedIntegers, pkt)
    assert [x.val for x in decoded.values] == [1, 2]


def check_ber_asn1_object_codec_kwargs():
    # type: () -> None
    """ASN1_Object values must honor field codec kwargs such as size_len."""
    as_int = BERSizedInteger(n=5)
    as_obj = BERSizedInteger(n=ASN1_INTEGER(5))
    assert raw(as_int) == raw(as_obj) == b"\x02\x81\x01\x05"
    assert _roundtrip(BERSizedInteger, as_obj).n.val == 5


def check_ber_field_choice():
    # type: () -> None
    as_int = BERChoiceField(c=ASN1_INTEGER(99))
    assert raw(as_int) == b"\x02\x01c"
    decoded = _roundtrip(BERChoiceField, as_int)
    assert decoded.c.val == 99

    as_str = BERChoiceField(c=ASN1_STRING("x"))
    assert raw(as_str) == b"\x04\x01x"
    decoded = _roundtrip(BERChoiceField, as_str)
    assert decoded.c.val == b"x"


def check_ber_packet_record():
    # type: () -> None
    pkt = BERRecord(
        id=42, flag=True, label="hi", extra=7, values=[1, 2, 3],
    )
    expected = bytes.fromhex(
        "301a02012a01010104026869"
        "a003020107"
        "3009020101020102020103"
    )
    assert raw(pkt) == expected
    decoded = _roundtrip(BERRecord, pkt)
    assert decoded.id.val == 42
    assert decoded.flag.val == 1
    assert decoded.label.val == b"hi"
    assert decoded.extra.val == 7
    assert [x.val for x in decoded.values] == [1, 2, 3]

    empty = BERRecord(id=1, flag=False, label="", extra=None, values=[])
    assert raw(empty) == bytes.fromhex("300a02010101010004003000")
    decoded = _roundtrip(BERRecord, empty)
    assert decoded.id.val == 1
    assert decoded.flag.val == 0
    assert decoded.label.val == b""
    assert decoded.extra is None
    assert [x.val for x in decoded.values] == []
