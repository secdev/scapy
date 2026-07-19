# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
OER ASN1_Packet and ASN1F_field tests.
"""
import scapy.contrib.oer  # noqa: F401  # register OER stem

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


class OERTaggedInteger(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.OER
    ASN1_root = ASN1F_INTEGER("n", 0, explicit_tag=0xA1)


class OERFixedFields(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.OER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("n", 0, size_len=1, oer_unsigned=True),
        ASN1F_STRING("s", "", size_len=3),
    )


class OEROptionalField(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.OER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_optional(ASN1F_INTEGER("extra", 0, explicit_tag=0xA0)),
    )


class OERSequenceOfIntegers(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.OER
    ASN1_root = ASN1F_SEQUENCE_OF("values", [], ASN1F_INTEGER)


class OERChoiceField(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.OER
    ASN1_root = ASN1F_CHOICE(
        "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
    )


class OERRecord(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.OER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_BOOLEAN("flag", False),
        ASN1F_STRING("label", ""),
        ASN1F_optional(ASN1F_INTEGER("extra", 0, explicit_tag=0xA0)),
        ASN1F_SEQUENCE_OF("values", [], ASN1F_INTEGER),
    )


class OERNestedSequence(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.OER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("x", 0),
            ASN1F_BOOLEAN("y", False),
        ),
    )


class OERNestedSequenceTrailing(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.OER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("x", 0),
            ASN1F_BOOLEAN("y", False),
        ),
        ASN1F_INTEGER("id", 0),
    )


class OERSequenceOfWithTrailing(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.OER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE_OF("values", [], ASN1F_INTEGER),
        ASN1F_INTEGER("id", 0),
    )


def _roundtrip(cls, pkt):
    # type: (type, ASN1_Packet) -> ASN1_Packet
    return cls(raw(pkt))


def check_oer_field_explicit_tag():
    # type: () -> None
    pkt = OERTaggedInteger(n=5)
    assert raw(pkt) == b"\xa1\x01\x05"
    decoded = _roundtrip(OERTaggedInteger, pkt)
    assert decoded.n.val == 5


def check_oer_field_fixed_size():
    # type: () -> None
    pkt = OERFixedFields(n=200, s=b"ABC")
    assert raw(pkt) == b"\xc8ABC"
    decoded = _roundtrip(OERFixedFields, pkt)
    assert decoded.n.val == 200
    assert decoded.s.val == b"ABC"


def check_oer_field_optional():
    # type: () -> None
    present = OEROptionalField(id=1, extra=7)
    assert raw(present) == b"\x01\x01\xa0\x01\x07"
    decoded = _roundtrip(OEROptionalField, present)
    assert decoded.id.val == 1
    assert decoded.extra.val == 7

    absent = OEROptionalField(id=1, extra=None)
    assert raw(absent) == b"\x01\x01"
    decoded = _roundtrip(OEROptionalField, absent)
    assert decoded.id.val == 1
    assert decoded.extra is None


def check_oer_field_sequence_of():
    # type: () -> None
    pkt = OERSequenceOfIntegers(values=[1, 2, 3])
    assert raw(pkt) == b"\x01\x03\x01\x01\x01\x02\x01\x03"
    decoded = _roundtrip(OERSequenceOfIntegers, pkt)
    assert [x.val for x in decoded.values] == [1, 2, 3]


def check_oer_field_choice():
    # type: () -> None
    as_int = OERChoiceField(c=ASN1_INTEGER(99))
    assert raw(as_int) == b"\x02\x01c"
    decoded = _roundtrip(OERChoiceField, as_int)
    assert decoded.c.val == 99

    as_str = OERChoiceField(c=ASN1_STRING("x"))
    assert raw(as_str) == b"\x04\x01x"
    decoded = _roundtrip(OERChoiceField, as_str)
    assert decoded.c.val == b"x"


def check_oer_packet_record():
    # type: () -> None
    pkt = OERRecord(
        id=42, flag=True, label="hi", extra=7, values=[1, 2, 3],
    )
    expected = (
        b"\x01*\xff\x02hi\xa0\x01\x07"
        b"\x01\x03\x01\x01\x01\x02\x01\x03"
    )
    assert raw(pkt) == expected
    decoded = _roundtrip(OERRecord, pkt)
    assert decoded.id.val == 42
    assert decoded.flag.val == 1
    assert decoded.label.val == b"hi"
    assert decoded.extra.val == 7
    assert [x.val for x in decoded.values] == [1, 2, 3]

    empty = OERRecord(id=1, flag=False, label="", extra=None, values=[])
    assert raw(empty) == b"\x01\x01\x00\x00\x01\x00"
    decoded = _roundtrip(OERRecord, empty)
    assert decoded.id.val == 1
    assert decoded.flag.val == 0
    assert decoded.label.val == b""
    assert decoded.extra is None
    assert [x.val for x in decoded.values] == []


def check_oer_nested_sequence():
    # type: () -> None
    pkt = OERNestedSequence(id=5, x=3, y=True)
    assert raw(pkt) == b"\x01\x05\x01\x03\xff"
    decoded = _roundtrip(OERNestedSequence, pkt)
    assert decoded.id.val == 5
    assert decoded.x.val == 3
    assert decoded.y.val == 1


def check_oer_nested_sequence_trailing():
    # type: () -> None
    pkt = OERNestedSequenceTrailing(x=3, y=True, id=5)
    assert raw(pkt) == b"\x01\x03\xff\x01\x05"
    decoded = _roundtrip(OERNestedSequenceTrailing, pkt)
    assert decoded.x.val == 3
    assert decoded.y.val == 1
    assert decoded.id.val == 5


def check_oer_sequence_of_with_trailing():
    # type: () -> None
    pkt = OERSequenceOfWithTrailing(values=[1, 2], id=7)
    assert raw(pkt) == b"\x01\x02\x01\x01\x01\x02\x01\x07"
    decoded = _roundtrip(OERSequenceOfWithTrailing, pkt)
    assert [x.val for x in decoded.values] == [1, 2]
    assert decoded.id.val == 7
