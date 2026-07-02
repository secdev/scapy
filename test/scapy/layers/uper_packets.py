# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
UPER ASN1_Packet and ASN1F_field tests.
"""

from scapy.asn1.asn1 import ASN1_Codecs, ASN1_INTEGER, ASN1_STRING
from scapy.asn1fields import (
    ASN1F_BIT_STRING,
    ASN1F_BOOLEAN,
    ASN1F_CHOICE,
    ASN1F_ENUMERATED,
    ASN1F_INTEGER,
    ASN1F_NULL,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
    ASN1F_STRING,
    ASN1F_optional,
)
from scapy.asn1packet import ASN1_Packet
from scapy.packet import raw


class UPERFixedFields(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("n", 0, size_len=1, oer_unsigned=True),
        ASN1F_STRING("s", "", size_len=3),
    )


class UPERIntegerField(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_INTEGER("n", 0)


class UPERBooleanField(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_BOOLEAN("b", False)


class UPERStringField(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_STRING("s", "")


class UPERConstrainedInteger(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_INTEGER(
        "n", 0, size_len=1, oer_unsigned=True,
    )


class UPEROptionalField(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_BOOLEAN("flag", False),
        ASN1F_optional(ASN1F_INTEGER("extra", 0)),
    )


class UPERSequenceOfIntegers(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE_OF("values", [], ASN1F_INTEGER)


class UPERChoiceField(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_CHOICE(
        "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
    )


class UPERChoiceStringFirst(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_CHOICE(
        "c", ASN1_STRING(b""), ASN1F_STRING, ASN1F_INTEGER,
    )


class UPERRecord(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_BOOLEAN("flag", False),
        ASN1F_STRING("label", ""),
        ASN1F_optional(ASN1F_INTEGER("extra", 0)),
        ASN1F_SEQUENCE_OF("values", [], ASN1F_INTEGER),
    )


class UPEREnumeratedField(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_ENUMERATED(
        "state", 1, {1: "alpha", 200: "beta"},
    )


class UPERBitStringField(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_BIT_STRING(
        "bits", "0", uper_min=1, uper_max=20,
    )


class UPERMessagePrefix(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("msgId", 0),
        ASN1F_INTEGER("myflag", 0),
        ASN1F_STRING("szDescription", "", size_len=10),
        ASN1F_BOOLEAN("isReady", False),
    )


class UPERSequenceWithChoice(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_CHOICE("c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING),
    )


class UPERNullPacket(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_NULL("n", None)


class UPERVariableOctetString(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_STRING("data", "", uper_min=1, uper_max=20)


class UPERConstrainedRangeInt(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_INTEGER("n", 0, uper_min=0, uper_max=15)


class UPERSequenceWithEnumerated(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_ENUMERATED("state", 1, {1: "alpha", 200: "beta"}),
    )


class UPERSequenceOfStrings(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE_OF("items", [], ASN1F_STRING)


class UPERNestedSequence(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("x", 0),
            ASN1F_BOOLEAN("y", False),
        ),
    )


class UPERSequenceWithNull(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_NULL("n", None),
    )


class UPERFixedBitString(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_BIT_STRING("b", "0", uper_min=16, uper_max=16)


class UPERSequenceOfConstrainedInts(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE_OF(
        "values", [], ASN1F_INTEGER("item", 0, uper_min=0, uper_max=255),
    )


class UPERSignedInteger(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_INTEGER("n", 0, uper_min=-128, uper_max=127)


class UPERMultiOptional(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_optional(ASN1F_INTEGER("a", 0)),
        ASN1F_optional(ASN1F_STRING("b", "")),
    )


def _roundtrip(cls, pkt):
    # type: (type, ASN1_Packet) -> ASN1_Packet
    return cls(raw(pkt))


def check_uper_field_fixed_size():
    # type: () -> None
    pkt = UPERFixedFields(n=200, s=b"ABC")
    assert raw(pkt) == b"\xc8ABC"
    decoded = _roundtrip(UPERFixedFields, pkt)
    assert decoded.n.val == 200
    assert decoded.s.val == b"ABC"


def check_uper_field_integer():
    # type: () -> None
    pkt = UPERIntegerField(n=12345)
    assert raw(pkt) == bytes.fromhex("023039")
    decoded = _roundtrip(UPERIntegerField, pkt)
    assert decoded.n.val == 12345


def check_uper_field_boolean():
    # type: () -> None
    true_pkt = UPERBooleanField(b=True)
    assert raw(true_pkt) == b"\x80"
    decoded = _roundtrip(UPERBooleanField, true_pkt)
    assert decoded.b.val == 1

    false_pkt = UPERBooleanField(b=False)
    assert raw(false_pkt) == b"\x00"
    decoded = _roundtrip(UPERBooleanField, false_pkt)
    assert decoded.b.val == 0


def check_uper_field_string():
    # type: () -> None
    pkt = UPERStringField(s=b"hi")
    assert raw(pkt) == bytes.fromhex("026869")
    decoded = _roundtrip(UPERStringField, pkt)
    assert decoded.s.val == b"hi"


def check_uper_field_constrained_integer():
    # type: () -> None
    pkt = UPERConstrainedInteger(n=200)
    assert raw(pkt) == b"\xc8"
    decoded = _roundtrip(UPERConstrainedInteger, pkt)
    assert decoded.n.val == 200


def check_uper_field_optional():
    # type: () -> None
    present = UPEROptionalField(id=42, flag=True, extra=7)
    assert raw(present) == bytes.fromhex("80954041c0")
    decoded = _roundtrip(UPEROptionalField, present)
    assert decoded.id.val == 42
    assert decoded.flag.val == 1
    assert decoded.extra.val == 7

    absent = UPEROptionalField(id=42, flag=True, extra=None)
    assert raw(absent) == bytes.fromhex("009540")
    decoded = _roundtrip(UPEROptionalField, absent)
    assert decoded.id.val == 42
    assert decoded.flag.val == 1
    assert decoded.extra is None


def check_uper_field_sequence_of():
    # type: () -> None
    pkt = UPERSequenceOfIntegers(values=[1, 2, 3])
    assert raw(pkt) == bytes.fromhex("03010101020103")
    decoded = _roundtrip(UPERSequenceOfIntegers, pkt)
    assert [x.val for x in decoded.values] == [1, 2, 3]

    empty = UPERSequenceOfIntegers(values=[])
    assert raw(empty) == b"\x00"
    decoded = _roundtrip(UPERSequenceOfIntegers, empty)
    assert [x.val for x in decoded.values] == []


def check_uper_field_choice():
    # type: () -> None
    as_int = UPERChoiceField(c=ASN1_INTEGER(99))
    assert raw(as_int) == bytes.fromhex("00b180")
    decoded = _roundtrip(UPERChoiceField, as_int)
    assert decoded.c.val == 99

    as_str = UPERChoiceField(c=ASN1_STRING(b"AB"))
    assert raw(as_str) == bytes.fromhex("8120a100")
    decoded = _roundtrip(UPERChoiceField, as_str)
    assert decoded.c.val == b"AB"


def check_uper_field_choice_definition_order():
    # type: () -> None
    as_str = UPERChoiceStringFirst(c=ASN1_STRING(b"AB"))
    assert raw(as_str) == bytes.fromhex("0120a100")
    decoded = _roundtrip(UPERChoiceStringFirst, as_str)
    assert decoded.c.val == b"AB"

    as_int = UPERChoiceStringFirst(c=ASN1_INTEGER(99))
    assert raw(as_int) == bytes.fromhex("80b180")
    decoded = _roundtrip(UPERChoiceStringFirst, as_int)
    assert decoded.c.val == 99


def check_uper_packet_record():
    # type: () -> None
    full = UPERRecord(
        id=42,
        flag=True,
        label=b"hi",
        extra=7,
        values=[1, 2, 3],
    )
    assert raw(full) == bytes.fromhex("8095409a1a4041c0c04040408040c0")
    decoded = _roundtrip(UPERRecord, full)
    assert decoded.id.val == 42
    assert decoded.flag.val == 1
    assert decoded.label.val == b"hi"
    assert decoded.extra.val == 7
    assert [x.val for x in decoded.values] == [1, 2, 3]

    pkt = UPERRecord(
        id=42,
        flag=True,
        label=b"AB",
        extra=None,
        values=[1, 2],
    )
    body = bytes.fromhex("0095409050808040404080")
    assert raw(pkt) == body
    decoded = _roundtrip(UPERRecord, pkt)
    assert decoded.id.val == 42
    assert decoded.flag.val == 1
    assert decoded.label.val == b"AB"
    assert decoded.extra is None
    assert [x.val for x in decoded.values] == [1, 2]

    empty = UPERRecord(
        id=1,
        flag=False,
        label=b"",
        extra=None,
        values=[],
    )
    assert raw(empty) == bytes.fromhex("0080800000")
    decoded = _roundtrip(UPERRecord, empty)
    assert decoded.id.val == 1
    assert decoded.flag.val == 0
    assert decoded.label.val == b""
    assert decoded.extra is None
    assert [x.val for x in decoded.values] == []


def check_uper_field_enumerated():
    # type: () -> None
    alpha = UPEREnumeratedField(state=1)
    assert raw(alpha) == b"\x00"
    decoded = _roundtrip(UPEREnumeratedField, alpha)
    assert decoded.state.val == 1

    beta = UPEREnumeratedField(state=200)
    assert raw(beta) == b"\x80"
    decoded = _roundtrip(UPEREnumeratedField, beta)
    assert decoded.state.val == 200


def check_uper_field_bit_string():
    # type: () -> None
    from scapy.asn1.asn1 import ASN1_BIT_STRING

    pkt = UPERBitStringField(bits=ASN1_BIT_STRING("1010101111001101"))
    assert raw(pkt) == bytes.fromhex("7d5e68")
    decoded = _roundtrip(UPERBitStringField, pkt)
    assert decoded.bits.val == "1010101111001101"


def check_uper_message_prefix():
    # type: () -> None
    pkt = UPERMessagePrefix(
        msgId=1,
        myflag=2,
        szDescription=b"HelloWorld",
        isReady=True,
    )
    assert raw(pkt) == bytes.fromhex("0101010248656c6c6f576f726c6480")
    decoded = _roundtrip(UPERMessagePrefix, pkt)
    assert decoded.msgId.val == 1
    assert decoded.myflag.val == 2
    assert decoded.szDescription.val == b"HelloWorld"
    assert decoded.isReady.val == 1


def check_uper_sequence_with_choice():
    # type: () -> None
    pkt = UPERSequenceWithChoice(id=42, c=ASN1_INTEGER(99))
    body = raw(pkt)
    decoded = UPERSequenceWithChoice(body)
    assert decoded.id.val == 42
    assert decoded.c.val == 99

    as_str = UPERSequenceWithChoice(id=1, c=ASN1_STRING(b"AB"))
    decoded = UPERSequenceWithChoice(raw(as_str))
    assert decoded.id.val == 1
    assert decoded.c.val == b"AB"


def check_uper_null_packet():
    # type: () -> None
    pkt = UPERNullPacket()
    assert raw(pkt) == b""
    decoded = _roundtrip(UPERNullPacket, pkt)
    assert decoded.n is None


def check_uper_variable_octet_string():
    # type: () -> None
    pkt = UPERVariableOctetString(data=bytes.fromhex("afbc4583"))
    assert raw(pkt) == bytes.fromhex("1d7de22c18")
    decoded = _roundtrip(UPERVariableOctetString, pkt)
    assert decoded.data.val == bytes.fromhex("afbc4583")


def check_uper_constrained_range_integer():
    # type: () -> None
    pkt = UPERConstrainedRangeInt(n=10)
    assert raw(pkt) == b"\xa0"
    decoded = _roundtrip(UPERConstrainedRangeInt, pkt)
    assert decoded.n.val == 10


def check_uper_sequence_with_enumerated():
    # type: () -> None
    pkt = UPERSequenceWithEnumerated(id=1, state=200)
    assert raw(pkt) == bytes.fromhex("010180")
    decoded = _roundtrip(UPERSequenceWithEnumerated, pkt)
    assert decoded.id.val == 1
    assert decoded.state.val == 200

    alpha = UPERSequenceWithEnumerated(id=7, state=1)
    assert raw(alpha) == bytes.fromhex("010700")
    decoded = _roundtrip(UPERSequenceWithEnumerated, alpha)
    assert decoded.state.val == 1


def check_uper_sequence_of_strings():
    # type: () -> None
    pkt = UPERSequenceOfStrings(items=[b"A", b"BC"])
    assert raw(pkt) == bytes.fromhex("020141024243")
    decoded = _roundtrip(UPERSequenceOfStrings, pkt)
    assert [x.val for x in decoded.items] == [b"A", b"BC"]

    empty = UPERSequenceOfStrings(items=[])
    assert raw(empty) == b"\x00"
    decoded = _roundtrip(UPERSequenceOfStrings, empty)
    assert [x.val for x in decoded.items] == []


def check_uper_sequence_choice_hex():
    # type: () -> None
    """Cross-check against asn1tools composite encoding."""
    pkt = UPERSequenceWithChoice(id=1, c=ASN1_INTEGER(99))
    assert raw(pkt) == bytes.fromhex("010100b180")
    decoded = UPERSequenceWithChoice(raw(pkt))
    assert decoded.id.val == 1
    assert decoded.c.val == 99


def check_uper_nested_sequence():
    # type: () -> None
    pkt = UPERNestedSequence(id=5, x=3, y=True)
    assert raw(pkt) == bytes.fromhex("0105010380")
    decoded = _roundtrip(UPERNestedSequence, pkt)
    assert decoded.id.val == 5
    assert decoded.x.val == 3
    assert decoded.y.val == 1


def check_uper_sequence_with_null():
    # type: () -> None
    pkt = UPERSequenceWithNull(id=1)
    assert raw(pkt) == bytes.fromhex("0101")
    decoded = _roundtrip(UPERSequenceWithNull, pkt)
    assert decoded.id.val == 1
    assert getattr(decoded.n, "val", decoded.n) is None


def check_uper_fixed_bit_string():
    # type: () -> None
    from scapy.asn1.asn1 import ASN1_BIT_STRING

    pkt = UPERFixedBitString(b=ASN1_BIT_STRING("1010101111001101"))
    assert raw(pkt) == bytes.fromhex("abcd")
    decoded = _roundtrip(UPERFixedBitString, pkt)
    assert decoded.b.val == "1010101111001101"


def check_uper_sequence_of_constrained_ints():
    # type: () -> None
    pkt = UPERSequenceOfConstrainedInts(values=[1, 200, 0])
    assert raw(pkt) == bytes.fromhex("0301c800")
    decoded = _roundtrip(UPERSequenceOfConstrainedInts, pkt)
    assert [x.val for x in decoded.values] == [1, 200, 0]


def check_uper_signed_integer():
    # type: () -> None
    for value, expected in [
        (0, b"\x80"),
        (-1, b"\x7f"),
        (127, b"\xff"),
        (-128, b"\x00"),
    ]:
        pkt = UPERSignedInteger(n=value)
        assert raw(pkt) == expected
        decoded = _roundtrip(UPERSignedInteger, pkt)
        assert decoded.n.val == value


def check_uper_multi_optional():
    # type: () -> None
    both = UPERMultiOptional(id=1, a=2, b=b"hi")
    assert raw(both) == bytes.fromhex("c0404040809a1a40")
    decoded = _roundtrip(UPERMultiOptional, both)
    assert decoded.id.val == 1
    assert decoded.a.val == 2
    assert decoded.b.val == b"hi"

    none = UPERMultiOptional(id=1, a=None, b=None)
    assert raw(none) == bytes.fromhex("004040")
    decoded = _roundtrip(UPERMultiOptional, none)
    assert decoded.id.val == 1
    assert decoded.a is None
    assert decoded.b is None

    only_a = UPERMultiOptional(id=3, a=9, b=None)
    assert raw(only_a) == bytes.fromhex("8040c04240")
    decoded = _roundtrip(UPERMultiOptional, only_a)
    assert decoded.id.val == 3
    assert decoded.a.val == 9
    assert decoded.b is None
