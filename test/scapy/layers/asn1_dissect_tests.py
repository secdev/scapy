# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
ASN.1 packet dissection tests from fixed byte vectors (BER, OER, PER).
"""
import scapy.contrib.oer  # noqa: F401  # register OER stem
import scapy.contrib.uper  # noqa: F401  # register UPER stem

from typing import Any, Type

from scapy.asn1.asn1 import ASN1_Codecs
from scapy.asn1fields import (
    ASN1F_DEFAULT,
    ASN1F_INTEGER,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
)
from scapy.asn1packet import ASN1_Packet

from test.scapy.layers.ber_packets import (
    BERChoiceField,
    BERFixedFields,
    BEROptionalField,
    BERRecord,
    BERSequenceOfIntegers,
    BERTaggedInteger,
)
from test.scapy.layers.oer_packets import (
    OERChoiceField,
    OERFixedFields,
    OEROptionalField,
    OERRecord,
    OERSequenceOfIntegers,
    OERTaggedInteger,
)
from test.scapy.layers.uper_packets import (
    UPERChoiceField,
    UPERFixedFields,
    UPEROptionalField,
    UPERRecord,
    UPERSequenceOfIntegers,
)


def _asn1_int(val):
    # type: (Any) -> int
    return val.val if hasattr(val, "val") else val


def _assert_record(decoded):
    # type: (ASN1_Packet) -> None
    assert decoded.id.val == 42
    assert decoded.flag.val == 1
    assert decoded.label.val == b"hi"
    assert decoded.extra.val == 7
    assert [x.val for x in decoded.values] == [1, 2, 3]


def _assert_record_empty(decoded):
    # type: (ASN1_Packet) -> None
    assert decoded.id.val == 1
    assert decoded.flag.val == 0
    assert decoded.label.val == b""
    assert decoded.extra is None
    assert [x.val for x in decoded.values] == []


def _dissect(cls, data_hex):
    # type: (Type[ASN1_Packet], str) -> ASN1_Packet
    return cls(bytes.fromhex(data_hex))


def check_ber_field_dissect():
    # type: () -> None
    tagged = _dissect(BERTaggedInteger, "a103020105")
    assert tagged.n.val == 5

    fixed = _dissect(BERFixedFields, "300d02810200c80483000003414243")
    assert fixed.n.val == 200
    assert fixed.s.val == b"ABC"

    present = _dissect(BEROptionalField, "3008020101a003020107")
    assert present.id.val == 1
    assert present.extra.val == 7

    absent = _dissect(BEROptionalField, "3003020101")
    assert absent.id.val == 1
    assert absent.extra is None

    seqof = _dissect(BERSequenceOfIntegers, "3009020101020102020103")
    assert [x.val for x in seqof.values] == [1, 2, 3]

    as_int = _dissect(BERChoiceField, "020163")
    assert as_int.c.val == 99

    as_str = _dissect(BERChoiceField, "040178")
    assert as_str.c.val == b"x"


def check_ber_record_dissect():
    # type: () -> None
    decoded = _dissect(
        BERRecord,
        "301a02012a01010104026869"
        "a003020107"
        "3009020101020102020103",
    )
    _assert_record(decoded)

    empty = _dissect(BERRecord, "300a02010101010004003000")
    _assert_record_empty(empty)


def check_oer_field_dissect():
    # type: () -> None
    tagged = _dissect(OERTaggedInteger, "a10105")
    assert tagged.n.val == 5

    fixed = _dissect(OERFixedFields, "c8414243")
    assert fixed.n.val == 200
    assert fixed.s.val == b"ABC"

    present = _dissect(OEROptionalField, "0101a00107")
    assert present.id.val == 1
    assert present.extra.val == 7

    absent = _dissect(OEROptionalField, "0101")
    assert absent.id.val == 1
    assert absent.extra is None

    seqof = _dissect(OERSequenceOfIntegers, "0103010101020103")
    assert [x.val for x in seqof.values] == [1, 2, 3]

    as_int = _dissect(OERChoiceField, "020163")
    assert as_int.c.val == 99

    as_str = _dissect(OERChoiceField, "040178")
    assert as_str.c.val == b"x"


def check_oer_record_dissect():
    # type: () -> None
    decoded = _dissect(
        OERRecord,
        "012aff026869a00107"
        "0103010101020103",
    )
    _assert_record(decoded)

    empty = _dissect(OERRecord, "010100000100")
    _assert_record_empty(empty)


def check_per_field_dissect():
    # type: () -> None
    fixed = _dissect(UPERFixedFields, "c8414243")
    assert fixed.n.val == 200
    assert fixed.s.val == b"ABC"

    present = _dissect(UPEROptionalField, "80954041c0")
    assert present.id.val == 42
    assert present.flag.val == 1
    assert present.extra.val == 7

    absent = _dissect(UPEROptionalField, "009540")
    assert absent.id.val == 42
    assert absent.flag.val == 1
    assert absent.extra is None

    seqof = _dissect(UPERSequenceOfIntegers, "03010101020103")
    assert [x.val for x in seqof.values] == [1, 2, 3]

    empty_seqof = _dissect(UPERSequenceOfIntegers, "00")
    assert [x.val for x in empty_seqof.values] == []

    as_int = _dissect(UPERChoiceField, "00b180")
    assert as_int.c.val == 99

    as_str = _dissect(UPERChoiceField, "8120a100")
    assert as_str.c.val == b"AB"


def check_per_record_dissect():
    # type: () -> None
    decoded = _dissect(
        UPERRecord,
        "8095409a1a4041c0c04040408040c0",
    )
    _assert_record(decoded)

    partial = _dissect(UPERRecord, "0095409050808040404080")
    assert partial.id.val == 42
    assert partial.flag.val == 1
    assert partial.label.val == b"AB"
    assert partial.extra is None
    assert [x.val for x in partial.values] == [1, 2]

    empty = _dissect(UPERRecord, "0080800000")
    _assert_record_empty(empty)


def check_per_default_field_dissect():
    # type: () -> None
    class UPERDefaultRecord(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER("id", 0, uper_min=0, uper_max=255),
            ASN1F_DEFAULT(
                ASN1F_INTEGER(
                    "count", 600,
                    uper_min=0, uper_max=86401, oer_unsigned=True,
                ),
                600,
            ),
        )

    absent = _dissect(UPERDefaultRecord, "0080")
    assert absent.id.val == 1
    assert _asn1_int(absent.count) == 600

    present = _dissect(UPERDefaultRecord, "80d46000")
    assert present.id.val == 1
    assert _asn1_int(present.count) == 86400


def check_per_extensible_integer_dissect():
    # type: () -> None
    class UPERExtInt(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_INTEGER(
                "n", 0,
                uper_min=1, uper_max=65535,
                uper_extensible=True, oer_unsigned=True,
            ),
        )

    in_range = _dissect(UPERExtInt, "001480")
    assert in_range.n.val == 42

    out_of_range = _dissect(UPERExtInt, "8232dd587c80")
    assert out_of_range.n.val == 1706733817


def check_per_constrained_sequence_of_dissect():
    # type: () -> None
    class UPERConstrainedSeqOf(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE_OF(
            "items", [],
            ASN1F_INTEGER("n", 0, uper_min=0, uper_max=7),
            uper_min=1, uper_max=3,
        )

    decoded = _dissect(UPERConstrainedSeqOf, "4a")
    assert [x.val for x in decoded.items] == [1, 2]


def check_ber_oer_per_record_dissect():
    # type: () -> None
    for cls, data_hex in [
        (
            BERRecord,
            "301a02012a01010104026869"
            "a003020107"
            "3009020101020102020103",
        ),
        (
            OERRecord,
            "012aff026869a00107"
            "0103010101020103",
        ),
        (
            UPERRecord,
            "8095409a1a4041c0c04040408040c0",
        ),
    ]:
        _assert_record(_dissect(cls, data_hex))
