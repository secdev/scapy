# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Cross-codec ASN.1 packet build and round-trip tests (BER, OER, PER).
"""

from scapy.asn1.asn1 import ASN1_Codecs, ASN1_INTEGER, ASN1_STRING
from scapy.asn1fields import (
    ASN1F_BOOLEAN,
    ASN1F_CHOICE,
    ASN1F_DEFAULT,
    ASN1F_INTEGER,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
    ASN1F_STRING,
    ASN1F_optional,
)
from scapy.asn1packet import ASN1_Packet
from scapy.packet import raw

from typing import Any

from test.scapy.layers.ber_packets import BERRecord
from test.scapy.layers.oer_packets import OERRecord
from test.scapy.layers.uper_packets import UPERRecord


def _roundtrip(cls, pkt):
    # type: (type, ASN1_Packet) -> ASN1_Packet
    return cls(raw(pkt))


def _record_kwargs():
    # type: () -> dict
    return dict(
        id=42,
        flag=True,
        label=b"hi",
        extra=7,
        values=[1, 2, 3],
    )


def check_ber_record_build_roundtrip():
    # type: () -> None
    pkt = BERRecord(**_record_kwargs())
    assert len(raw(pkt)) > 0
    decoded = _roundtrip(BERRecord, pkt)
    assert decoded.id.val == 42
    assert decoded.flag.val == 1
    assert decoded.label.val == b"hi"
    assert decoded.extra.val == 7
    assert [x.val for x in decoded.values] == [1, 2, 3]


def check_oer_record_build_roundtrip():
    # type: () -> None
    pkt = OERRecord(**_record_kwargs())
    assert len(raw(pkt)) > 0
    decoded = _roundtrip(OERRecord, pkt)
    assert decoded.id.val == 42
    assert decoded.flag.val == 1
    assert decoded.label.val == b"hi"
    assert decoded.extra.val == 7
    assert [x.val for x in decoded.values] == [1, 2, 3]


def check_per_record_build_roundtrip():
    # type: () -> None
    pkt = UPERRecord(**_record_kwargs())
    assert len(raw(pkt)) > 0
    decoded = _roundtrip(UPERRecord, pkt)
    assert decoded.id.val == 42
    assert decoded.flag.val == 1
    assert decoded.label.val == b"hi"
    assert decoded.extra.val == 7
    assert [x.val for x in decoded.values] == [1, 2, 3]


def _asn1_int(val):
    # type: (Any) -> int
    return val.val if hasattr(val, "val") else val


def check_per_default_field_build():
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

    absent = UPERDefaultRecord(id=1)
    assert raw(absent) == b"\x00\x80"
    decoded = _roundtrip(UPERDefaultRecord, absent)
    assert decoded.id.val == 1
    assert _asn1_int(decoded.count) == 600

    present = UPERDefaultRecord(id=1, count=86400)
    assert raw(present) == bytes.fromhex("80d46000")
    decoded = _roundtrip(UPERDefaultRecord, present)
    assert decoded.id.val == 1
    assert _asn1_int(decoded.count) == 86400


def check_per_extensible_integer_build():
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

    in_range = UPERExtInt(n=42)
    assert raw(in_range) == bytes.fromhex("001480")
    decoded = _roundtrip(UPERExtInt, in_range)
    assert decoded.n.val == 42

    out_of_range = UPERExtInt(n=1706733817)
    assert raw(out_of_range) == bytes.fromhex("8232dd587c80")
    decoded = _roundtrip(UPERExtInt, out_of_range)
    assert decoded.n.val == 1706733817


def check_per_constrained_sequence_of_build():
    # type: () -> None
    class UPERConstrainedSeqOf(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_SEQUENCE_OF(
            "items", [],
            ASN1F_INTEGER("n", 0, uper_min=0, uper_max=7),
            uper_min=1, uper_max=3,
        )

    pkt = UPERConstrainedSeqOf(items=[1, 2])
    assert raw(pkt) == bytes.fromhex("4a")
    decoded = _roundtrip(UPERConstrainedSeqOf, pkt)
    assert [x.val for x in decoded.items] == [1, 2]


def check_ber_oer_per_choice_build():
    # type: () -> None
    class BERChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
        )

    class OERChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.OER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
        )

    class PERChoice(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.PER
        ASN1_root = ASN1F_CHOICE(
            "c", ASN1_INTEGER(0), ASN1F_INTEGER, ASN1F_STRING,
        )

    for cls in (BERChoice, OERChoice, PERChoice):
        as_int = cls(c=ASN1_INTEGER(99))
        assert len(raw(as_int)) > 0
        decoded = _roundtrip(cls, as_int)
        assert decoded.c.val == 99

        as_str = cls(c=ASN1_STRING(b"AB"))
        assert len(raw(as_str)) > 0
        decoded = _roundtrip(cls, as_str)
        assert decoded.c.val == b"AB"
