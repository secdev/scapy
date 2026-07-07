# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
UPER interoperability helpers.

Cross-check Scapy's UPER codec against reference encodings (from asn1tools).
"""

from typing import Any

from scapy.asn1.uper import (
    UPERcodec_BOOLEAN,
    UPERcodec_ENUMERATED,
    UPERcodec_INTEGER,
    UPERcodec_NULL,
    UPERcodec_STRING,
    UPER_Encoder,
    UPER_choice_index_enc,
)
from scapy.packet import raw

from test.scapy.layers.uper_packets import (
    UPERMultiOptional,
    UPERNestedSequence,
)

# (type name, value, scapy encoder callable, reference encoding)
PRIMITIVE_VECTORS = [
    ("A", True, lambda v: UPERcodec_BOOLEAN.enc(1 if v else 0), b"\x80"),
    ("A", False, lambda v: UPERcodec_BOOLEAN.enc(1 if v else 0), b"\x00"),
    ("B", 42, lambda v: UPERcodec_INTEGER.enc(v), b"\x01*"),
    ("B", -1, lambda v: UPERcodec_INTEGER.enc(v), b"\x01\xff"),
    (
        "C",
        200,
        lambda v: UPERcodec_INTEGER.enc(v, uper_min=0, uper_max=255),
        b"\xc8",
    ),
    ("D", b"AB", lambda v: UPERcodec_STRING.enc(v), b"\x02AB"),
    (
        "E",
        b"\x12\x34\x56",
        lambda v: UPERcodec_STRING.enc(v, size_len=3),
        b"\x12\x34\x56",
    ),
    ("G", None, lambda v: UPERcodec_NULL.enc(None), b""),
    (
        "H",
        "beta",
        lambda v: UPERcodec_ENUMERATED.enc(200, uper_enum_values=[1, 200]),
        b"\x80",
    ),
]

# (type name, value, reference encoding)
COMPOSITE_VECTORS = [
    ("Seq", {"id": 42, "flag": True}, b"\x00\x95@"),
    ("Seq", {"id": 42, "flag": True, "extra": 7}, b"\x80\x95@A\xc0"),
    ("SeqOf", [1, 2, 3], b"\x03\x01\x01\x01\x02\x01\x03"),
    ("SeqOfC", [1, 200, 0], b"\x03\x01\xc8\x00"),
    ("Choice", ("a", 99), b"\x00\xb1\x80"),
    ("Choice", ("b", b"AB"), b"\x81 \xa1\x00"),
    ("ChoiceC", ("a", 10), b"P"),
    ("ChoiceC", ("b", b"AB"), b"\x81 \xa1\x00"),
]

DECODE_PACKET_VECTORS = [
    (
        UPERNestedSequence,
        {"id": 5, "x": 3, "y": True},
        bytes.fromhex("0105010380"),
    ),
    (
        UPERMultiOptional,
        {"id": 1, "a": 2, "b": b"hi"},
        bytes.fromhex("c0404040809a1a40"),
    ),
]

PACKET_REFERENCE_VECTORS = [
    (
        UPERNestedSequence,
        {"id": 5, "x": 3, "y": True},
        bytes.fromhex("0105010380"),
    ),
    (
        UPERMultiOptional,
        {"id": 1, "a": 2, "b": b"hi"},
        bytes.fromhex("c0404040809a1a40"),
    ),
]


def check_primitive_interop():
    # type: () -> None
    for typename, value, encoder, expected in PRIMITIVE_VECTORS:
        got = encoder(value)
        assert got == expected, (
            "%s %r: expected %s, got %s" %
            (typename, value, expected.hex(), got.hex())
        )


def check_composite_interop():
    # type: () -> None
    for typename, value, expected in COMPOSITE_VECTORS:
        got = _encode_composite(typename, value)
        assert got == expected, (
            "%s %r: expected %s, got %s" %
            (typename, value, expected.hex(), got.hex())
        )


def check_packet_reference_interop():
    # type: () -> None
    for cls, pkt_kwargs, expected in PACKET_REFERENCE_VECTORS:
        got = raw(cls(**pkt_kwargs))
        assert got == expected, (
            "%s: expected %s, got %s" %
            (cls.__name__, expected.hex(), got.hex())
        )
        decoded = cls(got)
        for key, value in pkt_kwargs.items():
            field = getattr(decoded, key)
            if value is None:
                assert field is None
            elif isinstance(value, bool):
                assert field.val == (1 if value else 0)
            else:
                assert field.val == value


def check_packet_decode_vectors():
    # type: () -> None
    for cls, pkt_kwargs, data in DECODE_PACKET_VECTORS:
        decoded = cls(data)
        for key, value in pkt_kwargs.items():
            field = getattr(decoded, key)
            if isinstance(value, bool):
                assert field.val == (1 if value else 0)
            else:
                assert field.val == value


def _encode_composite(typename, value):
    # type: (str, Any) -> bytes
    enc = UPER_Encoder()
    if typename == "Seq":
        enc.append_bit(1 if value.get("extra") is not None else 0)
        UPERcodec_INTEGER.encode_into(enc, value["id"])
        UPERcodec_BOOLEAN.encode_into(enc, 1 if value["flag"] else 0)
        if value.get("extra") is not None:
            UPERcodec_INTEGER.encode_into(enc, value["extra"])
        return enc.as_bytes()
    if typename == "SeqOf":
        enc.append_length_determinant(len(value))
        for item in value:
            UPERcodec_INTEGER.encode_into(enc, item)
        return enc.as_bytes()
    if typename == "SeqOfC":
        enc.append_length_determinant(len(value))
        for item in value:
            UPERcodec_INTEGER.encode_into(
                enc, item, uper_min=0, uper_max=255,
            )
        return enc.as_bytes()
    if typename == "Choice":
        alt, payload = value
        index = 0 if alt == "a" else 1
        UPER_choice_index_enc(index, 2, enc=enc)
        if alt == "a":
            UPERcodec_INTEGER.encode_into(enc, payload)
        else:
            UPERcodec_STRING.encode_into(enc, payload)
        return enc.as_bytes()
    if typename == "ChoiceC":
        alt, payload = value
        index = 0 if alt == "a" else 1
        UPER_choice_index_enc(index, 2, enc=enc)
        if alt == "a":
            UPERcodec_INTEGER.encode_into(
                enc, payload, uper_min=0, uper_max=15,
            )
        else:
            UPERcodec_STRING.encode_into(enc, payload)
        return enc.as_bytes()
    raise ValueError("unknown composite type %s" % typename)
