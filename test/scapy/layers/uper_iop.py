# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
UPER interoperability helpers.

Cross-check Scapy's UPER codec against asn1tools when available.
"""

from typing import Any, Callable, List, Optional, Tuple

try:
    import asn1tools
    HAS_ASN1TOOLS = True
except ImportError:
    asn1tools = None  # type: ignore
    HAS_ASN1TOOLS = False

from scapy.asn1.uper import (
    UPERcodec_BOOLEAN,
    UPERcodec_ENUMERATED,
    UPERcodec_INTEGER,
    UPERcodec_NULL,
    UPERcodec_STRING,
    UPER_Encoder,
    UPER_choice_index_enc,
)


ASN1TOOLS_UPER_SPEC = (
    "Foo DEFINITIONS AUTOMATIC TAGS ::= "
    "BEGIN "
    "A ::= BOOLEAN "
    "B ::= INTEGER "
    "C ::= INTEGER (0..255) "
    "Signed ::= INTEGER (-128..127) "
    "SeqOfC ::= SEQUENCE OF INTEGER (0..255) "
    "ChoiceC ::= CHOICE { a INTEGER (0..15), b OCTET STRING } "
    "D ::= OCTET STRING "
    "E ::= OCTET STRING (SIZE(3)) "
    "G ::= NULL "
    "Seq ::= SEQUENCE { id INTEGER, flag BOOLEAN, extra INTEGER OPTIONAL } "
    "SeqOf ::= SEQUENCE OF INTEGER "
    "Choice ::= CHOICE { a INTEGER, b OCTET STRING } "
    "H ::= ENUMERATED { alpha(1), beta(200) } "
    "Inner ::= SEQUENCE { x INTEGER, y BOOLEAN } "
    "Outer ::= SEQUENCE { id INTEGER, inner Inner } "
    "Multi ::= SEQUENCE { id INTEGER, a INTEGER OPTIONAL, b OCTET STRING OPTIONAL } "
    "END"
)

PRIMITIVE_VECTORS = [
    ("A", True, lambda v: UPERcodec_BOOLEAN.enc(1 if v else 0)),
    ("A", False, lambda v: UPERcodec_BOOLEAN.enc(1 if v else 0)),
    ("B", 42, lambda v: UPERcodec_INTEGER.enc(v)),
    ("B", -1, lambda v: UPERcodec_INTEGER.enc(v)),
    ("C", 200, lambda v: UPERcodec_INTEGER.enc(v, uper_min=0, uper_max=255)),
    ("D", b"AB", lambda v: UPERcodec_STRING.enc(v)),
    ("E", b"\x12\x34\x56", lambda v: UPERcodec_STRING.enc(v, size_len=3)),
    ("G", None, lambda v: UPERcodec_NULL.enc(None)),
    ("H", "beta", lambda v: UPERcodec_ENUMERATED.enc(
        200, uper_enum_values=[1, 200],
    )),
]

COMPOSITE_VECTORS = [
    ("Seq", {"id": 42, "flag": True}),
    ("Seq", {"id": 42, "flag": True, "extra": 7}),
    ("SeqOf", [1, 2, 3]),
    ("SeqOfC", [1, 200, 0]),
    ("Choice", ("a", 99)),
    ("Choice", ("b", b"AB")),
    ("ChoiceC", ("a", 10)),
    ("ChoiceC", ("b", b"AB")),
]

from test.scapy.layers.uper_packets import (
    UPERMultiOptional,
    UPERNestedSequence,
)
from scapy.packet import raw

DECODE_COMPOSITE_VECTORS = [
    ("Seq", {"id": 42, "flag": True}, {"id": 42, "flag": True}),
    (
        "Seq",
        {"id": 42, "flag": True, "extra": 7},
        {"id": 42, "flag": True, "extra": 7},
    ),
    ("SeqOf", [1, 2, 3], [1, 2, 3]),
    ("SeqOfC", [1, 200, 0], [1, 200, 0]),
    ("Choice", ("a", 99), ("a", 99)),
    ("Choice", ("b", b"AB"), ("b", b"AB")),
    ("ChoiceC", ("a", 10), ("a", 10)),
    ("ChoiceC", ("b", b"AB"), ("b", b"AB")),
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

ASN1TOOLS_PACKET_VECTORS = [
    (
        "Outer",
        {"id": 5, "inner": {"x": 3, "y": True}},
        UPERNestedSequence,
        {"id": 5, "x": 3, "y": True},
    ),
    (
        "Multi",
        {"id": 1, "a": 2, "b": b"hi"},
        UPERMultiOptional,
        {"id": 1, "a": 2, "b": b"hi"},
    ),
]


def require_asn1tools():
    # type: () -> bool
    return HAS_ASN1TOOLS


def _compile_asn1tools():
    # type: () -> Any
    if not HAS_ASN1TOOLS:
        raise RuntimeError("asn1tools is not installed")
    return asn1tools.compile_string(ASN1TOOLS_UPER_SPEC, "uper")


def check_primitive_interop():
    # type: () -> None
    foo = _compile_asn1tools()
    for typename, value, encoder in PRIMITIVE_VECTORS:
        expected = foo.encode(typename, value)
        got = encoder(value)
        assert got == expected, (
            "%s %r: expected %s, got %s" %
            (typename, value, expected.hex(), got.hex())
        )


def check_composite_interop():
    # type: () -> None
    foo = _compile_asn1tools()
    for typename, value in COMPOSITE_VECTORS:
        expected = foo.encode(typename, value)
        got = _encode_composite(typename, value)
        assert got == expected, (
            "%s %r: expected %s, got %s" %
            (typename, value, expected.hex(), got.hex())
        )


def check_composite_decode_interop():
    # type: () -> None
    foo = _compile_asn1tools()
    for typename, encoded_value, expected in DECODE_COMPOSITE_VECTORS:
        data = foo.encode(typename, encoded_value)
        got = foo.decode(typename, _encode_composite(typename, encoded_value))
        assert got == expected, (
            "%s %r: expected %r, got %r" % (typename, encoded_value, expected, got)
        )
        assert foo.decode(typename, data) == expected


def check_packet_asn1tools_interop():
    # type: () -> None
    foo = _compile_asn1tools()
    for typename, asn1_value, cls, pkt_kwargs in ASN1TOOLS_PACKET_VECTORS:
        expected = foo.encode(typename, asn1_value)
        got = raw(cls(**pkt_kwargs))
        assert got == expected, (
            "%s: expected %s, got %s" %
            (typename, expected.hex(), got.hex())
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
