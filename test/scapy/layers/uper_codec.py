# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
UPER primitive codec roundtrip and decode interoperability tests.
"""

from typing import Any, Dict, List, Tuple, Type

try:
    import asn1tools
    HAS_ASN1TOOLS = True
except ImportError:
    asn1tools = None  # type: ignore
    HAS_ASN1TOOLS = False

from scapy.asn1.uper import (
    UPERcodec_BIT_STRING,
    UPERcodec_BOOLEAN,
    UPERcodec_ENUMERATED,
    UPERcodec_INTEGER,
    UPERcodec_NULL,
    UPERcodec_OID,
    UPERcodec_STRING,
)

CodecRoundtrip = Tuple[
    Type[Any],
    Any,
    Dict[str, Any],
    Any,
]

CODEC_ROUNDTRIPS = [
    (UPERcodec_NULL, None, {}, None),
    (UPERcodec_BOOLEAN, 1, {}, 1),
    (UPERcodec_BOOLEAN, 0, {}, 0),
    (UPERcodec_INTEGER, 42, {}, 42),
    (UPERcodec_INTEGER, -1, {}, -1),
    (UPERcodec_INTEGER, 68719476736, {}, 68719476736),
    (UPERcodec_INTEGER, 200, {"uper_min": 0, "uper_max": 255}, 200),
    (UPERcodec_INTEGER, -1, {"uper_min": -128, "uper_max": 127}, -1),
    (UPERcodec_INTEGER, 127, {"uper_min": -128, "uper_max": 127}, 127),
    (UPERcodec_INTEGER, -128, {"uper_min": -128, "uper_max": 127}, -128),
    (UPERcodec_STRING, b"AB", {}, b"AB"),
    (UPERcodec_STRING, b"\x12\x34\x56", {"size_len": 3}, b"\x12\x34\x56"),
    (
        UPERcodec_STRING,
        bytes.fromhex("afbc4583"),
        {"uper_min": 1, "uper_max": 20},
        bytes.fromhex("afbc4583"),
    ),
    (UPERcodec_ENUMERATED, 1, {"uper_enum_values": [1, 200]}, 1),
    (UPERcodec_ENUMERATED, 200, {"uper_enum_values": [1, 200]}, 200),
    (
        UPERcodec_BIT_STRING,
        (bytes.fromhex("abcd"), 16),
        {"uper_min": 1, "uper_max": 20},
        "1010101111001101",
    ),
    (
        UPERcodec_BIT_STRING,
        (bytes.fromhex("abcd"), 16),
        {"uper_min": 16, "uper_max": 16},
        "1010101111001101",
    ),
    (UPERcodec_ENUMERATED, 1, {"uper_enum_values": [1]}, 1),
]

DecodeVector = Tuple[
    str,
    Any,
    Type[Any],
    Dict[str, Any],
    Any,
]

DECODE_VECTORS = [
    ("A", True, UPERcodec_BOOLEAN, {}, 1),
    ("A", False, UPERcodec_BOOLEAN, {}, 0),
    ("B", 42, UPERcodec_INTEGER, {}, 42),
    ("B", -1, UPERcodec_INTEGER, {}, -1),
    ("C", 200, UPERcodec_INTEGER, {"uper_min": 0, "uper_max": 255}, 200),
    ("Signed", -1, UPERcodec_INTEGER, {"uper_min": -128, "uper_max": 127}, -1),
    ("Signed", 127, UPERcodec_INTEGER, {"uper_min": -128, "uper_max": 127}, 127),
    ("D", b"AB", UPERcodec_STRING, {}, b"AB"),
    ("E", b"\x12\x34\x56", UPERcodec_STRING, {"size_len": 3}, b"\x12\x34\x56"),
    ("G", None, UPERcodec_NULL, {}, None),
    (
        "H",
        "alpha",
        UPERcodec_ENUMERATED,
        {"uper_enum_values": [1, 200]},
        1,
    ),
    (
        "H",
        "beta",
        UPERcodec_ENUMERATED,
        {"uper_enum_values": [1, 200]},
        200,
    ),
]

ASN1TOOLS_OID_SPEC = (
    "Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN "
    "A ::= OBJECT IDENTIFIER "
    "END"
)


def require_asn1tools():
    # type: () -> bool
    return HAS_ASN1TOOLS


def _assert_codec_roundtrip(codec, value, kwargs, expected):
    # type: (Type[Any], Any, Dict[str, Any], Any) -> None
    data = codec.enc(value, **kwargs)
    decoded, _remain = codec.do_dec(data, **kwargs)
    assert decoded.val == expected


def check_uper_codec_roundtrips():
    # type: () -> None
    for codec, value, kwargs, expected in CODEC_ROUNDTRIPS:
        _assert_codec_roundtrip(codec, value, kwargs, expected)


def check_uper_codec_oid_roundtrip():
    # type: () -> None
    import scapy.all  # noqa: F401  # loads conf.mib for ASN1_OID
    for oid in ("1.2.3", "1.2.840.113549"):
        data = UPERcodec_OID.enc(oid)
        decoded, remain = UPERcodec_OID.do_dec(data)
        assert remain == b""
        assert decoded.val == oid


def check_uper_codec_oid_encode_interop():
    # type: () -> None
    if not HAS_ASN1TOOLS:
        raise RuntimeError("asn1tools is not installed")
    foo = asn1tools.compile_string(ASN1TOOLS_OID_SPEC, "uper")
    for oid in ("1.2.3", "2.999.3"):
        expected = foo.encode("A", oid)
        got = UPERcodec_OID.enc(oid)
        assert got == expected, (
            "OID %r: expected %s, got %s" %
            (oid, expected.hex(), got.hex())
        )


def check_uper_codec_asn1tools_decode():
    # type: () -> None
    if not HAS_ASN1TOOLS:
        raise RuntimeError("asn1tools is not installed")
    from test.scapy.layers.uper_iop import ASN1TOOLS_UPER_SPEC

    foo = asn1tools.compile_string(ASN1TOOLS_UPER_SPEC, "uper")
    for typename, value, codec, kwargs, expected in DECODE_VECTORS:
        encoded = foo.encode(typename, value)
        decoded, _remain = codec.do_dec(encoded, **kwargs)
        assert decoded.val == expected, (
            "%s %r: expected %r, got %r" %
            (typename, value, expected, decoded.val)
        )


def check_uper_codec_scapy_decode_asn1tools():
    # type: () -> None
    if not HAS_ASN1TOOLS:
        raise RuntimeError("asn1tools is not installed")
    from test.scapy.layers.uper_iop import ASN1TOOLS_UPER_SPEC, PRIMITIVE_VECTORS

    foo = asn1tools.compile_string(ASN1TOOLS_UPER_SPEC, "uper")
    for typename, value, encoder in PRIMITIVE_VECTORS:
        encoded = encoder(value)
        asn1_value = foo.decode(typename, encoded)
        if typename == "H":
            assert asn1_value == value
        elif typename == "G":
            assert asn1_value is None
        else:
            assert asn1_value == value
