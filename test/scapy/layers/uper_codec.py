# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
UPER primitive codec roundtrip and decode interoperability tests.
"""

from typing import Any, Dict, Tuple, Type

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
    bytes,
]

DECODE_VECTORS = [
    ("A", True, UPERcodec_BOOLEAN, {}, 1, b"\x80"),
    ("A", False, UPERcodec_BOOLEAN, {}, 0, b"\x00"),
    ("B", 42, UPERcodec_INTEGER, {}, 42, b"\x01*"),
    ("B", -1, UPERcodec_INTEGER, {}, -1, b"\x01\xff"),
    (
        "C",
        200,
        UPERcodec_INTEGER,
        {"uper_min": 0, "uper_max": 255},
        200,
        b"\xc8",
    ),
    (
        "Signed",
        -1,
        UPERcodec_INTEGER,
        {"uper_min": -128, "uper_max": 127},
        -1,
        b"\x7f",
    ),
    (
        "Signed",
        127,
        UPERcodec_INTEGER,
        {"uper_min": -128, "uper_max": 127},
        127,
        b"\xff",
    ),
    ("D", b"AB", UPERcodec_STRING, {}, b"AB", b"\x02AB"),
    (
        "E",
        b"\x12\x34\x56",
        UPERcodec_STRING,
        {"size_len": 3},
        b"\x12\x34\x56",
        b"\x12\x34\x56",
    ),
    ("G", None, UPERcodec_NULL, {}, None, b""),
    ("H", "alpha", UPERcodec_ENUMERATED, {"uper_enum_values": [1, 200]}, 1, b"\x00"),
    ("H", "beta", UPERcodec_ENUMERATED, {"uper_enum_values": [1, 200]}, 200, b"\x80"),
]

OID_ENCODE_VECTORS = [
    ("1.2.3", b"\x02*\x03"),
    ("2.999.3", b"\x03\x887\x03"),
]


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
    for oid, expected in OID_ENCODE_VECTORS:
        got = UPERcodec_OID.enc(oid)
        assert got == expected, (
            "OID %r: expected %s, got %s" %
            (oid, expected.hex(), got.hex())
        )


def check_uper_codec_reference_decode():
    # type: () -> None
    for _typename, _value, codec, kwargs, expected, encoded in DECODE_VECTORS:
        decoded, _remain = codec.do_dec(encoded, **kwargs)
        assert decoded.val == expected, (
            "%s %r: expected %r, got %r" %
            (_typename, _value, expected, decoded.val)
        )


def check_uper_codec_encode_reference():
    # type: () -> None
    from test.scapy.layers.uper_iop import PRIMITIVE_VECTORS

    for typename, value, encoder, expected in PRIMITIVE_VECTORS:
        encoded = encoder(value)
        assert encoded == expected, (
            "%s %r: expected %s, got %s" %
            (typename, value, expected.hex(), encoded.hex())
        )
