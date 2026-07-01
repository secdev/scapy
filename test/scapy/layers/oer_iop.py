# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
OER interoperability helpers.

Cross-check Scapy's OER codec against asn1tools when available.
asn1tools is an optional test dependency (pip install asn1tools).
Reference vectors are taken from asn1tools/tests/test_oer.py.
"""

from typing import Any, Callable, List, Optional, Tuple

try:
    import asn1tools
    HAS_ASN1TOOLS = True
except ImportError:
    asn1tools = None  # type: ignore
    HAS_ASN1TOOLS = False

from scapy.asn1.oer import (
    OERcodec_BIT_STRING,
    OERcodec_BOOLEAN,
    OERcodec_ENUMERATED,
    OERcodec_INTEGER,
    OERcodec_NULL,
    OERcodec_OID,
    OERcodec_STRING,
    OER_len_dec,
    OER_len_enc,
    OER_signed_integer_dec,
    OER_signed_integer_enc,
    OER_unsigned_integer_dec,
    OER_unsigned_integer_enc,
)


ASN1TOOLS_INTEGER_SPEC = (
    "Foo DEFINITIONS AUTOMATIC TAGS ::= "
    "BEGIN "
    "A ::= INTEGER "
    "B ::= INTEGER (-128..127) "
    "C ::= INTEGER (-32768..32767) "
    "D ::= INTEGER (-2147483648..2147483647) "
    "E ::= INTEGER (-9223372036854775808..9223372036854775807) "
    "F ::= INTEGER (0..255) "
    "G ::= INTEGER (0..65535) "
    "H ::= INTEGER (0..4294967295) "
    "I ::= INTEGER (0..18446744073709551615) "
    "J ::= INTEGER (0..18446744073709551616) "
    "K ::= INTEGER (1..MAX) "
    "L ::= INTEGER (MIN..0) "
    "END"
)

# (asn1tools type, value, scapy encoder callable)
INTEGER_VECTORS = [
    ("A", 0, lambda v: OERcodec_INTEGER.enc(v)),
    ("A", 128, lambda v: OERcodec_INTEGER.enc(v)),
    ("A", 100000, lambda v: OERcodec_INTEGER.enc(v)),
    ("A", -255, lambda v: OERcodec_INTEGER.enc(v)),
    ("A", -1234567, lambda v: OERcodec_INTEGER.enc(v)),
    ("B", -2, lambda v: OERcodec_INTEGER.enc(v, size_len=1)),
    ("C", -2, lambda v: OERcodec_INTEGER.enc(v, size_len=2)),
    ("D", -2, lambda v: OERcodec_INTEGER.enc(v, size_len=4)),
    ("E", -2, lambda v: OERcodec_INTEGER.enc(v, size_len=8)),
    ("F", 128, lambda v: OERcodec_INTEGER.enc(v, size_len=1)),
    ("G", 128, lambda v: OERcodec_INTEGER.enc(v, size_len=2)),
    ("G", 1000, lambda v: OERcodec_INTEGER.enc(v, size_len=2)),
    ("H", 128, lambda v: OERcodec_INTEGER.enc(v, size_len=4)),
    ("I", 128, lambda v: OERcodec_INTEGER.enc(v, size_len=8)),
    ("B", 1, lambda v: OERcodec_INTEGER.enc(v, size_len=1)),
    ("K", 1, lambda v: OER_unsigned_integer_enc(v)),
    ("K", 128, lambda v: OER_unsigned_integer_enc(v)),
    ("L", -128, lambda v: OER_signed_integer_enc(v)),
]

BOOLEAN_VECTORS = [
    (True, lambda v: OERcodec_BOOLEAN.enc(1 if v else 0)),
    (False, lambda v: OERcodec_BOOLEAN.enc(1 if v else 0)),
]

ENUMERATED_VECTORS = [
    ("A ::= ENUMERATED { a(1) }", "A", "a", 1),
    ("B ::= ENUMERATED { a(128) }", "B", "a", 128),
    ("C ::= ENUMERATED { a(0), b(127) }", "C", "a", 0),
    ("C ::= ENUMERATED { a(0), b(127) }", "C", "b", 127),
    ("E ::= ENUMERATED { a(-1), b(1234) }", "E", "a", -1),
]

OID_VECTORS = [
    ("1.2", lambda v: OERcodec_OID.enc(v)),
    ("1.2.3321", lambda v: OERcodec_OID.enc(v)),
]

OCTET_STRING_VECTORS = [
    (b"\x12\x34", 0),
    (b"\x12\x34\x56", 3),
]

BIT_STRING_VECTORS = [
    # (asn1 value, scapy bit string)
    ((b"\x40", 4), "0100"),
    ((b"\x41", 8), "01000001"),
]


def require_asn1tools():
    # type: () -> bool
    """Return True if asn1tools is available for interoperability tests."""
    return HAS_ASN1TOOLS


def _compile(spec_body):
    # type: (str) -> Any
    assert asn1tools is not None
    spec = "Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN %s END" % spec_body
    return asn1tools.compile_string(spec, "oer")


def _assert_encode_match(spec_body, type_name, value, scapy_enc):
    # type: (str, str, Any, Callable[..., bytes]) -> None
    compiled = _compile(spec_body)
    expected = compiled.encode(type_name, value)
    got = scapy_enc(value)
    assert got == expected, (
        "OER encode mismatch for %s=%r: asn1tools=%r scapy=%r" %
        (type_name, value, expected, got)
    )


def _assert_decode_match(type_name, encoded, scapy_dec, expected_value):
    # type: (str, bytes, Callable[[bytes], Tuple[Any, bytes]], Any) -> None
    obj, remain = scapy_dec(encoded)
    assert remain == b"", "unexpected remainder after decode of %s" % type_name
    assert obj.val == expected_value, (
        "OER decode mismatch for %s: got %r expected %r" %
        (type_name, obj.val, expected_value)
    )


def check_primitive_interop():
    # type: () -> bool
    """Compare Scapy OER primitives against asn1tools. Returns True on success."""
    if not HAS_ASN1TOOLS:
        return True

    compiled = asn1tools.compile_string(ASN1TOOLS_INTEGER_SPEC, "oer")
    for type_name, value, enc in INTEGER_VECTORS:
        expected = compiled.encode(type_name, value)
        got = enc(value)
        assert got == expected, (
            "integer %s=%r: asn1tools=%r scapy=%r" %
            (type_name, value, expected, got)
        )
        if type_name == "A":
            dec, remain = OERcodec_INTEGER.do_dec(got)
            assert remain == b"" and dec.val == value

    bool_spec = _compile("A ::= BOOLEAN")
    for value, enc in BOOLEAN_VECTORS:
        expected = bool_spec.encode("A", value)
        got = enc(value)
        assert got == expected
        dec, remain = OERcodec_BOOLEAN.do_dec(got)
        assert remain == b"" and dec.val == (1 if value else 0)

    _assert_encode_match("A ::= NULL", "A", None, lambda _: OERcodec_NULL.enc(None))

    for spec_body, type_name, enum_name, enum_val in ENUMERATED_VECTORS:
        compiled = _compile(spec_body)
        expected = compiled.encode(type_name, enum_name)
        got = OERcodec_ENUMERATED.enc(enum_val)
        assert got == expected
        dec, remain = OERcodec_ENUMERATED.do_dec(got)
        assert remain == b"" and dec.val == enum_val

    oid_spec = _compile("A ::= OBJECT IDENTIFIER")
    for oid, enc in OID_VECTORS:
        expected = oid_spec.encode("A", oid)
        got = enc(oid)
        assert got == expected
        dec, remain = OERcodec_OID.do_dec(got)
        assert remain == b"" and dec.val == oid

    octet_spec = _compile(
        "A ::= OCTET STRING\nB ::= OCTET STRING (SIZE (3))"
    )
    for data, fixed_size in OCTET_STRING_VECTORS:
        type_name = "B" if fixed_size else "A"
        expected = octet_spec.encode(type_name, data)
        got = OERcodec_STRING.enc(data, size_len=fixed_size or 0)
        assert got == expected
        dec, remain = OERcodec_STRING.do_dec(got, size_len=fixed_size or 0)
        assert remain == b"" and dec.val == data

    bit_spec = _compile("A ::= BIT STRING")
    for (data, nbits), bitstr in BIT_STRING_VECTORS:
        expected = bit_spec.encode("A", (data, nbits))
        got = OERcodec_BIT_STRING.enc(bitstr)
        assert got == expected
        dec, remain = OERcodec_BIT_STRING.do_dec(got)
        assert remain == b"" and dec.val == bitstr

    return True


def check_asn1tools_decode_scapy_encode():
    # type: () -> bool
    """Encode with Scapy, decode with asn1tools."""
    if not HAS_ASN1TOOLS:
        return True

    compiled = asn1tools.compile_string(ASN1TOOLS_INTEGER_SPEC, "oer")
    samples = [("A", 42), ("F", 200), ("B", -99)]
    for type_name, value in samples:
        encoded = {
            "A": OERcodec_INTEGER.enc,
            "F": lambda v: OERcodec_INTEGER.enc(v, size_len=1),
            "B": lambda v: OERcodec_INTEGER.enc(v, size_len=1),
        }[type_name](value)
        decoded = compiled.decode(type_name, encoded)
        assert decoded == value

    bool_spec = _compile("A ::= BOOLEAN")
    for val in [0, 1]:
        encoded = OERcodec_BOOLEAN.enc(val)
        assert bool_spec.decode("A", encoded) == bool(val)

    return True
