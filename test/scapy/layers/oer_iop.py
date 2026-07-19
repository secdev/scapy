# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
OER interoperability helpers.

Cross-check Scapy's OER codec against reference encodings (from asn1tools).
Reference vectors are taken from asn1tools/tests/test_oer.py.
"""

from scapy.contrib.oer import (
    OERcodec_BIT_STRING,
    OERcodec_BOOLEAN,
    OERcodec_ENUMERATED,
    OERcodec_INTEGER,
    OERcodec_NULL,
    OERcodec_OID,
    OERcodec_STRING,
    OER_signed_integer_enc,
    OER_unsigned_integer_enc,
)

# (type name, value, scapy encoder callable, reference encoding)
INTEGER_VECTORS = [
    ("A", 0, lambda v: OERcodec_INTEGER.enc(v), b"\x01\x00"),
    ("A", 128, lambda v: OERcodec_INTEGER.enc(v), b"\x02\x00\x80"),
    ("A", 100000, lambda v: OERcodec_INTEGER.enc(v), b"\x03\x01\x86\xa0"),
    ("A", -255, lambda v: OERcodec_INTEGER.enc(v), b"\x02\xff\x01"),
    ("A", -1234567, lambda v: OERcodec_INTEGER.enc(v), b"\x03\xed)y"),
    ("B", -2, lambda v: OERcodec_INTEGER.enc(v, size_len=1), b"\xfe"),
    ("C", -2, lambda v: OERcodec_INTEGER.enc(v, size_len=2), b"\xff\xfe"),
    ("D", -2, lambda v: OERcodec_INTEGER.enc(v, size_len=4), b"\xff\xff\xff\xfe"),
    (
        "E",
        -2,
        lambda v: OERcodec_INTEGER.enc(v, size_len=8),
        b"\xff\xff\xff\xff\xff\xff\xff\xfe",
    ),
    ("F", 128, lambda v: OERcodec_INTEGER.enc(v, size_len=1), b"\x80"),
    ("G", 128, lambda v: OERcodec_INTEGER.enc(v, size_len=2), b"\x00\x80"),
    ("G", 1000, lambda v: OERcodec_INTEGER.enc(v, size_len=2), b"\x03\xe8"),
    ("H", 128, lambda v: OERcodec_INTEGER.enc(v, size_len=4), b"\x00\x00\x00\x80"),
    (
        "I",
        128,
        lambda v: OERcodec_INTEGER.enc(v, size_len=8),
        b"\x00\x00\x00\x00\x00\x00\x00\x80",
    ),
    ("B", 1, lambda v: OERcodec_INTEGER.enc(v, size_len=1), b"\x01"),
    ("K", 1, lambda v: OER_unsigned_integer_enc(v), b"\x01\x01"),
    ("K", 128, lambda v: OER_unsigned_integer_enc(v), b"\x01\x80"),
    ("L", -128, lambda v: OER_signed_integer_enc(v), b"\x01\x80"),
]

BOOLEAN_VECTORS = [
    (True, lambda v: OERcodec_BOOLEAN.enc(1 if v else 0), b"\xff"),
    (False, lambda v: OERcodec_BOOLEAN.enc(1 if v else 0), b"\x00"),
]

ENUMERATED_VECTORS = [
    ("A", "a", 1, b"\x01"),
    ("B", "a", 128, b"\x82\x00\x80"),
    ("C", "a", 0, b"\x00"),
    ("C", "b", 127, b"\x7f"),
    ("E", "a", -1, b"\x81\xff"),
]

OID_VECTORS = [
    ("1.2", lambda v: OERcodec_OID.enc(v), b"\x01*"),
    ("1.2.3321", lambda v: OERcodec_OID.enc(v), b"\x03*\x99y"),
]

OCTET_STRING_VECTORS = [
    (b"\x12\x34", 0, b"\x02\x124"),
    (b"\x12\x34\x56", 3, b"\x124V"),
]

BIT_STRING_VECTORS = [
    ("0100", b"\x02\x04@"),
    ("01000001", b"\x02\x00A"),
]

# (type name, value, reference encoding)
SCAPY_DECODE_VECTORS = [
    ("A", 42, b"\x01*"),
    ("F", 200, b"\xc8"),
    ("B", -99, b"\x9d"),
]


def check_primitive_interop():
    # type: () -> bool
    """Compare Scapy OER primitives against reference encodings."""
    for type_name, value, enc, expected in INTEGER_VECTORS:
        got = enc(value)
        assert got == expected, (
            "integer %s=%r: reference=%r scapy=%r" %
            (type_name, value, expected, got)
        )
        if type_name == "A":
            dec, remain = OERcodec_INTEGER.do_dec(got)
            assert remain == b"" and dec.val == value

    for value, enc, expected in BOOLEAN_VECTORS:
        got = enc(value)
        assert got == expected
        dec, remain = OERcodec_BOOLEAN.do_dec(got)
        assert remain == b"" and dec.val == (1 if value else 0)

    got = OERcodec_NULL.enc(None)
    assert got == b""

    for type_name, _enum_name, enum_val, expected in ENUMERATED_VECTORS:
        got = OERcodec_ENUMERATED.enc(enum_val)
        assert got == expected
        dec, remain = OERcodec_ENUMERATED.do_dec(got)
        assert remain == b"" and dec.val == enum_val

    for oid, enc, expected in OID_VECTORS:
        got = enc(oid)
        assert got == expected
        dec, remain = OERcodec_OID.do_dec(got)
        assert remain == b"" and dec.val == oid

    for data, fixed_size, expected in OCTET_STRING_VECTORS:
        got = OERcodec_STRING.enc(data, size_len=fixed_size or 0)
        assert got == expected
        dec, remain = OERcodec_STRING.do_dec(got, size_len=fixed_size or 0)
        assert remain == b"" and dec.val == data

    for bitstr, expected in BIT_STRING_VECTORS:
        got = OERcodec_BIT_STRING.enc(bitstr)
        assert got == expected
        dec, remain = OERcodec_BIT_STRING.do_dec(got)
        assert remain == b"" and dec.val == bitstr

    return True


def check_scapy_encode_reference_decode():
    # type: () -> bool
    """Decode reference encodings with Scapy."""
    for type_name, value, encoded in SCAPY_DECODE_VECTORS:
        if type_name == "A":
            dec, remain = OERcodec_INTEGER.do_dec(encoded)
        elif type_name == "F":
            dec, remain = OERcodec_INTEGER.do_dec(
                encoded, size_len=1, oer_unsigned=True,
            )
        else:
            dec, remain = OERcodec_INTEGER.do_dec(encoded, size_len=1)
        assert remain == b"" and dec.val == value

    for val in [0, 1]:
        encoded = OERcodec_BOOLEAN.enc(val)
        dec, remain = OERcodec_BOOLEAN.do_dec(encoded)
        assert remain == b"" and dec.val == val

    return True
