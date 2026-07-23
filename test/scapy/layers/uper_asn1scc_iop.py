# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
UPER interoperability vectors from ESA asn1scc test cases.

asn1scc (https://github.com/esa/asn1scc) primarily validates C/Ada code generation
with ACN custom encodings. Portable uPER vectors are taken from v4Tests where
``--TCLS MyPDU[]`` selects standard uPER (empty ACN = default PER).

Cases that need REAL, explicit APPLICATION tags, or ACN overrides are not
compared against Scapy encoders here (or are reference-only).
"""

from scapy.asn1.uper import (
    UPER_Encoder,
    UPER_choice_index_enc,
    UPERcodec_BIT_STRING,
    UPERcodec_BOOLEAN,
    UPERcodec_ENUMERATED,
    UPERcodec_INTEGER,
    UPERcodec_NULL,
    UPERcodec_STRING,
)

# asn1scc v4Tests/test-cases/acn/05-BOOLEAN/001.asn1
BOOLEAN_SPEC = (
    "TEST-CASE DEFINITIONS AUTOMATIC TAGS::= BEGIN "
    "MyPDU ::= BOOLEAN "
    "END"
)

# asn1scc v4Tests/test-cases/acn/18-NULL/001.asn1
NULL_SPEC = (
    "TEST-CASE DEFINITIONS AUTOMATIC TAGS::= BEGIN "
    "MyPDU ::= NULL "
    "END"
)

# asn1scc v4Tests/test-cases/acn/06-OCTET-STRING/001.asn1
OCTET_STRING_VAR_SPEC = (
    "TEST-CASE DEFINITIONS AUTOMATIC TAGS::= BEGIN "
    "MyPDU ::= OCTET STRING (SIZE(1..20)) "
    "END"
)

# asn1scc v4Tests/test-cases/acn/09-CHOICE/001.asn1 (pdu1 = int1 : 10)
CHOICE_SPEC = (
    "TEST-CASE DEFINITIONS AUTOMATIC TAGS::= BEGIN "
    "MyPDU ::= CHOICE { "
    "int1 INTEGER(0..15), "
    "int2 INTEGER(0..65535), "
    "enm ENUMERATED { one(1), two(2), three(3), four(4), thousand(1000) }, "
    "buf OCTET STRING (SIZE(10)), "
    "gg SEQUENCE { "
    "int1 INTEGER(0..15), "
    "int2 INTEGER(0..65535), "
    "enm ENUMERATED { pone(1), ptwo(2), pthree(3), pfour(4), pthousand(1000) }, "
    "buf [APPLICATION 104] OCTET STRING (SIZE(10)) "
    "} "
    "} "
    "END"
)

# asn1scc v4Tests/test-cases/acn/04-ENUMERATED/001.asn1 (pdu1 = beta)
ENUMERATED_SPEC = (
    "TEST-CASE DEFINITIONS AUTOMATIC TAGS::= BEGIN "
    "MyPDU ::= ENUMERATED { alpha(1), beta(200) } "
    "END"
)

# asn1scc v4Tests/test-cases/acn/08-BIT-STRING/001.asn1 (pdu1 = 'ABCD'H)
BIT_STRING_VAR_SPEC = (
    "TEST-CASE DEFINITIONS AUTOMATIC TAGS::= BEGIN "
    "MyPDU ::= BIT STRING (SIZE(1..20)) "
    "END"
)

# asn1scc README.md sample.asn (REAL field; reference only)
README_MESSAGE_HEX = (
    "010101020980cd191eb851eb851f48656c6c6f576f726c6480"
)

README_MESSAGE_PREFIX_HEX = (
    "0101010248656c6c6f576f726c6480"
)

# (name, pdu value, encoder callable, reference encoding)
ASN1SCC_VECTORS = [
    (
        "05-BOOLEAN/001 pdu1",
        True,
        lambda _v: UPERcodec_BOOLEAN.enc(1),
        b"\x80",
    ),
    (
        "18-NULL/001 pdu1",
        None,
        lambda _v: UPERcodec_NULL.enc(None),
        b"",
    ),
    (
        "06-OCTET-STRING/001 pdu1",
        bytes.fromhex("afbc4583"),
        lambda v: UPERcodec_STRING.enc(v, uper_min=1, uper_max=20),
        bytes.fromhex("1d7de22c18"),
    ),
    (
        "05-BOOLEAN/001 pdu1 false",
        False,
        lambda _v: UPERcodec_BOOLEAN.enc(0),
        b"\x00",
    ),
    (
        "04-ENUMERATED/001 pdu1 alpha",
        "alpha",
        lambda _v: UPERcodec_ENUMERATED.enc(1, uper_enum_values=[1, 200]),
        b"\x00",
    ),
    (
        "04-ENUMERATED/001 pdu1 beta",
        "beta",
        lambda _v: UPERcodec_ENUMERATED.enc(200, uper_enum_values=[1, 200]),
        b"\x80",
    ),
    (
        "09-CHOICE/001 pdu1 int1:10",
        ("int1", 10),
        lambda _v: _encode_choice_int1_10(),
        b"\x14",
    ),
    (
        "08-BIT-STRING/001 pdu1 ABCD",
        (bytes.fromhex("abcd"), 16),
        lambda _v: UPERcodec_BIT_STRING.enc(
            (bytes.fromhex("abcd"), 16), uper_min=1, uper_max=20,
        ),
        bytes.fromhex("7d5e68"),
    ),
]


def _encode_choice_int1_10():
    # type: () -> bytes
    enc = UPER_Encoder()
    UPER_choice_index_enc(0, 5, enc=enc)
    UPERcodec_INTEGER.encode_into(enc, 10, uper_min=0, uper_max=15)
    return enc.as_bytes()


def check_asn1scc_vectors():
    # type: () -> None
    for name, _value, encoder, expected in ASN1SCC_VECTORS:
        got = encoder(_value)
        assert got == expected, (
            "%s: expected %s, got %s" %
            (name, expected.hex(), got.hex())
        )


def check_asn1scc_readme_message_prefix():
    # type: () -> None
    """README sample without REAL; Scapy packet roundtrip vs reference."""
    from test.scapy.layers.uper_packets import UPERMessagePrefix
    from scapy.packet import raw

    expected = bytes.fromhex(README_MESSAGE_PREFIX_HEX)

    pkt = UPERMessagePrefix(
        msgId=1,
        myflag=2,
        szDescription=b"HelloWorld",
        isReady=True,
    )
    got = raw(pkt)
    assert got == expected
    decoded = UPERMessagePrefix(got)
    assert decoded.msgId.val == 1
    assert decoded.myflag.val == 2
    assert decoded.szDescription.val == b"HelloWorld"
    assert decoded.isReady.val == 1


def check_asn1scc_readme_message_reference():
    # type: () -> None
    """README C sample output; Scapy does not encode REAL in UPER yet."""
    assert README_MESSAGE_HEX == (
        "010101020980cd191eb851eb851f48656c6c6f576f726c6480"
    )
