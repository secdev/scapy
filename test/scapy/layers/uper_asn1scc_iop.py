# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
UPER interoperability vectors from ESA asn1scc test cases.

asn1scc (https://github.com/esa/asn1scc) primarily validates C/Ada code generation
with ACN custom encodings. Portable uPER vectors are taken from v4Tests where
``--TCLS MyPDU[]`` selects standard uPER (empty ACN = default PER).

Cases that need REAL, explicit APPLICATION tags, or ACN overrides are not
compared against Scapy encoders here (or are asn1tools reference only).
"""

from typing import Any, List, Tuple

try:
    import asn1tools
    HAS_ASN1TOOLS = True
except ImportError:
    asn1tools = None  # type: ignore
    HAS_ASN1TOOLS = False

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

# asn1scc README.md sample.asn (REAL field; asn1tools reference only)
README_MESSAGE_SPEC = (
    "Sample DEFINITIONS AUTOMATIC TAGS ::= BEGIN "
    "Message ::= SEQUENCE { "
    "msgId INTEGER, "
    "myflag INTEGER, "
    "value REAL, "
    "szDescription OCTET STRING (SIZE(10)), "
    "isReady BOOLEAN "
    "} "
    "END"
)

README_MESSAGE_HEX = (
    "010101020980cd191eb851eb851f48656c6c6f576f726c6480"
)

README_MESSAGE_PREFIX_SPEC = (
    "Sample DEFINITIONS AUTOMATIC TAGS ::= BEGIN "
    "MessagePrefix ::= SEQUENCE { "
    "msgId INTEGER, "
    "myflag INTEGER, "
    "szDescription OCTET STRING (SIZE(10)), "
    "isReady BOOLEAN "
    "} "
    "END"
)

README_MESSAGE_PREFIX_HEX = (
    "0101010248656c6c6f576f726c6480"
)

ASN1SCC_VECTORS = [
    (
        "05-BOOLEAN/001 pdu1",
        BOOLEAN_SPEC,
        "MyPDU",
        True,
        lambda _v: UPERcodec_BOOLEAN.enc(1),
    ),
    (
        "18-NULL/001 pdu1",
        NULL_SPEC,
        "MyPDU",
        None,
        lambda _v: UPERcodec_NULL.enc(None),
    ),
    (
        "06-OCTET-STRING/001 pdu1",
        OCTET_STRING_VAR_SPEC,
        "MyPDU",
        bytes.fromhex("afbc4583"),
        lambda v: UPERcodec_STRING.enc(v, uper_min=1, uper_max=20),
    ),
    (
        "05-BOOLEAN/001 pdu1 false",
        BOOLEAN_SPEC,
        "MyPDU",
        False,
        lambda _v: UPERcodec_BOOLEAN.enc(0),
    ),
    (
        "04-ENUMERATED/001 pdu1 alpha",
        ENUMERATED_SPEC,
        "MyPDU",
        "alpha",
        lambda _v: UPERcodec_ENUMERATED.enc(
            1, uper_enum_values=[1, 200],
        ),
    ),
    (
        "04-ENUMERATED/001 pdu1 beta",
        ENUMERATED_SPEC,
        "MyPDU",
        "beta",
        lambda _v: UPERcodec_ENUMERATED.enc(
            200, uper_enum_values=[1, 200],
        ),
    ),
    (
        "09-CHOICE/001 pdu1 int1:10",
        CHOICE_SPEC,
        "MyPDU",
        ("int1", 10),
        lambda _v: _encode_choice_int1_10(),
    ),
    (
        "08-BIT-STRING/001 pdu1 ABCD",
        BIT_STRING_VAR_SPEC,
        "MyPDU",
        (bytes.fromhex("abcd"), 16),
        lambda _v: UPERcodec_BIT_STRING.enc(
            (bytes.fromhex("abcd"), 16), uper_min=1, uper_max=20,
        ),
    ),
]


def require_asn1tools():
    # type: () -> bool
    return HAS_ASN1TOOLS


def _encode_choice_int1_10():
    # type: () -> bytes
    enc = UPER_Encoder()
    UPER_choice_index_enc(0, 5, enc=enc)
    UPERcodec_INTEGER.encode_into(enc, 10, uper_min=0, uper_max=15)
    return enc.as_bytes()


def check_asn1scc_vectors():
    # type: () -> None
    if not HAS_ASN1TOOLS:
        raise RuntimeError("asn1tools is not installed")
    for name, spec, pdu, value, encoder in ASN1SCC_VECTORS:
        foo = asn1tools.compile_string(spec, "uper")
        expected = foo.encode(pdu, value)
        got = encoder(value)
        assert got == expected, (
            "%s: expected %s, got %s" %
            (name, expected.hex(), got.hex())
        )


def check_asn1scc_readme_message_prefix():
    # type: () -> None
    """README sample without REAL; Scapy packet roundtrip vs asn1tools."""
    if not HAS_ASN1TOOLS:
        raise RuntimeError("asn1tools is not installed")
    from test.scapy.layers.uper_packets import UPERMessagePrefix
    from scapy.packet import raw

    foo = asn1tools.compile_string(README_MESSAGE_PREFIX_SPEC, "uper")
    value = {
        "msgId": 1,
        "myflag": 2,
        "szDescription": b"HelloWorld",
        "isReady": True,
    }
    expected = foo.encode("MessagePrefix", value)
    assert expected.hex() == README_MESSAGE_PREFIX_HEX

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
    if not HAS_ASN1TOOLS:
        raise RuntimeError("asn1tools is not installed")
    foo = asn1tools.compile_string(README_MESSAGE_SPEC, "uper")
    value = {
        "msgId": 1,
        "myflag": 2,
        "value": 3.14,
        "szDescription": b"HelloWorld",
        "isReady": True,
    }
    got = foo.encode("Message", value)
    assert got.hex() == README_MESSAGE_HEX
