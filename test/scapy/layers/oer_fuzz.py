# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
OER fuzzing helpers.

Exercise OER encode/decode paths with packet.fuzz() and random payloads.
"""

import os
import random
from typing import Iterable, Type

from scapy.asn1.asn1 import ASN1_Codecs, ASN1_Decoding_Error, ASN1_Error
from scapy.contrib.oer import (
    OER_Decoding_Error,
    OERcodec_BIT_STRING,
    OERcodec_BOOLEAN,
    OERcodec_ENUMERATED,
    OERcodec_INTEGER,
    OERcodec_NULL,
    OERcodec_OID,
    OERcodec_STRING,
)
from scapy.asn1fields import (
    ASN1F_BOOLEAN,
    ASN1F_INTEGER,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
    ASN1F_STRING,
    ASN1F_optional,
)
from scapy.asn1packet import ASN1_Packet
from scapy.packet import fuzz, raw

_OER_CODEC_CLASSES = (
    OERcodec_INTEGER,
    OERcodec_BOOLEAN,
    OERcodec_NULL,
    OERcodec_STRING,
    OERcodec_OID,
    OERcodec_ENUMERATED,
    OERcodec_BIT_STRING,
)

_DECODE_ERRORS = (
    OER_Decoding_Error,
    ASN1_Decoding_Error,
    ASN1_Error,
    ValueError,
    IndexError,
)


class OERFuzzRecord(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.OER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_BOOLEAN("flag", False),
        ASN1F_STRING("label", ""),
        ASN1F_optional(ASN1F_INTEGER("extra", 0, explicit_tag=0xA0)),
        ASN1F_SEQUENCE_OF("values", [], ASN1F_INTEGER),
    )


def _fuzz_packets():
    # type: () -> Iterable[Type[ASN1_Packet]]
    return (OERFuzzRecord,)


def check_oer_fuzz_encode(iterations=25):
    # type: (int) -> None
    for cls in _fuzz_packets():
        for _ in range(iterations):
            data = raw(fuzz(cls()))
            assert isinstance(data, bytes)


def check_oer_fuzz_roundtrip(iterations=25):
    # type: (int) -> None
    for cls in _fuzz_packets():
        for _ in range(iterations):
            cls(raw(fuzz(cls())))


def check_oer_fuzz_codec_decode(iterations=100):
    # type: (int) -> None
    for codec in _OER_CODEC_CLASSES:
        for _ in range(iterations):
            data = os.urandom(random.randint(0, 64))
            try:
                codec.safedec(data)
            except _DECODE_ERRORS:
                pass


def check_oer_fuzz_packet_decode(iterations=100):
    # type: (int) -> None
    for cls in _fuzz_packets():
        for _ in range(iterations):
            data = os.urandom(random.randint(0, 128))
            try:
                cls(data)
            except _DECODE_ERRORS:
                pass
