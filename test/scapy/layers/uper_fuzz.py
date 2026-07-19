# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
UPER fuzzing helpers.

Exercise UPER encode/decode paths with packet.fuzz() and random payloads.
"""

import os
import random
from typing import Iterable, Type

from scapy.asn1.asn1 import ASN1_Codecs, ASN1_Decoding_Error, ASN1_Error
from scapy.contrib.uper import (
    UPER_Decoding_Error,
    UPER_Encoding_Error,
    UPERcodec_BIT_STRING,
    UPERcodec_BOOLEAN,
    UPERcodec_ENUMERATED,
    UPERcodec_INTEGER,
    UPERcodec_NULL,
    UPERcodec_OID,
    UPERcodec_STRING,
)
from scapy.asn1fields import (
    ASN1F_BOOLEAN,
    ASN1F_ENUMERATED,
    ASN1F_INTEGER,
    ASN1F_SEQUENCE,
    ASN1F_SEQUENCE_OF,
    ASN1F_STRING,
    ASN1F_optional,
)
from scapy.asn1packet import ASN1_Packet
from scapy.packet import fuzz, raw

_UPER_CODEC_CLASSES = (
    UPERcodec_INTEGER,
    UPERcodec_BOOLEAN,
    UPERcodec_NULL,
    UPERcodec_STRING,
    UPERcodec_OID,
    UPERcodec_ENUMERATED,
    UPERcodec_BIT_STRING,
)

_DECODE_ERRORS = (
    UPER_Decoding_Error,
    UPER_Encoding_Error,
    ASN1_Decoding_Error,
    ASN1_Error,
    ValueError,
    IndexError,
)


class UPERFuzzRecord(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_BOOLEAN("flag", False),
        ASN1F_STRING("label", ""),
        ASN1F_optional(ASN1F_INTEGER("extra", 0)),
        ASN1F_SEQUENCE_OF("values", [], ASN1F_INTEGER),
    )


class UPERFuzzNested(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("id", 0),
        ASN1F_SEQUENCE(
            ASN1F_INTEGER("x", 0),
            ASN1F_BOOLEAN("y", False),
        ),
    )


class UPERFuzzEnumerated(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.PER
    ASN1_root = ASN1F_ENUMERATED(
        "state", 1, {1: "alpha", 200: "beta"},
    )


def _fuzz_packets():
    # type: () -> Iterable[Type[ASN1_Packet]]
    return (UPERFuzzRecord, UPERFuzzNested, UPERFuzzEnumerated)


def check_uper_fuzz_encode(iterations=25):
    # type: (int) -> None
    for cls in _fuzz_packets():
        for _ in range(iterations):
            try:
                data = raw(fuzz(cls()))
            except _DECODE_ERRORS:
                continue
            assert isinstance(data, bytes)


def check_uper_fuzz_roundtrip(iterations=25):
    # type: (int) -> None
    for cls in _fuzz_packets():
        for _ in range(iterations):
            try:
                cls(raw(fuzz(cls())))
            except _DECODE_ERRORS:
                pass


def check_uper_fuzz_codec_decode(iterations=100):
    # type: (int) -> None
    for codec in _UPER_CODEC_CLASSES:
        for _ in range(iterations):
            data = os.urandom(random.randint(0, 64))
            try:
                codec.safedec(data)
            except _DECODE_ERRORS:
                pass


def check_uper_fuzz_packet_decode(iterations=100):
    # type: (int) -> None
    for cls in _fuzz_packets():
        for _ in range(iterations):
            data = os.urandom(random.randint(0, 128))
            try:
                cls(data)
            except _DECODE_ERRORS:
                pass
