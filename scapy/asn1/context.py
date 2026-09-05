# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""ASN.1 encoder and decoder contexts."""

from typing import Any

from scapy.asn1.asn1 import ASN1_Codecs
from scapy.asn1.compound_ber import (
    ber_sequence_encode_to, ber_sequence_decode_from,
    ber_sequence_of_encode_to, ber_sequence_of_decode_from,
    ber_choice_encode_to, ber_choice_decode_from,
    ber_packet_encode_to, ber_packet_decode_from,
)
from scapy.asn1.compound_oer import (
    oer_sequence_encode_to, oer_sequence_decode_from,
    oer_sequence_of_encode_to, oer_sequence_of_decode_from,
    oer_choice_encode_to, oer_choice_decode_from,
)
from scapy.asn1.compound_uper import (
    uper_sequence_encode_to, uper_sequence_decode_from,
    uper_sequence_of_encode_to, uper_sequence_of_decode_from,
    uper_choice_encode_to, uper_choice_decode_from,
    uper_packet_encode_to, uper_packet_decode_from,
)


class ASN1Encoder(object):
    codec = None  # type: Any

    def finish(self):
        # type: () -> bytes
        raise NotImplementedError


class ASN1Decoder(object):
    codec = None  # type: Any

    def remaining(self):
        # type: () -> bytes
        raise NotImplementedError


class BER_Encoder(ASN1Encoder):
    codec = ASN1_Codecs.BER
    encode_sequence = ber_sequence_encode_to
    encode_sequence_of = ber_sequence_of_encode_to
    encode_choice = ber_choice_encode_to
    encode_packet = ber_packet_encode_to

    def __init__(self, codec=None):
        # type: (Any) -> None
        self.codec = codec or self.codec
        self._parts = []  # type: list[bytes]

    def write(self, data):
        # type: (bytes) -> None
        self._parts.append(data)

    def finish(self):
        # type: () -> bytes
        return b"".join(self._parts)


class BER_Decoder(ASN1Decoder):
    codec = ASN1_Codecs.BER
    decode_sequence = ber_sequence_decode_from
    decode_sequence_of = ber_sequence_of_decode_from
    decode_choice = ber_choice_decode_from
    decode_packet = ber_packet_decode_from

    def __init__(self, data, codec=None):
        # type: (bytes, Any) -> None
        self.codec = codec or self.codec
        self._data = data

    def remaining(self):
        # type: () -> bytes
        return self._data

    def set_remainder(self, remainder):
        # type: (bytes) -> None
        self._data = remainder


class OER_Encoder(BER_Encoder):
    codec = ASN1_Codecs.OER
    encode_sequence = oer_sequence_encode_to
    encode_sequence_of = oer_sequence_of_encode_to
    encode_choice = oer_choice_encode_to


class OER_Decoder(BER_Decoder):
    codec = ASN1_Codecs.OER
    decode_sequence = oer_sequence_decode_from
    decode_sequence_of = oer_sequence_of_decode_from
    decode_choice = oer_choice_decode_from


class UPER_EncoderContext(ASN1Encoder):
    codec = ASN1_Codecs.PER
    encode_sequence = uper_sequence_encode_to
    encode_sequence_of = uper_sequence_of_encode_to
    encode_choice = uper_choice_encode_to
    encode_packet = uper_packet_encode_to

    def __init__(self):
        # type: () -> None
        # Lazy: keep BER/OER paths from importing scapy.asn1.uper.
        from scapy.asn1.uper import UPER_Encoder
        self.bit_encoder = UPER_Encoder()

    def finish(self):
        # type: () -> bytes
        return self.bit_encoder.as_bytes()


class UPER_DecoderContext(ASN1Decoder):
    codec = ASN1_Codecs.PER
    decode_sequence = uper_sequence_decode_from
    decode_sequence_of = uper_sequence_of_decode_from
    decode_choice = uper_choice_decode_from
    decode_packet = uper_packet_decode_from

    def __init__(self, data):
        # type: (bytes) -> None
        from scapy.asn1.uper import UPER_Decoder
        self.bit_decoder = UPER_Decoder(data)

    def remaining(self):
        # type: () -> bytes
        return self.bit_decoder.remaining_bytes()


def new_encoder(codec):
    # type: (Any) -> ASN1Encoder
    if codec is ASN1_Codecs.PER:
        return UPER_EncoderContext()
    if codec is ASN1_Codecs.OER:
        return OER_Encoder()
    return BER_Encoder(codec=codec)


def new_decoder(codec, data):
    # type: (Any, bytes) -> ASN1Decoder
    if codec is ASN1_Codecs.PER:
        return UPER_DecoderContext(data)
    if codec is ASN1_Codecs.OER:
        return OER_Decoder(data)
    return BER_Decoder(data, codec=codec)
