# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""ASN.1 encoder and decoder contexts."""

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.asn1.uper import UPER_Decoder as _UPER_Decoder
    from scapy.asn1.uper import UPER_Encoder as _UPER_Encoder


class ASN1Encoder(object):
    codec = None  # type: Any

    def finish(self):
        # type: () -> bytes
        raise NotImplementedError

    def encode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import ber_sequence_encode_to
        ber_sequence_encode_to(field, pkt, self)

    def encode_sequence_of(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import ber_sequence_of_encode_to
        ber_sequence_of_encode_to(field, pkt, self)

    def encode_choice(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        from scapy.asn1.compound import ber_choice_encode_to
        ber_choice_encode_to(field, pkt, self, value)

    def encode_packet(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        from scapy.asn1.compound import ber_packet_encode_to
        ber_packet_encode_to(field, pkt, self, value)


class ASN1Decoder(object):
    codec = None  # type: Any

    def remaining(self):
        # type: () -> bytes
        raise NotImplementedError

    def set_remainder(self, remainder):
        # type: (bytes) -> None
        raise NotImplementedError

    def decode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import ber_sequence_decode_from
        ber_sequence_decode_from(field, pkt, self)

    def decode_sequence_of(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import ber_sequence_of_decode_from
        ber_sequence_of_decode_from(field, pkt, self)

    def decode_choice(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import ber_choice_decode_from
        ber_choice_decode_from(field, pkt, self)

    def decode_packet(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import ber_packet_decode_from
        ber_packet_decode_from(field, pkt, self)


class BER_Encoder(ASN1Encoder):
    from scapy.asn1.asn1 import ASN1_Codecs

    def __init__(self, codec=None):
        # type: (Any) -> None
        from scapy.asn1.asn1 import ASN1_Codecs
        self.codec = codec or ASN1_Codecs.BER
        self._parts = []  # type: list[bytes]

    def write(self, data):
        # type: (bytes) -> None
        self._parts.append(data)

    def finish(self):
        # type: () -> bytes
        return b"".join(self._parts)


class BER_Decoder(ASN1Decoder):
    from scapy.asn1.asn1 import ASN1_Codecs

    def __init__(self, data, codec=None):
        # type: (bytes, Any) -> None
        from scapy.asn1.asn1 import ASN1_Codecs
        self.codec = codec or ASN1_Codecs.BER
        self._data = data
        self._offset = 0

    def remaining(self):
        # type: () -> bytes
        return self._data[self._offset:]

    def set_remainder(self, remainder):
        # type: (bytes) -> None
        self._data = remainder
        self._offset = 0


class OER_Encoder(BER_Encoder):
    from scapy.asn1.asn1 import ASN1_Codecs

    codec = ASN1_Codecs.OER

    def __init__(self):
        # type: () -> None
        super(OER_Encoder, self).__init__(codec=self.codec)

    def encode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import oer_sequence_encode_to
        oer_sequence_encode_to(field, pkt, self)

    def encode_sequence_of(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import oer_sequence_of_encode_to
        oer_sequence_of_encode_to(field, pkt, self)

    def encode_choice(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        from scapy.asn1.compound import oer_choice_encode_to
        oer_choice_encode_to(field, pkt, self, value)

    def encode_packet(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        from scapy.asn1.compound import oer_packet_encode_to
        oer_packet_encode_to(field, pkt, self, value)


class OER_Decoder(BER_Decoder):
    from scapy.asn1.asn1 import ASN1_Codecs

    codec = ASN1_Codecs.OER

    def __init__(self, data):
        # type: (bytes) -> None
        super(OER_Decoder, self).__init__(data, codec=self.codec)

    def decode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import oer_sequence_decode_from
        oer_sequence_decode_from(field, pkt, self)

    def decode_sequence_of(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import oer_sequence_of_decode_from
        oer_sequence_of_decode_from(field, pkt, self)

    def decode_choice(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import oer_choice_decode_from
        oer_choice_decode_from(field, pkt, self)

    def decode_packet(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import oer_packet_decode_from
        oer_packet_decode_from(field, pkt, self)


class UPER_EncoderContext(ASN1Encoder):
    from scapy.asn1.asn1 import ASN1_Codecs

    codec = ASN1_Codecs.PER

    def __init__(self):
        # type: () -> None
        from scapy.asn1.uper import UPER_Encoder
        self._enc = UPER_Encoder()

    @property
    def bit_encoder(self):
        # type: () -> _UPER_Encoder
        return self._enc

    def finish(self):
        # type: () -> bytes
        return self._enc.as_bytes()

    def encode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import uper_sequence_encode_to
        uper_sequence_encode_to(field, pkt, self)

    def encode_sequence_of(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import uper_sequence_of_encode_to
        uper_sequence_of_encode_to(field, pkt, self)

    def encode_choice(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        from scapy.asn1.compound import uper_choice_encode_to
        uper_choice_encode_to(field, pkt, self, value)

    def encode_packet(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        from scapy.asn1.compound import uper_packet_encode_to
        uper_packet_encode_to(field, pkt, self, value)


class UPER_DecoderContext(ASN1Decoder):
    from scapy.asn1.asn1 import ASN1_Codecs

    codec = ASN1_Codecs.PER

    def __init__(self, data):
        # type: (bytes) -> None
        from scapy.asn1.uper import UPER_Decoder
        self._dec = UPER_Decoder(data)

    @property
    def bit_decoder(self):
        # type: () -> _UPER_Decoder
        return self._dec

    def remaining(self):
        # type: () -> bytes
        return self._dec.remaining_bytes()

    def set_remainder(self, remainder):
        # type: (bytes) -> None
        from scapy.asn1.uper import UPER_Decoder
        self._dec = UPER_Decoder(remainder)

    def decode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import uper_sequence_decode_from
        uper_sequence_decode_from(field, pkt, self)

    def decode_sequence_of(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import uper_sequence_of_decode_from
        uper_sequence_of_decode_from(field, pkt, self)

    def decode_choice(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import uper_choice_decode_from
        uper_choice_decode_from(field, pkt, self)

    def decode_packet(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.compound import uper_packet_decode_from
        uper_packet_decode_from(field, pkt, self)


def new_encoder(codec):
    # type: (Any) -> ASN1Encoder
    from scapy.asn1.asn1 import ASN1_Codecs
    if codec is ASN1_Codecs.PER:
        return UPER_EncoderContext()
    if codec is ASN1_Codecs.OER:
        return OER_Encoder()
    return BER_Encoder(codec=codec)


def new_decoder(codec, data):
    # type: (Any, bytes) -> ASN1Decoder
    from scapy.asn1.asn1 import ASN1_Codecs
    if codec is ASN1_Codecs.PER:
        return UPER_DecoderContext(data)
    if codec is ASN1_Codecs.OER:
        return OER_Decoder(data)
    return BER_Decoder(data, codec=codec)


def per_bit_encoder(enc):
    # type: (Any) -> Any
    """Return the PER bit encoder, or *None* for byte-oriented contexts.

    Prefer ``enc.bit_encoder`` on ``UPER_EncoderContext``. The
    ``isinstance(UPER_Encoder)`` check is only a nested codec-internal
    fallback so call sites that already hold a bare bit stream keep
    working.
    """
    from scapy.asn1.asn1 import ASN1_Codecs
    codec = getattr(enc, "codec", None)
    if codec is not None and codec is not ASN1_Codecs.PER:
        return None
    bit_enc = getattr(enc, "bit_encoder", None)
    if bit_enc is not None:
        return bit_enc
    from scapy.asn1.uper import UPER_Encoder
    if isinstance(enc, UPER_Encoder):
        return enc
    return None


def per_bit_decoder(dec):
    # type: (Any) -> Any
    """Return the PER bit decoder, or *None* for byte-oriented contexts.

    Prefer ``dec.bit_decoder`` on ``UPER_DecoderContext``. The
    ``isinstance(UPER_Decoder)`` check is only a nested codec-internal
    fallback so call sites that already hold a bare bit stream keep
    working.
    """
    from scapy.asn1.asn1 import ASN1_Codecs
    codec = getattr(dec, "codec", None)
    if codec is not None and codec is not ASN1_Codecs.PER:
        return None
    bit_dec = getattr(dec, "bit_decoder", None)
    if bit_dec is not None:
        return bit_dec
    from scapy.asn1.uper import UPER_Decoder
    if isinstance(dec, UPER_Decoder):
        return dec
    return None
