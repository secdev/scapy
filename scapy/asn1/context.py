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


class ASN1Decoder(object):
    codec = None  # type: Any

    def remaining(self):
        # type: () -> bytes
        raise NotImplementedError

    def set_remainder(self, remainder):
        # type: (bytes) -> None
        raise NotImplementedError


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

    def read_all(self):
        # type: () -> bytes
        return self._data[self._offset:]

    def consume(self, n):
        # type: (int) -> bytes
        chunk = self._data[self._offset:self._offset + n]
        self._offset += n
        return chunk

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


class OER_Decoder(BER_Decoder):
    from scapy.asn1.asn1 import ASN1_Codecs

    codec = ASN1_Codecs.OER

    def __init__(self, data):
        # type: (bytes) -> None
        super(OER_Decoder, self).__init__(data, codec=self.codec)


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

    @property
    def inner(self):
        # type: () -> _UPER_Encoder
        return self._enc

    def finish(self):
        # type: () -> bytes
        return self._enc.as_bytes()


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

    @property
    def inner(self):
        # type: () -> _UPER_Decoder
        return self._dec

    def remaining(self):
        # type: () -> bytes
        return self._dec.remaining()

    def set_remainder(self, remainder):
        # type: (bytes) -> None
        from scapy.asn1.uper import UPER_Decoder
        self._dec = UPER_Decoder(remainder)

    def check_no_remainder(self, name):
        # type: (str) -> None
        from scapy.asn1.uper import UPER_Decoding_Error
        if self._dec.remaining():
            raise UPER_Decoding_Error(
                "unexpected remainder in %s" % name,
            )


def new_encoder(codec):
    # type: (Any) -> ASN1Encoder
    from scapy.asn1.asn1 import ASN1_Codecs
    if codec is ASN1_Codecs.PER:
        return UPER_EncoderContext()
    if codec is ASN1_Codecs.OER:
        return OER_Encoder()
    return BER_Encoder()


def new_decoder(codec, data):
    # type: (Any, bytes) -> ASN1Decoder
    from scapy.asn1.asn1 import ASN1_Codecs
    if codec is ASN1_Codecs.PER:
        return UPER_DecoderContext(data)
    if codec is ASN1_Codecs.OER:
        return OER_Decoder(data)
    return BER_Decoder(data)


def per_bit_encoder(enc):
    # type: (Any) -> Any
    """Return the PER bit encoder, or *None* for byte-oriented contexts."""
    bit_enc = getattr(enc, "bit_encoder", None)
    if bit_enc is not None:
        return bit_enc
    from scapy.asn1.uper import UPER_Encoder
    if isinstance(enc, UPER_Encoder):
        return enc
    return None


def per_bit_decoder(dec):
    # type: (Any) -> Any
    """Return the PER bit decoder, or *None* for byte-oriented contexts."""
    bit_dec = getattr(dec, "bit_decoder", None)
    if bit_dec is not None:
        return bit_dec
    from scapy.asn1.uper import UPER_Decoder
    if isinstance(dec, UPER_Decoder):
        return dec
    return None
