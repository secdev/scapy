# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
ASN.1 Packet

Packet holding data in Abstract Syntax Notation (ASN.1).
"""

from scapy.base_classes import Packet_metaclass
from scapy.packet import Packet

from typing import (
    Any,
    Dict,
    Tuple,
    Type,
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from scapy.asn1fields import ASN1F_field  # noqa: F401


class ASN1Packet_metaclass(Packet_metaclass):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[ASN1_Packet]
        if dct["ASN1_root"] is not None:
            dct["fields_desc"] = dct["ASN1_root"].get_fields_list()
        return cast(
            'Type[ASN1_Packet]',
            super(ASN1Packet_metaclass, cls).__new__(cls, name, bases, dct),
        )


class ASN1_Packet(Packet, metaclass=ASN1Packet_metaclass):
    ASN1_root = cast('ASN1F_field[Any, Any]', None)
    ASN1_codec = cast(Any, None)

    def self_build(self):
        # type: () -> bytes
        if self.raw_packet_cache is not None:
            return self.raw_packet_cache
        enc = self.ASN1_codec.new_encoder()
        self.ASN1_root.encode_to(self, enc)
        return enc.finish()

    def do_dissect(self, x):
        # type: (bytes) -> bytes
        from scapy.asn1.asn1 import ASN1_Codecs
        from scapy.asn1.uper import UPER_has_unexpected_remainder

        self._asn1_observed_tags = {}  # type: ignore[attr-defined]
        dec = self.ASN1_codec.new_decoder(x)
        self.ASN1_root.decode_from(self, dec)
        if self.ASN1_codec is ASN1_Codecs.PER:
            if not UPER_has_unexpected_remainder(dec.bit_decoder):
                return b""
        return dec.remaining()
