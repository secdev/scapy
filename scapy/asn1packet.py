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
    Optional,
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
    _asn1_observed_tags = None  # type: Optional[Dict[str, int]]

    def self_build(self):
        # type: () -> bytes
        if self.raw_packet_cache is not None:
            return self.raw_packet_cache
        from scapy.asn1.context import new_encoder
        enc = new_encoder(self.ASN1_codec)
        self.ASN1_root.encode_to(self, enc)
        return cast(bytes, enc.finish())

    def do_dissect(self, x):
        # type: (bytes) -> bytes
        self._asn1_observed_tags = {}
        from scapy.asn1.context import new_decoder
        dec = new_decoder(self.ASN1_codec, x)
        self.ASN1_root.decode_from(self, dec)
        return cast(bytes, dec.remaining())
