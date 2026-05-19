# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
CBOR Packet

Packet holding data encoded in Concise Binary Object Representation (CBOR).
Modelled after scapy/asn1packet.py.
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
    from scapy.cbor.cborfields import CBORF_field  # noqa: F401


class CBORPacket_metaclass(Packet_metaclass):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[CBOR_Packet]
        if dct.get("CBOR_root") is not None:
            dct["fields_desc"] = dct["CBOR_root"].get_fields_list()
        return cast(
            'Type[CBOR_Packet]',
            super(CBORPacket_metaclass, cls).__new__(cls, name, bases, dct),
        )


class CBOR_Packet(Packet, metaclass=CBORPacket_metaclass):
    CBOR_root = cast('CBORF_field[Any, Any]', None)

    def self_build(self):
        # type: () -> bytes
        """Build this CBOR packet to wire bytes using CBOR_root.

        Returns the raw packet cache when already built, otherwise delegates
        to CBOR_root.build() which encodes all fields according to the CBOR
        schema defined for this packet.
        """
        if self.raw_packet_cache is not None:
            return self.raw_packet_cache
        return self.CBOR_root.build(self)

    def do_dissect(self, x):
        # type: (bytes) -> bytes
        """Dissect CBOR-encoded bytes into packet fields.

        Delegates to CBOR_root.dissect() which reads CBOR items from *x*,
        populates each field on the packet, and returns any unconsumed bytes.
        """
        return self.CBOR_root.dissect(self, x)
