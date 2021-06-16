# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
ASN.1 Packet

Packet holding data in Abstract Syntax Notation (ASN.1).
"""

from __future__ import absolute_import
from scapy.base_classes import Packet_metaclass
from scapy.packet import Packet
import scapy.modules.six as six

from scapy.compat import (
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
    def __new__(cls,  # type: ignore
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[ASN1_Packet]
        if dct["ASN1_root"] is not None:
            dct["fields_desc"] = dct["ASN1_root"].get_fields_list()
        return super(ASN1Packet_metaclass, cls).__new__(cls, name, bases, dct)


@six.add_metaclass(ASN1Packet_metaclass)
class ASN1_Packet(Packet):
    ASN1_root = cast('ASN1F_field[Any, Any]', None)
    ASN1_codec = None

    def self_build(self):
        # type: () -> bytes
        if self.raw_packet_cache is not None:
            return self.raw_packet_cache
        return self.ASN1_root.build(self)

    def do_dissect(self, x):
        # type: (bytes) -> bytes
        return self.ASN1_root.dissect(self, x)
