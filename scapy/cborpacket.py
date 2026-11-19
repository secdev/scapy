# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
CBOR Packet

Packet holding data encoded in Concise Binary Object Representation (CBOR).
Modelled after scapy/asn1packet.py.
"""

from typing import (
    Any,
    Dict,
    Optional,
    Tuple,
    Type,
    cast,
)

from scapy.base_classes import Packet_metaclass
from scapy.packet import Packet


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
    """CBOR packet with root-schema build/dissect and isolated defaults."""

    CBOR_root = None  # type: Optional[Any]

    def do_init_cached_fields(self, for_dissect_only=False):
        # type: (bool) -> None
        super(CBOR_Packet, self).do_init_cached_fields(
            for_dissect_only=for_dissect_only
        )
        if for_dissect_only:
            return
        # Packet isolates list/Packet defaults into fields; re-parent those.
        for f in self.packetfields:
            if f.name in self.fields:
                self.fields[f.name] = f.any2i(self, self.fields[f.name])
        # Isolate CBOR ismutable defaults (e.g. CBORF_ANY objects) without
        # promoting into fields (bind overloads stay Packet-global).
        need = [
            f.name for f in self.fields_desc
            if getattr(f, "ismutable", False)
            and f.name in self.default_fields
            and f.name not in self.fields
        ]
        if need:
            self.default_fields = dict(self.default_fields)
            for name in need:
                fld = self.fieldtype[name]
                self.default_fields[name] = fld.do_copy(
                    self.default_fields[name]
                )

    def self_build(self):
        # type: () -> bytes
        if self.raw_packet_cache is not None:
            return self.raw_packet_cache
        return self.CBOR_root.build(self)

    def do_dissect(self, s):
        # type: (bytes) -> bytes
        return self.CBOR_root.dissect(self, s)

    def copy(self):
        # type: () -> Packet
        """Deep-copy this packet and re-parent embedded CBOR children.

        Generic ``Packet.copy()`` copies packet-valued fields but leaves each
        child's ``.parent`` pointing at the original owner. CBOR fields rely on
        ``parent`` for ownership, so reattach after the clone is built.
        """
        clone = super(CBOR_Packet, self).copy()
        for f in clone.fields_desc:
            if f.holds_packets and f.name in clone.fields:
                clone.fields[f.name] = f.any2i(clone, clone.fields[f.name])
        return clone
