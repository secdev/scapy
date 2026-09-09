# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
CBOR Packet

Packet holding data encoded in Concise Binary Object Representation (CBOR).
Modelled after scapy/asn1packet.py, with CBOR-specific raw-cache integration
for sentinels (``CBOR_ABSENT``), mutable ANY values, and nested item counts.
"""

from scapy.base_classes import Packet_metaclass
from scapy.packet import Packet

from typing import (
    Any,
    Dict,
    Tuple,
    Type,
    Optional,
    cast,
)


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
    """CBOR packet with root-schema build/dissect and cache integration.

    Field flags (``islist`` / ``ismutable`` / ``holds_packets``) drive
    Scapy's mutation detection and per-instance default copying. This class
    re-parents nested packet defaults and stores parsed root item counts for
    exact-wire rebuilds.
    """

    CBOR_root = None  # type: Optional[Any]

    def _raw_cache_is_valid(self):
        # type: () -> bool
        """Return True if ``raw_packet_cache`` still matches nested field state."""
        if not super(CBOR_Packet, self)._raw_packet_cache_is_valid():
            self._cbor_raw_cache_items = None  # type: ignore[attr-defined]
            return False
        return True

    def _cbor_build_counted(self):
        # type: () -> Any
        """Return ``_CBORBuildResult`` for this packet's root schema.

        When the raw cache is valid, return the exact received bytes together
        with the dissected top-level item count. Never rebuild an unchanged
        packet merely to recover cardinality.
        """
        from scapy.cbor.cborfields import _CBORBuildResult
        if self._raw_cache_is_valid():
            items = getattr(self, "_cbor_raw_cache_items", None)
            if items is None:
                items = 1
            return _CBORBuildResult(self.raw_packet_cache, items)
        result = self.CBOR_root._build_counted(self)
        self._cbor_raw_cache_items = result.items  # type: ignore[attr-defined]
        return result

    def do_init_cached_fields(self, for_dissect_only=False):
        # type: (bool) -> None
        super(CBOR_Packet, self).do_init_cached_fields(
            for_dissect_only=for_dissect_only
        )
        if for_dissect_only:
            return
        # Packet copies ismutable defaults into fields; promote leftovers and
        # re-parent nested packet defaults onto this instance.
        for f in self.fields_desc:
            if f.name in self.fields:
                if f.holds_packets:
                    self.fields[f.name] = f.any2i(self, self.fields[f.name])
                continue
            if not (
                getattr(f, "ismutable", False) or f.holds_packets
            ) or f.name not in self.default_fields:
                continue
            val = f.do_copy(self.default_fields[f.name])
            if f.holds_packets:
                val = f.any2i(self, val)
            self.fields[f.name] = val

    def _raw_packet_cache_field_value(self, fld, val, copy=False):
        # type: (Any, Any, bool) -> Optional[Any]
        # Field-local fingerprints (e.g. CBORF_ANY) include wire-cache state
        # that semantic CBOR_Object equality ignores.
        cache_fingerprint = getattr(fld, "cache_fingerprint", None)
        if cache_fingerprint is not None:
            return cache_fingerprint(val)
        return super(CBOR_Packet, self)._raw_packet_cache_field_value(
            fld, val, copy
        )

    def self_build(self):
        # type: () -> bytes
        if self._raw_cache_is_valid():
            return self.raw_packet_cache
        return self.CBOR_root.build(self)

    def do_dissect(self, s):
        # type: (bytes) -> bytes
        from scapy.cbor.cborfields import CBOR_ABSENT
        result = self.CBOR_root._dissect_counted(self, s)
        remain = result.remaining
        self.raw_packet_cache = s[:-len(remain)] if remain else s
        self._cbor_raw_cache_items = result.items  # type: ignore[attr-defined]
        self.raw_packet_cache_fields = {}
        for f in self.fields_desc:
            if f.name not in self.fields:
                continue
            fval = self.fields[f.name]
            if fval is CBOR_ABSENT:
                self.raw_packet_cache_fields[f.name] = CBOR_ABSENT
                continue
            if getattr(f, "isconditional", False) and fval is None:
                continue
            if (f.islist or f.holds_packets or getattr(f, "ismutable", False)) \
                    and fval is not None:
                self.raw_packet_cache_fields[f.name] = \
                    self._raw_packet_cache_field_value(f, fval, copy=True)
        self.explicit = 1
        return remain

    def copy(self):
        # type: () -> Packet
        """Deep-copy this packet and re-parent embedded CBOR children.

        Generic ``Packet.copy()`` copies packet-valued fields but leaves each
        child's ``.parent`` pointing at the original owner. CBOR fields rely on
        ``parent`` for ownership, so reattach after the clone is built.
        """
        clone = super(CBOR_Packet, self).copy()
        if hasattr(self, "_cbor_raw_cache_items"):
            clone._cbor_raw_cache_items = (  # type: ignore[attr-defined]
                self._cbor_raw_cache_items
            )
        for f in clone.fields_desc:
            if f.holds_packets and f.name in clone.fields:
                clone.fields[f.name] = f.any2i(clone, clone.fields[f.name])
        return clone
