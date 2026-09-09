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
    Scapy's mutation detection. This class additionally deepens ``ismutable``
    defaults and stores parsed root item counts for exact-wire rebuilds.
    """

    CBOR_root = None  # type: Optional[Any]

    def _raw_cache_is_valid(self):
        # type: () -> bool
        """Return True if ``raw_packet_cache`` still matches nested field state."""
        if self.raw_packet_cache is None or self.raw_packet_cache_fields is None:
            return False
        for fname, fval in self.raw_packet_cache_fields.items():
            fld, val = self.getfield_and_val(fname)
            if self._raw_packet_cache_field_value(fld, val) != fval:
                self.raw_packet_cache = None
                self.raw_packet_cache_fields = None
                self._cbor_raw_cache_items = None  # type: ignore[attr-defined]
                self.wirelen = None
                return False
        return True

    def cbor_build_result(self):
        # type: () -> Any
        """Return ``CBORBuildResult`` for this packet's root schema.

        When the raw cache is valid, return the exact received bytes together
        with the dissected top-level item count. Never rebuild an unchanged
        packet merely to recover cardinality.
        """
        from scapy.cbor.cborfields import CBORBuildResult
        if self._raw_cache_is_valid():
            items = getattr(self, "_cbor_raw_cache_items", None)
            if items is None:
                items = 1
            return CBORBuildResult(self.raw_packet_cache, items)
        result = self.CBOR_root.build_result(self)
        self._cbor_raw_cache_items = result.items  # type: ignore[attr-defined]
        return result

    def do_init_cached_fields(self, for_dissect_only=False):
        # type: (bool) -> None
        super(CBOR_Packet, self).do_init_cached_fields(
            for_dissect_only=for_dissect_only
        )
        if for_dissect_only:
            return
        # Packet only deep-copies list/dict/set defaults; deepen ismutable.
        for f in self.fields_desc:
            if getattr(f, "ismutable", False) and f.name in self.fields:
                self.fields[f.name] = f.do_copy(self.fields[f.name])
            # Packet-valued defaults are copied in Packet.__init__ with
            # parent=None; re-run any2i so this instance becomes the parent.
            if f.holds_packets and f.name in self.fields:
                self.fields[f.name] = f.any2i(self, self.fields[f.name])

    def _materialize_cbor_default(self, attr):
        # type: (str) -> Optional[Tuple[Any, Any]]
        """Copy mutable/packet defaults into ``fields`` on first access."""
        if attr in self.fields or attr not in self.default_fields:
            return None
        fld = self.get_field(attr)
        if fld is None or not (
            getattr(fld, "ismutable", False) or fld.holds_packets
        ):
            return None
        val = fld.do_copy(self.default_fields[attr])
        # Re-run any2i so packet-valued defaults attach this instance
        # as parent (defaults were normalized with pkt=None).
        if fld.holds_packets:
            val = fld.any2i(self, val)
        self.fields[attr] = val
        return fld, self.fields[attr]

    def getfield_and_val(self, attr):
        # type: (str) -> Tuple[Any, Any]
        materialized = self._materialize_cbor_default(attr)
        if materialized is not None:
            return materialized
        return super(CBOR_Packet, self).getfield_and_val(attr)

    def getfieldval(self, attr):
        # type: (str) -> Any
        materialized = self._materialize_cbor_default(attr)
        if materialized is not None:
            return materialized[1]
        return super(CBOR_Packet, self).getfieldval(attr)

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
        result = self.CBOR_root.dissect_result(self, s)
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
