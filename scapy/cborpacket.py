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

import copy

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


def _finalize_cbor_raw_cache(pkt, raw, remain, items):
    # type: (Packet, bytes, bytes, int) -> None
    """Record raw cache, item count, and mutable-field snapshot after dissect.

    CBOR-specific Packet cache integration: mirrors ``Packet.do_dissect``
    bookkeeping and also stores ``_cbor_raw_cache_items`` so unframed sequence
    roots can return the exact received bytes without rebuilding.
    """
    from scapy.cbor.cborfields import CBOR_ABSENT
    pkt.raw_packet_cache = raw[:-len(remain)] if remain else raw
    pkt._cbor_raw_cache_items = items  # type: ignore[attr-defined]
    pkt.raw_packet_cache_fields = {}
    for f in pkt.fields_desc:
        if f.name not in pkt.fields:
            continue
        fval = pkt.fields[f.name]
        if fval is CBOR_ABSENT:
            pkt.raw_packet_cache_fields[f.name] = CBOR_ABSENT
            continue
        if getattr(f, "isconditional", False) and fval is None:
            continue
        if (f.islist or f.holds_packets or getattr(f, "ismutable", False)) \
                and fval is not None:
            pkt.raw_packet_cache_fields[f.name] = \
                pkt._raw_packet_cache_field_value(f, fval, copy=True)
    pkt.explicit = 1


def _cbor_raw_cache_is_valid(pkt):
    # type: (Packet) -> bool
    """Return True if ``raw_packet_cache`` still matches nested field state."""
    if pkt.raw_packet_cache is None or pkt.raw_packet_cache_fields is None:
        return False
    for fname, fval in pkt.raw_packet_cache_fields.items():
        fld, val = pkt.getfield_and_val(fname)
        if pkt._raw_packet_cache_field_value(fld, val) != fval:
            pkt.raw_packet_cache = None
            pkt.raw_packet_cache_fields = None
            pkt._cbor_raw_cache_items = None  # type: ignore[attr-defined]
            pkt.wirelen = None
            return False
    return True


class CBOR_Packet(Packet, metaclass=CBORPacket_metaclass):
    """CBOR packet with root-schema build/dissect and cache integration.

    Field flags (``islist`` / ``ismutable`` / ``holds_packets``) drive
    Scapy's mutation detection. This class additionally deepens ``ismutable``
    defaults and stores parsed root item counts for exact-wire rebuilds.
    """

    CBOR_root = None  # type: Optional[Any]

    def cbor_build_result(self):
        # type: () -> Any
        """Return ``CBORBuildResult`` for this packet's root schema.

        When the raw cache is valid, return the exact received bytes together
        with the dissected top-level item count. Never rebuild an unchanged
        packet merely to recover cardinality.
        """
        from scapy.cbor.cborfields import CBORBuildResult
        if _cbor_raw_cache_is_valid(self):
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

    def getfield_and_val(self, attr):
        # type: (str) -> Tuple[Any, Any]
        if attr not in self.fields and attr in self.default_fields:
            fld = self.get_field(attr)
            if fld is not None and (
                getattr(fld, "ismutable", False) or fld.holds_packets
            ):
                val = fld.do_copy(self.default_fields[attr])
                # Re-run any2i so packet-valued defaults attach this instance
                # as parent (defaults were normalized with pkt=None).
                if fld.holds_packets:
                    val = fld.any2i(self, val)
                self.fields[attr] = val
                return fld, self.fields[attr]
        return super(CBOR_Packet, self).getfield_and_val(attr)

    def getfieldval(self, attr):
        # type: (str) -> Any
        if attr not in self.fields and attr in self.default_fields:
            fld = self.get_field(attr)
            if fld is not None and (
                getattr(fld, "ismutable", False) or fld.holds_packets
            ):
                val = fld.do_copy(self.default_fields[attr])
                if fld.holds_packets:
                    val = fld.any2i(self, val)
                self.fields[attr] = val
                return self.fields[attr]
        return super(CBOR_Packet, self).getfieldval(attr)

    def self_build(self):
        # type: () -> bytes
        if _cbor_raw_cache_is_valid(self):
            return self.raw_packet_cache
        return self.CBOR_root.build(self)

    def do_build(self):
        # type: () -> bytes
        # Packet.do_build() expands via __iter__ when explicit=0 (setfieldval).
        # That would drop CBOR-only packet state such as unknown map pairs.
        pkt = self.self_build()
        for t in self.post_transforms:
            pkt = t(pkt)
        pay = self.do_build_payload()
        if self.raw_packet_cache is None:
            return self.post_build(pkt, pay)
        return pkt + pay

    def do_dissect(self, x):
        # type: (bytes) -> bytes
        result = self.CBOR_root.dissect_result(self, x)
        _finalize_cbor_raw_cache(self, x, result.remaining, result.items)
        return result.remaining

    def copy(self):
        # type: () -> Packet
        """Deep-copy this packet and re-parent embedded CBOR children.

        Generic ``Packet.copy()`` copies packet-valued fields but leaves each
        child's ``.parent`` pointing at the original owner. CBOR fields rely on
        ``parent`` for ownership, so reattach after the clone is built.
        """
        clone = super(CBOR_Packet, self).copy()
        for attr in (
            "_cbor_raw_cache_items",
            "_cbor_unknown_map_pairs",
            "_crc_content_span",
        ):
            if hasattr(self, attr):
                val = getattr(self, attr)
                if attr == "_cbor_unknown_map_pairs":
                    setattr(
                        clone,
                        attr,
                        copy.deepcopy(val),
                    )
                else:
                    setattr(clone, attr, val)
        from scapy.cbor.cborfields import _cbor_attach_parent
        for f in clone.fields_desc:
            if not f.holds_packets or f.name not in clone.fields:
                continue
            fval = clone.fields[f.name]
            if isinstance(fval, Packet):
                _cbor_attach_parent(clone, fval)
            elif isinstance(fval, list):
                for item in fval:
                    if isinstance(item, Packet):
                        _cbor_attach_parent(clone, item)
        return clone
