# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
CBOR Packet

Packet holding data encoded in Concise Binary Object Representation (CBOR).
Modelled after scapy/asn1packet.py, with CBOR-specific raw-cache integration
for sentinels (``CBOR_ABSENT``) and mutable ANY values.
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
    re-parents nested packet defaults for exact-wire rebuilds.
    """

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

    def _raw_packet_cache_field_value(self, fld, val, copy=False):
        # type: (Any, Any, bool) -> Optional[Any]
        # Field-local fingerprints (e.g. CBORF_ANY) include wire-cache state
        # that semantic CBOR_Object equality ignores.
        cache_fingerprint = getattr(fld, "cache_fingerprint", None)
        if cache_fingerprint is not None:
            fingerprint = cache_fingerprint(val)
            if fingerprint is not None:
                return fingerprint
        if fld.holds_packets:
            # Compose nested CBOR field fingerprints instead of shallow-copying
            # child.fields (which aliases mutable CBOR_Object trees).
            def _child_fp(child):
                # type: (Packet) -> Tuple[Any, Any]
                child_fields = {}  # type: Dict[str, Any]
                if isinstance(child, CBOR_Packet):
                    from scapy.cbor.cborfields import CBOR_ABSENT
                    for cf in child.fields_desc:
                        if cf.name not in child.fields:
                            continue
                        cval = child.fields[cf.name]
                        if cval is CBOR_ABSENT:
                            child_fields[cf.name] = CBOR_ABSENT
                            continue
                        if cval is None and getattr(cf, "isconditional", False):
                            continue
                        if (
                            cf.islist
                            or cf.holds_packets
                            or getattr(cf, "ismutable", False)
                        ) and cval is not None:
                            child_fields[cf.name] = (
                                child._raw_packet_cache_field_value(
                                    cf, cval, copy=copy
                                )
                            )
                        else:
                            child_fields[cf.name] = cval
                else:
                    child_fields = (
                        fld.do_copy(child.fields) if copy else child.fields
                    )
                return (child_fields, child.payload.raw_packet_cache)

            if fld.islist:
                return [_child_fp(item) for item in val]
            return _child_fp(val)
        return super(CBOR_Packet, self)._raw_packet_cache_field_value(
            fld, val, copy
        )

    def self_build(self):
        # type: () -> bytes
        if self._raw_packet_cache_is_valid():
            return self.raw_packet_cache
        return self.CBOR_root.build(self)

    def do_dissect(self, s):
        # type: (bytes) -> bytes
        from scapy.cbor.cborfields import CBOR_ABSENT
        result = self.CBOR_root._dissect_counted(self, s)
        remain = result.remaining
        self.raw_packet_cache = s[:-len(remain)] if remain else s
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
        for f in clone.fields_desc:
            if f.holds_packets and f.name in clone.fields:
                clone.fields[f.name] = f.any2i(clone, clone.fields[f.name])
        return clone
