# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Brian Sipos <brian.sipos@gmail.com>

# scapy.contrib.description = Bundle Protocol Version 7 (BPv7)
# scapy.contrib.status = loads

from __future__ import annotations

from dataclasses import dataclass, field
import datetime
import enum
from typing import Any, Callable, ClassVar, Optional, Union, cast

from scapy import volatile
from scapy.cbor.cborcodec import (
    cbor_is_break,
    cbor_find_non_deterministic,
    CBOR_decode_head,
    CBOR_INDEFINITE,
)
from scapy.cbor import (
    CBORF_field,
    CBORF_UNSIGNED_INTEGER,
    CBORF_ARRAY,
    CBORF_ARRAY_INDEFINITE,
    CBORF_BYTE_STRING,
    CBORF_CONDITIONAL,
    CBORF_SEQUENCE_OF,
    CBORF_PACKET,
    CBORF_BYTE_STRING_PACKET,
    CBORF_UNSIGNED_ENUM,
    CBORF_UNSIGNED_FLAGS,
    CBORcodec_ARRAY,
    CBOR_NO_ITEM,
    CBOR_Encoding_Error,
)
from scapy.cbor.cborfields import (
    CBORBuildResult,
    cbor_object_to_python,
)
from scapy.cborpacket import CBOR_Packet, _cbor_raw_cache_is_valid
from scapy.error import log_runtime
from scapy.libs.crc import CRC, CRC_16_X25, CRC_32C
from scapy.packet import Packet

_MISSING = object()


def _as_int(val: Any) -> int:
    """Coerce a BPv7 numeric field value (always a Python int at rest)."""
    return int(val)


def _require_uint(val: Any, what: str = "unsigned integer") -> int:
    """Require a RFC 9171 CBOR unsigned integer already normalized to Python.

    Uses ``type(val) is int`` so ``bool`` subclasses of ``int`` are rejected.
    """
    if type(val) is not int or val < 0:
        raise TypeError(
            "%s must be a CBOR unsigned integer, got %r" % (what, val)
        )
    return val


def _as_bytes(val: Any) -> bytes:
    if val is None or val is _MISSING:
        return b""
    return cast(bytes, val)


class BlockTypeField(CBORF_UNSIGNED_INTEGER):
    """Canonical block type code; ``None`` means infer from BTSD on build."""

    def build_result(self, pkt):
        val = pkt.getfieldval(self.name)
        if val is None:
            inferred = getattr(pkt, "inferred_type_code", lambda: None)()
            if inferred is None:
                raise CBOR_Encoding_Error(
                    "Block type_code is None and cannot be inferred from BTSD"
                )
            val = inferred
        return CBORBuildResult(self.i2m(pkt, val), 1)


class CrcBytesField(CBORF_BYTE_STRING):
    """CRC content octets; ``None`` means compute automatically on build."""

    def m2i(self, pkt, s):
        # Record the exact received CRC content span on the owning block.
        # Kept here (not on generic CBORF_BYTE_STRING) so other definite
        # byte-string fields cannot overwrite BPv7 CRC bookkeeping.
        before = len(s)
        val, remain = super(CrcBytesField, self).m2i(pkt, s)
        if pkt is not None:
            pkt._crc_content_span = (  # type: ignore[attr-defined]
                len(val),
                len(remain),
                before - len(remain) - len(val),
            )
        return val, remain

    def build_result(self, pkt):
        override = getattr(pkt, "_cbor_crc_override", _MISSING)
        if override is not _MISSING:
            val = override
        else:
            val = pkt.getfieldval(self.name)
            if val is None:
                # Zero placeholder sized for the selected CRC type.
                defn = (
                    pkt._crc_definition()
                    if hasattr(pkt, "_crc_definition") else None
                )
                if defn is None:
                    raise CBOR_Encoding_Error(
                        "CRC field present but CRC type is unsupported"
                    )
                val = defn.encode(0)
        return CBORBuildResult(self.i2m(pkt, val), 1)


class CrcTypeField(CBORF_UNSIGNED_ENUM):
    """Human-friendly CRC type enumeration."""

    def any2i(self, pkt, x):
        # Temporary: accept legacy "CRC32" as CRC-32C (RFC 9171).
        if x in ("CRC32", b"CRC32"):
            x = "CRC32C"
        return super(CrcTypeField, self).any2i(pkt, x)


class DtnTimeField(CBORF_UNSIGNED_INTEGER):
    """A DTN time value representing number of milliseconds from the
    DTN epoch 2000-01-01T00:00:00Z.

    This value is automatically converted from a
    :py:class:`datetime.datetime` object and human friendly text in ISO8601
    format.
    The special human value "zero" represents the zero value time.
    """

    DTN_EPOCH = datetime.datetime(2000, 1, 1, 0, 0, 0, 0, datetime.timezone.utc)

    @staticmethod
    def datetime_to_dtntime(val: Optional[datetime.datetime]) -> int:
        if val is None:
            return 0
        if val.tzinfo is None:
            raise ValueError("DTN time requires a timezone-aware datetime")
        val = val.astimezone(datetime.timezone.utc)
        if val < DtnTimeField.DTN_EPOCH:
            raise ValueError("DTN time before epoch is not allowed")
        delta = val - DtnTimeField.DTN_EPOCH
        return (
            delta.days * 86400000
            + delta.seconds * 1000
            + delta.microseconds // 1000
        )

    @staticmethod
    def dtntime_to_datetime(val: Any) -> Optional[datetime.datetime]:
        if val is None:
            return None
        ival = _as_int(val)
        if ival == 0:
            return None
        delta = datetime.timedelta(milliseconds=ival)
        return delta + DtnTimeField.DTN_EPOCH

    def i2h(self, pkt, x):
        if x is None:
            return None
        if _as_int(x) == 0:
            return "zero"
        try:
            dtval = DtnTimeField.dtntime_to_datetime(x)
        except OverflowError:
            return "dtntime:%d" % _as_int(x)
        if dtval is None:
            return "zero"
        return dtval.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

    def h2i(self, pkt, x):
        return self.any2i(pkt, x)

    @staticmethod
    def _parse_text(val: Union[str, bytes]) -> int:
        if val in ("zero", b"zero"):
            return 0
        text = val.decode("ascii") if isinstance(val, bytes) else val
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(text)
        return DtnTimeField.datetime_to_dtntime(dt)

    def any2i(self, pkt, x):
        if x is None:
            return 0
        if isinstance(x, (str, bytes)):
            return self._parse_text(x)
        if isinstance(x, datetime.datetime):
            return DtnTimeField.datetime_to_dtntime(x)
        val = _as_int(x)
        if val < 0:
            raise ValueError("DTN time must be unsigned")
        if val > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("DTN time exceeds uint64")
        return val

    def randval(self):
        return volatile.RandNum(0, int(2**16))


class BundleTimestamp(CBOR_Packet):
    """A structured representation of an DTN Timestamp.
    The timestamp is a two-tuple of (time, sequence number)
    The creation time portion is automatically converted from a
    :py:class:`datetime.datetime` object and text.
    """

    CBOR_root = CBORF_ARRAY(
        DtnTimeField("dtntime", default=0),
        CBORF_UNSIGNED_INTEGER("seqno", default=0),
    )


@enum.unique
class EidScheme(enum.IntEnum):
    """Handled EID scheme names and values."""

    dtn = 1
    ipn = 2


_DTN_WELL_KNOWN_SSP = {
    0: "none",
}
"""Compressed SSP encoding."""


_IPN_LOCALNODE = 0xFFFFFFFF
# RFC 9758 Table 4: Default Allocator Node Numbers reserved for Private Use.
_IPN_PRIVATE_USE_NODE_MAX = 0x3FFF
_IPN_ASCII_DIGITS = frozenset("0123456789")


def _parse_ipn_ascii_uint(text: str) -> int:
    """Parse an RFC 9758 DIGIT (%x30-39) decimal component."""
    if not text or not _IPN_ASCII_DIGITS.issuperset(text):
        raise ValueError("Invalid IPN numeric component: %r" % text)
    if len(text) > 1 and text[0] == "0":
        raise ValueError("IPN components must not have leading zeros: %r" % text)
    return int(text, 10)


def _dtn_is_vchar(text: str) -> bool:
    """Return True when *text* is RFC 5234 ``*VCHAR`` (%x21-7E)."""
    return all(0x21 <= ord(ch) <= 0x7E for ch in text)


_DTN_REG_NAME_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_DTN_REG_NAME_SUB_DELIMS = frozenset("!$&'()*+,;=")
_DTN_REG_NAME_HEXDIG = frozenset("0123456789ABCDEFabcdef")


def _dtn_is_reg_name(text: str) -> bool:
    """Return True when *text* matches RFC 3986 ``reg-name``."""
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "%":
            if i + 2 >= len(text):
                return False
            if (
                text[i + 1] not in _DTN_REG_NAME_HEXDIG
                or text[i + 2] not in _DTN_REG_NAME_HEXDIG
            ):
                return False
            i += 3
        elif ch in _DTN_REG_NAME_UNRESERVED or ch in _DTN_REG_NAME_SUB_DELIMS:
            i += 1
        else:
            return False
    return True


def _parse_dtn_hier_ssp(ssp_text: str) -> tuple[str, str]:
    """Split a DTN hierarchical SSP into ``(node_name, demux)``.

    RFC 9171: ``dtn-hier-part = "//" node-name "/" demux``.
    """
    if not ssp_text.startswith("//"):
        raise ValueError(
            "DTN EID must be 'dtn:none' or 'dtn://node-name/demux', "
            "got 'dtn:%s'" % ssp_text
        )
    rest = ssp_text[2:]
    slash = rest.find("/")
    if slash < 0:
        raise ValueError(
            "DTN hierarchical EID requires '/' after node-name: 'dtn:%s'"
            % ssp_text
        )
    node_name = rest[:slash]
    demux = rest[slash + 1:]
    if not node_name:
        raise ValueError("DTN node-name must not be empty")
    if not _dtn_is_reg_name(node_name):
        raise ValueError(
            "DTN node-name must be an RFC 3986 reg-name: %r" % node_name
        )
    if not _dtn_is_vchar(demux):
        raise ValueError("DTN demux must be *VCHAR: %r" % demux)
    return node_name, demux


def _parse_dtn_composed_ssp(ssp_text: str) -> Union[int, str]:
    """Validate and normalize a locally composed ``dtn:`` SSP."""
    for key, val in _DTN_WELL_KNOWN_SSP.items():
        if ssp_text == val:
            return key
    _parse_dtn_hier_ssp(ssp_text)
    return ssp_text


def _known_eid_scheme(scheme: int) -> Optional[EidScheme]:
    """Return a known :class:`EidScheme` or ``None`` for private-use values."""
    try:
        return EidScheme(_as_int(scheme))
    except ValueError:
        return None


@dataclass(frozen=True)
class IpnSsp:
    """Normalized IPN scheme-specific part.

    Stores the RFC 9758 logical triple ``(allocator, node, service)`` and the
    CBOR array arity used on the wire. The 2- vs 3-element choice is part of
    the value: after an EID is first encoded, later decode/re-encode cycles
    must preserve that element count.
    """

    allocator: int
    node: int
    service: int
    # 2 = packed [fqnn, service]; 3 = explicit [allocator, node, service]
    wire_elements: int = 3
    # When True, allow received allocator=0/node=0/service!=0 (treat as Null).
    # Newly composed values must not use that form (RFC 9758).
    allow_invalid_null: bool = field(default=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        for name, value in (
            ("allocator", self.allocator),
            ("node", self.node),
            ("service", self.service),
        ):
            if value < 0:
                raise ValueError("%s cannot be negative" % name)
        if self.allocator > 0xFFFFFFFF:
            raise ValueError("allocator exceeds uint32")
        if self.node > 0xFFFFFFFF:
            raise ValueError("node exceeds uint32")
        if self.service > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("service exceeds uint64")
        if self.wire_elements not in (2, 3):
            raise ValueError("IPN wire element count must be 2 or 3")
        if (
            self.allocator == 0
            and self.node == 0
            and self.service != 0
            and not self.allow_invalid_null
        ):
            raise ValueError(
                "Null IPN URI must not be composed with a nonzero service number"
            )

    @classmethod
    def from_wire(cls, parts: list[int]) -> IpnSsp:
        if len(parts) == 2:
            fqnn, service = parts
            return cls(
                fqnn >> 32,
                fqnn & 0xFFFFFFFF,
                service,
                wire_elements=2,
                allow_invalid_null=True,
            )
        if len(parts) == 3:
            return cls(
                parts[0],
                parts[1],
                parts[2],
                wire_elements=3,
                allow_invalid_null=True,
            )
        raise ValueError("IPN SSP must be 2 or 3 elements")

    def to_wire(self) -> list[int]:
        if self.wire_elements == 2:
            fqnn = (self.allocator << 32) | self.node
            return [fqnn, self.service]
        return [self.allocator, self.node, self.service]

    def same_endpoint(self, other: object) -> bool:
        """Return True when *other* names the same logical IPN endpoint."""
        if not isinstance(other, IpnSsp):
            return False
        # RFC 9758: any allocator=0/node=0 form identifies the Null endpoint,
        # including received invalid non-zero service numbers.
        if self.is_null_endpoint() and other.is_null_endpoint():
            return True
        return (
            self.allocator == other.allocator
            and self.node == other.node
            and self.service == other.service
        )

    def is_null_endpoint(self) -> bool:
        # RFC 9758: allocator 0 and node 0 is the Null Endpoint for any service.
        return self.allocator == 0 and self.node == 0

    def is_local_node(self) -> bool:
        """Return True for Default Allocator LocalNode FQNN (RFC 9758)."""
        return self.allocator == 0 and self.node == _IPN_LOCALNODE

    def is_private_use(self) -> bool:
        """Return True for Default Allocator Private Use Node Numbers."""
        return (
            self.allocator == 0
            and 1 <= self.node <= _IPN_PRIVATE_USE_NODE_MAX
        )

    def to_text(self) -> str:
        # RFC 9758: "!" is the entire FQNN (allocator 0 + LocalNode), never a
        # lone allocator or service component. Prefer bang for the usual
        # 2-element wire form; keep an explicit 3-element numeric URI when
        # that arity was received so text round-trips preserve CBOR shape.
        if self.allocator == 0 and self.node == _IPN_LOCALNODE:
            if self.wire_elements == 3:
                return "ipn:0.%d.%d" % (_IPN_LOCALNODE, self.service)
            return "ipn:!.%d" % self.service
        if self.wire_elements == 2 and self.allocator == 0:
            return "ipn:%d.%d" % (self.node, self.service)
        return "ipn:%d.%d.%d" % (self.allocator, self.node, self.service)


@dataclass(frozen=True)
class EidStruct:
    """
    Internal state for the :class:`BundleEidField` class.
    """

    scheme: int
    ssp: Any

    def is_known_scheme(self) -> bool:
        """Return True when Scapy has semantic support for this scheme."""
        return _known_eid_scheme(self.scheme) is not None

    @staticmethod
    def from_text(text: str) -> EidStruct:
        scheme_name, ssp_text = text.split(":", 1)

        try:
            scheme = EidScheme[scheme_name.lower()]
        except KeyError:
            raise ValueError(f"BP EID scheme {scheme_name} not understood")
        ssp = None
        if scheme == EidScheme.dtn:
            # Local composition rejects syntactically impossible DTN URIs
            # (RFC 9171). Wire decode via from_cbor() remains permissive.
            ssp = _parse_dtn_composed_ssp(ssp_text)

        elif scheme == EidScheme.ipn:
            # RFC 9758: "!" is only the full FQNN form ipn:!.<service>
            if ssp_text.startswith("!."):
                service_text = ssp_text[2:]
                if not service_text or "." in service_text:
                    raise ValueError("Invalid LocalNode IPN URI: %r" % text)
                ssp = IpnSsp(
                    0,
                    _IPN_LOCALNODE,
                    _parse_ipn_ascii_uint(service_text),
                    wire_elements=2,
                )
            else:
                parts = ssp_text.split(".")
                if len(parts) == 2:
                    # from_text() is local composition: reject invalid Null+service
                    # (RFC 9758). Wire decode uses IpnSsp.from_wire() / from_cbor().
                    ssp = IpnSsp(
                        0,
                        _parse_ipn_ascii_uint(parts[0]),
                        _parse_ipn_ascii_uint(parts[1]),
                        wire_elements=2,
                    )
                elif len(parts) == 3:
                    ssp = IpnSsp(
                        _parse_ipn_ascii_uint(parts[0]),
                        _parse_ipn_ascii_uint(parts[1]),
                        _parse_ipn_ascii_uint(parts[2]),
                        wire_elements=3,
                    )
                else:
                    raise ValueError("IPN SSP must be 2 or 3 elements")

        else:
            raise ValueError("Invalid scheme state")

        return EidStruct(scheme=int(scheme), ssp=ssp)

    def to_text(self) -> str:
        known = _known_eid_scheme(self.scheme)
        if known == EidScheme.dtn:
            if isinstance(self.ssp, int):
                try:
                    ssp = _DTN_WELL_KNOWN_SSP[self.ssp]
                except KeyError:
                    ssp = "!unknown-ssp-%d" % self.ssp
            else:
                ssp = str(self.ssp)
            return "dtn:" + ssp
        if known == EidScheme.ipn:
            if isinstance(self.ssp, IpnSsp):
                return self.ssp.to_text()
            return IpnSsp.from_wire(list(self.ssp)).to_text()
        return "%d:%r" % (self.scheme, self.ssp)

    def is_null_endpoint(self) -> bool:
        """Return True for the BPv7 Null Endpoint (dtn:none / ipn:0.*)."""
        known = _known_eid_scheme(self.scheme)
        if known == EidScheme.dtn:
            return self.ssp == 0 or self.ssp == "none"
        if known == EidScheme.ipn:
            if isinstance(self.ssp, IpnSsp):
                return self.ssp.is_null_endpoint()
            return IpnSsp.from_wire(list(self.ssp)).is_null_endpoint()
        return False

    def _ipn_ssp(self) -> Optional[IpnSsp]:
        if _known_eid_scheme(self.scheme) != EidScheme.ipn:
            return None
        if isinstance(self.ssp, IpnSsp):
            return self.ssp
        try:
            return IpnSsp.from_wire(list(self.ssp))
        except (TypeError, ValueError):
            return None

    def is_local_node(self) -> bool:
        """Return True for an IPN LocalNode EID (``ipn:!.service``)."""
        ssp = self._ipn_ssp()
        return ssp is not None and ssp.is_local_node()

    def is_private_use(self) -> bool:
        """Return True for Default Allocator Private Use IPN EIDs."""
        ssp = self._ipn_ssp()
        return ssp is not None and ssp.is_private_use()

    def is_valid(self) -> bool:
        """Return True when this EID has a RFC-conformant structure.

        Received wire forms may still dissect when ``False``; use this (and
        :meth:`validate`) to report protocol issues. Local text composition
        already rejects invalid DTN/IPN forms in :meth:`from_text`.

        Private-use / unknown schemes are not judged invalid merely because
        Scapy lacks semantic rules for them.
        """
        known = _known_eid_scheme(self.scheme)
        if known is None:
            return True
        if known == EidScheme.dtn:
            if isinstance(self.ssp, int):
                return self.ssp in _DTN_WELL_KNOWN_SSP
            if not isinstance(self.ssp, str):
                return False
            if self.ssp == "none":
                return True
            try:
                _parse_dtn_hier_ssp(self.ssp)
            except ValueError:
                return False
            return True
        if known == EidScheme.ipn:
            if isinstance(self.ssp, IpnSsp):
                return True
            try:
                IpnSsp.from_wire(list(self.ssp))
            except (TypeError, ValueError):
                return False
            return True
        return False

    def is_node_id(self) -> bool:
        """Return True when this EID may serve as a BPv7 Node ID.

        - Null endpoint is not a Node ID.
        - ``dtn:`` Node IDs require an empty demux (``dtn://node-name/``).
        - RFC 9758: any IPN EID may identify the node named by its FQNN
          (do not require service number zero).
        - Unknown/private-use schemes cannot be classified as Node IDs.
        """
        if self.is_null_endpoint() or not self.is_known_scheme():
            return False
        if not self.is_valid():
            return False
        known = _known_eid_scheme(self.scheme)
        if known == EidScheme.ipn:
            return True
        if known == EidScheme.dtn:
            if isinstance(self.ssp, int):
                return False
            try:
                _node_name, demux = _parse_dtn_hier_ssp(str(self.ssp))
            except ValueError:
                return False
            return demux == ""
        return False

    def same_endpoint(self, other: object) -> bool:
        """Return True when *other* denotes the same logical endpoint."""
        return (
            isinstance(other, EidStruct)
            and self.semantic_key() == other.semantic_key()
        )

    def semantic_key(self) -> tuple[Any, ...]:
        """Stable logical identity key independent of wire arity / text form."""
        if self.is_null_endpoint():
            return ("bpv7-null-endpoint",)
        known = _known_eid_scheme(self.scheme)
        if known == EidScheme.dtn:
            if isinstance(self.ssp, int):
                return ("dtn", self.ssp)
            # Normalize well-known text SSP to the compressed code.
            if self.ssp == "none":
                return ("dtn", 0)
            return ("dtn", self.ssp)
        if known == EidScheme.ipn:
            if isinstance(self.ssp, IpnSsp):
                ssp = self.ssp
            else:
                ssp = IpnSsp.from_wire(list(self.ssp))
            return ("ipn", ssp.allocator, ssp.node, ssp.service)
        return ("unknown-scheme", self.scheme, repr(self.ssp))

    @staticmethod
    def _wire_parts(ssp_item: Any) -> list[int]:
        if not isinstance(ssp_item, (list, tuple)):
            raise TypeError("IPN SSP must be a list, have %r" % (ssp_item,))
        return [
            _require_uint(item, "IPN SSP component") for item in ssp_item
        ]

    @staticmethod
    def from_cbor(item: Any) -> EidStruct:
        # Expect Python natives after BundleEidField.m2i normalization.
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise TypeError("Need a 2-element EID array, have %r" % (item,))
        scheme_id, ssp_item = item
        scheme_num = _require_uint(scheme_id, "EID scheme")
        known = _known_eid_scheme(scheme_num)

        if known == EidScheme.dtn:
            if isinstance(ssp_item, int):
                ssp = _require_uint(ssp_item, "DTN compressed SSP")
                if ssp not in _DTN_WELL_KNOWN_SSP:
                    raise ValueError(
                        "Unknown compressed DTN SSP value: %r" % (ssp,)
                    )
            elif isinstance(ssp_item, str):
                ssp = ssp_item
            else:
                raise TypeError("Invalid DTN SSP: %r" % (ssp_item,))
        elif known == EidScheme.ipn:
            ssp = IpnSsp.from_wire(EidStruct._wire_parts(ssp_item))
        else:
            # Private-use / future schemes: preserve the SSP generically.
            ssp = ssp_item

        return EidStruct(scheme=scheme_num, ssp=ssp)

    def to_cbor(self) -> list[Any]:
        known = _known_eid_scheme(self.scheme)
        if known == EidScheme.dtn:
            ssp_item = self.ssp
        elif known == EidScheme.ipn:
            if isinstance(self.ssp, IpnSsp):
                ssp_item = self.ssp.to_wire()
            else:
                ssp_item = IpnSsp.from_wire(list(self.ssp)).to_wire()
        else:
            ssp_item = self.ssp

        return [self.scheme, ssp_item]


class BundleEidField(CBORF_field[EidStruct]):
    """Provide a human-friendly representation of a BP Endpoint ID (EID) as
    a single field.
    The EID is a two-item array of (scheme ID, scheme-specific part).

    Internal representation is always :class:`EidStruct`.
    """

    def i2h(self, _pkt, x):
        if x is None:
            return None
        if not isinstance(x, EidStruct):
            raise TypeError("EID internal value must be an EidStruct")
        return x.to_text()

    def h2i(self, _pkt, x):
        if x is None:
            return None
        if isinstance(x, EidStruct):
            return x
        if isinstance(x, str):
            return EidStruct.from_text(x)
        raise TypeError("Cannot convert %r to an EidStruct" % (x,))

    def any2i(self, pkt, x):
        return self.h2i(pkt, x)

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

    def encode_value(self, x):
        if not isinstance(x, EidStruct):
            raise TypeError("Cannot encode EID value %r" % (x,))
        return CBORcodec_ARRAY.enc(x.to_cbor())

    def m2i(self, pkt, s):
        item, remain = CBORcodec_ARRAY.dec(s)
        return EidStruct.from_cbor(cbor_object_to_python(item)), remain


class CrcType(enum.IntEnum):
    """
    CRC type values defined in RFC 9171.

    ``CRC32`` is a temporary alias of ``CRC32C`` (Castagnoli); prefer
    ``CRC32C`` in new code. ``@enum.unique`` is omitted so the alias is valid.
    """

    NONE = 0
    CRC16 = 1
    CRC32C = 2
    CRC32 = 2


@dataclass(frozen=True)
class CrcInfo:
    """
    Processing for a specific :class:`CrcType`
    """

    cls: type[CRC]
    width: int

    def encode(self, value: int) -> bytes:
        return value.to_bytes(self.width, "big")


_CRC_DEFN: dict[CrcType, CrcInfo] = {
    CrcType.CRC16: CrcInfo(cls=CRC_16_X25, width=2),
    CrcType.CRC32C: CrcInfo(cls=CRC_32C, width=4),
}


def _enum_dict(cls: type[enum.IntEnum]) -> dict[int, str]:
    return {item.value: item.name for item in cls}


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    path: str
    message: str
    severity: str = "error"


class AbstractBlock:
    """Represent an abstract block internal interface mixin."""

    _crc_type_name = "crc_type"
    _crc_value_name = "crc_value"

    def has_crc(self) -> bool:
        crc_type = self.getfieldval(self._crc_type_name)
        return _as_int(crc_type) != int(CrcType.NONE)

    def _crc_definition(self) -> Optional[CrcInfo]:
        value = _as_int(self.getfieldval(self._crc_type_name))
        try:
            return _CRC_DEFN[CrcType(value)]
        except (ValueError, KeyError):
            return None

    def _build_root_with_crc_value(self, crc_value: bytes) -> bytes:
        # CrcBytesField reads ``_cbor_crc_override`` instead of mutating fields.
        self._cbor_crc_override = crc_value  # type: ignore[attr-defined]
        try:
            return self.CBOR_root.build(self)
        finally:
            try:
                del self._cbor_crc_override  # type: ignore[attr-defined]
            except AttributeError:
                pass

    def cbor_build_result(self):
        """Return final wire bytes and cardinality in one schema traversal."""
        return CBORBuildResult(data=self.self_build(), items=1)

    def calculate_crc(self) -> Optional[bytes]:
        crc_type = _as_int(self.getfieldval(self._crc_type_name))
        if crc_type == int(CrcType.NONE):
            return None
        defn = self._crc_definition()
        if defn is None:
            raise CBOR_Encoding_Error(
                "Unsupported CRC type %d" % crc_type
            )
        # Build once with zero placeholder; derive CRC from that buffer.
        pre_crc = self._build_root_with_crc_value(defn.encode(0))
        return defn.encode(defn.cls(pre_crc))

    def _self_build_with_crc(self) -> bytes:
        if _cbor_raw_cache_is_valid(self):
            return self.raw_packet_cache  # type: ignore[return-value]
        crc_type = _as_int(self.getfieldval(self._crc_type_name))
        if crc_type == int(CrcType.NONE):
            return self.CBOR_root.build(self)
        crc_value = self.getfieldval(self._crc_value_name)
        if crc_value is not None and crc_value is not _MISSING:
            actual = _as_bytes(crc_value)
            defn = self._crc_definition()
            if defn is None:
                raise CBOR_Encoding_Error(
                    "Unsupported CRC type %d" % crc_type
                )
            if len(actual) != defn.width:
                raise CBOR_Encoding_Error(
                    "CRC value length %d does not match type %s"
                    % (len(actual), CrcType(crc_type).name)
                )
            return self._build_root_with_crc_value(actual)
        # None means auto: build once with a zero CRC, then patch.
        defn = self._crc_definition()
        if defn is None:
            raise CBOR_Encoding_Error(
                "Unsupported CRC type %d" % crc_type
            )
        zero = defn.encode(0)
        pre_crc = self._build_root_with_crc_value(zero)
        crc_bytes = defn.encode(defn.cls(pre_crc))
        if len(crc_bytes) != len(zero):
            raise CBOR_Encoding_Error("CRC width mismatch during patch")
        # Rebuild with the computed CRC rather than searching for the zero
        # placeholder (BTSD may contain identical zero sequences).
        return self._build_root_with_crc_value(crc_bytes)

    def freeze_crc(self) -> None:
        crc_type = _as_int(self.getfieldval(self._crc_type_name))
        if crc_type == int(CrcType.NONE):
            self.setfieldval(self._crc_value_name, None)
        else:
            self.setfieldval(self._crc_value_name, self.calculate_crc())

    def _crc_over_received_or_built(self, defn: CrcInfo, actual: bytes) -> bytes:
        """CRC over exact received bytes when available; else rebuilt form."""
        # Nested mutations must invalidate a dissected raw cache first.
        _cbor_raw_cache_is_valid(self)
        raw = self.raw_packet_cache
        if raw is not None and actual:
            span = getattr(self, "_crc_content_span", None)
            if span is not None:
                content_len, remain_after, _head_len = span
                if content_len == len(actual) and remain_after <= len(raw):
                    start = len(raw) - remain_after - content_len
                    if start >= 0 and raw[start:start + content_len] == actual:
                        zeroed = bytearray(raw)
                        for i in range(content_len):
                            zeroed[start + i] = 0
                        return defn.encode(defn.cls(bytes(zeroed)))
            # Fall back: CRC is the final array element (preferred bstr head
            # only). Do not rfind overlong heads — BTSD may embed matching
            # short sequences. Missing span + non-preferred CRC head rebuilds.
            from scapy.cbor.cborcodec import CBOR_encode_head
            n = len(actual)
            head = CBOR_encode_head(2, n)
            payload = head + actual
            if raw.endswith(b"\xff"):
                if not raw.endswith(payload + b"\xff"):
                    return self.calculate_crc() or b""
                start = len(raw) - 1 - len(payload)
            else:
                if not raw.endswith(payload):
                    return self.calculate_crc() or b""
                start = len(raw) - len(payload)
            zeroed = bytearray(raw)
            content_off = start + len(head)
            for i in range(n):
                zeroed[content_off + i] = 0
            return defn.encode(defn.cls(bytes(zeroed)))
        return self.calculate_crc() or b""

    def check_crc(self) -> bool:
        crc_type = _as_int(self.getfieldval(self._crc_type_name))
        actual = _as_bytes(self.getfieldval(self._crc_value_name))
        if crc_type == int(CrcType.NONE):
            expect = b""
            valid = actual == b""
        else:
            defn = self._crc_definition()
            if defn is None:
                return False
            expect = self._crc_over_received_or_built(defn, actual)
            valid = actual == expect

        if not valid:
            log_runtime.warning(
                "CRC check failed for %s: expected %s, got %s",
                self.__class__.__name__,
                expect.hex(),
                actual.hex(),
            )

        return valid

    def validate(self, path: str = "") -> list[ValidationIssue]:
        issues = []
        crc_type = _as_int(self.getfieldval(self._crc_type_name))
        crc_value = self.getfieldval(self._crc_value_name)
        actual = _as_bytes(crc_value)
        if crc_type == int(CrcType.NONE) and actual:
            issues.append(
                ValidationIssue(
                    "unexpected-crc",
                    path,
                    "CRC value present when CRC type is NONE",
                )
            )
        elif crc_type != int(CrcType.NONE):
            defn = self._crc_definition()
            if defn is None:
                issues.append(
                    ValidationIssue(
                        "unsupported-crc-type",
                        path,
                        "Unsupported CRC type %d" % crc_type,
                    )
                )
            else:
                expect_len = defn.width
                if crc_value is None:
                    # None means "compute on build" — not a protocol error.
                    pass
                elif len(actual) != expect_len:
                    issues.append(
                        ValidationIssue(
                            "bad-crc-length",
                            path,
                            "CRC value length %d does not match type %s"
                            % (len(actual), CrcType(crc_type).name),
                        )
                    )
                elif not self.check_crc():
                    issues.append(
                        ValidationIssue("crc-mismatch", path, "CRC check failed")
                    )
        return issues


def _append_non_deterministic_issues(
    issues: list[ValidationIssue],
    raw: Optional[bytes],
    path: str,
) -> None:
    """Flag non-shortest encodings and indefinite items in block CBOR.

    RFC 9171 requires definite-length CBOR for primary and canonical blocks
    (only the outer bundle array is indefinite). Dissection still accepts
    indefinite block arrays for interop/fuzzing; ``validate()`` reports them.
    """
    if not raw:
        return
    for offset, message in cbor_find_non_deterministic(
        raw, allow_indefinite=False
    ):
        if message.startswith("Indefinite-length item"):
            code = "indefinite-length-cbor"
        else:
            code = "non-deterministic-cbor"
        issues.append(
            ValidationIssue(
                code,
                path,
                "%s at offset %d" % (message, offset),
            )
        )


class PrimaryBlock(CBOR_Packet, AbstractBlock):
    """The primary block definition"""

    @enum.unique
    class Flag(enum.IntFlag):
        """Bundle processing control flags."""

        REQ_DELETION_REPORT = 0x040000
        REQ_DELIVERY_REPORT = 0x020000
        REQ_FORWARDING_REPORT = 0x010000
        REQ_RECEPTION_REPORT = 0x004000
        REQ_STATUS_TIME = 0x000040
        USER_APP_ACK = 0x000020
        NO_FRAGMENT = 0x000004
        PAYLOAD_ADMIN = 0x000002
        IS_FRAGMENT = 0x000001

    def is_fragment(self) -> bool:
        flags = _as_int(self.getfieldval("bundle_flags"))
        return bool(flags & PrimaryBlock.Flag.IS_FRAGMENT)

    CBOR_root = CBORF_ARRAY(
        CBORF_UNSIGNED_INTEGER("version", default=7),
        CBORF_UNSIGNED_FLAGS(
            "bundle_flags", default=0, size=64, names=_enum_dict(Flag)
        ),
        CrcTypeField("crc_type", default=CrcType.NONE, enum=CrcType),
        BundleEidField("destination", default="dtn:none"),
        BundleEidField("source", default="dtn:none"),
        BundleEidField("report_to", default="dtn:none"),
        CBORF_PACKET("create_ts", default=BundleTimestamp(), cls=BundleTimestamp),
        CBORF_UNSIGNED_INTEGER("lifetime", default=0),
        CBORF_CONDITIONAL(
            CBORF_UNSIGNED_INTEGER("fragment_offset", default=0), cond=is_fragment
        ),
        CBORF_CONDITIONAL(
            CBORF_UNSIGNED_INTEGER("total_app_data_len", default=0), cond=is_fragment
        ),
        CBORF_CONDITIONAL(
            CrcBytesField("crc_value", default=None, definite_only=True),
            cond=AbstractBlock.has_crc
        ),
    )

    def mysummary(self):
        return self.sprintf(
            "BPv7 Primary %source% > %destination% crc=%crc_type%"
        )

    def self_build(self):
        return self._self_build_with_crc()

    def cbor_build_result(self):
        return AbstractBlock.cbor_build_result(self)

    def validate(self, path: str = "") -> list[ValidationIssue]:
        issues = super().validate(path)
        _append_non_deterministic_issues(
            issues, self.raw_packet_cache, path
        )
        if _as_int(self.getfieldval("version")) != 7:
            issues.append(
                ValidationIssue(
                    "bad-version",
                    path,
                    "Primary block version must be 7",
                )
            )
        flags = int(self.getfieldval("bundle_flags") or 0)
        if (flags & int(PrimaryBlock.Flag.IS_FRAGMENT)) and (
            flags & int(PrimaryBlock.Flag.NO_FRAGMENT)
        ):
            issues.append(
                ValidationIssue(
                    "conflicting-fragment-flags",
                    path,
                    "IS_FRAGMENT and NO_FRAGMENT must not both be set",
                )
            )
        for fname in ("destination", "source", "report_to"):
            eid = self.getfieldval(fname)
            if not isinstance(eid, EidStruct):
                continue
            if not eid.is_known_scheme():
                # Private-use / unallocated schemes stay opaque: Scapy cannot
                # apply dtn/ipn Node-ID rules, so only warn.
                issues.append(
                    ValidationIssue(
                        "unknown-scheme-eid",
                        "%s.%s" % (path, fname) if path else fname,
                        "EID scheme %d is not semantically validated "
                        "(private-use or unallocated)" % eid.scheme,
                        severity="warning",
                    )
                )
                continue
            if not eid.is_valid():
                issues.append(
                    ValidationIssue(
                        "invalid-eid",
                        "%s.%s" % (path, fname) if path else fname,
                        "EID is not a valid BPv7 endpoint identifier",
                    )
                )
            elif fname == "source" and (
                not eid.is_null_endpoint() and not eid.is_node_id()
            ):
                issues.append(
                    ValidationIssue(
                        "source-not-node-id",
                        "%s.source" % path if path else "source",
                        "Source must be the Null endpoint or a Node ID",
                    )
                )
        if self.is_fragment():
            if self.getfieldval("fragment_offset") is None:
                issues.append(
                    ValidationIssue(
                        "missing-fragment-offset",
                        path,
                        "Fragment offset required for fragments",
                    )
                )
            if self.getfieldval("total_app_data_len") is None:
                issues.append(
                    ValidationIssue(
                        "missing-total-app-data-len",
                        path,
                        "Total application data length required for fragments",
                    )
                )
            else:
                offset = self.getfieldval("fragment_offset")
                total = self.getfieldval("total_app_data_len")
                if (
                    offset is not None
                    and total is not None
                    and _as_int(offset) > _as_int(total)
                ):
                    issues.append(
                        ValidationIssue(
                            "fragment-offset-exceeds-total",
                            path,
                            "Fragment offset must not exceed total "
                            "application data length",
                        )
                    )
        return issues


class CanonicalBlock(CBOR_Packet, AbstractBlock):
    """The canonical block definition with a block-type-specific data (BTSD)
    field containing a dissected Packet.
    """

    @enum.unique
    class Flag(enum.IntFlag):
        """Block processing control flags"""

        REMOVE_IF_NO_PROCESS = 0x10
        DELETE_IF_NO_PROCESS = 0x04
        STATUS_IF_NO_PROCESS = 0x02
        REPLICATE_IN_FRAGMENT = 0x01

    _reg_types: ClassVar[dict[int, type[Packet]]] = {}
    _reg_codes: ClassVar[dict[type[Packet], int]] = {}

    @classmethod
    def register_type(cls, type_code: int) -> Callable[[type[Packet]], type[Packet]]:
        def reg(pkt_cls: type[Packet]) -> type[Packet]:
            bind_bpv7_block(type_code, pkt_cls)
            return pkt_cls

        return reg

    def inferred_type_code(self) -> Optional[int]:
        btsd = self.getfieldval("btsd")
        if btsd is None:
            return None
        return getattr(type(btsd), "BPV7_BLOCK_TYPE", None)

    def _effective_type_code(self) -> Optional[int]:
        type_code = self.getfieldval("type_code")
        if type_code is not None:
            return _as_int(type_code)
        return self.inferred_type_code()

    def btsd_class(self, data: bytes):
        type_code = self._effective_type_code()
        if type_code is not None:
            try:
                return self._reg_types[type_code]
            except KeyError:
                pass
        return None

    CBOR_root = CBORF_ARRAY(
        BlockTypeField("type_code", default=None),
        CBORF_UNSIGNED_INTEGER("block_num", default=None),
        CBORF_UNSIGNED_FLAGS("block_flags", default=0, size=64, names=_enum_dict(Flag)),
        CrcTypeField("crc_type", default=CrcType.NONE, enum=CrcType),
        CBORF_BYTE_STRING_PACKET(
            "btsd", default=None, cls_cb=btsd_class, definite_only=True
        ),
        CBORF_CONDITIONAL(
            CrcBytesField("crc_value", default=None, definite_only=True),
            cond=AbstractBlock.has_crc
        ),
    )

    def extract_padding(self, s):
        return None, s

    def self_build(self):
        return self._self_build_with_crc()

    def cbor_build_result(self):
        return AbstractBlock.cbor_build_result(self)

    def mysummary(self):
        return self.sprintf(
            "BPv7 Block #%block_num% type=%type_code% crc=%crc_type%"
        )

    def validate(self, path: str = "") -> list[ValidationIssue]:
        issues = super().validate(path)
        effective = self._effective_type_code()
        if effective is None:
            issues.append(
                ValidationIssue("missing-type-code", path, "Block type code is missing")
            )
        else:
            btsd = self.getfieldval("btsd")
            if btsd is not None:
                inferred = self.inferred_type_code()
                if inferred is not None and inferred != effective:
                    issues.append(
                        ValidationIssue(
                            "type-code-mismatch",
                            path,
                            "Block type code %d does not match BTSD type %d"
                            % (effective, inferred),
                        )
                    )
                if hasattr(btsd, "validate"):
                    issues.extend(btsd.validate(path + ".btsd"))
        if self.getfieldval("block_num") is None:
            issues.append(
                ValidationIssue("missing-block-num", path, "Block number is missing")
            )
        if self.getfieldval("btsd") is None:
            issues.append(ValidationIssue("missing-btsd", path, "BTSD is missing"))
        _append_non_deterministic_issues(
            issues, self.raw_packet_cache, path
        )
        btsd = self.getfieldval("btsd")
        # Only scan BTSD contents when the block-type data is itself CBOR.
        if isinstance(btsd, CBOR_Packet):
            btsd_raw = getattr(btsd, "raw_packet_cache", None)
            if not btsd_raw and hasattr(btsd, "original"):
                btsd_raw = btsd.original
            # Freshly composed CBOR BTSD may lack a received cache; build it
            # so deterministic-CBOR checks still cover newly generated data.
            if not btsd_raw:
                try:
                    btsd_raw = bytes(btsd)
                except Exception:
                    btsd_raw = None
            _append_non_deterministic_issues(
                issues, btsd_raw, path + ".btsd"
            )
        return issues


def bind_bpv7_block(type_code: int, pkt_cls: type[Packet]) -> type[Packet]:
    """Register a BTSD packet class for a canonical block type code.

    Analogous to ``bind_layers()``, but for embedded BTSD content rather than
    Scapy payload stacking.
    """
    existing = CanonicalBlock._reg_types.get(type_code)
    if existing is not None and existing is not pkt_cls:
        raise ValueError(
            "Block type code %d already registered to %s"
            % (type_code, existing.__name__)
        )
    prior = CanonicalBlock._reg_codes.get(pkt_cls)
    if prior is not None and prior != type_code:
        raise ValueError(
            "Block class %s already registered as type %d"
            % (pkt_cls.__name__, prior)
        )
    CanonicalBlock._reg_types[type_code] = pkt_cls
    CanonicalBlock._reg_codes[pkt_cls] = type_code
    pkt_cls.BPV7_BLOCK_TYPE = type_code
    return pkt_cls


def split_bpv7_block(type_code: int) -> None:
    """Unregister a previously bound BPv7 block type code."""
    pkt_cls = CanonicalBlock._reg_types.pop(type_code, None)
    if pkt_cls is not None:
        CanonicalBlock._reg_codes.pop(pkt_cls, None)
        if getattr(pkt_cls, "BPV7_BLOCK_TYPE", None) == type_code:
            try:
                delattr(pkt_cls, "BPV7_BLOCK_TYPE")
            except AttributeError:
                pass


@CanonicalBlock.register_type(6)
class PreviousNodeBlock(CBOR_Packet):
    """Block data content from Section 4.4.1 of RFC 9171."""

    CBOR_root = BundleEidField("node", default=None)

    def validate(self, path: str = "") -> list[ValidationIssue]:
        issues = []  # type: list[ValidationIssue]
        node = self.getfieldval("node")
        if node is None:
            issues.append(
                ValidationIssue(
                    "missing-previous-node",
                    path,
                    "Previous Node block requires a node ID",
                )
            )
        elif isinstance(node, EidStruct):
            if not node.is_known_scheme():
                issues.append(
                    ValidationIssue(
                        "unknown-scheme-eid",
                        path + ".node" if path else "node",
                        "EID scheme %d is not semantically validated "
                        "(private-use or unallocated)" % node.scheme,
                        severity="warning",
                    )
                )
            elif not node.is_valid():
                issues.append(
                    ValidationIssue(
                        "invalid-eid",
                        path + ".node" if path else "node",
                        "Previous Node EID is not a valid endpoint identifier",
                    )
                )
            elif not node.is_node_id():
                issues.append(
                    ValidationIssue(
                        "previous-node-not-node-id",
                        path + ".node" if path else "node",
                        "Previous Node must contain a Node ID",
                    )
                )
        return issues


@CanonicalBlock.register_type(7)
class BundleAgeBlock(CBOR_Packet):
    """Block data content from Section 4.4.2 of RFC 9171."""

    CBOR_root = CBORF_UNSIGNED_INTEGER("age", default=None)

    def validate(self, path: str = "") -> list[ValidationIssue]:
        issues = []  # type: list[ValidationIssue]
        age = self.getfieldval("age")
        if age is None:
            issues.append(
                ValidationIssue(
                    "missing-bundle-age",
                    path,
                    "Bundle Age block requires an age value",
                )
            )
        elif type(age) is not int or age < 0:
            issues.append(
                ValidationIssue(
                    "bad-bundle-age",
                    path,
                    "Bundle Age must be an unsigned integer",
                )
            )
        return issues


@CanonicalBlock.register_type(10)
class HopCountBlock(CBOR_Packet):
    """Block data content from Section 4.4.3 of RFC 9171."""

    CBOR_root = CBORF_ARRAY(
        CBORF_UNSIGNED_INTEGER("limit", default=None),
        CBORF_UNSIGNED_INTEGER("count", default=0),
    )

    def validate(self, path: str = "") -> list[ValidationIssue]:
        issues = []  # type: list[ValidationIssue]
        limit = self.getfieldval("limit")
        count = self.getfieldval("count")
        if limit is None or _as_int(limit) < 1 or _as_int(limit) > 255:
            issues.append(
                ValidationIssue(
                    "bad-hop-limit",
                    path,
                    "Hop Count limit must be in 1..255",
                )
            )
        if count is None:
            issues.append(
                ValidationIssue(
                    "missing-hop-count",
                    path,
                    "Hop Count block requires a count value",
                )
            )
        elif limit is not None and _as_int(count) > _as_int(limit):
            issues.append(
                ValidationIssue(
                    "hop-count-exceeds-limit",
                    path,
                    "Hop Count count must not exceed limit",
                )
            )
        return issues


class BundleV7(CBOR_Packet):
    """An entire decoded BPv7 bundle (primary block plus canonical blocks)."""

    BLOCK_TYPE_PAYLOAD = 1
    BLOCK_NUM_PAYLOAD = 1
    BLOCK_TYPE_PREVIOUS_NODE = 6
    BLOCK_TYPE_BUNDLE_AGE = 7
    BLOCK_TYPE_HOP_COUNT = 10
    STATUS_REPORT_FLAGS = (
        int(PrimaryBlock.Flag.REQ_DELETION_REPORT)
        | int(PrimaryBlock.Flag.REQ_DELIVERY_REPORT)
        | int(PrimaryBlock.Flag.REQ_FORWARDING_REPORT)
        | int(PrimaryBlock.Flag.REQ_RECEPTION_REPORT)
    )

    def _block_until_break(self, lst, cur, remain):
        if cbor_is_break(remain):
            return CBOR_NO_ITEM
        return CanonicalBlock

    CBOR_root = CBORF_ARRAY_INDEFINITE(
        CBORF_PACKET("primary", default=PrimaryBlock(), cls=PrimaryBlock),
        CBORF_SEQUENCE_OF(
            "blocks", default=[], next_cls_cb=_block_until_break
        ),
    )

    def mysummary(self):
        nblocks = len(self.blocks or [])
        return "BPv7 %s > %s (%d blocks)" % (
            self.primary.source if self.primary else "?",
            self.primary.destination if self.primary else "?",
            nblocks,
        )

    def check_crc(self) -> bool:
        return self.primary.check_crc() and all(blk.check_crc() for blk in self.blocks)

    def validate(
        self,
        primary_integrity_protected: bool = False,
    ) -> list[ValidationIssue]:
        issues = []
        raw = self.raw_packet_cache
        if raw:
            try:
                major_type, count, _ = CBOR_decode_head(raw)
                if major_type == 4 and count is not CBOR_INDEFINITE:
                    issues.append(
                        ValidationIssue(
                            "bundle-array-must-be-indefinite",
                            "",
                            "BPv7 bundle array must use indefinite length",
                        )
                    )
            except Exception:
                pass
            # Do not scan the whole bundle here: primary/canonical validates
            # already cover nested spans and would duplicate diagnostics.
        primary = self.primary
        if primary is not None:
            issues.extend(primary.validate("primary"))
        else:
            issues.append(
                ValidationIssue(
                    "missing-primary",
                    "primary",
                    "Primary block is missing",
                )
            )

        flags = 0
        source_text = ""
        create_dtntime = 0
        is_admin = False
        is_anonymous = False
        if primary is not None:
            flags = int(primary.getfieldval("bundle_flags") or 0)
            crc_type = _as_int(primary.getfieldval("crc_type"))
            if crc_type == int(CrcType.NONE) and not primary_integrity_protected:
                issues.append(
                    ValidationIssue(
                        "primary-crc-required",
                        "primary",
                        "Primary block requires a nonzero CRC type unless a "
                        "Block Integrity Block protects the primary block",
                    )
                )
            source = primary.getfieldval("source")
            if isinstance(source, EidStruct):
                is_anonymous = source.is_null_endpoint()
                source_text = source.to_text()
            elif hasattr(source, "to_text"):
                source_text = source.to_text()
                is_anonymous = source_text in (
                    "dtn:none", "ipn:0.0", "ipn:0.0.0"
                )
            else:
                source_text = str(source)
                try:
                    is_anonymous = EidStruct.from_text(source_text).is_null_endpoint()
                except Exception:
                    is_anonymous = source_text == "dtn:none"
            is_admin = bool(flags & int(PrimaryBlock.Flag.PAYLOAD_ADMIN))
            if is_anonymous and not (flags & int(PrimaryBlock.Flag.NO_FRAGMENT)):
                issues.append(
                    ValidationIssue(
                        "anonymous-source-must-not-fragment",
                        "primary",
                        "Anonymous source must set must-not-fragment",
                    )
                )
            if is_anonymous and (flags & self.STATUS_REPORT_FLAGS):
                issues.append(
                    ValidationIssue(
                        "anonymous-source-status-flags",
                        "primary",
                        "Anonymous source must not request status reports",
                    )
                )
            if is_admin and (flags & self.STATUS_REPORT_FLAGS):
                issues.append(
                    ValidationIssue(
                        "admin-record-status-flags",
                        "primary",
                        "Administrative records must not request status reports",
                    )
                )
            create_ts = primary.getfieldval("create_ts")
            if create_ts is not None:
                create_dtntime = _as_int(create_ts.getfieldval("dtntime") or 0)

        payload_blocks = []
        seen_nums: dict[int, int] = {}
        type_counts: dict[int, int] = {}
        for index, blk in enumerate(self.blocks):
            path = "blocks[%d]" % index
            if not isinstance(blk, CanonicalBlock):
                issues.append(
                    ValidationIssue(
                        "invalid-canonical-block",
                        path,
                        "Bundle blocks entry is not a CanonicalBlock",
                    )
                )
                continue
            issues.extend(blk.validate(path))
            type_code = blk._effective_type_code()
            if type_code is not None:
                type_counts[type_code] = type_counts.get(type_code, 0) + 1
            block_num = blk.getfieldval("block_num")
            if block_num is not None:
                bnum = _as_int(block_num)
                if bnum == 0:
                    issues.append(
                        ValidationIssue(
                            "canonical-block-uses-primary-number",
                            path,
                            "Canonical block number 0 is reserved",
                        )
                    )
                if bnum in seen_nums:
                    issues.append(
                        ValidationIssue(
                            "duplicate-block-num",
                            path,
                            "Block number %d already used at blocks[%d]"
                            % (bnum, seen_nums[bnum]),
                        )
                    )
                else:
                    seen_nums[bnum] = index
                if (
                    type_code != self.BLOCK_TYPE_PAYLOAD
                    and bnum == self.BLOCK_NUM_PAYLOAD
                ):
                    issues.append(
                        ValidationIssue(
                            "reserved-payload-block-num",
                            path,
                            "Non-payload block must not use block number 1",
                        )
                    )
            if type_code == self.BLOCK_TYPE_PAYLOAD:
                payload_blocks.append((index, block_num))
            if isinstance(blk, CanonicalBlock):
                block_flags = int(blk.getfieldval("block_flags") or 0)
                if block_flags & int(CanonicalBlock.Flag.STATUS_IF_NO_PROCESS):
                    if is_anonymous or is_admin:
                        issues.append(
                            ValidationIssue(
                                "forbidden-block-status-report",
                                path,
                                "Block status-report flag forbidden for "
                                "anonymous or administrative bundles",
                            )
                        )

        if type_counts.get(self.BLOCK_TYPE_PREVIOUS_NODE, 0) > 1:
            issues.append(
                ValidationIssue(
                    "duplicate-previous-node",
                    "blocks",
                    "At most one Previous Node block is allowed",
                )
            )
        age_count = type_counts.get(self.BLOCK_TYPE_BUNDLE_AGE, 0)
        if create_dtntime == 0 and age_count != 1:
            issues.append(
                ValidationIssue(
                    "bundle-age-required",
                    "blocks",
                    "Zero creation time requires exactly one Bundle Age block",
                )
            )
        if age_count > 1:
            issues.append(
                ValidationIssue(
                    "duplicate-bundle-age",
                    "blocks",
                    "At most one Bundle Age block is allowed",
                )
            )
        if type_counts.get(self.BLOCK_TYPE_HOP_COUNT, 0) > 1:
            issues.append(
                ValidationIssue(
                    "duplicate-hop-count",
                    "blocks",
                    "At most one Hop Count block is allowed",
                )
            )

        if not self.blocks:
            issues.append(
                ValidationIssue(
                    "missing-canonical-blocks",
                    "blocks",
                    "Bundle has no canonical blocks",
                )
            )
        if len(payload_blocks) == 0:
            issues.append(
                ValidationIssue(
                    "missing-payload",
                    "blocks",
                    "Bundle must contain exactly one payload block",
                )
            )
        elif len(payload_blocks) > 1:
            issues.append(
                ValidationIssue(
                    "bad-payload-count",
                    "blocks",
                    "Bundle must contain exactly one payload block",
                )
            )
        elif payload_blocks[0][0] != len(self.blocks) - 1:
            issues.append(
                ValidationIssue(
                    "payload-not-last",
                    "blocks[%d]" % payload_blocks[0][0],
                    "Payload block must be the last block",
                )
            )
        elif (
            payload_blocks[0][1] is None
            or _as_int(payload_blocks[0][1]) != self.BLOCK_NUM_PAYLOAD
        ):
            issues.append(
                ValidationIssue(
                    "bad-payload-block-num",
                    "blocks[%d]" % payload_blocks[0][0],
                    "Payload block number must be 1",
                )
            )
        elif (
            primary is not None
            and primary.is_fragment()
            and primary.getfieldval("fragment_offset") is not None
            and primary.getfieldval("total_app_data_len") is not None
        ):
            # RFC 9171: fragment ADU bytes must fit in [offset, total).
            offset = _as_int(primary.getfieldval("fragment_offset"))
            total = _as_int(primary.getfieldval("total_app_data_len"))
            payload_blk = self.blocks[payload_blocks[0][0]]
            btsd = payload_blk.getfieldval("btsd")
            payload_len = None  # type: Optional[int]
            if btsd is not None:
                load = getattr(btsd, "load", None)
                if isinstance(load, (bytes, bytearray)):
                    payload_len = len(load)
                else:
                    raw = getattr(btsd, "raw_packet_cache", None)
                    if not raw:
                        try:
                            raw = bytes(btsd)
                        except Exception:
                            raw = None
                    if raw is not None:
                        payload_len = len(raw)
            if payload_len is not None and offset + payload_len > total:
                issues.append(
                    ValidationIssue(
                        "fragment-extends-past-total",
                        "blocks[%d]" % payload_blocks[0][0],
                        "Fragment offset plus payload length must not "
                        "exceed total application data length",
                    )
                )
        return issues

    def validate_lifecycle(
        self,
        direction: str = "ingress",
        crossing_admin_domain: bool = False,
    ) -> list[ValidationIssue]:
        """Apply RFC 9758 context-dependent LocalNode / Private Use rules.

        Structural checks remain in :meth:`validate`. This method covers rules
        that require deployment context:

        - ``direction="ingress"``: externally received LocalNode source,
          destination, report-to, or Previous Node EIDs are invalid.
        - ``direction="egress"``: LocalNode source/destination/report-to
          (and Previous Node) EIDs must not leave the local node.
        - ``crossing_admin_domain=True``: Private Use IPN EIDs on those
          fields must not cross administrative domains.

        Call :meth:`assert_valid` with ``lifecycle=`` to combine both.
        """
        if direction not in ("ingress", "egress"):
            raise ValueError(
                "direction must be 'ingress' or 'egress', got %r" % direction
            )
        issues = []  # type: list[ValidationIssue]
        primary = self.primary
        if primary is None:
            return issues

        def _check_eid(eid: Any, path: str) -> None:
            if not isinstance(eid, EidStruct):
                return
            if eid.is_local_node():
                if direction == "ingress":
                    issues.append(
                        ValidationIssue(
                            "localnode-eid-on-ingress",
                            path,
                            "Externally received LocalNode IPN EIDs are invalid",
                        )
                    )
                else:
                    issues.append(
                        ValidationIssue(
                            "localnode-eid-on-egress",
                            path,
                            "LocalNode IPN EIDs must not leave the local node",
                        )
                    )
            elif crossing_admin_domain and eid.is_private_use():
                issues.append(
                    ValidationIssue(
                        "private-use-eid-cross-domain",
                        path,
                        "Private Use IPN EIDs must not cross administrative "
                        "domains",
                    )
                )

        for fname in ("destination", "source", "report_to"):
            _check_eid(
                primary.getfieldval(fname),
                "primary.%s" % fname,
            )

        for index, blk in enumerate(self.blocks or []):
            if not isinstance(blk, CanonicalBlock):
                continue
            if blk._effective_type_code() != self.BLOCK_TYPE_PREVIOUS_NODE:
                continue
            btsd = blk.getfieldval("btsd")
            if isinstance(btsd, PreviousNodeBlock):
                _check_eid(
                    btsd.getfieldval("node"),
                    "blocks[%d].btsd.node" % index,
                )
        return issues

    def assert_valid(
        self,
        primary_integrity_protected: bool = False,
        lifecycle: Optional[str] = None,
        crossing_admin_domain: bool = False,
    ) -> None:
        """Raise ``ValueError`` when structural (and optional lifecycle) errors exist.

        Warnings (e.g. ``unknown-scheme-eid``) do not fail this check.
        Pass ``lifecycle="ingress"`` or ``"egress"`` to also enforce
        :meth:`validate_lifecycle`.
        """
        issues = list(
            self.validate(
                primary_integrity_protected=primary_integrity_protected
            )
        )
        if lifecycle is not None:
            issues.extend(
                self.validate_lifecycle(
                    direction=lifecycle,
                    crossing_admin_domain=crossing_admin_domain,
                )
            )
        errors = [issue for issue in issues if issue.severity == "error"]
        if errors:
            raise ValueError(
                "\n".join(
                    "%s at %s: %s" % (issue.code, issue.path, issue.message)
                    for issue in errors
                )
            )
