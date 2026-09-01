# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Classes that implement CBOR (Concise Binary Object Representation) data
structures as packet fields.  Modelled after scapy/asn1fields.py.

Public leaf/compound hooks follow Scapy/ASN.1 style (``any2i`` / ``i2m`` /
``m2i``, ``build`` / ``dissect``). Compounds additionally use
``build_result`` / ``dissect_result`` so unframed sequences and array
budgeting can return an item count for raw-cache fidelity; callers outside
this module should prefer ``build`` / ``dissect``.
"""

import copy

from dataclasses import dataclass

from scapy.cbor.cbor import (
    CBOR_Decoding_Error,
    CBOR_Encoding_Error,
    CBOR_MajorTypes,
    CBOR_Object,
    CBOR_UNSIGNED_INTEGER,
    CBOR_NEGATIVE_INTEGER,
    CBOR_BYTE_STRING,
    CBOR_TEXT_STRING,
    CBOR_ARRAY,
    CBOR_SEMANTIC_TAG,
    CBOR_FALSE,
    CBOR_TRUE,
    CBOR_NULL,
    CBOR_UNDEFINED,
    CBOR_UNDEFINED_VALUE,
    CBOR_NO_ITEM,
    CBOR_FLOAT,
    CBOR_MAP,
    CBOR_SIMPLE_VALUE,
    CBORTagValue,
    CBORSimpleValue,
)
from scapy.cbor.cborcodec import (
    CBOR_Codec_Decoding_Error,
    CBOR_INDEFINITE,
    CBOR_decode_head,
    CBOR_encode_head,
    CBOR_encode_indefinite_head,
    CBOR_encode_break,
    cbor_is_break,
    cbor_consume_break,
    CBORcodec_Object,
    CBORcodec_UNSIGNED_INTEGER,
    CBORcodec_NEGATIVE_INTEGER,
    CBORcodec_BYTE_STRING,
    CBORcodec_TEXT_STRING,
    CBORcodec_SIMPLE_AND_FLOAT,
)
from scapy.error import log_runtime
from scapy.packet import Packet
from scapy.volatile import (
    RandChoice,
    RandFloat,
    RandNum,
    RandString,
    RandField,
)

from scapy import packet, fields, config

from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from scapy.cborpacket import CBOR_Packet  # noqa: F401


class CBORF_badsequence(Exception):
    pass


class CBOR_Type_Mismatch(CBOR_Decoding_Error):
    """Raised when a CBOR field encounters an unexpected major type."""


@dataclass(frozen=True)
class CBORBuildResult(object):
    """Encoded CBOR bytes and how many top-level items they contain."""
    data: bytes = b""
    items: int = 0


@dataclass(frozen=True)
class CBORParseResult(object):
    """Decoded value, unconsumed input, and items consumed."""
    value: Any = None
    remaining: bytes = b""
    items: int = 0


# Sentinel for an optional field that was not present on the wire.
# Distinct from Python ``None``, which encodes CBOR null for CBORF_ANY.
# Identity must survive copy/deepcopy used by Packet default caches.


class _CBORAbsent(object):
    def __repr__(self):
        # type: () -> str
        return "CBOR_ABSENT"

    def __copy__(self):
        # type: () -> _CBORAbsent
        return self

    def __deepcopy__(self, memo):
        # type: (dict) -> _CBORAbsent
        return self


CBOR_ABSENT = _CBORAbsent()


def cbor_item_span(s):
    # type: (bytes) -> Tuple[bytes, bytes]
    """Split *s* into the first well-formed CBOR item and the remainder."""
    _obj, remain = CBORcodec_Object.decode_cbor_item(s)
    if remain:
        return s[:-len(remain)], remain
    return s, b""


def _encode_exactly_one_cbor_item(val, context="value"):
    # type: (Any, str) -> bytes
    """Serialize *val* and require it to be exactly one well-formed CBOR item.

    Used by packet-valued fields so Raw/bytes/Packet fallbacks cannot claim
    ``items=1`` while emitting multiple or malformed CBOR items.
    """
    if hasattr(val, "cbor_build_result"):
        result = val.cbor_build_result()
        if result.items != 1:
            raise CBOR_Encoding_Error(
                "%s must encode exactly one top-level CBOR item, "
                "but encoded %d"
                % (getattr(type(val), "__name__", context), result.items)
            )
        data = result.data
    else:
        data = bytes(val)
    try:
        item, remaining = cbor_item_span(data)
    except Exception as exc:
        raise CBOR_Encoding_Error(
            "%s did not encode a well-formed CBOR item: %s"
            % (context, exc)
        )
    if remaining:
        raise CBOR_Encoding_Error(
            "%s encoded more than one top-level CBOR item"
            % context
        )
    if item != data:
        raise CBOR_Encoding_Error(
            "%s encoded a CBOR item that does not cover the full payload"
            % context
        )
    return data


def _cbor_attach_parent(parent, child):
    # type: (Optional[Packet], Any) -> Any
    """Attach *child* as a field-contained packet of *parent* (Scapy parent)."""
    if child is not None and parent is not None and hasattr(child, "add_parent"):
        child.add_parent(parent)
    return child


def _cbor_packet_from_bytes(cls, data, parent):
    # type: (Type[Packet], bytes, Optional[Packet]) -> Packet
    """Instantiate a nested packet with Scapy field-parent ownership."""
    return cls(data, _parent=parent)  # type: ignore


def cbor_object_to_python(obj):
    # type: (Any) -> Any
    """Convert a :class:`CBOR_Object` tree to native Python values."""
    if not isinstance(obj, CBOR_Object):
        return obj
    if isinstance(obj, CBOR_UNDEFINED):
        return CBOR_UNDEFINED_VALUE
    if isinstance(obj, CBOR_ARRAY):
        return [cbor_object_to_python(item) for item in obj.val]
    if isinstance(obj, CBOR_MAP):
        # Preserve an explicit map wrapper so rebuild cannot confuse maps
        # with arrays of pairs.
        from scapy.cbor.cbor import CBORMapData
        if isinstance(obj.val, CBORMapData):
            pairs = obj.val.cbor_pairs()
        elif isinstance(obj.val, list):
            pairs = obj.val
        else:
            pairs = list(obj.val.items())
        return CBORMapData([
            (cbor_object_to_python(k), cbor_object_to_python(v))
            for k, v in pairs
        ])
    if isinstance(obj, CBOR_SEMANTIC_TAG):
        tag_num, item = obj.val
        return CBORTagValue(tag_num, cbor_object_to_python(item))
    if isinstance(obj, CBOR_SIMPLE_VALUE):
        return CBORSimpleValue(obj.val)
    if isinstance(obj, CBOR_FLOAT):
        from scapy.cbor.cbor import CBORFloatValue
        return CBORFloatValue(obj.val, encoded=getattr(obj, "_encoded", None))
    return obj.val


class CBORF_element(object):
    """Base class for CBOR packet field elements."""

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        data = self.build(pkt)
        return CBORBuildResult(data, self.min_items(pkt))

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        remaining = self.dissect(pkt, s)
        return CBORParseResult(remaining=remaining, items=self.max_items(pkt))

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        raise NotImplementedError

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        raise NotImplementedError

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1


##########################
#    Basic CBOR Field    #
##########################

_I = TypeVar('_I')  # Internal storage


class CBORF_field(CBORF_element, Generic[_I]):
    """Base class for CBOR items in packet fields.

    Packet fields store native Python values (``int``, ``bytes``, ``str``,
    ``bool``, ``float``, ``list``, ``dict``, ``None``).
    """
    holds_packets = 0
    islist = 0
    ismutable = False
    allows_none = False
    CBOR_tag = None  # type: Optional[Any]

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[_I]
                 ):
        # type: (...) -> None
        self.name = name
        self.owners = []  # type: List[Type[CBOR_Packet]]
        # Mirror Scapy Field: normalize defaults through any2i().
        self.default = self.any2i(None, default)

    def register_owner(self, cls):
        # type: (Type[CBOR_Packet]) -> None
        self.owners.append(cls)

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, _I) -> str
        return repr(x)

    def i2h(self, pkt, x):
        # type: (CBOR_Packet, _I) -> Any
        return x

    def h2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> _I
        return cast(_I, x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[_I, bytes]
        raise NotImplementedError(
            "Subclasses must implement m2i for %s" % type(self))

    def encode_value(self, x):
        # type: (Any) -> bytes
        """Encode a native Python value to CBOR bytes.

        Prefer overriding :meth:`i2m` in new code; ``encode_value`` remains
        the shared leaf encoder used by the default :meth:`i2m`.
        """
        raise NotImplementedError(
            "Subclasses must implement encode_value for %s" % type(self))

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        """Convert internal value to CBOR wire bytes (Scapy build hook)."""
        if isinstance(x, fields.RawVal):
            data = bytes(x)
            try:
                item, remaining = cbor_item_span(data)
            except Exception as exc:
                raise CBOR_Encoding_Error(
                    "RawVal for %r is not well-formed CBOR: %s"
                    % (self.name, exc)
                )
            if remaining or item != data:
                raise CBOR_Encoding_Error(
                    "RawVal for %r must contain exactly one CBOR item"
                    % self.name
                )
            return data
        # Do not special-case None here: for CBORF_ANY, None is CBOR null.
        # Absent/optional skipping is handled in build_result().
        return self.encode_value(x)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> _I
        if x is CBOR_ABSENT or x is CBOR_UNDEFINED_VALUE or x is CBOR_NO_ITEM:
            return cast(_I, x)
        if isinstance(x, CBOR_Object):
            x = cbor_object_to_python(x)
        return self.h2i(pkt, x)

    def extract_packet(self,
                       cls,  # type: Type[CBOR_Packet]
                       s,  # type: bytes
                       _parent=None,  # type: Optional[CBOR_Packet]
                       ):
        # type: (...) -> Tuple[CBOR_Packet, bytes]
        try:
            c = cls(s, _parent=_parent)
        except CBORF_badsequence:
            c = packet.Raw(s, _parent=_parent)  # type: ignore
        craw = c.getlayer(config.conf.raw_layer)
        cpad = c.getlayer(config.conf.padding_layer)
        s = b""
        if craw is not None:
            s = craw.load
            if craw.underlayer:
                del craw.underlayer.payload
        if cpad is not None:
            s = cpad.load
            if cpad.underlayer:
                del cpad.underlayer.payload
        return c, s

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        val = pkt.getfieldval(self.name)
        if val is None:
            if self.allows_none:
                return CBORBuildResult(b"", 0)
            raise CBOR_Encoding_Error(
                "Required field %r is None" % self.name)
        return CBORBuildResult(self.i2m(pkt, val), 1)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        val, remain = self.m2i(pkt, s)
        self.set_val(pkt, val)
        return CBORParseResult(remaining=remain, items=1)

    def parse_value(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        """Decode a free value without assigning it onto *pkt*."""
        val, remain = self.m2i(pkt, s)
        return CBORParseResult(value=val, remaining=remain, items=1)

    def build_value(self, pkt, value):
        # type: (CBOR_Packet, Any) -> CBORBuildResult
        """Encode *value* without reading it from *pkt* fields."""
        return CBORBuildResult(
            data=self.i2m(pkt, self.any2i(pkt, value)),
            items=1,
        )

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def do_copy(self, x):
        # type: (Any) -> Any
        if x is CBOR_ABSENT or x is CBOR_UNDEFINED_VALUE or x is CBOR_NO_ITEM:
            return x
        if isinstance(x, list):
            return copy.deepcopy(x)
        if hasattr(x, "copy"):
            try:
                return x.copy()
            except TypeError:
                pass
        return copy.deepcopy(x)

    def set_val(self, pkt, val):
        # type: (CBOR_Packet, Any) -> None
        if val is CBOR_ABSENT:
            # Bypass any2i so presence sentinel is stored verbatim.
            pkt.fields[self.name] = CBOR_ABSENT
            pkt.explicit = 0
            pkt.raw_packet_cache = None
            pkt.raw_packet_cache_fields = None
            pkt.wirelen = None
            return
        pkt.setfieldval(self.name, val)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        val = pkt.getfieldval(self.name)
        return val is None or val is CBOR_ABSENT

    def matches_next_item(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bool
        """Return True if the next CBOR item matches this field's outer type."""
        if not s or cbor_is_break(s):
            return False
        try:
            major_type, _info, _rem = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error:
            return False
        tag = self.CBOR_tag
        if tag is None:
            return True
        return major_type == int(tag)

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any]]
        return [self]

    def __str__(self):
        # type: () -> str
        return repr(self)

    def randval(self):
        # type: () -> RandField[_I]
        return cast(RandField[_I], RandNum(0, 2 ** 32))

    def copy(self):
        # type: () -> CBORF_field[_I]
        return copy.copy(self)


class CBORF_ANY(CBORF_field[Any]):
    """Represent any well-formed CBOR value, including recursion."""
    ismutable = True
    # Treat composites as atomic values so Packet.__iter__/do_build does not
    # expand a decoded CBOR array into individual generator elements.
    islist = 1

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        # Python None is CBOR null; only CBOR_ABSENT means "no item".
        return pkt.getfieldval(self.name) is CBOR_ABSENT

    def matches_next_item(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bool
        if not s or cbor_is_break(s):
            return False
        try:
            CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error:
            return False
        return True

    def do_copy(self, x):  # type: ignore[override]
        # type: (Any) -> Any
        if x is CBOR_ABSENT or x is CBOR_UNDEFINED_VALUE or x is CBOR_NO_ITEM:
            return x
        # Deep-copy composites so in-place nested mutations invalidate cache.
        return copy.deepcopy(x)

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        val = pkt.getfieldval(self.name)
        if val is CBOR_ABSENT:
            return CBORBuildResult(b"", 0)
        return CBORBuildResult(self.i2m(pkt, val), 1)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[Any, bytes]
        obj, remain = CBORcodec_Object.decode_cbor_item(s)
        return cbor_object_to_python(obj), remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        if x is CBOR_ABSENT:
            return b""
        if isinstance(x, CBOR_Object):
            x = cbor_object_to_python(x)
        return CBORcodec_Object.encode_cbor_item(x)


#############################
#    Simple CBOR Fields     #
#############################

class CBORF_UNSIGNED_INTEGER(CBORF_field[int]):
    """CBOR unsigned integer field (major type 0)."""
    CBOR_tag = CBOR_MajorTypes.UNSIGNED_INTEGER

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> int
        if isinstance(x, CBOR_Object):
            x = x.val
        if x is None:
            return None  # type: ignore
        i = int(x)
        if i < 0 or i > 0xFFFFFFFFFFFFFFFF:
            raise CBOR_Encoding_Error(
                "Unsigned integer out of CBOR range: %r" % (i,))
        return i

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[int, bytes]
        obj, remain = CBORcodec_UNSIGNED_INTEGER.dec(s)
        if not isinstance(obj, CBOR_UNSIGNED_INTEGER):
            raise CBOR_Type_Mismatch(
                "Expected unsigned integer, got %r" % obj)
        return obj.val, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_UNSIGNED_INTEGER.enc(int(x))

    def randval(self):
        # type: () -> RandNum
        return RandNum(0, 2 ** 64 - 1)


class CBORF_NEGATIVE_INTEGER(CBORF_field[int]):
    """CBOR negative integer field (major type 1)."""
    CBOR_tag = CBOR_MajorTypes.NEGATIVE_INTEGER

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> int
        if isinstance(x, CBOR_Object):
            x = x.val
        if x is None:
            return None  # type: ignore
        i = int(x)
        if i >= 0 or i < -(1 << 64):
            raise CBOR_Encoding_Error(
                "Negative integer out of CBOR range: %r" % (i,))
        return i

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[int, bytes]
        obj, remain = CBORcodec_NEGATIVE_INTEGER.dec(s)
        if not isinstance(obj, CBOR_NEGATIVE_INTEGER):
            raise CBOR_Type_Mismatch(
                "Expected negative integer, got %r" % obj)
        return obj.val, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_NEGATIVE_INTEGER.enc(int(x))

    def randval(self):
        # type: () -> RandNum
        return RandNum(-2 ** 64, -1)


class CBORF_INTEGER(CBORF_field[int]):
    """CBOR integer field handling both positive and negative values."""

    def matches_next_item(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bool
        if not s or cbor_is_break(s):
            return False
        try:
            major_type, _info, _rem = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error:
            return False
        return major_type in (0, 1)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> int
        if isinstance(x, CBOR_Object):
            x = x.val
        if x is None:
            return None  # type: ignore
        i = int(x)
        if i < -(1 << 64) or i > 0xFFFFFFFFFFFFFFFF:
            raise CBOR_Encoding_Error(
                "Integer out of CBOR range: %r" % (i,))
        return i

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[int, bytes]
        if not s:
            raise CBOR_Decoding_Error("Empty CBOR data")
        major_type = (s[0] >> 5) & 0x7
        if major_type == 0:
            obj, remain = CBORcodec_UNSIGNED_INTEGER.dec(s)
            return obj.val, remain
        elif major_type == 1:
            obj, remain = CBORcodec_NEGATIVE_INTEGER.dec(s)
            return obj.val, remain
        raise CBOR_Type_Mismatch(
            "Expected integer (major type 0 or 1), got %d" % major_type)

    def encode_value(self, x):
        # type: (Any) -> bytes
        i = int(x)
        if i >= 0:
            return CBORcodec_UNSIGNED_INTEGER.enc(i)
        return CBORcodec_NEGATIVE_INTEGER.enc(i)

    def randval(self):
        # type: () -> RandNum
        return RandNum(-2 ** 64, 2 ** 64 - 1)


class CBORF_BYTE_STRING(CBORF_field[bytes]):
    """CBOR byte string field (major type 2)."""
    CBOR_tag = CBOR_MajorTypes.BYTE_STRING

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[bytes]
                 definite_only=False,  # type: bool
                 ):
        # type: (...) -> None
        super(CBORF_BYTE_STRING, self).__init__(name, default)
        self.definite_only = definite_only

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        if isinstance(x, CBOR_Object):
            x = x.val
        if x is None:
            return None  # type: ignore
        return bytes(x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[bytes, bytes]
        if self.definite_only:
            try:
                major_type, length, _rem = CBOR_decode_head(s)
            except CBOR_Codec_Decoding_Error as e:
                raise CBOR_Decoding_Error(str(e))
            if major_type != 2:
                raise CBOR_Type_Mismatch(
                    "Expected byte string, got major type %d" % major_type)
            if length is CBOR_INDEFINITE:
                raise CBOR_Decoding_Error(
                    "Indefinite-length byte string not allowed here")
        obj, remain = CBORcodec_BYTE_STRING.dec(s)
        if not isinstance(obj, CBOR_BYTE_STRING):
            raise CBOR_Type_Mismatch(
                "Expected byte string, got %r" % obj)
        return obj.val, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        data = bytes(x)
        if self.definite_only:
            # Always emit definite form (codec already does).
            pass
        return CBORcodec_BYTE_STRING.enc(data)

    def randval(self):
        # type: () -> RandString
        return RandString(RandNum(0, 1000))


class CBORF_BYTE_STRING_PACKET(CBORF_field[Packet]):
    """CBOR byte string which wraps another packet field.

    The inner packet may or may not itself be CBOR or CBOR sequence data.
    """
    CBOR_tag = CBOR_MajorTypes.BYTE_STRING
    holds_packets = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[Packet]
                 pkt_cls=None,  # type: Optional[Type[Packet]]
                 cls_cb=None,  # type: Optional[Callable[[Packet, bytes], Optional[Type[Packet]]]]  # noqa: E501
                 definite_only=False,  # type: bool
                 ):
        # type: (...) -> None
        if pkt_cls is None and cls_cb is None:
            raise ValueError('Must give one of pkt_cls or cls_cb')
        # any2i() needs these during default normalization in super().__init__.
        self.pkt_cls = pkt_cls
        self.cls_cb = cls_cb
        self.definite_only = definite_only
        super(CBORF_BYTE_STRING_PACKET, self).__init__(name, default)

    def _resolve_packet_class(self, pkt, data):
        # type: (CBOR_Packet, bytes) -> Tuple[Optional[Type[Packet]], bool]
        if self.pkt_cls is not None:
            return self.pkt_cls, True
        if self.cls_cb is not None:
            pkt_cls = self.cls_cb(pkt, data)
            return pkt_cls, pkt_cls is not None
        return None, False

    def _decode_packet_value(self, pkt, data):
        # type: (CBOR_Packet, bytes) -> Packet
        pkt_cls, registered = self._resolve_packet_class(pkt, data)
        if pkt_cls is None:
            return _cbor_packet_from_bytes(packet.Raw, data, pkt)
        try:
            return _cbor_packet_from_bytes(pkt_cls, data, pkt)
        except Exception as exc:
            if registered:
                raise CBOR_Decoding_Error(
                    "Failed to decode registered block-type-specific data: %s"
                    % exc
                )
            log_runtime.exception(
                "Failed to decode byte string content to %s", pkt_cls)
            return _cbor_packet_from_bytes(packet.Raw, data, pkt)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> Packet
        if isinstance(x, CBOR_BYTE_STRING):
            x = x.val
        if isinstance(x, (bytes, bytearray)):
            return self._decode_packet_value(pkt, bytes(x))
        return _cbor_attach_parent(pkt, x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[Packet, bytes]
        if self.definite_only:
            try:
                major_type, length, _rem = CBOR_decode_head(s)
            except CBOR_Codec_Decoding_Error as e:
                raise CBOR_Decoding_Error(str(e))
            if major_type != 2:
                raise CBOR_Type_Mismatch(
                    "Expected byte string, got major type %d" % major_type)
            if length is CBOR_INDEFINITE:
                raise CBOR_Decoding_Error(
                    "Indefinite-length byte string not allowed here")
        obj, remain = CBORcodec_BYTE_STRING.dec(s)
        if not isinstance(obj, CBOR_BYTE_STRING):
            raise CBOR_Type_Mismatch(
                "Expected byte string, got %r" % obj)
        return self._decode_packet_value(pkt, obj.val), remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_BYTE_STRING.enc(bytes(x))


class CBORF_TEXT_STRING(CBORF_field[str]):
    """CBOR text string field (major type 3)."""
    CBOR_tag = CBOR_MajorTypes.TEXT_STRING

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> str
        if isinstance(x, CBOR_Object):
            x = x.val
        if x is None:
            return None  # type: ignore
        # Reject bytes: str(b"hi") == "b'hi'", which silently corrupts the value.
        if isinstance(x, (bytes, bytearray, memoryview)):
            raise TypeError(
                "CBOR text string field %r requires str, got %s"
                % (self.name, type(x).__name__)
            )
        return str(x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[str, bytes]
        obj, remain = CBORcodec_TEXT_STRING.dec(s)
        if not isinstance(obj, CBOR_TEXT_STRING):
            raise CBOR_Type_Mismatch(
                "Expected text string, got %r" % obj)
        return obj.val, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_TEXT_STRING.enc(str(x))

    def randval(self):
        # type: () -> RandString
        return RandString(RandNum(0, 1000))


class CBORF_BOOLEAN(CBORF_field[bool]):
    """CBOR boolean field (major type 7, simple values 20/21)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def matches_next_item(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bool
        if not s or cbor_is_break(s):
            return False
        ai = s[0] & 0x1f
        return ((s[0] >> 5) & 0x7) == 7 and ai in (20, 21)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bool
        if x is CBOR_ABSENT:
            return CBOR_ABSENT  # type: ignore
        if x is None:
            return None  # type: ignore
        if isinstance(x, (CBOR_FALSE, CBOR_TRUE)):
            return x.val
        if isinstance(x, CBOR_Object):
            return bool(x.val)
        return bool(x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[bool, bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, (CBOR_FALSE, CBOR_TRUE)):
            raise CBOR_Type_Mismatch(
                "Expected boolean (CBOR_FALSE or CBOR_TRUE), got %r" % obj)
        return obj.val, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_SIMPLE_AND_FLOAT.enc(bool(x))

    def randval(self):
        # type: () -> RandChoice
        return RandChoice(True, False)


class CBORF_NULL(CBORF_field[None]):
    """CBOR null field (major type 7, simple value 22)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT
    allows_none = True

    def __init__(self,
                 name,  # type: str
                 default=None,  # type: None
                 ):
        # type: (...) -> None
        super(CBORF_NULL, self).__init__(name, None)

    def matches_next_item(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bool
        if not s or cbor_is_break(s):
            return False
        return s[0] == 0xf6

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> None
        if x is CBOR_ABSENT:
            return CBOR_ABSENT  # type: ignore
        return None

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[None, bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, CBOR_NULL):
            raise CBOR_Type_Mismatch(
                "Expected null, got %r" % obj)
        return None, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBOR_NULL().enc()

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        if pkt.getfieldval(self.name) is CBOR_ABSENT:
            return CBORBuildResult(b"", 0)
        return CBORBuildResult(self.encode_value(None), 1)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return pkt.getfieldval(self.name) is CBOR_ABSENT

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1


class CBORF_UNDEFINED(CBORF_field[None]):
    """CBOR undefined field (major type 7, simple value 23)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT
    allows_none = True

    def __init__(self,
                 name,  # type: str
                 default=None,  # type: None
                 ):
        # type: (...) -> None
        super(CBORF_UNDEFINED, self).__init__(name, None)

    def matches_next_item(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bool
        if not s or cbor_is_break(s):
            return False
        return s[0] == 0xf7

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> None
        if x is CBOR_ABSENT:
            return CBOR_ABSENT  # type: ignore
        return None

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[None, bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, CBOR_UNDEFINED):
            raise CBOR_Type_Mismatch(
                "Expected undefined, got %r" % obj)
        return None, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBOR_UNDEFINED().enc()

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        if pkt.getfieldval(self.name) is CBOR_ABSENT:
            return CBORBuildResult(b"", 0)
        return CBORBuildResult(self.encode_value(None), 1)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return pkt.getfieldval(self.name) is CBOR_ABSENT

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1


class CBORF_FLOAT(CBORF_field[float]):
    """CBOR float field (major type 7).

    Dissected values retain the received encoding (half / single / double,
    including NaN payloads) via :class:`~scapy.cbor.cbor.CBORFloatValue`.
    Assigning a plain ``float`` uses preferred serialization on the next
    rebuild.
    """
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def matches_next_item(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bool
        if not s or cbor_is_break(s):
            return False
        ai = s[0] & 0x1f
        return ((s[0] >> 5) & 0x7) == 7 and ai in (25, 26, 27)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> float
        from scapy.cbor.cbor import CBORFloatValue
        if x is CBOR_ABSENT:
            return CBOR_ABSENT  # type: ignore
        if x is None:
            return None  # type: ignore
        if isinstance(x, CBORFloatValue):
            return x
        if isinstance(x, CBOR_FLOAT):
            return CBORFloatValue(x.val, encoded=x._encoded)
        if isinstance(x, CBOR_Object):
            return float(cbor_object_to_python(x))
        return float(x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[float, bytes]
        from scapy.cbor.cbor import CBORFloatValue
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, CBOR_FLOAT):
            raise CBOR_Type_Mismatch(
                "Expected float, got %r" % obj)
        return CBORFloatValue(obj.val, encoded=obj._encoded), remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        from scapy.cbor.cbor import CBORFloatValue
        if isinstance(x, CBOR_FLOAT):
            return x.enc()
        if isinstance(x, CBORFloatValue) and x.cbor_encoded is not None:
            return x.cbor_encoded
        return CBORcodec_SIMPLE_AND_FLOAT.enc(float(x))

    def i2h(self, pkt, x):
        # type: (CBOR_Packet, Any) -> Any
        if isinstance(x, CBOR_FLOAT):
            return x.val
        return x

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, Any) -> str
        if isinstance(x, CBOR_FLOAT):
            return repr(x.val)
        return repr(x)

    def randval(self):
        # type: () -> RandFloat
        return RandFloat(0, 2 ** 32)


##############################
#    Structured CBOR Fields  #
##############################

class CBORF_UNSIGNED_ENUM(CBORF_UNSIGNED_INTEGER):
    """
    Display like EnumField, codec like CBORF
    """
    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[int]
                 enum,  # type: fields._EnumType[int]
                 ):
        # type: (...) -> None
        self._enum = fields.EnumField(name, default, enum, "Q")
        CBORF_UNSIGNED_INTEGER.__init__(self, name, default)

    def i2repr(self, pkt, x):
        return self._enum.i2repr(pkt, x)

    def any2i(self, pkt, x):
        if isinstance(x, CBOR_Object):
            x = x.val
        x = self._enum.any2i(pkt, x)
        return super().any2i(pkt, x)


class CBORF_UNSIGNED_FLAGS(CBORF_UNSIGNED_INTEGER):
    """
    Display like FlagsField, codec like CBORF
    """
    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[Union[int, fields.FlagValue]]
                 size,  # type: int
                 names,  # type: Union[List[str], str, Dict[int, str]]
                 ):
        # type: (...) -> None
        self._flags = fields.FlagsField(name, default, size, names)
        CBORF_UNSIGNED_INTEGER.__init__(self, name, default)

    def i2repr(self, pkt, x):
        return self._flags.i2repr(pkt, x)

    def any2i(self, pkt, x):
        if isinstance(x, CBOR_Object):
            x = x.val
        x = self._flags.any2i(pkt, x)
        return super().any2i(pkt, x)


class _CBORF_compound(CBORF_element):
    """Shared helpers for sequence-like CBOR field containers."""
    CBOR_tag = None
    holds_packets = 1

    def __init__(self, *seq, **kwargs):
        # type: (*Any, **Any) -> None
        self.seq = seq
        self.islist = len(seq) > 1

    def __repr__(self):
        # type: () -> str
        return "<%s%r>" % (self.__class__.__name__, self.seq)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return all(f.is_empty(pkt) for f in self.seq)

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any]]
        return [
            child
            for field in self.seq
            for child in field.get_fields_list()
        ]

    def _build_children(self, pkt):
        # type: (CBOR_Packet) -> Tuple[bytes, int]
        parts = []  # type: List[bytes]
        total_items = 0
        for field in self.seq:
            result = field.build_result(pkt)
            parts.append(result.data)
            total_items += result.items
        return b"".join(parts), total_items

    def _mark_absent(self, pkt, field):
        # type: (CBOR_Packet, Any) -> None
        """Record that an optional/conditional field was not present."""
        if isinstance(field, CBORF_optional):
            field._field.set_val(pkt, CBOR_ABSENT)
        elif isinstance(field, CBORF_CONDITIONAL):
            # Condition false or skipped: leave value untouched.
            pass

    def _dissect_children(self, pkt, s, count):
        # type: (CBOR_Packet, bytes, Union[int, CBOR_INDEFINITE]) -> bytes
        remaining = s
        if count is CBOR_INDEFINITE:
            # Count items with a memoryview cursor (no suffix copies / span).
            if not isinstance(remaining, memoryview):
                view = memoryview(remaining)
            else:
                view = remaining
            probe = view
            item_count = 0
            while probe and not cbor_is_break(probe):
                _obj, probe = CBORcodec_Object.decode_cbor_item(probe)
                item_count += 1
            remaining = self._dissect_children_budgeted(
                pkt, remaining, item_count
            )
            return cbor_consume_break(remaining)

        return self._dissect_children_budgeted(pkt, remaining, count)

    def _dissect_children_budgeted(self, pkt, s, count):
        # type: (CBOR_Packet, bytes, int) -> bytes
        remaining = s
        items_left = count
        for index, field in enumerate(self.seq):
            reserved = sum(
                f.min_items(pkt) for f in self.seq[index + 1:]
            )
            available = items_left - reserved
            needed = field.min_items(pkt)
            if available < 0:
                raise CBOR_Decoding_Error("CBOR item count mismatch")
            if available < needed:
                raise CBOR_Decoding_Error("CBOR item count mismatch")
            if available == 0:
                if needed > 0:
                    raise CBOR_Decoding_Error("CBOR item count mismatch")
                # Zero budget: later required fields reserved every remaining
                # item. Optionals stay absent for reservation, but a *matching*
                # optional must still be well-formed — otherwise a malformed
                # present value would silently migrate into a trailing ANY.
                if (
                    isinstance(field, CBORF_optional)
                    and remaining
                    and field._field.matches_next_item(pkt, remaining)
                ):
                    probe = pkt.__class__()
                    try:
                        field.dissect_result(probe, remaining)
                    except CBORF_badsequence:
                        pass
                    # CBOR_Decoding_Error / Type_Mismatch propagate.
                self._mark_absent(pkt, field)
                continue
            try:
                if isinstance(field, CBORF_SEQUENCE_OF):
                    result = field.dissect_result(
                        pkt, remaining, max_items=available
                    )
                elif isinstance(field, CBORF_optional):
                    if not field._field.matches_next_item(pkt, remaining):
                        self._mark_absent(pkt, field)
                        continue
                    result = field.dissect_result(pkt, remaining)
                else:
                    result = field.dissect_result(pkt, remaining)
            except CBORF_badsequence:
                if needed > 0:
                    raise CBOR_Decoding_Error("CBOR item count mismatch")
                self._mark_absent(pkt, field)
                continue
            if result.items > items_left:
                raise CBOR_Decoding_Error(
                    "CBOR field consumed more items than remaining"
                )
            if result.items == 0:
                self._mark_absent(pkt, field)
            remaining = result.remaining
            items_left -= result.items
        if items_left != 0:
            raise CBOR_Decoding_Error("CBOR item count mismatch")
        return remaining


class CBORF_SEQUENCE(_CBORF_compound):
    """
    Unframed fixed sequence of named, typed fields (no CBOR array head).

    Unlike :class:`CBORF_ARRAY`, this emits/consumes a stream of top-level
    CBOR items. Use it when a schema is a field list without a major-type-4
    envelope (ASN.1 SEQUENCE analogy belongs on :class:`CBORF_ARRAY`).

    Example::

        class MyCBOR(CBOR_Packet):
            CBOR_root = CBORF_SEQUENCE(
                CBORF_INTEGER("version", 1),
                CBORF_TEXT_STRING("name", ""),
            )
    """

    def __init__(self, *seq, **kwargs):
        # type: (*Any, **Any) -> None
        super(CBORF_SEQUENCE, self).__init__(*seq, **kwargs)
        self._reject_ambiguous_unbounded_sequences()

    def _reject_ambiguous_unbounded_sequences(self):
        # type: () -> None
        CBORF_ARRAY._reject_ambiguous_unbounded_sequences(self)

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        data, total_items = self._build_children(pkt)
        return CBORBuildResult(data, total_items)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        # Count only up to this schema's max so trailing CBOR items remain for
        # a parent (e.g. Raw / Padding), matching definite ARRAY roots.
        view = memoryview(s) if not isinstance(s, memoryview) else s
        probe = view
        item_count = 0
        max_count = self.max_items(pkt)
        while probe and not cbor_is_break(probe) and item_count < max_count:
            _obj, probe = CBORcodec_Object.decode_cbor_item(probe)
            item_count += 1
        remaining = self._dissect_children_budgeted(pkt, s, item_count)
        return CBORParseResult(remaining=remaining, items=item_count)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return sum(f.min_items(pkt) for f in self.seq)

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return sum(f.max_items(pkt) for f in self.seq)


class CBORF_ARRAY(_CBORF_compound):
    """
    CBOR array with a fixed sequence of named, typed fields (major type 4).

    Analogous to ASN1F_SEQUENCE: each positional element is a
    :class:`CBORF_field`, wrapped in one definite (or indefinite) CBOR array.
    Prefer this over :class:`CBORF_SEQUENCE` when the wire form is a single
    array item.

    Example::

        class MyCBOR(CBOR_Packet):
            CBOR_root = CBORF_ARRAY(
                CBORF_INTEGER("version", 1),
                CBORF_TEXT_STRING("name", ""),
            )
    """
    CBOR_tag = CBOR_MajorTypes.ARRAY

    encode_indefinite = False
    """Set to true to encode using indefinite length."""

    def __init__(self, *seq, **kwargs):
        # type: (*Any, **Any) -> None
        super(CBORF_ARRAY, self).__init__(*seq, **kwargs)
        self._reject_ambiguous_unbounded_sequences()

    def _reject_ambiguous_unbounded_sequences(self):
        # type: () -> None
        def _unbounded(field):
            # type: (Any) -> bool
            if isinstance(field, CBORF_optional):
                return False
            if isinstance(field, CBORF_CONDITIONAL):
                return False
            return (
                isinstance(field, CBORF_SEQUENCE_OF)
                or (
                    hasattr(field, "min_items")
                    and hasattr(field, "max_items")
                    and field.min_items(None) == 0  # type: ignore[arg-type]
                    and field.max_items(None) > 1  # type: ignore[arg-type]
                )
            )

        def _skippable(field):
            # type: (Any) -> bool
            return isinstance(field, (CBORF_optional, CBORF_CONDITIONAL))

        unbounded_indexes = [
            index for index, field in enumerate(self.seq) if _unbounded(field)
        ]
        for left, right in zip(unbounded_indexes, unbounded_indexes[1:]):
            # Adjacent unbounded fields, or unbounded fields separated only by
            # optional/conditional fillers, cannot be partitioned uniquely.
            if all(_skippable(self.seq[i]) for i in range(left + 1, right)):
                raise ValueError(
                    "Ambiguous unbounded CBOR sequences in array schema"
                )

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        items_data, total_items = self._build_children(pkt)
        if self.encode_indefinite:
            data = (
                CBOR_encode_indefinite_head(int(CBOR_MajorTypes.ARRAY)) +
                items_data +
                CBOR_encode_break()
            )
        else:
            data = CBOR_encode_head(int(CBOR_MajorTypes.ARRAY), total_items)
            data += items_data
        return CBORBuildResult(data, 1)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        try:
            major_type, count, remaining = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 4:
            raise CBOR_Type_Mismatch(
                "Expected major type 4 (array), got %d" % major_type)
        remaining = self._dissect_children(pkt, remaining, count)
        return CBORParseResult(remaining=remaining, items=1)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1


class CBORF_ARRAY_INDEFINITE(CBORF_ARRAY):
    """A field to act as an array but to always encode to indefinite-length."""

    encode_indefinite = True


_ARRAY_T = Union[
    'CBOR_Packet',
    Type['CBORF_field[Any]'],
    'CBORF_PACKET',
    'CBORF_field[Any]',
]


class CBORF_SEQUENCE_OF(CBORF_field[List[Any]]):
    """
    Unframed sequence of homogeneous elements (no CBOR array head).

    Preferred constructors (ASN1F_SEQUENCE_OF / PacketListField style)::

        CBORF_SEQUENCE_OF("items", [], cls=MyPacket)
        CBORF_SEQUENCE_OF("items", [], cls=CBORF_UNSIGNED_INTEGER)
        CBORF_SEQUENCE_OF("items", [], next_cls_cb=choose_next)

    ``pkt_cls`` is accepted as an alias of ``cls`` for PacketListField
    familiarity. Pass only one of ``cls`` / ``pkt_cls`` / ``next_cls_cb``.
    """
    CBOR_tag = None
    islist = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 cls=None,  # type: _ARRAY_T
                 pkt_cls=None,  # type: Optional[Type[Packet]]
                 next_cls_cb=None,  # type: Optional[Callable[..., Optional[Type[Packet]]]]  # noqa: E501
                 ):
        # type: (...) -> None
        self.next_cls_cb = None  # type: Optional[Callable[..., Optional[Type[Packet]]]]
        self.cls = None
        self.item_field = None
        self.holds_packets = 0

        if next_cls_cb is not None:
            if cls is not None or pkt_cls is not None:
                raise ValueError(
                    "Pass only next_cls_cb, or only cls/pkt_cls"
                )
            self.next_cls_cb = next_cls_cb
            self.holds_packets = 1
        else:
            if cls is not None and pkt_cls is not None:
                raise ValueError("Pass only one of cls or pkt_cls")
            chosen = pkt_cls if pkt_cls is not None else cls
            if isinstance(chosen, type) and issubclass(chosen, CBORF_field) or \
                    isinstance(chosen, CBORF_field):
                if isinstance(chosen, type):
                    self.item_field = chosen("_item", None)  # type: ignore
                else:
                    self.item_field = chosen
                self.holds_packets = 0
            elif hasattr(chosen, "CBOR_root") or callable(chosen):
                self.cls = cast("Type[CBOR_Packet]", chosen)
                self.holds_packets = 1
            else:
                raise ValueError(
                    "Provide cls, pkt_cls, or next_cls_cb"
                )
        super(CBORF_SEQUENCE_OF, self).__init__(name, default)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> List[Any]
        if x is None:
            return None  # type: ignore
        if self.holds_packets:
            items = list(x)
            for item in items:
                _cbor_attach_parent(pkt, item)
            return items
        return [self.item_field.any2i(pkt, item) for item in x]

    def _decode_items(self, pkt, data, max_items=None):
        # type: (CBOR_Packet, bytes, Optional[int]) -> Tuple[List[Any], bytes, int]
        """Decode zero or more immediate CBOR items; do not consume break."""
        values = []  # type: List[Any]
        remaining = data
        consumed = 0
        while remaining and not cbor_is_break(remaining):
            if max_items is not None and consumed >= max_items:
                break
            before_len = len(remaining)
            if self.holds_packets:
                pkt_cls = self.cls
                if self.next_cls_cb is not None:
                    pkt_cls = self.next_cls_cb(
                        pkt,
                        values,
                        values[-1] if values else None,
                        remaining,
                    )
                    if pkt_cls is CBOR_NO_ITEM or pkt_cls is None:
                        break
                item_bytes, next_remaining = cbor_item_span(remaining)
                if len(next_remaining) >= before_len:
                    raise CBOR_Decoding_Error(
                        "Sequence decoder did not consume input")
                try:
                    child = _cbor_packet_from_bytes(pkt_cls, item_bytes, pkt)
                except CBOR_Decoding_Error:
                    raise
                except Exception as exc:
                    raise CBOR_Decoding_Error(str(exc))
                values.append(child)
                consumed += 1
                remaining = next_remaining
            else:
                result = self.item_field.parse_value(pkt, remaining)
                if result.items != 1:
                    raise CBOR_Decoding_Error(
                        "SEQUENCE_OF element must consume exactly one item"
                    )
                if len(result.remaining) >= before_len:
                    raise CBOR_Decoding_Error(
                        "Sequence decoder did not consume input")
                values.append(result.value)
                consumed += 1
                remaining = result.remaining
        return values, remaining, consumed

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[List[Any], bytes]
        values, remaining, _consumed = self._decode_items(pkt, s)
        return values, remaining

    def dissect_result(self, pkt, s, max_items=None):
        # type: (CBOR_Packet, bytes, Optional[int]) -> CBORParseResult
        values, remaining, consumed = self._decode_items(
            pkt, s, max_items=max_items
        )
        self.set_val(pkt, values)
        return CBORParseResult(remaining=remaining, items=consumed)

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        val = pkt.getfieldval(self.name)
        if val is None:
            raise CBOR_Encoding_Error(
                "Required collection field %r is None" % self.name)
        parts = []  # type: List[bytes]
        total_items = 0
        for item in val:
            if self.holds_packets:
                parts.append(
                    _encode_exactly_one_cbor_item(
                        item, context="SEQUENCE_OF element"
                    )
                )
                total_items += 1
            else:
                result = self.item_field.build_value(pkt, item)
                if result.items != 1:
                    raise CBOR_Encoding_Error(
                        "SEQUENCE_OF element must emit exactly one item"
                    )
                parts.append(result.data)
                total_items += 1
        return CBORBuildResult(b"".join(parts), total_items)

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 0

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1 << 30

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, Any) -> str
        if self.holds_packets:
            return repr(x)
        elif x is None:
            return "()"
        else:
            return "(%s)" % ", ".join(
                self.item_field.i2repr(pkt, item) for item in x
            )

    def __repr__(self):
        # type: () -> str
        return "<%s %s>" % (self.__class__.__name__, self.name)


class CBORF_ARRAY_OF(CBORF_field[List[Any]]):
    """
    CBOR array of homogeneous elements (major type 4).

    Preferred constructors::

        CBORF_ARRAY_OF("items", [], cls=MyPacket)
        CBORF_ARRAY_OF("items", [], cls=CBORF_UNSIGNED_INTEGER)

    ``pkt_cls`` is accepted as an alias of ``cls``. Pass only one of them.
    """
    CBOR_tag = CBOR_MajorTypes.ARRAY
    islist = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 cls=None,  # type: _ARRAY_T
                 pkt_cls=None,  # type: Optional[Type[Packet]]
                 ):
        # type: (...) -> None
        if cls is not None and pkt_cls is not None:
            raise ValueError("Pass only one of cls or pkt_cls")
        chosen = pkt_cls if pkt_cls is not None else cls
        if chosen is None:
            raise ValueError("Provide cls or pkt_cls")
        if isinstance(chosen, type) and issubclass(chosen, CBORF_field) or \
                isinstance(chosen, CBORF_field):
            if isinstance(chosen, type):
                self.item_field = chosen("_item", None)  # type: ignore
            else:
                self.item_field = chosen
            self.holds_packets = 0
        elif hasattr(chosen, "CBOR_root") or callable(chosen):
            self.cls = cast("Type[CBOR_Packet]", chosen)
            self.holds_packets = 1
        else:
            raise ValueError("cls must be a CBORF_field or CBOR_Packet")
        super(CBORF_ARRAY_OF, self).__init__(name, default)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> List[Any]
        if x is None:
            return None  # type: ignore
        if self.holds_packets:
            items = list(x)
            for item in items:
                _cbor_attach_parent(pkt, item)
            return items
        return [self.item_field.any2i(pkt, item) for item in x]

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[List[Any], bytes]
        try:
            major_type, count, s = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 4:
            raise CBOR_Type_Mismatch(
                "Expected major type 4 (array), got %d" % major_type)
        lst = []  # type: List[Any]

        def _decode_element():
            # type: () -> None
            nonlocal s
            if self.holds_packets:
                item_bytes, s = cbor_item_span(s)
                try:
                    child = _cbor_packet_from_bytes(self.cls, item_bytes, pkt)
                except CBOR_Decoding_Error:
                    raise
                except Exception as exc:
                    raise CBOR_Decoding_Error(str(exc))
                lst.append(child)
            else:
                result = self.item_field.parse_value(pkt, s)
                if result.items != 1:
                    raise CBOR_Decoding_Error(
                        "ARRAY_OF element must consume exactly one item"
                    )
                lst.append(result.value)
                s = result.remaining

        if count is CBOR_INDEFINITE:
            while True:
                if cbor_is_break(s):
                    s = cbor_consume_break(s)
                    break
                _decode_element()
        else:
            for _ in range(count):
                _decode_element()
        return lst, s

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        val = pkt.getfieldval(self.name)
        if val is None:
            raise CBOR_Encoding_Error(
                "Required collection field %r is None" % self.name)
        parts = []  # type: List[bytes]
        for item in val:
            if self.holds_packets:
                parts.append(
                    _encode_exactly_one_cbor_item(
                        item, context="ARRAY_OF element"
                    )
                )
            else:
                result = self.item_field.build_value(pkt, item)
                if result.items != 1:
                    raise CBOR_Encoding_Error(
                        "ARRAY_OF element must emit exactly one item"
                    )
                parts.append(result.data)
        items = b"".join(parts)
        data = CBOR_encode_head(4, len(val)) + items
        return CBORBuildResult(data, 1)

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, Any) -> str
        if self.holds_packets:
            return repr(x)
        elif x is None:
            return "[]"
        else:
            return "[%s]" % ", ".join(
                self.item_field.i2repr(pkt, item) for item in x
            )

    def __repr__(self):
        # type: () -> str
        return "<%s %s>" % (self.__class__.__name__, self.name)


class CBORF_MAP(CBORF_element):
    """
    CBOR map with a fixed set of named, typed fields (major type 5).

    This is a **JSON-like named-field** schema helper, not a general CBOR map
    codec: keys must be CBOR text strings (the field ``name``, or unknown
    extension names). Integer / byte-string / other key types are rejected.
    Protocols that need arbitrary CBOR map keys should use :class:`CBORF_ANY`
    or a dedicated field.

    Each field in ``seq`` represents one key-value pair.  The key is the
    field's ``name`` encoded as a CBOR text string.  The value is encoded
    and decoded by the corresponding :class:`CBORF_field`.

    On encode, pairs are emitted in RFC 8949 core-deterministic order
    (sorted by encoded key bytes), independent of declaration order.

    Unknown received key/value pairs are retained on the packet
    (``_cbor_unknown_map_pairs``) as decoded semantic ``(key, value)`` pairs.
    While the packet raw cache is valid the exact received bytes are preserved;
    after any mutation unknown members are re-encoded using core-deterministic
    CBOR together with known fields.

    Example::

        class MyCBOR(CBOR_Packet):
            CBOR_root = CBORF_MAP(
                CBORF_INTEGER("version", 1),
                CBORF_TEXT_STRING("name", ""),
            )
    """
    CBOR_tag = CBOR_MajorTypes.MAP
    holds_packets = 1
    islist = 1

    def __init__(self, *seq, **kwargs):
        # type: (*Any, **Any) -> None
        self.seq = seq
        field_by_name = {}  # type: Dict[str, Any]
        encoded_keys = {}  # type: Dict[str, bytes]
        for fld in seq:
            name = fld.name
            if name in field_by_name:
                raise ValueError(
                    "Duplicate CBOR map field name: %r" % (name,)
                )
            field_by_name[name] = fld
            encoded_keys[name] = CBORcodec_TEXT_STRING.enc(name)
        self._field_by_name = field_by_name
        self._encoded_keys = encoded_keys

    def __repr__(self):
        # type: () -> str
        return "<%s%r>" % (self.__class__.__name__, self.seq)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return all(f.is_empty(pkt) for f in self.seq)

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any]]
        return [
            child
            for field in self.seq
            for child in field.get_fields_list()
        ]

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        # Emit pairs sorted by encoded key bytes (RFC 8949 core deterministic).
        pairs = []  # type: List[Tuple[bytes, bytes]]
        for fld in self.seq:
            value_result = fld.build_result(pkt)
            if value_result.items == 0:
                continue
            if value_result.items != 1:
                raise CBOR_Encoding_Error(
                    "CBOR map value for %r must emit exactly one item"
                    % fld.name
                )
            pairs.append((self._encoded_keys[fld.name], value_result.data))
        unknown = getattr(pkt, "_cbor_unknown_map_pairs", None) or []
        for key, value in unknown:
            key_bytes = CBORcodec_TEXT_STRING.enc(key)
            value_bytes = CBORcodec_Object.encode_cbor_item_deterministic(value)
            pairs.append((key_bytes, value_bytes))
        pairs.sort(key=lambda item: item[0])
        parts = []  # type: List[bytes]
        for key_bytes, value_bytes in pairs:
            parts.append(key_bytes)
            parts.append(value_bytes)
        data = CBOR_encode_head(5, len(pairs)) + b"".join(parts)
        return CBORBuildResult(data, 1)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        try:
            major_type, count, remaining = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 5:
            raise CBOR_Type_Mismatch(
                "Expected major type 5 (map), got %d" % major_type)

        field_map = self._field_by_name
        seen_keys = set()  # type: set[str]
        seen_fields = set()  # type: set[str]
        pair_values = {}  # type: Dict[str, bytes]
        unknown_pairs = []  # type: List[Tuple[str, Any]]

        def _map_text_key(key_obj):
            # type: (Any) -> str
            if not isinstance(key_obj, CBOR_TEXT_STRING):
                raise CBOR_Decoding_Error(
                    "CBOR map field key must be a text string, got %r"
                    % (key_obj,)
                )
            key = key_obj.val
            if key in seen_keys:
                raise CBOR_Decoding_Error(
                    "Duplicate CBOR map field name: %r" % (key,)
                )
            seen_keys.add(key)
            return key

        def _collect_pair():
            # type: () -> None
            nonlocal remaining
            # Keep encoded key bytes so unknown extensions round-trip exactly.
            key_bytes, after_key = cbor_item_span(remaining)
            key_obj, key_rest = CBORcodec_Object.decode_cbor_item(key_bytes)
            if key_rest:
                raise CBOR_Decoding_Error(
                    "CBOR map key did not decode to a single item"
                )
            key = _map_text_key(key_obj)
            val_bytes, remaining = cbor_item_span(after_key)
            if key in field_map:
                pair_values[key] = val_bytes
            else:
                val_obj, val_rest = CBORcodec_Object.decode_cbor_item(val_bytes)
                if val_rest:
                    raise CBOR_Decoding_Error(
                        "CBOR map value did not decode to a single item"
                    )
                unknown_pairs.append(
                    (key, cbor_object_to_python(val_obj))
                )

        if count is CBOR_INDEFINITE:
            while True:
                if cbor_is_break(remaining):
                    remaining = cbor_consume_break(remaining)
                    break
                _collect_pair()
        else:
            for _ in range(count):
                _collect_pair()

        def _dissect_value_bytes(fld, val_bytes):
            # type: (Any, bytes) -> None
            if isinstance(fld, CBORF_optional):
                value_fld = fld._field
            elif isinstance(fld, CBORF_CONDITIONAL):
                value_fld = fld.fld
            else:
                value_fld = fld
            result = value_fld.dissect_result(pkt, val_bytes)
            if result.items != 1 or result.remaining:
                raise CBOR_Decoding_Error(
                    "Map value for %r must contain exactly one item"
                    % getattr(value_fld, "name", value_fld)
                )
            seen_fields.add(value_fld.name)

        # Phase 1: unconditional members (order-independent).
        for fld in self.seq:
            if isinstance(fld, CBORF_CONDITIONAL):
                continue
            name = fld.name
            if name not in pair_values:
                self._mark_map_field_absent(pkt, fld)
                continue
            _dissect_value_bytes(fld, pair_values[name])

        # Phase 2: conditionals after discriminators are populated.
        for fld in self.seq:
            if not isinstance(fld, CBORF_CONDITIONAL):
                continue
            name = fld.fld.name
            if name not in pair_values:
                continue
            if not fld._evalcond(pkt):
                raise CBOR_Decoding_Error(
                    "Map field %r present but condition is false" % name
                )
            _dissect_value_bytes(fld, pair_values[name])

        for fld in self.seq:
            if fld.min_items(pkt) > 0 and fld.name not in seen_fields:
                raise CBOR_Decoding_Error(
                    "Required map field %r is missing" % fld.name
                )
        pkt._cbor_unknown_map_pairs = unknown_pairs  # type: ignore[attr-defined]
        return CBORParseResult(remaining=remaining, items=1)

    def _mark_map_field_absent(self, pkt, fld):
        # type: (CBOR_Packet, Any) -> None
        if isinstance(fld, CBORF_optional):
            fld._field.set_val(pkt, CBOR_ABSENT)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1


class CBORF_SEMANTIC_TAG(CBORF_field[int]):
    """
    CBOR semantic tag field (major type 6).

    Wraps an ``inner_field`` with the given numeric ``tag_num``.  The inner
    field handles encoding and decoding of the tagged value.  The outer field
    (named ``name``) stores the tag number, while the inner field stores its
    value under its own name on the packet.

    Example::

        class TimestampPkt(CBOR_Packet):
            CBOR_root = CBORF_SEMANTIC_TAG(
                "tag_info", None, 1, CBORF_INTEGER("ts", 0)
            )
    """
    CBOR_tag = CBOR_MajorTypes.TAG
    holds_packets = 0

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 tag_num,  # type: int
                 inner_field,  # type: CBORF_field[Any]
                 ):
        # type: (...) -> None
        self.tag_num = tag_num
        if tag_num < 0 or tag_num > 0xFFFFFFFFFFFFFFFF:
            raise CBOR_Encoding_Error(
                "Semantic tag number out of uint64 range")
        self.inner_field = inner_field
        # Honour an explicit default (e.g. CBOR_ABSENT); otherwise the field
        # stores the configured tag number when present.
        if default is None:
            default = tag_num
        super(CBORF_SEMANTIC_TAG, self).__init__(name, default)

    def _parse_tag_head(self, s, require_match=True):
        # type: (bytes, bool) -> Tuple[int, bytes]
        try:
            major_type, tag_num, remaining = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 6:
            raise CBOR_Type_Mismatch(
                "Expected major type 6 (semantic tag), got %d" % major_type)
        if require_match and tag_num != self.tag_num:
            raise CBOR_Type_Mismatch(
                "Expected tag %d, got %d" % (self.tag_num, tag_num))
        return tag_num, remaining

    def _encode_tagged(self, inner_data):
        # type: (bytes) -> bytes
        return CBOR_encode_head(6, self.tag_num) + inner_data

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[int, bytes]
        return self._parse_tag_head(s, require_match=True)

    def matches_next_item(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bool
        if not s or cbor_is_break(s):
            return False
        try:
            major_type, tag_num, _rem = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error:
            return False
        return major_type == 6 and tag_num == self.tag_num

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        tag_num, remaining = self._parse_tag_head(s)
        inner = self.inner_field.dissect_result(pkt, remaining)
        if inner.items != 1:
            raise CBOR_Decoding_Error(
                "Semantic tag content must be exactly one CBOR item")
        self.set_val(pkt, tag_num)
        return CBORParseResult(remaining=inner.remaining, items=1)

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        inner = self.inner_field.build_result(pkt)
        if inner.items != 1:
            raise CBOR_Encoding_Error(
                "Semantic tag content must be exactly one CBOR item")
        return CBORBuildResult(self._encode_tagged(inner.data), 1)

    def parse_value(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        _tag_num, remaining = self._parse_tag_head(s)
        inner = self.inner_field.parse_value(pkt, remaining)
        if inner.items != 1:
            raise CBOR_Decoding_Error(
                "Semantic tag content must be exactly one CBOR item")
        return CBORParseResult(value=inner.value, remaining=inner.remaining, items=1)

    def build_value(self, pkt, value):
        # type: (CBOR_Packet, Any) -> CBORBuildResult
        inner = self.inner_field.build_value(pkt, value)
        if inner.items != 1:
            raise CBOR_Encoding_Error(
                "Semantic tag content must be exactly one CBOR item")
        return CBORBuildResult(data=self._encode_tagged(inner.data), items=1)

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any]]
        return [self] + self.inner_field.get_fields_list()

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return pkt.getfieldval(self.name) is CBOR_ABSENT


##############################
#    Complex CBOR Fields     #
##############################

class CBORF_optional(CBORF_element):
    """
    Wrapper making a :class:`CBORF_field` optional.

    Absence is recorded as ``CBOR_ABSENT`` on every path (lookahead mismatch,
    exhausted parent array, missing map key).  If the next item matches but
    decoding fails, the error propagates (the value is present but malformed).
    """

    def __init__(self, field):
        # type: (CBORF_field[Any]) -> None
        self._field = field

    def __getattr__(self, attr):
        # type: (str) -> Any
        return getattr(self._field, attr)

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        if pkt.getfieldval(self._field.name) is CBOR_ABSENT:
            return CBORBuildResult(b"", 0)
        if self._field.is_empty(pkt):
            return CBORBuildResult(b"", 0)
        return self._field.build_result(pkt)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        if not self._field.matches_next_item(pkt, s):
            self._field.set_val(pkt, CBOR_ABSENT)
            return CBORParseResult(remaining=s, items=0)
        return self._field.dissect_result(pkt, s)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 0

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return self._field.max_items(pkt)


class CBORF_CONDITIONAL(CBORF_element, fields.ConditionalField):
    """
    Wrapper making a :class:`CBORF_field` conditional on some other packet
    state.
    """

    def __init__(self,
                 fld,  # type: CBORF_field[Any]
                 cond,  # type: Callable[[Packet], bool]
                 ):
        # type: (...) -> None
        fields.ConditionalField.__init__(self, fld, cond)

    def __repr__(self):
        # type: () -> str
        return "<%s%r>" % (self.__class__.__name__, self.fld)

    @property
    def owners(self):
        return self.fld.owners

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        if self._evalcond(pkt):
            return self.fld.build_result(pkt)
        return CBORBuildResult(b"", 0)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        if self._evalcond(pkt):
            return self.fld.dissect_result(pkt, s)
        return CBORParseResult(remaining=s, items=0)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        if self._evalcond(pkt):
            return self.fld.min_items(pkt)
        return 0

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        if self._evalcond(pkt):
            return self.fld.max_items(pkt)
        return 0


class CBORF_PACKET(CBORF_field['CBOR_Packet']):
    """
    CBOR field that encapsulates a nested :class:`CBOR_Packet`.

    The nested packet is encoded as-is (its ``CBOR_root.build()`` output)
    and decoded by instantiating ``cls`` from the current byte stream.
    """
    holds_packets = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[CBOR_Packet]
                 cls,  # type: Type[CBOR_Packet]
                 ):
        # type: (...) -> None
        self.cls = cls
        super(CBORF_PACKET, self).__init__(name, default)

    def _parse_packet_item(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_Packet, bytes]
        """Decode exactly one CBOR item into a nested packet."""
        item_bytes, remain = cbor_item_span(s)
        try:
            child = _cbor_packet_from_bytes(self.cls, item_bytes, pkt)
        except CBOR_Decoding_Error:
            raise
        except Exception as exc:
            raise CBOR_Decoding_Error(str(exc))
        return child, remain

    def _build_packet_item(self, pkt, val):
        # type: (CBOR_Packet, Any) -> CBORBuildResult
        """Encode a nested packet and enforce one top-level CBOR item."""
        if val is None:
            raise CBOR_Encoding_Error(
                "Required field %r is None" % self.name)
        data = _encode_exactly_one_cbor_item(
            val, context="field %r" % self.name
        )
        return CBORBuildResult(data, 1)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_Packet, bytes]
        return self._parse_packet_item(pkt, s)

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        if x is None:
            return b""
        return self._build_packet_item(pkt, x).data

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> CBOR_Packet
        return cast('CBOR_Packet', _cbor_attach_parent(pkt, x))

    def encode_value(self, x):
        # type: (Any) -> bytes
        return self._build_packet_item(None, x).data  # type: ignore

    def parse_value(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        child, remain = self._parse_packet_item(pkt, s)
        return CBORParseResult(value=child, remaining=remain, items=1)

    def build_value(self, pkt, value):
        # type: (CBOR_Packet, Any) -> CBORBuildResult
        return self._build_packet_item(pkt, value)

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        return self._build_packet_item(pkt, pkt.getfieldval(self.name))

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORParseResult
        child, remain = self._parse_packet_item(pkt, s)
        self.set_val(pkt, child)
        return CBORParseResult(remaining=remain, items=1)

    def randval(self):  # type: ignore
        # type: () -> CBOR_Packet
        return packet.fuzz(self.cls())
