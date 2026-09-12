# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Classes that implement CBOR (Concise Binary Object Representation) data
structures as packet fields.  Modelled after scapy/asn1fields.py.

Public leaf/compound hooks follow Scapy/ASN.1 style (``any2i`` / ``i2m`` /
``m2i``, ``build`` / ``dissect``). Compounds additionally use
``_build_counted`` / ``_dissect_counted`` so unframed sequences and array
budgeting can return an item count; callers outside this module should
prefer ``build`` / ``dissect``.
"""

import copy
import math

from dataclasses import dataclass

from scapy.cbor.cbor import (
    CBOR_AdditionalInfo,
    CBOR_Decoding_Error,
    CBOR_Encoding_Error,
    CBOR_FloatAI,
    CBOR_MajorTypes,
    CBOR_Object,
    CBOR_SimpleValue,
    CBOR_UINT64_MAX,
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
    CBOR_NO_ITEM,
    CBOR_FLOAT,
    CBOR_MAP,
    CBOR_SIMPLE_VALUE,
)
from scapy.cbor.cborcodec import (
    CBOR_BREAK_BYTE,
    CBOR_Codec_Decoding_Error,
    CBOR_INDEFINITE,
    CBOR_decode_head,
    CBOR_encode_head,
    CBOR_encode_initial,
    cbor_count_items,
    cbor_item_span,
    cbor_is_break,
    cbor_consume_break,
    CBORcodec_Object,
    CBORcodec_UNSIGNED_INTEGER,
    CBORcodec_NEGATIVE_INTEGER,
    CBORcodec_BYTE_STRING,
    CBORcodec_TEXT_STRING,
    CBORcodec_SIMPLE_AND_FLOAT,
)
from scapy.packet import Packet
from scapy.utils import Enum_metaclass
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


class CBOR_Type_Mismatch(CBOR_Decoding_Error):
    """Raised when a CBOR field encounters an unexpected major type."""


@dataclass(frozen=True)
class _CBORBuildResult(object):
    """Encoded CBOR bytes and how many top-level items they contain."""
    data: bytes = b""
    items: int = 0


@dataclass(frozen=True)
class _CBORParseResult(object):
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


def _encode_exactly_one_cbor_item(val, context="value"):
    # type: (Any, str) -> bytes
    """Serialize *val* and require it to be exactly one well-formed CBOR item.

    Always goes through ``bytes(val)`` so Packet ``post_build`` / payload are
    included, then fully decodes to prove single-item cardinality.
    """
    data = bytes(val)
    try:
        _obj, remaining = CBORcodec_Object.decode_cbor_item(data)
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
    return data


def _cbor_attach_parent(parent, child):
    # type: (Optional[Packet], Any) -> Any
    """Attach *child* as a field-contained packet of *parent* (Scapy parent)."""
    if child is not None and parent is not None and hasattr(child, "add_parent"):
        child.add_parent(parent)
    return child


class CBORF_element(object):
    """Base class for CBOR packet field elements.

    Public API is ``build`` / ``dissect`` (bytes in, bytes out). Item
    cardinality for compound budgeting lives in ``_build_counted`` /
    ``_dissect_counted``.
    """

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        raise NotImplementedError

    def _dissect_counted(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> _CBORParseResult
        raise NotImplementedError

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self._build_counted(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self._dissect_counted(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def structural_max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        """Upper bound independent of not-yet-dissected discriminators."""
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

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        """Convert internal value to CBOR wire bytes (Scapy build hook)."""
        if isinstance(x, fields.RawVal):
            data = bytes(x)
            try:
                _obj, remaining = CBORcodec_Object.decode_cbor_item(data)
            except Exception as exc:
                raise CBOR_Encoding_Error(
                    "RawVal for %r is not well-formed CBOR: %s"
                    % (self.name, exc)
                )
            if remaining:
                raise CBOR_Encoding_Error(
                    "RawVal for %r must contain exactly one CBOR item"
                    % self.name
                )
            return data
        # Do not special-case None here: for CBORF_ANY, None is CBOR null.
        # Absent/optional skipping is handled in _build_counted().
        return self._encode_leaf(x)

    def _encode_leaf(self, x):
        # type: (Any) -> bytes
        """Encode a native Python value to CBOR bytes (leaf fields only)."""
        raise NotImplementedError(
            "Subclasses must implement _encode_leaf for %s" % type(self))

    @staticmethod
    def _object_to_python(obj):
        # type: (Any) -> Any
        """Convert a :class:`CBOR_Object` tree to native Python values.

        Prefer keeping :class:`CBOR_Object` for arbitrary CBOR (``CBORF_ANY``).
        Tags, simples, and undefined stay as ``CBOR_Object`` instances.
        """
        if not isinstance(obj, CBOR_Object):
            return obj
        if isinstance(obj, (CBOR_UNDEFINED, CBOR_SEMANTIC_TAG, CBOR_SIMPLE_VALUE)):
            return obj
        if isinstance(obj, CBOR_ARRAY):
            return [CBORF_field._object_to_python(item) for item in obj.val]
        if isinstance(obj, CBOR_MAP):
            from scapy.cbor.cbor import CBORMapData, _cbor_map_pairs
            pairs = _cbor_map_pairs(obj)
            return CBORMapData([
                (CBORF_field._object_to_python(k),
                 CBORF_field._object_to_python(v))
                for k, v in pairs
            ])
        if isinstance(obj, CBOR_FLOAT):
            return float(obj.val)
        return obj.val

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> _I
        if x is CBOR_ABSENT or x is CBOR_NO_ITEM:
            return cast(_I, x)
        if isinstance(x, CBOR_UNDEFINED):
            return cast(_I, x)
        if isinstance(x, CBOR_Object):
            x = self._object_to_python(x)
        return self.h2i(pkt, x)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        """Encode this field's value from *pkt* (ASN.1-style leaf build)."""
        val = pkt.getfieldval(self.name)
        if val is None:
            raise CBOR_Encoding_Error(
                "Required field %r is None" % self.name)
        return self.i2m(pkt, val)

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        """Decode one item from *s* into *pkt* (ASN.1-style leaf dissect)."""
        val, remain = self.m2i(pkt, s)
        pkt.setfieldval(self.name, val)
        return remain

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        return _CBORBuildResult(self.build(pkt), 1)

    def _dissect_counted(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> _CBORParseResult
        remain = self.dissect(pkt, s)
        return _CBORParseResult(remaining=remain, items=1)

    def _parse_value(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> _CBORParseResult
        """Decode a free value without assigning it onto *pkt*."""
        val, remain = self.m2i(pkt, s)
        return _CBORParseResult(value=val, remaining=remain, items=1)

    def _build_value(self, pkt, value):
        # type: (CBOR_Packet, Any) -> _CBORBuildResult
        """Encode *value* without reading it from *pkt* fields."""
        return _CBORBuildResult(
            data=self.i2m(pkt, self.any2i(pkt, value)),
            items=1,
        )

    def do_copy(self, x):
        # type: (Any) -> Any
        if x is CBOR_ABSENT or x is CBOR_NO_ITEM:
            return x
        if isinstance(x, CBOR_UNDEFINED):
            return x
        if isinstance(x, list):
            return [self.do_copy(item) for item in x]
        if isinstance(x, dict):
            return {key: self.do_copy(value) for key, value in x.items()}
        if hasattr(x, "copy"):
            try:
                return x.copy()
            except TypeError:
                pass
        return copy.deepcopy(x)

    def mark_absent(self, pkt):
        # type: (CBOR_Packet) -> None
        """Record that this field was not present on the wire.

        Assign ``CBOR_ABSENT`` without ``any2i`` so integer leaves that
        reject non-int values still accept the presence sentinel.
        """
        pkt.fields[self.name] = CBOR_ABSENT
        pkt.explicit = 0
        pkt.raw_packet_cache = None
        pkt.raw_packet_cache_fields = None
        pkt.wirelen = None

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


class _CBORFingerprintKind(metaclass=Enum_metaclass):
    """Private discriminator for ``CBORF_ANY`` raw-cache fingerprints."""
    name = "CBOR_FINGERPRINT_KIND"
    UNDEF = 3
    ARRAY = 7
    MAP = 8
    TAG = 9
    OBJ = 11
    NAN = 13
    FINITE = 14
    SENTINEL = 15
    FLOAT = 16
    INF = 17
    ZERO = 18
    MAPDATA = 19
    LIST = 20
    DICT = 21
    PY = 22


_CBORFingerprint = Tuple[Any, ...]


class CBORF_ANY(CBORF_field[Any]):
    """Represent any well-formed CBOR value as a lossless ``CBOR_Object``."""
    ismutable = True

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        # Python None / CBOR null is a real value; only CBOR_ABSENT means absent.
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
        if x is CBOR_ABSENT or x is CBOR_NO_ITEM:
            return x
        if isinstance(x, CBOR_UNDEFINED):
            return x
        return copy.deepcopy(x)

    @staticmethod
    def python_to_cbor_object(value):
        # type: (Any) -> Any
        """Convert native Python values into a :class:`CBOR_Object` tree."""
        from scapy.cbor.cbor import (
            CBOR_ARRAY,
            CBOR_BYTE_STRING,
            CBOR_FALSE,
            CBOR_FLOAT,
            CBOR_MAP,
            CBOR_NEGATIVE_INTEGER,
            CBOR_NULL,
            CBOR_TEXT_STRING,
            CBOR_TRUE,
            CBOR_UNSIGNED_INTEGER,
            CBORMapData,
        )
        convert = CBORF_ANY.python_to_cbor_object
        if isinstance(value, CBOR_Object):
            return value
        if isinstance(value, CBORMapData):
            return CBOR_MAP(CBORMapData([
                (convert(k), convert(v))
                for k, v in value.cbor_pairs()
            ]))
        if isinstance(value, bool):
            return CBOR_TRUE() if value else CBOR_FALSE()
        if value is None:
            return CBOR_NULL()
        if isinstance(value, int):
            if value >= 0:
                return CBOR_UNSIGNED_INTEGER(value)
            return CBOR_NEGATIVE_INTEGER(value)
        if isinstance(value, float):
            return CBOR_FLOAT(value)
        if isinstance(value, bytes):
            return CBOR_BYTE_STRING(value)
        if isinstance(value, str):
            return CBOR_TEXT_STRING(value)
        if isinstance(value, list):
            return CBOR_ARRAY([convert(item) for item in value])
        if isinstance(value, dict):
            return CBOR_MAP(CBORMapData([
                (convert(k), convert(v))
                for k, v in value.items()
            ]))
        raise TypeError("Cannot convert %r to CBOR_Object" % (type(value),))

    @staticmethod
    def _cache_fingerprint(obj):
        # type: (Any) -> _CBORFingerprint
        """Recursive rebuild-relevant fingerprint for ``CBORF_ANY`` values."""
        from scapy.cbor.cbor import CBORMapData
        fingerprint = CBORF_ANY._cache_fingerprint
        Kind = _CBORFingerprintKind
        if obj is CBOR_ABSENT or obj is CBOR_NO_ITEM:
            return (Kind.SENTINEL, obj)
        if isinstance(obj, CBOR_UNDEFINED):
            return (Kind.UNDEF,)
        if isinstance(obj, CBOR_FLOAT):
            fval = float(obj.val)
            if math.isnan(fval):
                token = (Kind.NAN,)  # type: Tuple[Any, ...]
            elif math.isinf(fval):
                token = (Kind.INF, math.copysign(1.0, fval))
            elif fval == 0.0:
                token = (Kind.ZERO, math.copysign(1.0, fval))
            else:
                token = (Kind.FINITE, fval)
            encoded = getattr(obj, "_encoded", None)
            return (Kind.FLOAT, token, encoded)
        if isinstance(obj, CBOR_ARRAY):
            return (
                Kind.ARRAY,
                tuple(fingerprint(item) for item in obj.val),
            )
        if isinstance(obj, CBOR_MAP):
            from scapy.cbor.cbor import _cbor_map_pairs
            pairs = _cbor_map_pairs(obj)
            return (
                Kind.MAP,
                tuple(
                    (fingerprint(key), fingerprint(value))
                    for key, value in pairs
                ),
            )
        if isinstance(obj, CBORMapData):
            return (
                Kind.MAPDATA,
                tuple(
                    (fingerprint(key), fingerprint(value))
                    for key, value in obj.cbor_pairs()
                ),
            )
        if isinstance(obj, CBOR_SEMANTIC_TAG):
            tag_num, inner = obj.val
            return (Kind.TAG, int(tag_num), fingerprint(inner))
        if isinstance(obj, CBOR_Object):
            return (Kind.OBJ, type(obj).__name__, fingerprint(obj.val))
        if isinstance(obj, list):
            return (Kind.LIST, tuple(fingerprint(item) for item in obj))
        if isinstance(obj, dict):
            return (
                Kind.DICT,
                tuple(
                    (fingerprint(key), fingerprint(value))
                    for key, value in obj.items()
                ),
            )
        return (Kind.PY, type(obj).__name__, obj)

    def cache_fingerprint(self, x):
        # type: (Any) -> _CBORFingerprint
        """Snapshot for Scapy mutable raw-cache comparison.

        Includes ``CBOR_FLOAT._encoded`` so explicit ``.val`` assignment that
        clears the wire cache is visible even when the semantic float is
        unchanged.
        """
        return self._cache_fingerprint(x)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> Any
        if x is CBOR_ABSENT or x is CBOR_NO_ITEM:
            return x
        if isinstance(x, CBOR_UNDEFINED):
            return x
        return self.python_to_cbor_object(x)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        val = pkt.getfieldval(self.name)
        if val is CBOR_ABSENT:
            return b""
        return self.i2m(pkt, val)

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        data = self.build(pkt)
        if not data:
            return _CBORBuildResult(b"", 0)
        return _CBORBuildResult(data, 1)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[Any, bytes]
        return CBORcodec_Object.decode_cbor_item(s)

    def _encode_leaf(self, x):
        # type: (Any) -> bytes
        if x is CBOR_ABSENT:
            return b""
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
        if i < 0 or i > CBOR_UINT64_MAX:
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

    def _encode_leaf(self, x):
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
        if i >= 0 or i < -(CBOR_UINT64_MAX + 1):
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

    def _encode_leaf(self, x):
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
        return major_type in (
            CBOR_MajorTypes.UNSIGNED_INTEGER,
            CBOR_MajorTypes.NEGATIVE_INTEGER,
        )

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> int
        if isinstance(x, CBOR_Object):
            x = x.val
        if x is None:
            return None  # type: ignore
        i = int(x)
        if i < -(CBOR_UINT64_MAX + 1) or i > CBOR_UINT64_MAX:
            raise CBOR_Encoding_Error(
                "Integer out of CBOR range: %r" % (i,))
        return i

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[int, bytes]
        if not s:
            raise CBOR_Decoding_Error("Empty CBOR data")
        major_type = (s[0] >> 5) & 0x7
        if major_type == CBOR_MajorTypes.UNSIGNED_INTEGER:
            obj, remain = CBORcodec_UNSIGNED_INTEGER.dec(s)
            return obj.val, remain
        elif major_type == CBOR_MajorTypes.NEGATIVE_INTEGER:
            obj, remain = CBORcodec_NEGATIVE_INTEGER.dec(s)
            return obj.val, remain
        raise CBOR_Type_Mismatch(
            "Expected integer (major type 0 or 1), got %d" % major_type)

    def _encode_leaf(self, x):
        # type: (Any) -> bytes
        i = int(x)
        if i >= 0:
            return CBORcodec_UNSIGNED_INTEGER.enc(i)
        return CBORcodec_NEGATIVE_INTEGER.enc(i)

    def randval(self):
        # type: () -> RandNum
        return RandNum(-2 ** 64, 2 ** 64 - 1)


def _cbor_decode_byte_string(s, definite_only=False):
    # type: (bytes, bool) -> Tuple[bytes, bytes]
    """Decode one CBOR byte string item; optionally reject indefinite form."""
    if definite_only:
        try:
            major_type, length, _rem = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != CBOR_MajorTypes.BYTE_STRING:
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


def _cbor_encode_byte_string(x):
    # type: (Any) -> bytes
    """Encode *x* as a definite CBOR byte string item."""
    return CBORcodec_BYTE_STRING.enc(bytes(x))


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
        return _cbor_decode_byte_string(s, definite_only=self.definite_only)

    def _encode_leaf(self, x):
        # type: (Any) -> bytes
        return _cbor_encode_byte_string(x)

    def randval(self):
        # type: () -> RandString
        return RandString(RandNum(0, 1000))


class CBORF_BYTE_STRING_PACKET(CBORF_field[Packet]):
    """CBOR byte string which wraps another packet field.

    The inner packet may or may not itself be CBOR or CBOR sequence data.
    Shares byte-string wire helpers with :class:`CBORF_BYTE_STRING`.
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

    def _decode_packet_value(self, pkt, data):
        # type: (CBOR_Packet, bytes) -> Packet
        if self.pkt_cls is not None:
            pkt_cls = self.pkt_cls
        elif self.cls_cb is not None:
            pkt_cls = self.cls_cb(pkt, data)
        else:
            pkt_cls = None
        if pkt_cls is None:
            return packet.Raw(data)
        try:
            return pkt_cls(data, _parent=pkt)  # type: ignore
        except CBOR_Decoding_Error:
            raise
        except Exception as exc:
            if config.conf.debug_dissector:
                raise
            raise CBOR_Decoding_Error(
                "Failed to decode byte-string packet content: %s" % exc
            ) from exc

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> Packet
        if isinstance(x, CBOR_BYTE_STRING):
            x = x.val
        if isinstance(x, (bytes, bytearray)):
            return self._decode_packet_value(pkt, bytes(x))
        return _cbor_attach_parent(pkt, x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[Packet, bytes]
        data, remain = _cbor_decode_byte_string(
            s, definite_only=self.definite_only
        )
        return self._decode_packet_value(pkt, data), remain

    def _encode_leaf(self, x):
        # type: (Any) -> bytes
        return _cbor_encode_byte_string(x)


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

    def _encode_leaf(self, x):
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
        return (
            ((s[0] >> 5) & 0x7) == CBOR_MajorTypes.SIMPLE_AND_FLOAT
            and ai in (
                CBOR_SimpleValue.FALSE,
                CBOR_SimpleValue.TRUE,
            )
        )

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

    def _encode_leaf(self, x):
        # type: (Any) -> bytes
        return CBORcodec_SIMPLE_AND_FLOAT.enc(bool(x))

    def randval(self):
        # type: () -> RandChoice
        return RandChoice(True, False)


class CBORF_NULL(CBORF_field[None]):
    """CBOR null field (major type 7, simple value 22)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

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
        return s[0] == CBOR_encode_initial(
            CBOR_MajorTypes.SIMPLE_AND_FLOAT, CBOR_SimpleValue.NULL
        )[0]

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

    def _encode_leaf(self, x):
        # type: (Any) -> bytes
        return CBOR_NULL().enc()

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        if pkt.getfieldval(self.name) is CBOR_ABSENT:
            return b""
        return self._encode_leaf(None)

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        data = self.build(pkt)
        if not data:
            return _CBORBuildResult(b"", 0)
        return _CBORBuildResult(data, 1)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return pkt.getfieldval(self.name) is CBOR_ABSENT


class CBORF_UNDEFINED(CBORF_field[None]):
    """CBOR undefined field (major type 7, simple value 23)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

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
        return s[0] == CBOR_encode_initial(
            CBOR_MajorTypes.SIMPLE_AND_FLOAT, CBOR_SimpleValue.UNDEFINED
        )[0]

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

    def _encode_leaf(self, x):
        # type: (Any) -> bytes
        return CBOR_UNDEFINED().enc()

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        if pkt.getfieldval(self.name) is CBOR_ABSENT:
            return b""
        return self._encode_leaf(None)

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        data = self.build(pkt)
        if not data:
            return _CBORBuildResult(b"", 0)
        return _CBORBuildResult(data, 1)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return pkt.getfieldval(self.name) is CBOR_ABSENT


class CBORF_FLOAT(CBORF_field[float]):
    """CBOR float field (major type 7).

    Stores a plain Python ``float``. Exact received encodings are preserved
    only while the packet ``raw_packet_cache`` remains valid; after semantic
    rebuild, preferred (shortest exact) encoding is used.
    """
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def matches_next_item(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bool
        if not s or cbor_is_break(s):
            return False
        ai = s[0] & 0x1f
        return (
            ((s[0] >> 5) & 0x7) == CBOR_MajorTypes.SIMPLE_AND_FLOAT
            and ai in (
                CBOR_FloatAI.HALF,
                CBOR_FloatAI.SINGLE,
                CBOR_FloatAI.DOUBLE,
            )
        )

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> float
        if x is CBOR_ABSENT:
            return CBOR_ABSENT  # type: ignore
        if x is None:
            return None  # type: ignore
        if isinstance(x, CBOR_FLOAT):
            return float(x.val)
        if isinstance(x, CBOR_Object):
            return float(self._object_to_python(x))
        return float(x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[float, bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, CBOR_FLOAT):
            raise CBOR_Type_Mismatch(
                "Expected float, got %r" % obj)
        return float(obj.val), remain

    def _encode_leaf(self, x):
        # type: (Any) -> bytes
        return CBORcodec_SIMPLE_AND_FLOAT.enc(float(x))

    def i2h(self, pkt, x):
        # type: (CBOR_Packet, Any) -> Any
        return x

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, Any) -> str
        return repr(x)

    def randval(self):
        # type: () -> RandFloat
        return RandFloat(0, 2 ** 32)


##############################
#    Structured CBOR Fields  #
##############################


class _CBORF_compound(CBORF_element):
    """Shared helpers for sequence-like CBOR field containers."""
    CBOR_tag = None
    holds_packets = 1

    def __init__(self, *seq):
        # type: (*Any) -> None
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
        fields_list = [
            child
            for field in self.seq
            for child in field.get_fields_list()
        ]
        names = [f.name for f in fields_list]
        if len(names) != len(set(names)):
            dupes = sorted({n for n in names if names.count(n) > 1})
            raise ValueError(
                "Duplicate CBOR field name(s) %s; for multiple maps use "
                "distinct unknown_field= values" % (dupes,)
            )
        return fields_list

    def _build_children(self, pkt):
        # type: (CBOR_Packet) -> Tuple[bytes, int]
        parts = []  # type: List[bytes]
        total_items = 0
        for field in self.seq:
            result = field._build_counted(pkt)
            parts.append(result.data)
            total_items += result.items
        return b"".join(parts), total_items

    def _dissect_field(self, pkt, field, remaining, max_items=None):
        # type: (CBOR_Packet, Any, bytes, Optional[int]) -> _CBORParseResult
        if isinstance(field, CBORF_REMAINDER_OF):
            return field._dissect_counted(
                pkt, remaining, max_items=max_items
            )
        return field._dissect_counted(pkt, remaining)

    def _reject_nonterminal_remainder_of(self, allow_terminal=True):
        # type: (bool) -> None
        """Reject ``CBORF_REMAINDER_OF`` that is not a direct final child of *self*.

        Nested unframed ``CBORF_ITEMS`` share this framing context, so they
        recurse with ``allow_terminal=False``. Framed ``CBORF_ARRAY``
        compounds establish their own item budget and are not walked.
        """
        for i, field in enumerate(self.seq):
            is_last = i == len(self.seq) - 1
            if isinstance(field, CBORF_REMAINDER_OF):
                if not (allow_terminal and is_last):
                    raise ValueError(
                        "CBORF_REMAINDER_OF must be the last field "
                        "in the sequence"
                    )
            elif isinstance(field, CBORF_ITEMS):
                # Only unframed ITEMS share this framing context; framed
                # ARRAY establishes its own count boundary.
                field._reject_nonterminal_remainder_of(allow_terminal=False)


class CBORF_ITEMS(_CBORF_compound):
    """
    Unframed fixed sequence of named, typed fields (no CBOR array head).

    Unlike :class:`CBORF_ARRAY`, this emits/consumes a stream of top-level
    CBOR items with greedy left-to-right parsing and no suffix lookahead.
    Use it when a schema is a field list without a major-type-4 envelope
    (ASN.1 SEQUENCE analogy belongs on :class:`CBORF_ARRAY`).

    Same-type optional-then-required schemas are ambiguous on the wire;
    prefer :class:`CBORF_ARRAY` (item budget) or :class:`CBORF_CONDITIONAL`
    with a previously decoded discriminator.

    Example::

        class MyCBOR(CBOR_Packet):
            CBOR_root = CBORF_ITEMS(
                CBORF_INTEGER("version", 1),
                CBORF_TEXT_STRING("name", ""),
            )
    """

    def __init__(self, *seq):
        # type: (*Any) -> None
        super(CBORF_ITEMS, self).__init__(*seq)
        self._reject_nonterminal_remainder_of()

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        data, total_items = self._build_children(pkt)
        return _CBORBuildResult(data, total_items)

    def _dissect_counted(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> _CBORParseResult
        # Stream schema fields greedily left-to-right; leave trailing bytes
        # for the parent without requiring them to be well-formed CBOR.
        remaining = s
        total_items = 0
        for field in self.seq:
            result = self._dissect_field(pkt, field, remaining)
            remaining = result.remaining
            total_items += result.items
        return _CBORParseResult(remaining=remaining, items=total_items)

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return sum(f.min_items(pkt) for f in self.seq)

    def structural_max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return sum(f.structural_max_items(pkt) for f in self.seq)


class CBORF_ARRAY(_CBORF_compound):
    """
    CBOR array with a fixed sequence of named, typed fields (major type 4).

    Analogous to ASN1F_SEQUENCE: each positional element is a
    :class:`CBORF_field`, wrapped in one definite (or indefinite) CBOR array.
    Prefer this over :class:`CBORF_ITEMS` when the wire form is a single
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

    def __init__(self, *seq):
        # type: (*Any) -> None
        super(CBORF_ARRAY, self).__init__(*seq)
        self._reject_nonterminal_remainder_of()

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
            if available < 0 or available < needed:
                raise CBOR_Decoding_Error("CBOR item count mismatch")
            if available == 0:
                if isinstance(field, CBORF_optional):
                    field._field.mark_absent(pkt)
                continue
            result = self._dissect_field(
                pkt, field, remaining, max_items=available
            )
            if result.items > items_left:
                raise CBOR_Decoding_Error(
                    "CBOR field consumed more items than remaining"
                )
            remaining = result.remaining
            items_left -= result.items
        if items_left != 0:
            raise CBOR_Decoding_Error("CBOR item count mismatch")
        return remaining

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        items_data, total_items = self._build_children(pkt)
        if self.encode_indefinite:
            data = (
                CBOR_encode_initial(
                    CBOR_MajorTypes.ARRAY, CBOR_AdditionalInfo.INDEFINITE
                ) +
                items_data +
                bytes([CBOR_BREAK_BYTE])
            )
        else:
            data = CBOR_encode_head(CBOR_MajorTypes.ARRAY, total_items)
            data += items_data
        return _CBORBuildResult(data, 1)

    def _dissect_counted(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> _CBORParseResult
        try:
            major_type, count, remaining = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != CBOR_MajorTypes.ARRAY:
            raise CBOR_Type_Mismatch(
                "Expected major type 4 (array), got %d" % major_type)
        if count is CBOR_INDEFINITE:
            # Lightweight head/span walk — avoid building CBOR_Object trees
            # just to learn the item budget before the schema pass.
            child_max = sum(
                f.structural_max_items(pkt) for f in self.seq
            )
            try:
                item_count = cbor_count_items(
                    remaining,
                    max_count=child_max + 1,
                    until_break=True,
                )
            except CBOR_Codec_Decoding_Error as e:
                raise CBOR_Decoding_Error(str(e))
            if item_count > child_max:
                raise CBOR_Decoding_Error("CBOR item count mismatch")
            remaining = self._dissect_children_budgeted(
                pkt, remaining, item_count
            )
            try:
                remaining = cbor_consume_break(remaining)
            except CBOR_Codec_Decoding_Error as e:
                raise CBOR_Decoding_Error(str(e))
        else:
            remaining = self._dissect_children_budgeted(
                pkt, remaining, count
            )
        return _CBORParseResult(remaining=remaining, items=1)


class CBORF_ARRAY_INDEFINITE(CBORF_ARRAY):
    """A field to act as an array but to always encode to indefinite-length."""

    encode_indefinite = True


_ARRAY_T = Union[
    Type[Packet],
    Type['CBORF_field[Any]'],
    'CBORF_PACKET',
    'CBORF_field[Any]',
]


class _CBORF_HOMOGENEOUS(CBORF_field[List[Any]]):
    """Shared machinery for homogeneous CBOR collections."""
    islist = 1

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        # Collections are not leaf encoders; use counted compound build.
        return self._build_counted(pkt).data

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 pkt_cls=None,  # type: _ARRAY_T
                 next_cls_cb=None,  # type: Optional[Callable[..., Optional[Type[Packet]]]]  # noqa: E501
                 max_count=None,  # type: Optional[int]
                 ):
        # type: (...) -> None
        self.cls = None
        self.item_field = None
        self.holds_packets = 0
        self.next_cls_cb = None  # type: Optional[Callable[..., Optional[Type[Packet]]]]
        self.max_count = max_count
        if next_cls_cb is not None:
            if pkt_cls is not None:
                raise ValueError(
                    "Pass only next_cls_cb, or only pkt_cls"
                )
            self.next_cls_cb = next_cls_cb
            self.holds_packets = 1
        elif pkt_cls is None:
            raise ValueError("Provide pkt_cls or next_cls_cb")
        elif (
            (isinstance(pkt_cls, type) and
             issubclass(pkt_cls, CBORF_REMAINDER_OF))
            or isinstance(pkt_cls, CBORF_REMAINDER_OF)
        ):
            raise ValueError(
                "CBORF_REMAINDER_OF is not one CBOR item and cannot be "
                "used as pkt_cls"
            )
        elif (
            (isinstance(pkt_cls, type) and issubclass(pkt_cls, CBORF_field))
            or isinstance(pkt_cls, CBORF_field)
        ):
            if isinstance(pkt_cls, type):
                self.item_field = pkt_cls("_item", None)  # type: ignore
            else:
                self.item_field = pkt_cls
            # Packet-valued element fields must register as packet storage
            # even though decode/encode still go through item_field.
            self.holds_packets = 1 if getattr(
                self.item_field, "holds_packets", False
            ) else 0
        else:
            self.cls = self._require_packet_cls(pkt_cls)
            self.holds_packets = 1
        super(_CBORF_HOMOGENEOUS, self).__init__(name, default)

    def cache_fingerprint(self, x):
        # type: (Any) -> Any
        """Compose item fingerprints when the element field provides them.

        Packet-valued collections return ``None`` so the parent packet uses
        nested ``_raw_packet_cache_field_value`` composition.
        """
        if self.holds_packets or self.item_field is None or x is None:
            return None
        item_fp = getattr(self.item_field, "cache_fingerprint", None)
        if item_fp is None:
            return None
        return tuple(item_fp(item) for item in x)

    @staticmethod
    def _require_packet_cls(pkt_cls):
        # type: (Any) -> Type[CBOR_Packet]
        """Validate a CBOR_Packet subclass with a non-None CBOR_root."""
        from scapy.cborpacket import CBOR_Packet
        if (
            isinstance(pkt_cls, type)
            and issubclass(pkt_cls, CBOR_Packet)
            and getattr(pkt_cls, "CBOR_root", None) is not None
        ):
            return cast("Type[CBOR_Packet]", pkt_cls)
        raise ValueError(
            "pkt_cls must be a CBOR_Packet subclass with CBOR_root"
        )

    def _list_limit(self):
        # type: () -> int
        if self.max_count is not None:
            return self.max_count
        return config.conf.max_list_count

    def _check_list_limit(self, consumed):
        # type: (int) -> None
        limit = self._list_limit()
        if consumed >= limit:
            raise CBOR_Decoding_Error(
                "CBOR %s exceeded max_count=%d"
                % (self.__class__.__name__, limit)
            )

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> List[Any]
        if x is None:
            return None  # type: ignore
        if self.item_field is not None:
            return [self.item_field.any2i(pkt, item) for item in x]
        items = list(x)
        for item in items:
            _cbor_attach_parent(pkt, item)
        return items

    def _decode_element(self, pkt, s, values=None):
        # type: (CBOR_Packet, bytes, Optional[List[Any]]) -> Tuple[Any, bytes]
        if self.item_field is not None:
            result = self.item_field._parse_value(pkt, s)
            if result.items != 1:
                raise CBOR_Decoding_Error(
                    "%s element must consume exactly one item"
                    % self.__class__.__name__
                )
            return result.value, result.remaining
        pkt_cls = self.cls
        if self.next_cls_cb is not None:
            values = values if values is not None else []
            pkt_cls = self.next_cls_cb(
                pkt,
                values,
                values[-1] if values else None,
                s,
            )
            if pkt_cls is CBOR_NO_ITEM or pkt_cls is None:
                return CBOR_NO_ITEM, s
            pkt_cls = self._require_packet_cls(pkt_cls)
        item_bytes, remaining = cbor_item_span(s)
        try:
            child = pkt_cls(item_bytes, _parent=pkt)  # type: ignore
        except CBOR_Decoding_Error:
            raise
        except Exception as exc:
            if config.conf.debug_dissector:
                raise
            raise CBOR_Decoding_Error(str(exc))
        return child, remaining

    def _encode_element(self, pkt, item):
        # type: (CBOR_Packet, Any) -> bytes
        if self.item_field is not None:
            result = self.item_field._build_value(pkt, item)
            if result.items != 1:
                raise CBOR_Encoding_Error(
                    "%s element must emit exactly one item"
                    % self.__class__.__name__
                )
            return result.data
        return _encode_exactly_one_cbor_item(
            item, context="%s element" % self.__class__.__name__
        )

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, Any) -> str
        if self.item_field is None:
            return repr(x)
        if x is None:
            return self._empty_repr
        return self._open_repr + ", ".join(
            self.item_field.i2repr(pkt, item) for item in x
        ) + self._close_repr

    def __repr__(self):
        # type: () -> str
        return "<%s %s>" % (self.__class__.__name__, self.name)


class CBORF_REMAINDER_OF(_CBORF_HOMOGENEOUS):
    """
    Unframed sequence of homogeneous elements (no CBOR array head).

    Preferred constructors (ASN1F_SEQUENCE_OF / PacketListField style)::

        CBORF_REMAINDER_OF("items", [], pkt_cls=MyPacket)
        CBORF_REMAINDER_OF("items", [], pkt_cls=CBORF_UNSIGNED_INTEGER)
        CBORF_REMAINDER_OF("items", [], next_cls_cb=choose_next)

    ``pkt_cls`` may be a :class:`CBOR_Packet` subclass or a
    :class:`CBORF_field` class/instance. Do not use a ``cls=`` keyword:
    :class:`~typing.Generic` reserves that name on Python 3.7.
    Pass only one of ``pkt_cls`` / ``next_cls_cb``.

    ``CBORF_REMAINDER_OF`` represents an unframed greedy tail of zero or more
    CBOR items. Because it consumes the remaining item budget/input, it must
    be a direct final child of a positional ``CBORF_ITEMS`` or
    ``CBORF_ARRAY``.

    It must not be wrapped in ``CBORF_optional``, ``CBORF_CONDITIONAL``, or
    ``CBORF_SEMANTIC_TAG``. Use ``max_count`` to cap decoding (defaults to
    ``conf.max_list_count``).
    """
    CBOR_tag = None
    _empty_repr = "()"
    _open_repr = "("
    _close_repr = ")"

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 pkt_cls=None,  # type: _ARRAY_T
                 next_cls_cb=None,  # type: Optional[Callable[..., Optional[Type[Packet]]]]  # noqa: E501
                 max_count=None,  # type: Optional[int]
                 ):
        # type: (...) -> None
        super(CBORF_REMAINDER_OF, self).__init__(
            name,
            default,
            pkt_cls=pkt_cls,
            next_cls_cb=next_cls_cb,
            max_count=max_count,
        )

    def _decode_items(self, pkt, data, max_items=None):
        # type: (CBOR_Packet, bytes, Optional[int]) -> Tuple[List[Any], bytes, int]
        """Decode zero or more immediate CBOR items; do not consume break."""
        values = []  # type: List[Any]
        remaining = data
        consumed = 0
        while remaining and not cbor_is_break(remaining):
            if max_items is not None and consumed >= max_items:
                break
            self._check_list_limit(consumed)
            before_len = len(remaining)
            item, next_remaining = self._decode_element(
                pkt, remaining, values=values
            )
            if item is CBOR_NO_ITEM:
                break
            if len(next_remaining) >= before_len:
                raise CBOR_Decoding_Error(
                    "Sequence decoder did not consume input")
            values.append(item)
            consumed += 1
            remaining = next_remaining
        return values, remaining, consumed

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[List[Any], bytes]
        values, remaining, _consumed = self._decode_items(pkt, s)
        return values, remaining

    def _dissect_counted(self, pkt, s, max_items=None):
        # type: (CBOR_Packet, bytes, Optional[int]) -> _CBORParseResult
        values, remaining, consumed = self._decode_items(
            pkt, s, max_items=max_items
        )
        pkt.setfieldval(self.name, values)
        return _CBORParseResult(remaining=remaining, items=consumed)

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        val = pkt.getfieldval(self.name)
        if val is None:
            raise CBOR_Encoding_Error(
                "Required collection field %r is None" % self.name)
        parts = [self._encode_element(pkt, item) for item in val]
        return _CBORBuildResult(b"".join(parts), len(val))

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 0

    def structural_max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return self._list_limit()


class CBORF_ARRAY_OF(_CBORF_HOMOGENEOUS):
    """
    CBOR array of homogeneous elements (major type 4).

    Preferred constructors::

        CBORF_ARRAY_OF("items", [], pkt_cls=MyPacket)
        CBORF_ARRAY_OF("items", [], pkt_cls=CBORF_UNSIGNED_INTEGER)

    ``pkt_cls`` may be a :class:`CBOR_Packet` subclass or a
    :class:`CBORF_field` class/instance. Do not use a ``cls=`` keyword:
    :class:`~typing.Generic` reserves that name on Python 3.7.
    Use ``max_count`` to cap decoding (defaults to ``conf.max_list_count``).
    """
    CBOR_tag = CBOR_MajorTypes.ARRAY
    _empty_repr = "[]"
    _open_repr = "["
    _close_repr = "]"

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 pkt_cls=None,  # type: _ARRAY_T
                 max_count=None,  # type: Optional[int]
                 ):
        # type: (...) -> None
        super(CBORF_ARRAY_OF, self).__init__(
            name, default, pkt_cls=pkt_cls, max_count=max_count
        )

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[List[Any], bytes]
        try:
            major_type, count, s = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != CBOR_MajorTypes.ARRAY:
            raise CBOR_Type_Mismatch(
                "Expected major type 4 (array), got %d" % major_type)
        lst = []  # type: List[Any]
        if count is CBOR_INDEFINITE:
            while True:
                if cbor_is_break(s):
                    s = cbor_consume_break(s)
                    break
                self._check_list_limit(len(lst))
                item, s = self._decode_element(pkt, s)
                lst.append(item)
        else:
            if count > self._list_limit():
                raise CBOR_Decoding_Error(
                    "CBOR %s exceeded max_count=%d"
                    % (self.__class__.__name__, self._list_limit())
                )
            for _ in range(count):
                item, s = self._decode_element(pkt, s)
                lst.append(item)
        return lst, s

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        if isinstance(x, fields.RawVal):
            return super(CBORF_ARRAY_OF, self).i2m(pkt, x)
        parts = [self._encode_element(pkt, item) for item in x]
        return (
            CBOR_encode_head(CBOR_MajorTypes.ARRAY, len(x))
            + b"".join(parts)
        )

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        val = pkt.getfieldval(self.name)
        if val is None:
            raise CBOR_Encoding_Error(
                "Required collection field %r is None" % self.name)
        return _CBORBuildResult(self.i2m(pkt, val), 1)


class _CBORF_MAP_UNKNOWN(CBORF_field[List[Tuple[str, Any]]]):
    """Per-map storage for unknown text-key extension pairs.

    Not a CBOR wire field by itself: owning :class:`CBORF_MAP` instances read
    and write this packet field around known members.
    """
    ismutable = True
    islist = 1

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> List[Tuple[str, Any]]
        if x is None or x is CBOR_ABSENT:
            return []
        return list(x)

    def do_copy(self, x):  # type: ignore[override]
        # type: (Any) -> Any
        return copy.deepcopy(x)

    def cache_fingerprint(self, x):
        # type: (Any) -> _CBORFingerprint
        """Wire-sensitive fingerprint for unknown text-key extension pairs."""
        if not x:
            return ()
        fingerprint = CBORF_ANY._cache_fingerprint
        return tuple(
            (fingerprint(key), fingerprint(value))
            for key, value in x
        )

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return not pkt.getfieldval(self.name)

    def _encode_leaf(self, x):
        # type: (Any) -> bytes
        raise CBOR_Encoding_Error(
            "_CBORF_MAP_UNKNOWN is not encoded as a standalone CBOR item"
        )

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[Any, bytes]
        raise CBOR_Decoding_Error(
            "_CBORF_MAP_UNKNOWN is not decoded as a standalone CBOR item"
        )


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

    Unknown received key/value pairs are retained in a dedicated packet field
    (``unknown_field``, default ``"_cbor_unknown"``) as ordered ``(key, value)``
    pairs.  While the packet raw cache is valid the exact received bytes are
    preserved; after any mutation unknown members are re-encoded using
    core-deterministic CBOR together with known fields. Schemas with more than
    one map must pass distinct ``unknown_field=`` names.

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
        unknown_field = kwargs.pop("unknown_field", "_cbor_unknown")
        if kwargs:
            raise TypeError(
                "CBORF_MAP() got unexpected keyword arguments: %s"
                % ", ".join(sorted(kwargs))
            )
        self.seq = seq
        field_by_name = {}  # type: Dict[str, Any]
        encoded_keys = {}  # type: Dict[str, bytes]
        for fld in seq:
            if isinstance(fld, CBORF_REMAINDER_OF):
                raise ValueError(
                    "CBORF_REMAINDER_OF cannot be a map member; "
                    "place it directly as the final positional field"
                )
            name = fld.name
            if name in field_by_name:
                raise ValueError(
                    "Duplicate CBOR map field name: %r" % (name,)
                )
            field_by_name[name] = fld
            encoded_keys[name] = CBORcodec_TEXT_STRING.enc(name)
        self._field_by_name = field_by_name
        self._encoded_keys = encoded_keys
        if unknown_field in field_by_name:
            raise ValueError(
                "CBORF_MAP unknown_field %r collides with a known member"
                % (unknown_field,)
            )
        self._unknown_field = _CBORF_MAP_UNKNOWN(unknown_field, [])

    def __repr__(self):
        # type: () -> str
        return "<%s%r>" % (self.__class__.__name__, self.seq)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return (
            all(f.is_empty(pkt) for f in self.seq)
            and self._unknown_field.is_empty(pkt)
        )

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any]]
        return [
            child
            for field in self.seq
            for child in field.get_fields_list()
        ] + [self._unknown_field]

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        # Emit pairs sorted by encoded key bytes (RFC 8949 core deterministic).
        pairs = []  # type: List[Tuple[bytes, bytes]]
        for fld in self.seq:
            value_result = fld._build_counted(pkt)
            if value_result.items == 0:
                continue
            if value_result.items != 1:
                raise CBOR_Encoding_Error(
                    "CBOR map value for %r must emit exactly one item"
                    % fld.name
                )
            pairs.append((self._encoded_keys[fld.name], value_result.data))
        known_names = set(self._field_by_name)
        seen_unknown = set()  # type: set[str]
        unknown = pkt.getfieldval(self._unknown_field.name) or []
        for key, value in unknown:
            if not isinstance(key, str):
                raise CBOR_Encoding_Error(
                    "CBOR map unknown key must be a text string, got %r"
                    % (key,)
                )
            if key in known_names or key in seen_unknown:
                raise CBOR_Encoding_Error(
                    "Duplicate CBOR map key: %r" % (key,)
                )
            seen_unknown.add(key)
            key_bytes = CBORcodec_TEXT_STRING.enc(key)
            value_bytes = CBORcodec_Object.encode_cbor_item_deterministic(value)
            pairs.append((key_bytes, value_bytes))
        pairs.sort(key=lambda item: item[0])
        parts = []  # type: List[bytes]
        for key_bytes, value_bytes in pairs:
            parts.append(key_bytes)
            parts.append(value_bytes)
        data = CBOR_encode_head(CBOR_MajorTypes.MAP, len(pairs)) + b"".join(parts)
        return _CBORBuildResult(data, 1)

    def _dissect_counted(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> _CBORParseResult
        try:
            major_type, count, remaining = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != CBOR_MajorTypes.MAP:
            raise CBOR_Type_Mismatch(
                "Expected major type 5 (map), got %d" % major_type)

        field_map = self._field_by_name
        seen_keys = set()  # type: set[str]
        seen_fields = set()  # type: set[str]
        pair_values = {}  # type: Dict[str, bytes]
        unknown_pairs = []  # type: List[Tuple[str, Any]]

        def _collect_pair():
            # type: () -> None
            nonlocal remaining
            try:
                key_obj, after_key = CBORcodec_Object.decode_cbor_item(remaining)
            except CBOR_Codec_Decoding_Error as e:
                raise CBOR_Decoding_Error(str(e))
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
            if key in field_map:
                try:
                    val_bytes, remaining = cbor_item_span(after_key)
                except CBOR_Codec_Decoding_Error as e:
                    raise CBOR_Decoding_Error(str(e))
                pair_values[key] = val_bytes
            else:
                try:
                    val_obj, remaining = CBORcodec_Object.decode_cbor_item(
                        after_key
                    )
                except CBOR_Codec_Decoding_Error as e:
                    raise CBOR_Decoding_Error(str(e))
                unknown_pairs.append((key, val_obj))

        limit = config.conf.max_list_count
        if count is CBOR_INDEFINITE:
            while True:
                if cbor_is_break(remaining):
                    remaining = cbor_consume_break(remaining)
                    break
                if len(seen_keys) >= limit:
                    raise CBOR_Decoding_Error(
                        "CBOR %s exceeded max_count=%d"
                        % (self.__class__.__name__, limit)
                    )
                _collect_pair()
        else:
            if count > limit:
                raise CBOR_Decoding_Error(
                    "CBOR %s exceeded max_count=%d"
                    % (self.__class__.__name__, limit)
                )
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
            result = value_fld._dissect_counted(pkt, val_bytes)
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
                if isinstance(fld, CBORF_optional):
                    fld._field.mark_absent(pkt)
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
        pkt.setfieldval(self._unknown_field.name, unknown_pairs)
        return _CBORParseResult(remaining=remaining, items=1)


class CBORF_SEMANTIC_TAG(CBORF_element):
    """
    CBOR semantic tag wrapper (major type 6).

    Wraps an ``inner_field`` with the given numeric ``tag_num``.  The tag
    number is schema metadata only: it is not stored as editable packet
    field state.  The inner field stores its value under its own name.

    Example::

        class TimestampPkt(CBOR_Packet):
            CBOR_root = CBORF_SEMANTIC_TAG(
                1, CBORF_INTEGER("ts", 0)
            )
    """
    CBOR_tag = CBOR_MajorTypes.TAG
    holds_packets = 0

    def __init__(self,
                 tag_num,  # type: int
                 inner_field,  # type: CBORF_field[Any]
                 ):
        # type: (...) -> None
        if tag_num < 0 or tag_num > CBOR_UINT64_MAX:
            raise CBOR_Encoding_Error(
                "Semantic tag number out of uint64 range")
        if isinstance(inner_field, CBORF_REMAINDER_OF):
            raise ValueError(
                "CBORF_REMAINDER_OF cannot be wrapped; "
                "place it directly as the final positional field"
            )
        self.tag_num = tag_num
        self.inner_field = inner_field

    @property
    def name(self):
        # type: () -> str
        """Map/schema key identity comes from the tagged value field."""
        return self.inner_field.name

    def _parse_tag_head(self, s):
        # type: (bytes) -> bytes
        try:
            major_type, tag_num, remaining = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != CBOR_MajorTypes.TAG:
            raise CBOR_Type_Mismatch(
                "Expected major type 6 (semantic tag), got %d" % major_type)
        if tag_num != self.tag_num:
            raise CBOR_Type_Mismatch(
                "Expected tag %d, got %d" % (self.tag_num, tag_num))
        return remaining

    def _encode_tagged(self, inner_data):
        # type: (bytes) -> bytes
        return CBOR_encode_head(CBOR_MajorTypes.TAG, self.tag_num) + inner_data

    def matches_next_item(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bool
        if not s or cbor_is_break(s):
            return False
        try:
            major_type, tag_num, _rem = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error:
            return False
        return (
            major_type == CBOR_MajorTypes.TAG
            and tag_num == self.tag_num
        )

    def _dissect_counted(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> _CBORParseResult
        remaining = self._parse_tag_head(s)
        inner = self.inner_field._dissect_counted(pkt, remaining)
        if inner.items != 1:
            raise CBOR_Decoding_Error(
                "Semantic tag content must be exactly one CBOR item")
        return _CBORParseResult(remaining=inner.remaining, items=1)

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        inner = self.inner_field._build_counted(pkt)
        if inner.items != 1:
            raise CBOR_Encoding_Error(
                "Semantic tag content must be exactly one CBOR item")
        return _CBORBuildResult(self._encode_tagged(inner.data), 1)

    def _parse_value(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> _CBORParseResult
        remaining = self._parse_tag_head(s)
        inner = self.inner_field._parse_value(pkt, remaining)
        if inner.items != 1:
            raise CBOR_Decoding_Error(
                "Semantic tag content must be exactly one CBOR item")
        return _CBORParseResult(
            value=inner.value, remaining=inner.remaining, items=1
        )

    def _build_value(self, pkt, value):
        # type: (CBOR_Packet, Any) -> _CBORBuildResult
        inner = self.inner_field._build_value(pkt, value)
        if inner.items != 1:
            raise CBOR_Encoding_Error(
                "Semantic tag content must be exactly one CBOR item")
        return _CBORBuildResult(data=self._encode_tagged(inner.data), items=1)

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any]]
        # Tag number is schema metadata; only the tagged value is packet state.
        return self.inner_field.get_fields_list()

    def mark_absent(self, pkt):
        # type: (CBOR_Packet) -> None
        self.inner_field.mark_absent(pkt)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return self.inner_field.is_empty(pkt)


##############################
#    Complex CBOR Fields     #
##############################

class CBORF_optional(CBORF_element):
    """
    Wrapper making a CBOR field or semantic-tag field optional.

    Accepts :class:`CBORF_field` or :class:`CBORF_SEMANTIC_TAG` (presence
    methods required). Absence is recorded as ``CBOR_ABSENT`` on every path
    (lookahead mismatch, exhausted parent array, missing map key).  If the
    next item matches but decoding fails, the error propagates.
    """

    def __init__(self, field):
        # type: (Union[CBORF_field[Any], CBORF_SEMANTIC_TAG]) -> None
        if not isinstance(field, (CBORF_field, CBORF_SEMANTIC_TAG)):
            raise TypeError(
                "CBORF_optional requires CBORF_field or CBORF_SEMANTIC_TAG; "
                "got %r" % (type(field).__name__,)
            )
        if isinstance(field, CBORF_REMAINDER_OF):
            raise ValueError(
                "CBORF_REMAINDER_OF cannot be wrapped; "
                "place it directly as the final positional field"
            )
        self._field = field

    def __getattr__(self, attr):
        # type: (str) -> Any
        return getattr(self._field, attr)

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        if self._field.is_empty(pkt):
            return _CBORBuildResult(b"", 0)
        return self._field._build_counted(pkt)

    def _dissect_counted(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> _CBORParseResult
        if not self._field.matches_next_item(pkt, s):
            self._field.mark_absent(pkt)
            return _CBORParseResult(remaining=s, items=0)
        return self._field._dissect_counted(pkt, s)

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 0

    def structural_max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return self._field.structural_max_items(pkt)


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
        if isinstance(fld, CBORF_REMAINDER_OF):
            raise ValueError(
                "CBORF_REMAINDER_OF cannot be wrapped; "
                "place it directly as the final positional field"
            )
        fields.ConditionalField.__init__(self, fld, cond)

    def __repr__(self):
        # type: () -> str
        return "<%s%r>" % (self.__class__.__name__, self.fld)

    @property
    def owners(self):
        return self.fld.owners

    def _build_counted(self, pkt):
        # type: (CBOR_Packet) -> _CBORBuildResult
        if self._evalcond(pkt):
            return self.fld._build_counted(pkt)
        return _CBORBuildResult(b"", 0)

    def _dissect_counted(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> _CBORParseResult
        if self._evalcond(pkt):
            return self.fld._dissect_counted(pkt, s)
        return _CBORParseResult(remaining=s, items=0)

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        if self._evalcond(pkt):
            return self.fld.min_items(pkt)
        return 0

    def structural_max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return self.fld.structural_max_items(pkt)


class CBORF_PACKET(CBORF_field['CBOR_Packet']):
    """
    CBOR field that encapsulates a nested :class:`CBOR_Packet`.

    The nested packet is encoded as-is (its ``CBOR_root.build()`` output)
    and decoded by instantiating ``pkt_cls`` from the current byte stream.

    Use ``pkt_cls=`` (or a positional third argument). A ``cls=`` keyword
    conflicts with :class:`~typing.Generic` on Python 3.7.
    """
    holds_packets = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[CBOR_Packet]
                 pkt_cls,  # type: Type[CBOR_Packet]
                 ):
        # type: (...) -> None
        self.cls = _CBORF_HOMOGENEOUS._require_packet_cls(pkt_cls)
        super(CBORF_PACKET, self).__init__(name, default)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_Packet, bytes]
        item_bytes, remain = cbor_item_span(s)
        try:
            child = self.cls(item_bytes, _parent=pkt)  # type: ignore
        except CBOR_Decoding_Error:
            raise
        except Exception as exc:
            if config.conf.debug_dissector:
                raise
            raise CBOR_Decoding_Error(str(exc))
        return child, remain

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        if x is None:
            raise CBOR_Encoding_Error(
                "Required field %r is None" % self.name)
        return _encode_exactly_one_cbor_item(
            x, context="field %r" % self.name
        )

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> CBOR_Packet
        return cast('CBOR_Packet', _cbor_attach_parent(pkt, x))

    def randval(self):  # type: ignore
        # type: () -> CBOR_Packet
        return packet.fuzz(self.cls())
