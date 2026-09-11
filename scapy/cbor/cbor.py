# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
CBOR (Concise Binary Object Representation) - RFC 8949
Following the ASN.1 paradigm
"""

import copy
import math
import random
import struct
from typing import (
    Any,
    Dict,
    FrozenSet,
    Generic,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    TYPE_CHECKING,
)

from scapy.compat import plain_str
from scapy.error import Scapy_Exception, log_runtime
from scapy.utils import Enum_metaclass, EnumElement
from scapy.volatile import RandField

if TYPE_CHECKING:
    from scapy.cbor import CBORcodec_Object


class RandCBORObject(RandField["CBOR_Object[Any]"]):
    """Random CBOR object generator for fuzzing"""

    def __init__(self, objlist=None):
        # type: (Optional[List[Type[CBOR_Object[Any]]]]) -> None
        if objlist:
            self.objlist = objlist
        else:
            # Default list will be populated lazily to avoid forward reference
            self.objlist = None  # type: ignore
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"  # noqa: E501

    def _get_objlist(self):
        # type: () -> List[Type[CBOR_Object[Any]]]
        """Get the list of CBOR object types (lazy initialization)"""
        if self.objlist is None:
            # Import here to avoid circular dependency
            self.objlist = [
                CBOR_UNSIGNED_INTEGER,
                CBOR_NEGATIVE_INTEGER,
                CBOR_BYTE_STRING,
                CBOR_TEXT_STRING,
                CBOR_ARRAY,
                CBOR_MAP,
                CBOR_FALSE,
                CBOR_TRUE,
                CBOR_NULL,
                CBOR_UNDEFINED,
                CBOR_FLOAT,
            ]
        return self.objlist

    def _fix(self, n=0):
        # type: (int) -> CBOR_Object[Any]
        objlist = self._get_objlist()

        # If we're at max recursion depth and have arrays/maps in objlist,
        # filter them out to avoid infinite recursion
        if n >= 10:
            objlist = [o for o in objlist if o not in [CBOR_ARRAY, CBOR_MAP]]
            if not objlist:
                # Fallback to a simple type
                return CBOR_UNSIGNED_INTEGER(
                    abs(int(random.gauss(1000, 2000))))

        o = random.choice(objlist)

        if o == CBOR_UNSIGNED_INTEGER:
            # Random unsigned integer using gaussian distribution
            return o(abs(int(random.gauss(1000, 2000))))
        elif o == CBOR_NEGATIVE_INTEGER:
            # Random negative integer - ensure it's always negative
            return o(-abs(int(random.gauss(1000, 2000))) - 1)
        elif o == CBOR_BYTE_STRING:
            # Random byte string with exponential length
            length = int(random.expovariate(0.05) + 1)
            return o(bytes(random.randint(0, 255) for _ in range(length)))
        elif o == CBOR_TEXT_STRING:
            # Random text string with exponential length
            length = int(random.expovariate(0.05) + 1)
            return o(
                "".join(random.choice(self.chars) for _ in range(length)))
        elif o == CBOR_ARRAY:
            # Random array with random elements (limit recursion depth)
            # Use smaller size and limit depth more aggressively for performance
            size = min(int(random.expovariate(0.2) + 1), 3)  # Smaller arrays

            # Get child objlist - use simple types if current list only has
            # recursive types
            child_objlist = self._get_objlist()
            non_recursive = [
                t for t in child_objlist if t not in [CBOR_ARRAY, CBOR_MAP]]

            # If objlist only contains recursive types or we're deep, use simple
            # types for children
            if not non_recursive or n >= 3:
                child_objlist = [
                    CBOR_UNSIGNED_INTEGER, CBOR_TEXT_STRING, CBOR_NULL]

            return o([self.__class__(objlist=child_objlist)._fix(n + 1)
                      for _ in range(size)])
        elif o == CBOR_MAP:
            # Random map with random key-value pairs (limit recursion depth)
            # CBOR maps use raw Python values as keys, CBOR objects as values
            # Use smaller size and limit depth more aggressively for
            # performance
            size = min(int(random.expovariate(0.2) + 1), 3)  # Smaller maps

            # Get child objlist - use simple types if current list only has
            # recursive types
            child_objlist = self._get_objlist()
            non_recursive = [
                t for t in child_objlist if t not in [CBOR_ARRAY, CBOR_MAP]]

            # If objlist only contains recursive types or we're deep,
            # use simple types for children
            if not non_recursive or n >= 3:
                child_objlist = [
                    CBOR_UNSIGNED_INTEGER, CBOR_TEXT_STRING, CBOR_NULL]

            map_dict = {}
            for _ in range(size):
                # Use simple hashable types for keys (int or str)
                if random.choice([True, False]):
                    key = abs(int(random.gauss(100, 200)))
                else:
                    key_len = int(random.expovariate(0.1) + 1)
                    key = "".join(random.choice(self.chars) for _ in range(key_len))  # noqa: E501
                val_obj = self.__class__(objlist=child_objlist)._fix(n + 1)
                map_dict[key] = val_obj
            return o(map_dict)
        elif o == CBOR_FALSE:
            return o()
        elif o == CBOR_TRUE:
            return o()
        elif o == CBOR_NULL:
            return o()
        elif o == CBOR_UNDEFINED:
            return o()
        elif o == CBOR_FLOAT:
            # Random float with gaussian distribution
            return o(random.gauss(0, 1000.0))

        # Default fallback to unsigned integer
        return CBOR_UNSIGNED_INTEGER(
            abs(int(random.gauss(1000, 2000))))


##############
#    CBOR    #
##############


class CBOR_Error(Scapy_Exception):
    pass


class CBOR_Encoding_Error(CBOR_Error):
    pass


class CBOR_Decoding_Error(CBOR_Error):
    pass


class CBOR_BadTag_Decoding_Error(CBOR_Decoding_Error):
    pass


class CBORCodec(EnumElement):
    def register_stem(cls, stem):
        # type: (Type[CBORcodec_Object[Any]]) -> None
        cls._stem = stem

    def dec(cls, s, context=None, _depth=0):
        # type: (bytes, Optional[Any], int) -> CBOR_Object[Any]
        return cls._stem.dec(s, context=context, _depth=_depth)  # type: ignore

    def safedec(cls, s, context=None, _depth=0):
        # type: (bytes, Optional[Any], int) -> CBOR_Object[Any]
        return cls._stem.safedec(s, context=context, _depth=_depth)  # type: ignore

    def get_stem(cls):
        # type: () -> type
        return cls._stem


class CBOR_Codecs_metaclass(Enum_metaclass):
    element_class = CBORCodec


class CBOR_Codecs(metaclass=CBOR_Codecs_metaclass):
    CBOR = cast(CBORCodec, 1)


class CBORTag(EnumElement):
    """Represents a CBOR major type"""

    def __init__(self,
                 key,  # type: str
                 value,  # type: int
                 codec=None  # type: Optional[Dict[CBORCodec, Type[CBORcodec_Object[Any]]]]  # noqa: E501
                 ):
        # type: (...) -> None
        EnumElement.__init__(self, key, value)
        if codec is None:
            codec = {}
        self._codec = codec

    def clone(self):
        # type: () -> CBORTag
        return self.__class__(self._key, self._value, self._codec)

    def register_cbor_object(self, cborobj):
        # type: (Type[CBOR_Object[Any]]) -> None
        self._cbor_obj = cborobj

    def cbor_object(self, val):
        # type: (Any) -> CBOR_Object[Any]
        if hasattr(self, "_cbor_obj"):
            return self._cbor_obj(val)
        raise CBOR_Error("%r does not have any assigned CBOR object" % self)

    def register(self, codecnum, codec):
        # type: (CBORCodec, Type[CBORcodec_Object[Any]]) -> None
        self._codec[codecnum] = codec

    def get_codec(self, codec):
        # type: (Any) -> Type[CBORcodec_Object[Any]]
        try:
            c = self._codec[codec]
        except KeyError:
            raise CBOR_Error("Codec %r not found for tag %r" % (codec, self))
        return c


class CBOR_MajorTypes_metaclass(Enum_metaclass):
    element_class = CBORTag

    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[CBOR_MajorTypes]
        rdict = {}
        for k, v in dct.items():
            if isinstance(v, int):
                v = CBORTag(k, v)
                dct[k] = v
                rdict[v] = v
            elif isinstance(v, CBORTag):
                rdict[v] = v
        dct["__rdict__"] = rdict

        ncls = cast('Type[CBOR_MajorTypes]',
                    type.__new__(cls, name, bases, dct))
        return ncls


class CBOR_MajorTypes(metaclass=CBOR_MajorTypes_metaclass):
    """CBOR Major Types (RFC 8949)"""
    name = "CBOR_MAJOR_TYPES"
    # CBOR major types (3-bit value in the high-order 3 bits)
    UNSIGNED_INTEGER = cast(CBORTag, 0)
    NEGATIVE_INTEGER = cast(CBORTag, 1)
    BYTE_STRING = cast(CBORTag, 2)
    TEXT_STRING = cast(CBORTag, 3)
    ARRAY = cast(CBORTag, 4)
    MAP = cast(CBORTag, 5)
    TAG = cast(CBORTag, 6)
    SIMPLE_AND_FLOAT = cast(CBORTag, 7)


class CBOR_AdditionalInfo(metaclass=Enum_metaclass):
    """CBOR additional-info codes used with argument encoding (RFC 8949)."""
    name = "CBOR_ADDITIONAL_INFO"
    ONE_BYTE = 24
    TWO_BYTES = 25
    FOUR_BYTES = 26
    EIGHT_BYTES = 27
    RESERVED_28 = 28
    RESERVED_29 = 29
    RESERVED_30 = 30
    INDEFINITE = 31


class CBOR_SimpleValue(metaclass=Enum_metaclass):
    """Well-known CBOR simple values encoded in major type 7."""
    name = "CBOR_SIMPLE_VALUE"
    FALSE = 20
    TRUE = 21
    NULL = 22
    UNDEFINED = 23


class CBOR_FloatAI(metaclass=Enum_metaclass):
    """Float additional-info codes under major type 7 (RFC 8949 §3.3)."""
    name = "CBOR_FLOAT_AI"
    HALF = 25    # IEEE binary16
    SINGLE = 26  # IEEE binary32
    DOUBLE = 27  # IEEE binary64


class CBOR_KeyKind(metaclass=Enum_metaclass):
    """Discriminator for hashable RFC 8949 map-key norms.

    Norms are tuples ``(kind, ...)`` (not dicts) so they remain hashable for
    ``frozenset`` map-key identity.  ``kind`` is always a ``CBOR_KeyKind``.
    """
    name = "CBOR_KEY_KIND"
    BOOL = 1
    NULL = 2
    UNDEF = 3
    INT = 4
    BSTR = 5
    TSTR = 6
    ARRAY = 7
    MAP = 8
    TAG = 9
    SIMPLE = 10
    OBJ = 11
    OTHER = 12
    NAN = 13
    FINITE = 14


class CBOR_FingerprintKind(CBOR_KeyKind):
    """Discriminator for ``CBORF_ANY`` raw-cache fingerprints.

    Extends :class:`CBOR_KeyKind` with rebuild-sensitive tags that map-key
    norms do not need (sentinels, signed zero/inf, ``_encoded`` floats,
    Python containers).
    """
    name = "CBOR_FINGERPRINT_KIND"
    SENTINEL = 15
    FLOAT = 16
    INF = 17
    ZERO = 18
    MAPDATA = 19
    LIST = 20
    DICT = 21
    PY = 22


# Recursive hashable RFC 8949 map-key norm.
# First element is a ``CBOR_KeyKind`` ``EnumElement`` (typed ``Any`` because
# ``Enum_metaclass`` members are ``int`` in the class body).
_CBORKeyNorm = Union[
    Tuple[Any, None],
    Tuple[Any, bool],
    Tuple[Any, int],
    Tuple[Any, bytes],
    Tuple[Any, str],
    Tuple[Any, float],
    Tuple[Any, int, int],
    Tuple[Any, Tuple["_CBORKeyNorm", ...]],
    Tuple[Any, FrozenSet[Tuple["_CBORKeyNorm", "_CBORKeyNorm"]]],
    Tuple[Any, int, "_CBORKeyNorm"],
    Tuple[Any, str, "_CBORKeyNorm"],
    Tuple[Any, str, str],
]

# Recursive rebuild-relevant fingerprint for ``CBORF_ANY`` raw-cache state.
# Kind discriminator is ``CBOR_FingerprintKind`` (same EnumElement typing note).
_CBORFingerprint = Tuple[Any, ...]


CBOR_UINT64_MAX = (1 << 64) - 1


class CBOR_Object_metaclass(type):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[CBOR_Object[Any]]
        c = cast(
            'Type[CBOR_Object[Any]]',
            super(CBOR_Object_metaclass, cls).__new__(cls, name, bases, dct)
        )
        if c.tag is not None:
            try:
                c.tag.register_cbor_object(c)
            except Exception:
                # Some objects may not have tags yet
                log_runtime.exception("Failed to register CBOR object %r" % c)
        return c


_K = TypeVar('_K')


class CBOR_Object(Generic[_K], metaclass=CBOR_Object_metaclass):
    """Base class for CBOR value objects"""
    tag = None  # type: ignore  # Subclasses must define their own tag

    def __init__(self, val):
        # type: (_K) -> None
        self.val = val

    def enc(self, codec=None):
        # type: (Any) -> bytes
        if codec is None:
            codec = CBOR_Codecs.CBOR
        if self.tag is None:
            raise CBOR_Error("Cannot encode object without a tag")
        # Pass self instead of self.val for special handling
        return self.tag.get_codec(codec).enc(self)

    def __repr__(self):
        # type: () -> str
        return "<%s[%r]>" % (self.__class__.__name__, self.val)

    def __str__(self):
        # type: () -> str
        return plain_str(self.enc())

    def __bytes__(self):
        # type: () -> bytes
        return self.enc()

    def strshow(self, lvl=0):
        # type: (int) -> str
        return ("  " * lvl) + repr(self) + "\n"

    def show(self, lvl=0):
        # type: (int) -> None
        print(self.strshow(lvl))

    def __eq__(self, other):
        # type: (Any) -> bool
        if isinstance(other, CBOR_Object):
            return (
                type(self) is type(other)
                and self.val == other.val
            )
        return NotImplemented

    def __ne__(self, other):
        # type: (Any) -> bool
        equal = self.__eq__(other)
        if equal is NotImplemented:
            return NotImplemented
        return not equal

    # No __hash__: defining __eq__ without __hash__ makes instances unhashable.
    # Immutable scalar subclasses may add semantic hashing later if needed.


#######################
#     CBOR objects    #
#######################


class CBOR_UNSIGNED_INTEGER(CBOR_Object[int]):
    """CBOR unsigned integer (major type 0)"""
    tag = CBOR_MajorTypes.UNSIGNED_INTEGER


class CBOR_NEGATIVE_INTEGER(CBOR_Object[int]):
    """CBOR negative integer (major type 1)"""
    tag = CBOR_MajorTypes.NEGATIVE_INTEGER


class CBOR_BYTE_STRING(CBOR_Object[bytes]):
    """CBOR byte string (major type 2)"""
    tag = CBOR_MajorTypes.BYTE_STRING

    def __repr__(self):
        # type: () -> str
        hexval = self.val.hex() if self.val else ''
        return "<%s[h'%s']>" % (self.__class__.__name__, hexval)


class CBOR_TEXT_STRING(CBOR_Object[str]):
    """CBOR text string (major type 3)"""
    tag = CBOR_MajorTypes.TEXT_STRING


class CBOR_ARRAY(CBOR_Object[List[Any]]):
    """CBOR array (major type 4)"""
    tag = CBOR_MajorTypes.ARRAY

    def strshow(self, lvl=0):
        # type: (int) -> str
        s = ("  " * lvl) + ("# CBOR_ARRAY:") + "\n"
        for o in self.val:
            if hasattr(o, 'strshow'):
                s += o.strshow(lvl=lvl + 1)
            else:
                s += ("  " * (lvl + 1)) + repr(o) + "\n"
        return s


class CBORMapData(object):
    """Ordered CBOR map pairs with typed dict-like access for scalar keys.

    Storage preserves ordered ``(key, value)`` pairs so ``enc()`` can emit a
    faithful CBOR map.  Lookup (``__getitem__`` / ``__contains__``) uses
    RFC 8949 map-key equivalence via :func:`_cbor_key_equivalent`, so values
    that compare equal under Python ``==`` but differ as CBOR items (``1`` vs
    ``True``, distinct NaN payloads, etc.) stay distinct.

    Arbitrary CBOR maps cannot always be represented as Python ``dict``
    objects; :meth:`as_dict` raises when equivalence or Python key collision
    would lose distinctions.
    """

    __slots__ = ("_pairs",)

    def __init__(self, pairs=None):
        # type: (Optional[List[Tuple[Any, Any]]]) -> None
        self._pairs = list(pairs or [])

    def cbor_pairs(self):
        # type: () -> List[Tuple[Any, Any]]
        return list(self._pairs)

    def as_dict(self):
        # type: () -> Dict[Any, Any]
        """Convert to a Python dict, raising if CBOR key distinctions would be lost."""
        out = {}  # type: Dict[Any, Any]
        used_norms = set()  # type: Set[_CBORKeyNorm]
        for key, value in self._pairs:
            norm = _cbor_key_norm(key)
            if norm in used_norms:
                raise ValueError(
                    "CBOR map keys are equivalent under RFC 8949; "
                    "cannot convert to dict without losing distinctions"
                )
            py_key = key.val if isinstance(key, CBOR_Object) else key
            try:
                hash(py_key)
            except TypeError:
                raise ValueError(
                    "CBOR map key cannot be represented as a Python dict key"
                )
            # Also reject Python-dict collisions (True vs 1, etc.).
            if py_key in out:
                raise ValueError(
                    "Converting CBOR map to dict would collapse distinct keys"
                )
            used_norms.add(norm)
            out[py_key] = value
        return out

    def copy(self):
        # type: () -> CBORMapData
        return copy.deepcopy(self)

    def __copy__(self):
        # type: () -> CBORMapData
        return self.copy()

    def __deepcopy__(self, memo):
        # type: (Dict[int, Any]) -> CBORMapData
        return CBORMapData(copy.deepcopy(self._pairs, memo))

    def __len__(self):
        # type: () -> int
        return len(self._pairs)

    def __iter__(self):
        # type: () -> Any
        return iter(self.keys())

    def keys(self):
        # type: () -> List[Any]
        out = []  # type: List[Any]
        for key, _value in self._pairs:
            out.append(key.val if isinstance(key, CBOR_Object) else key)
        return out

    def values(self):
        # type: () -> List[Any]
        return [value for _key, value in self._pairs]

    def items(self):
        # type: () -> List[Tuple[Any, Any]]
        return [
            (key.val if isinstance(key, CBOR_Object) else key, value)
            for key, value in self._pairs
        ]

    def __contains__(self, key):
        # type: (Any) -> bool
        try:
            self[key]
            return True
        except KeyError:
            return False

    def __getitem__(self, key):
        # type: (Any) -> Any
        matches = []  # type: List[Any]
        for map_key, value in self._pairs:
            if _cbor_key_equivalent(map_key, key):
                matches.append(value)
        if not matches:
            raise KeyError(key)
        if len(matches) > 1:
            raise KeyError("Ambiguous CBOR map key %r" % (key,))
        return matches[0]

    def get(self, key, default=None):
        # type: (Any, Any) -> Any
        try:
            return self[key]
        except KeyError:
            return default

    def __eq__(self, other):
        # type: (Any) -> bool
        if isinstance(other, dict):
            # Do not use dict(self.items()): Python collapses True/1 (and
            # similar) as equal keys, which is not the CBOR data model.
            other_items = list(other.items())
        elif isinstance(other, CBORMapData):
            # RFC 8949 maps are unordered; pair order is not identity.
            other_items = other._pairs
        else:
            return NotImplemented
        if len(self._pairs) != len(other_items):
            return False
        used = [False] * len(other_items)
        for map_key, value in self._pairs:
            matched = False
            for idx, (other_key, other_value) in enumerate(other_items):
                if used[idx]:
                    continue
                if not _cbor_key_equivalent(map_key, other_key):
                    continue
                if value != other_value:
                    return False
                used[idx] = True
                matched = True
                break
            if not matched:
                return False
        return True

    def __repr__(self):
        # type: () -> str
        return "CBORMapData(%r)" % (self.items(),)


def _cbor_map_pairs(mapping):
    # type: (Any) -> List[Tuple[Any, Any]]
    """Return ordered ``(key, value)`` pairs from a CBOR map representation.

    Accepts :class:`CBOR_MAP`, :class:`CBORMapData`, ``dict``, or a sequence
    of pairs. Used by encode, display, and key-normalization paths.
    """
    if isinstance(mapping, CBOR_MAP):
        mapping = mapping.val
    if isinstance(mapping, CBORMapData):
        return mapping.cbor_pairs()
    if isinstance(mapping, dict):
        return list(mapping.items())
    return list(mapping)


class CBOR_MAP(CBOR_Object[Any]):
    """CBOR map (major type 5).

    Always stores :class:`CBORMapData`. Constructors accept ``CBORMapData``,
    ``dict``, or a sequence of ``(key, value)`` pairs.
    """
    tag = CBOR_MajorTypes.MAP

    def __init__(self, val):
        # type: (Any) -> None
        if isinstance(val, CBORMapData):
            super(CBOR_MAP, self).__init__(val)
        elif isinstance(val, dict):
            super(CBOR_MAP, self).__init__(CBORMapData(list(val.items())))
        else:
            super(CBOR_MAP, self).__init__(CBORMapData(list(val)))

    def strshow(self, lvl=0):
        # type: (int) -> str
        s = ("  " * lvl) + ("# CBOR_MAP:") + "\n"
        for k, v in _cbor_map_pairs(self.val):
            s += ("  " * (lvl + 1)) + "Key: "
            if hasattr(k, 'strshow'):
                s += k.strshow(0).strip() + "\n"
            else:
                s += repr(k) + "\n"
            s += ("  " * (lvl + 1)) + "Value: "
            if hasattr(v, 'strshow'):
                s += v.strshow(0).strip() + "\n"
            else:
                s += repr(v) + "\n"
        return s


class CBOR_SEMANTIC_TAG(CBOR_Object[Tuple[int, Any]]):
    """CBOR semantic tag (major type 6)"""
    tag = CBOR_MajorTypes.TAG


class CBOR_SIMPLE_VALUE(CBOR_Object[int]):
    """CBOR simple value (major type 7)"""
    tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT


class CBOR_FALSE(CBOR_Object[bool]):
    """CBOR false value"""
    tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def __init__(self):
        # type: () -> None
        super(CBOR_FALSE, self).__init__(False)


class CBOR_TRUE(CBOR_Object[bool]):
    """CBOR true value"""
    tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def __init__(self):
        # type: () -> None
        super(CBOR_TRUE, self).__init__(True)


class CBOR_NULL(CBOR_Object[None]):
    """CBOR null value"""
    tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def __init__(self):
        # type: () -> None
        super(CBOR_NULL, self).__init__(None)


class CBOR_UNDEFINED(CBOR_Object[None]):
    """CBOR undefined value (singleton)."""
    tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT
    _instance = None  # type: Optional["CBOR_UNDEFINED"]

    def __new__(cls):
        # type: () -> CBOR_UNDEFINED
        if cls._instance is None:
            cls._instance = CBOR_Object.__new__(cls)
        return cls._instance

    def __init__(self):
        # type: () -> None
        if not hasattr(self, "val"):
            super(CBOR_UNDEFINED, self).__init__(None)

    def __bool__(self):
        # type: () -> bool
        return False

    def __copy__(self):
        # type: () -> CBOR_UNDEFINED
        return self

    def __deepcopy__(self, memo):
        # type: (dict) -> CBOR_UNDEFINED
        return self


class _CBORNoItem(object):
    """Structural sentinel: sequence ended without consuming input."""

    def __repr__(self):
        # type: () -> str
        return "CBOR_NO_ITEM"

    def __copy__(self):
        # type: () -> _CBORNoItem
        return self

    def __deepcopy__(self, memo):
        # type: (dict) -> _CBORNoItem
        return self


CBOR_NO_ITEM = _CBORNoItem()


class CBOR_FLOAT(CBOR_Object[float]):
    """CBOR floating-point number (major type 7)"""
    tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def __init__(self, val, encoded=None):
        # type: (float, Optional[bytes]) -> None
        CBOR_Object.__init__(self, val)
        # Exact received float encoding when known; preferred width when None.
        self._encoded = encoded

    def __setattr__(self, name, value):
        # type: (str, Any) -> None
        # After construction, assigning val invalidates the wire cache even
        # when the new semantic value compares equal to the old one.
        if name == "val" and hasattr(self, "_encoded"):
            object.__setattr__(self, "_encoded", None)
        super(CBOR_FLOAT, self).__setattr__(name, value)

    def enc(self, codec=None):
        # type: (Any) -> bytes
        if self._encoded is not None:
            return self._encoded
        return super(CBOR_FLOAT, self).enc(codec)


def _cbor_float_wire_parts(encoded):
    # type: (bytes) -> Tuple[int, int]
    """Return ``(ai, bits)`` for a definite CBOR float encoding."""
    wire = bytes(encoded)
    if not wire:
        raise ValueError("empty CBOR float encoding")
    ai = wire[0] & 0x1f
    if ai == CBOR_FloatAI.HALF:
        if len(wire) < 3:
            raise ValueError("truncated half float")
        return ai, struct.unpack(">H", wire[1:3])[0]
    if ai == CBOR_FloatAI.SINGLE:
        if len(wire) < 5:
            raise ValueError("truncated single float")
        return ai, struct.unpack(">I", wire[1:5])[0]
    if ai == CBOR_FloatAI.DOUBLE:
        if len(wire) < 9:
            raise ValueError("truncated double float")
        return ai, struct.unpack(">Q", wire[1:9])[0]
    raise ValueError("not a CBOR float encoding: ai=%d" % ai)


def _cbor_float_key_identity(value, encoded=None):
    # type: (float, Optional[bytes]) -> _CBORKeyNorm
    """Return RFC 8949 floating-point map-key identity for *value*.

    Finite ``+0.0`` / ``-0.0`` collapse.  NaNs compare by sign and
    significand after zero-extension to a 52-bit binary64 significand.
    When *encoded* is a CBOR float item, prefer that bit pattern so payload
    and sign survive Python's NaN canonicalization.
    """
    if encoded is not None:
        from scapy.cbor.cborcodec import (
            _cbor_float_from_bits,
            _cbor_nan_components,
        )
        ai, bits = _cbor_float_wire_parts(encoded)
        comps = _cbor_nan_components(ai, bits)
        if comps is not None:
            sign, significand52 = comps
            return (CBOR_KeyKind.NAN, sign, significand52)
        return _cbor_float_key_identity(_cbor_float_from_bits(ai, bits))

    fval = float(value)
    if math.isnan(fval):
        bits = struct.unpack(">Q", struct.pack(">d", fval))[0]
        sign = (bits >> 63) & 0x1
        significand = bits & ((1 << 52) - 1)
        return (CBOR_KeyKind.NAN, sign, significand)
    if fval == 0.0:
        return (CBOR_KeyKind.FINITE, 0.0)
    return (CBOR_KeyKind.FINITE, fval)


def _cbor_key_norm(value):
    # type: (Any) -> _CBORKeyNorm
    """Return a hashable RFC 8949 map-key equivalence form for *value*.

    Integers and floats remain distinct groups.  Floating ``+0.0`` and
    ``-0.0`` collapse.  NaNs are equivalent only when sign and normalized
    significand match across widths.  Arrays compare order-sensitively;
    maps compare as unordered pairs of norms.  Semantic tags require the
    same tag number and an equivalent tagged value.

    Each norm is a tuple starting with :class:`CBOR_KeyKind` (not a dict),
    so norms stay hashable for map ``frozenset`` identity.
    """
    if isinstance(value, CBOR_Object):
        if isinstance(value, (CBOR_TRUE, CBOR_FALSE)):
            return (CBOR_KeyKind.BOOL, bool(value.val))
        if isinstance(value, CBOR_NULL):
            return (CBOR_KeyKind.NULL, None)
        if isinstance(value, CBOR_UNDEFINED):
            return (CBOR_KeyKind.UNDEF, None)
        if isinstance(value, (CBOR_UNSIGNED_INTEGER, CBOR_NEGATIVE_INTEGER)):
            return (CBOR_KeyKind.INT, int(value.val))
        if isinstance(value, CBOR_BYTE_STRING):
            return (CBOR_KeyKind.BSTR, bytes(value.val))
        if isinstance(value, CBOR_TEXT_STRING):
            return (CBOR_KeyKind.TSTR, str(value.val))
        if isinstance(value, CBOR_FLOAT):
            return _cbor_float_key_identity(
                value.val, getattr(value, "_encoded", None)
            )
        if isinstance(value, CBOR_ARRAY):
            return (
                CBOR_KeyKind.ARRAY,
                tuple(_cbor_key_norm(v) for v in value.val),
            )
        if isinstance(value, CBOR_MAP):
            return (
                CBOR_KeyKind.MAP,
                frozenset(
                    (_cbor_key_norm(k), _cbor_key_norm(v))
                    for k, v in _cbor_map_pairs(value)
                ),
            )
        if isinstance(value, CBOR_SEMANTIC_TAG):
            tag_num, inner = value.val
            return (CBOR_KeyKind.TAG, int(tag_num), _cbor_key_norm(inner))
        if isinstance(value, CBOR_SIMPLE_VALUE):
            return (CBOR_KeyKind.SIMPLE, int(value.val))
        return (
            CBOR_KeyKind.OBJ,
            type(value).__name__,
            _cbor_key_norm(value.val),
        )
    if isinstance(value, CBORMapData):
        return (
            CBOR_KeyKind.MAP,
            frozenset(
                (_cbor_key_norm(k), _cbor_key_norm(v))
                for k, v in value.cbor_pairs()
            ),
        )
    if isinstance(value, dict):
        return (
            CBOR_KeyKind.MAP,
            frozenset(
                (_cbor_key_norm(k), _cbor_key_norm(v))
                for k, v in value.items()
            ),
        )
    if isinstance(value, bool):
        return (CBOR_KeyKind.BOOL, value)
    if isinstance(value, int):
        return (CBOR_KeyKind.INT, value)
    if isinstance(value, float):
        return _cbor_float_key_identity(value)
    if isinstance(value, bytes):
        return (CBOR_KeyKind.BSTR, value)
    if isinstance(value, str):
        return (CBOR_KeyKind.TSTR, value)
    if isinstance(value, list):
        return (CBOR_KeyKind.ARRAY, tuple(_cbor_key_norm(v) for v in value))
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], int):
        # Bare semantic-tag tuple (tag_num, inner), as stored on CBOR_SEMANTIC_TAG.
        return (CBOR_KeyKind.TAG, int(value[0]), _cbor_key_norm(value[1]))
    return (CBOR_KeyKind.OTHER, type(value).__name__, repr(value))


def _cbor_key_equivalent(a, b):
    # type: (Any, Any) -> bool
    """Return True when *a* and *b* are equivalent CBOR map keys (RFC 8949)."""
    return _cbor_key_norm(a) == _cbor_key_norm(b)


class _CBOR_ERROR(CBOR_Object[Union[bytes, CBOR_Object[Any]]]):
    """CBOR decoding error wrapper"""
    tag = None  # type: ignore  # Error objects don't have a CBOR tag


class CBOR_DECODING_ERROR(_CBOR_ERROR):
    """CBOR decoding error object"""

    def __init__(self, val, exc=None):
        # type: (Union[bytes, CBOR_Object[Any]], Optional[Exception]) -> None
        CBOR_Object.__init__(self, val)
        self.exc = exc

    def __repr__(self):
        # type: () -> str
        return "<%s[%r]{{%r}}>" % (
            self.__class__.__name__,
            self.val,
            self.exc and self.exc.args[0] or ""
        )

    def enc(self, codec=None):
        # type: (Any) -> bytes
        if isinstance(self.val, CBOR_Object):
            return self.val.enc(codec)
        return self.val  # type: ignore
