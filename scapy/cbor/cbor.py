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

    def __hash__(self):
        # type: () -> int
        try:
            return hash((type(self), self.val))
        except TypeError:
            return hash((type(self), id(self)))


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

    Preserves full CBOR key objects for faithful ``enc()`` round-trips while
    still supporting ``map_data['name']`` / ``'name' in map_data`` for the
    common scalar-key cases used by existing tests.

    Lookup uses ``(type(key), key)`` identity so CBOR/Python values that
    compare equal under ``==`` but differ by type (``1`` vs ``True``) remain
    distinct.
    """

    __slots__ = ("_pairs",)

    def __init__(self, pairs=None):
        # type: (Optional[List[Tuple[Any, Any]]]) -> None
        self._pairs = list(pairs or [])

    def cbor_pairs(self):
        # type: () -> List[Tuple[Any, Any]]
        return list(self._pairs)

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

    @staticmethod
    def _float_key_identity(val, encoded=None):
        # type: (float, Optional[bytes]) -> Tuple[Any, ...]
        """Identity that distinguishes +0.0 / -0.0 and NaN payloads."""
        fval = float(val)
        if math.isnan(fval):
            if encoded is not None:
                return (float, "nan", bytes(encoded))
            return (float, "nan", struct.pack(">d", fval))
        # struct.pack preserves the IEEE sign bit so +0.0 != -0.0.
        return (float, "f", struct.pack(">d", fval))

    @staticmethod
    def _key_identity(key):
        # type: (Any) -> Tuple[Any, ...]
        """Return a typed identity for map-key lookup."""
        if isinstance(key, CBOR_Object):
            # Normalize CBOR wrappers to the native Python type they encode.
            if isinstance(key, (CBOR_TRUE, CBOR_FALSE)):
                return (bool, bool(key.val))
            if isinstance(key, CBOR_NULL):
                return (type(None), None)
            if isinstance(key, CBOR_UNDEFINED):
                from scapy.cbor.cbor import CBOR_UNDEFINED_VALUE
                return (type(CBOR_UNDEFINED_VALUE), CBOR_UNDEFINED_VALUE)
            if isinstance(key, CBOR_UNSIGNED_INTEGER):
                return (int, int(key.val))
            if isinstance(key, CBOR_NEGATIVE_INTEGER):
                return (int, int(key.val))
            if isinstance(key, CBOR_FLOAT):
                return CBORMapData._float_key_identity(
                    key.val, getattr(key, "_encoded", None)
                )
            if isinstance(key, CBOR_BYTE_STRING):
                return (bytes, bytes(key.val))
            if isinstance(key, CBOR_TEXT_STRING):
                return (str, str(key.val))
            if isinstance(key, CBOR_ARRAY):
                return (list, key)
            if isinstance(key, CBOR_MAP):
                return (CBORMapData, key)
            if isinstance(key, CBOR_SEMANTIC_TAG):
                return (CBOR_SEMANTIC_TAG, key.val)
            if isinstance(key, CBOR_SIMPLE_VALUE):
                return (CBOR_SIMPLE_VALUE, key.val)
            return (type(key), key.val)
        # bool is a subclass of int; float includes CBORFloatValue.
        if isinstance(key, bool):
            return (bool, key)
        if isinstance(key, float):
            encoded = getattr(key, "cbor_encoded", None)
            return CBORMapData._float_key_identity(key, encoded)
        if isinstance(key, int):
            return (int, key)
        return (type(key), key)

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
        want = self._key_identity(key)
        matches = []  # type: List[Any]
        for map_key, value in self._pairs:
            if self._key_identity(map_key) == want:
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
            if len(other) != len(self._pairs):
                return False
            other_items = list(other.items())
            used = [False] * len(other_items)
            for map_key, value in self._pairs:
                want = self._key_identity(map_key)
                matched = False
                for idx, (other_key, other_value) in enumerate(other_items):
                    if used[idx]:
                        continue
                    if self._key_identity(other_key) != want:
                        continue
                    if value != other_value:
                        return False
                    used[idx] = True
                    matched = True
                    break
                if not matched:
                    return False
            return True
        if isinstance(other, CBORMapData):
            return self._pairs == other._pairs
        return NotImplemented

    def __repr__(self):
        # type: () -> str
        return "CBORMapData(%r)" % (self.items(),)


class CBOR_MAP(CBOR_Object[Any]):
    """CBOR map (major type 5).

    Decoded maps use :class:`CBORMapData` (ordered pairs). Manually
    constructed maps may still use a plain ``dict``.
    """
    tag = CBOR_MajorTypes.MAP

    def strshow(self, lvl=0):
        # type: (int) -> str
        s = ("  " * lvl) + ("# CBOR_MAP:") + "\n"
        if isinstance(self.val, CBORMapData):
            items = self.val.cbor_pairs()
        elif isinstance(self.val, dict):
            items = list(self.val.items())
        else:
            items = list(self.val)
        for k, v in items:
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
    """CBOR undefined value"""
    tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def __init__(self):
        # type: () -> None
        super(CBOR_UNDEFINED, self).__init__(None)


class CBORTagValue(object):
    """Packet-field internal representation of a CBOR semantic tag."""
    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        # type: (int, Any) -> None
        self.tag = int(tag)
        self.value = value

    def __repr__(self):
        # type: () -> str
        return "CBORTagValue(tag=%r, value=%r)" % (self.tag, self.value)

    def __eq__(self, other):
        # type: (object) -> bool
        return (
            isinstance(other, CBORTagValue) and
            self.tag == other.tag and
            self.value == other.value
        )

    def __hash__(self):
        # type: () -> int
        return hash((self.tag, self.value))


class CBORSimpleValue(object):
    """Packet-field internal representation of a CBOR simple value."""
    __slots__ = ("value",)

    def __init__(self, value):
        # type: (int) -> None
        self.value = int(value)

    def __repr__(self):
        # type: () -> str
        return "CBORSimpleValue(%r)" % self.value

    def __eq__(self, other):
        # type: (object) -> bool
        return isinstance(other, CBORSimpleValue) and self.value == other.value

    def __hash__(self):
        # type: () -> int
        return hash(self.value)


class _CBORUndefined(object):
    """Sentinel for CBOR undefined (distinct from Python ``None`` / null)."""

    def __repr__(self):
        # type: () -> str
        return "CBOR_UNDEFINED"

    def __bool__(self):
        # type: () -> bool
        return False

    def __copy__(self):
        # type: () -> _CBORUndefined
        return self

    def __deepcopy__(self, memo):
        # type: (dict) -> _CBORUndefined
        return self


CBOR_UNDEFINED_VALUE = _CBORUndefined()


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

    def enc(self, codec=None):
        # type: (Any) -> bytes
        if self._encoded is not None:
            return self._encoded
        return super(CBOR_FLOAT, self).enc(codec)


class CBORFloatValue(float):
    """Native float that optionally retains the exact CBOR encoding.

    Used by :class:`~scapy.cbor.cborfields.CBORF_FLOAT` and
    :class:`~scapy.cbor.cborfields.CBORF_ANY` so dissected half / single /
    double (and NaN payloads) survive field storage and rebuild when the
    packet raw cache is cleared, until the value is replaced by a plain
    ``float``.
    """

    __slots__ = ("_cbor_encoded",)

    def __new__(cls, value, encoded=None):
        # type: (float, Optional[bytes]) -> CBORFloatValue
        self = float.__new__(cls, value)
        object.__setattr__(self, "_cbor_encoded", encoded)
        return self

    @property
    def cbor_encoded(self):
        # type: () -> Optional[bytes]
        return getattr(self, "_cbor_encoded", None)

    def __copy__(self):
        # type: () -> CBORFloatValue
        return CBORFloatValue(float(self), self.cbor_encoded)

    def __deepcopy__(self, memo):
        # type: (dict) -> CBORFloatValue
        return self.__copy__()


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
