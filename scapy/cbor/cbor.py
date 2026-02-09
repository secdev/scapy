# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
CBOR (Concise Binary Object Representation) - RFC 8949
Following the ASN.1 paradigm
"""

from scapy.error import Scapy_Exception
from scapy.compat import plain_str
from scapy.utils import Enum_metaclass, EnumElement

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

if TYPE_CHECKING:
    from scapy.cbor.cborcodec import CBORcodec_Object

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

    def dec(cls, s, context=None):
        # type: (bytes, Optional[Any]) -> CBOR_Object[Any]
        return cls._stem.dec(s, context=context)  # type: ignore

    def safedec(cls, s, context=None):
        # type: (bytes, Optional[Any]) -> CBOR_Object[Any]
        return cls._stem.safedec(s, context=context)  # type: ignore

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
        try:
            c.tag.register_cbor_object(c)
        except Exception:
            pass  # Some objects may not have tags yet
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
        return bool(self.val == other)


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


class CBOR_MAP(CBOR_Object[Dict[Any, Any]]):
    """CBOR map (major type 5)"""
    tag = CBOR_MajorTypes.MAP

    def strshow(self, lvl=0):
        # type: (int) -> str
        s = ("  " * lvl) + ("# CBOR_MAP:") + "\n"
        for k, v in self.val.items():
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


class CBOR_FLOAT(CBOR_Object[float]):
    """CBOR floating-point number (major type 7)"""
    tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT


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
