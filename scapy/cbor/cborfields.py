# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Classes that implement CBOR (Concise Binary Object Representation) data
structures as packet fields.  Modelled after scapy/asn1fields.py.
"""

import copy

from functools import reduce

from scapy.cbor.cbor import (
    CBOR_Decoding_Error,
    CBOR_Error,
    CBOR_MajorTypes,
    CBOR_Object,
    CBOR_UNSIGNED_INTEGER,
    CBOR_NEGATIVE_INTEGER,
    CBOR_BYTE_STRING,
    CBOR_TEXT_STRING,
    CBOR_SEMANTIC_TAG,
    CBOR_FALSE,
    CBOR_TRUE,
    CBOR_NULL,
    CBOR_UNDEFINED,
    CBOR_FLOAT,
)
from scapy.cbor.cborcodec import (
    CBOR_Codec_Decoding_Error,
    CBOR_decode_head,
    CBOR_encode_head,
    CBORcodec_Object,
    CBORcodec_UNSIGNED_INTEGER,
    CBORcodec_NEGATIVE_INTEGER,
    CBORcodec_BYTE_STRING,
    CBORcodec_TEXT_STRING,
    CBORcodec_SIMPLE_AND_FLOAT,
)
from scapy.base_classes import BasePacket
from scapy.volatile import (
    RandChoice,
    RandFloat,
    RandNum,
    RandString,
    RandField,
)

from scapy import packet

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
    from scapy.cborpacket import CBOR_Packet  # noqa: F401


class CBORF_badsequence(Exception):
    pass


class CBORF_element(object):
    pass


##########################
#    Basic CBOR Field    #
##########################

_I = TypeVar('_I')  # Internal storage
_A = TypeVar('_A')  # CBOR object


class CBORF_field(CBORF_element, Generic[_I, _A]):
    holds_packets = 0
    islist = 0
    CBOR_tag = None  # type: Optional[Any]

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[_A]
                 ):
        # type: (...) -> None
        self.name = name
        if default is None:
            self.default = default  # type: Optional[_A]
        else:
            self.default = self._wrap(default)
        self.owners = []  # type: List[Type[CBOR_Packet]]

    def _wrap(self, val):
        # type: (Any) -> _A
        """Return a CBOR object wrapping *val*.

        The base implementation is a pass-through cast; subclasses override
        this to convert a raw Python value to the appropriate CBOR object
        type (e.g. :class:`~scapy.cbor.cbor.CBOR_UNSIGNED_INTEGER`).
        """
        return cast(_A, val)

    def register_owner(self, cls):
        # type: (Type[CBOR_Packet]) -> None
        self.owners.append(cls)

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, _I) -> str
        return repr(x)

    def i2h(self, pkt, x):
        # type: (CBOR_Packet, _I) -> Any
        return x

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[_A, bytes]
        raise NotImplementedError("Subclasses must implement m2i")

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Union[bytes, _I, _A]) -> bytes
        if x is None:
            return b""
        if isinstance(x, CBOR_Object):
            return x.enc()
        return self._encode(x)

    def _encode(self, x):
        # type: (Any) -> bytes
        """Encode a raw Python value to CBOR bytes."""
        raise NotImplementedError("Subclasses must implement _encode")

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> _I
        return cast(_I, x)

    def extract_packet(self,
                       cls,  # type: Type[CBOR_Packet]
                       s,  # type: bytes
                       _underlayer=None,  # type: Optional[CBOR_Packet]
                       ):
        # type: (...) -> Tuple[CBOR_Packet, bytes]
        try:
            c = cls(s, _underlayer=_underlayer)
        except CBORF_badsequence:
            c = packet.Raw(s, _underlayer=_underlayer)  # type: ignore
        cpad = c.getlayer(packet.Raw)
        s = b""
        if cpad is not None:
            s = cpad.load
            if cpad.underlayer:
                del cpad.underlayer.payload
        return c, s

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.i2m(pkt, getattr(pkt, self.name))

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        v, s = self.m2i(pkt, s)
        self.set_val(pkt, v)
        return s

    def do_copy(self, x):
        # type: (Any) -> Any
        if isinstance(x, list):
            x = x[:]
            for i in range(len(x)):
                if isinstance(x[i], BasePacket):
                    x[i] = x[i].copy()
            return x
        if hasattr(x, "copy"):
            return x.copy()
        return x

    def set_val(self, pkt, val):
        # type: (CBOR_Packet, Any) -> None
        setattr(pkt, self.name, val)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return getattr(pkt, self.name) is None

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any, Any]]
        return [self]

    def __str__(self):
        # type: () -> str
        return repr(self)

    def randval(self):
        # type: () -> RandField[_I]
        return cast(RandField[_I], RandNum(0, 2 ** 32))

    def copy(self):
        # type: () -> CBORF_field[_I, _A]
        return copy.copy(self)


#############################
#    Simple CBOR Fields     #
#############################

class CBORF_UNSIGNED_INTEGER(CBORF_field[int, CBOR_UNSIGNED_INTEGER]):
    """CBOR unsigned integer field (major type 0)."""
    CBOR_tag = CBOR_MajorTypes.UNSIGNED_INTEGER

    def _wrap(self, val):
        # type: (Any) -> CBOR_UNSIGNED_INTEGER
        if isinstance(val, CBOR_UNSIGNED_INTEGER):
            return val
        return CBOR_UNSIGNED_INTEGER(int(val))

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_UNSIGNED_INTEGER, bytes]
        return CBORcodec_UNSIGNED_INTEGER.dec(s)  # type: ignore

    def _encode(self, x):
        # type: (Any) -> bytes
        return CBORcodec_UNSIGNED_INTEGER.enc(
            x if isinstance(x, CBOR_Object) else CBOR_UNSIGNED_INTEGER(int(x))
        )

    def randval(self):
        # type: () -> RandNum
        return RandNum(0, 2 ** 64 - 1)


class CBORF_NEGATIVE_INTEGER(CBORF_field[int, CBOR_NEGATIVE_INTEGER]):
    """CBOR negative integer field (major type 1)."""
    CBOR_tag = CBOR_MajorTypes.NEGATIVE_INTEGER

    def _wrap(self, val):
        # type: (Any) -> CBOR_NEGATIVE_INTEGER
        if isinstance(val, CBOR_NEGATIVE_INTEGER):
            return val
        return CBOR_NEGATIVE_INTEGER(int(val))

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_NEGATIVE_INTEGER, bytes]
        return CBORcodec_NEGATIVE_INTEGER.dec(s)  # type: ignore

    def _encode(self, x):
        # type: (Any) -> bytes
        return CBORcodec_NEGATIVE_INTEGER.enc(
            x if isinstance(x, CBOR_Object) else CBOR_NEGATIVE_INTEGER(int(x))
        )

    def randval(self):
        # type: () -> RandNum
        return RandNum(-2 ** 64, -1)


class CBORF_INTEGER(CBORF_field[int,
                                Union[CBOR_UNSIGNED_INTEGER,
                                      CBOR_NEGATIVE_INTEGER]]):
    """CBOR integer field handling both positive and negative values."""

    def _wrap(self, val):
        # type: (Any) -> Union[CBOR_UNSIGNED_INTEGER, CBOR_NEGATIVE_INTEGER]
        if isinstance(val, (CBOR_UNSIGNED_INTEGER, CBOR_NEGATIVE_INTEGER)):
            return val
        i = int(val)
        if i >= 0:
            return CBOR_UNSIGNED_INTEGER(i)
        return CBOR_NEGATIVE_INTEGER(i)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[Union[CBOR_UNSIGNED_INTEGER, CBOR_NEGATIVE_INTEGER], bytes]  # noqa: E501
        if not s:
            raise CBOR_Decoding_Error("Empty CBOR data")
        major_type = (s[0] >> 5) & 0x7
        if major_type == 0:
            return CBORcodec_UNSIGNED_INTEGER.dec(s)  # type: ignore
        elif major_type == 1:
            return CBORcodec_NEGATIVE_INTEGER.dec(s)  # type: ignore
        raise CBOR_Decoding_Error(
            "Expected integer (major type 0 or 1), got %d" % major_type)

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        if x is None:
            return b""
        if isinstance(x, CBOR_Object):
            return x.enc()
        i = int(x)
        if i >= 0:
            return CBORcodec_UNSIGNED_INTEGER.enc(CBOR_UNSIGNED_INTEGER(i))
        return CBORcodec_NEGATIVE_INTEGER.enc(CBOR_NEGATIVE_INTEGER(i))

    def randval(self):
        # type: () -> RandNum
        return RandNum(-2 ** 64, 2 ** 64 - 1)


class CBORF_BYTE_STRING(CBORF_field[bytes, CBOR_BYTE_STRING]):
    """CBOR byte string field (major type 2)."""
    CBOR_tag = CBOR_MajorTypes.BYTE_STRING

    def _wrap(self, val):
        # type: (Any) -> CBOR_BYTE_STRING
        if isinstance(val, CBOR_BYTE_STRING):
            return val
        return CBOR_BYTE_STRING(bytes(val))

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_BYTE_STRING, bytes]
        return CBORcodec_BYTE_STRING.dec(s)  # type: ignore

    def _encode(self, x):
        # type: (Any) -> bytes
        return CBORcodec_BYTE_STRING.enc(
            x if isinstance(x, CBOR_Object) else CBOR_BYTE_STRING(bytes(x))
        )

    def randval(self):
        # type: () -> RandString
        return RandString(RandNum(0, 1000))


class CBORF_TEXT_STRING(CBORF_field[str, CBOR_TEXT_STRING]):
    """CBOR text string field (major type 3)."""
    CBOR_tag = CBOR_MajorTypes.TEXT_STRING

    def _wrap(self, val):
        # type: (Any) -> CBOR_TEXT_STRING
        if isinstance(val, CBOR_TEXT_STRING):
            return val
        return CBOR_TEXT_STRING(str(val))

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_TEXT_STRING, bytes]
        return CBORcodec_TEXT_STRING.dec(s)  # type: ignore

    def _encode(self, x):
        # type: (Any) -> bytes
        return CBORcodec_TEXT_STRING.enc(
            x if isinstance(x, CBOR_Object) else CBOR_TEXT_STRING(str(x))
        )

    def randval(self):
        # type: () -> RandString
        return RandString(RandNum(0, 1000))


class CBORF_BOOLEAN(CBORF_field[bool, Union[CBOR_FALSE, CBOR_TRUE]]):
    """CBOR boolean field (major type 7, simple values 20/21)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def _wrap(self, val):
        # type: (Any) -> Union[CBOR_FALSE, CBOR_TRUE]
        if isinstance(val, (CBOR_FALSE, CBOR_TRUE)):
            return val
        return CBOR_TRUE() if val else CBOR_FALSE()

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[Union[CBOR_FALSE, CBOR_TRUE], bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, (CBOR_FALSE, CBOR_TRUE)):
            raise CBOR_Decoding_Error(
                "Expected boolean (CBOR_FALSE or CBOR_TRUE), got %r" % obj)
        return obj, remain  # type: ignore

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        if x is None:
            return b""
        if isinstance(x, (CBOR_FALSE, CBOR_TRUE)):
            return x.enc()
        return CBORcodec_SIMPLE_AND_FLOAT.enc(
            CBOR_TRUE() if x else CBOR_FALSE()
        )

    def randval(self):
        # type: () -> RandChoice
        return RandChoice(True, False)


class CBORF_NULL(CBORF_field[None, CBOR_NULL]):
    """CBOR null field (major type 7, simple value 22)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def __init__(self,
                 name,  # type: str
                 default=None,  # type: None
                 ):
        # type: (...) -> None
        super(CBORF_NULL, self).__init__(name, None)

    def _wrap(self, val):
        # type: (Any) -> CBOR_NULL
        return CBOR_NULL()

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_NULL, bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, CBOR_NULL):
            raise CBOR_Decoding_Error(
                "Expected null, got %r" % obj)
        return obj, remain  # type: ignore

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        return CBOR_NULL().enc()

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return False


class CBORF_UNDEFINED(CBORF_field[None, CBOR_UNDEFINED]):
    """CBOR undefined field (major type 7, simple value 23)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def __init__(self,
                 name,  # type: str
                 default=None,  # type: None
                 ):
        # type: (...) -> None
        super(CBORF_UNDEFINED, self).__init__(name, None)

    def _wrap(self, val):
        # type: (Any) -> CBOR_UNDEFINED
        return CBOR_UNDEFINED()

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_UNDEFINED, bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, CBOR_UNDEFINED):
            raise CBOR_Decoding_Error(
                "Expected undefined, got %r" % obj)
        return obj, remain  # type: ignore

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        return CBOR_UNDEFINED().enc()

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return False


class CBORF_FLOAT(CBORF_field[float, CBOR_FLOAT]):
    """CBOR float field (major type 7, double precision)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def _wrap(self, val):
        # type: (Any) -> CBOR_FLOAT
        if isinstance(val, CBOR_FLOAT):
            return val
        return CBOR_FLOAT(float(val))

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_FLOAT, bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, CBOR_FLOAT):
            raise CBOR_Decoding_Error(
                "Expected float, got %r" % obj)
        return obj, remain  # type: ignore

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        if x is None:
            return b""
        if isinstance(x, CBOR_FLOAT):
            return x.enc()
        return CBORcodec_SIMPLE_AND_FLOAT.enc(CBOR_FLOAT(float(x)))

    def randval(self):
        # type: () -> RandFloat
        return RandFloat(0, 2 ** 32)


##############################
#    Structured CBOR Fields  #
##############################

class CBORF_ARRAY(CBORF_field[List[Any], List[Any]]):
    """
    CBOR array with a fixed sequence of named, typed fields (major type 4).
    Analogous to ASN1F_SEQUENCE: each positional element corresponds to a
    specific CBORF_field.  The CBOR array count must match the number of
    declared fields.

    Example::

        class MyCBOR(CBOR_Packet):
            CBOR_root = CBORF_ARRAY(
                CBORF_INTEGER("version", 1),
                CBORF_TEXT_STRING("name", ""),
            )
    """
    CBOR_tag = CBOR_MajorTypes.ARRAY
    holds_packets = 1

    def __init__(self, *seq, **kwargs):
        # type: (*Any, **Any) -> None
        # The array itself is a structural field without its own named slot on
        # the packet; a placeholder name is used so the base class __init__
        # stays happy.  Individual element fields are the ones that carry names.
        name = "_cbor_array"
        default = [field.default for field in seq]
        super(CBORF_ARRAY, self).__init__(name, None)
        self.default = default
        self.seq = seq
        self.islist = len(seq) > 1

    def __repr__(self):
        # type: () -> str
        return "<%s%r>" % (self.__class__.__name__, self.seq)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return all(f.is_empty(pkt) for f in self.seq)

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any, Any]]
        return reduce(lambda x, y: x + y.get_fields_list(),
                      self.seq, [])

    def m2i(self, pkt, s):
        # type: (Any, bytes) -> Tuple[Any, bytes]
        """
        Decode a CBOR array.  Each element is decoded by its corresponding
        field in ``self.seq``.  The decoded values are set directly on the
        packet by each field's ``dissect`` call, so this method returns an
        empty list (which is discarded by ``dissect``).
        """
        try:
            major_type, count, s = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 4:
            raise CBOR_Decoding_Error(
                "Expected major type 4 (array), got %d" % major_type)
        if count != len(self.seq):
            raise CBOR_Decoding_Error(
                "Array length mismatch: expected %d, got %d" %
                (len(self.seq), count))
        for obj in self.seq:
            try:
                s = obj.dissect(pkt, s)
            except CBORF_badsequence:
                break
        return [], s

    def dissect(self, pkt, s):
        # type: (Any, bytes) -> bytes
        _, x = self.m2i(pkt, s)
        return x

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        items = b"".join(obj.build(pkt) for obj in self.seq)
        return CBOR_encode_head(4, len(self.seq)) + items


_ARRAY_T = Union[
    'CBOR_Packet',
    Type[CBORF_field[Any, Any]],
    'CBORF_PACKET',
    CBORF_field[Any, Any],
]


class CBORF_ARRAY_OF(CBORF_field[List[_ARRAY_T], List[CBOR_Object[Any]]]):
    """
    CBOR array of homogeneous elements (major type 4).
    Analogous to ASN1F_SEQUENCE_OF: variable-length array where every
    element shares the same type, specified by ``cls``.

    ``cls`` may be a :class:`CBORF_field` class/instance (leaf type) or a
    :class:`CBOR_Packet` subclass (structured type).
    """
    CBOR_tag = CBOR_MajorTypes.ARRAY
    islist = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 cls,  # type: _ARRAY_T
                 ):
        # type: (...) -> None
        if isinstance(cls, type) and issubclass(cls, CBORF_field) or \
                isinstance(cls, CBORF_field):
            if isinstance(cls, type):
                self.fld = cls("_item", None)  # type: ignore
            else:
                self.fld = cls
            self._extract_item = lambda s, pkt: self.fld.m2i(pkt, s)
            self.holds_packets = 0
        elif hasattr(cls, "CBOR_root") or callable(cls):
            self.cls = cast("Type[CBOR_Packet]", cls)
            self._extract_item = lambda s, pkt: self.extract_packet(
                self.cls, s, _underlayer=pkt)
            self.holds_packets = 1
        else:
            raise ValueError("cls must be a CBORF_field or CBOR_Packet")
        super(CBORF_ARRAY_OF, self).__init__(name, None)
        self.default = default

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return CBORF_field.is_empty(self, pkt)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[List[Any], bytes]
        try:
            major_type, count, s = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 4:
            raise CBOR_Decoding_Error(
                "Expected major type 4 (array), got %d" % major_type)
        lst = []
        for _ in range(count):
            c, s = self._extract_item(s, pkt)  # type: ignore
            if c is not None:
                lst.append(c)
        return lst, s

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        val = getattr(pkt, self.name)
        if val is None:
            val = []
        items = b"".join(bytes(item) for item in val)
        return CBOR_encode_head(4, len(val)) + items

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, Any) -> str
        if self.holds_packets:
            return repr(x)
        elif x is None:
            return "[]"
        else:
            return "[%s]" % ", ".join(
                self.fld.i2repr(pkt, item) for item in x  # type: ignore
            )

    def __repr__(self):
        # type: () -> str
        return "<%s %s>" % (self.__class__.__name__, self.name)


class CBORF_MAP(CBORF_field[Dict[str, Any], Dict[str, Any]]):
    """
    CBOR map with a fixed set of named, typed fields (major type 5).

    Each field in ``seq`` represents one key-value pair.  The key is the
    field's ``name`` encoded as a CBOR text string.  The value is encoded
    and decoded by the corresponding :class:`CBORF_field`.

    Example::

        class MyCBOR(CBOR_Packet):
            CBOR_root = CBORF_MAP(
                CBORF_INTEGER("version", 1),
                CBORF_TEXT_STRING("name", ""),
            )
    """
    CBOR_tag = CBOR_MajorTypes.MAP
    holds_packets = 1

    def __init__(self, *seq, **kwargs):
        # type: (*Any, **Any) -> None
        # The map itself is a structural field without its own named slot on
        # the packet; a placeholder name is used so the base class __init__
        # stays happy.  Individual value fields are the ones that carry names
        # (which also serve as the CBOR text-string keys in the wire encoding).
        name = "_cbor_map"
        default = {field.name: field.default for field in seq}
        super(CBORF_MAP, self).__init__(name, None)
        self.default = default
        self.seq = seq
        self.islist = 1

    def __repr__(self):
        # type: () -> str
        return "<%s%r>" % (self.__class__.__name__, self.seq)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return all(f.is_empty(pkt) for f in self.seq)

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any, Any]]
        return reduce(lambda x, y: x + y.get_fields_list(),
                      self.seq, [])

    def m2i(self, pkt, s):
        # type: (Any, bytes) -> Tuple[Any, bytes]
        """
        Decode a CBOR map.  Keys are decoded as CBOR items and matched to
        fields by name.  Values are decoded by the matching field.  Unknown
        keys are silently skipped.
        """
        try:
            major_type, count, s = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 5:
            raise CBOR_Decoding_Error(
                "Expected major type 5 (map), got %d" % major_type)
        # Build a lookup from field name to field object.
        field_map = {f.name: f for f in self.seq}
        for _ in range(count):
            # Decode the key (any CBOR type; convert to str for lookup).
            key_obj, s = CBORcodec_Object.decode_cbor_item(s)
            if isinstance(key_obj, CBOR_Object):
                key = str(key_obj.val)
            else:
                key = str(key_obj)
            fld = field_map.get(key)
            if fld is not None:
                s = fld.dissect(pkt, s)
            else:
                # Skip unknown value.
                _unknown, s = CBORcodec_Object.decode_cbor_item(s)
        return [], s

    def dissect(self, pkt, s):
        # type: (Any, bytes) -> bytes
        _, x = self.m2i(pkt, s)
        return x

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        result = CBOR_encode_head(5, len(self.seq))
        for fld in self.seq:
            # Encode key as a CBOR text string.
            result += CBORcodec_TEXT_STRING.enc(CBOR_TEXT_STRING(fld.name))
            result += fld.build(pkt)
        return result


class CBORF_SEMANTIC_TAG(CBORF_field[Tuple[int, Any],
                                     CBOR_SEMANTIC_TAG]):
    """
    CBOR semantic tag field (major type 6).

    Wraps an ``inner_field`` with the given numeric ``tag_num``.  The inner
    field handles encoding and decoding of the tagged value.  The outer field
    (named ``name``) stores the :class:`~scapy.cbor.cbor.CBOR_SEMANTIC_TAG`
    wrapper (tag number + ``None`` placeholder), while the inner field stores
    its value under its own name on the packet.

    Example::

        class TimestampPkt(CBOR_Packet):
            CBOR_root = CBORF_SEMANTIC_TAG(
                "tag_info", None, 1, CBORF_INTEGER("ts", 0)
            )
    """
    CBOR_tag = CBOR_MajorTypes.TAG

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 tag_num,  # type: int
                 inner_field,  # type: CBORF_field[Any, Any]
                 ):
        # type: (...) -> None
        self.tag_num = tag_num
        self.inner_field = inner_field
        super(CBORF_SEMANTIC_TAG, self).__init__(name, default)

    def _wrap(self, val):
        # type: (Any) -> CBOR_SEMANTIC_TAG
        if isinstance(val, CBOR_SEMANTIC_TAG):
            return val
        return CBOR_SEMANTIC_TAG((self.tag_num, val))

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_SEMANTIC_TAG, bytes]
        try:
            major_type, tag_num, s = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 6:
            raise CBOR_Decoding_Error(
                "Expected major type 6 (semantic tag), got %d" % major_type)
        return CBOR_SEMANTIC_TAG((tag_num, None)), s  # type: ignore

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        tag_obj, s = self.m2i(pkt, s)
        self.set_val(pkt, tag_obj)
        # Dissect the tagged content using the inner field.
        return self.inner_field.dissect(pkt, s)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        inner_bytes = self.inner_field.build(pkt)
        return CBOR_encode_head(6, self.tag_num) + inner_bytes

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any, Any]]
        return [self] + self.inner_field.get_fields_list()


##############################
#    Complex CBOR Fields     #
##############################

class CBORF_optional(CBORF_element):
    """
    Wrapper making a :class:`CBORF_field` optional.

    During decoding, if the next CBOR item does not match the expected major
    type, the field value is set to ``None`` and the stream is left unchanged.
    """

    def __init__(self, field):
        # type: (CBORF_field[Any, Any]) -> None
        self._field = field

    def __getattr__(self, attr):
        # type: (str) -> Optional[Any]
        return getattr(self._field, attr)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[Any, bytes]
        try:
            return self._field.m2i(pkt, s)
        except (CBOR_Error, CBORF_badsequence,
                CBOR_Codec_Decoding_Error):
            return None, s

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        try:
            return self._field.dissect(pkt, s)
        except (CBOR_Error, CBORF_badsequence,
                CBOR_Codec_Decoding_Error):
            self._field.set_val(pkt, None)
            return s

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        if self._field.is_empty(pkt):
            return b""
        return self._field.build(pkt)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> Any
        return self._field.any2i(pkt, x)

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, Any) -> str
        return self._field.i2repr(pkt, x)


class CBORF_PACKET(CBORF_field['CBOR_Packet', Optional['CBOR_Packet']]):
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
        super(CBORF_PACKET, self).__init__(name, None)
        self.default = default

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[Any, bytes]
        return self.extract_packet(self.cls, s, _underlayer=pkt)

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        if x is None:
            return b""
        if isinstance(x, bytes):
            return x
        return bytes(x)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> CBOR_Packet
        if hasattr(x, "add_underlayer"):
            x.add_underlayer(pkt)
        return super(CBORF_PACKET, self).any2i(pkt, x)  # type: ignore

    def randval(self):  # type: ignore
        # type: () -> CBOR_Packet
        return packet.fuzz(self.cls())
