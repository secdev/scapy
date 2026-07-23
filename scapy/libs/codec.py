# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Generic codec base classes shared by the ASN.1 and CBOR implementations.
"""

import copy as _copy

from typing import Any, Generic, List, Optional, Tuple, Type, TypeVar, cast

_K = TypeVar('_K')
_I = TypeVar('_I')
_A = TypeVar('_A')


class GenericCodec_metaclass(type):
    """Register codec classes with their tag on class creation."""

    def __new__(cls,
                name,   # type: str
                bases,  # type: Tuple[type, ...]
                dct     # type: Any
                ):
        # type: (...) -> Type[GenericCodecObject[Any]]
        c = cast(
            'Type[GenericCodecObject[Any]]',
            super(GenericCodec_metaclass, cls).__new__(cls, name, bases, dct)
        )
        try:
            c.tag.register(c.codec, c)
        except Exception as exc:
            cls._handle_registration_error(c, exc)
        return c

    @classmethod
    def _handle_registration_error(cls, c, exc):
        # type: (Type[Any], Exception) -> None
        pass


class GenericCodecObject(Generic[_K], metaclass=GenericCodec_metaclass):
    """Base for BERcodec_Object and CBORcodec_Object.

    Subclasses must set tag, codec, _decoding_error_class,
    _generic_error_classes, _decoding_error_object_class and implement
    do_dec and enc.
    """

    @classmethod
    def check_string(cls, s):
        # type: (bytes) -> None
        if not s:
            raise cls._decoding_error_class(  # type: ignore
                "%s: Got empty object while expecting tag %r" %
                (cls.__name__, cls.tag),
                remaining=s
            )

    @classmethod
    def do_dec(cls,
               s,           # type: bytes
               context=None,  # type: Optional[Any]
               safe=False   # type: bool
               ):
        # type: (...) -> Tuple[Any, bytes]
        raise NotImplementedError("Subclasses must implement do_dec")

    @classmethod
    def dec(cls,
            s,           # type: bytes
            context=None,  # type: Optional[Any]
            safe=False   # type: bool
            ):
        # type: (...) -> Tuple[Any, bytes]
        """When safe=True, decode errors are wrapped, not raised."""
        if not safe:
            return cls.do_dec(s, context, safe)
        try:
            return cls.do_dec(s, context, safe)
        except cls._generic_error_classes as e:  # type: ignore
            return cls._decoding_error_object_class(s, exc=e), b""  # type: ignore

    @classmethod
    def safedec(cls,
                s,           # type: bytes
                context=None  # type: Optional[Any]
                ):
        # type: (...) -> Tuple[Any, bytes]
        return cls.dec(s, context, safe=True)

    @classmethod
    def enc(cls, s):
        # type: (Any) -> bytes
        raise NotImplementedError("Subclasses must implement enc")


class GenericCodecField_element(object):
    pass


class GenericCodecField(Generic[_I, _A]):
    """Shared field utilities; set _badsequence_error_class for extract_packet."""

    holds_packets = 0
    islist = 0
    _badsequence_error_class = Exception  # type: Type[Exception]

    def register_owner(self, cls):
        # type: (Any) -> None
        self.owners.append(cls)  # type: ignore[attr-defined]

    def i2repr(self, pkt, x):
        # type: (Any, Any) -> str
        return repr(x)

    def i2h(self, pkt, x):
        # type: (Any, Any) -> Any
        return x

    def any2i(self, pkt, x):
        # type: (Any, Any) -> _I
        return cast(_I, x)

    def extract_packet(self,
                       cls,  # type: Any
                       s,  # type: bytes
                       _underlayer=None,  # type: Optional[Any]
                       ):
        # type: (...) -> Tuple[Any, bytes]
        """Falls back to Raw when nested packet parsing fails."""
        from scapy import packet as _packet
        try:
            c = cls(s, _underlayer=_underlayer)
        except self._badsequence_error_class:
            c = _packet.Raw(s, _underlayer=_underlayer)  # type: ignore[assignment]
        cpad = c.getlayer(_packet.Raw)
        s = b""
        if cpad is not None:
            s = cpad.load
            if cpad.underlayer:
                del cpad.underlayer.payload
        return c, s

    def build(self, pkt):
        # type: (Any) -> bytes
        return self.i2m(pkt, getattr(pkt, self.name))  # type: ignore[attr-defined]

    def dissect(self, pkt, s):
        # type: (Any, bytes) -> bytes
        v, s = self.m2i(pkt, s)  # type: ignore[attr-defined]
        self.set_val(pkt, v)
        return s

    def do_copy(self, x):
        # type: (Any) -> Any
        from scapy.base_classes import BasePacket
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
        # type: (Any, Any) -> None
        setattr(pkt, self.name, val)  # type: ignore[attr-defined]

    def is_empty(self, pkt):
        # type: (Any) -> bool
        return getattr(pkt, self.name) is None  # type: ignore[attr-defined]

    def get_fields_list(self):
        # type: () -> List[Any]
        return [self]

    def __str__(self):
        # type: () -> str
        return repr(self)

    def copy(self):
        # type: () -> Any
        return _copy.copy(self)


class GenericCodecOptionalField(object):
    """Optional field wrapper; set _optional_error_classes for m2i/dissect."""

    _optional_error_classes = (Exception,)  # type: Tuple[Type[Exception], ...]

    def __getattr__(self, attr):
        # type: (str) -> Any
        return getattr(self._field, attr)  # type: ignore[attr-defined]

    def m2i(self, pkt, s):
        # type: (Any, bytes) -> Tuple[Any, bytes]
        try:
            return self._field.m2i(pkt, s)  # type: ignore[attr-defined]
        except self._optional_error_classes:
            return None, s

    def dissect(self, pkt, s):
        # type: (Any, bytes) -> bytes
        try:
            return self._field.dissect(pkt, s)  # type: ignore[attr-defined]
        except self._optional_error_classes:
            self._field.set_val(pkt, None)  # type: ignore[attr-defined]
            return s

    def build(self, pkt):
        # type: (Any) -> bytes
        if self._field.is_empty(pkt):  # type: ignore[attr-defined]
            return b""
        return self._field.build(pkt)  # type: ignore[attr-defined]

    def any2i(self, pkt, x):
        # type: (Any, Any) -> Any
        return self._field.any2i(pkt, x)  # type: ignore[attr-defined]

    def i2repr(self, pkt, x):
        # type: (Any, Any) -> str
        return self._field.i2repr(pkt, x)  # type: ignore[attr-defined]
