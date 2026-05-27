# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Generic codec base classes combining identical parts from the ASN.1 and
CBOR codec implementations.

Both the ASN.1 BER codec (BERcodec_Object) and the CBOR codec
(CBORcodec_Object) share:

- A metaclass that registers each codec class with its associated tag upon
  class creation (``GenericCodec_metaclass``).
- A base codec class providing ``check_string``, ``dec``, ``safedec``, and
  ``enc`` template methods (``GenericCodecObject``).

Both the ASN.1 field layer (ASN1F_field / ASN1F_optional) and the CBOR
field layer (CBORF_field / CBORF_optional) share a large set of utility
methods that are identical across formats:

- ``GenericCodecField_element`` — empty marker base (replaces per-format
  ``ASN1F_element`` / ``CBORF_element`` as a common ancestor).
- ``GenericCodecField[_I, _A]`` — provides the shared field utility methods:
  ``register_owner``, ``i2repr``, ``i2h``, ``any2i``, ``extract_packet``,
  ``build``, ``dissect``, ``do_copy``, ``set_val``, ``is_empty``,
  ``get_fields_list``, ``__str__``, and ``copy``.
  The only format-specific hook is ``_badsequence_error_class``.
- ``GenericCodecOptionalField`` — provides the shared optional-wrapper
  methods: ``__getattr__``, ``m2i`` / ``dissect`` (parameterised by
  ``_optional_error_classes``), ``build``, ``any2i``, and ``i2repr``.
"""

import copy as _copy

from typing import Any, Generic, List, Optional, Tuple, Type, TypeVar, cast

_K = TypeVar('_K')
_I = TypeVar('_I')
_A = TypeVar('_A')


class GenericCodec_metaclass(type):
    """Metaclass for codec objects shared by BER and CBOR implementations.

    Upon class creation, registers each codec class with its associated tag
    by calling ``c.tag.register(c.codec, c)``.  Subclass metaclasses can
    customise the behaviour on registration failure by overriding
    ``_handle_registration_error``.
    """

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
        """Called when tag registration fails.  Override to add logging."""
        pass


class GenericCodecObject(Generic[_K], metaclass=GenericCodec_metaclass):
    """Generic base class for codec objects.

    Combines the identical functionality shared between ASN.1's
    ``BERcodec_Object`` and CBOR's ``CBORcodec_Object``:

    * ``check_string`` — raises a decoding error when the input is empty.
    * ``dec`` — decodes bytes with optional *safe* mode that wraps errors in
      an error object instead of raising an exception.
    * ``safedec`` — convenience wrapper that calls ``dec`` in safe mode.
    * ``enc`` — encode stub (must be implemented by concrete subclasses).

    Concrete subclasses must define the following **class-level** attributes
    so that the shared methods work correctly:

    ``tag``
        The codec tag (e.g. an ``ASN1Tag`` or ``CBORTag`` instance).
    ``codec``
        The codec identifier (e.g. ``ASN1_Codecs.BER`` or
        ``CBOR_Codecs.CBOR``).
    ``_decoding_error_class``
        Exception class instantiated by ``check_string`` when the input is
        empty (e.g. ``BER_Decoding_Error`` or ``CBOR_Codec_Decoding_Error``).
    ``_generic_error_classes``
        Tuple of exception classes caught by ``dec`` when operating in safe
        mode (e.g. ``(BER_Decoding_Error, ASN1_Error)``).
    ``_decoding_error_object_class``
        Object class used to wrap decoding errors in safe mode (e.g.
        ``ASN1_DECODING_ERROR`` or ``CBOR_DECODING_ERROR``).

    Concrete subclasses must also implement:

    ``do_dec(cls, s, context, safe)``
        The actual decoding logic.
    ``enc(cls, s)``
        The encoding logic.
    """

    @classmethod
    def check_string(cls, s):
        # type: (bytes) -> None
        """Raise a decoding error if the input bytes *s* are empty."""
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
        """Decode bytes.

        Raises :exc:`NotImplementedError` by default; concrete subclasses must
        override this method with format-specific decode logic.
        """
        raise NotImplementedError("Subclasses must implement do_dec")

    @classmethod
    def dec(cls,
            s,           # type: bytes
            context=None,  # type: Optional[Any]
            safe=False   # type: bool
            ):
        # type: (...) -> Tuple[Any, bytes]
        """Decode bytes with optional *safe* mode.

        When *safe* is ``False`` (the default), any decoding exception
        propagates to the caller unchanged.

        When *safe* is ``True``, exceptions listed in
        ``_generic_error_classes`` are caught and returned as an instance of
        ``_decoding_error_object_class`` paired with an empty remainder
        (``b""``), so callers never receive an exception in safe mode.
        """
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
        """Decode bytes in safe mode (decoding errors are wrapped, not raised).

        This is a convenience wrapper around ``dec(s, context, safe=True)``.
        """
        return cls.dec(s, context, safe=True)

    @classmethod
    def enc(cls, s):
        # type: (Any) -> bytes
        """Encode *s* to bytes.  Must be implemented by concrete subclasses."""
        raise NotImplementedError("Subclasses must implement enc")


##############################################
#  Generic codec field base classes          #
##############################################


class GenericCodecField_element(object):
    """Marker base class for all codec field elements.

    Both ``ASN1F_element`` (ASN.1) and ``CBORF_element`` (CBOR) inherit from
    this class so that format-agnostic code can test ``isinstance(obj,
    GenericCodecField_element)`` without importing format-specific symbols.
    """
    pass


class GenericCodecField(Generic[_I, _A]):
    """Shared utility methods for codec packet fields.

    ``ASN1F_field`` and ``CBORF_field`` are both structured as format-specific
    thin layers on top of this base.  All methods listed here are byte-for-byte
    identical in the two implementations; only the exception class used in
    ``extract_packet`` differs and is injected via ``_badsequence_error_class``.

    Concrete subclasses **must** define:

    ``name`` (str)
        Field name — set by the subclass ``__init__``.
    ``owners`` (list)
        List of packet classes that own this field — set by ``__init__``.
    ``_badsequence_error_class`` (exception class)
        Exception caught in ``extract_packet`` when the nested packet cannot
        be parsed (e.g. ``ASN1F_badsequence`` or ``CBORF_badsequence``).

    Concrete subclasses **must** also implement:

    ``m2i(self, pkt, s)``
        Format-specific machine-to-internal conversion.
    ``i2m(self, pkt, x)``
        Format-specific internal-to-machine conversion.
    ``randval(self)``
        Return a random value generator appropriate for the field type.
    """

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
        """Extract a nested packet from bytes *s*.

        On success returns ``(packet, remainder)``.  If ``cls(s, ...)`` raises
        ``_badsequence_error_class``, falls back to a ``Raw`` packet so that
        the caller always receives a packet object.
        """
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
    """Shared optional-wrapper logic for ``ASN1F_optional`` and
    ``CBORF_optional``.

    Both wrappers delegate all work to a wrapped ``_field`` object.  The only
    format-specific part is the set of exception classes caught in ``m2i`` and
    ``dissect``, injected via ``_optional_error_classes``.

    Concrete subclasses **must** define:

    ``_field``
        The wrapped field object — set by the subclass ``__init__``.
    ``_optional_error_classes`` (tuple of exception classes)
        Exceptions caught during optional decoding (e.g.
        ``(ASN1_Error, ASN1F_badsequence, BER_Decoding_Error)``).
    """

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
