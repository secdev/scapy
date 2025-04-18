# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Michael Farrell <micolous+git@gmail.com>


"""
Fields: basic data structures that make up parts of packets.
"""

import calendar
import collections
import copy
import datetime
import inspect
import math
import socket
import struct
import time
import warnings

from types import MethodType
from uuid import UUID
from enum import Enum

from scapy.config import conf
from scapy.dadict import DADict
from scapy.volatile import RandBin, RandByte, RandEnumKeys, RandInt, \
    RandIP, RandIP6, RandLong, RandMAC, RandNum, RandShort, RandSInt, \
    RandSByte, RandTermString, RandUUID, VolatileValue, RandSShort, \
    RandSLong, RandFloat
from scapy.data import EPOCH
from scapy.error import log_runtime, Scapy_Exception
from scapy.compat import bytes_hex, plain_str, raw, bytes_encode
from scapy.pton_ntop import inet_ntop, inet_pton
from scapy.utils import inet_aton, inet_ntoa, lhex, mac2str, str2mac, EDecimal
from scapy.utils6 import in6_6to4ExtractAddr, in6_isaddr6to4, \
    in6_isaddrTeredo, in6_ptop, Net6, teredoAddrExtractInfo
from scapy.base_classes import (
    _ScopedIP,
    BasePacket,
    Field_metaclass,
    Net,
    ScopedIP,
)

# Typing imports
from typing import (
    Any,
    AnyStr,
    Callable,
    Dict,
    List,
    Generic,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    # func
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    # Do not import on runtime ! (import loop)
    from scapy.packet import Packet


class RawVal:
    r"""
    A raw value that will not be processed by the field and inserted
    as-is in the packet string.

    Example::

        >>> a = IP(len=RawVal("####"))
        >>> bytes(a)
        b'F\x00####\x00\x01\x00\x005\xb5\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01\x00\x00'

    """

    def __init__(self, val=b""):
        # type: (bytes) -> None
        self.val = bytes_encode(val)

    def __str__(self):
        # type: () -> str
        return str(self.val)

    def __bytes__(self):
        # type: () -> bytes
        return self.val

    def __len__(self):
        # type: () -> int
        return len(self.val)

    def __repr__(self):
        # type: () -> str
        return "<RawVal [%r]>" % self.val


class ObservableDict(Dict[int, str]):
    """
    Helper class to specify a protocol extendable for runtime modifications
    """

    def __init__(self, *args, **kw):
        # type: (*Dict[int, str], **Any) -> None
        self.observers = []  # type: List[_EnumField[Any]]
        super(ObservableDict, self).__init__(*args, **kw)

    def observe(self, observer):
        # type: (_EnumField[Any]) -> None
        self.observers.append(observer)

    def __setitem__(self, key, value):
        # type: (int, str) -> None
        for o in self.observers:
            o.notify_set(self, key, value)
        super(ObservableDict, self).__setitem__(key, value)

    def __delitem__(self, key):
        # type: (int) -> None
        for o in self.observers:
            o.notify_del(self, key)
        super(ObservableDict, self).__delitem__(key)

    def update(self, anotherDict):  # type: ignore
        for k in anotherDict:
            self[k] = anotherDict[k]


############
#  Fields  #
############

I = TypeVar('I')  # Internal storage  # noqa: E741
M = TypeVar('M')  # Machine storage


class Field(Generic[I, M], metaclass=Field_metaclass):
    """
    For more information on how this works, please refer to the
    'Adding new protocols' chapter in the online documentation:

    https://scapy.readthedocs.io/en/stable/build_dissect.html
    """
    __slots__ = [
        "name",
        "fmt",
        "default",
        "sz",
        "owners",
        "struct"
    ]
    islist = 0
    ismutable = False
    holds_packets = 0

    def __init__(self, name, default, fmt="H"):
        # type: (str, Any, str) -> None
        if not isinstance(name, str):
            raise ValueError("name should be a string")
        self.name = name
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!" + fmt
        self.struct = struct.Struct(self.fmt)
        self.default = self.any2i(None, default)
        self.sz = struct.calcsize(self.fmt)  # type: int
        self.owners = []  # type: List[Type[Packet]]

    def register_owner(self, cls):
        # type: (Type[Packet]) -> None
        self.owners.append(cls)

    def i2len(self,
              pkt,  # type: Packet
              x,  # type: Any
              ):
        # type: (...) -> int
        """Convert internal value to a length usable by a FieldLenField"""
        if isinstance(x, RawVal):
            return len(x)
        return self.sz

    def i2count(self, pkt, x):
        # type: (Optional[Packet], I) -> int
        """Convert internal value to a number of elements usable by a FieldLenField.
        Always 1 except for list fields"""
        return 1

    def h2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> I
        """Convert human value to internal value"""
        return cast(I, x)

    def i2h(self, pkt, x):
        # type: (Optional[Packet], I) -> Any
        """Convert internal value to human value"""
        return x

    def m2i(self, pkt, x):
        # type: (Optional[Packet], M) -> I
        """Convert machine value to internal value"""
        return cast(I, x)

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[I]) -> M
        """Convert internal value to machine value"""
        if x is None:
            return cast(M, 0)
        elif isinstance(x, str):
            return cast(M, bytes_encode(x))
        return cast(M, x)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> Optional[I]
        """Try to understand the most input values possible and make an internal value from them"""  # noqa: E501
        return self.h2i(pkt, x)

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], I) -> str
        """Convert internal value to a nice representation"""
        return repr(self.i2h(pkt, x))

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[I]) -> bytes
        """Add an internal value to a string

        Copy the network representation of field `val` (belonging to layer
        `pkt`) to the raw string packet `s`, and return the new string packet.
        """
        try:
            return s + self.struct.pack(self.i2m(pkt, val))
        except struct.error as ex:
            raise ValueError(
                "Incorrect type of value for field %s:\n" % self.name +
                "struct.error('%s')\n" % ex +
                "To inject bytes into the field regardless of the type, " +
                "use RawVal. See help(RawVal)"
            )

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, I]
        """Extract an internal value from a string

        Extract from the raw packet `s` the field value belonging to layer
        `pkt`.

        Returns a two-element list,
        first the raw packet string after having removed the extracted field,
        second the extracted field itself in internal representation.
        """
        return s[self.sz:], self.m2i(pkt, self.struct.unpack(s[:self.sz])[0])

    def do_copy(self, x):
        # type: (I) -> I
        if isinstance(x, list):
            x = x[:]  # type: ignore
            for i in range(len(x)):
                if isinstance(x[i], BasePacket):
                    x[i] = x[i].copy()
            return x  # type: ignore
        if hasattr(x, "copy"):
            return x.copy()  # type: ignore
        return x

    def __repr__(self):
        # type: () -> str
        return "<%s (%s).%s>" % (
            self.__class__.__name__,
            ",".join(x.__name__ for x in self.owners),
            self.name
        )

    def copy(self):
        # type: () -> Field[I, M]
        return copy.copy(self)

    def randval(self):
        # type: () -> VolatileValue[Any]
        """Return a volatile object whose value is both random and suitable for this field"""  # noqa: E501
        fmtt = self.fmt[-1]
        if fmtt in "BbHhIiQq":
            return {"B": RandByte, "b": RandSByte,
                    "H": RandShort, "h": RandSShort,
                    "I": RandInt, "i": RandSInt,
                    "Q": RandLong, "q": RandSLong}[fmtt]()
        elif fmtt == "s":
            if self.fmt[0] in "0123456789":
                value = int(self.fmt[:-1])
            else:
                value = int(self.fmt[1:-1])
            return RandBin(value)
        else:
            raise ValueError(
                "no random class for [%s] (fmt=%s)." % (
                    self.name, self.fmt
                )
            )


class _FieldContainer(object):
    """
    A field that acts as a container for another field
    """
    __slots__ = ["fld"]

    def __getattr__(self, attr):
        # type: (str) -> Any
        return getattr(self.fld, attr)


AnyField = Union[Field[Any, Any], _FieldContainer]


class Emph(_FieldContainer):
    """Empathize sub-layer for display"""
    __slots__ = ["fld"]

    def __init__(self, fld):
        # type: (Any) -> None
        self.fld = fld

    def __eq__(self, other):
        # type: (Any) -> bool
        return bool(self.fld == other)

    def __hash__(self):
        # type: () -> int
        return hash(self.fld)


class MayEnd(_FieldContainer):
    """
    Allow packet dissection to end after the dissection of this field
    if no bytes are left.

    A good example would be a length field that can be 0 or a set value,
    and where it would be too annoying to use multiple ConditionalFields

    Important note: any field below this one MUST default
    to an empty value, else the behavior will be unexpected.
    """
    __slots__ = ["fld"]

    def __init__(self, fld):
        # type: (Any) -> None
        self.fld = fld

    def __eq__(self, other):
        # type: (Any) -> bool
        return bool(self.fld == other)

    def __hash__(self):
        # type: () -> int
        return hash(self.fld)


class ActionField(_FieldContainer):
    __slots__ = ["fld", "_action_method", "_privdata"]

    def __init__(self, fld, action_method, **kargs):
        # type: (Field[Any, Any], str, **Any) -> None
        self.fld = fld
        self._action_method = action_method
        self._privdata = kargs

    def any2i(self, pkt, val):
        # type: (Optional[Packet], int) -> Any
        getattr(pkt, self._action_method)(val, self.fld, **self._privdata)
        return getattr(self.fld, "any2i")(pkt, val)


class ConditionalField(_FieldContainer):
    __slots__ = ["fld", "cond"]

    def __init__(self,
                 fld,  # type: AnyField
                 cond  # type: Callable[[Packet], bool]
                 ):
        # type: (...) -> None
        self.fld = fld
        self.cond = cond

    def _evalcond(self, pkt):
        # type: (Packet) -> bool
        return bool(self.cond(pkt))

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> Any
        # BACKWARD COMPATIBILITY
        # Note: we shouldn't need this function. (it's not correct)
        # However, having i2h implemented (#2364), it changes the default
        # behavior and broke all packets that wrongly use two ConditionalField
        # with the same name. Those packets are the problem: they are wrongly
        # built (they should either be re-using the same conditional field, or
        # using a MultipleTypeField).
        # But I don't want to dive into fixing all of them just yet,
        # so for now, let's keep this this way, even though it's not correct.
        if type(self.fld) is Field:
            return x
        return self.fld.any2i(pkt, x)

    def i2h(self, pkt, val):
        # type: (Optional[Packet], Any) -> Any
        if pkt and not self._evalcond(pkt):
            return None
        return self.fld.i2h(pkt, val)

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, Any]
        if self._evalcond(pkt):
            return self.fld.getfield(pkt, s)
        else:
            return s, None

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Any) -> bytes
        if self._evalcond(pkt):
            return self.fld.addfield(pkt, s, val)
        else:
            return s

    def __getattr__(self, attr):
        # type: (str) -> Any
        return getattr(self.fld, attr)


class MultipleTypeField(_FieldContainer):
    """
    MultipleTypeField are used for fields that can be implemented by
    various Field subclasses, depending on conditions on the packet.

    It is initialized with `flds` and `dflt`.

    :param dflt: is the default field type, to be used when none of the
                 conditions matched the current packet.
    :param flds: is a list of tuples (`fld`, `cond`) or (`fld`, `cond`, `hint`)
                 where `fld` if a field type, and `cond` a "condition" to
                 determine if `fld` is the field type that should be used.

    ``cond`` is either:

    - a callable `cond_pkt` that accepts one argument (the packet) and
      returns True if `fld` should be used, False otherwise.
    - a tuple (`cond_pkt`, `cond_pkt_val`), where `cond_pkt` is the same
      as in the previous case and `cond_pkt_val` is a callable that
      accepts two arguments (the packet, and the value to be set) and
      returns True if `fld` should be used, False otherwise.

    See scapy.layers.l2.ARP (type "help(ARP)" in Scapy) for an example of
    use.
    """

    __slots__ = ["flds", "dflt", "hints", "name", "default"]

    def __init__(
        self,
        flds: List[Union[
            Tuple[Field[Any, Any], Any, str],
            Tuple[Field[Any, Any], Any]
        ]],
        dflt: Field[Any, Any]
    ) -> None:
        self.hints = {
            x[0]: x[2]
            for x in flds
            if len(x) == 3
        }
        self.flds = [
            (x[0], x[1]) for x in flds
        ]
        self.dflt = dflt
        self.default = None  # So that we can detect changes in defaults
        self.name = self.dflt.name
        if any(x[0].name != self.name for x in self.flds):
            warnings.warn(
                ("All fields should have the same name in a "
                 "MultipleTypeField (%s). Use hints.") % self.name,
                SyntaxWarning
            )

    def _iterate_fields_cond(self, pkt, val, use_val):
        # type: (Optional[Packet], Any, bool) -> Field[Any, Any]
        """Internal function used by _find_fld_pkt & _find_fld_pkt_val"""
        # Iterate through the fields
        for fld, cond in self.flds:
            if isinstance(cond, tuple):
                if use_val:
                    if val is None:
                        val = self.dflt.default
                    if cond[1](pkt, val):
                        return fld
                    continue
                else:
                    cond = cond[0]
            if cond(pkt):
                return fld
        return self.dflt

    def _find_fld_pkt(self, pkt):
        # type: (Optional[Packet]) -> Field[Any, Any]
        """Given a Packet instance `pkt`, returns the Field subclass to be
used. If you know the value to be set (e.g., in .addfield()), use
._find_fld_pkt_val() instead.

        """
        return self._iterate_fields_cond(pkt, None, False)

    def _find_fld_pkt_val(self,
                          pkt,  # type: Optional[Packet]
                          val,  # type: Any
                          ):
        # type: (...) -> Tuple[Field[Any, Any], Any]
        """Given a Packet instance `pkt` and the value `val` to be set,
returns the Field subclass to be used, and the updated `val` if necessary.

        """
        fld = self._iterate_fields_cond(pkt, val, True)
        if val is None:
            val = fld.default
        return fld, val

    def _find_fld(self):
        # type: () -> Field[Any, Any]
        """Returns the Field subclass to be used, depending on the Packet
instance, or the default subclass.

DEV: since the Packet instance is not provided, we have to use a hack
to guess it. It should only be used if you cannot provide the current
Packet instance (for example, because of the current Scapy API).

If you have the current Packet instance, use ._find_fld_pkt_val() (if
the value to set is also known) of ._find_fld_pkt() instead.

        """
        # Hack to preserve current Scapy API
        # See https://stackoverflow.com/a/7272464/3223422
        frame = inspect.currentframe().f_back.f_back  # type: ignore
        while frame is not None:
            try:
                pkt = frame.f_locals['self']
            except KeyError:
                pass
            else:
                if isinstance(pkt, tuple(self.dflt.owners)):
                    if not pkt.default_fields:
                        # Packet not initialized
                        return self.dflt
                    return self._find_fld_pkt(pkt)
            frame = frame.f_back
        return self.dflt

    def getfield(self,
                 pkt,  # type: Packet
                 s,  # type: bytes
                 ):
        # type: (...) -> Tuple[bytes, Any]
        return self._find_fld_pkt(pkt).getfield(pkt, s)

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Any) -> bytes
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.addfield(pkt, s, val)

    def any2i(self, pkt, val):
        # type: (Optional[Packet], Any) -> Any
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.any2i(pkt, val)

    def h2i(self, pkt, val):
        # type: (Optional[Packet], Any) -> Any
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.h2i(pkt, val)

    def i2h(self,
            pkt,  # type: Packet
            val,  # type: Any
            ):
        # type: (...) -> Any
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.i2h(pkt, val)

    def i2m(self, pkt, val):
        # type: (Optional[Packet], Optional[Any]) -> Any
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.i2m(pkt, val)

    def i2len(self, pkt, val):
        # type: (Packet, Any) -> int
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.i2len(pkt, val)

    def i2repr(self, pkt, val):
        # type: (Optional[Packet], Any) -> str
        fld, val = self._find_fld_pkt_val(pkt, val)
        hint = ""
        if fld in self.hints:
            hint = " (%s)" % self.hints[fld]
        return fld.i2repr(pkt, val) + hint

    def register_owner(self, cls):
        # type: (Type[Packet]) -> None
        for fld, _ in self.flds:
            fld.owners.append(cls)
        self.dflt.owners.append(cls)

    def get_fields_list(self):
        # type: () -> List[Any]
        return [self]

    @property
    def fld(self):
        # type: () -> Field[Any, Any]
        return self._find_fld()


class PadField(_FieldContainer):
    """Add bytes after the proxified field so that it ends at the specified
       alignment from its beginning"""
    __slots__ = ["fld", "_align", "_padwith"]

    def __init__(self, fld, align, padwith=None):
        # type: (AnyField, int, Optional[bytes]) -> None
        self.fld = fld
        self._align = align
        self._padwith = padwith or b"\x00"

    def padlen(self, flen, pkt):
        # type: (int, Packet) -> int
        return -flen % self._align

    def getfield(self,
                 pkt,  # type: Packet
                 s,  # type: bytes
                 ):
        # type: (...) -> Tuple[bytes, Any]
        remain, val = self.fld.getfield(pkt, s)
        padlen = self.padlen(len(s) - len(remain), pkt)
        return remain[padlen:], val

    def addfield(self,
                 pkt,  # type: Packet
                 s,  # type: bytes
                 val,  # type: Any
                 ):
        # type: (...) -> bytes
        sval = self.fld.addfield(pkt, b"", val)
        return s + sval + (
            self.padlen(len(sval), pkt) * self._padwith
        )


class ReversePadField(PadField):
    """Add bytes BEFORE the proxified field so that it starts at the specified
       alignment from its beginning"""

    def original_length(self, pkt):
        # type: (Packet) -> int
        return len(pkt.original)

    def getfield(self,
                 pkt,  # type: Packet
                 s,  # type: bytes
                 ):
        # type: (...) -> Tuple[bytes, Any]
        # We need to get the length that has already been dissected
        padlen = self.padlen(self.original_length(pkt) - len(s), pkt)
        return self.fld.getfield(pkt, s[padlen:])

    def addfield(self,
                 pkt,  # type: Packet
                 s,  # type: bytes
                 val,  # type: Any
                 ):
        # type: (...) -> bytes
        sval = self.fld.addfield(pkt, b"", val)
        return s + struct.pack("%is" % (
            self.padlen(len(s), pkt)
        ), self._padwith) + sval


class TrailerBytes(bytes):
    """
    Reverses slice operations to take from the back of the packet,
    not the front
    """

    def __getitem__(self, item):  # type: ignore
        # type: (Union[int, slice]) -> Union[int, bytes]
        if isinstance(item, int):
            if item < 0:
                item = 1 + item
            else:
                item = len(self) - 1 - item
        elif isinstance(item, slice):
            start, stop, step = item.start, item.stop, item.step
            new_start = -stop if stop else None
            new_stop = -start if start else None
            item = slice(new_start, new_stop, step)
        return super(self.__class__, self).__getitem__(item)


class TrailerField(_FieldContainer):
    """Special Field that gets its value from the end of the *packet*
    (Note: not layer, but packet).

    Mostly used for FCS
    """
    __slots__ = ["fld"]

    def __init__(self, fld):
        # type: (Field[Any, Any]) -> None
        self.fld = fld

    # Note: this is ugly. Very ugly.
    # Do not copy this crap elsewhere, so that if one day we get
    # brave enough to refactor it, it'll be easier.

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, int]
        previous_post_dissect = pkt.post_dissect

        def _post_dissect(self, s):
            # type: (Packet, bytes) -> bytes
            # Reset packet to allow post_build
            self.raw_packet_cache = None
            self.post_dissect = previous_post_dissect  # type: ignore
            return previous_post_dissect(s)
        pkt.post_dissect = MethodType(_post_dissect, pkt)  # type: ignore
        s = TrailerBytes(s)
        s, val = self.fld.getfield(pkt, s)
        return bytes(s), val

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[int]) -> bytes
        previous_post_build = pkt.post_build
        value = self.fld.addfield(pkt, b"", val)

        def _post_build(self, p, pay):
            # type: (Packet, bytes, bytes) -> bytes
            pay += value
            self.post_build = previous_post_build  # type: ignore
            return previous_post_build(p, pay)
        pkt.post_build = MethodType(_post_build, pkt)  # type: ignore
        return s


class FCSField(TrailerField):
    """
    A FCS field that gets appended at the end of the *packet* (not layer).
    """

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        super(FCSField, self).__init__(Field(*args, **kwargs))

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return lhex(self.i2h(pkt, x))


class DestField(Field[str, bytes]):
    __slots__ = ["defaultdst"]
    # Each subclass must have its own bindings attribute
    bindings = {}  # type: Dict[Type[Packet], Tuple[str, Any]]

    def __init__(self, name, default):
        # type: (str, str) -> None
        self.defaultdst = default

    def dst_from_pkt(self, pkt):
        # type: (Packet) -> str
        for addr, condition in self.bindings.get(pkt.payload.__class__, []):
            try:
                if all(pkt.payload.getfieldval(field) == value
                       for field, value in condition.items()):
                    return addr  # type: ignore
            except AttributeError:
                pass
        return self.defaultdst

    @classmethod
    def bind_addr(cls, layer, addr, **condition):
        # type: (Type[Packet], str, **Any) -> None
        cls.bindings.setdefault(layer, []).append(  # type: ignore
            (addr, condition)
        )


class MACField(Field[Optional[str], bytes]):
    def __init__(self, name, default):
        # type: (str, Optional[Any]) -> None
        Field.__init__(self, name, default, "6s")

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[str]) -> bytes
        if not x:
            return b"\0\0\0\0\0\0"
        try:
            y = mac2str(x)
        except (struct.error, OverflowError):
            y = bytes_encode(x)
        return y

    def m2i(self, pkt, x):
        # type: (Optional[Packet], bytes) -> str
        return str2mac(x)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> str
        if isinstance(x, bytes) and len(x) == 6:
            return self.m2i(pkt, x)
        return cast(str, x)

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], Optional[str]) -> str
        x = self.i2h(pkt, x)
        if x is None:
            return repr(x)
        if self in conf.resolve:
            x = conf.manufdb._resolve_MAC(x)
        return x

    def randval(self):
        # type: () -> RandMAC
        return RandMAC()


class LEMACField(MACField):
    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[str]) -> bytes
        return MACField.i2m(self, pkt, x)[::-1]

    def m2i(self, pkt, x):
        # type: (Optional[Packet], bytes) -> str
        return MACField.m2i(self, pkt, x[::-1])


class IPField(Field[Union[str, Net], bytes]):
    def __init__(self, name, default):
        # type: (str, Optional[str]) -> None
        Field.__init__(self, name, default, "4s")

    def h2i(self, pkt, x):
        # type: (Optional[Packet], Union[AnyStr, List[AnyStr]]) -> Any
        if isinstance(x, bytes):
            x = plain_str(x)  # type: ignore
        if isinstance(x, _ScopedIP):
            return x
        elif isinstance(x, str):
            x = ScopedIP(x)
            try:
                inet_aton(x)
            except socket.error:
                return Net(x)
        elif isinstance(x, tuple):
            if len(x) != 2:
                raise ValueError("Invalid IP format")
            return Net(*x)
        elif isinstance(x, list):
            return [self.h2i(pkt, n) for n in x]
        return x

    def i2h(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net]]) -> str
        return cast(str, x)

    def resolve(self, x):
        # type: (str) -> str
        if self in conf.resolve:
            try:
                ret = socket.gethostbyaddr(x)[0]
            except Exception:
                pass
            else:
                if ret:
                    return ret
        return x

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net]]) -> bytes
        if x is None:
            return b'\x00\x00\x00\x00'
        return inet_aton(plain_str(x))

    def m2i(self, pkt, x):
        # type: (Optional[Packet], bytes) -> str
        return inet_ntoa(x)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> Any
        return self.h2i(pkt, x)

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], Union[str, Net]) -> str
        if isinstance(x, _ScopedIP) and x.scope:
            return repr(x)
        r = self.resolve(self.i2h(pkt, x))
        return r if isinstance(r, str) else repr(r)

    def randval(self):
        # type: () -> RandIP
        return RandIP()


class SourceIPField(IPField):
    def __init__(self, name):
        # type: (str) -> None
        IPField.__init__(self, name, None)

    def __findaddr(self, pkt):
        # type: (Packet) -> Optional[str]
        if conf.route is None:
            # unused import, only to initialize conf.route
            import scapy.route  # noqa: F401
        return pkt.route()[1] or conf.route.route()[1]

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net]]) -> bytes
        if x is None and pkt is not None:
            x = self.__findaddr(pkt)
        return super(SourceIPField, self).i2m(pkt, x)

    def i2h(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net]]) -> str
        if x is None and pkt is not None:
            x = self.__findaddr(pkt)
        return super(SourceIPField, self).i2h(pkt, x)


class IP6Field(Field[Optional[Union[str, Net6]], bytes]):
    def __init__(self, name, default):
        # type: (str, Optional[str]) -> None
        Field.__init__(self, name, default, "16s")

    def h2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> str
        if isinstance(x, bytes):
            x = plain_str(x)
        if isinstance(x, _ScopedIP):
            return x
        elif isinstance(x, str):
            x = ScopedIP(x)
            try:
                x = ScopedIP(in6_ptop(x), scope=x.scope)
            except socket.error:
                return Net6(x)  # type: ignore
        elif isinstance(x, tuple):
            if len(x) != 2:
                raise ValueError("Invalid IPv6 format")
            return Net6(*x)  # type: ignore
        elif isinstance(x, list):
            x = [self.h2i(pkt, n) for n in x]
        return x  # type: ignore

    def i2h(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net6]]) -> str
        return cast(str, x)

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net6]]) -> bytes
        if x is None:
            x = "::"
        return inet_pton(socket.AF_INET6, plain_str(x))

    def m2i(self, pkt, x):
        # type: (Optional[Packet], bytes) -> str
        return inet_ntop(socket.AF_INET6, x)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Optional[str]) -> str
        return self.h2i(pkt, x)

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net6]]) -> str
        if x is None:
            return self.i2h(pkt, x)
        elif not isinstance(x, Net6) and not isinstance(x, list):
            if in6_isaddrTeredo(x):   # print Teredo info
                server, _, maddr, mport = teredoAddrExtractInfo(x)
                return "%s [Teredo srv: %s cli: %s:%s]" % (self.i2h(pkt, x), server, maddr, mport)  # noqa: E501
            elif in6_isaddr6to4(x):   # print encapsulated address
                vaddr = in6_6to4ExtractAddr(x)
                return "%s [6to4 GW: %s]" % (self.i2h(pkt, x), vaddr)
            elif isinstance(x, _ScopedIP) and x.scope:
                return repr(x)
        r = self.i2h(pkt, x)          # No specific information to return
        return r if isinstance(r, str) else repr(r)

    def randval(self):
        # type: () -> RandIP6
        return RandIP6()


class SourceIP6Field(IP6Field):
    def __init__(self, name):
        # type: (str) -> None
        IP6Field.__init__(self, name, None)

    def __findaddr(self, pkt):
        # type: (Packet) -> Optional[str]
        if conf.route6 is None:
            # unused import, only to initialize conf.route
            import scapy.route6  # noqa: F401
        return pkt.route()[1]

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net6]]) -> bytes
        if x is None and pkt is not None:
            x = self.__findaddr(pkt)
        return super(SourceIP6Field, self).i2m(pkt, x)

    def i2h(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net6]]) -> str
        if x is None and pkt is not None:
            x = self.__findaddr(pkt)
        return super(SourceIP6Field, self).i2h(pkt, x)


class DestIP6Field(IP6Field, DestField):
    bindings = {}  # type: Dict[Type[Packet], Tuple[str, Any]]

    def __init__(self, name, default):
        # type: (str, str) -> None
        IP6Field.__init__(self, name, None)
        DestField.__init__(self, name, default)

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net6]]) -> bytes
        if x is None and pkt is not None:
            x = self.dst_from_pkt(pkt)
        return IP6Field.i2m(self, pkt, x)

    def i2h(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net6]]) -> str
        if x is None and pkt is not None:
            x = self.dst_from_pkt(pkt)
        return super(DestIP6Field, self).i2h(pkt, x)


class ByteField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "B")


class XByteField(ByteField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return lhex(self.i2h(pkt, x))


# XXX Unused field: at least add some tests
class OByteField(ByteField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return "%03o" % self.i2h(pkt, x)


class ThreeBytesField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, int) -> None
        Field.__init__(self, name, default, "!I")

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[int]) -> bytes
        return s + struct.pack(self.fmt, self.i2m(pkt, val))[1:4]

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, int]
        return s[3:], self.m2i(pkt, struct.unpack(self.fmt, b"\x00" + s[:3])[0])  # noqa: E501


class X3BytesField(ThreeBytesField, XByteField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return XByteField.i2repr(self, pkt, x)


class LEThreeBytesField(ByteField):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "<I")

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[int]) -> bytes
        return s + struct.pack(self.fmt, self.i2m(pkt, val))[:3]

    def getfield(self, pkt, s):
        # type: (Optional[Packet], bytes) -> Tuple[bytes, int]
        return s[3:], self.m2i(pkt, struct.unpack(self.fmt, s[:3] + b"\x00")[0])  # noqa: E501


class XLE3BytesField(LEThreeBytesField, XByteField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return XByteField.i2repr(self, pkt, x)


def LEX3BytesField(*args, **kwargs):
    # type: (*Any, **Any) -> Any
    warnings.warn(
        "LEX3BytesField is deprecated. Use XLE3BytesField",
        DeprecationWarning
    )
    return XLE3BytesField(*args, **kwargs)


class NBytesField(Field[int, List[int]]):
    def __init__(self, name, default, sz):
        # type: (str, Optional[int], int) -> None
        Field.__init__(self, name, default, "<" + "B" * sz)

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[int]) -> List[int]
        if x is None:
            return [0] * self.sz
        x2m = list()
        for _ in range(self.sz):
            x2m.append(x % 256)
            x //= 256
        return x2m[::-1]

    def m2i(self, pkt, x):
        # type: (Optional[Packet], Union[List[int], int]) -> int
        if isinstance(x, int):
            return x
        # x can be a tuple when coming from struct.unpack  (from getfield)
        if isinstance(x, (list, tuple)):
            return sum(d * (256 ** i) for i, d in enumerate(reversed(x)))
        return 0

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        if isinstance(x, int):
            return '%i' % x
        return super(NBytesField, self).i2repr(pkt, x)

    def addfield(self, pkt, s, val):
        # type: (Optional[Packet], bytes, Optional[int]) -> bytes
        return s + self.struct.pack(*self.i2m(pkt, val))

    def getfield(self, pkt, s):
        # type: (Optional[Packet], bytes) -> Tuple[bytes, int]
        return (s[self.sz:],
                self.m2i(pkt, self.struct.unpack(s[:self.sz])))  # type: ignore

    def randval(self):
        # type: () -> RandNum
        return RandNum(0, 2 ** (self.sz * 8) - 1)


class XNBytesField(NBytesField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        if isinstance(x, int):
            return '0x%x' % x
        # x can be a tuple when coming from struct.unpack (from getfield)
        if isinstance(x, (list, tuple)):
            return "0x" + "".join("%02x" % b for b in x)
        return super(XNBytesField, self).i2repr(pkt, x)


class SignedByteField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "b")


class FieldValueRangeException(Scapy_Exception):
    pass


class MaximumItemsCount(Scapy_Exception):
    pass


class FieldAttributeException(Scapy_Exception):
    pass


class YesNoByteField(ByteField):
    """
    A byte based flag field that shows representation of its number
    based on a given association

    In its default configuration the following representation is generated:
        x == 0 : 'no'
        x != 0 : 'yes'

    In more sophisticated use-cases (e.g. yes/no/invalid) one can use the
    config attribute to configure.
    Key-value, key-range and key-value-set associations that will be used to
    generate the values representation.

    - A range is given by a tuple (<first-val>, <last-value>) including the
      last value.
    - A single-value tuple is treated as scalar.
    - A list defines a set of (probably non consecutive) values that should be
      associated to a given key.

    All values not associated with a key will be shown as number of type
    unsigned byte.

    **For instance**::

        config = {
            'no' : 0,
            'foo' : (1,22),
            'yes' : 23,
            'bar' : [24,25, 42, 48, 87, 253]
        }

    Generates the following representations::

        x == 0 : 'no'
        x == 15: 'foo'
        x == 23: 'yes'
        x == 42: 'bar'
        x == 43: 43

    Another example, using the config attribute one could also revert
    the stock-yes-no-behavior::

        config = {
                'yes' : 0,
                'no' : (1,255)
        }

    Will generate the following value representation::

        x == 0 : 'yes'
        x != 0 : 'no'

    """
    __slots__ = ['eval_fn']

    def _build_config_representation(self, config):
        # type: (Dict[str, Any]) -> None
        assoc_table = dict()
        for key in config:
            value_spec = config[key]

            value_spec_type = type(value_spec)

            if value_spec_type is int:
                if value_spec < 0 or value_spec > 255:
                    raise FieldValueRangeException('given field value {} invalid - '  # noqa: E501
                                                   'must be in range [0..255]'.format(value_spec))  # noqa: E501
                assoc_table[value_spec] = key

            elif value_spec_type is list:
                for value in value_spec:
                    if value < 0 or value > 255:
                        raise FieldValueRangeException('given field value {} invalid - '  # noqa: E501
                                                       'must be in range [0..255]'.format(value))  # noqa: E501
                    assoc_table[value] = key

            elif value_spec_type is tuple:
                value_spec_len = len(value_spec)
                if value_spec_len != 2:
                    raise FieldAttributeException('invalid length {} of given config item tuple {} - must be '  # noqa: E501
                                                  '(<start-range>, <end-range>).'.format(value_spec_len, value_spec))  # noqa: E501

                value_range_start = value_spec[0]
                if value_range_start < 0 or value_range_start > 255:
                    raise FieldValueRangeException('given field value {} invalid - '  # noqa: E501
                                                   'must be in range [0..255]'.format(value_range_start))  # noqa: E501

                value_range_end = value_spec[1]
                if value_range_end < 0 or value_range_end > 255:
                    raise FieldValueRangeException('given field value {} invalid - '  # noqa: E501
                                                   'must be in range [0..255]'.format(value_range_end))  # noqa: E501

                for value in range(value_range_start, value_range_end + 1):

                    assoc_table[value] = key

        self.eval_fn = lambda x: assoc_table[x] if x in assoc_table else x

    def __init__(self, name, default, config=None):
        # type: (str, int, Optional[Dict[str, Any]]) -> None

        if not config:
            # this represents the common use case and therefore it is kept small  # noqa: E501
            self.eval_fn = lambda x: 'no' if x == 0 else 'yes'
        else:
            self._build_config_representation(config)
        ByteField.__init__(self, name, default)

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return self.eval_fn(x)  # type: ignore


class ShortField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "H")


class SignedShortField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "h")


class LEShortField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "<H")


class LESignedShortField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "<h")


class XShortField(ShortField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return lhex(self.i2h(pkt, x))


class IntField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "I")


class SignedIntField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, int) -> None
        Field.__init__(self, name, default, "i")


class LEIntField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "<I")


class LESignedIntField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, int) -> None
        Field.__init__(self, name, default, "<i")


class XIntField(IntField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return lhex(self.i2h(pkt, x))


class XLEIntField(LEIntField, XIntField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return XIntField.i2repr(self, pkt, x)


class XLEShortField(LEShortField, XShortField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return XShortField.i2repr(self, pkt, x)


class LongField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, int) -> None
        Field.__init__(self, name, default, "Q")


class SignedLongField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "q")


class LELongField(LongField):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "<Q")


class LESignedLongField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[Any]) -> None
        Field.__init__(self, name, default, "<q")


class XLongField(LongField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return lhex(self.i2h(pkt, x))


class XLELongField(LELongField, XLongField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return XLongField.i2repr(self, pkt, x)


class IEEEFloatField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "f")


class IEEEDoubleField(Field[int, int]):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "d")


class _StrField(Field[I, bytes]):
    __slots__ = ["remain"]

    def __init__(self, name, default, fmt="H", remain=0):
        # type: (str, Optional[I], str, int) -> None
        Field.__init__(self, name, default, fmt)
        self.remain = remain

    def i2len(self, pkt, x):
        # type: (Optional[Packet], Any) -> int
        if x is None:
            return 0
        return len(x)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> I
        if isinstance(x, str):
            x = bytes_encode(x)
        return super(_StrField, self).any2i(pkt, x)  # type: ignore

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], I) -> str
        if x and isinstance(x, bytes):
            return repr(x)
        return super(_StrField, self).i2repr(pkt, x)

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[I]) -> bytes
        if x is None:
            return b""
        if not isinstance(x, bytes):
            return bytes_encode(x)
        return x

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[I]) -> bytes
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, I]
        if self.remain == 0:
            return b"", self.m2i(pkt, s)
        else:
            return s[-self.remain:], self.m2i(pkt, s[:-self.remain])

    def randval(self):
        # type: () -> RandBin
        return RandBin(RandNum(0, 1200))


class StrField(_StrField[bytes]):
    pass


class StrFieldUtf16(StrField):
    def any2i(self, pkt, x):
        # type: (Optional[Packet], Optional[str]) -> bytes
        if isinstance(x, str):
            return self.h2i(pkt, x)
        return super(StrFieldUtf16, self).any2i(pkt, x)

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], bytes) -> str
        return plain_str(self.i2h(pkt, x))

    def h2i(self, pkt, x):
        # type: (Optional[Packet], Optional[str]) -> bytes
        return plain_str(x).encode('utf-16-le', errors="replace")

    def i2h(self, pkt, x):
        # type: (Optional[Packet], bytes) -> str
        return bytes_encode(x).decode('utf-16-le', errors="replace")


class _StrEnumField:
    def __init__(self, **kwargs):
        # type: (**Any) -> None
        self.enum = kwargs.pop("enum", {})

    def i2repr(self, pkt, v):
        # type: (Optional[Packet], bytes) -> str
        r = v.rstrip(b"\0")
        rr = repr(r)
        if self.enum:
            if v in self.enum:
                rr = "%s (%s)" % (rr, self.enum[v])
            elif r in self.enum:
                rr = "%s (%s)" % (rr, self.enum[r])
        return rr


class StrEnumField(_StrEnumField, StrField):
    __slots__ = ["enum"]

    def __init__(
            self,
            name,  # type: str
            default,  # type: bytes
            enum=None,  # type: Optional[Dict[str, str]]
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        StrField.__init__(self, name, default, **kwargs)  # type: ignore
        self.enum = enum


K = TypeVar('K', List[BasePacket], BasePacket, Optional[BasePacket])


class _PacketField(_StrField[K]):
    __slots__ = ["cls"]
    holds_packets = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[K]
                 pkt_cls,  # type: Union[Callable[[bytes], Packet], Type[Packet]]  # noqa: E501
                 ):
        # type: (...) -> None
        super(_PacketField, self).__init__(name, default)
        self.cls = pkt_cls

    def i2m(self,
            pkt,  # type: Optional[Packet]
            i,  # type: Any
            ):
        # type: (...) -> bytes
        if i is None:
            return b""
        return raw(i)

    def m2i(self, pkt, m):  # type: ignore
        # type: (Optional[Packet], bytes) -> Packet
        try:
            # we want to set parent wherever possible
            return self.cls(m, _parent=pkt)  # type: ignore
        except TypeError:
            return self.cls(m)


class _PacketFieldSingle(_PacketField[K]):
    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> K
        if x and pkt and hasattr(x, "add_parent"):
            cast("Packet", x).add_parent(pkt)
        return super(_PacketFieldSingle, self).any2i(pkt, x)

    def getfield(self,
                 pkt,  # type: Packet
                 s,  # type: bytes
                 ):
        # type: (...) -> Tuple[bytes, K]
        i = self.m2i(pkt, s)
        remain = b""
        if conf.padding_layer in i:
            r = i[conf.padding_layer]
            del r.underlayer.payload
            remain = r.load
        return remain, i  # type: ignore


class PacketField(_PacketFieldSingle[BasePacket]):
    def randval(self):  # type: ignore
        # type: () -> Packet
        from scapy.packet import fuzz
        return fuzz(self.cls())  # type: ignore


class PacketLenField(_PacketFieldSingle[Optional[BasePacket]]):
    __slots__ = ["length_from"]

    def __init__(self,
                 name,  # type: str
                 default,  # type: Packet
                 cls,  # type: Union[Callable[[bytes], Packet], Type[Packet]]  # noqa: E501
                 length_from=None  # type: Optional[Callable[[Packet], int]]  # noqa: E501
                 ):
        # type: (...) -> None
        super(PacketLenField, self).__init__(name, default, cls)
        self.length_from = length_from or (lambda x: 0)

    def getfield(self,
                 pkt,  # type: Packet
                 s,  # type: bytes
                 ):
        # type: (...) -> Tuple[bytes, Optional[BasePacket]]
        len_pkt = self.length_from(pkt)
        i = None
        if len_pkt:
            try:
                i = self.m2i(pkt, s[:len_pkt])
            except Exception:
                if conf.debug_dissector:
                    raise
                i = conf.raw_layer(load=s[:len_pkt])
        return s[len_pkt:], i


class PacketListField(_PacketField[List[BasePacket]]):
    """PacketListField represents a list containing a series of Packet instances
    that might occur right in the middle of another Packet field.
    This field type may also be used to indicate that a series of Packet
    instances have a sibling semantic instead of a parent/child relationship
    (i.e. a stack of layers). All elements in PacketListField have current
    packet referenced in parent field.
    """
    __slots__ = ["count_from", "length_from", "next_cls_cb", "max_count"]
    islist = 1

    def __init__(
            self,
            name,  # type: str
            default,  # type: Optional[List[BasePacket]]
            pkt_cls=None,  # type: Optional[Union[Callable[[bytes], Packet], Type[Packet]]]  # noqa: E501
            count_from=None,  # type: Optional[Callable[[Packet], int]]
            length_from=None,  # type: Optional[Callable[[Packet], int]]
            next_cls_cb=None,  # type: Optional[Callable[[Packet, List[BasePacket], Optional[Packet], bytes], Type[Packet]]]  # noqa: E501
            max_count=None,  # type: Optional[int]
    ):
        # type: (...) -> None
        """
        The number of Packet instances that are dissected by this field can
        be parametrized using one of three different mechanisms/parameters:

            * count_from: a callback that returns the number of Packet
              instances to dissect. The callback prototype is::

                count_from(pkt:Packet) -> int

            * length_from: a callback that returns the number of bytes that
              must be dissected by this field. The callback prototype is::

                length_from(pkt:Packet) -> int

            * next_cls_cb: a callback that enables a Scapy developer to
              dynamically discover if another Packet instance should be
              dissected or not. See below for this callback prototype.

        The bytes that are not consumed during the dissection of this field
        are passed to the next field of the current packet.

        For the serialization of such a field, the list of Packets that are
        contained in a PacketListField can be heterogeneous and is
        unrestricted.

        The type of the Packet instances that are dissected with this field is
        specified or discovered using one of the following mechanism:

            * the pkt_cls parameter may contain a callable that returns an
              instance of the dissected Packet. This may either be a
              reference of a Packet subclass (e.g. DNSRROPT in layers/dns.py)
              to generate an homogeneous PacketListField or a function
              deciding the type of the Packet instance
              (e.g. _CDPGuessAddrRecord in contrib/cdp.py)

            * the pkt_cls parameter may contain a class object with a defined
              ``dispatch_hook`` classmethod. That method must return a Packet
              instance. The ``dispatch_hook`` callmethod must implement the
                following prototype::

                dispatch_hook(cls,
                              _pkt:Optional[Packet],
                              *args, **kargs
                ) -> Type[Packet]

                The _pkt parameter may contain a reference to the packet
                instance containing the PacketListField that is being
                dissected.

            * the ``next_cls_cb`` parameter may contain a callable whose
              prototype is::

                cbk(pkt:Packet,
                    lst:List[Packet],
                    cur:Optional[Packet],
                    remain:str
                ) -> Optional[Type[Packet]]

              The pkt argument contains a reference to the Packet instance
              containing the PacketListField that is being dissected.
              The lst argument is the list of all Packet instances that were
              previously parsed during the current ``PacketListField``
              dissection, saved for the very last Packet instance.
              The cur argument contains a reference to that very last parsed
              ``Packet`` instance. The remain argument contains the bytes
              that may still be consumed by the current PacketListField
              dissection operation.

              This callback returns either the type of the next Packet to
              dissect or None to indicate that no more Packet are to be
              dissected.

              These four arguments allows a variety of dynamic discovery of
              the number of Packet to dissect and of the type of each one of
              these Packets, including: type determination based on current
              Packet instances or its underlayers, continuation based on the
              previously parsed Packet instances within that PacketListField,
              continuation based on a look-ahead on the bytes to be
              dissected...

        The pkt_cls and next_cls_cb parameters are semantically exclusive,
        although one could specify both. If both are specified, pkt_cls is
        silently ignored. The same is true for count_from and next_cls_cb.

        length_from and next_cls_cb are compatible and the dissection will
        end, whichever of the two stop conditions comes first.

        :param name: the name of the field
        :param default: the default value of this field; generally an empty
            Python list
        :param pkt_cls: either a callable returning a Packet instance or a
            class object defining a ``dispatch_hook`` class method
        :param count_from: a callback returning the number of Packet
            instances to dissect.
        :param length_from: a callback returning the number of bytes to dissect
        :param next_cls_cb: a callback returning either None or the type of
            the next Packet to dissect.
        :param max_count: an int containing the max amount of results. This is
            a safety mechanism, exceeding this value will raise a Scapy_Exception.
        """
        if default is None:
            default = []  # Create a new list for each instance
        super(PacketListField, self).__init__(
            name,
            default,
            pkt_cls  # type: ignore
        )
        self.count_from = count_from
        self.length_from = length_from
        self.next_cls_cb = next_cls_cb
        self.max_count = max_count

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> List[BasePacket]
        if not isinstance(x, list):
            if x and pkt and hasattr(x, "add_parent"):
                x.add_parent(pkt)
            return [x]
        elif pkt:
            for i in x:
                if not i or not hasattr(i, "add_parent"):
                    continue
                i.add_parent(pkt)
        return x

    def i2count(self,
                pkt,  # type: Optional[Packet]
                val,  # type: List[BasePacket]
                ):
        # type: (...) -> int
        if isinstance(val, list):
            return len(val)
        return 1

    def i2len(self,
              pkt,  # type: Optional[Packet]
              val,  # type: List[Packet]
              ):
        # type: (...) -> int
        return sum(len(self.i2m(pkt, p)) for p in val)

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, List[BasePacket]]
        c = len_pkt = cls = None
        if self.length_from is not None:
            len_pkt = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)
        if self.next_cls_cb is not None:
            cls = self.next_cls_cb(pkt, [], None, s)
            c = 1
            if cls is None:
                c = 0

        lst = []  # type: List[BasePacket]
        ret = b""
        remain = s
        if len_pkt is not None:
            remain, ret = s[:len_pkt], s[len_pkt:]
        while remain:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            try:
                if cls is not None:
                    try:
                        # we want to set parent wherever possible
                        p = cls(remain, _parent=pkt)
                    except TypeError:
                        p = cls(remain)
                else:
                    p = self.m2i(pkt, remain)
            except Exception:
                if conf.debug_dissector:
                    raise
                p = conf.raw_layer(load=remain)
                remain = b""
            else:
                if conf.padding_layer in p:
                    pad = p[conf.padding_layer]
                    remain = pad.load
                    del pad.underlayer.payload
                    if self.next_cls_cb is not None:
                        cls = self.next_cls_cb(pkt, lst, p, remain)
                        if cls is not None:
                            c = 0 if c is None else c
                            c += 1
                else:
                    remain = b""
            lst.append(p)
            if len(lst) > (self.max_count or conf.max_list_count):
                raise MaximumItemsCount(
                    "Maximum amount of items reached in PacketListField: %s "
                    "(defaults to conf.max_list_count)"
                    % (self.max_count or conf.max_list_count)
                )

        if isinstance(remain, tuple):
            remain, nb = remain
            return (remain + ret, nb), lst
        else:
            return remain + ret, lst

    def i2m(self,
            pkt,  # type: Optional[Packet]
            i,  # type: Any
            ):
        # type: (...) -> bytes
        return bytes_encode(i)

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Any) -> bytes
        return s + b"".join(self.i2m(pkt, v) for v in val)


class StrFixedLenField(StrField):
    __slots__ = ["length_from"]

    def __init__(
            self,
            name,  # type: str
            default,  # type: Optional[bytes]
            length=None,  # type: Optional[int]
            length_from=None,  # type: Optional[Callable[[Packet], int]]  # noqa: E501
    ):
        # type: (...) -> None
        super(StrFixedLenField, self).__init__(name, default)
        self.length_from = length_from or (lambda x: 0)
        if length is not None:
            self.sz = length
            self.length_from = lambda x, length=length: length  # type: ignore

    def i2repr(self,
               pkt,  # type: Optional[Packet]
               v,  # type: bytes
               ):
        # type: (...) -> str
        if isinstance(v, bytes):
            v = v.rstrip(b"\0")
        return super(StrFixedLenField, self).i2repr(pkt, v)

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, bytes]
        len_pkt = self.length_from(pkt)
        if len_pkt == 0:
            return s, b""
        return s[len_pkt:], self.m2i(pkt, s[:len_pkt])

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[bytes]) -> bytes
        len_pkt = self.length_from(pkt)
        if len_pkt is None:
            return s + self.i2m(pkt, val)
        return s + struct.pack("%is" % len_pkt, self.i2m(pkt, val))

    def randval(self):
        # type: () -> RandBin
        try:
            return RandBin(self.length_from(None))  # type: ignore
        except Exception:
            return RandBin(RandNum(0, 200))


class StrFixedLenFieldUtf16(StrFixedLenField, StrFieldUtf16):
    pass


class StrFixedLenEnumField(_StrEnumField, StrFixedLenField):
    __slots__ = ["enum"]

    def __init__(
            self,
            name,  # type: str
            default,  # type: bytes
            enum=None,  # type: Optional[Dict[str, str]]
            length=None,  # type: Optional[int]
            length_from=None  # type: Optional[Callable[[Optional[Packet]], int]]  # noqa: E501
    ):
        # type: (...) -> None
        StrFixedLenField.__init__(self, name, default, length=length, length_from=length_from)  # noqa: E501
        self.enum = enum


class NetBIOSNameField(StrFixedLenField):
    def __init__(self, name, default, length=31):
        # type: (str, bytes, int) -> None
        StrFixedLenField.__init__(self, name, default, length)

    def h2i(self, pkt, x):
        # type: (Optional[Packet], bytes) -> bytes
        if x and len(x) > 15:
            x = x[:15]
        return x

    def i2m(self, pkt, y):
        # type: (Optional[Packet], Optional[bytes]) -> bytes
        if pkt:
            len_pkt = self.length_from(pkt) // 2
        else:
            len_pkt = 0
        x = bytes_encode(y or b"")  # type: bytes
        x += b" " * len_pkt
        x = x[:len_pkt]
        x = b"".join(
            struct.pack(
                "!BB",
                0x41 + (b >> 4),
                0x41 + (b & 0xf),
            )
            for b in x
        )
        return b" " + x

    def m2i(self, pkt, x):
        # type: (Optional[Packet], bytes) -> bytes
        x = x[1:].strip(b"\x00")
        return b"".join(map(
            lambda x, y: struct.pack(
                "!B",
                (((x - 1) & 0xf) << 4) + ((y - 1) & 0xf)
            ),
            x[::2], x[1::2]
        )).rstrip(b" ")


class StrLenField(StrField):
    """
    StrField with a length

    :param length_from: a function that returns the size of the string
    :param max_length: max size to use as randval
    """
    __slots__ = ["length_from", "max_length"]
    ON_WIRE_SIZE_UTF16 = True

    def __init__(
            self,
            name,  # type: str
            default,  # type: bytes
            length_from=None,  # type: Optional[Callable[[Packet], int]]
            max_length=None,  # type: Optional[Any]
    ):
        # type: (...) -> None
        super(StrLenField, self).__init__(name, default)
        self.length_from = length_from
        self.max_length = max_length

    def getfield(self, pkt, s):
        # type: (Any, bytes) -> Tuple[bytes, bytes]
        len_pkt = (self.length_from or (lambda x: 0))(pkt)
        if not self.ON_WIRE_SIZE_UTF16:
            len_pkt *= 2
        if len_pkt == 0:
            return s, b""
        return s[len_pkt:], self.m2i(pkt, s[:len_pkt])

    def randval(self):
        # type: () -> RandBin
        return RandBin(RandNum(0, self.max_length or 1200))


class _XStrField(Field[bytes, bytes]):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], bytes) -> str
        if isinstance(x, bytes):
            return bytes_hex(x).decode()
        return super(_XStrField, self).i2repr(pkt, x)


class XStrField(_XStrField, StrField):
    """
    StrField which value is printed as hexadecimal.
    """


class XStrLenField(_XStrField, StrLenField):
    """
    StrLenField which value is printed as hexadecimal.
    """


class XStrFixedLenField(_XStrField, StrFixedLenField):
    """
    StrFixedLenField which value is printed as hexadecimal.
    """


class XLEStrLenField(XStrLenField):
    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[bytes]) -> bytes
        if not x:
            return b""
        return x[:: -1]

    def m2i(self, pkt, x):
        # type: (Optional[Packet], bytes) -> bytes
        return x[:: -1]


class StrLenFieldUtf16(StrLenField, StrFieldUtf16):
    pass


class StrLenEnumField(_StrEnumField, StrLenField):
    __slots__ = ["enum"]

    def __init__(
            self,
            name,  # type: str
            default,  # type: bytes
            enum=None,  # type: Optional[Dict[str, str]]
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        StrLenField.__init__(self, name, default, **kwargs)
        self.enum = enum


class BoundStrLenField(StrLenField):
    __slots__ = ["minlen", "maxlen"]

    def __init__(
            self,
            name,  # type: str
            default,  # type: bytes
            minlen=0,  # type: int
            maxlen=255,  # type: int
            length_from=None  # type: Optional[Callable[[Packet], int]]
    ):
        # type: (...) -> None
        StrLenField.__init__(self, name, default, length_from=length_from)
        self.minlen = minlen
        self.maxlen = maxlen

    def randval(self):
        # type: () -> RandBin
        return RandBin(RandNum(self.minlen, self.maxlen))


class FieldListField(Field[List[Any], List[Any]]):
    __slots__ = ["field", "count_from", "length_from", "max_count"]
    islist = 1

    def __init__(
            self,
            name,  # type: str
            default,  # type: Optional[List[AnyField]]
            field,  # type: AnyField
            length_from=None,  # type: Optional[Callable[[Packet], int]]
            count_from=None,  # type: Optional[Callable[[Packet], int]]
            max_count=None,  # type: Optional[int]
    ):
        # type: (...) -> None
        if default is None:
            default = []  # Create a new list for each instance
        self.field = field
        Field.__init__(self, name, default)
        self.count_from = count_from
        self.length_from = length_from
        self.max_count = max_count

    def i2count(self, pkt, val):
        # type: (Optional[Packet], List[Any]) -> int
        if isinstance(val, list):
            return len(val)
        return 1

    def i2len(self, pkt, val):
        # type: (Packet, List[Any]) -> int
        return int(sum(self.field.i2len(pkt, v) for v in val))

    def any2i(self, pkt, x):
        # type: (Optional[Packet], List[Any]) -> List[Any]
        if not isinstance(x, list):
            return [self.field.any2i(pkt, x)]
        else:
            return [self.field.any2i(pkt, e) for e in x]

    def i2repr(self,
               pkt,  # type: Optional[Packet]
               x,  # type: List[Any]
               ):
        # type: (...) -> str
        return "[%s]" % ", ".join(self.field.i2repr(pkt, v) for v in x)

    def addfield(self,
                 pkt,  # type: Packet
                 s,  # type: bytes
                 val,  # type: Optional[List[Any]]
                 ):
        # type: (...) -> bytes
        val = self.i2m(pkt, val)
        for v in val:
            s = self.field.addfield(pkt, s, v)
        return s

    def getfield(self,
                 pkt,  # type: Packet
                 s,  # type: bytes
                 ):
        # type: (...) -> Any
        c = len_pkt = None
        if self.length_from is not None:
            len_pkt = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)

        val = []
        ret = b""
        if len_pkt is not None:
            s, ret = s[:len_pkt], s[len_pkt:]

        while s:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            s, v = self.field.getfield(pkt, s)
            val.append(v)
            if len(val) > (self.max_count or conf.max_list_count):
                raise MaximumItemsCount(
                    "Maximum amount of items reached in FieldListField: %s "
                    "(defaults to conf.max_list_count)"
                    % (self.max_count or conf.max_list_count)
                )

        if isinstance(s, tuple):
            s, bn = s
            return (s + ret, bn), val
        else:
            return s + ret, val


class FieldLenField(Field[int, int]):
    __slots__ = ["length_of", "count_of", "adjust"]

    def __init__(
            self,
            name,  # type: str
            default,  # type: Optional[Any]
            length_of=None,  # type: Optional[str]
            fmt="H",  # type: str
            count_of=None,  # type: Optional[str]
            adjust=lambda pkt, x: x,  # type: Callable[[Packet, int], int]
    ):
        # type: (...) -> None
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[int]) -> int
        if x is None and pkt is not None:
            if self.length_of is not None:
                fld, fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
            elif self.count_of is not None:
                fld, fval = pkt.getfield_and_val(self.count_of)
                f = fld.i2count(pkt, fval)
            else:
                raise ValueError(
                    "Field should have either length_of or count_of"
                )
            x = self.adjust(pkt, f)
        elif x is None:
            x = 0
        return x


class StrNullField(StrField):
    DELIMITER = b"\x00"

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[bytes]) -> bytes
        return s + self.i2m(pkt, val) + self.DELIMITER

    def getfield(self,
                 pkt,  # type: Packet
                 s,  # type: bytes
                 ):
        # type: (...) -> Tuple[bytes, bytes]
        len_str = 0
        while True:
            len_str = s.find(self.DELIMITER, len_str)
            if len_str < 0:
                # DELIMITER not found: return empty
                return b"", s
            if len_str % len(self.DELIMITER):
                len_str += 1
            else:
                break
        return s[len_str + len(self.DELIMITER):], self.m2i(pkt, s[:len_str])

    def randval(self):
        # type: () -> RandTermString
        return RandTermString(RandNum(0, 1200), self.DELIMITER)

    def i2len(self, pkt, x):
        # type: (Optional[Packet], Any) -> int
        return super(StrNullField, self).i2len(pkt, x) + 1


class StrNullFieldUtf16(StrNullField, StrFieldUtf16):
    DELIMITER = b"\x00\x00"


class StrStopField(StrField):
    __slots__ = ["stop", "additional"]

    def __init__(self, name, default, stop, additional=0):
        # type: (str, str, bytes, int) -> None
        Field.__init__(self, name, default)
        self.stop = stop
        self.additional = additional

    def getfield(self, pkt, s):
        # type: (Optional[Packet], bytes) -> Tuple[bytes, bytes]
        len_str = s.find(self.stop)
        if len_str < 0:
            return b"", s
        len_str += len(self.stop) + self.additional
        return s[len_str:], s[:len_str]

    def randval(self):
        # type: () -> RandTermString
        return RandTermString(RandNum(0, 1200), self.stop)


class LenField(Field[int, int]):
    """
    If None, will be filled with the size of the payload
    """
    __slots__ = ["adjust"]

    def __init__(self, name, default, fmt="H", adjust=lambda x: x):
        # type: (str, Optional[Any], str, Callable[[int], int]) -> None
        Field.__init__(self, name, default, fmt)
        self.adjust = adjust

    def i2m(self,
            pkt,  # type: Optional[Packet]
            x,  # type: Optional[int]
            ):
        # type: (...) -> int
        if x is None:
            x = 0
            if pkt is not None:
                x = self.adjust(len(pkt.payload))
        return x


class BCDFloatField(Field[float, int]):
    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[float]) -> int
        if x is None:
            return 0
        return int(256 * x)

    def m2i(self, pkt, x):
        # type: (Optional[Packet], int) -> float
        return x / 256.0


class _BitField(Field[I, int]):
    """
    Field to handle bits.

    :param name: name of the field
    :param default: default value
    :param size: size (in bits). If negative, Low endian
    :param tot_size: size of the total group of bits (in bytes) the bitfield
                     is in. If negative, Low endian.
    :param end_tot_size: same but for the BitField ending a group.

    Example - normal usage::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             A             |               B               | C |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                                 Fig. TestPacket

        class TestPacket(Packet):
            fields_desc = [
                BitField("a", 0, 14),
                BitField("b", 0, 16),
                BitField("c", 0, 2),
            ]

    Example - Low endian stored as 16 bits on the network::

        x x x x x x x x x x x x x x x x
        a [b] [   c   ] [      a      ]

        Will first get reversed during dissecion:

        x x x x x x x x x x x x x x x x
        [      a        ] [b] [   c   ]

        class TestPacket(Packet):
            fields_desc = [
                BitField("a", 0, 9, tot_size=-2),
                BitField("b", 0, 2),
                BitField("c", 0, 5, end_tot_size=-2)
            ]

    """
    __slots__ = ["rev", "size", "tot_size", "end_tot_size"]

    def __init__(self, name, default, size,
                 tot_size=0, end_tot_size=0):
        # type: (str, Optional[I], int, int, int) -> None
        Field.__init__(self, name, default)
        if callable(size):
            size = size(self)
        self.rev = size < 0 or tot_size < 0 or end_tot_size < 0
        self.size = abs(size)
        if not tot_size:
            tot_size = self.size // 8
        self.tot_size = abs(tot_size)
        if not end_tot_size:
            end_tot_size = self.size // 8
        self.end_tot_size = abs(end_tot_size)
        # Fields always have a round sz except BitField
        # so to keep it simple, we'll ignore it here.
        self.sz = self.size / 8.  # type: ignore

    # We need to # type: ignore a few things because of how special
    # BitField is
    def addfield(self,  # type: ignore
                 pkt,  # type: Packet
                 s,  # type: Union[Tuple[bytes, int, int], bytes]
                 ival,  # type: I
                 ):
        # type: (...) -> Union[Tuple[bytes, int, int], bytes]
        val = self.i2m(pkt, ival)
        if isinstance(s, tuple):
            s, bitsdone, v = s
        else:
            bitsdone = 0
            v = 0
        v <<= self.size
        v |= val & ((1 << self.size) - 1)
        bitsdone += self.size
        while bitsdone >= 8:
            bitsdone -= 8
            s = s + struct.pack("!B", v >> bitsdone)
            v &= (1 << bitsdone) - 1
        if bitsdone:
            return s, bitsdone, v
        else:
            # Apply LE if necessary
            if self.rev and self.end_tot_size > 1:
                s = s[:-self.end_tot_size] + s[-self.end_tot_size:][::-1]
            return s

    def getfield(self,  # type: ignore
                 pkt,  # type: Packet
                 s,  # type: Union[Tuple[bytes, int], bytes]
                 ):
        # type: (...) -> Union[Tuple[Tuple[bytes, int], I], Tuple[bytes, I]]  # noqa: E501
        if isinstance(s, tuple):
            s, bn = s
        else:
            bn = 0
            # Apply LE if necessary
            if self.rev and self.tot_size > 1:
                s = s[:self.tot_size][::-1] + s[self.tot_size:]

        # we don't want to process all the string
        nb_bytes = (self.size + bn - 1) // 8 + 1
        w = s[:nb_bytes]

        # split the substring byte by byte
        _bytes = struct.unpack('!%dB' % nb_bytes, w)

        b = 0
        for c in range(nb_bytes):
            b |= int(_bytes[c]) << (nb_bytes - c - 1) * 8

        # get rid of high order bits
        b &= (1 << (nb_bytes * 8 - bn)) - 1

        # remove low order bits
        b = b >> (nb_bytes * 8 - self.size - bn)

        bn += self.size
        s = s[bn // 8:]
        bn = bn % 8
        b2 = self.m2i(pkt, b)
        if bn:
            return (s, bn), b2
        else:
            return s, b2

    def randval(self):
        # type: () -> RandNum
        return RandNum(0, 2**self.size - 1)

    def i2len(self, pkt, x):  # type: ignore
        # type: (Optional[Packet], Optional[float]) -> float
        return float(self.size) / 8


class BitField(_BitField[int]):
    __doc__ = _BitField.__doc__


class BitLenField(BitField):
    __slots__ = ["length_from"]

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[int]
                 length_from  # type: Callable[[Packet], int]
                 ):
        # type: (...) -> None
        self.length_from = length_from
        super(BitLenField, self).__init__(name, default, 0)

    def getfield(self,  # type: ignore
                 pkt,  # type: Packet
                 s,  # type: Union[Tuple[bytes, int], bytes]
                 ):
        # type: (...) -> Union[Tuple[Tuple[bytes, int], int], Tuple[bytes, int]]  # noqa: E501
        self.size = self.length_from(pkt)
        return super(BitLenField, self).getfield(pkt, s)

    def addfield(self,  # type: ignore
                 pkt,  # type: Packet
                 s,  # type: Union[Tuple[bytes, int, int], bytes]
                 val  # type: int
                 ):
        # type: (...) -> Union[Tuple[bytes, int, int], bytes]
        self.size = self.length_from(pkt)
        return super(BitLenField, self).addfield(pkt, s, val)


class BitFieldLenField(BitField):
    __slots__ = ["length_of", "count_of", "adjust", "tot_size", "end_tot_size"]

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[int]
                 size,  # type: int
                 length_of=None,  # type: Optional[Union[Callable[[Optional[Packet]], int], str]]  # noqa: E501
                 count_of=None,  # type: Optional[str]
                 adjust=lambda pkt, x: x,  # type: Callable[[Optional[Packet], int], int]  # noqa: E501
                 tot_size=0,  # type: int
                 end_tot_size=0,  # type: int
                 ):
        # type: (...) -> None
        super(BitFieldLenField, self).__init__(name, default, size,
                                               tot_size, end_tot_size)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[Any]) -> int
        return FieldLenField.i2m(self, pkt, x)  # type: ignore


class XBitField(BitField):
    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        return lhex(self.i2h(pkt, x))


class _EnumField(Field[Union[List[I], I], I]):
    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[I]
                 enum,  # type: Union[Dict[I, str], Dict[str, I], List[str], DADict[I, str], Type[Enum], Tuple[Callable[[I], str], Callable[[str], I]]]  # noqa: E501
                 fmt="H",  # type: str
                 ):
        # type: (...) -> None
        """ Initializes enum fields.

        @param name:    name of this field
        @param default: default value of this field
        @param enum:    either an enum, a dict or a tuple of two callables.
                        Dict keys are the internal values, while the dict
                        values are the user-friendly representations. If the
                        tuple is provided, the first callable receives the
                        internal value as parameter and returns the
                        user-friendly representation and the second callable
                        does the converse. The first callable may return None
                        to default to a literal string (repr()) representation.
        @param fmt:     struct.pack format used to parse and serialize the
                        internal value from and to machine representation.
        """
        if isinstance(enum, ObservableDict):
            cast(ObservableDict, enum).observe(self)

        if isinstance(enum, tuple):
            self.i2s_cb = enum[0]  # type: Optional[Callable[[I], str]]
            self.s2i_cb = enum[1]  # type: Optional[Callable[[str], I]]
            self.i2s = None  # type: Optional[Dict[I, str]]
            self.s2i = None  # type: Optional[Dict[str, I]]
        elif isinstance(enum, type) and issubclass(enum, Enum):
            # Python's Enum
            i2s = self.i2s = {}
            s2i = self.s2i = {}
            self.i2s_cb = None
            self.s2i_cb = None
            names = [x.name for x in enum]
            for n in names:
                value = enum[n].value
                i2s[value] = n
                s2i[n] = value
        else:
            i2s = self.i2s = {}
            s2i = self.s2i = {}
            self.i2s_cb = None
            self.s2i_cb = None
            keys = []  # type: List[I]
            if isinstance(enum, list):
                keys = list(range(len(enum)))  # type: ignore
            elif isinstance(enum, DADict):
                keys = enum.keys()
            else:
                keys = list(enum)  # type: ignore
                if any(isinstance(x, str) for x in keys):
                    i2s, s2i = s2i, i2s  # type: ignore
            for k in keys:
                value = cast(str, enum[k])  # type: ignore
                i2s[k] = value
                s2i[value] = k
        Field.__init__(self, name, default, fmt)

    def any2i_one(self, pkt, x):
        # type: (Optional[Packet], Any) -> I
        if isinstance(x, Enum):
            return cast(I, x.value)
        elif isinstance(x, str):
            if self.s2i:
                x = self.s2i[x]
            elif self.s2i_cb:
                x = self.s2i_cb(x)
        return cast(I, x)

    def _i2repr(self, pkt, x):
        # type: (Optional[Packet], I) -> str
        return repr(x)

    def i2repr_one(self, pkt, x):
        # type: (Optional[Packet], I) -> str
        if self not in conf.noenum and not isinstance(x, VolatileValue):
            if self.i2s:
                try:
                    return self.i2s[x]
                except KeyError:
                    pass
            elif self.i2s_cb:
                ret = self.i2s_cb(x)
                if ret is not None:
                    return ret
        return self._i2repr(pkt, x)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> Union[I, List[I]]
        if isinstance(x, list):
            return [self.any2i_one(pkt, z) for z in x]
        else:
            return self.any2i_one(pkt, x)

    def i2repr(self, pkt, x):  # type: ignore
        # type: (Optional[Packet], Any) -> Union[List[str], str]
        if isinstance(x, list):
            return [self.i2repr_one(pkt, z) for z in x]
        else:
            return self.i2repr_one(pkt, x)

    def notify_set(self, enum, key, value):
        # type: (ObservableDict, I, str) -> None
        ks = "0x%x" if isinstance(key, int) else "%s"
        log_runtime.debug(
            "At %s: Change to %s at " + ks, self, value, key
        )
        if self.i2s is not None and self.s2i is not None:
            self.i2s[key] = value
            self.s2i[value] = key

    def notify_del(self, enum, key):
        # type: (ObservableDict, I) -> None
        ks = "0x%x" if isinstance(key, int) else "%s"
        log_runtime.debug("At %s: Delete value at " + ks, self, key)
        if self.i2s is not None and self.s2i is not None:
            value = self.i2s[key]
            del self.i2s[key]
            del self.s2i[value]


class EnumField(_EnumField[I]):
    __slots__ = ["i2s", "s2i", "s2i_cb", "i2s_cb"]


class CharEnumField(EnumField[str]):
    def __init__(self,
                 name,  # type: str
                 default,  # type: str
                 enum,  # type: Union[Dict[str, str], Tuple[Callable[[str], str], Callable[[str], str]]]  # noqa: E501
                 fmt="1s",  # type: str
                 ):
        # type: (...) -> None
        super(CharEnumField, self).__init__(name, default, enum, fmt)
        if self.i2s is not None:
            k = list(self.i2s)
            if k and len(k[0]) != 1:
                self.i2s, self.s2i = self.s2i, self.i2s

    def any2i_one(self, pkt, x):
        # type: (Optional[Packet], str) -> str
        if len(x) != 1:
            if self.s2i:
                x = self.s2i[x]
            elif self.s2i_cb:
                x = self.s2i_cb(x)
        return x


class BitEnumField(_BitField[Union[List[int], int]], _EnumField[int]):
    __slots__ = EnumField.__slots__

    def __init__(self, name, default, size, enum, **kwargs):
        # type: (str, Optional[int], int, Dict[int, str], **Any) -> None
        _EnumField.__init__(self, name, default, enum)
        _BitField.__init__(self, name, default, size, **kwargs)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> Union[List[int], int]
        return _EnumField.any2i(self, pkt, x)

    def i2repr(self,
               pkt,  # type: Optional[Packet]
               x,  # type: Union[List[int], int]
               ):
        # type: (...) -> Any
        return _EnumField.i2repr(self, pkt, x)


class BitLenEnumField(BitLenField, _EnumField[int]):
    __slots__ = EnumField.__slots__

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[int]
                 length_from,  # type: Callable[[Packet], int]
                 enum,  # type: Dict[int, str]
                 **kwargs,  # type: Any
                 ):
        # type: (...) -> None
        _EnumField.__init__(self, name, default, enum)
        BitLenField.__init__(self, name, default, length_from, **kwargs)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> int
        return _EnumField.any2i(self, pkt, x)  # type: ignore

    def i2repr(self,
               pkt,  # type: Optional[Packet]
               x,  # type: Union[List[int], int]
               ):
        # type: (...) -> Any
        return _EnumField.i2repr(self, pkt, x)


class ShortEnumField(EnumField[int]):
    __slots__ = EnumField.__slots__

    def __init__(self,
                 name,  # type: str
                 default,  # type: int
                 enum,  # type: Union[Dict[int, str], Dict[str, int], Tuple[Callable[[int], str], Callable[[str], int]], DADict[int, str]]  # noqa: E501
                 ):
        # type: (...) -> None
        super(ShortEnumField, self).__init__(name, default, enum, "H")


class LEShortEnumField(EnumField[int]):
    def __init__(self, name, default, enum):
        # type: (str, int, Union[Dict[int, str], List[str]]) -> None
        super(LEShortEnumField, self).__init__(name, default, enum, "<H")


class LongEnumField(EnumField[int]):
    def __init__(self, name, default, enum):
        # type: (str, int, Union[Dict[int, str], List[str]]) -> None
        super(LongEnumField, self).__init__(name, default, enum, "Q")


class LELongEnumField(EnumField[int]):
    def __init__(self, name, default, enum):
        # type: (str, int, Union[Dict[int, str], List[str]]) -> None
        super(LELongEnumField, self).__init__(name, default, enum, "<Q")


class ByteEnumField(EnumField[int]):
    def __init__(self, name, default, enum):
        # type: (str, Optional[int], Dict[int, str]) -> None
        super(ByteEnumField, self).__init__(name, default, enum, "B")


class XByteEnumField(ByteEnumField):
    def i2repr_one(self, pkt, x):
        # type: (Optional[Packet], int) -> str
        if self not in conf.noenum and not isinstance(x, VolatileValue):
            if self.i2s:
                try:
                    return self.i2s[x]
                except KeyError:
                    pass
            elif self.i2s_cb:
                ret = self.i2s_cb(x)
                if ret is not None:
                    return ret
        return lhex(x)


class IntEnumField(EnumField[int]):
    def __init__(self, name, default, enum):
        # type: (str, Optional[int], Dict[int, str]) -> None
        super(IntEnumField, self).__init__(name, default, enum, "I")


class SignedIntEnumField(EnumField[int]):
    def __init__(self, name, default, enum):
        # type: (str, Optional[int], Dict[int, str]) -> None
        super(SignedIntEnumField, self).__init__(name, default, enum, "i")


class LEIntEnumField(EnumField[int]):
    def __init__(self, name, default, enum):
        # type: (str, int, Dict[int, str]) -> None
        super(LEIntEnumField, self).__init__(name, default, enum, "<I")


class XShortEnumField(ShortEnumField):
    def _i2repr(self, pkt, x):
        # type: (Optional[Packet], Any) -> str
        return lhex(x)


class LE3BytesEnumField(LEThreeBytesField, _EnumField[int]):
    __slots__ = EnumField.__slots__

    def __init__(self, name, default, enum):
        # type: (str, Optional[int], Dict[int, str]) -> None
        _EnumField.__init__(self, name, default, enum)
        LEThreeBytesField.__init__(self, name, default)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> int
        return _EnumField.any2i(self, pkt, x)  # type: ignore

    def i2repr(self, pkt, x):  # type: ignore
        # type: (Optional[Packet], Any) -> Union[List[str], str]
        return _EnumField.i2repr(self, pkt, x)


class XLE3BytesEnumField(LE3BytesEnumField):
    def _i2repr(self, pkt, x):
        # type: (Optional[Packet], Any) -> str
        return lhex(x)


class _MultiEnumField(_EnumField[I]):
    def __init__(self,
                 name,  # type: str
                 default,  # type: int
                 enum,  # type: Dict[I, Dict[I, str]]
                 depends_on,  # type: Callable[[Optional[Packet]], I]
                 fmt="H"  # type: str
                 ):
        # type: (...) -> None

        self.depends_on = depends_on
        self.i2s_multi = enum
        self.s2i_multi = {}  # type: Dict[I, Dict[str, I]]
        self.s2i_all = {}  # type: Dict[str, I]
        for m in enum:
            s2i = {}  # type: Dict[str, I]
            self.s2i_multi[m] = s2i
            for k, v in enum[m].items():
                s2i[v] = k
                self.s2i_all[v] = k
        Field.__init__(self, name, default, fmt)

    def any2i_one(self, pkt, x):
        # type: (Optional[Packet], Any) -> I
        if isinstance(x, str):
            v = self.depends_on(pkt)
            if v in self.s2i_multi:
                s2i = self.s2i_multi[v]
                if x in s2i:
                    return s2i[x]
            return self.s2i_all[x]
        return cast(I, x)

    def i2repr_one(self, pkt, x):
        # type: (Optional[Packet], I) -> str
        v = self.depends_on(pkt)
        if isinstance(v, VolatileValue):
            return repr(v)
        if v in self.i2s_multi:
            return str(self.i2s_multi[v].get(x, x))
        return str(x)


class MultiEnumField(_MultiEnumField[int], EnumField[int]):
    __slots__ = ["depends_on", "i2s_multi", "s2i_multi", "s2i_all"]


class BitMultiEnumField(_BitField[Union[List[int], int]],
                        _MultiEnumField[int]):
    __slots__ = EnumField.__slots__ + MultiEnumField.__slots__

    def __init__(
            self,
            name,  # type: str
            default,  # type: int
            size,  # type: int
            enum,  # type: Dict[int, Dict[int, str]]
            depends_on  # type: Callable[[Optional[Packet]], int]
    ):
        # type: (...) -> None
        _MultiEnumField.__init__(self, name, default, enum, depends_on)
        self.rev = size < 0
        self.size = abs(size)
        self.sz = self.size / 8.  # type: ignore

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> Union[List[int], int]
        return _MultiEnumField[int].any2i(
            self,  # type: ignore
            pkt,
            x
        )

    def i2repr(  # type: ignore
            self,
            pkt,  # type: Optional[Packet]
            x  # type: Union[List[int], int]
    ):
        # type: (...) -> Union[str, List[str]]
        return _MultiEnumField[int].i2repr(
            self,  # type: ignore
            pkt,
            x
        )


class ByteEnumKeysField(ByteEnumField):
    """ByteEnumField that picks valid values when fuzzed. """

    def randval(self):
        # type: () -> RandEnumKeys
        return RandEnumKeys(self.i2s or {})


class ShortEnumKeysField(ShortEnumField):
    """ShortEnumField that picks valid values when fuzzed. """

    def randval(self):
        # type: () -> RandEnumKeys
        return RandEnumKeys(self.i2s or {})


class IntEnumKeysField(IntEnumField):
    """IntEnumField that picks valid values when fuzzed. """

    def randval(self):
        # type: () -> RandEnumKeys
        return RandEnumKeys(self.i2s or {})


# Little endian fixed length field


class LEFieldLenField(FieldLenField):
    def __init__(
            self,
            name,  # type: str
            default,  # type: Optional[Any]
            length_of=None,  # type: Optional[str]
            fmt="<H",  # type: str
            count_of=None,  # type: Optional[str]
            adjust=lambda pkt, x: x,  # type: Callable[[Packet, int], int]
    ):
        # type: (...) -> None
        FieldLenField.__init__(
            self, name, default,
            length_of=length_of,
            fmt=fmt,
            count_of=count_of,
            adjust=adjust
        )


class FlagValueIter(object):

    __slots__ = ["flagvalue", "cursor"]

    def __init__(self, flagvalue):
        # type: (FlagValue) -> None
        self.flagvalue = flagvalue
        self.cursor = 0

    def __iter__(self):
        # type: () -> FlagValueIter
        return self

    def __next__(self):
        # type: () -> str
        x = int(self.flagvalue)
        x >>= self.cursor
        while x:
            self.cursor += 1
            if x & 1:
                return self.flagvalue.names[self.cursor - 1]
            x >>= 1
        raise StopIteration

    next = __next__


class FlagValue(object):
    __slots__ = ["value", "names", "multi"]

    def _fixvalue(self, value):
        # type: (Any) -> int
        if not value:
            return 0
        if isinstance(value, str):
            value = value.split('+') if self.multi else list(value)
        if isinstance(value, list):
            y = 0
            for i in value:
                y |= 1 << self.names.index(i)
            value = y
        return int(value)

    def __init__(self, value, names):
        # type: (Union[List[str], int, str], Union[List[str], str]) -> None
        self.multi = isinstance(names, list)
        self.names = names
        self.value = self._fixvalue(value)

    def __hash__(self):
        # type: () -> int
        return hash(self.value)

    def __int__(self):
        # type: () -> int
        return self.value

    def __eq__(self, other):
        # type: (Any) -> bool
        return self.value == self._fixvalue(other)

    def __lt__(self, other):
        # type: (Any) -> bool
        return self.value < self._fixvalue(other)

    def __le__(self, other):
        # type: (Any) -> bool
        return self.value <= self._fixvalue(other)

    def __gt__(self, other):
        # type: (Any) -> bool
        return self.value > self._fixvalue(other)

    def __ge__(self, other):
        # type: (Any) -> bool
        return self.value >= self._fixvalue(other)

    def __ne__(self, other):
        # type: (Any) -> bool
        return self.value != self._fixvalue(other)

    def __and__(self, other):
        # type: (int) -> FlagValue
        return self.__class__(self.value & self._fixvalue(other), self.names)
    __rand__ = __and__

    def __or__(self, other):
        # type: (int) -> FlagValue
        return self.__class__(self.value | self._fixvalue(other), self.names)
    __ror__ = __or__
    __add__ = __or__  # + is an alias for |

    def __sub__(self, other):
        # type: (int) -> FlagValue
        return self.__class__(
            self.value & (2 ** len(self.names) - 1 - self._fixvalue(other)),
            self.names
        )

    def __xor__(self, other):
        # type: (int) -> FlagValue
        return self.__class__(self.value ^ self._fixvalue(other), self.names)

    def __lshift__(self, other):
        # type: (int) -> int
        return self.value << self._fixvalue(other)

    def __rshift__(self, other):
        # type: (int) -> int
        return self.value >> self._fixvalue(other)

    def __nonzero__(self):
        # type: () -> bool
        return bool(self.value)
    __bool__ = __nonzero__

    def flagrepr(self):
        # type: () -> str
        warnings.warn(
            "obj.flagrepr() is obsolete. Use str(obj) instead.",
            DeprecationWarning
        )
        return str(self)

    def __str__(self):
        # type: () -> str
        i = 0
        r = []
        x = int(self)
        while x:
            if x & 1:
                try:
                    name = self.names[i]
                except IndexError:
                    name = "?"
                r.append(name)
            i += 1
            x >>= 1
        return ("+" if self.multi else "").join(r)

    def __iter__(self):
        # type: () -> FlagValueIter
        return FlagValueIter(self)

    def __repr__(self):
        # type: () -> str
        return "<Flag %d (%s)>" % (self, self)

    def __deepcopy__(self, memo):
        # type: (Dict[Any, Any]) -> FlagValue
        return self.__class__(int(self), self.names)

    def __getattr__(self, attr):
        # type: (str) -> Any
        if attr in self.__slots__:
            return super(FlagValue, self).__getattribute__(attr)
        try:
            if self.multi:
                return bool((2 ** self.names.index(attr)) & int(self))
            return all(bool((2 ** self.names.index(flag)) & int(self))
                       for flag in attr)
        except ValueError:
            if '_' in attr:
                try:
                    return self.__getattr__(attr.replace('_', '-'))
                except AttributeError:
                    pass
            return super(FlagValue, self).__getattribute__(attr)

    def __setattr__(self, attr, value):
        # type: (str, Union[List[str], int, str]) -> None
        if attr == "value" and not isinstance(value, int):
            raise ValueError(value)
        if attr in self.__slots__:
            return super(FlagValue, self).__setattr__(attr, value)
        if attr in self.names:
            if value:
                self.value |= (2 ** self.names.index(attr))
            else:
                self.value &= ~(2 ** self.names.index(attr))
        else:
            return super(FlagValue, self).__setattr__(attr, value)

    def copy(self):
        # type: () -> FlagValue
        return self.__class__(self.value, self.names)


class FlagsField(_BitField[Optional[Union[int, FlagValue]]]):
    """ Handle Flag type field

   Make sure all your flags have a label

   Example (list):
       >>> from scapy.packet import Packet
       >>> class FlagsTest(Packet):
               fields_desc = [FlagsField("flags", 0, 8, ["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7"])]  # noqa: E501
       >>> FlagsTest(flags=9).show2()
       ###[ FlagsTest ]###
         flags     = f0+f3

    Example (str):
       >>> from scapy.packet import Packet
       >>> class TCPTest(Packet):
               fields_desc = [
                   BitField("reserved", 0, 7),
                   FlagsField("flags", 0x2, 9, "FSRPAUECN")
               ]
       >>> TCPTest(flags=3).show2()
       ###[ FlagsTest ]###
         reserved  = 0
         flags     = FS

    Example (dict):
       >>> from scapy.packet import Packet
       >>> class FlagsTest2(Packet):
               fields_desc = [
                   FlagsField("flags", 0x2, 16, {
                       0x0001: "A",
                       0x0008: "B",
                   })
               ]

   :param name: field's name
   :param default: default value for the field
   :param size: number of bits in the field (in bits). if negative, LE
   :param names: (list or str or dict) label for each flag
       If it's a str or a list, the least Significant Bit tag's name
       is written first.
   """
    ismutable = True
    __slots__ = ["names"]

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[Union[int, FlagValue]]
                 size,  # type: int
                 names,     # type: Union[List[str], str, Dict[int, str]]
                 **kwargs   # type: Any
                 ):
        # type: (...) -> None
        # Convert the dict to a list
        if isinstance(names, dict):
            tmp = ["bit_%d" % i for i in range(abs(size))]
            for i, v in names.items():
                tmp[int(math.floor(math.log(i, 2)))] = v
            names = tmp
        # Store the names as str or list
        self.names = names
        super(FlagsField, self).__init__(name, default, size, **kwargs)

    def _fixup_val(self, x):
        # type: (Any) -> Optional[FlagValue]
        """Returns a FlagValue instance when needed. Internal method, to be
used in *2i() and i2*() methods.

        """
        if isinstance(x, (FlagValue, VolatileValue)):
            return x  # type: ignore
        if x is None:
            return None
        return FlagValue(x, self.names)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> Optional[FlagValue]
        return self._fixup_val(super(FlagsField, self).any2i(pkt, x))

    def m2i(self, pkt, x):
        # type: (Optional[Packet], int) -> Optional[FlagValue]
        return self._fixup_val(super(FlagsField, self).m2i(pkt, x))

    def i2h(self, pkt, x):
        # type: (Optional[Packet], Any) -> Optional[FlagValue]
        return self._fixup_val(super(FlagsField, self).i2h(pkt, x))

    def i2repr(self,
               pkt,  # type: Optional[Packet]
               x,  # type: Any
               ):
        # type: (...) -> str
        if isinstance(x, (list, tuple)):
            return repr(type(x)(
                "None" if v is None else str(self._fixup_val(v)) for v in x
            ))
        return "None" if x is None else str(self._fixup_val(x))


MultiFlagsEntry = collections.namedtuple('MultiFlagsEntry', ['short', 'long'])


class MultiFlagsField(_BitField[Set[str]]):
    __slots__ = FlagsField.__slots__ + ["depends_on"]

    def __init__(self,
                 name,  # type: str
                 default,  # type: Set[str]
                 size,  # type: int
                 names,  # type: Dict[int, Dict[int, MultiFlagsEntry]]
                 depends_on,  # type: Callable[[Optional[Packet]], int]
                 ):
        # type: (...) -> None
        self.names = names
        self.depends_on = depends_on
        super(MultiFlagsField, self).__init__(name, default, size)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> Set[str]
        if not isinstance(x, (set, int)):
            raise ValueError('set expected')

        if pkt is not None:
            if isinstance(x, int):
                return self.m2i(pkt, x)
            else:
                v = self.depends_on(pkt)
                if v is not None:
                    assert v in self.names, 'invalid dependency'
                    these_names = self.names[v]
                    s = set()
                    for i in x:
                        for val in these_names.values():
                            if val.short == i:
                                s.add(i)
                                break
                        else:
                            assert False, 'Unknown flag "{}" with this dependency'.format(i)  # noqa: E501
                            continue
                    return s
        if isinstance(x, int):
            return set()
        return x

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[Set[str]]) -> int
        v = self.depends_on(pkt)
        these_names = self.names.get(v, {})

        r = 0
        if x is None:
            return r
        for flag_set in x:
            for i, val in these_names.items():
                if val.short == flag_set:
                    r |= 1 << i
                    break
            else:
                r |= 1 << int(flag_set[len('bit '):])
        return r

    def m2i(self, pkt, x):
        # type: (Optional[Packet], int) -> Set[str]
        v = self.depends_on(pkt)
        these_names = self.names.get(v, {})

        r = set()
        i = 0
        while x:
            if x & 1:
                if i in these_names:
                    r.add(these_names[i].short)
                else:
                    r.add('bit {}'.format(i))
            x >>= 1
            i += 1
        return r

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], Set[str]) -> str
        v = self.depends_on(pkt)
        these_names = self.names.get(v, {})

        r = set()
        for flag_set in x:
            for i in these_names.values():
                if i.short == flag_set:
                    r.add("{} ({})".format(i.long, i.short))
                    break
            else:
                r.add(flag_set)
        return repr(r)


class FixedPointField(BitField):
    __slots__ = ['frac_bits']

    def __init__(self, name, default, size, frac_bits=16):
        # type: (str, int, int, int) -> None
        self.frac_bits = frac_bits
        super(FixedPointField, self).__init__(name, default, size)

    def any2i(self, pkt, val):
        # type: (Optional[Packet], Optional[float]) -> Optional[int]
        if val is None:
            return val
        ival = int(val)
        fract = int((val - ival) * 2**self.frac_bits)
        return (ival << self.frac_bits) | fract

    def i2h(self, pkt, val):
        # type: (Optional[Packet], Optional[int]) -> Optional[EDecimal]
        # A bit of trickery to get precise floats
        if val is None:
            return val
        int_part = val >> self.frac_bits
        pw = 2.0**self.frac_bits
        frac_part = EDecimal(val & (1 << self.frac_bits) - 1)
        frac_part /= pw  # type: ignore
        return int_part + frac_part.normalize(int(math.log10(pw)))

    def i2repr(self, pkt, val):
        # type: (Optional[Packet], int) -> str
        return str(self.i2h(pkt, val))


# Base class for IPv4 and IPv6 Prefixes inspired by IPField and IP6Field.
# Machine values are encoded in a multiple of wordbytes bytes.
class _IPPrefixFieldBase(Field[Tuple[str, int], Tuple[bytes, int]]):
    __slots__ = ["wordbytes", "maxbytes", "aton", "ntoa", "length_from"]

    def __init__(
            self,
            name,  # type: str
            default,  # type: Tuple[str, int]
            wordbytes,  # type: int
            maxbytes,  # type: int
            aton,  # type: Callable[..., Any]
            ntoa,  # type: Callable[..., Any]
            length_from=None  # type: Optional[Callable[[Packet], int]]
    ):
        # type: (...) -> None
        self.wordbytes = wordbytes
        self.maxbytes = maxbytes
        self.aton = aton
        self.ntoa = ntoa
        Field.__init__(self, name, default, "%is" % self.maxbytes)
        if length_from is None:
            length_from = lambda x: 0
        self.length_from = length_from

    def _numbytes(self, pfxlen):
        # type: (int) -> int
        wbits = self.wordbytes * 8
        return ((pfxlen + (wbits - 1)) // wbits) * self.wordbytes

    def h2i(self, pkt, x):
        # type: (Optional[Packet], str) -> Tuple[str, int]
        # "fc00:1::1/64" -> ("fc00:1::1", 64)
        [pfx, pfxlen] = x.split('/')
        self.aton(pfx)  # check for validity
        return (pfx, int(pfxlen))

    def i2h(self, pkt, x):
        # type: (Optional[Packet], Tuple[str, int]) -> str
        # ("fc00:1::1", 64) -> "fc00:1::1/64"
        (pfx, pfxlen) = x
        return "%s/%i" % (pfx, pfxlen)

    def i2m(self,
            pkt,  # type: Optional[Packet]
            x  # type: Optional[Tuple[str, int]]
            ):
        # type: (...) -> Tuple[bytes, int]
        # ("fc00:1::1", 64) -> (b"\xfc\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 64)  # noqa: E501
        if x is None:
            pfx, pfxlen = "", 0
        else:
            (pfx, pfxlen) = x
        s = self.aton(pfx)
        return (s[:self._numbytes(pfxlen)], pfxlen)

    def m2i(self, pkt, x):
        # type: (Optional[Packet], Tuple[bytes, int]) -> Tuple[str, int]
        # (b"\xfc\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 64) -> ("fc00:1::1", 64)  # noqa: E501
        (s, pfxlen) = x

        if len(s) < self.maxbytes:
            s = s + (b"\0" * (self.maxbytes - len(s)))
        return (self.ntoa(s), pfxlen)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Optional[Any]) -> Tuple[str, int]
        if x is None:
            return (self.ntoa(b"\0" * self.maxbytes), 1)

        return self.h2i(pkt, x)

    def i2len(self, pkt, x):
        # type: (Packet, Tuple[str, int]) -> int
        (_, pfxlen) = x
        return pfxlen

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[Tuple[str, int]]) -> bytes
        (rawpfx, pfxlen) = self.i2m(pkt, val)
        fmt = "!%is" % self._numbytes(pfxlen)
        return s + struct.pack(fmt, rawpfx)

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, Tuple[str, int]]
        pfxlen = self.length_from(pkt)
        numbytes = self._numbytes(pfxlen)
        fmt = "!%is" % numbytes
        return s[numbytes:], self.m2i(pkt, (struct.unpack(fmt, s[:numbytes])[0], pfxlen))  # noqa: E501


class IPPrefixField(_IPPrefixFieldBase):
    def __init__(
            self,
            name,  # type: str
            default,  # type: Tuple[str, int]
            wordbytes=1,  # type: int
            length_from=None  # type: Optional[Callable[[Packet], int]]
    ):
        _IPPrefixFieldBase.__init__(
            self,
            name,
            default,
            wordbytes,
            4,
            inet_aton,
            inet_ntoa,
            length_from
        )


class IP6PrefixField(_IPPrefixFieldBase):
    def __init__(
            self,
            name,  # type: str
            default,  # type: Tuple[str, int]
            wordbytes=1,  # type: int
            length_from=None  # type: Optional[Callable[[Packet], int]]
    ):
        # type: (...) -> None
        _IPPrefixFieldBase.__init__(
            self,
            name,
            default,
            wordbytes,
            16,
            lambda a: inet_pton(socket.AF_INET6, a),
            lambda n: inet_ntop(socket.AF_INET6, n),
            length_from
        )


class UTCTimeField(Field[float, int]):
    __slots__ = ["epoch", "delta", "strf",
                 "use_msec", "use_micro", "use_nano", "custom_scaling"]

    def __init__(self,
                 name,  # type: str
                 default,  # type: int
                 use_msec=False,  # type: bool
                 use_micro=False,  # type: bool
                 use_nano=False,  # type: bool
                 epoch=None,  # type: Optional[Tuple[int, int, int, int, int, int, int, int, int]]  # noqa: E501
                 strf="%a, %d %b %Y %H:%M:%S %z",  # type: str
                 custom_scaling=None,  # type: Optional[int]
                 fmt="I"  # type: str
                 ):
        # type: (...) -> None
        Field.__init__(self, name, default, fmt=fmt)
        mk_epoch = EPOCH if epoch is None else calendar.timegm(epoch)
        self.epoch = mk_epoch
        self.delta = mk_epoch - EPOCH
        self.strf = strf
        self.use_msec = use_msec
        self.use_micro = use_micro
        self.use_nano = use_nano
        self.custom_scaling = custom_scaling

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], float) -> str
        if x is None:
            x = time.time() - self.delta
        elif self.use_msec:
            x = x / 1e3
        elif self.use_micro:
            x = x / 1e6
        elif self.use_nano:
            x = x / 1e9
        elif self.custom_scaling:
            x = x / self.custom_scaling
        x += self.delta
        # To make negative timestamps work on all plateforms (e.g. Windows),
        # we need a trick.
        t = (
            datetime.datetime(1970, 1, 1) +
            datetime.timedelta(seconds=x)
        ).strftime(self.strf)
        return "%s (%d)" % (t, int(x))

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[float]) -> int
        if x is None:
            x = time.time() - self.delta
            if self.use_msec:
                x = x * 1e3
            elif self.use_micro:
                x = x * 1e6
            elif self.use_nano:
                x = x * 1e9
            elif self.custom_scaling:
                x = x * self.custom_scaling
            return int(x)
        return int(x)


class SecondsIntField(Field[float, int]):
    __slots__ = ["use_msec", "use_micro", "use_nano"]

    def __init__(self, name, default,
                 use_msec=False,
                 use_micro=False,
                 use_nano=False):
        # type: (str, int, bool, bool, bool) -> None
        Field.__init__(self, name, default, "I")
        self.use_msec = use_msec
        self.use_micro = use_micro
        self.use_nano = use_nano

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], Optional[float]) -> str
        if x is None:
            y = 0  # type: Union[int, float]
        elif self.use_msec:
            y = x / 1e3
        elif self.use_micro:
            y = x / 1e6
        elif self.use_nano:
            y = x / 1e9
        else:
            y = x
        return "%s sec" % y


class _ScalingField(object):
    def __init__(self,
                 name,  # type: str
                 default,  # type: float
                 scaling=1,  # type: Union[int, float]
                 unit="",  # type: str
                 offset=0,  # type: Union[int, float]
                 ndigits=3,  # type: int
                 fmt="B",  # type: str
                 ):
        # type: (...) -> None
        self.scaling = scaling
        self.unit = unit
        self.offset = offset
        self.ndigits = ndigits
        Field.__init__(self, name, default, fmt)  # type: ignore

    def i2m(self,
            pkt,  # type: Optional[Packet]
            x  # type: Optional[Union[int, float]]
            ):
        # type: (...) -> Union[int, float]
        if x is None:
            x = 0
        x = (x - self.offset) / self.scaling
        if isinstance(x, float) and self.fmt[-1] != "f":  # type: ignore
            x = int(round(x))
        return x

    def m2i(self, pkt, x):
        # type: (Optional[Packet], Union[int, float]) -> Union[int, float]
        x = x * self.scaling + self.offset
        if isinstance(x, float) and self.fmt[-1] != "f":  # type: ignore
            x = round(x, self.ndigits)
        return x

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> Union[int, float]
        if isinstance(x, (str, bytes)):
            x = struct.unpack(self.fmt, bytes_encode(x))[0]  # type: ignore
            x = self.m2i(pkt, x)
        if not isinstance(x, (int, float)):
            raise ValueError("Unknown type")
        return x

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], Union[int, float]) -> str
        return "%s %s" % (
            self.i2h(pkt, x),  # type: ignore
            self.unit
        )

    def randval(self):
        # type: () -> RandFloat
        value = Field.randval(self)  # type: ignore
        if value is not None:
            min_val = round(value.min * self.scaling + self.offset,
                            self.ndigits)
            max_val = round(value.max * self.scaling + self.offset,
                            self.ndigits)

            return RandFloat(min(min_val, max_val), max(min_val, max_val))


class ScalingField(_ScalingField,
                   Field[Union[int, float], Union[int, float]]):
    """ Handle physical values which are scaled and/or offset for communication

       Example:
           >>> from scapy.packet import Packet
           >>> class ScalingFieldTest(Packet):
                   fields_desc = [ScalingField('data', 0, scaling=0.1, offset=-1, unit='mV')]  # noqa: E501
           >>> ScalingFieldTest(data=10).show2()
           ###[ ScalingFieldTest ]###
             data= 10.0 mV
           >>> hexdump(ScalingFieldTest(data=10))
           0000  6E                                               n
           >>> hexdump(ScalingFieldTest(data=b"\x6D"))
           0000  6D                                               m
           >>> ScalingFieldTest(data=b"\x6D").show2()
           ###[ ScalingFieldTest ]###
             data= 9.9 mV

        bytes(ScalingFieldTest(...)) will produce 0x6E in this example.
        0x6E is 110 (decimal). This is calculated through the scaling factor
        and the offset. "data" was set to 10, which means, we want to transfer
        the physical value 10 mV. To calculate the value, which has to be
        sent on the bus, the offset has to subtracted and the scaling has to be
        applied by division through the scaling factor.
        bytes = (data - offset) / scaling
        bytes = ( 10  -  (-1) ) /    0.1
        bytes =  110 = 0x6E

        If you want to force a certain internal value, you can assign a byte-
        string to the field (data=b"\x6D"). If a string of a bytes object is
        given to the field, no internal value conversion will be applied

       :param name: field's name
       :param default: default value for the field
       :param scaling: scaling factor for the internal value conversion
       :param unit: string for the unit representation of the internal value
       :param offset: value to offset the internal value during conversion
       :param ndigits: number of fractional digits for the internal conversion
       :param fmt: struct.pack format used to parse and serialize the internal value from and to machine representation # noqa: E501
       """


class BitScalingField(_ScalingField, BitField):  # type: ignore
    """
    A ScalingField that is a BitField
    """

    def __init__(self, name, default, size, *args, **kwargs):
        # type: (str, int, int, *Any, **Any) -> None
        _ScalingField.__init__(self, name, default, *args, **kwargs)
        BitField.__init__(self, name, default, size)  # type: ignore


class OUIField(X3BytesField):
    """
    A field designed to carry a OUI (3 bytes)
    """

    def i2repr(self, pkt, val):
        # type: (Optional[Packet], int) -> str
        by_val = struct.pack("!I", val or 0)[1:]
        oui = str2mac(by_val + b"\0" * 3)[:8]
        if conf.manufdb:
            fancy = conf.manufdb._get_manuf(oui)
            if fancy != oui:
                return "%s (%s)" % (fancy, oui)
        return oui


class UUIDField(Field[UUID, bytes]):
    """Field for UUID storage, wrapping Python's uuid.UUID type.

    The internal storage format of this field is ``uuid.UUID`` from the Python
    standard library.

    There are three formats (``uuid_fmt``) for this field type:

    * ``FORMAT_BE`` (default): the UUID is six fields in big-endian byte order,
      per RFC 4122.

      This format is used by DHCPv6 (RFC 6355) and most network protocols.

    * ``FORMAT_LE``: the UUID is six fields, with ``time_low``, ``time_mid``
      and ``time_high_version`` in little-endian byte order. This *doesn't*
      change the arrangement of the fields from RFC 4122.

      This format is used by Microsoft's COM/OLE libraries.

    * ``FORMAT_REV``: the UUID is a single 128-bit integer in little-endian
      byte order. This *changes the arrangement* of the fields.

      This format is used by Bluetooth Low Energy.

    Note: You should use the constants here.

    The "human encoding" of this field supports a number of different input
    formats, and wraps Python's ``uuid.UUID`` library appropriately:

    * Given a bytearray, bytes or str of 16 bytes, this class decodes UUIDs in
      wire format.

    * Given a bytearray, bytes or str of other lengths, this delegates to
      ``uuid.UUID`` the Python standard library. This supports a number of
      different encoding options -- see the Python standard library
      documentation for more details.

    * Given an int or long, presumed to be a 128-bit integer to pass to
      ``uuid.UUID``.

    * Given a tuple:

      * Tuples of 11 integers are treated as having the last 6 integers forming
        the ``node`` field, and are merged before being passed as a tuple of 6
        integers to ``uuid.UUID``.

      * Otherwise, the tuple is passed as the ``fields`` parameter to
        ``uuid.UUID`` directly without modification.

        ``uuid.UUID`` expects a tuple of 6 integers.

    Other types (such as ``uuid.UUID``) are passed through.
    """

    __slots__ = ["uuid_fmt"]

    FORMAT_BE = 0
    FORMAT_LE = 1
    FORMAT_REV = 2

    # Change this when we get new formats
    FORMATS = (FORMAT_BE, FORMAT_LE, FORMAT_REV)

    def __init__(self, name, default, uuid_fmt=FORMAT_BE):
        # type: (str, Optional[int], int) -> None
        self.uuid_fmt = uuid_fmt
        self._check_uuid_fmt()
        Field.__init__(self, name, default, "16s")

    def _check_uuid_fmt(self):
        # type: () -> None
        """Checks .uuid_fmt, and raises an exception if it is not valid."""
        if self.uuid_fmt not in UUIDField.FORMATS:
            raise FieldValueRangeException(
                "Unsupported uuid_fmt ({})".format(self.uuid_fmt))

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[UUID]) -> bytes
        self._check_uuid_fmt()
        if x is None:
            return b'\0' * 16
        if self.uuid_fmt == UUIDField.FORMAT_BE:
            return x.bytes
        elif self.uuid_fmt == UUIDField.FORMAT_LE:
            return x.bytes_le
        elif self.uuid_fmt == UUIDField.FORMAT_REV:
            return x.bytes[::-1]
        else:
            raise FieldAttributeException("Unknown fmt")

    def m2i(self,
            pkt,  # type: Optional[Packet]
            x,  # type: bytes
            ):
        # type: (...) -> UUID
        self._check_uuid_fmt()
        if self.uuid_fmt == UUIDField.FORMAT_BE:
            return UUID(bytes=x)
        elif self.uuid_fmt == UUIDField.FORMAT_LE:
            return UUID(bytes_le=x)
        elif self.uuid_fmt == UUIDField.FORMAT_REV:
            return UUID(bytes=x[::-1])
        else:
            raise FieldAttributeException("Unknown fmt")

    def any2i(self,
              pkt,  # type: Optional[Packet]
              x  # type: Any  # noqa: E501
              ):
        # type: (...) -> Optional[UUID]
        # Python's uuid doesn't handle bytearray, so convert to an immutable
        # type first.
        if isinstance(x, bytearray):
            x = bytes_encode(x)

        if isinstance(x, int):
            u = UUID(int=x)
        elif isinstance(x, tuple):
            if len(x) == 11:
                # For compatibility with dce_rpc: this packs into a tuple where
                # elements 7..10 are the 48-bit node ID.
                node = 0
                for i in x[5:]:
                    node = (node << 8) | i

                x = (x[0], x[1], x[2], x[3], x[4], node)

            u = UUID(fields=x)
        elif isinstance(x, (str, bytes)):
            if len(x) == 16:
                # Raw bytes
                u = self.m2i(pkt, bytes_encode(x))
            else:
                u = UUID(plain_str(x))
        elif isinstance(x, (UUID, RandUUID)):
            u = cast(UUID, x)
        else:
            return None
        return u

    @staticmethod
    def randval():
        # type: () -> RandUUID
        return RandUUID()


class UUIDEnumField(UUIDField, _EnumField[UUID]):
    __slots__ = EnumField.__slots__

    def __init__(self, name, default, enum, uuid_fmt=0):
        # type: (str, Optional[int], Any, int) -> None
        _EnumField.__init__(self, name, default, enum, "16s")  # type: ignore
        UUIDField.__init__(self, name, default, uuid_fmt=uuid_fmt)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> UUID
        return _EnumField.any2i(self, pkt, x)  # type: ignore

    def i2repr(self,
               pkt,  # type: Optional[Packet]
               x,  # type: UUID
               ):
        # type: (...) -> Any
        return _EnumField.i2repr(self, pkt, x)


class BitExtendedField(Field[Optional[int], bytes]):
    """
    Bit Extended Field

    This type of field has a variable number of bytes. Each byte is defined
    as follows:
    - 7 bits of data
    - 1 bit an an extension bit:

      + 0 means it is last byte of the field ("stopping bit")
      + 1 means there is another byte after this one ("forwarding bit")

    To get the actual data, it is necessary to hop the binary data byte per
    byte and to check the extension bit until 0
    """

    __slots__ = ["extension_bit"]

    def prepare_byte(self, x):
        # type: (int) -> int
        # Moves the forwarding bit to the LSB
        x = int(x)
        fx_bit = (x & 2**self.extension_bit) >> self.extension_bit
        lsb_bits = x & 2**self.extension_bit - 1
        msb_bits = x >> (self.extension_bit + 1)
        x = (msb_bits << (self.extension_bit + 1)) + (lsb_bits << 1) + fx_bit
        return x

    def str2extended(self, x=b""):
        # type: (bytes) -> Tuple[bytes, Optional[int]]
        # For convenience, we reorder the byte so that the forwarding
        # bit is always the LSB. We then apply the same algorithm
        # whatever the real forwarding bit position

        # First bit is the stopping bit at zero
        bits = 0b0
        end = None

        # We retrieve 7 bits.
        # If "forwarding bit" is 1 then we continue on another byte
        i = 0
        for c in bytearray(x):
            c = self.prepare_byte(c)
            bits = bits << 7 | (int(c) >> 1)
            if not int(c) & 0b1:
                end = x[i + 1:]
                break
            i = i + 1
        if end is None:
            # We reached the end of the data but there was no
            # "ending bit". This is not normal.
            return b"", None
        else:
            return end, bits

    def extended2str(self, x):
        # type: (Optional[int]) -> bytes
        if x is None:
            return b""
        x = int(x)
        s = []
        LSByte = True
        FX_Missing = True
        bits = 0b0
        i = 0
        while (x > 0 or FX_Missing):
            if i == 8:
                # End of byte
                i = 0
                s.append(bits)
                bits = 0b0
                FX_Missing = True
            else:
                if i % 8 == self.extension_bit:
                    # This is extension bit
                    if LSByte:
                        bits = bits | 0b0 << i
                        LSByte = False
                    else:
                        bits = bits | 0b1 << i
                    FX_Missing = False
                else:
                    bits = bits | (x & 0b1) << i
                    x = x >> 1
                # Still some bits
                i = i + 1
        s.append(bits)

        result = "".encode()
        for x in s[:: -1]:
            result = result + struct.pack(">B", x)
        return result

    def __init__(self, name, default, extension_bit):
        # type: (str, Optional[Any], int) -> None
        Field.__init__(self, name, default, "B")
        self.extension_bit = extension_bit

    def i2m(self, pkt, x):
        # type: (Optional[Any], Optional[int]) -> bytes
        return self.extended2str(x)

    def m2i(self, pkt, x):
        # type: (Optional[Any], bytes) -> Optional[int]
        return self.str2extended(x)[1]

    def addfield(self, pkt, s, val):
        # type: (Optional[Packet], bytes, Optional[int]) -> bytes
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        # type: (Optional[Any], bytes) -> Tuple[bytes, Optional[int]]
        return self.str2extended(s)


class LSBExtendedField(BitExtendedField):
    # This is a BitExtendedField with the extension bit on LSB
    def __init__(self, name, default):
        # type: (str, Optional[Any]) -> None
        BitExtendedField.__init__(self, name, default, extension_bit=0)


class MSBExtendedField(BitExtendedField):
    # This is a BitExtendedField with the extension bit on MSB
    def __init__(self, name, default):
        # type: (str, Optional[Any]) -> None
        BitExtendedField.__init__(self, name, default, extension_bit=7)
