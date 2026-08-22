# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Packet class

Provides:
 - the default Packet classes
 - binding mechanisms
 - fuzz() method
 - exploration methods: explore() / ls()
"""

from collections import defaultdict

import json
import re
import time
import itertools
import copy
import types
import warnings

from scapy.fields import (
    AnyField,
    BitField,
    ConditionalField,
    Emph,
    EnumField,
    Field,
    FieldListField,
    FlagsField,
    _FieldContainer,
    FlagValue,
    MultiEnumField,
    MultipleTypeField,
    PadField,
    PacketListField,
    RawVal,
    StrField,
)
from scapy.config import conf, _version_checker
from scapy.compat import raw, bytes_encode
from scapy.base_classes import BasePacket, Gen, SetGen, Packet_metaclass, \
    _CanvasDumpExtended
from scapy.interfaces import _GlobInterfaceType
from scapy.volatile import MAGIC_BOUNDARIES, RandField, VolatileValue
from scapy.utils import import_hexcap, tex_escape, colgen, issubtype, \
    pretty_list, EDecimal
from scapy.error import Scapy_Exception, log_runtime, warning
from scapy.libs.test_pyx import PYX

# Typing imports
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Iterator,
    List,
    NoReturn,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    Sequence,
    cast,
)
from scapy.compat import Self

try:
    import pyx
except ImportError:
    pass


_T = TypeVar("_T", Dict[str, Any], Optional[Dict[str, Any]])


class FuzzStates(list):
    """
    The list Packet.prepare_combinations() returns, plus a cursor.

    Packet.forward() has to find the first state whose 'done' is still
    False, and used to look for it from index 0 on every call. A state
    only ever goes from not-done to done, so the finished prefix grows
    monotonically and that scan re-walks it every time - quadratic in the
    state count, paid per case sent (a 210-state stack examined 66.6
    entries per step to reach one live state).

    'first_live' is the index the scan starts at: the finished prefix is
    everything below it. forward() moves it forward as states complete
    and never back, so the scan is O(1) amortised over a run.

    A plain list still works everywhere a FuzzStates does - forward()
    reads the cursor with getattr(states, 'first_live', 0) and skips
    updating it when it isn't there, so a caller that hands over its own
    hand-built list (or a filtered subset, as several tests do) gets
    exactly the old full-scan behaviour rather than an error. Wrap such a
    list in FuzzStates() to get the cursor back.

    The one thing that would break the cursor is a caller setting a
    state's 'done' back to False after forward() has passed it; nothing
    in this fork does that, and prepare_combinations() is the way to get
    a fresh walk.
    """

    def __init__(self, iterable=()):
        # type: (Any) -> None
        super(FuzzStates, self).__init__(iterable)
        self.first_live = 0


class Packet(
    BasePacket,
    _CanvasDumpExtended,
    metaclass=Packet_metaclass
):
    __slots__ = [
        "time", "sent_time", "name",
        "default_fields", "fields", "fieldtype",
        "overload_fields", "overloaded_fields",
        "packetfields",
        "original", "explicit", "raw_packet_cache",
        "raw_packet_cache_fields", "_pkt", "post_transforms",
        "stop_dissection_after",
        # then payload, underlayer and parent
        "payload", "underlayer", "parent",
        "name",
        # used for sr()
        "_answered",
        # used when sniffing
        "direction", "sniffed_on",
        # handle snaplen Vs real length
        "wirelen",
        "comments",
        "process_information"
    ]
    name = None
    fields_desc = []  # type: ClassVar[List[AnyField]]
    deprecated_fields = {}  # type: Dict[str, Tuple[str, str]]
    overload_fields = {}  # type: Dict[Type[Packet], Dict[str, Any]]
    payload_guess = []  # type: List[Tuple[Dict[str, Any], Type[Packet]]]
    show_indent = 1
    show_summary = True
    match_subclass = False
    class_dont_cache = {}  # type: Dict[Type[Packet], bool]
    class_packetfields = {}  # type: Dict[Type[Packet], Any]
    class_default_fields = {}  # type: Dict[Type[Packet], Dict[str, Any]]
    class_default_fields_ref = {}  # type: Dict[Type[Packet], List[str]]
    class_fieldtype = {}  # type: Dict[Type[Packet], Dict[str, AnyField]]  # noqa: E501

    @classmethod
    def from_hexcap(cls):
        # type: (Type[Packet]) -> Packet
        return cls(import_hexcap())

    @classmethod
    def upper_bonds(self):
        # type: () -> None
        for fval, upper in self.payload_guess:
            print(
                "%-20s  %s" % (
                    upper.__name__,
                    ", ".join("%-12s" % ("%s=%r" % i) for i in fval.items()),
                )
            )

    @classmethod
    def lower_bonds(self):
        # type: () -> None
        for lower, fval in self._overload_fields.items():
            print(
                "%-20s  %s" % (
                    lower.__name__,
                    ", ".join("%-12s" % ("%s=%r" % i) for i in fval.items()),
                )
            )

    def __init__(self,
                 _pkt=b"",  # type: Union[bytes, bytearray]
                 post_transform=None,  # type: Any
                 _internal=0,  # type: int
                 _underlayer=None,  # type: Optional[Packet]
                 _parent=None,  # type: Optional[Packet]
                 stop_dissection_after=None,  # type: Optional[Type[Packet]]
                 **fields  # type: Any
                 ):
        # type: (...) -> None
        self.time = 0.0 if _internal else time.time()  # type: Union[EDecimal, float]
        self.sent_time = None  # type: Union[EDecimal, float, None]
        self.name = (self.__class__.__name__
                     if self._name is None else
                     self._name)
        self.default_fields = {}  # type: Dict[str, Any]
        self.overload_fields = self._overload_fields
        self.overloaded_fields = {}  # type: Dict[str, Any]
        self.fields = {}  # type: Dict[str, Any]
        self.fieldtype = {}  # type: Dict[str, AnyField]
        self.packetfields = []  # type: List[AnyField]
        self.payload = NoPayload()  # type: Packet
        self.init_fields(bool(_pkt))
        self.underlayer = _underlayer
        self.parent = _parent
        if isinstance(_pkt, bytearray):
            _pkt = bytes(_pkt)
        self.original = _pkt
        self.explicit = 0
        self.raw_packet_cache = None  # type: Optional[bytes]
        self.raw_packet_cache_fields = None  # type: Optional[Dict[str, Any]]  # noqa: E501
        self.wirelen = None  # type: Optional[int]
        self.direction = None  # type: Optional[int]
        self.sniffed_on = None  # type: Optional[_GlobInterfaceType]
        self.comments = None  # type: Optional[List[bytes]]
        self.process_information = None  # type: Optional[Dict[str, Any]]
        self.stop_dissection_after = stop_dissection_after
        if _pkt:
            self.dissect(_pkt)
            if not _internal:
                self.dissection_done(self)
        # We use this strange initialization so that the fields
        # are initialized in their declaration order.
        # It is required to always support MultipleTypeField
        for field in self.fields_desc:
            fname = field.name
            try:
                value = fields.pop(fname)
            except KeyError:
                continue
            self.fields[fname] = value if isinstance(value, RawVal) else \
                self.get_field(fname).any2i(self, value)
        # The remaining fields are unknown
        for fname in fields:
            if fname in self.deprecated_fields:
                # Resolve deprecated fields
                value = fields[fname]
                fname = self._resolve_alias(fname)
                self.fields[fname] = value if isinstance(value, RawVal) else \
                    self.get_field(fname).any2i(self, value)
                continue
            raise AttributeError(fname)
        if isinstance(post_transform, list):
            self.post_transforms = post_transform
        elif post_transform is None:
            self.post_transforms = []
        else:
            self.post_transforms = [post_transform]

    _PickleType = Tuple[
        Union[EDecimal, float],
        Optional[Union[EDecimal, float, None]],
        Optional[int],
        Optional[_GlobInterfaceType],
        Optional[int],
        Optional[bytes],
    ]
    _PickleStateType = Union[_PickleType, Dict[str, Any]]

    @property
    def comment(self):
        # type: () -> Optional[bytes]
        """Get the comment of the packet"""
        if self.comments and len(self.comments):
            return self.comments[0]
        return None

    @comment.setter
    def comment(self, value):
        # type: (Optional[bytes]) -> None
        """
        Set the comment of the packet.
        If value is None, it will clear the comments.
        """
        if value is not None:
            self.comments = [value]
        else:
            self.comments = None

    @classmethod
    def _rebuild_pkt(cls, raw_packet):
        # type: (Type[Packet], bytes) -> Packet
        """Helper used by pickle to reconstruct Packet from raw bytes."""
        return cls(raw_packet)

    def __reduce__(self):
        # type: () -> Tuple[Any, ...]
        """Used by pickling methods"""
        state = {
            "pickle_state_version": 2,
            "time": self.time,
            "sent_time": self.sent_time,
            "direction": self.direction,
            "sniffed_on": self.sniffed_on,
            "wirelen": self.wirelen,
            # Keep both keys for compatibility with historical/transition code.
            "comment": self.comment,
            "comments": self.comments,
        }
        extra_slots = {}
        for attr in type(self).__all_slots__ - set(Packet.__slots__):
            if hasattr(self, attr):
                extra_slots[attr] = getattr(self, attr)
        if extra_slots:
            state["extra_slots"] = extra_slots  # type: ignore
        return (type(self)._rebuild_pkt, (self.build(),), state)

    def __setstate__(self, state):
        # type: (Packet._PickleStateType) -> Packet
        """Rebuild state using pickable methods"""
        # Legacy format: tuple produced by older Packet.__reduce__.
        if isinstance(state, tuple):
            self.time = state[0]
            self.sent_time = state[1]
            self.direction = state[2]
            self.sniffed_on = state[3]
            self.wirelen = state[4]
            self.comment = state[5]
            return self

        # New format: versioned dict metadata.
        self.time = state.get("time", self.time)
        self.sent_time = state.get("sent_time", self.sent_time)
        self.direction = state.get("direction", self.direction)
        self.sniffed_on = state.get("sniffed_on", self.sniffed_on)
        self.wirelen = state.get("wirelen", self.wirelen)

        if "comments" in state:
            self.comments = state["comments"]
        elif "comment" in state:
            self.comment = state["comment"]

        extra_slots = state.get("extra_slots", {})
        if isinstance(extra_slots, dict):
            for attr, value in extra_slots.items():
                # Only restore known subclass slots; ignore stale/unknown entries.
                if attr in type(self).__all_slots__ and attr not in Packet.__slots__:
                    try:
                        setattr(self, attr, value)
                    except AttributeError:
                        pass
        return self

    def __deepcopy__(self,
                     memo,  # type: Any
                     ):
        # type: (...) -> Packet
        """Used by copy.deepcopy"""
        return self.copy()

    def init_fields(self, for_dissect_only=False):
        # type: (bool) -> None
        """
        Initialize each fields of the fields_desc dict
        """

        if self.class_dont_cache.get(self.__class__, False):
            self.do_init_fields(self.fields_desc)
        else:
            self.do_init_cached_fields(for_dissect_only=for_dissect_only)

    def do_init_fields(self,
                       flist,  # type: Sequence[AnyField]
                       ):
        # type: (...) -> None
        """
        Initialize each fields of the fields_desc dict
        """
        default_fields = {}
        for f in flist:
            default_fields[f.name] = copy.deepcopy(f.default)
            self.fieldtype[f.name] = f
            if f.holds_packets:
                self.packetfields.append(f)
        # We set default_fields last to avoid race issues
        self.default_fields = default_fields

    def do_init_cached_fields(self, for_dissect_only=False):
        # type: (bool) -> None
        """
        Initialize each fields of the fields_desc dict, or use the cached
        fields information
        """

        cls_name = self.__class__

        # Build the fields information
        default_fields = Packet.class_default_fields.get(cls_name)
        if default_fields is None:
            self.prepare_cached_fields(self.fields_desc)
            default_fields = Packet.class_default_fields.get(cls_name)

        # Use fields information from cache
        if default_fields:
            self.default_fields = default_fields
            self.fieldtype = Packet.class_fieldtype[cls_name]
            self.packetfields = Packet.class_packetfields[cls_name]

            # Optimization: no need for references when only dissecting.
            if for_dissect_only:
                return

            # Deepcopy default references
            for fname in Packet.class_default_fields_ref[cls_name]:
                value = self.default_fields[fname]
                try:
                    self.fields[fname] = value.copy()
                except AttributeError:
                    # Python 2.7 - list only
                    self.fields[fname] = value[:]

    def prepare_cached_fields(self, flist):
        # type: (Sequence[AnyField]) -> None
        """
        Prepare the cached fields of the fields_desc dict
        """

        cls_name = self.__class__

        # Fields cache initialization
        if not flist:
            return

        class_default_fields = dict()
        class_default_fields_ref = list()
        class_fieldtype = dict()
        class_packetfields = list()

        # Fields initialization
        for f in flist:
            if isinstance(f, MultipleTypeField):
                # Abort
                self.class_dont_cache[cls_name] = True
                self.do_init_fields(self.fields_desc)
                return

            class_default_fields[f.name] = copy.deepcopy(f.default)
            class_fieldtype[f.name] = f
            if f.holds_packets:
                class_packetfields.append(f)

            # Remember references
            if isinstance(f.default, (list, dict, set, RandField, Packet)):
                class_default_fields_ref.append(f.name)

        # Apply
        Packet.class_default_fields_ref[cls_name] = class_default_fields_ref
        Packet.class_fieldtype[cls_name] = class_fieldtype
        Packet.class_packetfields[cls_name] = class_packetfields
        # Last to avoid racing issues
        Packet.class_default_fields[cls_name] = class_default_fields

    def dissection_done(self, pkt):
        # type: (Packet) -> None
        """DEV: will be called after a dissection is completed"""
        self.post_dissection(pkt)
        self.payload.dissection_done(pkt)

    def post_dissection(self, pkt):
        # type: (Packet) -> None
        """DEV: is called after the dissection of the whole packet"""
        pass

    def get_field(self, fld):
        # type: (str) -> AnyField
        """DEV: returns the field instance from the name of the field"""
        return self.fieldtype[fld]

    def add_payload(self, payload):
        # type: (Union[Packet, bytes]) -> None
        if payload is None:
            return
        elif not isinstance(self.payload, NoPayload):
            self.payload.add_payload(payload)
        else:
            if isinstance(payload, Packet):
                self.payload = payload
                payload.add_underlayer(self)
                for t in self.aliastypes:
                    if t in payload.overload_fields:
                        self.overloaded_fields = payload.overload_fields[t]
                        break
            elif isinstance(payload, (bytes, str, bytearray, memoryview)):
                self.payload = conf.raw_layer(load=bytes_encode(payload))
            else:
                raise TypeError("payload must be 'Packet', 'bytes', 'str', 'bytearray', or 'memoryview', not [%s]" % repr(payload))  # noqa: E501

    def remove_payload(self):
        # type: () -> None
        self.payload.remove_underlayer(self)
        self.payload = NoPayload()
        self.overloaded_fields = {}

    def add_underlayer(self, underlayer):
        # type: (Packet) -> None
        self.underlayer = underlayer

    def remove_underlayer(self, other):
        # type: (Packet) -> None
        self.underlayer = None

    def add_parent(self, parent):
        # type: (Packet) -> None
        """Set packet parent.
        When packet is an element in PacketListField, parent field would
        point to the list owner packet."""
        self.parent = parent

    def remove_parent(self, other):
        # type: (Packet) -> None
        """Remove packet parent.
        When packet is an element in PacketListField, parent field would
        point to the list owner packet."""
        self.parent = None

    def copy(self) -> Self:
        """Returns a deep copy of the instance."""
        clone = self.__class__()
        clone.fields = self.copy_fields_dict(self.fields)
        clone.default_fields = self.copy_fields_dict(self.default_fields)
        clone.overloaded_fields = self.overloaded_fields.copy()
        clone.underlayer = self.underlayer
        clone.parent = self.parent
        clone.explicit = self.explicit
        clone.raw_packet_cache = self.raw_packet_cache
        clone.raw_packet_cache_fields = self.copy_fields_dict(
            self.raw_packet_cache_fields
        )
        clone.wirelen = self.wirelen
        clone.post_transforms = self.post_transforms[:]
        clone.payload = self.payload.copy()
        clone.payload.add_underlayer(clone)
        clone.time = self.time
        clone.comments = self.comments
        clone.direction = self.direction
        clone.sniffed_on = self.sniffed_on
        return clone

    def _resolve_alias(self, attr):
        # type: (str) -> str
        new_attr, version = self.deprecated_fields[attr]
        warnings.warn(
            "%s has been deprecated in favor of %s since %s !" % (
                attr, new_attr, version
            ), DeprecationWarning
        )
        return new_attr

    def getfieldval(self, attr):
        # type: (str) -> Any
        if self.deprecated_fields and attr in self.deprecated_fields:
            attr = self._resolve_alias(attr)
        try:
            return self.fields[attr]
        except KeyError:
            pass
        try:
            return self.overloaded_fields[attr]
        except KeyError:
            pass
        try:
            return self.default_fields[attr]
        except KeyError:
            pass
        return self.payload.getfieldval(attr)

    def getfield_and_val(self, attr):
        # type: (str) -> Tuple[AnyField, Any]
        if self.deprecated_fields and attr in self.deprecated_fields:
            attr = self._resolve_alias(attr)
        if attr in self.fields:
            return self.get_field(attr), self.fields[attr]
        if attr in self.overloaded_fields:
            return self.get_field(attr), self.overloaded_fields[attr]
        if attr in self.default_fields:
            return self.get_field(attr), self.default_fields[attr]
        raise ValueError

    def __getattr__(self, attr):
        # type: (str) -> Any
        try:
            fld, v = self.getfield_and_val(attr)
        except ValueError:
            return self.payload.__getattr__(attr)
        if fld is not None:
            return v if isinstance(v, RawVal) else fld.i2h(self, v)
        return v

    def setfieldval(self, attr, val):
        # type: (str, Any) -> None
        if self.deprecated_fields and attr in self.deprecated_fields:
            attr = self._resolve_alias(attr)
        if attr in self.default_fields:
            fld = self.get_field(attr)
            if fld is None:
                any2i = lambda x, y: y  # type: Callable[..., Any]
            else:
                any2i = fld.any2i
            self.fields[attr] = val if isinstance(val, RawVal) else \
                any2i(self, val)
            self.explicit = 0
            self.raw_packet_cache = None
            self.raw_packet_cache_fields = None
            self.wirelen = None
        elif attr == "payload":
            self.remove_payload()
            self.add_payload(val)
        else:
            self.payload.setfieldval(attr, val)

    def __setattr__(self, attr, val):
        # type: (str, Any) -> None
        if attr in self.__all_slots__:
            return object.__setattr__(self, attr, val)
        try:
            return self.setfieldval(attr, val)
        except AttributeError:
            pass
        return object.__setattr__(self, attr, val)

    def delfieldval(self, attr):
        # type: (str) -> None
        if attr in self.fields:
            del self.fields[attr]
            self.explicit = 0  # in case a default value must be explicit
            self.raw_packet_cache = None
            self.raw_packet_cache_fields = None
            self.wirelen = None
        elif attr in self.default_fields:
            pass
        elif attr == "payload":
            self.remove_payload()
        else:
            self.payload.delfieldval(attr)

    def __delattr__(self, attr):
        # type: (str) -> None
        if attr == "payload":
            return self.remove_payload()
        if attr in self.__all_slots__:
            return object.__delattr__(self, attr)
        try:
            return self.delfieldval(attr)
        except AttributeError:
            pass
        return object.__delattr__(self, attr)

    def _superdir(self):
        # type: () -> Set[str]
        """
        Return a list of slots and methods, including those from subclasses.
        """
        attrs = set()  # type: Set[str]
        cls = self.__class__
        if hasattr(cls, '__all_slots__'):
            attrs.update(cls.__all_slots__)
        for bcls in cls.__mro__:
            if hasattr(bcls, '__dict__'):
                attrs.update(bcls.__dict__)
        return attrs

    def __dir__(self):
        # type: () -> List[str]
        """
        Add fields to tab completion list.
        """
        return sorted(itertools.chain(self._superdir(), self.default_fields))

    def __repr__(self):
        # type: () -> str
        s = ""
        ct = conf.color_theme
        for f in self.fields_desc:
            if isinstance(f, ConditionalField) and not f._evalcond(self):
                continue
            if f.name in self.fields:
                fval = self.fields[f.name]
                if isinstance(fval, (list, dict, set)) and len(fval) == 0:
                    continue
                val = f.i2repr(self, fval)
            elif f.name in self.overloaded_fields:
                fover = self.overloaded_fields[f.name]
                if isinstance(fover, (list, dict, set)) and len(fover) == 0:
                    continue
                val = f.i2repr(self, fover)
            else:
                continue
            if isinstance(f, Emph) or f in conf.emph:
                ncol = ct.emph_field_name
                vcol = ct.emph_field_value
            else:
                ncol = ct.field_name
                vcol = ct.field_value

            s += " %s%s%s" % (ncol(f.name),
                              ct.punct("="),
                              vcol(val))
        return "%s%s %s %s%s%s" % (ct.punct("<"),
                                   ct.layer_name(self.__class__.__name__),
                                   s,
                                   ct.punct("|"),
                                   repr(self.payload),
                                   ct.punct(">"))

    def __str__(self):
        # type: () -> str
        return self.summary()

    def __bytes__(self):
        # type: () -> bytes
        return self.build()

    def __div__(self, other):
        # type: (Any) -> Self
        if isinstance(other, Packet):
            cloneA = self.copy()
            cloneB = other.copy()
            cloneA.add_payload(cloneB)
            return cloneA
        elif isinstance(other, (bytes, str, bytearray, memoryview)):
            return self / conf.raw_layer(load=bytes_encode(other))
        else:
            return other.__rdiv__(self)  # type: ignore
    __truediv__ = __div__

    def __rdiv__(self, other):
        # type: (Any) -> Packet
        if isinstance(other, (bytes, str, bytearray, memoryview)):
            return conf.raw_layer(load=bytes_encode(other)) / self
        else:
            raise TypeError
    __rtruediv__ = __rdiv__

    def __mul__(self, other):
        # type: (Any) -> List[Packet]
        if isinstance(other, int):
            return [self] * other
        else:
            raise TypeError

    def __rmul__(self, other):
        # type: (Any) -> List[Packet]
        return self.__mul__(other)

    def __nonzero__(self):
        # type: () -> bool
        return True
    __bool__ = __nonzero__

    def __len__(self):
        # type: () -> int
        return len(self.__bytes__())

    def copy_field_value(self, fieldname, value):
        # type: (str, Any) -> Any
        return self.get_field(fieldname).do_copy(value)

    def copy_fields_dict(self, fields):
        # type: (_T) -> _T
        if fields is None:
            return None
        return {fname: self.copy_field_value(fname, fval)
                for fname, fval in fields.items()}

    def _raw_packet_cache_field_value(self, fld, val, copy=False):
        # type: (AnyField, Any, bool) -> Optional[Any]
        """Get a value representative of a mutable field to detect changes"""
        if fld.holds_packets:
            # avoid copying whole packets (perf: #GH3894)
            if fld.islist:
                if copy:
                    return [
                        (fld.do_copy(x.fields), x.payload.raw_packet_cache)
                        for x in val
                    ]
                return [
                    (x.fields, x.payload.raw_packet_cache) for x in val
                ]
            else:
                if copy:
                    return (fld.do_copy(val.fields),
                            val.payload.raw_packet_cache)
                return (val.fields, val.payload.raw_packet_cache)
        elif fld.islist or fld.ismutable:
            return fld.do_copy(val) if copy else val
        return None

    def clear_cache(self):
        # type: () -> None
        """Clear the raw packet cache for the field and all its subfields"""
        self.raw_packet_cache = None
        for fname, fval in self.fields.items():
            fld = self.get_field(fname)
            if fld.holds_packets:
                if isinstance(fval, Packet):
                    fval.clear_cache()
                elif isinstance(fval, list):
                    for fsubval in fval:
                        fsubval.clear_cache()
        self.payload.clear_cache()

    def self_build(self):
        # type: () -> bytes
        """
        Create the default layer regarding fields_desc dict
        """
        if self.raw_packet_cache is not None and \
                self.raw_packet_cache_fields is not None:
            for fname, fval in self.raw_packet_cache_fields.items():
                fld, val = self.getfield_and_val(fname)
                if self._raw_packet_cache_field_value(fld, val) != fval:
                    self.raw_packet_cache = None
                    self.raw_packet_cache_fields = None
                    self.wirelen = None
                    break
            if self.raw_packet_cache is not None:
                return self.raw_packet_cache
        p = b""
        for f in self.fields_desc:
            val = self.getfieldval(f.name)
            if isinstance(val, RawVal):
                p += bytes(val)
            else:
                try:
                    p = f.addfield(self, p, val)
                except Exception as ex:
                    try:
                        ex.args = (
                            "While building field '%s': " % f.name +
                            ex.args[0],
                        ) + ex.args[1:]
                    except (AttributeError, IndexError):
                        pass
                    raise ex
        return p

    def do_build_payload(self):
        # type: () -> bytes
        """
        Create the default version of the payload layer

        :return: a string of payload layer
        """
        return self.payload.do_build()

    def do_build(self):
        # type: () -> bytes
        """
        Create the default version of the layer

        :return: a string of the packet with the payload
        """
        if not self.explicit:
            self = next(iter(self))
        pkt = self.self_build()
        for t in self.post_transforms:
            pkt = t(pkt)
        pay = self.do_build_payload()
        if self.raw_packet_cache is None:
            return self.post_build(pkt, pay)
        else:
            return pkt + pay

    def build_padding(self):
        # type: () -> bytes
        return self.payload.build_padding()

    def return_relevant_fields(self, pkt):
        """
        Recursively collect all the fields that we can fuzz
        """
        relevant_fields = []
        
        # If we provided fields in the constrcution, override the default ones
        for field_name in pkt.fields:
            current = pkt.default_fields[field_name]
            if isinstance(current, VolatileValue):
                continue
            if isinstance(current, list) and any(
                isinstance(v, VolatileValue)
                or (isinstance(v, tuple) and any(isinstance(vv, VolatileValue) for vv in v))
                for v in current
            ):
                # A FieldListField whose items were individually fuzzed
                # (e.g. Dot11EltRates.rates), or a named-option-style
                # field whose items' values were individually fuzzed
                # (e.g. DHCP.options via fuzz_current_value()) - don't
                # clobber the fuzzed items with the plain constructor-time
                # value.
                continue
            pkt.default_fields[field_name] = pkt.fields[field_name]

        for field_name in pkt.default_fields:
            if field_name in pkt.overloaded_fields:
                # This is not actually fuzzable, as it gets overloaded
                # print(f"Skipping: {pkt._name}-{field_name}")
                continue

            field = pkt.default_fields[field_name]

            if isinstance(field, list):
                # If the field is a list, see if it has something inside, if it does
                #  go into it
                if len(field) == 0:
                    # Empty list should be skipped
                    continue

                for idx, field_value in enumerate(field):
                    if isinstance(field_value, VolatileValue):
                        # A FieldListField item (e.g. Dot11EltRates.rates) -
                        # fuzz() gives each item its own randval taken from
                        # the field's inner field type, so it's directly
                        # fuzzable without going through a sub-Packet.
                        relevant_fields.append(f"{pkt.name}:{field_name}:{idx}")
                        continue

                    if isinstance(field_value, tuple):
                        # A named-option-style list item (e.g. DHCP.options'
                        # ('requested_addr', <VolatileValue>)) - the tuple
                        # itself isn't fuzzable, but one of its elements is.
                        if any(isinstance(v, VolatileValue) for v in field_value):
                            relevant_fields.append(f"{pkt.name}:{field_name}:{idx}")
                        continue

                    if not isinstance(field_value, Packet):
                        continue

                    for field_in_list_name in field_value.default_fields.keys():
                        field_in_list = field_value.default_fields[field_in_list_name]

                        # Only genuinely fuzzed (VolatileValue) sub-fields are
                        # relevant - anything else is a concrete/unfuzzed
                        # value (NoneType/int/str/bytes/_ScopedIP/BGPORF/a
                        # FlagValue whose ConditionalField gate wasn't met/
                        # RSNCipherSuite/PMKIDListPacket/...). We don't allow
                        # 'list' inside 'list' (at the moment) either.
                        if not isinstance(field_in_list, VolatileValue):
                            continue

                        relevant_fields.append(f"{pkt.name}:{field_name}:{idx}:{field_in_list_name}")

                continue

            if not isinstance(field, VolatileValue):
                # Concrete/unfuzzed value - covers plain NoneType/int/str/
                # bytes/_ScopedIP/BGPORF defaults fuzz() never touched, as
                # well as a FlagValue left concrete because its
                # ConditionalField's condition wasn't met when fuzz() ran
                # (RadioTap.hemuou_per_user_known, Dot11.FCfield2, ...), and
                # RSNCipherSuite/PMKIDListPacket (not yet supported).
                continue

            # print(f"Adding: {pkt.name}-{field_name}")
            relevant_fields.append(f"{pkt.name}:{field_name}")

        if type(pkt.payload).__name__ != 'NoPayload':
            relevant_fields += self.return_relevant_fields(pkt.payload)

        return relevant_fields

    def locate_field(self, pkt, name):
        """ Locate a given field name inside a pkt (recursively) """
        packet_type = name[0:name.index(':')]
        packet_field = name[name.index(':')+1:]
        field_type = "normal"
        field_idx = None
        field_in_list = None

        # Make sure we are in the right place
        if pkt.name == packet_type:
            if ":" in packet_field:
                # There is a subsequent item/value here, it should be the index of 'list'
                field_list = packet_field[packet_field.index(':')+1:]

                # Remove the 'list' part
                packet_field = packet_field[:packet_field.index(':')]

                if ":" in field_list:
                    # A list of sub-Packets: idx:subfield (e.g. IP options)
                    field_type = "list"
                    field_idx = field_list[:field_list.index(':')]
                    field_in_list = field_list[field_list.index(':')+1:]
                else:
                    # A list of raw scalar VolatileValues: idx only
                    #  (e.g. Dot11EltRates.rates)
                    field_type = "list_scalar"
                    field_idx = field_list
                    field_in_list = None

                try:
                    field_idx = int(field_idx)
                except:
                    raise ValueError(f"We expected {field_idx} to be an int ")

                if packet_field not in pkt.default_fields:
                    raise ValueError(f"We are referencing {packet_field} which is not found inside default_fields")

                val = pkt.default_fields[packet_field]
                if not isinstance(val, list):
                    raise ValueError(f"The field {packet_field} isn't a list")

                if field_idx > len(val):
                    raise ValueError(f"The field {packet_field} cannot accomodate {field_idx} index")

            if (packet_field not in pkt.fields and packet_field not in pkt.default_fields):
                raise ValueError(f"Cannot find {packet_field} inside {packet_type}")

            if packet_field in pkt.default_fields:
                if field_type == "list":
                    if field_idx >= len(pkt.default_fields[packet_field]):
                        raise ValueError(f"Shouldn't be None, did we not find the obj? {field_idx=}:{field_in_list=}")

                    item_in_list = pkt.default_fields[packet_field][field_idx]

                    if item_in_list.default_fields[field_in_list] is None:
                        raise ValueError(f"Shouldn't be None, did we not find the obj? {field_idx=}:{field_in_list=}")
                    return (pkt, item_in_list.default_fields[field_in_list])

                if field_type == "list_scalar":
                    if field_idx >= len(pkt.default_fields[packet_field]):
                        raise ValueError(f"Shouldn't be None, did we not find the obj? {field_idx=}")

                    item = pkt.default_fields[packet_field][field_idx]
                    if isinstance(item, tuple):
                        # A named-option-style item (e.g. DHCP.options'
                        # ('requested_addr', <VolatileValue>)) - locate the
                        # VolatileValue element inside it.
                        for v in item:
                            if isinstance(v, VolatileValue):
                                return (pkt, v)
                        raise ValueError(
                            f"No VolatileValue found inside tuple at "
                            f"{packet_field}[{field_idx}]"
                        )

                    return (pkt, item)

                return (pkt, pkt.default_fields[packet_field])

            if packet_field in pkt.fields:
                return (pkt, pkt.fields[packet_field])
            
            raise ValueError("Shouldn't have reached this point")

        return pkt.locate_field(pkt.payload, name)


    def prepare_combinations(
        self,
        complexity: int,
        max_samples_per_field: int = 128,
        boundary_values: bool = False,
    ) -> List:
        """
        Prepare fuzzing by returning a 'states' of fields.

        :param complexity: how many fields are fuzzed together per state
            (as before).
        :param max_samples_per_field: caps how many distinct values a
            single field is sampled at before forward() moves on (replaces
            the previously hardcoded 128). Defaults to 128, matching prior
            behavior exactly for callers that don't pass this.
        :param boundary_values: when True, guarantees each field's exact
            min/max/off-by-one/type-width 'magic' values (0x7F, 0x80, 0xFF,
            ...) are visited at least once, in addition to the normal
            uniform sampling - see Packet._boundary_checkpoints(). Defaults
            to False, so existing callers see no change in the sequence of
            values produced or in combination counts.
        """
        relevant_fields = self.return_relevant_fields(self)

        # If there is more than one field, do a combination, otherwise just put it
        if len(relevant_fields) > 1:
            potential_states = itertools.combinations(relevant_fields, complexity)
        else:
            potential_states = [relevant_fields]

        states = []

        for potential_state in potential_states:
            state = {
                'active': False,
                'done': False,
                'combinations': 0
            }

            fields = []
            for field in potential_state:
                fields.append({
                    'name': field,
                    'done': False,
                    'combinations': 0,
                    'active': False,
                    'max_samples': max_samples_per_field,
                    'boundary_values': boundary_values,
                })

            state['fields'] = fields

            states.append(state)

        # A FuzzStates rather than a plain list: it carries the cursor
        # forward() scans from, so a long walk doesn't re-examine its own
        # finished prefix on every call - see FuzzStates.
        return FuzzStates(states)

    def display_now_fuzzing(self, fields):
        """
        Display the 'now fuzzing' in a nicer way
        """
        fields_fuzzed = []
        for field in fields:
            fields_fuzzed.append(field['name'])

        print(f"Now fuzzing: {', '.join(fields_fuzzed)}")

    def return_active_state(self, states):
        """
        Return the state that is active or 'None'
        """

        # Same cursor as forward() uses: a done state is never active
        # (forward() clears 'active' when it marks one done), so the
        # active state - if there is one - is always at or past it.
        for index in range(getattr(states, 'first_live', 0), len(states)):
            if states[index]['active']:
                return states[index]

        return None

    def initialize_volatile_field(self, field_obj, boundary_values=False,
                                  max_samples=128):
        """
        Set up a VolatileValue so forward() can drive it: state_pos, default,
        min/max all need to be concrete before anything does
        field_obj.state_pos += 1. Used both the first time a field becomes
        part of an active fuzzing state, and whenever
        resync_multiple_type_fields() swaps in a freshly-created
        VolatileValue for a MultipleTypeField mid-run.

        boundary_values=True additionally seeds a queue of edge-case
        checkpoints (see _boundary_checkpoints()) that _advance_state_pos()
        will drain before falling back to uniform jump sampling. Defaults to
        False so existing callers that don't opt in see no behavior change.

        max_samples is the state's max_samples_per_field. Most volatiles get
        their density applied by _advance_state_pos() striding over a fixed
        range, but a volatile that enumerates a list (RandEnumWalk) has to
        apply it when it *builds* that list - striding would drop the very
        values it exists to send - so it's offered the budget here, before
        anything reads its min/max.
        """
        plan_budget = getattr(field_obj, 'plan_budget', None)
        if callable(plan_budget):
            plan_budget(max_samples)

        if hasattr(field_obj, "default"):
            # Some fields have a 'default'
            if type(field_obj.default).__name__ in ['str', 'bytes', 'tuple']:
                # Store the value so we can use it
                field_obj.default = field_obj.default
            elif type(field_obj.default).__name__ == 'int':
                field_obj.state_pos = field_obj.default
            else:
                field_obj.default = None

        # Some fields don't have a 'default', try to use 'min'
        if hasattr(field_obj, "min") and type(field_obj.min).__name__ == 'int':
            field_obj.state_pos = field_obj.min

            if not hasattr(field_obj, "default") or field_obj.default is None:
                # set it to something if it doesn't have a value
                field_obj.default = field_obj.min
        else:
            # Some have nothing
            field_obj.default = 0
            field_obj.min = 0
            field_obj.state_pos = 0

        # RandString has a 'size' rather than max
        if hasattr(field_obj, 'size'):
            if isinstance(field_obj.size, int):
                field_obj.max = field_obj.size
            else:
                field_obj.max = field_obj.size.max

        # Make sure it exists
        if not hasattr(field_obj, 'max'):
            field_obj.max = field_obj.min

        field_obj._pending_checkpoints = (
            self._boundary_checkpoints(field_obj) if boundary_values else []
        )
        # Independent cursor for the sampling walk, so that draining
        # boundary checkpoints (which can leave state_pos sitting anywhere,
        # including field_obj.max) never perturbs where the walk itself has
        # gotten to - see _advance_state_pos().
        self._restart_walk(field_obj)

    def _boundary_checkpoints(self, field_obj):
        """
        Edge-case state_pos values for field_obj, clipped to [min, max]:
        the range's own endpoints, their immediate neighbors, the midpoint,
        and any MAGIC_BOUNDARIES constant that falls inside the range
        (0x7F/0x80/0xFF/... - classic off-by-one/overflow boundaries).
        Uniform jump sampling isn't guaranteed to land on any of these when
        (max - min) doesn't divide evenly by the jump stride.
        """
        if getattr(field_obj, 'exhaustive', False):
            # A RandEnumWalk indexes a value list, so 0x7f/0x80/0xff here would
            # name list positions rather than values - and its list already
            # carries the field's real boundaries (see
            # _EnumField._enum_walk_edges()), which the walk visits anyway.
            return []

        lo, hi = field_obj.min, field_obj.max
        if lo > hi:
            lo, hi = hi, lo

        candidates = {lo, hi}
        width = hi - lo
        if width > 0:
            candidates.add(lo + 1)
            candidates.add(hi - 1)
            candidates.add(lo + width // 2)

        for magic in MAGIC_BOUNDARIES:
            if lo <= magic <= hi:
                candidates.add(magic)

        return sorted(candidates)

    def _restart_walk(self, field_obj, after_reset=False):
        """
        Begin a fresh sampling cycle for field_obj.

        Called from initialize_volatile_field(), where state_pos is the
        field's min and nothing has been built from this field yet, so the
        cycle starts there and its first advance emits it.

        Also called from every place forward() force-resets an exhausted
        field, because a field carried into again at complexity >= 2 walks
        its range once more. Two things differ there (after_reset=True):

        - **the new cycle climbs from 'min', not from where the reset left
          state_pos.** The reset puts the field back on the value it
          renders while it is not being driven - its default - and that is
          not a starting point for a fresh traversal. For a field whose
          default is its own max it is the *end* of one: BGPHeader.marker
          defaults to 2**128-1, so every later cycle spanned nothing and
          spent its carry sending that one value again (256 of 383 driven
          steps, 67%, at complexity 2). PPTPStartControlConnectionRequest
          .maximum_channels is the same shape.
        - **the first value is skipped when the reset already sent it.**
          The call that resets a field also builds a case with the field
          at that value, so re-emitting it on the next call would send a
          byte-identical packet - one wasted case per carry, which for a
          4-value field like LWAPP.ver at complexity 2 was 791 of 4,000
          steps. A field whose default is not its min (or is not an int
          at all - state_pos is None then, meaning "render your own
          default") has not sent min, so it starts at index 0.
        """
        if after_reset:
            field_obj._walk_base = field_obj.min
            field_obj._walk_index = (
                1 if field_obj.state_pos == field_obj._walk_base else 0
            )
            return

        field_obj._walk_base = field_obj.state_pos
        # 0, not 1: the first advance of a cycle emits _walk_base itself -
        # see _advance_state_pos().
        field_obj._walk_index = 0

    def _advance_state_pos(self, field_obj, max_samples):
        """
        Move field_obj.state_pos to its next sample.

        The samples of one cycle are spread over [_walk_base, max]
        *inclusive of both ends*, so a field reaches its own extremes:

        - the first advance of a cycle emits _walk_base itself. forward()
          advances a field before reading it, so a walk that started by
          stepping emitted min + 1 .. max and never min - and min is what a
          reserved-must-be-zero field, a "no such type" branch or a
          zero-length count turns on. This is the same reason RandEnumWalk
          used to start its index at -1, which it no longer needs to.
        - the rest are 'max_samples' points evenly spread to land exactly on
          max, rather than a fixed integer stride from min. A byte field at
          the default density used to jump by round(256/128) = 2 and send
          2, 4, ... 254: one parity of the range, no minimum and no maximum.
          Counting samples instead of accumulating a rounded stride sends
          both endpoints and both parities.

        Pending boundary checkpoints (see _boundary_checkpoints()) are
        drained after the cycle's first value and before the spread ones, so
        boundary_values=True still supplements the walk rather than
        replacing it: the spread is driven by the sample count it keeps in
        _walk_index, which a checkpoint leaving state_pos at max cannot
        perturb.

        _walk_base/_walk_index always exist by the time a normal
        (prepare_combinations-driven) field reaches here, seeded by
        initialize_volatile_field(). The seeding below is only for a field
        whose state_pos was set directly by the caller instead - e.g. a
        hand-crafted 'active': True state that bypasses
        initialize_volatile_field() entirely. It counts that position as a
        value already emitted, so such a field advances *past* where the
        caller left it instead of re-sending it.
        """
        if not hasattr(field_obj, '_walk_base'):
            field_obj._walk_base = field_obj.state_pos
            field_obj._walk_index = 1

        if field_obj._walk_index == 0:
            field_obj._walk_index = 1
            field_obj.state_pos = field_obj._walk_base
            return

        pending = getattr(field_obj, '_pending_checkpoints', None)
        while pending:
            candidate = pending.pop(0)
            if candidate != field_obj.state_pos:
                field_obj.state_pos = candidate
                return

        if getattr(field_obj, 'exhaustive', False):
            # A RandEnumWalk's [min, max] is an index into a value list that is
            # already the interesting set - the protocol's own vocabulary plus
            # its edges. Sampling that down at every other index is exactly the
            # blind spot RandEnumWalk exists to close, so it always steps by 1.
            max_samples = max(max_samples, field_obj.max - field_obj.min)

        base = field_obj._walk_base
        index = field_obj._walk_index
        span = field_obj.max - base
        if span > max_samples > 1:
            # index runs 0 .. max_samples - 1 over the cycle, so the last
            # sample is base + span == max exactly, and the one after it
            # overshoots and ends the field.
            field_obj.state_pos = base + round(index * span / (max_samples - 1))
        else:
            # The whole range fits in the budget - send every value of it.
            field_obj.state_pos = base + index
        field_obj._walk_index = index + 1

    def _is_fuzzed_list(self, value):
        """
        Is this default_fields entry a list whose items fuzz() replaced
        with per-item randvals (see _fuzz_list_items())? Those are driven
        one index at a time ("Layer:field:index"), so anything that
        replaces the field wholesale has to keep that shape.
        """
        return (
            isinstance(value, list)
            and len(value) > 0
            and any(isinstance(item, VolatileValue) for item in value)
        )

    def _write_list_index(self, packet_holder, field_name, list_idx, new_value):
        """
        Update a single index of a list-shaped field's raw stored value
        (packet_holder.fields[field_name]), preserving every other item.
        Collapsing the whole list down to a single-item list (the older
        behavior) is only correct when the list genuinely has one item
        (e.g. Dot11EltRates.rates' default [0x82]) - for a multi-item list
        (Dot11EltRates.rates=[130, 132, 11, 22], DHCP.options with several
        named options) it would silently discard every other item.

        If the item at that index is a tuple (e.g. DHCP's
        ('option_name', <value>)), only the element that was the
        VolatileValue gets replaced - looked up via default_fields, which
        always keeps the live VolatileValue at that position regardless of
        what 'fields' currently holds (already-fixed concrete values,
        which don't carry that information anymore).
        """
        if list_idx is None:
            return

        template = packet_holder.default_fields.get(field_name)
        if not isinstance(template, list) or list_idx >= len(template):
            return

        if not hasattr(packet_holder, "default_list_value"):
            # Snapshot the pristine (pre-fuzzing) list the first time any
            # index of this field is touched - restoring one index to its
            # default later needs this, not whatever's mid-cycle by then.
            setattr(
                packet_holder,
                "default_list_value",
                list(packet_holder.fields.get(field_name, template)),
            )

        if field_name in packet_holder.fields and isinstance(packet_holder.fields[field_name], list):  # noqa: E501
            current_list = list(packet_holder.fields[field_name])
        else:
            current_list = list(packet_holder.default_list_value)

        while len(current_list) <= list_idx:
            current_list.append(template[len(current_list)])

        template_item = template[list_idx]
        if isinstance(template_item, tuple):
            current_list[list_idx] = tuple(
                new_value if isinstance(v, VolatileValue) else v
                for v in template_item
            )
        else:
            current_list[list_idx] = new_value

        packet_holder.fields[field_name] = current_list

    def _reset_list_index(self, packet_holder, field_name, list_idx):
        """
        Restore a single index of a list-shaped field back to its
        pristine (pre-fuzzing) value, leaving every other index (which
        may still be actively fuzzed as part of a different combination)
        untouched.
        """
        if list_idx is None or not hasattr(packet_holder, "default_list_value"):
            return
        if list_idx >= len(packet_holder.default_list_value):
            return

        if field_name in packet_holder.fields and isinstance(packet_holder.fields[field_name], list):  # noqa: E501
            current_list = list(packet_holder.fields[field_name])
        else:
            current_list = list(packet_holder.default_list_value)

        current_list[list_idx] = packet_holder.default_list_value[list_idx]
        packet_holder.fields[field_name] = current_list

    def resync_multiple_type_fields(self, pkt, max_samples=128):
        """
        A MultipleTypeField's concrete field (and therefore the shape of
        value it expects - e.g. int vs bytes, and its own min/max/size) is
        picked by looking at other fields on the packet (e.g. ICMP.type
        selects whether 'unused' is a Short/Int/StrFixedLen). When one of
        those selector fields is itself being fuzzed, the VolatileValue we
        cached in default_fields at fuzz()-time can go stale: it was built
        for a different concrete field than the one that will actually be
        used to pack it once the selector's value has moved on. Whenever a
        field's value changes, re-resolve every MultipleTypeField on the
        same packet and refresh its cached VolatileValue if the resolved
        concrete field no longer matches.

        Resolved VolatileValues are cached per concrete variant (keyed by
        the resolved Field descriptor's identity - MultipleTypeField.flds
        holds the same descriptor objects across calls, so this is
        stable) instead of always building a fresh one. Without this, a
        selector that oscillates between two ranges (e.g.
        LLDPDUChassisID.subtype cycling through the value that selects
        RandMAC for 'id' and then back out of it) would rebuild 'id' from
        scratch - with state_pos reset to the start - on every single
        oscillation, wiping out whatever progress 'id' had accumulated
        and livelocking forward() (it can never reach 'done').

        max_samples is passed through to initialize_volatile_field() for a
        freshly-built volatile: a MultipleTypeField can resolve to an enum
        field (rtmsg_rtattr.rta_data has an EnumField(fmt="=I") variant), and
        one of those sizes its value list to the sampling budget, so handing it
        the default here would silently pin it to a density the run isn't at.
        """
        if not hasattr(pkt, '_multiple_type_field_cache'):
            pkt._multiple_type_field_cache = {}
        cache = pkt._multiple_type_field_cache

        for outer in pkt.fields_desc:
            # Unwrap the same way fuzz() does: a MultipleTypeField can sit
            # inside a single-field container (rtmsg_rtattr.rta_data is a
            # PadField around one), and fuzz() looks through those when it
            # decides which fields need a resolved randval - so this has to
            # look through them too, or the fields fuzz() cached are exactly
            # the ones that never get refreshed. Reached once an enum
            # selector started walking its declared values: rta_type's
            # integer sweep only ever produced multiples of 512, none of
            # which select a variant, so this stayed latent.
            f = _unwrap_field(outer)
            if not isinstance(f, MultipleTypeField):
                continue

            resolved_fld = f._find_fld_pkt(pkt)
            cache_key = id(resolved_fld)
            field_cache = cache.setdefault(f.name, {})

            if field_cache.get('_active_key') == cache_key:
                # Still resolved to the same variant as last time, nothing to do
                continue

            if cache_key in field_cache:
                # Seen this concrete variant before on this packet -
                # restore its previous progress rather than starting over
                pkt.default_fields[f.name] = field_cache[cache_key]
            elif self._is_fuzzed_list(pkt.default_fields.get(f.name)):
                # This MultipleTypeField is driven per list item (fuzz()
                # found the caller holding a list here - see
                # _fuzz_list_items()), so the replacement has to be a list
                # too: assigning a scalar randval would throw the caller's
                # value away, which is the whole reason the list branch
                # exists.
                current_list = pkt.default_fields[f.name]
                originals = [
                    item.default if isinstance(item, VolatileValue) else item
                    for item in current_list
                ]
                fresh_list = _fuzz_list_items(resolved_fld, originals)

                if all(
                    type(was).__name__ == type(now).__name__
                    for (was, now) in zip(current_list, fresh_list)
                ):
                    # Same per-item type as what's already there (e.g.
                    # fuzz()'s own initial assignment) - adopt it as-is,
                    # preserving each item's state_pos, rather than
                    # restarting every item's walk.
                    field_cache[cache_key] = current_list
                else:
                    for item in fresh_list:
                        if isinstance(item, VolatileValue):
                            self.initialize_volatile_field(
                                item, max_samples=max_samples)
                    field_cache[cache_key] = fresh_list
                    pkt.default_fields[f.name] = fresh_list

                    # The raw list in 'fields' was built for the previous
                    # variant's item type (an IPv4 address where the
                    # variant now wants an IPv6 one), so it can't be
                    # packed by this one.
                    pkt.fields.pop(f.name, None)

                field_cache['_active_key'] = cache_key
                # Deliberately not falling through to the 'fields' cleanup
                # below: for a per-item walk 'fields' holds the live list
                # forward() is writing single indexes of.
                continue
            else:
                fresh = resolved_fld.randval()
                if fresh is None:
                    continue

                current = pkt.default_fields.get(f.name)
                if current is not None and type(current).__name__ == type(fresh).__name__:
                    # Already the right concrete type (e.g. fuzz()'s own
                    # initial assignment) - adopt it as-is, preserving its
                    # identity/state_pos, instead of discarding it for a
                    # fresh, uninitialized replacement.
                    field_cache[cache_key] = current
                else:
                    fresh.default = resolved_fld.default
                    self.initialize_volatile_field(fresh, max_samples=max_samples)
                    field_cache[cache_key] = fresh
                    pkt.default_fields[f.name] = fresh

            field_cache['_active_key'] = cache_key

            # Drop any raw value of the now-wrong type sitting in 'fields'
            # (used by command()/show() to display non-default values)
            if f.name in pkt.fields:
                del pkt.fields[f.name]


    def forward(self, states):
        """
        Go through each field, find if they can still move
        if they can great, move them, otherwise reset them to default
        and move to the next one
        """
        if states is None:
            raise ValueError("Please provide states")

        if len(states) == 0:
            raise ValueError("States should include at least one permutation")

        # Find the first state that has 'done' False, starting from the
        # cursor rather than from index 0: everything below it finished on
        # an earlier call and a state never becomes live again, so
        # re-examining that prefix is pure overhead - see FuzzStates. A
        # caller's own plain list has no cursor, and then this is the
        # original full scan.
        state_fuzzed = None
        state = None
        first_live = getattr(states, 'first_live', 0)
        for index in range(first_live, len(states)):
            state = states[index]
            if not state['done']:
                if index != first_live and hasattr(states, 'first_live'):
                    # Everything we just walked past is done for good, so
                    # the next call can start here. Advancing lazily (here)
                    # rather than at the moment a state completes keeps the
                    # cursor right no matter who marked the state done.
                    states.first_live = index
                state_fuzzed = state
                fields = state['fields']

                # Mark it as active, and print the transition once
                was_active = state['active']
                if not was_active:
                    self.display_now_fuzzing(fields)
                    # print(f"Now fuzzing: {fields}")
                    state['active'] = True

                # Initialize every field the first time THIS state/pair
                # becomes active (was_active False), regardless of
                # whatever a field's own state_pos/default happens to be
                # left at from a *different*, earlier pair reusing the
                # same field object - a field whose default isn't its own
                # min (e.g. a ShortField defaulting to its own max, like
                # PPTPStartControlConnectionRequest.maximum_channels)
                # would otherwise resume from that leftover value instead
                # of a fresh min-to-max climb, silently collapsing this
                # pair's combination count. ALSO initialize whenever
                # state_pos is still None even though was_active was
                # already True - covers a state handed to forward()
                # pre-marked active=True (e.g. a hand-crafted state
                # targeting one specific field directly, skipping
                # prepare_combinations()); without this, such a field's
                # state_pos stays None forever and 'state_pos += jump'
                # below raises TypeError.
                for field_item in fields:
                    (_, field_obj) = self.locate_field(self, field_item['name'])

                    if not isinstance(field_obj, VolatileValue):
                        err = (f"field_obj: '{field_item['name']}' "
                               f"isn't VolatileValue: {type(field_obj)=}, was scapy.all.fuzz called?")
                        raise ValueError(err)

                    # getattr(..., None), not a direct attribute read: a
                    # VolatileValue subclass that doesn't declare
                    # state_pos at all (anything outside this fork's own
                    # Rand* classes) would otherwise fall through
                    # VolatileValue.__getattr__ into _fix() and raise
                    # AttributeError on the fixed value instead.
                    if not was_active or getattr(field_obj, 'state_pos', None) is None:
                        self.initialize_volatile_field(
                            field_obj,
                            boundary_values=field_item.get('boundary_values', False),
                            max_samples=field_item.get('max_samples', 128),
                        )

                break

        if state_fuzzed is None: # Means we couldn't find a state to fuzz
            return (states, False)

        # Find the first field that is not done and move it forward
        found_a_fuzzable_field = False
        next_field = None
        for (field_idx, field) in enumerate(state_fuzzed['fields']):
            if not field['done']:
                (packet_holder, field_fuzzed) = self.locate_field(self, field['name'])
                if field_fuzzed.max == field_fuzzed.min and field_fuzzed.max == 0:
                    print(f"Why is '{field['name']}' max == 0? this is not going to do anything")

                if not hasattr(field_fuzzed, "state_pos"):
                    # Make sure next_field exists, as it might be the first element
                    if next_field is not None:
                        next_field['done'] = True # Mark it as done
                    continue

                # print(f"'{field['name']}' {field_fuzzed.state_pos=}")
                self._advance_state_pos(field_fuzzed, field.get('max_samples', 128))

                field_split = field['name'].split(":")
                field_name = None
                list_idx = None
                if len(field_split) > 1:
                    field_name = field_split[1]
                if len(field_split) == 3:
                    # "pkt:field:idx" - a list-of-scalar-VolatileValue item
                    # (e.g. Dot11EltRates.rates, DHCP.options) - part 2 is
                    # the index into that list, not a sub-field name.
                    try:
                        list_idx = int(field_split[2])
                    except ValueError:
                        list_idx = None

                # If we reached max for this field, try the next one
                if field_fuzzed.state_pos > field_fuzzed.max:
                    # Reset the position back to default
                    if type(field_fuzzed.default).__name__ in ['str', 'bytes', 'tuple']:
                        # None, not 0: every Rand* reads 'state_pos is
                        # None' as "not the field being fuzzed, render the
                        # value the packet would have had" and hands back
                        # its default. 0 used to be written here as if it
                        # meant the same thing, and it does not - it is a
                        # position like any other, so a finished RandBin
                        # rendered chars[0:0], the empty string, and a
                        # finished RandIP rendered _COMBINATIONS[0],
                        # 0.0.0.0, for the rest of the run rather than the
                        # address the field carries.
                        field_fuzzed.state_pos = None
                    elif type(field_fuzzed.default).__name__ != 'int':
                        raise ValueError("field_fuzzed.default is not int")
                    else:
                        field_fuzzed.state_pos = field_fuzzed.default
                    # Start a fresh sampling cycle from the value we just
                    # reset to - a field that gets carried into again later
                    # (complexity >= 2) counts its samples from _walk_base,
                    # not from state_pos; leaving that stale at its old
                    # near-max value would overshoot on the very next call
                    # and end this field's new cycle instantly.
                    self._restart_walk(field_fuzzed, after_reset=True)

                    if field_name is not None and field_name in packet_holder.fields:
                        if isinstance(packet_holder.fields[field_name], list):
                            # Make sure that the first item is not 'obj'
                            if len(packet_holder.fields[field_name]) > 0:
                                if isinstance(packet_holder.fields[field_name][0], Packet):
                                    # We don't touch it
                                    pass
                                elif list_idx is not None:
                                    self._reset_list_index(packet_holder, field_name, list_idx)
                                else:
                                    if hasattr(packet_holder, "default_list_value"):
                                        # Keep record of what was there by default, which is better than putting an empty array (fixes VRRP edge case of 'addrlist')
                                        packet_holder.fields[field_name] = packet_holder.default_list_value

                                        # Remove the attr, so that it can be placed again if relevant
                                        delattr(packet_holder, 'default_list_value')
                                    else:
                                        packet_holder.fields[field_name] = []
                        else:
                            del packet_holder.fields[field_name]

                    if field_name is not None:
                        self.resync_multiple_type_fields(
                            packet_holder, field.get('max_samples', 128))

                    # Breaks send, shows 'int' error
                    # # Make the 'fields' no longer list this value as non-default
                    # field_name = field['name']
                    # packet_field = field_name[field_name.index(':')+1:]
                    # del packet_holder.fields[packet_field]

                    field['done'] = True
                    field['active'] = False

                    curr_pos = field_idx

                    # Make sure we aren't the last one
                    are_we_last = (curr_pos + 1) == len(state_fuzzed['fields'])

                    while not are_we_last:
                        next_field = state_fuzzed['fields'][curr_pos+1]

                        if not next_field['done']:
                            # Try to move to the next item
                            (next_field_holder, field_fuzzed) = self.locate_field(self, next_field['name'])

                            if not hasattr(field_fuzzed, 'state_pos'):
                                err = f"We will fail for: {field_fuzzed}"
                                raise ValueError(err)

                            # Same jump-scaling as the main advance path
                            # above - without it, a wide-range field
                            # advanced via carry (i.e. it isn't the
                            # fastest/innermost field in its combo) only
                            # ever moves by 1 per carry, needing up to
                            # (max - min) carries - millions of iterations
                            # for something like a ShortField - to finish.
                            self._advance_state_pos(field_fuzzed, next_field.get('max_samples', 128))
                            if field_fuzzed.state_pos > field_fuzzed.max:
                                if type(field_fuzzed.default).__name__ in ['str', 'bytes', 'tuple']:
                                    # See the matching comment on the main
                                    # reset path above: None is what says
                                    # "render your own default".
                                    field_fuzzed.state_pos = None
                                elif type(field_fuzzed.default).__name__ != 'int':
                                    raise ValueError("field_fuzzed.default is not int")
                                else:
                                    field_fuzzed.state_pos = field_fuzzed.default
                                # See the matching comment on the main
                                # advance path above - this field may
                                # itself be carried into again by a still
                                # further-out field at higher complexity.
                                self._restart_walk(field_fuzzed, after_reset=True)
                                next_field['done'] = True

                            self.resync_multiple_type_fields(
                                next_field_holder,
                                next_field.get('max_samples', 128))

                            if not next_field['done']:
                                # Reset the item before us to not done
                                state_fuzzed['fields'][curr_pos]['done'] = False

                                # Reset the previous item pos to the begining
                                (curr_field_holder, field_fuzzed) = self.locate_field(
                                    self,
                                    state_fuzzed['fields'][curr_pos]['name']
                                )

                                if type(field_fuzzed.default).__name__ in ['str', 'bytes', 'tuple']:
                                    # See the matching comment on the main
                                    # reset path above: None is what says
                                    # "render your own default".
                                    field_fuzzed.state_pos = None
                                elif type(field_fuzzed.default).__name__ != 'int':
                                    raise ValueError("field_fuzzed.default is not int")
                                else:
                                    field_fuzzed.state_pos = field_fuzzed.default
                                # This is the actual carry restart: without
                                # restarting the walk here too, the next
                                # _advance_state_pos() call on this field
                                # counts on from its stale near-max cursor
                                # and overshoots immediately, ending the
                                # new cycle before it visits anything past
                                # this reset value.
                                self._restart_walk(field_fuzzed, after_reset=True)

                                self.resync_multiple_type_fields(
                                    curr_field_holder,
                                    field.get('max_samples', 128))

                                field['combinations'] += 1
                                field['active'] = True
                                state_fuzzed['combinations'] += 1
                                found_a_fuzzable_field = True
                                break

                        curr_pos += 1
                        are_we_last = (curr_pos + 1) == len(state_fuzzed['fields'])

                    if found_a_fuzzable_field:
                        # The inner while's own 'break' above only exits
                        # IT, not this outer 'for field_idx, field in
                        # enumerate(...)' loop - without this, control
                        # falls through to the next outer iteration, which
                        # lands on the very field the inner while just
                        # carried into, finds it not done, and advances it
                        # AGAIN via the normal branch below - incrementing
                        # combinations (and fuzzing a second, different
                        # value) twice within a single forward() call.
                        break

                else:
                    # Put the new value (fuzzed) in the 'fields' so that ".commmand()" will display it
                    if field_name is not None:
                        if list_idx is not None:
                            # A list-of-scalar-VolatileValue item (e.g.
                            # Dot11EltRates.rates, DHCP.options) - update
                            # just this index, preserving every other item
                            # (which may belong to a different active
                            # combination, or simply not be fuzzed at all).
                            self._write_list_index(packet_holder, field_name, list_idx, field_fuzzed._fix())
                        # If the field_name exists already and is a list (i.e. it is a list from 'init', keep the structure)
                        elif field_name in packet_holder.fields:
                            if isinstance(packet_holder.fields[field_name], list):
                                if len(packet_holder.fields[field_name]) > 0:
                                    if isinstance(packet_holder.fields[field_name][0], Packet):
                                        # We don't touch it
                                        pass
                                    else:
                                        if not hasattr(packet_holder, "default_list_value"):
                                            # Keep record of what was there by default
                                            setattr(packet_holder, 'default_list_value', packet_holder.fields[field_name])
                                        packet_holder.fields[field_name] = [field_fuzzed._fix()]
                                else:
                                    packet_holder.fields[field_name] = [field_fuzzed._fix()]
                            else:
                                packet_holder.fields[field_name] = field_fuzzed._fix()
                        else:
                            packet_holder.fields[field_name] = field_fuzzed._fix()

                        self.resync_multiple_type_fields(
                            packet_holder, field.get('max_samples', 128))

                    field['combinations'] += 1
                    field['active'] = True
                    state_fuzzed['combinations'] += 1

                    found_a_fuzzable_field = True

                    break

        if not found_a_fuzzable_field and state is not None:
            # We reached the end...
            state['done'] = True
            state['active'] = False

            # Try to find the next one that is fuzzable (state)
            (states, found_a_fuzzable_field) = self.forward(states)

        # Breaks send
        # if found_a_fuzzable_field:
        #     # If we found a field to fuzz, put it in the 'fields' so that
        #     #  command() will return its non-default value
        #     for state in states:
        #         if not state['active']:
        #             continue

        #         fields = state['fields']
        #         for field in fields:
        #             field_name = field["name"]
        #             packet_field = field_name[field_name.index(':')+1:]

        #             (packet_holder, field_obj) = self.locate_field(self, field_name)
        #             packet_holder.fields[packet_field] = field_obj._fix()

        #         break

        return (states, found_a_fuzzable_field)

    def build(self):
        # type: () -> bytes
        """
        Create the current layer

        :return: string of the packet with the payload
        """
        p = self.do_build()
        p += self.build_padding()
        p = self.build_done(p)
        return p

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        """
        DEV: called right after the current layer is build.

        :param str pkt: the current packet (build by self_build function)
        :param str pay: the packet payload (build by do_build_payload function)
        :return: a string of the packet with the payload
        """
        return pkt + pay

    def build_done(self, p):
        # type: (bytes) -> bytes
        return self.payload.build_done(p)

    def do_build_ps(self):
        # type: () -> Tuple[bytes, List[Tuple[Packet, List[Tuple[Field[Any, Any], str, bytes]]]]]  # noqa: E501
        p = b""
        pl = []
        q = b""
        for f in self.fields_desc:
            if isinstance(f, ConditionalField) and not f._evalcond(self):
                continue
            p = f.addfield(self, p, self.getfieldval(f.name))
            if isinstance(p, bytes):
                r = p[len(q):]
                q = p
            else:
                r = b""
            pl.append((f, f.i2repr(self, self.getfieldval(f.name)), r))

        pkt, lst = self.payload.build_ps(internal=1)
        p += pkt
        lst.append((self, pl))

        return p, lst

    def build_ps(self, internal=0):
        # type: (int) -> Tuple[bytes, List[Tuple[Packet, List[Tuple[Any, Any, bytes]]]]]  # noqa: E501
        p, lst = self.do_build_ps()
#        if not internal:
#            pkt = self
#            while pkt.haslayer(conf.padding_layer):
#                pkt = pkt.getlayer(conf.padding_layer)
#                lst.append( (pkt, [ ("loakjkjd", pkt.load, pkt.load) ] ) )
#                p += pkt.load
#                pkt = pkt.payload
        return p, lst

    def canvas_dump(self, layer_shift=0, rebuild=1):
        # type: (int, int) -> pyx.canvas.canvas
        if PYX == 0:
            raise ImportError("PyX and its dependencies must be installed")
        canvas = pyx.canvas.canvas()
        if rebuild:
            _, t = self.__class__(raw(self)).build_ps()
        else:
            _, t = self.build_ps()
        YTXTI = len(t)
        for _, l in t:
            YTXTI += len(l)
        YTXT = float(YTXTI)
        YDUMP = YTXT

        XSTART = 1
        XDSTART = 10
        y = 0.0
        yd = 0.0
        XMUL = 0.55
        YMUL = 0.4

        backcolor = colgen(0.6, 0.8, 1.0, trans=pyx.color.rgb)
        forecolor = colgen(0.2, 0.5, 0.8, trans=pyx.color.rgb)
#        backcolor=makecol(0.376, 0.729, 0.525, 1.0)

        def hexstr(x):
            # type: (bytes) -> str
            return " ".join("%02x" % c for c in x)

        def make_dump_txt(x, y, txt):
            # type: (int, float, bytes) -> pyx.text.text
            return pyx.text.text(
                XDSTART + x * XMUL,
                (YDUMP - y) * YMUL,
                r"\tt{%s}" % hexstr(txt),
                [pyx.text.size.Large]
            )

        def make_box(o):
            # type: (pyx.bbox.bbox) -> pyx.bbox.bbox
            return pyx.box.rect(
                o.left(), o.bottom(), o.width(), o.height(),
                relcenter=(0.5, 0.5)
            )

        def make_frame(lst):
            # type: (List[Any]) -> pyx.path.path
            if len(lst) == 1:
                b = lst[0].bbox()
                b.enlarge(pyx.unit.u_pt)
                return b.path()
            else:
                fb = lst[0].bbox()
                fb.enlarge(pyx.unit.u_pt)
                lb = lst[-1].bbox()
                lb.enlarge(pyx.unit.u_pt)
                if len(lst) == 2 and fb.left() > lb.right():
                    return pyx.path.path(pyx.path.moveto(fb.right(), fb.top()),
                                         pyx.path.lineto(fb.left(), fb.top()),
                                         pyx.path.lineto(fb.left(), fb.bottom()),  # noqa: E501
                                         pyx.path.lineto(fb.right(), fb.bottom()),  # noqa: E501
                                         pyx.path.moveto(lb.left(), lb.top()),
                                         pyx.path.lineto(lb.right(), lb.top()),
                                         pyx.path.lineto(lb.right(), lb.bottom()),  # noqa: E501
                                         pyx.path.lineto(lb.left(), lb.bottom()))  # noqa: E501
                else:
                    # XXX
                    gb = lst[1].bbox()
                    if gb != lb:
                        gb.enlarge(pyx.unit.u_pt)
                    kb = lst[-2].bbox()
                    if kb != gb and kb != lb:
                        kb.enlarge(pyx.unit.u_pt)
                    return pyx.path.path(pyx.path.moveto(fb.left(), fb.top()),
                                         pyx.path.lineto(fb.right(), fb.top()),
                                         pyx.path.lineto(fb.right(), kb.bottom()),  # noqa: E501
                                         pyx.path.lineto(lb.right(), kb.bottom()),  # noqa: E501
                                         pyx.path.lineto(lb.right(), lb.bottom()),  # noqa: E501
                                         pyx.path.lineto(lb.left(), lb.bottom()),  # noqa: E501
                                         pyx.path.lineto(lb.left(), gb.top()),
                                         pyx.path.lineto(fb.left(), gb.top()),
                                         pyx.path.closepath(),)

        def make_dump(s,   # type: bytes
                      shift=0,  # type: int
                      y=0.,  # type: float
                      col=None,  # type: pyx.color.color
                      bkcol=None,  # type: pyx.color.color
                      large=16  # type: int
                      ):
            # type: (...) -> Tuple[pyx.canvas.canvas, pyx.bbox.bbox, int, float]  # noqa: E501
            c = pyx.canvas.canvas()
            tlist = []
            while s:
                dmp, s = s[:large - shift], s[large - shift:]
                txt = make_dump_txt(shift, y, dmp)
                tlist.append(txt)
                shift += len(dmp)
                if shift >= 16:
                    shift = 0
                    y += 1
            if col is None:
                col = pyx.color.rgb.red
            if bkcol is None:
                bkcol = pyx.color.rgb.white
            c.stroke(make_frame(tlist), [col, pyx.deco.filled([bkcol]), pyx.style.linewidth.Thick])  # noqa: E501
            for txt in tlist:
                c.insert(txt)
            return c, tlist[-1].bbox(), shift, y

        last_shift, last_y = 0, 0.0
        while t:
            bkcol = next(backcolor)
            proto, fields = t.pop()
            y += 0.5
            pt = pyx.text.text(
                XSTART,
                (YTXT - y) * YMUL,
                r"\font\cmssfont=cmss10\cmssfont{%s}" % tex_escape(
                    str(proto.name)
                ),
                [pyx.text.size.Large]
            )
            y += 1
            ptbb = pt.bbox()
            ptbb.enlarge(pyx.unit.u_pt * 2)
            canvas.stroke(ptbb.path(), [pyx.color.rgb.black, pyx.deco.filled([bkcol])])  # noqa: E501
            canvas.insert(pt)
            for field, fval, fdump in fields:
                col = next(forecolor)
                ft = pyx.text.text(XSTART, (YTXT - y) * YMUL, r"\font\cmssfont=cmss10\cmssfont{%s}" % tex_escape(field.name))  # noqa: E501
                if isinstance(field, BitField):
                    fsize = '%sb' % field.size
                else:
                    fsize = '%sB' % len(fdump)
                if (hasattr(field, 'field') and
                        'LE' in field.field.__class__.__name__[:3] or
                        'LE' in field.__class__.__name__[:3]):
                    fsize = r'$\scriptstyle\langle$' + fsize
                st = pyx.text.text(XSTART + 3.4, (YTXT - y) * YMUL, r"\font\cmbxfont=cmssbx10 scaled 600\cmbxfont{%s}" % fsize, [pyx.text.halign.boxright])  # noqa: E501
                if isinstance(fval, str):
                    if len(fval) > 18:
                        fval = fval[:18] + "[...]"
                else:
                    fval = ""
                vt = pyx.text.text(XSTART + 3.5, (YTXT - y) * YMUL, r"\font\cmssfont=cmss10\cmssfont{%s}" % tex_escape(fval))  # noqa: E501
                y += 1.0
                if fdump:
                    dt, target, last_shift, last_y = make_dump(fdump, last_shift, last_y, col, bkcol)  # noqa: E501

                    dtb = target
                    vtb = vt.bbox()
                    bxvt = make_box(vtb)
                    bxdt = make_box(dtb)
                    dtb.enlarge(pyx.unit.u_pt)
                    try:
                        if yd < 0:
                            cnx = pyx.connector.curve(bxvt, bxdt, absangle1=0, absangle2=-90)  # noqa: E501
                        else:
                            cnx = pyx.connector.curve(bxvt, bxdt, absangle1=0, absangle2=90)  # noqa: E501
                    except Exception:
                        pass
                    else:
                        canvas.stroke(cnx, [pyx.style.linewidth.thin, pyx.deco.earrow.small, col])  # noqa: E501

                    canvas.insert(dt)

                canvas.insert(ft)
                canvas.insert(st)
                canvas.insert(vt)
            last_y += layer_shift

        return canvas

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        """
        DEV: to be overloaded to extract current layer's padding.

        :param str s: the current layer
        :return: a couple of strings (actual layer, padding)
        """
        return s, None

    def post_dissect(self, s):
        # type: (bytes) -> bytes
        """DEV: is called right after the current layer has been dissected"""
        return s

    def pre_dissect(self, s):
        # type: (bytes) -> bytes
        """DEV: is called right before the current layer is dissected"""
        return s

    def do_dissect(self, s):
        # type: (bytes) -> bytes
        _raw = s
        self.raw_packet_cache_fields = {}
        for f in self.fields_desc:
            s, fval = f.getfield(self, s)
            # Skip unused ConditionalField
            if f.isconditional and fval is None:
                continue
            # We need to track fields with mutable values to discard
            # .raw_packet_cache when needed.
            if (f.islist or f.holds_packets or f.ismutable) and fval is not None:
                self.raw_packet_cache_fields[f.name] = \
                    self._raw_packet_cache_field_value(f, fval, copy=True)
            self.fields[f.name] = fval
            # Nothing left to dissect
            if not s and (f.ismayend or
                          (fval is not None and f.isconditional and
                           f.fld.ismayend)):  # type: ignore
                break
        self.raw_packet_cache = _raw[:-len(s)] if s else _raw
        self.explicit = 1
        return s

    def do_dissect_payload(self, s):
        # type: (bytes) -> None
        """
        Perform the dissection of the layer's payload

        :param str s: the raw layer
        """
        if s:
            if (
                self.stop_dissection_after and
                isinstance(self, self.stop_dissection_after)
            ):
                # stop dissection here
                p = conf.raw_layer(s, _internal=1, _underlayer=self)
                self.add_payload(p)
                return
            cls = self.guess_payload_class(s)
            try:
                p = cls(
                    s,
                    stop_dissection_after=self.stop_dissection_after,
                    _internal=1,
                    _underlayer=self,
                )
            except KeyboardInterrupt:
                raise
            except Exception:
                if conf.debug_dissector:
                    if issubtype(cls, Packet):
                        log_runtime.error("%s dissector failed", cls.__name__)
                    else:
                        log_runtime.error("%s.guess_payload_class() returned "
                                          "[%s]",
                                          self.__class__.__name__, repr(cls))
                    if cls is not None:
                        raise
                p = conf.raw_layer(s, _internal=1, _underlayer=self)
            self.add_payload(p)

    def dissect(self, s):
        # type: (bytes) -> None
        s = self.pre_dissect(s)

        s = self.do_dissect(s)

        s = self.post_dissect(s)

        payl, pad = self.extract_padding(s)
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            self.add_payload(conf.padding_layer(pad))

    def guess_payload_class(self, payload):
        # type: (bytes) -> Type[Packet]
        """
        DEV: Guesses the next payload class from layer bonds.
        Can be overloaded to use a different mechanism.

        :param str payload: the layer's payload
        :return: the payload class
        """
        for t in self.aliastypes:
            for fval, cls in t.payload_guess:
                try:
                    if all(v == self.getfieldval(k)
                           for k, v in fval.items()):
                        return cls  # type: ignore
                except AttributeError:
                    pass
        return self.default_payload_class(payload)

    def default_payload_class(self, payload):
        # type: (bytes) -> Type[Packet]
        """
        DEV: Returns the default payload class if nothing has been found by the
        guess_payload_class() method.

        :param str payload: the layer's payload
        :return: the default payload class define inside the configuration file
        """
        return conf.raw_layer

    def hide_defaults(self):
        # type: () -> None
        """Removes fields' values that are the same as default values."""
        # use list(): self.fields is modified in the loop
        for k, v in list(self.fields.items()):
            v = self.fields[k]
            if k in self.default_fields:
                if self.default_fields[k] == v:
                    del self.fields[k]
        self.payload.hide_defaults()

    def clone_with(self, payload=None, **kargs):
        # type: (Optional[Any], **Any) -> Any
        pkt = self.__class__()
        pkt.explicit = 1
        pkt.fields = kargs
        pkt.default_fields = self.copy_fields_dict(self.default_fields)
        pkt.overloaded_fields = self.overloaded_fields.copy()
        pkt.time = self.time
        pkt.underlayer = self.underlayer
        pkt.parent = self.parent
        pkt.post_transforms = self.post_transforms
        pkt.raw_packet_cache = self.raw_packet_cache
        pkt.raw_packet_cache_fields = self.copy_fields_dict(
            self.raw_packet_cache_fields
        )
        pkt.wirelen = self.wirelen
        pkt.comments = self.comments
        pkt.sniffed_on = self.sniffed_on
        pkt.direction = self.direction
        if payload is not None:
            pkt.add_payload(payload)
        return pkt

    def __iter__(self):
        # type: () -> Iterator[Packet]
        """Iterates through all sub-packets generated by this Packet."""
        def loop(todo, done, self=self):
            # type: (List[str], Dict[str, Any], Any) -> Iterator[Packet]
            if todo:
                eltname = todo.pop()
                elt = self.getfieldval(eltname)
                if not isinstance(elt, Gen):
                    if self.get_field(eltname).islist:
                        elt = SetGen([elt])
                    else:
                        elt = SetGen(elt)
                for e in elt:
                    done[eltname] = e
                    for x in loop(todo[:], done):
                        yield x
            else:
                if isinstance(self.payload, NoPayload):
                    payloads = SetGen([None])  # type: SetGen[Packet]
                else:
                    payloads = self.payload
                for payl in payloads:
                    # Let's make sure subpackets are consistent
                    done2 = done.copy()
                    for k in done2:
                        if isinstance(done2[k], VolatileValue):
                            done2[k] = done2[k]._fix()
                    pkt = self.clone_with(payload=payl, **done2)
                    yield pkt

        if self.explicit or self.raw_packet_cache is not None:
            todo = []
            done = self.fields
        else:
            todo = [k for (k, v) in itertools.chain(self.default_fields.items(),
                                                    self.overloaded_fields.items())
                    if isinstance(v, VolatileValue)] + list(self.fields)
            done = {}
        return loop(todo, done)

    def iterpayloads(self):
        # type: () -> Iterator[Packet]
        """Used to iter through the payloads of a Packet.
        Useful for DNS or 802.11 for instance.
        """
        yield self
        current = self
        while current.payload:
            current = current.payload
            yield current

    def __gt__(self, other):
        # type: (Packet) -> int
        """True if other is an answer from self (self ==> other)."""
        if isinstance(other, Packet):
            return other < self
        elif isinstance(other, bytes):
            return 1
        else:
            raise TypeError((self, other))

    def __lt__(self, other):
        # type: (Packet) -> int
        """True if self is an answer from other (other ==> self)."""
        if isinstance(other, Packet):
            return self.answers(other)
        elif isinstance(other, bytes):
            return 1
        else:
            raise TypeError((self, other))

    def __eq__(self, other):
        # type: (Any) -> bool
        if not isinstance(other, self.__class__):
            return False
        for f in self.fields_desc:
            if f not in other.fields_desc:
                return False
            if self.getfieldval(f.name) != other.getfieldval(f.name):
                return False
        return self.payload == other.payload

    def __ne__(self, other):
        # type: (Any) -> bool
        return not self.__eq__(other)

    # Note: setting __hash__ to None is the standard way
    # of making an object un-hashable. mypy doesn't know that
    __hash__ = None  # type: ignore

    def hashret(self):
        # type: () -> bytes
        """DEV: returns a string that has the same value for a request
        and its answer."""
        return self.payload.hashret()

    def answers(self, other):
        # type: (Packet) -> int
        """DEV: true if self is an answer from other"""
        if other.__class__ == self.__class__:
            return self.payload.answers(other.payload)
        return 0

    def layers(self):
        # type: () -> List[Type[Packet]]
        """returns a list of layer classes (including subclasses) in this packet"""  # noqa: E501
        layers = []
        lyr = self  # type: Optional[Packet]
        while lyr:
            layers.append(lyr.__class__)
            lyr = lyr.payload.getlayer(0, _subclass=True)
        return layers

    def haslayer(self, cls, _subclass=None):
        # type: (Union[Type[Packet], str], Optional[bool]) -> int
        """
        true if self has a layer that is an instance of cls.
        Superseded by "cls in self" syntax.
        """
        if _subclass is None:
            _subclass = self.match_subclass or None
        if _subclass:
            match = issubtype
        else:
            match = lambda x, t: bool(x == t)
        if cls is None or match(self.__class__, cls) \
           or cls in [self.__class__.__name__, self._name]:
            return True
        for f in self.packetfields:
            fvalue_gen = self.getfieldval(f.name)
            if fvalue_gen is None:
                continue
            if not f.islist:
                fvalue_gen = SetGen(fvalue_gen, _iterpacket=0)
            for fvalue in fvalue_gen:
                if isinstance(fvalue, Packet):
                    ret = fvalue.haslayer(cls, _subclass=_subclass)
                    if ret:
                        return ret
        return self.payload.haslayer(cls, _subclass=_subclass)

    def getlayer(self,
                 cls,  # type: Union[int, Type[Packet], str]
                 nb=1,  # type: int
                 _track=None,  # type: Optional[List[int]]
                 _subclass=None,  # type: Optional[bool]
                 **flt  # type: Any
                 ):
        # type: (...) -> Optional[Packet]
        """Return the nb^th layer that is an instance of cls, matching flt
values.
        """
        if _subclass is None:
            _subclass = self.match_subclass or None
        if _subclass:
            match = issubtype
        else:
            match = lambda x, t: bool(x == t)
        # Note:
        # cls can be int, packet, str
        # string_class_name can be packet, str (packet or packet+field)
        # class_name can be packet, str (packet only)
        if isinstance(cls, int):
            nb = cls + 1
            string_class_name = ""  # type: Union[Type[Packet], str]
        else:
            string_class_name = cls
        class_name = ""  # type: Union[Type[Packet], str]
        fld = None  # type: Optional[str]
        if isinstance(string_class_name, str) and "." in string_class_name:
            class_name, fld = string_class_name.split(".", 1)
        else:
            class_name, fld = string_class_name, None
        if not class_name or match(self.__class__, class_name) \
           or class_name in [self.__class__.__name__, self._name]:
            if all(self.getfieldval(fldname) == fldvalue
                   for fldname, fldvalue in flt.items()):
                if nb == 1:
                    if fld is None:
                        return self
                    else:
                        return self.getfieldval(fld)  # type: ignore
                else:
                    nb -= 1
        for f in self.packetfields:
            fvalue_gen = self.getfieldval(f.name)
            if fvalue_gen is None:
                continue
            if not f.islist:
                fvalue_gen = SetGen(fvalue_gen, _iterpacket=0)
            for fvalue in fvalue_gen:
                if isinstance(fvalue, Packet):
                    track = []  # type: List[int]
                    ret = fvalue.getlayer(class_name, nb=nb, _track=track,
                                          _subclass=_subclass, **flt)
                    if ret is not None:
                        return ret
                    nb = track[0]
        return self.payload.getlayer(class_name, nb=nb, _track=_track,
                                     _subclass=_subclass, **flt)

    def firstlayer(self):
        # type: () -> Packet
        q = self
        while q.underlayer is not None:
            q = q.underlayer
        return q

    def __getitem__(self, cls):
        # type: (Union[Type[Packet], str]) -> Any
        if isinstance(cls, slice):
            lname = cls.start
            if cls.stop:
                ret = self.getlayer(cls.start, nb=cls.stop, **(cls.step or {}))
            else:
                ret = self.getlayer(cls.start, **(cls.step or {}))
        else:
            lname = cls
            ret = self.getlayer(cls)
        if ret is None:
            if isinstance(lname, type):
                name = lname.__name__
            elif not isinstance(lname, bytes):
                name = repr(lname)
            else:
                name = cast(str, lname)
            raise IndexError("Layer [%s] not found" % name)
        return ret

    def __delitem__(self, cls):
        # type: (Type[Packet]) -> None
        del self[cls].underlayer.payload

    def __setitem__(self, cls, val):
        # type: (Type[Packet], Packet) -> None
        self[cls].underlayer.payload = val

    def __contains__(self, cls):
        # type: (Union[Type[Packet], str]) -> int
        """
        "cls in self" returns true if self has a layer which is an
        instance of cls.
        """
        return self.haslayer(cls)

    def route(self):
        # type: () -> Tuple[Optional[str], Optional[str], Optional[str]]
        return self.payload.route()

    def fragment(self, *args, **kargs):
        # type: (*Any, **Any) -> List[Packet]
        return self.payload.fragment(*args, **kargs)

    def display(self, *args, **kargs):  # Deprecated. Use show()
        # type: (*Any, **Any) -> None
        """Deprecated. Use show() method."""
        self.show(*args, **kargs)

    def break_highlight_field(self, highlight_field):
        # type(str) -> Tuple[str, str]:
        if ":" not in highlight_field:
            msg = f"This is unexpected structure: {highlight_field}"
            raise ValueError(msg)

        values = highlight_field.split(":")
        return values


    def _show_or_dump(self,
                      dump=False,  # type: bool
                      indent=3,  # type: int
                      lvl="",  # type: str
                      label_lvl="",  # type: str
                      first_call=True,  # type: bool
                      highlight_fields=[] # type: List[str]
                      ):
        # type: (...) -> Optional[str]
        """
        Internal method that shows or dumps a hierarchical view of a packet.
        Called by show.

        :param dump: determine if it prints or returns the string value
        :param int indent: the size of indentation for each layer
        :param str lvl: additional information about the layer lvl
        :param str label_lvl: additional information about the layer fields
        :param first_call: determine if the current function is the first
        :return: return a hierarchical view if dump, else print it
        """

        if dump:
            from scapy.themes import ColorTheme, AnsiColorTheme
            ct: ColorTheme = AnsiColorTheme()  # No color for dump output
        else:
            ct = conf.color_theme
        s = "%s%s %s %s\n" % (label_lvl,
                              ct.punct("###["),
                              ct.layer_name(self.name),
                              ct.punct("]###"))
        fields = self.fields_desc.copy()
        while fields:
            f = fields.pop(0)
            if isinstance(f, ConditionalField) and not f._evalcond(self):
                continue
            if hasattr(f, "fields"):  # Field has subfields
                s += "%s  %s =\n" % (
                    label_lvl + lvl,
                    ct.depreciate_field_name(f.name),
                )
                lvl += " " * indent * self.show_indent
                for i, fld in enumerate(x for x in f.fields if hasattr(self, x.name)):
                    fields.insert(i, fld)
                continue
            if isinstance(f, Emph) or f in conf.emph:
                ncol = ct.emph_field_name
                vcol = ct.emph_field_value
            else:
                ncol = ct.field_name
                vcol = ct.field_value

            pad = max(0, 10 - len(f.name)) * " "
            fvalue = self.getfieldval(f.name)

            # Check if we should highlight the field as fuzzed
            highlight_value = False
            sub_highlight_fields = highlight_fields
            for highlight_field in highlight_fields:
                values = self.break_highlight_field(highlight_field)
                # Highlighting can be either:
                #  2 -> Holder and field
                #  4 -> Holder, field, item in list and field (like ip IPv4 with Option) = 'IP:options:0:pointer'

                if len(values) == 2:
                    layer_name = values[0]
                    field_name = values[1]
                    if layer_name == ct.layer_name(self.name):
                        if field_name == f.name:
                            highlight_value = True
                            break
                    
                if len(values) == 4:
                    layer_name = values[0]
                    field_name = values[1]
                    if layer_name == ct.layer_name(self.name):
                        if field_name == f.name:
                            # Combine the fvalue[0] with the rest
                            #  IP:options:0:pointer => "IP Option ..:pointer"
                            #  IP Option comes from the fvalue[0]
                            sub_highlight_field = values[2] + ":" + fvalue[0].name + ":" + ":".join(values[3:])
                            sub_highlight_fields = [sub_highlight_field]

            if isinstance(fvalue, Packet) or (f.islist and f.holds_packets and isinstance(fvalue, list)):  # noqa: E501
                s += "%s  %s%s%s%s\n" % (label_lvl + lvl,
                                         ct.punct("\\"),
                                         ncol(f.name),
                                         pad,
                                         ct.punct("\\"))
                fvalue_gen = SetGen(
                    fvalue,
                    _iterpacket=0
                )  # type: SetGen[Packet]
                for idx, fvalue in enumerate(fvalue_gen):
                    relevant_highlight_fields = []
                    idx_highlight = None
                    try:
                        sub_highlight_field = sub_highlight_fields[idx].split(":")
                        idx_highlight = int(sub_highlight_field[0])
                    except Exception:
                        pass

                    if idx == idx_highlight:
                        relevant_highlight_fields = [":".join(sub_highlight_field[1:])]
                        relevant_highlight_fields += sub_highlight_fields[1:]

                    s += fvalue._show_or_dump(dump=dump, indent=indent, label_lvl=label_lvl + lvl + "   |", first_call=False, highlight_fields=relevant_highlight_fields)  # noqa: E501
            else:
                begn = "%s  %s%s%s " % (label_lvl + lvl,
                                        ncol(f.name),
                                        pad,
                                        ct.punct("="),)
                reprval = f.i2repr(self, fvalue)
                if isinstance(reprval, str):
                    reprval = reprval.replace("\n", "\n" + " " * (len(label_lvl) +  # noqa: E501
                                                                  len(lvl) +
                                                                  len(f.name) +
                                                                  4))
                if highlight_value:
                    reprval += " (fuzzed)"
                s += "%s%s\n" % (begn, vcol(reprval))
        if self.payload:
            s += self.payload._show_or_dump(  # type: ignore
                dump=dump,
                indent=indent,
                lvl=lvl + (" " * indent * self.show_indent),
                label_lvl=label_lvl,
                first_call=False,
                highlight_fields=highlight_fields
            )

        if first_call and not dump:
            print(s)
            return None
        else:
            return s

    def show(self, dump=False, indent=3, lvl="", label_lvl="", highlight_fields=[]):
        # type: (bool, int, str, str, List[str]) -> Optional[Any]
        """
        Prints or returns (when "dump" is true) a hierarchical view of the
        packet.

        :param dump: determine if it prints or returns the string value
        :param int indent: the size of indentation for each layer
        :param str lvl: additional information about the layer lvl
        :param str label_lvl: additional information about the layer fields
        :return: return a hierarchical view if dump, else print it
        """
        return self._show_or_dump(dump, indent, lvl, label_lvl, True, highlight_fields)

    def show2(self, dump=False, indent=3, lvl="", label_lvl="", highlight_fields=[]):
        # type: (bool, int, str, str, List[str]) -> Optional[Any]
        """
        Prints or returns (when "dump" is true) a hierarchical view of an
        assembled version of the packet, so that automatic fields are
        calculated (checksums, etc.)

        :param dump: determine if it prints or returns the string value
        :param int indent: the size of indentation for each layer
        :param str lvl: additional information about the layer lvl
        :param str label_lvl: additional information about the layer fields
        :return: return a hierarchical view if dump, else print it
        """
        return self.__class__(raw(self)).show(dump, indent, lvl, label_lvl, highlight_fields)

    def sprintf(self, fmt, relax=1):
        # type: (str, int) -> str
        """
        sprintf(format, [relax=1]) -> str

        Where format is a string that can include directives. A directive
        begins and ends by % and has the following format:
        ``%[fmt[r],][cls[:nb].]field%``

        :param fmt: is a classic printf directive, "r" can be appended for raw
          substitution:
          (ex: IP.flags=0x18 instead of SA), nb is the number of the layer
          (ex: for IP/IP packets, IP:2.src is the src of the upper IP layer).
          Special case : "%.time%" is the creation time.
          Ex::

            p.sprintf(
              "%.time% %-15s,IP.src% -> %-15s,IP.dst% %IP.chksum% "
              "%03xr,IP.proto% %r,TCP.flags%"
            )

          Moreover, the format string can include conditional statements. A
          conditional statement looks like : {layer:string} where layer is a
          layer name, and string is the string to insert in place of the
          condition if it is true, i.e. if layer is present. If layer is
          preceded by a "!", the result is inverted. Conditions can be
          imbricated. A valid statement can be::

            p.sprintf("This is a{TCP: TCP}{UDP: UDP}{ICMP:n ICMP} packet")
            p.sprintf("{IP:%IP.dst% {ICMP:%ICMP.type%}{TCP:%TCP.dport%}}")

          A side effect is that, to obtain "{" and "}" characters, you must use
          "%(" and "%)".
        """

        escape = {"%": "%",
                  "(": "{",
                  ")": "}"}

        # Evaluate conditions
        while "{" in fmt:
            i = fmt.rindex("{")
            j = fmt[i + 1:].index("}")
            cond = fmt[i + 1:i + j + 1]
            k = cond.find(":")
            if k < 0:
                raise Scapy_Exception("Bad condition in format string: [%s] (read sprintf doc!)" % cond)  # noqa: E501
            cond, format_ = cond[:k], cond[k + 1:]
            res = False
            if cond[0] == "!":
                res = True
                cond = cond[1:]
            if self.haslayer(cond):
                res = not res
            if not res:
                format_ = ""
            fmt = fmt[:i] + format_ + fmt[i + j + 2:]

        # Evaluate directives
        s = ""
        while "%" in fmt:
            i = fmt.index("%")
            s += fmt[:i]
            fmt = fmt[i + 1:]
            if fmt and fmt[0] in escape:
                s += escape[fmt[0]]
                fmt = fmt[1:]
                continue
            try:
                i = fmt.index("%")
                sfclsfld = fmt[:i]
                fclsfld = sfclsfld.split(",")
                if len(fclsfld) == 1:
                    f = "s"
                    clsfld = fclsfld[0]
                elif len(fclsfld) == 2:
                    f, clsfld = fclsfld
                else:
                    raise Scapy_Exception
                if "." in clsfld:
                    cls, fld = clsfld.split(".")
                else:
                    cls = self.__class__.__name__
                    fld = clsfld
                num = 1
                if ":" in cls:
                    cls, snum = cls.split(":")
                    num = int(snum)
                fmt = fmt[i + 1:]
            except Exception:
                raise Scapy_Exception("Bad format string [%%%s%s]" % (fmt[:25], fmt[25:] and "..."))  # noqa: E501
            else:
                if fld == "time":
                    val = time.strftime(
                        "%H:%M:%S.%%06i",
                        time.localtime(float(self.time))
                    ) % int((self.time - int(self.time)) * 1000000)
                elif cls == self.__class__.__name__ and hasattr(self, fld):
                    if num > 1:
                        val = self.payload.sprintf("%%%s,%s:%s.%s%%" % (f, cls, num - 1, fld), relax)  # noqa: E501
                        f = "s"
                    else:
                        try:
                            val = self.getfieldval(fld)
                        except AttributeError:
                            val = getattr(self, fld)
                        if f[-1] == "r":  # Raw field value
                            f = f[:-1]
                            if not f:
                                f = "s"
                        else:
                            if fld in self.fieldtype:
                                val = self.fieldtype[fld].i2repr(self, val)
                else:
                    val = self.payload.sprintf("%%%s%%" % sfclsfld, relax)
                    f = "s"
                s += ("%" + f) % val

        s += fmt
        return s

    def mysummary(self):
        # type: () -> str
        """DEV: can be overloaded to return a string that summarizes the layer.
           Only one mysummary() is used in a whole packet summary: the one of the upper layer,  # noqa: E501
           except if a mysummary() also returns (as a couple) a list of layers whose  # noqa: E501
           mysummary() must be called if they are present."""
        return ""

    def _do_summary(self):
        # type: () -> Tuple[int, str, List[Any]]
        found, s, needed = self.payload._do_summary()
        ret = ""
        if not found or self.__class__ in needed:
            ret = self.mysummary()
            if isinstance(ret, tuple):
                ret, n = ret
                needed += n
        if ret or needed:
            found = 1
        if not ret:
            ret = self.__class__.__name__ if self.show_summary else ""
        if self.__class__ in conf.emph:
            impf = []
            for f in self.fields_desc:
                if f in conf.emph:
                    impf.append("%s=%s" % (f.name, f.i2repr(self, self.getfieldval(f.name))))  # noqa: E501
            ret = "%s [%s]" % (ret, " ".join(impf))
        if ret and s:
            ret = "%s / %s" % (ret, s)
        else:
            ret = "%s%s" % (ret, s)
        return found, ret, needed

    def summary(self, intern=0):
        # type: (int) -> str
        """Prints a one line summary of a packet."""
        return self._do_summary()[1]

    def lastlayer(self, layer=None):
        # type: (Optional[Packet]) -> Packet
        """Returns the uppest layer of the packet"""
        return self.payload.lastlayer(self)

    def decode_payload_as(self, cls):
        # type: (Type[Packet]) -> None
        """Reassembles the payload and decode it using another packet class"""
        s = raw(self.payload)
        self.payload = cls(s, _internal=1, _underlayer=self)
        pp = self
        while pp.underlayer is not None:
            pp = pp.underlayer
        self.payload.dissection_done(pp)

    def _command_fields(self):
        # type: () -> Iterator[Tuple[str, Any]]
        """
        The (name, value) pairs command() renders: everything set in
        'fields', then every field fuzz() left a volatile on.

        fuzz() installs its random values as *defaults*, and command()
        reports 'fields', so a packet mid-walk used to render only the one
        field forward() had promoted - the other field of a complexity-2
        pair, and everything else fuzz() touched, was missing from the
        example entirely. Evaluating that example rebuilt a different
        packet than the one that was sent, which is the only thing the
        example is for.

        The volatiles are rendered by the value they resolve to, not by
        their constructor: '_fix()' is exactly what build() will pack, so
        this is what makes the example reproduce the bytes. A volatile the
        caller put in 'fields' themselves (IP(ttl=RandByte())) is left
        alone and still renders as 'RandByte()' - that packet is a
        generator, and re-evaluating it is meant to draw again.
        """
        for name, value in self.fields.items():
            yield (name, value)

        # An overloaded field (IP.proto under a TCP payload) is skipped:
        # it isn't fuzzable - return_relevant_fields() skips it too - and
        # the overload is what both the sent and the rebuilt packet use, so
        # naming it in the example would pin the wrong value.
        for field in self.fields_desc:
            name = field.name
            if name in self.fields or name in self.overloaded_fields:
                continue

            value = self.default_fields.get(name)
            if isinstance(value, VolatileValue):
                yield (name, value._fix())
            elif self._is_fuzzed_list(value):
                yield (name, [
                    item._fix() if isinstance(item, VolatileValue) else item
                    for item in value
                ])

    def _command(self, json=False):
        # type: (bool) -> List[Tuple[str, Any]]
        """
        Internal method used to generate command() and json()
        """
        f = []
        iterator: Iterator[Tuple[str, Any]]
        if json:
            iterator = ((x.name, self.getfieldval(x.name)) for x in self.fields_desc)
        else:
            iterator = self._command_fields()
        for fn, fv in iterator:
            fld = self.get_field(fn)
            if isinstance(fv, (list, dict, set)) and not fv and not fld.default:
                continue
            if isinstance(fv, Packet):
                if json:
                    fv = {k: v for (k, v) in fv._command(json=True)}
                else:
                    fv = fv.command()
            elif fld.islist and fld.holds_packets and isinstance(fv, list):
                if json:
                    fv = [
                        {k: v for (k, v) in x}
                        for x in map(lambda y: Packet._command(y, json=True), fv)
                    ]
                else:
                    fv = "[%s]" % ",".join(map(Packet.command, fv))
            elif fld.islist and isinstance(fv, list):
                if json:
                    fv = [
                        getattr(x, 'command', lambda: repr(x))()
                        for x in fv
                    ]
                else:
                    fv = "[%s]" % ",".join(
                        getattr(x, 'command', lambda: repr(x))()
                        for x in fv
                    )
            elif isinstance(fv, FlagValue):
                fv = int(fv)
            elif callable(getattr(fv, 'command', None)):
                fv = fv.command(json=json)
            else:
                if json:
                    if isinstance(fv, bytes):
                        fv = fv.decode("utf-8", errors="backslashreplace")
                    else:
                        fv = fld.i2h(self, fv)
                else:
                    fv = fld.i2h(self, fv)
                    if isinstance(fv, FlagValue):
                        # A flags field's i2h() wraps the int back up, and
                        # repr() of that is '<Flag 2 (S)>' - not something
                        # the command can be evaluated back from. Reached
                        # when the value comes in as a plain int, which is
                        # what a fuzzed field resolves to (a FlagValue set
                        # through the packet is caught further up).
                        fv = int(fv)
                    fv = repr(fv)
            f.append((fn, fv))
        return f

    def command(self):
        # type: () -> str
        """
        Returns a string representing the command you have to type to
        obtain the same packet
        """
        c = "%s(%s)" % (
            self.__class__.__name__,
            ", ".join("%s=%s" % x for x in self._command())
        )
        pc = self.payload.command()
        if pc:
            c += "/" + pc
        return c

    def json(self):
        # type: () -> str
        """
        Returns a JSON representing the packet.

        Please note that this cannot be used for bijective usage: data loss WILL occur,
        so it will not make sense to try to rebuild the packet from the output.
        This must only be used for a grepping/displaying purpose.
        """
        dump = json.dumps({k: v for (k, v) in self._command(json=True)})
        pc = self.payload.json()
        if pc:
            dump = dump[:-1] + ", \"payload\": %s}" % pc
        return dump


class NoPayload(Packet):
    def __new__(cls, *args, **kargs):
        # type: (Type[Packet], *Any, **Any) -> NoPayload
        singl = cls.__dict__.get("__singl__")
        if singl is None:
            cls.__singl__ = singl = Packet.__new__(cls)
            Packet.__init__(singl)
        return singl  # type: ignore

    def __init__(self, *args, **kargs):
        # type: (*Any, **Any) -> None
        pass

    def dissection_done(self, pkt):
        # type: (Packet) -> None
        pass

    def add_payload(self, payload):
        # type: (Union[Packet, bytes]) -> NoReturn
        raise Scapy_Exception("Can't add payload to NoPayload instance")

    def remove_payload(self):
        # type: () -> None
        pass

    def add_underlayer(self, underlayer):
        # type: (Any) -> None
        pass

    def remove_underlayer(self, other):
        # type: (Packet) -> None
        pass

    def add_parent(self, parent):
        # type: (Any) -> None
        pass

    def remove_parent(self, other):
        # type: (Packet) -> None
        pass

    def copy(self):
        # type: () -> NoPayload
        return self

    def clear_cache(self):
        # type: () -> None
        pass

    def __repr__(self):
        # type: () -> str
        return ""

    def __str__(self):
        # type: () -> str
        return ""

    def __bytes__(self):
        # type: () -> bytes
        return b""

    def __nonzero__(self):
        # type: () -> bool
        return False
    __bool__ = __nonzero__

    def do_build(self):
        # type: () -> bytes
        return b""

    def build(self):
        # type: () -> bytes
        return b""

    def build_padding(self):
        # type: () -> bytes
        return b""

    def build_done(self, p):
        # type: (bytes) -> bytes
        return p

    def build_ps(self, internal=0):
        # type: (int) -> Tuple[bytes, List[Any]]
        return b"", []

    def getfieldval(self, attr):
        # type: (str) -> NoReturn
        raise AttributeError(attr)

    def getfield_and_val(self, attr):
        # type: (str) -> NoReturn
        raise AttributeError(attr)

    def setfieldval(self, attr, val):
        # type: (str, Any) -> NoReturn
        raise AttributeError(attr)

    def delfieldval(self, attr):
        # type: (str) -> NoReturn
        raise AttributeError(attr)

    def hide_defaults(self):
        # type: () -> None
        pass

    def __iter__(self):
        # type: () -> Iterator[Packet]
        return iter([])

    def __eq__(self, other):
        # type: (Any) -> bool
        if isinstance(other, NoPayload):
            return True
        return False

    def hashret(self):
        # type: () -> bytes
        return b""

    def answers(self, other):
        # type: (Packet) -> bool
        return isinstance(other, (NoPayload, conf.padding_layer))  # noqa: E501

    def haslayer(self, cls, _subclass=None):
        # type: (Union[Type[Packet], str], Optional[bool]) -> int
        return 0

    def getlayer(self,
                 cls,  # type: Union[int, Type[Packet], str]
                 nb=1,  # type: int
                 _track=None,  # type: Optional[List[int]]
                 _subclass=None,  # type: Optional[bool]
                 **flt  # type: Any
                 ):
        # type: (...) -> Optional[Packet]
        if _track is not None:
            _track.append(nb)
        return None

    def fragment(self, *args, **kargs):
        # type: (*Any, **Any) -> List[Packet]
        raise Scapy_Exception("cannot fragment this packet")

    def show(self, dump=False, indent=3, lvl="", label_lvl=""):
        # type: (bool, int, str, str) -> None
        pass

    def sprintf(self, fmt, relax=1):
        # type: (str, int) -> str
        if relax:
            return "??"
        else:
            raise Scapy_Exception("Format not found [%s]" % fmt)

    def _do_summary(self):
        # type: () -> Tuple[int, str, List[Any]]
        return 0, "", []

    def layers(self):
        # type: () -> List[Type[Packet]]
        return []

    def lastlayer(self, layer=None):
        # type: (Optional[Packet]) -> Packet
        return layer or self

    def command(self):
        # type: () -> str
        return ""

    def json(self):
        # type: () -> str
        return ""

    def route(self):
        # type: () -> Tuple[None, None, None]
        return (None, None, None)


####################
#  packet classes  #
####################


class Raw(Packet):
    name = "Raw"
    fields_desc = [StrField("load", b"")]

    def __init__(self, _pkt=b"", *args, **kwargs):
        # type: (bytes, *Any, **Any) -> None
        if _pkt and not isinstance(_pkt, bytes):
            if isinstance(_pkt, tuple):
                _pkt, bn = _pkt
                _pkt = bytes_encode(_pkt), bn
            else:
                _pkt = bytes_encode(_pkt)
        super(Raw, self).__init__(_pkt, *args, **kwargs)

    def answers(self, other):
        # type: (Packet) -> int
        return 1

    def mysummary(self):
        # type: () -> str
        cs = conf.raw_summary
        if cs:
            if callable(cs):
                return "Raw %s" % cs(self.load)
            else:
                return "Raw %r" % self.load
        return Packet.mysummary(self)


class Padding(Raw):
    name = "Padding"

    def self_build(self):
        # type: (Optional[Any]) -> bytes
        return b""

    def build_padding(self):
        # type: () -> bytes
        return (
            bytes_encode(self.load) if self.raw_packet_cache is None
            else self.raw_packet_cache
        ) + self.payload.build_padding()


conf.raw_layer = Raw
conf.padding_layer = Padding
if conf.default_l2 is None:
    conf.default_l2 = Raw

#################
#  Bind layers  #
#################


def bind_bottom_up(lower,  # type: Type[Packet]
                   upper,  # type: Type[Packet]
                   __fval=None,  # type: Optional[Any]
                   **fval  # type: Any
                   ):
    # type: (...) -> None
    r"""Bind 2 layers for dissection.
    The upper layer will be chosen for dissection on top of the lower layer, if
    ALL the passed arguments are validated. If multiple calls are made with
    the same layers, the last one will be used as default.

    ex:
        >>> bind_bottom_up(Ether, SNAP, type=0x1234)
        >>> Ether(b'\xff\xff\xff\xff\xff\xff\xd0P\x99V\xdd\xf9\x124\x00\x00\x00\x00\x00')  # noqa: E501
        <Ether  dst=ff:ff:ff:ff:ff:ff src=d0:50:99:56:dd:f9 type=0x1234 |<SNAP  OUI=0x0 code=0x0 |>>  # noqa: E501
    """
    if __fval is not None:
        fval.update(__fval)
    lower.payload_guess = lower.payload_guess[:]
    lower.payload_guess.append((fval, upper))


def bind_top_down(lower,  # type: Type[Packet]
                  upper,  # type: Type[Packet]
                  __fval=None,  # type: Optional[Any]
                  **fval  # type: Any
                  ):
    # type: (...) -> None
    """Bind 2 layers for building.
    When the upper layer is added as a payload of the lower layer, all the
    arguments will be applied to them.

    ex:
        >>> bind_top_down(Ether, SNAP, type=0x1234)
        >>> Ether()/SNAP()
        <Ether  type=0x1234 |<SNAP  |>>
    """
    if __fval is not None:
        fval.update(__fval)
    upper._overload_fields = upper._overload_fields.copy()  # type: ignore
    upper._overload_fields[lower] = fval


@conf.commands.register
def bind_layers(lower,  # type: Type[Packet]
                upper,  # type: Type[Packet]
                __fval=None,  # type: Optional[Dict[str, int]]
                **fval  # type: Any
                ):
    # type: (...) -> None
    """Bind 2 layers on some specific fields' values.

    It makes the packet being built and dissected when the arguments
    are present.

    This function calls both bind_bottom_up and bind_top_down, with
    all passed arguments.

    Please have a look at their docs:
     - help(bind_bottom_up)
     - help(bind_top_down)
     """
    if __fval is not None:
        fval.update(__fval)
    bind_top_down(lower, upper, **fval)
    bind_bottom_up(lower, upper, **fval)


def split_bottom_up(lower,  # type: Type[Packet]
                    upper,  # type: Type[Packet]
                    __fval=None,  # type: Optional[Any]
                    **fval  # type: Any
                    ):
    # type: (...) -> None
    """This call un-links an association that was made using bind_bottom_up.
    Have a look at help(bind_bottom_up)
    """
    if __fval is not None:
        fval.update(__fval)

    def do_filter(params, cls):
        # type: (Dict[str, int], Type[Packet]) -> bool
        params_is_invalid = any(
            k not in params or params[k] != v for k, v in fval.items()
        )
        return cls != upper or params_is_invalid
    lower.payload_guess = [x for x in lower.payload_guess if do_filter(*x)]


def split_top_down(lower,  # type: Type[Packet]
                   upper,  # type: Type[Packet]
                   __fval=None,  # type: Optional[Any]
                   **fval  # type: Any
                   ):
    # type: (...) -> None
    """This call un-links an association that was made using bind_top_down.
    Have a look at help(bind_top_down)
    """
    if __fval is not None:
        fval.update(__fval)
    if lower in upper._overload_fields:
        ofval = upper._overload_fields[lower]
        if any(k not in ofval or ofval[k] != v for k, v in fval.items()):
            return
        upper._overload_fields = upper._overload_fields.copy()  # type: ignore
        del upper._overload_fields[lower]


@conf.commands.register
def split_layers(lower,  # type: Type[Packet]
                 upper,  # type: Type[Packet]
                 __fval=None,  # type: Optional[Any]
                 **fval  # type: Any
                 ):
    # type: (...) -> None
    """Split 2 layers previously bound.
    This call un-links calls bind_top_down and bind_bottom_up. It is the opposite of  # noqa: E501
    bind_layers.

    Please have a look at their docs:
     - help(split_bottom_up)
     - help(split_top_down)
    """
    if __fval is not None:
        fval.update(__fval)
    split_bottom_up(lower, upper, **fval)
    split_top_down(lower, upper, **fval)


@conf.commands.register
def explore(layer=None):
    # type: (Optional[str]) -> None
    """Function used to discover the Scapy layers and protocols.
    It helps to see which packets exists in contrib or layer files.

    params:
     - layer: If specified, the function will explore the layer. If not,
              the GUI mode will be activated, to browse the available layers

    examples:
      >>> explore()  # Launches the GUI
      >>> explore("dns")  # Explore scapy.layers.dns
      >>> explore("http2")  # Explore scapy.contrib.http2
      >>> explore(scapy.layers.bluetooth4LE)

    Note: to search a packet by name, use ls("name") rather than explore.
    """
    if layer is None:  # GUI MODE
        if not conf.interactive:
            raise Scapy_Exception("explore() GUI-mode cannot be run in "
                                  "interactive mode. Please provide a "
                                  "'layer' parameter !")
        # 0 - Imports
        try:
            import prompt_toolkit
        except ImportError:
            raise ImportError("prompt_toolkit is not installed ! "
                              "You may install IPython, which contains it, via"
                              " `pip install ipython`")
        if not _version_checker(prompt_toolkit, (2, 0)):
            raise ImportError("prompt_toolkit >= 2.0.0 is required !")
        # Only available with prompt_toolkit > 2.0, not released on PyPi yet
        from prompt_toolkit.shortcuts.dialogs import radiolist_dialog, \
            button_dialog
        from prompt_toolkit.formatted_text import HTML
        # Check for prompt_toolkit >= 3.0.0
        call_ptk = lambda x: cast(str, x)  # type: Callable[[Any], str]
        if _version_checker(prompt_toolkit, (3, 0)):
            call_ptk = lambda x: x.run()
        # 1 - Ask for layer or contrib
        btn_diag = button_dialog(
            title="Scapy v%s" % conf.version,
            text=HTML(
                '<style bg="white" fg="red">Chose the type of packets'
                ' you want to explore:</style>'
            ),
            buttons=[
                ("Layers", "layers"),
                ("Contribs", "contribs"),
                ("Cancel", "cancel")
            ])
        action = call_ptk(btn_diag)
        # 2 - Retrieve list of Packets
        if action == "layers":
            # Get all loaded layers
            lvalues = conf.layers.layers()
            # Restrict to layers-only (not contribs) + packet.py and asn1*.py
            values = [x for x in lvalues if ("layers" in x[0] or
                                             "packet" in x[0] or
                                             "asn1" in x[0])]
        elif action == "contribs":
            # Get all existing contribs
            from scapy.main import list_contrib
            cvalues = cast(List[Dict[str, str]], list_contrib(ret=True))
            values = [(x['name'], x['description'])
                      for x in cvalues]
            # Remove very specific modules
            values = [x for x in values if "can" not in x[0]]
        else:
            # Escape/Cancel was pressed
            return
        # Build tree
        if action == "contribs":
            # A tree is a dictionary. Each layer contains a keyword
            # _l which contains the files in the layer, and a _name
            # argument which is its name. The other keys are the subfolders,
            # which are similar dictionaries
            tree = defaultdict(list)  # type: Dict[str, Union[List[Any], Dict[str, Any]]]  # noqa: E501
            for name, desc in values:
                if "." in name:  # Folder detected
                    parts = name.split(".")
                    subtree = tree
                    for pa in parts[:-1]:
                        if pa not in subtree:
                            subtree[pa] = {}
                        # one layer deeper
                        subtree = subtree[pa]  # type: ignore
                        subtree["_name"] = pa  # type: ignore
                    if "_l" not in subtree:
                        subtree["_l"] = []
                    subtree["_l"].append((parts[-1], desc))  # type: ignore
                else:
                    tree["_l"].append((name, desc))  # type: ignore
        elif action == "layers":
            tree = {"_l": values}
        # 3 - Ask for the layer/contrib module to explore
        current = tree  # type: Any
        previous = []  # type: List[Dict[str, Union[List[Any], Dict[str, Any]]]]  # noqa: E501
        while True:
            # Generate tests & form
            folders = list(current.keys())
            _radio_values = [
                ("$" + name, str('[+] ' + name.capitalize()))
                for name in folders if not name.startswith("_")
            ] + current.get("_l", [])  # type: List[str]
            cur_path = ""
            if previous:
                cur_path = ".".join(
                    itertools.chain(
                        (x["_name"] for x in previous[1:]),  # type: ignore
                        (current["_name"],)
                    )
                )
            extra_text = (
                '\n<style bg="white" fg="green">> scapy.%s</style>'
            ) % (action + ("." + cur_path if cur_path else ""))
            # Show popup
            rd_diag = radiolist_dialog(
                values=_radio_values,
                title="Scapy v%s" % conf.version,
                text=HTML(
                    (
                        '<style bg="white" fg="red">Please select a file'
                        'among the following, to see all layers contained in'
                        ' it:</style>'
                    ) + extra_text
                ),
                cancel_text="Back" if previous else "Cancel"
            )
            result = call_ptk(rd_diag)
            if result is None:
                # User pressed "Cancel/Back"
                if previous:  # Back
                    current = previous.pop()
                    continue
                else:  # Cancel
                    return
            if result.startswith("$"):
                previous.append(current)
                current = current[result[1:]]
            else:
                # Enter on layer
                if previous:  # In subfolder
                    result = cur_path + "." + result
                break
        # 4 - (Contrib only): load contrib
        if action == "contribs":
            from scapy.main import load_contrib
            load_contrib(result)
            result = "scapy.contrib." + result
    else:  # NON-GUI MODE
        # We handle layer as a short layer name, full layer name
        # or the module itself
        if isinstance(layer, types.ModuleType):
            layer = layer.__name__
        if isinstance(layer, str):
            if layer.startswith("scapy.layers."):
                result = layer
            else:
                if layer.startswith("scapy.contrib."):
                    layer = layer.replace("scapy.contrib.", "")
                from scapy.main import load_contrib
                load_contrib(layer)
                result_layer, result_contrib = (("scapy.layers.%s" % layer),
                                                ("scapy.contrib.%s" % layer))
                if result_layer in conf.layers.ldict:
                    result = result_layer
                elif result_contrib in conf.layers.ldict:
                    result = result_contrib
                else:
                    raise Scapy_Exception("Unknown scapy module '%s'" % layer)
        else:
            warning("Wrong usage ! Check out help(explore)")
            return

    # COMMON PART
    # Get the list of all Packets contained in that module
    try:
        all_layers = conf.layers.ldict[result]
    except KeyError:
        raise Scapy_Exception("Unknown scapy module '%s'" % layer)
    # Print
    print(conf.color_theme.layer_name("Packets contained in %s:" % result))
    rtlst = []  # type: List[Tuple[Union[str, List[str]], ...]]
    rtlst = [(lay.__name__ or "", cast(str, lay._name) or "") for lay in all_layers]
    print(pretty_list(rtlst, [("Class", "Name")], borders=True))


def _pkt_ls(obj,  # type: Union[Packet, Type[Packet]]
            verbose=False,  # type: bool
            ):
    # type: (...) -> List[Tuple[str, Type[AnyField], str, str, List[str]]]  # noqa: E501
    """Internal function used to resolve `fields_desc` to display it.

    :param obj: a packet object or class
    :returns: a list containing tuples [(name, clsname, clsname_extras,
        default, long_attrs)]
    """
    is_pkt = isinstance(obj, Packet)
    if not issubtype(obj, Packet) and not is_pkt:
        raise ValueError
    fields = []
    for f in obj.fields_desc:
        cur_fld = f
        attrs = []  # type: List[str]
        long_attrs = []  # type: List[str]
        while isinstance(cur_fld, (Emph, ConditionalField)):
            if isinstance(cur_fld, ConditionalField):
                attrs.append(cur_fld.__class__.__name__[:4])
            cur_fld = cur_fld.fld
        name = cur_fld.name
        default = cur_fld.default
        if verbose and isinstance(cur_fld, EnumField) \
           and hasattr(cur_fld, "i2s") and cur_fld.i2s:
            if len(cur_fld.i2s or []) < 50:
                long_attrs.extend(
                    "%s: %d" % (strval, numval)
                    for numval, strval in
                    sorted(cur_fld.i2s.items())
                )
        elif isinstance(cur_fld, MultiEnumField):
            if isinstance(obj, Packet):
                obj_pkt = obj
            else:
                obj_pkt = obj()
            fld_depend = cur_fld.depends_on(obj_pkt)
            attrs.append("Depends on %s" % fld_depend)
            if verbose:
                cur_i2s = cur_fld.i2s_multi.get(
                    cur_fld.depends_on(obj_pkt), {}
                )
                if len(cur_i2s) < 50:
                    long_attrs.extend(
                        "%s: %d" % (strval, numval)
                        for numval, strval in
                        sorted(cur_i2s.items())
                    )
        elif verbose and isinstance(cur_fld, FlagsField):
            names = cur_fld.names
            long_attrs.append(", ".join(names))
        elif isinstance(cur_fld, MultipleTypeField):
            default = cur_fld.dflt.default
            attrs.append(", ".join(
                x[0].__class__.__name__ for x in
                itertools.chain(cur_fld.flds, [(cur_fld.dflt,)])
            ))

        cls = cur_fld.__class__
        class_name_extras = "(%s)" % (
            ", ".join(attrs)
        ) if attrs else ""
        if isinstance(cur_fld, BitField):
            class_name_extras += " (%d bit%s)" % (
                cur_fld.size,
                "s" if cur_fld.size > 1 else ""
            )
        fields.append(
            (name,
             cls,
             class_name_extras,
             repr(default),
             long_attrs)
        )
    return fields


@conf.commands.register
def ls(obj=None,  # type: Optional[Union[str, Packet, Type[Packet]]]
       case_sensitive=False,  # type: bool
       verbose=False  # type: bool
       ):
    # type: (...) -> None
    """List  available layers, or infos on a given layer class or name.

    :param obj: Packet / packet name to use
    :param case_sensitive: if obj is a string, is it case sensitive?
    :param verbose:
    """
    if obj is None or isinstance(obj, str):
        tip = False
        if obj is None:
            tip = True
            all_layers = sorted(conf.layers, key=lambda x: x.__name__)
        else:
            pattern = re.compile(
                obj,
                0 if case_sensitive else re.I
            )
            # We first order by accuracy, then length
            if case_sensitive:
                sorter = lambda x: (x.__name__.index(obj), len(x.__name__))
            else:
                obj = obj.lower()
                sorter = lambda x: (x.__name__.lower().index(obj),
                                    len(x.__name__))
            all_layers = sorted((layer for layer in conf.layers
                                 if (isinstance(layer.__name__, str) and
                                     pattern.search(layer.__name__)) or
                                 (isinstance(layer.name, str) and
                                     pattern.search(layer.name))),
                                key=sorter)
        for layer in all_layers:
            print("%-10s : %s" % (layer.__name__, layer._name))
        if tip and conf.interactive:
            print("\nTIP: You may use explore() to navigate through all "
                  "layers using a clear GUI")
    else:
        try:
            fields = _pkt_ls(
                obj,
                verbose=verbose
            )
            is_pkt = isinstance(obj, Packet)
            # Print
            for fname, cls, clsne, dflt, long_attrs in fields:
                clsinfo = cls.__name__ + " " + clsne
                print("%-10s : %-35s =" % (fname, clsinfo), end=' ')
                if is_pkt:
                    print("%-15r" % (getattr(obj, fname),), end=' ')
                print("(%r)" % (dflt,))
                for attr in long_attrs:
                    print("%-15s%s" % ("", attr))
            # Restart for payload if any
            if is_pkt:
                obj = cast(Packet, obj)
                if isinstance(obj.payload, NoPayload):
                    return
                print("--")
                ls(obj.payload)
        except ValueError:
            print("Not a packet class or name. Type 'ls()' to list packet classes.")  # noqa: E501


@conf.commands.register
def rfc(cls, ret=False, legend=True):
    # type: (Type[Packet], bool, bool) -> Optional[str]
    """
    Generate an RFC-like representation of a packet def.

    :param cls: the Packet class
    :param ret: return the result instead of printing (def. False)
    :param legend: show text under the diagram (default True)

    Ex::

        >>> rfc(Ether)

    """
    if not issubclass(cls, Packet):
        raise TypeError("Packet class expected")
    cur_len = 0
    cur_line = []
    lines = []
    # Get the size (width) that a field will take
    # when formatted, from its length in bits
    clsize = lambda x: 2 * x - 1  # type: Callable[[int], int]
    ident = 0  # Fields UUID

    # Generate packet groups
    def _iterfields() -> Iterator[Tuple[str, int]]:
        for f in cls.fields_desc:
            # Fancy field name
            fname = f.name.upper().replace("_", " ")
            fsize = int(f.sz * 8)
            yield fname, fsize
            # Add padding optionally
            if isinstance(f, PadField):
                if isinstance(f._align, tuple):
                    pad = - cur_len % (f._align[0] * 8)
                else:
                    pad = - cur_len % (f._align * 8)
                if pad:
                    yield "padding", pad
    for fname, flen in _iterfields():
        cur_len += flen
        ident += 1
        # The field might exceed the current line or
        # take more than one line. Copy it as required
        while True:
            over = max(0, cur_len - 32)  # Exceed
            len1 = clsize(flen - over)  # What fits
            cur_line.append((fname[:len1], len1, ident))
            if cur_len >= 32:
                # Current line is full. start a new line
                lines.append(cur_line)
                cur_len = flen = over
                fname = ""  # do not repeat the field
                cur_line = []
                if not over:
                    # there is no data left
                    break
            else:
                # End of the field
                break
    # Add the last line if un-finished
    if cur_line:
        lines.append(cur_line)
    # Calculate separations between lines
    seps = []
    seps.append("+-" * 32 + "+\n")
    for i in range(len(lines) - 1):
        # Start with a full line
        sep = "+-" * 32 + "+\n"
        # Get the line above and below the current
        # separation
        above, below = lines[i], lines[i + 1]
        # The last field of above is shared with below
        if above[-1][2] == below[0][2]:
            # where the field in "above" starts
            pos_above = sum(x[1] for x in above[:-1]) + len(above[:-1]) - 1
            # where the field in "below" ends
            pos_below = below[0][1]
            if pos_above < pos_below:
                # they are overlapping.
                # Now crop the space between those pos
                # and fill it with " "
                pos_above = pos_above + pos_above % 2
                sep = (
                    sep[:1 + pos_above] +
                    " " * (pos_below - pos_above) +
                    sep[1 + pos_below:]
                )
        # line is complete
        seps.append(sep)
    # Graph
    result = ""
    # Bytes markers
    result += " " + (" " * 19).join(
        str(x) for x in range(4)
    ) + "\n"
    # Bits markers
    result += " " + " ".join(
        str(x % 10) for x in range(32)
    ) + "\n"
    # Add fields and their separations
    for line, sep in zip(lines, seps):
        result += sep
        for elt, flen, _ in line:
            result += "|" + elt.center(flen, " ")
        result += "|\n"
    result += "+-" * (cur_len or 32) + "+\n"
    # Annotate with the figure name
    if legend:
        result += "\n" + ("Fig. " + cls.__name__).center(66, " ")
    # return if asked for, else print
    if ret:
        return result
    print(result)
    return None


#############
#  Fuzzing  #
#############

_P = TypeVar('_P', bound=Packet)


def _unwrap_field(f):
    # type: (AnyField) -> Any
    """
    Peel away single-field container wrappers (MayEnd, Emph, PadField,
    TrailerField, ActionField, ...) to get at the real field underneath, so
    fuzz() can tell e.g. a MayEnd(PacketListField(...)) apart from a plain
    scalar field. MultipleTypeField is deliberately left alone - it has its
    own dedicated handling below and isn't a single-field wrapper.
    """
    while isinstance(f, _FieldContainer) and not isinstance(f, MultipleTypeField):
        f = f.fld
    return f


@conf.commands.register
def _fuzz_list_items(fld, values):
    # type: (Any, List[Any]) -> List[Any]
    """
    A per-item randval for each item of a list-valued field.

    fld.randval() would build one value from the *container's* own fmt
    (e.g. FieldListField's default "!H"), which has nothing to do with the
    type or range of the items it holds - and assigning that to the field
    replaces the caller's whole list with a single scalar. The items are
    what gets fuzzed, so each one gets a randval from the inner field's
    type instead, carrying the caller's own item as its default so the
    walk fuzzes around the value that was set rather than losing it.
    return_relevant_fields()/locate_field() know how to target list items
    directly ("Layer:field:index").

    An item whose type has no randval is left exactly as it was.
    """
    inner = getattr(fld, 'field', None)
    if inner is None:
        # Not a container (a MultipleTypeField can resolve to a plain
        # StrField while the value the caller set is still a list) - the
        # field's own randval is then the right per-item type.
        inner = fld

    new_list = []
    for item in values:
        try:
            item_rnd = inner.randval()
        except Exception:
            item_rnd = None
        if item_rnd is None:
            new_list.append(item)
        else:
            item_rnd.default = item
            new_list.append(item_rnd)
    return new_list


def fuzz(p,  # type: _P
         _inplace=0,  # type: int
         ):
    # type: (...) -> _P
    """
    Transform a layer into a fuzzy layer by replacing some default values
    by random objects.

    :param p: the Packet instance to fuzz
    :return: the fuzzed packet.
    """
    if not _inplace:
        p = p.copy()
    q = cast(Packet, p)
    while not isinstance(q, NoPayload):
        new_default_fields = {}
        multiple_type_fields = []  # type: List[str]
        for f in q.fields_desc:
            real_f = _unwrap_field(f)
            # A PacketListField/FieldListField can itself be wrapped in a
            # ConditionalField (e.g. RadioTap.Ext). When that condition
            # isn't currently met, getattr(q, f.name) returns None (that's
            # ConditionalField.i2h()'s contract), not the field's actual
            # list default - so these branches must not run at all then,
            # same as the generic scalar branch below already guards for.
            field_is_active = not isinstance(f, ConditionalField) or f._evalcond(q)

            if field_is_active and hasattr(real_f, 'fuzz_current_value'):
                # Optional hook: lets a field type produce something that
                # preserves/extends the packet's CURRENT value for this
                # field (e.g. DHCPOptionsField replacing each of the
                # user's actual options' values with a properly-typed
                # randval, keeping option names/order intact) instead of
                # generating something unrelated from scratch the way a
                # plain f.randval() call would. Return None to fall
                # through to the generic handling below.
                rnd = real_f.fuzz_current_value(q)
                if rnd is not None:
                    new_default_fields[f.name] = rnd
                    continue

            if isinstance(real_f, PacketListField):
                if field_is_active:
                    for r in getattr(q, f.name):
                        fuzz(r, _inplace=1)
            elif isinstance(real_f, FieldListField):
                # Fuzz each item with the inner field's own randval, keeping
                # the list shape intact - see _fuzz_list_items().
                current_list = getattr(q, f.name) if field_is_active else None
                if isinstance(current_list, list) and len(current_list) > 0:
                    new_default_fields[f.name] = _fuzz_list_items(
                        real_f, current_list)
            elif isinstance(real_f, MultipleTypeField):
                # the type of the field will depend on others
                multiple_type_fields.append(f.name)
            elif f.default is not None:
                if not isinstance(f, ConditionalField) or f._evalcond(q):
                    rnd = f.randval()

                    # Store the default value of the field
                    rnd.default = f.default
                    if rnd is not None:
                        # print(f"Adding: {f.name} with {f.default=}")
                        new_default_fields[f.name] = rnd
                        # if f.name in p.fields:
                        #     # Remove the override found inside fields
                        #     del p.fields[f.name]

        # Process packets with MultipleTypeFields
        if multiple_type_fields:
            # We don't want this freeze - 2025-08-18 - we want to fuzz all
            #  fields, even if they are dependent on something else
            # freeze the other random values
            # new_default_fields = {
            #     key: (val._fix() if isinstance(val, VolatileValue) else val)
            #     for key, val in new_default_fields.items()
            # }
            # q.default_fields.update(new_default_fields)
            # new_default_fields.clear()

            # add the random values of the MultipleTypeFields
            for name in multiple_type_fields:
                fld = cast(MultipleTypeField, q.get_field(name))
                resolved = fld._find_fld_pkt(q)

                # A MultipleTypeField can resolve to a list-valued field
                # (VRRPv3.addrlist is a FieldListField of IPField once
                # there's an IP underlayer, a StrField without one), and
                # then a single scalar randval would replace the caller's
                # whole list - their address list, their option list - on
                # the first step of the walk, with nothing downstream able
                # to recover the value. Fuzz within the list instead,
                # exactly as the FieldListField branch above does. Keyed on
                # the value the packet actually carries rather than on the
                # resolved field's own class, because it's the caller's
                # value that is at stake and it stays a list either way.
                current_list = getattr(q, name, None)
                if isinstance(current_list, list) and len(current_list) > 0:
                    new_default_fields[name] = _fuzz_list_items(
                        resolved, current_list)
                    continue

                rnd = resolved.randval()
                if rnd is not None:
                    new_default_fields[name] = rnd
        q.default_fields.update(new_default_fields)
        q = q.payload
    return p
