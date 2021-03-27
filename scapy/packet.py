# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Packet class

Provides:
 - the default Packet classes
 - binding mechanisms
 - fuzz() method
 - exploration methods: explore() / ls()
"""

from __future__ import absolute_import
from __future__ import print_function
from collections import defaultdict
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
    FlagsField,
    MultiEnumField,
    MultipleTypeField,
    PacketListField,
    RawVal,
    StrField,
)
from scapy.config import conf, _version_checker
from scapy.compat import raw, orb, bytes_encode
from scapy.base_classes import BasePacket, Gen, SetGen, Packet_metaclass, \
    _CanvasDumpExtended
from scapy.interfaces import _GlobInterfaceType
from scapy.volatile import RandField, VolatileValue
from scapy.utils import import_hexcap, tex_escape, colgen, issubtype, \
    pretty_list, EDecimal
from scapy.error import Scapy_Exception, log_runtime, warning
from scapy.extlib import PYX
import scapy.modules.six as six

# Typing imports
from scapy.compat import (
    Any,
    Callable,
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
try:
    import pyx
except ImportError:
    pass


_T = TypeVar("_T", Dict[str, Any], Optional[Dict[str, Any]])


# six.with_metaclass typing is glitchy
class Packet(six.with_metaclass(Packet_metaclass,  # type: ignore
             BasePacket, _CanvasDumpExtended)):
    __slots__ = [
        "time", "sent_time", "name",
        "default_fields", "fields", "fieldtype",
        "overload_fields", "overloaded_fields",
        "packetfields",
        "original", "explicit", "raw_packet_cache",
        "raw_packet_cache_fields", "_pkt", "post_transforms",
        # then payload and underlayer
        "payload", "underlayer",
        "name",
        # used for sr()
        "_answered",
        # used when sniffing
        "direction", "sniffed_on",
        # handle snaplen Vs real length
        "wirelen",
    ]
    name = None
    fields_desc = []  # type: Sequence[AnyField]
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
            print("%-20s  %s" % (upper.__name__, ", ".join("%-12s" % ("%s=%r" % i) for i in six.iteritems(fval))))  # noqa: E501

    @classmethod
    def lower_bonds(self):
        # type: () -> None
        for lower, fval in six.iteritems(self._overload_fields):
            print("%-20s  %s" % (lower.__name__, ", ".join("%-12s" % ("%s=%r" % i) for i in six.iteritems(fval))))  # noqa: E501

    def __init__(self,
                 _pkt=b"",  # type: bytes
                 post_transform=None,  # type: Any
                 _internal=0,  # type: int
                 _underlayer=None,  # type: Optional[Packet]
                 **fields  # type: Any
                 ):
        # type: (...) -> None
        self.time = time.time()  # type: Union[EDecimal, float]
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
        self.payload = NoPayload()
        self.init_fields()
        self.underlayer = _underlayer
        self.original = _pkt
        self.explicit = 0
        self.raw_packet_cache = None  # type: Optional[bytes]
        self.raw_packet_cache_fields = None  # type: Optional[Dict[str, Any]]  # noqa: E501
        self.wirelen = None  # type: Optional[int]
        self.direction = None  # type: Optional[int]
        self.sniffed_on = None  # type: Optional[_GlobInterfaceType]
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
            self.fields[fname] = self.get_field(fname).any2i(self, value)
        # The remaining fields are unknown
        for fname in fields:
            if fname in self.deprecated_fields:
                # Resolve deprecated fields
                value = fields[fname]
                fname = self._resolve_alias(fname)
                self.fields[fname] = self.get_field(fname).any2i(self, value)
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
        Optional[int]
    ]

    def __reduce__(self):
        # type: () -> Tuple[Type[Packet], Tuple[bytes], Packet._PickleType]
        """Used by pickling methods"""
        return (self.__class__, (self.build(),), (
            self.time,
            self.sent_time,
            self.direction,
            self.sniffed_on,
            self.wirelen,
        ))

    def __setstate__(self, state):
        # type: (Packet._PickleType) -> Packet
        """Rebuild state using pickable methods"""
        self.time = state[0]
        self.sent_time = state[1]
        self.direction = state[2]
        self.sniffed_on = state[3]
        self.wirelen = state[4]
        return self

    def __deepcopy__(self,
                     memo,  # type: Any
                     ):
        # type: (...) -> Packet
        """Used by copy.deepcopy"""
        return self.copy()

    def init_fields(self):
        # type: () -> None
        """
        Initialize each fields of the fields_desc dict
        """

        if self.class_dont_cache.get(self.__class__, False):
            self.do_init_fields(self.fields_desc)
        else:
            self.do_init_cached_fields()

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

    def do_init_cached_fields(self):
        # type: () -> None
        """
        Initialize each fields of the fields_desc dict, or use the cached
        fields information
        """

        cls_name = self.__class__

        # Build the fields information
        if Packet.class_default_fields.get(cls_name, None) is None:
            self.prepare_cached_fields(self.fields_desc)

        # Use fields information from cache
        default_fields = Packet.class_default_fields.get(cls_name, None)
        if default_fields:
            self.default_fields = default_fields
            self.fieldtype = Packet.class_fieldtype[cls_name]
            self.packetfields = Packet.class_packetfields[cls_name]

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

            tmp_copy = copy.deepcopy(f.default)
            class_default_fields[f.name] = tmp_copy
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

    def copy(self):
        # type: () -> Packet
        """Returns a deep copy of the instance."""
        clone = self.__class__()
        clone.fields = self.copy_fields_dict(self.fields)
        clone.default_fields = self.copy_fields_dict(self.default_fields)
        clone.overloaded_fields = self.overloaded_fields.copy()
        clone.underlayer = self.underlayer
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
        if attr in self.fields:
            return self.fields[attr]
        if attr in self.overloaded_fields:
            return self.overloaded_fields[attr]
        if attr in self.default_fields:
            return self.default_fields[attr]
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
            return fld.i2h(self, v)
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
            self.fields[attr] = any2i(self, val)
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
            if attr == "sent_time":
                self.update_sent_time(val)
            return object.__setattr__(self, attr, val)
        try:
            return self.setfieldval(attr, val)
        except AttributeError:
            pass
        return object.__setattr__(self, attr, val)

    def delfieldval(self, attr):
        # type: (str) -> None
        if attr in self.fields:
            del(self.fields[attr])
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
        attrs = set()
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

    if six.PY2:
        def __str__(self):
            # type: () -> str
            return self.build()
    else:
        def __str__(self):
            # type: () -> str
            warning("Calling str(pkt) on Python 3 makes no sense!")
            return str(self.build())

    def __bytes__(self):
        # type: () -> bytes
        return self.build()

    def __div__(self, other):
        # type: (Any) -> Packet
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
                for fname, fval in six.iteritems(fields)}

    def clear_cache(self):
        # type: () -> None
        """Clear the raw packet cache for the field and all its subfields"""
        self.raw_packet_cache = None
        for fld, fval in six.iteritems(self.fields):
            fld = self.get_field(fld)
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

        :param field_pos_list:
        """
        if self.raw_packet_cache is not None:
            for fname, fval in six.iteritems(self.raw_packet_cache_fields):
                if self.getfieldval(fname) != fval:
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
                p = f.addfield(self, p, val)
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

        :param str pkt: the current packet (build by self_buil function)
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
            return " ".join("%02x" % orb(c) for c in x)

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
            if not s:
                break
            s, fval = f.getfield(self, s)
            # Skip unused ConditionalField
            if isinstance(f, ConditionalField) and fval is None:
                continue
            # We need to track fields with mutable values to discard
            # .raw_packet_cache when needed.
            if f.islist or f.holds_packets or f.ismutable:
                self.raw_packet_cache_fields[f.name] = f.do_copy(fval)
            self.fields[f.name] = fval
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
            cls = self.guess_payload_class(s)
            try:
                p = cls(s, _internal=1, _underlayer=self)
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
                           for k, v in six.iteritems(fval)):
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
        for k, v in list(six.iteritems(self.fields)):
            v = self.fields[k]
            if k in self.default_fields:
                if self.default_fields[k] == v:
                    del self.fields[k]
        self.payload.hide_defaults()

    def update_sent_time(self, time):
        # type: (Optional[float]) -> None
        """Use by clone_with to share the sent_time value"""
        pass

    def clone_with(self, payload=None, share_time=False, **kargs):
        # type: (Optional[Any], bool, **Any) -> Any
        pkt = self.__class__()
        pkt.explicit = 1
        pkt.fields = kargs
        pkt.default_fields = self.copy_fields_dict(self.default_fields)
        pkt.overloaded_fields = self.overloaded_fields.copy()
        pkt.time = self.time
        pkt.underlayer = self.underlayer
        pkt.post_transforms = self.post_transforms
        pkt.raw_packet_cache = self.raw_packet_cache
        pkt.raw_packet_cache_fields = self.copy_fields_dict(
            self.raw_packet_cache_fields
        )
        pkt.wirelen = self.wirelen
        if payload is not None:
            pkt.add_payload(payload)
        if share_time:
            # This binds the subpacket .sent_time to this layer
            def _up_time(x, parent=self):
                # type: (float, Packet) -> None
                parent.sent_time = x
            pkt.update_sent_time = _up_time  # type: ignore
        return pkt

    def __iter__(self):
        # type: () -> Iterator[Packet]
        """Iterates through all sub-packets generated by this Packet."""
        # We use __iterlen__ as low as possible, to lower processing time
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
                share_time = False
                if self.fields == done and payloads.__iterlen__() == 1:
                    # In this case, the packets are identical. Let's bind
                    # their sent_time attribute for sending purpose
                    share_time = True
                for payl in payloads:
                    # Let's make sure subpackets are consistent
                    done2 = done.copy()
                    for k in done2:
                        if isinstance(done2[k], VolatileValue):
                            done2[k] = done2[k]._fix()
                    pkt = self.clone_with(payload=payl, share_time=share_time,
                                          **done2)
                    yield pkt

        if self.explicit or self.raw_packet_cache is not None:
            todo = []
            done = self.fields
        else:
            todo = [k for (k, v) in itertools.chain(six.iteritems(self.default_fields),  # noqa: E501
                                                    six.iteritems(self.overloaded_fields))  # noqa: E501
                    if isinstance(v, VolatileValue)] + list(self.fields)
            done = {}
        return loop(todo, done)

    def __iterlen__(self):
        # type: () -> int
        """Predict the total length of the iterator"""
        fields = [key for (key, val) in itertools.chain(six.iteritems(self.default_fields),  # noqa: E501
                  six.iteritems(self.overloaded_fields))
                  if isinstance(val, VolatileValue)] + list(self.fields)
        length = 1

        def is_valid_gen_tuple(x):
            # type: (Any) -> bool
            if not isinstance(x, tuple):
                return False
            return len(x) == 2 and all(isinstance(z, int) for z in x)

        for field in fields:
            fld, val = self.getfield_and_val(field)
            if hasattr(val, "__iterlen__"):
                length *= val.__iterlen__()
            elif is_valid_gen_tuple(val):
                length *= (val[1] - val[0] + 1)
            elif isinstance(val, list) and not fld.islist:
                len2 = 0
                for x in val:
                    if hasattr(x, "__iterlen__"):
                        len2 += x.__iterlen__()
                    elif is_valid_gen_tuple(x):
                        len2 += (x[1] - x[0] + 1)
                    elif isinstance(x, list):
                        len2 += len(x)
                    else:
                        len2 += 1
                length *= len2 or 1
        if not isinstance(self.payload, NoPayload):
            return length * self.payload.__iterlen__()
        return length

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
            match = lambda cls1, cls2: bool(cls1 == cls2)
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
            match = lambda cls1, cls2: bool(cls1 == cls2)
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
                   for fldname, fldvalue in six.iteritems(flt)):
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
        del(self[cls].underlayer.payload)

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
        # type: () -> Tuple[Any, Optional[str], Optional[str]]
        return self.payload.route()

    def fragment(self, *args, **kargs):
        # type: (*Any, **Any) -> List[Packet]
        return self.payload.fragment(*args, **kargs)

    def display(self, *args, **kargs):  # Deprecated. Use show()
        # type: (*Any, **Any) -> None
        """Deprecated. Use show() method."""
        self.show(*args, **kargs)

    def _show_or_dump(self,
                      dump=False,  # type: bool
                      indent=3,  # type: int
                      lvl="",  # type: str
                      label_lvl="",  # type: str
                      first_call=True  # type: bool
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
            from scapy.themes import AnsiColorTheme
            ct = AnsiColorTheme()  # No color for dump output
        else:
            ct = conf.color_theme
        s = "%s%s %s %s \n" % (label_lvl,
                               ct.punct("###["),
                               ct.layer_name(self.name),
                               ct.punct("]###"))
        for f in self.fields_desc:
            if isinstance(f, ConditionalField) and not f._evalcond(self):
                continue
            if isinstance(f, Emph) or f in conf.emph:
                ncol = ct.emph_field_name
                vcol = ct.emph_field_value
            else:
                ncol = ct.field_name
                vcol = ct.field_value
            fvalue = self.getfieldval(f.name)
            if isinstance(fvalue, Packet) or (f.islist and f.holds_packets and isinstance(fvalue, list)):  # noqa: E501
                pad = max(0, 10 - len(f.name)) * " "
                s += "%s  \\%s%s\\\n" % (label_lvl + lvl, ncol(f.name), pad)
                fvalue_gen = SetGen(
                    fvalue,
                    _iterpacket=0
                )  # type: SetGen[Packet]
                for fvalue in fvalue_gen:
                    s += fvalue._show_or_dump(dump=dump, indent=indent, label_lvl=label_lvl + lvl + "   |", first_call=False)  # noqa: E501
            else:
                pad = max(0, 10 - len(f.name)) * " "
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
                s += "%s%s\n" % (begn, vcol(reprval))
        if self.payload:
            s += self.payload._show_or_dump(  # type: ignore
                dump=dump,
                indent=indent,
                lvl=lvl + (" " * indent * self.show_indent),
                label_lvl=label_lvl,
                first_call=False
            )

        if first_call and not dump:
            print(s)
            return None
        else:
            return s

    def show(self, dump=False, indent=3, lvl="", label_lvl=""):
        # type: (bool, int, str, str) -> Optional[Any]
        """
        Prints or returns (when "dump" is true) a hierarchical view of the
        packet.

        :param dump: determine if it prints or returns the string value
        :param int indent: the size of indentation for each layer
        :param str lvl: additional information about the layer lvl
        :param str label_lvl: additional information about the layer fields
        :return: return a hierarchical view if dump, else print it
        """
        return self._show_or_dump(dump, indent, lvl, label_lvl)

    def show2(self, dump=False, indent=3, lvl="", label_lvl=""):
        # type: (bool, int, str, str) -> Optional[Any]
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
        return self.__class__(raw(self)).show(dump, indent, lvl, label_lvl)

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
                    elif f[-1] == "r":  # Raw field value
                        val = getattr(self, fld)
                        f = f[:-1]
                        if not f:
                            f = "s"
                    else:
                        val = getattr(self, fld)
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

    def command(self):
        # type: () -> str
        """
        Returns a string representing the command you have to type to
        obtain the same packet
        """
        f = []
        for fn, fv in six.iteritems(self.fields):
            fld = self.get_field(fn)
            if isinstance(fv, (list, dict, set)) and len(fv) == 0:
                continue
            if isinstance(fv, Packet):
                fv = fv.command()
            elif fld.islist and fld.holds_packets and isinstance(fv, list):
                fv = "[%s]" % ",".join(map(Packet.command, fv))
            elif isinstance(fld, FlagsField):
                fv = int(fv)
            elif callable(getattr(fv, 'command', None)):
                fv = fv.command()
            else:
                fv = repr(fv)
            f.append("%s=%s" % (fn, fv))
        c = "%s(%s)" % (self.__class__.__name__, ", ".join(f))
        pc = self.payload.command()
        if pc:
            c += "/" + pc
        return c

    def convert_to(self, other_cls, **kwargs):
        # type: (Type[Packet], **Any) -> Packet
        """Converts this Packet to another type.

        This is not guaranteed to be a lossless process.

        By default, this only implements conversion to ``Raw``.

        :param other_cls: Reference to a Packet class to convert to.
        :type other_cls: Type[scapy.packet.Packet]
        :return: Converted form of the packet.
        :rtype: other_cls
        :raises TypeError: When conversion is not possible
        """
        if not issubtype(other_cls, Packet):
            raise TypeError("{} must implement Packet".format(other_cls))

        if other_cls is Raw:
            return Raw(raw(self))

        if "_internal" not in kwargs:
            return other_cls.convert_packet(self, _internal=True, **kwargs)

        raise TypeError("Cannot convert {} to {}".format(
            type(self).__name__, other_cls.__name__))

    @classmethod
    def convert_packet(cls, pkt, **kwargs):
        # type: (Packet, **Any) -> Packet
        """Converts another packet to be this type.

        This is not guaranteed to be a lossless process.

        :param pkt: The packet to convert.
        :type pkt: scapy.packet.Packet
        :return: Converted form of the packet.
        :rtype: cls
        :raises TypeError: When conversion is not possible
        """
        if not isinstance(pkt, Packet):
            raise TypeError("Can only convert Packets")

        if "_internal" not in kwargs:
            return pkt.convert_to(cls, _internal=True, **kwargs)

        raise TypeError("Cannot convert {} to {}".format(
            type(pkt).__name__, cls.__name__))

    @classmethod
    def convert_packets(cls,
                        pkts,  # type: List[Packet]
                        **kwargs  # type: Any
                        ):
        # type: (...) -> Iterator[Iterator[Packet]]
        """Converts many packets to this type.

        This is implemented as a generator.

        See ``Packet.convert_packet``.
        """
        for pkt in pkts:
            yield cls.convert_packet(pkt, **kwargs)


class NoPayload(Packet):
    def __new__(cls, *args, **kargs):
        # type: (Type[Packet], *Any, **Any) -> Packet
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
        # type: (NoPayload) -> bool
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

    @classmethod
    def convert_packet(cls, pkt, **kwargs):
        # type: (Packet, **Any) -> Raw
        return Raw(raw(pkt))


class Padding(Raw):
    name = "Padding"

    def self_build(self, field_pos_list=None):
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
    upper._overload_fields = upper._overload_fields.copy()
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
            k not in params or params[k] != v for k, v in six.iteritems(fval)
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
        if any(k not in ofval or ofval[k] != v for k, v in six.iteritems(fval)):  # noqa: E501
            return
        upper._overload_fields = upper._overload_fields.copy()
        del(upper._overload_fields[lower])


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
            call_ptk = lambda x: x.run()  # type: ignore
        # 1 - Ask for layer or contrib
        btn_diag = button_dialog(
            title=six.text_type("Scapy v%s" % conf.version),
            text=HTML(
                six.text_type(
                    '<style bg="white" fg="red">Chose the type of packets'
                    ' you want to explore:</style>'
                )
            ),
            buttons=[
                (six.text_type("Layers"), "layers"),
                (six.text_type("Contribs"), "contribs"),
                (six.text_type("Cancel"), "cancel")
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
        # Python 2 compat
        if six.PY2:
            values = [(six.text_type(x), six.text_type(y))
                      for x, y in values]
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
                ("$" + name, six.text_type('[+] ' + name.capitalize()))
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
                title=six.text_type(
                    "Scapy v%s" % conf.version
                ),
                text=HTML(
                    six.text_type((
                        '<style bg="white" fg="red">Please select a file'
                        'among the following, to see all layers contained in'
                        ' it:</style>'
                    ) + extra_text)
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
    rtlst = [(lay.__name__ or "", lay._name or "") for lay in all_layers]
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
           and hasattr(cur_fld, "i2s"):
            if len(cur_fld.i2s or []) < 50:
                long_attrs.extend(
                    "%s: %d" % (strval, numval)
                    for numval, strval in
                    sorted(six.iteritems(cur_fld.i2s))
                )
        elif isinstance(cur_fld, MultiEnumField):
            fld_depend = cur_fld.depends_on(
                cast(Packet, obj if is_pkt else obj())
            )
            attrs.append("Depends on %s" % fld_depend)
            if verbose:
                cur_i2s = cur_fld.i2s_multi.get(
                    cur_fld.depends_on(
                        cast(Packet, obj if is_pkt else obj())
                    ), {}
                )
                if len(cur_i2s) < 50:
                    long_attrs.extend(
                        "%s: %d" % (strval, numval)
                        for numval, strval in
                        sorted(six.iteritems(cur_i2s))
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
    is_string = isinstance(obj, str)

    if obj is None or is_string:
        tip = False
        if obj is None:
            tip = True
            all_layers = sorted(conf.layers, key=lambda x: x.__name__)
        else:
            pattern = re.compile(
                cast(str, obj),
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
                obj,  # type: ignore
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
    for f in cls.fields_desc:
        flen = int(f.sz * 8)
        cur_len += flen
        ident += 1
        # Fancy field name
        fname = f.name.upper().replace("_", " ")
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
            pos_above = sum(x[1] for x in above[:-1])
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

@conf.commands.register
def fuzz(p,  # type: Packet
         _inplace=0,  # type: int
         ):
    # type: (...) -> Packet
    """
    Transform a layer into a fuzzy layer by replacing some default values
    by random objects.

    :param p: the Packet instance to fuzz
    :return: the fuzzed packet.
    """
    if not _inplace:
        p = p.copy()
    q = p
    while not isinstance(q, NoPayload):
        new_default_fields = {}
        multiple_type_fields = []  # type: List[str]
        for f in q.fields_desc:
            if isinstance(f, PacketListField):
                for r in getattr(q, f.name):
                    fuzz(r, _inplace=1)
            elif isinstance(f, MultipleTypeField):
                # the type of the field will depend on others
                multiple_type_fields.append(f.name)
            elif f.default is not None:
                if not isinstance(f, ConditionalField) or f._evalcond(q):
                    rnd = f.randval()
                    if rnd is not None:
                        new_default_fields[f.name] = rnd
        # Process packets with MultipleTypeFields
        if multiple_type_fields:
            # freeze the other random values
            new_default_fields = {
                key: (val._fix() if isinstance(val, VolatileValue) else val)
                for key, val in six.iteritems(new_default_fields)
            }
            q.default_fields.update(new_default_fields)
            # add the random values of the MultipleTypeFields
            for name in multiple_type_fields:
                fld = cast(MultipleTypeField, q.get_field(name))
                rnd = fld._find_fld_pkt(q).randval()
                if rnd is not None:
                    new_default_fields[name] = rnd
        q.default_fields.update(new_default_fields)
        q = q.payload
    return p
