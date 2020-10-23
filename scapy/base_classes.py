# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Generators and packet meta classes.
"""

################
#  Generators  #
################

from __future__ import absolute_import

from functools import reduce
import operator
import os
import re
import random
import socket
import subprocess
import types
import warnings

import scapy
from scapy.consts import WINDOWS
import scapy.modules.six as six

from scapy.modules.six.moves import range

from scapy.compat import (
    Any,
    Dict,
    Generic,
    Iterator,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    _Generic_metaclass,
    cast,
)

try:
    import pyx
except ImportError:
    pass

_T = TypeVar("_T")


@six.add_metaclass(_Generic_metaclass)
class Gen(Generic[_T]):
    __slots__ = []  # type: List[str]

    def __iter__(self):
        # type: () -> Iterator[_T]
        return iter([])

    def __iterlen__(self):
        # type: () -> int
        return sum(1 for _ in iter(self))


def _get_values(value):
    # type: (Any) -> Any
    """Generate a range object from (start, stop[, step]) tuples, or
    return value.

    """
    if (isinstance(value, tuple) and (2 <= len(value) <= 3) and
            all(hasattr(i, "__int__") for i in value)):
        # We use values[1] + 1 as stop value for (x)range to maintain
        # the behavior of using tuples as field `values`
        return range(*((int(value[0]), int(value[1]) + 1) +
                       tuple(int(v) for v in value[2:])))
    return value


class SetGen(Gen[_T]):
    def __init__(self, values, _iterpacket=1):
        # type: (Any, int) -> None
        self._iterpacket = _iterpacket
        if isinstance(values, (list, BasePacketList)):
            self.values = [_get_values(val) for val in values]
        else:
            self.values = [_get_values(values)]

    def __iter__(self):
        # type: () -> Iterator[Any]
        for i in self.values:
            if (isinstance(i, Gen) and
                (self._iterpacket or not isinstance(i, BasePacket))) or (
                    isinstance(i, (range, types.GeneratorType))):
                for j in i:
                    yield j
            else:
                yield i

    def __repr__(self):
        # type: () -> str
        return "<SetGen %r>" % self.values


class Net(Gen[str]):
    """Generate a list of IPs from a network address or a name"""
    name = "ip"
    ip_regex = re.compile(r"^(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)(/[0-3]?[0-9])?$")  # noqa: E501

    @staticmethod
    def _parse_digit(a, netmask):
        # type: (str, int) -> Tuple[int, int]
        netmask = min(8, max(netmask, 0))
        if a == "*":
            return (0, 256)
        elif a.find("-") >= 0:
            x, y = [int(d) for d in a.split('-')]
            if x > y:
                y = x
            return (x & (0xff << netmask), max(y, (x | (0xff >> (8 - netmask)))) + 1)  # noqa: E501
        else:
            return (int(a) & (0xff << netmask), (int(a) | (0xff >> (8 - netmask))) + 1)  # noqa: E501

    @classmethod
    def _parse_net(cls, net):
        # type: (str) -> Tuple[List[Tuple[int, int]], int]
        tmp = net.split('/') + ["32"]
        if not cls.ip_regex.match(net):
            tmp[0] = socket.gethostbyname(tmp[0])
        netmask = int(tmp[1])
        ret_list = [cls._parse_digit(x, y - netmask) for (x, y) in zip(tmp[0].split('.'), [8, 16, 24, 32])]  # noqa: E501
        return ret_list, netmask

    def __init__(self, net):
        # type: (str) -> None
        self.repr = net
        self.parsed, self.netmask = self._parse_net(net)

    def __str__(self):
        # type: () -> str
        return next(self.__iter__(), "")

    def __iter__(self):
        # type: () -> Iterator[str]
        for d in range(*self.parsed[3]):
            for c in range(*self.parsed[2]):
                for b in range(*self.parsed[1]):
                    for a in range(*self.parsed[0]):
                        yield "%i.%i.%i.%i" % (a, b, c, d)

    def __iterlen__(self):
        # type: () -> int
        return reduce(operator.mul, ((y - x) for (x, y) in self.parsed), 1)

    def choice(self):
        # type: () -> str
        return ".".join(str(random.randint(v[0], v[1] - 1)) for v in self.parsed)  # noqa: E501

    def __repr__(self):
        # type: () -> str
        return "Net(%r)" % self.repr

    def __eq__(self, other):
        # type: (Any) -> bool
        if not other:
            return False
        if hasattr(other, "parsed"):
            p2 = other.parsed
        else:
            p2, nm2 = self._parse_net(other)
        return bool(self.parsed == p2)

    def __ne__(self, other):
        # type: (Any) -> bool
        # Python 2.7 compat
        return not self == other

    __hash__ = None  # type: ignore

    def __contains__(self, other):
        # type: (Union[str, Net]) -> bool
        if hasattr(other, "parsed"):
            p2 = cast(Net, other).parsed
        else:
            p2, _ = self._parse_net(cast(str, other))
        return all(a1 <= a2 and b1 >= b2 for (a1, b1), (a2, b2) in zip(self.parsed, p2))  # noqa: E501

    def __rcontains__(self, other):
        # type: (str) -> bool
        return self in self.__class__(other)


class OID(Gen[str]):
    name = "OID"

    def __init__(self, oid):
        # type: (str) -> None
        self.oid = oid
        self.cmpt = []
        fmt = []
        for i in oid.split("."):
            if "-" in i:
                fmt.append("%i")
                self.cmpt.append(tuple(map(int, i.split("-"))))
            else:
                fmt.append(i)
        self.fmt = ".".join(fmt)

    def __repr__(self):
        # type: () -> str
        return "OID(%r)" % self.oid

    def __iter__(self):
        # type: () -> Iterator[str]
        ii = [k[0] for k in self.cmpt]
        while True:
            yield self.fmt % tuple(ii)
            i = 0
            while True:
                if i >= len(ii):
                    return
                if ii[i] < self.cmpt[i][1]:
                    ii[i] += 1
                    break
                else:
                    ii[i] = self.cmpt[i][0]
                i += 1

    def __iterlen__(self):
        # type: () -> int
        return reduce(operator.mul, (max(y - x, 0) + 1 for (x, y) in self.cmpt), 1)  # noqa: E501


######################################
#  Packet abstract and base classes  #
######################################

class Packet_metaclass(_Generic_metaclass):
    def __new__(cls,  # type: ignore
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type['scapy.packet.Packet']
        if "fields_desc" in dct:  # perform resolution of references to other packets  # noqa: E501
            current_fld = dct["fields_desc"]  # type: List[Union['scapy.fields.Field'[Any, Any], Packet_metaclass]]  # noqa: E501
            resolved_fld = []  # type: List['scapy.fields.Field'[Any, Any]]
            for fld_or_pkt in current_fld:
                if isinstance(fld_or_pkt, Packet_metaclass):
                    # reference to another fields_desc
                    for pkt_fld in fld_or_pkt.fields_desc:  # type: ignore
                        resolved_fld.append(pkt_fld)
                else:
                    resolved_fld.append(fld_or_pkt)
        else:  # look for a fields_desc in parent classes
            resolved_fld = []
            for b in bases:
                if hasattr(b, "fields_desc"):
                    resolved_fld = b.fields_desc  # type: ignore
                    break

        if resolved_fld:  # perform default value replacements
            final_fld = []  # type: List['scapy.fields.Field'[Any, Any]]
            names = []
            for f in resolved_fld:
                if f.name in names:
                    war_msg = (
                        "Packet '%s' has a duplicated '%s' field ! "
                        "If you are using several ConditionalFields, have "
                        "a look at MultipleTypeField instead ! This will "
                        "become a SyntaxError in a future version of "
                        "Scapy !" % (
                            name, f.name
                        )
                    )
                    warnings.warn(war_msg, SyntaxWarning)
                names.append(f.name)
                if f.name in dct:
                    f = f.copy()
                    f.default = dct[f.name]
                    del(dct[f.name])
                final_fld.append(f)

            dct["fields_desc"] = final_fld

        dct.setdefault("__slots__", [])
        for attr in ["name", "overload_fields"]:
            try:
                dct["_%s" % attr] = dct.pop(attr)
            except KeyError:
                pass
        newcls = type.__new__(cls, name, bases, dct)
        # Note: below can't be typed because we use attributes
        # created dynamically..
        newcls.__all_slots__ = set(  # type: ignore
            attr
            for cls in newcls.__mro__ if hasattr(cls, "__slots__")
            for attr in cls.__slots__
        )

        newcls.aliastypes = (  # type: ignore
            [newcls] + getattr(newcls, "aliastypes", [])
        )

        if hasattr(newcls, "register_variant"):
            newcls.register_variant()  # type: ignore
        for f in newcls.fields_desc:  # type: ignore
            if hasattr(f, "register_owner"):
                f.register_owner(newcls)
        if newcls.__name__[0] != "_":
            from scapy import config
            config.conf.layers.register(newcls)
        return newcls

    def __getattr__(self, attr):
        # type: (str) -> 'scapy.fields.Field'[Any, Any]
        for k in self.fields_desc:  # type: ignore
            if k.name == attr:
                return k  # type: ignore
        raise AttributeError(attr)

    def __call__(cls,
                 *args,  # type: Any
                 **kargs  # type: Any
                 ):
        # type: (...) -> 'scapy.packet.Packet'
        if "dispatch_hook" in cls.__dict__:
            try:
                cls = cls.dispatch_hook(*args, **kargs)  # type: ignore
            except Exception:
                from scapy import config
                if config.conf.debug_dissector:
                    raise
                cls = config.conf.raw_layer  # type: ignore
        i = cls.__new__(
            cls,  # type: ignore
            cls.__name__,
            cls.__bases__,
            cls.__dict__
        )
        i.__init__(*args, **kargs)
        return i  # type: ignore


# Note: see compat.py for an explanation

class Field_metaclass(_Generic_metaclass):
    def __new__(cls,  # type: ignore
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type['scapy.fields.Field'[Any, Any]]
        dct.setdefault("__slots__", [])
        newcls = super(Field_metaclass, cls).__new__(cls, name, bases, dct)
        return newcls


PacketList_metaclass = Field_metaclass


class BasePacket(Gen['scapy.packet.Packet']):
    __slots__ = []  # type: List[str]


#############################
#  Packet list base class   #
#############################

class BasePacketList(Gen[_T]):
    __slots__ = []  # type: List[str]


class _CanvasDumpExtended(object):
    def canvas_dump(self, **kwargs):
        # type: (**Any) -> 'pyx.canvas.canvas'
        pass

    def psdump(self, filename=None, **kargs):
        # type: (Optional[str], **Any) -> None
        """
        psdump(filename=None, layer_shift=0, rebuild=1)

        Creates an EPS file describing a packet. If filename is not provided a
        temporary file is created and gs is called.

        :param filename: the file's filename
        """
        from scapy.config import conf
        from scapy.utils import get_temp_file, ContextManagerSubprocess
        canvas = self.canvas_dump(**kargs)
        if filename is None:
            fname = cast(str, get_temp_file(
                autoext=kargs.get("suffix", ".eps")
            ))
            canvas.writeEPSfile(fname)
            if WINDOWS and conf.prog.psreader is None:
                os.startfile(fname)
            else:
                with ContextManagerSubprocess(conf.prog.psreader):
                    subprocess.Popen([conf.prog.psreader, fname])
        else:
            canvas.writeEPSfile(filename)
        print()

    def pdfdump(self, filename=None, **kargs):
        # type: (Optional[str], **Any) -> None
        """
        pdfdump(filename=None, layer_shift=0, rebuild=1)

        Creates a PDF file describing a packet. If filename is not provided a
        temporary file is created and xpdf is called.

        :param filename: the file's filename
        """
        from scapy.config import conf
        from scapy.utils import get_temp_file, ContextManagerSubprocess
        canvas = self.canvas_dump(**kargs)
        if filename is None:
            fname = cast(str, get_temp_file(
                autoext=kargs.get("suffix", ".pdf")
            ))
            canvas.writePDFfile(fname)
            if WINDOWS and conf.prog.pdfreader is None:
                os.startfile(fname)
            else:
                with ContextManagerSubprocess(conf.prog.pdfreader):
                    subprocess.Popen([conf.prog.pdfreader, fname])
        else:
            canvas.writePDFfile(filename)
        print()

    def svgdump(self, filename=None, **kargs):
        # type: (Optional[str], **Any) -> None
        """
        svgdump(filename=None, layer_shift=0, rebuild=1)

        Creates an SVG file describing a packet. If filename is not provided a
        temporary file is created and gs is called.

        :param filename: the file's filename
        """
        from scapy.config import conf
        from scapy.utils import get_temp_file, ContextManagerSubprocess
        canvas = self.canvas_dump(**kargs)
        if filename is None:
            fname = cast(str, get_temp_file(
                autoext=kargs.get("suffix", ".svg")
            ))
            canvas.writeSVGfile(fname)
            if WINDOWS and conf.prog.svgreader is None:
                os.startfile(fname)
            else:
                with ContextManagerSubprocess(conf.prog.svgreader):
                    subprocess.Popen([conf.prog.svgreader, fname])
        else:
            canvas.writeSVGfile(filename)
        print()
