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
import random
import re
import socket
import struct
import subprocess
import types
import warnings

import scapy
from scapy.error import Scapy_Exception
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

    def __len__(self):
        # type: () -> int
        return self.__iterlen__()

    def __repr__(self):
        # type: () -> str
        return "<SetGen %r>" % self.values


class Net(Gen[str]):
    """Network object from an IP address or hostname and mask"""
    name = "Net"  # type: str
    family = socket.AF_INET  # type: int
    max_mask = 32  # type: int

    @classmethod
    def name2addr(cls, name):
        # type: (str) -> str
        try:
            return next(
                addr_port[0]
                for family, _, _, _, addr_port in
                socket.getaddrinfo(name, None, cls.family)
                if family == cls.family
            )
        except socket.error:
            if re.search("(^|\\.)[0-9]+-[0-9]+($|\\.)", name) is not None:
                raise Scapy_Exception("Ranges are no longer accepted in %s()" %
                                      cls.__name__)
            raise

    @classmethod
    def ip2int(cls, addr):
        # type: (str) -> int
        return cast(int, struct.unpack(
            "!I", socket.inet_aton(cls.name2addr(addr))
        )[0])

    @staticmethod
    def int2ip(val):
        # type: (int) -> str
        return socket.inet_ntoa(struct.pack('!I', val))

    def __init__(self, net, stop=None):
        # type: (str, Union[None, str]) -> None
        if "*" in net:
            raise Scapy_Exception("Wildcards are no longer accepted in %s()" %
                                  self.__class__.__name__)
        if stop is None:
            try:
                net, mask = net.split("/", 1)
            except ValueError:
                self.mask = self.max_mask  # type: Union[None, int]
            else:
                self.mask = int(mask)
            self.net = net  # type: Union[None, str]
            inv_mask = self.max_mask - self.mask
            self.start = self.ip2int(net) >> inv_mask << inv_mask
            self.count = 1 << inv_mask
            self.stop = self.start + self.count - 1
        else:
            self.start = self.ip2int(net)
            self.stop = self.ip2int(stop)
            self.count = self.stop - self.start + 1
            self.net = self.mask = None

    def __str__(self):
        # type: () -> str
        return next(iter(self), "")

    def __iter__(self):
        # type: () -> Iterator[str]
        # Python 2 won't handle huge (> sys.maxint) values in range()
        for i in range(self.count):
            yield self.int2ip(self.start + i)

    def __len__(self):
        # type: () -> int
        return self.count

    def __iterlen__(self):
        # type: () -> int
        # for compatibility
        return len(self)

    def choice(self):
        # type: () -> str
        return self.int2ip(random.randint(self.start, self.stop))

    def __repr__(self):
        # type: () -> str
        if self.mask is not None:
            return '%s("%s/%d")' % (
                self.__class__.__name__,
                self.net,
                self.mask,
            )
        return '%s("%s", "%s")' % (
            self.__class__.__name__,
            self.int2ip(self.start),
            self.int2ip(self.stop),
        )

    def __eq__(self, other):
        # type: (Any) -> bool
        if isinstance(other, str):
            return self == self.__class__(other)
        if not isinstance(other, Net):
            return False
        if self.family != other.family:
            return False
        return (self.start == other.start) and (self.stop == other.stop)

    def __ne__(self, other):
        # type: (Any) -> bool
        # Python 2.7 compat
        return not self == other

    def __hash__(self):
        # type: () -> int
        return hash(("scapy.Net", self.family, self.start, self.stop))

    def __contains__(self, other):
        # type: (Any) -> bool
        if isinstance(other, int):
            return self.start <= other <= self.stop
        if isinstance(other, str):
            return self.__class__(other) in self
        if type(other) is not self.__class__:
            return False
        return cast(
            bool,
            (self.start <= other.start <= other.stop <= self.stop),
        )


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
            fname = get_temp_file(autoext=kargs.get("suffix", ".eps"))
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
            fname = get_temp_file(autoext=kargs.get("suffix", ".pdf"))
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
            fname = get_temp_file(autoext=kargs.get("suffix", ".svg"))
            canvas.writeSVGfile(fname)
            if WINDOWS and conf.prog.svgreader is None:
                os.startfile(fname)
            else:
                with ContextManagerSubprocess(conf.prog.svgreader):
                    subprocess.Popen([conf.prog.svgreader, fname])
        else:
            canvas.writeSVGfile(filename)
        print()
