# -*- mode: python3; indent-tabs-mode: nil; tab-width: 4 -*-
# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Michael Farrell <micolous+git@gmail.com>
# This program is published under a GPLv2 license

"""
Fields: basic data structures that make up parts of packets.
"""

from __future__ import absolute_import
import calendar
import collections
import copy
import inspect
import socket
import struct
import time
from types import MethodType
from uuid import UUID


from scapy.config import conf
from scapy.dadict import DADict
from scapy.volatile import RandBin, RandByte, RandEnumKeys, RandInt, \
    RandIP, RandIP6, RandLong, RandMAC, RandNum, RandShort, RandSInt, \
    RandSByte, RandTermString, RandUUID, VolatileValue, RandSShort, \
    RandSLong, RandFloat
from scapy.data import EPOCH
from scapy.error import log_runtime, Scapy_Exception
from scapy.compat import bytes_hex, chb, orb, plain_str, raw, bytes_encode
from scapy.pton_ntop import inet_ntop, inet_pton
from scapy.utils import inet_aton, inet_ntoa, lhex, mac2str, str2mac
from scapy.utils6 import in6_6to4ExtractAddr, in6_isaddr6to4, \
    in6_isaddrTeredo, in6_ptop, Net6, teredoAddrExtractInfo
from scapy.base_classes import BasePacket, Gen, Net, Field_metaclass
from scapy.error import warning
import scapy.modules.six as six
from scapy.modules.six.moves import range


"""
Helper class to specify a protocol extendable for runtime modifications
"""


class ObservableDict(dict):
    def __init__(self, *args, **kw):
        self.observers = []
        super(ObservableDict, self).__init__(*args, **kw)

    def observe(self, observer):
        self.observers.append(observer)

    def __setitem__(self, key, value):
        for o in self.observers:
            o.notify_set(self, key, value)
        super(ObservableDict, self).__setitem__(key, value)

    def __delitem__(self, key):
        for o in self.observers:
            o.notify_del(self, key)
        super(ObservableDict, self).__delitem__(key)

    def update(self, anotherDict):
        for k in anotherDict:
            self[k] = anotherDict[k]


############
#  Fields  #
############

class Field(six.with_metaclass(Field_metaclass, object)):
    """For more information on how this work, please refer to
       http://www.secdev.org/projects/scapy/files/scapydoc.pdf
       chapter ``Adding a New Field''"""
    __slots__ = ["name", "fmt", "default", "sz", "owners"]
    islist = 0
    ismutable = False
    holds_packets = 0

    def __init__(self, name, default, fmt="H"):
        self.name = name
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!" + fmt
        self.default = self.any2i(None, default)
        self.sz = struct.calcsize(self.fmt)
        self.owners = []

    def register_owner(self, cls):
        self.owners.append(cls)

    def i2len(self, pkt, x):
        """Convert internal value to a length usable by a FieldLenField"""
        return self.sz

    def i2count(self, pkt, x):
        """Convert internal value to a number of elements usable by a FieldLenField.
        Always 1 except for list fields"""
        return 1

    def h2i(self, pkt, x):
        """Convert human value to internal value"""
        return x

    def i2h(self, pkt, x):
        """Convert internal value to human value"""
        return x

    def m2i(self, pkt, x):
        """Convert machine value to internal value"""
        return x

    def i2m(self, pkt, x):
        """Convert internal value to machine value"""
        if x is None:
            x = 0
        elif isinstance(x, str):
            return bytes_encode(x)
        return x

    def any2i(self, pkt, x):
        """Try to understand the most input values possible and make an internal value from them"""  # noqa: E501
        return self.h2i(pkt, x)

    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        return repr(self.i2h(pkt, x))

    def addfield(self, pkt, s, val):
        """Add an internal value to a string

        Copy the network representation of field `val` (belonging to layer
        `pkt`) to the raw string packet `s`, and return the new string packet.
        """
        return s + struct.pack(self.fmt, self.i2m(pkt, val))

    def getfield(self, pkt, s):
        """Extract an internal value from a string

        Extract from the raw packet `s` the field value belonging to layer
        `pkt`.

        Returns a two-element list,
        first the raw packet string after having removed the extracted field,
        second the extracted field itself in internal representation.
        """
        return s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, s[:self.sz])[0])  # noqa: E501

    def do_copy(self, x):
        if hasattr(x, "copy"):
            return x.copy()
        if isinstance(x, list):
            x = x[:]
            for i in range(len(x)):
                if isinstance(x[i], BasePacket):
                    x[i] = x[i].copy()
        return x

    def __repr__(self):
        return "<Field (%s).%s>" % (",".join(x.__name__ for x in self.owners), self.name)  # noqa: E501

    def copy(self):
        return copy.deepcopy(self)

    def randval(self):
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
            warning("no random class for [%s] (fmt=%s).", self.name, self.fmt)


class Emph(object):
    """Empathize sub-layer for display"""
    __slots__ = ["fld"]

    def __init__(self, fld):
        self.fld = fld

    def __getattr__(self, attr):
        return getattr(self.fld, attr)

    def __hash__(self):
        return hash(self.fld)

    def __eq__(self, other):
        return self.fld == other


class ActionField(object):
    __slots__ = ["_fld", "_action_method", "_privdata"]

    def __init__(self, fld, action_method, **kargs):
        self._fld = fld
        self._action_method = action_method
        self._privdata = kargs

    def any2i(self, pkt, val):
        getattr(pkt, self._action_method)(val, self._fld, **self._privdata)
        return getattr(self._fld, "any2i")(pkt, val)

    def __getattr__(self, attr):
        return getattr(self._fld, attr)


class ConditionalField(object):
    __slots__ = ["fld", "cond"]

    def __init__(self, fld, cond):
        self.fld = fld
        self.cond = cond

    def _evalcond(self, pkt):
        return self.cond(pkt)

    def getfield(self, pkt, s):
        if self._evalcond(pkt):
            return self.fld.getfield(pkt, s)
        else:
            return s, None

    def addfield(self, pkt, s, val):
        if self._evalcond(pkt):
            return self.fld.addfield(pkt, s, val)
        else:
            return s

    def __getattr__(self, attr):
        return getattr(self.fld, attr)


class MultipleTypeField(object):
    """MultipleTypeField are used for fields that can be implemented by
various Field subclasses, depending on conditions on the packet.

It is initialized with `flds` and `dflt`.

`dflt` is the default field type, to be used when none of the
conditions matched the current packet.

`flds` is a list of tuples (`fld`, `cond`), where `fld` if a field
type, and `cond` a "condition" to determine if `fld` is the field type
that should be used.

`cond` is either:

  - a callable `cond_pkt` that accepts one argument (the packet) and
    returns True if `fld` should be used, False otherwise.

  - a tuple (`cond_pkt`, `cond_pkt_val`), where `cond_pkt` is the same
    as in the previous case and `cond_pkt_val` is a callable that
    accepts two arguments (the packet, and the value to be set) and
    returns True if `fld` should be used, False otherwise.

See scapy.layers.l2.ARP (type "help(ARP)" in Scapy) for an example of
use.

    """

    __slots__ = ["flds", "dflt", "name"]

    def __init__(self, flds, dflt):
        self.flds = flds
        self.dflt = dflt
        self.name = self.dflt.name

    def _iterate_fields_cond(self, pkt, val, use_val):
        """Internal function used by _find_fld_pkt & _find_fld_pkt_val"""
        # Iterate through the fields
        for fld, cond in self.flds:
            if isinstance(cond, tuple):
                if use_val:
                    if cond[1](pkt, val):
                        return fld
                    continue
                else:
                    cond = cond[0]
            if cond(pkt):
                return fld
        return self.dflt

    def _find_fld_pkt(self, pkt):
        """Given a Packet instance `pkt`, returns the Field subclass to be
used. If you know the value to be set (e.g., in .addfield()), use
._find_fld_pkt_val() instead.

        """
        return self._iterate_fields_cond(pkt, None, False)

    def _find_fld_pkt_val(self, pkt, val):
        """Given a Packet instance `pkt` and the value `val` to be set,
returns the Field subclass to be used, and the updated `val` if necessary.

        """
        fld = self._iterate_fields_cond(pkt, val, True)
        # Default ? (in this case, let's make sure it's up-do-date)
        dflts_pkt = pkt.default_fields
        if val == dflts_pkt[self.name] and self.name not in pkt.fields:
            dflts_pkt[self.name] = fld.default
            val = fld.default
        return fld, val

    def _find_fld(self):
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
        frame = inspect.currentframe().f_back.f_back
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

    def getfield(self, pkt, s):
        return self._find_fld_pkt(pkt).getfield(pkt, s)

    def addfield(self, pkt, s, val):
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.addfield(pkt, s, val)

    def any2i(self, pkt, val):
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.any2i(pkt, val)

    def h2i(self, pkt, val):
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.h2i(pkt, val)

    def i2h(self, pkt, val):
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.i2h(pkt, val)

    def i2m(self, pkt, val):
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.i2m(pkt, val)

    def i2len(self, pkt, val):
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.i2len(pkt, val)

    def i2repr(self, pkt, val):
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.i2repr(pkt, val)

    def register_owner(self, cls):
        for fld, _ in self.flds:
            fld.owners.append(cls)
        self.dflt.owners.append(cls)

    def __getattr__(self, attr):
        return getattr(self._find_fld(), attr)


class PadField(object):
    """Add bytes after the proxified field so that it ends at the specified
       alignment from its beginning"""
    __slots__ = ["_fld", "_align", "_padwith"]

    def __init__(self, fld, align, padwith=None):
        self._fld = fld
        self._align = align
        self._padwith = padwith or b""

    def padlen(self, flen):
        return -flen % self._align

    def getfield(self, pkt, s):
        remain, val = self._fld.getfield(pkt, s)
        padlen = self.padlen(len(s) - len(remain))
        return remain[padlen:], val

    def addfield(self, pkt, s, val):
        sval = self._fld.addfield(pkt, b"", val)
        return s + sval + struct.pack("%is" % (self.padlen(len(sval))), self._padwith)  # noqa: E501

    def __getattr__(self, attr):
        return getattr(self._fld, attr)


class ReversePadField(PadField):
    """Add bytes BEFORE the proxified field so that it starts at the specified
       alignment from its beginning"""

    def getfield(self, pkt, s):
        # We need to get the length that has already been dissected
        padlen = self.padlen(pkt._tmp_dissect_pos)
        remain, val = self._fld.getfield(pkt, s[padlen:])
        return remain, val

    def addfield(self, pkt, s, val):
        sval = self._fld.addfield(pkt, b"", val)
        return s + struct.pack("%is" % (self.padlen(len(s))), self._padwith) + sval  # noqa: E501


class FCSField(Field):
    """Special Field that gets its value from the end of the *packet*
    (Note: not layer, but packet).

    Mostly used for FCS
    """
    def getfield(self, pkt, s):
        previous_post_dissect = pkt.post_dissect
        val = self.m2i(pkt, struct.unpack(self.fmt, s[-self.sz:])[0])

        def _post_dissect(self, s):
            # Reset packet to allow post_build
            self.raw_packet_cache = None
            self.post_dissect = previous_post_dissect
            return previous_post_dissect(s)
        pkt.post_dissect = MethodType(_post_dissect, pkt)
        return s[:-self.sz], val

    def addfield(self, pkt, s, val):
        previous_post_build = pkt.post_build
        value = struct.pack(self.fmt, self.i2m(pkt, val))

        def _post_build(self, p, pay):
            pay += value
            self.post_build = previous_post_build
            return previous_post_build(p, pay)
        pkt.post_build = MethodType(_post_build, pkt)
        return s

    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class DestField(Field):
    __slots__ = ["defaultdst"]
    # Each subclass must have its own bindings attribute
    # bindings = {}

    def __init__(self, name, default):
        self.defaultdst = default

    def dst_from_pkt(self, pkt):
        for addr, condition in self.bindings.get(pkt.payload.__class__, []):
            try:
                if all(pkt.payload.getfieldval(field) == value
                       for field, value in six.iteritems(condition)):
                    return addr
            except AttributeError:
                pass
        return self.defaultdst

    @classmethod
    def bind_addr(cls, layer, addr, **condition):
        cls.bindings.setdefault(layer, []).append((addr, condition))


class MACField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "6s")

    def i2m(self, pkt, x):
        if x is None:
            return b"\0\0\0\0\0\0"
        return mac2str(x)

    def m2i(self, pkt, x):
        return str2mac(x)

    def any2i(self, pkt, x):
        if isinstance(x, bytes) and len(x) == 6:
            x = self.m2i(pkt, x)
        return x

    def i2repr(self, pkt, x):
        x = self.i2h(pkt, x)
        if self in conf.resolve:
            x = conf.manufdb._resolve_MAC(x)
        return x

    def randval(self):
        return RandMAC()


class IPField(Field):
    slots = []

    def __init__(self, name, default):
        Field.__init__(self, name, default, "4s")

    def h2i(self, pkt, x):
        if isinstance(x, bytes):
            x = plain_str(x)
        if isinstance(x, str):
            try:
                inet_aton(x)
            except socket.error:
                x = Net(x)
        elif isinstance(x, list):
            x = [self.h2i(pkt, n) for n in x]
        return x

    def resolve(self, x):
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
        if x is None:
            return b'\x00\x00\x00\x00'
        return inet_aton(plain_str(x))

    def m2i(self, pkt, x):
        return inet_ntoa(x)

    def any2i(self, pkt, x):
        return self.h2i(pkt, x)

    def i2repr(self, pkt, x):
        r = self.resolve(self.i2h(pkt, x))
        return r if isinstance(r, str) else repr(r)

    def randval(self):
        return RandIP()


class SourceIPField(IPField):
    __slots__ = ["dstname"]

    def __init__(self, name, dstname):
        IPField.__init__(self, name, None)
        self.dstname = dstname

    def __findaddr(self, pkt):
        if conf.route is None:
            # unused import, only to initialize conf.route
            import scapy.route  # noqa: F401
        dst = ("0.0.0.0" if self.dstname is None
               else getattr(pkt, self.dstname) or "0.0.0.0")
        if isinstance(dst, (Gen, list)):
            r = {conf.route.route(str(daddr)) for daddr in dst}
            if len(r) > 1:
                warning("More than one possible route for %r" % (dst,))
            return min(r)[1]
        return conf.route.route(dst)[1]

    def i2m(self, pkt, x):
        if x is None:
            x = self.__findaddr(pkt)
        return IPField.i2m(self, pkt, x)

    def i2h(self, pkt, x):
        if x is None:
            x = self.__findaddr(pkt)
        return IPField.i2h(self, pkt, x)


class IP6Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "16s")

    def h2i(self, pkt, x):
        if isinstance(x, bytes):
            x = plain_str(x)
        if isinstance(x, str):
            try:
                x = in6_ptop(x)
            except socket.error:
                x = Net6(x)
        elif isinstance(x, list):
            x = [self.h2i(pkt, n) for n in x]
        return x

    def i2m(self, pkt, x):
        if x is None:
            x = "::"
        return inet_pton(socket.AF_INET6, plain_str(x))

    def m2i(self, pkt, x):
        return inet_ntop(socket.AF_INET6, x)

    def any2i(self, pkt, x):
        return self.h2i(pkt, x)

    def i2repr(self, pkt, x):
        if x is None:
            return self.i2h(pkt, x)
        elif not isinstance(x, Net6) and not isinstance(x, list):
            if in6_isaddrTeredo(x):   # print Teredo info
                server, _, maddr, mport = teredoAddrExtractInfo(x)
                return "%s [Teredo srv: %s cli: %s:%s]" % (self.i2h(pkt, x), server, maddr, mport)  # noqa: E501
            elif in6_isaddr6to4(x):   # print encapsulated address
                vaddr = in6_6to4ExtractAddr(x)
                return "%s [6to4 GW: %s]" % (self.i2h(pkt, x), vaddr)
        r = self.i2h(pkt, x)          # No specific information to return
        return r if isinstance(r, str) else repr(r)

    def randval(self):
        return RandIP6()


class SourceIP6Field(IP6Field):
    __slots__ = ["dstname"]

    def __init__(self, name, dstname):
        IP6Field.__init__(self, name, None)
        self.dstname = dstname

    def i2m(self, pkt, x):
        if x is None:
            dst = ("::" if self.dstname is None else
                   getattr(pkt, self.dstname) or "::")
            iff, x, nh = conf.route6.route(dst)
        return IP6Field.i2m(self, pkt, x)

    def i2h(self, pkt, x):
        if x is None:
            if conf.route6 is None:
                # unused import, only to initialize conf.route6
                import scapy.route6  # noqa: F401
            dst = ("::" if self.dstname is None else getattr(pkt, self.dstname))  # noqa: E501
            if isinstance(dst, (Gen, list)):
                r = {conf.route6.route(str(daddr)) for daddr in dst}
                if len(r) > 1:
                    warning("More than one possible route for %r" % (dst,))
                x = min(r)[1]
            else:
                x = conf.route6.route(dst)[1]
        return IP6Field.i2h(self, pkt, x)


class DestIP6Field(IP6Field, DestField):
    bindings = {}

    def __init__(self, name, default):
        IP6Field.__init__(self, name, None)
        DestField.__init__(self, name, default)

    def i2m(self, pkt, x):
        if x is None:
            x = self.dst_from_pkt(pkt)
        return IP6Field.i2m(self, pkt, x)

    def i2h(self, pkt, x):
        if x is None:
            x = self.dst_from_pkt(pkt)
        return IP6Field.i2h(self, pkt, x)


class ByteField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")


class XByteField(ByteField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class OByteField(ByteField):
    def i2repr(self, pkt, x):
        return "%03o" % self.i2h(pkt, x)


class ThreeBytesField(ByteField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "!I")

    def addfield(self, pkt, s, val):
        return s + struct.pack(self.fmt, self.i2m(pkt, val))[1:4]

    def getfield(self, pkt, s):
        return s[3:], self.m2i(pkt, struct.unpack(self.fmt, b"\x00" + s[:3])[0])  # noqa: E501


class X3BytesField(ThreeBytesField, XByteField):
    def i2repr(self, pkt, x):
        return XByteField.i2repr(self, pkt, x)


class LEThreeBytesField(ByteField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<I")

    def addfield(self, pkt, s, val):
        return s + struct.pack(self.fmt, self.i2m(pkt, val))[:3]

    def getfield(self, pkt, s):
        return s[3:], self.m2i(pkt, struct.unpack(self.fmt, s[:3] + b"\x00")[0])  # noqa: E501


class LEX3BytesField(LEThreeBytesField, XByteField):
    def i2repr(self, pkt, x):
        return XByteField.i2repr(self, pkt, x)


class SignedByteField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "b")


class FieldValueRangeException(Scapy_Exception):
    pass


class FieldAttributeException(Scapy_Exception):
    pass


class YesNoByteField(ByteField):
    """
    byte based flag field that shows representation of its number based on a given association  # noqa: E501

    in its default configuration the following representation is generated:
        x == 0 : 'no'
        x != 0 : 'yes'

    in more sophisticated use-cases (e.g. yes/no/invalid) one can use the config attribute to configure  # noqa: E501
    key-value, key-range and key-value-set associations that will be used to generate the values representation.  # noqa: E501

    a range is given by a tuple (<first-val>, <last-value>) including the last value. a single-value tuple  # noqa: E501
    is treated as scalar.

    a list defines a set of (probably non consecutive) values that should be associated to a given key.  # noqa: E501

    all values not associated with a key will be shown as number of type unsigned byte.  # noqa: E501

    config = {
                'no' : 0,
                'foo' : (1,22),
                'yes' : 23,
                'bar' : [24,25, 42, 48, 87, 253]
             }

    generates the following representations:

        x == 0 : 'no'
        x == 15: 'foo'
        x == 23: 'yes'
        x == 42: 'bar'
        x == 43: 43

    using the config attribute one could also revert the stock-yes-no-behavior:

    config = {
                'yes' : 0,
                'no' : (1,255)
             }

    will generate the following value representation:

        x == 0 : 'yes'
        x != 0 : 'no'

    """
    __slots__ = ['eval_fn']

    def _build_config_representation(self, config):
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

    def __init__(self, name, default, config=None, *args, **kargs):

        if not config:
            # this represents the common use case and therefore it is kept small  # noqa: E501
            self.eval_fn = lambda x: 'no' if x == 0 else 'yes'
        else:
            self._build_config_representation(config)
        ByteField.__init__(self, name, default, *args, **kargs)

    def i2repr(self, pkt, x):
        return self.eval_fn(x)


class ShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "H")


class SignedShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "h")


class LEShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<H")


class XShortField(ShortField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class IntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "I")


class SignedIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "i")


class LEIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<I")


class LESignedIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<i")


class XIntField(IntField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class XLEIntField(LEIntField, XIntField):
    def i2repr(self, pkt, x):
        return XIntField.i2repr(self, pkt, x)


class XLEShortField(LEShortField, XShortField):
    def i2repr(self, pkt, x):
        return XShortField.i2repr(self, pkt, x)


class LongField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "Q")


class LELongField(LongField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<Q")


class XLongField(LongField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class XLELongField(LELongField, XLongField):
    def i2repr(self, pkt, x):
        return XLongField.i2repr(self, pkt, x)


class IEEEFloatField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "f")


class IEEEDoubleField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "d")


class StrField(Field):
    __slots__ = ["remain"]

    def __init__(self, name, default, fmt="H", remain=0):
        Field.__init__(self, name, default, fmt)
        self.remain = remain

    def i2len(self, pkt, x):
        return len(x)

    def any2i(self, pkt, x):
        if isinstance(x, six.text_type):
            x = bytes_encode(x)
        return super(StrField, self).any2i(pkt, x)

    def i2repr(self, pkt, x):
        val = super(StrField, self).i2repr(pkt, x)
        if val[:2] in ['b"', "b'"]:
            return val[1:]
        return val

    def i2m(self, pkt, x):
        if x is None:
            return b""
        if not isinstance(x, bytes):
            return bytes_encode(x)
        return x

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        if self.remain == 0:
            return b"", self.m2i(pkt, s)
        else:
            return s[-self.remain:], self.m2i(pkt, s[:-self.remain])

    def randval(self):
        return RandBin(RandNum(0, 1200))


class PacketField(StrField):
    __slots__ = ["cls"]
    holds_packets = 1

    def __init__(self, name, default, cls, remain=0):
        StrField.__init__(self, name, default, remain=remain)
        self.cls = cls

    def i2m(self, pkt, i):
        if i is None:
            return b""
        return raw(i)

    def m2i(self, pkt, m):
        return self.cls(m)

    def getfield(self, pkt, s):
        i = self.m2i(pkt, s)
        remain = b""
        if conf.padding_layer in i:
            r = i[conf.padding_layer]
            del(r.underlayer.payload)
            remain = r.load
        return remain, i

    def randval(self):
        from scapy.packet import fuzz
        return fuzz(self.cls())


class PacketLenField(PacketField):
    __slots__ = ["length_from"]

    def __init__(self, name, default, cls, length_from=None):
        PacketField.__init__(self, name, default, cls)
        self.length_from = length_from

    def getfield(self, pkt, s):
        len_pkt = self.length_from(pkt)
        try:
            i = self.m2i(pkt, s[:len_pkt])
        except Exception:
            if conf.debug_dissector:
                raise
            i = conf.raw_layer(load=s[:len_pkt])
        return s[len_pkt:], i


class PacketListField(PacketField):
    """ PacketListField represents a series of Packet instances that might occur right in the middle of another Packet  # noqa: E501
    field list.
    This field type may also be used to indicate that a series of Packet instances have a sibling semantic instead of  # noqa: E501
    a parent/child relationship (i.e. a stack of layers).
    """
    __slots__ = ["count_from", "length_from", "next_cls_cb"]
    islist = 1

    def __init__(self, name, default, cls=None, count_from=None, length_from=None, next_cls_cb=None):  # noqa: E501
        """ The number of Packet instances that are dissected by this field can be parametrized using one of three  # noqa: E501
        different mechanisms/parameters:
            * count_from: a callback that returns the number of Packet instances to dissect. The callback prototype is:  # noqa: E501
            count_from(pkt:Packet) -> int
            * length_from: a callback that returns the number of bytes that must be dissected by this field. The  # noqa: E501
            callback prototype is:
            length_from(pkt:Packet) -> int
            * next_cls_cb: a callback that enables a Scapy developer to dynamically discover if another Packet instance  # noqa: E501
            should be dissected or not. See below for this callback prototype.

        The bytes that are not consumed during the dissection of this field are passed to the next field of the current  # noqa: E501
        packet.

        For the serialization of such a field, the list of Packets that are contained in a PacketListField can be  # noqa: E501
        heterogeneous and is unrestricted.

        The type of the Packet instances that are dissected with this field is specified or discovered using one of the  # noqa: E501
        following mechanism:
            * the cls parameter may contain a callable that returns an instance of the dissected Packet. This  # noqa: E501
                may either be a reference of a Packet subclass (e.g. DNSRROPT in layers/dns.py) to generate an  # noqa: E501
                homogeneous PacketListField or a function deciding the type of the Packet instance  # noqa: E501
                (e.g. _CDPGuessAddrRecord in contrib/cdp.py)
            * the cls parameter may contain a class object with a defined "dispatch_hook" classmethod. That  # noqa: E501
                method must return a Packet instance. The dispatch_hook callmethod must implement the following prototype:  # noqa: E501
                dispatch_hook(cls, _pkt:Optional[Packet], *args, **kargs) -> Packet_metaclass  # noqa: E501
                The _pkt parameter may contain a reference to the packet instance containing the PacketListField that is  # noqa: E501
                being dissected.
            * the next_cls_cb parameter may contain a callable whose prototype is:  # noqa: E501
                cbk(pkt:Packet, lst:List[Packet], cur:Optional[Packet], remain:str) -> Optional[Packet_metaclass]  # noqa: E501
                The pkt argument contains a reference to the Packet instance containing the PacketListField that is  # noqa: E501
                being dissected. The lst argument is the list of all Packet instances that were previously parsed during  # noqa: E501
                the current PacketListField dissection, save for the very last Packet instance. The cur argument  # noqa: E501
                contains a reference to that very last parsed Packet instance. The remain argument contains the bytes  # noqa: E501
                that may still be consumed by the current PacketListField dissection operation. This callback returns  # noqa: E501
                either the type of the next Packet to dissect or None to indicate that no more Packet are to be  # noqa: E501
                dissected.
                These four arguments allows a variety of dynamic discovery of the number of Packet to dissect and of the  # noqa: E501
                type of each one of these Packets, including: type determination based on current Packet instances or  # noqa: E501
                its underlayers, continuation based on the previously parsed Packet instances within that  # noqa: E501
                PacketListField, continuation based on a look-ahead on the bytes to be dissected...  # noqa: E501

        The cls and next_cls_cb parameters are semantically exclusive, although one could specify both. If both are  # noqa: E501
        specified, cls is silently ignored. The same is true for count_from and next_cls_cb.  # noqa: E501
        length_from and next_cls_cb are compatible and the dissection will end, whichever of the two stop conditions  # noqa: E501
        comes first.

        @param name: the name of the field
        @param default: the default value of this field; generally an empty Python list  # noqa: E501
        @param cls: either a callable returning a Packet instance or a class object defining a dispatch_hook class  # noqa: E501
            method
        @param count_from: a callback returning the number of Packet instances to dissect  # noqa: E501
        @param length_from: a callback returning the number of bytes to dissect
        @param next_cls_cb: a callback returning either None or the type of the next Packet to dissect.  # noqa: E501
        """
        if default is None:
            default = []  # Create a new list for each instance
        PacketField.__init__(self, name, default, cls)
        self.count_from = count_from
        self.length_from = length_from
        self.next_cls_cb = next_cls_cb

    def any2i(self, pkt, x):
        if not isinstance(x, list):
            return [x]
        else:
            return x

    def i2count(self, pkt, val):
        if isinstance(val, list):
            return len(val)
        return 1

    def i2len(self, pkt, val):
        return sum(len(p) for p in val)

    def do_copy(self, x):
        if x is None:
            return None
        else:
            return [p if isinstance(p, (str, bytes)) else p.copy() for p in x]

    def getfield(self, pkt, s):
        c = len_pkt = cls = None
        if self.length_from is not None:
            len_pkt = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)
        if self.next_cls_cb is not None:
            cls = self.next_cls_cb(pkt, [], None, s)
            c = 1

        lst = []
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
                    del(pad.underlayer.payload)
                    if self.next_cls_cb is not None:
                        cls = self.next_cls_cb(pkt, lst, p, remain)
                        if cls is not None:
                            c = 0 if c is None else c
                            c += 1
                else:
                    remain = b""
            lst.append(p)
        return remain + ret, lst

    def addfield(self, pkt, s, val):
        return s + b"".join(bytes_encode(v) for v in val)


class StrFixedLenField(StrField):
    __slots__ = ["length_from"]

    def __init__(self, name, default, length=None, length_from=None):
        StrField.__init__(self, name, default)
        self.length_from = length_from
        if length is not None:
            self.length_from = lambda pkt, length=length: length

    def i2repr(self, pkt, v):
        if isinstance(v, bytes):
            v = v.rstrip(b"\0")
        return super(StrFixedLenField, self).i2repr(pkt, v)

    def getfield(self, pkt, s):
        len_pkt = self.length_from(pkt)
        return s[len_pkt:], self.m2i(pkt, s[:len_pkt])

    def addfield(self, pkt, s, val):
        len_pkt = self.length_from(pkt)
        if len_pkt is None:
            return s + self.i2m(pkt, val)
        return s + struct.pack("%is" % len_pkt, self.i2m(pkt, val))

    def randval(self):
        try:
            len_pkt = self.length_from(None)
        except Exception:
            len_pkt = RandNum(0, 200)
        return RandBin(len_pkt)


class StrFixedLenEnumField(StrFixedLenField):
    __slots__ = ["enum"]

    def __init__(self, name, default, length=None, enum=None, length_from=None):  # noqa: E501
        StrFixedLenField.__init__(self, name, default, length=length, length_from=length_from)  # noqa: E501
        self.enum = enum

    def i2repr(self, pkt, v):
        r = v.rstrip("\0" if isinstance(v, str) else b"\0")
        rr = repr(r)
        if v in self.enum:
            rr = "%s (%s)" % (rr, self.enum[v])
        elif r in self.enum:
            rr = "%s (%s)" % (rr, self.enum[r])
        return rr


class NetBIOSNameField(StrFixedLenField):
    def __init__(self, name, default, length=31):
        StrFixedLenField.__init__(self, name, default, length)

    def i2m(self, pkt, x):
        len_pkt = self.length_from(pkt) // 2
        x = bytes_encode(x)
        if x is None:
            x = b""
        x += b" " * len_pkt
        x = x[:len_pkt]
        x = b"".join(chb(0x41 + (orb(b) >> 4)) + chb(0x41 + (orb(b) & 0xf)) for b in x)  # noqa: E501
        x = b" " + x
        return x

    def m2i(self, pkt, x):
        x = x.strip(b"\x00").strip(b" ")
        return b"".join(map(lambda x, y: chb((((orb(x) - 1) & 0xf) << 4) + ((orb(y) - 1) & 0xf)), x[::2], x[1::2]))  # noqa: E501


class StrLenField(StrField):
    __slots__ = ["length_from", "max_length"]

    def __init__(self, name, default, fld=None, length_from=None, max_length=None):  # noqa: E501
        StrField.__init__(self, name, default)
        self.length_from = length_from
        self.max_length = max_length

    def getfield(self, pkt, s):
        len_pkt = self.length_from(pkt)
        return s[len_pkt:], self.m2i(pkt, s[:len_pkt])

    def randval(self):
        return RandBin(RandNum(0, self.max_length or 1200))


class XStrField(StrField):
    """
    StrField which value is printed as hexadecimal.
    """

    def i2repr(self, pkt, x):
        if x is None:
            return repr(x)
        return bytes_hex(x).decode()


class _XStrLenField:
    def i2repr(self, pkt, x):
        if not x:
            return repr(x)
        return bytes_hex(x[:self.length_from(pkt)]).decode()


class XStrLenField(_XStrLenField, StrLenField):
    """
    StrLenField which value is printed as hexadecimal.
    """


class XStrFixedLenField(_XStrLenField, StrFixedLenField):
    """
    StrFixedLenField which value is printed as hexadecimal.
    """


class XLEStrLenField(XStrLenField):
    def i2m(self, pkt, x):
        return x[:: -1]

    def m2i(self, pkt, x):
        return x[:: -1]


class StrLenFieldUtf16(StrLenField):
    def h2i(self, pkt, x):
        return plain_str(x).encode('utf-16')[2:]

    def i2h(self, pkt, x):
        return x.decode('utf-16')


class BoundStrLenField(StrLenField):
    __slots__ = ["minlen", "maxlen"]

    def __init__(self, name, default, minlen=0, maxlen=255, fld=None, length_from=None):  # noqa: E501
        StrLenField.__init__(self, name, default, fld, length_from)
        self.minlen = minlen
        self.maxlen = maxlen

    def randval(self):
        return RandBin(RandNum(self.minlen, self.maxlen))


class FieldListField(Field):
    __slots__ = ["field", "count_from", "length_from"]
    islist = 1

    def __init__(self, name, default, field, length_from=None, count_from=None):  # noqa: E501
        if default is None:
            default = []  # Create a new list for each instance
        self.field = field
        Field.__init__(self, name, default)
        self.count_from = count_from
        self.length_from = length_from

    def i2count(self, pkt, val):
        if isinstance(val, list):
            return len(val)
        return 1

    def i2len(self, pkt, val):
        return int(sum(self.field.i2len(pkt, v) for v in val))

    def i2m(self, pkt, val):
        if val is None:
            val = []
        return val

    def any2i(self, pkt, x):
        if not isinstance(x, list):
            return [self.field.any2i(pkt, x)]
        else:
            return [self.field.any2i(pkt, e) for e in x]

    def i2repr(self, pkt, x):
        return "[%s]" % ", ".join(self.field.i2repr(pkt, v) for v in x)

    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        for v in val:
            s = self.field.addfield(pkt, s, v)
        return s

    def getfield(self, pkt, s):
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
        return s + ret, val


class FieldLenField(Field):
    __slots__ = ["length_of", "count_of", "adjust"]

    def __init__(self, name, default, length_of=None, fmt="H", count_of=None, adjust=lambda pkt, x: x, fld=None):  # noqa: E501
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust
        if fld is not None:
            # FIELD_LENGTH_MANAGEMENT_DEPRECATION(self.__class__.__name__)
            self.length_of = fld

    def i2m(self, pkt, x):
        if x is None:
            if self.length_of is not None:
                fld, fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
            else:
                fld, fval = pkt.getfield_and_val(self.count_of)
                f = fld.i2count(pkt, fval)
            x = self.adjust(pkt, f)
        return x


class StrNullField(StrField):
    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val) + b"\x00"

    def getfield(self, pkt, s):
        len_str = s.find(b"\x00")
        if len_str < 0:
            # XXX \x00 not found
            return b"", s
        return s[len_str + 1:], self.m2i(pkt, s[:len_str])

    def randval(self):
        return RandTermString(RandNum(0, 1200), b"\x00")


class StrStopField(StrField):
    __slots__ = ["stop", "additional"]

    def __init__(self, name, default, stop, additional=0):
        Field.__init__(self, name, default)
        self.stop = stop
        self.additional = additional

    def getfield(self, pkt, s):
        len_str = s.find(self.stop)
        if len_str < 0:
            return b"", s
#            raise Scapy_Exception,"StrStopField: stop value [%s] not found" %stop  # noqa: E501
        len_str += len(self.stop) + self.additional
        return s[len_str:], s[:len_str]

    def randval(self):
        return RandTermString(RandNum(0, 1200), self.stop)


class LenField(Field):
    __slots__ = ["adjust"]

    def __init__(self, name, default, fmt="H", adjust=lambda x: x):
        Field.__init__(self, name, default, fmt)
        self.adjust = adjust

    def i2m(self, pkt, x):
        if x is None:
            x = self.adjust(len(pkt.payload))
        return x


class BCDFloatField(Field):
    def i2m(self, pkt, x):
        return int(256 * x)

    def m2i(self, pkt, x):
        return x / 256.0


class BitField(Field):
    __slots__ = ["rev", "size"]

    def __init__(self, name, default, size):
        Field.__init__(self, name, default)
        self.rev = size < 0
        self.size = abs(size)

    def reverse(self, val):
        if self.size == 16:
            # Replaces socket.ntohs (but work on both little/big endian)
            val = struct.unpack('>H', struct.pack('<H', int(val)))[0]
        elif self.size == 32:
            # Same here but for socket.ntohl
            val = struct.unpack('>I', struct.pack('<I', int(val)))[0]
        return val

    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        if isinstance(s, tuple):
            s, bitsdone, v = s
        else:
            bitsdone = 0
            v = 0
        if self.rev:
            val = self.reverse(val)
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
            return s

    def getfield(self, pkt, s):
        if isinstance(s, tuple):
            s, bn = s
        else:
            bn = 0
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

        if self.rev:
            b = self.reverse(b)

        bn += self.size
        s = s[bn // 8:]
        bn = bn % 8
        b = self.m2i(pkt, b)
        if bn:
            return (s, bn), b
        else:
            return s, b

    def randval(self):
        return RandNum(0, 2**self.size - 1)

    def i2len(self, pkt, x):
        return float(self.size) / 8


class BitFieldLenField(BitField):
    __slots__ = ["length_of", "count_of", "adjust"]

    def __init__(self, name, default, size, length_of=None, count_of=None, adjust=lambda pkt, x: x):  # noqa: E501
        BitField.__init__(self, name, default, size)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust

    def i2m(self, pkt, x):
        return (FieldLenField.i2m.__func__ if six.PY2 else FieldLenField.i2m)(self, pkt, x)  # noqa: E501


class XBitField(BitField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class _EnumField(Field):
    def __init__(self, name, default, enum, fmt="H"):
        """ Initializes enum fields.

        @param name:    name of this field
        @param default: default value of this field
        @param enum:    either a dict or a tuple of two callables. Dict keys are  # noqa: E501
                        the internal values, while the dict values are the
                        user-friendly representations. If the tuple is provided,  # noqa: E501
                        the first callable receives the internal value as
                        parameter and returns the user-friendly representation
                        and the second callable does the converse. The first
                        callable may return None to default to a literal string
                        (repr()) representation.
        @param fmt:     struct.pack format used to parse and serialize the
                        internal value from and to machine representation.
        """
        if isinstance(enum, ObservableDict):
            enum.observe(self)

        if isinstance(enum, tuple):
            self.i2s_cb = enum[0]
            self.s2i_cb = enum[1]
            self.i2s = None
            self.s2i = None
        else:
            i2s = self.i2s = {}
            s2i = self.s2i = {}
            self.i2s_cb = None
            self.s2i_cb = None
            if isinstance(enum, list):
                keys = list(range(len(enum)))
            elif isinstance(enum, DADict):
                keys = enum.keys()
            else:
                keys = list(enum)
            if any(isinstance(x, str) for x in keys):
                i2s, s2i = s2i, i2s
            for k in keys:
                i2s[k] = enum[k]
                s2i[enum[k]] = k
        Field.__init__(self, name, default, fmt)

    def any2i_one(self, pkt, x):
        if isinstance(x, str):
            try:
                x = self.s2i[x]
            except TypeError:
                x = self.s2i_cb(x)
        return x

    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x, VolatileValue):
            try:
                return self.i2s[x]
            except KeyError:
                pass
            except TypeError:
                ret = self.i2s_cb(x)
                if ret is not None:
                    return ret
        return repr(x)

    def any2i(self, pkt, x):
        if isinstance(x, list):
            return [self.any2i_one(pkt, z) for z in x]
        else:
            return self.any2i_one(pkt, x)

    def i2repr(self, pkt, x):
        if isinstance(x, list):
            return [self.i2repr_one(pkt, z) for z in x]
        else:
            return self.i2repr_one(pkt, x)

    def notify_set(self, enum, key, value):
        log_runtime.debug("At %s: Change to %s at 0x%x" % (self, value, key))
        self.i2s[key] = value
        self.s2i[value] = key

    def notify_del(self, enum, key):
        log_runtime.debug("At %s: Delete value at 0x%x" % (self, key))
        value = self.i2s[key]
        del self.i2s[key]
        del self.s2i[value]


class EnumField(_EnumField):
    __slots__ = ["i2s", "s2i", "s2i_cb", "i2s_cb"]


class CharEnumField(EnumField):
    def __init__(self, name, default, enum, fmt="1s"):
        EnumField.__init__(self, name, default, enum, fmt)
        if self.i2s is not None:
            k = list(self.i2s)
            if k and len(k[0]) != 1:
                self.i2s, self.s2i = self.s2i, self.i2s

    def any2i_one(self, pkt, x):
        if len(x) != 1:
            if self.s2i is None:
                x = self.s2i_cb(x)
            else:
                x = self.s2i[x]
        return x


class BitEnumField(BitField, _EnumField):
    __slots__ = EnumField.__slots__

    def __init__(self, name, default, size, enum):
        _EnumField.__init__(self, name, default, enum)
        self.rev = size < 0
        self.size = abs(size)

    def any2i(self, pkt, x):
        return _EnumField.any2i(self, pkt, x)

    def i2repr(self, pkt, x):
        return _EnumField.i2repr(self, pkt, x)


class ShortEnumField(EnumField):
    __slots__ = EnumField.__slots__

    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "H")


class LEShortEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "<H")


class ByteEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "B")


class XByteEnumField(ByteEnumField):
    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x, VolatileValue):
            try:
                return self.i2s[x]
            except KeyError:
                pass
            except TypeError:
                ret = self.i2s_cb(x)
                if ret is not None:
                    return ret
        return lhex(x)


class IntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "I")


class SignedIntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "i")


class LEIntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "<I")


class XShortEnumField(ShortEnumField):
    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x, VolatileValue):
            try:
                return self.i2s[x]
            except KeyError:
                pass
            except TypeError:
                ret = self.i2s_cb(x)
                if ret is not None:
                    return ret
        return lhex(x)


class _MultiEnumField(_EnumField):
    def __init__(self, name, default, enum, depends_on, fmt="H"):

        self.depends_on = depends_on
        self.i2s_multi = enum
        self.s2i_multi = {}
        self.s2i_all = {}
        for m in enum:
            self.s2i_multi[m] = s2i = {}
            for k, v in six.iteritems(enum[m]):
                s2i[v] = k
                self.s2i_all[v] = k
        Field.__init__(self, name, default, fmt)

    def any2i_one(self, pkt, x):
        if isinstance(x, str):
            v = self.depends_on(pkt)
            if v in self.s2i_multi:
                s2i = self.s2i_multi[v]
                if x in s2i:
                    return s2i[x]
            return self.s2i_all[x]
        return x

    def i2repr_one(self, pkt, x):
        v = self.depends_on(pkt)
        if v in self.i2s_multi:
            return self.i2s_multi[v].get(x, x)
        return x


class MultiEnumField(_MultiEnumField, EnumField):
    __slots__ = ["depends_on", "i2s_multi", "s2i_multi", "s2i_all"]


class BitMultiEnumField(BitField, _MultiEnumField):
    __slots__ = EnumField.__slots__ + MultiEnumField.__slots__

    def __init__(self, name, default, size, enum, depends_on):
        _MultiEnumField.__init__(self, name, default, enum, depends_on)
        self.rev = size < 0
        self.size = abs(size)

    def any2i(self, pkt, x):
        return _MultiEnumField.any2i(self, pkt, x)

    def i2repr(self, pkt, x):
        return _MultiEnumField.i2repr(self, pkt, x)


class ByteEnumKeysField(ByteEnumField):
    """ByteEnumField that picks valid values when fuzzed. """

    def randval(self):
        return RandEnumKeys(self.i2s)


class ShortEnumKeysField(ShortEnumField):
    """ShortEnumField that picks valid values when fuzzed. """

    def randval(self):
        return RandEnumKeys(self.i2s)


class IntEnumKeysField(IntEnumField):
    """IntEnumField that picks valid values when fuzzed. """

    def randval(self):
        return RandEnumKeys(self.i2s)


# Little endian fixed length field


class LEFieldLenField(FieldLenField):
    def __init__(self, name, default, length_of=None, fmt="<H", count_of=None, adjust=lambda pkt, x: x, fld=None):  # noqa: E501
        FieldLenField.__init__(self, name, default, length_of=length_of, fmt=fmt, count_of=count_of, fld=fld, adjust=adjust)  # noqa: E501


class FlagValueIter(object):

    slots = ["flagvalue", "cursor"]

    def __init__(self, flagvalue):
        self.flagvalue = flagvalue
        self.cursor = 0

    def __iter__(self):
        return self

    def __next__(self):
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
        if not value:
            return 0
        if isinstance(value, six.string_types):
            value = value.split('+') if self.multi else list(value)
        if isinstance(value, list):
            y = 0
            for i in value:
                y |= 1 << self.names.index(i)
            value = y
        return int(value)

    def __init__(self, value, names):
        self.multi = isinstance(names, list)
        self.names = names
        self.value = self._fixvalue(value)

    def __hash__(self):
        return hash(self.value)

    def __int__(self):
        return self.value

    def __eq__(self, other):
        return self.value == self._fixvalue(other)

    def __lt__(self, other):
        return self.value < self._fixvalue(other)

    def __le__(self, other):
        return self.value <= self._fixvalue(other)

    def __gt__(self, other):
        return self.value > self._fixvalue(other)

    def __ge__(self, other):
        return self.value >= self._fixvalue(other)

    def __ne__(self, other):
        return self.value != self._fixvalue(other)

    def __and__(self, other):
        return self.__class__(self.value & self._fixvalue(other), self.names)
    __rand__ = __and__

    def __or__(self, other):
        return self.__class__(self.value | self._fixvalue(other), self.names)
    __ror__ = __or__

    def __lshift__(self, other):
        return self.value << self._fixvalue(other)

    def __rshift__(self, other):
        return self.value >> self._fixvalue(other)

    def __nonzero__(self):
        return bool(self.value)
    __bool__ = __nonzero__

    def flagrepr(self):
        warning("obj.flagrepr() is obsolete. Use str(obj) instead.")
        return str(self)

    def __str__(self):
        i = 0
        r = []
        x = int(self)
        while x:
            if x & 1:
                r.append(self.names[i])
            i += 1
            x >>= 1
        return ("+" if self.multi else "").join(r)

    def __iter__(self):
        return FlagValueIter(self)

    def __repr__(self):
        return "<Flag %d (%s)>" % (self, self)

    def __deepcopy__(self, memo):
        return self.__class__(int(self), self.names)

    def __getattr__(self, attr):
        if attr in self.__slots__:
            return super(FlagValue, self).__getattr__(attr)
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
            return super(FlagValue, self).__getattr__(attr)

    def __setattr__(self, attr, value):
        if attr == "value" and not isinstance(value, six.integer_types):
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
        return self.__class__(self.value, self.names)


class FlagsField(BitField):
    """ Handle Flag type field

   Make sure all your flags have a label

   Example:
       >>> from scapy.packet import Packet
       >>> class FlagsTest(Packet):
               fields_desc = [FlagsField("flags", 0, 8, ["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7"])]  # noqa: E501
       >>> FlagsTest(flags=9).show2()
       ###[ FlagsTest ]###
         flags     = f0+f3
       >>> FlagsTest(flags=0).show2().strip()
       ###[ FlagsTest ]###
         flags     =

   :param name: field's name
   :param default: default value for the field
   :param size: number of bits in the field
   :param names: (list or dict) label for each flag, Least Significant Bit tag's name is written first  # noqa: E501
   """
    ismutable = True
    __slots__ = ["multi", "names"]

    def __init__(self, name, default, size, names):
        self.multi = isinstance(names, list)
        self.names = names
        BitField.__init__(self, name, default, size)

    def _fixup_val(self, x):
        """Returns a FlagValue instance when needed. Internal method, to be
used in *2i() and i2*() methods.

        """
        if isinstance(x, FlagValue):
            return x
        if x is None:
            return None
        return FlagValue(x, self.names)

    def any2i(self, pkt, x):
        return self._fixup_val(super(FlagsField, self).any2i(pkt, x))

    def m2i(self, pkt, x):
        return self._fixup_val(super(FlagsField, self).m2i(pkt, x))

    def i2h(self, pkt, x):
        if isinstance(x, VolatileValue):
            return super(FlagsField, self).i2h(pkt, x)
        return self._fixup_val(super(FlagsField, self).i2h(pkt, x))

    def i2repr(self, pkt, x):
        if isinstance(x, (list, tuple)):
            return repr(type(x)(
                None if v is None else str(self._fixup_val(v)) for v in x
            ))
        return None if x is None else str(self._fixup_val(x))


MultiFlagsEntry = collections.namedtuple('MultiFlagEntry', ['short', 'long'])


class MultiFlagsField(BitField):
    __slots__ = FlagsField.__slots__ + ["depends_on"]

    def __init__(self, name, default, size, names, depends_on):
        self.names = names
        self.depends_on = depends_on
        super(MultiFlagsField, self).__init__(name, default, size)

    def any2i(self, pkt, x):
        assert isinstance(x, six.integer_types + (set,)), 'set expected'

        if pkt is not None:
            if isinstance(x, six.integer_types):
                x = self.m2i(pkt, x)
            else:
                v = self.depends_on(pkt)
                if v is not None:
                    assert v in self.names, 'invalid dependency'
                    these_names = self.names[v]
                    s = set()
                    for i in x:
                        for val in six.itervalues(these_names):
                            if val.short == i:
                                s.add(i)
                                break
                        else:
                            assert False, 'Unknown flag "{}" with this dependency'.format(i)  # noqa: E501
                            continue
                    x = s
        return x

    def i2m(self, pkt, x):
        v = self.depends_on(pkt)
        these_names = self.names.get(v, {})

        r = 0
        for flag_set in x:
            for i, val in six.iteritems(these_names):
                if val.short == flag_set:
                    r |= 1 << i
                    break
            else:
                r |= 1 << int(flag_set[len('bit '):])
        return r

    def m2i(self, pkt, x):
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
        v = self.depends_on(pkt)
        these_names = self.names.get(v, {})

        r = set()
        for flag_set in x:
            for i in six.itervalues(these_names):
                if i.short == flag_set:
                    r.add("{} ({})".format(i.long, i.short))
                    break
            else:
                r.add(flag_set)
        return repr(r)


class FixedPointField(BitField):
    __slots__ = ['frac_bits']

    def __init__(self, name, default, size, frac_bits=16):
        self.frac_bits = frac_bits
        BitField.__init__(self, name, default, size)

    def any2i(self, pkt, val):
        if val is None:
            return val
        ival = int(val)
        fract = int((val - ival) * 2**self.frac_bits)
        return (ival << self.frac_bits) | fract

    def i2h(self, pkt, val):
        int_part = val >> self.frac_bits
        frac_part = val & (1 << self.frac_bits) - 1
        frac_part /= 2.0**self.frac_bits
        return int_part + frac_part

    def i2repr(self, pkt, val):
        return self.i2h(pkt, val)


# Base class for IPv4 and IPv6 Prefixes inspired by IPField and IP6Field.
# Machine values are encoded in a multiple of wordbytes bytes.
class _IPPrefixFieldBase(Field):
    __slots__ = ["wordbytes", "maxbytes", "aton", "ntoa", "length_from"]

    def __init__(self, name, default, wordbytes, maxbytes, aton, ntoa, length_from):  # noqa: E501
        self.wordbytes = wordbytes
        self.maxbytes = maxbytes
        self.aton = aton
        self.ntoa = ntoa
        Field.__init__(self, name, default, "%is" % self.maxbytes)
        self.length_from = length_from

    def _numbytes(self, pfxlen):
        wbits = self.wordbytes * 8
        return ((pfxlen + (wbits - 1)) // wbits) * self.wordbytes

    def h2i(self, pkt, x):
        # "fc00:1::1/64" -> ("fc00:1::1", 64)
        [pfx, pfxlen] = x.split('/')
        self.aton(pfx)  # check for validity
        return (pfx, int(pfxlen))

    def i2h(self, pkt, x):
        # ("fc00:1::1", 64) -> "fc00:1::1/64"
        (pfx, pfxlen) = x
        return "%s/%i" % (pfx, pfxlen)

    def i2m(self, pkt, x):
        # ("fc00:1::1", 64) -> (b"\xfc\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 64)  # noqa: E501
        (pfx, pfxlen) = x
        s = self.aton(pfx)
        return (s[:self._numbytes(pfxlen)], pfxlen)

    def m2i(self, pkt, x):
        # (b"\xfc\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 64) -> ("fc00:1::1", 64)  # noqa: E501
        (s, pfxlen) = x

        if len(s) < self.maxbytes:
            s = s + (b"\0" * (self.maxbytes - len(s)))
        return (self.ntoa(s), pfxlen)

    def any2i(self, pkt, x):
        if x is None:
            return (self.ntoa(b"\0" * self.maxbytes), 1)

        return self.h2i(pkt, x)

    def i2len(self, pkt, x):
        (_, pfxlen) = x
        return pfxlen

    def addfield(self, pkt, s, val):
        (rawpfx, pfxlen) = self.i2m(pkt, val)
        fmt = "!%is" % self._numbytes(pfxlen)
        return s + struct.pack(fmt, rawpfx)

    def getfield(self, pkt, s):
        pfxlen = self.length_from(pkt)
        numbytes = self._numbytes(pfxlen)
        fmt = "!%is" % numbytes
        return s[numbytes:], self.m2i(pkt, (struct.unpack(fmt, s[:numbytes])[0], pfxlen))  # noqa: E501


class IPPrefixField(_IPPrefixFieldBase):
    def __init__(self, name, default, wordbytes=1, length_from=None):
        _IPPrefixFieldBase.__init__(self, name, default, wordbytes, 4, inet_aton, inet_ntoa, length_from)  # noqa: E501


class IP6PrefixField(_IPPrefixFieldBase):
    def __init__(self, name, default, wordbytes=1, length_from=None):
        _IPPrefixFieldBase.__init__(self, name, default, wordbytes, 16, lambda a: inet_pton(socket.AF_INET6, a), lambda n: inet_ntop(socket.AF_INET6, n), length_from)  # noqa: E501


class UTCTimeField(IntField):
    __slots__ = ["epoch", "delta", "strf",
                 "use_msec", "use_micro", "use_nano"]

    # Do not change the order of the keywords in here
    # Netflow heavily rely on this
    def __init__(self, name, default,
                 use_msec=False,
                 use_micro=False,
                 use_nano=False,
                 epoch=None,
                 strf="%a, %d %b %Y %H:%M:%S %z"):
        IntField.__init__(self, name, default)
        mk_epoch = EPOCH if epoch is None else calendar.timegm(epoch)
        self.epoch = mk_epoch
        self.delta = mk_epoch - EPOCH
        self.strf = strf
        self.use_msec = use_msec
        self.use_micro = use_micro
        self.use_nano = use_nano

    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        elif self.use_msec:
            x = x / 1e3
        elif self.use_micro:
            x = x / 1e6
        elif self.use_nano:
            x = x / 1e9
        x = int(x) + self.delta
        t = time.strftime(self.strf, time.gmtime(x))
        return "%s (%d)" % (t, x)

    def i2m(self, pkt, x):
        return int(x) if x is not None else 0


class SecondsIntField(IntField):
    __slots__ = ["use_msec", "use_micro", "use_nano"]

    # Do not change the order of the keywords in here
    # Netflow heavily rely on this
    def __init__(self, name, default,
                 use_msec=False,
                 use_micro=False,
                 use_nano=False):
        IntField.__init__(self, name, default)
        self.use_msec = use_msec
        self.use_micro = use_micro
        self.use_nano = use_nano

    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        elif self.use_msec:
            x = x / 1e3
        elif self.use_micro:
            x = x / 1e6
        elif self.use_nano:
            x = x / 1e9
        return "%s sec" % x


class ScalingField(Field):
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
    __slots__ = ["scaling", "unit", "offset", "ndigits"]

    def __init__(self, name, default, scaling=1, unit="",
                 offset=0, ndigits=3, fmt="B"):
        self.scaling = scaling
        self.unit = unit
        self.offset = offset
        self.ndigits = ndigits
        Field.__init__(self, name, default, fmt)

    def i2m(self, pkt, x):
        if x is None:
            x = 0
        x = (x - self.offset) / self.scaling
        if isinstance(x, float) and self.fmt[-1] != "f":
            x = int(round(x))
        return x

    def m2i(self, pkt, x):
        x = x * self.scaling + self.offset
        if isinstance(x, float) and self.fmt[-1] != "f":
            x = round(x, self.ndigits)
        return x

    def any2i(self, pkt, x):
        if isinstance(x, str) or isinstance(x, bytes):
            x = struct.unpack(self.fmt, bytes_encode(x))[0]
            x = self.m2i(pkt, x)
        return x

    def i2repr(self, pkt, x):
        return "%s %s" % (self.i2h(pkt, x), self.unit)

    def randval(self):
        value = super(ScalingField, self).randval()
        if value is not None:
            min_val = round(value.min * self.scaling + self.offset,
                            self.ndigits)
            max_val = round(value.max * self.scaling + self.offset,
                            self.ndigits)

            return RandFloat(min(min_val, max_val), max(min_val, max_val))


class UUIDField(Field):
    """Field for UUID storage, wrapping Python's uuid.UUID type.

    The internal storage format of this field is ``uuid.UUID`` from the Python
    standard library.

    There are three formats (``uuid_fmt``) for this field type::

    * ``FORMAT_BE`` (default): the UUID is six fields in big-endian byte order,
      per RFC 4122.

      This format is used by DHCPv6 (RFC 6355) and most network protocols.

    * ``FORMAT_LE``: the UUID is six fields, with ``time_low``, ``time_mid``
      and ``time_high_version`` in little-endian byte order. This _doesn't_
      change the arrangement of the fields from RFC 4122.

      This format is used by Microsoft's COM/OLE libraries.

    * ``FORMAT_REV``: the UUID is a single 128-bit integer in little-endian
      byte order. This _changes the arrangement_ of the fields.

      This format is used by Bluetooth Low Energy.

    Note: You should use the constants here.

    The "human encoding" of this field supports a number of different input
    formats, and wraps Python's ``uuid.UUID`` library appropriately::

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
        self.uuid_fmt = uuid_fmt
        self._check_uuid_fmt()
        Field.__init__(self, name, default, "16s")

    def _check_uuid_fmt(self):
        """Checks .uuid_fmt, and raises an exception if it is not valid."""
        if self.uuid_fmt not in UUIDField.FORMATS:
            raise FieldValueRangeException(
                "Unsupported uuid_fmt ({})".format(self.uuid_fmt))

    def i2m(self, pkt, x):
        self._check_uuid_fmt()
        if x is None:
            return b'\0' * 16
        if self.uuid_fmt == UUIDField.FORMAT_BE:
            return x.bytes
        elif self.uuid_fmt == UUIDField.FORMAT_LE:
            return x.bytes_le
        elif self.uuid_fmt == UUIDField.FORMAT_REV:
            return x.bytes[::-1]

    def m2i(self, pkt, x):
        self._check_uuid_fmt()
        if self.uuid_fmt == UUIDField.FORMAT_BE:
            return UUID(bytes=x)
        elif self.uuid_fmt == UUIDField.FORMAT_LE:
            return UUID(bytes_le=x)
        elif self.uuid_fmt == UUIDField.FORMAT_REV:
            return UUID(bytes=x[::-1])

    def any2i(self, pkt, x):
        # Python's uuid doesn't handle bytearray, so convert to an immutable
        # type first.
        if isinstance(x, bytearray):
            x = bytes(x)

        if isinstance(x, six.integer_types):
            x = UUID(int=x)
        elif isinstance(x, tuple):
            if len(x) == 11:
                # For compatibility with dce_rpc: this packs into a tuple where
                # elements 7..10 are the 48-bit node ID.
                node = 0
                for i in x[5:]:
                    node = (node << 8) | i

                x = (x[0], x[1], x[2], x[3], x[4], node)

            x = UUID(fields=x)
        elif isinstance(x, (six.binary_type, six.text_type)):
            if len(x) == 16:
                # Raw bytes
                x = self.m2i(pkt, x)
            else:
                x = UUID(plain_str(x))
        return x

    @staticmethod
    def randval():
        return RandUUID()


class BitExtendedField(Field):
    """
    Bit Extended Field
    ------------------

    This type of field has a variable number of bytes. Each byte is defined
    as follows:
    - 7 bits of data
    - 1 bit an an extension bit
        * 0 means it is last byte of the field ("stopping bit")
        * 1 means there is another byte after this one ("forwarding bit")

    To get the actual data, it is necessary to hop the binary data byte per
    byte and to check the extension bit until 0
    """

    __slots__ = ["extension_bit"]

    def prepare_byte(self, x):
        # Moves the forwarding bit to the LSB
        x = int(x)
        fx_bit = (x & 2**self.extension_bit) >> self.extension_bit
        lsb_bits = x & 2**self.extension_bit - 1
        msb_bits = x >> (self.extension_bit + 1)
        x = (msb_bits << (self.extension_bit + 1)) + (lsb_bits << 1) + fx_bit
        return x

    def str2extended(self, x=""):
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
            return None, None
        else:
            return end, bits

    def extended2str(self, x):
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
        Field.__init__(self, name, default, "B")
        self.extension_bit = extension_bit

    def i2m(self, pkt, x):
        return self.extended2str(x)

    def m2i(self, pkt, x):
        return self.str2extended(x)[1]

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        return self.str2extended(s)


class LSBExtendedField(BitExtendedField):
    # This is a BitExtendedField with the extension bit on LSB
    def __init__(self, name, default):
        BitExtendedField.__init__(self, name, default, extension_bit=0)


class MSBExtendedField(BitExtendedField):
    # This is a BitExtendedField with the extension bit on MSB
    def __init__(self, name, default):
        BitExtendedField.__init__(self, name, default, extension_bit=7)
