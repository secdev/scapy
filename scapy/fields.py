## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Fields: basic data structures that make up parts of packets.
"""

from __future__ import absolute_import
import struct,copy,socket,collections
from scapy.config import conf
from scapy.dadict import DADict
from scapy.volatile import *
from scapy.data import *
from scapy.compat import *
from scapy.utils import *
from scapy.base_classes import BasePacket, Gen, Net, Field_metaclass
from scapy.error import warning
import scapy.modules.six as six
from scapy.modules.six.moves import range


############
## Fields ##
############

class Field(six.with_metaclass(Field_metaclass, object)):
    """For more informations on how this work, please refer to
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
            self.fmt = "!"+fmt
        self.default = self.any2i(None,default)
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
            return raw(x)
        return x
    def any2i(self, pkt, x):
        """Try to understand the most input values possible and make an internal value from them"""
        return self.h2i(pkt, x)
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        return repr(self.i2h(pkt,x))
    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""
        return s+struct.pack(self.fmt, self.i2m(pkt,val))
    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        return  s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, s[:self.sz])[0])
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
        return "<Field (%s).%s>" % (",".join(x.__name__ for x in self.owners),self.name)
    def copy(self):
        return copy.deepcopy(self)
    def randval(self):
        """Return a volatile object whose value is both random and suitable for this field"""
        fmtt = self.fmt[-1]
        if fmtt in "BHIQ":
            return {"B":RandByte,"H":RandShort,"I":RandInt, "Q":RandLong}[fmtt]()
        elif fmtt == "s":
            if self.fmt[0] in "0123456789":
                l = int(self.fmt[:-1])
            else:
                l = int(self.fmt[1:-1])
            return RandBin(l)
        else:
            warning("no random class for [%s] (fmt=%s).", self.name, self.fmt)




class Emph(object):
    __slots__ = ["fld"]
    def __init__(self, fld):
        self.fld = fld
    def __getattr__(self, attr):
        return getattr(self.fld,attr)
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
        return getattr(self._fld,attr)


class ConditionalField(object):
    __slots__ = ["fld", "cond"]
    def __init__(self, fld, cond):
        self.fld = fld
        self.cond = cond
    def _evalcond(self,pkt):
        return self.cond(pkt)

    def getfield(self, pkt, s):
        if self._evalcond(pkt):
            return self.fld.getfield(pkt,s)
        else:
            return s,None

    def addfield(self, pkt, s, val):
        if self._evalcond(pkt):
            return self.fld.addfield(pkt,s,val)
        else:
            return s
    def __getattr__(self, attr):
        return getattr(self.fld,attr)


class PadField(object):
    """Add bytes after the proxified field so that it ends at the specified
       alignment from its beginning"""
    __slots__ = ["_fld", "_align", "_padwith"]
    def __init__(self, fld, align, padwith=None):
        self._fld = fld
        self._align = align
        self._padwith = padwith or b""

    def padlen(self, flen):
        return -flen%self._align

    def getfield(self, pkt, s):
        remain,val = self._fld.getfield(pkt,s)
        padlen = self.padlen(len(s)-len(remain))
        return remain[padlen:], val

    def addfield(self, pkt, s, val):
        sval = self._fld.addfield(pkt, b"", val)
        return s+sval+struct.pack("%is" % (self.padlen(len(sval))), self._padwith)

    def __getattr__(self, attr):
        return getattr(self._fld,attr)


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
            except:
                pass
            else:
                if ret:
                    return ret
        return x
    def i2m(self, pkt, x):
        return inet_aton(x)
    def m2i(self, pkt, x):
        return inet_ntoa(x)
    def any2i(self, pkt, x):
        return self.h2i(pkt,x)
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
            import scapy.route
        dst = ("0.0.0.0" if self.dstname is None
               else getattr(pkt, self.dstname))
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




class ByteField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")

class XByteField(ByteField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))

class OByteField(ByteField):
    def i2repr(self, pkt, x):
        return "%03o"%self.i2h(pkt, x)

class X3BytesField(XByteField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "!I")
    def addfield(self, pkt, s, val):
        return s+struct.pack(self.fmt, self.i2m(pkt,val))[1:4]
    def getfield(self, pkt, s):
        return  s[3:], self.m2i(pkt, struct.unpack(self.fmt, b"\x00"+s[:3])[0])

class ThreeBytesField(X3BytesField, ByteField):
    def i2repr(self, pkt, x):
        return ByteField.i2repr(self, pkt, x)

class SignedByteField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "b")


class FieldValueRangeException(Scapy_Exception):
    pass


class FieldAttributeException(Scapy_Exception):
    pass


class YesNoByteField(ByteField):
    """
    byte based flag field that shows representation of its number based on a given association

    in its default configuration the following representation is generated:
        x == 0 : 'no'
        x != 0 : 'yes'

    in more sophisticated use-cases (e.g. yes/no/invalid) one can use the config attribute to configure
    key-value, key-range and key-value-set associations that will be used to generate the values representation.

    a range is given by a tuple (<first-val>, <last-value>) including the last value. a single-value tuple
    is treated as scalar.

    a list defines a set of (probably non consecutive) values that should be associated to a given key.

    all values not associated with a key will be shown as number of type unsigned byte.

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
                    raise FieldValueRangeException('given field value {} invalid - '
                                                   'must be in range [0..255]'.format(value_spec))
                assoc_table[value_spec] = key

            elif value_spec_type is list:
                for value in value_spec:
                    if value < 0 or value > 255:
                        raise FieldValueRangeException('given field value {} invalid - '
                                                       'must be in range [0..255]'.format(value))
                    assoc_table[value] = key

            elif value_spec_type is tuple:
                value_spec_len = len(value_spec)
                if value_spec_len != 2:
                    raise FieldAttributeException('invalid length {} of given config item tuple {} - must be '
                                                  '(<start-range>, <end-range>).'.format(value_spec_len, value_spec))

                value_range_start = value_spec[0]
                if value_range_start < 0 or value_range_start > 255:
                    raise FieldValueRangeException('given field value {} invalid - '
                                                   'must be in range [0..255]'.format(value_range_start))

                value_range_end = value_spec[1]
                if value_range_end < 0 or value_range_end > 255:
                    raise FieldValueRangeException('given field value {} invalid - '
                                                   'must be in range [0..255]'.format(value_range_end))

                for value in range(value_range_start, value_range_end + 1):

                    assoc_table[value] = key

        self.eval_fn = lambda x: assoc_table[x] if x in assoc_table else x

    def __init__(self, name, default, config=None, *args, **kargs):

        if not config:
            # this represents the common use case and therefore it is kept small
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
    def randval(self):
        return RandSInt()

class LEIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<I")

class LESignedIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<i")
    def randval(self):
        return RandSInt()

class XIntField(IntField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class LongField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "Q")

class LELongField(LongField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<Q")

class XLongField(LongField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))

class IEEEFloatField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "f")

class IEEEDoubleField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "d")


class StrField(Field):
    __slots__ = ["remain"]
    def __init__(self, name, default, fmt="H", remain=0):
        Field.__init__(self,name,default,fmt)
        self.remain = remain
    def i2len(self, pkt, i):
        return len(i)
    def any2i(self, pkt, x):
        if isinstance(x, str if six.PY3 else unicode):
            x = raw(x)
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
            return raw(x)
        return x
    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)
    def getfield(self, pkt, s):
        if self.remain == 0:
            return b"", self.m2i(pkt, s)
        else:
            return s[-self.remain:],self.m2i(pkt, s[:-self.remain])
    def randval(self):
        return RandBin(RandNum(0,1200))

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
        return remain,i

class PacketLenField(PacketField):
    __slots__ = ["length_from"]
    def __init__(self, name, default, cls, length_from=None):
        PacketField.__init__(self, name, default, cls)
        self.length_from = length_from
    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        try:
            i = self.m2i(pkt, s[:l])
        except Exception:
            if conf.debug_dissector:
                raise
            i = conf.raw_layer(load=s[:l])
        return s[l:],i


class PacketListField(PacketField):
    """ PacketListField represents a series of Packet instances that might occur right in the middle of another Packet
    field list.
    This field type may also be used to indicate that a series of Packet instances have a sibling semantic instead of
    a parent/child relationship (i.e. a stack of layers).
    """
    __slots__ = ["count_from", "length_from", "next_cls_cb"]
    islist = 1
    def __init__(self, name, default, cls=None, count_from=None, length_from=None, next_cls_cb=None):
        """ The number of Packet instances that are dissected by this field can be parametrized using one of three
        different mechanisms/parameters:
            * count_from: a callback that returns the number of Packet instances to dissect. The callback prototype is:
            count_from(pkt:Packet) -> int
            * length_from: a callback that returns the number of bytes that must be dissected by this field. The
            callback prototype is:
            length_from(pkt:Packet) -> int
            * next_cls_cb: a callback that enables a Scapy developer to dynamically discover if another Packet instance
            should be dissected or not. See below for this callback prototype.

        The bytes that are not consumed during the dissection of this field are passed to the next field of the current
        packet.

        For the serialization of such a field, the list of Packets that are contained in a PacketListField can be
        heterogeneous and is unrestricted.

        The type of the Packet instances that are dissected with this field is specified or discovered using one of the
        following mechanism:
            * the cls parameter may contain a callable that returns an instance of the dissected Packet. This
                may either be a reference of a Packet subclass (e.g. DNSRROPT in layers/dns.py) to generate an
                homogeneous PacketListField or a function deciding the type of the Packet instance
                (e.g. _CDPGuessAddrRecord in contrib/cdp.py)
            * the cls parameter may contain a class object with a defined "dispatch_hook" classmethod. That
                method must return a Packet instance. The dispatch_hook callmethod must implement the following prototype:
                dispatch_hook(cls, _pkt:Optional[Packet], *args, **kargs) -> Packet_metaclass
                The _pkt parameter may contain a reference to the packet instance containing the PacketListField that is
                being dissected.
            * the next_cls_cb parameter may contain a callable whose prototype is:
                cbk(pkt:Packet, lst:List[Packet], cur:Optional[Packet], remain:str) -> Optional[Packet_metaclass]
                The pkt argument contains a reference to the Packet instance containing the PacketListField that is
                being dissected. The lst argument is the list of all Packet instances that were previously parsed during
                the current PacketListField dissection, save for the very last Packet instance. The cur argument
                contains a reference to that very last parsed Packet instance. The remain argument contains the bytes
                that may still be consumed by the current PacketListField dissection operation. This callback returns
                either the type of the next Packet to dissect or None to indicate that no more Packet are to be
                dissected.
                These four arguments allows a variety of dynamic discovery of the number of Packet to dissect and of the
                type of each one of these Packets, including: type determination based on current Packet instances or
                its underlayers, continuation based on the previously parsed Packet instances within that
                PacketListField, continuation based on a look-ahead on the bytes to be dissected...

        The cls and next_cls_cb parameters are semantically exclusive, although one could specify both. If both are
        specified, cls is silently ignored. The same is true for count_from and next_cls_cb.
        length_from and next_cls_cb are compatible and the dissection will end, whichever of the two stop conditions
        comes first.

        @param name: the name of the field
        @param default: the default value of this field; generally an empty Python list
        @param cls: either a callable returning a Packet instance or a class object defining a dispatch_hook class
            method
        @param count_from: a callback returning the number of Packet instances to dissect
        @param length_from: a callback returning the number of bytes to dissect
        @param next_cls_cb: a callback returning either None or the type of the next Packet to dissect.
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
        return sum( len(p) for p in val )
    def do_copy(self, x):
        if x is None:
            return None
        else:
            return [p if isinstance(p, six.string_types) else p.copy() for p in x]
    def getfield(self, pkt, s):
        c = l = cls = None
        if self.length_from is not None:
            l = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)
        if self.next_cls_cb is not None:
            cls = self.next_cls_cb(pkt, [], None, s)
            c = 1

        lst = []
        ret = b""
        remain = s
        if l is not None:
            remain,ret = s[:l],s[l:]
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
                            c += 1
                else:
                    remain = b""
            lst.append(p)
        return remain+ret,lst
    def addfield(self, pkt, s, val):
        return s + b"".join(raw(v) for v in val)


class StrFixedLenField(StrField):
    __slots__ = ["length_from"]
    def __init__(self, name, default, length=None, length_from=None):
        StrField.__init__(self, name, default)
        self.length_from  = length_from
        if length is not None:
            self.length_from = lambda pkt,length=length: length
    def i2repr(self, pkt, v):
        if isinstance(v, bytes):
            v = v.rstrip(b"\0")
        return super(StrFixedLenField, self).i2repr(pkt, v)
    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        return s[l:], self.m2i(pkt,s[:l])
    def addfield(self, pkt, s, val):
        l = self.length_from(pkt)
        return s+struct.pack("%is"%l,self.i2m(pkt, val))
    def randval(self):
        try:
            l = self.length_from(None)
        except:
            l = RandNum(0,200)
        return RandBin(l)

class StrFixedLenEnumField(StrFixedLenField):
    __slots__ = ["enum"]
    def __init__(self, name, default, length=None, enum=None, length_from=None):
        StrFixedLenField.__init__(self, name, default, length=length, length_from=length_from)
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
        l = self.length_from(pkt)//2
        if x is None:
            x = b""
        x += b" "*(l)
        x = x[:l]
        x = b"".join(chb(0x41 + orb(b)>>4) + chb(0x41 + orb(b)&0xf) for b in x)
        x = b" "+x
        return x
    def m2i(self, pkt, x):
        x = x.strip(b"\x00").strip(b" ")
        return b"".join(map(lambda x,y: chb((((orb(x)-1)&0xf)<<4)+((orb(y)-1)&0xf)), x[::2],x[1::2]))

class StrLenField(StrField):
    __slots__ = ["length_from"]
    def __init__(self, name, default, fld=None, length_from=None):
        StrField.__init__(self, name, default)
        self.length_from = length_from
    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        return s[l:], self.m2i(pkt,s[:l])

class XStrField(StrField):
    """
    StrField which value is printed as hexadecimal.
    """

    def i2repr(self, pkt, x):
        if x is None:
            return repr(x)
        return bytes_hex(x).decode()

class XStrLenField(StrLenField):
    """
    StrLenField which value is printed as hexadecimal.
    """

    def i2repr(self, pkt, x):
        if not x:
            return repr(x)
        return bytes_hex(x[:self.length_from(pkt)]).decode()

class XStrFixedLenField(StrFixedLenField):
    """
    StrFixedLenField which value is printed as hexadecimal.
    """

    def i2repr(self, pkt, x):
        if not x:
            return repr(x)
        return bytes_hex(x[:self.length_from(pkt)]).decode()

class StrLenFieldUtf16(StrLenField):
    def h2i(self, pkt, x):
        return plain_str(x).encode('utf-16')[2:]
    def i2h(self, pkt, x):
        return x.decode('utf-16')

class BoundStrLenField(StrLenField):
    __slots__ = ["minlen", "maxlen"]
    def __init__(self,name, default, minlen= 0, maxlen= 255, fld=None, length_from=None):
        StrLenField.__init__(self, name, default, fld, length_from)
        self.minlen = minlen
        self.maxlen = maxlen

    def randval(self):
        return RandBin(RandNum(self.minlen, self.maxlen))

class FieldListField(Field):
    __slots__ = ["field", "count_from", "length_from"]
    islist = 1
    def __init__(self, name, default, field, length_from=None, count_from=None):
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
        return int(sum(self.field.i2len(pkt,v) for v in val))

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
        c = l = None
        if self.length_from is not None:
            l = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)

        val = []
        ret = b""
        if l is not None:
            s,ret = s[:l],s[l:]

        while s:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            s,v = self.field.getfield(pkt, s)
            val.append(v)
        return s+ret, val

class FieldLenField(Field):
    __slots__ = ["length_of", "count_of", "adjust"]
    def __init__(self, name, default,  length_of=None, fmt = "H", count_of=None, adjust=lambda pkt,x:x, fld=None):
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust
        if fld is not None:
            #FIELD_LENGTH_MANAGEMENT_DEPRECATION(self.__class__.__name__)
            self.length_of = fld
    def i2m(self, pkt, x):
        if x is None:
            if self.length_of is not None:
                fld,fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
            else:
                fld,fval = pkt.getfield_and_val(self.count_of)
                f = fld.i2count(pkt, fval)
            x = self.adjust(pkt,f)
        return x

class StrNullField(StrField):
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)+b"\x00"
    def getfield(self, pkt, s):
        l = s.find(b"\x00")
        if l < 0:
            #XXX \x00 not found
            return b"",s
        return s[l+1:],self.m2i(pkt, s[:l])
    def randval(self):
        return RandTermString(RandNum(0,1200),b"\x00")

class StrStopField(StrField):
    __slots__ = ["stop", "additionnal"]
    def __init__(self, name, default, stop, additionnal=0):
        Field.__init__(self, name, default)
        self.stop = stop
        self.additionnal = additionnal
    def getfield(self, pkt, s):
        l = s.find(self.stop)
        if l < 0:
            return b"",s
#            raise Scapy_Exception,"StrStopField: stop value [%s] not found" %stop
        l += len(self.stop)+self.additionnal
        return s[l:],s[:l]
    def randval(self):
        return RandTermString(RandNum(0,1200),self.stop)

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
        return int(256*x)
    def m2i(self, pkt, x):
        return x/256.0

class BitField(Field):
    __slots__ = ["rev", "size"]
    def __init__(self, name, default, size):
        Field.__init__(self, name, default)
        self.rev = size < 0
        self.size = abs(size)
    def reverse(self, val):
        if self.size == 16:
            # Replaces socket.ntohs (but work on both little/big endian)
            val = struct.unpack('>H',struct.pack('<H', int(val)))[0]
        elif self.size == 32:
            # Same here but for socket.ntohl
            val = struct.unpack('>I',struct.pack('<I', int(val)))[0]
        return val

    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        if isinstance(s, tuple):
            s,bitsdone,v = s
        else:
            bitsdone = 0
            v = 0
        if self.rev:
            val = self.reverse(val)
        v <<= self.size
        v |= val & ((1<<self.size) - 1)
        bitsdone += self.size
        while bitsdone >= 8:
            bitsdone -= 8
            s = s+struct.pack("!B", v >> bitsdone)
            v &= (1<<bitsdone)-1
        if bitsdone:
            return s,bitsdone,v
        else:
            return s
    def getfield(self, pkt, s):
        if isinstance(s, tuple):
            s,bn = s
        else:
            bn = 0
        # we don't want to process all the string
        nb_bytes = (self.size+bn-1)//8 + 1
        w = s[:nb_bytes]

        # split the substring byte by byte
        _bytes = struct.unpack('!%dB' % nb_bytes , w)

        b = 0
        for c in range(nb_bytes):
            b |= int(_bytes[c]) << (nb_bytes-c-1)*8

        # get rid of high order bits
        b &= (1 << (nb_bytes*8-bn)) - 1

        # remove low order bits
        b = b >> (nb_bytes*8 - self.size - bn)

        if self.rev:
            b = self.reverse(b)

        bn += self.size
        s = s[bn//8:]
        bn = bn%8
        b = self.m2i(pkt, b)
        if bn:
            return (s,bn),b
        else:
            return s,b
    def randval(self):
        return RandNum(0,2**self.size-1)
    def i2len(self, pkt, x):
        return float(self.size)/8


class BitFieldLenField(BitField):
    __slots__ = ["length_of", "count_of", "adjust"]
    def __init__(self, name, default, size, length_of=None, count_of=None, adjust=lambda pkt,x:x):
        BitField.__init__(self, name, default, size)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust
    def i2m(self, pkt, x):
        return (FieldLenField.i2m.__func__ if six.PY2 else FieldLenField.i2m)(self, pkt, x)


class XBitField(BitField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt,x))


class _EnumField(Field):
    def __init__(self, name, default, enum, fmt = "H"):
        """ Initializes enum fields.

        @param name:    name of this field
        @param default: default value of this field
        @param enum:    either a dict or a tuple of two callables. Dict keys are
                        the internal values, while the dict values are the
                        user-friendly representations. If the tuple is provided,
                        the first callable receives the internal value as
                        parameter and returns the user-friendly representation
                        and the second callable does the converse. The first
                        callable may return None to default to a literal string
                        (repr()) representation.
        @param fmt:     struct.pack format used to parse and serialize the
                        internal value from and to machine representation.
        """
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
                keys = range(len(enum))
            elif isinstance(enum, DADict):
                keys = enum.iterkeys()
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
        if self not in conf.noenum and not isinstance(x,VolatileValue):
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
            return self.any2i_one(pkt,x)

    def i2repr(self, pkt, x):
        if isinstance(x, list):
            return [self.i2repr_one(pkt, z) for z in x]
        else:
            return self.i2repr_one(pkt,x)

class EnumField(_EnumField):
    __slots__ = ["i2s", "s2i", "s2i_cb", "i2s_cb"]

class CharEnumField(EnumField):
    def __init__(self, name, default, enum, fmt = "1s"):
        EnumField.__init__(self, name, default, enum, fmt)
        if self.i2s is not None:
            k = list(self.i2s)
            if k and len(k[0]) != 1:
                self.i2s,self.s2i = self.s2i,self.i2s
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

class IntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "I")

class SignedIntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "i")
    def randval(self):
        return RandSInt()

class LEIntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "<I")

class XShortEnumField(ShortEnumField):
    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x,VolatileValue):
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
    def __init__(self, name, default, enum, depends_on, fmt = "H"):

        self.depends_on = depends_on
        self.i2s_multi = enum
        self.s2i_multi = {}
        self.s2i_all = {}
        for m in enum:
            self.s2i_multi[m] = s2i = {}
            for k,v in six.iteritems(enum[m]):
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
            return self.i2s_multi[v].get(x,x)
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


# Little endian long field
class LELongField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<Q")

# Little endian fixed length field
class LEFieldLenField(FieldLenField):
    def __init__(self, name, default,  length_of=None, fmt = "<H", count_of=None, adjust=lambda pkt,x:x, fld=None):
        FieldLenField.__init__(self, name, default, length_of=length_of, fmt=fmt, count_of=count_of, fld=fld, adjust=adjust)


class FlagValue(object):
    __slots__ = ["value", "names", "multi"]
    def _fixvalue(self, value):
        if isinstance(value, six.string_types):
            value = value.split('+') if self.multi else list(value)
        if isinstance(value, list):
            y = 0
            for i in value:
                y |= 1 << self.names.index(i)
            value = y
        return None if value is None else int(value)
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
               fields_desc = [FlagsField("flags", 0, 8, ["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7"])]
       >>> FlagsTest(flags=9).show2()
       ###[ FlagsTest ]###
         flags     = f0+f3
       >>> FlagsTest(flags=0).show2().strip()
       ###[ FlagsTest ]###
         flags     =

   :param name: field's name
   :param default: default value for the field
   :param size: number of bits in the field
   :param names: (list or dict) label for each flag, Least Significant Bit tag's name is written first
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
        if isinstance(x, (list, tuple)):
            return type(x)(
                v if v is None or isinstance(v, FlagValue)
                else FlagValue(v, self.names)
                for v in x
            )
        return x if x is None or isinstance(x, FlagValue) else FlagValue(x, self.names)

    def any2i(self, pkt, x):
        return self._fixup_val(super(FlagsField, self).any2i(pkt, x))

    def m2i(self, pkt, x):
        return self._fixup_val(super(FlagsField, self).m2i(pkt, x))

    def i2h(self, pkt, x):
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
                            assert False, 'Unknown flag "{}" with this dependency'.format(i)
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
        fract = int( (val-ival) * 2**self.frac_bits )
        return (ival << self.frac_bits) | fract

    def i2h(self, pkt, val):
        int_part = val >> self.frac_bits
        frac_part = val & (1 << self.frac_bits) - 1
        frac_part /= 2.0**self.frac_bits
        return int_part+frac_part
    def i2repr(self, pkt, val):
        return self.i2h(pkt, val)


# Base class for IPv4 and IPv6 Prefixes inspired by IPField and IP6Field.
# Machine values are encoded in a multiple of wordbytes bytes.
class _IPPrefixFieldBase(Field):
    __slots__ = ["wordbytes", "maxbytes", "aton", "ntoa", "length_from"]
    def __init__(self, name, default, wordbytes, maxbytes, aton, ntoa, length_from):
        self.wordbytes = wordbytes
        self.maxbytes = maxbytes
        self.aton = aton
        self.ntoa = ntoa
        Field.__init__(self, name, default, "%is" % self.maxbytes)
        self.length_from = length_from

    def _numbytes(self, pfxlen):
        wbits= self.wordbytes * 8
        return ((pfxlen + (wbits - 1)) // wbits) * self.wordbytes

    def h2i(self, pkt, x):
        # "fc00:1::1/64" -> ("fc00:1::1", 64)
        [pfx,pfxlen]= x.split('/')
        self.aton(pfx) # check for validity
        return (pfx, int(pfxlen))


    def i2h(self, pkt, x):
        # ("fc00:1::1", 64) -> "fc00:1::1/64"
        (pfx,pfxlen)= x
        return "%s/%i" % (pfx,pfxlen)

    def i2m(self, pkt, x):
        # ("fc00:1::1", 64) -> (b"\xfc\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 64)
        (pfx,pfxlen)= x
        s= self.aton(pfx);
        return (s[:self._numbytes(pfxlen)], pfxlen)

    def m2i(self, pkt, x):
        # (b"\xfc\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 64) -> ("fc00:1::1", 64)
        (s,pfxlen)= x

        if len(s) < self.maxbytes:
            s= s + (b"\0" * (self.maxbytes - len(s)))
        return (self.ntoa(s), pfxlen)

    def any2i(self, pkt, x):
        if x is None:
            return (self.ntoa(b"\0"*self.maxbytes), 1)

        return self.h2i(pkt,x)

    def i2len(self, pkt, x):
        (_,pfxlen)= x
        return pfxlen

    def addfield(self, pkt, s, val):
        (rawpfx,pfxlen)= self.i2m(pkt,val)
        fmt= "!%is" % self._numbytes(pfxlen)
        return s+struct.pack(fmt, rawpfx)

    def getfield(self, pkt, s):
        pfxlen= self.length_from(pkt)
        numbytes= self._numbytes(pfxlen)
        fmt= "!%is" % numbytes
        return s[numbytes:], self.m2i(pkt, (struct.unpack(fmt, s[:numbytes])[0], pfxlen))


class IPPrefixField(_IPPrefixFieldBase):
    def __init__(self, name, default, wordbytes=1, length_from= None):
        _IPPrefixFieldBase.__init__(self, name, default, wordbytes, 4, inet_aton, inet_ntoa, length_from)


class IP6PrefixField(_IPPrefixFieldBase):
    def __init__(self, name, default, wordbytes= 1, length_from= None):
        _IPPrefixFieldBase.__init__(self, name, default, wordbytes, 16, lambda a: inet_pton(socket.AF_INET6, a), lambda n: inet_ntop(socket.AF_INET6, n), length_from)

class UTCTimeField(IntField):
    __slots__ = ["epoch", "delta", "strf", "use_nano"]
    def __init__(self, name, default, epoch=None, use_nano=False, strf="%a, %d %b %Y %H:%M:%S +0000"):
        IntField.__init__(self, name, default)
        mk_epoch = EPOCH if epoch is None else time.mktime(epoch)
        self.epoch = mk_epoch
        self.delta = mk_epoch - EPOCH
        self.strf = strf
        self.use_nano = use_nano
    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        elif self.use_nano:
            x = x/1e9
        x = int(x) + self.delta
        t = time.strftime(self.strf, time.gmtime(x))
        return "%s (%d)" % (t, x)
    def i2m(self, pkt, x):
        return int(x) if x != None else 0

class SecondsIntField(IntField):
    __slots__ = ["use_msec"]
    def __init__(self, name, default, use_msec=False):
        IntField.__init__(self, name, default)
        self.use_msec = use_msec
    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        elif self.use_msec:
            x = x/1e3
        return "%s sec" % x
