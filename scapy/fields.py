## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Fields: basic data structures that make up parts of packets.
"""

import struct,copy,socket
from config import conf
from volatile import *
from data import *
from utils import *
from base_classes import BasePacket,Gen,Net


############
## Fields ##
############

class Field:
    """For more informations on how this work, please refer to
       http://www.secdev.org/projects/scapy/files/scapydoc.pdf
       chapter ``Adding a New Field''"""
    islist=0
    holds_packets=0
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
        if type(x) is list:
            x = x[:]
            for i in xrange(len(x)):
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
            warning("no random class for [%s] (fmt=%s)." % (self.name, self.fmt))
            



class Emph:
    fld = ""
    def __init__(self, fld):
        self.fld = fld
    def __getattr__(self, attr):
        return getattr(self.fld,attr)
    def __hash__(self):
        return hash(self.fld)
    def __eq__(self, other):
        return self.fld == other
    

class ActionField:
    _fld = None
    def __init__(self, fld, action_method, **kargs):
        self._fld = fld
        self._action_method = action_method
        self._privdata = kargs
    def any2i(self, pkt, val):
        getattr(pkt, self._action_method)(val, self._fld, **self._privdata)
        return getattr(self._fld, "any2i")(pkt, val)
    def __getattr__(self, attr):
        return getattr(self._fld,attr)


class ConditionalField:
    fld = None
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
        

class PadField:
    """Add bytes after the proxified field so that it ends at the specified
       alignment from its begining"""
    _fld = None
    def __init__(self, fld, align, padwith=None):
        self._fld = fld
        self._align = align
        self._padwith = padwith or ""

    def padlen(self, flen):
        return -flen%self._align

    def getfield(self, pkt, s):
        remain,val = self._fld.getfield(pkt,s)
        padlen = self.padlen(len(s)-len(remain))
        return remain[padlen:], val

    def addfield(self, pkt, s, val):
        sval = self._fld.addfield(pkt, "", val)
        return s+sval+struct.pack("%is" % (self.padlen(len(sval))), self._padwith)
    
    def __getattr__(self, attr):
        return getattr(self._fld,attr)
        

class MACField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "6s")
    def i2m(self, pkt, x):
        if x is None:
            return "\0\0\0\0\0\0"
        return mac2str(x)
    def m2i(self, pkt, x):
        return str2mac(x)
    def any2i(self, pkt, x):
        if type(x) is str and len(x) is 6:
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
    def __init__(self, name, default):
        Field.__init__(self, name, default, "4s")
    def h2i(self, pkt, x):
        if type(x) is str:
            try:
                inet_aton(x)
            except socket.error:
                x = Net(x)
        elif type(x) is list:
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
        return self.resolve(self.i2h(pkt, x))
    def randval(self):
        return RandIP()

class SourceIPField(IPField):
    def __init__(self, name, dstname):
        IPField.__init__(self, name, None)
        self.dstname = dstname
    def i2m(self, pkt, x):
        if x is None:
            iff,x,gw = pkt.route()
            if x is None:
                x = "0.0.0.0"
        return IPField.i2m(self, pkt, x)
    def i2h(self, pkt, x):
        if x is None:
            dst=getattr(pkt,self.dstname)
            if isinstance(dst,Gen):
                r = map(conf.route.route, dst)
                r.sort()
                if r[0] != r[-1]:
                    warning("More than one possible route for %s"%repr(dst))
                iff,x,gw = r[0]
            else:
                iff,x,gw = conf.route.route(dst)
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
        return  s[3:], self.m2i(pkt, struct.unpack(self.fmt, "\x00"+s[:3])[0])


class ShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "H")

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
    def __init__(self, name, default, fmt="H", remain=0):
        Field.__init__(self,name,default,fmt)
        self.remain = remain        
    def i2len(self, pkt, i):
        return len(i)
    def i2m(self, pkt, x):
        if x is None:
            x = ""
        elif type(x) is not str:
            x=str(x)
        return x
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)
    def getfield(self, pkt, s):
        if self.remain == 0:
            return "",self.m2i(pkt, s)
        else:
            return s[-self.remain:],self.m2i(pkt, s[:-self.remain])
    def randval(self):
        return RandBin(RandNum(0,1200))

class PacketField(StrField):
    holds_packets=1
    def __init__(self, name, default, cls, remain=0):
        StrField.__init__(self, name, default, remain=remain)
        self.cls = cls
    def i2m(self, pkt, i):
        return str(i)
    def m2i(self, pkt, m):
        return self.cls(m)
    def getfield(self, pkt, s):
        i = self.m2i(pkt, s)
        remain = ""
        if conf.padding_layer in i:
            r = i[conf.padding_layer]
            del(r.underlayer.payload)
            remain = r.load
        return remain,i
    
class PacketLenField(PacketField):
    holds_packets=1
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
    islist = 1
    holds_packets=1
    def __init__(self, name, default, cls, count_from=None, length_from=None):
        if default is None:
            default = []  # Create a new list for each instance
        PacketField.__init__(self, name, default, cls)
        self.count_from = count_from
        self.length_from = length_from


    def any2i(self, pkt, x):
        if type(x) is not list:
            return [x]
        else:
            return x
    def i2count(self, pkt, val):
        if type(val) is list:
            return len(val)
        return 1
    def i2len(self, pkt, val):
        return sum( len(p) for p in val )
    def do_copy(self, x):
        return map(lambda p:p.copy(), x)
    def getfield(self, pkt, s):
        c = l = None
        if self.length_from is not None:
            l = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)
            
        lst = []
        ret = ""
        remain = s
        if l is not None:
            remain,ret = s[:l],s[l:]
        while remain:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            try:
                p = self.m2i(pkt,remain)
            except Exception:
                if conf.debug_dissector:
                    raise
                p = conf.raw_layer(load=remain)
                remain = ""
            else:
                if conf.padding_layer in p:
                    pad = p[conf.padding_layer]
                    remain = pad.load
                    del(pad.underlayer.payload)
                else:
                    remain = ""
            lst.append(p)
        return remain+ret,lst
    def addfield(self, pkt, s, val):
        return s+"".join(map(str, val))


class StrFixedLenField(StrField):
    def __init__(self, name, default, length=None, length_from=None):
        StrField.__init__(self, name, default)
        self.length_from  = length_from
        if length is not None:
            self.length_from = lambda pkt,length=length: length
    def i2repr(self, pkt, v):
        if type(v) is str:
            v = v.rstrip("\0")
        return repr(v)
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
    def __init__(self, name, default, length=None, enum=None, length_from=None):
        StrFixedLenField.__init__(self, name, default, length=length, length_from=length_from)
        self.enum = enum
    def i2repr(self, pkt, v):
        r = v.rstrip("\0")
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
        l = self.length_from(pkt)/2
        if x is None:
            x = ""
        x += " "*(l)
        x = x[:l]
        x = "".join(map(lambda x: chr(0x41+(ord(x)>>4))+chr(0x41+(ord(x)&0xf)), x))
        x = " "+x
        return x
    def m2i(self, pkt, x):
        x = x.strip("\x00").strip(" ")
        return "".join(map(lambda x,y: chr((((ord(x)-1)&0xf)<<4)+((ord(y)-1)&0xf)), x[::2],x[1::2]))

class StrLenField(StrField):
    def __init__(self, name, default, fld=None, length_from=None):
        StrField.__init__(self, name, default)
        self.length_from = length_from
    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        return s[l:], self.m2i(pkt,s[:l])

class FieldListField(Field):
    islist=1
    def __init__(self, name, default, field, length_from=None, count_from=None):
        if default is None:
            default = []  # Create a new list for each instance
        Field.__init__(self, name, default)
        self.count_from = count_from
        self.length_from = length_from
        self.field = field            
            
    def i2count(self, pkt, val):
        if type(val) is list:
            return len(val)
        return 1
    def i2len(self, pkt, val):
        return sum( self.field.i2len(pkt,v) for v in val )
    
    def i2m(self, pkt, val):
        if val is None:
            val = []
        return val
    def any2i(self, pkt, x):
        if type(x) is not list:
            return [x]
        else:
            return x
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
        ret=""
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
    def __init__(self, name, default,  length_of=None, fmt = "H", count_of=None, adjust=lambda pkt,x:x, fld=None):
        Field.__init__(self, name, default, fmt)
        self.length_of=length_of
        self.count_of=count_of
        self.adjust=adjust
        if fld is not None:
            FIELD_LENGTH_MANAGEMENT_DEPRECATION(self.__class__.__name__)
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
        return s+self.i2m(pkt, val)+"\x00"
    def getfield(self, pkt, s):
        l = s.find("\x00")
        if l < 0:
            #XXX \x00 not found
            return "",s
        return s[l+1:],self.m2i(pkt, s[:l])
    def randval(self):
        return RandTermString(RandNum(0,1200),"\x00")

class StrStopField(StrField):
    def __init__(self, name, default, stop, additionnal=0):
        Field.__init__(self, name, default)
        self.stop=stop
        self.additionnal=additionnal
    def getfield(self, pkt, s):
        l = s.find(self.stop)
        if l < 0:
            return "",s
#            raise Scapy_Exception,"StrStopField: stop value [%s] not found" %stop
        l += len(self.stop)+self.additionnal
        return s[l:],s[:l]
    def randval(self):
        return RandTermString(RandNum(0,1200),self.stop)

class LenField(Field):
    def i2m(self, pkt, x):
        if x is None:
            x = len(pkt.payload)
        return x

class BCDFloatField(Field):
    def i2m(self, pkt, x):
        return int(256*x)
    def m2i(self, pkt, x):
        return x/256.0

class BitField(Field):
    def __init__(self, name, default, size):
        Field.__init__(self, name, default)
        self.rev = size < 0 
        self.size = abs(size)
    def reverse(self, val):
        if self.size == 16:
            val = socket.ntohs(val)
        elif self.size == 32:
            val = socket.ntohl(val)
        return val
        
    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        if type(s) is tuple:
            s,bitsdone,v = s
        else:
            bitsdone = 0
            v = 0
        if self.rev:
            val = self.reverse(val)
        v <<= self.size
        v |= val & ((1L<<self.size) - 1)
        bitsdone += self.size
        while bitsdone >= 8:
            bitsdone -= 8
            s = s+struct.pack("!B", v >> bitsdone)
            v &= (1L<<bitsdone)-1
        if bitsdone:
            return s,bitsdone,v
        else:
            return s
    def getfield(self, pkt, s):
        if type(s) is tuple:
            s,bn = s
        else:
            bn = 0
        # we don't want to process all the string
        nb_bytes = (self.size+bn-1)/8 + 1
        w = s[:nb_bytes]

        # split the substring byte by byte
        bytes = struct.unpack('!%dB' % nb_bytes , w)

        b = 0L
        for c in range(nb_bytes):
            b |= long(bytes[c]) << (nb_bytes-c-1)*8

        # get rid of high order bits
        b &= (1L << (nb_bytes*8-bn)) - 1

        # remove low order bits
        b = b >> (nb_bytes*8 - self.size - bn)

        if self.rev:
            b = self.reverse(b)

        bn += self.size
        s = s[bn/8:]
        bn = bn%8
        b = self.m2i(pkt, b)
        if bn:
            return (s,bn),b
        else:
            return s,b
    def randval(self):
        return RandNum(0,2**self.size-1)


class BitFieldLenField(BitField):
    def __init__(self, name, default, size, length_of=None, count_of=None, adjust=lambda pkt,x:x):
        BitField.__init__(self, name, default, size)
        self.length_of=length_of
        self.count_of=count_of
        self.adjust=adjust
    def i2m(self, pkt, x):
        return FieldLenField.i2m.im_func(self, pkt, x)


class XBitField(BitField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt,x))


class EnumField(Field):
    def __init__(self, name, default, enum, fmt = "H"):
        i2s = self.i2s = {}
        s2i = self.s2i = {}
        if type(enum) is list:
            keys = xrange(len(enum))
        else:
            keys = enum.keys()
        if filter(lambda x: type(x) is str, keys):
            i2s,s2i = s2i,i2s
        for k in keys:
            i2s[k] = enum[k]
            s2i[enum[k]] = k
        Field.__init__(self, name, default, fmt)
    def any2i_one(self, pkt, x):
        if type(x) is str:
            x = self.s2i[x]
        return x
    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x,VolatileValue) and x in self.i2s:
            return self.i2s[x]
        return repr(x)
    
    def any2i(self, pkt, x):
        if type(x) is list:
            return map(lambda z,pkt=pkt:self.any2i_one(pkt,z), x)
        else:
            return self.any2i_one(pkt,x)        
    def i2repr(self, pkt, x):
        if type(x) is list:
            return map(lambda z,pkt=pkt:self.i2repr_one(pkt,z), x)
        else:
            return self.i2repr_one(pkt,x)

class CharEnumField(EnumField):
    def __init__(self, name, default, enum, fmt = "1s"):
        EnumField.__init__(self, name, default, enum, fmt)
        k = self.i2s.keys()
        if k and len(k[0]) != 1:
            self.i2s,self.s2i = self.s2i,self.i2s
    def any2i_one(self, pkt, x):
        if len(x) != 1:
            x = self.s2i[x]
        return x

class BitEnumField(BitField,EnumField):
    def __init__(self, name, default, size, enum):
        EnumField.__init__(self, name, default, enum)
        self.rev = size < 0
        self.size = abs(size)
    def any2i(self, pkt, x):
        return EnumField.any2i(self, pkt, x)
    def i2repr(self, pkt, x):
        return EnumField.i2repr(self, pkt, x)

class ShortEnumField(EnumField):
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
        if self not in conf.noenum and not isinstance(x,VolatileValue) and x in self.i2s:
            return self.i2s[x]
        return lhex(x)

class MultiEnumField(EnumField):
    def __init__(self, name, default, enum, depends_on, fmt = "H"):
        
        self.depends_on = depends_on
        self.i2s_multi = enum
        self.s2i_multi = {}
        self.s2i_all = {}
        for m in enum:
            self.s2i_multi[m] = s2i = {}
            for k,v in enum[m].iteritems():
                s2i[v] = k
                self.s2i_all[v] = k
        Field.__init__(self, name, default, fmt)
    def any2i_one(self, pkt, x):
        if type (x) is str:
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

class BitMultiEnumField(BitField,MultiEnumField):
    def __init__(self, name, default, size, enum, depends_on):
        MultiEnumField.__init__(self, name, default, enum)
        self.rev = size < 0
        self.size = abs(size)
    def any2i(self, pkt, x):
        return MultiEnumField.any2i(self, pkt, x)
    def i2repr(self, pkt, x):
        return MultiEnumField.i2repr(self, pkt, x)


# Little endian long field
class LELongField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<Q")

# Little endian fixed length field
class LEFieldLenField(FieldLenField):
    def __init__(self, name, default,  length_of=None, fmt = "<H", count_of=None, adjust=lambda pkt,x:x, fld=None):
        FieldLenField.__init__(self, name, default, length_of=length_of, fmt=fmt, fld=fld, adjust=adjust)


class FlagsField(BitField):
    def __init__(self, name, default, size, names):
        self.multi = type(names) is list
        if self.multi:
            self.names = map(lambda x:[x], names)
        else:
            self.names = names
        BitField.__init__(self, name, default, size)
    def any2i(self, pkt, x):
        if type(x) is str:
            if self.multi:
                x = map(lambda y:[y], x.split("+"))
            y = 0
            for i in x:
                y |= 1 << self.names.index(i)
            x = y
        return x
    def i2repr(self, pkt, x):
        if type(x) is list or type(x) is tuple:
            return repr(x)
        if self.multi:
            r = []
        else:
            r = ""
        i=0
        while x:
            if x & 1:
                r += self.names[i]
            i += 1
            x >>= 1
        if self.multi:
            r = "+".join(r)
        return r

            


class FixedPointField(BitField):
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
        frac_part = val & (1L << self.frac_bits) - 1
        frac_part /= 2.0**self.frac_bits
        return int_part+frac_part
    def i2repr(self, pkt, val):
        return self.i2h(pkt, val)
