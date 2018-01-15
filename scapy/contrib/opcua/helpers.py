# coding=utf-8
"""
This module contains helper functions that the implementation of the OPC UA protocol needs.
"""
from scapy.compat import raw
from scapy.fields import Field, PacketField
from scapy.packet import Packet
from scapy.config import conf


class UaConnectionContext(object):
    """
    This class contains all connection related data. If it is passed to packets while assembling or dissecting,
    it will be used to fill in fields like the sequence number if they are set to None.
    The state needs to be manually updated or one of the available automatons needs to be used. The automatons
    automatically update the context when messages are sent and received.
    """
    
    def __init__(self):
        from scapy.contrib.opcua.binary.schemaTypes import UaChannelSecurityToken
        self.securityPolicy = None
        self.securityToken = UaChannelSecurityToken()


class UaTypePacket(Packet):
    __slots__ = ["connectionContext"]
    binaryEncodingId = None
    """
    This helper class makes all types not contain a payload, since they are built
    in a hierarchical way with PacketFields.
    Almost all of the OPC UA types are modelled as 'Packets' due to the complex structure (e.g. types that contain
    other types). The 'padding' of a packet is passed on to the fields after this one.
    """

    def __init__(self, _pkt=b"", connectionContext=None,
                 post_transform=None, _internal=0, _underlayer=None, **fields):
        self.connectionContext = connectionContext
        super(UaTypePacket, self).__init__(_pkt, post_transform, _internal, _underlayer, **fields)

    def guess_payload_class(self, payload):
        return conf.padding_layer

    def copy(self):
        pkt = super(UaTypePacket,self).copy()
        pkt.connectionContext = self.connectionContext
        return pkt

    def clone_with(self, payload=None, **kargs):
        pkt = super(UaTypePacket, self).clone_with(payload, **kargs)
        pkt.connectionContext = self.connectionContext
        return pkt

    def show2(self, dump=False, indent=3, lvl="", label_lvl=""):
        """
        This method needs to be overridden because the connectionContext needs to be passed on.
        Otherwise the packet cannot be decrypted
        """
        return self.__class__(raw(self), connectionContext=self.connectionContext).show(dump, indent, lvl, label_lvl)


class ByteListField(Field):
    __slots__ = ["field", "count_from", "length_from", "decode_callback", "encode_callback"]
    islist = 1

    def __init__(self, name, default, field, length_from=None,
                 count_from=None, decode_callback=lambda s: s,
                 encode_callback=lambda s: s.encode()):
        """

        :param name:
        :param default:
        :param field:
        :param length_from:
        :param count_from:
        :param decode_callback: gets a bytes object and should return an eventually decoded string which
                                is more readable.
        :param encode_callback: gets a string object and should return an encoded bytes object
        """
        self.field = field
        Field.__init__(self, name, default)
        self.count_from = count_from
        self.length_from = length_from
        self.decode_callback = decode_callback
        self.encode_callback = encode_callback
        self.default = default

        if self.field.sz != 1:
            raise TypeError("Field has to be byte size")

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
        if x is None:
            return None
        elif isinstance(x, bytes):
            return [self.field.any2i(pkt, x[i:i + 1]) for i in range(len(x))]
        elif isinstance(x, str):
            return self.any2i(pkt, self.encode_callback(x))
        elif not isinstance(x, list):
            return [self.field.any2i(pkt, x)]
        else:
            return [self.field.any2i(pkt, e) for e in x]

    def i2repr(self, pkt, x):
        if x is None:
            return repr(None)
        res = []
        for v in x:
            res.append(bytes(bytearray([v])))
        return repr(self.decode_callback(b''.join(res)))

    def i2h(self, pkt, x):
        if x is None:
            return None
        res = []
        for v in x:
            r = self.field.i2h(pkt, v)
            res.append(r)
        return self.decode_callback(b''.join(res))

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
            s, ret = s[:l], s[l:]

        while s:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            s, v = self.field.getfield(pkt, s)
            val.append(v)
        return s + ret, val


class LengthField(Field):
    """
    This helper class enables fields that inherit from it (e.g. UaUInt32) to be used as length fields.
    """
    __slots__ = ["length_of", "count_of", "adjust"]

    def __init__(self, name, default, fmt, length_of=None, count_of=None, adjust=lambda pkt, x: x):
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust

    def i2m(self, pkt, x):
        if x is None:
            if self.length_of is not None:
                fld, fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
                x = self.adjust(pkt, f)
            elif self.count_of is not None:
                fld, fval = pkt.getfield_and_val(self.count_of)
                f = fld.i2count(pkt, fval)
                x = self.adjust(pkt, f)
            else:
                x = 0x0
        return x


class UaPacketField(PacketField):
    """
    Specialized version of PacketField to make containing packets available as underlayer
    """
    def m2i(self, pkt, m):
        return self.cls(m, _underlayer=pkt, connectionContext=pkt.connectionContext)

    def addfield(self, pkt, s, val):
        if val is not None:
            val.connectionContext = pkt.connectionContext
        return super(UaPacketField, self).addfield(pkt, s, val)


def flatten(l):
    """
    Flattens arbitrarily deep lists of lists.
    Idea taken from https://stackoverflow.com/questions/2158395/flatten-an-irregular-list-of-lists

    :param l: the list to flatten
    :return A generator for the flattened list
    """

    for el in l:
        if isinstance(el, list):
            for sub in flatten(el):
                yield sub
        else:
            yield el
