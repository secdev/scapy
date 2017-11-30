# coding=utf-8
from scapy.fields import Field
from scapy.packet import Packet, Padding
from scapy.config import conf


class UaTypePacket(Packet):
    """

    This helper class makes all types not contain a payload, since they are built
    in a hierarchical way with PacketFields

    """
    def guess_payload_class(self, payload):
        return conf.padding_layer


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
        if default is None:
            default = []  # Create a new list for each instance
        self.field = field
        Field.__init__(self, name, default)
        self.count_from = count_from
        self.length_from = length_from
        self.decode_callback = decode_callback
        self.encode_callback = encode_callback

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
        if isinstance(x, bytes):
            return [self.field.any2i(pkt, x[i:i+1]) for i in range(len(x))]
        elif isinstance(x, str):
            return self.any2i(pkt, self.encode_callback(x))
        if not isinstance(x, list):
            return [self.field.any2i(pkt, x)]
        else:
            return [self.field.any2i(pkt, e) for e in x]

    def i2repr(self, pkt, x):
        res = []
        for v in x:
            res.append(bytes(bytearray([v])))
        return repr(self.decode_callback(b''.join(res)))

    def i2h(self, pkt, x):
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
