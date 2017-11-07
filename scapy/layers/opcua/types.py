from scapy.fields import Field, IntField
import struct


class UaByteField(Field):
    __slots__ = []
    """
    Represents the Byte data type according to the OPC UA standard
    """
    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")

    def h2i(self, pkt, x):
        return struct.unpack("!B", x)[0]

    def i2h(self, pkt, x):
        return struct.pack("!B", x)

    def m2i(self, pkt, x):
        return struct.unpack("!B", x)[0]

    def i2m(self, pkt, x):
        return struct.pack("!B", x)

    def any2i(self, pkt, x):
        if isinstance(x, str):
            return self.h2i(pkt, x)
        elif isinstance(x, int):
            return x
        else:
            raise TypeError("Cannot convert supplied argument")

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        return s[1:], self.m2i(pkt, s[:1])


class UaBytesField(UaByteField):
    __slots__ = ["num_bytes"]

    def __init__(self, name, default, num_bytes):
        """

        :param name: The name of the field
        :param default: The default value of the field
        :param num_bytes: The number of bytes the field is long.
        """
        Field.__init__(self, name, default)
        self.num_bytes = num_bytes

    def h2i(self, pkt, x):
        return map(lambda val, self=self: UaByteField.h2i(self, pkt, val), x)

    def i2h(self, pkt, x):
        return self.i2m(pkt, x)

    def m2i(self, pkt, x):
        return map(lambda val, self=self: UaByteField.m2i(self, pkt, val), x)

    def i2m(self, pkt, x):
        return ''.join(map(lambda val, self=self: UaByteField.i2m(self, pkt, val), x))

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        return s[self.num_bytes:], self.m2i(pkt, s[:self.num_bytes])


class UaUInt32Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<I")  # Little endian to conform with standard


class UaStringField(Field):

    def __init__(self, name, default, length_field):
        """

        :param name: The name of the field
        :param default: The default value of the field
        :param length_field: A Field that contains the length of the string
        """
        Field.__init__(self, name, default)
        self.length_field = length_field


class UaByteStringField(UaStringField):
    pass
