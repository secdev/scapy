# coding=utf-8
import struct

from scapy.contrib.opcua.helpers import ByteListField, UaTypePacket
from scapy.fields import Field, PacketField, ConditionalField
import binascii


class UABooleanField(Field):
    """ Field type that represents the UA Boolean data type

     Specified in Spec ver 1.03 Part 6 §5.2.2.1
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "<B")

    def h2i(self, pkt, x):
        return True if x == "true" else False

    def i2h(self, pkt, x):
        return "true" if x else "false"

    def m2i(self, pkt, x):
        return True if struct.unpack("<B", x)[0] != 0 else False

    def i2m(self, pkt, x):
        return struct.pack("<B", 1 if x else 0)

    def any2i(self, pkt, x):
        if x == "false":
            return False
        else:
            return bool(x)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        return s[1:], self.m2i(pkt, s[:1])


class UaByteField(Field):
    """
    Represents the Byte data type according to the OPC UA standard
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "<B")

    def h2i(self, pkt, x):
        return struct.unpack("<B", x)[0]

    def i2h(self, pkt, x):
        if x is None:
            return None
        return struct.pack("<B", x)

    def m2i(self, pkt, x):
        return struct.unpack("<B", x)[0]

    def i2m(self, pkt, x):
        if x is None:
            x = 0
        return struct.pack("<B", x)

    def any2i(self, pkt, x):
        if isinstance(x, bytes) and len(x) == 1:
            return struct.unpack("<B", x)[0]
        elif isinstance(x, int) or x is None:
            return x
        else:
            raise TypeError("Cannot convert supplied argument")

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        return s[1:], self.m2i(pkt, s[:1])


class UaSByteField(Field):
    """ Represents a signed byte data type

    Specified in Spec ver 1.03 Part 3 §8.17
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "<b")


class UaBytesField(UaByteField):
    __slots__ = ["num_bytes"]

    islist = 1

    def __init__(self, name, default, num_bytes):
        """

        :param name: The name of the field
        :param default: The default value of the field
        :param num_bytes: The number of bytes the field is long.
        """
        Field.__init__(self, name, default)
        self.num_bytes = num_bytes
        self.sz = num_bytes

    def h2i(self, pkt, x):
        if x is None:
            return None
        return [super(UaBytesField, self).h2i(pkt, x[i:i + 1]) for i in range(len(x))]
        # return list(map(lambda val, self=self: UaByteField.h2i(self, pkt, val), x))

    def i2h(self, pkt, x):
        return self.i2m(pkt, x)

    def m2i(self, pkt, x):
        return [super(UaBytesField, self).m2i(pkt, x[i:i + 1]) for i in range(len(x))]
        # return list(map(lambda val, self=self: UaByteField.m2i(self, pkt, val), x))

    def i2m(self, pkt, x):
        if x is None:
            return b'\x00' * self.num_bytes
        elif not isinstance(x, list):
            return self.i2m(pkt, self.any2i(pkt, x))
        return b''.join(map(lambda val, self=self: UaByteField.i2m(self, pkt, val), x))

    def any2i(self, pkt, x):
        return self.h2i(pkt, x)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        return s[self.num_bytes:], self.m2i(pkt, s[:self.num_bytes])


class UaUInt16Field(Field):
    def __init__(self, name, default):
        super(UaUInt16Field, self).__init__(name, default, "<H")


class UaUInt32Field(Field):
    def __init__(self, name, default):
        super(UaUInt32Field, self).__init__(name, default, "<I")


class UaUInt64Field(Field):
    def __init__(self, name, default):
        super(UaUInt64Field, self).__init__(name, default, "<Q")


class UaInt16Field(Field):
    def __init__(self, name, default):
        super(UaInt16Field, self).__init__(name, default, "<h")


class UaInt32Field(Field):
    def __init__(self, name, default):
        super(UaInt32Field, self).__init__(name, default, "<i")


class UaInt64Field(Field):
    def __init__(self, name, default):
        super(UaInt64Field, self).__init__(name, default, "<q")


class UaFloatField(Field):
    def __init__(self, name, default):
        super(UaFloatField, self).__init__(name, default, "<f")


class UaDoubleField(Field):
    def __init__(self, name, default):
        super(UaDoubleField, self).__init__(name, default, "<d")


class UaDateTimeField(Field):
    def __init__(self, name, default):
        super(UaDateTimeField, self).__init__(name, default, "<q")


class UaGuidField(Field):
    def __init__(self, name, default):
        super(UaGuidField, self).__init__(name, default, "<I2H8B")

    def i2h(self, pkt, x):
        parts = [binascii.hexlify(struct.pack(">I", x[0]))]

        parts += map(lambda val: binascii.hexlify(struct.pack(">H", val)), x[1:3])
        parts.append(binascii.hexlify(x[3]))

        parts = map(lambda val: val.decode('ascii'), parts)

        return "-".join(parts)

    def i2m(self, pkt, x):
        return tuple(x[0:3]) + tuple(x[3])

    def m2i(self, pkt, x):
        front = x[:3]
        return front + tuple([bytes(x[3:])])

    def any2i(self, pkt, x):
        parts = []

        if isinstance(x, str) and x != "":
            parts = x.split('-')

            if len(parts) != 5:
                raise TypeError("Guids have to have 5 parts separated by '-'")
            if len(parts[0]) != 8:
                raise TypeError("The first part of a Guid has to be 8 characters long")
            if len(parts[1]) != 4:
                raise TypeError("The second part of a Guid has to be 4 characters long")
            if len(parts[2]) != 4:
                raise TypeError("The third part of a Guid has to be 4 characters long")
            if len(parts[3]) != 4:
                raise TypeError("The fourth part of a Guid has to be 4 characters long")
            if len(parts[4]) != 12:
                raise TypeError("The fifth part of a Guid has to be 12 characters long")

            parts[:3] = map(lambda val: bytes(bytearray.fromhex(val)), parts[:3])
            parts[3:] = [bytes(bytearray.fromhex("".join(parts[3:])))]

            parts[0] = struct.unpack(">I", parts[0])[0]
            parts[1:3] = map(lambda val: struct.unpack(">H", val)[0], parts[1:3])
            return tuple(parts)

        elif isinstance(x, tuple) and \
                len(x) == 4 and \
                isinstance(x[0], int) and \
                isinstance(x[1], int) and \
                isinstance(x[2], int) and \
                isinstance(x[3], bytes):
            return x

        elif x is None:
            return 0, 0, 0, b'\x00' * 8
        else:
            raise TypeError("Cannot convert supplied value to Guid")

    def addfield(self, pkt, s, val):
        return s + struct.pack(self.fmt, *self.i2m(pkt, val))

    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        return s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, s[:self.sz]))


def _ua_str_len_function(p):
    if p.length < 0:
        return 0
    return p.length


class UaByteString(UaTypePacket):
    fields_desc = [UaInt32Field("length", None),
                   ByteListField("data", b'', UaByteField("", 0), length_from=_ua_str_len_function)]

    def post_build(self, pkt, pay):
        lengthField, length = self.getfield_and_val("length")
        if length is None:
            dataPart = pkt[lengthField.sz:]
            sizePart = lengthField.addfield(self, b'', len(dataPart))
            return sizePart + dataPart + pay
        return pkt + pay


class UaString(UaByteString):
    fields_desc = [UaInt32Field("length", None),
                   ByteListField("data", b'', UaByteField("", 0), length_from=_ua_str_len_function,
                                 decode_callback=lambda s: s.decode("utf8"),
                                 encode_callback=lambda s: s.encode("utf8"))]


class UaXMLElement(UaString):
    pass


class UaQualifiedName(UaTypePacket):
    fields_desc = [UaUInt16Field("NamespaceIndex", 0),
                   PacketField("Name", UaString(), UaString)]


def _has_locale(p):
    if p.Locale is not None:
        return True
    if p.EncodingMask is None:
        return False
    return p.EncodingMask[0] & 0x1


def _has_text(p):
    if p.Text is not None:
        return True
    if p.EncodingMask is None:
        return False
    return p.EncodingMask[0] & 0x2


class UaLocalizedText(UaTypePacket):
    fields_desc = [UaByteField("EncodingMask", None),
                   ConditionalField(PacketField("Locale", None, UaString), _has_locale),
                   ConditionalField(PacketField("Text", None, UaString), _has_text)]

    def post_build(self, pkt, pay):

        encodingMaskField, encodingMask = self.getfield_and_val("EncodingMask")

        if encodingMask is not None:
            return pkt + pay

        encodingMask = 0
        rest = pkt[encodingMaskField.sz:]

        if self.Locale is not None:
            encodingMask |= 0x1
        if self.Text is not None:
            encodingMask |= 0x2

        self.EncodingMask = encodingMask
        maskPart = encodingMaskField.addfield(self, b'', encodingMask)
        return maskPart + rest + pay


class UaStatusCodeField(UaUInt32Field):
    pass


class UaEnumerationField(UaInt32Field):
    pass


# TODO: Implement correctly
class UaVariant(UaTypePacket):
    fields_desc = [UaByteField("EncodingMask", None),
                   UaInt32Field("ArrayLength", None)]


class UaNodeId(UaTypePacket):
    fields_desc = [UaByteField("Encoding", None),
                   UaUInt16Field("Namespace", 0)]

    encodings = {0x2: "NUMERIC",
                 0x3: "STRING"}

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is not None and len(_pkt) > 0:
            encodingField = UaByteField("Encoding", None)

            rest, val = encodingField.getfield(None, _pkt)
            if val == UaTwoByteNodeId.encoding:
                return UaTwoByteNodeId
            elif val == UaFourByteNodeId.encoding:
                return UaFourByteNodeId

        return cls


class UaTwoByteNodeId(UaNodeId):
    encoding = 0x0

    fields_desc = [UaByteField("Encoding", encoding),
                   UaByteField("Identifier", 0)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return super(UaTwoByteNodeId, cls).dispatch_hook(_pkt, args, kargs)


class UaFourByteNodeId(UaNodeId):
    encoding = 0x1

    fields_desc = [UaByteField("Encoding", encoding),
                   UaByteField("Namespace", 0),
                   UaInt16Field("Identifier", 0)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return super(UaFourByteNodeId, cls).dispatch_hook(_pkt, args, kargs)
