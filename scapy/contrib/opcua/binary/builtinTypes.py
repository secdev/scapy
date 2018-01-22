# coding=utf-8
"""
This module implements all builtin data types as specified by the OPC UA standard.
Refer to OPC UA Specification Part 3 and 6 (Version 1.04)

Every data type is available as a UaTypePacket. When using these as a field they need to be wrapped in
a UaPacketField. Normal scapy PacketFields can be used if they do not need access to the containing packet.
If possible use UaPacketField.

Some data types are available as UA___Field. Using these is preferred if possible, since they induce less overhead.

If all OPC UA basic data types are needed load the types module
"""
import struct
from functools import reduce

from scapy.contrib.opcua.helpers import ByteListField, UaTypePacket, LengthField, flatten, UaPacketField
from scapy.fields import Field, ConditionalField, FieldListField
from operator import mul
import binascii

builtinNodeIdMappings = {}


def _make_check_encoding_mask_function(field, mask):
    def has_field(p):
        if getattr(p, field) is not None:
            return True
        if p.EncodingMask is None:
            return False
        return p.getfieldval("EncodingMask") & mask

    return has_field


class UaBuiltin(UaTypePacket):
    nodeId = None


class UaBooleanField(Field):
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


class UaBoolean(UaBuiltin):
    nodeId = 1
    fields_desc = [UaBooleanField("value", None)]


class UaByteField(LengthField):
    """
    Represents the Byte data type according to the OPC UA standard
    """

    __slots__ = ["displayAsChar"]

    def __init__(self, name, default, displayAsChar=False, *args, **kwargs):
        super(UaByteField, self).__init__(name, default, "<B", *args, **kwargs)
        self.displayAsChar = displayAsChar

    def h2i(self, pkt, x):
        if isinstance(x, str):
            x = bytearray(x, "ascii")
        return struct.unpack("<B", x)[0]

    def i2h(self, pkt, x):
        if x is None:
            return None
        if self.displayAsChar:
            return struct.pack("<B", x)
        return x

    def m2i(self, pkt, x):
        return struct.unpack("<B", x)[0]

    def i2m(self, pkt, x):
        return struct.pack("<B", super(UaByteField, self).i2m(pkt, x))

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


class UaByte(UaBuiltin):
    nodeId = 3
    fields_desc = [UaByteField("value", None)]


class UaSByteField(Field):
    """ Represents a signed byte data type

    Specified in Spec ver 1.03 Part 3 §8.17
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "<b")


class UaSByte(UaBuiltin):
    nodeId = 2
    fields_desc = [UaSByteField("value", None)]


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


class UaUInt16Field(LengthField):
    def __init__(self, name, default, *args, **kwargs):
        super(UaUInt16Field, self).__init__(name, default, "<H", *args, **kwargs)


class UaUInt16(UaBuiltin):
    nodeId = 5
    fields_desc = [UaUInt16Field("value", None)]


class UaUInt32Field(LengthField):
    def __init__(self, name, default, *args, **kwargs):
        super(UaUInt32Field, self).__init__(name, default, "<I", *args, **kwargs)


class UaUInt32(UaBuiltin):
    nodeId = 7
    fields_desc = [UaUInt32Field("value", None)]


class UaUInt64Field(LengthField):
    def __init__(self, name, default, *args, **kwargs):
        super(UaUInt64Field, self).__init__(name, default, "<Q", *args, **kwargs)


class UaUInt64(UaBuiltin):
    nodeId = 9
    fields_desc = [UaUInt64Field("value", None)]


class UaInt16Field(LengthField):
    def __init__(self, name, default, *args, **kwargs):
        super(UaInt16Field, self).__init__(name, default, "<h", *args, **kwargs)


class UaInt16(UaBuiltin):
    nodeId = 4
    fields_desc = [UaInt16Field("value", None)]


class UaInt32Field(LengthField):
    def __init__(self, name, default, *args, **kwargs):
        super(UaInt32Field, self).__init__(name, default, "<i", *args, **kwargs)


class UaInt32(UaBuiltin):
    nodeId = 6
    fields_desc = [UaInt32Field("value", None)]


class UaInt64Field(LengthField):
    def __init__(self, name, default, *args, **kwargs):
        super(UaInt64Field, self).__init__(name, default, "<q", *args, **kwargs)


class UaInt64(UaBuiltin):
    nodeId = 8
    fields_desc = [UaInt64Field("value", None)]


class UaFloatField(Field):
    def __init__(self, name, default):
        super(UaFloatField, self).__init__(name, default, "<f")


class UaFloat(UaBuiltin):
    nodeId = 10
    fields_desc = [UaFloatField("value", None)]


class UaDoubleField(Field):
    def __init__(self, name, default):
        super(UaDoubleField, self).__init__(name, default, "<d")


class UaDouble(UaBuiltin):
    nodeId = 11
    fields_desc = [UaDoubleField("value", None)]


class UaDateTimeField(Field):
    def __init__(self, name, default):
        super(UaDateTimeField, self).__init__(name, default, "<q")


class UaDateTime(UaBuiltin):
    nodeId = 13
    fields_desc = [UaDateTimeField("value", None)]


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


class UaGuid(UaBuiltin):
    nodeId = 14
    fields_desc = [UaGuidField("value", None)]


def _ua_str_len_function(p):
    if p.length < 0:
        return 0
    return p.length


class UaByteString(UaBuiltin):
    nodeId = 15
    fields_desc = [UaInt32Field("length", None),
                   ByteListField("data", None, UaByteField("", None, True), length_from=_ua_str_len_function)]

    def post_build(self, pkt, pay):
        lengthField, length = self.getfield_and_val("length")
        if length is None:
            dataPart = pkt[lengthField.sz:]
            if self.getfieldval("data") is None:
                sizePart = lengthField.addfield(self, b'', -1)
            else:
                sizePart = lengthField.addfield(self, b'', len(dataPart))
            return sizePart + dataPart + pay
        return pkt + pay

    def post_dissect(self, s):
        if self.getfieldval("length") == -1:
            self.setfieldval("data", None)
        return s


class UaString(UaByteString):
    nodeId = 12
    fields_desc = [UaInt32Field("length", None),
                   ByteListField("data", None, UaByteField("", None), length_from=_ua_str_len_function,
                                 decode_callback=lambda s: s.decode("utf8"),
                                 encode_callback=lambda s: s.encode("utf8"))]


class UaXmlElement(UaString):
    nodeId = 16


class UaQualifiedName(UaBuiltin):
    nodeId = 20
    fields_desc = [UaUInt16Field("NamespaceIndex", 0),
                   UaPacketField("Name", UaString(), UaString)]


class UaLocalizedText(UaBuiltin):
    nodeId = 21
    fields_desc = [UaByteField("EncodingMask", None),
                   ConditionalField(UaPacketField("Locale", None, UaString),
                                    _make_check_encoding_mask_function("Locale", 0x01)),
                   ConditionalField(UaPacketField("Text", None, UaString),
                                    _make_check_encoding_mask_function("Text", 0x02))]

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
    
    def i2h(self, pkt, x):
        from scapy.contrib.opcua.binary.schemaTypes import statusCodes
        if x is None:
            return None
        return statusCodes[x][0]

    def any2i(self, pkt, x):
        if isinstance(x, str):
            from scapy.contrib.opcua.binary.schemaTypes import UaStatusCodes
            return getattr(UaStatusCodes, x)
        return super(UaStatusCodeField, self).any2i(pkt, x)


class UaStatusCode(UaBuiltin):
    nodeId = 19
    fields_desc = [UaStatusCodeField("value", None)]


class UaEnumerationField(UaInt32Field):
    pass


class UaNodeId(UaBuiltin):
    nodeId = 17
    fields_desc = [UaByteField("Encoding", 0x02),
                   UaUInt16Field("Namespace", 0),
                   UaUInt32Field("Identifier", None)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        if _pkt is not None and len(_pkt) > 0:
            encodingField = UaByteField("Encoding", None)

            rest, val = encodingField.getfield(None, _pkt)

            # Mask out the ExpandedNodeId bits
            expanded = val & UaExpandedNodeId.encoding
            if expanded and "partOfExpanded" not in kwargs:
                return UaExpandedNodeId

            val &= ~UaExpandedNodeId.encoding

            if val == UaTwoByteNodeId.encoding:
                return UaTwoByteNodeId
            elif val == UaFourByteNodeId.encoding:
                return UaFourByteNodeId
            elif val == UaNumericNodeId.encoding:
                return UaNumericNodeId
            elif val == UaStringNodeId.encoding:
                return UaStringNodeId
            elif val == UaGuidNodeId.encoding:
                return UaGuidNodeId
            elif val == UaByteStringNodeId.encoding:
                return UaByteStringNodeId

        return cls


class UaTwoByteNodeId(UaNodeId):
    encoding = 0x00

    fields_desc = [UaByteField("Encoding", encoding),
                   UaByteField("Identifier", None)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return super(UaTwoByteNodeId, cls).dispatch_hook(_pkt, args, kargs)


class UaFourByteNodeId(UaNodeId):
    encoding = 0x01

    fields_desc = [UaByteField("Encoding", encoding),
                   UaByteField("Namespace", 0),
                   UaUInt16Field("Identifier", None)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return super(UaFourByteNodeId, cls).dispatch_hook(_pkt, args, kargs)


class UaNumericNodeId(UaNodeId):
    encoding = 0x02

    fields_desc = [UaByteField("Encoding", encoding),
                   UaUInt16Field("Namespace", 0),
                   UaUInt32Field("Identifier", None)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        return super(UaNumericNodeId, cls).dispatch_hook(_pkt, args, kwargs)


class UaStringNodeId(UaNodeId):
    encoding = 0x03

    fields_desc = [UaByteField("Encoding", encoding),
                   UaUInt16Field("Namespace", 0),
                   UaPacketField("Identifier", UaString(), UaString)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        return super(UaStringNodeId, cls).dispatch_hook(_pkt, args, kwargs)


class UaGuidNodeId(UaNodeId):
    encoding = 0x04

    fields_desc = [UaByteField("Encoding", encoding),
                   UaUInt16Field("Namespace", 0),
                   UaGuidField("Identifier", None)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        return super(UaGuidNodeId, cls).dispatch_hook(_pkt, args, kwargs)


class UaByteStringNodeId(UaNodeId):
    encoding = 0x05

    fields_desc = [UaByteField("Encoding", encoding),
                   UaUInt16Field("Namespace", 0),
                   UaPacketField("Identifier", UaByteString(), UaByteString)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        return super(UaByteStringNodeId, cls).dispatch_hook(_pkt, args, kwargs)


# TODO: use make function?
def _id_has_uri(p):
    uri = p.getfieldval("NamespaceUri")
    if uri is not None:
        return True
    return p.NodeId.getfieldval("Encoding") & 0x80 != 0


def _id_has_index(p):
    index = p.getfieldval("ServerIndex")
    if index is not None and index != 0:
        return True
    return p.NodeId.getfieldval("Encoding") & 0x40 != 0


class _NodeIdNoRecurse(UaNodeId):

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        return super(_NodeIdNoRecurse, cls).dispatch_hook(_pkt, args, kwargs, partOfExpanded=True)


class UaExpandedNodeId(UaNodeId):
    nodeId = 18
    fields_desc = [UaPacketField("NodeId", UaNodeId(), _NodeIdNoRecurse),
                   ConditionalField(UaPacketField("NamespaceUri", None, UaString), _id_has_uri),
                   ConditionalField(UaUInt32Field("ServerIndex", 0), _id_has_index)]

    encoding = 0x80 | 0x40

    def post_build(self, pkt, pay):
        encodingField, encoding = self.NodeId.getfield_and_val("Encoding")

        if self.ServerIndex != 0:
            encoding |= 0x40

        if self.NamespaceUri is not None:
            uriLen = self.NamespaceUri.length
            if uriLen is None:
                uriLen = len(self.NamespaceUri.data)
            if uriLen <= 0:
                # TODO:
                print("Remove string length if it is 0 or -1")
            else:
                encoding |= 0x80

        pkt = encodingField.addfield(self, b'', encoding) + pkt[encodingField.sz:]

        return pkt + pay

    def __getattr__(self, attr):
        try:
            fld, v = self.getfield_and_val(attr)
        except TypeError:
            return self.NodeId.__getattr__(attr)
        if fld is not None:
            return fld.i2h(self, v)
        return v

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        return super(UaExpandedNodeId, cls).dispatch_hook(_pkt, *args, **kwargs)


class UaDiagnosticInfo(UaBuiltin):
    nodeId = 25
    fields_desc = [UaByteField("EncodingMask", None),
                   ConditionalField(UaInt32Field("SymbolicId", None),
                                    _make_check_encoding_mask_function("SymbolicId", 0x01)),
                   ConditionalField(UaInt32Field("NamespaceUri", None),
                                    _make_check_encoding_mask_function("NamespaceUri", 0x02)),
                   ConditionalField(UaInt32Field("LocalizedText", None),
                                    _make_check_encoding_mask_function("LocalizedText", 0x04)),
                   ConditionalField(UaInt32Field("Locale", None),
                                    _make_check_encoding_mask_function("Locale", 0x08)),
                   ConditionalField(UaPacketField("AdditionalInfo", None, UaString),
                                    _make_check_encoding_mask_function("AdditionalInfo", 0x10)),
                   ConditionalField(UaStatusCodeField("InnerStatusCode", None),
                                    _make_check_encoding_mask_function("InnerStatusCode", 0x20))]

    def post_build(self, pkt, pay):

        encodingMaskField, encodingMask = self.getfield_and_val("EncodingMask")

        if encodingMask is not None:
            return pkt + pay

        encodingMask = 0
        rest = pkt[encodingMaskField.sz:]

        if self.SymbolicId is not None:
            encodingMask |= 0x01
        if self.NamespaceUri is not None:
            encodingMask |= 0x02
        if self.LocalizedText is not None:
            encodingMask |= 0x04
        if self.Locale is not None:
            encodingMask |= 0x08
        if self.AdditionalInfo is not None:
            encodingMask |= 0x10
        if self.InnerStatusCode is not None:
            encodingMask |= 0x20
        if self.InnerDiagnosticInfo is not None:
            encodingMask |= 0x40

        # self.EncodingMask = encodingMask
        maskPart = encodingMaskField.addfield(self, b'', encodingMask)
        return maskPart + rest + pay


# We need to append the InnerDiagnosticInfo field after declaring the class, since it can contain itself
UaDiagnosticInfo.fields_desc.append(ConditionalField(UaPacketField("InnerDiagnosticInfo", None, UaDiagnosticInfo),
                                                     _make_check_encoding_mask_function("InnerDiagnosticInfo", 0x40)))


def _extension_obj_has_object(p):
    if p.Body is not None:
        return True
    if p.Encoding is None:
        return False
    return p.getfieldval("Encoding") & (0x01 | 0x02)


def _create_extended_extension_object(cls, dispatchedClass):
    fields_desc = cls.fields_desc[:-1]
    fields_desc.append(ConditionalField(UaPacketField("Body", None, dispatchedClass),
                                        _extension_obj_has_object))
    newDict = dict(cls.__dict__)
    newDict["fields_desc"] = fields_desc
    return type(cls.__name__, cls.__bases__, newDict)


def _extension_body_len(p):
    if p.underlayer is None:
        if p.bytes is None:
            return 0
        return len(p.bytes)
    return p.underlayer.Length


class ExtensionObjectRawBytes(UaTypePacket):
    fields_desc = [ByteListField("bytes", None, UaByteField("", None), length_from=_extension_body_len)]


class UaExtensionObject(UaBuiltin):
    nodeId = 22
    fields_desc = [UaPacketField("TypeId", UaNodeId(), UaNodeId),
                   UaByteField("Encoding", None),
                   ConditionalField(UaInt32Field("Length", None, length_of="Body"),
                                    _extension_obj_has_object),
                   ConditionalField(UaPacketField("Body", None, ExtensionObjectRawBytes),
                                    _extension_obj_has_object)]

    _cache = {}

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        from scapy.contrib.opcua.binary.schemaTypes import nodeIdMappings
        if _pkt is not None:
            nodeId = UaExpandedNodeId(_pkt)
            _, encoding = cls.fields_desc[1].getfield(None, nodeId.payload.load)

            if encoding == 0x01:
                if nodeId.Identifier in nodeIdMappings:
                    if nodeId.Identifier not in UaExtensionObject._cache:
                        dispatchedClass = nodeIdMappings[nodeId.Identifier]
                        UaExtensionObject._cache[nodeId.Identifier] = \
                            _create_extended_extension_object(cls, dispatchedClass)
                    return UaExtensionObject._cache[nodeId.Identifier]
                return cls

        return cls

    def post_build(self, pkt, pay):
        identifierField, identifier = self.TypeId.getfield_and_val("Identifier")
        removeUpToTypeId = len(self.TypeId)

        encodingField, encoding = self.getfield_and_val("Encoding")
        removeUpToEncoding = encodingField.sz

        if encoding is None:
            # Use Binary as default encoding
            if self.Body is not None:
                encoding = 0x01
                pkt = encodingField.addfield(self, pkt[:removeUpToTypeId], encoding) \
                      + pkt[removeUpToTypeId + removeUpToEncoding:]

        if identifier is None:
            if self.Body is not None and self.Body.binaryEncodingId is not None:
                identifier = self.Body.binaryEncodingId
                typeIdEncoding = self.TypeId.getfieldval("Encoding")
                namespace = self.TypeId.getfieldval("Namespace")

                pkt = UaNodeId(Encoding=typeIdEncoding, Namespace=namespace, Identifier=identifier).build() \
                      + pkt[removeUpToTypeId:]

        return pkt + pay


def has_value(p):
    if getattr(p, "Value") is not None and not has_values(p):
        return True
    if p.EncodingMask is None:
        return False
    encodingMask = p.getfieldval("EncodingMask")
    return (encodingMask & 0x80) == 0 and encodingMask & 0b00111111


def has_values(p):
    if getattr(p, "Values"):
        return True
    if p.EncodingMask is None:
        return False
    return p.getfieldval("EncodingMask") & 0x80


def has_array_length(p):
    if getattr(p, "ArrayLength") is not None:
        return True
    if p.EncodingMask is None:
        return has_values(p)
    return p.getfieldval("EncodingMask") & 0x80


def has_dimensions(p):
    if getattr(p, "ArrayDimensions"):
        return True
    if p.EncodingMask is None:
        return False
    return p.getfieldval("EncodingMask") & 0x40


def has_dimensions_length(p):
    if getattr(p, "ArrayDimensionsLength") is not None:
        return True
    if p.EncodingMask is None:
        return has_dimensions(p)
    return p.getfieldval("EncodingMask") & 0x40


class BuiltinListField(Field):
    __slots__ = ["count_from", "type_from", "field"]
    islist = 1

    def __init__(self, name, default, type_from, count_from):
        if default is None:
            default = []  # Create a new list for each instance
        super(BuiltinListField, self).__init__(name, default)
        self.count_from = count_from
        self.type_from = type_from
        self.field = UaPacketField("", None, UaBuiltin)

    def i2count(self, pkt, val):
        if isinstance(val, list):
            return len(list(flatten(val)))
        return 1

    def i2len(self, pkt, val):
        return int(sum(self.field.i2len(pkt, v) for v in flatten(val)))

    def i2m(self, pkt, val):
        if val is None:
            val = []
        val = list(flatten(val))
        return val

    def any2i(self, pkt, x):
        if not isinstance(x, list):
            return [self.field.any2i(pkt, x)]
        else:
            return x

    def i2repr(self, pkt, x):
        res = []
        for v in x:
            r = self.field.i2repr(pkt, v)
            res.append(r)
        return "[%s]" % ", ".join(res)

    def addfield(self, pkt, s, val):
        inner = val
        dimensions = []
        while isinstance(inner, list) and inner != []:
            dimensions.append(len(inner))
            inner = inner[0]

        if len(pkt.getfieldval("ArrayDimensions")) == 0 and len(dimensions) > 1:
            pkt.setfieldval("ArrayDimensions", dimensions)
        val = self.i2m(pkt, val)
        if len(val) > 0:
            self.field.cls = builtinNodeIdMappings[val[0].nodeId]
        for v in val:
            s = self.field.addfield(pkt, s, v)
        return s

    def getfield(self, pkt, s):
        encoding = pkt.getfieldval(self.type_from)
        encoding &= 0b00111111
        self.field.cls = builtinNodeIdMappings[encoding]
        c = None
        if self.count_from is not None:
            c = self.count_from(pkt)

        val = []
        ret = b""

        while s:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            self.field.cls = builtinNodeIdMappings[encoding]
            s, v = self.field.getfield(pkt, s)
            val.append(v)
        return s + ret, val


class BuiltinField(UaPacketField):
    __slots__ = ["type_from"]

    def __init__(self, name, default, type_from, remain=0):
        super(BuiltinField, self).__init__(name, default, UaBuiltin, remain=remain)
        self.cls = UaBuiltin
        self.type_from = type_from

    def getfield(self, pkt, s):
        encoding = pkt.getfieldval(self.type_from)
        encoding &= 0b00111111
        self.cls = builtinNodeIdMappings[encoding]
        return super(BuiltinField, self).getfield(pkt, s)


class UaVariant(UaBuiltin):
    nodeId = 24
    fields_desc = [UaByteField("EncodingMask", None),
                   ConditionalField(UaInt32Field("ArrayLength", None, count_of="Values"),
                                    has_array_length),
                   ConditionalField(BuiltinListField("Values", None, type_from="EncodingMask",
                                                     count_from=lambda p: p.ArrayLength),
                                    has_values),
                   ConditionalField(BuiltinField("Value", None, type_from="EncodingMask"),
                                    has_value),
                   ConditionalField(UaInt32Field("ArrayDimensionsLength", None, count_of="ArrayDimensions"),
                                    has_dimensions_length),
                   ConditionalField(FieldListField("ArrayDimensions", None, UaInt32Field("", None),
                                                   count_from=lambda p: p.ArrayDimensionsLength),
                                    has_dimensions)]

    def post_build(self, pkt, pay):
        encodingMaskField, encodingMask = self.getfield_and_val("EncodingMask")

        if encodingMask is not None:
            return pkt + pay

        encodingMask = 0
        rest = pkt[encodingMaskField.sz:]

        if has_values(self):
            encodingMask |= 0x80
        if has_dimensions(self):
            encodingMask |= 0x40

        valuesField, values = self.getfield_and_val("Values")
        if values is not None and values != []:
            encodingMask |= next(flatten(values)).nodeId

        valueField, value = self.getfield_and_val("Value")
        if value is not None and values == []:
            encodingMask |= value.nodeId

        maskPart = encodingMaskField.addfield(self, b'', encodingMask)
        return maskPart + rest + pay

    def post_dissect(self, s):
        if has_dimensions(self):
            values = self.Values
            dimensions = self.ArrayDimensions
            assert len(values) == reduce(mul, dimensions)
            # Apply array dimensions to the flat list
            for dim in reversed(dimensions):
                values = [values[j:j + dim] for j in range(0, len(values), dim)]

            self.Values = values[0]
        return s


class UaDataValue(UaBuiltin):
    nodeId = 23
    fields_desc = [UaByteField("EncodingMask", None),
                   ConditionalField(UaPacketField("Value", None, UaVariant),
                                    _make_check_encoding_mask_function("Value", 0x01)),
                   ConditionalField(UaStatusCodeField("Status", None),
                                    _make_check_encoding_mask_function("Status", 0x02)),
                   ConditionalField(UaDateTimeField("SourceTimestamp", None),
                                    _make_check_encoding_mask_function("SourceTimestamp", 0x04)),
                   ConditionalField(UaUInt16Field("SourcePicoSeconds", None),
                                    _make_check_encoding_mask_function("SourcePicoSeconds", 0x10)),
                   ConditionalField(UaDateTimeField("ServerTimestamp", None),
                                    _make_check_encoding_mask_function("ServerTimestamp", 0x08)),
                   ConditionalField(UaUInt16Field("ServerPicoSeconds", None),
                                    _make_check_encoding_mask_function("ServerPicoSeconds", 0x20))]

    def post_build(self, pkt, pay):

        encodingMaskField, encodingMask = self.getfield_and_val("EncodingMask")

        if encodingMask is not None:
            return pkt + pay

        encodingMask = 0
        rest = pkt[encodingMaskField.sz:]

        if self.Value is not None:
            encodingMask |= 0x01
        if self.Status is not None:
            encodingMask |= 0x02
        if self.SourceTimestamp is not None:
            encodingMask |= 0x04
        if self.SourcePicoSeconds is not None:
            encodingMask |= 0x10
        if self.ServerTimestamp is not None:
            encodingMask |= 0x08
        if self.ServerPicoSeconds is not None:
            encodingMask |= 0x20

        maskPart = encodingMaskField.addfield(self, b'', encodingMask)
        return maskPart + rest + pay


def _make_node_id_mappings():
    from inspect import getmro
    module = globals()
    for objname in module:
        obj = module[objname]
        if hasattr(obj, "__bases__") and UaBuiltin in getmro(obj):
            builtinNodeIdMappings[obj.nodeId] = obj


_make_node_id_mappings()
