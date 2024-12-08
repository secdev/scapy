# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
.NET RemoTing Protocol

This implements:
- [MS-NRTP] - .NET Remoting Core Protocol
- [MS-NRBF] - .NET Remoting Binary Format
"""

import enum
import functools
import struct

from scapy.automaton import Automaton, ATMT
from scapy.config import conf
from scapy.main import interact
from scapy.fields import (
    ByteEnumField,
    ByteField,
    ConditionalField,
    FieldLenField,
    FieldListField,
    FlagsField,
    LEIntField,
    LELongField,
    LEShortEnumField,
    LEShortField,
    LESignedIntField,
    LESignedLongField,
    LESignedShortField,
    LenField,
    MSBExtendedField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    SignedByteField,
    StrField,
    StrFixedLenField,
    StrLenField,
    StrLenFieldUtf16,
)
from scapy.packet import Packet
from scapy.supersocket import StreamSocket


# [MS-NRTP] sect 2.2.3.2.1


class CountedString(Packet):
    fields_desc = [
        ByteEnumField(
            "StringEncoding",
            0,
            {
                0: "Unicode",
                1: "UTF8",
            },
        ),
        FieldLenField("Length", None, fmt="<I", count_of="StringData"),
        MultipleTypeField(
            [
                (
                    StrLenFieldUtf16(
                        "StringData", "", length_from=lambda pkt: pkt.Length
                    ),
                    lambda pkt: pkt.StringEncoding == 0,
                ),
                (
                    StrLenField("StringData", "", length_from=lambda pkt: pkt.Length),
                    lambda pkt: pkt.StringEncoding == 1,
                ),
            ],
            StrLenField("StringData", "", length_from=lambda pkt: pkt.Length),
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


CountedStringField = lambda name: PacketField(name, CountedString(), CountedString)

# [MS-NRTP] sect 2.2.3.1.4

NRTP_HeaderDataFormat = {
    0: "Void",
    1: "CountedString",
    2: "Byte",
    3: "Uint16",
    4: "Int32",
}

# [MS-NRTP] sect 2.2.3.3.3.1


class NRTPHeader(Packet):
    fields_desc = [
        LEShortEnumField(
            "HeaderToken",
            0,
            {
                0: "End",
                1: "Custom",
                2: "StatusCode",
                3: "StatusPhrase",
                4: "RequestUri",
                5: "CloseConnection",
                6: "ContentType",
            },
        ),
    ]

    registered_headers = {}

    @classmethod
    def register_variant(cls, id=None):
        cls.registered_headers[cls.HeaderToken.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            return cls.registered_headers.get(
                struct.unpack("<H", _pkt[:2])[0], NRTPUnknownHeader
            )
        return cls

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-NRTP] sect 2.2.3.3.3.1


class NRTPEndHeader(NRTPHeader):
    HeaderToken = 0
    fields_desc = [
        NRTPHeader,
    ]


# [MS-NRTP] sect 2.2.3.3.3.2


class NRTPCustomHeader(NRTPHeader):
    HeaderToken = 1
    fields_desc = [
        NRTPHeader,
        CountedStringField("HeaderName"),
        CountedStringField("HeaderValue"),
    ]


# [MS-NRTP] sect 2.2.3.3.3.3


class NRTPStatusCodeHeader(NRTPHeader):
    HeaderToken = 2
    fields_desc = [
        NRTPHeader,
        ByteEnumField("DataType", 3, NRTP_HeaderDataFormat),
        LEShortField("StatusCodeValue", 0),
    ]


# [MS-NRTP] sect 2.2.3.3.3.4


class NRTPStatusPhraseHeader(NRTPHeader):
    HeaderToken = 3
    fields_desc = [
        NRTPHeader,
        ByteEnumField("DataType", 1, NRTP_HeaderDataFormat),
        CountedStringField("StatusPhraseValue"),
    ]


# [MS-NRTP] sect 2.2.3.3.3.5


class NRTPRequestUriHeader(NRTPHeader):
    HeaderToken = 4
    fields_desc = [
        NRTPHeader,
        ByteEnumField("DataType", 1, NRTP_HeaderDataFormat),
        CountedStringField("UriValue"),
    ]


# [MS-NRTP] sect 2.2.3.3.3.6


class NRTPCloseConnectionHeader(NRTPHeader):
    HeaderToken = 5
    fields_desc = [
        NRTPHeader,
        ByteEnumField("DataType", 0, NRTP_HeaderDataFormat),
    ]


# [MS-NRTP] sect 2.2.3.3.3.7


class NRTPContentTypeHeader(NRTPHeader):
    HeaderToken = 6
    fields_desc = [
        NRTPHeader,
        ByteEnumField("DataType", 1, NRTP_HeaderDataFormat),
        CountedStringField("ContentTypeValue"),
    ]


# [MS-NRTP] sect 2.2.3.3.3.8


class NRTPUnknownHeader(NRTPHeader):
    HeaderToken = 7
    fields_desc = [
        NRTPHeader,
        ByteEnumField("DataType", 0, NRTP_HeaderDataFormat),
        MultipleTypeField(
            [
                (
                    StrFixedLenField("DataValue", b"", length=0),
                    lambda pkt: pkt.DataType == 0,
                ),
                (
                    CountedStringField("DataValue"),
                    lambda pkt: pkt.DataType == 1,
                ),
                (
                    StrFixedLenField("DataValue", b"", length=1),
                    lambda pkt: pkt.DataType == 2,
                ),
                (
                    LEShortField("DataValue", 0),
                    lambda pkt: pkt.DataType == 3,
                ),
                (
                    LEIntField("DataValue", 0),
                    lambda pkt: pkt.DataType == 4,
                ),
            ],
            StrField("DataValue", b""),
        ),
    ]


# [MS-NRTP] sect 2.2.3.3.1


class NRTPSingleMessageContent(Packet):
    name = "NRTP Single Message Content"
    fields_desc = [
        StrFixedLenField("ProtocolId", b"\x2e\x4E\x45\x54", 4),
        ByteField("MajorVersion", 1),
        ByteField("MinorVersion", 0),
        LEShortEnumField(
            "OperationType",
            0,
            {
                0: "Request",
                1: "OneWayRequest",
                2: "Reply",
            },
        ),
        LEShortEnumField(
            "ContentDistribution",
            0,
            {
                0: "Not chunked",
                1: "Chunked",
            },
        ),
        ConditionalField(
            LenField("Length", None, fmt="<I"), lambda pkt: pkt.ContentDistribution == 0
        ),
        PacketListField(
            "Headers",
            [NRTPEndHeader()],
            None,
            next_cls_cb=lambda pkt, lst, cur, remain: (
                None if isinstance(cur, NRTPEndHeader) else NRTPHeader
            ),
        ),
    ]

    @classmethod
    def tcp_reassemble(cls, data, metadata, session):
        if not data:
            return None
        # Recover Length if available
        length = metadata.get("length", None)
        if length is None and len(data) >= 14:
            cd = struct.unpack("<H", data[8:10])[0]
            if cd == 0:
                # Not chunked
                length = struct.unpack("<I", data[10:14])[0]
                metadata["length"] = length
        if length is None:
            return cls(data)
        # Parse only the header packet
        pkt = cls(data, stop_dissection_after=Packet)
        # Is it complete?
        if pkt.payload and len(pkt.payload) >= length:
            # Get content-type
            try:
                content_type = next(
                    x.ContentTypeValue.StringData
                    for x in pkt.Headers
                    if x.HeaderToken == 6
                )
                session["content_type"] = content_type
            except StopIteration:
                # Not in this packet. Do we know it from the session?
                content_type = session.get("content_type", None)
                if not content_type:
                    return pkt
            # We have a content-type. Parse it.
            if content_type == b"application/octet-stream":
                # pkt.payload is NRBF.
                pkt.payload = NRBF(bytes(pkt.payload))
            return pkt
        return None


# [MS-NRBF] .NET Remoting Binary Format


class MSBExtendedFieldLen(MSBExtendedField):
    __slots__ = FieldLenField.__slots__

    def __init__(self, name, default, length_of=None):
        FieldLenField.__init__(self, name, default, length_of=length_of)
        super(MSBExtendedFieldLen, self).__init__(name, default)

    i2m = FieldLenField.i2m


# [MS-NRBF] sect 2.1.1.6


class NRBFLengthPrefixedString(Packet):
    fields_desc = [
        MSBExtendedFieldLen("Length", None, length_of="String"),
        StrLenField("String", b"", length_from=lambda pkt: pkt.Length),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-NRBF] sect 2.1.1.8


class NRBFClassTypeInfo(Packet):
    fields_desc = [
        PacketField("TypeName", NRBFLengthPrefixedString(), NRBFLengthPrefixedString),
        LESignedIntField("LibraryId", 0),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-NRBF] sect 2.1.2.3


class PrimitiveTypeEnum(enum.IntEnum):
    Boolean = 1
    Byte = 2
    Char = 2
    Decimal = 5
    Double = 6
    Int16 = 7
    Int32 = 8
    Int64 = 9
    SByte = 10
    Single = 11
    TimeSpan = 12
    DateTime = 13
    UInt16 = 14
    UInt32 = 15
    UInt64 = 16
    Null = 17
    String = 18


# [MS-NRBF] sect 2.1.2.2


class BinaryTypeEnum(enum.IntEnum):
    Primitive = 0
    String = 1
    Object = 2
    SystemClass = 3
    Class = 4
    ObjectArray = 5
    StringArray = 6
    PrimitiveArray = 7


# [MS-NRBF] sect 2.2.2.1


class NRBFValueWithCode(Packet):
    fields_desc = [
        ByteEnumField("PrimitiveType", 0, PrimitiveTypeEnum),
        MultipleTypeField(
            [
                (ByteField("Value", 0), lambda pkt: pkt.PrimitiveType in [1, 2, 3, 4]),
                (LESignedShortField("Value", 0), lambda pkt: pkt.PrimitiveType == 7),
                (LESignedIntField("Value", 0), lambda pkt: pkt.PrimitiveType == 8),
                (LESignedLongField("Value", 0), lambda pkt: pkt.PrimitiveType == 9),
                (SignedByteField("Value", 0), lambda pkt: pkt.PrimitiveType == 10),
                (LEShortField("Value", 0), lambda pkt: pkt.PrimitiveType == 14),
                (LEIntField("Value", 0), lambda pkt: pkt.PrimitiveType == 15),
                (LELongField("Value", 0), lambda pkt: pkt.PrimitiveType == 16),
                (
                    PacketField(
                        "Value", NRBFLengthPrefixedString(), NRBFLengthPrefixedString
                    ),
                    lambda pkt: pkt.PrimitiveType == 18,
                ),
            ],
            StrFixedLenField("Value", b"", length=0),
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-NRBF] sect 2.2.2.2


class NRBFStringValueWithCode(NRBFValueWithCode):
    PrimitiveType = 18


StringValueWithCode = lambda name: PacketField(
    name, NRBFStringValueWithCode(), NRBFStringValueWithCode
)


# [MS-NRBF] sect 2.2.2.3


class NRBFArrayOfValueWithCode(Packet):
    fields_desc = [
        FieldLenField("Length", None, fmt="<I", count_of="ListOfValueWithCode"),
        PacketListField(
            "ListOfValueWithCode",
            [],
            NRBFValueWithCode,
            count_from=lambda pkt: pkt.Length,
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


# Generic record type

NRBF_RecordTypeEnumeration = {
    0: "SerializedStreamHeader",
    1: "ClassWithId",
    2: "SystemClassWithMembers",
    3: "ClassWithMembers",
    4: "SystemClassWithMembersAndTypes",
    5: "ClassWithMembersAndTypes",
    6: "BinaryObjectString",
    7: "BinaryArray",
    8: "MemberPrimitiveTyped",
    9: "MemberReference",
    10: "ObjectNull",
    11: "MessageEnd",
    12: "BinaryLibrary",
    13: "ObjectNullMultiple256",
    14: "ObjectNullMultiple",
    15: "ArraySinglePrimitive",
    16: "ArraySingleObject",
    17: "ArraySingleString",
    21: "MethodCall",
    22: "MethodReturn",
}


class NRBFRecord(Packet):
    fields_desc = [
        ByteEnumField("RecordTypeEnum", 255, NRBF_RecordTypeEnumeration),
    ]

    registered_records = {}

    @classmethod
    def register_variant(cls, id=None):
        cls.registered_records[cls.RecordTypeEnum.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            return cls.registered_records.get(_pkt[0], NRBFRecord)
        return cls

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-NRBF] sect 2.2.3.1

_NRBF_MessageFlags = {
    0x00000001: "NoArgs",
    0x00000002: "ArgsInline",
    0x00000004: "ArgsIsArray",
    0x00000008: "ArgsInArray",
    0x00000010: "NoContext",
    0x00000020: "ContextInline",
    0x00000040: "ContextInArray",
    0x00000080: "MethodSignatureInArray",
    0x00000100: "PropertiesInArray",
    0x00000200: "NoReturnValue",
    0x00000400: "ReturnValueVoid",
    0x00000800: "ReturnValueInline",
    0x00001000: "ReturnValueInArray",
    0x00002000: "ExceptionInArray",
    0x00008000: "GenericMethod",
}


class NRBFBinaryMethodCall(NRBFRecord):
    RecordTypeEnum = 21
    fields_desc = [
        NRBFRecord,
        FlagsField("MessageEnum", 0, -32, _NRBF_MessageFlags),
        StringValueWithCode("MethodName"),
        StringValueWithCode("TypeName"),
        ConditionalField(
            StringValueWithCode("CallContext"),
            lambda pkt: pkt.MessageEnum.ContextInline,
        ),
        ConditionalField(
            PacketField("Args", NRBFArrayOfValueWithCode(), NRBFArrayOfValueWithCode),
            lambda pkt: pkt.MessageEnum.ArgsInline,
        ),
    ]


# [MS-NRBF] sect 2.2.3.3


class NRBFBinaryMethodReturn(NRBFRecord):
    RecordTypeEnum = 22
    fields_desc = [
        NRBFRecord,
        FlagsField("MessageEnum", 0, -32, _NRBF_MessageFlags),
        ConditionalField(
            PacketField("ReturnValue", NRBFValueWithCode(), NRBFValueWithCode),
            lambda pkt: pkt.MessageEnum.ReturnValueInline,
        ),
        ConditionalField(
            StringValueWithCode("CallContext"),
            lambda pkt: pkt.MessageEnum.ContextInline,
        ),
        ConditionalField(
            PacketField("Args", NRBFArrayOfValueWithCode(), NRBFArrayOfValueWithCode),
            lambda pkt: pkt.MessageEnum.ArgsInline,
        ),
    ]


# [MS-NRBF] sect 2.3 - Class Records

# A generic packet use for Member data


def _members_cb(pkt, lst, cur, remain):
    index = len(lst) + (1 if cur is not None else 0)
    if index >= pkt.MemberCount:
        return None
    if hasattr(pkt, "BinaryTypeEnums"):
        if index < len(pkt.BinaryTypeEnums):
            typeEnum = pkt.BinaryTypeEnums[index]
            if typeEnum == BinaryTypeEnum.Primitive:
                # Get AdditionalInfo to get the matching primitive type.
                primitiveType = pkt.AdditionalInfos[
                    sum(
                        1
                        for x in pkt.BinaryTypeEnums[:index]
                        if x
                        not in [
                            BinaryTypeEnum.String,
                            BinaryTypeEnum.Object,
                            BinaryTypeEnum.ObjectArray,
                            BinaryTypeEnum.StringArray,
                        ]
                    )
                ].Value
                return functools.partial(
                    NRBFMemberPrimitiveUnTyped,
                    type=PrimitiveTypeEnum(primitiveType),
                )
    return NRBFRecord


class _NRBFMembers(Packet):
    fields_desc = [
        PacketListField(
            "Members",
            [],
            None,
            next_cls_cb=_members_cb,
        )
    ]


# [MS-NRBF] sect 2.3.1.1


class NRBFClassInfo(Packet):
    fields_desc = [
        LESignedIntField("ObjectId", 0),
        PacketField("Name", NRBFLengthPrefixedString(), NRBFLengthPrefixedString),
        FieldLenField("MemberCount", None, fmt="<i", count_of="MemberNames"),
        PacketListField(
            "MemberNames",
            [],
            NRBFLengthPrefixedString,
            count_from=lambda pkt: pkt.MemberCount,
        ),
    ]


# [MS-NRBF] sect 2.3.1.2


class NRBFAdditionalInfo(Packet):
    __slots__ = ["type"]

    fields_desc = [
        MultipleTypeField(
            [
                (
                    ByteEnumField("Value", 0, PrimitiveTypeEnum),
                    lambda pkt: pkt.type
                    in [
                        BinaryTypeEnum.Primitive,
                        BinaryTypeEnum.PrimitiveArray,
                    ],
                ),
                (
                    PacketField(
                        "Value", NRBFLengthPrefixedString(), NRBFLengthPrefixedString
                    ),
                    lambda pkt: pkt.type == BinaryTypeEnum.SystemClass,
                ),
                (
                    PacketField("Value", NRBFClassTypeInfo(), NRBFClassTypeInfo),
                    lambda pkt: pkt.type == BinaryTypeEnum.Class,
                ),
            ],
            StrFixedLenField("Value", b"", length=0),
        ),
    ]

    def __init__(self, _pkt=None, **kwargs):
        self.type = kwargs.pop("type", BinaryTypeEnum.Primitive)
        assert isinstance(self.type, BinaryTypeEnum)
        super(NRBFAdditionalInfo, self).__init__(_pkt, **kwargs)

    def clone_with(self, *args, **kwargs):
        pkt = super(NRBFAdditionalInfo, self).clone_with(*args, **kwargs)
        pkt.type = self.type
        return pkt

    def copy(self):
        pkt = super(NRBFAdditionalInfo, self).copy()
        pkt.type = self.type
        return pkt

    def default_payload_class(self, payload):
        return conf.padding_layer


def _member_type_infos_cb(pkt, lst, cur, remain):
    """
    Returns a NRBFAdditionalInfo with the type selected.
    """
    # Get the next member of 'BinaryTypeEnums'
    index = len(lst) + (1 if cur is not None else 0)
    try:
        typeEnum = next(
            y
            for i, y in enumerate(
                x
                for x in pkt.BinaryTypeEnums
                if x
                not in [
                    # Some types are ignored (see table in [MS-NRBF] sect 2.3.1.2)
                    BinaryTypeEnum.String,
                    BinaryTypeEnum.Object,
                    BinaryTypeEnum.ObjectArray,
                    BinaryTypeEnum.StringArray,
                ]
            )
            if i >= index
        )
    except StopIteration:
        return None
    typeEnum = BinaryTypeEnum(typeEnum)
    # Return BinaryTypeEnum tainted with a pre-selected type.
    return functools.partial(
        NRBFAdditionalInfo,
        type=typeEnum,
    )


class NRBFMemberTypeInfo(Packet):
    fields_desc = [
        FieldListField(
            "BinaryTypeEnums",
            [],
            ByteEnumField("", 0, BinaryTypeEnum),
            count_from=lambda pkt: pkt.MemberCount,
        ),
        PacketListField(
            "AdditionalInfos",
            [],
            None,
            next_cls_cb=_member_type_infos_cb,
        ),
    ]


# [MS-NRBF] 2.3.2.5


class NRBFClassWithId(NRBFRecord):
    RecordTypeEnum = 1
    fields_desc = [
        NRBFRecord,
        LESignedIntField("ObjectId", 0),
        LESignedIntField("MetadataId", 0),
    ]


# [MS-NRBF] sect 2.5.2


class NRBFMemberPrimitiveUnTyped(Packet):
    __slots__ = ["type"]

    fields_desc = [
        NRBFValueWithCode.fields_desc[1],
    ]

    def __init__(self, _pkt=None, **kwargs):
        self.type = kwargs.pop("type", PrimitiveTypeEnum.Byte)
        assert isinstance(self.type, PrimitiveTypeEnum)
        super(NRBFMemberPrimitiveUnTyped, self).__init__(_pkt, **kwargs)

    def clone_with(self, *args, **kwargs):
        pkt = super(NRBFMemberPrimitiveUnTyped, self).clone_with(*args, **kwargs)
        pkt.type = self.type
        return pkt

    def copy(self):
        pkt = super(NRBFMemberPrimitiveUnTyped, self).copy()
        pkt.type = self.type
        return pkt

    @property
    def PrimitiveType(self):
        return self.type

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-NRBF] sect 2.3.2.1


class NRBFClassWithMembersAndTypes(NRBFRecord):
    RecordTypeEnum = 5
    fields_desc = [
        NRBFRecord,
        NRBFClassInfo,
        NRBFMemberTypeInfo,
        LESignedIntField("LibraryId", 0),
        _NRBFMembers,
    ]


# [MS-NRBF] sect 2.3.2.3


class NRBFSystemClassWithMembersAndTypes(NRBFRecord):
    RecordTypeEnum = 4
    fields_desc = [
        NRBFRecord,
        NRBFClassInfo,
        NRBFMemberTypeInfo,
        _NRBFMembers,
    ]


# [MS-NRBF] sect 2.3.2.4


class NRBFSystemClassWithMembers(NRBFRecord):
    RecordTypeEnum = 2
    fields_desc = [
        NRBFRecord,
        NRBFClassInfo,
        _NRBFMembers,
    ]


# [MS-NRBF] sect 2.4.2.1


class ArrayInfo(Packet):
    fields_desc = [LEIntField("ObjectId", 0), LEIntField("Length", None)]


# [MS-NRBF] sect 2.4.3.2


class NRBFArraySingleObject(NRBFRecord):
    RecordTypeEnum = 16
    Length = 1
    fields_desc = [
        NRBFRecord,
        ArrayInfo,
    ]


# [MS-NRBF] sect 2.4.3.3


def _values_singleprim_cb(pkt, lst, cur, remain):
    index = len(lst) + (1 if cur is not None else 0)
    if index >= pkt.Length:
        return None
    return functools.partial(
        NRBFMemberPrimitiveUnTyped,
        type=PrimitiveTypeEnum(pkt.PrimitiveTypeEnum),
    )


class NRBFArraySinglePrimitive(NRBFRecord):
    RecordTypeEnum = 15
    fields_desc = [
        NRBFRecord,
        ArrayInfo,
        ByteEnumField("PrimitiveTypeEnum", 0, PrimitiveTypeEnum),
        MultipleTypeField(
            [
                (
                    StrLenField("Values", [], length_from=lambda pkt: pkt.Length),
                    lambda pkt: pkt.PrimitiveTypeEnum == PrimitiveTypeEnum.Byte,
                )
            ],
            PacketListField(
                "Values",
                [],
                next_cls_cb=_values_singleprim_cb,
                max_count=1000,
            ),
        ),
    ]

    def post_build(self, p, pay):
        if self.Length is None:
            p = p[:5] + struct.pack("<I", len(self.Values)) + p[9:]
        return p + pay


# [MS-NRBF] sect 2.5.1


class NRBFMemberPrimitiveTyped(NRBFRecord):
    RecordTypeEnum = 9
    fields_desc = [
        NRBFRecord,
        NRBFValueWithCode,
    ]


# [MS-NRBF] sect 2.5.3


class NRBFMemberReference(NRBFRecord):
    RecordTypeEnum = 9
    fields_desc = [
        NRBFRecord,
        LEIntField("IdRef", 0),
    ]


# [MS-NRBF] sect 2.5.4


class NRBFObjectNull(NRBFRecord):
    RecordTypeEnum = 10
    fields_desc = [
        NRBFRecord,
    ]


# [MS-NRBF] sect 2.5.7


class NRBFBinaryObjectString(NRBFRecord):
    RecordTypeEnum = 6
    fields_desc = [
        NRBFRecord,
        LEIntField("ObjectId", 0),
        PacketField("Value", NRBFLengthPrefixedString(), NRBFLengthPrefixedString),
    ]


# [MS-NRBF] sect 2.6.1


class NRBFSerializationHeader(NRBFRecord):
    RecordTypeEnum = 0
    fields_desc = [
        NRBFRecord,
        LESignedIntField("RootID", 1),
        LESignedIntField("HeaderId", 0),
        LESignedIntField("MajorVersion", 1),
        LESignedIntField("MinorVersion", 0),
    ]


# [MS-NRBF] sect 2.6.2


class NRBFBinaryLibrary(NRBFRecord):
    RecordTypeEnum = 12
    fields_desc = [
        NRBFRecord,
        LESignedIntField("LibraryId", 0),
        PacketField(
            "LibraryName", NRBFLengthPrefixedString(), NRBFLengthPrefixedString
        ),
    ]


# [MS-NRBF] sect 2.6.3


class NRBFMessageEnd(NRBFRecord):
    RecordTypeEnum = 11
    fields_desc = [
        NRBFRecord,
    ]


# NRBF is a list of records


def _nrbf_records_cls(pkt, lst, cur, remain):
    # Detect end
    if isinstance(cur, NRBFMessageEnd):
        return None
    return NRBFRecord


class NRBF(Packet):
    # This is the same structure as what is returned by ysoserial.net
    fields_desc = [
        PacketListField(
            "records",
            [NRBFMessageEnd()],
            None,
            max_count=1000,
            next_cls_cb=_nrbf_records_cls,
        )
    ]

    def default_payload_class(self, _):
        return conf.padding_layer


# Automatons


class NRTP_Server(Automaton):
    """
    NRTP server to send a single payload.
    """

    pkt_cls = NRTPSingleMessageContent
    socketcls = StreamSocket

    def __init__(self, PAYLOAD, verb=True, *args, **kwargs):
        self.PAYLOAD = PAYLOAD
        self.verb = verb
        if "sock" not in kwargs:
            raise ValueError(
                "NMF_Server cannot be started directly ! Use NMF_Server.spawn"
            )
        Automaton.__init__(
            self,
            *args,
            **kwargs,
        )

    @ATMT.state(initial=1)
    def BEGIN(self):
        pass

    @ATMT.state(error=1)
    def FAILURE(self, error):
        return error

    @ATMT.receive_condition(BEGIN)
    def should_send_response(self, pkt):
        if NRTPSingleMessageContent in pkt:
            raise self.END().action_parameters(pkt)

    @ATMT.action(should_send_response)
    def send_response(self, pkt):
        self.send(NRTPSingleMessageContent(OperationType="Reply") / self.PAYLOAD)

    @ATMT.state(final=1)
    def END(self):
        pass


if __name__ == "__main__":
    interact(mydict=globals(), mybanner="Scapy [MS-NRTP] addon")
