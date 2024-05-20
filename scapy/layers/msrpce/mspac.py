# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
[MS-PAC]

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962
Up to date with version: 23.0
"""

import struct

from scapy.config import conf
from scapy.error import log_runtime
from scapy.fields import (
    ConditionalField,
    FieldLenField,
    FieldListField,
    FlagsField,
    LEIntEnumField,
    LELongField,
    LEIntField,
    LEShortField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    StrField,
    StrFieldUtf16,
    StrFixedLenField,
    StrLenFieldUtf16,
    UTCTimeField,
    XStrField,
    XStrLenField,
)
from scapy.packet import Packet
from scapy.layers.kerberos import (
    _AUTHORIZATIONDATA_VALUES,
    _KRB_S_TYPES,
)
from scapy.layers.dcerpc import (
    NDRByteField,
    NDRConfFieldListField,
    NDRConfPacketListField,
    NDRConfStrLenField,
    NDRConfVarStrLenFieldUtf16,
    NDRConfVarStrNullFieldUtf16,
    NDRConformantString,
    NDRFieldListField,
    NDRFullPointerField,
    NDRInt3264EnumField,
    NDRIntField,
    NDRLongField,
    NDRPacket,
    NDRPacketField,
    NDRSerialization1Header,
    NDRSerializeType1PacketLenField,
    NDRShortField,
    NDRSignedLongField,
    NDRUnionField,
    _NDRConfField,
    ndr_deserialize1,
    ndr_serialize1,
)
from scapy.layers.ntlm import (
    _NTLMPayloadField,
    _NTLMPayloadPacket,
)
from scapy.layers.smb2 import WINNT_SID

# sect 2.4


class PAC_INFO_BUFFER(Packet):
    fields_desc = [
        LEIntEnumField(
            "ulType",
            0x00000001,
            {
                0x00000001: "Logon information",
                0x00000002: "Credentials information",
                0x00000006: "Server Signature",
                0x00000007: "KDC Signature",
                0x0000000A: "Client name and ticket information",
                0x0000000B: "Constrained delegation information",
                0x0000000C: "UPN and DNS information",
                0x0000000D: "Client claims information",
                0x0000000E: "Device information",
                0x0000000F: "Device claims information",
                0x00000010: "Ticket Signature",
                0x00000011: "PAC Attributes",
                0x00000012: "PAC Requestor",
                0x00000013: "Extended KDC Signature",
            },
        ),
        LEIntField("cbBufferSize", None),
        LELongField("Offset", None),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


_PACTYPES = {}


# sect 2.5 - NDR PACKETS


class RPC_UNICODE_STRING(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRShortField("Length", None, size_of="Buffer", adjust=lambda _, x: (x * 2)),
        NDRShortField(
            "MaximumLength", None, size_of="Buffer", adjust=lambda _, x: (x * 2)
        ),
        NDRFullPointerField(
            NDRConfVarStrLenFieldUtf16(
                "Buffer",
                "",
                size_is=lambda pkt: (pkt.MaximumLength // 2),
                length_is=lambda pkt: (pkt.Length // 2),
            ),
            deferred=True,
        ),
    ]


class FILETIME(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [NDRIntField("dwLowDateTime", 0), NDRIntField("dwHighDateTime", 0)]


class GROUP_MEMBERSHIP(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [NDRIntField("RelativeId", 0), NDRIntField("Attributes", 0)]


class CYPHER_BLOCK(NDRPacket):
    fields_desc = [StrFixedLenField("data", "", length=8)]


class USER_SESSION_KEY(NDRPacket):
    fields_desc = [PacketListField("data", [], CYPHER_BLOCK, count_from=lambda _: 2)]


class RPC_SID_IDENTIFIER_AUTHORITY(NDRPacket):
    fields_desc = [StrFixedLenField("Value", "", length=6)]


class SID(NDRPacket):
    ALIGNMENT = (4, 8)
    DEPORTED_CONFORMANTS = ["SubAuthority"]
    fields_desc = [
        NDRByteField("Revision", 0),
        NDRByteField("SubAuthorityCount", None, size_of="SubAuthority"),
        NDRPacketField(
            "IdentifierAuthority",
            RPC_SID_IDENTIFIER_AUTHORITY(),
            RPC_SID_IDENTIFIER_AUTHORITY,
        ),
        NDRConfFieldListField(
            "SubAuthority",
            [],
            NDRIntField("", 0),
            size_is=lambda pkt: pkt.SubAuthorityCount,
            conformant_in_struct=True,
        ),
    ]

    def summary(self):
        return WINNT_SID.summary(self)


class KERB_SID_AND_ATTRIBUTES(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullPointerField(NDRPacketField("Sid", SID(), SID), deferred=True),
        NDRIntField("Attributes", 0),
    ]


class KERB_VALIDATION_INFO(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRPacketField("LogonTime", FILETIME(), FILETIME),
        NDRPacketField("LogoffTime", FILETIME(), FILETIME),
        NDRPacketField("KickOffTime", FILETIME(), FILETIME),
        NDRPacketField("PasswordLastSet", FILETIME(), FILETIME),
        NDRPacketField("PasswordCanChange", FILETIME(), FILETIME),
        NDRPacketField("PasswordMustChange", FILETIME(), FILETIME),
        NDRPacketField("EffectiveName", RPC_UNICODE_STRING(), RPC_UNICODE_STRING),
        NDRPacketField("FullName", RPC_UNICODE_STRING(), RPC_UNICODE_STRING),
        NDRPacketField("LogonScript", RPC_UNICODE_STRING(), RPC_UNICODE_STRING),
        NDRPacketField("ProfilePath", RPC_UNICODE_STRING(), RPC_UNICODE_STRING),
        NDRPacketField("HomeDirectory", RPC_UNICODE_STRING(), RPC_UNICODE_STRING),
        NDRPacketField("HomeDirectoryDrive", RPC_UNICODE_STRING(), RPC_UNICODE_STRING),
        NDRShortField("LogonCount", 0),
        NDRShortField("BadPasswordCount", 0),
        NDRIntField("UserId", 0),
        NDRIntField("PrimaryGroupId", 0),
        NDRIntField("GroupCount", None, size_of="GroupIds"),
        NDRFullPointerField(
            NDRConfPacketListField(
                "GroupIds",
                [GROUP_MEMBERSHIP()],
                GROUP_MEMBERSHIP,
                size_is=lambda pkt: pkt.GroupCount,
            ),
            deferred=True,
        ),
        NDRIntField("UserFlags", 0),
        NDRPacketField("UserSessionKey", USER_SESSION_KEY(), USER_SESSION_KEY),
        NDRPacketField("LogonServer", RPC_UNICODE_STRING(), RPC_UNICODE_STRING),
        NDRPacketField("LogonDomainName", RPC_UNICODE_STRING(), RPC_UNICODE_STRING),
        NDRFullPointerField(NDRPacketField("LogonDomainId", SID(), SID), deferred=True),
        NDRFieldListField("Reserved1", [], NDRIntField("", 0), length_is=lambda _: 2),
        NDRIntField("UserAccountControl", 0),
        NDRFieldListField("Reserved3", [], NDRIntField("", 0), length_is=lambda _: 7),
        NDRIntField("SidCount", None, size_of="ExtraSids"),
        NDRFullPointerField(
            NDRConfPacketListField(
                "ExtraSids",
                [KERB_SID_AND_ATTRIBUTES()],
                KERB_SID_AND_ATTRIBUTES,
                size_is=lambda pkt: pkt.SidCount,
            ),
            deferred=True,
        ),
        NDRFullPointerField(
            NDRPacketField("ResourceGroupDomainSid", SID(), SID), deferred=True
        ),
        NDRIntField("ResourceGroupCount", None, size_of="ResourceGroupIds"),
        NDRFullPointerField(
            NDRConfPacketListField(
                "ResourceGroupIds",
                [GROUP_MEMBERSHIP()],
                GROUP_MEMBERSHIP,
                size_is=lambda pkt: pkt.ResourceGroupCount,
            ),
            deferred=True,
        ),
    ]


_PACTYPES[1] = KERB_VALIDATION_INFO

# sect 2.6


class PAC_CREDENTIAL_INFO(Packet):
    fields_desc = [
        LEIntField("Version", 0),
        LEIntEnumField(
            "EncryptionType",
            1,
            {
                0x00000001: "DES-CBC-CRC",
                0x00000003: "DES-CBC-MD5",
                0x00000011: "AES128_CTS_HMAC_SHA1_96",
                0x00000012: "AES256_CTS_HMAC_SHA1_96",
                0x00000017: "RC4-HMAC",
            },
        ),
        XStrField("SerializedData", b""),
    ]


_PACTYPES[2] = PAC_CREDENTIAL_INFO

# sect 2.7


class PAC_CLIENT_INFO(Packet):
    fields_desc = [
        UTCTimeField(
            "ClientId", None, fmt="<Q", epoch=[1601, 1, 1, 0, 0, 0], custom_scaling=1e7
        ),
        FieldLenField("NameLength", None, length_of="Name", fmt="<H"),
        StrLenFieldUtf16("Name", b"", length_from=lambda pkt: pkt.NameLength),
    ]


_PACTYPES[0xA] = PAC_CLIENT_INFO

# sect 2.8


class PAC_SIGNATURE_DATA(Packet):
    fields_desc = [
        LEIntEnumField(
            "SignatureType",
            None,
            _KRB_S_TYPES,
        ),
        XStrLenField(
            "Signature",
            b"",
            length_from=lambda pkt: {
                0x1: 4,
                0xFFFFFF76: 16,
                0x0000000F: 12,
                0x00000010: 12,
            }.get(pkt.SignatureType, 0),
        ),
        StrField("RODCIdentifier", b""),
    ]


_PACTYPES[6] = PAC_SIGNATURE_DATA
_PACTYPES[7] = PAC_SIGNATURE_DATA
_PACTYPES[0x10] = PAC_SIGNATURE_DATA
_PACTYPES[0x13] = PAC_SIGNATURE_DATA

# sect 2.9


class S4U_DELEGATION_INFO(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRPacketField("S4U2proxyTarget", RPC_UNICODE_STRING(), RPC_UNICODE_STRING),
        NDRIntField("TransitedListSize", None, size_of="S4UTransitedServices"),
        NDRFullPointerField(
            NDRConfPacketListField(
                "S4UTransitedServices",
                [RPC_UNICODE_STRING()],
                RPC_UNICODE_STRING,
                size_is=lambda pkt: pkt.TransitedListSize,
            ),
            deferred=True,
        ),
    ]


# sect 2.10


def _pac_post_build(self, p, pay_offset, fields):
    """Util function to build the offset and populate the lengths"""
    for field_name, value in self.fields["Payload"]:
        length = self.get_field("Payload").fields_map[field_name].i2len(self, value)
        offset = fields[field_name]
        # Length
        if self.getfieldval(field_name + "Len") is None:
            p = p[:offset] + struct.pack("<H", length) + p[offset + 2 :]
        # Offset
        if self.getfieldval(field_name + "BufferOffset") is None:
            p = p[: offset + 2] + struct.pack("<H", pay_offset) + p[offset + 4 :]
        pay_offset += length
    return p


class UPN_DNS_INFO(_NTLMPayloadPacket):
    fields_desc = [
        LEShortField("UpnLen", None),
        LEShortField("UpnBufferOffset", None),
        LEShortField("DnsDomainNameLen", None),
        LEShortField("DnsDomainNameBufferOffset", None),
        FlagsField(
            "Flags",
            0,
            -32,
            [
                "U",
                "S",  # Extended
            ],
        ),
        ConditionalField(
            # Extended
            LEShortField("SamNameLen", None),
            lambda pkt: pkt.Flags.S,
        ),
        ConditionalField(
            # Extended
            LEShortField("SamNameBufferOffset", None),
            lambda pkt: pkt.Flags.S,
        ),
        ConditionalField(
            # Extended
            LEShortField("SidLen", None),
            lambda pkt: pkt.Flags.S,
        ),
        ConditionalField(
            # Extended
            LEShortField("SidBufferOffset", None),
            lambda pkt: pkt.Flags.S,
        ),
        MultipleTypeField(
            [
                (
                    # Extended
                    _NTLMPayloadField(
                        "Payload",
                        20,
                        [
                            StrFieldUtf16("Upn", b""),
                            StrFieldUtf16("DnsDomainName", b""),
                            StrFieldUtf16("SamName", b""),
                            PacketField("Sid", WINNT_SID(), WINNT_SID),
                        ],
                    ),
                    lambda pkt: pkt.Flags.S,
                )
            ],
            # Not-extended
            _NTLMPayloadField(
                "Payload",
                12,
                [
                    StrFieldUtf16("Upn", b""),
                    StrFieldUtf16("DnsDomainName", b""),
                ],
            ),
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        offset = 12
        fields = {
            "Upn": 0,
            "DnsDomainName": 4,
        }
        if self.Flags.S:
            offset = 20
            fields["SamName"] = 12
            fields["Sid"] = 16
        return (
            _pac_post_build(
                self,
                pkt,
                offset,
                fields,
            )
            + pay
        )


_PACTYPES[0xC] = UPN_DNS_INFO

# sect 2.11 - NDR PACKETS

try:
    from enum import IntEnum
except ImportError:
    IntEnum = object


class CLAIM_TYPE(IntEnum):
    CLAIM_TYPE_INT64 = 1
    CLAIM_TYPE_UINT64 = 2
    CLAIM_TYPE_STRING = 3
    CLAIM_TYPE_BOOLEAN = 6


class CLAIMS_SOURCE_TYPE(IntEnum):
    CLAIMS_SOURCE_TYPE_AD = 1
    CLAIMS_SOURCE_TYPE_CERTIFICATE = 2


class CLAIMS_COMPRESSION_FORMAT(IntEnum):
    COMPRESSION_FORMAT_NONE = 0
    COMPRESSION_FORMAT_LZNT1 = 2
    COMPRESSION_FORMAT_XPRESS = 3
    COMPRESSION_FORMAT_XPRESS_HUFF = 4


class CLAIM_ENTRY_sub0(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("ValueCount", None, size_of="Int64Values"),
        NDRFullPointerField(
            NDRConfFieldListField(
                "Int64Values",
                [],
                NDRSignedLongField,
                size_is=lambda pkt: pkt.ValueCount,
            ),
            deferred=True,
        ),
    ]


class CLAIM_ENTRY_sub1(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("ValueCount", None, size_of="Uint64Values"),
        NDRFullPointerField(
            NDRConfFieldListField(
                "Uint64Values", [], NDRLongField, size_is=lambda pkt: pkt.ValueCount
            ),
            deferred=True,
        ),
    ]


class CLAIM_ENTRY_sub2(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("ValueCount", None, size_of="StringValues"),
        NDRFullPointerField(
            NDRConfFieldListField(
                "StringValues",
                [],
                NDRFullPointerField(
                    NDRConfVarStrNullFieldUtf16("StringVal", ""),
                    deferred=True,
                ),
                size_is=lambda pkt: pkt.ValueCount,
            ),
            deferred=True,
        ),
    ]


class CLAIM_ENTRY_sub3(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("ValueCount", None, size_of="BooleanValues"),
        NDRFullPointerField(
            NDRConfFieldListField(
                "BooleanValues", [], NDRLongField, size_is=lambda pkt: pkt.ValueCount
            ),
            deferred=True,
        ),
    ]


class CLAIM_ENTRY(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("Id", ""), deferred=True),
        NDRInt3264EnumField("Type", 0, CLAIM_TYPE),
        NDRUnionField(
            [
                (
                    NDRPacketField("Values", CLAIM_ENTRY_sub0(), CLAIM_ENTRY_sub0),
                    (
                        (
                            lambda pkt: getattr(pkt, "Type", None)
                            == CLAIM_TYPE.CLAIM_TYPE_INT64
                        ),
                        (lambda _, val: val.tag == CLAIM_TYPE.CLAIM_TYPE_INT64),
                    ),
                ),
                (
                    NDRPacketField("Values", CLAIM_ENTRY_sub1(), CLAIM_ENTRY_sub1),
                    (
                        (
                            lambda pkt: getattr(pkt, "Type", None)
                            == CLAIM_TYPE.CLAIM_TYPE_UINT64
                        ),
                        (lambda _, val: val.tag == CLAIM_TYPE.CLAIM_TYPE_UINT64),
                    ),
                ),
                (
                    NDRPacketField("Values", CLAIM_ENTRY_sub2(), CLAIM_ENTRY_sub2),
                    (
                        (
                            lambda pkt: getattr(pkt, "Type", None)
                            == CLAIM_TYPE.CLAIM_TYPE_STRING
                        ),
                        (lambda _, val: val.tag == CLAIM_TYPE.CLAIM_TYPE_STRING),
                    ),
                ),
                (
                    NDRPacketField("Values", CLAIM_ENTRY_sub3(), CLAIM_ENTRY_sub3),
                    (
                        (
                            lambda pkt: getattr(pkt, "Type", None)
                            == CLAIM_TYPE.CLAIM_TYPE_BOOLEAN
                        ),
                        (lambda _, val: val.tag == CLAIM_TYPE.CLAIM_TYPE_BOOLEAN),
                    ),
                ),
            ],
            StrFixedLenField("Values", "", length=0),
            align=(2, 8),
            switch_fmt=("H", "I"),
        ),
    ]


class CLAIMS_ARRAY(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRInt3264EnumField("usClaimsSourceType", 0, CLAIMS_SOURCE_TYPE),
        NDRIntField("ulClaimsCount", None, size_of="ClaimEntries"),
        NDRFullPointerField(
            NDRConfPacketListField(
                "ClaimEntries",
                [CLAIM_ENTRY()],
                CLAIM_ENTRY,
                size_is=lambda pkt: pkt.ulClaimsCount,
            ),
            deferred=True,
        ),
    ]


class CLAIMS_SET(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("ulClaimsArrayCount", None, size_of="ClaimsArrays"),
        NDRFullPointerField(
            NDRConfPacketListField(
                "ClaimsArrays",
                [CLAIMS_ARRAY()],
                CLAIMS_ARRAY,
                size_is=lambda pkt: pkt.ulClaimsArrayCount,
            ),
            deferred=True,
        ),
        NDRShortField("usReservedType", 0),
        NDRIntField("ulReservedFieldSize", None, size_of="ReservedField"),
        NDRFullPointerField(
            NDRConfStrLenField(
                "ReservedField", "", size_is=lambda pkt: pkt.ulReservedFieldSize
            ),
            deferred=True,
        ),
    ]


class _CLAIMSClaimSet(_NDRConfField, NDRSerializeType1PacketLenField):
    CONFORMANT_STRING = True
    LENGTH_FROM = True

    def m2i(self, pkt, s):
        if pkt.usCompressionFormat == CLAIMS_COMPRESSION_FORMAT.COMPRESSION_FORMAT_NONE:
            return ndr_deserialize1(s, CLAIMS_SET, ndr64=False)
        else:
            # TODO: There are 3 funky compression formats... see sect 2.2.18.4
            return NDRConformantString(value=s)

    def i2m(self, pkt, val):
        val = val[0]
        if pkt.usCompressionFormat == CLAIMS_COMPRESSION_FORMAT.COMPRESSION_FORMAT_NONE:
            return ndr_serialize1(val)
        else:
            # funky
            return bytes(val)

    def valueof(self, pkt, x):
        if pkt.usCompressionFormat == CLAIMS_COMPRESSION_FORMAT.COMPRESSION_FORMAT_NONE:
            return self._subval(x)[0]
        else:
            return x


class CLAIMS_SET_METADATA(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("ulClaimsSetSize", None, size_of="ClaimsSet"),
        NDRFullPointerField(
            _CLAIMSClaimSet(
                "ClaimsSet", None, None, size_is=lambda pkt: pkt.ulClaimsSetSize
            ),
            deferred=True,
        ),
        NDRInt3264EnumField(
            "usCompressionFormat",
            0,
            CLAIMS_COMPRESSION_FORMAT,
        ),
        # this size_of is technically wrong. we just assume it's uncompressed...
        NDRIntField("ulUncompressedClaimsSetSize", None, size_of="ClaimsSet"),
        NDRShortField("usReservedType", 0),
        NDRIntField("ulReservedFieldSize", None, size_of="ReservedField"),
        NDRFullPointerField(
            NDRConfStrLenField(
                "ReservedField", "", size_is=lambda pkt: pkt.ulReservedFieldSize
            ),
            deferred=True,
        ),
    ]


class PAC_CLIENT_CLAIMS_INFO(NDRPacket):
    fields_desc = [NDRPacketField("Claims", CLAIMS_SET_METADATA(), CLAIMS_SET_METADATA)]


if IntEnum != object:
    # If not available, ignore. I can't be bothered
    _PACTYPES[0xD] = PAC_CLIENT_CLAIMS_INFO


# sect 2.12 - NDR PACKETS


class DOMAIN_GROUP_MEMBERSHIP(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullPointerField(NDRPacketField("DomainId", SID(), SID), deferred=True),
        NDRIntField("GroupCount", 0),
        NDRFullPointerField(
            NDRConfPacketListField(
                "GroupIds",
                [GROUP_MEMBERSHIP()],
                GROUP_MEMBERSHIP,
                size_is=lambda pkt: pkt.GroupCount,
            ),
            deferred=True,
        ),
    ]


class PAC_DEVICE_INFO(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("UserId", 0),
        NDRIntField("PrimaryGroupId", 0),
        NDRFullPointerField(
            NDRPacketField("AccountDomainId", SID(), SID), deferred=True
        ),
        NDRIntField("AccountGroupCount", 0),
        NDRFullPointerField(
            NDRConfPacketListField(
                "AccountGroupIds",
                [GROUP_MEMBERSHIP()],
                GROUP_MEMBERSHIP,
                size_is=lambda pkt: pkt.AccountGroupCount,
            ),
            deferred=True,
        ),
        NDRIntField("SidCount", 0),
        NDRFullPointerField(
            NDRConfPacketListField(
                "ExtraSids",
                [KERB_SID_AND_ATTRIBUTES()],
                KERB_SID_AND_ATTRIBUTES,
                size_is=lambda pkt: pkt.SidCount,
            ),
            deferred=True,
        ),
        NDRIntField("DomainGroupCount", 0),
        NDRFullPointerField(
            NDRConfPacketListField(
                "DomainGroup",
                [DOMAIN_GROUP_MEMBERSHIP()],
                DOMAIN_GROUP_MEMBERSHIP,
                size_is=lambda pkt: pkt.DomainGroupCount,
            ),
            deferred=True,
        ),
    ]


_PACTYPES[0xE] = PAC_DEVICE_INFO

# sect 2.14 - PAC_ATTRIBUTES_INFO


class PAC_ATTRIBUTES_INFO(Packet):
    fields_desc = [
        LEIntField("FlagsLength", 2),
        FieldListField(
            "Flags",
            ["PAC_WAS_REQUESTED"],
            FlagsField(
                "",
                0,
                -32,
                {
                    0x00000001: "PAC_WAS_REQUESTED",
                    0x00000002: "PAC_WAS_GIVEN_IMPLICITLY",
                },
            ),
            count_from=lambda pkt: (pkt.FlagsLength + 7) // 8,
        ),
    ]


_PACTYPES[0x11] = PAC_ATTRIBUTES_INFO

# sect 2.15 - PAC_REQUESTOR


class PAC_REQUESTOR(Packet):
    fields_desc = [
        PacketField("Sid", WINNT_SID(), WINNT_SID),
    ]


_PACTYPES[0x12] = PAC_REQUESTOR

# sect 2.3


class _PACTYPEBuffers(PacketListField):
    def addfield(self, pkt, s, val):
        # we use this field to set Offset and cbBufferSize
        res = b""
        if len(val) != len(pkt.Payloads):
            log_runtime.warning("Size of 'Buffers' does not match size of 'Payloads' !")
            return super(_PACTYPEBuffers, self).addfield(pkt, s, val)
        offset = 16 * len(pkt.Payloads) + 8
        for i, v in enumerate(val):
            x = self.i2m(pkt, v)
            pay = pkt.Payloads[i]
            if isinstance(pay, NDRPacket) or isinstance(pay, NDRSerialization1Header):
                lgth = len(ndr_serialize1(pay))
            else:
                lgth = len(pay)
            if v.cbBufferSize is None:
                x = x[:4] + struct.pack("<I", lgth) + x[8:]
            if v.Offset is None:
                x = x[:8] + struct.pack("<Q", offset) + x[16:]
            offset += lgth
            offset += (-offset) % 8  # Account for padding
            res += x
        return s + res


class _PACTYPEPayloads(PacketListField):
    def i2m(self, pkt, val):
        if isinstance(val, NDRPacket) or isinstance(val, NDRSerialization1Header):
            s = ndr_serialize1(val)
        else:
            s = bytes(val)
        return s + b"\x00" * ((-len(s)) % 8)

    def getfield(self, pkt, s):
        if not pkt or not s:
            return s, []
        result = []
        for i in range(len(pkt.Buffers)):
            buf = pkt.Buffers[i]
            offset = buf.Offset - 16 * len(pkt.Buffers) - 8
            try:
                cls = _PACTYPES[buf.ulType]
                if buf.cbBufferSize == 0:
                    # empty size
                    raise KeyError
                if issubclass(cls, NDRPacket):
                    val = ndr_deserialize1(
                        s[offset : offset + buf.cbBufferSize],
                        cls,
                        ndr64=False,
                    )
                else:
                    val = cls(s[offset : offset + buf.cbBufferSize])
                if conf.raw_layer in val:
                    pad = conf.padding_layer(load=val[conf.raw_layer].load)
                    lay = val[conf.raw_layer].underlayer
                    if not lay:
                        val.show()
                        raise ValueError("Dissection failed")
                    lay.remove_payload()
                    lay.add_payload(pad)
            except KeyError:
                val = conf.padding_layer(s[offset : offset + buf.cbBufferSize])
            result.append(val)
        return b"", result


class PACTYPE(Packet):
    name = "PACTYPE - PAC"
    fields_desc = [
        FieldLenField("cBuffers", None, count_of="Buffers", fmt="<I"),
        LEIntField("Version", 0x00000000),
        _PACTYPEBuffers(
            "Buffers",
            [PAC_INFO_BUFFER()],
            PAC_INFO_BUFFER,
            count_from=lambda pkt: pkt.cBuffers,
        ),
        _PACTYPEPayloads("Payloads", [], None),
    ]


_AUTHORIZATIONDATA_VALUES[128] = PACTYPE  # AD-WIN2K-PAC
