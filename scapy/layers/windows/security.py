# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Python objects for Microsoft Windows security structures.
"""

import re
import struct

from scapy.config import conf
from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteEnumField,
    ByteField,
    ConditionalField,
    FieldLenField,
    FieldListField,
    FlagsField,
    FlagValue,
    LEIntField,
    LELongField,
    LenField,
    LEShortEnumField,
    LEShortField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    ShortField,
    StrFieldUtf16,
    StrFixedLenField,
    StrLenField,
    StrLenFieldUtf16,
    UUIDField,
)

from scapy.layers.ntlm import (
    _NTLM_ENUM,
    _NTLM_post_build,
    _NTLMPayloadField,
    _NTLMPayloadPacket,
)

# [MS-DTYP] sect 2.4.1


class WINNT_SID_IDENTIFIER_AUTHORITY(Packet):

    fields_desc = [
        StrFixedLenField("Value", b"\x00\x00\x00\x00\x00\x01", length=6),
    ]

    def default_payload_class(self, payload: bytes) -> Packet:
        return conf.padding_layer


# [MS-DTYP] sect 2.4.2


class WINNT_SID(Packet):
    fields_desc = [
        ByteField("Revision", 1),
        FieldLenField("SubAuthorityCount", None, count_of="SubAuthority", fmt="B"),
        PacketField(
            "IdentifierAuthority",
            WINNT_SID_IDENTIFIER_AUTHORITY(),
            WINNT_SID_IDENTIFIER_AUTHORITY,
        ),
        FieldListField(
            "SubAuthority",
            [0],
            LEIntField("", 0),
            count_from=lambda pkt: pkt.SubAuthorityCount,
        ),
    ]

    def default_payload_class(self, payload: bytes) -> Packet:
        return conf.padding_layer

    _SID_REG = re.compile(r"^S-(\d)-(\d+)((?:-\d+)*)$")

    @staticmethod
    def fromstr(x: str):
        """
        Helper to create a SID from its string representation.

        :param x: string representation of the SID like "S-1-5-18"
        :type x: str

        Example:

            >>> from scapy.layers.windows.security import WINNT_SID
            >>> WINNT_SID.fromstr("S-1-5-18")
            <WINNT_SID  Revision=1 IdentifierAuthority=<WINNT_SID_IDENTIFIER_AUTHORITY
            Value=b'\x00\x00\x00\x00\x00\x05' |> SubAuthority=[18] |>
            >>> _.summary()
            >>> 'S-1-5-18'
        """

        m = WINNT_SID._SID_REG.match(x)
        if not m:
            raise ValueError("Invalid SID format !")
        rev, authority, subauthority = m.groups()
        return WINNT_SID(
            Revision=int(rev),
            IdentifierAuthority=WINNT_SID_IDENTIFIER_AUTHORITY(
                Value=struct.pack(">Q", int(authority))[2:]
            ),
            SubAuthority=[int(x) for x in subauthority[1:].split("-")],
        )

    def summary(self) -> str:
        """
        Return the string representation of the SID.
        """
        return "S-%s-%s%s" % (
            self.Revision,
            struct.unpack(">Q", b"\x00\x00" + self.IdentifierAuthority.Value)[0],
            (
                ("-%s" % "-".join(str(x) for x in self.SubAuthority))
                if self.SubAuthority
                else ""
            ),
        )


# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers

WELL_KNOWN_SIDS = {
    # Universal well-known SID
    "S-1-0-0": "Null SID",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3-0": "Creator Owner ID",
    "S-1-3-1": "Creator Group ID",
    "S-1-3-2": "Owner Server",
    "S-1-3-3": "Group Server",
    "S-1-3-4": "Owner Rights",
    "S-1-4": "Non-unique Authority",
    "S-1-5": "NT Authority",
    "S-1-5-80-0": "All Services",
    # NT well-known SIDs
    "S-1-5-1": "Dialup",
    "S-1-5-113": "Local account",
    "S-1-5-114": "Local account and member of Administrators group",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server User",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "System (or LocalSystem)",
    "S-1-5-19": "NT Authority (LocalService)",
    "S-1-5-20": "Network Service",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-32-554": r"Builtin\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": r"Builtin\Remote Desktop Users",
    "S-1-5-32-556": r"Builtin\Network Configuration Operators",
    "S-1-5-32-557": r"Builtin\Incoming Forest Trust Builders",
    "S-1-5-32-558": r"Builtin\Performance Monitor Users",
    "S-1-5-32-559": r"Builtin\Performance Log Users",
    "S-1-5-32-560": r"Builtin\Windows Authorization Access Group",
    "S-1-5-32-561": r"Builtin\Terminal Server License Servers",
    "S-1-5-32-562": r"Builtin\Distributed COM Users",
    "S-1-5-32-568": r"Builtin\IIS_IUSRS",
    "S-1-5-32-569": r"Builtin\Cryptographic Operators",
    "S-1-5-32-573": r"Builtin\Event Log Readers",
    "S-1-5-32-574": r"Builtin\Certificate Service DCOM Access",
    "S-1-5-32-575": r"Builtin\RDS Remote Access Servers",
    "S-1-5-32-576": r"Builtin\RDS Endpoint Servers",
    "S-1-5-32-577": r"Builtin\RDS Management Servers",
    "S-1-5-32-578": r"Builtin\Hyper-V Administrators",
    "S-1-5-32-579": r"Builtin\Access Control Assistance Operators",
    "S-1-5-32-580": r"Builtin\Remote Management Users",
    "S-1-5-32-581": r"Builtin\Default Account",
    "S-1-5-32-582": r"Builtin\Storage Replica Admins",
    "S-1-5-32-583": r"Builtin\Device Owners",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authentication",
    "S-1-5-80": "NT Service",
    "S-1-5-80-0": "All Services",
    "S-1-5-83-0": r"NT VIRTUAL MACHINE\Virtual Machines",
}


# [MS-DTYP] sect 2.4.3

_WINNT_ACCESS_MASK = {
    0x80000000: "GENERIC_READ",
    0x40000000: "GENERIC_WRITE",
    0x20000000: "GENERIC_EXECUTE",
    0x10000000: "GENERIC_ALL",
    0x02000000: "MAXIMUM_ALLOWED",
    0x01000000: "ACCESS_SYSTEM_SECURITY",
    0x00100000: "SYNCHRONIZE",
    0x00080000: "WRITE_OWNER",
    0x00040000: "WRITE_DACL",
    0x00020000: "READ_CONTROL",
    0x00010000: "DELETE",
}


# [MS-DTYP] sect 2.4.4.1


WINNT_ACE_FLAGS = {
    0x01: "OBJECT_INHERIT",
    0x02: "CONTAINER_INHERIT",
    0x04: "NO_PROPAGATE_INHERIT",
    0x08: "INHERIT_ONLY",
    0x10: "INHERITED_ACE",
    0x40: "SUCCESSFUL_ACCESS",
    0x80: "FAILED_ACCESS",
}


class WINNT_ACE_HEADER(Packet):
    """
    Access Control Entry (ACE) Header
    It is composed of 3 fields, followed by ACE-specific data:

        - AceType (1 byte): see below for standard values
        - AceFlags (1 byte): see WINNT_ACE_FLAGS
        - AceSize (2 bytes): total size of the ACE, including the header
                             and the ACE-specific data.
    """

    fields_desc = [
        ByteEnumField(
            "AceType",
            0,
            {
                0x00: "ACCESS_ALLOWED",
                0x01: "ACCESS_DENIED",
                0x02: "SYSTEM_AUDIT",
                0x03: "SYSTEM_ALARM",
                0x04: "ACCESS_ALLOWED_COMPOUND",
                0x05: "ACCESS_ALLOWED_OBJECT",
                0x06: "ACCESS_DENIED_OBJECT",
                0x07: "SYSTEM_AUDIT_OBJECT",
                0x08: "SYSTEM_ALARM_OBJECT",
                0x09: "ACCESS_ALLOWED_CALLBACK",
                0x0A: "ACCESS_DENIED_CALLBACK",
                0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT",
                0x0C: "ACCESS_DENIED_CALLBACK_OBJECT",
                0x0D: "SYSTEM_AUDIT_CALLBACK",
                0x0E: "SYSTEM_ALARM_CALLBACK",
                0x0F: "SYSTEM_AUDIT_CALLBACK_OBJECT",
                0x10: "SYSTEM_ALARM_CALLBACK_OBJECT",
                0x11: "SYSTEM_MANDATORY_LABEL",
                0x12: "SYSTEM_RESOURCE_ATTRIBUTE",
                0x13: "SYSTEM_SCOPED_POLICY_ID",
            },
        ),
        FlagsField(
            "AceFlags",
            0,
            8,
            WINNT_ACE_FLAGS,
        ),
        LenField("AceSize", None, fmt="<H", adjust=lambda x: x + 4),
    ]

    def extract_padding(self, p):
        return p[: self.AceSize - 4], p[self.AceSize - 4 :]

    # fmt: off
    def extractData(self, accessMask=None):
        """
        Return the ACE data as usable data.

        :param accessMask: context-specific flags for the ACE Mask.
        """
        sid_string = self.payload.Sid.summary()
        mask = self.payload.Mask
        if accessMask is not None:
            mask = FlagValue(mask, FlagsField("", 0, 32, accessMask).names)
        ace_flag_string = str(
            FlagValue(self.AceFlags, ["OI", "CI", "NP", "IO", "ID", "SA", "FA"])
        )
        object_guid = getattr(self.payload, "ObjectType", "")
        inherit_object_guid = getattr(self.payload, "InheritedObjectType", "")
        # ApplicationData -> conditional expression
        cond_expr = None
        if hasattr(self.payload, "ApplicationData"):
            # Parse tokens
            res = []
            for ct in self.payload.ApplicationData.Tokens:
                if ct.TokenType in [
                    # binary operators
                    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x88, 0x8e, 0x8f,
                    0xa0, 0xa1
                ]:
                    t1 = res.pop(-1)
                    t0 = res.pop(-1)
                    tt = ct.sprintf("%TokenType%")
                    if ct.TokenType in [0xa0, 0xa1]:  # && and ||
                        res.append(f"({t0}) {tt} ({t1})")
                    else:
                        res.append(f"{t0} {tt} {t1}")
                elif ct.TokenType in [
                    # unary operators
                    0x87, 0x8d, 0xa2, 0x89, 0x8a, 0x8b, 0x8c, 0x91, 0x92, 0x93
                ]:
                    t0 = res.pop(-1)
                    tt = ct.sprintf("%TokenType%")
                    res.append(f"{tt}{t0}")
                elif ct.TokenType in [
                    # values
                    0x01, 0x02, 0x03, 0x04, 0x10, 0x18, 0x50, 0x51, 0xf8, 0xf9,
                    0xfa, 0xfb
                ]:
                    def lit(ct):
                        if ct.TokenType in [0x10, 0x18]:  # literal strings
                            return '"%s"' % ct.value
                        elif ct.TokenType == 0x50:  # composite
                            return "({%s})" % ",".join(lit(x) for x in ct.value)
                        else:
                            return str(ct.value)
                    res.append(lit(ct))
                elif ct.TokenType == 0x00:  # padding
                    pass
                else:
                    raise ValueError("Unhandled token type %s" % ct.TokenType)
            if len(res) != 1:
                raise ValueError("Incomplete SDDL !")
            cond_expr = "(%s)" % res[0]
        return {
            "ace-flags-string": ace_flag_string,
            "sid-string": sid_string,
            "mask": mask,
            "object-guid": object_guid,
            "inherited-object-guid": inherit_object_guid,
            "cond-expr": cond_expr,
        }
    # fmt: on

    def toSDDL(self, accessMask=None):
        """
        Return SDDL
        """
        data = self.extractData(accessMask=accessMask)
        ace_rights = ""  # TODO
        if self.AceType in [0x9, 0xA, 0xB, 0xD]:  # Conditional ACE
            conditional_ace_type = {
                0x09: "XA",
                0x0A: "XD",
                0x0B: "XU",
                0x0D: "ZA",
            }[self.AceType]
            return "D:(%s)" % (
                ";".join(
                    x
                    for x in [
                        conditional_ace_type,
                        data["ace-flags-string"],
                        ace_rights,
                        str(data["object-guid"]),
                        str(data["inherited-object-guid"]),
                        data["sid-string"],
                        data["cond-expr"],
                    ]
                    if x is not None
                )
            )
        else:
            ace_type = {
                0x00: "A",
                0x01: "D",
                0x02: "AU",
                0x05: "OA",
                0x06: "OD",
                0x07: "OU",
                0x11: "ML",
                0x13: "SP",
            }[self.AceType]
            return "(%s)" % (
                ";".join(
                    x
                    for x in [
                        ace_type,
                        data["ace-flags-string"],
                        ace_rights,
                        str(data["object-guid"]),
                        str(data["inherited-object-guid"]),
                        data["sid-string"],
                        data["cond-expr"],
                    ]
                    if x is not None
                )
            )


# [MS-DTYP] sect 2.4.4.2


class WINNT_ACCESS_ALLOWED_ACE(Packet):
    fields_desc = [
        FlagsField("Mask", 0, -32, _WINNT_ACCESS_MASK),
        PacketField("Sid", WINNT_SID(), WINNT_SID),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_ALLOWED_ACE, AceType=0x00)


# [MS-DTYP] sect 2.4.4.3


class WINNT_ACCESS_ALLOWED_OBJECT_ACE(Packet):
    fields_desc = [
        FlagsField("Mask", 0, -32, _WINNT_ACCESS_MASK),
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x00000001: "OBJECT_TYPE_PRESENT",
                0x00000002: "INHERITED_OBJECT_TYPE_PRESENT",
            },
        ),
        ConditionalField(
            UUIDField("ObjectType", None, uuid_fmt=UUIDField.FORMAT_LE),
            lambda pkt: pkt.Flags.OBJECT_TYPE_PRESENT,
        ),
        ConditionalField(
            UUIDField("InheritedObjectType", None, uuid_fmt=UUIDField.FORMAT_LE),
            lambda pkt: pkt.Flags.INHERITED_OBJECT_TYPE_PRESENT,
        ),
        PacketField("Sid", WINNT_SID(), WINNT_SID),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_ALLOWED_OBJECT_ACE, AceType=0x05)


# [MS-DTYP] sect 2.4.4.4


class WINNT_ACCESS_DENIED_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_DENIED_ACE, AceType=0x01)


# [MS-DTYP] sect 2.4.4.5


class WINNT_ACCESS_DENIED_OBJECT_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_OBJECT_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_DENIED_OBJECT_ACE, AceType=0x06)


# [MS-DTYP] sect 2.4.4.17.4+


class WINNT_APPLICATION_DATA_LITERAL_TOKEN(Packet):
    def default_payload_class(self, payload):
        return conf.padding_layer


# fmt: off
WINNT_APPLICATION_DATA_LITERAL_TOKEN.fields_desc = [
    ByteEnumField(
        "TokenType",
        0,
        {
            # [MS-DTYP] sect 2.4.4.17.5
            0x00: "Padding token",
            0x01: "Signed int8",
            0x02: "Signed int16",
            0x03: "Signed int32",
            0x04: "Signed int64",
            0x10: "Unicode",
            0x18: "Octet String",
            0x50: "Composite",
            0x51: "SID",
            # [MS-DTYP] sect 2.4.4.17.6
            0x80: "==",
            0x81: "!=",
            0x82: "<",
            0x83: "<=",
            0x84: ">",
            0x85: ">=",
            0x86: "Contains",
            0x88: "Any_of",
            0x8e: "Not_Contains",
            0x8f: "Not_Any_of",
            0x89: "Member_of",
            0x8a: "Device_Member_of",
            0x8b: "Member_of_Any",
            0x8c: "Device_Member_of_Any",
            0x90: "Not_Member_of",
            0x91: "Not_Device_Member_of",
            0x92: "Not_Member_of_Any",
            0x93: "Not_Device_Member_of_Any",
            # [MS-DTYP] sect 2.4.4.17.7
            0x87: "Exists",
            0x8d: "Not_Exists",
            0xa0: "&&",
            0xa1: "||",
            0xa2: "!",
            # [MS-DTYP] sect 2.4.4.17.8
            0xf8: "Local attribute",
            0xf9: "User Attribute",
            0xfa: "Resource Attribute",
            0xfb: "Device Attribute",
        }
    ),
    ConditionalField(
        # Strings
        LEIntField("length", 0),
        lambda pkt: pkt.TokenType in [
            0x10,  # Unicode string
            0x18,  # Octet string
            0xf8, 0xf9, 0xfa, 0xfb,  # Attribute tokens
            0x50,  # Composite
        ]
    ),
    ConditionalField(
        MultipleTypeField(
            [
                (
                    LELongField("value", 0),
                    lambda pkt: pkt.TokenType in [
                        0x01,  # signed int8
                        0x02,  # signed int16
                        0x03,  # signed int32
                        0x04,  # signed int64
                    ]
                ),
                (
                    StrLenFieldUtf16("value", b"", length_from=lambda pkt: pkt.length),
                    lambda pkt: pkt.TokenType in [
                        0x10,  # Unicode string
                        0xf8, 0xf9, 0xfa, 0xfb,  # Attribute tokens
                    ]
                ),
                (
                    StrLenField("value", b"", length_from=lambda pkt: pkt.length),
                    lambda pkt: pkt.TokenType == 0x18,  # Octet string
                ),
                (
                    PacketListField("value", [], WINNT_APPLICATION_DATA_LITERAL_TOKEN,
                                    length_from=lambda pkt: pkt.length),
                    lambda pkt: pkt.TokenType == 0x50,  # Composite
                ),

            ],
            StrFixedLenField("value", b"", length=0),
        ),
        lambda pkt: pkt.TokenType in [
            0x01, 0x02, 0x03, 0x04, 0x10, 0x18, 0xf8, 0xf9, 0xfa, 0xfb, 0x50
        ]
    ),
    ConditionalField(
        # Literal
        ByteEnumField("sign", 0, {
            0x01: "+",
            0x02: "-",
            0x03: "None",
        }),
        lambda pkt: pkt.TokenType in [
            0x01,  # signed int8
            0x02,  # signed int16
            0x03,  # signed int32
            0x04,  # signed int64
        ]
    ),
    ConditionalField(
        # Literal
        ByteEnumField("base", 0, {
            0x01: "Octal",
            0x02: "Decimal",
            0x03: "Hexadecimal",
        }),
        lambda pkt: pkt.TokenType in [
            0x01,  # signed int8
            0x02,  # signed int16
            0x03,  # signed int32
            0x04,  # signed int64
        ]
    ),
]
# fmt: on


class WINNT_APPLICATION_DATA(Packet):
    fields_desc = [
        StrFixedLenField("Magic", b"\x61\x72\x74\x78", length=4),
        PacketListField(
            "Tokens",
            [],
            WINNT_APPLICATION_DATA_LITERAL_TOKEN,
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-DTYP] sect 2.4.4.6


class WINNT_ACCESS_ALLOWED_CALLBACK_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc + [
        PacketField(
            "ApplicationData", WINNT_APPLICATION_DATA(), WINNT_APPLICATION_DATA
        ),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_ALLOWED_CALLBACK_ACE, AceType=0x09)


# [MS-DTYP] sect 2.4.4.7


class WINNT_ACCESS_DENIED_CALLBACK_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_CALLBACK_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_DENIED_CALLBACK_ACE, AceType=0x0A)


# [MS-DTYP] sect 2.4.4.8


class WINNT_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_OBJECT_ACE.fields_desc + [
        PacketField(
            "ApplicationData", WINNT_APPLICATION_DATA(), WINNT_APPLICATION_DATA
        ),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, AceType=0x0B)


# [MS-DTYP] sect 2.4.4.9


class WINNT_ACCESS_DENIED_CALLBACK_OBJECT_ACE(Packet):
    fields_desc = WINNT_ACCESS_DENIED_OBJECT_ACE.fields_desc + [
        PacketField(
            "ApplicationData", WINNT_APPLICATION_DATA(), WINNT_APPLICATION_DATA
        ),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_DENIED_CALLBACK_OBJECT_ACE, AceType=0x0C)


# [MS-DTYP] sect 2.4.4.10


class WINNT_SYSTEM_AUDIT_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_AUDIT_ACE, AceType=0x02)


# [MS-DTYP] sect 2.4.4.11


class WINNT_SYSTEM_AUDIT_OBJECT_ACE(Packet):
    # doc is wrong.
    fields_desc = WINNT_ACCESS_ALLOWED_OBJECT_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_AUDIT_OBJECT_ACE, AceType=0x07)


# [MS-DTYP] sect 2.4.4.12


class WINNT_SYSTEM_AUDIT_CALLBACK_ACE(Packet):
    fields_desc = WINNT_SYSTEM_AUDIT_ACE.fields_desc + [
        PacketField(
            "ApplicationData", WINNT_APPLICATION_DATA(), WINNT_APPLICATION_DATA
        ),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_AUDIT_CALLBACK_ACE, AceType=0x0D)


# [MS-DTYP] sect 2.4.4.13


class WINNT_SYSTEM_MANDATORY_LABEL_ACE(Packet):
    fields_desc = WINNT_SYSTEM_AUDIT_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_MANDATORY_LABEL_ACE, AceType=0x11)


# [MS-DTYP] sect 2.4.4.14


class WINNT_SYSTEM_AUDIT_CALLBACK_OBJECT_ACE(Packet):
    fields_desc = WINNT_SYSTEM_AUDIT_OBJECT_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, AceType=0x0F)

# [MS-DTYP] sect 2.4.10.1


class CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1(_NTLMPayloadPacket):
    _NTLM_PAYLOAD_FIELD_NAME = "Data"
    fields_desc = [
        LEIntField("NameOffset", 0),
        LEShortEnumField(
            "ValueType",
            0,
            {
                0x0001: "CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64",
                0x0002: "CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64",
                0x0003: "CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING",
                0x0005: "CLAIM_SECURITY_ATTRIBUTE_TYPE_SID",
                0x0006: "CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN",
                0x0010: "CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING",
            },
        ),
        LEShortField("Reserved", 0),
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x0001: "CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE",
                0x0002: "CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE",
                0x0004: "CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY",
                0x0008: "CLAIM_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT",
                0x0010: "CLAIM_SECURITY_ATTRIBUTE_DISABLED",
                0x0020: "CLAIM_SECURITY_ATTRIBUTE_MANDATORY",
            },
        ),
        LEIntField("ValueCount", 0),
        FieldListField(
            "ValueOffsets", [], LEIntField("", 0), count_from=lambda pkt: pkt.ValueCount
        ),
        _NTLMPayloadField(
            "Data",
            lambda pkt: 16 + pkt.ValueCount * 4,
            [
                ConditionalField(
                    StrFieldUtf16("Name", b""),
                    lambda pkt: pkt.NameOffset,
                ),
                # TODO: Values
            ],
            offset_name="Offset",
        ),
    ]


# [MS-DTYP] sect 2.4.4.15


class WINNT_SYSTEM_RESOURCE_ATTRIBUTE_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc + [
        PacketField(
            "AttributeData",
            CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1(),
            CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1,
        )
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_RESOURCE_ATTRIBUTE_ACE, AceType=0x12)

# [MS-DTYP] sect 2.4.4.16


class WINNT_SYSTEM_SCOPED_POLICY_ID_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_SCOPED_POLICY_ID_ACE, AceType=0x13)

# [MS-DTYP] sect 2.4.5


class WINNT_ACL(Packet):
    fields_desc = [
        ByteField("AclRevision", 2),
        ByteField("Sbz1", 0x00),
        # Total size including header:
        # AclRevision(1) + Sbz1(1) + AclSize(2) + AceCount(2) + Sbz2(2)
        FieldLenField(
            "AclSize",
            None,
            length_of="Aces",
            adjust=lambda _, x: x + 8,
            fmt="<H",
        ),
        FieldLenField("AceCount", None, count_of="Aces", fmt="<H"),
        ShortField("Sbz2", 0),
        PacketListField(
            "Aces",
            [],
            WINNT_ACE_HEADER,
            count_from=lambda pkt: pkt.AceCount,
        ),
    ]

    def toSDDL(self):
        return [x.toSDDL() for x in self.Aces]


# [MS-DTYP] 2.4.6 SECURITY_DESCRIPTOR


class SECURITY_DESCRIPTOR(_NTLMPayloadPacket):
    OFFSET = 20
    _NTLM_PAYLOAD_FIELD_NAME = "Data"
    fields_desc = [
        ByteField("Revision", 0x01),
        ByteField("Sbz1", 0x00),
        FlagsField(
            "Control",
            0x00,
            -16,
            [
                "OWNER_DEFAULTED",
                "GROUP_DEFAULTED",
                "DACL_PRESENT",
                "DACL_DEFAULTED",
                "SACL_PRESENT",
                "SACL_DEFAULTED",
                "DACL_TRUSTED",
                "SERVER_SECURITY",
                "DACL_COMPUTED",
                "SACL_COMPUTED",
                "DACL_AUTO_INHERITED",
                "SACL_AUTO_INHERITED",
                "DACL_PROTECTED",
                "SACL_PROTECTED",
                "RM_CONTROL_VALID",
                "SELF_RELATIVE",
            ],
        ),
        LEIntField("OwnerSidOffset", None),
        LEIntField("GroupSidOffset", None),
        LEIntField("SACLOffset", None),
        LEIntField("DACLOffset", None),
        _NTLMPayloadField(
            "Data",
            OFFSET,
            [
                ConditionalField(
                    PacketField("OwnerSid", WINNT_SID(), WINNT_SID),
                    lambda pkt: pkt.OwnerSidOffset != 0,
                ),
                ConditionalField(
                    PacketField("GroupSid", WINNT_SID(), WINNT_SID),
                    lambda pkt: pkt.GroupSidOffset != 0,
                ),
                ConditionalField(
                    PacketField("SACL", WINNT_ACL(), WINNT_ACL),
                    lambda pkt: pkt.Control.SACL_PRESENT,
                ),
                ConditionalField(
                    PacketField("DACL", WINNT_ACL(), WINNT_ACL),
                    lambda pkt: pkt.Control.DACL_PRESENT,
                ),
            ],
            offset_name="Offset",
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _NTLM_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "OwnerSid": 4,
                    "GroupSid": 8,
                    "SACL": 12,
                    "DACL": 16,
                },
                config=[
                    ("Offset", _NTLM_ENUM.OFFSET),
                ],
            )
            + pay
        )
