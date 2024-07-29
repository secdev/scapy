# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter

"""
SMB 1.0 (Server Message Block), also known as CIFS.

.. note::
    You will find more complete documentation for this layer over at
    `SMB <https://scapy.readthedocs.io/en/latest/layers/smb.html>`_

Specs:

- [MS-CIFS] (base)
- [MS-SMB] (extension of CIFS - SMB v1)
"""

import struct

from scapy.config import conf
from scapy.packet import Packet, bind_layers, bind_top_down
from scapy.fields import (
    ByteEnumField,
    ByteField,
    ConditionalField,
    FieldLenField,
    FieldListField,
    FlagsField,
    IPField,
    LEFieldLenField,
    LEIntEnumField,
    LEIntField,
    LELongField,
    LEShortEnumField,
    LEShortField,
    MultipleTypeField,
    PacketField,
    PacketLenField,
    PacketListField,
    ReversePadField,
    ScalingField,
    ShortField,
    StrFixedLenField,
    StrNullField,
    StrNullFieldUtf16,
    UTCTimeField,
    UUIDField,
    XLEShortField,
    XStrLenField,
)

from scapy.layers.dns import (
    DNSStrField,
    DNSCompressedPacket,
)
from scapy.layers.ntlm import (
    _NTLMPayloadPacket,
    _NTLMPayloadField,
    _NTLM_ENUM,
    _NTLM_post_build,
)
from scapy.layers.netbios import NBTSession, NBTDatagram
from scapy.layers.gssapi import (
    GSSAPI_BLOB,
)
from scapy.layers.smb2 import (
    STATUS_ERREF,
    SMB2_Header,
)


SMB_COM = {
    0x00: "SMB_COM_CREATE_DIRECTORY",
    0x01: "SMB_COM_DELETE_DIRECTORY",
    0x02: "SMB_COM_OPEN",
    0x03: "SMB_COM_CREATE",
    0x04: "SMB_COM_CLOSE",
    0x05: "SMB_COM_FLUSH",
    0x06: "SMB_COM_DELETE",
    0x07: "SMB_COM_RENAME",
    0x08: "SMB_COM_QUERY_INFORMATION",
    0x09: "SMB_COM_SET_INFORMATION",
    0x0A: "SMB_COM_READ",
    0x0B: "SMB_COM_WRITE",
    0x0C: "SMB_COM_LOCK_BYTE_RANGE",
    0x0D: "SMB_COM_UNLOCK_BYTE_RANGE",
    0x0E: "SMB_COM_CREATE_TEMPORARY",
    0x0F: "SMB_COM_CREATE_NEW",
    0x10: "SMB_COM_CHECK_DIRECTORY",
    0x11: "SMB_COM_PROCESS_EXIT",
    0x12: "SMB_COM_SEEK",
    0x13: "SMB_COM_LOCK_AND_READ",
    0x14: "SMB_COM_WRITE_AND_UNLOCK",
    0x1A: "SMB_COM_READ_RAW",
    0x1B: "SMB_COM_READ_MPX",
    0x1C: "SMB_COM_READ_MPX_SECONDARY",
    0x1D: "SMB_COM_WRITE_RAW",
    0x1E: "SMB_COM_WRITE_MPX",
    0x1F: "SMB_COM_WRITE_MPX_SECONDARY",
    0x20: "SMB_COM_WRITE_COMPLETE",
    0x21: "SMB_COM_QUERY_SERVER",
    0x22: "SMB_COM_SET_INFORMATION2",
    0x23: "SMB_COM_QUERY_INFORMATION2",
    0x24: "SMB_COM_LOCKING_ANDX",
    0x25: "SMB_COM_TRANSACTION",
    0x26: "SMB_COM_TRANSACTION_SECONDARY",
    0x27: "SMB_COM_IOCTL",
    0x28: "SMB_COM_IOCTL_SECONDARY",
    0x29: "SMB_COM_COPY",
    0x2A: "SMB_COM_MOVE",
    0x2B: "SMB_COM_ECHO",
    0x2C: "SMB_COM_WRITE_AND_CLOSE",
    0x2D: "SMB_COM_OPEN_ANDX",
    0x2E: "SMB_COM_READ_ANDX",
    0x2F: "SMB_COM_WRITE_ANDX",
    0x30: "SMB_COM_NEW_FILE_SIZE",
    0x31: "SMB_COM_CLOSE_AND_TREE_DISC",
    0x32: "SMB_COM_TRANSACTION2",
    0x33: "SMB_COM_TRANSACTION2_SECONDARY",
    0x34: "SMB_COM_FIND_CLOSE2",
    0x35: "SMB_COM_FIND_NOTIFY_CLOSE",
    0x70: "SMB_COM_TREE_CONNECT",
    0x71: "SMB_COM_TREE_DISCONNECT",
    0x72: "SMB_COM_NEGOTIATE",
    0x73: "SMB_COM_SESSION_SETUP_ANDX",
    0x74: "SMB_COM_LOGOFF_ANDX",
    0x75: "SMB_COM_TREE_CONNECT_ANDX",
    0x7E: "SMB_COM_SECURITY_PACKAGE_ANDX",
    0x80: "SMB_COM_QUERY_INFORMATION_DISK",
    0x81: "SMB_COM_SEARCH",
    0x82: "SMB_COM_FIND",
    0x83: "SMB_COM_FIND_UNIQUE",
    0x84: "SMB_COM_FIND_CLOSE",
    0xA0: "SMB_COM_NT_TRANSACT",
    0xA1: "SMB_COM_NT_TRANSACT_SECONDARY",
    0xA2: "SMB_COM_NT_CREATE_ANDX",
    0xA4: "SMB_COM_NT_CANCEL",
    0xA5: "SMB_COM_NT_RENAME",
    0xC0: "SMB_COM_OPEN_PRINT_FILE",
    0xC1: "SMB_COM_WRITE_PRINT_FILE",
    0xC2: "SMB_COM_CLOSE_PRINT_FILE",
    0xC3: "SMB_COM_GET_PRINT_QUEUE",
    0xD8: "SMB_COM_READ_BULK",
    0xD9: "SMB_COM_WRITE_BULK",
    0xDA: "SMB_COM_WRITE_BULK_DATA",
    0xFE: "SMB_COM_INVALID",
    0xFF: "SMB_COM_NO_ANDX_COMMAND",
}


class SMB_Header(Packet):
    name = "SMB 1 Protocol Request Header"
    fields_desc = [
        StrFixedLenField("Start", b"\xffSMB", 4),
        ByteEnumField("Command", 0x72, SMB_COM),
        LEIntEnumField("Status", 0, STATUS_ERREF),
        FlagsField(
            "Flags",
            0x18,
            8,
            [
                "LOCK_AND_READ_OK",
                "BUF_AVAIL",
                "res",
                "CASE_INSENSITIVE",
                "CANONICALIZED_PATHS",
                "OPLOCK",
                "OPBATCH",
                "REPLY",
            ],
        ),
        FlagsField(
            "Flags2",
            0x0000,
            -16,
            [
                "LONG_NAMES",
                "EAS",
                "SMB_SECURITY_SIGNATURE",
                "COMPRESSED",
                "SMB_SECURITY_SIGNATURE_REQUIRED",
                "res",
                "IS_LONG_NAME",
                "res",
                "res",
                "res",
                "REPARSE_PATH",
                "EXTENDED_SECURITY",
                "DFS",
                "PAGING_IO",
                "NT_STATUS",
                "UNICODE",
            ],
        ),
        LEShortField("PIDHigh", 0x0000),
        StrFixedLenField("SecuritySignature", b"", length=8),
        LEShortField("Reserved", 0x0),
        LEShortField("TID", 0),
        LEShortField("PIDLow", 0),
        LEShortField("UID", 0),
        LEShortField("MID", 0),
    ]

    def guess_payload_class(self, payload):
        # type: (bytes) -> Packet
        if not payload:
            return super(SMB_Header, self).guess_payload_class(payload)
        WordCount = ord(payload[:1])
        if self.Command == 0x72:
            if self.Flags.REPLY:
                if self.Flags2.EXTENDED_SECURITY:
                    return SMBNegotiate_Response_Extended_Security
                else:
                    return SMBNegotiate_Response_Security
            else:
                return SMBNegotiate_Request
        elif self.Command == 0x73:
            if WordCount == 0:
                return SMBSession_Null
            if self.Flags.REPLY:
                if WordCount == 0x04:
                    return SMBSession_Setup_AndX_Response_Extended_Security
                elif WordCount == 0x03:
                    return SMBSession_Setup_AndX_Response
                if self.Flags2.EXTENDED_SECURITY:
                    return SMBSession_Setup_AndX_Response_Extended_Security
                else:
                    return SMBSession_Setup_AndX_Response
            else:
                if WordCount == 0x0C:
                    return SMBSession_Setup_AndX_Request_Extended_Security
                elif WordCount == 0x0D:
                    return SMBSession_Setup_AndX_Request
                if self.Flags2.EXTENDED_SECURITY:
                    return SMBSession_Setup_AndX_Request_Extended_Security
                else:
                    return SMBSession_Setup_AndX_Request
        elif self.Command == 0x25:
            if self.Flags.REPLY:
                if WordCount == 0x11:
                    return SMBMailslot_Write
                else:
                    return SMBTransaction_Response
            else:
                if WordCount == 0x11:
                    return SMBMailslot_Write
                else:
                    return SMBTransaction_Request
        return super(SMB_Header, self).guess_payload_class(payload)

    def answers(self, pkt):
        return SMB_Header in pkt


# SMB Negotiate Request


class SMB_Dialect(Packet):
    name = "SMB Dialect"
    fields_desc = [
        ByteField("BufferFormat", 0x02),
        StrNullField("DialectString", "NT LM 0.12"),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class SMBNegotiate_Request(Packet):
    name = "SMB Negotiate Request"
    fields_desc = [
        ByteField("WordCount", 0),
        LEFieldLenField("ByteCount", None, length_of="Dialects"),
        PacketListField(
            "Dialects",
            [SMB_Dialect()],
            SMB_Dialect,
            length_from=lambda pkt: pkt.ByteCount,
        ),
    ]


bind_layers(SMB_Header, SMBNegotiate_Request, Command=0x72)

# SMBNegociate Protocol Response


def _SMBStrNullField(name, default):
    """
    Returns a StrNullField that is either normal or UTF-16 depending
    on the SMB headers.
    """

    def _isUTF16(pkt):
        while not hasattr(pkt, "Flags2") and pkt.underlayer:
            pkt = pkt.underlayer
        return hasattr(pkt, "Flags2") and pkt.Flags2.UNICODE

    return MultipleTypeField(
        [(StrNullFieldUtf16(name, default), _isUTF16)],
        StrNullField(name, default),
    )


def _len(pkt, name):
    """
    Returns the length of a field, works with Unicode strings.
    """
    fld, v = pkt.getfield_and_val(name)
    return len(fld.addfield(pkt, v, b""))


class _SMBNegotiate_Response(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            # Yes this is inspired by
            # https://github.com/wireshark/wireshark/blob/925e01b23fd5aad2fa929fafd894128a88832e74/epan/dissectors/packet-smb.c#L2902
            wc = struct.unpack("<H", _pkt[:1])
            # dialect = struct.unpack("<H", _pkt[1:3])
            if wc == 1:
                # Core Protocol
                return SMBNegotiate_Response_NoSecurity
            elif wc == 0xD:
                # LAN Manager 1.0 - LAN Manager 2.1
                # TODO
                pass
            elif wc == 0x11:
                # NT LAN Manager
                return cls
        return cls


_SMB_ServerCapabilities = [
    "RAW_MODE",
    "MPX_MODE",
    "UNICODE",
    "LARGE_FILES",
    "NT_SMBS",
    "RPC_REMOTE_APIS",
    "STATUS32",
    "LEVEL_II_OPLOCKS",
    "LOCK_AND_READ",
    "NT_FIND",
    "res",
    "res",
    "DFS",
    "INFOLEVEL_PASSTHRU",
    "LARGE_READX",
    "LARGE_WRITEX",
    "LWIO",
    "res",
    "res",
    "res",
    "res",
    "res",
    "res",
    "UNIX",
    "res",
    "COMPRESSED_DATA",
    "res",
    "res",
    "res",
    "DYNAMIC_REAUTH",
    "PERSISTENT_HANDLES",
    "EXTENDED_SECURITY",
]


# CIFS sect 2.2.4.52.2


class SMBNegotiate_Response_NoSecurity(_SMBNegotiate_Response):
    name = "SMB Negotiate No-Security Response (CIFS)"
    fields_desc = [
        ByteField("WordCount", 0x1),
        LEShortField("DialectIndex", 7),
        FlagsField(
            "SecurityMode",
            0x03,
            8,
            [
                "USER_SECURITY",
                "ENCRYPT_PASSWORDS",
                "SECURITY_SIGNATURES_ENABLED",
                "SECURITY_SIGNATURES_REQUIRED",
            ],
        ),
        LEShortField("MaxMpxCount", 50),
        LEShortField("MaxNumberVC", 1),
        LEIntField("MaxBufferSize", 16144),  # Windows: 4356
        LEIntField("MaxRawSize", 65536),
        LEIntField("SessionKey", 0x0000),
        FlagsField("ServerCapabilities", 0xF3F9, -32, _SMB_ServerCapabilities),
        UTCTimeField(
            "ServerTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        ScalingField("ServerTimeZone", 0x3C, fmt="<h", unit="min-UTC"),
        FieldLenField(
            "ChallengeLength",
            None,
            # aka EncryptionKeyLength
            length_of="Challenge",
            fmt="<B",
        ),
        LEFieldLenField(
            "ByteCount",
            None,
            length_of="DomainName",
            adjust=lambda pkt, x: x + len(pkt.Challenge),
        ),
        XStrLenField(
            "Challenge",
            b"",  # aka EncryptionKey
            length_from=lambda pkt: pkt.ChallengeLength,
        ),
        StrNullField("DomainName", "WORKGROUP"),
    ]


bind_top_down(SMB_Header, SMBNegotiate_Response_NoSecurity, Command=0x72, Flags=0x80)

# SMB sect 2.2.4.5.2.1


class SMBNegotiate_Response_Extended_Security(_SMBNegotiate_Response):
    name = "SMB Negotiate Extended Security Response (SMB)"
    WordCount = 0x11
    fields_desc = SMBNegotiate_Response_NoSecurity.fields_desc[:12] + [
        LEFieldLenField(
            "ByteCount", None, length_of="SecurityBlob", adjust=lambda _, x: x + 16
        ),
        SMBNegotiate_Response_NoSecurity.fields_desc[13],
        UUIDField("GUID", None, uuid_fmt=UUIDField.FORMAT_LE),
        PacketLenField(
            "SecurityBlob", None, GSSAPI_BLOB, length_from=lambda x: x.ByteCount - 16
        ),
    ]


bind_top_down(
    SMB_Header,
    SMBNegotiate_Response_Extended_Security,
    Command=0x72,
    Flags=0x80,
    Flags2=0x800,
)

# SMB sect 2.2.4.5.2.2


class SMBNegotiate_Response_Security(_SMBNegotiate_Response):
    name = "SMB Negotiate Non-Extended Security Response (SMB)"
    WordCount = 0x11
    fields_desc = SMBNegotiate_Response_NoSecurity.fields_desc[:12] + [
        LEFieldLenField(
            "ByteCount",
            None,
            length_of="DomainName",
            adjust=lambda pkt, x: x
            + 2
            + _len(pkt, "Challenge")
            + _len(pkt, "ServerName"),
        ),
        XStrLenField(
            "Challenge",
            b"",  # aka EncryptionKey
            length_from=lambda pkt: pkt.ChallengeLength,
        ),
        _SMBStrNullField("DomainName", "WORKGROUP"),
        _SMBStrNullField("ServerName", "RMFF1"),
    ]


bind_top_down(SMB_Header, SMBNegotiate_Response_Security, Command=0x72, Flags=0x80)

# Session Setup AndX Request

# CIFS sect 2.2.4.53


class SMBSession_Setup_AndX_Request(Packet):
    name = "Session Setup AndX Request (CIFS)"
    fields_desc = [
        ByteField("WordCount", 0x0D),
        ByteEnumField("AndXCommand", 0xFF, SMB_COM),
        ByteField("AndXReserved", 0),
        LEShortField("AndXOffset", None),
        LEShortField("MaxBufferSize", 16144),  # Windows: 4356
        LEShortField("MaxMPXCount", 50),
        LEShortField("VCNumber", 0),
        LEIntField("SessionKey", 0),
        LEFieldLenField("OEMPasswordLength", None, length_of="OEMPassword"),
        LEFieldLenField("UnicodePasswordLength", None, length_of="UnicodePassword"),
        LEIntField("Reserved", 0),
        FlagsField("ServerCapabilities", 0x05, -32, _SMB_ServerCapabilities),
        LEShortField("ByteCount", None),
        XStrLenField("OEMPassword", "Pass", length_from=lambda x: x.OEMPasswordLength),
        XStrLenField(
            "UnicodePassword", "Pass", length_from=lambda x: x.UnicodePasswordLength
        ),
        ReversePadField(_SMBStrNullField("AccountName", "GUEST"), 2, b"\0"),
        _SMBStrNullField("PrimaryDomain", ""),
        _SMBStrNullField("NativeOS", "Windows 4.0"),
        _SMBStrNullField("NativeLanMan", "Windows 4.0"),
    ]

    def post_build(self, pkt, pay):
        if self.AndXOffset is None and self.AndXCommand != 0xFF:
            pkt = pkt[:3] + struct.pack("<H", len(pkt) + 32) + pkt[5:]
        if self.ByteCount is None:
            pkt = pkt[:27] + struct.pack("<H", len(pkt) - 29) + pkt[29:]
        if self.payload and hasattr(self.payload, "AndXOffset") and pay:
            pay = pay[:3] + struct.pack("<H", len(pkt) + len(pay) + 32) + pay[5:]
        return pkt + pay


bind_top_down(SMB_Header, SMBSession_Setup_AndX_Request, Command=0x73)

# SMB sect 2.2.4.7


class SMBTree_Connect_AndX(Packet):
    name = "Session Tree Connect AndX"
    WordCount = 0x04
    fields_desc = SMBSession_Setup_AndX_Request.fields_desc[:4] + [
        FlagsField(
            "Flags",
            "",
            -16,
            ["DISCONNECT_TID", "r2", "EXTENDED_SIGNATURES", "EXTENDED_RESPONSE"],
        ),
        FieldLenField("PasswordLength", None, length_of="Password", fmt="<H"),
        LEShortField("ByteCount", None),
        XStrLenField("Password", b"", length_from=lambda pkt: pkt.PasswordLength),
        ReversePadField(_SMBStrNullField("Path", "\\\\WIN2K\\IPC$"), 2),
        StrNullField("Service", "?????"),
    ]

    def post_build(self, pkt, pay):
        pkt += pay
        if self.ByteCount is None:
            pkt = pkt[:9] + struct.pack("<H", len(pkt) - 11) + pkt[11:]
        return pkt


bind_layers(SMB_Header, SMBTree_Connect_AndX, Command=0x75)
bind_layers(SMBSession_Setup_AndX_Request, SMBTree_Connect_AndX, AndXCommand=0x75)

# SMB sect 2.2.4.6.1


class SMBSession_Setup_AndX_Request_Extended_Security(Packet):
    name = "Session Setup AndX Extended Security Request (SMB)"
    WordCount = 0x0C
    fields_desc = (
        SMBSession_Setup_AndX_Request.fields_desc[:8]
        + [
            LEFieldLenField("SecurityBlobLength", None, length_of="SecurityBlob"),
        ]
        + SMBSession_Setup_AndX_Request.fields_desc[10:12]
        + [
            LEShortField("ByteCount", None),
            PacketLenField(
                "SecurityBlob",
                None,
                GSSAPI_BLOB,
                length_from=lambda x: x.SecurityBlobLength,
            ),
            ReversePadField(
                _SMBStrNullField("NativeOS", "Windows 4.0"),
                2,
                b"\0",
            ),
            _SMBStrNullField("NativeLanMan", "Windows 4.0"),
        ]
    )

    def post_build(self, pkt, pay):
        if self.ByteCount is None:
            pkt = pkt[:25] + struct.pack("<H", len(pkt) - 27) + pkt[27:]
        return pkt + pay


bind_top_down(
    SMB_Header,
    SMBSession_Setup_AndX_Request_Extended_Security,
    Command=0x73,
    Flags2=0x800,
)

# Session Setup AndX Response


# CIFS sect 2.2.4.53.2


class SMBSession_Setup_AndX_Response(Packet):
    name = "Session Setup AndX Response (CIFS)"
    fields_desc = [
        ByteField("WordCount", 0x3),
        ByteEnumField("AndXCommand", 0xFF, SMB_COM),
        ByteField("AndXReserved", 0),
        LEShortField("AndXOffset", None),
        FlagsField(
            "Action",
            0,
            -16,
            {
                0x0001: "SMB_SETUP_GUEST",
                0x0002: "SMB_SETUP_USE_LANMAN_KEY",
            },
        ),
        LEShortField("ByteCount", 25),
        _SMBStrNullField("NativeOS", "Windows 4.0"),
        _SMBStrNullField("NativeLanMan", "Windows 4.0"),
        _SMBStrNullField("PrimaryDomain", ""),
        # Off spec?
        ByteField("WordCount2", 3),
        ByteEnumField("AndXCommand2", 0xFF, SMB_COM),
        ByteField("Reserved3", 0),
        LEShortField("AndXOffset2", 80),
        LEShortField("OptionalSupport", 0x01),
        LEShortField("ByteCount2", 5),
        StrNullField("Service", "IPC"),
        StrNullField("NativeFileSystem", ""),
    ]

    def post_build(self, pkt, pay):
        if self.AndXOffset is None:
            pkt = pkt[:3] + struct.pack("<H", len(pkt) + 32) + pkt[5:]
        return pkt + pay


bind_top_down(SMB_Header, SMBSession_Setup_AndX_Response, Command=0x73, Flags=0x80)

# SMB sect 2.2.4.6.2


class SMBSession_Setup_AndX_Response_Extended_Security(
    SMBSession_Setup_AndX_Response
):  # noqa: E501
    name = "Session Setup AndX Extended Security Response (SMB)"
    WordCount = 0x4
    fields_desc = (
        SMBSession_Setup_AndX_Response.fields_desc[:5]
        + [SMBSession_Setup_AndX_Request_Extended_Security.fields_desc[8]]
        + SMBSession_Setup_AndX_Request_Extended_Security.fields_desc[11:]
    )

    def post_build(self, pkt, pay):
        if self.ByteCount is None:
            pkt = pkt[:9] + struct.pack("<H", len(pkt) - 11) + pkt[11:]
        return super(SMBSession_Setup_AndX_Response_Extended_Security, self).post_build(
            pkt, pay
        )


bind_top_down(
    SMB_Header,
    SMBSession_Setup_AndX_Response_Extended_Security,
    Command=0x73,
    Flags=0x80,
    Flags2=0x800,
)

# SMB null (no wordcount)


class SMBSession_Null(Packet):
    fields_desc = [ByteField("WordCount", 0), LEShortField("ByteCount", 0)]


bind_top_down(SMB_Header, SMBSession_Null, Command=0x73)

# [MS-CIFS] sect 2.2.4.33.1

_SMB_CONFIG = [
    ("Len", _NTLM_ENUM.LEN),
    ("BufferOffset", _NTLM_ENUM.OFFSET),
]


class _SMB_TransactionRequest_Data(PacketLenField):
    def m2i(self, pkt, m):
        if pkt.Name == b"\\MAILSLOT\\NET\\NETLOGON":
            return NETLOGON(m)
        elif pkt.Name == b"\\MAILSLOT\\BROWSE" or pkt.name == b"\\MAILSLOT\\LANMAN":
            return BRWS(m)
        return conf.raw_layer(m)


def _optlen(pkt, x):
    try:
        return len(getattr(pkt, x))
    except AttributeError:
        return 0


class SMBTransaction_Request(_NTLMPayloadPacket):
    name = "SMB COM Transaction Request"
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"

    fields_desc = [
        FieldLenField(
            "WordCount",
            None,
            length_of="SetupCount",
            adjust=lambda pkt, x: x + 0x0E,
            fmt="B",
        ),
        FieldLenField(
            "TotalParamCount",
            None,
            length_of="Buffer",
            fmt="<H",
            adjust=lambda pkt, _: _optlen(pkt, "Parameter"),
        ),
        FieldLenField(
            "TotalDataCount",
            None,
            length_of="Buffer",
            fmt="<H",
            adjust=lambda pkt, _: _optlen(pkt, "Data"),
        ),
        LEShortField("MaxParamCount", 0),
        LEShortField("MaxDataCount", 0),
        ByteField("MaxSetupCount", 0),
        ByteField("Reserved1", 0),
        FlagsField("Flags", 0, -16, {0x1: "DISCONNECT_TID", 0x2: "NO_RESPONSE"}),
        LEIntField("Timeout", 1000),
        ShortField("Reserved2", 0),
        LEShortField("ParameterLen", None),
        LEShortField("ParameterBufferOffset", None),
        LEShortField("DataLen", None),
        LEShortField("DataBufferOffset", None),
        FieldLenField("SetupCount", 3, count_of="Setup", fmt="B"),
        ByteField("Reserved3", 0),
        FieldListField(
            "Setup",
            [1, 1, 2],
            LEShortField("", 0),
            count_from=lambda pkt: pkt.SetupCount,
        ),
        # SMB Data
        FieldLenField(
            "ByteCount",
            None,
            length_of="Name",
            fmt="<H",
            adjust=lambda pkt, x: x + _optlen(pkt, "Parameter") + _optlen(pkt, "Data"),
        ),
        StrNullField("Name", "\\MAILSLOT\\NET\\NETLOGON"),
        _NTLMPayloadField(
            "Buffer",
            lambda pkt: 32 + 31 + len(pkt.Setup) * 2 + len(pkt.Name) + 1,
            [
                XStrLenField(
                    "Parameter", b"", length_from=lambda pkt: pkt.ParameterLen
                ),
                _SMB_TransactionRequest_Data(
                    "Data", None, conf.raw_layer, length_from=lambda pkt: pkt.DataLen
                ),
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _NTLM_post_build(
                self,
                pkt,
                32 + 31 + len(self.Setup) * 2 + len(self.Name) + 1,
                {
                    "Parameter": 19,
                    "Data": 23,
                },
                config=_SMB_CONFIG,
            )
            + pay
        )

    def mysummary(self):
        if getattr(self, "Data", None) is not None:
            return self.sprintf("Tran %Name% ") + self.Data.mysummary()
        return self.sprintf("Tran %Name%")


bind_top_down(SMB_Header, SMBTransaction_Request, Command=0x25)


class SMBMailslot_Write(SMBTransaction_Request):
    WordCount = 0x11


# [MS-CIFS] sect 2.2.4.33.2


class SMBTransaction_Response(_NTLMPayloadPacket):
    name = "SMB COM Transaction Response"
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        FieldLenField(
            "WordCount",
            None,
            length_of="SetupCount",
            adjust=lambda pkt, x: x + 0x0A,
            fmt="B",
        ),
        FieldLenField(
            "TotalParamCount",
            None,
            length_of="Buffer",
            fmt="<H",
            adjust=lambda pkt, _: _optlen(pkt, "Parameter"),
        ),
        FieldLenField(
            "TotalDataCount",
            None,
            length_of="Buffer",
            fmt="<H",
            adjust=lambda pkt, _: _optlen(pkt, "Data"),
        ),
        LEShortField("Reserved1", None),
        LEShortField("ParameterLen", None),
        LEShortField("ParameterBufferOffset", None),
        LEShortField("ParameterDisplacement", 0),
        LEShortField("DataLen", None),
        LEShortField("DataBufferOffset", None),
        LEShortField("DataDisplacement", 0),
        FieldLenField("SetupCount", 3, count_of="Setup", fmt="B"),
        ByteField("Reserved2", 0),
        FieldListField(
            "Setup",
            [1, 1, 2],
            LEShortField("", 0),
            count_from=lambda pkt: pkt.SetupCount,
        ),
        # SMB Data
        FieldLenField(
            "ByteCount",
            None,
            length_of="Buffer",
            fmt="<H",
            adjust=lambda pkt, x: _optlen(pkt, "Parameter") + _optlen(pkt, "Data"),
        ),
        _NTLMPayloadField(
            "Buffer",
            lambda pkt: 32 + 22 + len(pkt.Setup) * 2,
            [
                XStrLenField(
                    "Parameter", b"", length_from=lambda pkt: pkt.ParameterLen
                ),
                XStrLenField("Data", b"", length_from=lambda pkt: pkt.DataLen),
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _NTLM_post_build(
                self,
                pkt,
                32 + 22 + len(self.Setup) * 2,
                {
                    "Parameter": 7,
                    "Data": 13,
                },
                config=_SMB_CONFIG,
            )
            + pay
        )


bind_top_down(SMB_Header, SMBTransaction_Response, Command=0x25, Flags=0x80)


# [MS-ADTS] sect 6.3.1.4

_NETLOGON_opcodes = {
    0x7: "LOGON_PRIMARY_QUERY",
    0x12: "LOGON_SAM_LOGON_REQUEST",
    0x13: "LOGON_SAM_LOGON_RESPONSE",
    0x15: "LOGON_SAM_USER_UNKNOWN",
    0x17: "LOGON_SAM_LOGON_RESPONSE_EX",
    0x19: "LOGON_SAM_USER_UNKNOWN_EX",
}

_NV_VERSION = {
    0x00000001: "V1",
    0x00000002: "V5",
    0x00000004: "V5EX",
    0x00000008: "V5EX_WITH_IP",
    0x00000010: "V5EX_WITH_CLOSEST_SITE",
    0x01000000: "AVOID_NT4EMUL",
    0x10000000: "PDC",
    0x20000000: "IP",
    0x40000000: "LOCAL",
    0x80000000: "GC",
}


class NETLOGON(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            if _pkt[0] == 0x07:  # LOGON_PRIMARY_QUERY
                return NETLOGON_LOGON_QUERY
            elif _pkt[0] == 0x12:  # LOGON_SAM_LOGON_REQUEST
                return NETLOGON_SAM_LOGON_REQUEST
            elif _pkt[0] == 0x13:  # LOGON_SAM_USER_RESPONSE
                try:
                    i = _pkt.index(b"\xff\xff\xff\xff")
                    NtVersion = (
                        NETLOGON_SAM_LOGON_RESPONSE_NT40.fields_desc[-3].getfield(
                            None, _pkt[i - 4:i]
                        )[1]
                    )
                    if NtVersion.V1 and not NtVersion.V5:
                        return NETLOGON_SAM_LOGON_RESPONSE_NT40
                except Exception:
                    pass
                return NETLOGON_SAM_LOGON_RESPONSE
            elif _pkt[0] == 0x15:  # LOGON_SAM_USER_UNKNOWN
                return NETLOGON_SAM_LOGON_RESPONSE
            elif _pkt[0] == 0x17:  # LOGON_SAM_LOGON_RESPONSE_EX
                return NETLOGON_SAM_LOGON_RESPONSE_EX
            elif _pkt[0] == 0x19:  # LOGON_SAM_USER_UNKNOWN_EX
                return NETLOGON_SAM_LOGON_RESPONSE
        return cls


class NETLOGON_LOGON_QUERY(NETLOGON):
    fields_desc = [
        LEShortEnumField("OpCode", 0x7, _NETLOGON_opcodes),
        StrNullField("ComputerName", ""),
        StrNullField("MailslotName", ""),
        StrNullFieldUtf16("UnicodeComputerName", ""),
        FlagsField("NtVersion", 0xB, -32, _NV_VERSION),
        XLEShortField("LmNtToken", 0xFFFF),
        XLEShortField("Lm20Token", 0xFFFF),
    ]


# [MS-ADTS] sect 6.3.1.6


class NETLOGON_SAM_LOGON_REQUEST(NETLOGON):
    fields_desc = [
        LEShortEnumField("OpCode", 0x12, _NETLOGON_opcodes),
        LEShortField("RequestCount", 0),
        StrNullFieldUtf16("UnicodeComputerName", ""),
        StrNullFieldUtf16("UnicodeUserName", ""),
        StrNullField("MailslotName", "\\MAILSLOT\\NET\\GETDC701253F9"),
        LEIntField("AllowableAccountControlBits", 0),
        FieldLenField("DomainSidSize", None, fmt="<I", length_of="DomainSid"),
        XStrLenField("DomainSid", b"", length_from=lambda pkt: pkt.DomainSidSize),
        FlagsField("NtVersion", 0xB, -32, _NV_VERSION),
        XLEShortField("LmNtToken", 0xFFFF),
        XLEShortField("Lm20Token", 0xFFFF),
    ]


# [MS-ADTS] sect 6.3.1.7


class NETLOGON_SAM_LOGON_RESPONSE_NT40(NETLOGON):
    fields_desc = [
        LEShortEnumField("OpCode", 0x13, _NETLOGON_opcodes),
        StrNullFieldUtf16("UnicodeLogonServer", ""),
        StrNullFieldUtf16("UnicodeUserName", ""),
        StrNullFieldUtf16("UnicodeDomainName", ""),
        FlagsField("NtVersion", 0x1, -32, _NV_VERSION),
        XLEShortField("LmNtToken", 0xFFFF),
        XLEShortField("Lm20Token", 0xFFFF),
    ]


# [MS-ADTS] sect 6.3.1.2


_NETLOGON_FLAGS = {
    0x00000001: "PDC",
    0x00000004: "GC",
    0x00000008: "LDAP",
    0x00000010: "DC",
    0x00000020: "KDC",
    0x00000040: "TIMESERV",
    0x00000080: "CLOSEST",
    0x00000100: "RODC",
    0x00000200: "GOOD_TIMESERV",
    0x00000400: "NC",
    0x00000800: "SELECT_SECRET_DOMAIN_6",
    0x00001000: "FULL_SECRET_DOMAIN_6",
    0x00002000: "WS",
    0x00004000: "DS_8",
    0x00008000: "DS_9",
    0x00010000: "DS_10",  # guess
    0x00020000: "DS_11",  # guess
    0x20000000: "DNS_CONTROLLER",
    0x40000000: "DNS_DOMAIN",
    0x80000000: "DNS_FOREST",
}


# [MS-ADTS] sect 6.3.1.8

class NETLOGON_SAM_LOGON_RESPONSE(NETLOGON, DNSCompressedPacket):
    fields_desc = [
        LEShortEnumField("OpCode", 0x17, _NETLOGON_opcodes),
        StrNullFieldUtf16("UnicodeLogonServer", ""),
        StrNullFieldUtf16("UnicodeUserName", ""),
        StrNullFieldUtf16("UnicodeDomainName", ""),
        UUIDField("DomainGuid", None, uuid_fmt=UUIDField.FORMAT_LE),
        UUIDField("NullGuid", None, uuid_fmt=UUIDField.FORMAT_LE),
        DNSStrField("DnsForestName", ""),
        DNSStrField("DnsDomainName", ""),
        DNSStrField("DnsHostName", ""),
        IPField("DcIpAddress", "0.0.0.0"),
        FlagsField("Flags", 0, -32, _NETLOGON_FLAGS),
        FlagsField("NtVersion", 0x1, -32, _NV_VERSION),
        XLEShortField("LmNtToken", 0xFFFF),
        XLEShortField("Lm20Token", 0xFFFF),
    ]

    def get_full(self):
        return self.original


# [MS-ADTS] sect 6.3.1.9


class DcSockAddr(Packet):
    fields_desc = [
        LEShortField("sin_family", 2),
        LEShortField("sin_port", 0),
        IPField("sin_addr", None),
        LELongField("sin_zero", 0),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class NETLOGON_SAM_LOGON_RESPONSE_EX(NETLOGON, DNSCompressedPacket):
    fields_desc = [
        LEShortEnumField("OpCode", 0x17, _NETLOGON_opcodes),
        LEShortField("Sbz", 0),
        FlagsField("Flags", 0, -32, _NETLOGON_FLAGS),
        UUIDField("DomainGuid", None, uuid_fmt=UUIDField.FORMAT_LE),
        DNSStrField("DnsForestName", ""),
        DNSStrField("DnsDomainName", ""),
        DNSStrField("DnsHostName", ""),
        DNSStrField("NetbiosDomainName", ""),
        DNSStrField("NetbiosComputerName", ""),
        DNSStrField("UserName", ""),
        DNSStrField("DcSiteName", "Default-First-Site-Name"),
        DNSStrField("ClientSiteName", "Default-First-Site-Name"),
        ConditionalField(
            ByteField("DcSockAddrSize", 0x10),
            lambda pkt: pkt.NtVersion.V5EX_WITH_IP,
        ),
        ConditionalField(
            PacketField("DcSockAddr", DcSockAddr(), DcSockAddr),
            lambda pkt: pkt.NtVersion.V5EX_WITH_IP,
        ),
        ConditionalField(
            DNSStrField("NextClosestSiteName", ""),
            lambda pkt: pkt.NtVersion.V5EX_WITH_CLOSEST_SITE,
        ),
        FlagsField("NtVersion", 0xB, -32, _NV_VERSION),
        XLEShortField("LmNtToken", 0xFFFF),
        XLEShortField("Lm20Token", 0xFFFF),
    ]

    def pre_dissect(self, s):
        try:
            i = s.index(b"\xff\xff\xff\xff")
            self.fields["NtVersion"] = self.fields_desc[-3].getfield(
                self,
                s[i - 4:i]
            )[1]
        except Exception:
            self.NtVersion = 0xB
        return s

    def get_full(self):
        return self.original


# [MS-BRWS] sect 2.2

class BRWS(Packet):
    fields_desc = [
        ByteEnumField("OpCode", 0x00, {
            0x01: "HostAnnouncement",
            0x02: "AnnouncementRequest",
            0x08: "RequestElection",
            0x09: "GetBackupListRequest",
            0x0A: "GetBackupListResponse",
            0x0B: "BecomeBackup",
            0x0C: "DomainAnnouncement",
            0x0D: "MasterAnnouncement",
            0x0E: "ResetStateRequest",
            0x0F: "LocalMasterAnnouncement",
        }),
    ]

    def mysummary(self):
        return self.sprintf("%OpCode%")

    registered_opcodes = {}

    @classmethod
    def register_variant(cls):
        cls.registered_opcodes[cls.OpCode.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            return cls.registered_opcodes.get(_pkt[0], cls)
        return cls

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-BRWS] sect 2.2.1

class BRWS_HostAnnouncement(BRWS):
    OpCode = 0x01
    fields_desc = [
        BRWS,
        ByteField("UpdateCount", 0),
        LEIntField("Periodicity", 128000),
        StrFixedLenField("ServerName", b"", length=16),
        ByteField("OSVersionMajor", 6),
        ByteField("OSVersionMinor", 1),
        LEIntField("ServerType", 4611),
        ByteField("BrowserConfigVersionMajor", 21),
        ByteField("BrowserConfigVersionMinor", 1),
        XLEShortField("Signature", 0xAA55),
        StrNullField("Comment", ""),
    ]

    def mysummary(self):
        return self.sprintf("%OpCode% for %ServerName%")


# [MS-BRWS] sect 2.2.6

class BRWS_BecomeBackup(BRWS):
    OpCode = 0x0B
    fields_desc = [
        BRWS,
        StrNullField("BrowserToPromote", b""),
    ]

    def mysummary(self):
        return self.sprintf("%OpCode% from %BrowserToPromote%")


# [MS-BRWS] sect 2.2.10

class BRWS_LocalMasterAnnouncement(BRWS_HostAnnouncement):
    OpCode = 0x0F


# SMB dispatcher


class _SMBGeneric(Packet):
    name = "SMB Generic dispatcher"
    fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Depending on the first 4 bytes of the packet,
        dispatch to the correct version of Header
        (either SMB or SMB2)
        """
        if _pkt and len(_pkt) >= 4:
            if _pkt[:4] == b"\xffSMB":
                return SMB_Header
            if _pkt[:4] == b"\xfeSMB":
                return SMB2_Header
        return cls


bind_layers(NBTSession, _SMBGeneric)
bind_layers(NBTDatagram, _SMBGeneric)
