# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
SMB (Server Message Block), also known as CIFS.

Specs:
- [MS-CIFS] (base)
- [MS-SMB] (extension of CIFS - SMB v1)

Implements:
- CIFS/SMB
- NTLM SMB Relay
"""

import struct
import time

from scapy.automaton import ATMT, Automaton
from scapy.config import conf
from scapy.layers.ntlm import (
    NTLM_AUTHENTICATE,
    NTLM_AUTHENTICATE_V2,
    NTLM_CHALLENGE,
    NTLM_NEGOTIATE,
    NTLM_Client,
    NTLM_Server,
)
from scapy.packet import Packet, Raw, bind_layers, bind_top_down
from scapy.fields import (
    ByteEnumField,
    ByteField,
    FieldLenField,
    FlagsField,
    LEFieldLenField,
    LEIntField,
    LEShortField,
    MultipleTypeField,
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
    XStrLenField,
)
from scapy.volatile import RandUUID

from scapy.layers.netbios import NBTSession
from scapy.layers.gssapi import (
    GSSAPI_BLOB,
    SPNEGO_MechListMIC,
    SPNEGO_MechType,
    SPNEGO_Token,
    SPNEGO_negToken,
    SPNEGO_negTokenInit,
    SPNEGO_negTokenResp,
)
from scapy.layers.smb2 import (
    SMB2_Header,
    SMB2_Negotiate_Protocol_Request,
    SMB2_Negotiate_Protocol_Response,
    SMB2_Session_Setup_Request,
    SMB2_Session_Setup_Response,
    SMB2_IOCTL_Request,
    SMB2_Error_Response,
    SMB2_Tree_Connect_Request,
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
    fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4),
                   ByteEnumField("Command", 0x72, SMB_COM),
                   LEIntField("Status", 0),
                   FlagsField("Flags", 0x18, 8,
                              ["LOCK_AND_READ_OK",
                               "BUF_AVAIL",
                               "res",
                               "CASE_INSENSITIVE",
                               "CANONICALIZED_PATHS",
                               "OPLOCK",
                               "OPBATCH",
                               "REPLY"]),
                   FlagsField("Flags2", 0x0000, -16,
                              ["LONG_NAMES",
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
                               "UNICODE"]),
                   LEShortField("PIDHigh", 0x0000),
                   StrFixedLenField("SecuritySignature", b"", length=8),
                   LEShortField("Reserved", 0x0),
                   LEShortField("TID", 0),
                   LEShortField("PIDLow", 1),
                   LEShortField("UID", 0),
                   LEShortField("MID", 0)]

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
            return SMBNetlogon_Protocol_Response_Header
        return super(SMB_Header, self).guess_payload_class(payload)

    def answers(self, pkt):
        return SMB_Header in pkt


# SMB Negotiate Request


class SMB_Dialect(Packet):
    name = "SMB Dialect"
    fields_desc = [ByteField("BufferFormat", 0x02),
                   StrNullField("DialectString", "NT LM 0.12")]

    def default_payload_class(self, payload):
        return conf.padding_layer


class SMBNegotiate_Request(Packet):
    name = "SMB Negotiate Request"
    fields_desc = [ByteField("WordCount", 0),
                   LEFieldLenField("ByteCount", None, length_of="Dialects"),
                   PacketListField(
                       "Dialects", [SMB_Dialect()], SMB_Dialect,
                       length_from=lambda pkt: pkt.ByteCount)
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
        [
            (StrNullFieldUtf16(name, default),
             _isUTF16)
        ],
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
    "res", "res",
    "DFS",
    "INFOLEVEL_PASSTHRU",
    "LARGE_READX",
    "LARGE_WRITEX",
    "LWIO",
    "res", "res", "res", "res", "res", "res",
    "UNIX",
    "res",
    "COMPRESSED_DATA",
    "res", "res", "res",
    "DYNAMIC_REAUTH",
    "PERSISTENT_HANDLES",
    "EXTENDED_SECURITY"
]


# CIFS sect 2.2.4.52.2

class SMBNegotiate_Response_NoSecurity(_SMBNegotiate_Response):
    name = "SMB Negotiate No-Security Response (CIFS)"
    fields_desc = [ByteField("WordCount", 0x1),
                   LEShortField("DialectIndex", 7),
                   FlagsField("SecurityMode", 0x03, 8,
                              ["USER_SECURITY",
                               "ENCRYPT_PASSWORDS",
                               "SECURITY_SIGNATURES_ENABLED",
                               "SECURITY_SIGNATURES_REQUIRED"]),
                   LEShortField("MaxMpxCount", 50),
                   LEShortField("MaxNumberVC", 1),
                   LEIntField("MaxBufferSize", 16144),  # Windows: 4356
                   LEIntField("MaxRawSize", 65536),
                   LEIntField("SessionKey", 0x0000),
                   FlagsField("ServerCapabilities", 0xf3f9, -32,
                              _SMB_ServerCapabilities),
                   UTCTimeField("ServerTime", None, fmt="<Q",
                                epoch=[1601, 1, 1, 0, 0, 0],
                                custom_scaling=1e7),
                   ScalingField("ServerTimeZone", 0x3c, fmt="<h",
                                unit="min-UTC"),
                   FieldLenField("ChallengeLength", None,
                                 # aka EncryptionKeyLength
                                 length_of="Challenge", fmt="<B"),
                   LEFieldLenField("ByteCount", None, length_of="DomainName",
                                   adjust=lambda pkt, x: x +
                                   len(pkt.Challenge)),
                   XStrLenField("Challenge", b"",  # aka EncryptionKey
                                length_from=lambda pkt: pkt.ChallengeLength),
                   StrNullField("DomainName", "WORKGROUP")]


bind_top_down(SMB_Header, SMBNegotiate_Response_NoSecurity,
              Command=0x72, Flags=0x80)

# SMB sect 2.2.4.5.2.1


class SMBNegotiate_Response_Extended_Security(_SMBNegotiate_Response):
    name = "SMB Negotiate Extended Security Response (SMB)"
    WordCount = 0x11
    fields_desc = SMBNegotiate_Response_NoSecurity.fields_desc[:12] + [
        LEFieldLenField("ByteCount", None, length_of="SecurityBlob",
                        adjust=lambda _, x: x + 16),
        SMBNegotiate_Response_NoSecurity.fields_desc[13],
        UUIDField("GUID", None, uuid_fmt=UUIDField.FORMAT_LE),
        PacketLenField("SecurityBlob", None, GSSAPI_BLOB,
                       length_from=lambda x: x.ByteCount - 16)
    ]


bind_top_down(SMB_Header, SMBNegotiate_Response_Extended_Security,
              Command=0x72, Flags=0x80, Flags2=0x800)

# SMB sect 2.2.4.5.2.2


class SMBNegotiate_Response_Security(_SMBNegotiate_Response):
    name = "SMB Negotiate Non-Extended Security Response (SMB)"
    WordCount = 0x11
    fields_desc = SMBNegotiate_Response_NoSecurity.fields_desc[:12] + [
        LEFieldLenField("ByteCount", None, length_of="DomainName",
                        adjust=lambda pkt, x: x + 2 + _len(pkt, "Challenge") +
                        _len(pkt, "ServerName")),
        XStrLenField("Challenge", b"",  # aka EncryptionKey
                     length_from=lambda pkt: pkt.ChallengeLength),
        _SMBStrNullField("DomainName", "WORKGROUP"),
        _SMBStrNullField("ServerName", "RMFF1")
    ]


bind_top_down(SMB_Header, SMBNegotiate_Response_Security,
              Command=0x72, Flags=0x80)

# Session Setup AndX Request

# CIFS sect 2.2.4.53


class SMBSession_Setup_AndX_Request(Packet):
    name = "Session Setup AndX Request (CIFS)"
    fields_desc = [
        ByteField("WordCount", 0x0D),
        ByteEnumField("AndXCommand", 0xff,
                      SMB_COM),
        ByteField("AndXReserved", 0),
        LEShortField("AndXOffset", None),
        LEShortField("MaxBufferSize", 16144),  # Windows: 4356
        LEShortField("MaxMPXCount", 50),
        LEShortField("VCNumber", 0),
        LEIntField("SessionKey", 0),
        LEFieldLenField("OEMPasswordLength", None,
                        length_of="OEMPassword"),
        LEFieldLenField("UnicodePasswordLength", None,
                        length_of="UnicodePassword"),
        LEIntField("Reserved", 0),
        FlagsField("ServerCapabilities", 0x05, -32,
                   _SMB_ServerCapabilities),
        LEShortField("ByteCount", None),
        XStrLenField("OEMPassword", "Pass",
                     length_from=lambda x: x.OEMPasswordLength),
        XStrLenField("UnicodePassword", "Pass",
                     length_from=lambda x: x.UnicodePasswordLength),
        ReversePadField(
            _SMBStrNullField("AccountName", "GUEST"), 2, b"\0"
        ),
        _SMBStrNullField("PrimaryDomain", ""),
        _SMBStrNullField("NativeOS", "Windows 4.0"),
        _SMBStrNullField("NativeLanMan", "Windows 4.0")]

    def post_build(self, pkt, pay):
        if self.AndXOffset is None and self.AndXCommand != 0xff:
            pkt = pkt[:3] + struct.pack("<H", len(pkt) + 32) + pkt[5:]
        if self.ByteCount is None:
            pkt = pkt[:27] + struct.pack("<H", len(pkt) - 29) + pkt[29:]
        if self.payload and hasattr(self.payload, "AndXOffset") and pay:
            pay = pay[:3] + \
                struct.pack("<H", len(pkt) + len(pay) + 32) + pay[5:]
        return pkt + pay


bind_top_down(SMB_Header, SMBSession_Setup_AndX_Request,
              Command=0x73)

# SMB sect 2.2.4.7


class SMBTree_Connect_AndX(Packet):
    name = "Session Tree Connect AndX"
    WordCount = 0x04
    fields_desc = SMBSession_Setup_AndX_Request.fields_desc[:4] + [
        FlagsField("Flags", "", -16, ["DISCONNECT_TID",
                                      "r2",
                                      "EXTENDED_SIGNATURES",
                                      "EXTENDED_RESPONSE"]),
        FieldLenField("PasswordLength", None,
                      length_of="Password", fmt="<H"),
        LEShortField("ByteCount", None),
        XStrLenField("Password", b"",
                     length_from=lambda pkt: pkt.PasswordLength),
        ReversePadField(
            _SMBStrNullField("Path", "\\\\WIN2K\\IPC$"),
            2
        ),
        StrNullField("Service", "?????")
    ]

    def post_build(self, pkt, pay):
        pkt += pay
        if self.ByteCount is None:
            pkt = pkt[:9] + struct.pack("<H", len(pkt) - 11) + pkt[11:]
        return pkt


bind_layers(SMB_Header, SMBTree_Connect_AndX,
            Command=0x75)
bind_layers(SMBSession_Setup_AndX_Request,
            SMBTree_Connect_AndX, AndXCommand=0x75)

# SMB sect 2.2.4.6.1


class SMBSession_Setup_AndX_Request_Extended_Security(Packet):
    name = "Session Setup AndX Extended Security Request (SMB)"
    WordCount = 0x0C
    fields_desc = SMBSession_Setup_AndX_Request.fields_desc[:8] + [
        LEFieldLenField("SecurityBlobLength", None,
                        length_of="SecurityBlob"),
    ] + SMBSession_Setup_AndX_Request.fields_desc[10:12] + [
        LEShortField("ByteCount", None),
        PacketLenField("SecurityBlob", None, GSSAPI_BLOB,
                       length_from=lambda x: x.SecurityBlobLength),
        ReversePadField(
            _SMBStrNullField("NativeOS", "Windows 4.0"),
            2, b"\0",
        ),
        _SMBStrNullField("NativeLanMan", "Windows 4.0"),
    ]

    def post_build(self, pkt, pay):
        if self.ByteCount is None:
            pkt = pkt[:25] + struct.pack("<H", len(pkt) - 27) + pkt[27:]
        return pkt + pay


bind_top_down(SMB_Header, SMBSession_Setup_AndX_Request_Extended_Security,
              Command=0x73, Flags2=0x800)

# Session Setup AndX Response


# CIFS sect 2.2.4.53.2

class SMBSession_Setup_AndX_Response(Packet):
    name = "Session Setup AndX Response (CIFS)"
    fields_desc = [
        ByteField("WordCount", 0x3),
        ByteEnumField("AndXCommand", 0xff,
                      SMB_COM),
        ByteField("AndXReserved", 0),
        LEShortField("AndXOffset", None),
        LEShortField("Action", 0),
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
        StrNullField("NativeFileSystem", "")]

    def post_build(self, pkt, pay):
        if self.AndXOffset is None:
            pkt = pkt[:3] + struct.pack("<H", len(pkt) + 32) + pkt[5:]
        return pkt + pay


bind_top_down(SMB_Header, SMBSession_Setup_AndX_Response,
              Command=0x73, Flags=0x80)

# SMB sect 2.2.4.6.2
# uWu


class SMBSession_Setup_AndX_Response_Extended_Security(SMBSession_Setup_AndX_Response):  # noqa: E501
    name = "Session Setup AndX Extended Security Response (SMB)"
    WordCount = 0x4
    fields_desc = (
        SMBSession_Setup_AndX_Response.fields_desc[:5] +
        [SMBSession_Setup_AndX_Request_Extended_Security.fields_desc[8]] +
        SMBSession_Setup_AndX_Request_Extended_Security.fields_desc[11:]
    )

    def post_build(self, pkt, pay):
        if self.ByteCount is None:
            pkt = pkt[:9] + struct.pack("<H", len(pkt) - 11) + pkt[11:]
        return super(
            SMBSession_Setup_AndX_Response_Extended_Security,
            self
        ).post_build(pkt, pay)


bind_top_down(SMB_Header, SMBSession_Setup_AndX_Response_Extended_Security,
              Command=0x73, Flags=0x80, Flags2=0x800)

# SMB null (no wordcount)


class SMBSession_Null(Packet):
    fields_desc = [ByteField("WordCount", 0),
                   LEShortField("ByteCount", 0)]


bind_top_down(SMB_Header, SMBSession_Null,
              Command=0x73)

# SMB NetLogon Response Header


class SMBNetlogon_Protocol_Response_Header(Packet):
    name = "SMBNetlogon Protocol Response Header"
    fields_desc = [ByteField("WordCount", 17),
                   LEShortField("TotalParamCount", 0),
                   LEShortField("TotalDataCount", 112),
                   LEShortField("MaxParamCount", 0),
                   LEShortField("MaxDataCount", 0),
                   ByteField("MaxSetupCount", 0),
                   ByteField("unused2", 0),
                   LEShortField("Flags3", 0),
                   ByteField("TimeOut1", 0xe8),
                   ByteField("TimeOut2", 0x03),
                   LEShortField("unused3", 0),
                   LEShortField("unused4", 0),
                   LEShortField("ParamCount2", 0),
                   LEShortField("ParamOffset", 0),
                   LEShortField("DataCount", 112),
                   LEShortField("DataOffset", 92),
                   ByteField("SetupCount", 3),
                   ByteField("unused5", 0)]


bind_top_down(SMB_Header, SMBNetlogon_Protocol_Response_Header,
              Command=0x25)

# SMB MailSlot Protocol


class SMBMailSlot(Packet):
    name = "SMB Mail Slot Protocol"
    fields_desc = [LEShortField("opcode", 1),
                   LEShortField("priority", 1),
                   LEShortField("class", 2),
                   LEShortField("size", 135),
                   StrNullField("name", "\\MAILSLOT\\NET\\GETDC660")]

# SMB NetLogon Protocol Response Tail SAM


class SMBNetlogon_Protocol_Response_Tail_SAM(Packet):
    name = "SMB Netlogon Protocol Response Tail SAM"
    fields_desc = [ByteEnumField("Command", 0x17,
                                 {0x12: "SAM logon request",
                                  0x17: "SAM Active directory Response"}),
                   ByteField("unused", 0),
                   ShortField("Data1", 0),
                   ShortField("Data2", 0xfd01),
                   ShortField("Data3", 0),
                   ShortField("Data4", 0xacde),
                   ShortField("Data5", 0x0fe5),
                   ShortField("Data6", 0xd10a),
                   ShortField("Data7", 0x374c),
                   ShortField("Data8", 0x83e2),
                   ShortField("Data9", 0x7dd9),
                   ShortField("Data10", 0x3a16),
                   ShortField("Data11", 0x73ff),
                   ByteField("Data12", 0x04),
                   StrFixedLenField("Data13", "rmff", 4),
                   ByteField("Data14", 0x0),
                   ShortField("Data16", 0xc018),
                   ByteField("Data18", 0x0a),
                   StrFixedLenField("Data20", "rmff-win2k", 10),
                   ByteField("Data21", 0xc0),
                   ShortField("Data22", 0x18c0),
                   ShortField("Data23", 0x180a),
                   StrFixedLenField("Data24", "RMFF-WIN2K", 10),
                   ShortField("Data25", 0),
                   ByteField("Data26", 0x17),
                   StrFixedLenField("Data27", "Default-First-Site-Name", 23),
                   ShortField("Data28", 0x00c0),
                   ShortField("Data29", 0x3c10),
                   ShortField("Data30", 0x00c0),
                   ShortField("Data31", 0x0200),
                   ShortField("Data32", 0x0),
                   ShortField("Data33", 0xac14),
                   ShortField("Data34", 0x0064),
                   ShortField("Data35", 0x0),
                   ShortField("Data36", 0x0),
                   ShortField("Data37", 0x0),
                   ShortField("Data38", 0x0),
                   ShortField("Data39", 0x0d00),
                   ShortField("Data40", 0x0),
                   ShortField("Data41", 0xffff)]

# SMB NetLogon Protocol Response Tail LM2.0
# coucou bg


class SMBNetlogon_Protocol_Response_Tail_LM20(Packet):
    name = "SMB Netlogon Protocol Response Tail LM20"
    fields_desc = [ByteEnumField("Command", 0x06, {0x06: "LM 2.0 Response to logon request"}),  # noqa: E501
                   ByteField("unused", 0),
                   StrFixedLenField("DblSlash", "\\\\", 2),
                   StrNullField("ServerName", "WIN"),
                   LEShortField("LM20Token", 0xffff)]

# Generic version of SMBNegociate Protocol Request Header


class SMBNegociate_Protocol_Request_Header_Generic(Packet):
    name = "SMBNegociate Protocol Request Header Generic"
    fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
            Depending on the first 4 bytes of the packet,
            dispatch to the correct version of Header
            (either SMB or SMB2)
        """
        if _pkt and len(_pkt) >= 4:
            if _pkt[:4] == b'\xffSMB':
                return SMB_Header
            if _pkt[:4] == b'\xfeSMB':
                return SMB2_Header
        return cls


bind_layers(NBTSession, SMBNegociate_Protocol_Request_Header_Generic)

# Automatons


class NTLM_SMB_Server(NTLM_Server, Automaton):
    port = 445
    cls = NBTSession

    def __init__(self, *args, **kwargs):
        self.CLIENT_PROVIDES_NEGOEX = kwargs.pop(
            "CLIENT_PROVIDES_NEGOEX", False)
        self.ECHO = kwargs.pop("ECHO", False)
        self.PASS_NEGOEX = kwargs.pop("PASS_NEGOEX", False)
        self.EXTENDED_SECURITY = kwargs.pop("EXTENDED_SECURITY", True)
        self.ALLOW_SMB2 = kwargs.pop("ALLOW_SMB2", True)
        self.REAL_HOSTNAME = kwargs.pop(
            "REAL_HOSTNAME", None)  # Compulsory for SMB1 !!!
        self.SMB2 = False
        super(NTLM_SMB_Server, self).__init__(*args, **kwargs)

    @ATMT.state(initial=1)
    def BEGIN(self):
        self.authenticated = False

    @ATMT.receive_condition(BEGIN)
    def received_negotiate(self, pkt):
        if SMBNegotiate_Request in pkt:
            self.start_client()
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.receive_condition(BEGIN)
    def received_negotiate_smb2_begin(self, pkt):
        if SMB2_Negotiate_Protocol_Request in pkt:
            self.SMB2 = True
            self.start_client(
                CONTINUE_SMB2=True,
                SMB2_INIT_PARAMS={
                    "ClientGUID": pkt.ClientGUID
                }
            )
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.action(received_negotiate_smb2_begin)
    def on_negotiate_smb2_begin(self, pkt):
        self.on_negotiate(pkt)

    @ATMT.action(received_negotiate)
    def on_negotiate(self, pkt):
        if self.CLIENT_PROVIDES_NEGOEX:
            negoex_token, _, _ = self.get_token()
        else:
            negoex_token = None
        if not self.SMB2 and not self.get("GUID", 0):
            self.EXTENDED_SECURITY = False
        # Build negotiate response
        DialectIndex = None
        DialectRevision = None
        if SMB2_Negotiate_Protocol_Request in pkt:
            # SMB2
            DialectRevisions = pkt[SMB2_Negotiate_Protocol_Request].Dialects
            DialectRevisions.sort()
            DialectRevision = DialectRevisions[0]
            if DialectRevision >= 0x300:  # SMB3
                raise ValueError(
                    "SMB client requires SMB3 which is unimplemented.")
        else:
            DialectIndexes = [
                x.DialectString for x in pkt[SMBNegotiate_Request].Dialects
            ]
            if self.ALLOW_SMB2:
                # Find a value matching SMB2, fallback to SMB1
                for key, rev in [(b"SMB 2.???", 0x02ff),
                                 (b"SMB 2.002", 0x0202)]:
                    try:
                        DialectIndex = DialectIndexes.index(key)
                        DialectRevision = rev
                        self.SMB2 = True
                        break
                    except ValueError:
                        pass
                else:
                    DialectIndex = DialectIndexes.index(b"NT LM 0.12")
            else:
                # Enforce SMB1
                DialectIndex = DialectIndexes.index(b"NT LM 0.12")
        cls = None
        if self.SMB2:
            # SMB2
            cls = SMB2_Negotiate_Protocol_Response
            self.smb_header = NBTSession() / SMB2_Header(
                CreditsRequested=1,
            )
            if SMB2_Negotiate_Protocol_Request in pkt:
                self.smb_header.MessageId = pkt.MessageId
                self.smb_header.AsyncId = pkt.AsyncId
                self.smb_header.SessionId = pkt.SessionId
        else:
            # SMB1
            self.smb_header = NBTSession() / SMB_Header(
                Flags="REPLY+CASE_INSENSITIVE+CANONICALIZED_PATHS",
                Flags2=(
                    "LONG_NAMES+EAS+NT_STATUS+SMB_SECURITY_SIGNATURE+"
                    "UNICODE+EXTENDED_SECURITY"
                ),
                TID=pkt.TID,
                MID=pkt.MID,
                UID=pkt.UID,
                PIDLow=pkt.PIDLow
            )
            if self.EXTENDED_SECURITY:
                cls = SMBNegotiate_Response_Extended_Security
            else:
                cls = SMBNegotiate_Response_Security
        if self.SMB2:
            # SMB2
            resp = self.smb_header.copy() / cls(
                DialectRevision=DialectRevision,
                Capabilities="DFS",
                SecurityMode=0,  # self.get("SecurityMode", 1),
                ServerTime=self.get("ServerTime", time.time() + 11644473600),
                ServerStartTime=0,
                MaxTransactionSize=65536,
                MaxReadSize=65536,
                MaxWriteSize=65536,
            )
        else:
            # SMB1
            resp = self.smb_header.copy() / cls(
                DialectIndex=DialectIndex,
                ServerCapabilities=(
                    "UNICODE+LARGE_FILES+NT_SMBS+RPC_REMOTE_APIS+STATUS32+"
                    "LEVEL_II_OPLOCKS+LOCK_AND_READ+NT_FIND+"
                    "LWIO+INFOLEVEL_PASSTHRU+LARGE_READX+LARGE_WRITEX"
                ),
                SecurityMode=self.get("SecurityMode"),
                ServerTime=self.get("ServerTime"),
                ServerTimeZone=self.get("ServerTimeZone")
            )
            if self.EXTENDED_SECURITY:
                resp.ServerCapabilities += "EXTENDED_SECURITY"
        if self.EXTENDED_SECURITY or self.SMB2:
            # Extended SMB1 / SMB2
            # Add security blob
            resp.SecurityBlob = GSSAPI_BLOB(
                innerContextToken=SPNEGO_negToken(
                    token=SPNEGO_negTokenInit(
                        mechTypes=[
                            # NEGOEX - Optional. See below
                            # NTLMSSP
                            SPNEGO_MechType(oid="1.3.6.1.4.1.311.2.2.10")],

                    )
                )
            )
            resp.GUID = self.get("GUID", RandUUID())
            if self.PASS_NEGOEX:  # NEGOEX handling
                # NOTE: NegoEX has an effect on how the SecurityContext is
                # initialized, as detailed in [MS-AUTHSOD] sect 3.3.2
                # But the format that the Exchange token uses appears not to
                # be documented :/
                resp.SecurityBlob.innerContextToken.token.mechTypes.insert(
                    0,
                    # NEGOEX
                    SPNEGO_MechType(oid="1.3.6.1.4.1.311.2.2.30"),
                )
                resp.SecurityBlob.innerContextToken.token.mechToken = SPNEGO_Token(  # noqa: E501
                    value=negoex_token
                )
        else:
            # Non-extended SMB1
            resp.Challenge = self.get("Challenge")
            resp.DomainName = self.get("DomainName")
            resp.ServerName = self.get("ServerName")
            resp.Flags2 -= "EXTENDED_SECURITY"
        if not self.SMB2:
            resp[SMB_Header].Flags2 = resp[SMB_Header].Flags2 - \
                "SMB_SECURITY_SIGNATURE" + \
                "SMB_SECURITY_SIGNATURE_REQUIRED+IS_LONG_NAME"
        self.send(resp)

    @ATMT.state()
    def NEGOTIATED(self):
        pass

    @ATMT.receive_condition(NEGOTIATED)
    def received_negotiate_smb2(self, pkt):
        if SMB2_Negotiate_Protocol_Request in pkt:
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.action(received_negotiate_smb2)
    def on_negotiate_smb2(self, pkt):
        self.on_negotiate(pkt)

    @ATMT.receive_condition(NEGOTIATED)
    def receive_setup_andx_request(self, pkt):
        if SMBSession_Setup_AndX_Request_Extended_Security in pkt or \
                SMBSession_Setup_AndX_Request in pkt:
            # SMB1
            if SMBSession_Setup_AndX_Request_Extended_Security in pkt:
                # Extended
                ntlm_tuple = self._get_token(
                    pkt.SecurityBlob
                )
            else:
                # Non-extended
                self.set_cli("AccountName", pkt.getfieldval("AccountName"))
                self.set_cli("PrimaryDomain",
                             pkt.getfieldval("PrimaryDomain"))
                self.set_cli("Path", pkt.getfieldval("Path"))
                self.set_cli("Service", pkt.getfieldval("Service"))
                ntlm_tuple = self._get_token(
                    pkt[SMBSession_Setup_AndX_Request].UnicodePassword
                )
            self.set_cli("VCNumber", pkt.VCNumber)
            self.set_cli("SecuritySignature", pkt.SecuritySignature)
            self.set_cli("UID", pkt.UID)
            self.set_cli("MID", pkt.MID)
            self.set_cli("TID", pkt.TID)
            self.received_ntlm_token(ntlm_tuple)
            raise self.RECEIVED_SETUP_ANDX_REQUEST().action_parameters(pkt)
        elif SMB2_Session_Setup_Request in pkt:
            # SMB2
            ntlm_tuple = self._get_token(pkt.SecurityBlob)
            self.set_cli("SecuritySignature", pkt.SecuritySignature)
            self.set_cli("MessageId", pkt.MessageId)
            self.set_cli("AsyncId", pkt.AsyncId)
            self.set_cli("SessionId", pkt.SessionId)
            self.set_cli("SecurityMode", pkt.SecurityMode)
            self.received_ntlm_token(ntlm_tuple)
            raise self.RECEIVED_SETUP_ANDX_REQUEST().action_parameters(pkt)

    @ATMT.state()
    def RECEIVED_SETUP_ANDX_REQUEST(self):
        pass

    @ATMT.action(receive_setup_andx_request)
    def on_setup_andx_request(self, pkt):
        ntlm_token, negResult, MIC = ntlm_tuple = self.get_token()
        if SMBSession_Setup_AndX_Request_Extended_Security in pkt or \
                SMBSession_Setup_AndX_Request in pkt or\
                SMB2_Session_Setup_Request in pkt:
            if SMB2_Session_Setup_Request in pkt:
                # SMB2
                self.smb_header.MessageId = self.get(
                    "MessageId", self.smb_header.MessageId + 1)
                self.smb_header.AsyncId = self.get(
                    "AsyncId", self.smb_header.AsyncId)
                self.smb_header.SessionId = self.get(
                    "SessionId", self.smb_header.SessionId)
            else:
                # SMB1
                self.smb_header.UID = self.get("UID")
                self.smb_header.MID = self.get("MID")
                self.smb_header.TID = self.get("TID")
            if ntlm_tuple == (None, None, None):
                # Error
                if SMB2_Session_Setup_Request in pkt:
                    # SMB2
                    resp = self.smb_header.copy() / \
                        SMB2_Session_Setup_Response()
                else:
                    # SMB1
                    resp = self.smb_header.copy() / SMBSession_Null()
                resp.Status = self.get("Status", 0xc000006d)
            else:
                # Negotiation
                if SMBSession_Setup_AndX_Request_Extended_Security in pkt or\
                        SMB2_Session_Setup_Request in pkt:
                    # SMB1 extended / SMB2
                    if SMB2_Session_Setup_Request in pkt:
                        # SMB2
                        resp = self.smb_header.copy() / \
                            SMB2_Session_Setup_Response()
                    else:
                        # SMB1 extended
                        resp = self.smb_header.copy() / \
                            SMBSession_Setup_AndX_Response_Extended_Security(
                                NativeOS=self.get("NativeOS"),
                                NativeLanMan=self.get("NativeLanMan")
                        )
                    if isinstance(ntlm_token, NTLM_CHALLENGE):
                        resp.SecurityBlob = SPNEGO_negToken(
                            token=SPNEGO_negTokenResp(
                                negResult=1,
                                supportedMech=SPNEGO_MechType(
                                    # NTLMSSP
                                    oid="1.3.6.1.4.1.311.2.2.10"),
                                responseToken=SPNEGO_Token(
                                    value=ntlm_token
                                )
                            )
                        )
                    elif not ntlm_token:
                        # No token (e.g. accepted)
                        resp.SecurityBlob = SPNEGO_negToken(
                            token=SPNEGO_negTokenResp(
                                negResult=negResult,
                            )
                        )
                        if MIC and not self.DROP_MIC:  # Drop the MIC?
                            resp.SecurityBlob.token.mechListMIC = SPNEGO_MechListMIC(  # noqa: E501
                                value=MIC
                            )
                        if negResult == 0:
                            self.authenticated = True
                    else:
                        resp.SecurityBlob = ntlm_token
                elif SMBSession_Setup_AndX_Request in pkt:
                    # Non-extended
                    resp = self.smb_header.copy() / \
                        SMBSession_Setup_AndX_Response(
                            NativeOS=self.get("NativeOS"),
                            NativeLanMan=self.get("NativeLanMan")
                    )
                resp.Status = self.get(
                    "Status", 0x0 if self.authenticated else 0xc0000016)
        self.send(resp)

    @ATMT.condition(RECEIVED_SETUP_ANDX_REQUEST)
    def wait_for_next_request(self):
        if self.authenticated:
            raise self.AUTHENTICATED()
        else:
            raise self.NEGOTIATED()

    @ATMT.state()
    def AUTHENTICATED(self):
        """Dev: overload this"""
        pass

    @ATMT.condition(AUTHENTICATED, prio=0)
    def should_end(self):
        if not self.ECHO:
            # Close connection
            raise self.END()

    @ATMT.receive_condition(AUTHENTICATED, prio=1)
    def receive_packet(self, pkt):
        if self.ECHO:
            raise self.AUTHENTICATED().action_parameters(pkt)

    @ATMT.action(receive_packet)
    def pass_packet(self, pkt):
        # Pre-process some of the data if possible
        if not self.SMB2:
            # SMB1 - no signature (disabled by our implementation)
            if SMBTree_Connect_AndX in pkt and self.REAL_HOSTNAME:
                pkt.LENGTH = None
                pkt.ByteCount = None
                pkt.Path = (
                    "\\\\%s\\" % self.REAL_HOSTNAME +
                    pkt.Path[2:].split("\\", 1)[1]
                )
        else:
            self.smb_header.MessageId += 1
            # SMB2
            if SMB2_IOCTL_Request in pkt and pkt.CtlCode == 0x00140204:
                # FSCTL_VALIDATE_NEGOTIATE_INFO
                # This is a security measure asking the server to validate
                # what flags were negotiated during the SMBNegotiate exchange.
                # This packet is ALWAYS signed.
                # A SMB server < SMB3 (e.g. Windows 7) will reply with
                # STATUS_FILE_CLOSED, which is what we do here, however we
                # CANNOT SIGN the response. Most clients will abort the
                # connection after receiving this, despite our best effort,
                # as our answer is unsigned...
                pkt = self.smb_header.copy() / \
                    SMB2_Error_Response(ErrorData=b"\xff")
                pkt.Status = 0xc0000128  # STATUS_FILE_CLOSED
                pkt.Command = "SMB2_IOCTL"
                pkt.Flags = pkt.Flags + "SMB2_FLAGS_SERVER_TO_REDIR" - \
                    "SMB2_FLAGS_SIGNED"
                self.send(pkt)
                return
        self.echo(pkt)

    @ATMT.state(final=1)
    def END(self):
        self.end()


class NTLM_SMB_Client(NTLM_Client, Automaton):
    port = 445
    cls = NBTSession
    kwargs_cls = {
        NTLM_SMB_Server: {"CLIENT_PROVIDES_NEGOEX": True, "ECHO": True}
    }

    def __init__(self, *args, **kwargs):
        self.EXTENDED_SECURITY = kwargs.pop("EXTENDED_SECURITY", True)
        self.ALLOW_SMB2 = kwargs.pop("ALLOW_SMB2", True)
        self.REAL_HOSTNAME = kwargs.pop("REAL_HOSTNAME", None)
        self.RUN_SCRIPT = kwargs.pop("RUN_SCRIPT", None)
        self.SMB2 = False
        super(NTLM_SMB_Client, self).__init__(*args, **kwargs)

    @ATMT.state(initial=1)
    def BEGIN(self):
        pass

    @ATMT.condition(BEGIN)
    def continue_smb2(self):
        kwargs = self.wait_server()
        self.CONTINUE_SMB2 = kwargs.pop("CONTINUE_SMB2", False)
        self.SMB2_INIT_PARAMS = kwargs.pop("SMB2_INIT_PARAMS", {})
        if self.CONTINUE_SMB2:
            self.SMB2 = True
            self.smb_header = NBTSession() / SMB2_Header(
                AsyncId=0xfeff
            )
            raise self.SMB2_NEGOTIATE()

    @ATMT.condition(BEGIN, prio=1)
    def send_negotiate(self):
        raise self.SENT_NEGOTIATE()

    @ATMT.action(send_negotiate)
    def on_negotiate(self):
        self.smb_header = NBTSession() / SMB_Header(
            Flags2=(
                "LONG_NAMES+EAS+NT_STATUS+UNICODE+"
                "SMB_SECURITY_SIGNATURE+EXTENDED_SECURITY"
            ),
            TID=0xFFFF,
            PIDLow=0xFEFF,
            UID=0,
            MID=0
        )
        if self.EXTENDED_SECURITY:
            self.smb_header.Flags2 += "EXTENDED_SECURITY"
        pkt = self.smb_header.copy() / SMBNegotiate_Request(
            Dialects=[SMB_Dialect(DialectString=x) for x in [
                "PC NETWORK PROGRAM 1.0", "LANMAN1.0",
                "Windows for Workgroups 3.1a", "LM1.2X002", "LANMAN2.1",
                "NT LM 0.12"
            ] + (["SMB 2.002", "SMB 2.???"] if self.ALLOW_SMB2 else [])
            ],
        )
        if not self.EXTENDED_SECURITY:
            pkt.Flags2 -= "EXTENDED_SECURITY"
        pkt[SMB_Header].Flags2 = pkt[SMB_Header].Flags2 - \
            "SMB_SECURITY_SIGNATURE" + \
            "SMB_SECURITY_SIGNATURE_REQUIRED+IS_LONG_NAME"
        self.send(pkt)

    @ATMT.state()
    def SENT_NEGOTIATE(self):
        pass

    @ATMT.receive_condition(SENT_NEGOTIATE)
    def receive_negotiate_response(self, pkt):
        if SMBNegotiate_Response_Security in pkt or\
                SMBNegotiate_Response_Extended_Security in pkt or\
                SMB2_Negotiate_Protocol_Response in pkt:
            self.set_srv(
                "ServerTime",
                pkt.ServerTime
            )
            self.set_srv(
                "SecurityMode",
                pkt.SecurityMode
            )
            if SMB2_Negotiate_Protocol_Response in pkt:
                # SMB2
                self.SMB2 = True  # We are using SMB2 to talk to the server
                self.smb_header = NBTSession() / SMB2_Header(
                    AsyncId=0xfeff
                )
            else:
                # SMB1
                self.set_srv(
                    "ServerTimeZone",
                    pkt.ServerTimeZone
                )
        if SMBNegotiate_Response_Extended_Security in pkt or\
                SMB2_Negotiate_Protocol_Response in pkt:
            # Extended SMB1 / SMB2
            negoex_tuple = self._get_token(
                pkt.SecurityBlob
            )
            self.set_srv(
                "GUID",
                pkt.GUID
            )
            self.received_ntlm_token(negoex_tuple)
            if SMB2_Negotiate_Protocol_Response in pkt and \
                    pkt.DialectRevision in [0x02ff, 0x03ff]:
                # There will be a second negotiate protocol request
                self.smb_header.MessageId += 1
                raise self.SMB2_NEGOTIATE()
            else:
                raise self.NEGOTIATED()
        elif SMBNegotiate_Response_Security in pkt:
            # Non-extended SMB1
            self.set_srv("Challenge", pkt.Challenge)
            self.set_srv("DomainName", pkt.DomainName)
            self.set_srv("ServerName", pkt.ServerName)
            self.received_ntlm_token((None, None, None))
            raise self.NEGOTIATED()

    @ATMT.state()
    def SMB2_NEGOTIATE(self):
        pass

    @ATMT.condition(SMB2_NEGOTIATE)
    def send_negotiate_smb2(self):
        raise self.SENT_NEGOTIATE()

    @ATMT.action(send_negotiate_smb2)
    def on_negotiate_smb2(self):
        pkt = self.smb_header.copy() / SMB2_Negotiate_Protocol_Request(
            # Only ask for SMB 2.0.2 because it has the lowest security
            Dialects=[0x0202],
            Capabilities=(
                "DFS+Leasing+LargeMTU+MultiChannel+"
                "PersistentHandles+DirectoryLeasing+Encryption"
            ),
            SecurityMode=0,
            ClientGUID=self.SMB2_INIT_PARAMS.get("ClientGUID", RandUUID()),
        )
        self.send(pkt)

    @ATMT.state()
    def NEGOTIATED(self):
        pass

    @ATMT.condition(NEGOTIATED)
    def should_send_setup_andx_request(self):
        ntlm_tuple = self.get_token()
        raise self.SENT_SETUP_ANDX_REQUEST().action_parameters(ntlm_tuple)

    @ATMT.state()
    def SENT_SETUP_ANDX_REQUEST(self):
        pass

    @ATMT.action(should_send_setup_andx_request)
    def send_setup_andx_request(self, ntlm_tuple):
        ntlm_token, negResult, MIC = ntlm_tuple
        if self.SMB2:
            self.smb_header.MessageId = self.get("MessageId")
            self.smb_header.AsyncId = self.get("AsyncId")
            self.smb_header.SessionId = self.get("SessionId")
        else:
            self.smb_header.UID = self.get("UID", 0)
            self.smb_header.MID = self.get("MID")
            self.smb_header.TID = self.get("TID")
        if self.SMB2 or self.EXTENDED_SECURITY:
            # SMB1 extended / SMB2
            if self.SMB2:
                # SMB2
                pkt = self.smb_header.copy() / SMB2_Session_Setup_Request(
                    Capabilities="DFS",
                    SecurityMode=0,
                )
                pkt.CreditsRequested = 33
            else:
                # SMB1 extended
                pkt = self.smb_header.copy() / \
                    SMBSession_Setup_AndX_Request_Extended_Security(
                        ServerCapabilities=(
                            "UNICODE+NT_SMBS+STATUS32+LEVEL_II_OPLOCKS+"
                            "DYNAMIC_REAUTH+EXTENDED_SECURITY"
                        ),
                        VCNumber=self.get("VCNumber"),
                        NativeOS=b"",
                        NativeLanMan=b""
                )
            pkt.SecuritySignature = self.get("SecuritySignature")
            if isinstance(ntlm_token, NTLM_NEGOTIATE):
                pkt.SecurityBlob = GSSAPI_BLOB(
                    innerContextToken=SPNEGO_negToken(
                        token=SPNEGO_negTokenInit(
                            mechTypes=[
                                # NTLMSSP
                                SPNEGO_MechType(oid="1.3.6.1.4.1.311.2.2.10")],
                            mechToken=SPNEGO_Token(
                                value=ntlm_token
                            )
                        )
                    )
                )
            elif isinstance(ntlm_token, (NTLM_AUTHENTICATE,
                                         NTLM_AUTHENTICATE_V2)):
                pkt.SecurityBlob = SPNEGO_negToken(
                    token=SPNEGO_negTokenResp(
                        negResult=negResult,
                    )
                )
                # Token may be missing (e.g. STATUS_MORE_PROCESSING_REQUIRED)
                if ntlm_token:
                    pkt.SecurityBlob.token.responseToken = SPNEGO_Token(
                        value=ntlm_token
                    )
                if MIC and not self.DROP_MIC:  # Drop the MIC?
                    pkt.SecurityBlob.token.mechListMIC = SPNEGO_MechListMIC(
                        value=MIC
                    )
        else:
            # Non-extended security
            pkt = self.smb_header.copy() / SMBSession_Setup_AndX_Request(
                ServerCapabilities="UNICODE+NT_SMBS+STATUS32+LEVEL_II_OPLOCKS",
                VCNumber=self.get("VCNumber"),
                NativeOS=b"",
                NativeLanMan=b"",
                OEMPassword=b"\0" * 24,
                UnicodePassword=ntlm_token,
                PrimaryDomain=self.get("PrimaryDomain"),
                AccountName=self.get("AccountName"),
            ) / SMBTree_Connect_AndX(
                Flags="EXTENDED_RESPONSE",
                Path=self.get("Path"),
                Service=self.get("Service"),
                Password=b"\0",
            )
        self.send(pkt)

    @ATMT.receive_condition(SENT_SETUP_ANDX_REQUEST)
    def receive_setup_andx_response(self, pkt):
        if SMBSession_Null in pkt or \
                SMBSession_Setup_AndX_Response_Extended_Security in pkt or \
                SMBSession_Setup_AndX_Response in pkt:
            # SMB1
            self.set_srv("Status", pkt[SMB_Header].Status)
            self.set_srv(
                "UID",
                pkt[SMB_Header].UID
            )
            self.set_srv(
                "MID",
                pkt[SMB_Header].MID
            )
            self.set_srv(
                "TID",
                pkt[SMB_Header].TID
            )
            if SMBSession_Null in pkt:
                # Likely an error
                self.received_ntlm_token((None, None, None))
                raise self.NEGOTIATED()
            elif SMBSession_Setup_AndX_Response_Extended_Security in pkt or \
                    SMBSession_Setup_AndX_Response in pkt:
                self.set_srv(
                    "NativeOS",
                    pkt.getfieldval(
                        "NativeOS")
                )
                self.set_srv(
                    "NativeLanMan",
                    pkt.getfieldval(
                        "NativeLanMan")
                )
        if SMB2_Session_Setup_Response in pkt:
            # SMB2
            self.set_srv("Status", pkt.Status)
            self.set_srv("SecuritySignature", pkt.SecuritySignature)
            self.set_srv("MessageId", pkt.MessageId)
            self.set_srv("AsyncId", pkt.AsyncId)
            self.set_srv("SessionId", pkt.SessionId)
        if SMBSession_Setup_AndX_Response_Extended_Security in pkt or \
                SMB2_Session_Setup_Response in pkt:
            # SMB1 extended / SMB2
            _, negResult, _ = ntlm_tuple = self._get_token(
                pkt.SecurityBlob
            )
            if negResult == 0:  # Authenticated
                self.received_ntlm_token(ntlm_tuple)
                raise self.AUTHENTICATED()
            else:
                self.received_ntlm_token(ntlm_tuple)
                raise self.NEGOTIATED().action_parameters(pkt)
        elif SMBSession_Setup_AndX_Response_Extended_Security in pkt:
            # SMB1 non-extended
            pass

    @ATMT.state()
    def AUTHENTICATED(self):
        pass

    @ATMT.condition(AUTHENTICATED)
    def should_run_script(self):
        if self.RUN_SCRIPT:
            raise self.DO_RUN_SCRIPT()

    @ATMT.receive_condition(AUTHENTICATED)
    def receive_packet(self, pkt):
        raise self.AUTHENTICATED().action_parameters(pkt)

    @ATMT.action(receive_packet)
    def pass_packet(self, pkt):
        self.echo(pkt)

    @ATMT.state(final=1)
    def DO_RUN_SCRIPT(self):
        # This is an example script, mostly unimplemented...
        # Tree connect
        self.smb_header.MessageId += 1
        self.send(
            self.smb_header.copy() /
            SMB2_Tree_Connect_Request(
                Buffer=[('Path', '\\\\%s\\IPC$' % self.REAL_HOSTNAME)]
            )
        )
        # Create srvsvc
        self.smb_header.MessageId += 1
        pkt = self.smb_header.copy()
        pkt.Command = "SMB2_CREATE"
        pkt /= Raw(load=b'9\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9f\x01\x12\x00\x00\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00x\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00s\x00r\x00v\x00s\x00v\x00c\x00')  # noqa: E501
        self.send(pkt)
        # ... run something?
        self.end()
