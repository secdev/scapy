# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
SMB (Server Message Block), also known as CIFS.

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
    FlagsField,
    LEFieldLenField,
    LEIntField,
    LELongField,
    LEShortField,
    MultipleTypeField,
    PacketLenField,
    PacketListField,
    ReversePadField,
    ShortField,
    StrFixedLenField,
    StrLenField,
    StrNullField,
    StrNullFieldUtf16,
    UTCTimeField,
    UUIDField,
    XStrLenField,
)
from scapy.layers.netbios import NBTSession
from scapy.layers.gssapi import GSSAPI_BLOB
from scapy.layers.smb2 import SMB2_Header

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
                   LELongField("SecurityFeatures", 0x0),
                   LEShortField("Reserved", 0x0),
                   LEShortField("TID", 0),
                   LEShortField("PID", 1),
                   LEShortField("UID", 0),
                   LEShortField("MID", 2)]

    def guess_payload_class(self, payload):
        # type: (bytes) -> Packet
        if self.Command == 0x72:
            if self.Flags.REPLY:
                if self.Flags2.EXTENDED_SECURITY:
                    return SMBNegotiate_Response_Extended_Security
                else:
                    return SMBNegotiate_Response_Security
            else:
                return SMBNegotiate_Request
        elif self.Command == 0x73:
            if self.Flags.REPLY:
                if self.Flags2.EXTENDED_SECURITY:
                    return SMBSession_Setup_AndX_Response_Extended_Security
                else:
                    return SMBSession_Setup_AndX_Response
            else:
                if self.Flags2.EXTENDED_SECURITY:
                    return SMBSession_Setup_AndX_Request_Extended_Security
                else:
                    return SMBSession_Setup_AndX_Request
        elif self.Command == 0x25:
            return SMBNetlogon_Protocol_Response_Header
        return super(SMB_Header, self).guess_payload_class(payload)

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
                   LEFieldLenField("ByteCount", None, length_of="Dialects",
                                   adjust=lambda pkt, x: x + 1),
                   PacketListField(
                       "Dialects", [SMB_Dialect()], SMB_Dialect,
                       length_from=lambda pkt: pkt.ByteCount)
                   ]


bind_layers(SMB_Header, SMBNegotiate_Request, Command=0x72)

# SMBNegociate Protocol Response


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
                   LEIntField("MaxBufferSize", 16144),
                   LEIntField("MaxRawSize", 65536),
                   LEIntField("SessionKey", 0x0000),
                   FlagsField("ServerCapabilities", 0xf3f9, -32,
                              _SMB_ServerCapabilities),
                   UTCTimeField("ServerTime", None, fmt="<Q",
                                epoch=[1601, 1, 1, 0, 0, 0],
                                custom_scaling=1e7),
                   LEShortField("ServerTimeZone", 0x3c),
                   ByteField("ChallengeLength", 0),  # aka EncryptionKeyLength
                   LEFieldLenField("ByteCount", None, length_of="DomainName",
                                   adjust=lambda pkt, x: x +
                                   len(pkt.Challenge)),
                   StrLenField("Challenge", b"",  # aka EncryptionKey
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
                        adjust=lambda pkt, x: x + len(pkt.Challenge) +
                        len(pkt.ServerName)),
        StrLenField("Challenge", b"",  # aka EncryptionKey
                    length_from=lambda pkt: pkt.ChallengeLength),
        StrNullField("DomainName", "WORKGROUP"),
        StrNullFieldUtf16("ServerName", "RMFF1")
    ]


bind_top_down(SMB_Header, SMBNegotiate_Response_Security,
              Command=0x72, Flags=0x80)

# Session Setup AndX Request

# CIFS sect 2.2.4.53


def _SMBStrNullField(name, default):
    return MultipleTypeField(
        [
            (StrNullFieldUtf16(name, default),
             lambda pkt: hasattr(pkt.underlayer, "Flags2") and
             pkt.underlayer.Flags2.UNICODE)
        ],
        StrNullField(name, default),
    )


class SMBSession_Setup_AndX_Request(Packet):
    name = "Session Setup AndX Request (CIFS)"
    fields_desc = [
        ByteField("WordCount", 13),
        ByteEnumField("AndXCommand", 0x75,
                      SMB_COM),
        ByteField("AndXReserved", 0),
        LEShortField("AndXOffset", 96),
        LEShortField("MaxBufferSize", 2920),
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
        LEShortField("ByteCount", 35),
        XStrLenField("OEMPassword", "Pass",
                     length_from=lambda x: x.OEMPasswordLength),
        XStrLenField("UnicodePassword", "Pass",
                     length_from=lambda x: x.UnicodePasswordLength),
        ReversePadField(
            StrNullField("AccountName", "GUEST"), 2, b"\0"
        ),
        _SMBStrNullField("PrimaryDomain", ""),
        _SMBStrNullField("NativeOS", "Windows 4.0"),
        _SMBStrNullField("NativeLanMan", "Windows 4.0"),
        # Off spec?
        ByteField("WordCount2", 4),
        ByteEnumField("AndXCommand2", 0xFF, {0xFF: "SMB_COM_NONE"}),
        ByteField("Reserved6", 0),
        LEShortField("AndXOffset2", 0),
        LEShortField("Flags3", 0x2),
        LEShortField("PasswordLength", 0x1),
        LEShortField("ByteCount2", 18),
        ByteField("Password", 0),
        StrNullField("Path", "\\\\WIN2K\\IPC$"),
        StrNullField("Service", "IPC")]


bind_top_down(SMB_Header, SMBSession_Setup_AndX_Request,
              Command=0x73)

# SMB sect 2.2.4.6.1


class SMBSession_Setup_AndX_Request_Extended_Security(Packet):
    name = "Session Setup AndX Extended Security Request (SMB)"
    fields_desc = SMBSession_Setup_AndX_Request.fields_desc[:8] + [
        LEFieldLenField("SecurityBlobLength", None,
                        length_of="SecurityBlob"),
    ] + SMBSession_Setup_AndX_Request.fields_desc[10:12] + [
        LEShortField("ByteCount", 35),
        PacketLenField("SecurityBlob", None, GSSAPI_BLOB,
                       length_from=lambda x: x.SecurityBlobLength),
        ReversePadField(
            _SMBStrNullField("NativeOS", "Windows 4.0"),
            2, b"\0",
        ),
        _SMBStrNullField("NativeLanMan", "Windows 4.0"),
    ]


bind_top_down(SMB_Header, SMBSession_Setup_AndX_Request_Extended_Security,
              Command=0x73, Flags2=0x800)

# Session Setup AndX Response


# CIFS sect 2.2.4.53.2

class SMBSession_Setup_AndX_Response(Packet):
    name = "Session Setup AndX Response (CIFS)"
    fields_desc = [
        ByteField("WordCount", 3),
        ByteEnumField("AndXCommand", 0x75,
                      SMB_COM),
        ByteField("AndXReserved", 0),
        LEShortField("AndXOffset", 66),
        LEShortField("Action", 0),
        LEShortField("ByteCount", 25),
        _SMBStrNullField("NativeOS", "Windows 4.0"),
        _SMBStrNullField("NativeLanManager", "Windows 4.0"),
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


bind_top_down(SMB_Header, SMBSession_Setup_AndX_Response,
              Command=0x73, Flags=0x80)

# SMB sect 2.2.4.6.2


class SMBSession_Setup_AndX_Response_Extended_Security(Packet):
    name = "Session Setup AndX Extended Security Response (SMB)"
    WordCount = 7
    fields_desc = SMBSession_Setup_AndX_Response.fields_desc[:5] + [
        LEFieldLenField("SecurityBlobLength", None,
                        length_of="SecurityBlob"),
        LEShortField("ByteCount", 25),
        PacketLenField("SecurityBlob", None, GSSAPI_BLOB,
                       length_from=lambda x: x.SecurityBlobLength),
        ReversePadField(
            _SMBStrNullField("NativeOS", "Windows 4.0"),
            2, b"\0",
        ),
        _SMBStrNullField("NativeLanMan", "Windows 4.0")]


bind_top_down(SMB_Header, SMBSession_Setup_AndX_Response_Extended_Security,
              Command=0x73, Flags=0x80, Flags2=0x800)

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
    fields_desc = [ByteEnumField("Command", 0x17, {0x12: "SAM logon request", 0x17: "SAM Active directory Response"}),  # noqa: E501
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
