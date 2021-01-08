# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
SMB (Server Message Block), also known as CIFS.
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteEnumField, ByteField, FlagsField, \
    LEFieldLenField, LEIntField, LELongField, LEShortField, ShortField, \
    StrFixedLenField, StrLenField, StrNullField
from scapy.layers.netbios import NBTSession
from scapy.layers.smb2 import SMB2_Header


# SMB NetLogon Response Header
class SMBNetlogon_Protocol_Response_Header(Packet):
    name = "SMBNetlogon Protocol Response Header"
    fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4),
                   ByteEnumField("Command", 0x25, {0x25: "Trans"}),
                   ByteField("Error_Class", 0x02),
                   ByteField("Reserved", 0),
                   LEShortField("Error_code", 4),
                   ByteField("Flags", 0),
                   LEShortField("Flags2", 0x0000),
                   LEShortField("PIDHigh", 0x0000),
                   LELongField("Signature", 0x0),
                   LEShortField("Unused", 0x0),
                   LEShortField("TID", 0),
                   LEShortField("PID", 0),
                   LEShortField("UID", 0),
                   LEShortField("MID", 0),
                   ByteField("WordCount", 17),
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

# SMBNegociate Protocol Request Header


class SMBNegociate_Protocol_Request_Header(Packet):
    name = "SMBNegociate Protocol Request Header"
    fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4),
                   ByteEnumField("Command", 0x72, {0x72: "SMB_COM_NEGOTIATE"}),
                   ByteField("Error_Class", 0),
                   ByteField("Reserved", 0),
                   LEShortField("Error_code", 0),
                   ByteField("Flags", 0x18),
                   LEShortField("Flags2", 0x0000),
                   LEShortField("PIDHigh", 0x0000),
                   LELongField("Signature", 0x0),
                   LEShortField("Unused", 0x0),
                   LEShortField("TID", 0),
                   LEShortField("PID", 1),
                   LEShortField("UID", 0),
                   LEShortField("MID", 2),
                   ByteField("WordCount", 0),
                   LEShortField("ByteCount", 12)]

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
                return SMBNegociate_Protocol_Request_Header
            if _pkt[:4] == b'\xfeSMB':
                return SMB2_Header
        return cls

# SMB Negotiate Protocol Request Tail


class SMBNegociate_Protocol_Request_Tail(Packet):
    name = "SMB Negotiate Protocol Request Tail"
    fields_desc = [ByteField("BufferFormat", 0x02),
                   StrNullField("BufferData", "NT LM 0.12")]

# SMBNegociate Protocol Response Advanced Security


class SMBNegociate_Protocol_Response_Advanced_Security(Packet):
    name = "SMBNegociate Protocol Response Advanced Security"
    fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4),
                   ByteEnumField("Command", 0x72, {0x72: "SMB_COM_NEGOTIATE"}),
                   ByteField("Error_Class", 0),
                   ByteField("Reserved", 0),
                   LEShortField("Error_Code", 0),
                   ByteField("Flags", 0x98),
                   LEShortField("Flags2", 0x0000),
                   LEShortField("PIDHigh", 0x0000),
                   LELongField("Signature", 0x0),
                   LEShortField("Unused", 0x0),
                   LEShortField("TID", 0),
                   LEShortField("PID", 1),
                   LEShortField("UID", 0),
                   LEShortField("MID", 2),
                   ByteField("WordCount", 17),
                   LEShortField("DialectIndex", 7),
                   ByteField("SecurityMode", 0x03),
                   LEShortField("MaxMpxCount", 50),
                   LEShortField("MaxNumberVC", 1),
                   LEIntField("MaxBufferSize", 16144),
                   LEIntField("MaxRawSize", 65536),
                   LEIntField("SessionKey", 0x0000),
                   LEShortField("ServerCapabilities", 0xf3f9),
                   BitField("UnixExtensions", 0, 1),
                   BitField("Reserved2", 0, 7),
                   BitField("ExtendedSecurity", 1, 1),
                   BitField("CompBulk", 0, 2),
                   BitField("Reserved3", 0, 5),
                   # There have been 127490112000000000 tenths of micro-seconds between 1st january 1601 and 1st january 2005. 127490112000000000=0x1C4EF94D6228000, so ServerTimeHigh=0xD6228000 and ServerTimeLow=0x1C4EF94.  # noqa: E501
                   LEIntField("ServerTimeHigh", 0xD6228000),
                   LEIntField("ServerTimeLow", 0x1C4EF94),
                   LEShortField("ServerTimeZone", 0x3c),
                   ByteField("EncryptionKeyLength", 0),
                   LEFieldLenField("ByteCount", None, "SecurityBlob", adjust=lambda pkt, x: x - 16),  # noqa: E501
                   BitField("GUID", 0, 128),
                   StrLenField("SecurityBlob", "", length_from=lambda x: x.ByteCount + 16)]  # noqa: E501

# SMBNegociate Protocol Response No Security
# When using no security, with EncryptionKeyLength=8, you must have an EncryptionKey before the DomainName  # noqa: E501


class SMBNegociate_Protocol_Response_No_Security(Packet):
    name = "SMBNegociate Protocol Response No Security"
    fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4),
                   ByteEnumField("Command", 0x72, {0x72: "SMB_COM_NEGOTIATE"}),
                   ByteField("Error_Class", 0),
                   ByteField("Reserved", 0),
                   LEShortField("Error_Code", 0),
                   ByteField("Flags", 0x98),
                   LEShortField("Flags2", 0x0000),
                   LEShortField("PIDHigh", 0x0000),
                   LELongField("Signature", 0x0),
                   LEShortField("Unused", 0x0),
                   LEShortField("TID", 0),
                   LEShortField("PID", 1),
                   LEShortField("UID", 0),
                   LEShortField("MID", 2),
                   ByteField("WordCount", 17),
                   LEShortField("DialectIndex", 7),
                   ByteField("SecurityMode", 0x03),
                   LEShortField("MaxMpxCount", 50),
                   LEShortField("MaxNumberVC", 1),
                   LEIntField("MaxBufferSize", 16144),
                   LEIntField("MaxRawSize", 65536),
                   LEIntField("SessionKey", 0x0000),
                   LEShortField("ServerCapabilities", 0xf3f9),
                   BitField("UnixExtensions", 0, 1),
                   BitField("Reserved2", 0, 7),
                   BitField("ExtendedSecurity", 0, 1),
                   FlagsField("CompBulk", 0, 2, "CB"),
                   BitField("Reserved3", 0, 5),
                   # There have been 127490112000000000 tenths of micro-seconds between 1st january 1601 and 1st january 2005. 127490112000000000=0x1C4EF94D6228000, so ServerTimeHigh=0xD6228000 and ServerTimeLow=0x1C4EF94.  # noqa: E501
                   LEIntField("ServerTimeHigh", 0xD6228000),
                   LEIntField("ServerTimeLow", 0x1C4EF94),
                   LEShortField("ServerTimeZone", 0x3c),
                   ByteField("EncryptionKeyLength", 8),
                   LEShortField("ByteCount", 24),
                   BitField("EncryptionKey", 0, 64),
                   StrNullField("DomainName", "WORKGROUP"),
                   StrNullField("ServerName", "RMFF1")]

# SMBNegociate Protocol Response No Security No Key


class SMBNegociate_Protocol_Response_No_Security_No_Key(Packet):
    namez = "SMBNegociate Protocol Response No Security No Key"
    fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4),
                   ByteEnumField("Command", 0x72, {0x72: "SMB_COM_NEGOTIATE"}),
                   ByteField("Error_Class", 0),
                   ByteField("Reserved", 0),
                   LEShortField("Error_Code", 0),
                   ByteField("Flags", 0x98),
                   LEShortField("Flags2", 0x0000),
                   LEShortField("PIDHigh", 0x0000),
                   LELongField("Signature", 0x0),
                   LEShortField("Unused", 0x0),
                   LEShortField("TID", 0),
                   LEShortField("PID", 1),
                   LEShortField("UID", 0),
                   LEShortField("MID", 2),
                   ByteField("WordCount", 17),
                   LEShortField("DialectIndex", 7),
                   ByteField("SecurityMode", 0x03),
                   LEShortField("MaxMpxCount", 50),
                   LEShortField("MaxNumberVC", 1),
                   LEIntField("MaxBufferSize", 16144),
                   LEIntField("MaxRawSize", 65536),
                   LEIntField("SessionKey", 0x0000),
                   LEShortField("ServerCapabilities", 0xf3f9),
                   BitField("UnixExtensions", 0, 1),
                   BitField("Reserved2", 0, 7),
                   BitField("ExtendedSecurity", 0, 1),
                   FlagsField("CompBulk", 0, 2, "CB"),
                   BitField("Reserved3", 0, 5),
                   # There have been 127490112000000000 tenths of micro-seconds between 1st january 1601 and 1st january 2005. 127490112000000000=0x1C4EF94D6228000, so ServerTimeHigh=0xD6228000 and ServerTimeLow=0x1C4EF94.  # noqa: E501
                   LEIntField("ServerTimeHigh", 0xD6228000),
                   LEIntField("ServerTimeLow", 0x1C4EF94),
                   LEShortField("ServerTimeZone", 0x3c),
                   ByteField("EncryptionKeyLength", 0),
                   LEShortField("ByteCount", 16),
                   StrNullField("DomainName", "WORKGROUP"),
                   StrNullField("ServerName", "RMFF1")]

# Session Setup AndX Request


class SMBSession_Setup_AndX_Request(Packet):
    name = "Session Setup AndX Request"
    fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4),
                   ByteEnumField("Command", 0x73, {0x73: "SMB_COM_SESSION_SETUP_ANDX"}),  # noqa: E501
                   ByteField("Error_Class", 0),
                   ByteField("Reserved", 0),
                   LEShortField("Error_Code", 0),
                   ByteField("Flags", 0x18),
                   LEShortField("Flags2", 0x0001),
                   LEShortField("PIDHigh", 0x0000),
                   LELongField("Signature", 0x0),
                   LEShortField("Unused", 0x0),
                   LEShortField("TID", 0),
                   LEShortField("PID", 1),
                   LEShortField("UID", 0),
                   LEShortField("MID", 2),
                   ByteField("WordCount", 13),
                   ByteEnumField("AndXCommand", 0x75, {0x75: "SMB_COM_TREE_CONNECT_ANDX"}),  # noqa: E501
                   ByteField("Reserved2", 0),
                   LEShortField("AndXOffset", 96),
                   LEShortField("MaxBufferS", 2920),
                   LEShortField("MaxMPXCount", 50),
                   LEShortField("VCNumber", 0),
                   LEIntField("SessionKey", 0),
                   LEFieldLenField("ANSIPasswordLength", None, "ANSIPassword"),
                   LEShortField("UnicodePasswordLength", 0),
                   LEIntField("Reserved3", 0),
                   LEShortField("ServerCapabilities", 0x05),
                   BitField("UnixExtensions", 0, 1),
                   BitField("Reserved4", 0, 7),
                   BitField("ExtendedSecurity", 0, 1),
                   BitField("CompBulk", 0, 2),
                   BitField("Reserved5", 0, 5),
                   LEShortField("ByteCount", 35),
                   StrLenField("ANSIPassword", "Pass", length_from=lambda x: x.ANSIPasswordLength),  # noqa: E501
                   StrNullField("Account", "GUEST"),
                   StrNullField("PrimaryDomain", ""),
                   StrNullField("NativeOS", "Windows 4.0"),
                   StrNullField("NativeLanManager", "Windows 4.0"),
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

# Session Setup AndX Response


class SMBSession_Setup_AndX_Response(Packet):
    name = "Session Setup AndX Response"
    fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4),
                   ByteEnumField("Command", 0x73, {0x73: "SMB_COM_SESSION_SETUP_ANDX"}),  # noqa: E501
                   ByteField("Error_Class", 0),
                   ByteField("Reserved", 0),
                   LEShortField("Error_Code", 0),
                   ByteField("Flags", 0x90),
                   LEShortField("Flags2", 0x1001),
                   LEShortField("PIDHigh", 0x0000),
                   LELongField("Signature", 0x0),
                   LEShortField("Unused", 0x0),
                   LEShortField("TID", 0),
                   LEShortField("PID", 1),
                   LEShortField("UID", 0),
                   LEShortField("MID", 2),
                   ByteField("WordCount", 3),
                   ByteEnumField("AndXCommand", 0x75, {0x75: "SMB_COM_TREE_CONNECT_ANDX"}),  # noqa: E501
                   ByteField("Reserved2", 0),
                   LEShortField("AndXOffset", 66),
                   LEShortField("Action", 0),
                   LEShortField("ByteCount", 25),
                   StrNullField("NativeOS", "Windows 4.0"),
                   StrNullField("NativeLanManager", "Windows 4.0"),
                   StrNullField("PrimaryDomain", ""),
                   ByteField("WordCount2", 3),
                   ByteEnumField("AndXCommand2", 0xFF, {0xFF: "SMB_COM_NONE"}),
                   ByteField("Reserved3", 0),
                   LEShortField("AndXOffset2", 80),
                   LEShortField("OptionalSupport", 0x01),
                   LEShortField("ByteCount2", 5),
                   StrNullField("Service", "IPC"),
                   StrNullField("NativeFileSystem", "")]


bind_layers(NBTSession, SMBNegociate_Protocol_Request_Header_Generic, )
bind_layers(NBTSession, SMBNegociate_Protocol_Response_Advanced_Security, ExtendedSecurity=1)  # noqa: E501
bind_layers(NBTSession, SMBNegociate_Protocol_Response_No_Security, ExtendedSecurity=0, EncryptionKeyLength=8)  # noqa: E501
bind_layers(NBTSession, SMBNegociate_Protocol_Response_No_Security_No_Key, ExtendedSecurity=0, EncryptionKeyLength=0)  # noqa: E501
bind_layers(NBTSession, SMBSession_Setup_AndX_Request, )
bind_layers(NBTSession, SMBSession_Setup_AndX_Response, )
bind_layers(SMBNegociate_Protocol_Request_Header, SMBNegociate_Protocol_Request_Tail, )  # noqa: E501
bind_layers(SMBNegociate_Protocol_Request_Tail, SMBNegociate_Protocol_Request_Tail, )  # noqa: E501
