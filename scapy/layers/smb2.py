# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
SMB (Server Message Block), also known as CIFS - version 2
"""

import struct

from scapy.config import conf
from scapy.error import log_runtime
from scapy.packet import Packet, bind_layers, bind_top_down
from scapy.fields import (
    ByteEnumField,
    ByteField,
    ConditionalField,
    FieldLenField,
    FieldListField,
    FlagsField,
    IntEnumField,
    IntField,
    LEIntField,
    LEIntEnumField,
    LELongField,
    LEShortEnumField,
    LEShortField,
    MultipleTypeField,
    PadField,
    PacketField,
    PacketLenField,
    PacketListField,
    ReversePadField,
    ShortEnumField,
    ShortField,
    StrFieldUtf16,
    StrFixedLenField,
    StrLenFieldUtf16,
    StrLenField,
    StrNullFieldUtf16,
    UTCTimeField,
    UUIDField,
    XLEIntField,
    XLELongField,
    XLEShortField,
    XStrLenField,
    XStrFixedLenField,
)

from scapy.layers.netbios import NBTSession
from scapy.layers.gssapi import GSSAPI_BLOB
from scapy.layers.ntlm import _NTLMPayloadField, _NTLMPayloadPacket


# EnumField
SMB_DIALECTS = {
    0x0202: 'SMB 2.002',
    0x0210: 'SMB 2.1',
    0x02ff: 'SMB 2.???',
    0x0300: 'SMB 3.0',
    0x0302: 'SMB 3.0.2',
    0x0311: 'SMB 3.1.1',
}

# SMB2 sect 3.3.5.15 + [MS-ERREF]
STATUS_ERREF = {
    0x00000000: "STATUS_SUCCESS",
    0x00000103: "STATUS_PENDING",
    0x0000010C: "STATUS_NOTIFY_ENUM_DIR",
    0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
    0xC0000120: "STATUS_CANCELLED",
    0xC0000128: "STATUS_FILE_CLOSED",  # backup error for older Win versions
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC000000F: "STATUS_NO_SUCH_FILE",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC000019C: "STATUS_FS_DRIVER_REQUIRED",
    0xC0000225: "STATUS_NOT_FOUND",
    0x80000005: "STATUS_BUFFER_OVERFLOW",
    0x80000006: "STATUS_NO_MORE_FILES",
}

# SMB2 sect 2.2.1.1
SMB2_COM = {
    0x0000: "SMB2_NEGOTIATE",
    0x0001: "SMB2_SESSION_SETUP",
    0x0002: "SMB2_LOGOFF",
    0x0003: "SMB2_TREE_CONNECT",
    0x0004: "SMB2_TREE_DISCONNECT",
    0x0005: "SMB2_CREATE",
    0x0006: "SMB2_CLOSE",
    0x0007: "SMB2_FLUSH",
    0x0008: "SMB2_READ",
    0x0009: "SMB2_WRITE",
    0x000A: "SMB2_LOCK",
    0x000B: "SMB2_IOCTL",
    0x000C: "SMB2_CANCEL",
    0x000D: "SMB2_ECHO",
    0x000E: "SMB2_QUERY_DIRECTORY",
    0x000F: "SMB2_CHANGE_NOTIFY",
    0x0010: "SMB2_QUERY_INFO",
    0x0011: "SMB2_SET_INFO",
    0x0012: "SMB2_OPLOCK_BREAK",
}

# EnumField
SMB2_NEGOTIATE_CONTEXT_TYPES = {
    0x0001: 'SMB2_PREAUTH_INTEGRITY_CAPABILITIES',
    0x0002: 'SMB2_ENCRYPTION_CAPABILITIES',
    0x0003: 'SMB2_COMPRESSION_CAPABILITIES',
    0x0005: 'SMB2_NETNAME_NEGOTIATE_CONTEXT_ID',
    0x0006: 'SMB2_TRANSPORT_CAPABILITIES',
    0x0007: 'SMB2_RDMA_TRANSFORM_CAPABILITIES',
    0x0008: 'SMB2_SIGNING_CAPABILITIES',
}

# FlagField
SMB2_CAPABILITIES = {
    0x00000001: "DFS",
    0x00000002: "Leasing",
    0x00000004: "LargeMTU",
    0x00000008: "MultiChannel",
    0x00000010: "PersistentHandles",
    0x00000020: "DirectoryLeasing",
    0x00000040: "Encryption",

}

# EnumField
SMB2_COMPRESSION_ALGORITHMS = {
    0x0000: "None",
    0x0001: "LZNT1",
    0x0002: "LZ77",
    0x0003: "LZ77 + Huffman",
    0x0004: "Pattern_V1",
}


# [MS-FSCC] sec 2.6
FileAttributes = {
    0x00000001: "FILE_ATTRIBUTE_READONLY",
    0x00000002: "FILE_ATTRIBUTE_HIDDEN",
    0x00000004: "FILE_ATTRIBUTE_SYSTEM",
    0x00000010: "FILE_ATTRIBUTE_DIRECTORY",
    0x00000020: "FILE_ATTRIBUTE_ARCHIVE",
    0x00000080: "FILE_ATTRIBUTE_NORMAL",
    0x00000100: "FILE_ATTRIBUTE_TEMPORARY",
    0x00000200: "FILE_ATTRIBUTE_SPARSE_FILE",
    0x00000400: "FILE_ATTRIBUTE_REPARSE_POINT",
    0x00000800: "FILE_ATTRIBUTE_COMPRESSED",
    0x00001000: "FILE_ATTRIBUTE_OFFLINE",
    0x00002000: "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED",
    0x00004000: "FILE_ATTRIBUTE_ENCRYPTED",
    0x00008000: "FILE_ATTRIBUTE_INTEGRITY_STREAM",
    0x00020000: "FILE_ATTRIBUTE_NO_SCRUB_DATA",
    0x00040000: "FILE_ATTRIBUTE_RECALL_ON_OPEN",
    0x00080000: "FILE_ATTRIBUTE_PINNED",
    0x00100000: "FILE_ATTRIBUTE_UNPINNED",
    0x00400000: "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS",
}


# [MS-FSCC] sect 2.4
FileInformationClasses = {
    0x01: "FileDirectoryInformation",
    0x02: "FileFullDirectoryInformation",
    0x03: "FileBothDirectoryInformation",
    0x05: "FileStandardInformation",
    0x06: "FileInternalInformation",
    0x07: "FileEaInformation",
    0x22: "FileNetworkOpenInformation",
    0x25: "FileIdBothDirectoryInformation",
    0x26: "FileIdFullDirectoryInformation",
    0x0C: "FileNamesInformation",
    0x3C: "FileIdExtdDirectoryInformation",
}


# [MS-FSCC] 2.4.12 FileEaInformation

class FileEaInformation(Packet):
    fields_desc = [
        LEIntField("EaSize", 0),
    ]


# [MS-FSCC] 2.4.29 FileNetworkOpenInformation


class FileNetworkOpenInformation(Packet):
    fields_desc = [
        UTCTimeField("CreationTime", None, fmt="<Q",
                     epoch=[1601, 1, 1, 0, 0, 0],
                     custom_scaling=1e7),
        UTCTimeField("LastAccessTime", None, fmt="<Q",
                     epoch=[1601, 1, 1, 0, 0, 0],
                     custom_scaling=1e7),
        UTCTimeField("LastWriteTime", None, fmt="<Q",
                     epoch=[1601, 1, 1, 0, 0, 0],
                     custom_scaling=1e7),
        UTCTimeField("ChangeTime", None, fmt="<Q",
                     epoch=[1601, 1, 1, 0, 0, 0],
                     custom_scaling=1e7),
        LELongField("AllocationSize", 4096),
        LELongField("EnfofFile", 4096),
        FlagsField("FileAttributes", 0x00000080, -32, FileAttributes),
        IntField("Reserved2", 0),
    ]

# [MS-FSCC] 2.4.17 FileIdBothDirectoryInformation


class FILE_ID_BOTH_DIR_INFORMATION(Packet):
    fields_desc = [
        LEIntField("Next", None),  # 0 = no next entry
        LEIntField("FileIndex", 0),
    ] + FileNetworkOpenInformation.fields_desc[:7] + [
        FieldLenField("FileNameLength", None, fmt="<I", length_of="FileName"),
        LEIntField("EaSize", 0),
        ByteField("ShortNameLength", 0),
        ByteField("Reserved1", 0),
        StrFixedLenField("ShortName", b"", length=24),
        LEShortField("Reserved2", 0),
        LELongField("FileId", 0),
        PadField(
            StrLenFieldUtf16(
                "FileName",
                b".",
                length_from=lambda pkt: pkt.FileNameLength
            ),
            align=8,
        ),
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


class _NextPacketListField(PacketListField):
    def addfield(self, pkt, s, val):
        # we use this field to set NextEntryOffset
        res = b""
        for i, v in enumerate(val):
            x = self.i2m(pkt, v)
            if v.Next is None and i != len(val) - 1:
                x = struct.pack("<I", len(x)) + x[4:]
            res += x
        return s + res


class FileIdBothDirectoryInformation(Packet):
    fields_desc = [
        _NextPacketListField("files", [], FILE_ID_BOTH_DIR_INFORMATION),
    ]

# [MS-FSCC] 2.4.22 FileInternalInformation


class FileInternalInformation(Packet):
    fields_desc = [
        LELongField("IndexNumber", 0),
    ]

# [MS-FSCC] 2.4.41 FileStandardInformation


class FileStandardInformation(Packet):
    fields_desc = [
        LELongField("AllocationSize", 4096),
        LELongField("EndOfFile", 0),
        LEIntField("NumberOfLinks", 1),
        ByteField("DeletePending", 0),
        ByteField("Directory", 0),
        ShortField("Reserved", 0),
    ]

# [MS-FSCC] 2.4.43 FileStreamInformation


class FileStreamInformation(Packet):
    fields_desc = [
        LEIntField("Next", 0),
        FieldLenField("StreamNameLength", None, length_of="StreamName", fmt="<I"),
        LELongField("StreamSize", 0),
        LELongField("StreamAllocationSize", 0),
        StrLenFieldUtf16("StreamName", b"::$DATA",
                         length_from=lambda pkt: pkt.StreamNameLength)
    ]

# [MS-DTYP] 2.4.6 SECURITY_DESCRIPTOR


class SECURITY_DESCRIPTOR(Packet):
    fields_desc = [
        ByteField("Revision", 0x01),
        ByteField("Sbz1", 0x00),
        FlagsField("Control", 0x00, -16, [
            "SelfRelative",
            "RMControlValid",
            "SACLProtected",
            "DACLProtected",
            "SACLAutoInherited",
            "DACLAutoInheriter",
            "SACLComputer",
            "DACLComputer",
            "ServerSecurity",
            "DACLTrusted",
            "SACLDefaulted",
            "SACLPresent",
            "DACLDefaulted",
            "DACLPresent",
            "GroupDefaulted",
            "OwnerDefaulted",
        ]),
        LEIntField("OffsetOwner", 0),
        LEIntField("OffsetGroup", 0),
        LEIntField("OffsetSacl", 0),
        LEIntField("OffsetDacl", 0),
        ConditionalField(
            XStrLenField("OwnerSid", b""),
            lambda pkt: pkt.OffsetOwner
        ),
        ConditionalField(
            XStrLenField("GroupSid", b""),
            lambda pkt: pkt.OffsetGroup
        ),
        ConditionalField(
            XStrLenField("Sacl", b""),
            lambda pkt: pkt.Control.SACLPresent,
        ),
        ConditionalField(
            XStrLenField("Dacl", b""),
            lambda pkt: pkt.Control.DACLPresent,
        )
    ]

# [MS-FSCC] 2.5.1 FileFsAttributeInformation


class FileFsAttributeInformation(Packet):
    fields_desc = [
        FlagsField("FileSystemAttributes", 0x80000f, -32, {
            0x02000000: "FILE_SUPPORTS_USN_JOURNAL",
            0x01000000: "FILE_SUPPORTS_OPEN_BY_FILE_ID",
            0x00800000: "FILE_SUPPORTS_EXTENDED_ATTRIBUTES",
            0x00400000: "FILE_SUPPORTS_HARD_LINKS",
            0x00200000: "FILE_SUPPORTS_TRANSACTIONS",
            0x00100000: "FILE_SEQUENTIAL_WRITE_ONCE",
            0x00080000: "FILE_READ_ONLY_VOLUME",
            0x00040000: "FILE_NAMED_STREAMS",
            0x00020000: "FILE_SUPPORTS_ENCRYPTION",
            0x00010000: "FILE_SUPPORTS_OBJECT_IDS",
            0x00008000: "FILE_VOLUME_IS_COMPRESSED",
            0x00000100: "FILE_SUPPORTS_REMOTE_STORAGE",
            0x00000080: "FILE_SUPPORTS_REPARSE_POINTS",
            0x00000040: "FILE_SUPPORTS_SPARSE_FILES",
            0x00000020: "FILE_VOLUME_QUOTAS",
            0x00000010: "FILE_FILE_COMPRESSION",
            0x00000008: "FILE_PERSISTENT_ACLS",
            0x00000004: "FILE_UNICODE_ON_DISK",
            0x00000002: "FILE_CASE_PRESERVED_NAMES",
            0x00000001: "FILE_CASE_SENSITIVE_SEARCH",
            0x04000000: "FILE_SUPPORT_INTEGRITY_STREAMS",
            0x08000000: "FILE_SUPPORTS_BLOCK_REFCOUNTING",
            0x10000000: "FILE_SUPPORTS_SPARSE_VDL",
        }),
        LEIntField("MaximumComponentNameLength", 255),
        FieldLenField("FileSystemNameLength", None,
                      length_of="FileSystemName", fmt="<I"),
        StrLenFieldUtf16("FileSystemName", b"NTFS",
                         length_from=lambda pkt: pkt.FileSystemNameLength),
    ]

# [MS-FSCC] 2.5.8 FileFsSizeInformation


class FileFsSizeInformation(Packet):
    fields_desc = [
        LELongField("TotalAllocationUnits", 10485760),
        LELongField("AvailableAllocationUnits", 1048576),
        LEIntField("SectorsPerAllocationUnit", 8),
        LEIntField("BytesPerSector", 512),
    ]

# [MS-FSCC] 2.5.9 FileFsVolumeInformation


class FileFsVolumeInformation(Packet):
    fields_desc = [
        UTCTimeField("VolumeCreationTime", None, fmt="<Q",
                     epoch=[1601, 1, 1, 0, 0, 0],
                     custom_scaling=1e7),
        LEIntField("VolumeSerialNumber", 0),
        LEIntField("VolumeLabelLength", 0),
        ByteField("SupportsObjects", 1),
        ByteField("Reserved", 0),
        StrNullFieldUtf16("VolumeLabel", b"C"),
    ]


def _SMB2_post_build(self, p, pay_offset, fields):
    """Util function to build the offset and populate the lengths"""
    for field_name, offset in fields.items():
        try:
            value = next(x[1] for x in self.fields["Buffer"] if x[0] == field_name)
            length = self.get_field(
                "Buffer").fields_map[field_name].i2len(self, value)
        except StopIteration:
            length = 0
        i = 0
        r = lambda y: {2: "H", 4: "I", 8: "Q"}[y]
        # Offset
        if self.getfieldval(field_name + "BufferOffset") is None:
            sz = self.get_field(field_name + "BufferOffset").sz
            p = p[:offset + i] + \
                struct.pack("<%s" % r(sz), pay_offset) + p[offset + sz:]
            i += sz
        # Len
        if self.getfieldval(field_name + "Len") is None:
            sz = self.get_field(field_name + "Len").sz
            p = p[:offset + i] + \
                struct.pack("<%s" % r(sz), length) + p[offset + i + sz:]
            i += sz
        pay_offset += length
    return p

# SMB2 sect 2.2.1.1


class SMB2_Header(Packet):
    name = "SMB2 Header"
    fields_desc = [
        StrFixedLenField("Start", b"\xfeSMB", 4),
        LEShortField("StructureSize", 64),
        LEShortField("CreditCharge", 0),
        LEIntEnumField("Status", 0, STATUS_ERREF),
        LEShortEnumField("Command", 0, SMB2_COM),
        LEShortField("CreditsRequested", 0),
        FlagsField("Flags", 0, -32, {
            0x00000001: "SMB2_FLAGS_SERVER_TO_REDIR",
            0x00000002: "SMB2_FLAGS_ASYNC_COMMAND",
            0x00000004: "SMB2_FLAGS_RELATED_OPERATIONS",
            0x00000008: "SMB2_FLAGS_SIGNED",
            0x10000000: "SMB2_FLAGS_DFS_OPERATIONS",
            0x20000000: "SMB2_FLAGS_REPLAY_OPERATION",
        }),
        XLEIntField("NextCommand", 0),
        LELongField("MID", 0),  # MessageID
        # ASYNC
        ConditionalField(
            LELongField("AsyncId", 0),
            lambda pkt: pkt.Flags.SMB2_FLAGS_ASYNC_COMMAND),
        # SYNC
        ConditionalField(
            LEIntField("PID", 0),  # Reserved, but PID per wireshark
            lambda pkt: not pkt.Flags.SMB2_FLAGS_ASYNC_COMMAND),
        ConditionalField(
            LEIntField("TID", 0),  # TreeID
            lambda pkt: not pkt.Flags.SMB2_FLAGS_ASYNC_COMMAND),
        # COMMON
        LELongField("SessionId", 0),
        XStrFixedLenField("SecuritySignature", 0, length=16),
    ]

    _SMB2_OK_RETURNCODES = (
        # sect 3.3.4.4
        0x00000000,  # SUCCESS
        0xC0000016,  # STATUS_MORE_PROCESSING_REQUIRED
        0x80000005,  # STATUS_BUFFER_OVERFLOW
        0xC000000D,  # STATUS_INVALID_PARAMETER
        0x0000010C,  # STATUS_NOTIFY_ENUM_DIR
    )

    def guess_payload_class(self, payload):
        if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
            # Check status for responses
            if self.Status not in SMB2_Header._SMB2_OK_RETURNCODES:
                return SMB2_Error_Response
        if self.Command == 0x0000:  # Negotiate
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Negotiate_Protocol_Response
            return SMB2_Negotiate_Protocol_Request
        elif self.Command == 0x0001:  # Setup
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Session_Setup_Response
            return SMB2_Session_Setup_Request
        elif self.Command == 0x0002:  # Logoff
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Session_Logoff_Response
            return SMB2_Session_Logoff_Request
        elif self.Command == 0x0003:  # TREE connect
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Tree_Connect_Response
            return SMB2_Tree_Connect_Request
        elif self.Command == 0x0004:  # TREE disconnect
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Tree_Disconnect_Response
            return SMB2_Tree_Disconnect_Request
        elif self.Command == 0x0005:  # Create
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Create_Response
            return SMB2_Create_Request
        elif self.Command == 0x0006:  # Close
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Close_Response
            return SMB2_Close_Request
        elif self.Command == 0x0008:  # Read
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Read_Response
            return SMB2_Read_Request
        elif self.Command == 0x0009:  # Write
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Write_Response
            return SMB2_Write_Request
        elif self.Command == 0x000C:  # Cancel
            return SMB2_Cancel_Request
        elif self.Command == 0x000E:  # Query directory
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Query_Directory_Response
            return SMB2_Query_Directory_Request
        elif self.Command == 0x000F:  # Change Notify
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Change_Notify_Response
            return SMB2_Change_Notify_Request
        elif self.Command == 0x0010:  # Query info
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Query_Info_Response
            return SMB2_Query_Info_Request
        elif self.Command == 0x000B:  # IOCTL
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_IOCTL_Response
            return SMB2_IOCTL_Request
        return super(SMB2_Header, self).guess_payload_class(payload)

    def sign(self, dialect, SigningSessionKey):
        self.SecuritySignature = b"\x00" * 16
        s = bytes(self)
        if len(s) <= 64:
            log_runtime.warning("Cannot sign invalid SMB packet !")
            return s
        if dialect == 0x0311:  # SMB 3.1.1
            raise Exception("SMB 3.1.1 signing unimplemented")
        elif dialect in [0x0300, 0x0302]:  # other SMB 3
            from cryptography.hazmat.primitives import cmac
            from cryptography.hazmat.primitives.ciphers import algorithms
            c = cmac.CMAC(algorithms.AES(SigningSessionKey))
            c.update(s)
            sig = c.finalize()
        elif dialect in [0x0210, 0x0202]:  # SMB 2.1 or SMB 2.0.2
            from scapy.layers.tls.crypto.h_mac import Hmac_SHA256
            sig = Hmac_SHA256(SigningSessionKey).digest(s)
            sig = sig[:16]
        else:
            log_runtime.warning(
                "Unknown SMB Version %s ! Cannot sign." % dialect)
            sig = s[:-16] + b"\x00" * 16
        self.SecuritySignature = sig


class _SMB2_Payload(Packet):
    def do_dissect_payload(self, s):
        # There can be padding between this layer and the next one
        if self.underlayer and isinstance(self.underlayer, SMB2_Header):
            if self.underlayer.NextCommand:
                padlen = self.underlayer.NextCommand - (64 + len(self.raw_packet_cache))
                if padlen:
                    self.add_payload(conf.padding_layer(s[:padlen]))
                    s = s[padlen:]
        super(_SMB2_Payload, self).do_dissect_payload(s)

    def guess_payload_class(self, s):
        if self.underlayer and isinstance(self.underlayer, SMB2_Header):
            if self.underlayer.NextCommand:
                return SMB2_Header
        return NBTSession


# sect 2.2.2


class SMB2_Error_Response(_SMB2_Payload):
    name = "SMB2 Error Response"
    fields_desc = [
        XLEShortField("StructureSize", 0x09),
        ByteField("ErrorContextCount", 0),
        ByteField("Reserved", 0),
        FieldLenField(
            "ByteCount", None,
            fmt="<I",
            length_of="ErrorData"
        ),
        XStrLenField("ErrorData", b"",
                     length_from=lambda pkt: pkt.ByteCount)
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Error_Response,
    Flags=1  # SMB2_FLAGS_SERVER_TO_REDIR
)

# sect 2.2.3


class SMB2_Negotiate_Context(Packet):
    name = "SMB2 Negotiate Context"
    fields_desc = [
        LEShortEnumField("ContextType", 0x0, SMB2_NEGOTIATE_CONTEXT_TYPES),
        FieldLenField("DataLength", 0x0, fmt="<H", length_of="Data"),
        IntField("Reserved", 0),
    ]


class SMB2_Negotiate_Protocol_Request(_SMB2_Payload):
    name = "SMB2 Negotiate Protocol Request"
    fields_desc = [
        XLEShortField("StructureSize", 0x24),
        FieldLenField(
            "DialectCount", None,
            fmt="<H",
            count_of="Dialects"
        ),
        # SecurityMode
        FlagsField("SecurityMode", 0, -16, {
            0x01: "SMB2_NEGOTIATE_SIGNING_ENABLED",
            0x02: "SMB2_NEGOTIATE_SIGNING_REQUIRED",
        }),
        LEShortField("Reserved", 0),
        # Capabilities
        FlagsField("Capabilities", 0, -32, SMB2_CAPABILITIES),
        UUIDField("ClientGUID", 0x0, uuid_fmt=UUIDField.FORMAT_LE),
        # XXX TODO If we ever want to properly dissect the offsets, we have
        # a _NTLMPayloadField in scapy/layers/ntlm.py that does precisely that
        XLEIntField("NegotiateContextOffset", 0x0),
        FieldLenField(
            "NegotiateCount", None,
            fmt="<H",
            count_of="NegotiateContexts"
        ),
        ShortField("Reserved2", 0),
        FieldListField(
            "Dialects", [0x0202],
            LEShortEnumField("", 0x0, SMB_DIALECTS),
            count_from=lambda pkt: pkt.DialectCount
        ),
        # Field only exists if Dialects contains 0x0311
        # Each negotiate context must be 8-byte aligned
        ConditionalField(
            FieldListField(
                "NegotiateContexts", [],
                ReversePadField(
                    PacketField("Context", None, SMB2_Negotiate_Context), 8
                ), count_from=lambda pkt: pkt.NegotiateCount
            ), lambda x: 0x0311 in x.Dialects
        ),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Negotiate_Protocol_Request,
    Command=0x0000,
)

# sect 2.2.3.1.1


class SMB2_Preauth_Integrity_Capabilities(Packet):
    name = "SMB2 Preauth Integrity Capabilities"
    fields_desc = [
        # According to the spec, this field value must be greater than 0
        # (cf Section 2.2.3.1.1 of MS-SMB2.pdf)
        FieldLenField(
            "HashAlgorithmCount", 1,
            fmt="<H",
            count_of="HashAlgorithms"
        ),
        FieldLenField("SaltLength", 0, fmt="<H", length_of="Salt"),
        FieldListField("HashAlgorithms", [0x0001], LEShortEnumField("", 0x0, {
            # As for today, no other hash algorithm is described by the spec
            0x0001: "SHA-512",
        }), count_from=lambda pkt: pkt.HashAlgorithmCount),
        XStrLenField("Salt", "", length_from=lambda pkt: pkt.SaltLength),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(
    SMB2_Negotiate_Context,
    SMB2_Preauth_Integrity_Capabilities,
    ContextType=0x0001
)

# sect 2.2.3.1.2


class SMB2_Encryption_Capabilities(Packet):
    name = "SMB2 Encryption Capabilities"
    fields_desc = [
        # According to the spec, this field value must be greater than 0
        # (cf Section 2.2.3.1.2 of MS-SMB2.pdf)
        FieldLenField("CipherCount", 1, fmt="<H", count_of="Ciphers"),
        FieldListField("Ciphers", [0x0001], LEShortEnumField("", 0x0, {
            0x0001: "AES-128-CCM",
            0x0002: "AES-128-GCM",
        }), count_from=lambda pkt: pkt.CipherCount),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(
    SMB2_Negotiate_Context,
    SMB2_Encryption_Capabilities,
    ContextType=0x0002
)

# sect 2.2.3.1.3


class SMB2_Compression_Capabilities(Packet):
    name = "SMB2 Compression Capabilities"
    fields_desc = [
        FieldLenField(
            "CompressionAlgorithmCount", 0,
            fmt="<H",
            count_of="CompressionAlgorithms"
        ),
        ShortField("Padding", 0x0),
        IntEnumField("Flags", 0x0, {
            0x00000000: "SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE",
            0x00000001: "SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED",
        }),
        FieldListField(
            "CompressionAlgorithms",
            None,
            LEShortEnumField("", 0x0, SMB2_COMPRESSION_ALGORITHMS),
            count_from=lambda pkt: pkt.CompressionAlgorithmCount,
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(
    SMB2_Negotiate_Context,
    SMB2_Compression_Capabilities,
    ContextType=0x0003
)

# sect 2.2.3.1.4


class SMB2_Netname_Negotiate_Context_ID(Packet):
    name = "SMB2 Netname Negotiate Context ID"
    fields_desc = [
        StrFieldUtf16("NetName", "")
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(
    SMB2_Negotiate_Context,
    SMB2_Netname_Negotiate_Context_ID,
    ContextType=0x0005
)

# sect 2.2.3.1.5


class SMB2_Transport_Capabilities(Packet):
    name = "SMB2 Transport Capabilities"
    fields_desc = [
        FlagsField("Flags", 0x0, -32, {
            0x00000001: "SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY",
        }),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(
    SMB2_Negotiate_Context,
    SMB2_Transport_Capabilities,
    ContextType=0x0006
)


# sect 2.2.4


class SMB2_Negotiate_Protocol_Response(_SMB2_Payload):
    name = "SMB2 Negotiate Protocol Response"
    fields_desc = [
        XLEShortField("StructureSize", 0x41),
        FlagsField("SecurityMode", 0, -16, {
            0x1: "Signing Required",
            0x2: "Signing Enabled",
        }),
        LEShortEnumField("DialectRevision", 0x0, SMB_DIALECTS),
        FieldLenField(
            "NegotiateCount", None,
            fmt="<H",
            count_of="NegotiateContexts"
        ),
        UUIDField("GUID", 0x0,
                  uuid_fmt=UUIDField.FORMAT_LE),
        # Capabilities
        FlagsField("Capabilities", 0, -32, SMB2_CAPABILITIES),
        LEIntField("MaxTransactionSize", 65536),
        LEIntField("MaxReadSize", 65536),
        LEIntField("MaxWriteSize", 65536),
        UTCTimeField("ServerTime", None, fmt="<Q",
                     epoch=[1601, 1, 1, 0, 0, 0],
                     custom_scaling=1e7),
        UTCTimeField("ServerStartTime", None, fmt="<Q",
                     epoch=[1601, 1, 1, 0, 0, 0],
                     custom_scaling=1e7),
        FieldLenField(
            "SecurityBlobOffset", None,
            fmt="<H",
            length_of="SecurityBlobPad",
            adjust=lambda pkt, x: x + 0x80
        ),
        FieldLenField(
            "SecurityBlobLength", None,
            fmt="<H",
            length_of="SecurityBlob"
        ),
        XLEIntField("NegotiateContextOffset", 0),
        XStrLenField("SecurityBlobPad", "",
                     length_from=lambda pkt: pkt.SecurityBlobOffset - 0x80),
        PacketLenField("SecurityBlob", None, GSSAPI_BLOB,
                       length_from=lambda x: x.SecurityBlobLength),
        # Field only exists if Dialect is 0x0311
        # Each negotiate context must be 8-byte aligned
        ConditionalField(
            FieldListField(
                "NegotiateContexts", [],
                ReversePadField(
                    PacketField("Context", None, SMB2_Negotiate_Context), 8
                ), count_from=lambda pkt: pkt.NegotiateCount
            ), lambda x: x.DialectRevision == 0x0311
        ),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Negotiate_Protocol_Response,
    Command=0x0000,
    Flags=1  # SMB2_FLAGS_SERVER_TO_REDIR
)

# sect 2.2.5


class SMB2_Session_Setup_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 Session Setup Request"
    OFFSET = 24 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x19),
        FlagsField("Flags", 0, -8, ["SMB2_SESSION_FLAG_BINDING"]),
        FlagsField("SecurityMode", 0, -8, {
            0x1: "Signing Required",
            0x2: "Signing Enabled",
        }),
        FlagsField("Capabilities", 0, -32, SMB2_CAPABILITIES),
        LEIntField("Channel", 0),
        XLEShortField("SecurityBufferOffset", None),
        LEShortField("SecurityLen", None),
        XLELongField("PreviousSessionId", 0),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                PacketField("Security", None, GSSAPI_BLOB),
            ])
    ]

    def __getattr__(self, attr):
        # Ease SMB1 backward compatibility
        if attr == "SecurityBlob":
            return (super(SMB2_Session_Setup_Request, self).__getattr__(
                "Buffer"
            ) or [(None, None)])[0][1]
        return super(SMB2_Session_Setup_Request, self).__getattr__(attr)

    def setfieldval(self, attr, val):
        if attr == "SecurityBlob":
            return super(SMB2_Session_Setup_Request, self).setfieldval(
                "Buffer", [("Security", val)]
            )
        return super(SMB2_Session_Setup_Request, self).setfieldval(attr, val)

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Security": 12,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Session_Setup_Request,
    Command=0x0001,
)

# sect 2.2.6


class SMB2_Session_Setup_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 Session Setup Response"
    OFFSET = 8 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x9),
        FlagsField("SessionFlags", 0, -16, {
            0x0001: "IS_GUEST",
            0x0002: "IS_NULL",
            0x0004: "ENCRYPT_DATE",
        }),
        XLEShortField("SecurityBufferOffset", None),
        LEShortField("SecurityLen", None),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                PacketField("Security", None, GSSAPI_BLOB),
            ])
    ]

    def __getattr__(self, attr):
        # Ease SMB1 backward compatibility
        if attr == "SecurityBlob":
            return (super(SMB2_Session_Setup_Response, self).__getattr__(
                "Buffer"
            ) or [(None, None)])[0][1]
        return super(SMB2_Session_Setup_Response, self).__getattr__(attr)

    def setfieldval(self, attr, val):
        if attr == "SecurityBlob":
            return super(SMB2_Session_Setup_Response, self).setfieldval(
                "Buffer", [("Security", val)]
            )
        return super(SMB2_Session_Setup_Response, self).setfieldval(attr, val)

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Security": 4,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Session_Setup_Response,
    Command=0x0001,
    Flags=1  # SMB2_FLAGS_SERVER_TO_REDIR
)

# sect 2.2.7


class SMB2_Session_Logoff_Request(_SMB2_Payload):
    name = "SMB2 LOGOFF Request"
    fields_desc = [
        XLEShortField("StructureSize", 0x4),
        ShortField("reserved", 0),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Session_Logoff_Request,
    Command=0x0002,
)

# sect 2.2.8


class SMB2_Session_Logoff_Response(_SMB2_Payload):
    name = "SMB2 LOGOFF Request"
    fields_desc = [
        XLEShortField("StructureSize", 0x4),
        ShortField("reserved", 0),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Session_Logoff_Response,
    Command=0x0002,
    Flags=1  # SMB2_FLAGS_SERVER_TO_REDIR
)

# sect 2.2.9


class SMB2_Tree_Connect_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 TREE_CONNECT Request"
    OFFSET = 8 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x9),
        FlagsField("Flags", 0, -16, ["CLUSTER_RECONNECT",
                                     "REDIRECT_TO_OWNER",
                                     "EXTENSION_PRESENT"]),
        XLEShortField("PathBufferOffset", None),
        LEShortField("PathLen", None),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                StrFieldUtf16("Path", b""),
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Path": 4,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Tree_Connect_Request,
    Command=0x0003,
)

# sect 2.2.10


SMB2_ACCESS_FLAGS = {
    # sect 2.2.13.1.2
    0x00000001: "FILE_LIST_DIRECTORY",
    0x00000002: "FILE_ADD_FILE",
    0x00000004: "FILE_ADD_SUBDIRECTORY",
    0x00000008: "FILE_READ_EA",
    0x00000010: "FILE_WRITE_EA",
    0x00000020: "FILE_TRAVERSE",
    0x00000040: "FILE_DELETE_CHILD",
    0x00000080: "FILE_READ_ATTRIBUTES",
    0x00000100: "FILE_WRITE_ATTRIBUTES",
    0x00010000: "DELETE",
    0x00020000: "READ_CONTROL",
    0x00040000: "WRITE_DAC",
    0x00080000: "WRITE_OWNER",
    0x00100000: "SYNCHRONIZE",
    0x01000000: "ACCESS_SYSTEM_SECURITY",
    0x02000000: "MAXIMUM_ALLOWED",
    0x10000000: "GENERIC_ALL",
    0x20000000: "GENERIC_EXECUTE",
    0x40000000: "GENERIC_WRITE",
    0x80000000: "GENERIC_READ",
}


class SMB2_Tree_Connect_Response(_SMB2_Payload):
    name = "SMB2 TREE_CONNECT Response"
    fields_desc = [
        XLEShortField("StructureSize", 0x10),
        ByteEnumField("ShareType", 0, {0x01: "DISK",
                                       0x02: "PIPE",
                                       0x03: "PRINT"}),
        ByteField("Reserved", 0),
        FlagsField("ShareFlags", 0x30, -32, {
            0x00000010: "AUTO_CACHING",
            0x00000020: "VDO_CACHING",
            0x00000030: "NO_CACHING",
            0x00000001: "DFS",
            0x00000002: "DFS_ROOT",
            0x00000100: "RESTRICT_EXCLUSIVE_OPENS",
            0x00000200: "FORCE_SHARED_DELETE",
            0x00000400: "ALLOW_NAMESPACE_CACHING",
            0x00000800: "ACCESS_BASED_DIRECTORY_ENUM",
            0x00001000: "FORCE_LEVELII_OPLOCK",
            0x00002000: "ENABLE_HASH_V1",
            0x00004000: "ENABLE_HASH_V2",
            0x00008000: "ENCRYPT_DATA",
            0x00040000: "IDENTITY_REMOTING",
            0x00100000: "COMPRESS_DATA",
        }),
        FlagsField("Capabilities", 0, -32, {
            0x00000008: "DFS",
            0x00000010: "CONTINUOUS_AVAILABILITY",
            0x00000020: "SCALEOUT",
            0x00000040: "CLUSTER",
            0x00000080: "ASYMMETRIC",
            0x00000100: "REDIRECT_TO_OWNER",
        }),
        FlagsField("MaximalAccess", 0, -32, SMB2_ACCESS_FLAGS),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Tree_Connect_Response,
    Command=0x0003,
    Flags=1
)

# sect 2.2.11


class SMB2_Tree_Disconnect_Request(_SMB2_Payload):
    name = "SMB2 TREE_DISCONNECT Request"
    fields_desc = [
        XLEShortField("StructureSize", 0x4),
        XLEShortField("Reserved", 0),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Tree_Disconnect_Request,
    Command=0x0004
)

# sect 2.2.12


class SMB2_Tree_Disconnect_Response(_SMB2_Payload):
    name = "SMB2 TREE_DISCONNECT Response"
    fields_desc = [
        XLEShortField("StructureSize", 0x4),
        XLEShortField("Reserved", 0),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Tree_Disconnect_Response,
    Command=0x0004,
    Flags=1
)


# sect 2.2.14.1


class SMB2_FILEID(Packet):
    fields_desc = [
        XLELongField("Persistent", 0),
        XLELongField("Volatile", 0)
    ]

    def __hash__(self):
        return self.Persistent + self.Volatile << 64

    def default_payload_class(self, payload):
        return conf.padding_layer

# sect 2.2.14.2


class SMB2_CREATE_DURABLE_HANDLE_RESPONSE(Packet):
    fields_desc = [
        XStrFixedLenField("Reserved", b"\x00" * 8, length=8),
    ]


class SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE(Packet):
    fields_desc = [
        LEIntEnumField("QueryStatus", 0, STATUS_ERREF),
        FlagsField("MaximalAccess", 0, -32, SMB2_ACCESS_FLAGS),
    ]


class SMB2_CREATE_QUERY_ON_DISK_ID(Packet):
    fields_desc = [
        LELongField("DiskFileId", 0),
        LELongField("VolumeId", 0),
        XStrFixedLenField("Reserved", b"", length=16),
    ]


class SMB2_CREATE_RESPONSE_LEASE(Packet):
    fields_desc = [
        XStrFixedLenField("LeaseKey", b"", length=16),
        FlagsField("LeaseState", 0x7, -32, {
            0x01: "SMB2_LEASE_READ_CACHING",
            0x02: "SMB2_LEASE_HANDLE_CACHING",
            0x04: "SMB2_LEASE_WRITE_CACHING",
        }),
        FlagsField("LeaseFlags", 0, -32, {
            0x02: "SMB2_LEASE_FLAG_BREAK_IN_PROGRESS",
            0x04: "SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET",
        }),
        LELongField("LeaseDuration", 0),
    ]


class SMB2_CREATE_RESPONSE_LEASE_V2(Packet):
    fields_desc = [
        SMB2_CREATE_RESPONSE_LEASE,
        XStrFixedLenField("ParentLeaseKey", b"", length=16),
        LEShortField("Epoch", 0),
        LEShortField("Reserved", 0),
    ]


class SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2(Packet):
    fields_desc = [
        LEIntField("Timeout", 0),
        FlagsField("Flags", 0, -32, {
            0x02: "SMB2_DHANDLE_FLAG_PERSISTENT",
        }),
    ]

# sect 2.2.13


class SMB2_CREATE_DURABLE_HANDLE_REQUEST(Packet):
    fields_desc = [
        XStrFixedLenField("DurableRequest", b"", length=16),
    ]


class SMB2_CREATE_DURABLE_HANDLE_RECONNECT(Packet):
    fields_desc = [
        PacketField("Data", SMB2_FILEID(), SMB2_FILEID),
    ]


class SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST(Packet):
    fields_desc = [
        LELongField("Timestamp", 0),
    ]


class SMB2_CREATE_ALLOCATION_SIZE(Packet):
    fields_desc = [
        LELongField("AllocationSize", 0),
    ]


class SMB2_CREATE_TIMEWARP_TOKEN(Packet):
    fields_desc = [
        LELongField("Timestamp", 0),
    ]


class SMB2_CREATE_REQUEST_LEASE(Packet):
    fields_desc = [
        SMB2_CREATE_RESPONSE_LEASE,
    ]


class SMB2_CREATE_REQUEST_LEASE_V2(Packet):
    fields_desc = [
        SMB2_CREATE_RESPONSE_LEASE_V2,
    ]


class SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2(Packet):
    fields_desc = [
        SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2,
        XStrFixedLenField("Reserved", b"", length=8),
        UUIDField("CreateGuid", 0x0, uuid_fmt=UUIDField.FORMAT_LE),
    ]


class SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2(Packet):
    fields_desc = [
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        UUIDField("CreateGuid", 0x0, uuid_fmt=UUIDField.FORMAT_LE),
        FlagsField("Flags", 0, -32, {
            0x02: "SMB2_DHANDLE_FLAG_PERSISTENT",
        }),
    ]


class SMB2_CREATE_APP_INSTANCE_ID(Packet):
    fields_desc = [
        XLEShortField("StructureSize", 0x14),
        LEShortField("Reserved", 0),
        XStrFixedLenField("AppInstanceId", b"", length=16),
    ]


class SMB2_CREATE_APP_INSTANCE_VERSION(Packet):
    fields_desc = [
        XLEShortField("StructureSize", 0x18),
        LEShortField("Reserved", 0),
        LEIntField("Padding", 0),
        LELongField("AppInstanceVersionHigh", 0),
        LELongField("AppInstanceVersionLow", 0),
    ]


class SMB2_Create_Context(_NTLMPayloadPacket):
    name = "SMB2 CREATE CONTEXT"
    OFFSET = 14
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        LEIntField("Next", None),
        XLEShortField("NameBufferOffset", None),
        LEShortField("NameLen", None),
        ShortField("Reserved", 0),
        XLEShortField("DataBufferOffset", None),
        LEShortField("DataLen", None),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                StrLenField("Name", b"",
                            length_from=lambda pkt: pkt.NameLen),
                PacketLenField("Data", None, conf.raw_layer,
                               length_from=lambda pkt: pkt.DataLen),
            ]),
        StrLenField("pad", b"",
                    length_from=lambda x: (
                        x.Next -
                        max(x.DataBufferOffset + x.DataLen,
                            x.NameBufferOffset + x.NameLen)) if x.Next else 0)
    ]

    def post_dissect(self, s):
        if not self.DataLen:
            return s
        try:
            if isinstance(self.parent, SMB2_Create_Request):
                data_cls = {
                    b"DHnQ": SMB2_CREATE_DURABLE_HANDLE_REQUEST,
                    b"DHnC": SMB2_CREATE_DURABLE_HANDLE_RECONNECT,
                    b"AISi": SMB2_CREATE_ALLOCATION_SIZE,
                    b"MxAc": SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST,
                    b"TWrp": SMB2_CREATE_TIMEWARP_TOKEN,
                    b"QFid": SMB2_CREATE_QUERY_ON_DISK_ID,
                    b"RqLs": SMB2_CREATE_REQUEST_LEASE,
                    b"DH2Q": SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2,
                    b"DH2C": SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2,
                    # 3.1.1 only
                    b'E\xbc\xa6j\xef\xa7\xf7J\x90\x08\xfaF.\x14Mt': SMB2_CREATE_APP_INSTANCE_ID,  # noqa: E501
                    b'\xb9\x82\xd0\xb7;V\x07O\xa0{RJ\x81\x16\xa0\x10': SMB2_CREATE_APP_INSTANCE_VERSION,  # noqa: E501
                }[self.Name]
                if self.Name == b"RqLs" and self.DataLen > 32:
                    data_cls = SMB2_CREATE_REQUEST_LEASE_V2
            elif isinstance(self.parent, SMB2_Create_Response):
                data_cls = {
                    b"DHnQ": SMB2_CREATE_DURABLE_HANDLE_RESPONSE,
                    b"MxAc": SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE,
                    b"QFid": SMB2_CREATE_QUERY_ON_DISK_ID,
                    b"RqLs": SMB2_CREATE_RESPONSE_LEASE,
                    b"DH2Q": SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2,
                }[self.Name]
                if self.Name == b"RqLs" and self.DataLen > 32:
                    data_cls = SMB2_CREATE_RESPONSE_LEASE_V2
            else:
                return s
        except KeyError:
            return s
        self.Data = data_cls(self.Data.load)
        return s

    def default_payload_class(self, _):
        return conf.padding_layer

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Name": 4,
            "Data": 10,
        }) + pay


# sect 2.2.13

SMB2_OPLOCK_LEVELS = {
    0x00: "SMB2_OPLOCK_LEVEL_NONE",
    0x01: "SMB2_OPLOCK_LEVEL_II",
    0x08: "SMB2_OPLOCK_LEVEL_EXCLUSIVE",
    0x09: "SMB2_OPLOCK_LEVEL_BATCH",
    0xff: "SMB2_OPLOCK_LEVEL_LEASE",
}


class SMB2_Create_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 CREATE Request"
    OFFSET = 56 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x39),
        ByteField("ShareType", 0),
        ByteEnumField("RequestedOplockLevel", 0, SMB2_OPLOCK_LEVELS),
        LEIntEnumField("ImpersonationLevel", 0, {
            0x00000000: "Anonymous",
            0x00000001: "Identification",
            0x00000002: "Impersonation",
            0x00000003: "Delegate",
        }),
        LELongField("SmbCreateFlags", 0),
        LELongField("Reserved", 0),
        FlagsField("DesiredAccess", 0, -32, SMB2_ACCESS_FLAGS),
        FlagsField("FileAttributes", 0x00000080, -32, FileAttributes),
        FlagsField("ShareAccess", 0, -32, {
            0x00000001: "FILE_SHARE_READ",
            0x00000002: "FILE_SHARE_WRITE",
            0x00000004: "FILE_SHARE_DELETE",
        }),
        LEIntEnumField("CreateDisposition", 1, {
            0x00000000: "FILE_SUPERSEDE",
            0x00000001: "FILE_OPEN",
            0x00000002: "FILE_CREATE",
            0x00000003: "FILE_OPEN_IF",
            0x00000004: "FILE_OVERWRITE",
            0x00000005: "FILE_OVERWRITE_IF",
        }),
        FlagsField("CreateOptions", 0, -32, {
            0x00000001: "FILE_DIRECTORY_FILE",
            0x00000002: "FILE_WRITE_THROUGH",
            0x00000004: "FILE_SEQUENTIAL_ONLY",
            0x00000008: "FILE_NO_INTERMEDIATE_BUFFERING",
            0x00000010: "FILE_SYNCHRONOUS_IO_ALERT",
            0x00000020: "FILE_SYNCHRONOUS_IO_NONALERT",
            0x00000040: "FILE_NON_DIRECTORY_FILE",
            0x00000100: "FILE_COMPLETE_IF_OPLOCKED",
            0x00000200: "FILE_RANDOM_ACCESS",
            0x00001000: "FILE_DELETE_ON_CLOSE",
            0x00002000: "FILE_OPEN_BY_FILE_ID",
            0x00004000: "FILE_OPEN_FOR_BACKUP_INTENT",
            0x00008000: "FILE_NO_COMPRESSION",
            0x00000400: "FILE_OPEN_REMOTE_INSTANCE",
            0x00010000: "FILE_OPEN_REQUIRING_OPLOCK",
            0x00020000: "FILE_DISALLOW_EXCLUSIVE",
            0x00100000: "FILE_RESERVE_OPFILTER",
            0x00200000: "FILE_OPEN_REPARSE_POINT",
            0x00400000: "FILE_OPEN_NO_RECALL",
            0x00800000: "FILE_OPEN_FOR_FREE_SPACE_QUERY",
        }),
        XLEShortField("NameBufferOffset", None),
        LEShortField("NameLen", None),
        XLEIntField("CreateContextsBufferOffset", None),
        LEIntField("CreateContextsLen", None),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                StrFieldUtf16("Name", b""),
                _NextPacketListField("CreateContexts", [], SMB2_Create_Context,
                                     length_from=lambda pkt: pkt.CreateContextsLen),
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Name": 44,
            "CreateContexts": 48,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Create_Request,
    Command=0x0005
)


# sect 2.2.14


class SMB2_Create_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 CREATE Response"
    OFFSET = 88 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x59),
        ByteEnumField("OplockLevel", 0, SMB2_OPLOCK_LEVELS),
        FlagsField("Flags", 0, -8, {0x01: "SMB2_CREATE_FLAG_REPARSEPOINT"}),
        LEIntEnumField("CreateAction", 1, {
            0x00000000: "FILE_SUPERSEDED",
            0x00000001: "FILE_OPENED",
            0x00000002: "FILE_CREATED",
            0x00000003: "FILE_OVERWRITEN",
        }),
        FileNetworkOpenInformation,
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        XLEIntField("CreateContextsBufferOffset", None),
        LEIntField("CreateContextsLen", None),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                _NextPacketListField("CreateContexts", [], SMB2_Create_Context,
                                     length_from=lambda pkt: pkt.CreateContextsLen),
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "CreateContexts": 80,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Create_Response,
    Command=0x0005,
    Flags=1
)

# sect 2.2.15


class SMB2_Close_Request(_SMB2_Payload):
    name = "SMB2 CLOSE Request"
    fields_desc = [
        XLEShortField("StructureSize", 0x18),
        FlagsField("Flags", 0, -16,
                   ["SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB"]),
        LEIntField("Reserved", 0),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID)
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Close_Request,
    Command=0x0006,
)

# sect 2.2.16


class SMB2_Close_Response(_SMB2_Payload):
    name = "SMB2 CLOSE Response"
    FileAttributes = 0
    CreationTime = 0
    LastAccessTime = 0
    LastWriteTime = 0
    ChangeTime = 0
    fields_desc = [
        XLEShortField("StructureSize", 0x3c),
        FlagsField("Flags", 0, -16,
                   ["SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB"]),
        LEIntField("Reserved", 0),
    ] + FileNetworkOpenInformation.fields_desc[:7]


bind_top_down(
    SMB2_Header,
    SMB2_Close_Response,
    Command=0x0006,
    Flags=1,
)

# sect 2.2.19


class SMB2_Read_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 READ Request"
    OFFSET = 48 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x31),
        ByteField("Padding", 0),
        FlagsField("Flags", 0, -8, {
            0x01: "SMB2_READFLAG_READ_UNBUFFERED",
            0x02: "SMB2_READFLAG_REQUEST_COMPRESSED",
        }),
        LEIntField("Length", 0),
        LELongField("Offset", 0),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        LEIntField("MinimumCount", 0),
        LEIntEnumField("Channel", 0, {
            0x00000000: "SMB2_CHANNEL_NONE",
            0x00000001: "SMB2_CHANNEL_RDMA_V1",
            0x00000002: "SMB2_CHANNEL_RDMA_V1_INVALIDATE",
            0x00000003: "SMB2_CHANNEL_RDMA_TRANSFORM",
        }),
        LEIntField("RemainingBytes", 0),
        LEShortField("ReadChannelInfoBufferOffset", None),
        LEShortField("ReadChannelInfoLen", None),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                StrLenField("ReadChannelInfo", b"",
                            length_from=lambda pkt: pkt.ReadChannelInfoLen)
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "ReadChannelInfo": 44,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Read_Request,
    Command=0x0008,
)

# sect 2.2.20


class SMB2_Read_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 READ Response"
    OFFSET = 16 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x11),
        LEShortField("DataBufferOffset", None),
        LEIntField("DataLen", None),
        LEIntField("DataRemaining", 0),
        FlagsField("Flags", 0, -32, {
            0x01: "SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM",
        }),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                StrLenField("Data", b"",
                            length_from=lambda pkt: pkt.DataLen)
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Data": 2,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Read_Response,
    Command=0x0008,
    Flags=1,
)


# sect 2.2.21


class SMB2_Write_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 WRITE Request"
    OFFSET = 48 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x31),
        LEShortField("DataBufferOffset", None),
        LEIntField("DataLen", None),
        LELongField("Offset", 0),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        LEIntEnumField("Channel", 0, {
            0x00000000: "SMB2_CHANNEL_NONE",
            0x00000001: "SMB2_CHANNEL_RDMA_V1",
            0x00000002: "SMB2_CHANNEL_RDMA_V1_INVALIDATE",
            0x00000003: "SMB2_CHANNEL_RDMA_TRANSFORM",
        }),
        LEIntField("RemainingBytes", 0),
        LEShortField("WriteChannelInfoBufferOffset", None),
        LEShortField("WriteChannelInfoLen", None),
        FlagsField("Flags", 0, -32, {
            0x00000001: "SMB2_WRITEFLAG_WRITE_THROUGH",
            0x00000002: "SMB2_WRITEFLAG_WRITE_UNBUFFERED",
        }),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                StrLenField("Data", b"",
                            length_from=lambda pkt: pkt.DataLen),
                StrLenField("WriteChannelInfo", b"",
                            length_from=lambda pkt: pkt.WriteChannelInfoLen)
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Data": 2,
            "WriteChannelInfo": 40,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Write_Request,
    Command=0x0009,
)

# sect 2.2.22


class SMB2_Write_Response(_SMB2_Payload):
    name = "SMB2 WRITE Response"
    fields_desc = [
        XLEShortField("StructureSize", 0x11),
        LEShortField("Reserved", 0),
        LEIntField("Count", 0),
        LEIntField("Remaining", 0),
        LEShortField("WriteChannelInfoBufferOffset", 0),
        LEShortField("WriteChannelInfoLen", 0),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Write_Response,
    Command=0x0009,
    Flags=1
)

# sect 2.2.30


class SMB2_Cancel_Request(_SMB2_Payload):
    name = "SMB2 CANCEL Request"
    fields_desc = [
        XLEShortField("StructureSize", 0x4),
        LEShortField("Reserved", 0),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Cancel_Request,
    Command=0x0009,
)

# sect 2.2.31.4


class SMB2_IOCTL_Validate_Negotiate_Info_Request(Packet):
    name = "SMB2 IOCTL Validate Negotiate Info"
    fields_desc = (
        SMB2_Negotiate_Protocol_Request.fields_desc[4:6] +  # Cap/GUID
        SMB2_Negotiate_Protocol_Request.fields_desc[1:3][::-1] +  # SecMod/DC
        [SMB2_Negotiate_Protocol_Request.fields_desc[9]]  # Dialects
    )


# sect 2.2.31

class _SMB2_IOCTL_Request_PacketLenField(PacketLenField):
    def m2i(self, pkt, m):
        if pkt.CtlCode == 0x00140204:  # FSCTL_VALIDATE_NEGOTIATE_INFO
            return SMB2_IOCTL_Validate_Negotiate_Info_Request(m)
        return conf.raw_layer(m)


class SMB2_IOCTL_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 IOCTL Request"
    OFFSET = 56 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    deprecated_fields = {
        "IntputCount": ("InputLen", "alias"),
        "OutputCount": ("OutputLen", "alias"),
    }
    fields_desc = [
        XLEShortField("StructureSize", 0x39),
        LEShortField("Reserved", 0),
        LEIntEnumField("CtlCode", 0, {
            0x00060194: "FSCTL_DFS_GET_REFERRALS",
            0x0011400C: "FSCTL_PIPE_PEEK",
            0x00110018: "FSCTL_PIPE_WAIT",
            0x0011C017: "FSCTL_PIPE_TRANSCEIVE",
            0x001440F2: "FSCTL_SRV_COPYCHUNK",
            0x00144064: "FSCTL_SRV_ENUMERATE_SNAPSHOTS",
            0x00140078: "FSCTL_SRV_REQUEST_RESUME_KEY",
            0x001441bb: "FSCTL_SRV_READ_HASH",
            0x001480F2: "FSCTL_SRV_COPYCHUNK_WRITE",
            0x001401D4: "FSCTL_LMR_REQUEST_RESILIENCY",
            0x001401FC: "FSCTL_QUERY_NETWORK_INTERFACE_INFO",
            0x000900A4: "FSCTL_SET_REPARSE_POINT",
            0x000601B0: "FSCTL_DFS_GET_REFERRALS_EX",
            0x00098208: "FSCTL_FILE_LEVEL_TRIM",
            0x00140204: "FSCTL_VALIDATE_NEGOTIATE_INFO",
        }),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        LEIntField("InputBufferOffset", None),
        LEIntField("InputLen", None),  # Called InputCount but it's a length
        LEIntField("MaxInputResponse", 0),
        LEIntField("OutputBufferOffset", None),
        LEIntField("OutputLen", None),  # Called OutputCount.
        LEIntField("MaxOutputResponse", 0),
        FlagsField("Flags", 0, -32, {
            0x00000001: "SMB2_0_IOCTL_IS_FSCTL"
        }),
        LEIntField("Reserved2", 0),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                _SMB2_IOCTL_Request_PacketLenField(
                    "Input", None, conf.raw_layer,
                    length_from=lambda pkt: pkt.InputLen),
                _SMB2_IOCTL_Request_PacketLenField(
                    "Output", None, conf.raw_layer,
                    length_from=lambda pkt: pkt.OutputLen),
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Input": 24,
            "Output": 36,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_IOCTL_Request,
    Command=0x000B,
)

# sect 2.2.32.6


class SMB2_IOCTL_Validate_Negotiate_Info_Response(Packet):
    name = "SMB2 IOCTL Validate Negotiate Info"
    fields_desc = (
        SMB2_Negotiate_Protocol_Response.fields_desc[4:6][::-1] +  # Cap/GUID
        SMB2_Negotiate_Protocol_Response.fields_desc[1:3]  # SecMod/DialectRevision
    )

# sect 2.2.32


class _SMB2_IOCTL_Response_PacketLenField(PacketLenField):
    def m2i(self, pkt, m):
        if pkt.CtlCode == 0x00140204:  # FSCTL_VALIDATE_NEGOTIATE_INFO
            return SMB2_IOCTL_Validate_Negotiate_Info_Response(m)
        return conf.raw_layer(m)


class SMB2_IOCTL_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 IOCTL Response"
    OFFSET = 48 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    StructureSize = 0x31
    fields_desc = (
        SMB2_IOCTL_Request.fields_desc[:6] +
        SMB2_IOCTL_Request.fields_desc[7:9] +
        SMB2_IOCTL_Request.fields_desc[10:12] + [
            _NTLMPayloadField(
                'Buffer', OFFSET, [
                    _SMB2_IOCTL_Response_PacketLenField(
                        "Input", None, conf.raw_layer,
                        length_from=lambda pkt: pkt.InputLen),
                    _SMB2_IOCTL_Response_PacketLenField(
                        "Output", None, conf.raw_layer,
                        length_from=lambda pkt: pkt.OutputLen),
                ],
            ),
        ]
    )

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Input": 24,
            "Output": 32,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_IOCTL_Response,
    Command=0x000B,
    Flags=1  # SMB2_FLAGS_SERVER_TO_REDIR
)

# sect 2.2.33


class SMB2_Query_Directory_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 QUERY DIRECTORY Request"
    OFFSET = 32 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x21),
        ByteEnumField("FileInformationClass", 0x1, FileInformationClasses),
        FlagsField("Flags", 0, -8, {
            0x01: "SMB2_RESTART_SCANS",
            0x02: "SMB2_RETURN_SINGLE_ENTRY",
            0x04: "SMB2_INDEX_SPECIFIED",
            0x10: "SMB2_REOPEN",
        }),
        LEIntField("FileIndex", 0),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        LEShortField("FileNameBufferOffset", None),
        LEShortField("FileNameLen", None),
        LEIntField("OutputBufferLength", 2048),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                StrFieldUtf16("FileName", b"")
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "FileName": 24,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Query_Directory_Request,
    Command=0x000E,
)

# sect 2.2.34


class SMB2_Query_Directory_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 QUERY DIRECTORY Response"
    OFFSET = 8 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x9),
        LEShortField("OutputBufferOffset", None),
        LEIntField("OutputLen", None),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                # TODO
                StrFixedLenField("Output", b"",
                                 length_from=lambda pkt: pkt.OutputLen)
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Output": 2,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Query_Directory_Response,
    Command=0x000E,
    Flags=1,
)

# sect 2.2.35


class SMB2_Change_Notify_Request(_SMB2_Payload):
    name = "SMB2 CHANGE NOTIFY Request"
    fields_desc = [
        XLEShortField("StructureSize", 0x20),
        FlagsField("Flags", 0, -16, {
            0x0001: "SMB2_WATCH_TREE",
        }),
        LEIntField("OutputBufferLength", 2048),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        FlagsField("CompletionFilter", 0, -32, {
            0x00000001: "FILE_NOTIFY_CHANGE_FILE_NAME",
            0x00000002: "FILE_NOTIFY_CHANGE_DIR_NAME",
            0x00000004: "FILE_NOTIFY_CHANGE_ATTRIBUTES",
            0x00000008: "FILE_NOTIFY_CHANGE_SIZE",
            0x00000010: "FILE_NOTIFY_CHANGE_LAST_WRITE",
            0x00000020: "FILE_NOTIFY_CHANGE_LAST_ACCESS",
            0x00000040: "FILE_NOTIFY_CHANGE_CREATION",
            0x00000080: "FILE_NOTIFY_CHANGE_EA",
            0x00000100: "FILE_NOTIFY_CHANGE_SECURITY",
            0x00000200: "FILE_NOTIFY_CHANGE_STREAM_NAME",
            0x00000400: "FILE_NOTIFY_CHANGE_STREAM_SIZE",
            0x00000800: "FILE_NOTIFY_CHANGE_STREAM_WRITE"
        }),
        LEIntField("Reserved", 0),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Change_Notify_Request,
    Command=0x000F,
)

# sect 2.2.36


class SMB2_Change_Notify_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 CHANGE NOTIFY Response"
    OFFSET = 8 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x9),
        LEShortField("OutputBufferOffset", None),
        LEIntField("OutputLen", None),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                # TODO
                StrFixedLenField("Output", b"",
                                 length_from=lambda pkt: pkt.OutputLen)
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Output": 2,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Change_Notify_Response,
    Command=0x000F,
    Flags=1,
)

# sect 2.2.37


class FILE_GET_QUOTA_INFORMATION(Packet):
    fields_desc = [
        IntField("NextEntryOffset", 0),
        FieldLenField("SidLength", None, length_of="Sid"),
        StrLenField("Sid", b"", length_from=lambda x: x.SidLength),
        StrLenField("pad", b"",
                    length_from=lambda x: ((x.NextEntryOffset -
                                           x.SidLength)
                                           if x.NextEntryOffset else 0))
    ]


class SMB2_Query_Quota_Info(Packet):
    fields_desc = [
        ByteField("ReturnSingle", 0),
        ByteField("ReturnBoolean", 0),
        ShortField("Reserved", 0),
        LEIntField("SidListLength", 0),
        LEIntField("StartSidLength", 0),
        LEIntField("StartSidOffset", 0),
        StrLenField("pad", b"", length_from=lambda x: x.StartSidOffset),
        MultipleTypeField(
            [
                (PacketListField("SidBuffer", [], FILE_GET_QUOTA_INFORMATION,
                                 length_from=lambda x: x.SidListLength),
                 lambda x: x.SidListLength),
                (StrLenField("SidBuffer", b"",
                             length_from=lambda x: x.StartSidLength),
                 lambda x: x.StartSidLength)
            ],
            StrFixedLenField("SidBuffer", b"", length=0)
        )
    ]


class SMB2_Query_Info_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 QUERY INFO Request"
    OFFSET = 40 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x29),
        ByteEnumField("InfoType", 0, {
            0x01: "SMB2_0_INFO_FILE",
            0x02: "SMB2_0_INFO_FILESYSTEM",
            0x03: "SMB2_0_INFO_SECURITY",
            0x04: "SMB2_0_INFO_QUOTA",
        }),
        ByteEnumField("FileInfoClass", 0, FileInformationClasses),
        LEIntField("OutputBufferLength", 0),
        XLEIntField("InputBufferOffset", None),  # Short + Reserved = Int
        LEIntField("InputLen", None),
        FlagsField("AdditionalInformation", 0, -32, {
            0x00000001: "OWNER_SECURITY_INFORMATION",
            0x00000002: "GROUP_SECURITY_INFORMATION",
            0x00000004: "DACL_SECURITY_INFORMATION",
            0x00000008: "SACL_SECURITY_INFORMATION",
            0x00000010: "LABEL_SECURITY_INFORMATION",
            0x00000020: "ATTRIBUTE_SECURITY_INFORMATION",
            0x00000040: "SCOPE_SECURITY_INFORMATION",
            0x00010000: "BACKUP_SECURITY_INFORMATION",
        }),
        FlagsField("Flags", 0, -32, {
            0x00000001: "SL_RESTART_SCAN",
            0x00000002: "SL_RETURN_SINGLE_ENTRY",
            0x00000004: "SL_INDEX_SPECIFIED",
        }),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                PacketListField(
                    "Input", None, SMB2_Query_Quota_Info,
                    length_from=lambda pkt: pkt.InputLen),
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Input": 4,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Query_Info_Request,
    Command=0x00010,
)


class SMB2_Query_Info_Response(_SMB2_Payload):
    name = "SMB2 QUERY INFO Response"
    OFFSET = 8 + 64
    fields_desc = [
        XLEShortField("StructureSize", 0x9),
        LEShortField("OutputBufferOffset", None),
        LEIntField("OutputLen", None),
        _NTLMPayloadField(
            'Buffer', OFFSET, [
                # TODO
                StrFixedLenField("Output", b"",
                                 length_from=lambda pkt: pkt.OutputLen)
            ])
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return _SMB2_post_build(self, pkt, self.OFFSET, {
            "Output": 2,
        }) + pay


bind_top_down(
    SMB2_Header,
    SMB2_Query_Info_Response,
    Command=0x00010,
    Flags=1,
)


# sect 2.2.42.1


class SMB2_Compression_Transform_Header(Packet):
    name = "SMB2 Compression Transform Header"
    fields_desc = [
        StrFixedLenField("Start", b"\xfcSMB", 4),
        LEIntField("OriginalCompressedSegmentSize", 0x0),
        LEShortEnumField(
            "CompressionAlgorithm", 0,
            SMB2_COMPRESSION_ALGORITHMS
        ),
        ShortEnumField("Flags", 0x0, {
            0x0000: "SMB2_COMPRESSION_FLAG_NONE",
            0x0001: "SMB2_COMPRESSION_FLAG_CHAINED",
        }),
        XLEIntField("Offset_or_Length", 0),
    ]
