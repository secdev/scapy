# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
SMB (Server Message Block), also known as CIFS - version 2

.. note::
    You will find more complete documentation for this layer over at
    `SMB <https://scapy.readthedocs.io/en/latest/layers/smb.html>`_
"""

import collections
import hashlib
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
    FlagValue,
    FlagsField,
    IP6Field,
    IPField,
    IntEnumField,
    IntField,
    LEIntField,
    LEIntEnumField,
    LELongField,
    LenField,
    LEShortEnumField,
    LEShortField,
    MultipleTypeField,
    PadField,
    PacketField,
    PacketLenField,
    PacketListField,
    ReversePadField,
    ScalingField,
    ShortEnumField,
    ShortField,
    StrFieldUtf16,
    StrFixedLenField,
    StrLenField,
    StrLenFieldUtf16,
    StrNullFieldUtf16,
    ThreeBytesField,
    UTCTimeField,
    UUIDField,
    XLEIntField,
    XLELongField,
    XLEShortField,
    XStrLenField,
    XStrFixedLenField,
)
from scapy.supersocket import StreamSocket

from scapy.layers.gssapi import GSSAPI_BLOB
from scapy.layers.netbios import NBTSession
from scapy.layers.ntlm import (
    _NTLMPayloadField,
    _NTLMPayloadPacket,
    _NTLM_ENUM,
    _NTLM_post_build,
)


# EnumField
SMB_DIALECTS = {
    0x0202: "SMB 2.002",
    0x0210: "SMB 2.1",
    0x02FF: "SMB 2.???",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

# SMB2 sect 3.3.5.15 + [MS-ERREF]
STATUS_ERREF = {
    0x00000000: "STATUS_SUCCESS",
    0x00000103: "STATUS_PENDING",
    0x0000010B: "STATUS_NOTIFY_CLEANUP",
    0x0000010C: "STATUS_NOTIFY_ENUM_DIR",
    0x00000532: "ERROR_PASSWORD_EXPIRED",
    0x00000533: "ERROR_ACCOUNT_DISABLED",
    0x80000005: "STATUS_BUFFER_OVERFLOW",
    0x80000006: "STATUS_NO_MORE_FILES",
    0x8000002D: "STATUS_STOPPED_ON_SYMLINK",
    0xC0000003: "STATUS_INVALID_INFO_CLASS",
    0xC0000004: "STATUS_INFO_LENGTH_MISMATCH",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC000000F: "STATUS_NO_SUCH_FILE",
    0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000033: "STATUS_OBJECT_NAME_INVALID",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC0000043: "STATUS_SHARING_VIOLATION",
    0xC000006D: "STATUS_LOGON_FAILURE",
    0xC0000071: "STATUS_PASSWORD_EXPIRED",
    0xC0000072: "STATUS_ACCOUNT_DISABLED",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
    0xC00000BA: "STATUS_FILE_IS_A_DIRECTORY",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC00000C9: "STATUS_NETWORK_NAME_DELETED",
    0xC00000CC: "STATUS_BAD_NETWORK_NAME",
    0xC0000120: "STATUS_CANCELLED",
    0xC0000128: "STATUS_FILE_CLOSED",  # backup error for older Win versions
    0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED",
    0xC000019C: "STATUS_FS_DRIVER_REQUIRED",
    0xC0000203: "STATUS_USER_SESSION_DELETED",
    0xC000020C: "STATUS_CONNECTION_DISCONNECTED",
    0xC0000225: "STATUS_NOT_FOUND",
    0xC0000257: "STATUS_PATH_NOT_COVERED",
    0xC000035C: "STATUS_NETWORK_SESSION_EXPIRED",
}

# SMB2 sect 2.1.2.1
REPARSE_TAGS = {
    0x00000000: "IO_REPARSE_TAG_RESERVED_ZERO",
    0x00000001: "IO_REPARSE_TAG_RESERVED_ONE",
    0x00000002: "IO_REPARSE_TAG_RESERVED_TWO",
    0xA0000003: "IO_REPARSE_TAG_MOUNT_POINT",
    0xC0000004: "IO_REPARSE_TAG_HSM",
    0x80000005: "IO_REPARSE_TAG_DRIVE_EXTENDER",
    0x80000006: "IO_REPARSE_TAG_HSM2",
    0x80000007: "IO_REPARSE_TAG_SIS",
    0x80000008: "IO_REPARSE_TAG_WIM",
    0x80000009: "IO_REPARSE_TAG_CSV",
    0x8000000A: "IO_REPARSE_TAG_DFS",
    0x8000000B: "IO_REPARSE_TAG_FILTER_MANAGER",
    0xA000000C: "IO_REPARSE_TAG_SYMLINK",
    0xA0000010: "IO_REPARSE_TAG_IIS_CACHE",
    0x80000012: "IO_REPARSE_TAG_DFSR",
    0x80000013: "IO_REPARSE_TAG_DEDUP",
    0xC0000014: "IO_REPARSE_TAG_APPXSTRM",
    0x80000014: "IO_REPARSE_TAG_NFS",
    0x80000015: "IO_REPARSE_TAG_FILE_PLACEHOLDER",
    0x80000016: "IO_REPARSE_TAG_DFM",
    0x80000017: "IO_REPARSE_TAG_WOF",
    0x80000018: "IO_REPARSE_TAG_WCI",
    0x90001018: "IO_REPARSE_TAG_WCI_1",
    0xA0000019: "IO_REPARSE_TAG_GLOBAL_REPARSE",
    0x9000001A: "IO_REPARSE_TAG_CLOUD",
    0x9000101A: "IO_REPARSE_TAG_CLOUD_1",
    0x9000201A: "IO_REPARSE_TAG_CLOUD_2",
    0x9000301A: "IO_REPARSE_TAG_CLOUD_3",
    0x9000401A: "IO_REPARSE_TAG_CLOUD_4",
    0x9000501A: "IO_REPARSE_TAG_CLOUD_5",
    0x9000601A: "IO_REPARSE_TAG_CLOUD_6",
    0x9000701A: "IO_REPARSE_TAG_CLOUD_7",
    0x9000801A: "IO_REPARSE_TAG_CLOUD_8",
    0x9000901A: "IO_REPARSE_TAG_CLOUD_9",
    0x9000A01A: "IO_REPARSE_TAG_CLOUD_A",
    0x9000B01A: "IO_REPARSE_TAG_CLOUD_B",
    0x9000C01A: "IO_REPARSE_TAG_CLOUD_C",
    0x9000D01A: "IO_REPARSE_TAG_CLOUD_D",
    0x9000E01A: "IO_REPARSE_TAG_CLOUD_E",
    0x9000F01A: "IO_REPARSE_TAG_CLOUD_F",
    0x8000001B: "IO_REPARSE_TAG_APPEXECLINK",
    0x9000001C: "IO_REPARSE_TAG_PROJFS",
    0xA000001D: "IO_REPARSE_TAG_LX_SYMLINK",
    0x8000001E: "IO_REPARSE_TAG_STORAGE_SYNC",
    0xA000001F: "IO_REPARSE_TAG_WCI_TOMBSTONE",
    0x80000020: "IO_REPARSE_TAG_UNHANDLED",
    0x80000021: "IO_REPARSE_TAG_ONEDRIVE",
    0xA0000022: "IO_REPARSE_TAG_PROJFS_TOMBSTONE",
    0x80000023: "IO_REPARSE_TAG_AF_UNIX",
    0x80000024: "IO_REPARSE_TAG_LX_FIFO",
    0x80000025: "IO_REPARSE_TAG_LX_CHR",
    0x80000026: "IO_REPARSE_TAG_LX_BLK",
    0xA0000027: "IO_REPARSE_TAG_WCI_LINK",
    0xA0001027: "IO_REPARSE_TAG_WCI_LINK_1",
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
    0x0001: "SMB2_PREAUTH_INTEGRITY_CAPABILITIES",
    0x0002: "SMB2_ENCRYPTION_CAPABILITIES",
    0x0003: "SMB2_COMPRESSION_CAPABILITIES",
    0x0005: "SMB2_NETNAME_NEGOTIATE_CONTEXT_ID",
    0x0006: "SMB2_TRANSPORT_CAPABILITIES",
    0x0007: "SMB2_RDMA_TRANSFORM_CAPABILITIES",
    0x0008: "SMB2_SIGNING_CAPABILITIES",
}

# FlagField
SMB2_CAPABILITIES = {
    0x00000001: "DFS",
    0x00000002: "LEASING",
    0x00000004: "LARGE_MTU",
    0x00000008: "MULTI_CHANNEL",
    0x00000010: "PERSISTENT_HANDLES",
    0x00000020: "DIRECTORY_LEASING",
    0x00000040: "ENCRYPTION",
}
SMB2_SECURITY_MODE = {
    0x01: "SIGNING_ENABLED",
    0x02: "SIGNING_REQUIRED",
}

# [MS-SMB2] 2.2.3.1.3
SMB2_COMPRESSION_ALGORITHMS = {
    0x0000: "None",
    0x0001: "LZNT1",
    0x0002: "LZ77",
    0x0003: "LZ77 + Huffman",
    0x0004: "Pattern_V1",
}

# sect [MS-SMB2] 2.2.13.1.1
SMB2_ACCESS_FLAGS_FILE = {
    0x00000001: "FILE_READ_DATA",
    0x00000002: "FILE_WRITE_DATA",
    0x00000004: "FILE_APPEND_DATA",
    0x00000008: "FILE_READ_EA",
    0x00000010: "FILE_WRITE_EA",
    0x00000040: "FILE_DELETE_CHILD",
    0x00000020: "FILE_EXECUTE",
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

# sect [MS-SMB2] 2.2.13.1.2
SMB2_ACCESS_FLAGS_DIRECTORY = {
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

# [MS-SRVS] sec 2.2.2.4
SRVSVC_SHARE_TYPES = {
    0x00000000: "DISKTREE",
    0x00000001: "PRINTQ",
    0x00000002: "DEVICE",
    0x00000003: "IPC",
    0x02000000: "CLUSTER_FS",
    0x04000000: "CLUSTER_SOFS",
    0x08000000: "CLUSTER_DFS",
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
    0x04: "FileBasicInformation",
    0x05: "FileStandardInformation",
    0x06: "FileInternalInformation",
    0x07: "FileEaInformation",
    0x08: "FileAccessInformation",
    0x0E: "FilePositionInformation",
    0x10: "FileModeInformation",
    0x11: "FileAlignmentInformation",
    0x12: "FileAllInformation",
    0x22: "FileNetworkOpenInformation",
    0x25: "FileIdBothDirectoryInformation",
    0x26: "FileIdFullDirectoryInformation",
    0x0C: "FileNamesInformation",
    0x30: "FileNormalizedNameInformation",
    0x3C: "FileIdExtdDirectoryInformation",
}


# [MS-FSCC] 2.1.7 FILE_NAME_INFORMATION


class FILE_NAME_INFORMATION(Packet):
    fields_desc = [
        FieldLenField("FileNameLength", None, length_of="FileName", fmt="<I"),
        StrLenFieldUtf16("FileName", "", length_from=lambda pkt: pkt.FileNameLength),
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


# [MS-FSCC] 2.4.1 FileAccessInformation


class FileAccessInformation(Packet):
    fields_desc = [
        FlagsField("AccessFlags", 0, -32, SMB2_ACCESS_FLAGS_FILE),
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


# [MS-FSCC] 2.4.3 FileAlignmentInformation


class FileAlignmentInformation(Packet):
    fields_desc = [
        LEIntEnumField(
            "AccessFlags",
            0,
            {
                0x00000000: "FILE_BYTE_ALIGNMENT",
                0x00000001: "FILE_WORD_ALIGNMENT",
                0x00000003: "FILE_LONG_ALIGNMENT",
                0x00000007: "FILE_QUAD_ALIGNMENT",
                0x0000000F: "FILE_OCTA_ALIGNMENT",
                0x0000001F: "FILE_32_BYTE_ALIGNMENT",
                0x0000003F: "FILE_64_BYTE_ALIGNMENT",
                0x0000007F: "FILE_128_BYTE_ALIGNMENT",
                0x000000FF: "FILE_256_BYTE_ALIGNMENT",
                0x000001FF: "FILE_512_BYTE_ALIGNMENT",
            },
        ),
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


# [MS-FSCC] 2.4.5 FileAlternateNameInformation


class FileAlternateNameInformation(Packet):
    fields_desc = [
        FieldLenField("FileNameLength", None, length_of="FileName", fmt="<I"),
        StrLenFieldUtf16("FileName", b"", length_from=lambda pkt: pkt.FileNameLength),
    ]


# [MS-FSCC] 2.4.7 FileBasicInformation


class FileBasicInformation(Packet):
    fields_desc = [
        UTCTimeField(
            "CreationTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        UTCTimeField(
            "LastAccessTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        UTCTimeField(
            "LastWriteTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        UTCTimeField(
            "ChangeTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        FlagsField("FileAttributes", 0x00000080, -32, FileAttributes),
        IntField("Reserved", 0),
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


# [MS-FSCC] 2.4.12 FileEaInformation


class FileEaInformation(Packet):
    fields_desc = [
        LEIntField("EaSize", 0),
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


# [MS-FSCC] 2.4.29 FileNetworkOpenInformation


class FileNetworkOpenInformation(Packet):
    fields_desc = [
        UTCTimeField(
            "CreationTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        UTCTimeField(
            "LastAccessTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        UTCTimeField(
            "LastWriteTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        UTCTimeField(
            "ChangeTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        LELongField("AllocationSize", 4096),
        LELongField("EndOfFile", 0),
        FlagsField("FileAttributes", 0x00000080, -32, FileAttributes),
        IntField("Reserved2", 0),
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


# [MS-FSCC] 2.4.8 FileBothDirectoryInformation


class FILE_BOTH_DIR_INFORMATION(Packet):
    fields_desc = (
        [
            LEIntField("Next", None),  # 0 = no next entry
            LEIntField("FileIndex", 0),
        ]
        + (
            FileNetworkOpenInformation.fields_desc[:4]
            + FileNetworkOpenInformation.fields_desc[4:6][::-1]
            + [FileNetworkOpenInformation.fields_desc[6]]
        )
        + [
            FieldLenField("FileNameLength", None, fmt="<I", length_of="FileName"),
            MultipleTypeField(
                # "If FILE_ATTRIBUTE_REPARSE_POINT is set in the FileAttributes field,
                # this field MUST contain a reparse tag as specified in section
                # 2.1.2.1."
                [
                    (
                        LEIntEnumField("EaSize", 0, REPARSE_TAGS),
                        lambda pkt: pkt.FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT,
                    )
                ],
                LEIntField("EaSize", 0),
            ),
            ByteField("ShortNameLength", 0),
            ByteField("Reserved1", 0),
            StrFixedLenField("ShortName", b"", length=24),
            PadField(
                StrLenFieldUtf16(
                    "FileName", b".", length_from=lambda pkt: pkt.FileNameLength
                ),
                align=8,
            ),
        ]
    )

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


class FileBothDirectoryInformation(Packet):
    fields_desc = [
        _NextPacketListField(
            "files",
            [],
            FILE_BOTH_DIR_INFORMATION,
            max_count=1000,
        ),
    ]


# [MS-FSCC] 2.4.14 FileFullDirectoryInformation


class FILE_FULL_DIR_INFORMATION(Packet):
    fields_desc = FILE_BOTH_DIR_INFORMATION.fields_desc[:11] + [
        FILE_BOTH_DIR_INFORMATION.fields_desc[-1]
    ]


class FileFullDirectoryInformation(Packet):
    fields_desc = [
        _NextPacketListField(
            "files",
            [],
            FILE_FULL_DIR_INFORMATION,
            max_count=1000,
        ),
    ]


# [MS-FSCC] 2.4.17 FileIdBothDirectoryInformation


class FILE_ID_BOTH_DIR_INFORMATION(Packet):
    fields_desc = FILE_BOTH_DIR_INFORMATION.fields_desc[:14] + [
        LEShortField("Reserved2", 0),
        LELongField("FileId", 0),
        FILE_BOTH_DIR_INFORMATION.fields_desc[-1],
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


class FileIdBothDirectoryInformation(Packet):
    fields_desc = [
        _NextPacketListField(
            "files",
            [],
            FILE_ID_BOTH_DIR_INFORMATION,
            max_count=1000,  # > 65535 / len(FILE_ID_BOTH_DIR_INFORMATION())
        ),
    ]


# [MS-FSCC] 2.4.22 FileInternalInformation


class FileInternalInformation(Packet):
    fields_desc = [
        LELongField("IndexNumber", 0),
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


# [MS-FSCC] 2.4.26 FileModeInformation


class FileModeInformation(Packet):
    fields_desc = [
        FlagsField(
            "Mode",
            0,
            -32,
            {
                0x00000002: "FILE_WRITE_TROUGH",
                0x00000004: "FILE_SEQUENTIAL_ONLY",
                0x00000008: "FILE_NO_INTERMEDIATE_BUFFERING",
                0x00000010: "FILE_SYNCHRONOUS_IO_ALERT",
                0x00000020: "FILE_SYNCHRONOUS_IO_NONALERT",
                0x00001000: "FILE_DELETE_ON_CLOSE",
            },
        )
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


# [MS-FSCC] 2.4.35 FilePositionInformation


class FilePositionInformation(Packet):
    fields_desc = [
        LELongField("CurrentByteOffset", 0),
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


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

    def default_payload_class(self, s):
        return conf.padding_layer


# [MS-FSCC] 2.4.43 FileStreamInformation


class FileStreamInformation(Packet):
    fields_desc = [
        LEIntField("Next", 0),
        FieldLenField("StreamNameLength", None, length_of="StreamName", fmt="<I"),
        LELongField("StreamSize", 0),
        LELongField("StreamAllocationSize", 4096),
        StrLenFieldUtf16(
            "StreamName", b"::$DATA", length_from=lambda pkt: pkt.StreamNameLength
        ),
    ]


# [MS-DTYP] sect 2.4.1


class WINNT_SID_IDENTIFIER_AUTHORITY(Packet):
    fields_desc = [
        StrFixedLenField("Value", b"", length=6),
    ]

    def default_payload_class(self, payload):
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
            [],
            LEIntField("", 0),
            count_from=lambda pkt: pkt.SubAuthorityCount,
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer

    def summary(self):
        return "S-%s-%s%s" % (
            self.Revision,
            struct.unpack(">Q", b"\x00\x00" + self.IdentifierAuthority.Value)[0],
            ("-%s" % "-".join(str(x) for x in self.SubAuthority))
            if self.SubAuthority
            else "",
        )


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


class WINNT_ACE_HEADER(Packet):
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
            {
                0x01: "OBJECT_INHERIT",
                0x02: "CONTAINER_INHERIT",
                0x04: "NO_PROPAGATE_INHERIT",
                0x08: "INHERIT_ONLY",
                0x10: "INHERITED_ACE",
                0x40: "SUCCESSFUL_ACCESS",
                0x80: "FAILED_ACCESS",
            },
        ),
        LenField("AceSize", None, fmt="<H", adjust=lambda x: x + 4),
    ]

    def extract_padding(self, p):
        return p[: self.AceSize - 4], p[self.AceSize - 4 :]

    def toSDDL(self):
        """
        Return SDDL
        """
        sid = self.payload.Sid.summary()
        ace_flag_string = str(
            FlagValue(
                self.AceFlags,
                ["OI", "CI", "NP", "IO", "ID", "SA", "FA"]
            )
        )
        ace_rights = ""  # TODO
        object_guid = ""  # TODO
        inherit_object_guid = ""  # TODO
        # ApplicationData -> conditional expression
        condexpr = ""
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
            condexpr = ";(%s)" % res[0]
        if self.AceType in [0x9, 0xA, 0xB, 0xD]:  # Conditional ACE
            conditional_ace_type = {
                0x09: "XA",
                0x0A: "XD",
                0x0B: "XU",
                0x0D: "ZA",
            }[self.AceType]
            return "D:(%s)" % (
                ";".join([
                    conditional_ace_type,
                    ace_flag_string,
                    ace_rights,
                    object_guid,
                    inherit_object_guid,
                    sid
                ]) + condexpr
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
                ";".join([
                    ace_type,
                    ace_flag_string,
                    ace_rights,
                    object_guid,
                    inherit_object_guid,
                    sid
                ]) + condexpr
            )


# [MS-DTYP] sect 2.4.4.2


class WINNT_ACCESS_ALLOWED_ACE(Packet):
    fields_desc = [
        FlagsField("Mask", 0, -32, _WINNT_ACCESS_MASK),
        PacketField("Sid", WINNT_SID(), WINNT_SID),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_ALLOWED_ACE, AceType=0x00)


# [MS-DTYP] sect 2.4.4.4


class WINNT_ACCESS_DENIED_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_DENIED_ACE, AceType=0x01)


# [MS-DTYP] sect 2.4.4.17.4+


class WINNT_APPLICATION_DATA_LITERAL_TOKEN(Packet):
    def default_payload_class(self, payload):
        return conf.padding_layer


WINNT_APPLICATION_DATA_LITERAL_TOKEN.fields_desc = [
    ByteEnumField("TokenType", 0, {
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
    }),
    ConditionalField(
        # Strings
        LEIntField("length", 0),
        lambda pkt: pkt.TokenType in [
            0x10,  # Unicode string
            0x18,  # Octet string
            0xf8, 0xf8, 0xfa, 0xfb,  # Attribute tokens
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
                        0xf8, 0xf8, 0xfa, 0xfb,  # Attribute tokens
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
            0x01, 0x02, 0x03, 0x04, 0x10, 0x18, 0xf8, 0xf8, 0xfa, 0xfb, 0x50
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
            "ApplicationData",
            WINNT_APPLICATION_DATA(),
            WINNT_APPLICATION_DATA
        ),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_ALLOWED_CALLBACK_ACE, AceType=0x09)


# [MS-DTYP] sect 2.4.4.6


class WINNT_ACCESS_DENIED_CALLBACK_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_CALLBACK_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_DENIED_CALLBACK_ACE, AceType=0x0A)


# [MS-DTYP] sect 2.4.4.10


class WINNT_AUDIT_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_AUDIT_ACE, AceType=0x02)


# [MS-DTYP] sect 2.4.5


class WINNT_ACL(Packet):
    fields_desc = [
        ByteField("AclRevision", 2),
        ByteField("Sbz1", 0x00),
        FieldLenField(
            "AclSize", None, length_of="Aces", adjust=lambda _, x: x + 14, fmt="<H"
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
                "OwnerDefaulted",
                "GroupDefaulted",
                "DACLPresent",
                "DACLDefaulted",
                "SACLPresent",
                "SACLDefaulted",
                "DACLTrusted",
                "ServerSecurity",
                "DACLComputer",
                "SACLComputer",
                "DACLAutoInheriter",
                "SACLAutoInherited",
                "DACLProtected",
                "SACLProtected",
                "RMControlValid",
                "SelfRelative",
            ],
        ),
        LEIntField("OwnerSidOffset", 0),
        LEIntField("GroupSidOffset", 0),
        LEIntField("SaclOffset", 0),
        LEIntField("DaclOffset", 0),
        _NTLMPayloadField(
            "Data",
            OFFSET,
            [
                ConditionalField(
                    PacketField("OwnerSid", WINNT_SID(), WINNT_SID),
                    lambda pkt: pkt.OwnerSidOffset,
                ),
                ConditionalField(
                    PacketField("GroupSid", WINNT_SID(), WINNT_SID),
                    lambda pkt: pkt.GroupSidOffset,
                ),
                ConditionalField(
                    PacketField("Sacl", WINNT_ACL(), WINNT_ACL),
                    lambda pkt: pkt.Control.SACLPresent,
                ),
                ConditionalField(
                    PacketField("Dacl", WINNT_ACL(), WINNT_ACL),
                    lambda pkt: pkt.Control.DACLPresent,
                ),
            ],
            offset_name="Offset",
        ),
    ]


# [MS-FSCC] 2.4.2 FileAllInformation


class FileAllInformation(Packet):
    fields_desc = [
        PacketField("BasicInformation", FileBasicInformation(), FileBasicInformation),
        PacketField(
            "StandardInformation", FileStandardInformation(), FileStandardInformation
        ),
        PacketField(
            "InternalInformation", FileInternalInformation(), FileInternalInformation
        ),
        PacketField("EaInformation", FileEaInformation(), FileEaInformation),
        PacketField(
            "AccessInformation", FileAccessInformation(), FileAccessInformation
        ),
        PacketField(
            "PositionInformation", FilePositionInformation(), FilePositionInformation
        ),
        PacketField("ModeInformation", FileModeInformation(), FileModeInformation),
        PacketField(
            "AlignmentInformation", FileAlignmentInformation(), FileAlignmentInformation
        ),
        PacketField("NameInformation", FILE_NAME_INFORMATION(), FILE_NAME_INFORMATION),
    ]


# [MS-FSCC] 2.5.1 FileFsAttributeInformation


class FileFsAttributeInformation(Packet):
    fields_desc = [
        FlagsField(
            "FileSystemAttributes",
            0x00C706FF,
            -32,
            {
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
            },
        ),
        LEIntField("MaximumComponentNameLength", 255),
        FieldLenField(
            "FileSystemNameLength", None, length_of="FileSystemName", fmt="<I"
        ),
        StrLenFieldUtf16(
            "FileSystemName", b"NTFS", length_from=lambda pkt: pkt.FileSystemNameLength
        ),
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
        UTCTimeField(
            "VolumeCreationTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        LEIntField("VolumeSerialNumber", 0),
        LEIntField("VolumeLabelLength", 0),
        ByteField("SupportsObjects", 1),
        ByteField("Reserved", 0),
        StrNullFieldUtf16("VolumeLabel", b"C"),
    ]


# [MS-FSCC] 2.7.1 FILE_NOTIFY_INFORMATION


class FILE_NOTIFY_INFORMATION(Packet):
    fields_desc = [
        IntField("NextEntryOffset", 0),
        LEIntEnumField(
            "Action",
            0,
            {
                0x00000001: "FILE_ACTION_ADDED",
                0x00000002: "FILE_ACTION_REMOVED",
                0x00000003: "FILE_ACTION_MODIFIED",
                0x00000004: "FILE_ACTION_RENAMED_OLD_NAME",
                0x00000005: "FILE_ACTION_RENAMED_NEW_NAME",
                0x00000006: "FILE_ACTION_ADDED_STREAM",
                0x00000007: "FILE_ACTION_REMOVED_STREAM",
                0x00000008: "FILE_ACTION_MODIFIED_STREAM",
                0x00000009: "FILE_ACTION_REMOVED_BY_DELETE",
                0x0000000A: "FILE_ACTION_ID_NOT_TUNNELLED",
                0x0000000B: "FILE_ACTION_TUNNELLED_ID_COLLISION",
            },
        ),
        FieldLenField(
            "FileNameLength",
            None,
            length_of="FileName",
            fmt="<I",
        ),
        StrLenFieldUtf16("FileName", b"", length_from=lambda x: x.FileNameLength),
        StrLenField(
            "pad",
            b"",
            length_from=lambda x: (
                (x.NextEntryOffset - x.FileNameLength) if x.NextEntryOffset else 0
            ),
        ),
    ]

    def default_payload_class(self, s):
        return conf.padding_layer


_SMB2_CONFIG = [
    ("BufferOffset", _NTLM_ENUM.OFFSET),
    ("Len", _NTLM_ENUM.LEN),
]


def _SMB2_post_build(self, p, pay_offset, fields):
    """Util function to build the offset and populate the lengths"""
    return _NTLM_post_build(self, p, pay_offset, fields, config=_SMB2_CONFIG)


# SMB2 sect 2.1


class DirectTCP(NBTSession):
    name = "Direct TCP"
    MAXLENGTH = 0xFFFFFF
    fields_desc = [ByteField("zero", 0), ThreeBytesField("LENGTH", None)]


# SMB2 sect 2.2.1.1


class SMB2_Header(Packet):
    name = "SMB2 Header"
    fields_desc = [
        StrFixedLenField("Start", b"\xfeSMB", 4),
        LEShortField("StructureSize", 64),
        LEShortField("CreditCharge", 0),
        LEIntEnumField("Status", 0, STATUS_ERREF),
        LEShortEnumField("Command", 0, SMB2_COM),
        LEShortField("CreditRequest", 0),
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x00000001: "SMB2_FLAGS_SERVER_TO_REDIR",
                0x00000002: "SMB2_FLAGS_ASYNC_COMMAND",
                0x00000004: "SMB2_FLAGS_RELATED_OPERATIONS",
                0x00000008: "SMB2_FLAGS_SIGNED",
                0x10000000: "SMB2_FLAGS_DFS_OPERATIONS",
                0x20000000: "SMB2_FLAGS_REPLAY_OPERATION",
            },
        ),
        XLEIntField("NextCommand", 0),
        LELongField("MID", 0),  # MessageID
        # ASYNC
        ConditionalField(
            LELongField("AsyncId", 0), lambda pkt: pkt.Flags.SMB2_FLAGS_ASYNC_COMMAND
        ),
        # SYNC
        ConditionalField(
            LEIntField("PID", 0),  # Reserved, but PID per wireshark
            lambda pkt: not pkt.Flags.SMB2_FLAGS_ASYNC_COMMAND,
        ),
        ConditionalField(
            LEIntField("TID", 0),  # TreeID
            lambda pkt: not pkt.Flags.SMB2_FLAGS_ASYNC_COMMAND,
        ),
        # COMMON
        LELongField("SessionId", 0),
        XStrFixedLenField("SecuritySignature", 0, length=16),
    ]

    _SMB2_OK_RETURNCODES = (
        # sect 3.3.4.4
        (0xC0000016, 0x0001),  # STATUS_MORE_PROCESSING_REQUIRED
        (0x80000005, 0x0008),  # STATUS_BUFFER_OVERFLOW (Read)
        (0x80000005, 0x0010),  # STATUS_BUFFER_OVERFLOW (QueryInfo)
        (0x80000005, 0x000B),  # STATUS_BUFFER_OVERFLOW (IOCTL)
        (0xC000000D, 0x000B),  # STATUS_INVALID_PARAMETER
        (0x0000010C, 0x000F),  # STATUS_NOTIFY_ENUM_DIR
    )

    def guess_payload_class(self, payload):
        if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR and self.Status != 0x00000000:
            # Check status for responses
            if (self.Status, self.Command) not in SMB2_Header._SMB2_OK_RETURNCODES:
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
        elif self.Command == 0x000D:  # Echo
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Echo_Response
            return SMB2_Echo_Request
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

    def sign(self, dialect, SigningSessionKey, SigningAlgorithmId=None, IsClient=None):
        # [MS-SMB2] 3.1.4.1
        self.SecuritySignature = b"\x00" * 16
        s = bytes(self)
        if len(s) <= 64:
            log_runtime.warning("Cannot sign invalid SMB packet !")
            return s
        if dialect in [0x0300, 0x0302, 0x0311]:  # SMB 3
            if dialect == 0x0311:  # SMB 3.1.1
                if SigningAlgorithmId is None or IsClient is None:
                    raise Exception("SMB 3.1.1 needs a SigningAlgorithmId and IsClient")
            else:
                SigningAlgorithmId = "AES-CMAC"  # AES-128-CMAC
            if "GMAC" in SigningAlgorithmId:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                aesgcm = AESGCM(SigningSessionKey)
                nonce = struct.pack("<Q", self.MID) + struct.pack(
                    "<I",
                    (0 if IsClient else 1) | (0x8000000 if self.Command == 9 else 0),
                )
                sig = aesgcm.encrypt(nonce, b"", s)
            elif "CMAC" in SigningAlgorithmId:
                from cryptography.hazmat.primitives import cmac
                from cryptography.hazmat.primitives.ciphers import algorithms

                c = cmac.CMAC(algorithms.AES(SigningSessionKey))
                c.update(s)
                sig = c.finalize()
            elif "HMAC" in SigningAlgorithmId:
                from scapy.layers.tls.crypto.h_mac import Hmac_SHA256

                sig = Hmac_SHA256(SigningSessionKey).digest(s)
                sig = sig[:16]
            else:
                raise ValueError("Unknown SigningAlgorithmId")
        elif dialect in [0x0210, 0x0202]:  # SMB 2.1 or SMB 2.0.2
            from scapy.layers.tls.crypto.h_mac import Hmac_SHA256

            sig = Hmac_SHA256(SigningSessionKey).digest(s)
            sig = sig[:16]
        else:
            log_runtime.warning("Unknown SMB Version %s ! Cannot sign." % dialect)
            sig = s[:-16] + b"\x00" * 16
        self.SecuritySignature = sig
        # we make sure the payload is static
        self.payload = conf.raw_layer(load=s[64:])


class _SMB2_Payload(Packet):
    def do_dissect_payload(self, s):
        # There can be padding between this layer and the next one
        if self.underlayer and isinstance(self.underlayer, SMB2_Header):
            if self.underlayer.NextCommand:
                padlen = self.underlayer.NextCommand - (64 + len(self.raw_packet_cache))
                if padlen:
                    self.add_payload(s[:padlen])
                    s = s[padlen:]
        super(_SMB2_Payload, self).do_dissect_payload(s)

    def answers(self, other):
        return (
            isinstance(other, _SMB2_Payload)
            and self.__class__ != other.__class__
            and (self.Command == other.Command or self.Command == -1)
        )

    def guess_payload_class(self, s):
        if self.underlayer and isinstance(self.underlayer, SMB2_Header):
            if self.underlayer.NextCommand:
                return SMB2_Header
        return super(_SMB2_Payload, self).guess_payload_class(s)


class SMBStreamSocket(StreamSocket):
    """
    A modified StreamSocket to dissect SMB compounded requests
    [MS-SMB2] 3.3.5.2.7
    """

    def __init__(self, *args, **kwargs):
        self.queue = collections.deque()
        super(SMBStreamSocket, self).__init__(*args, **kwargs)

    def recv(self, x=None):
        # note: normal StreamSocket takes care of NBTSession / DirectTCP fragments.
        # this takes care of compounded requests
        if self.queue:
            return self.queue.popleft()
        pkt = super(SMBStreamSocket, self).recv(x)
        if pkt is not None and SMB2_Header in pkt:
            pay = pkt[SMB2_Header].payload
            while SMB2_Header in pay:
                pay = pay[SMB2_Header]
                pay.underlayer.remove_payload()
                self.queue.append(pay)
                if not pay.NextCommand:
                    break
                pay = pay.payload
        return pkt

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        if any(getattr(x, "queue", None) for x in sockets):
            return [x for x in sockets if isinstance(x, SMBStreamSocket) and x.queue]
        return StreamSocket.select(sockets, remain=remain)


# sect 2.2.2


class SMB2_Error_Response(_SMB2_Payload):
    Command = -1
    __slots__ = ["NTStatus"]  # extra info
    name = "SMB2 Error Response"
    fields_desc = [
        XLEShortField("StructureSize", 0x09),
        ByteField("ErrorContextCount", 0),
        ByteField("Reserved", 0),
        FieldLenField("ByteCount", None, fmt="<I", length_of="ErrorData"),
        XStrLenField("ErrorData", b"", length_from=lambda pkt: pkt.ByteCount),
    ]


bind_top_down(SMB2_Header, SMB2_Error_Response, Flags=1)  # SMB2_FLAGS_SERVER_TO_REDIR

# sect 2.2.2.2.2


class MOVE_DST_IPADDR(Packet):
    fields_desc = [
        # Wireshark appears to get this wrong
        LEIntEnumField("Type", 1, {1: "IPv4", 2: "IPv6"}),
        IntField("Reserved", 0),
        MultipleTypeField(
            [(IP6Field("IPAddress", None), lambda pkt: pkt.Type == 2)],
            IPField("IPAddress", None),
        ),
        ConditionalField(
            # For IPv4
            StrFixedLenField("Reserved2", b"", length=12),
            lambda pkt: pkt.Type == 1,
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class SMB2_Error_Share_Redirect_Context_Response(_NTLMPayloadPacket):
    name = "Share Redirect Error Context Response"
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEIntField("StructureSize", 0x30),
        LEIntEnumField("NotificationType", 3, {3: "SHARE_MOVE_NOTIFICATION"}),
        XLEIntField("ResourceNameBufferOffset", None),
        LEIntField("ResourceNameLen", None),
        ShortField("Reserved", 0),
        ShortEnumField("TargetType", 0, {0: "IP"}),
        FieldLenField("IPAddrCount", None, fmt="<I", count_of="IPAddrMoveList"),
        PacketListField(
            "IPAddrMoveList",
            [],
            MOVE_DST_IPADDR,
            count_from=lambda pkt: pkt.IPAddrCount,
        ),
        _NTLMPayloadField(
            "Buffer",
            lambda pkt: 24 + len(pkt.IPAddrMoveList) * 24,
            [
                StrLenFieldUtf16(
                    "ResourceName", b"", length_from=lambda pkt: pkt.ResourceNameLen
                ),
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                24 + len(self.IPAddrMoveList) * 24,
                {
                    "ResourceName": 8,
                },
            )
            + pay
        )


# sect 2.2.2.1


class SMB2_Error_ContextResponse(Packet):
    fields_desc = [
        FieldLenField("ErrorDatalength", None, fmt="<I", length_of="ErrorContextData"),
        LEIntEnumField("ErrorId", 0, {0: "DEFAULT", 0x72645253: "SHARE_REDIRECT"}),
        MultipleTypeField(
            [
                (
                    PacketField(
                        "ErrorContextData",
                        SMB2_Error_Share_Redirect_Context_Response(),
                        SMB2_Error_Share_Redirect_Context_Response,
                    ),
                    lambda pkt: pkt.ErrorId == 0x72645253,
                )
            ],
            XStrLenField(
                "ErrorContextData", b"", length_from=lambda pkt: pkt.ErrorDatalength
            ),
        ),
    ]


# sect 2.2.3


class SMB2_Negotiate_Context(Packet):
    name = "SMB2 Negotiate Context"
    fields_desc = [
        LEShortEnumField("ContextType", 0x0, SMB2_NEGOTIATE_CONTEXT_TYPES),
        LenField("DataLength", None, fmt="<H"),
        IntField("Reserved", 0),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class SMB2_Negotiate_Protocol_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 Negotiate Protocol Request"
    Command = 0x0000
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x24),
        FieldLenField("DialectCount", None, fmt="<H", count_of="Dialects"),
        # SecurityMode
        FlagsField("SecurityMode", 0, -16, SMB2_SECURITY_MODE),
        LEShortField("Reserved", 0),
        # Capabilities
        FlagsField("Capabilities", 0, -32, SMB2_CAPABILITIES),
        UUIDField("ClientGUID", 0x0, uuid_fmt=UUIDField.FORMAT_LE),
        XLEIntField("NegotiateContextsBufferOffset", None),
        LEShortField("NegotiateContextsCount", None),
        ShortField("Reserved2", 0),
        FieldListField(
            "Dialects",
            [0x0202],
            LEShortEnumField("", 0x0, SMB_DIALECTS),
            count_from=lambda pkt: pkt.DialectCount,
        ),
        _NTLMPayloadField(
            "Buffer",
            lambda pkt: 64 + 36 + len(pkt.Dialects) * 2,
            [
                # Field only exists if Dialects contains 0x0311
                FieldListField(
                    "NegotiateContexts",
                    [],
                    ReversePadField(
                        PacketField("Context", None, SMB2_Negotiate_Context),
                        8,
                    ),
                    count_from=lambda pkt: pkt.NegotiateContextsCount,
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
                64 + 36 + len(self.Dialects) * 2,
                {
                    "NegotiateContexts": 28,
                },
                config=[
                    ("BufferOffset", _NTLM_ENUM.OFFSET | _NTLM_ENUM.PAD8),
                    ("Count", _NTLM_ENUM.COUNT),
                ],
            )
            + pay
        )


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
        FieldLenField("HashAlgorithmCount", None, fmt="<H", count_of="HashAlgorithms"),
        FieldLenField("SaltLength", None, fmt="<H", length_of="Salt"),
        FieldListField(
            "HashAlgorithms",
            [0x0001],
            LEShortEnumField(
                "",
                0x0,
                {
                    # As for today, no other hash algorithm is described by the spec
                    0x0001: "SHA-512",
                },
            ),
            count_from=lambda pkt: pkt.HashAlgorithmCount,
        ),
        XStrLenField("Salt", "", length_from=lambda pkt: pkt.SaltLength),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(
    SMB2_Negotiate_Context, SMB2_Preauth_Integrity_Capabilities, ContextType=0x0001
)

# sect 2.2.3.1.2


class SMB2_Encryption_Capabilities(Packet):
    name = "SMB2 Encryption Capabilities"
    fields_desc = [
        # According to the spec, this field value must be greater than 0
        # (cf Section 2.2.3.1.2 of MS-SMB2.pdf)
        FieldLenField("CipherCount", None, fmt="<H", count_of="Ciphers"),
        FieldListField(
            "Ciphers",
            [0x0001],
            LEShortEnumField(
                "",
                0x0,
                {
                    0x0001: "AES-128-CCM",
                    0x0002: "AES-128-GCM",
                    0x0003: "AES-256-CCM",
                    0x0004: "AES-256-GCM",
                },
            ),
            count_from=lambda pkt: pkt.CipherCount,
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(SMB2_Negotiate_Context, SMB2_Encryption_Capabilities, ContextType=0x0002)

# sect 2.2.3.1.3


class SMB2_Compression_Capabilities(Packet):
    name = "SMB2 Compression Capabilities"
    fields_desc = [
        FieldLenField(
            "CompressionAlgorithmCount",
            None,
            fmt="<H",
            count_of="CompressionAlgorithms",
        ),
        ShortField("Padding", 0x0),
        IntEnumField(
            "Flags",
            0x0,
            {
                0x00000000: "SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE",
                0x00000001: "SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED",
            },
        ),
        FieldListField(
            "CompressionAlgorithms",
            None,
            LEShortEnumField("", 0x0, SMB2_COMPRESSION_ALGORITHMS),
            count_from=lambda pkt: pkt.CompressionAlgorithmCount,
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(SMB2_Negotiate_Context, SMB2_Compression_Capabilities, ContextType=0x0003)

# sect 2.2.3.1.4


class SMB2_Netname_Negotiate_Context_ID(Packet):
    name = "SMB2 Netname Negotiate Context ID"
    fields_desc = [StrFieldUtf16("NetName", "")]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(
    SMB2_Negotiate_Context, SMB2_Netname_Negotiate_Context_ID, ContextType=0x0005
)

# sect 2.2.3.1.5


class SMB2_Transport_Capabilities(Packet):
    name = "SMB2 Transport Capabilities"
    fields_desc = [
        FlagsField(
            "Flags",
            0x0,
            -32,
            {
                0x00000001: "SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY",
            },
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(SMB2_Negotiate_Context, SMB2_Transport_Capabilities, ContextType=0x0006)

# sect 2.2.3.1.6


class SMB2_RDMA_Transform_Capabilities(Packet):
    name = "SMB2 RDMA Transform Capabilities"
    fields_desc = [
        FieldLenField("TransformCount", None, fmt="<H", count_of="RDMATransformIds"),
        LEShortField("Reserved1", 0),
        LEIntField("Reserved2", 0),
        FieldListField(
            "RDMATransformIds",
            None,
            LEShortEnumField(
                "",
                0x0,
                {
                    0x0000: "SMB2_RDMA_TRANSFORM_NONE",
                    0x0001: "SMB2_RDMA_TRANSFORM_ENCRYPTION",
                    0x0002: "SMB2_RDMA_TRANSFORM_SIGNING",
                },
            ),
            count_from=lambda pkt: pkt.TransformCount,
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(
    SMB2_Negotiate_Context, SMB2_RDMA_Transform_Capabilities, ContextType=0x0007
)

# sect 2.2.3.1.7


class SMB2_Signing_Capabilities(Packet):
    name = "SMB2 Signing Capabilities"
    fields_desc = [
        FieldLenField(
            "SigningAlgorithmCount", None, fmt="<H", count_of="SigningAlgorithms"
        ),
        FieldListField(
            "SigningAlgorithms",
            None,
            LEShortEnumField(
                "",
                0x0,
                {
                    0x0000: "HMAC-SHA256",
                    0x0001: "AES-CMAC",
                    0x0002: "AES-GMAC",
                },
            ),
            count_from=lambda pkt: pkt.SigningAlgorithmCount,
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(SMB2_Negotiate_Context, SMB2_Signing_Capabilities, ContextType=0x0008)

# sect 2.2.4


class SMB2_Negotiate_Protocol_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 Negotiate Protocol Response"
    Command = 0x0000
    OFFSET = 64 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x41),
        FlagsField("SecurityMode", 0, -16, SMB2_SECURITY_MODE),
        LEShortEnumField("DialectRevision", 0x0, SMB_DIALECTS),
        LEShortField("NegotiateContextsCount", None),
        UUIDField("GUID", 0x0, uuid_fmt=UUIDField.FORMAT_LE),
        # Capabilities
        FlagsField("Capabilities", 0, -32, SMB2_CAPABILITIES),
        LEIntField("MaxTransactionSize", 65536),
        LEIntField("MaxReadSize", 65536),
        LEIntField("MaxWriteSize", 65536),
        UTCTimeField(
            "ServerTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        UTCTimeField(
            "ServerStartTime",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
        ),
        XLEShortField("SecurityBlobBufferOffset", None),
        LEShortField("SecurityBlobLen", None),
        XLEIntField("NegotiateContextsBufferOffset", None),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                PacketLenField(
                    "SecurityBlob",
                    None,
                    GSSAPI_BLOB,
                    length_from=lambda x: x.SecurityBlobLen,
                ),
                # Field only exists if Dialect is 0x0311
                FieldListField(
                    "NegotiateContexts",
                    [],
                    ReversePadField(
                        PacketField("Context", None, SMB2_Negotiate_Context),
                        8,
                    ),
                    count_from=lambda pkt: pkt.NegotiateContextsCount,
                ),
            ],
            force_order=["SecurityBlob", "NegotiateContexts"],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        pkt = _NTLM_post_build(
            self,
            pkt,
            self.OFFSET,
            {
                "SecurityBlob": 56,
                "NegotiateContexts": 60,
            },
            config=[
                (
                    "BufferOffset",
                    {
                        "SecurityBlob": _NTLM_ENUM.OFFSET,
                        "NegotiateContexts": _NTLM_ENUM.OFFSET | _NTLM_ENUM.PAD8,
                    },
                ),
            ],
        )
        if getattr(self, "SecurityBlob", None):
            if self.SecurityBlobLen is None:
                pkt = pkt[:58] + struct.pack("<H", len(self.SecurityBlob)) + pkt[60:]
        if getattr(self, "NegotiateContexts", None):
            if self.NegotiateContextsCount is None:
                pkt = pkt[:6] + struct.pack("<H", len(self.NegotiateContexts)) + pkt[8:]
        return pkt + pay


bind_top_down(
    SMB2_Header,
    SMB2_Negotiate_Protocol_Response,
    Command=0x0000,
    Flags=1,  # SMB2_FLAGS_SERVER_TO_REDIR
)

# sect 2.2.5


class SMB2_Session_Setup_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 Session Setup Request"
    Command = 0x0001
    OFFSET = 24 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x19),
        FlagsField("Flags", 0, -8, ["SMB2_SESSION_FLAG_BINDING"]),
        FlagsField("SecurityMode", 0, -8, SMB2_SECURITY_MODE),
        FlagsField("Capabilities", 0, -32, SMB2_CAPABILITIES),
        LEIntField("Channel", 0),
        XLEShortField("SecurityBlobBufferOffset", None),
        LEShortField("SecurityBlobLen", None),
        XLELongField("PreviousSessionId", 0),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                PacketField("SecurityBlob", None, GSSAPI_BLOB),
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "SecurityBlob": 12,
                },
            )
            + pay
        )


bind_top_down(
    SMB2_Header,
    SMB2_Session_Setup_Request,
    Command=0x0001,
)

# sect 2.2.6


class SMB2_Session_Setup_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 Session Setup Response"
    Command = 0x0001
    OFFSET = 8 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x9),
        FlagsField(
            "SessionFlags",
            0,
            -16,
            {
                0x0001: "IS_GUEST",
                0x0002: "IS_NULL",
                0x0004: "ENCRYPT_DATE",
            },
        ),
        XLEShortField("SecurityBufferOffset", None),
        LEShortField("SecurityLen", None),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                PacketField("Security", None, GSSAPI_BLOB),
            ],
        ),
    ]

    def __getattr__(self, attr):
        # Ease SMB1 backward compatibility
        if attr == "SecurityBlob":
            return (
                super(SMB2_Session_Setup_Response, self).__getattr__("Buffer")
                or [(None, None)]
            )[0][1]
        return super(SMB2_Session_Setup_Response, self).__getattr__(attr)

    def setfieldval(self, attr, val):
        if attr == "SecurityBlob":
            return super(SMB2_Session_Setup_Response, self).setfieldval(
                "Buffer", [("Security", val)]
            )
        return super(SMB2_Session_Setup_Response, self).setfieldval(attr, val)

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Security": 4,
                },
            )
            + pay
        )


bind_top_down(
    SMB2_Header,
    SMB2_Session_Setup_Response,
    Command=0x0001,
    Flags=1,  # SMB2_FLAGS_SERVER_TO_REDIR
)

# sect 2.2.7


class SMB2_Session_Logoff_Request(_SMB2_Payload):
    name = "SMB2 LOGOFF Request"
    Command = 0x0002
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
    Command = 0x0002
    fields_desc = [
        XLEShortField("StructureSize", 0x4),
        ShortField("reserved", 0),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Session_Logoff_Response,
    Command=0x0002,
    Flags=1,  # SMB2_FLAGS_SERVER_TO_REDIR
)

# sect 2.2.9


class SMB2_Tree_Connect_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 TREE_CONNECT Request"
    Command = 0x0003
    OFFSET = 8 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x9),
        FlagsField(
            "Flags",
            0,
            -16,
            ["CLUSTER_RECONNECT", "REDIRECT_TO_OWNER", "EXTENSION_PRESENT"],
        ),
        XLEShortField("PathBufferOffset", None),
        LEShortField("PathLen", None),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                StrFieldUtf16("Path", b""),
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Path": 4,
                },
            )
            + pay
        )


bind_top_down(
    SMB2_Header,
    SMB2_Tree_Connect_Request,
    Command=0x0003,
)

# sect 2.2.10


class SMB2_Tree_Connect_Response(_SMB2_Payload):
    name = "SMB2 TREE_CONNECT Response"
    Command = 0x0003
    fields_desc = [
        XLEShortField("StructureSize", 0x10),
        ByteEnumField("ShareType", 0, {0x01: "DISK", 0x02: "PIPE", 0x03: "PRINT"}),
        ByteField("Reserved", 0),
        FlagsField(
            "ShareFlags",
            0x30,
            -32,
            {
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
            },
        ),
        FlagsField(
            "Capabilities",
            0,
            -32,
            {
                0x00000008: "DFS",
                0x00000010: "CONTINUOUS_AVAILABILITY",
                0x00000020: "SCALEOUT",
                0x00000040: "CLUSTER",
                0x00000080: "ASYMMETRIC",
                0x00000100: "REDIRECT_TO_OWNER",
            },
        ),
        FlagsField("MaximalAccess", 0, -32, SMB2_ACCESS_FLAGS_FILE),
    ]


bind_top_down(SMB2_Header, SMB2_Tree_Connect_Response, Command=0x0003, Flags=1)

# sect 2.2.11


class SMB2_Tree_Disconnect_Request(_SMB2_Payload):
    name = "SMB2 TREE_DISCONNECT Request"
    Command = 0x0004
    fields_desc = [
        XLEShortField("StructureSize", 0x4),
        XLEShortField("Reserved", 0),
    ]


bind_top_down(SMB2_Header, SMB2_Tree_Disconnect_Request, Command=0x0004)

# sect 2.2.12


class SMB2_Tree_Disconnect_Response(_SMB2_Payload):
    name = "SMB2 TREE_DISCONNECT Response"
    Command = 0x0004
    fields_desc = [
        XLEShortField("StructureSize", 0x4),
        XLEShortField("Reserved", 0),
    ]


bind_top_down(SMB2_Header, SMB2_Tree_Disconnect_Response, Command=0x0004, Flags=1)


# sect 2.2.14.1


class SMB2_FILEID(Packet):
    fields_desc = [XLELongField("Persistent", 0), XLELongField("Volatile", 0)]

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
        FlagsField("MaximalAccess", 0, -32, SMB2_ACCESS_FLAGS_FILE),
    ]


class SMB2_CREATE_QUERY_ON_DISK_ID(Packet):
    fields_desc = [
        XLELongField("DiskFileId", 0),
        XLELongField("VolumeId", 0),
        XStrFixedLenField("Reserved", b"", length=16),
    ]


class SMB2_CREATE_RESPONSE_LEASE(Packet):
    fields_desc = [
        XStrFixedLenField("LeaseKey", b"", length=16),
        FlagsField(
            "LeaseState",
            0x7,
            -32,
            {
                0x01: "SMB2_LEASE_READ_CACHING",
                0x02: "SMB2_LEASE_HANDLE_CACHING",
                0x04: "SMB2_LEASE_WRITE_CACHING",
            },
        ),
        FlagsField(
            "LeaseFlags",
            0,
            -32,
            {
                0x02: "SMB2_LEASE_FLAG_BREAK_IN_PROGRESS",
                0x04: "SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET",
            },
        ),
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
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x02: "SMB2_DHANDLE_FLAG_PERSISTENT",
            },
        ),
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
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x02: "SMB2_DHANDLE_FLAG_PERSISTENT",
            },
        ),
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
    OFFSET = 16
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        LEIntField("Next", None),
        XLEShortField("NameBufferOffset", None),
        LEShortField("NameLen", None),
        ShortField("Reserved", 0),
        XLEShortField("DataBufferOffset", None),
        LEIntField("DataLen", None),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                PadField(
                    StrLenField("Name", b"", length_from=lambda pkt: pkt.NameLen),
                    8,
                ),
                # Must be padded on 8-octet alignment
                PacketLenField(
                    "Data", None, conf.raw_layer, length_from=lambda pkt: pkt.DataLen
                ),
            ],
            force_order=["Name", "Data"],
        ),
        StrLenField(
            "pad",
            b"",
            length_from=lambda x: (
                x.Next
                - max(x.DataBufferOffset + x.DataLen, x.NameBufferOffset + x.NameLen)
            )
            if x.Next
            else 0,
        ),
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
                    b"E\xbc\xa6j\xef\xa7\xf7J\x90\x08\xfaF.\x14Mt": SMB2_CREATE_APP_INSTANCE_ID,  # noqa: E501
                    b"\xb9\x82\xd0\xb7;V\x07O\xa0{RJ\x81\x16\xa0\x10": SMB2_CREATE_APP_INSTANCE_VERSION,  # noqa: E501
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
        return (
            _NTLM_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Name": 4,
                    "Data": 10,
                },
                config=[
                    (
                        "BufferOffset",
                        {
                            "Name": _NTLM_ENUM.OFFSET,
                            "Data": _NTLM_ENUM.OFFSET | _NTLM_ENUM.PAD8,
                        },
                    ),
                    ("Len", _NTLM_ENUM.LEN),
                ],
            )
            + pay
        )


# sect 2.2.13

SMB2_OPLOCK_LEVELS = {
    0x00: "SMB2_OPLOCK_LEVEL_NONE",
    0x01: "SMB2_OPLOCK_LEVEL_II",
    0x08: "SMB2_OPLOCK_LEVEL_EXCLUSIVE",
    0x09: "SMB2_OPLOCK_LEVEL_BATCH",
    0xFF: "SMB2_OPLOCK_LEVEL_LEASE",
}


class SMB2_Create_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 CREATE Request"
    Command = 0x0005
    OFFSET = 56 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x39),
        ByteField("ShareType", 0),
        ByteEnumField("RequestedOplockLevel", 0, SMB2_OPLOCK_LEVELS),
        LEIntEnumField(
            "ImpersonationLevel",
            0,
            {
                0x00000000: "Anonymous",
                0x00000001: "Identification",
                0x00000002: "Impersonation",
                0x00000003: "Delegate",
            },
        ),
        LELongField("SmbCreateFlags", 0),
        LELongField("Reserved", 0),
        FlagsField("DesiredAccess", 0, -32, SMB2_ACCESS_FLAGS_FILE),
        FlagsField("FileAttributes", 0x00000080, -32, FileAttributes),
        FlagsField(
            "ShareAccess",
            0,
            -32,
            {
                0x00000001: "FILE_SHARE_READ",
                0x00000002: "FILE_SHARE_WRITE",
                0x00000004: "FILE_SHARE_DELETE",
            },
        ),
        LEIntEnumField(
            "CreateDisposition",
            1,
            {
                0x00000000: "FILE_SUPERSEDE",
                0x00000001: "FILE_OPEN",
                0x00000002: "FILE_CREATE",
                0x00000003: "FILE_OPEN_IF",
                0x00000004: "FILE_OVERWRITE",
                0x00000005: "FILE_OVERWRITE_IF",
            },
        ),
        FlagsField(
            "CreateOptions",
            0,
            -32,
            {
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
            },
        ),
        XLEShortField("NameBufferOffset", None),
        LEShortField("NameLen", None),
        XLEIntField("CreateContextsBufferOffset", None),
        LEIntField("CreateContextsLen", None),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                StrFieldUtf16("Name", b""),
                _NextPacketListField(
                    "CreateContexts",
                    [],
                    SMB2_Create_Context,
                    length_from=lambda pkt: pkt.CreateContextsLen,
                ),
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        if len(pkt) == 0x38:
            # 'In the request, the Buffer field MUST be at least one byte in length.'
            pkt += b"\x00"
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Name": 44,
                    "CreateContexts": 48,
                },
            )
            + pay
        )


bind_top_down(SMB2_Header, SMB2_Create_Request, Command=0x0005)


# sect 2.2.14


class SMB2_Create_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 CREATE Response"
    Command = 0x0005
    OFFSET = 88 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x59),
        ByteEnumField("OplockLevel", 0, SMB2_OPLOCK_LEVELS),
        FlagsField("Flags", 0, -8, {0x01: "SMB2_CREATE_FLAG_REPARSEPOINT"}),
        LEIntEnumField(
            "CreateAction",
            1,
            {
                0x00000000: "FILE_SUPERSEDED",
                0x00000001: "FILE_OPENED",
                0x00000002: "FILE_CREATED",
                0x00000003: "FILE_OVERWRITEN",
            },
        ),
        FileNetworkOpenInformation,
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        XLEIntField("CreateContextsBufferOffset", None),
        LEIntField("CreateContextsLen", None),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                _NextPacketListField(
                    "CreateContexts",
                    [],
                    SMB2_Create_Context,
                    length_from=lambda pkt: pkt.CreateContextsLen,
                ),
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "CreateContexts": 80,
                },
            )
            + pay
        )


bind_top_down(SMB2_Header, SMB2_Create_Response, Command=0x0005, Flags=1)

# sect 2.2.15


class SMB2_Close_Request(_SMB2_Payload):
    name = "SMB2 CLOSE Request"
    Command = 0x0006
    fields_desc = [
        XLEShortField("StructureSize", 0x18),
        FlagsField("Flags", 0, -16, ["SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB"]),
        LEIntField("Reserved", 0),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Close_Request,
    Command=0x0006,
)

# sect 2.2.16


class SMB2_Close_Response(_SMB2_Payload):
    name = "SMB2 CLOSE Response"
    Command = 0x0006
    FileAttributes = 0
    CreationTime = 0
    LastAccessTime = 0
    LastWriteTime = 0
    ChangeTime = 0
    fields_desc = [
        XLEShortField("StructureSize", 0x3C),
        FlagsField("Flags", 0, -16, ["SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB"]),
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
    Command = 0x0008
    OFFSET = 48 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x31),
        ByteField("Padding", 0x00),
        FlagsField(
            "Flags",
            0,
            -8,
            {
                0x01: "SMB2_READFLAG_READ_UNBUFFERED",
                0x02: "SMB2_READFLAG_REQUEST_COMPRESSED",
            },
        ),
        LEIntField("Length", 4280),
        LELongField("Offset", 0),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        LEIntField("MinimumCount", 0),
        LEIntEnumField(
            "Channel",
            0,
            {
                0x00000000: "SMB2_CHANNEL_NONE",
                0x00000001: "SMB2_CHANNEL_RDMA_V1",
                0x00000002: "SMB2_CHANNEL_RDMA_V1_INVALIDATE",
                0x00000003: "SMB2_CHANNEL_RDMA_TRANSFORM",
            },
        ),
        LEIntField("RemainingBytes", 0),
        LEShortField("ReadChannelInfoBufferOffset", None),
        LEShortField("ReadChannelInfoLen", None),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                StrLenField(
                    "ReadChannelInfo",
                    b"",
                    length_from=lambda pkt: pkt.ReadChannelInfoLen,
                )
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        if len(pkt) == 0x30:
            # 'The first byte of the Buffer field MUST be set to 0.'
            pkt += b"\x00"
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "ReadChannelInfo": 44,
                },
            )
            + pay
        )


bind_top_down(
    SMB2_Header,
    SMB2_Read_Request,
    Command=0x0008,
)

# sect 2.2.20


class SMB2_Read_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 READ Response"
    Command = 0x0008
    OFFSET = 16 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x11),
        LEShortField("DataBufferOffset", None),
        LEIntField("DataLen", None),
        LEIntField("DataRemaining", 0),
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x01: "SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM",
            },
        ),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [StrLenField("Data", b"", length_from=lambda pkt: pkt.DataLen)],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Data": 2,
                },
            )
            + pay
        )


bind_top_down(
    SMB2_Header,
    SMB2_Read_Response,
    Command=0x0008,
    Flags=1,
)


# sect 2.2.21


class SMB2_Write_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 WRITE Request"
    Command = 0x0009
    OFFSET = 48 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x31),
        LEShortField("DataBufferOffset", None),
        LEIntField("DataLen", None),
        LELongField("Offset", 0),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        LEIntEnumField(
            "Channel",
            0,
            {
                0x00000000: "SMB2_CHANNEL_NONE",
                0x00000001: "SMB2_CHANNEL_RDMA_V1",
                0x00000002: "SMB2_CHANNEL_RDMA_V1_INVALIDATE",
                0x00000003: "SMB2_CHANNEL_RDMA_TRANSFORM",
            },
        ),
        LEIntField("RemainingBytes", 0),
        LEShortField("WriteChannelInfoBufferOffset", None),
        LEShortField("WriteChannelInfoLen", None),
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x00000001: "SMB2_WRITEFLAG_WRITE_THROUGH",
                0x00000002: "SMB2_WRITEFLAG_WRITE_UNBUFFERED",
            },
        ),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                StrLenField("Data", b"", length_from=lambda pkt: pkt.DataLen),
                StrLenField(
                    "WriteChannelInfo",
                    b"",
                    length_from=lambda pkt: pkt.WriteChannelInfoLen,
                ),
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Data": 2,
                    "WriteChannelInfo": 40,
                },
            )
            + pay
        )


bind_top_down(
    SMB2_Header,
    SMB2_Write_Request,
    Command=0x0009,
)

# sect 2.2.22


class SMB2_Write_Response(_SMB2_Payload):
    name = "SMB2 WRITE Response"
    Command = 0x0009
    fields_desc = [
        XLEShortField("StructureSize", 0x11),
        LEShortField("Reserved", 0),
        LEIntField("Count", 0),
        LEIntField("Remaining", 0),
        LEShortField("WriteChannelInfoBufferOffset", 0),
        LEShortField("WriteChannelInfoLen", 0),
    ]


bind_top_down(SMB2_Header, SMB2_Write_Response, Command=0x0009, Flags=1)

# sect 2.2.28


class SMB2_Echo_Request(_SMB2_Payload):
    name = "SMB2 ECHO Request"
    Command = 0x000D
    fields_desc = [
        XLEShortField("StructureSize", 0x4),
        LEShortField("Reserved", 0),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Echo_Request,
    Command=0x000D,
)

# sect 2.2.29


class SMB2_Echo_Response(_SMB2_Payload):
    name = "SMB2 ECHO Response"
    Command = 0x000D
    fields_desc = [
        XLEShortField("StructureSize", 0x4),
        LEShortField("Reserved", 0),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Echo_Response,
    Command=0x000D,
    Flags=1,  # SMB2_FLAGS_SERVER_TO_REDIR
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
        SMB2_Negotiate_Protocol_Request.fields_desc[4:6]
        + SMB2_Negotiate_Protocol_Request.fields_desc[1:3][::-1]  # Cap/GUID
        + [SMB2_Negotiate_Protocol_Request.fields_desc[9]]  # SecMod/DC  # Dialects
    )


# sect 2.2.31


class _SMB2_IOCTL_Request_PacketLenField(PacketLenField):
    def m2i(self, pkt, m):
        if pkt.CtlCode == 0x00140204:  # FSCTL_VALIDATE_NEGOTIATE_INFO
            return SMB2_IOCTL_Validate_Negotiate_Info_Request(m)
        elif pkt.CtlCode == 0x00060194:  # FSCTL_DFS_GET_REFERRALS
            return SMB2_IOCTL_REQ_GET_DFS_Referral(m)
        elif pkt.CtlCode == 0x00094264:  # FSCTL_OFFLOAD_READ
            return SMB2_IOCTL_OFFLOAD_READ_Request(m)
        return conf.raw_layer(m)


class SMB2_IOCTL_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 IOCTL Request"
    Command = 0x000B
    OFFSET = 56 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    deprecated_fields = {
        "IntputCount": ("InputLen", "alias"),
        "OutputCount": ("OutputLen", "alias"),
    }
    fields_desc = [
        XLEShortField("StructureSize", 0x39),
        LEShortField("Reserved", 0),
        LEIntEnumField(
            "CtlCode",
            0,
            {
                0x00060194: "FSCTL_DFS_GET_REFERRALS",
                0x0011400C: "FSCTL_PIPE_PEEK",
                0x00110018: "FSCTL_PIPE_WAIT",
                0x0011C017: "FSCTL_PIPE_TRANSCEIVE",
                0x001440F2: "FSCTL_SRV_COPYCHUNK",
                0x00144064: "FSCTL_SRV_ENUMERATE_SNAPSHOTS",
                0x00140078: "FSCTL_SRV_REQUEST_RESUME_KEY",
                0x001441BB: "FSCTL_SRV_READ_HASH",
                0x001480F2: "FSCTL_SRV_COPYCHUNK_WRITE",
                0x001401D4: "FSCTL_LMR_REQUEST_RESILIENCY",
                0x001401FC: "FSCTL_QUERY_NETWORK_INTERFACE_INFO",
                0x000900A4: "FSCTL_SET_REPARSE_POINT",
                0x000601B0: "FSCTL_DFS_GET_REFERRALS_EX",
                0x00098208: "FSCTL_FILE_LEVEL_TRIM",
                0x00140204: "FSCTL_VALIDATE_NEGOTIATE_INFO",
                0x00094264: "FSCTL_OFFLOAD_READ",
            },
        ),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        LEIntField("InputBufferOffset", None),
        LEIntField("InputLen", None),  # Called InputCount but it's a length
        LEIntField("MaxInputResponse", 0),
        LEIntField("OutputBufferOffset", None),
        LEIntField("OutputLen", None),  # Called OutputCount.
        LEIntField("MaxOutputResponse", 1024),
        FlagsField("Flags", 0, -32, {0x00000001: "SMB2_0_IOCTL_IS_FSCTL"}),
        LEIntField("Reserved2", 0),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                _SMB2_IOCTL_Request_PacketLenField(
                    "Input", None, conf.raw_layer, length_from=lambda pkt: pkt.InputLen
                ),
                _SMB2_IOCTL_Request_PacketLenField(
                    "Output",
                    None,
                    conf.raw_layer,
                    length_from=lambda pkt: pkt.OutputLen,
                ),
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Input": 24,
                    "Output": 36,
                },
            )
            + pay
        )


bind_top_down(
    SMB2_Header,
    SMB2_IOCTL_Request,
    Command=0x000B,
)

# sect 2.2.32.5


class SOCKADDR_STORAGE(Packet):
    fields_desc = [
        LEShortEnumField("Family", 0x0002, {0x0002: "IPv4", 0x0017: "IPv6"}),
        ShortField("Port", 0),
        # IPv4
        ConditionalField(
            IPField("IPv4Adddress", None),
            lambda pkt: pkt.Family == 0x0002,
        ),
        ConditionalField(
            StrFixedLenField("Reserved", b"", length=8),
            lambda pkt: pkt.Family == 0x0002,
        ),
        # IPv6
        ConditionalField(
            LEIntField("FlowInfo", 0),
            lambda pkt: pkt.Family == 0x00017,
        ),
        ConditionalField(
            IP6Field("IPv6Address", None),
            lambda pkt: pkt.Family == 0x00017,
        ),
        ConditionalField(
            LEIntField("ScopeId", 0),
            lambda pkt: pkt.Family == 0x00017,
        ),
    ]

    def default_payload_class(self, _):
        return conf.padding_layer


class NETWORK_INTERFACE_INFO(Packet):
    fields_desc = [
        LEIntField("Next", None),  # 0 = no next entry
        LEIntField("IfIndex", 1),
        FlagsField(
            "Capability",
            1,
            -32,
            {
                0x00000001: "RSS_CAPABLE",
                0x00000002: "RDMA_CAPABLE",
            },
        ),
        LEIntField("Reserved", 0),
        ScalingField("LinkSpeed", 10000000000, fmt="<Q", unit="bit/s"),
        PacketField("SockAddr_Storage", SOCKADDR_STORAGE(), SOCKADDR_STORAGE),
    ]

    def default_payload_class(self, _):
        return conf.padding_layer


class SMB2_IOCTL_Network_Interface_Info(Packet):
    name = "SMB2 IOCTL Network Interface Info response"
    fields_desc = [
        _NextPacketListField("interfaces", [], NETWORK_INTERFACE_INFO),
    ]


# sect 2.2.32.6


class SMB2_IOCTL_Validate_Negotiate_Info_Response(Packet):
    name = "SMB2 IOCTL Validate Negotiate Info"
    fields_desc = (
        SMB2_Negotiate_Protocol_Response.fields_desc[4:6][::-1]
        + SMB2_Negotiate_Protocol_Response.fields_desc[  # Cap/GUID
            1:3
        ]  # SecMod/DialectRevision
    )


# [MS-FSCC] sect 2.3.42


class SMB2_IOCTL_OFFLOAD_READ_Request(Packet):
    name = "SMB2 IOCTL OFFLOAD_READ Request"
    fields_desc = [
        LEIntField("StructureSize", 0x20),
        LEIntField("Flags", 0),
        LEIntField("TokenTimeToLive", 0),
        LEIntField("Reserved", 0),
        LELongField("FileOffset", 0),
        LELongField("CopyLength", 0),
    ]


# [MS-FSCC] sect 2.1.11


class STORAGE_OFFLOAD_TOKEN(Packet):
    fields_desc = [
        LEIntEnumField(
            "TokenType",
            0xFFFF0001,
            {
                0xFFFF0001: "STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA",
            },
        ),
        LEShortField("Reserved", 0),
        FieldLenField("TokenIdLength", None, fmt="<H", length_of="TokenId"),
        StrFixedLenField("TokenId", b"", length=504),
    ]


# [MS-FSCC] sect 2.3.42


class SMB2_IOCTL_OFFLOAD_READ_Response(Packet):
    name = "SMB2 IOCTL OFFLOAD_READ Response"
    fields_desc = [
        LEIntField("StructureSize", 0x210),
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x00000001: "OFFLOAD_READ_FLAG_ALL_ZERO_BEYOND_CURRENT_RANGE",
            },
        ),
        LELongField("TransferLength", 0),
        PacketField("Token", STORAGE_OFFLOAD_TOKEN(), STORAGE_OFFLOAD_TOKEN),
    ]


# sect 2.2.32


class _SMB2_IOCTL_Response_PacketLenField(PacketLenField):
    def m2i(self, pkt, m):
        if pkt.CtlCode == 0x00140204:  # FSCTL_VALIDATE_NEGOTIATE_INFO
            return SMB2_IOCTL_Validate_Negotiate_Info_Response(m)
        elif pkt.CtlCode == 0x001401FC:  # FSCTL_QUERY_NETWORK_INTERFACE_INFO
            return SMB2_IOCTL_Network_Interface_Info(m)
        elif pkt.CtlCode == 0x00060194:  # FSCTL_DFS_GET_REFERRALS
            return SMB2_IOCTL_RESP_GET_DFS_Referral(m)
        return conf.raw_layer(m)


class SMB2_IOCTL_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 IOCTL Response"
    Command = 0x000B
    OFFSET = 48 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    StructureSize = 0x31
    MaxOutputResponse = 0
    fields_desc = (
        SMB2_IOCTL_Request.fields_desc[:6]
        + SMB2_IOCTL_Request.fields_desc[7:9]
        + SMB2_IOCTL_Request.fields_desc[10:12]
        + [
            _NTLMPayloadField(
                "Buffer",
                OFFSET,
                [
                    _SMB2_IOCTL_Response_PacketLenField(
                        "Input",
                        None,
                        conf.raw_layer,
                        length_from=lambda pkt: pkt.InputLen,
                    ),
                    _SMB2_IOCTL_Response_PacketLenField(
                        "Output",
                        None,
                        conf.raw_layer,
                        length_from=lambda pkt: pkt.OutputLen,
                    ),
                ],
            ),
        ]
    )

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Input": 24,
                    "Output": 32,
                },
            )
            + pay
        )


bind_top_down(
    SMB2_Header,
    SMB2_IOCTL_Response,
    Command=0x000B,
    Flags=1,  # SMB2_FLAGS_SERVER_TO_REDIR
)

# sect 2.2.33


class SMB2_Query_Directory_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 QUERY DIRECTORY Request"
    Command = 0x000E
    OFFSET = 32 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x21),
        ByteEnumField("FileInformationClass", 0x1, FileInformationClasses),
        FlagsField(
            "Flags",
            0,
            -8,
            {
                0x01: "SMB2_RESTART_SCANS",
                0x02: "SMB2_RETURN_SINGLE_ENTRY",
                0x04: "SMB2_INDEX_SPECIFIED",
                0x10: "SMB2_REOPEN",
            },
        ),
        LEIntField("FileIndex", 0),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        LEShortField("FileNameBufferOffset", None),
        LEShortField("FileNameLen", None),
        LEIntField("OutputBufferLength", 65535),
        _NTLMPayloadField("Buffer", OFFSET, [StrFieldUtf16("FileName", b"")]),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "FileName": 24,
                },
            )
            + pay
        )


bind_top_down(
    SMB2_Header,
    SMB2_Query_Directory_Request,
    Command=0x000E,
)

# sect 2.2.34


class SMB2_Query_Directory_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 QUERY DIRECTORY Response"
    Command = 0x000E
    OFFSET = 8 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x9),
        LEShortField("OutputBufferOffset", None),
        LEIntField("OutputLen", None),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                # TODO
                StrFixedLenField("Output", b"", length_from=lambda pkt: pkt.OutputLen)
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Output": 2,
                },
            )
            + pay
        )


bind_top_down(
    SMB2_Header,
    SMB2_Query_Directory_Response,
    Command=0x000E,
    Flags=1,
)

# sect 2.2.35


class SMB2_Change_Notify_Request(_SMB2_Payload):
    name = "SMB2 CHANGE NOTIFY Request"
    Command = 0x000F
    fields_desc = [
        XLEShortField("StructureSize", 0x20),
        FlagsField(
            "Flags",
            0,
            -16,
            {
                0x0001: "SMB2_WATCH_TREE",
            },
        ),
        LEIntField("OutputBufferLength", 2048),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        FlagsField(
            "CompletionFilter",
            0,
            -32,
            {
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
                0x00000800: "FILE_NOTIFY_CHANGE_STREAM_WRITE",
            },
        ),
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
    Command = 0x000F
    OFFSET = 8 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x9),
        LEShortField("OutputBufferOffset", None),
        LEIntField("OutputLen", None),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                _NextPacketListField(
                    "Output",
                    [],
                    FILE_NOTIFY_INFORMATION,
                    length_from=lambda pkt: pkt.OutputLen,
                    max_count=1000,
                )
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Output": 2,
                },
            )
            + pay
        )


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
        StrLenField(
            "pad",
            b"",
            length_from=lambda x: (
                (x.NextEntryOffset - x.SidLength) if x.NextEntryOffset else 0
            ),
        ),
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
                (
                    PacketListField(
                        "SidBuffer",
                        [],
                        FILE_GET_QUOTA_INFORMATION,
                        length_from=lambda x: x.SidListLength,
                    ),
                    lambda x: x.SidListLength,
                ),
                (
                    StrLenField(
                        "SidBuffer", b"", length_from=lambda x: x.StartSidLength
                    ),
                    lambda x: x.StartSidLength,
                ),
            ],
            StrFixedLenField("SidBuffer", b"", length=0),
        ),
    ]


class SMB2_Query_Info_Request(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 QUERY INFO Request"
    Command = 0x0010
    OFFSET = 40 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x29),
        ByteEnumField(
            "InfoType",
            0,
            {
                0x01: "SMB2_0_INFO_FILE",
                0x02: "SMB2_0_INFO_FILESYSTEM",
                0x03: "SMB2_0_INFO_SECURITY",
                0x04: "SMB2_0_INFO_QUOTA",
            },
        ),
        ByteEnumField("FileInfoClass", 0, FileInformationClasses),
        LEIntField("OutputBufferLength", 0),
        XLEIntField("InputBufferOffset", None),  # Short + Reserved = Int
        LEIntField("InputLen", None),
        FlagsField(
            "AdditionalInformation",
            0,
            -32,
            {
                0x00000001: "OWNER_SECURITY_INFORMATION",
                0x00000002: "GROUP_SECURITY_INFORMATION",
                0x00000004: "DACL_SECURITY_INFORMATION",
                0x00000008: "SACL_SECURITY_INFORMATION",
                0x00000010: "LABEL_SECURITY_INFORMATION",
                0x00000020: "ATTRIBUTE_SECURITY_INFORMATION",
                0x00000040: "SCOPE_SECURITY_INFORMATION",
                0x00010000: "BACKUP_SECURITY_INFORMATION",
            },
        ),
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x00000001: "SL_RESTART_SCAN",
                0x00000002: "SL_RETURN_SINGLE_ENTRY",
                0x00000004: "SL_INDEX_SPECIFIED",
            },
        ),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                PacketListField(
                    "Input",
                    None,
                    SMB2_Query_Quota_Info,
                    length_from=lambda pkt: pkt.InputLen,
                ),
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Input": 4,
                },
            )
            + pay
        )


bind_top_down(
    SMB2_Header,
    SMB2_Query_Info_Request,
    Command=0x00010,
)


class SMB2_Query_Info_Response(_SMB2_Payload, _NTLMPayloadPacket):
    name = "SMB2 QUERY INFO Response"
    Command = 0x0010
    OFFSET = 8 + 64
    _NTLM_PAYLOAD_FIELD_NAME = "Buffer"
    fields_desc = [
        XLEShortField("StructureSize", 0x9),
        LEShortField("OutputBufferOffset", None),
        LEIntField("OutputLen", None),
        _NTLMPayloadField(
            "Buffer",
            OFFSET,
            [
                # TODO
                StrFixedLenField("Output", b"", length_from=lambda pkt: pkt.OutputLen)
            ],
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _SMB2_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "Output": 2,
                },
            )
            + pay
        )


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
        LEShortEnumField("CompressionAlgorithm", 0, SMB2_COMPRESSION_ALGORITHMS),
        ShortEnumField(
            "Flags",
            0x0,
            {
                0x0000: "SMB2_COMPRESSION_FLAG_NONE",
                0x0001: "SMB2_COMPRESSION_FLAG_CHAINED",
            },
        ),
        XLEIntField("Offset_or_Length", 0),
    ]


# [MS-DFSC] sect 2.2


class SMB2_IOCTL_REQ_GET_DFS_Referral(Packet):
    fields_desc = [
        LEShortField("MaxReferralLevel", 0),
        StrNullFieldUtf16("RequestFileName", ""),
    ]


class DFS_REFERRAL(Packet):
    fields_desc = [
        LEShortField("Version", 1),
        FieldLenField(
            "Size", None, fmt="<H", length_of="ShareName", adjust=lambda pkt, x: x + 9
        ),
        LEShortEnumField("ServerType", 0, {0: "non-root", 1: "root"}),
        LEShortField("ReferralEntryFlags", 0),
        StrNullFieldUtf16("ShareName", ""),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            version = struct.unpack("<H", _pkt[:2])[0]
            if version == 1:
                return DFS_REFERRAL
            elif version == 3:
                return DFS_REFERRAL_V3
            elif version == 4:
                return DFS_REFERRAL_V4
        return cls

    def default_payload_class(self, s):
        return conf.padding_layer


class DFS_REFERRAL_V3(DFS_REFERRAL):
    fields_desc = [
        LEShortField("Version", 3),
        LEShortField("Size", None),
        LEShortEnumField("ServerType", 0, {0: "non-root", 1: "root"}),
        FlagsField(
            "ReferralEntryFlags",
            0,
            -16,
            {
                0x0002: "NameListReferral",
                0x0004: "TargetSetBoundary",
            },
        ),
        LEIntField("TimeToLive", 300),
        # NameListReferral is 0
        ConditionalField(
            LEShortField("DFSPathOffset", None),
            lambda pkt: not pkt.ReferralEntryFlags.NameListReferral,
        ),
        ConditionalField(
            LEShortField("DFSAlternatePathOffset", None),
            lambda pkt: not pkt.ReferralEntryFlags.NameListReferral,
        ),
        ConditionalField(
            LEShortField("NetworkAddressOffset", None),
            lambda pkt: not pkt.ReferralEntryFlags.NameListReferral,
        ),
        ConditionalField(
            StrFixedLenField("ServiceSiteGuid", 0, length=16),
            lambda pkt: not pkt.ReferralEntryFlags.NameListReferral,
        ),
        # NameListReferral is 1
        ConditionalField(
            LEShortField("SpecialNameOffset", None),
            lambda pkt: pkt.ReferralEntryFlags.NameListReferral,
        ),
        ConditionalField(
            LEShortField("NumberOfExpandedNames", None),
            lambda pkt: pkt.ReferralEntryFlags.NameListReferral,
        ),
        ConditionalField(
            LEShortField("ExpandedNameOffset", None),
            lambda pkt: pkt.ReferralEntryFlags.NameListReferral,
        ),
        ConditionalField(
            StrLenField("Padding", None, length_from=lambda pkt: pkt.Size - 18),
            lambda pkt: pkt.ReferralEntryFlags.NameListReferral,
        ),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        if self.Size is None:
            pkt = pkt[:2] + struct.pack("<H", len(pkt)) + pkt[4:]
        return pkt + pay


class DFS_REFERRAL_V4(DFS_REFERRAL_V3):
    Version = 4


class DFS_REFERRAL_ENTRY0(Packet):
    fields_desc = [
        StrNullFieldUtf16("DFSPath", ""),
        StrNullFieldUtf16("DFSAlternatePath", ""),
        StrNullFieldUtf16("NetworkAddress", ""),
    ]


class DFS_REFERRAL_ENTRY1(Packet):
    fields_desc = [
        StrNullFieldUtf16("SpecialName", ""),
        FieldListField(
            "ExpandedName",
            [],
            StrNullFieldUtf16("", ""),
        ),
    ]


class _DFS_Referrals_BufferField(PacketListField):
    def getfield(self, pkt, s):
        results = []
        offset = sum(x.Size for x in pkt.ReferralEntries)
        for ref in pkt.ReferralEntries:
            # For every ref
            if not ref.ReferralEntryFlags.NameListReferral:
                cls = DFS_REFERRAL_ENTRY0
            else:
                cls = DFS_REFERRAL_ENTRY1
            # Build the fields manually
            fld = _NTLMPayloadField(
                "",
                offset,
                cls.fields_desc,
                force_order=[x.name for x in cls.fields_desc],
                offset_name="Offset",
            )
            remain, vals = fld.getfield(ref, s)
            vals = fld.i2h(ref, vals)
            # Append the entry class
            results.append(cls(**{x[0]: x[1] for x in vals}))
            offset -= ref.Size
        return b"", results

    def addfield(self, pkt, s, vals):
        offset = sum(len(x) for x in pkt.ReferralEntries)
        for i, val in enumerate(vals):
            try:
                ref = pkt.ReferralEntries[i]
            except KeyError:
                ref = None
            fld = _NTLMPayloadField(
                "",
                offset,
                val.fields_desc,
                force_order=[x.name for x in val.fields_desc],
                offset_name="Offset",
            )
            # Append the bytes manually
            values = [(fld.name, getattr(val, fld.name)) for fld in val.fields_desc]
            values = fld.h2i(ref, values)
            s += fld.addfield(ref, b"", values)
            offset -= len(ref)
        return s


class SMB2_IOCTL_RESP_GET_DFS_Referral(Packet):
    fields_desc = [
        LEShortField("PathConsumed", 0),
        FieldLenField("NumberOfReferrals", None, fmt="<H", count_of="ReferralEntries"),
        FlagsField(
            "ReferralHeaderFlags",
            0,
            -32,
            {
                0x00000001: "ReferralServers",
                0x00000002: "StorageServers",
                0x00000004: "TargetFailback",
            },
        ),
        PacketListField(
            "ReferralEntries",
            [],
            DFS_REFERRAL,
            count_from=lambda pkt: pkt.NumberOfReferrals,
        ),
        _DFS_Referrals_BufferField("ReferralBuffer", []),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        # Note: Windows is smart and uses some sort of compression in the sense
        # that it re-uses fields that are used several times across ReferralBuffer.
        # But we just do the dumb thing because it's 'easier', and do no compression.
        offsets = {
            # DFS_REFERRAL_ENTRY0
            "DFSPath": 12,
            "DFSAlternatePath": 14,
            "NetworkAddress": 16,
            # DFS_REFERRAL_ENTRY1
            "SpecialName": 12,
            "ExpandedName": 16,
        }
        # dataoffset = pointer in the ReferralBuffer
        # entryoffset = pointer in the ReferralEntries
        dataoffset = sum(len(x) for x in self.ReferralEntries)
        entryoffset = 8
        for ref, buf in zip(self.ReferralEntries, self.ReferralBuffer):
            for fld in buf.fields_desc:
                off = entryoffset + offsets[fld.name]
                if ref.getfieldval(fld.name + "Offset") is None and buf.getfieldval(
                    fld.name
                ):
                    pkt = pkt[:off] + struct.pack("<H", dataoffset) + pkt[off + 2 :]
                dataoffset += len(fld.addfield(self, b"", buf.getfieldval(fld.name)))
            dataoffset -= len(ref)
            entryoffset += len(ref)
        return pkt + pay


# [MS-SMB2] various usages


def SMB2computePreauthIntegrityHashValue(
    PreauthIntegrityHashValue, s, HashId="SHA-512"
):
    """
    Update the PreauthIntegrityHashValue
    """
    # get hasher
    hasher = {"SHA-512": hashlib.sha512}[HashId]
    # compute the hash of concatenation of previous and bytes
    return hasher(PreauthIntegrityHashValue + s).digest()
