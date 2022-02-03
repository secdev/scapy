# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
SMB (Server Message Block), also known as CIFS - version 2
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
    IntEnumField,
    IntField,
    LEIntField,
    LELongField,
    LEShortEnumField,
    LEShortField,
    PacketField,
    PacketLenField,
    ReversePadField,
    ShortEnumField,
    ShortField,
    StrFieldUtf16,
    StrFixedLenField,
    UTCTimeField,
    UUIDField,
    XLEIntField,
    XLELongField,
    XLEShortField,
    XNBytesField,
    XStrLenField,
    XStrFixedLenField,
    XStrField,
)

from scapy.layers.gssapi import GSSAPI_BLOB
from scapy.layers.ntlm import _NTLMPayloadField


# EnumField
SMB_DIALECTS = {
    0x0202: 'SMB 2.002',
    0x0210: 'SMB 2.1',
    0x02ff: 'SMB 2.???',
    0x0300: 'SMB 3.0',
    0x0302: 'SMB 3.0.2',
    0x0311: 'SMB 3.1.1',
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


def _SMB2_post_build(self, p, pay_offset, fields):
    """Util function to build the offset and populate the lengths"""
    for field_name, value in self.fields["Buffer"]:
        length = self.get_field(
            "Buffer").fields_map[field_name].i2len(self, value)
        offset = fields[field_name]
        # Offset
        if self.getfieldval(field_name + "BufferOffset") is None:
            p = p[:offset] + \
                struct.pack("<H", pay_offset) + p[offset + 2:]
        # Len
        if self.getfieldval(field_name + "Len") is None:
            p = p[:offset + 2] + \
                struct.pack("<H", length) + p[offset + 4:]
        pay_offset += length
    return p

# SMB2 sect 2.2.1.1


class SMB2_Header(Packet):
    name = "SMB2 Header"
    fields_desc = [
        StrFixedLenField("Start", b"\xfeSMB", 4),
        LEShortField("StructureSize", 64),
        LEShortField("CreditCharge", 0),
        LEIntField("Status", 0),
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
        LELongField("MessageId", 0),
        LELongField("AsyncId", 0),
        LELongField("SessionId", 0),
        XNBytesField("SecuritySignature", 0, 16),
    ]

    def guess_payload_class(self, payload):
        if self.Command == 0x0000:  # Negotiate
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Negotiate_Protocol_Response
            return SMB2_Negotiate_Protocol_Request
        elif self.Command == 0x0001:  # Setup
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Session_Setup_Response
            return SMB2_Session_Setup_Request
        elif self.Command == 0x0003:  # TREE connect
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Tree_Connect_Response
            return SMB2_Tree_Connect_Request
        elif self.Command == 0x0006:  # Close
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                pass
            return SMB2_Close_Request
        elif self.Command == 0x000B:  # IOCTL
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                pass
            return SMB2_IOCTL_Request
        return super(SMB2_Header, self).guess_payload_class(payload)


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

# sect 2.2.2


class SMB2_Error_Response(Packet):
    name = "SMB2 Negotiate Context"
    fields_desc = [
        XLEShortField("StructureSize", 0x09),
        ByteField("ErrorContextCount", 0),
        ByteField("Reserved", 0),
        FieldLenField(
            "ByteCount", None,
            fmt="<I",
            count_of="ErrorData"
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


class SMB2_Negotiate_Protocol_Request(Packet):
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

# sect 2.2.4


class SMB2_Negotiate_Protocol_Response(Packet):
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


class SMB2_Session_Setup_Request(Packet):
    name = "SMB2 Session Setup Request"
    OFFSET = 24 + 64
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


class SMB2_Session_Setup_Response(Packet):
    name = "SMB2 Session Setup Response"
    OFFSET = 8 + 64
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


# sect 2.2.9


class SMB2_Tree_Connect_Request(Packet):
    name = "SMB2 TREE_CONNECT Request"
    OFFSET = 8 + 64
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


class SMB2_Tree_Connect_Response(Packet):
    name = "SMB2 TREE_CONNECT Response"
    OFFSET = 8 + 64
    fields_desc = [
        XLEShortField("StructureSize", 0x9),
        ByteEnumField("ShareType", 0, {0x01: "DISK",
                                       0x02: "PIPE",
                                       0x03: "PRINT"}),
        ByteField("Reserved", 0),
        FlagsField("ShareFlags", 0, -32, {
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
        FlagsField("Capabilities", 0, -32, {}),
        XLEIntField("MaximalAccess", 0),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Tree_Connect_Response,
    Command=0x0003,
    Flags=1
)

# sect 2.2.14.1


class SMB2_FILEID(Packet):
    fields_desc = [
        LELongField("Persistent", 0),
        LELongField("Volatile", 0)
    ]

# sect 2.2.15


class SMB2_Close_Request(Packet):
    name = "SMB2 CLOSE Request"
    fields_desc = [
        XLEShortField("StructureSize", 0x18),
        FlagsField("Flags", 0, -16,
                   ["POSTQUERY_ATTRIB"]),
        LEIntField("Reserved", 0),
        PacketField("FileId", SMB2_FILEID(), SMB2_FILEID)
    ]


bind_top_down(
    SMB2_Header,
    SMB2_Close_Request,
    Command=0x0006,
)


# sect 2.2.31


class SMB2_IOCTL_Request(Packet):
    name = "SMB2 IOCTL Request"
    # Barely implemented
    fields_desc = [
        XLEShortField("StructureSize", 0x39),
        LEShortField("Reserved", 0),
        LEIntField("CtlCode", 0),
        XStrFixedLenField("FileId", b"", length=16),
        LEIntField("InputOffset", 0),
        LEIntField("InputCount", 0),
        LEIntField("MaxInputResponse", 0),
        LEIntField("OutputOffset", 0),
        LEIntField("OutputCount", 0),
        LEIntField("MaxOutputResponse", 0),
        LEIntField("Flags", 0),
        LEIntField("Reserved2", 0),
        XStrField("Buffer", b""),
    ]


bind_top_down(
    SMB2_Header,
    SMB2_IOCTL_Request,
    Command=0x000B,
)

# sect 2.2.32


class SMB2_IOCTL_Response(Packet):
    name = "SMB2 IOCTL Request"
    # Barely implemented
    StructureSize = 0x31
    fields_desc = (
        SMB2_IOCTL_Request.fields_desc[:6] +
        SMB2_IOCTL_Request.fields_desc[7:9] +
        SMB2_IOCTL_Request.fields_desc[10:]
    )


bind_top_down(
    SMB2_Header,
    SMB2_IOCTL_Response,
    Command=0x000B,
    Flags=1  # SMB2_FLAGS_SERVER_TO_REDIR
)
