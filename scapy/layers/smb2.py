# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

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
    XStrLenField,
    XStrFixedLenField,
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

# SMB2 sect 3.3.5.15 + [MS-ERREF]
STATUS_ERREF = {
    0x00000000: "STATUS_SUCCESS",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000128: "STATUS_FILE_CLOSED",  # backup error for older Win versions
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0x80000005: "STATUS_BUFFER_OVERFLOW",
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


def _SMB2_post_build(self, p, pay_offset, fields):
    """Util function to build the offset and populate the lengths"""
    for field_name, value in self.fields["Buffer"]:
        length = self.get_field(
            "Buffer").fields_map[field_name].i2len(self, value)
        offset = fields[field_name]
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
    name = "SMB2 Error Response"
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
        XLEShortField("StructureSize", 0x10),
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
        FlagsField("Capabilities", 0, -32, {
            0x00000008: "DFS",
            0x00000010: "CONTINUOUS_AVAILABILITY",
            0x00000020: "SCALEOUT",
            0x00000040: "CLUSTER",
            0x00000080: "ASYMETRIC",
            0x00000100: "REDIRECT_TO_OWNER",
        }),
        FlagsField("MaximalAccess", 0, -32, {
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
        }),
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
        XLELongField("Persistent", 0),
        XLELongField("Volatile", 0)
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer

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


# sect 2.2.31.4

class SMB2_IOCTL_Validate_Negotiate_Info(Packet):
    name = "SMB2 IOCTL Validate Negotiate Info"
    fields_desc = (
        SMB2_Negotiate_Protocol_Request.fields_desc[4:6] +  # Cap/GUID
        SMB2_Negotiate_Protocol_Request.fields_desc[1:3][::-1] +  # SecMod/DC
        [SMB2_Negotiate_Protocol_Request.fields_desc[9]]  # Dialects
    )


class _SMB2_IOCTL_PacketLenField(PacketLenField):
    def m2i(self, pkt, m):
        if pkt.CtlCode == 0x00140204:  # FSCTL_VALIDATE_NEGOTIATE_INFO
            return SMB2_IOCTL_Validate_Negotiate_Info(m)
        return conf.raw_layer(m)


# sect 2.2.31


class SMB2_IOCTL_Request(Packet):
    name = "SMB2 IOCTL Request"
    OFFSET = 56 + 64
    deprecated_fields = {
        "IntputCount": ("InputLen", "alias"),
        "OutputCount": ("OutputLen", "alias"),
    }
    fields_desc = [
        XLEShortField("StructureSize", 0x39),
        LEShortField("Reserved", 0),
        LEIntEnumField("CtlCode", 0, {
            0x00060194: "FSCTL_DFS_GET_REFERRALS",
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
                _SMB2_IOCTL_PacketLenField(
                    "Input", None, conf.raw_layer,
                    length_from=lambda pkt: pkt.InputLen),
                _SMB2_IOCTL_PacketLenField(
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
