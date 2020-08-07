# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
SMB (Server Message Block), also known as CIFS - version 2
"""

from scapy.config import conf
from scapy.packet import Packet, bind_layers, bind_top_down
from scapy.fields import (
    FieldLenField,
    FieldListField,
    FlagsField,
    IntEnumField,
    IntField,
    LEIntField,
    LELongField,
    LEShortEnumField,
    LEShortField,
    PacketListField,
    PadField,
    ShortEnumField,
    ShortField,
    StrFieldUtf16,
    StrFixedLenField,
    UUIDField,
    XLEIntField,
    XLELongField,
    XLEShortField,
    XLongField,
    XNBytesField,
    XStrLenField,
)


# EnumField
SMB_DIALECTS = {
    0x0202: 'SMB 2.0.2',
    0x0210: 'SMB 2.1',
    0x0300: 'SMB 3.0',
    0x0302: 'SMB 3.0.2',
    0x0311: 'SMB 3.1.1',
}

# EnumField
SMB2_NEGOCIATE_CONTEXT_TYPES = {
    0x0001: 'SMB2_PREAUTH_INTEGRITY_CAPABILITIES',
    0x0002: 'SMB2_ENCRYPTION_CAPABILITIES',
    0x0003: 'SMB2_COMPRESSION_CAPABILITIES',
    0x0005: 'SMB2_NETNAME_NEGOCIATE_CONTEXT_ID',
}

# FlagField
SMB2_CAPABILITIES = {
    30: "Encryption",
    29: "DirectoryLeasing",
    28: "PersistentHandles",
    27: "MultiChannel",
    26: "LargeMTU",
    25: "Leasing",
    24: "DFS",
}

# EnumField
SMB2_COMPRESSION_ALGORITHMS = {
    0x0000: "None",
    0x0001: "LZNT1",
    0x0002: "LZ77",
    0x0003: "LZ77 + Huffman",
    0x0004: "Pattern_V1",
}


class SMB2_Header(Packet):
    name = "SMB2 Header"
    fields_desc = [
        StrFixedLenField("Start", b"\xfeSMB", 4),
        LEShortField("HeaderLength", 0),
        LEShortField("CreditCharge", 0),
        LEShortField("ChannelSequence", 0),
        LEShortField("Unused", 0),
        ShortEnumField("Command", 0, {0x0000: "SMB2_COM_NEGOCIATE"}),
        LEShortField("CreditsRequested", 0),
        # XLEIntField("Flags", 0),
        FlagsField("Flags", 0, 32, {
            24: "SMB2_FLAGS_SERVER_TO_REDIR",
        }),
        XLEIntField("ChainOffset", 0),
        LELongField("MessageID", 0),
        XLEIntField("ProcessID", 0),
        XLEIntField("TreeID", 0),
        XLELongField("SessionID", 0),
        XNBytesField("Signature", 0, 16),
    ]

    def guess_payload_class(self, payload):
        if self.Command == 0x0000:
            if self.Flags.SMB2_FLAGS_SERVER_TO_REDIR:
                return SMB2_Negociate_Protocol_Response_Header
            return SMB2_Negociate_Protocol_Request_Header
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
        XLEIntField("Offset/Length", 0),
    ]


class SMB2_Negociate_Context(Packet):
    name = "SMB2 Negociate Context"
    fields_desc = [
        LEShortEnumField("ContextType", 0x0, SMB2_NEGOCIATE_CONTEXT_TYPES),
        FieldLenField("DataLength", 0x0, fmt="<H", length_of="Data"),
        IntField("Reserved", 0),
    ]


class SMB2_Negociate_Protocol_Request_Header(Packet):
    name = "SMB2 Negociate Protocol Request Header"
    fields_desc = [
        XLEShortField("StructureSize", 0),
        FieldLenField(
            "DialectCount", 0,
            fmt="<H",
            count_of="Dialects"
        ),
        # SecurityMode
        FlagsField("SecurityMode", 0, 16, {
            0x7: "Signing Required",
            0x8: "Signing Enabled",
        }),
        LEShortField("Reserved", 0),
        # Capabilities
        FlagsField("Capabilities", 0, 32, SMB2_CAPABILITIES),
        UUIDField("ClientGUID", 0x0, uuid_fmt=UUIDField.FORMAT_LE),
        XLEIntField("NegociateContextOffset", 0x0),
        FieldLenField(
            "NegociateCount", 0x0,
            fmt="<H",
            count_of="NegociateContexts"
        ),
        ShortField("Reserved2", 0),
        # Padding the dialects - the whole packet (from the
        # beginning) should be aligned on 8 bytes ; so the list of
        # dialects should be aligned on 6 bytes (because it starts
        # at PKT + 8 * N + 2
        PadField(FieldListField(
            "Dialects", [0x0202],
            LEShortEnumField("", 0x0, SMB_DIALECTS),
            count_from=lambda pkt: pkt.DialectCount
        ), 6),
        PacketListField(
            "NegociateContexts", [],
            SMB2_Negociate_Context,
            count_from=lambda pkt: pkt.NegociateCount
        ),
    ]


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
        # Pad the whole packet on 8 bytes
        XStrLenField(
            "Padding", "",
            length_from=lambda pkt:
                    (8 - (4 + pkt.HashAlgorithmCount * 2 + pkt.SaltLength)) % 8
        ),
    ]


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
        # Pad the whole packet on 8 bytes
        XStrLenField(
            "Padding", "",
            length_from=lambda pkt: (8 - (2 + pkt.CipherCount * 2)) % 8
        ),
    ]


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
        # Pad the whole packet on 8 bytes
        XStrLenField(
            "Padding2", "",
            length_from=lambda pkt:
                    (8 - (2 + 2 + 4 + pkt.CompressionAlgorithmCount * 2)) % 8
        ),
    ]


class SMB2_Netname_Negociate_Context_ID(Packet):
    name = "SMB2 Netname Negociate Context ID"
    fields_desc = [
        StrFieldUtf16("NetName", "")
    ]


class SMB2_Negociate_Protocol_Response_Header(Packet):
    name = "SMB2 Negociate Protocol Response Header"
    fields_desc = [
        XLEShortField("StructureSize", 0),
        FlagsField("SecurityMode", 0, 16, {
            0x7: "Signing Required",
            0x8: "Signing Enabled",
        }),
        LEShortEnumField("Dialect", 0x0, SMB_DIALECTS),
        FieldLenField(
            "NegociateCount", 0x0,
            fmt="<H",
            count_of="NegociateContexts"
        ),
        UUIDField("ServerGUID", 0x0, uuid_fmt=UUIDField.FORMAT_LE),
        # Capabilities
        FlagsField("Capabilities", 0, 32, SMB2_CAPABILITIES),
        LEIntField("MaxTransactionSize", 0),
        LEIntField("MaxReadSize", 0),
        LEIntField("MaxWriteSize", 0),
        # TODO FIXME
        XLongField("SystemTime", 0),
        XLongField("ServerStartTime", 0),
        XLEShortField("SecurityBufferOffset", 0),
        FieldLenField(
            "SecurityBufferLength", 0,
            fmt="<H",
            length_of="SecurityBuffer"
        ),
        XLEIntField("NegociateContextOffset", 0),
        # TODO FIXME
        XStrLenField(
            "SecurityBuffer", None,
            length_from=lambda pkt: pkt.SecurityBufferLength
        ),
        PacketListField(
            "NegociateContexts", [],
            SMB2_Negociate_Context,
            count_from=lambda pkt: pkt.NegociateCount
        ),
    ]


bind_layers(SMB2_Preauth_Integrity_Capabilities, conf.padding_layer)
bind_layers(SMB2_Encryption_Capabilities, conf.padding_layer)
bind_layers(SMB2_Compression_Capabilities, conf.padding_layer)
bind_layers(SMB2_Netname_Negociate_Context_ID, conf.padding_layer)
bind_top_down(
    SMB2_Header,
    SMB2_Negociate_Protocol_Request_Header,
    Command=0x0000,
    Flags=0
)
bind_top_down(
    SMB2_Header,
    SMB2_Negociate_Protocol_Response_Header,
    Command=0x0000,
    Flags=2 ** 24  # SMB2_FLAGS_SERVER_TO_REDIR
)
bind_layers(
    SMB2_Negociate_Context,
    SMB2_Preauth_Integrity_Capabilities,
    ContextType=0x0001
)
bind_layers(
    SMB2_Negociate_Context,
    SMB2_Encryption_Capabilities,
    ContextType=0x0002
)
bind_layers(
    SMB2_Negociate_Context,
    SMB2_Compression_Capabilities,
    ContextType=0x0003
)
bind_layers(
    SMB2_Negociate_Context,
    SMB2_Netname_Negociate_Context_ID,
    ContextType=0x0005
)
