# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

# scapy.contrib.description = DCE/RPC
# scapy.contrib.status = loads

"""
DCE/RPC
Distributed Computing Environment / Remote Procedure Calls

Based on [C706] - aka DCE/RPC 1.1
https://pubs.opengroup.org/onlinepubs/9629399/toc.pdf

And on [MS-RPCE]
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15

.. note::
    Please read the documentation over
    `DCE/RPC <https://scapy.readthedocs.io/en/latest/layers/dcerpc.html>`_
"""

from functools import partial

import collections
import struct
from enum import IntEnum
from uuid import UUID
from scapy.base_classes import Packet_metaclass

from scapy.config import conf
from scapy.compat import bytes_encode, plain_str
from scapy.error import log_runtime
from scapy.layers.dns import DNSStrField
from scapy.layers.ntlm import (
    NTLM_Header,
    NTLMSSP_MESSAGE_SIGNATURE,
)
from scapy.packet import (
    Packet,
    Raw,
    bind_bottom_up,
    bind_layers,
    bind_top_down,
    NoPayload,
)
from scapy.fields import (
    _FieldContainer,
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    EnumField,
    Field,
    FieldLenField,
    FieldListField,
    FlagsField,
    IntField,
    LEIntEnumField,
    LEIntField,
    LELongField,
    LEShortEnumField,
    LEShortField,
    LenField,
    MultipleTypeField,
    PacketField,
    PacketLenField,
    PacketListField,
    PadField,
    ReversePadField,
    ShortEnumField,
    ShortField,
    SignedByteField,
    StrField,
    StrFixedLenField,
    StrLenField,
    StrLenFieldUtf16,
    StrNullField,
    StrNullFieldUtf16,
    TrailerField,
    UUIDEnumField,
    UUIDField,
    XByteField,
    XLEIntField,
    XLELongField,
    XLEShortField,
    XShortField,
    XStrFixedLenField,
)
from scapy.sessions import DefaultSession
from scapy.supersocket import StreamSocket

from scapy.layers.kerberos import (
    KRB_InnerToken,
    Kerberos,
)
from scapy.layers.gssapi import (
    GSS_S_COMPLETE,
    GSSAPI_BLOB_SIGNATURE,
    GSSAPI_BLOB,
    SSP,
)
from scapy.layers.inet import TCP

from scapy.contrib.rtps.common_types import (
    EField,
    EPacket,
    EPacketField,
    EPacketListField,
)

# Typing imports
from typing import (
    Optional,
)

# the alignment of auth_pad
# This is 4 in [C706] 13.2.6.1 but was updated to 16 in [MS-RPCE] 2.2.2.11
_COMMON_AUTH_PAD = 16
# the alignment of the NDR Type 1 serialization private header
# ([MS-RPCE] sect 2.2.6.2)
_TYPE1_S_PAD = 8

# DCE/RPC Packet
DCE_RPC_TYPE = {
    0: "request",
    1: "ping",
    2: "response",
    3: "fault",
    4: "working",
    5: "no_call",
    6: "reject",
    7: "acknowledge",
    8: "connectionless_cancel",
    9: "frag_ack",
    10: "cancel_ack",
    11: "bind",
    12: "bind_ack",
    13: "bind_nak",
    14: "alter_context",
    15: "alter_context_resp",
    16: "auth3",
    17: "shutdown",
    18: "co_cancel",
    19: "orphaned",
}
_DCE_RPC_4_FLAGS1 = [
    "reserved_01",
    "last_frag",
    "frag",
    "no_frag_ack",
    "maybe",
    "idempotent",
    "broadcast",
    "reserved_7",
]
_DCE_RPC_4_FLAGS2 = [
    "reserved_0",
    "cancel_pending",
    "reserved_2",
    "reserved_3",
    "reserved_4",
    "reserved_5",
    "reserved_6",
    "reserved_7",
]
DCE_RPC_TRANSFER_SYNTAXES = {
    UUID("00000000-0000-0000-0000-000000000000"): "NULL",
    UUID("6cb71c2c-9812-4540-0300-000000000000"): "Bind Time Feature Negotiation",
    UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"): "NDR 2.0",
    UUID("71710533-beba-4937-8319-b5dbef9ccc36"): "NDR64",
}
DCE_RPC_INTERFACES_NAMES = {}
DCE_RPC_INTERFACES_NAMES_rev = {}


class DCERPC_Transport(IntEnum):
    NCACN_IP_TCP = 1
    NCACN_NP = 2
    # TODO: add more.. if people use them?


def _dce_rpc_endianness(pkt):
    """
    Determine the right endianness sign for a given DCE/RPC packet
    """
    if pkt.endian == 0:  # big endian
        return ">"
    elif pkt.endian == 1:  # little endian
        return "<"
    else:
        return "!"


class _EField(EField):
    def __init__(self, fld):
        super(_EField, self).__init__(fld, endianness_from=_dce_rpc_endianness)


class DceRpc(Packet):
    """DCE/RPC packet"""

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 1:
            ver = ord(_pkt[0:1])
            if ver == 4:
                return DceRpc4
            elif ver == 5:
                return DceRpc5
        return DceRpc5


bind_bottom_up(TCP, DceRpc, sport=135)
bind_layers(TCP, DceRpc, dport=135)


class _DceRpcPayload(Packet):
    @property
    def endianness(self):
        if not self.underlayer:
            return "!"
        return _dce_rpc_endianness(self.underlayer)


# sect 12.5

_drep = [
    BitEnumField("endian", 1, 4, ["big", "little"]),
    BitEnumField("encoding", 0, 4, ["ASCII", "EBCDIC"]),
    ByteEnumField("float", 0, ["IEEE", "VAX", "CRAY", "IBM"]),
    ByteField("reserved1", 0),
]


class DceRpc4(DceRpc):
    """
    DCE/RPC v4 'connection-less' packet
    """

    name = "DCE/RPC v4"
    fields_desc = (
        [
            ByteEnumField(
                "rpc_vers", 4, {4: "4 (connection-less)", 5: "5 (connection-oriented)"}
            ),
            ByteEnumField("ptype", 0, DCE_RPC_TYPE),
            FlagsField("flags1", 0, 8, _DCE_RPC_4_FLAGS1),
            FlagsField("flags2", 0, 8, _DCE_RPC_4_FLAGS2),
        ]
        + _drep
        + [
            XByteField("serial_hi", 0),
            _EField(UUIDField("object", None)),
            _EField(UUIDField("if_id", None)),
            _EField(UUIDField("act_id", None)),
            _EField(IntField("server_boot", 0)),
            _EField(IntField("if_vers", 1)),
            _EField(IntField("seqnum", 0)),
            _EField(ShortField("opnum", 0)),
            _EField(XShortField("ihint", 0xFFFF)),
            _EField(XShortField("ahint", 0xFFFF)),
            _EField(LenField("len", None, fmt="H")),
            _EField(ShortField("fragnum", 0)),
            ByteEnumField("auth_proto", 0, ["none", "OSF DCE Private Key"]),
            XByteField("serial_lo", 0),
        ]
    )


# Exceptionally, we define those 3 here.


class NL_AUTH_MESSAGE(Packet):
    # [MS-NRPC] sect 2.2.1.3.1
    name = "NL_AUTH_MESSAGE"
    fields_desc = [
        LEIntEnumField(
            "MessageType",
            0x00000000,
            {
                0x00000000: "Request",
                0x00000001: "Response",
            },
        ),
        FlagsField(
            "Flags",
            0,
            -32,
            [
                "NETBIOS_DOMAIN_NAME",
                "NETBIOS_COMPUTER_NAME",
                "DNS_DOMAIN_NAME",
                "DNS_HOST_NAME",
                "NETBIOS_COMPUTER_NAME_UTF8",
            ],
        ),
        ConditionalField(
            StrNullField("NetbiosDomainName", ""),
            lambda pkt: pkt.Flags.NETBIOS_DOMAIN_NAME,
        ),
        ConditionalField(
            StrNullField("NetbiosComputerName", ""),
            lambda pkt: pkt.Flags.NETBIOS_COMPUTER_NAME,
        ),
        ConditionalField(
            DNSStrField("DnsDomainName", ""),
            lambda pkt: pkt.Flags.DNS_DOMAIN_NAME,
        ),
        ConditionalField(
            DNSStrField("DnsHostName", ""),
            lambda pkt: pkt.Flags.DNS_HOST_NAME,
        ),
        ConditionalField(
            # What the fuck? Why are they doing this
            # The spec is just wrong
            DNSStrField("NetbiosComputerNameUtf8", ""),
            lambda pkt: pkt.Flags.NETBIOS_COMPUTER_NAME_UTF8,
        ),
    ]


class NL_AUTH_SIGNATURE(Packet):
    # [MS-NRPC] sect 2.2.1.3.2/2.2.1.3.3
    name = "NL_AUTH_(SHA2_)SIGNATURE"
    fields_desc = [
        LEShortEnumField(
            "SignatureAlgorithm",
            0x0077,
            {
                0x0077: "HMAC-MD5",
                0x0013: "HMAC-SHA256",
            },
        ),
        LEShortEnumField(
            "SealAlgorithm",
            0xFFFF,
            {
                0xFFFF: "Unencrypted",
                0x007A: "RC4",
                0x001A: "AES-128",
            },
        ),
        XLEShortField("Pad", 0xFFFF),
        ShortField("Flags", 0),
        XStrFixedLenField("SequenceNumber", b"", length=8),
        XStrFixedLenField("Checksum", b"", length=8),
        ConditionalField(
            XStrFixedLenField("Confounder", b"", length=8),
            lambda pkt: pkt.SealAlgorithm != 0xFFFF,
        ),
        MultipleTypeField(
            [
                (
                    StrFixedLenField("Reserved2", b"", length=24),
                    lambda pkt: pkt.SignatureAlgorithm == 0x0013,
                ),
            ],
            StrField("Reserved2", b""),
        ),
    ]


# [MS-RPCE] sect 2.2.1.1.7
# https://learn.microsoft.com/en-us/windows/win32/rpc/authentication-service-constants
# rpcdce.h


class RPC_C_AUTHN(IntEnum):
    NONE = 0x00
    DCE_PRIVATE = 0x01
    DCE_PUBLIC = 0x02
    DEC_PUBLIC = 0x04
    GSS_NEGOTIATE = 0x09
    WINNT = 0x0A
    GSS_SCHANNEL = 0x0E
    GSS_KERBEROS = 0x10
    DPA = 0x11
    MSN = 0x12
    KERNEL = 0x14
    DIGEST = 0x15
    NEGO_EXTENDED = 0x1E
    PKU2U = 0x1F
    LIVE_SSP = 0x20
    LIVEXP_SSP = 0x23
    CLOUD_AP = 0x24
    NETLOGON = 0x44
    MSONLINE = 0x52
    MQ = 0x64
    DEFAULT = 0xFFFFFFFF


class RPC_C_AUTHN_LEVEL(IntEnum):
    DEFAULT = 0x0
    NONE = 0x1
    CONNECT = 0x2
    CALL = 0x3
    PKT = 0x4
    PKT_INTEGRITY = 0x5
    PKT_PRIVACY = 0x6


DCE_C_AUTHN_LEVEL = RPC_C_AUTHN_LEVEL  # C706 name


# C706 sect 13.2.6.1


class CommonAuthVerifier(Packet):
    name = "Common Authentication Verifier"
    fields_desc = [
        ByteEnumField(
            "auth_type",
            0,
            RPC_C_AUTHN,
        ),
        ByteEnumField("auth_level", 0, RPC_C_AUTHN_LEVEL),
        ByteField("auth_pad_length", None),
        ByteField("auth_reserved", 0),
        XLEIntField("auth_context_id", 0),
        MultipleTypeField(
            [
                # SPNEGO
                (
                    PacketLenField(
                        "auth_value",
                        GSSAPI_BLOB(),
                        GSSAPI_BLOB,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type == 0x09 and pkt.parent and
                    # Bind/Alter
                    pkt.parent.ptype in [11, 12, 13, 14, 15, 16],
                ),
                (
                    PacketLenField(
                        "auth_value",
                        GSSAPI_BLOB_SIGNATURE(),
                        GSSAPI_BLOB_SIGNATURE,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type == 0x09
                    and pkt.parent
                    and (
                        # Other
                        not pkt.parent
                        or pkt.parent.ptype not in [11, 12, 13, 14, 15, 16]
                    ),
                ),
                # Kerberos
                (
                    PacketLenField(
                        "auth_value",
                        Kerberos(),
                        Kerberos,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type == 0x10 and pkt.parent and
                    # Bind/Alter
                    pkt.parent.ptype in [11, 12, 13, 14, 15, 16],
                ),
                (
                    PacketLenField(
                        "auth_value",
                        KRB_InnerToken(),
                        KRB_InnerToken,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type == 0x10
                    and pkt.parent
                    and (
                        # Other
                        not pkt.parent
                        or pkt.parent.ptype not in [11, 12, 13, 14, 15, 16]
                    ),
                ),
                # NTLM
                (
                    PacketLenField(
                        "auth_value",
                        NTLM_Header(),
                        NTLM_Header,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type in [0x0A, 0xFF] and pkt.parent and
                    # Bind/Alter
                    pkt.parent.ptype in [11, 12, 13, 14, 15, 16],
                ),
                (
                    PacketLenField(
                        "auth_value",
                        NTLMSSP_MESSAGE_SIGNATURE(),
                        NTLMSSP_MESSAGE_SIGNATURE,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type in [0x0A, 0xFF]
                    and pkt.parent
                    and (
                        # Other
                        not pkt.parent
                        or pkt.parent.ptype not in [11, 12, 13, 14, 15, 16]
                    ),
                ),
                # NetLogon
                (
                    PacketLenField(
                        "auth_value",
                        NL_AUTH_MESSAGE(),
                        NL_AUTH_MESSAGE,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type == 0x44 and pkt.parent and
                    # Bind/Alter
                    pkt.parent.ptype in [11, 12, 13, 14, 15],
                ),
                (
                    PacketLenField(
                        "auth_value",
                        NL_AUTH_SIGNATURE(),
                        NL_AUTH_SIGNATURE,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type == 0x44
                    and (
                        # Other
                        not pkt.parent
                        or pkt.parent.ptype not in [11, 12, 13, 14, 15]
                    ),
                ),
            ],
            PacketLenField(
                "auth_value",
                None,
                conf.raw_layer,
                length_from=lambda pkt: pkt.parent and pkt.parent.auth_len or 0,
            ),
        ),
    ]

    def is_protected(self):
        if not self.auth_value:
            return False
        if self.parent and self.parent.ptype in [11, 12, 13, 14, 15, 16]:
            return False
        return True

    def is_ssp(self):
        if not self.auth_value:
            return False
        if self.parent and self.parent.ptype not in [11, 12, 13, 14, 15, 16]:
            return False
        return True

    def default_payload_class(self, pkt):
        return conf.padding_layer


# [MS-RPCE] sect 2.2.2.13 - Verification Trailer
_SECTRAILER_MAGIC = b"\x8a\xe3\x13\x71\x02\xf4\x36\x71"


class DceRpcSecVTCommand(Packet):
    name = "Verification trailer command"
    fields_desc = [
        BitField("SEC_VT_MUST_PROCESS_COMMAND", 0, 1, tot_size=-2),
        BitField("SEC_VT_COMMAND_END", 0, 1),
        BitEnumField(
            "Command",
            0,
            -14,
            {
                0x0001: "SEC_VT_COMMAND_BITMASK_1",
                0x0002: "SEC_VT_COMMAND_PCONTEXT",
                0x0003: "SEC_VT_COMMAND_HEADER2",
            },
            end_tot_size=-2,
        ),
        LEShortField("Length", None),
    ]

    def guess_payload_class(self, payload):
        if self.Command == 0x0001:
            return DceRpcSecVTBitmask
        elif self.Command == 0x0002:
            return DceRpcSecVTPcontext
        elif self.Command == 0x0003:
            return DceRpcSecVTHeader2
        return conf.raw_payload


# [MS-RPCE] sect 2.2.2.13.2


class DceRpcSecVTBitmask(Packet):
    name = "rpc_sec_vt_bitmask"
    fields_desc = [
        LEIntField("bits", 1),
    ]

    def default_payload_class(self, pkt):
        return conf.padding_layer


# [MS-RPCE] sect 2.2.2.13.4


class DceRpcSecVTPcontext(Packet):
    name = "rpc_sec_vt_pcontext"
    fields_desc = [
        UUIDEnumField(
            "InterfaceId",
            None,
            (
                DCE_RPC_INTERFACES_NAMES.get,
                lambda x: DCE_RPC_INTERFACES_NAMES_rev.get(x.lower()),
            ),
            uuid_fmt=UUIDField.FORMAT_LE,
        ),
        LEIntField("Version", 0),
        UUIDEnumField(
            "TransferSyntax",
            None,
            DCE_RPC_TRANSFER_SYNTAXES,
            uuid_fmt=UUIDField.FORMAT_LE,
        ),
        LEIntField("TransferVersion", 0),
    ]

    def default_payload_class(self, pkt):
        return conf.padding_layer


# [MS-RPCE] sect 2.2.2.13.3


class DceRpcSecVTHeader2(Packet):
    name = "rpc_sec_vt_header2"
    fields_desc = [
        ByteField("PTYPE", 0),
        ByteField("Reserved1", 0),
        LEShortField("Reserved2", 0),
        LEIntField("drep", 0),
        LEIntField("call_id", 0),
        LEShortField("p_cont_id", 0),
        LEShortField("opnum", 0),
    ]

    def default_payload_class(self, pkt):
        return conf.padding_layer


class DceRpcSecVT(Packet):
    name = "Verification trailer"
    fields_desc = [
        XStrFixedLenField("rpc_sec_verification_trailer", _SECTRAILER_MAGIC, length=8),
        PacketListField("commands", [], DceRpcSecVTCommand),
    ]


class _VerifTrailerField(PacketField):
    def getfield(
        self,
        pkt,
        s,
    ):
        if _SECTRAILER_MAGIC in s:
            # a bit ugly
            ind = s.index(_SECTRAILER_MAGIC)
            sectrailer_bytes, remain = bytes(s[:-ind]), bytes(s[-ind:])
            vt_trailer = self.m2i(pkt, sectrailer_bytes)
            if not isinstance(vt_trailer.payload, NoPayload):
                # bad parse
                return s, None
            return remain, vt_trailer
        return s, None


# sect 12.6.3


_DCE_RPC_5_FLAGS = {
    0x01: "PFC_FIRST_FRAG",
    0x02: "PFC_LAST_FRAG",
    0x04: "PFC_PENDING_CANCEL",
    0x08: "PFC_RESERVED_1",
    0x10: "PFC_CONC_MPX",
    0x20: "PFC_DID_NOT_EXECUTE",
    0x40: "PFC_MAYBE",
    0x80: "PFC_OBJECT_UUID",
}

# [MS-RPCE] sect 2.2.2.3

_DCE_RPC_5_FLAGS_2 = _DCE_RPC_5_FLAGS.copy()
_DCE_RPC_5_FLAGS_2[0x04] = "PFC_SUPPORT_HEADER_SIGN"


_DCE_RPC_ERROR_CODES = {
    # Appendix N
    0x1C010001: "nca_s_comm_failure",
    0x1C010002: "nca_s_op_rng_error",
    0x1C010003: "nca_s_unk_if",
    0x1C010006: "nca_s_wrong_boot_time",
    0x1C010009: "nca_s_you_crashed",
    0x1C01000B: "nca_s_proto_error",
    0x1C010013: "nca_s_out_args_too_big",
    0x1C010014: "nca_s_server_too_busy",
    0x1C010015: "nca_s_fault_string_too_long",
    0x1C010017: "nca_s_unsupported_type",
    0x1C000001: "nca_s_fault_int_div_by_zero",
    0x1C000002: "nca_s_fault_addr_error",
    0x1C000003: "nca_s_fault_fp_div_zero",
    0x1C000004: "nca_s_fault_fp_underflow",
    0x1C000005: "nca_s_fault_fp_overflow",
    0x1C000006: "nca_s_fault_invalid_tag",
    0x1C000007: "nca_s_fault_invalid_bound",
    0x1C000008: "nca_s_rpc_version_mismatch",
    0x1C000009: "nca_s_unspec_reject",
    0x1C00000A: "nca_s_bad_actid",
    0x1C00000B: "nca_s_who_are_you_failed",
    0x1C00000C: "nca_s_manager_not_entered",
    0x1C00000D: "nca_s_fault_cancel",
    0x1C00000E: "nca_s_fault_ill_inst",
    0x1C00000F: "nca_s_fault_fp_error",
    0x1C000010: "nca_s_fault_int_overflow",
    0x1C000012: "nca_s_fault_unspec",
    0x1C000013: "nca_s_fault_remote_comm_failure",
    0x1C000014: "nca_s_fault_pipe_empty",
    0x1C000015: "nca_s_fault_pipe_closed",
    0x1C000016: "nca_s_fault_pipe_order",
    0x1C000017: "nca_s_fault_pipe_discipline",
    0x1C000018: "nca_s_fault_pipe_comm_error",
    0x1C000019: "nca_s_fault_pipe_memory",
    0x1C00001A: "nca_s_fault_context_mismatch",
    0x1C00001B: "nca_s_fault_remote_no_memory",
    0x1C00001C: "nca_s_invalid_pres_context_id",
    0x1C00001D: "nca_s_unsupported_authn_level",
    0x1C00001F: "nca_s_invalid_checksum",
    0x1C000020: "nca_s_invalid_crc",
    0x1C000021: "nca_s_fault_user_defined",
    0x1C000022: "nca_s_fault_tx_open_failed",
    0x1C000023: "nca_s_fault_codeset_conv_error",
    0x1C000024: "nca_s_fault_object_not_found",
    0x1C000025: "nca_s_fault_no_client_stub",
    # [MS-ERREF]
    0x000006D3: "RPC_S_UNKNOWN_AUTHN_SERVICE",
    0x000006F7: "RPC_X_BAD_STUB_DATA",
    # [MS-RPCE]
    0x000006D8: "EPT_S_CANT_PERFORM_OP",
}

_DCE_RPC_REJECTION_REASONS = {
    0: "REASON_NOT_SPECIFIED",
    1: "TEMPORARY_CONGESTION",
    2: "LOCAL_LIMIT_EXCEEDED",
    3: "CALLED_PADDR_UNKNOWN",
    4: "PROTOCOL_VERSION_NOT_SUPPORTED",
    5: "DEFAULT_CONTEXT_NOT_SUPPORTED",
    6: "USER_DATA_NOT_READABLE",
    7: "NO_PSAP_AVAILABLE",
    8: "AUTHENTICATION_TYPE_NOT_RECOGNIZED",
    9: "INVALID_CHECKSUM",
}


class DceRpc5(DceRpc):
    """
    DCE/RPC v5 'connection-oriented' packet
    """

    name = "DCE/RPC v5"
    fields_desc = (
        [
            ByteEnumField(
                "rpc_vers", 5, {4: "4 (connection-less)", 5: "5 (connection-oriented)"}
            ),
            ByteField("rpc_vers_minor", 0),
            ByteEnumField("ptype", 0, DCE_RPC_TYPE),
            MultipleTypeField(
                # [MS-RPCE] sect 2.2.2.3
                [
                    (
                        FlagsField("pfc_flags", 0x3, 8, _DCE_RPC_5_FLAGS_2),
                        lambda pkt: pkt.ptype in [11, 12, 13, 14, 15, 16],
                    )
                ],
                FlagsField("pfc_flags", 0x3, 8, _DCE_RPC_5_FLAGS),
            ),
        ]
        + _drep
        + [
            ByteField("reserved2", 0),
            _EField(ShortField("frag_len", None)),
            _EField(
                FieldLenField(
                    "auth_len",
                    None,
                    fmt="H",
                    length_of="auth_verifier",
                    adjust=lambda pkt, x: 0 if not x else (x - 8),
                )
            ),
            _EField(IntField("call_id", None)),
            # Now let's proceed with trailer fields, i.e. at the end of the PACKET
            # (below all payloads, etc.). Have a look at Figure 3 in sect 2.2.2.13
            # of [MS-RPCE] but note the following:
            # - auth_verifier includes sec_trailer + the authentication token
            # - auth_padding is the authentication padding
            # - vt_trailer is the verification trailer
            ConditionalField(
                TrailerField(
                    PacketLenField(
                        "auth_verifier",
                        None,
                        CommonAuthVerifier,
                        length_from=lambda pkt: pkt.auth_len + 8,
                    )
                ),
                lambda pkt: pkt.auth_len != 0,
            ),
            ConditionalField(
                TrailerField(
                    StrLenField(
                        "auth_padding",
                        None,
                        length_from=lambda pkt: pkt.auth_verifier.auth_pad_length,
                    )
                ),
                lambda pkt: pkt.auth_len != 0,
            ),
            TrailerField(
                _VerifTrailerField("vt_trailer", None, DceRpcSecVT),
            ),
        ]
    )

    def do_dissect(self, s):
        # Overload do_dissect to only include the current layer in dissection.
        # This allows to support TrailerFields, even in the case where multiple DceRpc5
        # packets are concatenated
        frag_len = self.get_field("frag_len").getfield(self, s[8:10])[1]
        s, remain = s[:frag_len], s[frag_len:]
        return super(DceRpc5, self).do_dissect(s) + remain

    def extract_padding(self, s):
        # Now, take any data that doesn't fit in the current fragment and make it
        # padding. The caller is responsible for looking for eventual padding and
        # creating the next fragment, etc.
        pay_len = self.frag_len - len(self.original) + len(s)
        return s[:pay_len], s[pay_len:]

    def post_build(self, pkt, pay):
        if (
            self.auth_verifier
            and self.auth_padding is None
            and self.auth_verifier.auth_pad_length is None
        ):
            # Compute auth_len and add padding
            auth_len = self.get_field("auth_len").getfield(self, pkt[10:12])[1] + 8
            auth_verifier, pay = pay[-auth_len:], pay[:-auth_len]
            pdu_len = len(pay)
            if self.payload:
                pdu_len -= len(self.payload.self_build())
            padlen = (-pdu_len) % _COMMON_AUTH_PAD
            auth_verifier = (
                auth_verifier[:2] + struct.pack("B", padlen) + auth_verifier[3:]
            )
            pay = pay + (padlen * b"\x00") + auth_verifier
        if self.frag_len is None:
            # Compute frag_len
            length = len(pkt) + len(pay)
            pkt = (
                pkt[:8]
                + self.get_field("frag_len").addfield(self, b"", length)
                + pkt[10:]
            )
        return pkt + pay

    def answers(self, pkt):
        return isinstance(pkt, DceRpc5) and pkt[DceRpc5].call_id == self.call_id

    @classmethod
    def tcp_reassemble(cls, data, _, session):
        if data[0:1] != b"\x05":
            return
        endian = struct.unpack("!B", data[4:5])[0] >> 4
        if endian not in [0, 1]:
            return
        length = struct.unpack(("<" if endian else ">") + "H", data[8:10])[0]
        if len(data) >= length:
            if conf.dcerpc_session_enable:
                # If DCE/RPC sessions are enabled, use them !
                if "dcerpcsess" not in session:
                    session["dcerpcsess"] = dcerpcsess = DceRpcSession()
                else:
                    dcerpcsess = session["dcerpcsess"]
                return dcerpcsess.process(DceRpc5(data))
            return DceRpc5(data)


# sec 12.6.3.1


class DceRpc5AbstractSyntax(EPacket):
    name = "Presentation Syntax (p_syntax_id_t)"
    fields_desc = [
        _EField(
            UUIDEnumField(
                "if_uuid",
                None,
                (
                    # Those are dynamic
                    DCE_RPC_INTERFACES_NAMES.get,
                    lambda x: DCE_RPC_INTERFACES_NAMES_rev.get(x.lower()),
                ),
            )
        ),
        _EField(IntField("if_version", 3)),
    ]


class DceRpc5TransferSyntax(EPacket):
    name = "Presentation Transfer Syntax (p_syntax_id_t)"
    fields_desc = [
        _EField(
            UUIDEnumField(
                "if_uuid",
                None,
                DCE_RPC_TRANSFER_SYNTAXES,
            )
        ),
        _EField(IntField("if_version", 3)),
    ]


class DceRpc5Context(EPacket):
    name = "Presentation Context (p_cont_elem_t)"
    fields_desc = [
        _EField(ShortField("cont_id", 0)),
        FieldLenField("n_transfer_syn", None, count_of="transfer_syntaxes", fmt="B"),
        ByteField("reserved", 0),
        EPacketField("abstract_syntax", None, DceRpc5AbstractSyntax),
        EPacketListField(
            "transfer_syntaxes",
            None,
            DceRpc5TransferSyntax,
            count_from=lambda pkt: pkt.n_transfer_syn,
            endianness_from=_dce_rpc_endianness,
        ),
    ]


class DceRpc5Result(EPacket):
    name = "Context negotiation Result"
    fields_desc = [
        _EField(
            ShortEnumField(
                "result", 0, ["acceptance", "user_rejection", "provider_rejection"]
            )
        ),
        _EField(
            ShortEnumField(
                "reason",
                0,
                _DCE_RPC_REJECTION_REASONS,
            )
        ),
        EPacketField("transfer_syntax", None, DceRpc5TransferSyntax),
    ]


class DceRpc5PortAny(EPacket):
    name = "Port Any (port_any_t)"
    fields_desc = [
        _EField(FieldLenField("length", None, length_of="port_spec", fmt="H")),
        _EField(StrLenField("port_spec", b"", length_from=lambda pkt: pkt.length)),
    ]


# sec 12.6.4.3


class DceRpc5Bind(_DceRpcPayload):
    name = "DCE/RPC v5 - Bind"
    fields_desc = [
        _EField(ShortField("max_xmit_frag", 5840)),
        _EField(ShortField("max_recv_frag", 8192)),
        _EField(IntField("assoc_group_id", 0)),
        # p_cont_list_t
        _EField(
            FieldLenField("n_context_elem", None, count_of="context_elem", fmt="B")
        ),
        StrFixedLenField("reserved", 0, length=3),
        EPacketListField(
            "context_elem",
            [],
            DceRpc5Context,
            endianness_from=_dce_rpc_endianness,
            count_from=lambda pkt: pkt.n_context_elem,
        ),
    ]


bind_layers(DceRpc5, DceRpc5Bind, ptype=11)

# sec 12.6.4.4


class DceRpc5BindAck(_DceRpcPayload):
    name = "DCE/RPC v5 - Bind Ack"
    fields_desc = [
        _EField(ShortField("max_xmit_frag", 5840)),
        _EField(ShortField("max_recv_frag", 8192)),
        _EField(IntField("assoc_group_id", 0)),
        PadField(
            EPacketField("sec_addr", None, DceRpc5PortAny),
            align=4,
        ),
        # p_result_list_t
        _EField(FieldLenField("n_results", None, count_of="results", fmt="B")),
        StrFixedLenField("reserved", 0, length=3),
        EPacketListField(
            "results",
            [],
            DceRpc5Result,
            endianness_from=_dce_rpc_endianness,
            count_from=lambda pkt: pkt.n_results,
        ),
    ]


bind_layers(DceRpc5, DceRpc5BindAck, ptype=12)

# sec 12.6.4.5


class DceRpc5Version(EPacket):
    name = "version_t"
    fields_desc = [
        ByteField("major", 0),
        ByteField("minor", 0),
    ]


class DceRpc5BindNak(_DceRpcPayload):
    name = "DCE/RPC v5 - Bind Nak"
    fields_desc = [
        _EField(
            ShortEnumField("provider_reject_reason", 0, _DCE_RPC_REJECTION_REASONS)
        ),
        # p_rt_versions_supported_t
        _EField(FieldLenField("n_protocols", None, count_of="protocols", fmt="B")),
        EPacketListField(
            "protocols",
            [],
            DceRpc5Version,
            count_from=lambda pkt: pkt.n_protocols,
            endianness_from=_dce_rpc_endianness,
        ),
        # [MS-RPCE] sect 2.2.2.9
        ConditionalField(
            ReversePadField(
                _EField(
                    UUIDEnumField(
                        "signature",
                        None,
                        {
                            UUID(
                                "90740320-fad0-11d3-82d7-009027b130ab"
                            ): "Extended Error",
                        },
                    )
                ),
                align=8,
            ),
            lambda pkt: pkt.fields.get("signature", None)
            or (
                pkt.underlayer
                and pkt.underlayer.frag_len >= 24 + pkt.n_protocols * 2 + 16
            ),
        ),
    ]


bind_layers(DceRpc5, DceRpc5BindNak, ptype=13)


# sec 12.6.4.1


class DceRpc5AlterContext(_DceRpcPayload):
    name = "DCE/RPC v5 - AlterContext"
    fields_desc = DceRpc5Bind.fields_desc


bind_layers(DceRpc5, DceRpc5AlterContext, ptype=14)


# sec 12.6.4.2


class DceRpc5AlterContextResp(_DceRpcPayload):
    name = "DCE/RPC v5 - AlterContextResp"
    fields_desc = DceRpc5BindAck.fields_desc


bind_layers(DceRpc5, DceRpc5AlterContextResp, ptype=15)

# [MS-RPCE] sect 2.2.2.10 - rpc_auth_3


class DceRpc5Auth3(Packet):
    name = "DCE/RPC v5 - Auth3"
    fields_desc = [StrFixedLenField("pad", b"", length=4)]


bind_layers(DceRpc5, DceRpc5Auth3, ptype=16)

# sec 12.6.4.7


class DceRpc5Fault(_DceRpcPayload):
    name = "DCE/RPC v5 - Fault"
    fields_desc = [
        _EField(IntField("alloc_hint", 0)),
        _EField(ShortField("cont_id", 0)),
        ByteField("cancel_count", 0),
        FlagsField("reserved", 0, -8, {0x1: "RPC extended error"}),
        _EField(LEIntEnumField("status", 0, _DCE_RPC_ERROR_CODES)),
        IntField("reserved2", 0),
    ]


bind_layers(DceRpc5, DceRpc5Fault, ptype=3)


# sec 12.6.4.9


class DceRpc5Request(_DceRpcPayload):
    name = "DCE/RPC v5 - Request"
    fields_desc = [
        _EField(IntField("alloc_hint", 0)),
        _EField(ShortField("cont_id", 0)),
        _EField(ShortField("opnum", 0)),
        ConditionalField(
            PadField(
                _EField(UUIDField("object", None)),
                align=8,
            ),
            lambda pkt: pkt.underlayer and pkt.underlayer.pfc_flags.PFC_OBJECT_UUID,
        ),
    ]


bind_layers(DceRpc5, DceRpc5Request, ptype=0)

# sec 12.6.4.10


class DceRpc5Response(_DceRpcPayload):
    name = "DCE/RPC v5 - Response"
    fields_desc = [
        _EField(IntField("alloc_hint", 0)),
        _EField(ShortField("cont_id", 0)),
        ByteField("cancel_count", 0),
        ByteField("reserved", 0),
    ]


bind_layers(DceRpc5, DceRpc5Response, ptype=2)

# --- API

DceRpcOp = collections.namedtuple("DceRpcOp", ["request", "response"])
DCE_RPC_INTERFACES = {}


class DceRpcInterface:
    def __init__(self, name, uuid, version_tuple, if_version, opnums):
        self.name = name
        self.uuid = uuid
        self.major_version, self.minor_version = version_tuple
        self.if_version = if_version
        self.opnums = opnums

    def __repr__(self):
        return "<DCE/RPC Interface %s v%s.%s>" % (
            self.name,
            self.major_version,
            self.minor_version,
        )


def register_dcerpc_interface(name, uuid, version, opnums):
    """
    Register a DCE/RPC interface
    """
    version_tuple = tuple(map(int, version.split(".")))
    assert len(version_tuple) == 2, "Version should be in format 'X.X' !"
    if_version = (version_tuple[1] << 16) + version_tuple[0]
    if (uuid, if_version) in DCE_RPC_INTERFACES:
        # Interface is already registered.
        interface = DCE_RPC_INTERFACES[(uuid, if_version)]
        if interface.name == name:
            if interface.if_version == if_version and set(opnums) - set(
                interface.opnums
            ):
                # Interface is an extension of a previous interface
                interface.opnums.update(opnums)
                return
            elif interface.if_version != if_version:
                # Interface has a different version
                pass
            else:
                log_runtime.warning(
                    "This interface is already registered: %s. Skip" % interface
                )
                return
        else:
            raise ValueError(
                "An interface with the same UUID is already registered: %s" % interface
            )
    DCE_RPC_INTERFACES_NAMES[uuid] = name
    DCE_RPC_INTERFACES_NAMES_rev[name.lower()] = uuid
    DCE_RPC_INTERFACES[(uuid, if_version)] = DceRpcInterface(
        name,
        uuid,
        version_tuple,
        if_version,
        opnums,
    )
    # bind for build
    for opnum, operations in opnums.items():
        bind_top_down(DceRpc5Request, operations.request, opnum=opnum)


def find_dcerpc_interface(name):
    """
    Find an interface object through the name in the IDL
    """
    try:
        return next(x for x in DCE_RPC_INTERFACES.values() if x.name == name)
    except StopIteration:
        raise AttributeError("Unknown interface !")


COM_INTERFACES = {}


class ComInterface:
    def __init__(self, name, uuid, opnums):
        self.name = name
        self.uuid = uuid
        self.opnums = opnums

    def __repr__(self):
        return "<COM Interface %s>" % (self.name,)


def register_com_interface(name, uuid, opnums):
    """
    Register a COM interface
    """
    COM_INTERFACES[uuid] = ComInterface(
        name,
        uuid,
        opnums,
    )


# --- NDR fields - [C706] chap 14


def _set_ctx_on(f, obj):
    if isinstance(f, _NDRPacket):
        f.ndr64 = obj.ndr64
        f.ndrendian = obj.ndrendian
    if isinstance(f, list):
        for x in f:
            if isinstance(x, _NDRPacket):
                x.ndr64 = obj.ndr64
                x.ndrendian = obj.ndrendian


def _e(ndrendian):
    return {"big": ">", "little": "<"}[ndrendian]


class _NDRPacket(Packet):
    __slots__ = ["ndr64", "ndrendian", "deferred_pointers", "request_packet"]

    def __init__(self, *args, **kwargs):
        self.ndr64 = kwargs.pop("ndr64", False)
        self.ndrendian = kwargs.pop("ndrendian", "little")
        # request_packet is used in the session, so that a response packet
        # can resolve union arms if the case parameter is in the request.
        self.request_packet = kwargs.pop("request_packet", None)
        self.deferred_pointers = []
        super(_NDRPacket, self).__init__(*args, **kwargs)

    def do_dissect(self, s):
        _up = self.parent or self.underlayer
        if _up and isinstance(_up, _NDRPacket):
            self.ndr64 = _up.ndr64
            self.ndrendian = _up.ndrendian
        else:
            # See comment above NDRConstructedType
            return NDRConstructedType([]).read_deferred_pointers(
                self, super(_NDRPacket, self).do_dissect(s)
            )
        return super(_NDRPacket, self).do_dissect(s)

    def post_dissect(self, s):
        if self.deferred_pointers:
            # Can't trust the cache if there were deferred pointers
            self.raw_packet_cache = None
        return s

    def do_build(self):
        _up = self.parent or self.underlayer
        for f in self.fields.values():
            _set_ctx_on(f, self)
        if not _up or not isinstance(_up, _NDRPacket):
            # See comment above NDRConstructedType
            return NDRConstructedType([]).add_deferred_pointers(
                self, super(_NDRPacket, self).do_build()
            )
        return super(_NDRPacket, self).do_build()

    def default_payload_class(self, pkt):
        return conf.padding_layer

    def clone_with(self, *args, **kwargs):
        pkt = super(_NDRPacket, self).clone_with(*args, **kwargs)
        # We need to copy deferred_pointers to not break pointer deferral
        # on build.
        pkt.deferred_pointers = self.deferred_pointers
        pkt.ndr64 = self.ndr64
        pkt.ndrendian = self.ndrendian
        return pkt

    def copy(self):
        pkt = super(_NDRPacket, self).copy()
        pkt.deferred_pointers = self.deferred_pointers
        pkt.ndr64 = self.ndr64
        pkt.ndrendian = self.ndrendian
        return pkt

    def show2(self, dump=False, indent=3, lvl="", label_lvl=""):
        return self.__class__(
            bytes(self), ndr64=self.ndr64, ndrendian=self.ndrendian
        ).show(dump, indent, lvl, label_lvl)

    def getfield_and_val(self, attr):
        try:
            return Packet.getfield_and_val(self, attr)
        except ValueError:
            if self.request_packet:
                # Try to resolve the field from the request on failure
                try:
                    return self.request_packet.getfield_and_val(attr)
                except AttributeError:
                    pass
            raise

    def valueof(self, request):
        """
        Util to get the value of a NDRField, ignoring arrays, pointers, etc.
        """
        val = self
        for ndr_field in request.split("."):
            fld, fval = val.getfield_and_val(ndr_field)
            val = fld.valueof(val, fval)
        return val


class _NDRAlign:
    def padlen(self, flen, pkt):
        return -flen % self._align[pkt.ndr64]

    def original_length(self, pkt):
        # Find the length of the NDR frag to be able to pad properly
        while pkt:
            par = pkt.parent or pkt.underlayer
            if par and isinstance(par, _NDRPacket):
                pkt = par
            else:
                break
        return len(pkt.original)


class NDRAlign(_NDRAlign, ReversePadField):
    """
    ReversePadField modified to fit NDR.

    - If no align size is specified, use the one from the inner field
    - Size is calculated from the beginning of the NDR stream
    """

    def __init__(self, fld, align, padwith=None):
        super(NDRAlign, self).__init__(fld, align=align, padwith=padwith)


class _VirtualField(Field):
    # Hold a value but doesn't show up when building/dissecting
    def addfield(self, pkt, s, x):
        return s

    def getfield(self, pkt, s):
        return s, None


class _NDRPacketMetaclass(Packet_metaclass):
    def __new__(cls, name, bases, dct):
        newcls = super(_NDRPacketMetaclass, cls).__new__(cls, name, bases, dct)
        conformants = dct.get("DEPORTED_CONFORMANTS", [])
        if conformants:
            amount = len(conformants)
            if amount == 1:
                newcls.fields_desc.insert(
                    0,
                    _VirtualField("max_count", None),
                )
            else:
                newcls.fields_desc.insert(
                    0,
                    FieldListField(
                        "max_counts",
                        [],
                        _VirtualField("", 0),
                        count_from=lambda _: amount,
                    ),
                )
        return newcls  # type: ignore


class NDRPacket(_NDRPacket, metaclass=_NDRPacketMetaclass):
    """
    A NDR Packet. Handles pointer size & endianness
    """

    __slots__ = ["_align"]

    # NDR64 pad structures
    # [MS-RPCE] 2.2.5.3.4.1
    ALIGNMENT = (1, 1)
    # [C706] sect 14.3.7 - Conformants max_count can be added to the beginning
    DEPORTED_CONFORMANTS = []


# Primitive types


class _NDRValueOf:
    def valueof(self, pkt, x):
        return x


class _NDRLenField(_NDRValueOf, Field):
    """
    Field similar to FieldLenField that takes size_of and adjust as arguments,
    and take the value of a size on build.
    """

    __slots__ = ["size_of", "adjust"]

    def __init__(self, *args, **kwargs):
        self.size_of = kwargs.pop("size_of", None)
        self.adjust = kwargs.pop("adjust", lambda _, x: x)
        super(_NDRLenField, self).__init__(*args, **kwargs)

    def i2m(self, pkt, x):
        if x is None and pkt is not None and self.size_of is not None:
            fld, fval = pkt.getfield_and_val(self.size_of)
            f = fld.i2len(pkt, fval)
            x = self.adjust(pkt, f)
        elif x is None:
            x = 0
        return x


class NDRByteField(_NDRLenField, ByteField):
    pass


class NDRSignedByteField(_NDRLenField, SignedByteField):
    pass


class _NDRField(_NDRLenField):
    FMT = ""
    ALIGN = (0, 0)

    def getfield(self, pkt, s):
        return NDRAlign(
            Field("", 0, fmt=_e(pkt.ndrendian) + self.FMT), align=self.ALIGN
        ).getfield(pkt, s)

    def addfield(self, pkt, s, val):
        return NDRAlign(
            Field("", 0, fmt=_e(pkt.ndrendian) + self.FMT), align=self.ALIGN
        ).addfield(pkt, s, self.i2m(pkt, val))


class NDRShortField(_NDRField):
    FMT = "H"
    ALIGN = (2, 2)


class NDRSignedShortField(_NDRField):
    FMT = "h"
    ALIGN = (2, 2)


class NDRIntField(_NDRField):
    FMT = "I"
    ALIGN = (4, 4)


class NDRSignedIntField(_NDRField):
    FMT = "i"
    ALIGN = (4, 4)


class NDRLongField(_NDRField):
    FMT = "Q"
    ALIGN = (8, 8)


class NDRSignedLongField(_NDRField):
    FMT = "q"
    ALIGN = (8, 8)


class NDRIEEEFloatField(_NDRField):
    FMT = "f"
    ALIGN = (4, 4)


class NDRIEEEDoubleField(_NDRField):
    FMT = "d"
    ALIGN = (8, 8)


# Enum types


class _NDREnumField(_NDRValueOf, EnumField):
    # [MS-RPCE] sect 2.2.5.2 - Enums are 4 octets in NDR64
    FMTS = ["H", "I"]

    def getfield(self, pkt, s):
        fmt = _e(pkt.ndrendian) + self.FMTS[pkt.ndr64]
        return NDRAlign(Field("", 0, fmt=fmt), align=(2, 4)).getfield(pkt, s)

    def addfield(self, pkt, s, val):
        fmt = _e(pkt.ndrendian) + self.FMTS[pkt.ndr64]
        return NDRAlign(Field("", 0, fmt=fmt), align=(2, 4)).addfield(
            pkt, s, self.i2m(pkt, val)
        )


class NDRInt3264EnumField(NDRAlign):
    def __init__(self, *args, **kwargs):
        super(NDRInt3264EnumField, self).__init__(
            _NDREnumField(*args, **kwargs), align=(2, 4)
        )


class NDRIntEnumField(_NDRValueOf, NDRAlign):
    # v1_enum are always 4-octets, even in NDR32
    def __init__(self, *args, **kwargs):
        super(NDRIntEnumField, self).__init__(
            LEIntEnumField(*args, **kwargs), align=(4, 4)
        )


# Special types


class NDRInt3264Field(_NDRLenField):
    FMTS = ["I", "Q"]

    def getfield(self, pkt, s):
        fmt = _e(pkt.ndrendian) + self.FMTS[pkt.ndr64]
        return NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).getfield(pkt, s)

    def addfield(self, pkt, s, val):
        fmt = _e(pkt.ndrendian) + self.FMTS[pkt.ndr64]
        return NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).addfield(
            pkt, s, self.i2m(pkt, val)
        )


class NDRSignedInt3264Field(NDRInt3264Field):
    FMTS = ["i", "q"]


# Pointer types


class NDRPointer(_NDRPacket):
    fields_desc = [
        MultipleTypeField(
            [(XLELongField("referent_id", 1), lambda pkt: pkt and pkt.ndr64)],
            XLEIntField("referent_id", 1),
        ),
        PacketField("value", None, conf.raw_layer),
    ]


class NDRFullPointerField(_FieldContainer):
    """
    A NDR Full/Unique pointer field encapsulation.

    :param deferred: This pointer is deferred. This means that it's representation
                     will not appear after the pointer.
                     See [C706] 14.3.12.3 - Algorithm for Deferral of Referents
    """

    EMBEDDED = False

    def __init__(self, fld, deferred=False, fmt="I"):
        self.fld = fld
        self.default = None
        self.deferred = deferred

    def getfield(self, pkt, s):
        fmt = _e(pkt.ndrendian) + ["I", "Q"][pkt.ndr64]
        remain, referent_id = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).getfield(
            pkt, s
        )
        if not self.EMBEDDED and referent_id == 0:
            return remain, None
        if self.deferred:
            # deferred
            ptr = NDRPointer(
                ndr64=pkt.ndr64, ndrendian=pkt.ndrendian, referent_id=referent_id
            )
            pkt.deferred_pointers.append((ptr, partial(self.fld.getfield, pkt)))
            return remain, ptr
        remain, val = self.fld.getfield(pkt, remain)
        return remain, NDRPointer(
            ndr64=pkt.ndr64, ndrendian=pkt.ndrendian, referent_id=referent_id, value=val
        )

    def addfield(self, pkt, s, val):
        if val is not None and not isinstance(val, NDRPointer):
            raise ValueError(
                "Expected NDRPointer in %s. You are using it wrong!" % self.name
            )
        fmt = _e(pkt.ndrendian) + ["I", "Q"][pkt.ndr64]
        fld = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8))
        if not self.EMBEDDED and val is None:
            return fld.addfield(pkt, s, 0)
        else:
            _set_ctx_on(val.value, pkt)
            s = fld.addfield(pkt, s, val.referent_id)
        if self.deferred:
            # deferred
            pkt.deferred_pointers.append(
                ((lambda s: self.fld.addfield(pkt, s, val.value)), val)
            )
            return s
        return self.fld.addfield(pkt, s, val.value)

    def any2i(self, pkt, x):
        # User-friendly helper
        if x is not None and not isinstance(x, NDRPointer):
            return NDRPointer(
                referent_id=0x20000,
                value=self.fld.any2i(pkt, x),
            )
        return x

    # Can't use i2repr = Field.i2repr and so on on PY2 :/
    def i2repr(self, pkt, val):
        return repr(val)

    def i2h(self, pkt, x):
        return x

    def h2i(self, pkt, x):
        return x

    def i2len(self, pkt, x):
        if x is None:
            return 0
        return self.fld.i2len(pkt, x.value)

    def valueof(self, pkt, x):
        if x is None:
            return x
        return self.fld.valueof(pkt, x.value)


class NDRRefEmbPointerField(NDRFullPointerField):
    """
    A NDR Embedded Reference pointer
    """

    EMBEDDED = True


# Constructed types


# Note: this is utterly complex and will drive you crazy

# If you have a NDRPacket that contains a deferred pointer on the top level
# (only happens in non DCE/RPC structures, such as in MS-PAC, where you have an NDR
# structure encapsulated in a non-NDR structure), there will be left-over deferred
# pointers when exiting dissection/build (deferred pointers are only computed when
# reaching a field that extends NDRConstructedType, which is normal: if you follow
# the DCE/RPC spec, pointers are never deferred in root structures)
# Therefore there is a special case forcing the build/dissection of any leftover
# pointers in NDRPacket, if Scapy detects that they won't be handled by any parent.

# Implementation notes: I chose to set 'handles_deferred' inside the FIELD, rather
# than inside the PACKET. This is faster to compute because whether a constructed type
# should handle deferral or not is computed only once when loading, therefore Scapy
# knows in advance whether to handle deferred pointers or not. But it is technically
# incorrect: with this approach, a structure (packet) cannot be used in 2 code paths
# that have different pointer managements. I mean by that that if there was a
# structure that was directly embedded in a RPC request without a pointer but also
# embedded with a pointer in another RPC request, it would break.
# Fortunately this isn't the case: structures are never reused for 2 purposes.
# (or at least I never seen that... <i hope this works>)


class NDRConstructedType(object):
    def __init__(self, fields):
        self.handles_deferred = False
        self.ndr_fields = fields
        self.rec_check_deferral()

    def rec_check_deferral(self):
        # We iterate through the fields within this constructed type.
        # If we have a pointer, mark this field as handling deferrance
        # and make all sub-constructed types not.
        for f in self.ndr_fields:
            if isinstance(f, NDRFullPointerField) and f.deferred:
                self.handles_deferred = True
            if isinstance(f, NDRConstructedType):
                f.rec_check_deferral()
                if f.handles_deferred:
                    self.handles_deferred = True
                    f.handles_deferred = False

    def getfield(self, pkt, s):
        s, fval = super(NDRConstructedType, self).getfield(pkt, s)
        if isinstance(fval, _NDRPacket):
            # If a sub-packet we just dissected has deferred pointers,
            # pass it to parent packet to propagate.
            pkt.deferred_pointers.extend(fval.deferred_pointers)
            del fval.deferred_pointers[:]
        if self.handles_deferred:
            # This field handles deferral !
            s = self.read_deferred_pointers(pkt, s)
        return s, fval

    def read_deferred_pointers(self, pkt, s):
        # Now read content of the pointers that were deferred
        q = collections.deque()
        q.extend(pkt.deferred_pointers)
        del pkt.deferred_pointers[:]
        while q:
            # Recursively resolve pointers that were deferred
            ptr, getfld = q.popleft()
            s, val = getfld(s)
            ptr.value = val
            if isinstance(val, _NDRPacket):
                # Pointer resolves to a packet.. that may have deferred pointers?
                q.extend(val.deferred_pointers)
                del val.deferred_pointers[:]
        return s

    def addfield(self, pkt, s, val):
        s = super(NDRConstructedType, self).addfield(pkt, s, val)
        if isinstance(val, _NDRPacket):
            # If a sub-packet we just dissected has deferred pointers,
            # pass it to parent packet to propagate.
            pkt.deferred_pointers.extend(val.deferred_pointers)
            del val.deferred_pointers[:]
        if self.handles_deferred:
            # This field handles deferral !
            s = self.add_deferred_pointers(pkt, s)
        return s

    def add_deferred_pointers(self, pkt, s):
        # Now add content of pointers that were deferred
        q = collections.deque()
        q.extend(pkt.deferred_pointers)
        del pkt.deferred_pointers[:]
        while q:
            addfld, fval = q.popleft()
            s = addfld(s)
            if isinstance(fval, NDRPointer) and isinstance(fval.value, _NDRPacket):
                q.extend(fval.value.deferred_pointers)
                del fval.value.deferred_pointers[:]
        return s


class _NDRPacketField(_NDRValueOf, PacketField):
    def m2i(self, pkt, m):
        return self.cls(m, ndr64=pkt.ndr64, ndrendian=pkt.ndrendian, _parent=pkt)


# class _NDRPacketPadField(PadField):
#     def padlen(self, flen, pkt):
#         if pkt.ndr64:
#             return -flen % self._align[1]
#         else:
#             return 0


class NDRPacketField(NDRConstructedType, NDRAlign):
    def __init__(self, name, default, pkt_cls, **kwargs):
        self.DEPORTED_CONFORMANTS = pkt_cls.DEPORTED_CONFORMANTS
        self.fld = _NDRPacketField(name, default, pkt_cls=pkt_cls, **kwargs)
        NDRAlign.__init__(
            self,
            # There is supposed to be padding after a struct in NDR64?
            # _NDRPacketPadField(fld, align=pkt_cls.ALIGNMENT),
            self.fld,
            align=pkt_cls.ALIGNMENT,
        )
        NDRConstructedType.__init__(self, pkt_cls.fields_desc)

    def getfield(self, pkt, x):
        # Handle deformed conformants max_count here
        if self.DEPORTED_CONFORMANTS:
            # C706 14.3.2: "In other words, the size information precedes the
            # structure and is aligned independently of the structure alignment."
            fld = NDRInt3264Field("", 0)
            max_counts = []
            for _ in self.DEPORTED_CONFORMANTS:
                x, max_count = fld.getfield(pkt, x)
                max_counts.append(max_count)
            res, val = super(NDRPacketField, self).getfield(pkt, x)
            if len(max_counts) == 1:
                val.max_count = max_counts[0]
            else:
                val.max_counts = max_counts
            return res, val
        return super(NDRPacketField, self).getfield(pkt, x)

    def addfield(self, pkt, s, x):
        # Handle deformed conformants max_count here
        if self.DEPORTED_CONFORMANTS:
            mcfld = NDRInt3264Field("", 0)
            if len(self.DEPORTED_CONFORMANTS) == 1:
                max_counts = [x.max_count]
            else:
                max_counts = x.max_counts
            for fldname, max_count in zip(self.DEPORTED_CONFORMANTS, max_counts):
                if max_count is None:
                    fld, val = x.getfield_and_val(fldname)
                    max_count = fld.i2len(x, val)
                s = mcfld.addfield(pkt, s, max_count)
            return super(NDRPacketField, self).addfield(pkt, s, x)
        return super(NDRPacketField, self).addfield(pkt, s, x)


# Array types


class _NDRPacketListField(NDRConstructedType, PacketListField):
    """
    A PacketListField for NDR that can optionally pack the packets into NDRPointers
    """

    islist = 1
    holds_packets = 1

    __slots__ = ["ptr_pack", "fld"]

    def __init__(self, name, default, pkt_cls, **kwargs):
        self.ptr_pack = kwargs.pop("ptr_pack", False)
        if self.ptr_pack:
            self.fld = NDRFullPointerField(
                NDRPacketField("", None, pkt_cls), deferred=True
            )
        else:
            self.fld = NDRPacketField("", None, pkt_cls)
        PacketListField.__init__(self, name, default, pkt_cls=pkt_cls, **kwargs)
        NDRConstructedType.__init__(self, [self.fld])

    def m2i(self, pkt, s):
        remain, val = self.fld.getfield(pkt, s)
        # A mistake here would be to use / instead of add_payload. It adds a copy
        # which breaks pointer defferal. Same applies elsewhere
        val.add_payload(conf.padding_layer(remain))
        return val

    def any2i(self, pkt, x):
        # User-friendly helper
        if isinstance(x, list):
            x = [self.fld.any2i(pkt, y) for y in x]
        return super(_NDRPacketListField, self).any2i(pkt, x)

    def i2m(self, pkt, val):
        return self.fld.addfield(pkt, b"", val)

    def i2len(self, pkt, x):
        return len(x)

    def valueof(self, pkt, x):
        return [self.fld.valueof(pkt, y) for y in x]


class NDRFieldListField(NDRConstructedType, FieldListField):
    """
    A FieldListField for NDR
    """

    islist = 1

    def __init__(self, *args, **kwargs):
        kwargs.pop("ptr_pack", None)  # TODO: unimplemented
        if "length_is" in kwargs:
            kwargs["count_from"] = kwargs.pop("length_is")
        elif "size_is" in kwargs:
            kwargs["count_from"] = kwargs.pop("size_is")
        FieldListField.__init__(self, *args, **kwargs)
        NDRConstructedType.__init__(self, [self.field])

    def i2len(self, pkt, x):
        return len(x)

    def valueof(self, pkt, x):
        return [self.field.valueof(pkt, y) for y in x]


class NDRVaryingArray(_NDRPacket):
    fields_desc = [
        MultipleTypeField(
            [(LELongField("offset", 0), lambda pkt: pkt and pkt.ndr64)],
            LEIntField("offset", 0),
        ),
        MultipleTypeField(
            [
                (
                    LELongField("actual_count", None),
                    lambda pkt: pkt and pkt.ndr64,
                )
            ],
            LEIntField("actual_count", None),
        ),
        PacketField("value", None, conf.raw_layer),
    ]


class _NDRVarField(object):
    """
    NDR Varying Array / String field
    """

    LENGTH_FROM = False
    COUNT_FROM = False

    def __init__(self, *args, **kwargs):
        # size is either from the length_is, if specified, or the "actual_count"
        self.from_actual = "length_is" not in kwargs
        length_is = kwargs.pop("length_is", lambda pkt: pkt.actual_count)
        if self.LENGTH_FROM:
            kwargs["length_from"] = length_is
        elif self.COUNT_FROM:
            kwargs["count_from"] = length_is
        super(_NDRVarField, self).__init__(*args, **kwargs)

    def getfield(self, pkt, s):
        fmt = _e(pkt.ndrendian) + ["I", "Q"][pkt.ndr64]
        remain, offset = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).getfield(pkt, s)
        remain, actual_count = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).getfield(
            pkt, remain
        )
        final = NDRVaryingArray(
            ndr64=pkt.ndr64,
            ndrendian=pkt.ndrendian,
            offset=offset,
            actual_count=actual_count,
        )
        if self.from_actual:
            remain, val = super(_NDRVarField, self).getfield(final, remain)
        else:
            remain, val = super(_NDRVarField, self).getfield(pkt, remain)
        final.value = super(_NDRVarField, self).i2h(pkt, val)
        return remain, final

    def addfield(self, pkt, s, val):
        if not isinstance(val, NDRVaryingArray):
            raise ValueError(
                "Expected NDRVaryingArray in %s. You are using it wrong!" % self.name
            )
        fmt = _e(pkt.ndrendian) + ["I", "Q"][pkt.ndr64]
        _set_ctx_on(val.value, pkt)
        s = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).addfield(pkt, s, val.offset)
        s = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).addfield(
            pkt,
            s,
            val.actual_count is None
            and super(_NDRVarField, self).i2len(pkt, val.value)
            or val.actual_count,
        )
        return super(_NDRVarField, self).addfield(
            pkt, s, super(_NDRVarField, self).h2i(pkt, val.value)
        )

    def i2len(self, pkt, x):
        return super(_NDRVarField, self).i2len(pkt, x.value)

    def any2i(self, pkt, x):
        # User-friendly helper
        if not isinstance(x, NDRVaryingArray):
            return NDRVaryingArray(
                value=super(_NDRVarField, self).any2i(pkt, x),
            )
        return x

    # Can't use i2repr = Field.i2repr and so on on PY2 :/
    def i2repr(self, pkt, val):
        return repr(val)

    def i2h(self, pkt, x):
        return x

    def h2i(self, pkt, x):
        return x

    def valueof(self, pkt, x):
        return super(_NDRVarField, self).valueof(pkt, x.value)


class NDRConformantArray(_NDRPacket):
    fields_desc = [
        MultipleTypeField(
            [(LELongField("max_count", None), lambda pkt: pkt and pkt.ndr64)],
            LEIntField("max_count", None),
        ),
        MultipleTypeField(
            [
                (
                    PacketListField(
                        "value",
                        [],
                        conf.raw_layer,
                        count_from=lambda pkt: pkt.max_count,
                    ),
                    (
                        lambda pkt: pkt.fields.get("value", None)
                        and isinstance(pkt.fields["value"][0], Packet),
                        lambda _, val: val and isinstance(val[0], Packet),
                    ),
                )
            ],
            FieldListField(
                "value", [], LEIntField("", 0), count_from=lambda pkt: pkt.max_count
            ),
        ),
    ]


class NDRConformantString(_NDRPacket):
    fields_desc = [
        MultipleTypeField(
            [(LELongField("max_count", None), lambda pkt: pkt and pkt.ndr64)],
            LEIntField("max_count", None),
        ),
        StrField("value", ""),
    ]


class _NDRConfField(object):
    """
    NDR Conformant Array / String field
    """

    CONFORMANT_STRING = False
    LENGTH_FROM = False
    COUNT_FROM = False

    def __init__(self, *args, **kwargs):
        self.conformant_in_struct = kwargs.pop("conformant_in_struct", False)
        # size_is/max_is end up here, and is what defines a conformant field.
        if "size_is" in kwargs:
            size_is = kwargs.pop("size_is")
            if self.LENGTH_FROM:
                kwargs["length_from"] = size_is
            elif self.COUNT_FROM:
                kwargs["count_from"] = size_is
        super(_NDRConfField, self).__init__(*args, **kwargs)

    def getfield(self, pkt, s):
        # [C706] - 14.3.7 Structures Containing Arrays
        fmt = _e(pkt.ndrendian) + ["I", "Q"][pkt.ndr64]
        if self.conformant_in_struct:
            return super(_NDRConfField, self).getfield(pkt, s)
        remain, max_count = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).getfield(
            pkt, s
        )
        remain, val = super(_NDRConfField, self).getfield(pkt, remain)
        return remain, (
            NDRConformantString if self.CONFORMANT_STRING else NDRConformantArray
        )(ndr64=pkt.ndr64, ndrendian=pkt.ndrendian, max_count=max_count, value=val)

    def addfield(self, pkt, s, val):
        if self.conformant_in_struct:
            return super(_NDRConfField, self).addfield(pkt, s, val)
        if self.CONFORMANT_STRING and not isinstance(val, NDRConformantString):
            raise ValueError(
                "Expected NDRConformantString in %s. You are using it wrong!"
                % self.name
            )
        elif not self.CONFORMANT_STRING and not isinstance(val, NDRConformantArray):
            raise ValueError(
                "Expected NDRConformantArray in %s. You are using it wrong!" % self.name
            )
        fmt = _e(pkt.ndrendian) + ["I", "Q"][pkt.ndr64]
        _set_ctx_on(val.value, pkt)
        if val.value and isinstance(val.value[0], NDRVaryingArray):
            value = val.value[0]
        else:
            value = val.value
        s = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).addfield(
            pkt,
            s,
            val.max_count is None
            and super(_NDRConfField, self).i2len(pkt, value)
            or val.max_count,
        )
        return super(_NDRConfField, self).addfield(pkt, s, value)

    def _subval(self, x):
        if self.conformant_in_struct:
            value = x
        elif (
            not self.CONFORMANT_STRING
            and x.value
            and isinstance(x.value[0], NDRVaryingArray)
        ):
            value = x.value[0]
        else:
            value = x.value
        return value

    def i2len(self, pkt, x):
        return super(_NDRConfField, self).i2len(pkt, self._subval(x))

    def any2i(self, pkt, x):
        # User-friendly helper
        if self.conformant_in_struct:
            return super(_NDRConfField, self).any2i(pkt, x)
        if self.CONFORMANT_STRING and not isinstance(x, NDRConformantString):
            return NDRConformantString(
                value=super(_NDRConfField, self).any2i(pkt, x),
            )
        elif not isinstance(x, NDRConformantArray):
            return NDRConformantArray(
                value=super(_NDRConfField, self).any2i(pkt, x),
            )
        return x

    # Can't use i2repr = Field.i2repr and so on on PY2 :/
    def i2repr(self, pkt, val):
        return repr(val)

    def i2h(self, pkt, x):
        return x

    def h2i(self, pkt, x):
        return x

    def valueof(self, pkt, x):
        return super(_NDRConfField, self).valueof(pkt, self._subval(x))


class NDRVarPacketListField(_NDRVarField, _NDRPacketListField):
    """
    NDR Varying PacketListField. Unused
    """

    COUNT_FROM = True


class NDRConfPacketListField(_NDRConfField, _NDRPacketListField):
    """
    NDR Conformant PacketListField
    """

    COUNT_FROM = True


class NDRConfVarPacketListField(_NDRConfField, _NDRVarField, _NDRPacketListField):
    """
    NDR Conformant Varying PacketListField
    """

    COUNT_FROM = True


class NDRConfFieldListField(_NDRConfField, NDRFieldListField):
    """
    NDR Conformant FieldListField
    """

    COUNT_FROM = True


class NDRConfVarFieldListField(_NDRConfField, _NDRVarField, NDRFieldListField):
    """
    NDR Conformant Varying FieldListField
    """

    COUNT_FROM = True


# NDR String fields


class _NDRUtf16(Field):
    def h2i(self, pkt, x):
        encoding = {"big": "utf-16be", "little": "utf-16le"}[pkt.ndrendian]
        return plain_str(x).encode(encoding)

    def i2h(self, pkt, x):
        encoding = {"big": "utf-16be", "little": "utf-16le"}[pkt.ndrendian]
        return bytes_encode(x).decode(encoding, errors="replace")


class NDRConfStrLenField(_NDRConfField, _NDRValueOf, StrLenField):
    """
    NDR Conformant StrLenField.

    This is not a "string" per NDR, but an a conformant byte array
    (e.g. tower_octet_string)
    """

    CONFORMANT_STRING = True
    LENGTH_FROM = True


class NDRConfStrLenFieldUtf16(_NDRConfField, _NDRValueOf, StrLenFieldUtf16, _NDRUtf16):
    """
    NDR Conformant StrLenField.

    See NDRConfLenStrField for comment.
    """

    CONFORMANT_STRING = True
    ON_WIRE_SIZE_UTF16 = False
    LENGTH_FROM = True


class NDRVarStrLenField(_NDRVarField, StrLenField):
    """
    NDR Varying StrLenField
    """

    LENGTH_FROM = True


class NDRVarStrLenFieldUtf16(_NDRVarField, _NDRValueOf, StrLenFieldUtf16, _NDRUtf16):
    """
    NDR Varying StrLenField
    """

    ON_WIRE_SIZE_UTF16 = False
    LENGTH_FROM = True


class NDRConfVarStrLenField(_NDRConfField, _NDRVarField, _NDRValueOf, StrLenField):
    """
    NDR Conformant Varying StrLenField
    """

    LENGTH_FROM = True


class NDRConfVarStrLenFieldUtf16(
    _NDRConfField, _NDRVarField, _NDRValueOf, StrLenFieldUtf16, _NDRUtf16
):
    """
    NDR Conformant Varying StrLenField
    """

    ON_WIRE_SIZE_UTF16 = False
    LENGTH_FROM = True


class NDRConfVarStrNullField(_NDRConfField, _NDRVarField, _NDRValueOf, StrNullField):
    """
    NDR Conformant Varying StrNullField
    """

    NULLFIELD = True


class NDRConfVarStrNullFieldUtf16(
    _NDRConfField, _NDRVarField, _NDRValueOf, StrNullFieldUtf16, _NDRUtf16
):
    """
    NDR Conformant Varying StrNullFieldUtf16
    """

    ON_WIRE_SIZE_UTF16 = False
    NULLFIELD = True


# Union type


class NDRUnion(_NDRPacket):
    fields_desc = [
        IntField("tag", 0),
        PacketField("value", None, conf.raw_layer),
    ]


class _NDRUnionField(MultipleTypeField):
    __slots__ = ["switch_fmt", "align"]

    def __init__(self, flds, dflt, align, switch_fmt):
        self.switch_fmt = switch_fmt
        self.align = align
        super(_NDRUnionField, self).__init__(flds, dflt)

    def getfield(self, pkt, s):
        fmt = _e(pkt.ndrendian) + self.switch_fmt[pkt.ndr64]
        remain, tag = NDRAlign(Field("", 0, fmt=fmt), align=self.align).getfield(pkt, s)
        fld, _ = super(_NDRUnionField, self)._find_fld_pkt_val(pkt, NDRUnion(tag=tag))
        remain, val = fld.getfield(pkt, remain)
        return remain, NDRUnion(
            tag=tag, value=val, ndr64=pkt.ndr64, ndrendian=pkt.ndrendian, _parent=pkt
        )

    def addfield(self, pkt, s, val):
        fmt = _e(pkt.ndrendian) + self.switch_fmt[pkt.ndr64]
        if not isinstance(val, NDRUnion):
            raise ValueError(
                "Expected NDRUnion in %s. You are using it wrong!" % self.name
            )
        _set_ctx_on(val.value, pkt)
        # First, align the whole tag+union against the align param
        s = NDRAlign(Field("", 0, fmt=fmt), align=self.align).addfield(pkt, s, val.tag)
        # Then, compute the subfield with its own alignment
        return super(_NDRUnionField, self).addfield(pkt, s, val)

    def _find_fld_pkt_val(self, pkt, val):
        fld, val = super(_NDRUnionField, self)._find_fld_pkt_val(pkt, val)
        return fld, val.value

    # Can't use i2repr = Field.i2repr and so on on PY2 :/
    def i2repr(self, pkt, val):
        return repr(val)

    def i2h(self, pkt, x):
        return x

    def h2i(self, pkt, x):
        return x

    def valueof(self, pkt, x):
        fld, val = self._find_fld_pkt_val(pkt, x)
        return fld.valueof(pkt, x.value)


class NDRUnionField(NDRConstructedType, _NDRUnionField):
    def __init__(self, flds, dflt, align, switch_fmt):
        _NDRUnionField.__init__(self, flds, dflt, align=align, switch_fmt=switch_fmt)
        NDRConstructedType.__init__(self, [x[0] for x in flds] + [dflt])

    def any2i(self, pkt, x):
        # User-friendly helper
        if x:
            if not isinstance(x, NDRUnion):
                raise ValueError("Invalid value for %s; should be NDRUnion" % self.name)
            else:
                x.value = _NDRUnionField.any2i(self, pkt, x)
        return x


# Misc


class NDRRecursiveField(Field):
    """
    A special Field that is used for pointer recursion
    """

    def __init__(self, name, fmt="I"):
        super(NDRRecursiveField, self).__init__(name, None, fmt=fmt)

    def getfield(self, pkt, s):
        return NDRFullPointerField(
            NDRPacketField("", None, pkt.__class__), deferred=True
        ).getfield(pkt, s)

    def addfield(self, pkt, s, val):
        return NDRFullPointerField(
            NDRPacketField("", None, pkt.__class__), deferred=True
        ).addfield(pkt, s, val)


# The very few NDR-specific structures


class NDRContextHandle(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        LEIntField("attributes", 0),
        StrFixedLenField("uuid", b"", length=16),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


# --- Type Serialization Version 1 - [MSRPCE] sect 2.2.6


def _get_ndrtype1_endian(pkt):
    if pkt.underlayer is None:
        return "<"
    return {0x00: ">", 0x10: "<"}.get(pkt.underlayer.Endianness, "<")


class NDRSerialization1Header(Packet):
    fields_desc = [
        ByteField("Version", 1),
        ByteEnumField("Endianness", 0x10, {0x00: "big", 0x10: "little"}),
        LEShortField("CommonHeaderLength", 8),
        XLEIntField("Filler", 0xCCCCCCCC),
    ]


class NDRSerialization1PrivateHeader(Packet):
    fields_desc = [
        EField(
            LEIntField("ObjectBufferLength", 0), endianness_from=_get_ndrtype1_endian
        ),
        XLEIntField("Filler", 0),
    ]


def ndr_deserialize1(b, cls, ndr64=False):
    """
    Deserialize Type Serialization Version 1 according to [MS-RPCE] sect 2.2.6
    """
    if issubclass(cls, NDRPacket):
        # We use an intermediary class for two reasons:
        # - it properly sets deferred pointers
        # - it uses NDRPacketField which handles deported conformant fields
        class _cls(NDRPacket):
            fields_desc = [
                NDRFullPointerField(NDRPacketField("pkt", None, cls)),
            ]

        hdr = NDRSerialization1Header(b[:8]) / NDRSerialization1PrivateHeader(b[8:16])
        endian = {0x00: "big", 0x10: "little"}[hdr.Endianness]
        padlen = (-hdr.ObjectBufferLength) % _TYPE1_S_PAD
        # padlen should be 0 (pad included in length), but some implementations
        # implement apparently misread the spec
        return (
            hdr
            / _cls(
                b[16 : 20 + hdr.ObjectBufferLength],
                ndr64=ndr64,
                ndrendian=endian,
            ).pkt
            / conf.padding_layer(b[20 + padlen + hdr.ObjectBufferLength :])
        )
    return NDRSerialization1Header(b[:8]) / cls(b[8:])


def ndr_serialize1(pkt):
    """
    Serialize Type Serialization Version 1
    """
    pkt = pkt.copy()
    endian = getattr(pkt, "ndrendian", "little")
    if not isinstance(pkt, NDRSerialization1Header):
        if not isinstance(pkt, NDRPacket):
            return bytes(NDRSerialization1Header(Endianness=endian) / pkt)
        if isinstance(pkt, NDRPointer):
            cls = pkt.value.__class__
        else:
            cls = pkt.__class__
        val = pkt
        pkt_len = len(pkt)
        # ObjectBufferLength:
        # > It MUST include the padding length and exclude the header itself
        pkt = NDRSerialization1Header(
            Endianness=endian
        ) / NDRSerialization1PrivateHeader(
            ObjectBufferLength=pkt_len + (-pkt_len) % _TYPE1_S_PAD
        )
    else:
        cls = pkt.value.__class__
        val = pkt.payload.payload
        pkt.payload.remove_payload()

    # See above about why we need an intermediary class
    class _cls(NDRPacket):
        fields_desc = [
            NDRFullPointerField(NDRPacketField("pkt", None, cls)),
        ]

    ret = bytes(pkt / _cls(pkt=val))
    return ret + (-len(ret) % _TYPE1_S_PAD) * b"\x00"


class _NDRSerializeType1:
    def __init__(self, *args, **kwargs):
        super(_NDRSerializeType1, self).__init__(*args, **kwargs)

    def i2m(self, pkt, val):
        return ndr_serialize1(val)

    def m2i(self, pkt, s):
        return ndr_deserialize1(s, self.cls, ndr64=False)

    def i2len(self, pkt, val):
        return len(self.i2m(pkt, val))


class NDRSerializeType1PacketField(_NDRSerializeType1, PacketField):
    __slots__ = ["ptr"]


class NDRSerializeType1PacketLenField(_NDRSerializeType1, PacketLenField):
    __slots__ = ["ptr"]


class NDRSerializeType1PacketListField(_NDRSerializeType1, PacketListField):
    __slots__ = ["ptr"]


# --- DCE/RPC session


class DceRpcSession(DefaultSession):
    """
    A DCE/RPC session within a TCP socket.
    """

    def __init__(self, *args, **kwargs):
        self.rpc_bind_interface = None
        self.ndr64 = False
        self.ndrendian = "little"
        self.support_header_signing = kwargs.pop("support_header_signing", True)
        self.header_sign = conf.dcerpc_force_header_signing
        self.ssp = kwargs.pop("ssp", None)
        self.sspcontext = kwargs.pop("sspcontext", None)
        self.auth_level = kwargs.pop("auth_level", None)
        self.auth_context_id = kwargs.pop("auth_context_id", 0)
        self.map_callid_opnum = {}
        self.frags = collections.defaultdict(lambda: b"")
        self.sniffsspcontexts = {}  # Unfinished contexts for passive
        if conf.dcerpc_session_enable and conf.winssps_passive:
            for ssp in conf.winssps_passive:
                self.sniffsspcontexts[ssp] = None
        super(DceRpcSession, self).__init__(*args, **kwargs)

    def _up_pkt(self, pkt):
        """
        Common function to handle the DCE/RPC session: what interfaces are bind,
        opnums, etc.
        """
        opnum = None
        opts = {}
        if DceRpc5Bind in pkt or DceRpc5AlterContext in pkt:
            # bind => get which RPC interface
            for ctx in pkt.context_elem:
                if_uuid = ctx.abstract_syntax.if_uuid
                if_version = ctx.abstract_syntax.if_version
                try:
                    self.rpc_bind_interface = DCE_RPC_INTERFACES[(if_uuid, if_version)]
                except KeyError:
                    self.rpc_bind_interface = None
                    log_runtime.warning(
                        "Unknown RPC interface %s. Try loading the IDL" % if_uuid
                    )
        elif DceRpc5BindAck in pkt or DceRpc5AlterContextResp in pkt:
            # bind ack => is it NDR64
            for res in pkt.results:
                if res.result == 0:  # Accepted
                    self.ndrendian = {0: "big", 1: "little"}[pkt[DceRpc5].endian]
                    if res.transfer_syntax.sprintf("%if_uuid%") == "NDR64":
                        self.ndr64 = True
        elif DceRpc5Request in pkt:
            # request => match opnum with callID
            opnum = pkt.opnum
            self.map_callid_opnum[pkt.call_id] = opnum, pkt[DceRpc5Request].payload
        elif DceRpc5Response in pkt:
            # response => get opnum from table
            try:
                opnum, opts["request_packet"] = self.map_callid_opnum[pkt.call_id]
                del self.map_callid_opnum[pkt.call_id]
            except KeyError:
                log_runtime.info("Unknown call_id %s in DCE/RPC session" % pkt.call_id)
        # Bind / Alter request/response specific
        if (
            DceRpc5Bind in pkt
            or DceRpc5AlterContext in pkt
            or DceRpc5BindAck in pkt
            or DceRpc5AlterContextResp in pkt
        ):
            # Detect if "Header Signing" is in use
            if pkt.pfc_flags & 0x04:  # PFC_SUPPORT_HEADER_SIGN
                self.header_sign = True
        return opnum, opts

    # [C706] sect 12.6.2 - Fragmentation and Reassembly
    # Since the connection-oriented transport guarantees sequentiality, the receiver
    # will always receive the fragments in order.

    def _defragment(self, pkt):
        """
        Function to defragment DCE/RPC packets.
        """
        uid = pkt.call_id
        if pkt.pfc_flags.PFC_FIRST_FRAG and pkt.pfc_flags.PFC_LAST_FRAG:
            # Not fragmented
            return pkt
        if pkt.pfc_flags.PFC_FIRST_FRAG or uid in self.frags:
            # Packet is fragmented
            self.frags[uid] += pkt[DceRpc5].payload.payload.original
            if pkt.pfc_flags.PFC_LAST_FRAG:
                pkt[DceRpc5].payload.remove_payload()
                pkt[DceRpc5].payload /= self.frags[uid]
                return pkt
        else:
            # Not fragmented
            return pkt

    def _fragment(self, pkt):
        """
        Function to fragment DCE/RPC packets.
        """
        # unimplemented
        pass

    # [MS-RPCE] sect 3.3.1.5.2.2

    # The PDU header, PDU body, and sec_trailer MUST be passed in the input message, in
    # this order, to GSS_WrapEx, GSS_UnwrapEx, GSS_GetMICEx, and GSS_VerifyMICEx. For
    # integrity protection the sign flag for that PDU segment MUST be set to TRUE, else
    # it MUST be set to FALSE. For confidentiality protection, the conf_req_flag for
    # that PDU segment MUST be set to TRUE, else it MUST be set to FALSE.

    # If the authentication level is RPC_C_AUTHN_LEVEL_PKT_PRIVACY, the PDU body will
    # be encrypted.
    # The PDU body from the output message of GSS_UnwrapEx represents the plain text
    # version of the PDU body. The PDU header and sec_trailer output from the output
    # message SHOULD be ignored.
    # Similarly the signature output SHOULD be ignored.

    def in_pkt(self, pkt):
        # Defragment
        pkt = self._defragment(pkt)
        if not pkt:
            return
        # Get opnum and options
        opnum, opts = self._up_pkt(pkt)
        # Check for encrypted payloads
        body = None
        if conf.raw_layer in pkt.payload:
            body = bytes(pkt.payload[conf.raw_layer])
        # If we are doing passive sniffing
        if conf.dcerpc_session_enable and conf.winssps_passive:
            # We have Windows SSPs, and no current context
            if pkt.auth_verifier and pkt.auth_verifier.is_ssp():
                # This is a bind/alter/auth3 req/resp
                for ssp in self.sniffsspcontexts:
                    self.sniffsspcontexts[ssp], status = ssp.GSS_Passive(
                        self.sniffsspcontexts[ssp],
                        pkt.auth_verifier.auth_value,
                    )
                    if status == GSS_S_COMPLETE:
                        self.auth_level = DCE_C_AUTHN_LEVEL(
                            int(pkt.auth_verifier.auth_level)
                        )
                        self.ssp = ssp
                        self.sspcontext = self.sniffsspcontexts[ssp]
                        self.sniffsspcontexts[ssp] = None
            elif (
                self.sspcontext
                and pkt.auth_verifier
                and pkt.auth_verifier.is_protected()
                and body
            ):
                # This is a request/response
                if self.sspcontext.passive:
                    self.ssp.GSS_Passive_set_Direction(
                        self.sspcontext,
                        IsAcceptor=DceRpc5Response in pkt,
                    )
        if pkt.auth_verifier and pkt.auth_verifier.is_protected() and body:
            if self.sspcontext is None:
                return pkt
            if self.auth_level in (
                RPC_C_AUTHN_LEVEL.PKT_INTEGRITY,
                RPC_C_AUTHN_LEVEL.PKT_PRIVACY,
            ):
                # note: 'vt_trailer' is included in the pdu body
                # [MS-RPCE] sect 2.2.2.13
                # "The data structures MUST only appear in a request PDU, and they
                # SHOULD be placed in the PDU immediately after the stub data but
                # before the authentication padding octets. Therefore, for security
                # purposes, the verification trailer is considered part of the PDU
                # body."
                if pkt.vt_trailer:
                    body += bytes(pkt.vt_trailer)
                # Account for padding when computing checksum/encryption
                if pkt.auth_padding:
                    body += pkt.auth_padding

                # Build pdu_header and sec_trailer
                pdu_header = pkt.copy()
                sec_trailer = pdu_header.auth_verifier
                # sec_trailer: include the sec_trailer but not the Authentication token
                authval_len = len(sec_trailer.auth_value)
                # Discard everything out of the header
                pdu_header.auth_padding = None
                pdu_header.auth_verifier = None
                pdu_header.payload.payload = NoPayload()
                pdu_header.vt_trailer = None

                # [MS-RPCE] sect 2.2.2.12
                if self.auth_level == RPC_C_AUTHN_LEVEL.PKT_PRIVACY:
                    _msgs = self.ssp.GSS_UnwrapEx(
                        self.sspcontext,
                        [
                            # "PDU header"
                            SSP.WRAP_MSG(
                                conf_req_flag=False,
                                sign=self.header_sign,
                                data=bytes(pdu_header),
                            ),
                            # "PDU body"
                            SSP.WRAP_MSG(
                                conf_req_flag=True,
                                sign=True,
                                data=body,
                            ),
                            # "sec_trailer"
                            SSP.WRAP_MSG(
                                conf_req_flag=False,
                                sign=self.header_sign,
                                data=bytes(sec_trailer)[:-authval_len],
                            ),
                        ],
                        pkt.auth_verifier.auth_value,
                    )
                    body = _msgs[1].data  # PDU body
                elif self.auth_level == RPC_C_AUTHN_LEVEL.PKT_INTEGRITY:
                    self.ssp.GSS_VerifyMICEx(
                        self.sspcontext,
                        [
                            # "PDU header"
                            SSP.MIC_MSG(
                                sign=self.header_sign,
                                data=bytes(pdu_header),
                            ),
                            # "PDU body"
                            SSP.MIC_MSG(
                                sign=True,
                                data=body,
                            ),
                            # "sec_trailer"
                            SSP.MIC_MSG(
                                sign=self.header_sign,
                                data=bytes(sec_trailer)[:-authval_len],
                            ),
                        ],
                        pkt.auth_verifier.auth_value,
                    )
                # Put padding back into the header
                if pkt.auth_padding:
                    padlen = len(pkt.auth_padding)
                    body, pkt.auth_padding = body[:-padlen], body[-padlen:]
                # Put back vt_trailer into the header
                if pkt.vt_trailer:
                    vtlen = len(pkt.vt_trailer)
                    body, pkt.vt_trailer = body[:-vtlen], body[-vtlen:]
        # Try to parse the payload
        if opnum is not None and self.rpc_bind_interface:
            # use opnum to parse the payload
            is_response = DceRpc5Response in pkt
            try:
                cls = self.rpc_bind_interface.opnums[opnum][is_response]
            except KeyError:
                log_runtime.warning(
                    "Unknown opnum %s for interface %s"
                    % (opnum, self.rpc_bind_interface)
                )
                pkt.payload[conf.raw_layer].load = body
                return pkt
            if body:
                # Dissect payload using class
                payload = cls(body, ndr64=self.ndr64, ndrendian=self.ndrendian, **opts)
                pkt.payload[conf.raw_layer].underlayer.remove_payload()
                pkt /= payload
            elif not cls.fields_desc:
                # Request class has no payload
                pkt /= cls(ndr64=self.ndr64, ndrendian=self.ndrendian, **opts)
        elif body:
            pkt.payload[conf.raw_layer].load = body
        return pkt

    def out_pkt(self, pkt):
        assert DceRpc5 in pkt
        self._up_pkt(pkt)
        if pkt.auth_verifier is not None:
            # Verifier already set
            return [pkt]
        if self.sspcontext and isinstance(
            pkt.payload, (DceRpc5Request, DceRpc5Response)
        ):
            body = bytes(pkt.payload.payload)
            signature = None
            if self.auth_level in (
                RPC_C_AUTHN_LEVEL.PKT_INTEGRITY,
                RPC_C_AUTHN_LEVEL.PKT_PRIVACY,
            ):
                # Account for padding when computing checksum/encryption
                if pkt.auth_padding is None:
                    padlen = (-len(body)) % _COMMON_AUTH_PAD  # authdata padding
                    pkt.auth_padding = b"\x00" * padlen
                else:
                    padlen = len(pkt.auth_padding)
                # Remember that vt_trailer is included in the PDU
                if pkt.vt_trailer:
                    body += bytes(pkt.vt_trailer)
                # Remember that padding IS SIGNED & ENCRYPTED
                body += pkt.auth_padding
                # Add the auth_verifier
                pkt.auth_verifier = CommonAuthVerifier(
                    auth_type=self.ssp.auth_type,
                    auth_level=self.auth_level,
                    auth_context_id=self.auth_context_id,
                    auth_pad_length=padlen,
                    # Note: auth_value should have the correct length because when
                    # using PFC_SUPPORT_HEADER_SIGN, auth_len (and frag_len) is
                    # included in the token.. but this creates a dependency loop as
                    # you'd need to know the token length to compute the token.
                    # Windows solves this by setting the 'Maximum Signature Length'
                    # (or something similar) beforehand, instead of the real length.
                    # See `gensec_sig_size` in samba.
                    auth_value=b"\x00"
                    * self.ssp.MaximumSignatureLength(self.sspcontext),
                )
                # Build pdu_header and sec_trailer
                pdu_header = pkt.copy()
                pdu_header.auth_len = len(pdu_header.auth_verifier) - 8
                pdu_header.frag_len = len(pdu_header)
                sec_trailer = pdu_header.auth_verifier
                # sec_trailer: include the sec_trailer but not the Authentication token
                authval_len = len(sec_trailer.auth_value)
                # sec_trailer.auth_value = None
                # Discard everything out of the header
                pdu_header.auth_padding = None
                pdu_header.auth_verifier = None
                pdu_header.payload.payload = NoPayload()
                pdu_header.vt_trailer = None
                signature = None
                # [MS-RPCE] sect 2.2.2.12
                if self.auth_level == RPC_C_AUTHN_LEVEL.PKT_PRIVACY:
                    _msgs, signature = self.ssp.GSS_WrapEx(
                        self.sspcontext,
                        [
                            # "PDU header"
                            SSP.WRAP_MSG(
                                conf_req_flag=False,
                                sign=self.header_sign,
                                data=bytes(pdu_header),
                            ),
                            # "PDU body"
                            SSP.WRAP_MSG(
                                conf_req_flag=True,
                                sign=True,
                                data=body,
                            ),
                            # "sec_trailer"
                            SSP.WRAP_MSG(
                                conf_req_flag=False,
                                sign=self.header_sign,
                                data=bytes(sec_trailer)[:-authval_len],
                            ),
                        ],
                    )
                    s = _msgs[1].data  # PDU body
                elif self.auth_level == RPC_C_AUTHN_LEVEL.PKT_INTEGRITY:
                    signature = self.ssp.GSS_GetMICEx(
                        self.sspcontext,
                        [
                            # "PDU header"
                            SSP.MIC_MSG(
                                sign=self.header_sign,
                                data=bytes(pdu_header),
                            ),
                            # "PDU body"
                            SSP.MIC_MSG(
                                sign=True,
                                data=body,
                            ),
                            # "sec_trailer"
                            SSP.MIC_MSG(
                                sign=self.header_sign,
                                data=bytes(sec_trailer)[:-authval_len],
                            ),
                        ],
                        pkt.auth_verifier.auth_value,
                    )
                    s = body
                else:
                    raise ValueError("Impossible")
                # Put padding back in the header
                if padlen:
                    s, pkt.auth_padding = s[:-padlen], s[-padlen:]
                # Put back vt_trailer into the header
                if pkt.vt_trailer:
                    vtlen = len(pkt.vt_trailer)
                    s, pkt.vt_trailer = s[:-vtlen], s[-vtlen:]
            else:
                s = body

            # now inject the encrypted payload into the packet
            pkt.payload.payload = conf.raw_layer(load=s)
            # and the auth_value
            if signature:
                pkt.auth_verifier.auth_value = signature
            else:
                pkt.auth_verifier = None
        return [pkt]

    def process(self, pkt: Packet) -> Optional[Packet]:
        pkt = super(DceRpcSession, self).process(pkt)
        if pkt is not None and DceRpc5 in pkt:
            return self.in_pkt(pkt)
        return pkt


class DceRpcSocket(StreamSocket):
    """
    A Wrapper around StreamSocket that uses a DceRpcSession
    """

    def __init__(self, *args, **kwargs):
        self.session = DceRpcSession(
            ssp=kwargs.pop("ssp", None),
            auth_level=kwargs.pop("auth_level", None),
            auth_context_id=kwargs.pop("auth_context_id", None),
            support_header_signing=kwargs.pop("support_header_signing", True),
        )
        super(DceRpcSocket, self).__init__(*args, **kwargs)

    def send(self, x, **kwargs):
        for pkt in self.session.out_pkt(x):
            return super(DceRpcSocket, self).send(pkt, **kwargs)

    def recv(self, x=None):
        pkt = super(DceRpcSocket, self).recv(x)
        if pkt is not None:
            return self.session.in_pkt(pkt)


# --- TODO cleanup below

# Heuristically way to find the payload class
#
# To add a possible payload to a DCE/RPC packet, one must first create the
# packet class, then instead of binding layers using bind_layers, he must
# call DceRpcPayload.register_possible_payload() with the payload class as
# parameter.
#
# To be able to decide if the payload class is capable of handling the rest of
# the dissection, the classmethod can_handle() should be implemented in the
# payload class. This method is given the rest of the string to dissect as
# first argument, and the DceRpc packet instance as second argument. Based on
# this information, the method must return True if the class is capable of
# handling the dissection, False otherwise


class DceRpc4Payload(Packet):
    """Dummy class which use the dispatch_hook to find the payload class"""

    _payload_class = []

    @classmethod
    def dispatch_hook(cls, _pkt, _underlayer=None, *args, **kargs):
        """dispatch_hook to choose among different registered payloads"""
        for klass in cls._payload_class:
            if hasattr(klass, "can_handle") and klass.can_handle(_pkt, _underlayer):
                return klass
        log_runtime.warning("DCE/RPC payload class not found or undefined (using Raw)")
        return Raw

    @classmethod
    def register_possible_payload(cls, pay):
        """Method to call from possible DCE/RPC endpoint to register it as
        possible payload"""
        cls._payload_class.append(pay)


bind_layers(DceRpc4, DceRpc4Payload)
