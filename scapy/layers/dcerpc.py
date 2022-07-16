# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2016 Gauthier Sebaux
#               2022 Gabriel Potter

# scapy.contrib.description = DCE/RPC
# scapy.contrib.status = loads

"""
DCE/RPC
Distributed Computing Environment / Remote Procedure Calls

Based on [C706] - aka DCE/RPC 1.1
https://pubs.opengroup.org/onlinepubs/9629399/toc.pdf
"""

from functools import partial
from collections import namedtuple, deque

import struct
from uuid import UUID
from scapy.base_classes import Packet_metaclass

from scapy.config import conf
from scapy.error import log_runtime
from scapy.layers.dns import DNSStrField
from scapy.layers.ntlm import NTLM_Header
from scapy.packet import Packet, Raw, bind_bottom_up, bind_layers, bind_top_down
from scapy.fields import (
    _FieldContainer,
    BitEnumField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    FieldListField,
    FlagsField,
    IEEEDoubleField,
    IEEEFloatField,
    IntField,
    LEIntEnumField,
    LEIntField,
    LELongField,
    LEShortEnumField,
    LEShortField,
    LESignedIntField,
    LESignedLongField,
    LESignedShortField,
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

from scapy.layers.kerberos import KRB5_GSS_Wrap_RFC1964, KRB5_GSS_Wrap, Kerberos
from scapy.layers.gssapi import GSSAPI_BLOB
from scapy.layers.inet import TCP

from scapy.contrib.rtps.common_types import (
    EField,
    EPacket,
    EPacketField,
    EPacketListField,
)

import scapy.libs.six as six


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


def _dce_rpc_endianess(pkt):
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
        super(_EField, self).__init__(fld, endianness_from=_dce_rpc_endianess)


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
        return _dce_rpc_endianess(self.underlayer)


# sect 12.5

_drep = [
    BitEnumField("endian", 1, 4, ["big", "little"]),
    BitEnumField("encoding", 0, 4, ["ASCII", "EBCDIC"]),
    ByteEnumField("float", 0, ["IEEE", "VAX", "CRAY", "IBM"]),
    ByteField("reserved1", 0),
]


class DceRpc4(Packet):
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
        ] +
        _drep +
        [
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


# Exceptionally, we define those 2 here.


class NetlogonAuthMessage(Packet):
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
            StrNullField("NetbiosComputerNameUtf8", ""),
            lambda pkt: pkt.Flags.NETBIOS_COMPUTER_NAME_UTF8,
        ),
    ]


class NetlogonAuthSignature(Packet):
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
                0x00A1: "AES-128",
            },
        ),
        XLEShortField("Pad", 0xFFFF),
        ShortField("Reserved", 0),
        XLELongField("SequenceNumber", 0),
        XStrFixedLenField("Checksum", b"", length=8),
        XStrFixedLenField("Confounder", b"", length=8),
        ConditionalField(
            StrFixedLenField("Reserved2", b"", length=24),
            lambda pkt: pkt.SignatureAlgorithm == 0x0013,
        ),
    ]


# sect 13.2.6.1


_MSRPCE_SECURITY_PROVIDERS = {
    # [MS-RPCE] sect 2.2.1.1.7
    0x00: "None",
    0x09: "SPNEGO",
    0x0A: "NTLM",
    0x0E: "TLS",
    0x10: "Kerberos",
    0x44: "Netlogon",
    0xFF: "NTLM",
}

_MSRPCE_SECURITY_AUTHLEVELS = {
    # [MS-RPCE] sect 2.2.1.1.7
    0x00: "RPC_C_AUTHN_LEVEL_DEFAULT",
    0x01: "RPC_C_AUTHN_LEVEL_NONE",
    0x02: "RPC_C_AUTHN_LEVEL_CONNECT",
    0x03: "RPC_C_AUTHN_LEVEL_CALL",
    0x04: "RPC_C_AUTHN_LEVEL_PKT",
    0x05: "RPC_C_AUTHN_LEVEL_PKT_INTEGRITY",
    0x06: "RPC_C_AUTHN_LEVEL_PRIVACY",
}


class CommonAuthVerifier(Packet):
    name = "Common Authentication Verifier (auth_verifier_co_t)"
    fields_desc = [
        ReversePadField(
            ByteEnumField(
                "auth_type",
                0,
                _MSRPCE_SECURITY_PROVIDERS,
            ),
            align=4,
        ),
        ByteEnumField("auth_level", 0, _MSRPCE_SECURITY_AUTHLEVELS),
        ByteField("auth_pad_length", 0),
        ByteField("auth_reserved", 0),
        XLEIntField("auth_context_id", 0),
        MultipleTypeField(
            [
                (
                    PacketLenField(
                        "auth_value",
                        GSSAPI_BLOB(),
                        GSSAPI_BLOB,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type == 0x09,
                ),
                (
                    PacketLenField(
                        "auth_value",
                        NTLM_Header(),
                        NTLM_Header,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type in [0x0A, 0xFF],
                ),
                (
                    PacketLenField(
                        "auth_value",
                        Kerberos(),
                        Kerberos,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type == 0x10,
                ),
                # NetLogon
                (
                    PacketLenField(
                        "auth_value",
                        NetlogonAuthMessage(),
                        NetlogonAuthMessage,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type == 0x44 and
                    pkt.parent and
                    pkt.parent.ptype in [11, 12, 13],
                ),
                (
                    PacketLenField(
                        "auth_value",
                        NetlogonAuthSignature(),
                        NetlogonAuthSignature,
                        length_from=lambda pkt: pkt.parent.auth_len,
                    ),
                    lambda pkt: pkt.auth_type == 0x44 and
                    (not pkt.parent or pkt.parent.ptype not in [11, 12, 13]),
                ),
            ],
            PacketLenField(
                "auth_value",
                None,
                conf.raw_layer,
                length_from=lambda pkt: pkt.parent.auth_len,
            ),
        ),
    ]

    def is_encrypted(self):
        if self.auth_type == 9 and isinstance(self.auth_value, GSSAPI_BLOB):
            return isinstance(
                self.auth_value.innerContextToken,
                (KRB5_GSS_Wrap_RFC1964, KRB5_GSS_Wrap),
            )
        return False


# sect 12.6


_DCE_RPC_5_FLAGS = {
    0x01: "FIRST_FRAG",
    0x02: "LAST_FRAG",
    0x04: "PENDING_CANCEL",
    0x10: "CONC_MPX",
    0x20: "DID_NOT_EXECUTE",
    0x40: "MAYBE",
    0x80: "OBJECT_UUID",
}


class DceRpc5(Packet):
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
            FlagsField("pfc_flags", 0, 8, _DCE_RPC_5_FLAGS),
        ] +
        _drep +
        [
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
        ]
    )

    def post_build(self, pkt, pay):
        if self.frag_len is None:
            length = len(pkt) + len(pay)
            pkt = (
                pkt[:8] +
                self.get_field("frag_len").addfield(self, b"", length) +
                pkt[10:]
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
        if len(data) == length:
            # Start a DCE/RPC session for this TCP stream
            dcerpc_session = session.get("dcerpc_session", None)
            if not dcerpc_session:
                dcerpc_session = session["dcerpc_session"] = DceRpcSession()
            pkt = dcerpc_session._process_dcerpc_packet(DceRpc5(data))
            return pkt


# sec 12.6.3.1


DCE_RPC_INTERFACES_NAMES = {}
DCE_RPC_INTERFACES_NAMES_rev = {}

DCE_RPC_TRANSFER_SYNTAXES = {
    UUID("00000000-0000-0000-0000-000000000000"): "NULL",
    UUID("6cb71c2c-9812-4540-0300-000000000000"): "Bind Time Feature Negotiation",
    UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"): "NDR 2.0",
    UUID("71710533-beba-4937-8319-b5dbef9ccc36"): "NDR64",
}


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
                    DCE_RPC_INTERFACES_NAMES_rev.get,
                ),
            )
        ),
        _EField(ShortField("if_version", 3)),
        _EField(ShortField("if_version_minor", 0)),
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
        _EField(ShortField("if_version", 3)),
        _EField(ShortField("reserved", 0)),
    ]


class DceRpc5Context(EPacket):
    name = "Presentation Context (p_cont_elem_t)"
    fields_desc = [
        _EField(ShortField("context_id", 0)),
        FieldLenField("n_transfer_syn", None, count_of="transfer_syntaxes", fmt="B"),
        ByteField("reserved", 0),
        EPacketField("abstract_syntax", None, DceRpc5AbstractSyntax),
        EPacketListField(
            "transfer_syntaxes",
            None,
            DceRpc5TransferSyntax,
            count_from=lambda pkt: pkt.n_transfer_syn,
            endianness_from=_dce_rpc_endianess,
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
                [
                    "reason_not_specified",
                    "abstract_syntax_not_supported",
                    "proposed_transfer_syntaxes_not_supported",
                    "local_limit_exceeded",
                ],
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


# sec 12.6.4.1


class DceRpc5AlterContext(_DceRpcPayload):
    name = "DCE/RPC v5 - AlterContext"
    fields_desc = [
        _EField(ShortField("max_xmit_frag", 5840)),
        _EField(ShortField("max_recv_frag", 8192)),
        _EField(IntField("assoc_group_id", 0)),
        # p_result_list_t
        _EField(FieldLenField("n_results", None, count_of="results", fmt="B")),
        StrFixedLenField("reserved", 0, length=3),
        EPacketListField(
            "results",
            [],
            DceRpc5Result,
            count_from=lambda pkt: pkt.n_results,
            endianness_from=_dce_rpc_endianess,
        ),
    ]


bind_layers(DceRpc5, DceRpc5AlterContext, ptype=14)


# sec 12.6.4.2


class DceRpc5AlterContextResp(_DceRpcPayload):
    name = "DCE/RPC v5 - AlterContextResp"
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
            count_from=lambda pkt: pkt.n_results,
            endianness_from=_dce_rpc_endianess,
        ),
    ]


bind_layers(DceRpc5, DceRpc5AlterContextResp, ptype=15)

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
            endianness_from=_dce_rpc_endianess,
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
            endianness_from=_dce_rpc_endianess,
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
        _EField(ShortField("provider_reject_reason", 0)),
        # p_rt_versions_supported_t
        _EField(FieldLenField("n_protocols", None, length_of="protocols", fmt="B")),
        EPacketListField(
            "protocols",
            [],
            DceRpc5Version,
            count_from=lambda pkt: pkt.n_protocols,
            endianness_from=_dce_rpc_endianess,
        ),
    ]


bind_layers(DceRpc5, DceRpc5BindNak, ptype=13)

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
            lambda pkt: pkt.underlayer.pfc_flags.OBJECT_UUID,
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

DceRpcOp = namedtuple("DceRpcOp", ["request", "response"])
DCE_RPC_INTERFACES = {}


class DceRpcInterface:
    def __init__(self, name, uuid, version, opnums):
        self.name = name
        self.uuid = uuid
        self.version = version
        self.opnums = opnums

    def __repr__(self):
        return "<DCE/RPC Interface %s v%s>" % (self.name, self.version)


def register_dcerpc_interface(name, uuid, version, opnums):
    """
    Register a DCE/RPC interface
    """
    if uuid in DCE_RPC_INTERFACES:
        raise ValueError("Interface is already registered !")
    DCE_RPC_INTERFACES_NAMES[uuid] = "%s (v%s)" % (name.upper(), version)
    DCE_RPC_INTERFACES_NAMES_rev[name.upper()] = uuid
    DCE_RPC_INTERFACES[uuid] = DceRpcInterface(
        name,
        uuid,
        version,
        opnums,
    )
    # bind for build
    for opnum, operations in opnums.items():
        bind_top_down(DceRpc5Request, operations.request, opnum=opnum)


def find_dcerpc_interface(name):
    """
    Find an interface object through the name in the IDL
    """
    return next(x for x in DCE_RPC_INTERFACES.values() if x.name == name)


# --- NDR fields - [C706] chap 14


class _NDRPacket(Packet):
    __slots__ = ["ndr64", "defered_pointers"]

    def __init__(self, *args, **kwargs):
        self.ndr64 = kwargs.pop("ndr64", True)
        self.defered_pointers = []
        super(_NDRPacket, self).__init__(*args, **kwargs)

    def _update_fields(self):
        _up = self.parent or self.underlayer
        if _up and isinstance(_up, _NDRPacket):
            self.ndr64 = _up.ndr64

    def do_build(self):
        self._update_fields()
        return super(_NDRPacket, self).do_build()

    def dissect(self, s):
        self._update_fields()
        return super(_NDRPacket, self).dissect(s)

    def default_payload_class(self, pkt):
        return conf.padding_layer

    def clone_with(self, *args, **kwargs):
        pkt = super(_NDRPacket, self).clone_with(*args, **kwargs)
        # We need to copy defered_pointers to not break pointer deferral
        # on build.
        pkt.defered_pointers = self.defered_pointers
        pkt.ndr64 = self.ndr64
        return pkt

    def copy(self):
        pkt = super(_NDRPacket, self).copy()
        pkt.defered_pointers = self.defered_pointers
        pkt.ndr64 = self.ndr64
        return pkt


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


class _NDRPacketMetaclass(Packet_metaclass):
    def __new__(cls, name, bases, dct):
        newcls = super(_NDRPacketMetaclass, cls).__new__(cls, name, bases, dct)
        conformants = dct.get("CONFORMANT_COUNT", 0)
        if conformants:
            if conformants == 1:
                newcls.fields_desc.insert(
                    0,
                    MultipleTypeField(
                        [
                            (
                                NDRLongField("max_count", 0),
                                lambda pkt: pkt and pkt.ndr64,
                            )
                        ],
                        NDRIntField("max_count", 0),
                    ),
                )
            else:
                newcls.fields_desc.insert(
                    0,
                    MultipleTypeField(
                        [
                            (
                                NDRAlign(
                                    FieldListField(
                                        "max_counts",
                                        0,
                                        LELongField("", 0),
                                        count_from=lambda _: conformants,
                                    ),
                                    align=(8, 8),
                                ),
                                lambda pkt: pkt and pkt.ndr64,
                            )
                        ],
                        NDRAlign(
                            FieldListField(
                                "max_counts",
                                0,
                                LEIntField("", 0),
                                count_from=lambda _: conformants,
                            ),
                            align=(4, 4),
                        ),
                    ),
                )
        return newcls  # type: ignore


@six.add_metaclass(_NDRPacketMetaclass)
class NDRPacket(_NDRPacket):
    """
    A NDR Packet. Handles pointer size & endianness
    """

    __slots__ = ["_align"]

    # NDR64 pad structures
    # [MS-RPCE] 2.2.5.3.4.1
    ALIGNMENT = (1, 1)
    # Conformants max_count can be added to the beginning
    CONFORMANT_COUNT = 0


# Primitive types
NDRByteField = ByteField
NDRSignedByteField = SignedByteField


class NDRShortField(NDRAlign):
    def __init__(self, *args, **kwargs):
        super(NDRShortField, self).__init__(LEShortField(*args, **kwargs), align=(2, 2))


class NDRSignedShortField(NDRAlign):
    def __init__(self, *args, **kwargs):
        super(NDRSignedShortField, self).__init__(
            LESignedShortField(*args, **kwargs), align=(2, 2)
        )


class NDRIntField(NDRAlign):
    def __init__(self, *args, **kwargs):
        super(NDRIntField, self).__init__(LEIntField(*args, **kwargs), align=(4, 4))


class NDRSignedIntField(NDRAlign):
    def __init__(self, *args, **kwargs):
        super(NDRSignedIntField, self).__init__(
            LESignedIntField(*args, **kwargs), align=(4, 4)
        )


class NDRLongField(NDRAlign):
    def __init__(self, *args, **kwargs):
        super(NDRLongField, self).__init__(LELongField(*args, **kwargs), align=(8, 8))


class NDRSignedLongField(NDRAlign):
    def __init__(self, *args, **kwargs):
        super(NDRSignedLongField, self).__init__(
            LESignedLongField(*args, **kwargs), align=(8, 8)
        )


class NDRIEEEFloatField(NDRAlign):
    def __init__(self, *args, **kwargs):
        super(NDRIEEEFloatField, self).__init__(
            IEEEFloatField(*args, **kwargs), align=(4, 4)
        )


class NDRIEEEDoubleField(NDRAlign):
    def __init__(self, *args, **kwargs):
        super(NDRIEEEDoubleField, self).__init__(
            IEEEDoubleField(*args, **kwargs), align=(8, 8)
        )


# Enum types


class NDRShortEnumField(NDRAlign):
    def __init__(self, *args, **kwargs):
        super(NDRShortEnumField, self).__init__(
            LEShortEnumField(*args, **kwargs), align=(2, 2)
        )


class NDRIntEnumField(NDRAlign):
    def __init__(self, *args, **kwargs):
        super(NDRIntEnumField, self).__init__(
            LEIntEnumField(*args, **kwargs), align=(4, 4)
        )


# Special types


class NDRInt3264Field(Field):
    FMTS = ["<I", "<Q"]

    def getfield(self, pkt, s):
        fmt = self.FMTS[pkt.ndr64]
        return NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).getfield(pkt, s)

    def addfield(self, pkt, s, val):
        fmt = self.FMTS[pkt.ndr64]
        return NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).addfield(pkt, s, val)


class NDRSignedInt3264Field(NDRInt3264Field):
    FMTS = ["<i", "<q"]


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
        self.deferred = deferred

    def getfield(self, pkt, s):
        fmt = ["<I", "<Q"][pkt.ndr64]
        remain, referent_id = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).getfield(
            pkt, s
        )
        if not self.EMBEDDED and referent_id == 0:
            return remain, None
        if self.deferred:
            # deferred
            ptr = NDRPointer(ndr64=pkt.ndr64, referent_id=referent_id)
            pkt.defered_pointers.append((ptr, partial(self.fld.getfield, pkt)))
            return remain, ptr
        remain, val = self.fld.getfield(pkt, remain)
        return remain, NDRPointer(ndr64=pkt.ndr64, referent_id=referent_id, value=val)

    def addfield(self, pkt, s, val):
        if val is not None and not isinstance(val, NDRPointer):
            raise ValueError(
                "Expected NDRPointer in %s. You are using it wrong!" % self.name
            )
        fmt = ["<I", "<Q"][pkt.ndr64]
        fld = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8))
        if not self.EMBEDDED and val is None:
            return fld.addfield(pkt, s, 0)
        else:
            s = fld.addfield(pkt, s, val.referent_id)
        if self.deferred:
            # deferred
            pkt.defered_pointers.append(
                ((lambda s: self.fld.addfield(pkt, s, val.value)), val)
            )
            return s
        return self.fld.addfield(pkt, s, val.value)

    def i2repr(self, pkt, val):
        return repr(val)


class NDRRefEmbPointerField(NDRFullPointerField):
    """
    A NDR Embedded Reference pointer
    """

    EMBEDDED = True


# Constructed types


# Note: this is utterly complex and will drive you crazy


class NDRConstructedType:
    def __init__(self, fields):
        self.handles_deferred = False
        self.ndr_fields = fields
        self.rec_check_deferral()

    def rec_check_deferral(self):
        # We iterate through the fields within this constructed type.
        # If we have a pointer, mark this field as handling deferrance
        # and make all sub-constructed types not.
        for f in self.ndr_fields:
            if isinstance(f, NDRConstructedType):
                if f.handles_deferred:
                    self.handles_deferred = True
                    f.handles_deferred = False
            if isinstance(f, NDRFullPointerField) and f.deferred:
                self.handles_deferred = True

    def getfield(self, pkt, s):
        s, fval = super(NDRConstructedType, self).getfield(pkt, s)
        if self.handles_deferred:
            # Now read content of the pointers that were deferred
            q = deque()
            q.extend(pkt.defered_pointers)
            pkt.defered_pointers.clear()
            while q:
                # Recursively resolve pointers that were deferred
                ptr, getfld = q.popleft()
                s, val = getfld(s)
                ptr.value = val
                if isinstance(val, _NDRPacket):
                    # Pointer resolves to a packet.. that may have deferred pointers?
                    q.extend(val.defered_pointers)
                    val.defered_pointers.clear()
        elif isinstance(fval, _NDRPacket):
            # If a sub-packet we just dissected has deferred pointers,
            # pass it to parent packet to propagate.
            pkt.defered_pointers.extend(fval.defered_pointers)
            fval.defered_pointers.clear()
        return s, fval

    def addfield(self, pkt, s, val):
        # Same logic than above, same comments.
        s = super(NDRConstructedType, self).addfield(pkt, s, val)
        if isinstance(val, _NDRPacket):
            pkt.defered_pointers.extend(val.defered_pointers)
            val.defered_pointers.clear()
        if self.handles_deferred:
            q = deque()
            q.extend(pkt.defered_pointers)
            pkt.defered_pointers.clear()
            while q:
                addfld, fval = q.popleft()
                s = addfld(s)
                if isinstance(fval, NDRPointer) and isinstance(fval.value, _NDRPacket):
                    q.extend(fval.value.defered_pointers)
                    fval.value.defered_pointers.clear()
        return s


class _NDRPacketField(PacketField):
    def m2i(self, pkt, m):
        return self.cls(m, ndr64=pkt.ndr64, _parent=pkt)


# class _NDRPacketPadField(PadField):
#     def padlen(self, flen, pkt):
#         return -flen % self._align[pkt.ndr64]


class NDRPacketField(NDRConstructedType, NDRAlign):
    def __init__(self, name, default, pkt_cls, **kwargs):
        fld = _NDRPacketField(name, default, pkt_cls=pkt_cls, **kwargs)
        NDRAlign.__init__(
            self,
            # There is supposed to be padding after a struct in NDR64?
            # _NDRPacketPadField(fld, align=pkt_cls.ALIGNMENT),
            fld,
            align=pkt_cls.ALIGNMENT,
        )
        NDRConstructedType.__init__(self, pkt_cls.fields_desc)


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
        PacketListField.__init__(self, name, default, pkt_cls=pkt_cls, **kwargs)
        self.fld = NDRPacketField("", None, pkt_cls)
        NDRConstructedType.__init__(self, self.fld.ndr_fields)

    def m2i(self, pkt, s):
        if not self.ptr_pack:
            remain, val = self.fld.getfield(pkt, s)
            # A mistake here would be to use / instead of add_payload. It adds a copy
            # which breaks pointer defferal. Same applies elsewhere
            val.add_payload(conf.padding_layer(remain))
            return val
        else:
            fmt = ["<I", "<Q"][pkt.ndr64]
            # We need to follow alignment for pointers
            remain, referent_id = NDRAlign(
                Field("", 0, fmt=fmt), align=(4, 8)
            ).getfield(pkt, s)
            if referent_id == 0:
                ptr = NDRPointer(ndr64=pkt.ndr64, referent_id=0, value=None)
                ptr.add_payload(conf.padding_layer(remain))
                return ptr
        remain, val = self.fld.getfield(pkt, remain)
        ptr = NDRPointer(
            ndr64=pkt.ndr64,
            referent_id=referent_id,
            value=val,
        )
        ptr.add_payload(conf.padding_layer(remain))
        return ptr

    def i2m(self, pkt, val):
        if not self.ptr_pack:
            return self.fld.addfield(pkt, b"", val)
        fmt = ["<I", "<Q"][pkt.ndr64]
        return NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).addfield(
            pkt, b"", val and val.referent_id or 0
        ) + (self.fld.addfield(pkt, b"", val.value) if val.value is not None else b"")


class NDRVaryingArray(_NDRPacket):
    fields_desc = [
        MultipleTypeField(
            [(LELongField("offset", 0), lambda pkt: pkt and pkt.ndr64)],
            LEIntField("offset", 0),
        ),
        MultipleTypeField(
            [
                (
                    FieldLenField("actual_count", None, fmt="<Q"),
                    lambda pkt: pkt and pkt.ndr64,
                )
            ],
            FieldLenField("actual_count", None, fmt="<I"),
        ),
        PacketField("value", None, conf.raw_layer),
    ]


class _NDRVarField:
    holds_packets = 1

    def getfield(self, pkt, s):
        fmt = ["<I", "<Q"][pkt.ndr64]
        remain, offset = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).getfield(pkt, s)
        remain, actual_count = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).getfield(
            pkt, remain
        )
        remain, val = super(_NDRVarField, self).getfield(pkt, remain)
        return remain, NDRVaryingArray(
            ndr64=pkt.ndr64,
            offset=offset,
            actual_count=actual_count,
            value=super(_NDRVarField, self).i2h(pkt, val),
        )

    def addfield(self, pkt, s, val):
        if not isinstance(val, NDRVaryingArray):
            raise ValueError(
                "Expected NDRVaryingArray in %s. You are using it wrong!" % self.name
            )
        fmt = ["<I", "<Q"][pkt.ndr64]
        s = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).addfield(pkt, s, val.offset)
        s = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).addfield(
            pkt, s, val.actual_count is None and len(val.value) or val.actual_count
        )
        return super(_NDRVarField, self).addfield(
            pkt, s, super(_NDRVarField, self).h2i(pkt, val.value)
        )

    def i2len(self, pkt, x):
        return len(self.addfield(pkt, b"", x))

    any2i = Field.any2i
    i2repr = Field.i2repr
    i2count = Field.i2count


class NDRConformantArray(_NDRPacket):
    fields_desc = [
        MultipleTypeField(
            [(LELongField("max_count", None), lambda pkt: pkt and pkt.ndr64)],
            LEIntField("max_count", None),
        ),
        PacketListField(
            "value", [], conf.raw_layer, count_from=lambda pkt: pkt.max_count
        ),
    ]


class _NDRConfField:
    holds_packets = 1

    def __init__(self, *args, **kwargs):
        self.conformant_in_struct = kwargs.pop("conformant_in_struct", False)
        super(_NDRConfField, self).__init__(*args, **kwargs)

    def getfield(self, pkt, s):
        # [C706] - 14.3.7 Structures Containing Arrays
        fmt = ["<I", "<Q"][pkt.ndr64]
        if self.conformant_in_struct:
            return super(_NDRConfField, self).getfield(pkt, s)
        remain, max_count = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).getfield(
            pkt, s
        )
        remain, val = super(_NDRConfField, self).getfield(pkt, remain)
        return remain, NDRConformantArray(
            ndr64=pkt.ndr64, max_count=max_count, value=val
        )

    def addfield(self, pkt, s, val):
        if self.conformant_in_struct:
            return super(_NDRConfField, self).addfield(pkt, s, val)
        if not isinstance(val, NDRConformantArray):
            raise ValueError(
                "Expected NDRConformantArray in %s. You are using it wrong!" % self.name
            )
        if isinstance(val.value[0], NDRVaryingArray):
            value = val.value[0]
        else:
            value = val.value
        fmt = ["<I", "<Q"][pkt.ndr64]
        s = NDRAlign(Field("", 0, fmt=fmt), align=(4, 8)).addfield(
            pkt,
            s,
            val.max_count,
        )
        return super(_NDRConfField, self).addfield(pkt, s, value)

    def i2len(self, pkt, x):
        return len(self.addfield(pkt, b"", x))

    any2i = Field.any2i
    i2repr = Field.i2repr
    i2count = Field.i2count


class NDRVarPacketListField(_NDRVarField, _NDRPacketListField):
    """
    NDR Varying PacketListField
    """

    pass


class NDRConfPacketListField(_NDRConfField, _NDRPacketListField):
    """
    NDR Conformant PacketListField
    """

    pass


class NDRConfVarPacketListField(_NDRConfField, _NDRVarField, _NDRPacketListField):
    """
    NDR Conformant Varying PacketListField
    """

    pass


class NDRConfFieldListField(_NDRConfField, FieldListField):
    """
    NDR Conformant FieldListField
    """

    pass


class NDRConfVarFieldListField(_NDRConfField, _NDRVarField, FieldListField):
    """
    NDR Conformant Varying FieldListField
    """

    pass


# NDR String fields


class NDRConfStrLenField(_NDRConfField, StrLenField):
    """
    NDR Conformant StrLenField.

    This is not a "string" per NDR, but an a conformant byte array
    (e.g. tower_octet_string)
    """

    pass


class NDRConfStrLenFieldUtf16(_NDRConfField, StrLenFieldUtf16):
    """
    NDR Conformant StrLenField.

    See NDRConfLenStrField for comment.
    """

    pass


class NDRVarStrLenField(_NDRVarField, StrLenField):
    """
    NDR Varying StrLenField
    """

    pass


class NDRVarStrLenFieldUtf16(_NDRVarField, StrLenFieldUtf16):
    """
    NDR Varying StrLenField
    """

    pass


class NDRConfVarStrLenField(_NDRConfField, _NDRVarField, StrLenField):
    """
    NDR Conformant Varying StrLenField
    """

    pass


class NDRConfVarStrLenFieldUtf16(_NDRConfField, _NDRVarField, StrLenFieldUtf16):
    """
    NDR Conformant Varying StrLenField
    """

    pass


class NDRConfVarStrNullField(_NDRConfField, _NDRVarField, StrNullField):
    """
    NDR Conformant Varying StrNullFieldUtf16
    """

    pass


class NDRConfVarStrNullFieldUtf16(_NDRConfField, _NDRVarField, StrNullFieldUtf16):
    """
    NDR Conformant Varying StrNullFieldUtf16
    """

    pass


# Union type


class NDRUnion(Packet):
    # Unlike the others NDRXXXX objects, this is only used as
    # a container, not for building/dissecting
    fields_desc = [
        IntField("tag", 0),
        PacketField("value", None, conf.raw_layer),
    ]


class _NDRUnionField(MultipleTypeField):
    def getfield(self, pkt, s):
        fmt, sz = [("<H", 2), ("<I", 4)][pkt.ndr64]  # special for union
        tag = struct.unpack(fmt, s[:sz])[0]
        remain, val = super(_NDRUnionField, self).getfield(pkt, s[sz:])
        return remain, NDRUnion(tag=tag, value=val)

    def addfield(self, pkt, s, val):
        fmt = ["<I", "<Q"][pkt.ndr64]
        return (
            s +
            struct.pack(fmt, val.tag) +
            super(_NDRUnionField, self).addfield(pkt, b"", val.value)
        )


class NDRUnionField(NDRConstructedType, NDRAlign):
    def __init__(self, flds, dflt, align):
        align = max(align[0], 2), max(align[1], 4)
        NDRAlign.__init__(self, _NDRUnionField(flds, dflt), align=align)
        NDRConstructedType.__init__(self, [x[0] for x in flds] + [dflt])


# Misc


class NDRRecursiveField(Field):
    """
    A special Field that is used for pointer recursion
    """

    def __init__(self, name, fmt="I"):
        super(NDRRecursiveField, self).__init__(name, None, fmt=fmt)

    def getfield(self, pkt, s):
        fmt, sz = [("<I", 4), ("<Q", 8)][pkt.ndr64]
        if s[:sz] == b"\0" * sz:
            return s[sz:], None
        referent_id = struct.unpack(fmt, s[:sz])[0]
        remain, val = NDRPacketField("", None, pkt.__class__).getfield(pkt, s[sz:])
        return remain, NDRPointer(ndr64=pkt.ndr64, referent_id=referent_id, value=val)

    def addfield(self, pkt, s, val):
        if val is None:
            sz = [4, 8][pkt.ndr64]
            return s + b"\0" * sz
        return s + bytes(val)  # FIXME


# The very few NDR-specific structures


class NDRContextHandle(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        LEIntField("attributes", 0),
        StrFixedLenField("uuid", b"", length=16),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


# --- DCE/RPC session


class DceRpcSession(DefaultSession):
    """
    A DCE/RPC session within a TCP socket.
    """

    def __init__(self, *args, **kwargs):
        self.rpc_bind_interface = None
        self.ndr64 = False
        self.map_callid_opnum = {}
        super(DceRpcSession, self).__init__(*args, **kwargs)

    def _process_dcerpc_packet(self, pkt):
        opnum = None
        if DceRpc5Bind in pkt:
            # bind => get which RPC interface
            for ctx in pkt.context_elem:
                if_uuid = ctx.abstract_syntax.if_uuid
                try:
                    self.rpc_bind_interface = DCE_RPC_INTERFACES[if_uuid]
                except KeyError:
                    log_runtime.warning(
                        "Unknown RPC interface %s. Try loading the IDL" % if_uuid
                    )
        elif DceRpc5BindAck in pkt:
            # bind ack => is it NDR64
            for res in pkt[DceRpc5BindAck].results:
                if res.result == 0:  # Accepted
                    if res.transfer_syntax.sprintf("%if_uuid%") == "NDR64":
                        self.ndr64 = True
        elif DceRpc5Request in pkt:
            # request => match opnum with callID
            opnum = self.map_callid_opnum[pkt.call_id] = pkt.opnum
        elif DceRpc5Response in pkt:
            # response => get opnum from table
            try:
                opnum = self.map_callid_opnum[pkt.call_id]
                del self.map_callid_opnum[pkt.call_id]
            except KeyError:
                log_runtime.info("Unknown call_id %s in DCE/RPC session" % pkt.call_id)
        # Check for encrypted payloads
        if pkt.auth_verifier and pkt.auth_verifier.is_encrypted():
            return pkt
        # Try to parse the payload
        if opnum is not None and self.rpc_bind_interface and conf.raw_layer in pkt:
            # use opnum to parse the payload
            is_response = DceRpc5Response in pkt
            try:
                cls = self.rpc_bind_interface.opnums[opnum][is_response]
            except KeyError:
                log_runtime.warning(
                    "Unknown opnum %s for interface %s"
                    % (opnum, self.rpc_bind_interface)
                )
                return
            # Dissect payload using class
            payload = cls(pkt[conf.raw_layer].load, ndr64=self.ndr64)
            pkt[conf.raw_layer].underlayer.remove_payload()
            pkt = pkt / payload
        return pkt

    def on_packet_received(self, pkt):
        if DceRpc5 in pkt:
            return super(DceRpcSession, self).on_packet_received(
                self._process_dcerpc_packet(pkt)
            )
        return super(DceRpcSession, self).on_packet_received(pkt)


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
        print("DCE/RPC payload class not found or undefined (using Raw)")
        return Raw

    @classmethod
    def register_possible_payload(cls, pay):
        """Method to call from possible DCE/RPC endpoint to register it as
        possible payload"""
        cls._payload_class.append(pay)


bind_layers(DceRpc4, DceRpc4Payload)
