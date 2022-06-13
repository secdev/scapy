# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) 2016 Gauthier Sebaux
#               2022 Gabriel Potter

# scapy.contrib.description = DCE/RPC
# scapy.contrib.status = loads

"""
DCE/RPC
Distributed Computing Environment / Remote Procedure Calls

Based on [C706] - DCE/RPC 1.1
https://pubs.opengroup.org/onlinepubs/9629399/toc.pdf
"""

from uuid import UUID
from scapy.config import conf
from scapy.layers.gssapi import GSSAPI_BLOB
from scapy.packet import Packet, Raw, bind_bottom_up, bind_layers
from scapy.fields import (
    BitEnumField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    FieldLenField,
    FlagsField,
    IntField,
    LenField,
    MultipleTypeField,
    PacketLenField,
    PadField,
    ReversePadField,
    ShortEnumField,
    ShortField,
    StrFixedLenField,
    StrLenField,
    TrailerField,
    UUIDEnumField,
    UUIDField,
    XByteField,
    XLEIntField,
    XShortField,
)
from scapy.layers.inet import TCP

from scapy.contrib.rtps.common_types import (
    EField,
    EPacket,
    EPacketField,
    EPacketListField,
)


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
_DCE_RPC_4_FLAGS1 = ["reserved_01", "last_frag", "frag", "no_frag_ack",
                     "maybe", "idempotent", "broadcast", "reserved_7"]
_DCE_RPC_4_FLAGS2 = ["reserved_0", "cancel_pending", "reserved_2",
                     "reserved_3", "reserved_4", "reserved_5", "reserved_6",
                     "reserved_7"]


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
    BitEnumField("endian", 0, 4, ["big", "little"]),
    BitEnumField("encoding", 0, 4, ["ASCII", "EBCDIC"]),
    ByteEnumField("float", 0, ["IEEE", "VAX", "CRAY", "IBM"]),
    ByteField("reserved1", 0),
]


class DceRpc4(Packet):
    """
    DCE/RPC v4 'connection-less' packet
    """
    name = "DCE/RPC v4"
    fields_desc = [
        ByteEnumField("rpc_vers", 4, {4: "4 (connection-less)",
                                      5: "5 (connection-oriented)"}),
        ByteEnumField("ptype", 0, DCE_RPC_TYPE),
        FlagsField("flags1", 0, 8, _DCE_RPC_4_FLAGS1),
        FlagsField("flags2", 0, 8, _DCE_RPC_4_FLAGS2),
    ] + _drep + [
        XByteField("serial_hi", 0),
        _EField(UUIDField("object", None)),
        _EField(UUIDField("if_id", None)),
        _EField(UUIDField("act_id", None)),
        _EField(IntField("server_boot", 0)),
        _EField(IntField("if_vers", 1)),
        _EField(IntField("seqnum", 0)),
        _EField(ShortField("opnum", 0)),
        _EField(XShortField("ihint", 0xffff)),
        _EField(XShortField("ahint", 0xffff)),
        _EField(LenField("len", None, fmt="H")),
        _EField(ShortField("fragnum", 0)),
        ByteEnumField("auth_proto", 0, ["none", "OSF DCE Private Key"]),
        XByteField("serial_lo", 0),
    ]


# sect 13.2.6.1

class CommonAuthVerifier(Packet):
    name = "Common Authentication Verifier (auth_verifier_co_t)"
    fields_desc = [
        ReversePadField(ByteEnumField("auth_type", 0, {
            9: "SPNEGO",
        }), align=4),
        ByteField("auth_level", 0),
        ByteField("auth_pad_length", 0),
        ByteField("auth_reserved", 0),
        XLEIntField("auth_context_id", 0),
        MultipleTypeField([
            (PacketLenField("auth_value", GSSAPI_BLOB(), GSSAPI_BLOB,
                            length_from=lambda pkt: pkt.parent.auth_len),
             lambda pkt: pkt.auth_type == 9)
        ],
            PacketLenField("auth_value", None, conf.raw_layer,
                           length_from=lambda pkt: pkt.parent.auth_len)
        )
    ]

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
    fields_desc = [
        ByteEnumField("rpc_vers", 5, {4: "4 (connection-less)",
                                      5: "5 (connection-oriented)"}),
        ByteField("rpc_vers_minor", 1),
        ByteEnumField("ptype", 0, DCE_RPC_TYPE),
        FlagsField("pfc_flags", 0, 8, _DCE_RPC_5_FLAGS),
    ] + _drep + [
        ByteField("reserved2", 0),
        _EField(LenField("frag_len", None, fmt="H")),
        _EField(LenField("auth_len", None, fmt="H")),
        _EField(IntField("call_id", None)),
        ConditionalField(
            TrailerField(
                PacketLenField("auth_verifier", None, CommonAuthVerifier,
                               length_from=lambda pkt: pkt.auth_len + 8)
            ),
            lambda pkt: pkt.auth_len
        )
    ]


# sec 12.6.3.1

class DceRpc5Syntax(EPacket):
    name = "Presentation Syntax (p_syntax_id_t)"
    fields_desc = [
        _EField(UUIDEnumField("if_uuid", None, {
            UUID("4b324fc8-1670-01d3-1278-5a47bf6ee188"): "SRVSVC",
            UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"): "NDR 2.0",
            UUID("71710533-beba-4937-8319-b5dbef9ccc36"): "NDR64",
        })),
        _EField(ShortField("if_version", 3)),
        _EField(ShortField("if_version_minor", 0)),
    ]


class DceRpc5Context(EPacket):
    name = "Presentation Context (p_cont_elem_t)"
    fields_desc = [
        _EField(ShortField("context_id", 0)),
        FieldLenField("n_transfer_syn", None,
                      length_of="transfer_syntaxes", fmt="B"),
        ByteField("reserved", 0),
        EPacketField("abstract_syntax", None, DceRpc5Syntax),
        EPacketListField("transfer_syntaxes", None, DceRpc5Syntax,
                         count_from=lambda pkt: pkt.n_transfer_syn,
                         endianness_from=_dce_rpc_endianess),
    ]


class DceRpc5Result(EPacket):
    name = "Context negotiation Result"
    fields_desc = [
        _EField(ShortEnumField("result", 0,
                               ["acceptance",
                                "user_rejection",
                                "provider_rejection"])),
        _EField(ShortEnumField("reason", 0,
                               ["reason_not_specified",
                                "abstract_syntax_not_supported",
                                "proposed_transfer_syntaxes_not_supported",
                                "local_limit_exceeded"])),
        EPacketField("transfer_syntax", None, DceRpc5Syntax),
    ]


class DceRpc5PortAny(EPacket):
    name = "Port Any (port_any_t)"
    fields_desc = [
        _EField(FieldLenField("length", None,
                              length_of="port_spec", fmt="H")),
        _EField(StrLenField("port_spec", b"",
                            length_from=lambda pkt: pkt.length)),
    ]

# sec 12.6.4.1


class DceRpc5AlterContext(_DceRpcPayload):
    name = "DCE/RPC v5 - AlterContext"
    fields_desc = [
        _EField(ShortField("max_xmit_frag", 0)),
        _EField(ShortField("max_recv_frag", 0)),
        _EField(IntField("assoc_group_id", 0)),
        # p_result_list_t
        _EField(FieldLenField("n_results",
                None, length_of="results", fmt="B")),
        StrFixedLenField("reserved", 0, length=3),
        EPacketListField("results", [], DceRpc5Result,
                         endianness_from=_dce_rpc_endianess),
    ]


bind_layers(DceRpc5, DceRpc5AlterContext, ptype=14)


# sec 12.6.4.2


class DceRpc5AlterContextResp(_DceRpcPayload):
    name = "DCE/RPC v5 - AlterContextResp"
    fields_desc = [
        _EField(ShortField("max_xmit_frag", 0)),
        _EField(ShortField("max_recv_frag", 0)),
        _EField(IntField("assoc_group_id", 0)),
        PadField(
            EPacketField("sec_addr", None, DceRpc5PortAny),
            align=4,
        ),
        # p_result_list_t
        _EField(FieldLenField("n_results",
                None, length_of="results", fmt="B")),
        StrFixedLenField("reserved", 0, length=3),
        EPacketListField("results", [], DceRpc5Result,
                         endianness_from=_dce_rpc_endianess),
    ]


bind_layers(DceRpc5, DceRpc5AlterContextResp, ptype=15)

# sec 12.6.4.3


class DceRpc5Bind(_DceRpcPayload):
    name = "DCE/RPC v5 - Bind"
    fields_desc = [
        _EField(ShortField("max_xmit_frag", 0)),
        _EField(ShortField("max_recv_frag", 0)),
        _EField(IntField("assoc_group_id", 0)),
        # p_cont_list_t
        _EField(FieldLenField("n_context_elem",
                None, length_of="context_elem", fmt="B")),
        StrFixedLenField("reserved", 0, length=3),
        EPacketListField("context_elem", [], DceRpc5Context,
                         endianness_from=_dce_rpc_endianess,
                         count_from=lambda pkt: pkt.n_context_elem),
    ]


bind_layers(DceRpc5, DceRpc5Bind, ptype=11)

# sec 12.6.4.4


class DceRpc5BindAck(_DceRpcPayload):
    name = "DCE/RPC v5 - Bind Ack"
    fields_desc = [
        _EField(ShortField("max_xmit_frag", 0)),
        _EField(ShortField("max_recv_frag", 0)),
        _EField(IntField("assoc_group_id", 0)),
        PadField(
            EPacketField("sec_addr", None, DceRpc5PortAny),
            align=4,
        ),
        # p_result_list_t
        _EField(FieldLenField("n_results",
                None, length_of="results", fmt="B")),
        StrFixedLenField("reserved", 0, length=3),
        EPacketListField("results", [], DceRpc5Result,
                         endianness_from=_dce_rpc_endianess),
    ]


bind_layers(DceRpc5, DceRpc5BindAck, ptype=12)

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
            lambda pkt: pkt.underlayer.pfc_flags.OBJECT_UUID
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
        PadField(
            ByteField("reserved", 0),
            align=8,
        ),
    ]


bind_layers(DceRpc5, DceRpc5Response, ptype=2)

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


class DceRpcPayload(Packet):
    """Dummy class which use the dispatch_hook to find the payload class"""
    _payload_class = []

    @classmethod
    def dispatch_hook(cls, _pkt, _underlayer=None, *args, **kargs):
        """dispatch_hook to choose among different registered payloads"""
        for klass in cls._payload_class:
            if hasattr(klass, "can_handle") and \
                    klass.can_handle(_pkt, _underlayer):
                return klass
        print("DCE/RPC payload class not found or undefined (using Raw)")
        return Raw

    @classmethod
    def register_possible_payload(cls, pay):
        """Method to call from possible DCE/RPC endpoint to register it as
        possible payload"""
        cls._payload_class.append(pay)


bind_layers(DceRpc4, DceRpcPayload)
