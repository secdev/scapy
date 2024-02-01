# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Very partial RPC definitions for the following interfaces:
- ept (v3.0): e1af8308-5d1f-11c9-91a4-08002b14a0fa
"""

import uuid

from scapy.fields import StrFixedLenField
from scapy.layers.dcerpc import (
    register_dcerpc_interface,
    DceRpcOp,
    NDRConfStrLenField,
    NDRConfVarPacketListField,
    NDRContextHandle,
    NDRFullPointerField,
    NDRIntField,
    NDRPacket,
    NDRPacketField,
    NDRShortField,
    NDRVarStrLenField,
)


class UUID(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRIntField("Data1", 0),
        NDRShortField("Data2", 0),
        NDRShortField("Data3", 0),
        StrFixedLenField("Data4", "", length=8),
    ]


class twr_p_t(NDRPacket):
    ALIGNMENT = (4, 8)
    DEPORTED_CONFORMANTS = ["tower_octet_string"]
    fields_desc = [
        NDRIntField("tower_length", None, size_of="tower_octet_string"),
        NDRConfStrLenField(
            "tower_octet_string",
            "",
            length_from=lambda pkt: pkt.tower_length,
            conformant_in_struct=True,
        ),
    ]


class ept_entry_t(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRPacketField("object", UUID(), UUID),
        NDRFullPointerField(NDRPacketField("tower", twr_p_t(), twr_p_t), deferred=True),
        NDRVarStrLenField("annotation", ""),
    ]


class RPC_IF_ID(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRPacketField("Uuid", UUID(), UUID),
        NDRShortField("VersMajor", 0),
        NDRShortField("VersMinor", 0),
    ]


class ept_lookup_Request(NDRPacket):
    fields_desc = [
        NDRIntField("inquiry_type", 0),
        NDRFullPointerField(NDRPacketField("object", UUID(), UUID)),
        NDRFullPointerField(NDRPacketField("Ifid", RPC_IF_ID(), RPC_IF_ID)),
        NDRIntField("vers_option", 0),
        NDRPacketField("entry_handle", NDRContextHandle(), NDRContextHandle),
        NDRIntField("max_ents", 0),
    ]


class ept_lookup_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("entry_handle", NDRContextHandle(), NDRContextHandle),
        NDRIntField("num_ents", None, size_of="entries"),
        NDRConfVarPacketListField(
            "entries",
            [],
            ept_entry_t,
            size_is=lambda pkt: pkt.max_ents,
            length_is=lambda pkt: pkt.num_ents,
        ),
        NDRIntField("status", 0),
    ]


class ept_map_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRPacketField("obj", UUID(), UUID)),
        NDRFullPointerField(NDRPacketField("map_tower", twr_p_t(), twr_p_t)),
        NDRPacketField("entry_handle", NDRContextHandle(), NDRContextHandle),
        NDRIntField("max_towers", 0),
    ]


class ept_map_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("entry_handle", NDRContextHandle(), NDRContextHandle),
        NDRIntField("num_towers", None, size_of="ITowers"),
        NDRConfVarPacketListField(
            "ITowers", [], twr_p_t, count_from=lambda pkt: pkt.num_towers, ptr_pack=True
        ),
        NDRIntField("status", 0),
    ]


EPT_OPNUMS = {
    2: DceRpcOp(ept_lookup_Request, ept_lookup_Response),
    3: DceRpcOp(ept_map_Request, ept_map_Response),
}
register_dcerpc_interface(
    name="ept",
    uuid=uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa"),
    version="3.0",
    opnums=EPT_OPNUMS,
)
