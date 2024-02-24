# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Very partial RPC definitions for the following interfaces:
- IObjectExporter (v0.0): 99fcfec4-5260-101b-bbcb-00aa0021347a
"""


import uuid

from scapy.fields import StrFixedLenField
from scapy.layers.dcerpc import (
    NDRPacket,
    DceRpcOp,
    NDRConfPacketListField,
    NDRConfStrLenField,
    NDRConfStrLenFieldUtf16,
    NDRFullPointerField,
    NDRIntField,
    NDRPacketField,
    NDRShortField,
    register_dcerpc_interface,
)


# Basic ORPC structures


class COMVERSION(NDRPacket):
    ALIGNMENT = (2, 2)
    fields_desc = [NDRShortField("MajorVersion", 0), NDRShortField("MinorVersion", 0)]


class GUID(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRIntField("Data1", 0),
        NDRShortField("Data2", 0),
        NDRShortField("Data3", 0),
        StrFixedLenField("Data4", "", length=8),
    ]


class ORPC_EXTENT(NDRPacket):
    ALIGNMENT = (4, 8)
    DEPORTED_CONFORMANTS = ["data"]
    fields_desc = [
        NDRPacketField("id", GUID(), GUID),
        NDRIntField("size", 0),
        NDRConfStrLenField(
            "data",
            "",
            size_is=lambda pkt: ((pkt.size + 7) & (~7)),
            conformant_in_struct=True,
        ),
    ]


class ORPC_EXTENT_ARRAY(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("size", 0),
        NDRIntField("reserved", 0),
        NDRFullPointerField(
            NDRConfPacketListField(
                "extent",
                [ORPC_EXTENT()],
                ORPC_EXTENT,
                size_is=lambda pkt: ((pkt.size + 1) & (~1)),
            ),
            deferred=True,
        ),
    ]


class ORPCTHIS(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRPacketField("version", COMVERSION(), COMVERSION),
        NDRIntField("flags", 0),
        NDRIntField("reserved1", 0),
        NDRPacketField("cid", GUID(), GUID),
        NDRFullPointerField(
            NDRPacketField("extensions", ORPC_EXTENT_ARRAY(), ORPC_EXTENT_ARRAY),
            deferred=True,
        ),
    ]


class MInterfacePointer(NDRPacket):
    ALIGNMENT = (4, 8)
    DEPORTED_CONFORMANTS = ["abData"]
    fields_desc = [
        NDRIntField("ulCntData", None, size_of="abData"),
        NDRConfStrLenField(
            "abData", "", size_is=lambda pkt: pkt.ulCntData, conformant_in_struct=True
        ),
    ]


class ORPCTHAT(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("flags", 0),
        NDRFullPointerField(
            NDRPacketField("extensions", ORPC_EXTENT_ARRAY(), ORPC_EXTENT_ARRAY),
            deferred=True,
        ),
    ]


class DUALSTRINGARRAY(NDRPacket):
    ALIGNMENT = (4, 8)
    DEPORTED_CONFORMANTS = ["aStringArray"]
    fields_desc = [
        NDRShortField("wNumEntries", None, size_of="aStringArray"),
        NDRShortField("wSecurityOffset", 0),
        NDRConfStrLenFieldUtf16(
            "aStringArray",
            "",
            size_is=lambda pkt: pkt.wNumEntries,
            conformant_in_struct=True,
        ),
    ]


# A few RPCs


class ServerAlive_Request(NDRPacket):
    fields_desc = []


class ServerAlive_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class ServerAlive2_Request(NDRPacket):
    fields_desc = []


class ServerAlive2_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("pComVersion", COMVERSION(), COMVERSION),
        NDRFullPointerField(
            NDRPacketField("ppdsaOrBindings", DUALSTRINGARRAY(), DUALSTRINGARRAY)
        ),
        NDRIntField("pReserved", 0),
        NDRIntField("status", 0),
    ]


IOBJECTEXPORTER_OPNUMS = {
    3: DceRpcOp(ServerAlive_Request, ServerAlive_Response),
    5: DceRpcOp(ServerAlive2_Request, ServerAlive2_Response),
}
register_dcerpc_interface(
    name="IObjectExporter",
    uuid=uuid.UUID("99fcfec4-5260-101b-bbcb-00aa0021347a"),
    version="0.0",
    opnums=IOBJECTEXPORTER_OPNUMS,
)
