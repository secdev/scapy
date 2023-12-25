# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Very partial RPC definitions for the following interfaces:
- srvsvc (v3.0): 4B324FC8-1670-01D3-1278-5A47BF6EE188
"""

import uuid

from scapy.fields import StrFixedLenField
from scapy.layers.dcerpc import (
    register_dcerpc_interface,
    DceRpcOp,
    NDRConfPacketListField,
    NDRConfVarStrNullFieldUtf16,
    NDRFullPointerField,
    NDRIntField,
    NDRPacket,
    NDRPacketField,
    NDRUnionField,
)


class LPSHARE_INFO_1(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullPointerField(
            NDRConfVarStrNullFieldUtf16("shi1_netname", ""), deferred=True
        ),
        NDRIntField("shi1_type", 0),
        NDRFullPointerField(
            NDRConfVarStrNullFieldUtf16("shi1_remark", ""), deferred=True
        ),
    ]


class SHARE_INFO_1_CONTAINER(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("EntriesRead", None, size_of="Buffer"),
        NDRFullPointerField(
            NDRConfPacketListField(
                "Buffer",
                [LPSHARE_INFO_1()],
                LPSHARE_INFO_1,
                count_from=lambda pkt: pkt.EntriesRead,
            ),
            deferred=True,
        ),
    ]


class LPSHARE_ENUM_STRUCT(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("Level", 0),
        NDRUnionField(
            [
                (
                    NDRFullPointerField(
                        NDRPacketField(
                            "ShareInfo",
                            SHARE_INFO_1_CONTAINER(),
                            SHARE_INFO_1_CONTAINER,
                        ),
                        deferred=True,
                    ),
                    (
                        (lambda pkt: getattr(pkt, "Level", None) == 1),
                        (lambda _, val: val.tag == 1),
                    ),
                ),
            ],
            StrFixedLenField("ShareInfo", "", length=0),
            align=(4, 8),
            switch_fmt=("L", "L"),
        ),
    ]


class NetrShareEnum_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("ServerName", "")),
        NDRPacketField("InfoStruct", LPSHARE_ENUM_STRUCT(), LPSHARE_ENUM_STRUCT),
        NDRIntField("PreferedMaximumLength", 0),
        NDRFullPointerField(NDRIntField("ResumeHandle", 0)),
    ]


class NetrShareEnum_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("InfoStruct", LPSHARE_ENUM_STRUCT(), LPSHARE_ENUM_STRUCT),
        NDRIntField("TotalEntries", 0),
        NDRFullPointerField(NDRIntField("ResumeHandle", 0)),
        NDRIntField("status", 0),
    ]


class NetrShareGetInfo_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("ServerName", "")),
        NDRConfVarStrNullFieldUtf16("NetName", ""),
        NDRIntField("Level", 0),
    ]


class NetrShareGetInfo_Response(NDRPacket):
    fields_desc = [
        NDRUnionField(
            [
                (
                    NDRFullPointerField(
                        NDRPacketField("ShareInfo", LPSHARE_INFO_1(), LPSHARE_INFO_1)
                    ),
                    (
                        (lambda pkt: getattr(pkt, "Level", None) == 1),
                        (lambda _, val: val.tag == 1),
                    ),
                ),
            ],
            StrFixedLenField("ShareInfo", "", length=0),
            align=(4, 8),
            switch_fmt=("L", "L"),
        ),
        NDRIntField("status", 0),
    ]


class LPSERVER_INFO_101(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("sv101_platform_id", 0),
        NDRFullPointerField(
            NDRConfVarStrNullFieldUtf16("sv101_name", ""), deferred=True
        ),
        NDRIntField("sv101_version_major", 0),
        NDRIntField("sv101_version_minor", 0),
        NDRIntField("sv101_type", 0),
        NDRFullPointerField(
            NDRConfVarStrNullFieldUtf16("sv101_comment", ""), deferred=True
        ),
    ]


class NetrServerGetInfo_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("ServerName", "")),
        NDRIntField("Level", 0),
    ]


class NetrServerGetInfo_Response(NDRPacket):
    fields_desc = [
        NDRUnionField(
            [
                (
                    NDRFullPointerField(
                        NDRPacketField(
                            "ServerInfo", LPSERVER_INFO_101(), LPSERVER_INFO_101
                        )
                    ),
                    (
                        (lambda pkt: getattr(pkt, "Level", None) == 101),
                        (lambda _, val: val.tag == 101),
                    ),
                ),
            ],
            StrFixedLenField("ServerInfo", "", length=0),
            align=(4, 8),
            switch_fmt=("L", "L"),
        ),
        NDRIntField("status", 0),
    ]


SRVSVC_OPNUMS = {
    15: DceRpcOp(NetrShareEnum_Request, NetrShareEnum_Response),
    16: DceRpcOp(NetrShareGetInfo_Request, NetrShareGetInfo_Response),
    21: DceRpcOp(NetrServerGetInfo_Request, NetrServerGetInfo_Response),
}
register_dcerpc_interface(
    name="srvsvc",
    uuid=uuid.UUID("4B324FC8-1670-01D3-1278-5A47BF6EE188"),
    version="3.0",
    opnums=SRVSVC_OPNUMS,
)
