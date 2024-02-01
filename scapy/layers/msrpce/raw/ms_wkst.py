# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Very partial RPC definitions for the following interfaces:
- wkssvc (v1.0): 6BFFD098-A112-3610-9833-46C3F87E345A
"""

from enum import IntEnum
import uuid

from scapy.fields import StrFixedLenField
from scapy.layers.dcerpc import (
    register_dcerpc_interface,
    DceRpcOp,
    NDRConfPacketListField,
    NDRConfVarStrLenFieldUtf16,
    NDRConfVarStrNullFieldUtf16,
    NDRFullPointerField,
    NDRInt3264EnumField,
    NDRIntField,
    NDRPacket,
    NDRPacketField,
    NDRShortField,
    NDRUnionField,
)


class LPWKSTA_INFO_100(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("wki100_platform_id", 0),
        NDRFullPointerField(
            NDRConfVarStrNullFieldUtf16("wki100_computername", ""), deferred=True
        ),
        NDRFullPointerField(
            NDRConfVarStrNullFieldUtf16("wki100_langroup", ""), deferred=True
        ),
        NDRIntField("wki100_ver_major", 0),
        NDRIntField("wki100_ver_minor", 0),
    ]


class NetrWkstaGetInfo_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("ServerName", "")),
        NDRIntField("Level", 0),
    ]


class NetrWkstaGetInfo_Response(NDRPacket):
    fields_desc = [
        NDRUnionField(
            [
                (
                    NDRFullPointerField(
                        NDRPacketField(
                            "WkstaInfo", LPWKSTA_INFO_100(), LPWKSTA_INFO_100
                        )
                    ),
                    (
                        (lambda pkt: getattr(pkt, "Level", None) == 100),
                        (lambda _, val: val.tag == 100),
                    ),
                ),
            ],
            StrFixedLenField("WkstaInfo", "", length=0),
            align=(4, 8),
            switch_fmt=("L", "L"),
        ),
        NDRIntField("status", 0),
    ]


class NET_COMPUTER_NAME_TYPE(IntEnum):
    NetPrimaryComputerName = 0
    NetAlternateComputerNames = 1
    NetAllComputerNames = 2
    NetComputerNameTypeMax = 3


class PUNICODE_STRING(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRShortField("Length", None, size_of="Buffer", adjust=lambda _, x: (x * 2)),
        NDRShortField(
            "MaximumLength", None, size_of="Buffer", adjust=lambda _, x: (x * 2)
        ),
        NDRFullPointerField(
            NDRConfVarStrLenFieldUtf16(
                "Buffer", "", length_from=lambda pkt: (pkt.Length // 2)
            ),
            deferred=True,
        ),
    ]


class PNET_COMPUTER_NAME_ARRAY(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("EntryCount", None, size_of="ComputerNames"),
        NDRFullPointerField(
            NDRConfPacketListField(
                "ComputerNames",
                [PUNICODE_STRING()],
                PUNICODE_STRING,
                count_from=lambda pkt: pkt.EntryCount,
            ),
            deferred=True,
        ),
    ]


class NetrEnumerateComputerNames_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("ServerName", "")),
        NDRInt3264EnumField("NameType", 0, NET_COMPUTER_NAME_TYPE),
        NDRIntField("Reserved", 0),
    ]


class NetrEnumerateComputerNames_Response(NDRPacket):
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField(
                "ComputerNames", PNET_COMPUTER_NAME_ARRAY(), PNET_COMPUTER_NAME_ARRAY
            )
        ),
        NDRIntField("status", 0),
    ]


WKSSVC_OPNUMS = {
    0: DceRpcOp(NetrWkstaGetInfo_Request, NetrWkstaGetInfo_Response),
    30: DceRpcOp(
        NetrEnumerateComputerNames_Request, NetrEnumerateComputerNames_Response
    ),
}
register_dcerpc_interface(
    name="wkssvc",
    uuid=uuid.UUID("6BFFD098-A112-3610-9833-46C3F87E345A"),
    version="1.0",
    opnums=WKSSVC_OPNUMS,
)
