# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Very partial RPC definitions for the following interfaces:
- drsuapi (v4.0): e3514235-4b06-11d1-ab04-00c04fc2dcd2
"""

from enum import IntEnum
import uuid

from scapy.fields import StrFixedLenField
from scapy.layers.dcerpc import (
    NDRPacket,
    DceRpcOp,
    NDRByteField,
    NDRConfFieldListField,
    NDRConfPacketListField,
    NDRConfStrLenField,
    NDRConfStrLenFieldUtf16,
    NDRConfVarFieldListField,
    NDRConfVarStrNullField,
    NDRConfVarStrNullFieldUtf16,
    NDRContextHandle,
    NDRFullPointerField,
    NDRInt3264EnumField,
    NDRIntField,
    NDRLongField,
    NDRPacketField,
    NDRRecursiveField,
    NDRRefEmbPointerField,
    NDRShortField,
    NDRSignedByteField,
    NDRSignedIntField,
    NDRSignedLongField,
    NDRUnionField,
    NDRVarStrLenField,
    NDRVarStrLenFieldUtf16,
    register_dcerpc_interface,
)


class UUID(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRIntField("Data1", 0),
        NDRShortField("Data2", 0),
        NDRShortField("Data3", 0),
        StrFixedLenField("Data4", "", length=8),
    ]


class DRS_EXTENSIONS(NDRPacket):
    ALIGNMENT = (4, 8)
    DEPORTED_CONFORMANTS = ["rgb"]
    fields_desc = [
        NDRIntField("cb", None, size_of="rgb"),
        NDRConfStrLenField(
            "rgb", "", size_is=lambda pkt: pkt.cb, conformant_in_struct=True
        ),
    ]


class IDL_DRSBind_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRPacketField("puuidClientDsa", UUID(), UUID)),
        NDRFullPointerField(
            NDRPacketField("pextClient", DRS_EXTENSIONS(), DRS_EXTENSIONS)
        ),
    ]


class IDL_DRSBind_Response(NDRPacket):
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField("ppextServer", DRS_EXTENSIONS(), DRS_EXTENSIONS)
        ),
        NDRPacketField("phDrs", NDRContextHandle(), NDRContextHandle),
        NDRIntField("status", 0),
    ]


class IDL_DRSUnbind_Request(NDRPacket):
    fields_desc = [NDRPacketField("phDrs", NDRContextHandle(), NDRContextHandle)]


class IDL_DRSUnbind_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("phDrs", NDRContextHandle(), NDRContextHandle),
        NDRIntField("status", 0),
    ]


class DRS_MSG_CRACKREQ_V1(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("CodePage", 0),
        NDRIntField("LocaleId", 0),
        NDRIntField("dwFlags", 0),
        NDRIntField("formatOffered", 0),
        NDRIntField("formatDesired", 0),
        NDRIntField("cNames", None, size_of="rpNames"),
        NDRFullPointerField(
            NDRConfFieldListField(
                "rpNames",
                [],
                NDRFullPointerField(
                    NDRConfVarStrNullFieldUtf16("rpNames", ""), deferred=True
                ),
                size_is=lambda pkt: pkt.cNames,
            ),
            deferred=True,
        ),
    ]


class PDS_NAME_RESULT_ITEMW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("status", 0),
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("pDomain", ""), deferred=True),
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("pName", ""), deferred=True),
    ]


class DS_NAME_RESULTW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("cItems", None, size_of="rItems"),
        NDRFullPointerField(
            NDRConfPacketListField(
                "rItems",
                [PDS_NAME_RESULT_ITEMW()],
                PDS_NAME_RESULT_ITEMW,
                size_is=lambda pkt: pkt.cItems,
            ),
            deferred=True,
        ),
    ]


class DRS_MSG_CRACKREPLY_V1(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField("pResult", DS_NAME_RESULTW(), DS_NAME_RESULTW), deferred=True
        )
    ]


class IDL_DRSCrackNames_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("hDrs", NDRContextHandle(), NDRContextHandle),
        NDRIntField("dwInVersion", 0),
        NDRUnionField(
            [
                (
                    NDRPacketField(
                        "pmsgIn", DRS_MSG_CRACKREQ_V1(), DRS_MSG_CRACKREQ_V1
                    ),
                    (
                        (lambda pkt: getattr(pkt, "dwInVersion", None) == 1),
                        (lambda _, val: val.tag == 1),
                    ),
                )
            ],
            StrFixedLenField("pmsgIn", "", length=0),
            align=(4, 8),
            switch_fmt=("L", "L"),
        ),
    ]


class IDL_DRSCrackNames_Response(NDRPacket):
    fields_desc = [
        NDRIntField("pdwOutVersion", 0),
        NDRUnionField(
            [
                (
                    NDRPacketField(
                        "pmsgOut", DRS_MSG_CRACKREPLY_V1(), DRS_MSG_CRACKREPLY_V1
                    ),
                    (
                        (lambda pkt: getattr(pkt, "pdwOutVersion", None) == 1),
                        (lambda _, val: val.tag == 1),
                    ),
                )
            ],
            StrFixedLenField("pmsgOut", "", length=0),
            align=(4, 8),
            switch_fmt=("L", "L"),
        ),
        NDRIntField("status", 0),
    ]


DRSUAPI_OPNUMS = {
    0: DceRpcOp(IDL_DRSBind_Request, IDL_DRSBind_Response),
    1: DceRpcOp(IDL_DRSUnbind_Request, IDL_DRSUnbind_Response),
    12: DceRpcOp(IDL_DRSCrackNames_Request, IDL_DRSCrackNames_Response),
}
register_dcerpc_interface(
    name="drsuapi",
    uuid=uuid.UUID("e3514235-4b06-11d1-ab04-00c04fc2dcd2"),
    version="4.0",
    opnums=DRSUAPI_OPNUMS,
)
