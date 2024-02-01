# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Very partial RPC definitions for the following interfaces:
- samr (v1.0): 12345778-1234-abcd-ef00-0123456789ac
"""

import uuid

from scapy.layers.dcerpc import (
    NDRPacket,
    DceRpcOp,
    NDRConfPacketListField,
    NDRConfVarStrLenFieldUtf16,
    NDRContextHandle,
    NDRFullPointerField,
    NDRIntField,
    NDRPacketField,
    NDRShortField,
    register_dcerpc_interface,
)


class SamrConnect_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRShortField("ServerName", 0)),
        NDRIntField("DesiredAccess", 0),
    ]


class SamrConnect_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("ServerHandle", NDRContextHandle(), NDRContextHandle),
        NDRIntField("status", 0),
    ]


class RPC_UNICODE_STRING(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRShortField("Length", None, size_of="Buffer", adjust=lambda _, x: (x * 2)),
        NDRShortField(
            "MaximumLength", None, size_of="Buffer", adjust=lambda _, x: (x * 2)
        ),
        NDRFullPointerField(
            NDRConfVarStrLenFieldUtf16(
                "Buffer",
                "",
                size_is=lambda pkt: (pkt.MaximumLength // 2),
                length_is=lambda pkt: (pkt.Length // 2),
            ),
            deferred=True,
        ),
    ]


class PSAMPR_RID_ENUMERATION(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("RelativeId", 0),
        NDRPacketField("Name", RPC_UNICODE_STRING(), RPC_UNICODE_STRING),
    ]


class PSAMPR_ENUMERATION_BUFFER(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("EntriesRead", None, size_of="Buffer"),
        NDRFullPointerField(
            NDRConfPacketListField(
                "Buffer",
                [PSAMPR_RID_ENUMERATION()],
                PSAMPR_RID_ENUMERATION,
                size_is=lambda pkt: pkt.EntriesRead,
            ),
            deferred=True,
        ),
    ]


class SamrEnumerateDomainsInSamServer_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("ServerHandle", NDRContextHandle(), NDRContextHandle),
        NDRIntField("EnumerationContext", 0),
        NDRIntField("PreferedMaximumLength", 0),
    ]


class SamrEnumerateDomainsInSamServer_Response(NDRPacket):
    fields_desc = [
        NDRIntField("EnumerationContext", 0),
        NDRFullPointerField(
            NDRPacketField(
                "Buffer", PSAMPR_ENUMERATION_BUFFER(), PSAMPR_ENUMERATION_BUFFER
            )
        ),
        NDRIntField("CountReturned", 0),
        NDRIntField("status", 0),
    ]


SAMR_OPNUMS = {
    0: DceRpcOp(SamrConnect_Request, SamrConnect_Response),
    6: DceRpcOp(
        SamrEnumerateDomainsInSamServer_Request,
        SamrEnumerateDomainsInSamServer_Response,
    ),
}
register_dcerpc_interface(
    name="samr",
    uuid=uuid.UUID("12345778-1234-ABCD-EF00-0123456789AC"),
    version="1.0",
    opnums=SAMR_OPNUMS,
)
