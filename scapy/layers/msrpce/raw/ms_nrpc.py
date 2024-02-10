# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Very partial RPC definitions for the following interfaces:
- logon (v1.0): 12345678-1234-ABCD-EF00-01234567CFFB
"""

from enum import IntEnum
import uuid

from scapy.fields import StrFixedLenField
from scapy.layers.dcerpc import (
    register_dcerpc_interface,
    DceRpcOp,
    NDRConfVarStrNullFieldUtf16,
    NDRFullPointerField,
    NDRInt3264EnumField,
    NDRIntField,
    NDRPacket,
    NDRPacketField,
)


class PNETLOGON_CREDENTIAL(NDRPacket):
    fields_desc = [StrFixedLenField("data", "", length=8)]


class PNETLOGON_AUTHENTICATOR(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRPacketField("Credential", PNETLOGON_CREDENTIAL(), PNETLOGON_CREDENTIAL),
        NDRIntField("Timestamp", 0),
    ]


class NetrServerReqChallenge_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("PrimaryName", "")),
        NDRConfVarStrNullFieldUtf16("ComputerName", ""),
        NDRPacketField("ClientChallenge", PNETLOGON_CREDENTIAL(), PNETLOGON_CREDENTIAL),
    ]


class NetrServerReqChallenge_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("ServerChallenge", PNETLOGON_CREDENTIAL(), PNETLOGON_CREDENTIAL),
        NDRIntField("status", 0),
    ]


class NETLOGON_SECURE_CHANNEL_TYPE(IntEnum):
    NullSecureChannel = 0
    MsvApSecureChannel = 1
    WorkstationSecureChannel = 2
    TrustedDnsDomainSecureChannel = 3
    TrustedDomainSecureChannel = 4
    UasServerSecureChannel = 5
    ServerSecureChannel = 6
    CdcServerSecureChannel = 7


class NetrServerAuthenticate3_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("PrimaryName", "")),
        NDRConfVarStrNullFieldUtf16("AccountName", ""),
        NDRInt3264EnumField("SecureChannelType", 0, NETLOGON_SECURE_CHANNEL_TYPE),
        NDRConfVarStrNullFieldUtf16("ComputerName", ""),
        NDRPacketField(
            "ClientCredential", PNETLOGON_CREDENTIAL(), PNETLOGON_CREDENTIAL
        ),
        NDRIntField("NegotiateFlags", 0),
    ]


class NetrServerAuthenticate3_Response(NDRPacket):
    fields_desc = [
        NDRPacketField(
            "ServerCredential", PNETLOGON_CREDENTIAL(), PNETLOGON_CREDENTIAL
        ),
        NDRIntField("NegotiateFlags", 0),
        NDRIntField("AccountRid", 0),
        NDRIntField("status", 0),
    ]


LOGON_OPNUMS = {
    4: DceRpcOp(NetrServerReqChallenge_Request, NetrServerReqChallenge_Response),
    26: DceRpcOp(NetrServerAuthenticate3_Request, NetrServerAuthenticate3_Response),
}
register_dcerpc_interface(
    name="logon",
    uuid=uuid.UUID("12345678-1234-ABCD-EF00-01234567CFFB"),
    version="1.0",
    opnums=LOGON_OPNUMS,
)
