# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
[MS-DCOM]

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0
"""

import collections
import uuid

from scapy.config import conf
from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ConditionalField,
    LEIntField,
    LEShortEnumField,
    LEShortField,
    PacketField,
    PacketListField,
    StrNullFieldUtf16,
    UUIDField,
    XStrFixedLenField,
    XShortField,
)
from scapy.layers.dcerpc import (
    NDRFieldListField,
    NDRIntField,
    NDRLongField,
    NDRPacket,
    NDRPacketField,
    NDRFullPointerField,
    NDRConfPacketListField,
    NDRConfFieldListField,
    NDRConfStrLenFieldUtf16,
    NDRConfVarStrNullFieldUtf16,
    NDRShortField,
    NDRSignedIntField,
    NDRSerializeType1PacketField,
    NDRSerializeType1PacketListField,
    ndr_deserialize1,
    find_dcerpc_interface,
    RPC_C_AUTHN,
)
from scapy.layers.msrpce.rpcclient import DCERPC_Client, DCERPC_Transport

from scapy.layers.msrpce.raw.ms_dcom import (
    COMVERSION,
    GUID,
    ServerAlive2_Request,
    MInterfacePointer,
)


def _uid_to_bytes(x, ndrendian="little"):
    if ndrendian == "little":
        return uuid.UUID(x).bytes_le
    elif ndrendian == "big":
        return uuid.UUID(x).bytes
    else:
        raise ValueError("bad ndrendian")


def _uid_from_bytes(x, ndrendian="little"):
    if ndrendian == "little":
        return uuid.UUID(bytes_le=x)
    elif ndrendian == "big":
        return uuid.UUID(bytes=x)
    else:
        raise ValueError("bad ndrendian")


# [MS-DCOM] sect 1.9

CLSID_ActivationContextInfo = uuid.UUID("000001a5-0000-0000-c000-000000000046")
CLSID_ActivationPropertiesIn = uuid.UUID("00000338-0000-0000-c000-000000000046")
CLSID_ActivationPropertiesOut = uuid.UUID("00000339-0000-0000-c000-000000000046")
CLSID_CONTEXT_EXTENSION = uuid.UUID("00000334-0000-0000-c000-000000000046")
CLSID_ContextMarshaler = uuid.UUID("0000033b-0000-0000-c000-000000000046")
CLSID_ERROR_EXTENSION = uuid.UUID("0000031c-0000-0000-c000-000000000046")
CLSID_ErrorObject = uuid.UUID("0000031b-0000-0000-c000-000000000046")
CLSID_InstanceInfo = uuid.UUID("000001ad-0000-0000-c000-000000000046")
CLSID_InstantiationInfo = uuid.UUID("000001ab-0000-0000-c000-000000000046")
CLSID_PropsOutInfo = uuid.UUID("00000339-0000-0000-c000-000000000046")
CLSID_ScmReplyInfo = uuid.UUID("000001b6-0000-0000-c000-000000000046")
CLSID_ScmRequestInfo = uuid.UUID("000001aa-0000-0000-c000-000000000046")
CLSID_SecurityInfo = uuid.UUID("000001a6-0000-0000-c000-000000000046")
CLSID_ServerLocationInfo = uuid.UUID("000001a4-0000-0000-c000-000000000046")
CLSID_SpecialSystemProperties = uuid.UUID("000001b9-0000-0000-c000-000000000046")

# Some special non-interfaces UUIDs:

IID_IActivationPropertiesIn = uuid.UUID("000001A2-0000-0000-C000-000000000046")
IID_IActivationPropertiesOut = uuid.UUID("000001A3-0000-0000-C000-000000000046")
IID_IContext = uuid.UUID("000001c0-0000-0000-C000-000000000046")

# [MS-DCOM] 2.2.22.2.1


class InstantiationInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRPacketField("classId", GUID(), GUID),
        NDRIntField("classCtx", 0),
        NDRIntField("actvflags", 0),
        NDRSignedIntField("fIsSurrogate", 0),
        NDRIntField("cIID", 0),
        NDRIntField("instFlag", 0),
        NDRFullPointerField(
            NDRConfPacketListField(
                "pIID", [GUID()], GUID, count_from=lambda pkt: pkt.cIID
            ),
            deferred=True,
        ),
        NDRIntField("thisSize", 0),
        NDRPacketField("clientCOMVersion", COMVERSION(), COMVERSION),
    ]


# [MS-DCOM] 2.2.22.2.2


class SpecialPropertiesData(NDRPacket):
    ALIGNMENT = (8, 8)
    fields_desc = [
        NDRIntField("dwSessionId", 0),
        NDRSignedIntField("fRemoteThisSessionId", 0),
        NDRSignedIntField("fClientImpersonating", 0),
        NDRSignedIntField("fPartitionIDPresent", 0),
        NDRIntField("dwDefaultAuthnLvl", 0),
        NDRPacketField("guidPartition", GUID(), GUID),
        NDRIntField("dwPRTFlags", 0),
        NDRIntField("dwOrigClsctx", 0),
        NDRIntField("dwFlags", 0),
        NDRIntField("Reserved1", 0),
        NDRLongField("Reserved2", 0),
        NDRFieldListField("Reserved3", [], NDRIntField("", 0), count_from=lambda _: 5),
    ]


# [MS-DCOM] 2.2.22.2.3


class InstanceInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("fileName", ""), deferred=True),
        NDRIntField("mode", 0),
        NDRFullPointerField(
            NDRPacketField("ifdROT", MInterfacePointer(), MInterfacePointer),
            deferred=True,
        ),
        NDRFullPointerField(
            NDRPacketField("ifdStg", MInterfacePointer(), MInterfacePointer),
            deferred=True,
        ),
    ]


# [MS-DCOM] 2.2.22.2.4


class customREMOTE_REQUEST_SCM_INFO(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("ClientImpLevel", 0),
        NDRShortField("cRequestedProtseqs", 0),
        NDRFullPointerField(
            NDRConfStrLenFieldUtf16(
                "pRequestedProtseqs", "", length_from=lambda pkt: pkt.cRequestedProtseqs
            ),
            deferred=True,
        ),
    ]


class ScmRequestInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullPointerField(NDRIntField("pdwReserved", 0), deferred=True),
        NDRFullPointerField(
            NDRPacketField(
                "remoteRequest",
                customREMOTE_REQUEST_SCM_INFO(),
                customREMOTE_REQUEST_SCM_INFO,
            ),
            deferred=True,
        ),
    ]


# [MS-DCOM] 2.2.22.2.5


class ActivationContextInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRSignedIntField("clientOK", 0),
        NDRSignedIntField("bReserved1", 0),
        NDRIntField("dwReserved1", 0),
        NDRIntField("dwReserved2", 0),
        NDRFullPointerField(
            NDRPacketField("pIFDClientCtx", MInterfacePointer(), MInterfacePointer),
            deferred=True,
        ),
        NDRFullPointerField(
            NDRPacketField("pIFDPrototypeCtx", MInterfacePointer(), MInterfacePointer),
            deferred=True,
        ),
    ]


# [MS-DCOM] 2.2.22.2.6


class LocationInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullPointerField(
            NDRConfVarStrNullFieldUtf16("machineName", ""), deferred=True
        ),
        NDRIntField("processId", 0),
        NDRIntField("apartmentId", 0),
        NDRIntField("contextId", 0),
    ]


# [MS-DCOM] 2.2.22.2.7


class COSERVERINFO(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwReserved1", 0),
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("pwszName", ""), deferred=True),
        NDRFullPointerField(NDRIntField("pdwReserved", 0), deferred=True),
        NDRIntField("dwReserved2", 0),
    ]


class SecurityInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwAuthnFlags", 0),
        NDRFullPointerField(
            NDRPacketField("pServerInfo", COSERVERINFO(), COSERVERINFO), deferred=True
        ),
        NDRFullPointerField(NDRIntField("pdwReserved", 0), deferred=True),
    ]


# [MS-DCOM] 2.2.22.2.8


class DUALSTRINGARRAY(NDRPacket):
    ALIGNMENT = (4, 8)
    CONFORMANT_COUNT = 1
    fields_desc = [
        NDRShortField("wNumEntries", 0),
        NDRShortField("wSecurityOffset", 0),
        NDRConfStrLenFieldUtf16(
            "aStringArray", "", length_from=lambda pkt: pkt.wNumEntries
        ),
    ]


def _parseStringArray(self):
    """
    Process aStringArray
    """
    str_fld = PacketListField("", [], STRINGBINDING)
    sec_fld = PacketListField("", [], SECURITYBINDING)
    string = str_fld.getfield(self, self.aStringArray[: self.wSecurityOffset * 2])[1]
    secs = sec_fld.getfield(self, self.aStringArray[self.wSecurityOffset * 2 :])[1]
    return string, secs


class customREMOTE_REPLY_SCM_INFO(NDRPacket):
    ALIGNMENT = (8, 8)
    fields_desc = [
        NDRLongField("Oxid", 0),
        NDRFullPointerField(
            NDRPacketField("pdsaOxidBindings", DUALSTRINGARRAY(), DUALSTRINGARRAY),
            deferred=True,
        ),
        NDRPacketField("ipidRemUnknown", GUID(), GUID),
        NDRIntField("authnHint", 0),
        NDRPacketField("serverVersion", COMVERSION(), COMVERSION),
    ]


class ScmReplyInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullPointerField(NDRIntField("pdwReserved", 0), deferred=True),
        NDRFullPointerField(
            NDRPacketField(
                "remoteReply",
                customREMOTE_REPLY_SCM_INFO(),
                customREMOTE_REPLY_SCM_INFO,
            ),
            deferred=True,
        ),
    ]


# [MS-DCOM] 2.2.22.2.9


class PropsOutInfo(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("cIfs", 0),
        NDRFullPointerField(
            NDRConfPacketListField(
                "piid", [GUID()], GUID, count_from=lambda pkt: pkt.cIfs
            ),
            deferred=True,
        ),
        NDRFullPointerField(
            NDRConfFieldListField(
                "phresults",
                [],
                NDRSignedIntField("", 0),
                count_from=lambda pkt: pkt.cIfs,
            ),
            deferred=True,
        ),
        NDRFullPointerField(
            NDRConfPacketListField(
                "ppIntfData",
                [MInterfacePointer()],
                MInterfacePointer,
                count_from=lambda pkt: pkt.cIfs,
            ),
            deferred=True,
        ),
    ]


# [MS-DCOM] 2.2.22.1


class CustomHeader(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("totalSize", 0),
        NDRIntField("headerSize", 0),
        NDRIntField("dwReserved", 0),
        NDRIntField("destCtx", 0),
        NDRIntField("cIfs", 0),
        NDRPacketField("classInfoClsid", GUID(), GUID),
        NDRFullPointerField(
            NDRConfPacketListField(
                "pclsid", [GUID()], GUID, count_from=lambda pkt: pkt.cIfs
            ),
            deferred=True,
        ),
        NDRFullPointerField(
            NDRConfFieldListField(
                "pSizes", [], NDRIntField("", 0), count_from=lambda pkt: pkt.cIfs
            ),
            deferred=True,
        ),
        NDRFullPointerField(NDRIntField("pdwReserved", 0), deferred=True),
    ]


class _ActivationPropertiesField(NDRSerializeType1PacketListField):
    def __init__(self, *args, **kwargs):
        kwargs["next_cls_cb"] = self._get_cls_activation
        # kwargs["ptr"] = False
        super(_ActivationPropertiesField, self).__init__(*args, **kwargs)

    def _get_cls_activation(self, pkt, lst, cur, remain):
        pclsid = pkt.CustomHeader.data.pclsid.value.value
        ndrendian = pkt.CustomHeader.data.ndrendian
        i = len(lst) + int(bool(cur))
        if i >= len(pclsid):
            return
        next_uid = _uid_from_bytes(pclsid[i], ndrendian=ndrendian)
        # [MS-DCOM] 1.9
        cls = {
            CLSID_ActivationContextInfo: ActivationContextInfoData,
            CLSID_InstanceInfo: InstanceInfoData,
            CLSID_InstantiationInfo: InstantiationInfoData,
            CLSID_PropsOutInfo: PropsOutInfo,
            CLSID_ScmReplyInfo: ScmReplyInfoData,
            CLSID_ScmRequestInfo: ScmRequestInfoData,
            CLSID_SecurityInfo: SecurityInfoData,
            CLSID_ServerLocationInfo: LocationInfoData,
            CLSID_SpecialSystemProperties: SpecialPropertiesData,
        }[next_uid]
        return lambda x: ndr_deserialize1(x, cls, ndr64=False)


class ActivationPropertiesBlob(Packet):
    fields_desc = [
        LEIntField("dwSize", 0),
        LEIntField("dwReserved", 0),
        NDRSerializeType1PacketField("CustomHeader", CustomHeader(), CustomHeader),
        _ActivationPropertiesField("Property", []),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-DCOM] 2.2.18


class OBJREF(Packet):
    fields_desc = [
        XStrFixedLenField("signature", b"MEOW", length=4),  # :3
        LEIntField("flags", 0x04),
        XStrFixedLenField("iid", IID_IActivationPropertiesIn, length=16),
    ]


# [MS-DCOM] 2.2.18.6


class OBJREF_CUSTOM(Packet):
    fields_desc = [
        UUIDField("clsid", CLSID_ActivationPropertiesIn),
        LEIntField("cbExtension", 0),
        LEIntField("reserved", 0),
        PacketField(
            "pObjectData", ActivationPropertiesBlob(), ActivationPropertiesBlob
        ),
    ]


# [MS-DCOM] 2.2.19.3


class STRINGBINDING(Packet):
    fields_desc = [
        LEShortField("wTowerId", 0),
        StrNullFieldUtf16("aNetworkAddr", ""),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-DCOM] 2.2.19.4


class SECURITYBINDING(Packet):
    fields_desc = [
        LEShortEnumField("wAuthnSvc", 0, RPC_C_AUTHN),
        ConditionalField(XShortField("Reserved", 0xFFFF), lambda pkt: pkt.wAuthnSvc),
        ConditionalField(
            StrNullFieldUtf16("aPrincName", ""), lambda pkt: pkt.wAuthnSvc
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


bind_layers(OBJREF, OBJREF_CUSTOM, flags=4)


class DCOM_Client(DCERPC_Client):
    """
    A wrapper of DCERPC_Client that adds functions to use COM interfaces.

    In this client, the DCE/RPC is abstracted to allow to focus on the upper
    DCOM one. DCE/RPC interfaces are bound automatically and ORPCTHIS/ORPCTHAT
    automatically added/extracted.

    It also provides common handlers for the few [MS-DCOM] special interfaces.
    """

    def __init__(self, verb=True, **kwargs):
        super(DCOM_Client, self).__init__(
            DCERPC_Transport.NCACN_IP_TCP, ndr64=False, verb=verb, **kwargs
        )

    def connect(self, *args, **kwargs):
        kwargs.setdefault("port", 135)
        super(DCOM_Client, self).connect(*args, **kwargs)

    def ServerAlive2(self):
        """
        Call IObjectExporter::ServerAlive2
        """
        self.bind_or_alter(find_dcerpc_interface("IObjectExporter"))
        resp = self.sr1_req(ServerAlive2_Request(ndr64=False))
        binds, secs = _parseStringArray(resp.ppdsaOrBindings.value)
        DCOMResults = collections.namedtuple("DCOMResults", ["addresses", "ssps"])
        addresses = []
        ssps = []
        for b in binds:
            if b.wTowerId == 0:
                continue
            addresses.append(b.aNetworkAddr)
        for b in secs:
            ssps.append(
                "%s%s"
                % (
                    b.sprintf("%wAuthnSvc%"),
                    b.aPrincName and "%s/" % b.aPrincName or "",
                )
            )
        return DCOMResults(addresses, ssps)
