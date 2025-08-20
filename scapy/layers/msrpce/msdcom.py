# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
[MS-DCOM]

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0
"""

import enum
import hashlib
import re
import socket
import uuid

from scapy.config import conf
from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ConditionalField,
    FieldLenField,
    FlagsField,
    LEIntField,
    LELongField,
    LEShortEnumField,
    LEShortField,
    PacketField,
    PacketListField,
    PadField,
    StrLenField,
    StrNullFieldUtf16,
    UUIDField,
    XShortField,
    XStrFixedLenField,
)
from scapy.volatile import RandUUID

from scapy.layers.dcerpc import (
    ComInterface,
    DCE_C_AUTHN_LEVEL,
    DCE_RPC_PROTOCOL_IDENTIFIERS,
    DceRpc5Request,
    find_com_interface,
    find_dcerpc_interface,
    ndr_deserialize1,
    NDRConfFieldListField,
    NDRConfPacketListField,
    NDRConfVarStrNullFieldUtf16,
    NDRFieldListField,
    NDRFullEmbPointerField,
    NDRFullPointerField,
    NDRIntEnumField,
    NDRIntField,
    NDRLongField,
    NDRPacket,
    NDRPacketField,
    NDRSerializeType1PacketField,
    NDRSerializeType1PacketListField,
    NDRShortField,
    NDRSignedIntField,
    RPC_C_AUTHN,
)
from scapy.utils import valid_ip6, valid_ip
from scapy.layers.msrpce.rpcclient import DCERPC_Client, DCERPC_Transport

from scapy.layers.msrpce.raw.ms_dcom import (
    COMVERSION,
    DUALSTRINGARRAY,
    GUID,
    MInterfacePointer,
    ORPCTHAT,
    ORPCTHIS,
    REMINTERFACEREF,
    RemoteCreateInstance_Request,
    RemoteCreateInstance_Response,
    RemoteGetClassObject_Request,
    RemoteGetClassObject_Response,
    RemQueryInterface_Request,
    RemRelease_Request,
    ResolveOxid2_Request,
    ServerAlive2_Request,
    tagCPFLAGS,
)

# Typing
from typing import (
    Any,
    List,
    Dict,
    Optional,
    Tuple,
)


def _uid_to_bytes(x, ndrendian="little"):
    if ndrendian == "little":
        return x.bytes_le
    elif ndrendian == "big":
        return x.bytes
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


class ACTVFLAGS(enum.IntEnum):
    DISABLE_AAA = 0x00000002
    ACTIVATE_32_BIT_SERVER = 0x00000004
    ACTIVATE_64_BIT_SERVER = 0x00000008
    NO_FAILURE_LOG = 0x00000020


class InstantiationInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRPacketField("classId", GUID(), GUID),
        NDRIntField("classCtx", 0),
        NDRIntField("actvflags", 0),
        NDRSignedIntField("fIsSurrogate", 0),
        NDRIntField("cIID", None, size_of="pIID"),
        NDRIntField("instFlag", 0),
        NDRFullEmbPointerField(
            NDRConfPacketListField(
                "pIID", [GUID()], GUID, count_from=lambda pkt: pkt.cIID
            ),
        ),
        NDRIntField("thisSize", 0),
        NDRPacketField(
            "clientCOMVersion",
            COMVERSION(),
            COMVERSION,
        ),
    ]


# [MS-DCOM] 2.2.22.2.2


class SpecialPropertiesData(NDRPacket):
    ALIGNMENT = (8, 8)
    fields_desc = [
        NDRIntField("dwSessionId", 0xFFFFFFFF),
        NDRSignedIntField("fRemoteThisSessionId", 0),
        NDRSignedIntField("fClientImpersonating", 0),
        NDRSignedIntField("fPartitionIDPresent", 0),
        NDRIntField(
            "dwDefaultAuthnLvl", DCE_C_AUTHN_LEVEL.PKT_INTEGRITY
        ),  # Same than Windows
        NDRPacketField("guidPartition", GUID(), GUID),
        NDRIntField("dwPRTFlags", 0),
        NDRIntField("dwOrigClsctx", 0),
        NDRIntEnumField(
            "dwFlags",
            0,
            {
                0x00000001: "SPD_FLAG_USE_CONSOLE_SESSION",
            },
        ),
        NDRIntField("Reserved1", 0),
        NDRLongField("Reserved2", 0),
        NDRFieldListField(
            "Reserved3", [0, 0, 0, 0, 0], NDRIntField("", 0), count_from=lambda _: 5
        ),
    ]


# [MS-DCOM] 2.2.22.2.3


class InstanceInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("fileName", "")),
        NDRIntField("mode", 0),
        NDRFullEmbPointerField(
            NDRPacketField("ifdROT", MInterfacePointer(), MInterfacePointer),
        ),
        NDRFullEmbPointerField(
            NDRPacketField("ifdStg", MInterfacePointer(), MInterfacePointer),
        ),
    ]


# [MS-DCOM] 2.2.22.2.4


class customREMOTE_REQUEST_SCM_INFO(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("ClientImpLevel", 2),  # note <33>
        NDRShortField("cRequestedProtseqs", None, size_of="pRequestedProtseqs"),
        NDRFullEmbPointerField(
            NDRConfFieldListField(
                "pRequestedProtseqs",
                [],
                NDRShortField("", 0),
                size_is=lambda pkt: pkt.cRequestedProtseqs,
            ),
        ),
    ]


class ScmRequestInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullEmbPointerField(NDRIntField("pdwReserved", 0)),
        NDRFullEmbPointerField(
            NDRPacketField(
                "remoteRequest",
                customREMOTE_REQUEST_SCM_INFO(),
                customREMOTE_REQUEST_SCM_INFO,
            ),
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
        NDRFullEmbPointerField(
            NDRPacketField("pIFDClientCtx", MInterfacePointer(), MInterfacePointer),
        ),
        NDRFullEmbPointerField(
            NDRPacketField("pIFDPrototypeCtx", MInterfacePointer(), MInterfacePointer),
        ),
    ]


# [MS-DCOM] 2.2.22.2.6


class LocationInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("machineName", None),
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
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("pwszName", "")),
        NDRFullEmbPointerField(NDRIntField("pdwReserved", 0)),
        NDRIntField("dwReserved2", 0),
    ]


class SecurityInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwAuthnFlags", 0),
        NDRFullEmbPointerField(
            NDRPacketField("pServerInfo", COSERVERINFO(), COSERVERINFO),
        ),
        NDRFullPointerField(NDRIntField("pdwReserved", None)),
    ]


class customREMOTE_REPLY_SCM_INFO(NDRPacket):
    ALIGNMENT = (8, 8)
    fields_desc = [
        NDRLongField("Oxid", 0),
        NDRFullEmbPointerField(
            NDRPacketField("pdsaOxidBindings", DUALSTRINGARRAY(), DUALSTRINGARRAY),
        ),
        NDRPacketField("ipidRemUnknown", GUID(), GUID),
        NDRIntField("authnHint", 0),
        NDRPacketField("serverVersion", COMVERSION(), COMVERSION),
    ]


class ScmReplyInfoData(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullEmbPointerField(NDRIntField("pdwReserved", 0)),
        NDRFullEmbPointerField(
            NDRPacketField(
                "remoteReply",
                customREMOTE_REPLY_SCM_INFO(),
                customREMOTE_REPLY_SCM_INFO,
            ),
        ),
    ]


# [MS-DCOM] 2.2.22.2.9


class PropsOutInfo(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("cIfs", None, size_of="ppIntfData"),
        NDRFullEmbPointerField(
            NDRConfPacketListField("piid", [], GUID, size_is=lambda pkt: pkt.cIfs)
        ),
        NDRFullEmbPointerField(
            NDRConfFieldListField(
                "phresults",
                [],
                NDRSignedIntField("phresults", 0),
                size_is=lambda pkt: pkt.cIfs,
            )
        ),
        NDRFullEmbPointerField(
            NDRConfPacketListField(
                "ppIntfData",
                [],
                MInterfacePointer,
                size_is=lambda pkt: pkt.cIfs,
                ptr_pack=True,
            )
        ),
    ]


# [MS-DCOM] 2.2.22.1


class CustomHeader(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("totalSize", 0),
        NDRIntField("headerSize", 0),
        NDRIntField("dwReserved", 0),
        NDRIntEnumField("destCtx", 2, {2: "MSHCTX_DIFFERENTMACHINE"}),
        NDRIntField("cIfs", None, size_of="pSizes"),
        NDRPacketField("classInfoClsid", GUID(), GUID),
        NDRFullEmbPointerField(
            NDRConfPacketListField(
                "pclsid", [GUID()], GUID, count_from=lambda pkt: pkt.cIfs
            ),
        ),
        NDRFullEmbPointerField(
            NDRConfFieldListField(
                "pSizes", None, NDRIntField("", 0), count_from=lambda pkt: pkt.cIfs
            ),
        ),
        NDRFullEmbPointerField(NDRIntField("pdwReserved", None)),
    ]


class _ActivationPropertiesField(NDRSerializeType1PacketListField):
    def __init__(self, *args, **kwargs):
        kwargs["next_cls_cb"] = self._get_cls_activation
        super(_ActivationPropertiesField, self).__init__(*args, **kwargs)

    def _get_cls_activation(self, pkt, lst, cur, remain):
        # Get all the pcslsid
        pclsid = pkt.CustomHeader[CustomHeader].valueof("pclsid")
        ndrendian = pkt.CustomHeader[CustomHeader].ndrendian
        i = len(lst) + int(bool(cur))
        if i >= len(pclsid):
            return
        # Get the next pclsid we need to process
        next_uid = _uid_from_bytes(bytes(pclsid[i]), ndrendian=ndrendian)
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
        return lambda x: ndr_deserialize1(x, cls)


class ActivationPropertiesBlob(Packet):
    fields_desc = [
        FieldLenField(
            "dwSize",
            None,
            fmt="<I",
            length_of="CustomHeader",
            adjust=lambda pkt, x: x
            + pkt.get_field("Property").i2len(pkt, pkt.Property),
        ),
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
        UUIDField("iid", IID_IActivationPropertiesIn, uuid_fmt=UUIDField.FORMAT_LE),
    ]


# [MS-DCOM] 2.2.18.2


class STDOBJREF(Packet):
    fields_desc = [
        FlagsField(
            "flags",
            0,
            -32,
            {
                0x00001000: "SORF_NOPING",
            },
        ),
        LEIntField("cPublicRefs", 0),
        LELongField("oxid", 0),
        LELongField("oid", 0),
        UUIDField("ipid", None, uuid_fmt=UUIDField.FORMAT_LE),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-DCOM] 2.2.18.4


class OBJREF_STANDARD(Packet):
    fields_desc = [
        PacketField("std", STDOBJREF(), STDOBJREF),
        PacketField("saResAddr", DUALSTRINGARRAY(), DUALSTRINGARRAY),
    ]


bind_layers(OBJREF, OBJREF_STANDARD, flags=1)


# [MS-DCOM] 2.2.18.5


class OBJREF_HANDLER(Packet):
    fields_desc = [
        PacketField("std", STDOBJREF(), STDOBJREF),
        UUIDField("clsid", None, uuid_fmt=UUIDField.FORMAT_LE),
        PacketField("saResAddr", DUALSTRINGARRAY(), DUALSTRINGARRAY),
    ]


bind_layers(OBJREF, OBJREF_HANDLER, flags=2)

# [MS-DCOM] 2.2.18.6


class _pObjectDataField(PacketField):
    def m2i(self, pkt, s):
        if pkt.clsid in [CLSID_ActivationPropertiesIn, CLSID_ActivationPropertiesOut]:
            return ActivationPropertiesBlob(s, _parent=pkt)
        elif pkt.clsid == CLSID_ContextMarshaler:
            return Context(s, _parent=pkt)
        return conf.raw_layer(s, _parent=pkt)


class OBJREF_CUSTOM(Packet):
    fields_desc = [
        UUIDField("clsid", CLSID_ActivationPropertiesIn, uuid_fmt=UUIDField.FORMAT_LE),
        LEIntField("cbExtension", 0),
        # The following field is called "reserved" in the spec, but is the size
        # in practice :P
        FieldLenField(
            "reserved",
            None,
            length_of="pObjectData",
            adjust=lambda _, x: x + 8,
            fmt="<I",
        ),
        _pObjectDataField("pObjectData", ActivationPropertiesBlob(), None),
    ]


bind_layers(OBJREF, OBJREF_CUSTOM, flags=4)

# [MS-DCOM] 2.2.18.8


class DATAELEMENT(Packet):
    fields_desc = [
        UUIDField("dataID", None, uuid_fmt=UUIDField.FORMAT_LE),
        FieldLenField("cbSize", None, fmt="<I", length_of="Data"),
        FieldLenField(
            "cbRounded",
            None,
            fmt="<I",
            length_of="Data",
            adjust=lambda _, x: x + (-x % 8),
        ),
        PadField(
            StrLenField("Data", b"", length_from=lambda pkt: pkt.cbSize),
            align=8,
        ),
    ]


# [MS-DCOM] 2.2.18.7


class OBJREF_EXTENDED(Packet):
    fields_desc = [
        PacketField("std", STDOBJREF(), STDOBJREF),
        LEIntField("Signature1", 0x4E535956),
        PacketField("saResAddr", DUALSTRINGARRAY(), DUALSTRINGARRAY),
        LEIntField("nElms", 1),
        LEIntField("Signature2", 0x4E535956),
        # Doc says the array length is always 1
        PacketField("ElmArray", DATAELEMENT(), DATAELEMENT),
    ]


bind_layers(OBJREF, OBJREF_EXTENDED, flags=8)


# [MS-DCOM] 2.2.19.3


class STRINGBINDING(Packet):
    fields_desc = [
        LEShortEnumField("wTowerId", 0, DCE_RPC_PROTOCOL_IDENTIFIERS),
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


# [MS-DCOM] 2.2.20


class PROPMARSHALHEADER(Packet):
    fields_desc = [
        UUIDField("clsid", None, uuid_fmt=UUIDField.FORMAT_LE),
        UUIDField("policyId", None, uuid_fmt=UUIDField.FORMAT_LE),
        FlagsField("flags", 0, -32, tagCPFLAGS),
        FieldLenField("cb", None, length_of="ctxProperty"),
        StrLenField("ctxProperty", b"", length_from=lambda pkt: pkt.cb),
    ]


class Context(Packet):
    fields_desc = [
        LEShortField("MajorVersion", 0x0001),
        LEShortField("MinVersion", 0x0001),
        UUIDField("ContextId", None, uuid_fmt=UUIDField.FORMAT_LE),
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x00000002: "CTXMSHLFLAGS_BYVAL",
            },
        ),
        LEIntField("Reserved", 0),
        LEIntField("dwNumExtents", 0),
        LEIntField("cbExtents", 0),
        LEIntField("MshlFlags", 0),
        FieldLenField("Count", None, fmt="<I", count_of="PropMarshalHeader"),
        LEIntField("Frozen", 0x00000001),
        PacketListField(
            "PropMarshalHeader", [], PROPMARSHALHEADER, count_from=lambda pkt: pkt.Count
        ),
    ]


# -- DCOM Client and utils --

# Utils


def _ParseStringArray(
    dual: DUALSTRINGARRAY,
) -> Tuple[List[STRINGBINDING], List[SECURITYBINDING]]:
    """
    Process aStringArray in a DUALSTRINGARRAY to extract string bindings and
    security bindings.
    """
    str_fld = PacketListField("", [], STRINGBINDING)
    sec_fld = PacketListField("", [], SECURITYBINDING)
    string = str_fld.getfield(dual, dual.aStringArray[: dual.wSecurityOffset * 2])[1]
    secs = sec_fld.getfield(dual, dual.aStringArray[dual.wSecurityOffset * 2 :])[1]
    if string[-1].wTowerId != 0 or secs[-1].wAuthnSvc != 0:
        raise ValueError("Invalid DUALSTRINGARRAY !")
    return string[:-1], secs[:-1]


def _HashStringBinding(strings: List[STRINGBINDING]):
    """
    Hash a STRINGBINDING list
    """
    return hashlib.sha256(b"".join(bytes(x) for x in strings)).digest()


# Entries.


class IPID_Entry:
    """
    An entry in the IPID table
    [MS-DCOM] 3.1.1.1 Abstract Data Model
    """

    def __init__(self):
        self.ipid: Optional[uuid.UUID] = None
        self.iid: Optional[uuid.UUID] = None
        self.oid: Optional[int] = None
        self.oxid: Optional[int] = None
        self.cPublicRefs: int = 0
        self.cPrivateRefs: int = 0
        self.state: Any = None
        # Additions
        self.iface: Optional[ComInterface] = None


class OID_Entry:
    """
    An entry in the OID table
    [MS-DCOM] 3.1.1.1 Abstract Data Model
    """

    def __init__(self):
        self.oid: Optional[int] = None
        self.oxid: Optional[int] = None
        self.ipids: List[uuid.UUID] = []
        self.hash: Optional[bytes] = None
        self.last_orpc: int = None
        self.garbage_collection: bool = True
        self.state = None


class Resolver_Entry:
    """
    An entry in the Resolver table.
    [MS-DCOM] 3.2.1 Abstract Data Model
    """

    def __init__(self):
        self.hash: Optional[bytes] = None
        self.binds: List[STRINGBINDING] = []
        self.secs: List[SECURITYBINDING] = []
        self.setid: Optional[int] = None
        self.client: Optional[DCERPC_Client] = None


class SETID_Entry:
    """
    An entry in the SETID table.
    [MS-DCOM] 3.2.1 Abstract Data Model
    """

    def __init__(self):
        self.setid: Optional[int] = None
        self.oids: List[int] = []
        self.seq: Optional[int] = None


class OXID_Entry:
    """
    An entry in the OXID table.
    [MS-DCOM] 3.2.1 Abstract Data Model
    """

    def __init__(self):
        self.oxid: Optional[int] = None
        self.bindingInfo: Optional[Tuple[str, int]] = None
        self.authnHint: DCE_C_AUTHN_LEVEL = DCE_C_AUTHN_LEVEL.CONNECT
        self.version: Optional[COMVERSION] = None
        self.ipid_IRemUnknown: Optional[uuid.UUID] = None

    def __repr__(self):
        return f"<OXID_Entry {hex(self.oxid)}>"


class ObjectInstance:
    """
    An reference to an instantiated object.

    This is a helper to manipulate this object and perform calls over it.
    """

    def __init__(self, client: "DCOM_Client", oid: int):
        self.client = client
        self.oid = oid

    def __repr__(self):
        return f"<ObjectInstance {self.oid}>"

    @property
    def valid(self):
        """
        Returns whether the current object still exists
        """
        return self.oid in self.client.OID_table

    @property
    def ndr64(self):
        """
        Whether NDR64 is required to talk to this object
        """
        return self.client.ndr64

    def sr1_req(
        self,
        pkt: NDRPacket,
        iface: ComInterface,
        ssp=None,
        auth_level=None,
        timeout=None,
        **kwargs,
    ):
        """
        Make an ORPC call on this object instance.

        :param iface: the ComInterface to call.
        :param pkt: the request to make.

        :param ssp: (optional) non default SSP to use to connect to the object exporter
        :param auth_level: (optional) non default authn level to use
        :param timeout: (optional) timeout for the connection
        """
        # Look for this object's entry
        try:
            oid_entry = self.client.OID_table[self.oid]
        except KeyError:
            raise ValueError("This object has been released.")

        # Look for the ipid matching the interface required by the user
        ipid = None
        for ipid in oid_entry.ipids:
            ipid_entry = self.client.IPID_table[ipid]
            if ipid_entry.iid == iface.uuid:
                break
        else:
            # Acquire interface on the object
            self.client.AcquireInterface(
                ipid=oid_entry.ipids[0],
                iids=[
                    iface,
                ],
                cPublicRefs=1,
            )

        return self.client.sr1_orpc_req(
            ipid=ipid,
            pkt=pkt,
            ssp=ssp,
            auth_level=auth_level,
            timeout=timeout,
            **kwargs,
        )

    def release(self):
        """
        Call IRemUnknown2::RemRelease to release counts on an object reference.
        """
        for ipid in self.client.OID_table[self.oid].ipids:
            self.client.RemRelease(ipid)


class DCOM_Client(DCERPC_Client):
    """
    A wrapper of DCERPC_Client that adds functions to use COM interfaces.

    :param cid: the client identifier
    """

    IREMUNKNOWN = find_com_interface("IRemUnknown2")

    def __init__(self, cid: GUID = None, verb=True, **kwargs):
        # Pick a random cid to identify this client
        self.cid = cid or GUID(RandUUID().bytes_le)

        # The OXID table kept up-to-date by the client
        self.OXID_table: Dict[int, OXID_Entry] = {}

        # The IPID table kept up-to-date by the client
        self.IPID_table: Dict[int, IPID_Entry] = {}

        # The OID table kept up-to-date by the client
        self.OID_table: Dict[int, OID_Entry] = {}

        # The Resolver table kept up-to-date by the client
        self.Resolver_table: Dict[STRINGBINDING, Resolver_Entry] = {}

        # DCOM defaults to at least PKT_INTEGRITY
        if "auth_level" not in kwargs and "ssp" in kwargs:
            kwargs["auth_level"] = DCE_C_AUTHN_LEVEL.PKT_INTEGRITY

        super(DCOM_Client, self).__init__(
            DCERPC_Transport.NCACN_IP_TCP,
            ndr64=False,
            verb=verb,
            **kwargs,
        )

    def connect(self, host: str, timeout=5):
        """
        Initiate a connection to the object resolver.

        :param host: the host to connect to
        :param timeout: (optional) the connection timeout (default 5)
        """
        # [MS-DCOM] 3.2.4.1.2.1 Determining RPC Binding Information
        binds, _ = ServerAlive2(host)
        host, port = self._ChoseRPCBinding(binds)

        super(DCOM_Client, self).connect(
            host=host,
            port=port,
            timeout=timeout,
        )

    def sr1_req(self, pkt, **kwargs):
        raise NotImplementedError("Cannot use sr1_req on DCOM_Client !")

    def _GetObjectInstance(self, oid: int):
        """
        Internal function to get an ObjectInstance from an oid
        """
        return ObjectInstance(
            client=self,
            oid=oid,
        )

    def _RemoteCreateInstanceOrGetClassObject(
        self,
        clsreq,
        clsresp,
        clsid: uuid.UUID,
        iids: List[ComInterface],
    ) -> ObjectInstance:
        """
        Internal function common to RemoteCreateInstance and RemoteGetClassObject
        """
        if not iids:
            raise ValueError("Must specify at least one interface !")

        # Bind IObjectExporter if not already
        self.bind_or_alter(find_dcerpc_interface("IRemoteSCMActivator"))

        # [MS-DCOM] sect 3.1.2.5.2.3.3 - Issuing the Activation Request

        # Build the activation properties
        ActivationProperties = [
            SpecialPropertiesData(
                # Same as windows
                dwDefaultAuthnLvl=self.auth_level,
                dwOrigClsctx=16,
                dwFlags=2,  # ???
                ndr64=False,
            ),
            InstantiationInfoData(
                classId=GUID(_uid_to_bytes(clsid)),
                classCtx=16,
                actvflags=0,
                fIsSurrogate=0,
                clientCOMVersion=COMVERSION(
                    MajorVersion=5,
                    MinorVersion=7,
                ),
                pIID=[GUID(_uid_to_bytes(x.uuid)) for x in iids],
                ndr64=False,
            ),
            ActivationContextInfoData(
                pIFDClientCtx=MInterfacePointer(
                    abData=OBJREF(iid=IID_IContext)
                    / OBJREF_CUSTOM(
                        clsid=CLSID_ContextMarshaler,
                        pObjectData=Context(
                            ContextId=uuid.UUID("53394e9f-e973-4bf0-a341-154519534fe1"),
                            Flags="CTXMSHLFLAGS_BYVAL",
                        ),
                    ),
                ),
                ndr64=False,
            ),
            SecurityInfoData(
                pServerInfo=COSERVERINFO(
                    pwszName=self.host,
                ),
                ndr64=False,
            ),
            LocationInfoData(ndr64=False),
            ScmRequestInfoData(
                remoteRequest=customREMOTE_REQUEST_SCM_INFO(
                    pRequestedProtseqs=[
                        # Note <51> for Windows Vista and later
                        int(DCERPC_Transport.NCACN_IP_TCP),
                    ]
                ),
                ndr64=False,
            ),
        ]

        # Build CustomHeader
        hdr = CustomHeader(
            pclsid=[
                GUID(_uid_to_bytes(CLSID_SpecialSystemProperties)),
                GUID(_uid_to_bytes(CLSID_InstantiationInfo)),
                GUID(_uid_to_bytes(CLSID_ActivationContextInfo)),
                GUID(_uid_to_bytes(CLSID_SecurityInfo)),
                GUID(_uid_to_bytes(CLSID_ServerLocationInfo)),
                GUID(_uid_to_bytes(CLSID_ScmRequestInfo)),
            ],
            pSizes=[
                # Account for the size of the Type1 header + padding
                len(x) + 16 + (-len(x) % 8)
                for x in ActivationProperties
            ],
            ndr64=False,
        )
        hdr.headerSize = len(hdr) + 16  # 16: size of the Type1 serialization header
        hdr.totalSize = hdr.headerSize + sum(hdr.valueof("pSizes"))

        # Build final request
        pkt = clsreq(
            orpcthis=ORPCTHIS(
                version=COMVERSION(
                    MajorVersion=5,
                    MinorVersion=7,
                ),
                flags=tagCPFLAGS.CPFLAG_PROPAGATE,
                cid=self.cid,
            ),
            pActProperties=MInterfacePointer(
                abData=OBJREF(iid=IID_IActivationPropertiesIn)
                / OBJREF_CUSTOM(
                    clsid=CLSID_ActivationPropertiesIn,
                    pObjectData=ActivationPropertiesBlob(
                        CustomHeader=hdr,
                        Property=ActivationProperties,
                    ),
                ),
            ),
            ndr64=False,
        )

        if isinstance(pkt, RemoteCreateInstance_Request):
            pkt.pUnkOuter = None

        # Send and receive
        resp = super(DCOM_Client, self).sr1_req(pkt)
        if not resp or resp.status != 0:
            raise ValueError("%s failed." % clsreq.__name__)

        entry = OXID_Entry()
        objrefs = []

        # [MS-DCOM] sect 3.2.4.1.1.3 - Updating the Client OXID Table after Activation
        abData = OBJREF(resp.valueof("ppActProperties").abData)
        for prop in abData.pObjectData.Property:
            if ScmReplyInfoData in prop:
                # Information about the object exporter the server found for us
                remoteReply = prop[ScmReplyInfoData].valueof("remoteReply")

                # Get OXID, IPID, COMVERSION, authentication level hint
                entry.oxid = remoteReply.Oxid
                entry.version = remoteReply.serverVersion
                entry.authnHint = DCE_C_AUTHN_LEVEL(remoteReply.authnHint)
                entry.ipid_IRemUnknown = _uid_from_bytes(
                    bytes(remoteReply.ipidRemUnknown), ndrendian=remoteReply.ndrendian
                )

                # Set RPC bindings from the activation request
                binds, _ = _ParseStringArray(remoteReply.valueof("pdsaOxidBindings"))
                entry.bindingInfo = self._ChoseRPCBinding(binds)

            if PropsOutInfo in prop:
                # Information about the interfaces that the client requested
                info = prop[PropsOutInfo]

                # Check that all interfaces were obtained
                phresults = info.valueof("phresults")
                if any(x > 0 for x in phresults):
                    raise ValueError(
                        "Interfaces %s were not obtained !"
                        % [iids[i] for i, x in enumerate(phresults) if x > 0]
                    )

                # Now store the object references for each interface
                for i, ptr in enumerate(info.valueof("ppIntfData")):
                    if phresults[i] == 0:
                        objrefs.append(OBJREF(ptr.abData))
                    else:
                        objrefs.append(None)

        # Update the OXID table
        if entry.oxid not in self.OXID_table:
            self.OXID_table[entry.oxid] = entry

        # Get oid
        oid = objrefs[0].std.oid

        # Add an entry to the IPID table for the RemUnknown
        if entry.ipid_IRemUnknown not in self.IPID_table:
            ipid_entry = IPID_Entry()
            ipid_entry.iface = self.IREMUNKNOWN
            ipid_entry.iid = self.IREMUNKNOWN.uuid
            ipid_entry.oxid = entry.oxid
            ipid_entry.oid = oid
            self.IPID_table[entry.ipid_IRemUnknown] = ipid_entry

        # "For each object reference returned from the activation request for
        # which the corresponding status code indicates success, the client MUST
        # unmarshal the object reference"
        for i, obj in enumerate(objrefs):
            if obj is None:
                continue
            # Unmarshall
            self._UnmarshallObjref(obj, iid=iids[i])

        return self._GetObjectInstance(oid=oid)

    def _UnmarshallObjref(
        self,
        obj: OBJREF,
        iid: Optional[ComInterface] = None,
    ) -> int:
        """
        [MS-DCOM] sect 3.2.4.1.2 - Unmarshaling an Object Reference

        :param iid: "IID specified by the application when unmarshalling the object
            reference" (see [MS-DCOM] sect 4.5)
        """
        # "If the OBJREF_STANDARD flag is set"
        if OBJREF_STANDARD in obj and iid:
            # "the client MUST look up the OXID entry in the OXID
            # table using the OXID from the STDOBJREF"
            try:
                ox = self.OXID_table[obj.std.oxid]
            except KeyError:
                # "If the table entry is not found"

                # "determine the RPC binding information to be used"
                binds, _ = _ParseStringArray(obj.saResAddr)
                host, port = self._ChoseRPCBinding(binds)

                # "issue OXID resolution"
                ox = self.ResolveOxid2(oxid=obj.std.oxid, host=host, port=port)

            # "Next, the client MUST update its tables"
            self._UpdateTables(iid, ox, obj, obj.std)

            # "Finally, the client MUST compare the IID in the OBJREF with the
            # IID specified by the application"
            if obj.iid != iid.uuid:
                # "First, the client SHOULD acquire an object reference of the IID
                # specified by the application"
                self.AcquireInterface(
                    ipid=obj.std.ipid,
                    iids=[
                        iid,
                    ],
                    cPublicRefs=1,
                )

                # "Next, the client MUST release the object reference unmarshaled
                # from the OBJREF"
                self.RemRelease(obj.std.ipid)

            return obj.std.oid
        else:
            obj.show()
            raise NotImplementedError("Non OBJREF_STANDARD ! Please report.")

    def _UpdateTables(
        self,
        iface: ComInterface,
        ox: OXID_Entry,
        obj: OBJREF,
        std: STDOBJREF,
    ) -> None:
        """
        [MS-DCOM] 3.2.4.1.2.3 Updating Client Tables After Unmarshaling
        """
        # [MS-DCOM] 3.2.4.1.2.3.1 Updating the OXID
        if std.oxid not in self.OXID_table:
            self.OXID_table[std.oxid] = ox

        # [MS-DCOM] 3.2.4.1.2.3.2 Updating the OID/IPID/Resolver
        if std.ipid in self.IPID_table:
            self.IPID_table[std.ipid].cPublicRefs += std.cPublicRefs
        else:
            entry = IPID_Entry()
            entry.ipid = std.ipid
            entry.oxid = std.oxid
            entry.oid = std.oid
            entry.iid = obj.iid
            entry.iface = iface
            entry.cPublicRefs = std.cPublicRefs
            if entry.cPublicRefs == 0:
                # "If the STDOBJREF contains a public reference count of zero,
                # the client MUST obtain additional references on the interface"
                raise NotImplementedError("Should acquire additional references !")
            entry.cPrivateRefs = 0
            self.IPID_table[std.ipid] = entry

        if std.oid in self.OID_table:
            oid_entry = self.OID_table[std.oid]
            if std.ipid not in oid_entry.ipids:
                oid_entry.ipids.append(std.ipid)
        else:
            binds, secs = _ParseStringArray(obj.saResAddr)

            oid_entry = OID_Entry()
            oid_entry.oid = std.oid
            oid_entry.oxid = std.oxid
            oid_entry.ipids.append(std.ipid)
            oid_entry.garbage_collection = not std.flags.SORF_NOPING
            oid_entry.hash = _HashStringBinding(binds)
            self.OID_table[std.oid] = oid_entry

            if oid_entry.hash not in self.Resolver_table:
                resolver_entry = Resolver_Entry()
                resolver_entry.setid = 0
                resolver_entry.hash = oid_entry.hash
                resolver_entry.binds = binds
                resolver_entry.secs = secs
                self.Resolver_table[oid_entry.hash] = resolver_entry

    def _ChoseRPCBinding(self, bindings: List[STRINGBINDING]):
        """
        [MS-DCOM] 3.2.4.1.2.1 - Determining RPC Binding Information for OXID Resolution
        """
        # We don't try security bindings, only string ones (connection).
        # We take the first valid one.
        for binding in bindings:
            # Only NCACN_IP_TCP is supported by DCOM
            if binding.wTowerId == DCERPC_Transport.NCACN_IP_TCP:
                # [MS-DCOM] 2.2.19.3
                m = re.match(r"(.*)\[(.*)\]", binding.aNetworkAddr)
                if m:
                    host, port = m.group(1), int(m.group(2))
                else:
                    host, port = binding.aNetworkAddr, 135

                # Check validity of the host/port tuple
                if valid_ip6(host):
                    # IPv6
                    pass
                elif valid_ip(host):
                    # IPv4
                    pass
                else:
                    # Netbios/FQDN
                    try:
                        socket.gethostbyname(host)
                    except Exception:
                        # Resolution failed. Skip.
                        continue

                # Success
                return host, port
        raise ValueError("No valid bindings available !")

    def UnmarshallObjectReference(
        self, mifaceptr: MInterfacePointer, iid: ComInterface
    ):
        """
        [MS-DCOM] 3.2.4.3 Marshaling an Object Reference

        Unmarshall a MInterfacePointer received by the applicative layer.
        """
        oid = self._UnmarshallObjref(obj=OBJREF(mifaceptr.abData), iid=iid)
        return self._GetObjectInstance(oid)

    def ResolveOxid2(
        self, oxid: int, host: Optional[str] = None, port: Optional[int] = None
    ):
        """
        [MS-DCOM] 3.2.4.1.2.2 Issuing the OXID Resolution Request

        :param oxid: the OXID to resolve
        :param host: (optional) connect to a different host
        :param port: (optional) connect to a different port
        """

        if host == self.host and port == self.port:
            host = self.host
            port = self.port
            client = self
        else:
            # Create and connect client
            client = DCOM_Client(
                # Note <85>: Windows uses INTEGRITY
                auth_level=DCE_C_AUTHN_LEVEL.PKT_INTEGRITY,
                ssp=self.ssp,
            )
            client.connect(host, port=port)

        # Bind IObjectExporter if not already
        client.bind_or_alter(find_dcerpc_interface("IObjectExporter"))

        try:
            # Perform ResolveOxid2
            resp = super(DCOM_Client, client).sr1_req(
                ResolveOxid2_Request(
                    pOxid=oxid,
                    arRequestedProtseqs=[
                        DCERPC_Transport.NCACN_IP_TCP,
                    ],
                    ndr64=self.ndr64,
                )
            )
        finally:
            if host != self.host or port != self.port:
                client.close()

        # Entry
        if oxid in self.OXID_table:
            entry = self.OXID_table[oxid]
        else:
            entry = OXID_Entry()

        # Get OXID, IPID, COMVERSION, authentication level hint
        entry.oxid = oxid
        entry.version = resp.pComVersion
        entry.authnHint = DCE_C_AUTHN_LEVEL(resp.pAuthnHint)
        entry.ipid_IRemUnknown = _uid_from_bytes(
            bytes(resp.pipidRemUnknown), ndrendian=resp.ndrendian
        )

        # Set RPC bindings from the oxid request
        binds, _ = _ParseStringArray(resp.valueof("ppdsaOxidBindings"))
        entry.bindingInfo = self._ChoseRPCBinding(binds)

        # Update the OXID table
        if entry.oxid not in self.OXID_table:
            self.OXID_table[entry.oxid] = entry

        return entry

    def RemoteCreateInstance(
        self, clsid: uuid.UUID, iids: List[ComInterface]
    ) -> ObjectInstance:
        """
        Calls IRemoteSCMActivator::RemoteCreateInstance and returns a OXID_Entry
        that points to an instance of the provided class.

        :param clsid: the class ID to initialize
        :param iids: the IDs of the interfaces to request
        """
        return self._RemoteCreateInstanceOrGetClassObject(
            RemoteCreateInstance_Request,
            RemoteCreateInstance_Response,
            clsid,
            iids,
        )

    def RemoteGetClassObject(
        self, clsid: uuid.UUID, iids: List[ComInterface]
    ) -> ObjectInstance:
        """
        Calls IRemoteSCMActivator::RemoteGetClassObject and returns a OXID_Entry
        that points to the factory.

        :param clsid: the class ID to initialize
        :param iids: the IDs of the interfaces to request
        """
        return self._RemoteCreateInstanceOrGetClassObject(
            RemoteGetClassObject_Request,
            RemoteGetClassObject_Response,
            clsid,
            iids,
        )

    def sr1_orpc_req(
        self,
        pkt: NDRPacket,
        ipid: uuid.UUID,
        ssp=None,
        auth_level=None,
        timeout=5,
        **kwargs,
    ):
        """
        Make an ORPC call.

        :param ipid: the reference to a specific interface on an object.
        :param pkt: the request to make.

        :param ssp: (optional) non default SSP to use to connect to the object exporter
        :param auth_level: (optional) non default authn level to use
        :param timeout: (optional) timeout for the connection
        """
        # [MS-DCOM] sect 3.2.4.2

        # 1. look up the object exporter information in the client tables

        try:
            # "The client MUST use the IPID specified by the client application to
            # look up the IPID entry in the IPID table."
            ipid_entry = self.IPID_table[ipid]
        except KeyError:
            raise ValueError("The IPID that was passed is unknown.")

        # "The client MUST then look up the OXID entry"
        oxid_entry = self.OXID_table[ipid_entry.oxid]
        oid_entry = self.OID_table[ipid_entry.oid]
        resolver_entry = self.Resolver_table[oid_entry.hash]

        # Get opnum
        try:
            opnum = pkt.overload_fields[DceRpc5Request]["opnum"]
        except KeyError:
            raise ValueError("This packet is not part of a registered COM interface !")

        # Build ORPC request

        if resolver_entry.client is None:
            # We don't have a client ready, make one.
            resolver_entry.client = DCERPC_Client(
                DCERPC_Transport.NCACN_IP_TCP,
                ssp=ssp or self.ssp,
                auth_level=auth_level or oxid_entry.authnHint,
                verb=self.verb,
            )

            resolver_entry.client.connect(
                host=oxid_entry.bindingInfo[0],
                port=oxid_entry.bindingInfo[1],
                timeout=timeout,
            )

        # Bind the COM interface
        resolver_entry.client.bind_or_alter(ipid_entry.iface)

        # We need to set the NDR very late, after the bind
        pkt.ndr64 = resolver_entry.client.ndr64

        # "The ORPCTHIS and ORPCTHAT structures MUST be marshaled using
        # the NDR [2.0] Transfer Syntax"
        pkt = (
            ORPCTHIS(
                version=oxid_entry.version,
                cid=self.cid,
                ndr64=False,
            )
            / pkt
        )

        # Send/Receive !
        resp = resolver_entry.client.sr1_req(
            pkt,
            opnum=opnum,
            objectuuid=ipid,
            **kwargs,
        )

        return resp[ORPCTHAT].payload

    def AcquireInterface(
        self,
        ipid: uuid.UUID,
        iids: List[ComInterface],
        cPublicRefs: int,
    ):
        """
        [MS-DCOM] 3.2.4.4.3 - Acquiring Additional Interfaces on the Object
        """
        # 1. Look up the OID entry
        ipid_entry = self.IPID_table[ipid]
        oxid_entry = self.OXID_table[ipid_entry.oxid]

        # 2. Perform call
        resp = self.sr1_orpc_req(
            ipid=oxid_entry.ipid_IRemUnknown,
            pkt=RemQueryInterface_Request(
                ripid=GUID(_uid_to_bytes(ipid)),
                cRefs=cPublicRefs,
                cIids=len(iids),
                iids=[GUID(_uid_to_bytes(x.uuid)) for x in iids],
            ),
        )

        # 3. Process answer
        if not resp or resp.status != 0:
            raise ValueError

        # "When the call returns successfully..."
        for i, remqir in enumerate(resp.valueof("ppQIResults")):
            self._UnmarshallObjref(
                OBJREF(iid=iids[i].uuid)
                / OBJREF_STANDARD(std=STDOBJREF(bytes(remqir.std))),
                iid=iids[i],
            )

    def RemRelease(self, ipid: uuid.UUID):
        """
        3.2.4.4.2 Releasing Reference Counts on an Interface
        """

        # 1. Look up the OID entry
        ipid_entry = self.IPID_table[ipid]
        oxid_entry = self.OXID_table[ipid_entry.oxid]
        oid_entry = self.OID_table[ipid_entry.oid]

        # 2. Perform call
        resp = self.sr1_orpc_req(
            ipid=oxid_entry.ipid_IRemUnknown,
            pkt=RemRelease_Request(
                InterfaceRefs=[
                    REMINTERFACEREF(
                        ipid=GUID(_uid_to_bytes(ipid)),
                        cPublicRefs=ipid_entry.cPublicRefs,
                        cPrivateRefs=ipid_entry.cPrivateRefs,
                    )
                ],
            ),
        )

        # 3. Process answer
        if resp and resp.status == 0:
            # "When the call returns successfully..."
            # "It MUST remove the IPID entry from the IPID table."
            del self.IPID_table[ipid]

            # "It MUST remove the IPID from the IPID list in the OID entry."
            oid_entry.ipids.remove(ipid)

            # "If the IPID list of the OID entry is empty, it MUST remove the
            # OID entry from the OID table."
            if not oid_entry.ipids:
                del self.OID_table[ipid_entry.oid]


def ServerAlive2(host, timeout=5) -> Tuple[List[STRINGBINDING], List[SECURITYBINDING]]:
    """
    Call IObjectExporter::ServerAlive2
    """
    client = DCERPC_Client(
        transport=DCERPC_Transport.NCACN_IP_TCP,
        verb=False,
        ndr64=False,
        # "The client MUST NOT specify security on the call"
        auth_level=DCE_C_AUTHN_LEVEL.NONE,
    )
    client.connect(host, port=135, timeout=timeout)

    # Bind IObjectExporter if not already
    client.bind_or_alter(find_dcerpc_interface("IObjectExporter"))

    # Send ServerAlive2 request
    resp = client.sr1_req(ServerAlive2_Request(ndr64=False), timeout=timeout)
    if not resp or resp.status != 0:
        raise ValueError("ServerAlive2 failed !")

    # Parse bindings and security options
    return _ParseStringArray(resp.ppdsaOrBindings.value)
