# coding: utf8

# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software FounDation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Copyright (C)
# @Author: GuillaumeF
# @Email:  guillaume4favre@gmail.com
# @Date:   2016-10-18
# @Last modified by:   GuillaumeF
# @Last modified by:   Sebastien Mainand
# @Last modified time: 2016-12-08 11:16:27
# @Last modified time: 2017-07-05

# scapy.contrib.description = OPC Data Access
# scapy.contrib.status = loads

"""
Opc Data Access

Spec: Google 'OPCDA3.00.pdf'

RPC PDU encodings:
- DCE 1.1 RPC: https://pubs.opengroup.org/onlinepubs/9629399/toc.pdf
- http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm

DCOM Remote Protocol.
[MS-DCOM]: Distributed Component Object Model (DCOM) Remote Protocol
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0
XXX TODO: does not appear to have been linked to RPC

NT LAN Manager (NTLM) Authentication Protocol
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4
"""

import struct

from scapy.config import conf
from scapy.fields import (
    BitEnumField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    FlagsField,
    IntEnumField,
    IntField,
    LEIntEnumField,
    LEIntField,
    LELongField,
    LEShortField,
    MultipleTypeField,
    PacketField,
    PacketLenField,
    PacketListField,
    ShortEnumField,
    ShortField,
    StrField,
    StrFixedLenField,
    StrLenField,
    ThreeBytesField,
    UUIDField,
    _FieldContainer,
    _PacketField,
)
from scapy.packet import Packet

# Defined values
_tagOPCDataSource = {
    1: "OPC_DS_CACHE",
    2: "OPC_DS_DEVICE"
}

_tagOPCBrowseType = {
    1: "OPC_BRANCH",
    2: "OPC_LEAF",
    3: "OPC_FLAT"
}

_tagOPCNameSpaceType = {
    1: "OPC_NS_HIERARCHIAL",
    2: "OPC_NS_FLAT"
}

_tagOPCBrowseDirection = {
    1: "OPC_BROWSE_UP",
    2: "OPC_BROWSE_DOWN",
    3: "OPC_BROWSE_TO"
}

_tagOPCEuType = {
    0: "OPC_NOENUM",
    1: "OPC_ANALOG",
    2: "OPC_ENUMERATED"
}

_tagOPCServerState = {
    1: "OPC_STATUS_RUNNING",
    2: "OPC_STATUS_FAILED",
    3: "OPC_STATUS_NOCONFIG",
    4: "OPC_STATUS_SUSPENDED",
    5: "OPC_STATUS_TEST",
    6: "OPC_STATUS_COMM_FAULT"
}

_tagOPCEnumScope = {
    1: "OPC_ENUM_PRIVATE_CONNECTIONS",
    2: "OPC_ENUM_PUBLIC_CONNECTIONS",
    3: "OPC_ENUM_ALL_CONNECTIONS",
    4: "OPC_ENUM_PRIVATE",
    5: "OPC_ENUM_PUBLIC",
    6: "OPC_ENUM_ALL"
}

_pfc_flags = [
    "firstFragment",            # First fragment
    "lastFragment",             # Last fragment
    "pendingCancel",            # Cancel was pending at sender
    "reserved",                 #
    "concurrentMultiplexing",   # supports concurrent multiplexing
                                # of a single connection
    "didNotExecute",            # only meaningful on `fault' packet if true,
                                # guaranteed call did not execute
    "maybe",                    # `maybe' call semantics requested
    "objectUuid"                # if true, a non-nil object UUID was specified
                                # in the handle, and is present in the optional
                                # object field. If false, the object field
                                # is omitted
]

_faultStatus = {
    382312475: 'rpc_s_fault_object_not_found',
    382312497: 'rpc_s_call_cancelled',
    382312564: 'rpc_s_fault_addr_error',
    382312565: 'rpc_s_fault_context_mismatch',
    382312566: 'rpc_s_fault_fp_div_by_zero',
    382312567: 'rpc_s_fault_fp_error',
    382312568: 'rpc_s_fault_fp_overflow',
    382312569: 'rpc_s_fault_fp_underflow',
    382312570: 'rpc_s_fault_ill_inst',
    382312571: 'rpc_s_fault_int_div_by_zero',
    382312572: 'rpc_s_fault_int_overflow',
    382312573: 'rpc_s_fault_invalid_bound',
    382312574: 'rpc_s_fault_invalid_tag',
    382312575: 'rpc_s_fault_pipe_closed',
    382312576: 'rpc_s_fault_pipe_comm_error',
    382312577: 'rpc_s_fault_pipe_discipline',
    382312578: 'rpc_s_fault_pipe_empty',
    382312579: 'rpc_s_fault_pipe_memory',
    382312580: 'rpc_s_fault_pipe_order',
    382312582: 'rpc_s_fault_remote_no_memory',
    382312583: 'rpc_s_fault_unspec',
    382312723: 'rpc_s_fault_user_defined',
    382312726: 'rpc_s_fault_tx_open_failed',
    382312814: 'rpc_s_fault_codeset_conv_error',
    382312816: 'rpc_s_fault_no_client_stub',
    469762049: 'nca_s_fault_int_div_by_zero',
    469762050: 'nca_s_fault_addr_error',
    469762051: 'nca_s_fault_fp_div_zero',
    469762052: 'nca_s_fault_fp_underflow',
    469762053: 'nca_s_fault_fp_overflow',
    469762054: 'nca_s_fault_invalid_tag',
    469762055: 'nca_s_fault_invalid_bound',
    469762061: 'nca_s_fault_cancel',
    469762062: 'nca_s_fault_ill_inst',
    469762063: 'nca_s_fault_fp_error',
    469762064: 'nca_s_fault_int_overflow',
    469762068: 'nca_s_fault_pipe_empty',
    469762069: 'nca_s_fault_pipe_closed',
    469762070: 'nca_s_fault_pipe_order',
    469762071: 'nca_s_fault_pipe_discipline',
    469762072: 'nca_s_fault_pipe_comm_error',
    469762073: 'nca_s_fault_pipe_memory',
    469762074: 'nca_s_fault_context_mismatch',
    469762075: 'nca_s_fault_remote_no_memory',
    469762081: 'ncs_s_fault_user_defined',
    469762082: 'nca_s_fault_tx_open_failed',
    469762083: 'nca_s_fault_codeset_conv_error',
    469762084: 'nca_s_fault_object_not_found',
    469762085: 'nca_s_fault_no_client_stub',
}

_defResult = {
    0: 'ACCEPTANCE',
    1: 'USER_REJECTION',
    2: 'PROVIDER_REJECTION',
}

_defReason = {
    0: 'REASON_NOT_SPECIFIED',
    1: 'ABSTRACT_SYNTAX_NOT_SUPPORTED',
    2: 'PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED',
    3: 'LOCAL_LIMIT_EXCEEDED',
}

_rejectBindNack = {
    0: 'REASON_NOT_SPECIFIED',
    1: 'TEMPORARY_CONGESTION',
    2: 'LOCAL_LIMIT_EXCEEDED',
    3: 'CALLED_PADDR_UNKNOWN',
    4: 'PROTOCOL_VERSION_NOT_SUPPORTED',
    5: 'DEFAULT_CONTEXT_NOT_SUPPORTED',
    6: 'USER_DATA_NOT_READABLE',
    7: 'NO_PSAP_AVAILABLE'
}

_rejectStatus = {
    469762056: 'nca_rpc_version_mismatch',
    469762057: 'nca_unspec_reject',
    469762058: 'nca_s_bad_actid',
    469762059: 'nca_who_are_you_failed',
    469762060: 'nca_manager_not_entered',
    469827586: 'nca_op_rng_error',
    469827587: 'nca_unk_if',
    469827590: 'nca_wrong_boot_time',
    469827593: 'nca_s_you_crashed',
    469827595: 'nca_proto_error',
    469827603: 'nca_out_args_too_big',
    469827604: 'nca_server_too_busy',
    469827607: 'nca_unsupported_type',
    469762076: 'nca_invalid_pres_context_id',
    469762077: 'nca_unsupported_authn_level',
    469762079: 'nca_invalid_checksum',
    469762080: 'nca_invalid_crc'
}

_pduType = {
    0: "REQUEST",
    1: "PING",
    2: "RESPONSE",
    3: "FAULT",
    4: "WORKING",
    5: "NOCALL",
    6: "REJECT",
    7: "ACK",
    8: "CI_CANCEL",
    9: "FACK",
    10: "CANCEL_ACK",
    11: "BIND",
    12: "BIND_ACK",
    13: "BIND_NACK",
    14: "ALTER_CONTEXT",
    15: "ALTER_CONTEXT_RESP",
    17: "SHUTDOWN",
    18: "CO_CANCEL",
    19: "ORPHANED",
    # Not documented
    16: "Auth3",
}

_authentification_protocol = {
    0: 'None',
    1: 'OsfDcePrivateKeyAuthentication',
}

# Util


def _make_le(pkt_cls):
    """
    Make all fields in a packet LE.
    """
    flds = [f.copy() for f in pkt_cls.fields_desc]
    for f in flds:
        if isinstance(f, _FieldContainer):
            f = f.fld
        if isinstance(f, UUIDField):
            f.uuid_fmt = UUIDField.FORMAT_LE
        elif isinstance(f, _PacketField):
            f.cls = globals().get(f.cls.__name__ + "LE", f.cls)
        elif not isinstance(f, StrField):
            f.fmt = "<" + f.fmt.replace(">", "").replace("!", "")
            f.struct = struct.Struct(f.fmt)

    class LEPacket(pkt_cls):
        fields_desc = flds
        name = pkt_cls().name + " (LE)"
    LEPacket.__name__ = pkt_cls.__name__ + "LE"
    return LEPacket


#  Sub class for dissection
class AuthentificationProtocol(Packet):
    name = 'authentificationProtocol'

    def extract_padding(self, p):
        return b"", p

    def guess_payload_class(self, payload):
        if self.underlayer and hasattr(self.underlayer, "authLength"):
            authLength = self.underlayer.authLength
            if authLength != 0:
                try:
                    return _authentification_protocol[authLength]
                except Exception:
                    pass
        return conf.raw_layer


class OsfDcePrivateKeyAuthentification(Packet):
    name = "OsfDcePrivateKeyAuthentication"
    # TODO

    def extract_padding(self, p):
        return b"", p


class OPCHandle(Packet):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "16s")

    def extract_padding(self, p):
        return b"", p


class LenStringPacket(Packet):
    # Among other things, can be (port_any_t -  DCE 1.1 RPC - p592)
    name = "len string packet"
    fields_desc = [
        FieldLenField('length', 0, length_of='data', fmt="H"),
        MultipleTypeField(
            [(StrFixedLenField('data', '', length=2),
                lambda pkt: not pkt.length)],
            StrLenField('data', '', length_from=lambda pkt: pkt.length)
        )
    ]

    def extract_padding(self, p):
        return b"", p


LenStringPacketLE = _make_le(LenStringPacket)


class SyntaxId(Packet):
    name = "syntax Id"
    fields_desc = [
        UUIDField('interfaceUUID', str('0001' * 8),
                  uuid_fmt=UUIDField.FORMAT_BE),
        ShortField('versionMajor', 0),
        ShortField('versionMinor', 0),
    ]

    def extract_padding(self, p):
        return b"", p


SyntaxIdLE = _make_le(SyntaxId)


class ResultElement(Packet):
    # p_result_list_t -  DCE 1.1 RPC - p591
    name = "p_result_t"
    fields_desc = [
        ShortEnumField('resultContextNegotiation', 0, _defResult),
        ConditionalField(ShortEnumField('reason', 0, _defReason),
                         lambda pkt:pkt.resultContextNegotiation != 0),
        PacketField('transferSyntax', '\x00' * 20, SyntaxId),
    ]

    def extract_padding(self, p):
        return b"", p


ResultElementLE = _make_le(ResultElement)


class ResultList(Packet):
    # p_result_list_t -  DCE 1.1 RPC - p592
    name = "p_result_list_t"
    fields_desc = [
        ByteField('nbResult', 0),
        ByteField('reserved', 0),
        ShortField('reserved2', 0),
        PacketListField('resultList', None, ResultElement,
                        count_from=lambda pkt:pkt.nbResult),
    ]

    def extract_padding(self, p):
        return b"", p


ResultListLE = _make_le(ResultList)


class ContextElement(Packet):
    name = "context element"
    fields_desc = [
        ShortField('contxtId', 0),
        ByteField('nbTransferSyn', 0),
        ByteField('reserved', 0),
        PacketField('abstractSyntax', None, SyntaxId),
        PacketListField('transferSyntax', None, SyntaxId,
                        count_from=lambda pkt:pkt.nbTransferSyn),
    ]

    def extract_padding(self, p):
        return b"", p


ContextElementLE = _make_le(ContextElement)


# Only in Little-Endian
class STDOBJREF(Packet):
    name = 'stdObjRef'
    fields_desc = [
        LEIntEnumField('flags', 1, {0: 'PINGING', 8: 'SORF_NOPING'}),
        LEIntField('cPublicRefs', 0),
        LELongField('OXID', 0),
        LELongField('OID', 0),
        PacketField('IPID', None, UUIDField),
    ]


class StringBinding(Packet):
    name = 'String Binding'
    fields_desc = [
        LEShortField('wTowerId', 0),
        # Not enough information to continue
    ]


class DualStringArray(Packet):
    name = "Dual String Array"
    fields_desc = [
        ShortField('wNumEntries', 0),
        ShortField('wSecurityOffset', 0),
        StrFixedLenField('StringBinding', '',
                         # Simplify the problem
                         length_from=lambda pkt:pkt.wSecurityOffset),
    ]


DualStringArrayLE = _make_le(DualStringArray)


class OBJREF_STANDARD(Packet):
    name = "objetref stanDard"
    fields_desc = [
        PacketField('std', None, STDOBJREF),
        PacketField('saResAddr', None, DualStringArray),
    ]


OBJREF_STANDARDLE = _make_le(OBJREF_STANDARD)


class OBJREF_HANDLER(Packet):
    name = "objetref stanDard"
    fields_desc = [
        PacketField('std', None, STDOBJREF),
        UUIDField('clsid', str('0001' * 8), uuid_fmt=UUIDField.FORMAT_BE),
        PacketField('saResAddr', None, DualStringArray),
    ]


OBJREF_HANDLERLE = _make_le(OBJREF_HANDLER)


class OBJREF_CUSTOM(Packet):
    name = "objetref stanDard"
    fields_desc = [
        UUIDField('clsid', str('0001' * 8), uuid_fmt=UUIDField.FORMAT_BE),
        IntField('cbExtension', 0),
        IntField('reserved', 0),
    ]


OBJREF_CUSTOMLE = _make_le(OBJREF_CUSTOM)


class OBJREF_EXTENDED(Packet):
    name = "objetref stanDard"
    fields_desc = [

    ]


OBJREF_EXTENDEDLE = _make_le(OBJREF_EXTENDED)


# Packet for the interfaces defined
_objref_flag = {
    1: 'OBJREF_STANDARD',
    2: 'OBJREF_HANDLER',
    4: 'OBJREF_CUSTOM',
    8: 'OBJREF_EXTENDED',
}


_objref_pdu = {
    1: [OBJREF_STANDARD, OBJREF_STANDARDLE],
    2: [OBJREF_HANDLER, OBJREF_HANDLERLE],
    4: [OBJREF_CUSTOM, OBJREF_CUSTOMLE],
    8: [OBJREF_EXTENDED, OBJREF_EXTENDEDLE],
}


class IRemoteSCMActivator_RemoteCreateInstance(Packet):
    name = 'RemoteCreateInstance'
    fields_desc = [
        ShortField('versionMajor', 0),
        ShortField('versionMinor', 0),
        IntEnumField('flag', 1, _objref_flag),
        IntField('reserved', 0),
    ]

    def guess_payload_class(self, payload):
        try:
            return _objref_pdu[self.flag][
                self.__class__.__name__.endswith("LE")
            ]
        except Exception:
            pass


IRemoteSCMActivator_RemoteCreateInstanceLE = _make_le(
    IRemoteSCMActivator_RemoteCreateInstance
)


IRemoteSCMActivator = {
    # 0: 'Reserved for local use',
    # 1: 'Reserved for local use',
    # 2: 'Reserved for local use',
    # 3: [IRemoteSCMActivator_RemoteGetClassObject,
    # IRemoteSCMActivator_RemoteGetClassObject],
    4: [IRemoteSCMActivator_RemoteCreateInstance,
        IRemoteSCMActivator_RemoteCreateInstanceLE],
}


# UUID defined for DCOM
# Specifies the Distributed Component Object Model (DCOM) Remote Protocol
# https://msdn.microsoft.com/en-us/library/cc226801.aspx
# MS-Dcom.pdf 1.9
# OPC DA Specification.pdf
_standardDcomEndpoint = {
    # MS-DCOM
    '4d9f4ab8-7d1c-11cf-861e-0020af6e7c57': "IActivation",
    '000001A0-0000-0000-C000-000000000046': IRemoteSCMActivator,
    '99fcfec4-5260-101b-bbcb-00aa0021347a': "IObjectExporter",
    '00000000-0000-0000-C000-000000000046': "IUnknown",
    '00000131-0000-0000-C000-000000000046': "IRemUnknown_IUnknown",
    '00000143-0000-0000-C000-000000000046': "IRemUnknown2_IRemUnknown",
    # OLE for Process Control
    '63D5F430-CFE4-11d1-B2C8-0060083BA1FB': "CATID_OPCDAServer10",
    '63D5F432-CFE4-11d1-B2C8-0060083BA1FB': "CATID_OPCDAServer20",
    'CC603642-66D7-48f1-B69A-B625E73652D7': "CATID_OPCDAServer30",
    '39c13a4d-011e-11d0-9675-0020afd8adb3': "IOPCServer_IUnknown",
    '39c13a4e-011e-11d0-9675-0020afd8adb3': "IOPCServerPublicGroups_IUnknown",
    '39c13a4f-011e-11d0-9675-0020afd8adb3': "IOPCBrowseServerAddrSpace_IUnknown",  # noqa: E501
    '39c13a50-011e-11d0-9675-0020afd8adb3': "IOPCGroupStateMgt_IUnknown",
    '39c13a51-011e-11d0-9675-0020afd8adb3': "IOPCPublicGroupStateMgt_IUnknown",
    '39c13a52-011e-11d0-9675-0020afd8adb3': "IOPCSyncIO_IUnknown",
    '39c13a53-011e-11d0-9675-0020afd8adb3': "IOPCAsyncIO_IUnknown",
    '39c13a54-011e-11d0-9675-0020afd8adb3': "IOPCItemMgt_IUnknown",
    '39c13a55-011e-11d0-9675-0020afd8adb3': "IEnumOPCItemAttributes_IUnknown",
    '39c13a70-011e-11d0-9675-0020afd8adb3': "IOPCDataCallback_IUnknown",
    '39c13a71-011e-11d0-9675-0020afd8adb3': "IOPCAsyncIO2_IUnknown",
    '39c13a72-011e-11d0-9675-0020afd8adb3': "IOPCItemProperties_IUnknown",
    '5946DA93-8B39-4ec8-AB3D-AA73DF5BC86F': "IOPCItemDeadbandMgt_IUnknown",
    '3E22D313-F08B-41a5-86C8-95E95CB49FFC': "IOPCItemSamplingMgt_IUnknown",
    '39227004-A18F-4b57-8B0A-5235670F4468': "IOPCBrowse_IUnknown",
    '85C0B427-2893-4cbc-BD78-E5FC5146F08F': "IOPCItemIO_IUnknown",
    '730F5F0F-55B1-4c81-9E18-FF8A0904E1FA': "IOPCSyncIO2_IOPCSyncIO",
    '0967B97B-36EF-423e-B6F8-6BFF1E40D39D': "IOPCAsyncIO3_IOPCAsyncIO2",
    '8E368666-D72E-4f78-87ED-647611C61C9F': "IOPCGroupStateMgt2_IOPCGroupStateMgt",  # noqa: E501
    '3B540B51-0378-4551-ADCC-EA9B104302BF': "library_OPCDA",
    # Other
    '000001a5-0000-0000-c000-000000000046': "ActivationContextInfo",
    '00000338-0000-0000-c000-000000000046': "ActivationPropertiesIn",
}


# [MS-NLMP] 2.2.2.1
_attribute_type = {
    0: 'EndOfList',
    1: 'NetBIOSComputerName',
    2: 'NetBIOSDomainName',
    3: 'DNSComputername',
    4: 'DNSDomainName',
    6: 'Flags',
    7: 'TimeStamp',
    8: 'Restrictions',
    9: 'TargetName',
    10: 'ChannelBindings'
}

# Maybe depend of LE or BE
_negociate_flags = [
    "negociate_0x01",
    "negociate_version",
    "negociate_0x04",
    "negociate_0x08",
    "negociate_0x10",
    "negociate_128",
    "negociate_key_exchange",
    "negociate_56",
    "target_type_domain",
    "target_type_server",
    "taget_type_share",
    "negociate_extended_security",
    "negociate_identity",
    "negociate_0x002",
    "request_non_nt",
    "negociate_target_info",
    "negociate_0x000001",
    "negociate_ntlm_key",
    "negociate_nt_only",
    "negociate_anonymous",
    "negociate_oem_doamin",
    "negociate_oem_workstation",
    "negociate_0x00004",
    "negociate_always_sign",
    "negociate_unicode",
    "negociate_oem",
    "request_target",
    "negociate_00000008",
    "negociate_sign",
    "negociate_seal",
    "negociate_datagram",
    "negociate_lan_manager_key",
]


class AV_PAIR(Packet):
    name = "AV_PAIR"
    fields_desc = [
        ShortEnumField('avID', 2, _attribute_type),
        ShortField('avLen', 0),
        StrLenField('value', '',
                    length_from=lambda pkt:pkt.avLen),
    ]

    def extract_padding(self, p):
        return b"", p


AV_PAIRLE = _make_le(AV_PAIR)


class NTLMSSP(Packet):
    # [MS-NLMP] v16.2 sect 2.2.1
    name = 'NTLM Authentication Protocol'
    deprecated_fields_desc = {
        'identifier': ('signature', '2.5.0'),
    }
    fields_desc = [
        StrFixedLenField('signature', b'NTLMSSP\0', length=8),
        IntEnumField('messageType', 3, {1: 'NEGOTIATE_MESSAGE',
                                        2: 'CHALLENGE_MESSAGE',
                                        3: 'AUTHENTICATE_MESSAGE'}),
        # TODO: ONLY AUTHENTICATE_MESSAGE IMPLEMENTED
        # sect 2.2.1.3
        ShortField('lmChallengeResponseLen', 0),
        ShortField('lmChallengeResponseMaxLen', 0),
        IntField('lmChallengeResponseBufferOffset', 0),
        ShortField('ntChallengeResponseLen', 0),
        ShortField('ntChallengeResponseMaxLen', 0),
        IntField('ntChallengeResponseBufferOffset', 0),
        ShortField('domainNameLen', 0),
        ShortField('domainNameMax', 0),
        IntField('domainNameOffset', 0),
        ShortField('userNameLen', 0),
        ShortField('userNameMax', 0),
        IntField('userNameOffset', 0),
        ShortField('workstationLen', 0),
        ShortField('workstationMaxLen', 0),
        IntField('workstationBufferOffset', 0),
        ShortField('encryptedRandomSessionKeyLen', 0),
        ShortField('encryptedRandomSessionKeyMaxLen', 0),
        IntField('encryptedRandomSessionKeyBufferOffset', 0),
        FlagsField('negociateFlags', 0, 32, _negociate_flags),
        ByteField('productMajorVersion', 0),
        ByteField('productMinorVersion', 0),
        ShortField('productBuild', 0),
        ThreeBytesField('reserved', 0),
        ByteField('NTLMRevisionCurrent', 0),
        StrFixedLenField('MIC', '', 16),
        # payload field.
        # TODO: those challenges are structures that should be defined
        StrLenField('lmChallengeResponse', '',
                    length_from=lambda pkt: pkt.lmChallengeResponseLen),
        StrLenField('ntChallengeResponse', '',
                    length_from=lambda pkt: pkt.ntChallengeResponseLen),
        StrLenField('domainName', '',
                    length_from=lambda pkt: pkt.domainNameLen),
        StrLenField('userName', '',
                    length_from=lambda pkt: pkt.userNameLen),
        StrLenField('workstation', '',
                    length_from=lambda pkt: pkt.workstationLen),
        StrLenField('encryptedRandomSessionKey', '',
                    length_from=lambda pkt: pkt.encryptedRandomSessionKeyLen)
    ]

    def extract_padding(self, p):
        return b"", p


NTLMSSPLE = _make_le(NTLMSSP)

_opcDa_auth_classes = {
    10: [NTLMSSP, NTLMSSPLE],
}


class OpcDaAuth3(Packet):
    name = "Auth3"
    fields_desc = [
        ShortField('code?', 5840),
        ShortField('code2?', 5840),
        ByteField('authType', 10),
        ByteField('authLevel', 2),
        ByteField('authPadLen', 0),
        ByteField('authReserved', 0),
        IntField('authContextId', 0),
    ]

    def guess_payload_class(self, payload):
        try:
            return _opcDa_auth_classes[self.authType][
                self.__class__.__name__.endswith("LE")
            ]
        except Exception:
            pass


OpcDaAuth3LE = _make_le(OpcDaAuth3)


# A client sends a request PDU when it wants to execute a remote operation.
#  In a multi-PDU request, the request consists of a series of request PDUs
#  with the same sequence number and monotonically increasing fragment
#  numbers. The body of a request PDU contains data that represents input
#  parameters for the operation.

class RequestStubData(Packet):
    name = 'RequestStubData'
    fields_desc = [
        ShortField('versionMajor', 0),
        ShortField('versionMinor', 0),
        StrField('stubdata', ''),
    ]

    def extract_padding(self, p):
        return b"", p


RequestStubDataLE = _make_le(RequestStubData)


def _opc_stubdata_length(pkt):
    if not pkt.underlayer or not isinstance(pkt.underlayer, OpcDaHeaderN):
        return 0
    stub_data_length = pkt.underlayer.fragLength - 24
    stub_data_length -= pkt.underlayer.authLength
    if (OpcDaHeaderMessage in pkt.firstlayer() and
            pkt.firstlayer()[OpcDaHeaderMessage].pfc_flags & 'objectUuid'):
        stub_data_length -= 36
    return max(0, stub_data_length)


class OpcDaRequest(Packet):
    # DCE 1.1 RPC - 12.6.4.9
    name = "OpcDaRequest"
    fields_desc = [
        IntField('allocHint', 0),
        ShortField('contextId', 0),
        ShortField('opNum', 0),
        ConditionalField(
            UUIDField('uuid', str('0001' * 8), uuid_fmt=UUIDField.FORMAT_BE),
            lambda pkt: OpcDaHeaderMessage in pkt.firstlayer() and
            pkt.firstlayer()[OpcDaHeaderMessage].pfc_flags & 'objectUuid'
        ),
        PacketLenField('stubData', None, RequestStubData,
                       length_from=lambda pkt: _opc_stubdata_length(pkt)),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


OpcDaRequestLE = _make_le(OpcDaRequest)


# A client sends a ping PDU when it wants to inquire about an outstanding
#  request.
# A ping PDU contains no body data.
class OpcDaPing(Packet):
    # DCE 1.1 RPC - 12.5.3.7
    name = "OpcDaPing"
    fields_desc = []

    def extract_padding(self, p):
        return b"", p


# A server sends a response PDU if an operation invoked by an idempotent,
#  broadcast or at-most-once request executes successfully. Servers do not send
#  responses for maybe or broadcast/maybe requests. A multi-PDU response
#  consists of a series of response PDUs with the same sequence number and
#  monotonically increasing fragment numbers.
class OpcDaResponse(Packet):
    # DCE 1.1 RPC - 12.6.4.10
    name = "OpcDaResponse"
    fields_desc = [
        IntField('allocHint', 0),
        ShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        StrLenField('stubData', None,
                    length_from=lambda pkt:pkt.allocHint - 32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


OpcDaResponseLE = _make_le(OpcDaResponse)


# The fault PDU is used to indicate either an RPC run-time, RPC stub, or
#  RPC-specific exception to the client.
# Length of the stubdata egal allochint less header
class OpcDaFault(Packet):
    # DCE 1.1 RPC - 12.6.4.7
    name = "OpcDaFault"
    fields_desc = [
        IntField('allocHint', 0),
        ShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        IntEnumField('Group', 0, _faultStatus),
        IntField('reserved2', 0),
        StrLenField('stubData', None,
                    length_from=lambda pkt:pkt.allocHint - 32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


OpcDaFaultLE = _make_le(OpcDaFault)


# A server sends a working PDU in reply to a ping PDU. This reply indicates
#  that the server is processing the client's call.
# A working PDU contains no body data.
class OpcDaWorking(Packet):
    name = "OpcDaWorking"

    def extract_padding(self, p):
        return OpcDaFack


# A nocall PDU can optionally carry a body whose format is the same as the
# optional fack PDU body.
class OpcDaNoCall(Packet):
    name = "OpcDaNoCall"

    def extract_padding(self, p):
        return OpcDaFack


class OpcDaNoCallLE(Packet):
    name = "OpcDaNoCall"

    def extract_padding(self, p):
        return OpcDaFackLE


# A server sends a reject PDU if an RPC request is rejected. The body of
#  a reject PDU contains a status code indicating why a callee is rejecting
#  a request PDU from a caller.
class OpcDaReject(Packet):
    # DCE 1.1 RPC - 12.5.3.8
    name = "OpcDaReject"
    fields_desc = [
        IntField('allocHint', 0),
        ShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        IntEnumField('Group', 0, _rejectStatus),
        StrLenField('stubData', None,
                    length_from=lambda pkt:pkt.allocHint - 32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


OpcDaRejectLE = _make_le(OpcDaReject)


# A client sends an ack PDU after it has received a response to
#  an at-most-once request. An ack PDU explicitly acknowledges that the
#  client has received the response; it tells the server to cease resending
#  the response and discard the response PDU. (A client can also implicitly
#  acknowledge receipt of a response by sending a new request.)
# An ack PDU contains no body data.
class OpcDaAck(Packet):
    name = "OpcDaAck"

    def extract_padding(self, p):
        return b"", p


# The cancel PDU is used to forward a cancel.
class OpcDaCl_cancel(Packet):
    # DCE 1.1 RPC - 12.5.3.3
    name = "OpcDaCl_cancel"
    fields_desc = [
        PacketField('authentication', None, AuthentificationProtocol),
        IntField('version', 0),
        IntField('cancelId', 0),
    ]

    def extract_padding(self, p):
        return b"", p


OpcDaCl_cancelLE = _make_le(OpcDaCl_cancel)


#  Both clients and servers send fack PDUs.
# A client sends a fack PDU after it has received a fragment of a multi-PDU
#  response. A fack PDU explicitly acknowledges that the client has received
#  the fragment; it may tell the sender to stop sending for a while.
# A server sends a fack PDU after it has received a fragment of a multi-PDU
#  request. A fack PDU explicitly acknowledges that the server has received the
#  fragment; it may tell the sender to stop sending for a while.
class OpcDaFack(Packet):
    # DCE 1.1 RPC - 12.5.3.4
    name = "OpcDaFack"
    fields_desc = [
        ShortField('version', 0),
        ByteField('pad', 0),
        ShortField('windowSize', 0),
        IntField('maxTsdu', 0),
        IntField('maxFragSize', 0),
        ShortField('serialNum', 0),
        FieldLenField('selackLen', 0, count_of='selack', fmt="H"),
        PacketListField('selack', None, IntField,
                        count_from=lambda pkt:pkt.selackLen),
    ]

    def extract_padding(self, p):
        return b"", p


OpcDaFackLE = _make_le(OpcDaFack)


# A server sends a cancel_ack PDU after it has received a cancel PDU.
# A cancel_ack PDU acknowledges that the server has cancelled or orphaned
#  a remote call or indicates that the server is not accepting cancels.
# A ancel_ack PDUs can optionally have a body. A cancel_ack PDU without a body
#  acknowledges orphaning of a call, whereas a cancel_ack PDU with a body
#  acknowledges cancellation of a call. Orphaned calls do not perform any
#  further processing. Canceled calls transparently deliver a notification to
#  the server manager routine without altering the run-time system state of the
#  call. The run-time system's processing of a cancelled call continues
#  uninterrupted.
class OpcDaCancel_ack(Packet):
    # DCE 1.1 RPC - 12.5.3.2
    name = "OpcDaCancel_ack"
    fields_desc = [
        IntField('version', 0),
        IntField('cancelId', 0),
        ByteField('accepting', 1)
    ]

    def extract_padding(self, p):
        return b"", p


OpcDaCancel_ackLE = _make_le(OpcDaCancel_ack)


# The bind PDU is used to initiate the presentation negotiation for the body
#  data, and optionally, authentication. The presentation negotiation follows
#  the model of the OSI presentation layer.
class OpcDaBind(Packet):
    # DCE 1.1 RPC - 12.6.4.3
    name = "OpcDaBind"
    fields_desc = [
        ShortField('maxXmitFrag', 5840),
        ShortField('maxRecvtFrag', 5840),
        IntField('assocGroupId', 0),
        ByteField('nbContextElement', 1),
        ByteField('reserved', 0),
        ShortField('reserved2', 0),
        PacketListField('contextItem', None, ContextElement,
                        count_from=lambda pkt:pkt.nbContextElement),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


OpcDaBindLE = _make_le(OpcDaBind)


# The bind_ack PDU is returned by the server when it accepts a bind request
#  initiated by the client's bind PDU. It contains the results of presentation
#  context and fragment size negotiations. It may also contain a new
#  association group identifier if one was requested by the client.
class OpcDaBind_ack(Packet):
    # DCE 1.1 RPC - 12.6.4.4
    name = "OpcDaBind_ack"
    fields_desc = [
        ShortField('maxXmitFrag', 5840),
        ShortField('maxRecvtFrag', 5840),
        IntField('assocGroupId', 0),
        PacketField('portSpec', '\x00\x00\x00\x00', LenStringPacket),
        IntField('pad2', 0),
        PacketField('resultList', None, ResultList),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


OpcDaBind_ackLE = _make_le(OpcDaBind_ack)


# The bind_nak PDU is returned by the server when it rejects an association
#  request initiated by the client's bind PDU. The provider_reject_reason field
#  holds the rejection reason code. When the reject reason is
#  protocol_version_not_supported, the versions field contains a list of
#  run-time protocol versions supported by the server.
class OpcDaBind_nak(Packet):
    # DCE 1.1 RPC - 12.6.4.5
    name = "OpcDaBind_nak"
    fields_desc = [
        ShortEnumField("providerRejectReason", 0, _rejectBindNack)
    ]  # To complete

    def extract_padding(self, p):
        return b"", p


OpcDaBind_nakLE = _make_le(OpcDaBind_nak)


# The alter_context PDU is used to request additional presentation negotiation
#  for another interface and/or version, or to negotiate a new security
#  context, or both.
class OpcDaAlter_context(Packet):
    # DCE 1.1 RPC - 12.6.4.1
    name = "OpcDaAlter_context"
    fields_desc = [
        ShortField('maxXmitFrag', 5840),
        ShortField('maxRecvtFrag', 5840),
        IntField('assocGroupId', 0),
        # PacketField('authentication', None, AuthentificationProtocol),
    ]  # To complete

    def extract_padding(self, p):
        return b"", p


OpcDaAlter_contextLE = _make_le(OpcDaAlter_context)


class OpcDaAlter_Context_Resp(Packet):
    # DCE 1.1 RPC - 12.6.4.2
    name = "OpcDaAlter_Context_Resp"
    fields_desc = [
        ShortField('maxXmitFrag', 5840),
        ShortField('maxRecvtFrag', 5840),
        IntField('assocGroupId', 0),
        PacketField('portSpec', '\x00\x00\x00\x00', LenStringPacket),
        IntField('pad2', 0),
        PacketField('resultList', None, ResultList),
        PacketField('authentication', None, AuthentificationProtocol),
    ]  # To complete

    def extract_padding(self, p):
        return b"", p


OpcDaAlter_Context_RespLE = _make_le(OpcDaAlter_Context_Resp)


# The shutdown PDU is sent by the server to request that a client terminate the
#  connection, freeing the related resources.
# The shutdown PDU never contains an authentication verifier even if
#  authentication services are in use.
class OpcDaShutdown(Packet):
    # DCE 1.1 RPC - 12.6.4.11
    name = "OpcDaShutdown"

    def extract_padding(self, p):
        return b"", p


# The cancel PDU is used to forward a cancel.
class OpcDaCo_cancel(Packet):
    # DCE 1.1 RPC - 12.5.3.3
    name = "OpcDaCO_cancel"
    fields_desc = [
        PacketField('authentication', None, AuthentificationProtocol),
        IntField('version', 0),
        IntField('cancelId', 0),
    ]

    def extract_padding(self, p):
        return b"", p


OpcDaCo_cancelLE = _make_le(OpcDaCo_cancel)


# The orphaned PDU is used by a client to notify a server that it is aborting a
#  request in progress that has not been entirely transmitted yet, or that it
#  is aborting a (possibly lengthy) response in progress.
class OpcDaOrphaned(AuthentificationProtocol):
    name = "OpcDaOrphaned"


# DCE 1.1 RPC sect 12
_opcDa_pdu_classes = {
    0: [OpcDaRequest, OpcDaRequestLE],
    1: [OpcDaPing, OpcDaPing],
    2: [OpcDaResponse, OpcDaResponseLE],
    3: [OpcDaFault, OpcDaFaultLE],
    4: [OpcDaWorking, OpcDaWorking],
    5: [OpcDaNoCall, OpcDaNoCallLE],
    6: [OpcDaReject, OpcDaRejectLE],
    7: [OpcDaAck, OpcDaAck],
    8: [OpcDaCl_cancel, OpcDaCl_cancelLE],
    9: [OpcDaFack, OpcDaFackLE],
    10: [OpcDaCancel_ack, OpcDaCancel_ackLE],
    11: [OpcDaBind, OpcDaBindLE],
    12: [OpcDaBind_ack, OpcDaBind_ackLE],
    13: [OpcDaBind_nak, OpcDaBind_nakLE],
    14: [OpcDaAlter_context, OpcDaAlter_contextLE],
    15: [OpcDaAlter_Context_Resp, OpcDaAlter_Context_RespLE],
    17: [OpcDaShutdown, OpcDaShutdown],
    18: [OpcDaCo_cancel, OpcDaCo_cancelLE],
    19: [OpcDaOrphaned, OpcDaOrphaned],
    # Not in the official documentation
    16: [OpcDaAuth3, OpcDaAuth3LE],
}


class OpcDaHeaderN(Packet):
    # Last 3 fields of the common fields, used for dispatching the PDUs
    name = "OpcDaHeaderNext"
    fields_desc = [
        ShortField('fragLength', 0),
        ShortEnumField('authLength', 0, _authentification_protocol),
        IntField('callID', 0)
    ]

    def guess_payload_class(self, payload):
        if self.underlayer:
            try:
                return _opcDa_pdu_classes[self.underlayer.pduType][
                    self.__class__.__name__.endswith("LE")
                ]
            except AttributeError:
                pass
        return conf.raw_layer


OpcDaHeaderNLE = _make_le(OpcDaHeaderN)


_opcda_next_header = {
    0: OpcDaHeaderN,
    1: OpcDaHeaderNLE
}


class OpcDaHeaderMessage(Packet):
    # An actual RPC PDU
    # DCE 1.1 RPC - 12.6.3.1
    name = "OpcDaHeader"
    deprecated_fields = {
        "pdu_type": ("pduType", "2.5.0"),
    }
    fields_desc = [
        ByteField('versionMajor', 0),
        ByteField('versionMinor', 0),
        ByteEnumField("pduType", 0, _pduType),
        FlagsField('pfc_flags', 0, 8, _pfc_flags),
        # Non-Delivery Report/Receipt  (NDR) Format Label
        # DCE 1.1 RPC - 14.1
        BitEnumField('integerRepresentation', 1, 4,
                     {0: "bigEndian", 1: "littleEndian"}),
        BitEnumField('characterRepresentation', 0, 4,
                     {0: "ascii", 1: "ebcdic"}),
        ByteEnumField('floatingPointRepresentation', 0,
                      {0: "ieee", 1: "vax", 2: "cray", 3: "ibm"}),
        ShortField('res', 0),
    ]

    def guess_payload_class(self, payload):
        try:
            return _opcda_next_header[self.integerRepresentation]
        except Exception:
            pass
# try:
#     return _opcDa_pdu_classes[self.pduType][self.integerRepresentation]
# except Exception:
#     pass


class OpcDaMessage(Packet):
    name = "OpcDaMessage"
    fields_desc = [
        PacketField('OpcDaMessage', None, OpcDaHeaderMessage)
    ]
