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

"""
Opc Data Access.
References: Data Access Custom Interface StanDard
Using the website: http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm

DCOM Remote Protocol.
References: Specifies Distributed Component Object Model (DCOM) Remote Protocol
Using the website: https://msdn.microsoft.com/en-us/library/cc226801.aspx
"""

import uuid

from scapy.compat import plain_str
from scapy.config import conf
from scapy.fields import Field, ByteField, ShortField, LEShortField, \
    IntField, LEIntField, LongField, LELongField, StrField, StrLenField, \
    StrFixedLenField, BitEnumField, ByteEnumField, ShortEnumField, \
    LEShortEnumField, IntEnumField, LEIntEnumField, FieldLenField, \
    LEFieldLenField, PacketField, PacketListField, PacketLenField, \
    ConditionalField, FlagsField
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


#  Sub class for dissection
class AuthentificationProtocol(Packet):
    name = 'authentificationProtocol'

    def extract_padding(self, p):
        return b"", p

    def guess_payload_class(self, payload):
        if self.underlayer and hasattr(self.underlayer, "auth_length"):
            auth_length = self.underlayer.auth_length
            if auth_length != 0:
                try:
                    return _authentification_protocol[auth_length]
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


class PUUID(Field):
    __slots__ = ["endianType"]

    def __init__(self, name, default, endianType):
        _repr = {0: 'bigEndian', 1: 'littleEndian'}
        Field.__init__(self, name, default, "16s")
        self.endianType = _repr[endianType]

    def h2i(self, pkt, x):
        """ Description: transform a string uuid in uuid type object """
        self.default = uuid.UUID(plain_str(x or ""))
        return self.default

    def i2h(self, pkt, x):
        """ Description: transform a type uuid object in string uuid """
        x = str(self.default)
        return x

    def m2i(self, pkt, x):
        """ Description: transform a byte string uuid in uuid type object """
        if self.endianType == 'bigEndian':
            self.default = uuid.UUID(bytes=x)
        elif self.endianType == 'littleEndian':
            self.default = uuid.UUID(bytes_le=x)
        return self.default

    def i2m(self, pkt, x):
        """ Description: transform a uuid type object in a byte string """
        if self.endianType == 'bigEndian':
            x = self.default.bytes
        elif self.endianType == 'littleEndian':
            x = self.default.bytes_le
        return x

    def i2repr(self, pkt, x):
        return str(self.default)

    def getfield(self, pkt, s):
        """ Extract an internal value from a string """
        self.default = self.m2i(pkt, s[:self.sz])
        return s[self.sz:], self.default

    def addfield(self, pkt, s, val):
        """ Add an internal value  to a string """
        return s + self.i2m(pkt, val)

    def any2i(self, pkt, x):
        """ Try to understand the most input values possible and make an
            internal value from them """
        return self.h2i(pkt, x)


class LenStringPacket(Packet):
    name = "len string packet"
    fields_desc = [
        FieldLenField('length', 0, length_of='data', fmt="H"),
        ConditionalField(StrLenField('data', None,
                         length_from=lambda pkt:pkt.length + 2),
                         lambda pkt:pkt.length == 0),
        ConditionalField(StrLenField('data', '',
                         length_from=lambda pkt:pkt.length),
                         lambda pkt:pkt.length != 0),
    ]

    def extract_padding(self, p):
        return b"", p


class LenStringPacketLE(Packet):
    name = "len string packet"
    fields_desc = [
        LEFieldLenField('length', 0, length_of='data', fmt="<H"),
        ConditionalField(StrLenField('data', None,
                         length_from=lambda pkt:pkt.length + 2),
                         lambda pkt:pkt.length == 0),
        ConditionalField(StrLenField('data', '',
                         length_from=lambda pkt:pkt.length),
                         lambda pkt:pkt.length != 0),
    ]

    def extract_padding(self, p):
        return b"", p


class SyntaxId(Packet):
    name = "syntax Id"
    fields_desc = [
        PUUID('interfaceUUID', str('0001' * 8), 0),
        ShortField('versionMajor', 0),
        ShortField('versionMinor', 0),
    ]

    def extract_padding(self, p):
        return b"", p


class SyntaxIdLE(Packet):
    name = "syntax Id"
    fields_desc = [
        PUUID('interfaceUUID', str('0001' * 8), 1),
        LEShortField('versionMajor', 0),
        LEShortField('versionMinor', 0),
    ]

    def extract_padding(self, p):
        return b"", p


class ResultElement(Packet):
    name = "result"
    fields_desc = [
        ShortEnumField('resultContextNegotiation', 0, _defResult),
        ConditionalField(LEShortEnumField('reason', 0, _defReason),
                         lambda pkt:pkt.resultContextNegotiation != 0),
        PacketField('transferSyntax', '\x00' * 20, SyntaxId),
    ]

    def extract_padding(self, p):
        return b"", p


class ResultElementLE(Packet):
    name = "result"
    fields_desc = [
        LEShortEnumField('resultContextNegotiation', 0, _defResult),
        ConditionalField(LEShortEnumField('reason', 0, _defReason),
                         lambda pkt:pkt.resultContextNegotiation != 0),
        PacketField('transferSyntax', '\x00' * 20, SyntaxId),
    ]

    def extract_padding(self, p):
        return b"", p


class ResultList(Packet):
    name = "list result"
    fields_desc = [
        ByteField('nbResult', 0),
        ByteField('reserved', 0),
        ShortField('reserved2', 0),
        PacketListField('resultList', None, ResultElement,
                        count_from=lambda pkt:pkt.nbResult),
    ]

    def extract_padding(self, p):
        return b"", p


class ResultListLE(Packet):
    name = "list result"
    fields_desc = [
        ByteField('nbResult', 0),
        ByteField('reserved', 0),
        ShortField('reserved2', 0),
        PacketListField('resultList', None, ResultElementLE,
                        count_from=lambda pkt:pkt.nbResult),
    ]

    def extract_padding(self, p):
        return b"", p


class ContextElment(Packet):
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


class ContextElmentLE(Packet):
    name = "context element"
    fields_desc = [
        LEShortField('contxtId', 0),
        ByteField('nbTransferSyn', 0),
        ByteField('reserved', 0),
        PacketField('abstractSyntax', None, SyntaxIdLE),
        PacketListField('transferSyntax', None, SyntaxIdLE,
                        count_from=lambda pkt:pkt.nbTransferSyn),
    ]

    def extract_padding(self, p):
        return b"", p


# Only in Little-Endian
class STDOBJREF(Packet):
    name = 'stdObjRef'
    fields_desc = [
        LEIntEnumField('flags', 1, {0: 'PINGING', 8: 'SORF_NOPING'}),
        LEIntField('cPublicRefs', 0),
        LELongField('OXID', 0),
        LELongField('OID', 0),
        PacketField('IPID', None, PUUID),
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


class DualStringArrayLE(Packet):
    name = "Dual String Array"
    fields_desc = [
        LEShortField('wNumEntries', 0),
        LEShortField('wSecurityOffset', 0),
        StrFixedLenField('StringBinding', '',
                         length_from=lambda pkt:pkt.wSecurityOffset),
    ]


class OBJREF_STANDARD(Packet):
    name = "objetref stanDard"
    fields_desc = [
        PacketField('std', None, STDOBJREF),
        PacketField('saResAddr', None, DualStringArray),
    ]


class OBJREF_STANDARDLE(Packet):
    name = "objetref stanDard"
    fields_desc = [
        PacketField('std', None, STDOBJREF),
        PacketField('saResAddr', None, DualStringArrayLE),
    ]


class OBJREF_HANDLER(Packet):
    name = "objetref stanDard"
    fields_desc = [
        PacketField('std', None, STDOBJREF),
        PUUID('clsid', str('0001' * 8), 0),
        PacketField('saResAddr', None, DualStringArray),
    ]


class OBJREF_HANDLERLE(Packet):
    name = "objetref stanDard"
    fields_desc = [
        PacketField('std', None, STDOBJREF),
        PUUID('clsid', str('0001' * 8), 1),
        PacketField('saResAddr', None, DualStringArrayLE),
    ]


class OBJREF_CUSTOM(Packet):
    name = "objetref stanDard"
    fields_desc = [
        PUUID('clsid', str('0001' * 8), 0),
        IntField('cbExtension', 0),
        IntField('reserved', 0),
    ]


class OBJREF_CUSTOMLE(Packet):
    name = "objetref stanDard"
    fields_desc = [
        PUUID('clsid', str('0001' * 8), 1),
        LEIntField('cbExtension', 0),
        LEIntField('reserved', 0),
    ]


class OBJREF_EXTENDED(Packet):
    name = "objetref stanDard"
    fields_desc = [

    ]


class OBJREF_EXTENDEDLE(Packet):
    name = "objetref stanDard"
    fields_desc = [

    ]


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
            return _objref_pdu[self.flag][1]
        except Exception:
            pass


class IRemoteSCMActivator_RemoteCreateInstanceLE(Packet):
    name = 'RemoteCreateInstance'
    fields_desc = [
        LEShortField('versionMajor', 0),
        LEShortField('versionMinor', 0),
        LEIntEnumField('flag', 1, _objref_flag),
        LEIntField('reserved', 0),
    ]

    def guess_payload_class(self, payload):
        try:
            return _objref_pdu[self.flag][1]
        except Exception:
            pass


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


# Not in the official Documentation
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


class AttributeName(Packet):
    name = "Attribute"
    fields_desc = [
        ShortEnumField('attributeItemType', 2, _attribute_type),
        ShortField('attributeItemLen', 0),
        StrLenField('attributeItem', '',
                    length_from=lambda pkt:pkt.responseItemLen),
    ]

    def extract_padding(self, p):
        return b"", p


# Next version adapte the type with one PDU
class AttributeNameLE(Packet):
    name = "Attribute"
    fields_desc = [
        LEShortEnumField('attributeItemType', 2, _attribute_type),
        LEShortField('attributeItemLen', 0),
        StrLenField('attributeItem', '',
                    length_from=lambda pkt:pkt.attributeItemLen),
    ]

    def extract_padding(self, p):
        return b"", p


class NTLMSSP(Packet):
    name = 'NTLM Secure Service Provider'
    fields_desc = [
        StrFixedLenField('identifier', 'NTLMSSP', length=8),
        IntEnumField('messageType', 3, {3: 'NTLMSSP_AUTH'}),
        ShortField('lanManagerLen', 0),
        ShortField('lanManagerMax', 0),
        ShortField('lanManagerOffset', 0),
        ShortField('NTLMRepLen', 0),
        ShortField('NTLMRepMax', 0),
        IntField('NTLMRepOffset', 0),
        ShortField('domainNameLen', 0),
        ShortField('domainNameMax', 0),
        IntField('domainNameOffset', 0),
        ShortField('userNameLen', 0),
        ShortField('userNameMax', 0),
        IntField('userNameOffset', 0),
        ShortField('hostNameLen', 0),
        ShortField('hostNameMax', 0),
        IntField('hostNameOffset', 0),
        ShortField('sessionKeyLen', 0),
        ShortField('sessionKeyMax', 0),
        IntField('sessionKeyOffset', 0),
        FlagsField('negociateFlags', 0, 32, _negociate_flags),
        ByteField('versionMajor', 0),
        ByteField('versionMinor', 0),
        ShortField('buildNumber', 0),
        ByteField('reserved', 0),
        ShortField('reserved2', 0),
        ByteField('NTLMCurrentRevision', 0),
        StrFixedLenField('MIC', '', 16),
        StrLenField('domainName', '',
                    length_from=lambda pkt: pkt.domainNameLen),
        StrLenField('userName', '', length_from=lambda pkt: pkt.userNameLen),
        StrLenField('hostName', '', length_from=lambda pkt: pkt.hostNameLen),
        StrLenField('lanManager', '',
                    length_from=lambda pkt: pkt.lanManagerLen),
        StrLenField('NTLMRep', '', length_from=lambda pkt: pkt.NTLMRepLen),
        ByteField('responseVersion', 0),
        ByteField('hiResponseVersion', 0),
        StrFixedLenField('Z', '', 6),
        LongField('timestamp', 0),  # Time in nanoseconde
        StrFixedLenField('clientChallenge', '', 8),
        IntField('Z', 0),
        PacketField('attributeNTLMV2', None, AttributeName),
        PacketField('attributeNTLMV2', None, AttributeName),
        PacketField('attributeNTLMV2', None, AttributeName),
        PacketField('attributeNTLMV2', None, AttributeName),
        PacketField('attributeNTLMV2', None, AttributeName),
        PacketField('attributeNTLMV2', None, AttributeName),
        PacketField('attributeNTLMV2', None, AttributeName),
        PacketField('attributeNTLMV2', None, AttributeName),
        PacketField('attributeNTLMV2', None, AttributeName),
        PacketField('attributeNTLMV2', None, AttributeName),
        IntField('Z', 0),
        IntField('padding', 0),
        StrLenField('sessionKey', '',
                    length_from=lambda pkt: pkt.sessionKeyLen),
    ]

    def extract_padding(self, p):
        return b"", p


class NTLMSSPLE(Packet):
    name = 'NTLM Secure Service Provider'
    fields_desc = [
        StrFixedLenField('identifier', 'NTLMSSP', length=8),
        LEIntEnumField('messageType', 3, {3: 'NTLMSSP_AUTH'}),
        LEShortField('lanManagerLen', 0),
        LEShortField('lanManagerMax', 0),
        LEIntField('lanManagerOffset', 0),
        LEShortField('NTLMRepLen', 0),
        LEShortField('NTLMRepMax', 0),
        LEIntField('NTLMRepOffset', 0),
        LEShortField('domainNameLen', 0),
        LEShortField('domainNameMax', 0),
        LEIntField('domainNameOffset', 0),
        LEShortField('userNameLen', 0),
        LEShortField('userNameMax', 0),
        LEIntField('userNameOffset', 0),
        LEShortField('hostNameLen', 0),
        LEShortField('hostNameMax', 0),
        LEIntField('hostNameOffset', 0),
        LEShortField('sessionKeyLen', 0),
        LEShortField('sessionKeyMax', 0),
        LEIntField('sessionKeyOffset', 0),
        FlagsField('negociateFlags', 0, 32, _negociate_flags),
        ByteField('versionMajor', 0),
        ByteField('versionMinor', 0),
        LEShortField('buildNumber', 0),
        ByteField('reserved', 0),
        ShortField('reserved2', 0),
        ByteField('NTLMCurrentRevision', 0),
        StrFixedLenField('MIC', '', 16),
        StrLenField('domainName', '',
                    length_from=lambda pkt: pkt.domainNameLen),
        StrLenField('userName', '', length_from=lambda pkt: pkt.userNameLen),
        StrLenField('hostName', '', length_from=lambda pkt: pkt.hostNameLen),
        StrLenField('lanManager', '',
                    length_from=lambda pkt: pkt.lanManagerLen),
        StrFixedLenField('NTLMRep', '', length=16),
        ByteField('responseVersion', 0),
        ByteField('hiResponseVersion', 0),
        StrFixedLenField('Z', '', 6),
        LELongField('timestamp', 0),  # Time in nanosecond
        StrFixedLenField('clientChallenge', '', 8),
        LEIntField('Z', 0),
        PacketField('attribute1', None, AttributeNameLE),
        PacketField('attribute2', None, AttributeNameLE),
        PacketField('attribute3', None, AttributeNameLE),
        PacketField('attribute4', None, AttributeNameLE),
        PacketField('attribute5', None, AttributeNameLE),
        PacketField('attribute6', None, AttributeNameLE),
        PacketField('attribute7', None, AttributeNameLE),
        PacketField('attribute8', None, AttributeNameLE),
        PacketField('attribute9', None, AttributeNameLE),
        PacketField('attribute10', None, AttributeNameLE),
        LEIntField('Z', 0),
        LEIntField('padding', 0),
        StrLenField('sessionKey', '',
                    length_from=lambda pkt: pkt.sessionKeyLen),
    ]

    def extract_padding(self, p):
        return b"", p


_opcDa_auth_classes = {
    10: [NTLMSSP, NTLMSSPLE],
}


class OpcDaAuth3LE(Packet):
    name = "Auth3"
    fields_desc = [
        LEShortField('code?', 5840),
        LEShortField('code2?', 5840),
        ByteField('authType', 10),
        ByteField('authLevel', 2),
        ByteField('authPadLen', 0),
        ByteField('authReserved', 0),
        LEIntField('authContextId', 0),
    ]

    def guess_payload_class(self, payload):
        try:
            return _opcDa_auth_classes[self.authType][1]
        except Exception:
            pass


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
            return _opcDa_auth_classes[self.authType][0]
        except Exception:
            pass


# A client sends a request PDU when it wants to execute a remote operation.
#  In a multi-PDU request, the request consists of a series of request PDUs
#  with the same sequence number and monotonically increasing fragment
#  numbers. The body of a request PDU contains data that represents input
#  parameters for the operation.
class RequestSubData(Packet):
    name = 'RequestSubData'
    fields_desc = [
        ShortField('versionMajor', 0),
        ShortField('versionMinor', 0),
        StrField('subdata', ''),
    ]

    def extract_padding(self, p):
        return b"", p


class RequestSubDataLE(Packet):
    name = 'RequestSubData'
    fields_desc = [
        LEShortField('versionMajor', 0),
        LEShortField('versionMinor', 0),
        LEIntField('flags', 0),
        LEIntField('reserved', 0),
        PUUID('subUuid', str('0001' * 8), 1),
        StrField('subdata', ''),
    ]

    def extract_padding(self, p):
        return b"", p


class OpcDaRequest(Packet):
    name = "OpcDaRequest"
    fields_desc = [
        IntField('allocHint', 0),
        ShortField('contextId', 0),
        ShortField('opNum', 0),
        PUUID('uuid', str('0001' * 8), 0),
        PacketLenField('subData', None, RequestSubData,
                       length_from=lambda pkt:pkt.allocHint),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


class OpcDaRequestLE(Packet):
    name = "OpcDaRequest"
    fields_desc = [
        LEIntField('allocHint', 0),
        LEShortField('contextId', 0),
        LEShortField('opNum', 0),
        PUUID('uuid', str('0001' * 8), 1),
        PacketLenField('subData', None, RequestSubDataLE,
                       length_from=lambda pkt:pkt.allocHint),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


# A client sends a ping PDU when it wants to inquire about an outstanding
#  request.
# A ping PDU contains no body data.
class OpcDaPing(Packet):
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
    name = "OpcDaResponse"
    fields_desc = [
        IntField('allocHint', 0),
        ShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        StrLenField('subData', None,
                    length_from=lambda pkt:pkt.allocHint - 32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


class OpcDaResponseLE(Packet):
    name = "OpcDaResponse"
    fields_desc = [
        LEIntField('allocHint', 0),
        LEShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        StrLenField('subData', None,
                    length_from=lambda pkt:pkt.allocHint - 32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


# The fault PDU is used to indicate either an RPC run-time, RPC stub, or
#  RPC-specific exception to the client.
# Length of the subdata egal allochint less header
class OpcDaFault(Packet):
    name = "OpcDaFault"
    fields_desc = [
        IntField('allocHint', 0),
        ShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        IntEnumField('Group', 0, _faultStatus),
        IntField('reserved2', 0),
        StrLenField('subData', None,
                    length_from=lambda pkt:pkt.allocHint - 32),
    ]

    def extract_padding(self, p):
        return b"", p


class OpcDaFaultLE(Packet):
    name = "OpcDaFault"
    fields_desc = [
        LEIntField('allocHint', 0),
        LEShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        LEIntEnumField('Group', 0, _faultStatus),
        LEIntField('reserved2', 0),
        StrLenField('subData', None,
                    length_from=lambda pkt:pkt.allocHint - 32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


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
    name = "OpcDaReject"
    fields_desc = [
        IntField('allocHint', 0),
        ShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        IntEnumField('Group', 0, _rejectStatus),
        StrLenField('subData', None,
                    length_from=lambda pkt:pkt.allocHint - 32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


class OpcDaRejectLE(Packet):
    name = "OpcDaReject"
    fields_desc = [
        LEIntField('allocHint', 0),
        LEShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        LEIntEnumField('Group', 0, _rejectStatus),
        StrLenField('subData', None,
                    length_from=lambda pkt: pkt.allocHint - 32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


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
    name = "OpcDaCl_cancel"
    fields_desc = [
        PacketField('authentication', None, AuthentificationProtocol),
        IntField('version', 0),
        IntField('cancelId', 0),
    ]

    def extract_padding(self, p):
        return b"", p


class OpcDaCl_cancelLE(Packet):
    name = "OpcDaCl_cancel"
    fields_desc = [
        PacketField('authentication', None, AuthentificationProtocol),
        LEIntField('version', 0),
        LEIntField('cancelId', 0),
    ]

    def extract_padding(self, p):
        return b"", p


#  Both clients and servers send fack PDUs.
# A client sends a fack PDU after it has received a fragment of a multi-PDU
#  response. A fack PDU explicitly acknowledges that the client has received
#  the fragment; it may tell the sender to stop sending for a while.
# A server sends a fack PDU after it has received a fragment of a multi-PDU
#  request. A fack PDU explicitly acknowledges that the server has received the
#  fragment; it may tell the sender to stop sending for a while.
class OpcDaFack(Packet):
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


class OpcDaFackLE(Packet):
    name = "OpcDaFackLE"
    fields_desc = [
        LEShortField('version', 0),
        ByteField('pad', 0),
        LEShortField('windowSize', 0),
        LEIntField('maxTsdu', 0),
        LEIntField('maxFragSize', 0),
        LEShortField('serialNum', 0),
        LEFieldLenField('selackLen', 0, count_of='selack', fmt="<H"),
        PacketListField('selack', None, LEIntField,
                        count_from=lambda pkt:pkt.selackLen),
    ]

    def extract_padding(self, p):
        return b"", p


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
    name = "OpcDaCancel_ack"
    fields_desc = [
        IntField('version', 0),
        IntField('cancelId', 0),
        ByteField('accepting', 1)
    ]

    def extract_padding(self, p):
        return b"", p


class OpcDaCancel_ackLE(Packet):
    name = "OpcDaCancel_ackLE"
    fields_desc = [
        LEIntField('version', 0),
        LEIntField('cancelId', 0),
        ByteField('accepting', 1)
    ]

    def extract_padding(self, p):
        return b"", p


# The bind PDU is used to initiate the presentation negotiation for the body
#  data, and optionally, authentication. The presentation negotiation follows
#  the model of the OSI presentation layer.
class OpcDaBind(Packet):
    name = "OpcDaBind"
    fields_desc = [
        ShortField('maxXmitFrag', 5840),
        ShortField('maxRecvtFrag', 5840),
        IntField('assocGroupId', 0),
        ByteField('nbContextElement', 1),
        ByteField('reserved', 0),
        ShortField('reserved2', 0),
        PacketListField('contextItem', None, ContextElment,
                        count_from=lambda pkt:pkt.nbContextElement),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


class OpcDaBindLE(Packet):
    name = "OpcDaBind"
    fields_desc = [
        LEShortField('maxXmitFrag', 5840),
        LEShortField('maxRecvtFrag', 5840),
        LEIntField('assocGroupId', 0),
        ByteField('nbContextElement', 1),
        ByteField('reserved', 0),
        LEShortField('reserved2', 0),
        PacketListField('contextItem', None, ContextElmentLE,
                        count_from=lambda pkt:pkt.nbContextElement),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


# The bind_ack PDU is returned by the server when it accepts a bind request
#  initiated by the client's bind PDU. It contains the results of presentation
#  context and fragment size negotiations. It may also contain a new
#  association group identifier if one was requested by the client.
class OpcDaBind_ack(Packet):
    name = "OpcDaBind_ack"
    fields_desc = [
        ShortField('maxXmitFrag', 5840),
        ShortField('maxRecvtFrag', 5840),
        IntField('assocGroupId', 0),
        PacketField('portSpec', '\x00\x00\x00\x00', LenStringPacket),
        IntField('pda2', 0),
        PacketField('resultList', None, ResultList),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


class OpcDaBind_ackLE(Packet):
    name = "OpcDaBind_ackLE"
    fields_desc = [
        LEShortField('maxXmitFrag', 5840),
        LEShortField('maxRecvtFrag', 5840),
        LEIntField('assocGroupId', 0),
        PacketField('portSpec', None, LenStringPacketLE),
        LEIntField('pda2', 0),
        PacketField('resultList', None, ResultListLE),
        PacketField('authentication', None, AuthentificationProtocol),
    ]

    def extract_padding(self, p):
        return b"", p


# The bind_nak PDU is returned by the server when it rejects an association
#  request initiated by the client's bind PDU. The provider_reject_reason field
#  holds the rejection reason code. When the reject reason is
#  protocol_version_not_supported, the versions field contains a list of
#  run-time protocol versions supported by the server.
class OpcDaBind_nak(Packet):
    name = "OpcDaBind_nak"
    fields_desc = [
        ShortEnumField("providerRejectReason", 0, _rejectBindNack)
    ]  # To complete

    def extract_padding(self, p):
        return b"", p


class OpcDaBind_nakLE(Packet):
    name = "OpcDaBind_nak"
    fields_desc = [
        LEShortEnumField("providerRejectReason", 0, _rejectBindNack)
    ]  # To complete

    def extract_padding(self, p):
        return b"", p


# The alter_context PDU is used to request additional presentation negotiation
#  for another interface and/or version, or to negotiate a new security
#  context, or both.
class OpcDaAlter_context(Packet):
    name = "OpcDaAlter_context"
    fields_desc = [
        ShortField('maxXmitFrag', 5840),
        ShortField('maxRecvtFrag', 5840),
        IntField('assocGroupId', 0),
        # PacketField('authentication', None, AuthentificationProtocol),
    ]  # To complete

    def extract_padding(self, p):
        return b"", p


class OpcDaAlter_contextLE(Packet):
    name = "OpcDaAlter_context"
    fields_desc = [
        LEShortField('maxXmitFrag', 5840),
        LEShortField('maxRecvtFrag', 5840),
        LEIntField('assocGroupId', 0),
        # PacketField('authentication', None, AuthentificationProtocol),
    ]  # To complete

    def extract_padding(self, p):
        return b"", p


class OpcDaAlter_Context_Resp(Packet):
    name = "OpcDaAlter_Context_Resp"
    fields_desc = [
        ShortField('maxXmitFrag', 5840),
        ShortField('maxRecvtFrag', 5840),
        IntField('assocGroupId', 0),
        PacketField('portSPec', '\x00\x00\x00\x00', LenStringPacket),
        LEIntField('numResult', 0),
        # PacketField('authentication', None, AuthentificationProtocol),
    ]  # To complete

    def extract_padding(self, p):
        return b"", p


class OpcDaAlter_Context_RespLE(Packet):
    name = "OpcDaAlter_Context_RespLE"
    fields_desc = [
        LEShortField('maxXmitFrag', 5840),
        LEShortField('maxRecvtFrag', 5840),
        LEIntField('assocGroupId', 0),
        PacketField('portSpec', '\x00\x00\x00\x00', LenStringPacketLE),
        LEIntField('numResult', 0),
        # PacketField('authentication', None, AuthentificationProtocol),
    ]  # To complete

    def extract_padding(self, p):
        return b"", p


# The shutdown PDU is sent by the server to request that a client terminate the
#  connection, freeing the related resources.
# The shutdown PDU never contains an authentication verifier even if
#  authentication services are in use.
class OpcDaShutdown(Packet):
    name = "OpcDaShutdown"

    def extract_padding(self, p):
        return b"", p


# The cancel PDU is used to forward a cancel.
class OpcDaCo_cancel(Packet):
    name = "OpcDaCO_cancel"
    fields_desc = [
        PacketField('authentication', None, AuthentificationProtocol),
        IntField('version', 0),
        IntField('cancelId', 0),
    ]

    def extract_padding(self, p):
        return b"", p


class OpcDaCo_cancelLE(Packet):
    name = "OpcDaCo_cancelLE"
    fields_desc = [
        PacketField('authentication', None, AuthentificationProtocol),
        LEIntField('version', 0),
        LEIntField('cancelId', 0),
    ]

    def extract_padding(self, p):
        return b"", p


# The orphaned PDU is used by a client to notify a server that it is aborting a
#  request in progress that has not been entirely transmitted yet, or that it
#  is aborting a (possibly lengthy) response in progress.
class OpcDaOrphaned(AuthentificationProtocol):
    name = "OpcDaOrphaned"


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
    9: [OpcDaFack, OpcDaFack],
    10: [OpcDaCancel_ack, OpcDaCancel_ackLE],
    11: [OpcDaBind, OpcDaBindLE],
    12: [OpcDaBind_ack, OpcDaBind_ackLE],
    13: [OpcDaBind_nak, OpcDaBind_nak],
    14: [OpcDaAlter_context, OpcDaAlter_contextLE],
    15: [OpcDaAlter_Context_Resp, OpcDaAlter_Context_RespLE],
    17: [OpcDaShutdown, OpcDaShutdown],
    18: [OpcDaCo_cancel, OpcDaCo_cancelLE],
    19: [OpcDaOrphaned, OpcDaOrphaned],
    # Not in the official documentation
    16: [OpcDaAuth3, OpcDaAuth3LE],
}


class OpcDaHeaderN(Packet):
    name = "OpcDaHeaderNext"
    fields_desc = [
        ShortField('fragLenght', 0),
        ShortEnumField('authLenght', 0, _authentification_protocol),
        IntField('callID', 0)
    ]

    def guess_payload_class(self, payload):
        if self.underlayer:
            try:
                return _opcDa_pdu_classes[self.underlayer.pdu_type][1]
            except AttributeError:
                pass
        return conf.raw_layer


class OpcDaHeaderNLE(OpcDaHeaderN):
    name = "OpcDaHeaderNextLE"
    fields_desc = [
        LEShortField('fragLenght', 0),
        LEShortEnumField('authLenght', 0, _authentification_protocol),
        LEIntField('callID', 0)
    ]


_opcda_next_header = {
    0: OpcDaHeaderN,
    1: OpcDaHeaderNLE
}


class OpcDaHeaderMessage(Packet):
    name = "OpcDaHeader"
    fields_desc = [
        ByteField('versionMajor', 0),
        ByteField('versionMinor', 0),
        ByteEnumField("pduType", 0, _pduType),
        FlagsField('pfc_flags', 0, 8, _pfc_flags),
        # Non-Delivery Report/Receipt  (NDR) Format Label
        BitEnumField('integerRepresentation', 1, 4,
                     {0: "bigEndian", 1: "littleEndian"}),
        BitEnumField('characterRepresentation', 0, 4,
                     {0: "ascii", 1: "ebcdic"}),
        ByteEnumField('floatingPointRepresentation', 0,
                      {0: "ieee", 1: "vax", 2: "cray", 3: "ibm"}),
        ByteField('reservedForFutur', 0),
        ByteField('reservedForFutur', 0),
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
