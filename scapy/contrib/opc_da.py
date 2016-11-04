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
# @Date:   2016-10-18
# @Last modified by:   GuilaumeF
# @Last modified time: 2016-11-03 11:45:08

"""
Opc Data Access.
References : Data Access Custom Interface StanDard
Using the website : http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
"""

###############################################################################
###############################################################################
# Import
###############################################################################
###############################################################################

import binascii
from scapy.fields import *
from scapy.packet import Packet
import uuid #https://docs.python.org/2/library/uuid.html

###############################################################################
###############################################################################
# Global Variables
###############################################################################
###############################################################################

pfc_flag_objectUuid = 0
auth_length = 0
pdu_type = 0
etat = 0

###############################################################################
###############################################################################
# Defined values
###############################################################################
###############################################################################

_tagOPCDataSource = {
    1 : "OPC_DS_CACHE",
    2 : "OPC_DS_DEVICE"
}

_tagOPCBrowseType = {
    1 : "OPC_BRANCH",
    2 : "OPC_LEAF",
    3 : "OPC_FLAT"
}

_tagOPCNameSpaceType = {
    1 : "OPC_NS_HIERARCHIAL",
    2 : "OPC_NS_FLAT"
}

_tagOPCBrowseDirection = {
    1 : "OPC_BROWSE_UP",
    2 : "OPC_BROWSE_DOWN",
    3 : "OPC_BROWSE_TO"
}

_tagOPCEuType = {
    0 : "OPC_NOENUM",
    1 : "OPC_ANALOG",
    2 : "OPC_ENUMERATED"
}

_tagOPCServerState = {
    1 : "OPC_STATUS_RUNNING",
    2 : "OPC_STATUS_FAILED",
    3 : "OPC_STATUS_NOCONFIG",
    4 : "OPC_STATUS_SUSPENDED",
    5 : "OPC_STATUS_TEST",
    6 : "OPC_STATUS_COMM_FAULT"
}

_tagOPCEnumScope = {
    1 : "OPC_ENUM_PRIVATE_CONNECTIONS",
    2 : "OPC_ENUM_PUBLIC_CONNECTIONS",
    3 : "OPC_ENUM_ALL_CONNECTIONS",
    4 : "OPC_ENUM_PRIVATE",
    5 : "OPC_ENUM_PUBLIC",
    6 : "OPC_ENUM_ALL"
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
    382312475 : 'rpc_s_fault_object_not_found',
    382312497 : 'rpc_s_call_cancelled',
    382312564 : 'rpc_s_fault_addr_error',
    382312565 : 'rpc_s_fault_context_mismatch',
    382312566 : 'rpc_s_fault_fp_div_by_zero',
    382312567 : 'rpc_s_fault_fp_error',
    382312568 : 'rpc_s_fault_fp_overflow',
    382312569 : 'rpc_s_fault_fp_underflow',
    382312570 : 'rpc_s_fault_ill_inst',
    382312571 : 'rpc_s_fault_int_div_by_zero',
    382312572 : 'rpc_s_fault_int_overflow',
    382312573 : 'rpc_s_fault_invalid_bound',
    382312574 : 'rpc_s_fault_invalid_tag',
    382312575 : 'rpc_s_fault_pipe_closed',
    382312576 : 'rpc_s_fault_pipe_comm_error',
    382312577 : 'rpc_s_fault_pipe_discipline',
    382312578 : 'rpc_s_fault_pipe_empty',
    382312579 : 'rpc_s_fault_pipe_memory',
    382312580 : 'rpc_s_fault_pipe_order',
    382312582 : 'rpc_s_fault_remote_no_memory',
    382312583 : 'rpc_s_fault_unspec',
    382312723 : 'rpc_s_fault_user_defined',
    382312726 : 'rpc_s_fault_tx_open_failed',
    382312814 : 'rpc_s_fault_codeset_conv_error',
    382312816 : 'rpc_s_fault_no_client_stub',
    469762049 : 'nca_s_fault_int_div_by_zero',
    469762050 : 'nca_s_fault_addr_error',
    469762051 : 'nca_s_fault_fp_div_zero',
    469762052 : 'nca_s_fault_fp_underflow',
    469762053 : 'nca_s_fault_fp_overflow',
    469762054 : 'nca_s_fault_invalid_tag',
    469762055 : 'nca_s_fault_invalid_bound',
    469762061 : 'nca_s_fault_cancel',
    469762062 : 'nca_s_fault_ill_inst',
    469762063 : 'nca_s_fault_fp_error',
    469762064 : 'nca_s_fault_int_overflow',
    469762068 : 'nca_s_fault_pipe_empty',
    469762069 : 'nca_s_fault_pipe_closed',
    469762070 : 'nca_s_fault_pipe_order',
    469762071 : 'nca_s_fault_pipe_discipline',
    469762072 : 'nca_s_fault_pipe_comm_error',
    469762073 : 'nca_s_fault_pipe_memory',
    469762074 : 'nca_s_fault_context_mismatch',
    469762075 : 'nca_s_fault_remote_no_memory',
    469762081 : 'ncs_s_fault_user_defined',
    469762082 : 'nca_s_fault_tx_open_failed',
    469762083 : 'nca_s_fault_codeset_conv_error',
    469762084 : 'nca_s_fault_object_not_found',
    469762085 : 'nca_s_fault_no_client_stub',
}

_defResult = {
    0 : 'ACCEPTANCE',
    1 : 'USER_REJECTION',
    2 : 'PROVIDER_REJECTION',
}

_defReason = {
    0 : 'REASON_NOT_SPECIFIED',
    1 : 'ABSTRACT_SYNTAX_NOT_SUPPORTED',
    2 : 'PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED',
    3 : 'LOCAL_LIMIT_EXCEEDED',
}

_rejectBindNack = {
    0 : 'REASON_NOT_SPECIFIED',
    1 : 'TEMPORARY_CONGESTION',
    2 : 'LOCAL_LIMIT_EXCEEDED',
    3 : 'CALLED_PADDR_UNKNOWN',
    4 : 'PROTOCOL_VERSION_NOT_SUPPORTED',
    5 : 'DEFAULT_CONTEXT_NOT_SUPPORTED',
    6 : 'USER_DATA_NOT_READABLE',
    7 : 'NO_PSAP_AVAILABLE'
}

_rejectStatus = {
    469762056 : 'nca_rpc_version_mismatch',
    469762057 : 'nca_unspec_reject',
    469762058 : 'nca_s_bad_actid',
    469762059 : 'nca_who_are_you_failed',
    469762060 : 'nca_manager_not_entered',
    469827586 : 'nca_op_rng_error',
    469827587 : 'nca_unk_if',
    469827590 : 'nca_wrong_boot_time',
    469827593 : 'nca_s_you_crashed',
    469827595 : 'nca_proto_error',
    469827603 : 'nca_out_args_too_big',
    469827604 : 'nca_server_too_busy',
    469827607 : 'nca_unsupported_type',
    469762076 : 'nca_invalid_pres_context_id',
    469762077 : 'nca_unsupported_authn_level',
    469762079 : 'nca_invalid_checksum',
    469762080 : 'nca_invalid_crc'
}

_pduType = {
    0:"REQUEST",
    1:"PING",
    2:"RESPONSE",
    3:"FAULT",
    4:"WORKING",
    5:"NOCALL",
    6:"REJECT",
    7:"ACK",
    8:"CI_CANCEL",
    9:"FACK",
    10:"CANCEL_ACK",
    11:"BIND",
    12:"BIND_ACK",
    13:"BIND_NACK",
    14:"ALTER_CONTEXT",
    15:"ALTER_CONTEXT_RESP",
    17:"SHUTDOWN",
    18:"CO_CANCEL",
    19:"ORPHANED"
}

_authentification_protocol = {
    0 : 'None',
    1 : 'OsfDcePrivateKeyAuthentication',
}

###############################################################################
###############################################################################
#  Sub class for dissection
###############################################################################
###############################################################################

class AuthentificationProtocol(Packet):
    name = 'authentificationProtocol'
    def extract_padding(self, p):
        return "", p
    def guess_payload_class(self, payload):
        if auth_length != 0 :
            try :
                return _authentification_protocol[auth_length]
            except :
                pass
        else :
            return extract_padding(self, payload)


class OsfDcePrivateKeyAuthentification(Packet):
    name = "OsfDcePrivateKeyAuthentication"
    #TODO
    def extract_padding(self, p):
        return "", p

class OPCHandle(Packet):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "16s")
    def extract_padding(self, p):
        return "", p

class PUUID(Field):
    __slots__ = ["endianType"]
    def __init__(self, name, default, endianType):
        _repr = {0:'bigEndian', 1:'littleEndian'}
        Field.__init__(self, name, default, "16s")
        self.endianType = _repr[endianType]
    def h2i(self, pkt, x):
        """Descritption: Transform a string uuid in uuid type object"""
        if pkt is None:
            self.default = uuid.UUID(x)
        else:
            self.default = uuid.UUID(x)
        return self.default
    def i2h(self, pkt, x):
        """Descritption: Transform a type uuid object in string uuid"""
        x = str(self.default)
        return x
    def m2i(self, pkt, x):
        """Descritption: Transform a byte string uuid in uuid type object"""
        if self.endianType == 'bigEndian':
            self.default = uuid.UUID(bytes = x)
        elif self.endianType == 'littleEndian' :
            self.default = uuid.UUID(bytes_le = x)
        return self.default
    def i2m(self, pkt, x):
        """Descritption: Transform a uuid type object in a byte string"""
        if self.endianType == 'bigEndian':
            x = self.default.bytes
        elif self.endianType == 'littleEndian' :
            x = self.default.bytes_le
        return x
    def i2repr(self, pkt, x):
        return str(self.default)
    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        self.default = self.m2i(pkt, s[:self.sz])
        return  s[self.sz:], self.default
    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""
        return s+self.i2m(pkt, default)
    def any2i(self, pkt, x):
        """Try to understand the most input values possible and make an
            internal value from them"""
        return self.h2i(pkt, x)


class LenStringPacket(Packet):
    name = "len string packet"
    fields_desc = [
        FieldLenField('length', 0, length_of='data', fmt="H"),
        ConditionalField(StrLenField('data', None,
            length_from=lambda pkt:pkt.length+2),lambda pkt:pkt.length == 0),
        ConditionalField(StrLenField('data', '',
            length_from=lambda pkt:pkt.length),lambda pkt:pkt.length != 0),
        ]
    def extract_padding(self, p):
        return "", p

class LenStringPacketLE(Packet):
    name = "len string packet"
    fields_desc = [
        LEFieldLenField('length', 0, length_of='data', fmt="<H"),
        ConditionalField(StrLenField('data', None,
            length_from=lambda pkt:pkt.length+2),lambda pkt:pkt.length == 0),
        ConditionalField(StrLenField('data', '',
            length_from=lambda pkt:pkt.length),lambda pkt:pkt.length != 0),
        ]
    def extract_padding(self, p):
        return "", p

class SyntaxId(Packet):
    name = "syntax Id"
    fields_desc = [
        PUUID('interfaceUUID', str('0001'*8), 0),
        ShortField('versionMajor', 0),
        ShortField('versionMinor', 0),
    ]

class SyntaxIdLE(Packet):
    name = "syntax Id"
    fields_desc = [
        PUUID('interfaceUUID', str('0001'*8), 1),
        LEShortField('versionMajor', 0),
        LEShortField('versionMinor', 0),
    ]

class ResultElement(Packet):
    name = "result"
    fields_desc = [
        ShortEnumField('resultContextNegotiation', 0, _defResult),
        ConditionalField(LEShortEnumField('reason', 0, _defReason),
            lambda pkt:pkt.resultContextNegotiation != 0),
        PacketField('transferSyntax', '\x00'*20, SyntaxId),
    ]

class ResultList(Packet):
    name = "list result"
    fields_desc = [
        ByteField('nbResult', 0),
        ByteField('reserved', 0),
        ShortField('reserved2', 0),
        PacketListField('resultList', None, ResultElement,
                                count_from=lambda pkt:pkt.nbResult),
    ]

class ResultElementLE(Packet):
    name = "result"
    fields_desc = [
        LEShortEnumField('resultContextNegotiation', 0, _defResult),
        ConditionalField(LEShortEnumField('reason', 0, _defReason),
            lambda pkt:pkt.resultContextNegotiation != 0),
        PacketField('transferSyntax', '\x00'*20, SyntaxId),
    ]

class ResultListLE(Packet):
    name = "list result"
    fields_desc = [
        ByteField('nbResult', 0),
        ByteField('reserved', 0),
        ShortField('reserved2', 0),
        PacketListField('resultList', None, ResultElementLE,
                                count_from=lambda pkt:pkt.nbResult),
    ]

###############################################################################
# UUID defined for DCOM
###############################################################################

# MS-Dcom.pdf 1.9
_standardDcomEndpoint = {
    '000001a5-0000-0000-c000-000000000046' : "ActivationContextInfo",
    '00000338-0000-0000-c000-000000000046' : "ActivationPropertiesIn",
    '39c13a4d-011e-11d0-9675-0020afd8adb3' : "IUnknwon"
}

###############################################################################
###############################################################################

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
        return "", p

class RequestSubDataLE(Packet):
    name = 'RequestSubData'
    fields_desc = [
        LEShortField('versionMajor', 0),
        LEShortField('versionMinor', 0),
        LEIntField('flags',0),
        LEIntField('reserved',0),
        PUUID('uuid-test', str('0001'*8),1),
        StrField('subdata', ''),
    ]
    def extract_padding(self, p):
        return "", p


class OpcDaRequest(Packet):
    name = "OpcDaRequest"
    fields_desc = [
        IntField('allocHint', 0),
        ShortField('contextId', 0),
        ShortField('opNum', 0),
        PUUID("uuid", str('0001'*8), 0),
        PacketLenField('subData', None, RequestSubData,
            length_from=lambda pkt:pkt.allocHint),
        PacketField('authentication', None, AuthentificationProtocol),
    ]
    def extract_padding(self, p):
        return "", p

class OpcDaRequestLE(Packet):
    name = "OpcDaRequest"
    fields_desc = [
        LEIntField('allocHint', 0),
        LEShortField('contextId', 0),
        LEShortField('opNum', 0),
        PUUID("uuid", str('0001'*8), 1),
        PacketLenField('subData', None, RequestSubDataLE,
            length_from=lambda pkt:pkt.allocHint),
        PacketField('authentication', None, AuthentificationProtocol),
    ]
    def extract_padding(self, p):
        return "", p

# A client sends a ping PDU when it wants to inquire about an outstanding
#  request.
# A ping PDU contains no body data.
class OpcDaPing(Packet):
    name = "OpcDaPing"
    fields_desc = []
    def extract_padding(self, p):
        return "", p

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
        StrLenField('subData', None, length_from=lambda pkt:pkt.allocHint-32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]
    def extract_padding(self, p):
        return "", p

class OpcDaResponseLE(Packet):
    name = "OpcDaResponse"
    fields_desc = [
        LEIntField('allocHint', 0),
        LEShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        StrLenField('subData', None, length_from=lambda pkt:pkt.allocHint-32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]
    def extract_padding(self, p):
        return "", p

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
        StrLenField('subData', None, length_from=lambda pkt:pkt.allocHint-32),
    ]
    def extract_padding(self, p):
        return "", p

class OpcDaFaultLE(Packet):
    name = "OpcDaFault"
    fields_desc = [
        LEIntField('allocHint', 0),
        LEShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        LEIntEnumField('Group', 0, _faultStatus),
        LEIntField('reserved2', 0),
        StrLenField('subData', None, length_from=lambda pkt:pkt.allocHint-32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]
    def extract_padding(self, p):
        return "", p

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
        StrLenField('subData', None, length_from=lambda pkt:pkt.allocHint-32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]
    def extract_padding(self, p):
        return "", p

class OpcDaRejectLE(Packet):
    name = "OpcDaReject"
    fields_desc = [
        LEIntField('allocHint', 0),
        LEShortField('contextId', 0),
        ByteField('cancelCount', 0),
        ByteField('reserved', 0),
        LEIntEnumField('Group', 0, _rejectStatus),
        StrLenField('subData', None, length_from=lambda pkt:pkt.allocHint-32),
        PacketField('authentication', None, AuthentificationProtocol),
    ]
    def extract_padding(self, p):
        return "", p

# A client sends an ack PDU after it has received a response to
#  an at-most-once request. An ack PDU explicitly acknowledges that the
#  client has received the response; it tells the server to cease resending
#  the response and discard the response PDU. (A client can also implicitly
#  acknowledge receipt of a response by sending a new request.)
# An ack PDU contains no body data.
class OpcDaAck(Packet):
    name = "OpcDaAck"
    def extract_padding(self, p):
        return "", p

# The cancel PDU is used to forward a cancel.
class OpcDaCl_cancel(Packet):
    name = "OpcDaCl_cancel"
    fields_desc = [
        PacketField('authentication', None, AuthentificationProtocol),
        IntField('version', 0),
        IntField('cancelId', 0),
    ]
    def extract_padding(self, p):
        return "", p

class OpcDaCl_cancelLE(Packet):
    name = "OpcDaCl_cancel"
    fields_desc = [
        PacketField('authentication', None, AuthentificationProtocol),
        LEIntField('version', 0),
        LEIntField('cancelId', 0),
    ]
    def extract_padding(self, p):
        return "", p

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
        return "", p

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
        return "", p

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
        return "", p

class OpcDaCancel_ackLE(Packet):
    name = "OpcDaCancel_ackLE"
    fields_desc = [
        LEIntField('version', 0),
        LEIntField('cancelId', 0),
        ByteField('accepting', 1)
    ]
    def extract_padding(self, p):
        return "", p

# The bind PDU is used to initiate the presentation negotiation for the body
#  data, and optionally, authentication. The presentation negotiation follows
#  the model of the OSI presentation layer.
class OpcDaBind(Packet):
    name = "OpcDaBind"
    fields_desc = [
        ShortField('maxXmitFrag', 5840),
        ShortField('maxRecvtFrag', 5840),
        IntField('assocGroupId', 0),
        #
        # PacketField('authentication', None, AuthentificationProtocol),
    ] # To complete
    def extract_padding(self, p):
        return "", p

class OpcDaBindLE(Packet):
    name = "OpcDaBind"
    fields_desc = [
        LEShortField('maxXmitFrag', 5840),
        LEShortField('maxRecvtFrag', 5840),
        LEIntField('assocGroupId', 0),
        #
        # PacketField('authentication', None, AuthentificationProtocol),
    ] # To complete
    def extract_padding(self, p):
        return "", p

# The bind_ack PDU is returned by the server when it accepts a bind request
#  initiated by the client's bind PDU. It contains the results of presentation
#  context and fragment size negotiations. It may also contain a new association
#  group identifier if one was requested by the client.
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
        return "", p

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
        return "", p

# The bind_nak PDU is returned by the server when it rejects an association
#  request initiated by the client's bind PDU. The provider_reject_reason field
#  holds the rejection reason code. When the reject reason is
#  protocol_version_not_supported, the versions field contains a list of
#  run-time protocol versions supported by the server.
class OpcDaBind_nak(Packet):
    name = "OpcDaBind_nak"
    fields_desc = [
        ShortEnumField("providerRejectReason", 0, _rejectBindNack)
    ] # To complete
    def extract_padding(self, p):
        return "", p

class OpcDaBind_nakLE(Packet):
    name = "OpcDaBind_nak"
    fields_desc = [
        LEShortEnumField("providerRejectReason", 0, _rejectBindNack)
    ] # To complete
    def extract_padding(self, p):
        return "", p

# The alter_context PDU is used to request additional presentation negotiation
#  for another interface and/or version, or to negotiate a new security
#  context, or both.
class OpcDaAlter_context(Packet):
    name = "OpcDaAlter_context"
    fields_desc = [
        ShortField('maxXmitFrag', 5840),
        ShortField('maxRecvtFrag', 5840),
        IntField('assocGroupId', 0),
        #
        # PacketField('authentication', None, AuthentificationProtocol),
    ] # To complete
    def extract_padding(self, p):
        return "", p

class OpcDaAlter_contextLE(Packet):
    name = "OpcDaAlter_context"
    fields_desc = [
        LEShortField('maxXmitFrag', 5840),
        LEShortField('maxRecvtFrag', 5840),
        LEIntField('assocGroupId', 0),
        #
        # PacketField('authentication', None, AuthentificationProtocol),
    ] # To complete
    def extract_padding(self, p):
        return "", p


class OpcDaAlter_Context_Resp(Packet):
    name = "OpcDaAlter_Context_Resp"
    fields_desc = [
        ShortField('maxXmitFrag', 5840),
        ShortField('maxRecvtFrag', 5840),
        IntField('assocGroupId', 0),
        PacketField('portSPec', '\x00\x00\x00\x00', LenStringPacket),
        LEIntField('numResult', 0),
        #
        # PacketField('authentication', None, AuthentificationProtocol),
    ] # To complete
    def extract_padding(self, p):
        return "", p

class OpcDaAlter_Context_RespLE(Packet):
    name = "OpcDaAlter_Context_RespLE"
    fields_desc = [
        LEShortField('maxXmitFrag', 5840),
        LEShortField('maxRecvtFrag', 5840),
        LEIntField('assocGroupId', 0),
        PacketField('portSpec', '\x00\x00\x00\x00', LenStringPacketLE),
        LEIntField('numResult', 0),
        #
        # PacketField('authentication', None, AuthentificationProtocol),
    ] # To complete
    def extract_padding(self, p):
        return "", p

# The shutdown PDU is sent by the server to request that a client terminate the
#  connection, freeing the related resources.
# The shutdown PDU never contains an authentication verifier even if
#  authentication services are in use.
class OpcDaShutdown(Packet):
    name = "OpcDaShutdown"
    def extract_padding(self, p):
        return "", p

# The cancel PDU is used to forward a cancel.
class OpcDaCo_cancel(Packet):
    name = "OpcDaCO_cancel"
    fields_desc = [
        PacketField('authentication', None, AuthentificationProtocol),
        IntField('version', 0),
        IntField('cancelId', 0),
    ]
    def extract_padding(self, p):
        return "", p

class OpcDaCo_cancelLE(Packet):
    name = "OpcDaCo_cancelLE"
    fields_desc = [
        PacketField('authentication', None, AuthentificationProtocol),
        LEIntField('version', 0),
        LEIntField('cancelId', 0),
    ]
    def extract_padding(self, p):
        return "", p

# The orphaned PDU is used by a client to notify a server that it is aborting a
#  request in progress that has not been entirely transmitted yet, or that it
#  is aborting a (possibly lengthy) response in progress.
class OpcDaOrphaned(Packet):
    name = "OpcDaOrphaned"
    def guess_payload_class(self, payload):
        if auth_length != 0 :
            try :
                return _authentification_protocol[auth_length]
            except :
                pass


_opcDa_pdu_classes = {
    0: [OpcDaRequest,OpcDaRequestLE],
    1: [OpcDaPing,OpcDaPing],
    2: [OpcDaResponse,OpcDaResponseLE],
    3: [OpcDaFault,OpcDaFaultLE],
    4: [OpcDaWorking,OpcDaWorking],
    5: [OpcDaNoCall,OpcDaNoCallLE],
    6: [OpcDaReject,OpcDaRejectLE],
    7: [OpcDaAck,OpcDaAck],
    8: [OpcDaCl_cancel,OpcDaCl_cancelLE],
    9: [OpcDaFack,OpcDaFack],
    10: [OpcDaCancel_ack,OpcDaCancel_ackLE],
    11: [OpcDaBind,OpcDaBindLE],
    12: [OpcDaBind_ack,OpcDaBind_ackLE],
    13: [OpcDaBind_nak,OpcDaBind_nak],
    14: [OpcDaAlter_context,OpcDaAlter_contextLE],
    15: [OpcDaAlter_Context_Resp,OpcDaAlter_Context_RespLE],
    17: [OpcDaShutdown,OpcDaShutdown],
    18: [OpcDaCo_cancel,OpcDaCo_cancelLE],
    19: [OpcDaOrphaned,OpcDaOrphaned]
}


class OpcDaHeaderN(Packet):
    name = "OpcDaHeaderNext"
    fields_desc = [
        ShortField('fragLenght', 0),
        ShortEnumField('authLenght', 0, _authentification_protocol),
        IntField('callID', 0)
    ]
    def guess_payload_class(self, payload):
        global auth_length
        auth_length = self.authLenght
        try :
            return _opcDa_pdu_classes[pdu_type][0]
        except :
            pass

class OpcDaHeaderNLE(Packet):
    name = "OpcDaHeaderNextLE"
    fields_desc = [
        LEShortField('fragLenght', 0),
        LEShortEnumField('authLenght', 0, _authentification_protocol),
        LEIntField('callID', 0)
    ]
    def guess_payload_class(self, payload):
        global auth_length
        auth_length = self.authLenght
        try :
            return _opcDa_pdu_classes[pdu_type][1]
        except :
            pass

_opcda_next_header = {
    0 : OpcDaHeaderN,
    1 : OpcDaHeaderNLE
}

class OpcDaHeaderMessage (Packet):
    name = "OpcDaHeader"
    fields_desc = [
        ByteField('versionMajor', 0),
        ByteField('versionMinor', 0),
        ByteEnumField("pduType", 0, _pduType),
        FlagsField('pfc_flags', 0, 8, _pfc_flags),
        #Non-Delivery Report/Receipt  (NDR) Format Label
        BitEnumField('integerRepresentation', 1, 4,
                {0:"bigEndian", 1:"littleEndian"}),
        BitEnumField('characterRepresentation', 0, 4,
                {0:"ascii", 1:"ebcdic"}),
        ByteEnumField('floatingPointRepresentation', 0,
                {0:"ieee", 1:"vax", 2:"cray", 3:"ibm"}),
        ByteField('reservedForFutur', 0),
        ByteField('reservedForFutur', 0),
    ]

    def guess_payload_class(self, payload):
        global pfc_flag_objectUuid
        global pdu_type
        pfc_flag_objectUuid = self.pfc_flags & 10000000
        pdu_type = self.pduType
        try :
            return _opcda_next_header[self.integerRepresentation]
        except :
            pass
        # try :
        #     return _opcDa_pdu_classes[self.pduType][self.integerRepresentation]
        # except :
        #     pass

class OpcDaMessage (Packet):
    name = "OpcDaMessage"
    fields_desc = [
        PacketField('OpcDaMessage', None, OpcDaHeaderMessage)
    ]

if __name__ == '__main__':
    # OpcDa_packet_bind = '05000b03100000007400000002000000d016d0160000000002000'\
    # '000000001004301000000000000c00000000000004600000000045d888aeb1cc9119fe808'\
    # '002b10486002000000010001004301000000000000c000000000000046000000002c1cb76'\
    # 'c12984045030000000000000001000000'.decode('hex')
    # OpcDa_packet_request = '05000083100000008c00000009000000640000000400030007b00000f003000015384d9857f87b1c050007000000000000000000b71c168324e2c449875c7a9273739d9a0000000005000000000000000500000047005200500031000000000001000000e803000001000000000000000000020000000000000000000000000000000000c000000000000046'.decode('hex')
    OpcDa_packet_request = '050000831000000074000000050000004c0000000000030002fc0000ac030000b900764f3d063aaa050007000000000000000000c18e0a94d13a3647a5b6883fa4d4c0150000000028f80000ac030000e1b42e67158aaadf05000000010000000100000084b296b1b4ba1a10b69c00aa00341d07'.decode('hex')
    test_1 = OpcDaMessage(OpcDa_packet_request)
    test_1.show()
    #Request Ouverture Client 4 N°30
    # t = '56000000010007001ec400009c0a0000778bc2fa9d0246e50500070000000000000000000ee2be543ffc754fb9c9817d7f5d3f6f000000001500000000000000150000004f004600530043006c00690065006e00740020002d00200046006100630074006f007200790033000000'.decode('hex')
    # test2 = OpcDaRequestLE(t)
    # test2.show()

    #littleEndian bigEndian

    # Ouverture client 4 N°29
    # opcDaAlter_context_RespLEPacket_Dissect = \
    #     '05000f03100000003800000017000000d016d01645290800000000000100000000000000'\
    #     '045d888aeb1cc9119fe808002b10486002000000'.decode('hex')
    # elem1 = str(OpcDaMessage(opcDaAlter_context_RespLEPacket_Dissect))
    #
    # opcDaAlter_context_RespPacketLE_Build = OpcDaMessage(OpcDaMessage= \
    #     OpcDaHeaderMessage (versionMajor=5,versionMinor=0,pduType=15, \
    #     pfc_flags = 3,integerRepresentation='littleEndian',\
    #     characterRepresentation='ascii',floatingPointRepresentation='ieee',\
    #     reservedForFutur=0)/ OpcDaHeaderNLE(fragLenght=56,authLenght=0,callID=23)\
    #     / OpcDaAlter_Context_RespLE(maxXmitFrag=5840,maxRecvtFrag=5840,\
    #         assocGroupId=534853,portSpec=LenStringPacketLE(length=0,data='\x00\x00'),numResult=1)) \
    #     / '\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb'\
    #     '\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00'
    # elem2 = str(opcDaAlter_context_RespPacketLE_Build)
    #
    # OpcDaMessage(opcDaAlter_context_RespLEPacket_Dissect).show()
    # print '###########################################'
    # opcDaAlter_context_RespPacketLE_Build.show()
    # print elem1 == elem2

    # Retrouve uuid N°12
    # opcDaBind_ackLEPacket_Dissect = '05000c03100000005400000002000000d016d0164a2f'\
    #     '000004003133350000000200000000000000045d888aeb1cc9119fe808002b1048600200'\
    #     '0000030003000000000000000000000000000000000000000000'.decode('hex')
    # OpcDaMessage(opcDaBind_ackLEPacket_Dissect).show()

    # test=LenStringPacketLE(length=4,data='135\x00')
    # test1=LenStringPacketLE(length=0,data='\x00\x00')
    # test2=LenStringPacketLE(data=None)
    # test.show()
    # test1.show()
    # test2.show()
    # print str(test1) == str(test2)
