# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.


# scapy.contrib.description = Postgres PSQL Binary Protocol
# scapy.contrib.status = loads


from scapy.packet import Packet
from scapy.fields import ByteField, CharEnumField, IntEnumField, FieldLenField, PacketListField, StrLenField, XNBytesField


FRONTEND_MSG_TYPE = {
    b'B' : 'Bind',
    b'C': 'Close',
    b'd': 'CopyData',
    b'c': 'CopyDone',
    b'f': 'CopyFail',
    b'D': 'Describe',
    b'E': 'Execute',
    b'H': 'Flush',
    b'F': 'FunctionCall',
    b'P': 'Parse',
    b'p': 'PasswordMessage',
    b'Q': 'Query',
    b'S': 'Sync',
    b'X': 'Terminate'
}

BACKEND_MSG_TYPE = {
    b'R': 'Authentication',
    b'K': 'BackendKeyData',
    b'2': 'BindComplete',
    b'3': 'CloseComplete',
    b'C': 'CommandComplete',
    b'd': 'CopyData', # backend and frontend message
    b'c': 'CopyDone', # backend and frontend message
    b'G': 'CopyInResponse',
    b'H': 'CopyOutResponse',
    b'W': 'CopyBothResponse',
    b'D': 'DataRow',
    b'I': 'EmptyQueryResponse',
    b'E': 'ErrorResponse',
    b'V': 'FunctionCallResponse',
    b'v': 'NegotiateProtocolVersion',
    b'n': 'NoData',
    b'N': 'NoticeResponse',
    b'A': 'NotificationResponse',
    b't': 'ParameterDescription',
    b'S': 'ParameterStatus',
    b'1': 'ParseComplete',
    b's': 'PortalSuspended',
    b'Z': 'ReadyForQuery',
    b'T': 'RowDescription'
}

TAG_TO_PACKET_CLS = dict() # Lazy-defined

AUTH_CODES = {
    0: 'AuthenticationOk',
    1: 'AuthenticationKerberosV4',
    2: 'AuthenticationKerberosV5',
    3: 'AuthenticationCleartextPassword',
    4: 'AuthenticationCryptPassword',
    5: 'AuthenticationMD5Password',
    6: 'AuthenticationSCMCredential',
    7: 'AuthenticationGSS',
    8: 'AuthenticationGSSContinue',
    9: 'AuthenticationSSPI',
    10: 'AuthenticationSASL',
    11: 'AuthenticationSASLContinue',
    12: 'AuthenticationSASLFinal'
}


class Startup(Packet):
    name = 'Startup Request Packet'
    fields_desc = [
        FieldLenField("length", None, length_of="options", fmt="I", adjust=lambda pkt, x: x + 9),
        XNBytesField("protocol_version_major", 0x3, 2),
        XNBytesField("protocol_version_minor", 0x0, 2),
        StrLenField("options", "", length_from = lambda pkt: pkt.length - 9),
        ByteField("padding", 0x00)
    ]

def determine_pg_field(pkt, lst, cur, remain):
    if pkt.tag in TAG_TO_PACKET_CLS:
        return TAG_TO_PACKET_CLS[pkt.tag]
    else:
        return Packet

class BasePacket(Packet):
    name = 'Regular packet'
    fields_desc = [
        CharEnumField("tag", b'R', FRONTEND_MSG_TYPE),
        FieldLenField("len", None, fmt="I"),
        PacketListField("payload", [], next_cls_cb=determine_pg_field)
    ]

class AuthenticationRequest(Packet):
    name = 'Authentication Request'
    fields_desc = [
        CharEnumField("tag", b'R', BACKEND_MSG_TYPE),
        FieldLenField("len", None, length_of="optional", fmt="I", adjust=lambda pkt, x: x + 8),
        IntEnumField("method", default=0, enum=AUTH_CODES),
        StrLenField("optional", None, length_from = lambda pkt: pkt.len - 8)
    ]

class ParameterStatus(Packet):
    name = 'Parameter Status'
    fields_desc = [
        CharEnumField("tag", b'S', BACKEND_MSG_TYPE),
        FieldLenField("len", None, length_of="keyvalue", fmt="I", adjust=lambda pkt, x: x + 8),
        StrLenField("keyvalue", "", length_from = lambda pkt: pkt.len - 8),
    ]

class ErrorResponse(Packet):
    name = 'Error Response'
    fields_desc = [
        ByteField("tag", b'E'),
        FieldLenField("len", None, length_of="optional", fmt="I", adjust=lambda pkt, x: x + 4),
        IntEnumField("method", default=0, enum=AUTH_CODES),
        StrLenField("optional", "\0", length_from = lambda pkt: pkt.len - 4)
    ]

TAG_TO_PACKET_CLS = {
    b'R': AuthenticationRequest,
    b'S': ParameterStatus,
}