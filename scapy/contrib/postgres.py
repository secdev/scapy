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


from scapy.fields import (ByteField, CharEnumField, FieldLenField,
                          IntEnumField, IntField, PacketListField, ShortField, SignedIntField, SignedShortField,
                          StrLenField, StrNullField, XNBytesField)
from scapy.packet import Packet

__all__ = ["AuthenticationRequest", "BasePacket", "ColumnDescription", "CommandCompletion", "ErrorResponse", "KeyData", "ParameterStatus", "Ready", "RowDescription", "SimpleQuery", "Startup"]

# Based heavily on the information provided here https://beta.pgcon.org/2014/schedule/attachments/330_postgres-for-the-wire.pdf

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
    key = b''
    if remain:
        key = bytes(chr(remain[0]), 'ascii')
    if key in TAG_TO_PACKET_CLS:
        return TAG_TO_PACKET_CLS[key]
    else:
        return None

class BasePacket(Packet):
    name = 'Regular packet'
    fields_desc = [
        PacketListField("contents", [], next_cls_cb=determine_pg_field)
    ]

class PgComponentPacket(Packet):

    def extract_padding(self, p):
        return b"", p

class AuthenticationRequest(PgComponentPacket):
    name = 'Authentication Request'
    fields_desc = [
        CharEnumField("tag", b'R', BACKEND_MSG_TYPE),
        FieldLenField("len", None, length_of="optional", fmt="I", adjust=lambda pkt, x: x + 8),
        IntEnumField("method", default=0, enum=AUTH_CODES),
        StrLenField("optional", None, length_from = lambda pkt: pkt.len - 8)
    ]



class ParameterStatus(PgComponentPacket):
    name = 'Parameter Status'
    fields_desc = [
        CharEnumField("tag", b'S', BACKEND_MSG_TYPE),
        FieldLenField("len", None, length_of="keyvalue", fmt="I", adjust=lambda pkt, x: x + 4),
        StrLenField("keyvalue", "", length_from = lambda pkt: pkt.len - 4),
    ]

class SimpleQuery(PgComponentPacket):
    name = 'Simple Query'
    fields_desc = [
        CharEnumField("tag", b'Q', FRONTEND_MSG_TYPE),
        FieldLenField("len", None, length_of="query", fmt="I", adjust=lambda pkt, x: x + 4),
        StrLenField("query", "", length_from = lambda pkt: pkt.len - 4),
    ]

class CommandCompletion(PgComponentPacket):
    name = 'Command Completion Response'
    fields_desc = [
        CharEnumField("tag", b'C', FRONTEND_MSG_TYPE),
        FieldLenField("len", None, length_of="cmdtag", fmt="I", adjust=lambda pkt, x: x + 4),
        StrLenField("cmdtag", "", length_from = lambda pkt: pkt.len - 4),
    ]


class KeyData(PgComponentPacket):
    name = 'Backend Key Data'
    fields_desc = [
        CharEnumField("tag", b'K', BACKEND_MSG_TYPE),
        FieldLenField("len", None,  fmt="I"),
        SignedIntField("pid", 0),
        SignedIntField("key", 0),
    ]

STATUS_TYPE = {
    b'E': "E",
    b'I': "Idle",
    b'T': "T",
}

class Ready(PgComponentPacket):
    name = 'Ready Signal'
    fields_desc = [
        CharEnumField("tag", b'Z', BACKEND_MSG_TYPE),
        FieldLenField("len", None,  fmt="I",),
        CharEnumField("status", b'I', STATUS_TYPE),
    ]

class ColumnDescription(Packet):
    name = 'Column Description'
    fields_desc = [
        StrNullField("col", None),
        SignedIntField("tableoid", 0),
        SignedShortField("colno", 0),
        SignedIntField("typeoid", 0),
        SignedShortField("typelen", 0),
        SignedIntField("typemod", 0),
        SignedShortField("format", 0),
    ]

class RowDescription(PgComponentPacket):
    name = 'Row Description'
    fields_desc = [
        CharEnumField("tag", b'T', BACKEND_MSG_TYPE),
        FieldLenField("len", 0,  fmt="I",),
        SignedShortField("numfields", 0),
        PacketListField('cols', [], ColumnDescription, length_from=lambda pkt: pkt.len - 6)
    ]

class DataRow(PgComponentPacket):
    name = 'Data Row'
    fields_desc = [
        CharEnumField("tag", b'D', BACKEND_MSG_TYPE),
        FieldLenField("len", 0,  fmt="I",),
        SignedShortField("numfields", 0),
        SignedIntField("fieldlen", 0),
        PacketListField('data', [], ColumnDescription, length_from=lambda pkt: pkt.len - 6)
    ]

class ErrorResponse(PgComponentPacket):
    name = 'Error Response'
    fields_desc = [
        ByteField("tag", b'E'),
        FieldLenField("len", None, length_of="optional", fmt="I", adjust=lambda pkt, x: x + 4),
        IntEnumField("method", default=0, enum=AUTH_CODES),
        StrLenField("optional", "\0", length_from = lambda pkt: pkt.len - 4)
    ]

TAG_TO_PACKET_CLS = {
    b'C': CommandCompletion,
    b'D': DataRow,
    b'R': AuthenticationRequest,
    b'S': ParameterStatus,
    b'T': RowDescription,
    b'K': KeyData,
    b'Z': Ready,
    b'Q': SimpleQuery
}
