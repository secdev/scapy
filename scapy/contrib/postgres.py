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

import struct

from scapy.fields import (
    ByteField,
    CharEnumField,
    FieldLenField,
    IntEnumField,
    PacketListField,
    ShortField,
    SignedIntField,
    SignedShortField,
    StrLenField,
    StrNullField,
)
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import TCP


# Based heavily on the information provided here https://beta.pgcon.org/2014/schedule/attachments/330_postgres-for-the-wire.pdf

FRONTEND_MSG_TYPE = {
    b"B": "Bind",
    b"C": "Close",
    b"d": "CopyData",
    b"c": "CopyDone",
    b"f": "CopyFail",
    b"D": "Describe",
    b"E": "Execute",
    b"H": "Flush",
    b"F": "FunctionCall",
    b"P": "Parse",
    b"p": "PasswordMessage",
    b"Q": "Query",
    b"S": "Sync",
    b"X": "Terminate",
}

BACKEND_MSG_TYPE = {
    b"R": "Authentication",
    b"K": "BackendKeyData",
    b"2": "BindComplete",
    b"3": "CloseComplete",
    b"C": "CommandComplete",
    b"d": "CopyData",  # backend and frontend message
    b"c": "CopyDone",  # backend and frontend message
    b"G": "CopyInResponse",
    b"H": "CopyOutResponse",
    b"W": "CopyBothResponse",
    b"D": "DataRow",
    b"I": "EmptyQueryResponse",
    b"E": "ErrorResponse",
    b"V": "FunctionCallResponse",
    b"v": "NegotiateProtocolVersion",
    b"n": "NoData",
    b"N": "NoticeResponse",
    b"A": "NotificationResponse",
    b"t": "ParameterDescription",
    b"S": "ParameterStatus",
    b"1": "ParseComplete",
    b"s": "PortalSuspended",
    b"Z": "ReadyForQuery",
    b"T": "RowDescription",
}

AUTH_CODES = {
    0: "AuthenticationOk",
    1: "AuthenticationKerberosV4",
    2: "AuthenticationKerberosV5",
    3: "AuthenticationCleartextPassword",
    4: "AuthenticationCryptPassword",
    5: "AuthenticationMD5Password",
    6: "AuthenticationSCMCredential",
    7: "AuthenticationGSS",
    8: "AuthenticationGSSContinue",
    9: "AuthenticationSSPI",
    10: "AuthenticationSASL",
    11: "AuthenticationSASLContinue",
    12: "AuthenticationSASLFinal",
}

class KeepAlive(Packet):
    name = "Keep Alive"
    fields_desc = [
        FieldLenField(
            "length", None, fmt="I"
        ),
    ]

class SSLRequest(Packet):
    name = "SSL request code message"
    fields_desc = [
        FieldLenField(
            "length", None, fmt="I"
        ),
        SignedIntField("request_code", 0),
    ]


class Startup(Packet):
    name = "Startup Request Packet"
    fields_desc = [
        FieldLenField(
            "length", None, length_of="options", fmt="I", adjust=lambda pkt, x: x + 9
        ),
        ShortField("protocol_version_major", 3),
        ShortField("protocol_version_minor", 0),
        StrLenField("options", "", length_from=lambda pkt: pkt.length - 9),
        ByteField("padding", 0x00),
    ]


def determine_pg_field(pkt, lst, cur, remain):
    key = b""
    if remain:
        key = bytes(chr(remain[0]), "ascii")
    if key in pkt.cls_mapping:
        return pkt.cls_mapping[key]
    elif remain[0] == 0:
        length = struct.unpack("!I", remain[0:3])[0]
        if length == 0:
            return KeepAlive
        elif length == 8:
            return SSLRequest
        else:
            return Startup
    else:
        return None


class _BasePostgres(Packet):
    name = "Regular packet"
    fields_desc = [PacketListField("contents", [], next_cls_cb=determine_pg_field)]

    @classmethod
    def tcp_reassemble(cls, data, metadata):
        if data[0] == 0:
            length = struct.unpack("!I", data[0:3])[0]
            if length == 8:
                return SSLRequest(data)
            else:
                return Startup(data)
        else:
            return cls(data)


class _ZeroPadding(Packet):
    def extract_padding(self, p):
        return b"", p


class Authentication(_ZeroPadding):
    name = "Authentication Request"
    fields_desc = [
        CharEnumField("tag", b"R", BACKEND_MSG_TYPE),
        FieldLenField(
            "len", None, length_of="optional", fmt="I", adjust=lambda pkt, x: x + 8
        ),
        IntEnumField("method", default=0, enum=AUTH_CODES),
        StrLenField("optional", None, length_from=lambda pkt: pkt.len - 8),
    ]


class ParameterStatus(_ZeroPadding):
    name = "Parameter Status"
    fields_desc = [
        CharEnumField("tag", b"S", BACKEND_MSG_TYPE),
        FieldLenField("len", None, fmt="I"),
        StrNullField(
            "key",
            "",
        ),
        StrNullField(
            "value",
            "",
        ),
    ]


class Query(_ZeroPadding):
    name = "Simple Query"
    fields_desc = [
        CharEnumField("tag", b"Q", FRONTEND_MSG_TYPE),
        FieldLenField(
            "len", None, length_of="query", fmt="I", adjust=lambda pkt, x: x + 4
        ),
        StrNullField("query", ""),
    ]


class CommandComplete(_ZeroPadding):
    name = "Command Completion Response"
    fields_desc = [
        CharEnumField("tag", b"C", FRONTEND_MSG_TYPE),
        FieldLenField(
            "len", None, length_of="cmdtag", fmt="I", adjust=lambda pkt, x: x + 4
        ),
        StrLenField("cmdtag", "", length_from=lambda pkt: pkt.len - 4),
    ]


class BackendKeyData(_ZeroPadding):
    name = "Backend Key Data"
    fields_desc = [
        CharEnumField("tag", b"K", BACKEND_MSG_TYPE),
        FieldLenField("len", None, fmt="I"),
        SignedIntField("pid", 0),
        SignedIntField("key", 0),
    ]


STATUS_TYPE = {
    b"E": "InFailedTransaction",
    b"I": "Idle",
    b"T": "InTransaction",
}


class ReadyForQuery(_ZeroPadding):
    name = "Ready Signal"
    fields_desc = [
        CharEnumField("tag", b"Z", BACKEND_MSG_TYPE),
        FieldLenField(
            "len",
            None,
            fmt="I",
        ),
        CharEnumField("status", b"I", STATUS_TYPE),
    ]


class ColumnDescription(_ZeroPadding):
    name = "Column Description"
    fields_desc = [
        StrNullField("col", None),
        SignedIntField("tableoid", 0),
        SignedShortField("colno", 0),
        SignedIntField("typeoid", 0),
        SignedShortField("typelen", 0),
        SignedIntField("typemod", 0),
        SignedShortField("format", 0),
    ]


class RowDescription(_ZeroPadding):
    name = "Row Description"
    fields_desc = [
        CharEnumField("tag", b"T", BACKEND_MSG_TYPE),
        FieldLenField(
            "len",
            0,
            fmt="I",
        ),
        SignedShortField("numfields", 0),
        PacketListField(
            "cols",
            [],
            pkt_cls=ColumnDescription,
            count_from=lambda pkt: pkt.numfields,
            length_from=lambda pkt: pkt.len - 6,
        ),
    ]


class DataRow(_ZeroPadding):
    name = "Data Row"
    fields_desc = [
        CharEnumField("tag", b"D", BACKEND_MSG_TYPE),
        FieldLenField(
            "len",
            0,
            fmt="I",
        ),
        SignedShortField("numfields", 0),
        SignedIntField("fieldlen", 0),
        StrLenField("data", None, length_from=lambda pkt: pkt.len - 10),
    ]


class ErrorResponse(_ZeroPadding):
    name = "Error Response"
    fields_desc = [
        ByteField("tag", b"E"),
        FieldLenField(
            "len", None, length_of="optional", fmt="I", adjust=lambda pkt, x: x + 4
        ),
        IntEnumField("method", default=0, enum=AUTH_CODES),
        StrLenField("optional", "\0", length_from=lambda pkt: pkt.len - 4),
    ]


class Terminate(_ZeroPadding):
    name = "Termination Request"
    fields_desc = [
        ByteField("tag", b"X"),
        FieldLenField("len", None, fmt="I"),
    ]


class BindComplete(_ZeroPadding):
    name = "Bind Complete"
    fields_desc = [
        ByteField("tag", b"2"),
        FieldLenField("len", None, fmt="I"),
    ]


CLOSE_DESCRIBE_TYPE = {b"S": "PreparedStatement", b"P": "Portal"}


class Close(_ZeroPadding):
    name = "Close Request"
    fields_desc = [
        ByteField("tag", b"C"),
        FieldLenField(
            "len", None, length_of="statement", fmt="I", adjust=lambda pkt, x: x + 5
        ),
        CharEnumField("close_type", b"S", enum=CLOSE_DESCRIBE_TYPE),
        StrLenField("statement", None, length_from=lambda pkt: pkt.len - 5),
    ]


class CloseComplete(_ZeroPadding):
    name = "Close Complete"
    fields_desc = [
        ByteField("tag", b"3"),
        FieldLenField("len", None, fmt="I"),
    ]


class Describe(_ZeroPadding):
    name = "Describe"
    fields_desc = [
        ByteField("tag", b"C"),
        FieldLenField(
            "len", None, length_of="statement", fmt="I", adjust=lambda pkt, x: x + 5
        ),
        CharEnumField("close_type", b"S", enum=CLOSE_DESCRIBE_TYPE),
        StrLenField("statement", None, length_from=lambda pkt: pkt.len - 5),
    ]


class EmptyQueryResponse(_ZeroPadding):
    name = "Empty Query Response"
    fields_desc = [
        ByteField("tag", b"I"),
        FieldLenField("len", None, fmt="I"),
    ]


class Flush(_ZeroPadding):
    name = "Flush Request"
    fields_desc = [
        ByteField("tag", b"F"),
        FieldLenField("len", None, fmt="I"),
    ]


class NoData(_ZeroPadding):
    name = "No Data Response"
    fields_desc = [
        ByteField("tag", b"n"),
        FieldLenField("len", None, fmt="I"),
    ]


class ParseComplete(_ZeroPadding):
    name = "Parse Complete Response"
    fields_desc = [
        ByteField("tag", b"1"),
        FieldLenField("len", None, fmt="I"),
    ]


class PortalSuspended(_ZeroPadding):
    name = "Portal Suspended Response"
    fields_desc = [
        ByteField("tag", b"s"),
        FieldLenField("len", None, fmt="I"),
    ]


class Sync(_ZeroPadding):
    name = "Sync Request"
    fields_desc = [
        ByteField("tag", b"S"),
        FieldLenField("len", None, fmt="I"),
    ]


class Parse(_ZeroPadding):
    name = "Parse Request"
    fields_desc = [
        ByteField("tag", b"P"),
        FieldLenField("len", None, fmt="I"),
        StrNullField("destination", None),
        StrNullField("query", None),
        FieldLenField("num_param_dtypes", 0, fmt="H"),
        StrLenField("params", None, length_from=lambda pkt: pkt.num_param_dtypes * 4),
    ]


FRONTEND_TAG_TO_PACKET_CLS = {
    # b'B' : 'Bind',
    b"C": Close,
    # TODO : Implement copy stream.
    # b'd': 'CopyData',
    # b'c': 'CopyDone',
    # b'f': 'CopyFail',
    b"D": Describe,
    # b'E': 'Execute',
    b"H": Flush,
    # b'F': 'FunctionCall',
    b"P": Parse,
    # b'p': 'PasswordMessage',
    b"Q": Query,
    b"S": Sync,
    b"X": Terminate,
}

BACKEND_TAG_TO_PACKET_CLS = {
    b"R": Authentication,
    b"K": BackendKeyData,
    b"2": BindComplete,
    b"3": CloseComplete,
    b"C": CommandComplete,
    # TODO: Implement COPY stream
    # b'd': 'CopyData', # backend and frontend message
    # b'c': 'CopyDone', # backend and frontend message
    # b'G': 'CopyInResponse',
    # b'H': 'CopyOutResponse',
    # b'W': 'CopyBothResponse',
    b"D": DataRow,
    b"I": EmptyQueryResponse,
    # b'E': 'ErrorResponse',
    # b'V': 'FunctionCallResponse',
    # b'v': 'NegotiateProtocolVersion',
    b"n": NoData,
    # b'N': 'NoticeResponse',
    # b'A': 'NotificationResponse',
    # b't': 'ParameterDescription',
    b"S": ParameterStatus,
    b"1": ParseComplete,
    b"s": PortalSuspended,
    b"Z": ReadyForQuery,
    b"T": RowDescription,
}


class PostgresFrontend(_BasePostgres):
    cls_mapping = FRONTEND_TAG_TO_PACKET_CLS


class PostgresBackend(_BasePostgres):
    cls_mapping = BACKEND_TAG_TO_PACKET_CLS


bind_layers(TCP, PostgresFrontend, dport=5432)
bind_layers(TCP, PostgresBackend, sport=5432)
