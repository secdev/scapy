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
from typing import Any

from scapy.fields import (
    ByteField,
    CharEnumField,
    FieldLenField,
    FieldListField,
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
from scapy.volatile import VolatileValue

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
        SignedIntField("len", 4),
    ]


class SSLRequest(Packet):
    name = "SSL request code message"
    fields_desc = [
        FieldLenField("length", None, fmt="I"),
        SignedIntField("request_code", 0),
    ]


class Startup(Packet):
    name = "Startup Request Packet"
    fields_desc = [
        FieldLenField(
            "len", None, length_of="options", fmt="I", adjust=lambda pkt, x: x + 9
        ),
        ShortField("protocol_version_major", 3),
        ShortField("protocol_version_minor", 0),
        StrLenField("options", "", length_from=lambda pkt: pkt.len - 9),
        ByteField("padding", 0x00),
    ]


def determine_pg_field(pkt, lst, cur, remain):
    key = b""
    if remain:
        key = bytes(chr(remain[0]), "ascii")
    if key in pkt.cls_mapping:
        return pkt.cls_mapping[key]
    elif remain[0] == 0 and len(remain) >= 4:
        length = struct.unpack("!I", remain[0:3])[0]
        if length == 0:
            return KeepAlive
        elif length == 8:
            return SSLRequest
        else:
            return Startup
    else:
        return None


class ByteTagField(ByteField):
    def __init__(self, default: bytes):
        super(ByteTagField, self).__init__("tag", ord(default))

    def randval(self) -> VolatileValue[Any]:
        return ord(self.default)


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
        ByteTagField(b"R"),
        FieldLenField(
            "len", None, length_of="optional", fmt="I", adjust=lambda pkt, x: x + 8
        ),
        IntEnumField("method", default=0, enum=AUTH_CODES),
        StrLenField("optional", None, length_from=lambda pkt: pkt.len - 8),
    ]


class ParameterStatus(_ZeroPadding):
    name = "Parameter Status"
    fields_desc = [
        ByteTagField(b"S"),
        FieldLenField("len", None, fmt="I"), # TODO : length_of
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
        ByteTagField(b"Q"),
        FieldLenField(
            "len", None, length_of="query", fmt="I", adjust=lambda pkt, x: x + 5
        ),
        StrNullField("query", None),
    ]


class CommandComplete(_ZeroPadding):
    name = "Command Completion Response"
    fields_desc = [
        ByteTagField(b"C"),
        FieldLenField(
            "len", None, length_of="cmdtag", fmt="I", adjust=lambda pkt, x: x + 4
        ),
        StrLenField("cmdtag", "", length_from=lambda pkt: pkt.len - 4),
    ]


class BackendKeyData(_ZeroPadding):
    name = "Backend Key Data"
    fields_desc = [
        ByteTagField(b"K"),
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
        ByteTagField(b"Z"),
        FieldLenField(
            "len",
            None,
            fmt="I", # TODO: length_of
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
        ByteTagField(b"T"),
        FieldLenField(
            "len",
            None,
            fmt="I", # TODO : length_of
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


class SignedIntStrPair(_ZeroPadding):
    name = "Bytes data"
    fields_desc = [
        FieldLenField("len", None, length_of="data", fmt="I"),
        StrLenField("data", None, length_from=lambda pkt: pkt.len),
    ]


class DataRow(_ZeroPadding):
    name = "Data Row"
    fields_desc = [
        ByteTagField(b"D"),
        FieldLenField(
            "len",
            None,
            fmt="I", # TODO : length_of
        ),
        SignedShortField("numfields", 0),
        PacketListField(
            "data",
            [],
            pkt_cls=SignedIntStrPair,
            count_from=lambda pkt: pkt.numfields,
            length_from=lambda pkt: pkt.len - 6,
        ),
    ]


# See https://www.postgresql.org/docs/current/protocol-error-fields.html
ERROR_FIELD = {
    "S": "Severity",
    "V": "SeverityNonLocalized",
    "C": "Code",
    "M": "Message",
    "D": "Detail",
    "H": "Hint",
    "P": "Position",
    "p": "InternalPosition",
    "q": "InternalQuery",
    "W": "Where",
    "s": "SchemaName",
    "t": "TableName",
    "c": "ColumnName",
    "d": "DataTypeName",
    "n": "ConstraintName",
    "F": "File",
    "L": "Line",
    "R": "Routine",
}


class ErrorResponseField(StrNullField):
    def m2i(self, pkt, x):
        """Unpack into a tuple of Field, Value."""
        i = super(ErrorResponseField, self).m2i(pkt, x)
        i_code = chr(i[0])
        return (ERROR_FIELD.get(i_code, i_code), i[1:])


class ErrorResponse(_ZeroPadding):
    name = "Error Response"
    fields_desc = [
        ByteTagField(b"E"),
        FieldLenField(
            "len", None, length_of="error_fields", fmt="I", adjust=lambda pkt, x: x + 5
        ),
        FieldListField(
            "error_fields",
            [],
            ErrorResponseField("value", None),
            length_from=lambda pkt: pkt.len - 5,
        ),
        ByteField("terminator", None),
    ]


class Terminate(_ZeroPadding):
    name = "Termination Request"
    fields_desc = [
        ByteTagField(b"X"),
        SignedIntField("len", 4),
    ]


class BindComplete(_ZeroPadding):
    name = "Bind Complete"
    fields_desc = [
        ByteTagField(b"2"),
        SignedIntField("len", 4),
    ]


CLOSE_DESCRIBE_TYPE = {b"S": "PreparedStatement", b"P": "Portal"}


class Close(_ZeroPadding):
    name = "Close Request"
    fields_desc = [
        ByteTagField(b"C"),
        FieldLenField(
            "len", None, length_of="statement", fmt="I", adjust=lambda pkt, x: x + 5
        ),
        CharEnumField("close_type", b"S", enum=CLOSE_DESCRIBE_TYPE),
        StrLenField("statement", None, length_from=lambda pkt: pkt.len - 5),
    ]


class CloseComplete(_ZeroPadding):
    name = "Close Complete"
    fields_desc = [
        ByteTagField(b"3"),
        SignedIntField("len", 4),
    ]


class Describe(_ZeroPadding):
    name = "Describe"
    fields_desc = [
        ByteTagField(b"C"),
        FieldLenField(
            "len", None, length_of="statement", fmt="I", adjust=lambda pkt, x: x + 5
        ),
        CharEnumField("close_type", b"S", enum=CLOSE_DESCRIBE_TYPE),
        StrLenField("statement", None, length_from=lambda pkt: pkt.len - 5),
    ]


class EmptyQueryResponse(_ZeroPadding):
    name = "Empty Query Response"
    fields_desc = [
        ByteTagField(b"I"),
        SignedIntField("len", 4),
    ]


class Flush(_ZeroPadding):
    name = "Flush Request"
    fields_desc = [
        ByteTagField(b"F"),
        SignedIntField("len", 4),
    ]


class NoData(_ZeroPadding):
    name = "No Data Response"
    fields_desc = [
        ByteTagField(b"n"),
        SignedIntField("len", 4),
    ]


class ParseComplete(_ZeroPadding):
    name = "Parse Complete Response"
    fields_desc = [
        ByteTagField(b"1"),
        SignedIntField("len", 4),
    ]


class PortalSuspended(_ZeroPadding):
    name = "Portal Suspended Response"
    fields_desc = [
        ByteTagField(b"s"),
        SignedIntField("len", 4),
    ]


class Sync(_ZeroPadding):
    name = "Sync Request"
    fields_desc = [
        ByteTagField(b"S"),
        SignedIntField("len", 4),
    ]


class Parse(_ZeroPadding):
    name = "Parse Request"
    fields_desc = [
        ByteTagField(b"P"),
        FieldLenField("len", None, fmt="I", length_of="query", adjust=lambda pkt, x: x + 4), # TODO : Length of
        StrNullField("destination", None),
        StrNullField("query", None),
        FieldLenField("num_param_dtypes", None, fmt="H", count_of="params"),
        StrLenField("params", None, length_from=lambda pkt: pkt.num_param_dtypes * 4),
    ]


class Execute(_ZeroPadding):
    name = "Execute Request"
    fields_desc = [
        ByteTagField(b"E"),
        FieldLenField("len", None, fmt="I", length_of="portal", adjust=lambda pkt, x: x + 8),
        StrNullField(
            "portal",
            "",
        ),
        SignedIntField("rows", 0),
    ]


class PasswordMessage(_ZeroPadding):
    """
    Identifies the message as a password response.
    Note that this is also used for GSSAPI, SSPI and SASL
    response messages. The exact message type can be deduced
    from the context.
    """

    name = "Password Request Response"
    fields_desc = [
        ByteTagField(b"p"),
        FieldLenField("len", None, fmt="I", length_of="password", adjust=lambda pkt, x: x + 4),
        StrLenField("password", None, length_from=lambda pkt: pkt.len - 4),
    ]


class NoticeResponse(_ZeroPadding):
    name = "Notice Response"
    fields_desc = [
        ByteTagField(b"N"),
        FieldLenField(
            "len", None, length_of="notice_fields", fmt="I", adjust=lambda pkt, x: x + 5
        ),
        FieldListField(
            "notice_fields",
            [],
            ErrorResponseField("value", None),
            length_from=lambda pkt: pkt.len - 5,
        ),
        ByteField("terminator", None),
    ]


class NotificationResponse(_ZeroPadding):
    name = "Password Request Response"
    fields_desc = [
        ByteTagField(b"A"),
        FieldLenField("len", None, fmt="I"), # TODO : Length_of
        SignedIntField("process_id", 0),
        StrNullField("channel", None),
        StrNullField("payload", None),
    ]


class NegotiateProtocolVersion(_ZeroPadding):
    name = "Negotiate Protocol Version Response"
    fields_desc = [
        ByteTagField(b"v"),
        FieldLenField("len", None, fmt="I"), # TODO: Length_of
        SignedIntField("min_minor_version", 0),
        SignedIntField("unrecognized_options", 0),
        StrNullField("option", None),
    ]


class FunctionCallResponse(_ZeroPadding):
    name = "Function Call Response"
    fields_desc = [
        ByteTagField(b"V"),
        FieldLenField("len", None, fmt="I"), # TODO : length_of
        FieldLenField("result_len", None, length_of="result"),
        StrLenField("result", None, length_from=lambda pkt: pkt.result_len),
    ]


class ParameterDescription(_ZeroPadding):
    name = "Parameter Description"
    fields_desc = [
        ByteTagField(b"t"),
        SignedIntField("len", None), # TODO : Implement length_of
        SignedShortField("param_len", 0),
        FieldListField(
            "notice_fields",
            [],
            SignedIntField("object_id", None),
            count_from=lambda pkt: pkt.param_len,
        ),
    ]


class CopyData(_ZeroPadding):
    name = "Copy Data"
    fields_desc = [
        ByteTagField(b"d"),
        FieldLenField(
            "len", None, fmt="I", length_of="data", adjust=lambda pkt, x: x + 4
        ),
        StrLenField("data", None, length_from=lambda pkt: pkt.len - 4),
    ]


class CopyDone(_ZeroPadding):
    name = "Copy Done"
    fields_desc = [
        ByteTagField(b"c"),
        SignedIntField("len", 4),
    ]


class CopyFail(_ZeroPadding):
    name = "Copy Fail Reason"
    fields_desc = [
        ByteTagField(b"f"),
        FieldLenField(
            "len", None, fmt="I", length_of="reason", adjust=lambda pkt, x: x + 4
        ),
        StrLenField("reason", None, length_from=lambda pkt: pkt.len - 4),
    ]


FRONTEND_TAG_TO_PACKET_CLS = {
    # b'B' : 'Bind',  # TODO
    b"C": Close,
    b"d": CopyData,
    b"c": CopyDone,
    b"f": CopyFail,
    b"D": Describe,
    b"E": Execute,
    b"H": Flush,
    # b'F': 'FunctionCall',  # TODO
    b"P": Parse,
    b"p": PasswordMessage,
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
    b"d": CopyData,
    b"c": CopyDone,
    # TODO: Implement COPY stream
    # b'G': 'CopyInResponse',
    # b'H': 'CopyOutResponse',
    # b'W': 'CopyBothResponse',
    b"D": DataRow,
    b"I": EmptyQueryResponse,
    b"E": ErrorResponse,
    b"V": FunctionCallResponse,
    b"v": NegotiateProtocolVersion,
    b"n": NoData,
    b"N": NoticeResponse,
    b"A": NotificationResponse,
    b"t": ParameterDescription,
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
