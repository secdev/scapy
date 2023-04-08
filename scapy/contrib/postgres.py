# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Postgres PSQL Binary Protocol
# scapy.contrib.status = loads

import struct

from typing import (
    Optional,
    Callable,
    Any,
    Tuple,
)
from scapy.fields import (
    ByteField,
    CharEnumField,
    Field,
    FieldLenField,
    FieldListField,
    IntEnumField,
    PacketListField,
    ShortField,
    SignedIntField,
    SignedShortField,
    StrField,
    StrLenField,
    StrNullField,
)
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import TCP
from scapy.sessions import TCPSession

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
        SignedIntField("request_code", 80877103),
    ]


class _DictStrField(StrField):
    """Takes a dictionary as an argument and packs back into a byte string."""

    def i2m(self, pkt, x):
        if isinstance(x, bytes):
            return x
        if isinstance(x, dict):
            result = bytes()
            for k, v in x.items():
                result += k + b"\x00" + v + b"\x00"
            return result + b"\x00"
        else:
            return super(_DictStrField, self).i2m(pkt, x)

    def i2len(self, pkt, x):
        # type: (Optional[Packet], Any) -> int
        if x is None:
            return 0
        return len(self.i2m(pkt, x))


class Startup(Packet):
    name = "Startup Request Packet"
    fields_desc = [
        FieldLenField(
            "len", None, length_of="options", fmt="I", adjust=lambda pkt, x: x + 8
        ),
        ShortField("protocol_version_major", 3),
        ShortField("protocol_version_minor", 0),
        _DictStrField("options", None),
    ]


class _FieldsLenField(Field[int, int]):
    """Same as FieldLenField but takes a tuple of fields for length_of."""

    __slots__ = ["length_of", "adjust"]

    def __init__(
        self,
        name,  # type: str
        default,  # type: Optional[Any]
        length_of=None,  # type: Optional[Tuple[str]]
        fmt="H",  # type: str
        adjust=lambda pkt, x: x,  # type: Callable[[Packet, int], int]
    ):
        # type: (...) -> None
        super(_FieldsLenField, self).__init__(name, default, fmt)
        self.length_of = length_of
        self.adjust = adjust

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[int]) -> int
        if x is None and pkt is not None:
            if self.length_of is not None:
                f = 0
                for length_of_field in self.length_of:
                    fld, fval = pkt.getfield_and_val(length_of_field)
                    f += fld.i2len(pkt, fval)
            else:
                raise ValueError("Field should have either length_of or count_of")
            x = self.adjust(pkt, f)
        elif x is None:
            x = 0
        return x


def determine_pg_field(pkt, lst, cur, remain):
    key = b""
    if remain:
        key = remain[0:1]  # Python 2/3 compat
    if key in pkt.cls_mapping:
        return pkt.cls_mapping[key]
    elif remain[0:1] == b"\x00" and len(remain) >= 4:
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
    def __init__(
        self, default  # type: bytes
    ):
        super(ByteTagField, self).__init__("tag", ord(default))

    def randval(self):
        return ord(self.default)


class _BasePostgres(Packet, TCPSession):
    name = "Regular packet"
    fields_desc = [PacketListField("contents", [], next_cls_cb=determine_pg_field)]

    @classmethod
    def tcp_reassemble(cls, data, metadata):
        if data and data[0:1] == b"\x00":
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


class SignedIntStrPair(_ZeroPadding):
    name = "Bytes data"
    fields_desc = [
        FieldLenField("len", 0, fmt="i", length_of="value"),
        StrLenField(
            "data", None, length_from=lambda pkt: pkt.len if pkt.len > 0 else 0
        ),
    ]


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
        FieldLenField(
            "len",
            None,
            fmt="I",
            length_of=("parameter", "value"),
            adjust=lambda pkt, x: x + 4,
        ),
        StrNullField(
            "parameter",
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
        SignedIntField("len", 6),
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
            "len", None, fmt="I", length_of="cols", adjust=lambda pkt, x: x + 6
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
        ByteTagField(b"D"),
        FieldLenField(
            "len", None, fmt="I", length_of="data", adjust=lambda pkt, x: len(pkt) - 1
        ),
        FieldLenField("numfields", 0),
        PacketListField(
            "data",
            [],
            SignedIntStrPair,
            count_from=lambda pkt: pkt.numfields,
        ),
    ]


# See https://www.postgresql.org/docs/current/protocol-error-fields.html
ERROR_FIELD = {
    b"S": "Severity",
    b"V": "SeverityNonLocalized",
    b"C": "Code",
    b"M": "Message",
    b"D": "Detail",
    b"H": "Hint",
    b"P": "Position",
    b"p": "InternalPosition",
    b"q": "InternalQuery",
    b"W": "Where",
    b"s": "SchemaName",
    b"t": "TableName",
    b"c": "ColumnName",
    b"d": "DataTypeName",
    b"n": "ConstraintName",
    b"F": "File",
    b"L": "Line",
    b"R": "Routine",
}


class ErrorResponseField(StrNullField):
    def m2i(self, pkt, x):
        """Unpack into a tuple of Field, Value."""
        i = super(ErrorResponseField, self).m2i(pkt, x)
        i_code = i[0:1]  # Python 2/3 compatible
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


class _Todo(_ZeroPadding):
    name = "Unsupported message"
    fields_desc = [
        ByteTagField(b"?"),
        FieldLenField("len", None, fmt="I", length_of="body"),
        StrLenField("body", None, length_from=lambda pkt: pkt.len - 4),
    ]


class Bind(_ZeroPadding):
    name = "Bind Request"
    fields_desc = [
        ByteTagField(b"?"),
        FieldLenField(
            "len", None, fmt="I", length_of="body", adjust=lambda pkt, x: len(pkt) - 1
        ),
        StrNullField("destination", ""),
        StrNullField("statement", ""),
        FieldLenField("codes_count", 0, fmt="H", count_of="codes"),
        FieldListField(
            "codes", [], ShortField("", 0), count_from=lambda pkt: pkt.codes_count
        ),
        FieldLenField("values_count", 0, fmt="H", count_of="values"),
        PacketListField(
            "values", [], SignedIntStrPair, count_from=lambda pkt: pkt.values_count
        ),
        FieldLenField("results_count", 0, fmt="H", count_of="results"),
        FieldListField(
            "results", [], ShortField("", 0), count_from=lambda pkt: pkt.results_count
        ),
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
            "len", None, fmt="I", length_of="statement", adjust=lambda pkt, x: x + 6
        ),
        CharEnumField("close_type", b"S", enum=CLOSE_DESCRIBE_TYPE),
        StrNullField(
            "statement",
            "",
        ),
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
        ByteTagField(b"D"),
        FieldLenField(
            "len", None, fmt="I", length_of="statement", adjust=lambda pkt, x: x + 6
        ),
        CharEnumField("close_type", b"S", enum=CLOSE_DESCRIBE_TYPE),
        StrNullField("statement", ""),
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
        ByteTagField(b"H"),
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
        FieldLenField("len", None, fmt="I", adjust=lambda pkt, x: len(pkt) - 1),
        StrNullField("destination", ""),
        StrNullField("query", ""),
        FieldLenField("num_param_dtypes", None, fmt="H", count_of="params"),
        FieldListField(
            "params",
            [],
            SignedIntField("param", None),
            count_from=lambda pkt: pkt.num_param_dtypes,
        ),
    ]


class Execute(_ZeroPadding):
    name = "Execute Request"
    fields_desc = [
        ByteTagField(b"E"),
        FieldLenField(
            "len", None, fmt="I", length_of="portal", adjust=lambda pkt, x: x + 9
        ),
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
        FieldLenField(
            "len", None, fmt="I", length_of="password", adjust=lambda pkt, x: x + 4
        ),
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
        _FieldsLenField(
            "len",
            None,
            fmt="I",
            length_of=("channel", "payload"),
            adjust=lambda pkt, x: x + 8,
        ),
        SignedIntField("process_id", 0),
        StrNullField("channel", None),
        StrNullField("payload", None),
    ]


class NegotiateProtocolVersion(_ZeroPadding):
    name = "Negotiate Protocol Version Response"
    fields_desc = [
        ByteTagField(b"v"),
        FieldLenField(
            "len", None, fmt="I", length_of="option", adjust=lambda pkt, x: x + 12
        ),
        SignedIntField("min_minor_version", 0),
        SignedIntField("unrecognized_options", 0),
        StrNullField("option", None),
    ]


class FunctionCallResponse(_ZeroPadding):
    name = "Function Call Response"
    fields_desc = [
        ByteTagField(b"V"),
        FieldLenField(
            "len", None, fmt="I", length_of="result", adjust=lambda pkt, x: x + 8
        ),
        FieldLenField("result_len", None, length_of="result"),
        StrLenField("result", None, length_from=lambda pkt: pkt.result_len),
    ]


class ParameterDescription(_ZeroPadding):
    name = "Parameter Description"
    fields_desc = [
        ByteTagField(b"t"),
        FieldLenField(
            "len", None, fmt="I", length_of="dtypes", adjust=lambda pkt, x: x + 6
        ),
        SignedShortField("dtypes_len", 0),
        FieldListField(
            "dtypes",
            [],
            SignedIntField("dtype", None),
            count_from=lambda pkt: pkt.dtypes_len,
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


class CancelRequest(Packet):
    name = "Cancel Request"
    fields_desc = [
        SignedIntField("len", 16),
        SignedIntField("request_code", 80877102),
        SignedIntField("process_id", 0),
        SignedIntField("secret", 0),
    ]


class GSSENCRequest(Packet):
    name = "GSSENC Request"
    fields_desc = [
        SignedIntField("len", 8),
        SignedIntField("request_code", 80877104),
    ]


class CopyInResponse(_ZeroPadding):
    name = "Copy in Response"
    fields_desc = [
        ByteTagField(b"G"),
        FieldLenField(
            "len", None, fmt="I", length_of="cols", adjust=lambda pkt, x: x + 7
        ),
        ByteField("format", 0),
        ShortField("ncols", 0),
        FieldListField(
            "cols",
            [],
            ShortField("format", None),
            count_from=lambda pkt: pkt.ncols,
        ),
    ]


class CopyOutResponse(_ZeroPadding):
    name = "Copy out Response"
    fields_desc = [
        ByteTagField(b"H"),
        FieldLenField(
            "len", None, fmt="I", length_of="cols", adjust=lambda pkt, x: x + 7
        ),
        ByteField("format", 0),
        ShortField("ncols", 0),
        FieldListField(
            "cols",
            [],
            ShortField("format", None),
            count_from=lambda pkt: pkt.ncols,
        ),
    ]


class CopyBothResponse(_ZeroPadding):
    name = "Copy both Response"
    fields_desc = [
        ByteTagField(b"W"),
        FieldLenField(
            "len", None, fmt="I", length_of="cols", adjust=lambda pkt, x: x + 7
        ),
        ByteField("format", 0),
        ShortField("ncols", 0),
        FieldListField(
            "cols",
            [],
            ShortField("format", None),
            count_from=lambda pkt: pkt.ncols,
        ),
    ]


FRONTEND_TAG_TO_PACKET_CLS = {
    b"B": Bind,
    b"C": Close,
    b"d": CopyData,
    b"c": CopyDone,
    b"f": CopyFail,
    b"D": Describe,
    b"E": Execute,
    b"H": Flush,
    b"F": _Todo,
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
    b"G": CopyInResponse,
    b"H": CopyOutResponse,
    b"W": CopyBothResponse,
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

    @classmethod
    def tcp_reassemble(cls, data, metadata):
        msgs = PostgresFrontend(data)
        if msgs.contents and "Sync" in msgs.contents[-1]:
            return msgs


class PostgresBackend(_BasePostgres):
    cls_mapping = BACKEND_TAG_TO_PACKET_CLS

    @classmethod
    def tcp_reassemble(cls, data, metadata):
        msgs = PostgresBackend(data)
        if msgs.contents and "ReadyForQuery" in msgs.contents[-1]:
            return msgs


bind_layers(TCP, PostgresFrontend, dport=5432)
bind_layers(TCP, PostgresBackend, sport=5432)
