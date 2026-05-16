# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Author: Pablo Gonzalez <pablo.gonzalezpe@gmail.com>

# scapy.contrib.description = MySQL client/server protocol
# scapy.contrib.status = loads

"""
MySQL client/server protocol.

This contrib module implements support for the MySQL classic protocol over TCP,
including packet framing, common handshake/authentication messages, query
packets, text resultsets, prepared statement metadata, and some legacy flows
seen in real captures.

Currently supported messages include:

- Protocol::HandshakeV10
- Protocol::SSLRequest
- Protocol::HandshakeResponse41
- OldAuthSwitchRequest
- AuthSwitchRequest
- AuthSwitchResponse
- AuthMoreData
- OK_Packet
- ERR_Packet
- EOF_Packet
- COM_QUERY
- COM_STMT_PREPARE_OK
- text resultset column counts, column definitions, and rows

This module does not currently implement TLS-encrypted MySQL payloads,
compression, binary resultsets, or full command/authentication coverage.
"""

import struct
from typing import Any, Optional, Tuple

from scapy.compat import orb
from scapy.fields import (
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldListField,
    FlagsField,
    LEIntField,
    LEShortEnumField,
    LEShortField,
    LEThreeBytesField,
    MultipleTypeField,
    PacketListField,
    StrField,
    StrFixedLenField,
    StrLenField,
    StrNullField,
)
from scapy.layers.inet import TCP
from scapy.packet import Packet, Raw, bind_layers
from scapy.sessions import TCPSession

__all__ = [
    "MYSQL_PORT",
    "CLIENT_PROTOCOL_41",
    "CLIENT_SSL",
    "CLIENT_CONNECT_WITH_DB",
    "CLIENT_SECURE_CONNECTION",
    "CLIENT_PLUGIN_AUTH",
    "CLIENT_CONNECT_ATTRS",
    "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA",
    "CLIENT_DEPRECATE_EOF",
    "MySQLClient",
    "MySQLServer",
    "MySQLClientPacket",
    "MySQLServerPacket",
    "MySQLHandshakeV10",
    "MySQLSSLRequest",
    "MySQLHandshakeResponse41",
    "MySQLOldAuthSwitchRequest",
    "MySQLAuthSwitchRequest",
    "MySQLAuthMoreData",
    "MySQLAuthSwitchResponse",
    "MySQLStmtPrepareOK",
    "MySQLResultSetColumnCount",
    "MySQLColumnDefinition41",
    "MySQLTextResultSetRow",
    "MySQLOKPacket",
    "MySQLErrPacket",
    "MySQLEOFPacket",
    "MySQLCommand",
    "MySQLComQuery",
]

MYSQL_PORT = 3306

CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_LONG_FLAG = 0x00000004
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_COMPRESS = 0x00000020
CLIENT_LOCAL_FILES = 0x00000080
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SSL = 0x00000800
CLIENT_TRANSACTIONS = 0x00002000
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_MULTI_STATEMENTS = 0x00010000
CLIENT_MULTI_RESULTS = 0x00020000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_CONNECT_ATTRS = 0x00100000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
CLIENT_SESSION_TRACK = 0x00800000
CLIENT_DEPRECATE_EOF = 0x01000000
CLIENT_ZSTD_COMPRESSION_ALGORITHM = 0x04000000
CLIENT_QUERY_ATTRIBUTES = 0x08000000

MYSQL_COMMANDS = {
    0x01: "COM_QUIT",
    0x02: "COM_INIT_DB",
    0x03: "COM_QUERY",
    0x04: "COM_FIELD_LIST",
    0x0E: "COM_PING",
    0x16: "COM_STMT_PREPARE",
    0x17: "COM_STMT_EXECUTE",
    0x19: "COM_STMT_CLOSE",
}

MYSQL_CHARACTER_SETS = {
    0x08: "latin1_swedish_ci",
    0x21: "utf8_general_ci",
    0x2D: "utf8mb4_general_ci",
    0x2E: "utf8mb4_bin",
    0x3F: "binary",
    0xFF: "utf8mb4_0900_ai_ci",
}

MYSQL_CLIENT_FLAGS = {
    CLIENT_LONG_PASSWORD: "LONG_PASSWORD",
    CLIENT_LONG_FLAG: "LONG_FLAG",
    CLIENT_CONNECT_WITH_DB: "CONNECT_WITH_DB",
    CLIENT_COMPRESS: "COMPRESS",
    CLIENT_LOCAL_FILES: "LOCAL_FILES",
    CLIENT_PROTOCOL_41: "PROTOCOL_41",
    CLIENT_SSL: "SSL",
    CLIENT_TRANSACTIONS: "TRANSACTIONS",
    CLIENT_SECURE_CONNECTION: "SECURE_CONNECTION",
    CLIENT_MULTI_STATEMENTS: "MULTI_STATEMENTS",
    CLIENT_MULTI_RESULTS: "MULTI_RESULTS",
    CLIENT_PLUGIN_AUTH: "PLUGIN_AUTH",
    CLIENT_CONNECT_ATTRS: "CONNECT_ATTRS",
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: "PLUGIN_AUTH_LENENC_CLIENT_DATA",
    CLIENT_SESSION_TRACK: "SESSION_TRACK",
    CLIENT_DEPRECATE_EOF: "DEPRECATE_EOF",
    CLIENT_ZSTD_COMPRESSION_ALGORITHM: "ZSTD_COMPRESSION_ALGORITHM",
    CLIENT_QUERY_ATTRIBUTES: "QUERY_ATTRIBUTES",
}

MYSQL_STATUS_FLAGS = {
    0x0001: "IN_TRANS",
    0x0002: "AUTOCOMMIT",
    0x0008: "MORE_RESULTS_EXISTS",
    0x0010: "NO_GOOD_INDEX_USED",
    0x0020: "NO_INDEX_USED",
    0x0040: "CURSOR_EXISTS",
    0x0080: "LAST_ROW_SENT",
    0x0100: "DB_DROPPED",
    0x0200: "NO_BACKSLASH_ESCAPES",
    0x0400: "METADATA_CHANGED",
    0x0800: "QUERY_WAS_SLOW",
    0x1000: "PS_OUT_PARAMS",
    0x2000: "IN_TRANS_READONLY",
    0x4000: "SESSION_STATE_CHANGED",
}

MYSQL_COLUMN_TYPES = {
    0x00: "DECIMAL",
    0x01: "TINY",
    0x02: "SHORT",
    0x03: "LONG",
    0x04: "FLOAT",
    0x05: "DOUBLE",
    0x06: "NULL",
    0x07: "TIMESTAMP",
    0x08: "LONGLONG",
    0x09: "INT24",
    0x0A: "DATE",
    0x0B: "TIME",
    0x0C: "DATETIME",
    0x0D: "YEAR",
    0x0F: "VARCHAR",
    0x10: "BIT",
    0xF5: "JSON",
    0xF6: "NEWDECIMAL",
    0xF7: "ENUM",
    0xF8: "SET",
    0xF9: "TINY_BLOB",
    0xFA: "MEDIUM_BLOB",
    0xFB: "LONG_BLOB",
    0xFC: "BLOB",
    0xFD: "VAR_STRING",
    0xFE: "STRING",
    0xFF: "GEOMETRY",
}

MYSQL_COLUMN_FLAGS = {
    0x0001: "NOT_NULL",
    0x0002: "PRI_KEY",
    0x0004: "UNIQUE_KEY",
    0x0008: "MULTIPLE_KEY",
    0x0010: "BLOB",
    0x0020: "UNSIGNED",
    0x0040: "ZEROFILL",
    0x0080: "BINARY",
    0x0100: "ENUM",
    0x0200: "AUTO_INCREMENT",
    0x0400: "TIMESTAMP",
    0x0800: "SET",
}


def _capability(flags: int, mask: int) -> bool:
    return bool(int(flags) & mask)


def _read_lenenc_int(data: bytes) -> Tuple[int, int]:
    """Decode a MySQL length-encoded integer and return (value, consumed)."""
    if not data:
        return 0, 0
    first = orb(data[0])
    if first < 0xFB:
        return first, 1
    if first == 0xFC:
        return struct.unpack("<H", data[1:3])[0], 3
    if first == 0xFD:
        return struct.unpack("<I", data[1:4] + b"\x00")[0], 4
    if first == 0xFE:
        return struct.unpack("<Q", data[1:9])[0], 9
    return 0, 1


def _build_lenenc_int(value: int) -> bytes:
    if value < 0xFB:
        return struct.pack("B", value)
    if value < (1 << 16):
        return b"\xFC" + struct.pack("<H", value)
    if value < (1 << 24):
        return b"\xFD" + struct.pack("<I", value)[:3]
    return b"\xFE" + struct.pack("<Q", value)


def _can_parse_text_row(payload: bytes, column_count: int) -> bool:
    remain = payload
    parsed = 0
    while remain and parsed < column_count:
        if remain[:1] == b"\xFB":
            remain = remain[1:]
            parsed += 1
            continue
        try:
            length, size = _read_lenenc_int(remain)
        except struct.error:
            return False
        end = size + length
        if end > len(remain):
            return False
        remain = remain[end:]
        parsed += 1
    return parsed == column_count and not remain


def _can_parse_column_definition(payload: bytes) -> bool:
    try:
        pkt = MySQLColumnDefinition41(payload)
        return bytes(pkt) == payload
    except Exception:
        return False


class MySQLLenEncIntField(Field[Any, Any]):
    def __init__(self, name: str, default: Any = 0) -> None:
        Field.__init__(self, name, default)

    def addfield(self, pkt: Packet, s: bytes, val: Any) -> bytes:
        if val is None:
            val = 0
        return s + _build_lenenc_int(int(val))

    def getfield(self, pkt: Packet, s: bytes) -> Tuple[bytes, Any]:
        value, size = _read_lenenc_int(s)
        return s[size:], value

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        return repr(val)


class MySQLLenEncStrField(Field[Any, Any]):
    def __init__(self, name: str, default: Any = b"") -> None:
        Field.__init__(self, name, default)

    def addfield(self, pkt: Packet, s: bytes, val: Any) -> bytes:
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("utf-8")
        return s + _build_lenenc_int(len(val)) + val

    def getfield(self, pkt: Packet, s: bytes) -> Tuple[bytes, Any]:
        length, size = _read_lenenc_int(s)
        start = size
        end = size + length
        return s[end:], s[start:end]

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        return repr(val)


class MySQLByteLenStrField(Field[Any, Any]):
    def __init__(self, name: str, default: Any = b"") -> None:
        Field.__init__(self, name, default)

    def addfield(self, pkt: Packet, s: bytes, val: Any) -> bytes:
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("utf-8")
        return s + struct.pack("B", len(val)) + val

    def getfield(self, pkt: Packet, s: bytes) -> Tuple[bytes, Any]:
        if not s:
            return s, b""
        length = orb(s[0])
        return s[1 + length:], s[1:1 + length]

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        return repr(val)


class MySQLTextRowValueField(Field[Any, Any]):
    def __init__(self, name: str, default: Any = b"") -> None:
        Field.__init__(self, name, default)

    def any2i(self, pkt: Optional[Packet], val: Any) -> Any:
        if isinstance(val, str):
            return val.encode("utf-8")
        return val

    def addfield(self, pkt: Packet, s: bytes, val: Any) -> bytes:
        if val is None:
            return s + b"\xFB"
        if isinstance(val, str):
            val = val.encode("utf-8")
        return s + _build_lenenc_int(len(val)) + val

    def getfield(self, pkt: Packet, s: bytes) -> Tuple[bytes, Any]:
        if s[:1] == b"\xFB":
            return s[1:], None
        length, size = _read_lenenc_int(s)
        start = size
        end = size + length
        return s[end:], s[start:end]


class MySQLTextRowValuesField(FieldListField):
    def __init__(self, name: str, default: Any = None) -> None:
        super().__init__(
            name,
            [] if default is None else default,
            MySQLTextRowValueField("value"),
        )

    def any2i(self, pkt: Optional[Packet], val: Any) -> Any:
        if val is None:
            return []
        return super().any2i(pkt, val)

    def i2m(self, pkt: Optional[Packet], val: Any) -> Any:
        return self.any2i(pkt, val)


class _MySQLPacket(Packet):
    fields_desc = [
        LEThreeBytesField("payload_length", None),
        ByteField("sequence_id", 0),
    ]

    def do_build(self) -> bytes:
        pkt = self.self_build()
        pay = self.do_build_payload()
        return self.post_build(pkt, pay)

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.payload_length is None:
            pkt = struct.pack("<I", len(pay))[:3] + pkt[3:]
        return pkt + pay

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        length = self.payload_length or 0
        return s[:length], s[length:]


class MySQLHandshakeV10(Packet):
    name = "MySQL HandshakeV10"
    fields_desc = [
        ByteField("protocol_version", 10),
        StrNullField("server_version", b""),
        LEIntField("connection_id", 0),
        StrFixedLenField("auth_plugin_data_part_1", b"", length=8),
        ByteField("filler", 0),
        LEShortField("capability_flags_lower", 0),
        ByteEnumField("character_set", 0, MYSQL_CHARACTER_SETS),
        FlagsField("status_flags", 0, -16, MYSQL_STATUS_FLAGS),
        LEShortField("capability_flags_upper", 0),
        ByteField("auth_plugin_data_len", 0),
        StrFixedLenField("reserved", b"\x00" * 10, length=10),
        StrLenField(
            "auth_plugin_data_part_2",
            b"",
            length_from=lambda pkt: max(13, pkt.auth_plugin_data_len - 8)
            if pkt.auth_plugin_data_len
            else 0,
        ),
        StrNullField("auth_plugin_name", b""),
    ]

    @property
    def capability_flags(self) -> int:
        return (
            ((self.capability_flags_upper & 0xFFFF) << 16)
            | (self.capability_flags_lower & 0xFFFF)
        )


class MySQLSSLRequest(Packet):
    name = "MySQL SSLRequest"
    fields_desc = [
        FlagsField(
            "client_flags",
            CLIENT_PROTOCOL_41 | CLIENT_SSL,
            -32,
            MYSQL_CLIENT_FLAGS,
        ),
        LEIntField("max_packet_size", 0),
        ByteEnumField("character_set", 0, MYSQL_CHARACTER_SETS),
        StrFixedLenField("filler", b"\x00" * 23, length=23),
    ]


class MySQLHandshakeResponse41(Packet):
    name = "MySQL HandshakeResponse41"
    fields_desc = [
        FlagsField(
            "client_flags",
            CLIENT_PROTOCOL_41,
            -32,
            MYSQL_CLIENT_FLAGS,
        ),
        LEIntField("max_packet_size", 0),
        ByteEnumField("character_set", 0, MYSQL_CHARACTER_SETS),
        StrFixedLenField("filler", b"\x00" * 23, length=23),
        StrNullField("username", b""),
        MultipleTypeField(
            [
                (
                    MySQLLenEncStrField("auth_response", b""),
                    lambda pkt: _capability(
                        pkt.client_flags,
                        CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
                    ),
                ),
                (
                    MySQLByteLenStrField("auth_response", b""),
                    lambda pkt: _capability(
                        pkt.client_flags,
                        CLIENT_SECURE_CONNECTION,
                    ),
                ),
            ],
            StrNullField("auth_response", b""),
        ),
        ConditionalField(
            StrNullField("database", b""),
            lambda pkt: _capability(pkt.client_flags, CLIENT_CONNECT_WITH_DB),
        ),
        ConditionalField(
            StrNullField("auth_plugin_name", b""),
            lambda pkt: _capability(pkt.client_flags, CLIENT_PLUGIN_AUTH),
        ),
        ConditionalField(
            MySQLLenEncStrField("connect_attrs", b""),
            lambda pkt: _capability(pkt.client_flags, CLIENT_CONNECT_ATTRS),
        ),
        ConditionalField(
            ByteField("zstd_compression_level", 0),
            lambda pkt: _capability(
                pkt.client_flags,
                CLIENT_ZSTD_COMPRESSION_ALGORITHM,
            ),
        ),
    ]


class MySQLAuthSwitchRequest(Packet):
    name = "MySQL AuthSwitchRequest"
    fields_desc = [
        ByteField("header", 0xFE),
        StrNullField("plugin_name", b""),
        StrField("plugin_data", b""),
    ]


class MySQLAuthSwitchResponse(Packet):
    name = "MySQL AuthSwitchResponse"
    fields_desc = [
        StrField("data", b""),
    ]


class MySQLOldAuthSwitchRequest(Packet):
    name = "MySQL OldAuthSwitchRequest"
    fields_desc = [
        ByteField("header", 0xFE),
    ]


class MySQLAuthMoreData(Packet):
    name = "MySQL AuthMoreData"
    fields_desc = [
        ByteField("header", 0x01),
        StrField("data", b""),
    ]


class MySQLStmtPrepareOK(Packet):
    name = "MySQL COM_STMT_PREPARE_OK"
    fields_desc = [
        ByteField("status", 0x00),
        LEIntField("statement_id", 0),
        LEShortField("num_columns", 0),
        LEShortField("num_params", 0),
        ByteField("reserved_1", 0),
        LEShortField("warning_count", 0),
    ]


class MySQLResultSetColumnCount(Packet):
    name = "MySQL ResultSet Column Count"
    fields_desc = [
        MySQLLenEncIntField("column_count", 0),
    ]


class MySQLColumnDefinition41(Packet):
    name = "MySQL ColumnDefinition41"
    fields_desc = [
        MySQLLenEncStrField("catalog", b"def"),
        MySQLLenEncStrField("schema", b""),
        MySQLLenEncStrField("table", b""),
        MySQLLenEncStrField("org_table", b""),
        MySQLLenEncStrField("column_name", b""),
        MySQLLenEncStrField("org_column_name", b""),
        MySQLLenEncIntField("fixed_length_fields_len", 0x0C),
        LEShortEnumField("character_set", 0, MYSQL_CHARACTER_SETS),
        LEIntField("column_length", 0),
        ByteEnumField("column_type", 0xFD, MYSQL_COLUMN_TYPES),
        FlagsField("flags", 0, -16, MYSQL_COLUMN_FLAGS),
        ByteField("decimals", 0),
        LEShortField("filler", 0),
    ]


class MySQLTextResultSetRow(Packet):
    name = "MySQL Text ResultSet Row"
    fields_desc = [
        MySQLTextRowValuesField("values", []),
    ]

    def do_build(self) -> bytes:
        pkt = self.self_build()
        pay = self.do_build_payload()
        return self.post_build(pkt, pay)


class MySQLOKPacket(Packet):
    name = "MySQL OK_Packet"
    fields_desc = [
        ByteField("header", 0x00),
        MySQLLenEncIntField("affected_rows", 0),
        MySQLLenEncIntField("last_insert_id", 0),
        FlagsField("status_flags", 0, -16, MYSQL_STATUS_FLAGS),
        LEShortField("warnings", 0),
        StrField("info", b""),
    ]


class MySQLErrPacket(Packet):
    name = "MySQL ERR_Packet"
    fields_desc = [
        ByteField("header", 0xFF),
        LEShortField("error_code", 0),
        StrFixedLenField("sql_state_marker", b"#", length=1),
        StrFixedLenField("sql_state", b"HY000", length=5),
        StrField("error_message", b""),
    ]


class MySQLEOFPacket(Packet):
    name = "MySQL EOF_Packet"
    fields_desc = [
        ByteField("header", 0xFE),
        ConditionalField(
            LEShortField("warnings", 0),
            lambda pkt: getattr(
                getattr(pkt, "underlayer", None),
                "payload_length",
                None,
            ) != 1,
        ),
        ConditionalField(
            FlagsField("status_flags", 0, -16, MYSQL_STATUS_FLAGS),
            lambda pkt: getattr(
                getattr(pkt, "underlayer", None),
                "payload_length",
                None,
            ) != 1,
        ),
    ]


class MySQLCommand(Packet):
    name = "MySQL Command"
    fields_desc = [
        ByteEnumField("cmd", 0x03, MYSQL_COMMANDS),
        StrField("data", b""),
    ]


class MySQLComQuery(Packet):
    name = "MySQL COM_QUERY"
    fields_desc = [
        ByteEnumField("cmd", 0x03, MYSQL_COMMANDS),
        StrField("query", b""),
    ]


class MySQLClientPacket(_MySQLPacket):
    name = "MySQL Client Packet"

    def guess_payload_class(self, payload: bytes) -> type:
        if len(payload) >= 32 and self.sequence_id == 1:
            flags = struct.unpack("<I", payload[:4])[0]
            if _capability(flags, CLIENT_SSL) and len(payload) == 32:
                return MySQLSSLRequest
            if _capability(flags, CLIENT_PROTOCOL_41):
                return MySQLHandshakeResponse41
        if payload:
            command = orb(payload[0])
            if command == 0x03:
                return MySQLComQuery
            if command in MYSQL_COMMANDS:
                return MySQLCommand
            if self.sequence_id > 1:
                return MySQLAuthSwitchResponse
        return Raw


class MySQLServerPacket(_MySQLPacket):
    name = "MySQL Server Packet"

    def guess_payload_class(self, payload: bytes) -> type:
        forced_payload_cls = getattr(
            self.parent,
            "_mysql_forced_payload_cls",
            None,
        )
        if forced_payload_cls is not None:
            self.parent._mysql_forced_payload_cls = None
            return forced_payload_cls
        if payload and self.sequence_id == 0 and orb(payload[0]) == 0x0A:
            return MySQLHandshakeV10
        if payload:
            header = orb(payload[0])
            if header == 0x00:
                if self.sequence_id == 1 and len(payload) == 12:
                    return MySQLStmtPrepareOK
                return MySQLOKPacket
            if header == 0x01 and len(payload) > 1 and self.sequence_id > 0:
                return MySQLAuthMoreData
            if header == 0xFF:
                return MySQLErrPacket
            if header == 0xFE and len(payload) >= 9:
                return MySQLAuthSwitchRequest
            if header == 0xFE and len(payload) == 1:
                if self.sequence_id == 2:
                    return MySQLOldAuthSwitchRequest
                return MySQLEOFPacket
            if header == 0xFE and len(payload) < 9:
                return MySQLEOFPacket
        return Raw


def _next_mysql_client_packet(
    pkt: Packet,
    lst: Any,
    cur: bytes,
    remain: bytes,
) -> Optional[type]:
    if len(remain) < 4:
        return None
    return MySQLClientPacket


# Track enough server-side state to force metadata/resultset packet types
# during TCP stream reassembly.
def _mysql_server_cls(
    pkt: Packet,
    lst: Any,
    cur: bytes,
    remain: bytes,
) -> Optional[type]:
    if len(remain) < 4:
        return None
    pkt._mysql_forced_payload_cls = None
    payload_length = struct.unpack("<I", remain[:3] + b"\x00")[0]
    payload = remain[4:4 + payload_length]
    state_items = list(lst)
    if cur is not None:
        state_items.append(cur)

    in_field_list = False
    prepare_phase = None
    prepare_params_remaining = 0
    prepare_columns_remaining = 0
    resultset_column_count = None
    resultset_column_defs = 0
    resultset_metadata_done = False

    for item in state_items:
        item_payload = getattr(item, "payload", None)

        if isinstance(item_payload, MySQLColumnDefinition41):
            if not in_field_list:
                in_field_list = True
        elif in_field_list:
            in_field_list = False

        if isinstance(item_payload, MySQLStmtPrepareOK):
            if item_payload.num_params:
                prepare_phase = "params"
            elif item_payload.num_columns:
                prepare_phase = "columns"
            else:
                prepare_phase = None
            prepare_params_remaining = item_payload.num_params
            prepare_columns_remaining = item_payload.num_columns
            continue
        if prepare_phase is not None:
            if isinstance(item_payload, MySQLColumnDefinition41):
                if prepare_phase == "params" and prepare_params_remaining > 0:
                    prepare_params_remaining -= 1
                    if prepare_params_remaining == 0:
                        prepare_phase = "params_eof"
                elif (
                    prepare_phase == "columns"
                    and prepare_columns_remaining > 0
                ):
                    prepare_columns_remaining -= 1
                    if prepare_columns_remaining == 0:
                        prepare_phase = "columns_eof"
            elif isinstance(item_payload, MySQLEOFPacket):
                if prepare_phase == "params_eof":
                    if prepare_columns_remaining > 0:
                        prepare_phase = "columns"
                    else:
                        prepare_phase = None
                elif prepare_phase == "columns_eof":
                    prepare_phase = None
            elif isinstance(item_payload, MySQLErrPacket):
                prepare_phase = None

        if isinstance(item_payload, MySQLResultSetColumnCount):
            resultset_column_count = item_payload.column_count
            resultset_column_defs = 0
            resultset_metadata_done = False
            continue
        if resultset_column_count is not None:
            if isinstance(item_payload, MySQLColumnDefinition41):
                resultset_column_defs += 1
            elif isinstance(item_payload, (MySQLEOFPacket, MySQLOKPacket)):
                if not resultset_metadata_done and (
                    resultset_column_defs >= resultset_column_count
                ):
                    resultset_metadata_done = True
                elif resultset_metadata_done:
                    resultset_column_count = None
            elif isinstance(item_payload, MySQLErrPacket):
                resultset_column_count = None

    if in_field_list:
        if payload[:1] == b"\xFE":
            pkt._mysql_forced_payload_cls = MySQLEOFPacket
            return MySQLServerPacket
        if _can_parse_column_definition(payload):
            pkt._mysql_forced_payload_cls = MySQLColumnDefinition41
            return MySQLServerPacket
    if prepare_phase is not None:
        if prepare_phase in ("params", "columns"):
            pkt._mysql_forced_payload_cls = MySQLColumnDefinition41
            return MySQLServerPacket
        if prepare_phase in ("params_eof", "columns_eof"):
            pkt._mysql_forced_payload_cls = MySQLEOFPacket
            return MySQLServerPacket
    if resultset_column_count is not None:
        if (
            not resultset_metadata_done
            and resultset_column_defs < resultset_column_count
        ):
            pkt._mysql_forced_payload_cls = MySQLColumnDefinition41
            return MySQLServerPacket
        if not payload:
            return MySQLServerPacket
        header = orb(payload[0])
        if not resultset_metadata_done:
            return MySQLServerPacket
        if _can_parse_text_row(payload, resultset_column_count):
            pkt._mysql_forced_payload_cls = MySQLTextResultSetRow
            return MySQLServerPacket
        if header == 0xFE and len(payload) < 9:
            pkt._mysql_forced_payload_cls = MySQLEOFPacket
            return MySQLServerPacket
        return MySQLServerPacket
    if payload:
        header = orb(payload[0])
        if header in (0x00, 0x0A, 0xFE, 0xFF):
            return MySQLServerPacket
        if header == 0x01 and payload_length > 1:
            return MySQLServerPacket
        if _can_parse_column_definition(payload):
            pkt._mysql_forced_payload_cls = MySQLColumnDefinition41
            return MySQLServerPacket
        if header != 0xFB:
            pkt._mysql_forced_payload_cls = MySQLResultSetColumnCount
            return MySQLServerPacket
    return MySQLServerPacket


class _MySQLStream(Packet, TCPSession):
    @classmethod
    def tcp_reassemble(
        cls,
        data: bytes,
        metadata: Any,
        session: Any = None,
    ) -> Optional[Packet]:
        offset = 0
        while offset < len(data):
            if len(data) - offset < 4:
                return None
            payload_length = struct.unpack(
                "<I",
                data[offset:offset + 3] + b"\x00",
            )[0]
            offset += 4
            if len(data) - offset < payload_length:
                return None
            offset += payload_length
        if data:
            return cls(data)
        return None


class MySQLClient(_MySQLStream):
    name = "MySQL Client Stream"
    fields_desc = [
        PacketListField("contents", [], next_cls_cb=_next_mysql_client_packet),
    ]


class MySQLServer(_MySQLStream):
    name = "MySQL Server Stream"
    fields_desc = [
        PacketListField("contents", [], next_cls_cb=_mysql_server_cls),
    ]


bind_layers(TCP, MySQLClient, dport=MYSQL_PORT)
bind_layers(TCP, MySQLServer, sport=MYSQL_PORT)
