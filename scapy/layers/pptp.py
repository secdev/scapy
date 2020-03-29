# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Jan Sebechlebsky <sebechlebskyjan@gmail.com>
# This program is published under a GPLv2 license

"""
PPTP (Point to Point Tunneling Protocol)

[RFC 2637]
"""

from scapy.packet import Packet, bind_layers
from scapy.layers.inet import TCP
from scapy.compat import orb
from scapy.fields import ByteEnumField, FieldLenField, FlagsField, IntField, \
    IntEnumField, LenField, XIntField, ShortField, ShortEnumField, \
    StrFixedLenField, StrLenField, XShortField, XByteField

_PPTP_MAGIC_COOKIE = 0x1a2b3c4d

_PPTP_msg_type = {1: "Control Message",
                  2: "Managemenent Message"}

_PPTP_ctrl_msg_type = {  # Control Connection Management
    1: "Start-Control-Connection-Request",
    2: "Start-Control-Connection-Reply",
    3: "Stop-Control-Connection-Request",
    4: "Stop-Control-Connection-Reply",
    5: "Echo-Request",
    6: "Echo-Reply",
    # Call Management
    7: "Outgoing-Call-Request",
    8: "Outgoing-Call-Reply",
    9: "Incoming-Call-Request",
    10: "Incoming-Call-Reply",
    11: "Incoming-Call-Connected",
    12: "Call-Clear-Request",
    13: "Call-Disconnect-Notify",
    # Error Reporting
    14: "WAN-Error-Notify",
    # PPP Session Control
    15: "Set-Link-Info"}

_PPTP_general_error_code = {0: "None",
                            1: "Not-Connected",
                            2: "Bad-Format",
                            3: "Bad-Value",
                            4: "No-Resource",
                            5: "Bad-Call ID",
                            6: "PAC-Error"}


class PPTP(Packet):
    name = "PPTP"
    fields_desc = [FieldLenField("len", None, fmt="H", length_of="data",
                                 adjust=lambda p, x: x + 12),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 1, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   StrLenField("data", "", length_from=lambda p: p.len - 12)]

    registered_options = {}

    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.ctrl_msg_type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = orb(_pkt[9])
            return cls.registered_options.get(o, cls)
        return cls


_PPTP_FRAMING_CAPABILITIES_FLAGS = ["Asynchronous Framing supported",
                                    "Synchronous Framing supported"]

_PPTP_BEARER_CAPABILITIES_FLAGS = ["Analog access supported",
                                   "Digital access supported"]


class PPTPStartControlConnectionRequest(PPTP):
    name = "PPTP Start Control Connection Request"
    fields_desc = [LenField("len", 156),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 1, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ShortField("protocol_version", 0x0100),
                   XShortField("reserved_1", 0x0000),
                   FlagsField("framing_capabilities", 0, 32,
                              _PPTP_FRAMING_CAPABILITIES_FLAGS),
                   FlagsField("bearer_capabilities", 0, 32,
                              _PPTP_BEARER_CAPABILITIES_FLAGS),
                   ShortField("maximum_channels", 65535),
                   ShortField("firmware_revision", 256),
                   StrFixedLenField("host_name", "linux", 64),
                   StrFixedLenField("vendor_string", "", 64)]


_PPTP_start_control_connection_result = {1: "OK",
                                         2: "General error",
                                         3: "Command channel already exists",
                                         4: "Not authorized",
                                         5: "Unsupported protocol version"}


class PPTPStartControlConnectionReply(PPTP):
    name = "PPTP Start Control Connection Reply"
    fields_desc = [LenField("len", 156),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 2, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ShortField("protocol_version", 0x0100),
                   ByteEnumField("result_code", 1,
                                 _PPTP_start_control_connection_result),
                   ByteEnumField("error_code", 0, _PPTP_general_error_code),
                   FlagsField("framing_capabilities", 0, 32,
                              _PPTP_FRAMING_CAPABILITIES_FLAGS),
                   FlagsField("bearer_capabilities", 0, 32,
                              _PPTP_BEARER_CAPABILITIES_FLAGS),
                   ShortField("maximum_channels", 65535),
                   ShortField("firmware_revision", 256),
                   StrFixedLenField("host_name", "linux", 64),
                   StrFixedLenField("vendor_string", "", 64)]

    def answers(self, other):
        return isinstance(other, PPTPStartControlConnectionRequest)


_PPTP_stop_control_connection_reason = {1: "None",
                                        2: "Stop-Protocol",
                                        3: "Stop-Local-Shutdown"}


class PPTPStopControlConnectionRequest(PPTP):
    name = "PPTP Stop Control Connection Request"
    fields_desc = [LenField("len", 16),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 3, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ByteEnumField("reason", 1,
                                 _PPTP_stop_control_connection_reason),
                   XByteField("reserved_1", 0x00),
                   XShortField("reserved_2", 0x0000)]


_PPTP_stop_control_connection_result = {1: "OK",
                                        2: "General error"}


class PPTPStopControlConnectionReply(PPTP):
    name = "PPTP Stop Control Connection Reply"
    fields_desc = [LenField("len", 16),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 4, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ByteEnumField("result_code", 1,
                                 _PPTP_stop_control_connection_result),
                   ByteEnumField("error_code", 0, _PPTP_general_error_code),
                   XShortField("reserved_2", 0x0000)]

    def answers(self, other):
        return isinstance(other, PPTPStopControlConnectionRequest)


class PPTPEchoRequest(PPTP):
    name = "PPTP Echo Request"
    fields_desc = [LenField("len", 16),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 5, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   IntField("identifier", None)]


_PPTP_echo_result = {1: "OK",
                     2: "General error"}


class PPTPEchoReply(PPTP):
    name = "PPTP Echo Reply"
    fields_desc = [LenField("len", 20),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 6, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   IntField("identifier", None),
                   ByteEnumField("result_code", 1, _PPTP_echo_result),
                   ByteEnumField("error_code", 0, _PPTP_general_error_code),
                   XShortField("reserved_1", 0x0000)]

    def answers(self, other):
        return isinstance(other, PPTPEchoRequest) and other.identifier == self.identifier  # noqa: E501


_PPTP_bearer_type = {1: "Analog channel",
                     2: "Digital channel",
                     3: "Any type of channel"}

_PPTP_framing_type = {1: "Asynchronous framing",
                      2: "Synchronous framing",
                      3: "Any type of framing"}


class PPTPOutgoingCallRequest(PPTP):
    name = "PPTP Outgoing Call Request"
    fields_desc = [LenField("len", 168),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 7, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ShortField("call_id", 1),
                   ShortField("call_serial_number", 0),
                   IntField("minimum_bps", 32768),
                   IntField("maximum_bps", 2147483648),
                   IntEnumField("bearer_type", 3, _PPTP_bearer_type),
                   IntEnumField("framing_type", 3, _PPTP_framing_type),
                   ShortField("pkt_window_size", 16),
                   ShortField("pkt_proc_delay", 0),
                   ShortField('phone_number_len', 0),
                   XShortField("reserved_1", 0x0000),
                   StrFixedLenField("phone_number", '', 64),
                   StrFixedLenField("subaddress", '', 64)]


_PPTP_result_code = {1: "Connected",
                     2: "General error",
                     3: "No Carrier",
                     4: "Busy",
                     5: "No dial tone",
                     6: "Time-out",
                     7: "Do not accept"}


class PPTPOutgoingCallReply(PPTP):
    name = "PPTP Outgoing Call Reply"
    fields_desc = [LenField("len", 32),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 8, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ShortField("call_id", 1),
                   ShortField("peer_call_id", 1),
                   ByteEnumField("result_code", 1, _PPTP_result_code),
                   ByteEnumField("error_code", 0, _PPTP_general_error_code),
                   ShortField("cause_code", 0),
                   IntField("connect_speed", 100000000),
                   ShortField("pkt_window_size", 16),
                   ShortField("pkt_proc_delay", 0),
                   IntField("channel_id", 0)]

    def answers(self, other):
        return isinstance(other, PPTPOutgoingCallRequest) and other.call_id == self.peer_call_id  # noqa: E501


class PPTPIncomingCallRequest(PPTP):
    name = "PPTP Incoming Call Request"
    fields_desc = [LenField("len", 220),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 9, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ShortField("call_id", 1),
                   ShortField("call_serial_number", 1),
                   IntEnumField("bearer_type", 3, _PPTP_bearer_type),
                   IntField("channel_id", 0),
                   ShortField("dialed_number_len", 0),
                   ShortField("dialing_number_len", 0),
                   StrFixedLenField("dialed_number", "", 64),
                   StrFixedLenField("dialing_number", "", 64),
                   StrFixedLenField("subaddress", "", 64)]


class PPTPIncomingCallReply(PPTP):
    name = "PPTP Incoming Call Reply"
    fields_desc = [LenField("len", 148),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 10, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ShortField("call_id", 1),
                   ShortField("peer_call_id", 1),
                   ByteEnumField("result_code", 1, _PPTP_result_code),
                   ByteEnumField("error_code", 0, _PPTP_general_error_code),
                   ShortField("pkt_window_size", 64),
                   ShortField("pkt_transmit_delay", 0),
                   XShortField("reserved_1", 0x0000)]

    def answers(self, other):
        return isinstance(other, PPTPIncomingCallRequest) and other.call_id == self.peer_call_id  # noqa: E501


class PPTPIncomingCallConnected(PPTP):
    name = "PPTP Incoming Call Connected"
    fields_desc = [LenField("len", 28),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 11, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ShortField("peer_call_id", 1),
                   XShortField("reserved_1", 0x0000),
                   IntField("connect_speed", 100000000),
                   ShortField("pkt_window_size", 64),
                   ShortField("pkt_transmit_delay", 0),
                   IntEnumField("framing_type", 1, _PPTP_framing_type)]

    def answers(self, other):
        return isinstance(other, PPTPIncomingCallReply) and other.call_id == self.peer_call_id  # noqa: E501


class PPTPCallClearRequest(PPTP):
    name = "PPTP Call Clear Request"
    fields_desc = [LenField("len", 16),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 12, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ShortField("call_id", 1),
                   XShortField("reserved_1", 0x0000)]


_PPTP_call_disconnect_result = {1: "Lost Carrier",
                                2: "General error",
                                3: "Admin Shutdown",
                                4: "Request"}


class PPTPCallDisconnectNotify(PPTP):
    name = "PPTP Call Disconnect Notify"
    fields_desc = [LenField("len", 148),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 13, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ShortField("call_id", 1),
                   ByteEnumField("result_code", 1,
                                 _PPTP_call_disconnect_result),
                   ByteEnumField("error_code", 0, _PPTP_general_error_code),
                   ShortField("cause_code", 0),
                   XShortField("reserved_1", 0x0000),
                   StrFixedLenField("call_statistic", "", 128)]


class PPTPWANErrorNotify(PPTP):
    name = "PPTP WAN Error Notify"
    fields_desc = [LenField("len", 40),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 14, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ShortField("peer_call_id", 1),
                   XShortField("reserved_1", 0x0000),
                   IntField("crc_errors", 0),
                   IntField("framing_errors", 0),
                   IntField("hardware_overruns", 0),
                   IntField("buffer_overruns", 0),
                   IntField("time_out_errors", 0),
                   IntField("alignment_errors", 0)]


class PPTPSetLinkInfo(PPTP):
    name = "PPTP Set Link Info"
    fields_desc = [LenField("len", 24),
                   ShortEnumField("type", 1, _PPTP_msg_type),
                   XIntField("magic_cookie", _PPTP_MAGIC_COOKIE),
                   ShortEnumField("ctrl_msg_type", 15, _PPTP_ctrl_msg_type),
                   XShortField("reserved_0", 0x0000),
                   ShortField("peer_call_id", 1),
                   XShortField("reserved_1", 0x0000),
                   XIntField("send_accm", 0x00000000),
                   XIntField("receive_accm", 0x00000000)]


bind_layers(TCP, PPTP, sport=1723)
bind_layers(TCP, PPTP, dport=1723)
