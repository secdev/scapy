#! /usr/bin/env python

# MIT License

# Copyright (c) 2018 Jose Amores

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Sebastian Baar <sebastian.baar@gmx.de>
# This program is published under a GPLv2 license

import struct

from scapy.layers.inet import TCP, UDP
from scapy.modules.six.moves import range
from scapy.packet import Packet, bind_layers
from scapy.fields import ShortField, BitEnumField, ConditionalField, \
    BitField, PacketField, IntField, ByteField, ByteEnumField


class _SOMEIP_MessageId(Packet):
    """ MessageId subpacket."""
    name = "MessageId"
    fields_desc = [
        ShortField("srv_id", 0),
        BitEnumField("sub_id", 0, 1, {0: "METHOD_ID", 1: "EVENT_ID"}),
        ConditionalField(BitField("method_id", 0, 15),
                         lambda pkt: pkt.sub_id == 0),
        ConditionalField(BitField("event_id", 0, 15),
                         lambda pkt: pkt.sub_id == 1)
    ]

    def extract_padding(self, s):
        return "", s


class _SOMEIP_RequestId(Packet):
    """ RequestId subpacket."""
    name = "RequestId"
    fields_desc = [
        ShortField("client_id", 0),
        ShortField("session_id", 0)
    ]

    def extract_padding(self, s):
        return "", s


class SOMEIP(Packet):
    """ SOME/IP Packet."""

    PROTOCOL_VERSION = 0x01
    INTERFACE_VERSION = 0x01
    LEN_OFFSET = 0x08
    TYPE_REQUEST = 0x00
    TYPE_REQUEST_NO_RET = 0x01
    TYPE_NOTIFICATION = 0x02
    TYPE_REQUEST_ACK = 0x40
    TYPE_REQUEST_NORET_ACK = 0x41
    TYPE_NOTIFICATION_ACK = 0x42
    TYPE_RESPONSE = 0x80
    TYPE_ERROR = 0x81
    TYPE_RESPONSE_ACK = 0xc0
    TYPE_ERROR_ACK = 0xc1
    RET_E_OK = 0x00
    RET_E_NOT_OK = 0x01
    RET_E_UNKNOWN_SERVICE = 0x02
    RET_E_UNKNOWN_METHOD = 0x03
    RET_E_NOT_READY = 0x04
    RET_E_NOT_REACHABLE = 0x05
    RET_E_TIMEOUT = 0x06
    RET_E_WRONG_PROTOCOL_V = 0x07
    RET_E_WRONG_INTERFACE_V = 0x08
    RET_E_MALFORMED_MSG = 0x09
    RET_E_WRONG_MESSAGE_TYPE = 0x0a

    _OVERALL_LEN_NOPAYLOAD = 16

    name = "SOME/IP"

    fields_desc = [
        PacketField("msg_id", _SOMEIP_MessageId(),
                    _SOMEIP_MessageId),
        IntField("len", None),
        PacketField("req_id", _SOMEIP_RequestId(),
                    _SOMEIP_RequestId),
        ByteField("proto_ver", PROTOCOL_VERSION),
        ByteField("iface_ver", INTERFACE_VERSION),
        ByteEnumField("msg_type", TYPE_REQUEST, {
            TYPE_REQUEST: "REQUEST",
            TYPE_REQUEST_NO_RET: "REQUEST_NO_RETURN",
            TYPE_NOTIFICATION: "NOTIFICATION",
            TYPE_REQUEST_ACK: "REQUEST_ACK",
            TYPE_REQUEST_NORET_ACK: "REQUEST_NO_RETURN_ACK",
            TYPE_NOTIFICATION_ACK: "NOTIFICATION_ACK",
            TYPE_RESPONSE: "RESPONSE",
            TYPE_ERROR: "ERROR",
            TYPE_RESPONSE_ACK: "RESPONSE_ACK",
            TYPE_ERROR_ACK: "ERROR_ACK",
        }),
        ByteEnumField("retcode", 0, {
            RET_E_OK: "E_OK",
            RET_E_NOT_OK: "E_NOT_OK",
            RET_E_UNKNOWN_SERVICE: "E_UNKNOWN_SERVICE",
            RET_E_UNKNOWN_METHOD: "E_UNKNOWN_METHOD",
            RET_E_NOT_READY: "E_NOT_READY",
            RET_E_NOT_REACHABLE: "E_NOT_REACHABLE",
            RET_E_TIMEOUT: "E_TIMEOUT",
            RET_E_WRONG_PROTOCOL_V: "E_WRONG_PROTOCOL_VERSION",
            RET_E_WRONG_INTERFACE_V: "E_WRONG_INTERFACE_VERSION",
            RET_E_MALFORMED_MSG: "E_MALFORMED_MESSAGE",
            RET_E_WRONG_MESSAGE_TYPE: "E_WRONG_MESSAGE_TYPE",
        }),
    ]

    def post_build(self, pkt, pay):
        length = self.len
        if (length is None):
            length = self.LEN_OFFSET + len(pay)
            pkt = pkt[:4] + struct.pack("!I", length) + pkt[8:]
        return pkt + pay

    def answers(self, other):
        if other.__class__ == self.__class__:
            if self.msg_type in [SOMEIP.TYPE_REQUEST_NO_RET,
                                 SOMEIP.TYPE_REQUEST_NORET_ACK]:
                return 0
            return self.payload.answers(other.payload)
        return 0


def _bind_someip_layers():
    for i in range(15):
        bind_layers(UDP, SOMEIP, sport=30490 + i)
        bind_layers(TCP, SOMEIP, sport=30490 + i)


_bind_someip_layers()
