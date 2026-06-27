# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

#  V2GInjector is a tool to penetrate V2G network through PowerLine, monitor and inject traffic
# Copyright (C) 2019 Sebastien Dudek (@FlUxIuS)

# scapy.contrib.description = ISO 15118 V2G Transport Protocol and SECC Discovery
# scapy.contrib.status = loads

import struct

from scapy.fields import (
    ByteField,
    FieldLenField,
    IntField,
    IP6Field,
    ShortEnumField,
    ShortField,
    StrLenField,
)
from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet, bind_bottom_up, bind_layers

V2GTP_PAYLOAD_TYPES = {
    0x8001: "EXI",
}

SECC_TYPES = {
    0x9000: "SECC_RequestMessage",
    0x9001: "SECC_ResponseMessage",
}


class V2GTP(Packet):
    name = "V2GTP"
    fields_desc = [
        ByteField("Version", 0x01),
        ByteField("Invers", 0xfe),
        ShortEnumField("PayloadType", 0x8001, V2GTP_PAYLOAD_TYPES),
        FieldLenField("PayloadLen", 0, count_of="Payload", fmt="!I"),
        StrLenField("Payload", "", length_from=lambda pkt: pkt.PayloadLen),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        payload = self.Payload or pay
        if self.PayloadLen == 0 and payload:
            pkt = pkt[:4] + struct.pack("!I", len(payload)) + pkt[8:]
        if self.Payload:
            return pkt
        return pkt + pay


class SECC_RequestMessage(Packet):
    name = "SECC_RequestMessage"
    fields_desc = [
        ByteField("SecurityProtocol", 0x0),
        ByteField("TransportProtocol", 0x0),
    ]


class SECC_ResponseMessage(Packet):
    name = "SECC_ResponseMessage"
    fields_desc = [
        IP6Field("TargetAddress", "::"),
        ShortField("TargetPort", 0),
        ByteField("SecurityProtocol", 0x0),
        ByteField("TransportProtocol", 0x0),
    ]


class SECC(Packet):
    name = "SECC"
    fields_desc = [
        ByteField("Version", 0x01),
        ByteField("Inversion", 0xfe),
        ShortEnumField("SECCType", 0, SECC_TYPES),
        IntField("PayloadLen", 0),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        if self.PayloadLen == 0 and pay:
            pkt = pkt[:4] + struct.pack("!I", len(pay)) + pkt[8:]
        return pkt + pay


bind_bottom_up(UDP, SECC, sport=15118)
bind_bottom_up(UDP, SECC, dport=15118)
bind_layers(UDP, SECC, sport=15118, dport=15118)

bind_bottom_up(TCP, V2GTP, sport=15118)
bind_bottom_up(TCP, V2GTP, dport=15118)
bind_layers(TCP, V2GTP, sport=15118, dport=15118)

bind_layers(SECC, SECC_RequestMessage, SECCType=0x9000)
bind_layers(SECC, SECC_ResponseMessage, SECCType=0x9001)
