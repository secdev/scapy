# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Satveer Brar

"""
PTP (Precision Time Protocol).
References : IEEE 1588-2008
"""

import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteField,
    IntField,
    LongField,
    ShortField,
    ByteEnumField,
    FlagsField,
    XLongField,
    XByteField,
    ConditionalField,
)
from scapy.layers.inet import UDP


#############################################################################
#     PTPv2
#############################################################################

# IEEE 1588-2008 / Section 13.3.2.2

_message_type = {
    0x0: "Sync",
    0x1: "Delay_Req",
    0x2: "Pdelay_Req",
    0x3: "Pdelay_Resp",
    0x4: "Reserved",
    0x5: "Reserved",
    0x6: "Reserved",
    0x7: "Reserved",
    0x8: "Follow_Up",
    0x9: "Delay_Resp",
    0xA: "Pdelay_Resp_Follow",
    0xB: "Announce",
    0xC: "Signaling",
    0xD: "Management",
    0xE: "Reserved",
    0xF: "Reserved"
}

_control_field = {
    0x00: "Sync",
    0x01: "Delay_Req",
    0x02: "Follow_Up",
    0x03: "Delay_Resp",
    0x04: "Management",
    0x05: "All others",
}

_flags = {
    0x0001: "alternateMasterFlag",
    0x0002: "twoStepFlag",
    0x0004: "unicastFlag",
    0x0010: "ptpProfileSpecific1",
    0x0020: "ptpProfileSpecific2",
    0x0040: "reserved",
    0x0100: "leap61",
    0x0200: "leap59",
    0x0400: "currentUtcOffsetValid",
    0x0800: "ptpTimescale",
    0x1000: "timeTraceable",
    0x2000: "frequencyTraceable"
}


class PTP(Packet):
    """
    PTP packet based on IEEE 1588-2008 / Section 13.3
    """

    name = "PTP"
    match_subclass = True
    fields_desc = [
        BitField("transportSpecific", 0, 4),
        BitEnumField("messageType", 0x0, 4, _message_type),
        BitField("reserved1", 0, 4),
        BitField("version", 2, 4),
        ShortField("messageLength", None),
        ByteField("domainNumber", 0),
        ByteField("reserved2", 0),
        FlagsField("flags", 0, 16, _flags),
        LongField("correctionField", 0),
        IntField("reserved3", 0),
        XLongField("clockIdentity", 0),
        ShortField("portNumber", 0),
        ShortField("sequenceId", 0),
        ByteEnumField("controlField", 0, _control_field),
        ByteField("logMessageInterval", 0),
        ConditionalField(BitField("originTimestamp_seconds", 0, 48),
                         lambda pkt: pkt.messageType in [0x0, 0x1, 0x2, 0xB]),
        ConditionalField(IntField("originTimestamp_nanoseconds", 0),
                         lambda pkt: pkt.messageType in [0x0, 0x1, 0x2, 0xB]),
        ConditionalField(BitField("preciseOriginTimestamp_seconds", 0, 48),
                         lambda pkt: pkt.messageType == 0x8),
        ConditionalField(IntField("preciseOriginTimestamp_nanoseconds", 0),
                         lambda pkt: pkt.messageType == 0x8),
        ConditionalField(BitField("requestReceiptTimestamp_seconds", 0, 48),
                         lambda pkt: pkt.messageType == 0x3),
        ConditionalField(IntField("requestReceiptTimestamp_nanoseconds", 0),
                         lambda pkt: pkt.messageType == 0x3),
        ConditionalField(BitField("receiveTimestamp_seconds", 0, 48),
                         lambda pkt: pkt.messageType == 0x9),
        ConditionalField(IntField("receiveTimestamp_nanoseconds", 0),
                         lambda pkt: pkt.messageType == 0x9),
        ConditionalField(BitField("responseOriginTimestamp_seconds", 0, 48),
                         lambda pkt: pkt.messageType == 0xA),
        ConditionalField(IntField("responseOriginTimestamp_nanoseconds", 0),
                         lambda pkt: pkt.messageType == 0xA),
        ConditionalField(ShortField("currentUtcOffset", 0),
                         lambda pkt: pkt.messageType == 0xB),
        ConditionalField(ByteField("reserved4", 0),
                         lambda pkt: pkt.messageType == 0xB),
        ConditionalField(ByteField("grandmasterPriority1", 0),
                         lambda pkt: pkt.messageType == 0xB),
        ConditionalField(ByteField("grandmasterClockClass", 0),
                         lambda pkt: pkt.messageType == 0xB),
        ConditionalField(XByteField("grandmasterClockAccuracy", 0),
                         lambda pkt: pkt.messageType == 0xB),
        ConditionalField(ShortField("grandmasterClockVariance", 0),
                         lambda pkt: pkt.messageType == 0xB),
        ConditionalField(ByteField("grandmasterPriority2", 0),
                         lambda pkt: pkt.messageType == 0xB),
        ConditionalField(XLongField("grandmasterIdentity", 0),
                         lambda pkt: pkt.messageType == 0xB),
        ConditionalField(ShortField("stepsRemoved", 0),
                         lambda pkt: pkt.messageType == 0xB),
        ConditionalField(XByteField("timeSource", 0),
                         lambda pkt: pkt.messageType == 0xB)

    ]

    def post_build(self, pkt, pay):  # type: (bytes, bytes) -> bytes
        """
        Update the messageLength field after building the packet
        """
        if self.messageLength is None:
            pkt = pkt[:2] + struct.pack("!H", len(pkt)) + pkt[4:]

        return pkt + pay


#     Layer bindings

bind_layers(UDP, PTP, sport=319, dport=319)
bind_layers(UDP, PTP, sport=320, dport=320)
