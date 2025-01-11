# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Satveer Brar

"""
PTP (Precision Time Protocol).
References : IEEE 1588-2008
"""

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
    PacketField,
    XLongField,
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


class OriginTimestamp(Packet):
    name = "originTimestamp"
    fields_desc = [
        BitField("seconds", 0, 48),
        IntField("nanoseconds", 0)
    ]


class PTPHeader(Packet):
    """
    PTP Header based on IEEE 1588-2008 / Section 13.3.
    """
    name = "PTPHeader"
    match_subclass = True
    fields_desc = [
        BitField("transportSpecific", 0, 4),
        BitEnumField("messageType", 0x0, 4, _message_type),
        BitField("reserved1", 0, 4),
        BitField("version", 2, 4),
        ShortField("messageLength", 0),
        ByteField("domainNumber", 0),
        ByteField("reserved2", 0),
        FlagsField("flags", 0, 16, _flags),
        LongField("correctionField", 0),
        IntField("reserved3", 0),
        XLongField("clockIdentity", 0),
        ShortField("portNumber", 0),
        ShortField("sequenceId", 0),
        ByteEnumField("controlField", 0, _control_field),
        ByteField("logMessageInterval", 0)
    ]

    def guess_payload_class(self, payload):  # type: (bytes) -> Type[Packet]
        """
        Guess payload class based on messageType
        """

        if self.messageType == 0x0:
            return Sync
        elif self.messageType == 0x1:
            return DelayReq
        elif self.messageType == 0x2:
            return PDelayReq
        elif self.messageType == 0x3:
            return PDelayResp
        elif self.messageType == 0x8:
            return FollowUp
        elif self.messageType == 0x9:
            return DelayResp
        elif self.messageType == 0xA:
            return PDelayRespFollow
        elif self.messageType == 0xB:
            return Announce
        elif self.messageType == 0xC:
            return Signaling
        elif self.messageType == 0xD:
            return Management

        return Packet.guess_payload_class(self, payload)

    def post_build(self, pkt, pay):  # type: (bytes, bytes) -> bytes
        """
        Update the messageLength field after building the packet
        """
        pass


class Sync(Packet):
    """
    Handle the Sync message type in PTP
    """
    name = "Sync"
    fields_desc = [
        PacketField("originTimestamp", 0, OriginTimestamp)
    ]


class DelayReq(Packet):
    """
    Handle the DelayReq message type in PTP
    """


class PDelayReq(Packet):
    """
    Handle the PDelayReq message type in PTP
    """


class FollowUp(Packet):
    """
    Handle the FollowUp message type in PTP
    """


class PDelayResp(Packet):
    """
    Handle the PDelayResp message type in PTP
    """


class DelayResp(Packet):
    """
    Handle the DelayResp message type in PTP
    """


class PDelayRespFollow(Packet):
    """
    Handle the PDelayRespFollow message type in PTP
    """


class Announce(Packet):
    """
    Handle the Announce message type in PTP
    """


class Signaling(Packet):
    """
    Handle the Signaling message type in PTP
    """


class Management(Packet):
    """
    Handle the Management message type in PTP
    """


##############################################################################
#     Layer bindings
##############################################################################

bind_layers(UDP, PTPHeader, sport=319, dport=319)
bind_layers(UDP, PTPHeader, sport=320, dport=320)