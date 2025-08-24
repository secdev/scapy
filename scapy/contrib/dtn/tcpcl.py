# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = TCP Convergence Layer version 4 (TCPCLv4)
# scapy.contrib.status = loads

"""
    TCP Convergence Layer version 4 (TCPCLv4) layer
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :author:    Timothy Recker, timothy.recker@nasa.gov
"""

from scapy.packet import Packet, Raw, bind_layers
from scapy.fields import (
    XByteEnumField,
    PacketField,
    BitField,
    BitFieldLenField,
    ConditionalField,
    PacketListField,
    StrLenField,
    FieldLenField
)

import struct
from enum import IntEnum

from scapy.contrib.dtn.common import ControlPacket, FieldPacket
import scapy.contrib.dtn.bpv7 as BPv7


class MagicValueError(Exception):
    """
    Exception raised when a ContactHeader is dissected and the magic value is incorrect.
    """
    def __init__(self, value):
        super().__init__(f"Tried to decode ContactHeader with invalid magic value of {value}")


class ContactHeader(ControlPacket):
    MAGIC_VALUE = 0x64746e21

    class Flag(IntEnum):
        CAN_TLS = 0x01

    fields_desc = [
        BitField("magic", MAGIC_VALUE, 32),
        BitField("version", 4, 8),
        XByteEnumField("flags", 0, {Flag.CAN_TLS: "can tls"})
    ]

    def post_dissect(self, s):
        if self.magic != self.MAGIC_VALUE:
            raise MagicValueError(self.magic)
        return super().post_dissect(s)


class MsgHeader(Packet):
    class MsgType(IntEnum):
        SESS_INIT = 0x07
        SESS_TERM = 0x05
        XFER_SEGMENT = 0x01
        XFER_ACK = 0x02
        XFER_REFUSE = 0x03
        KEEPALIVE = 0x04
        MSG_REJECT = 0x06

    fields_desc = [
        XByteEnumField("type", MsgType.XFER_SEGMENT, {
            MsgType.SESS_INIT: "sess_init",
            MsgType.SESS_TERM: "sess_term",
            MsgType.XFER_SEGMENT: "xfer_segment",
            MsgType.XFER_ACK: "xfer_ack",
            MsgType.XFER_REFUSE: "xfer_refuse",
            MsgType.KEEPALIVE: "keepalive",
            MsgType.MSG_REJECT: "msg_reject"
        })
    ]


class Ext(FieldPacket):
    """
    Class definition for an Extension Item in the format of a Type-Length-Value container.
    """
    class Flag(IntEnum):
        CRITICAL = 0x01

    class Type(IntEnum):
        LENGTH = 0x0001

    fields_desc = [
        XByteEnumField("flags", 0, {Flag.CRITICAL: "critical"}),
        BitField("type", 0, 16),
        BitFieldLenField("length", default=0, size=16, length_of="data"),
        StrLenField("data", 0, length_from=lambda pkt: pkt.length)
    ]


class SessInit(ControlPacket):
    fields_desc = [
        BitField("keepalive", 0, 16),
        BitField("segment_mru", 0, 64),
        BitField("transfer_mru", 0, 64),
        FieldLenField("id_length", None, length_of="id", fmt="H"),  # Node ID Length (U16)
        StrLenField("id", b"", length_from=lambda pkt: pkt.id_length),  # Node ID Data (variable)
        BitFieldLenField("ext_length", 0, 32, length_of="ext_items"),
        ConditionalField(
            PacketListField("ext_items",
                            [],
                            Ext,
                            length_from=lambda pkt: pkt.ext_length),
            lambda pkt: pkt.ext_length > 0)
    ]


class Keepalive(ControlPacket):
    """
    A keepalive message consists only of a MsgHeader with the type code KEEPALIVE.
    """


class MsgReject(ControlPacket):
    class ReasonCode(IntEnum):
        UNKNOWN = 0x01
        UNSUPPORTED = 0x02
        UNEXPECTED = 0x03

    fields_desc = [
        XByteEnumField("reason", ReasonCode.UNSUPPORTED, {
            ReasonCode.UNKNOWN: "message type unknown",
            ReasonCode.UNSUPPORTED: "message unsupported",
            ReasonCode.UNEXPECTED: "message unexpected"
        }),
        PacketField("header", MsgHeader(), MsgHeader)
    ]


class Xfer(Packet):
    """
    Abstract class containing fields and flags common to Xfer messages
    """
    class Flag(IntEnum):
        END = 0x01
        START = 0x02

    fields_desc = [
        XByteEnumField("flags", 0, {
            Flag.END: "END",
            Flag.START: "START",
            Flag.START | Flag.END: "START|END"
        }),
        BitField("id", 0, 64)
    ]


class InvalidPayloadError(Exception):
    """
    This error indicates that an XferSegment contains raw bytes instead of
    a properly formatted Bundle as its payload.
    """
    def __init__(self, payload_bytes):
        super().__init__(f"Failed to fully parse Bundle from Xfer payload: bundle={payload_bytes}")


class XferSegment(Xfer):
    """
    Packet for transferring a data segment
    """
    fields_desc = Xfer.fields_desc + [
        ConditionalField(
            BitFieldLenField("ext_length", default=0, size=32, length_of="ext_items"),
            lambda pkt: pkt.flags & Xfer.Flag.START),
        ConditionalField(
            PacketListField("ext_items",
                            [Ext(type=Ext.Type.LENGTH)],
                            Ext,
                            length_from=lambda pkt: pkt.ext_length),
            lambda pkt: (pkt.flags & Xfer.Flag.START) and (pkt.ext_length > 0)),
        BitField("length", default=0, size=64)
    ]

    def post_build(self, pkt, pay):
        # calculate the length field
        if not self.length:
            index = len(pkt) - 8  # size of length is 8 bytes, thus position=len(pkt)-8
            length = len(pay)
            pkt = pkt[:index] + struct.pack('!Q', length)
        return pkt + pay

    def post_dissect(self, s):
        "An XferSegment message should have a Bundle as payload. If it has raw bytes instead, raise an error."
        try:
            if self[Raw].load is not None:
                raise InvalidPayloadError(self[Raw].load)
        except IndexError:  # Raw layer or load field does not exist
            pass  # no action required

        return s


class XferAck(ControlPacket):
    fields_desc = Xfer.fields_desc + [
        BitField("length", default=0, size=64)
    ]


class XferRefuse(ControlPacket):
    class ReasonCode(IntEnum):
        UNKNOWN = 0x00
        COMPLETED = 0x01
        NO_RESOURCES = 0x02
        RETRANSMIT = 0x03
        NOT_ACCEPTABLE = 0x04
        EXT_FAIL = 0x05
        SESS_TERM = 0x06

    fields_desc = [
        XByteEnumField("reason", ReasonCode.UNKNOWN, {
            ReasonCode.UNKNOWN: "unknown",
            ReasonCode.COMPLETED: "complete bundle received",
            ReasonCode.NO_RESOURCES: "resources exhausted",
            ReasonCode.RETRANSMIT: "retransmit bundle",
            ReasonCode.NOT_ACCEPTABLE: "bundle not acceptable",
            ReasonCode.EXT_FAIL: "failed to process extensions",
            ReasonCode.SESS_TERM: "session is terminating"
        }),
        BitField("id", 0, 64)
    ]


class SessTerm(ControlPacket):
    class Flag(IntEnum):
        REPLY = 0x01

    class ReasonCode(IntEnum):
        UNKNOWN = 0x00
        TIMEOUT = 0x01
        MISMATCH = 0x02
        BUSY = 0x03
        CONTACT_FAIL = 0x04
        NO_RESOURCES = 0x05

    fields_desc = [
        XByteEnumField("flags", 0, {Flag.REPLY: "reply"}),
        XByteEnumField("reason", ReasonCode.UNKNOWN, {
            ReasonCode.UNKNOWN: "unknown",
            ReasonCode.TIMEOUT: "idle timeout",
            ReasonCode.MISMATCH: "version mismatch",
            ReasonCode.BUSY: "entity busy",
            ReasonCode.CONTACT_FAIL: "failed to process contact header or sess init",
            ReasonCode.NO_RESOURCES: "entity resource exhaustion"
        }),

    ]


# Bind all TCPCL message headers to TCPCL messages.
# This way, if `some_bytes` consists of the raw representation of a TCPCL message,
# you can evaluate e.g. `x=MsgHeader(some_bytes)` and `x` will be a Packet consisting of a TCPCL
# MsgHeader with the correct type code plus a payload of the correct TCPCL message type.
bind_layers(MsgHeader, SessInit, type=MsgHeader.MsgType.SESS_INIT)
bind_layers(MsgHeader, Keepalive, type=MsgHeader.MsgType.KEEPALIVE)
bind_layers(MsgHeader, MsgReject, type=MsgHeader.MsgType.MSG_REJECT)
bind_layers(MsgHeader, XferSegment, type=MsgHeader.MsgType.XFER_SEGMENT)
bind_layers(MsgHeader, XferAck, type=MsgHeader.MsgType.XFER_ACK)
bind_layers(MsgHeader, XferRefuse, type=MsgHeader.MsgType.XFER_REFUSE)
bind_layers(MsgHeader, SessTerm, type=MsgHeader.MsgType.SESS_TERM)
bind_layers(XferSegment, BPv7.Bundle)
