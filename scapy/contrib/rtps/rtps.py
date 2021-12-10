"""
Real-Time Publish-Subscribe Protocol (RTPS) dissection

Copyright (C) 2021 Trend Micro Incorporated
Copyright (C) 2021 Alias Robotics S.L.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

# scapy.contrib.description = RTPS abstractions
# scapy.contrib.status = library

import struct
from typing import List, Optional

from scapy.base_classes import Packet_metaclass
from scapy.fields import (
    ConditionalField,
    IntField,
    PacketField,
    PacketListField,
    ShortField,
    StrField,
    StrFixedLenField,
    StrLenField,
    X3BytesField,
    XByteField,
    XIntField,
    XLongField,
    XNBytesField,
    XShortField,
    XStrLenField,
    FlagsField,
    Field,
    EnumField,
)
from scapy.packet import Packet, bind_layers

from scapy.contrib.rtps.common_types import (
    EField,
    EPacket,
    EPacketField,
    InlineQoSPacketField,
    ProtocolVersionPacket,
    DataPacketField,
    STR_MAX_LEN,
    SerializedDataField,
    VendorIdPacket,
)
from scapy.contrib.rtps.pid_types import (
    ParameterListPacket,
    get_pid_class,
    PID_SENTINEL
)


_rtps_reserved_entity_ids = {
    b"\x00\x00\x00\x00": "ENTITY_UNKNOWN",
    b"\x00\x00\x01\xc1": "ENTITYID_PARTICIPANT",
    b"\x00\x00\x02\xc2": "ENTITYID_SEDP_BUILTIN_TOPIC_WRITER",
    b"\x00\x00\x02\xc7": "ENTITYID_SEDP_BUILTIN_TOPIC_READER",
    b"\x00\x00\x03\xc2": "ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER",
    b"\x00\x00\x03\xc7": "ENTITYID_SEDP_BUILTIN_PUBLICATIONS_READER",
    b"\x00\x00\x04\xc2": "ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER",
    b"\x00\x00\x04\xc7": "ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_READER",
    b"\x00\x01\x00\xc2": "ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER",
    b"\x00\x01\x00\xc7": "ENTITYID_SPDP_BUILTIN_PARTICIPANT_READER",
    b"\x00\x02\x00\xc2": "ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER",
    b"\x00\x02\x00\xc7": "ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER",
}


class GUIDPrefixPacket(Packet):
    name = "RTPS GUID Prefix"
    fields_desc = [
        XIntField("hostId", 0),
        XIntField("appId", 0),
        XIntField("instanceId", 0),
    ]

    def extract_padding(self, p):
        return b"", p


class RTPS(Packet):
    """
    RTPS package, overall structure as per DDSI-RTPS v2.3, section 9.4.1
    The structure is also discussed at 8.3.3.

    The wire representation (bits) is as follows:

        0...2...........7...............15.............23.............. 31
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Header (RTPSHeader)                                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Submessage  (RTPSSubmessage)                                  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        .................................................................
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Submessage                                                    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    For representation purposes, this package will only contain the header
    and other submessages will be bound as layers (bind_layers):

    RTPS Header structure as per DDSI-RTPS v2.3, section 9.4.4
    The wire representation (bits) is as follows:

        0...2...........7...............15.............23...............31
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |      'R'      |       'T'     |      'P'      |       'S'     |
        +---------------+---------------+---------------+---------------+
        | ProtocolVersion version       | VendorId vendorId             |
        +---------------+---------------+---------------+---------------+
        |                                                               |
        +                                                               +
        |                 GuidPrefix      guidPrefix                    |
        +                                                               +
        |                                                               |
        +---------------+---------------+---------------+---------------+

    References:

    * https://community.rti.com/static/documentation/wireshark/current/doc/understanding_rtps.html # noqa E501
    * https://www.omg.org/spec/DDSI-RTPS/2.3/PDF
    * https://www.wireshark.org/docs/dfref/r/rtps.html
    """

    name = "RTPS Header"
    fields_desc = [
        StrFixedLenField("magic", b"", 4),
        PacketField(
            "protocolVersion", ProtocolVersionPacket(), ProtocolVersionPacket),
        PacketField(
            "vendorId", VendorIdPacket(), VendorIdPacket),
        PacketField(
            "guidPrefix", GUIDPrefixPacket(), GUIDPrefixPacket),
    ]


class InlineQoSPacket(EPacket):
    name = "Inline QoS"

    fields_desc = [
        PacketListField("parameters", [], next_cls_cb=get_pid_class),
        PacketField("sentinel", "", PID_SENTINEL),
    ]


class ParticipantMessageDataPacket(EPacket):
    name = "Participant Message Data"
    fields_desc = [
        PacketField("guidPrefix", "", GUIDPrefixPacket),
        XIntField("kind", 0),
        EField(XIntField("sequenceSize", 0)),  # octets
        StrLenField(
            "serializedData",
            "",
            length_from=lambda x: x.sequenceSize * 4,
            max_length=STR_MAX_LEN,
        ),
    ]


class DataPacket(EPacket):
    name = "Data Packet"
    _pl_type = None
    _pl_len = 0

    fields_desc = [
        XShortField("encapsulationKind", 0),
        XShortField("encapsulationOptions", 0),
        # if payload encoding == PL_CDR_{LE,BE} then parameter list
        ConditionalField(
            EPacketField("parameterList", "", ParameterListPacket),
            lambda pkt: pkt.encapsulationKind == 0x0003,
        ),
        # if writer entity id == 0x200c2: then participant message data
        ConditionalField(
            EPacketField(
                "participantMessageData", "", ParticipantMessageDataPacket),
            lambda pkt: pkt._pl_type == "ParticipantMessageData",
        ),
        # else (neither the cases)
        ConditionalField(
            SerializedDataField(
                "serializedData", "", length_from=lambda pkt: pkt._pl_len
            ),
            lambda pkt: (
                pkt.encapsulationKind != 0x0003 \
                and pkt._pl_type != "ParticipantMessageData"
            ),
        ),
    ]

    def __init__(
        self,
        *args,
        writer_entity_id_key=None,
        writer_entity_id_kind=None,
        endianness=None,
        pl_len=0,
        **kwargs
    ):
        if writer_entity_id_key == 0x200 and writer_entity_id_kind == 0xC2:
            DataPacket._pl_type = "ParticipantMessageData"
        else:
            DataPacket._pl_type = "SerializedData"

        DataPacket._pl_len = pl_len

        super().__init__(*args, endianness=endianness, **kwargs)


class RTPSSubMessage_DATA(EPacket):
    """
    0...2...........7...............15.............23...............31
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | RTPS_DATA     |     flags     |      octetsToNextHeader       |
    +---------------+---------------+---------------+---------------+
    | Flags extraFlags              |      octetsToInlineQos        |
    +---------------+---------------+---------------+---------------+
    | EntityId readerEntityId                                       |
    +---------------+---------------+---------------+---------------+
    | EntityId writerEntityId                                       |
    +---------------+---------------+---------------+---------------+
    |                                                               |
    + SequenceNumber writerSeqNum                                   +
    |                                                               |
    +---------------+---------------+---------------+---------------+
    |                                                               |
    ~ ParameterList inlineQos [only if Q==1]                        ~
    |                                                               |
    +---------------+---------------+---------------+---------------+
    |                                                               |
    ~ SerializedData serializedData [only if D==1 || K==1]          ~
    |                                                               |
    +---------------+---------------+---------------+---------------+
    """

    name = "RTPS DATA (0x15)"
    fields_desc = [
        XByteField("submessageId", 0x15),
        XByteField("submessageFlags", 0x00),
        EField(ShortField("octetsToNextHeader", 0)),
        XNBytesField("extraFlags", 0x0000, 2),
        EField(ShortField("octetsToInlineQoS", 0)),
        X3BytesField("readerEntityIdKey", 0),
        XByteField("readerEntityIdKind", 0),
        X3BytesField("writerEntityIdKey", 0),
        XByteField("writerEntityIdKind", 0),
        # EnumField(
        #     "reader_id",
        #     default=b"\x00\x00\x00\x00",
        #     fmt="4s",
        #     enum=_rtps_reserved_entity_ids,
        # ),
        # EnumField(
        #     "writer_id",
        #     default=b"\x00\x00\x00\x00",
        #     fmt="4s",
        #     enum=_rtps_reserved_entity_ids,
        # ),
        EField(IntField("writerSeqNumHi", 0)),
        EField(IntField("writerSeqNumLow", 0)),
        # -------------------------------------
        ConditionalField(
            InlineQoSPacketField("inlineQoS", "", InlineQoSPacket),
            lambda pkt: pkt.submessageFlags & 0b00000010 == 0b00000010,
        ),
        ConditionalField(
            DataPacketField("key", "", DataPacket),
            lambda pkt: pkt.submessageFlags & 0b00001000 == 0b00001000,
        ),
        ConditionalField(
            DataPacketField("data", "", DataPacket),
            lambda pkt: pkt.submessageFlags & 0b00000100 == 0b00000100,
        ),
    ]


class RTPSSubMessage_INFO_TS(EPacket):
    """
    0...2...........7...............15.............23...............31
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   INFO_TS     |     flags     |      octetsToNextHeader       |
    +---------------+---------------+---------------+---------------+
    |                                                               |
    + Timestamp timestamp [only if T==1]                            +
    |                                                               |
    +---------------+---------------+---------------+---------------+
    """

    name = "RTPS INFO_TS (0x09)"
    fields_desc = [
        XByteField("submessageId", 0x09),
        FlagsField(
            "submessageFlags", 0, 8,
            ["E", "I", "?", "?", "?", "?", "?", "?"]),
        EField(ShortField("octetsToNextHeader", 0)),
        ConditionalField(
            Field("ts_seconds", default=0, fmt="<l"),
            lambda pkt: str(pkt.submessageFlags).find("I"),
        ),
        ConditionalField(
            Field("ts_fraction", default=0, fmt="<L"),
            lambda pkt: str(pkt.submessageFlags).find("I"),
        ),
    ]


class RTPSSubMessage_ACKNACK(EPacket):
    """
    0...2...........7...............15.............23...............31
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   ACKNACK     |     flags     |      octetsToNextHeader       |
    +---------------+---------------+---------------+---------------+
    | EntityId readerEntityId                                       |
    +---------------+---------------+---------------+---------------+
    | EntityId writerEntityId                                       |
    +---------------+---------------+---------------+---------------+
    |                                                               |
    + SequenceNumberSet readerSNState                               +
    |                                                               |
    +---------------+---------------+---------------+---------------+
    | Counter count                                                 |
    +---------------+---------------+---------------+---------------+
    """

    name = "RTPS ACKNACK (0x06)"
    fields_desc = [
        XByteField("submessageId", 0x06),
        XByteField("submessageFlags", 0x00),
        EField(ShortField("octetsToNextHeader", 0)),
        EnumField(
            "reader_id",
            default=b"\x00\x00\x00\x00",
            fmt="4s",
            enum=_rtps_reserved_entity_ids,
        ),
        EnumField(
            "writer_id",
            default=b"\x00\x00\x00\x00",
            fmt="4s",
            enum=_rtps_reserved_entity_ids,
        ),
        XStrLenField(
            "readerSNState",
            0, length_from=lambda pkt: pkt.octetsToNextHeader - 8 - 4
        ),
        XNBytesField("count", 0, 4),
    ]


class RTPSSubMessage_HEARTBEAT(EPacket):
    """
    0...2...........7...............15.............23...............31
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   HEARTBEAT   |     flags     |      octetsToNextHeader       |
    +---------------+---------------+---------------+---------------+
    | EntityId readerEntityId                                       |
    +---------------+---------------+---------------+---------------+
    | EntityId writerEntityId                                       |
    +---------------+---------------+---------------+---------------+
    |                                                               |
    + SequenceNumber firstAvailableSeqNumber                        +
    |                                                               |
    +---------------+---------------+---------------+---------------+
    |                                                               |
    + SequenceNumber lastSeqNumber                                  +
    |                                                               |
    +---------------+---------------+---------------+---------------+
    | Counter count                                                 |
    +---------------+---------------+---------------+---------------+
    """

    name = "RTPS HEARTBEAT (0x07)"
    fields_desc = [
        XByteField("submessageId", 0x07),
        XByteField("submessageFlags", 0),
        EField(ShortField("octetsToNextHeader", 0)),
        EnumField(
            "reader_id",
            default=b"\x00\x00\x00\x00",
            fmt="4s",
            enum=_rtps_reserved_entity_ids,
        ),
        EnumField(
            "writer_id",
            default=b"\x00\x00\x00\x00",
            fmt="4s",
            enum=_rtps_reserved_entity_ids,
        ),
        XLongField("firstAvailableSeqNum", 0),
        XLongField("lastSeqNum", 0),
        EField(IntField("count", 0)),
    ]


class RTPSSubMessage_INFO_DST(EPacket):
    """
    0...2...........7...............15.............23...............31
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   INFO_DST    |     flags     |      octetsToNextHeader       |
    +---------------+---------------+---------------+---------------+
    |                                                               |
    + GuidPrefix guidPrefix                                         +
    |                                                               |
    +---------------+---------------+---------------+---------------+
    """

    name = "RTPS INFO_DTS (0x0e)"
    endianness = ">"

    fields_desc = [
        XByteField("submessageId", 0x0E),
        XByteField("submessageFlags", 0),
        EField(ShortField("octetsToNextHeader", 0)),
        PacketField("guidPrefix", "", GUIDPrefixPacket),
    ]


class RTPSSubMessage_PAD(EPacket):
    """
    0...2...........7...............15.............23...............31
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   PAD         |     flags     |      octetsToNextHeader       |
    +---------------+---------------+---------------+---------------+
    """

    name = "RTPS PAD (0x01)"
    fields_desc = [
        XByteField("submessageId", 0x01),
        XByteField("submessageFlags", 0),
        EField(ShortField("octetsToNextHeader", 0)),
    ]


class RTPSSubMessage_DATA_FRAG(EPacket):
    name = "RTPS DATA_FRAG (0x16)"
    fields_desc = [StrField("uninterpreted_data", 0)]


class RTPSSubMessage_SEC_PREFIX(EPacket):
    name = "RTPS SEC_PREFIX (0x31)"
    fields_desc = [StrField("uninterpreted_data", 0)]


class RTPSSubMessage_SEC_POSTFIX(EPacket):
    name = "RTPS SEC_POSTFIX (0x32)"
    fields_desc = [StrField("uninterpreted_data", 0)]


class RTPSSubMessage_SEC_BODY(EPacket):
    name = "RTPS SEC_BODY (0x30)"
    fields_desc = [StrField("uninterpreted_data", 0)]


class RTPSSubMessage_SRTPS_PREFIX(EPacket):
    name = "RTPS SRPTS_PREFIX (0x33)"
    fields_desc = [StrField("uninterpreted_data", 0)]


class RTPSSubMessage_SRTPS_POSTFIX(EPacket):
    name = "RTPS SRPTS_POSTFIX (0x34)"
    fields_desc = [StrField("uninterpreted_data", 0)]


class RTPSSubMessage_GAP(EPacket):
    name = "RTPS GAP (0x08)"
    fields_desc = [StrField("uninterpreted_data", 0)]


_RTPSSubMessageTypes = {
    0x01: RTPSSubMessage_PAD,
    0x06: RTPSSubMessage_ACKNACK,
    0x07: RTPSSubMessage_HEARTBEAT,
    0x09: RTPSSubMessage_INFO_TS,
    0x0E: RTPSSubMessage_INFO_DST,
    0x15: RTPSSubMessage_DATA,
    # ----------------------------
    0x16: RTPSSubMessage_DATA_FRAG,
    0x31: RTPSSubMessage_SEC_PREFIX,
    0x32: RTPSSubMessage_SEC_POSTFIX,
    0x30: RTPSSubMessage_SEC_BODY,
    0x33: RTPSSubMessage_SRTPS_PREFIX,
    0x34: RTPSSubMessage_SRTPS_POSTFIX,
    0x08: RTPSSubMessage_GAP,
}


def _next_cls_cb(
    pkt: Packet, lst: List[Packet], p: Optional[Packet], remain: str
) -> Optional[Packet_metaclass]:

    sm_id = struct.unpack("!b", remain[0:1])[0]
    next_cls = _RTPSSubMessageTypes.get(sm_id, None)

    return next_cls


class RTPSMessage(Packet):
    name = "RTPS Message"
    fields_desc = [
        PacketListField("submessages", [], next_cls_cb=_next_cls_cb)
    ]


bind_layers(RTPS, RTPSMessage, magic=b"RTPS")
bind_layers(RTPS, RTPSMessage, magic=b"RTPX")
