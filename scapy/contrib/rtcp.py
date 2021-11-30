# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Pavel Oborin <oborin.p@gmail.com>
# This program is published under a GPLv2 license

# RFC 3550
# scapy.contrib.description = Real-Time Transport Control Protocol
# scapy.contrib.status = loads

import struct

from scapy.packet import Packet, bind_layers, Padding, Raw
from scapy.fields import (
    BitField, ByteEnumField, IntField, ConditionalField,
    PacketListField, BitFieldLenField,
    LongField, PacketField, ByteField,
    X3BytesField, LenField, PacketLenField,
    FieldListField
)


_rtcp_packet_types = {
    200: 'Sender report',
    201: 'Receiver report',
    202: 'Source description',
    203: 'BYE',
    204: 'APP'
}


class RTCPHeader(Packet):
    name = "RTCP header"
    fields_desc = [BitField('version', 2, 2),
                   BitField('padding', 0, 1),
                   BitFieldLenField('report_count', 0, 5, count_of='report_blocks'),
                   ByteEnumField('packet_type', 0, _rtcp_packet_types),
                   LenField('length', None, fmt='!h')
    ]

    def __new__(cls, name, bases, dct):
        raise NotImplementedError()


class SenderInfo(Packet):
    name = "Sender info"
    fields_desc = [
        LongField('ntp_timestamp', None),
        IntField('rtp_timestamp', None),
        IntField('sender_packet_count', None),
        IntField('sender_octet_count', None)
    ]


class ReceptionReport(Packet):
    name = "Reception report"
    fields_desc = [
        IntField('sourcesync', None),
        ByteField('fraction_lost', None),
        X3BytesField('cumulative_lost', None),
        IntField('highest_seqnum_recv', None),
        IntField('interarrival_jitter', None),
        IntField('last_SR_timestamp', None),
        IntField('delay_since_last_SR', None)
    ]


class RTCPSenderReport(Packet):
    name = "RTCP sender report"
    fields_desc = [
        RTCPHeader,
        IntField('sourcesync', 0),
        PacketField('sender_info', SenderInfo(), SenderInfo),
        PacketListField('report_blocks', None, pkt_cls=ReceptionReport, count_from=lambda pkt: pkt.record_count)
    ]
    packet_type = 200

    def post_build(self, pkt, pay):
        pkt += pay
        if self.length is None:
            pkt = pkt[:2] + struct.pack("!h", len(pkt) // 4 - 1) + pkt[4:]
        return pkt
