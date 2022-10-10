# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Carmine Scarpitta <carmine.scarpitta@uniroma2.it>

# scapy.contrib.description = Simple Two-Way Active Measurement Protocol (STAMP)
# scapy.contrib.status = loads

"""
STAMP (Simple Two-Way Active Measurement Protocol) - RFC 8762.

References:
    * `Simple Two-Way Active Measurement Protocol [RFC 8762]
      <https://www.rfc-editor.org/rfc/rfc8762.html>`_
    * `Simple Two-Way Active Measurement Protocol Optional Extensions [RFC 8972]
      <https://www.rfc-editor.org/rfc/rfc8972.html>`_
"""

from scapy import config
from scapy.base_classes import Packet_metaclass
from scapy.layers.inet import UDP
from scapy.layers.ntp import TimeStampField
from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    FlagsField,
    IntField,
    MultipleTypeField,
    NBytesField,
    PacketField,
    PacketListField,
    ShortField,
    StrLenField,
    UTCTimeField
)


_sync_types = {
    0: 'No External Synchronization for the Time Source',
    1: 'Clock Synchronized to UTC using an External Source'
}

_timestamp_types = {
    0: 'NTP 64-bit Timestamp Format',
    1: 'PTPv2 Truncated Timestamp Format'
}

_stamp_tlvs = {

}


class ErrorEstimate(Packet):
    """
    The Error Estimate specifies the estimate of the error and
    synchronization. The format of the Error Estimate field
    (defined in Section 4.1.2 of `RFC 4656
    <https://www.rfc-editor.org/rfc/rfc4656.html>`_) is reported below::

        0                   1
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |S|Z|   Scale   |   Multiplier  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ``S`` is interpreted as follows:

        +-------+-------------------------------------------------------+
        | Value | Description                                           |
        +-------+-------------------------------------------------------+
        |   0   | there is no notion of external synchronization for    |
        |       | the time source                                       |
        +-------+-------------------------------------------------------+
        |   1   | the party generating the timestamp has a clock that   |
        |       | is synchronized to UTC using an external source       |
        +-------+-------------------------------------------------------+

    ``Z`` is interpreted as follows (defined in Section 2.3 of `RFC 8186
    <https://www.rfc-editor.org/rfc/rfc8186.html>`_):

        +-------+---------------------------------------+
        | Value | Description                           |
        +-------+---------------------------------------+
        |   0   | NTP 64-bit format of a timestamp      |
        +-------+---------------------------------------+
        |   1   | PTPv2 truncated format of a timestamp |
        +-------+---------------------------------------+

    ``Scale`` and ``Multiplier`` are linked by the following relationship::

        ErrorEstimate = Multiplier*2^(-32)*2^Scale (in seconds)


    References:
        * `A One-way Active Measurement Protocol (OWAMP) [RFC 4656]
          <https://www.rfc-editor.org/rfc/rfc4656.html>`_
        * `Support of the IEEE 1588 Timestamp Format in a Two-Way Active
          Measurement Protocol (TWAMP) [RFC 8186]
          <https://www.rfc-editor.org/rfc/rfc8186.html>`_
    """

    name = 'Error Estimate'
    fields_desc = [
        BitEnumField('S', 0, 1, _sync_types),
        BitEnumField('Z', 0, 1, _timestamp_types),
        BitField('scale', 0, 6),
        ByteField('multiplier', 1),
    ]

    def guess_payload_class(self, payload):
        # type: (str) -> Packet_metaclass
        # Trick to tell scapy that the remaining bytes of the currently
        # dissected string is not a payload of this packet but of some other
        # underlayer packet
        return config.conf.padding_layer


class STAMPTestTLV(Packet):
    """
    The STAMP Test TLV defined in Section 4 of [RFC 8972] provides a flexible
    extension mechanism for optional informational elements.

    The TLV Format in a STAMP Test packet is reported below::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |STAMP TLV Flags|     Type      |           Length              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        ~                            Value                              ~
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    +-------+---------+-------------------------------------------------+
    | Field           | Description                                     |
    +-----------------+-------------------------------------------------+
    | STAMP TLV Flags | 8-bit field; for the details about the STAMP    |
    |                 | TLV Flags Format, see RFC 8972                  |
    +-----------------+-------------------------------------------------+
    | Type            | characterizes the interpretation of the Value   |
    |                 | field                                           |
    +-----------------+-------------------------------------------------+
    | Length          | the length of the Value field in octets         |
    +-----------------+-------------------------------------------------+
    | Value           | interpreted according to the value of the Type  |
    |                 | field                                           |
    +-----------------+-------------------------------------------------+


    References:
        * `Simple Two-Way Active Measurement Protocol Optional Extensions
          [RFC 8972] <https://www.rfc-editor.org/rfc/rfc8972.html>`_
    """

    name = 'STAMP Test Packet - Generic TLV'
    fields_desc = [
        FlagsField('flags', 0, 8, "UMIRRRRR"),
        ByteEnumField('type', None, _stamp_tlvs),
        ShortField('len', 0),
        StrLenField('value', '', length_from=lambda pkt: pkt.len),
    ]

    def extract_padding(self, p):
        return b"", p

    registered_stamp_tlv = {}

    @classmethod
    def register_variant(cls):
        cls.registered_stamp_tlv[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        if pkt:
            tmp_type = ord(pkt[1:2])
            return cls.registered_stamp_tlv.get(tmp_type, cls)
        return cls


class STAMPSessionSenderTestUnauthenticated(Packet):
    """
    Extended STAMP Session-Sender Test Packet in Unauthenticated Mode.

    The format (defined in Section 3 of `RFC 8972
    <https://www.rfc-editor.org/rfc/rfc8972.html>`_) is shown below::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Sequence Number                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                          Timestamp                            |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Error Estimate        |             SSID              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        |                                                               |
        |                         MBZ (28 octets)                       |
        |                                                               |
        |                                                               |
        |                                                               |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        ~                            TLVs                               ~
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    References:
        * `Simple Two-Way Active Measurement Protocol Optional Extensions
          [RFC 8972] <https://www.rfc-editor.org/rfc/rfc8972.html>`_
    """
    name = 'STAMP Session-Sender Test'
    fields_desc = [
        IntField('seq', 0),
        MultipleTypeField(
            [
                (TimeStampField('ts', 0),
                    lambda pkt:pkt.err_estimate.Z == 0)
            ],
            UTCTimeField('ts', 0, fmt='Q')
        ),
        PacketField('err_estimate', ErrorEstimate(), ErrorEstimate),
        ShortField('ssid', 1),
        NBytesField('mbz', 0, 28),  # 28 bytes MBZ
        PacketListField('tlv_objects', [], STAMPTestTLV,
                        length_from=lambda pkt: pkt.parent.len - 8 - 44),
    ]


class STAMPSessionReflectorTestUnauthenticated(Packet):
    """
    Extended STAMP Session-Reflector Test Packet in Unauthenticated Mode.

    The format (defined in Section 3 of `RFC 8972
    <https://www.rfc-editor.org/rfc/rfc8972.html>`_) is shown below::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Sequence Number                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                          Timestamp                            |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Error Estimate        |           SSID                |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                          Receive Timestamp                    |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                 Session-Sender Sequence Number                |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                  Session-Sender Timestamp                     |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Session-Sender Error Estimate |           MBZ                 |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Ses-Sender TTL |                   MBZ                         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        ~                            TLVs                               ~
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    References:
        * `Simple Two-Way Active Measurement Protocol Optional Extensions
          [RFC 8972] <https://www.rfc-editor.org/rfc/rfc8972.html>`_
    """
    name = 'STAMP Session-Reflector Test'
    fields_desc = [
        IntField('seq', 0),
        MultipleTypeField(
            [
                (TimeStampField('ts', 0),
                    lambda pkt:pkt.err_estimate.Z == 0),
            ],
            UTCTimeField('ts', 0, fmt='Q')
        ),
        PacketField('err_estimate', ErrorEstimate(), ErrorEstimate),
        ShortField('ssid', 1),
        MultipleTypeField(
            [
                (TimeStampField('ts_rx', 0),
                    lambda pkt:pkt.err_estimate.Z == 0)
            ],
            UTCTimeField('ts_rx', 0, fmt='Q')
        ),
        IntField('seq_sender', 0),
        MultipleTypeField(
            [
                (TimeStampField('ts_sender', 0),
                    lambda pkt:pkt.err_estimate_sender.Z == 0)
            ],
            UTCTimeField('ts_sender', 0, fmt='Q')
        ),
        PacketField('err_estimate_sender', ErrorEstimate(), ErrorEstimate),
        ShortField('mbz1', 0),
        ByteField('ttl_sender', 255),
        NBytesField('mbz2', 0, 3),  # 3 bytes MBZ
        PacketListField('tlv_objects', [], STAMPTestTLV,
                        length_from=lambda pkt: pkt.parent.len - 8 - 44),
    ]


bind_layers(UDP, STAMPSessionSenderTestUnauthenticated, dport=862)
bind_layers(UDP, STAMPSessionReflectorTestUnauthenticated, sport=862)
