# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright 2012 (C) The MITRE Corporation

"""
.. centered::
    NOTICE
    This software/technical data was produced for the U.S. Government
    under Prime Contract No. NASA-03001 and JPL Contract No. 1295026
    and is subject to FAR 52.227-14 (6/87) Rights in Data General,
    and Article GP-51, Rights in Data  General, respectively.
    This software is publicly released under MITRE case #12-3054
"""

# scapy.contrib.description = Licklider Transmission Protocol (LTP)
# scapy.contrib.status = loads

import scapy.libs.six as six
from scapy.packet import Packet, bind_layers, bind_top_down
from scapy.fields import BitEnumField, BitField, BitFieldLenField, \
    ByteEnumField, ConditionalField, PacketListField, StrLenField
from scapy.layers.inet import UDP
from scapy.config import conf
from scapy.contrib.sdnv import SDNV2, SDNV2FieldLenField

# LTP https://tools.ietf.org/html/rfc5326

_ltp_flag_vals = {
    0: '0x0 Red data, NOT (Checkpoint, EORP or EOB)',
    1: '0x1 Red data, Checkpoint, NOT (EORP or EOB)',
    2: '0x2 Red data, Checkpoint, EORP, NOT EOB',
    3: '0x3 Red data, Checkpoint, EORP, EOB',
    4: '0x4 Green data, NOT EOB',
    5: '0x5 Green data, undefined',
    6: '0x6 Green data, undefined',
    7: '0x7 Green data, EOB',
    8: '0x8 Report segment',
    9: '0x9 Report-acknowledgment segmen',
    10: '0xA Control segment, undefined',
    11: '0xB Control segment, undefined',
    12: '0xC Cancel segment from block sender',
    13: '0xD Cancel-acknowledgment segment to block sender',
    14: '0xE Cancel segment from block receiver',
    15: '0xF Cancel-acknowledgment segment to block receiver'}

_ltp_cancel_reasons = {
    0: 'USR_CNCLD  - Client service canceled session.',
    1: 'UNREACH    - Unreachable client service.',
    2: 'RLEXC      - Retransmission limit exceeded.',
    3: 'MISCOLORED - Received miscolored segment.',
    4: 'SYS_CNCLD  - System error condition.',
    5: 'RXMTCYCEXC - Exceeded the retransmission cycles limit.',
    6: 'RESERVED'}   # Reserved 0x06-0xFF

# LTP Extensions https://tools.ietf.org/html/rfc5327

_ltp_extension_tag = {
    0: 'LTP authentication extension',
    1: 'LTP cookie extension'
}

_ltp_data_segment = [0, 1, 2, 3, 4, 5, 6, 7]
_ltp_checkpoint_segment = [1, 2, 3]

_ltp_payload_conditions = {}


def ltp_bind_payload(cls, lambd):
    """Bind payload class to the LTP packets.

    :param cls: the class to bind
    :param lambd: lambda that will be called to check
        whether or not the cls should be used
        ex: lambda pkt: ...
    """
    _ltp_payload_conditions[cls] = lambd


class LTPex(Packet):
    name = "LTP Extension"
    fields_desc = [
        ByteEnumField("ExTag", 0, _ltp_extension_tag),
        SDNV2FieldLenField("ExLength", None, length_of="ExData"),
        # SDNV2FieldLenField
        StrLenField("ExData", "", length_from=lambda x: x.ExLength)
    ]

    def default_payload_class(self, pay):
        return conf.padding_layer


class LTPReceptionClaim(Packet):
    name = "LTP Reception Claim"
    fields_desc = [SDNV2("ReceptionClaimOffset", 0),
                   SDNV2("ReceptionClaimLength", 0)]

    def default_payload_class(self, pay):
        return conf.padding_layer


def _ltp_guess_payload(pkt, *args):
    for k, v in six.iteritems(_ltp_payload_conditions):
        if v(pkt):
            return k
    return conf.raw_layer


class LTP(Packet):
    name = "LTP"
    fields_desc = [
        BitField('version', 0, 4),
        BitEnumField('flags', 0, 4, _ltp_flag_vals),
        SDNV2("SessionOriginator", 0),
        SDNV2("SessionNumber", 0),
        BitFieldLenField("HeaderExtensionCount", None, 4, count_of="HeaderExtensions"),  # noqa: E501
        BitFieldLenField("TrailerExtensionCount", None, 4, count_of="TrailerExtensions"),  # noqa: E501
        PacketListField("HeaderExtensions", [], LTPex, count_from=lambda x: x.HeaderExtensionCount),  # noqa: E501
        #
        # LTP segments containing data have a DATA header
        #
        ConditionalField(SDNV2("DATA_ClientServiceID", 0),
                         lambda x: x.flags in _ltp_data_segment),
        ConditionalField(SDNV2("DATA_PayloadOffset", 0),
                         lambda x: x.flags in _ltp_data_segment),
        ConditionalField(SDNV2FieldLenField("DATA_PayloadLength", None, length_of="LTP_Payload"),  # noqa: E501
                         lambda x: x.flags in _ltp_data_segment),
        #
        # LTP segments that are checkpoints will have a checkpoint serial number and report serial number.  # noqa: E501
        #
        ConditionalField(SDNV2("CheckpointSerialNo", 0),
                         lambda x: x.flags in _ltp_checkpoint_segment),
        #
        # For segments that are checkpoints or reception reports.
        #
        ConditionalField(SDNV2("ReportSerialNo", 0),
                         lambda x: x.flags in _ltp_checkpoint_segment \
                         or x.flags == 8),
        #
        # Then comes the actual payload for data carrying segments.
        #
        ConditionalField(PacketListField("LTP_Payload", None, next_cls_cb=_ltp_guess_payload,  # noqa: E501
                                         length_from=lambda x: x.DATA_PayloadLength),  # noqa: E501
                         lambda x: x.flags in _ltp_data_segment),
        #
        # Report ACKS acknowledge a particular report serial number.
        #
        ConditionalField(SDNV2("RA_ReportSerialNo", 0),
                         lambda x: x.flags == 9),
        #
        # Reception reports have the following fields,
        # excluding ReportSerialNo defined above.
        #
        ConditionalField(SDNV2("ReportCheckpointSerialNo", 0),
                         lambda x: x.flags == 8),
        ConditionalField(SDNV2("ReportUpperBound", 0),
                         lambda x: x.flags == 8),
        ConditionalField(SDNV2("ReportLowerBound", 0),
                         lambda x: x.flags == 8),
        ConditionalField(SDNV2FieldLenField("ReportReceptionClaimCount", None, count_of="ReportReceptionClaims"),  # noqa: E501
                         lambda x: x.flags == 8),
        ConditionalField(PacketListField("ReportReceptionClaims", [], LTPReceptionClaim,  # noqa: E501
                                         count_from=lambda x: x.ReportReceptionClaimCount),  # noqa: E501
                         lambda x: x.flags == 8 and (not x.ReportReceptionClaimCount or x.ReportReceptionClaimCount > 0)),  # noqa: E501
        #
        # Cancellation Requests
        #
        ConditionalField(ByteEnumField("CancelFromSenderReason",
                                       15, _ltp_cancel_reasons),
                         lambda x: x.flags == 12),
        ConditionalField(ByteEnumField("CancelFromReceiverReason",
                                       15, _ltp_cancel_reasons),
                         lambda x: x.flags == 14),
        #
        # Cancellation Acknowldgements
        #
        ConditionalField(SDNV2("CancelAckToBlockSender", 0),
                         lambda x: x.flags == 13),
        ConditionalField(SDNV2("CancelAckToBlockReceiver", 0),
                         lambda x: x.flags == 15),
        #
        # Finally, trailing extensions
        #
        PacketListField("TrailerExtensions", [], LTPex, count_from=lambda x: x.TrailerExtensionCount)  # noqa: E501
    ]

    def mysummary(self):
        return self.sprintf("LTP %SessionNumber%"), [UDP]


bind_top_down(UDP, LTP, sport=1113)
bind_top_down(UDP, LTP, dport=1113)
bind_top_down(UDP, LTP, sport=2113)
bind_top_down(UDP, LTP, dport=2113)
bind_layers(UDP, LTP, sport=1113, dport=1113)
