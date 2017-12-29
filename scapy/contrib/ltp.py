#!/usr/bin/env python

# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

"""
 Copyright 2012, The MITRE Corporation
 
                              NOTICE
    This software/technical data was produced for the U.S. Government
    under Prime Contract No. NASA-03001 and JPL Contract No. 1295026
      and is subject to FAR 52.227-14 (6/87) Rights in Data General,
        and Article GP-51, Rights in Data  General, respectively.
       This software is publicly released under MITRE case #12-3054
"""

# scapy.contrib.description = Licklider Transmission Protocol (LTP)
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP
from scapy.config import conf
from scapy.contrib.sdnv import *
from sys import *

## LTP

_ltp_flag_vals = {
    0:  '0x0 Red data, NOT (Checkpoint, EORP or EOB)',
    1:  '0x1 Red data, Checkpoint, NOT (EORP or EOB)',
    2:  '0x2 Red data, Checkpoint, EORP, NOT EOB',
    3:  '0x3 Red data, Checkpoint, EORP, EOB',
    4:  '0x4 Green data, NOT EOB',
    5:  '0x5 Green data, undefined',
    6:  '0x6 Green data, undefined',
    7:  '0x7 Green data, EOB',
    8:  '0x8 Report segment',
    9:  '0x9 Report-acknowledgment segmen',
    10: '0xA Control segment, undefined',
    11: '0xB Control segment, undefined',
    12: '0xC Cancel segment from block sender',
    13: '0xD Cancel-acknowledgment segment to block sender',
    14: '0xE Cancel segment from block receiver',
    15: '0xF Cancel-acknowledgment segment to block receiver'}

_ltp_cancel_reasons = {
    0:  'USR_CNCLD  - Client service canceled session.',
    1:  'UNREACH    - Unreachable client service.',
    2:  'RLEXC      - Retransmission limit exceeded.',
    3:  'MISCOLORED - Received miscolored segment.',
    4:  'SYS_CNCLD  - System error condition.',
    5:  'RXMTCYCEXC - Exceeded the retransmission cycles limit.',
    6:  'RESERVED'}   # Reserved 0x06-0xFF

_ltp_data_segment = [0, 1, 2, 3, 4, 5, 6, 7]
_ltp_checkpoint_segment = [1, 2, 3]

class LTPex(Packet):
    name = "LTP Extension"
    fields_desc = [ ByteField("ExTag", 0),
                    SDNV2("ExLength", 0),
                    StrLenField("ExData", "", length_from=lambda x: x.ExLength)]

    def default_payload_class(self, pay):
        return conf.padding_layer

class LTPReceptionClaim(Packet):
    name = "LTP Reception Claim"
    fields_desc = [ SDNV2("ReceptionClaimOffset", 0),
                    SDNV2("ReceptionClaimLength", 0) ]

    def default_payload_class(self, pay):
        return conf.padding_layer

class LTP(Packet):
    name = "LTP"
    fields_desc = [ByteField('version', 0),
                   ByteEnumField('flags', 0, _ltp_flag_vals),
                   SDNV2("SessionOriginator", 0),
                   SDNV2("SessionNumber", 0),
                   FieldLenField("HeaderExtensionCount", None, count_of="HeaderExtensions", fmt="B"),
                   FieldLenField("TrailerExtensionCount", None, count_of="TrailerExtensions", fmt="B"),
                   PacketListField("HeaderExtensions", [], LTPex, count_from=lambda x: x.HeaderExtensionCount),

                   #
                   # LTP segments containing data have a DATA header
                   #
                   ConditionalField(SDNV2("DATA_ClientServiceID", 0),
                                    lambda x: x.flags in _ltp_data_segment),
                   ConditionalField(SDNV2("DATA_PayloadOffset", 0),
                                    lambda x: x.flags in _ltp_data_segment),
                   ConditionalField(SDNV2("DATA_PayloadLength", 0),
                                    lambda x: x.flags in _ltp_data_segment),

                   #
                   # LTP segments that are checkpoints will have a checkpoint serial number and report serial number.
                   #
                   ConditionalField(SDNV2("CheckpointSerialNo", 0),
                                    lambda x: x.flags in _ltp_checkpoint_segment),
                   ConditionalField(SDNV2("ReportSerialNo", 0),
                                    lambda x: x.flags in _ltp_checkpoint_segment),

                   #
                   # Then comes the actual payload for data carrying segments.
                   #
                   ConditionalField(StrLenField("LTP_Payload", "",
                                                length_from=lambda x: x.DATA_PayloadLength),
                                    lambda x: x.flags in _ltp_data_segment),

                   #
                   # Report ACKS acknowledge a particular report serial number.
                   #
                   ConditionalField(SDNV2("RA_ReportSerialNo", 0),
                                    lambda x: x.flags == 9),

                   #
                   # Reception reports have the following fields.
                   #
                   ConditionalField(SDNV2("ReportSerialNo", 0),
                                    lambda x: x.flags == 8),
                   ConditionalField(SDNV2("ReportCheckpointSerialNo", 0),
                                    lambda x: x.flags == 8),
                   ConditionalField(SDNV2("ReportUpperBound", 0),
                                    lambda x: x.flags == 8),
                   ConditionalField(SDNV2("ReportLowerBound", 0),
                                    lambda x: x.flags == 8),
                   ConditionalField(SDNV2FieldLenField("ReportReceptionClaimCount", None, count_of="ReportReceptionClaims"),
                                    lambda x: x.flags == 8),
                   ConditionalField(PacketListField("ReportReceptionClaims", [], LTPReceptionClaim,
                                                    count_from=lambda x: x.ReportReceptionClaimCount),
                                    lambda x: x.ReportReceptionClaimCount and x.ReportReceptionClaimCount > 0),

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
                   PacketListField("TrailerExtensions", [], LTPex, count_from=lambda x: x.TrailerExtensionCount)
                ]

    def mysummary(self):
        return self.sprintf("LTP %SessionNumber%"), [UDP]

bind_layers(UDP, LTP, sport=1113)
bind_layers(UDP, LTP, dport=1113)
bind_layers(UDP, LTP, sport=2113)
bind_layers(UDP, LTP, dport=2113)
