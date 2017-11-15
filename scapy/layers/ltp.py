# Copyright 2012, The MITRE Corporation
#
#                             NOTICE
#    This software/technical data was produced for the U.S. Government
#    under Prime Contract No. NASA-03001 and JPL Contract No. 1295026
#      and is subject to FAR 52.227-14 (6/87) Rights in Data General,
#        and Article GP-51, Rights in Data  General, respectively.
#    
#      This software is publicly released under MITRE case #12-3054


from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP
from sdnv import *

_ltp_flag_vals = {
    0:  '0x0 Red data, NOT (Checkpoint, EORP or EOB)',
    1:  '0x1 Red data, Checkpoint, NOT (EORP or EOB)',
    2:  '0x2 Red data, Checkpoint, EORP, NOT EOB',
    3:  '0x3 Red data, Checkpoint, EORP, EOB',
    4:  'x04 Green data, NOT EOB',
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
    6:  'RESERVED'} # Reserved 0x06-0xFF

class SDNV2(Field):
    """ SDNV2 field """

    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def i2m(self, pkt, x):
        return x

    def m2i(self, pkt, x):
        return x

    def addfield(self, pkt, s, val):
        return s+str(toSDNV(val))

    def getfield(self, pkt, s):
        b = bytearray(s)
        val, len = extractSDNVFromByteArray(b, 0)
        return s[len:], val


class LTP(Packet):
    name="LTP"
    fields_desc = [ BitField('version', 0, 4),
                    BitEnumField('flags', 0, 4, _ltp_flag_vals),
                    SDNV2("SessionOriginator", 0),
                    SDNV2("SessionNumber", 0),
                                BitField('HeaderExtensionCount', 0, 4),
                                BitField('TrailerExtensionCount', 0, 4),

                                        #
                                        # Header extensions.  I really have difficulty dealing correctly with a variable
                                        # number of these things followed by the rest of the LTP header stuff, so for
                                        # now we're going to support up to 3 header extensions.
                                        #
                                        ConditionalField(ByteField("HEx1Tag", 0),                lambda Packet: (Packet.HeaderExtensionCount>0)),
                                        ConditionalField(SDNV2("HEx1Length", 0),                 lambda Packet: (Packet.HeaderExtensionCount>0)),
                                        ConditionalField(StrLenField("Hex1Data", 0, length_from= lambda Packet: (Packet.HEx1Length)), lambda Packet: Packet.HeaderExtensionCount>0),
                                        ConditionalField(ByteField("HEx2Tag", 0),                lambda Packet: (Packet.HeaderExtensionCount>1)),
                                        ConditionalField(SDNV2("HEx2Length", 0),                 lambda Packet: (Packet.HeaderExtensionCount>1)),
                                        ConditionalField(StrLenField("Hex3Data", 0, length_from= lambda Packet: (Packet.HEx2Length)), lambda Packet: Packet.HeaderExtensionCount>1),
                                        ConditionalField(ByteField("HEx3Tag", 0),                lambda Packet: (Packet.HeaderExtensionCount>2)),
                                        ConditionalField(SDNV2("HEx3Length", 0),                 lambda Packet: (Packet.HeaderExtensionCount>2)),
                                        ConditionalField(StrLenField("Hex2Data", 0, length_from= lambda Packet: (Packet.HEx3Length)), lambda Packet: Packet.HeaderExtensionCount>2),

                                        #
                                        # LTP segments containing data have a DATA header
                                        #
                                        ConditionalField(SDNV2("DATA_ClientServiceID", 0),       lambda Packet: (Packet.flags in [0,1,2,3,4,5,6,7])),
                                        ConditionalField(SDNV2("DATA_PayloadOffset", 0),         lambda Packet: (Packet.flags in [0,1,2,3,4,5,6,7])),
                                        ConditionalField(SDNV2("DATA_PayloadLength", 0),         lambda Packet: (Packet.flags in [0,1,2,3,4,5,6,7])),

                                        #
                                        # LTP segments that are checkpoints will have a checkpoint serial number and report serial number.
                                        #
                                        ConditionalField(SDNV2("CheckpointSerialNo", 0),         lambda Packet: (Packet.flags in [1,2,3])),
                                        ConditionalField(SDNV2("ReportSerialNo", 0),             lambda Packet: (Packet.flags in [1,2,3])),

                                        #
                                        # Then comes the actual payload for data carrying segments.
                                        #
                                        ConditionalField(StrLenField("LTP_Payload", 0, length_from = lambda Packet : (Packet.DATA_PayloadLength)), lambda Packet: (Packet.flags in [0,1,2,3,4,5,6,7])),

                                        #
                                        # Report ACKS acknowledge a particular report serial number.
                                        #
                                        ConditionalField(SDNV2("RA_ReportSerialNo", 0),          lambda Packet: (Packet.flags in [9])),

                                        #
                                        # Reception reports have the following fields.  Again with the variable number of receptionclaims,
                                        # I'm supporting up to 5.
                                        #
                                        ConditionalField(SDNV2("ReportSerialNo", 0),            lambda Packet: (Packet.flags in [8])),
                                        ConditionalField(SDNV2("ReportSerialNo", 0),            lambda Packet: (Packet.flags in [8])),
                                        ConditionalField(SDNV2("ReportCheckpointSerialNo", 0),  lambda Packet: (Packet.flags in [8])),
                                        ConditionalField(SDNV2("ReportUpperBound", 0),          lambda Packet: (Packet.flags in [8])),
                                        ConditionalField(SDNV2("ReportLowerBound", 0),          lambda Packet: (Packet.flags in [8])),
                                        ConditionalField(SDNV2("ReportReceptionClaimCount", 0), lambda Packet: (Packet.flags in [8])),
                                        ConditionalField(SDNV2("ReceptionClaimOffset1", 0),     lambda Packet: (Packet.ReportReceptionClaimCount>0)),
                                        ConditionalField(SDNV2("ReceptionClaimLength1", 0),     lambda Packet: (Packet.ReportReceptionClaimCount>0)),
                                        ConditionalField(SDNV2("ReceptionClaimOffset2", 0),     lambda Packet: (Packet.ReportReceptionClaimCount>1)),
                                        ConditionalField(SDNV2("ReceptionClaimLength2", 0),     lambda Packet: (Packet.ReportReceptionClaimCount>1)),
                                        ConditionalField(SDNV2("ReceptionClaimOffset3", 0),     lambda Packet: (Packet.ReportReceptionClaimCount>2)),
                                        ConditionalField(SDNV2("ReceptionClaimLength3", 0),     lambda Packet: (Packet.ReportReceptionClaimCount>2)),
                                        ConditionalField(SDNV2("ReceptionClaimOffset4", 0),     lambda Packet: (Packet.ReportReceptionClaimCount>3)),
                                        ConditionalField(SDNV2("ReceptionClaimLength4", 0),     lambda Packet: (Packet.ReportReceptionClaimCount>3)),
                                        ConditionalField(SDNV2("ReceptionClaimOffset5", 0),     lambda Packet: (Packet.ReportReceptionClaimCount>4)),
                                        ConditionalField(SDNV2("ReceptionClaimLength5", 0),     lambda Packet: (Packet.ReportReceptionClaimCount>4)),

                                        #
                                        #
                                        # Cancellation Requests
                                        #
                                        ConditionalField(ByteEnumField("CancelFromSenderReason", 15, _ltp_cancel_reasons),   lambda Packet: (Packet.flags in [12])),
                                        ConditionalField(ByteEnumField("CancelFromReceiverReason", 15, _ltp_cancel_reasons), lambda Packet: (Packet.flags in [14])),

                                        #
                                        # Cancellation Acknowldgements
                                        #
                                        ConditionalField(SDNV2("CancelAckToBlockSender", 0),        lambda Packet: (Packet.flags in [13])),
                                        ConditionalField(SDNV2("CancelAckToBlockReceiver", 0),      lambda Packet: (Packet.flags in [15])),
                
                                        #
                                        # Finally, trailing extensions
                                        #
                                        ConditionalField(ByteField("TEx1Tag", 0),                   lambda Packet: (Packet.TrailerExtensionCount>0)),
                                        ConditionalField(SDNV2("TEx1Length", 0),                    lambda Packet: (Packet.TrailerExtensionCount>0)),
                                        ConditionalField(StrLenField("TEx1Data", 0, length_from=    lambda Packet: (Packet.TEx1Length)), lambda Packet: Packet.TrailerExtensionCount>0),
                                        ConditionalField(ByteField("TEx2Tag", 0),                   lambda Packet: (Packet.TrailerExtensionCount>1)),
                                        ConditionalField(SDNV2("TEx2Length", 0),                    lambda Packet: (Packet.TrailerExtensionCount>1)),
                                        ConditionalField(StrLenField("TEx2Data", 0, length_from=    lambda Packet: (Packet.TEx2Length)), lambda Packet: Packet.TrailerExtensionCount>1)
                  ]
    def mysummary(self):
        return self.sprintf("LTP %SessionNumber%"), [UDP]
    
bind_layers (UDP,               LTP,                    sport=1113)
bind_layers (UDP,               LTP,                    dport=1113)
bind_layers (UDP,               LTP,                    sport=2113)
bind_layers (UDP,               LTP,                    dport=2113)

