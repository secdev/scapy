# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from scapy.fields import ByteField, XByteField, XShortField, StrField, \
    BitEnumField, PacketListField, XBitField, XByteEnumField
from scapy.packet import Packet


class OBD_DTC(Packet):
    name = "DiagnosticTroubleCode"

    locations = {
        0b00: 'Powertrain',
        0b01: 'Chassis',
        0b10: 'Body',
        0b11: 'Network',
    }

    fields_desc = [
        BitEnumField('location', 0, 2, locations),
        XBitField('code1', 0, 2),
        XBitField('code2', 0, 4),
        XBitField('code3', 0, 4),
        XBitField('code4', 0, 4),
    ]

    def extract_padding(self, s):
        return '', s


class OBD_NR(Packet):
    name = "NegativeResponse"

    responses = {
        0x10: 'generalReject',
        0x11: 'serviceNotSupported',
        0x12: 'subFunctionNotSupported-InvalidFormat',
        0x21: 'busy-RepeatRequest',
        0x22: 'conditionsNotCorrectOrRequestSequenceError',
        0x78: 'requestCorrectlyReceived-ResponsePending'
    }

    fields_desc = [
        XByteField('requestServiceId', 0),
        XByteEnumField('responseCode', 0, responses)
    ]


class OBD_S01(Packet):
    name = "S1_CurrentData"
    fields_desc = [
        XByteField('pid', 0)
    ]


class OBD_S02(Packet):
    name = "S2_FreezeFrameData"
    fields_desc = [
        XByteField('pid', 0),
        ByteField('frameNo', 0)
    ]


class OBD_S03(Packet):
    name = "S3_RequestDTCs"
    fields_desc = [
        ByteField('count', b''),
        PacketListField('DTCs', [], OBD_DTC, count_from=lambda pkt: pkt.count)
    ]


class OBD_S04(Packet):
    name = "S4_ClearDTCs"


class OBD_S05(Packet):
    name = "S5_OxygenSensorMonitoring_NonCAN"
    fields_desc = [
        XShortField('pid', 0)
    ]


class OBD_S06(Packet):
    name = "S6_OxygenSensorMonitoring_CAN"
    fields_desc = [
        XShortField('pid', 0)
    ]


class OBD_S07(Packet):
    name = "S7_RequestPendingDTCs"
    fields_desc = [
        ByteField('count', b''),
        PacketListField('DTCs', [], OBD_DTC, count_from=lambda pkt: pkt.count)
    ]


class OBD_S09(Packet):
    name = "S9_VehicleInformation"
    fields_desc = [
        XByteField('pid', 0)
    ]


class OBD_S0A(Packet):
    name = "S0A_RequestPermanentDTCs"
    fields_desc = [
        StrField('data', b'')
    ]
