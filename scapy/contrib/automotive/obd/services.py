# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.status = skip

from scapy.fields import ByteField, XByteField, BitEnumField, \
    PacketListField, XBitField, XByteEnumField, FieldListField, FieldLenField
from scapy.packet import Packet
from scapy.contrib.automotive.obd.packet import OBD_Packet
from scapy.config import conf


class OBD_DTC(OBD_Packet):
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
        XByteField('request_service_id', 0),
        XByteEnumField('response_code', 0, responses)
    ]

    def answers(self, other):
        return self.request_service_id == other.service and \
            (self.response_code != 0x78 or
             conf.contribs['OBD']['treat-response-pending-as-answer'])


class OBD_S01(Packet):
    name = "S1_CurrentData"
    fields_desc = [
        FieldListField("pid", [], XByteField('', 0))
    ]


class OBD_S02_Record(OBD_Packet):
    fields_desc = [
        XByteField('pid', 0),
        ByteField('frame_no', 0)
    ]


class OBD_S02(Packet):
    name = "S2_FreezeFrameData"
    fields_desc = [
        PacketListField("requests", [], OBD_S02_Record)
    ]


class OBD_S03(Packet):
    name = "S3_RequestDTCs"


class OBD_S03_PR(Packet):
    name = "S3_ResponseDTCs"
    fields_desc = [
        FieldLenField('count', None, count_of='dtcs', fmt='B'),
        PacketListField('dtcs', [], OBD_DTC, count_from=lambda pkt: pkt.count)
    ]

    def answers(self, other):
        return isinstance(other, OBD_S03)


class OBD_S04(Packet):
    name = "S4_ClearDTCs"


class OBD_S04_PR(Packet):
    name = "S4_ClearDTCsPositiveResponse"

    def answers(self, other):
        return isinstance(other, OBD_S04)


class OBD_S06(Packet):
    name = "S6_OnBoardDiagnosticMonitoring"
    fields_desc = [
        FieldListField("mid", [], XByteField('', 0))
    ]


class OBD_S07(Packet):
    name = "S7_RequestPendingDTCs"


class OBD_S07_PR(Packet):
    name = "S7_ResponsePendingDTCs"
    fields_desc = [
        FieldLenField('count', None, count_of='dtcs', fmt='B'),
        PacketListField('dtcs', [], OBD_DTC, count_from=lambda pkt: pkt.count)
    ]

    def answers(self, other):
        return isinstance(other, OBD_S07)


class OBD_S08(Packet):
    name = "S8_RequestControlOfSystem"
    fields_desc = [
        FieldListField("tid", [], XByteField('', 0))
    ]


class OBD_S09(Packet):
    name = "S9_VehicleInformation"
    fields_desc = [
        FieldListField("iid", [], XByteField('', 0))
    ]


class OBD_S0A(Packet):
    name = "S0A_RequestPermanentDTCs"


class OBD_S0A_PR(Packet):
    name = "S0A_ResponsePermanentDTCs"
    fields_desc = [
        FieldLenField('count', None, count_of='dtcs', fmt='B'),
        PacketListField('dtcs', [], OBD_DTC, count_from=lambda pkt: pkt.count)
    ]

    def answers(self, other):
        return isinstance(other, OBD_S0A)
