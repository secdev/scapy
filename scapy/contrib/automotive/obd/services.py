# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from scapy.fields import ByteField, XByteField, BitEnumField, \
    PacketListField, XBitField, XByteEnumField, FieldListField
from scapy.packet import Packet
from scapy.contrib.automotive.obd.packet import OBD_Packet


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


class OBD_S01(Packet):
    name = "S1_CurrentData"
    fields_desc = [
        FieldListField("pid", [0], XByteField('', 0))
    ]


class OBD_S02_Req(OBD_Packet):
    fields_desc = [
        XByteField('pid', 0),
        ByteField('frame_no', 0)
    ]


class OBD_S02(Packet):
    name = "S2_FreezeFrameData"
    fields_desc = [
        PacketListField("requests", None, OBD_S02_Req)
    ]


class OBD_S03(Packet):
    name = "S3_RequestDTCs"


class OBD_S03_DTC(Packet):
    name = "S3_ResponseDTCs"
    fields_desc = [
        ByteField('count', 0),
        PacketListField('dtcs', [], OBD_DTC, count_from=lambda pkt: pkt.count)
    ]


class OBD_S04(Packet):
    name = "S4_ClearDTCs"


class OBD_S04_PR(Packet):
    name = "S4_ClearDTCsPositiveResponse"


class OBD_S06(Packet):
    name = "S6_OnBoardDiagnosticMonitoring"
    fields_desc = [
        FieldListField("mid", [0], XByteField('', 0))
    ]


class OBD_S07(Packet):
    name = "S7_RequestPendingDTCs"


class OBD_S07_DTC(Packet):
    name = "S7_ResponsePendingDTCs"
    fields_desc = [
        ByteField('count', 0),
        PacketListField('dtcs', [], OBD_DTC, count_from=lambda pkt: pkt.count)
    ]


class OBD_S08(Packet):
    name = "S8_RequestControlOfSystem"
    fields_desc = [
        FieldListField("tid", [0], XByteField('', 0))
    ]


class OBD_S09(Packet):
    name = "S9_VehicleInformation"
    fields_desc = [
        XByteField('iid', 0)
    ]


class OBD_S09_PR(Packet):
    name = "S9_VehicleInformationPositiveResponse"
    fields_desc = [
        XByteField('iid', 0)
    ]


class OBD_S0A(Packet):
    name = "S0A_RequestPermanentDTCs"


class OBD_S0A_DTC(Packet):
    name = "S0A_ResponsePermanentDTCs"
    fields_desc = [
        ByteField('count', 0),
        PacketListField('dtcs', [], OBD_DTC, count_from=lambda pkt: pkt.count)
    ]
