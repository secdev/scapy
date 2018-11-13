#! /usr/bin/env python

from scapy.fields import ByteField, XByteField, XShortField, StrField, BitEnumField, PacketListField, \
    XBitField, XByteEnumField, PacketLenField
from scapy.packet import Packet


class DTC(Packet):
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


class NegativeResponseOBD(Packet):
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
        XByteField('requestedService', 0),
        XByteEnumField('responseCode', b'', responses)
    ]

    def hashret(self):
        return self.requestedService

    def answers(self, other):
        """DEV: true if self is an answer from other"""
        if other.__class__ == self.__class__:
            return other.service == self.requestedService

        return False


class Service01(Packet):
    name = "S1_CurrentData"
    fields_desc = [
        XByteField('pid', 0)
    ]


class Service02(Packet):
    name = "S2_FreezeFrameData"
    fields_desc = [
        XByteField('pid', 0),
        ByteField('frameNo', 0)
    ]


class Service03(Packet):
    name = "S3_RequestDTCs"
    fields_desc = [
        ByteField('count', b''),
        PacketListField('DTCs', [], DTC, count_from=lambda pkt: pkt.count)
    ]


class Service04(Packet):
    name = "S4_ClearDTCs"


class Service05(Packet):
    name = "S5_OxygenSensorMonitoring_NonCAN"
    fields_desc = [
        XShortField('pid', 0)
    ]


class Service06(Packet):
    name = "S6_OxygenSensorMonitoring_CAN"
    fields_desc = [
        XShortField('pid', 0)
    ]


class Service07(Packet):
    name = "S7_RequestPendingDTCs"
    fields_desc = [
        ByteField('count', b''),
        PacketListField('DTCs', [], DTC, count_from=lambda pkt: pkt.count)
    ]


class Service09(Packet):
    name = "S9_VehicleInformation"
    fields_desc = [
        XByteField('pid', 0)
    ]


class Service0A(Packet):
    name = "S0A_RequestPermanentDTCs"
    fields_desc = [
        StrField('data', b'')
    ]
