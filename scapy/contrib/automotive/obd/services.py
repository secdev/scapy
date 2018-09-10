#! /usr/bin/env python

from scapy.fields import ByteField, XByteField, XShortField, StrField
from scapy.packet import Packet


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
        StrField('data', b'')
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
        StrField('data', b'')
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
