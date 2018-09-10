#! /usr/bin/env python

from scapy.fields import FieldLenField, FieldListField, StrFixedLenField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class Pid00_S9(Packet):
    name = "PID_00_Service9SupportedPids"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid01_S9(Packet):
    name = "PID_01_VinMessageCount"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid02_S9(Packet):
    name = "PID_02_VehicleIdentificationNumber"
    fields_desc = [
        FieldLenField('count', None, count_of='data', fmt='B'),
        # 17 = Length of VIN
        FieldListField('data', None,
                       StrFixedLenField('', 0, 17),
                       count_from=lambda pkt: pkt.count)
    ]


class Pid03_S9(Packet):
    name = "PID_03_CalibrationIdMessageCount"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid04_S9(Packet):
    name = "PID_04_CalibrationId"
    fields_desc = [
        FieldLenField('count', None, count_of='data', fmt='B'),
        # 16 = Length of CID
        FieldListField('data', None,
                       StrFixedLenField('', 0, 16),
                       count_from=lambda pkt: pkt.count)
    ]


class Pid05_S9(Packet):
    name = "PID_05_CalibrationVerificationNumbersMessageCount"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid06_S9(Packet):
    name = "PID_06_CalibrationVerificationNumbers"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid07_S9(Packet):
    name = "PID_07_InUsePerformanceTrackingMessageCount"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid08_S9(Packet):
    name = "PID_08_InUsePerformanceTracking"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid09_S9(Packet):
    name = "PID_09_EcuNameMessageCount"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid0A_S9(Packet):
    name = "PID_0A_EcuName"
    fields_desc = [
        StrFixedLenField('data', b'', 20)
    ]


class Pid0B_S9(Packet):
    name = "PID_0B_InUsePerformanceTrackingForCompressionIgnitionVehicles"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]
