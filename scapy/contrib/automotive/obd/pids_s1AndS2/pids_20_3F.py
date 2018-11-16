#! /usr/bin/env python

from scapy.fields import StrFixedLenField, FlagsField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class Pid20_S1AndS2(Packet):
    name = "PID_20_PidsSupported"
    fields_desc = [
        FlagsField('supportedPids', b'', 32, [
            'Pid40',
            'Pid3F',
            'Pid3E',
            'Pid3D',
            'Pid3C',
            'Pid3B',
            'Pid3A',
            'Pid39',
            'Pid38',
            'Pid37',
            'Pid36',
            'Pid35',
            'Pid34',
            'Pid33',
            'Pid32',
            'Pid31',
            'Pid30',
            'Pid2F',
            'Pid2E',
            'Pid2D',
            'Pid2C',
            'Pid2B',
            'Pid2A',
            'Pid29',
            'Pid28',
            'Pid27',
            'Pid26',
            'Pid25',
            'Pid24',
            'Pid23',
            'Pid22',
            'Pid21'
        ])
    ]


class Pid21_S1AndS2(Packet):
    name = "PID_21_DistanceTraveledWithMalfunctionIndicatorLampOn"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid22_S1AndS2(Packet):
    name = "PID_22_FuelRailPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid23_S1AndS2(Packet):
    name = "PID_23_FuelRailGaugePressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid24_S1AndS2(Packet):
    name = "PID_24_OxygenSensor1"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid25_S1AndS2(Packet):
    name = "PID_25_OxygenSensor2"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid26_S1AndS2(Packet):
    name = "PID_26_OxygenSensor3"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid27_S1AndS2(Packet):
    name = "PID_27_OxygenSensor4"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid28_S1AndS2(Packet):
    name = "PID_28_OxygenSensor5"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid29_S1AndS2(Packet):
    name = "PID_29_OxygenSensor6"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid2A_S1AndS2(Packet):
    name = "PID_2A_OxygenSensor7"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid2B_S1AndS2(Packet):
    name = "PID_2B_OxygenSensor8"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid2C_S1AndS2(Packet):
    name = "PID_2C_CommandedEgr"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid2D_S1AndS2(Packet):
    name = "PID_2D_EgrError"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid2E_S1AndS2(Packet):
    name = "PID_2E_CommandedEvaporativePurge"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid2F_S1AndS2(Packet):
    name = "PID_2F_FuelTankLevelInput"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid30_S1AndS2(Packet):
    name = "PID_30_WarmUpsSinceCodesCleared"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid31_S1AndS2(Packet):
    name = "PID_31_DistanceTraveledSinceCodesCleared"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid32_S1AndS2(Packet):
    name = "PID_32_EvapSystemVaporPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid33_S1AndS2(Packet):
    name = "PID_33_AbsoluteBarometricPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid34_S1AndS2(Packet):
    name = "PID_34_OxygenSensor1"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid35_S1AndS2(Packet):
    name = "PID_35_OxygenSensor2"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid36_S1AndS2(Packet):
    name = "PID_36_OxygenSensor3"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid37_S1AndS2(Packet):
    name = "PID_37_OxygenSensor4"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid38_S1AndS2(Packet):
    name = "PID_38_OxygenSensor5"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid39_S1AndS2(Packet):
    name = "PID_39_OxygenSensor6"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid3A_S1AndS2(Packet):
    name = "PID_3A_OxygenSensor7"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid3B_S1AndS2(Packet):
    name = "PID_3B_OxygenSensor8"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid3C_S1AndS2(Packet):
    name = "PID_3C_CatalystTemperatureBank1Sensor1"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid3D_S1AndS2(Packet):
    name = "PID_3D_CatalystTemperatureBank2Sensor1"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid3E_S1AndS2(Packet):
    name = "PID_3E_CatalystTemperatureBank1Sensor2"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid3F_S1AndS2(Packet):
    name = "PID_3F_CatalystTemperatureBank2Sensor2"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]
