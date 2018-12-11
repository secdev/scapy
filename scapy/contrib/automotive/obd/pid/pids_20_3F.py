# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from scapy.fields import StrFixedLenField, FlagsField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class OBD_PID20(Packet):
    name = "PID_20_PidsSupported"
    fields_desc = [
        FlagsField('supportedPids', 0, 32, [
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


class OBD_PID21(Packet):
    name = "PID_21_DistanceTraveledWithMalfunctionIndicatorLampOn"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID22(Packet):
    name = "PID_22_FuelRailPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID23(Packet):
    name = "PID_23_FuelRailGaugePressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID24(Packet):
    name = "PID_24_OxygenSensor1"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID25(Packet):
    name = "PID_25_OxygenSensor2"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID26(Packet):
    name = "PID_26_OxygenSensor3"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID27(Packet):
    name = "PID_27_OxygenSensor4"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID28(Packet):
    name = "PID_28_OxygenSensor5"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID29(Packet):
    name = "PID_29_OxygenSensor6"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID2A(Packet):
    name = "PID_2A_OxygenSensor7"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID2B(Packet):
    name = "PID_2B_OxygenSensor8"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID2C(Packet):
    name = "PID_2C_CommandedEgr"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID2D(Packet):
    name = "PID_2D_EgrError"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID2E(Packet):
    name = "PID_2E_CommandedEvaporativePurge"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID2F(Packet):
    name = "PID_2F_FuelTankLevelInput"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID30(Packet):
    name = "PID_30_WarmUpsSinceCodesCleared"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID31(Packet):
    name = "PID_31_DistanceTraveledSinceCodesCleared"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID32(Packet):
    name = "PID_32_EvapSystemVaporPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID33(Packet):
    name = "PID_33_AbsoluteBarometricPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID34(Packet):
    name = "PID_34_OxygenSensor1"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID35(Packet):
    name = "PID_35_OxygenSensor2"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID36(Packet):
    name = "PID_36_OxygenSensor3"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID37(Packet):
    name = "PID_37_OxygenSensor4"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID38(Packet):
    name = "PID_38_OxygenSensor5"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID39(Packet):
    name = "PID_39_OxygenSensor6"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID3A(Packet):
    name = "PID_3A_OxygenSensor7"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID3B(Packet):
    name = "PID_3B_OxygenSensor8"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID3C(Packet):
    name = "PID_3C_CatalystTemperatureBank1Sensor1"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID3D(Packet):
    name = "PID_3D_CatalystTemperatureBank2Sensor1"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID3E(Packet):
    name = "PID_3E_CatalystTemperatureBank1Sensor2"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID3F(Packet):
    name = "PID_3F_CatalystTemperatureBank2Sensor2"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]
