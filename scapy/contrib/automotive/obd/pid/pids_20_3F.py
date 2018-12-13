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
    name = "PID_20_PIDsSupported"
    fields_desc = [
        FlagsField('supportedPIDs', 0, 32, [
            'PID40',
            'PID3F',
            'PID3E',
            'PID3D',
            'PID3C',
            'PID3B',
            'PID3A',
            'PID39',
            'PID38',
            'PID37',
            'PID36',
            'PID35',
            'PID34',
            'PID33',
            'PID32',
            'PID31',
            'PID30',
            'PID2F',
            'PID2E',
            'PID2D',
            'PID2C',
            'PID2B',
            'PID2A',
            'PID29',
            'PID28',
            'PID27',
            'PID26',
            'PID25',
            'PID24',
            'PID23',
            'PID22',
            'PID21'
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
