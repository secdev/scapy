# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.status = skip

from scapy.fields import FlagsField, ScalingField
from scapy.contrib.automotive.obd.packet import OBD_Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification


class OBD_PID20(OBD_Packet):
    name = "PID_20_PIDsSupported"
    fields_desc = [
        FlagsField('supported_pids', 0, 32, [
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


class OBD_PID21(OBD_Packet):
    name = "PID_21_DistanceTraveledWithMalfunctionIndicatorLampOn"
    fields_desc = [
        ScalingField('data', 0, unit="km", fmt="H")
    ]


class OBD_PID22(OBD_Packet):
    name = "PID_22_FuelRailPressure"
    fields_desc = [
        ScalingField('data', 0, scaling=0.079, unit="kPa", fmt="H")
    ]


class OBD_PID23(OBD_Packet):
    name = "PID_23_FuelRailGaugePressure"
    fields_desc = [
        ScalingField('data', 0, scaling=10, unit="kPa", fmt="H")
    ]


class _OBD_PID24_2B(OBD_Packet):
    fields_desc = [
        ScalingField('equivalence_ratio', 0, scaling=0.0000305, fmt="H"),
        ScalingField('voltage', 0, scaling=0.000122, unit="V", fmt="H")
    ]


class OBD_PID24(_OBD_PID24_2B):
    name = "PID_24_OxygenSensor1"


class OBD_PID25(_OBD_PID24_2B):
    name = "PID_25_OxygenSensor2"


class OBD_PID26(_OBD_PID24_2B):
    name = "PID_26_OxygenSensor3"


class OBD_PID27(_OBD_PID24_2B):
    name = "PID_27_OxygenSensor4"


class OBD_PID28(_OBD_PID24_2B):
    name = "PID_28_OxygenSensor5"


class OBD_PID29(_OBD_PID24_2B):
    name = "PID_29_OxygenSensor6"


class OBD_PID2A(_OBD_PID24_2B):
    name = "PID_2A_OxygenSensor7"


class OBD_PID2B(_OBD_PID24_2B):
    name = "PID_2B_OxygenSensor8"


class OBD_PID2C(OBD_Packet):
    name = "PID_2C_CommandedEgr"
    fields_desc = [
        ScalingField('data', 0, scaling=100 / 255., unit="%")
    ]


class OBD_PID2D(OBD_Packet):
    name = "PID_2D_EgrError"
    fields_desc = [
        ScalingField('data', 0, scaling=100 / 128.,
                     unit="%", offset=-100.0)
    ]


class OBD_PID2E(OBD_Packet):
    name = "PID_2E_CommandedEvaporativePurge"
    fields_desc = [
        ScalingField('data', 0, scaling=100 / 255., unit="%")
    ]


class OBD_PID2F(OBD_Packet):
    name = "PID_2F_FuelTankLevelInput"
    fields_desc = [
        ScalingField('data', 0, scaling=100 / 255., unit="%")
    ]


class OBD_PID30(OBD_Packet):
    name = "PID_30_WarmUpsSinceCodesCleared"
    fields_desc = [
        ScalingField('data', 0)
    ]


class OBD_PID31(OBD_Packet):
    name = "PID_31_DistanceTraveledSinceCodesCleared"
    fields_desc = [
        ScalingField('data', 0, unit="km", fmt="H")
    ]


class OBD_PID32(OBD_Packet):
    name = "PID_32_EvapSystemVaporPressure"
    fields_desc = [
        ScalingField('data', 0, scaling=0.25, unit="Pa", fmt="h")
    ]


class OBD_PID33(OBD_Packet):
    name = "PID_33_AbsoluteBarometricPressure"
    fields_desc = [
        ScalingField('data', 0, unit="kPa")
    ]


class _OBD_PID34_3B(OBD_Packet):
    fields_desc = [
        ScalingField('equivalence_ratio', 0, scaling=0.0000305, fmt="H"),
        ScalingField('current', 0, scaling=0.00390625, unit="mA", fmt="H")
    ]


class OBD_PID34(_OBD_PID34_3B):
    name = "PID_34_OxygenSensor1"


class OBD_PID35(_OBD_PID34_3B):
    name = "PID_35_OxygenSensor2"


class OBD_PID36(_OBD_PID34_3B):
    name = "PID_36_OxygenSensor3"


class OBD_PID37(_OBD_PID34_3B):
    name = "PID_37_OxygenSensor4"


class OBD_PID38(_OBD_PID34_3B):
    name = "PID_38_OxygenSensor5"


class OBD_PID39(_OBD_PID34_3B):
    name = "PID_39_OxygenSensor6"


class OBD_PID3A(_OBD_PID34_3B):
    name = "PID_3A_OxygenSensor7"


class OBD_PID3B(_OBD_PID34_3B):
    name = "PID_3B_OxygenSensor8"


class OBD_PID3C(OBD_Packet):
    name = "PID_3C_CatalystTemperatureBank1Sensor1"
    fields_desc = [
        ScalingField('data', 0, scaling=0.1, unit="deg. C",
                     offset=-40.0, fmt="H")
    ]


class OBD_PID3D(OBD_Packet):
    name = "PID_3D_CatalystTemperatureBank2Sensor1"
    fields_desc = [
        ScalingField('data', 0, scaling=0.1, unit="deg. C",
                     offset=-40.0, fmt="H")
    ]


class OBD_PID3E(OBD_Packet):
    name = "PID_3E_CatalystTemperatureBank1Sensor2"
    fields_desc = [
        ScalingField('data', 0, scaling=0.1, unit="deg. C",
                     offset=-40.0, fmt="H")
    ]


class OBD_PID3F(OBD_Packet):
    name = "PID_3F_CatalystTemperatureBank2Sensor2"
    fields_desc = [
        ScalingField('data', 0, scaling=0.1, unit="deg. C",
                     offset=-40.0, fmt="H")
    ]
