# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from scapy.fields import StrFixedLenField, FlagsField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class OBD_PID80(Packet):
    name = "PID_80_PidsSupported"
    fields_desc = [
        FlagsField('supportedPids', 0, 32, [
            'PidA0',
            'Pid9F',
            'Pid9E',
            'Pid9D',
            'Pid9C',
            'Pid9B',
            'Pid9A',
            'Pid99',
            'Pid98',
            'Pid97',
            'Pid96',
            'Pid95',
            'Pid94',
            'Pid93',
            'Pid92',
            'Pid91',
            'Pid90',
            'Pid8F',
            'Pid8E',
            'Pid8D',
            'Pid8C',
            'Pid8B',
            'Pid8A',
            'Pid89',
            'Pid88',
            'Pid87',
            'Pid86',
            'Pid85',
            'Pid84',
            'Pid83',
            'Pid82',
            'Pid81'
        ])
    ]


class OBD_PID81(Packet):
    name = "PID_81_EngineRunTimeForAuxiliaryEmissionsControlDevice"
    fields_desc = [
        StrFixedLenField('data', b'', 21)
    ]


class OBD_PID82(Packet):
    name = "PID_82_EngineRunTimeForAuxiliaryEmissionsControlDevice"
    fields_desc = [
        StrFixedLenField('data', b'', 21)
    ]


class OBD_PID83(Packet):
    name = "PID_83_NoxSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID84(Packet):
    name = "PID_84_ManifoldSurfaceTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID85(Packet):
    name = "PID_85_NoxReagentSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 10)
    ]


class OBD_PID86(Packet):
    name = "PID_86_ParticulateMatterSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID87(Packet):
    name = "PID_87_IntakeManifoldAbsolutePressure"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID88(Packet):
    name = "PID_88_ScrInduceSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 13)
    ]


class OBD_PID89(Packet):
    # 11 - 15
    name = "PID_89_RunTimeForAecd"
    fields_desc = [
        StrFixedLenField('data', b'', 41)
    ]


class OBD_PID8A(Packet):
    # 16 - 20
    name = "PID_8A_RunTimeForAecd"
    fields_desc = [
        StrFixedLenField('data', b'', 41)
    ]


class OBD_PID8B(Packet):
    name = "PID_8B_DieselAftertreatment"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class OBD_PID8C(Packet):
    name = "PID_8C_O2Sensor"
    fields_desc = [
        StrFixedLenField('data', b'', 16)
    ]


class OBD_PID8D(Packet):
    name = "PID_8D_ThrottlePositionG"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID8E(Packet):
    name = "PID_8E_EngineFrictionPercentTorque"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID8F(Packet):
    name = "PID_8F_PmSensorBank1And2"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID90(Packet):
    name = "PID_90_WwhObdVehicleObdSystemInformation"
    fields_desc = [
        StrFixedLenField('data', b'', 3)
    ]


class OBD_PID91(Packet):
    name = "PID_91_WwhObdVehicleObdSystemInformation"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID92(Packet):
    name = "PID_92_FuelSystemControl"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID93(Packet):
    name = "PID_93_WwhObdVehicleObdCountersSupport"
    fields_desc = [
        StrFixedLenField('data', b'', 3)
    ]


class OBD_PID94(Packet):
    name = "PID_94_NoxWarningAndInducementSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 12)
    ]


class OBD_PID98(Packet):
    name = "PID_98_ExhaustGasTemperatureSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class OBD_PID99(Packet):
    name = "PID_99_ExhaustGasTemperatureSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class OBD_PID9A(Packet):
    name = "PID_9A_HybridEvVehicleSystemDataBatteryVoltage"
    fields_desc = [
        StrFixedLenField('data', b'', 6)
    ]


class OBD_PID9B(Packet):
    name = "PID_9B_DieselExhaustFluidSensorData"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID9C(Packet):
    name = "PID_9C_O2SensorData"
    fields_desc = [
        StrFixedLenField('data', b'', 17)
    ]


class OBD_PID9D(Packet):
    name = "PID_9D_EngineFuelRate"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID9E(Packet):
    name = "PID_9E_EngineExhaustFlowRate"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID9F(Packet):
    name = "PID_9F_FuelSystemPercentageUse"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]
