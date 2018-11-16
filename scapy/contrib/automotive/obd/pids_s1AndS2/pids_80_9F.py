#! /usr/bin/env python

from scapy.fields import StrFixedLenField, FlagsField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class Pid80_S1AndS2(Packet):
    name = "PID_80_PidsSupported"
    fields_desc = [
        FlagsField('supportedPids', b'', 32, [
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


class Pid81_S1AndS2(Packet):
    name = "PID_81_EngineRunTimeForAuxiliaryEmissionsControlDevice"
    fields_desc = [
        StrFixedLenField('data', b'', 21)
    ]


class Pid82_S1AndS2(Packet):
    name = "PID_82_EngineRunTimeForAuxiliaryEmissionsControlDevice"
    fields_desc = [
        StrFixedLenField('data', b'', 21)
    ]


class Pid83_S1AndS2(Packet):
    name = "PID_83_NoxSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid84_S1AndS2(Packet):
    name = "PID_84_ManifoldSurfaceTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid85_S1AndS2(Packet):
    name = "PID_85_NoxReagentSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 10)
    ]


class Pid86_S1AndS2(Packet):
    name = "PID_86_ParticulateMatterSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid87_S1AndS2(Packet):
    name = "PID_87_IntakeManifoldAbsolutePressure"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid88_S1AndS2(Packet):
    name = "PID_88_ScrInduceSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 13)
    ]


class Pid89_S1AndS2(Packet):
    # 11 - 15
    name = "PID_89_RunTimeForAecd"
    fields_desc = [
        StrFixedLenField('data', b'', 41)
    ]


class Pid8A_S1AndS2(Packet):
    # 16 - 20
    name = "PID_8A_RunTimeForAecd"
    fields_desc = [
        StrFixedLenField('data', b'', 41)
    ]


class Pid8B_S1AndS2(Packet):
    name = "PID_8B_DieselAftertreatment"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class Pid8C_S1AndS2(Packet):
    name = "PID_8C_O2Sensor"
    fields_desc = [
        StrFixedLenField('data', b'', 16)
    ]


class Pid8D_S1AndS2(Packet):
    name = "PID_8D_ThrottlePositionG"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid8E_S1AndS2(Packet):
    name = "PID_8E_EngineFrictionPercentTorque"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid8F_S1AndS2(Packet):
    name = "PID_8F_PmSensorBank1And2"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid90_S1AndS2(Packet):
    name = "PID_90_WwhObdVehicleObdSystemInformation"
    fields_desc = [
        StrFixedLenField('data', b'', 3)
    ]


class Pid91_S1AndS2(Packet):
    name = "PID_91_WwhObdVehicleObdSystemInformation"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid92_S1AndS2(Packet):
    name = "PID_92_FuelSystemControl"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid93_S1AndS2(Packet):
    name = "PID_93_WwhObdVehicleObdCountersSupport"
    fields_desc = [
        StrFixedLenField('data', b'', 3)
    ]


class Pid94_S1AndS2(Packet):
    name = "PID_94_NoxWarningAndInducementSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 12)
    ]


class Pid98_S1AndS2(Packet):
    name = "PID_98_ExhaustGasTemperatureSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class Pid99_S1AndS2(Packet):
    name = "PID_99_ExhaustGasTemperatureSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class Pid9A_S1AndS2(Packet):
    name = "PID_9A_HybridEvVehicleSystemDataBatteryVoltage"
    fields_desc = [
        StrFixedLenField('data', b'', 6)
    ]


class Pid9B_S1AndS2(Packet):
    name = "PID_9B_DieselExhaustFluidSensorData"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid9C_S1AndS2(Packet):
    name = "PID_9C_O2SensorData"
    fields_desc = [
        StrFixedLenField('data', b'', 17)
    ]


class Pid9D_S1AndS2(Packet):
    name = "PID_9D_EngineFuelRate"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid9E_S1AndS2(Packet):
    name = "PID_9E_EngineExhaustFlowRate"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid9F_S1AndS2(Packet):
    name = "PID_9F_FuelSystemPercentageUse"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]
