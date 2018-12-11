#! /usr/bin/env python

from scapy.fields import StrFixedLenField, BitField, FlagsField, XShortField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class Pid60_S1AndS2(Packet):
    name = "PID_60_PidsSupported"
    fields_desc = [
        FlagsField('supportedPids', 0, 32, [
            'Pid80',
            'Pid7F',
            'Pid7E',
            'Pid7D',
            'Pid7C',
            'Pid7B',
            'Pid7A',
            'Pid79',
            'Pid78',
            'Pid77',
            'Pid76',
            'Pid75',
            'Pid74',
            'Pid73',
            'Pid72',
            'Pid71',
            'Pid70',
            'Pid6F',
            'Pid6E',
            'Pid6D',
            'Pid6C',
            'Pid6B',
            'Pid6A',
            'Pid69',
            'Pid68',
            'Pid67',
            'Pid66',
            'Pid65',
            'Pid64',
            'Pid63',
            'Pid62',
            'Pid61'
        ])
    ]


class Pid61_S1AndS2(Packet):
    name = "PID_61_DriverSDemandEnginePercentTorque"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid62_S1AndS2(Packet):
    name = "PID_62_ActualEnginePercentTorque"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid63_S1AndS2(Packet):
    name = "PID_63_EngineReferenceTorque"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid64_S1AndS2(Packet):
    name = "PID_64_EnginePercentTorqueData"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid65_S1AndS2(Packet):
    name = "PID_65_AuxiliaryInputOutputSupported"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid66_S1AndS2(Packet):
    name = "PID_66_MassAirFlowSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid67_S1AndS2(Packet):
    name = "PID_67_EngineCoolantTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 3)
    ]


class Pid68_S1AndS2(Packet):
    name = "PID_68_IntakeAirTemperatureSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class Pid69_S1AndS2(Packet):
    name = "PID_69_CommandedEgrAndEgrError"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class Pid6A_S1AndS2(Packet):
    name = "PID_6A_CommandedDieselIntakeAirFlowControl" \
           "AndRelativeIntakeAirFlowPosition"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid6B_S1AndS2(Packet):
    name = "PID_6B_ExhaustGasRecirculationTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid6C_S1AndS2(Packet):
    name = "PID_6C_CommandedThrottleActuatorControlAndRelativeThrottlePosition"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid6D_S1AndS2(Packet):
    name = "PID_6D_FuelPressureControlSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 6)
    ]


class Pid6E_S1AndS2(Packet):
    name = "PID_6E_InjectionPressureControlSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid6F_S1AndS2(Packet):
    name = "PID_6F_TurbochargerCompressorInletPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 3)
    ]


class Pid70_S1AndS2(Packet):
    name = "PID_70_BoostPressureControl"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class Pid71_S1AndS2(Packet):
    name = "PID_71_VariableGeometryTurboControl"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid72_S1AndS2(Packet):
    name = "PID_72_WastegateControl"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid73_S1AndS2(Packet):
    name = "PID_73_ExhaustPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid74_S1AndS2(Packet):
    name = "PID_74_TurbochargerRpm"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid75_S1AndS2(Packet):
    name = "PID_75_TurbochargerTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class Pid76_S1AndS2(Packet):
    name = "PID_76_TurbochargerTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class Pid77_S1AndS2(Packet):
    name = "PID_77_ChargeAirCoolerTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class Pid78_S1AndS2(Packet):
    name = "PID_78_ExhaustGasTemperatureBank1"
    fields_desc = [
        BitField('reserved', 0, 4),
        FlagsField('supportedSensors', 0, 4, ['Sensor1', 'Sensor2', 'Sensor3', 'Sensor4']),
        XShortField('temperature1', b''),
        XShortField('temperature2', b''),
        XShortField('temperature3', b''),
        XShortField('temperature4', b'')
    ]


class Pid79_S1AndS2(Packet):
    name = "PID_79_ExhaustGasTemperatureBank2"
    fields_desc = [
        BitField('reserved', 0, 4),
        FlagsField('supportedSensors', 0, 4, ['Sensor1', 'Sensor2', 'Sensor3', 'Sensor4']),
        XShortField('temperature1', b''),
        XShortField('temperature2', b''),
        XShortField('temperature3', b''),
        XShortField('temperature4', b'')
    ]


class Pid7A_S1AndS2(Packet):
    name = "PID_7A_DieselParticulateFilter"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class Pid7B_S1AndS2(Packet):
    name = "PID_7B_DieselParticulateFilter"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class Pid7C_S1AndS2(Packet):
    name = "PID_7C_DieselParticulateFilterTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class Pid7D_S1AndS2(Packet):
    name = "PID_7D_NoxNteControlAreaStatus"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid7E_S1AndS2(Packet):
    name = "PID_7E_PmNteControlAreaStatus"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid7F_S1AndS2(Packet):
    name = "PID_7F_EngineRunTime"
    fields_desc = [
        StrFixedLenField('data', b'', 13)
    ]
