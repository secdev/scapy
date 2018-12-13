# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from scapy.fields import StrFixedLenField, BitField, FlagsField, XShortField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class OBD_PID60(Packet):
    name = "PID_60_PIDsSupported"
    fields_desc = [
        FlagsField('supportedPIDs', 0, 32, [
            'PID80',
            'PID7F',
            'PID7E',
            'PID7D',
            'PID7C',
            'PID7B',
            'PID7A',
            'PID79',
            'PID78',
            'PID77',
            'PID76',
            'PID75',
            'PID74',
            'PID73',
            'PID72',
            'PID71',
            'PID70',
            'PID6F',
            'PID6E',
            'PID6D',
            'PID6C',
            'PID6B',
            'PID6A',
            'PID69',
            'PID68',
            'PID67',
            'PID66',
            'PID65',
            'PID64',
            'PID63',
            'PID62',
            'PID61'
        ])
    ]


class OBD_PID61(Packet):
    name = "PID_61_DriverSDemandEnginePercentTorque"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID62(Packet):
    name = "PID_62_ActualEnginePercentTorque"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID63(Packet):
    name = "PID_63_EngineReferenceTorque"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID64(Packet):
    name = "PID_64_EnginePercentTorqueData"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID65(Packet):
    name = "PID_65_AuxiliaryInputOutputSupported"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID66(Packet):
    name = "PID_66_MassAirFlowSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID67(Packet):
    name = "PID_67_EngineCoolantTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 3)
    ]


class OBD_PID68(Packet):
    name = "PID_68_IntakeAirTemperatureSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class OBD_PID69(Packet):
    name = "PID_69_CommandedEgrAndEgrError"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class OBD_PID6A(Packet):
    name = "PID_6A_CommandedDieselIntakeAirFlowControl" \
           "AndRelativeIntakeAirFlowPosition"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID6B(Packet):
    name = "PID_6B_ExhaustGasRecirculationTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID6C(Packet):
    name = "PID_6C_CommandedThrottleActuatorControlAndRelativeThrottlePosition"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID6D(Packet):
    name = "PID_6D_FuelPressureControlSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 6)
    ]


class OBD_PID6E(Packet):
    name = "PID_6E_InjectionPressureControlSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID6F(Packet):
    name = "PID_6F_TurbochargerCompressorInletPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 3)
    ]


class OBD_PID70(Packet):
    name = "PID_70_BoostPressureControl"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class OBD_PID71(Packet):
    name = "PID_71_VariableGeometryTurboControl"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID72(Packet):
    name = "PID_72_WastegateControl"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID73(Packet):
    name = "PID_73_ExhaustPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID74(Packet):
    name = "PID_74_TurbochargerRpm"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID75(Packet):
    name = "PID_75_TurbochargerTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class OBD_PID76(Packet):
    name = "PID_76_TurbochargerTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class OBD_PID77(Packet):
    name = "PID_77_ChargeAirCoolerTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID78(Packet):
    name = "PID_78_ExhaustGasTemperatureBank1"
    fields_desc = [
        BitField('reserved', 0, 4),
        FlagsField('supportedSensors', 0, 4, ['Sensor1', 'Sensor2', 'Sensor3', 'Sensor4']),
        XShortField('temperature1', b''),
        XShortField('temperature2', b''),
        XShortField('temperature3', b''),
        XShortField('temperature4', b'')
    ]


class OBD_PID79(Packet):
    name = "PID_79_ExhaustGasTemperatureBank2"
    fields_desc = [
        BitField('reserved', 0, 4),
        FlagsField('supportedSensors', 0, 4, ['Sensor1', 'Sensor2', 'Sensor3', 'Sensor4']),
        XShortField('temperature1', b''),
        XShortField('temperature2', b''),
        XShortField('temperature3', b''),
        XShortField('temperature4', b'')
    ]


class OBD_PID7A(Packet):
    name = "PID_7A_DieselParticulateFilter"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class OBD_PID7B(Packet):
    name = "PID_7B_DieselParticulateFilter"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class OBD_PID7C(Packet):
    name = "PID_7C_DieselParticulateFilterTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class OBD_PID7D(Packet):
    name = "PID_7D_NoxNteControlAreaStatus"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID7E(Packet):
    name = "PID_7E_PmNteControlAreaStatus"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID7F(Packet):
    name = "PID_7F_EngineRunTime"
    fields_desc = [
        StrFixedLenField('data', b'', 13)
    ]
