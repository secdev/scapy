# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.status = skip

from scapy.fields import ByteEnumField, BitField, FlagsField, XByteField, \
    ScalingField, ThreeBytesField
from scapy.contrib.automotive.obd.packet import OBD_Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification


class OBD_PID40(OBD_Packet):
    name = "PID_40_PIDsSupported"
    fields_desc = [
        FlagsField('supported_pids', 0, 32, [
            'PID60',
            'PID5F',
            'PID5E',
            'PID5D',
            'PID5C',
            'PID5B',
            'PID5A',
            'PID59',
            'PID58',
            'PID57',
            'PID56',
            'PID55',
            'PID54',
            'PID53',
            'PID52',
            'PID51',
            'PID50',
            'PID4F',
            'PID4E',
            'PID4D',
            'PID4C',
            'PID4B',
            'PID4A',
            'PID49',
            'PID48',
            'PID47',
            'PID46',
            'PID45',
            'PID44',
            'PID43',
            'PID42',
            'PID41'
        ])
    ]


class OBD_PID41(OBD_Packet):
    name = "PID_41_MonitorStatusThisDriveCycle"
    onOff = {
        0: 'off',
        1: 'on'
    }

    fields_desc = [
        XByteField('reserved', 0),

        BitField('reserved1', 0, 1),
        FlagsField('continuous_tests_ready', 0, 3, [
            'misfire',
            'fuelSystem',
            'components'
        ]),

        BitField('reserved2', 0, 1),
        FlagsField('continuous_tests_supported', 0, 3, [
            'misfire',
            'fuelSystem',
            'components'
        ]),

        FlagsField('once_per_trip_tests_supported', 0, 8, [
            'egr',
            'oxygenSensorHeater',
            'oxygenSensor',
            'acSystemRefrigerant',
            'secondaryAirSystem',
            'evaporativeSystem',
            'heatedCatalyst',
            'catalyst'
        ]),

        FlagsField('once_per_trip_tests_ready', 0, 8, [
            'egr',
            'oxygenSensorHeater',
            'oxygenSensor',
            'acSystemRefrigerant',
            'secondaryAirSystem',
            'evaporativeSystem',
            'heatedCatalyst',
            'catalyst'
        ])
    ]


class OBD_PID42(OBD_Packet):
    name = "PID_42_ControlModuleVoltage"
    fields_desc = [
        ScalingField('data', 0, scaling=0.001, unit="V", fmt="H")
    ]


class OBD_PID43(OBD_Packet):
    name = "PID_43_AbsoluteLoadValue"
    fields_desc = [
        ScalingField('data', 0, scaling=100 / 255., unit="%", fmt="H")
    ]


class OBD_PID44(OBD_Packet):
    name = "PID_44_FuelAirCommandedEquivalenceRatio"
    fields_desc = [
        ScalingField('data', 0, scaling=0.0000305, fmt="H")
    ]


class _OBD_PercentPacket(OBD_Packet):
    fields_desc = [
        ScalingField('data', 0, scaling=100 / 255., unit="%")
    ]


class OBD_PID45(_OBD_PercentPacket):
    name = "PID_45_RelativeThrottlePosition"


class OBD_PID46(OBD_Packet):
    name = "PID_46_AmbientAirTemperature"
    fields_desc = [
        ScalingField('data', 0, unit="deg. C", offset=-40.0)
    ]


class OBD_PID47(_OBD_PercentPacket):
    name = "PID_47_AbsoluteThrottlePositionB"


class OBD_PID48(_OBD_PercentPacket):
    name = "PID_48_AbsoluteThrottlePositionC"


class OBD_PID49(_OBD_PercentPacket):
    name = "PID_49_AcceleratorPedalPositionD"


class OBD_PID4A(_OBD_PercentPacket):
    name = "PID_4A_AcceleratorPedalPositionE"


class OBD_PID4B(_OBD_PercentPacket):
    name = "PID_4B_AcceleratorPedalPositionF"


class OBD_PID4C(_OBD_PercentPacket):
    name = "PID_4C_CommandedThrottleActuator"


class OBD_PID4D(OBD_Packet):
    name = "PID_4D_TimeRunWithMilOn"
    fields_desc = [
        ScalingField('data', 0, unit="min", fmt="H")
    ]


class OBD_PID4E(OBD_Packet):
    name = "PID_4E_TimeSinceTroubleCodesCleared"
    fields_desc = [
        ScalingField('data', 0, unit="min", fmt="H")
    ]


class OBD_PID4F(OBD_Packet):
    name = "PID_4F_VariousMaxValues"
    fields_desc = [
        ScalingField('equivalence_ratio', 0),
        ScalingField('sensor_voltage', 0, unit="V"),
        ScalingField('sensor_current', 0, unit="mA"),
        ScalingField('intake_manifold_absolute_pressure', 0,
                     scaling=10, unit="kPa")
    ]


class OBD_PID50(OBD_Packet):
    name = "PID_50_MaximumValueForAirFlowRateFromMassAirFlowSensor"
    fields_desc = [
        ScalingField('data', 0, scaling=10, unit="g/s"),
        ThreeBytesField('reserved', 0)
    ]


class OBD_PID51(OBD_Packet):
    name = "PID_51_FuelType"

    fuelTypes = {
        0: 'Not available',
        1: 'Gasoline',
        2: 'Methanol',
        3: 'Ethanol',
        4: 'Diesel',
        5: 'LPG',
        6: 'CNG',
        7: 'Propane',
        8: 'Electric',
        9: 'Bifuel running Gasoline',
        10: 'Bifuel running Methanol',
        11: 'Bifuel running Ethanol',
        12: 'Bifuel running LPG',
        13: 'Bifuel running CNG',
        14: 'Bifuel running Propane',
        15: 'Bifuel running Electricity',
        16: 'Bifuel running electric and combustion engine',
        17: 'Hybrid gasoline',
        18: 'Hybrid Ethanol',
        19: 'Hybrid Diesel',
        20: 'Hybrid Electric',
        21: 'Hybrid running electric and combustion engine',
        22: 'Hybrid Regenerative',
        23: 'Bifuel running diesel'}

    fields_desc = [
        ByteEnumField('data', 0, fuelTypes)
    ]


class OBD_PID52(_OBD_PercentPacket):
    name = "PID_52_EthanolFuel"


class OBD_PID53(OBD_Packet):
    name = "PID_53_AbsoluteEvapSystemVaporPressure"
    fields_desc = [
        ScalingField('data', 0, scaling=1 / 200., unit="kPa", fmt="H")
    ]


class OBD_PID54(OBD_Packet):
    name = "PID_54_EvapSystemVaporPressure"
    fields_desc = [
        ScalingField('data', 0, unit="Pa", fmt="h")
    ]


class _OBD_SensorTrimPacket1(OBD_Packet):
    fields_desc = [
        ScalingField('bank1', 0, scaling=100 / 128.,
                     offset=-100, unit="%"),
        ScalingField('bank3', 0, scaling=100 / 128.,
                     offset=-100, unit="%")
    ]


class _OBD_SensorTrimPacket2(OBD_Packet):
    fields_desc = [
        ScalingField('bank2', 0, scaling=100 / 128.,
                     offset=-100, unit="%"),
        ScalingField('bank4', 0, scaling=100 / 128.,
                     offset=-100, unit="%")
    ]


class OBD_PID55(_OBD_SensorTrimPacket1):
    name = "PID_55_ShortTermSecondaryOxygenSensorTrim"


class OBD_PID56(_OBD_SensorTrimPacket1):
    name = "PID_56_LongTermSecondaryOxygenSensorTrim"


class OBD_PID57(_OBD_SensorTrimPacket2):
    name = "PID_57_ShortTermSecondaryOxygenSensorTrim"


class OBD_PID58(_OBD_SensorTrimPacket2):
    name = "PID_58_LongTermSecondaryOxygenSensorTrim"


class OBD_PID59(OBD_Packet):
    name = "PID_59_FuelRailAbsolutePressure"
    fields_desc = [
        ScalingField('data', 0, scaling=10, unit="kPa", fmt="H")
    ]


class OBD_PID5A(_OBD_PercentPacket):
    name = "PID_5A_RelativeAcceleratorPedalPosition"


class OBD_PID5B(_OBD_PercentPacket):
    name = "PID_5B_HybridBatteryPackRemainingLife"


class OBD_PID5C(OBD_Packet):
    name = "PID_5C_EngineOilTemperature"
    fields_desc = [
        ScalingField('data', 0, unit="deg. C", offset=-40.0)
    ]


class OBD_PID5D(OBD_Packet):
    name = "PID_5D_FuelInjectionTiming"
    fields_desc = [
        ScalingField('data', 0, scaling=1 / 128., offset=-210,
                     unit="deg.", fmt="H")
    ]


class OBD_PID5E(OBD_Packet):
    name = "PID_5E_EngineFuelRate"
    fields_desc = [
        ScalingField('data', 0, scaling=0.05, unit="L/h", fmt="H")
    ]


class OBD_PID5F(OBD_Packet):
    name = "PID_5F_EmissionRequirementsToWhichVehicleIsDesigned"

    emissionRequirementTypes = {
        0xE: 'Heavy Duty Vehicles (EURO IV) B1',
        0xF: 'Heavy Duty Vehicles (EURO V) B2',
        0x10: 'Heavy Duty Vehicles (EURO EEV) C',
    }

    fields_desc = [
        ByteEnumField('data', 0, emissionRequirementTypes)
    ]
