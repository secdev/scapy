# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from scapy.fields import StrFixedLenField, ByteEnumField, BitEnumField, \
    BitField, ConditionalField, FlagsField, XByteField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class OBD_PID40(Packet):
    name = "PID_40_PidsSupported"
    fields_desc = [
        FlagsField('supportedPids', 0, 32, [
            'Pid60',
            'Pid5F',
            'Pid5E',
            'Pid5D',
            'Pid5C',
            'Pid5B',
            'Pid5A',
            'Pid59',
            'Pid58',
            'Pid57',
            'Pid56',
            'Pid55',
            'Pid54',
            'Pid53',
            'Pid52',
            'Pid51',
            'Pid50',
            'Pid4F',
            'Pid4E',
            'Pid4D',
            'Pid4C',
            'Pid4B',
            'Pid4A',
            'Pid49',
            'Pid48',
            'Pid47',
            'Pid46',
            'Pid45',
            'Pid44',
            'Pid43',
            'Pid42',
            'Pid41'
        ])
    ]


class OBD_PID41(Packet):
    name = "PID_41_MonitorStatusThisDriveCycle"
    onOff = {
        0: 'off',
        1: 'on'
    }

    availability = {
        0: 'unavailable',
        1: 'available'
    }

    completeness = {
        0: 'complete',
        1: 'uncomplete'
    }

    ignitionTypes = {
        0: 'Spark ignition',
        1: 'Compression ignition'
    }

    @staticmethod
    def isspark(pkt):
        return pkt.ignitionType == 0

    @staticmethod
    def iscompression(pkt):
        return pkt.ignitionType == 1

    fields_desc = [
        # always zero
        XByteField('reserved', b''),

        BitField('reserved', 0, 1),
        BitEnumField('componentsCompleteness', 0, 1, completeness),
        BitEnumField('fuelSystemCompleteness', 0, 1, completeness),
        BitEnumField('misfireCompleteness', 0, 1, completeness),

        BitEnumField('componentsAvailability', 0, 1, availability),
        BitEnumField('ignitionType', 0, 1, ignitionTypes),
        BitEnumField('fuelSystemAvailability', 0, 1, availability),
        BitEnumField('misfireAvailability', 0, 1, availability),

        # Spark
        # Availability
        ConditionalField(BitEnumField('egrSystemAvailability', 0, 1, availability), isspark),
        ConditionalField(BitEnumField('oxygenSensorHeaterAvailability', 0, 1, availability), isspark),
        ConditionalField(BitEnumField('oxygenSensorAvailability', 0, 1, availability), isspark),
        ConditionalField(BitEnumField('acRefrigerantAvailability', 0, 1, availability), isspark),
        ConditionalField(BitEnumField('secondaryAirSystemAvailability', 0, 1, availability), isspark),
        ConditionalField(BitEnumField('evaporativeSystemAvailability', 0, 1, availability), isspark),
        ConditionalField(BitEnumField('heatedCatalystAvailability', 0, 1, availability), isspark),
        ConditionalField(BitEnumField('catalystAvailability', 0, 1, availability), isspark),

        # Completeness
        ConditionalField(BitEnumField('egrSystemCompleteness', 0, 1, completeness), isspark),
        ConditionalField(BitEnumField('oxygenSensorHeaterCompleteness', 0, 1, completeness), isspark),
        ConditionalField(BitEnumField('oxygenSensorCompleteness', 0, 1, completeness), isspark),
        ConditionalField(BitEnumField('acRefrigerantCompleteness', 0, 1, completeness), isspark),
        ConditionalField(BitEnumField('secondaryAirSystemCompleteness', 0, 1, completeness), isspark),
        ConditionalField(BitEnumField('evaporativeSystemCompleteness', 0, 1, completeness), isspark),
        ConditionalField(BitEnumField('heatedCatalystCompleteness', 0, 1, completeness), isspark),
        ConditionalField(BitEnumField('catalystCompleteness', 0, 1, completeness), isspark),

        # Compression
        # Availability
        ConditionalField(BitEnumField('egrVvtSystemAvailability', 0, 1, availability), iscompression),
        ConditionalField(BitEnumField('pmFilterMonitoringAvailability', 0, 1, availability), iscompression),
        ConditionalField(BitEnumField('exhaustGasSensorAvailability', 0, 1, availability), iscompression),
        ConditionalField(BitEnumField('Reserved1', 0, 1, availability), iscompression),
        ConditionalField(BitEnumField('boostPressureAvailability', 0, 1, availability), iscompression),
        ConditionalField(BitEnumField('Reserved2', 0, 1, availability), iscompression),
        ConditionalField(BitEnumField('noxScrMonitorAvailability', 0, 1, availability), iscompression),
        ConditionalField(BitEnumField('nmhcCatalystAvailability', 0, 1, availability), iscompression),

        # Completeness
        ConditionalField(BitEnumField('egrVvtSystemCompleteness', 0, 1, completeness), iscompression),
        ConditionalField(BitEnumField('pmFilterMonitoringCompleteness', 0, 1, completeness), iscompression),
        ConditionalField(BitEnumField('exhaustGasSensorCompleteness', 0, 1, completeness), iscompression),
        ConditionalField(BitEnumField('Reserved1', 0, 1, completeness), iscompression),
        ConditionalField(BitEnumField('boostPressureCompleteness', 0, 1, completeness), iscompression),
        ConditionalField(BitEnumField('Reserved2', 0, 1, completeness), iscompression),
        ConditionalField(BitEnumField('noxScrMonitorCompleteness', 0, 1, completeness), iscompression),
        ConditionalField(BitEnumField('nmhcCatalystCompleteness', 0, 1, completeness), iscompression),
    ]


class OBD_PID42(Packet):
    name = "PID_42_ControlModuleVoltage"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID43(Packet):
    name = "PID_43_AbsoluteLoadValue"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID44(Packet):
    name = "PID_44_FuelAirCommandedEquivalenceRatio"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID45(Packet):
    name = "PID_45_RelativeThrottlePosition"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID46(Packet):
    name = "PID_46_AmbientAirTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID47(Packet):
    name = "PID_47_AbsoluteThrottlePositionB"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID48(Packet):
    name = "PID_48_AbsoluteThrottlePositionC"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID49(Packet):
    name = "PID_49_AcceleratorPedalPositionD"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID4A(Packet):
    name = "PID_4A_AcceleratorPedalPositionE"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID4B(Packet):
    name = "PID_4B_AcceleratorPedalPositionF"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID4C(Packet):
    name = "PID_4C_CommandedThrottleActuator"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID4D(Packet):
    name = "PID_4D_TimeRunWithMilOn"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID4E(Packet):
    name = "PID_4E_TimeSinceTroubleCodesCleared"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID4F(Packet):
    name = "PID_4F_VariousMaxValues"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID50(Packet):
    name = "PID_50_MaximumValueForAirFlowRateFromMassAirFlowSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID51(Packet):
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


class OBD_PID52(Packet):
    name = "PID_52_EthanolFuel"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID53(Packet):
    name = "PID_53_AbsoluteEvapSystemVaporPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID54(Packet):
    name = "PID_54_EvapSystemVaporPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID55(Packet):
    name = "PID_55_ShortTermSecondaryOxygenSensorTrimABank1BBank3"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID56(Packet):
    name = "PID_56_LongTermSecondaryOxygenSensorTrimABank1BBank3"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID57(Packet):
    name = "PID_57_ShortTermSecondaryOxygenSensorTrimABank2BBank4"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID58(Packet):
    name = "PID_58_LongTermSecondaryOxygenSensorTrimABank2BBank4"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID59(Packet):
    name = "PID_59_FuelRailAbsolutePressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID5A(Packet):
    name = "PID_5A_RelativeAcceleratorPedalPosition"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID5B(Packet):
    name = "PID_5B_HybridBatteryPackRemainingLife"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID5C(Packet):
    name = "PID_5C_EngineOilTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID5D(Packet):
    name = "PID_5D_FuelInjectionTiming"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID5E(Packet):
    name = "PID_5E_EngineFuelRate"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID5F(Packet):
    name = "PID_5F_EmissionRequirementsToWhichVehicleIsDesigned"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]
