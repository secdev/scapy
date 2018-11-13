#! /usr/bin/env python

from scapy.fields import StrFixedLenField, ByteEnumField, BitEnumField, BitField, ConditionalField, FlagsField, \
    XByteEnumField, XByteField, XShortField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class Pid00_S1AndS2(Packet):
    name = "PID_00_PidsSupported"

    fields_desc = [
        FlagsField('supportedPids', b'', 32, [
            'Pid20',
            'Pid1F',
            'Pid1E',
            'Pid1D',
            'Pid1C',
            'Pid1B',
            'Pid1A',
            'Pid19',
            'Pid18',
            'Pid17',
            'Pid16',
            'Pid15',
            'Pid14',
            'Pid13',
            'Pid12',
            'Pid11',
            'Pid10',
            'Pid0F',
            'Pid0E',
            'Pid0D',
            'Pid0C',
            'Pid0B',
            'Pid0A',
            'Pid09',
            'Pid08',
            'Pid07',
            'Pid06',
            'Pid05',
            'Pid04',
            'Pid03',
            'Pid02',
            'Pid01'
        ])
    ]


class Pid01_S1AndS2(Packet):
    name = "PID_01_MonitorStatusSinceDtcsCleared"

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
        0: 'spark ignition',
        1: 'compression ignition'
    }

    @staticmethod
    def isspark(pkt):
        return pkt.ignitionType == 0

    @staticmethod
    def iscompression(pkt):
        return pkt.ignitionType == 1

    fields_desc = [
        BitEnumField('MIL', b'', 1, onOff),
        BitField('DTC_Count', b'', 7),

        BitField('reserved', b'', 1),
        BitEnumField('componentsCompleteness', b'', 1, completeness),
        BitEnumField('fuelSystemCompleteness', b'', 1, completeness),
        BitEnumField('misfireCompleteness', b'', 1, completeness),

        BitEnumField('componentsAvailability', b'', 1, availability),
        BitEnumField('ignitionType', b'', 1, ignitionTypes),
        BitEnumField('fuelSystemAvailability', b'', 1, availability),
        BitEnumField('misfireAvailability', b'', 1, availability),

        # Spark
        # Availability
        ConditionalField(BitEnumField('egrSystemAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('oxygenSensorHeaterAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('oxygenSensorAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('acRefrigerantAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('secondaryAirSystemAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('evaporativeSystemAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('heatedCatalystAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('catalystAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 0),

        # Completeness
        ConditionalField(BitEnumField('egrSystemCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('oxygenSensorHeaterCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('oxygenSensorCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('acRefrigerantCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('secondaryAirSystemCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('evaporativeSystemCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('heatedCatalystCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('catalystCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 0),

        # Compression
        # Availability
        ConditionalField(BitEnumField('egrVvtSystemAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('pmFilterMonitoringAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('exhaustGasSensorAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('Reserved1', b'', 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('boostPressureAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('Reserved2', b'', 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('noxScrMonitorAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('nmhcCatalystAvailability', b'', 1, availability), lambda pkt: pkt.ignitionType == 1),

        # Completeness
        ConditionalField(BitEnumField('egrVvtSystemCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('pmFilterMonitoringCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('exhaustGasSensorCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('Reserved1', b'', 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('boostPressureCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('Reserved2', b'', 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('noxScrMonitorCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('nmhcCatalystCompleteness', b'', 1, completeness), lambda pkt: pkt.ignitionType == 1),
    ]


class Pid02_S1AndS2(Packet):
    name = "PID_02_FreezeDtc"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid03_S1AndS2(Packet):
    name = "PID_03_FuelSystemStatus"

    loopStates = {
        0x00: 'OpenLoopInsufficientEngineTemperature',
        0x02: 'ClosedLoop',
        0x04: 'OpenLoopEngineLoadOrFuelCut',
        0x08: 'OpenLoopDueSystemFailure',
        0x10: 'ClosedLoopWithFault'
    }

    fields_desc = [
        XByteEnumField('fuelSystem1', b'', loopStates),
        XByteEnumField('fuelSystem2', b'', loopStates)
    ]


class Pid04_S1AndS2(Packet):
    name = "PID_04_CalculatedEngineLoad"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid05_S1AndS2(Packet):
    name = "PID_05_EngineCoolantTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid06_S1AndS2(Packet):
    name = "PID_06_ShortTermFuelTrimBank1"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid07_S1AndS2(Packet):
    name = "PID_07_LongTermFuelTrimBank1"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid08_S1AndS2(Packet):
    name = "PID_08_ShortTermFuelTrimBank2"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid09_S1AndS2(Packet):
    name = "PID_09_LongTermFuelTrimBank2"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid0A_S1AndS2(Packet):
    name = "PID_0A_FuelPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid0B_S1AndS2(Packet):
    name = "PID_0B_IntakeManifoldAbsolutePressure"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid0C_S1AndS2(Packet):
    name = "PID_0C_EngineRpm"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid0D_S1AndS2(Packet):
    name = "PID_0D_VehicleSpeed"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid0E_S1AndS2(Packet):
    name = "PID_0E_TimingAdvance"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid0F_S1AndS2(Packet):
    name = "PID_0F_IntakeAirTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid10_S1AndS2(Packet):
    name = "PID_10_MafAirFlowRate"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid11_S1AndS2(Packet):
    name = "PID_11_ThrottlePosition"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid12_S1AndS2(Packet):
    name = "PID_12_CommandedSecondaryAirStatus"

    states = {
        0x00: 'Upstream',
        0x02: 'downstreamCatalyticConverter',
        0x04: 'outsideAtmosphereOrOff',
        0x08: 'pumpCommanded'
    }

    fields_desc = [
        XByteEnumField('data', b'', states)
    ]


class Pid13_S1AndS2(Packet):
    name = "PID_13_OxygenSensorsPresent"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid14_S1AndS2(Packet):
    name = "PID_14_OxygenSensor1"
    fields_desc = [
        XByteField('oxygenSensorOutputVoltage', b''),
        XByteField('shortTermFuelTrim', b'')
    ]


class Pid15_S1AndS2(Packet):
    name = "PID_15_OxygenSensor2"
    fields_desc = [
        XByteField('oxygenSensorOutputVoltage', b''),
        XByteField('shortTermFuelTrim', b'')
    ]


class Pid16_S1AndS2(Packet):
    name = "PID_16_OxygenSensor3"
    fields_desc = [
        XByteField('oxygenSensorOutputVoltage', b''),
        XByteField('shortTermFuelTrim', b'')
    ]


class Pid17_S1AndS2(Packet):
    name = "PID_17_OxygenSensor4"
    fields_desc = [
        XByteField('oxygenSensorOutputVoltage', b''),
        XByteField('shortTermFuelTrim', b'')
    ]


class Pid18_S1AndS2(Packet):
    name = "PID_18_OxygenSensor5"
    fields_desc = [
        XByteField('oxygenSensorOutputVoltage', b''),
        XByteField('shortTermFuelTrim', b'')
    ]


class Pid19_S1AndS2(Packet):
    name = "PID_19_OxygenSensor6"
    fields_desc = [
        XByteField('oxygenSensorOutputVoltage', b''),
        XByteField('shortTermFuelTrim', b'')
    ]


class Pid1A_S1AndS2(Packet):
    name = "PID_1A_OxygenSensor7"
    fields_desc = [
        XByteField('oxygenSensorOutputVoltage', b''),
        XByteField('shortTermFuelTrim', b'')
    ]


class Pid1B_S1AndS2(Packet):
    name = "PID_1B_OxygenSensor8"
    fields_desc = [
        XByteField('oxygenSensorOutputVoltage', b''),
        XByteField('shortTermFuelTrim', b'')
    ]


class Pid1C_S1AndS2(Packet):
    name = "PID_1C_ObdStandardsThisVehicleConformsTo"

    obdStandards = {
        0x01: 'OBD-II as defined by the CARB',
        0x02: 'OBD as defined by the EPA',
        0x03: 'OBD and OBD-II ',
        0x04: 'OBD-I ',
        0x05: 'Not OBD compliant',
        0x06: 'EOBD (Europe) ',
        0x07: 'EOBD and OBD-II ',
        0x08: 'EOBD and OBD',
        0x09: 'EOBD, OBD and OBD II ',
        0x0A: 'JOBD (Japan)',
        0x0B: 'JOBD and OBD II ',
        0x0C: 'JOBD and EOBD',
        0x0D: 'JOBD, EOBD, and OBD II',
        0x0E: 'Reserved',
        0x0F: 'Reserved',
        0x10: 'Reserved',
        0x11: 'Engine Manufacturer Diagnostics (EMD)',
        0x12: 'Engine Manufacturer Diagnostics Enhanced (EMD+)',
        0x13: 'Heavy Duty On-Board Diagnostics (Child/Partial) (HD OBD-C)',
        0x14: 'Heavy Duty On-Board Diagnostics (HD OBD)',
        0x15: 'World Wide Harmonized OBD (WWH OBD)',
        0x16: 'Reserved',
        0x17: 'Heavy Duty Euro OBD Stage I without NOx control (HD EOBD-I)',
        0x18: 'Heavy Duty Euro OBD Stage I with NOx control (HD EOBD-I N)',
        0x19: 'Heavy Duty Euro OBD Stage II without NOx control (HD EOBD-II)',
        0x1A: 'Heavy Duty Euro OBD Stage II with NOx control (HD EOBD-II N)',
        0x1B: 'Reserved',
        0x1C: 'Brazil OBD Phase 1 (OBDBr-1)',
        0x1D: 'Brazil OBD Phase 2 (OBDBr-2)',
        0x1E: 'Korean OBD (KOBD)',
        0x1F: 'India OBD I (IOBD I)',
        0x20: 'India OBD II (IOBD II)',
        0x21: 'Heavy Duty Euro OBD Stage VI (HD EOBD-IV)',
    }

    fields_desc = [
        XByteEnumField('data', b'', obdStandards)
    ]


class Pid1D_S1AndS2(Packet):
    name = "PID_1D_OxygenSensorsPresent"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid1E_S1AndS2(Packet):
    name = "PID_1E_AuxiliaryInputStatus"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid1F_S1AndS2(Packet):
    name = "PID_1F_RunTimeSinceEngineStart"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


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


class Pid40_S1AndS2(Packet):
    name = "PID_40_PidsSupported"
    fields_desc = [
        FlagsField('supportedPids', b'', 32, [
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


class Pid41_S1AndS2(Packet):
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

        BitField('reserved', b'', 1),
        BitEnumField('componentsCompleteness', b'', 1, completeness),
        BitEnumField('fuelSystemCompleteness', b'', 1, completeness),
        BitEnumField('misfireCompleteness', b'', 1, completeness),

        BitEnumField('componentsAvailability', b'', 1, availability),
        BitEnumField('ignitionType', b'', 1, ignitionTypes),
        BitEnumField('fuelSystemAvailability', b'', 1, availability),
        BitEnumField('misfireAvailability', b'', 1, availability),

        # Spark
        # Availability
        ConditionalField(BitEnumField('egrSystemAvailability', b'', 1, availability), isspark),
        ConditionalField(BitEnumField('oxygenSensorHeaterAvailability', b'', 1, availability), isspark),
        ConditionalField(BitEnumField('oxygenSensorAvailability', b'', 1, availability), isspark),
        ConditionalField(BitEnumField('acRefrigerantAvailability', b'', 1, availability), isspark),
        ConditionalField(BitEnumField('secondaryAirSystemAvailability', b'', 1, availability), isspark),
        ConditionalField(BitEnumField('evaporativeSystemAvailability', b'', 1, availability), isspark),
        ConditionalField(BitEnumField('heatedCatalystAvailability', b'', 1, availability), isspark),
        ConditionalField(BitEnumField('catalystAvailability', b'', 1, availability), isspark),

        # Completeness
        ConditionalField(BitEnumField('egrSystemCompleteness', b'', 1, completeness), isspark),
        ConditionalField(BitEnumField('oxygenSensorHeaterCompleteness', b'', 1, completeness), isspark),
        ConditionalField(BitEnumField('oxygenSensorCompleteness', b'', 1, completeness), isspark),
        ConditionalField(BitEnumField('acRefrigerantCompleteness', b'', 1, completeness), isspark),
        ConditionalField(BitEnumField('secondaryAirSystemCompleteness', b'', 1, completeness), isspark),
        ConditionalField(BitEnumField('evaporativeSystemCompleteness', b'', 1, completeness), isspark),
        ConditionalField(BitEnumField('heatedCatalystCompleteness', b'', 1, completeness), isspark),
        ConditionalField(BitEnumField('catalystCompleteness', b'', 1, completeness), isspark),

        # Compression
        # Availability
        ConditionalField(BitEnumField('egrVvtSystemAvailability', b'', 1, availability), iscompression),
        ConditionalField(BitEnumField('pmFilterMonitoringAvailability', b'', 1, availability), iscompression),
        ConditionalField(BitEnumField('exhaustGasSensorAvailability', b'', 1, availability), iscompression),
        ConditionalField(BitEnumField('Reserved1', b'', 1, availability), iscompression),
        ConditionalField(BitEnumField('boostPressureAvailability', b'', 1, availability), iscompression),
        ConditionalField(BitEnumField('Reserved2', b'', 1, availability), iscompression),
        ConditionalField(BitEnumField('noxScrMonitorAvailability', b'', 1, availability), iscompression),
        ConditionalField(BitEnumField('nmhcCatalystAvailability', b'', 1, availability), iscompression),

        # Completeness
        ConditionalField(BitEnumField('egrVvtSystemCompleteness', b'', 1, completeness), iscompression),
        ConditionalField(BitEnumField('pmFilterMonitoringCompleteness', b'', 1, completeness), iscompression),
        ConditionalField(BitEnumField('exhaustGasSensorCompleteness', b'', 1, completeness), iscompression),
        ConditionalField(BitEnumField('Reserved1', b'', 1, completeness), iscompression),
        ConditionalField(BitEnumField('boostPressureCompleteness', b'', 1, completeness), iscompression),
        ConditionalField(BitEnumField('Reserved2', b'', 1, completeness), iscompression),
        ConditionalField(BitEnumField('noxScrMonitorCompleteness', b'', 1, completeness), iscompression),
        ConditionalField(BitEnumField('nmhcCatalystCompleteness', b'', 1, completeness), iscompression),
    ]


class Pid42_S1AndS2(Packet):
    name = "PID_42_ControlModuleVoltage"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid43_S1AndS2(Packet):
    name = "PID_43_AbsoluteLoadValue"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid44_S1AndS2(Packet):
    name = "PID_44_FuelAirCommandedEquivalenceRatio"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid45_S1AndS2(Packet):
    name = "PID_45_RelativeThrottlePosition"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid46_S1AndS2(Packet):
    name = "PID_46_AmbientAirTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid47_S1AndS2(Packet):
    name = "PID_47_AbsoluteThrottlePositionB"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid48_S1AndS2(Packet):
    name = "PID_48_AbsoluteThrottlePositionC"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid49_S1AndS2(Packet):
    name = "PID_49_AcceleratorPedalPositionD"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid4A_S1AndS2(Packet):
    name = "PID_4A_AcceleratorPedalPositionE"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid4B_S1AndS2(Packet):
    name = "PID_4B_AcceleratorPedalPositionF"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid4C_S1AndS2(Packet):
    name = "PID_4C_CommandedThrottleActuator"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid4D_S1AndS2(Packet):
    name = "PID_4D_TimeRunWithMilOn"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid4E_S1AndS2(Packet):
    name = "PID_4E_TimeSinceTroubleCodesCleared"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid4F_S1AndS2(Packet):
    name = "PID_4F_VariousMaxValues"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid50_S1AndS2(Packet):
    name = "PID_50_MaximumValueForAirFlowRateFromMassAirFlowSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class Pid51_S1AndS2(Packet):
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
        ByteEnumField('data', b'', fuelTypes)
    ]


class Pid52_S1AndS2(Packet):
    name = "PID_52_EthanolFuel"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid53_S1AndS2(Packet):
    name = "PID_53_AbsoluteEvapSystemVaporPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid54_S1AndS2(Packet):
    name = "PID_54_EvapSystemVaporPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid55_S1AndS2(Packet):
    name = "PID_55_ShortTermSecondaryOxygenSensorTrimABank1BBank3"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid56_S1AndS2(Packet):
    name = "PID_56_LongTermSecondaryOxygenSensorTrimABank1BBank3"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid57_S1AndS2(Packet):
    name = "PID_57_ShortTermSecondaryOxygenSensorTrimABank2BBank4"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid58_S1AndS2(Packet):
    name = "PID_58_LongTermSecondaryOxygenSensorTrimABank2BBank4"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid59_S1AndS2(Packet):
    name = "PID_59_FuelRailAbsolutePressure"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid5A_S1AndS2(Packet):
    name = "PID_5A_RelativeAcceleratorPedalPosition"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid5B_S1AndS2(Packet):
    name = "PID_5B_HybridBatteryPackRemainingLife"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid5C_S1AndS2(Packet):
    name = "PID_5C_EngineOilTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid5D_S1AndS2(Packet):
    name = "PID_5D_FuelInjectionTiming"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid5E_S1AndS2(Packet):
    name = "PID_5E_EngineFuelRate"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class Pid5F_S1AndS2(Packet):
    name = "PID_5F_EmissionRequirementsToWhichVehicleIsDesigned"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class Pid60_S1AndS2(Packet):
    name = "PID_60_PidsSupported"
    fields_desc = [
        FlagsField('supportedPids', b'', 32, [
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
        BitField('reserved', b'', 4),
        FlagsField('supportedSensors', b'', 4, ['Sensor1', 'Sensor2', 'Sensor3', 'Sensor4']),
        XShortField('temperature1', b''),
        XShortField('temperature2', b''),
        XShortField('temperature3', b''),
        XShortField('temperature4', b'')
    ]


class Pid79_S1AndS2(Packet):
    name = "PID_79_ExhaustGasTemperatureBank2"
    fields_desc = [
        BitField('reserved', b'', 4),
        FlagsField('supportedSensors', b'', 4, ['Sensor1', 'Sensor2', 'Sensor3', 'Sensor4']),
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


class PidA0_S1AndS2(Packet):
    name = "PID_A0_PidsSupported"
    fields_desc = [
        FlagsField('supportedPids', b'', 32, [
            'PidC0',
            'PidBF',
            'PidBE',
            'PidBD',
            'PidBC',
            'PidBB',
            'PidBA',
            'PidB9',
            'PidB8',
            'PidB7',
            'PidB6',
            'PidB5',
            'PidB4',
            'PidB3',
            'PidB2',
            'PidB1',
            'PidB0',
            'PidAF',
            'PidAE',
            'PidAD',
            'PidAC',
            'PidAB',
            'PidAA',
            'PidA9',
            'PidA8',
            'PidA7',
            'PidA6',
            'PidA5',
            'PidA4',
            'PidA3',
            'PidA2',
            'PidA1'
        ])
    ]


class PidA1_S1AndS2(Packet):
    name = "PID_A1_NoxSensorCorrectedData"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class PidA2_S1AndS2(Packet):
    name = "PID_A2_CylinderFuelRate"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class PidA3_S1AndS2(Packet):
    name = "PID_A3_EvapSystemVaporPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class PidA4_S1AndS2(Packet):
    name = "PID_A4_TransmissionActualGear"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class PidA5_S1AndS2(Packet):
    name = "PID_A5_DieselExhaustFluidDosing"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class PidA6_S1AndS2(Packet):
    name = "PID_A6_Odometer"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class PidC0_S1AndS2(Packet):
    name = "PID_C0_PidsSupported"
    fields_desc = [
        FlagsField('supportedPids', b'', 32, [
            'PidE0',
            'PidDF',
            'PidDE',
            'PidDD',
            'PidDC',
            'PidDB',
            'PidDA',
            'PidD9',
            'PidD8',
            'PidD7',
            'PidD6',
            'PidD5',
            'PidD4',
            'PidD3',
            'PidD2',
            'PidD1',
            'PidD0',
            'PidCF',
            'PidCE',
            'PidCD',
            'PidCC',
            'PidCB',
            'PidCA',
            'PidC9',
            'PidC8',
            'PidC7',
            'PidC6',
            'PidC5',
            'PidC4',
            'PidC3',
            'PidC2',
            'PidC1'
        ])
    ]
