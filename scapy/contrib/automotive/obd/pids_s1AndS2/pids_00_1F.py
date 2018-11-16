#! /usr/bin/env python

from scapy.fields import StrFixedLenField, BitEnumField, BitField, ConditionalField, FlagsField, \
    XByteEnumField, XByteField
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
