# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from scapy.fields import StrFixedLenField, BitEnumField, BitField, \
    ScalingField, ConditionalField, FlagsField, XByteEnumField, ShortField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class OBD_PID00(Packet):
    name = "PID_00_PIDsSupported"

    fields_desc = [
        FlagsField('supportedPIDs', b'', 32, [
            'PID20',
            'PID1F',
            'PID1E',
            'PID1D',
            'PID1C',
            'PID1B',
            'PID1A',
            'PID19',
            'PID18',
            'PID17',
            'PID16',
            'PID15',
            'PID14',
            'PID13',
            'PID12',
            'PID11',
            'PID10',
            'PID0F',
            'PID0E',
            'PID0D',
            'PID0C',
            'PID0B',
            'PID0A',
            'PID09',
            'PID08',
            'PID07',
            'PID06',
            'PID05',
            'PID04',
            'PID03',
            'PID02',
            'PID01'
        ])
    ]


class OBD_PID01(Packet):
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
        BitEnumField('MIL', 0, 1, onOff),
        BitField('DTC_Count', 0, 7),

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
        ConditionalField(BitEnumField('egrSystemAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('oxygenSensorHeaterAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('oxygenSensorAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('acRefrigerantAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('secondaryAirSystemAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('evaporativeSystemAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('heatedCatalystAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('catalystAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 0),

        # Completeness
        ConditionalField(BitEnumField('egrSystemCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('oxygenSensorHeaterCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('oxygenSensorCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('acRefrigerantCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('secondaryAirSystemCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('evaporativeSystemCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('heatedCatalystCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 0),
        ConditionalField(BitEnumField('catalystCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 0),

        # Compression
        # Availability
        ConditionalField(BitEnumField('egrVvtSystemAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('pmFilterMonitoringAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('exhaustGasSensorAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('Reserved1', 0, 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('boostPressureAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('Reserved2', 0, 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('noxScrMonitorAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('nmhcCatalystAvailability', 0, 1, availability), lambda pkt: pkt.ignitionType == 1),

        # Completeness
        ConditionalField(BitEnumField('egrVvtSystemCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('pmFilterMonitoringCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('exhaustGasSensorCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('Reserved1', 0, 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('boostPressureCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('Reserved2', 0, 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('noxScrMonitorCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 1),
        ConditionalField(BitEnumField('nmhcCatalystCompleteness', 0, 1, completeness), lambda pkt: pkt.ignitionType == 1),
    ]


class OBD_PID02(Packet):
    name = "PID_02_FreezeDtc"
    fields_desc = [
        ShortField('data', 0)
    ]


class OBD_PID03(Packet):
    name = "PID_03_FuelSystemStatus"

    loopStates = {
        0x00: 'OpenLoopInsufficientEngineTemperature',
        0x02: 'ClosedLoop',
        0x04: 'OpenLoopEngineLoadOrFuelCut',
        0x08: 'OpenLoopDueSystemFailure',
        0x10: 'ClosedLoopWithFault'
    }

    fields_desc = [
        XByteEnumField('fuelSystem1', 0, loopStates),
        XByteEnumField('fuelSystem2', 0, loopStates)
    ]


class OBD_PID04(Packet):
    name = "PID_04_CalculatedEngineLoad"
    fields_desc = [
        ScalingField('data', 0, 100/float(255), "%")
    ]


class OBD_PID05(Packet):
    name = "PID_05_EngineCoolantTemperature"
    fields_desc = [
        ScalingField('data', 0, unit="\xC2\xB0C", offset=-40.0)
    ]


class OBD_PID06(Packet):
    name = "PID_06_ShortTermFuelTrimBank1"
    fields_desc = [
        ScalingField('data', 0, scaling=100/float(128), unit="%", offset=-100.0)
    ]


class OBD_PID07(Packet):
    name = "PID_07_LongTermFuelTrimBank1"
    fields_desc = [
        ScalingField('data', 0, scaling=100/float(128), unit="%", offset=-100.0)
    ]


class OBD_PID08(Packet):
    name = "PID_08_ShortTermFuelTrimBank2"
    fields_desc = [
        ScalingField('data', 0, scaling=100/float(128), unit="%", offset=-100.0)
    ]


class OBD_PID09(Packet):
    name = "PID_09_LongTermFuelTrimBank2"
    fields_desc = [
        ScalingField('data', 0, scaling=100/float(128), unit="%", offset=-100.0)
    ]


class OBD_PID0A(Packet):
    name = "PID_0A_FuelPressure"
    fields_desc = [
        ScalingField('data', 0, scaling=3, unit="kPa")
    ]


class OBD_PID0B(Packet):
    name = "PID_0B_IntakeManifoldAbsolutePressure"
    fields_desc = [
        ScalingField('data', 0, scaling=1, unit="kPa")
    ]


class OBD_PID0C(Packet):
    name = "PID_0C_EngineRpm"
    fields_desc = [
        ScalingField('data', 0, scaling=1/float(4), unit="min-1", fmt="H")
    ]


class OBD_PID0D(Packet):
    name = "PID_0D_VehicleSpeed"
    fields_desc = [
        ScalingField('data', 0, unit="km/h")
    ]


class OBD_PID0E(Packet):
    name = "PID_0E_TimingAdvance"
    fields_desc = [
        ScalingField('data', 0, scaling=1/float(2), unit="\xC2\xB0", offset=-64.0)
    ]


class OBD_PID0F(Packet):
    name = "PID_0F_IntakeAirTemperature"
    fields_desc = [
        ScalingField('data', 0, scaling=1, unit="\xC2\xB0C", offset=-40.0)
    ]


class OBD_PID10(Packet):
    name = "PID_10_MafAirFlowRate"
    fields_desc = [
        ScalingField('data', 0, scaling=1/float(100), unit="g/s")
    ]


class OBD_PID11(Packet):
    name = "PID_11_ThrottlePosition"
    fields_desc = [
        ScalingField('data', 0, scaling=100/float(255), unit="%")
    ]


class OBD_PID12(Packet):
    name = "PID_12_CommandedSecondaryAirStatus"

    states = {
        0x00: 'upstream',
        0x02: 'downstreamCatalyticConverter',
        0x04: 'outsideAtmosphereOrOff',
        0x08: 'pumpCommanded'
    }

    fields_desc = [
        XByteEnumField('data', 0, states)
    ]


class OBD_PID13(Packet):
    name = "PID_13_OxygenSensorsPresent"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]

class _OBD_PID14_1B(Packet):
    fields_desc = [
        ScalingField('outputVoltage', 0, scaling=0.005, unit="V"),
        ScalingField('trim', 0, scaling=100/float(128), unit="%", offset=-100.0)
    ]


class OBD_PID14(_OBD_PID14_1B):
    name = "PID_14_OxygenSensor1"


class OBD_PID15(_OBD_PID14_1B):
    name = "PID_15_OxygenSensor2"


class OBD_PID16(_OBD_PID14_1B):
    name = "PID_16_OxygenSensor3"


class OBD_PID17(_OBD_PID14_1B):
    name = "PID_17_OxygenSensor4"


class OBD_PID18(_OBD_PID14_1B):
    name = "PID_18_OxygenSensor5"


class OBD_PID19(_OBD_PID14_1B):
    name = "PID_19_OxygenSensor6"


class OBD_PID1A(_OBD_PID14_1B):
    name = "PID_1A_OxygenSensor7"


class OBD_PID1B(_OBD_PID14_1B):
    name = "PID_1B_OxygenSensor8"


class OBD_PID1C(Packet):
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
        XByteEnumField('data', 0, obdStandards)
    ]


class OBD_PID1D(Packet):
    name = "PID_1D_OxygenSensorsPresent"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID1E(Packet):
    name = "PID_1E_AuxiliaryInputStatus"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID1F(Packet):
    name = "PID_1F_RunTimeSinceEngineStart"
    fields_desc = [
        ScalingField('data', 0, scaling=1, unit="s", fmt="H")
    ]
