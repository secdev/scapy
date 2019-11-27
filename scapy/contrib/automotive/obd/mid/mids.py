# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.status = skip

from scapy.fields import FlagsField, ScalingField, ByteEnumField, \
    MultipleTypeField, ShortField, ShortEnumField, PacketListField
from scapy.packet import Packet, bind_layers
from scapy.contrib.automotive.obd.packet import OBD_Packet
from scapy.contrib.automotive.obd.services import OBD_S06


def _unit_and_scaling_fields(name):
    return [
        (ScalingField(name, 0, fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x1),
        (ScalingField(name, 0, scaling=0.1, fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x2),
        (ScalingField(name, 0, scaling=0.01, fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x3),
        (ScalingField(name, 0, scaling=0.001, fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x4),
        (ScalingField(name, 0, scaling=0.0000305, fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x5),
        (ScalingField(name, 0, scaling=0.000305, fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x6),
        (ScalingField(name, 0, scaling=0.25, unit="rpm", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x7),
        (ScalingField(name, 0, scaling=0.01, unit="km/h", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x8),
        (ScalingField(name, 0, unit="km/h", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x9),
        (ScalingField(name, 0, scaling=0.122, unit="mV", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0xA),
        (ScalingField(name, 0, scaling=0.001, unit="V", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0xB),
        (ScalingField(name, 0, scaling=0.01, unit="V", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0xC),
        (ScalingField(name, 0, scaling=0.00390625, unit="mA", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0xD),
        (ScalingField(name, 0, scaling=0.001, unit="A", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0xE),
        (ScalingField(name, 0, scaling=0.01, unit="A", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0xF),
        (ScalingField(name, 0, unit="ms", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x10),
        (ScalingField(name, 0, scaling=100, unit="ms", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x11),
        (ScalingField(name, 0, scaling=1, unit="s", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x12),
        (ScalingField(name, 0, scaling=1, unit="mOhm", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x13),
        (ScalingField(name, 0, scaling=1, unit="Ohm", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x14),
        (ScalingField(name, 0, scaling=1, unit="kOhm", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x15),
        (ScalingField(name, -40, scaling=0.1, unit="deg. C",
                      offset=-40, fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x16),
        (ScalingField(name, 0, scaling=0.01, unit="kPa", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x17),
        (ScalingField(name, 0, scaling=0.0117, unit="kPa", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x18),
        (ScalingField(name, 0, scaling=0.079, unit="kPa", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x19),
        (ScalingField(name, 0, scaling=1, unit="kPa", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x1A),
        (ScalingField(name, 0, scaling=10, unit="kPa", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x1B),
        (ScalingField(name, 0, scaling=0.01, unit="deg.", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x1C),
        (ScalingField(name, 0, scaling=0.5, unit="deg.", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x1D),
        (ScalingField(name, 0, scaling=0.0000305, fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x1E),
        (ScalingField(name, 0, scaling=0.05, fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x1F),
        (ScalingField(name, 0, scaling=0.0039062, fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x20),
        (ScalingField(name, 0, scaling=1, unit="mHz", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x21),
        (ScalingField(name, 0, scaling=1, unit="Hz", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x22),
        (ScalingField(name, 0, scaling=1, unit="KHz", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x23),
        (ScalingField(name, 0, scaling=1, unit="counts", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x24),
        (ScalingField(name, 0, scaling=1, unit="km", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x25),
        (ScalingField(name, 0, scaling=0.1, unit="mV/ms", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x26),
        (ScalingField(name, 0, scaling=0.01, unit="g/s", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x27),
        (ScalingField(name, 0, scaling=1, unit="g/s", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x28),
        (ScalingField(name, 0, scaling=0.25, unit="Pa/s", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x29),
        (ScalingField(name, 0, scaling=0.001, unit="kg/h", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x2A),
        (ScalingField(name, 0, scaling=1, unit="switches", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x2B),
        (ScalingField(name, 0, scaling=0.01, unit="g/cyl", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x2C),
        (ScalingField(name, 0, scaling=0.01, unit="mg/stroke", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x2D),
        (ShortEnumField(name, 0, {0: "false", 1: "true"}),
         lambda pkt: pkt.unit_and_scaling_id == 0x2E),
        (ScalingField(name, 0, scaling=0.01, unit="%", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x2F),
        (ScalingField(name, 0, scaling=0.001526, unit="%", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x30),
        (ScalingField(name, 0, scaling=0.001, unit="L", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x31),
        (ScalingField(name, 0, scaling=0.0000305, unit="inch", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x32),
        (ScalingField(name, 0, scaling=0.00024414, fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x33),
        (ScalingField(name, 0, scaling=1, unit="min", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x34),
        (ScalingField(name, 0, scaling=10, unit="ms", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x35),
        (ScalingField(name, 0, scaling=0.01, unit="g", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x36),
        (ScalingField(name, 0, scaling=0.1, unit="g", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x37),
        (ScalingField(name, 0, scaling=1, unit="g", fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x38),
        (ScalingField(name, 0, scaling=0.01, unit="%", offset=-327.68,
                      fmt='H'),
         lambda pkt: pkt.unit_and_scaling_id == 0x39),
        (ScalingField(name, 0, scaling=1, fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x81),
        (ScalingField(name, 0, scaling=0.1, fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x82),
        (ScalingField(name, 0, scaling=0.01, fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x83),
        (ScalingField(name, 0, scaling=0.001, fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x84),
        (ScalingField(name, 0, scaling=0.0000305, fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x85),
        (ScalingField(name, 0, scaling=0.000305, fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x86),
        (ScalingField(name, 0, scaling=0.122, unit="mV", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x8A),
        (ScalingField(name, 0, scaling=0.001, unit="V", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x8B),
        (ScalingField(name, 0, scaling=0.01, unit="V", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x8C),
        (ScalingField(name, 0, scaling=0.00390625, unit="mA", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x8D),
        (ScalingField(name, 0, scaling=0.001, unit="A", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x8E),
        (ScalingField(name, 0, scaling=1, unit="ms", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x90),
        (ScalingField(name, 0, scaling=0.1, unit="deg. C", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x96),
        (ScalingField(name, 0, scaling=0.01, unit="deg.", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x9C),
        (ScalingField(name, 0, scaling=0.5, unit="deg.", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0x9D),
        (ScalingField(name, 0, scaling=1, unit="g/s", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0xA8),
        (ScalingField(name, 0, scaling=0.25, unit="Pa/s", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0xA9),
        (ScalingField(name, 0, scaling=0.01, unit="%", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0xAF),
        (ScalingField(name, 0, scaling=0.003052, unit="%", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0xB0),
        (ScalingField(name, 0, scaling=2, unit="mV/s", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0xB1),
        (ScalingField(name, 0, scaling=0.001, unit="kPa", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0xFD),
        (ScalingField(name, 0, scaling=0.25, unit="Pa", fmt='h'),
         lambda pkt: pkt.unit_and_scaling_id == 0xFE)
    ]


def _mid_flags(basemid):
    return [
        'MID%02X' % (basemid + 0x20),
        'MID%02X' % (basemid + 0x1F),
        'MID%02X' % (basemid + 0x1E),
        'MID%02X' % (basemid + 0x1D),
        'MID%02X' % (basemid + 0x1C),
        'MID%02X' % (basemid + 0x1B),
        'MID%02X' % (basemid + 0x1A),
        'MID%02X' % (basemid + 0x19),
        'MID%02X' % (basemid + 0x18),
        'MID%02X' % (basemid + 0x17),
        'MID%02X' % (basemid + 0x16),
        'MID%02X' % (basemid + 0x15),
        'MID%02X' % (basemid + 0x14),
        'MID%02X' % (basemid + 0x13),
        'MID%02X' % (basemid + 0x12),
        'MID%02X' % (basemid + 0x11),
        'MID%02X' % (basemid + 0x10),
        'MID%02X' % (basemid + 0x0F),
        'MID%02X' % (basemid + 0x0E),
        'MID%02X' % (basemid + 0x0D),
        'MID%02X' % (basemid + 0x0C),
        'MID%02X' % (basemid + 0x0B),
        'MID%02X' % (basemid + 0x0A),
        'MID%02X' % (basemid + 0x09),
        'MID%02X' % (basemid + 0x08),
        'MID%02X' % (basemid + 0x07),
        'MID%02X' % (basemid + 0x06),
        'MID%02X' % (basemid + 0x05),
        'MID%02X' % (basemid + 0x04),
        'MID%02X' % (basemid + 0x03),
        'MID%02X' % (basemid + 0x02),
        'MID%02X' % (basemid + 0x01)
    ]


class OBD_MIDXX(OBD_Packet):
    standardized_test_ids = {
        1: "TID_01_RichToLeanSensorThresholdVoltage",
        2: "TID_02_LeanToRichSensorThresholdVoltage",
        3: "TID_03_LowSensorVoltageForSwitchTimeCalculation",
        4: "TID_04_HighSensorVoltageForSwitchTimeCalculation",
        5: "TID_05_RichToLeanSensorSwitchTime",
        6: "TID_06_LeanToRichSensorSwitchTime",
        7: "TID_07_MinimumSensorVoltageForTestCycle",
        8: "TID_08_MaximumSensorVoltageForTestCycle",
        9: "TID_09_TimeBetweenSensorTransitions",
        10: "TID_0A_SensorPeriod"}
    unit_and_scaling_ids = {
        0x01: "Raw Value",
        0x02: "Raw Value",
        0x03: "Raw Value",
        0x04: "Raw Value",
        0x05: "Raw Value",
        0x06: "Raw Value",
        0x07: "rotational frequency",
        0x08: "Speed",
        0x09: "Speed",
        0x0A: "Voltage",
        0x0B: "Voltage",
        0x0C: "Voltage",
        0x0D: "Current",
        0x0E: "Current",
        0x0F: "Current",
        0x10: "Time",
        0x11: "Time",
        0x12: "Time",
        0x13: "Resistance",
        0x14: "Resistance",
        0x15: "Resistance",
        0x16: "Temperature",
        0x17: "Pressure (Gauge)",
        0x18: "Pressure (Air pressure)",
        0x19: "Pressure (Fuel pressure)",
        0x1A: "Pressure (Gauge)",
        0x1B: "Pressure (Diesel pressure)",
        0x1C: "Angle",
        0x1D: "Angle",
        0x1E: "Equivalence ratio (lambda)",
        0x1F: "Air/Fuel ratio",
        0x20: "Ratio",
        0x21: "Frequency",
        0x22: "Frequency",
        0x23: "Frequency",
        0x24: "Counts",
        0x25: "Distance",
        0x26: "Voltage per time",
        0x27: "Mass per time",
        0x28: "Mass per time",
        0x29: "Pressure per time",
        0x2A: "Mass per time",
        0x2B: "Switches",
        0x2C: "Mass per cylinder",
        0x2D: "Mass per stroke",
        0x2E: "True/False",
        0x2F: "Percent",
        0x30: "Percent",
        0x31: "volume",
        0x32: "length",
        0x33: "Equivalence ratio (lambda)",
        0x34: "Time",
        0x35: "Time",
        0x36: "Weight",
        0x37: "Weight",
        0x38: "Weight",
        0x39: "Percent",
        0x81: "Raw Value",
        0x82: "Raw Value",
        0x83: "Raw Value",
        0x84: "Raw Value",
        0x85: "Raw Value",
        0x86: "Raw Value",
        0x8A: "Voltage",
        0x8B: "Voltage",
        0x8C: "Voltage",
        0x8D: "Current",
        0x8E: "Current",
        0x90: "Time",
        0x96: "Temperature",
        0x9C: "Angle",
        0x9D: "Angle",
        0xA8: "Mass per time",
        0xA9: "Pressure per time",
        0xAF: "Percent",
        0xB0: "Percent",
        0xB1: "Voltage per time",
        0xFD: "Pressure",
        0xFE: "Pressure"
    }

    name = "OBD MID data record"
    fields_desc = [
        ByteEnumField("standardized_test_id", 1, standardized_test_ids),
        ByteEnumField("unit_and_scaling_id", 1, unit_and_scaling_ids),
        MultipleTypeField(_unit_and_scaling_fields("test_value"),
                          ShortField("test_value", 0)),
        MultipleTypeField(_unit_and_scaling_fields("min_limit"),
                          ShortField("min_limit", 0)),
        MultipleTypeField(_unit_and_scaling_fields("max_limit"),
                          ShortField("max_limit", 0)),
    ]


class OBD_MID00(OBD_Packet):
    fields_desc = [
        FlagsField('supported_mids', 0, 32, _mid_flags(0x00)),
    ]


class OBD_MID20(OBD_Packet):
    fields_desc = [
        FlagsField('supported_mids', 0, 32, _mid_flags(0x20)),
    ]


class OBD_MID40(OBD_Packet):
    fields_desc = [
        FlagsField('supported_mids', 0, 32, _mid_flags(0x40)),
    ]


class OBD_MID60(OBD_Packet):
    fields_desc = [
        FlagsField('supported_mids', 0, 32, _mid_flags(0x60)),
    ]


class OBD_MID80(OBD_Packet):
    fields_desc = [
        FlagsField('supported_mids', 0, 32, _mid_flags(0x80)),
    ]


class OBD_MIDA0(OBD_Packet):
    fields_desc = [
        FlagsField('supported_mids', 0, 32, _mid_flags(0xA0)),
    ]


class OBD_S06_PR_Record(Packet):
    on_board_monitoring_ids = {
        0x00: "OBD Monitor IDs supported ($01 - $20)",
        0x01: "Oxygen Sensor Monitor Bank 1 - Sensor 1",
        0x02: "Oxygen Sensor Monitor Bank 1 - Sensor 2",
        0x03: "Oxygen Sensor Monitor Bank 1 - Sensor 3",
        0x04: "Oxygen Sensor Monitor Bank 1 - Sensor 4",
        0x05: "Oxygen Sensor Monitor Bank 2 - Sensor 1",
        0x06: "Oxygen Sensor Monitor Bank 2 - Sensor 2",
        0x07: "Oxygen Sensor Monitor Bank 2 - Sensor 3",
        0x08: "Oxygen Sensor Monitor Bank 2 - Sensor 4",
        0x09: "Oxygen Sensor Monitor Bank 3 - Sensor 1",
        0x0A: "Oxygen Sensor Monitor Bank 3 - Sensor 2",
        0x0B: "Oxygen Sensor Monitor Bank 3 - Sensor 3",
        0x0C: "Oxygen Sensor Monitor Bank 3 - Sensor 4",
        0x0D: "Oxygen Sensor Monitor Bank 4 - Sensor 1",
        0x0E: "Oxygen Sensor Monitor Bank 4 - Sensor 2",
        0x0F: "Oxygen Sensor Monitor Bank 4 - Sensor 3",
        0x10: "Oxygen Sensor Monitor Bank 4 - Sensor 4",
        0x20: "OBD Monitor IDs supported ($21 - $40)",
        0x21: "Catalyst Monitor Bank 1",
        0x22: "Catalyst Monitor Bank 2",
        0x23: "Catalyst Monitor Bank 3",
        0x24: "Catalyst Monitor Bank 4",
        0x32: "EGR Monitor Bank 2",
        0x33: "EGR Monitor Bank 3",
        0x34: "EGR Monitor Bank 4",
        0x35: "VVT Monitor Bank 1",
        0x36: "VVT Monitor Bank 2",
        0x37: "VVT Monitor Bank 3",
        0x38: "VVT Monitor Bank 4",
        0x39: "EVAP Monitor (Cap Off / 0.150\")",
        0x3A: "EVAP Monitor (0.090\")",
        0x3B: "EVAP Monitor (0.040\")",
        0x3C: "EVAP Monitor (0.020\")",
        0x3D: "Purge Flow Monitor",
        0x40: "OBD Monitor IDs supported ($41 - $60)",
        0x41: "Oxygen Sensor Heater Monitor Bank 1 - Sensor 1",
        0x42: "Oxygen Sensor Heater Monitor Bank 1 - Sensor 2",
        0x43: "Oxygen Sensor Heater Monitor Bank 1 - Sensor 3",
        0x44: "Oxygen Sensor Heater Monitor Bank 1 - Sensor 4",
        0x45: "Oxygen Sensor Heater Monitor Bank 2 - Sensor 1",
        0x46: "Oxygen Sensor Heater Monitor Bank 2 - Sensor 2",
        0x47: "Oxygen Sensor Heater Monitor Bank 2 - Sensor 3",
        0x48: "Oxygen Sensor Heater Monitor Bank 2 - Sensor 4",
        0x49: "Oxygen Sensor Heater Monitor Bank 3 - Sensor 1",
        0x4A: "Oxygen Sensor Heater Monitor Bank 3 - Sensor 2",
        0x4B: "Oxygen Sensor Heater Monitor Bank 3 - Sensor 3",
        0x4C: "Oxygen Sensor Heater Monitor Bank 3 - Sensor 4",
        0x4D: "Oxygen Sensor Heater Monitor Bank 4 - Sensor 1",
        0x4E: "Oxygen Sensor Heater Monitor Bank 4 - Sensor 2",
        0x4F: "Oxygen Sensor Heater Monitor Bank 4 - Sensor 3",
        0x50: "Oxygen Sensor Heater Monitor Bank 4 - Sensor 4",
        0x60: "OBD Monitor IDs supported ($61 - $80)",
        0x61: "Heated Catalyst Monitor Bank 1",
        0x62: "Heated Catalyst Monitor Bank 2",
        0x63: "Heated Catalyst Monitor Bank 3",
        0x64: "Heated Catalyst Monitor Bank 4",
        0x71: "Secondary Air Monitor 1",
        0x72: "Secondary Air Monitor 2",
        0x73: "Secondary Air Monitor 3",
        0x74: "Secondary Air Monitor 4",
        0x80: "OBD Monitor IDs supported ($81 - $A0)",
        0x81: "Fuel System Monitor Bank 1",
        0x82: "Fuel System Monitor Bank 2",
        0x83: "Fuel System Monitor Bank 3",
        0x84: "Fuel System Monitor Bank 4",
        0x85: "Boost Pressure Control Monitor Bank 1",
        0x86: "Boost Pressure Control Monitor Bank 2",
        0x90: "NOx Adsorber Monitor Bank 1",
        0x91: "NOx Adsorber Monitor Bank 2",
        0x98: "NOx Catalyst Monitor Bank 1",
        0x99: "NOx Catalyst Monitor Bank 2",
        0xA0: "OBD Monitor IDs supported ($A1 - $C0)",
        0xA1: "Misfire Monitor General Data",
        0xA2: "Misfire Cylinder 1 Data",
        0xA3: "Misfire Cylinder 2 Data",
        0xA4: "Misfire Cylinder 3 Data",
        0xA5: "Misfire Cylinder 4 Data",
        0xA6: "Misfire Cylinder 5 Data",
        0xA7: "Misfire Cylinder 6 Data",
        0xA8: "Misfire Cylinder 7 Data",
        0xA9: "Misfire Cylinder 8 Data",
        0xAA: "Misfire Cylinder 9 Data",
        0xAB: "Misfire Cylinder 10 Data",
        0xAC: "Misfire Cylinder 11 Data",
        0xAD: "Misfire Cylinder 12 Data",
        0xB0: "PM Filter Monitor Bank 1",
        0xB1: "PM Filter Monitor Bank 2"
    }
    name = "On-Board diagnostic monitoring ID"
    fields_desc = [
        ByteEnumField("mid", 0, on_board_monitoring_ids),
    ]


class OBD_S06_PR(Packet):
    name = "On-Board monitoring IDs"
    fields_desc = [
        PacketListField("data_records", [], OBD_S06_PR_Record)
    ]

    def answers(self, other):
        return other.__class__ == OBD_S06 \
            and all(r.mid in other.mid for r in self.data_records)


bind_layers(OBD_S06_PR_Record, OBD_MID00, mid=0x00)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x01)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x02)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x03)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x04)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x05)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x06)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x07)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x08)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x09)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x0A)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x0B)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x0C)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x0D)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x0E)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x0F)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x10)
bind_layers(OBD_S06_PR_Record, OBD_MID20, mid=0x20)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x21)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x22)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x23)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x24)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x32)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x33)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x34)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x35)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x36)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x37)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x38)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x39)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x3A)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x3B)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x3C)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x3D)
bind_layers(OBD_S06_PR_Record, OBD_MID40, mid=0x40)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x41)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x42)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x43)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x44)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x45)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x46)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x47)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x48)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x49)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x4A)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x4B)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x4C)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x4D)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x4E)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x4F)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x50)
bind_layers(OBD_S06_PR_Record, OBD_MID60, mid=0x60)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x61)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x62)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x63)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x64)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x71)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x72)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x73)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x74)
bind_layers(OBD_S06_PR_Record, OBD_MID80, mid=0x80)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x81)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x82)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x83)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x84)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x85)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x86)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x90)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x91)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x98)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0x99)
bind_layers(OBD_S06_PR_Record, OBD_MIDA0, mid=0xA0)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xA1)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xA2)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xA3)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xA4)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xA5)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xA6)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xA7)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xA8)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xA9)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xAA)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xAB)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xAC)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xAD)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xB0)
bind_layers(OBD_S06_PR_Record, OBD_MIDXX, mid=0xB1)
