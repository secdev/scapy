# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.status = skip

from scapy.fields import FlagsField, ByteField, ScalingField, PacketListField
from scapy.packet import bind_layers, Packet
from scapy.contrib.automotive.obd.packet import OBD_Packet
from scapy.contrib.automotive.obd.services import OBD_S08


class _OBD_TID_Voltage(OBD_Packet):
    fields_desc = [
        ScalingField('data_a', 0, 0.005, "V"),
        ScalingField('data_b', 0, 0.005, "V"),
        ScalingField('data_c', 0, 0.005, "V"),
        ScalingField('data_d', 0, 0.005, "V"),
        ScalingField('data_e', 0, 0.005, "V"),
    ]


class _OBD_TID_Time(OBD_Packet):
    fields_desc = [
        ScalingField('data_a', 0, 0.004, "s"),
        ScalingField('data_b', 0, 0.004, "s"),
        ScalingField('data_c', 0, 0.004, "s"),
        ScalingField('data_d', 0, 0.004, "s"),
        ScalingField('data_e', 0, 0.004, "s"),
    ]


class _OBD_TID_Period(OBD_Packet):
    fields_desc = [
        ScalingField('data_a', 0, 0.04, "s"),
        ScalingField('data_b', 0, 0.04, "s"),
        ScalingField('data_c', 0, 0.04, "s"),
        ScalingField('data_d', 0, 0.04, "s"),
        ScalingField('data_e', 0, 0.04, "s"),
    ]


class OBD_TID00(OBD_Packet):
    name = "TID_00_Service8SupportedTestIdentifiers"
    fields_desc = [
        FlagsField('supported_tids', 0, 32, [
            'TID20',
            'TID1F',
            'TID1E',
            'TID1D',
            'TID1C',
            'TID1B',
            'TID1A',
            'TID19',
            'TID18',
            'TID17',
            'TID16',
            'TID15',
            'TID14',
            'TID13',
            'TID12',
            'TID11',
            'TID10',
            'TID0F',
            'TID0E',
            'TID0D',
            'TID0C',
            'TID0B',
            'TID0A',
            'TID09',
            'TID08',
            'TID07',
            'TID06',
            'TID05',
            'TID04',
            'TID03',
            'TID02',
            'TID01'
        ])
    ]


class OBD_TID01(_OBD_TID_Voltage):
    name = "TID_01_RichToLeanSensorThresholdVoltage"


class OBD_TID02(_OBD_TID_Voltage):
    name = "TID_02_LeanToRichSensorThresholdVoltage"


class OBD_TID03(_OBD_TID_Voltage):
    name = "TID_03_LowSensorVoltageForSwitchTimeCalculation"


class OBD_TID04(_OBD_TID_Voltage):
    name = "TID_04_HighSensorVoltageForSwitchTimeCalculation"


class OBD_TID05(_OBD_TID_Time):
    name = "TID_05_RichToLeanSensorSwitchTime"


class OBD_TID06(_OBD_TID_Time):
    name = "TID_06_LeanToRichSensorSwitchTime"


class OBD_TID07(_OBD_TID_Voltage):
    name = "TID_07_MinimumSensorVoltageForTestCycle"


class OBD_TID08(_OBD_TID_Voltage):
    name = "TID_08_MaximumSensorVoltageForTestCycle"


class OBD_TID09(_OBD_TID_Period):
    name = "TID_09_TimeBetweenSensorTransitions"


class OBD_TID0A(_OBD_TID_Period):
    name = "TID_0A_SensorPeriod"


class OBD_S08_PR_Record(Packet):
    name = "Control Operation ID"
    fields_desc = [
        ByteField("tid", 0),
    ]


class OBD_S08_PR(Packet):
    name = "Control Operation IDs"
    fields_desc = [
        PacketListField("data_records", [], OBD_S08_PR_Record)
    ]

    def answers(self, other):
        return isinstance(other, OBD_S08) \
            and all(r.tid in other.tid for r in self.data_records)


bind_layers(OBD_S08_PR_Record, OBD_TID00, tid=0x00)
bind_layers(OBD_S08_PR_Record, OBD_TID01, tid=0x01)
bind_layers(OBD_S08_PR_Record, OBD_TID02, tid=0x02)
bind_layers(OBD_S08_PR_Record, OBD_TID03, tid=0x03)
bind_layers(OBD_S08_PR_Record, OBD_TID04, tid=0x04)
bind_layers(OBD_S08_PR_Record, OBD_TID05, tid=0x05)
bind_layers(OBD_S08_PR_Record, OBD_TID06, tid=0x06)
bind_layers(OBD_S08_PR_Record, OBD_TID07, tid=0x07)
bind_layers(OBD_S08_PR_Record, OBD_TID08, tid=0x08)
bind_layers(OBD_S08_PR_Record, OBD_TID09, tid=0x09)
bind_layers(OBD_S08_PR_Record, OBD_TID0A, tid=0x0A)
