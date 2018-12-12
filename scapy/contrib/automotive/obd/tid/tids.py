# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from scapy.fields import StrFixedLenField, ByteField, ScalingField
from scapy.packet import Packet


class _OBD_TID_Voltage(Packet):
    fields_desc = [
        ScalingField('data_A', 0, 0.005, "V"),
        ScalingField('data_B', 0, 0.005, "V"),
        ScalingField('data_C', 0, 0.005, "V"),
        ScalingField('data_D', 0, 0.005, "V"),
        ScalingField('data_E', 0, 0.005, "V"),
    ]


class _OBD_TID_Time(Packet):
    fields_desc = [
        ScalingField('data_A', 0, 0.004, "s"),
        ScalingField('data_B', 0, 0.004, "s"),
        ScalingField('data_C', 0, 0.004, "s"),
        ScalingField('data_D', 0, 0.004, "s"),
        ScalingField('data_E', 0, 0.004, "s"),
    ]


class _OBD_TID_Period(Packet):
    fields_desc = [
        ScalingField('data_A', 0, 0.04, "s"),
        ScalingField('data_B', 0, 0.04, "s"),
        ScalingField('data_C', 0, 0.04, "s"),
        ScalingField('data_D', 0, 0.04, "s"),
        ScalingField('data_E', 0, 0.04, "s"),
    ]


class OBD_TID00(Packet):
    name = "TID_00_Service8SupportedTestIdentifiers"
    fields_desc = [
        ByteField('reserved', 0),
        StrFixedLenField('data', b'', 4)
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
