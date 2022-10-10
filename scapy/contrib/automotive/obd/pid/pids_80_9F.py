# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.status = skip

from scapy.fields import StrFixedLenField, FlagsField, ScalingField, BitField
from scapy.contrib.automotive.obd.packet import OBD_Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class OBD_PID80(OBD_Packet):
    name = "PID_80_PIDsSupported"
    fields_desc = [
        FlagsField('supported_pids', 0, 32, [
            'PIDA0',
            'PID9F',
            'PID9E',
            'PID9D',
            'PID9C',
            'PID9B',
            'PID9A',
            'PID99',
            'PID98',
            'PID97',
            'PID96',
            'PID95',
            'PID94',
            'PID93',
            'PID92',
            'PID91',
            'PID90',
            'PID8F',
            'PID8E',
            'PID8D',
            'PID8C',
            'PID8B',
            'PID8A',
            'PID89',
            'PID88',
            'PID87',
            'PID86',
            'PID85',
            'PID84',
            'PID83',
            'PID82',
            'PID81'
        ])
    ]


class OBD_PID81(OBD_Packet):
    name = "PID_81_EngineRunTimeForAuxiliaryEmissionsControlDevice"
    fields_desc = [
        BitField('reserved', 0, 3),
        BitField('total_run_time_with_ei_aecd5_supported', 0, 1),
        BitField('total_run_time_with_ei_aecd4_supported', 0, 1),
        BitField('total_run_time_with_ei_aecd3_supported', 0, 1),
        BitField('total_run_time_with_ei_aecd2_supported', 0, 1),
        BitField('total_run_time_with_ei_aecd1_supported', 0, 1),
        ScalingField('total_run_time_with_ei_aecd1', 0, unit='sec',
                     fmt='Q'),
        ScalingField('total_run_time_with_ei_aecd2', 0, unit='sec',
                     fmt='Q'),
        ScalingField('total_run_time_with_ei_aecd3', 0, unit='sec',
                     fmt='Q'),
        ScalingField('total_run_time_with_ei_aecd4', 0, unit='sec',
                     fmt='Q'),
        ScalingField('total_run_time_with_ei_aecd5', 0, unit='sec',
                     fmt='Q'),
    ]


class OBD_PID82(OBD_Packet):
    name = "PID_82_EngineRunTimeForAuxiliaryEmissionsControlDevice"
    fields_desc = [
        BitField('reserved', 0, 3),
        BitField('total_run_time_with_ei_aecd10_supported', 0, 1),
        BitField('total_run_time_with_ei_aecd9_supported', 0, 1),
        BitField('total_run_time_with_ei_aecd8_supported', 0, 1),
        BitField('total_run_time_with_ei_aecd7_supported', 0, 1),
        BitField('total_run_time_with_ei_aecd6_supported', 0, 1),
        ScalingField('total_run_time_with_ei_aecd6', 0, unit='sec',
                     fmt='Q'),
        ScalingField('total_run_time_with_ei_aecd7', 0, unit='sec',
                     fmt='Q'),
        ScalingField('total_run_time_with_ei_aecd8', 0, unit='sec',
                     fmt='Q'),
        ScalingField('total_run_time_with_ei_aecd9', 0, unit='sec',
                     fmt='Q'),
        ScalingField('total_run_time_with_ei_aecd10', 0, unit='sec',
                     fmt='Q'),
    ]


class OBD_PID83(OBD_Packet):
    name = "PID_83_NOxSensor"
    fields_desc = [
        BitField('reserved', 0, 6),
        BitField('nox_sensor_concentration_bank2_sensor1_supported', 0, 1),
        BitField('nox_sensor_concentration_bank1_sensor1_supported', 0, 1),
        ScalingField('nox_sensor_concentration_bank1_sensor1', 0, unit='ppm',
                     fmt='H'),
        ScalingField('nox_sensor_concentration_bank2_sensor1', 0, unit='ppm',
                     fmt='H'),
    ]


class OBD_PID84(OBD_Packet):
    name = "PID_84_ManifoldSurfaceTemperature"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID85(OBD_Packet):
    name = "PID_85_NoxReagentSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 10)
    ]


class OBD_PID86(OBD_Packet):
    name = "PID_86_ParticulateMatterSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID87(OBD_Packet):
    name = "PID_87_IntakeManifoldAbsolutePressure"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID88(OBD_Packet):
    name = "PID_88_ScrInduceSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 13)
    ]


class OBD_PID89(OBD_Packet):
    # 11 - 15
    name = "PID_89_RunTimeForAecd"
    fields_desc = [
        StrFixedLenField('data', b'', 41)
    ]


class OBD_PID8A(OBD_Packet):
    # 16 - 20
    name = "PID_8A_RunTimeForAecd"
    fields_desc = [
        StrFixedLenField('data', b'', 41)
    ]


class OBD_PID8B(OBD_Packet):
    name = "PID_8B_DieselAftertreatment"
    fields_desc = [
        StrFixedLenField('data', b'', 7)
    ]


class OBD_PID8C(OBD_Packet):
    name = "PID_8C_O2Sensor"
    fields_desc = [
        StrFixedLenField('data', b'', 16)
    ]


class OBD_PID8D(OBD_Packet):
    name = "PID_8D_ThrottlePositionG"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID8E(OBD_Packet):
    name = "PID_8E_EngineFrictionPercentTorque"
    fields_desc = [
        StrFixedLenField('data', b'', 1)
    ]


class OBD_PID8F(OBD_Packet):
    name = "PID_8F_PmSensorBank1And2"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID90(OBD_Packet):
    name = "PID_90_WwhObdVehicleObdSystemInformation"
    fields_desc = [
        StrFixedLenField('data', b'', 3)
    ]


class OBD_PID91(OBD_Packet):
    name = "PID_91_WwhObdVehicleObdSystemInformation"
    fields_desc = [
        StrFixedLenField('data', b'', 5)
    ]


class OBD_PID92(OBD_Packet):
    name = "PID_92_FuelSystemControl"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID93(OBD_Packet):
    name = "PID_93_WwhObdVehicleObdCountersSupport"
    fields_desc = [
        StrFixedLenField('data', b'', 3)
    ]


class OBD_PID94(OBD_Packet):
    name = "PID_94_NoxWarningAndInducementSystem"
    fields_desc = [
        StrFixedLenField('data', b'', 12)
    ]


class OBD_PID98(OBD_Packet):
    name = "PID_98_ExhaustGasTemperatureSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class OBD_PID99(OBD_Packet):
    name = "PID_99_ExhaustGasTemperatureSensor"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class OBD_PID9A(OBD_Packet):
    name = "PID_9A_HybridEvVehicleSystemDataBatteryVoltage"
    fields_desc = [
        StrFixedLenField('data', b'', 6)
    ]


class OBD_PID9B(OBD_Packet):
    name = "PID_9B_DieselExhaustFluidSensorData"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID9C(OBD_Packet):
    name = "PID_9C_O2SensorData"
    fields_desc = [
        StrFixedLenField('data', b'', 17)
    ]


class OBD_PID9D(OBD_Packet):
    name = "PID_9D_EngineFuelRate"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PID9E(OBD_Packet):
    name = "PID_9E_EngineExhaustFlowRate"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PID9F(OBD_Packet):
    name = "PID_9F_FuelSystemPercentageUse"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]
