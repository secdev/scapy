# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.status = skip

from scapy.fields import BitField, FlagsField, ScalingField
from scapy.contrib.automotive.obd.packet import OBD_Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification


class OBD_PID60(OBD_Packet):
    name = "PID_60_PIDsSupported"
    fields_desc = [
        FlagsField('supported_pids', 0, 32, [
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


class OBD_PID61(OBD_Packet):
    name = "PID_61_DriverSDemandEnginePercentTorque"
    fields_desc = [
        ScalingField('data', 0, unit="%", offset=-125.0)
    ]


class OBD_PID62(OBD_Packet):
    name = "PID_62_ActualEnginePercentTorque"
    fields_desc = [
        ScalingField('data', 0, unit="%", offset=-125.0)
    ]


class OBD_PID63(OBD_Packet):
    name = "PID_63_EngineReferenceTorque"
    fields_desc = [
        ScalingField('data', 0, unit="Nm", fmt="H")
    ]


class OBD_PID64(OBD_Packet):
    name = "PID_64_EnginePercentTorqueData"
    fields_desc = [
        ScalingField('at_point1', 0, unit="%", offset=-125.0),
        ScalingField('at_point2', 0, unit="%", offset=-125.0),
        ScalingField('at_point3', 0, unit="%", offset=-125.0),
        ScalingField('at_point4', 0, unit="%", offset=-125.0),
        ScalingField('at_point5', 0, unit="%", offset=-125.0)
    ]


class OBD_PID65(OBD_Packet):
    name = "PID_65_AuxiliaryInputOutputSupported"
    fields_desc = [
        BitField('reserved1', 0, 4),
        BitField('glow_plug_lamp_status_supported', 0, 1),
        BitField('manual_trans_neutral_drive_status_supported', 0, 1),
        BitField('auto_trans_neutral_drive_status_supported', 0, 1),
        BitField('power_take_off_status_supported', 0, 1),

        BitField('reserved2', 0, 4),
        BitField('glow_plug_lamp_status', 0, 1),
        BitField('manual_trans_neutral_drive_status', 0, 1),
        BitField('auto_trans_neutral_drive_status', 0, 1),
        BitField('power_take_off_status', 0, 1),
    ]


class OBD_PID66(OBD_Packet):
    name = "PID_66_MassAirFlowSensor"
    fields_desc = [
        BitField('reserved', 0, 6),
        BitField('sensor_b_supported', 0, 1),
        BitField('sensor_a_supported', 0, 1),
        ScalingField('sensor_a', 0, scaling=0.03125, unit="g/s", fmt="H"),
        ScalingField('sensor_b', 0, scaling=0.03125, unit="g/s", fmt="H"),
    ]


class OBD_PID67(OBD_Packet):
    name = "PID_67_EngineCoolantTemperature"
    fields_desc = [
        BitField('reserved', 0, 6),
        BitField('sensor2_supported', 0, 1),
        BitField('sensor1_supported', 0, 1),
        ScalingField('sensor1', 0, unit="deg. C", offset=-40.0),
        ScalingField('sensor2', 0, unit="deg. C", offset=-40.0)
    ]


class OBD_PID68(OBD_Packet):
    name = "PID_68_IntakeAirTemperatureSensor"
    fields_desc = [
        BitField('reserved', 0, 2),
        BitField('bank2_sensor3_supported', 0, 1),
        BitField('bank2_sensor2_supported', 0, 1),
        BitField('bank2_sensor1_supported', 0, 1),
        BitField('bank1_sensor3_supported', 0, 1),
        BitField('bank1_sensor2_supported', 0, 1),
        BitField('bank1_sensor1_supported', 0, 1),
        ScalingField('bank1_sensor1', 0, unit="deg. C", offset=-40),
        ScalingField('bank1_sensor2', 0, unit="deg. C", offset=-40),
        ScalingField('bank1_sensor3', 0, unit="deg. C", offset=-40),
        ScalingField('bank2_sensor1', 0, unit="deg. C", offset=-40),
        ScalingField('bank2_sensor2', 0, unit="deg. C", offset=-40),
        ScalingField('bank2_sensor3', 0, unit="deg. C", offset=-40)
    ]


class OBD_PID69(OBD_Packet):
    name = "PID_69_CommandedEgrAndEgrError"
    fields_desc = [
        BitField('reserved', 0, 2),
        BitField('egr_b_error_supported', 0, 1),
        BitField('actual_egr_b_duty_cycle_supported', 0, 1),
        BitField('commanded_egr_b_duty_cycle_supported', 0, 1),
        BitField('egr_a_error_supported', 0, 1),
        BitField('actual_egr_a_duty_cycle_supported', 0, 1),
        BitField('commanded_egr_a_duty_cycle_supported', 0, 1),
        ScalingField('commanded_egr_a_duty_cycle', 0, scaling=100 / 255.,
                     unit="%"),
        ScalingField('actual_egr_a_duty_cycle', 0, scaling=100 / 255.,
                     unit="%"),
        ScalingField('egr_a_error', 0, scaling=100 / 128., unit="%",
                     offset=-100),
        ScalingField('commanded_egr_b_duty_cycle', 0, scaling=100 / 255.,
                     unit="%"),
        ScalingField('actual_egr_b_duty_cycle', 0, scaling=100 / 255.,
                     unit="%"),
        ScalingField('egr_b_error', 0, scaling=100 / 128., unit="%",
                     offset=-100),
    ]


class OBD_PID6A(OBD_Packet):
    name = "PID_6A_CommandedDieselIntakeAirFlowControl" \
           "AndRelativeIntakeAirFlowPosition"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('relative_intake_air_flow_b_position_supported', 0, 1),
        BitField('commanded_intake_air_flow_b_control_supported', 0, 1),
        BitField('relative_intake_air_flow_a_position_supported', 0, 1),
        BitField('commanded_intake_air_flow_a_control_supported', 0, 1),
        ScalingField('commanded_intake_air_flow_a_control', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('relative_intake_air_flow_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('commanded_intake_air_flow_b_control', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('relative_intake_air_flow_b_position', 0,
                     scaling=100 / 255., unit="%"),
    ]


class OBD_PID6B(OBD_Packet):
    name = "PID_6B_ExhaustGasRecirculationTemperature"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('bank2_sensor2_supported', 0, 1),
        BitField('bank2_sensor1_supported', 0, 1),
        BitField('bank1_sensor2_supported', 0, 1),
        BitField('bank1_sensor1_supported', 0, 1),
        ScalingField('bank1_sensor1', 0, unit="deg. C", offset=-40),
        ScalingField('bank1_sensor2', 0, unit="deg. C", offset=-40),
        ScalingField('bank2_sensor1', 0, unit="deg. C", offset=-40),
        ScalingField('bank2_sensor2', 0, unit="deg. C", offset=-40),
    ]


class OBD_PID6C(OBD_Packet):
    name = "PID_6C_CommandedThrottleActuatorControlAndRelativeThrottlePosition"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('relative_throttle_b_position_supported', 0, 1),
        BitField('commanded_throttle_actuator_b_control_supported', 0, 1),
        BitField('relative_throttle_a_position_supported', 0, 1),
        BitField('commanded_throttle_actuator_a_control_supported', 0, 1),
        ScalingField('commanded_throttle_actuator_a_control', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('relative_throttle_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('commanded_throttle_actuator_b_control', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('relative_throttle_b_position', 0,
                     scaling=100 / 255., unit="%"),
    ]


class OBD_PID6D(OBD_Packet):
    name = "PID_6D_FuelPressureControlSystem"
    fields_desc = [
        BitField('reserved', 0, 5),
        BitField('fuel_temperature_supported', 0, 1),
        BitField('fuel_rail_pressure_supported', 0, 1),
        BitField('commanded_fuel_rail_pressure_supported', 0, 1),
        ScalingField('commanded_fuel_rail_pressure', 0, scaling=10, unit="kPa",
                     fmt='H'),
        ScalingField('fuel_rail_pressure', 0, scaling=10, unit="kPa",
                     fmt='H'),
        ScalingField('fuel_rail_temperature', 0, unit="deg. C", offset=-40)
    ]


class OBD_PID6E(OBD_Packet):
    name = "PID_6E_InjectionPressureControlSystem"
    fields_desc = [
        BitField('reserved', 0, 6),
        BitField('injection_control_pressure_supported', 0, 1),
        BitField('commanded_injection_control_pressure_supported', 0, 1),
        ScalingField('commanded_injection_control_pressure', 0, scaling=10,
                     unit="kPa", fmt='H'),
        ScalingField('injection_control_pressure', 0, scaling=10,
                     unit="kPa", fmt='H'),
    ]


class OBD_PID6F(OBD_Packet):
    name = "PID_6F_TurbochargerCompressorInletPressure"
    fields_desc = [
        BitField('reserved', 0, 6),
        BitField('sensor_b_supported', 0, 1),
        BitField('sensor_a_supported', 0, 1),
        ScalingField('sensor_a', 0, unit="kPa"),
        ScalingField('sensor_b', 0, unit="kPa"),
    ]


class OBD_PID70(OBD_Packet):
    name = "PID_70_BoostPressureControl"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('boost_pressure_sensor_b_supported', 0, 1),
        BitField('commanded_boost_pressure_b_supported', 0, 1),
        BitField('boost_pressure_sensor_a_supported', 0, 1),
        BitField('commanded_boost_pressure_a_supported', 0, 1),
        ScalingField('commanded_boost_pressure_a', 0, scaling=0.03125,
                     unit="kPa", fmt='H'),
        ScalingField('boost_pressure_sensor_a', 0, scaling=0.03125,
                     unit="kPa", fmt='H'),
        ScalingField('commanded_boost_pressure_b', 0, scaling=0.03125,
                     unit="kPa", fmt='H'),
        ScalingField('boost_pressure_sensor_b', 0, scaling=0.03125,
                     unit="kPa", fmt='H'),
    ]


class OBD_PID71(OBD_Packet):
    name = "PID_71_VariableGeometryTurboControl"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('vgt_b_position_supported', 0, 1),
        BitField('commanded_vgt_b_position_supported', 0, 1),
        BitField('vgt_a_position_supported', 0, 1),
        BitField('commanded_vgt_a_position_supported', 0, 1),
        ScalingField('commanded_variable_geometry_turbo_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('variable_geometry_turbo_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('commanded_variable_geometry_turbo_b_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('variable_geometry_turbo_b_position', 0,
                     scaling=100 / 255., unit="%"),
    ]


class OBD_PID72(OBD_Packet):
    name = "PID_72_WastegateControl"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('wastegate_b_position_supported', 0, 1),
        BitField('commanded_wastegate_b_position_supported', 0, 1),
        BitField('wastegate_a_position_supported', 0, 1),
        BitField('commanded_wastegate_a_position_supported', 0, 1),
        ScalingField('commanded_wastegate_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('wastegate_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('commanded_wastegate_b_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('wastegate_b_position', 0,
                     scaling=100 / 255., unit="%"),
    ]


class OBD_PID73(OBD_Packet):
    name = "PID_73_ExhaustPressure"
    fields_desc = [
        BitField('reserved', 0, 6),
        BitField('sensor_bank2_supported', 0, 1),
        BitField('sensor_bank1_supported', 0, 1),
        ScalingField('sensor_bank1', 0, scaling=0.01, unit="kPa", fmt='H'),
        ScalingField('sensor_bank2', 0, scaling=0.01, unit="kPa", fmt='H'),
    ]


class OBD_PID74(OBD_Packet):
    name = "PID_74_TurbochargerRpm"
    fields_desc = [
        BitField('reserved', 0, 6),
        BitField('b_supported', 0, 1),
        BitField('a_supported', 0, 1),
        ScalingField('a_rpm', 0, unit="min-1", fmt='H'),
        ScalingField('b_rpm', 0, unit="min-1", fmt='H'),
    ]


class OBD_PID75(OBD_Packet):
    name = "PID_75_TurbochargerATemperature"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('turbo_a_turbine_outlet_temperature_supported', 0, 1),
        BitField('turbo_a_turbine_inlet_temperature_supported', 0, 1),
        BitField('turbo_a_compressor_outlet_temperature_supported', 0, 1),
        BitField('turbo_a_compressor_inlet_temperature_supported', 0, 1),
        ScalingField('turbocharger_a_compressor_inlet_temperature', 0,
                     unit="deg. C", offset=-40),
        ScalingField('turbocharger_a_compressor_outlet_temperature', 0,
                     unit="deg. C", offset=-40),
        ScalingField('turbocharger_a_turbine_inlet_temperature', 0,
                     unit="deg. C", offset=-40, fmt='H',
                     scaling=0.1),
        ScalingField('turbocharger_a_turbine_outlet_temperature', 0,
                     unit="deg. C", offset=-40, fmt='H',
                     scaling=0.1),
    ]


class OBD_PID76(OBD_Packet):
    name = "PID_76_TurbochargerBTemperature"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('turbo_a_turbine_outlet_temperature_supported', 0, 1),
        BitField('turbo_a_turbine_inlet_temperature_supported', 0, 1),
        BitField('turbo_a_compressor_outlet_temperature_supported', 0, 1),
        BitField('turbo_a_compressor_inlet_temperature_supported', 0, 1),
        ScalingField('turbocharger_a_compressor_inlet_temperature', 0,
                     unit="deg. C", offset=-40),
        ScalingField('turbocharger_a_compressor_outlet_temperature', 0,
                     unit="deg. C", offset=-40),
        ScalingField('turbocharger_a_turbine_inlet_temperature', 0,
                     unit="deg. C", offset=-40, fmt='H',
                     scaling=0.1),
        ScalingField('turbocharger_a_turbine_outlet_temperature', 0,
                     unit="deg. C", offset=-40, fmt='H',
                     scaling=0.1),
    ]


class OBD_PID77(OBD_Packet):
    name = "PID_77_ChargeAirCoolerTemperature"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('bank2_sensor2_supported', 0, 1),
        BitField('bank2_sensor1_supported', 0, 1),
        BitField('bank1_sensor2_supported', 0, 1),
        BitField('bank1_sensor1_supported', 0, 1),
        ScalingField('bank1_sensor1', 0, unit="deg. C", offset=-40),
        ScalingField('bank1_sensor2', 0, unit="deg. C", offset=-40),
        ScalingField('bank2_sensor1', 0, unit="deg. C", offset=-40),
        ScalingField('bank2_sensor2', 0, unit="deg. C", offset=-40),
    ]


class _OBD_PID_ExhaustGasTemperatureBank(OBD_Packet):
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('sensor4_supported', 0, 1),
        BitField('sensor3_supported', 0, 1),
        BitField('sensor2_supported', 0, 1),
        BitField('sensor1_supported', 0, 1),
        ScalingField('sensor1', 0, unit="deg. C", offset=-40,
                     scaling=0.1, fmt='H'),
        ScalingField('sensor2', 0, unit="deg. C", offset=-40,
                     scaling=0.1, fmt='H'),
        ScalingField('sensor3', 0, unit="deg. C", offset=-40,
                     scaling=0.1, fmt='H'),
        ScalingField('sensor4', 0, unit="deg. C", offset=-40,
                     scaling=0.1, fmt='H'),
    ]


class OBD_PID78(_OBD_PID_ExhaustGasTemperatureBank):
    name = "PID_78_ExhaustGasTemperatureBank1"


class OBD_PID79(_OBD_PID_ExhaustGasTemperatureBank):
    name = "PID_79_ExhaustGasTemperatureBank2"


class _OBD_PID_DieselParticulateFilter(OBD_Packet):
    fields_desc = [
        BitField('reserved', 0, 5),
        BitField('outlet_pressure_supported', 0, 1),
        BitField('inlet_pressure_supported', 0, 1),
        BitField('delta_pressure_supported', 0, 1),
        ScalingField('delta_pressure', 0,
                     unit='kPa', offset=-327.68, scaling=0.01, fmt='H'),
        ScalingField('particulate_filter', 0,
                     unit='kPa', scaling=0.01, fmt='H'),
        ScalingField('outlet_pressure', 0,
                     unit='kPa', scaling=0.01, fmt='H'),
    ]


class OBD_PID7A(_OBD_PID_DieselParticulateFilter):
    name = "PID_7A_DieselParticulateFilter1"


class OBD_PID7B(_OBD_PID_DieselParticulateFilter):
    name = "PID_7B_DieselParticulateFilter2"


class OBD_PID7C(OBD_Packet):
    name = "PID_7C_DieselParticulateFilterTemperature"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('bank2_outlet_temperature_supported', 0, 1),
        BitField('bank2_inlet_temperature_supported', 0, 1),
        BitField('bank1_outlet_temperature_supported', 0, 1),
        BitField('bank1_inlet_temperature_supported', 0, 1),
        ScalingField('bank1_inlet_temperature_sensor', 0,
                     unit="deg. C", offset=-40, scaling=0.1, fmt='H'),
        ScalingField('bank1_outlet_temperature_sensor', 0,
                     unit="deg. C", offset=-40, scaling=0.1, fmt='H'),
        ScalingField('bank2_inlet_temperature_sensor', 0,
                     unit="deg. C", offset=-40, scaling=0.1, fmt='H'),
        ScalingField('bank2_outlet_temperature_sensor', 0,
                     unit="deg. C", offset=-40, scaling=0.1, fmt='H'),
    ]


class OBD_PID7D(OBD_Packet):
    name = "PID_7D_NoxNteControlAreaStatus"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('nte_deficiency_for_nox_active_area', 0, 1),
        BitField('inside_manufacturer_specific_nox_nte_carve_out_area', 0, 1),
        BitField('outside', 0, 1),
        BitField('inside', 0, 1),
    ]


class OBD_PID7E(OBD_Packet):
    name = "PID_7E_PmNteControlAreaStatus"
    fields_desc = [
        BitField('reserved', 0, 4),
        BitField('nte_deficiency_for_pm_active_area', 0, 1),
        BitField('inside_manufacturer_specific_pm_nte_carve_out_area', 0, 1),
        BitField('outside', 0, 1),
        BitField('inside', 0, 1),
    ]


class OBD_PID7F(OBD_Packet):
    name = "PID_7F_EngineRunTime"
    fields_desc = [
        BitField('reserved', 0, 5),
        BitField('total_with_pto_active_supported', 0, 1),
        BitField('total_idle_supported', 0, 1),
        BitField('total_supported', 0, 1),
        ScalingField('total', 0, unit='sec', fmt='Q'),
        ScalingField('total_idle', 0, unit='sec', fmt='Q'),
        ScalingField('total_with_pto_active', 0, unit='sec', fmt='Q'),
    ]
