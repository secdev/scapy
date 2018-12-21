# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from scapy.fields import BitField, FlagsField, ScalingField, ScalingIntField
from scapy.packet import Packet
import scapy.modules.six as six

if six.PY2:
    _temperature = "\xC2\xB0C"
else:
    _temperature = "\xB0C"

# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification


class OBD_PID60(Packet):
    name = "PID_60_PIDsSupported"
    fields_desc = [
        FlagsField('supportedPIDs', 0, 32, [
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


class OBD_PID61(Packet):
    name = "PID_61_DriverSDemandEnginePercentTorque"
    fields_desc = [
        ScalingField('data', 0, unit="%", offset=-125.0)
    ]


class OBD_PID62(Packet):
    name = "PID_62_ActualEnginePercentTorque"
    fields_desc = [
        ScalingField('data', 0, unit="%", offset=-125.0)
    ]


class OBD_PID63(Packet):
    name = "PID_63_EngineReferenceTorque"
    fields_desc = [
        ScalingField('data', 0, unit="Nm", fmt="H")
    ]


class OBD_PID64(Packet):
    name = "PID_64_EnginePercentTorqueData"
    fields_desc = [
        ScalingField('atPoint1', 0, unit="%", offset=-125.0),
        ScalingField('atPoint2', 0, unit="%", offset=-125.0),
        ScalingField('atPoint3', 0, unit="%", offset=-125.0),
        ScalingField('atPoint4', 0, unit="%", offset=-125.0),
        ScalingField('atPoint5', 0, unit="%", offset=-125.0)
    ]


class OBD_PID65(Packet):
    name = "PID_65_AuxiliaryInputOutputSupported"
    fields_desc = [
        BitField('PowerTakeOffStatusSupported', 0, 1),
        BitField('AutoTransNeutralDriveStatusSupported', 0, 1),
        BitField('ManualTransNeutralDriveStatusSupported', 0, 1),
        BitField('GlowPlugLampStatusSupported', 0, 1),
        BitField('reserved1', 0, 4),
        BitField('PowerTakeOffStatus', 0, 1),
        BitField('AutoTransNeutralDriveStatus', 0, 1),
        BitField('ManualTransNeutralDriveStatus', 0, 1),
        BitField('GlowPlugLampStatus', 0, 1),
        BitField('reserved2', 0, 4),
    ]


class OBD_PID66(Packet):
    name = "PID_66_MassAirFlowSensor"
    fields_desc = [
        BitField('SensorASupported', 0, 1),
        BitField('SensorBSupported', 0, 1),
        BitField('reserved', 0, 6),
        ScalingField('SensorA', 0, scaling=0.03125, unit="g/s", fmt="H"),
        ScalingField('SensorB', 0, scaling=0.03125, unit="g/s", fmt="H"),
    ]


class OBD_PID67(Packet):
    name = "PID_67_EngineCoolantTemperature"
    fields_desc = [
        BitField('Sensor1Supported', 0, 1),
        BitField('Sensor2Supported', 0, 1),
        BitField('reserved', 0, 6),
        ScalingField('Sensor1', 0, unit=_temperature, offset=-40.0),
        ScalingField('Sensor2', 0, unit=_temperature, offset=-40.0)
    ]


class OBD_PID68(Packet):
    name = "PID_68_IntakeAirTemperatureSensor"
    fields_desc = [
        BitField('Bank1Sensor1Supported', 0, 1),
        BitField('Bank1Sensor2Supported', 0, 1),
        BitField('Bank1Sensor3Supported', 0, 1),
        BitField('Bank2Sensor1Supported', 0, 1),
        BitField('Bank2Sensor2Supported', 0, 1),
        BitField('Bank2Sensor3Supported', 0, 1),
        BitField('reserved', 0, 2),
        ScalingField('Bank1Sensor1', 0, unit=_temperature, offset=-40.0),
        ScalingField('Bank1Sensor2', 0, unit=_temperature, offset=-40.0),
        ScalingField('Bank1Sensor3', 0, unit=_temperature, offset=-40.0),
        ScalingField('Bank2Sensor1', 0, unit=_temperature, offset=-40.0),
        ScalingField('Bank2Sensor2', 0, unit=_temperature, offset=-40.0),
        ScalingField('Bank2Sensor3', 0, unit=_temperature, offset=-40.0)
    ]


class OBD_PID69(Packet):
    name = "PID_69_CommandedEgrAndEgrError"
    fields_desc = [
        BitField('CommandedEGRADutyCycleSupported', 0, 1),
        BitField('ActualEGRADutyCycleSupported', 0, 1),
        BitField('EGRAErrorSupported', 0, 1),
        BitField('CommandedEGRBDutyCycleSupported', 0, 1),
        BitField('ActualEGRBDutyCycleSupported', 0, 1),
        BitField('EGRBErrorSupported', 0, 1),
        BitField('reserved', 0, 2),
        ScalingField('CommandedEGRADutyCycle', 0, scaling=100 / 255.,
                     unit="%"),
        ScalingField('ActualEGRADutyCycle', 0, scaling=100 / 255.,
                     unit="%"),
        ScalingField('EGRAError', 0, scaling=100 / 128., unit="%",
                     offset=-100),
        ScalingField('CommandedEGRBDutyCycle', 0, scaling=100 / 255.,
                     unit="%"),
        ScalingField('ActualEGRBDutyCycle', 0, scaling=100 / 255.,
                     unit="%"),
        ScalingField('EGRBError', 0, scaling=100 / 128., unit="%",
                     offset=-100),
    ]


class OBD_PID6A(Packet):
    name = "PID_6A_CommandedDieselIntakeAirFlowControl" \
           "AndRelativeIntakeAirFlowPosition"
    fields_desc = [
        BitField('commanded_intake_air_flow_a_control_supported', 0, 1),
        BitField('relative_intake_air_flow_a_position_supported', 0, 1),
        BitField('commanded_intake_air_flow_b_control_supported', 0, 1),
        BitField('relative_intake_air_flow_b_position_supported', 0, 1),
        BitField('reserved', 0, 4),
        ScalingField('CommandedIntakeAirFlowAControl', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('relative_intake_air_flow_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('commanded_intake_air_flow_b_control', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('relative_intake_air_flow_b_position', 0,
                     scaling=100 / 255., unit="%"),
    ]


class OBD_PID6B(Packet):
    name = "PID_6B_ExhaustGasRecirculationTemperature"
    fields_desc = [
        BitField('bank_1_sensor_1_supported', 0, 1),
        BitField('bank_1_sensor_2_supported', 0, 1),
        BitField('bank_2_sensor_1_supported', 0, 1),
        BitField('bank_2_sensor_2_supported', 0, 1),
        BitField('reserved', 0, 4),
        ScalingField('bank_1_sensor_1', 0, unit=_temperature, offset=-40),
        ScalingField('bank_1_sensor_2', 0, unit=_temperature, offset=-40),
        ScalingField('bank_2_sensor_1', 0, unit=_temperature, offset=-40),
        ScalingField('bank_2_sensor_2', 0, unit=_temperature, offset=-40),
    ]


class OBD_PID6C(Packet):
    name = "PID_6C_CommandedThrottleActuatorControlAndRelativeThrottlePosition"
    fields_desc = [
        BitField('commanded_throttle_actuator_a_control_supported', 0, 1),
        BitField('relative_throttle_a_position_supported', 0, 1),
        BitField('commanded_throttle_actuator_b_control_supported', 0, 1),
        BitField('relative_throttle_b_position_supported', 0, 1),
        BitField('reserved', 0, 4),
        ScalingField('commanded_throttle_actuator_a_control', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('relative_throttle_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('commanded_throttle_actuator_b_control', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('relative_throttle_b_position', 0,
                     scaling=100 / 255., unit="%"),
    ]


class OBD_PID6D(Packet):
    name = "PID_6D_FuelPressureControlSystem"
    fields_desc = [
        BitField('commanded_fuel_rail_pressure_supported', 0, 1),
        BitField('fuel_rail_pressure_supported', 0, 1),
        BitField('fuel_temperature_supported', 0, 1),
        BitField('reserved', 0, 5),
        ScalingField('commanded_fuel_rail_pressure', 0, scaling=10, unit="kPa",
                     fmt='H'),
        ScalingField('fuel_rail_pressure', 0, scaling=10, unit="kPa",
                     fmt='H'),
        ScalingField('fuel_rail_temperature', 0, unit=_temperature,
                     offset=-40),
    ]


class OBD_PID6E(Packet):
    name = "PID_6E_InjectionPressureControlSystem"
    fields_desc = [
        BitField('commanded_injection_control_pressure_supported', 0, 1),
        BitField('injection_control_pressure_supported', 0, 1),
        BitField('reserved', 0, 6),
        ScalingField('commanded_injection_control_pressure', 0, scaling=10,
                     unit="kPa", fmt='H'),
        ScalingField('injection_control_pressure', 0, scaling=10,
                     unit="kPa", fmt='H'),
    ]


class OBD_PID6F(Packet):
    name = "PID_6F_TurbochargerCompressorInletPressure"
    fields_desc = [
        BitField('sensor_a_supported', 0, 1),
        BitField('sensor_b_supported', 0, 1),
        BitField('reserved', 0, 6),
        ScalingField('sensor_a', 0, unit="kPa"),
        ScalingField('sensor_b', 0, unit="kPa"),
    ]


class OBD_PID70(Packet):
    name = "PID_70_BoostPressureControl"
    fields_desc = [
        BitField('commanded_boost_pressure_a_supported', 0, 1),
        BitField('boost_pressure_sensor_a_supported', 0, 1),
        BitField('commanded_boost_pressure_b_supported', 0, 1),
        BitField('boost_pressure_sensor_b_supported', 0, 1),
        BitField('reserved', 0, 4),
        ScalingField('commanded_boost_pressure_a', 0, scaling=0.03125,
                     unit="kPa", fmt='H'),
        ScalingField('boost_pressure_sensor_a', 0, scaling=0.03125,
                     unit="kPa", fmt='H'),
        ScalingField('commanded_boost_pressure_b', 0, scaling=0.03125,
                     unit="kPa", fmt='H'),
        ScalingField('boost_pressure_sensor_b', 0, scaling=0.03125,
                     unit="kPa", fmt='H'),
    ]


class OBD_PID71(Packet):
    name = "PID_71_VariableGeometryTurboControl"
    fields_desc = [
        BitField('commanded_vgt_a_position_supported', 0, 1),
        BitField('vgt_a_position_supported', 0, 1),
        BitField('commanded_vgt_b_position_supported', 0, 1),
        BitField('vgt_b_position_supported', 0, 1),
        BitField('reserved', 0, 4),
        ScalingField('commanded_variable_geometry_turbo_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('variable_geometry_turbo_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('commanded_variable_geometry_turbo_b_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('variable_geometry_turbo_b_position', 0,
                     scaling=100 / 255., unit="%"),
    ]


class OBD_PID72(Packet):
    name = "PID_72_WastegateControl"
    fields_desc = [
        BitField('commanded_wastegate_a_position_supported', 0, 1),
        BitField('wastegate_a_position_supported', 0, 1),
        BitField('commanded_wastegate_b_position_supported', 0, 1),
        BitField('wastegate_b_position_supported', 0, 1),
        BitField('reserved', 0, 4),
        ScalingField('commanded_wastegate_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('wastegate_a_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('commanded_wastegate_b_position', 0,
                     scaling=100 / 255., unit="%"),
        ScalingField('wastegate_b_position', 0,
                     scaling=100 / 255., unit="%"),
    ]


class OBD_PID73(Packet):
    name = "PID_73_ExhaustPressure"
    fields_desc = [
        BitField('sensor_bank_1_supported', 0, 1),
        BitField('sensor_bank_2_supported', 0, 1),
        BitField('reserved', 0, 6),
        ScalingField('sensor_bank_1', 0, scaling=0.01, unit="kPa", fmt='H'),
        ScalingField('sensor_bank_2', 0, scaling=0.01, unit="kPa", fmt='H'),
    ]


class OBD_PID74(Packet):
    name = "PID_74_TurbochargerRpm"
    fields_desc = [
        BitField('a_supported', 0, 1),
        BitField('b_supported', 0, 1),
        BitField('reserved', 0, 6),
        ScalingField('a_rpm', 0, unit="min-1", fmt='H'),
        ScalingField('b_rpm', 0, unit="min-1", fmt='H'),
    ]


class OBD_PID75(Packet):
    name = "PID_75_TurbochargerATemperature"
    fields_desc = [
        BitField('turbo_a_compressor_inlet_temperature_supported', 0, 1),
        BitField('turbo_a_compressor_outlet_temperature_supported', 0, 1),
        BitField('turbo_a_turbine_inlet_temperature_supported', 0, 1),
        BitField('turbo_a_turbine_outlet_temperature_supported', 0, 1),
        BitField('reserved', 0, 4),
        ScalingField('turbocharger_a_compressor_inlet_temperature', 0,
                     unit=_temperature, offset=-40),
        ScalingField('turbocharger_a_compressor_outlet_temperature', 0,
                     unit=_temperature, offset=-40),
        ScalingField('turbocharger_a_turbine_inlet_temperature', 0,
                     unit=_temperature, offset=-40, fmt='H', scaling=0.1),
        ScalingField('turbocharger_a_turbine_outlet_temperature', 0,
                     unit=_temperature, offset=-40, fmt='H', scaling=0.1),
    ]


class OBD_PID76(Packet):
    name = "PID_76_TurbochargerBTemperature"
    fields_desc = [
        BitField('turbo_a_compressor_inlet_temperature_supported', 0, 1),
        BitField('turbo_a_compressor_outlet_temperature_supported', 0, 1),
        BitField('turbo_a_turbine_inlet_temperature_supported', 0, 1),
        BitField('turbo_a_turbine_outlet_temperature_supported', 0, 1),
        BitField('reserved', 0, 4),
        ScalingField('turbocharger_a_compressor_inlet_temperature', 0,
                     unit=_temperature, offset=-40),
        ScalingField('turbocharger_a_compressor_outlet_temperature', 0,
                     unit=_temperature, offset=-40),
        ScalingField('turbocharger_a_turbine_inlet_temperature', 0,
                     unit=_temperature, offset=-40, fmt='H', scaling=0.1),
        ScalingField('turbocharger_a_turbine_outlet_temperature', 0,
                     unit=_temperature, offset=-40, fmt='H', scaling=0.1),
    ]


class OBD_PID77(Packet):
    name = "PID_77_ChargeAirCoolerTemperature"
    fields_desc = [
        BitField('bank_1_sensor_1_supported', 0, 1),
        BitField('bank_1_sensor_2_supported', 0, 1),
        BitField('bank_2_sensor_1_supported', 0, 1),
        BitField('bank_2_sensor_2_supported', 0, 1),
        BitField('reserved', 0, 4),
        ScalingField('bank_1_sensor_1', 0, unit=_temperature, offset=-40),
        ScalingField('bank_1_sensor_2', 0, unit=_temperature, offset=-40),
        ScalingField('bank_2_sensor_1', 0, unit=_temperature, offset=-40),
        ScalingField('bank_2_sensor_2', 0, unit=_temperature, offset=-40),
    ]


class _OBD_PID_ExhaustGasTemperatureBank(Packet):
    fields_desc = [
        BitField('sensor_1_supported', 0, 1),
        BitField('sensor_2_supported', 0, 1),
        BitField('sensor_3_supported', 0, 1),
        BitField('sensor_4_supported', 0, 1),
        BitField('reserved', 0, 4),
        ScalingField('sensor_1', 0,
                     unit=_temperature, offset=-40, scaling=0.1, fmt='H'),
        ScalingField('sensor_2', 0,
                     unit=_temperature, offset=-40, scaling=0.1, fmt='H'),
        ScalingField('sensor_3', 0,
                     unit=_temperature, offset=-40, scaling=0.1, fmt='H'),
        ScalingField('sensor_4', 0,
                     unit=_temperature, offset=-40, scaling=0.1, fmt='H'),
    ]


class OBD_PID78(_OBD_PID_ExhaustGasTemperatureBank):
    name = "PID_78_ExhaustGasTemperatureBank1"


class OBD_PID79(_OBD_PID_ExhaustGasTemperatureBank):
    name = "PID_79_ExhaustGasTemperatureBank2"


class _OBD_PID_DieselParticulateFilter(Packet):
    fields_desc = [
        BitField('delta_pressure_supported', 0, 1),
        BitField('inlet_pressure_supported', 0, 1),
        BitField('outlet_pressure_supported', 0, 1),
        BitField('reserved', 0, 5),
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


class OBD_PID7C(Packet):
    name = "PID_7C_DieselParticulateFilterTemperature"
    fields_desc = [
        BitField('bank_1_inlet_temperature_supported', 0, 1),
        BitField('bank_1_outlet_temperature_supported', 0, 1),
        BitField('bank_2_inlet_temperature_supported', 0, 1),
        BitField('bank_2_outlet_temperature_supported', 0, 1),
        BitField('reserved', 0, 4),
        ScalingField('bank_1_inlet_temperature_sensor', 0,
                     unit=_temperature, offset=-40, scaling=0.1, fmt='H'),
        ScalingField('bank_1_outlet_temperature_sensor', 0,
                     unit=_temperature, offset=-40, scaling=0.1, fmt='H'),
        ScalingField('bank_2_inlet_temperature_sensor', 0,
                     unit=_temperature, offset=-40, scaling=0.1, fmt='H'),
        ScalingField('bank_2_outlet_temperature_sensor', 0,
                     unit=_temperature, offset=-40, scaling=0.1, fmt='H'),
    ]


class OBD_PID7D(Packet):
    name = "PID_7D_NoxNteControlAreaStatus"
    fields_desc = [
        BitField('inside', 0, 1),
        BitField('outside', 0, 1),
        BitField('inside_manufacturer_specific_nox_nte_carve_out_area', 0, 1),
        BitField('nte_deficiency_for_nox_active_area', 0, 1),
        BitField('reserved', 0, 4),
    ]


class OBD_PID7E(Packet):
    name = "PID_7E_PmNteControlAreaStatus"
    fields_desc = [
        BitField('inside', 0, 1),
        BitField('outside', 0, 1),
        BitField('inside_manufacturer_specific_pm_nte_carve_out_area', 0, 1),
        BitField('nte_deficiency_for_pm_active_area', 0, 1),
        BitField('reserved', 0, 4),
    ]


class OBD_PID7F(Packet):
    name = "PID_7F_EngineRunTime"
    fields_desc = [
        BitField('total_supported', 0, 1),
        BitField('total_idle_supported', 0, 1),
        BitField('total_with_pto_active_supported', 0, 1),
        BitField('reserved', 0, 5),
        ScalingIntField('total', 0, unit='sec', fmt='Q'),
        ScalingIntField('total_idle', 0, unit='sec', fmt='Q'),
        ScalingIntField('total_with_pto_active', 0, unit='sec', fmt='Q'),
    ]
