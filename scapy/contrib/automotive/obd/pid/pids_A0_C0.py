#! /usr/bin/env python

from scapy.fields import StrFixedLenField, FlagsField
from scapy.packet import Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class PidA0_S1AndS2(Packet):
    name = "PID_A0_PidsSupported"
    fields_desc = [
        FlagsField('supportedPids', 0, 32, [
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
        FlagsField('supportedPids', 0, 32, [
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
