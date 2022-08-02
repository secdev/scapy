# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.status = skip

from scapy.fields import StrFixedLenField, FlagsField
from scapy.contrib.automotive.obd.packet import OBD_Packet


# See https://en.wikipedia.org/wiki/OBD-II_PIDs for further information
# PID = Parameter IDentification

class OBD_PIDA0(OBD_Packet):
    name = "PID_A0_PIDsSupported"
    fields_desc = [
        FlagsField('supported_pids', 0, 32, [
            'PIDC0',
            'PIDBF',
            'PIDBE',
            'PIDBD',
            'PIDBC',
            'PIDBB',
            'PIDBA',
            'PIDB9',
            'PIDB8',
            'PIDB7',
            'PIDB6',
            'PIDB5',
            'PIDB4',
            'PIDB3',
            'PIDB2',
            'PIDB1',
            'PIDB0',
            'PIDAF',
            'PIDAE',
            'PIDAD',
            'PIDAC',
            'PIDAB',
            'PIDAA',
            'PIDA9',
            'PIDA8',
            'PIDA7',
            'PIDA6',
            'PIDA5',
            'PIDA4',
            'PIDA3',
            'PIDA2',
            'PIDA1'
        ])
    ]


class OBD_PIDA1(OBD_Packet):
    name = "PID_A1_NoxSensorCorrectedData"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class OBD_PIDA2(OBD_Packet):
    name = "PID_A2_CylinderFuelRate"
    fields_desc = [
        StrFixedLenField('data', b'', 2)
    ]


class OBD_PIDA3(OBD_Packet):
    name = "PID_A3_EvapSystemVaporPressure"
    fields_desc = [
        StrFixedLenField('data', b'', 9)
    ]


class OBD_PIDA4(OBD_Packet):
    name = "PID_A4_TransmissionActualGear"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PIDA5(OBD_Packet):
    name = "PID_A5_DieselExhaustFluidDosing"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PIDA6(OBD_Packet):
    name = "PID_A6_Odometer"
    fields_desc = [
        StrFixedLenField('data', b'', 4)
    ]


class OBD_PIDC0(OBD_Packet):
    name = "PID_C0_PIDsSupported"
    fields_desc = [
        FlagsField('supported_pids', 0, 32, [
            'PIDE0',
            'PIDDF',
            'PIDDE',
            'PIDDD',
            'PIDDC',
            'PIDDB',
            'PIDDA',
            'PIDD9',
            'PIDD8',
            'PIDD7',
            'PIDD6',
            'PIDD5',
            'PIDD4',
            'PIDD3',
            'PIDD2',
            'PIDD1',
            'PIDD0',
            'PIDCF',
            'PIDCE',
            'PIDCD',
            'PIDCC',
            'PIDCB',
            'PIDCA',
            'PIDC9',
            'PIDC8',
            'PIDC7',
            'PIDC6',
            'PIDC5',
            'PIDC4',
            'PIDC3',
            'PIDC2',
            'PIDC1'
        ])
    ]
