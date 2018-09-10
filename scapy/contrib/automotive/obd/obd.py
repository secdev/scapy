# flake8: noqa: F405

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

import struct

from scapy.contrib.automotive.obd.iid.iids import *
from scapy.contrib.automotive.obd.mid.mids import *
from scapy.contrib.automotive.obd.pid.pids import *
from scapy.contrib.automotive.obd.tid.tids import *
from scapy.contrib.automotive.obd.services import *
from scapy.packet import Packet, bind_layers
from scapy.fields import XByteEnumField


class OBD(Packet):
    services = {
        0x01: 'CurrentPowertrainDiagnosticDataRequest',
        0x02: 'PowertrainFreezeFrameDataRequest',
        0x03: 'EmissionRelatedDiagnosticTroubleCodesRequest',
        0x04: 'ClearResetDiagnosticTroubleCodesRequest',
        0x05: 'OxygenSensorMonitoringTestResultsRequest',
        0x06: 'OnBoardMonitoringTestResultsRequest',
        0x07: 'PendingEmissionRelatedDiagnosticTroubleCodesRequest',
        0x08: 'ControlOperationRequest',
        0x09: 'VehicleInformationRequest',
        0x0A: 'PermanentDiagnosticTroubleCodesRequest',
        0x41: 'CurrentPowertrainDiagnosticDataResponse',
        0x42: 'PowertrainFreezeFrameDataResponse',
        0x43: 'EmissionRelatedDiagnosticTroubleCodesResponse',
        0x44: 'ClearResetDiagnosticTroubleCodesResponse',
        0x45: 'OxygenSensorMonitoringTestResultsResponse',
        0x46: 'OnBoardMonitoringTestResultsResponse',
        0x47: 'PendingEmissionRelatedDiagnosticTroubleCodesResponse',
        0x48: 'ControlOperationResponse',
        0x49: 'VehicleInformationResponse',
        0x4A: 'PermanentDiagnosticTroubleCodesResponse',
        0x7f: 'NegativeResponse'}

    name = "On-board diagnostics"

    fields_desc = [
        XByteEnumField('service', 0, services)
    ]

    def hashret(self):
        if self.service == 0x7f:
            return struct.pack('B', self.requestServiceId)
        return struct.pack('B', self.service & ~0x40)

    def answers(self, other):
        """DEV: true if self is an answer from other"""
        if other.__class__ == self.__class__:
            return (other.service + 0x40) == self.service or \
                   (self.service == 0x7f and
                    self.requestServiceId == other.service)
        return False


# Service Bindings

bind_layers(OBD, OBD_S01, service=0x01)
bind_layers(OBD, OBD_S02, service=0x02)
bind_layers(OBD, OBD_S03, service=0x03)
bind_layers(OBD, OBD_S04, service=0x04)
bind_layers(OBD, OBD_S06, service=0x06)
bind_layers(OBD, OBD_S07, service=0x07)
bind_layers(OBD, OBD_S08, service=0x08)
bind_layers(OBD, OBD_S09, service=0x09)
bind_layers(OBD, OBD_S0A, service=0x0A)

bind_layers(OBD, OBD_S01_PID, service=0x41)
bind_layers(OBD, OBD_S02_PID, service=0x42)
bind_layers(OBD, OBD_S03_DTC, service=0x43)
bind_layers(OBD, OBD_S04_PR, service=0x44)
bind_layers(OBD, OBD_S06_MID, service=0x46)
bind_layers(OBD, OBD_S07_DTC, service=0x47)
bind_layers(OBD, OBD_S08_TID, service=0x48)
bind_layers(OBD, OBD_S09_PR, service=0x49)
bind_layers(OBD, OBD_S0A_DTC, service=0x4A)
bind_layers(OBD, OBD_NR, service=0x7F)


# Service 09 Bindings

bind_layers(OBD_S09_PR, OBD_IID00, iid=0x00)
bind_layers(OBD_S09_PR, OBD_IID01, iid=0x01)
bind_layers(OBD_S09_PR, OBD_IID02, iid=0x02)
bind_layers(OBD_S09_PR, OBD_IID03, iid=0x03)
bind_layers(OBD_S09_PR, OBD_IID04, iid=0x04)
bind_layers(OBD_S09_PR, OBD_IID05, iid=0x05)
bind_layers(OBD_S09_PR, OBD_IID06, iid=0x06)
bind_layers(OBD_S09_PR, OBD_IID07, iid=0x07)
bind_layers(OBD_S09_PR, OBD_IID08, iid=0x08)
bind_layers(OBD_S09_PR, OBD_IID09, iid=0x09)
bind_layers(OBD_S09_PR, OBD_IID0A, iid=0x0A)
bind_layers(OBD_S09_PR, OBD_IID0B, iid=0x0B)
