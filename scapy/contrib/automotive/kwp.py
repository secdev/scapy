# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = Keyword Protocol 2000 (KWP2000) / ISO 14230
# scapy.contrib.status = loads

import struct
import time

from scapy.fields import ByteEnumField, StrField, ConditionalField, \
    BitField, XByteField, X3BytesField, ByteField, \
    ObservableDict, XShortEnumField, XByteEnumField
from scapy.packet import Packet, bind_layers, NoPayload
from scapy.config import conf
from scapy.error import log_loading
from scapy.utils import PeriodicSenderThread
from scapy.plist import _PacketIterable
from scapy.contrib.isotp import ISOTP
from scapy.compat import Dict, Any


try:
    if conf.contribs['KWP']['treat-response-pending-as-answer']:
        pass
except KeyError:
    log_loading.info("Specify \"conf.contribs['KWP'] = "
                     "{'treat-response-pending-as-answer': True}\" to treat "
                     "a negative response 'requestCorrectlyReceived-"
                     "ResponsePending' as answer of a request. \n"
                     "The default value is False.")
    conf.contribs['KWP'] = {'treat-response-pending-as-answer': False}


class KWP(ISOTP):
    services = ObservableDict(
        {0x10: 'StartDiagnosticSession',
         0x11: 'ECUReset',
         0x14: 'ClearDiagnosticInformation',
         0x17: 'ReadStatusOfDiagnosticTroubleCodes',
         0x18: 'ReadDiagnosticTroubleCodesByStatus',
         0x1A: 'ReadECUIdentification',
         0x21: 'ReadDataByLocalIdentifier',
         0x22: 'ReadDataByIdentifier',
         0x23: 'ReadMemoryByAddress',
         0x27: 'SecurityAccess',
         0x28: 'DisableNormalMessageTransmission',
         0x29: 'EnableNormalMessageTransmission',
         0x2C: 'DynamicallyDefineLocalIdentifier',
         0x2E: 'WriteDataByIdentifier',
         0x30: 'InputOutputControlByLocalIdentifier',
         0x31: 'StartRoutineByLocalIdentifier',
         0x32: 'StopRoutineByLocalIdentifier',
         0x33: 'RequestRoutineResultsByLocalIdentifier',
         0x34: 'RequestDownload',
         0x35: 'RequestUpload',
         0x36: 'TransferData',
         0x37: 'RequestTransferExit',
         0x3B: 'WriteDataByLocalIdentifier',
         0x3D: 'WriteMemoryByAddress',
         0x3E: 'TesterPresent',
         0x85: 'ControlDTCSetting',
         0x86: 'ResponseOnEvent',
         0x50: 'StartDiagnosticSessionPositiveResponse',
         0x51: 'ECUResetPositiveResponse',
         0x54: 'ClearDiagnosticInformationPositiveResponse',
         0x57: 'ReadStatusOfDiagnosticTroubleCodesPositiveResponse',
         0x58: 'ReadDiagnosticTroubleCodesByStatusPositiveResponse',
         0x5A: 'ReadECUIdentificationPositiveResponse',
         0x61: 'ReadDataByLocalIdentifierPositiveResponse',
         0x62: 'ReadDataByIdentifierPositiveResponse',
         0x63: 'ReadMemoryByAddressPositiveResponse',
         0x67: 'SecurityAccessPositiveResponse',
         0x68: 'DisableNormalMessageTransmissionPositiveResponse',
         0x69: 'EnableNormalMessageTransmissionPositiveResponse',
         0x6C: 'DynamicallyDefineLocalIdentifierPositiveResponse',
         0x6E: 'WriteDataByIdentifierPositiveResponse',
         0x70: 'InputOutputControlByLocalIdentifierPositiveResponse',
         0x71: 'StartRoutineByLocalIdentifierPositiveResponse',
         0x72: 'StopRoutineByLocalIdentifierPositiveResponse',
         0x73: 'RequestRoutineResultsByLocalIdentifierPositiveResponse',
         0x74: 'RequestDownloadPositiveResponse',
         0x75: 'RequestUploadPositiveResponse',
         0x76: 'TransferDataPositiveResponse',
         0x77: 'RequestTransferExitPositiveResponse',
         0x7B: 'WriteDataByLocalIdentifierPositiveResponse',
         0x7D: 'WriteMemoryByAddressPositiveResponse',
         0x7E: 'TesterPresentPositiveResponse',
         0xC5: 'ControlDTCSettingPositiveResponse',
         0xC6: 'ResponseOnEventPositiveResponse',
         0x7f: 'NegativeResponse'})  # type: Dict[int, str]
    name = 'KWP'
    fields_desc = [
        XByteEnumField('service', 0, services)
    ]

    def answers(self, other):
        # type: (Packet) -> bool
        if not isinstance(other, type(self)):
            return False
        if self.service == 0x7f:
            return self.payload.answers(other)
        if self.service == (other.service + 0x40):
            if isinstance(self.payload, NoPayload) or \
                    isinstance(other.payload, NoPayload):
                return len(self) <= len(other)
            else:
                return self.payload.answers(other.payload)
        return False

    def hashret(self):
        # type: () -> bytes
        if self.service == 0x7f:
            return struct.pack('B', self.requestServiceId)
        else:
            return struct.pack('B', self.service & ~0x40)


# ########################SDS###################################
class KWP_SDS(Packet):
    diagnosticSessionTypes = ObservableDict({
        0x81: 'defaultSession',
        0x85: 'programmingSession',
        0x89: 'standBySession',
        0x90: 'EcuPassiveSession',
        0x92: 'extendedDiagnosticSession'})
    name = 'StartDiagnosticSession'
    fields_desc = [
        ByteEnumField('diagnosticSession', 0, diagnosticSessionTypes)
    ]


bind_layers(KWP, KWP_SDS, service=0x10)


class KWP_SDSPR(Packet):
    name = 'StartDiagnosticSessionPositiveResponse'
    fields_desc = [
        ByteEnumField('diagnosticSession', 0,
                      KWP_SDS.diagnosticSessionTypes),
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_SDS) and \
            other.diagnosticSession == self.diagnosticSession


bind_layers(KWP, KWP_SDSPR, service=0x50)


# ######################### KWP_ER ###################################
class KWP_ER(Packet):
    resetModes = {
        0x00: 'reserved',
        0x01: 'powerOnReset',
        0x82: 'nonvolatileMemoryReset'}
    name = 'ECUReset'
    fields_desc = [
        ByteEnumField('resetMode', 0, resetModes)
    ]


bind_layers(KWP, KWP_ER, service=0x11)


class KWP_ERPR(Packet):
    name = 'ECUResetPositiveResponse'

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_ER)


bind_layers(KWP, KWP_ERPR, service=0x51)


# ######################### KWP_SA ###################################
class KWP_SA(Packet):
    name = 'SecurityAccess'
    fields_desc = [
        ByteField('accessMode', 0),
        ConditionalField(StrField('key', b""),
                         lambda pkt: pkt.accessMode % 2 == 0)
    ]


bind_layers(KWP, KWP_SA, service=0x27)


class KWP_SAPR(Packet):
    name = 'SecurityAccessPositiveResponse'
    fields_desc = [
        ByteField('accessMode', 0),
        ConditionalField(StrField('seed', b""),
                         lambda pkt: pkt.accessMode % 2 == 1),
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_SA) \
            and other.accessMode == self.accessMode


bind_layers(KWP, KWP_SAPR, service=0x67)


# ######################### KWP_IOCBLI ###################################
class KWP_IOCBLI(Packet):
    name = 'InputOutputControlByLocalIdentifier'
    inputOutputControlParameters = {
        0x00: "Return Control to ECU",
        0x01: "Report Current State",
        0x04: "Reset to Default",
        0x05: "Freeze Current State",
        0x07: "Short Term Adjustment",
        0x08: "Long Term Adjustment"
    }
    fields_desc = [
        XByteField('localIdentifier', 0),
        XByteEnumField('inputOutputControlParameter', 0,
                       inputOutputControlParameters),
        StrField('controlState', b"", fmt="B")
    ]


bind_layers(KWP, KWP_IOCBLI, service=0x30)


class KWP_IOCBLIPR(Packet):
    name = 'InputOutputControlByLocalIdentifierPositiveResponse'
    fields_desc = [
        XByteField('localIdentifier', 0),
        XByteEnumField('inputOutputControlParameter', 0,
                       KWP_IOCBLI.inputOutputControlParameters),
        StrField('controlState', b"", fmt="B")
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_IOCBLI) \
            and other.localIdentifier == self.localIdentifier


bind_layers(KWP, KWP_IOCBLIPR, service=0x70)


# ######################### KWP_DNMT ###################################
class KWP_DNMT(Packet):
    responseTypes = {
        0x01: 'responseRequired',
        0x02: 'noResponse',
    }
    name = 'DisableNormalMessageTransmission'
    fields_desc = [
        ByteEnumField('responseRequired', 0, responseTypes)
    ]


bind_layers(KWP, KWP_DNMT, service=0x28)


class KWP_DNMTPR(Packet):
    name = 'DisableNormalMessageTransmissionPositiveResponse'

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_DNMT)


bind_layers(KWP, KWP_DNMTPR, service=0x68)


# ######################### KWP_ENMT ###################################
class KWP_ENMT(Packet):
    responseTypes = {
        0x01: 'responseRequired',
        0x02: 'noResponse',
    }
    name = 'EnableNormalMessageTransmission'
    fields_desc = [
        ByteEnumField('responseRequired', 1, responseTypes)
    ]


bind_layers(KWP, KWP_ENMT, service=0x29)


class KWP_ENMTPR(Packet):
    name = 'EnableNormalMessageTransmissionPositiveResponse'

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_DNMT)


bind_layers(KWP, KWP_ENMTPR, service=0x69)


# ######################### KWP_TP ###################################
class KWP_TP(Packet):
    responseTypes = {
        0x01: 'responseRequired',
        0x02: 'noResponse',
    }
    name = 'TesterPresent'
    fields_desc = [
        ByteEnumField('responseRequired', 1, responseTypes)
    ]


bind_layers(KWP, KWP_TP, service=0x3E)


class KWP_TPPR(Packet):
    name = 'TesterPresentPositiveResponse'

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_TP)


bind_layers(KWP, KWP_TPPR, service=0x7E)


# ######################### KWP_CDTCS ###################################
class KWP_CDTCS(Packet):
    responseTypes = {
        0x01: 'responseRequired',
        0x02: 'noResponse',
    }
    DTCGroups = {
        0x0000: 'allPowertrainDTCs',
        0x4000: 'allChassisDTCs',
        0x8000: 'allBodyDTCs',
        0xC000: 'allNetworkDTCs',
        0xFF00: 'allDTCs'
    }
    DTCSettingModes = {
        0: 'Reserved',
        1: 'on',
        2: 'off'
    }
    name = 'ControlDTCSetting'
    fields_desc = [
        ByteEnumField('responseRequired', 1, responseTypes),
        XShortEnumField('groupOfDTC', 0, DTCGroups),
        ByteEnumField('DTCSettingMode', 0, DTCSettingModes),
    ]


bind_layers(KWP, KWP_CDTCS, service=0x85)


class KWP_CDTCSPR(Packet):
    name = 'ControlDTCSettingPositiveResponse'

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_CDTCS)


bind_layers(KWP, KWP_CDTCSPR, service=0xC5)


# ######################### KWP_ROE ###################################
class KWP_ROE(Packet):
    responseTypes = {
        0x01: 'responseRequired',
        0x02: 'noResponse',
    }
    eventWindowTimes = {
        0x00: 'reserved',
        0x01: 'testerPresentRequired',
        0x02: 'infiniteTimeToResponse',
        0x80: 'noEventWindow'
    }
    eventTypes = {
        0x80: 'reportActivatedEvents',
        0x81: 'stopResponseOnEvent',
        0x82: 'onNewDTC',
        0x83: 'onTimerInterrupt',
        0x84: 'onChangeOfRecordValue',
        0xA0: 'onComparisonOfValues'
    }
    name = 'ResponseOnEvent'
    fields_desc = [
        ByteEnumField('responseRequired', 1, responseTypes),
        ByteEnumField('eventWindowTime', 0, eventWindowTimes),
        ByteEnumField('eventType', 0, eventTypes),
        ByteField('eventParameter', 0),
        ByteEnumField('serviceToRespond', 0, KWP.services),
        ByteField('serviceParameter', 0)
    ]


bind_layers(KWP, KWP_ROE, service=0x86)


class KWP_ROEPR(Packet):
    name = 'ResponseOnEventPositiveResponse'
    fields_desc = [
        ByteField("numberOfActivatedEvents", 0),
        ByteEnumField('eventWindowTime', 0, KWP_ROE.eventWindowTimes),
        ByteEnumField('eventType', 0, KWP_ROE.eventTypes),
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_ROE) \
            and other.eventType == self.eventType


bind_layers(KWP, KWP_ROEPR, service=0xC6)


# ######################### KWP_RDBLI ###################################
class KWP_RDBLI(Packet):
    localIdentifiers = ObservableDict({
        0xE0: "Development Data",
        0xE1: "ECU Serial Number",
        0xE2: "DBCom Data",
        0xE3: "Operating System Version",
        0xE4: "Ecu Reprogramming Identification",
        0xE5: "Vehicle Information",
        0xE6: "Flash Info 1",
        0xE7: "Flash Info 2",
        0xE8: "System Diagnostic general parameter data",
        0xE9: "System Diagnostic global parameter data",
        0xEA: "Ecu Configuration",
        0xEB: "Diagnostic Protocol Information"
    })
    name = 'ReadDataByLocalIdentifier'
    fields_desc = [
        XByteEnumField('recordLocalIdentifier', 0, localIdentifiers)
    ]


bind_layers(KWP, KWP_RDBLI, service=0x21)


class KWP_RDBLIPR(Packet):
    name = 'ReadDataByLocalIdentifierPositiveResponse'
    fields_desc = [
        XByteEnumField('recordLocalIdentifier', 0, KWP_RDBLI.localIdentifiers)
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_RDBLI) \
            and self.recordLocalIdentifier == other.recordLocalIdentifier


bind_layers(KWP, KWP_RDBLIPR, service=0x61)


# ######################### KWP_WDBLI ###################################
class KWP_WDBLI(Packet):
    name = 'WriteDataByLocalIdentifier'
    fields_desc = [
        XByteEnumField('recordLocalIdentifier', 0, KWP_RDBLI.localIdentifiers)
    ]


bind_layers(KWP, KWP_WDBLI, service=0x3B)


class KWP_WDBLIPR(Packet):
    name = 'WriteDataByLocalIdentifierPositiveResponse'
    fields_desc = [
        XByteEnumField('recordLocalIdentifier', 0, KWP_RDBLI.localIdentifiers)
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_WDBLI) \
            and self.recordLocalIdentifier == other.recordLocalIdentifier


bind_layers(KWP, KWP_WDBLIPR, service=0x7B)


# ######################### KWP_RDBI ###################################
class KWP_RDBI(Packet):
    dataIdentifiers = ObservableDict()
    name = 'ReadDataByIdentifier'
    fields_desc = [
        XShortEnumField('identifier', 0, dataIdentifiers)
    ]


bind_layers(KWP, KWP_RDBI, service=0x22)


class KWP_RDBIPR(Packet):
    name = 'ReadDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('identifier', 0, KWP_RDBI.dataIdentifiers),
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_RDBI) \
            and self.identifier == other.identifier


bind_layers(KWP, KWP_RDBIPR, service=0x62)


# ######################### KWP_RMBA ###################################
class KWP_RMBA(Packet):
    name = 'ReadMemoryByAddress'
    fields_desc = [
        X3BytesField('memoryAddress', 0),
        ByteField('memorySize', 0)
    ]


bind_layers(KWP, KWP_RMBA, service=0x23)


class KWP_RMBAPR(Packet):
    name = 'ReadMemoryByAddressPositiveResponse'
    fields_desc = [
        StrField('dataRecord', b"", fmt="B")
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_RMBA)


bind_layers(KWP, KWP_RMBAPR, service=0x63)


# ######################### KWP_DDLI ###################################
# TODO: Implement correct interpretation here,
#       instead of using just the dataRecord
class KWP_DDLI(Packet):
    name = 'DynamicallyDefineLocalIdentifier'
    definitionModes = {0x1: "defineByLocalIdentifier",
                       0x2: "defineByMemoryAddress",
                       0x3: "defineByIdentifier",
                       0x4: "clearDynamicallyDefinedLocalIdentifier"}
    fields_desc = [
        XByteField('dynamicallyDefineLocalIdentifier', 0),
        ByteEnumField('definitionMode', 0, definitionModes),
        StrField('dataRecord', b"", fmt="B")
    ]


bind_layers(KWP, KWP_DDLI, service=0x2C)


class KWP_DDLIPR(Packet):
    name = 'DynamicallyDefineLocalIdentifierPositiveResponse'
    fields_desc = [
        XByteField('dynamicallyDefineLocalIdentifier', 0)
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_DDLI) and \
            other.dynamicallyDefineLocalIdentifier == self.dynamicallyDefineLocalIdentifier  # noqa: E501


bind_layers(KWP, KWP_DDLIPR, service=0x6C)


# ######################### KWP_WDBI ###################################
class KWP_WDBI(Packet):
    name = 'WriteDataByIdentifier'
    fields_desc = [
        XShortEnumField('identifier', 0, KWP_RDBI.dataIdentifiers)
    ]


bind_layers(KWP, KWP_WDBI, service=0x2E)


class KWP_WDBIPR(Packet):
    name = 'WriteDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('identifier', 0, KWP_RDBI.dataIdentifiers),
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_WDBI) \
            and other.identifier == self.identifier


bind_layers(KWP, KWP_WDBIPR, service=0x6E)


# ######################### KWP_WMBA ###################################
class KWP_WMBA(Packet):
    name = 'WriteMemoryByAddress'
    fields_desc = [
        X3BytesField('memoryAddress', 0),
        ByteField('memorySize', 0),
        StrField('dataRecord', b'', fmt="B")
    ]


bind_layers(KWP, KWP_WMBA, service=0x3D)


class KWP_WMBAPR(Packet):
    name = 'WriteMemoryByAddressPositiveResponse'
    fields_desc = [
        X3BytesField('memoryAddress', 0)
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_WMBA) and \
            other.memoryAddress == self.memoryAddress


bind_layers(KWP, KWP_WMBAPR, service=0x7D)


# ######################### KWP_CDI ###################################
class KWP_CDI(Packet):
    DTCGroups = {
        0x0000: 'allPowertrainDTCs',
        0x4000: 'allChassisDTCs',
        0x8000: 'allBodyDTCs',
        0xC000: 'allNetworkDTCs',
        0xFF00: 'allDTCs'
    }
    name = 'ClearDiagnosticInformation'
    fields_desc = [
        XShortEnumField('groupOfDTC', 0, DTCGroups)
    ]


bind_layers(KWP, KWP_CDI, service=0x14)


class KWP_CDIPR(Packet):
    name = 'ClearDiagnosticInformationPositiveResponse'

    fields_desc = [
        XShortEnumField('groupOfDTC', 0, KWP_CDI.DTCGroups)
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_CDI) and \
            self.groupOfDTC == other.groupOfDTC


bind_layers(KWP, KWP_CDIPR, service=0x54)


# ######################### KWP_RSODTC ###################################
class KWP_RSODTC(Packet):
    name = 'ReadStatusOfDiagnosticTroubleCodes'
    fields_desc = [
        XShortEnumField('groupOfDTC', 0, KWP_CDI.DTCGroups)
    ]


bind_layers(KWP, KWP_RSODTC, service=0x17)


class KWP_RSODTCPR(Packet):
    name = 'ReadStatusOfDiagnosticTroubleCodesPositiveResponse'

    fields_desc = [
        ByteField('numberOfDTC', 0),
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_RSODTC)


bind_layers(KWP, KWP_RSODTCPR, service=0x57)


# ######################### KWP_RECUI ###################################
class KWP_RECUI(Packet):
    name = 'ReadECUIdentification'
    localIdentifiers = ObservableDict({
        0x86: "DCS ECU Identification",
        0x87: "DCX / MMC ECU Identification",
        0x88: "VIN (Original)",
        0x89: "Diagnostic Variant Code",
        0x90: "VIN (Current)",
        0x96: "Calibration Identification",
        0x97: "Calibration Verification Number",
        0x9A: "ECU Code Fingerprint",
        0x98: "ECU Data Fingerprint",
        0x9C: "ECU Code Software Identification",
        0x9D: "ECU Data Software Identification",
        0x9E: "ECU Boot Software Identification",
        0x9F: "ECU Boot Fingerprint"
    })
    fields_desc = [
        XByteEnumField('localIdentifier', 0, localIdentifiers)
    ]


bind_layers(KWP, KWP_RECUI, service=0x1A)


class KWP_RECUIPR(Packet):
    name = 'ReadECUIdentificationPositiveResponse'

    fields_desc = [
        XByteEnumField('localIdentifier', 0, KWP_RECUI.localIdentifiers)
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_RECUI) and \
            self.localIdentifier == other.localIdentifier


bind_layers(KWP, KWP_RECUIPR, service=0x5A)


# ######################### KWP_SRBLI ###################################
class KWP_SRBLI(Packet):
    routineLocalIdentifiers = ObservableDict({
        0xE0: "FlashEraseRoutine",
        0xE1: "FlashCheckRoutine",
        0xE2: "Tell-TaleRetentionStack",
        0xE3: "RequestDTCsFromShadowErrorMemory",
        0xE4: "RequestEnvironmentDataFromShadowErrorMemory",
        0xE5: "RequestEventInformation",
        0xE6: "RequestEventEnvironmentData",
        0xE7: "RequestSoftwareModuleInformation",
        0xE8: "ClearTell-TaleRetentionStack",
        0xE9: "ClearEventInformation"
    })
    name = 'StartRoutineByLocalIdentifier'
    fields_desc = [
        XByteEnumField('routineLocalIdentifier', 0, routineLocalIdentifiers)
    ]


bind_layers(KWP, KWP_SRBLI, service=0x31)


class KWP_SRBLIPR(Packet):
    name = 'StartRoutineByLocalIdentifierPositiveResponse'
    fields_desc = [
        XByteEnumField('routineLocalIdentifier', 0,
                       KWP_SRBLI.routineLocalIdentifiers)
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_SRBLI) \
            and other.routineLocalIdentifier == self.routineLocalIdentifier


bind_layers(KWP, KWP_SRBLIPR, service=0x71)


# ######################### KWP_STRBLI ###################################
class KWP_STRBLI(Packet):
    name = 'StopRoutineByLocalIdentifier'
    fields_desc = [
        XByteEnumField('routineLocalIdentifier', 0,
                       KWP_SRBLI.routineLocalIdentifiers)
    ]


bind_layers(KWP, KWP_STRBLI, service=0x32)


class KWP_STRBLIPR(Packet):
    name = 'StopRoutineByLocalIdentifierPositiveResponse'
    fields_desc = [
        XByteEnumField('routineLocalIdentifier', 0,
                       KWP_SRBLI.routineLocalIdentifiers)
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_STRBLI) \
            and other.routineLocalIdentifier == self.routineLocalIdentifier


bind_layers(KWP, KWP_STRBLIPR, service=0x72)


# ######################### KWP_RRRBLI ###################################
class KWP_RRRBLI(Packet):
    name = 'RequestRoutineResultsByLocalIdentifier'
    fields_desc = [
        XByteEnumField('routineLocalIdentifier', 0,
                       KWP_SRBLI.routineLocalIdentifiers)
    ]


bind_layers(KWP, KWP_RRRBLI, service=0x33)


class KWP_RRRBLIPR(Packet):
    name = 'RequestRoutineResultsByLocalIdentifierPositiveResponse'
    fields_desc = [
        XByteEnumField('routineLocalIdentifier', 0,
                       KWP_SRBLI.routineLocalIdentifiers)
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_RRRBLI) \
            and other.routineLocalIdentifier == self.routineLocalIdentifier


bind_layers(KWP, KWP_RRRBLIPR, service=0x73)


# ######################### KWP_RD ###################################
class KWP_RD(Packet):
    name = 'RequestDownload'
    fields_desc = [
        X3BytesField('memoryAddress', 0),
        BitField('compression', 0, 4),
        BitField('encryption', 0, 4),
        X3BytesField('uncompressedMemorySize', 0)
    ]


bind_layers(KWP, KWP_RD, service=0x34)


class KWP_RDPR(Packet):
    name = 'RequestDownloadPositiveResponse'
    fields_desc = [
        StrField('maxNumberOfBlockLength', b"", fmt="B"),
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_RD)


bind_layers(KWP, KWP_RDPR, service=0x74)


# ######################### KWP_RU ###################################
class KWP_RU(Packet):
    name = 'RequestUpload'
    fields_desc = [
        X3BytesField('memoryAddress', 0),
        BitField('compression', 0, 4),
        BitField('encryption', 0, 4),
        X3BytesField('uncompressedMemorySize', 0)
    ]


bind_layers(KWP, KWP_RU, service=0x35)


class KWP_RUPR(Packet):
    name = 'RequestUploadPositiveResponse'
    fields_desc = [
        StrField('maxNumberOfBlockLength', b"", fmt="B"),
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_RU)


bind_layers(KWP, KWP_RUPR, service=0x75)


# ######################### KWP_TD ###################################
class KWP_TD(Packet):
    name = 'TransferData'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferDataRequestParameter', b"", fmt="B")
    ]


bind_layers(KWP, KWP_TD, service=0x36)


class KWP_TDPR(Packet):
    name = 'TransferDataPositiveResponse'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferDataRequestParameter', b"", fmt="B")
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_TD) \
            and other.blockSequenceCounter == self.blockSequenceCounter


bind_layers(KWP, KWP_TDPR, service=0x76)


# ######################### KWP_RTE ###################################
class KWP_RTE(Packet):
    name = 'RequestTransferExit'
    fields_desc = [
        StrField('transferDataRequestParameter', b"", fmt="B")
    ]


bind_layers(KWP, KWP_RTE, service=0x37)


class KWP_RTEPR(Packet):
    name = 'RequestTransferExitPositiveResponse'
    fields_desc = [
        StrField('transferDataRequestParameter', b"", fmt="B")
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return isinstance(other, KWP_RTE)


bind_layers(KWP, KWP_RTEPR, service=0x77)


# ######################### KWP_NR ###################################
class KWP_NR(Packet):
    negativeResponseCodes = {
        0x00: 'positiveResponse',
        0x10: 'generalReject',
        0x11: 'serviceNotSupported',
        0x12: 'subFunctionNotSupported-InvalidFormat',
        0x21: 'busyRepeatRequest',
        0x22: 'conditionsNotCorrect-RequestSequenceError',
        0x23: 'routineNotComplete',
        0x31: 'requestOutOfRange',
        0x33: 'securityAccessDenied-SecurityAccessRequested',
        0x35: 'invalidKey',
        0x36: 'exceedNumberOfAttempts',
        0x37: 'requiredTimeDelayNotExpired',
        0x40: 'downloadNotAccepted',
        0x50: 'uploadNotAccepted',
        0x71: 'transferSuspended',
        0x78: 'requestCorrectlyReceived-ResponsePending',
        0x80: 'subFunctionNotSupportedInActiveDiagnosticSession',
        0x9A: 'dataDecompressionFailed',
        0x9B: 'dataDecryptionFailed',
        0xA0: 'EcuNotResponding',
        0xA1: 'EcuAddressUnknown'
    }
    name = 'NegativeResponse'
    fields_desc = [
        XByteEnumField('requestServiceId', 0, KWP.services),
        ByteEnumField('negativeResponseCode', 0, negativeResponseCodes)
    ]

    def answers(self, other):
        # type: (Packet) -> int
        return self.requestServiceId == other.service and \
            (self.negativeResponseCode != 0x78 or
             conf.contribs['KWP']['treat-response-pending-as-answer'])


bind_layers(KWP, KWP_NR, service=0x7f)


# ##################################################################
# ######################## UTILS ###################################
# ##################################################################

class KWP_TesterPresentSender(PeriodicSenderThread):
    def __init__(self, sock, pkt=KWP() / KWP_TP(), interval=2):
        # type: (Any, _PacketIterable, float) -> None
        """ Thread that sends TesterPresent packets periodically

        :param sock: socket where packet is sent periodically
        :param pkt: packet to send
        :param interval: interval between two packets
        """
        PeriodicSenderThread.__init__(self, sock, pkt, interval)

    def run(self):
        # type: () -> None
        while not self._stopped.is_set():
            for p in self._pkts:
                self._socket.sr1(p, timeout=0.3, verbose=False)
                time.sleep(self._interval)
