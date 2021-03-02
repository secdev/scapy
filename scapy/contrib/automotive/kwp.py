# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Keyword Protocol 2000 (KWP2000) / ISO 14230
# scapy.contrib.status = loads

import struct
import time

from scapy.fields import ByteEnumField, StrField, ConditionalField, \
    BitEnumField, BitField, XByteField, FieldListField, \
    XShortField, X3BytesField, XIntField, ByteField, \
    ShortField, ObservableDict, XShortEnumField, XByteEnumField, StrLenField, \
    FieldLenField
from scapy.packet import Packet, bind_layers, NoPayload
from scapy.config import conf
from scapy.error import log_loading
from scapy.utils import PeriodicSenderThread
from scapy.contrib.isotp import ISOTP
from scapy.compat import Dict, Union

"""
KWP2000
"""

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
        {0x10: 'DiagnosticSessionControl',
         0x11: 'ECUReset',
         0x14: 'ClearDiagnosticInformation',
         0x19: 'ReadDTCInformation',
         0x22: 'ReadDataByIdentifier',
         0x23: 'ReadMemoryByAddress',
         0x24: 'ReadScalingDataByIdentifier',
         0x27: 'SecurityAccess',
         0x28: 'CommunicationControl',
         0x2A: 'ReadDataPeriodicIdentifier',
         0x2C: 'DynamicallyDefineDataIdentifier',
         0x2E: 'WriteDataByIdentifier',
         0x2F: 'InputOutputControlByIdentifier',
         0x31: 'RoutineControl',
         0x34: 'RequestDownload',
         0x35: 'RequestUpload',
         0x36: 'TransferData',
         0x37: 'RequestTransferExit',
         0x38: 'RequestFileTransfer',
         0x3D: 'WriteMemoryByAddress',
         0x3E: 'TesterPresent',
         0x50: 'DiagnosticSessionControlPositiveResponse',
         0x51: 'ECUResetPositiveResponse',
         0x54: 'ClearDiagnosticInformationPositiveResponse',
         0x59: 'ReadDTCInformationPositiveResponse',
         0x62: 'ReadDataByIdentifierPositiveResponse',
         0x63: 'ReadMemoryByAddressPositiveResponse',
         0x64: 'ReadScalingDataByIdentifierPositiveResponse',
         0x67: 'SecurityAccessPositiveResponse',
         0x68: 'CommunicationControlPositiveResponse',
         0x6A: 'ReadDataPeriodicIdentifierPositiveResponse',
         0x6C: 'DynamicallyDefineDataIdentifierPositiveResponse',
         0x6E: 'WriteDataByIdentifierPositiveResponse',
         0x6F: 'InputOutputControlByIdentifierPositiveResponse',
         0x71: 'RoutineControlPositiveResponse',
         0x74: 'RequestDownloadPositiveResponse',
         0x75: 'RequestUploadPositiveResponse',
         0x76: 'TransferDataPositiveResponse',
         0x77: 'RequestTransferExitPositiveResponse',
         0x78: 'RequestFileTransferPositiveResponse',
         0x7D: 'WriteMemoryByAddressPositiveResponse',
         0x7E: 'TesterPresentPositiveResponse',
         0x83: 'AccessTimingParameter',
         0x84: 'SecuredDataTransmission',
         0x85: 'ControlDTCSetting',
         0x86: 'ResponseOnEvent',
         0x87: 'LinkControl',
         0xC3: 'AccessTimingParameterPositiveResponse',
         0xC4: 'SecuredDataTransmissionPositiveResponse',
         0xC5: 'ControlDTCSettingPositiveResponse',
         0xC6: 'ResponseOnEventPositiveResponse',
         0xC7: 'LinkControlPositiveResponse',
         0x7f: 'NegativeResponse'})  # type: Dict[int, str]
    name = 'KWP'
    fields_desc = [
        XByteEnumField('service', 0, services)
    ]

    def answers(self, other):
        # type: (Union[KWP, Packet]) -> bool
        if other.__class__ != self.__class__:
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
        return struct.pack('B', self.service & ~0x40)


# ########################DSC###################################
class KWP_DSC(Packet):
    diagnosticSessionTypes = ObservableDict({
        0x00: 'ISOSAEReserved',
        0x01: 'defaultSession',
        0x02: 'programmingSession',
        0x03: 'extendedDiagnosticSession',
        0x04: 'safetySystemDiagnosticSession',
        0x7F: 'ISOSAEReserved'})
    name = 'DiagnosticSessionControl'
    fields_desc = [
        ByteEnumField('diagnosticSessionType', 0, diagnosticSessionTypes)
    ]


bind_layers(KWP, KWP_DSC, service=0x10)


class KWP_DSCPR(Packet):
    name = 'DiagnosticSessionControlPositiveResponse'
    fields_desc = [
        ByteEnumField('diagnosticSessionType', 0,
                      KWP_DSC.diagnosticSessionTypes),
        StrField('sessionParameterRecord', b"")
    ]

    def answers(self, other):
        return other.__class__ == KWP_DSC and \
            other.diagnosticSessionType == self.diagnosticSessionType


bind_layers(KWP, KWP_DSCPR, service=0x50)


# #########################ER###################################
class KWP_ER(Packet):
    resetTypes = {
        0x00: 'ISOSAEReserved',
        0x01: 'hardReset',
        0x02: 'keyOffOnReset',
        0x03: 'softReset',
        0x04: 'enableRapidPowerShutDown',
        0x05: 'disableRapidPowerShutDown',
        0x41: 'powerDown',
        0x7F: 'ISOSAEReserved'}
    name = 'ECUReset'
    fields_desc = [
        ByteEnumField('resetType', 0, resetTypes)
    ]


bind_layers(KWP, KWP_ER, service=0x11)


class KWP_ERPR(Packet):
    name = 'ECUResetPositiveResponse'
    fields_desc = [
        ByteEnumField('resetType', 0, KWP_ER.resetTypes),
        ConditionalField(ByteField('powerDownTime', 0),
                         lambda pkt: pkt.resetType == 0x04)
    ]

    def answers(self, other):
        return other.__class__ == KWP_ER


bind_layers(KWP, KWP_ERPR, service=0x51)


# #########################SA###################################
class KWP_SA(Packet):
    name = 'SecurityAccess'
    fields_desc = [
        ByteField('securityAccessType', 0),
        ConditionalField(StrField('securityAccessDataRecord', b""),
                         lambda pkt: pkt.securityAccessType % 2 == 1),
        ConditionalField(StrField('securityKey', b""),
                         lambda pkt: pkt.securityAccessType % 2 == 0)
    ]


bind_layers(KWP, KWP_SA, service=0x27)


class KWP_SAPR(Packet):
    name = 'SecurityAccessPositiveResponse'
    fields_desc = [
        ByteField('securityAccessType', 0),
        ConditionalField(StrField('securitySeed', b""),
                         lambda pkt: pkt.securityAccessType % 2 == 1),
    ]

    def answers(self, other):
        return other.__class__ == KWP_SA \
            and other.securityAccessType == self.securityAccessType


bind_layers(KWP, KWP_SAPR, service=0x67)


# #########################CC###################################
class KWP_CC(Packet):
    controlTypes = {
        0x00: 'enableRxAndTx',
        0x01: 'enableRxAndDisableTx',
        0x02: 'disableRxAndEnableTx',
        0x03: 'disableRxAndTx'
    }
    name = 'CommunicationControl'
    fields_desc = [
        ByteEnumField('controlType', 0, controlTypes),
        BitEnumField('communicationType0', 0, 2,
                     {0: 'ISOSAEReserved',
                      1: 'normalCommunicationMessages',
                      2: 'networkManagmentCommunicationMessages',
                      3: 'networkManagmentCommunicationMessages and '
                         'normalCommunicationMessages'}),
        BitField('communicationType1', 0, 2),
        BitEnumField('communicationType2', 0, 4,
                     {0: 'Disable/Enable specified communication Type',
                      1: 'Disable/Enable specific subnet',
                      2: 'Disable/Enable specific subnet',
                      3: 'Disable/Enable specific subnet',
                      4: 'Disable/Enable specific subnet',
                      5: 'Disable/Enable specific subnet',
                      6: 'Disable/Enable specific subnet',
                      7: 'Disable/Enable specific subnet',
                      8: 'Disable/Enable specific subnet',
                      9: 'Disable/Enable specific subnet',
                      10: 'Disable/Enable specific subnet',
                      11: 'Disable/Enable specific subnet',
                      12: 'Disable/Enable specific subnet',
                      13: 'Disable/Enable specific subnet',
                      14: 'Disable/Enable specific subnet',
                      15: 'Disable/Enable network'})
    ]


bind_layers(KWP, KWP_CC, service=0x28)


class KWP_CCPR(Packet):
    name = 'CommunicationControlPositiveResponse'
    fields_desc = [
        ByteEnumField('controlType', 0, KWP_CC.controlTypes)
    ]

    def answers(self, other):
        return other.__class__ == KWP_CC \
            and other.controlType == self.controlType


bind_layers(KWP, KWP_CCPR, service=0x68)


# #########################TP###################################
class KWP_TP(Packet):
    name = 'TesterPresent'
    fields_desc = [
        ByteField('subFunction', 0)
    ]


bind_layers(KWP, KWP_TP, service=0x3E)


class KWP_TPPR(Packet):
    name = 'TesterPresentPositiveResponse'
    fields_desc = [
        ByteField('zeroSubFunction', 0)
    ]

    def answers(self, other):
        return other.__class__ == KWP_TP


bind_layers(KWP, KWP_TPPR, service=0x7E)


# #########################ATP###################################
class KWP_ATP(Packet):
    timingParameterAccessTypes = {
        0: 'ISOSAEReserved',
        1: 'readExtendedTimingParameterSet',
        2: 'setTimingParametersToDefaultValues',
        3: 'readCurrentlyActiveTimingParameters',
        4: 'setTimingParametersToGivenValues'
    }
    name = 'AccessTimingParameter'
    fields_desc = [
        ByteEnumField('timingParameterAccessType', 0,
                      timingParameterAccessTypes),
        ConditionalField(StrField('timingParameterRequestRecord', b""),
                         lambda pkt: pkt.timingParameterAccessType == 0x4)
    ]


bind_layers(KWP, KWP_ATP, service=0x83)


class KWP_ATPPR(Packet):
    name = 'AccessTimingParameterPositiveResponse'
    fields_desc = [
        ByteEnumField('timingParameterAccessType', 0,
                      KWP_ATP.timingParameterAccessTypes),
        ConditionalField(StrField('timingParameterResponseRecord', b""),
                         lambda pkt: pkt.timingParameterAccessType == 0x3)
    ]

    def answers(self, other):
        return other.__class__ == KWP_ATP \
            and other.timingParameterAccessType == \
            self.timingParameterAccessType


bind_layers(KWP, KWP_ATPPR, service=0xC3)


# #########################SDT###################################
class KWP_SDT(Packet):
    name = 'SecuredDataTransmission'
    fields_desc = [
        StrField('securityDataRequestRecord', b"")
    ]


bind_layers(KWP, KWP_SDT, service=0x84)


class KWP_SDTPR(Packet):
    name = 'SecuredDataTransmissionPositiveResponse'
    fields_desc = [
        StrField('securityDataResponseRecord', b"")
    ]

    def answers(self, other):
        return other.__class__ == KWP_SDT


bind_layers(KWP, KWP_SDTPR, service=0xC4)


# #########################CDTCS###################################
class KWP_CDTCS(Packet):
    DTCSettingTypes = {
        0: 'ISOSAEReserved',
        1: 'on',
        2: 'off'
    }
    name = 'ControlDTCSetting'
    fields_desc = [
        ByteEnumField('DTCSettingType', 0, DTCSettingTypes),
        StrField('DTCSettingControlOptionRecord', b"")
    ]


bind_layers(KWP, KWP_CDTCS, service=0x85)


class KWP_CDTCSPR(Packet):
    name = 'ControlDTCSettingPositiveResponse'
    fields_desc = [
        ByteEnumField('DTCSettingType', 0, KWP_CDTCS.DTCSettingTypes)
    ]

    def answers(self, other):
        return other.__class__ == KWP_CDTCS


bind_layers(KWP, KWP_CDTCSPR, service=0xC5)


# #########################ROE###################################
# TODO: improve this protocol implementation
class KWP_ROE(Packet):
    eventTypes = {
        0: 'doNotStoreEvent',
        1: 'storeEvent'
    }
    name = 'ResponseOnEvent'
    fields_desc = [
        ByteEnumField('eventType', 0, eventTypes),
        ByteField('eventWindowTime', 0),
        StrField('eventTypeRecord', b"")
    ]


bind_layers(KWP, KWP_ROE, service=0x86)


class KWP_ROEPR(Packet):
    name = 'ResponseOnEventPositiveResponse'
    fields_desc = [
        ByteEnumField('eventType', 0, KWP_ROE.eventTypes),
        ByteField('numberOfIdentifiedEvents', 0),
        ByteField('eventWindowTime', 0),
        StrField('eventTypeRecord', b"")
    ]

    def answers(self, other):
        return other.__class__ == KWP_ROE \
            and other.eventType == self.eventType


bind_layers(KWP, KWP_ROEPR, service=0xC6)


# #########################LC###################################
class KWP_LC(Packet):
    linkControlTypes = {
        0: 'ISOSAEReserved',
        1: 'verifyBaudrateTransitionWithFixedBaudrate',
        2: 'verifyBaudrateTransitionWithSpecificBaudrate',
        3: 'transitionBaudrate'
    }
    name = 'LinkControl'
    fields_desc = [
        ByteEnumField('linkControlType', 0, linkControlTypes),
        ConditionalField(ByteField('baudrateIdentifier', 0),
                         lambda pkt: pkt.linkControlType == 0x1),
        ConditionalField(ByteField('baudrateHighByte', 0),
                         lambda pkt: pkt.linkControlType == 0x2),
        ConditionalField(ByteField('baudrateMiddleByte', 0),
                         lambda pkt: pkt.linkControlType == 0x2),
        ConditionalField(ByteField('baudrateLowByte', 0),
                         lambda pkt: pkt.linkControlType == 0x2)
    ]


bind_layers(KWP, KWP_LC, service=0x87)


class KWP_LCPR(Packet):
    name = 'LinkControlPositiveResponse'
    fields_desc = [
        ByteEnumField('linkControlType', 0, KWP_LC.linkControlTypes)
    ]

    def answers(self, other):
        return other.__class__ == KWP_LC \
            and other.linkControlType == self.linkControlType


bind_layers(KWP, KWP_LCPR, service=0xC7)


# #########################RDBI###################################
class KWP_RDBI(Packet):
    dataIdentifiers = ObservableDict()
    name = 'ReadDataByIdentifier'
    fields_desc = [
        FieldListField("identifiers", None,
                       XShortEnumField('dataIdentifier', 0,
                                       dataIdentifiers))
    ]


bind_layers(KWP, KWP_RDBI, service=0x22)


class KWP_RDBIPR(Packet):
    name = 'ReadDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0,
                        KWP_RDBI.dataIdentifiers),
    ]

    def answers(self, other):
        return other.__class__ == KWP_RDBI \
            and self.dataIdentifier in other.identifiers


bind_layers(KWP, KWP_RDBIPR, service=0x62)


# #########################RMBA###################################
class KWP_RMBA(Packet):
    name = 'ReadMemoryByAddress'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0),
                         lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0),
                         lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0),
                         lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0),
                         lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0),
                         lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0),
                         lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0),
                         lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0),
                         lambda pkt: pkt.memorySizeLen == 4),
    ]


bind_layers(KWP, KWP_RMBA, service=0x23)


class KWP_RMBAPR(Packet):
    name = 'ReadMemoryByAddressPositiveResponse'
    fields_desc = [
        StrField('dataRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == KWP_RMBA


bind_layers(KWP, KWP_RMBAPR, service=0x63)


# #########################RSDBI###################################
class KWP_RSDBI(Packet):
    name = 'ReadScalingDataByIdentifier'
    dataIdentifiers = ObservableDict()
    fields_desc = [
        XShortEnumField('dataIdentifier', 0, dataIdentifiers)
    ]


bind_layers(KWP, KWP_RSDBI, service=0x24)


# TODO: Implement correct scaling here, instead of using just the dataRecord
class KWP_RSDBIPR(Packet):
    name = 'ReadScalingDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0, KWP_RSDBI.dataIdentifiers),
        ByteField('scalingByte', 0),
        StrField('dataRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == KWP_RSDBI \
            and other.dataIdentifier == self.dataIdentifier


bind_layers(KWP, KWP_RSDBIPR, service=0x64)


# #########################RDBPI###################################
class KWP_RDBPI(Packet):
    transmissionModes = {
        0: 'ISOSAEReserved',
        1: 'sendAtSlowRate',
        2: 'sendAtMediumRate',
        3: 'sendAtFastRate',
        4: 'stopSending'
    }
    name = 'ReadDataByPeriodicIdentifier'
    fields_desc = [
        ByteEnumField('transmissionMode', 0, transmissionModes),
        ByteField('periodicDataIdentifier', 0),
        StrField('furtherPeriodicDataIdentifier', b"", fmt="B")
    ]


bind_layers(KWP, KWP_RDBPI, service=0x2A)


# TODO: Implement correct scaling here, instead of using just the dataRecord
class KWP_RDBPIPR(Packet):
    name = 'ReadDataByPeriodicIdentifierPositiveResponse'
    fields_desc = [
        ByteField('periodicDataIdentifier', 0),
        StrField('dataRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == KWP_RDBPI \
            and other.periodicDataIdentifier == self.periodicDataIdentifier


bind_layers(KWP, KWP_RDBPIPR, service=0x6A)


# #########################DDDI###################################
# TODO: Implement correct interpretation here,
# instead of using just the dataRecord
class KWP_DDDI(Packet):
    name = 'DynamicallyDefineDataIdentifier'
    subFunctions = {0x1: "defineByIdentifier",
                    0x2: "defineByMemoryAddress",
                    0x3: "clearDynamicallyDefinedDataIdentifier"}
    fields_desc = [
        ByteEnumField('subFunction', 0, subFunctions),
        StrField('dataRecord', b"", fmt="B")
    ]


bind_layers(KWP, KWP_DDDI, service=0x2C)


class KWP_DDDIPR(Packet):
    name = 'DynamicallyDefineDataIdentifierPositiveResponse'
    fields_desc = [
        ByteEnumField('subFunction', 0, KWP_DDDI.subFunctions),
        XShortField('dynamicallyDefinedDataIdentifier', 0)
    ]

    def answers(self, other):
        return other.__class__ == KWP_DDDI \
            and other.subFunction == self.subFunction


bind_layers(KWP, KWP_DDDIPR, service=0x6C)


# #########################WDBI###################################
class KWP_WDBI(Packet):
    name = 'WriteDataByIdentifier'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0,
                        KWP_RDBI.dataIdentifiers)
    ]


bind_layers(KWP, KWP_WDBI, service=0x2E)


class KWP_WDBIPR(Packet):
    name = 'WriteDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0,
                        KWP_RDBI.dataIdentifiers),
    ]

    def answers(self, other):
        return other.__class__ == KWP_WDBI \
            and other.dataIdentifier == self.dataIdentifier


bind_layers(KWP, KWP_WDBIPR, service=0x6E)


# #########################WMBA###################################
class KWP_WMBA(Packet):
    name = 'WriteMemoryByAddress'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0),
                         lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0),
                         lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0),
                         lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0),
                         lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0),
                         lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0),
                         lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0),
                         lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0),
                         lambda pkt: pkt.memorySizeLen == 4),
        StrField('dataRecord', b'', fmt="B"),

    ]


bind_layers(KWP, KWP_WMBA, service=0x3D)


class KWP_WMBAPR(Packet):
    name = 'WriteMemoryByAddressPositiveResponse'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0),
                         lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0),
                         lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0),
                         lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0),
                         lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0),
                         lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0),
                         lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0),
                         lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0),
                         lambda pkt: pkt.memorySizeLen == 4)
    ]

    def answers(self, other):
        return other.__class__ == KWP_WMBA \
            and other.memorySizeLen == self.memorySizeLen \
            and other.memoryAddressLen == self.memoryAddressLen


bind_layers(KWP, KWP_WMBAPR, service=0x7D)


# #########################CDTCI###################################
class KWP_CDTCI(Packet):
    name = 'ClearDiagnosticInformation'
    fields_desc = [
        ByteField('groupOfDTCHighByte', 0),
        ByteField('groupOfDTCMiddleByte', 0),
        ByteField('groupOfDTCLowByte', 0),
    ]


bind_layers(KWP, KWP_CDTCI, service=0x14)


class KWP_CDTCIPR(Packet):
    name = 'ClearDiagnosticInformationPositiveResponse'

    def answers(self, other):
        return other.__class__ == KWP_CDTCI


bind_layers(KWP, KWP_CDTCIPR, service=0x54)


# #########################RDTCI###################################
class KWP_RDTCI(Packet):
    reportTypes = {
        0: 'ISOSAEReserved',
        1: 'reportNumberOfDTCByStatusMask',
        2: 'reportDTCByStatusMask',
        3: 'reportDTCSnapshotIdentification',
        4: 'reportDTCSnapshotRecordByDTCNumber',
        5: 'reportDTCSnapshotRecordByRecordNumber',
        6: 'reportDTCExtendedDataRecordByDTCNumber',
        7: 'reportNumberOfDTCBySeverityMaskRecord',
        8: 'reportDTCBySeverityMaskRecord',
        9: 'reportSeverityInformationOfDTC',
        10: 'reportSupportedDTC',
        11: 'reportFirstTestFailedDTC',
        12: 'reportFirstConfirmedDTC',
        13: 'reportMostRecentTestFailedDTC',
        14: 'reportMostRecentConfirmedDTC',
        15: 'reportMirrorMemoryDTCByStatusMask',
        16: 'reportMirrorMemoryDTCExtendedDataRecordByDTCNumber',
        17: 'reportNumberOfMirrorMemoryDTCByStatusMask',
        18: 'reportNumberOfEmissionsRelatedOBDDTCByStatusMask',
        19: 'reportEmissionsRelatedOBDDTCByStatusMask',
        20: 'reportDTCFaultDetectionCounter',
        21: 'reportDTCWithPermanentStatus'
    }
    name = 'ReadDTCInformation'
    fields_desc = [
        ByteEnumField('reportType', 0, reportTypes),
        ConditionalField(ByteField('DTCSeverityMask', 0),
                         lambda pkt: pkt.reportType in [0x07, 0x08]),
        ConditionalField(XByteField('DTCStatusMask', 0),
                         lambda pkt: pkt.reportType in [
                             0x01, 0x02, 0x07, 0x08, 0x0f, 0x11, 0x12, 0x13]),
        ConditionalField(ByteField('DTCHighByte', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x6,
                                                        0x10, 0x09]),
        ConditionalField(ByteField('DTCMiddleByte', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x6,
                                                        0x10, 0x09]),
        ConditionalField(ByteField('DTCLowByte', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x6,
                                                        0x10, 0x09]),
        ConditionalField(ByteField('DTCSnapshotRecordNumber', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x5]),
        ConditionalField(ByteField('DTCExtendedDataRecordNumber', 0),
                         lambda pkt: pkt.reportType in [0x6, 0x10])
    ]


bind_layers(KWP, KWP_RDTCI, service=0x19)


class KWP_RDTCIPR(Packet):
    name = 'ReadDTCInformationPositiveResponse'
    fields_desc = [
        ByteEnumField('reportType', 0, KWP_RDTCI.reportTypes),
        ConditionalField(XByteField('DTCStatusAvailabilityMask', 0),
                         lambda pkt: pkt.reportType in [0x01, 0x07, 0x11,
                                                        0x12, 0x02, 0x0A,
                                                        0x0B, 0x0C, 0x0D,
                                                        0x0E, 0x0F, 0x13,
                                                        0x15]),
        ConditionalField(ByteEnumField('DTCFormatIdentifier', 0,
                                       {0: 'ISO15031-6DTCFormat',
                                        1: 'KWP-1DTCFormat',
                                        2: 'SAEJ1939-73DTCFormat',
                                        3: 'ISO11992-4DTCFormat'}),
                         lambda pkt: pkt.reportType in [0x01, 0x07,
                                                        0x11, 0x12]),
        ConditionalField(ShortField('DTCCount', 0),
                         lambda pkt: pkt.reportType in [0x01, 0x07,
                                                        0x11, 0x12]),
        ConditionalField(StrField('DTCAndStatusRecord', b""),
                         lambda pkt: pkt.reportType in [0x02, 0x0A, 0x0B,
                                                        0x0C, 0x0D, 0x0E,
                                                        0x0F, 0x13, 0x15]),
        ConditionalField(StrField('dataRecord', b""),
                         lambda pkt: pkt.reportType in [0x03, 0x04, 0x05,
                                                        0x06, 0x08, 0x09,
                                                        0x10, 0x14])
    ]

    def answers(self, other):
        return other.__class__ == KWP_RDTCI \
            and other.reportType == self.reportType


bind_layers(KWP, KWP_RDTCIPR, service=0x59)


# #########################RC###################################
class KWP_RC(Packet):
    routineControlTypes = {
        0: 'ISOSAEReserved',
        1: 'startRoutine',
        2: 'stopRoutine',
        3: 'requestRoutineResults'
    }
    routineControlIdentifiers = ObservableDict()
    name = 'RoutineControl'
    fields_desc = [
        ByteEnumField('routineControlType', 0, routineControlTypes),
        XShortEnumField('routineIdentifier', 0, routineControlIdentifiers)
    ]


bind_layers(KWP, KWP_RC, service=0x31)


class KWP_RCPR(Packet):
    name = 'RoutineControlPositiveResponse'
    fields_desc = [
        ByteEnumField('routineControlType', 0, KWP_RC.routineControlTypes),
        XShortEnumField('routineIdentifier', 0,
                        KWP_RC.routineControlIdentifiers),
    ]

    def answers(self, other):
        return other.__class__ == KWP_RC \
            and other.routineControlType == self.routineControlType \
            and other.routineIdentifier == self.routineIdentifier


bind_layers(KWP, KWP_RCPR, service=0x71)


# #########################RD###################################
class KWP_RD(Packet):
    dataFormatIdentifiers = ObservableDict({
        0: 'noCompressionNoEncryption'
    })
    name = 'RequestDownload'
    fields_desc = [
        ByteEnumField('dataFormatIdentifier', 0, dataFormatIdentifiers),
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0),
                         lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0),
                         lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0),
                         lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0),
                         lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0),
                         lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0),
                         lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0),
                         lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0),
                         lambda pkt: pkt.memorySizeLen == 4)
    ]


bind_layers(KWP, KWP_RD, service=0x34)


class KWP_RDPR(Packet):
    name = 'RequestDownloadPositiveResponse'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('reserved', 0, 4),
        StrField('maxNumberOfBlockLength', b"", fmt="B"),
    ]

    def answers(self, other):
        return other.__class__ == KWP_RD


bind_layers(KWP, KWP_RDPR, service=0x74)


# #########################RU###################################
class KWP_RU(Packet):
    name = 'RequestUpload'
    fields_desc = [
        ByteEnumField('dataFormatIdentifier', 0,
                      KWP_RD.dataFormatIdentifiers),
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0),
                         lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0),
                         lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0),
                         lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0),
                         lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0),
                         lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0),
                         lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0),
                         lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0),
                         lambda pkt: pkt.memorySizeLen == 4)
    ]


bind_layers(KWP, KWP_RU, service=0x35)


class KWP_RUPR(Packet):
    name = 'RequestUploadPositiveResponse'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('reserved', 0, 4),
        StrField('maxNumberOfBlockLength', b"", fmt="B"),
    ]

    def answers(self, other):
        return other.__class__ == KWP_RU


bind_layers(KWP, KWP_RUPR, service=0x75)


# #########################TD###################################
class KWP_TD(Packet):
    name = 'TransferData'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferRequestParameterRecord', b"", fmt="B")
    ]


bind_layers(KWP, KWP_TD, service=0x36)


class KWP_TDPR(Packet):
    name = 'TransferDataPositiveResponse'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferResponseParameterRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == KWP_TD \
            and other.blockSequenceCounter == self.blockSequenceCounter


bind_layers(KWP, KWP_TDPR, service=0x76)


# #########################RTE###################################
class KWP_RTE(Packet):
    name = 'RequestTransferExit'
    fields_desc = [
        StrField('transferRequestParameterRecord', b"", fmt="B")
    ]


bind_layers(KWP, KWP_RTE, service=0x37)


class KWP_RTEPR(Packet):
    name = 'RequestTransferExitPositiveResponse'
    fields_desc = [
        StrField('transferResponseParameterRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == KWP_RTE


bind_layers(KWP, KWP_RTEPR, service=0x77)


# #########################RFT###################################
class KWP_RFT(Packet):
    name = 'RequestFileTransfer'

    modeOfOperations = {
        0x00: "ISO/SAE Reserved",
        0x01: "Add File",
        0x02: "Delete File",
        0x03: "Replace File",
        0x04: "Read File",
        0x05: "Read Directory"
    }

    @staticmethod
    def _contains_file_size(packet):
        return packet.modeOfOperation not in [2, 4, 5]

    fields_desc = [
        XByteEnumField('modeOfOperation', 0, modeOfOperations),
        FieldLenField('filePathAndNameLength', 0,
                      length_of='filePathAndName', fmt='H'),
        StrLenField('filePathAndName', b"",
                    length_from=lambda p: p.filePathAndNameLength),
        ConditionalField(BitField('compressionMethod', 0, 4),
                         lambda p: p.modeOfOperation not in [2, 5]),
        ConditionalField(BitField('encryptingMethod', 0, 4),
                         lambda p: p.modeOfOperation not in [2, 5]),
        ConditionalField(FieldLenField('fileSizeParameterLength', 0, fmt="B",
                                       length_of='fileSizeUnCompressed'),
                         lambda p: KWP_RFT._contains_file_size(p)),
        ConditionalField(StrLenField('fileSizeUnCompressed', b"",
                                     length_from=lambda p:
                                     p.fileSizeParameterLength),
                         lambda p: KWP_RFT._contains_file_size(p)),
        ConditionalField(StrLenField('fileSizeCompressed', b"",
                                     length_from=lambda p:
                                     p.fileSizeParameterLength),
                         lambda p: KWP_RFT._contains_file_size(p))
    ]


bind_layers(KWP, KWP_RFT, service=0x38)


class KWP_RFTPR(Packet):
    name = 'RequestFileTransferPositiveResponse'

    @staticmethod
    def _contains_data_format_identifier(packet):
        return packet.modeOfOperation != 0x02

    fields_desc = [
        XByteEnumField('modeOfOperation', 0, KWP_RFT.modeOfOperations),
        ConditionalField(FieldLenField('lengthFormatIdentifier', 0,
                                       length_of='maxNumberOfBlockLength',
                                       fmt='B'),
                         lambda p: p.modeOfOperation != 2),
        ConditionalField(StrLenField('maxNumberOfBlockLength', b"",
                         length_from=lambda p: p.lengthFormatIdentifier),
                         lambda p: p.modeOfOperation != 2),
        ConditionalField(BitField('compressionMethod', 0, 4),
                         lambda p: p.modeOfOperation != 0x02),
        ConditionalField(BitField('encryptingMethod', 0, 4),
                         lambda p: p.modeOfOperation != 0x02),
        ConditionalField(FieldLenField('fileSizeOrDirInfoParameterLength', 0,
                         length_of='fileSizeUncompressedOrDirInfoLength'),
                         lambda p: p.modeOfOperation not in [1, 2, 3]),
        ConditionalField(StrLenField('fileSizeUncompressedOrDirInfoLength',
                                     b"",
                                     length_from=lambda p:
                                     p.fileSizeOrDirInfoParameterLength),
                         lambda p: p.modeOfOperation not in [1, 2, 3]),
        ConditionalField(StrLenField('fileSizeCompressed', b"",
                         length_from=lambda p:
                         p.fileSizeOrDirInfoParameterLength),
                         lambda p: p.modeOfOperation not in [1, 2, 3, 5]),
    ]

    def answers(self, other):
        return other.__class__ == KWP_RFT


bind_layers(KWP, KWP_RFTPR, service=0x78)


# #########################IOCBI###################################
class KWP_IOCBI(Packet):
    name = 'InputOutputControlByIdentifier'
    dataIdentifiers = ObservableDict()
    fields_desc = [
        XShortEnumField('dataIdentifier', 0, dataIdentifiers),
        ByteField('controlOptionRecord', 0),
        StrField('controlEnableMaskRecord', b"", fmt="B")
    ]


bind_layers(KWP, KWP_IOCBI, service=0x2F)


class KWP_IOCBIPR(Packet):
    name = 'InputOutputControlByIdentifierPositiveResponse'
    fields_desc = [
        XShortField('dataIdentifier', 0),
        StrField('controlStatusRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == KWP_IOCBI \
            and other.dataIdentifier == self.dataIdentifier


bind_layers(KWP, KWP_IOCBIPR, service=0x6F)


# #########################NR###################################
class KWP_NR(Packet):
    negativeResponseCodes = {
        0x00: 'positiveResponse',
        0x10: 'generalReject',
        0x11: 'serviceNotSupported',
        0x12: 'subFunctionNotSupported',
        0x13: 'incorrectMessageLengthOrInvalidFormat',
        0x14: 'responseTooLong',
        0x20: 'ISOSAEReserved',
        0x21: 'busyRepeatRequest',
        0x22: 'conditionsNotCorrect',
        0x23: 'ISOSAEReserved',
        0x24: 'requestSequenceError',
        0x25: 'noResponseFromSubnetComponent',
        0x26: 'failurePreventsExecutionOfRequestedAction',
        0x31: 'requestOutOfRange',
        0x33: 'securityAccessDenied',
        0x35: 'invalidKey',
        0x36: 'exceedNumberOfAttempts',
        0x37: 'requiredTimeDelayNotExpired',
        0x70: 'uploadDownloadNotAccepted',
        0x71: 'transferDataSuspended',
        0x72: 'generalProgrammingFailure',
        0x73: 'wrongBlockSequenceCounter',
        0x78: 'requestCorrectlyReceived-ResponsePending',
        0x7E: 'subFunctionNotSupportedInActiveSession',
        0x7F: 'serviceNotSupportedInActiveSession',
        0x80: 'ISOSAEReserved',
        0x81: 'rpmTooHigh',
        0x82: 'rpmTooLow',
        0x83: 'engineIsRunning',
        0x84: 'engineIsNotRunning',
        0x85: 'engineRunTimeTooLow',
        0x86: 'temperatureTooHigh',
        0x87: 'temperatureTooLow',
        0x88: 'vehicleSpeedTooHigh',
        0x89: 'vehicleSpeedTooLow',
        0x8a: 'throttle/PedalTooHigh',
        0x8b: 'throttle/PedalTooLow',
        0x8c: 'transmissionRangeNotInNeutral',
        0x8d: 'transmissionRangeNotInGear',
        0x8e: 'ISOSAEReserved',
        0x8f: 'brakeSwitch(es)NotClosed',
        0x90: 'shifterLeverNotInPark',
        0x91: 'torqueConverterClutchLocked',
        0x92: 'voltageTooHigh',
        0x93: 'voltageTooLow',
    }
    name = 'NegativeResponse'
    fields_desc = [
        XByteEnumField('requestServiceId', 0, KWP.services),
        ByteEnumField('negativeResponseCode', 0, negativeResponseCodes)
    ]

    def answers(self, other):
        return self.requestServiceId == other.service and \
            (self.negativeResponseCode != 0x78 or
             conf.contribs['KWP']['treat-response-pending-as-answer'])


bind_layers(KWP, KWP_NR, service=0x7f)


# ##################################################################
# ######################## UTILS ###################################
# ##################################################################


class KWP_TesterPresentSender(PeriodicSenderThread):
    def __init__(self, sock, pkt=KWP() / KWP_TP(), interval=2):
        """ Thread to send TesterPresent messages packets periodically

        Args:
            sock: socket where packet is sent periodically
            pkt: packet to send
            interval: interval between two packets
        """
        PeriodicSenderThread.__init__(self, sock, pkt, interval)

    def run(self):
        # type: () -> None
        while not self._stopped.is_set():
            for p in self._pkts:
                self._socket.sr1(p, timeout=0.3, verbose=False)
                time.sleep(self._interval)
