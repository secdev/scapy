#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

import struct
from scapy.fields import ByteEnumField, StrField, ConditionalField, \
    BitEnumField, BitField, XByteField, FieldListField, \
    XShortField, X3BytesField, XIntField, ByteField, \
    ShortField, ObservableDict, XShortEnumField, XByteEnumField
from scapy.packet import Packet, bind_layers

"""
UDS
"""


class UDS(Packet):
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
         0x7f: 'NegativeResponse'})
    name = 'UDS'
    fields_desc = [
        XByteEnumField('service', 0, services)
    ]

    def answers(self, other):
        """DEV: true if self is an answer from other"""
        if other.__class__ == self.__class__:
            return (other.service + 0x40) == self.service or \
                   (self.service == 0x7f and
                    self.requestServiceId == other.service)
        return 0

    def hashret(self):
        if self.service == 0x7f:
            return struct.pack('B', self.requestServiceId)
        return struct.pack('B', self.service & ~0x40)


# ########################DSC###################################
class UDS_DSC(Packet):
    diagnosticSessionTypes = {
        0x00: 'ISOSAEReserved',
        0x01: 'defaultSession',
        0x02: 'programmingSession',
        0x03: 'extendedDiagnosticSession',
        0x04: 'safetySystemDiagnosticSession',
        0x7F: 'ISOSAEReserved'}
    name = 'DiagnosticSessionControl'
    fields_desc = [
        ByteEnumField('diagnosticSessionType', 0, diagnosticSessionTypes)
    ]


bind_layers(UDS, UDS_DSC, service=0x10)


class UDS_DSCPR(Packet):
    name = 'DiagnosticSessionControlPositiveResponse'
    fields_desc = [
        ByteEnumField('diagnosticSessionType', 0,
                      UDS_DSC.diagnosticSessionTypes),
        StrField('sessionParameterRecord', B"")
    ]


bind_layers(UDS, UDS_DSCPR, service=0x50)


# #########################ER###################################
class UDS_ER(Packet):
    resetTypes = {
        0x00: 'ISOSAEReserved',
        0x01: 'hardReset',
        0x02: 'keyOffOnReset',
        0x03: 'softReset',
        0x04: 'enableRapidPowerShutDown',
        0x05: 'disableRapidPowerShutDown',
        0x7F: 'ISOSAEReserved'}
    name = 'ECUReset'
    fields_desc = [
        ByteEnumField('resetType', 0, resetTypes)
    ]


bind_layers(UDS, UDS_ER, service=0x11)


class UDS_ERPR(Packet):
    name = 'ECUResetPositiveResponse'
    fields_desc = [
        ByteEnumField('resetType', 0, UDS_ER.resetTypes),
        ConditionalField(ByteField('powerDownTime', 0),
                         lambda pkt: pkt.resetType == 0x04)
    ]


bind_layers(UDS, UDS_ERPR, service=0x51)


# #########################SA###################################
class UDS_SA(Packet):
    name = 'SecurityAccess'
    fields_desc = [
        ByteField('securityAccessType', 0),
        ConditionalField(StrField('securityAccessDataRecord', B""),
                         lambda pkt: pkt.securityAccessType % 2 == 1),
        ConditionalField(StrField('securityKey', B""),
                         lambda pkt: pkt.securityAccessType % 2 == 0)
    ]


bind_layers(UDS, UDS_SA, service=0x27)


class UDS_SAPR(Packet):
    name = 'SecurityAccessPositiveResponse'
    fields_desc = [
        ByteField('securityAccessType', 0),
        ConditionalField(StrField('securitySeed', B""),
                         lambda pkt: pkt.securityAccessType % 2 == 1),
    ]


bind_layers(UDS, UDS_SAPR, service=0x67)


# #########################CC###################################
class UDS_CC(Packet):
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


bind_layers(UDS, UDS_CC, service=0x28)


class UDS_CCPR(Packet):
    name = 'CommunicationControlPositiveResponse'
    fields_desc = [
        ByteEnumField('controlType', 0, UDS_CC.controlTypes)
    ]


bind_layers(UDS, UDS_CCPR, service=0x68)


# #########################TP###################################
class UDS_TP(Packet):
    name = 'TesterPresent'
    fields_desc = [
        ByteField('subFunction', 0)
    ]


bind_layers(UDS, UDS_TP, service=0x3E)


class UDS_TPPR(Packet):
    name = 'TesterPresentPositiveResponse'
    fields_desc = [
        ByteField('zeroSubFunction', 0)
    ]


bind_layers(UDS, UDS_TPPR, service=0x7E)


# #########################ATP###################################
class UDS_ATP(Packet):
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
        ConditionalField(StrField('timingParameterRequestRecord', B""),
                         lambda pkt: pkt.timingParameterAccessType == 0x4)
    ]


bind_layers(UDS, UDS_ATP, service=0x83)


class UDS_ATPPR(Packet):
    name = 'AccessTimingParameterPositiveResponse'
    fields_desc = [
        ByteEnumField('timingParameterAccessType', 0,
                      UDS_ATP.timingParameterAccessTypes),
        ConditionalField(StrField('timingParameterResponseRecord', B""),
                         lambda pkt: pkt.timingParameterAccessType == 0x3)
    ]


bind_layers(UDS, UDS_ATPPR, service=0xC3)


# #########################SDT###################################
class UDS_SDT(Packet):
    name = 'SecuredDataTransmission'
    fields_desc = [
        StrField('securityDataRequestRecord', B"")
    ]


bind_layers(UDS, UDS_SDT, service=0x84)


class UDS_SDTPR(Packet):
    name = 'SecuredDataTransmissionPositiveResponse'
    fields_desc = [
        StrField('securityDataResponseRecord', B"")
    ]


bind_layers(UDS, UDS_SDTPR, service=0xC4)


# #########################CDTCS###################################
class UDS_CDTCS(Packet):
    DTCSettingTypes = {
        0: 'ISOSAEReserved',
        1: 'on',
        2: 'off'
    }
    name = 'ControlDTCSetting'
    fields_desc = [
        ByteEnumField('DTCSettingType', 0, DTCSettingTypes),
        StrField('DTCSettingControlOptionRecord', B"")
    ]


bind_layers(UDS, UDS_CDTCS, service=0x85)


class UDS_CDTCSPR(Packet):
    name = 'ControlDTCSettingPositiveResponse'
    fields_desc = [
        ByteEnumField('DTCSettingType', 0, UDS_CDTCS.DTCSettingTypes)
    ]


bind_layers(UDS, UDS_CDTCSPR, service=0xC5)


# #########################ROE###################################
# TODO: improve this protocol implementation
class UDS_ROE(Packet):
    eventTypes = {
        0: 'doNotStoreEvent',
        1: 'storeEvent'
    }
    name = 'ResponseOnEvent'
    fields_desc = [
        ByteEnumField('eventType', 0, eventTypes),
        ByteField('eventWindowTime', 0),
        StrField('eventTypeRecord', B"")
    ]


bind_layers(UDS, UDS_ROE, service=0x86)


class UDS_ROEPR(Packet):
    name = 'ResponseOnEventPositiveResponse'
    fields_desc = [
        ByteEnumField('eventType', 0, UDS_ROE.eventTypes),
        ByteField('numberOfIdentifiedEvents', 0),
        ByteField('eventWindowTime', 0),
        StrField('eventTypeRecord', B"")
    ]


bind_layers(UDS, UDS_ROEPR, service=0xC6)


# #########################LC###################################
class UDS_LC(Packet):
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


bind_layers(UDS, UDS_LC, service=0x87)


class UDS_LCPR(Packet):
    name = 'LinkControlPositiveResponse'
    fields_desc = [
        ByteEnumField('linkControlType', 0, UDS_LC.linkControlTypes)
    ]


bind_layers(UDS, UDS_LCPR, service=0xC7)


# #########################RDBI###################################
class UDS_RDBI(Packet):
    dataIdentifiers = ObservableDict()
    name = 'ReadDataByIdentifier'
    fields_desc = [
        FieldListField("identifiers", [],
                       XShortEnumField('dataIdentifier', 0,
                                       dataIdentifiers))
    ]


bind_layers(UDS, UDS_RDBI, service=0x22)


class UDS_RDBIPR(Packet):
    name = 'ReadDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0,
                        UDS_RDBI.dataIdentifiers),
    ]


bind_layers(UDS, UDS_RDBIPR, service=0x62)


# #########################RMBA###################################
class UDS_RMBA(Packet):
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


bind_layers(UDS, UDS_RMBA, service=0x23)


class UDS_RMBAPR(Packet):
    name = 'ReadMemoryByAddressPositiveResponse'
    fields_desc = [
        StrField('dataRecord', None, fmt="B")
    ]


bind_layers(UDS, UDS_RMBAPR, service=0x63)


# #########################RSDBI###################################
class UDS_RSDBI(Packet):
    name = 'ReadScalingDataByIdentifier'
    fields_desc = [
        XShortField('dataIdentifier', 0)
    ]


bind_layers(UDS, UDS_RSDBI, service=0x24)


# TODO: Implement correct scaling here, instead of using just the dataRecord
class UDS_RSDBIPR(Packet):
    name = 'ReadScalingDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortField('dataIdentifier', 0),
        ByteField('scalingByte', 0),
        StrField('dataRecord', None, fmt="B")
    ]


bind_layers(UDS, UDS_RSDBIPR, service=0x64)


# #########################RDBPI###################################
class UDS_RDBPI(Packet):
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
        StrField('furtherPeriodicDataIdentifier', 0, fmt="B")
    ]


bind_layers(UDS, UDS_RDBPI, service=0x2A)


# TODO: Implement correct scaling here, instead of using just the dataRecord
class UDS_RDBPIPR(Packet):
    name = 'ReadDataByPeriodicIdentifierPositiveResponse'
    fields_desc = [
        ByteField('periodicDataIdentifier', 0),
        StrField('dataRecord', None, fmt="B")
    ]


bind_layers(UDS, UDS_RDBPIPR, service=0x6A)


# #########################DDDI###################################
# TODO: Implement correct interpretation here,
# instead of using just the dataRecord
class UDS_DDDI(Packet):
    name = 'DynamicallyDefineDataIdentifier'
    fields_desc = [
        ByteField('definitionMode', 0),
        StrField('dataRecord', 0, fmt="B")
    ]


bind_layers(UDS, UDS_DDDI, service=0x2C)


class UDS_DDDIPR(Packet):
    name = 'DynamicallyDefineDataIdentifierPositiveResponse'
    fields_desc = [
        ByteField('definitionMode', 0),
        XShortField('dynamicallyDefinedDataIdentifier', 0)
    ]


bind_layers(UDS, UDS_DDDIPR, service=0x6C)


# #########################WDBI###################################
class UDS_WDBI(Packet):
    name = 'WriteDataByIdentifier'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0,
                        UDS_RDBI.dataIdentifiers),
        StrField('dataRecord', 0, fmt="B")
    ]


bind_layers(UDS, UDS_WDBI, service=0x2E)


class UDS_WDBIPR(Packet):
    name = 'WriteDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0,
                        UDS_RDBI.dataIdentifiers),
    ]


bind_layers(UDS, UDS_WDBIPR, service=0x6E)


# #########################WMBA###################################
class UDS_WMBA(Packet):
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
        StrField('dataRecord', b'\x00', fmt="B"),

    ]


bind_layers(UDS, UDS_WMBA, service=0x3D)


class UDS_WMBAPR(Packet):
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


bind_layers(UDS, UDS_WMBAPR, service=0x7D)


# #########################CDTCI###################################
class UDS_CDTCI(Packet):
    name = 'ClearDiagnosticInformation'
    fields_desc = [
        ByteField('groupOfDTCHighByte', 0),
        ByteField('groupOfDTCMiddleByte', 0),
        ByteField('groupOfDTCLowByte', 0),
    ]


bind_layers(UDS, UDS_CDTCI, service=0x14)


# #########################RDTCI###################################
class UDS_RDTCI(Packet):
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
        ConditionalField(XByteField('DTCStatusMask', 0),
                         lambda pkt: pkt.reportType in [0x01, 0x02, 0x0f,
                                                        0x11, 0x12, 0x13]),
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
                         lambda pkt: pkt.reportType in [0x6, 0x10]),
        ConditionalField(ByteField('DTCSeverityMask', 0),
                         lambda pkt: pkt.reportType in [0x07, 0x08]),
        ConditionalField(ByteField('DTCStatusMask', 0),
                         lambda pkt: pkt.reportType in [0x07, 0x08]),
    ]


bind_layers(UDS, UDS_RDTCI, service=0x19)


class UDS_RDTCIPR(Packet):
    name = 'ReadDTCInformationPositiveResponse'
    fields_desc = [
        ByteEnumField('reportType', 0, UDS_RDTCI.reportTypes),
        ConditionalField(XByteField('DTCStatusAvailabilityMask', 0),
                         lambda pkt: pkt.reportType in [0x01, 0x07, 0x11,
                                                        0x12, 0x02, 0x0A,
                                                        0x0B, 0x0C, 0x0D,
                                                        0x0E, 0x0F, 0x13,
                                                        0x15]),
        ConditionalField(ByteEnumField('DTCFormatIdentifier', 0,
                                       {0: 'ISO15031-6DTCFormat',
                                        1: 'UDS-1DTCFormat',
                                        2: 'SAEJ1939-73DTCFormat',
                                        3: 'ISO11992-4DTCFormat'}),
                         lambda pkt: pkt.reportType in [0x01, 0x07,
                                                        0x11, 0x12]),
        ConditionalField(ShortField('DTCCount', 0),
                         lambda pkt: pkt.reportType in [0x01, 0x07,
                                                        0x11, 0x12]),
        ConditionalField(StrField('DTCAndStatusRecord', 0),
                         lambda pkt: pkt.reportType in [0x02, 0x0A, 0x0B,
                                                        0x0C, 0x0D, 0x0E,
                                                        0x0F, 0x13, 0x15]),
        ConditionalField(StrField('dataRecord', 0),
                         lambda pkt: pkt.reportType in [0x03, 0x04, 0x05,
                                                        0x06, 0x08, 0x09,
                                                        0x10, 0x14])
    ]


bind_layers(UDS, UDS_RDTCIPR, service=0x59)


# #########################RC###################################
class UDS_RC(Packet):
    routineControlTypes = {
        0: 'ISOSAEReserved',
        1: 'startRoutine',
        2: 'stopRoutine',
        3: 'requestRoutineResults'
    }
    name = 'RoutineControl'
    fields_desc = [
        ByteEnumField('routineControlType', 0, routineControlTypes),
        XShortField('routineIdentifier', 0),
        StrField('routineControlOptionRecord', 0, fmt="B"),
    ]


bind_layers(UDS, UDS_RC, service=0x31)


class UDS_RCPR(Packet):
    name = 'RoutineControlPositiveResponse'
    fields_desc = [
        ByteEnumField('routineControlType', 0,
                      UDS_RC.routineControlTypes),
        XShortField('routineIdentifier', 0),
        StrField('routineStatusRecord', 0, fmt="B"),
    ]


bind_layers(UDS, UDS_RCPR, service=0x71)


# #########################RD###################################
class UDS_RD(Packet):
    dataFormatIdentifiers = {
        0: 'noCompressionNoEncryption'
    }
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


bind_layers(UDS, UDS_RD, service=0x34)


class UDS_RDPR(Packet):
    name = 'RequestDownloadPositiveResponse'
    fields_desc = [
        ByteEnumField('routineControlType', 0,
                      UDS_RC.routineControlTypes),
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        StrField('maxNumberOfBlockLength', 0, fmt="B"),
    ]


bind_layers(UDS, UDS_RDPR, service=0x74)


# #########################RU###################################
class UDS_RU(Packet):
    name = 'RequestUpload'
    fields_desc = [
        ByteEnumField('dataFormatIdentifier', 0,
                      UDS_RD.dataFormatIdentifiers),
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


bind_layers(UDS, UDS_RU, service=0x35)


class UDS_RUPR(Packet):
    name = 'RequestUploadPositiveResponse'
    fields_desc = [
        ByteEnumField('routineControlType', 0,
                      UDS_RC.routineControlTypes),
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        StrField('maxNumberOfBlockLength', 0, fmt="B"),
    ]


bind_layers(UDS, UDS_RUPR, service=0x75)


# #########################TD###################################
class UDS_TD(Packet):
    name = 'TransferData'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferRequestParameterRecord', 0, fmt="B")
    ]


bind_layers(UDS, UDS_TD, service=0x36)


class UDS_TDPR(Packet):
    name = 'TransferDataPositiveResponse'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferResponseParameterRecord', 0, fmt="B")
    ]


bind_layers(UDS, UDS_TDPR, service=0x76)


# #########################RTE###################################
class UDS_RTE(Packet):
    name = 'RequestTransferExit'
    fields_desc = [
        StrField('transferRequestParameterRecord', 0, fmt="B")
    ]


bind_layers(UDS, UDS_RTE, service=0x37)


class UDS_RTEPR(Packet):
    name = 'RequestTransferExitPositiveResponse'
    fields_desc = [
        StrField('transferResponseParameterRecord', 0, fmt="B")
    ]


bind_layers(UDS, UDS_RTEPR, service=0x77)


# #########################IOCBI###################################
class UDS_IOCBI(Packet):
    name = 'InputOutputControlByIdentifier'
    fields_desc = [
        XShortField('dataIdentifier', 0),
        ByteField('controlOptionRecord', 0),
        StrField('controlEnableMaskRecord', 0, fmt="B")
    ]


bind_layers(UDS, UDS_IOCBI, service=0x2F)


class UDS_IOCBIPR(Packet):
    name = 'InputOutputControlByIdentifierPositiveResponse'
    fields_desc = [
        XShortField('dataIdentifier', 0),
        StrField('controlStatusRecord', 0, fmt="B")
    ]


bind_layers(UDS, UDS_IOCBIPR, service=0x6F)


# #########################NRC###################################
class UDS_NRC(Packet):
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
    name = 'NegativeResponseCode'
    fields_desc = [
        XByteEnumField('requestServiceId', 0, UDS.services),
        ByteEnumField('negativeResponseCode', 0, negativeResponseCodes)
    ]


bind_layers(UDS, UDS_NRC, service=0x7f)
