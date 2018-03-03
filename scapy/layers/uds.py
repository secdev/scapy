#! /usr/bin/env python

## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Nils Weiss <nils@we155.de>
## This program is published under a GPLv2 license

from scapy.fields import *
from scapy.packet import *

"""
Helper class to specify the protocol extendable 
for runtime imports of brand specific modifications or additions
"""


class ObservableDict(dict):
    def __init__(self, *args, **kw):
        self.observers = []
        super(ObservableDict, self).__init__(*args, **kw)

    def observe(self, observer):
        self.observers.append(observer)

    def __setitem__(self, key, value):
        for o in self.observers:
            o.notify(self, key, value)
        super(ObservableDict, self).__setitem__(key, value)

    def update(self, anotherDict):
        for k in anotherDict:
            self[k] = anotherDict[k]


"""
Custom Field definitions
"""


class XByteUpdateableEnumField(ByteEnumField):
    def __init__(self, name, default, enum):
        if type(enum) is ObservableDict:
            enum.observe(self)
        EnumField.__init__(self, name, default, enum, "B")

    def notify(self, enum, key, new):
        if conf.verb is True:
            print("At %s: Change to %s at 0x%x" % (self, new, key))
        EnumField.__init__(self, self.name, self.default, enum, "B")

    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x, VolatileValue) and x in self.i2s:
            return self.i2s[x]
        return lhex(x)


class XShortUpdateableEnumField(XShortEnumField):
    def __init__(self, name, default, enum):
        if type(enum) is ObservableDict:
            enum.observe(self)
        EnumField.__init__(self, name, default, enum, "H")

    def notify(self, enum, key, new):
        if conf.verb is True:
            print("At %s: Change to %s at 0x%x" % (self, new, key))
        EnumField.__init__(self, self.name, self.default, enum, "H")


"""
ISO14229
"""

class ISO14229(Packet):
    services = ObservableDict(
        {0x10: 'DiagnosticSessionControl',
         0x50: 'DiagnosticSessionControlPositiveResponse',
         0x11: 'ECUReset',
         0x51: 'ECUResetPositiveResponse',
         0x27: 'SecurityAccess',
         0x67: 'SecurityAccessPositiveResponse',
         0x28: 'CommunicationControl',
         0x68: 'CommunicationControlPositiveResponse',
         0x3E: 'TesterPresent',
         0x7E: 'TesterPresentPositiveResponse',
         0x83: 'AccessTimingParameter',
         0xC3: 'AccessTimingParameterPositiveResponse',
         0x84: 'SecuredDataTransmission',
         0xC4: 'SecuredDataTransmissionPositiveResponse',
         0x85: 'ControlDTCSetting',
         0xC5: 'ControlDTCSettingPositiveResponse',
         0x86: 'ResponseOnEvent',
         0xC6: 'ResponseOnEventPositiveResponse',
         0x87: 'LinkControl',
         0xC7: 'LinkControlPositiveResponse',
         0x22: 'ReadDataByIdentifier',
         0x62: 'ReadDataByIdentifierPositiveResponse',
         0x23: 'ReadMemoryByAddress',
         0x63: 'ReadMemoryByAddressPositiveResponse',
         0x24: 'ReadScalingDataByIdentifier',
         0x64: 'ReadScalingDataByIdentifierPositiveResponse',
         0x2A: 'ReadDataPeriodicIdentifier',
         0x6A: 'ReadDataPeriodicIdentifierPositiveResponse',
         0x2C: 'DynamicallyDefineDataIdentifier',
         0x6C: 'DynamicallyDefineDataIdentifierPositiveResponse',
         0x2E: 'WriteDataByIdentifier',
         0x6E: 'WriteDataByIdentifierPositiveResponse',
         0x3D: 'WriteMemoryByAddress',
         0x7D: 'WriteMemoryByAddressPositiveResponse',
         0x14: 'ClearDiagnosticInformation',
         0x54: 'ClearDiagnosticInformationPositiveResponse',
         0x19: 'ReadDTCInformation',
         0x59: 'ReadDTCInformationPositiveResponse',
         0x2F: 'InputOutputControlByIdentifier',
         0x6F: 'InputOutputControlByIdentifierPositiveResponse',
         0x31: 'RoutineControl',
         0x71: 'RoutineControlPositiveResponse',
         0x34: 'RequestDownload',
         0x74: 'RequestDownloadPositiveResponse',
         0x35: 'RequestUpload',
         0x75: 'RequestUploadPositiveResponse',
         0x36: 'TransferData',
         0x76: 'TransferDataPositiveResponse',
         0x37: 'RequestTransferExit',
         0x77: 'RequestTransferExitPositiveResponse',
         0x7f: 'NegativeResponse'})
    name = 'ISO14229'
    fields_desc = [
        XByteUpdateableEnumField('service', 0, services)
    ]

    def answers(self, other):
        """DEV: true if self is an answer from other"""
        if other.__class__ == self.__class__:
            return (other.service + 0x40) == self.service or \
                   (self.service == 0x7f and (self.requestServiceId == other.service))
        return 0

    def hashret(self):
        """DEV: returns a string that has the same value for a request and its answer."""
        if 'PositiveResponse' in self.services[self.service]:
            return struct.pack('B', self.service - 0x40)
        elif self.service == 0x7f:
            return struct.pack('B', self.requestServiceId)
        else:
            return struct.pack('B', self.service)


#########################DSC###################################
class ISO14229_DSC(Packet):
    diagnosticSessionTypes = {
        0x00: 'ISOSAEReserved',
        0x01: 'defaultSession',
        0x02: 'programmingSession',
        0x03: 'extendedDiagnosticSession',
        0x04: 'safetySystemDiagnosticSession',
        0x7F: 'ISOSAEReserved'}
    name = 'DSC'
    fields_desc = [
        ByteEnumField('diagnosticSessionType', 0, diagnosticSessionTypes)
    ]


bind_layers(ISO14229, ISO14229_DSC, service=0x10)


class ISO14229_DSCPR(Packet):
    name = 'DSCPR'
    fields_desc = [
        ByteEnumField('diagnosticSessionType', 0, ISO14229_DSC.diagnosticSessionTypes),
        StrField('sessionParameterRecord', B"")
    ]


bind_layers(ISO14229, ISO14229_DSCPR, service=0x50)


#########################ER###################################
class ISO14229_ER(Packet):
    resetTypes = {
        0x00: 'ISOSAEReserved',
        0x01: 'hardReset',
        0x02: 'keyOffOnReset',
        0x03: 'softReset',
        0x04: 'enableRapidPowerShutDown',
        0x05: 'disableRapidPowerShutDown',
        0x7F: 'ISOSAEReserved'}
    name = 'ER'
    fields_desc = [
        ByteEnumField('resetType', 0, resetTypes)
    ]


bind_layers(ISO14229, ISO14229_ER, service=0x11)


class ISO14229_ERPR(Packet):
    name = 'ERPR'
    fields_desc = [
        ByteEnumField('resetType', 0, ISO14229_ER.resetTypes),
        ConditionalField(ByteField('powerDownTime', 0), lambda pkt: pkt.resetType == 0x04)
    ]


bind_layers(ISO14229, ISO14229_ERPR, service=0x51)


#########################SA###################################
class ISO14229_SA(Packet):
    name = 'SA'
    fields_desc = [
        ByteField('securityAccessType', 0),
        ConditionalField(StrField('securityAccessDataRecord', B""), lambda pkt: pkt.securityAccessType % 2 == 1),
        ConditionalField(StrField('securityKey', B""), lambda pkt: pkt.securityAccessType % 2 == 0)
    ]


bind_layers(ISO14229, ISO14229_SA, service=0x27)


class ISO14229_SAPR(Packet):
    name = 'SAPR'
    fields_desc = [
        ByteField('securityAccessType', 0),
        ConditionalField(StrField('securitySeed', B""), lambda pkt: pkt.securityAccessType % 2 == 1),
    ]


bind_layers(ISO14229, ISO14229_SAPR, service=0x67)


#########################CC###################################
class ISO14229_CC(Packet):
    controlTypes = {
        0x00: 'enableRxAndTx',
        0x01: 'enableRxAndDisableTx',
        0x02: 'disableRxAndEnableTx',
        0x03: 'disableRxAndTx'
    }
    name = 'CC'
    fields_desc = [
        ByteEnumField('controlType', 0, controlTypes),
        BitEnumField('communicationType0', 0, 2,
                     {0: 'ISOSAEReserved',
                      1: 'normalCommunicationMessages',
                      2: 'networkManagmentCommunicationMessages',
                      3: 'networkManagmentCommunicationMessages and normalCommunicationMessages'}),
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


bind_layers(ISO14229, ISO14229_CC, service=0x28)


class ISO14229_CCPR(Packet):
    name = 'CCPR'
    fields_desc = [
        ByteEnumField('controlType', 0, ISO14229_CC.controlTypes)
    ]


bind_layers(ISO14229, ISO14229_CCPR, service=0x68)


#########################TP###################################
class ISO14229_TP(Packet):
    name = 'TP'
    fields_desc = [
        ByteField('subFunction', 0)
    ]


bind_layers(ISO14229, ISO14229_TP, service=0x3E)


class ISO14229_TPPR(Packet):
    name = 'TPPR'
    fields_desc = [
        ByteField('zeroSubFunction', 0)
    ]


bind_layers(ISO14229, ISO14229_TPPR, service=0x7E)


#########################ATP###################################



class ISO14229_ATP(Packet):
    timingParameterAccessTypes = {
        0: 'ISOSAEReserved',
        1: 'readExtendedTimingParameterSet',
        2: 'setTimingParametersToDefaultValues',
        3: 'readCurrentlyActiveTimingParameters',
        4: 'setTimingParametersToGivenValues'
    }
    name = 'ATP'
    fields_desc = [
        ByteEnumField('timingParameterAccessType', 0, timingParameterAccessTypes),
        ConditionalField(StrField('TimingParameterRequestRecord', B""),
                         lambda pkt: pkt.timingParameterAccessType == 0x4)
    ]


bind_layers(ISO14229, ISO14229_ATP, service=0x83)


class ISO14229_ATPPR(Packet):
    name = 'ATPPR'
    fields_desc = [
        ByteEnumField('timingParameterAccessType', 0, ISO14229_ATP.timingParameterAccessTypes),
        ConditionalField(StrField('TimingParameterResponseRecord', B""),
                         lambda pkt: pkt.timingParameterAccessType == 0x3)
    ]


bind_layers(ISO14229, ISO14229_ATPPR, service=0xC3)


#########################SDT###################################
class ISO14229_SDT(Packet):
    name = 'SDT'
    fields_desc = [
        StrField('securityDataRequestRecord', B"")
    ]


bind_layers(ISO14229, ISO14229_SDT, service=0x84)


class ISO14229_SDTPR(Packet):
    name = 'SDTPR'
    fields_desc = [
        StrField('securityDataResponseRecord', B"")
    ]


bind_layers(ISO14229, ISO14229_SDT, service=0xC4)


#########################CDTCS###################################
class ISO14229_CDTCS(Packet):
    DTCSettingTypes = {
        0: 'ISOSAEReserved',
        1: 'on',
        2: 'off'
    }
    name = 'CDTCS'
    fields_desc = [
        ByteEnumField('DTCSettingType', 0, DTCSettingTypes),
        StrField('DTCSettingControlOptionRecord', B"")
    ]


bind_layers(ISO14229, ISO14229_CDTCS, service=0x85)


class ISO14229_CDTCSPR(Packet):
    name = 'CDTCSPR'
    fields_desc = [
        ByteEnumField('DTCSettingType', 0, ISO14229_CDTCS.DTCSettingTypes)
    ]


bind_layers(ISO14229, ISO14229_CDTCSPR, service=0xC5)


#########################ROE###################################
# TODO: improve this protocol implementation
class ISO14229_ROE(Packet):
    eventTypes = {
        0: 'doNotStoreEvent',
        1: 'storeEvent'
    }
    name = 'ROE'
    fields_desc = [
        ByteEnumField('eventType', 0, eventTypes),
        ByteField('eventWindowTime', 0),
        StrField('eventTypeRecord', B"")
    ]


bind_layers(ISO14229, ISO14229_ROE, service=0x86)


class ISO14229_ROEPR(Packet):
    name = 'ROEPR'
    fields_desc = [
        ByteEnumField('eventType', 0, ISO14229_ROE.eventTypes),
        ByteField('numberOfIdentifiedEvents', 0),
        ByteField('eventWindowTime', 0),
        StrField('eventTypeRecord', B"")
    ]


bind_layers(ISO14229, ISO14229_ROEPR, service=0xC6)


#########################LC###################################
class ISO14229_LC(Packet):
    linkControlTypes = {
        0: 'ISOSAEReserved',
        1: 'verifyBaudrateTransitionWithFixedBaudrate',
        2: 'verifyBaudrateTransitionWithSpecificBaudrate',
        3: 'transitionBaudrate'
    }
    name = 'LC'
    fields_desc = [
        ByteEnumField('linkControlType', 0, linkControlTypes),
        ConditionalField(ByteField('baudrateIdentifier', 0), lambda pkt: pkt.linkControlType == 0x1),
        ConditionalField(ByteField('baudrateHighByte', 0), lambda pkt: pkt.linkControlType == 0x2),
        ConditionalField(ByteField('baudrateMiddleByte', 0), lambda pkt: pkt.linkControlType == 0x2),
        ConditionalField(ByteField('baudrateLowByte', 0), lambda pkt: pkt.linkControlType == 0x2)
    ]


bind_layers(ISO14229, ISO14229_LC, service=0x87)


class ISO14229_LCPR(Packet):
    name = 'LCPR'
    fields_desc = [
        ByteEnumField('linkControlType', 0, ISO14229_LC.linkControlTypes)
    ]


bind_layers(ISO14229, ISO14229_LCPR, service=0xC7)


#########################RDBI###################################
# TODO: Multiple dataIdentifier in one packet are not supported yet.
class ISO14229_RDBI(Packet):
    dataIdentifiers = ObservableDict()
    name = 'RDBI'
    fields_desc = [
        XShortUpdateableEnumField('dataIdentifier', 0, dataIdentifiers)
    ]


bind_layers(ISO14229, ISO14229_RDBI, service=0x22)


class ISO14229_RDBIPR(Packet):
    name = 'RDBIPR'
    fields_desc = [
        XShortUpdateableEnumField('dataIdentifier', 0, ISO14229_RDBI.dataIdentifiers),
    ]


bind_layers(ISO14229, ISO14229_RDBIPR, service=0x62)


#########################RMBA###################################
class ISO14229_RMBA(Packet):
    name = 'RMBA'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0), lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0), lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0), lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0), lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0), lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0), lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0), lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0), lambda pkt: pkt.memorySizeLen == 4),
    ]


bind_layers(ISO14229, ISO14229_RMBA, service=0x23)


class ISO14229_RMBAPR(Packet):
    name = 'RMBAPR'
    fields_desc = [
        StrField('dataRecord', None, fmt="B")
    ]


bind_layers(ISO14229, ISO14229_RMBAPR, service=0x63)


#########################RSDBI###################################
class ISO14229_RSDBI(Packet):
    name = 'RSDBI'
    fields_desc = [
        XShortField('dataIdentifier', 0)
    ]


bind_layers(ISO14229, ISO14229_RSDBI, service=0x24)


# TODO: Implement correct scaling here, instead of using just the dataRecord
class ISO14229_RSDBIPR(Packet):
    name = 'RSDBIPR'
    fields_desc = [
        XShortField('dataIdentifier', 0),
        ByteField('scalingByte', 0),
        StrField('dataRecord', None, fmt="B")
    ]


bind_layers(ISO14229, ISO14229_RSDBIPR, service=0x64)


#########################RDBPI###################################
class ISO14229_RDBPI(Packet):
    transmissionModes = {
        0: 'ISOSAEReserved',
        1: 'sendAtSlowRate',
        2: 'sendAtMediumRate',
        3: 'sendAtFastRate',
        4: 'stopSending'
    }
    name = 'RDBPI'
    fields_desc = [
        ByteEnumField('transmissionMode', 0, transmissionModes),
        ByteField('periodicDataIdentifier', 0),
        StrField('furtherPeriodicDataIdentifier', 0, fmt="B")
    ]


bind_layers(ISO14229, ISO14229_RDBPI, service=0x2A)


# TODO: Implement correct scaling here, instead of using just the dataRecord
class ISO14229_RDBPIPR(Packet):
    name = 'RDBPIPR'
    fields_desc = [
        ByteField('periodicDataIdentifier', 0),
        StrField('dataRecord', None, fmt="B")
    ]


bind_layers(ISO14229, ISO14229_RDBPIPR, service=0x6A)


#########################DDDI###################################
# TODO: Implement correct interpretation here, instead of using just the dataRecord
class ISO14229_DDDI(Packet):
    name = 'DDDI'
    fields_desc = [
        ByteField('definitionMode', 0),
        StrField('dataRecord', 0, fmt="B")
    ]


bind_layers(ISO14229, ISO14229_DDDI, service=0x2C)


class ISO14229_DDDIPR(Packet):
    name = 'DDDIPR'
    fields_desc = [
        ByteField('definitionMode', 0),
        XShortField('dynamicallyDefinedDataIdentifier', 0)
    ]


bind_layers(ISO14229, ISO14229_DDDIPR, service=0x6C)


#########################WDBI###################################
class ISO14229_WDBI(Packet):
    name = 'WDBI'
    fields_desc = [
        XShortUpdateableEnumField('dataIdentifier', 0, ISO14229_RDBI.dataIdentifiers),
        StrField('dataRecord', 0, fmt="B")
    ]


bind_layers(ISO14229, ISO14229_WDBI, service=0x2E)


class ISO14229_WDBIPR(Packet):
    name = 'WDBIPR'
    fields_desc = [
        XShortUpdateableEnumField('dataIdentifier', 0, ISO14229_RDBI.dataIdentifiers),
    ]


bind_layers(ISO14229, ISO14229_WDBIPR, service=0x6E)


#########################WMBA###################################
class ISO14229_WMBA(Packet):
    name = 'WMBA'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0), lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0), lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0), lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0), lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0), lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0), lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0), lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0), lambda pkt: pkt.memorySizeLen == 4),
        StrField('dataRecord', b'\x00', fmt="B"),

    ]


bind_layers(ISO14229, ISO14229_WMBA, service=0x3D)


class ISO14229_WMBAPR(Packet):
    name = 'WMBAPR'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0), lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0), lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0), lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0), lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0), lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0), lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0), lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0), lambda pkt: pkt.memorySizeLen == 4)
    ]


bind_layers(ISO14229, ISO14229_WMBAPR, service=0x7D)


#########################CDTCI###################################
class ISO14229_CDTCI(Packet):
    name = 'CDTCI'
    fields_desc = [
        ByteField('groupOfDTCHighByte', 0),
        ByteField('groupOfDTCMiddleByte', 0),
        ByteField('groupOfDTCLowByte', 0),
    ]


bind_layers(ISO14229, ISO14229_CDTCI, service=0x14)


#########################RDTCI###################################
class ISO14229_RDTCI(Packet):
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
    name = 'RDTCI'
    fields_desc = [
        ByteEnumField('reportType', 0, reportTypes),
        ConditionalField(XByteField('DTCStatusMask', 0),
                         lambda pkt: pkt.reportType in [0x01, 0x02, 0x0f, 0x11, 0x12, 0x13]),
        ConditionalField(ByteField('DTCHighByte', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x6, 0x10, 0x09]),
        ConditionalField(ByteField('DTCMiddleByte', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x6, 0x10, 0x09]),
        ConditionalField(ByteField('DTCLowByte', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x6, 0x10, 0x09]),
        ConditionalField(ByteField('DTCSnapshotRecordNumber', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x5]),
        ConditionalField(ByteField('DTCExtendedDataRecordNumber', 0),
                         lambda pkt: pkt.reportType in [0x6, 0x10]),
        ConditionalField(ByteField('DTCSeverityMask', 0),
                         lambda pkt: pkt.reportType in [0x07, 0x08]),
        ConditionalField(ByteField('DTCStatusMask', 0),
                         lambda pkt: pkt.reportType in [0x07, 0x08]),
    ]


bind_layers(ISO14229, ISO14229_RDTCI, service=0x19)


class ISO14229_RDTCIPR(Packet):
    name = 'RDTCIPR'
    fields_desc = [
        ByteEnumField('reportType', 0, ISO14229_RDTCI.reportTypes),
        ConditionalField(XByteField('DTCStatusAvailabilityMask', 0),
                         lambda pkt: pkt.reportType in [0x01, 0x07, 0x11, 0x12, 0x02, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                                                        0x0F, 0x13, 0x15]),
        ConditionalField(ByteEnumField('DTCFormatIdentifier', 0, {0: 'ISO15031-6DTCFormat',
                                                                  1: 'ISO14229-1DTCFormat',
                                                                  2: 'SAEJ1939-73DTCFormat',
                                                                  3: 'ISO11992-4DTCFormat'}),
                         lambda pkt: pkt.reportType in [0x01, 0x07, 0x11, 0x12]),
        ConditionalField(ShortField('DTCCount', 0),
                         lambda pkt: pkt.reportType in [0x01, 0x07, 0x11, 0x12]),
        ConditionalField(StrField('DTCAndStatusRecord', 0),
                         lambda pkt: pkt.reportType in [0x02, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x13, 0x15]),
        ConditionalField(StrField('dataRecord', 0),
                         lambda pkt: pkt.reportType in [0x03, 0x4, 0x5, 0x6, 0x8, 0x9, 0x10, 0x14])
    ]


bind_layers(ISO14229, ISO14229_RDTCIPR, service=0x59)


#########################RC###################################
class ISO14229_RC(Packet):
    routineControlTypes = {
        0: 'ISOSAEReserved',
        1: 'startRoutine',
        2: 'stopRoutine',
        3: 'requestRoutineResults'
    }
    name = 'RC'
    fields_desc = [
        ByteEnumField('routineControlType', 0, routineControlTypes),
        XShortField('routineIdentifier', 0),
        StrField('routineControlOptionRecord', 0, fmt="B"),
    ]


bind_layers(ISO14229, ISO14229_RC, service=0x31)


class ISO14229_RCPR(Packet):
    name = 'RCPR'
    fields_desc = [
        ByteEnumField('routineControlType', 0, ISO14229_RC.routineControlTypes),
        XShortField('routineIdentifier', 0),
        StrField('routineStatusRecord', 0, fmt="B"),
    ]


bind_layers(ISO14229, ISO14229_RCPR, service=0x71)


#########################RD###################################
class ISO14229_RD(Packet):
    dataFormatIdentifiers = {
        0: 'noCompressionNoEncryption'
    }
    name = 'RD'
    fields_desc = [
        ByteEnumField('dataFormatIdentifier', 0, dataFormatIdentifiers),
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0), lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0), lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0), lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0), lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0), lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0), lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0), lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0), lambda pkt: pkt.memorySizeLen == 4)
    ]


bind_layers(ISO14229, ISO14229_RD, service=0x34)


class ISO14229_RDPR(Packet):
    name = 'RDPR'
    fields_desc = [
        ByteEnumField('routineControlType', 0, ISO14229_RC.routineControlTypes),
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        StrField('maxNumberOfBlockLength', 0, fmt="B"),
    ]


bind_layers(ISO14229, ISO14229_RDPR, service=0x74)


#########################RU###################################
class ISO14229_RU(Packet):
    name = 'RU'
    fields_desc = [
        ByteEnumField('dataFormatIdentifier', 0, ISO14229_RD.dataFormatIdentifiers),
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0), lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0), lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0), lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0), lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0), lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0), lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0), lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0), lambda pkt: pkt.memorySizeLen == 4)
    ]


bind_layers(ISO14229, ISO14229_RU, service=0x35)


class ISO14229_RUPR(Packet):
    name = 'RUPR'
    fields_desc = [
        ByteEnumField('routineControlType', 0, ISO14229_RC.routineControlTypes),
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        StrField('maxNumberOfBlockLength', 0, fmt="B"),
    ]


bind_layers(ISO14229, ISO14229_RUPR, service=0x75)


#########################TD###################################
class ISO14229_TD(Packet):
    name = 'TD'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferRequestParameterRecord', 0, fmt="B")
    ]


bind_layers(ISO14229, ISO14229_TD, service=0x36)


class ISO14229_TDPR(Packet):
    name = 'TDPR'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferResponseParameterRecord', 0, fmt="B")
    ]


bind_layers(ISO14229, ISO14229_TDPR, service=0x76)


#########################RTE###################################
class ISO14229_RTE(Packet):
    name = 'RTE'
    fields_desc = [
        StrField('transferRequestParameterRecord', 0, fmt="B")
    ]


bind_layers(ISO14229, ISO14229_RTE, service=0x37)


class ISO14229_RTEPR(Packet):
    name = 'RTEPR'
    fields_desc = [
        StrField('transferResponseParameterRecord', 0, fmt="B")
    ]


bind_layers(ISO14229, ISO14229_RTEPR, service=0x77)


#########################NRC###################################
class ISO14229_NRC(Packet):
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
    name = 'NRC'
    fields_desc = [
        XByteUpdateableEnumField('requestServiceId', 0, ISO14229.services),
        ByteEnumField('negativeResponseCode', 0, negativeResponseCodes)
    ]


bind_layers(ISO14229, ISO14229_NRC, service=0x7f)
