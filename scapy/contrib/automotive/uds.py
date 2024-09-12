# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = Unified Diagnostic Service (UDS)
# scapy.contrib.status = loads

"""
UDS
"""

import struct
from collections import defaultdict

from scapy.fields import ByteEnumField, StrField, ConditionalField, \
    BitEnumField, BitField, XByteField, FieldListField, \
    XShortField, X3BytesField, XIntField, ByteField, \
    ShortField, ObservableDict, XShortEnumField, XByteEnumField, StrLenField, \
    FieldLenField, XStrFixedLenField, XStrLenField, FlagsField, PacketListField, \
    PacketField
from scapy.packet import Packet, bind_layers, NoPayload, Raw
from scapy.config import conf
from scapy.error import log_loading
from scapy.utils import PeriodicSenderThread
from scapy.contrib.isotp import ISOTP

# Typing imports
from typing import (
    Dict,
    Union,
)

try:
    if conf.contribs['UDS']['treat-response-pending-as-answer']:
        pass
except KeyError:
    log_loading.info("Specify \"conf.contribs['UDS'] = "
                     "{'treat-response-pending-as-answer': True}\" to treat "
                     "a negative response 'requestCorrectlyReceived-"
                     "ResponsePending' as answer of a request. \n"
                     "The default value is False.")
    conf.contribs['UDS'] = {'treat-response-pending-as-answer': False}


conf.debug_dissector = True


class UDS(ISOTP):
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
         0x29: 'Authentication',
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
         0x69: 'AuthenticationPositiveResponse',
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
    name = 'UDS'
    fields_desc = [
        XByteEnumField('service', 0, services)
    ]

    def answers(self, other):
        # type: (Union[UDS, Packet]) -> bool
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
        if self.service == 0x7f and len(self) >= 3:
            return struct.pack('B', bytes(self)[1] & ~0x40)
        return struct.pack('B', self.service & ~0x40)


# ########################DSC###################################
class UDS_DSC(Packet):
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


bind_layers(UDS, UDS_DSC, service=0x10)


class UDS_DSCPR(Packet):
    name = 'DiagnosticSessionControlPositiveResponse'
    fields_desc = [
        ByteEnumField('diagnosticSessionType', 0,
                      UDS_DSC.diagnosticSessionTypes),
        StrField('sessionParameterRecord', b"")
    ]

    def answers(self, other):
        return isinstance(other, UDS_DSC) and \
            other.diagnosticSessionType == self.diagnosticSessionType


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
        0x41: 'powerDown',
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

    def answers(self, other):
        return isinstance(other, UDS_ER) and other.resetType == self.resetType


bind_layers(UDS, UDS_ERPR, service=0x51)


# #########################SA###################################
class UDS_SA(Packet):
    name = 'SecurityAccess'
    fields_desc = [
        ByteField('securityAccessType', 0),
        ConditionalField(StrField('securityAccessDataRecord', b""),
                         lambda pkt: pkt.securityAccessType % 2 == 1),
        ConditionalField(StrField('securityKey', b""),
                         lambda pkt: pkt.securityAccessType % 2 == 0)
    ]


bind_layers(UDS, UDS_SA, service=0x27)


class UDS_SAPR(Packet):
    name = 'SecurityAccessPositiveResponse'
    fields_desc = [
        ByteField('securityAccessType', 0),
        ConditionalField(StrField('securitySeed', b""),
                         lambda pkt: pkt.securityAccessType % 2 == 1),
    ]

    def answers(self, other):
        return isinstance(other, UDS_SA) \
            and other.securityAccessType == self.securityAccessType


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

    def answers(self, other):
        return isinstance(other, UDS_CC) \
            and other.controlType == self.controlType


bind_layers(UDS, UDS_CCPR, service=0x68)


# #########################AUTH###################################
class UDS_AUTH(Packet):
    subFunctions = {
        0x00: 'deAuthenticate',
        0x01: 'verifyCertificateUnidirectional',
        0x02: 'verifyCertificateBidirectional',
        0x03: 'proofOfOwnership',
        0x04: 'transmitCertificate',
        0x05: 'requestChallengeForAuthentication',
        0x06: 'verifyProofOfOwnershipUnidirectional',
        0x07: 'verifyProofOfOwnershipBidirectional',
        0x08: 'authenticationConfiguration',
        0x7F: 'ISOSAEReserved'
    }
    name = "Authentication"
    fields_desc = [
        ByteEnumField('subFunction', 0, subFunctions),
        ConditionalField(XByteField('communicationConfiguration', 0),
                         lambda pkt: pkt.subFunction in [0x01, 0x02, 0x5]),
        ConditionalField(XShortField('certificateEvaluationId', 0),
                         lambda pkt: pkt.subFunction == 0x04),
        ConditionalField(XStrFixedLenField('algorithmIndicator', 0, length=16),
                         lambda pkt: pkt.subFunction in [0x05, 0x06, 0x07]),
        ConditionalField(FieldLenField('lengthOfCertificateClient', None,
                                       fmt="H", length_of='certificateClient'),
                         lambda pkt: pkt.subFunction in [0x01, 0x02]),
        ConditionalField(XStrLenField('certificateClient', b"",
                                      length_from=lambda p:
                                      p.lengthOfCertificateClient),
                         lambda pkt: pkt.subFunction in [0x01, 0x02]),
        ConditionalField(FieldLenField('lengthOfProofOfOwnershipClient', None,
                                       fmt="H",
                                       length_of='proofOfOwnershipClient'),
                         lambda pkt: pkt.subFunction in [0x03, 0x06, 0x07]),
        ConditionalField(XStrLenField('proofOfOwnershipClient', b"",
                                      length_from=lambda p:
                                      p.lengthOfProofOfOwnershipClient),
                         lambda pkt: pkt.subFunction in [0x03, 0x06, 0x07]),
        ConditionalField(FieldLenField('lengthOfChallengeClient', None,
                                       fmt="H", length_of='challengeClient'),
                         lambda pkt: pkt.subFunction in [0x01, 0x02, 0x06,
                                                         0x07]),
        ConditionalField(XStrLenField('challengeClient', b"",
                                      length_from=lambda p:
                                      p.lengthOfChallengeClient),
                         lambda pkt: pkt.subFunction in [0x01, 0x02, 0x06,
                                                         0x07]),
        ConditionalField(FieldLenField('lengthOfEphemeralPublicKeyClient',
                                       None, fmt="H",
                                       length_of='ephemeralPublicKeyClient'),
                         lambda pkt: pkt.subFunction == 0x03),
        ConditionalField(XStrLenField('ephemeralPublicKeyClient', b"",
                                      length_from=lambda p:
                                      p.lengthOfEphemeralPublicKeyClient),
                         lambda pkt: pkt.subFunction == 0x03),
        ConditionalField(FieldLenField('lengthOfCertificateData', None,
                                       fmt="H", length_of='certificateData'),
                         lambda pkt: pkt.subFunction == 0x04),
        ConditionalField(XStrLenField('certificateData', b"",
                                      length_from=lambda p:
                                      p.lengthOfCertificateData),
                         lambda pkt: pkt.subFunction == 0x04),
        ConditionalField(FieldLenField('lengthOfAdditionalParameter', None,
                                       fmt="H",
                                       length_of='additionalParameter'),
                         lambda pkt: pkt.subFunction in [0x06, 0x07]),
        ConditionalField(XStrLenField('additionalParameter', b"",
                                      length_from=lambda p:
                                      p.lengthOfAdditionalParameter),
                         lambda pkt: pkt.subFunction in [0x06, 0x07]),
    ]


bind_layers(UDS, UDS_AUTH, service=0x29)


class UDS_AUTHPR(Packet):
    authenticationReturnParameterTypes = {
        0x00: 'requestAccepted',
        0x01: 'generalReject',
        # Authentication with PKI Certificate Exchange (ACPE)
        0x02: 'authenticationConfigurationAPCE',
        # Authentication with Challenge-Response (ACR)
        0x03: 'authenticationConfigurationACRWithAsymmetricCryptography',
        0x04: 'authenticationConfigurationACRWithSymmetricCryptography',
        0x05: 'ISOSAEReserved',
        0x0F: 'ISOSAEReserved',
        0x10: 'deAuthenticationSuccessful',
        0x11: 'certificateVerifiedOwnershipVerificationNecessary',
        0x12: 'ownershipVerifiedAuthenticationComplete',
        0x13: 'certificateVerified',
        0x14: 'ISOSAEReserved',
        0x9F: 'ISOSAEReserved',
        0xFF: 'ISOSAEReserved'
    }
    name = 'AuthenticationPositiveResponse'
    fields_desc = [
        ByteEnumField('subFunction', 0, UDS_AUTH.subFunctions),
        ByteEnumField('returnValue', 0, authenticationReturnParameterTypes),
        ConditionalField(XStrFixedLenField('algorithmIndicator', 0, length=16),
                         lambda pkt: pkt.subFunction in [0x05, 0x06, 0x07]),
        ConditionalField(FieldLenField('lengthOfChallengeServer', None,
                                       fmt="H", length_of='challengeServer'),
                         lambda pkt: pkt.subFunction in [0x01, 0x02, 0x05]),
        ConditionalField(XStrLenField('challengeServer', b"",
                                      length_from=lambda p:
                                      p.lengthOfChallengeServer),
                         lambda pkt: pkt.subFunction in [0x01, 0x02, 0x05]),
        ConditionalField(FieldLenField('lengthOfCertificateServer', None,
                                       fmt="H", length_of='certificateServer'),
                         lambda pkt: pkt.subFunction == 0x02),
        ConditionalField(XStrLenField('certificateServer', b"",
                                      length_from=lambda p:
                                      p.lengthOfCertificateServer),
                         lambda pkt: pkt.subFunction == 0x02),
        ConditionalField(FieldLenField('lengthOfProofOfOwnershipServer', None,
                                       fmt="H",
                                       length_of='proofOfOwnershipServer'),
                         lambda pkt: pkt.subFunction in [0x02, 0x07]),
        ConditionalField(XStrLenField('proofOfOwnershipServer', b"",
                                      length_from=lambda p:
                                      p.lengthOfProofOfOwnershipServer),
                         lambda pkt: pkt.subFunction in [0x02, 0x07]),
        ConditionalField(FieldLenField('lengthOfSessionKeyInfo', None, fmt="H",
                                       length_of='sessionKeyInfo'),
                         lambda pkt: pkt.subFunction in [0x03, 0x06, 0x07]),
        ConditionalField(XStrLenField('sessionKeyInfo', b"",
                                      length_from=lambda p:
                                      p.lengthOfSessionKeyInfo),
                         lambda pkt: pkt.subFunction in [0x03, 0x06, 0x07]),
        ConditionalField(FieldLenField('lengthOfEphemeralPublicKeyServer',
                                       None, fmt="H",
                                       length_of='ephemeralPublicKeyServer'),
                         lambda pkt: pkt.subFunction in [0x01, 0x02]),
        ConditionalField(XStrLenField('ephemeralPublicKeyServer', b"",
                                      length_from=lambda p:
                                      p.lengthOfEphemeralPublicKeyServer),
                         lambda pkt: pkt.subFunction in [0x1, 0x02]),
        ConditionalField(FieldLenField('lengthOfNeededAdditionalParameter',
                                       None, fmt="H",
                                       length_of='neededAdditionalParameter'),
                         lambda pkt: pkt.subFunction == 0x05),
        ConditionalField(XStrLenField('neededAdditionalParameter', b"",
                                      length_from=lambda p:
                                      p.lengthOfNeededAdditionalParameter),
                         lambda pkt: pkt.subFunction == 0x05),
    ]

    def answers(self, other):
        return isinstance(other, UDS_AUTH) \
            and other.subFunction == self.subFunction


bind_layers(UDS, UDS_AUTHPR, service=0x69)


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

    def answers(self, other):
        return isinstance(other, UDS_TP)


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
        ConditionalField(StrField('timingParameterRequestRecord', b""),
                         lambda pkt: pkt.timingParameterAccessType == 0x4)
    ]


bind_layers(UDS, UDS_ATP, service=0x83)


class UDS_ATPPR(Packet):
    name = 'AccessTimingParameterPositiveResponse'
    fields_desc = [
        ByteEnumField('timingParameterAccessType', 0,
                      UDS_ATP.timingParameterAccessTypes),
        ConditionalField(StrField('timingParameterResponseRecord', b""),
                         lambda pkt: pkt.timingParameterAccessType == 0x3)
    ]

    def answers(self, other):
        return isinstance(other, UDS_ATP) \
            and other.timingParameterAccessType == \
            self.timingParameterAccessType


bind_layers(UDS, UDS_ATPPR, service=0xC3)


# #########################SDT###################################
# TODO: Implement correct internal message service handling here,
# instead of using just the dataRecord
class UDS_SDT(Packet):
    name = 'SecuredDataTransmission'
    fields_desc = [
        BitField('requestMessage', 0, 1),
        BitField('ISOSAEReservedBackwardsCompatibility', 0, 2),
        BitField('preEstablishedKeyUsed', 0, 1),
        BitField('encryptedMessage', 0, 1),
        BitField('signedMessage', 0, 1),
        BitField('signedResponseRequested', 0, 1),
        BitField('ISOSAEReserved', 0, 9),
        ByteField('signatureEncryptionCalculation', 0),
        XShortField('signatureLength', 0),
        XShortField('antiReplayCounter', 0),
        ByteField('internalMessageServiceRequestId', 0),
        StrField('dataRecord', b"", fmt="B")
    ]


bind_layers(UDS, UDS_SDT, service=0x84)


class UDS_SDTPR(Packet):
    name = 'SecuredDataTransmissionPositiveResponse'
    fields_desc = [
        BitField('requestMessage', 0, 1),
        BitField('ISOSAEReservedBackwardsCompatibility', 0, 2),
        BitField('preEstablishedKeyUsed', 0, 1),
        BitField('encryptedMessage', 0, 1),
        BitField('signedMessage', 0, 1),
        BitField('signedResponseRequested', 0, 1),
        BitField('ISOSAEReserved', 0, 9),
        ByteField('signatureEncryptionCalculation', 0),
        XShortField('signatureLength', 0),
        XShortField('antiReplayCounter', 0),
        ByteField('internalMessageServiceResponseId', 0),
        StrField('dataRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return isinstance(other, UDS_SDT)


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
        StrField('DTCSettingControlOptionRecord', b"")
    ]


bind_layers(UDS, UDS_CDTCS, service=0x85)


class UDS_CDTCSPR(Packet):
    name = 'ControlDTCSettingPositiveResponse'
    fields_desc = [
        ByteEnumField('DTCSettingType', 0, UDS_CDTCS.DTCSettingTypes)
    ]

    def answers(self, other):
        return isinstance(other, UDS_CDTCS)


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
        StrField('eventTypeRecord', b"")
    ]


bind_layers(UDS, UDS_ROE, service=0x86)


class UDS_ROEPR(Packet):
    name = 'ResponseOnEventPositiveResponse'
    fields_desc = [
        ByteEnumField('eventType', 0, UDS_ROE.eventTypes),
        ByteField('numberOfIdentifiedEvents', 0),
        ByteField('eventWindowTime', 0),
        StrField('eventTypeRecord', b"")
    ]

    def answers(self, other):
        return isinstance(other, UDS_ROE) \
            and other.eventType == self.eventType


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

    def answers(self, other):
        return isinstance(other, UDS_LC) \
            and other.linkControlType == self.linkControlType


bind_layers(UDS, UDS_LCPR, service=0xC7)


# #########################RDBI###################################
class UDS_RDBI(Packet):
    dataIdentifiers = ObservableDict()
    name = 'ReadDataByIdentifier'
    fields_desc = [
        FieldListField("identifiers", None,
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

    def answers(self, other):
        return isinstance(other, UDS_RDBI) \
            and self.dataIdentifier in other.identifiers


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
        StrField('dataRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return isinstance(other, UDS_RMBA)


bind_layers(UDS, UDS_RMBAPR, service=0x63)


# #########################RSDBI###################################
class UDS_RSDBI(Packet):
    name = 'ReadScalingDataByIdentifier'
    dataIdentifiers = ObservableDict()
    fields_desc = [
        XShortEnumField('dataIdentifier', 0, dataIdentifiers)
    ]


bind_layers(UDS, UDS_RSDBI, service=0x24)


# TODO: Implement correct scaling here, instead of using just the dataRecord
class UDS_RSDBIPR(Packet):
    name = 'ReadScalingDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0, UDS_RSDBI.dataIdentifiers),
        ByteField('scalingByte', 0),
        StrField('dataRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return isinstance(other, UDS_RSDBI) \
            and other.dataIdentifier == self.dataIdentifier


bind_layers(UDS, UDS_RSDBIPR, service=0x64)


# #########################RDBPI###################################
class UDS_RDBPI(Packet):
    periodicDataIdentifiers = ObservableDict()
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
        ByteEnumField('periodicDataIdentifier', 0, periodicDataIdentifiers),
        StrField('furtherPeriodicDataIdentifier', b"", fmt="B")
    ]


bind_layers(UDS, UDS_RDBPI, service=0x2A)


# TODO: Implement correct scaling here, instead of using just the dataRecord
class UDS_RDBPIPR(Packet):
    name = 'ReadDataByPeriodicIdentifierPositiveResponse'
    fields_desc = [
        ByteField('periodicDataIdentifier', 0),
        StrField('dataRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return isinstance(other, UDS_RDBPI) \
            and other.periodicDataIdentifier == self.periodicDataIdentifier


bind_layers(UDS, UDS_RDBPIPR, service=0x6A)


# #########################DDDI###################################
# TODO: Implement correct interpretation here,
# instead of using just the dataRecord
class UDS_DDDI(Packet):
    name = 'DynamicallyDefineDataIdentifier'
    subFunctions = {0x1: "defineByIdentifier",
                    0x2: "defineByMemoryAddress",
                    0x3: "clearDynamicallyDefinedDataIdentifier"}
    fields_desc = [
        ByteEnumField('subFunction', 0, subFunctions),
        StrField('dataRecord', b"", fmt="B")
    ]


bind_layers(UDS, UDS_DDDI, service=0x2C)


class UDS_DDDIPR(Packet):
    name = 'DynamicallyDefineDataIdentifierPositiveResponse'
    fields_desc = [
        ByteEnumField('subFunction', 0, UDS_DDDI.subFunctions),
        XShortField('dynamicallyDefinedDataIdentifier', 0)
    ]

    def answers(self, other):
        return isinstance(other, UDS_DDDI) \
            and other.subFunction == self.subFunction


bind_layers(UDS, UDS_DDDIPR, service=0x6C)


# #########################WDBI###################################
class UDS_WDBI(Packet):
    name = 'WriteDataByIdentifier'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0,
                        UDS_RDBI.dataIdentifiers)
    ]


bind_layers(UDS, UDS_WDBI, service=0x2E)


class UDS_WDBIPR(Packet):
    name = 'WriteDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0,
                        UDS_RDBI.dataIdentifiers),
    ]

    def answers(self, other):
        return isinstance(other, UDS_WDBI) \
            and other.dataIdentifier == self.dataIdentifier


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
        StrField('dataRecord', b'', fmt="B"),

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

    def answers(self, other):
        return isinstance(other, UDS_WMBA) \
            and other.memorySizeLen == self.memorySizeLen \
            and other.memoryAddressLen == self.memoryAddressLen


bind_layers(UDS, UDS_WMBAPR, service=0x7D)


# ##########################DTC#####################################
class DTC(Packet):
    name = 'Diagnostic Trouble Code'
    dtc_descriptions = {}  # Customize this dictionary for each individual ECU / OEM

    fields_desc = [
        BitEnumField("system", 0, 2, {
            0: "Powertrain",
            1: "Chassis",
            2: "Body",
            3: "Network"}),
        BitEnumField("type", 0, 2, {
            0: "Generic",
            1: "ManufacturerSpecific",
            2: "Generic",
            3: "Generic"}),
        BitField("numeric_value_code", 0, 12),
        ByteField("additional_information_code", 0),
    ]

    def extract_padding(self, s):
        return '', s


# #########################CDTCI###################################
class UDS_CDTCI(Packet):
    name = 'ClearDiagnosticInformation'
    fields_desc = [
        ByteField('groupOfDTCHighByte', 0),
        ByteField('groupOfDTCMiddleByte', 0),
        ByteField('groupOfDTCLowByte', 0),
    ]


bind_layers(UDS, UDS_CDTCI, service=0x14)


class UDS_CDTCIPR(Packet):
    name = 'ClearDiagnosticInformationPositiveResponse'

    def answers(self, other):
        return isinstance(other, UDS_CDTCI)


bind_layers(UDS, UDS_CDTCIPR, service=0x54)


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
    dtcStatus = {
        1: 'TestFailed',
        2: 'TestFailedThisOperationCycle',
        4: 'PendingDTC',
        8: 'ConfirmedDTC',
        16: 'TestNotCompletedSinceLastClear',
        32: 'TestFailedSinceLastClear',
        64: 'TestNotCompletedThisOperationCycle',
        128: 'WarningIndicatorRequested'
    }
    dtcStatusMask = {
        1: 'ActiveDTCs',
        4: 'PendingDTCs',
        8: 'ConfirmedOrStoredDTCs',
        255: 'AllRecordDTCs'
    }
    dtcSeverityMask = {
        # 0: 'NoSeverityInformation',
        1: 'NoClassInformation',
        2: 'WWH-OBDClassA',
        4: 'WWH-OBDClassB1',
        8: 'WWH-OBDClassB2',
        16: 'WWH-OBDClassC',
        32: 'MaintenanceRequired',
        64: 'CheckAtNextHalt',
        128: 'CheckImmediately'
    }
    name = 'ReadDTCInformation'
    fields_desc = [
        ByteEnumField('reportType', 0, reportTypes),
        ConditionalField(FlagsField('DTCSeverityMask', 0, 8, dtcSeverityMask),
                         lambda pkt: pkt.reportType in [0x07, 0x08]),
        ConditionalField(FlagsField('DTCStatusMask', 0, 8, dtcStatusMask),
                         lambda pkt: pkt.reportType in [
                             0x01, 0x02, 0x07, 0x08, 0x0f, 0x11, 0x12, 0x13]),
        ConditionalField(PacketField("dtc", None, pkt_cls=DTC),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x6,
                                                        0x10, 0x09]),
        ConditionalField(ByteField('DTCSnapshotRecordNumber', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x5]),
        ConditionalField(ByteField('DTCExtendedDataRecordNumber', 0),
                         lambda pkt: pkt.reportType in [0x6, 0x10])
    ]


bind_layers(UDS, UDS_RDTCI, service=0x19)


class DTCAndStatusRecord(Packet):
    name = 'DTC and status record'
    fields_desc = [
        PacketField("dtc", None, pkt_cls=DTC),
        FlagsField("status", 0, 8, UDS_RDTCI.dtcStatus)
    ]

    def extract_padding(self, s):
        return '', s


class DTCExtendedData(Packet):
    name = 'Diagnostic Trouble Code Extended Data'
    dataTypes = ObservableDict()
    fields_desc = [
        ByteEnumField("data_type", 0, dataTypes),
        XByteField("record", 0)
    ]

    def extract_padding(self, s):
        return '', s


class DTCExtendedDataRecord(Packet):
    fields_desc = [
        PacketField("dtcAndStatus", None, pkt_cls=DTCAndStatusRecord),
        PacketListField("extendedData", None, pkt_cls=DTCExtendedData)
    ]


class DTCSnapshot(Packet):
    identifiers = defaultdict(list)  # for later extension

    @staticmethod
    def next_identifier_cb(pkt, lst, cur, remain):
        return Raw

    fields_desc = [
        ByteField("record_number", 0),
        ByteField("record_number_of_identifiers", 0),
        PacketListField(
            "snapshotData", None,
            next_cls_cb=lambda pkt, lst, cur, remain: DTCSnapshot.next_identifier_cb(
                pkt, lst, cur, remain))
    ]

    def extract_padding(self, s):
        return '', s


class DTCSnapshotRecord(Packet):
    fields_desc = [
        PacketField("dtcAndStatus", None, pkt_cls=DTCAndStatusRecord),
        PacketListField("snapshots", None, pkt_cls=DTCSnapshot)
    ]


class UDS_RDTCIPR(Packet):
    name = 'ReadDTCInformationPositiveResponse'
    fields_desc = [
        ByteEnumField('reportType', 0, UDS_RDTCI.reportTypes),
        ConditionalField(
            FlagsField('DTCStatusAvailabilityMask', 0, 8, UDS_RDTCI.dtcStatus),
            lambda pkt: pkt.reportType in [0x01, 0x07, 0x11, 0x12, 0x02, 0x0A,
                                           0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x13,
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
        ConditionalField(PacketListField('DTCAndStatusRecord', None,
                                         pkt_cls=DTCAndStatusRecord),
                         lambda pkt: pkt.reportType in [0x02, 0x0A, 0x0B,
                                                        0x0C, 0x0D, 0x0E,
                                                        0x0F, 0x13, 0x15]),
        ConditionalField(StrField('dataRecord', b""),
                         lambda pkt: pkt.reportType in [0x03, 0x08, 0x09,
                                                        0x10, 0x14]),
        ConditionalField(PacketField('snapshotRecord', None,
                                     pkt_cls=DTCSnapshotRecord),
                         lambda pkt: pkt.reportType in [0x04]),
        ConditionalField(PacketField('extendedDataRecord', None,
                                     pkt_cls=DTCExtendedDataRecord),
                         lambda pkt: pkt.reportType in [0x06])
    ]

    def answers(self, other):
        if not isinstance(other, UDS_RDTCI):
            return False
        if not other.reportType == self.reportType:
            return False
        if self.reportType == 0x06:
            return other.dtc == self.extendedDataRecord.dtcAndStatus.dtc
        if self.reportType == 0x04:
            return other.dtc == self.snapshotRecord.dtcAndStatus.dtc
        return True


bind_layers(UDS, UDS_RDTCIPR, service=0x59)


# #########################RC###################################
class UDS_RC(Packet):
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


bind_layers(UDS, UDS_RC, service=0x31)


class UDS_RCPR(Packet):
    name = 'RoutineControlPositiveResponse'
    fields_desc = [
        ByteEnumField('routineControlType', 0, UDS_RC.routineControlTypes),
        XShortEnumField('routineIdentifier', 0,
                        UDS_RC.routineControlIdentifiers),
    ]

    def answers(self, other):
        return isinstance(other, UDS_RC) \
            and other.routineControlType == self.routineControlType \
            and other.routineIdentifier == self.routineIdentifier


bind_layers(UDS, UDS_RCPR, service=0x71)


# #########################RD###################################
class UDS_RD(Packet):
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


bind_layers(UDS, UDS_RD, service=0x34)


class UDS_RDPR(Packet):
    name = 'RequestDownloadPositiveResponse'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('reserved', 0, 4),
        StrField('maxNumberOfBlockLength', b"", fmt="B"),
    ]

    def answers(self, other):
        return isinstance(other, UDS_RD)


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
        BitField('memorySizeLen', 0, 4),
        BitField('reserved', 0, 4),
        StrField('maxNumberOfBlockLength', b"", fmt="B"),
    ]

    def answers(self, other):
        return isinstance(other, UDS_RU)


bind_layers(UDS, UDS_RUPR, service=0x75)


# #########################TD###################################
class UDS_TD(Packet):
    name = 'TransferData'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferRequestParameterRecord', b"", fmt="B")
    ]


bind_layers(UDS, UDS_TD, service=0x36)


class UDS_TDPR(Packet):
    name = 'TransferDataPositiveResponse'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferResponseParameterRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return isinstance(other, UDS_TD) \
            and other.blockSequenceCounter == self.blockSequenceCounter


bind_layers(UDS, UDS_TDPR, service=0x76)


# #########################RTE###################################
class UDS_RTE(Packet):
    name = 'RequestTransferExit'
    fields_desc = [
        StrField('transferRequestParameterRecord', b"", fmt="B")
    ]


bind_layers(UDS, UDS_RTE, service=0x37)


class UDS_RTEPR(Packet):
    name = 'RequestTransferExitPositiveResponse'
    fields_desc = [
        StrField('transferResponseParameterRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return isinstance(other, UDS_RTE)


bind_layers(UDS, UDS_RTEPR, service=0x77)


# #########################RFT###################################
class UDS_RFT(Packet):
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
        FieldLenField('filePathAndNameLength', None,
                      length_of='filePathAndName', fmt='H'),
        StrLenField('filePathAndName', b"",
                    length_from=lambda p: p.filePathAndNameLength),
        ConditionalField(BitField('compressionMethod', 0, 4),
                         lambda p: p.modeOfOperation not in [2, 5]),
        ConditionalField(BitField('encryptingMethod', 0, 4),
                         lambda p: p.modeOfOperation not in [2, 5]),
        ConditionalField(FieldLenField('fileSizeParameterLength', None,
                                       fmt="B",
                                       length_of='fileSizeUnCompressed'),
                         lambda p: UDS_RFT._contains_file_size(p)),
        ConditionalField(StrLenField('fileSizeUnCompressed', b"",
                                     length_from=lambda p:
                                     p.fileSizeParameterLength),
                         lambda p: UDS_RFT._contains_file_size(p)),
        ConditionalField(StrLenField('fileSizeCompressed', b"",
                                     length_from=lambda p:
                                     p.fileSizeParameterLength),
                         lambda p: UDS_RFT._contains_file_size(p))
    ]


bind_layers(UDS, UDS_RFT, service=0x38)


class UDS_RFTPR(Packet):
    name = 'RequestFileTransferPositiveResponse'

    @staticmethod
    def _contains_data_format_identifier(packet):
        return packet.modeOfOperation != 0x02

    fields_desc = [
        XByteEnumField('modeOfOperation', 0, UDS_RFT.modeOfOperations),
        ConditionalField(FieldLenField('lengthFormatIdentifier', None,
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
        ConditionalField(FieldLenField('fileSizeOrDirInfoParameterLength',
                                       None,
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
        return isinstance(other, UDS_RFT)


bind_layers(UDS, UDS_RFTPR, service=0x78)


# #########################IOCBI###################################
class UDS_IOCBI(Packet):
    name = 'InputOutputControlByIdentifier'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0, UDS_RDBI.dataIdentifiers),
    ]


bind_layers(UDS, UDS_IOCBI, service=0x2F)


class UDS_IOCBIPR(Packet):
    name = 'InputOutputControlByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0, UDS_RDBI.dataIdentifiers),
    ]

    def answers(self, other):
        return isinstance(other, UDS_IOCBI) \
            and other.dataIdentifier == self.dataIdentifier


bind_layers(UDS, UDS_IOCBIPR, service=0x6F)


# #########################NR###################################
class UDS_NR(Packet):
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
        0x34: 'authenticationRequired',
        0x35: 'invalidKey',
        0x36: 'exceedNumberOfAttempts',
        0x37: 'requiredTimeDelayNotExpired',
        0x3A: 'secureDataVerificationFailed',
        0x50: 'certificateVerificationFailedInvalidTimePeriod',
        0x51: 'certificateVerificationFailedInvalidSignature',
        0x52: 'certificateVerificationFailedInvalidChainOfTrust',
        0x53: 'certificateVerificationFailedInvalidType',
        0x54: 'certificateVerificationFailedInvalidFormat',
        0x55: 'certificateVerificationFailedInvalidContent',
        0x56: 'certificateVerificationFailedInvalidScope',
        0x57: 'certificateVerificationFailedInvalidCertificateRevoked',
        0x58: 'ownershipVerificationFailed',
        0x59: 'challengeCalculationFailed',
        0x5a: 'settingAccessRightsFailed',
        0x5b: 'sessionKeyCreationOrDerivationFailed',
        0x5c: 'configurationDataUsageFailed',
        0x5d: 'deAuthenticationFailed',
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
        XByteEnumField('requestServiceId', 0, UDS.services),
        ByteEnumField('negativeResponseCode', 0, negativeResponseCodes)
    ]

    def answers(self, other):
        return self.requestServiceId == other.service and \
            (self.negativeResponseCode != 0x78 or
             conf.contribs['UDS']['treat-response-pending-as-answer'])


bind_layers(UDS, UDS_NR, service=0x7f)


# ##################################################################
# ######################## UTILS ###################################
# ##################################################################


class UDS_TesterPresentSender(PeriodicSenderThread):
    def __init__(self, sock, pkt=UDS() / UDS_TP(subFunction=0x80), interval=2):
        """ Thread to send TesterPresent messages packets periodically

        Args:
            sock: socket where packet is sent periodically
            pkt: packet to send
            interval: interval between two packets
        """
        PeriodicSenderThread.__init__(self, sock, pkt, interval)
