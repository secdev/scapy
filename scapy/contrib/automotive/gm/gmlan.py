# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Enrico Pozzobon <enrico.pozzobon@gmail.com>

# scapy.contrib.description = General Motors Local Area Network (GMLAN)
# scapy.contrib.status = loads

import struct

from scapy.contrib.automotive import log_automotive
from scapy.fields import ObservableDict, XByteEnumField, ByteEnumField, \
    ConditionalField, XByteField, StrField, XShortEnumField, XShortField, \
    X3BytesField, XIntField, ShortField, PacketField, PacketListField, \
    FieldListField, MultipleTypeField, StrFixedLenField
from scapy.packet import Packet, bind_layers, NoPayload
from scapy.config import conf
from scapy.contrib.isotp import ISOTP

"""
GMLAN
"""

try:
    if conf.contribs['GMLAN']['treat-response-pending-as-answer']:
        pass
except KeyError:
    log_automotive.info("Specify \"conf.contribs['GMLAN'] = "
                        "{'treat-response-pending-as-answer': True}\" to treat "
                        "a negative response 'RequestCorrectlyReceived-"
                        "ResponsePending' as answer of a request. \n"
                        "The default value is False.")
    conf.contribs['GMLAN'] = {'treat-response-pending-as-answer': False}

conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme'] = None


class GMLAN(ISOTP):
    @staticmethod
    def determine_len(x):
        if conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme'] is None:
            log_automotive.warning(
                "Define conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme']! "
                "Assign either 2,3 or 4")
        if conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme'] \
                not in [2, 3, 4]:
            log_automotive.warning(
                "Define conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme']! "
                "Assign either 2,3 or 4")
        return conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme'] == x

    services = ObservableDict(
        {0x04: 'ClearDiagnosticInformation',
         0x10: 'InitiateDiagnosticOperation',
         0x12: 'ReadFailureRecordData',
         0x1a: 'ReadDataByIdentifier',
         0x20: 'ReturnToNormalOperation',
         0x22: 'ReadDataByParameterIdentifier',
         0x23: 'ReadMemoryByAddress',
         0x27: 'SecurityAccess',
         0x28: 'DisableNormalCommunication',
         0x2c: 'DynamicallyDefineMessage',
         0x2d: 'DefinePIDByAddress',
         0x34: 'RequestDownload',
         0x36: 'TransferData',
         0x3b: 'WriteDataByIdentifier',
         0x3e: 'TesterPresent',
         0x44: 'ClearDiagnosticInformationPositiveResponse',
         0x50: 'InitiateDiagnosticOperationPositiveResponse',
         0x52: 'ReadFailureRecordDataPositiveResponse',
         0x5a: 'ReadDataByIdentifierPositiveResponse',
         0x60: 'ReturnToNormalOperationPositiveResponse',
         0x62: 'ReadDataByParameterIdentifierPositiveResponse',
         0x63: 'ReadMemoryByAddressPositiveResponse',
         0x67: 'SecurityAccessPositiveResponse',
         0x68: 'DisableNormalCommunicationPositiveResponse',
         0x6c: 'DynamicallyDefineMessagePositiveResponse',
         0x6d: 'DefinePIDByAddressPositiveResponse',
         0x74: 'RequestDownloadPositiveResponse',
         0x76: 'TransferDataPositiveResponse',
         0x7b: 'WriteDataByIdentifierPositiveResponse',
         0x7e: 'TesterPresentPositiveResponse',
         0x7f: 'NegativeResponse',
         0xa2: 'ReportProgrammingState',
         0xa5: 'ProgrammingMode',
         0xa9: 'ReadDiagnosticInformation',
         0xaa: 'ReadDataByPacketIdentifier',
         0xae: 'DeviceControl',
         0xe2: 'ReportProgrammingStatePositiveResponse',
         0xe5: 'ProgrammingModePositiveResponse',
         0xe9: 'ReadDiagnosticInformationPositiveResponse',
         0xea: 'ReadDataByPacketIdentifierPositiveResponse',
         0xee: 'DeviceControlPositiveResponse'})
    name = 'General Motors Local Area Network'
    fields_desc = [
        XByteEnumField('service', 0, services)
    ]

    def answers(self, other):
        if not isinstance(other, type(self)):
            return False
        if self.service == 0x7f:
            return self.payload.answers(other)
        if self.service == (other.service + 0x40):
            if isinstance(self.payload, NoPayload) or \
                    isinstance(other.payload, NoPayload):
                return True
            else:
                return self.payload.answers(other.payload)
        return False

    def hashret(self):
        if self.service == 0x7f:
            return struct.pack('B', self.requestServiceId)
        return struct.pack('B', self.service & ~0x40)


# ########################IDO###################################
class GMLAN_IDO(Packet):
    subfunctions = {
        0x02: 'disableAllDTCs',
        0x03: 'enableDTCsDuringDevCntrl',
        0x04: 'wakeUpLinks'}
    name = 'InitiateDiagnosticOperation'
    fields_desc = [
        ByteEnumField('subfunction', 0, subfunctions)
    ]


bind_layers(GMLAN, GMLAN_IDO, service=0x10)


# ########################RFRD###################################
class GMLAN_DTC(Packet):
    name = 'GMLAN DTC information'
    fields_desc = [
        XByteField('failureRecordNumber', 0),
        XByteField('DTCHighByte', 0),
        XByteField('DTCLowByte', 0),
        XByteField('DTCFailureType', 0)
    ]

    def extract_padding(self, p):
        return "", p


class GMLAN_RFRD(Packet):
    subfunctions = {
        0x01: 'readFailureRecordIdentifiers',
        0x02: 'readFailureRecordParameters'}
    name = 'ReadFailureRecordData'
    fields_desc = [
        ByteEnumField('subfunction', 0, subfunctions),
        ConditionalField(PacketField("dtc", b'', GMLAN_DTC),
                         lambda pkt: pkt.subfunction == 0x02)
    ]


bind_layers(GMLAN, GMLAN_RFRD, service=0x12)


class GMLAN_RFRDPR(Packet):
    name = 'ReadFailureRecordDataPositiveResponse'
    fields_desc = [
        ByteEnumField('subfunction', 0, GMLAN_RFRD.subfunctions)
    ]

    def answers(self, other):
        return isinstance(other, GMLAN_RFRD) and \
            other.subfunction == self.subfunction


bind_layers(GMLAN, GMLAN_RFRDPR, service=0x52)


class GMLAN_RFRDPR_RFRI(Packet):
    failureRecordDataStructureIdentifiers = {
        0x00: "PID",
        0x01: "DPID"
    }
    name = 'ReadFailureRecordDataPositiveResponse_readFailureRecordIdentifiers'
    fields_desc = [
        ByteEnumField('failureRecordDataStructureIdentifier', 0,
                      failureRecordDataStructureIdentifiers),
        PacketListField("dtcs", [], GMLAN_DTC)
    ]


bind_layers(GMLAN_RFRDPR, GMLAN_RFRDPR_RFRI, subfunction=0x01)


class GMLAN_RFRDPR_RFRP(Packet):
    name = 'ReadFailureRecordDataPositiveResponse_readFailureRecordParameters'
    fields_desc = [
        PacketField("dtc", b'', GMLAN_DTC)
    ]


bind_layers(GMLAN_RFRDPR, GMLAN_RFRDPR_RFRP, subfunction=0x02)


# ########################RDBI###################################
class GMLAN_RDBI(Packet):
    dataIdentifiers = ObservableDict({
        0x90: "$90: VehicleIdentificationNumber (VIN)",
        0x92: "$92: SystemSupplierId (SYSSUPPID)",
        0x97: "$97: SystemNameOrEngineType (SNOET)",
        0x98: "$98: RepairShopCodeOrTesterSerialNumber (RSCOTSN)",
        0x99: "$99: ProgrammingDate (PD)",
        0x9a: "$9a: DiagnosticDataIdentifier (DDI)",
        0x9b: "$9b: XmlConfigurationCompatibilityIdentifier (XMLCCID)",
        0x9C: "$9C: XmlDataFilePartNumber (XMLDFPN)",
        0x9D: "$9D: XmlDataFileAlphaCode (XMLDFAC)",
        0x9F: "$9F: PreviousStoredRepairShopCodeOrTesterSerialNumbers "
              "(PSRSCOTSN)",
        0xA0: "$A0: manufacturers_enable_counter (MEC)",
        0xA1: "$A1: ECUConfigurationOrCustomizationData (ECUCOCGD) 1",
        0xA2: "$A2: ECUConfigurationOrCustomizationData (ECUCOCGD) 2",
        0xA3: "$A3: ECUConfigurationOrCustomizationData (ECUCOCGD) 3",
        0xA4: "$A4: ECUConfigurationOrCustomizationData (ECUCOCGD) 4",
        0xA5: "$A5: ECUConfigurationOrCustomizationData (ECUCOCGD) 5",
        0xA6: "$A6: ECUConfigurationOrCustomizationData (ECUCOCGD) 6",
        0xA7: "$A7: ECUConfigurationOrCustomizationData (ECUCOCGD) 7",
        0xA8: "$A8: ECUConfigurationOrCustomizationData (ECUCOCGD) 8",
        0xB0: "$B0: ECUDiagnosticAddress (ECUADDR)",
        0xB1: "$B1: ECUFunctionalSystemsAndVirtualDevices (ECUFSAVD)",
        0xB2: "$B2: GM ManufacturingData (GMMD)",
        0xB3: "$B3: Data Universal Numbering System Identification (DUNS)",
        0xB4: "$B4: Manufacturing Traceability Characters (MTC)",
        0xB5: "$B5: GM BroadcastCode (GMBC)",
        0xB6: "$B6: GM Target Vehicle (GMTV)",
        0xB7: "$B7: GM Software Usage Description (GMSUD)",
        0xB8: "$B8: GM Bench Verification Information (GMBVI)",
        0xB9: "$B9: Subnet_Config_List_HighSpeed (SCLHS)",
        0xBA: "$BA: Subnet_Config_List_LowSpeed (SCLLS)",
        0xBB: "$BB: Subnet_Config_List_MidSpeed (SCLMS)",
        0xBC: "$BC: Subnet_Config_List_NonCan 1 (SCLNC 1)",
        0xBD: "$BD: Subnet_Config_List_NonCan 2 (SCLNC 2)",
        0xBE: "$BE: Subnet_Config_List_LIN (SCLLIN)",
        0xBF: "$BF: Subnet_Config_List_GMLANChassisExpansionBus (SCLGCEB)",
        0xC0: "$C0: BootSoftwarePartNumber (BSPN)",
        0xC1: "$C1: SoftwareModuleIdentifier (SWMI) 01",
        0xC2: "$C2: SoftwareModuleIdentifier (SWMI) 02",
        0xC3: "$C3: SoftwareModuleIdentifier (SWMI) 03",
        0xC4: "$C4: SoftwareModuleIdentifier (SWMI) 04",
        0xC5: "$C5: SoftwareModuleIdentifier (SWMI) 05",
        0xC6: "$C6: SoftwareModuleIdentifier (SWMI) 06",
        0xC7: "$C7: SoftwareModuleIdentifier (SWMI) 07",
        0xC8: "$C8: SoftwareModuleIdentifier (SWMI) 08",
        0xC9: "$C9: SoftwareModuleIdentifier (SWMI) 09",
        0xCA: "$CA: SoftwareModuleIdentifier (SWMI) 10",
        0xCB: "$CB: EndModelPartNumber",
        0xCC: "$CC: BaseModelPartNumber (BMPN)",
        0xD0: "$D0: BootSoftwarePartNumberAlphaCode",
        0xD1: "$D1: SoftwareModuleIdentifierAlphaCode (SWMIAC) 01",
        0xD2: "$D2: SoftwareModuleIdentifierAlphaCode (SWMIAC) 02",
        0xD3: "$D3: SoftwareModuleIdentifierAlphaCode (SWMIAC) 03",
        0xD4: "$D4: SoftwareModuleIdentifierAlphaCode (SWMIAC) 04",
        0xD5: "$D5: SoftwareModuleIdentifierAlphaCode (SWMIAC) 05",
        0xD6: "$D6: SoftwareModuleIdentifierAlphaCode (SWMIAC) 06",
        0xD7: "$D7: SoftwareModuleIdentifierAlphaCode (SWMIAC) 07",
        0xD8: "$D8: SoftwareModuleIdentifierAlphaCode (SWMIAC) 08",
        0xD9: "$D9: SoftwareModuleIdentifierAlphaCode (SWMIAC) 09",
        0xDA: "$DA: SoftwareModuleIdentifierAlphaCode (SWMIAC) 10",
        0xDB: "$DB: EndModelPartNumberAlphaCode",
        0xDC: "$DC: BaseModelPartNumberAlphaCode",
        0xDD: "$DD: SoftwareModuleIdentifierDataIdentifiers (SWMIDID)",
        0xDE: "$DE: GMLANIdentificationData (GMLANID)",
        0xDF: "$DF: ECUOdometerValue (ECUODO)",
        0xE0: "$E0: VehicleLevelDataRecord (VLDR) 0",
        0xE1: "$E1: VehicleLevelDataRecord (VLDR) 1",
        0xE2: "$E2: VehicleLevelDataRecord (VLDR) 2",
        0xE3: "$E3: VehicleLevelDataRecord (VLDR) 3",
        0xE4: "$E4: VehicleLevelDataRecord (VLDR) 4",
        0xE5: "$E5: VehicleLevelDataRecord (VLDR) 5",
        0xE6: "$E6: VehicleLevelDataRecord (VLDR) 6",
        0xE7: "$E7: VehicleLevelDataRecord (VLDR) 7",
        0xE8: "$E8: Subnet_Config_List_GMLANPowertrainExpansionBus (SCLGPEB)",
        0xE9: "$E9: Subnet_Config_List_GMLANFrontObjectExpansionBus "
              "(SCLGFOEB)",
        0xEA: "$EA: Subnet_Config_List_GMLANRearObjectExpansionBus (SCLGROEB)",
        0xEB: "$EB: Subnet_Config_List_GMLANExpansionBus1 (SCLGEB1)",
        0xEC: "$EC: Subnet_Config_List_GMLANExpansionBus2 (SCLGEB2)",
        0xED: "$ED: Subnet_Config_List_GMLANExpansionBus3 (SCLGEB3)",
        0xEE: "$EE: Subnet_Config_List_GMLANExpansionBus4 (SCLGEB4)",
        0xEF: "$EF: Subnet_Config_List_GMLANExpansionBus5 (SCLGEB5)",
    })

    name = 'ReadDataByIdentifier'
    fields_desc = [
        XByteEnumField('dataIdentifier', 0, dataIdentifiers)
    ]


bind_layers(GMLAN, GMLAN_RDBI, service=0x1A)


class GMLAN_RDBIPR(Packet):
    name = 'ReadDataByIdentifierPositiveResponse'
    fields_desc = [
        XByteEnumField('dataIdentifier', 0, GMLAN_RDBI.dataIdentifiers),
    ]

    def answers(self, other):
        return isinstance(other, GMLAN_RDBI) and \
            other.dataIdentifier == self.dataIdentifier


bind_layers(GMLAN, GMLAN_RDBIPR, service=0x5A)


# ########################RDBI###################################
class GMLAN_RDBPI(Packet):
    dataIdentifiers = ObservableDict({
        0x0005: "OBD_EngineCoolantTemperature",
        0x000C: "OBD_EngineRPM",
        0x001f: "OBD_TimeSinceEngineStart"
    })
    name = 'ReadDataByParameterIdentifier'
    fields_desc = [
        FieldListField("identifiers", [],
                       XShortEnumField('parameterIdentifier', 0,
                                       dataIdentifiers))
    ]


bind_layers(GMLAN, GMLAN_RDBPI, service=0x22)


class GMLAN_RDBPIPR(Packet):
    name = 'ReadDataByParameterIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('parameterIdentifier', 0, GMLAN_RDBPI.dataIdentifiers),
    ]

    def answers(self, other):
        return isinstance(other, GMLAN_RDBPI) and \
            self.parameterIdentifier in other.identifiers


bind_layers(GMLAN, GMLAN_RDBPIPR, service=0x62)


# ########################RDBPKTI###################################
class GMLAN_RDBPKTI(Packet):
    name = 'ReadDataByPacketIdentifier'
    subfunctions = {
        0x00: "stopSending",
        0x01: "sendOneResponse",
        0x02: "scheduleAtSlowRate",
        0x03: "scheduleAtMediumRate",
        0x04: "scheduleAtFastRate"
    }

    fields_desc = [
        XByteEnumField('subfunction', 0, subfunctions),
        ConditionalField(FieldListField('request_DPIDs', [],
                                        XByteField("", 0)),
                         lambda pkt: pkt.subfunction > 0x0)
    ]


bind_layers(GMLAN, GMLAN_RDBPKTI, service=0xAA)


# ########################RMBA###################################
class GMLAN_RMBA(Packet):
    name = 'ReadMemoryByAddress'
    fields_desc = [
        MultipleTypeField(
            [
                (XShortField('memoryAddress', 0),
                 lambda pkt: GMLAN.determine_len(2)),
                (X3BytesField('memoryAddress', 0),
                 lambda pkt: GMLAN.determine_len(3)),
                (XIntField('memoryAddress', 0),
                 lambda pkt: GMLAN.determine_len(4))
            ],
            XIntField('memoryAddress', 0)),
        XShortField('memorySize', 0),
    ]


bind_layers(GMLAN, GMLAN_RMBA, service=0x23)


class GMLAN_RMBAPR(Packet):
    name = 'ReadMemoryByAddressPositiveResponse'
    fields_desc = [
        MultipleTypeField(
            [
                (XShortField('memoryAddress', 0),
                 lambda pkt: GMLAN.determine_len(2)),
                (X3BytesField('memoryAddress', 0),
                 lambda pkt: GMLAN.determine_len(3)),
                (XIntField('memoryAddress', 0),
                 lambda pkt: GMLAN.determine_len(4))
            ],
            XIntField('memoryAddress', 0)),
        StrField('dataRecord', b"", fmt="B")
    ]

    def answers(self, other):
        return isinstance(other, GMLAN_RMBA) and \
            other.memoryAddress == self.memoryAddress


bind_layers(GMLAN, GMLAN_RMBAPR, service=0x63)


# ########################SA###################################
class GMLAN_SA(Packet):
    subfunctions = {
        0: 'ReservedByDocument',
        1: 'SPSrequestSeed',
        2: 'SPSsendKey',
        3: 'DevCtrlrequestSeed',
        4: 'DevCtrlsendKey',
        255: 'ReservedByDocument'}
    for i in range(0x05, 0x0a + 1):
        subfunctions[i] = 'ReservedByDocument'
    for i in range(0x0b, 0xfa + 1):
        subfunctions[i] = 'Reserved for vehicle manufacturer specific needs'
    for i in range(0xfb, 0xfe + 1):
        subfunctions[i] = 'Reserved for ECU or ' \
                          'system supplier manufacturing needs'

    name = 'SecurityAccess'
    fields_desc = [
        ByteEnumField('subfunction', 0, subfunctions),
        ConditionalField(XShortField('securityKey', 0),
                         lambda pkt: pkt.subfunction % 2 == 0)
    ]


bind_layers(GMLAN, GMLAN_SA, service=0x27)


class GMLAN_SAPR(Packet):
    name = 'SecurityAccessPositiveResponse'
    fields_desc = [
        ByteEnumField('subfunction', 0, GMLAN_SA.subfunctions),
        ConditionalField(XShortField('securitySeed', 0),
                         lambda pkt: pkt.subfunction % 2 == 1),
    ]

    def answers(self, other):
        return isinstance(other, GMLAN_SA) \
            and other.subfunction == self.subfunction


bind_layers(GMLAN, GMLAN_SAPR, service=0x67)


# ########################DDM###################################
class GMLAN_DDM(Packet):
    name = 'DynamicallyDefineMessage'
    fields_desc = [
        XByteField('DPIDIdentifier', 0),
        StrField('PIDData', b'\x00\x00')
    ]


bind_layers(GMLAN, GMLAN_DDM, service=0x2C)


class GMLAN_DDMPR(Packet):
    name = 'DynamicallyDefineMessagePositiveResponse'
    fields_desc = [
        XByteField('DPIDIdentifier', 0)
    ]

    def answers(self, other):
        return isinstance(other, GMLAN_DDM) \
            and other.DPIDIdentifier == self.DPIDIdentifier


bind_layers(GMLAN, GMLAN_DDMPR, service=0x6C)


# ########################DPBA###################################
class GMLAN_DPBA(Packet):
    name = 'DefinePIDByAddress'
    fields_desc = [
        XShortField('parameterIdentifier', 0),
        MultipleTypeField(
            [
                (XShortField('memoryAddress', 0),
                 lambda pkt: GMLAN.determine_len(2)),
                (X3BytesField('memoryAddress', 0),
                 lambda pkt: GMLAN.determine_len(3)),
                (XIntField('memoryAddress', 0),
                 lambda pkt: GMLAN.determine_len(4))
            ],
            XIntField('memoryAddress', 0)),
        XByteField('memorySize', 0),
    ]


bind_layers(GMLAN, GMLAN_DPBA, service=0x2D)


class GMLAN_DPBAPR(Packet):
    name = 'DefinePIDByAddressPositiveResponse'
    fields_desc = [
        XShortField('parameterIdentifier', 0),
    ]

    def answers(self, other):
        return isinstance(other, GMLAN_DPBA) \
            and other.parameterIdentifier == self.parameterIdentifier


bind_layers(GMLAN, GMLAN_DPBAPR, service=0x6D)


# ########################RD###################################
class GMLAN_RD(Packet):
    name = 'RequestDownload'
    fields_desc = [
        XByteField('dataFormatIdentifier', 0),
        MultipleTypeField(
            [
                (XShortField('memorySize', 0),
                 lambda pkt: GMLAN.determine_len(2)),
                (X3BytesField('memorySize', 0),
                 lambda pkt: GMLAN.determine_len(3)),
                (XIntField('memorySize', 0),
                 lambda pkt: GMLAN.determine_len(4))
            ],
            XIntField('memorySize', 0))
    ]


bind_layers(GMLAN, GMLAN_RD, service=0x34)


# ########################TD###################################
class GMLAN_TD(Packet):
    subfunctions = {
        0x00: "download",
        0x80: "downloadAndExecuteOrExecute"
    }
    name = 'TransferData'
    fields_desc = [
        ByteEnumField('subfunction', 0, subfunctions),
        MultipleTypeField(
            [
                (XShortField('startingAddress', 0),
                 lambda pkt: GMLAN.determine_len(2)),
                (X3BytesField('startingAddress', 0),
                 lambda pkt: GMLAN.determine_len(3)),
                (XIntField('startingAddress', 0),
                 lambda pkt: GMLAN.determine_len(4))
            ],
            XIntField('startingAddress', 0)),
        StrField("dataRecord", b"")
    ]


bind_layers(GMLAN, GMLAN_TD, service=0x36)


# ########################WDBI###################################
class GMLAN_WDBI(Packet):
    name = 'WriteDataByIdentifier'
    fields_desc = [
        XByteEnumField('dataIdentifier', 0, GMLAN_RDBI.dataIdentifiers),
        StrField("dataRecord", b'')
    ]


bind_layers(GMLAN, GMLAN_WDBI, service=0x3B)


class GMLAN_WDBIPR(Packet):
    name = 'WriteDataByIdentifierPositiveResponse'
    fields_desc = [
        XByteEnumField('dataIdentifier', 0, GMLAN_RDBI.dataIdentifiers)
    ]

    def answers(self, other):
        return isinstance(other, GMLAN_WDBI) \
            and other.dataIdentifier == self.dataIdentifier


bind_layers(GMLAN, GMLAN_WDBIPR, service=0x7B)


# ########################RPSPR###################################
class GMLAN_RPSPR(Packet):
    programmedStates = {
        0x00: "fully programmed",
        0x01: "no op s/w or cal data",
        0x02: "op s/w present, cal data missing",
        0x03: "s/w present, default or no start cal present",
        0x50: "General Memory Fault",
        0x51: "RAM Memory Fault",
        0x52: "NVRAM Memory Fault",
        0x53: "Boot Memory Failure",
        0x54: "Flash Memory Failure",
        0x55: "EEPROM Memory Failure",
    }
    name = 'ReportProgrammedStatePositiveResponse'
    fields_desc = [
        ByteEnumField('programmedState', 0, programmedStates),
    ]


bind_layers(GMLAN, GMLAN_RPSPR, service=0xE2)


# ########################PM###################################
class GMLAN_PM(Packet):
    subfunctions = {
        0x01: "requestProgrammingMode",
        0x02: "requestProgrammingMode_HighSpeed",
        0x03: "enableProgrammingMode"
    }
    name = 'ProgrammingMode'
    fields_desc = [
        ByteEnumField('subfunction', 0, subfunctions),
    ]


bind_layers(GMLAN, GMLAN_PM, service=0xA5)


# ########################RDI###################################
class GMLAN_RDI(Packet):
    subfunctions = {
        0x80: 'readStatusOfDTCByDTCNumber',
        0x81: 'readStatusOfDTCByStatusMask',
        0x82: 'sendOnChangeDTCCount'
    }
    name = 'ReadDiagnosticInformation'
    fields_desc = [
        ByteEnumField('subfunction', 0, subfunctions)
    ]


bind_layers(GMLAN, GMLAN_RDI, service=0xA9)


class GMLAN_RDI_BN(Packet):
    name = 'ReadStatusOfDTCByDTCNumber'
    fields_desc = [
        XByteField('DTCHighByte', 0),
        XByteField('DTCLowByte', 0),
        XByteField('DTCFailureType', 0),
    ]


bind_layers(GMLAN_RDI, GMLAN_RDI_BN, subfunction=0x80)


class GMLAN_RDI_BM(Packet):
    name = 'ReadStatusOfDTCByStatusMask'
    fields_desc = [
        XByteField('DTCStatusMask', 0),
    ]


bind_layers(GMLAN_RDI, GMLAN_RDI_BM, subfunction=0x81)


class GMLAN_RDI_BC(Packet):
    name = 'SendOnChangeDTCCount'
    fields_desc = [
        XByteField('DTCStatusMask', 0),
    ]


bind_layers(GMLAN_RDI, GMLAN_RDI_BC, subfunction=0x82)


# TODO:This function receive single frame responses... (Implement GMLAN Socket)


# ########################DC###################################
class GMLAN_DC(Packet):
    name = 'DeviceControl'
    fields_desc = [
        XByteField('CPIDNumber', 0),
        StrFixedLenField('CPIDControlBytes', b"", 5)
    ]


bind_layers(GMLAN, GMLAN_DC, service=0xAE)


class GMLAN_DCPR(Packet):
    name = 'DeviceControlPositiveResponse'
    fields_desc = [
        XByteField('CPIDNumber', 0)
    ]

    def answers(self, other):
        return isinstance(other, GMLAN_DC) \
            and other.CPIDNumber == self.CPIDNumber


bind_layers(GMLAN, GMLAN_DCPR, service=0xEE)


# ########################NRC###################################
class GMLAN_NR(Packet):
    negativeResponseCodes = {
        0x11: 'ServiceNotSupported',
        0x12: 'SubFunctionNotSupported',
        0x22: 'ConditionsNotCorrectOrRequestSequenceError',
        0x31: 'RequestOutOfRange',
        0x35: 'InvalidKey',
        0x36: 'ExceedNumberOfAttempts',
        0x37: 'RequiredTimeDelayNotExpired',
        0x78: 'RequestCorrectlyReceived-ResponsePending',
        0x81: 'SchedulerFull',
        0x83: 'VoltageOutOfRange',
        0x85: 'GeneralProgrammingFailure',
        0x89: 'DeviceTypeError',
        0x99: 'ReadyForDownload-DTCStored',
        0xe3: 'DeviceControlLimitsExceeded',
    }
    name = 'NegativeResponse'
    fields_desc = [
        XByteEnumField('requestServiceId', 0, GMLAN.services),
        ByteEnumField('returnCode', 0, negativeResponseCodes),
        ShortField('deviceControlLimitExceeded', 0)
    ]

    def answers(self, other):
        return self.requestServiceId == other.service and \
            (self.returnCode != 0x78 or
             conf.contribs['GMLAN']['treat-response-pending-as-answer'])


bind_layers(GMLAN, GMLAN_NR, service=0x7f)
