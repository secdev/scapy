# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) 2016 Gauthier Sebaux

"""
PNIO RPC constants
"""

##################
## Block Packet ##
##################

BLOCK_TYPES_ENUM = {
    0x0000: "AlarmNotification_High",
    0x0001: "AlarmNotification_Low",
    0x0008: "IODWriteReqHeader",
    0x0009: "IODReadReqHeader",
    0x0010: "DiagnosisData",
    0x0012: "ExpectedIdentificationData",
    0x0013: "RealIdentificationData",
    0x0014: "SubsituteValue",
    0x0015: "RecordInputDataObjectElement",
    0x0016: "RecordOutputDataObjectElement",
    0x0018: "ARData",
    0x0019: "LogBookData",
    0x001a: "APIData",
    0x001b: "SRLData",
    0x0020: "I&M0",
    0x0021: "I&M1",
    0x0022: "I&M2",
    0x0023: "I&M3",
    0x0024: "I&M4",
    0x0030: "I&M0FilterDataSubmodule",
    0x0031: "I&M0FilterDataModule",
    0x0032: "I&M0FilterDataDevice",
    0x0101: "ARBlockReq",
    0x0102: "IOCRBlockReq",
    0x0103: "AlarmCRBlockReq",
    0x0104: "ExpectedSubmoduleBlockReq",
    0x0105: "PrmServerBlockReq",
    0x0106: "MCRBlockReq",
    0x0107: "ARRPCBlockReq",
    0x0108: "ARVendorBlockReq",
    0x0109: "IRInfoBlock",
    0x010a: "SRInfoBlock",
    0x010b: "ARFSUBlock",
    0x0110: "IODBlockReq_connect_end",
    0x0111: "IODBlockReq_plug",
    0x0112: "IOXBlockReq_connect",
    0x0113: "IOXBlockReq_plug",
    0x0114: "ReleaseBlockReq",
    0x0116: "IOXBlockReq_companion",
    0x0117: "IOXBlockReq_rt_class_3",
    0x0118: "IODBlockReq_connect_begin",
    0x0119: "SubmoduleListBlock",
    0x0200: "PDPortDataCheck",
    0x0201: "PdevData",
    0x0202: "PDPortDataAdjust",
    0x0203: "PDSyncData",
    0x0204: "IsochronousModeData",
    0x0205: "PDIRData",
    0x0206: "PDIRGlobalData",
    0x0207: "PDIRFrameData",
    0x0208: "PDIRBeginEndData",
    0x0209: "AdjustDomainBoundary",
    0x020a: "SubBlock_check_Peers",
    0x020b: "SubBlock_check_LineDelay",
    0x020c: "SubBlock_check_MAUType",
    0x020e: "AdjustMAUType",
    0x020f: "PDPortDataReal",
    0x0210: "AdjustMulticastBoundary",
    0x0211: "PDInterfaceMrpDataAdjust",
    0x0212: "PDInterfaceMrpDataReal",
    0x0213: "PDInterfaceMrpDataCheck",
    0x0214: "PDPortMrpDataAdjust",
    0x0215: "PDPortMrpDataReal",
    0x0216: "MrpManagerParams",
    0x0217: "MrpClientParams",
    0x0219: "MrpRingStateData",
    0x021b: "AdjustLinkState",
    0x021c: "CheckLinkState",
    0x021e: "CheckSyncDifference",
    0x021f: "CheckMAUTypeDifference",
    0x0220: "PDPortFODataReal",
    0x0221: "FiberOpticManufacturerSpecific",
    0x0222: "PDPortFODataAdjust",
    0x0223: "PDPortFODataCheck",
    0x0224: "AdjustPeerToPeerBoundary",
    0x0225: "AdjustDCPBoundary",
    0x0226: "AdjustPreambleLength",
    0x0228: "FiberOpticDiagnosisInfo",
    0x022a: "PDIRSubframeData",
    0x022b: "SubframeBlock",
    0x022d: "PDTimeData",
    0x0230: "PDNCDataCheck",
    0x0231: "MrpInstanceDataAdjustBlock",
    0x0232: "MrpInstanceDataRealBlock",
    0x0233: "MrpInstanceDataCheckBlock",
    0x0240: "PDInterfaceDataReal",
    0x0250: "PDInterfaceAdjust",
    0x0251: "PDPortStatistic",
    0x0400: "MultipleBlockHeader",
    0x0401: "COContainerContent",
    0x0500: "RecordDataReadQuery",
    0x0600: "FSHelloBlock",
    0x0601: "FSParameterBlock",
    0x0608: "PDInterfaceFSUDataAdjust",
    0x0609: "ARFSUDataAdjust",
    0x0700: "AutoConfiguration",
    0x0701: "AutoConfigurationCommunication",
    0x0702: "AutoConfigurationConfiguration",
    0x0703: "AutoConfigurationIsochronous",
    0x0A00: "UploadBLOBQuery",
    0x0A01: "UploadBLOB",
    0x0A02: "NestedDiagnosisInfo",
    0x0F00: "MaintenanceItem",
    0x0F01: "UploadRecord",
    0x0F02: "iParameterItem",
    0x0F03: "RetrieveRecord",
    0x0F04: "RetrieveAllRecord",
    0x8001: "AlarmAckHigh",
    0x8002: "AlarmAckLow",
    0x8008: "IODWriteResHeader",
    0x8009: "IODReadResHeader",
    0x8101: "ARBlockRes",
    0x8102: "IOCRBlockRes",
    0x8103: "AlarmCRBlockRes",
    0x8104: "ModuleDiffBlock",
    0x8105: "PrmServerBlockRes",
    0x8106: "ARServerBlockRes",
    0x8107: "ARRPCBlockRes",
    0x8108: "ARVendorBlockRes",
    0x8110: "IODBlockRes_connect_end",
    0x8111: "IODBlockRes_plug",
    0x8112: "IOXBlockRes_connect",
    0x8113: "IOXBlockRes_plug",
    0x8114: "ReleaseBlockRes",
    0x8116: "IOXBlockRes_companion",
    0x8117: "IOXBlockRes_rt_class_3",
    0x8118: "IODBlockRes_connect_begin",
    }


###############################################
## IODWriteReq & IODWriteMultipleReq Packets ##
###############################################

IOD_WRITE_REQ_INDEX = {
    0x8000: "ExpectedIdentificationData_subslot",
    0x8001: "RealIdentificationData_subslot",
    0x800a: "Diagnosis_channel_subslot",
    0x800b: "Diagnosis_all_subslot",
    0x800c: "Diagnosis_Maintenance_subslot",
    0x8010: "Maintenance_required_in_channel_subslot",
    0x8011: "Maintenance_demanded_in_channel_subslot",
    0x8012: "Maintenance_required_in_all_channels_subslot",
    0x8013: "Maintenance_demanded_in_all_channels_subslot",
    0x801e: "SubstitueValue_subslot",
    0x8020: "PDIRSubframeData_subslot",
    0x8028: "RecordInputDataObjectElement_subslot",
    0x8029: "RecordOutputDataObjectElement_subslot",
    0x802a: "PDPortDataReal_subslot",
    0x802b: "PDPortDataCheck_subslot",
    0x802c: "PDIRData_subslot",
    0x802d: "Expected_PDSyncData_subslot",
    0x802f: "PDPortDataAdjust_subslot",
    0x8030: "IsochronousModeData_subslot",
    0x8031: "Expected_PDTimeData_subslot",
    0x8050: "PDInterfaceMrpDataReal_subslot",
    0x8051: "PDInterfaceMrpDataCheck_subslot",
    0x8052: "PDInterfaceMrpDataAdjust_subslot",
    0x8053: "PDPortMrpDataAdjust_subslot",
    0x8054: "PDPortMrpDataReal_subslot",
    0x8060: "PDPortFODataReal_subslot",
    0x8061: "PDPortFODataCheck_subslot",
    0x8062: "PDPortFODataAdjust_subslot",
    0x8070: "PdNCDataCheck_subslot",
    0x8071: "PDInterfaceAdjust_subslot",
    0x8072: "PDPortStatistic_subslot",
    0x8080: "PDInterfaceDataReal_subslot",
    0x8090: "Expected_PDInterfaceFSUDataAdjust",
    0x80a0: "Energy_saving_profile_record_0",
    0x80b0: "CombinedObjectContainer",
    0x80c0: "Sequence_events_profile_record_0",
    0xaff0: "I&M0",
    0xaff1: "I&M1",
    0xaff2: "I&M2",
    0xaff3: "I&M3",
    0xaff4: "I&M4",
    0xc000: "Expect edIdentificationData_slot",
    0xc001: "RealId entificationData_slot",
    0xc00a: "Diagno sis_channel_slot",
    0xc00b: "Diagnosis_all_slot",
    0xc00c: "Diagnosis_Maintenance_slot",
    0xc010: "Maintenance_required_in_channel_slot",
    0xc011: "Maintenance_demanded_in_channel_slot",
    0xc012: "Maintenance_required_in_all_channels_slot",
    0xc013: "Maintenance_demanded_in_all_channels_slot",
    0xe000: "ExpectedIdentificationData_AR",
    0xe001: "RealIdentificationData_AR",
    0xe002: "ModuleDiffBlock_AR",
    0xe00a: "Diagnosis_channel_AR",
    0xe00b: "Diagnosis_all_AR",
    0xe00c: "Diagnosis_Maintenance_AR",
    0xe010: "Maintenance_required_in_channel_AR",
    0xe011: "Maintenance_demanded_in_channel_AR",
    0xe012: "Maintenance_required_in_all_channels_AR",
    0xe013: "Maintenance_demanded_in_all_channels_AR",
    0xe040: "WriteMultiple",
    0xe050: "ARFSUDataAdjust_AR",
    0xf000: "RealIdentificationData_API",
    0xf00a: "Diagnosis_channel_API",
    0xf00b: "Diagnosis_all_API",
    0xf00c: "Diagnosis_Maintenance_API",
    0xf010: "Maintenance_required_in_channel_API",
    0xf011: "Maintenance_demanded_in_channel_API",
    0xf012: "Maintenance_required_in_all_channels_API",
    0xf013: "Maintenance_demanded_in_all_channels_API",
    0xf020: "ARData_API",
    0xf80c: "Diagnosis_Maintenance_device",
    0xf820: "ARData",
    0xf821: "APIData",
    0xf830: "LogBookData",
    0xf831: "PdevData",
    0xf840: "I&M0FilterData",
    0xf841: "PDRealData",
    0xf842: "PDExpectedData",
    0xf850: "AutoConfiguration",
    0xf860: "GSD_upload",
    0xf861: "Nested_Diagnosis_info",
    0xfbff: "Trigger_index_CMSM",
    }

########################
## ARBlockReq Packets ##
########################

AR_TYPE = {
    0x0001: "IOCARSingle",
    0x0006: "IOSAR",
    0x0010: "IOCARSingle_RT_CLASS_3",
    0x0020: "IOCARSR",
    }


##########################
## IOCRBlockReq Packets ##
##########################

IOCR_TYPE = {
    0x0001: "InputCR",
    0x0002: "OutputCR",
    0x0003: "MulticastProviderCR",
    0x0004: "MulticastConsumerCR",
    }

IOCR_BLOCK_REQ_IOCR_PROPERTIES = {
    0x1: "RT_CLASS_1",
    0x2: "RT_CLASS_2",
    0x3: "RT_CLASS_3",
    0x4: "RT_CLASS_UDP",
    }

# list of all valid activiy uuid for the DceRpc layer with PROFINET RPC
# endpoint
RPC_INTERFACE_UUID = {
    "UUID_IO_DeviceInterface": "dea00001-6c97-11d1-8271-00a02442df7d",
    "UUID_IO_ControllerInterface": "dea00002-6c97-11d1-8271-00a02442df7d",
    "UUID_IO_SupervisorInterface": "dea00003-6c97-11d1-8271-00a02442df7d",
    "UUID_IO_ParameterServerInterface": "dea00004-6c97-11d1-8271-00a02442df7d",
    }
