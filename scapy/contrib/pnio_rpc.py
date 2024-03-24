# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2016 Gauthier Sebaux

# scapy.contrib.description = ProfinetIO Remote Procedure Call (RPC)
# scapy.contrib.status = loads

"""
PNIO RPC endpoints
"""

import struct
from uuid import UUID

from scapy.packet import Packet, Raw, bind_layers
from scapy.config import conf
from scapy.fields import BitField, ByteField, BitEnumField, ByteEnumField, \
    ConditionalField, FieldLenField, FieldListField, IntField, IntEnumField, \
    LenField, MACField, PadField, PacketField, PacketListField, \
    ShortEnumField, ShortField, StrFixedLenField, StrLenField, \
    UUIDField, XByteField, XIntField, XShortEnumField, XShortField
from scapy.layers.dcerpc import DceRpc4, DceRpc4Payload
from scapy.contrib.rtps.common_types import EField
from scapy.compat import bytes_hex
from scapy.volatile import RandUUID

# Block Packet
BLOCK_TYPES_ENUM = {
    0x0001: "AlarmNotification_High",
    0x0002: "AlarmNotification_Low",
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

# IODWriteReq & IODWriteMultipleReq Packets
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

# ARBlockReq Packets
AR_TYPE = {
    0x0001: "IOCARSingle",
    0x0006: "IOSAR",
    0x0010: "IOCARSingle_RT_CLASS_3",
    0x0020: "IOCARSR",
}

# IOCRBlockReq Packets
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

MAU_TYPE = {
    0x0000: "Radio",
    0x001e: "1000-BaseT-FD"
}

MAU_EXTENSION = {
    0x0000: "None",
    0x0100: "Polymeric-Optical-Fiber"
}

LINKSTATE_LINK = {
    0x0000: "Reserved",
    0x0001: "Up",
    0x0002: "Down",
    0x0003: "Testing",
    0x0004: "Unknown",
    0x0005: "Dormant",
    0x0006: "NotPresent",
    0x0007: "LowerLayerDown",
}

LINKSTATE_PORT = {
    0x0000: "Unknown",
    0x0001: "Disabled/Discarding",
    0x0002: "Blocking",
    0x0003: "Listening",
    0x0004: "Learning",
    0x0005: "Forwarding",
    0x0006: "Broken",
    0x0007: "Reserved",
}

MEDIA_TYPE = {
    0x00: "Unknown",
    0x01: "Copper cable",
    0x02: "Fiber optic cable",
    0x03: "Radio communication"
}

# List of all valid activity UUIDs for the DceRpc layer with PROFINET RPC
# endpoint.
#
# Because these are used in overloaded_fields, it must be a ``UUID``, not a
# string.
RPC_INTERFACE_UUID = {
    "UUID_IO_DeviceInterface": UUID("dea00001-6c97-11d1-8271-00a02442df7d"),
    "UUID_IO_ControllerInterface":
        UUID("dea00002-6c97-11d1-8271-00a02442df7d"),
    "UUID_IO_SupervisorInterface":
        UUID("dea00003-6c97-11d1-8271-00a02442df7d"),
    "UUID_IO_ParameterServerInterface":
        UUID("dea00004-6c97-11d1-8271-00a02442df7d"),
}


# Generic Block Packet
class BlockHeader(Packet):
    """Abstract packet to centralize block headers fields"""
    fields_desc = [
        ShortEnumField("block_type", None, BLOCK_TYPES_ENUM),
        ShortField("block_length", None),
        ByteField("block_version_high", 1),
        ByteField("block_version_low", 0),
    ]

    def __new__(cls, name, bases, dct):
        raise NotImplementedError()


class Block(Packet):
    """A generic block packet for PNIO RPC"""
    fields_desc = [
        BlockHeader,
        StrLenField("load", "", length_from=lambda pkt: pkt.block_length - 2),
    ]
    # default block_type
    block_type = 0

    def post_build(self, p, pay):
        # update the block_length if needed
        if self.block_length is None:
            # block_length and block_type are not part of the length count
            length = len(p) - 4
            p = p[:2] + struct.pack("!H", length) + p[4:]

        return Packet.post_build(self, p, pay)

    def extract_padding(self, s):
        # all fields after block_length are included in the length and must be
        # subtracted from the pdu length l
        length = self.payload_length()
        return s[:length], s[length:]

    def payload_length(self):
        """ A function for each block, to determine the length of
        the payload """
        return 0  # default, no payload


# Specific Block Packets
#     IODControlRe{q,s}
class IODControlReq(Block):
    """IODControl request block"""
    fields_desc = [
        BlockHeader,
        StrFixedLenField("padding", "", length=2),
        UUIDField("ARUUID", None),
        ShortField("SessionKey", 0),
        XShortField("AlarmSequenceNumber", 0),
        # ControlCommand
        BitField("ControlCommand_reserved", 0, 9),
        BitField("ControlCommand_PrmBegin", 0, 1),
        BitField("ControlCommand_ReadyForRT_CLASS_3", 0, 1),
        BitField("ControlCommand_ReadyForCompanion", 0, 1),
        BitField("ControlCommand_Done", 0, 1),
        BitField("ControlCommand_Release", 0, 1),
        BitField("ControlCommand_ApplicationReady", 0, 1),
        BitField("ControlCommand_PrmEnd", 0, 1),
        XShortField("ControlBlockProperties", 0)
    ]

    def post_build(self, p, pay):
        # Try to find the right block type
        if self.block_type is None:
            if self.ControlCommand_PrmBegin:
                p = struct.pack("!H", 0x0118) + p[2:]
            elif self.ControlCommand_ReadyForRT_CLASS_3:
                p = struct.pack("!H", 0x0117) + p[2:]
            elif self.ControlCommand_ReadyForCompanion:
                p = struct.pack("!H", 0x0116) + p[2:]
            elif self.ControlCommand_Release:
                p = struct.pack("!H", 0x0114) + p[2:]
            elif self.ControlCommand_ApplicationReady:
                if self.AlarmSequenceNumber > 0:
                    p = struct.pack("!H", 0x0113) + p[2:]
                else:
                    p = struct.pack("!H", 0x0112) + p[2:]
            elif self.ControlCommand_PrmEnd:
                if self.AlarmSequenceNumber > 0:
                    p = struct.pack("!H", 0x0111) + p[2:]
                else:
                    p = struct.pack("!H", 0x0110) + p[2:]
        return Block.post_build(self, p, pay)

    def get_response(self):
        """Generate the response block of this request.
        Careful: it only sets the fields which can be set from the request
        """
        res = IODControlRes()
        for field in ["ARUUID", "SessionKey", "AlarmSequenceNumber"]:
            res.setfieldval(field, self.getfieldval(field))

        res.block_type = self.block_type + 0x8000
        return res


class IODControlRes(Block):
    """IODControl response block"""
    fields_desc = [
        BlockHeader,
        StrFixedLenField("padding", "", length=2),
        UUIDField("ARUUID", None),
        ShortField("SessionKey", 0),
        XShortField("AlarmSequenceNumber", 0),
        # ControlCommand
        BitField("ControlCommand_reserved", 0, 9),
        BitField("ControlCommand_PrmBegin", 0, 1),
        BitField("ControlCommand_ReadyForRT_CLASS_3", 0, 1),
        BitField("ControlCommand_ReadyForCompanion", 0, 1),
        BitField("ControlCommand_Done", 1, 1),
        BitField("ControlCommand_Release", 0, 1),
        BitField("ControlCommand_ApplicationReady", 0, 1),
        BitField("ControlCommand_PrmEnd", 0, 1),
        XShortField("ControlBlockProperties", 0)
    ]

    # default block_type value
    block_type = 0x8110
    # The block_type can be among 0x8110 to 0x8118 except 0x8115
    # The right type is however determine by the type of the request
    # (same type as the request + 0x8000)


#     IODWriteRe{q,s}
class IODWriteReq(Block):
    """IODWrite request block"""
    fields_desc = [
        BlockHeader,
        ShortField("seqNum", 0),
        UUIDField("ARUUID", None),
        XIntField("API", 0),
        XShortField("slotNumber", 0),
        XShortField("subslotNumber", 0),
        StrFixedLenField("padding", "", length=2),
        XShortEnumField("index", 0, IOD_WRITE_REQ_INDEX),
        LenField("recordDataLength", None, fmt="I"),
        StrFixedLenField("RWPadding", "", length=24),
    ]
    # default block_type value
    block_type = 0x0008

    def payload_length(self):
        return self.recordDataLength

    def get_response(self):
        """Generate the response block of this request.
        Careful: it only sets the fields which can be set from the request
        """
        res = IODWriteRes()
        for field in ["seqNum", "ARUUID", "API", "slotNumber",
                      "subslotNumber", "index"]:
            res.setfieldval(field, self.getfieldval(field))
        return res


class IODWriteRes(Block):
    """IODWrite response block"""
    fields_desc = [
        BlockHeader,
        ShortField("seqNum", 0),
        UUIDField("ARUUID", None),
        XIntField("API", 0),
        XShortField("slotNumber", 0),
        XShortField("subslotNumber", 0),
        StrFixedLenField("padding", "", length=2),
        XShortEnumField("index", 0, IOD_WRITE_REQ_INDEX),
        LenField("recordDataLength", None, fmt="I"),
        XShortField("additionalValue1", 0),
        XShortField("additionalValue2", 0),
        IntEnumField("status", 0, ["OK"]),
        StrFixedLenField("RWPadding", "", length=16),
    ]
    # default block_type value
    block_type = 0x8008


#     IODReadRe{q,s}
class IODReadReq(Block):
    """IODRead request block"""
    fields_desc = [
        BlockHeader,
        ShortField("seqNum", 0),
        UUIDField("ARUUID", None),
        XIntField("API", 0),
        XShortField("slotNumber", 0),
        XShortField("subslotNumber", 0),
        StrFixedLenField("padding", "", length=2),
        XShortEnumField("index", 0, IOD_WRITE_REQ_INDEX),
        LenField("recordDataLength", None, fmt="I"),
        StrFixedLenField("RWPadding", "", length=24),
    ]
    block_type = 0x0009

    def payload_length(self):
        return self.recordDataLength

    def get_response(self):
        res = IODReadRes()
        for field in ["seqNum", "ARUUID", "API", "slotNumber",
                      "subslotNumber", "index"]:
            res.setfieldval(field, self.getfieldval(field))
        return res


class IODReadRes(Block):
    """IODRead response block"""
    fields_desc = [
        BlockHeader,
        ShortField("seqNum", 0),
        UUIDField("ARUUID", None),
        XIntField("API", 0),
        XShortField("slotNumber", 0),
        XShortField("subslotNumber", 0),
        StrFixedLenField("padding", "", length=2),
        XShortEnumField("index", 0, IOD_WRITE_REQ_INDEX),
        LenField("recordDataLength", None, fmt="I"),
        XShortField("additionalValue1", 0),
        XShortField("additionalValue2", 0),
        StrFixedLenField("RWPadding", "", length=20),
    ]
    block_type = 0x8009


F_PARAMETERS_BLOCK_ID = [
    "No_F_WD_Time2_No_F_iPar_CRC", "No_F_WD_Time2_F_iPar_CRC",
    "F_WD_Time2_No_F_iPar_CRC", "F_WD_Time2_F_iPar_CRC",
    "reserved_4", "reserved_5", "reserved_6", "reserved_7"
]


class FParametersBlock(Packet):
    """F-Parameters configuration block"""
    name = "F-Parameters Block"
    fields_desc = [
        # F_Prm_Flag1
        BitField("F_Prm_Flag1_Reserved_7", 0, 1),
        BitField("F_CRC_Seed", 0, 1),
        BitEnumField("F_CRC_Length", 0, 2,
                     ["CRC-24", "depreciated", "CRC-32", "reserved"]),
        BitEnumField("F_SIL", 2, 2, ["SIL_1", "SIL_2", "SIL_3", "No_SIL"]),
        BitField("F_Check_iPar", 0, 1),
        BitField("F_Check_SeqNr", 0, 1),

        # F_Prm_Flag2
        BitEnumField("F_Par_Version", 1, 2,
                     ["V1", "V2", "reserved_2", "reserved_3"]),
        BitEnumField("F_Block_ID", 0, 3, F_PARAMETERS_BLOCK_ID),
        BitField("F_Prm_Flag2_Reserved", 0, 2),
        BitField("F_Passivation", 0, 1),

        XShortField("F_Source_Add", 0),
        XShortField("F_Dest_Add", 0),
        ShortField("F_WD_Time", 0),
        ConditionalField(
            cond=lambda p: p.getfieldval("F_Block_ID") & 0b110 == 0b010,
            fld=ShortField("F_WD_Time_2", 0)),
        ConditionalField(
            cond=lambda p: p.getfieldval("F_Block_ID") & 0b101 == 0b001,
            fld=XIntField("F_iPar_CRC", 0)),
        XShortField("F_Par_CRC", 0)
    ]
    overload_fields = {
        IODWriteReq: {
            "index": 0x100,  # commonly used index for F-Parameters block
        }
    }


bind_layers(IODWriteReq, FParametersBlock, index=0x0100)
bind_layers(FParametersBlock, conf.padding_layer)


#     IODWriteMultipleRe{q,s}
class PadFieldWithLen(PadField):
    """PadField which handles the i2len function to include padding"""

    def i2len(self, pkt, val):
        """get the length of the field, including the padding length"""
        fld_len = self.fld.i2len(pkt, val)
        return fld_len + self.padlen(fld_len, pkt)


class IODWriteMultipleReq(Block):
    """IODWriteMultiple request"""
    fields_desc = [
        BlockHeader,
        ShortField("seqNum", 0),
        UUIDField("ARUUID", None),
        XIntField("API", 0xffffffff),
        XShortField("slotNumber", 0xffff),
        XShortField("subslotNumber", 0xffff),
        StrFixedLenField("padding", "", length=2),
        XShortEnumField("index", 0, IOD_WRITE_REQ_INDEX),
        FieldLenField("recordDataLength", None, fmt="I", length_of="blocks"),
        StrFixedLenField("RWPadding", "", length=24),
        FieldListField("blocks", [],
                       PadFieldWithLen(PacketField("", None, IODWriteReq), 4),
                       length_from=lambda pkt: pkt.recordDataLength)
    ]
    # default values
    block_type = 0x0008
    index = 0xe040
    API = 0xffffffff
    slotNumber = 0xffff
    subslotNumber = 0xffff

    def post_build(self, p, pay):
        # patch the update of block_length, as requests field must not be
        # included. block_length is always 60
        if self.block_length is None:
            p = p[:2] + struct.pack("!H", 60) + p[4:]

        # Remove the final padding added in requests
        fld, val = self.getfield_and_val("blocks")
        if fld.i2count(self, val) > 0:
            length = len(val[-1])
            pad = fld.field.padlen(length, self)
            if pad > 0:
                p = p[:-pad]
                # also reduce the recordDataLength accordingly
                if self.recordDataLength is None:
                    val = struct.unpack("!I", p[36:40])[0]
                    val -= pad
                    p = p[:36] + struct.pack("!I", val) + p[40:]

        return Packet.post_build(self, p, pay)

    def get_response(self):
        """Generate the response block of this request.
        Careful: it only sets the fields which can be set from the request
        """
        res = IODWriteMultipleRes()
        for field in ["seqNum", "ARUUID", "API", "slotNumber",
                      "subslotNumber", "index"]:
            res.setfieldval(field, self.getfieldval(field))

        # append all block response
        res_blocks = []
        for block in self.getfieldval("blocks"):
            res_blocks.append(block.get_response())
        res.setfieldval("blocks", res_blocks)
        return res


class IODWriteMultipleRes(Block):
    """IODWriteMultiple response"""
    fields_desc = [
        BlockHeader,
        ShortField("seqNum", 0),
        UUIDField("ARUUID", None),
        XIntField("API", 0xffffffff),
        XShortField("slotNumber", 0xffff),
        XShortField("subslotNumber", 0xffff),
        StrFixedLenField("padding", "", length=2),
        XShortEnumField("index", 0, IOD_WRITE_REQ_INDEX),
        FieldLenField("recordDataLength", None, fmt="I", length_of="blocks"),
        XShortField("additionalValue1", 0),
        XShortField("additionalValue2", 0),
        IntEnumField("status", 0, ["OK"]),
        StrFixedLenField("RWPadding", "", length=16),
        FieldListField("blocks", [], PacketField("", None, IODWriteRes),
                       length_from=lambda pkt: pkt.recordDataLength)
    ]
    # default values
    block_type = 0x8008
    index = 0xe040

    def post_build(self, p, pay):
        # patch the update of block_length, as requests field must not be
        # included. block_length is always 60
        if self.block_length is None:
            p = p[:2] + struct.pack("!H", 60) + p[4:]

        return Packet.post_build(self, p, pay)


#     I&M0
class IM0Block(Block):
    """Identification and Maintenance 0"""
    fields_desc = [
        BlockHeader,
        ByteField("VendorIDHigh", 0x00),
        ByteField("VendorIDLow", 0x00),
        StrFixedLenField("OrderID", "", length=20),
        StrFixedLenField("IMSerialNumber", "", length=16),
        ShortField("IMHardwareRevision", 0),
        StrFixedLenField("IMSWRevisionPrefix", "V", length=1),
        ByteField("IMSWRevisionFunctionalEnhancement", 0),
        ByteField("IMSWRevisionBugFix", 0),
        ByteField("IMSWRevisionInternalChange", 0),
        ShortField("IMRevisionCounter", 0),
        ShortField("IMProfileID", 0),
        ShortField("IMProfileSpecificType", 0),
        ByteField("IMVersionMajor", 1),
        ByteField("IMVersionMinor", 1),
        ShortField("IMSupported", 0x0),
    ]

    block_type = 0x0020


#     I&M1
class IM1Block(Block):
    """Identification and Maintenance 1"""
    fields_desc = [
        BlockHeader,
        StrFixedLenField("IMTagFunction", "", length=32),
        StrFixedLenField("IMTagLocation", "", length=22),
    ]

    block_type = 0x0021


#     I&M2
class IM2Block(Block):
    """Identification and Maintenance 2"""
    fields_desc = [
        BlockHeader,
        StrFixedLenField("IMDate", "", length=16),
    ]

    block_type = 0x0022


#     I&M3
class IM3Block(Block):
    """Identification and Maintenance 3"""
    fields_desc = [
        BlockHeader,
        StrFixedLenField("IMDescriptor", "", length=54),
    ]

    block_type = 0x0023


#     I&M4
class IM4Block(Block):
    """Identification and Maintenance 4"""
    fields_desc = [
        BlockHeader,
        StrFixedLenField("IMSignature", "", 54)
    ]

    block_type = 0x0024


#     ARBlockRe{q,s}
class ARBlockReq(Block):
    """Application relationship block request"""
    fields_desc = [
        BlockHeader,
        XShortEnumField("ARType", 1, AR_TYPE),
        UUIDField("ARUUID", None),
        ShortField("SessionKey", 0),
        MACField("CMInitiatorMacAdd", None),
        UUIDField("CMInitiatorObjectUUID", None),
        # ARProperties
        BitField("ARProperties_PullModuleAlarmAllowed", 0, 1),
        BitEnumField("ARProperties_StartupMode", 0, 1,
                     ["Legacy", "Advanced"]),
        BitField("ARProperties_reserved_3", 0, 6),
        BitField("ARProperties_reserved_2", 0, 12),
        BitField("ARProperties_AcknowledgeCompanionAR", 0, 1),
        BitEnumField("ARProperties_CompanionAR", 0, 2,
                     ["Single_AR", "First_AR", "Companion_AR", "reserved"]),
        BitEnumField("ARProperties_DeviceAccess", 0, 1,
                     ["ExpectedSubmodule", "Controlled_by_IO_device_app"]),
        BitField("ARProperties_reserved_1", 0, 3),
        BitEnumField("ARProperties_ParametrizationServer", 0, 1,
                     ["External_PrmServer", "CM_Initator"]),
        BitField("ARProperties_SupervisorTakeoverAllowed", 0, 1),
        BitEnumField("ARProperties_State", 1, 3, {1: "Active"}),
        ShortField("CMInitiatorActivityTimeoutFactor", 1000),
        ShortField("CMInitiatorUDPRTPort", 0x8892),
        FieldLenField("StationNameLength", None, fmt="H",
                      length_of="CMInitiatorStationName"),
        StrLenField("CMInitiatorStationName", "",
                    length_from=lambda pkt: pkt.StationNameLength),
    ]
    # default block_type value
    block_type = 0x0101

    def get_response(self):
        """Generate the response block of this request.
        Careful: it only sets the fields which can be set from the request
        """
        res = ARBlockRes()
        for field in ["ARType", "ARUUID", "SessionKey"]:
            res.setfieldval(field, self.getfieldval(field))
        return res


class ARBlockRes(Block):
    """Application relationship block response"""
    fields_desc = [
        BlockHeader,
        XShortEnumField("ARType", 1, AR_TYPE),
        UUIDField("ARUUID", None),
        ShortField("SessionKey", 0),
        MACField("CMResponderMacAdd", None),
        ShortField("CMResponderUDPRTPort", 0x8892),
    ]
    # default block_type value
    block_type = 0x8101


#     IOCRBlockRe{q,s}
class IOCRAPIObject(Packet):
    """API item descriptor used in API description of IOCR blocks"""
    name = "API item"
    fields_desc = [
        XShortField("SlotNumber", 0),
        XShortField("SubslotNumber", 0),
        ShortField("FrameOffset", 0),
    ]

    def extract_padding(self, s):
        return None, s  # No extra payload


class IOCRAPI(Packet):
    """API description used in IOCR block"""
    name = "API"
    fields_desc = [
        XIntField("API", 0),
        FieldLenField("NumberOfIODataObjects", None,
                      count_of="IODataObjects"),
        PacketListField("IODataObjects", [], IOCRAPIObject,
                        count_from=lambda p: p.NumberOfIODataObjects),
        FieldLenField("NumberOfIOCS", None,
                      count_of="IOCSs"),
        PacketListField("IOCSs", [], IOCRAPIObject,
                        count_from=lambda p: p.NumberOfIOCS),
    ]

    def extract_padding(self, s):
        return None, s  # No extra payload


class IOCRBlockReq(Block):
    """IO Connection Relationship block request"""
    fields_desc = [
        BlockHeader,
        XShortEnumField("IOCRType", 1, IOCR_TYPE),
        XShortField("IOCRReference", 1),
        XShortField("LT", 0x8892),
        # IOCRProperties
        BitField("IOCRProperties_reserved3", 0, 8),
        BitField("IOCRProperties_reserved2", 0, 11),
        BitField("IOCRProperties_reserved1", 0, 9),
        BitEnumField("IOCRProperties_RTClass", 0, 4,
                     IOCR_BLOCK_REQ_IOCR_PROPERTIES),
        ShortField("DataLength", 40),
        XShortField("FrameID", 0x8000),
        ShortField("SendClockFactor", 32),
        ShortField("ReductionRatio", 32),
        ShortField("Phase", 1),
        ShortField("Sequence", 0),
        XIntField("FrameSendOffset", 0xffffffff),
        ShortField("WatchdogFactor", 10),
        ShortField("DataHoldFactor", 10),
        # IOCRTagHeader
        BitEnumField("IOCRTagHeader_IOUserPriority", 6, 3,
                     {6: "IOCRPriority"}),
        BitField("IOCRTagHeader_reserved", 0, 1),
        BitField("IOCRTagHeader_IOCRVLANID", 0, 12),
        MACField("IOCRMulticastMACAdd", None),
        FieldLenField("NumberOfAPIs", None, fmt="H", count_of="APIs"),
        PacketListField("APIs", [], IOCRAPI,
                        count_from=lambda p: p.NumberOfAPIs)
    ]
    # default block_type value
    block_type = 0x0102

    def get_response(self):
        """Generate the response block of this request.
        Careful: it only sets the fields which can be set from the request
        """
        res = IOCRBlockRes()
        for field in ["IOCRType", "IOCRReference", "FrameID"]:
            res.setfieldval(field, self.getfieldval(field))
        return res


class IOCRBlockRes(Block):
    """IO Connection Relationship block response"""
    fields_desc = [
        BlockHeader,
        XShortEnumField("IOCRType", 1, IOCR_TYPE),
        XShortField("IOCRReference", 1),
        XShortField("FrameID", 0x8000),
    ]
    # default block_type value
    block_type = 0x8102


class AdjustLinkState(Block):
    fields_desc = [
        BlockHeader,
        StrFixedLenField("padding", "", length=2),
        XShortEnumField("LinkState", 0, LINKSTATE_LINK),
        ShortField("AdjustProperties", 0)
    ]

    block_type = 0x021B


class AdjustPeerToPeerBoundary(Block):
    fields_desc = [
        BlockHeader,
        StrFixedLenField("padding1", "", length=2),
        IntField("peerToPeerBoundary", 0),
        ShortField("adjustProperties", 0),
        PadField(ShortField("padding2", 0), 2),
    ]

    block_type = 0x0224


class AdjustDomainBoundary(Block):
    fields_desc = [
        BlockHeader,
        StrFixedLenField("padding1", "", length=2),
        IntEnumField("DomainBoundaryIngress", 0, {
            0x00: "No Block",
            0x01: "Block",
        }),
        IntEnumField("DomainBoundaryEgress", 0, {
            0x00: "No Block",
            0x01: "Block",
        }),
        ShortField("adjustProperties", 0),
        PadField(ShortField("padding2", 0), 2)
    ]

    block_type = 0x0209


class AdjustMulticastBoundary(Block):
    fields_desc = [
        BlockHeader,
        StrFixedLenField("padding1", "", length=2),
        IntField("MulticastAddress", 0),
        ShortField("adjustProperties", 0),
        PadField(ShortField("padding2", 0), 2)
    ]

    block_type = 0x0210


class AdjustMauType(Block):
    fields_desc = [
        BlockHeader,
        PadField(ShortField("padding", 0), 2),
        XShortEnumField("MAUType", 1, MAU_TYPE),
        ShortField("adjustProperties", 0),
    ]

    block_type = 0x020E


class AdjustMauTypeExtension(Block):
    fields_desc = [
        BlockHeader,
        PadField(ShortField("padding", 0), 2),
        XShortEnumField("MAUTypeExtension", 0, MAU_EXTENSION),
        ShortField("adjustProperties", 0),
    ]

    block_type = 0x0229


class AdjustDCPBoundary(Block):
    fields_desc = [
        BlockHeader,
        StrFixedLenField("padding1", "", length=2),
        IntField("dcpBoundary", 0),
        ShortField("adjustProperties", 0),
        PadField(ShortField("padding2", 0), 2),
    ]

    block_type = 0x0225


PDPORT_ADJUST_BLOCK_ASSOCIATION = {
    0x0209: AdjustDomainBoundary,
    0x020e: AdjustMauType,
    0x0210: AdjustMulticastBoundary,
    0x021b: AdjustLinkState,
    0x0224: AdjustPeerToPeerBoundary,
    0x0225: AdjustDCPBoundary,
    0x0229: AdjustMauTypeExtension,
}


def _guess_pdportadjust_block(_pkt, *args, **kargs):
    cls = Block

    btype = struct.unpack("!H", _pkt[:2])[0]
    if btype in PDPORT_ADJUST_BLOCK_ASSOCIATION:
        cls = PDPORT_ADJUST_BLOCK_ASSOCIATION[btype]

    return cls(_pkt, *args, **kargs)


class PDPortDataAdjust(Block):
    fields_desc = [
        BlockHeader,
        StrFixedLenField("padding", "", length=2),
        XShortField("slotNumber", 0),
        XShortField("subslotNumber", 0),
        PacketListField("blocks", [], _guess_pdportadjust_block,
                        length_from=lambda p: p.block_length)
    ]

    block_type = 0x0202


#     ExpectedSubmoduleBlockReq
class ExpectedSubmoduleDataDescription(Packet):
    """Description of the data of a submodule"""
    name = "Data Description"
    fields_desc = [
        XShortEnumField("DataDescription", 0, {1: "Input", 2: "Output"}),
        ShortField("SubmoduleDataLength", 0),
        ByteField("LengthIOCS", 0),
        ByteField("LengthIOPS", 0),
    ]

    def extract_padding(self, s):
        return None, s  # No extra payload


class ExpectedSubmodule(Packet):
    """Description of a submodule in an API of an expected submodule"""
    name = "Submodule"
    fields_desc = [
        XShortField("SubslotNumber", 0),
        XIntField("SubmoduleIdentNumber", 0),
        # Submodule Properties
        XByteField("SubmoduleProperties_reserved_2", 0),
        BitField("SubmoduleProperties_reserved_1", 0, 2),
        BitField("SubmoduleProperties_DiscardIOXS", 0, 1),
        BitField("SubmoduleProperties_ReduceOutputSubmoduleDataLength", 0, 1),
        BitField("SubmoduleProperties_ReduceInputSubmoduleDataLength", 0, 1),
        BitField("SubmoduleProperties_SharedInput", 0, 1),
        BitEnumField("SubmoduleProperties_Type", 0, 2,
                     ["NO_IO", "INPUT", "OUTPUT", "INPUT_OUTPUT"]),
        PacketListField(
            "DataDescription", [], ExpectedSubmoduleDataDescription,
            count_from=lambda p: 2 if p.SubmoduleProperties_Type == 3 else 1
        ),
    ]

    def extract_padding(self, s):
        return None, s  # No extra payload


class ExpectedSubmoduleAPI(Packet):
    """Description of an API in the expected submodules blocks"""
    name = "API"
    fields_desc = [
        XIntField("API", 0),
        XShortField("SlotNumber", 0),
        XIntField("ModuleIdentNumber", 0),
        XShortField("ModuleProperties", 0),
        FieldLenField("NumberOfSubmodules", None, fmt="H",
                      count_of="Submodules"),
        PacketListField("Submodules", [], ExpectedSubmodule,
                        count_from=lambda p: p.NumberOfSubmodules),
    ]

    def extract_padding(self, s):
        return None, s  # No extra payload


class ExpectedSubmoduleBlockReq(Block):
    """Expected submodule block request"""
    fields_desc = [
        BlockHeader,
        FieldLenField("NumberOfAPIs", None, fmt="H", count_of="APIs"),
        PacketListField("APIs", [], ExpectedSubmoduleAPI,
                        count_from=lambda p: p.NumberOfAPIs)
    ]
    # default block_type value
    block_type = 0x0104

    def get_response(self):
        """Generate the response block of this request.
        Careful: it only sets the fields which can be set from the request
        """
        return None  # no response associated (should be modulediffblock)


ALARM_CR_TYPE = {
    0x0001: "AlarmCR",
}

ALARM_CR_TRANSPORT = {
    0x0: "RTA_CLASS_1",
    0x1: "RTA_CLASS_UDP"
}


class AlarmCRBlockReq(Block):
    """Alarm CR block request"""
    fields_desc = [
        BlockHeader,
        XShortEnumField("AlarmCRType", 1, ALARM_CR_TYPE),
        ShortField("LT", 0x8892),
        BitField("AlarmCRProperties_Priority", 0, 1),
        BitEnumField("AlarmCRProperties_Transport", 0, 1, ALARM_CR_TRANSPORT),
        BitField("AlarmCRProperties_Reserved1", 0, 22),
        BitField("AlarmCRProperties_Reserved2", 0, 8),
        ShortField("RTATimeoutFactor", 0x0001),
        ShortField("RTARetries", 0x0003),
        ShortField("LocalAlarmReference", 0x0003),
        ShortField("MaxAlarmDataLength", 0x00C8),
        ShortField("AlarmCRTagHeaderHigh", 0xC000),
        ShortField("AlarmCRTagHeaderLow", 0xA000),
    ]
    # default block_type value
    block_type = 0x0103

    def post_build(self, p, pay):
        # Set the LT based on transport
        if self.AlarmCRProperties_Transport == 0x1:
            p = p[:8] + struct.pack("!H", 0x0800) + p[10:]

        return Block.post_build(self, p, pay)

    def get_response(self):
        """Generate the response block of this request.
        Careful: it only sets the fields which can be set from the request
        """
        res = AlarmCRBlockRes()
        for field in ["AlarmCRType", "LocalAlarmReference"]:
            res.setfieldval(field, self.getfieldval(field))

        res.block_type = self.block_type + 0x8000
        return res


class AlarmCRBlockRes(Block):
    fields_desc = [
        BlockHeader,
        XShortEnumField("AlarmCRType", 1, ALARM_CR_TYPE),
        ShortField("LocalAlarmReference", 0),
        ShortField("MaxAlarmDataLength", 0)
    ]
    # default block_type value
    block_type = 0x8103


class AlarmItem(Packet):
    fields_desc = [
        XShortField("UserStructureIdentifier", 0),
        PacketField("load", "", Raw),
    ]

    def extract_padding(self, s):
        return None, s  # No extra payload


class MaintenanceItem(AlarmItem):
    fields_desc = [
        XShortField("UserStructureIdentifier", 0),
        BlockHeader,
        StrFixedLenField("padding", "", length=2),
        XIntField("MaintenanceStatus", 0),
    ]


class DiagnosisItem(AlarmItem):
    fields_desc = [
        XShortField("UserStructureIdentifier", 0),
        XShortField("ChannelNumber", 0),
        XShortField("ChannelProperties", 0),
        XShortField("ChannelErrorType", 0),
        ConditionalField(
            cond=lambda p: p.getfieldval("UserStructureIdentifier") in [
                0x8002, 0x8003],
            fld=XShortField("ExtChannelErrorType", 0)),
        ConditionalField(
            cond=lambda p: p.getfieldval("UserStructureIdentifier") in [
                0x8002, 0x8003],
            fld=XIntField("ExtChannelAddValue", 0)),
        ConditionalField(
            cond=lambda p: p.getfieldval("UserStructureIdentifier") == 0x8003,
            fld=XIntField("QualifiedChannelQualifier", 0)),
    ]


class UploadRetrievalItem(AlarmItem):
    fields_desc = [
        XShortField("UserStructureIdentifier", 0),
        BlockHeader,
        StrFixedLenField("padding", "", length=2),
        XIntField("URRecordIndex", 0),
        XIntField("URRecordLength", 0),
    ]


class iParameterItem(AlarmItem):
    fields_desc = [
        XShortField("UserStructureIdentifier", 0),
        BlockHeader,
        StrFixedLenField("padding", "", length=2),
        XIntField("iPar_Req_Header", 0),
        XIntField("Max_Segm_Size", 0),
        XIntField("Transfer_Index", 0),
        XIntField("Total_iPar_Size", 0),
    ]


PE_OPERATIONAL_MODE = {
    0x00: "PE_PowerOff",
    0xF0: "PE_Operate",
    0xFE: "PE_SleepModeWOL",
    0xFF: "PE_ReadyToOperate",
}
PE_OPERATIONAL_MODE.update({i: "PE_EnergySavingMode_{}".format(i)
                            for i in range(0x1, 0x20)})
PE_OPERATIONAL_MODE.update({i: "Reserved" for i in range(0x20, 0xF0)})
PE_OPERATIONAL_MODE.update({i: "Reserved" for i in range(0xF1, 0xFE)})


class PE_AlarmItem(AlarmItem):
    fields_desc = [
        XShortField("UserStructureIdentifier", 0),
        BlockHeader,
        ByteEnumField("PE_OperationalMode", 0, PE_OPERATIONAL_MODE),
    ]


class RS_AlarmItem(AlarmItem):
    fields_desc = [
        XShortField("UserStructureIdentifier", 0),
        XShortField("RS_AlarmInfo", 0),
    ]


class PRAL_AlarmItem(AlarmItem):
    fields_desc = [
        XShortField("UserStructureIdentifier", 0),
        XShortField("ChannelNumber", 0),
        XShortField("PRAL_ChannelProperties", 0),
        XShortField("PRAL_Reason", 0),
        XShortField("PRAL_ExtReason", 0),
        StrLenField("PRAL_ReasonAddValue", "",
                    length_from=lambda x:x.len - 10),
    ]


PNIO_RPC_ALARM_ASSOCIATION = {
    "8000": DiagnosisItem,
    "8002": DiagnosisItem,
    "8003": DiagnosisItem,
    "8100": MaintenanceItem,
    "8200": UploadRetrievalItem,
    "8201": iParameterItem,
    "8300": RS_AlarmItem,
    "8301": RS_AlarmItem,
    "8302": RS_AlarmItem,
    # "8303": RS_AlarmItem,
    "8310": PE_AlarmItem,
    "8320": PRAL_AlarmItem,
}


def _guess_alarm_payload(_pkt, *args, **kargs):
    cls = AlarmItem

    btype = bytes_hex(_pkt[:2]).decode("utf8")
    if btype in PNIO_RPC_ALARM_ASSOCIATION:
        cls = PNIO_RPC_ALARM_ASSOCIATION[btype]

    return cls(_pkt, *args, **kargs)


class AlarmNotificationPDU(Block):
    fields_desc = [
        # IEC-61158-6-10:2021, Table 513
        BlockHeader,
        ShortField("AlarmType", 0),
        XIntField("API", 0),
        ShortField("SlotNumber", 0),
        ShortField("SubslotNumber", 0),
        XIntField("ModuleIdentNumber", 0),
        XIntField("SubmoduleIdentNUmber", 0),
        XShortField("AlarmSpecifier", 0),
        PacketListField("AlarmPayload", [], _guess_alarm_payload)
    ]


class AlarmNotification_High(AlarmNotificationPDU):
    block_type = 0x0001


class AlarmNotification_Low(AlarmNotificationPDU):
    block_type = 0x0002


PDU_TYPE_TYPE = {
    0x01: "RTA_TYPE_DATA",
    0x02: "RTA_TYPE_NACK",
    0x03: "RTA_TYPE_ACK",
    0x04: "RTA_TYPE_ERR",
    0x05: "RTA_TYPE_FREQ",
    0x06: "RTA_TYPE_FRSP",
}
PDU_TYPE_TYPE.update({i: "Reserved" for i in range(0x07, 0x10)})


PDU_TYPE_VERSION = {
    0x00: "Reserved",
    0x01: "Version 1",
    0x02: "Version 2",
}
PDU_TYPE_VERSION.update({i: "Reserved" for i in range(0x03, 0x10)})


class PNIORealTimeAcyclicPDUHeader(Packet):
    fields_desc = [
        # IEC-61158-6-10:2021, Table 241
        ShortField("AlarmDstEndpoint", 0),
        ShortField("AlarmSrcEndpoint", 0),
        BitEnumField("PDUTypeType", 0, 4, PDU_TYPE_TYPE),
        BitEnumField("PDUTypeVersion", 0, 4, PDU_TYPE_VERSION),
        BitField("AddFlags", 0, 8),
        XShortField("SendSeqNum", 0),
        XShortField("AckSeqNum", 0),
        XShortField("VarPartLen", 0),
    ]

    def __new__(cls, name, bases, dct):
        raise NotImplementedError()


class Alarm_Low(Packet):
    fields_desc = [
        PNIORealTimeAcyclicPDUHeader,
        PacketField("RTA_SDU", None, AlarmNotification_Low),
    ]


class Alarm_High(Packet):
    fields_desc = [
        PNIORealTimeAcyclicPDUHeader,
        PacketField("RTA_SDU", None, AlarmNotification_High),
    ]


# PROFINET IO DCE/RPC PDU
PNIO_RPC_BLOCK_ASSOCIATION = {
    # I&M Records
    "0020": IM0Block,
    "0021": IM1Block,
    "0022": IM2Block,
    "0023": IM3Block,
    "0024": IM4Block,

    # requests
    "0101": ARBlockReq,
    "0102": IOCRBlockReq,
    "0103": AlarmCRBlockReq,
    "0104": ExpectedSubmoduleBlockReq,
    "0110": IODControlReq,
    "0111": IODControlReq,
    "0112": IODControlReq,
    "0113": IODControlReq,
    "0114": IODControlReq,
    "0116": IODControlReq,
    "0117": IODControlReq,
    "0118": IODControlReq,
    "0202": PDPortDataAdjust,

    # responses
    "8101": ARBlockRes,
    "8102": IOCRBlockRes,
    "8103": AlarmCRBlockRes,
    "8110": IODControlRes,
    "8111": IODControlRes,
    "8112": IODControlRes,
    "8113": IODControlRes,
    "8114": IODControlRes,
    "8116": IODControlRes,
    "8117": IODControlRes,
    "8118": IODControlRes,
}


def _guess_block_class(_pkt, *args, **kargs):
    cls = Block  # Default block type

    # Special cases
    if _pkt[:2] == b'\x00\x08':  # IODWriteReq
        if _pkt[34:36] == b'\xe0@':  # IODWriteMultipleReq
            cls = IODWriteMultipleReq
        else:
            cls = IODWriteReq

    elif _pkt[:2] == b'\x00\x09':  # IODReadReq
        cls = IODReadReq

    elif _pkt[:2] == b'\x80\x08':    # IODWriteRes
        if _pkt[34:36] == b'\xe0@':  # IODWriteMultipleRes
            cls = IODWriteMultipleRes
        else:
            cls = IODWriteRes

    elif _pkt[:2] == b'\x80\x09':  # IODReadRes
        cls = IODReadRes

    # Common cases
    else:
        btype = bytes_hex(_pkt[:2]).decode("utf8")
        if btype in PNIO_RPC_BLOCK_ASSOCIATION:
            cls = PNIO_RPC_BLOCK_ASSOCIATION[btype]

    return cls(_pkt, *args, **kargs)


def dce_rpc_endianness(pkt):
    """determine the symbol for the endianness of a the DCE/RPC"""
    try:
        endianness = pkt.underlayer.endian
    except AttributeError:
        # handle the case where a PNIO class is
        # built without its DCE-RPC under-layer
        # i.e there is no endianness indication
        return "!"
    if endianness == 0:  # big endian
        return ">"
    elif endianness == 1:  # little endian
        return "<"
    else:
        return "!"


class NDRData(Packet):
    """Base NDRData to centralize some fields. It can't be instantiated"""
    fields_desc = [
        EField(
            FieldLenField("args_length", None, fmt="I", length_of="blocks"),
            endianness_from=dce_rpc_endianness),
        EField(
            FieldLenField("max_count", None, fmt="I", length_of="blocks"),
            endianness_from=dce_rpc_endianness),
        EField(
            IntField("offset", 0),
            endianness_from=dce_rpc_endianness),
        EField(
            FieldLenField("actual_count", None, fmt="I", length_of="blocks"),
            endianness_from=dce_rpc_endianness),
        PacketListField("blocks", [], _guess_block_class,
                        length_from=lambda p: p.args_length)
    ]

    def __new__(cls, name, bases, dct):
        raise NotImplementedError()


class PNIOServiceReqPDU(Packet):
    """PNIO PDU for RPC Request"""
    fields_desc = [
        EField(
            FieldLenField("args_max", None, fmt="I", length_of="blocks"),
            endianness_from=dce_rpc_endianness),
        NDRData,
    ]
    overload_fields = {
        DceRpc4: {
            # random object in the appropriate range
            "object": RandUUID("dea00000-6c97-11d1-8271-******"),
            # interface uuid to send to a device
            "if_id": RPC_INTERFACE_UUID["UUID_IO_DeviceInterface"],
            # Request DCE/RPC type
            "ptype": 0,
        },
    }

    @classmethod
    def can_handle(cls, pkt, rpc):
        """heuristic guess_payload_class"""
        # type = 0 => request
        if rpc.ptype == 0 and \
                str(rpc.object).startswith("dea00000-6c97-11d1-8271-"):
            return True
        return False


DceRpc4Payload.register_possible_payload(PNIOServiceReqPDU)


class PNIOServiceResPDU(Packet):
    """PNIO PDU for RPC Response"""
    fields_desc = [
        EField(IntEnumField("status", 0, ["OK"]),
               endianness_from=dce_rpc_endianness),
        NDRData,
    ]
    overload_fields = {
        DceRpc4: {
            # random object in the appropriate range
            "object": RandUUID("dea00000-6c97-11d1-8271-******"),
            # interface uuid to send to a host
            "if_id": RPC_INTERFACE_UUID[
                "UUID_IO_ControllerInterface"],
            # Request DCE/RPC type
            "ptype": 2,
        },
    }

    @classmethod
    def can_handle(cls, pkt, rpc):
        """heuristic guess_payload_class"""
        # type = 2 => response
        if rpc.ptype == 2 and \
                str(rpc.object).startswith("dea00000-6c97-11d1-8271-"):
            return True
        return False


DceRpc4Payload.register_possible_payload(PNIOServiceResPDU)
