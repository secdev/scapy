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

# scapy.contrib.description = ProfinetIO Remote Procedure Call (RPC)
# scapy.contrib.status = loads

"""
PNIO RPC endpoints
"""

# External imports
import struct


# Scapy imports
from scapy.all import Packet, bind_layers, ConditionalField, conf
from scapy.fields import BitEnumField, BitField, ByteField,\
        FieldLenField, FieldListField,\
        IntEnumField, IntField,\
        LenField,\
        MACField,\
        PadField, PacketField, PacketListField,\
        ShortEnumField, ShortField, StrFixedLenField, StrLenField,\
        XByteField, XIntField, XShortEnumField, XShortField


# internal imports
from scapy.contrib.pnio_rpc_consts import BLOCK_TYPES_ENUM, IOD_WRITE_REQ_INDEX,\
    AR_TYPE, IOCR_TYPE, IOCR_BLOCK_REQ_IOCR_PROPERTIES, RPC_INTERFACE_UUID

from scapy.contrib.dce_rpc import DceRpc, EndiannessField, DceRpcPayload,\
        UUIDField, RandUUID


##########################
## Generic Block Packet ##
##########################

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
        # substracted from the pdu length l
        length = self.payload_length()
        return s[:length], s[length:]

    def payload_length(self):
        """A function for each block, to determine the lenght of the payload"""
        return 0        # default, no payload


###############################################################################
                          ############################
                          ## Specific Block Packets ##
                          ############################
###############################################################################


#######################
## IODControlRe{q,s} ##
#######################

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
        Carefull: it only sets the fields which can be set from the request
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


#####################
## IODWriteRe{q,s} ##
#####################

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
        Carefull: it only sets the fields which can be set from the request
        """
        res = IODWriteRes()
        for field in ["seqNum", "ARUUID", "API", "slotNumber", "subslotNumber",
                      "index"]:
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


F_PARAMETERS_BLOCK_ID = ["No_F_WD_Time2_No_F_iPar_CRC", "No_F_WD_Time2_F_iPar_CRC",
                         "F_WD_Time2_No_F_iPar_CRC", "F_WD_Time2_F_iPar_CRC",
                         "reserved_4", "reserved_5", "reserved_6", "reserved_7"]
class FParametersBlock(Packet):
    """F-Parameters configuration block"""
    name = "F-Parameters Block"
    fields_desc = [
        # F_Prm_Flag1
        BitField("F_Prm_Flag1_Reserved_7", 0, 1),
        BitField("F_CRC_Seed", 0, 1),
        BitEnumField("F_CRC_Length", 0, 2, ["CRC-24", "depreciated", "CRC-32", "reserved"]),
        BitEnumField("F_SIL", 2, 2, ["SIL_1", "SIL_2", "SIL_3", "No_SIL"]),
        BitField("F_Check_iPar", 0, 1),
        BitField("F_Check_SeqNr", 0, 1),

        # F_Prm_Flag2
        BitEnumField("F_Par_Version", 1, 2, ["V1", "V2", "reserved_2", "reserved_3"]),
        BitEnumField("F_Block_ID", 0, 3, F_PARAMETERS_BLOCK_ID),
        BitField("F_Prm_Flag2_Reserved", 0, 2),
        BitField("F_Passivation", 0, 1),

        XShortField("F_Source_Add", 0),
        XShortField("F_Dest_Add", 0),
        ShortField("F_WD_Time", 0),
        ConditionalField(cond=lambda p: p.getfieldval("F_Block_ID") & 0b110 == 0b010, fld=ShortField("F_WD_Time_2", 0)),
        ConditionalField(cond=lambda p: p.getfieldval("F_Block_ID") & 0b101 == 0b001, fld=XIntField("F_iPar_CRC", 0)),
        XShortField("F_Par_CRC", 0)
        ]
    overload_fields = {
        IODWriteReq: {
            "index": 0x100, # commonly used index for F-Parameters block
            }
        }

bind_layers(IODWriteReq, FParametersBlock, index=0x0100)
bind_layers(FParametersBlock, conf.padding_layer)

#############################
## IODWriteMultipleRe{q,s} ##
#############################

class PadFieldWithLen(PadField):
    """PadField which handles the i2len function to include padding"""
    def i2len(self, pkt, val):
        """get the length of the field, including the padding length"""
        fld_len = self._fld.i2len(pkt, val)
        return fld_len + self.padlen(fld_len)

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
        FieldListField("blocks", [], PadFieldWithLen(PacketField("", None, IODWriteReq), 4), length_from=lambda pkt: pkt.recordDataLength)
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
            pad = fld.field.padlen(length)
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
        Carefull: it only sets the fields which can be set from the request
        """
        res = IODWriteMultipleRes()
        for field in ["seqNum", "ARUUID", "API", "slotNumber", "subslotNumber",
                      "index"]:
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
        FieldListField("blocks", [], PacketField("", None, IODWriteRes), length_from=lambda pkt: pkt.recordDataLength)
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



####################
## ARBlockRe{q,s} ##
####################

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
        BitEnumField("ARProperties_StartupMode", 0, 1, ["Legacy", "Advanced"]),
        BitField("ARProperties_reserved_3", 0, 6),
        BitField("ARProperties_reserved_2", 0, 12),
        BitField("ARProperties_AcknowledgeCompanionAR", 0, 1),
        BitEnumField("ARProperties_CompanionAR", 0, 2, ["Single_AR", "First_AR", "Companion_AR", "reserved"]),
        BitEnumField("ARProperties_DeviceAccess", 0, 1, ["ExpectedSubmodule", "Controlled_by_IO_device_app"]),
        BitField("ARProperties_reserved_1", 0, 3),
        BitEnumField("ARProperties_ParametrizationServer", 0, 1, ["External_PrmServer", "CM_Initator"]),
        BitField("ARProperties_SupervisorTakeoverAllowed", 0, 1),
        BitEnumField("ARProperties_State", 1, 3, {1: "Active"}),
        ShortField("CMInitiatorActivityTimeoutFactor", 1000),
        ShortField("CMInitiatorUDPRTPort", 0x8892),
        FieldLenField("StationNameLength", None, fmt="H", length_of="CMInitiatorStationName"),
        StrLenField("CMInitiatorStationName", "", length_from=lambda pkt: pkt.StationNameLength),
        ]
    # default block_type value
    block_type = 0x0101

    def get_response(self):
        """Generate the response block of this request.
        Carefull: it only sets the fields which can be set from the request
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


######################
## IOCRBlockRe{q,s} ##
######################

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
        FieldLenField("NumberOfIODataObjects", None, count_of="IODataObjects"),
        PacketListField("IODataObjects", [], IOCRAPIObject, count_from=lambda p: p.NumberOfIODataObjects),
        FieldLenField("NumberOfIOCS", None, count_of="IOCSs"),
        PacketListField("IOCSs", [], IOCRAPIObject, count_from=lambda p: p.NumberOfIOCS),
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
        #IOCRProperties
        BitField("IOCRProperties_reserved3", 0, 8),
        BitField("IOCRProperties_reserved2", 0, 11),
        BitField("IOCRProperties_reserved1", 0, 9),
        BitEnumField("IOCRProperties_RTClass", 0, 4, IOCR_BLOCK_REQ_IOCR_PROPERTIES),
        ShortField("DataLength", 40),
        XShortField("FrameID", 0x8000),
        ShortField("SendClockFactor", 32),
        ShortField("ReductionRatio", 32),
        ShortField("Phase", 1),
        ShortField("Sequence", 0),
        XIntField("FrameSendOffset", 0xffffffff),
        ShortField("WatchdogFactor", 10),
        ShortField("DataHoldFactor", 10),
        #IOCRTagHeader
        BitEnumField("IOCRTagHeader_IOUserPriority", 6, 3, {6: "IOCRPriority"}),
        BitField("IOCRTagHeader_reserved", 0, 1),
        BitField("IOCRTagHeader_IOCRVLANID", 0, 12),
        MACField("IOCRMulticastMACAdd", None),
        FieldLenField("NumberOfAPIs", None, fmt="H", count_of="APIs"),
        PacketListField("APIs", [], IOCRAPI, count_from=lambda p: p.NumberOfAPIs)
        ]
    # default block_type value
    block_type = 0x0102

    def get_response(self):
        """Generate the response block of this request.
        Carefull: it only sets the fields which can be set from the request
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

###############################
## ExpectedSubmoduleBlockReq ##
###############################

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
        BitEnumField("SubmoduleProperties_Type", 0, 2, ["NO_IO", "INPUT", "OUTPUT", "INPUT_OUTPUT"]),
        PacketListField("DataDescription", [], ExpectedSubmoduleDataDescription, count_from=lambda p: 2 if p.SubmoduleProperties_Type == 3 else 1),
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
        FieldLenField("NumberOfSubmodules", None, fmt="H", count_of="Submodules"),
        PacketListField("Submodules", [], ExpectedSubmodule, count_from=lambda p: p.NumberOfSubmodules),
        ]
    def extract_padding(self, s):
        return None, s  # No extra payload

class ExpectedSubmoduleBlockReq(Block):
    """Expected submodule block request"""
    fields_desc = [
        BlockHeader,
        FieldLenField("NumberOfAPIs", None, fmt="H", count_of="APIs"),
        PacketListField("APIs", [], ExpectedSubmoduleAPI, count_from=lambda p: p.NumberOfAPIs)
        ]
    # default block_type value
    block_type = 0x0104

    def get_response(self):
        """Generate the response block of this request.
        Carefull: it only sets the fields which can be set from the request
        """
        return None # no response associated (should be modulediffblock)

###############################################################################



###############################################################################


#############################
## PROFINET IO DCE/RPC PDU ##
#############################

PNIO_RPC_BLOCK_ASSOCIATION = {
    # requests
    "0101": ARBlockReq,
    "0102": IOCRBlockReq,
    "0104": ExpectedSubmoduleBlockReq,
    "0110": IODControlReq,
    "0111": IODControlReq,
    "0112": IODControlReq,
    "0113": IODControlReq,
    "0114": IODControlReq,
    "0116": IODControlReq,
    "0117": IODControlReq,
    "0118": IODControlReq,

    # responses
    "8101": ARBlockRes,
    "8102": IOCRBlockRes,
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
    cls = Block         # Default block type

    # Special cases
    if _pkt[:2] == "0008".decode("hex"):    # IODWriteReq
        if _pkt[34:36] == "e040".decode("hex"): # IODWriteMultipleReq
            cls = IODWriteMultipleReq
        else:
            cls = IODWriteReq

    elif _pkt[:2] == "8008".decode("hex"):    # IODWriteRes
        if _pkt[34:36] == "e040".decode("hex"): # IODWriteMultipleRes
            cls = IODWriteMultipleRes
        else:
            cls = IODWriteRes

    # Common cases
    else:
        btype = _pkt[:2].encode("hex")
        if btype in PNIO_RPC_BLOCK_ASSOCIATION:
            cls = PNIO_RPC_BLOCK_ASSOCIATION[btype]

    return cls(_pkt, *args, **kargs)

def dce_rpc_endianess(pkt):
    """determine the symbol for the endianess of a the DCE/RPC"""
    endianess = pkt.underlayer.endianess
    if endianess == 0:  # big endian
        return ">"
    elif endianess == 1:  # little endian
        return "<"
    else:
        return "!"

class NDRData(Packet):
    """Base NDRData to centralize some fields. It can't be instanciated"""
    fields_desc = [
        EndiannessField(FieldLenField("args_length", None, fmt="I", length_of="blocks"), endianess_from=dce_rpc_endianess),
        EndiannessField(FieldLenField("max_count", None, fmt="I", length_of="blocks"), endianess_from=dce_rpc_endianess),
        EndiannessField(IntField("offset", 0), endianess_from=dce_rpc_endianess),
        EndiannessField(FieldLenField("actual_count", None, fmt="I", length_of="blocks"), endianess_from=dce_rpc_endianess),
        PacketListField("blocks", [], _guess_block_class, length_from=lambda p: p.args_length)
        ]
    def __new__(cls, name, bases, dct):
        raise NotImplementedError()

class PNIOServiceReqPDU(Packet):
    """PNIO PDU for RPC Request"""
    fields_desc = [
        EndiannessField(FieldLenField("args_max", None, fmt="I", length_of="blocks"), endianess_from=dce_rpc_endianess),
        NDRData,
        ]
    overload_fields = {
        DceRpc: {
            # random object_uuid in the appropriate range
            "object_uuid": RandUUID("dea00000-6c97-11d1-8271-******"),
            # interface uuid to send to a device
            "interface_uuid": RPC_INTERFACE_UUID["UUID_IO_DeviceInterface"],
            # Request DCE/RPC type
            "type": 0,
            },
        }

    @classmethod
    def can_handle(cls, pkt, rpc):
        """heuristical guess_payload_class"""
        # type = 0 => request
        if rpc.getfieldval("type") == 0 and \
                rpc.object_uuid.startswith("dea00000-6c97-11d1-8271-"):
            return True
        return False

DceRpcPayload.register_possible_payload(PNIOServiceReqPDU)


class PNIOServiceResPDU(Packet):
    """PNIO PDU for RPC Response"""
    fields_desc = [
        EndiannessField(IntEnumField("status", 0, ["OK"]), endianess_from=dce_rpc_endianess),
        NDRData,
        ]
    overload_fields = {
        DceRpc: {
            # random object_uuid in the appropriate range
            "object_uuid": RandUUID("dea00000-6c97-11d1-8271-******"),
            # interface uuid to send to a host
            "interface_uuid": RPC_INTERFACE_UUID["UUID_IO_ControllerInterface"],
            # Request DCE/RPC type
            "type": 2,
            },
        }

    @classmethod
    def can_handle(cls, pkt, rpc):
        """heuristical guess_payload_class"""
        # type = 2 => response
        if rpc.getfieldval("type") == 2 and \
                rpc.object_uuid.startswith("dea00000-6c97-11d1-8271-"):
            return True
        return False

DceRpcPayload.register_possible_payload(PNIOServiceResPDU)

