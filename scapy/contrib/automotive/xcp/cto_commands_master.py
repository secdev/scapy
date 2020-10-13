# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Tabea Spahn <tabea.spahn@e-mundo.de>
# This program is published under a GPLv2 license

# scapy.contrib.status = skip

from scapy.contrib.automotive.xcp.utils import get_ag, get_max_cto, \
    XCPEndiannessField, StrVarLenField
from scapy.fields import ByteEnumField, ByteField, ShortField, StrLenField, \
    IntField, ThreeBytesField, FlagsField, ConditionalField, XByteField, \
    XIntField, FieldLenField
from scapy.packet import Packet, bind_layers


# ##### CTO COMMANDS ######

# STANDARD COMMANDS

class Connect(Packet):
    commands = {0x00: "NORMAL", 0x01: "USER_DEFINED"}
    fields_desc = [
        ByteEnumField("connection_mode", 0, commands),
    ]


class Disconnect(Packet):
    # DISCONNECT has no data
    pass


class GetStatus(Packet):
    # GET_STATUS has no data
    pass


class Synch(Packet):
    # SYNCH has no data
    pass


class GetCommModeInfo(Packet):
    # GET_COMM_MODE_INFO has no data
    pass


class GetId(Packet):
    """Get identification from slave"""
    types = {0x00: "ASCII",
             0x01: "file_name_without_path_and_extension",
             0x02: "file_name_with_path_and_extension",
             0x03: "URL",
             0x04: "File"
             }
    fields_desc = [ByteEnumField("identification_type", 0x00, types)]


class SetRequest(Packet):
    """Request to save to non-volatile memory"""
    fields_desc = [
        FlagsField("mode", 0, 8, [
            "store_cal_req", "store_daq_req", "clear_daq_req", "x3", "x4",
            "x5", "x6", "x7"]),
        XCPEndiannessField(ShortField("session_configuration_id", 0x00))
    ]


class GetSeed(Packet):
    # Get seed for unlocking a protected resource
    seed_mode = {0x00: "first", 0x01: "remaining"}
    res = {0x00: "resource", 0x01: "ignore"}
    fields_desc = [
        ByteEnumField("mode", 0, seed_mode),
        ByteEnumField("resource", 0, res)
    ]


class Unlock(Packet):
    # Send key for unlocking a protected resource
    fields_desc = [
        FieldLenField("len", None, length_of="seed", fmt="B"),
        StrVarLenField("seed", b"", length_from=lambda p: p.len,
                       max_length=lambda: get_max_cto() - 2)
    ]


class SetMta(Packet):
    # Set Memory Transfer Address in slave
    fields_desc = [
        # specification says: position 1,2 type byte (not WORD) The example(
        # Part 5 Example Communication Sequences ) shows 2 bytes for
        # "reserved"
        # http://read.pudn.com/downloads192/doc/comm/903802/XCP%20-Part%205-%20Example%20Communication%20Sequences%20-1.0.pdf # noqa: E501
        # --> 2 bytes
        XCPEndiannessField(ShortField("reserved", 0)),
        ByteField("address_extension", 0),
        XCPEndiannessField(XIntField("address", 0))
    ]


class Upload(Packet):
    # Upload from slave to master
    fields_desc = [ByteField("nr_of_data_elements", 0)]


class ShortUpload(Packet):
    # Upload from slave to master (short version)
    fields_desc = [
        ByteField("nr_of_data_elements", 0),
        ByteField("reserved", 0),
        XByteField("address_extension", 0),
        XCPEndiannessField(IntField("address", 0))
    ]


class BuildChecksum(Packet):
    # Build checksum over memory range
    fields_desc = [
        # specification says: position 1-3 type byte The example(Part 5
        # Example Communication Sequences ) shows 3 bytes for "reserved"
        # http://read.pudn.com/downloads192/doc/comm/903802/XCP%20-Part%205-%20Example%20Communication%20Sequences%20-1.0.pdf # noqa: E501
        # --> 3 bytes
        XCPEndiannessField(ThreeBytesField("reserved", 0)),
        XCPEndiannessField(XIntField("block_size", 0))
    ]


class TransportLayerCmd(Packet):
    # Refer to transport layer specific command
    sub_commands = {
        0xFF: "GET_SLAVE_ID",
        0xFE: "GET_DAQ_ID",
        0xFD: "SET_DAQ_ID",
    }
    fields_desc = [
        ByteEnumField("sub_command_code", 0xFF, sub_commands),
    ]


class TransportLayerCmdGetSlaveId(Packet):
    echo_mode = {
        0x00: "identify_by_echo",
        0x01: "confirm_by_inverse_echo",
    }

    fields_desc = [
        XByteField("x", 0x58),  # ASCII = X
        XByteField("c", 0x43),  # ASCII = C
        XByteField("p", 0x50),  # ASCII = P
        ByteEnumField("mode", 0x00, echo_mode),
    ]


bind_layers(TransportLayerCmd, TransportLayerCmdGetSlaveId,
            sub_command_code=0xFF)


class TransportLayerCmdGetDAQId(Packet):
    fields_desc = [
        XCPEndiannessField(ShortField("daq_list_number", 0)),
    ]


bind_layers(TransportLayerCmd, TransportLayerCmdGetDAQId,
            sub_command_code=0xFE)


class TransportLayerCmdSetDAQId(Packet):
    sub_command = {
        0xFD: "SET_DAQ_ID",
    }
    fields_desc = [
        XCPEndiannessField(ShortField("daq_list_number", 0)),
        XCPEndiannessField(IntField("can_identifier", 0))
    ]


bind_layers(TransportLayerCmd, TransportLayerCmdSetDAQId,
            sub_command_code=0xFD)


class UserCmd(Packet):
    # Refer to user defined command
    fields_desc = [
        ByteField("sub_command_code", 0),
    ]


# Calibration Commands

class Download(Packet):
    # Download from master to slave
    fields_desc = [
        ByteField("nr_of_data_elements", 0),
        ConditionalField(
            StrLenField("alignment", b"",
                        length_from=lambda pkt: get_ag() - 2),
            lambda pkt: get_ag() > 2),
        StrLenField("data_elements", b"",
                    length_from=lambda pkt: get_max_cto() - 2 if get_ag() == 1
                    else get_max_cto() - get_ag()),
    ]


class DownloadNext(Download):
    # Used for the download from master to slave in block mode
    # Same as "Download", but with different command code
    pass


class DownloadMax(Packet):
    # Download from master to slave (fixed size)
    fields_desc = [
        ConditionalField(
            StrLenField("alignment", b"", length_from=lambda _: get_ag() - 1),
            lambda _: get_ag() > 1),
        StrLenField("data_elements", b"",
                    length_from=lambda _: get_max_cto() - (get_ag() * 2 - 1))
    ]


class ShortDownload(Packet):
    # Download from master to slave (short version)
    fields_desc = [
        FieldLenField("len", None, length_of="data_elements", fmt="B"),
        ByteField("reserved", 0),
        ByteField("address_extension", 0),
        XCPEndiannessField(IntField("address", 0)),
        StrVarLenField("data_elements", b"", length_from=lambda p: p.len,
                       max_length=lambda: get_max_cto() - 8)
    ]


class ModifyBits(Packet):
    # Modify bits
    fields_desc = [
        ByteField("shift_value", 0),
        XCPEndiannessField(ShortField("and_mask", 0)),
        XCPEndiannessField(ShortField("xor_mask", 0))
    ]


# Page Switching commands
class SetCalPage(Packet):
    """Set calibration page"""
    fields_desc = [
        FlagsField("mode", 0, 8,
                   ["ecu", "xcp", "x2", "x3", "x4", "x5", "x6", "all"]),
        ByteField("data_segment_num", 0),
        ByteField("data_page_num", 0)
    ]


class GetCalPage(Packet):
    """Get calibration page"""
    fields_desc = [
        ByteField("access_mode", 0),
        ByteField("data_segment_num", 0)
    ]


class GetPagProcessorInfo(Packet):
    """Get general information on PAG processor"""
    pass


class GetSegmentInfo(Packet):
    """Get specific information for a SEGMENT"""
    info_mode = {
        0x00: "get_basic_address_info",
        0x01: "get_standard_info",
        0x02: "get_address_mapping_info"
    }

    fields_desc = [
        ByteEnumField("mode", 0x00, info_mode),
        ByteField("segment_number", 0),
        ByteField("segment_info", 0),
        ByteField("mapping_index", 0)

    ]


class GetPageInfo(Packet):
    """Get specific information for a PAGE"""
    fields_desc = [
        ByteField("reserved", 0),
        ByteField("segment_number", 0),
        ByteField("page_number", 0)
    ]


class SetSegmentMode(Packet):
    """Set mode for a SEGMENT"""
    fields_desc = [
        FlagsField("mode", 0, 8,
                   ["freeze", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]),
        ByteField("segment_number", 0)
    ]


class GetSegmentMode(Packet):
    """Get mode for a SEGMENT"""
    fields_desc = [
        ByteField("reserved", 0),
        ByteField("segment_number", 0)
    ]


class CopyCalPage(Packet):
    """This command forces the slave to copy one calibration page to another.
    This command is only available if more than one calibration page is defined
    """
    fields_desc = [
        ByteField("segment_num_src", 0),
        ByteField("page_num_src", 0),
        ByteField("segment_num_dst", 0),
        ByteField("page_num_dst", 0)
    ]


class SetDaqPtr(Packet):
    """Data acquisition and stimulation, static, mandatory"""
    fields_desc = [
        ByteField("reserved", 0),
        XCPEndiannessField(ShortField("daq_list_num", 0)),
        ByteField("odt_num", 0),
        ByteField("odt_entry_num", 0)
    ]


class WriteDaq(Packet):
    """Data acquisition and stimulation, static, mandatory"""
    fields_desc = [
        ByteField("bit_offset", 0),
        ByteField("size_of_daq_element", 0),
        ByteField("address_extension", 0),
        XCPEndiannessField(IntField("address", 0))
    ]


class SetDaqListMode(Packet):
    """Set mode for DAQ list"""
    fields_desc = [
        FlagsField("mode", 0, 8,
                   ["x0", "direction", "x2", "x3", "timestamp", "pid_off",
                    "x6", "x7"]),
        XCPEndiannessField(ShortField("daq_list_num", 0)),
        XCPEndiannessField(ShortField("event_channel_num", 0)),
        ByteField("transmission_rate_prescaler", 0),
        ByteField("daq_list_prio", 0)
    ]


class GetDaqListMode(Packet):
    """Get mode from DAQ list"""
    fields_desc = [
        ByteField("reserved", 0),
        XCPEndiannessField(ShortField("daq_list_number", 0))
    ]


class StartStopDaqList(Packet):
    """Start/stop/select DAQ list"""
    mode_enum = {0x00: "stop", 0x01: "start", 0x02: "select"}
    fields_desc = [
        ByteEnumField("mode", 0, mode_enum),
        XCPEndiannessField(ShortField("daq_list_number", 0))
    ]


class StartStopSynch(Packet):
    """Start/stop DAQ lists (synchronously)"""
    mode_enum = {0x00: "stop", 0x01: "start", 0x02: "select"}
    fields_desc = [
        ByteEnumField("mode", 0x00, mode_enum)
    ]


class ReadDaq(Packet):
    """Read element from ODT entry"""
    pass


class GetDaqClock(Packet):
    """Get DAQ clock from slave"""
    pass


class GetDaqProcessorInfo(Packet):
    """Get general information on DAQ processor"""
    pass


class GetDaqResolutionInfo(Packet):
    """Get general information on DAQ processing resolutioin"""
    pass


class GetDaqListInfo(Packet):
    """Get specific information for a DAQ list"""
    fields_desc = [
        ByteField("reserved", 0),
        XCPEndiannessField(ShortField("daq_list_num", 0))
    ]


class GetDaqEventInfo(Packet):
    """Get specific information for an event channel"""
    fields_desc = [
        ByteField("reserved", 0),
        XCPEndiannessField(ShortField("event_channel_num", 0))
    ]

    # Cyclic data transfer - static configuration commands


class ClearDaqList(Packet):
    """Clear DAQ list configuration"""
    fields_desc = [
        ByteField("reserved", 0),
        XCPEndiannessField(ShortField("daq_list_num", 0))
    ]


# Cyclic Data transfer - dynamic configuration commands


class FreeDaq(Packet):
    """Clear dynamic DAQ configuration"""
    pass


class AllocDaq(Packet):
    """Allocate DAQ lists"""
    fields_desc = [
        ByteField("reserved", 0),
        XCPEndiannessField(ShortField("daq_count", 0))
    ]


class AllocOdt(Packet):
    """Allocate ODTs to a DAQ list"""
    fields_desc = [
        ByteField("reserved", 0),
        XCPEndiannessField(ShortField("daq_list_num", 0)),
        ByteField("odt_count", 0)
    ]


class AllocOdtEntry(Packet):
    """Allocate ODT entries to an ODT"""
    fields_desc = [
        ByteField("reserved", 0),
        XCPEndiannessField(ShortField("daq_list_num", 0)),
        ByteField("odt_num", 0),
        ByteField("odt_entries_count", 0)
    ]


# Flash Programming commands

class ProgramStart(Packet):
    """Indicate the beginning of a programming sequence"""
    pass


class ProgramClear(Packet):
    """Clear a part of non-volatile memory"""
    access_mode = {0x00: "absolute_access", 0x01: "functional_access"}
    fields_desc = [
        ByteEnumField("mode", 0, access_mode),
        XCPEndiannessField(ShortField("reserved", 0)),
        XCPEndiannessField(IntField("clear_range", 0))
    ]


class Program(Download):
    """Program a non-volatile memory segment"""
    # Same structure as "Download", but with different command code
    pass


class ProgramReset(Packet):
    """Indicate the end of a programming sequence"""
    pass


class GetPgmProcessorInfo(Packet):
    """Get general information on PGM processor"""
    pass


class GetSectorInfo(Packet):
    """Get specific information for a SECTOR"""
    address_mode = {0x00: "get_address", 0x01: "get_length"}
    fields_desc = [
        ByteEnumField("mode", 0, address_mode),
        ByteField("sector_number", 0)
    ]


class ProgramPrepare(Packet):
    """Prepare non-volatile memory programming"""
    fields_desc = [
        ByteField("not_used", 0),
        XCPEndiannessField(ShortField("code_size", 0))
    ]


class ProgramFormat(Packet):
    """Set data format before programming"""
    fields_desc = [
        ByteField("compression_method", 0),
        ByteField("encryption_mode", 0),
        ByteField("programming_method", 0),
        ByteField("access_method", 0)
    ]


class ProgramNext(Download):
    """Program a non-volatile memory segment (Block Mode)"""
    # Same structure as "Download", but with different command code
    pass


class ProgramMax(DownloadMax):
    """Program a non-volatile memory segment (fixed size)"""
    # Same as "DownloadMax", but with different command code
    pass


class ProgramVerify(Packet):
    """Program  Verify"""
    start_mode = {
        0x00: "request_to_start_internal_routine",
        0x01: "sending_verification_value"
    }
    fields_desc = [
        ByteEnumField("verification_mode", 0, start_mode),
        XCPEndiannessField(ShortField("verification_type", 0)),
        XCPEndiannessField(IntField("verification_value", 0))
    ]
