# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Tabea Spahn <tabea.spahn@e-mundo.de>
# This program is published under a GPLv2 license

# scapy.contrib.status = skip

from logging import warning

from scapy.config import conf
from scapy.contrib.automotive.xcp.utils import get_max_cto, get_ag, \
    XCPEndiannessField, StrVarLenField
from scapy.fields import ByteEnumField, ByteField, ShortField, StrLenField, \
    FlagsField, IntField, ThreeBytesField, ConditionalField, XByteField, \
    StrField, LEShortField, XIntField, FieldLenField
from scapy.packet import Packet


# ##### CTO COMMANDS ######

# STANDARD COMMANDS

class NegativeResponse(Packet):
    """Error Packet"""
    error_code_enum = {
        0x00: "ERR_CMD_SYNCH",
        0x10: "ERR_CMD_BUSY",
        0x11: "ERR_DAQ_ACTIVE",
        0x12: "ERR_PGM_ACTIVE",
        0x20: "ERR_CMD_UNKNOWN",
        0x21: "ERR_CMD_SYNTAX",
        0x22: "ERR_OUT_OF_RANGE",
        0x23: "ERR_WRITE_PROTECTED",
        0x24: "ERR_ACCESS_DENIED",
        0x25: "ERR_ACCESS_LOCKED",
        0x26: "ERR_PAGE_NOT_VALID",
        0x27: "ERR_MODE_NOT_VALID",
        0x28: "ERR_SEGMENT_NOT_VALID",
        0x29: "ERR_SEQUENCE",
        0x2A: "ERR_DAQ_CONFIG",
        0x30: "ERR_MEMORY_OVERFLOW",
        0x31: "ERR_GENERIC",
        0x32: "ERR_VERIFY"
    }
    fields_desc = [
        ByteEnumField("error_code", 0, error_code_enum),
        StrField("error_info", "")
    ]


class GenericResponse(Packet):
    """Command Response packet """
    fields_desc = [
        StrField("command_response_data", "")
    ]


class ConnectPositiveResponse(Packet):
    fields_desc = [
        FlagsField("resource", 0, 8,
                   ["cal_pag", "x1", "daq", "stim", "pgm", "x5", "x6", "x7"]),
        FlagsField("comm_mode_basic", 0, 8,
                   ["byte_order", "address_granularity_0",
                    "address_granularity_1", "x3", "x4", "x5",
                    "slave_block_mode", "optional"]),
        ByteField("max_cto", 0),
        ConditionalField(ShortField("max_dto", 0),
                         lambda p: p.comm_mode_basic.byte_order),
        ConditionalField(LEShortField("max_dto_le", 0),
                         lambda p: not p.comm_mode_basic.byte_order),
        ByteField("xcp_protocol_layer_version_number_msb", 1),
        ByteField("xcp_transport_layer_version_number_msb", 1)
    ]

    def post_dissection(self, pkt):
        if conf.contribs["XCP"]["allow_byte_order_change"]:
            new_value = int(self.comm_mode_basic.byte_order)
            if new_value != conf.contribs["XCP"]["byte_order"]:
                conf.contribs["XCP"]["byte_order"] = new_value

                desc = "Big Endian" if new_value else "Little Endian"
                warning("Byte order changed to {0} because of received "
                        "positive connect packet".format(desc))

        if conf.contribs["XCP"]["allow_ag_change"]:
            conf.contribs["XCP"][
                "Address_Granularity_Byte"] = self.get_address_granularity()

        if conf.contribs["XCP"]["allow_cto_and_dto_change"]:
            conf.contribs["XCP"]["MAX_CTO"] = self.max_cto
            conf.contribs["XCP"]["MAX_DTO"] = self.max_dto or self.max_dto_le

    def get_address_granularity(self):
        comm_mode_basic = self.comm_mode_basic
        if not comm_mode_basic.address_granularity_0 and \
                not comm_mode_basic.address_granularity_1:
            return 1
        if comm_mode_basic.address_granularity_0 and \
                not comm_mode_basic.address_granularity_1:
            return 2
        if not comm_mode_basic.address_granularity_0 and \
                comm_mode_basic.address_granularity_1:
            return 4
        else:
            warning(
                "Getting address granularity from packet failed:"
                "both flags are 1")


class StatusPositiveResponse(Packet):
    fields_desc = [
        FlagsField("current_session_status", 0, 8,
                   ["store_cal_req", "x1", "store_daq_req",
                    "clear_daq_request", "x4", "x5", "daq_running", "resume"]),
        FlagsField("current_resource_protection_status", 0, 8,
                   ["cal_pag", "x1", "daq", "stim", "pgm", "x5", "x6", "x7"]),
        ByteField("reserved", 0),
        XCPEndiannessField(ShortField("session_configuration_id", 0))
    ]


class CommonModeInfoPositiveResponse(Packet):
    fields_desc = [
        ByteField("reserved1", 0),
        FlagsField("comm_mode_optional", 0, 8,
                   ["master_block_mode", "interleaved_mode", "x2", "x3", "x4",
                    "x5", "x6", "x7"]),
        ByteField("reserved2", 0),
        ByteField("max_bs", 0),
        ByteField("min_st", 0),
        ByteField("queue_size", 0),
        ByteField("xcp_driver_version_number", 0),
    ]


class IdPositiveResponse(Packet):
    fields_desc = [
        ByteField("mode", 0),
        XCPEndiannessField(ShortField("reserved", 0)),
        XCPEndiannessField(FieldLenField("length", None, length_of="element",
                                         fmt="I")),
        StrVarLenField("element", b"", length_from=lambda p: p.length,
                       max_length=lambda pkt: get_ag())
    ]


class SeedPositiveResponse(Packet):
    fields_desc = [
        FieldLenField("seed_length", None, length_of="seed", fmt="B"),
        StrVarLenField("seed", b"", length_from=lambda p: p.seed_length,
                       max_length=lambda: get_max_cto() - 2)
    ]


class UnlockPositiveResponse(Packet):
    fields_desc = [
        FlagsField("current_resource_protection_status", 0, 8,
                   ["cal_pag", "x1", "daq", "stim", "pgm", "x5", "x6", "x7"])
    ]


class UploadPositiveResponse(Packet):
    fields_desc = [
        ConditionalField(
            StrLenField("alignment", b"",
                        length_from=lambda pkt: get_ag() - 1),
            lambda _: get_ag() > 1),
        StrLenField("element", b"",
                    length_from=lambda pkt: get_max_cto() - get_ag()),
    ]


class ShortUploadPositiveResponse(Packet):
    fields_desc = [
        ConditionalField(
            StrLenField("alignment", b"",
                        length_from=lambda pkt: get_ag() - 1),
            lambda _: get_ag() > 1),
        StrLenField("element", b"",
                    length_from=lambda pkt: get_max_cto() - get_ag()),
    ]


class ChecksumPositiveResponse(Packet):
    checksum_type_dict = {
        0x01: "XCP_ADD_11",
        0x02: "XCP_ADD_12",
        0x03: "XCP_ADD_14",
        0x04: "XCP_ADD_22",
        0x05: "XCP_ADD_24",
        0x06: "XCP_ADD_44",
        0x07: "XCP_CRC_16",
        0x08: "XCP_CRC_16_CITT",
        0x09: "XCP_CRC_32",
        0xFF: "XCP_USER_DEFINED"
    }
    fields_desc = [
        ByteEnumField("checksum_type", 0, checksum_type_dict),
        # specification says: position 2,3 type byte (not WORD) The example(
        # Part 5 Example Communication Sequences) shows 2 bytes for
        # "reserved"
        # http://read.pudn.com/downloads192/doc/comm/903802/XCP%20-Part%205-%20Example%20Communication%20Sequences%20-1.0.pdf # noqa: E501
        # --> 2 bytes
        XCPEndiannessField(ShortField("reserved", 0)),
        XCPEndiannessField(XIntField("checksum", 0)),
    ]


class TransportLayerCmdGetSlaveIdResponse(Packet):
    fields_desc = [
        XByteField("position_1", 0x58),  # 0xA7 (inversed echo)
        XByteField("position_2", 0x43),  # 0xBC (inversed echo)
        XByteField("position_3", 0x50),  # 0xAF (inversed echo)
        XCPEndiannessField(IntField("can_identifier", 0))
    ]


class TransportLayerCmdGetDAQIdResponse(Packet):
    can_id_fixed_enum = {
        0x00: "configurable",
        0x01: "fixed"
    }
    fields_desc = [
        ByteEnumField("can_id_fixed", 0xFE, can_id_fixed_enum),
        XCPEndiannessField(ShortField("reserved", 0)),
        XCPEndiannessField(IntField("can_identifier", 0))
    ]


class CalPagePositiveResponse(Packet):
    fields_desc = [
        ByteField("reserved_1", 0),
        ByteField("reserved_2", 0),
        ByteField("logical_data_page_number", 0),
    ]


class PagProcessorInfoPositiveResponse(Packet):
    fields_desc = [
        ByteField("max_segment", 0),
        FlagsField("pag_properties", 0, 8,
                   ["freeze_supported", "x1", "x2", "x3", "x4", "x5", "x6",
                    "x7"]),
    ]


class SegmentInfoMode0PositiveResponse(Packet):
    fields_desc = [
        # spec: position 1-3: type byte
        # --> take position over type
        XCPEndiannessField(ThreeBytesField("reserved", 0)),
        XCPEndiannessField(IntField("basic_info", 0)),
    ]


class SegmentInfoMode1PositiveResponse(Packet):
    fields_desc = [
        ByteField("max_pages", 0),
        ByteField("address_extension", 0),
        ByteField("max_extension", 0),
        ByteField("compression_method", 0),
        ByteField("encryption_method", 0),
    ]


class SegmentInfoMode2PositiveResponse(Packet):
    fields_desc = [
        # spec:  position 1-3: type byte
        # --> take position over type
        XCPEndiannessField(ThreeBytesField("reserved", 0)),
        XCPEndiannessField(IntField("mapping_info", 0)),
    ]


class PageInfoPositiveResponse(Packet):
    fields_desc = [
        FlagsField("page_properties", 0, 8,
                   ["ecu_access_without_xcp", "ecu_access_with_xcp",
                    "xcp_read_access_without_ecu", "xcp_read_access_with_ecu",
                    "xcp_write_access_without_ecu",
                    "xcp_write_access_with_ecu", "x6", "x7"]),
        ByteField("init_segment", 0),
    ]


class SegmentModePositiveResponse(Packet):
    fields_desc = [
        ByteField("reserved", 0),
        FlagsField("mode", 0, 8,
                   ["freeze", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]),
    ]


class DAQListModePositiveResponse(Packet):
    fields_desc = [
        FlagsField("current_mode", 0, 8,
                   ["selected", "direction", "x2", "x3", "timestamp",
                    "pid_off", "running", "resume"]),
        XCPEndiannessField(ShortField("reserved", 0)),
        XCPEndiannessField(ShortField("current_event_channel_number", 0)),
        ByteField("current_prescaler", 0),
        ByteField("current_daq_list_priority", 0),
    ]


class StartStopDAQListPositiveResponse(Packet):
    fields_desc = [
        ByteField("first_pid", 0),
    ]


class DAQClockListPositiveResponse(Packet):
    fields_desc = [
        # spec: position 1-3: type byte
        # --> take position over type
        XCPEndiannessField(ThreeBytesField("reserved", 0)),
        XCPEndiannessField(IntField("receive_timestamp", 0))
    ]


class ReadDAQPositiveResponse(Packet):
    fields_desc = [
        ByteField("bit_offset", 0),
        ByteField("size_daq_element", 0),
        ByteField("address_extension_daq_element", 0),
        XCPEndiannessField(IntField("daq_element_address", 0))
    ]


class DAQProcessorInfoPositiveResponse(Packet):
    fields_desc = [
        FlagsField("daq_properties", 0, 8,
                   ["daq_config_type", "prescaler_supported",
                    "resume_supported", "bit_stim_supported",
                    "timestamp_supported", "pid_off_supported", "overload_msb",
                    "overload_event"]),
        XCPEndiannessField(ShortField("max_daq", 0)),
        XCPEndiannessField(ShortField("max_event_channel", 0)),
        ByteField("min_daq", 0),
        FlagsField("daq_key_byte", 0, 8,
                   ["optimisation_type_0", "optimisation_type_1",
                    "optimisation_type_2", "optimisation_type_3",
                    "address_extension_odt", "address_extension_daq",
                    "identification_field_type_0",
                    "identification_field_type_1"]),
    ]

    def write_identification_field_type_to_config(self):
        conf.contribs["XCP"][
            "identification_field_type_0"] = bool(
            self.daq_key_byte.identification_field_type_0)
        conf.contribs["XCP"][
            "identification_field_type_1"] = bool(
            self.daq_key_byte.identification_field_type_1)

    def post_dissection(self, pkt):
        self.write_identification_field_type_to_config()


class DAQResolutionInfoPositiveResponse(Packet):
    fields_desc = [
        ByteField("granularity_odt_entry_size_daq", 0),
        ByteField("max_odt_entry_size_daq", 0),
        ByteField("granularity_odt_entry_size_stim", 0),
        ByteField("max_odt_entry_size_stim", 0),
        FlagsField("timestamp_mode", 0, 8,
                   ["size_0", "size_1", "size_2", "timestamp_fixed", "unit_0",
                    "unit_1", "unit_2", "unit_3"]),
        XCPEndiannessField(ShortField("timestamp_ticks", 0)),
    ]

    def get_timestamp_size(self):
        size_0 = bool(self.timestamp_mode.size_0)
        size_1 = bool(self.timestamp_mode.size_1)
        size_2 = bool(self.timestamp_mode.size_2)

        if not size_2 and not size_1 == 0 and size_0:
            return 1
        if not size_2 and size_1 and not size_0:
            return 2
        if size_2 and not size_1 and not size_0:
            return 4
        return 0

    def write_timestamp_size_to_config(self):
        conf.contribs["XCP"]["timestamp_size"] = self.get_timestamp_size()

    def post_dissection(self, pkt):
        self.write_timestamp_size_to_config()


class DAQListInfoPositiveResponse(Packet):
    fields_desc = [
        FlagsField("daq_list_properties", 0, 8,
                   ["predefined", "event_fixed", "daq", "stim", "x4", "x5",
                    "x6", "x7"]),
        ByteField("max_odt", 0),
        ByteField("max_odt_entries", 0),
        XCPEndiannessField(ShortField("fixed_event", 0)),
    ]


class DAQEventInfoPositiveResponse(Packet):
    fields_desc = [
        FlagsField("daq_event_properties", 0, 8,
                   ["x0", "x1", "daq", "stim", "x4", "x5", "x6", "x7"]),
        ByteField("max_daq_list", 0),
        ByteField("event_channel_name_length", 0),
        ByteField("event_channel_time_cycle", 0),
        ByteField("event_channel_time_unit", 0),
        ByteField("event_channel_priority", 0),
    ]


class ProgramStartPositiveResponse(Packet):
    fields_desc = [
        ByteField("reserved", 0),
        FlagsField("comm_mode_pgm", 0, 8,
                   ["master_block_mode", "interleaved_mode", "x2", "x3", "x4",
                    "x5", "slave_block_mode", "x7"]),
        ByteField("max_cto_pgm", 0),
        ByteField("max_bs_pgm", 0),
        ByteField("min_bs_pgm", 0),
        ByteField("queue_size_pgm", 0),
    ]


class PgmProcessorPositiveResponse(Packet):
    fields_desc = [
        FlagsField("pgm_properties", 0, 8,
                   ["absolute_mode", "functional_mode",
                    "compression_supported", "compression_required",
                    "encryption_supported", "encryption_required",
                    "non_seq_pgm_supported", "non_seq_pgm_required"]),
        ByteField("max_sector", 0),
    ]


class SectorInfoPositiveResponse(Packet):
    fields_desc = [
        ByteField("clear_sequence_number", 0),
        ByteField("program_sequence_number", 0),
        ByteField("programming_method", 0),
        XCPEndiannessField(IntField("sector_info", 0))
    ]


class EvPacket(Packet):
    """Event packet"""
    event_code_enum = {
        0x00: "EV_RESUME_MODE",
        0x01: "EV_CLEAR_DAQ",
        0x02: "EV_STORE_DAQ",
        0x03: "EV_STORE_CAL",
        0x05: "EV_CMD_PENDING",
        0x06: "EV_DAQ_OVERLOAD",
        0x07: "EV_SESSION_TERMINATED",
        0xFE: "EV_USER",
        0xFF: "EV_TRANSPORT",
    }
    fields_desc = [
        ByteEnumField("event_code", 0, event_code_enum),
        StrLenField("event_information_data", b"",
                    max_length=lambda _: get_max_cto() - 2)
    ]


class ServPacket(Packet):
    """Service Request packet"""
    service_request_code_enum = {
        0x00: "SERV_RESET",
        0x01: "SERV_TEXT",
    }

    fields_desc = [
        ByteEnumField("service_request_code", 0, service_request_code_enum),
        StrLenField("command_response_data", b"",
                    max_length=lambda _: get_max_cto() - 2)
    ]
