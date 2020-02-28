# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = XCP over CAN(CAN-XCP)
# scapy.contrib.status = loads

import scapy.modules.six as six
from scapy.config import LINUX
from scapy.layers.can import CAN
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ShortField, ByteField,\
    FlagsField, XBitField, ThreeBytesField, StrFixedLenField, \
    StrLenField, IntField

MAX_CTO = 0xffff
MAX_DTO = 0xffff


class XCP(Packet):
    name = "Universal calibration and measurement protocol"
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        XBitField('identifier', 0, 29),
        ByteField('length', 8),
        ThreeBytesField('reserved', 0),
    ]


class CTO(Packet):
    commands = {
        0xFF: "CONNECT",
        0xFE: "DISCONNECT",
        0xFD: "GET_STATUS",
        0xF0: "DOWNLOAD",
        0xEF: "DOWNLOAD_NEXT",
        0xEE: "DOWNLOAD_MAX",
        0xED: "SHORT_DOWNLOAD",
        0xEC: "MODIFY_BITS",
        0xEB: "SET_CAL_PAGE",
        0xEA: "GET_CAL_PAGE",
        0xE9: "GET_PAG_PROCESSOR_INFO",
        0xE8: "GET_SEGMENT_INFO",
        0xE7: "GET_PAGE_INFO",
        0xE6: "SET_SEGMENT_MODE",
        0xE5: "GET_SEGMENT_MODE",
        0xE4: "COPY_CAL_PAGE",
        0xE2: "SET_DAQ_PTR",
        0xE1: "WRITE_DAQ",
        0xE0: "SET_DAQ_LIST_MODE",
        0xDF: "GET_DAQ_LIST_MODE",
        0xDE: "START_STOP_DAQ_LIST",
        0xDD: "START_STOP_SYNCH",
        0xC7: "WRITE_DAQ_MULTIPLE",
        0xDB: "READ_DAQ",
        0xDC: "GET_DAQ_CLOCK",
        0xDA: "GET_DAQ_PROCESSOR_INFO",
        0xD9: "GET_DAQ_RESOLUTION_INFO",
        0xD8: "GET_DAQ_LIST_INFO",
        0xD7: "GET_DAQ_EVENT_INFO",
        0xE3: "CLEAR_DAQ_LIST",
        0xD6: "FREE_DAQ",
        0xD5: "ALLOC_DAQ",
        0xD4: "ALLOC_ODT",
        0xD3: "ALLOC_ODT_ENTRY",
        0xD2: "PROGRAM_START",
        0xD1: "PROGRAM_CLEAR",
        0xD0: "PROGRAM",
        0xCF: "PROGRAM_RESET",
        0xCE: "GET_PGM_PROCESSOR_INFO",
        0xCD: "GET_SECTOR_INFO",
        0xCC: "PROGRAM_PREPARE",
        0xCB: "PROGRAM_FORMAT",
        0xCA: "PROGRAM_NEXT",
        0xC9: "PROGRAM_MAX",
        0xC8: "PROGRAM_VERIFY",

    }
    name = 'Command Transfer Object'

    fields_desc = [
        ByteEnumField('cmd', 0x01, commands),
    ]


# ##### CTO COMMANDS ######

# STANDARD COMMANDS


class XCP_CONNECT(Packet):
    commands = {0x00: 'NORMAL', 0x01: 'USER_DEFINED'}
    fields_desc = [
        ByteEnumField('connection_mode', 0x1, commands),
    ]


bind_layers(CTO, XCP_CONNECT, cmd=0xFF)


class DISCONNECT(Packet):
    # DISCONNECT has no data
    pass


bind_layers(CTO, DISCONNECT, cmd=0xFE)


class GET_STATUS(Packet):
    # GET_STATU has no data
    pass


bind_layers(CTO, GET_STATUS, cmd=0xFD)


class SYNCH(Packet):
    # SYNCH has no data
    pass


bind_layers(CTO, SYNCH, cmd=0xFC)


class GET_COMM_MODE_INFO(Packet):
    # GET_COMM_MODE_INFO has no data
    pass


bind_layers(CTO, GET_COMM_MODE_INFO, cmd=0xFB)


class GET_ID(Packet):
    """Get identification from slave """
    types = {0x00: 'ASCII',
             0x01: "file_name_without_path_and_extension",
             0x02: "file_name_with_path_and_extension",
             0x03: "URL",
             0x04: "File"
             }
    fields_desc = [ByteEnumField("identification_type", 0x00, types)]


bind_layers(CTO, GET_ID, cmd=0xFA)


class SET_REQUEST(Packet):
    """Request to save to non-volatile memory"""
    fields_desc = [
        XBitField("store_cal_req", 0, 1),
        XBitField("reserved1", 0, 1),
        XBitField("store_daq_req", 0, 1),
        XBitField("clear_daq_req", 0, 1),
        XBitField("reserved2", 0, 4),
        ShortField("session_configuration_id", 0x00)
    ]


bind_layers(CTO, SET_REQUEST, cmd=0xF9)


class GET_SEED(Packet):
    # Get seed for unlocking a protected resource
    mode = {0x00: "first", 0x01: "remaining"}
    res = {0x00: "resource", 0x01: "ignore"}
    fields_desc = [
        ByteEnumField("mode", 0, mode),
        ByteEnumField("resource", 0, res)
    ]


bind_layers(CTO, GET_SEED, cmd=0xF8)


class UNLOCK(Packet):
    # Send key for unlocking a protected resource
    fields_desc = [
        ByteField("len", 0),
        StrLenField(0, "", length_from=0, max_length=MAX_CTO - 1)
    ]


bind_layers(CTO, UNLOCK, cmd=0xF7)


class SET_MTA(Packet):
    # Set Memory Transfer Address in slave
    fields_desc = [
        ShortField("Reserved", 0),
        ByteField("dress_extension", 0),
        IntField("address", 0)
    ]


bind_layers(CTO, SET_MTA, cmd=0xF6)


class UPLOAD(Packet):
    # Upload from slave to master
    fields_desc = [ByteField("len", 0)]


bind_layers(CTO, UPLOAD, cmd=0xF5)


class SHORT_UPLOAD(Packet):
    # Upload from slave to master (short version)
    fields_desc = [
        ByteField("len", 0),
        ByteField("reserved", 0),
        ByteField("address_extension", 0),
        IntField("address", 0)
    ]


bind_layers(CTO, SHORT_UPLOAD, cmd=0xF4)


class BUILD_CHECKSUM(Packet):
    # Build checksum over memory range
    fields_desc = [
        ThreeBytesField("reserved", 0),
        IntField("block_size", 0)
    ]


bind_layers(CTO, BUILD_CHECKSUM, cmd=0xF3)


class TRANSPORT_LAYER_CMD(Packet):
    # Refer to transport layer specific command
    fields_desc = [
        ByteField("sub_command_code", 0),
        StrLenField("parameters", "", length_from=0, max_length=MAX_CTO - 1)
    ]


bind_layers(CTO, TRANSPORT_LAYER_CMD, cmd=0xF2)


class USER_CMD(Packet):
    # Refer to user defined command
    fields_desc = [
        ByteField("sub_command_code", 0),
        StrLenField("parameters", "", length_from=0, max_length=MAX_CTO - 1)
    ]


bind_layers(CTO, USER_CMD, cmd=0xF1)


# Calibration Commands

class DOWNLOAD(Packet):
    # Download from master to slave
    fields_desc = [
        ByteField("len", 0),
        StrLenField("data", "", length_from=0, max_length=MAX_CTO - 1)
    ]
    pass


bind_layers(CTO, DOWNLOAD, cmd=0xF0)


class DOWNLOAD_NEXT(Packet):
    # Download from master to slave (Block Mode)
    fields_desc = [
        ByteField("len", 0),
        StrLenField("data", "", length_from=0, max_length=MAX_CTO - 1)
    ]


bind_layers(CTO, DOWNLOAD_NEXT, cmd=0xEF)


class DOWNLOAD_MAX(Packet):
    # Download from master to slave (fixed size)
    fields_desc = [
        StrLenField("data", "", length_from=0, max_length=MAX_CTO - 1)
    ]


bind_layers(CTO, DOWNLOAD_MAX, cmd=0xEE)


class SHORT_DOWNLOAD(Packet):
    # Download from master to slave (short version)
    field_desc = [
        ByteField("len", 0),
        ByteField("reserved", 0),
        ByteField("addres_extension", 0),
        IntField("address", 0),
        StrLenField("data_elements", "", length_from=0, max_length=MAX_CTO - 1)
    ]


bind_layers(CTO, SHORT_DOWNLOAD, cmd=0xED)


class MODIFY_BITS(Packet):
    # Modify  bits
    field_desc = [
        ByteField("shift_value", 0),
        ShortField("and_mask", 0),
        ShortField("xor_mask", 0)
    ]


bind_layers(CTO, MODIFY_BITS, cmd=0xEC)


# Page Switching commands


class SET_CAL_PAGE(Packet):
    """Set calibration page"""
    field_desc = [
        FlagsField('flags', 0, 8, ['ECU',
                                   'XCP',
                                   'reserved1',
                                   'reserved2',
                                   'reserved3',
                                   'reserved4',
                                   'reserved5'
                                   'all']),
        ByteField("data_segment_num", 0),
        ByteField("data_page_num", 0)
    ]


bind_layers(CTO, SET_CAL_PAGE, cmd=0xEB)


class GET_CAL_PAGE(Packet):
    """Get calibration page"""
    fields_desc = [
        ByteField("access_mode", 0),
        ByteField("data_segment_num", 0)
    ]


bind_layers(CTO, GET_CAL_PAGE, cmd=0xEA)


class GET_PAG_PROCESSOR_INFO(Packet):
    """Get general information on PAG processor"""
    pass


bind_layers(CTO, GET_PAG_PROCESSOR_INFO, cmd=0xE9)


class GET_SEGMENT_INFO(Packet):
    """Get specific information for a SEGMENT"""
    mode = {
        0x00: "get_basic_address_info",
        0x01: "get_standard_info",
        0x02: "get_address_mapping_info"
    }

    field_desc = [
        ByteEnumField("mode", 0, mode),
        ByteField("segment_number", 0),
        ByteField("segment_info", 0),
        ByteField("mapping_index", 0)

    ]


bind_layers(CTO, GET_SEGMENT_INFO, cmd=0xE8)


class GET_PAGE_INFO(Packet):
    """ Get specific information for a PAGE """
    field_desc = [
        ByteField("reserved", 0),
        ByteField("segment_number", 0),
        ByteField("page_number", 0)
    ]


bind_layers(CTO, GET_PAGE_INFO, cmd=0xE7)


class SET_SEGMENT_MODE(Packet):
    """Set mode for a SEGMENT"""
    field_desc = [
        FlagsField('flags', 0, 8, ['FREEZE',
                                   'reserved1',
                                   'reserved2',
                                   'reserved3',
                                   'reserved4',
                                   'reserved5',
                                   'reserved6',
                                   'reserved7']),
        ByteField("segment_number", 0)
    ]


bind_layers(CTO, SET_SEGMENT_MODE, cmd=0xE6)


class GET_SEGMENT_MODE(Packet):
    """Get mode for a SEGMENT """
    fields_desc = [
        ByteField("reserverd", 0),
        ByteField("segment_number", 0)
    ]


bind_layers(CTO, GET_SEGMENT_MODE, cmd=0xE5)


class COPY_CAL_PAGE(Packet):
    """This command forces the slave to copy one calibration page to another.
    This command is only available if more than one calibration page is defined
    """
    fields_desc = [
        ByteField("segment_num_src", 0),
        ByteField("page_num_src", 0),
        ByteField("segment_num_dst", 0),
        ByteField("page_num_dst", 0)
    ]


bind_layers(CTO, COPY_CAL_PAGE, cmd=0xE4)


# Cyclic Data exchange Basic commands


class SET_DAQ_PTR(Packet):
    """Data acquisition and stimulation, static, mandatory"""
    fields_desc = [
        ByteField("reserved", 0),
        ShortField("daq_list_num", 0),
        ByteField("odt_num", 0),
        ByteField("odt_entry_num", 0)
    ]


bind_layers(CTO, SET_DAQ_PTR, cmd=0xE2)


class WRITE_DAQ(Packet):
    """Data acquisition and stimulation, static, mandatory """
    fields_desc = [
        ByteField("bit_offset", 0),
        ByteField("size_of_daq", 0),
        ByteField("address_extension", 0),
        IntField("address", 0)
    ]


bind_layers(CTO, WRITE_DAQ, cmd=0xE1)


class SET_DAQ_LIST_MODE(Packet):
    """Set mode for DAQ list """
    fields_desc = [
        FlagsField('flags', 0, 8, ['reserved1',
                                   'direction',
                                   'reserved2',
                                   'reserved3',
                                   'timestamp',
                                   'pid_off',
                                   'reserved4',
                                   'reserved5']),
        ShortField("daq_list_num", 0),
        ShortField("event_channel_num", 0),
        ByteField("transmission_rate_prescaler", 0),
        ByteField("daq_list_prio", 0)
    ]


bind_layers(CTO, SET_DAQ_LIST_MODE, cmd=0xE0)


class GET_DAQ_LIST_MODE(Packet):
    """Get mode from DAQ list"""
    fields_desc = [
        ByteField("reserverd", 0),
        ShortField("daq_list_number", 0)
    ]


bind_layers(CTO, GET_DAQ_LIST_MODE, cmd=0xDF)


class START_STOP_DAQ_LIST(Packet):
    """Start /stop/select DAQ list"""
    mode = {0x00: "stop", 0x01: "start", 0x02: "select"}
    field_desc = [
        ByteEnumField("mode", 0, mode),
        ShortField("daq_list_number", 0)
    ]


bind_layers(CTO, START_STOP_DAQ_LIST, cmd=0xDE)


class START_STOP_SYNCH(Packet):
    """Start/stop DAQ lists (synchronously)"""
    mode = {0x00: "stop", 0x01: "start", 0x02: "select"}
    fields = [
        ByteEnumField("mode", 0, mode)
    ]


bind_layers(CTO, START_STOP_SYNCH, cmd=0xDD)


class READ_DAQ(Packet):
    """Read element from ODT entry"""
    pass


bind_layers(CTO, READ_DAQ, cmd=0xDB)


class GET_DAQ_CLOCK(Packet):
    """ Get DAQ clock from slave """
    pass


bind_layers(CTO, GET_DAQ_CLOCK, cmd=0xDC)


class GET_DAQ_PROCESSOR_INFO(Packet):
    """Get general information on DAQ processor"""
    pass


bind_layers(CTO, GET_DAQ_PROCESSOR_INFO, cmd=0xDA)


class GET_DAQ_RESOLUTION_INFO(Packet):
    """Get general information on DAQ processing resolutioin"""
    pass


bind_layers(CTO, GET_DAQ_RESOLUTION_INFO, cmd=0xD9)


class GET_DAQ_LIST_INFO(Packet):
    """ Get specific information for a DAQ list """
    fields_desc = [
        ByteField("reserved", 0),
        ShortField("daq_list_num", 0)
    ]


bind_layers(CTO, GET_DAQ_LIST_INFO, cmd=0xD8)


class GET_DAQ_EVENT_INFO(Packet):
    """Get specific information for an event channel """
    fields_desc = [
        ByteField("reserved", 0),
        ShortField("event_channel_num", 0)
    ]


bind_layers(CTO, GET_DAQ_EVENT_INFO, cmd=0xD7)


# Cyclic data transfer - static configuration commands


class CLEAR_DAQ_LIST(Packet):
    """Clear DAQ list configuration"""
    fields_desc = [
        ByteField("reserverd", 0),
        ShortField("daq_list_num", 0)
    ]


bind_layers(CTO, CLEAR_DAQ_LIST, cmd=0xE3)


# Cyclic Data transfer - dynamic configuration commands


class FREE_DAQ(Packet):
    """Clear dynamic DAQ configuration"""
    pass


bind_layers(CTO, FREE_DAQ, cmd=0xD6)


class ALLOC_DAQ(Packet):
    """ Allocate DAQ lists """
    fields_desc = [
        ByteField("reserved", 0),
        ShortField("daq_count", 0)
    ]


bind_layers(CTO, ALLOC_DAQ, cmd=0xD5)


class ALLOC_ODT(Packet):
    """Allocate ODTs to a DAQ list"""
    fields_desc = [
        ByteField("reserved", 0),
        ShortField("daq_list_num", 0),
        ByteField("odt_cnt", 0)
    ]


bind_layers(CTO, ALLOC_ODT, cmd=0xD4)


class ALLOC_ODT_ENTRY(Packet):
    """Allocate ODT entries to an ODT """
    fields_desc = [
        ByteField("reserved", 0),
        ShortField("daq_list_num", 0),
        ByteField("odt_num", 0),
        ByteField("odt_entries_cnt", 0)
    ]


bind_layers(CTO, ALLOC_ODT_ENTRY, cmd=0xD3)


# Flash Programming commands


class PROGRAM_START(Packet):
    """Indicate the beginning of a programming sequence"""
    pass


bind_layers(CTO, PROGRAM_START, cmd=0xD2)


class PROGRAM_CLEAR(Packet):
    """Clear a part of non-volatile memory """
    mode = {0x00: "absolute_access", 0x01: "functional_access"}
    fields_desc = [
        ByteEnumField("mode", 0, mode),
        ShortField("reserved", 0),
        IntField("clear_range", 0)
    ]


bind_layers(CTO, PROGRAM_CLEAR, cmd=0xD1)


class PROGRAM(Packet):
    """Program a non-volatile memory segment"""
    fields_desc = [
        ByteField("len", 0),
        StrLenField("data", "", length_from=0, max_length=MAX_CTO - 2)
    ]


bind_layers(CTO, PROGRAM, cmd=0xD0)


class PROGRAM_RESET(Packet):
    """Indicate the end of a programming sequence"""
    pass


bind_layers(CTO, PROGRAM_RESET, cmd=0xCF)


class GET_PGM_PROCESSOR_INFO(Packet):
    """Get general information on PGM processor"""
    pass


bind_layers(CTO, GET_PGM_PROCESSOR_INFO, cmd=0xCE)


class GET_SECTOR_INFO(Packet):
    """Get specific information for a SECTOR"""
    mode = {0x00: "get_address", 0x01: "get_length"}
    fields_desc = [
        ByteEnumField("mode", 0, mode),
        ByteField("sector_number", 0)
    ]


bind_layers(CTO, GET_SECTOR_INFO, cmd=0xCD)


class PROGRAM_PREPARE(Packet):
    """Prepare non-volatile memory programming"""
    fields_desc = [
        ByteField("not_used", 0),
        ShortField("code_size", 0)
    ]


bind_layers(CTO, PROGRAM_PREPARE, cmd=0xCC)


class PROGRAM_FORMAT(Packet):
    """Set data format before programming"""
    fields_desc = [
        ByteField("compression_method", 0),
        ByteField("encryption_mode", 0),
        ByteField("programming_method", 0),
        ByteField("access_method", 0)
    ]


bind_layers(CTO, PROGRAM_FORMAT, cmd=0xCB)


class PROGRAM_NEXT(Packet):
    """Program a non-volatile memory segment (Block Mode) """
    fields_desc = [
        ByteField("len", 0),
        StrLenField("data", "", length_from=0, max_length=MAX_CTO - 2)
    ]


bind_layers(CTO, PROGRAM_NEXT, cmd=0xCA)


class PROGRAM_MAX(Packet):
    """ Program a non-volatile memory segment (fixed size) """
    fields_desc = [
        StrLenField("data", "", length_from=0, max_length=MAX_CTO - 1)
    ]


bind_layers(CTO, PROGRAM_MAX, cmd=0xC9)


class PROGRAM_VERIFY(Packet):
    """Program  Verify"""
    mode = {
        0x00: "request_to_start_internal_routine",
        0x01: "sending_verification_value"
    }
    fields_desc = [
        ByteEnumField("verification_mode", 0, mode),
        ShortField("verification_type", 0),
        IntField("verification_value", 0)
    ]


bind_layers(CTO, PROGRAM_VERIFY, cmd=0xC8)


class ERROR_PACKET(Packet):
    """ Error Packet """
    error_code = {
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
        ByteEnumField("error_code", 0, error_code),
        StrLenField("error_info", 0, length_from=0, max_length=MAX_CTO-1)
    ]


# ##### DTOs #####
class DEFAULT_DTO(Packet):
    fields_desc = [
        StrFixedLenField('load', b'\xff' * 5, length=5)
    ]


class POS_CONNECT_DTO(Packet):
    resource = {}
    comm_mode_basic = {}
    fields_desc = [
        ByteEnumField('resource', 1, resource),
        ByteEnumField('comm_mode_basic',
                      2, comm_mode_basic),
        ByteField('max_cto', 3),
        ShortField('max_dto', 5),
        ByteField('xcp_protocol_layer_version_number_msb', 6),
        ByteField('xcp_transport_layer_version_number_msb', 7)
    ]


class POS_GET_STATUS_DTO(Packet):
    pass


class DTO(Packet):
    __slots__ = Packet.__slots__ + ["payload_cls"]

    packet_ids = {0xFF: 'POSITIVE', 0xFE: 'NEGATIVE'}

    fields_desc = [
        ByteEnumField("packet_id", "POSITIVE", packet_ids)
    ]

    def __init__(self, *args, **kwargs):
        self.payload_cls = DEFAULT_DTO
        if "payload_cls" in kwargs:
            self.payload_cls = kwargs["payload_cls"]
            del kwargs["payload_cls"]
        Packet.__init__(self, *args, **kwargs)

    def get_dto_cls(self, sent_cmd, response_code):
        try:
            response = self.packet_ids[response_code]
        except KeyError:
            return DEFAULT_DTO
        if response == 'POSITIVE':
            try:
                return {
                    0xFF: POS_CONNECT_DTO,
                    0xFD: POS_GET_STATUS_DTO
                }[sent_cmd]
            except KeyError:
                return DEFAULT_DTO
        else:  # negative
            return DEFAULT_DTO

    def answers(self, other):
        if not hasattr(other, "cmd"):
            return 0
        try:
            response_code = self.load[0]
        except (KeyError, TypeError) as e:
            print(e.msg)
            response_code = 0x00
        payload_cls = self.get_dto_cls(other.cmd, response_code)
        if self.payload_cls != payload_cls:
            data = bytes(self.load)
            self.remove_payload()
            self.add_payload(payload_cls(data))
            self.payload_cls = payload_cls
            self.payload_cls = payload_cls
        return 1


bind_layers(XCP, DTO)
# ##### DTOs ######


class XCP_Port():
    """ Reresentation of a XCP Port,
        Holds all infomration of a found port.
    """
    def __init__(self, request_id, response_id, cto_connet_answer):
        self.__answer_msg = cto_connet_answer
        self.__request_id = request_id
        self.__response_id = response_id

    def get_request_id(self):
        return self.__request_id

    def get_response_id(self):
        return self.__response_id

    def __str__(self):
        return """  Found XCP Port
                    Request ID: 0x%x
                    Response ID: 0x%x
                    Comm_Mode: 0x%x, Resource: 0x%x,
                    max_cto: %d, max_dto: %d,
                    portocol_verison: %d, transport_version: %d
               """ % (self.__request_id, self.__response_id,
                      self.__answer_msg.comm_mode_basic,
                      self.__answer_msg.resource,
                      self.__answer_msg.max_cto, self.__answer_msg.max_dto,
                      self.__answer_msg.xcp_protocol_layer_version_number_msb,
                      self.__answer_msg.xcp_transport_layer_version_number_msb)


class XCP_SCANNER():
    """
    Main class for scanning
    """
    def __init__(self, can_socket, start, end, use_extended_can_id,
                 verbose, timeout=0.02):
        """
        Constructor
        :param can_socket: Socket where scan is happening
        :param start: Start ID for scanning
        :param end: Last ID for scanning
        :param use_extended_can_id: True if extended IDs are used
        :param verbose: Select verbosing
        :param timeout: Timeout for receiving messages
        """
        self.__socket = can_socket
        self.__start = start
        self.__end = end
        self.__use_extended_can_id = use_extended_can_id
        self.__receive_thread = None
        self.__send_thread = None
        self.__results = list()
        self.__verbose = verbose
        self.__known_ids = list()
        self.__flags = 0
        if use_extended_can_id:
            self.__flags = "extended"

        if six.PY2 or not LINUX:
            self.__socket.timeout = timeout
        else:
            self.__socket.ins.settimeout(timeout)  # Set RX-timeout of socket

    def get_known_ids(self):
        """
        Wakes up CAN and safes all ids on the bus
        """
        dummy_pkt = CAN(identifier=0x123,
                        data=b'\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA')
        known_ids = list()
        lsend = lambda: self.__socket.send(dummy_pkt)
        backrdn_pkts = self.__socket.sniff(timeout=5,
                                           started_callback=lsend)
        for p in backrdn_pkts:
            if p.identifier not in known_ids:
                known_ids.append(p)
        return known_ids

    def KNOWN_IDS(self):
        return self.__known_ids

    def __add_answers_to_list(self, sent, recv):
        """ Check if port has been found and add it to list """
        if recv.identifier in self.__known_ids:
            return
        if recv.length != 8:
            self.__known_ids.append(recv.identifier)
            return
        try:
            recv_cto = POS_CONNECT_DTO(bytes(recv.payload))
        except IOError:
            self.__known_ids.append(recv.identifier)
            return
        if (recv.data[0] == 0xFF and recv.length == 8):
            self.__results.append(XCP_Port(sent.identifier,
                                           recv.identifier, recv_cto))

    def start_scan(self):
        """Starts the Scan"""
        self.__known_ids = self.get_known_ids()

        # Craft connect packet
        sent = CAN(identifier=self.__start, length=2, flags=self.__flags)
        sent = sent / CTO(cmd="CONNECT")
        sent = sent / XCP_CONNECT(connection_mode="NORMAL")

        recv_callback = lambda recv: self.__add_answers_to_list(sent, recv)
        lsend = lambda: self.__socket.send(sent)
        while sent.identifier <= self.__end:
            #  Sniff for responses after sending
            self.__socket.sniff(prn=recv_callback,
                                timeout=0.01, started_callback=lsend)
            sent.identifier += 1

    def get_results(self):
        """ Getter for results """
        return self.__results
