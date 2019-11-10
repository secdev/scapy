# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = CAN Calibration Protocol (CCP)
# scapy.contrib.status = loads

import struct

from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import XIntField, FlagsField, ByteEnumField, \
    ThreeBytesField, XBitField, ShortField, IntField, XShortField, \
    ByteField, XByteField, StrFixedLenField, LEShortField
from scapy.layers.can import CAN


class CCP(CAN):
    name = 'CAN Calibration Protocol'
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        XBitField('identifier', 0, 29),
        ByteField('length', 8),
        ThreeBytesField('reserved', 0),
    ]

    def extract_padding(self, p):
        return p, None


class CRO(Packet):
    commands = {
        0x01: "CONNECT",
        0x1B: "GET_CCP_VERSION",
        0x17: "EXCHANGE_ID",
        0x12: "GET_SEED",
        0x13: "UNLOCK",
        0x02: "SET_MTA",
        0x03: "DNLOAD",
        0x23: "DNLOAD_6",
        0x04: "UPLOAD",
        0x0F: "SHORT_UP",
        0x11: "SELECT_CAL_PAGE",
        0x14: "GET_DAQ_SIZE",
        0x15: "SET_DAQ_PTR",
        0x16: "WRITE_DAQ",
        0x06: "START_STOP",
        0x07: "DISCONNECT",
        0x0C: "SET_S_STATUS",
        0x0D: "GET_S_STATUS",
        0x0E: "BUILD_CHKSUM",
        0x10: "CLEAR_MEMORY",
        0x18: "PROGRAM",
        0x22: "PROGRAM_6",
        0x19: "MOVE",
        0x05: "TEST",
        0x09: "GET_ACTIVE_CAL_PAGE",
        0x08: "START_STOP_ALL",
        0x20: "DIAG_SERVICE",
        0x21: "ACTION_SERVICE"
    }
    name = 'Command Receive Object'
    fields_desc = [
        ByteEnumField('cmd', 0x01, commands),
        ByteField('ctr', 0)
    ]

    def hashret(self):
        return struct.pack('B', self.ctr)


# ##### CROs ######

class CONNECT(Packet):
    fields_desc = [
        LEShortField('station_address', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 4, length=4),
    ]


bind_layers(CRO, CONNECT, cmd=0x01)


class GET_CCP_VERSION(Packet):
    fields_desc = [
        XByteField('main_protocol_version', 0),
        XByteField('release_version', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 4, length=4)
    ]


bind_layers(CRO, GET_CCP_VERSION, cmd=0x1B)


class EXCHANGE_ID(Packet):
    fields_desc = [
        StrFixedLenField('ccp_master_device_id', b'\x00' * 6, length=6)
    ]


bind_layers(CRO, EXCHANGE_ID, cmd=0x17)


class GET_SEED(Packet):
    fields_desc = [
        XByteField('resource', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 5, length=5)
    ]


bind_layers(CRO, GET_SEED, cmd=0x12)


class UNLOCK(Packet):
    fields_desc = [
        StrFixedLenField('key', b'\x00' * 6, length=6)
    ]


bind_layers(CRO, UNLOCK, cmd=0x13)


class SET_MTA(Packet):
    fields_desc = [
        XByteField('mta_num', 0),
        XByteField('address_extension', 0),
        XIntField('address', 0),
    ]


bind_layers(CRO, SET_MTA, cmd=0x02)


class DNLOAD(Packet):
    fields_desc = [
        XByteField('size', 0),
        StrFixedLenField('data', b'\x00' * 5, length=5)
    ]


bind_layers(CRO, DNLOAD, cmd=0x03)


class DNLOAD_6(Packet):
    fields_desc = [
        StrFixedLenField('data', b'\x00' * 6, length=6)
    ]


bind_layers(CRO, DNLOAD_6, cmd=0x23)


class UPLOAD(Packet):
    fields_desc = [
        XByteField('size', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 5, length=5)
    ]


bind_layers(CRO, UPLOAD, cmd=0x04)


class SHORT_UP(Packet):
    fields_desc = [
        XByteField('size', 0),
        XByteField('address_extension', 0),
        XIntField('address', 0),
    ]


bind_layers(CRO, SHORT_UP, cmd=0x0F)


class SELECT_CAL_PAGE(Packet):
    fields_desc = [
        StrFixedLenField('ccp_reserved', b'\xff' * 6, length=6)
    ]


bind_layers(CRO, SELECT_CAL_PAGE, cmd=0x11)


class GET_DAQ_SIZE(Packet):
    fields_desc = [
        XByteField('DAQ_num', 0),
        XByteField('ccp_reserved', 0),
        XIntField('DTO_identifier', 0),
    ]


bind_layers(CRO, GET_DAQ_SIZE, cmd=0x14)


class SET_DAQ_PTR(Packet):
    fields_desc = [
        XByteField('DAQ_num', 0),
        XByteField('ODT_num', 0),
        XByteField('ODT_element', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 3, length=3)
    ]


bind_layers(CRO, SET_DAQ_PTR, cmd=0x15)


class WRITE_DAQ(Packet):
    fields_desc = [
        XByteField('DAQ_size', 0),
        XByteField('address_extension', 0),
        XIntField('address', 0),
    ]


bind_layers(CRO, WRITE_DAQ, cmd=0x16)


class START_STOP(Packet):
    fields_desc = [
        XByteField('mode', 0),
        XByteField('DAQ_num', 0),
        XByteField('ODT_num', 0),
        XByteField('event_channel', 0),
        XShortField('transmission_rate', 0),
    ]


bind_layers(CRO, START_STOP, cmd=0x06)


class DISCONNECT(Packet):
    fields_desc = [
        ByteEnumField('type', 0, {0: "temporary", 1: "end_of_session"}),
        StrFixedLenField('ccp_reserved0', b'\xff' * 1, length=1),
        LEShortField('station_address', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 2, length=2)
    ]


bind_layers(CRO, DISCONNECT, cmd=0x07)


class SET_S_STATUS(Packet):
    name = "Set Session Status"
    fields_desc = [
        FlagsField("session_status", 0, 8, ["CAL", "DAQ", "RESUME", "RES0",
                                            "RES1", "RES2", "STORE", "RUN"]),
        StrFixedLenField('ccp_reserved', b'\xff' * 5, length=5)
    ]


bind_layers(CRO, SET_S_STATUS, cmd=0x0C)


class GET_S_STATUS(Packet):
    fields_desc = [
        StrFixedLenField('ccp_reserved', b'\xff' * 6, length=6)
    ]


bind_layers(CRO, GET_S_STATUS, cmd=0x0D)


class BUILD_CHKSUM(Packet):
    fields_desc = [
        IntField('size', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 2, length=2)
    ]


bind_layers(CRO, BUILD_CHKSUM, cmd=0x0E)


class CLEAR_MEMORY(Packet):
    fields_desc = [
        IntField('size', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 2, length=2)
    ]


bind_layers(CRO, CLEAR_MEMORY, cmd=0x10)


class PROGRAM(Packet):
    fields_desc = [
        XByteField('size', 0),
        StrFixedLenField('data', b'\x00' * 0,
                         length_from=lambda pkt: pkt.size),
        StrFixedLenField('ccp_reserved', b'\xff' * 5,
                         length_from=lambda pkt: 5 - pkt.size)
    ]


bind_layers(CRO, PROGRAM, cmd=0x18)


class PROGRAM_6(Packet):
    fields_desc = [
        StrFixedLenField('data', b'\x00' * 6, length=6)
    ]


bind_layers(CRO, PROGRAM_6, cmd=0x22)


class MOVE(Packet):
    fields_desc = [
        IntField('size', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 2, length=2)
    ]


bind_layers(CRO, MOVE, cmd=0x19)


class TEST(Packet):
    fields_desc = [
        LEShortField('station_address', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 4, length=4)
    ]


bind_layers(CRO, TEST, cmd=0x05)


class GET_ACTIVE_CAL_PAGE(Packet):
    fields_desc = [
        StrFixedLenField('ccp_reserved', b'\xff' * 6, length=6)
    ]


bind_layers(CRO, GET_ACTIVE_CAL_PAGE, cmd=0x09)


class START_STOP_ALL(Packet):
    fields_desc = [
        ByteEnumField('type', 0, {0: "stop", 1: "start"}),
        StrFixedLenField('ccp_reserved', b'\xff' * 5, length=5)

    ]


bind_layers(CRO, START_STOP_ALL, cmd=0x08)


class DIAG_SERVICE(Packet):
    fields_desc = [
        ShortField('diag_service', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 4, length=4)
    ]


bind_layers(CRO, DIAG_SERVICE, cmd=0x20)


class ACTION_SERVICE(Packet):
    fields_desc = [
        ShortField('action_service', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 4, length=4)
    ]


bind_layers(CRO, ACTION_SERVICE, cmd=0x21)


# ##### DTOs ######

class DEFAULT_DTO(Packet):
    fields_desc = [
        StrFixedLenField('load', b'\xff' * 5, length=5),
    ]


class GET_CCP_VERSION_DTO(Packet):
    fields_desc = [
        XByteField('main_protocol_version', 0),
        XByteField('release_version', 0),
        StrFixedLenField('ccp_reserved', b'\x00' * 3, length=3)
    ]


class EXCHANGE_ID_DTO(Packet):
    fields_desc = [
        ByteField('slave_device_ID_length', 0),
        ByteField('data_type_qualifier', 0),
        ByteField('resource_availability_mask', 0),
        ByteField('resource_protection_mask', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 1, length=1),
    ]


class GET_SEED_DTO(Packet):
    fields_desc = [
        XByteField('protection_status', 0),
        StrFixedLenField('seed', b'\x00' * 4, length=4)
    ]


class UNLOCK_DTO(Packet):
    fields_desc = [
        ByteField('privilege_status', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 4, length=4),
    ]


class DNLOAD_DTO(Packet):
    fields_desc = [
        XByteField('MTA0_extension', 0),
        XIntField('MTA0_address', 0)
    ]


class DNLOAD_6_DTO(Packet):
    fields_desc = [
        XByteField('MTA0_extension', 0),
        XIntField('MTA0_address', 0)
    ]


class UPLOAD_DTO(Packet):
    fields_desc = [
        StrFixedLenField('data', b'\x00' * 5, length=5)
    ]


class SHORT_UP_DTO(Packet):
    fields_desc = [
        StrFixedLenField('data', b'\x00' * 5, length=5)
    ]


class GET_DAQ_SIZE_DTO(Packet):
    fields_desc = [
        XByteField('DAQ_list_size', 0),
        XByteField('first_pid', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 3, length=3)
    ]


class GET_S_STATUS_DTO(Packet):
    fields_desc = [
        FlagsField("session_status", 0, 8, ["CAL", "DAQ", "RESUME", "RES0",
                                            "RES1", "RES2", "STORE", "RUN"]),
        ByteField('information_qualifier', 0),
        StrFixedLenField('information', b'\x00' * 3, length=3)
    ]


class BUILD_CHKSUM_DTO(Packet):
    fields_desc = [
        ByteField('checksum_size', 0),
        StrFixedLenField('checksum_data', b'\x00' * 4,
                         length_from=lambda pkt: pkt.checksum_size),
        StrFixedLenField('ccp_reserved', b'\xff' * 0,
                         length_from=lambda pkt: 4 - pkt.checksum_size)
    ]


class PROGRAM_DTO(Packet):
    fields_desc = [
        ByteField('MTA0_extension', 0),
        XIntField('MTA0_address', 0)
    ]


class PROGRAM_6_DTO(Packet):
    fields_desc = [
        ByteField('MTA0_extension', 0),
        XIntField('MTA0_address', 0)
    ]


class GET_ACTIVE_CAL_PAGE_DTO(Packet):
    fields_desc = [
        XByteField('address_extension', 0),
        XIntField('address', 0)
    ]


class DIAG_SERVICE_DTO(Packet):
    fields_desc = [
        ByteField('data_length', 0),
        ByteField('data_type', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 3, length=3)
    ]


class ACTION_SERVICE_DTO(Packet):
    fields_desc = [
        ByteField('data_length', 0),
        ByteField('data_type', 0),
        StrFixedLenField('ccp_reserved', b'\xff' * 3, length=3)
    ]


class DTO(Packet):
    __slots__ = Packet.__slots__ + ["payload_cls"]

    return_codes = {
        0x00: "acknowledge / no error",
        0x01: "DAQ processor overload",
        0x10: "command processor busy",
        0x11: "DAQ processor busy",
        0x12: "internal timeout",
        0x18: "key request",
        0x19: "session status request",
        0x20: "cold start request",
        0x21: "cal. data init. request",
        0x22: "DAQ list init. request",
        0x23: "code update request",
        0x30: "unknown command",
        0x31: "command syntax",
        0x32: "parameter(s) out of range",
        0x33: "access denied",
        0x34: "overload",
        0x35: "access locked",
        0x36: "resource/function not available"
    }
    fields_desc = [
        XByteField("packet_id", 0xff),
        ByteEnumField('return_code', 0x00, return_codes),
        ByteField('ctr', 0)
    ]

    def __init__(self, *args, **kwargs):
        self.payload_cls = DEFAULT_DTO
        if "payload_cls" in kwargs:
            self.payload_cls = kwargs["payload_cls"]
            del kwargs["payload_cls"]
        Packet.__init__(self, *args, **kwargs)

    def guess_payload_class(self, payload):
        return self.payload_cls

    @staticmethod
    def get_dto_cls(cmd):
        try:
            return {
                0x03: DNLOAD_DTO,
                0x04: UPLOAD_DTO,
                0x09: GET_ACTIVE_CAL_PAGE_DTO,
                0x0D: GET_S_STATUS_DTO,
                0x0E: BUILD_CHKSUM_DTO,
                0x0F: SHORT_UP_DTO,
                0x12: GET_SEED_DTO,
                0x13: UNLOCK_DTO,
                0x14: GET_DAQ_SIZE_DTO,
                0x17: EXCHANGE_ID_DTO,
                0x18: PROGRAM_DTO,
                0x1B: GET_CCP_VERSION_DTO,
                0x20: DIAG_SERVICE_DTO,
                0x21: ACTION_SERVICE_DTO,
                0x22: PROGRAM_6_DTO,
                0x23: DNLOAD_6_DTO
            }[cmd]
        except KeyError:
            return DEFAULT_DTO

    def answers(self, other):
        """In CCP, the payload of a DTO packet is dependent on the cmd field
        of a corresponding CRO packet. Two packets correspond, if there
        ctr field is equal. If answers detect the corresponding CRO, it will
        interpret the payload of a DTO with the correct class. In CCP, there is
        no other way, to determine the class of a DTO payload. Since answers is
        called on sr and sr1, this modification of the original answers
        implementation will give a better user experience. """
        if not hasattr(other, "ctr"):
            return 0
        if self.ctr != other.ctr:
            return 0
        if not hasattr(other, "cmd"):
            return 0

        new_pl_cls = self.get_dto_cls(other.cmd)
        if self.payload_cls != new_pl_cls and \
                self.payload_cls == DEFAULT_DTO:
            data = bytes(self.load)
            self.remove_payload()
            self.add_payload(new_pl_cls(data))
            self.payload_cls = new_pl_cls
        return 1

    def hashret(self):
        return struct.pack('B', self.ctr)


bind_bottom_up(CCP, DTO)
