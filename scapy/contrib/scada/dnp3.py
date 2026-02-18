"""
DNP3 (Distributed Network Protocol 3).

Original code by: Copyright 2014-2016 N.R Rodofile

Licensed under the GPLv3.
This program is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details. You should have received a copy of
the GNU General Public License along with this program. If not, see
http://www.gnu.org/licenses/.

"""

import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    XShortField,
    LEShortField,
    BitField,
    BitEnumField,
    PacketField,
    ConditionalField,
    ByteField,
)
from scapy.layers.inet import TCP, UDP

bitState = {1: "SET", 0: "UNSET"}
stations = {1: "MASTER", 0: "OUTSTATION"}

MASTER = 1
OUTSTATION = 0
SET = 1
UNSET = 0
DNP3_PORT = 20000

TRANSPORT_SUMMARY = "Seq:%DNP3Transport.SEQUENCE% "
APPLICATION_RSP_SUMMARY = "Response %DNP3ApplicationResponse.FUNC_CODE% "
APPLICATION_REQ_SUMMARY = "Request %DNP3ApplicationRequest.FUNC_CODE% "
DNP3_SUMMARY = "From %DNP3.SOURCE% to %DNP3.DESTINATION% "


def crc16_dnp3(data):
    """DNP3 CRC-16 calculation"""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return crc


def CRC_check(chunk, crc):
    chunk_crc = crc16_dnp3(chunk)
    crc = struct.unpack("<H", crc)[0]
    if crc == chunk_crc:
        return True, crc

    return False, crc


def update_data_chunk_crc(chunk):
    crc = crc16_dnp3(chunk[:-2])
    chunk = chunk[:-2] + struct.pack("<H", crc)
    return chunk


def add_CRC_payload(payload):
    if len(payload) > 18:
        chunk = payload[:18]
        chunk = update_data_chunk_crc(chunk)
        payload = chunk + payload[18:]
    else:
        chunk = payload[:-2]
        chunk = update_data_chunk_crc(chunk)
        payload = chunk

    return payload


applicationFunctionCode = {
    0: "CONFIRM",
    1: "READ",
    2: "WRITE",
    3: "SELECT",
    4: "OPERATE",
    5: "DIRECT_OPERATE",
    6: "DIRECT_OPERATE_NR",
    7: "IMMED_FREEZE",
    8: "IMMED_FREEZE_NR",
    9: "FREEZE_CLEAR",
    10: "FREEZE_CLEAR_NR",
    11: "FREEZE_AT_TIME",
    12: "FREEZE_AT_TIME_NR",
    13: "COLD_RESTART",
    14: "WARM_RESTART",
    15: "INITIALIZE_DATA",
    16: "INITIALIZE_APPL",
    17: "START_APPL",
    18: "STOP_APPL",
    19: "SAVE_CONFIG",
    20: "ENABLE_UNSOLICITED",
    21: "DISABLE_UNSOLICITED",
    22: "ASSIGN_CLASS",
    23: "DELAY_MEASURE",
    24: "RECORD_CURRENT_TIME",
    25: "OPEN_FILE",
    26: "CLOSE_FILE",
    27: "DELETE_FILE",
    28: "GET_FILE_INFO",
    29: "AUTHENTICATE_FILE",
    30: "ABORT_FILE",
    31: "ACTIVATE_CONFIG",
    32: "AUTHENTICATE_REQ",
    33: "AUTH_REQ_NO_ACK",
    129: "RESPONSE",
    130: "UNSOLICITED_RESPONSE",
    131: "AUTHENTICATE_RESP",
}


class DNP3RequestDataObjects(Packet):
    fields_desc = [
        BitField("Obj", 1, 4),
        BitField("Var", 1, 4),
        BitField("IndexPref", 1, 4),
        BitEnumField("QualfierCode", 1, 4, bitState),
    ]

    def extract_padding(self, s):
        return b"", s


class DNP3Application(Packet):
    def guess_payload_class(self, payload):
        return Packet.guess_payload_class(self, payload)


class DNP3ApplicationControl(Packet):
    fields_desc = [
        BitEnumField("FIN", 1, 1, bitState),
        BitEnumField("FIR", 1, 1, bitState),
        BitEnumField("CON", 1, 1, bitState),
        BitEnumField("UNS", 1, 1, bitState),
        BitField("SEQ", 1, 4),
    ]

    def extract_padding(self, s):
        return b"", s


class DNP3ApplicationIIN(Packet):
    name = "DNP3_Application_response"
    fields_desc = [
        BitEnumField("DEVICE_RESTART", UNSET, 1, bitState),
        BitEnumField("DEVICE_TROUBLE", UNSET, 1, bitState),
        BitEnumField("LOCAL_CONTROL", UNSET, 1, bitState),
        BitEnumField("NEED_TIME", UNSET, 1, bitState),
        BitEnumField("CLASS_3_EVENTS", UNSET, 1, bitState),
        BitEnumField("CLASS_2_EVENTS", UNSET, 1, bitState),
        BitEnumField("CLASS_1_EVENTS", UNSET, 1, bitState),
        BitEnumField("BROADCAST", UNSET, 1, bitState),
        BitEnumField("RESERVED_1", UNSET, 1, bitState),
        BitEnumField("RESERVED_2", UNSET, 1, bitState),
        BitEnumField("CONFIG_CORRUPT", UNSET, 1, bitState),
        BitEnumField("ALREADY_EXECUTING", UNSET, 1, bitState),
        BitEnumField("EVENT_BUFFER_OVERFLOW", UNSET, 1, bitState),
        BitEnumField("PARAMETER_ERROR", UNSET, 1, bitState),
        BitEnumField("OBJECT_UNKNOWN", UNSET, 1, bitState),
        BitEnumField("NO_FUNC_CODE_SUPPORT", UNSET, 1, bitState),
    ]

    def extract_padding(self, s):
        return b"", s


class DNP3ApplicationResponse(DNP3Application):
    name = "DNP3_Application_response"
    fields_desc = [
        PacketField(
            "Application_control", DNP3ApplicationControl(), DNP3ApplicationControl
        ),
        BitEnumField("FUNC_CODE", 1, 8, applicationFunctionCode),
        PacketField("IIN", DNP3ApplicationIIN(), DNP3ApplicationIIN),
    ]

    def mysummary(self):
        if self.underlayer is not None and isinstance(self.underlayer.underlayer, DNP3):
            print(self.FUNC_CODE.SEQ, "Hello")
            return self.underlayer.underlayer.sprintf(
                DNP3_SUMMARY + TRANSPORT_SUMMARY + APPLICATION_RSP_SUMMARY
            )
        if isinstance(self.underlayer, DNP3Transport):
            return self.underlayer.sprintf(TRANSPORT_SUMMARY + APPLICATION_RSP_SUMMARY)
        else:
            return self.sprintf(APPLICATION_REQ_SUMMARY)


class DNP3ApplicationRequest(DNP3Application):
    name = "DNP3_Application_request"
    fields_desc = [
        PacketField(
            "Application_control", DNP3ApplicationControl(), DNP3ApplicationControl
        ),
        BitEnumField("FUNC_CODE", 1, 8, applicationFunctionCode),
    ]

    def mysummary(self):
        if self.underlayer is not None and isinstance(self.underlayer.underlayer, DNP3):
            return self.underlayer.underlayer.sprintf(
                DNP3_SUMMARY + TRANSPORT_SUMMARY + APPLICATION_REQ_SUMMARY
            )
        if isinstance(self.underlayer, DNP3Transport):
            return self.underlayer.sprintf(TRANSPORT_SUMMARY + APPLICATION_REQ_SUMMARY)
        else:
            return self.sprintf(APPLICATION_REQ_SUMMARY)


class DNP3Transport(Packet):
    name = "DNP3_Transport"
    fields_desc = [
        BitEnumField("FIN", None, 1, bitState),
        BitEnumField("FIR", None, 1, bitState),
        BitField("SEQUENCE", None, 6),
    ]

    def guess_payload_class(self, payload):
        if isinstance(self.underlayer, DNP3):
            DIR = self.underlayer.CONTROL.DIR

            if DIR == MASTER:
                return DNP3ApplicationRequest

            if DIR == OUTSTATION:
                return DNP3ApplicationResponse

        return Packet.guess_payload_class(self, payload)


class DNP3HeaderControl(Packet):
    name = "DNP3_Header_control"

    controlFunctionCodePri = {
        0: "RESET_LINK_STATES",
        2: "TEST_LINK_STATES",
        3: "CONFIRMED_USER_DATA",
        4: "UNCONFIRMED_USER_DATA",
        9: "REQUEST_LINK_STATUS",
    }

    controlFunctionCodeSec = {
        0: "ACK",
        1: "NACK",
        11: "LINK_STATUS",
        15: "NOT_SUPPORTED",
    }

    cond_field = [
        BitEnumField("FCB", 0, 1, bitState),
        BitEnumField("FCV", 0, 1, bitState),
        BitEnumField("FUNC_CODE_PRI", 4, 4, controlFunctionCodePri),
        BitEnumField("reserved", 0, 1, bitState),
        BitEnumField("DFC", 0, 1, bitState),
        BitEnumField("FUNC_CODE_SEC", 4, 4, controlFunctionCodeSec),
    ]

    fields_desc = [
        BitEnumField("DIR", MASTER, 1, stations),  # 9.2.4.1.3.1 DIR bit field
        BitEnumField("PRM", MASTER, 1, stations),  # 9.2.4.1.3.2 PRM bit field
        ConditionalField(cond_field[0], lambda x: x.PRM == MASTER),
        ConditionalField(cond_field[1], lambda x: x.PRM == MASTER),
        ConditionalField(cond_field[2], lambda x: x.PRM == MASTER),
        ConditionalField(cond_field[3], lambda x: x.PRM == OUTSTATION),
        ConditionalField(cond_field[4], lambda x: x.PRM == OUTSTATION),
        ConditionalField(cond_field[5], lambda x: x.PRM == OUTSTATION),
    ]

    def extract_padding(self, s):
        return b"", s


class DNP3(Packet):
    name = "DNP3"
    fields_desc = [
        XShortField("START", 0x0564),
        ByteField("LENGTH", None),
        PacketField("CONTROL", None, DNP3HeaderControl),
        LEShortField("DESTINATION", None),
        LEShortField("SOURCE", None),
        XShortField("CRC", None),
    ]

    data_chunks = []  # Data Chunks are 16 octets
    data_chunks_crc = []
    chunk_len = 18
    data_chunk_len = 16

    # def show_data_chunks(self):
    #     for i, data_chunk in enumerate(self.data_chunks):
    #         print(
    #             f"\tData Chunk {i}, Len {len(data_chunk)}, " "CRC (",
    #             hex(struct.unpack("<H", self.data_chunks_crc[i])[0]),
    #             ")",
    #         )

    def add_data_chunk(self, chunk):
        chunk = update_data_chunk_crc(chunk)
        self.data_chunks.append(chunk[:-2])
        self.data_chunks_crc.append(chunk[-2:])

    def post_build(self, pkt, pay):
        cnk_len = self.chunk_len
        pay_len = len(pay)
        # pkt_len = len(pkt)
        # total = pkt_len + pay_len
        chunks = int(pay_len / cnk_len)  # chunk size
        # chunks = total / cnk_len  # chunk size
        last_chunk = pay_len % cnk_len

        if last_chunk > 0:
            chunks += 1

        if pay_len == 3 and self.CONTROL.DIR == MASTER:
            # No IIN in Application layer and empty Payload
            pay = pay + struct.pack("H", crc16_dnp3(pay))

        if pay_len == 5 and self.CONTROL.DIR == OUTSTATION:
            # IIN in Application layer and empty Payload
            pay = pay + struct.pack("H", crc16_dnp3(pay))

        if self.LENGTH is None:
            # Remove length , crc, start octets as part of length
            length = len(pkt + pay) - ((chunks * 2) + 1 + 2 + 2)
            pkt = pkt[:2] + struct.pack("<B", length) + pkt[3:]

        CRC = crc16_dnp3(pkt[:8])  # use only the first 8 octets

        if self.CRC is None:
            pkt = pkt[:-2] + struct.pack("H", CRC)

        else:
            if CRC != self.CRC:
                pkt = pkt[:-2] + struct.pack("H", CRC)

        self.data_chunks = []
        self.data_chunks_crc = []

        remaining_pay = pay_len
        for c in range(chunks):
            index = c * cnk_len  # data chunk

            if (remaining_pay < cnk_len) and (remaining_pay > 0):
                self.add_data_chunk(pay[index:])
                break  # should be the last chunk
            else:
                self.add_data_chunk(pay[index : index + cnk_len])
                remaining_pay -= cnk_len

        payload = b""
        for chunk, data_chunk in enumerate(self.data_chunks):
            payload = payload + data_chunk + self.data_chunks_crc[chunk]

        #  self.show_data_chunks()  # --DEBUGGING

        return pkt + payload

    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return DNP3Transport
        else:
            return Packet.guess_payload_class(self, payload)


bind_layers(TCP, DNP3, dport=DNP3_PORT)
bind_layers(TCP, DNP3, sport=DNP3_PORT)
bind_layers(UDP, DNP3, dport=DNP3_PORT)
bind_layers(UDP, DNP3, sport=DNP3_PORT)
