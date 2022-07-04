# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Tabea Spahn <tabea.spahn@e-mundo.de>

# scapy.contrib.description = Universal calibration and measurement protocol (XCP) # noqa: E501
# scapy.contrib.status = loads
import struct

from scapy.config import conf
from scapy.contrib.automotive.xcp.cto_commands_master import Connect, \
    Disconnect, GetStatus, Synch, GetCommModeInfo, GetId, SetRequest, \
    GetSeed, Unlock, SetMta, Upload, ShortUpload, BuildChecksum, \
    TransportLayerCmd, TransportLayerCmdGetSlaveId, \
    TransportLayerCmdGetDAQId, TransportLayerCmdSetDAQId, UserCmd, Download, \
    DownloadNext, DownloadMax, ShortDownload, ModifyBits, SetCalPage, \
    GetCalPage, GetPagProcessorInfo, GetSegmentInfo, GetPageInfo, \
    SetSegmentMode, GetSegmentMode, CopyCalPage, SetDaqPtr, WriteDaq, \
    SetDaqListMode, GetDaqListMode, StartStopDaqList, StartStopSynch, \
    ReadDaq, GetDaqClock, GetDaqProcessorInfo, GetDaqResolutionInfo, \
    GetDaqListInfo, GetDaqEventInfo, ClearDaqList, FreeDaq, AllocDaq, \
    AllocOdt, AllocOdtEntry, ProgramStart, ProgramClear, Program, \
    ProgramReset, GetPgmProcessorInfo, GetSectorInfo, ProgramPrepare, \
    ProgramFormat, ProgramNext, ProgramMax, ProgramVerify
from scapy.contrib.automotive.xcp.cto_commands_slave import \
    GenericResponse, NegativeResponse, EvPacket, ServPacket, \
    TransportLayerCmdGetSlaveIdResponse, TransportLayerCmdGetDAQIdResponse, \
    SegmentInfoMode0PositiveResponse, SegmentInfoMode1PositiveResponse, \
    SegmentInfoMode2PositiveResponse, ConnectPositiveResponse, \
    StatusPositiveResponse, CommonModeInfoPositiveResponse, \
    IdPositiveResponse, SeedPositiveResponse, UnlockPositiveResponse, \
    UploadPositiveResponse, ShortUploadPositiveResponse, \
    ChecksumPositiveResponse, CalPagePositiveResponse, \
    PagProcessorInfoPositiveResponse, PageInfoPositiveResponse, \
    SegmentModePositiveResponse, DAQListModePositiveResponse, \
    StartStopDAQListPositiveResponse, DAQClockListPositiveResponse, \
    ReadDAQPositiveResponse, DAQProcessorInfoPositiveResponse, \
    DAQResolutionInfoPositiveResponse, DAQListInfoPositiveResponse, \
    DAQEventInfoPositiveResponse, ProgramStartPositiveResponse, \
    PgmProcessorPositiveResponse, SectorInfoPositiveResponse
from scapy.contrib.automotive.xcp.utils import get_timestamp_length, \
    identification_field_needs_alignment, get_daq_length, \
    get_daq_data_field_length
from scapy.fields import ByteEnumField, ShortField, XBitField, \
    FlagsField, ByteField, ThreeBytesField, StrField, ConditionalField, \
    XByteField, StrLenField
from scapy.layers.can import CAN
from scapy.layers.inet import UDP, TCP
from scapy.packet import Packet, bind_layers, bind_bottom_up, bind_top_down

conf.contribs.setdefault("XCP", {})

# 0 stands for Intel/little-endian format, 1 for Motorola/big-endian format
conf.contribs["XCP"].setdefault("byte_order", 1)
conf.contribs["XCP"].setdefault("allow_byte_order_change", True)
# Can be 1, 2 or 4
conf.contribs["XCP"].setdefault("Address_Granularity_Byte", None)
conf.contribs["XCP"].setdefault("allow_ag_change", True)

conf.contribs["XCP"].setdefault("MAX_CTO", None)
conf.contribs["XCP"].setdefault("MAX_DTO", None)
conf.contribs["XCP"].setdefault("allow_cto_and_dto_change", True)
conf.contribs["XCP"].setdefault("add_padding_for_can", False)

conf.contribs['XCP'].setdefault('timestamp_size', 0)


# Specifications from:
# http://read.pudn.com/downloads293/doc/comm/1316424/ASAM_XCP_Part1-Overview_V1.0.0.pdf # noqa: E501
# http://read.pudn.com/downloads192/doc/comm/903802/XCP%20-Part%202-%20Protocol%20Layer%20Specification%20-1.0.pdf # noqa: E501
# http://read.pudn.com/downloads192/doc/comm/903802/XCP%20-Part%203-%20Transport_layer_specification_xcp_on_can_1-0.pdf # noqa: E501
# http://read.pudn.com/downloads192/doc/comm/903802/XCP%20-Part%204-%20Interface%20Specification%20-1.0.pdf # noqa: E501
# http://read.pudn.com/downloads192/doc/comm/903802/XCP%20-Part%205-%20Example%20Communication%20Sequences%20-1.0.pdf # noqa: E501

# XCP on USB is left out because it has "no practical meaning"
# XCP on Lin is left out because it has no official specification
class XCPOnCAN(CAN):
    name = "Universal calibration and measurement protocol on CAN"
    fields_desc = [
        FlagsField("flags", 0, 3, ["error",
                                   "remote_transmission_request",
                                   "extended"]),
        XBitField("identifier", 0, 29),
        ByteField("length", None),
        ThreeBytesField("reserved", 0),
    ]

    def post_build(self, pkt, pay):
        if self.length is None or \
                (len(pay) < 8 and conf.contribs["XCP"]["add_padding_for_can"]):
            tmp_len = 8 if conf.contribs["XCP"]["add_padding_for_can"] else \
                len(pay)
            pkt = pkt[:4] + struct.pack("B", tmp_len) + pkt[5:]
            pay += b"\xCC" * (tmp_len - len(pay))
        return super(XCPOnCAN, self).post_build(pkt, pay)

    def extract_padding(self, p):
        return p[:self.length], None


class XCPOnUDP(UDP):
    name = "Universal calibration and measurement protocol on Ethernet"
    fields_desc = UDP.fields_desc + [
        ShortField("length", None),
        ShortField("ctr", 0),  # counter
    ]

    def post_build(self, pkt, pay):
        if self.length is None:
            tmp_len = len(pay)
            pkt = pkt[:8] + struct.pack("!H", tmp_len) + pkt[10:]
        return super(XCPOnUDP, self).post_build(pkt, pay)


class XCPOnTCP(TCP):
    name = "Universal calibration and measurement protocol on Ethernet"

    fields_desc = TCP.fields_desc + [
        ShortField("length", None),
        ShortField("ctr", 0),  # counter
    ]

    def answers(self, other):
        if not isinstance(other, XCPOnTCP):
            return 0
        if isinstance(other.payload, CTORequest) and isinstance(self.payload,
                                                                CTOResponse):
            return self.payload.answers(other.payload)

    def post_build(self, pkt, pay):
        if self.length is None:
            len_offset = 20 + len(self.options)
            tmp_len = len(pay)
            tmp_len = struct.pack("!H", tmp_len)
            pkt = pkt[:len_offset] + tmp_len + pkt[len_offset + 2:]
        return super(XCPOnTCP, self).post_build(pkt, pay)


class XCPOnCANTail(Packet):
    name = "XCP Tail on CAN"

    fields_desc = [
        StrField("control_field", "")
    ]


class CTORequest(Packet):
    pids = {
        # Standard commands
        0xFF: "CONNECT",
        0xFE: "DISCONNECT",
        0xFD: "GET_STATUS",
        0xFC: "SYNCH",
        0xFB: "GET_COMM_MODE_INFO",
        0xFA: "GET_ID",
        0xF9: "SET_REQUEST",
        0xF8: "GET_SEED",
        0xF7: "UNLOCK",
        0xF6: "SET_MTA",
        0xF5: "UPLOAD",
        0xF4: "SHORT_UPLOAD",
        0xF3: "BUILD_CHECKSUM",
        0xF2: "TRANSPORT_LAYER_CMD",
        0xF1: "USER_CMD",
        # Calibration commands
        0xF0: "DOWNLOAD",
        0xEF: "DOWNLOAD_NEXT",
        0xEE: "DOWNLOAD_MAX",
        0xED: "SHORT_DOWNLOAD",
        0xEC: "MODIFY_BITS",
        # Page change commands
        0xEB: "SET_CAL_PAGE",
        0xEA: "GET_CAL_PAGE",
        0xE9: "GET_PAG_PROCESSOR_INFO",
        0xE8: "GET_SEGMENT_INFO",
        0xE7: "GET_PAGE_INFO",
        0xE6: "SET_SEGMENT_MODE",
        0xE5: "GET_SEGMENT_MODE",
        0xE4: "COPY_CAL_PAGE",
        # Periodic data exchange basics
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
        # Periodic data exchange static configuration
        0xE3: "CLEAR_DAQ_LIST",
        # Cyclic data exchange dynamic configuration
        0xD6: "FREE_DAQ",
        0xD5: "ALLOC_DAQ",
        0xD4: "ALLOC_ODT",
        0xD3: "ALLOC_ODT_ENTRY",
        # Flash programming
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

    for pid in range(0, 192):
        pids[pid] = "STIM"
    name = "Command Transfer Object Request"

    fields_desc = [
        ByteEnumField("pid", 0xFF, pids),
    ]


# ##### CTO COMMANDS ######

# STANDARD COMMANDS
bind_layers(CTORequest, Connect, pid=0xFF)
bind_layers(CTORequest, Disconnect, pid=0xFE)
bind_layers(CTORequest, GetStatus, pid=0xFD)
bind_layers(CTORequest, Synch, pid=0xFC)
bind_layers(CTORequest, GetCommModeInfo, pid=0xFB)
bind_layers(CTORequest, GetId, pid=0xFA)
bind_layers(CTORequest, SetRequest, pid=0xF9)
bind_layers(CTORequest, GetSeed, pid=0xF8)
bind_layers(CTORequest, Unlock, pid=0xF7)
bind_layers(CTORequest, SetMta, pid=0xF6)
bind_layers(CTORequest, Upload, pid=0xF5)
bind_layers(CTORequest, ShortUpload, pid=0xF4)
bind_layers(CTORequest, BuildChecksum, pid=0xF3)
bind_layers(CTORequest, TransportLayerCmd, pid=0xF2)
bind_layers(CTORequest, TransportLayerCmdGetSlaveId, pid=0xF2,
            sub_command_code=0xFF)
bind_layers(CTORequest, TransportLayerCmdGetDAQId, pid=0xF2,
            sub_command_code=0xFE)
bind_layers(CTORequest, TransportLayerCmdSetDAQId, pid=0xF2,
            sub_command_code=0xFD)
bind_layers(CTORequest, UserCmd, pid=0xF1)

# Calibration Commands
bind_layers(CTORequest, Download, pid=0xF0)
bind_layers(CTORequest, DownloadNext, pid=0xEF)
bind_layers(CTORequest, DownloadMax, pid=0xEE)
bind_layers(CTORequest, ShortDownload, pid=0xED)
bind_layers(CTORequest, ModifyBits, pid=0xEC)

# Page Switching commands
bind_layers(CTORequest, SetCalPage, pid=0xEB)
bind_layers(CTORequest, GetCalPage, pid=0xEA)
bind_layers(CTORequest, GetPagProcessorInfo, pid=0xE9)
bind_layers(CTORequest, GetSegmentInfo, pid=0xE8)
bind_layers(CTORequest, GetPageInfo, pid=0xE7)
bind_layers(CTORequest, SetSegmentMode, pid=0xE6)
bind_layers(CTORequest, GetSegmentMode, pid=0xE5)
bind_layers(CTORequest, CopyCalPage, pid=0xE4)

# Cyclic Data exchange Basic commands
bind_layers(CTORequest, SetDaqPtr, pid=0xE2)
bind_layers(CTORequest, WriteDaq, pid=0xE1)
bind_layers(CTORequest, SetDaqListMode, pid=0xE0)
bind_layers(CTORequest, GetDaqListMode, pid=0xDF)
bind_layers(CTORequest, StartStopDaqList, pid=0xDE)
bind_layers(CTORequest, StartStopSynch, pid=0xDD)
bind_layers(CTORequest, ReadDaq, pid=0xDB)
bind_layers(CTORequest, GetDaqClock, pid=0xDC)
bind_layers(CTORequest, GetDaqProcessorInfo, pid=0xDA)
bind_layers(CTORequest, GetDaqResolutionInfo, pid=0xD9)
bind_layers(CTORequest, GetDaqListInfo, pid=0xD8)
bind_layers(CTORequest, GetDaqEventInfo, pid=0xD7)

# Cyclic data transfer - static configuration commands
bind_layers(CTORequest, ClearDaqList, pid=0xE3)

# Cyclic Data transfer - dynamic configuration commands
bind_layers(CTORequest, FreeDaq, pid=0xD6)
bind_layers(CTORequest, AllocDaq, pid=0xD5)
bind_layers(CTORequest, AllocOdt, pid=0xD4)
bind_layers(CTORequest, AllocOdtEntry, pid=0xD3)

# Flash Programming commands
bind_layers(CTORequest, ProgramStart, pid=0xD2)
bind_layers(CTORequest, ProgramClear, pid=0xD1)
bind_layers(CTORequest, Program, pid=0xD0)
bind_layers(CTORequest, ProgramReset, pid=0xCF)
bind_layers(CTORequest, GetPgmProcessorInfo, pid=0xCE)
bind_layers(CTORequest, GetSectorInfo, pid=0xCD)
bind_layers(CTORequest, ProgramPrepare, pid=0xCC)
bind_layers(CTORequest, ProgramFormat, pid=0xCB)
bind_layers(CTORequest, ProgramNext, pid=0xCA)
bind_layers(CTORequest, ProgramMax, pid=0xC9)
bind_layers(CTORequest, ProgramVerify, pid=0xC8)


# ##### DTOs #####
# Master -> Slave:  STIM (Stimulation)
# Slave  -> Master: DAQ (Data AcQuisition)
class DTO(Packet):
    name = "Data transfer object"
    fields_desc = [
        ConditionalField(XByteField("fill", 0x00),
                         lambda _: identification_field_needs_alignment()),
        ConditionalField(
            StrLenField("daq", b"", length_from=lambda _: get_daq_length()),
            lambda _: get_daq_length() > 0),
        ConditionalField(
            StrLenField("timestamp", b"",
                        length_from=lambda _: get_timestamp_length()),
            lambda _: get_timestamp_length() > 0),
        ConditionalField(
            StrLenField("data", b"",
                        length_from=lambda _: get_daq_data_field_length()),
            lambda _: get_daq_data_field_length() > 0)
    ]


for pid in range(0, 0xBF + 1):
    bind_layers(CTORequest, DTO, pid=pid)


class CTOResponse(Packet):
    packet_codes = {
        0xFF: "RES",
        0xFE: "ERR",
        0xFD: "EV",
        0xFC: "SERV",
    }
    name = "Command Transfer Object Response"

    fields_desc = [
        ByteEnumField("packet_code", 0xFF, packet_codes),
    ]

    @staticmethod
    def get_positive_response_cls(request):
        # The pid of the request this packet is the response for
        request_pid = request.pid
        # First check the special cases with sub commands
        # They can't be fit in a simple dictionary,
        # so deal with them separately
        if request_pid == 0xF2:
            if request.sub_command_code == 255:
                return TransportLayerCmdGetSlaveIdResponse
            if request.sub_command_code == 254:
                return TransportLayerCmdGetDAQIdResponse
        if request_pid == 0xE8:
            if request.mode == "get_basic_address_info":
                return SegmentInfoMode0PositiveResponse
            if request.mode == "get_standard_info":
                return SegmentInfoMode1PositiveResponse
            if request.mode == "get_address_mapping_info":
                return SegmentInfoMode2PositiveResponse
        return {0xFF: ConnectPositiveResponse,
                0xFD: StatusPositiveResponse,
                0xFB: CommonModeInfoPositiveResponse,
                0xFA: IdPositiveResponse,
                0xF8: SeedPositiveResponse,
                0xF7: UnlockPositiveResponse,
                0xF5: UploadPositiveResponse,
                0xF4: ShortUploadPositiveResponse,
                0xF3: ChecksumPositiveResponse,
                0xEA: CalPagePositiveResponse,
                0xE9: PagProcessorInfoPositiveResponse,
                0xE7: PageInfoPositiveResponse,
                0xE5: SegmentModePositiveResponse,
                0xDF: DAQListModePositiveResponse,
                0xDE: StartStopDAQListPositiveResponse,
                0xDC: DAQClockListPositiveResponse,
                0xDB: ReadDAQPositiveResponse,
                0xDA: DAQProcessorInfoPositiveResponse,
                0xD9: DAQResolutionInfoPositiveResponse,
                0xD8: DAQListInfoPositiveResponse,
                0xD7: DAQEventInfoPositiveResponse,
                0xD2: ProgramStartPositiveResponse,
                0xCE: PgmProcessorPositiveResponse,
                0xCD: SectorInfoPositiveResponse,
                }.get(request_pid, GenericResponse)

    def answers(self, request):
        """In XCP, the payload of a response packet is dependent on the pid
        field of the corresponding request.
        This method changes the class of the payload to the class
        which is expected for the given request."""
        if not isinstance(request, CTORequest):
            return False

        # FE: Negative Response
        # FD: Event Packet
        # FC: Service Packet
        # They are always a valid response
        if self.packet_code in [0xFE, 0xFD, 0xFC]:
            return True
        # FF: Positive Response
        if self.packet_code != 0xFF:
            return False

        payload_cls = self.get_positive_response_cls(request)

        minimum_expected_byte_count = len(payload_cls())
        given_byte_count = len(self.payload)

        if given_byte_count < minimum_expected_byte_count:
            return False

        # Even if there are enough bytes, we can't be sure that they align
        # correctly to the fields. Then a struct.error exception is thrown.
        # For example
        # Fields: byte, byte, short
        # Packet: 01 02 03
        # This would fail because there are enough bytes that scapy starts
        # to parse the short field, but there are actually not enough bytes
        # to fill it.
        try:
            data = bytes(self.payload)
            self.remove_payload()
            self.add_payload(payload_cls(data))
        except struct.error:
            return False
        return True


for pid in range(0, 0xFB + 1):
    bind_layers(CTOResponse, DTO, pid=pid)

positive_response_classes = [ConnectPositiveResponse,
                             StatusPositiveResponse,
                             CommonModeInfoPositiveResponse,
                             IdPositiveResponse,
                             SeedPositiveResponse,
                             UnlockPositiveResponse,
                             UploadPositiveResponse,
                             ShortUploadPositiveResponse,
                             ChecksumPositiveResponse,
                             CalPagePositiveResponse,
                             PagProcessorInfoPositiveResponse,
                             PageInfoPositiveResponse,
                             SegmentModePositiveResponse,
                             DAQListModePositiveResponse,
                             StartStopDAQListPositiveResponse,
                             DAQClockListPositiveResponse,
                             ReadDAQPositiveResponse,
                             DAQProcessorInfoPositiveResponse,
                             DAQResolutionInfoPositiveResponse,
                             DAQListInfoPositiveResponse,
                             DAQEventInfoPositiveResponse,
                             ProgramStartPositiveResponse,
                             PgmProcessorPositiveResponse,
                             SectorInfoPositiveResponse]

for cls in positive_response_classes:
    bind_top_down(CTOResponse, cls, packet_code=0xFF)

bind_layers(CTOResponse, NegativeResponse, packet_code=0xFE)

# Asynchronous Event/request messages from the slave
bind_layers(CTOResponse, EvPacket, packet_code=0xFD)
bind_layers(CTOResponse, ServPacket, packet_code=0xFC)

bind_bottom_up(XCPOnCAN, CTOResponse)
bind_bottom_up(XCPOnUDP, CTOResponse)
bind_bottom_up(XCPOnTCP, CTOResponse)
