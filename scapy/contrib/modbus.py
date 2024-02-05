# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2017 Arthur Gervais
#                    Ken LE PRADO,
#                    Sebastien Mainand
#                    Thomas Aurel

# scapy.contrib.description = ModBus Protocol
# scapy.contrib.status = loads


import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import XByteField, XShortField, StrLenField, ByteEnumField, \
    BitFieldLenField, ByteField, ConditionalField, EnumField, FieldListField, \
    ShortField, StrFixedLenField, XShortEnumField
from scapy.layers.inet import TCP
from scapy.utils import orb
from scapy.config import conf
from scapy.volatile import VolatileValue


_modbus_exceptions = {1: "Illegal Function Code",
                      2: "Illegal Data Address",
                      3: "Illegal Data Value",
                      4: "Server Device Failure",
                      5: "Acknowledge",
                      6: "Server Device Busy",
                      8: "Memory Parity Error",
                      10: "Gateway Path Unavailable",
                      11: "Gateway Target Device Failed to Respond"}


class _ModbusPDUNoPayload(Packet):

    def extract_padding(self, s):
        return b"", None


class ModbusPDU01ReadCoilsRequest(_ModbusPDUNoPayload):
    name = "Read Coils Request"
    fields_desc = [XByteField("funcCode", 0x01),
                   XShortField("startAddr", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("quantity", 0x0001)]


class ModbusPDU01ReadCoilsResponse(_ModbusPDUNoPayload):
    name = "Read Coils Response"
    fields_desc = [XByteField("funcCode", 0x01),
                   BitFieldLenField("byteCount", None, 8,
                                    count_of="coilStatus"),
                   FieldListField("coilStatus", [0x00], ByteField("", 0x00),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU01ReadCoilsError(_ModbusPDUNoPayload):
    name = "Read Coils Exception"
    fields_desc = [XByteField("funcCode", 0x81),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU02ReadDiscreteInputsRequest(_ModbusPDUNoPayload):
    name = "Read Discrete Inputs"
    fields_desc = [XByteField("funcCode", 0x02),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantity", 0x0001)]


class ModbusPDU02ReadDiscreteInputsResponse(Packet):
    """ inputStatus: result is represented as bytes, padded with 0 to have a
        integer number of bytes. The field does not parse this result and
        present the bytes directly
    """
    name = "Read Discrete Inputs Response"
    fields_desc = [XByteField("funcCode", 0x02),
                   BitFieldLenField("byteCount", None, 8,
                                    count_of="inputStatus"),
                   FieldListField("inputStatus", [0x00], ByteField("", 0x00),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU02ReadDiscreteInputsError(Packet):
    name = "Read Discrete Inputs Exception"
    fields_desc = [XByteField("funcCode", 0x82),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU03ReadHoldingRegistersRequest(_ModbusPDUNoPayload):
    name = "Read Holding Registers"
    fields_desc = [XByteField("funcCode", 0x03),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantity", 0x0001)]


class ModbusPDU03ReadHoldingRegistersResponse(Packet):
    name = "Read Holding Registers Response"
    fields_desc = [XByteField("funcCode", 0x03),
                   BitFieldLenField("byteCount", None, 8,
                                    count_of="registerVal",
                                    adjust=lambda pkt, x: x * 2),
                   FieldListField("registerVal", [0x0000],
                                  ShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU03ReadHoldingRegistersError(Packet):
    name = "Read Holding Registers Exception"
    fields_desc = [XByteField("funcCode", 0x83),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU04ReadInputRegistersRequest(_ModbusPDUNoPayload):
    name = "Read Input Registers"
    fields_desc = [XByteField("funcCode", 0x04),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantity", 0x0001)]


class ModbusPDU04ReadInputRegistersResponse(Packet):
    name = "Read Input Registers Response"
    fields_desc = [XByteField("funcCode", 0x04),
                   BitFieldLenField("byteCount", None, 8,
                                    count_of="registerVal",
                                    adjust=lambda pkt, x: x * 2),
                   FieldListField("registerVal", [0x0000],
                                  ShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU04ReadInputRegistersError(Packet):
    name = "Read Input Registers Exception"
    fields_desc = [XByteField("funcCode", 0x84),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU05WriteSingleCoilRequest(Packet):
    name = "Write Single Coil"
    fields_desc = [XByteField("funcCode", 0x05),
                   # from 0x0000 to 0xFFFF
                   XShortField("outputAddr", 0x0000),
                   # 0x0000: Off, 0xFF00: On
                   XShortField("outputValue", 0x0000)]


class ModbusPDU05WriteSingleCoilResponse(Packet):
    # The answer is the same as the request if successful
    name = "Write Single Coil"
    fields_desc = [XByteField("funcCode", 0x05),
                   # from 0x0000 to 0xFFFF
                   XShortField("outputAddr", 0x0000),
                   # 0x0000 == Off, 0xFF00 == On
                   XShortField("outputValue", 0x0000)]


class ModbusPDU05WriteSingleCoilError(Packet):
    name = "Write Single Coil Exception"
    fields_desc = [XByteField("funcCode", 0x85),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU06WriteSingleRegisterRequest(_ModbusPDUNoPayload):
    name = "Write Single Register"
    fields_desc = [XByteField("funcCode", 0x06),
                   XShortField("registerAddr", 0x0000),
                   XShortField("registerValue", 0x0000)]


class ModbusPDU06WriteSingleRegisterResponse(Packet):
    name = "Write Single Register Response"
    fields_desc = [XByteField("funcCode", 0x06),
                   XShortField("registerAddr", 0x0000),
                   XShortField("registerValue", 0x0000)]


class ModbusPDU06WriteSingleRegisterError(Packet):
    name = "Write Single Register Exception"
    fields_desc = [XByteField("funcCode", 0x86),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU07ReadExceptionStatusRequest(_ModbusPDUNoPayload):
    name = "Read Exception Status"
    fields_desc = [XByteField("funcCode", 0x07)]


class ModbusPDU07ReadExceptionStatusResponse(Packet):
    name = "Read Exception Status Response"
    fields_desc = [XByteField("funcCode", 0x07),
                   XByteField("startAddr", 0x00)]


class ModbusPDU07ReadExceptionStatusError(Packet):
    name = "Read Exception Status Exception"
    fields_desc = [XByteField("funcCode", 0x87),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


_diagnostics_sub_function = {
    0x0000: "Return Query Data",
    0x0001: "Restart Communications Option",
    0x0002: "Return Diagnostic Register",
    0x0003: "Change ASCII Input Delimiter",
    0x0004: "Force Listen Only Mode",
    0x000A: "Clear Counters and Diagnostic Register",
    0x000B: "Return Bus Message Count",
    0x000C: "Return Bus Communication Error Count",
    0x000D: "Return Bus Exception Error Count",
    0x000E: "Return Slave Message Count",
    0x000F: "Return Slave No Response Count",
    0x0010: "Return Slave NAK Count",
    0x0011: "Return Slave Busy Count",
    0x0012: "Return Bus Character Overrun Count",
    0x0014: "Clear Overrun Counter and Flag"
}


class ModbusPDU08DiagnosticsRequest(_ModbusPDUNoPayload):
    name = "Diagnostics"
    fields_desc = [XByteField("funcCode", 0x08),
                   XShortEnumField("subFunc", 0x0000,
                                   _diagnostics_sub_function),
                   FieldListField("data", [0x0000], XShortField("", 0x0000))]


class ModbusPDU08DiagnosticsResponse(_ModbusPDUNoPayload):
    name = "Diagnostics Response"
    fields_desc = [XByteField("funcCode", 0x08),
                   XShortEnumField("subFunc", 0x0000,
                                   _diagnostics_sub_function),
                   FieldListField("data", [0x0000], XShortField("", 0x0000))]


class ModbusPDU08DiagnosticsError(_ModbusPDUNoPayload):
    name = "Diagnostics Exception"
    fields_desc = [XByteField("funcCode", 0x88),
                   ByteEnumField("exceptionCode", 1, _modbus_exceptions)]


class ModbusPDU0BGetCommEventCounterRequest(_ModbusPDUNoPayload):
    name = "Get Comm Event Counter"
    fields_desc = [XByteField("funcCode", 0x0B)]


class ModbusPDU0BGetCommEventCounterResponse(_ModbusPDUNoPayload):
    name = "Get Comm Event Counter Response"
    fields_desc = [XByteField("funcCode", 0x0B),
                   XShortField("status", 0x0000),
                   XShortField("eventCount", 0xFFFF)]


class ModbusPDU0BGetCommEventCounterError(_ModbusPDUNoPayload):
    name = "Get Comm Event Counter Exception"
    fields_desc = [XByteField("funcCode", 0x8B),
                   ByteEnumField("exceptionCode", 1, _modbus_exceptions)]


class ModbusPDU0CGetCommEventLogRequest(_ModbusPDUNoPayload):
    name = "Get Comm Event Log"
    fields_desc = [XByteField("funcCode", 0x0C)]


class ModbusPDU0CGetCommEventLogResponse(_ModbusPDUNoPayload):
    name = "Get Comm Event Log Response"
    fields_desc = [XByteField("funcCode", 0x0C),
                   ByteField("byteCount", 8),
                   XShortField("status", 0x0000),
                   XShortField("eventCount", 0x0108),
                   XShortField("messageCount", 0x0121),
                   FieldListField("event", [0x20, 0x00], XByteField("", 0x00))]


class ModbusPDU0CGetCommEventLogError(_ModbusPDUNoPayload):
    name = "Get Comm Event Log Exception"
    fields_desc = [XByteField("funcCode", 0x8C),
                   XByteField("exceptionCode", 1)]


class ModbusPDU0FWriteMultipleCoilsRequest(Packet):
    name = "Write Multiple Coils"
    fields_desc = [XByteField("funcCode", 0x0F),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantityOutput", 0x0001),
                   BitFieldLenField("byteCount", None, 8,
                                    count_of="outputsValue"),
                   FieldListField("outputsValue", [0x00], XByteField("", 0x00),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU0FWriteMultipleCoilsResponse(Packet):
    name = "Write Multiple Coils Response"
    fields_desc = [XByteField("funcCode", 0x0F),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantityOutput", 0x0001)]


class ModbusPDU0FWriteMultipleCoilsError(Packet):
    name = "Write Multiple Coils Exception"
    fields_desc = [XByteField("funcCode", 0x8F),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU10WriteMultipleRegistersRequest(Packet):
    name = "Write Multiple Registers"
    fields_desc = [XByteField("funcCode", 0x10),
                   XShortField("startAddr", 0x0000),
                   BitFieldLenField("quantityRegisters", None, 16,
                                    count_of="outputsValue"),
                   BitFieldLenField("byteCount", None, 8,
                                    count_of="outputsValue",
                                    adjust=lambda pkt, x: x * 2),
                   FieldListField("outputsValue", [0x0000],
                                  XShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU10WriteMultipleRegistersResponse(Packet):
    name = "Write Multiple Registers Response"
    fields_desc = [XByteField("funcCode", 0x10),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantityRegisters", 0x0001)]


class ModbusPDU10WriteMultipleRegistersError(Packet):
    name = "Write Multiple Registers Exception"
    fields_desc = [XByteField("funcCode", 0x90),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU11ReportSlaveIdRequest(_ModbusPDUNoPayload):
    name = "Report Slave Id"
    fields_desc = [XByteField("funcCode", 0x11)]


class ModbusPDU11ReportSlaveIdResponse(Packet):
    name = "Report Slave Id Response"
    fields_desc = [
        XByteField("funcCode", 0x11),
        BitFieldLenField("byteCount", None, 8, length_of="slaveId"),
        ConditionalField(StrLenField("slaveId", "",
                                     length_from=lambda pkt: pkt.byteCount),
                         lambda pkt: pkt.byteCount > 0),
        ConditionalField(XByteField("runIdicatorStatus", 0x00),
                         lambda pkt: pkt.byteCount > 0),
    ]


class ModbusPDU11ReportSlaveIdError(Packet):
    name = "Report Slave Id Exception"
    fields_desc = [XByteField("funcCode", 0x91),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusReadFileSubRequest(Packet):
    name = "Sub-request of Read File Record"
    fields_desc = [ByteField("refType", 0x06),
                   ShortField("fileNumber", 0x0001),
                   ShortField("recordNumber", 0x0000),
                   ShortField("recordLength", 0x0001)]

    def guess_payload_class(self, payload):
        return ModbusReadFileSubRequest


class ModbusPDU14ReadFileRecordRequest(Packet):
    name = "Read File Record"
    fields_desc = [XByteField("funcCode", 0x14),
                   ByteField("byteCount", None)]

    def guess_payload_class(self, payload):
        if self.byteCount > 0:
            return ModbusReadFileSubRequest
        else:
            return Packet.guess_payload_class(self, payload)

    def post_build(self, p, pay):
        if self.byteCount is None:
            tmp_len = len(pay)
            p = p[:1] + struct.pack("!B", tmp_len) + p[3:]
        return p + pay


class ModbusReadFileSubResponse(Packet):
    name = "Sub-response"
    fields_desc = [
        BitFieldLenField("respLength", None, 8, count_of="recData",
                         adjust=lambda pkt, p: p * 2 + 1),
        ByteField("refType", 0x06),
        FieldListField("recData", [0x0000], XShortField("", 0x0000),
                       count_from=lambda pkt: (pkt.respLength - 1) // 2),
    ]

    def guess_payload_class(self, payload):
        return ModbusReadFileSubResponse


class ModbusPDU14ReadFileRecordResponse(Packet):
    name = "Read File Record Response"
    fields_desc = [XByteField("funcCode", 0x14),
                   ByteField("dataLength", None)]

    def post_build(self, p, pay):
        if self.dataLength is None:
            tmp_len = len(pay)
            p = p[:1] + struct.pack("!B", tmp_len) + p[3:]
        return p + pay

    def guess_payload_class(self, payload):
        if self.dataLength > 0:
            return ModbusReadFileSubResponse
        else:
            return Packet.guess_payload_class(self, payload)


class ModbusPDU14ReadFileRecordError(Packet):
    name = "Read File Record Exception"
    fields_desc = [XByteField("funcCode", 0x94),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


# 0x15 : Write File Record
class ModbusWriteFileSubRequest(Packet):
    name = "Sub request of Write File Record"
    fields_desc = [
        ByteField("refType", 0x06),
        ShortField("fileNumber", 0x0001),
        ShortField("recordNumber", 0x0000),
        BitFieldLenField("recordLength", None, 16,
                         length_of="recordData",
                         adjust=lambda pkt, p: p // 2),
        FieldListField("recordData", [0x0000],
                       ShortField("", 0x0000),
                       length_from=lambda pkt: pkt.recordLength * 2),
    ]

    def guess_payload_class(self, payload):
        if payload:
            return ModbusWriteFileSubRequest


class ModbusPDU15WriteFileRecordRequest(Packet):
    name = "Write File Record"
    fields_desc = [XByteField("funcCode", 0x15),
                   ByteField("dataLength", None)]

    def post_build(self, p, pay):
        if self.dataLength is None:
            tmp_len = len(pay)
            p = p[:1] + struct.pack("!B", tmp_len) + p[3:]
            return p + pay

    def guess_payload_class(self, payload):
        if self.dataLength > 0:
            return ModbusWriteFileSubRequest
        else:
            return Packet.guess_payload_class(self, payload)


class ModbusWriteFileSubResponse(ModbusWriteFileSubRequest):
    name = "Sub response of Write File Record"

    def guess_payload_class(self, payload):
        if payload:
            return ModbusWriteFileSubResponse


class ModbusPDU15WriteFileRecordResponse(ModbusPDU15WriteFileRecordRequest):
    name = "Write File Record Response"

    def guess_payload_class(self, payload):
        if self.dataLength > 0:
            return ModbusWriteFileSubResponse
        else:
            return Packet.guess_payload_class(self, payload)


class ModbusPDU15WriteFileRecordError(Packet):
    name = "Write File Record Exception"
    fields_desc = [XByteField("funcCode", 0x95),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU16MaskWriteRegisterRequest(Packet):
    # and/or to 0xFFFF/0x0000 so that nothing is changed in memory
    name = "Mask Write Register"
    fields_desc = [XByteField("funcCode", 0x16),
                   XShortField("refAddr", 0x0000),
                   XShortField("andMask", 0xffff),
                   XShortField("orMask", 0x0000)]


class ModbusPDU16MaskWriteRegisterResponse(Packet):
    name = "Mask Write Register Response"
    fields_desc = [XByteField("funcCode", 0x16),
                   XShortField("refAddr", 0x0000),
                   XShortField("andMask", 0xffff),
                   XShortField("orMask", 0x0000)]


class ModbusPDU16MaskWriteRegisterError(Packet):
    name = "Mask Write Register Exception"
    fields_desc = [XByteField("funcCode", 0x96),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU17ReadWriteMultipleRegistersRequest(Packet):
    name = "Read Write Multiple Registers"
    fields_desc = [XByteField("funcCode", 0x17),
                   XShortField("readStartingAddr", 0x0000),
                   XShortField("readQuantityRegisters", 0x0001),
                   XShortField("writeStartingAddr", 0x0000),
                   BitFieldLenField("writeQuantityRegisters", None, 16,
                                    count_of="writeRegistersValue"),
                   BitFieldLenField("byteCount", None, 8,
                                    count_of="writeRegistersValue",
                                    adjust=lambda pkt, x: x * 2),
                   FieldListField("writeRegistersValue", [0x0000],
                                  XShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU17ReadWriteMultipleRegistersResponse(Packet):
    name = "Read Write Multiple Registers Response"
    fields_desc = [XByteField("funcCode", 0x17),
                   BitFieldLenField("byteCount", None, 8,
                                    count_of="registerVal",
                                    adjust=lambda pkt, x: x * 2),
                   FieldListField("registerVal", [0x0000],
                                  ShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU17ReadWriteMultipleRegistersError(Packet):
    name = "Read Write Multiple Exception"
    fields_desc = [XByteField("funcCode", 0x97),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU18ReadFIFOQueueRequest(Packet):
    name = "Read FIFO Queue"
    fields_desc = [XByteField("funcCode", 0x18),
                   XShortField("FIFOPointerAddr", 0x0000)]


class ModbusPDU18ReadFIFOQueueResponse(Packet):
    name = "Read FIFO Queue Response"
    fields_desc = [XByteField("funcCode", 0x18),
                   # TODO: ByteCount must includes size of FIFOCount
                   BitFieldLenField("byteCount", None, 16, count_of="FIFOVal",
                                    adjust=lambda pkt, p: p * 2 + 2),
                   BitFieldLenField("FIFOCount", None, 16, count_of="FIFOVal"),
                   FieldListField("FIFOVal", [], ShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU18ReadFIFOQueueError(Packet):
    name = "Read FIFO Queue Exception"
    fields_desc = [XByteField("funcCode", 0x98),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


# TODO: not implemented, out of the main specification
# class ModbusPDU2B0DCANOpenGeneralReferenceRequest(Packet):
#     name = "CANopen General Reference Request"
#     fields_desc = []
#
#
# class ModbusPDU2B0DCANOpenGeneralReferenceResponse(Packet):
#     name = "CANopen General Reference Response"
#     fields_desc = []
#
#
# class ModbusPDU2B0DCANOpenGeneralReferenceError(Packet):
#     name = "CANopen General Reference Error"
#     fields_desc = []


# 0x2B/0x0E - Read Device Identification values
_read_device_id_codes = {1: "Basic",
                         2: "Regular",
                         3: "Extended",
                         4: "Specific"}
# 0x00->0x02: mandatory
# 0x03->0x06: optional
# 0x07->0x7F: Reserved (optional)
# 0x80->0xFF: product dependent private objects (optional)
_read_device_id_object_id = {0x00: "VendorName",
                             0x01: "ProductCode",
                             0x02: "MajorMinorRevision",
                             0x03: "VendorUrl",
                             0x04: "ProductName",
                             0x05: "ModelName",
                             0x06: "UserApplicationName"}
_read_device_id_conformity_lvl = {
    0x01: "Basic Identification (stream only)",
    0x02: "Regular Identification (stream only)",
    0x03: "Extended Identification (stream only)",
    0x81: "Basic Identification (stream and individual access)",
    0x82: "Regular Identification (stream and individual access)",
    0x83: "Extended Identification (stream and individual access)",
}
_read_device_id_more_follow = {0x00: "No",
                               0x01: "Yes"}


class ModbusPDU2B0EReadDeviceIdentificationRequest(Packet):
    name = "Read Device Identification"
    fields_desc = [XByteField("funcCode", 0x2B),
                   XByteField("MEIType", 0x0E),
                   ByteEnumField("readCode", 1, _read_device_id_codes),
                   ByteEnumField("objectId", 0x00, _read_device_id_object_id)]


class ModbusPDU2B0EReadDeviceIdentificationResponse(Packet):
    name = "Read Device Identification"
    fields_desc = [XByteField("funcCode", 0x2B),
                   XByteField("MEIType", 0x0E),
                   ByteEnumField("readCode", 4, _read_device_id_codes),
                   ByteEnumField("conformityLevel", 0x01,
                                 _read_device_id_conformity_lvl),
                   ByteEnumField("more", 0x00, _read_device_id_more_follow),
                   ByteEnumField("nextObjId", 0x00, _read_device_id_object_id),
                   ByteField("objCount", 0x00)]

    def guess_payload_class(self, payload):
        if self.objCount > 0:
            return ModbusObjectId
        else:
            return Packet.guess_payload_class(self, payload)


class ModbusPDU2B0EReadDeviceIdentificationError(Packet):
    name = "Read Exception Status Exception"
    fields_desc = [XByteField("funcCode", 0xAB),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


_reserved_funccode_request = {
    0x09: '0x09 Unknown Reserved Request',
    0x0A: '0x0a Unknown Reserved Request',
    0x0D: '0x0d Unknown Reserved Request',
    0x0E: '0x0e Unknown Reserved Request',
    0x29: '0x29 Unknown Reserved Request',
    0x2A: '0x2a Unknown Reserved Request',
    0x5A: 'Specific Schneider Electric Request',
    0x5B: '0x5b Unknown Reserved Request',
    0x7D: '0x7d Unknown Reserved Request',
    0x7E: '0x7e Unknown Reserved Request',
    0x7F: '0x7f Unknown Reserved Request',
}

_reserved_funccode_response = {
    0x09: '0x09 Unknown Reserved Response',
    0x0A: '0x0a Unknown Reserved Response',
    0x0D: '0x0d Unknown Reserved Response',
    0x0E: '0x0e Unknown Reserved Response',
    0x29: '0x29 Unknown Reserved Response',
    0x2A: '0x2a Unknown Reserved Response',
    0x5A: 'Specific Schneider Electric Response',
    0x5B: '0x5b Unknown Reserved Response',
    0x7D: '0x7d Unknown Reserved Response',
    0x7E: '0x7e Unknown Reserved Response',
    0x7F: '0x7f Unknown Reserved Response',
}

_reserved_funccode_error = {
    0x89: '0x89 Unknown Reserved Error',
    0x8A: '0x8a Unknown Reserved Error',
    0x8D: '0x8d Unknown Reserved Error',
    0x8E: '0x8e Unknown Reserved Error',
    0xA9: '0x88 Unknown Reserved Error',
    0xAA: '0x88 Unknown Reserved Error',
    0xDA: 'Specific Schneider Electric Error',
    0xDB: '0xdb Unknown Reserved Error',
    0xDC: '0xdc Unknown Reserved Error',
    0xFD: '0xfd Unknown Reserved Error',
    0xFE: '0xfe Unknown Reserved Error',
    0xFF: '0xff Unknown Reserved Error',
}


class ModbusPDUReservedFunctionCodeRequest(_ModbusPDUNoPayload):
    name = "Reserved Function Code Request"
    fields_desc = [
        ByteEnumField("funcCode", 0x00, _reserved_funccode_request),
        StrFixedLenField('mb_payload', '', 255), ]

    def mysummary(self):
        return self.sprintf("Modbus Reserved Request %funcCode%")


class ModbusPDUReservedFunctionCodeResponse(_ModbusPDUNoPayload):
    name = "Reserved Function Code Response"
    fields_desc = [
        ByteEnumField("funcCode", 0x00, _reserved_funccode_response),
        StrFixedLenField('mb_payload', '', 255), ]

    def mysummary(self):
        return self.sprintf("Modbus Reserved Response %funcCode%")


class ModbusPDUReservedFunctionCodeError(_ModbusPDUNoPayload):
    name = "Reserved Function Code Error"
    fields_desc = [
        ByteEnumField("funcCode", 0x00, _reserved_funccode_error),
        StrFixedLenField('mb_payload', '', 255), ]

    def mysummary(self):
        return self.sprintf("Modbus Reserved Error %funcCode%")


_userdefined_funccode_request = {
}
_userdefined_funccode_response = {
}
_userdefined_funccode_error = {
}


class ModbusByteEnumField(EnumField):
    __slots__ = "defEnum"

    def __init__(self, name, default, enum, defEnum):
        EnumField.__init__(self, name, default, enum, "B")
        self.defEnum = defEnum

    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x, VolatileValue) \
                and x in self.i2s:
            return self.i2s[x]
        if self.defEnum:
            return self.defEnum
        return repr(x)


class ModbusPDUUserDefinedFunctionCodeRequest(_ModbusPDUNoPayload):
    name = "User-Defined Function Code Request"
    fields_desc = [
        ModbusByteEnumField(
            "funcCode", 0x00, _userdefined_funccode_request,
            "Unknown user-defined request function Code"),
        StrFixedLenField('mb_payload', '', 255), ]

    def mysummary(self):
        return self.sprintf("Modbus User-Defined Request %funcCode%")


class ModbusPDUUserDefinedFunctionCodeResponse(_ModbusPDUNoPayload):
    name = "User-Defined Function Code Response"
    fields_desc = [
        ModbusByteEnumField(
            "funcCode", 0x00, _userdefined_funccode_response,
            "Unknown user-defined response function Code"),
        StrFixedLenField('mb_payload', '', 255), ]

    def mysummary(self):
        return self.sprintf("Modbus User-Defined Response %funcCode%")


class ModbusPDUUserDefinedFunctionCodeError(_ModbusPDUNoPayload):
    name = "User-Defined Function Code Error"
    fields_desc = [
        ModbusByteEnumField(
            "funcCode", 0x00, _userdefined_funccode_error,
            "Unknown user-defined error function Code"),
        StrFixedLenField('mb_payload', '', 255), ]

    def mysummary(self):
        return self.sprintf("Modbus User-Defined Error %funcCode%")


class ModbusObjectId(Packet):
    name = "Object"
    fields_desc = [ByteEnumField("id", 0x00, _read_device_id_object_id),
                   BitFieldLenField("length", None, 8, length_of="value"),
                   StrLenField("value", "",
                               length_from=lambda pkt: pkt.length)]

    def guess_payload_class(self, payload):
        return ModbusObjectId


_modbus_request_classes = {
    0x01: ModbusPDU01ReadCoilsRequest,
    0x02: ModbusPDU02ReadDiscreteInputsRequest,
    0x03: ModbusPDU03ReadHoldingRegistersRequest,
    0x04: ModbusPDU04ReadInputRegistersRequest,
    0x05: ModbusPDU05WriteSingleCoilRequest,
    0x06: ModbusPDU06WriteSingleRegisterRequest,
    0x07: ModbusPDU07ReadExceptionStatusRequest,
    0x08: ModbusPDU08DiagnosticsRequest,
    0x0B: ModbusPDU0BGetCommEventCounterRequest,
    0x0C: ModbusPDU0CGetCommEventLogRequest,
    0x0F: ModbusPDU0FWriteMultipleCoilsRequest,
    0x10: ModbusPDU10WriteMultipleRegistersRequest,
    0x11: ModbusPDU11ReportSlaveIdRequest,
    0x14: ModbusPDU14ReadFileRecordRequest,
    0x15: ModbusPDU15WriteFileRecordRequest,
    0x16: ModbusPDU16MaskWriteRegisterRequest,
    0x17: ModbusPDU17ReadWriteMultipleRegistersRequest,
    0x18: ModbusPDU18ReadFIFOQueueRequest,
}
_modbus_error_classes = {
    0x81: ModbusPDU01ReadCoilsError,
    0x82: ModbusPDU02ReadDiscreteInputsError,
    0x83: ModbusPDU03ReadHoldingRegistersError,
    0x84: ModbusPDU04ReadInputRegistersError,
    0x85: ModbusPDU05WriteSingleCoilError,
    0x86: ModbusPDU06WriteSingleRegisterError,
    0x87: ModbusPDU07ReadExceptionStatusError,
    0x88: ModbusPDU08DiagnosticsError,
    0x8B: ModbusPDU0BGetCommEventCounterError,
    0x8C: ModbusPDU0CGetCommEventLogError,
    0x8F: ModbusPDU0FWriteMultipleCoilsError,
    0x90: ModbusPDU10WriteMultipleRegistersError,
    0x91: ModbusPDU11ReportSlaveIdError,
    0x94: ModbusPDU14ReadFileRecordError,
    0x95: ModbusPDU15WriteFileRecordError,
    0x96: ModbusPDU16MaskWriteRegisterError,
    0x97: ModbusPDU17ReadWriteMultipleRegistersError,
    0x98: ModbusPDU18ReadFIFOQueueError,
    0xAB: ModbusPDU2B0EReadDeviceIdentificationError,
}
_modbus_response_classes = {
    0x01: ModbusPDU01ReadCoilsResponse,
    0x02: ModbusPDU02ReadDiscreteInputsResponse,
    0x03: ModbusPDU03ReadHoldingRegistersResponse,
    0x04: ModbusPDU04ReadInputRegistersResponse,
    0x05: ModbusPDU05WriteSingleCoilResponse,
    0x06: ModbusPDU06WriteSingleRegisterResponse,
    0x07: ModbusPDU07ReadExceptionStatusResponse,
    0x08: ModbusPDU08DiagnosticsResponse,
    0x0B: ModbusPDU0BGetCommEventCounterResponse,
    0x0C: ModbusPDU0CGetCommEventLogResponse,
    0x0F: ModbusPDU0FWriteMultipleCoilsResponse,
    0x10: ModbusPDU10WriteMultipleRegistersResponse,
    0x11: ModbusPDU11ReportSlaveIdResponse,
    0x14: ModbusPDU14ReadFileRecordResponse,
    0x15: ModbusPDU15WriteFileRecordResponse,
    0x16: ModbusPDU16MaskWriteRegisterResponse,
    0x17: ModbusPDU17ReadWriteMultipleRegistersResponse,
    0x18: ModbusPDU18ReadFIFOQueueResponse,
}
_mei_types_request = {
    0x0E: ModbusPDU2B0EReadDeviceIdentificationRequest,
    # 0x0D: ModbusPDU2B0DCANOpenGeneralReferenceRequest,
}
_mei_types_response = {
    0x0E: ModbusPDU2B0EReadDeviceIdentificationResponse,
    # 0x0D: ModbusPDU2B0DCANOpenGeneralReferenceResponse,
}


class ModbusADURequest(Packet):
    name = "ModbusADU"
    fields_desc = [
        # needs to be unique
        XShortField("transId", 0x0000),
        # needs to be zero (Modbus)
        XShortField("protoId", 0x0000),
        # is calculated with payload
        ShortField("len", None),
        # 0xFF (recommended as non-significant value) or 0x00
        XByteField("unitId", 0xff),
    ]

    def guess_payload_class(self, payload):
        function_code = orb(payload[0])

        if function_code == 0x2B:
            sub_code = orb(payload[1])
            try:
                return _mei_types_request[sub_code]
            except KeyError:
                pass
        try:
            return _modbus_request_classes[function_code]
        except KeyError:
            pass
        if function_code in _reserved_funccode_request:
            return ModbusPDUReservedFunctionCodeRequest
        return ModbusPDUUserDefinedFunctionCodeRequest

    def post_build(self, p, pay):
        if self.len is None:
            tmp_len = len(pay) + 1  # +len(p)
            p = p[:4] + struct.pack("!H", tmp_len) + p[6:]
        return p + pay


class ModbusADUResponse(Packet):
    name = "ModbusADU"
    fields_desc = [
        # needs to be unique
        XShortField("transId", 0x0000),
        # needs to be zero (Modbus)
        XShortField("protoId", 0x0000),
        # is calculated with payload
        ShortField("len", None),
        # 0xFF or 0x00 should be used for Modbus over TCP/IP
        XByteField("unitId", 0xff),
    ]

    def guess_payload_class(self, payload):
        function_code = orb(payload[0])

        if function_code == 0x2B:
            sub_code = orb(payload[1])
            try:
                return _mei_types_response[sub_code]
            except KeyError:
                pass
        try:
            return _modbus_response_classes[function_code]
        except KeyError:
            pass
        try:
            return _modbus_error_classes[function_code]
        except KeyError:
            pass
        if function_code in _reserved_funccode_response:
            return ModbusPDUReservedFunctionCodeResponse
        elif function_code in _reserved_funccode_error:
            return ModbusPDUReservedFunctionCodeError
        if function_code < 0x80:
            return ModbusPDUUserDefinedFunctionCodeResponse
        return ModbusPDUUserDefinedFunctionCodeError

    def post_build(self, p, pay):
        if self.len is None:
            tmp_len = len(pay) + 1  # +len(p)
            p = p[:4] + struct.pack("!H", tmp_len) + p[6:]
        return p + pay


bind_layers(TCP, ModbusADURequest, dport=502)
bind_layers(TCP, ModbusADUResponse, sport=502)
