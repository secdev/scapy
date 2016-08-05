# coding: utf8

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

# Copyright (C) 2016 Arthur Gervais, Ken LE PRADO, Sébastien Mainand

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import *

# TODO: implement serial specific function codes

_modbus_exceptions = {1: "Illegal Function Code",
                      2: "Illegal Data Address",
                      3: "Illegal Data Value",
                      4: "Server Device Failure",
                      5: "Acknowledge",
                      6: "Server Device Busy",
                      8: "Memory Parity Error",
                      10: "Gateway Path Unavailable",
                      11: "Gateway Target Device Failed to Respond"}


class ModbusPDU00GenericRequest(Packet):
    name = "Generic Request"
    fields_desc = [XByteField("funcCode", 0x00),
                   StrFixedLenField("payload", "", 255)]

    def extract_padding(self, s):
        return "", None

    def mysummary(self):
        return self.sprintf("Modbus Request %funcCode%")


class ModbusPDU00GenericResponse(Packet):
    name = "Generic Request"
    fields_desc = [XByteField("funcCode", 0x00),
                   StrFixedLenField("payload", "", 255)]

    def extract_padding(self, s):
        return "", None

    def mysummary(self):
        return self.sprintf("Modbus Response %funcCode%")


class ModbusPDU00GenericError(Packet):
    name = "Generic Exception"
    fields_desc = [XByteField("funcCode", 0x80),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]

    def extract_padding(self, s):
        return "", None

    def my_summary(self):
        return self.sprintf("Modbus Exception %funcCode%")


class ModbusPDU01ReadCoilsRequest(Packet):
    name = "Read Coils Request"
    fields_desc = [XByteField("funcCode", 0x01),
                   XShortField("startAddr", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("quantity", 0x0001)]

    def extract_padding(self, s):
        return "", None


class ModbusPDU01ReadCoilsResponse(Packet):
    name = "Read Coils Response"
    fields_desc = [XByteField("funcCode", 0x01),
                   BitFieldLenField("byteCount", None, 8, count_of="coilStatus"),
                   FieldListField("coilStatus", [0x00], ByteField("", 0x00), count_from=lambda pkt: pkt.byteCount)]

    def extract_padding(self, s):
        return "", None


class ModbusPDU01ReadCoilsError(Packet):
    name = "Read Coils Exception"
    fields_desc = [XByteField("funcCode", 0x81),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]

    def extract_padding(self, s):
        return "", None


class ModbusPDU02ReadDiscreteInputsRequest(Packet):
    name = "Read Discrete Inputs"
    fields_desc = [XByteField("funcCode", 0x02),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantity", 0x0001)]

    def extract_padding(self, s):
        return "", None


class ModbusPDU02ReadDiscreteInputsResponse(Packet):
    """ inputStatus: result is represented as bytes, padded with 0 to have a
        integer number of bytes. The field does not parse this result and
        present the bytes directly
    """
    name = "Read Discrete Inputs Response"
    fields_desc = [XByteField("funcCode", 0x02),
                   BitFieldLenField("byteCount", None, 8, count_of="inputStatus"),
                   FieldListField("inputStatus", [0x00], ByteField("", 0x00), count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU02ReadDiscreteInputsError(Packet):
    name = "Read Discrete Inputs Exception"
    fields_desc = [XByteField("funcCode", 0x82),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU03ReadHoldingRegistersRequest(Packet):
    name = "Read Holding Registers"
    fields_desc = [XByteField("funcCode", 0x03),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantity", 0x0001)]

    def extract_padding(self, s):
        return "", None


class ModbusPDU03ReadHoldingRegistersResponse(Packet):
    name = "Read Holding Registers Response"
    fields_desc = [XByteField("funcCode", 0x03),
                   BitFieldLenField("byteCount", None, 8, count_of="registerVal", adjust=lambda pkt, x: x*2),
                   FieldListField("registerVal", [0x0000], ShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU03ReadHoldingRegistersError(Packet):
    name = "Read Holding Registers Exception"
    fields_desc = [XByteField("funcCode", 0x83),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU04ReadInputRegistersRequest(Packet):
    name = "Read Input Registers"
    fields_desc = [XByteField("funcCode", 0x04),
                   XShortField("startAddr", 0x0000),
                   XShortField("quantity", 0x0001)]

    def extract_padding(self, s):
        return "", None


class ModbusPDU04ReadInputRegistersResponse(Packet):
    name = "Read Input Registers Response"
    fields_desc = [XByteField("funcCode", 0x04),
                   BitFieldLenField("byteCount", None, 8, count_of="registerVal", adjust=lambda pkt, x: x*2),
                   FieldListField("registerVal", [0x0000], ShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU04ReadInputRegistersError(Packet):
    name = "Read Input Registers Exception"
    fields_desc = [XByteField("funcCode", 0x84),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU05WriteSingleCoilRequest(Packet):
    name = "Write Single Coil"
    fields_desc = [XByteField("funcCode", 0x05),
                   XShortField("outputAddr", 0x0000),  # from 0x0000 to 0xFFFF
                   XShortField("outputValue", 0x0000)]  # 0x0000 == Off, 0xFF00 == On


class ModbusPDU05WriteSingleCoilResponse(Packet):  # The answer is the same as the request if successful
    name = "Write Single Coil"
    fields_desc = [XByteField("funcCode", 0x05),
                   XShortField("outputAddr", 0x0000),  # from 0x0000 to 0xFFFF
                   XShortField("outputValue", 0x0000)]  # 0x0000 == Off, 0xFF00 == On


class ModbusPDU05WriteSingleCoilError(Packet):
    name = "Write Single Coil Exception"
    fields_desc = [XByteField("funcCode", 0x85),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU06WriteSingleRegisterRequest(Packet):
    name = "Write Single Register"
    fields_desc = [XByteField("funcCode", 0x06),
                   XShortField("registerAddr", 0x0000),
                   XShortField("registerValue", 0x0000)]

    def extract_padding(self, s):
        return "", None


class ModbusPDU06WriteSingleRegisterResponse(Packet):
    name = "Write Single Register Response"
    fields_desc = [XByteField("funcCode", 0x06),
                   XShortField("registerAddr", 0x0000),
                   XShortField("registerValue", 0x0000)]


class ModbusPDU06WriteSingleRegisterError(Packet):
    name = "Write Single Register Exception"
    fields_desc = [XByteField("funcCode", 0x86),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU07ReadExceptionStatusRequest(Packet):
    name = "Read Exception Status"
    fields_desc = [XByteField("funcCode", 0x07)]

    def extract_padding(self, s):
        return "", None


class ModbusPDU07ReadExceptionStatusResponse(Packet):
    name = "Read Exception Status Response"
    fields_desc = [XByteField("funcCode", 0x07),
                   XByteField("startingAddr", 0x00)]


class ModbusPDU07ReadExceptionStatusError(Packet):
    name = "Read Exception Status Exception"
    fields_desc = [XByteField("funcCode", 0x87),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU0FWriteMultipleCoilsRequest(Packet):
    name = "Write Multiple Coils"
    fields_desc = [XByteField("funcCode", 0x0F),
                   XShortField("startingAddr", 0x0000),
                   XShortField("quantityOutput", 0x0001),
                   BitFieldLenField("byteCount", None, 8, count_of="outputsValue"),
                   FieldListField("outputsValue", [0x00], XByteField("", 0x00), count_from=lambda pkt: pkt.byteCount)]

    def extract_padding(self, s):
        return "", None


class ModbusPDU0FWriteMultipleCoilsResponse(Packet):
    name = "Write Multiple Coils Response"
    fields_desc = [XByteField("funcCode", 0x0F),
                   XShortField("startingAddr", 0x0000),
                   XShortField("quantityOutput", 0x0001)]


class ModbusPDU0FWriteMultipleCoilsError(Packet):
    name = "Write Multiple Coils Exception"
    fields_desc = [XByteField("funcCode", 0x8F),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU10WriteMultipleRegistersRequest(Packet):
    name = "Write Multiple Registers"
    fields_desc = [XByteField("funcCode", 0x10),
                   XShortField("startingAddr", 0x0000),
                   BitFieldLenField("quantityRegisters", None, 16, count_of="outputsValue",),
                   BitFieldLenField("byteCount", None, 8, count_of="outputsValue", adjust=lambda pkt, x: x*2),
                   FieldListField("outputsValue", [0x0000], XShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU10WriteMultipleRegistersResponse(Packet):
    name = "Write Multiple Registers Response"
    fields_desc = [XByteField("funcCode", 0x10),
                   XShortField("startingAddr", 0x0000),
                   XShortField("quantityRegisters", 0x0001)]


class ModbusPDU10WriteMultipleRegistersError(Packet):
    name = "Write Multiple Registers Exception"
    fields_desc = [XByteField("funcCode", 0x90),
                   ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU11ReportSlaveIdRequest(Packet):
    name = "Report Slave Id"
    fields_desc = [XByteField("funcCode", 0x11)]

    def extract_padding(self, s):
        return "", None


class ModbusPDU11ReportSlaveIdResponse(Packet):
    name = "Report Slave Id Response"
    fields_desc = [XByteField("funcCode", 0x11),
                   BitFieldLenField("byteCount", None, 8, length_of="slaveId"),
                   ConditionalField(StrLenField("slaveId", "", length_from=lambda pkt: pkt.byteCount),
                                    lambda pkt: pkt.byteCount > 0),
                   ConditionalField(XByteField("runIdicatorStatus", 0x00), lambda pkt: pkt.byteCount > 0)]


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
            l = len(pay)
            p = p[:1] + struct.pack("!B", l) + p[3:]
        return p + pay


class ModbusReadFileSubResponse(Packet):
    name = "Sub-response"
    fields_desc = [BitFieldLenField("respLength", None, 8, count_of="recData", adjust=lambda pkt, p: p*2+1),
                   ByteField("refType", 0x06),
                   FieldListField("recData", [0x0000], XShortField("", 0x0000),
                                  count_from=lambda pkt: (pkt.respLength-1)/2)]

    def guess_payload_class(self, payload):
        return ModbusReadFileSubResponse


class ModbusPDU14ReadFileRecordResponse(Packet):
    name = "Read File Record Response"
    fields_desc = [XByteField("funcCode", 0x14),
                   ByteField("dataLength", None)]

    def post_build(self, p, pay):
        if self.dataLength is None:
            l = len(pay)
            p = p[:1] + struct.pack("!B", l) + p[3:]
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
    fields_desc = [ByteField("refType", 0x06),
                   ShortField("fileNumber", 0x0001),
                   ShortField("recordNumber", 0x0000),
                   BitFieldLenField("recordLength", None, 16, length_of="recordData", adjust=lambda pkt, p: p/2),
                   FieldListField("recordData", [0x0000], ShortField("", 0x0000),
                                  length_from=lambda pkt: pkt.recordLength*2)]

    def guess_payload_class(self, payload):
        if payload:
            return ModbusWriteFileSubRequest


class ModbusPDU15WriteFileRecordRequest(Packet):
    name = "Write File Record"
    fields_desc = [XByteField("funcCode", 0x15),
                   ByteField("dataLength", None)]

    def post_build(self, p, pay):
        if self.dataLength is None:
            l = len(pay)
            p = p[:1] + struct.pack("!B", l) + p[3:]
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
                   BitFieldLenField("writeQuantityRegisters", None, 16, count_of="writeRegistersValue"),
                   BitFieldLenField("byteCount", None, 8, count_of="writeRegistersValue", adjust=lambda pkt, x: x*2),
                   FieldListField("writeRegistersValue", [0x0000], XShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU17ReadWriteMultipleRegistersResponse(Packet):
    name = "Read Write Multiple Registers Response"
    fields_desc = [XByteField("funcCode", 0x17),
                   BitFieldLenField("byteCount", None, 8, count_of="registerVal", adjust=lambda pkt, x: x*2),
                   FieldListField("registerVal", [0x0000], ShortField("", 0x0000),
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
                   BitFieldLenField("byteCount", None, 16, count_of="FIFOVal", adjust=lambda pkt, p: p*2+2),
                   BitFieldLenField("FIFOCount", None, 16, count_of="FIFOVal"),
                   FieldListField("FIFOVal", [], ShortField("", 0x0000), count_from=lambda pkt: pkt.byteCount)]


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
_read_device_id_conformity_lvl = {0x01: "Basic Identification (stream only)",
                                  0x02: "Regular Identification (stream only)",
                                  0x03: "Extended Identification (stream only)",
                                  0x81: "Basic Identification (stream and individual access)",
                                  0x82: "Regular Identification (stream and individual access)",
                                  0x83: "Extended Identification (stream and individual access)"}
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
                   ByteEnumField("conformityLevel", 0x01, _read_device_id_conformity_lvl),
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


class ModbusObjectId(Packet):
    name = "Object"
    fields_desc = [ByteEnumField("id", 0x00, _read_device_id_object_id),
                   BitFieldLenField("length", None, 8, count_of="value"),
                   StrLenField("value", "", length_from=lambda pkt: pkt.length)]

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
    0x8F: ModbusPDU0FWriteMultipleCoilsError,
    0x90: ModbusPDU10WriteMultipleRegistersError,
    0x91: ModbusPDU11ReportSlaveIdError,
    0x94: ModbusPDU14ReadFileRecordError,
    0x95: ModbusPDU15WriteFileRecordError,
    0x96: ModbusPDU16MaskWriteRegisterError,
    0x97: ModbusPDU17ReadWriteMultipleRegistersError,
    0x98: ModbusPDU18ReadFIFOQueueError,
    0xAB: ModbusPDU2B0EReadDeviceIdentificationError
}
_modbus_response_classes = {
    0x01: ModbusPDU01ReadCoilsResponse,
    0x02: ModbusPDU02ReadDiscreteInputsResponse,
    0x03: ModbusPDU03ReadHoldingRegistersResponse,
    0x04: ModbusPDU04ReadInputRegistersResponse,
    0x05: ModbusPDU05WriteSingleCoilResponse,
    0x06: ModbusPDU06WriteSingleRegisterResponse,
    0x07: ModbusPDU07ReadExceptionStatusResponse,
    0x0F: ModbusPDU0FWriteMultipleCoilsResponse,
    0x10: ModbusPDU10WriteMultipleRegistersResponse,
    0x11: ModbusPDU11ReportSlaveIdResponse,
    0x14: ModbusPDU14ReadFileRecordResponse,
    0x15: ModbusPDU15WriteFileRecordResponse,
    0x16: ModbusPDU16MaskWriteRegisterResponse,
    0x17: ModbusPDU17ReadWriteMultipleRegistersResponse,
    0x18: ModbusPDU18ReadFIFOQueueResponse
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
    fields_desc = [XShortField("transId", 0x0000),  # needs to be unique
                   XShortField("protoId", 0x0000),  # needs to be zero (Modbus)
                   ShortField("len", None),  # is calculated with payload
                   XByteField("unitId", 0xff)]  # 0xFF (recommended as non-significant value) or 0x00

    def guess_payload_class(self, payload):
        function_code = int(payload[0].encode("hex"), 16)
        sub_code = int(payload[1].encode("hex"), 16)

        if function_code == 0x2B:
            try:
                return _mei_types_request[sub_code]
            except KeyError:
                pass
        try:
            return _modbus_request_classes[function_code]
        except KeyError:
            pass
        return ModbusPDU00GenericRequest

    def post_build(self, p, pay):
        if self.len is None:
            l = len(pay) + 1  # +len(p)
            p = p[:4] + struct.pack("!H", l) + p[6:]
        return p + pay


class ModbusADUResponse(Packet):
    name = "ModbusADU"
    fields_desc = [XShortField("transId", 0x0000),  # needs to be unique
                   XShortField("protoId", 0x0000),  # needs to be zero (Modbus)
                   ShortField("len", None),  # is calculated with payload
                   XByteField("unitId", 0xff)]  # 0xFF or 0x00 should be used for Modbus over TCP/IP

    def guess_payload_class(self, payload):
        function_code = int(payload[0].encode("hex"), 16)
        sub_code = int(payload[1].encode("hex"), 16)

        if function_code == 0x2B:
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
        if function_code < 0x81:
            return ModbusPDU00GenericResponse
        return ModbusPDU00GenericError

    def post_build(self, p, pay):
        if self.len is None:
            l = len(pay) + 1  # +len(p)
            p = p[:4] + struct.pack("!H", l) + p[6:]
        return p + pay


bind_layers(TCP, ModbusADURequest, dport=502)
bind_layers(TCP, ModbusADUResponse, sport=502)

