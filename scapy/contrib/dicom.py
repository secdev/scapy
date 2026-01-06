# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Tyler M

# scapy.contrib.description = DICOM (Digital Imaging and Communications in Medicine)
# scapy.contrib.status = loads

"""
DICOM (Digital Imaging and Communications in Medicine) Protocol
Reference: DICOM PS3.8 - Network Communication Support for Message Exchange
https://dicom.nema.org/medical/dicom/current/output/html/part08.html
"""

import logging
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from scapy.compat import Self
from scapy.packet import Packet, bind_layers
from scapy.error import Scapy_Exception
from scapy.fields import (
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    IntField,
    LenField,
    PacketListField,
    ShortField,
    StrFixedLenField,
    StrLenField,
)
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket
from scapy.volatile import RandShort, RandInt, RandString

__all__ = [
    "DICOM_PORT",
    "APP_CONTEXT_UID",
    "DEFAULT_TRANSFER_SYNTAX_UID",
    "VERIFICATION_SOP_CLASS_UID",
    "CT_IMAGE_STORAGE_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_FIND_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_GET_SOP_CLASS_UID",
    "STUDY_ROOT_QR_FIND_SOP_CLASS_UID",
    "STUDY_ROOT_QR_MOVE_SOP_CLASS_UID",
    "STUDY_ROOT_QR_GET_SOP_CLASS_UID",
    "DICOM",
    "A_ASSOCIATE_RQ",
    "A_ASSOCIATE_AC",
    "A_ASSOCIATE_RJ",
    "P_DATA_TF",
    "PresentationDataValueItem",
    "A_RELEASE_RQ",
    "A_RELEASE_RP",
    "A_ABORT",
    "DICOMVariableItem",
    "DICOMApplicationContext",
    "DICOMPresentationContextRQ",
    "DICOMPresentationContextAC",
    "DICOMAbstractSyntax",
    "DICOMTransferSyntax",
    "DICOMUserInformation",
    "DICOMMaximumLength",
    "DICOMImplementationClassUID",
    "DICOMAsyncOperationsWindow",
    "DICOMSCPSCURoleSelection",
    "DICOMImplementationVersionName",
    "DICOMUserIdentity",
    "DICOMUserIdentityResponse",
    "DICOMElementField",
    "DICOMAETitleField",
    "DICOMUIDField",
    "DICOMUIDFieldRaw",
    "DICOMUSField",
    "DICOMULField",
    "DICOMAEDIMSEField",
    "DIMSEPacket",
    "C_ECHO_RQ",
    "C_ECHO_RSP",
    "C_STORE_RQ",
    "C_STORE_RSP",
    "C_FIND_RQ",
    "C_FIND_RSP",
    "C_MOVE_RQ",
    "C_MOVE_RSP",
    "C_GET_RQ",
    "C_GET_RSP",
    "DICOMSocket",
    "parse_dimse_status",
    "_uid_to_bytes",
    "_uid_to_bytes_raw",
    "build_presentation_context_rq",
    "build_user_information",
]

log = logging.getLogger("scapy.contrib.dicom")

DICOM_PORT = 104
APP_CONTEXT_UID = "1.2.840.10008.3.1.1.1"
DEFAULT_TRANSFER_SYNTAX_UID = "1.2.840.10008.1.2"
VERIFICATION_SOP_CLASS_UID = "1.2.840.10008.1.1"
CT_IMAGE_STORAGE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.2"

PATIENT_ROOT_QR_FIND_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.1"
PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.2"
PATIENT_ROOT_QR_GET_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.3"
STUDY_ROOT_QR_FIND_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.1"
STUDY_ROOT_QR_MOVE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.2"
STUDY_ROOT_QR_GET_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.3"

PDU_TYPES = {
    0x01: "A-ASSOCIATE-RQ",
    0x02: "A-ASSOCIATE-AC",
    0x03: "A-ASSOCIATE-RJ",
    0x04: "P-DATA-TF",
    0x05: "A-RELEASE-RQ",
    0x06: "A-RELEASE-RP",
    0x07: "A-ABORT",
}

ITEM_TYPES = {
    0x10: "Application Context",
    0x20: "Presentation Context RQ",
    0x21: "Presentation Context AC",
    0x30: "Abstract Syntax",
    0x40: "Transfer Syntax",
    0x50: "User Information",
    0x51: "Maximum Length",
    0x52: "Implementation Class UID",
    0x53: "Asynchronous Operations Window",
    0x54: "SCP/SCU Role Selection",
    0x55: "Implementation Version Name",
    0x58: "User Identity",
    0x59: "User Identity Server Response",
}


def _uid_to_bytes(uid: Union[str, bytes]) -> bytes:
    """Convert UID to bytes with even-length padding (null byte if needed)."""
    if isinstance(uid, bytes):
        b_uid = uid
    elif isinstance(uid, str):
        b_uid = uid.encode("ascii")
    else:
        return b""
    if len(b_uid) % 2 != 0:
        b_uid += b"\x00"
    return b_uid


def _uid_to_bytes_raw(uid: Union[str, bytes]) -> bytes:
    """Convert UID to bytes without padding."""
    if isinstance(uid, bytes):
        return uid
    elif isinstance(uid, str):
        return uid.encode("ascii")
    else:
        return b""


class DICOMAETitleField(StrFixedLenField):
    """DICOM AE Title field - 16 bytes, space-padded per PS3.5 Section 6.2."""

    def __init__(self, name: str, default: bytes = b"") -> None:
        super(DICOMAETitleField, self).__init__(name, default, length=16)

    def i2m(self, pkt: Optional[Packet], val: Any) -> bytes:
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("ascii")
        return val.ljust(16, b" ")[:16]

    def m2i(self, pkt: Optional[Packet], val: bytes) -> bytes:
        return val

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace").rstrip()
        return str(val).rstrip()


class DICOMElementField(Field[bytes, bytes]):
    """DICOM data element field with explicit tag and length encoding."""

    __slots__ = ["tag_group", "tag_elem"]

    def __init__(self, name: str, default: Any, tag_group: int,
                 tag_elem: int) -> None:
        self.tag_group = tag_group
        self.tag_elem = tag_elem
        Field.__init__(self, name, default)

    def addfield(self, pkt: Optional[Packet], s: bytes, val: Any) -> bytes:
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("ascii")
        hdr = struct.pack("<HHI", self.tag_group, self.tag_elem, len(val))
        return s + hdr + val

    def getfield(self, pkt: Optional[Packet], s: bytes) -> Tuple[bytes, bytes]:
        if len(s) < 8:
            return s, b""
        tag_g, tag_e, length = struct.unpack("<HHI", s[:8])
        value = s[8:8 + length]
        return s[8 + length:], value

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if isinstance(val, bytes):
            try:
                return val.decode("ascii").rstrip("\x00")
            except UnicodeDecodeError:
                return val.hex()
        return repr(val)

    def randval(self) -> RandString:
        return RandString(8)


class DICOMUIDField(DICOMElementField):
    """DICOM UID element field with automatic even-length padding."""

    def addfield(self, pkt: Optional[Packet], s: bytes, val: Any) -> bytes:
        val = _uid_to_bytes(val) if val else b""
        return DICOMElementField.addfield(self, pkt, s, val)

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if isinstance(val, bytes):
            return val.decode("ascii").rstrip("\x00")
        return str(val)

    def randval(self) -> str:
        from scapy.volatile import RandNum
        return "1.2.3.%d.%d.%d" % (
            RandNum(1, 99999)._fix(),
            RandNum(1, 99999)._fix(),
            RandNum(1, 99999)._fix()
        )


class DICOMUIDFieldRaw(DICOMElementField):
    """DICOM UID element field without automatic padding."""

    def addfield(self, pkt: Optional[Packet], s: bytes, val: Any) -> bytes:
        val = _uid_to_bytes_raw(val) if val else b""
        return DICOMElementField.addfield(self, pkt, s, val)


class DICOMUSField(DICOMElementField):
    """DICOM Unsigned Short (US) element field."""

    def addfield(self, pkt: Optional[Packet], s: bytes, val: int) -> bytes:
        val_bytes = struct.pack("<H", val)
        return DICOMElementField.addfield(self, pkt, s, val_bytes)

    def getfield(self, pkt: Optional[Packet], s: bytes) -> Tuple[bytes, int]:
        remain, val_bytes = DICOMElementField.getfield(self, pkt, s)
        if len(val_bytes) >= 2:
            return remain, struct.unpack("<H", val_bytes[:2])[0]
        return remain, 0

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        return "0x%04X" % val

    def randval(self) -> RandShort:
        return RandShort()


class DICOMULField(DICOMElementField):
    """DICOM Unsigned Long (UL) element field."""

    def addfield(self, pkt: Optional[Packet], s: bytes, val: int) -> bytes:
        val_bytes = struct.pack("<I", val)
        return DICOMElementField.addfield(self, pkt, s, val_bytes)

    def getfield(self, pkt: Optional[Packet], s: bytes) -> Tuple[bytes, int]:
        remain, val_bytes = DICOMElementField.getfield(self, pkt, s)
        if len(val_bytes) >= 4:
            return remain, struct.unpack("<I", val_bytes[:4])[0]
        return remain, 0

    def randval(self) -> RandInt:
        return RandInt()


class DICOMAEDIMSEField(DICOMElementField):
    """DICOM AE element field for DIMSE - 16 bytes, space-padded."""

    def addfield(self, pkt: Optional[Packet], s: bytes, val: Any) -> bytes:
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("ascii")
        val = val.ljust(16, b" ")[:16]
        return DICOMElementField.addfield(self, pkt, s, val)

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace").strip()
        return str(val).strip()


class DIMSEPacket(Packet):
    """Base class for DIMSE command packets with automatic group length."""

    GROUP_LENGTH_ELEMENT_SIZE = 12

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        group_len = len(pkt)
        header = struct.pack("<HHI", 0x0000, 0x0000, 4)
        header += struct.pack("<I", group_len)
        return header + pkt + pay


DIMSE_COMMAND_FIELDS = {
    0x0001: "C-STORE-RQ",
    0x8001: "C-STORE-RSP",
    0x0020: "C-FIND-RQ",
    0x8020: "C-FIND-RSP",
    0x0010: "C-GET-RQ",
    0x8010: "C-GET-RSP",
    0x0021: "C-MOVE-RQ",
    0x8021: "C-MOVE-RSP",
    0x0030: "C-ECHO-RQ",
    0x8030: "C-ECHO-RSP",
    0x0FFF: "C-CANCEL-RQ",
    0x0100: "N-EVENT-REPORT-RQ",
    0x8100: "N-EVENT-REPORT-RSP",
    0x0110: "N-GET-RQ",
    0x8110: "N-GET-RSP",
    0x0120: "N-SET-RQ",
    0x8120: "N-SET-RSP",
    0x0130: "N-ACTION-RQ",
    0x8130: "N-ACTION-RSP",
    0x0140: "N-CREATE-RQ",
    0x8140: "N-CREATE-RSP",
    0x0150: "N-DELETE-RQ",
    0x8150: "N-DELETE-RSP",
}

DATA_SET_TYPES = {
    0x0000: "Data Set Present",
    0x0001: "Data Set Present",
    0x0101: "No Data Set",
}

PRIORITY_VALUES = {
    0x0000: "MEDIUM",
    0x0001: "HIGH",
    0x0002: "LOW",
}


class C_ECHO_RQ(DIMSEPacket):
    """C-ECHO-RQ DIMSE Command for verification."""

    name = "C-ECHO-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      VERIFICATION_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0030, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-ECHO-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_ECHO_RSP(DIMSEPacket):
    """C-ECHO-RSP DIMSE Response."""

    name = "C-ECHO-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      VERIFICATION_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8030, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-ECHO-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_ECHO_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_STORE_RQ(DIMSEPacket):
    """C-STORE-RQ DIMSE Command for storing DICOM objects."""

    name = "C-STORE-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      CT_IMAGE_STORAGE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0001, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
        DICOMUIDField("affected_sop_instance_uid",
                      "1.2.3.4.5.6.7.8.9", 0x0000, 0x1000),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-STORE-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_STORE_RSP(DIMSEPacket):
    """C-STORE-RSP DIMSE Response."""

    name = "C-STORE-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      CT_IMAGE_STORAGE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8001, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid",
                      "1.2.3.4.5.6.7.8.9", 0x0000, 0x1000),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-STORE-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_STORE_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_FIND_RQ(DIMSEPacket):
    """C-FIND-RQ DIMSE Command for querying DICOM objects."""

    name = "C-FIND-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_FIND_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0020, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-FIND-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_FIND_RSP(DIMSEPacket):
    """C-FIND-RSP DIMSE Response."""

    name = "C-FIND-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_FIND_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8020, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-FIND-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_FIND_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_MOVE_RQ(DIMSEPacket):
    """C-MOVE-RQ DIMSE Command for retrieving DICOM objects."""

    name = "C-MOVE-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0021, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
        DICOMAEDIMSEField("move_destination", b"", 0x0000, 0x0600),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-MOVE-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_MOVE_RSP(DIMSEPacket):
    """C-MOVE-RSP DIMSE Response."""

    name = "C-MOVE-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8021, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUSField("num_remaining", 0, 0x0000, 0x1020),
        DICOMUSField("num_completed", 0, 0x0000, 0x1021),
        DICOMUSField("num_failed", 0, 0x0000, 0x1022),
        DICOMUSField("num_warning", 0, 0x0000, 0x1023),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-MOVE-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_MOVE_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_GET_RQ(DIMSEPacket):
    """C-GET-RQ DIMSE Command for retrieving objects on same association."""

    name = "C-GET-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_GET_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0010, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-GET-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_GET_RSP(DIMSEPacket):
    """C-GET-RSP DIMSE Response."""

    name = "C-GET-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_GET_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8010, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUSField("num_remaining", 0, 0x0000, 0x1020),
        DICOMUSField("num_completed", 0, 0x0000, 0x1021),
        DICOMUSField("num_failed", 0, 0x0000, 0x1022),
        DICOMUSField("num_warning", 0, 0x0000, 0x1023),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-GET-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_GET_RQ):
            return self.message_id_responded == other.message_id
        return 0


def parse_dimse_status(dimse_bytes: bytes) -> Optional[int]:
    """Extract status code from DIMSE response bytes."""
    try:
        if len(dimse_bytes) < 12:
            return None
        cmd_group_len = struct.unpack("<I", dimse_bytes[8:12])[0]
        offset = 12
        group_end_offset = offset + cmd_group_len
        while offset < group_end_offset and offset + 8 <= len(dimse_bytes):
            tag_group, tag_elem = struct.unpack(
                "<HH", dimse_bytes[offset:offset + 4]
            )
            value_len = struct.unpack(
                "<I", dimse_bytes[offset + 4:offset + 8]
            )[0]
            if tag_group == 0x0000 and tag_elem == 0x0900 and value_len == 2:
                return struct.unpack(
                    "<H", dimse_bytes[offset + 8:offset + 10]
                )[0]
            offset += 8 + value_len
    except struct.error:
        return None
    return None


class DICOMGenericItem(Packet):
    """Generic fallback for unrecognized DICOM variable items."""

    name = "DICOM Generic Item"
    fields_desc = [
        StrLenField(
            "data", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.data)
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s


class DICOMVariableItem(Packet):
    """DICOM variable item header with type and length fields."""

    name = "DICOM Variable Item"
    fields_desc = [
        ByteEnumField("item_type", 0x10, ITEM_TYPES),
        ByteField("reserved", 0),
        LenField("length", None, fmt="!H"),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        if self.length is not None:
            if len(s) < self.length:
                raise Scapy_Exception("PDU payload incomplete")
            return s[:self.length], s[self.length:]
        return s, b""

    def guess_payload_class(self, payload: bytes) -> type:
        type_to_class = {
            0x10: DICOMApplicationContext,
            0x20: DICOMPresentationContextRQ,
            0x21: DICOMPresentationContextAC,
            0x30: DICOMAbstractSyntax,
            0x40: DICOMTransferSyntax,
            0x50: DICOMUserInformation,
            0x51: DICOMMaximumLength,
            0x52: DICOMImplementationClassUID,
            0x53: DICOMAsyncOperationsWindow,
            0x54: DICOMSCPSCURoleSelection,
            0x55: DICOMImplementationVersionName,
            0x58: DICOMUserIdentity,
            0x59: DICOMUserIdentityResponse,
        }
        return type_to_class.get(self.item_type, DICOMGenericItem)

    def mysummary(self) -> str:
        return self.sprintf("Item %item_type%")


class DICOMApplicationContext(Packet):
    """DICOM Application Context item."""

    name = "DICOM Application Context"
    fields_desc = [
        StrLenField(
            "uid", _uid_to_bytes(APP_CONTEXT_UID),
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        if isinstance(self.uid, bytes):
            uid = self.uid.decode("ascii").rstrip("\x00")
        else:
            uid = self.uid
        return "AppContext %s" % uid


class DICOMAbstractSyntax(Packet):
    """DICOM Abstract Syntax item."""

    name = "DICOM Abstract Syntax"
    fields_desc = [
        StrLenField(
            "uid", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        if isinstance(self.uid, bytes):
            uid = self.uid.decode("ascii").rstrip("\x00")
        else:
            uid = self.uid
        return "AbstractSyntax %s" % uid


class DICOMTransferSyntax(Packet):
    """DICOM Transfer Syntax item."""

    name = "DICOM Transfer Syntax"
    fields_desc = [
        StrLenField(
            "uid", _uid_to_bytes(DEFAULT_TRANSFER_SYNTAX_UID),
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        if isinstance(self.uid, bytes):
            uid = self.uid.decode("ascii").rstrip("\x00")
        else:
            uid = self.uid
        return "TransferSyntax %s" % uid


class DICOMPresentationContextRQ(Packet):
    """DICOM Presentation Context item for association requests."""

    name = "DICOM Presentation Context RQ"
    fields_desc = [
        ByteField("context_id", 1),
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteField("reserved3", 0),
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=64,
            length_from=lambda pkt: (
                pkt.underlayer.length - 4
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "PresentationContext-RQ ctx_id=%d" % self.context_id


class DICOMPresentationContextAC(Packet):
    """DICOM Presentation Context item for association accepts."""

    name = "DICOM Presentation Context AC"

    RESULT_CODES = {
        0: "acceptance",
        1: "user-rejection",
        2: "no-reason",
        3: "abstract-syntax-not-supported",
        4: "transfer-syntaxes-not-supported",
    }

    fields_desc = [
        ByteField("context_id", 1),
        ByteField("reserved1", 0),
        ByteEnumField("result", 0, RESULT_CODES),
        ByteField("reserved2", 0),
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=8,
            length_from=lambda pkt: (
                pkt.underlayer.length - 4
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return self.sprintf(
            "PresentationContext-AC ctx_id=%context_id% result=%result%"
        )


class DICOMMaximumLength(Packet):
    """DICOM Maximum Length sub-item."""

    name = "DICOM Maximum Length"
    fields_desc = [
        IntField("max_pdu_length", 16384),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "MaxLength %d" % self.max_pdu_length


class DICOMImplementationClassUID(Packet):
    """DICOM Implementation Class UID sub-item."""

    name = "DICOM Implementation Class UID"
    fields_desc = [
        StrLenField(
            "uid", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        if isinstance(self.uid, bytes):
            uid = self.uid.decode("ascii").rstrip("\x00")
        else:
            uid = self.uid
        return "ImplClassUID %s" % uid


class DICOMImplementationVersionName(Packet):
    """DICOM Implementation Version Name sub-item."""

    name = "DICOM Implementation Version Name"
    fields_desc = [
        StrLenField(
            "name", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.name)
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        if isinstance(self.name, bytes):
            name = self.name.decode("ascii").rstrip("\x00")
        else:
            name = self.name
        return "ImplVersion %s" % name


class DICOMAsyncOperationsWindow(Packet):
    """DICOM Asynchronous Operations Window sub-item."""

    name = "DICOM Async Operations Window"
    fields_desc = [
        ShortField("max_ops_invoked", 1),
        ShortField("max_ops_performed", 1),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "AsyncOps inv=%d perf=%d" % (
            self.max_ops_invoked, self.max_ops_performed
        )


class DICOMSCPSCURoleSelection(Packet):
    """DICOM SCP/SCU Role Selection sub-item."""

    name = "DICOM SCP/SCU Role Selection"
    fields_desc = [
        FieldLenField("uid_length", None, length_of="sop_class_uid", fmt="!H"),
        StrLenField("sop_class_uid", b"",
                    length_from=lambda pkt: pkt.uid_length),
        ByteField("scu_role", 0),
        ByteField("scp_role", 0),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "RoleSelection SCU=%d SCP=%d" % (self.scu_role, self.scp_role)


USER_IDENTITY_TYPES = {
    1: "Username",
    2: "Username and Passcode",
    3: "Kerberos Service Ticket",
    4: "SAML Assertion",
    5: "JSON Web Token (JWT)",
}


class DICOMUserIdentity(Packet):
    """DICOM User Identity sub-item."""

    name = "DICOM User Identity"
    fields_desc = [
        ByteEnumField("user_identity_type", 1, USER_IDENTITY_TYPES),
        ByteField("positive_response_requested", 0),
        FieldLenField("primary_field_length", None,
                      length_of="primary_field", fmt="!H"),
        StrLenField("primary_field", b"",
                    length_from=lambda pkt: pkt.primary_field_length),
        ConditionalField(
            FieldLenField("secondary_field_length", None,
                          length_of="secondary_field", fmt="!H"),
            lambda pkt: pkt.user_identity_type == 2
        ),
        ConditionalField(
            StrLenField("secondary_field", b"",
                        length_from=lambda pkt: pkt.secondary_field_length),
            lambda pkt: pkt.user_identity_type == 2
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return self.sprintf("UserIdentity %user_identity_type%")


class DICOMUserIdentityResponse(Packet):
    """DICOM User Identity Server Response sub-item."""

    name = "DICOM User Identity Response"
    fields_desc = [
        FieldLenField("response_length", None,
                      length_of="server_response", fmt="!H"),
        StrLenField("server_response", b"",
                    length_from=lambda pkt: pkt.response_length),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "UserIdentityResponse"


class DICOMUserInformation(Packet):
    """DICOM User Information item."""

    name = "DICOM User Information"
    fields_desc = [
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=32,
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        return "UserInfo (%d items)" % len(self.sub_items)


bind_layers(DICOMVariableItem, DICOMApplicationContext, item_type=0x10)
bind_layers(DICOMVariableItem, DICOMPresentationContextRQ, item_type=0x20)
bind_layers(DICOMVariableItem, DICOMPresentationContextAC, item_type=0x21)
bind_layers(DICOMVariableItem, DICOMAbstractSyntax, item_type=0x30)
bind_layers(DICOMVariableItem, DICOMTransferSyntax, item_type=0x40)
bind_layers(DICOMVariableItem, DICOMUserInformation, item_type=0x50)
bind_layers(DICOMVariableItem, DICOMMaximumLength, item_type=0x51)
bind_layers(DICOMVariableItem, DICOMImplementationClassUID, item_type=0x52)
bind_layers(DICOMVariableItem, DICOMAsyncOperationsWindow, item_type=0x53)
bind_layers(DICOMVariableItem, DICOMSCPSCURoleSelection, item_type=0x54)
bind_layers(DICOMVariableItem, DICOMImplementationVersionName, item_type=0x55)
bind_layers(DICOMVariableItem, DICOMUserIdentity, item_type=0x58)
bind_layers(DICOMVariableItem, DICOMUserIdentityResponse, item_type=0x59)
bind_layers(DICOMVariableItem, DICOMGenericItem)


class DICOM(Packet):
    """DICOM Upper Layer (UL) PDU header."""

    name = "DICOM UL"
    fields_desc = [
        ByteEnumField("pdu_type", 0x01, PDU_TYPES),
        ByteField("reserved1", 0),
        LenField("length", None, fmt="!I"),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        if self.length is not None:
            return s[:self.length], s[self.length:]
        return s, b""

    def mysummary(self) -> str:
        return self.sprintf("DICOM %pdu_type%")


class PresentationDataValueItem(Packet):
    """Presentation Data Value (PDV) item within P-DATA-TF PDU."""

    name = "PresentationDataValueItem"
    fields_desc = [
        FieldLenField("length", None, length_of="data", fmt="!I",
                      adjust=lambda pkt, x: x + 2),
        ByteField("context_id", 1),
        BitField("reserved_bits", 0, 6),
        BitField("is_last", 0, 1),
        BitField("is_command", 0, 1),
        StrLenField("data", b"",
                    length_from=lambda pkt: max(0, (pkt.length or 2) - 2)),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        cmd_or_data = "CMD" if self.is_command else "DATA"
        last = " LAST" if self.is_last else ""
        return "PDV ctx=%d %s%s len=%d" % (
            self.context_id, cmd_or_data, last, len(self.data)
        )


class A_ASSOCIATE_RQ(Packet):
    """A-ASSOCIATE-RQ PDU for initiating DICOM associations."""

    name = "A-ASSOCIATE-RQ"
    fields_desc = [
        ShortField("protocol_version", 1),
        ShortField("reserved1", 0),
        DICOMAETitleField("called_ae_title", b""),
        DICOMAETitleField("calling_ae_title", b""),
        StrFixedLenField("reserved2", b"\x00" * 32, 32),
        PacketListField(
            "variable_items", [],
            DICOMVariableItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length - 68
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        if isinstance(self.called_ae_title, bytes):
            called = self.called_ae_title.strip()
            called = called.decode("ascii", errors="replace")
        else:
            called = self.called_ae_title
        if isinstance(self.calling_ae_title, bytes):
            calling = self.calling_ae_title.strip()
            calling = calling.decode("ascii", errors="replace")
        else:
            calling = self.calling_ae_title
        return "A-ASSOCIATE-RQ %s -> %s" % (calling, called)

    def hashret(self) -> bytes:
        if isinstance(self.called_ae_title, bytes):
            called = self.called_ae_title
        else:
            called = self.called_ae_title.encode()
        if isinstance(self.calling_ae_title, bytes):
            calling = self.calling_ae_title
        else:
            calling = self.calling_ae_title.encode()
        return called + calling


class A_ASSOCIATE_AC(Packet):
    """A-ASSOCIATE-AC PDU for accepting DICOM associations."""

    name = "A-ASSOCIATE-AC"
    fields_desc = [
        ShortField("protocol_version", 1),
        ShortField("reserved1", 0),
        DICOMAETitleField("called_ae_title", b""),
        DICOMAETitleField("calling_ae_title", b""),
        StrFixedLenField("reserved2", b"\x00" * 32, 32),
        PacketListField(
            "variable_items", [],
            DICOMVariableItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length - 68
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        if isinstance(self.called_ae_title, bytes):
            called = self.called_ae_title.strip()
            called = called.decode("ascii", errors="replace")
        else:
            called = self.called_ae_title
        if isinstance(self.calling_ae_title, bytes):
            calling = self.calling_ae_title.strip()
            calling = calling.decode("ascii", errors="replace")
        else:
            calling = self.calling_ae_title
        return "A-ASSOCIATE-AC %s <- %s" % (calling, called)

    def hashret(self) -> bytes:
        if isinstance(self.called_ae_title, bytes):
            called = self.called_ae_title
        else:
            called = self.called_ae_title.encode()
        if isinstance(self.calling_ae_title, bytes):
            calling = self.calling_ae_title
        else:
            calling = self.calling_ae_title.encode()
        return called + calling

    def answers(self, other: Packet) -> bool:
        return isinstance(other, A_ASSOCIATE_RQ)


class A_ASSOCIATE_RJ(Packet):
    """A-ASSOCIATE-RJ PDU for rejecting DICOM associations."""

    name = "A-ASSOCIATE-RJ"

    RESULT_CODES = {
        1: "rejected-permanent",
        2: "rejected-transient",
    }

    SOURCE_CODES = {
        1: "DICOM UL service-user",
        2: "DICOM UL service-provider (ACSE)",
        3: "DICOM UL service-provider (Presentation)",
    }

    fields_desc = [
        ByteField("reserved1", 0),
        ByteEnumField("result", 1, RESULT_CODES),
        ByteEnumField("source", 1, SOURCE_CODES),
        ByteField("reason_diag", 1),
    ]

    def mysummary(self) -> str:
        return self.sprintf("A-ASSOCIATE-RJ %result% %source%")

    def answers(self, other: Packet) -> bool:
        return isinstance(other, A_ASSOCIATE_RQ)


class P_DATA_TF(Packet):
    """P-DATA-TF PDU for transferring DICOM data."""

    name = "P-DATA-TF"
    fields_desc = [
        PacketListField(
            "pdv_items", [],
            PresentationDataValueItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        return "P-DATA-TF (%d PDVs)" % len(self.pdv_items)


class A_RELEASE_RQ(Packet):
    """A-RELEASE-RQ PDU for requesting association release."""

    name = "A-RELEASE-RQ"
    fields_desc = [IntField("reserved1", 0)]

    def mysummary(self) -> str:
        return "A-RELEASE-RQ"


class A_RELEASE_RP(Packet):
    """A-RELEASE-RP PDU for confirming association release."""

    name = "A-RELEASE-RP"
    fields_desc = [IntField("reserved1", 0)]

    def mysummary(self) -> str:
        return "A-RELEASE-RP"

    def answers(self, other: Packet) -> bool:
        return isinstance(other, A_RELEASE_RQ)


class A_ABORT(Packet):
    """A-ABORT PDU for aborting DICOM associations."""

    name = "A-ABORT"

    SOURCE_CODES = {
        0: "DICOM UL service-user",
        2: "DICOM UL service-provider",
    }

    fields_desc = [
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteEnumField("source", 0, SOURCE_CODES),
        ByteField("reason_diag", 0),
    ]

    def mysummary(self) -> str:
        return self.sprintf("A-ABORT %source%")


bind_layers(TCP, DICOM, dport=DICOM_PORT)
bind_layers(TCP, DICOM, sport=DICOM_PORT)
bind_layers(DICOM, A_ASSOCIATE_RQ, pdu_type=0x01)
bind_layers(DICOM, A_ASSOCIATE_AC, pdu_type=0x02)
bind_layers(DICOM, A_ASSOCIATE_RJ, pdu_type=0x03)
bind_layers(DICOM, P_DATA_TF, pdu_type=0x04)
bind_layers(DICOM, A_RELEASE_RQ, pdu_type=0x05)
bind_layers(DICOM, A_RELEASE_RP, pdu_type=0x06)
bind_layers(DICOM, A_ABORT, pdu_type=0x07)


def build_presentation_context_rq(context_id: int,
                                  abstract_syntax_uid: str,
                                  transfer_syntax_uids: List[str]) -> Packet:
    """Build a Presentation Context RQ item."""
    abs_uid = _uid_to_bytes(abstract_syntax_uid)
    abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid=abs_uid)

    sub_items = [abs_syn]
    for ts_uid in transfer_syntax_uids:
        ts = DICOMVariableItem() / DICOMTransferSyntax(uid=_uid_to_bytes(ts_uid))
        sub_items.append(ts)

    return DICOMVariableItem() / DICOMPresentationContextRQ(
        context_id=context_id,
        sub_items=sub_items,
    )


def build_user_information(max_pdu_length: int = 16384,
                           implementation_class_uid: Optional[str] = None,
                           implementation_version: Optional[str] = None
                           ) -> Packet:
    """Build a User Information item."""
    sub_items = [
        DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=max_pdu_length)
    ]

    if implementation_class_uid:
        uid = _uid_to_bytes(implementation_class_uid)
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationClassUID(uid=uid)
        )

    if implementation_version:
        if isinstance(implementation_version, bytes):
            ver_bytes = implementation_version
        else:
            ver_bytes = implementation_version.encode('ascii')
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationVersionName(name=ver_bytes)
        )

    return DICOMVariableItem() / DICOMUserInformation(sub_items=sub_items)


class DICOMSocket:
    """DICOM application-layer socket for associations and DIMSE operations."""

    def __init__(self, dst_ip: str, dst_port: int, dst_ae: str,
                 src_ae: str = "SCAPY_SCU", read_timeout: int = 10) -> None:
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dst_ae = dst_ae
        self.src_ae = src_ae
        self.sock: Optional[socket.socket] = None
        self.stream: Optional[StreamSocket] = None
        self.assoc_established = False
        self.accepted_contexts: Dict[int, Tuple[str, str]] = {}
        self.read_timeout = read_timeout
        self._current_message_id_counter = int(time.time()) % 50000
        self._proposed_max_pdu = 16384
        self.max_pdu_length = 16384
        self._proposed_context_map: Dict[int, str] = {}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        if self.assoc_established:
            try:
                self.release()
            except (socket.error, socket.timeout, OSError):
                pass
        self.close()
        return False

    def connect(self) -> bool:
        try:
            self.sock = socket.create_connection(
                (self.dst_ip, self.dst_port),
                timeout=self.read_timeout,
            )
            self.stream = StreamSocket(self.sock, basecls=DICOM)
            return True
        except (socket.error, socket.timeout, OSError) as e:
            log.error("Connection failed: %s", e)
            return False

    def send(self, pkt: Packet) -> None:
        self.stream.send(pkt)

    def recv(self) -> Optional[Packet]:
        try:
            return self.stream.recv()
        except socket.timeout:
            return None
        except (socket.error, OSError) as e:
            log.error("Error receiving PDU: %s", e)
            return None

    def sr1(self, pkt: Packet) -> Optional[Packet]:
        try:
            return self.stream.sr1(pkt, timeout=self.read_timeout)
        except socket.timeout:
            return None
        except (socket.error, OSError) as e:
            log.error("Error in sr1: %s", e)
            return None

    def send_raw_bytes(self, raw_bytes: bytes) -> None:
        self.sock.sendall(raw_bytes)

    def associate(self, requested_contexts: Optional[Dict[str, List[str]]] = None
                  ) -> bool:
        if not self.stream and not self.connect():
            return False

        if requested_contexts is None:
            requested_contexts = {
                VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
            }

        self._proposed_context_map = {}

        variable_items: List[Packet] = [
            DICOMVariableItem() / DICOMApplicationContext()
        ]

        ctx_id = 1
        for abs_syntax, trn_syntaxes in requested_contexts.items():
            self._proposed_context_map[ctx_id] = abs_syntax
            pctx = build_presentation_context_rq(ctx_id, abs_syntax, trn_syntaxes)
            variable_items.append(pctx)
            ctx_id += 2

        user_info = build_user_information(max_pdu_length=self._proposed_max_pdu)
        variable_items.append(user_info)

        assoc_rq = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.dst_ae,
            calling_ae_title=self.src_ae,
            variable_items=variable_items,
        )

        response = self.sr1(assoc_rq)

        if response:
            if response.haslayer(A_ASSOCIATE_AC):
                self.assoc_established = True
                self._parse_accepted_contexts(response)
                self._parse_max_pdu_length(response)
                return True
            elif response.haslayer(A_ASSOCIATE_RJ):
                log.error(
                    "Association rejected: result=%d, source=%d, reason=%d",
                    response[A_ASSOCIATE_RJ].result,
                    response[A_ASSOCIATE_RJ].source,
                    response[A_ASSOCIATE_RJ].reason_diag,
                )
                return False

        log.error("Association failed: no valid response received")
        return False

    def _parse_max_pdu_length(self, response: Packet) -> None:
        try:
            for item in response[A_ASSOCIATE_AC].variable_items:
                if item.item_type != 0x50:
                    continue
                if not item.haslayer(DICOMUserInformation):
                    continue
                user_info = item[DICOMUserInformation]
                for sub_item in user_info.sub_items:
                    if sub_item.item_type != 0x51:
                        continue
                    if not sub_item.haslayer(DICOMMaximumLength):
                        continue
                    max_len = sub_item[DICOMMaximumLength]
                    server_max = max_len.max_pdu_length
                    self.max_pdu_length = min(
                        self._proposed_max_pdu, server_max
                    )
                    return
        except (KeyError, IndexError, AttributeError):
            pass
        self.max_pdu_length = self._proposed_max_pdu

    def _parse_accepted_contexts(self, response: Packet) -> None:
        for item in response[A_ASSOCIATE_AC].variable_items:
            if item.item_type != 0x21:
                continue
            if not item.haslayer(DICOMPresentationContextAC):
                continue
            pctx = item[DICOMPresentationContextAC]
            ctx_id = pctx.context_id
            result = pctx.result

            if result != 0:
                continue

            abs_syntax = self._proposed_context_map.get(ctx_id)
            if abs_syntax is None:
                continue

            for sub_item in pctx.sub_items:
                if sub_item.item_type != 0x40:
                    continue
                if not sub_item.haslayer(DICOMTransferSyntax):
                    continue
                ts_uid = sub_item[DICOMTransferSyntax].uid
                if isinstance(ts_uid, bytes):
                    ts_uid = ts_uid.rstrip(b"\x00")
                    ts_uid = ts_uid.decode("ascii")
                self.accepted_contexts[ctx_id] = (abs_syntax, ts_uid)
                break

    def _get_next_message_id(self) -> int:
        self._current_message_id_counter += 1
        return self._current_message_id_counter & 0xFFFF

    def _find_accepted_context_id(self, sop_class_uid: str,
                                  transfer_syntax_uid: Optional[str] = None
                                  ) -> Optional[int]:
        for ctx_id, (abs_syntax, ts_syntax) in self.accepted_contexts.items():
            if abs_syntax == sop_class_uid:
                if transfer_syntax_uid is None or transfer_syntax_uid == ts_syntax:
                    return ctx_id
        return None

    def c_echo(self) -> Optional[int]:
        if not self.assoc_established:
            log.error("Association not established")
            return None

        echo_ctx_id = self._find_accepted_context_id(VERIFICATION_SOP_CLASS_UID)
        if echo_ctx_id is None:
            log.error("No accepted context for Verification SOP Class")
            return None

        msg_id = self._get_next_message_id()
        dimse_rq = bytes(C_ECHO_RQ(message_id=msg_id))

        pdv_rq = PresentationDataValueItem(
            context_id=echo_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        pdata_rq = DICOM() / P_DATA_TF(pdv_items=[pdv_rq])

        response = self.sr1(pdata_rq)

        if response and response.haslayer(P_DATA_TF):
            pdv_items = response[P_DATA_TF].pdv_items
            if pdv_items:
                pdv_rsp = pdv_items[0]
                data = pdv_rsp.data
                if isinstance(data, str):
                    data = data.encode("latin-1")
                return parse_dimse_status(data)
        return None

    def c_store(self, dataset_bytes: bytes, sop_class_uid: str,
                sop_instance_uid: str, transfer_syntax_uid: str
                ) -> Optional[int]:
        if not self.assoc_established:
            log.error("Association not established")
            return None

        store_ctx_id = self._find_accepted_context_id(
            sop_class_uid,
            transfer_syntax_uid,
        )
        if store_ctx_id is None:
            log.error(
                "No accepted context for SOP %s with TS %s",
                sop_class_uid,
                transfer_syntax_uid,
            )
            return None

        msg_id = self._get_next_message_id()

        dimse_rq = bytes(C_STORE_RQ(
            affected_sop_class_uid=sop_class_uid,
            affected_sop_instance_uid=sop_instance_uid,
            message_id=msg_id,
        ))

        cmd_pdv = PresentationDataValueItem(
            context_id=store_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        pdata_cmd = DICOM() / P_DATA_TF(pdv_items=[cmd_pdv])
        self.send(pdata_cmd)

        max_pdv_data = self.max_pdu_length - 12

        if len(dataset_bytes) <= max_pdv_data:
            data_pdv = PresentationDataValueItem(
                context_id=store_ctx_id,
                data=dataset_bytes,
                is_command=0,
                is_last=1,
            )
            pdata_data = DICOM() / P_DATA_TF(pdv_items=[data_pdv])
            self.send(pdata_data)
        else:
            offset = 0
            while offset < len(dataset_bytes):
                chunk = dataset_bytes[offset:offset + max_pdv_data]
                is_last = 1 if (offset + len(chunk) >= len(dataset_bytes)) else 0
                data_pdv = PresentationDataValueItem(
                    context_id=store_ctx_id,
                    data=chunk,
                    is_command=0,
                    is_last=is_last,
                )
                pdata_data = DICOM() / P_DATA_TF(pdv_items=[data_pdv])
                self.send(pdata_data)
                offset += len(chunk)

        response = self.recv()

        if response and response.haslayer(P_DATA_TF):
            pdv_items = response[P_DATA_TF].pdv_items
            if pdv_items:
                pdv_rsp = pdv_items[0]
                data = pdv_rsp.data
                if isinstance(data, str):
                    data = data.encode("latin-1")
                return parse_dimse_status(data)
        return None

    def release(self) -> bool:
        if not self.assoc_established:
            return True

        release_rq = DICOM() / A_RELEASE_RQ()
        response = self.sr1(release_rq)
        self.close()

        if response:
            return response.haslayer(A_RELEASE_RP)
        return False

    def close(self) -> None:
        if self.stream:
            try:
                self.stream.close()
            except (socket.error, OSError):
                pass
        self.sock = None
        self.stream = None
        self.assoc_established = False