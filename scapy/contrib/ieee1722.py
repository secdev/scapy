# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Naresh Nayak <Naresh.Nayak@hs-furtwangen.de>

# scapy.contrib.description = IEEE 1722 serialization formats
# scapy.contrib.status = loads

"""
IEEE 1722 serialization formats for Scapy
"""

import struct
from enum import Enum

from scapy.all import UDP, Ether, bind_layers  # pylint: disable=no-name-in-module
from scapy.fields import (
    BitEnumField,
    BitField,
    BitFieldLenField,
    ByteField,
    ConditionalField,
    FieldLenField,
    IntField,
    LenField,
    LongField,
    PacketListField,
    ShortField,
    StrFixedLenField,
    XByteEnumField,
    XByteField,
    XIntField,
    XLongField,
    XShortField,
)
from scapy.packet import Packet


class AvtpStreamType(Enum):
    """
    AVTP Stream Subtypes - Table 7 - IEEE 1722-2025
    """

    IIDC_61883 = 0x0
    MMA_STREAM = 0x1
    AAF = 0x2
    CVF = 0x3
    CRF = 0x4
    TSCF = 0x5
    SVF = 0x6
    RVF = 0x7
    AEF_CONTINUOUS = 0x6E
    VSF_STREAM = 0x6F
    EF_STREAM = 0x7F
    NTSCF = 0x82
    IEEE_8021_MLAA = 0xEB
    ESCF = 0xEC
    EECF = 0xED
    AEF_DISCRETE = 0xEE
    ADP = 0xFA
    AECP = 0xFB
    ACMP = 0xFC
    MAAP = 0xFE
    EF_CONTROL = 0xFF


class AvtpAcfType(Enum):
    """
    AVTP ACF Message Types - Table 23 - IEEE 1722-2025
    """

    ACF_FLEXRAY = 0x0
    ACF_CAN = 0x1
    ACF_CAN_BRIEF = 0x2
    ACF_LIN = 0x3
    ACF_MOST = 0x4
    ACF_GPC = 0x5
    ACF_SERIAL = 0x6
    ACF_PARALLEL = 0x7
    ACF_SENSOR = 0x8
    ACF_SENSOR_BRIEF = 0x9
    ACF_AECP = 0xA
    ACF_ANCILLARY = 0xB
    ACF_GISF = 0xC
    ACF_GBB = 0xD
    ACF_ABB = 0xE
    ACF_I2C = 0xF
    ACF_I2C_BRIEF = 0x10
    ACF_CAN_XL = 0x11
    ACF_CAN_XL_BRIEF = 0x12
    ACF_CAN_V2 = 0x21
    ACF_CAN_BRIEF_V2 = 0x22
    ACF_LIN_V2 = 0x23
    ACF_CHECKSUM = 0x76
    ACF_CRC = 0x77


class AvtpHeaderVersion(Enum):
    """
    AVTP Header Versions - Table 8 - IEEE 1722-2025
    """

    V0 = 0
    V1 = 1
    AVTP_MAX_HEADER_VERSION = 1


class AvtpCommonHeader(Packet):
    """
    Common Header (Clause 4.7.3) for the AVTP-2025
    """

    name = "AVTP Common Header"
    fields_desc = [
        ConditionalField(
            IntField(name="encapsulation_sequence_num", default=0),
            lambda pkt: isinstance(pkt.underlayer, UDP),
        ),
        XByteEnumField(
            name="subtype",
            default=None,
            enum={i.name: i.value for i in AvtpStreamType},
        ),
        BitField(name="h", size=1, default=0),
        BitField(name="version", size=3, default=0),
    ]
    common_header_variants = {}

    @classmethod
    def register_variant(cls):
        """
        Register a variant of the common header based on subtype and version.
        We use a tuple of (subtype, version) as the key to store the variant
        class in a dictionary. For registering a variant, the subclass should
        set the default values for subtype and version fields.
        """

        if cls.subtype.default is not None:
            key = (cls.subtype.default, cls.version.default)
            cls.common_header_variants[key] = cls

    @classmethod
    def dispatch_hook(cls, pkt=None, **kargs):  # pylint: disable=unused-argument
        """
        Dispatch the appropriate class based on the parsed subtype and version.
        """
        if pkt is not None:
            if isinstance(kargs["_underlayer"], UDP):
                parsed_type = ord(pkt[4:5])
                parsed_version = (ord(pkt[5:6]) & 0x70) >> 4
            else:
                parsed_type = ord(pkt[0:1])
                parsed_version = (ord(pkt[1:2]) & 0x70) >> 4

            key = (parsed_type, parsed_version)
            return cls.common_header_variants.get(key, cls)
        return cls


class _CommonStreamHeaderV0(AvtpCommonHeader):
    name = "AVTP Common Stream Header v0"
    fields_desc = [
        ConditionalField(
            IntField(name="encapsulation_sequence_num", default=0),
            lambda pkt: isinstance(pkt.underlayer, UDP),
        ),
        XByteEnumField(
            name="subtype",
            default=None,
            enum={i.name: i.value for i in AvtpStreamType},
        ),
        BitField(name="h", size=1, default=0),
        BitField(name="version", size=3, default=0),
        XByteField(name="sequence_num", default=0),
        BitField(name="format_specific_data_1", size=7, default=0),
        BitField(name="tu", size=1, default=0),
        XLongField(name="stream_id", default=0),
        XIntField(name="avtp_timestamp", default=0),
        XIntField(name="format_specific_data_2", default=0),
        LenField(name="stream_data_length", default=None),
        XShortField(name="format_specific_data_3", default=0),
    ]


class _CommonStreamHeaderV1(AvtpCommonHeader):
    name = "AVTP Common Stream Header v1"
    fields_desc = [
        ConditionalField(
            IntField(name="encapsulation_sequence_num", default=0),
            lambda pkt: isinstance(pkt.underlayer, UDP),
        ),
        XByteEnumField(
            name="subtype",
            default=None,
            enum={i.name: i.value for i in AvtpStreamType},
        ),
        BitField(name="h", size=1, default=0),
        BitField(name="version", size=3, default=1),
        BitField(name="mr", size=1, default=0),
        BitField(name="f_s_d", size=2, default=0),
        BitField(name="tv", size=1, default=0),
        XByteField(name="format_specific_data_0", default=0),
        BitField(name="format_specific_data_1", size=7, default=0),
        BitField(name="tu", size=1, default=0),
        XLongField(name="stream_id", default=0),
        XIntField(name="sequence_num", default=0),
        XLongField(name="avtp_timestamp", default=0),
        XLongField(name="ptp_grandmaster_identity", default=0),
        XIntField(name="format_specific_data_2", default=0),
        LenField(name="stream_data_length", default=None),
        XShortField(name="format_specific_data_3", default=0),
    ]


class AvtpCommonStreamHeader(AvtpCommonHeader):
    """
    Common Stream Header (Clause 4.7.4) for the AVTP-2025
    """

    name = "AVTP Common Stream Header"

    @classmethod
    def dispatch_hook(cls, pkt=None, **kargs):
        version = 0
        if "version" in kargs:
            version = kargs.get("version", 0) == 1
        else:
            if pkt is not None:
                parsed_version = (ord(pkt[1:2]) & 0x70) >> 4
                version = parsed_version == 1
        return _CommonStreamHeaderV1 if version else _CommonStreamHeaderV0


class AvtpCommonControlHeader(AvtpCommonHeader):
    """
    Common Control Header (Clause 4.7.5) for the AVTP-2025
    """

    name = "AVTP Common Control Header"
    fields_desc = [
        ConditionalField(
            IntField(name="encapsulation_sequence_num", default=0),
            lambda pkt: isinstance(pkt.underlayer, UDP),
        ),
        XByteEnumField(
            name="subtype",
            default=None,
            enum={i.name: i.value for i in AvtpStreamType},
        ),
        BitField(name="sv", size=1, default=0),
        BitField(name="version", size=3, default=0),
        BitField(name="format_specific_data", size=9, default=0),
        BitField(name="control_data_length", size=11, default=None),
        XLongField(name="stream_id", default=0),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Update the length fields on packet building
        pay_length = len(pay) if len(pay) < 2**11 else 0
        current_length = (
            int.from_bytes(pkt[-10:-8], byteorder="big") & 0xF800
        ) | pay_length
        pkt = pkt[:-10] + struct.pack("!H", current_length) + pkt[-8:]
        pkt += pay
        return pkt


class _AlternativeHeaderV0(AvtpCommonHeader):
    name = "AVTP Alternative Header v0"
    fields_desc = [
        ConditionalField(
            IntField(name="encapsulation_sequence_num", default=0),
            lambda pkt: isinstance(pkt.underlayer, UDP),
        ),
        XByteEnumField(
            name="subtype",
            default=None,
            enum={i.name: i.value for i in AvtpStreamType},
        ),
        BitField(name="h", size=1, default=0),
        BitField(name="version", size=3, default=0),
    ]


class _AlternativeHeaderV1(AvtpCommonHeader):
    name = "AVTP Alternative Header v1"
    fields_desc = [
        ConditionalField(
            IntField(name="encapsulation_sequence_num", default=0),
            lambda pkt: isinstance(pkt.underlayer, UDP),
        ),
        XByteEnumField(
            name="subtype",
            default=None,
            enum={i.name: i.value for i in AvtpStreamType},
        ),
        BitField(name="h", size=1, default=0),
        BitField(name="version", size=3, default=0),
        BitField(name="reserved_1", size=20, default=0),
        XIntField(name="sequence_num", default=0),
        XLongField(name="gptp_grandmaster_identity", default=0),
        BitField(name="reserved_2", size=12, default=0),
    ]


class AvtpAlternativeHeader(AvtpCommonHeader):
    """
    Alternative Header (Clause 4.7.6) for the AVTP-2025
    """

    name = "AVTP Alternative Header"

    @classmethod
    def dispatch_hook(cls, pkt=None, **kargs):
        version = 0
        if "version" in kargs:
            version = kargs.get("version", 0) == 1
        else:
            if pkt is not None:
                parsed_version = (ord(pkt[1:2]) & 0x70) >> 4
                version = parsed_version == 1
        return _AlternativeHeaderV1 if version else _AlternativeHeaderV0


class AvtpAcfHeader(Packet):
    """
    Header for ACF Messages - Clause 9.4 - IEEE 1722 - 2025
    """

    name = "ACF Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=None,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
    ]

    acf_variants = {}

    @classmethod
    def register_variant(cls):
        """
        Register a variant of the ACF header based on acf_msg_type.
        """
        if cls.acf_msg_type.default is not None:
            cls.acf_variants[cls.acf_msg_type.default] = cls

    @classmethod
    def dispatch_hook(cls, pkt=None, **kargs):  # pylint: disable=unused-argument
        """
        Dispatch to the appropriate ACF header variant based on the acf_msg_type field.
        """
        if pkt is not None:
            tmp_type = (ord(pkt[:1]) & 0xFE) >> 1
            return cls.acf_variants.get(tmp_type, cls)
        return cls


class AvtpAcfFlexrayHeader(AvtpAcfHeader):
    """
    Header for FlexRay Messages - Clause 9.4.2 - IEEE 1722 - 2025
    """

    name = "ACF Flexray Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_FLEXRAY,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="fr_bus_id", size=5, default=0),
        BitField(name="rsv", size=2, default=0),
        BitField(name="chan", size=2, default=0),
        BitField(name="str", size=1, default=0),
        BitField(name="syn", size=1, default=0),
        BitField(name="pre", size=1, default=0),
        BitField(name="nfi", size=1, default=0),
        LongField(name="message_timestamp", default=0),
        BitField(name="fr_frame_id", size=11, default=0),
        BitField(name="reserved", size=15, default=0),
        BitField(name="cycle", size=6, default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        """
        Extract padding from the payload.
        """
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfCanHeader(AvtpAcfHeader):
    """
    Header for CAN/CAN-FD Messages - Clause 9.4.3 - IEEE 1722 - 2025
    """

    name = "ACF CAN Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_CAN,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rtr", size=1, default=0),
        BitField(name="eff", size=1, default=0),
        BitField(name="brs", size=1, default=0),
        BitField(name="fdf", size=1, default=0),
        BitField(name="esi", size=1, default=0),
        BitField(name="rsv1", size=3, default=0),
        BitField(name="can_bus_id", size=5, default=0),
        LongField(name="message_timestamp", default=0),
        BitField(name="rsv2", size=3, default=0),
        BitField(name="can_identifier", size=29, default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfCanV2Header(AvtpAcfHeader):
    """
    Header for CAN/CAN-FD version 2 Messages - Clause 9.4.3 - IEEE 1722 - 2025
    """

    name = "ACF CAN V2 Header"

    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_CAN_V2,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rtr", size=1, default=0),
        BitField(name="eff", size=1, default=0),
        BitField(name="can_bus_id", size=11, default=0),
        LongField(name="message_timestamp", default=0),
        BitField(name="brs", size=1, default=0),
        BitField(name="fdf", size=1, default=0),
        BitField(name="esi", size=1, default=0),
        BitField(name="can_identifier", size=29, default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfCanBriefHeader(AvtpAcfHeader):
    """
    Header for CAN/CAN-FD Brief Messages - Clause 9.4.4 - IEEE 1722 - 2025
    """

    name = "ACF CAN BRIEF Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_CAN_BRIEF,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rtr", size=1, default=0),
        BitField(name="eff", size=1, default=0),
        BitField(name="brs", size=1, default=0),
        BitField(name="fdf", size=1, default=0),
        BitField(name="esi", size=1, default=0),
        BitField(name="rsv1", size=3, default=0),
        BitField(name="can_bus_id", size=5, default=0),
        BitField(name="rsv2", size=3, default=0),
        BitField(name="can_identifier", size=29, default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfCanBriefV2Header(AvtpAcfHeader):
    """
    Header for CAN/CAN-FD Brief version 2 Messages - Clause 9.4.4 - IEEE 1722 - 2025
    """

    name = "ACF CAN Brief V2 Header"

    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_CAN_BRIEF_V2,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rtr", size=1, default=0),
        BitField(name="eff", size=1, default=0),
        BitField(name="can_bus_id", size=11, default=0),
        BitField(name="brs", size=1, default=0),
        BitField(name="fdf", size=1, default=0),
        BitField(name="esi", size=1, default=0),
        BitField(name="can_identifier", size=29, default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfLinHeader(AvtpAcfHeader):
    """
    Header for LIN Messages - Clause 9.4.5 - IEEE 1722 - 2025
    """

    name = "ACF LIN Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_LIN,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="lin_bus_id", size=5, default=0),
        XByteField(name="lin_identifier", default=0),
        LongField(name="message_timestamp", default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfLinV2Header(AvtpAcfHeader):
    """
    Header for LIN Messages - Clause 9.4.5 - IEEE 1722 - 2025
    """

    name = "ACF LIN V2 Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_LIN_V2,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rsv", size=2, default=0),
        BitField(name="lin_bus_id", size=11, default=0),
        LongField(name="message_timestamp", default=0),
        StrFixedLenField("reserved", None, length=3),
        XByteField(name="lin_identifier", default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfMostHeader(AvtpAcfHeader):
    """
    Header for MOST Messages - Clause 9.4.6 - IEEE 1722 - 2025
    """

    name = "ACF MOST Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_MOST,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="most_net_id", size=5, default=0),
        ByteField(name="reserved_1", default=0),
        LongField(name="message_timestamp", default=0),
        XShortField(name="device_id", default=0),
        XByteField(name="fblock_id", default=0),
        XByteField(name="inst_id", default=0),
        BitField(name="func_id", size=12, default=0),
        BitField(name="op_type", size=4, default=0),
        XShortField(name="reserved_2", default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfGpcHeader(AvtpAcfHeader):
    """
    Header for GPC Messages - Clause 9.4.7 - IEEE 1722 - 2025
    """

    name = "ACF GPC Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_GPC,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="gpc_msgid", size=48, default=0),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfSerialHeader(AvtpAcfHeader):
    """
    Header for Serial Messages - Clause 9.4.8 - IEEE 1722 - 2025
    """

    name = "ACF Serial Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_SERIAL,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="reserved", size=8, default=0),
        BitField(name="dcd", size=1, default=0),
        BitField(name="dtr", size=1, default=0),
        BitField(name="dsr", size=1, default=0),
        BitField(name="rts", size=1, default=0),
        BitField(name="cts", size=1, default=0),
        BitField(name="ri", size=1, default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfParallelHeader(AvtpAcfHeader):
    """
    Header for Parallel Messages - Clause 9.4.9 - IEEE 1722 - 2025
    """

    name = "ACF Parallel Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_PARALLEL,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        XByteField(name="reserved", default=0),
        XByteField(name="bit_width", default=0),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfSensorHeader(AvtpAcfHeader):
    """
    Header for Sensor Messages - Clause 9.4.10 - IEEE 1722 - 2025
    """

    name = "ACF Sensor Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_SENSOR,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="mtv", size=1, default=None),
        BitField(name="num_sensors", size=7, default=None),
        BitField(name="sz", size=2, default=None),
        BitField(name="sensor_group", size=6, default=None),
        XLongField(name="message_timestamp", default=None),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfSensorBriefHeader(AvtpAcfHeader):
    """
    Header for Sensor Brief Messages - Clause 9.4.11 - IEEE 1722 - 2025
    """

    name = "ACF Sensor Brief Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_SENSOR_BRIEF,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="mtv", size=1, default=None),
        BitField(name="num_sensors", size=7, default=None),
        BitField(name="sz", size=2, default=None),
        BitField(name="sensor_group", size=6, default=None),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfAecpHeader(AvtpAcfHeader):
    """
    Header for AECP Messages - Clause 9.4.12 - IEEE 1722 - 2025
    """

    name = "ACF AECP Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_AECP,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        XShortField(name="reserved", default=0),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfAncillaryHeader(AvtpAcfHeader):
    """
    Header for Ancillary Messages - Clause 9.4.13 - IEEE 1722 - 2025
    """

    class AncMode(Enum):
        """
        Ancillary Mode - Clause 9.4.13.3.2
        """

        ANC_8BIT = 0
        ANC_10BIT = 1

    name = "ACF Ancillary Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_ANCILLARY,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="reserved", size=10, default=0),
        BitEnumField(
            name="mode",
            default=AncMode.ANC_8BIT,
            size=2,
            enum={i.name: i.value for i in AncMode},
        ),
        BitField(name="fp", size=1, default=0),
        BitField(name="lp", size=1, default=0),
        XShortField(name="line_number", default=0),
        XByteField(name="did", default=0),
        XByteField(name="sdid_dbn", default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfGenericByteBusHeader(AvtpAcfHeader):
    """
    Header for Generic Byte Bus Messages - Clause 9.4.14 - IEEE 1722 - 2025
    """

    name = "ACF Generic Byte Bus Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_GBB,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rsv", size=2, default=0),
        BitField(name="byte_bus_id", size=11, default=0),
        LongField(name="message_timestamp", default=0),
        BitField(name="evt", size=4, default=0),
        BitField(name="rsv2", size=2, default=0),
        BitField(name="hs", size=1, default=0),
        BitField(name="cs", size=1, default=0),
        XByteField(name="transaction_num", default=0),
        BitField(name="op", size=1, default=0),
        BitField(name="rsp", size=1, default=0),
        BitField(name="err", size=1, default=0),
        BitField(name="ms", size=1, default=0),
        BitField(name="read_size_segment_num", size=12, default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfAbbreviatedByteBusHeader(AvtpAcfHeader):
    """
    Header for Abbreviated Byte Bus Messages - Clause 9.4.15 - IEEE 1722 - 2025
    """

    name = "ACF Abbreviated Byte Bus Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_ABB,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rsv", size=2, default=0),
        BitField(name="byte_bus_id", size=11, default=0),
        BitField(name="evt", size=4, default=0),
        BitField(name="rsv2", size=2, default=0),
        BitField(name="hs", size=1, default=0),
        BitField(name="cs", size=1, default=0),
        XByteField(name="transaction_num", default=0),
        BitField(name="op", size=1, default=0),
        BitField(name="rsp", size=1, default=0),
        BitField(name="err", size=1, default=0),
        BitField(name="ms", size=1, default=0),
        BitField(name="read_size_segment_num", size=12, default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfI2CHeader(AvtpAcfHeader):
    """
    Header for I2C Messages - Clause 9.4.16 - IEEE 1722 - 2025
    """

    name = "ACF I2C Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_I2C,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rsv", size=2, default=0),
        BitField(name="i2c_bus_id", size=11, default=0),
        LongField(name="message_timestamp", default=0),
        BitField(name="i2c_code", size=4, default=0),
        BitField(name="trr", size=1, default=0),
        BitField(name="reserved", size=3, default=0),
        XByteField(name="transaction_num", default=0),
        BitField(name="evt", size=4, default=0),
        BitField(name="exception_code", size=4, default=0),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:

        # A correct I2C message has a 1-byte payload.
        # If the payload is not 1 byte, we will pad it to 1 byte.

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfI2CBriefHeader(AvtpAcfHeader):
    """
    Header for I2C Brief Messages - Clause 9.4.17 - IEEE 1722 - 2025
    """

    name = "ACF I2C Brief Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_I2C_BRIEF,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rsv", size=2, default=0),
        BitField(name="i2c_bus_id", size=11, default=0),
        BitField(name="i2c_code", size=4, default=0),
        BitField(name="trr", size=1, default=0),
        BitField(name="reserved", size=3, default=0),
        XByteField(name="transaction_num", default=0),
        BitField(name="evt", size=4, default=0),
        BitField(name="exception_code", size=4, default=0),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:

        # A correct I2C brief message has a 1-byte payload.
        # If the payload is not 1 byte, we will pad it to 1 byte.

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfCanXlHeader(AvtpAcfHeader):
    """
    Header for CAN XL Messages - Clause 9.4.18 - IEEE 1722 - 2025
    """

    name = "ACF CAN XL Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_CAN_XL,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rsv", size=2, default=0),
        BitField(name="can_bus_id", size=11, default=0),
        LongField(name="message_timestamp", default=0),
        XByteField(name="vcid", default=0),
        XByteField(name="sdt", default=0),
        BitField(name="reserved", size=3, default=0),
        BitField(name="rrs", size=1, default=0),
        BitField(name="sec", size=1, default=0),
        BitField(name="priority_id", size=11, default=0),
        XIntField(name="acceptance_field", default=0),
        ByteField(name="reserved_2", default=0),
        XByteField(name="transaction_num", default=0),
        BitField(name="reserved_3", size=3, default=0),
        BitField(name="ms", size=1, default=0),
        BitField(name="segment_num", size=12, default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        """Extract padding from the payload."""
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfCanXlBriefHeader(AvtpAcfHeader):
    """
    Header for CAN XL Brief Messages - Clause 9.4.19 - IEEE 1722 - 2025
    """

    name = "ACF CAN XL Brief Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_CAN_XL_BRIEF,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rsv", size=2, default=0),
        BitField(name="can_bus_id", size=11, default=0),
        XByteField(name="vcid", default=0),
        XByteField(name="sdt", default=0),
        BitField(name="reserved", size=3, default=0),
        BitField(name="rrs", size=1, default=0),
        BitField(name="sec", size=1, default=0),
        BitField(name="priority_id", size=11, default=0),
        XIntField(name="acceptance_field", default=0),
        ByteField(name="reserved_2", default=0),
        XByteField(name="transaction_num", default=0),
        BitField(name="reserved_3", size=3, default=0),
        BitField(name="ms", size=1, default=0),
        BitField(name="segment_num", size=12, default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        """Extract padding from the payload."""
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfChecksumHeader(AvtpAcfHeader):
    """
    Header for Checksum Messages - Clause 9.4.20 - IEEE 1722 - 2025
    """

    name = "ACF Checksum Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_CHECKSUM,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=1),
        XShortField(name="checksum", default=0),
    ]


class AvtpAcfCrcHeader(AvtpAcfHeader):
    """
    Header for CRC Messages - Clause 9.4.21 - IEEE 1722 - 2025
    """

    name = "ACF CRC Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_CRC,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="reserved", size=12, default=0),
        BitField(name="crc_type", size=4, default=0),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class AvtpAcfGisfHeader(AvtpAcfHeader):
    """
    Header for GISF Messages - Clause 18 - IEEE 1722 - 2025
    """

    name = "ACF GISF Header"
    fields_desc = [
        BitEnumField(
            name="acf_msg_type",
            default=AvtpAcfType.ACF_GISF,
            size=7,
            enum={i.name: i.value for i in AvtpAcfType},
        ),
        BitField(name="acf_msg_length", size=9, default=None),
        BitField(name="padlength", size=2, default=0),
        BitField(name="mtv", size=1, default=0),
        BitField(name="rsv", size=2, default=0),
        BitField(name="image_sensor_id", size=11, default=0),
        LongField(name="message_timestamp", default=0),
        ShortField(name="reserved", default=0),
        BitField(name="r", size=1, default=0),
        BitField(name="el", size=1, default=0),
        BitField(name="t1", size=1, default=0),
        BitField(name="ef", size=1, default=0),
        BitField(name="evt", size=4, default=0),
        BitField(name="rsv2", size=2, default=0),
        BitField(name="bf", size=1, default=0),
        BitField(name="line_type_id", size=5, default=0),
        XByteField(name="evt2", default=0),
        XByteField(name="i_seq_num", default=0),
        XShortField(name="line_number", default=0),
    ]

    def do_dissect_payload(self, s):
        return super().do_dissect_payload(s[: len(s) - self.padlength])

    def extract_padding(self, s):
        """Extract padding from the payload."""
        payload_length = self.acf_msg_length * 4 - len(self.self_build())
        return s[0:payload_length], s[payload_length:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Do padding
        if len(pay) % 4:
            pad = [0] * (4 - len(pay) % 4)
            pad_byte = pkt[2] | ((4 - len(pay) % 4) << 6)
            pkt = pkt[0:2] + struct.pack("!B", pad_byte) + pkt[3:]
            pay += bytes(pad)

        # Take care for length updation if the acf_msg_length field is not set
        if self.acf_msg_length is None:
            acf_length = int((len(pkt) + len(pay)) / 4) & 0x1FF
            first_byte = (pkt[0] & 0xFE) | ((acf_length >> 8) & 0x01)
            pkt = (
                struct.pack("!B", first_byte)
                + struct.pack("!B", acf_length & 0xFF)
                + pkt[2:]
            )

        return pkt + pay


class _AvtpNtscfHeaderV0(_AlternativeHeaderV0):
    name = "AVTP NTSCF Header v0"
    fields_desc = [
        ConditionalField(
            IntField(name="encapsulation_sequence_num", default=0),
            lambda pkt: isinstance(pkt.underlayer, UDP),
        ),
        XByteEnumField(
            name="subtype",
            default=AvtpStreamType.NTSCF,
            enum={i.name: i.value for i in AvtpStreamType},
        ),
        BitField(name="h", size=1, default=0),
        BitField(name="version", size=3, default=0),
        BitField(name="r", size=1, default=0),
        BitFieldLenField(
            name="ntscf_data_length", size=11, default=None, length_of="acf_tlv"
        ),
        XByteField(name="sequence_num", default=0),
        XLongField(name="stream_id", default=0),
        PacketListField(name="acf_tlv", default=[], pkt_cls=AvtpAcfHeader),
    ]


class _AvtpNtscfHeaderV1(_AlternativeHeaderV1):
    name = "AVTP NTSCF Header v1"
    fields_desc = [
        ConditionalField(
            IntField(name="encapsulation_sequence_num", default=0),
            lambda pkt: isinstance(pkt.underlayer, UDP),
        ),
        XByteEnumField(
            name="subtype",
            default=AvtpStreamType.NTSCF,
            enum={i.name: i.value for i in AvtpStreamType},
        ),
        BitField(name="h", size=1, default=0),
        BitField(name="version", size=3, default=1),
        BitField(name="reserved_1", size=20, default=0),
        XIntField(name="sequence_num", default=0),
        XLongField(name="gptp_grandmaster_identity", default=0),
        BitField(name="reserved_2", size=12, default=0),
        BitField(name="r", size=1, default=0),
        BitFieldLenField(
            name="ntscf_data_length", size=11, default=None, length_of="acf_tlv"
        ),
        XByteField(name="sequence_num_lsb", default=0),
        XLongField(name="stream_id", default=0),
        PacketListField(name="acf_tlv", default=[], pkt_cls=AvtpAcfHeader),
    ]


class AvtpNtscfHeader(AvtpCommonHeader):
    """
    Header for Non-Time-Synchronous Control Format - Clause 9.2 - IEEE 1722 - 2025
    """

    name = "AVTP NTSCF Header"

    @classmethod
    def dispatch_hook(cls, pkt=None, **kargs):
        version = 0
        if "version" in kargs:
            version = kargs.get("version", 0) == 1
        else:
            if pkt is not None:
                # We do not check for the underlayer here.
                # This is only if the packet is being dissected from
                # raw bytes using the AvtpNtscfHeader class directly.
                parsed_version = (ord(pkt[1:2]) & 0x70) >> 4
                version = parsed_version == 1
        return _AvtpNtscfHeaderV1 if version else _AvtpNtscfHeaderV0


class _AvtpTscfHeaderV0(_CommonStreamHeaderV0):
    name = "AVTP TSCF Header v0"
    fields_desc = [
        ConditionalField(
            IntField(name="encapsulation_sequence_num", default=0),
            lambda pkt: isinstance(pkt.underlayer, UDP),
        ),
        XByteEnumField(
            name="subtype",
            default=AvtpStreamType.TSCF,
            enum={i.name: i.value for i in AvtpStreamType},
        ),
        BitField(name="sv", size=1, default=0),
        BitField(name="version", size=3, default=0),
        BitField(name="mr", size=1, default=0),
        BitField(name="rsv", size=2, default=0),
        BitField(name="tv", size=1, default=0),
        XByteField(name="sequence_num", default=0),
        BitField(name="reserved_1", size=7, default=0),
        BitField(name="tu", size=1, default=0),
        XLongField(name="stream_id", default=0),
        XIntField(name="avtp_timestamp", default=0),
        XIntField(name="reserved_2", default=0),
        FieldLenField(name="stream_data_length", default=None, length_of="acf_tlv"),
        XShortField(name="reserved_3", default=0),
        PacketListField(name="acf_tlv", default=[], pkt_cls=AvtpAcfHeader),
    ]


class _AvtpTscfHeaderV1(_CommonStreamHeaderV1):
    name = "AVTP TSCF Header v1"
    fields_desc = [
        ConditionalField(
            IntField(name="encapsulation_sequence_num", default=0),
            lambda pkt: isinstance(pkt.underlayer, UDP),
        ),
        XByteEnumField(
            name="subtype",
            default=AvtpStreamType.TSCF,
            enum={i.name: i.value for i in AvtpStreamType},
        ),
        BitField(name="sv", size=1, default=0),
        BitField(name="version", size=3, default=1),
        BitField(name="mr", size=1, default=0),
        BitField(name="rsv", size=2, default=0),
        BitField(name="tv", size=1, default=0),
        XByteField(name="sequence_num_lsb", default=0),
        BitField(name="reserved_1", size=7, default=0),
        BitField(name="tu", size=1, default=0),
        XLongField(name="stream_id", default=0),
        XIntField(name="sequence_num", default=0),
        XLongField(name="avtp_timestamp", default=0),
        XLongField(name="ptp_grandmaster_identity", default=0),
        XIntField(name="reserved_2", default=0),
        FieldLenField(name="stream_data_length", default=None, length_of="acf_tlv"),
        XShortField(name="reserved_3", default=0),
        PacketListField(name="acf_tlv", default=[], pkt_cls=AvtpAcfHeader),
    ]


class AvtpTscfHeader(AvtpCommonStreamHeader):
    """
    Header for Time-Synchronous Control Format - Clause 9.3 - IEEE 1722 - 2025
    """

    name = "AVTP TSCF Header"

    @classmethod
    def dispatch_hook(cls, pkt=None, **kargs):
        version = 0
        if "version" in kargs:
            version = kargs.get("version", 0) == 1
        else:
            if pkt is not None:
                # We do not check for the underlayer here.
                # This is only if the packet is being dissected from
                # raw bytes using the AvtpTscfHeader class directly.
                parsed_version = (ord(pkt[1:2]) & 0x70) >> 4
                version = parsed_version == 1
        return _AvtpTscfHeaderV1 if version else _AvtpTscfHeaderV0


bind_layers(Ether, AvtpCommonHeader, type=0x22F0)
bind_layers(UDP, AvtpCommonHeader, dport=17220)
