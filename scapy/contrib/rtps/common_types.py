# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2021 Trend Micro Incorporated
# Copyright (C) 2021 Alias Robotics S.L.

"""
Real-Time Publish-Subscribe Protocol (RTPS) dissection
"""

# scapy.contrib.description = RTPS common types
# scapy.contrib.status = library

import struct

from scapy.fields import (
    _FieldContainer,
    BitField,
    ConditionalField,
    EnumField,
    ByteField,
    IntField,
    IPField,
    LEIntField,
    PacketField,
    PacketListField,
    ReversePadField,
    StrField,
    StrLenField,
    UUIDField,
    XIntField,
    XStrFixedLenField,
)
from scapy.packet import Packet

FORMAT_LE = "<"
FORMAT_BE = ">"
STR_MAX_LEN = 8192
DEFAULT_ENDIANNESS = FORMAT_LE


def is_le(pkt):
    if hasattr(pkt, "submessageFlags"):
        end = pkt.submessageFlags & 0b000000001 == 0b000000001
        return end

    return False


def e_flags(pkt):
    if is_le(pkt):
        return FORMAT_LE
    else:
        return FORMAT_BE


class EField(_FieldContainer):
    """
    A field that manages endianness of a nested field passed to the constructor
    """

    __slots__ = ["fld", "endianness", "endianness_from"]

    def __init__(self, fld, endianness=None, endianness_from=None):
        self.fld = fld
        self.endianness = endianness
        self.endianness_from = endianness_from

    def set_endianness(self, pkt):
        if getattr(pkt, "endianness", None) is not None:
            self.endianness = pkt.endianness
        elif self.endianness_from is not None:
            self.endianness = self.endianness_from(pkt)

        if isinstance(self.endianness, str) and self.endianness:
            if isinstance(self.fld, UUIDField):
                self.fld.uuid_fmt = (UUIDField.FORMAT_LE if
                                     self.endianness == '<'
                                     else UUIDField.FORMAT_BE)
            elif hasattr(self.fld, "fmt"):
                if len(self.fld.fmt) == 1:  # if it's only "I"
                    _end = self.fld.fmt[0]
                else:  # if it's "<I"
                    _end = self.fld.fmt[1:]
                self.fld.fmt = self.endianness + _end
                self.fld.struct = struct.Struct(self.fld.fmt)

    def getfield(self, pkt, buf):
        self.set_endianness(pkt)
        return self.fld.getfield(pkt, buf)

    def addfield(self, pkt, buf, val):
        self.set_endianness(pkt)
        return self.fld.addfield(pkt, buf, val)


class EPacket(Packet):
    """A packet that manages its endianness"""

    __slots__ = ["endianness"]

    def __init__(self, *args, **kwargs):
        self.endianness = kwargs.pop("endianness", None)
        super(EPacket, self).__init__(*args, **kwargs)

    def clone_with(self, *args, **kwargs):
        pkt = super(EPacket, self).clone_with(*args, **kwargs)
        pkt.endianness = self.endianness
        return pkt

    def extract_padding(self, p):
        return b"", p


class _EPacketField(object):
    """
    A packet field that manages its endianness and that of its nested packet
    """

    def __init__(self, *args, **kwargs):
        self.endianness = kwargs.pop("endianness", None)
        self.endianness_from = kwargs.pop("endianness_from", e_flags)
        super(_EPacketField, self).__init__(*args, **kwargs)

    def set_endianness(self, pkt):
        if getattr(pkt, "endianness", None) is not None:
            self.endianness = pkt.endianness
        elif self.endianness_from is not None:
            self.endianness = self.endianness_from(pkt)

    def m2i(self, pkt, m):
        self.set_endianness(pkt)
        return self.cls(m, endianness=self.endianness)

    def i2m(self, pkt, m):
        if m:
            self.set_endianness(pkt)
            m.endianness = self.endianness
        return super(_EPacketField, self).i2m(pkt, m)


class EPacketField(_EPacketField, PacketField):
    """
    A PacketField that manages its endianness and that of its nested packet
    """
    __slots__ = ["endianness", "endianness_from"]


class EPacketListField(_EPacketField, PacketListField):
    """
    A PacketListField that manages its endianness and
    that of its nested packet
    """
    __slots__ = ["endianness", "endianness_from"]


class SerializedDataField(StrLenField):
    pass


class DataPacketField(EPacketField):
    def m2i(self, pkt, m):
        self.set_endianness(pkt)
        pl_len = pkt.octetsToNextHeader - 24
        _pkt = self.cls(
            m,
            endianness=self.endianness,
            writer_entity_id_key=pkt.writerEntityIdKey,
            writer_entity_id_kind=pkt.writerEntityIdKind,
            pl_len=pl_len,
        )

        return _pkt


class InlineQoSPacketField(EPacketField):
    pass


class PIDPadField(StrField):
    def getfield(self, pkt, s):
        len_pkt = 2  # TODO this is dynamic
        return s[len_pkt:], self.m2i(pkt, s[:len_pkt])


class GUIDPacket(Packet):
    name = "RTPS GUID"
    fields_desc = [
        XIntField("hostId", 0),
        XIntField("appId", 0),
        XIntField("instanceId", 0),
        XIntField("entityId", 0),
    ]

    def extract_padding(self, p):
        return b"", p


class LocatorPacket(EPacket):
    name = "RTPS Locator"
    fields_desc = [
        EField(
            XIntField("locatorKind", 0),
            endianness=FORMAT_LE,
            endianness_from=None),
        EField(
            IntField("port", 0),
            endianness=FORMAT_LE,
            endianness_from=None),
        ConditionalField(
            ReversePadField(IPField("address", "0.0.0.0"), 20),
            lambda p: p.locatorKind == 0x1
        ),
        ConditionalField(
            XStrFixedLenField("hostId", 0x0, 16),
            lambda p: p.locatorKind == 0x01000000
        )
    ]

    def extract_padding(self, p):
        return b"", p


class ProductVersionPacket(EPacket):
    name = "Product Version"
    fields_desc = [
        ByteField("major", 0),
        ByteField("minor", 0),
        ByteField("release", 0),
        ByteField("revision", 0),
    ]


class TransportInfoPacket(EPacket):
    name = "Transport Info"
    fields_desc = [
        LEIntField("classID", 0),
        LEIntField("messageSizeMax", 0)
    ]


class EndpointFlagsPacket(Packet):
    name = "RTPS Endpoint Builtin Endpoint Flags"
    fields_desc = [
        BitField("participantSecureReader", 0, 1),
        BitField("participantSecureWriter", 0, 1),
        BitField("secureParticipantVolatileMessageReader", 0, 1),
        BitField("secureParticipantVolatileMessageWriter", 0, 1),
        BitField("participantStatelessMessageReader", 0, 1),
        BitField("participantStatelessMessageWriter", 0, 1),
        BitField("secureParticipantMessageReader", 0, 1),
        BitField("secureParticipantMessageWriter", 0, 1),
        BitField("secureSubscriptionReader", 0, 1),
        BitField("secureSubscriptionWriter", 0, 1),
        BitField("securePublicationReader", 0, 1),
        BitField("securePublicationWriter", 0, 1),
        BitField("reserved", 0, 4),
        BitField("participantMessageDataReader", 0, 1),
        BitField("participantMessageDataWriter", 0, 1),
        BitField("participantStateDetector", 0, 1),
        BitField("participantStateAnnouncer", 0, 1),
        BitField("publicationDetector", 0, 1),
        BitField("publicationAnnouncer", 0, 1),
        BitField("participantDetector", 0, 1),
        BitField("participantAnnouncer", 0, 1),
    ]

    def extract_padding(self, p):
        return b"", p


class ProtocolVersionPacket(Packet):
    name = "RTPS Protocol Version"
    fields_desc = [ByteField("major", 0), ByteField("minor", 0)]

    def extract_padding(self, p):
        return b"", p


_rtps_vendor_ids = {
    0x0000: "VENDOR_ID_UNKNOWN (0x0000)",
    0x0101: "Real-Time Innovations, Inc. (RTI) - Connext DDS",
    0x0102: "ADLink Ltd. - OpenSplice DDS",
    0x0103: "Object Computing Inc. (OCI) - OpenDDS",
    0x0104: "MilSoft - Mil-DDS",
    0x0105: "Kongsberg - InterCOM DDS",
    0x0106: "Twin Oaks Computing, Inc. - CoreDX DDS",
    0x0107: "Lakota Technical Solutions, Inc.",
    0x0108: "ICOUP Consulting",
    0x0109: "Electronics and Telecommunication Research Institute (ETRI) - Diamond DDS",
    0x010A: "Real-Time Innovations, Inc. (RTI) - Connext DDS Micro",
    0x010B: "ADLink Ltd. - VortexCafe",
    0x010C: "PrismTech Ltd",
    0x010D: "ADLink Ltd. - Vortex Lite",
    0x010E: "Technicolor - Qeo",
    0x010F: "eProsima - FastRTPS, FastDDS",
    0x0110: "Eclipse Foundation - Cyclone DDS",
    0x0111: "Gurum Networks, Inc. - GurumDDS",
    0x0112: "Atostek - RustDDS",
    0x0113: "Nanjing Zhenrong Software Technology Co. \
        - Zhenrong Data Distribution Service (ZRDDS)",
    0x0114: "S2E Software Systems B.V. - Dust DDS",
}


class VendorIdPacket(Packet):
    name = "RTPS Vendor ID"
    fields_desc = [
        # ByteField("major", 0),
        # ByteField("minor", 0),
        EnumField(
            name="vendor_id",
            default=0,
            enum=_rtps_vendor_ids,
        ),
    ]

    def extract_padding(self, p):
        return b"", p


class LeaseDurationPacket(Packet):
    name = "Lease Duration"
    fields_desc = [
        IntField("seconds", 0),
        IntField("fraction", 0),
    ]

    def extract_padding(self, p):
        return b"", p
