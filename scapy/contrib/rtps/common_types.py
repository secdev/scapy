"""
Real-Time Publish-Subscribe Protocol (RTPS) dissection

Copyright (C) 2021 Trend Micro Incorporated
Copyright (C) 2021 Alias Robotics S.L.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

# scapy.contrib.description = RTPS common types
# scapy.contrib.status = library

import struct
import warnings

from scapy.fields import (
    BitField,
    ConditionalField,
    EnumField,
    ByteField,
    IntField,
    IPField,
    LEIntField,
    PacketField,
    ReversePadField,
    StrField,
    StrLenField,
    XIntField,
    XStrFixedLenField,
)
from scapy.packet import Packet, fuzz

FORMAT_LE = "<"
FORMAT_BE = ">"
STR_MAX_LEN = 8192
DEFAULT_ENDIANESS = FORMAT_LE


def is_le(pkt):
    if hasattr(pkt, "submessageFlags"):
        end = pkt.submessageFlags & 0b000000001 == 0b000000001
        return end

    return False


def e_flags(pkt: Packet) -> str:
    if is_le(pkt):
        return FORMAT_LE
    else:
        return FORMAT_BE


class EField(object):
    """
    A field that manages endianness of a nested field passed to the constructor
    """

    __slots__ = ["fld", "endianness", "endianness_from"]

    def __init__(self, fld, endianness=FORMAT_BE, endianness_from=e_flags):
        self.fld = fld
        self.endianness = endianness
        self.endianness_from = endianness_from

    def set_endianness(self, pkt):
        if getattr(pkt, "endianness", None) is not None:
            self.endianness = pkt.endianness
        elif self.endianness_from is not None:
            self.endianness = self.endianness_from(pkt)

        if hasattr(self.fld, "set_endianness"):
            self.fld.set_endianness(endianness=self.endianness)
            return

        if hasattr(self.fld, "endianness"):
            self.fld.endianness = self.endianness
            return

        if isinstance(self.endianness, str) and self.endianness:
            if hasattr(self.fld, "fmt"):
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

    def randval(self):
        return self.fld.randval()

    def __getattr__(self, attr):
        return getattr(self.fld, attr)


class EPacket(Packet):
    """A packet that manages its endianness"""

    __slots__ = ["endianness"]

    def __init__(self, *args, endianness=None, **kwargs):
        self.endianness = endianness
        super().__init__(*args, **kwargs)

    def extract_padding(self, p):
        return b"", p


class EPacketField(PacketField):
    """
    A packet field that manages its endianness and that of its nested packet
    """

    __slots__ = ["endianness", "endianness_from", "fuzz_fun"]

    def __init__(
        self,
        *args,
        fuzz_fun=fuzz,
        endianness=None,
        endianness_from=e_flags,
        **kwargs,
    ):
        self.endianness = endianness
        self.endianness_from = endianness_from
        self.fuzz_fun = fuzz_fun
        super().__init__(*args, **kwargs)

    def set_endianness(self, pkt):
        if getattr(pkt, "endianness", None) is not None:
            self.endianness = pkt.endianness
        elif self.endianness_from is not None and pkt:
            self.endianness = self.endianness_from(pkt)
            if self.endianness is None:
                warnings.warn(
                    'Endianess should never be None.'
                    'Setting it to default: {}', DEFAULT_ENDIANESS)
                self.endianness = DEFAULT_ENDIANESS

    def m2i(self, pkt, m):
        self.set_endianness(pkt)

        _pkt = self.cls(m, endianness=self.endianness)

        return _pkt

    def randval(self):
        if self.fuzz_fun is not None:
            return self.fuzz_fun(self.cls())
        return super().randval()


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
    b"\x00\x00": "VENDOR_ID_UNKNOWN (0x0000)",
    b"\x01\x01": "Real-Time Innovations, Inc. - Connext DDS",
    b"\x01\x02": "PrismTech Inc. - OpenSplice DDS",
    b"\x01\x03": "Object Computing Incorporated, Inc. (OCI) - OpenDDS",
    b"\x01\x04": "MilSoft",
    b"\x01\x05": "Gallium Visual Systems Inc. - InterCOM DDS",
    b"\x01\x06": "TwinOaks Computing, Inc. - CoreDX DDS",
    b"\x01\x07": "Lakota Technical Solutions, Inc.",
    b"\x01\x08": "ICOUP Consulting",
    b"\x01\x09": "ETRI Electronics and Telecommunication Research Institute",
    b"\x01\x0A": "Real-Time Innovations, Inc. (RTI) - Connext DDS Micro",
    b"\x01\x0B": "PrismTech - OpenSplice Mobile",
    b"\x01\x0C": "PrismTech - OpenSplice Gateway",
    b"\x01\x0D": "PrismTech - OpenSplice Lite",
    b"\x01\x0E": "Technicolor Inc. - Qeo",
    b"\x01\x0F": "eProsima - Fast-RTPS",
    b"\x01\x10": "ADLINK - Cyclone DDS",
    b"\x01\x11": "GurumNetworks - GurumDDS",
}


class VendorIdPacket(Packet):
    name = "RTPS Vendor ID"
    fields_desc = [
        # ByteField("major", 0),
        # ByteField("minor", 0),
        EnumField(
            name="vendor_id",
            default=b"\x00\x00",
            enum=_rtps_vendor_ids,
            fmt="2s"
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
