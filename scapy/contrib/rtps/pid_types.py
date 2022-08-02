# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2021 Trend Micro Incorporated
# Copyright (C) 2021 Alias Robotics S.L.

"""
Real-Time Publish-Subscribe Protocol (RTPS) dissection
"""

# scapy.contrib.description = RTPS PID type definitions
# scapy.contrib.status = library

import random
import struct

from scapy.fields import (
    IntField,
    PacketField,
    PacketListField,
    ShortField,
    StrLenField,
    XIntField,
    XShortField,
    XStrFixedLenField,
)
from scapy.packet import Packet

from scapy.contrib.rtps.common_types import (
    STR_MAX_LEN,
    EField,
    EPacket,
    GUIDPacket,
    LeaseDurationPacket,
    LocatorPacket,
    ProductVersionPacket,
    ProtocolVersionPacket,
    TransportInfoPacket,
    VendorIdPacket,
    FORMAT_LE,
)


class ParameterIdField(XShortField):
    _valid_ids = [
        0x0002,
        0x0004,
        0x0005,
        0x0006,
        0x0007,
        0x000B,
        0x000C,
        0x000D,
        0x000E,
        0x000F,
        0x0011,
        0x0015,
        0x0016,
        0x001A,
        0x001B,
        0x001D,
        0x001E,
        0x001F,
        0x0021,
        0x0023,
        0x0025,
        0x0027,
        0x0029,
        0x002B,
        0x002C,
        0x002D,
        0x002E,
        0x002F,
        0x0030,
        0x0031,
        0x0032,
        0x0033,
        0x0034,
        0x0035,
        0x0040,
        0x0041,
        0x0043,
        0x0044,
        0x0045,
        0x0046,
        0x0048,
        0x0049,
        0x0050,
        0x0052,
        0x0053,
        0x0058,
        0x0059,
        0x005A,
        0x0060,
        0x0062,
        0x0070,
        0x0071,
        0x0077,
        0x4014,
        0x8000,
        0x8001,
        0x800f,
        0x8010,
        0x8016,
        0x8017
    ]

    def randval(self):
        return random.choice(self._valid_ids)


class PIDPacketBase(Packet):
    name = "PID Base Packet"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        StrLenField(
            "parameterData",
            "",
            length_from=lambda x: x.parameterLength,
            max_length=STR_MAX_LEN,
        ),
    ]

    def extract_padding(self, p):
        return b"", p


class PID_PAD(PIDPacketBase):
    name = "PID_PAD"
    fields_desc = [
        StrLenField(
            "parameterId", "",
            length_from=lambda x: 2,
            max_length=STR_MAX_LEN)
    ]


class PID_SENTINEL(PIDPacketBase):
    name = "PID_SENTINEL"


class PID_USER_DATA(PIDPacketBase):
    name = "PID_USER_DATA"


class PID_TOPIC_NAME(PIDPacketBase):
    name = "PID_TOPIC_NAME"


class PID_TYPE_NAME(PIDPacketBase):
    name = "PID_TYPE_NAME"


class PID_GROUP_DATA(PIDPacketBase):
    name = "PID_GROUP_DATA"


class PID_TOPIC_DATA(PIDPacketBase):
    name = "PID_TOPIC_DATA"


class PID_DURABILITY(PIDPacketBase):
    name = "PID_DURABILITY"


class PID_DURABILITY_SERVICE(PIDPacketBase):
    name = "PID_DURABILITY_SERVICE"


class PID_DEADLINE(PIDPacketBase):
    name = "PID_DEADLINE"


class PID_LATENCY_BUDGET(PIDPacketBase):
    name = "PID_LATENCY_BUDGET"


class PID_LIVELINESS(PIDPacketBase):
    name = "PID_LIVELINESS"


class PID_RELIABILITY(PIDPacketBase):
    name = "PID_RELIABILITY"


class PID_LIFESPAN(PIDPacketBase):
    name = "PID_LIFESPAN"


class PID_DESTINATION_ORDER(PIDPacketBase):
    name = "PID_DESTINATION_ORDER"


class PID_HISTORY(PIDPacketBase):
    name = "PID_HISTORY"


class PID_RESOURCE_LIMITS(PIDPacketBase):
    name = "PID_RESOURCE_LIMITS"


class PID_OWNERSHIP(PIDPacketBase):
    name = "PID_OWNERSHIP"


class PID_OWNERSHIP_STRENGTH(PIDPacketBase):
    name = "PID_OWNERSHIP_STRENGTH"


class PID_PRESENTATION(PIDPacketBase):
    name = "PID_PRESENTATION"


class PID_PARTITION(PIDPacketBase):
    name = "PID_PARTITION"


class PID_TIME_BASED_FILTER(PIDPacketBase):
    name = "PID_TIME_BASED_FILTER"


class PID_TRANSPORT_PRIO(PIDPacketBase):
    name = "PID_TRANSPORT_PRIO"


class PID_PROTOCOL_VERSION(PIDPacketBase):
    name = "PID_PROTOCOL_VERSION"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        PacketField("protocolVersion", "", ProtocolVersionPacket),
        StrLenField(
            "padding",
            "",
            length_from=lambda x: x.parameterLength - 2,
            max_length=STR_MAX_LEN,
        ),
    ]


class PID_VENDOR_ID(PIDPacketBase):
    name = "PID_VENDOR_ID"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        PacketField("vendorId", "", VendorIdPacket),
        StrLenField(
            "padding",
            "",
            length_from=lambda x: x.parameterLength - 2,
            max_length=STR_MAX_LEN,
        ),
    ]


class PID_UNICAST_LOCATOR(PIDPacketBase):
    name = "PID_UNICAST_LOCATOR"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        PacketField("locator", "", LocatorPacket),
    ]


class PID_MULTICAST_LOCATOR(PIDPacketBase):
    name = "PID_MULTICAST_LOCATOR"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        StrLenField(
            "parameterData",
            "",
            length_from=lambda x: x.parameterLength,
            max_length=STR_MAX_LEN,
        ),
    ]


class PID_MULTICAST_IPADDRESS(PIDPacketBase):
    name = "PID_MULTICAST_IPADDRESS"


class PID_DEFAULT_UNICAST_LOCATOR(PIDPacketBase):
    name = "PID_DEFAULT_UNICAST_LOCATOR"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        PacketField("locator", "", LocatorPacket),
    ]


class PID_DEFAULT_MULTICAST_LOCATOR(PIDPacketBase):
    name = "PID_DEFAULT_MULTICAST_LOCATOR"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        PacketField("locator", "", LocatorPacket),
    ]


class PID_TRANSPORT_PRIORITY(PIDPacketBase):
    name = "PID_TRANSPORT_PRIORITY"


class PID_METATRAFFIC_UNICAST_LOCATOR(PIDPacketBase):
    name = "PID_METATRAFFIC_UNICAST_LOCATOR"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        PacketField("locator", "", LocatorPacket),
    ]


class PID_METATRAFFIC_MULTICAST_LOCATOR(PIDPacketBase):
    name = "PID_METATRAFFIC_MULTICAST_LOCATOR"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        PacketField("locator", "", LocatorPacket),
    ]


class PID_DEFAULT_UNICAST_IPADDRESS(PIDPacketBase):
    name = "PID_DEFAULT_UNICAST_IPADDRESS"


class PID_DEFAULT_UNICAST_PORT(PIDPacketBase):
    name = "PID_DEFAULT_UNICAST_PORT"


class PID_METATRAFFIC_UNICAST_IPADDRESS(PIDPacketBase):
    name = "PID_METATRAFFIC_UNICAST_IPADDRESS"


class PID_METATRAFFIC_UNICAST_PORT(PIDPacketBase):
    name = "PID_METATRAFFIC_UNICAST_PORT"


class PID_METATRAFFIC_MULTICAST_IPADDRESS(PIDPacketBase):
    name = "PID_METATRAFFIC_MULTICAST_IPADDRESS"


class PID_METATRAFFIC_MULTICAST_PORT(PIDPacketBase):
    name = "PID_METATRAFFIC_MULTICAST_PORT"


class PID_EXPECTS_INLINE_QOS(PIDPacketBase):
    name = "PID_EXPECTS_INLINE_QOS"


class PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT(PIDPacketBase):
    name = "PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT"


class PID_PARTICIPANT_BUILTIN_ENDPOINTS(PIDPacketBase):
    name = "PID_PARTICIPANT_BUILTIN_ENDPOINTS"


class PID_PARTICIPANT_LEASE_DURATION(PIDPacketBase):
    name = "PID_PARTICIPANT_LEASE_DURATION"


class PID_CONTENT_FILTER_PROPERTY(PIDPacketBase):
    name = "PID_CONTENT_FILTER_PROPERTY"


class PID_PARTICIPANT_GUID(PIDPacketBase):
    name = "PID_PARTICIPANT_GUID"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        PacketField("guid", "", GUIDPacket),
    ]


class PID_ENDPOINT_GUID(PIDPacketBase):
    name = "PID_ENDPOINT_GUID"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        PacketField("guid", "", GUIDPacket),
    ]


class PID_GROUP_GUID(PIDPacketBase):
    name = "PID_GROUP_GUID"


class PID_GROUP_ENTITYID(PIDPacketBase):
    name = "PID_GROUP_ENTITYID"


class PID_BUILTIN_ENDPOINT_SET(PIDPacketBase):
    name = "PID_BUILTIN_ENDPOINT_SET"


class PID_PROPERTY_LIST(PIDPacketBase):
    name = "PID_PROPERTY_LIST"


class PID_TYPE_MAX_SIZE_SERIALIZED(PIDPacketBase):
    name = "PID_TYPE_MAX_SIZE_SERIALIZED"


class PID_ENTITY_NAME(PIDPacketBase):
    name = "PID_ENTITY_NAME"


class PID_KEY_HASH(PIDPacketBase):
    name = "PID_KEY_HASH"


class PID_STATUS_INFO(PIDPacketBase):
    name = "PID_STATUS_INFO"


class PID_BUILTIN_ENDPOINT_QOS(PIDPacketBase):
    name = "PID_BUILTIN_ENDPOINT_QOS"


class PID_DOMAIN_TAG(PIDPacketBase):
    name = "PID_DOMAIN_TAG"


class PID_DOMAIN_ID(PIDPacketBase):
    name = "PID_DOMAIN_ID"


class PID_UNKNOWN(PIDPacketBase):
    name = "PID_UNKNOWN"


class PID_PRODUCT_VERSION(PIDPacketBase):
    name = "PID_PRODUCT_VERSION"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        PacketField("productVersion", "", ProductVersionPacket),
    ]


class PID_PLUGIN_PROMISCUITY_KIND(PIDPacketBase):
    name = "PID_PLUGIN_PROMISCUITY_KIND"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        EField(
            XIntField("promiscuityKind", 0x0),
            endianness=FORMAT_LE,
            endianness_from=None
        )
    ]


class PID_RTI_DOMAIN_ID(PIDPacketBase):
    name = "PID_RTI_DOMAIN_ID"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        EField(
            IntField("domainId", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        )
    ]


class PID_TRANSPORT_INFO_LIST(PIDPacketBase):
    name = "PID_TRANSPORT_INFO_LIST"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        XStrFixedLenField("padding", "", 4),
        EField(
            PacketListField(
                "transportInfo", [],
                TransportInfoPacket,
                length_from=lambda p: p.parameterLength - 4)
        )
    ]


class PID_REACHABILITY_LEASE_DURATION(PIDPacketBase):
    name = "PID_REACHABILITY_LEASE_DURATION"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        PacketField("lease_duration", "", LeaseDurationPacket),
    ]


class PID_VENDOR_BUILTIN_ENDPOINT_SET(PIDPacketBase):
    name = "PID_VENDOR_BUILTIN_ENDPOINT_SET"
    fields_desc = [
        EField(
            ParameterIdField("parameterId", 0),
            endianness=FORMAT_LE,
            endianness_from=None,
        ),
        EField(
            ShortField("parameterLength", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        ),
        EField(
            XIntField("flags", 0),
            endianness=FORMAT_LE,
            endianness_from=None
        )
    ]


_RTPSParameterIdTypes = {
    0x0000: PID_PAD,
    # 0x0001: PID_SENTINEL,
    0x0002: PID_PARTICIPANT_LEASE_DURATION,
    0x0004: PID_TIME_BASED_FILTER,
    0x0005: PID_TOPIC_NAME,
    0x0006: PID_OWNERSHIP_STRENGTH,
    0x0007: PID_TYPE_NAME,
    0x000B: PID_METATRAFFIC_MULTICAST_IPADDRESS,
    0x000C: PID_DEFAULT_UNICAST_IPADDRESS,
    0x000D: PID_METATRAFFIC_UNICAST_PORT,
    0x000E: PID_DEFAULT_UNICAST_PORT,
    0x000F: PID_DOMAIN_ID,
    0x0011: PID_MULTICAST_IPADDRESS,
    0x0015: PID_PROTOCOL_VERSION,
    0x0016: PID_VENDOR_ID,
    0x001A: PID_RELIABILITY,
    0x001B: PID_LIVELINESS,
    0x001D: PID_DURABILITY,
    0x001E: PID_DURABILITY_SERVICE,
    0x001F: PID_OWNERSHIP,
    0x0021: PID_PRESENTATION,
    0x0023: PID_DEADLINE,
    0x0025: PID_DESTINATION_ORDER,
    0x0027: PID_LATENCY_BUDGET,
    0x0029: PID_PARTITION,
    0x002B: PID_LIFESPAN,
    0x002C: PID_USER_DATA,
    0x002D: PID_GROUP_DATA,
    0x002E: PID_TOPIC_DATA,
    0x002F: PID_UNICAST_LOCATOR,
    0x0030: PID_MULTICAST_LOCATOR,
    0x0031: PID_DEFAULT_UNICAST_LOCATOR,
    0x0032: PID_METATRAFFIC_UNICAST_LOCATOR,
    0x0033: PID_METATRAFFIC_MULTICAST_LOCATOR,
    0x0034: PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT,
    0x0035: PID_CONTENT_FILTER_PROPERTY,
    0x0040: PID_HISTORY,
    0x0041: PID_RESOURCE_LIMITS,
    0x0043: PID_EXPECTS_INLINE_QOS,
    0x0044: PID_PARTICIPANT_BUILTIN_ENDPOINTS,
    0x0045: PID_METATRAFFIC_UNICAST_IPADDRESS,
    0x0046: PID_METATRAFFIC_MULTICAST_PORT,
    0x0048: PID_DEFAULT_MULTICAST_LOCATOR,
    0x0049: PID_TRANSPORT_PRIORITY,
    0x0050: PID_PARTICIPANT_GUID,
    0x0052: PID_GROUP_GUID,
    0x0053: PID_GROUP_ENTITYID,
    0x0058: PID_BUILTIN_ENDPOINT_SET,
    0x0059: PID_PROPERTY_LIST,
    0x005A: PID_ENDPOINT_GUID,
    0x0060: PID_TYPE_MAX_SIZE_SERIALIZED,
    0x0062: PID_ENTITY_NAME,
    0x0070: PID_KEY_HASH,
    0x0071: PID_STATUS_INFO,
    0x0077: PID_BUILTIN_ENDPOINT_QOS,
    0x4014: PID_DOMAIN_TAG,
    0x8000: PID_PRODUCT_VERSION,
    0x8001: PID_PLUGIN_PROMISCUITY_KIND,
    0x800f: PID_RTI_DOMAIN_ID,
    0x8010: PID_TRANSPORT_INFO_LIST,
    0x8016: PID_REACHABILITY_LEASE_DURATION,
    0x8017: PID_VENDOR_BUILTIN_ENDPOINT_SET
}


def get_pid_class(pkt, lst, cur, remain):

    endianness = getattr(pkt, "endianness", None)

    _id = struct.unpack(endianness + "h", remain[0:2])[0]

    if _id == 0x0001:
        return None

    _id = _id & 0xffff

    next_cls = _RTPSParameterIdTypes.get(_id, PID_UNKNOWN)

    next_cls.endianness = endianness

    return next_cls


class ParameterListPacket(EPacket):
    name = "PID list"
    fields_desc = [
        PacketListField("parameterValues", [], next_cls_cb=get_pid_class),
        PacketField("sentinel", "", PID_SENTINEL),
    ]
