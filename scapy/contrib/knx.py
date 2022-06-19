# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2021 Julien BEDEL <contact[at]julienbedel.com>
#                    Claire VACHEROT <lex[at]lex.os>

"""
KNXNet/IP

This module provides Scapy layers for KNXNet/IP communications over UDP
according to KNX specifications v2.1 / ISO-IEC 14543-3.
Specifications can be downloaded for free here :
https://my.knx.org/en/shop/knx-specifications

Currently, the module (partially) supports the following services :
* SEARCH REQUEST/RESPONSE
* DESCRIPTION REQUEST/RESPONSE
* CONNECT, DISCONNECT, CONNECTION_STATE REQUEST/RESPONSE
* CONFIGURATION REQUEST/RESPONSE
* TUNNELING REQUEST/RESPONSE
"""

# scapy.contrib.description = KNX Protocol
# scapy.contrib.status = loads
import struct

from scapy.fields import PacketField, MultipleTypeField, ByteField, \
    XByteField, ShortEnumField, ShortField, \
    ByteEnumField, IPField, StrFixedLenField, MACField, XBitField, \
    PacketListField, FieldLenField, \
    StrLenField, BitEnumField, BitField, ConditionalField
from scapy.packet import Packet, bind_layers, bind_bottom_up, Padding
from scapy.layers.inet import UDP

# KNX CODES

# KNX Standard v2.1 - 03_08_02 p20
SERVICE_IDENTIFIER_CODES = {
    0x0201: "SEARCH_REQUEST",
    0x0202: "SEARCH_RESPONSE",
    0x0203: "DESCRIPTION_REQUEST",
    0x0204: "DESCRIPTION_RESPONSE",
    0x0205: "CONNECT_REQUEST",
    0x0206: "CONNECT_RESPONSE",
    0x0207: "CONNECTIONSTATE_REQUEST",
    0x0208: "CONNECTIONSTATE_RESPONSE",
    0x0209: "DISCONNECT_REQUEST",
    0x020A: "DISCONNECT_RESPONSE",
    0x0310: "CONFIGURATION_REQUEST",
    0x0311: "CONFIGURATION_ACK",
    0x0420: "TUNNELING_REQUEST",
    0x0421: "TUNNELING_ACK"
}

# KNX Standard v2.1 - 03_08_02 p39
HOST_PROTOCOL_CODES = {
    0x01: "IPV4_UDP",
    0x02: "IPV4_TCP"
}

# KNX Standard v2.1 - 03_08_02 p23
DESCRIPTION_TYPE_CODES = {
    0x01: "DEVICE_INFO",
    0x02: "SUPP_SVC_FAMILIES",
    0x03: "IP_CONFIG",
    0x04: "IP_CUR_CONFIG",
    0x05: "KNX_ADDRESSES",
    0x06: "Reserved",
    0xFE: "MFR_DATA",
    0xFF: "not used"
}

# KNX Standard v2.1 - 03_08_02 p30
CONNECTION_TYPE_CODES = {
    0x03: "DEVICE_MANAGEMENT_CONNECTION",
    0x04: "TUNNEL_CONNECTION",
    0x06: "REMLOG_CONNECTION",
    0x07: "REMCONF_CONNECTION",
    0x08: "OBJSVR_CONNECTION"
}

# KNX Standard v2.1 - 03_08_04
MESSAGE_CODES = {
    0x11: "L_Data.req",
    0x2e: "L_Data.con",
    0xFC: "M_PropRead.req",
    0xFB: "M_PropRead.con",
    0xF6: "M_PropWrite.req",
    0xF5: "M_PropWrite.con"
}

# KNX Standard v2.1 - 03_08_02 p24
KNX_MEDIUM_CODES = {
    0x01: "reserved",
    0x02: "TP1",
    0x04: "PL110",
    0x08: "reserved",
    0x10: "RF",
    0x20: "KNX IP"
}

# KNX Standard v2.1 - 03_03_07 p9
KNX_ACPI_CODES = {
    0: "GroupValueRead",
    1: "GroupValueResp",
    2: "GroupValueWrite",
    3: "IndAddrWrite",
    4: "IndAddrRead",
    5: "IndAddrResp",
    6: "AdcRead",
    7: "AdcResp"
}

CEMI_OBJECT_TYPES = {
    0: "DEVICE",
    11: "IP PARAMETER_OBJECT"
}

# KNX Standard v2.1 - 03_05_01 p25
CEMI_PROPERTIES = {
    12: "PID_MANUFACTURER_ID",
    51: "PID_PROJECT_INSTALLATION_ID",
    52: "PID_KNX_INDIVIDUAL_ADDRESS",
    53: "PID_ADDITIONAL_INDIVIDUAL_ADDRESSES",
    54: "PID_CURRENT_IP_ASSIGNMENT_METHOD",
    55: "PID_IP_ASSIGNMENT_METHOD",
    56: "PID_IP_CAPABILITIES",
    57: "PID_CURRENT_IP_ADDRESS",
    58: "PID_CURRENT_SUBNET_MASK",
    59: "PID_CURRENT_DEFAULT_GATEWAY",
    60: "PID_IP_ADDRESS",
    61: "PID_SUBNET_MASK",
    62: "PID_DEFAULT_GATEWAY",
    63: "PID_DHCP_BOOTP_SERVER",
    64: "PID_MAC_ADDRESS",
    65: "PID_SYSTEM_SETUP_MULTICAST_ADDRESS",
    66: "PID_ROUTING_MULTICAST_ADDRESS",
    67: "PID_TTL",
    68: "PID_KNXNETIP_DEVICE_CAPABILITIES",
    69: "PID_KNXNETIP_DEVICE_STATE",
    70: "PID_KNXNETIP_ROUTING_CAPABILITIES",
    71: "PID_PRIORITY_FIFO_ENABLED",
    72: "PID_QUEUE_OVERFLOW_TO_IP",
    73: "PID_QUEUE_OVERFLOW_TO_KNX",
    74: "PID_MSG_TRANSMIT_TO_IP",
    75: "PID_MSG_TRANSMIT_TO_KNX",
    76: "PID_FRIENDLY_NAME",
    78: "PID_ROUTING_BUSY_WAIT_TIME"
}


# KNX SPECIFIC FIELDS

# KNX Standard v2.1 - 03_05_01 p.17
class KNXAddressField(ShortField):
    def i2repr(self, pkt, x):
        if x is None:
            return None
        else:
            return "%d.%d.%d" % ((x >> 12) & 0xf, (x >> 8) & 0xf, (x & 0xff))

    def any2i(self, pkt, x):
        if isinstance(x, str):
            try:
                a, b, c = map(int, x.split("."))
                x = (a << 12) | (b << 8) | c
            except ValueError:
                raise ValueError(x)
        return ShortField.any2i(self, pkt, x)


# KNX Standard v2.1 - 03_05_01 p.18
class KNXGroupField(ShortField):
    def i2repr(self, pkt, x):
        return "%d/%d/%d" % ((x >> 11) & 0x1f, (x >> 8) & 0x7, (x & 0xff))

    def any2i(self, pkt, x):
        if isinstance(x, str):
            try:
                a, b, c = map(int, x.split("/"))
                x = (a << 11) | (b << 8) | c
            except ValueError:
                raise ValueError(x)
        return ShortField.any2i(self, pkt, x)


# KNX PLACEHOLDERS

# KNX Standard v2.1 - 03_08_02 p21
class HPAI(Packet):
    name = "HPAI"
    fields_desc = [
        ByteField("structure_length", None),
        ByteEnumField("host_protocol", 0x01, HOST_PROTOCOL_CODES),
        IPField("ip_address", None),
        ShortField("port", None)
    ]

    def post_build(self, p, pay):
        if self.structure_length is None:
            p = struct.pack("!B", len(p)) + p[1:]
        return p + pay


# DIB, KNX Standard v2.1 - 03_08_02 p22
class ServiceFamily(Packet):
    name = "Service Family"
    fields_desc = [
        ByteField("id", None),
        ByteField("version", None)
    ]


# Different DIB types depends on the "description_type_code" field
# Defining a generic DIB packet and differentiating with `dispatch_hook` or
# `MultipleTypeField` may better fit KNX specs
class DIBDeviceInfo(Packet):
    name = "DIB: DEVICE_INFO"
    fields_desc = [
        ByteField("structure_length", None),
        ByteEnumField("description_type", 0x01, DESCRIPTION_TYPE_CODES),
        ByteEnumField("knx_medium", 0x02, KNX_MEDIUM_CODES),
        ByteField("device_status", None),
        KNXAddressField("knx_address", None),
        ShortField("project_installation_identifier", None),
        XBitField("device_serial_number", None, 48),
        IPField("device_multicast_address", None),
        MACField("device_mac_address", None),
        StrFixedLenField("device_friendly_name", None, 30)
    ]

    def post_build(self, p, pay):
        if self.structure_length is None:
            p = struct.pack("!B", len(p)) + p[1:]
        return p + pay


class DIBSuppSvcFamilies(Packet):
    name = "DIB: SUPP_SVC_FAMILIES"
    fields_desc = [
        ByteField("structure_length", 0x02),
        ByteEnumField("description_type", 0x02, DESCRIPTION_TYPE_CODES),
        ConditionalField(
            PacketListField("service_family",
                            ServiceFamily(),
                            ServiceFamily,
                            length_from=lambda pkt:
                            pkt.structure_length - 0x02),
            lambda pkt: pkt.structure_length > 0x02)
    ]

    def post_build(self, p, pay):
        if self.structure_length is None:
            p = struct.pack("!B", len(p)) + p[1:]
        return p + pay


# CRI and CRD, KNX Standard v2.1 - 03_08_02 p21

class TunnelingConnection(Packet):
    name = "Tunneling Connection"
    fields_desc = [
        ByteField("knx_layer", 0x02),
        ByteField("reserved", None)
    ]


class CRDTunnelingConnection(Packet):
    name = "CRD Tunneling Connection"
    fields_desc = [
        KNXAddressField("knx_individual_address", None)
    ]


class CRI(Packet):
    name = "CRI (Connection Request Information)"
    fields_desc = [
        ByteField("structure_length", 0x02),
        ByteEnumField("connection_type", 0x03, CONNECTION_TYPE_CODES),
        ConditionalField(PacketField("connection_data",
                                     TunnelingConnection(),
                                     TunnelingConnection),
                         lambda pkt: pkt.connection_type == 0x04)
    ]

    def post_build(self, p, pay):
        if self.structure_length is None:
            p = struct.pack("!B", len(p)) + p[1:]
        return p + pay


class CRD(Packet):
    name = "CRD (Connection Response Data)"
    fields_desc = [
        ByteField("structure_length", 0x00),
        ByteEnumField("connection_type", 0x03, CONNECTION_TYPE_CODES),
        ConditionalField(PacketField("connection_data",
                                     CRDTunnelingConnection(),
                                     CRDTunnelingConnection),
                         lambda pkt: pkt.connection_type == 0x04)
    ]

    def post_build(self, p, pay):
        if self.structure_length is None:
            p = struct.pack("!B", len(p)) + p[1:]
        return p + pay


# cEMI blocks

class LcEMI(Packet):
    name = "L_cEMI"
    fields_desc = [
        FieldLenField("additional_information_length", 0, fmt="B",
                      length_of="additional_information"),
        StrLenField("additional_information", None,
                    length_from=lambda pkt: pkt.additional_information_length),
        # Controlfield 1 (1 byte made of 8*1 bits)
        BitEnumField("frame_type", 1, 1, {
            1: "standard"
        }),
        BitField("reserved_1", 0, 1),
        BitField("repeat_on_error", 1, 1),
        BitEnumField("broadcast_type", 1, 1, {
            1: "domain"
        }),
        BitEnumField("priority", 3, 2, {
            3: "low"
        }),
        BitField("ack_request", 0, 1),
        BitField("confirmation_error", 0, 1),
        # Controlfield 2 (1 byte made of 1+3+4 bits)
        BitEnumField("address_type", 1, 1, {
            1: "group"
        }),
        BitField("hop_count", 6, 3),
        BitField("extended_frame_format", 0, 4),
        KNXAddressField("source_address", None),
        KNXGroupField("destination_address", "1/2/3"),
        FieldLenField("npdu_length", 0x01, fmt="B", length_of="data"),
        # TPCI and APCI (2 byte made of 1+1+4+4+6 bits)
        BitEnumField("packet_type", 0, 1, {
            0: "data"
        }),
        BitEnumField("sequence_type", 0, 1, {
            0: "unnumbered"
        }),
        BitField("reserved_2", 0, 4),
        BitEnumField("acpi", 2, 4, KNX_ACPI_CODES),
        BitField("data", 0, 6)

    ]


class DPcEMI(Packet):
    name = "DP_cEMI"
    fields_desc = [
        # see if best representation is str or hex
        ShortField("object_type", None),
        ByteField("object_instance", 1),
        ByteField("property_id", None),
        BitField("number_of_elements", 1, 4),
        BitField("start_index", None, 12)
    ]


class CEMI(Packet):
    name = "CEMI"
    fields_desc = [
        ByteEnumField("message_code", None, MESSAGE_CODES),
        MultipleTypeField(
            [
                (PacketField("cemi_data", LcEMI(), LcEMI),
                 lambda pkt: pkt.message_code == 0x11),
                (PacketField("cemi_data", LcEMI(), LcEMI),
                 lambda pkt: pkt.message_code == 0x2e),
                (PacketField("cemi_data", DPcEMI(), DPcEMI),
                 lambda pkt: pkt.message_code == 0xFC),
                (PacketField("cemi_data", DPcEMI(), DPcEMI),
                 lambda pkt: pkt.message_code == 0xFB),
                (PacketField("cemi_data", DPcEMI(), DPcEMI),
                 lambda pkt: pkt.message_code == 0xF6),
                (PacketField("cemi_data", DPcEMI(), DPcEMI),
                 lambda pkt: pkt.message_code == 0xF5)
            ],
            PacketField("cemi_data", LcEMI(), LcEMI)
        )
    ]


# KNX SERVICES

# KNX Standard v2.1 - 03_08_02 p28
class KNXSearchRequest(Packet):
    name = "SEARCH_REQUEST",
    fields_desc = [
        PacketField("discovery_endpoint", HPAI(), HPAI)
    ]


# KNX Standard v2.1 - 03_08_02 p28
class KNXSearchResponse(Packet):
    name = "SEARCH_RESPONSE",
    fields_desc = [
        PacketField("control_endpoint", HPAI(), HPAI),
        PacketField("device_info", DIBDeviceInfo(), DIBDeviceInfo),
        PacketField("supported_service_families", DIBSuppSvcFamilies(),
                    DIBSuppSvcFamilies)
    ]


# KNX Standard v2.1 - 03_08_02 p29
class KNXDescriptionRequest(Packet):
    name = "DESCRIPTION_REQUEST"
    fields_desc = [
        PacketField("control_endpoint", HPAI(), HPAI)
    ]


# KNX Standard v2.1 - 03_08_02 p29
class KNXDescriptionResponse(Packet):
    name = "DESCRIPTION_RESPONSE"
    fields_desc = [
        PacketField("device_info", DIBDeviceInfo(), DIBDeviceInfo),
        PacketField("supported_service_families", DIBSuppSvcFamilies(),
                    DIBSuppSvcFamilies)
        # TODO: this is an optional field in KNX specs,
        #  => Add conditions to take it into account
        # PacketField("other_device_info", DIBDeviceInfo(), DIBDeviceInfo)
    ]


# KNX Standard v2.1 - 03_08_02 p30
class KNXConnectRequest(Packet):
    name = "CONNECT_REQUEST"
    fields_desc = [
        PacketField("control_endpoint", HPAI(), HPAI),
        PacketField("data_endpoint", HPAI(), HPAI),
        PacketField("connection_request_information", CRI(), CRI)
    ]


# KNX Standard v2.1 - 03_08_02 p31
class KNXConnectResponse(Packet):
    name = "CONNECT_RESPONSE"
    fields_desc = [
        ByteField("communication_channel_id", None),
        ByteField("status", None),
        PacketField("data_endpoint", HPAI(), HPAI),
        PacketField("connection_response_data_block", CRD(), CRD)
    ]


# KNX Standard v2.1 - 03_08_02 p32
class KNXConnectionstateRequest(Packet):
    name = "CONNECTIONSTATE_REQUEST"
    fields_desc = [
        ByteField("communication_channel_id", None),
        ByteField("reserved", None),
        PacketField("control_endpoint", HPAI(), HPAI)
    ]


# KNX Standard v2.1 - 03_08_02 p32
class KNXConnectionstateResponse(Packet):
    name = "CONNECTIONSTATE_RESPONSE"
    fields_desc = [
        ByteField("communication_channel_id", None),
        ByteField("status", 0x00)
    ]


# KNX Standard v2.1 - 03_08_02 p33
class KNXDisconnectRequest(Packet):
    name = "DISCONNECT_REQUEST"
    fields_desc = [
        ByteField("communication_channel_id", 0x01),
        ByteField("reserved", None),
        PacketField("control_endpoint", HPAI(), HPAI)
    ]


# KNX Standard v2.1 - 03_08_02 p34
class KNXDisconnectResponse(Packet):
    name = "DISCONNECT_RESPONSE"
    fields_desc = [
        ByteField("communication_channel_id", None),
        ByteField("status", 0x00)
    ]


# KNX Standard v2.1 - 03_08_03 p22
class KNXConfigurationRequest(Packet):
    name = "CONFIGURATION_REQUEST"
    fields_desc = [
        ByteField("structure_length", 0x04),
        ByteField("communication_channel_id", 0x01),
        ByteField("sequence_counter", None),
        ByteField("reserved", None),
        PacketField("cemi", CEMI(), CEMI)
    ]

    def post_build(self, p, pay):
        if self.structure_length is None:
            p = struct.pack("!B", len(p[:4])) + p[1:]
        return p + pay


# KNX Standard v2.1 - 03_08_03 p22
class KNXConfigurationACK(Packet):
    name = "CONFIGURATION_ACK"
    fields_desc = [
        ByteField("structure_length", None),
        ByteField("communication_channel_id", 0x01),
        ByteField("sequence_counter", None),
        ByteField("status", None)
    ]

    def post_build(self, p, pay):
        if self.structure_length is None:
            p = struct.pack("!B", len(p)) + p[1:]
        return p + pay


# KNX Standard v2.1 - 03_08_04 p.17
class KNXTunnelingRequest(Packet):
    name = "TUNNELING_REQUEST"
    fields_desc = [
        ByteField("structure_length", 0x04),
        ByteField("communication_channel_id", 0x01),
        ByteField("sequence_counter", None),
        ByteField("reserved", None),
        PacketField("cemi", CEMI(), CEMI)
    ]

    def post_build(self, p, pay):
        if self.structure_length is None:
            p = struct.pack("!B", len(p[:4])) + p[1:]
        return p + pay


# KNX Standard v2.1 - 03_08_04 p.18
class KNXTunnelingACK(Packet):
    name = "TUNNELING_ACK"
    fields_desc = [
        ByteField("structure_length", None),
        ByteField("communication_channel_id", 0x01),
        ByteField("sequence_counter", None),
        ByteField("status", None)
    ]

    def post_build(self, p, pay):
        if self.structure_length is None:
            p = struct.pack("!B", len(p)) + p[1:]
        return p + pay


# KNX FRAME

# we made the choice to define a KNX service as a payload for a KNX Header
# it could also be possible to define the body as a conditional PacketField
# contained after header

class KNX(Packet):
    name = "KNXnet/IP"
    fields_desc = [
        ByteField("header_length", None),
        XByteField("protocol_version", 0x10),
        ShortEnumField("service_identifier", None, SERVICE_IDENTIFIER_CODES),
        ShortField("total_length", None)
    ]

    def post_build(self, p, pay):
        # computes header_length
        if self.header_length is None:
            p = struct.pack("!B", len(p)) + p[1:]
        # computes total_length
        if self.total_length is None:
            p = p[:-2] + struct.pack("!H", len(p) + len(pay))
        return p + pay


# LAYERS BINDING
bind_bottom_up(UDP, KNX, dport=3671)
bind_bottom_up(UDP, KNX, sport=3671)
bind_layers(UDP, KNX, sport=3671, dport=3671)

bind_layers(KNX, KNXSearchRequest, service_identifier=0x0201)
bind_layers(KNX, KNXSearchResponse, service_identifier=0x0202)
bind_layers(KNX, KNXDescriptionRequest, service_identifier=0x0203)
bind_layers(KNX, KNXDescriptionResponse, service_identifier=0x0204)
bind_layers(KNX, KNXConnectRequest, service_identifier=0x0205)
bind_layers(KNX, KNXConnectResponse, service_identifier=0x0206)
bind_layers(KNX, KNXConnectionstateRequest, service_identifier=0x0207)
bind_layers(KNX, KNXConnectionstateResponse, service_identifier=0x0208)
bind_layers(KNX, KNXDisconnectResponse, service_identifier=0x020A)
bind_layers(KNX, KNXDisconnectRequest, service_identifier=0x0209)
bind_layers(KNX, KNXConfigurationRequest, service_identifier=0x0310)
bind_layers(KNX, KNXConfigurationACK, service_identifier=0x0311)
bind_layers(KNX, KNXTunnelingRequest, service_identifier=0x0420)
bind_layers(KNX, KNXTunnelingACK, service_identifier=0x0421)

# we bind every layer to Padding in order to delete their payloads
# (from https://github.com/secdev/scapy/issues/360)
# we could also define a new Packet class with no payload and
# inherit every KNX packet from it :
# class _KNXBodyNoPayload(Packet):
#
#     def extract_padding(self, s):
#         return b"", None

bind_layers(HPAI, Padding)
bind_layers(ServiceFamily, Padding)
bind_layers(DIBDeviceInfo, Padding)
bind_layers(DIBSuppSvcFamilies, Padding)
bind_layers(TunnelingConnection, Padding)
bind_layers(CRDTunnelingConnection, Padding)
bind_layers(CRI, Padding)
bind_layers(CRD, Padding)
bind_layers(LcEMI, Padding)
bind_layers(DPcEMI, Padding)
bind_layers(CEMI, Padding)

bind_layers(KNXSearchRequest, Padding)
bind_layers(KNXSearchResponse, Padding)
bind_layers(KNXDescriptionRequest, Padding)
bind_layers(KNXDescriptionResponse, Padding)
bind_layers(KNXConnectRequest, Padding)
bind_layers(KNXConnectResponse, Padding)
bind_layers(KNXConnectionstateRequest, Padding)
bind_layers(KNXConnectionstateResponse, Padding)
bind_layers(KNXDisconnectRequest, Padding)
bind_layers(KNXDisconnectResponse, Padding)
bind_layers(KNXConfigurationRequest, Padding)
bind_layers(KNXConfigurationACK, Padding)
bind_layers(KNXTunnelingRequest, Padding)
bind_layers(KNXTunnelingACK, Padding)
