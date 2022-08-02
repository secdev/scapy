# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Ryan Speers <ryan@rmspeers.com> 2011-2012
# Copyright (C) Roger Meyer <roger.meyer@csus.edu>: 2012-03-10 Added frames
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>: 2018
# Copyright (C) 2020-2021 Dimitrios-Georgios Akestoridis <akestoridis@cmu.edu>

"""
ZigBee bindings for IEEE 802.15.4.
"""

import struct

from scapy.compat import orb
from scapy.packet import bind_layers, bind_bottom_up, Packet
from scapy.fields import BitField, ByteField, XLEIntField, ConditionalField, \
    ByteEnumField, EnumField, BitEnumField, FieldListField, FlagsField, \
    IntField, PacketListField, ShortField, StrField, StrFixedLenField, \
    StrLenField, XLEShortField, XStrField

from scapy.layers.dot15d4 import dot15d4AddressField, Dot15d4Beacon, Dot15d4, \
    Dot15d4FCS
from scapy.layers.inet import UDP
from scapy.layers.ntp import TimeStampField


# APS Profile Identifiers
_aps_profile_identifiers = {
    0x0000: "Zigbee_Device_Profile",
    0x0101: "IPM_Industrial_Plant_Monitoring",
    0x0104: "HA_Home_Automation",
    0x0105: "CBA_Commercial_Building_Automation",
    0x0107: "TA_Telecom_Applications",
    0x0108: "HC_Health_Care",
    0x0109: "SE_Smart_Energy_Profile",
}

# ZigBee Cluster Library Identifiers, Table 2.2 ZCL
_zcl_cluster_identifier = {
    # Functional Domain: General
    0x0000: "basic",
    0x0001: "power_configuration",
    0x0002: "device_temperature_configuration",
    0x0003: "identify",
    0x0004: "groups",
    0x0005: "scenes",
    0x0006: "on_off",
    0x0007: "on_off_switch_configuration",
    0x0008: "level_control",
    0x0009: "alarms",
    0x000a: "time",
    0x000b: "rssi_location",
    0x000c: "analog_input",
    0x000d: "analog_output",
    0x000e: "analog_value",
    0x000f: "binary_input",
    0x0010: "binary_output",
    0x0011: "binary_value",
    0x0012: "multistate_input",
    0x0013: "multistate_output",
    0x0014: "multistate_value",
    0x0015: "commissioning",
    # 0x0016 - 0x00ff reserved
    # Functional Domain: Closures
    0x0100: "shade_configuration",
    # 0x0101 - 0x01ff reserved
    # Functional Domain: HVAC
    0x0200: "pump_configuration_and_control",
    0x0201: "thermostat",
    0x0202: "fan_control",
    0x0203: "dehumidification_control",
    0x0204: "thermostat_user_interface_configuration",
    # 0x0205 - 0x02ff reserved
    # Functional Domain: Lighting
    0x0300: "color_control",
    0x0301: "ballast_configuration",
    # Functional Domain: Measurement and sensing
    0x0400: "illuminance_measurement",
    0x0401: "illuminance_level_sensing",
    0x0402: "temperature_measurement",
    0x0403: "pressure_measurement",
    0x0404: "flow_measurement",
    0x0405: "relative_humidity_measurement",
    0x0406: "occupancy_sensing",
    # Functional Domain: Security and safethy
    0x0500: "ias_zone",
    0x0501: "ias_ace",
    0x0502: "ias_wd",
    # Functional Domain: Protocol Interfaces
    0x0600: "generic_tunnel",
    0x0601: "bacnet_protocol_tunnel",
    0x0602: "analog_input_regular",
    0x0603: "analog_input_extended",
    0x0604: "analog_output_regular",
    0x0605: "analog_output_extended",
    0x0606: "analog_value_regular",
    0x0607: "analog_value_extended",
    0x0608: "binary_input_regular",
    0x0609: "binary_input_extended",
    0x060a: "binary_output_regular",
    0x060b: "binary_output_extended",
    0x060c: "binary_value_regular",
    0x060d: "binary_value_extended",
    0x060e: "multistate_input_regular",
    0x060f: "multistate_input_extended",
    0x0610: "multistate_output_regular",
    0x0611: "multistate_output_extended",
    0x0612: "multistate_value_regular",
    0x0613: "multistate_value",
    # Smart Energy Profile Clusters
    0x0700: "price",
    0x0701: "demand_response_and_load_control",
    0x0702: "metering",
    0x0703: "messaging",
    0x0704: "smart_energy_tunneling",
    0x0705: "prepayment",
    # Functional Domain: General
    # Key Establishment
    0x0800: "key_establishment",
}

# ZigBee Cluster Library, Table 2.8 ZCL Command Frames
_zcl_command_frames = {
    0x00: "read_attributes",
    0x01: "read_attributes_response",
    0x02: "write_attributes",
    0x03: "write_attributes_undivided",
    0x04: "write_attributes_response",
    0x05: "write_attributes_no_response",
    0x06: "configure_reporting",
    0x07: "configure_reporting_response",
    0x08: "read_reporting_configuration",
    0x09: "read_reporting_configuration_response",
    0x0a: "report_attributes",
    0x0b: "default_response",
    0x0c: "discover_attributes",
    0x0d: "discover_attributes_response",
    0x0e: "read_attributes_structured",
    0x0f: "write_attributes_structured",
    0x10: "write_attributes_structured_response",
    0x11: "discover_commands_received",
    0x12: "discover_commands_received_response",
    0x13: "discover_commands_generated",
    0x14: "discover_commands_generated_response",
    0x15: "discover_attributes_extended",
    0x16: "discover_attributes_extended_response",
    # 0x17 - 0xff Reserved
}

# ZigBee Cluster Library, Table 2.16 Enumerated Status Values
_zcl_enumerated_status_values = {
    0x00: "SUCCESS",
    0x01: "FAILURE",
    # 0x02 - 0x7d Reserved
    0x7e: "NOT_AUTHORIZED",
    0x7f: "RESERVED_FIELD_NOT_ZERO",
    0x80: "MALFORMED_COMMAND",
    0x81: "UNSUP_CLUSTER_COMMAND",
    0x82: "UNSUP_GENERAL_COMMAND",
    0x83: "UNSUP_MANUF_CLUSTER_COMMAND",
    0x84: "UNSUP_MANUF_GENERAL_COMMAND",
    0x85: "INVALID_FIELD",
    0x86: "UNSUPPORTED_ATTRIBUTE",
    0x87: "INVALID_VALUE",
    0x88: "READ_ONLY",
    0x89: "INSUFFICIENT_SPACE",
    0x8a: "DUPLICATE_EXISTS",
    0x8b: "NOT_FOUND",
    0x8c: "UNREPORTABLE_ATTRIBUTE",
    0x8d: "INVALID_DATA_TYPE",
    0x8e: "INVALID_SELECTOR",
    0x8f: "WRITE_ONLY",
    0x90: "INCONSISTENT_STARTUP_STATE",
    0x91: "DEFINED_OUT_OF_BAND",
    0x92: "INCONSISTENT",
    0x93: "ACTION_DENIED",
    0x94: "TIMEOUT",
    0x95: "ABORT",
    0x96: "INVALID_IMAGE",
    0x97: "WAIT_FOR_DATA",
    0x98: "NO_IMAGE_AVAILABLE",
    0x99: "REQUIRE_MORE_IMAGE",
    0x9a: "NOTIFICATION_PENDING",
    # 0x9b - 0xbf Reserved
    0xc0: "HARDWARE_FAILURE",
    0xc1: "SOFTWARE_FAILURE",
    0xc2: "CALIBRATION_ERROR",
    0xc3: "UNSUPPORTED_CLUSTER",
    # 0xc4 - 0xff Reserved
}

# ZigBee Cluster Library, Table 2.15 Data Types
_zcl_attribute_data_types = {
    0x00: "no_data",
    # General data
    0x08: "8-bit_data",
    0x09: "16-bit_data",
    0x0a: "24-bit_data",
    0x0b: "32-bit_data",
    0x0c: "40-bit_data",
    0x0d: "48-bit_data",
    0x0e: "56-bit_data",
    0x0f: "64-bit_data",
    # Logical
    0x10: "boolean",
    # Bitmap
    0x18: "8-bit_bitmap",
    0x19: "16-bit_bitmap",
    0x1a: "24-bit_bitmap",
    0x1b: "32-bit_bitmap",
    0x1c: "40-bit_bitmap",
    0x1d: "48-bit_bitmap",
    0x1e: "56-bit_bitmap",
    0x1f: "64-bit_bitmap",
    # Unsigned integer
    0x20: "Unsigned_8-bit_integer",
    0x21: "Unsigned_16-bit_integer",
    0x22: "Unsigned_24-bit_integer",
    0x23: "Unsigned_32-bit_integer",
    0x24: "Unsigned_40-bit_integer",
    0x25: "Unsigned_48-bit_integer",
    0x26: "Unsigned_56-bit_integer",
    0x27: "Unsigned_64-bit_integer",
    # Signed integer
    0x28: "Signed_8-bit_integer",
    0x29: "Signed_16-bit_integer",
    0x2a: "Signed_24-bit_integer",
    0x2b: "Signed_32-bit_integer",
    0x2c: "Signed_40-bit_integer",
    0x2d: "Signed_48-bit_integer",
    0x2e: "Signed_56-bit_integer",
    0x2f: "Signed_64-bit_integer",
    # Enumeration
    0x30: "8-bit_enumeration",
    0x31: "16-bit_enumeration",
    # Floating point
    0x38: "semi_precision",
    0x39: "single_precision",
    0x3a: "double_precision",
    # String
    0x41: "octet-string",
    0x42: "character_string",
    0x43: "long_octet_string",
    0x44: "long_character_string",
    # Ordered sequence
    0x48: "array",
    0x4c: "structure",
    # Collection
    0x50: "set",
    0x51: "bag",
    # Time
    0xe0: "time_of_day",
    0xe1: "date",
    0xe2: "utc_time",
    # Identifier
    0xe8: "cluster_id",
    0xe9: "attribute_id",
    0xea: "bacnet_oid",
    # Miscellaneous
    0xf0: "ieee_address",
    0xf1: "128-bit_security_key",
    # Unknown
    0xff: "unknown",
}

# Zigbee Cluster Library, IAS Zone, Enroll Response Codes
_zcl_ias_zone_enroll_response_codes = {
    0x00: "Success",
    0x01: "Not supported",
    0x02: "No enroll permit",
    0x03: "Too many zones",
}

# Zigbee Cluster Library, IAS Zone, Zone Types
_zcl_ias_zone_zone_types = {
    0x0000: "Standard CIE",
    0x000d: "Motion sensor",
    0x0015: "Contact switch",
    0x0028: "Fire sensor",
    0x002a: "Water sensor",
    0x002b: "Carbon Monoxide (CO) sensor",
    0x002c: "Personal emergency device",
    0x002d: "Vibration/Movement sensor",
    0x010f: "Remote Control",
    0x0115: "Key fob",
    0x021d: "Keypad",
    0x0225: "Standard Warning Device",
    0x0226: "Glass break sensor",
    0x0229: "Security repeater",
    # 0x8000 - 0xfffe Manufacturer-specific types
    0xffff: "Invalid Zone Type",
}


# ZigBee #

class ZigbeeNWK(Packet):
    name = "Zigbee Network Layer"
    fields_desc = [
        BitField("discover_route", 0, 2),
        BitField("proto_version", 2, 4),
        BitEnumField("frametype", 0, 2,
                     {0: 'data', 1: 'command', 3: 'Inter-PAN'}),
        FlagsField("flags", 0, 8, ['multicast', 'security', 'source_route', 'extended_dst', 'extended_src', 'reserved1', 'reserved2', 'reserved3']),  # noqa: E501
        XLEShortField("destination", 0),
        XLEShortField("source", 0),
        ByteField("radius", 0),
        ByteField("seqnum", 1),

        # ConditionalField(XLongField("ext_dst", 0), lambda pkt:pkt.flags & 8),

        ConditionalField(dot15d4AddressField("ext_dst", 0, adjust=lambda pkt, x: 8), lambda pkt:pkt.flags & 8),  # noqa: E501
        ConditionalField(dot15d4AddressField("ext_src", 0, adjust=lambda pkt, x: 8), lambda pkt:pkt.flags & 16),  # noqa: E501

        ConditionalField(ByteField("relay_count", 1), lambda pkt:pkt.flags & 0x04),  # noqa: E501
        ConditionalField(ByteField("relay_index", 0), lambda pkt:pkt.flags & 0x04),  # noqa: E501
        ConditionalField(FieldListField("relays", [], XLEShortField("", 0x0000), count_from=lambda pkt:pkt.relay_count), lambda pkt:pkt.flags & 0x04),  # noqa: E501
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            frametype = ord(_pkt[:1]) & 3
            if frametype == 3:
                return ZigbeeNWKStub
        return cls

    def guess_payload_class(self, payload):
        if self.flags.security:
            return ZigbeeSecurityHeader
        elif self.frametype == 0:
            return ZigbeeAppDataPayload
        elif self.frametype == 1:
            return ZigbeeNWKCommandPayload
        else:
            return Packet.guess_payload_class(self, payload)


class LinkStatusEntry(Packet):
    name = "ZigBee Link Status Entry"

    fields_desc = [
        # Neighbor network address (2 octets)
        XLEShortField("neighbor_network_address", 0x0000),
        # Link status (1 octet)
        BitField("reserved1", 0, 1),
        BitField("outgoing_cost", 0, 3),
        BitField("reserved2", 0, 1),
        BitField("incoming_cost", 0, 3),
    ]

    def extract_padding(self, p):
        return b"", p


class ZigbeeNWKCommandPayload(Packet):
    name = "Zigbee Network Layer Command Payload"
    fields_desc = [
        ByteEnumField("cmd_identifier", 1, {
            1: "route request",
            2: "route reply",
            3: "network status",
            4: "leave",
            5: "route record",
            6: "rejoin request",
            7: "rejoin response",
            8: "link status",
            9: "network report",
            10: "network update",
            11: "end device timeout request",
            12: "end device timeout response"
            # 0x0d - 0xff reserved
        }),

        # - Route Request Command - #
        # Command options (1 octet)
        ConditionalField(BitField("res1", 0, 1),
                         lambda pkt: pkt.cmd_identifier in [1, 2]),
        ConditionalField(BitField("multicast", 0, 1),
                         lambda pkt: pkt.cmd_identifier in [1, 2]),
        ConditionalField(BitField("dest_addr_bit", 0, 1), lambda pkt: pkt.cmd_identifier == 1),  # noqa: E501
        ConditionalField(
            BitEnumField("many_to_one", 0, 2, {
                0: "not_m2one", 1: "m2one_support_rrt", 2: "m2one_no_support_rrt", 3: "reserved"}  # noqa: E501
            ), lambda pkt: pkt.cmd_identifier == 1),
        ConditionalField(BitField("res2", 0, 3), lambda pkt: pkt.cmd_identifier == 1),  # noqa: E501

        # - Route Reply Command - #
        # Command options (1 octet)
        ConditionalField(BitField("responder_addr_bit", 0, 1), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        ConditionalField(BitField("originator_addr_bit", 0, 1), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        ConditionalField(BitField("res3", 0, 4), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        # Route request identifier (1 octet)
        ConditionalField(ByteField("route_request_identifier", 0),
                         lambda pkt: pkt.cmd_identifier in [1, 2]),  # noqa: E501
        # Originator address (2 octets)
        ConditionalField(XLEShortField("originator_address", 0x0000), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        # Responder address (2 octets)
        ConditionalField(XLEShortField("responder_address", 0x0000), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501

        # - Network Status Command - #
        # Status code (1 octet)
        ConditionalField(ByteEnumField("status_code", 0, {
            0x00: "No route available",
            0x01: "Tree link failure",
            0x02: "Non-tree link failure",
            0x03: "Low battery level",
            0x04: "No routing capacity",
            0x05: "No indirect capacity",
            0x06: "Indirect transaction expiry",
            0x07: "Target device unavailable",
            0x08: "Target address unallocated",
            0x09: "Parent link failure",
            0x0a: "Validate route",
            0x0b: "Source route failure",
            0x0c: "Many-to-one route failure",
            0x0d: "Address conflict",
            0x0e: "Verify addresses",
            0x0f: "PAN identifier update",
            0x10: "Network address update",
            0x11: "Bad frame counter",
            0x12: "Bad key sequence number",
            # 0x13 - 0xff Reserved
        }), lambda pkt: pkt.cmd_identifier == 3),
        # Destination address (2 octets)
        ConditionalField(XLEShortField("destination_address", 0x0000),
                         lambda pkt: pkt.cmd_identifier in [1, 3]),
        # Path cost (1 octet)
        ConditionalField(ByteField("path_cost", 0),
                         lambda pkt: pkt.cmd_identifier in [1, 2]),  # noqa: E501
        # Destination IEEE Address (0/8 octets), only present when dest_addr_bit has a value of 1  # noqa: E501
        ConditionalField(dot15d4AddressField("ext_dst", 0, adjust=lambda pkt, x: 8),  # noqa: E501
                         lambda pkt: (pkt.cmd_identifier == 1 and pkt.dest_addr_bit == 1)),  # noqa: E501
        # Originator IEEE address (0/8 octets)
        ConditionalField(dot15d4AddressField("originator_addr", 0, adjust=lambda pkt, x: 8),  # noqa: E501
                         lambda pkt: (pkt.cmd_identifier == 2 and pkt.originator_addr_bit == 1)),  # noqa: E501
        # Responder IEEE address (0/8 octets)
        ConditionalField(dot15d4AddressField("responder_addr", 0, adjust=lambda pkt, x: 8),  # noqa: E501
                         lambda pkt: (pkt.cmd_identifier == 2 and pkt.responder_addr_bit == 1)),  # noqa: E501

        # - Leave Command - #
        # Command options (1 octet)
        # Bit 7: Remove children
        ConditionalField(BitField("remove_children", 0, 1), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501
        # Bit 6: Request
        ConditionalField(BitField("request", 0, 1), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501
        # Bit 5: Rejoin
        ConditionalField(BitField("rejoin", 0, 1), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501
        # Bit 0 - 4: Reserved
        ConditionalField(BitField("res4", 0, 5), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501

        # - Route Record Command - #
        # Relay count (1 octet)
        ConditionalField(ByteField("rr_relay_count", 0), lambda pkt: pkt.cmd_identifier == 5),  # noqa: E501
        # Relay list (variable in length)
        ConditionalField(
            FieldListField("rr_relay_list", [], XLEShortField("", 0x0000), count_from=lambda pkt:pkt.rr_relay_count),  # noqa: E501
            lambda pkt:pkt.cmd_identifier == 5),

        # - Rejoin Request Command - #
        # Capability Information (1 octet)
        ConditionalField(BitField("allocate_address", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Allocate Address  # noqa: E501
        ConditionalField(BitField("security_capability", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Security Capability  # noqa: E501
        ConditionalField(BitField("reserved2", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # bit 5 is reserved  # noqa: E501
        ConditionalField(BitField("reserved1", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # bit 4 is reserved  # noqa: E501
        ConditionalField(BitField("receiver_on_when_idle", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Receiver On When Idle  # noqa: E501
        ConditionalField(BitField("power_source", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Power Source  # noqa: E501
        ConditionalField(BitField("device_type", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Device Type  # noqa: E501
        ConditionalField(BitField("alternate_pan_coordinator", 0, 1), lambda pkt:pkt.cmd_identifier == 6),  # Alternate PAN Coordinator  # noqa: E501

        # - Rejoin Response Command - #
        # Network address (2 octets)
        ConditionalField(XLEShortField("network_address", 0xFFFF), lambda pkt:pkt.cmd_identifier == 7),  # noqa: E501
        # Rejoin status (1 octet)
        ConditionalField(ByteField("rejoin_status", 0), lambda pkt:pkt.cmd_identifier == 7),  # noqa: E501

        # - Link Status Command - #
        # Command options (1 octet)
        ConditionalField(BitField("res5", 0, 1), lambda pkt:pkt.cmd_identifier == 8),  # Reserved  # noqa: E501
        ConditionalField(BitField("last_frame", 0, 1), lambda pkt:pkt.cmd_identifier == 8),  # Last frame  # noqa: E501
        ConditionalField(BitField("first_frame", 0, 1), lambda pkt:pkt.cmd_identifier == 8),  # First frame  # noqa: E501
        ConditionalField(BitField("entry_count", 0, 5), lambda pkt:pkt.cmd_identifier == 8),  # Entry count  # noqa: E501
        # Link status list (variable size)
        ConditionalField(
            PacketListField("link_status_list", [], LinkStatusEntry, count_from=lambda pkt:pkt.entry_count),  # noqa: E501
            lambda pkt:pkt.cmd_identifier == 8),

        # - Network Report Command - #
        # Command options (1 octet)
        ConditionalField(
            BitEnumField("report_command_identifier", 0, 3, {0: "PAN identifier conflict"}),  # 0x01 - 0x07 Reserved  # noqa: E501
            lambda pkt: pkt.cmd_identifier == 9),
        ConditionalField(BitField("report_information_count", 0, 5), lambda pkt: pkt.cmd_identifier == 9),  # noqa: E501

        # - Network Update Command - #
        # Command options (1 octet)
        ConditionalField(
            BitEnumField("update_command_identifier", 0, 3, {0: "PAN Identifier Update"}),  # 0x01 - 0x07 Reserved  # noqa: E501
            lambda pkt: pkt.cmd_identifier == 10),
        ConditionalField(BitField("update_information_count", 0, 5), lambda pkt: pkt.cmd_identifier == 10),  # noqa: E501
        # EPID: Extended PAN ID (8 octets)
        ConditionalField(
            dot15d4AddressField("epid", 0, adjust=lambda pkt, x: 8),
            lambda pkt: pkt.cmd_identifier in [9, 10]
        ),
        # Report information (variable length)
        # Only present if we have a PAN Identifier Conflict Report
        ConditionalField(
            FieldListField("PAN_ID_conflict_report", [], XLEShortField("", 0x0000),  # noqa: E501
                           count_from=lambda pkt:pkt.report_information_count),
            lambda pkt:(pkt.cmd_identifier == 9 and pkt.report_command_identifier == 0)  # noqa: E501
        ),
        # Update Id (1 octet)
        ConditionalField(ByteField("update_id", 0), lambda pkt: pkt.cmd_identifier == 10),  # noqa: E501
        # Update Information (Variable)
        # Only present if we have a PAN Identifier Update
        # New PAN ID (2 octets)
        ConditionalField(XLEShortField("new_PAN_ID", 0x0000),
                         lambda pkt: (pkt.cmd_identifier == 10 and pkt.update_command_identifier == 0)),  # noqa: E501

        # - End Device Timeout Request Command - #
        # Requested Timeout (1 octet)
        ConditionalField(
            ByteEnumField("req_timeout", 3, {
                0: "10 seconds",
                1: "2 minutes",
                2: "4 minutes",
                3: "8 minutes",
                4: "16 minutes",
                5: "32 minutes",
                6: "64 minutes",
                7: "128 minutes",
                8: "256 minutes",
                9: "512 minutes",
                10: "1024 minutes",
                11: "2048 minutes",
                12: "4096 minutes",
                13: "8192 minutes",
                14: "16384 minutes"
            }),
            lambda pkt: pkt.cmd_identifier == 11),
        # End Device Configuration (1 octet)
        ConditionalField(
            ByteField("ed_conf", 0),
            lambda pkt: pkt.cmd_identifier == 11),

        # - End Device Timeout Response Command - #
        # Status (1 octet)
        ConditionalField(
            ByteEnumField("status", 0, {
                0: "Success",
                1: "Incorrect Value"
            }),
            lambda pkt: pkt.cmd_identifier == 12),
        # Parent Information (1 octet)
        ConditionalField(
            BitField("res6", 0, 6),
            lambda pkt: pkt.cmd_identifier == 12),
        ConditionalField(
            BitField("ed_timeout_req_keepalive", 0, 1),
            lambda pkt: pkt.cmd_identifier == 12),
        ConditionalField(
            BitField("mac_data_poll_keepalive", 0, 1),
            lambda pkt: pkt.cmd_identifier == 12)

        # StrField("data", ""),
    ]


def util_mic_len(pkt):
    ''' Calculate the length of the attribute value field '''
    if (pkt.nwk_seclevel == 0):  # no encryption, no mic
        return 0
    elif (pkt.nwk_seclevel == 1):  # MIC-32
        return 4
    elif (pkt.nwk_seclevel == 2):  # MIC-64
        return 8
    elif (pkt.nwk_seclevel == 3):  # MIC-128
        return 16
    elif (pkt.nwk_seclevel == 4):  # ENC
        return 0
    elif (pkt.nwk_seclevel == 5):  # ENC-MIC-32
        return 4
    elif (pkt.nwk_seclevel == 6):  # ENC-MIC-64
        return 8
    elif (pkt.nwk_seclevel == 7):  # ENC-MIC-128
        return 16
    else:
        return 0


class ZigbeeSecurityHeader(Packet):
    name = "Zigbee Security Header"
    fields_desc = [
        # Security control (1 octet)
        FlagsField("reserved1", 0, 2, ['reserved1', 'reserved2']),
        BitField("extended_nonce", 1, 1),  # set to 1 if the sender address field is present (source)  # noqa: E501
        # Key identifier
        BitEnumField("key_type", 1, 2, {
            0: 'data_key',
            1: 'network_key',
            2: 'key_transport_key',
            3: 'key_load_key'
        }),
        # Security level (3 bits)
        BitEnumField("nwk_seclevel", 0, 3, {
            0: "None",
            1: "MIC-32",
            2: "MIC-64",
            3: "MIC-128",
            4: "ENC",
            5: "ENC-MIC-32",
            6: "ENC-MIC-64",
            7: "ENC-MIC-128"
        }),
        # Frame counter (4 octets)
        XLEIntField("fc", 0),  # provide frame freshness and prevent duplicate frames  # noqa: E501
        # Source address (0/8 octets)
        ConditionalField(dot15d4AddressField("source", 0, adjust=lambda pkt, x: 8), lambda pkt: pkt.extended_nonce),  # noqa: E501
        # Key sequence number (0/1 octet): only present when key identifier is 1 (network key)  # noqa: E501
        ConditionalField(ByteField("key_seqnum", 0), lambda pkt: pkt.getfieldval("key_type") == 1),  # noqa: E501
        # Payload
        # the length of the encrypted data is the payload length minus the MIC
        StrField("data", ""),  # noqa: E501
        # Message Integrity Code (0/variable in size), length depends on nwk_seclevel  # noqa: E501
        XStrField("mic", ""),
    ]

    def post_dissect(self, s):
        # Get the mic dissected correctly
        mic_length = util_mic_len(self)
        if mic_length > 0:  # Slice "data" into "data + mic"
            _data, _mic = self.data[:-mic_length], self.data[-mic_length:]
            self.data, self.mic = _data, _mic
        return s


class ZigbeeAppDataPayload(Packet):
    name = "Zigbee Application Layer Data Payload (General APS Frame Format)"
    fields_desc = [
        # Frame control (1 octet)
        FlagsField("frame_control", 2, 4,
                   ['ack_format', 'security', 'ack_req', 'extended_hdr']),
        BitEnumField("delivery_mode", 0, 2,
                     {0: 'unicast', 1: 'indirect',
                      2: 'broadcast', 3: 'group_addressing'}),
        BitEnumField("aps_frametype", 0, 2,
                     {0: 'data', 1: 'command', 2: 'ack'}),
        # Destination endpoint (0/1 octet)
        ConditionalField(
            ByteField("dst_endpoint", 10),
            lambda pkt: ((pkt.aps_frametype == 0 and
                          pkt.delivery_mode in [0, 2]) or
                         (pkt.aps_frametype == 2 and not
                          pkt.frame_control.ack_format))
        ),
        # Group address (0/2 octets)
        ConditionalField(
            XLEShortField("group_addr", 0x0000),
            lambda pkt: (pkt.aps_frametype == 0 and pkt.delivery_mode == 3)
        ),
        # Cluster identifier (0/2 octets)
        ConditionalField(
            # unsigned short (little-endian)
            XLEShortField("cluster", 0x0000),
            lambda pkt: ((pkt.aps_frametype == 0) or
                         (pkt.aps_frametype == 2 and not
                          pkt.frame_control.ack_format))
        ),
        # Profile identifier (0/2 octets)
        ConditionalField(
            EnumField("profile", 0, _aps_profile_identifiers, fmt="<H"),
            lambda pkt: ((pkt.aps_frametype == 0) or
                         (pkt.aps_frametype == 2 and not
                          pkt.frame_control.ack_format))
        ),
        # Source endpoint (0/1 octets)
        ConditionalField(
            ByteField("src_endpoint", 10),
            lambda pkt: ((pkt.aps_frametype == 0) or
                         (pkt.aps_frametype == 2 and not
                          pkt.frame_control.ack_format))
        ),
        # APS counter (1 octet)
        ByteField("counter", 0),
        # Extended header (0/1/2 octets)
        # cribbed from https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-zbee-aps.c  # noqa: E501
        ConditionalField(
            ByteEnumField(
                "fragmentation", 0,
                {0: "none", 1: "first_block", 2: "middle_block"}),
            lambda pkt: (pkt.aps_frametype in [0, 2] and
                         pkt.frame_control.extended_hdr)
        ),
        ConditionalField(
            ByteField("block_number", 0),
            lambda pkt: (pkt.aps_frametype in [0, 2] and
                         pkt.fragmentation in [1, 2])
        ),
        ConditionalField(
            ByteField("ack_bitfield", 0),
            lambda pkt: (pkt.aps_frametype == 2 and
                         pkt.fragmentation in [1, 2])
        ),
        # variable length frame payload:
        # 3 frame types: data, APS command, and acknowledgement
        # ConditionalField(StrField("data", ""), lambda pkt:pkt.aps_frametype == 0),  # noqa: E501
    ]

    def guess_payload_class(self, payload):
        if self.frame_control & 0x02:  # we have a security header
            return ZigbeeSecurityHeader
        elif self.aps_frametype == 0:  # data
            if self.profile == 0x0000:
                return ZigbeeDeviceProfile
            else:
                return ZigbeeClusterLibrary
        elif self.aps_frametype == 1:  # command
            return ZigbeeAppCommandPayload
        else:
            return Packet.guess_payload_class(self, payload)


_TransportKeyKeyTypes = {
    0x00: "Trust Center Master Key",
    0x01: "Standard Network Key",
    0x02: "Application Master Key",
    0x03: "Application Link Key",
    0x04: "Trust Center Link Key",
    0x05: "High-Security Network Key",
}


_RequestKeyKeyTypes = {
    0x02: "Application Link Key",
    0x04: "Trust Center Link Key",
}


_ApsStatusValues = {
    0x00: "SUCCESS",
    0xa0: "ASDU_TOO_LONG",
    0xa1: "DEFRAG_DEFERRED",
    0xa2: "DEFRAG_UNSUPPORTED",
    0xa3: "ILLEGAL_REQUEST",
    0xa4: "INVALID_BINDING",
    0xa5: "INVALID_GROUP",
    0xa6: "INVALID_PARAMETER",
    0xa7: "NO_ACK",
    0xa8: "NO_BOUND_DEVICE",
    0xa9: "NO_SHORT_ADDRESS",
    0xaa: "NOT_SUPPORTED",
    0xab: "SECURED_LINK_KEY",
    0xac: "SECURED_NWK_KEY",
    0xad: "SECURITY_FAIL",
    0xae: "TABLE_FULL",
    0xaf: "UNSECURED",
    0xb0: "UNSUPPORTED_ATTRIBUTE"
}


class ZigbeeAppCommandPayload(Packet):
    name = "Zigbee Application Layer Command Payload"
    fields_desc = [
        ByteEnumField("cmd_identifier", 1, {
            1: "APS_CMD_SKKE_1",
            2: "APS_CMD_SKKE_2",
            3: "APS_CMD_SKKE_3",
            4: "APS_CMD_SKKE_4",
            5: "APS_CMD_TRANSPORT_KEY",
            6: "APS_CMD_UPDATE_DEVICE",
            7: "APS_CMD_REMOVE_DEVICE",
            8: "APS_CMD_REQUEST_KEY",
            9: "APS_CMD_SWITCH_KEY",
            # TODO: implement 10 to 13
            10: "APS_CMD_EA_INIT_CHLNG",
            11: "APS_CMD_EA_RSP_CHLNG",
            12: "APS_CMD_EA_INIT_MAC_DATA",
            13: "APS_CMD_EA_RSP_MAC_DATA",
            14: "APS_CMD_TUNNEL",
            15: "APS_CMD_VERIFY_KEY",
            16: "APS_CMD_CONFIRM_KEY"
        }),
        # SKKE Commands
        ConditionalField(dot15d4AddressField("initiator", 0,
                                             adjust=lambda pkt, x: 8),
                         lambda pkt: pkt.cmd_identifier in [1, 2, 3, 4]),
        ConditionalField(dot15d4AddressField("responder", 0,
                                             adjust=lambda pkt, x: 8),
                         lambda pkt: pkt.cmd_identifier in [1, 2, 3, 4]),
        ConditionalField(StrFixedLenField("data", 0, length=16),
                         lambda pkt: pkt.cmd_identifier in [1, 2, 3, 4]),
        # Confirm-key command
        ConditionalField(
            ByteEnumField("status", 0, _ApsStatusValues),
            lambda pkt: pkt.cmd_identifier == 16),
        # Common fields
        ConditionalField(
            ByteEnumField("key_type", 0, _TransportKeyKeyTypes),
            lambda pkt: pkt.cmd_identifier in [5, 8, 15, 16]),
        ConditionalField(dot15d4AddressField("address", 0,
                                             adjust=lambda pkt, x: 8),
                         lambda pkt: pkt.cmd_identifier in [6, 7, 15, 16]),
        # Transport-key Command
        ConditionalField(
            StrFixedLenField("key", None, 16),
            lambda pkt: pkt.cmd_identifier == 5),
        ConditionalField(
            ByteField("key_seqnum", 0),
            lambda pkt: (pkt.cmd_identifier == 5 and
                         pkt.key_type in [0x01, 0x05])),
        ConditionalField(
            dot15d4AddressField("dest_addr", 0, adjust=lambda pkt, x: 8),
            lambda pkt: ((pkt.cmd_identifier == 5 and
                         pkt.key_type not in [0x02, 0x03]) or
                         pkt.cmd_identifier == 14)),
        ConditionalField(
            dot15d4AddressField("src_addr", 0, adjust=lambda pkt, x: 8),
            lambda pkt: (pkt.cmd_identifier == 5 and
                         pkt.key_type not in [0x02, 0x03])),
        ConditionalField(
            dot15d4AddressField("partner_addr", 0, adjust=lambda pkt, x: 8),
            lambda pkt: ((pkt.cmd_identifier == 5 and
                         pkt.key_type in [0x02, 0x03]) or
                         (pkt.cmd_identifier == 8 and pkt.key_type == 0x02))),
        ConditionalField(
            ByteField("initiator_flag", 0),
            lambda pkt: (pkt.cmd_identifier == 5 and
                         pkt.key_type in [0x02, 0x03])),
        # Update-Device Command
        ConditionalField(XLEShortField("short_address", 0),
                         lambda pkt: pkt.cmd_identifier == 6),
        ConditionalField(ByteField("update_status", 0),
                         lambda pkt: pkt.cmd_identifier == 6),
        # Switch-Key Command
        ConditionalField(StrFixedLenField("seqnum", None, 8),
                         lambda pkt: pkt.cmd_identifier == 9),
        # Un-implemented: 10-13 (+?)
        ConditionalField(StrField("unimplemented", ""),
                         lambda pkt: (pkt.cmd_identifier >= 10 and
                                      pkt.cmd_identifier <= 13)),
        # Tunnel Command
        ConditionalField(
            FlagsField("frame_control", 2, 4, [
                "ack_format",
                "security",
                "ack_req",
                "extended_hdr"
            ]),
            lambda pkt: pkt.cmd_identifier == 14),
        ConditionalField(
            BitEnumField("delivery_mode", 0, 2, {
                0: "unicast",
                1: "indirect",
                2: "broadcast",
                3: "group_addressing"
            }),
            lambda pkt: pkt.cmd_identifier == 14),
        ConditionalField(
            BitEnumField("aps_frametype", 1, 2, {
                0: "data",
                1: "command",
                2: "ack"
            }),
            lambda pkt: pkt.cmd_identifier == 14),
        ConditionalField(
            ByteField("counter", 0),
            lambda pkt: pkt.cmd_identifier == 14),
        # Verify-Key Command
        ConditionalField(
            StrFixedLenField("key_hash", None, 16),
            lambda pkt: pkt.cmd_identifier == 15),
    ]

    def guess_payload_class(self, payload):
        if self.cmd_identifier == 14:
            # Tunneled APS Auxiliary Header
            return ZigbeeSecurityHeader
        else:
            return Packet.guess_payload_class(self, payload)


class ZigBeeBeacon(Packet):
    name = "ZigBee Beacon Payload"
    fields_desc = [
        # Protocol ID (1 octet)
        ByteField("proto_id", 0),
        # nwkcProtocolVersion (4 bits)
        BitField("nwkc_protocol_version", 0, 4),
        # Stack profile (4 bits)
        BitField("stack_profile", 0, 4),
        # End device capacity (1 bit)
        BitField("end_device_capacity", 0, 1),
        # Device depth (4 bits)
        BitField("device_depth", 0, 4),
        # Router capacity (1 bit)
        BitField("router_capacity", 0, 1),
        # Reserved (2 bits)
        BitField("reserved", 0, 2),
        # Extended PAN ID (8 octets)
        dot15d4AddressField("extended_pan_id", 0, adjust=lambda pkt, x: 8),
        # Tx offset (3 bytes)
        # In ZigBee 2006 the Tx-Offset is optional, while in the 2007 and later versions, the Tx-Offset is a required value.  # noqa: E501
        BitField("tx_offset", 0, 24),
        # Update ID (1 octet)
        ByteField("update_id", 0),
    ]


# Inter-PAN Transmission #
class ZigbeeNWKStub(Packet):
    name = "Zigbee Network Layer for Inter-PAN Transmission"
    fields_desc = [
        # NWK frame control
        BitField("res1", 0, 2),  # remaining subfields shall have a value of 0  # noqa: E501
        BitField("proto_version", 2, 4),
        BitField("frametype", 0b11, 2),  # 0b11 (3) is a reserved frame type
        BitField("res2", 0, 8),  # remaining subfields shall have a value of 0  # noqa: E501
    ]

    def guess_payload_class(self, payload):
        if self.frametype == 0b11:
            return ZigbeeAppDataPayloadStub
        else:
            return Packet.guess_payload_class(self, payload)


class ZigbeeAppDataPayloadStub(Packet):
    name = "Zigbee Application Layer Data Payload for Inter-PAN Transmission"
    fields_desc = [
        FlagsField("frame_control", 0, 4, ['reserved1', 'security', 'ack_req', 'extended_hdr']),  # noqa: E501
        BitEnumField("delivery_mode", 0, 2, {0: 'unicast', 2: 'broadcast', 3: 'group'}),  # noqa: E501
        BitField("frametype", 3, 2),  # value 0b11 (3) is a reserved frame type
        # Group Address present only when delivery mode field has a value of 0b11 (group delivery mode)  # noqa: E501
        ConditionalField(
            XLEShortField("group_addr", 0x0),  # 16-bit identifier of the group
            lambda pkt: pkt.getfieldval("delivery_mode") == 0b11
        ),
        # Cluster identifier
        XLEShortField("cluster", 0x0000),
        # Profile identifier
        EnumField("profile", 0, _aps_profile_identifiers, fmt="<H"),
        # ZigBee Payload
        ConditionalField(
            StrField("data", ""),
            lambda pkt: pkt.frametype == 3
        ),
    ]


# Zigbee Device Profile #


class ZDPActiveEPReq(Packet):
    name = "ZDP Transaction Data: Active_EP_req"
    fields_desc = [
        # NWK Address (2 octets)
        XLEShortField("nwk_addr", 0),
    ]


class ZDPDeviceAnnce(Packet):
    name = "ZDP Transaction Data: Device_annce"
    fields_desc = [
        # NWK Address (2 octets)
        XLEShortField("nwk_addr", 0),
        # IEEE Address (8 octets)
        dot15d4AddressField("ieee_addr", 0, adjust=lambda pkt, x: 8),
        # Capability Information (1 octet)
        BitField("allocate_address", 0, 1),
        BitField("security_capability", 0, 1),
        BitField("reserved2", 0, 1),
        BitField("reserved1", 0, 1),
        BitField("receiver_on_when_idle", 0, 1),
        BitField("power_source", 0, 1),
        BitField("device_type", 0, 1),
        BitField("alternate_pan_coordinator", 0, 1),
    ]


class ZigbeeDeviceProfile(Packet):
    name = "Zigbee Device Profile (ZDP) Frame"
    fields_desc = [
        # Transaction Sequence Number (1 octet)
        ByteField("trans_seqnum", 0),
    ]

    def guess_payload_class(self, payload):
        if self.underlayer.cluster == 0x0005:
            return ZDPActiveEPReq
        elif self.underlayer.cluster == 0x0013:
            return ZDPDeviceAnnce
        return Packet.guess_payload_class(self, payload)


# ZigBee Cluster Library #


_ZCL_attr_length = {
    0x00: 0,  # no data
    0x08: 1,  # 8-bit data
    0x09: 2,  # 16-bit data
    0x0a: 3,  # 24-bit data
    0x0b: 4,  # 32-bit data
    0x0c: 5,  # 40-bit data
    0x0d: 6,  # 48-bit data
    0x0e: 7,  # 56-bit data
    0x0f: 8,  # 64-bit data
    0x10: 1,  # boolean
    0x18: 1,  # 8-bit bitmap
    0x19: 2,  # 16-bit bitmap
    0x1a: 3,  # 24-bit bitmap
    0x1b: 4,  # 32-bit bitmap
    0x1c: 5,  # 40-bit bitmap
    0x1d: 6,  # 48-bit bitmap
    0x1e: 7,  # 46-bit bitmap
    0x1f: 8,  # 64-bit bitmap
    0x20: 1,  # Unsigned 8-bit integer
    0x21: 2,  # Unsigned 16-bit integer
    0x22: 3,  # Unsigned 24-bit integer
    0x23: 4,  # Unsigned 32-bit integer
    0x24: 5,  # Unsigned 40-bit integer
    0x25: 6,  # Unsigned 48-bit integer
    0x26: 7,  # Unsigned 56-bit integer
    0x27: 8,  # Unsigned 64-bit integer
    0x28: 1,  # Signed 8-bit integer
    0x29: 2,  # Signed 16-bit integer
    0x2a: 3,  # Signed 24-bit integer
    0x2b: 4,  # Signed 32-bit integer
    0x2c: 5,  # Signed 40-bit integer
    0x2d: 6,  # Signed 48-bit integer
    0x2e: 7,  # Signed 56-bit integer
    0x2f: 8,  # Signed 64-bit integer
    0x30: 1,  # 8-bit enumeration
    0x31: 2,  # 16-bit enumeration
    0x38: 2,  # Semi-precision
    0x39: 4,  # Single precision
    0x3a: 8,  # Double precision
    0x41: (1, "!B"),  # Octet string
    0x42: (1, "!B"),  # Character string
    0x43: (2, "!H"),  # Long octet string
    0x44: (2, "!H"),  # Long character string
    # TODO (implement Ordered sequence & collection
    0xe0: 4,  # Time of day
    0xe1: 4,  # Date
    0xe2: 4,  # UTCTime
    0xe8: 2,  # Cluster ID
    0xe9: 2,  # Attribute ID
    0xea: 4,  # BACnet OID
    0xf0: 8,  # IEEE address
    0xf1: 16,  # 128-bit security key
    0xff: 0,  # Unknown
}


class _DiscreteString(StrLenField):
    def getfield(self, pkt, s):
        dtype = pkt.attribute_data_type
        length = _ZCL_attr_length.get(dtype, None)
        if length is None:
            return b"", self.m2i(pkt, s)
        elif isinstance(length, tuple):  # Variable length
            size, fmt = length
            # We add size as we include the length tag in the string
            length = struct.unpack(fmt, s[:size])[0] + size
        if isinstance(length, int):
            self.length_from = lambda x: length
            return StrLenField.getfield(self, pkt, s)
        return s


class ZCLReadAttributeStatusRecord(Packet):
    name = "ZCL Read Attribute Status Record"
    fields_desc = [
        # Attribute Identifier
        XLEShortField("attribute_identifier", 0),
        # Status
        ByteEnumField("status", 0, _zcl_enumerated_status_values),
        # Attribute data type (0/1 octet), and data (0/variable size)
        # are only included if status == 0x00 (SUCCESS)
        ConditionalField(
            ByteEnumField("attribute_data_type", 0, _zcl_attribute_data_types),
            lambda pkt:pkt.status == 0x00
        ),
        ConditionalField(
            _DiscreteString("attribute_value", ""),
            lambda pkt:pkt.status == 0x00
        ),
    ]

    def extract_padding(self, s):
        return "", s


class ZCLWriteAttributeRecord(Packet):
    name = "ZCL Write Attribute Record"
    fields_desc = [
        # Attribute Identifier (2 octets)
        XLEShortField("attribute_identifier", 0),
        # Attribute Data Type (1 octet)
        ByteEnumField("attribute_data_type", 0, _zcl_attribute_data_types),
        # Attribute Data (variable)
        _DiscreteString("attribute_data", ""),
    ]

    def extract_padding(self, s):
        return "", s


class ZCLWriteAttributeStatusRecord(Packet):
    name = "ZCL Write Attribute Status Record"
    fields_desc = [
        # Status (1 octet)
        ByteEnumField("status", 0, _zcl_enumerated_status_values),
        # Attribute Identifier (0/2 octets)
        ConditionalField(
            XLEShortField("attribute_identifier", 0),
            lambda pkt:pkt.status != 0x00
        ),
    ]

    def extract_padding(self, s):
        return "", s


class ZCLConfigureReportingRecord(Packet):
    name = "ZCL Configure Reporting Record"
    fields_desc = [
        # Direction (1 octet)
        ByteField("attribute_direction", 0),
        # Attribute Identifier (2 octets)
        XLEShortField("attribute_identifier", 0),
        # Attribute Data Type (0/1 octet)
        ConditionalField(
            ByteEnumField("attribute_data_type", 0, _zcl_attribute_data_types),
            lambda pkt:pkt.attribute_direction == 0x00
        ),
        # Minimum Reporting Interval (0/2 octets)
        ConditionalField(
            XLEShortField("min_reporting_interval", 0),
            lambda pkt:pkt.attribute_direction == 0x00
        ),
        # Maximum Reporting Interval (0/2 octets)
        ConditionalField(
            XLEShortField("max_reporting_interval", 0),
            lambda pkt:pkt.attribute_direction == 0x00
        ),
        # Reportable Change (variable)
        ConditionalField(
            _DiscreteString("reportable_change", ""),
            lambda pkt:pkt.attribute_direction == 0x00
        ),
        # Timeout Period (0/2 octets)
        ConditionalField(
            XLEShortField("timeout_period", 0),
            lambda pkt:pkt.attribute_direction == 0x01
        ),
    ]

    def extract_padding(self, s):
        return "", s


class ZCLConfigureReportingResponseRecord(Packet):
    name = "ZCL Configure Reporting Response Record"
    fields_desc = [
        # Status (1 octet)
        ByteEnumField("status", 0, _zcl_enumerated_status_values),
        # Direction (0/1 octet)
        ConditionalField(
            ByteField("attribute_direction", 0),
            lambda pkt:pkt.status != 0x00
        ),
        # Attribute Identifier (0/2 octets)
        ConditionalField(
            XLEShortField("attribute_identifier", 0),
            lambda pkt:pkt.status != 0x00
        ),
    ]

    def extract_padding(self, s):
        return "", s


class ZCLAttributeReport(Packet):
    name = "ZCL Attribute Report"
    fields_desc = [
        # Attribute Identifier (2 octets)
        XLEShortField("attribute_identifier", 0),
        # Attribute Data Type (1 octet)
        ByteEnumField("attribute_data_type", 0, _zcl_attribute_data_types),
        # Attribute Data (variable)
        _DiscreteString("attribute_data", ""),
    ]

    def extract_padding(self, s):
        return "", s


class ZCLGeneralReadAttributes(Packet):
    name = "General Domain: Command Frame Payload: read_attributes"
    fields_desc = [
        FieldListField("attribute_identifiers", [], XLEShortField("", 0x0000)),
    ]


class ZCLGeneralReadAttributesResponse(Packet):
    name = "General Domain: Command Frame Payload: read_attributes_response"
    fields_desc = [
        PacketListField("read_attribute_status_record", [], ZCLReadAttributeStatusRecord),  # noqa: E501
    ]


class ZCLGeneralWriteAttributes(Packet):
    name = "General Domain: Command Frame Payload: write_attributes"
    fields_desc = [
        PacketListField("write_records", [], ZCLWriteAttributeRecord),
    ]


class ZCLGeneralWriteAttributesResponse(Packet):
    name = "General Domain: Command Frame Payload: write_attributes_response"
    fields_desc = [
        PacketListField("status_records", [], ZCLWriteAttributeStatusRecord),
    ]


class ZCLGeneralConfigureReporting(Packet):
    name = "General Domain: Command Frame Payload: configure_reporting"
    fields_desc = [
        PacketListField("config_records", [], ZCLConfigureReportingRecord),
    ]


class ZCLGeneralConfigureReportingResponse(Packet):
    name = "General Domain: Command Frame Payload: configure_reporting_response"  # noqa: E501
    fields_desc = [
        PacketListField("status_records", [], ZCLConfigureReportingResponseRecord),  # noqa: E501
    ]


class ZCLGeneralReportAttributes(Packet):
    name = "General Domain: Command Frame Payload: report_attributes"
    fields_desc = [
        PacketListField("attribute_reports", [], ZCLAttributeReport),
    ]


class ZCLGeneralDefaultResponse(Packet):
    name = "General Domain: Command Frame Payload: default_response"
    fields_desc = [
        # Response Command Identifier (1 octet)
        ByteField("response_command_identifier", 0),
        # Status (1 octet)
        ByteEnumField("status", 0, _zcl_enumerated_status_values),
    ]


class ZCLIASZoneZoneEnrollResponse(Packet):
    name = "IAS Zone Cluster: Zone Enroll Response Command (Server: Received)"
    fields_desc = [
        # Enroll Response Code (1 octet)
        ByteEnumField("rsp_code", 0, _zcl_ias_zone_enroll_response_codes),
        # Zone ID (1 octet)
        ByteField("zone_id", 0),
    ]


class ZCLIASZoneZoneStatusChangeNotification(Packet):
    name = "IAS Zone Cluster: Zone Status Change Notification Command (Server: Generated)"  # noqa: E501
    fields_desc = [
        # Zone Status (2 octets)
        StrFixedLenField("zone_status", b'\x00\x00', length=2),
        # Extended Status (1 octet)
        StrFixedLenField("extended_status", b'\x00', length=1),
        # Zone ID (1 octet)
        ByteField("zone_id", 0),
        # Delay (2 octets)
        XLEShortField("delay", 0),
    ]


class ZCLIASZoneZoneEnrollRequest(Packet):
    name = "IAS Zone Cluster: Zone Enroll Request Command (Server: Generated)"
    fields_desc = [
        # Zone Type (2 octets)
        EnumField("zone_type", 0, _zcl_ias_zone_zone_types, fmt="<H"),
        # Manufacturer Code (2 octets)
        XLEShortField("manuf_code", 0),
    ]


class ZCLMeteringGetProfile(Packet):
    name = "Metering Cluster: Get Profile Command (Server: Received)"
    fields_desc = [
        # Interval Channel (8-bit Enumeration): 1 octet
        ByteField("Interval_Channel", 0),  # 0 == Consumption Delivered ; 1 == Consumption Received  # noqa: E501
        # End Time (UTCTime): 4 octets
        XLEIntField("End_Time", 0x00000000),
        # NumberOfPeriods (Unsigned 8-bit Integer): 1 octet
        ByteField("NumberOfPeriods", 1),  # Represents the number of intervals being requested.  # noqa: E501
    ]


class ZCLPriceGetCurrentPrice(Packet):
    name = "Price Cluster: Get Current Price Command (Server: Received)"
    fields_desc = [
        BitField("reserved", 0, 7),
        BitField("Requestor_Rx_On_When_Idle", 0, 1),
    ]


class ZCLPriceGetScheduledPrices(Packet):
    name = "Price Cluster: Get Scheduled Prices Command (Server: Received)"
    fields_desc = [
        XLEIntField("start_time", 0x00000000),  # UTCTime (4 octets)
        ByteField("number_of_events", 0),  # Number of Events (1 octet)
    ]


class ZCLPricePublishPrice(Packet):
    name = "Price Cluster: Publish Price Command (Server: Generated)"
    fields_desc = [
        XLEIntField("provider_id", 0x00000000),  # Unsigned 32-bit Integer (4 octets)  # noqa: E501
        # Rate Label is a UTF-8 encoded Octet String (0-12 octets). The first Octet indicates the length.  # noqa: E501
        StrLenField("rate_label", "", length_from=lambda pkt:int(pkt.rate_label[0])),  # TODO verify  # noqa: E501
        XLEIntField("issuer_event_id", 0x00000000),  # Unsigned 32-bit Integer (4 octets)  # noqa: E501
        XLEIntField("current_time", 0x00000000),  # UTCTime (4 octets)
        ByteField("unit_of_measure", 0),  # 8 bits enumeration (1 octet)
        XLEShortField("currency", 0x0000),  # Unsigned 16-bit Integer (2 octets)  # noqa: E501
        ByteField("price_trailing_digit", 0),  # 8-bit BitMap (1 octet)
        ByteField("number_of_price_tiers", 0),  # 8-bit BitMap (1 octet)
        XLEIntField("start_time", 0x00000000),  # UTCTime (4 octets)
        XLEShortField("duration_in_minutes", 0x0000),  # Unsigned 16-bit Integer (2 octets)  # noqa: E501
        XLEIntField("price", 0x00000000),  # Unsigned 32-bit Integer (4 octets)
        ByteField("price_ratio", 0),  # Unsigned 8-bit Integer (1 octet)
        XLEIntField("generation_price", 0x00000000),  # Unsigned 32-bit Integer (4 octets)  # noqa: E501
        ByteField("generation_price_ratio", 0),  # Unsigned 8-bit Integer (1 octet)  # noqa: E501
        XLEIntField("alternate_cost_delivered", 0x00000000),  # Unsigned 32-bit Integer (4 octets)  # noqa: E501
        ByteField("alternate_cost_unit", 0),  # 8-bit enumeration (1 octet)
        ByteField("alternate_cost_trailing_digit", 0),  # 8-bit BitMap (1 octet)  # noqa: E501
        ByteField("number_of_block_thresholds", 0),  # 8-bit BitMap (1 octet)
        ByteField("price_control", 0),  # 8-bit BitMap (1 octet)
    ]


class ZigbeeClusterLibrary(Packet):
    name = "Zigbee Cluster Library (ZCL) Frame"
    deprecated_fields = {
        "direction": ("command_direction", "2.5.0"),
    }
    fields_desc = [
        # Frame control (8 bits)
        BitField("reserved", 0, 3),
        BitField("disable_default_response", 0, 1),  # 0 default response command will be returned  # noqa: E501
        BitField("command_direction", 0, 1),  # 0 command sent from client to server; 1 command sent from server to client  # noqa: E501
        BitField("manufacturer_specific", 0, 1),  # 0 manufacturer code shall not be included in the ZCL frame  # noqa: E501
        # Frame Type
        # 0b00 command acts across the entire profile
        # 0b01 command is specific to a cluster
        # 0b10 - 0b11 reserved
        BitEnumField("zcl_frametype", 0, 2, {0: 'profile-wide', 1: 'cluster-specific', 2: 'reserved2', 3: 'reserved3'}),  # noqa: E501
        # Manufacturer code (0/16 bits) only present then manufacturer_specific field is set to 1  # noqa: E501
        ConditionalField(XLEShortField("manufacturer_code", 0x0),
                         lambda pkt: pkt.getfieldval("manufacturer_specific") == 1  # noqa: E501
                         ),
        # Transaction sequence number (8 bits)
        ByteField("transaction_sequence", 0),
        # Command identifier (8 bits): the cluster command
        ByteEnumField("command_identifier", 0, _zcl_command_frames),
    ]

    def guess_payload_class(self, payload):
        if self.zcl_frametype == 0x00:
            # Profile-wide command
            if (self.command_identifier in
                    {0x00, 0x01, 0x02, 0x04, 0x06, 0x07, 0x0a, 0x0b}):
                # done in bind_layers
                pass
        elif self.zcl_frametype == 0x01:
            # Cluster-specific command
            if self.underlayer.cluster == 0x0500:
                # IAS Zone
                if self.command_direction == 0:
                    # Client-to-Server command
                    if self.command_identifier == 0x00:
                        return ZCLIASZoneZoneEnrollResponse
                elif self.command_direction == 1:
                    # Server-to-Client command
                    if self.command_identifier == 0x00:
                        return ZCLIASZoneZoneStatusChangeNotification
                    elif self.command_identifier == 0x01:
                        return ZCLIASZoneZoneEnrollRequest
            elif self.underlayer.cluster == 0x0700:
                # Price cluster
                if self.command_direction == 0:
                    # Client-to-Server command
                    if self.command_identifier == 0x00:
                        return ZCLPriceGetCurrentPrice
                    elif self.command_identifier == 0x01:
                        return ZCLPriceGetScheduledPrices
                elif self.command_direction == 1:
                    # Server-to-Client command
                    if self.command_identifier == 0x00:
                        return ZCLPricePublishPrice
        return Packet.guess_payload_class(self, payload)


bind_layers(ZigbeeClusterLibrary, ZCLGeneralReadAttributes,
            zcl_frametype=0x00, command_identifier=0x00)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralReadAttributesResponse,
            zcl_frametype=0x00, command_identifier=0x01)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralWriteAttributes,
            zcl_frametype=0x00, command_identifier=0x02)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralWriteAttributesResponse,
            zcl_frametype=0x00, command_identifier=0x04)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralConfigureReporting,
            zcl_frametype=0x00, command_identifier=0x06)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralConfigureReportingResponse,
            zcl_frametype=0x00, command_identifier=0x07)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralReportAttributes,
            zcl_frametype=0x00, command_identifier=0x0a)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralDefaultResponse,
            zcl_frametype=0x00, command_identifier=0x0b)


# Zigbee Encapsulation Protocol


class ZEP2(Packet):
    name = "Zigbee Encapsulation Protocol (V2)"
    fields_desc = [
        StrFixedLenField("preamble", "EX", length=2),
        ByteField("ver", 0),
        ByteField("type", 0),
        ByteField("channel", 0),
        ShortField("device", 0),
        ByteField("lqi_mode", 1),
        ByteField("lqi_val", 0),
        TimeStampField("timestamp", 0),
        IntField("seq", 0),
        BitField("res", 0, 80),  # 10 bytes reserved field
        ByteField("length", 0),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=b"", *args, **kargs):
        if _pkt and len(_pkt) >= 4:
            v = orb(_pkt[2])
            if v == 1:
                return ZEP1
            elif v == 2:
                return ZEP2
        return cls

    def guess_payload_class(self, payload):
        if self.lqi_mode:
            return Dot15d4
        else:
            return Dot15d4FCS


class ZEP1(ZEP2):
    name = "Zigbee Encapsulation Protocol (V1)"
    fields_desc = [
        StrFixedLenField("preamble", "EX", length=2),
        ByteField("ver", 0),
        ByteField("channel", 0),
        ShortField("device", 0),
        ByteField("lqi_mode", 0),
        ByteField("lqi_val", 0),
        BitField("res", 0, 56),  # 7 bytes reserved field
        ByteField("len", 0),
    ]


# Bindings #

# TODO: find a way to chose between ZigbeeNWK and SixLoWPAN (cf. sixlowpan.py)
# Currently: use conf.dot15d4_protocol value
# bind_layers( Dot15d4Data, ZigbeeNWK)

bind_layers(ZigbeeAppDataPayload, ZigbeeAppCommandPayload, frametype=1)
bind_layers(Dot15d4Beacon, ZigBeeBeacon)

bind_bottom_up(UDP, ZEP2, sport=17754)
bind_bottom_up(UDP, ZEP2, sport=17754)
bind_layers(UDP, ZEP2, sport=17754, dport=17754)
