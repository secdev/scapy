# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
802.11 Constants for BPF filter construction.

This module contains the 802.11 frame format constants used by the
WiFi BPF Builder. Constants are based on IEEE 802.11-2016 standard.
"""

from enum import IntEnum
from typing import Dict


class WiFiConstants:
    """802.11 frame format constants for BPF filter construction."""
    
    # Frame Control field byte offsets (0-indexed)
    FRAME_CONTROL_BYTE_0 = 0  # Type, subtype, protocol version
    FRAME_CONTROL_BYTE_1 = 1  # Flags (to-DS, from-DS, etc.)
    
    # Frame Control byte 1 flag masks  
    TO_DS_MASK = 0x01         # To DS flag
    FROM_DS_MASK = 0x02       # From DS flag  
    DS_FLAGS_MASK = 0x03      # Both DS flags
    RETRY_FLAG_MASK = 0x08    # Retry flag
    PROTECTED_MASK = 0x40     # Protected frame flag
    
    # Frame Control byte 0 masks
    TYPE_MASK = 0x0C          # Frame type field
    SUBTYPE_MASK = 0xF0       # Frame subtype field
    TYPE_SUBTYPE_MASK = 0xFC  # Combined type and subtype
    
    # Common frame type/subtype combinations
    BEACON_FRAME = 0x80       # Type=0 (management), Subtype=8 (beacon)
    PROBE_REQ_FRAME = 0x40    # Type=0 (management), Subtype=4 (probe req)
    PROBE_RESP_FRAME = 0x50   # Type=0 (management), Subtype=5 (probe resp)
    DATA_FRAME = 0x08         # Type=2 (data), Subtype=0 (data)
    QOS_DATA_FRAME = 0x88     # Type=2 (data), Subtype=8 (QoS data)


class FrameType(IntEnum):
    """802.11 frame types."""
    MANAGEMENT = 0
    CONTROL = 1  
    DATA = 2
    EXTENSION = 3


class ManagementSubtype(IntEnum):
    """802.11 management frame subtypes."""
    ASSOCIATION_REQUEST = 0
    ASSOCIATION_RESPONSE = 1
    REASSOCIATION_REQUEST = 2
    REASSOCIATION_RESPONSE = 3
    PROBE_REQUEST = 4
    PROBE_RESPONSE = 5
    TIMING_ADVERTISEMENT = 6
    BEACON = 8
    ATIM = 9
    DISASSOCIATION = 10
    AUTHENTICATION = 11
    DEAUTHENTICATION = 12
    ACTION = 13
    ACTION_NO_ACK = 14


class ControlSubtype(IntEnum):
    """802.11 control frame subtypes."""
    TRIGGER = 2
    TACK = 3
    BEAMFORMING_REPORT_POLL = 4
    VHT_HE_NDP_ANNOUNCEMENT = 5
    CONTROL_FRAME_EXTENSION = 6
    CONTROL_WRAPPER = 7
    BLOCK_ACK_REQUEST = 8
    BLOCK_ACK = 9
    PS_POLL = 10
    RTS = 11
    CTS = 12
    ACK = 13
    CF_END = 14
    CF_END_CF_ACK = 15


class DataSubtype(IntEnum):
    """802.11 data frame subtypes."""
    DATA = 0
    DATA_CF_ACK = 1
    DATA_CF_POLL = 2
    DATA_CF_ACK_CF_POLL = 3
    NULL = 4
    CF_ACK = 5
    CF_POLL = 6
    CF_ACK_CF_POLL = 7
    QOS_DATA = 8
    QOS_DATA_CF_ACK = 9
    QOS_DATA_CF_POLL = 10
    QOS_DATA_CF_ACK_CF_POLL = 11
    QOS_NULL = 12
    QOS_CF_POLL = 14
    QOS_CF_ACK_CF_POLL = 15


class WiFiField(IntEnum):
    """WiFi frame address field identifiers for BPF."""
    ADDR1 = 1  # Destination address
    ADDR2 = 2  # Source address  
    ADDR3 = 3  # BSS ID / third address
    ADDR4 = 4  # Fourth address (WDS)


class DSFlags(IntEnum):
    """DS flag combinations for 802.11 frames."""
    TO_DS_0_FROM_DS_0 = 0x00  # IBSS/Direct
    TO_DS_0_FROM_DS_1 = 0x02  # From AP
    TO_DS_1_FROM_DS_0 = 0x01  # To AP
    TO_DS_1_FROM_DS_1 = 0x03  # WDS/Mesh


# Frame type string mappings for BPF syntax
FRAME_TYPE_STRINGS: Dict[FrameType, str] = {
    FrameType.MANAGEMENT: "mgt",
    FrameType.CONTROL: "ctl", 
    FrameType.DATA: "data",
    FrameType.EXTENSION: "ext"
}

# Management subtype string mappings
MANAGEMENT_SUBTYPE_STRINGS: Dict[ManagementSubtype, str] = {
    ManagementSubtype.ASSOCIATION_REQUEST: "assoc-req",
    ManagementSubtype.ASSOCIATION_RESPONSE: "assoc-resp", 
    ManagementSubtype.REASSOCIATION_REQUEST: "reassoc-req",
    ManagementSubtype.REASSOCIATION_RESPONSE: "reassoc-resp",
    ManagementSubtype.PROBE_REQUEST: "probe-req",
    ManagementSubtype.PROBE_RESPONSE: "probe-resp",
    ManagementSubtype.BEACON: "beacon",
    ManagementSubtype.ATIM: "atim",
    ManagementSubtype.DISASSOCIATION: "disassoc",
    ManagementSubtype.AUTHENTICATION: "auth",
    ManagementSubtype.DEAUTHENTICATION: "deauth",
    ManagementSubtype.ACTION: "action"
}

# Control subtype string mappings  
CONTROL_SUBTYPE_STRINGS: Dict[ControlSubtype, str] = {
    ControlSubtype.BLOCK_ACK_REQUEST: "bar",
    ControlSubtype.BLOCK_ACK: "ba",
    ControlSubtype.PS_POLL: "ps-poll",
    ControlSubtype.RTS: "rts",
    ControlSubtype.CTS: "cts", 
    ControlSubtype.ACK: "ack",
    ControlSubtype.CF_END: "cf-end"
}

# Address field string mappings
ADDR_FIELD_STRINGS: Dict[WiFiField, str] = {
    WiFiField.ADDR1: "addr1",
    WiFiField.ADDR2: "addr2", 
    WiFiField.ADDR3: "addr3",
    WiFiField.ADDR4: "addr4"
}
