# This program is published under a GPLv2 license
# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Ryan Speers <ryan@rmspeers.com> 2011-2012
# Copyright (C) Roger Meyer <roger.meyer@csus.edu>: 2012-03-10 Added frames
# Copyright (C) Gabriel Potter <gabriel@potter.fr>: 2018
# Intern at INRIA Grand Nancy Est
# This program is published under a GPLv2 license

"""
Wireless MAC according to IEEE 802.15.4.
"""

import re
import struct

from scapy.compat import orb, raw

from scapy.packet import *
from scapy.fields import *

from scapy.layers.ntp import TimeStampField
from scapy.layers.inet import UDP

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

# ZigBee stack profiles
_zcl_profile_identifier = {
    0x0000: "ZigBee_Stack_Profile_1",
    0x0101: "IPM_Industrial_Plant_Monitoring",
    0x0104: "HA_Home_Automation",
    0x0105: "CBA_Commercial_Building_Automation",
    0x0107: "TA_Telecom_Applications",
    0x0108: "HC_Health_Care",
    0x0109: "SE_Smart_Energy_Profile",
}

# ZigBee Cluster Library, Table 2.8 ZCL Command Frames
_zcl_command_frames = {
    0x00: "read_attributes",
    0x01: "read_attributes_response",
    0x02: "write_attributes_response",
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
    # 0x0e - 0xff Reserved
}

# ZigBee Cluster Library, Table 2.16 Enumerated Status Values
_zcl_enumerated_status_values = {
    0x00: "SUCCESS",
    0x02: "FAILURE",
    # 0x02 - 0x7f Reserved
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
    # 0x8e - 0xbf Reserved
    0xc0: "HARDWARE_FAILURE",
    0xc1: "SOFTWARE_FAILURE",
    0xc2: "CALIBRATION_ERROR",
    # 0xc3 - 0xff Reserved
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

# Fields #


class dot15d4AddressField(Field):
    __slots__ = ["adjust", "length_of"]

    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of
        if adjust is not None:
            self.adjust = adjust
        else:
            self.adjust = lambda pkt, x: self.lengthFromAddrMode(pkt, x)

    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        if len(hex(self.i2m(pkt, x))) < 7:  # short address
            return hex(self.i2m(pkt, x))
        else:  # long address
            x = "%016x" % self.i2m(pkt, x)
            return ":".join(["%s%s" % (x[i], x[i + 1]) for i in range(0, len(x), 2)])  # noqa: E501

    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.adjust(pkt, self.length_of) == 2:
            return s + struct.pack(self.fmt[0] + "H", val)
        elif self.adjust(pkt, self.length_of) == 8:
            return s + struct.pack(self.fmt[0] + "Q", val)
        else:
            return s

    def getfield(self, pkt, s):
        if self.adjust(pkt, self.length_of) == 2:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0] + "H", s[:2])[0])  # noqa: E501
        elif self.adjust(pkt, self.length_of) == 8:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0] + "Q", s[:8])[0])  # noqa: E501
        else:
            raise Exception('impossible case')

    def lengthFromAddrMode(self, pkt, x):
        addrmode = 0
        pkttop = pkt.underlayer
        while True:
            try:
                addrmode = pkttop.getfieldval(x)
                break
            except:
                if pkttop.underlayer is None:
                    break
                pkttop = pkttop.underlayer
        # print "Underlayer field value of", x, "is", addrmode
        if addrmode == 2:
            return 2
        elif addrmode == 3:
            return 8
        return 0


# class dot15d4Checksum(LEShortField,XShortField):
#    def i2repr(self, pkt, x):
#        return XShortField.i2repr(self, pkt, x)
#    def addfield(self, pkt, s, val):
#        return s
#    def getfield(self, pkt, s):
#        return s


# Layers #

class Dot15d4(Packet):
    name = "802.15.4"
    fields_desc = [
        BitField("fcf_reserved_1", 0, 1),  # fcf p1 b1
        BitEnumField("fcf_panidcompress", 0, 1, [False, True]),
        BitEnumField("fcf_ackreq", 0, 1, [False, True]),
        BitEnumField("fcf_pending", 0, 1, [False, True]),
        BitEnumField("fcf_security", 0, 1, [False, True]),  # fcf p1 b2
        Emph(BitEnumField("fcf_frametype", 0, 3, {0: "Beacon", 1: "Data", 2: "Ack", 3: "Command"})),  # noqa: E501
        BitEnumField("fcf_srcaddrmode", 0, 2, {0: "None", 1: "Reserved", 2: "Short", 3: "Long"}),  # fcf p2 b1  # noqa: E501
        BitField("fcf_framever", 0, 2),  # 00 compatibility with 2003 version; 01 compatible with 2006 version  # noqa: E501
        BitEnumField("fcf_destaddrmode", 2, 2, {0: "None", 1: "Reserved", 2: "Short", 3: "Long"}),  # fcf p2 b2  # noqa: E501
        BitField("fcf_reserved_2", 0, 2),
        Emph(ByteField("seqnum", 1))  # sequence number
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 %Dot15d4.fcf_frametype% ackreq(%Dot15d4.fcf_ackreq%) ( %Dot15d4.fcf_destaddrmode% -> %Dot15d4.fcf_srcaddrmode% ) Seq#%Dot15d4.seqnum%")  # noqa: E501

    def guess_payload_class(self, payload):
        if self.fcf_frametype == 0x00:
            return Dot15d4Beacon
        elif self.fcf_frametype == 0x01:
            return Dot15d4Data
        elif self.fcf_frametype == 0x02:
            return Dot15d4Ack
        elif self.fcf_frametype == 0x03:
            return Dot15d4Cmd
        else:
            return Packet.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, Dot15d4):
            if self.fcf_frametype == 2:  # ack
                if self.seqnum != other.seqnum:  # check for seqnum matching
                    return 0
                elif other.fcf_ackreq == 1:  # check that an ack was indeed requested  # noqa: E501
                    return 1
        return 0

    def post_build(self, p, pay):
        # This just forces destaddrmode to None for Ack frames.
        # TODO find a more elegant way to do this
        if self.fcf_frametype == 2 and self.fcf_destaddrmode != 0:
            self.fcf_destaddrmode = 0
            return raw(self)
        else:
            return p + pay


class Dot15d4FCS(Dot15d4, Packet):
    '''
    This class is a drop-in replacement for the Dot15d4 class above, except
    it expects a FCS/checksum in the input, and produces one in the output.
    This provides the user flexibility, as many 802.15.4 interfaces will have an AUTO_CRC setting  # noqa: E501
    that will validate the FCS/CRC in firmware, and add it automatically when transmitting.  # noqa: E501
    '''

    def pre_dissect(self, s):
        """Called right before the current layer is dissected"""
        if (makeFCS(s[:-2]) != s[-2:]):  # validate the FCS given
            warning("FCS on this packet is invalid or is not present in provided bytes.")  # noqa: E501
            return s  # if not valid, pretend there was no FCS present
        return s[:-2]  # otherwise just disect the non-FCS section of the pkt

    def post_build(self, p, pay):
        # This just forces destaddrmode to None for Ack frames.
        # TODO find a more elegant way to do this
        if self.fcf_frametype == 2 and self.fcf_destaddrmode != 0:
            self.fcf_destaddrmode = 0
            return raw(self)
        else:
            return p + pay + makeFCS(p + pay)  # construct the packet with the FCS at the end  # noqa: E501


class Dot15d4Ack(Packet):
    name = "802.15.4 Ack"
    fields_desc = []


class Dot15d4AuxSecurityHeader(Packet):
    name = "802.15.4 Auxiliary Security Header"
    fields_desc = [
        BitField("sec_sc_reserved", 0, 3),
        # Key Identifier Mode
        # 0: Key is determined implicitly from the originator and receipient(s) of the frame  # noqa: E501
        # 1: Key is determined explicitly from the the 1-octet Key Index subfield of the Key Identifier field  # noqa: E501
        # 2: Key is determined explicitly from the 4-octet Key Source and the 1-octet Key Index  # noqa: E501
        # 3: Key is determined explicitly from the 8-octet Key Source and the 1-octet Key Index  # noqa: E501
        BitEnumField("sec_sc_keyidmode", 0, 2, {
            0: "Implicit", 1: "1oKeyIndex", 2: "4o-KeySource-1oKeyIndex", 3: "8o-KeySource-1oKeyIndex"}  # noqa: E501
        ),
        BitEnumField("sec_sc_seclevel", 0, 3, {0: "None", 1: "MIC-32", 2: "MIC-64", 3: "MIC-128", 4: "ENC", 5: "ENC-MIC-32", 6: "ENC-MIC-64", 7: "ENC-MIC-128"}),  # noqa: E501
        XLEIntField("sec_framecounter", 0x00000000),  # 4 octets
        # Key Identifier (variable length): identifies the key that is used for cryptographic protection  # noqa: E501
        # Key Source : length of sec_keyid_keysource varies btwn 0, 4, and 8 bytes depending on sec_sc_keyidmode  # noqa: E501
        # 4 octets when sec_sc_keyidmode == 2
        ConditionalField(XLEIntField("sec_keyid_keysource", 0x00000000),
                         lambda pkt: pkt.getfieldval("sec_sc_keyidmode") == 2),
        # 8 octets when sec_sc_keyidmode == 3
        ConditionalField(LELongField("sec_keyid_keysource", 0x0000000000000000),  # noqa: E501
                         lambda pkt: pkt.getfieldval("sec_sc_keyidmode") == 3),
        # Key Index (1 octet): allows unique identification of different keys with the same originator  # noqa: E501
        ConditionalField(XByteField("sec_keyid_keyindex", 0xFF),
                         lambda pkt: pkt.getfieldval("sec_sc_keyidmode") != 0),
    ]


class Dot15d4Data(Packet):
    name = "802.15.4 Data"
    fields_desc = [
        XLEShortField("dest_panid", 0xFFFF),
        dot15d4AddressField("dest_addr", 0xFFFF, length_of="fcf_destaddrmode"),
        ConditionalField(XLEShortField("src_panid", 0x0),
                         lambda pkt:util_srcpanid_present(pkt)),
        ConditionalField(dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),  # noqa: E501
        # Security field present if fcf_security == True
        ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_security") is True),  # noqa: E501
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Data ( %Dot15d4Data.src_panid%:%Dot15d4Data.src_addr% -> %Dot15d4Data.dest_panid%:%Dot15d4Data.dest_addr% )")  # noqa: E501


class Dot15d4Beacon(Packet):
    name = "802.15.4 Beacon"
    fields_desc = [
        XLEShortField("src_panid", 0x0),
        dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"),
        # Security field present if fcf_security == True
        ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_security") is True),  # noqa: E501

        # Superframe spec field:
        BitField("sf_sforder", 15, 4),  # not used by ZigBee
        BitField("sf_beaconorder", 15, 4),  # not used by ZigBee
        BitEnumField("sf_assocpermit", 0, 1, [False, True]),
        BitEnumField("sf_pancoord", 0, 1, [False, True]),
        BitField("sf_reserved", 0, 1),  # not used by ZigBee
        BitEnumField("sf_battlifeextend", 0, 1, [False, True]),  # not used by ZigBee  # noqa: E501
        BitField("sf_finalcapslot", 15, 4),  # not used by ZigBee

        # GTS Fields
        #  GTS Specification (1 byte)
        BitEnumField("gts_spec_permit", 1, 1, [False, True]),  # GTS spec bit 7, true=1 iff PAN cord is accepting GTS requests  # noqa: E501
        BitField("gts_spec_reserved", 0, 4),  # GTS spec bits 3-6
        BitField("gts_spec_desccount", 0, 3),  # GTS spec bits 0-2
        #  GTS Directions (0 or 1 byte)
        ConditionalField(BitField("gts_dir_reserved", 0, 1), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),  # noqa: E501
        ConditionalField(BitField("gts_dir_mask", 0, 7), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),  # noqa: E501
        #  GTS List (variable size)
        # TODO add a Packet/FieldListField tied to 3bytes per count in gts_spec_desccount  # noqa: E501

        # Pending Address Fields:
        #  Pending Address Specification (1 byte)
        BitField("pa_num_short", 0, 3),  # number of short addresses pending
        BitField("pa_reserved_1", 0, 1),
        BitField("pa_num_long", 0, 3),  # number of long addresses pending
        BitField("pa_reserved_2", 0, 1),
        #  Address List (var length)
        # TODO add a FieldListField of the pending short addresses, followed by the pending long addresses, with max 7 addresses  # noqa: E501
        # TODO beacon payload
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Beacon ( %Dot15d4Beacon.src_panid%:%Dot15d4Beacon.src_addr% ) assocPermit(%Dot15d4Beacon.sf_assocpermit%) panCoord(%Dot15d4Beacon.sf_pancoord%)")  # noqa: E501


class Dot15d4Cmd(Packet):
    name = "802.15.4 Command"
    fields_desc = [
        XLEShortField("dest_panid", 0xFFFF),
        # Users should correctly set the dest_addr field. By default is 0x0 for construction to work.  # noqa: E501
        dot15d4AddressField("dest_addr", 0x0, length_of="fcf_destaddrmode"),
        ConditionalField(XLEShortField("src_panid", 0x0), \
                         lambda pkt:util_srcpanid_present(pkt)),
        ConditionalField(dot15d4AddressField("src_addr", None,
                         length_of="fcf_srcaddrmode"),
                         lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),  # noqa: E501
        # Security field present if fcf_security == True
        ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_security") is True),  # noqa: E501
        ByteEnumField("cmd_id", 0, {
            1: "AssocReq",  # Association request
            2: "AssocResp",  # Association response
            3: "DisassocNotify",  # Disassociation notification
            4: "DataReq",  # Data request
            5: "PANIDConflictNotify",  # PAN ID conflict notification
            6: "OrphanNotify",  # Orphan notification
            7: "BeaconReq",  # Beacon request
            8: "CoordRealign",  # coordinator realignment
            9: "GTSReq"  # GTS request
            # 0x0a - 0xff reserved
        }),
        # TODO command payload
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Command %Dot15d4Cmd.cmd_id% ( %Dot15dCmd.src_panid%:%Dot15d4Cmd.src_addr% -> %Dot15d4Cmd.dest_panid%:%Dot15d4Cmd.dest_addr% )")  # noqa: E501

    # command frame payloads are complete: DataReq, PANIDConflictNotify, OrphanNotify, BeaconReq don't have any payload  # noqa: E501
    # Although BeaconReq can have an optional ZigBee Beacon payload (implemented in ZigBeeBeacon)  # noqa: E501
    def guess_payload_class(self, payload):
        if self.cmd_id == 1:
            return Dot15d4CmdAssocReq
        elif self.cmd_id == 2:
            return Dot15d4CmdAssocResp
        elif self.cmd_id == 3:
            return Dot15d4CmdDisassociation
        elif self.cmd_id == 8:
            return Dot15d4CmdCoordRealign
        elif self.cmd_id == 9:
            return Dot15d4CmdGTSReq
        else:
            return Packet.guess_payload_class(self, payload)


class Dot15d4CmdCoordRealign(Packet):
    name = "802.15.4 Coordinator Realign Command"
    fields_desc = [
        # PAN Identifier (2 octets)
        XLEShortField("panid", 0xFFFF),
        # Coordinator Short Address (2 octets)
        XLEShortField("coord_address", 0x0000),
        # Logical Channel (1 octet): the logical channel that the coordinator intends to use for all future communications  # noqa: E501
        ByteField("channel", 0),
        # Short Address (2 octets)
        XLEShortField("dev_address", 0xFFFF),
        # Channel page (0/1 octet) TODO optional
        # ByteField("channel_page", 0),
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Coordinator Realign Payload ( PAN ID: %Dot15dCmdCoordRealign.pan_id% : channel %Dot15d4CmdCoordRealign.channel% )")  # noqa: E501


# ZigBee #

class ZigbeeNWK(Packet):
    name = "Zigbee Network Layer"
    fields_desc = [
        BitField("discover_route", 0, 2),
        BitField("proto_version", 2, 4),
        BitEnumField("frametype", 0, 2, {0: 'data', 1: 'command'}),
        FlagsField("flags", 0, 8, ['multicast', 'security', 'source_route', 'extended_dst', 'extended_src', 'reserved1', 'reserved2', 'reserved3']),  # noqa: E501
        XLEShortField("destination", 0),
        XLEShortField("source", 0),
        ByteField("radius", 0),
        ByteField("seqnum", 1),

        ConditionalField(ByteField("relay_count", 1), lambda pkt:pkt.flags & 0x04),  # noqa: E501
        ConditionalField(ByteField("relay_index", 0), lambda pkt:pkt.flags & 0x04),  # noqa: E501
        ConditionalField(FieldListField("relays", [], XLEShortField("", 0x0000), count_from=lambda pkt:pkt.relay_count), lambda pkt:pkt.flags & 0x04),  # noqa: E501

        # ConditionalField(XLongField("ext_dst", 0), lambda pkt:pkt.flags & 8),
        ConditionalField(dot15d4AddressField("ext_dst", 0, adjust=lambda pkt, x: 8), lambda pkt:pkt.flags & 8),  # noqa: E501
        # ConditionalField(XLongField("ext_src", 0), lambda pkt:pkt.flags & 16),  # noqa: E501
        ConditionalField(dot15d4AddressField("ext_src", 0, adjust=lambda pkt, x: 8), lambda pkt:pkt.flags & 16),  # noqa: E501
    ]

    def guess_payload_class(self, payload):
        if self.flags & 0x02:
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
            10: "network update"
            # 0x0b - 0xff reserved
        }),

        # - Route Request Command - #
        # Command options (1 octet)
        ConditionalField(BitField("reserved", 0, 1), lambda pkt: pkt.cmd_identifier == 1),  # noqa: E501
        ConditionalField(BitField("multicast", 0, 1), lambda pkt: pkt.cmd_identifier == 1),  # noqa: E501
        ConditionalField(BitField("dest_addr_bit", 0, 1), lambda pkt: pkt.cmd_identifier == 1),  # noqa: E501
        ConditionalField(
            BitEnumField("many_to_one", 0, 2, {
                0: "not_m2one", 1: "m2one_support_rrt", 2: "m2one_no_support_rrt", 3: "reserved"}  # noqa: E501
            ), lambda pkt: pkt.cmd_identifier == 1),
        ConditionalField(BitField("reserved", 0, 3), lambda pkt: pkt.cmd_identifier == 1),  # noqa: E501
        # Route request identifier (1 octet)
        ConditionalField(ByteField("route_request_identifier", 0), lambda pkt: pkt.cmd_identifier == 1),  # noqa: E501
        # Destination address (2 octets)
        ConditionalField(XLEShortField("destination_address", 0x0000), lambda pkt: pkt.cmd_identifier == 1),  # noqa: E501
        # Path cost (1 octet)
        ConditionalField(ByteField("path_cost", 0), lambda pkt: pkt.cmd_identifier == 1),  # noqa: E501
        # Destination IEEE Address (0/8 octets), only present when dest_addr_bit has a value of 1  # noqa: E501
        ConditionalField(dot15d4AddressField("ext_dst", 0, adjust=lambda pkt, x: 8),  # noqa: E501
                         lambda pkt: (pkt.cmd_identifier == 1 and pkt.dest_addr_bit == 1)),  # noqa: E501

        # - Route Reply Command - #
        # Command options (1 octet)
        ConditionalField(BitField("reserved", 0, 1), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        ConditionalField(BitField("multicast", 0, 1), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        ConditionalField(BitField("responder_addr_bit", 0, 1), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        ConditionalField(BitField("originator_addr_bit", 0, 1), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        ConditionalField(BitField("reserved", 0, 4), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        # Route request identifier (1 octet)
        ConditionalField(ByteField("route_request_identifier", 0), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        # Originator address (2 octets)
        ConditionalField(XLEShortField("originator_address", 0x0000), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        # Responder address (2 octets)
        ConditionalField(XLEShortField("responder_address", 0x0000), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        # Path cost (1 octet)
        ConditionalField(ByteField("path_cost", 0), lambda pkt: pkt.cmd_identifier == 2),  # noqa: E501
        # Originator IEEE address (0/8 octets)
        ConditionalField(dot15d4AddressField("originator_addr", 0, adjust=lambda pkt, x: 8),  # noqa: E501
                         lambda pkt: (pkt.cmd_identifier == 2 and pkt.originator_addr_bit == 1)),  # noqa: E501
        # Responder IEEE address (0/8 octets)
        ConditionalField(dot15d4AddressField("responder_addr", 0, adjust=lambda pkt, x: 8),  # noqa: E501
                         lambda pkt: (pkt.cmd_identifier == 2 and pkt.responder_addr_bit == 1)),  # noqa: E501

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
        ConditionalField(XLEShortField("destination_address", 0x0000), lambda pkt: pkt.cmd_identifier == 3),  # noqa: E501

        # - Leave Command - #
        # Command options (1 octet)
        # Bit 7: Remove children
        ConditionalField(BitField("remove_children", 0, 1), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501
        # Bit 6: Request
        ConditionalField(BitField("request", 0, 1), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501
        # Bit 5: Rejoin
        ConditionalField(BitField("rejoin", 0, 1), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501
        # Bit 0 - 4: Reserved
        ConditionalField(BitField("reserved", 0, 5), lambda pkt: pkt.cmd_identifier == 4),  # noqa: E501

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
        ConditionalField(BitField("reserved", 0, 1), lambda pkt:pkt.cmd_identifier == 8),  # Reserved  # noqa: E501
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
        # EPID: Extended PAN ID (8 octets)
        ConditionalField(dot15d4AddressField("epid", 0, adjust=lambda pkt, x: 8), lambda pkt: pkt.cmd_identifier == 9),  # noqa: E501
        # Report information (variable length)
        # Only present if we have a PAN Identifier Conflict Report
        ConditionalField(
            FieldListField("PAN_ID_conflict_report", [], XLEShortField("", 0x0000),  # noqa: E501
                           count_from=lambda pkt:pkt.report_information_count),
            lambda pkt:(pkt.cmd_identifier == 9 and pkt.report_command_identifier == 0)  # noqa: E501
        ),

        # - Network Update Command - #
        # Command options (1 octet)
        ConditionalField(
            BitEnumField("update_command_identifier", 0, 3, {0: "PAN Identifier Update"}),  # 0x01 - 0x07 Reserved  # noqa: E501
            lambda pkt: pkt.cmd_identifier == 10),
        ConditionalField(BitField("update_information_count", 0, 5), lambda pkt: pkt.cmd_identifier == 10),  # noqa: E501
        # EPID: Extended PAN ID (8 octets)
        ConditionalField(dot15d4AddressField("epid", 0, adjust=lambda pkt, x: 8), lambda pkt: pkt.cmd_identifier == 10),  # noqa: E501
        # Update Id (1 octet)
        ConditionalField(ByteField("update_id", 0), lambda pkt: pkt.cmd_identifier == 10),  # noqa: E501
        # Update Information (Variable)
        # Only present if we have a PAN Identifier Update
        # New PAN ID (2 octets)
        ConditionalField(XLEShortField("new_PAN_ID", 0x0000),
                         lambda pkt: (pkt.cmd_identifier == 10 and pkt.update_command_identifier == 0)),  # noqa: E501

        # StrLenField("data", "", length_from=lambda pkt, s:len(s)),
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
        StrLenField("data", "", length_from=lambda pkt, s: len(s) - util_mic_len(pkt)),  # noqa: E501
        # Message Integrity Code (0/variable in size), length depends on nwk_seclevel  # noqa: E501
        StrLenField("mic", "", length_from=lambda pkt: util_mic_len(pkt)),
    ]


class ZigbeeAppDataPayload(Packet):
    name = "Zigbee Application Layer Data Payload (General APS Frame Format)"
    fields_desc = [
        # Frame control (1 octet)
        FlagsField("frame_control", 2, 4, ['reserved1', 'security', 'ack_req', 'extended_hdr']),  # noqa: E501
        BitEnumField("delivery_mode", 0, 2, {0: 'unicast', 1: 'indirect', 2: 'broadcast', 3: 'group_addressing'}),  # noqa: E501
        BitEnumField("aps_frametype", 0, 2, {0: 'data', 1: 'command', 2: 'ack'}),  # noqa: E501
        # Destination endpoint (0/1 octet)
        ConditionalField(ByteField("dst_endpoint", 10), lambda pkt: (pkt.frame_control & 0x04 or pkt.aps_frametype == 2)),  # noqa: E501
        # Group address (0/2 octets) TODO
        # Cluster identifier (0/2 octets)
        ConditionalField(EnumField("cluster", 0, _zcl_cluster_identifier, fmt="<H"),  # unsigned short (little-endian)  # noqa: E501
                         lambda pkt: (pkt.frame_control & 0x04 or pkt.aps_frametype == 2)  # noqa: E501
                         ),
        # Profile identifier (0/2 octets)
        ConditionalField(EnumField("profile", 0, _zcl_profile_identifier, fmt="<H"),  # noqa: E501
                         lambda pkt: (pkt.frame_control & 0x04 or pkt.aps_frametype == 2)  # noqa: E501
                         ),
        # Source endpoint (0/1 octets)
        ConditionalField(ByteField("src_endpoint", 10), lambda pkt: (pkt.frame_control & 0x04 or pkt.aps_frametype == 2)),  # noqa: E501
        # APS counter (1 octet)
        ByteField("counter", 0),
        # optional extended header
        # variable length frame payload: 3 frame types: data, APS command, and acknowledgement  # noqa: E501
        # ConditionalField(StrLenField("data", "", length_from=lambda pkt, s:len(s)), lambda pkt:pkt.aps_frametype == 0),  # noqa: E501
    ]

    def guess_payload_class(self, payload):
        if self.frame_control & 0x02:  # we have a security header
            return ZigbeeSecurityHeader
        elif self.aps_frametype == 0:  # data
            return ZigbeeClusterLibrary  # TODO might also be another frame
        elif self.aps_frametype == 1:  # command
            return ZigbeeAppCommandPayload
        else:
            return Packet.guess_payload_class(self, payload)


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
            10: "APS_CMD_EA_INIT_CHLNG",
            11: "APS_CMD_EA_RSP_CHLNG",
            12: "APS_CMD_EA_INIT_MAC_DATA",
            13: "APS_CMD_EA_RSP_MAC_DATA",
            14: "APS_CMD_TUNNEL"
        }),
        StrLenField("data", "", length_from=lambda pkt, s: len(s)),
    ]

# Utility Functions #


def util_srcpanid_present(pkt):
    '''A source PAN ID is included if and only if both src addr mode != 0 and PAN ID Compression in FCF == 0'''  # noqa: E501
    if (pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0) and (pkt.underlayer.getfieldval("fcf_panidcompress") == 0):  # noqa: E501
        return True
    else:
        return False

# Do a CRC-CCITT Kermit 16bit on the data given
# Returns a CRC that is the FCS for the frame
#  Implemented using pseudocode from: June 1986, Kermit Protocol Manual
#  See also: http://regregex.bbcmicro.net/crc-catalogue.htm#crc.cat.kermit


def makeFCS(data):
    crc = 0
    for i in range(0, len(data)):
        c = orb(data[i])
        q = (crc ^ c) & 15  # Do low-order 4 bits
        crc = (crc // 16) ^ (q * 4225)
        q = (crc ^ (c // 16)) & 15  # And high 4 bits
        crc = (crc // 16) ^ (q * 4225)
    return struct.pack('<H', crc)  # return as bytes in little endian order


class Dot15d4CmdAssocReq(Packet):
    name = "802.15.4 Association Request Payload"
    fields_desc = [
        BitField("allocate_address", 0, 1),  # Allocate Address
        BitField("security_capability", 0, 1),  # Security Capability
        BitField("reserved2", 0, 1),  # bit 5 is reserved
        BitField("reserved1", 0, 1),  # bit 4 is reserved
        BitField("receiver_on_when_idle", 0, 1),  # Receiver On When Idle
        BitField("power_source", 0, 1),  # Power Source
        BitField("device_type", 0, 1),  # Device Type
        BitField("alternate_pan_coordinator", 0, 1),  # Alternate PAN Coordinator  # noqa: E501
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Association Request Payload ( Alt PAN Coord: %Dot15d4CmdAssocReq.alternate_pan_coordinator% Device Type: %Dot15d4CmdAssocReq.device_type% )")  # noqa: E501


class Dot15d4CmdAssocResp(Packet):
    name = "802.15.4 Association Response Payload"
    fields_desc = [
        XLEShortField("short_address", 0xFFFF),  # Address assigned to device from coordinator (0xFFFF == none)  # noqa: E501
        # Association Status
        # 0x00 == successful
        # 0x01 == PAN at capacity
        # 0x02 == PAN access denied
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
        ByteEnumField("association_status", 0x00, {0: 'successful', 1: 'PAN_at_capacity', 2: 'PAN_access_denied'}),  # noqa: E501
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Association Response Payload ( Association Status: %Dot15d4CmdAssocResp.association_status% Assigned Address: %Dot15d4CmdAssocResp.short_address% )")  # noqa: E501


class Dot15d4CmdDisassociation(Packet):
    name = "802.15.4 Disassociation Notification Payload"
    fields_desc = [
        # Disassociation Reason
        # 0x00 == Reserved
        # 0x01 == The coordinator wishes the device to leave the PAN
        # 0x02 == The device wishes to leave the PAN
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
        ByteEnumField("disassociation_reason", 0x02, {1: 'coord_wishes_device_to_leave', 2: 'device_wishes_to_leave'}),  # noqa: E501
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Disassociation Notification Payload ( Disassociation Reason %Dot15d4CmdDisassociation.disassociation_reason% )")  # noqa: E501


class Dot15d4CmdGTSReq(Packet):
    name = "802.15.4 GTS request command"
    fields_desc = [
        # GTS Characteristics field (1 octet)
        # Reserved (bits 6-7)
        BitField("reserved", 0, 2),
        # Characteristics Type (bit 5)
        BitField("charact_type", 0, 1),
        # GTS Direction (bit 4)
        BitField("gts_dir", 0, 1),
        # GTS Length (bits 0-3)
        BitField("gts_len", 0, 4),
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 GTS Request Command ( %Dot15d4CmdGTSReq.gts_len% : %Dot15d4CmdGTSReq.gts_dir% )")  # noqa: E501

# PAN ID conflict notification command frame is not necessary, only Dot15d4Cmd with cmd_id = 5 ("PANIDConflictNotify")  # noqa: E501
# Orphan notification command not necessary, only Dot15d4Cmd with cmd_id = 6 ("OrphanNotify")  # noqa: E501


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
        BitField("reserved", 0, 2),  # remaining subfields shall have a value of 0  # noqa: E501
        BitField("proto_version", 2, 4),
        BitField("frametype", 0b11, 2),  # 0b11 (3) is a reserved frame type
        BitField("reserved", 0, 8),  # remaining subfields shall have a value of 0  # noqa: E501
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
        EnumField("cluster", 0, _zcl_cluster_identifier, fmt="<H"),  # unsigned short (little-endian)  # noqa: E501
        # Profile identifier
        EnumField("profile", 0, _zcl_profile_identifier, fmt="<H"),
        # ZigBee Payload
        ConditionalField(
            StrLenField("data", "", length_from=lambda pkt, s: len(s)),
            lambda pkt: pkt.frametype == 3
        ),
    ]

# ZigBee Cluster Library #


def util_zcl_attribute_value_len(pkt):
    # Calculate the length of the attribute value field
    if (pkt.attribute_data_type == 0x00):  # no data
        return 0
    elif (pkt.attribute_data_type == 0x08):  # 8-bit data
        return 1
    elif (pkt.attribute_data_type == 0x09):  # 16-bit data
        return 2
    elif (pkt.attribute_data_type == 0x0a):  # 24-bit data
        return 3
    elif (pkt.attribute_data_type == 0x0b):  # 32-bit data
        return 4
    elif (pkt.attribute_data_type == 0x0c):  # 40-bit data
        return 5
    elif (pkt.attribute_data_type == 0x0d):  # 48-bit data
        return 6
    elif (pkt.attribute_data_type == 0x0e):  # 56-bit data
        return 7
    elif (pkt.attribute_data_type == 0x0f):  # 64-bit data
        return 8
    elif (pkt.attribute_data_type == 0x10):  # boolean
        return 1
    elif (pkt.attribute_data_type == 0x18):  # 8-bit bitmap
        return 1
    elif (pkt.attribute_data_type == 0x19):  # 16-bit bitmap
        return 2
    elif (pkt.attribute_data_type == 0x1a):  # 24-bit bitmap
        return 3
    elif (pkt.attribute_data_type == 0x1b):  # 32-bit bitmap
        return 4
    elif (pkt.attribute_data_type == 0x1c):  # 40-bit bitmap
        return 5
    elif (pkt.attribute_data_type == 0x1d):  # 48-bit bitmap
        return 6
    elif (pkt.attribute_data_type == 0x1e):  # 46-bit bitmap
        return 7
    elif (pkt.attribute_data_type == 0x1f):  # 64-bit bitmap
        return 8
    elif (pkt.attribute_data_type == 0x20):  # Unsigned 8-bit integer
        return 1
    elif (pkt.attribute_data_type == 0x21):  # Unsigned 16-bit integer
        return 2
    elif (pkt.attribute_data_type == 0x22):  # Unsigned 24-bit integer
        return 3
    elif (pkt.attribute_data_type == 0x23):  # Unsigned 32-bit integer
        return 4
    elif (pkt.attribute_data_type == 0x24):  # Unsigned 40-bit integer
        return 5
    elif (pkt.attribute_data_type == 0x25):  # Unsigned 48-bit integer
        return 6
    elif (pkt.attribute_data_type == 0x26):  # Unsigned 56-bit integer
        return 7
    elif (pkt.attribute_data_type == 0x27):  # Unsigned 64-bit integer
        return 8
    elif (pkt.attribute_data_type == 0x28):  # Signed 8-bit integer
        return 1
    elif (pkt.attribute_data_type == 0x29):  # Signed 16-bit integer
        return 2
    elif (pkt.attribute_data_type == 0x2a):  # Signed 24-bit integer
        return 3
    elif (pkt.attribute_data_type == 0x2b):  # Signed 32-bit integer
        return 4
    elif (pkt.attribute_data_type == 0x2c):  # Signed 40-bit integer
        return 5
    elif (pkt.attribute_data_type == 0x2d):  # Signed 48-bit integer
        return 6
    elif (pkt.attribute_data_type == 0x2e):  # Signed 56-bit integer
        return 7
    elif (pkt.attribute_data_type == 0x2f):  # Signed 64-bit integer
        return 8
    elif (pkt.attribute_data_type == 0x30):  # 8-bit enumeration
        return 1
    elif (pkt.attribute_data_type == 0x31):  # 16-bit enumeration
        return 2
    elif (pkt.attribute_data_type == 0x38):  # Semi-precision
        return 2
    elif (pkt.attribute_data_type == 0x39):  # Single precision
        return 4
    elif (pkt.attribute_data_type == 0x3a):  # Double precision
        return 8
    elif (pkt.attribute_data_type == 0x41):  # Octet string
        return int(pkt.attribute_value[0])  # defined in first octet
    elif (pkt.attribute_data_type == 0x42):  # Character string
        return int(pkt.attribute_value[0])  # defined in first octet
    elif (pkt.attribute_data_type == 0x43):  # Long octet string
        return int(pkt.attribute_value[0:2])  # defined in first two octets
    elif (pkt.attribute_data_type == 0x44):  # Long character string
        return int(pkt.attribute_value[0:2])  # defined in first two octets
    # TODO implement Ordered sequence & collection
    elif (pkt.attribute_data_type == 0xe0):  # Time of day
        return 4
    elif (pkt.attribute_data_type == 0xe1):  # Date
        return 4
    elif (pkt.attribute_data_type == 0xe2):  # UTCTime
        return 4
    elif (pkt.attribute_data_type == 0xe8):  # Cluster ID
        return 2
    elif (pkt.attribute_data_type == 0xe9):  # Attribute ID
        return 2
    elif (pkt.attribute_data_type == 0xea):  # BACnet OID
        return 4
    elif (pkt.attribute_data_type == 0xf0):  # IEEE address
        return 8
    elif (pkt.attribute_data_type == 0xf1):  # 128-bit security key
        return 16
    elif (pkt.attribute_data_type == 0xff):  # Unknown
        return 0
    else:
        return 0


class ZCLReadAttributeStatusRecord(Packet):
    name = "ZCL Read Attribute Status Record"
    fields_desc = [
        # Attribute Identifier
        XLEShortField("attribute_identifier", 0),
        # Status
        ByteEnumField("status", 0, _zcl_enumerated_status_values),
        # Attribute data type (0/1 octet), only included if status == 0x00 (SUCCESS)  # noqa: E501
        ConditionalField(
            ByteEnumField("attribute_data_type", 0, _zcl_attribute_data_types),
            lambda pkt:pkt.status == 0x00
        ),
        # Attribute data (0/variable in size), only included if status == 0x00 (SUCCESS)  # noqa: E501
        ConditionalField(
            StrLenField("attribute_value", "", length_from=lambda pkt:util_zcl_attribute_value_len(pkt)),  # noqa: E501
            lambda pkt:pkt.status == 0x00
        ),
    ]


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
    fields_desc = [
        # Frame control (8 bits)
        BitField("reserved", 0, 3),
        BitField("disable_default_response", 0, 1),  # 0 default response command will be returned  # noqa: E501
        BitField("direction", 0, 1),  # 0 command sent from client to server; 1 command sent from server to client  # noqa: E501
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
        ByteField("command_identifier", 0),
    ]

    def guess_payload_class(self, payload):
        # Profile-wide commands
        if self.zcl_frametype == 0x00 and self.command_identifier == 0x00:
            return ZCLGeneralReadAttributes
        elif self.zcl_frametype == 0x00 and self.command_identifier == 0x01:
            return ZCLGeneralReadAttributesResponse
        # Cluster-specific commands
        elif self.zcl_frametype == 0x01 and self.command_identifier == 0x00 and self.direction == 0 and self.underlayer.cluster == 0x0700:  # "price"  # noqa: E501
            return ZCLPriceGetCurrentPrice
        elif self.zcl_frametype == 0x01 and self.command_identifier == 0x01 and self.direction == 0 and self.underlayer.cluster == 0x0700:  # "price"  # noqa: E501
            return ZCLPriceGetScheduledPrices
        elif self.zcl_frametype == 0x01 and self.command_identifier == 0x00 and self.direction == 1 and self.underlayer.cluster == 0x0700:  # "price"  # noqa: E501
            return ZCLPricePublishPrice
        else:
            return Packet.guess_payload_class(self, payload)

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
bind_layers(Dot15d4, Dot15d4Beacon, fcf_frametype=0)
bind_layers(Dot15d4, Dot15d4Data, fcf_frametype=1)
bind_layers(Dot15d4, Dot15d4Ack, fcf_frametype=2)
bind_layers(Dot15d4, Dot15d4Cmd, fcf_frametype=3)
bind_layers(Dot15d4FCS, Dot15d4Beacon, fcf_frametype=0)
bind_layers(Dot15d4FCS, Dot15d4Data, fcf_frametype=1)
bind_layers(Dot15d4FCS, Dot15d4Ack, fcf_frametype=2)
bind_layers(Dot15d4FCS, Dot15d4Cmd, fcf_frametype=3)
# TODO: find a way to chose between ZigbeeNWK and SixLoWPAN (cf. sixlowpan.py)
# bind_layers( Dot15d4Data, ZigbeeNWK)
bind_layers(ZigbeeAppDataPayload, ZigbeeAppCommandPayload, frametype=1)
bind_layers(Dot15d4Beacon, ZigBeeBeacon)

bind_bottom_up(UDP, ZEP2, sport=17754)
bind_bottom_up(UDP, ZEP2, sport=17754)
bind_layers(UDP, ZEP2, sport=17754, dport=17754)

# DLT Types #
conf.l2types.register(195, Dot15d4FCS)
conf.l2types.register(230, Dot15d4)
