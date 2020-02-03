# Copyright (C) 2019 Juciano Cardoso <cjuciano@gmail.com>
#               2019 Guillaume Valadon <guillaume.valadon@netatmo.com>
##
# This program is published under a GPLv2 license

# scapy.contrib.description = Concox CRX1 unit tests
# scapy.contrib.status = loads

import binascii

from scapy.packet import Packet, bind_layers
from scapy.layers.inet import TCP, UDP
from scapy.fields import BitField, BitEnumField, X3BytesField, ShortField, \
    XShortField, FieldLenField, PacketLenField, XByteField, XByteEnumField, \
    ByteEnumField, StrFixedLenField, ConditionalField, FlagsField, ByteField, \
    IntField, XIntField, StrLenField, ScalingField

PROTOCOL_NUMBERS = {
    0x01: 'LOGIN MESSAGE',
    0x13: 'HEARTBEAT',
    0x12: 'LOCATION',
    0x16: 'ALARM',
    0x80: 'ONLINE COMMAND',
    0x15: 'ONLINE COMMAND REPLYED',
    0x94: 'INFORMATION TRANSMISSION',
}

SUBPROTOCOL_NUMBERS = {
    0x00: "EXTERNAL POWER VOLTAGE",
    0x04: "TERMINAL STATUS SYNCHRONIZATION",
    0x05: "DOOR STATUS",
}

VOLTAGE_LEVELS = {
    0x00: "No Power (Shutdown)",
    0x01: "Extremely Low Battery",
    0x02: "Very Low Battery",
    0x03: "Low Battery",
    0x04: "Medium",
    0x05: "High",
    0x06: "Very High",
}

GSM_SIGNAL_STRENGTH = {
    0x00: "No Signal",
    0x01: "Extremely Weak Signal",
    0x02: "Very Weak Signal",
    0x03: "Good Signal",
    0x04: "Strong Signal",
}

LANGUAGE = {
    0x01: "Chinese",
    0x02: "English",
}


class BCDStrFixedLenField(StrFixedLenField):
    def i2h(self, pkt, x):
        if isinstance(x, bytes):
            return binascii.b2a_hex(x)
        return binascii.a2b_hex(x)


class CRX1NewPacketContent(Packet):
    name = "CRX1 New Packet Content"
    fields_desc = [
        XByteEnumField('protocol_number', 0x12, PROTOCOL_NUMBERS),
        # Login
        ConditionalField(
            BCDStrFixedLenField('terminal_id', '00000000', length=8), lambda
            pkt: len(pkt.original) > 5 and pkt.protocol_number == 0x01),
        # GPS Location
        ConditionalField(
            ByteField('year', 0x00), lambda pkt: len(pkt.original) > 5 and pkt.
            protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('month', 0x01), lambda pkt: len(pkt.original) > 5 and pkt
            .protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('day', 0x01), lambda pkt: len(pkt.original) > 5 and pkt.
            protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('hour', 0x00), lambda pkt: len(pkt.original) > 5 and pkt.
            protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('minute', 0x00), lambda pkt: len(pkt.original) > 5 and
            pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('second', 0x00), lambda pkt: len(pkt.original) > 5 and
            pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            BitField('gps_information_length', 0x00, 4), lambda pkt: len(
                pkt.original) > 5 and pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            BitField('positioning_satellite_number', 0x00, 4), lambda pkt: len(
                pkt.original) > 5 and pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            ScalingField('latitude', 0x00,
                         scaling=1.0 / 1800000, ndigits=6, fmt="!I"),
            lambda pkt: len(pkt.original) > 5 and \
            pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            ScalingField('longitude', 0x00,
                         scaling=1.0 / 1800000, ndigits=6, fmt="!I"),
            lambda pkt: len(pkt.original) > 5 and \
            pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('speed', 0x00), lambda pkt: len(pkt.original) > 5 and pkt
            .protocol_number in (0x12, 0x16)),
        ConditionalField(
            BitField('course', 0x00, 10), lambda pkt: len(pkt.original) > 5 and
            pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            BitEnumField('latitude_hemisphere', 0x00, 1, {
                0: "South",
                1: "North"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x12, 0x16)),
        ConditionalField(
            BitEnumField('longitude_hemisphere', 0x00, 1, {
                0: "East",
                1: "West"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x12, 0x16)),
        ConditionalField(
            BitEnumField('gps_been_positioning', 0x00, 1, {
                0: "No",
                1: "Yes"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x12, 0x16)),
        ConditionalField(
            BitEnumField('gps_status', 0x00, 1, {
                0: "GPS real-time",
                1: "Differential positioning"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x12, 0x16)),
        ConditionalField(
            BitField('course_status_reserved', 0x00, 2), lambda pkt: len(
                pkt.original) > 5 and pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            ByteField('lbs_length', 0x00),
            lambda pkt: len(pkt.original) > 5 and \
            pkt.protocol_number in (0x16, )),
        ConditionalField(
            XShortField('mcc', 0x00), lambda pkt: len(pkt.original) > 5 and pkt
            .protocol_number in (0x12, 0x16)),
        ConditionalField(
            XByteField('mnc', 0x00), lambda pkt: len(pkt.original) > 5 and pkt.
            protocol_number in (0x12, 0x16)),
        ConditionalField(
            XShortField('lac', 0x00), lambda pkt: len(pkt.original) > 5 and pkt
            .protocol_number in (0x12, 0x16)),
        ConditionalField(
            X3BytesField('cell_id', 0x00),
            lambda pkt: len(pkt.original) > 5 and \
            pkt.protocol_number in (0x12, 0x16)),
        ConditionalField(
            IntField('mileage', 0x00), lambda pkt: len(pkt.original) > 5 and
            pkt.protocol_number in (0x12, ) and len(pkt.original) > 31),
        # Heartbeat
        ConditionalField(
            BitEnumField('defence', 0x00, 1, {
                0: "Deactivated",
                1: "Activated"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x13, 0x16)),
        ConditionalField(
            BitEnumField('acc', 0x00, 1, {
                0: "Low",
                1: "High"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x13, 0x16)),
        ConditionalField(
            BitEnumField('charge', 0x00, 1, {
                0: "Not Charge",
                1: "Charging"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x13, 0x16)),
        ConditionalField(
            BitEnumField(
                'alarm', 0x00, 3, {
                    0: "Normal",
                    1: "Vibration",
                    2: "Power Cut",
                    3: "Low Battery",
                    4: "SOS"
                }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number
            in (0x13, 0x16)),
        ConditionalField(
            BitEnumField('gps_tracking', 0x00, 1, {
                0: "Not Charge",
                1: "Charging"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x13, 0x16)),
        ConditionalField(
            BitEnumField('oil_and_eletricity', 0x00, 1, {
                0: "Connected",
                1: "Disconnected"
            }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x13, 0x16)),
        ConditionalField(
            ByteEnumField("voltage_level", 0x00, VOLTAGE_LEVELS), lambda pkt:
            len(pkt.original) > 5 and pkt.protocol_number in (0x13, 0x16)),
        ConditionalField(
            ByteEnumField("gsm_signal_strength", 0x00,
                          GSM_SIGNAL_STRENGTH), lambda pkt: len(pkt.original) >
            5 and pkt.protocol_number in (0x13, 0x16)),
        # Online Command
        ConditionalField(
            FieldLenField('command_length',
                          None,
                          fmt='B',
                          length_of="command_content"), lambda pkt:
            len(pkt.original) > 5 and pkt.protocol_number in (0x80, 0x15)),
        ConditionalField(
            XIntField('server_flag_bit', 0x00), lambda pkt: len(pkt.original) >
            5 and pkt.protocol_number in (0x80, 0x15)),
        ConditionalField(
            StrLenField(
                "command_content",
                "",
                length_from=lambda pkt: pkt.command_length - 4), lambda pkt:
            len(pkt.original) > 5 and pkt.protocol_number in (0x80, 0x15)),
        # Commun
        ConditionalField(
            ByteEnumField(
                "alarm_extended", 0x00, {
                    0x00: "Normal",
                    0x01: "SOS",
                    0x02: "Power cut",
                    0x03: "Vibration",
                    0x04: "Enter fence",
                    0x05: "Exit fence",
                    0x06: "Over speed",
                    0x09: "Displacement",
                    0x0a: "Enter GPS dead zone",
                    0x0b: "Exit GPS dead zone",
                    0x0c: "Power on",
                    0x0d: "GPS First fix notice",
                    0x0e: "Low battery",
                    0x0f: "Low battery protection",
                    0x10: "SIM Change",
                    0x11: "Power off",
                    0x12: "Airplane mode",
                    0x13: "Disassemble",
                    0x14: "Door",
                    0xfe: "ACC On",
                    0xff: "ACC Off",
                }), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number
            in (0x13, 0x15, 0x16)),
        ConditionalField(
            ByteEnumField("language", 0x00,
                          LANGUAGE), lambda pkt: len(pkt.original) > 5 and pkt.
            protocol_number in (0x13, 0x15, 0x16)),
        # Information transmission
        ConditionalField(
            ByteEnumField("subprotocol_number", 0x00,
                          SUBPROTOCOL_NUMBERS), lambda pkt: len(pkt.original) >
            5 and pkt.protocol_number in (0x94, )),
        ConditionalField(
            ShortField('external_battery',
                       0x00), lambda pkt: len(pkt.original) > 5 and pkt.
            protocol_number in (0x94, ) and pkt.subprotocol_number == 0x00),
        ConditionalField(
            FlagsField('external_io_detection', 0x00, 8, [
                'door_status',
                'trigger_status',
                'io_status',
            ]), lambda pkt: len(pkt.original) > 5 and pkt.protocol_number in (
                0x94, ) and pkt.subprotocol_number == 0x05),
        # Default
        XShortField('information_serial_number', None),
        XShortField('crc', None),
    ]


class CRX1New(Packet):
    name = "CRX1 New"
    fields_desc = [
        XShortField('start_bit', 0x7878),
        ConditionalField(ByteField(
            'default_packet_length',
            None,
        ), lambda pkt: pkt.start_bit == 0x7878),
        ConditionalField(ShortField(
            'extended_packet_length',
            None,
        ), lambda pkt: pkt.start_bit == 0x7979),
        ConditionalField(
            PacketLenField('default_packet_content',
                           None,
                           CRX1NewPacketContent,
                           length_from=lambda pkt: pkt.default_packet_length),
            lambda pkt: pkt.start_bit == 0x7878),
        ConditionalField(
            PacketLenField('extended_packet_content',
                           None,
                           CRX1NewPacketContent,
                           length_from=lambda pkt: pkt.extended_packet_length),
            lambda pkt: pkt.start_bit == 0x7979),
        XShortField('end_bit', 0x0d0a),
    ]


bind_layers(TCP, CRX1New, sport=8821, dport=8821)
bind_layers(UDP, CRX1New, sport=8821, dport=8821)
