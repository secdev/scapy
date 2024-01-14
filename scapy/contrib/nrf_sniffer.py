# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Michael Farrell <micolous+git@gmail.com>

"""
nRF sniffer

Firmware and documentation related to this module is available at:
https://www.nordicsemi.com/Software-and-Tools/Development-Tools/nRF-Sniffer
https://github.com/adafruit/Adafruit_BLESniffer_Python
https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-nordic_ble.c
"""

# scapy.contrib.description = nRF sniffer
# scapy.contrib.status = works

import struct

from scapy.config import conf
from scapy.data import DLT_NORDIC_BLE
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    LEIntField,
    LEShortField,
    LenField,
    ScalingField,
)
from scapy.layers.bluetooth4LE import BTLE
from scapy.packet import Packet, bind_layers


# nRF Sniffer v2


class NRFS2_Packet(Packet):
    """
    nRF Sniffer v2 Packet
    """

    fields_desc = [
        LenField("len", None, fmt="<H", adjust=lambda x: x + 6),
        ByteField("version", 2),
        LEShortField("counter", None),
        ByteEnumField(
            "type",
            None,
            {
                0x00: "req_follow",
                0x01: "event_follow",
                0x02: "event_device",  # missing from spreadsheet
                0x03: "req_single_packet",  # missing from spreadsheet
                0x04: "resp_single_packet",  # missing from spreadsheet
                0x05: "event_connect",
                0x06: "event_packet",
                0x07: "req_scan_cont",
                0x09: "event_disconnect",
                0x0A: "event_error",  # missing from spreadsheet
                0x0B: "event_empty_data_packet",  # missing from spreadsheet
                0x0C: "set_temporary_key",
                0x0D: "ping_req",
                0x0E: "ping_resp",
                0x0F: "test_command_id",  # missing from spreadsheet
                0x10: "test_result_id",  # missing from spreadsheet
                0x11: "uart_test_start",  # missing from spreadsheet
                0x12: "uart_dummy_packet",  # missing from spreadsheet
                0x13: "switch_baud_rate_req",  # not implemented in FW
                0x14: "switch_baud_rate_resp",  # not implemented in FW
                0x15: "uart_out_start",  # missing from spreadsheet
                0x16: "uart_out_stop",  # missing from spreadsheet
                0x17: "set_adv_channel_hop_seq",
                0xFE: "go_idle",  # not implemented in FW
            },
        ),
    ]

    def answer(self, other):
        if not isinstance(other, NRFS2_Packet):
            return False

        return (
            (self.type == 0x01 and other.type == 0x00) or
            (self.type == 0x0E and other.type == 0x0D) or
            (self.type == 0x14 and other.type == 0x13)
        )

    def post_build(self, p, pay):
        if self.hdr_len is None:
            p = p[:1] + struct.pack("!B", len(p)) + p[2:]
        return p + pay


class NRF2_Ping_Request(Packet):
    name = "Ping request"


class NRF2_Ping_Response(Packet):
    name = "Ping response"
    fields_desc = [
        LEShortField("version", None),
    ]


class NRF2_Packet_Event(Packet):
    name = "Packet event (device variant)"
    fields_desc = [
        ByteField("header_len", 10),
        # Flags (1 byte)
        BitField("reserved", 0, 1),
        BitEnumField("phy", None, 3, {0: "le-1m", 1: "le-2m", 2: "le-coded"}),
        BitField("mic", None, 1),
        BitField("encrypted", None, 1),
        BitField("direction", None, 1),
        BitField("crc_ok", 1, 1),
        ByteField("rf_channel", 0),
        ScalingField("rssi", -256, unit="dBm", fmt="b"),
        LEShortField("event_counter", 0),
        LEIntField("delta_time", 0),  # microseconds
    ]


bind_layers(NRFS2_Packet, NRF2_Ping_Request, type=0xD)
bind_layers(NRFS2_Packet, NRF2_Ping_Response, type=0xE)
bind_layers(NRFS2_Packet, NRF2_Packet_Event, type=0x6)

bind_layers(NRF2_Packet_Event, BTLE)

# Wire transport


class NRFS2_PCAP(Packet):
    """
    PCAP headers for DLT_NORDIC_BLE.

    Nordic's capture scripts either stick the COM port number (yep!) or a
    random number at the start of every packet.

    https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-nordic_ble.c

    The only "rule" is that we can't start packets with ``BE EF``, otherwise
    it becomes a "0.9.7" packet. So we just set "0" here.
    """

    name = "nRF Sniffer PCAP header"
    fields_desc = [
        ByteField("board_id", 0),
    ]


bind_layers(NRFS2_PCAP, NRFS2_Packet)
conf.l2types.register(DLT_NORDIC_BLE, NRFS2_PCAP)
